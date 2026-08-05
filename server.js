/* ============================================================
   Veripher — backend (Node.js + Express + PostgreSQL)
   Env vars (set in Render): FIVESIM_TOKEN, NOWPAY_KEY,
   NOWPAY_IPN_SECRET, JWT_SECRET, BASE_URL, DATABASE_URL
   ============================================================ */

const express = require('express');
const fetch   = require('node-fetch');
const bcrypt  = require('bcryptjs');
const jwt     = require('jsonwebtoken');
const crypto  = require('crypto');
const { pool, init } = require('./db');

const app = express();
app.use(express.static('public'));
app.use('/api/ipn', express.raw({ type: '*/*' }));
app.use(express.json());

const {
  FIVESIM_TOKEN, NOWPAY_KEY, NOWPAY_IPN_SECRET,
  FLW_SECRET_KEY, FLW_WEBHOOK_HASH,
  JWT_SECRET = 'dev-secret', BASE_URL = 'http://localhost:3000'
} = process.env;

/* ============================================================
   PRICING RULES  (one place — used for BOTH display and charge)
   - WhatsApp + USA  -> 2x  (loss-leader, high demand)
   - everything else -> 3x, with a $0.50 minimum floor
   ============================================================ */
const USD_TO_NGN_SERVER = 1600;
function resalePrice(service, country, costUSD){
  // Special: WhatsApp Australia -> fixed ₦10,000 ($6.25) ...
  if(service === 'whatsapp' && country === 'australia'){
    const fixedUSD = 10000 / USD_TO_NGN_SERVER;          // = $6.25
    // ...but never below cost + safe margin (never sell at a loss)
    const safeMin = costUSD * 1.3;
    return +(Math.max(fixedUSD, safeMin)).toFixed(2);
  }
  // Special: WhatsApp USA -> 1.8x (loss-leader)
  if(service === 'whatsapp' && country === 'usa'){
    return +(costUSD * 1.8).toFixed(2);
  }
  // Option B tiered markup: under $2.80 -> 2.5x, $2.80+ -> 1.8x, $0.50 floor
  const mult = costUSD >= 2.80 ? 1.8 : 2.5;
  return +(Math.max(costUSD * mult, 0.50)).toFixed(2);
}

/* find the cheapest IN-STOCK operator cost for a service in 5sim price data */
function cheapestInStock(serviceData){
  let cost = Infinity;
  if(serviceData){
    for(const info of Object.values(serviceData)){
      if(info && info.count > 0 && info.cost < cost) cost = info.cost;
    }
  }
  return cost === Infinity ? null : cost;
}

async function fivesim(path){
  const r = await fetch('https://5sim.net/v1' + path, {
    headers:{ 'Authorization':'Bearer '+FIVESIM_TOKEN, 'Accept':'application/json' }
  });
  const text = await r.text();
  if(!r.ok || !text){
    console.log('5sim', r.status, path, '->', JSON.stringify(text).slice(0,200));
    return { _error:true, status:r.status, body:text };
  }
  try { return JSON.parse(text); }
  catch { console.log('5sim non-JSON', path, '->', text.slice(0,200)); return { _error:true, body:text }; }
}

function auth(req,res,next){
  const t = (req.headers.authorization||'').replace('Bearer ','');
  try { req.email = jwt.verify(t, JWT_SECRET).email; next(); }
  catch { res.status(401).json({ error:'Please sign in again' }); }
}

/* ---------- auth ---------- */
app.post('/api/signup', async (req,res)=>{
  const { email, pass } = req.body;
  if(!email || !pass) return res.status(400).json({ error:'Email and password required' });
  const exists = await pool.query('SELECT 1 FROM users WHERE email=$1', [email]);
  if(exists.rowCount) return res.status(409).json({ error:'That email is already registered' });
  const hash = await bcrypt.hash(pass,10);
  await pool.query('INSERT INTO users (email, pass_hash) VALUES ($1,$2)', [email, hash]);
  res.json({ token: jwt.sign({ email }, JWT_SECRET, { expiresIn:'30d' }), balanceUSD: 0 });
});

app.post('/api/login', async (req,res)=>{
  const { email, pass } = req.body;
  const u = (await pool.query('SELECT * FROM users WHERE email=$1', [email])).rows[0];
  if(!u || !(await bcrypt.compare(pass, u.pass_hash)))
    return res.status(401).json({ error:'Wrong email or password' });
  res.json({ token: jwt.sign({ email }, JWT_SECRET, { expiresIn:'30d' }), balanceUSD: Number(u.balance_usd) });
});

app.get('/api/me', auth, async (req,res)=>{
  const u = (await pool.query('SELECT balance_usd FROM users WHERE email=$1', [req.email])).rows[0];
  res.json({ balanceUSD: Number(u.balance_usd) });
});

/* ============================================================
   BULK PRICES  — one call returns real live prices for every
   service in a chosen country (fast: single 5sim request)
   ============================================================ */
app.get('/api/prices/:country', async (req,res)=>{
  const country = req.params.country;
  const data = await fivesim(`/guest/prices?country=${country}`);
  if(data._error || !data[country]) return res.json({ prices:{} });

  const out = {};
  for(const [service, operators] of Object.entries(data[country])){
    const cost = cheapestInStock(operators);
    if(cost !== null){
      out[service] = { price: resalePrice(service, country, cost), available: true };
    }
  }
  res.json({ prices: out });
});

/* ---------- wallet top-up ---------- */
app.post('/api/wallet/topup', auth, async (req,res)=>{
  const amountUSD = parseFloat(req.body.amountUSD);
  if(!amountUSD || amountUSD < 20) return res.status(400).json({ error:'Minimum top-up is $20' });
  const orderId = 'topup_' + crypto.randomBytes(8).toString('hex');
  await pool.query('INSERT INTO invoices (order_id, email, amount_usd) VALUES ($1,$2,$3)', [orderId, req.email, amountUSD]);
  const r = await fetch('https://api.nowpayments.io/v1/invoice', {
    method:'POST',
    headers:{ 'x-api-key':NOWPAY_KEY, 'Content-Type':'application/json' },
    body: JSON.stringify({
      price_amount: amountUSD, price_currency:'usd', order_id: orderId,
      ipn_callback_url: BASE_URL + '/api/ipn/nowpayments',
      success_url: BASE_URL + '/account.html', cancel_url: BASE_URL + '/account.html'
    })
  });
  const inv = await r.json();
  if(!inv.invoice_url) return res.status(502).json({ error:'Could not start payment, try again' });
  res.json({ invoice_url: inv.invoice_url });
});

/* ---------- NOWPayments webhook ---------- */
app.post('/api/ipn/nowpayments', async (req,res)=>{
  const sig  = req.headers['x-nowpayments-sig'];
  const data = JSON.parse(req.body.toString());
  const sorted   = JSON.stringify(sortKeys(data));
  const expected = crypto.createHmac('sha512', NOWPAY_IPN_SECRET).update(sorted).digest('hex');
  if(sig !== expected) return res.status(401).send('bad signature');
  if(data.payment_status === 'finished'){
    const inv = (await pool.query('SELECT * FROM invoices WHERE order_id=$1 AND credited=false', [data.order_id])).rows[0];
    if(inv){
      await pool.query('UPDATE invoices SET credited=true WHERE order_id=$1', [inv.order_id]);
      await pool.query('UPDATE users SET balance_usd = balance_usd + $1 WHERE email=$2', [inv.amount_usd, inv.email]);
    }
  }
  res.status(200).send('ok');
});
function sortKeys(o){
  if(Array.isArray(o)) return o.map(sortKeys);
  if(o && typeof o==='object')
    return Object.keys(o).sort().reduce((a,k)=>(a[k]=sortKeys(o[k]),a),{});
  return o;
}


/* ============================================================
   FLUTTERWAVE  (Naira bank transfer / card -> wallet top-up)
   Rate: ₦1,600 = $1.  Customer pays Naira, wallet credited in USD.
   ============================================================ */
const NGN_RATE = 1600;
const MIN_NGN  = 1000;   // minimum naira top-up

app.post('/api/wallet/topup-ngn', auth, async (req,res)=>{
  const amountNGN = Math.round(parseFloat(req.body.amountNGN));
  if(!amountNGN || amountNGN < MIN_NGN)
    return res.status(400).json({ error:'Minimum top-up is ₦'+MIN_NGN.toLocaleString() });

  const ref = 'flw_' + crypto.randomBytes(8).toString('hex');
  const amountUSD = +(amountNGN / NGN_RATE).toFixed(2);   // credit value
  // store as a pending invoice (amount in USD, like crypto ones)
  await pool.query('INSERT INTO invoices (order_id, email, amount_usd) VALUES ($1,$2,$3)',
    [ref, req.email, amountUSD]);

  // create a Flutterwave hosted payment
  const r = await fetch('https://api.flutterwave.com/v3/payments', {
    method:'POST',
    headers:{ 'Authorization':'Bearer '+FLW_SECRET_KEY, 'Content-Type':'application/json' },
    body: JSON.stringify({
      tx_ref: ref,
      amount: amountNGN,
      currency: 'NGN',
      redirect_url: BASE_URL + '/account.html',
      customer: { email: req.email },
      payment_options: 'banktransfer',
      customizations: { title: 'Veripher wallet top-up', description: 'Add funds to your wallet' }
    })
  });
  const data = await r.json();
  if(data.status !== 'success' || !data.data || !data.data.link)
    return res.status(502).json({ error:'Could not start payment, try again' });
  res.json({ link: data.data.link });
});

/* Flutterwave webhook -> verify -> credit wallet */
app.post('/api/ipn/flutterwave', express.json(), async (req,res)=>{
  // verify the request is really from Flutterwave
  const sig = req.headers['verif-hash'];
  if(!sig || sig !== FLW_WEBHOOK_HASH) return res.status(401).send('bad signature');

  const ev = req.body;
  const ref = ev && ev.data && ev.data.tx_ref;
  const status = ev && ev.data && ev.data.status;

  if(ref && status === 'successful'){
    // double-check with Flutterwave that this payment truly succeeded
    const vr = await fetch('https://api.flutterwave.com/v3/transactions/'+ev.data.id+'/verify', {
      headers:{ 'Authorization':'Bearer '+FLW_SECRET_KEY }
    });
    const vd = await vr.json();
    if(vd.status === 'success' && vd.data && vd.data.status === 'successful'){
      const inv = (await pool.query('SELECT * FROM invoices WHERE order_id=$1 AND credited=false',[ref])).rows[0];
      if(inv){
        // safety: make sure the amount paid matches what we expected (₦)
        const expectedNGN = Math.round(inv.amount_usd * NGN_RATE);
        if(Number(vd.data.amount) >= expectedNGN - 1){
          await pool.query('UPDATE invoices SET credited=true WHERE order_id=$1',[ref]);
          await pool.query('UPDATE users SET balance_usd = balance_usd + $1 WHERE email=$2',[inv.amount_usd, inv.email]);
        }
      }
    }
  }
  res.status(200).send('ok');
});

/* ---------- orders (buy a number) ---------- */
app.post('/api/orders', auth, async (req,res)=>{
  const { service, country } = req.body;

  const prices = await fivesim(`/guest/prices?country=${country}&product=${service}`);
  let operator = 'any', cheapest = Infinity;
  try {
    const ops = prices[country][service];
    for(const [name, info] of Object.entries(ops)){
      if(info.count > 0 && info.cost < cheapest){ cheapest = info.cost; operator = name; }
    }
  } catch(e){}
  if(operator === 'any')
    return res.status(400).json({ error:'No numbers available right now, try another country' });

  const order = await fivesim(`/user/buy/activation/${country}/${operator}/${service}`);
  if(order._error)
    return res.status(400).json({ error:'5sim said: '+(order.body || ('HTTP '+order.status))+' — try another country' });
  if(order.status !== 'PENDING')
    return res.status(400).json({ error:'No numbers available, try another country' });

  const costUSD   = Number(order.price);
  const resaleUSD = resalePrice(service, country, costUSD);   // SAME rule as display

  const spend = await pool.query(
    'UPDATE users SET balance_usd = balance_usd - $1 WHERE email=$2 AND balance_usd >= $1 RETURNING balance_usd',
    [resaleUSD, req.email]
  );
  if(spend.rowCount === 0){
    await fivesim(`/user/cancel/${order.id}`);
    return res.status(402).json({ error:'Top up your wallet to continue' });
  }
  await pool.query('INSERT INTO orders (id, email, cost_usd, resale_usd) VALUES ($1,$2,$3,$4)',
    [String(order.id), req.email, costUSD, resaleUSD]);
  res.json({ id: order.id, phone: order.phone, priceUSD: resaleUSD });
});

app.get('/api/orders/:id', auth, async (req,res)=>{
  const d = await fivesim(`/user/check/${req.params.id}`);
  const sms = (d.sms && d.sms[0]) || null;
  res.json({ status:d.status, code: sms?sms.code:null, sender: sms?sms.sender:null });
});

app.post('/api/orders/:id/finish', auth, async (req,res)=>{
  await fivesim(`/user/finish/${req.params.id}`); res.json({ ok:true });
});

app.post('/api/orders/:id/cancel', auth, async (req,res)=>{
  await fivesim(`/user/cancel/${req.params.id}`);
  const o = (await pool.query('SELECT * FROM orders WHERE id=$1 AND refunded=false', [req.params.id])).rows[0];
  if(o){
    await pool.query('UPDATE orders SET refunded=true WHERE id=$1', [o.id]);
    await pool.query('UPDATE users SET balance_usd = balance_usd + $1 WHERE email=$2', [o.resale_usd, o.email]);
  }
  res.json({ ok:true });
});

const PORT = process.env.PORT || 3000;
init()
  .then(()=> app.listen(PORT, ()=> console.log('Veripher backend on port ' + PORT)))
  .catch(err => { console.error('DB init failed:', err); process.exit(1); });
