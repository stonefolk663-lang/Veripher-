/* ============================================================
   Veripher — backend (Node.js + Express + PostgreSQL)
   Env vars (set in Render): FIVESIM_TOKEN, NOWPAY_KEY,
   NOWPAY_IPN_SECRET, FLW_SECRET_KEY, FLW_WEBHOOK_HASH,
   JWT_SECRET, BASE_URL, DATABASE_URL
   *** THIS VERSION INCLUDES FLUTTERWAVE BANK TRANSFER ***
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
  const RATE = USD_TO_NGN_SERVER;               // 1600
  const CAP_NGN = 10000;                         // safe ceiling
  let priceUSD;

  // --- special fixed prices ---
  if(service === 'whatsapp' && country === 'usa'){
    priceUSD = 2000 / RATE;                       // fixed ₦2,000
  } else if(service === 'whatsapp' && country === 'australia'){
    priceUSD = 10000 / RATE;                      // fixed ₦10,000
  } else {
    // --- Option B tiered markup ---
    const mult = costUSD >= 2.80 ? 1.8 : 2.5;
    priceUSD = Math.max(costUSD * mult, 0.50);
  }

  // --- SAFE ₦10k cap: cap to ₦10k, but never below a safe margin over cost ---
  const capUSD  = CAP_NGN / RATE;                 // $6.25
  const safeMin = costUSD * 1.3;                  // never sell under cost+30%
  if(priceUSD > capUSD){
    priceUSD = Math.max(capUSD, safeMin);         // cap, unless that would lose money
  }
  return +priceUSD.toFixed(2);
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
const MIN_NGN  = 500;   // minimum naira top-up

app.post('/api/wallet/topup-ngn', auth, async (req,res)=>{
  const amountNGN = Math.round(parseFloat(req.body.amountNGN));
  if(!amountNGN || amountNGN < MIN_NGN)
    return res.status(400).json({ error:'Minimum deposit is ₦500' });

  const ref = 'flw_' + crypto.randomBytes(8).toString('hex');
  const amountUSD = +(amountNGN / NGN_RATE).toFixed(4);   // credit value (4dp avoids rounding gaps)
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
        const paidNGN = Number(vd.data.amount);
        if(vd.data.currency==='NGN' && paidNGN >= expectedNGN - 20){
          const creditUSD = +(paidNGN / NGN_RATE).toFixed(4);
          await pool.query('UPDATE invoices SET credited=true WHERE order_id=$1',[ref]);
          await pool.query('UPDATE users SET balance_usd = balance_usd + $1 WHERE email=$2',[creditUSD, inv.email]);
        }
      }
    }
  }
  res.status(200).send('ok');
});


/* verify-on-return: customer lands back from Flutterwave, we CONFIRM with FLW and credit.
   This does NOT depend on the webhook arriving — more reliable. */
app.get('/api/wallet/verify-ngn', auth, async (req,res)=>{
  const tx_ref = req.query.tx_ref;
  const tx_id  = req.query.transaction_id;   // Flutterwave passes this on redirect
  console.log('VERIFY-NGN called | tx_ref=', tx_ref, '| tx_id=', tx_id, '| user=', req.email);
  if(!tx_ref && !tx_id){ console.log('VERIFY-NGN: missing reference'); return res.status(400).json({ error:'missing reference' }); }

  // find our pending invoice by ref
  let inv = null;
  if(tx_ref){
    inv = (await pool.query('SELECT * FROM invoices WHERE order_id=$1', [tx_ref])).rows[0];
  }
  if(!inv){ console.log('VERIFY-NGN: no invoice found for ref', tx_ref); return res.json({ ok:false, credited:false, reason:'no_invoice' }); }
  if(inv.credited){ console.log('VERIFY-NGN: already credited', tx_ref); return res.json({ ok:true, credited:true, already:true }); }

  // ask Flutterwave directly whether this really succeeded
  let vd = null;
  if(tx_id){
    const vr = await fetch('https://api.flutterwave.com/v3/transactions/'+tx_id+'/verify', {
      headers:{ 'Authorization':'Bearer '+FLW_SECRET_KEY }
    });
    vd = await vr.json();
  } else {
    // fallback: verify by reference
    const vr = await fetch('https://api.flutterwave.com/v3/transactions/verify_by_reference?tx_ref='+encodeURIComponent(tx_ref), {
      headers:{ 'Authorization':'Bearer '+FLW_SECRET_KEY }
    });
    vd = await vr.json();
  }

  const okPaid = vd && vd.status==='success' && vd.data && vd.data.status==='successful';
  const expectedNGN = Math.round(inv.amount_usd * NGN_RATE);
  const paidAmt = vd && vd.data ? Number(vd.data.amount) : null;
  const paidCur = vd && vd.data ? vd.data.currency : null;
  // allow a small tolerance so naira/dollar rounding never blocks a genuine payment
  const paidEnough = okPaid && paidCur === 'NGN' && paidAmt >= (expectedNGN - 20);
  console.log('VERIFY-NGN result | flwStatus=', vd&&vd.status, '| txStatus=', vd&&vd.data&&vd.data.status,
              '| paid=', paidAmt, paidCur, '| expected=', expectedNGN, '| willCredit=', paidEnough);

  if(paidEnough){
    // credit once
    const creditUSD = +(paidAmt / NGN_RATE).toFixed(4);   // credit exactly what they paid
    const upd = await pool.query('UPDATE invoices SET credited=true WHERE order_id=$1 AND credited=false', [inv.order_id]);
    if(upd.rowCount === 1){
      await pool.query('UPDATE users SET balance_usd = balance_usd + $1 WHERE email=$2', [creditUSD, inv.email]);
      console.log('VERIFY-NGN CREDITED', tx_ref, '₦'+paidAmt, '-> $'+creditUSD);
    }
    return res.json({ ok:true, credited:true, amountUSD: creditUSD });
  }
  res.json({ ok:false, credited:false });
});

/* ---------- orders (buy a number) ---------- */
app.post('/api/orders', auth, async (req,res)=>{
  const { service, country } = req.body;

  console.log('BUY requested | service=', service, '| country=', country, '| user=', req.email);
  const prices = await fivesim(`/guest/prices?country=${country}&product=${service}`);
  let operator = 'any', cheapest = Infinity;
  try {
    const ops = prices[country][service];
    console.log('BUY operators found:', ops ? Object.keys(ops).length : 'NONE', ops ? JSON.stringify(ops).slice(0,300) : '');
    for(const [name, info] of Object.entries(ops)){
      if(info.count > 0 && info.cost < cheapest){ cheapest = info.cost; operator = name; }
    }
  } catch(e){ console.log('BUY price-parse error:', e.message, '| raw:', JSON.stringify(prices).slice(0,200)); }
  console.log('BUY chosen operator:', operator, '| cost:', cheapest);
  if(operator === 'any')
    return res.status(400).json({ error:'No numbers available right now, try another country' });

  const order = await fivesim(`/user/buy/activation/${country}/${operator}/${service}`);
  console.log('BUY result from 5sim:', JSON.stringify(order).slice(0,300));
  if(order._error)
    {
      const b=(order.body||'').toLowerCase();
      if(b.includes('no free phones')||b.includes('no free')) return res.status(400).json({ error:'No numbers available for this service/country right now. Please try another country.' });
      return res.status(400).json({ error:'Could not get a number, please try another country.' });
    }
  if(order.status !== 'PENDING' && order.status !== 'RECEIVED'){
    console.log('BUY unexpected status:', order.status);
    return res.status(400).json({ error:'No numbers available, try another country' });
  }

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
  console.log('CHECK order', req.params.id, '| status=', d.status, '| sms=', JSON.stringify(d.sms||null).slice(0,300));
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
