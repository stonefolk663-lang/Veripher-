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
app.set('trust proxy', 1);   // Render is behind a proxy

/* ---------- simple in-memory rate limiting ---------- */
const rlBuckets = new Map();
function rateLimit(maxHits, windowMs){
  return (req,res,next)=>{
    const key = (req.headers['x-forwarded-for'] || req.ip || 'unknown') + ':' + req.path;
    const now = Date.now();
    let b = rlBuckets.get(key);
    if(!b || now > b.reset){ b = { count:0, reset: now + windowMs }; rlBuckets.set(key, b); }
    b.count++;
    if(b.count > maxHits){
      const wait = Math.ceil((b.reset - now)/1000);
      return res.status(429).json({ error:'Too many attempts. Please wait '+wait+'s and try again.' });
    }
    next();
  };
}
// occasionally clear old buckets so memory stays small
setInterval(()=>{ const now=Date.now(); for(const [k,b] of rlBuckets){ if(now>b.reset) rlBuckets.delete(k); } }, 60000);


const {
  FIVESIM_TOKEN, NOWPAY_KEY, NOWPAY_IPN_SECRET,
  FLW_SECRET_KEY, FLW_WEBHOOK_HASH,
  ADMIN_EMAIL, ADMIN_PASSWORD,
  JWT_SECRET = 'dev-secret', BASE_URL = 'http://localhost:3000'
} = process.env;

/* ============================================================
   PRICING RULES  (one place — used for BOTH display and charge)
   - WhatsApp + USA  -> 2x  (loss-leader, high demand)
   - everything else -> 3x, with a $0.50 minimum floor
   ============================================================ */
const USD_TO_NGN_SERVER = 1600;
function resalePrice(service, country, costUSD){
  const RATE = USD_TO_NGN_SERVER;                // 1600
  const CAP_NGN = 10000;                          // safe ceiling
  let priceUSD;

  // ---- WhatsApp & Telegram: reliable operators, hybrid pricing ----
  // USA gets a fixed headline price; other countries use ×2.0 with a ₦1,200 min profit.
  if(service === 'whatsapp' && country === 'usa'){
    priceUSD = 3500 / RATE;                        // fixed ₦3,500
  } else if(service === 'telegram' && country === 'usa'){
    priceUSD = 4000 / RATE;                        // fixed ₦4,000
  } else if(service === 'whatsapp' || service === 'telegram'){
    const x2 = costUSD * 2.0;
    const minProfit = costUSD + (1200 / RATE);     // at least ₦1,200 profit
    priceUSD = Math.max(x2, minProfit);
  } else {
    // ---- everything else: Option B tiered markup ----
    const mult = costUSD >= 2.80 ? 1.8 : 2.5;
    priceUSD = Math.max(costUSD * mult, 0.50);
  }

  // ---- safe ₦10k cap: cap to ₦10k, but never below cost+30% (never sell at a loss) ----
  const capUSD  = CAP_NGN / RATE;
  const safeMin = costUSD * 1.3;
  if(priceUSD > capUSD){
    priceUSD = Math.max(capUSD, safeMin);
  }
  return +priceUSD.toFixed(4);
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
app.post('/api/signup', rateLimit(8, 60000), async (req,res)=>{
  const { email, pass } = req.body;
  if(!email || !pass) return res.status(400).json({ error:'Email and password required' });
  const exists = await pool.query('SELECT 1 FROM users WHERE email=$1', [email]);
  if(exists.rowCount) return res.status(409).json({ error:'That email is already registered' });
  const hash = await bcrypt.hash(pass,10);
  await pool.query('INSERT INTO users (email, pass_hash) VALUES ($1,$2)', [email, hash]);
  res.json({ token: jwt.sign({ email }, JWT_SECRET, { expiresIn:'30d' }), balanceUSD: 0 });
});

app.post('/api/login', rateLimit(8, 60000), async (req,res)=>{
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
app.post('/api/wallet/topup', rateLimit(15, 60000), auth, async (req,res)=>{
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

app.post('/api/wallet/topup-ngn', rateLimit(15, 60000), auth, async (req,res)=>{
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
  if(!tx_ref && !tx_id){ return res.status(400).json({ error:'missing reference' }); }

  // find our pending invoice by ref
  let inv = null;
  if(tx_ref){
    inv = (await pool.query('SELECT * FROM invoices WHERE order_id=$1', [tx_ref])).rows[0];
  }
  if(!inv){ return res.json({ ok:false, credited:false, reason:'no_invoice' }); }
  if(inv.credited){ return res.json({ ok:true, credited:true, already:true }); }

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


/* ============================================================
   ADMIN  (protected: must be logged in as ADMIN_EMAIL + admin password)
   ============================================================ */
function adminAuth(req,res,next){
  // layer 1: valid login token
  const t = (req.headers.authorization||'').replace('Bearer ','');
  let email;
  try { email = jwt.verify(t, JWT_SECRET).email; } catch { return res.status(401).json({ error:'unauthorized' }); }
  // layer 2: must be the admin account
  if(!ADMIN_EMAIL || email !== ADMIN_EMAIL) return res.status(403).json({ error:'forbidden' });
  // layer 3: correct admin password header
  const pw = req.headers['x-admin-password'] || '';
  if(!ADMIN_PASSWORD || pw !== ADMIN_PASSWORD) return res.status(403).json({ error:'admin password required' });
  req.email = email;
  next();
}

/* overview stats */
app.get('/api/admin/stats', rateLimit(20, 60000), adminAuth, async (req,res)=>{
  const users    = (await pool.query('SELECT COUNT(*)::int c, COALESCE(SUM(balance_usd),0)::float b FROM users')).rows[0];
  const orders   = (await pool.query('SELECT COUNT(*)::int c, COALESCE(SUM(resale_usd),0)::float rev, COALESCE(SUM(cost_usd),0)::float cost FROM orders WHERE refunded=false')).rows[0];
  const refunds  = (await pool.query('SELECT COUNT(*)::int c FROM orders WHERE refunded=true')).rows[0];
  const topups   = (await pool.query('SELECT COUNT(*)::int c, COALESCE(SUM(amount_usd),0)::float t FROM invoices WHERE credited=true')).rows[0];
  res.json({
    users: users.c, walletTotalUSD: users.b,
    ordersSold: orders.c, revenueUSD: orders.rev, supplierCostUSD: orders.cost,
    grossProfitUSD: +(orders.rev - orders.cost).toFixed(2),
    refunds: refunds.c,
    topupsCount: topups.c, topupsTotalUSD: topups.t
  });
});

/* users list */
app.get('/api/admin/users', adminAuth, async (req,res)=>{
  const rows = (await pool.query('SELECT email, balance_usd::float, created_at FROM users ORDER BY created_at DESC LIMIT 500')).rows;
  res.json({ users: rows });
});

/* recent orders */
app.get('/api/admin/orders', adminAuth, async (req,res)=>{
  const rows = (await pool.query('SELECT id, email, cost_usd::float, resale_usd::float, refunded, created_at FROM orders ORDER BY created_at DESC LIMIT 200')).rows;
  res.json({ orders: rows });
});

/* recent top-ups */
app.get('/api/admin/topups', adminAuth, async (req,res)=>{
  const rows = (await pool.query('SELECT order_id, email, amount_usd::float, credited, created_at FROM invoices ORDER BY created_at DESC LIMIT 200')).rows;
  res.json({ topups: rows });
});

/* manual credit a wallet (safe: adds to balance) */
app.post('/api/admin/credit', adminAuth, async (req,res)=>{
  const { email, amountUSD } = req.body;
  const amt = parseFloat(amountUSD);
  if(!email || !amt || amt <= 0) return res.status(400).json({ error:'email and positive amount required' });
  const u = await pool.query('UPDATE users SET balance_usd = balance_usd + $1 WHERE email=$2 RETURNING balance_usd::float', [amt, email]);
  if(u.rowCount === 0) return res.status(404).json({ error:'no such user' });
  console.log('ADMIN CREDIT', email, '+$'+amt, 'by', req.email);
  res.json({ ok:true, newBalanceUSD: u.rows[0].balance_usd });
});

/* ---------- orders (buy a number) ---------- */
app.post('/api/orders', rateLimit(20, 60000), auth, async (req,res)=>{
  const { service, country } = req.body;

  const prices = await fivesim(`/guest/prices?country=${country}&product=${service}`);
  const MIN_RATE = 15;                          // skip only near-dead operators
  const HARD_SERVICES = ['signal','whatsapp','telegram'];  // pick best-delivery operator for these
  const preferReliability = HARD_SERVICES.includes(service);

  // Build a ranked list of ALL in-stock operators so we can retry if one sells out
  // (fixes WhatsApp "no numbers" race: high-demand numbers sell between check and buy).
  let candidates = [];
  try {
    const ops = prices[country][service];
    for(const [name, info] of Object.entries(ops)){
      if(!info || info.count <= 0) continue;                 // must be in stock
      const rate = (info.rate ?? info.rate24 ?? info.rate168 ?? null);
      const rateVal = (rate === null) ? 0 : rate;
      const passes = (rate === null || rate === 0) ? (info.rate24 == null && info.rate168 == null) : rate >= MIN_RATE;
      candidates.push({ name, cost: info.cost, rate: rateVal, passes });
    }
  } catch(e){ /* no in-stock operators parsed */ }

  if(candidates.length === 0)
    return res.status(400).json({ error:'No numbers available right now, try another country' });

  // Rank operators.
  const GOOD_RATE = 15;   // WhatsApp/Signal/Telegram: prefer operators >=15% success
  if(preferReliability){
    candidates = candidates.filter(c => c.cost <= 3.5);       // skip crazy-expensive
    // GOOD operators (>=15%) first, sorted by rate desc; then POOR ones as last resort
    const good = candidates.filter(c => c.rate >= GOOD_RATE).sort((a,b)=> b.rate - a.rate || a.cost - b.cost);
    const poor = candidates.filter(c => c.rate <  GOOD_RATE).sort((a,b)=> b.rate - a.rate || a.cost - b.cost);
    candidates = good.concat(poor);   // good ones tried first, poor as fallback
  } else {
    candidates.sort((a,b)=> (b.passes - a.passes) || (a.cost - b.cost));
  }

  // Try operators in order until one actually sells us a number (up to 4 tries)
  let order = null, cheapest = 0;
  for(let i = 0; i < Math.min(candidates.length, 4); i++){
    const cand = candidates[i];
    const o = await fivesim(`/user/buy/activation/${country}/${cand.name}/${service}`);
    if(!o._error && (o.status === 'PENDING' || o.status === 'RECEIVED')){
      order = o; cheapest = cand.cost;
      console.log('BUY OK', service, country, '| operator=', cand.name, '| rate=', cand.rate, '| id=', o.id, '| phone=', o.phone);
      break;                 // success
    }
    // otherwise this operator sold out / errored -> try the next candidate
  }

  if(!order)
    return res.status(400).json({ error:'No numbers available for this service/country right now. Please try another country.' });

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
  console.log('SMS-CHECK', req.params.id, '| status=', d.status, '| sms=', JSON.stringify(d.sms||[]).slice(0,200));
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
