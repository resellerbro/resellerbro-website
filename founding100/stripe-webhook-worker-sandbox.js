// Reseller Bro Founding 500 — isolated Cloudflare Worker source.
// NOT LIVE: deploy only after configuring D1, Stripe TEST secrets, allowed origin and webhook.
// Bindings: FOUNDING_DB (D1), STRIPE_SECRET_KEY (secret), STRIPE_WEBHOOK_SECRET (secret),
// STRIPE_MODE ('test' or 'live'), SITE_ORIGIN ('https://resellerbro.com').
// Routes: POST /founding/checkout, POST /stripe/webhook, GET /founding/availability.
// The existing public Stripe Payment Link is intentionally NOT a production reservation path.
const enc = new TextEncoder();
const reply = (data,status=200) => new Response(JSON.stringify(data),{status,headers:{'content-type':'application/json','cache-control':'no-store','access-control-allow-origin':'https://resellerbro.com','vary':'Origin'}});
const str = (v,max=128) => typeof v==='string'?v.trim().slice(0,max):'';
function isConfigured(env) {return env.FOUNDING_DB && env.STRIPE_SECRET_KEY && env.STRIPE_WEBHOOK_SECRET && ['test','live'].includes(env.STRIPE_MODE) && env.SITE_ORIGIN==='https://resellerbro.com' && env.STRIPE_SECRET_KEY.startsWith(env.STRIPE_MODE==='test'?'sk_test_':'sk_live_');}
function bytesHex(b){return Array.from(new Uint8Array(b),x=>x.toString(16).padStart(2,'0')).join('');}
async function validSignature(body,header,secret){
  if(!header || !secret)return false;
  const t=header.split(',').find(p=>p.trim().startsWith('t='))?.trim().slice(2);
  const signatures=header.split(',').filter(p=>p.trim().startsWith('v1=')).map(p=>p.trim().slice(3));
  if(!/^\d+$/.test(t||'') || Math.abs(Date.now()/1000-Number(t))>300 || !signatures.length)return false;
  const key=await crypto.subtle.importKey('raw',enc.encode(secret),{name:'HMAC',hash:'SHA-256'},false,['sign']);
  const expected=bytesHex(await crypto.subtle.sign('HMAC',key,enc.encode(t+'.'+body)));
  return signatures.some(s=>s.length===expected.length && [...s].reduce((v,c,i)=>v|(c.charCodeAt(0)^expected.charCodeAt(i)),0)===0);
}
async function stripe(env,path,params){
  const response=await fetch('https://api.stripe.com/v1/'+path,{method:'POST',headers:{Authorization:'Bearer '+env.STRIPE_SECRET_KEY,'Content-Type':'application/x-www-form-urlencoded','Idempotency-Key':params.get('client_reference_id')},body:params});
  const data=await response.json();
  if(!response.ok)throw Error('Stripe checkout creation failed: '+(data.error?.type||response.status));
  return data;
}
async function releaseHold(db,id){await db.prepare('DELETE FROM founding_checkout_holds WHERE checkout_session_id=?').bind(id).run();}
async function checkout(request,env){
  const origin=request.headers.get('origin');
  const sandboxOrigin='https://resellerbro-founding100-test.gisttttt.workers.dev';
  if(origin!==env.SITE_ORIGIN && !(env.STRIPE_MODE==='test' && origin===sandboxOrigin))return reply({error:'Invalid origin'},403);
  let payload;try{payload=await request.json();}catch{return reply({error:'Invalid JSON'},400);}
  const email=str(payload.email,254).toLowerCase(),name=str(payload.name,200),referralCandidate=str(payload.referral_code,64).toUpperCase();
  if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))return reply({error:'Valid email required'},400);
  // Only active affiliate codes are retained. Unknown, mistyped, or paused codes receive no attribution.
  const affiliate=referralCandidate ? await env.FOUNDING_DB.prepare('SELECT referral_code FROM founding_affiliates WHERE referral_code=? AND active=1').bind(referralCandidate).first() : null;
  const referral=affiliate?.referral_code || '';
  // Idempotency key is client-supplied UUID; one hold per request. Limit request size and add Turnstile/rate limiting before production.
  const token=str(payload.request_id,64);
  if(!/^[0-9a-f-]{36}$/i.test(token))return reply({error:'Invalid request ID'},400);
  const hold='pending:'+token;
  await env.FOUNDING_DB.prepare("DELETE FROM founding_checkout_holds WHERE expires_at < datetime('now')").run();
  const reserved=await env.FOUNDING_DB.prepare(`INSERT INTO founding_checkout_holds(checkout_session_id,customer_email,referral_code,expires_at)
    SELECT ?,?,?,datetime('now','+30 minutes') WHERE
    (SELECT COUNT(*) FROM founding_reservations WHERE status='paid' AND stripe_mode=?) +
    (SELECT COUNT(*) FROM founding_checkout_holds WHERE expires_at > datetime('now')) < 500
    AND NOT EXISTS (SELECT 1 FROM founding_reservations WHERE lower(customer_email)=? AND status='paid' AND stripe_mode=?)
    AND NOT EXISTS (SELECT 1 FROM founding_checkout_holds WHERE lower(customer_email)=? AND expires_at > datetime('now'))
    ON CONFLICT(checkout_session_id) DO NOTHING`).bind(hold,email,referral,env.STRIPE_MODE,email,env.STRIPE_MODE,email).run();
  if(!reserved.meta?.changes){
    const existing=await env.FOUNDING_DB.prepare('SELECT checkout_session_id FROM founding_checkout_holds WHERE checkout_session_id=?').bind(hold).first();
    return reply({error:existing?'Checkout already started; wait before retrying':'No spots available or already reserved'},409);
  }
  try{
    const p=new URLSearchParams();
    p.set('mode','payment');p.set('customer_email',email);p.set('client_reference_id',token);
    p.set('line_items[0][price_data][currency]','usd');p.set('line_items[0][price_data][unit_amount]','799');
    p.set('line_items[0][price_data][product_data][name]','Reseller Bro — Founding 500 Reservation');
    p.set('line_items[0][quantity]','1');
    p.set('metadata[resellerbro_reservation]','founding100');
    p.set('metadata[reservation_hold]',hold);p.set('metadata[referral_code]',referral);
    p.set('metadata[customer_name]',name);
    p.set('expires_at',String(Math.floor(Date.now()/1000)+1800));
    p.set('success_url',env.SITE_ORIGIN+'/?founding_checkout=success&session_id={CHECKOUT_SESSION_ID}#flip');
    p.set('cancel_url',env.SITE_ORIGIN+'/?founding_checkout=cancelled#flip');
    const s=await stripe(env,'checkout/sessions',p);
    if(!s.id||!s.url)throw Error('Missing Stripe session');
    await env.FOUNDING_DB.prepare('UPDATE founding_checkout_holds SET checkout_session_id=? WHERE checkout_session_id=?').bind(s.id,hold).run();
    return reply({url:s.url});
  }catch(err){await releaseHold(env.FOUNDING_DB,hold);console.error('Checkout failed',String(err));return reply({error:'Checkout unavailable'},503);}
}
// Transactional email is isolated from checkout and runs only after a paid reservation is recorded.
const emailEscape = value => String(value ?? '').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
async function notifyFounder(env,sessionId){
  // Sandbox checkout tests must never send real transactional emails.
  if(env.STRIPE_MODE==='test')return;
  if(!env.RESEND_API_KEY)return;
  const row=await env.FOUNDING_DB.prepare("SELECT id,customer_name,customer_email FROM founding_reservations WHERE stripe_checkout_session_id=? AND status='paid' AND stripe_mode=?").bind(sessionId,env.STRIPE_MODE).first();
  if(!row)return;
  const numberRow=await env.FOUNDING_DB.prepare("SELECT COUNT(*) AS n FROM founding_reservations WHERE status='paid' AND stripe_mode=? AND id<=?").bind(env.STRIPE_MODE,row.id).first();
  const founderNumber=Number(numberRow?.n||0);
  if(founderNumber<1||founderNumber>500)throw Error('Invalid founder number for email');
  const name=str(row.customer_name,200)||'Reseller Bro Founder';
  const recipients=[
    {kind:'welcome',to:row.customer_email,subject:'Welcome to the Reseller Bro Founding 500!',html:`<p>Hey ${emailEscape(name)},</p><p>Welcome to the <strong>Reseller Bro Founding 500!</strong> You're Founder #${founderNumber}.</p><p>Your $7.99 reservation was received and will be credited toward your first subscription month when we launch. Your founding $7.99/month rate stays in effect while your subscription remains active.</p><p>We'll email you when Reseller Bro is ready to launch. Thanks for joining the original crew!</p><p>— Reseller Bro</p>`},
    {kind:'owner',to:'joe@resellerbro.com',subject:`New Reseller Bro Founder #${founderNumber}`,html:`<p>New paid Founding 500 reservation.</p><p>Founder #${founderNumber}<br>Name: ${emailEscape(name)}<br>Email: ${emailEscape(row.customer_email)}<br>Payment: $7.99</p>`}
  ];
  for(const message of recipients){
    const sent=await env.FOUNDING_DB.prepare('SELECT 1 FROM founding_email_deliveries WHERE reservation_id=? AND email_kind=?').bind(row.id,message.kind).first();
    if(sent)continue;
    const response=await fetch('https://api.resend.com/emails',{method:'POST',headers:{Authorization:'Bearer '+env.RESEND_API_KEY,'Content-Type':'application/json','Idempotency-Key':`founding-${row.id}-${message.kind}-v1`},body:JSON.stringify({from:'Reseller Bro <notifications@resellerbro.com>',to:[message.to],subject:message.subject,html:message.html})});
    if(!response.ok){console.error('Founder email failed',message.kind,response.status);throw Error('Founder email delivery failed');}
    await env.FOUNDING_DB.prepare('INSERT OR IGNORE INTO founding_email_deliveries(reservation_id,email_kind) VALUES(?,?)').bind(row.id,message.kind).run();
  }
}
async function webhook(request,env){
  const raw=await request.text();
  if(!(await validSignature(raw,request.headers.get('stripe-signature'),env.STRIPE_WEBHOOK_SECRET)))return reply({error:'Invalid signature'},400);
  let event;try{event=JSON.parse(raw);}catch{return reply({error:'Invalid payload'},400);}
  if(!!event.livemode!==(env.STRIPE_MODE==='live'))return reply({error:'Wrong Stripe mode'},400);
  const s=event.data?.object;
  if(!s || s.object!=='checkout.session')return reply({received:true});
  if(!['checkout.session.completed','checkout.session.async_payment_succeeded','checkout.session.expired'].includes(event.type))return reply({received:true});
  if(s.metadata?.resellerbro_reservation!=='founding100')return reply({received:true});
  if(event.type==='checkout.session.expired'){await releaseHold(env.FOUNDING_DB,s.id);return reply({received:true});}
  if(s.payment_status!=='paid'||s.amount_total!==799||s.currency!=='usd'||s.mode!=='payment')return reply({received:true});
  const email=str(s.customer_details?.email,254).toLowerCase();
  if(!email)return reply({error:'Missing email'},422);
  const hold=await env.FOUNDING_DB.prepare('SELECT checkout_session_id,referral_code FROM founding_checkout_holds WHERE checkout_session_id=?').bind(s.id).first();
  if(!hold){
    const recorded=await env.FOUNDING_DB.prepare('SELECT id FROM founding_reservations WHERE stripe_checkout_session_id=? AND status=? AND stripe_mode=?').bind(s.id,'paid',env.STRIPE_MODE).first();
    if(recorded){await env.FOUNDING_DB.prepare('INSERT OR IGNORE INTO founding_webhook_events(stripe_event_id,event_type,stripe_mode) VALUES(?,?,?)').bind(event.id,event.type,env.STRIPE_MODE).run();try{await notifyFounder(env,s.id);}catch(err){console.error('Email retry needed',String(err));return reply({error:'Email retry needed'},500);}return reply({received:true});}
    console.error('Unrecognized or expired hold for paid checkout',s.id);return reply({error:'Payment requires manual reconciliation'},500);
  }
  try{
    // D1 batch is transactional. Database triggers enforce <=500 paid members and unique paid email.
    await env.FOUNDING_DB.batch([
      env.FOUNDING_DB.prepare("INSERT INTO founding_reservations(stripe_checkout_session_id,stripe_payment_intent_id,stripe_customer_id,customer_email,customer_name,referral_code,amount_paid_cents,currency,status,stripe_mode) VALUES (?,?,?,?,?,?,?,?,?,?) ON CONFLICT(stripe_checkout_session_id) DO NOTHING").bind(s.id,typeof s.payment_intent==='string'?s.payment_intent:null,typeof s.customer==='string'?s.customer:null,email,str(s.customer_details?.name,200),hold.referral_code||'',799,'usd','paid',env.STRIPE_MODE),
      env.FOUNDING_DB.prepare('DELETE FROM founding_checkout_holds WHERE checkout_session_id=?').bind(s.id),
      env.FOUNDING_DB.prepare(`INSERT INTO creator_commissions(
        referral_code,affiliate_email,payment_type,founding_reservation_id,stripe_checkout_session_id,
        stripe_payment_intent_id,gross_amount_cents,commission_rate_bps,commission_amount_cents,currency,status
      )
      SELECT a.referral_code,a.affiliate_email,'founding_reservation',r.id,r.stripe_checkout_session_id,
        r.stripe_payment_intent_id,r.amount_paid_cents,a.commission_rate_bps,
        CAST(ROUND(r.amount_paid_cents * a.commission_rate_bps / 10000.0) AS INTEGER),
        r.currency,'pending'
      FROM founding_reservations r
      JOIN founding_affiliates a ON a.referral_code=r.referral_code AND a.active=1
      WHERE r.stripe_checkout_session_id=? AND r.status='paid' AND r.stripe_mode=? AND r.referral_code<>''
      ON CONFLICT DO NOTHING`).bind(s.id,env.STRIPE_MODE),
      env.FOUNDING_DB.prepare('INSERT OR IGNORE INTO founding_webhook_events(stripe_event_id,event_type,stripe_mode) VALUES(?,?,?)').bind(event.id,event.type,env.STRIPE_MODE)
    ]);
  }catch(err){console.error('Payment not recorded; requires reconciliation',s.id,String(err));return reply({error:'Unable to record payment'},500);}
  try{await notifyFounder(env,s.id);}catch(err){console.error('Email retry needed',String(err));return reply({error:'Email retry needed'},500);}
  return reply({received:true});
}
// A Stripe session ID is a bearer credential. Return only minimal confirmation data.
async function confirmation(request,env){
  const url=new URL(request.url);
  const sessionId=url.searchParams.get('session_id')||'';
  if(!/^cs_(test_|live_)[A-Za-z0-9]{10,}$/.test(sessionId))return reply({error:'Invalid checkout reference'},400);
  const row=await env.FOUNDING_DB.prepare("SELECT id,customer_name,amount_paid_cents,first_month_credit_cents FROM founding_reservations WHERE stripe_checkout_session_id=? AND status='paid' AND stripe_mode=?").bind(sessionId,env.STRIPE_MODE).first();
  if(!row)return reply({confirmed:false,pending:true});
  // Confirm directly with Stripe as well as our webhook-recorded database row.
  const response=await fetch('https://api.stripe.com/v1/checkout/sessions/'+encodeURIComponent(sessionId),{headers:{Authorization:'Bearer '+env.STRIPE_SECRET_KEY}});
  if(!response.ok)return reply({error:'Payment verification unavailable'},503);
  const session=await response.json();
  if(session.payment_status!=='paid'||session.amount_total!==799||session.currency!=='usd'||session.mode!=='payment'||session.metadata?.resellerbro_reservation!=='founding100')return reply({confirmed:false,pending:true});
  const count=await env.FOUNDING_DB.prepare("SELECT COUNT(*) AS n FROM founding_reservations WHERE status='paid' AND stripe_mode=? AND id<=?").bind(env.STRIPE_MODE,row.id).first();
  const number=Number(count?.n||0);
  return reply({confirmed:true,member_number:number>=1&&number<=500?number:null,name:str(row.customer_name,200),amount_paid_cents:Number(row.amount_paid_cents),first_month_credit_cents:Number(row.first_month_credit_cents)});
}

export default {async fetch(request,env){
  const path=new URL(request.url).pathname;
  if(request.method==='OPTIONS' && path==='/founding/checkout') {
    if(request.headers.get('origin')!==env.SITE_ORIGIN) return reply({error:'Invalid origin'},403);
    return new Response(null,{status:204,headers:{'access-control-allow-origin':env.SITE_ORIGIN,'access-control-allow-methods':'POST, OPTIONS','access-control-allow-headers':'content-type','access-control-max-age':'600','vary':'Origin'}});
  }
  if(!isConfigured(env))return reply({error:'Payment integration not configured'},503);
  if(path==='/founding/test'&&request.method==='GET'&&env.STRIPE_MODE==='test')return new Response("<!doctype html><html lang=\"en\"><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>Founding 500 — Sandbox Test</title><style>body{background:#101014;color:#f5f5f5;font:16px system-ui;margin:0;padding:40px 18px}main{max-width:430px;margin:auto}h1{color:#ff9b25}label{display:block;margin:20px 0 6px}input{box-sizing:border-box;width:100%;padding:13px;border:1px solid #777;border-radius:8px;background:#222;color:white}button{background:#ff9b25;border:0;border-radius:8px;padding:15px;width:100%;margin-top:24px;font-weight:700;cursor:pointer}small{color:#bcbcbc}#status{min-height:28px;color:#ffd08b}</style><main><h1>Founding 500</h1><p><strong>STRIPE SANDBOX — NO REAL MONEY</strong></p><p>Test the $7.99 reservation checkout. This page is separate from the live website.</p><form id=\"form\"><label for=\"name\">Test name</label><input id=\"name\" autocomplete=\"name\" required maxlength=\"200\" value=\"Founding Test\"><label for=\"email\">Test email</label><input id=\"email\" type=\"email\" autocomplete=\"email\" required maxlength=\"254\" placeholder=\"test@example.com\"><label for=\"referral\">Test creator code</label><input id=\"referral\" maxlength=\"20\" placeholder=\"BROTEST\"><button id=\"go\" type=\"submit\">Open $7.99 test checkout</button></form><p id=\"status\" role=\"status\"></p><small>Use Stripe test card 4242 4242 4242 4242, any future expiration, and any CVC. Do not use a real card.</small></main><script>document.getElementById('referral').value=(new URLSearchParams(location.search).get('ref')||'').toUpperCase();document.getElementById('form').addEventListener('submit',async e=>{e.preventDefault();const b=document.getElementById('go'),s=document.getElementById('status');b.disabled=true;s.textContent='Creating secure Stripe test checkout...';try{const r=await fetch('/founding/checkout',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({name:document.getElementById('name').value,email:document.getElementById('email').value,request_id:crypto.randomUUID(),referral_code:document.getElementById('referral').value})});const d=await r.json();if(!r.ok||!d.url)throw Error(d.error||'Checkout unavailable');const u=new URL(d.url);if(u.protocol!=='https:'||!u.hostname.endsWith('.stripe.com'))throw Error('Unexpected checkout destination');location.assign(d.url)}catch(err){s.textContent=err.message;b.disabled=false}})</script></html>",{headers:{'content-type':'text/html; charset=utf-8','cache-control':'no-store','x-robots-tag':'noindex, nofollow','content-security-policy':"default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"}});
  if(path==='/admin/affiliates/sync'&&request.method==='POST'){
    const expected=env.AFFILIATE_SYNC_SECRET;
    const supplied=request.headers.get('authorization')||'';
    if(!expected||supplied!=='Bearer '+expected)return reply({error:'Unauthorized'},401);
    let payload;try{payload=await request.json();}catch{return reply({error:'Invalid JSON'},400);}
    if(!Array.isArray(payload.affiliates)||payload.affiliates.length>500)return reply({error:'Invalid affiliate list'},400);
    const seen=new Set(), statements=[];
    for(const item of payload.affiliates){
      const code=str(item?.referral_code,20).toUpperCase();
      const email=str(item?.affiliate_email,254).toLowerCase();
      const active=item?.active===true?1:0;
      if(!/^[A-Z][A-Z0-9]{2,19}$/.test(code)||!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)||seen.has(code))return reply({error:'Invalid or duplicate affiliate'},400);
      seen.add(code);
      statements.push(env.FOUNDING_DB.prepare(`INSERT INTO founding_affiliates(referral_code,affiliate_email,commission_rate_bps,active)
        VALUES(?,?,3000,?) ON CONFLICT(referral_code) DO UPDATE SET
        affiliate_email=excluded.affiliate_email,commission_rate_bps=3000,active=excluded.active`).bind(code,email,active));
    }
    try{if(statements.length)await env.FOUNDING_DB.batch(statements);}
    catch(error){console.error('Affiliate sync failed',String(error));return reply({error:'Affiliate sync failed'},503);}
    return reply({ok:true,synced:statements.length});
  }
  if(path==='/admin/affiliates/dashboard'&&request.method==='POST'){
    const expected=env.AFFILIATE_SYNC_SECRET;
    const supplied=request.headers.get('authorization')||'';
    if(!expected||supplied!=='Bearer '+expected)return reply({error:'Unauthorized'},401);
    let payload;try{payload=await request.json();}catch{return reply({error:'Invalid JSON'},400);}
    const code=str(payload.referral_code,20).toUpperCase();
    const email=str(payload.affiliate_email,254).toLowerCase();
    if(!/^[A-Z][A-Z0-9]{2,19}$/.test(code)||!/^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$/.test(email))return reply({error:'Invalid creator'},400);
    const affiliate=await env.FOUNDING_DB.prepare('SELECT referral_code,affiliate_email,commission_rate_bps,active FROM founding_affiliates WHERE referral_code=? AND lower(affiliate_email)=?').bind(code,email).first();
    if(!affiliate)return reply({error:'Creator not found'},404);
    const [referrals,totals,commissions,payouts]=await Promise.all([
      env.FOUNDING_DB.prepare("SELECT COUNT(*) AS count FROM founding_reservations WHERE referral_code=? AND stripe_mode=? AND status='paid'").bind(code,env.STRIPE_MODE).first(),
      env.FOUNDING_DB.prepare("SELECT COALESCE(SUM(CASE WHEN status='pending' THEN commission_amount_cents ELSE 0 END),0) AS pending_cents, COALESCE(SUM(CASE WHEN status='paid' THEN commission_amount_cents ELSE 0 END),0) AS paid_cents, COALESCE(SUM(CASE WHEN status='reversed' THEN commission_amount_cents ELSE 0 END),0) AS reversed_cents, COALESCE(SUM(commission_amount_cents),0) AS earned_cents FROM creator_commissions WHERE referral_code=?").bind(code).first(),
      env.FOUNDING_DB.prepare("SELECT c.id,c.payment_type,c.gross_amount_cents,c.commission_amount_cents,c.currency,c.status,c.created_at,r.customer_email FROM creator_commissions c LEFT JOIN founding_reservations r ON r.id=c.founding_reservation_id WHERE c.referral_code=? ORDER BY c.created_at DESC LIMIT 100").bind(code).all(),
      env.FOUNDING_DB.prepare("SELECT amount_cents,currency,period_start,period_end,payout_reference,created_at,status FROM creator_payouts WHERE referral_code=? ORDER BY created_at DESC LIMIT 50").bind(code).all()
    ]);
    const maskEmail=value=>{const v=str(value,254).toLowerCase(),at=v.indexOf('@');if(at<1)return '';return v[0]+'***'+v.slice(at);};
    return reply({creator:{referral_code:affiliate.referral_code,commission_rate_bps:Number(affiliate.commission_rate_bps),active:!!affiliate.active},referrals:Number(referrals?.count||0),totals:{pending_cents:Number(totals?.pending_cents||0),paid_cents:Number(totals?.paid_cents||0),reversed_cents:Number(totals?.reversed_cents||0),earned_cents:Number(totals?.earned_cents||0)},commissions:(commissions.results||[]).map(row=>({...row,customer_email_masked:maskEmail(row.customer_email),customer_email:undefined,gross_amount_cents:Number(row.gross_amount_cents),commission_amount_cents:Number(row.commission_amount_cents)})),payouts:(payouts.results||[]).map(row=>({...row,amount_cents:Number(row.amount_cents)})),currency:'usd',stripe_mode:env.STRIPE_MODE});
  }
  if(path==='/stripe/webhook'&&request.method==='POST')return webhook(request,env);
  if(path==='/founding/checkout'&&request.method==='POST')return checkout(request,env);
  if(path==='/founding/confirmation'&&request.method==='GET')return confirmation(request,env);
  if(path==='/founding/availability'&&request.method==='GET'){
    const row=await env.FOUNDING_DB.prepare("SELECT (SELECT COUNT(*) FROM founding_reservations WHERE status='paid' AND stripe_mode=?) paid, (SELECT COUNT(*) FROM founding_checkout_holds WHERE expires_at > datetime('now')) held").bind(env.STRIPE_MODE).first();
    return reply({available:Math.max(0,500-Number(row.paid||0)-Number(row.held||0))});
  }
  return reply({error:'Not found'},404);
}};
