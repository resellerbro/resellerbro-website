// Reseller Bro Founding 100 — isolated Cloudflare Worker source.
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
  if(request.headers.get('origin')!==env.SITE_ORIGIN)return reply({error:'Invalid origin'},403);
  let payload;try{payload=await request.json();}catch{return reply({error:'Invalid JSON'},400);}
  const email=str(payload.email,254).toLowerCase(),name=str(payload.name,200),referral=str(payload.referral_code,64).toUpperCase();
  if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))return reply({error:'Valid email required'},400);
  // Idempotency key is client-supplied UUID; one hold per request. Limit request size and add Turnstile/rate limiting before production.
  const token=str(payload.request_id,64);
  if(!/^[0-9a-f-]{36}$/i.test(token))return reply({error:'Invalid request ID'},400);
  const hold='pending:'+token;
  await env.FOUNDING_DB.prepare("DELETE FROM founding_checkout_holds WHERE expires_at < datetime('now')").run();
  const reserved=await env.FOUNDING_DB.prepare(`INSERT INTO founding_checkout_holds(checkout_session_id,customer_email,referral_code,expires_at)
    SELECT ?,?,?,datetime('now','+30 minutes') WHERE
    (SELECT COUNT(*) FROM founding_reservations WHERE status='paid' AND stripe_mode=?) +
    (SELECT COUNT(*) FROM founding_checkout_holds WHERE expires_at > datetime('now')) < 100
    AND NOT EXISTS (SELECT 1 FROM founding_reservations WHERE lower(customer_email)=? AND status='paid' AND stripe_mode=?)
    ON CONFLICT(checkout_session_id) DO NOTHING`).bind(hold,email,referral,env.STRIPE_MODE,email,env.STRIPE_MODE).run();
  if(!reserved.meta?.changes){
    const existing=await env.FOUNDING_DB.prepare('SELECT checkout_session_id FROM founding_checkout_holds WHERE checkout_session_id=?').bind(hold).first();
    return reply({error:existing?'Checkout already started; wait before retrying':'No spots available or already reserved'},409);
  }
  try{
    const p=new URLSearchParams();
    p.set('mode','payment');p.set('customer_email',email);p.set('client_reference_id',token);
    p.set('line_items[0][price_data][currency]','usd');p.set('line_items[0][price_data][unit_amount]','799');
    p.set('line_items[0][price_data][product_data][name]','Reseller Bro — Founding 100 Reservation');
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
  if(!hold){console.error('Unrecognized or expired hold for paid checkout',s.id);return reply({error:'Payment requires manual reconciliation'},500);}
  try{
    // D1 batch is transactional. Database triggers enforce <=100 paid members and unique paid email.
    await env.FOUNDING_DB.batch([
      env.FOUNDING_DB.prepare("INSERT INTO founding_reservations(stripe_checkout_session_id,stripe_payment_intent_id,stripe_customer_id,customer_email,customer_name,referral_code,amount_paid_cents,currency,status,stripe_mode) VALUES (?,?,?,?,?,?,?,?,?,?) ON CONFLICT(stripe_checkout_session_id) DO NOTHING").bind(s.id,typeof s.payment_intent==='string'?s.payment_intent:null,typeof s.customer==='string'?s.customer:null,email,str(s.customer_details?.name,200),hold.referral_code||'',799,'usd','paid',env.STRIPE_MODE),
      env.FOUNDING_DB.prepare('DELETE FROM founding_checkout_holds WHERE checkout_session_id=?').bind(s.id),
      env.FOUNDING_DB.prepare('INSERT OR IGNORE INTO founding_webhook_events(stripe_event_id,event_type,stripe_mode) VALUES(?,?,?)').bind(event.id,event.type,env.STRIPE_MODE)
    ]);
  }catch(err){console.error('Payment not recorded; requires reconciliation',s.id,String(err));return reply({error:'Unable to record payment'},500);}
  return reply({received:true});
}
export default {async fetch(request,env){
  const path=new URL(request.url).pathname;
  if(!isConfigured(env))return reply({error:'Payment integration not configured'},503);
  if(path==='/stripe/webhook'&&request.method==='POST')return webhook(request,env);
  if(path==='/founding/checkout'&&request.method==='POST')return checkout(request,env);
  if(path==='/founding/availability'&&request.method==='GET'){
    const row=await env.FOUNDING_DB.prepare("SELECT (SELECT COUNT(*) FROM founding_reservations WHERE status='paid' AND stripe_mode=?) paid, (SELECT COUNT(*) FROM founding_checkout_holds WHERE expires_at > datetime('now')) held").bind(env.STRIPE_MODE).first();
    return reply({available:Math.max(0,100-Number(row.paid||0)-Number(row.held||0))});
  }
  return reply({error:'Not found'},404);
}};
