// Founding 100 Stripe webhook handler — NOT deployed until sandbox secrets and D1 binding are configured.
// Worker bindings: FOUNDING_DB (D1), STRIPE_WEBHOOK_SECRET (secret), STRIPE_MODE ("test" or "live").
// Stripe webhook endpoint: POST /stripe/webhook
const enc = new TextEncoder();
const json = (data, status = 200) => new Response(JSON.stringify(data), {status, headers: {'content-type':'application/json','cache-control':'no-store'}});
function hex(bytes) { return [...new Uint8Array(bytes)].map(b=>b.toString(16).padStart(2,'0')).join(''); }
async function verifyStripe(body, header, secret) {
  if (!header || !secret) return false;
  const parts = Object.fromEntries(header.split(',').map(x=>x.trim().split('=',2)));
  const timestamp = Number(parts.t);
  if (!Number.isSafeInteger(timestamp) || Math.abs(Date.now()/1000-timestamp)>300) return false;
  const key = await crypto.subtle.importKey('raw', enc.encode(secret), {name:'HMAC',hash:'SHA-256'}, false, ['sign']);
  const signature = hex(await crypto.subtle.sign('HMAC', key, enc.encode(parts.t+'.'+body)));
  const signatures = header.split(',').filter(x=>x.trim().startsWith('v1=')).map(x=>x.trim().slice(3));
  return signatures.some(candidate => candidate.length===signature.length && [...candidate].reduce((acc,ch,i)=>acc|(ch.charCodeAt(0)^signature.charCodeAt(i)),0)===0);
}
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname !== '/stripe/webhook' || request.method !== 'POST') return json({error:'not found'},404);
    if (!env.FOUNDING_DB || !env.STRIPE_WEBHOOK_SECRET || !['test','live'].includes(env.STRIPE_MODE)) return json({error:'not configured'},503);
    const body = await request.text();
    if (!(await verifyStripe(body,request.headers.get('stripe-signature'),env.STRIPE_WEBHOOK_SECRET))) return json({error:'invalid signature'},400);
    let event;
    try { event=JSON.parse(body); } catch { return json({error:'invalid JSON'},400); }
    if (!!event.livemode !== (env.STRIPE_MODE==='live')) return json({error:'wrong Stripe mode'},400);
    if (!event.id || !event.type) return json({error:'invalid event'},400);
    if (event.type!=='checkout.session.completed' && event.type!=='checkout.session.async_payment_succeeded') return json({received:true,ignored:true});
    const s=event.data?.object;
    if (!s || s.object!=='checkout.session' || s.mode!=='payment' || s.payment_status!=='paid' || s.amount_total!==799 || s.currency!=='usd') return json({received:true,ignored:true});
    // Only accept checkout sessions created by our future server-side checkout endpoint.
    // Public Stripe Payment Links must never bypass the reservation limit.
    if (s.metadata?.resellerbro_reservation !== 'founding100') return json({received:true,ignored:true});
    const email=s.customer_details?.email?.trim().toLowerCase();
    if (!email || !s.id) return json({error:'missing customer/session'},422);
    const referral=(s.metadata?.referral_code || '').slice(0,64);
    const name=(s.customer_details?.name || '').slice(0,256);
    try {
      // D1 batch is transactional; duplicate Stripe events and session IDs cannot double count.
      await env.FOUNDING_DB.batch([
        env.FOUNDING_DB.prepare('INSERT OR IGNORE INTO founding_webhook_events (stripe_event_id,event_type,stripe_mode) VALUES (?,?,?)').bind(event.id,event.type,env.STRIPE_MODE),
        env.FOUNDING_DB.prepare("INSERT OR IGNORE INTO founding_reservations (stripe_checkout_session_id,stripe_payment_intent_id,stripe_customer_id,customer_email,customer_name,referral_code,amount_paid_cents,currency,status,stripe_mode) VALUES (?,?,?,?,?,?,?,?,?,?)").bind(s.id,typeof s.payment_intent==='string'?s.payment_intent:null,typeof s.customer==='string'?s.customer:null,email,name,referral,799,'usd','paid',env.STRIPE_MODE)
      ]);
    } catch (e) {
      // Do not acknowledge events we cannot record. Alert operators on capacity/conflict;
      // reconcile any paid session that could not be admitted, including refund handling.
      console.error('Founding webhook persistence failure', String(e));
      return json({error:'reservation not recorded'},500);
    }
    return json({received:true});
  }
};
