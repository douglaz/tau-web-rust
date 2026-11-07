// Independent request verifier for the local provider fixture. No authorization is logged.
import {createHash, createECDH} from 'node:crypto';
export const digest = bytes => createHash('sha256').update(bytes).digest();
const p = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn;
const n = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const mod = (x, m = p) => (x % m + m) % m;
const pow = (x, e) => { let r = 1n; for (; e; e >>= 1n, x = mod(x*x)) if (e & 1n) r = mod(r*x); return r; };
const infinity = [0n, 1n, 0n];
const point = (x, y) => [x, y, 1n];
const generator = point(0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n, 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n);
const double = ([x,y,z]) => {
  if (!z || !y) return infinity;
  const a=mod(x*x), b=mod(y*y), c=mod(b*b), d=mod(2n*((x+b)*(x+b)-a-c)), e=3n*a, f=mod(e*e), X=mod(f-2n*d);
  return [X,mod(e*(d-X)-8n*c),mod(2n*y*z)];
};
const add = (a,b) => {
  if (!a[2]) return b; if (!b[2]) return a;
  const [x,y,z]=a, [X,Y,Z]=b, u=mod(x*Z*Z), U=mod(X*z*z), s=mod(y*Z*Z*Z), S=mod(Y*z*z*z);
  if (u===U) return s===S ? double(a) : infinity;
  const h=mod(U-u), r=mod(S-s), hh=mod(h*h), hhh=mod(h*hh), v=mod(u*hh), xx=mod(r*r-hhh-2n*v);
  return [xx,mod(r*(v-xx)-s*hhh),mod(h*z*Z)];
};
const multiply = (k,P) => {let r=infinity;for(;k;k>>=1n,P=double(P)) if(k&1n)r=add(r,P);return r;};
const integer = bytes => BigInt('0x'+Buffer.from(bytes).toString('hex'));
export const publicIdentity = secret => {const ecdh=createECDH('secp256k1');ecdh.setPrivateKey(Buffer.from(secret,'hex'));return ecdh.getPublicKey(null,'uncompressed').subarray(1,33).toString('hex');};
export class IdenticalReplay extends Error {
  constructor() { super('identical signed transport replay'); this.name='IdenticalReplay'; }
}
export function acceptRequest(accepted, event, header, url, method, body) {
  accepted.set(event.id, {header,url,method,body:Buffer.from(body)});
}
export function verifyRequest(header, url, method, body, expected, accepted, nowSeconds=Date.now()/1000) {
  if (typeof header!=='string' || !header.startsWith('Nostr ')) throw Error('missing request authorization');
  const event=JSON.parse(Buffer.from(header.slice(6),'base64').toString());
  if (event.pubkey!==expected || event.kind!==27235 || event.content!=='' || !Number.isSafeInteger(event.created_at) || Math.abs(nowSeconds-event.created_at)>60) throw Error('request identity or time');
  const canonical=JSON.stringify([0,event.pubkey,event.created_at,event.kind,event.tags,event.content]);
  const message=digest(canonical);
  if (message.toString('hex')!==event.id) throw Error('unbound event');
  const tags=name=>event.tags.filter(t=>t[0]===name).map(t=>t[1]);
  if (JSON.stringify(tags('u'))!==JSON.stringify([url]) || JSON.stringify(tags('method'))!==JSON.stringify([method]) || !tags('nonce')[0]) throw Error('request binding');
  if (body.length ? JSON.stringify(tags('payload'))!==JSON.stringify([digest(body).toString('hex')]) : tags('payload').length) throw Error('request body binding');
  if (!/^[0-9a-f]{128}$/.test(event.sig)) throw Error('signature encoding');
  const bytes=Buffer.from(event.sig,'hex'), r=integer(bytes.subarray(0,32)), s=integer(bytes.subarray(32)), x=BigInt('0x'+event.pubkey);
  if (r>=p || s>=n || x>=p) throw Error('signature scalar');
  let y=pow(mod(x*x*x+7n),(p+1n)/4n);if(mod(y*y)!==mod(x*x*x+7n))throw Error('public point');if(y&1n)y=p-y;
  const tag=digest('BIP0340/challenge');
  const e=integer(digest(Buffer.concat([tag,tag,bytes.subarray(0,32),Buffer.from(event.pubkey,'hex'),message])))%n;
  const R=add(multiply(s,generator),multiply(mod(-e,n),point(x,y)));
  if (!R[2]) throw Error('signature infinity');
  const inv=pow(R[2],p-2n), rx=mod(R[0]*inv*inv), ry=mod(R[1]*inv*inv*inv);
  if (rx!==r || (ry&1n)) throw Error('request signature');
  const prior=accepted.get(event.id);
  if (prior) {
    if (prior.header===header && prior.url===url && prior.method===method && prior.body.equals(body)) throw new IdenticalReplay();
    throw Error('nonidentical reused event');
  }
  return event;
}

// Synthetic fixture authorization for verifier/counter negative controls only.
export function fixtureAuthorization(secret, url, method, body=Buffer.alloc(0), nonce='counter-control') {
  let d=BigInt('0x'+secret);
  const key=createECDH('secp256k1');key.setPrivateKey(Buffer.from(secret,'hex'));
  const publicBytes=key.getPublicKey(null,'uncompressed');
  if (publicBytes[64]&1) d=n-d;
  const pubkey=publicBytes.subarray(1,33).toString('hex');
  const tags=[['u',url],['method',method],['nonce',nonce]];
  if(body.length)tags.push(['payload',digest(body).toString('hex')]);
  const event={pubkey,created_at:Math.floor(Date.now()/1000),kind:27235,tags,content:''};
  const message=digest(JSON.stringify([0,event.pubkey,event.created_at,event.kind,event.tags,event.content]));
  let k=integer(digest(Buffer.concat([Buffer.from(secret,'hex'),message])))%n;
  if(!k)throw Error('synthetic nonce');
  const ephemeral=createECDH('secp256k1');ephemeral.setPrivateKey(Buffer.from(k.toString(16).padStart(64,'0'),'hex'));
  const R=ephemeral.getPublicKey(null,'uncompressed');if(R[64]&1)k=n-k;
  const r=R.subarray(1,33),tag=digest('BIP0340/challenge');
  const challenge=integer(digest(Buffer.concat([tag,tag,r,Buffer.from(pubkey,'hex'),message])))%n;
  event.id=message.toString('hex');
  event.sig=r.toString('hex')+mod(k+challenge*d,n).toString(16).padStart(64,'0');
  return 'Nostr '+Buffer.from(JSON.stringify(event)).toString('base64');
}

// Alternative spellings stay in fixture memory and never enter result output.
export function signatureForms(signature) {
  let letter=0;
  return [Buffer.from(signature,'hex').toString('base64'),signature.toUpperCase(),signature.replace(/[a-f]/g,c=>++letter%2?c.toUpperCase():c)];
}
