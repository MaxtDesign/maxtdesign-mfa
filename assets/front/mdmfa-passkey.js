/*! MaxtDesign MFA passkeys | GPL-2.0-or-later | loaded only on screens that offer a passkey */
(()=>{const d=document,P=window.PublicKeyCredential,C=navigator.credentials;
const b=s=>Uint8Array.from(atob(s.replace(/-/g,"+").replace(/_/g,"/")),c=>c.charCodeAt(0)).buffer;
const e=a=>btoa(String.fromCharCode(...new Uint8Array(a))).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"");
const p=o=>{o.challenge=b(o.challenge);o.user&&(o.user.id=b(o.user.id));for(const k of["excludeCredentials","allowCredentials"])(o[k]||[]).forEach(c=>c.id=b(c.id));return o};
const j=c=>{const r=c.response,o={id:c.id,rawId:e(c.rawId),type:c.type,response:{clientDataJSON:e(r.clientDataJSON)}};
if(r.attestationObject){o.response.attestationObject=e(r.attestationObject);o.response.transports=r.getTransports?r.getTransports():[]}
else{o.response.authenticatorData=e(r.authenticatorData);o.response.signature=e(r.signature);o.response.userHandle=r.userHandle?e(r.userHandle):null}return JSON.stringify(o)};
let a;
const run=async(el,m)=>{const g=JSON.parse(el.dataset.mdmfaPasskey),f=el.closest("form"),o=p(g.options);
a&&a.abort();a=new AbortController;const q={publicKey:o,signal:a.signal};m&&(q.mediation=m);
try{const c=g.mode==="create"?await C.create(q):await C.get(q);f.querySelector('[name="'+g.field+'"]').value=j(c);f.submit()}
catch(x){if(!m&&x.name!=="AbortError"){const w=f.querySelector("[data-mdmfa-error]");w&&(w.hidden=!1)}}};
d.querySelectorAll("[data-mdmfa-passkey]").forEach(el=>{if(!P||!C){return}const g=JSON.parse(el.dataset.mdmfaPasskey);
el.hidden=!1;el.addEventListener("click",v=>{v.preventDefault();run(el)});
g.conditional&&P.isConditionalMediationAvailable&&P.isConditionalMediationAvailable().then(y=>{if(y){const u=d.getElementById(g.conditional);u&&(u.autocomplete="username webauthn");run(el,"conditional")}})})})();
