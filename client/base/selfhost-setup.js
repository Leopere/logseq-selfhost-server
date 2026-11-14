// Copyright (c) 2026 Colin Knapp, https://colinknapp.com
// SPDX-License-Identifier: AGPL-3.0-only
'use strict';
const form=document.getElementById('setup');
const field=document.getElementById('code');
const button=form.querySelector('button');
const status=document.getElementById('status');
const current=document.getElementById('current-code');
const server=document.getElementById('server-url');
window.syncCodeSetup.current().then(code=>{current.value=code}).catch(()=>{document.getElementById('current-settings').hidden=true;status.textContent='Enter your server URL and an issued sync code to connect.'});
window.syncCodeSetup.currentServer().then(url=>{server.value=url}).catch(()=>{});
document.getElementById('copy-code').addEventListener('click',async()=>{
  try{await window.syncCodeSetup.copy();status.textContent='Code copied.'}catch(_){status.textContent='The code could not be copied.'}
});
document.getElementById('reveal-code').addEventListener('click',event=>{
  current.type=current.type==='password'?'text':'password';event.target.textContent=current.type==='password'?'Show':'Hide';
});
form.addEventListener('submit',async event=>{
  event.preventDefault();
  button.disabled=true;
  status.textContent='Connecting…';
  try {
    const result=await window.syncCodeSetup.submit(field.value.trim(),server.value.trim());
    if(result&&result.ok===true) {
      field.value='';
      status.textContent='Connected. Opening your notes…';
      return;
    }
    status.textContent=result&&typeof result.message==='string'?result.message:'The sync code could not be saved for this device.';
  } catch (_) { status.textContent='The sync code could not be saved for this device.'; }
  button.disabled=false;
});
