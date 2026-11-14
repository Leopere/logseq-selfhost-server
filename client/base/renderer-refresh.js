// Copyright (c) 2026 Colin Knapp, https://colinknapp.com
// SPDX-License-Identifier: AGPL-3.0-only
gyb=function(){
  var channel=sh(1);
  window.apis.refreshSelfhostSession().then(function(session){
    var previous=localStorage.getItem("refresh-token");
    if(previous&&previous!==session.refreshToken)throw Error("Selfhost wrapping key changed; restore the existing private configuration");
    vfb(session.serverUrl);
    Zxb(session.idToken,session.accessToken,session.refreshToken);
    wra(channel,true);
    channel.tk(null);
  }).catch(function(){
    console.error("Selfhost owner token unavailable; renew it and restart Logseq Selfhost.");
    channel.tk(null);
  });
  return channel;
};
