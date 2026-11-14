// Copyright (c) 2026 Colin Knapp, https://colinknapp.com
// SPDX-License-Identifier: AGPL-3.0-only
case "request-e2ee-password":return $APP.T($APP.S(window.apis.getSelfhostSession()),function(session){
  if(session&&typeof session.rsaPassword==="string"&&session.rsaPassword.length>0){
    return $APP.S(new $APP.M(null,1,[Zv,session.rsaPassword],null));
  }
  return $APP.T($APP.S(null),function(){return $APP.T($APP.S($APP.fh(new $APP.G(null,2,5,$APP.H,[kac,b],null))),function(g){return $APP.T($APP.S(g),function(h){return $APP.S(new $APP.M(null,1,[Zv,h],null))})})});
});
