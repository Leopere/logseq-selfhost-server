// Copyright (c) 2026 Colin Knapp, https://colinknapp.com
// SPDX-License-Identifier: AGPL-3.0-only
oBc=function(){
  var state=$APP.ue(dh(),new $APP.G(null,9,5,$APP.H,[ft,$APP.Us,Aeb,Rxb,Beb,lBc,mBc,nBc,ebb],null));
  state=ft.J(state)==null?$APP.Sg.F(state,ft):state;
  // Expired-token refresh must never fall back to the Logseq Cognito service.
  state=$APP.N.V(state,mBc,"logseq-sync.nixc.us");
  return $APP.N.V(state,nBc,"cisl2-logseq-owner");
};
