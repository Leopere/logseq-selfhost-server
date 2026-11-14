// Copyright (c) 2026 Colin Knapp, https://colinknapp.com
// SPDX-License-Identifier: AGPL-3.0-only
iyb=function(){
  var channel=gyb();
  vra(channel,function(ready){
    if(ready){
      $APP.fh(new $APP.G(null,1,5,$APP.H,[hyb],null));
      if(!window.__logseqSelfhostRenewal){
        window.__logseqSelfhostRenewal=setInterval(function(){gyb()},3600000);
      }
    }
  });
  return channel;
};
