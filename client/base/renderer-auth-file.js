// Copyright (c) 2026 Colin Knapp, https://colinknapp.com
// SPDX-License-Identifier: AGPL-3.0-only
Vxb=function(){
  // Main owns the private native auth file; the upstream filesystem writer
  // creates replacement files with its own default permissions.
  return window.apis.refreshSelfhostSession().then(function(){return null}).catch(function(){
    console.warn("Selfhost private auth publication failed");
    return null;
  });
};
