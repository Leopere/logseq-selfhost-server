// Copyright (c) 2026 Colin Knapp, https://colinknapp.com
// SPDX-License-Identifier: AGPL-3.0-only
'use strict';
require('./public-url.cjs').configurePublicUrl().then(() => {
  require('./owner-auth.cjs').validateEnvironment();
  require('/app/worker/dist/node-adapter.js');
}).catch(() => {
  console.error('Sync startup failed; check public URL and authorization configuration');
  process.exitCode = 1;
});
