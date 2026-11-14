// Copyright (c) 2026 Colin Knapp, https://colinknapp.com
// SPDX-License-Identifier: AGPL-3.0-only
'use strict';
function allowedFrame({isMainFrame, href, topLevel}) {
  if (isMainFrame !== true || topLevel !== true) return false;
  try {
    const url = new URL(href);
    return url.protocol === 'lsp:' && url.hostname === 'logseq.com' && url.pathname === '/index.html' &&
      url.port === '' && url.username === '' && url.password === '' && url.search === '';
  } catch (_) { return false; }
}
module.exports = {allowedFrame};
