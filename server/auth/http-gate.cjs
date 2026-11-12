'use strict';
// Copyright (c) 2026 Colin Knapp, https://colinknapp.com
// SPDX-License-Identifier: AGPL-3.0-only
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const CLIENT_ORIGIN = 'lsp://logseq.com';

function empty(status) {
  return new Response(null, {status});
}

function preflight(request, url) {
  if (request.headers.get('Origin') !== CLIENT_ORIGIN) return empty(403);
  const method = request.headers.get('Access-Control-Request-Method');
  if (!method || !/^[A-Z]+$/.test(method)) return empty(400);
  const requestedHeaders = request.headers.get('Access-Control-Request-Headers') ?? '';
  const headers = requestedHeaders ? requestedHeaders.split(',').map(value => value.trim().toLowerCase()) : [];
  if (headers.some(value => !['authorization', 'content-type'].includes(value))
      || new Set(headers).size !== headers.length) return empty(400);

  const check = new Request(url, {method, headers: request.headers});
  const access = route(check, url);
  if (access === null) return empty(404);
  if (access === 'method' || access === 'websocket') return empty(405);
  if (access === 'query') return empty(400);
  const responseHeaders = new Headers({
    'Access-Control-Allow-Origin': CLIENT_ORIGIN,
    'Access-Control-Allow-Methods': method,
    'Vary': 'Origin'
  });
  if (headers.length) responseHeaders.set('Access-Control-Allow-Headers', headers.join(', '));
  return new Response(null, {status: 204, headers: responseHeaders});
}

function onlyParams(url, allowed) {
  const keys = [...url.searchParams.keys()];
  return keys.every(key => allowed.includes(key))
    && allowed.every(key => url.searchParams.getAll(key).length <= 1);
}

function route(request, url) {
  const {pathname, searchParams} = url;
  const upgrade = request.headers.get('Upgrade');
  const upgrading = upgrade?.toLowerCase() === 'websocket';
  if (upgrading) {
    if (request.method !== 'GET' || !/^\/sync\/[0-9a-f-]+$/.test(pathname)
        || !UUID.test(pathname.slice('/sync/'.length))) return null;
    return [...searchParams.keys()].every(key => key === 'token') ? 'websocket' : 'query';
  }
  if (upgrade !== null) return null;

  if (pathname === '/health') return request.method !== 'GET' ? 'method' : onlyParams(url, []) ? 'http' : 'query';
  if (pathname === '/graphs' || pathname === '/e2ee/user-keys') {
    if (!['GET', 'POST'].includes(request.method)) return 'method';
    return onlyParams(url, []) ? 'http' : 'query';
  }
  let match = pathname.match(/^\/e2ee\/graphs\/([^/]+)\/aes-key$/);
  if (match && UUID.test(match[1])) {
    if (!['GET', 'POST'].includes(request.method)) return 'method';
    return onlyParams(url, []) ? 'http' : 'query';
  }
  match = pathname.match(/^\/sync\/([^/]+)\/(pull|snapshot\/download|snapshot\/stream|snapshot\/upload)$/);
  if (match && UUID.test(match[1])) {
    const action = match[2];
    if (action === 'snapshot/upload') {
      const keys = ['reset', 'finished', 'checksum'];
      const valid = onlyParams(url, keys)
        && searchParams.getAll('reset').length === 1
        && ['true', 'false'].includes(searchParams.get('reset'))
        && searchParams.getAll('finished').length === 1
        && ['true', 'false'].includes(searchParams.get('finished'))
        && (!searchParams.has('checksum') || searchParams.get('checksum').length <= 4096);
      return request.method === 'POST' ? (valid ? 'http' : 'query') : 'method';
    }
    if (request.method !== 'GET') return 'method';
    return onlyParams(url, []) ? 'http' : 'query';
  }
  match = pathname.match(/^\/assets\/([^/]+)\/([^/]+)$/);
  if (match && UUID.test(match[1]) && /^[0-9a-f-]+\.[A-Za-z0-9]{1,16}$/.test(match[2])) {
    const asset = match[2].split('.')[0];
    if (!UUID.test(asset)) return null;
    if (request.method === 'PUT') return onlyParams(url, []) ? 'http' : 'query';
    if (request.method === 'GET') {
      // Native Logseq also fetches opaque asset bytes with its owner bearer.
      // The origin verifies that token; signed URLs remain a separate form.
      if (onlyParams(url, [])) return 'http';
      const expires = searchParams.get('expires');
      const signature = searchParams.get('signature');
      const exp = Number(expires);
      const valid = onlyParams(url, ['expires', 'signature'])
        && searchParams.getAll('expires').length === 1
        && searchParams.getAll('signature').length === 1
        && /^\d+$/.test(expires ?? '') && Number.isSafeInteger(exp)
        && exp > Math.floor(Date.now() / 1000) && exp <= Math.floor(Date.now() / 1000) + 300
        && /^[0-9a-fA-F]{64}$/.test(signature ?? '');
      return valid ? 'http' : 'query';
    }
    return 'method';
  }
  return null;
}


const {verifyRequest} = require('./owner-auth.cjs');
async function allowRequest(request) {
  try {
    const url = new URL(request.url);
    if (request.method === 'OPTIONS') return preflight(request, url).status === 204;
    if (route(request, url) !== 'http') return false;
    if (url.pathname === '/health') return true;
    // The upstream asset handler validates signature, expiry and ownership.
    if (request.method === 'GET' && url.pathname.startsWith('/assets/') && url.searchParams.has('signature')) return true;
    return !!(await verifyRequest(request));
  } catch (_) { return false; }
}
function normalizeResponse(response) {
  if ([401,403,404].includes(response.status)) {
    response.body?.cancel().catch(() => {});
    return new Response(null, {status:404});
  }
  return response;
}
async function allowUpgrade(request) {
  try {
    const url = new URL(request.url);
    return route(request,url) === 'websocket' && url.searchParams.getAll('token').length === 1 && !!(await verifyRequest(request));
  } catch (_) { return false; }
}
module.exports={allowRequest, allowUpgrade, normalizeResponse};
