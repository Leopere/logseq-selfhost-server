// Copyright (c) 2026 Colin Knapp, https://colinknapp.com
// SPDX-License-Identifier: AGPL-3.0-only
// Fixed VPC edge. The origin validates signed JWTs and retains graph ownership.
const ORIGIN = 'http://sync-origin.internal:8787';
const JWT_PART = /^[A-Za-z0-9_-]{1,8192}$/;
const JWT_SIGNATURE = /^(?:[A-Za-z0-9_-]{43}|[A-Za-z0-9_-]{86})$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const CLIENT_ORIGIN = 'lsp://logseq.com';

function ownerToken(url) {
  const values = url.searchParams.getAll('token');
  if (values.length !== 1) return null;
  const token = values[0];
  const parts = token.split('.');
  if (parts.length !== 3 || !JWT_PART.test(parts[0]) || !JWT_PART.test(parts[1])
      || !JWT_SIGNATURE.test(parts[2]) || token.length > 16384) return null;
  return token;
}

function originURL(requestURL) {
  const target = new URL(requestURL);
  target.protocol = 'http:';
  target.hostname = 'sync-origin.internal';
  target.port = '8787';
  return target;
}

function empty(status) {
  return new Response(null, {status});
}

function corsResponse(response) {
  const headers = new Headers(response.headers);
  headers.set('Access-Control-Allow-Origin', CLIENT_ORIGIN);
  const vary = (headers.get('Vary') ?? '').split(',').map(value => value.trim()).filter(Boolean);
  if (!vary.some(value => value.toLowerCase() === 'origin')) vary.push('Origin');
  headers.set('Vary', vary.join(', '));
  return new Response(response.body, {status: response.status, statusText: response.statusText, headers});
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

export default {
  async fetch(request, env) {
    const incoming = new URL(request.url);
    if (request.method === 'OPTIONS') return preflight(request, incoming);
    const access = route(request, incoming);
    if (access === null) return empty(404);
    if (access === 'method') return empty(405);
    if (access === 'query') return empty(400);
    if (access !== 'websocket') {
      const response = await env.SYNC_ORIGIN.fetch(new Request(originURL(incoming), request));
      if ([401, 403, 404].includes(response.status)) {
        try { await response.body?.cancel(); } catch (_) {}
        return empty(404);
      }
      return request.headers.get('Origin') === CLIENT_ORIGIN ? corsResponse(response) : response;
    }

    const token = ownerToken(incoming);
    if (token === null) return empty(404);

    // The fixed /graphs preflight asks the origin to verify signature, issuer,
    // audience, expiry, and owner. No signing secret or root code enters Worker.
    let authorization;
    try {
      authorization = await env.SYNC_ORIGIN.fetch(new Request(ORIGIN + '/graphs', {
        method: 'GET',
        signal: AbortSignal.timeout(8000),
        headers: {'Authorization': 'Bearer ' + token}
      }));
    } catch (_) {
      return empty(502);
    }
    const authorized = authorization.status === 200;
    const unauthorized = [401, 403, 404].includes(authorization.status);
    try { await authorization.body?.cancel(); } catch (_) {}
    if (!authorized) return empty(unauthorized ? 404 : 502);

    try {
      // Keep the exact client request and return the origin's original 101.
      return await env.SYNC_ORIGIN.fetch(new Request(originURL(incoming), request));
    } catch (_) {
      return empty(502);
    }
  }
};
