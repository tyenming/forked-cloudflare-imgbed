import { dualAuthCheck } from '../utils/auth/dualAuth.js';

export async function onRequest(context) {
    // 获取请求体中URL的内容
    const {
        request,
        env,
        params,
        waitUntil,
        next,
        data
    } = context;

    // 双重鉴权检查
    const url = new URL(request.url);
    const { authorized } = await dualAuthCheck(env, url, request);
    if (!authorized) {
        return new Response(JSON.stringify({ error: 'Unauthorized' }), {
            status: 401,
            headers: { 'Content-Type': 'application/json' }
        });
    }

    const jsonRequest = await request.json();
    const targetUrl = jsonRequest.url;
    if (targetUrl === undefined) {
        return new Response('URL is required', { status: 400 })
    }

    // SSRF protection: block requests to private/internal networks
    let parsed;
    try {
        parsed = new URL(targetUrl);
    } catch {
        return new Response(JSON.stringify({ error: 'Invalid URL' }), {
            status: 400,
            headers: { 'Content-Type': 'application/json' }
        });
    }

    // Only allow http(s) schemes
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
        return new Response(JSON.stringify({ error: 'Only HTTP(S) URLs are allowed' }), {
            status: 400,
            headers: { 'Content-Type': 'application/json' }
        });
    }

    // Block private/reserved IP ranges and cloud metadata endpoints
    const hostname = parsed.hostname.toLowerCase();
    const blockedPatterns = [
        /^localhost$/,
        /^127\./,
        /^10\./,
        /^172\.(1[6-9]|2\d|3[01])\./,
        /^192\.168\./,
        /^169\.254\./,            // link-local / cloud metadata
        /^0\./,
        /^\[::1\]$/,              // IPv6 loopback
        /^\[fc/i,                 // IPv6 unique local
        /^\[fd/i,                 // IPv6 unique local
        /^\[fe80:/i,              // IPv6 link-local
        /^metadata\.google\.internal$/,
    ];

    if (blockedPatterns.some(p => p.test(hostname))) {
        return new Response(JSON.stringify({ error: 'Requests to private/internal addresses are not allowed' }), {
            status: 403,
            headers: { 'Content-Type': 'application/json' }
        });
    }

    const response = await fetch(targetUrl);
    const headers = new Headers(response.headers);
    return new Response(response.body, {
        headers: headers
    })
}