/* Local HTTP server. Serves public assets only, binds loopback, accepts no
 * password body, and emits no access/error logs containing request content.
 * npm start (or simply node serve.cjs) → http://127.0.0.1:8080
 */
'use strict';
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const root = path.join(__dirname, 'dist');
const port = Number(process.env.SENTINEL_PORT || 8080);
if (!Number.isInteger(port) || port < 1024 || port > 65535) throw new Error('SENTINEL_PORT must be an integer from 1024 to 65535.');
const csp = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; worker-src 'self'; connect-src https://api.pwnedpasswords.com; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; object-src 'none'";
const headers = {
  'Cache-Control':'no-store, max-age=0', 'Pragma':'no-cache',
  'Content-Security-Policy':csp, 'X-Content-Type-Options':'nosniff',
  'Referrer-Policy':'no-referrer', 'X-Frame-Options':'DENY',
  'Permissions-Policy':'camera=(), microphone=(), geolocation=(), payment=()',
  'Cross-Origin-Opener-Policy':'same-origin',
  'Cross-Origin-Resource-Policy':'same-origin'
};
const types = { '.html':'text/html; charset=utf-8','.js':'application/javascript; charset=utf-8','.css':'text/css; charset=utf-8','.txt':'text/plain; charset=utf-8','.zip':'application/zip' };
const server = http.createServer((req, res) => {
  try {
    if (req.method !== 'GET' && req.method !== 'HEAD') { res.writeHead(405, {...headers, Allow:'GET, HEAD'}); res.end(); return; }
    const url = new URL(req.url, 'http://127.0.0.1');
    // Queries and traversal attempts are not necessary for this application.
    if (url.search) { res.writeHead(400, headers); res.end('Bad request'); return; }
    const pathname = decodeURIComponent(url.pathname);
    if (pathname.includes('\0') || pathname.includes('\\')) { res.writeHead(400, headers); res.end('Bad request'); return; }
    const file = path.resolve(root, '.' + (pathname === '/' ? '/index.html' : pathname));
    if (!file.startsWith(root + path.sep)) { res.writeHead(403, headers); res.end('Forbidden'); return; }
    fs.stat(file, (error, stat) => {
      if (error || !stat.isFile()) { res.writeHead(404, headers); res.end('Not found'); return; }
      res.writeHead(200, {...headers, 'Content-Type':types[path.extname(file)] || 'application/octet-stream', 'Content-Length':stat.size});
      if (req.method === 'HEAD') { res.end(); return; }
      const stream = fs.createReadStream(file);
      stream.on('error', () => { res.destroy(); });
      stream.pipe(res);
    });
  } catch { res.writeHead(400, headers); res.end('Bad request'); }
});
server.on('clientError', (_error, socket) => { socket.end('HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n'); });
server.on('error', () => { process.stderr.write('Local server could not start. Check that the selected port is available.\n'); process.exitCode = 1; });
server.listen(port, '127.0.0.1', () => { process.stdout.write('Sentinel running at http://127.0.0.1:' + port + '\n'); });
