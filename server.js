#!/usr/bin/env node
// Tiny static server: serves public/ plus policies/ at /policies. No dependencies.
const http = require('http'), fs = require('fs'), path = require('path');
const PORT = Number(process.env.PORT) || 4173;
const types = { '.html': 'text/html', '.js': 'text/javascript', '.json': 'application/json', '.yaml': 'text/yaml', '.css': 'text/css', '.jsonl': 'text/plain' };
http.createServer((req, res) => {
  let p = decodeURIComponent(req.url.split('?')[0]);
  if (p === '/') p = '/index.html';
  const base = p.startsWith('/policies/') ? __dirname : path.join(__dirname, 'public');
  const file = path.normalize(path.join(base, p));
  if (!file.startsWith(base)) { res.writeHead(403); return res.end(); }
  fs.readFile(file, (err, data) => {
    if (err) { res.writeHead(404); return res.end('not found'); }
    res.writeHead(200, { 'content-type': types[path.extname(file)] || 'application/octet-stream' });
    res.end(data);
  });
}).listen(PORT, () => console.log(`agent-tool-fence demo on http://localhost:${PORT}`));
