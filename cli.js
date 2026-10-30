#!/usr/bin/env node
// Usage: node cli.js <policy.yaml|json> '<call json>'
const fs = require('fs'); const { parsePolicy, evaluate, validatePolicy } = require('./src/fence');
const [pf, cj] = process.argv.slice(2);
if (!pf || !cj) { console.error("usage: node cli.js policies/guest.yaml '{\"tool\":\"web.search\",\"args\":{\"query\":\"hi\"}}'"); process.exit(2); }
const policy = parsePolicy(fs.readFileSync(pf, 'utf8')); const errs = validatePolicy(policy);
if (errs.length) { console.error(errs.join('\n')); process.exit(2); }
const r = evaluate(policy, JSON.parse(cj)); console.log(JSON.stringify(r, null, 2)); process.exit(r.decision === 'deny' ? 1 : 0);
