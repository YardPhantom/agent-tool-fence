#!/usr/bin/env node
// Usage:
//   node cli.js <policy.yaml|json> '<call json>'
//   node cli.js simulate <policy.yaml|json> <calls.jsonl|-> [--json]
const fs = require('fs'); const { parsePolicy, evaluate, validatePolicy, simulateBatch, formatSimulation } = require('./src/fence');
const argv = process.argv.slice(2);
const usage = "usage:\n  node cli.js policies/guest.yaml '{\"tool\":\"web.search\",\"args\":{\"query\":\"hi\"}}'\n  node cli.js simulate policies/owner.json policies/sample-batch.jsonl [--json]";
function loadPolicy(pf) {
  const policy = parsePolicy(fs.readFileSync(pf, 'utf8')); const errs = validatePolicy(policy);
  if (errs.length) { console.error(errs.join('\n')); process.exit(2); } return policy;
}
if (argv[0] === 'simulate') {
  const json = argv.includes('--json'); const [pf, bf] = argv.slice(1).filter((a) => a !== '--json');
  if (!pf || !bf) { console.error(usage); process.exit(2); }
  const sim = simulateBatch(loadPolicy(pf), fs.readFileSync(bf === '-' ? 0 : bf, 'utf8'));
  process.stdout.write(json ? JSON.stringify(sim, null, 2) + '\n' : formatSimulation(sim));
  process.exit(sim.summary.errors ? 2 : sim.summary.deny ? 1 : 0);
}
const [pf, cj] = argv;
if (!pf || !cj) { console.error(usage); process.exit(2); }
const r = evaluate(loadPolicy(pf), JSON.parse(cj)); console.log(JSON.stringify(r, null, 2)); process.exit(r.decision === 'deny' ? 1 : 0);
