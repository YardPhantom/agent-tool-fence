// agent-tool-fence: evaluate a proposed agent tool call against an allowlist policy.
// Works in Node (CommonJS) and the browser (window.ToolFence). No dependencies.
(function (root) {
  'use strict';

  function globToRegExp(glob) {
    const esc = String(glob).replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*').replace(/\?/g, '.');
    return new RegExp('^' + esc + '$');
  }
  const matches = (pattern, value) => globToRegExp(pattern).test(String(value));

  function checkArg(name, rule, value) {
    if (value === undefined) return rule.required ? `argument "${name}" is required` : null;
    if (rule.oneOf && !rule.oneOf.includes(value)) return `argument "${name}" must be one of ${JSON.stringify(rule.oneOf)}`;
    if (rule.pattern && !rule.pattern.some((p) => matches(p, value))) return `argument "${name}"="${value}" does not match ${JSON.stringify(rule.pattern)}`;
    if (rule.deny && rule.deny.some((p) => matches(p, value))) return `argument "${name}"="${value}" hits deny pattern`;
    if (typeof rule.max === 'number' && Number(value) > rule.max) return `argument "${name}"=${value} exceeds max ${rule.max}`;
    if (typeof rule.min === 'number' && Number(value) < rule.min) return `argument "${name}"=${value} below min ${rule.min}`;
    if (typeof rule.maxLength === 'number' && String(value).length > rule.maxLength) return `argument "${name}" longer than ${rule.maxLength}`;
    return null;
  }

  /**
   * evaluate(policy, call) -> { decision: 'allow'|'deny'|'confirm', rule, reason }
   * policy: { name, default: 'deny'|'allow', rules: [{ id, tool, effect, args, allowExtraArgs, reason }] }
   * call:   { tool: string, args: object }
   * First matching rule wins; deny rules are checked before allow rules.
   */
  function evaluate(policy, call) {
    if (!call || typeof call.tool !== 'string') return { decision: 'deny', rule: null, reason: 'malformed call: missing tool name' };
    const args = call.args || {};
    const rules = (policy.rules || []).filter((r) => matches(r.tool, call.tool));
    const ordered = rules.filter((r) => r.effect === 'deny').concat(rules.filter((r) => r.effect !== 'deny'));
    const misses = [];
    for (const rule of ordered) {
      const problems = [];
      const spec = rule.args || {};
      for (const [k, r] of Object.entries(spec)) { const p = checkArg(k, r, args[k]); if (p) problems.push(p); }
      if (!rule.allowExtraArgs) for (const k of Object.keys(args)) if (!(k in spec)) problems.push(`unexpected argument "${k}"`);
      if (rule.effect === 'deny') {
        // A deny rule fires when its arg constraints are satisfied (i.e. it matches).
        if (problems.length === 0) return { decision: 'deny', rule: rule.id, reason: rule.reason || `denied by rule ${rule.id}` };
        continue;
      }
      if (problems.length === 0) return { decision: rule.effect || 'allow', rule: rule.id, reason: rule.reason || `allowed by rule ${rule.id}` };
      misses.push(`${rule.id}: ${problems.join('; ')}`);
    }
    const def = policy.default || 'deny';
    const reason = misses.length ? `no rule satisfied (${misses.join(' | ')})` : `no rule for tool "${call.tool}"; default ${def}`;
    return { decision: def, rule: null, reason };
  }

  function validatePolicy(policy) {
    const errs = [];
    if (!policy || typeof policy !== 'object') return ['policy must be an object'];
    if (!Array.isArray(policy.rules)) errs.push('rules must be an array');
    if (policy.default && !['allow', 'deny', 'confirm'].includes(policy.default)) errs.push('default must be allow|deny|confirm');
    (policy.rules || []).forEach((r, i) => {
      if (!r.id) errs.push(`rules[${i}] missing id`);
      if (!r.tool) errs.push(`rules[${i}] missing tool`);
      if (r.effect && !['allow', 'deny', 'confirm'].includes(r.effect)) errs.push(`rules[${i}] bad effect`);
    });
    return errs;
  }

  // Minimal YAML subset parser (maps, lists, scalars, inline [a, b]) so policies can be YAML without deps.
  function parseYaml(text) {
    const lines = text.split(/\r?\n/).map((l) => l.replace(/\s+#.*$/, '')).filter((l) => l.trim() && !l.trim().startsWith('#'));
    let i = 0;
    const indent = (l) => l.match(/^ */)[0].length;
    function scalar(v) {
      v = v.trim();
      if (v === '{}') return {};
      if (v.startsWith('[') && v.endsWith(']')) return v.slice(1, -1).split(',').map((s) => s.trim()).filter(Boolean).map(scalar);
      if (/^".*"$/.test(v)) { try { return JSON.parse(v); } catch (e) { return v.slice(1, -1); } }
      if (/^'.*'$/.test(v)) return v.slice(1, -1);
      if (v === 'true') return true; if (v === 'false') return false; if (v === 'null' || v === '~') return null;
      if (/^-?\d+(\.\d+)?$/.test(v)) return Number(v);
      return v;
    }
    function block(level) {
      if (lines[i].trim().startsWith('- ')) {
        const arr = [];
        while (i < lines.length && indent(lines[i]) === level && lines[i].trim().startsWith('- ')) {
          const rest = lines[i].trim().slice(2);
          if (/^[\w.-]+:( |$)/.test(rest)) { lines[i] = ' '.repeat(level + 2) + rest; arr.push(block(level + 2)); }
          else { arr.push(scalar(rest)); i++; }
        }
        return arr;
      }
      const obj = {};
      while (i < lines.length && indent(lines[i]) === level) {
        const m = lines[i].trim().match(/^([\w.-]+):\s*(.*)$/);
        if (!m) throw new Error('YAML parse error near: ' + lines[i]);
        i++;
        if (m[2] !== '') obj[m[1]] = scalar(m[2]);
        else obj[m[1]] = i < lines.length && indent(lines[i]) > level ? block(indent(lines[i])) : (i < lines.length && indent(lines[i]) === level && lines[i].trim().startsWith('- ') ? block(level) : null);
      }
      return obj;
    }
    return lines.length ? block(indent(lines[0])) : {};
  }

  function parsePolicy(text) {
    const t = text.trim();
    return t.startsWith('{') ? JSON.parse(t) : parseYaml(t);
  }


  // Serialize a policy object to the YAML subset that parseYaml reads back (round-trip safe).
  function toYaml(value) {
    const q = (v) => {
      if (v === null || v === undefined) return 'null';
      if (typeof v === 'number' || typeof v === 'boolean') return String(v);
      const str = String(v);
      return /^[\w./@*?-][\w ./@*?,-]*$/.test(str) && !/^(true|false|null|~|-?\d+(\.\d+)?)$/.test(str) && !/[ ,]$/.test(str) && !str.includes(',') ? str : JSON.stringify(str);
    };
    const isObj = (v) => v && typeof v === 'object' && !Array.isArray(v);
    const scalarList = (a) => a.every((x) => (!x || typeof x !== 'object') && !/[,\[\]]/.test(String(x)));
    function emit(v, pad) {
      const out = [];
      if (Array.isArray(v)) {
        for (const item of v) {
          if (isObj(item)) {
            const sub = emit(item, pad + '  ');
            out.push(pad + '- ' + sub[0].trimStart(), ...sub.slice(1));
          } else out.push(pad + '- ' + q(item));
        }
      } else {
        for (const [k, val] of Object.entries(v)) {
          if (Array.isArray(val) && scalarList(val)) out.push(`${pad}${k}: [${val.map(q).join(', ')}]`);
          else if (Array.isArray(val) || isObj(val)) {
            if ((Array.isArray(val) ? val.length : Object.keys(val).length) === 0) { out.push(`${pad}${k}: ${Array.isArray(val) ? '[]' : '{}'}`); continue; }
            out.push(`${pad}${k}:`, ...emit(val, pad + '  '));
          } else out.push(`${pad}${k}: ${q(val)}`);
        }
      }
      return out;
    }
    return emit(value, '').join('\n') + '\n';
  }

  /**
   * createAuditLog({ now }) -> { record(policy, call, result), entries(), clear(), toJSON() }
   * Keeps an in-memory, append-only log of decisions with ISO-8601 timestamps.
   */
  function createAuditLog(opts) {
    const now = (opts && opts.now) || (() => new Date());
    const max = (opts && opts.max) || 1000;
    let log = [];
    return {
      record(policy, call, result) {
        const entry = {
          seq: log.length ? log[log.length - 1].seq + 1 : 1,
          timestamp: new Date(now()).toISOString(),
          policy: (policy && policy.name) || null,
          tool: call && call.tool,
          args: JSON.parse(JSON.stringify((call && call.args) || {})),
          decision: result.decision, rule: result.rule, reason: result.reason,
        };
        log.push(entry); if (log.length > max) log = log.slice(-max);
        return entry;
      },
      evaluate(policy, call) { const r = evaluate(policy, call); this.record(policy, call, r); return r; },
      entries() { return log.slice(); },
      clear() { log = []; },
      toJSON() { return { exportedAt: new Date(now()).toISOString(), count: log.length, entries: log.slice() }; },
    };
  }

  function serializePolicy(policy, format) {
    return format === 'json' ? JSON.stringify(policy, null, 2) + '\n' : toYaml(policy);
  }

  // Dry-run a batch of calls (JSONL text or array) against a policy. Never executes anything.
  function simulateBatch(policy, input) {
    const items = [];
    if (Array.isArray(input)) input.forEach((c, i) => items.push({ line: i + 1, call: c }));
    else String(input || '').split(/\r?\n/).forEach((raw, i) => {
      const t = raw.trim(); if (!t || t.startsWith('#') || t.startsWith('//')) return;
      try { items.push({ line: i + 1, call: JSON.parse(t) }); } catch (e) { items.push({ line: i + 1, error: 'invalid JSON: ' + e.message }); }
    });
    const results = items.map(({ line, call, error }) => {
      if (error) return { line, tool: null, decision: 'deny', rule: null, reason: error, error: true };
      const r = evaluate(policy, call);
      return { line, tool: call && call.tool, decision: r.decision, rule: r.rule, reason: r.reason };
    });
    const summary = { total: results.length, allow: 0, deny: 0, confirm: 0, errors: 0 };
    results.forEach((r) => { summary[r.decision]++; if (r.error) summary.errors++; });
    const byTool = {};
    results.forEach((r) => { const k = r.tool || '(invalid)'; const b = byTool[k] || (byTool[k] = { allow: 0, deny: 0, confirm: 0 }); b[r.decision]++; });
    return { policy: (policy && policy.name) || null, summary, byTool, results };
  }

  function formatSimulation(sim) {
    const rows = [['line', 'tool', 'decision', 'rule', 'reason']].concat(sim.results.map((r) =>
      [String(r.line), String(r.tool || '(invalid)'), r.decision.toUpperCase(), String(r.rule || '-'), String(r.reason || '')]));
    const w = rows[0].map((_, c) => Math.min(60, Math.max(...rows.map((r) => r[c].length))));
    const fmt = (r) => r.map((v, c) => (v.length > w[c] ? v.slice(0, w[c] - 1) + '\u2026' : v).padEnd(w[c])).join('  ').trimEnd();
    const out = [fmt(rows[0]), w.map((n) => '-'.repeat(n)).join('  ')].concat(rows.slice(1).map(fmt));
    const s = sim.summary;
    out.push('', `policy ${sim.policy || '(unnamed)'}: ${s.total} calls \u2014 ${s.allow} allow, ${s.confirm} confirm, ${s.deny} deny` + (s.errors ? ` (${s.errors} invalid lines)` : ''));
    return out.join('\n') + '\n';
  }

  const api = { evaluate, validatePolicy, parsePolicy, parseYaml, toYaml, serializePolicy, createAuditLog, globToRegExp, simulateBatch, formatSimulation };
  if (typeof module !== 'undefined' && module.exports) module.exports = api; else root.ToolFence = api;
})(typeof window !== 'undefined' ? window : globalThis);
