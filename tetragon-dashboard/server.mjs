import { createServer } from "node:http";
import { spawn, spawnSync, execSync } from "node:child_process";
import { readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join, resolve } from "node:path";

const __dirname = dirname(fileURLToPath(import.meta.url));
const PORT = parseInt(process.env.TETRAGON_DASH_PORT || "18790", 10);
const TETRA = "/usr/local/bin/tetra";
const OPENCLAW_HOME = process.env.HOME + "/.openclaw";
const SESSIONS_DIR = OPENCLAW_HOME + "/agents/main/sessions";
const POLICIES_DIR = join(__dirname, "policies");
const ALLOWED_POLICY_NAMES = new Set([
  "oc-file-ops", "oc-tool-exec", "oc-llm-api-egress", "oc-skill-sandbox",
  "oc-ks-exec", "oc-ks-net",
]);
const POLICY_NAMES = [
  "oc-llm-api-egress",
  "oc-tool-exec",
  "oc-file-ops",
  "oc-skill-sandbox",
];
const MAX_EVENTS = 5000;

// Some scanner tools (e.g. AI Defense) print a banner to stdout before JSON output.
// Find the first { or [ and parse from there.
function stripBanner(raw) {
  const start = Math.min(
    raw.indexOf("{") === -1 ? Infinity : raw.indexOf("{"),
    raw.indexOf("[") === -1 ? Infinity : raw.indexOf("["),
  );
  return start === Infinity ? raw : raw.slice(start);
}

const EXEC_POLICIES = ["oc-tool-exec", "oc-skill-sandbox"];
const NET_POLICIES = ["oc-llm-api-egress"];
const FILE_POLICIES = ["oc-file-ops", "oc-skill-sandbox"];

class RingBuffer {
  constructor(max) { this.items = []; this.max = max; }
  push(item) { this.items.push(item); if (this.items.length > this.max) this.items.shift(); }
  all() { return this.items; }
  since(d) { return this.items.filter(i => new Date(i.time) >= d); }
  last() { return this.items.length ? this.items[this.items.length - 1] : null; }
  count() { return this.items.length; }
}

const execBuf = new RingBuffer(MAX_EVENTS);
const netBuf = new RingBuffer(MAX_EVENTS);
const fileBuf = new RingBuffer(MAX_EVENTS);
let lastEvent = null;

// --- SessionReader: parse OpenClaw session transcripts for correlation ---
const SESSION_EVENT_MAX = 2000;
const sessionEventBuf = new RingBuffer(SESSION_EVENT_MAX);

function parseSessionLine(line, sessionId) {
  try {
    const obj = JSON.parse(line);
    const ts = obj.timestamp || obj.ts;
    if (!ts) return null;
    const time = new Date(ts).toISOString();
    const ev = { time, sessionId, type: obj.type, id: obj.id };

    if (obj.type === "session") {
      ev.kind = "session_start";
      ev.cwd = obj.cwd;
      return ev;
    }
    if (obj.type === "model_change") {
      ev.kind = "model_change";
      ev.provider = obj.provider;
      ev.modelId = obj.modelId;
      return ev;
    }
    if (obj.type === "message" && obj.message) {
      const msg = obj.message;
      if (msg.role === "user") {
        ev.kind = "user_message";
        const textPart = msg.content?.find(c => c.type === "text");
        ev.text = textPart?.text?.slice(0, 500) || "";
        ev.sender = (ev.text && ev.text.includes("sender")) ? "metadata" : "user";
        return ev;
      }
      if (msg.role === "assistant") {
        const toolUse = msg.content?.find(c => c.type === "tool_use");
        if (toolUse) {
          ev.kind = "tool_call";
          ev.toolName = toolUse.name;
          ev.toolCallId = toolUse.id;
          ev.input = typeof toolUse.input === "string" ? toolUse.input : JSON.stringify(toolUse.input || {}).slice(0, 300);
          return ev;
        }
        ev.kind = "assistant_message";
        return ev;
      }
      if (msg.role === "toolResult") {
        ev.kind = "tool_result";
        ev.toolName = msg.toolName;
        ev.toolCallId = msg.toolCallId;
        const textPart = msg.content?.find(c => c.type === "text");
        ev.resultPreview = textPart?.text?.slice(0, 200) || "";
        return ev;
      }
    }
    if (obj.type === "usage") {
      ev.kind = "usage";
      ev.inputTokens = obj.inputTokens;
      ev.outputTokens = obj.outputTokens;
      ev.estimatedCost = obj.estimatedCost;
      return ev;
    }
    return null;
  } catch { return null; }
}

function loadSessionEvents() {
  try {
    const files = readdirSync(SESSIONS_DIR, { withFileTypes: true })
      .filter(f => f.isFile() && f.name.endsWith(".jsonl"))
      .map(f => ({ name: f.name, path: join(SESSIONS_DIR, f.name), mtime: statSync(join(SESSIONS_DIR, f.name)).mtime }))
      .sort((a, b) => b.mtime - a.mtime)
      .slice(0, 30);
    for (const { path: fp, name } of files) {
      const sessionId = name.replace(".jsonl", "");
      const content = readFileSync(fp, "utf-8");
      const lines = content.split("\n").filter(l => l.trim());
      for (const line of lines) {
        const ev = parseSessionLine(line, sessionId);
        if (ev) sessionEventBuf.push(ev);
      }
    }
  } catch (e) { console.error("[session-reader]", e.message); }
}
loadSessionEvents();
setInterval(loadSessionEvents, 15000);

function startCollector() {
  const args = ["getevents", "-o", "json", ...POLICY_NAMES.flatMap(p => ["--policy-names", p])];
  const child = spawn(TETRA, args, { stdio: ["ignore", "pipe", "pipe"] });
  let buf = "";
  child.stdout.on("data", chunk => {
    buf += chunk.toString();
    const lines = buf.split("\n");
    buf = lines.pop() || "";
    for (const line of lines) {
      if (!line.trim()) continue;
      try { processEvent(JSON.parse(line)); } catch {}
    }
  });
  child.stderr.on("data", d => console.error("[collector]", d.toString().trim()));
  child.on("close", code => { console.error(`[collector] exited ${code}, restarting...`); setTimeout(startCollector, 3000); });
}

function processEvent(ev) {
  const time = ev.time;
  if (time) lastEvent = time;
  const kp = ev.process_kprobe;
  if (!kp) return;
  const pol = kp.policy_name;
  if (!pol) return;
  const proc = kp.process || {};
  const parent = kp.parent || {};

  if (EXEC_POLICIES.includes(pol)) {
    execBuf.push({
      time: time || new Date().toISOString(), policy: pol,
      process: proc.binary || "?", args: proc.arguments || "",
      pid: proc.pid || 0, ppid: parent.pid, cwd: proc.cwd,
    });
  } else if (NET_POLICIES.includes(pol)) {
    const sock = kp.args?.[0]?.sock_arg || {};
    netBuf.push({
      time: time || new Date().toISOString(), policy: pol,
      process: proc.binary || "?", pid: proc.pid || 0,
      local: `${sock.saddr || "?"}:${sock.sport || "?"}`,
      remote: `${sock.daddr || "?"}:${sock.dport || "?"}`,
      proto: sock.protocol || "", family: sock.family || "",
    });
  } else if (FILE_POLICIES.includes(pol)) {
    const fn = kp.function_name || kp.functionName || "";
    let path = "?";
    let operation = "open";
    let content = null;
    let contentSize = 0;
    let contentTruncated = false;
    const a0 = kp.args?.[0];
    const a1 = kp.args?.[1];
    const a2 = kp.args?.[2];

    if (fn === "vfs_write") {
      path = a0?.file_arg?.path || "?";
      operation = "write";
      const rawBytes = a1?.bytes_arg ?? a1?.char_buf_arg;
      if (typeof rawBytes === "string") {
        try {
          content = Buffer.from(rawBytes, "base64").toString("utf-8");
        } catch {
          content = rawBytes;
        }
      }
      const count = a2?.size_arg ?? a2?.uint64_arg;
      if (count != null) contentSize = Number(count);
      if (contentSize > (content?.length ?? 0) * 2) contentTruncated = true;
    } else if (fn === "do_unlinkat") {
      path = a1?.filename_arg ?? a1?.string_arg ?? a1?.path_arg ?? "?";
      if (typeof path === "object" && path?.path) path = path.path;
      operation = "delete";
    } else {
      path = a0?.file_arg?.path || "?";
      operation = "open";
    }

    fileBuf.push({
      time: time || new Date().toISOString(),
      policy: pol,
      process: proc.binary || "?",
      pid: proc.pid || 0,
      ppid: parent?.pid,
      cwd: proc.cwd,
      path,
      operation,
      content: content ?? undefined,
      contentSize: contentSize || undefined,
      contentTruncated: contentTruncated || undefined,
      functionName: fn || undefined,
    });
  }
}

function parseSince(s) {
  if (!s) return null;
  const m = s.match(/^(\d+)(m|h|d)$/);
  if (m) { const ms = { m: 60000, h: 3600000, d: 86400000 }; return new Date(Date.now() - parseInt(m[1]) * ms[m[2]]); }
  const d = new Date(s);
  return isNaN(d.getTime()) ? null : d;
}

function getStatus() {
  try { return execSync("systemctl is-active tetragon-enterprise", { encoding: "utf-8", timeout: 2000 }).trim() === "active" ? "up" : "down"; }
  catch { return "down"; }
}

function apiOverview() {
  const h24 = new Date(Date.now() - 86400000);
  return {
    status: getStatus(), lastEventTime: lastEvent,
    policies: [
      { name: "oc-llm-api-egress", count24h: netBuf.since(h24).length, lastEventTime: netBuf.last()?.time },
      { name: "oc-tool-exec", count24h: execBuf.since(h24).length, lastEventTime: execBuf.last()?.time },
      { name: "oc-file-ops", count24h: fileBuf.since(h24).length, lastEventTime: fileBuf.last()?.time },
      { name: "oc-skill-sandbox", count24h: execBuf.since(h24).filter(e => e.policy === "oc-skill-sandbox").length + fileBuf.since(h24).filter(e => e.policy === "oc-skill-sandbox").length, lastEventTime: fileBuf.last()?.time },
    ],
  };
}

function filterEvents(buf, since, filters = {}) {
  let items = since ? buf.since(since) : buf.all();
  for (const [k, v] of Object.entries(filters)) {
    if (!v) continue;
    items = items.filter(i => String(i[k] ?? "").toLowerCase().includes(v.toLowerCase()));
  }
  return items.reverse();
}

// --- Enricher: known API endpoints (IP/host hints), severity flags ---
const KNOWN_ENDPOINTS = {
  "127.0.0.1:8000": "VLLM local",
  "127.0.0.1:54321": "Tetragon gRPC",
  "127.0.0.1:18789": "OpenClaw gateway",
  "127.0.0.1:18790": "Tetragon dashboard",
  "::1:8000": "VLLM local",
  "::1:18789": "OpenClaw gateway",
};
const SENSITIVE_PATH_PREFIXES = [
  "/.openclaw/credentials/", "/.ssh/", "/.aws/", "/.kube/", "/.config/gcloud/",
  "/etc/shadow", "/openclaw.json",
];
const SKILL_PATH_PREFIX = "/.openclaw/tools/";

function labelRemote(remote) {
  return KNOWN_ENDPOINTS[remote] || remote;
}

function enrichNetEvent(e) {
  const remote = e.remote || "";
  const label = labelRemote(remote);
  const isUnknown = !KNOWN_ENDPOINTS[remote] && remote !== "?" && !remote.startsWith("?");
  return { ...e, remoteLabel: label, unknownEgress: isUnknown };
}

function enrichFileEvent(e) {
  const path = e.path || "";
  const fromSkill = (e.process || "").includes(".openclaw/tools") || (e.process || "").includes("clawhub");
  const sensitive = SENSITIVE_PATH_PREFIXES.some(p => path.includes(p));
  const outsideSkill = fromSkill && !path.includes(SKILL_PATH_PREFIX);
  const severity = outsideSkill && sensitive ? "critical" : sensitive ? "notable" : "normal";
  return { ...e, sensitive, fromSkill, outsideSkill, severity };
}

function mergeActivityFeed(since, limit = 200) {
  const sinceDate = parseSince(since) || new Date(0);
  const sessionEvents = sessionEventBuf.since(sinceDate).map(e => ({ ...e, source: "session", kind: e.kind || e.type }));
  const execEvents = execBuf.since(sinceDate).map(e => ({ ...e, source: "tetragon", kind: "exec", policy: e.policy }));
  const netEvents = netBuf.since(sinceDate).map(e => ({ ...enrichNetEvent(e), source: "tetragon", kind: "net" }));
  const fileEvents = fileBuf.since(sinceDate).map(e => ({ ...enrichFileEvent(e), source: "tetragon", kind: "file" }));
  const merged = [...sessionEvents, ...execEvents, ...netEvents, ...fileEvents]
    .sort((a, b) => new Date(b.time) - new Date(a.time))
    .slice(0, limit);
  return merged;
}

function getSessionEvents(since) {
  const d = parseSince(since);
  const events = d ? sessionEventBuf.since(d) : sessionEventBuf.all();
  return events.filter(e => ["tool_call", "tool_result", "usage", "model_change", "user_message"].includes(e.kind)).reverse();
}

function getSkillEvents(since) {
  const d = parseSince(since);
  const execs = (d ? execBuf.since(d) : execBuf.all()).filter(e => e.policy === "oc-skill-sandbox" || (e.process || "").includes("clawhub") || (e.process || "").includes(".openclaw/tools"));
  const files = (d ? fileBuf.since(d) : fileBuf.all()).filter(e => e.policy === "oc-skill-sandbox" || (e.path || "").includes(".openclaw/tools") || (e.path || "").includes(".openclaw/credentials"));
  const nets = (d ? netBuf.since(d) : netBuf.all()).filter(e => (e.process || "").includes(".openclaw/tools") || (e.process || "").includes("clawhub"));
  const combined = [...execs.map(e => ({ ...e, kind: "exec" })), ...files.map(e => ({ ...enrichFileEvent(e), kind: "file" })), ...nets.map(e => ({ ...enrichNetEvent(e), kind: "net" }))]
    .sort((a, b) => new Date(b.time) - new Date(a.time));
  return combined;
}

function getPolicies() {
  try {
    const out = execSync(`${TETRA} tp list -o json`, { encoding: "utf-8", timeout: 5000 });
    const data = JSON.parse(out);
    const list = (data.policies || []).map((p) => {
      const mode = (p.mode || "").includes("ENFORCE") ? "enforce" : "monitor";
      const counters = p.stats?.action_counters || {};
      const count = Number(counters.post ?? 0) + Number(counters.monitor_override ?? 0) + Number(counters.monitor_signal ?? 0);
      return {
        name: p.name,
        id: p.id,
        state: p.state,
        enabled: p.enabled,
        mode,
        kernelMemoryBytes: p.kernel_memory_bytes,
        eventCount: count,
      };
    });
    const h24 = new Date(Date.now() - 86400000);
    list.forEach((p) => {
      p.count24h = p.name === "oc-file-ops" ? fileBuf.since(h24).length
        : p.name === "oc-tool-exec" ? execBuf.since(h24).length
        : p.name === "oc-llm-api-egress" ? netBuf.since(h24).length
        : execBuf.since(h24).filter((e) => e.policy === "oc-skill-sandbox").length + fileBuf.since(h24).filter((e) => e.policy === "oc-skill-sandbox").length;
    });
    return { policies: list };
  } catch (e) {
    return { policies: [], error: e.message };
  }
}

function setPolicyMode(name, mode) {
  if (!ALLOWED_POLICY_NAMES.has(name) || !["enforce", "monitor"].includes(mode)) {
    return { ok: false, error: "invalid policy name or mode" };
  }
  try {
    execSync(`${TETRA} tp set-mode ${name} ${mode}`, { encoding: "utf-8", timeout: 5000 });
    return { ok: true, mode };
  } catch (e) {
    return { ok: false, error: e.message || String(e) };
  }
}

function getPolicyYaml(name) {
  if (!ALLOWED_POLICY_NAMES.has(name)) return null;
  const path = join(POLICIES_DIR, `${name}.yaml`);
  try {
    return readFileSync(path, "utf-8");
  } catch {
    return null;
  }
}

// ── Kill switch management ─────────────────────────────────────────────────────
const KS_EXEC_POLICY  = "oc-ks-exec";
const KS_NET_POLICY   = "oc-ks-net";
const KS_TIMEOUT_MS   = 60 * 1000; // 1 minute auto-expire

// Runtime state: timers and activation timestamps
const ksTimers      = { exec: null, net: null };
const ksActivatedAt = { exec: null, net: null };

function _ksDeactivate(type, name) {
  try { execSync(`${TETRA} tp delete ${name}`, { encoding: "utf-8", timeout: 5000 }); } catch {}
  ksTimers[type]      = null;
  ksActivatedAt[type] = null;
  console.log(`[kill-switch] ${name} auto-expired`);
}

function getKillSwitchStatus() {
  try {
    const out  = execSync(`${TETRA} tp list -o json`, { encoding: "utf-8", timeout: 5000 });
    const data = JSON.parse(out);
    const loaded = new Set((data.policies || []).map((p) => p.name));
    const now    = Date.now();

    const mkEntry = (policy, type) => {
      const active = loaded.has(policy);
      const activatedAt = ksActivatedAt[type];
      const remainingSeconds = active && activatedAt != null
        ? Math.max(0, Math.round((KS_TIMEOUT_MS - (now - activatedAt)) / 1000))
        : null;
      return { active, remainingSeconds, timeoutMs: KS_TIMEOUT_MS };
    };

    return {
      exec: mkEntry(KS_EXEC_POLICY, "exec"),
      net:  mkEntry(KS_NET_POLICY,  "net"),
    };
  } catch {
    return {
      exec: { active: false, remainingSeconds: null, timeoutMs: KS_TIMEOUT_MS },
      net:  { active: false, remainingSeconds: null, timeoutMs: KS_TIMEOUT_MS },
    };
  }
}

function toggleKillSwitch(type, active) {
  const name = type === "exec" ? KS_EXEC_POLICY : type === "net" ? KS_NET_POLICY : null;
  if (!name) return { ok: false, error: "unknown kill switch type" };
  try {
    if (active) {
      const yamlPath = join(POLICIES_DIR, `${name}.yaml`);
      execSync(`${TETRA} tp add ${yamlPath} -m enforce`, { encoding: "utf-8", timeout: 10000 });
      ksActivatedAt[type] = Date.now();
      // Clear any prior timer then start 60s auto-expire
      if (ksTimers[type]) clearTimeout(ksTimers[type]);
      ksTimers[type] = setTimeout(() => _ksDeactivate(type, name), KS_TIMEOUT_MS);
    } else {
      if (ksTimers[type]) { clearTimeout(ksTimers[type]); ksTimers[type] = null; }
      ksActivatedAt[type] = null;
      try { execSync(`${TETRA} tp delete ${name}`, { encoding: "utf-8", timeout: 5000 }); } catch {}
    }
    return { ok: true, active };
  } catch (e) {
    return { ok: false, error: e.stderr?.toString()?.trim() || e.message || String(e) };
  }
}

// ── Session context for LLM payload correlation ────────────────────────────────
function getSessionContext(timeISO, windowSecs = 5) {
  const center = new Date(timeISO);
  if (isNaN(center.getTime())) return [];
  const from = new Date(center.getTime() - windowSecs * 1000);
  const to   = new Date(center.getTime() + windowSecs * 1000);
  return sessionEventBuf.all()
    .filter((e) => {
      const t = new Date(e.time);
      return t >= from && t <= to &&
        ["user_message", "tool_call", "tool_result", "usage", "model_change"].includes(e.kind);
    })
    .sort((a, b) => new Date(a.time) - new Date(b.time));
}

// ── Cisco AI Defense Skill Scanner ─────────────────────────────────────────────
const SKILLS_DIR = process.env.OPENCLAW_SKILLS_DIR || (process.env.HOME + "/.npm-global/lib/node_modules/openclaw/skills");
const SKILL_SCANNER = "skill-scanner";

// ── Scan configuration (session-persistent, reset on server restart) ────────────
let scanConfig = {
  policy: "balanced",
  useBehavioral: false,
  useAiDefense: false,
  aiDefenseApiKey: "",
  aiDefenseApiUrl: "",
};

// ── Scan log ring buffer ─────────────────────────────────────────────────────────
const MAX_SCAN_LOGS = 200;
const scanLogBuf = new RingBuffer(MAX_SCAN_LOGS);
let scanLogSeq = 0;

function addScanLog(entry) {
  scanLogBuf.push({ id: ++scanLogSeq, ...entry });
}

function listSkillDirs() {
  try {
    const entries = readdirSync(SKILLS_DIR, { withFileTypes: true });
    return entries
      .filter(e => e.isDirectory())
      .map(e => ({ name: e.name, path: join(SKILLS_DIR, e.name) }))
      .filter(s => {
        try { statSync(join(s.path, "SKILL.md")); return true; } catch { return false; }
      });
  } catch { return []; }
}

const RAW_CAP = 200 * 1024; // 200 KB cap per stream stored in log

function scanSingleSkill(skillPath) {
  const skillName = skillPath.split("/").pop();
  const analyzers = ["static"];
  if (scanConfig.useBehavioral) analyzers.push("behavioral");
  if (scanConfig.useAiDefense) analyzers.push("aidefense");

  const args = ["scan", "--format", "json"];
  if (scanConfig.policy) args.push("--yara-mode", scanConfig.policy);
  if (scanConfig.useBehavioral) args.push("--use-behavioral");
  if (scanConfig.useAiDefense) args.push("--use-aidefense");
  if (scanConfig.useAiDefense && scanConfig.aiDefenseApiUrl) {
    args.push("--aidefense-api-url", scanConfig.aiDefenseApiUrl);
  }
  args.push(skillPath);

  const displayCmd = [SKILL_SCANNER, ...args].join(" ");

  const env = { ...process.env };
  const aiKeyPresent = !!(scanConfig.useAiDefense && scanConfig.aiDefenseApiKey);
  if (aiKeyPresent) {
    env.AI_DEFENSE_API_KEY = scanConfig.aiDefenseApiKey;
  }
  const timeoutMs = scanConfig.useAiDefense ? 120000 : 45000;

  const logBase = {
    time: new Date().toISOString(),
    skill: skillName,
    skillPath,
    policy: scanConfig.policy || "balanced",
    analyzers,
    aiDefenseEnabled: scanConfig.useAiDefense,
    aiDefenseApiKeyPresent: aiKeyPresent,
    aiDefenseApiUrl: (scanConfig.useAiDefense && scanConfig.aiDefenseApiUrl) || null,
    command: displayCmd,
  };

  addScanLog({ ...logBase, phase: "start", message: `Scan started — analyzers: [${analyzers.join(", ")}]` });

  const t0 = Date.now();
  const proc = spawnSync(SKILL_SCANNER, args, {
    encoding: "utf-8",
    timeout: timeoutMs,
    maxBuffer: 10 * 1024 * 1024,
    env,
  });

  const durationMs = Date.now() - t0;
  const rawStdout = (proc.stdout || "").slice(0, RAW_CAP);
  const rawStderr = (proc.stderr || "").slice(0, RAW_CAP);
  const spawnErr  = proc.error; // set on timeout or ENOENT
  const exitCode  = proc.status ?? -1;

  if (spawnErr || exitCode !== 0) {
    const errMsg = spawnErr
      ? (spawnErr.code === "ETIMEDOUT" ? `Timed out after ${timeoutMs / 1000}s` : String(spawnErr))
      : (rawStderr || `Exit code ${exitCode}`);

    // try to parse stdout anyway (some tools exit non-zero but still emit JSON)
    let result = null;
    if (rawStdout) { try { result = JSON.parse(stripBanner(rawStdout)); } catch {} }

    addScanLog({
      ...logBase,
      phase: "complete",
      outcome: "error",
      durationMs,
      exitCode,
      findingsCount: result ? (result.findings?.length ?? 0) : 0,
      isSafe: result?.is_safe ?? null,
      message: `Scan error after ${durationMs}ms (exit ${exitCode}): ${errMsg.slice(0, 300)}`,
      errorDetail: errMsg,
      rawStdout,
      rawStderr,
    });
    if (result) return result;
    return { error: errMsg, findings: [], is_safe: null };
  }

  let result;
  try {
    result = JSON.parse(stripBanner(rawStdout));
  } catch (parseErr) {
    const errMsg = `Failed to parse JSON output: ${parseErr.message}`;
    addScanLog({
      ...logBase,
      phase: "complete",
      outcome: "error",
      durationMs,
      exitCode,
      findingsCount: 0,
      isSafe: null,
      message: `${errMsg} — raw output captured`,
      errorDetail: errMsg,
      rawStdout,
      rawStderr,
    });
    return { error: errMsg, findings: [], is_safe: null };
  }

  const findingsCount = Array.isArray(result.findings) ? result.findings.length : 0;

  addScanLog({
    ...logBase,
    phase: "complete",
    outcome: "success",
    durationMs,
    exitCode,
    findingsCount,
    isSafe: result.is_safe ?? null,
    message: `Scan complete in ${durationMs}ms — ${findingsCount} finding(s), safe=${result.is_safe ?? "unknown"}`,
    rawStdout,
    rawStderr,
  });

  if (scanConfig.useAiDefense) {
    const aiFindings = Array.isArray(result.findings)
      ? result.findings.filter(f => f.analyzer === "aidefense" || f.analyzer === "aidefenseanalyzer")
      : [];
    addScanLog({
      ...logBase,
      phase: "aidefense-result",
      outcome: aiKeyPresent ? "success" : "skipped",
      durationMs,
      exitCode,
      findingsCount: aiFindings.length,
      message: aiKeyPresent
        ? `AI Defense cloud API returned ${aiFindings.length} finding(s)`
        : "AI Defense toggle is ON but no API key provided — cloud analysis skipped",
      rawStdout,
      rawStderr,
    });
  }

  return result;
}

const html = readFileSync(join(__dirname, "index.html"), "utf-8");

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf-8")));
    req.on("error", reject);
  });
}

const server = createServer(async (req, res) => {
  const url = new URL(req.url, `http://localhost:${PORT}`);
  const p = url.pathname;

  if (p === "/" || p === "/index.html") {
    res.writeHead(200, {
      "content-type": "text/html; charset=utf-8",
      "cache-control": "no-store",
    });
    res.end(readFileSync(join(__dirname, "index.html"), "utf-8"));
    return;
  }

  if (p === "/api/readme") {
    try {
      const md = readFileSync(join(__dirname, "README.md"), "utf-8");
      res.writeHead(200, { "content-type": "text/plain; charset=utf-8" });
      res.end(md);
    } catch {
      res.writeHead(404, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: "README.md not found" }));
    }
    return;
  }

  res.setHeader("content-type", "application/json");

  if (p === "/api/overview") {
    res.end(JSON.stringify(apiOverview()));
  } else if (p.startsWith("/api/policies/") && p.endsWith("/yaml")) {
    const name = p.slice("/api/policies/".length, -"/yaml".length);
    if (req.method === "PUT") {
      if (!ALLOWED_POLICY_NAMES.has(name)) {
        res.writeHead(400);
        res.end(JSON.stringify({ ok: false, error: "unknown policy" }));
        return;
      }
      const yamlContent = await readBody(req);
      if (!yamlContent || !yamlContent.trim()) {
        res.writeHead(400);
        res.end(JSON.stringify({ ok: false, error: "empty content" }));
        return;
      }
      try {
        // Get current mode before removing
        const listOut = execSync(`${TETRA} tp list -o json`, { encoding: "utf-8", timeout: 5000 });
        const listData = JSON.parse(listOut);
        const current = (listData.policies || []).find((pp) => pp.name === name);
        const currentMode = current && (current.mode || "").includes("ENFORCE") ? "enforce" : "monitor";
        // Write updated YAML
        const ymlPath = join(POLICIES_DIR, `${name}.yaml`);
        writeFileSync(ymlPath, yamlContent, "utf-8");
        // Reload: delete then re-add in previous mode
        try { execSync(`${TETRA} tp delete ${name}`, { encoding: "utf-8", timeout: 5000 }); } catch {}
        execSync(`${TETRA} tp add ${ymlPath} -m ${currentMode}`, { encoding: "utf-8", timeout: 10000 });
        res.end(JSON.stringify({ ok: true }));
      } catch (e) {
        res.end(JSON.stringify({ ok: false, error: e.stderr?.toString() || e.message || String(e) }));
      }
    } else {
      const yaml = getPolicyYaml(name);
      if (yaml === null) {
        res.writeHead(404);
        res.end(JSON.stringify({ error: "not found" }));
      } else {
        res.setHeader("content-type", "text/plain; charset=utf-8");
        res.end(yaml);
      }
    }
  } else if (p.startsWith("/api/policies/") && p.endsWith("/mode")) {
    const name = p.slice("/api/policies/".length, -"/mode".length);
    if (req.method !== "POST") {
      res.writeHead(405);
      res.end(JSON.stringify({ error: "method not allowed" }));
      return;
    }
    const body = await readBody(req);
    let mode;
    try {
      mode = JSON.parse(body || "{}").mode;
    } catch {
      mode = null;
    }
    const result = setPolicyMode(name, mode);
    res.end(JSON.stringify(result));
  } else if (p === "/api/policies") {
    res.end(JSON.stringify(getPolicies()));
  } else if (p === "/api/killswitches") {
    res.end(JSON.stringify(getKillSwitchStatus()));
  } else if (p.startsWith("/api/killswitches/")) {
    const type = p.slice("/api/killswitches/".length);
    if (req.method !== "POST") {
      res.writeHead(405);
      res.end(JSON.stringify({ error: "method not allowed" }));
      return;
    }
    const body = await readBody(req);
    let active = false;
    try { active = JSON.parse(body || "{}").active; } catch {}
    res.end(JSON.stringify(toggleKillSwitch(type, !!active)));
  } else if (p === "/api/session-context") {
    const timeISO = url.searchParams.get("time");
    const windowSecs = Math.min(parseFloat(url.searchParams.get("window") || "5"), 30);
    res.end(JSON.stringify({ events: getSessionContext(timeISO || "", windowSecs) }));
  } else if (p === "/api/activity") {
    const since = url.searchParams.get("since");
    const limit = Math.min(parseInt(url.searchParams.get("limit") || "200", 10), 500);
    const feed = mergeActivityFeed(since, limit);
    res.end(JSON.stringify({ events: feed, total: feed.length }));
  } else if (p === "/api/sessions") {
    const since = url.searchParams.get("since");
    const events = getSessionEvents(since);
    res.end(JSON.stringify({ events, total: events.length }));
  } else if (p === "/api/skills") {
    const since = url.searchParams.get("since");
    const events = getSkillEvents(since);
    res.end(JSON.stringify({ events, total: events.length }));
  } else if (p === "/api/events/exec") {
    const since = parseSince(url.searchParams.get("since"));
    const events = filterEvents(execBuf, since, { process: url.searchParams.get("process"), args: url.searchParams.get("q") });
    res.end(JSON.stringify({ events, total: events.length }));
  } else if (p === "/api/events/net") {
    const since = parseSince(url.searchParams.get("since"));
    let events = filterEvents(netBuf, since, { process: url.searchParams.get("process"), remote: url.searchParams.get("remote") });
    events = events.map(enrichNetEvent);
    res.end(JSON.stringify({ events, total: events.length }));
  } else if (p === "/api/events/file") {
    const since = parseSince(url.searchParams.get("since"));
    let events = filterEvents(fileBuf, since, { process: url.searchParams.get("process"), path: url.searchParams.get("path"), operation: url.searchParams.get("operation") });
    events = events.map(enrichFileEvent);
    res.end(JSON.stringify({ events, total: events.length }));
  } else if (p === "/api/scanner/config") {
    if (req.method === "GET") {
      res.end(JSON.stringify(scanConfig));
    } else if (req.method === "POST") {
      const body = await readBody(req);
      const patch = JSON.parse(body || "{}");
      if (patch.policy !== undefined) scanConfig.policy = String(patch.policy);
      if (patch.useBehavioral !== undefined) scanConfig.useBehavioral = !!patch.useBehavioral;
      if (patch.useAiDefense !== undefined) scanConfig.useAiDefense = !!patch.useAiDefense;
      if (patch.aiDefenseApiKey !== undefined) scanConfig.aiDefenseApiKey = String(patch.aiDefenseApiKey);
      if (patch.aiDefenseApiUrl !== undefined) scanConfig.aiDefenseApiUrl = String(patch.aiDefenseApiUrl);
      res.end(JSON.stringify({ ok: true }));
    } else {
      res.writeHead(405); res.end(JSON.stringify({ error: "method not allowed" }));
    }
  } else if (p === "/api/scanner/logs") {
    if (req.method === "GET") {
      const limit = parseInt(url.searchParams.get("limit") || "200", 10);
      const entries = scanLogBuf.all().slice(-limit).reverse();
      res.end(JSON.stringify({ logs: entries, total: entries.length }));
    } else if (req.method === "DELETE") {
      scanLogBuf.items.length = 0;
      scanLogSeq = 0;
      res.end(JSON.stringify({ ok: true }));
    } else {
      res.writeHead(405); res.end(JSON.stringify({ error: "method not allowed" }));
    }
  } else if (p === "/api/scanner/file") {
    const skillDir = url.searchParams.get("path");
    const filePath = url.searchParams.get("file");
    if (!skillDir || !filePath) {
      res.writeHead(400); res.end(JSON.stringify({ error: "missing path or file params" })); return;
    }
    const safeBase = resolve(skillDir);
    const safeFile = resolve(skillDir, filePath);
    if (!safeFile.startsWith(safeBase + "/") && safeFile !== safeBase) {
      res.writeHead(403); res.end(JSON.stringify({ error: "forbidden" })); return;
    }
    try {
      const content = readFileSync(safeFile, "utf-8");
      res.setHeader("content-type", "text/plain; charset=utf-8");
      res.end(content);
    } catch {
      res.writeHead(404); res.end(JSON.stringify({ error: "file not found" }));
    }
  } else if (p === "/api/scanner/skills") {
    const skills = listSkillDirs();
    res.end(JSON.stringify({ skills, skillsDir: SKILLS_DIR }));
  } else if (p === "/api/scanner/scan" && req.method === "POST") {
    const body = await readBody(req);
    let skillPath;
    try { skillPath = JSON.parse(body || "{}").path; } catch { skillPath = null; }
    if (!skillPath) {
      res.writeHead(400);
      res.end(JSON.stringify({ error: "missing path" }));
      return;
    }
    const result = scanSingleSkill(skillPath);
    res.end(JSON.stringify(result));
  } else if (p === "/api/scanner/scan-all" && req.method === "POST") {
    const skills = listSkillDirs();
    const results = [];
    for (const skill of skills) {
      results.push({ name: skill.name, ...scanSingleSkill(skill.path) });
    }
    res.end(JSON.stringify({ results, total: results.length }));
  } else {
    res.writeHead(404);
    res.end(JSON.stringify({ error: "not found" }));
  }
});

startCollector();
server.listen(PORT, "127.0.0.1", () => console.log(`Tetragon dashboard → http://127.0.0.1:${PORT}`));
