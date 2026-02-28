const express = require('express');
const axios = require('axios');

const app = express();
app.use(express.json({ limit: '2mb' }));

// Config via env
const PORT = process.env.PORT || 9000;
const UNDERLYING_LLM_BASE_URL =
  process.env.UNDERLYING_LLM_BASE_URL || 'http://127.0.0.1:8000/v1';

// Cisco AI Defense Inspection config
const AIDEFENSE_REGION = process.env.AIDEFENSE_REGION || 'us';
const AIDEFENSE_CHAT_URL =
  process.env.AIDEFENSE_CHAT_URL ||
  `https://${AIDEFENSE_REGION}.api.inspect.aidefense.security.cisco.com/api/v1/inspect/chat`;

const AIDEFENSE_API_KEY =
  process.env.AIDEFENSE_API_KEY || process.env.AI_DEFENSE_API_KEY || '';

// Upstream LLM auth — used when forwarding to OpenAI (or any Bearer-token API)
const UPSTREAM_API_KEY = process.env.OPENAI_API_KEY || '';

// Fields that vLLM's OpenAI-compatible server does not accept (or requires
// extra launch flags that the container wasn't started with).
const VLLM_UNSUPPORTED_FIELDS = new Set([
  'store',        // OpenAI "store completion" flag
  'strict',       // JSON schema strict mode
  'metadata',     // OpenAI request metadata bag
  'service_tier',
  'prediction',
  // Tool-calling requires --enable-auto-tool-choice + --tool-call-parser on
  // the vLLM server. Strip these until the container is restarted with those
  // flags. Without stripping, vLLM returns 400 for tool_choice:"auto".
  'tools',
  'tool_choice',
  'parallel_tool_calls',
]);

/**
 * Strip the provider prefix OpenClaw prepends to model IDs.
 * e.g. "vllm/Qwen/Qwen3-8b" → "Qwen/Qwen3-8b"
 */
function stripProviderPrefix(modelId) {
  if (!modelId) return modelId;
  // OpenClaw format is "<provider>/<model...>"; vLLM needs just the model part.
  // We detect the openclaw provider prefix by checking if the first segment
  // matches a known provider name.
  const knownPrefixes = ['vllm', 'openai', 'openai-codex', 'anthropic', 'groq'];
  const slashIdx = modelId.indexOf('/');
  if (slashIdx === -1) return modelId;
  const prefix = modelId.slice(0, slashIdx);
  if (knownPrefixes.includes(prefix)) {
    return modelId.slice(slashIdx + 1);
  }
  return modelId;
}

/**
 * Build a clean body for the upstream LLM by:
 *  - dropping fields unsupported by the upstream
 *  - stripping the OpenClaw provider prefix from the model ID
 *  - converting max_tokens → max_completion_tokens for GPT-5+ models
 *    (OpenAI deprecated max_tokens on newer models)
 */
function buildUpstreamBody(incoming) {
  const clean = {};
  for (const [k, v] of Object.entries(incoming)) {
    if (!VLLM_UNSUPPORTED_FIELDS.has(k)) {
      clean[k] = v;
    }
  }

  if (clean.model) {
    const stripped = stripProviderPrefix(clean.model);
    if (stripped !== clean.model) {
      console.log(`[SHIM] Rewriting model "${clean.model}" → "${stripped}"`);
      clean.model = stripped;
    }
  }

  // GPT-5+ rejects max_tokens; rename it to max_completion_tokens.
  if ('max_tokens' in clean && !('max_completion_tokens' in clean)) {
    clean.max_completion_tokens = clean.max_tokens;
    delete clean.max_tokens;
  }

  return clean;
}

async function inspectPrompt(messages) {
  if (!AIDEFENSE_API_KEY) {
    console.warn('[AI DEFENSE] Missing API key, skipping inspection');
    return { allowed: true, raw: null };
  }

  // Send only user-role messages for prompt inspection.
  // Assistant turns in history are not evaluated — we only care about
  // whether the inbound user content is safe to forward to vLLM.
  //
  // OpenAI-format content can be a plain string OR an array of content parts
  // (e.g. [{type:"text",text:"..."},{type:"image_url",...}]).
  // AI Defense only accepts a plain string, so we extract text parts.
  function contentToString(content) {
    if (typeof content === 'string') return content;
    if (Array.isArray(content)) {
      return content
        .filter((p) => p.type === 'text')
        .map((p) => p.text ?? '')
        .join('\n');
    }
    return String(content ?? '');
  }

  const userMessages = messages
    .filter((m) => m.role === 'user')
    .map((m) => ({ role: 'user', content: contentToString(m.content) }))
    .filter((m) => m.content.trim().length > 0);

  const payload = {
    messages: userMessages,
    metadata: {},
    config: {},   // empty → use policies configured in the AI Defense portal
  };

  try {
    const resp = await axios.post(AIDEFENSE_CHAT_URL, payload, {
      headers: {
        'X-Cisco-AI-Defense-API-Key': AIDEFENSE_API_KEY,
        'Content-Type': 'application/json',
        accept: 'application/json',
      },
      timeout: 8000,
    });

    const data = resp.data;

    // AI Defense response schema:
    //   is_safe: boolean  (false = block)
    //   action:  "Block" | "Alert" | "Pass"
    //   rules:   array of triggered rules (non-empty when a rule fires)
    const shouldBlock =
      data.is_safe === false ||
      data.action === 'Block' ||
      (Array.isArray(data.rules) && data.rules.length > 0);

    console.log(
      `[AI DEFENSE] is_safe=${data.is_safe} action=${data.action} triggered_rules=${JSON.stringify(data.rules || [])} → ${shouldBlock ? 'BLOCK' : 'ALLOW'}`
    );
    return { allowed: !shouldBlock, raw: data };
  } catch (err) {
    const detail = err.response?.data || err.message;
    console.error('[AI DEFENSE] Inspection error (failing open):', JSON.stringify(detail));
    // Fail open: if the guardrail call itself errors, let the request through.
    // Change to `allowed: false` to fail closed if you prefer.
    return { allowed: true, raw: { error: err.message } };
  }
}

app.post('/v1/chat/completions', async (req, res) => {
  const body = req.body;

  try {
    const messages = body.messages || [];

    const inspection = await inspectPrompt(messages);

    if (!inspection.allowed) {
      const rules = (inspection.raw?.rules || []).map((r) => r.rule_name).join(', ') || 'policy violation';
      console.log(`[AI DEFENSE] Blocked (${rules})`);

      const blockedPayload = {
        id: 'aidefense-blocked',
        object: 'chat.completion',
        created: Math.floor(Date.now() / 1000),
        model: body.model || 'guardrails',
        choices: [
          {
            index: 0,
            finish_reason: 'content_filter',
            message: {
              role: 'assistant',
              content: `[Blocked by Cisco AI Defense: ${rules}]`,
            },
            delta: {
              role: 'assistant',
              content: `[Blocked by Cisco AI Defense: ${rules}]`,
            },
          },
        ],
        usage: { prompt_tokens: 0, completion_tokens: 0, total_tokens: 0 },
      };

      if (body.stream) {
        res.setHeader('Content-Type', 'text/event-stream; charset=utf-8');
        res.setHeader('Cache-Control', 'no-cache');
        res.status(200);
        res.write(`data: ${JSON.stringify({ ...blockedPayload, object: 'chat.completion.chunk' })}\n\n`);
        res.write('data: [DONE]\n\n');
        return res.end();
      }
      return res.status(200).json(blockedPayload);
    }

    const upstreamBody = buildUpstreamBody(body);
    const isStreaming = upstreamBody.stream === true;

    // Build Authorization: prefer the upstream API key from env, fall back to
    // whatever the client sent (useful for local/no-auth upstreams like vLLM).
    const upstreamAuth = UPSTREAM_API_KEY
      ? `Bearer ${UPSTREAM_API_KEY}`
      : req.headers.authorization;

    const upstreamHeaders = {
      'Content-Type': 'application/json',
      ...(upstreamAuth ? { Authorization: upstreamAuth } : {}),
    };

    if (isStreaming) {
      // Pipe SSE stream directly to the client without buffering.
      const upstreamResp = await axios.post(
        `${UNDERLYING_LLM_BASE_URL}/chat/completions`,
        upstreamBody,
        {
          headers: upstreamHeaders,
          responseType: 'stream',
          timeout: 120000,
        }
      );

      res.setHeader('Content-Type', 'text/event-stream; charset=utf-8');
      res.setHeader('Cache-Control', 'no-cache');
      res.setHeader('Connection', 'keep-alive');
      res.status(upstreamResp.status);
      upstreamResp.data.pipe(res);

      upstreamResp.data.on('error', (err) => {
        console.error('[SHIM] Stream error:', err.message);
        res.end();
      });
    } else {
      const llmResp = await axios.post(
        `${UNDERLYING_LLM_BASE_URL}/chat/completions`,
        upstreamBody,
        {
          headers: upstreamHeaders,
          timeout: 120000,
        }
      );
      return res.status(llmResp.status).json(llmResp.data);
    }
  } catch (err) {
    const status = err.response?.status || 500;
    const safeData = typeof err.response?.data === 'object' && err.response?.data !== null
      ? (() => { try { JSON.stringify(err.response.data); return err.response.data; } catch { return { message: String(err.response.data) }; } })()
      : null;
    const payload = safeData || {
      error: {
        message: 'Shim proxy error',
        type: 'shim_error',
        details: err.message,
      },
    };
    console.error(`[SHIM] Upstream error ${status}:`, payload);
    return res.status(status).json(payload);
  }
});

// Proxy /v1/models so clients can discover available models
app.get('/v1/models', async (req, res) => {
  try {
    const r = await axios.get(`${UNDERLYING_LLM_BASE_URL}/models`, {
      timeout: 5000,
    });
    return res.status(r.status).json(r.data);
  } catch (err) {
    return res.status(502).json({ error: 'Failed to reach upstream /v1/models' });
  }
});

app.get('/healthz', (req, res) => {
  res.json({ ok: true, port: PORT, upstream: UNDERLYING_LLM_BASE_URL });
});

app.listen(PORT, '127.0.0.1', () => {
  console.log(`AI Defense shim listening on http://127.0.0.1:${PORT}`);
  console.log(`Forwarding to upstream LLM at ${UNDERLYING_LLM_BASE_URL}`);
  console.log(`Upstream auth: ${UPSTREAM_API_KEY ? 'ENABLED (OPENAI_API_KEY)' : 'none (client passthrough)'}`);
  console.log(
    `AI Defense inspection: ${AIDEFENSE_API_KEY ? 'ENABLED' : 'DISABLED (no API key)'}`
  );
});
