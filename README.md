# Tetragon AI Defense

Runtime security visibility and policy enforcement for [OpenClaw](https://github.com/open-claw/openclaw) AI agents. This monorepo contains two components:

| Component | Description |
|-----------|-------------|
| **tetragon-dashboard** | Web dashboard and server for Cilium Tetragon eBPF — real-time observability, policy management, kill switches |
| **aidef-shim** | HTTP proxy that inspects prompts via Cisco AI Defense before forwarding to the LLM |

Both work together for defense in depth: kernel-level enforcement (Tetragon) and prompt-level inspection (AI Defense).

## Quick Start

### Tetragon Dashboard
```bash
cd tetragon-dashboard
node server.mjs
# Open http://localhost:18790
```

### AI Defense Shim
```bash
cd aidef-shim
cp .env.example .env   # Edit with your AI Defense API key
npm install
./start-shim.sh
# Shim runs on http://127.0.0.1:9000
```

See `tetragon-dashboard/README.md` for full documentation.
