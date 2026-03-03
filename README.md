# Tetragon + AI Defense

**Proof of concept only** — not production-ready. For experimentation and evaluation.

Runtime security visibility and policy enforcement for [OpenClaw](https://github.com/open-claw/openclaw) AI agents. This monorepo contains two **independent** components — you can use either one, both, or neither:

| Component | Description |
|-----------|-------------|
| **tetragon-dashboard** | Web dashboard and server for Cilium Tetragon eBPF — real-time observability, policy management, kill switches |
| **aidef-shim** | HTTP proxy that inspects prompts via Cisco AI Defense before forwarding to the LLM |

They can be used together for defense in depth, or separately.

## Quick Start

### Tetragon Dashboard
```bash
cd tetragon-dashboard
# First run: replace /home/cuneocode in policies/*.yaml with your home directory:
sed -i "s|/home/cuneocode|$HOME|g" policies/*.yaml
node server.mjs
# Open http://localhost:18790
```

### AI Defense Shim (a basic proxy)
```bash
cd aidef-shim
cp .env.example .env   # Edit with your AI Defense API key
npm install
./start-shim.sh
# Shim runs on http://127.0.0.1:9000
```

See `tetragon-dashboard/README.md` for full documentation.
