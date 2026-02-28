# OpenClaw Security Dashboard

**Proof of concept only** — not production-ready.

Runtime security visibility and policy enforcement for [OpenClaw](https://github.com/open-claw/openclaw) AI agents, powered by Cilium Tetragon eBPF.

---

## Overview

The Security Dashboard provides real-time observability into everything an AI agent does at the system level — process execution, file access, network connections — and the ability to enforce security policies that constrain agent behavior. It combines three layers of defense:

| Layer | What it does | Where it runs |
|---|---|---|
| **Tetragon (eBPF)** | Kernel-level tracing and enforcement of syscalls | Linux kernel via eBPF |
| **AI Defense Shim** | Prompt-level inspection of LLM requests | HTTP proxy (port 9000) |
| **Skill Scanner** | Pre-deployment static + semantic analysis of agent skills | CLI tool invoked by dashboard |

---

## Architecture

### System Overview

```mermaid
graph TB
    subgraph User
        U[User / Operator]
    end

    subgraph Dashboard["Security Dashboard :18790"]
        UI[Web UI]
        SRV[Node.js Server]
        POL[Policy Manager]
    end

    subgraph OpenClaw["OpenClaw Agent :18789"]
        GW[Gateway]
        AG[Agent Runtime]
        SK[Skills]
    end

    subgraph Defense["AI Defense Layer"]
        SHIM["aidef-shim :9000"]
        AIDEF[Cisco AI Defense API]
    end

    subgraph LLM["LLM Backend :8000"]
        VLLM[vLLM / Model]
    end

    subgraph Kernel["Linux Kernel"]
        TET[Tetragon eBPF]
        KP[Kprobe Hooks]
    end

    U -->|operates| UI
    UI -->|API calls| SRV
    SRV -->|tetra CLI| TET
    SRV -->|reads policies| POL

    AG -->|LLM request| SHIM
    SHIM -->|inspect prompt| AIDEF
    SHIM -->|if safe, forward| VLLM
    VLLM -->|response| SHIM
    SHIM -->|response| AG

    AG -->|syscalls| KP
    SK -->|syscalls| KP
    KP -->|trace / enforce| TET
    TET -->|event stream| SRV

    style Dashboard fill:#1e1e2e,stroke:#6366f1,color:#e4e4e9
    style Defense fill:#1e1e2e,stroke:#f87171,color:#e4e4e9
    style Kernel fill:#1e1e2e,stroke:#34d399,color:#e4e4e9
    style OpenClaw fill:#1e1e2e,stroke:#fbbf24,color:#e4e4e9
    style LLM fill:#1e1e2e,stroke:#a78bfa,color:#e4e4e9
```

### Request Flow: LLM API Call

Every LLM request from the agent passes through two independent security checkpoints — one at the application layer (AI Defense) and one at the kernel layer (Tetragon).

```mermaid
sequenceDiagram
    participant Agent as OpenClaw Agent
    participant Shim as aidef-shim :9000
    participant AIDef as Cisco AI Defense
    participant LLM as vLLM :8000
    participant Kernel as Tetragon eBPF
    participant Dash as Dashboard

    Agent->>Shim: POST /v1/chat/completions
    Shim->>AIDef: Inspect prompt content
    
    alt Prompt is safe
        AIDef-->>Shim: ✅ is_safe: true
        Shim->>LLM: Forward request
        LLM-->>Shim: Model response
        Shim-->>Agent: Response (stream or JSON)
    else Prompt is unsafe
        AIDef-->>Shim: ❌ action: Block
        Shim-->>Agent: 200 + content_filter
    end

    Note over Kernel: Meanwhile, at the kernel level...
    Kernel->>Kernel: Trace TCP connect (egress policy)
    Kernel->>Dash: Network event stream
    Dash->>Dash: Correlate with session context
```

### Enforcement: Tetragon eBPF Pipeline

Tetragon hooks into kernel syscalls via eBPF kprobes. When an agent process triggers a hooked syscall, Tetragon evaluates the configured policy and either logs the event (monitor mode) or blocks it in-kernel before it completes (enforce mode).

```mermaid
graph LR
    subgraph Agent Process
        A[Agent executes syscall]
    end

    subgraph Kernel["Tetragon eBPF"]
        K1[Kprobe fires]
        K2{Policy match?}
        K3{Mode?}
        LOG[Log event]
        BLOCK[Block + Sigkill/Override]
        PASS[Allow through]
    end

    subgraph Dashboard
        D[Event stream]
        V[Visibility UI]
    end

    A --> K1
    K1 --> K2
    K2 -->|No match| PASS
    K2 -->|Match| K3
    K3 -->|Monitor| LOG
    K3 -->|Enforce| BLOCK
    LOG --> D
    BLOCK --> D
    D --> V

    style BLOCK fill:#7f1d1d,stroke:#f87171,color:#fca5a5
    style LOG fill:#064e3b,stroke:#34d399,color:#6ee7b7
    style PASS fill:#1e1e2e,stroke:#63636e,color:#9d9da8
```

---

## Tetragon Policies

Policies are Cilium TracingPolicy resources defined in YAML. Each policy hooks one or more kernel functions and specifies what to do when the hook fires.

### Core Policies

| Policy | Hooks | What it traces |
|---|---|---|
| `oc-file-ops` | `security_file_open`, `vfs_write`, `do_unlinkat` | File open, write, and delete operations on workspace and sensitive paths |
| `oc-tool-exec` | `__arm64_sys_execve` | Execution of tool binaries — curl, wget, git, python, node, etc. |
| `oc-llm-api-egress` | `tcp_connect` | Outbound TCP connections from agent processes |
| `oc-skill-sandbox` | `__arm64_sys_execve`, `security_file_open` | Any exec or file access originating from skill/clawhub directories |
| `oc-sensitive-files` | `security_file_open` | Access to credentials, SSH keys, kubeconfig, cloud tokens |
| `oc-priv-ops` | `bpf`, `init_module` | Privileged operations like BPF syscalls and kernel module loads |

### Kill Switches

Emergency lockout policies that can be activated from the dashboard footer. They auto-expire after 60 seconds.

| Kill Switch | Effect |
|---|---|
| `oc-ks-exec` | Blocks **all** subprocess execution (`execve`) from OpenClaw processes |
| `oc-ks-net` | Blocks **all** outbound TCP connections from OpenClaw processes |

### Policy Modes

Each policy operates in one of two modes, togglable from the dashboard:

```mermaid
graph LR
    M[Monitor Mode] -->|"toggle"| E[Enforce Mode]
    E -->|"toggle"| M

    M -.- MD["Log events only — no blocking.\nFull visibility, zero disruption."]
    E -.- ED["Block matching syscalls in-kernel.\nSigkill or Override return code."]

    style M fill:#064e3b,stroke:#34d399,color:#6ee7b7
    style E fill:#7f1d1d,stroke:#f87171,color:#fca5a5
    style MD fill:#0c0c0e,stroke:#232329,color:#9d9da8
    style ED fill:#0c0c0e,stroke:#232329,color:#9d9da8
```

---

## Skill Scanner

The Skill Scanner analyzes agent skills (plugins) **before** they execute, identifying security risks through multiple analysis engines.

### Scanner Pipeline

```mermaid
graph TB
    subgraph Input
        S[Skill Directory]
    end

    subgraph Analyzers
        SA[Static Analyzer<br/>YARA pattern matching]
        BA[Behavioral Analyzer<br/>Execution pattern analysis]
        AA[AI Defense Analyzer<br/>Cisco AI Defense API]
    end

    subgraph Output
        F[Findings]
        SEV{Severity}
        INFO[ℹ Info]
        WARN[⚠ Warning]
        CRIT[🛑 Critical]
    end

    S --> SA
    S --> BA
    S --> AA

    SA --> F
    BA --> F
    AA --> F

    F --> SEV
    SEV --> INFO
    SEV --> WARN
    SEV --> CRIT

    style SA fill:#1e1e2e,stroke:#6366f1,color:#e4e4e9
    style BA fill:#1e1e2e,stroke:#34d399,color:#e4e4e9
    style AA fill:#1e1e2e,stroke:#f87171,color:#e4e4e9
    style CRIT fill:#7f1d1d,stroke:#f87171,color:#fca5a5
    style WARN fill:#422006,stroke:#fbbf24,color:#fde68a
    style INFO fill:#1e1e2e,stroke:#6366f1,color:#a5b4fc
```

### Analyzers

**Static Analyzer** — Pattern-based code analysis using YARA rules. Detects dangerous patterns like `eval()`, shell injection, crypto-mining signatures, and credential harvesting. Runs with a configurable policy preset: `permissive`, `balanced`, or `strict`.

**Behavioral Analyzer** — Analyzes execution patterns and control flow for suspicious behavior like obfuscated code, data exfiltration patterns, or privilege escalation attempts.

**AI Defense Analyzer** — Sends skill content to the Cisco AI Defense cloud API for semantic threat analysis. Checks for prompt injection, harassment, hate speech, and other content policy violations using the same engine that powers the runtime aidef-shim.

---

## AI Defense Shim

The aidef-shim is an HTTP proxy that sits between OpenClaw and the upstream LLM. It inspects every prompt before it reaches the model.

### How It Works

```mermaid
sequenceDiagram
    participant OC as OpenClaw
    participant Shim as aidef-shim
    participant API as AI Defense API
    participant LLM as vLLM

    OC->>Shim: Chat completion request
    
    Note over Shim: Extract user messages<br/>Strip provider prefixes<br/>Remove unsupported fields

    Shim->>API: POST /api/v1/inspect/chat
    API-->>Shim: Assessment response

    alt Safe
        Note over Shim: is_safe=true, no rules triggered
        Shim->>LLM: Forward cleaned request
        LLM-->>Shim: Model response
        Shim-->>OC: Forward response
    else Blocked
        Note over Shim: is_safe=false or action=Block
        Shim-->>OC: Synthetic response<br/>finish_reason: content_filter
    end

    alt API Error (fail-open)
        Note over Shim: AI Defense API unreachable
        Shim->>LLM: Forward request anyway
        LLM-->>Shim: Model response
        Shim-->>OC: Forward response
    end
```

### Configuration

| Variable | Default | Purpose |
|---|---|---|
| `PORT` | `9000` | Shim listen port |
| `UPSTREAM_URL` | `http://127.0.0.1:8000/v1` | vLLM backend |
| `AI_DEFENSE_API_KEY` | — | Cisco AI Defense API key |
| `AI_DEFENSE_REGION` | `us` | API region (`us`, `eu`, `ap`) |

The shim is transparent to OpenClaw — the agent config simply points its LLM provider URL at `http://127.0.0.1:9000/v1` instead of directly at vLLM.

---

## Defense in Depth

The three security layers operate independently and complement each other:

```mermaid
graph TB
    subgraph Layer1["Layer 1: Pre-Deployment"]
        SS[Skill Scanner]
        SS --- SS1["Scans skill code before execution"]
        SS --- SS2["Static patterns + AI Defense semantics"]
        SS --- SS3["Blocks known-bad skills from loading"]
    end

    subgraph Layer2["Layer 2: Prompt Inspection"]
        AI[AI Defense Shim]
        AI --- AI1["Inspects every LLM prompt at runtime"]
        AI --- AI2["Blocks prompt injection & policy violations"]
        AI --- AI3["Transparent HTTP proxy, fail-open"]
    end

    subgraph Layer3["Layer 3: Kernel Enforcement"]
        TE[Tetragon eBPF]
        TE --- TE1["Hooks syscalls at the kernel level"]
        TE --- TE2["Blocks unauthorized exec, file, network ops"]
        TE --- TE3["Kill switches for emergency lockout"]
    end

    Layer1 -->|"skill approved"| Layer2
    Layer2 -->|"prompt approved"| Layer3

    style Layer1 fill:#1e1e2e,stroke:#6366f1,color:#e4e4e9
    style Layer2 fill:#1e1e2e,stroke:#fbbf24,color:#e4e4e9
    style Layer3 fill:#1e1e2e,stroke:#f87171,color:#e4e4e9
```

Each layer catches threats the others might miss:
- The **Skill Scanner** prevents known-malicious code from ever running.
- The **AI Defense Shim** blocks adversarial prompts that could trick the model into harmful actions.
- **Tetragon eBPF** enforces hard boundaries at the kernel level — even if a prompt slips through and the model generates a dangerous command, the kernel policy blocks the syscall before it executes.

---

## Dashboard Tabs

| Tab | Description |
|---|---|
| **Activity Feed** | Unified timeline merging OpenClaw session events with Tetragon kernel events. See what the agent is doing and what the kernel is observing side by side. |
| **LLM & API** | Network connection events filtered for LLM API egress. Highlights unknown or unexpected outbound connections. |
| **Tool Exec** | Process execution events — every binary the agent spawns. Filter by process name or arguments. |
| **File Ops** | File system events — opens, writes, deletes. See exactly what the agent reads and modifies. |
| **Skill Events** | Events originating from skill directories. Flags out-of-sandbox access and sensitive file touches. |
| **Skill Scanner** | Run the skill scanner, configure analyzers, view findings with severity levels and source code context. |
| **Policies** | View and edit Tetragon policy YAML. Toggle between monitor and enforce modes. Activate kill switches. |

---

## Quick Start

**Before first run:** Policy YAMLs in `policies/` use `/home/cuneocode` for paths. Replace with your home directory (e.g. `sed -i 's|/home/cuneocode|'$HOME'|g' policies/*.yaml`) before applying.

```bash
# Start the dashboard server
node server.mjs

# Open in browser
open http://localhost:18790
```

The dashboard expects Tetragon to be running with the `tetra` CLI available at `/usr/local/bin/tetra`. Policies in the `policies/` directory are loaded via `tetra tp add`.

---

## Ports

| Service | Port | Purpose |
|---|---|---|
| vLLM | 8000 | LLM model serving |
| aidef-shim | 9000 | AI Defense prompt inspection proxy |
| OpenClaw Gateway | 18789 | Agent gateway and control plane |
| Security Dashboard | 18790 | This dashboard |
