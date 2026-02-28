# Fix NVIDIA driver not loaded (nvml error)

After a power outage the driver is often not loaded. Try these in order.

---

## 1. Load the module (quick try)

```bash
sudo modprobe nvidia
```

If that works, run `nvidia-smi` to confirm. Then start vLLM:

```bash
~/.openclaw/workspace/aidef-shim/start-vllm-qwen3.sh
```

---

## 2. Reboot (most reliable)

The driver often only loads correctly at boot:

```bash
sudo reboot
```

After reboot, check:

```bash
nvidia-smi
```

Then start vLLM:

```bash
~/.openclaw/workspace/aidef-shim/start-vllm-qwen3.sh
```

---

## 3. Rebuild driver for current kernel (if module is missing)

Your system has **nvidia-driver-580-open** and kernel **6.14.0-1015-nvidia**. The open driver is built by DKMS. If the module was never built for this kernel (or kernel was updated later), do:

```bash
# Rebuild and install for current kernel
sudo dkms install nvidia/580.82.09 -k $(uname -r)

# Then load and confirm
sudo modprobe nvidia
nvidia-smi
```

If DKMS says the module is not found or build fails, install the kernel headers and try again:

```bash
sudo apt update
sudo apt install -y linux-headers-$(uname -r)
sudo dkms install nvidia/580.82.09 -k $(uname -r)
sudo modprobe nvidia
```

---

## 4. Secure Boot (if modprobe fails with "required key not present")

If the driver won’t load and you see a secure-boot/key error:

- Reboot into firmware (UEFI), **disable Secure Boot**, then boot again and run `sudo modprobe nvidia`, or  
- Sign the NVIDIA module for Secure Boot (more involved; search “sign nvidia module secure boot ubuntu”).

---

## Quick checklist

| Step | Command |
|------|--------|
| Try load | `sudo modprobe nvidia` |
| Check | `nvidia-smi` |
| Reboot | `sudo reboot` |
| Rebuild | `sudo dkms install nvidia/580.82.09 -k $(uname -r)` |
| Start vLLM | `~/.openclaw/workspace/aidef-shim/start-vllm-qwen3.sh` |
