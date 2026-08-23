# BPFabric with X.509 Signature Verification

This repository is based on BPFabric, a research framework for deploying BPF/uBPF programs into a programmable network dataplane.

This fork adds an X.509-based digital signature verification layer to the BPFabric function installation path. The purpose of the extension is to verify the authenticity and integrity of BPF/uBPF ELF object files before they are loaded into the switch pipeline.

## Project Aim

In the original BPFabric workflow, a controller sends a compiled ELF object file to a switch-side agent. The agent then loads the object using the uBPF loader and installs the resulting function into the switch pipeline.

This extension adds a trust check before the uBPF loading stage.

<pre>
Controller
   |
   | ELF object + signature + signer certificate
   v
BPFabric agent
   |
   | verify signer certificate against trusted CA certificate
   | verify ELF signature using public key from signer certificate
   v
uBPF loader / compiler
   |
   v
Switch pipeline
</pre>

If the signature or certificate check fails, the function is rejected before `ubpf_load_elf()` and `ubpf_compile()` are called.

## Security Model

The controller sends the following items during function installation:

- compiled ELF object file, for example `examples/flood_all.o`
- detached signature file, for example `examples/flood_all.o.sig`
- signer X.509 certificate, for example `security/signer/signer_cert.pem`

The switch-side agent must already have access to a trusted CA certificate:

```text
security/ca/ca_cert.pem

The private keys must remain on the trusted signing/build side and must not be committed to GitHub.
Do not commit:
security/ca/ca_private.key
security/signer/signer_private.key
*.sig


