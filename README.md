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

```
The private keys must remain on the trusted signing/build side and must not be committed to GitHub.
Do not commit:
```
security/ca/ca_private.key
security/signer/signer_private.key
*.sig
```
The agent trusts the local CA certificate, not arbitrary public keys supplied with object files. The signer certificate is accepted only if it chains to the trusted CA certificate. The public key inside the trusted signer certificate is then used to verify the ELF object signature.

## Repository Changes
The main files changed or added for this extension are:
protocol/Function.proto
controller/cli.py
controller/signature_utils.py
agent/agent.c
agent/signature_verifier.c
agent/signature_verifier.h
agent/Makefile
softswitch/Makefile
security/setup_x509.sh
examples/flood_all.c
examples/drop_all.c
examples/patch_flood.py

## High-level role of each component:
```
File	Purpose
protocol/Function.proto	Adds signature and certificate fields to FunctionAddRequest
controller/cli.py	Sends ELF object, signature, and signer certificate to the agent
controller/signature_utils.py	Loads .sig file and signer certificate
agent/agent.c	Verifies X.509 signature before uBPF loading
agent/signature_verifier.c	Implements certificate and signature verification using OpenSSL
agent/signature_verifier.h	Header for the verifier module
agent/Makefile	Builds the agent with signature verifier object
softswitch/Makefile	Links OpenSSL crypto library
security/setup_x509.sh	Generates CA and signer keys/certificates
examples/flood_all.c	Simple function that floods packets
examples/drop_all.c	Simple function that drops packets
examples/patch_flood.py	Demonstrates ELF byte tampering
```

## Prerequisites
This project is intended to be built and tested inside a Linux VM.
Recommended environment:
```
Ubuntu / Linux Lite based VM
Mininet
GCC
Make
Clang/LLVM
protobuf-c
OpenSSL
libssl-dev
Python 3
```

## Install common dependencies:
```
sudo apt update
sudo apt install -y build-essential make gcc clang llvm python3 python3-pip
sudo apt install -y protobuf-c-compiler libprotobuf-c-dev
sudo apt install -y openssl libssl-dev
sudo apt install -y mininet
```
If you are using VirtualBox, Guest Additions are useful for clipboard and screen resizing:
```sudo apt install -y build-essential dkms linux-headers-$(uname -r)```

Then insert the Guest Additions ISO from VirtualBox and run:
```
sudo mount /dev/sr1 /mnt/cdrom
cd /mnt/cdrom
sudo ./VBoxLinuxAdditions.run
sudo reboot
```
If /dev/sr1 does not exist, use /dev/sr0.

## Build BPFabric
From the repository root:
```
cd ~/BPFabric
make protocol-src
make agent-src
cd softswitch
make
```
If make clean reports a DPDK error, it can usually be ignored unless you are testing the DPDK switch.
## Generate X.509 Certificates
This fork includes a helper script:
```
cd ~/BPFabric
chmod +x security/setup_x509.sh
./security/setup_x509.sh
The script creates:
security/ca/ca_private.key
security/ca/ca_cert.pem
security/signer/signer_private.key
security/signer/signer.csr
security/signer/signer_cert.pem
```
It also verifies that the signer certificate chains to the local CA.
## Expected verification output:
```
security/signer/signer_cert.pem: OK
```
## Sign an ELF Object
Compile the example object from the examples directory if needed:
```
cd ~/BPFabric/examples
make flood_all.o
```
Sign the object:
```
cd ~/BPFabric
openssl pkeyutl -sign -inkey security/signer/signer_private.key -rawin -in examples/flood_all.o -out examples/flood_all.o.sig
```
The signature filename must match the object path with .sig appended.

Example:

examples/flood_all.o

examples/flood_all.o.sig

## Run Mininet and Controller
Start Mininet and pass the trusted CA certificate path to the switch-side agent:
```
cd ~/BPFabric/mininet
sudo -E BPFABRIC_CA_CERT=/home/amathur/BPFabric/security/ca/ca_cert.pem python3 ./1sw_topo.py
```
In another terminal, start the controller CLI and pass the signer certificate path:
```
cd ~/BPFabric/controller
BPFABRIC_SIGNER_CERT=/home/amathur/BPFabric/security/signer/signer_cert.pem python3 cli.py
```
Install a Signed Function

In the controller CLI, use:
```
1 add 0 flood ../examples/flood_all.o
```
Command format: <dpid> add <pipeline_index> <function_name> <object_path>

Example using the learning switch:

1 add 0 learningswitch ../examples/learningswitch.o

Expected result for a valid signed object:

Function has been installed

## Attack Demonstrations
-- Tampered Object Attack --

This attack modifies the ELF object bytes but reuses the old signature.

If flood_all_tampered.o has already been created, copy the original signature:

cd ~/BPFabric/examples
<br>
cp flood_all.o.sig flood_all_tampered.o.sig

Then install the tampered function from the controller CLI:

1 add 0 tampered ../examples/flood_all_tampered.o

Expected controller result:

Unable to install this function

Expected switch/Mininet output:

ELF signature verification failed

[MEASURE] function rejected by X.509 verification

-- Replacement Object Attack --

This attack replaces the intended object with a different valid object but reuses the wrong signature.

cd ~/BPFabric/examples
<br>
cp flood_all.o.sig drop_all.o.sig

Then install the replacement function from the controller CLI:

1 add 0 drop ../examples/drop_all.o

Expected controller result:

Unable to install this function

Expected switch/Mininet output:

ELF signature verification failed

[MEASURE] function rejected by X.509 verification

## Evaluation Mode

For experimental comparison, X.509 verification can be skipped using:
```
cd ~/BPFabric/mininet
sudo -E BPFABRIC_SKIP_X509=1 BPFABRIC_CA_CERT=/home/amathur/BPFabric/security/ca/ca_cert.pem python3 ./1sw_topo.py
This keeps the modified deployment path but disables the verification computation. It is useful for isolating the computational overhead of X.509 verification.
```
The agent prints timing information in microseconds:

[MEASURE] x509_verify_us=...

[MEASURE] ubpf_load_elf_us=...

[MEASURE] ubpf_compile_us=...

[MEASURE] total_add_success_us=...

[MEASURE] total_add_rejected_us=...

Meaning of each field:

```
Field	Meaning
x509_verify_us	Time spent verifying signer certificate and ELF signature
ubpf_load_elf_us	Time spent loading/parsing the ELF object
ubpf_compile_us	Time spent compiling/JITing the uBPF program
total_add_success_us	Total successful function installation time
total_add_rejected_us	Total time to reject an invalid function
```

## Example Evaluation Results
Example size measurements:

examples/flood_all.o              640 bytes

examples/flood_all.o.sig           64 bytes

security/signer/signer_cert.pem   400 bytes

The extra security payload for this example is:

64 + 400 = 464 bytes

Observed behaviour:
```
Scenario	Result
Valid signed object	Accepted
Tampered object with old signature	Rejected
Replacement object with wrong signature	Rejected
Unsigned object	Rejected
```

The security layer adds deployment-time overhead, mainly from certificate validation and signature verification. It does not add per-packet overhead because verification happens only during function installation, before the object reaches the uBPF loader.

```
Notes
This extension does not replace the uBPF loader or verifier. It adds an authenticity and integrity check before the object reaches the uBPF loading stage.

In this design:
X.509 layer checks: Is this ELF authentic and unmodified?
uBPF loader/verifier checks: Can this bytecode be loaded/executed safely?
Switch pipeline checks: Executes the installed function on packets.
```

## Cleanup
Stop Mininet and clean the topology:
<br>
exit
<br>
sudo mn -c
<br>
## Git Safety Notes
Before committing, check:

git status --short

Do not commit private keys or generated signatures:

security/ca/ca_private.key

security/signer/signer_private.key

*.sig

## Recommended .gitignore entries:

security/**/*.key

security/**/*.srl

*.sig

