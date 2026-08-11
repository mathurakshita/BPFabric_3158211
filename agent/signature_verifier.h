#ifndef SIGNATURE_VERIFIER_H
#define SIGNATURE_VERIFIER_H

#include <stddef.h>

int verify_elf_signature_x509(const unsigned char *elf, size_t elf_len, const unsigned char *sig, size_t sig_len, const unsigned char *cert, size_t cert_len);

#endif
