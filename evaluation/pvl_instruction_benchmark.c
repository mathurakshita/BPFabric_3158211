#include "signature_verifier.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <valgrind/callgrind.h>

typedef int (*operation_fn)(
    const unsigned char *, size_t,
    const unsigned char *, size_t,
    const unsigned char *, size_t
);

static volatile unsigned char sink;

static unsigned char *read_file(const char *path, size_t *length)
{
    FILE *file = fopen(path, "rb");
    if (file == NULL) {
        perror(path);
        return NULL;
    }

    fseek(file, 0, SEEK_END);
    long size = ftell(file);
    rewind(file);

    if (size <= 0) {
        fclose(file);
        return NULL;
    }

    unsigned char *data = malloc((size_t)size);
    if (data == NULL) {
        fclose(file);
        return NULL;
    }

    if (fread(data, 1, (size_t)size, file) != (size_t)size) {
        free(data);
        fclose(file);
        return NULL;
    }

    fclose(file);
    *length = (size_t)size;
    return data;
}

__attribute__((noinline))
static int empty_operation(
    const unsigned char *elf, size_t elf_len,
    const unsigned char *sig, size_t sig_len,
    const unsigned char *cert, size_t cert_len)
{
    if (elf_len == 0 || sig_len == 0 || cert_len == 0) {
        return 0;
    }

    sink ^= elf[0] ^ sig[0] ^ cert[0];
    return 1;
}

int main(int argc, char **argv)
{
    if (argc != 6) {
        fprintf(
            stderr,
            "Usage: %s verify|empty ELF SIGNATURE CERTIFICATE ITERATIONS\n",
            argv[0]
        );
        return EXIT_FAILURE;
    }

    int verify_mode = strcmp(argv[1], "verify") == 0;

    if (!verify_mode && strcmp(argv[1], "empty") != 0) {
        fprintf(stderr, "Mode must be 'verify' or 'empty'\n");
        return EXIT_FAILURE;
    }

    long iterations = strtol(argv[5], NULL, 10);
    if (iterations <= 0) {
        fprintf(stderr, "Iterations must be positive\n");
        return EXIT_FAILURE;
    }

    size_t elf_len, sig_len, cert_len;
    unsigned char *elf = read_file(argv[2], &elf_len);
    unsigned char *sig = read_file(argv[3], &sig_len);
    unsigned char *cert = read_file(argv[4], &cert_len);

    if (elf == NULL || sig == NULL || cert == NULL) {
        fprintf(stderr, "Unable to read benchmark artifacts\n");
        free(elf);
        free(sig);
        free(cert);
        return EXIT_FAILURE;
    }

    operation_fn operation = verify_mode
        ? verify_elf_signature_x509
        : empty_operation;

    /* Warm up the verification path before measurement. */
    if (!operation(elf, elf_len, sig, sig_len, cert, cert_len)) {
        fprintf(stderr, "Warm-up operation failed\n");
        return EXIT_FAILURE;
    }

    long successes = 0;

    CALLGRIND_ZERO_STATS;
    CALLGRIND_START_INSTRUMENTATION;

    for (long i = 0; i < iterations; ++i) {
        successes += operation(
            elf, elf_len,
            sig, sig_len,
            cert, cert_len
        );
    }

    CALLGRIND_STOP_INSTRUMENTATION;

    printf(
        "mode=%s iterations=%ld successes=%ld\n",
        argv[1],
        iterations,
        successes
    );

    free(elf);
    free(sig);
    free(cert);

    return successes == iterations ? EXIT_SUCCESS : EXIT_FAILURE;
}
