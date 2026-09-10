#include "signature_verifier.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/provider.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

static OSSL_PROVIDER *default_provider = NULL;
static OSSL_PROVIDER *signature_provider = NULL;

/*
 * Provider handles remain loaded for the lifetime of the soft-switch.
 * BPFABRIC_OPENSSL_PROVIDER may be set to "oqsprovider" for ML-DSA.
 */
static int initialise_crypto_providers(void)
{
    const char *provider_name =
        getenv("BPFABRIC_OPENSSL_PROVIDER");

    if (default_provider == NULL)
    {
        default_provider =
            OSSL_PROVIDER_load(NULL, "default");

        if (default_provider == NULL)
        {
            fprintf(stderr,
                    "Unable to load default OpenSSL provider\n");
            ERR_print_errors_fp(stderr);
            return 0;
        }
    }

    if (provider_name != NULL &&
        provider_name[0] != '\0' &&
        signature_provider == NULL)
    {
        signature_provider =
            OSSL_PROVIDER_load(NULL, provider_name);

        if (signature_provider == NULL)
        {
            fprintf(stderr,
                    "Unable to load OpenSSL provider: %s\n",
                    provider_name);
            ERR_print_errors_fp(stderr);
            return 0;
        }

        fprintf(stderr,
                "Loaded OpenSSL provider: %s\n",
                provider_name);
    }

    return 1;
}

static X509 *read_cert_from_memory(
    const unsigned char *data,
    size_t len)
{
    BIO *bio = BIO_new_mem_buf(data, (int)len);

    if (bio == NULL)
    {
        fprintf(stderr,
                "Unable to create BIO for signer certificate\n");
        ERR_print_errors_fp(stderr);
        return NULL;
    }

    X509 *cert =
        PEM_read_bio_X509(bio, NULL, NULL, NULL);

    if (cert == NULL)
    {
        fprintf(stderr,
                "OpenSSL certificate parsing failed:\n");
        ERR_print_errors_fp(stderr);
    }

    BIO_free(bio);
    return cert;
}

static X509 *read_trusted_ca_cert(void)
{
    const char *ca_path =
        getenv("BPFABRIC_CA_CERT");

    if (ca_path == NULL || ca_path[0] == '\0')
    {
        ca_path = "../security/ca/ca_cert.pem";
    }

    FILE *fp = fopen(ca_path, "rb");

    if (fp == NULL)
    {
        perror("Unable to open trusted CA certificate");
        return NULL;
    }

    X509 *ca_cert =
        PEM_read_X509(fp, NULL, NULL, NULL);

    fclose(fp);

    if (ca_cert == NULL)
    {
        fprintf(stderr,
                "Unable to parse trusted CA certificate\n");
        ERR_print_errors_fp(stderr);
    }

    return ca_cert;
}

static int verify_certificate_chain(
    X509 *signer_cert,
    X509 *ca_cert)
{
    int result = 0;

    X509_STORE *store = X509_STORE_new();

    if (store == NULL)
    {
        fprintf(stderr,
                "Unable to create X.509 certificate store\n");
        ERR_print_errors_fp(stderr);
        return 0;
    }

    if (X509_STORE_add_cert(store, ca_cert) != 1)
    {
        fprintf(stderr,
                "Unable to add trusted CA certificate to store\n");
        ERR_print_errors_fp(stderr);
        X509_STORE_free(store);
        return 0;
    }

    X509_STORE_CTX *ctx = X509_STORE_CTX_new();

    if (ctx == NULL)
    {
        fprintf(stderr,
                "Unable to create certificate-store context\n");
        ERR_print_errors_fp(stderr);
        X509_STORE_free(store);
        return 0;
    }

    if (X509_STORE_CTX_init(
            ctx,
            store,
            signer_cert,
            NULL) == 1)
    {
        result = X509_verify_cert(ctx) == 1;
    }
    else
    {
        fprintf(stderr,
                "Unable to initialise certificate verification\n");
        ERR_print_errors_fp(stderr);
    }

    if (!result)
    {
        int error = X509_STORE_CTX_get_error(ctx);

        fprintf(stderr,
                "Certificate verification failed: %s\n",
                X509_verify_cert_error_string(error));
    }

    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);

    return result;
}

static int verify_object_signature(
    X509 *signer_cert,
    const unsigned char *elf,
    size_t elf_len,
    const unsigned char *signature,
    size_t signature_len)
{
    int result = 0;

    EVP_PKEY *public_key =
        X509_get_pubkey(signer_cert);

    if (public_key == NULL)
    {
        fprintf(stderr,
                "Unable to extract public key "
                "from signer certificate\n");
        ERR_print_errors_fp(stderr);
        return 0;
    }

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();

    if (ctx == NULL)
    {
        fprintf(stderr,
                "Unable to create signature-verification context\n");
        ERR_print_errors_fp(stderr);
        EVP_PKEY_free(public_key);
        return 0;
    }

    if (EVP_DigestVerifyInit(
            ctx,
            NULL,
            NULL,
            NULL,
            public_key) == 1)
    {
        result =
            EVP_DigestVerify(
                ctx,
                signature,
                signature_len,
                elf,
                elf_len) == 1;
    }
    else
    {
        fprintf(stderr,
                "Unable to initialise signature verification\n");
        ERR_print_errors_fp(stderr);
    }

    if (!result)
    {
        fprintf(stderr,
                "ELF signature verification failed\n");
        ERR_print_errors_fp(stderr);
    }

    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(public_key);

    return result;
}

int verify_elf_signature_x509(
    const unsigned char *elf,
    size_t elf_len,
    const unsigned char *signature,
    size_t signature_len,
    const unsigned char *certificate,
    size_t certificate_len)
{
    int result = 0;

    if (elf == NULL ||
        signature == NULL ||
        certificate == NULL ||
        elf_len == 0 ||
        signature_len == 0 ||
        certificate_len == 0)
    {
        fprintf(stderr,
                "Missing or empty PVL verification artefact\n");
        return 0;
    }

    fprintf(stderr,
            "[PVL DEBUG] elf_len=%zu, "
            "sig_len=%zu, cert_len=%zu\n",
            elf_len,
            signature_len,
            certificate_len);

    /*
     * Providers must be loaded before parsing an ML-DSA certificate.
     */
    if (!initialise_crypto_providers())
    {
        return 0;
    }

    /*
     * Temporary diagnostic copy of the received certificate.
     * Remove this block after transport integrity is confirmed.
     */
    FILE *debug_cert =
        fopen("/tmp/received_signer_cert.pem", "wb");

    if (debug_cert == NULL)
    {
        perror("Unable to create received-certificate dump");
    }
    else
    {
        size_t written =
            fwrite(
                certificate,
                1,
                certificate_len,
                debug_cert);

        fprintf(stderr,
                "[PVL DEBUG] dumped %zu/%zu "
                "certificate bytes\n",
                written,
                certificate_len);

        fclose(debug_cert);
    }

    X509 *signer_cert =
        read_cert_from_memory(
            certificate,
            certificate_len);

    if (signer_cert == NULL)
    {
        fprintf(stderr,
                "Unable to parse signer certificate\n");
        return 0;
    }

    X509 *ca_cert = read_trusted_ca_cert();

    if (ca_cert == NULL)
    {
        X509_free(signer_cert);
        return 0;
    }

    if (!verify_certificate_chain(
            signer_cert,
            ca_cert))
    {
        goto cleanup;
    }

    if (!verify_object_signature(
            signer_cert,
            elf,
            elf_len,
            signature,
            signature_len))
    {
        goto cleanup;
    }

    result = 1;

cleanup:
    X509_free(ca_cert);
    X509_free(signer_cert);

    return result;
}
