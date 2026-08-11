#include "signature_verifier.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

static X509 *read_cert_from_memory(const unsigned char *data, size_t len)
{
	BIO *bio = BIO_new_mem_buf(data, (int)len);
	if (bio==NULL)
	{
		return NULL;
	}

	X509 *cert = PEM_read_bio_X509(bio, NULL,NULL,NULL);
	BIO_free(bio);
	return cert;
}

static X509 *read_trusted_ca_cert(void)
{
	const char *ca_path = getenv("BPFABRIC_CA_CERT");

	if (ca_path == NULL)
	{
		ca_path="../security/ca/ca_cert.pem";
	}
	FILE *fp = fopen(ca_path, "r");
	if (fp==NULL)
	{
		perror("Unable to open trusted CA certificate");
		return NULL;
	}

	X509 *ca_cert = PEM_read_X509(fp,NULL,NULL,NULL);
	fclose(fp);
	if (ca_cert == NULL)
	{
		fprintf(stderr, "Unable to parse trusted CA certificate\n");
	}
	return ca_cert;
}

static int verify_certificate_chain(X509 *signer_cert, X509 *ca_cert)
{
	int result = 0;

	X509_STORE *store = X509_STORE_new();
	if (store == NULL)
	{
		return 0;
	}

	if (X509_STORE_add_cert(store,ca_cert) !=1)
	{
		X509_STORE_free(store);
		return 0;
	}
	X509_STORE_CTX *ctx = X509_STORE_CTX_new();
	if (ctx == NULL)
	{
		X509_STORE_free(store);
		return 0;
	}
	if (X509_STORE_CTX_init(ctx,store,signer_cert,NULL)==1)
	{
		result=X509_verify_cert(ctx) == 1;
	}
	if (!result)
	{
		int err = X509_STORE_CTX_get_error(ctx);
		fprintf(stderr, "Certificate verification failed: %s\n", X509_verify_cert_error_string(err));
	}

	X509_STORE_CTX_free(ctx);
	X509_STORE_free(store);

	return result;

}

static int verify_object_signature(X509 *signer_cert, const unsigned char *elf, size_t elf_len, const unsigned char *sig, size_t sig_len)
{
	int result = 0;

	EVP_PKEY *pubkey = X509_get_pubkey(signer_cert);
	if (pubkey==NULL)
	{
		fprintf(stderr, "Unable to extract public key from signer certificate\n");
		return 0;
	}

	EVP_MD_CTX *ctx = EVP_MD_CTX_new();
	if (ctx == NULL)
	{
		EVP_PKEY_free(pubkey);
		return 0;
	}

	if (EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, pubkey) == 1)
	{
		result = EVP_DigestVerify(ctx, sig, sig_len, elf, elf_len) == 1;
	}

	if (!result)
	{
		fprintf(stderr, "ELF signature verification failed\n");
	}

	EVP_MD_CTX_free(ctx);
	EVP_PKEY_free(pubkey);
	return result;
}

int verify_elf_signature_x509(const unsigned char *elf, size_t elf_len, const unsigned char *sig, size_t sig_len, const unsigned char *cert, size_t cert_len)
{
	int result = 0;
	X509 *signer_cert = read_cert_from_memory(cert, cert_len);
	if (signer_cert == NULL)
	{
		fprintf(stderr, "Unable to parse signer certification\n");
		return 0;
	}

	X509 *ca_cert = read_trusted_ca_cert();
	if (ca_cert == NULL)
	{
		X509_free(signer_cert);
		return 0;
	}

	if (!verify_certificate_chain(signer_cert, ca_cert))
	{
		goto cleanup;
	}

	if (!verify_object_signature(signer_cert, elf, elf_len, sig, sig_len))
	{
		goto cleanup;
	}

	result = 1;

cleanup:
	X509_free(ca_cert);
	X509_free(signer_cert);

	return result;
}
