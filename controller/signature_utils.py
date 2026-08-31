import os

def load_signature_for_object(object_path):
	signature_path=object_path+".sig"

	if not os.path.isfile(signature_path):
		raise FileNotFoundError(f"Missing signature files: {signature_path}")
	with open(signature_path,"rb") as f:
		return f.read()

def load_signer_certificate():
	cert_path=os.environ.get(
		"BPFABRIC_SIGNER_CERT",
		"../security/signer/signer_cert.pem"
	)

	if not os.path.isfile(cert_path):
		raise FileNotFoundError(f"Missing signer certificate: {cert_path}")
	with open(cert_path,"rb") as f:
		return f.read()
