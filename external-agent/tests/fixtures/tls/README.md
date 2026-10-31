These certificates and the private key are public, local integration-test fixtures.
Never use them as production credentials or install this CA into system trust.
The server certificate covers `validator.example`; the second leaf expired in 2021.
Regenerate with `python3 scripts/generate_test_certificates.py` when the valid leaf expires.
The CA private key is generated in a temporary directory and is not retained.
