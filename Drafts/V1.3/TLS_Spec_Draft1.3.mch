/* Library
 * Author Alexander Onofrei
 * Creation date: 08-08-2024
 */
MACHINE TLS_specification
/*
  Specification of the TLS protocol
  University of Sherbrooke
  Draft 1.2
 */
CONSTANTS
   session_machine

VARIABLES
   server_certificate,
   client_certificate

DEFINITIONS

    TLS1_2VersionNumber == x0303;
    EmptyValue == {};
    RandomValue == A1;
    CurrentTLSVersion == TLS_1_3;
    PriorTLSVersion == TLS_1_2;
    DefaultKeyShare == {A1B1C1};
    InitialAlertMessage == NONE;
    InitialAlertLevel == OTHER;
    SessionID == "test";
    InitialSessionState == SESSION_CLOSED;
    ServerSupportedVersions == {TLS_1_1, TLS_1_2};
    HelloRetryRandomValue == CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C; //HARDCODED VALUE as mentionned in rfc

    SESSION_MACHINE == struct(State : SESSION_STATE, Status : SESSION_STATUS);
    CERTIFICATE == struct(CertificateType : CERTIFICATE_TYPE, CertificateAuthority : CERTIFICATE_AUTHORITIES, CertificatePublicKey : KEYS, CertificateTimestamp : TIMESTAMP                     );

PROPERTIES
   session_machine = rec(State : SESSION_CLOSED, Status : SUCCEEDED)

INVARIANT
   server_certificate : CERTIFICATE &
   client_certificate : CERTIFICATE
SETS
    TIMESTAMP = {
    D20231231,
    D20241231,
    D20251231};

    KEYS = {
    A1B1C1,
    A2B2C2,
    A3B3C3};

    RANDOM_VALUE = {
        A1,
	B1,
        C1,
	CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C}; 

    VERSION = {
	TLS_1_1,
	TLS_1_2, 
	TLS_1_3};
    
    VERSION_NUMBERS = {
        x0300,
        x0301,
        x0302,
        x0303};

    CIPHER_SUITE = {
	TLS_AES_128_GCM_SHA256, 
	TLS_AES_256_GCM_SHA384, 
	TLS_CHACHA20_POLY1305_SHA256, 
	TLS_AES_128_CCM_SHA256,
	TLS_AES_128_CCM_8_SHA256};

    SIGNATURE_ALGORITHMS = { 
    	/* RSASSA-PKCS1-v1_5 algorithms */
    	rsa_pkcs1_sha25,
    	rsa_pkcs1_sha384,
    	rsa_pkcs1_sha512,
    	/* ECDSA algorithms */
    	ecdsa_secp256r1_sha256,
    	ecdsa_secp384r1_sha384,
    	ecdsa_secp521r1_sha512,
    	/* RSASSA-PSS algorithms with public key OID rsaEncryption */
    	rsa_pss_rsae_sha256,
    	rsa_pss_rsae_sha384,
    	rsa_pss_rsae_sha512,
    	/* EdDSA algorithms */
    	ed25519,
    	ed448,
    	/* RSASSA-PSS algorithms with public key OID RSASSA-PSS */
    	rsa_pss_pss_sha256,
    	rsa_pss_pss_sha384,
    	rsa_pss_pss_sha512,
    	/* Legacy algorithms */
    	rsa_pkcs1_sha1,
    	ecdsa_sha1,
    	/* Reserved Code Points */
    	private_use};

    SUPPORTED_GROUPS = {X25519, X448};

    CERTIFICATE_TYPE = {X509,SSL,PGP};

    CERTIFICATE_AUTHORITIES = {ENTRUST, DIGICERT, COMODO};

    SESSION_STATE = {SENDCLIENTHELLO, RECEIVECLIENTHELLO,
                     SENDSERVERHELLO, RECEIVESERVERHELLO,
                     SENDHELLORETRYREQUEST, RECEIVEHELLORETRYREQUEST,
                     SENDENCRYPTEDEXTENSIONS, RECEIVEENCRYPTEDEXTENSIONS,
                     SENDSERVERCERTIFICATE,RECEIVESERVERCERTIFICATE,
                     SENDCLIENTCERTIFICATEREQUEST, RECEIVECLIENTCERTIFICATEREQUEST,
                     SESSION_CLOSED};

    SESSION_STATUS = {SUCCEEDED, FAILED};

    ALERT_MESSAGE = {NONE, PROTOCOL_VERSION, ILLEGAL_PARAMETER, HANDSHAKE_FAILURE, UNEXPECTED_MESSAGE};

    ALERT_LEVEL = {WARNING, FATAL, OTHER}

INITIALISATION
    server_certificate := rec(CertificateType : X509, CertificateAuthority : ENTRUST, CertificatePublicKey : A1B1C1, CertificateTimestamp : D20251231) ||
    client_certificate := rec(CertificateType : X509, CertificateAuthority : ENTRUST, CertificatePublicKey : A2B2C2, CertificateTimestamp : D20241231)

END