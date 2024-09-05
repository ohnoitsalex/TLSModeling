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
    ocsp_status_constant,
    compression_method_constant

DEFINITIONS
    NoLegacyVersionNumber == NO_VERSION;
    TLS1_2VersionNumber == x0303;
    EmptyValue == {};
    RandomValue == A1;
    KeyShare == {A1B1C1};
    CurrentTLSVersion == TLS_1_3;
    PriorTLSVersion == TLS_1_2;
    DefaultKeyShare == {A1B1C1};
    InitialAlertMessage == NONE;
    InitialAlertLevel == OTHER;
    InitialSessionState == SESSION_CLOSED;
    ServerSupportedVersions == {TLS_1_1, TLS_1_2};
    HelloRetryRandomValue == CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C; //HARDCODED VALUE as mentionned in rfc

    SESSION_MACHINE == struct(State : SESSION_STATE, Status : SESSION_STATUS);
    CERTIFICATE == struct(CertificateType : CERTIFICATE_TYPE, CertificateAuthority : CERTIFICATE_AUTHORITIES, CertificatePublicKey : KEYS, CertificateTimestamp : TIMESTAMP,
                          OCSPStatus : ocsp_status_constant, CertificateRequestContext : RANDOM_VALUE);
    MESSAGE_ALERT == struct(Message : ALERT_MESSAGE, AlertLevel : ALERT_LEVEL);

SETS
    IDS = {
    ID1,
    ID2};

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
        x0303,
        NO_VERSION};

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

VARIABLES

    /*Machines and Messages Variables*/
    session_machine,
    alert_message,
   
    /*SERVER PARAMS */
    server_certificate,
    client_certificate,
    certificate_request_context, /* An opaque string which identifies the certificate request and which will be echoed in the client's Certificate message*/
    certificate_request_signature_algorithm,

    /*HELLO RETRY PARAMS*/
    hello_retry_request_count,       /* Number of times a hello retry request has been sent -? If more than once, stop handshake */
    hello_retry_message,            /* Message with the HelloRetryRequest */

    /* CLIENT PARAMS*/
    client_pre_shared_key,        /* Client List of symmetric key identifies known to the client*/
    client_random,                /* Client Random value */
    client_legacy_version,        /* Client Version field from TLS 1.2 */
    client_version,               /* Client Version field for TLS 1.3 */
    client_legacy_session_id,     /* Client Session ID from TLS 1.2 -- NOT SUPPORTED IN TLS 1.3*/
    client_legacy_session_id_echo,/* Client echo used in hello retry request to see if it matches the legacy_session_id */
    client_legacy_compression_methods, /* Client Compression methods from TLS 1.2 -- (IGNORED??) IN TLS 1.3*/
    client_cipher_suites,         /* Client Supported cipher suites */
    client_key_share,             /* Client Key share for TLS 1.3 */
    client_signature_algorithms,  /* Client Extension containing list of supported signature algorithms*/
    client_supported_groups,      /* Client Extension containing list of supported kems*/
    client_supported_versions,    /* Client List of supported versions */

    /* SERVER PARAMS*/
    server_random,                /* Server Random value */
    server_legacy_session_id_echo,/* Server echo used in hello retry request to see if it matches the legacy_session_id */
    server_cipher_suite,          /* Server Supported cipher suites */
    server_legacy_compression_methods, /* Server Compression methods from TLS 1.2 -- (IGNORED??) IN TLS 1.3*/
    server_supported_versions,    /* Server List of supported versions */    
    server_key_share,             /* Server Key share for TLS 1.3 */
    server_pre_shared_key,        /* Server List of symmetric key identifies known to the client*/
    server_legacy_version,        /* Legacy version. Needs to be set to 0x0303 by default for TLS 1.3 to work. This means the server will be using the supported_versions                                                   extensions */
    server_supported_group,       /* Server Extension containing one of supported kems*/   
    server_signature_algorithm   /* Server Extension containing one of supported signature algorithms*/

PROPERTIES

    ocsp_status_constant = 0..3 &
    compression_method_constant = 0..1

INVARIANT

    /*Machines and Messages Invariants*/
    session_machine : SESSION_MACHINE &
    alert_message : MESSAGE_ALERT &
    /*Certificate Invariants */
    server_certificate : CERTIFICATE &
    client_certificate : CERTIFICATE &
    certificate_request_context : RANDOM_VALUE &
    certificate_request_signature_algorithm : SIGNATURE_ALGORITHMS & 

    /*HELLO RETRY PARAMS*/
    hello_retry_request_count : INTEGER &       /* Number of times a hello retry request has been sent -? If more than once, stop handshake */
    hello_retry_message : STRING &             /* Message with the HelloRetryRequest

    /*Client Invariants */
    client_pre_shared_key : POW(KEYS) &
    client_random : RANDOM_VALUE & //In our case, the random number will be formatted under string value
    client_legacy_version : VERSION_NUMBERS &
    client_version : VERSION &
    client_legacy_session_id : VERSION_NUMBERS &
    client_legacy_session_id_echo : VERSION_NUMBERS &
    client_legacy_compression_methods : compression_method_constant &
    client_cipher_suites : POW(CIPHER_SUITE) &
    client_key_share : POW(KEYS) &
    client_signature_algorithms : POW(SIGNATURE_ALGORITHMS) &
    client_supported_groups : POW(SUPPORTED_GROUPS) &
    client_supported_versions : POW(VERSION) &

    /* Sever Invariants*/
    server_random : RANDOM_VALUE & //In our case, the random number will be formatted under string value
    server_legacy_session_id_echo : VERSION_NUMBERS &
    server_cipher_suite : CIPHER_SUITE &
    server_legacy_compression_methods : compression_method_constant &
    server_supported_versions : POW(VERSION) &
    server_key_share : POW(KEYS) &
    server_pre_shared_key : POW(KEYS) &
    server_legacy_version : VERSION_NUMBERS &
    server_supported_group : SUPPORTED_GROUPS &
    server_signature_algorithm : SIGNATURE_ALGORITHMS 

INITIALISATION

    session_machine := rec(State : SESSION_CLOSED, Status : SUCCEEDED) ||
    alert_message := rec (Message : NONE, AlertLevel : OTHER) ||
    
    /*CERTIFICATE INIT */
    certificate_request_context :=  RandomValue||
    certificate_request_signature_algorithm := private_use ||//Will need to be changed to empty value
    server_certificate := rec(CertificateType : X509, CertificateAuthority : ENTRUST, CertificatePublicKey : A1B1C1, CertificateTimestamp : D20251231, OCSPStatus : 0,
                              CertificateRequestContext : A1) ||
    client_certificate := rec(CertificateType : X509, CertificateAuthority : ENTRUST, CertificatePublicKey : A2B2C2, CertificateTimestamp : D20241231, OCSPStatus : 0,
                              CertificateRequestContext : B1) ||

    /*HELLO RETRY INIT*/
    hello_retry_request_count := 0 ||       
    hello_retry_message := "" ||       

    /*Client params initialisation */
    client_pre_shared_key := EmptyValue ||
    client_random := RandomValue ||
    client_legacy_version := NoLegacyVersionNumber ||
    client_version := CurrentTLSVersion ||
    client_legacy_session_id := TLS1_2VersionNumber || /*Must be set to this value which referenciates the TLS version 1.2*/
    client_legacy_session_id_echo := TLS1_2VersionNumber || /*Must be set to this value which referenciates the TLS version 1.2 -> used after helloretryrequest to check i                                                               f it match the legacy_session_id*/
    client_legacy_compression_methods := 0 ||
    client_cipher_suites := EmptyValue ||
    client_key_share := KeyShare ||
    client_signature_algorithms := EmptyValue ||
    client_supported_groups := EmptyValue ||
    client_supported_versions := EmptyValue ||

    /*Server params initialisation */
    server_random := RandomValue || 
    server_legacy_session_id_echo := TLS1_2VersionNumber || /*Must be set to this value which referenciates the TLS version 1.2 -> used after helloretryrequest to check if 
                                                             it matchthe legacy_session_id*/
    server_cipher_suite := TLS_AES_128_GCM_SHA256 ||
    server_legacy_compression_methods := 0 ||
    server_supported_versions := ServerSupportedVersions ||
    server_key_share := KeyShare ||
    server_pre_shared_key := KeyShare ||
    server_legacy_version := NoLegacyVersionNumber ||
    server_supported_group := X448 ||  //Will need to be changed to empty value
    server_signature_algorithm := private_use //Will need to be changed to empty value

OPERATIONS

    SendClientHello (legacy_version, supported_versions, legacy_compression_methods, pre_shared_key, signature_algorithms, supported_groups, cipher_suites) =
    PRE /*Still need to add the random in the PRE*/
        session_machine'State = SESSION_CLOSED or 
        (session_machine'State = RECEIVEHELLORETRYREQUEST & session_machine'Status = SUCCEEDED) &
        supported_versions : POW(VERSION) &
        legacy_compression_methods : compression_method_constant &
	pre_shared_key : POW(KEYS) &
        //card (pre_shared_key) <= 2 &  /*limit cardinality for computing purposes -- WILL BE REMOVED*/
	signature_algorithms : POW(SIGNATURE_ALGORITHMS) &
        supported_groups : POW (SUPPORTED_GROUPS) &
        cipher_suites : POW(CIPHER_SUITE) &
        legacy_version : VERSION_NUMBERS
    THEN
        client_supported_versions := supported_versions ||
        client_legacy_compression_methods := legacy_compression_methods ||
        client_pre_shared_key := pre_shared_key || /* It is possible for the pre_shared_key field to be empty if no symmetric key identities are known to the client */
        client_signature_algorithms := signature_algorithms ||
        client_supported_groups := supported_groups ||
        client_cipher_suites := cipher_suites ||
        client_legacy_version := legacy_version;
        /* Simulate sending ClientHello and determine the alert message */
        IF TLS_1_3 : client_supported_versions
	    THEN
               IF (client_signature_algorithms /= {}) &
                  (client_supported_groups /= {}) &
                  (client_cipher_suites /= {}) & 
                  (client_legacy_compression_methods = 0)
                  THEN
                    alert_message := rec (Message : PROTOCOL_VERSION, AlertLevel : FATAL) ||
                    hello_retry_request_count := 0 //Reset to 0 for each ClientHello request sent
               ELSE
                  /* Determine the specific reason for refusal */
                  IF (client_supported_versions = {})  /*THIS IF CAN BE REMOVED */
		     THEN
                        session_machine := rec(State : SENDCLIENTHELLO, Status : FAILED) 
                  /* If the list of cipher_suites is empty, handshake is impossible */
                  /* If the legacy compression method is any other BYTE value other than 0 -> Return Illegal_Parameter alert*/
		  /* Check if supported signatures algorithms is part of the available signature algorithms */
		  /* Check if supported groups is part of the available KEM algorithms (supported groups algorithms) */
                  ELSE IF (client_cipher_suites = {}) or 
                     not (client_legacy_compression_methods = 0) or
                     (client_signature_algorithms = {}) or
                     (client_supported_groups = {}) or
                     not (client_legacy_version = TLS1_2VersionNumber)
                     THEN
                        alert_message := rec (Message : ILLEGAL_PARAMETER, AlertLevel : FATAL)
                  /*If Something else is missing */
                  ELSE
                      alert_message := rec (Message : HANDSHAKE_FAILURE, AlertLevel : FATAL)
                  END;
                  session_machine := rec(State : SENDCLIENTHELLO, Status : FAILED)
           	  END
           END
        ELSE
            alert_message := rec (Message : PROTOCOL_VERSION, AlertLevel : FATAL) ||
            session_machine := rec(State : SENDCLIENTHELLO, Status : FAILED)
        END
    END;

    TerminateSession = 
    PRE
        session_machine'Status = FAILED
    THEN
    	session_machine := rec(State : SESSION_CLOSED, Status : SUCCEEDED) ||
    	alert_message := rec (Message : NONE, AlertLevel : OTHER) ||
    
    	/*CERTIFICATE INIT */
    	certificate_request_context :=  RandomValue||
    	certificate_request_signature_algorithm := private_use ||//Will need to be changed to empty value
    	server_certificate := rec(CertificateType : X509, CertificateAuthority : ENTRUST, CertificatePublicKey : A1B1C1, CertificateTimestamp : D20251231, OCSPStatus : 0,
                              CertificateRequestContext : A1) ||
    	client_certificate := rec(CertificateType : X509, CertificateAuthority : ENTRUST, CertificatePublicKey : A2B2C2, CertificateTimestamp : D20241231, OCSPStatus : 0,
                              CertificateRequestContext : B1) ||

    	/*HELLO RETRY INIT*/
    	hello_retry_request_count := 0 ||       
    	hello_retry_message := "" ||       

    	/*Client params initialisation */
    	client_pre_shared_key := EmptyValue ||
    	client_random := RandomValue ||
    	client_legacy_version := NoLegacyVersionNumber ||
    	client_version := CurrentTLSVersion ||
    	client_legacy_session_id := TLS1_2VersionNumber || /*Must be set to this value which referenciates the TLS version 1.2*/
    	client_legacy_session_id_echo := TLS1_2VersionNumber || /*Must be set to this value which referenciates the TLS version 1.2 -> used after helloretryrequest to check i                                                               f it match the legacy_session_id*/
    	client_legacy_compression_methods := 0 ||
    	client_cipher_suites := EmptyValue ||
    	client_key_share := KeyShare ||
    	client_signature_algorithms := EmptyValue ||
    	client_supported_groups := EmptyValue ||
    	client_supported_versions := EmptyValue ||

    	/*Server params initialisation */
    	server_random := RandomValue || 
    	server_legacy_session_id_echo := TLS1_2VersionNumber || /*Must be set to this value which referenciates the TLS version 1.2 -> used after helloretryrequest to check i                                                               f it matchthe legacy_session_id*/
    	server_cipher_suite := TLS_AES_128_GCM_SHA256 ||
    	server_legacy_compression_methods := 0 ||
    	server_supported_versions := ServerSupportedVersions ||
    	server_key_share := KeyShare ||
    	server_pre_shared_key := KeyShare ||
    	server_legacy_version := NoLegacyVersionNumber ||
    	server_supported_group := X448 ||  //Will need to be changed to empty value
    	server_signature_algorithm := private_use //Will need to be changed to empty value
    	END
END