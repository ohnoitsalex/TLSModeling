/* Library
 * Author Alexander Onofrei
 * Creation date: 08-08-2024
 */
MACHINE TLS_specification
/*
  Specification of the TLS protocol
  University of Sherbrooke
  Draft 1.1
 */
SETS
    VERSION = {TLS_1_2, TLS_1_3};
    CIPHER_SUITE = {TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256, TLS_AES_128_CCM_SHA256,TLS_AES_128_CCM_8_SHA256};
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
    SUPPORTED_GROUPS = {/*1.3 supports only DH based KEMS */
    X25519,
    X448};
    EXTENSION = {KEY_SHARE, SERVER_NAME};
    RANDOM;
    SESSION_STATE = {CLIENTHELLO_INITATED, CLIENTHELLO_FAILED, CLIENTHELLO_SUCCEDED};
    ALERT_MESSAGE = {ACCEPTED, PROTOCOL_VERSION, ILLEGAL_PARAMETER, HANDSHAKE_FAILURE};
    ALERT_LEVEL = {WARNING, FATAL, OTHER}

VARIABLES
    legacy_version,        /* Version field from TLS 1.2 */
    client_version,        /* Version field for TLS 1.3 */
    random,                /* Random value */
    legacy_session_id,     /* Session ID from TLS 1.2 -- NOT SUPPORTED IN TLS 1.3*/
    legacy_session_id_echo /* echo used in hello retry request to see if it matches the legacy_session_id */
    legacy_compression_methods, /* Compression methods from TLS 1.2 -- (IGNORED??) IN TLS 1.3*/
    session_id,            /* Session ID for resumption in TLS 1.3 */
    cipher_suites,         /* Supported cipher suites */
    extensions,            /* Extensions in ClientHello */
    session_state,         /* State of the session */
    key_share,             /* Key share for TLS 1.3 */
    server_name,           /* Server name for SNI */
    alert_message,         /* Alert message indicating success or failure */
    alert_level,           /* Severity of the alert message */
    signature_algorithms,  /* Extension containing list of supported signature algorithms*/
    supported_groups,      /* Extension containing list of supported kems*/
    supported_versions,    /* List of supported versions */
    pre_shared_key         /* List of symmetric key identifies known to the client*/

INVARIANT
    legacy_version : VERSION &
    client_version : VERSION &
    random : POW(RANDOM) &
    legacy_session_id : STRING &
    legacy_session_id_echo : STRING &
    legacy_compression_methods : INTEGER &
    session_id : STRING &
    cipher_suites : POW(CIPHER_SUITE) &
    extensions : POW(EXTENSION) &
    session_state : SESSION_STATE &
    key_share : STRING &
    server_name : STRING &
    alert_message : ALERT_MESSAGE &
    alert_level : ALERT_LEVEL &
    signature_algorithms : POW(SIGNATURE_ALGORITHMS) &
    supported_groups : POW(SUPPORTED_GROUPS) &
    supported_versions : POW(VERSION) &
    pre_shared_key : POW(INTEGER)

INITIALISATION
    legacy_version := TLS_1_2 ||
    client_version := TLS_1_3 ||
    random := RANDOM ||
    legacy_session_id := "0x0303" || /*Must be set to this value which referenciates the TLS version 1.2*/
    legacy_session_id_echo := "0x0303" /*Must be set to this value which referenciates the TLS version 1.2 -> used after helloretryrequest to check if it matches 						the legacy_session_id*/
    legacy_compression_methods := 0 ||
    session_id := "1234" ||
    cipher_suites := {} ||
    extensions := {KEY_SHARE, SERVER_NAME} ||
    session_state := CLIENTHELLO_INITATED ||
    key_share := "1" ||
    server_name := "test" ||
    alert_message := ACCEPTED ||
    alert_level := OTHER ||
    signature_algorithms := {} ||
    supported_groups := {} ||
    supported_versions := {} ||
    pre_shared_key := {}

OPERATIONS
    ClientHello (p_supported_versions, p_legacy_compression_methods, p_pre_shared_key, p_signature_algorithms, p_supported_groups, p_cipher_suites) =
    PRE
        session_state = CLIENTHELLO_INITATED &
        p_supported_versions : POW(VERSION) &
        p_legacy_compression_methods : INTEGER &
        p_legacy_compression_methods ∈ {0, 1} & /* We're limiting the value to 0 or one to simplify the process -- WILL BE REMOVED*/
	p_pre_shared_key : POW(INTEGER) &
        card (p_pre_shared_key) <= 2 &  /*limit cardinality for computing purposes -- WILL BE REMOVED*/
	p_signature_algorithms : POW(SIGNATURE_ALGORITHMS) &
        p_supported_groups : POW (SUPPORTED_GROUPS) &
        p_cipher_suites : POW(CIPHER_SUITE)
    THEN
        supported_versions := p_supported_versions ||
        legacy_compression_methods := p_legacy_compression_methods ||
        pre_shared_key := p_pre_shared_key || /* It is possible for the pre_shared_key field to be empty if no symmetric key identities are known to the client */
        signature_algorithms := p_signature_algorithms ||
        supported_groups := p_supported_groups ||
        cipher_suites := p_cipher_suites;
        /* Simulate sending ClientHello and determine the alert message */
        IF TLS_1_3 : supported_versions THEN
            IF (signature_algorithms /= {}) &
               (supported_groups /= {}) &
	       (KEY_SHARE : extensions) &
               (cipher_suites /= {}) & 
               (legacy_compression_methods = 0)
               THEN
                   session_state := CLIENTHELLO_SUCCEDED
            ELSE
                /* Determine the specific reason for refusal */
                IF (supported_versions = {}) 
		   THEN
                      alert_message := PROTOCOL_VERSION ||
                      alert_level := FATAL
                /* If the list of cipher_suites is empty, handshake is impossible */
                /* If the legacy compression method is any other BYTE value other than 0 -> Return Illegal_Parameter alert*/
		/* Check if supported signatures algorithms is part of the available signature algorithms */
		/* Check if supported groups is part of the available KEM algorithms (supported groups algorithms) */
                ELSE IF (cipher_suites = {}) or 
                    not (legacy_compression_methods = 0) or
                    (signature_algorithms = {}) or
                    (supported_groups = {}) 
                   THEN
                      alert_message := ILLEGAL_PARAMETER || 
                      alert_level := FATAL
                /*If Something else is missing */
                ELSE
                    alert_message := HANDSHAKE_FAILURE ||
                    alert_level := FATAL
                END;
                session_state := CLIENTHELLO_FAILED
           	END
        END
        ELSE
            alert_message := PROTOCOL_VERSION ||
            alert_level := FATAL ||
            session_state := CLIENTHELLO_FAILED 
        END
    END
END