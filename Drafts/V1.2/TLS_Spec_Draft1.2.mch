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

DEFINITIONS
    TLS1_2VersionNumber == "0x0303
    EmptyValue == {};
    EmptyString == "";
    RandomValue == "randomStringValue";
    CurrentTLSVersion == TLS_1_3;
    PriorTLSVersion == TLS_1_2;
    KeyShare == {"1"};
    ServerName == "test";
    InitialAlertMessage == NONE;
    InitialAlertLevel == OTHER;
    SessionID == "test";
    InitialSessionState == SESSION_CLOSED;
    ServerSupportedVersions == {TLS_1_1, TLS_1_2};
    HelloRetryRandomValue == "CF 21 AD 74 E5 9A 61 11 BE 1D 8C 02 1E 65 B8 91 C2 A2 11 16 7A BB 8C 5E 07 9E 09 E2 C8 A8 33 9C" //HARDCODED VALUE as mentionned in rfc

SETS
    VERSION = {TLS_1_1, TLS_1_2, TLS_1_3};
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
    SUPPORTED_GROUPS = {X25519, X448};
    CERTIFICATE_TYPE = {X509,SSL,PGP};
    CERTIFICATE_AUTHORITIES = {ENTRUST, DIGICERT, COMODO};
    SESSION_STATE = {SENDCLIENTHELLO_FAILED, SENDCLIENTHELLO_SUCCEEDED, RECEIVECLIENTHELLO_SUCCEEDED, SENDSERVERHELLO_FAILED,
                     SENDSERVERHELLO_SUCCEEDED, SENDHELLORETRYREQUEST,SENDHELLORETRYREQUEST_FAILED, SENDHELLORETRYREQUEST_SUCCEEDED,
                     RECEIVEHELLORETRYREQUEST_FAILED,RECEIVEHELLORETRYREQUEST_SUCCEEDED,SENDENCRYPTEDEXTENSIONS_FAILED,SENDENCRYPTEDEXTENSIONS_SUCCEEDED, 
                     SENDCLIENTCERTIFICATEREQUEST_FAILED, SENDCLIENTCERTIFICATEREQUEST_SUCCEEDED, SENDSERVERCERTIFICATE_FAILED, SENDSERVERCERTIFICATE_SUCCEEDED,
                     RECEIVEENCRYPTEDEXTENSIONS_FAILED, RECEIVEENCRYPTEDEXTENSIONS_SUCCEEDED, RECEIVESERVERCERTIFICATE_SUCCEEDED, RECEIVESERVERCERTIFICATE_FAILED,
                     SESSION_CLOSED};
    ALERT_MESSAGE = {NONE, PROTOCOL_VERSION, ILLEGAL_PARAMETER, HANDSHAKE_FAILURE, UNEXPECTED_MESSAGE};
    ALERT_LEVEL = {WARNING, FATAL, OTHER}

VARIABLES
    server_name,                  /* Server name for SNI */
    alert_message,                /* Alert message indicating success or failure */
    alert_level,                  /* Severity of the alert message */
    session_state,                /* State of the session */
    session_id,                   /* Session ID for resumption in TLS 1.3 */
    helloRetryRequestCount,       /* Number of times a hello retry request has been sent -? If more than once, stop handshake */
    helloRetryMessage,            /* Message with the HelloRetryRequest */

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
    server_legacy_version,        /* Legacy version. Needs to be set to 0x0303 by default for TLS 1.3 to work. This means the server will be using the supported_versions                                        extensions */
    server_supported_group,       /* Server Extension containing one of supported kems*/   
    server_signature_algorithm,   /* Server Extension containing one of supported signature algorithms*/

    //Certificate Information     
    certificate_request_context, /* An opaque string which identifies the certificate request and which will be echoed in the client's Certificate message*/
    certificate_request_signature_algorithm,

    server_raw_public_key_certificate, /* */
    server_certificate_type, 
    server_signed_certificate_timestamp,
    server_ocsp_status,
    server_certificate_authorities,

    client_public_key_certificate, /* Public Key related to the certificate */
    client_certificate_type, 
    client_signed_certificate_timestamp,
    client_ocsp_status,
    client_certificate_authorities,
    client_certificate_request_context /*Supposed to match the certificate_request_context from the certificate request coming from the server */

INVARIANT
    server_name : STRING &
    alert_message : ALERT_MESSAGE &
    alert_level : ALERT_LEVEL &
    session_id : STRING &
    session_state : SESSION_STATE &
    helloRetryRequestCount : INTEGER &       /* Number of times a hello retry request has been sent -? If more than once, stop handshake */
    helloRetryMessage : STRING &             /* Message with the HelloRetryRequest

    /*Client Invariants */
    client_pre_shared_key : POW(STRING) &
    client_random : STRING & //In our case, the random number will be formatted under string value
    client_legacy_version : STRING &
    client_version : VERSION &
    client_legacy_session_id : STRING &
    client_legacy_session_id_echo : STRING &
    client_legacy_compression_methods : INTEGER &
    client_cipher_suites : POW(CIPHER_SUITE) &
    client_key_share : POW(STRING) &
    client_signature_algorithms : POW(SIGNATURE_ALGORITHMS) &
    client_supported_groups : POW(SUPPORTED_GROUPS) &
    client_supported_versions : POW(VERSION) &

    /* Sever Invariants*/
    server_random : STRING & //In our case, the random number will be formatted under string value
    server_legacy_session_id_echo : STRING &
    server_cipher_suite : CIPHER_SUITE &
    server_legacy_compression_methods : INTEGER &
    server_supported_versions : POW(VERSION) &
    server_key_share : POW(STRING) &
    server_pre_shared_key : POW(STRING) &
    server_legacy_version : STRING &
    server_supported_group : SUPPORTED_GROUPS &
    server_signature_algorithm : SIGNATURE_ALGORITHMS &

    /*Certificate Invariants */
    certificate_request_context : STRING &
    certificate_request_signature_algorithm : SIGNATURE_ALGORITHMS & 

    server_raw_public_key_certificate : STRING & 
    server_certificate_type : CERTIFICATE_TYPE &
    server_signed_certificate_timestamp : STRING &
    server_ocsp_status : INTEGER &
    server_certificate_authorities : CERTIFICATE_AUTHORITIES &

    client_public_key_certificate : STRING & 
    client_certificate_type : CERTIFICATE_TYPE &
    client_signed_certificate_timestamp : STRING &
    client_ocsp_status : INTEGER & 
    client_certificate_authorities : CERTIFICATE_AUTHORITIES &
    client_certificate_request_context : STRING/*Supposed to match the certificate_request_context from the certificate request coming from the server */


INITIALISATION
    server_name := ServerName ||
    alert_message := InitialAlertMessage ||
    alert_level := InitialAlertLevel ||
    session_id := TLS1_2VersionNumber ||
    session_state := InitialSessionState ||
    helloRetryRequestCount := 0 ||       
    helloRetryMessage := "" ||       

    /*Client params initialisation */
    client_pre_shared_key := EmptyValue ||
    client_random := RandomValue ||
    client_legacy_version := EmptyString ||
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
    server_legacy_version := EmptyString ||
    server_supported_group := X448 ||  //Will need to be changed to empty value
    server_signature_algorithm := private_use ||//Will need to be changed to empty value

    certificate_request_context := EmptyString ||
    certificate_request_signature_algorithm := private_use ||//Will need to be changed to empty value


    server_raw_public_key_certificate := EmptyString ||
    server_certificate_type := X509 || /* Default value */
    server_signed_certificate_timestamp := EmptyString ||
    server_ocsp_status := 0 || 
    server_certificate_authorities := ENTRUST || /* Will need to be changed to an empty value */

    client_public_key_certificate := EmptyString || 
    client_certificate_type := X509 || /* Default value */
    client_signed_certificate_timestamp := EmptyString ||
    client_ocsp_status := 0 ||
    client_certificate_authorities := ENTRUST ||
    client_certificate_request_context := EmptyString /*Supposed to match the certificate_request_context from the certificate request coming from the server */

OPERATIONS

    SendClientHello (legacy_version, supported_versions, legacy_compression_methods, pre_shared_key, signature_algorithms, supported_groups, cipher_suites) =
    PRE /*Still need to add the random in the PRE*/
        session_state = SESSION_CLOSED or 
        session_state = RECEIVEHELLORETRYREQUEST_SUCCEEDED &
        supported_versions : POW(VERSION) &
        legacy_compression_methods : INTEGER &
        legacy_compression_methods ∈ {0, 1} & /* We're limiting the value to 0 or one to simplify the process -- WILL BE REMOVED*/
	pre_shared_key : POW(STRING) &
        //card (pre_shared_key) <= 2 &  /*limit cardinality for computing purposes -- WILL BE REMOVED*/
	signature_algorithms : POW(SIGNATURE_ALGORITHMS) &
        supported_groups : POW (SUPPORTED_GROUPS) &
        cipher_suites : POW(CIPHER_SUITE) &
        legacy_version : STRING
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
                    session_state := SENDCLIENTHELLO_SUCCEEDED;
                    helloRetryRequestCount := 0 //Reset to 0 for each ClientHello request sent
               ELSE
                  /* Determine the specific reason for refusal */
                  IF (client_supported_versions = {})  /*THIS IF CAN BE REMOVED */
		     THEN
                        alert_message := PROTOCOL_VERSION ||
                        alert_level := FATAL
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
                        alert_message := ILLEGAL_PARAMETER || 
                        alert_level := FATAL
                  /*If Something else is missing */
                  ELSE
                      alert_message := HANDSHAKE_FAILURE ||
                      alert_level := FATAL
                  END;
                  session_state := SENDCLIENTHELLO_FAILED
           	  END
           END
        ELSE
            alert_message := PROTOCOL_VERSION ||
            alert_level := FATAL ||
            session_state := SENDCLIENTHELLO_FAILED 
        END
    END;
    
    /* Server Receives the ClientHello -> Parameters are not added here because there are considered in the sendclienthello operation */
    ReceiveClientHello =
    PRE session_state = SENDCLIENTHELLO_SUCCEEDED
    THEN
         /* Check if the Server has the parameter that are needed to establish an handshake
         Here, we consider the following parameters based on the RFC8446
         -List of signature algorithms
         -List of ciphers
         -List of supported groups
         -Legacy compression method set to 0 -> in order to supported TLS 1.3
         -List of supported Versions
         -NO ALERT MESSAGES SHOULD BE SENT?? -> ONLY SEND HELLORETRYREQUEST IF SOMETHING DOESN'T ADD UP
         -Here we considered only empty sents as a invalid value -> Later we can change this to a value that the server does not support
         */
        IF not(TLS_1_3 : client_supported_versions) or 
	   (client_signature_algorithms = {}) or
           (client_supported_groups = {}) or
           (client_cipher_suites = {}) or 
           (client_legacy_compression_methods /= 0) or
           (client_supported_versions /\ server_supported_versions = {})
	   THEN
                session_state := SENDHELLORETRYREQUEST
        ELSE
            session_state := RECEIVECLIENTHELLO_SUCCEEDED
        END
    END;

    /*Hello retry request -> Same format as the serverHello message. This means we will keep the same parameters but will add a message explaining which parameter the 
      client will need to change for the server to accept it. The Client will then have to analyse the HelloRetryRequest comming from the server*/
    SendHelloRetryRequest(legacy_version,legacy_session_id_echo, legacy_compression_methods, supported_versions, cipher_suites, key_share, pre_shared_key,
                          random,signature_algorithm, supported_group, message) =
    PRE
        legacy_version : VERSION & //Ignored in TLS 1.3
        supported_versions : POW(VERSION) &
        legacy_session_id_echo : STRING &
        legacy_compression_methods : INTEGER &
        legacy_compression_methods ∈ {0, 1} & /*We're limiting the value to 0 or one to simplify the process -- WILL BE REMOVED*/
	pre_shared_key : POW(STRING) &
        //card (pre_shared_key) <= 2 &  /*limit cardinality for computing purposes -- WILL BE REMOVED*/
        cipher_suites : CIPHER_SUITE &
        supported_versions : POW (VERSION) &
        key_share : POW (STRING)  &
        random : STRING &
        signature_algorithm : SIGNATURE_ALGORITHMS &
        supported_group : SUPPORTED_GROUPS &
        message :  STRING &
        session_state = SENDHELLORETRYREQUEST or
        session_state = SENDHELLORETRYREQUEST_SUCCEEDED /*Nothing says in the rfc that two helloretryrequests can't be sent consecutively. But, the client will recognize                                                             this, and will temrinate the session. hence, it is the clients job to see that 2 or more hello retry request                                                               have been sent for the same client hello and proceed to terminate the session*/
    THEN
	server_supported_versions := supported_versions ||
        server_legacy_compression_methods := legacy_compression_methods ||
        server_pre_shared_key := pre_shared_key || /* It is possible for the pre_shared_key field to be empty if no symmetric key identities are known to the client */
        server_cipher_suite := cipher_suites ||
        server_legacy_session_id_echo := legacy_session_id_echo ||
        server_key_share := key_share ||
        /*It is possible for a server to send a signature algorithm or supported group that the client didnt send in it's clienthello Hence, it is the role of the client             to adapt to this or send an alert message and terminate the session. This is why it won't be tested in the IF statements */
        server_signature_algorithm := signature_algorithm || 
        server_supported_group := supported_group ||
        server_random := random ||
        helloRetryRequestCount := helloRetryRequestCount + 1; 
	IF (TLS_1_3 : server_supported_versions)
           THEN
              IF (server_legacy_compression_methods = 0)
                 THEN
                    session_state := SENDHELLORETRYREQUEST_SUCCEEDED
              ELSE IF not (server_legacy_compression_methods = 0)
                 THEN 
                    alert_message := ILLEGAL_PARAMETER ||
                    alert_level := FATAL ||
                    session_state := SENDHELLORETRYREQUEST_FAILED
              /*If Something else is missing */
              ELSE
                 alert_message := HANDSHAKE_FAILURE ||
                 alert_level := FATAL ||
                 session_state := SENDHELLORETRYREQUEST_FAILED
              END 
              END
        ELSE
	   alert_message := PROTOCOL_VERSION ||
           alert_level := FATAL ||
           session_state := SENDHELLORETRYREQUEST_FAILED
        END
    END;
    
    /* Client Receives the HelloRetryRequest -> Parameters are not added here because there are considered in the sendhelloretryrequest operation */
    ReceiveHelloRetryRequest =
    PRE
        session_state = SENDHELLORETRYREQUEST_SUCCEEDED
    THEN
        /*It is possible for a server to send a signature algorithm or supported group that the client didnt send in it's clienthello Hence, it is the role of the client             to adapt to this or send an alert message and terminate the session. This is why it won't be tested in the IF statements. */
        IF not (server_legacy_version = TLS1_2VersionNumber) or // If not equal to 0x0303
           not (client_legacy_session_id_echo = server_legacy_session_id_echo) or  //A client which receives a legacy_session_id_echo field that does not match whatit sen
                                                                                   //in the ClientHello MUST abort the handshake with an "illegal_parameter" alert.
           not (server_cipher_suite : client_cipher_suites) or  //A client which receives a cipher suite that was not offered MUST abort the handshake with an
                                                                  //"illegal_parameter" alert.
           not (server_legacy_compression_methods = 0) or 
           (client_supported_groups = {}) or
           (server_random /= HelloRetryRandomValue)
            THEN
                alert_message := ILLEGAL_PARAMETER ||
                alert_level := FATAL ||
                session_state := RECEIVEHELLORETRYREQUEST_FAILED
        //- Check if helloretry request has been sent more than once from the same client hello = abort with unexpected message alert     
        ELSE IF (helloRetryRequestCount > 1)
            THEN
                alert_message := UNEXPECTED_MESSAGE ||
                alert_level := FATAL ||
                session_state := RECEIVEHELLORETRYREQUEST_FAILED
        ELSE IF (client_supported_versions /\ server_supported_versions = {})
            THEN
                alert_message := PROTOCOL_VERSION ||
                alert_level := FATAL ||
                session_state := RECEIVEHELLORETRYREQUEST_FAILED
        ELSE //IF everything is ok
           session_state := RECEIVEHELLORETRYREQUEST_SUCCEEDED
        END
        END 
        END      
        /* 
           - If the new clienthello results in the same clienthello as before - abort with llegal_parameter -> NOT CONSIDERED
           - OTHER CASES ARE PRESENT IN THE TLS SPEC (RFC) BUT WILL NOT BE CONSIDERED
        */
    END;

    /* The ServerHello MUST only include extensions which are required to establish the cryptographic context and negotiate the protocol version*/
    SendServerHello (legacy_version,legacy_session_id_echo, legacy_compression_methods, supported_versions, cipher_suites, key_share, pre_shared_key, random) =
    PRE
        legacy_version : STRING & //Ignored in TLS 1.3
        supported_versions : POW(VERSION) &
        legacy_session_id_echo : STRING &
        legacy_compression_methods : INTEGER &
        legacy_compression_methods ∈ {0, 1} & /*We're limiting the value to 0 or one to simplify the process -- WILL BE REMOVED*/
	pre_shared_key : POW(STRING) &
        //card (pre_shared_key) <= 2 &  /*limit cardinality for computing purposes -- WILL BE REMOVED*/
        cipher_suites : CIPHER_SUITE &
        supported_versions : POW (VERSION) &
        key_share : POW (STRING)  &
        random : STRING &
        session_state = RECEIVECLIENTHELLO_SUCCEEDED 
    THEN
	server_supported_versions := supported_versions ||
        server_legacy_compression_methods := legacy_compression_methods ||
        server_pre_shared_key := pre_shared_key || /* It is possible for the pre_shared_key field to be empty if no symmetric key identities are known to the client */
        server_cipher_suite := cipher_suites ||
        server_legacy_session_id_echo := legacy_session_id_echo ||
        server_key_share := key_share ||
        server_legacy_version := legacy_version;
        IF (TLS_1_3 : server_supported_versions)
           THEN
              IF (server_legacy_compression_methods = 0)
                 THEN
                    session_state := SENDSERVERHELLO_SUCCEEDED
              ELSE IF not (server_legacy_compression_methods = 0)
                 THEN 
                    alert_message := ILLEGAL_PARAMETER ||
                    alert_level := FATAL ||
                    session_state := SENDSERVERHELLO_FAILED
              /*If Something else is missing */
              ELSE
                 alert_message := HANDSHAKE_FAILURE ||
                 alert_level := FATAL ||
                 session_state := SENDSERVERHELLO_FAILED
              END 
              END
        ELSE
	   alert_message := PROTOCOL_VERSION ||
           alert_level := FATAL ||
           session_state := SENDSERVERHELLO_FAILED
	END
    END;

    /*In our case, we only supported the following two extensions (signature_algorithm and supported groups) since the other extensions: legacy_version,legacy_session_id_       echo, legacy_compression_methods, supported_versions, cipher_suites, key_share, pre_shared_key. Are sent via the ServerHello
    */
    SendEncryptedExtensions (signature_algorithm, supported_group) =
    PRE
        signature_algorithm : SIGNATURE_ALGORITHMS &
        supported_group : SUPPORTED_GROUPS &
        session_state = SENDSERVERHELLO_SUCCEEDED
    THEN
        server_signature_algorithm := signature_algorithm ||
        server_supported_group := supported_group;
        IF not (server_signature_algorithm : SIGNATURE_ALGORITHMS or server_supported_group : SUPPORTED_GROUPS)
            THEN
                alert_message := ILLEGAL_PARAMETER ||
                alert_level := FATAL ||
                session_state := SENDENCRYPTEDEXTENSIONS_FAILED
        ELSE
            session_state := SENDENCRYPTEDEXTENSIONS_SUCCEEDED
        END
    END;

    SendClientCertificateRequest (request_context, request_signature_algorithm) =
    PRE
       request_context : STRING &
       request_signature_algorithm : SIGNATURE_ALGORITHMS &
       session_state = SENDENCRYPTEDEXTENSIONS_SUCCEEDED
    THEN 
       certificate_request_context := request_context ||
       certificate_request_signature_algorithm := request_signature_algorithm;
       IF not (certificate_request_context /= "" or request_signature_algorithm : SIGNATURE_ALGORITHMS)
          THEN
              alert_message := ILLEGAL_PARAMETER ||
              alert_level := FATAL ||
              session_state := SENDCLIENTCERTIFICATEREQUEST_FAILED
       ELSE
          session_state := SENDCLIENTCERTIFICATEREQUEST_SUCCEEDED
       END
    END;
    
    SendServerCertificate (raw_public_key_certificate, certificate_type, signed_certificate_timestamp, ocsp_status, certificate_authorities)  =
    PRE
       raw_public_key_certificate : STRING &
       certificate_type : CERTIFICATE_TYPE & 
       signed_certificate_timestamp : STRING &
       ocsp_status : INTEGER & 
       certificate_authorities : CERTIFICATE_AUTHORITIES &
       session_state = SENDCLIENTCERTIFICATEREQUEST_SUCCEEDED or //Not mandatory as client certificate request is optional
       session_state = session_state = SENDENCRYPTEDEXTENSIONS_SUCCEEDED
    THEN
       server_raw_public_key_certificate := raw_public_key_certificate ||
       server_certificate_type := certificate_type ||
       server_signed_certificate_timestamp := signed_certificate_timestamp ||
       server_ocsp_status := ocsp_status ||
       server_certificate_authorities := certificate_authorities;
       IF (server_raw_public_key_certificate = "" or
           server_signed_certificate_timestamp = "" or 
           ocsp_status < 1)
           THEN 
              alert_message := ILLEGAL_PARAMETER ||
              alert_level := FATAL ||
              session_state := SENDSERVERCERTIFICATE_FAILED
       ELSE
           session_state := SENDSERVERCERTIFICATE_SUCCEEDED
       END
    END;

    ReceiveEncryptedExtensions =
    PRE
        session_state = SENDSERVERCERTIFICATE_SUCCEEDED
    THEN
       IF (server_signature_algorithm : client_signature_algorithms or
            server_supported_group : client_supported_groups)
           THEN
              alert_message := HANDSHAKE_FAILURE ||
              alert_level := FATAL ||
              session_state := RECEIVEENCRYPTEDEXTENSIONS_FAILED
       ELSE 
           session_state := RECEIVEENCRYPTEDEXTENSIONS_SUCCEEDED
       END
    END;

    ReceiveServerCertificate =
    PRE
       session_state = RECEIVEENCRYPTEDEXTENSIONS_SUCCEEDED
    THEN 
       /* Client should recheck the received information from the server to make sure it is correct. Code may be duplicated for this step */
       IF (server_raw_public_key_certificate = "" or
           server_signed_certificate_timestamp = "" or 
           ocsp_status < 1 or
           server_certificate_authorities ∉ CERTIFICATE_ATUHORITIES or
           server_certificate_type /= X509) //Here we focus on X509 certificates that us digital signatures and public keys for authentification. 99% Used in TLS 1.3
           THEN
              alert_message := HANDSHAKE_FAILURE ||
              alert_level := FATAL ||
              session_state := RECEIVESERVERCERTIFICATE_FAILED
       ELSE
       session_state := RECEIVESERVERCERTIFICATE_SUCCEEDED
    END;
    
    TerminateSession = 
    PRE
        session_state = SENDCLIENTHELLO_FAILED or 
        session_state = SENDSERVERHELLO_FAILED or
        session_state = SENDHELLORETRYREQUEST_FAILED or
        session_state = RECEIVEHELLORETRYREQUEST_FAILED or
        session_state = SENDENCRYPTEDEXTENSIONS_FAILED or 
        session_state = SENDCLIENTCERTIFICATEREQUEST_FAILED or 
        session_state = SENDSERVERCERTIFICATE_FAILED or
        session_state = RECEIVEENCRYPTEDEXTENSIONS_FAILED or
        session_state = RECEIVESERVERCERTIFICATE_FAILED
    THEN
        /* RESET ALL THE VALUES */
        session_state := SESSION_CLOSED ||
    	server_name := ServerName ||
    	alert_message := InitialAlertMessage ||
    	alert_level := InitialAlertLevel ||
    	session_id := TLS1_2VersionNumber ||
        helloRetryRequestCount := 0 ||       
        helloRetryMessage := "" ||       
    	/*Client params initialisation */
    	client_pre_shared_key := EmptyValue ||
    	client_random := RandomValue ||
    	client_legacy_version := TLS1_2VersionNumber ||
    	client_version := CurrentTLSVersion ||
    	client_legacy_session_id := TLS1_2VersionNumber ||
    	client_legacy_session_id_echo := TLS1_2VersionNumber ||
    	client_legacy_compression_methods := 0 ||
    	client_cipher_suites := EmptyValue ||
    	client_key_share := KeyShare ||
    	client_signature_algorithms := EmptyValue ||
    	client_supported_groups := EmptyValue ||
    	client_supported_versions := EmptyValue ||

    	/*Server params initialisation */
    	server_random := RandomValue || 
    	server_legacy_session_id_echo := TLS1_2VersionNumber || 
    	server_cipher_suite := TLS_AES_128_GCM_SHA256 ||
    	server_legacy_compression_methods := 0 ||
    	server_supported_versions := EmptyValue ||
    	server_key_share := KeyShare ||
    	server_pre_shared_key := KeyShare ||
        
        //Certificate Params (Client and Server)
        certificate_request_context := EmptyString ||
        certificate_request_signature_algorithm := private_use ||//Will need to be changed to empty value
        server_raw_public_key_certificate := EmptyString ||
        server_certificate_type := X509 || /* Default value */
        server_signed_certificate_timestamp := EmptyString ||
        server_ocsp_status := 0 || 
        server_certificate_authorities := ENTRUST || /* Will need to be changed to an empty value */
        client_public_key_certificate := EmptyString || 
        client_certificate_type := X509 || /* Default value */
        client_signed_certificate_timestamp := EmptyString ||
        client_ocsp_status := 0 ||
        client_certificate_authorities := ENTRUST ||
        client_certificate_request_context := EmptyString /*Supposed to match the certificate_request_context from the certificate request coming from the server */
    END

END