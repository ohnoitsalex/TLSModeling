/* Library
 * Author Alexander Onofrei
 * Creation date: 08-08-2024
 */
MACHINE TLS_specification
/*
  Specification of a the TLS protocol
  University of Sherbrooke
  Draft 1.0
 */

SETS
 MEMBERTYPES = {client, server, certificate_authority}; /*All possible member types in a tls session */
  
  KEYS; /*Represents the Keys (private and public and session keys*/

  SESSIONS; /*Represents a TLS Session*/
  
  CIPHERS = {TLS_AES_256_GCM_SHA384, /*Advanced Encryption Standard (AES) Cipher with 256 bit key Galois/Counter Mode (GCM) with ECDHE KEM and SHA-384 hash */
	     TLS_CHACHA20_POLY1305_SHA256, /*CHACHA20 Cipher with 128 bit key Poly1305 with ECDHE KEM and SHA-256 hash */
             TLS_AES_128_GCM_SHA256, /*Advanced Encryption Standard (AES) Cipher with 128 bit key Galois/Counter Mode (GCM) with ECDHE KEM and SHA-256 hash */
             TLS_AES_128_CCM_8_SHA256, /*Advanced Encryption Standard (AES) Cipher with 256 bit key CCM 8-bit authentication tag with ECDHE KEM and SHA-256 hash */
             TLS_AES_128_CCM_SHA256}; /*Advanced Encryption Standard (AES) Cipher with 256 bit key CCM with ECDHE KEM and SHA-256 hash */
  
  SIGNATURES = {
    /* RSASSA-PKCS1-v1_5 algorithms */
    rsa_pkcs1_sha1,
    rsa_pkcs1_sha25,
    rsa_pkcs1_sha384,ù
    rsa_pkcs1_sha512,
    /* ECDSA algorithms */
    ecdsa_secp256r1_sha256,
    ecdsa_secp384r1_sha384,
    ecdsa_secp521r1_sha512,
    /* RSASSA-PSS algorithms */
    rsa_pss_sha256,
    rsa_pss_sha384,
    rsa_pss_sha512,
    /* EdDSA algorithms */
    ed25519,
    ed448,
    /* Reserved Code Points */
    private_use};
  
  KEMS = { /*1.3 supports only DH based KEMS */
    X25519,
    X448};
  
  ALERTS = { /*Contains all the possible alerts */
            bad_certificate, certificate_required, decode_error, 
            decrypt_error, illegal_parameter, insufficient_security, 
            missing_extension, protocol_version, unexpected_message,
            unsupported_certificate, undefined};
  
  CERTIFICATES = { /*Contains all the possible certificates types for X.509 */
		  EV_certificate, OV_certificate, EV_certificate,
                  wildcard_certificate, SAN_certificate,
                  self_signed_certificate, client_certificate}*/



CONCRETE_CONSTANTS
  version_number   /* TLS version number */
	
CONSTANTS 

PROPERTIES
  version_number = "1.3"   /* TLS version number set to 1.3*/

VARIABLES
  server_public_key,
  server_private_key, 
  client_public_key,
  client_private_key,

  session_key,
  server_certificate,
  client_certificate,
  hash,

  handshake_message,
  legacy_version,

  client_hello_finished,
  server_hello_finished,
  client_certificate_verify_finished,
  server_certificate_verify_finished,
  client_key_calculation_finished,
  client_key_calculation_finished,

  alert,
  member,
  session

  /*choosen_kem,
  choosen_signature,
  choosen_cipher,*/
  
INVARIANT

  server_public_key : KEYS <-> MEMBERS,
  server_private_key : KEYS <-> MEMBERS, 
  client_public_key : KEYS <-> MEMBERS,
  client_private_key : KEYS <-> MEMBERS,

  session_key : KEYS <-> SESSIONS,
  server_certificate : CERTIFICATES --> MEMBERS,
  client_certificate : CERTIFICATES --> MEMBERS,
  hash : INT,

  handshake_message : STRING,
  legacy_version : STRING,

  client_hello_finished : BOOL,
  server_hello_finished : BOOL,
  client_certificate_verify_finished : BOOL,
  server_certificate_verify_finished : BOOL,
  client_key_calculation_finished : BOOL,
  client_key_calculation_finished : BOOL,

  alert : ALERTS,
  member : MEMBERS --> POW(MEMBERS),
  session : SESSIONS,

  choosen_kem : KEMS +-> SESSIONS,
  choosen_signature : SIGNATURES +-> SESSIONS,
  choosen_cipher : CIPHERS +-> SESSIONS
  
 
INITIALISATION

OPERATIONS
  ClientHello()
  ServerHello ();
  HelloRetryRequest();
  CertificateRequest();
  ServerCertificate();
  ClientCertificate();
  CertificateVerify();
  CertificateVerifyResponse();
  CertificateVerifyApproved();
  ServerKeyCalculation();
  ClientKeyCalculation(); 
  ClientFinished();
  ServerFinished()

END

