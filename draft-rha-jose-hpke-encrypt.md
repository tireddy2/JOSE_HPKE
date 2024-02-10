---
title: "Use of Hybrid Public-Key Encryption (HPKE) with Javascript Object Signing and Encryption (JOSE)"
abbrev: "Use of HPKE in JOSE"
category: std

docname: draft-rha-jose-hpke-encrypt
submissiontype: IETF
number:
date:
consensus: true
v: 3
area: "Security"
workgroup: "JOSE"
keyword:
 - HPKE
 - JOSE
 - PQC
 - Hybrid
 
venue:
  group: "jose"
  type: "Working Group"
  mail: "jose@ietf.org"
  arch: "https://mailarchive.ietf.org/arch/browse/jose/"
  

stand_alone: yes
pi: [toc, sortrefs, symrefs, strict, comments, docmapping]

author:
 -
    fullname: Tirumaleswar Reddy
    organization: Nokia
    city: Bangalore
    region: Karnataka
    country: India
    email: "kondtir@gmail.com"

 -
    fullname: Hannes Tschofenig
    organization: 
    city: 
    country: Austria
    email: "hannes.tschofenig@gmx.net"

 -
    fullname: Aritra Banerjee
    organization: Nokia
    city: Munich
    country: Germany
    email: "aritra.banerjee@nokia.com"

 -
    ins: O. Steele
    name: Orie Steele
    organization: Transmute
    email: orie@transmute.industries
    country: United States
 -
    ins: M. Jones
    name: Michael B. Jones
    organization: independent
    email: michael_b_jones@hotmail.com
    country: United States

normative:
  RFC2119:
  RFC8174:
  RFC9180:
  RFC7516:
  RFC7518:
  RFC7517:
  
informative:
  RFC8937:
  HPKE-IANA:
     author:
        org: IANA
     title: Hybrid Public Key Encryption (HPKE) IANA Registry
     target: https://www.iana.org/assignments/hpke/hpke.xhtml
     date: October 2023


     
--- abstract


This specification defines Hybrid public-key encryption (HPKE) for use with 
Javascript Object Signing and Encryption (JOSE). HPKE offers a variant of
public-key encryption of arbitrary-sized plaintexts for a recipient public key.

HPKE works for any combination of an asymmetric key encapsulation mechanism (KEM),
key derivation function (KDF), and authenticated encryption with additional data 
(AEAD) function. Authentication for HPKE in JOSE is provided by 
JOSE-native security mechanisms or by one of the authenticated variants of HPKE.

This document defines the use of the HPKE with JOSE.


--- middle

# Introduction

Hybrid public-key encryption (HPKE) {{RFC9180}} is a scheme that 
provides public key encryption of arbitrary-sized plaintexts given a 
recipient's public key. HPKE utilizes a non-interactive ephemeral-static 
Diffie-Hellman exchange to establish a shared secret. The motivation for
standardizing a public key encryption scheme is explained in the introduction
of {{RFC9180}}.

The HPKE specification provides a variant of public key encryption of
arbitrary-sized plaintexts for a recipient public key. It also
includes three authenticated variants, including one that authenticates
possession of a pre-shared key, one that authenticates possession of
a key encapsulation mechanism (KEM) private key, and one that
authenticates possession of both a pre-shared key and a KEM private key.

This specification utilizes HPKE as a foundational building block and
carries the output to JOSE ({{RFC7516}}, {{RFC7518}}).

# Conventions and Definitions

{::boilerplate bcp14-tagged}

# Conventions and Terminology

This specification uses the following abbreviations and terms:

- Key Type (kty), see {{RFC7517}}.
- Content Encryption Key (CEK), is defined in {{RFC7517}}.
- Hybrid Public Key Encryption (HPKE) is defined in {{RFC9180}}.
- pkR is the public key of the recipient, as defined in {{RFC9180}}.
- skR is the private key of the recipient, as defined in {{RFC9180}}.
- Key Encapsulation Mechanism (KEM), see {{RFC9180}}.
- Key Derivation Function (KDF), see {{RFC9180}}.
- Authenticated Encryption with Associated Data (AEAD), see {{RFC9180}}.
- Additional Authenticated Data (AAD), see {{RFC9180}}.


# HPKE for JOSE

## Overview

The JSON Web Algorithms (JWA) {{RFC7518}} in Section 4.6 defines two ways using the key agreement result 
(a) Direct Key Agreement (b) Key Agreement with Key Wrapping. 

This specification supports two uses of HPKE in JOSE, namely

  *  HPKE in a single recipient setup referred to as Integrated Encryption mode. In this case, the shared secret established through the HPKE will generate the content encryption key (CEK) and encrypts the plaintext.
  
  *  HPKE in a multiple recipient setup referred to as Key Encryption mode. In this case, the shared secret established through the HPKE will wrap the CEK.

In both modes, the existing JOSE header parameter, called 'epk', is used to convey the content of the "encapsulated key" structure defined in the HPKE specification. The "encapsulated key" structure represents the serialized form of a public key.

When the alg value is set to any of algorithms registered by this specification then the 'epk' header parameter MUST be present, and it MUST be a JSON Web Key as defined in {{EK}} of this document.

In both modes, the header parameter 'epk' will contain the 'ek' member. The "ek" member will contain the base64url encoded "enc" value produced by the encapsulate operation of the HPKE KEM.

In both JWE Compact Serialization and the JWE JSON Serialization, "ct" and "enc" will be base64url encoded (see Section 7.1 and 7.2 of {{RFC7518}}), since JSON lacks a way to directly represent arbitrary octet sequences.   

The two modes (Integrated Encryption, and Key Encryption) can be distinguished by determining whether an "enc" member is present in the protected header. 

If the "enc" member exists, it is a Key Encryption mode; otherwise, it is a Integrated Encryption mode.

## HPKE Encryption with SealBase

The message encryption process is as follows. 

1. The sending HPKE context is created by invoking invoking SetupBaseS() (Section 5.1.1 of {{RFC9180}}) with the recipient's public key "pkR" and "info". The HPKE specification defines the "info" parameter as a context information structure that is used to ensure that the derived keying material is bound to the context of the transaction. The SetupBaseS function will be called with the default value of an empty string for the 'info' parameter. This yields the context "sctxt" and an encapsulation key "enc". 

There exist two cases of HPKE plaintext which need to be distinguished:

*  In Integrated Encryption mode, the plaintext "pt" passed into Seal
  is the content to be encrypted.  Hence, there is no intermediate
  layer utilizing a CEK.

*  In Key Encryption mode, the plaintext "pt" passed into
  Seal is the CEK. The CEK is a random byte sequence of length
  appropriate for the encryption algorithm. For example, AES-128-GCM 
  requires a 16 byte key and the CEK would therefore be 16 bytes long.

## HPKE Decryption with OpenBase

The recipient will create the receiving HPKE context by invoking SetupBaseR() (Section 5.1.1 of {{RFC9180}}) with "skR", "enc" (output of base64url decoded 'ek'), and "info" (empty string). This yields the context "rctxt". The receiver then decrypts "ct" by invoking the Open() method on "rctxt" (Section 5.2 of {{RFC9180}}) with "aad", yielding "pt" or an error on failure. 

The Open function will, if successful, decrypts "ct".  When decrypted, the result will be either the CEK (when Key Encryption mode is used), or the content (if Integrated Encryption mode is used).  The CEK is the symmetric key used to decrypt the ciphertext.

## Encapsulated JSON Web Keys {#EK}

An encapsulated key can be represented as JSON Web Key as described in { Section 4 of RFC7515 }.

The "kty" parameter MUST be "EK".

The "ek" parameter MUST be present, and MUST be the base64url encoded output of the encap operation defined for the HPKE KEM.

As described in { Section 4 of RFC7515 }, additional members can be present in the JWK; if not understood by implementations encountering them, they MUST be ignored.

This example demonstrates the representaton of an encapsulated key as a JWK.

~~~
{
   "kty": "EK",
   "ek": "BHpP-u5JKziyUpqxNQqb0apHx1ecH2UzcRlhHR4ngJVS__gNu21DqqgPweuPpjglnXDnOuQ4kt9tHCs3PUzPxQs"
}
~~~

### Integrated Encryption

In Integrated Encryption mode, HPKE is employed to directly encrypt the (compressed) plaintext, and the resulting ciphertext is included in the JWE ciphertext. 

In this mode, JWE Compact serialization MUST be used. The sender MUST specify the 'epk' and 'alg' parameters in the protected header to indicate the use of HPKE. Optionally, the protected header MAY contain the 'kid' parameter used to identify the static recipient public key used by the sender. 

The Single-Shot APIs specified in Section 6 of {{RFC9180}} for encryption and decryption cannot be used. This is because they require an 'aad' parameter, which takes the Encoded Protected Header comprising of 'ek' as input.

In Integrated Encryption mode, HPKE is employed to directly encrypt the plaintext, and the resulting ciphertext is included in the JWE ciphertext. 

In Integrated Encryption mode:

- The JWE Ciphertext MUST be the base64url encoded 'ct' value.
- The JWE Initialization Vector value MUST be empty. 
- The JWE Authentication Tag MUST be empty.
- The JWE Encrypted Key MUST be empty.
- The "aad" parameter MUST take the Additional Authenticated Data encryption parameter defined in Step 14 of  
  Section 5.1 of {{RFC7516}} as input. 

In this setup, the 'enc' (Encryption Algorithm) parameter MUST NOT be present because the ciphersuite (KEM, KDF, AEAD) is fully-specified in the 'alg' parameter itself. 

This is a deviation from the rule in Section 4.1.2 of {{RFC7516}}. 

This example demonstrates the use of an encapsulated key with JSON Web Encryption Integrated Encryption and Compact Serialization:

~~~
eyJhbGciOiJIUEtFLUJhc2UtUDI1Ni1TSEEyNTYtQUVTMTI4R0NNIiwiZXBrIjp7Imt0eSI6IkVLIiwiZWsiOiJCQU9TeWV3M05JLUkwNEd2WU1MT3Y0cDBEVG5WMWZjWnBFVW10dGs0YkRTdDAtakxzY0FDN3h3MjdORTFHZ0VuMUgtM3ZXSFA5eW1BOHl4aFRmVDBkYjQifX0...afBw3T1hUNjci4qq3ZZ-9KxnttB0iCEO_GUqbIStqYqB5DgRDpyYSuvoH1mMA31qKPqB41ld5mSP34yUys6WJM7nstDJ1-4nqUdhRpgfkGTECA.
~~~
{: #compact-example align="left" title="Integrated Encryption Encryption"}

### Key Encryption

In Key Encryption mode, HPKE is used to encrypt the	Content Encryption Key (CEK), and the resulting ciphertext is included in the JWE ciphertext. The (compressed) plaintext will be encrypted using the CEK as explained in Step 15 of Section 5.1 of {{RFC7516}}.

In this mode, JWE JSON serialization MUST be used. The sender MUST place the 'epk' and 'alg' parameters in the per-recipient unprotected header to indicate the	use of HPKE. Optionally, the per-recipient unprotected header MAY contain the 'kid' parameter used to identify the static recipient public key used by the sender. The 'enc' (Encryption Algorithm) parameter MUST be present to identify the content encryption algorithm used to perform encryption on the plaintext to produce the ciphertext. The "enc" Header Parameter MUST occur only within the JWE Protected Header.	 		

In Key Encryption mode: 
- The JWE Encrypted Key MUST be the base64url encoded 'ct' value.
- The JWE Initialization Vector MUST be produced as described in { Section 5.1 of RFC7516 }
- The JWE Authentication Tag MUST be produced as described in { Section 5.1 of RFC7516 }

In JWE JSON Serialization, the following mechanisms MUST be selected to provide protection against an attacker who manipulates the encryption algorithm in the 'enc' parameter in the protected header. The attack is discussed in {{?I-D.draft-ietf-lamps-cms-cek-hkdf-sha256}}:

   * The "aad" parameter MUST take the Additional Authenticated Data encryption parameter defined in Step 14 of 
     Section 5.1 of {{RFC7516}} as input to encrypt the CEK. If the attacker changes encrytion algorithm in the 'enc' parameter prior to delivery to the recipient, then the recipient will derive a different authentication tag, leading to decryption failure and resulting in an OpenError.     

This example demonstrates the use of an encapsulated key with a JSON Web Encryption with Key Encryption as described in this document. 

~~~
{
  "protected": "eyJlbmMiOiJBMTI4R0NNIn0",
  "ciphertext": "S0qqrM3xXPUavbmL9LQkgUKRBu8BZ7DQWoT-mdNIZVU-ip_V-fbMokiGwp2aPM57DX3cXCK3TKHqdhZ8rSNduUja",
  "iv": "AzaXpooLg3ZxEASQ",
  "aad": "8J-SgCBhYWQ",
  "tag": "S0omWw35S0H7tyEHsmGLDw",
  "recipients": [
    {
      "encrypted_key": "yDVZLsO7-ecy_GCgEluwn9U723TCHNAzeYRRQPOfpHM",
      "header": {
        "kid": "urn:ietf:params:oauth:jwk-thumbprint:sha-256:adjwW6fyyZ94ZBjGjx_OpDEKHLGfd1ELkug_YmRAjCk",
        "alg": "HPKE-Base-P256-SHA256-AES128GCM",
        "epk": {
          "kty": "EK",
          "ek": "BHpP-u5JKziyUpqxNQqb0apHx1ecH2UzcRlhHR4ngJVS__gNu21DqqgPweuPpjglnXDnOuQ4kt9tHCs3PUzPxQs"
        }
      }
    },
    {
      "encrypted_key": "iS73TFqJ61gkmh4DHAXADx4wyftA7pnY",
      "header": {
        "kid": "urn:ietf:params:oauth:jwk-thumbprint:sha-256:D2FKlj9MTIQma5bwdOVXk5Zh3_d60knzlbmD-SyMNAI",
        "alg": "ECDH-ES+A128KW",
        "epk": {
          "kty": "EC",
          "crv": "P-256",
          "x": "nX6Y3DWC0olVe5H7-NkCzVDghsYSa_L9da3jzkHYkV8",
          "y": "wDshQdcaY0J08wx25V3ystQSNe_qjsCaaFeeRWJqcE0"
        }
      }
    }
  ]
}
~~~
{: #json-example align="left" title="Key Encryption Example"}

In the above example, the JWE Protected Header value is: 

~~~
{
   "enc": "A128GCM"
}
~~~

## Example Hybrid Key Agreement Computation

This example uses HPKE-Base-P256-SHA256-AES128GCM which corresponds
to the following HPKE algorithm combination:

- KEM: DHKEM(P-256, HKDF-SHA256)
- KDF: HKDF-SHA256
- AEAD: AES-128-GCM
- Mode: Base
- payload: "This is the content"
- aad: ""

# Ciphersuite Registration

This specification registers a number of ciphersuites for use with HPKE.
A ciphersuite is thereby a combination of several algorithm configurations:

- HPKE Mode
- KEM algorithm
- KDF algorithm
- AEAD algorithm

The "KEM", "KDF", and "AEAD" values are conceptually taken from the HPKE IANA
registry {{HPKE-IANA}}. Hence, JOSE-HPKE cannot use an algorithm combination
that is not already available with HPKE.

For better readability of the algorithm combination ciphersuites labels are
build according to the following scheme: 

~~~
HPKE-<Mode>-<KEM>-<KDF>-<AEAD>
~~~

The "Mode" indicator may be populated with the following values from
Table 1 of {{RFC9180}}:

- "Base" refers to "mode_base" described in Section 5.1.1 of {{RFC9180}},
which only enables encryption to the holder of a given KEM private key.
- "PSK" refers to "mode_psk", described in Section 5.1.2 of {{RFC9180}},
which authenticates using a pre-shared key.
- "Auth" refers to "mode_auth", described in Section 5.1.3 of {{RFC9180}},
which authenticates using an asymmetric key.
- "Auth_Psk" refers to "mode_auth_psk", described in Section 5.1.4 of {{RFC9180}},
which authenticates using both a PSK and an asymmetric key.

For a list of ciphersuite registrations, please see {{IANA}}.


# Security Considerations

This specification is based on HPKE and the security considerations of
{{RFC9180}} are therefore applicable also to this specification.

HPKE assumes the sender is in possession of the public key of the recipient and
HPKE JOSE makes the same assumptions. Hence, some form of public key distribution
mechanism is assumed to exist but outside the scope of this document.

HPKE in Base mode does not offer authentication as part of the HPKE KEM. In this case 
JOSE constructs like JWS and JSON Web Tokens (JWTs) can be used to add authentication. 
HPKE also offers modes that offer authentication.

HPKE relies on a source of randomness to be available on the device. In Key Agreement 
with Key Wrapping mode, CEK has to be randomly generated and it MUST be
ensured that the guidelines in {{RFC8937}} for random number generations are followed. 

#  IANA Considerations {#IANA}

The following is added to the "JSON Web Key Types" registry:

- "kty" Parameter Value: "EK"
- Key Type Description: HPKE
- JOSE Implementation Requirements: Optional
- Change Controller: IESG
- Specification Document(s): [[TBD: This RFC]]

The following is added to the "JSON Web Key Parameters" registry:

- Parameter Name: "ek"
- Parameter Description: Encapsulated Key
- Parameter Information Class: Public
- Used with "kty" Value(s): "EK"
- Specification Document(s): [[TBD: This RFC]]
   
This document requests IANA to add new values to the 'JOSE Algorithms' and to 
the 'JOSE Header Parameters' registries in the 'Standards Action 
With Expert Review category'.

## JOSE Algorithms Registry (Direct Key Agreement)

- Algorithm Name: HPKE-Base-P256-SHA256-AES128GCM
- Algorithm Description: Cipher suite for JOSE-HPKE in Base Mode that uses the DHKEM(P-256, HKDF-SHA256) KEM, the HKDF-SHA256 KDF and the AES-128-GCM AEAD.
- Algorithm Usage Location(s): "alg"
- JOSE Implementation Requirements: Optional
- Change Controller: IESG
- Specification Document(s): [[TBD: This RFC]]
- Algorithm Analysis Documents(s): TODO

- Algorithm Name: HPKE-Base-P384-SHA384-AES256GCM
- Algorithm Description: Cipher suite for JOSE-HPKE in Base Mode that uses the DHKEM(P-384, HKDF-SHA384) KEM, the HKDF-SHA384 KDF, and the AES-256-GCM AEAD.
- Algorithm Usage Location(s): "alg"
- JOSE Implementation Requirements: Optional
- Change Controller: IESG
- Specification Document(s): [[TBD: This RFC]]
- Algorithm Analysis Documents(s): TODO

- Algorithm Name: HPKE-Base-P521-SHA512-AES256GCM
- Algorithm Description: Cipher suite for JOSE-HPKE in Base Mode that uses the DHKEM(P-521, HKDF-SHA512) KEM, the HKDF-SHA512 KDF, and the AES-256-GCM AEAD.
- Algorithm Usage Location(s): "alg"
- JOSE Implementation Requirements: Optional
- Change Controller: IESG
- Specification Document(s): [[TBD: This RFC]]
- Algorithm Analysis Documents(s): TODO

- Algorithm Name: HPKE-Base-X25519-SHA256-AES128GCM
- Algorithm Description: Cipher suite for JOSE-HPKE in Base Mode that uses the DHKEM(X25519, HKDF-SHA256) KEM, the HKDF-SHA256 KDF, and the AES-128-GCM AEAD.
- Algorithm Usage Location(s): "alg"
- JOSE Implementation Requirements: Optional
- Change Controller: IESG
- Specification Document(s): [[TBD: This RFC]]
- Algorithm Analysis Documents(s): TODO

- Algorithm Name: HPKE-Base-X25519-SHA256-ChaCha20Poly1305
- Algorithm Description: Cipher suite for JOSE-HPKE in Base Mode that uses the DHKEM(X25519, HKDF-SHA256) KEM, the HKDF-SHA256 KDF, and the ChaCha20Poly1305 AEAD.
- Algorithm Usage Location(s): "alg"
- JOSE Implementation Requirements: Optional
- Change Controller: IESG
- Specification Document(s): [[TBD: This RFC]]
- Algorithm Analysis Documents(s): TODO

- Algorithm Name: HPKE-Base-X448-SHA512-AES256GCM
- Algorithm Description: Cipher suite for JOSE-HPKE in Base Mode that uses the DHKEM(X448, HKDF-SHA512) KEM, the HKDF-SHA512 KDF, and the AES-256-GCM AEAD.
- Algorithm Usage Location(s): "alg"
- JOSE Implementation Requirements: Optional
- Change Controller: IESG
- Specification Document(s): [[TBD: This RFC]]
- Algorithm Analysis Documents(s): TODO

- Algorithm Name: HPKE-Base-X448-SHA512-ChaCha20Poly1305
- Algorithm Description: Cipher suite for JOSE-HPKE in Base Mode that uses the DHKEM(X448, HKDF-SHA512) KEM, the HKDF-SHA512 KDF, and the ChaCha20Poly1305 AEAD.
- Algorithm Usage Location(s): "alg"
- JOSE Implementation Requirements: Optional
- Change Controller: IESG
- Specification Document(s): [[TBD: This RFC]]
- Algorithm Analysis Documents(s): TODO

## JOSE Algorithms Registry (Key Agreement with Key Wrapping)

- Algorithm Name: HPKE-Base-P256-SHA256-AES128GCMKW
- Algorithm Description: Cipher suite for JOSE-HPKE in Base Mode that uses the DHKEM(P-256, HKDF-SHA256) KEM, the HKDF-SHA256 KDF and Key wrapping with the AES-128-GCM AEAD.
- Algorithm Usage Location(s): "alg"
- JOSE Implementation Requirements: Optional
- Change Controller: IESG
- Specification Document(s): [[TBD: This RFC]]
- Algorithm Analysis Documents(s): TODO

- Algorithm Name: HPKE-Base-P384-SHA384-AES256GCMKW
- Algorithm Description: Cipher suite for JOSE-HPKE in Base Mode that uses the DHKEM(P-384, HKDF-SHA384) KEM, the HKDF-SHA384 KDF, and Key wrapping with the AES-256-GCM AEAD.
- Algorithm Usage Location(s): "alg"
- JOSE Implementation Requirements: Optional
- Change Controller: IESG
- Specification Document(s): [[TBD: This RFC]]
- Algorithm Analysis Documents(s): TODO

- Algorithm Name: HPKE-Base-P521-SHA512-AES256GCMKW
- Algorithm Description: Cipher suite for JOSE-HPKE in Base Mode that uses the DHKEM(P-521, HKDF-SHA512) KEM, the HKDF-SHA512 KDF, and Key wrapping with the AES-256-GCM AEAD.
- Algorithm Usage Location(s): "alg"
- JOSE Implementation Requirements: Optional
- Change Controller: IESG
- Specification Document(s): [[TBD: This RFC]]
- Algorithm Analysis Documents(s): TODO

- Algorithm Name: HPKE-Base-X25519-SHA256-AES128GCMKW
- Algorithm Description: Cipher suite for JOSE-HPKE in Base Mode that uses the DHKEM(X25519, HKDF-SHA256) KEM, the HKDF-SHA256 KDF, and Key wrapping with the AES-128-GCM AEAD.
- Algorithm Usage Location(s): "alg"
- JOSE Implementation Requirements: Optional
- Change Controller: IESG
- Specification Document(s): [[TBD: This RFC]]
- Algorithm Analysis Documents(s): TODO

- Algorithm Name: HPKE-Base-X25519-SHA256-ChaCha20Poly1305KW
- Algorithm Description: Cipher suite for JOSE-HPKE in Base Mode that uses the DHKEM(X25519, HKDF-SHA256) KEM, the HKDF-SHA256 KDF, and Key wrapping with the ChaCha20Poly1305 AEAD.
- Algorithm Usage Location(s): "alg"
- JOSE Implementation Requirements: Optional
- Change Controller: IESG
- Specification Document(s): [[TBD: This RFC]]
- Algorithm Analysis Documents(s): TODO

- Algorithm Name: HPKE-Base-X448-SHA512-AES256GCMKW
- Algorithm Description: Cipher suite for JOSE-HPKE in Base Mode that uses the DHKEM(X448, HKDF-SHA512) KEM, the HKDF-SHA512 KDF, and Key wrapping with the AES-256-GCM AEAD.
- Algorithm Usage Location(s): "alg"
- JOSE Implementation Requirements: Optional
- Change Controller: IESG
- Specification Document(s): [[TBD: This RFC]]
- Algorithm Analysis Documents(s): TODO

- Algorithm Name: HPKE-Base-X448-SHA512-ChaCha20Poly1305KW
- Algorithm Description: Cipher suite for JOSE-HPKE in Base Mode that uses the DHKEM(X448, HKDF-SHA512) KEM, the HKDF-SHA512 KDF, and Key wrapping with the ChaCha20Poly1305 AEAD.
- Algorithm Usage Location(s): "alg"
- JOSE Implementation Requirements: Optional
- Change Controller: IESG
- Specification Document(s): [[TBD: This RFC]]
- Algorithm Analysis Documents(s): TODO

## JOSE Header Parameters

### Authentication Using a Pre-Shared Key

- Parameter Name: "psk_id"
- Parameter Description: A key identifier (kid) for the pre-shared key as defined in { Section 5.1.1 of RFC9180 }
- Parameter Information Class: Public
- Change Controller: IESG
- Specification Document(s): [[This specification]]

### Authentication Using an Asymmetric Key

- Parameter Name: "auth_kid"
- Parameter Description: A key identifier (kid) for the asymmetric key as defined in { Section 5.1.4 of RFC9180 }
- Parameter Information Class: Public
- Change Controller: IESG
- Specification Document(s): [[This specification]]
 
--- back

# Acknowledgments
{: numbered="false"}

This specification leverages text from {{?I-D.ietf-cose-hpke}}. We would like to thank Matt Chanda, Ilari Liusvaara and Aaron Parecki for their feedback.


