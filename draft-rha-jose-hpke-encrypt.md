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

normative:
  RFC2119:
  RFC8174:
  RFC9180:
  RFC7516:
  RFC7518:
  
informative:
  RFC8937:
  RFC2630: 


     
--- abstract


This specification defines hybrid public-key encryption (HPKE) for use with 
Javascript Object Signing and Encryption (JOSE). HPKE offers a variant of
public-key encryption of arbitrary-sized plaintexts for a recipient public key.

HPKE works for any combination of an asymmetric key encapsulation mechanism (KEM),
key derivation function (KDF), and authenticated encryption with additional data 
(AEAD) function. Authentication for HPKE in JOSE is provided by 
JOSE-native security mechanisms.

This document defines the use of the HPKE with JOSE.


--- middle

# Introduction

Hybrid public-key encryption (HPKE) {{RFC9180}} is a scheme that 
provides public key encryption of arbitrary-sized plaintexts given a 
recipient's public key. HPKE utilizes a non-interactive ephemeral-static 
Diffie-Hellman exchange to establish a shared secret. The motivation for
standardizing a public key encryption scheme is explained in the introduction
of {{RFC9180}}.

The HPKE specification defines several features for use with public key encryption
and a subset of those features is applied to JOSE ({{RFC7516}}). Since 
JOSE provides constructs for authentication, those are not re-used from the HPKE specification.
This specification uses the "base" mode, as it is called in HPKE specification
language.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

# Conventions and Terminology

This specification uses the following abbreviations and terms:

- Content-encryption key (CEK), a term defined in CMS {{RFC2630}}.
- Hybrid Public Key Encryption (HPKE) is defined in {{RFC9180}}.
- pkR is the public key of the recipient, as defined in {{RFC9180}}.
- skR is the private key of the recipient, as defined in {{RFC9180}}.
- Key Encapsulation Mechanism (KEM), see {{RFC9180}}.
- Key Derivation Function (KDF), see {{RFC9180}}.
- Authenticated Encryption with Associated Data (AEAD), see {{RFC9180}}.
- Additional Authenticated Data (AAD), see {{RFC9180}}.

# HPKE for JOSE

## Overview

The JSON Web Algorithms (JWA) {{RFC7518}} in Section 4.6 defines two ways using the key agreement result. When Direct Key Agreement is employed, the shared secret established through the HPKE will be the content encryption key (CEK). When Key Agreement with Key Wrapping is employed, the shared secret established through the HPKE will wrap the CEK. If multiple recipients are needed, then the version with key wrap is used.

In both cases a new JOSE header parameter, called 'encapsulated_key',
is used to convey the content of the enc structure defined in the HPKE specification. "Enc" represents the serialized public key.

When the alg value is set to any of algorithms registered by this
specification then the 'encapsulated_key' header parameter MUST
be present in the unprotected header parameter.

The 'encapsulated_key' parameter contains the encapsulated key, which is output of the HPKE KEM, and is represented as a base64url encoded string.

# Ciphersuite Registration

This specification registers a number of ciphersuites for use with HPKE.
A ciphersuite is thereby a combination of several algorithm configurations:

- HPKE Mode
- KEM algorithm
- KDF algorithm
- AEAD algorithm

For better readability of the algorithm combination ciphersuites labels are
build according to the following scheme: 

~~~
HPKE-<Mode>-<KEM>-<KDF>-<AEAD>
~~~

For a list of ciphersuite registrations, please see {{IANA}}.

# HPKE Encryption and Decryption

## HPKE Encryption with SealBase

The SealBase(pkR, info, aad, pt) function is used to encrypt a plaintext pt to a recipient's public key (pkR).

   Two cases of plaintext need to be distinguished:

   *  In Key Agreement with Key Wrapping mode, the plaintext "pt" passed into
      SealBase is the CEK.  The CEK is a random byte sequence of length
      appropriate for the encryption algorithm. For example, AES-128-GCM 
      requires a 16 byte key and the CEK would therefore be 16 bytes long.

   *  In Direct Key Agreement mode, the plaintext "pt" passed into SealBase
      is the content to be encrypted.  Hence, there is no intermediate
      layer utilizing a CEK.

   The "aad" parameter in SealBase function will take the JWE AAD value as input. The "info" parameter in SealBase function will take the JOSE context specific data defined in Section 4.6.2 of {{RFC7518}} as input.

   If SealBase() is successful, it will output a ciphertext "ct" and an
   encapsulated key "enc".

## HPKE Decryption with OpenBase

   The recipient will use the OpenBase(enc, skR, info, aad, ct) function
   with the "encapsulated_key" and the "ciphertext" parameters received from the sender.  The
   "aad" and the "info" parameters are constructed from JWE AAD and JOSE context,
   respectively.

   The OpenBase function will, if successful, decrypt "ct".  When
   decrypted, the result will be either the CEK (when Key Agreement with Key Wrapping mode is
   used), or the content (if Direct Key Agreement mode is used).  The CEK is the
   symmetric key used to decrypt the ciphertext.

# Post-Quantum Considerations

The migration to Post-Quantum Cryptography (PQC) is unique in the history of modern digital cryptography in that neither the traditional algorithms nor the post-quantum algorithms are fully trusted to protect data for the required data lifetimes. The traditional algorithms, such as RSA and elliptic curve, will fall to quantum cryptalanysis, while the post-quantum algorithms face uncertainty about the underlying mathematics, compliance issues, unknown vulnerabilities, hardware and software implementations that have not had sufficient maturing time to rule out classical cryptanalytic attacks and implementation bugs.

Hybrid key exchange refers to using multiple key exchange algorithms simultaneously and combining the result with the goal of providing security even if all but one of the component algorithms is broken. It is motivated by transition to post-quantum cryptography. HPKE can be extended to support hybrid post-quantum KEM {{?I-D.westerbaan-cfrg-hpke-xyber768d00-02}}. Kyber, which is a KEM does not support the static-ephemeral key exchange that allows HPKE based on DH based KEMs and its optional authenticated modes as discussed in Section 1.2 of {{?I-D.westerbaan-cfrg-hpke-xyber768d00-02}}. 

The JOSE HPKE PQ/T hybrid algorithms are defined in {{IANA}}.

## Example Hybrid Key Agreement Computation

This example uses HPKE-Base-P256-SHA256-AES128GCM as the algorithm,
which correspond to the following HPKE algorithm combination:

- KEM: DHKEM(P-256, HKDF-SHA256)
- KDF: HKDF-SHA256
- AEAD: AES-128-GCM
- Mode: Base
- payload: "This is the content"
- aad: ""

{
    "header": {
        "alg": "HPKE-Base-P256-SHA256-AES128GCM",
        "kid": "7"
    },
    "encapsulated_key": "BIxvdeRjp3MILzyw06cBNIpXjGeAq6ZYZGaCqa9ykd/Cd+yTw9WHB4GChsEJeCVFczjcPcr/Nn4pUTQunbMNwOc=",
    "ciphertext": "7iIgYwjkeMJ5uUuwcfOl+7rEEqbv/jQZX3xBadfY6BZm2L4T"
}

# Security Considerations

This specification is based on HPKE and the security considerations of
{{RFC9180}} are therefore applicable also to this specification.

HPKE assumes the sender is in possession of the public key of the recipient and
HPKE JOSE makes the same assumptions. Hence, some form of public key distribution
mechanism is assumed to exist but outside the scope of this document.

HPKE relies on a source of randomness to be available on the device. Additionally, 
with the two layer structure the CEK is randomly generated and it MUST be
ensured that the guidelines in {{RFC8937}} for random number generations are followed. 

# IANA Considerations

#  IANA Considerations {#IANA}

This document requests IANA to add new values to the 'JOSE Algorithms' and to 
the 'JOSE Header Parameters' registries in the 'Standards Action 
With Expert Review category'.

## JOSE Algorithms Registry

- Algorithm Name: HPKE-Base-P256-SHA256-AES128GCM
- Algorithm Description: Cipher suite for JOSE-HPKE version 1 in Base Mode that uses the DHKEM(P-256, HKDF-SHA256) KEM, the HKDF-SHA256 KDF and the AES-128-GCM AEAD.
- Algorithm Usage Location(s): "alg"
- JOSE Implementation Requirements: Optional
- Change Controller: IESG
- Specification Document(s): [[TBD: This RFC]]
- Algorithm Analysis Documents(s): TODO

- Algorithm Name: HPKE-Base-P256-SHA256-ChaCha20Poly1305
- Algorithm Description: Cipher suite for JOSE-HPKE version 1 in Base Mode that uses the DHKEM(P-256, HKDF-SHA256) KEM, the HKDF-SHA256 KDF and the ChaCha20Poly1305 AEAD.
- Algorithm Usage Location(s): "alg"
- JOSE Implementation Requirements: Optional
- Change Controller: IESG
- Specification Document(s): [[TBD: This RFC]]
- Algorithm Analysis Documents(s): TODO

- Algorithm Name: HPKE-Base-P384-SHA384-AES256GCM
- Algorithm Description: Cipher suite for JOSE-HPKE version 1 in Base Mode that uses the DHKEM(P-384, HKDF-SHA384) KEM, the HKDF-SHA384 KDF, and the AES-256-GCM AEAD.
- Algorithm Usage Location(s): "alg"
- JOSE Implementation Requirements: Optional
- Change Controller: IESG
- Specification Document(s): [[TBD: This RFC]]
- Algorithm Analysis Documents(s): TODO

- Algorithm Name: HPKE-Base-P384-SHA384-ChaCha20Poly1305
- Algorithm Description: Cipher suite for JOSE-HPKE version 1 in Base Mode that uses the DHKEM(P-384, HKDF-SHA384) KEM, the HKDF-SHA384 KDF, and the ChaCha20Poly1305 AEAD.
- Algorithm Usage Location(s): "alg"
- JOSE Implementation Requirements: Optional
- Change Controller: IESG
- Specification Document(s): [[TBD: This RFC]]
- Algorithm Analysis Documents(s): TODO

- Algorithm Name: HPKE-Base-P521-SHA512-AES256GCM
- Algorithm Description: Cipher suite for JOSE-HPKE version 1 in Base Mode that uses the DHKEM(P-521, HKDF-SHA512) KEM, the HKDF-SHA512 KDF, and the AES-256-GCM AEAD.
- Algorithm Usage Location(s): "alg"
- JOSE Implementation Requirements: Optional
- Change Controller: IESG
- Specification Document(s): [[TBD: This RFC]]
- Algorithm Analysis Documents(s): TODO

- Algorithm Name: HPKE-Base-P521-SHA512-ChaCha20Poly1305
- Algorithm Description: Cipher suite for JOSE-HPKE version 1 in Base Mode that uses the DHKEM(P-521, HKDF-SHA512) KEM, the HKDF-SHA512 KDF, and the ChaCha20Poly1305 AEAD.
- Algorithm Usage Location(s): "alg"
- JOSE Implementation Requirements: Optional
- Change Controller: IESG
- Specification Document(s): [[TBD: This RFC]]
- Algorithm Analysis Documents(s): TODO

- Algorithm Name: HPKE-Base-X25519-SHA256-AES128GCM
- Algorithm Description: Cipher suite for JOSE-HPKE version 1 in Base Mode that uses the DHKEM(X25519, HKDF-SHA256) KEM, the HKDF-SHA256 KDF, and the AES-128-GCM AEAD.
- Algorithm Usage Location(s): "alg"
- JOSE Implementation Requirements: Optional
- Change Controller: IESG
- Specification Document(s): [[TBD: This RFC]]
- Algorithm Analysis Documents(s): TODO

- Algorithm Name: HPKE-Base-X25519-SHA256-ChaCha20Poly1305
- Algorithm Description: Cipher suite for JOSE-HPKE version 1 in Base Mode that uses the DHKEM(X25519, HKDF-SHA256) KEM, the HKDF-SHA256 KDF, and the ChaCha20Poly1305 AEAD.
- Algorithm Usage Location(s): "alg"
- JOSE Implementation Requirements: Optional
- Change Controller: IESG
- Specification Document(s): [[TBD: This RFC]]
- Algorithm Analysis Documents(s): TODO

- Algorithm Name: HPKE-Base-X448-SHA512-AES256GCM
- Algorithm Description: Cipher suite for JOSE-HPKE version 1 in Base Mode that uses the DHKEM(X448, HKDF-SHA512) KEM, the HKDF-SHA512 KDF, and the AES-256-GCM AEAD.
- Algorithm Usage Location(s): "alg"
- JOSE Implementation Requirements: Optional
- Change Controller: IESG
- Specification Document(s): [[TBD: This RFC]]
- Algorithm Analysis Documents(s): TODO

- Algorithm Name: HPKE-Base-X448-SHA512-ChaCha20Poly1305
- Algorithm Description: Cipher suite for JOSE-HPKE version 1 in Base Mode that uses the DHKEM(X448, HKDF-SHA512) KEM, the HKDF-SHA512 KDF, and the ChaCha20Poly1305 AEAD.
- Algorithm Usage Location(s): "alg"
- JOSE Implementation Requirements: Optional
- Change Controller: IESG
- Specification Document(s): [[TBD: This RFC]]
- Algorithm Analysis Documents(s): TODO

- Algorithm Name: HPKE-Base-X25519Kyber768-SHA256-AES256GCM
- Algorithm Description: Cipher suite for JOSE-HPKE version 1 in Base Mode that uses the X25519Kyber768Draft00 KEM, the HKDF-SHA256 KDF, and the AES-256-GCM AEAD.
- Algorithm Usage Location(s): "alg"
- JOSE Implementation Requirements: Optional
- Change Controller: IESG
- Specification Document(s): [[TBD: This RFC]]
- Algorithm Analysis Documents(s): TODO

- Algorithm Name: HPKE-Base-X25519Kyber768-SHA256-ChaCha20Poly1305
- Algorithm Description: Cipher suite for JOSE-HPKE version 1 in Base Mode that uses the X25519Kyber768Draft00 KEM, the HKDF-SHA256 KDF, and the ChaCha20Poly1305 AEAD.
- Algorithm Usage Location(s): "alg"
- JOSE Implementation Requirements: Optional
- Change Controller: IESG
- Specification Document(s): [[TBD: This RFC]]
- Algorithm Analysis Documents(s): TODO

## JOSE Header Parameters

- Parameter Name: "encapsulated_key"
- Parameter Description: HPKE encapsulated key
- Parameter Information Class: Public
- Used with "kty" Value(s): "OKP"
- Change Controller: IESG
- Specification Document(s): [[This specification]]
 
--- back

# Acknowledgments
{: numbered="false"}

It leverages text from {{?I-D.ietf-cose-hpke}}. 