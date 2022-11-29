# Symmetric and asymmetric cryptography

## Encryption

### Process

* cryptography is transforming plaintext content into a format that can not be read by anybody, but only by a specific receiver who has the means to decrypt it back.
* encryption: plaintext => ciphertext
* decryption: ciphertext=> plaintext
* encryption algorithm: plaintext + encryption key => ciphertext
* decryption algorithm: ciphertext + decryption key => plaintext

### Types

* **symmetric** cryptography: encryption and decryption key is the same
* **asymmetric** cryptography: encryption and decryption keys are different (private key and public key)
* *disadvantage* of symmetric: in order to communicate privately between two parties, each "pair" needs their own key
* public key are known to everybody is used to encrypt
* private key is used to decrypt and only used by the receiver

### 4 goals of cryptography

1. Confidentiality: only allowed parties can read content
   1. data at rest: stored on a hard drive
   2. data in transit: when data is sent over a network
   3. data in use: when data is placed in memory
2. Integrity: data is not changed by unauthorised parties
3. Authentication: proof of identity
4. Non-repudiation: confirming that a message came from the stated sender; also confirms that the message was actually sent

### Codes and ciphers

* **codes** are used to keep a *pre-defined content* secret by mapping a special word to a specific phrase or meaning
* **ciphers** use mathematical methods to transform *any content* from plaintext to encrypted
  * *stream ciphers*: one character/bit a a time
  * *block ciphers*: use chunks/blocks of a message and perform the action on them
  * *substitutional cipher*: a character is replaced by another, but stays in place in the message; to decrypt the process has to be reversed
  * *transposition cipher*: leaves the characters, but repositions them

### Cryptographic math

* **XOR**: true if only of of the inputs is true
* **pseudorandom** algorithm: "emulating randomness"
* **confusion**: hiding the connection between ciphertext and encryption key
* **diffusion**: changing a single bit of the plaintext should at least half of the ciphertext
* **obfuscation**: hiding code from users

### Choosing an encryption algorithm

* don't build you own
* security through obscurity doesn't work
* chose a proven algorithm instead
* choosing a key length
  * longer is more secure
  * longer uses more performance
* use a library to implement the algorithm

### The cryptographic lifecycle

* encryption systems age due to key lengths being no longer secure or algorithms loosing to modern hardware
* 5 steps in lifecycle
  1. Initiation: gathering requirements for a new system
  2. Development and Acquisition: finding a combination of hardware/software and algorithms
  3. Implementation and Assessment: configure and test system
  4. Operations and Maintenance: ensure continued secure operation
  5. Sunset: phasing out system and destroying keys

## Symmetric Cryptography

* uses the same key to encrypt and decrypt

###Data Encryption Standard DES

* designed by IBM for the US federal government
* used for non-classified information
* replaced untested existing standards used by agencies
* algorithm
  * 16 rounds of encryption (Feistel function)
  * each F-box takes half a block and a section of the encryption key as input
  * uses 8 different substitution
  * all 8 inputs are combined and then transpositioned
* **facts**
  * block cipher (64-bit blocks)
  * 56 bits key
  * symmetric encryption algorithm
  * no longer secure

### Triple DES (3DES)

* = running DES up to three times using three keys
* options for keys
  * using three different keys => 128 bits(?) *TODO: check this!*
  * K1 = K3, other keys different
  * all keys are identical (backward-compatible)
* facts
  * block cipher (64-bit blocks)
  * symmetric encryption algorithm
  * 112 bits key length
  * now being phased out

### AES

* combination of substitution and transposition
* facts
  * symmetric 
  * block, 128-bit blocks
  * key lengths: 128, 192, 256 bits
  * secure

### Blowfish

* public domain
* created to replace DES
* Uses Feistel (both substitution and transposition)
* symmetric encryption algorithm
* Block cipher operating on 64-bits blocks
* key lengths: 32 to 448 bits
* no longer secure

#### Twofish

* public domain
* created to replace DES
* Uses Feistel (both substitution and transposition)
* symmetric encryption algorithm
* Block cipher operating on 128-bits blocks
* key lengths: 128, 192 or 256 bits
* secure

### RC4

* trade secret algorithm until leaked online
* now public domain
* used in network-based encryption (WEP, WPA, SSL, TLS) 
* creates a pseudorandom keystream (not 100% random, due to initialisation)
* Since 2015 no longer secure (government intelligence can break it)
* facts
  * symmetric
  * stream cipher
  * variable key lengths: 40 to 2048bits
  * no longer secure

### Cipher modes

* ECB (Electronic Codebook)
  * breaks message into blocks and encrypts all with the same algorithm
  * using same block with same key will generate predictable identical ciphertext blocks
* Cipher Block Chaining (CBC)
  * uses the previous block as input to encrypt the next block
  * first step: Initiation Vector (IV) is used with XOR operation
  * all following steps: first ciphertext block is XOR'ed
* Counter Mode (CTR)
  * takes two inputs as additional inputs
    * nonce: randomly generated
    * counter: starts with 0
  * after every encryption the counter is increased
* Galois/Counter Mode (GCM): adds authentication capability

### Steganography

* hides information in plain sight
* uses high-res images to hide ASCII text
* other large files can be used (videos, sounds, ...)

## Asymmetric cryptography

* gives each user a pair of keys
  * private key to decrypt messages
  * public keys to encrypt messages
  * the public key must be shared with everybody who wants to send messages to receiver
  * private key must be kept secure and protected
* solves the issue of having a shared secret key for each pair for people who want to communicate securely

### RSA

* Named after: Ron Rivest, Adi Shamir, Leonard Adlmeman in 1977
* still used today
* key pair is generated using large prime numbers
* is slow, so often instead of encrypting long messages, a symmetric key is encrypted using RSA and that key is used to encrypt/decrypt the actual message
* RSA patent expired in 2000
* facts
  * asymmetric encryption algorithm
  * key lengths: 1024 and 4096 
  * secure

### Pretty Good Privacy (GPG)

* Open PGP
* uses public and private keys
* generates a random symmetrical key and encrypts this with the public key
* message + encrypted random key are sent to receiver
* a receiver decrypts the random key and uses it to decrypt the entire message
* exists as Open Source (GnuPG) and commercial products

### Elliptic curve and quantum cryptography

* all public key cryptography is based on Math complexity and getting the factors for a large prime numbers
* as soon as a solution is invited to solve those complex operations quickly, all public key cryptography will no longer be secure
* ECC (Elliptic Curve Cryptography) is not using prime numbers
* Quantum Computing
  * can defeat both
    * ECC
    * prime factorisation algorithms
  * could also help to improve cryptography

### Tor

* = "The Onion Router"
* must use at least three nodes
  * the first one knows the sender and first node
  * the second one know the first node and the the third node
  * the third node only know the second node and the target resource
* Perfect Forward Secrecy 
  * each nodes only knows the identity of the node before and after
  * every node can only decrypt the "envelop" that's addressed to itself
  * every node forwards the next envelop to the next node
* Hidden Sites
  * provides two-way anonymity
  * Onion address: `<random string>.onion`
* Tor can be used for criminal activities and it's impossible to track those

## Key Management

### Key Exchange (for symmetric keys)

* initially, keys have to be exchanged in plaintext between two parties
* this makes enables malicious people to intercept the keys and provide fake keys instead
* there must be a way to determine that the key sent by a party is from that party without giving an attacker the change to mess with this information
* out-of-bands (non-digital) ways to exchange
  * face-to-face
  * via phone
  * via post on a piece of paper or hardware
* solution: in-band key exchange

### Diffie-Hellman

* provides symmetric key exchange capability
* process:
    1. party members *agree* on a **two shared numbers** (one must be prime number)
    1. each party selects *one additional secret number*
    1. Alice uses the secret number and shared common values as inputs for the first algorithm
    1. **the result** of that algorithm is send from Alice to Bob
    1. Bob takes that result and uses it *and* his secret number as inputs for the first algorithm
    1. Bob now sends the result to Alice
1. Alice and Bob use the result and their secret value as inputs for the second algorithm
    1. **that** result is the symmetric key
* variant: Elliptic Curve Diffie-Helmann (ECDH)

### Key escrow

* a independent party will provide access to a third party under specific circumstances
* e.g. government agents gain access with a court order
* implementation this in a secure way is impossible
* **Recovery Agents** can be used to access information if a user forgets password or leaves the company.

### Key stretching

* = taking a insecure value and making it harder to crack
* two techniques
  * salting: adding a different value to encryption key (this also prevent rainbow table attacks)
  * hashing: this adds more time for verification so each "guess" is slower
* examples
  * **PBKDF2**: Password-Based Key Derivation Function v2
    * uses both techniques
    * process should be repeated 4,000 times
  * **bcrypt**: based on Blowfish

### Hardware security modules (HSM)

* cryptography is slow, special hardware can help accelerate
*  tasks of HSMs
  * manage encryption keys
  * perform cryptographic operations
* Cloud providers run HSMs and provide access to them via services

## Public Key Infrastructure

### Key exchange

* For exchanging symmetric keys two parties must be confident that...
  * they are communicating to the claimed person (»???)
  * nobody can listen to their messages (»Diffie Hellman)
* For exchanging asymmetric keys, only the identity of parties important

### Trust Models

#### Personal knowledge

#### Web of Trust (WOT)

* indirect relationships
* participants sign public keys of people they know personally
* if web becomes large enough there is a high change that connections allow communication between all members

#### Public Key Infrastructure (PKI)

* depends on the trust in service providers named *Certificate Authorities (CA)*
* CAs verify identity and issue certificate containing the public key

### Hash Function

* one-way functions
* generate a fixed-length output of _any_ input
* is collision-free: every hash must be unique (impossible to find two inputs that generate the same hash)

#### Message Digest 5 (MD5)

* 128-bit hash
* no longer secure

#### Secure Hash Algorithm (SHA)

* **SHA-1**
  * 160-bit hash
  * no longer secure
* **SHA-2**
  * is a family of six hash functions
  * 224, 256, 384, and 512-bit hashes
  * are similar to SHA-1
  * still secure
* **SHA-3**
  * different than SHA-2
  * variable fixed length (based on user configuration)
* **RIPEMD** 
  * alternative to government-sponsored hash functions
  * 128, 160, 256, and 320-bit hashes
  * 128 no longer secure, others are
#### Hash-based Message Authentication Code (HMAC)

* TODO: understand this

### Digital Signatures

* full fill 3 requirements
  * *authentication*: sender is who who claims
  * *integrity*: message was not tempered with
  * *non-repudiation*: receiver can proof to third party that message was sent by the sender
* confidentiality is _not_ part of this, therefore the message itself must be encrypted
* reversed process: private keys are used to encrypt and public keys to decrypt
* process
  1. Alice creates a hash of the message.
  1. That hash is encrypted with Alice's private key => digital signature.
  1. Alice sends both the message and the signature to Bob.
  1. Bob creates the hash of the message.
  1. Bob decrypts the signature with Alice's public key.
  1. Bob compare the hash with the decrypted signature. If the values are identical the message is from Alice and was not tempered with

### Certificate Revocation

* Certificate Revocation list (CRL)
  * serial number is added to a list
  * before relying on a cert, list has to be checked
* Online Certificate Status Protocol (OCSP)
  * request the CA if the cert is still active
  * all browsers but Chrome use OCSP

### Certificate Stapling

* OCSP would cause enormous traffic
* cert is checked using OCSP only once for a given timeframe
* the signed and timestamped response from OCSP server is saved by the requesting web server
* response + cert is returned to user
* every user within the timeframe is provided with the stapled certificate

### Types of Certificate Authorities (CAs)
#### Self-Signed Certificates 

* internal CA that's trusted within an organisation
* trust can be extended beyond one organisation

#### Intermediate CA

* can issue certificates
* are trusted by a "higher up" CA (e.g. a root CA)

#### Offline CA

* often root level CAs are not connected to the Web
* private keys of a root level CA are only used to generate new certificates for intermediate CAs (intermediate CAs then issue certificates)

### Certificate Chaining

* enables offline CAs
* enable self-signed certificates

### Certificate Types

* **Wildcard Certificate**
  * uses the `*` character; only one level deep (e.g. `*.example.org`)
  * use cases: load balancer so it can match many domain names
* **Verification levels**
  * *Domain Validation (DV)*: ownership of domain name
  *  *Validation (OV)*: Verifies that the business name matches the "owner" of the domain name
  * *Extended Validation (EV)*: highest type, CA has made sure that the business exists physically and is legit

### Certificate Subject

* = owner of a a public key contained within the certificate
* can be
  * *person*: by name or email
  * *server*: web, SSH
  * *devices*: VPNs, routers, switches
  * *developer*: code signing
* **certificate pinning**: ties a certificate to a subject for a period of time

### Certificate Format

* Distinguished Encoding Rules (**DER**)
  * binary
  * extensions: `.der`, `.crt`, `.cer`
* Privacy Enhanced Mail (**PEM**)
  * e-mail standard no longer in use, but PEM is
  * ASCII equivalent of DER
  * can be converted to DER with OpenSSL
  * extensions: `.pem`, `.crt`
* Personal Information Exchange (**PDX**)
  * binary
  * used by Windows
  * `.pfx`, `.p12`
* **P7B** Format
  * ASCII equivalent of PDX
  * used by Windows
  * extension: `.p7b`

## Cryptographic attacks

### Brute Force attacks

* guessing repeatedly
* take a lot of time (if every succeed)
* attacker just need an example or encrypted text => *known ciphertext attacks*
* Given a simple rotation cipher (e.g. Caesar cipher)
  * **keyspace** is small (25 different keys)
  * brute force attack would work easily
* modern algorithm are not vulnerable to brute-force attacks

### Knowledge-based attacks

* **Frequency analysis**: detects patters in cipher (e.g. most common letters)
* **Known plaintext attack**: attacker knows parts of the cipher and plaintext and uses this information for cracking the key
* **Chosen plaintext attack**: when attacker can encrypt a message with the given key
* **Birthday Attack**: using collisions in hash function to exploit it

### Limitations of encryption algorithm

* some algorithms are faster than others
  * asymmetric is usually slower
  * longer keys are more secure
  * longer keys use more computing power
* some keys can have flaws
* re-using the same keys is dangerous
* algorithms and key don't age well
* **high entropy**: algorithm is less predictable
* some protocols are vulnerable to downgrade attacks when the offer to use a legacy encryption that's less secure (e.g. SSL)

## Cryptographic Applications

### TLS and SSL

* secure communication over public network
* TLS is just a protocol, it uses encryption algorithms
* TLS can be used in an insecure manner (if insecure algorithms are used)
* process
  1. client asks server to use TLS with
    * supported algorithms
    * hash functions
  1. server responds back with
    * cipher suite to use
    * digital certificate
	1. client checks a few things:
	   * checks the CA that issued the certificate
	   * verifies with the CA's public key that the certificate is valid
	   * checks server name on the certificate against the DNS server
	   * certificate is not expired
	   * certificate has not been revoked
	1. session key
	   * client creates a random encryption key (**session key** = _ephemeral key_).
	     Symmetric encryption key used for session between this client and server.
	   * client encrypts the session key with the server's public key.
	   * sends it over to server
	* server decrypts the key with its private key
	* once the connection is closed the session key is destroyed
* SSL is predecessor to SSL and is no longer secure

### Intellectual Property

* Information Rights Management has 3 goals
  * Enforcing data rights (only provide authorised users access)
  * Provisioning access to employees, partners and users
  * Implementing access control models
* Digital Right Management (DRM)
  * uses encryption to prevent users without a license from accessing content
  * use cases: music, video games, books, etc.
  * business use it for trade secrets and other intellectual property

### Specialised use cases

* low power devices: e.g. objects in space or key cards that get power from a magnetic field. Dedicated cryptographic using lightweight encryption are used for that
* low latency: e.g. network traffic; dedicated encryption hardware helps, too
* high resiliency: solution is to ask the sender to keep a copy until the receiver has decrypted and confirmed that the data has been saved successfully
* privacy: *homomorphic encryption* allows hiding personal information while performing computations that (when decrypted) match the results on the plain text

### Blockchain

* = distributed, immutable ledger (can be public)
* data store that nobody can change or destroy
* applications
  * cryptocurrency without central regulators
  * supply chain
  * property information
  * vital records (e.g. passports)