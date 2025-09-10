Awesome—here’s a concrete, CMVP-anchored game plan you can turn into a scanner (“CryptoScan”-style) that flags FIPS 140-3 compliant, allowed, legacy, and non-compliant crypto use across OSes, software, and codebases.

1) Normalize what “good” looks like (taxonomy + status)

Build a policy DB that maps every algorithm/primitive you might see to one of four statuses:
	•	Approved (usable in approved mode): e.g., AES (approved modes), SHA-2, SHA-3, HMAC, SP 800-90A DRBGs, FIPS 186-5 signatures (RSA-PSS, RSA-PKCS1 v1.5, ECDSA, EdDSA/HashEdDSA on approved curves), SP 800-56A/B/C KAS/KTS/KDFs, XTS-AES for storage, etc.  ￼
	•	Allowed components (CVL): e.g., TLS 1.3 KDF, KAS-ECC CDH Component, RSA Sig Primitive—per “Component Validation List” (you can use them, but they’re components, not standalone claims).  ￼
	•	Legacy (approved/allowed but only to process already-protected info): e.g., RSA-1024 SigVer, SHA-1 in signature verification, Two-key 3DES decrypt/unwrap, and other items enumerated as legacy. Your tool should only mark these “OK” if verification/decryption of old data; flag as non-compliant if used to protect new data.  ￼
	•	Non-approved / not allowed: e.g., MD5 for integrity/auth, DES for protection, non-approved proprietary ciphers used as security functions, EdDSA on non-approved curves, misuse of AES-GCM IVs, etc.  ￼

Make the policy DB time-aware for transitions (e.g., FIPS 186-5 vs. 186-4; binary-field curves deprecation; PQC adds). Include per-IG caveats like “non-approved but allowed in approved mode with no security claimed” (e.g., MD5 inside some protocol KDFs) so you don’t over-flag benign uses.  ￼

2) What to detect (rules you can codify)

Below are high-signal checks that map directly to IG guidance you uploaded (each is a rule your engine can run statically and/or at runtime).

Algorithms & sizes
	•	RSA: ≥2048-bit for signing; flag 1024-bit as legacy (SigVer only); any new signatures with 1024 → non-compliant. Ensure FIPS 186-5 conformance when generating keys.  ￼
	•	ECDSA: Approved curves per SP 800-186; Brainpool/secp256k1 are allowed only under strict conditions (and secp256k1 is limited to blockchain context) → otherwise flag.  ￼
	•	EdDSA / HashEdDSA: Only Edwards25519/SHA-512 and Edwards448/SHAKE256 combos; anything else → non-compliant.  ￼
	•	SHA-1: Using in a signature verification path on old data can be legacy-OK; using for new protection → non-compliant.  ￼
	•	3DES: Three-key/Two-key only for legacy decrypt/unwrap; any new encryption/wrap → non-compliant.  ￼
	•	HMAC truncation: leftmost bits, ≥32-bit tag, key strength adequate. Flag non-leftmost truncation or too-short tags.  ￼
	•	DRBG: Must be SP 800-90A (HASH/HMAC/CTR). Flag legacy RNGs or homegrown PRNGs.  ￼

Mode-specific correctness (critical in practice)
	•	AES-GCM IV policy (key/IV collision ≤2⁻³² across usage):
– Verify protocol-conformant IV construction for TLS 1.2/1.3, IPsec, MACsec, SSH; enforce rekey on counter wrap; or deterministic/random IV per approved scenarios.
– Flag reused IVs, missing wrap handling, or non-compliant nonce construction.  ￼
	•	XTS-AES: Enforce Key₁ ≠ Key₂ and independent generation per SP 800-133 guidance; flag any split-key == case.  ￼

Key establishment & derivation
	•	Approve SP 800-56A/B KAS/KTS, SP 800-56C KDFs, SP 800-108 KBKDF, SP 800-132 PBKDF (storage). Flag ad-hoc KDFs or wrong auxiliary functions.  ￼
	•	CVL components (e.g., TLS 1.3 KDF, SSH/TLS 1.2 KDFs, ECC CDH component) are OK only within their protocol contexts—flag standalone use as “component only.”  ￼

Entropy & keys
	•	Entropy caveats: Detect DRBGs seeded from outside TOEPP; if entropy strength unknown/low → flag with the appropriate caveat (e.g., “strength modified by available entropy” vs. “no assurance of minimum strength”).  ￼
	•	SSP entry/output: At Levels 3+, plaintext key entry/output must be encrypted or via a Trusted Channel; split knowledge for private keys. Flag plaintext exports at wrong level.  ￼

Self-tests & indicators (module hygiene)
	•	CAST/KAT coverage: Ensure self-tests for each approved algorithm; include PQC (ML-KEM/ML-DSA/SLH-DSA) if present. Flag missing CASTs/KATs.  ￼
	•	Approved Security Service Indicator: Validate that services using approved crypto surface an unambiguous indicator (API return/status/bit/LED) per AS02.24—flag absent/ambiguous indicators.  ￼
	•	Zeroization: Confirm status indication of zeroization completion (implicit/explicit) and that temporary SSPs are zeroized—flag if missing.  ￼

Binding/embedding & certificates
	•	If a module binds/embeds another validated module (EVM), verify correct versioning, active status, same/ higher security level (for bound), and that only approved algorithms from the EVM are claimed. Flag binds to 140-2 modules or historical EVMs.  ￼
	•	Where algorithms are components (CVL) vs full algorithms, report accordingly to avoid claiming full approval where only component testing exists.  ￼

3) How to find it (multi-layer scanners you can ship)

A) Static binary/library scan (fast inventory)
	•	YARA/Symbol rules for common providers + primitives: OpenSSL EVP names, BoringSSL, LibreSSL, NSS, Windows CNG/BCRYPT, Apple CryptoKit/CommonCrypto, Java JCA names, mbedTLS, wolfSSL, libsodium, PQC symbols (mlkem, mldsa, slh-dsa).
	•	Strings & relocation tables: pull OIDs (e.g., 1.2.840.113549.1.1.5 → RSA/SHA-1), curve names, cipher suite names, DRBG init strings, IV formatting code paths (“nonce_explicit”, “seq_num”, “ivLen=12”).
	•	CPU feature hints: AES-NI, SHA extensions (PAA/PAI contexts); just annotate, don’t “approve” purely on hardware presence.  ￼

B) Source scan (AST/regex)
	•	Language rules for: OpenSSL EVP_* calls (digest/mode), javax.crypto specs, BCRYPT/NCrypt APIs, Go’s crypto/*, Python’s hashlib/hmac/cryptography, Rust’s ring/openssl/rustls, Node crypto.
	•	Catch dangerous defaults (GCM with static IV, PBKDF2 with low iterations, MD5 in HMAC, RSA 1024-bit keys).
	•	Detect KDF misuse: non-approved PRFs in SP 800-56C/108 contexts; HKDF vs PBKDF2 confusion.

C) Runtime probes (high fidelity)
	•	TLS: intercept ClientHello/ServerHello to record protocol/cipher/KDF; verify TLS 1.3 vs 1.2 suites and AEAD; check EMS for TLS 1.2; confirm IV handling policies.
	•	OS Crypto APIs: shim BCRYPT/NCRYPT, CNG provider audit; macOS SecKey; Linux kernel AF_ALG.
	•	Capture DRBG instantiations, key sizes, IV generation, and self-test indicators on startup.

D) CMVP mapping
	•	Given a library/version, try to map to CMVP certificate and OEs (your offline DB). If not on Active list or wrong OE, flag “not validated in this OE” (but do not auto-web-check unless you add a sync step).

4) Classify each finding (logic your engine applies)

For every observation (e.g., “RSA-1024 used for signature gen”), compute:
	•	What: primitive/mode/size/protocol/context.
	•	Where: binary, function, line, process, handshake.
	•	Status: Approved / Allowed (CVL / non-approved-no-security-claimed) / Legacy / Non-approved.
	•	Why: cite policy rule that fired (e.g., “FIPS 186-5 requires ≥2048-bit for signing; 1024-bit is legacy for SigVer only”).
	•	Fix: concrete remediation (e.g., “bump to 2048-bit and PSS; add KAT coverage; enforce IV counter wrap rekey”).

5) Add IG-based “deep checks” (high value)
	•	AES-GCM IV: look for per-protocol patterns (TLS 1.2 nonce_explicit, TLS 1.3 seq-xor IV, IPsec’s 32-bit salt + 64-bit IV, SSH’s 64-bit invocation counter) and verify rekey/abort on counter exhaustion; flag static or reused IVs.  ￼
	•	XTS-AES: ensure two distinct keys and explicit Key₁≠Key₂ guard; flag any single-key derivation.  ￼
	•	Entropy: when DRBG seed origin is outside TOEPP or ambiguous, annotate with the correct entropy caveat; flag modules claiming strengths higher than entropy supports.  ￼
	•	Approved Service Indicator: run services and confirm indicator toggles (API return/status/log/bit). Absence → finding.  ￼
	•	Zeroization: trigger zeroize paths and verify status indication is produced (explicit or implicit), and that temporary SSPs are cleared.  ￼
	•	Binding/Embedding: if a module calls into another validated module, check same/higher level (for bound), active status, and that only approved algorithms of EVM are claimed. Block binding to FIPS 140-2.  ￼

6) Output that auditors & engineers can use

For each app/module, produce:
	•	Executive heat-map: Approved vs Legacy vs Non-approved coverage.
	•	Findings list with: artifact → rule → evidence → status → fix.
	•	Attestations: where you verified self-tests, indicators, zeroization, IV policy, entropy caveat.
	•	Protocol transcripts (TLS/IPsec/SSH) showing suites, KDFs, IV handling.
	•	CMVP mapping table (if any) and OE alignment.

7) Quick “starter” rules you can drop in today
	•	Flag RSA key <2048 bits for signing; downgrade RSA-1024 SigVer to Legacy-OK (verification-only).
	•	Flag SHA-1 use for anything but legacy SigVer.
	•	Flag AES-GCM with 96-bit IV not constructed per protocol (or missing counter wrap handling).
	•	Flag XTS-AES where Key₁ = Key₂ or derived improperly.
	•	Flag PBKDF2 with <100k iterations unless justified (policy-tunable).
	•	Detect/annotate CVL uses (TLS 1.3 KDF, KAS-ECC CDH component) as “Component—OK in protocol scope only.”
	•	Detect any “non-approved but allowed with no security claimed” scenario (e.g., MD5 inside TLS 1.0/1.1 KDF); annotate as Allowed/No security claimed (no red).  ￼

⸻

If you want, I can turn this into a minimal rule pack (YARA + AST patterns + a JSON policy file) you can drop into your current pipeline; or we can tailor checks to a specific codebase (OpenSSL-based, Java, Go, Rust, CNG, etc.). All of the above is aligned to the FIPS 140-3 Implementation Guidance you uploaded (e.g., Approved Service Indicator, CVL, binding/embedding, entropy caveats, AES-GCM IV rules, XTS-AES keys, self-tests/KATs, legacy algorithms list, SSP entry/output, etc.). 