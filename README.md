commit-signer
-------------

A simple opinionated tool for enabling ~0 configuration secure
git commit signing and SSH key management backed by the MacOS secure enclave.

To use:

```
./cs install
```

This will install an ssh-agent implementation which has two keys,
both stored in the secure enclave of your processor.
The first is used for authenticating against GitHub and other sites
or servers which you may need to use. It is usable with no further
authentication.
The second meanwhile is to be used for code signing. Each signing
operation requires biometric authentication, which is validated
by the operating system and which generally uses TouchId.
