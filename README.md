## Secure(Se) Attestation(At) Sockets(S) Library

C++ library that abstracts and encapsulates the TCP, TLS and TLS extensions used for Attestation of Trusted Excecution Environments(TEEs).

Most of the implementation follows the [draft-fossati-tls-attestation-07](https://datatracker.ietf.org/doc/draft-fossati-tls-attestation/) which is the draft that explains how Attestation could be combined with TLS to establish secure connections. 

The implementation is not covering everything that draft defines and in some aspects are implemented differently but idea stays tthe same, but is designed to be easily extendend.

Currently, implementation supports component combinations (Model, Attestation Type, Attestation Creds, Platform): 

    - **Background Check Model, Server Attestation, Only Attestation Credentials, Amd-Sev-Snp**

Since some of the components on higher abastraction layers it is easy to implement new combinations of components.

#### TODO 

###### Implementation
1. Add Tool attestation submodules
    - sev-snp-measure
    - snpguest
    - snphost

###### Documentation
1. Add "How to use" section

