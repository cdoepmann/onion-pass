# Onion Pass – Tor Denial of Service Defenses for Onion Services

*Original Code Author: [Valentin Franck] <gaspar_ilom@campus.tu-berlin.de>*

This is a prototype implementation of *Onion Pass*, an extension to the
Tor network for effective DoS mitigation against Onion Services.

It accompanies the following scientific publication:

_Christoph Döpmann, Valentin Franck, and Florian Tschorsch: "Onion Pass: Token-Based Denial-of-Service Protection for Tor Onion Services", Proceedings of the 2021 IFIP Networking Conference, Helsinki/Espoo/virtual, Finland, June 21-24, 2021_

This is just a prototype and should not be used in production,
mostly because it was not written with security in mind, but only to proof and evaluate the concept.
Substantial parts of the implementation that are up to the Onion Service
(such as the choice of an challenge-response mechanism appropriate for the Onion service)
are still missing and ares out of scope of this work.

## Prerequisites:
The same as in vanilla Tor.
Cryptography is written for OpenSSL 1.1.1.

## Build
To build with the defenses enabled proceed as usual:

    sh autogen.sh && ./configure && make && make install

## Enable Onion Pass
To enable the defenses for an onion service add the following lines to your torrc:

    # set the HSDir as in vanilla Tor
    HiddenServiceDir /path/to/hs-dir

    # ...configure the onion service as in vanilla Tor.

    # only v3 onion services are supported
    HiddenServiceVersion 3

    # enables the defenses
    HiddenServiceEnableHsDoSDefense 1

    # number of tokens that may be requested per challenge.
    # note, there are no challenges implemented!
    HiddenServiceEnableHsDoSDefenseTokenNum 100
    
    # set the maximum rate for INTRODUCE2 cells without tokens.
    # exceeding cells will be discarded, unless they contain a token.
    HiddenServiceEnableHsDoSRatePerSec 10000

    # set the maximum burst for INTRODUCE2 cells without tokens.
    # exceeding cells will be discarded, unless they contain a token.
    HiddenServiceEnableHsDoSBurstPerSec 10000

## Enable the Defenses for a Client
To enable the defenses for a client add the following lines to your torrc:

    # enable the client to use the defenses, for all services that support it
    HsDoSRetrieveTokens 1
    
    # use this directory to store retrieved tokens for future redemptions.
    # if not set, tokens are only kept in memory by the tor process.
    HsDoSClientDir /path/to/client-dir 

## How do the Defenses work?
The DoS defenses are token-based.
Service operators define rate limits for new connections.
Once these rate limits are exceeded, clients may only connect to the onion service
if they include a valid token in their introduction cells.
Tokens are only issued by the onion service after the client solved a challenge.

Tokens are based on verifiable oblivious pseudo random functions (V-OPRFs).
The cryptographic scheme is borrowed from Privacy Pass: https://blog.cloudflare.com/privacy-pass-the-math/

For more details, please see the conference paper referenced above.

## Evaluation
There is a branch `evaluation` which by default prints some benchmarks to the CLI
when the DoS defenses are used by either client or onion service.
Furthermore, to evaluate the cryptographic operations, the test `test_hs_dos_token_benchmark` can be run.

## Tests
There are some unit tests for the cryptographic operations
and for encoding and decoding of service descriptors. The rest of the code is mostly untested.
