---
title: "Finding Tracking Tags"
category: info

docname: draft-fossaceca-dult-finding-latest
submissiontype: IETF  # also: "independent", "editorial", "IAB", or "IRTF"
number:
date:
consensus: true
v: 3
area: "Security"
workgroup: "Detecting Unwanted Location Trackers"
venue:
  group: "Detecting Unwanted Location Trackers"
  type: "Working Group"
  mail: "unwanted-trackers@ietf.org"
  arch: "https://mailarchive.ietf.org/arch/browse/unwanted-trackers/"
  github: "ekr/draft-fossaceca-dult-finding"
  latest: "https://ekr.github.io/draft-fossaceca-dult-finding/draft-fossaceca-dult-finding.html"

author:
 -
    fullname: "Christine Fossaceca"
    organization: Microsoft
    email: "cfossaceca@microsoft.com"

 -
    fullname: "Eric Rescorla"
    organization: Windy Hill Systems, LLC
    email: "ekr@rtfm.com"

normative:

informative:
  BlindMy:
       title: "Blind My — An Improved Cryptographic Protocol to Prevent Stalking in Apple’s Find My Network"
       date: 2023
       target: https://petsymposium.org/popets/2023/popets-2023-0006.pdf
       author:
       -
         ins: Travis Mayberry
       -
         ins: Erik-Oliver Blass
       -
         ins: Ellis Fenske

  GMCKV21:
       title: "Toward a secure crowdsourced location tracking system"
       date: 2021
       target: https://dl.acm.org/doi/10.1145/3448300.3467821
       author:
       -
         ins: Chinmay Garg
       -
         ins: Aravind Machiry
       -
         ins: Andrea Continella
       -
         ins: Christopher Kruegel
       -
         ins: Giovanni Vigna

  DultDoc4:
       title: "DRAFT Dult Threat Model"
       date: 2024
       target: https://datatracker.ietf.org/doc/html/draft-delano-dult-threat-model
       author:
       -
         ins: Maggie Delano
       -
         ins: Jessie Lowell

  DultDoc3:
       title: "Detecting Unwanted Location Trackers Accessory Protocol"
       date: 2024
       target: https://www.ietf.org/archive/id/draft-ledvina-dult-accessory-protocol-00.html
       author:
       -
         ins: Brent Ledvina
       -
         ins: D. Lazarov

       -
         ins: B. Detwiler

       -
         ins: S.P. Polatkan

  Okamoto:
       title: "Efficient blind and partially blind signatures without random oracles"
       date: 2006
       target: https://link.springer.com/chapter/10.1007/11681878_5
       author:
       -
         ins: Tatsuaki Okamoto

  Heinrich:
       title: "Who Can Find My Devices? Security and Privacy of Apple's Crowd-Sourced Bluetooth Location Tracking System"
       date: 2021
       target: https://petsymposium.org/popets/2021/popets-2021-0045.pdf
       author:
       -
         ins: Alexander Heinrich
       -
         ins: Milan Stute
       -
         ins: Tim Kornhuber
       -
         ins: Matthias Hollick

  WhoTracks:
       title: "Who Tracks the Trackers?"
       date: 2021
       target: https://dl.acm.org/doi/10.1145/3463676.3485616
       author:
       -
         ins: Travis Mayberry
       -
         ins: Ellis Fenske

       -
         ins: Dane Brown
       -
         ins: Christine Fossaceca
       -
         ins: Sam Teplov
       -
         ins: Lucas Foppe
       -
         ins: Jeremey Martin
       -
         ins: Erik Rye

--- abstract

Lightweight location tracking tags are in wide use to allow users
to locate items. These tags function as a component of a crowdsourced
tracking network in which devices belonging to other network
users (e.g., phones) report which
tags they see and their location, thus allowing the owner of the
tag to determine where their tag was most recently seen. This
document defines the protocol by which devices report tags
they have seen and by which owners look up their location.


--- middle

# Introduction

Lightweight location tracking tags are a mechanism by which users can track their personal items. These tags function as a component of a crowdsourced
tracking network in which devices belonging to other network users
(e.g., phones) report on the location of tags they have seen.
At a high level, this works as follows:

- Tags ("Accessories") broadcast an advertisement payload containing
  accessory-specific information. The payload also indicates whether
  the accessory is separated from its owner and thus potentially lost.

- Devices belonging to other users ("Non-Owner Devices" or "Finder Devices")
  observe those payloads and if the payload is in a separated
  mode, reports its location to some central service ("crowdsourced network").

- The owner ("Owner Device") queries the central service ("crowdsourced network") for the location of their
  accessory.

A naive implementation of this design exposes users to considerable
privacy risk. In particular:

* If accessories simply have a fixed identifier that is reported back
  to the tracking network, then the central server is able to track
  any accessory without the user's assistance, which is clearly
  undesirable.

* An attacker can surreptitiously plant an accessory on a target
  and thus track them by tracking their "own" accessory.


{{security-considerations}} provides more detailed definition of the
desired security privacy properties, but briefly, we would like to
have a system in which:

- Nobody other than the owner of an accessory would be able to learn
anything about the location of a given accessory.

- It is possible to detect when an accessory is being used to track
you.

- It is not possible for accessories that do not adhere to the protocol to use the crowdsourced network protocol.

- It is not possible for unverified accessories to use the crowdsourced network protocol.

This document defines a cryptographic reporting and finding protocol
which is intended to minimize these privacy risks. It is intended
to work in concert with the requirements defined in
{{!I-D.detecting-unwanted-location-trackers}}, which facilitate
detection of unwanted tracking tags. This protocol design is based on existing academic research surrounding the security and privacy of bluetooth location tracking accessories on the market today, as described in {{BlindMy}} and {{GMCKV21}}.


# Motivations


## Stalking Prevention

This work has been inspired by the negative security and privacy implications that were introduced by lightweight location tracking tags, and defined in part by {{!I-D.detecting-unwanted-location-trackers}}. The full threat model is described in detail in {{DultDoc4}}, however, a significant element of the threat model lies in part with the security of the Crowdsourced Network, which will be discussed in detail here.

The Crowdsourced Network has unwittingly provided stalkers with a means to anonymously upload and download location reports from BLE trackers. Thus, this document outlines the requirements and responsibilities of the Crowdsourced Network to verify the authenticity of the participants, while also preserving user privacy.


- First, the Crowdsourced Network has a responsibility to ensure that only authentic Finding Devices are sending reports to the Crowdsourced Network, and this should occur via an authenticated and encrypted channel. This will help prevent malicious actors from interfering with location reporting services.

- Second, the Crowdsourced Network has a responsibility to ensure that only authorized Owner Devices are able to download location reports, and this should occur via an authenticated and encrypted channel. This will prevent malicious actors from unauthorized access of location data.

- Third, the Crowdsourced Network must follow basic security principles, such as
  - Storing location reports in an encrypted manner
  - Limiting location report data storage to 7 days or less

  *(The benefits of this requirement are self explanatory.)*

- Fourth, the Crowdsourced Network must validate that the accessory registered to an owner is valid.  This wil prevent malicious actors from leveraging counterfeit accessories.

- Fifth, users should should be able to opt-out of their devices participating in the Crowdsourced Network.

## Existing Protocols





TODO list out all existing BLE tags like samsung etc.
- (Apple Airtags) https://www.apple.com/airtag/
TODO: Airtags, BlindMy



# Conventions and Definitions

{::boilerplate bcp14-tagged}

Section 1.2 of {{I-D.detecting-unwanted-location-trackers}} provides
definitions of the various system components.



Accessory (ACC): This is the device which will be tracked. It is assumed to lack direct internet access and GPS, but will possess Bluetooth Low Energy capabilities, which it uses to send advertisement messages. The accessory protocol is defined in {{DultDoc3}}.

Advertisement: This is the message that is sent over the BLE Protocol from the Accessory

Crowdsourced Network (CN): This is the network that provides the location reporting upload and download services for Owner Devices and Dinder Devices.

Finder Device (FD): This is a device that is a non-owner device that contributes information about an accessory to the crowdsourced network.

Owner Device (OD): This is the device which owns the accessory, and to which it is paired. There can be multiple owner devices, however, the security of that implementation is outside of the scope of this document.

# Protocol Overview

## High Level Protocol


{{fig-protocol-overview}} provides an overall view of the protocol.

In this protocol, the Accessory communicates to Finder Devices or `FDs`(such as phones) solely via Bluetooth, and the `FDs` communicate to a centralized service on the Crowdsourced Network `CN`. Only during the setup phase is the Owner Device `OD` able to act as a relay between the Accessory `ACC` and the Crowdsourced Network `CN`. In this implementation, the `CN` is able to act as a verifier and signer by leveraging Blind Signatures, which allows the `OD` to obtain a signature from the signer `CN` without revealing the input to the `CN`.

~~~~

                              ╭――――――――――――――――――╮
                              │        o         │
                              │ ╭──────────────╮ │
                              │ │              │ │
                              │ │              │ │                        .-~~~-.
                              │ │              │ │                .- ~ ~-(       )_ _
    o  o                      │ │              │ │               /                     ~ -.
 o        o                   │ │              │ │              |                           \
o          o     ------->     │ │              │ │   ------->    \                         .'
o          o                  │ │              │ │                 ~- . _____________ . -~
 o        o                   │ │              │ │
    o  o                      │ │              │ │
                              │ │              │ │
                              │ ╰──────────────╯ │
                              │       (_)        │
                              ╰――――――――――――――――――╯



  Accessory         BLE           Finder Device      Location            CN Server
               Advertisement                          Upload



~~~~
{: #fig-protocol-overview title="Protocol Overview"}


In this implementation, there are 4 stages that will be outlined, taking into account elements from both {{BlindMy}} and {{GMCKV21}}.  These stages are as follows:

1) __Initial Pairing / Accessory Setup__

In this phase, the Accessory `ACC` is paired with the Owner Device `OD`, and verified as authentic with the Crowdsourced Network `CN`

2) __Accessory in Nearby Owner Mode__

In this phase, the Accessory `ACC` is within Bluetooth range of the Owner Device `OD`. In this phase, Finder Devices `FDs` SHALL NOT generate location reports to send to the Crownsourced Network `CN`. The Accessory SHALL behave as defined in {{DultDoc3}}.

3) __Accessory in Separated (Lost) Mode__

In this phase, the Accessory `ACC` is not within Bluetooth raange fo the Owner Device `OD`, therefore, the accessory must generate "lost" messages to be received by Finder Devices `FD`, as described in {{DultDoc3}}.

4) __Finder Device creates a location report__

Finder Device `FD` receives a Bluetooth packet, and uploads a location report to the Crowdsourced Network `CN` if and only if it is confirmed to be a valid location report.

*(Should this be confirmed by the FD, or the CN? or Both?)

5) __Owner Device queries the Crowdsourced Network__

Owner Device `OD` queries the Crowdsourced Network `CN` for the encrypted location report.


## General Protocol Infrastructure Properties

Relying on {{BlindMy}}, we define the following constraints:

- There exists an agreed upon elliptic curve group with a generator,
a secure Message Authentication Algorithm, and a hashing
function *H*.

- `CN` knows a key pair `(K`<sub>S</sub>,`P`<sub>S</sub>`)`, where the public key
`P`<sub>S</sub> is known to all participants.

- `CN` has a private symmetric encryption key K<sub>SERIAL</sub>.

- `CN` maintains a database of registered serial values D<sub>SERIAL</sub>

-  Each Accessory `ACC`<sub>i</sub> contains a unique serial number and tag (`Serial`<sub>i</sub>, `T`<sub>i</sub>)

- All parties have a synchronized clock and the ability to represent the current day (or another arbitrary timestamp) as an integer

- A parameter *N* is defined by the protocol that represents the number of encryption keys produced during the pairing algorithm.

## Partial Blind Signature Scheme

In order to verify the parties involved in the protocol, we rely on a partial blind signature scheme as defined in {{BlindMy}} and {{Okamoto}}:

| Partial Blind Signature Scheme   |
|:------------------------------:|
| * There exists a probabilistic polynomial time (PPT) algorithm called *KeyGen* that takes a security parameter as input and outputs a key pair containing a secret key and public key (`s`<sub>k</sub>,`p`<sub>k</sub>).         |
| * There exists two interactive PPT algorithms called *Signer* and *User* that compute a signature `σ` of a message `m` and plaintext auxiliary information `info`. The *Signer* begins with (`s`<sub>k</sub>,`p`<sub>k</sub>,`info`), and the *User* starts with (`p`<sub>k</sub>,`info`, `m`). After interacting, the *User* outputs (`m`, `σ` ) if the protocol succeeds and    `⊥` if it fails.            |
| * There exists a PPT algorithm called *Verify* that receives  (`p`<sub>k</sub>,`info`, `m`,`σ` ) and outputs `accept` when the signature is valid, and `reject` if it is not.           |



## Initial Pairing / Accessory Setup

During the pairing process, the Accessory `ACC` pairs with the Owner Device `OD` over Bluetooth. In this process, the `ACC` and `OD` must generate cryptographically secure keys that will allow for the `OD` to decrypt the `ACC` location reports.

### Authenticity Verification

Upon the initial pairing of the the `ACC` and `OD`, before the key generation process, the `OD` must facilitate communication with the `CN` to verify the authenticity of the `ACC`. In {{GMCKV21}}, it is recommended that the `ACC` has a private key material fused into the chip at manufacture time.

In {{BlindMy}}, the principal of *Serial Unforgeability* is introduced, which recommends that the serial numbers are assigned as an unforgeable MAC that is computed with a secret key only known to the server.


(1)`OD` extracts the values (`Serial`<sub>i</sub>, `T`<sub>i</sub>) from `ACC`, where

`T`<sub>i</sub> = MAC<sub>KSERIAL</sub>(`Serial`<sub>i</sub>)

(2) `OD` transmits these values to `CN`.

(3) `CN` independently verifies `T`<sub>i</sub>

(4) To prevent re-enrollment of a tag, `CN` also checks `Serial`<sub>i</sub> ∉ `D`<sub>SERIAL</sub>

(5) If (3) or (4) fails, `CN` aborts. Otherwise, `CN` adds `Serial`<sub>i</sub> to `D`<sub>SERIAL</sub>

(6) `CN` sends public parameters for generating *N* partial blind signatures to `OD`. These parameters are defined in the next section.


### Key Generation and Signing with Partial Blind Signatures

In order for `OD` to have *N* keys signed by partial blind signatures, the scheme described in {{BlindMy}} must be implemented.

For convenience, it is summarized below:

(1) `CN` generates the public parameters `u, d, s, a, b` where `u, d, s` represent the Signer State and `a, b` represents the Signature Parameters.

They are generated by the following code given in {{BlindMy}} *pbs_dh.py*:

~~~
def raw_signer_gen_params(hashfunc, privkey, info):
    u = randbelow(q)
    d = randbelow(q)
    s = randbelow(q)

    z = hashToPoint(info, hashfunc)
    a = pow(g, u, p)
    b = (pow(g,s,p) * pow(z,d,p)) % p

    return (u, d, s, a, b)
~~~

(2) After receiving the public parameters required from `CN`, `OD` generates N elliptic-curve keypairs, as shown in the code from {{BlindMy}} *client.py*:

~~~
def gen_keys(privateseed: str, numkeys: int) -> List[str]:
    print(f"Generating {numkeys} keys")
    pubkeys = []
    for i in tqdm(range(numkeys)):
        pkey = hashToInt(privateseed + str(i), P224, sha256)
        pubkey = pkey * P224.G
        pubkeyx = '{:056x}'.format(pubkey.x)
        pubkeys.append(pubkeyx)
    return pubkeys
~~~

(3) `OD` generates signing requests for each public key in *N*,using params *a* and *b*, the hashing function *H*, and the auxiliary info for each signing request set as the integer representation of the current day and the *N − 1* following days. These requests are then sent to `CN`. Notice that `OD` performs blinding on each public key before making the request.

This is shown in the code from {{BlindMy}} *pbs_dh.py*:

~~~
    #sigparams - SignatureParams object, comes from generate_params function above
    #msg - string or bytes object representing the message being signed
    #info - string representing the plaintext auxiliary information to go along with the blinded signature
    def generate_signature_request(self, sigparams, msg, info):
        t1, t2, t3, t4, e = raw_user_blind(self.hashfunc, self.pubkey, msg, info, sigparams.a, sigparams.b)
        return UserState(t1, t2, t3, t4), e
~~~

(4) `CN` verifies the timestamp infomation and aborts if not in a valid range.


(5) `CN` signs each each public key with a blind signature and sends the *N* blind signatures to `OD`.

(6) `OD` unblinds the signatures and stores *N* pairs of the form `(KeyPair, UnblindedSignature)` and transfers the *N* public keys to the accessory `ACC`, ordered by timestamp.


## Accessory Behavior

As part of the setup phase (described in {{DultDoc3}}) the Accessory `ACC` and
Owner Device `OD` are paired, establishing a shared key `S`<sub>K</sub>
which is known to both the accessory and the owning device.
The rest of the protocol proceeds as follows:

### Accessory in Nearby Owner Mode

After pairing, when the Accessory `ACC` is in Bluetooth range of `OD`, it will follow the protocol as decribed in {{DultDoc3}}.

### Accessory in Separated (Lost) Mode

After pairing, when the Accessory `ACC` no longer in the Bluetooth range of `OD`, it will follow the protocol as decribed below:, which should correspond to the behavior outlined in {{DultDoc3}}:

`ACC` periodically sends out an Advertisement which contains
an ephemeral public key `Y`<sub>i</sub> where `i` is the epoch the key is valid
for.  As defined by our protocol, this epoch is a 24 hour period. `Y`<sub>i</sub> and its corresponding private key
`X`<sub>i</sub> are generated in a deterministic fashion from `S`<sub>K</sub> and the epoch
`i` (conceptually as `X`<sub>i</sub> = `PRF`(`S`<sub>K</sub>, `i`)).

The full payload format of the Advertisement is defined in {{DultDoc3}}.


## Finder Device creates a Location Report

The Finder Device `FD` receives the advertisement via Bluetooth. `FD` should have a mechanism by which to authenticate that this is a valid public key with `CN`. *

In order to report an accessory's location at time `i`, `FD` extracts the elliptic curve public key from the advertisement, and records it own location data, a timestamp, and a confidence value as described in {{Heinrich}}.

`FD` performs ECDH with the public key  `Y`<sub>i</sub> and derives a shared symmetric key with ECIES.

It then encrypts the location data using the symmetric key, and creates a payload as described in {{Heinrich}} and {{WhoTracks}}. It transmits a payload to `CN` with the encrypted packet
`( E(Y`<sub>i</sub>,`location), Y`<sub>i</sub>`)`.

`FD` uploads the encrypted payload, the public ephemeral key, a timestamp, and the hash of the public key to `CN`, who records it in a key-value store with the key as the hash of the `ACC` public key.

\* Some ideas include

- `FD` can request a signature itself of the key - but would it be the same?
- `ACC` can send the public key and the signature to `FD` so `FD` can verify the signature
- `CN` has the option of discarding the packet if the hash of the public key is unknown, since the server has already signed all of the keys in the past - but is it reasonable to save/store these?


## Owner Device queries the Crowdsourced Network

Following the sequence described in {{BlindMy}}, valid `OD`s can retrieve the location of a paired `ACC`.  In order to query the location of `ACC`, the `OD` can sends a request to the `CN`. The `CN` must verify that each location requested has been blind-signed and is within a valid date range This prevents adversaries from storing many old blind-signed keys and rotating them quickly in order to avoid detection.

This is achieved in the following manner:

(1) In order to locate an accessory at time `i`, the `OD` uses `SK` to
compute the hash of the desired public key `Y`<sub>i</sub>. The owner `OD` sends the unblinded, signed public key hashes to `CN` corresponding to the date range they are interested in retrieving, along with the corresponding info fields for each one.


(2) `CN` confirms the auxiliary information on each signature is reasonable (e.g. falls within the last 7 days) and that the signature of each hash verifies correctly.


(3) `CN` retrieves any report matching the hashes supplied `Y`<sub>i</sub> and returns them to the `OD`, including the public key hash, the ephemeral public key, and encrypted payload, minus any reports where the timestamp does not match the correct time period from the info field (this would indicate that they key was being used outside of its intended validity period).

(4) For each report, `OD` finds the public key for the report by its hash, and uses the corresponding private key alongside the ephemeral public key included in the report to decrypt the encrypted payload and recover the timestamp, confidence, and location data associated with the report.




# Security Considerations

TODO Security - as described in {{DultDoc4}}?


# Privacy Considerations

TODO Privacy - as described in {{DultDoc4}}?


# IANA Considerations

This document has no IANA actions.


--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.


