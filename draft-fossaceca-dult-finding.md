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

Lightweight location tracking tags are in wide use to allow users to
locate items. These tags function as a component of a crowdsourced
tracking network in which devices belonging to other network users
(e.g., phones) report on the location of tags they have seen.
At a high level, this works as follows:

- Tags ("accessories") broadcast an advertisement payload containing
  accessory-specific information. The payload also indicates whether
  the accessory is separated from its owner and thus potentially lost.

- Devices belonging to other users ("non-owner devices")
  observe those payloads and if the payload is in a separated
  mode, reports its location to some central service.

- The owner queries the central service for the location of their
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

- It is not possible for accessories that do not adhere to the protocol to use crowdsource network protocol.

- It is not possible for unverified accessories to use the crowdsource network protocol.

This document defines a cryptographic reporting and finding protocol
which is intended to minimize these privacy risks. It is intended
to work in concert with the requirements defined in
{{!I-D.detecting-unwanted-location-trackers}}, which facilitate
detection of unwanted tracking tags. This protocol design is based on existing academic research surrounding the security and privacy of bluetooth location tracking accessories on the market today.



TODO list out all existing BLE tags like samsung etc.
- (Apple Airtags) https://www.apple.com/airtag/
TODO: Airtags, BlindMy

# Motivations





# Conventions and Definitions

{::boilerplate bcp14-tagged}

Section 1.2 of {{I-D.detecting-unwanted-location-trackers}} provides
definitions of the various system components.

Accessory: This is the device which will be tracked. It is assumed to lack direct internet access and GPS, but will possess Bluetooth Low Energy capabilities, which it uses to send advertisement messages.

Advertisement: This is the message that is sent over the BLE Protocol


# Protocol Overview

~~~~
[TODO: Add Figure]
~~~~
{: #fig-protocol-overview title="Protocol Overview"}

{{fig-protocol-overview}} provides an overall view of the protocol.

In this protocol, the accessory communicates to networked devices (such as phones) solely via Bluetooth  (TODO, should we generalize this for UWB), while networked devices communicate to the centralized service. Only during the setup phase is the owning device able to act as a relay between the accessory and the central service.

We assume that during the setup phase, the communication channel between the owning device and the central service is authenticated and end-to-end encrypted.

In this implementation,

- All parties agree on an elliptic curve group with a generator,
a secure Message Authentication Algorithm, and a hashing
function H.


TODO - unsure if the database of used/ unused serial values in a central is really that secure, or how it can be abused?

- The server knows a key pair (KS , PS ), where the public key
PS is known to all parties. In addition, the server has a private
symmetric encryption key Kserial. Finally, the server also
maintains a database of used serial values DSerial.



- Each Tracking Device TDj has been initialized with a unique
serial number and a tag constructed by a secure Message
Authentication Code (MAC) algorithm applied to the serial,
so that each TDj has in its internal storage:

(Serialj, Tj) = MACkserial(Serialj)


During the setup phase, the accessory and owning device leverage partial blind signatures to authenticate the accessory with the central service.



As part of the setup phase (described above) the accessory and
owning device are paired, establishing a shared key `SK`
which is known to both the accessory and the owning device.
The rest of the protocol proceeds as follows.

* The accessory periodically sends out an advertisement which contains
an ephemeral public key `Y_i` where `i` is the epoch the key is valid
for (e.g., a one hour window). `Y_i` and its corresponding private key
`X_i` are generated in a deterministic fashion from `SK` and the epoch
`i` (conceptually as a `X_i = PRF(SK, i)`).

* In order to report an accessory's location at time `i` a non-owning
device encrypts it under `Y_i` and transmits the pair
`( E(Y_i, location), Y_i )` to the central service.

* In order to locate an accessory at time `i`, the owner uses `SK` to
compute `(X_i, Y_i)` and then sends `Y_i` to the central service.
The central service responds with all the reports it has for `Y_i`,
and the owner decrypts them with `X_i`.





# Security Considerations

TODO Security


# IANA Considerations

This document has no IANA actions.


--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.


