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

1. Nobody other than the owner of an accessory would be able to learn
anything about the location of a given accessory.

1. It is possible to detect when an accessory is being used to track
you.

This document defines a cryptographic reporting and finding protocol
which is intended to minimize these privacy risks. It is intended
to work in concert with the requirements defined in
{{!I-D.detecting-unwanted-location-trackers}}, which facilitate
detection of unwanted tracking tags. This protocol design is based
[TODO: Airtags, BlindMy]

# Conventions and Definitions

{::boilerplate bcp14-tagged}

Section 1.2 of {{I-D.detecting-unwanted-location-trackers}} provides
definitions of the various system components.


# Protocol Overview

~~~~
[TODO: Add Figure]
~~~~
{: #protocol-overview title="Protocol Overview"}

{{protocol-overview}} provides an overall view of the protocol.

As part of the setup phase (not shown) the accessory and
owning device are paired, establishing a shared key `SK`
which is known to both the accessory and the owning device.
The rest of the protocol proceeeds as follows.

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
