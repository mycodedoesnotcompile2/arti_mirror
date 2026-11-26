# dirauth auth part - data model

## Entity relationship diagram

```
 router_id_tuple_seen
 [any seen together in a routerdesc]
   |
   |
   ?
 router
 [id tuple doesn't overlap with any other]
   |
   |                 [see votes and consensuses, below]
   |                      *
   |                      *
   |                 routerdesc_sha1
   |                 [just the hash, we may not have the document]
   |                      |
   |                      |------------- [is it known-bad?]
   |                      |--- X auth -- [do they have it?]
   |                      |
   |                      ?
   |---------------? routerdesc
   |                 [verified, parseable, reasonably timely, routerdesc document]
   |                 [we retain only the most recent by `published`]
   |
   |---------------? uptime stats
   |                 [from stability scanner]
   |


 (voting-period)
 [actually the valid-from]
   |
   |
   |-----[consensus_recent]
   |     [implies is fully verified, with enough signatories]
   |                 |
   |                 |
   |                 ?
   |-------* consensus
   |         [bare, unsigned, consensus document body]
   |         [don't record a consensus in db until we have at least one valid sig on it]
   |         [retain: the majority-consensus]
   |         [retain: for anything more recent, anything with at least one valid cert]
   |         [retain: anything with our signature, for the past day?]
   |           *
   |           |
   |           |---* (router, routerdesc-hash)
   |           |
   |           |---* (router, microdesc) (see below)
   |           |     [microdescs that we generated, only]
   |           |
   |           X auth -|
   |                   |-? signature
   |                   |   [valid signature, verified using corresponding authcert]
   |                   |   [at least one for each entry in consensuses-all]
   |                   |          |
   |                   |          |----X auth2 --- [do they have it?]
                                  |
                                  |*---- authcert (see below)


  (auth)
  [set of known auths is from configuration]
   |
   |    signature (see above)
   |      *
   |      |
   |--* authcert
   |    [parsed, verified, from recognised authority, authcert doc]
   |    [retained only when it validity period includes relevant times]
   |
   |--? vote
   |    [vote for next period]
   |    [signed, verified vote document]
   |      |
   |      |---* (router, routerdesc-hash)
   |      |
   |      |--- X method --? (router, microdesc) (see below)



  consensus  *-------------------|
  (see above)                    |
                                 |
  vote ---------X cmethod *------|
  (see above)                    |
                                 X router --- microdesc
                                              [only microdescs we generated]
```

Notes & notation:

 * Not every node is a table or column.
   We sometimes write `(node)` for a node that's not a table.

 * `A -- X B -- C` means one `C` for each `(A, B)`

## Terminology, timing

 * "next" consensus: the one we are voting on
 * "current" consensus: fresh according to its lifetime
 * "previous" consensus: the one before that

## Concrete representation - basics

We reuse the following dirmirror tables:

 * `store`: content-addressable document store
 * `authority_key_certificate`, as `authcert`
   but maybe our invariant is different?  Invariant isn't documented in `schema_v1.sql`.

## Tables

Every table as a `rowid INTEGER PRIMARY KEY AUTOINCREMENT`, not shown.
Therefore the logical primary key (which might be multiple columns is `UNIQUE`.

Types are shown informally, often in a Rust-like syntax, which is
intended to show the representation (usually, in a `TEXT` field).

Fields are to be `NOT NULL` unless otherwise stated.

Other properties are also shown informally.

### Schema sketch in SQL-ish syntax

```sql
CREATE TABLE router_id_tuple_seen (
    kp_relay_id_ed              Ed25519Public  INDEX     } UNIQUE
    kp_relay_id_rsa_sha1        Fingerprint    INDEX     }
    last_seen                   Timestamp
    -- Expires based only on `last_seen`
)

-- Automatically maintained based on router_id_tuple_seen.
-- Contains precisely rows where both ids are unique within router_id_tuple_seen.
CREATE TABLE router (
    -- copy the key ids here, to avoid additional indirection to find a router's identities
    kp_relay_id_ed              Ed25519Public
    kp_relay_id_rsa_sha1        Fingerprint
    UNIQUE (kp_relay_id_ed, kp_relay_id_rsa_sha1)  REFERENCES router_id_tuple_seen
)

CREATE TABLE routerdesc_by_sha1 (
    routerdesc_sha1        B16U                UNIQUE
    timestamp              Timestamp
    status                 Ok/Absent/Known-Bad
    routerdesc_rowid       NULL iff not Ok
    -- Either `published`, or if we don't have the document,
    -- the earliest `valid_from` of a netstatus that we ever inserted that mentioned it.
    -- (Logically, that `valid_from` must be after the routerdesc's `published`,
    -- according to the peer authority that signed the netstatus.
    -- So we will expire the routerdesc_by_sha1 entry eventually, but not too early.)
)

CREATE TABLE routerdesc (
    router_rowid                               UNIQUE
    routerdesc_by_sha1_rowid                   UNIQUE
    docid
    published              Timestamp
    -- Validly signed and timely.
    -- We only retain the most recent for any router.
    -- We only download these.
)
CREATE TABLE routerdesc_peerstatus (
    routerdesc_sha1         B16U               } UNIQUE
    peer                    Peer               }
    status                  Ok/Absent/Known-Bad/Retry?
)
CREATE TABLE router_uptime (
    router_rowid                               UNIQUE
    -- data fields TBD
)

CREATE TABLE consensus (
    -- no logical primary key, so no UNIQUE
    valid_from             Timestamp
    docid                  -- just the body, without any signatures
    CHECK *at least one* consensus_signature
    -- So *might not be a validly signed consensus*!
    -- Retention policy: see "Entity relationship diagram" above.
    -- We both publish/upload and download these.
)
CREATE TABLE consensus_recent(
    -- no rowid INTEGER PRIMARY KEY AUTOINCREMENT in this table
    consensus_rowid
    CHECK zero or one rows
    CHECK enough corresponding rows in consensus_signature
)
CREATE TABLE consensus_signature (
    consensus_rowid                            } UNIQUE
    peer                   PeerAuthority       }
    docid                  -- the document is just the signature text
    authority_key_certificate_rowid
    -- Validly signed by this one authority, with a valid authcert,
    -- and everything is timely throughout the consensus's validity period.
    -- We both publish/upload and download these.
)

-- There is no explicit table linking a consensus or vote to its routerdescs.
-- Instead, whenever we insert a netstatus into the database,
-- we also add rows to routerdesc_by_sha1 for everything that that netstatus mentions.
-- That will cause us to start to try to exchange those routerdescs,
-- which we will continue to do so long as we regard them as valid
-- and not superseded or out of date.

CREATE TABLE consensus_signature_peerstatus (
    consensus_signature_rowid                  } UNIQUE
    peer_possessing           Peer             }
    status                    Ok/Absent/Known-Bad/Retry?
)

CREATE TABLE vote (
    valid_from                                 } UNIQUE
    peer                    PeerAuthority      }
    docid
    -- Entire vote, from a peer, validly signed,
    -- and timely for the entire period between published and valid-until.
    -- We both publish/upload and download these.
)
CREATE TABLE vote_peerstatus (
    vote_rowid                                } UNIQUE
    peer_possessing         Peer              }
    status                  Ok/Absent/Known-Bad/Retry?
)

CREATE TABLE microdesc (
    consensus_rowid        } CHECK exactly    } UNIQUE
    vote_rowid             }  one NOT NULL    }
    router_rowid                              }
    cmethod                ConsensusMethod    }
    microdesc_sha256
    docid
    -- Only contains microdescs that were part of votes we generated.
    -- for those votes contains all microdescs, which we keep trying
    -- to upload so long as they form part of any consensus in consensus.
    -- We don't download these.
)
CREATE TABLE microdesc_peerstatus (
    microdesc_rowid                           } UNIQUE
    peer_possessing         Peer              }
    status                  Ok/Absent/Known-Bad/Retry?
)
```

## Document validity and timeliness checks

We do not store documents in the database that we don't have at least
one good signature for, from a relevant signer.

 * routerdescs are self signed
 * authcerts are signed by KP_auth_id
 * votes come with their authcert so we can verify with KP_auth_sign
 * microdescs are not signed (but we only store ones we generate ourselves)
 * consensus documents do not *contain* their authcerts.
   We deal with consensus documents in two situations:
     - We generate our own consensus, and upload it (with our
       signature, and others we have acquired) to our pet mirror.
     - We try to download current consensus/signatures from all our peers.
       Each such signature might need an authcert we don't have
       before storing the consensus we try to get at least the authcert
       from the peer we got the consensus from, and if that fails
       (or doesn't verify) we call the download a failure and discard the document.
       We only need peers' consensuses to determine our own view of the agreed
       consensus for various ancillary purposes
       (and we also use it to help drive routerdesc exchange).

Documents in the database generally have had some timeliness checks.

"Reasonably timely" means not too far from the future.
Obviously it might mean from far in the past, but such things will be expired.

## Peers

For many documents, we track whether we think each of our peers has is.
This is used to determine if we want to try to upload it there.

Each peer is identified one of the following:

 * Us
 * KP_auth_id_rsa (another authority)
 * some future KP_auth_id_??? (we consider different id key algo as different authority)
 * one of our pet mirrors.  For now we have one such

This is represented as a Rust enum `Peer`
which appears as a SQL value (`peer` columns).

There is also `PeerAuthority`, which is a `Peer` that is an actual authority,
possibly including ourselves.

## Document peer status

For various documents, we record whether we think each peer has it.
This is useful both for downloading and uploading (but the information
recorded, and the algorithms, might vary between upload and download).

Example scenarios:

 * We know that the peer has the document.  Perhaps because we managed
   to download it from them, or upload it to them.

 * We tried to download from the peer and they told us they didn't have it.
   We might want to try later, but probably not until we have some
   particular reason to think they might have it.
   The document might no longer exist amongst any of the authorities.

 * We downloaded it; the hash was correct but the document was wrong
   in parts covered by the hash.  This document is busted and we
   should never try again.

 * We have the document ourselves but we haven't tried to send it to
   this peer yet.

 * We offered the document to the peer and it told us it hated it.

 * When we talked to the peer, our transaction failed in a
   way that seems to possibly implicate the document.
   Maybe the peer is broken or buggy.
   We should perhaps try other documents at the same peer?

 * We weren't able to talk to the peer at all, or maybe we haven't tried.

Precise details of the information recorded, and retry algorithms, are
TBD.
