# oracle-identity-verifier
Generates and verifies identity proofs for Oracles

## Generate Identity Proof:

```source prove_identity.sh; generate $ETH_FROM $ETH_KEYSTORE $ETH_PASSWORD $FEED_ADDR $KEYBASE_USERNAME```

where:

ETH_FROM = the owner of the Oracle Feed (format 0x#####)\
ETH_KEYSTORE = path to the directory containing the keystore file for ETH_FROM\
ETH_PASSWORD = path to the file containing the password to unlock the keystore file for ETH_FROM\
FEED_ADDR = public of your feed (format: 0x######)\
KEYBASE_USERNAME = your username on keybase

## Verify Identity Proof:

```source prove_identity.sh; verify $SIG $MSG```

where:

SIG = the signed message signature\
MSG = the message that was signed