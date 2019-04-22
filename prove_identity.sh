#!/usr/bin/env bash

#///////////////////////////////////////////////////////#
#                                                       #
#                     Configuration                     #
#                                                       #
#///////////////////////////////////////////////////////#

#Change these
ETH_FROM="" 
ETH_KEYSTORE=""
ETH_PASSWORD=""
KEYBASE_USERNAME=""
FEED_ADDR=""

#Leave these alone
MEDIANIZER_ADDR="0x729D19f657BD0614b4985Cf1D82531c67569197B"
ETH_RPC_URL="https://mainnet.infura.io/v3/7e7589fbfb8e4237b6ad945825a1d791"

FEED_ADDR=$(seth --to-address $FEED_ADDR)
ETH_FROM=$(seth --to-address $ETH_FROM)
MSG="$FEED_ADDR - $KEYBASE_USERNAME - $(date +"%s")"
#sig="" 

#///////////////////////////////////////////////////////#
#                                                       #
#                       Functions                       #
#                                                       #
#///////////////////////////////////////////////////////#

#gets keccak-256 hash of 1 or more input arguments
keccak256Hash () {
	local _inputs
	for arg in "$@"; do
		_inputs+="$arg"
	done
	seth keccak "$_inputs"
}

#sign message
signMessage () {
	local _data
	for arg in "$@"; do
		_data+="$arg"
	done
    ethsign message --from "$ETH_FROM" --key-store "$ETH_KEYSTORE" --passphrase-file "$ETH_PASSWORD" --data "$_data"
}

#generate oracle identity proof
generateIdentityProof () {
	#verify Oracle address
	echo "verifying feed address is whitelisted..."
	id=$(seth --to-dec "$(seth call --rpc-url $ETH_RPC_URL $MEDIANIZER_ADDR "indexes(address)(bytes12)" $FEED_ADDR)")
	if ! [[ "$id" -gt 0 ]]; then
		echo "Error - Feed ($FEED_ADDR) is not whitelisted"
		exit 1
	fi

	#verify feed ownership
	echo "verifying ownership of feed..."
	owner=$(seth --to-address "$(seth call --rpc-url $ETH_RPC_URL $FEED_ADDR "owner()(address)")")
	if ! [[ $ETH_FROM == *"$owner" ]]; then
		echo "Error - Owner of Feed ($FEED_ADDR) is $owner, not $ETH_FROM"
		exit 1
	fi

	#get message hash
	echo "hashing message..."
	hash=$(keccak256Hash "0x" "$MSG")
	if [[ ! "$hash" =~ ^(0x){1}[0-9a-fA-F]{64}$ ]]; then
		echo "Error - Failed to generate valid hash"
		exit 1
	fi

	#sign message hash
	echo "signing message..."
	sig=$(signMessage "$hash")
	if [[ ! "$sig" =~ ^(0x){1}[0-9a-f]{130}$ ]]; then
		echo "Error - Failed to generate valid signature"
		exit 1
	fi

	#print avatar
	echo ""
	echo "SUCCESS!"
	echo ""
	echo "Please paste the following into your Keybase bio:"
	echo "Message: $MSG"
	echo "Signature: $sig"
	echo ""
}

#verifies oracle identity proof
verifyIdentityProof () {
	sig="$1"
	msg="$2"

	#get feed addr from msg and verify feed addr is whitelisted
	echo "Verifying Feed address is whitelisted..."
	feedAddr=$(echo "$msg" | awk '{print $1;}')
	echo "feedAddr = $feedAddr"
	index=$(seth --to-dec "$(seth call --rpc-url "$ETH_RPC_URL" "$MEDIANIZER_ADDR" "indexes(address)(bytes12)" "$feedAddr")")
	if ! [[ $index -gt 0 ]]; then
		echo "Error - Feed ($feedAddr) is not whitelisted"
		echo "FAILED!"
		exit 1
	fi

	#get owner of feed
	echo "Querying owner of Feed..."
	feedOwner=$(seth --to-address "$(seth --rpc-url $ETH_RPC_URL call "$feedAddr" "owner()(address)")")
	if ! [[ $feedOwner =~ ^(0x){1}[0-9a-fA-F]{40}$ ]]; then
		echo "Error - failed to retrieve valid feed owner"
		echo "FAILED!"
		exit 1
	fi

	#convert message to hash
	hash=$(keccak256Hash "0x" "$msg")
	if [[ ! "$hash" =~ ^(0x){1}[0-9a-fA-F]{64}$ ]]; then
		echo "Error - Failed to generate valid hash"
		echo "FAILED!"
		exit 1
	fi

	#get signer of signature
	echo "Recovering signer from signature and comparing to feed owner"
	signer=$(ethsign recover --data "$hash" --sig "$sig")
	signer=$(seth --to-address "$signer")
	#verify signer is feed owner
	if ! [[ "$signer" == "$feedOwner" ]]; then
		echo "Error - signer ($signer) does not match up with feed owner ($feedOwner)"
		echo "FAILED!"
		exit 1
	fi

	echo ""
	echo "SUCCESS!"
	echo ""
	echo "Signer is an Oracle"
}

#///////////////////////////////////////////////////////#
#                                                       #
#                       Execution                       #
#                                                       #
#///////////////////////////////////////////////////////#

generateIdentityProof
verifyIdentityProof "$sig" "$MSG"