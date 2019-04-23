#!/usr/bin/env bash

#///////////////////////////////////////////////////////#
#                                                       #
#                     Configuration                     #
#                                                       #
#///////////////////////////////////////////////////////#

MEDIANIZER_ADDR="0x729D19f657BD0614b4985Cf1D82531c67569197B"
ETH_RPC_URL="https://mainnet.infura.io/v3/7e7589fbfb8e4237b6ad945825a1d791"

#///////////////////////////////////////////////////////#
#                                                       #
#                       Execution                       #
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
generate () {
	ETH_FROM="$1"
	ETH_KEYSTORE="$2"
	ETH_PASSWORD="$3"
	FEED_ADDR="$4"
	KEYBASE_USERNAME="$5"

	FEED_ADDR=$(seth --to-address "$FEED_ADDR")
	ETH_FROM=$(seth --to-address "$ETH_FROM")

	time=$(date +"%s")
	keybase_username_hex=$(seth --from-ascii "$KEYBASE_USERNAME")
	MSG="$FEED_ADDR${keybase_username_hex:2}$time"
	if ! [[ "$MSG" =~ ^(0x){1}[0-9a-fA-F]+$ ]]; then
		echo "Error - Generated invalid message $MSG"
		exit 1
	fi

	#verify Oracle address
	echo "Verifying feed address is whitelisted..."
	id=$(seth --to-dec "$(seth call --rpc-url $ETH_RPC_URL $MEDIANIZER_ADDR "indexes(address)(bytes12)" "$FEED_ADDR")")
	if ! [[ "$id" -gt 0 ]]; then
		echo "Error - Feed ($FEED_ADDR) is not whitelisted"
		exit 1
	fi

	#verify feed ownership
	echo "Verifying ownership of feed..."
	owner=$(seth --to-address "$(seth call --rpc-url $ETH_RPC_URL "$FEED_ADDR" "owner()(address)")")
	if ! [[ $ETH_FROM == *"$owner" ]]; then
		echo "Error - Owner of Feed ($FEED_ADDR) is $owner, not $ETH_FROM"
		exit 1
	fi

	#get message hash
	echo "Hashing message..."
	hash=$(keccak256Hash "$MSG")
	if ! [[ "$hash" =~ ^(0x){1}[0-9a-fA-F]{64}$ ]]; then
		echo "Error - Failed to generate valid hash"
		exit 1
	fi

	#sign message hash
	echo "Signing message..."
	sig=$(signMessage "$hash")
	if ! [[ "$sig" =~ ^(0x){1}[0-9a-f]{130}$ ]]; then
		echo "Error - Failed to generate valid signature"
		exit 1
	fi

	prettyMsg="$FEED_ADDR-$KEYBASE_USERNAME-$time"

	#print avatar
	echo ""
	echo "SUCCESS!"
	echo ""
	echo "Please send the following to master_chief on Keybase:"
	echo "Msg: $prettyMsg"
	echo "Sig: $sig"
	echo ""

	echo "Verifying generated oracle proof..."
	verify "$sig" "$prettyMsg"
}

#verifies oracle identity proof
verify () {
	sig="$1"
	msg="$2"

	#get feed addr from msg and verify feed addr is whitelisted
	echo "Verifying Feed address is whitelisted..."
	feedAddr=$(echo "$msg" | awk -F - '{print $1;}')
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

	#parse message
	keybase_username=$(echo "$msg" | awk -F - '{print $2;}')
	keybase_username_hex=$(seth --from-ascii "$keybase_username")
	time=$(echo "$msg" | awk -F - '{print $3;}')
	msg="$feedAddr${keybase_username_hex:2}$time"


	#convert message to hash
	hash=$(keccak256Hash "$msg")
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