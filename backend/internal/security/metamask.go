package security

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"strings"
)

func VerifyMetaMaskSignature(walletAddress, message, signature string) (bool, error) {
	signature = strings.TrimPrefix(signature, "0x")
	walletAddress = strings.TrimPrefix(walletAddress, "0x")

	sigByte, err := hex.DecodeString(signature)
	if err != nil {
		return false, err
	}

	if len(sigByte) != 65 {
		return false, fmt.Errorf("invalid signgature")
	}

	sigByte[64] = sigByte[64] - 27
	msgBytes := []byte(message)
	prefix := []byte(fmt.Sprintf("\x19Ethereum Signed Message:\n%d", len(msgBytes)))
	msgHash := crypto.Keccak256Hash(append(prefix, msgBytes...))

	pubicKeyBytes, err := crypto.Ecrecover(msgHash.Bytes(), sigByte)
	if err != nil {
		return false, err
	}

	publicKey, err := crypto.UnmarshalPubkey(pubicKeyBytes)
	if err != nil {
		return false, err
	}

	recoverAddress := crypto.PubkeyToAddress(*publicKey)

	provideAddress := common.HexToAddress(walletAddress)
	return bytes.Equal(recoverAddress.Bytes(), provideAddress.Bytes()), nil
}
