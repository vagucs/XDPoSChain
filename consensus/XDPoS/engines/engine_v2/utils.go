package engine_v2

import (
	"errors"
	"fmt"
	"io/fs"
	"math/big"
	"path/filepath"
	"strings"

	"github.com/XinFinOrg/XDPoSChain/accounts"
	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/consensus"
	"github.com/XinFinOrg/XDPoSChain/consensus/XDPoS/utils"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/crypto"
	"github.com/XinFinOrg/XDPoSChain/crypto/sha3"
	"github.com/XinFinOrg/XDPoSChain/log"
	"github.com/XinFinOrg/XDPoSChain/rlp"
	lru "github.com/hashicorp/golang-lru"
)

func sigHash(header *types.Header) (hash common.Hash) {
	hasher := sha3.NewKeccak256()

	err := rlp.Encode(hasher, []interface{}{
		header.ParentHash,
		header.UncleHash,
		header.Coinbase,
		header.Root,
		header.TxHash,
		header.ReceiptHash,
		header.Bloom,
		header.Difficulty,
		header.Number,
		header.GasLimit,
		header.GasUsed,
		header.Time,
		header.Extra,
		header.MixDigest,
		header.Nonce,
		header.Validators,
		header.Penalties,
	})
	if err != nil {
		log.Debug("Fail to encode", err)
	}
	hasher.Sum(hash[:0])
	return hash
}

func ecrecover(header *types.Header, sigcache *lru.ARCCache) (common.Address, error) {
	// If the signature's already cached, return that
	hash := header.Hash()
	if address, known := sigcache.Get(hash); known {
		return address.(common.Address), nil
	}

	// Recover the public key and the Ethereum address
	pubkey, err := crypto.Ecrecover(sigHash(header).Bytes(), header.Validator)
	if err != nil {
		return common.Address{}, err
	}
	var signer common.Address
	copy(signer[:], crypto.Keccak256(pubkey[1:])[12:])

	sigcache.Add(hash, signer)
	return signer, nil

}

// Get masternodes address from checkpoint Header. Only used for v1 last block
func decodeMasternodesFromHeaderExtra(checkpointHeader *types.Header) []common.Address {
	masternodes := make([]common.Address, (len(checkpointHeader.Extra)-utils.ExtraVanity-utils.ExtraSeal)/common.AddressLength)
	for i := 0; i < len(masternodes); i++ {
		copy(masternodes[i][:], checkpointHeader.Extra[utils.ExtraVanity+i*common.AddressLength:])
	}
	return masternodes
}

func UniqueSignatures(signatureSlice []types.Signature) ([]types.Signature, []types.Signature) {
	keys := make(map[string]bool)
	list := []types.Signature{}
	duplicates := []types.Signature{}
	for _, signature := range signatureSlice {
		hexOfSig := common.Bytes2Hex(signature)
		if _, value := keys[hexOfSig]; !value {
			keys[hexOfSig] = true
			list = append(list, signature)
		} else {
			duplicates = append(duplicates, signature)
		}
	}
	return list, duplicates
}

func (x *XDPoS_v2) signSignature(signingHash common.Hash) (types.Signature, error) {
	// Don't hold the signFn for the whole signing operation
	x.signLock.RLock()
	signer, signFn := x.signer, x.signFn
	x.signLock.RUnlock()

	signedHash, err := signFn(accounts.Account{Address: signer}, signingHash.Bytes())
	if err != nil {
		return nil, fmt.Errorf("Error %v while signing hash", err)
	}
	return signedHash, nil
}

func (x *XDPoS_v2) verifyMsgSignature(signedHashToBeVerified common.Hash, signature types.Signature, masternodes []common.Address) (bool, common.Address, error) {
	var signerAddress common.Address
	if len(masternodes) == 0 {
		return false, signerAddress, errors.New("Empty masternode list detected when verifying message signatures")
	}
	// Recover the public key and the Ethereum address
	pubkey, err := crypto.Ecrecover(signedHashToBeVerified.Bytes(), signature)
	if err != nil {
		return false, signerAddress, fmt.Errorf("Error while verifying message: %v", err)
	}

	copy(signerAddress[:], crypto.Keccak256(pubkey[1:])[12:])
	for _, mn := range masternodes {
		if mn == signerAddress {
			return true, signerAddress, nil
		}
	}

	log.Warn("[verifyMsgSignature] signer is not part of masternode list", "signer", signerAddress, "masternodes", masternodes)
	return false, signerAddress, nil
}

func (x *XDPoS_v2) getExtraFields(header *types.Header) (*types.QuorumCert, types.Round, []common.Address, error) {

	var masternodes []common.Address

	// last v1 block
	if header.Number.Cmp(x.config.V2.SwitchBlock) == 0 {
		masternodes = decodeMasternodesFromHeaderExtra(header)
		return nil, types.Round(0), masternodes, nil
	}

	// v2 block
	masternodes = x.GetMasternodesFromEpochSwitchHeader(header)
	var decodedExtraField types.ExtraFields_v2
	err := utils.DecodeBytesExtraFields(header.Extra, &decodedExtraField)
	if err != nil {
		log.Error("[getExtraFields] error on decode extra fields", "err", err, "extra", header.Extra)
		return nil, types.Round(0), masternodes, err
	}
	return decodedExtraField.QuorumCert, decodedExtraField.Round, masternodes, nil
}

func (x *XDPoS_v2) GetRoundNumber(header *types.Header) (types.Round, error) {
	// If not v2 yet, return 0
	if header.Number.Cmp(x.config.V2.SwitchBlock) <= 0 {
		return types.Round(0), nil
	} else {
		var decodedExtraField types.ExtraFields_v2
		err := utils.DecodeBytesExtraFields(header.Extra, &decodedExtraField)
		if err != nil {
			return types.Round(0), err
		}
		return decodedExtraField.Round, nil
	}
}

func (x *XDPoS_v2) GetSignersFromSnapshot(chain consensus.ChainReader, header *types.Header) ([]common.Address, error) {
	snap, err := x.getSnapshot(chain, header.Number.Uint64(), false)
	if err != nil {
		return nil, err
	}
	return snap.NextEpochCandidates, err
}

func (x *XDPoS_v2) CalculateMissingRounds(chain consensus.ChainReader, header *types.Header) (*utils.PublicApiMissedRoundsMetadata, error) {
	var missedRounds []utils.MissedRoundInfo
	switchInfo, err := x.getEpochSwitchInfo(chain, header, header.Hash())
	if err != nil {
		return nil, err
	}
	masternodes := switchInfo.Masternodes

	// Loop through from the epoch switch block to the current "header" block
	nextHeader := header
	for nextHeader.Number.Cmp(switchInfo.EpochSwitchBlockInfo.Number) > 0 {
		parentHeader := chain.GetHeaderByHash(nextHeader.ParentHash)
		parentRound, err := x.GetRoundNumber(parentHeader)
		if err != nil {
			return nil, err
		}
		currRound, err := x.GetRoundNumber(nextHeader)
		if err != nil {
			return nil, err
		}
		// This indicates that an increment in the round number is missing during the block production process.
		if parentRound+1 != currRound {
			// We need to iterate from the parentRound to the currRound to determine which miner did not perform mining.
			for i := parentRound + 1; i < currRound; i++ {
				leaderIndex := uint64(i) % x.config.Epoch % uint64(len(masternodes))
				whosTurn := masternodes[leaderIndex]
				missedRounds = append(
					missedRounds,
					utils.MissedRoundInfo{
						Round:            i,
						Miner:            whosTurn,
						CurrentBlockHash: nextHeader.Hash(),
						CurrentBlockNum:  nextHeader.Number,
						ParentBlockHash:  parentHeader.Hash(),
						ParentBlockNum:   parentHeader.Number,
					},
				)
			}
		}
		// Assign the pointer to the next one
		nextHeader = parentHeader
	}
	missedRoundsMetadata := &utils.PublicApiMissedRoundsMetadata{
		EpochRound:       switchInfo.EpochSwitchBlockInfo.Round,
		EpochBlockNumber: switchInfo.EpochSwitchBlockInfo.Number,
		MissedRounds:     missedRounds,
	}

	return missedRoundsMetadata, nil
}

func (x *XDPoS_v2) GetBlockInRewardFolderByEpochNumber(chain consensus.ChainReader, targetEpochNum uint64) (*types.BlockInfo, *types.BlockInfo, error) {
	// 1. go through the cache
	var smallestEpochSwitchInfo *types.BlockInfo
	var targetBlockInfo *types.BlockInfo
	var targetNextBlockInfo *types.BlockInfo
	for _, hash := range x.epochSwitches.Keys() {
		hash, ok := hash.(common.Hash)
		if !ok {
			return nil, nil, errors.New("epochSwitches cache key != Hash type, must be a bug")
		}
		info, err := x.getEpochSwitchInfo(chain, nil, hash)
		if err != nil {
			return nil, nil, err
		}
		epochNum := x.config.V2.SwitchBlock.Uint64()/x.config.Epoch + uint64(info.EpochSwitchBlockInfo.Round)/x.config.Epoch
		if epochNum == targetEpochNum {
			targetBlockInfo = info.EpochSwitchBlockInfo
			break
		}
		if smallestEpochSwitchInfo.Number.Cmp(info.EpochSwitchBlockInfo.Number) == 1 {
			smallestEpochSwitchInfo = info.EpochSwitchBlockInfo
		}
	}
	// 1.1. go again to find next block info
	if targetBlockInfo != nil {
		for _, hash := range x.epochSwitches.Keys() {
			hash, ok := hash.(common.Hash)
			if !ok {
				return nil, nil, errors.New("epochSwitches cache key != Hash type, must be a bug")
			}
			info, err := x.getEpochSwitchInfo(chain, nil, hash)
			if err != nil {
				return nil, nil, err
			}
			if info.EpochSwitchParentBlockInfo.Round == targetBlockInfo.Round {
				targetNextBlockInfo = info.EpochSwitchBlockInfo
				break
			}
		}
		return targetBlockInfo, targetNextBlockInfo, nil
	}
	// 2. if cache missed, use common.StoreRewardFolder to find the number and hash
	// 2.1. find estimated block (which must be earlier or equal to than target block)
	smallestEpochNum := x.config.V2.SwitchBlock.Uint64()/x.config.Epoch + uint64(smallestEpochSwitchInfo.Round)/x.config.Epoch
	epoch := big.NewInt(int64(x.config.Epoch))
	estblockNumDiff := new(big.Int).Mul(epoch, big.NewInt(int64(smallestEpochNum-targetEpochNum)))
	if estblockNumDiff.Cmp(common.Big0) == -1 {
		estblockNumDiff.Set(common.Big0)
	}
	estBlockNum := new(big.Int).Sub(smallestEpochSwitchInfo.Number, estblockNumDiff)
	if estBlockNum.Cmp(x.config.V2.SwitchBlock) == -1 {
		estBlockNum.Set(x.config.V2.SwitchBlock)
	}
	// 2.2. walk the dir
	rewardBlockInfos := make([]*types.BlockInfo, 0)
	filepath.WalkDir(common.StoreRewardFolder, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if !d.IsDir() {
			fileName := filepath.Base(path)
			parts := strings.Split(fileName, ".")
			number, ok := big.NewInt(0).SetString(parts[0], 10)
			if !ok {
				return nil
			}
			if number.Cmp(estBlockNum) == -1 {
				return nil
			}
			// this hash could be errored hash
			hash := common.HexToHash(parts[1])
			rewardBlockInfos = append(rewardBlockInfos, &types.BlockInfo{
				Number: number,
				Hash:   hash,
			})
		}
		return nil
	})
	for i, info := range rewardBlockInfos {
		header := chain.GetHeaderByHash(info.Hash)
		_, round, _, err := x.getExtraFields(header)
		if err != nil {
			return nil, nil, err
		}
		info.Round = round
		epochNum := x.config.V2.SwitchBlock.Uint64()/x.config.Epoch + uint64(round)/x.config.Epoch
		if epochNum == targetEpochNum {
			if i < len(rewardBlockInfos)-1 {
				nextEpoch := rewardBlockInfos[i+1]
				//todo: find next round, maybe unnecessary ?
				return info, nextEpoch, nil
			}
			return info, nil, nil
		}
	}
	return nil, nil, errors.New("input epoch number not found (all rounds in this epoch are missed, which is very rare)")
}
