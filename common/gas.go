package common

import "math/big"

var MinGasPrice50x = big.NewInt(12500000000)
var GasPrice50x = big.NewInt(12500000000)

func GetGasFee(blockNumber, gas uint64) *big.Int {
	fee := new(big.Int).SetUint64(gas)

	if blockNumber >= BlockNumberGas50x.Uint64() {
		fee = fee.Mul(fee, GasPrice50x)
	} else if blockNumber > TIPXDC21Fee.Uint64() {
		fee = fee.Mul(fee, XDC21GasPrice)
	}

	return fee
}

func GetGasPrice(number *big.Int) *big.Int {
	if number == nil || number.Cmp(BlockNumberGas50x) < 0 {
		return new(big.Int).Set(XDC21GasPrice)
	} else {
		return new(big.Int).Set(GasPrice50x)
	}
}

func GetMinGasPrice(number *big.Int) *big.Int {
	if number == nil || number.Cmp(BlockNumberGas50x) < 0 {
		return new(big.Int).Set(MinGasPrice)
	} else {
		return new(big.Int).Set(MinGasPrice50x)
	}
}
