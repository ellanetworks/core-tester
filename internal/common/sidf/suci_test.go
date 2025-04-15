/**
 * SPDX-License-Identifier: Apache-2.0
 * © Copyright 2019 The Free5GC Authors
 * © Copyright 2025 Free Mobile SAS
 */
package sidf

import (
	"crypto/ecdh"
	"encoding/hex"
)

var testHomeNetworkPrivateKeys = []HomeNetworkPrivateKey{
	{
		ProtectionScheme: "1", // Protect Scheme: Profile A
		PrivateKey:       Must(ecdh.X25519().NewPrivateKey(Must(hex.DecodeString("c53c22208b61860b06c62e5406a7b330c2b577aa5558981510d128247d38bd1d")))),
		PublicKey:        Must(ecdh.X25519().NewPublicKey(Must(hex.DecodeString("5a8d38864820197c3394b92613b20b91633cbd897119273bf8e4a6f4eec0a650")))),
	},
	{
		ProtectionScheme: "2", // Protect Scheme: Profile B
		PrivateKey:       Must(ecdh.P256().NewPrivateKey(Must(hex.DecodeString("F1AB1074477EBCC7F554EA1C5FC368B1616730155E0041AC447D6301975FECDA")))),
		PublicKey:        Must(ecdh.P256().NewPublicKey(Must(hex.DecodeString("0472DA71976234CE833A6907425867B82E074D44EF907DFB4B3E21C1C2256EBCD15A7DED52FCBB097A4ED250E036C7B9C8C7004C4EEDC4F068CD7BF8D3F900E3B4")))),
	},
	{
		ProtectionScheme: "2", // Protect Scheme: Profile B
		PrivateKey:       Must(ecdh.P256().NewPrivateKey(Must(hex.DecodeString("F1AB1074477EBCC7F554EA1C5FC368B1616730155E0041AC447D6301975FECDA")))),
		PublicKey:        Must(ecdh.P256().NewPublicKey(Must(hex.DecodeString("0472DA71976234CE833A6907425867B82E074D44EF907DFB4B3E21C1C2256EBCD15A7DED52FCBB097A4ED250E036C7B9C8C7004C4EEDC4F068CD7BF8D3F900E3B4")))),
	},
}

var testHomeNetworkPublicKeys = []HomeNetworkPublicKey{
	{
		ProtectionScheme: "1",
		PublicKeyID:      "1",
		PublicKey:        Must(ecdh.X25519().NewPublicKey(Must(hex.DecodeString("5a8d38864820197c3394b92613b20b91633cbd897119273bf8e4a6f4eec0a650")))),
	},
	{
		ProtectionScheme: "2",
		PublicKeyID:      "2",
		PublicKey:        Must(ecdh.P256().NewPublicKey(Must(hex.DecodeString("0472DA71976234CE833A6907425867B82E074D44EF907DFB4B3E21C1C2256EBCD15A7DED52FCBB097A4ED250E036C7B9C8C7004C4EEDC4F068CD7BF8D3F900E3B4")))),
	},
	{
		ProtectionScheme: "2",
		PublicKeyID:      "3",
		PublicKey:        Must(ecdh.P256().NewPublicKey(Must(hex.DecodeString("0472DA71976234CE833A6907425867B82E074D44EF907DFB4B3E21C1C2256EBCD15A7DED52FCBB097A4ED250E036C7B9C8C7004C4EEDC4F068CD7BF8D3F900E3B4")))),
	},
}

func Must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}
