package main

import (
	"gemalto.com/hsm"
	"github.com/op/go-logging"
	"crypto/ecdsa"
)

var hsmDemoLog = logging.MustGetLogger("hsm_demo")

func main() {
	hsmDemoLog.Info("HSM Demo Start")

	hsm.Initialize()

	hsm.OpenSession("testing", "S@fenet123")

	keyID := "gem_user17"

	rawPubKey, _ := hsm.GenerateECDSAKeypair(keyID, 256)

	hsmDemoLog.Info("ECDSA Public Key [%x]", rawPubKey)

	data := []byte("This is sample string.")

	signature, _ := hsm.ECDSASign(keyID, data)

	hsm.ECDSAVerify(keyID, data, signature)

	ecdsaPubKey, _ := hsm.ECDSARawtoPubKey(rawPubKey, 256)

	hsmDemoLog.Info("Signature Length %d", len(signature))

	r, s, _ := hsm.ECDSASigtoRS(signature)

	if ecdsa.Verify(ecdsaPubKey, data, r, s) {
		hsmDemoLog.Info("Wow! Cool...")
	} else {
		hsmDemoLog.Info("Oops!")
	}

	hsm.CloseSession()

	hsm.Uninitialize()

	hsmDemoLog.Info("HSM Demo Finish")
}