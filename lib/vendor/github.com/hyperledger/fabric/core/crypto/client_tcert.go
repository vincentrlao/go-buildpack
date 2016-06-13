/*
Copyright IBM Corp. 2016 All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

		 http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package crypto

import (
	"crypto/x509"
	"encoding/asn1"
	"fmt"

	"gemalto.com/hsm"
	"github.com/hyperledger/fabric/core/crypto/primitives"
	"github.com/hyperledger/fabric/core/crypto/utils"
)

type tCert interface {
	GetCertificate() *x509.Certificate

	Sign(msg []byte) ([]byte, error)

	SignHSM(keyID string, msg []byte) ([]byte, error)

	Verify(signature, msg []byte) error
}

type tCertImpl struct {
	client *clientImpl
	cert   *x509.Certificate
	sk     interface{}
}

func (tCert *tCertImpl) GetCertificate() *x509.Certificate {
	return tCert.cert
}

func (tCert *tCertImpl) Sign(msg []byte) ([]byte, error) {
	if tCert.sk == nil {
		return nil, utils.ErrNilArgument
	}

	return tCert.client.sign(tCert.sk, msg)
}

func (tCert *tCertImpl) SignHSM(keyID string, msg []byte) ([]byte, error) {

	fmt.Println(">>> SignHSM")

	hash := primitives.NewHash()
	hash.Write(msg)

	fmt.Println(">>> SignHSM 1")

	signature, err := hsm.ECDSASign(keyID, hash.Sum(nil))
	if err != nil {
		return nil, err
	}

	fmt.Println(">>> SignHSM 2")

	r, s, err := hsm.ECDSASigtoRS(signature)
	if err != nil {
		return nil, err
	}

	fmt.Println(">>> SignHSM 3")

	raw, err := asn1.Marshal(primitives.ECDSASignature{r, s})
	if err != nil {
		return nil, err
	}

	fmt.Println(">>> SignHSM 4")

	return raw, nil
}

func (tCert *tCertImpl) Verify(signature, msg []byte) (err error) {
	ok, err := tCert.client.verify(tCert.cert.PublicKey, msg, signature)
	if err != nil {
		return
	}
	if !ok {
		return utils.ErrInvalidSignature
	}
	return
}
