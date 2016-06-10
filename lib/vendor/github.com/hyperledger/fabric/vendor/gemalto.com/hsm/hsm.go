package hsm

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/asn1"
	"fmt"
	"math/big"
	"sync"

	"github.com/miekg/pkcs11"
	"github.com/op/go-logging"
)

var (
	hsmLog = logging.MustGetLogger("hsm")
	p      *pkcs11.Ctx
	s      pkcs11.SessionHandle
)

// Public Methods

// Initialize HSM
func Initialize() (err error) {
	hsmLog.Info("Initialize HSM")

	p = pkcs11.New("/usr/safenet/lunaclient/lib/libCryptoki2_64.so")

	err = p.Initialize()
	if err != nil {
		hsmLog.Error("Failed to initialize HSM %s\n", err)
		return err
	}

	return nil
}

// Initialize and OpenSession HSM
func OpenSession(enrollID string, pwd string) (err error) {
	hsmLog.Info("OpenSession HSM")

	if p == nil {
		hsmLog.Error("HSM is not yet initialized\n")
		return fmt.Errorf("HSM is not yet initialized")
	}

	slots, err := p.GetSlotList(true)
	if err != nil {
		hsmLog.Error("Failed to get slot list HSM %s\n", err)
		return err
	}

	s, err = p.OpenSession(slots[0], pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		hsmLog.Error("Failed to open session HSM %s\n", err)
		return err
	}

	err = p.Login(s, pkcs11.CKU_USER, pwd)
	if err != nil {
		hsmLog.Error("Failed to login HSM %s\n", err)
		return err
	}

	return nil
}

func CloseSession() {
	hsmLog.Info("CloseSession HSM")

	if p != nil {

		p.Logout(s)
		p.CloseSession(s)

		s = 0
	}
}

func Uninitialize() {
	hsmLog.Info("Uninitialize HSM")

	if p != nil {

		p.Destroy()
		p.Finalize()
		p = nil
	}
}

func IsSessionActive() (status bool) {

	if p != nil && s != 0 {
		return true
	} else {
		return false
	}
}

// Find Object
func FindAnObject(objTemplate []*pkcs11.Attribute) (objHandle pkcs11.ObjectHandle, err error) {
	hsmLog.Info(">>> FindAnObject")

	if p == nil || s == 0 {
		hsmLog.Error("HSM is not yet initialized or opensession\n")
		return 0, fmt.Errorf("HSM is not yet initialized or opensession")
	}

	err = p.FindObjectsInit(s, objTemplate)
	if err != nil {
		hsmLog.Error("Failed to FindObjectInit %s\n", err)
		return 0, err
	}

	objHandles, status, err := p.FindObjects(s, 1)
	if status == true {
		hsmLog.Error("Found objects more than expected %s\n", err)
		return 0, err
	}

	if err != nil {
		hsmLog.Error("Failed to FindObject %s\n", err)
		return 0, err
	}

	err = p.FindObjectsFinal(s)
	if err != nil {
		hsmLog.Error("Failed to FindObjectFinal %s\n", err)
		return 0, err
	}

	hsmLog.Info("Length of Object handle: %d", len(objHandles))

	if len(objHandles) == 1 {
		hsmLog.Info("Object found")
		return objHandles[0], nil
	} else {
		return 0, fmt.Errorf("FindAnObject error\n")
	}
}

// Store/Load Private Key
func StorePrivateKey(keyID string, privateKey []byte) (err error) {
	hsmLog.Info("Store Private Key")

	if p == nil || s == 0 {
		hsmLog.Error("HSM is not yet initialized or opensession\n")
		return fmt.Errorf("HSM is not yet initialized or opensession")
	}

	// Find Object
	objTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_DATA),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, keyID),
	}

	// If key is already there, destroy first (TODO: to improve)
	objHandle, err := FindAnObject(objTemplate)
	if objHandle != 0 {
		err := p.DestroyObject(s, objHandle)
		if err != nil {
			hsmLog.Error("Failed to destroy object for key %s, %s\n", keyID, err)
			return err
		}
	}

	dataTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_DATA),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE, privateKey),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, keyID),
	}

	_, err = p.CreateObject(s, dataTemplate)
	if err != nil {
		hsmLog.Error("Failed to create object for key %s, %s\n", keyID, err)
		return err
	}

	return nil
}

func LoadPrivateKey(keyID string) (privateKey []byte, err error) {
	hsmLog.Info("Load Private Key")

	if p == nil || s == 0 {
		hsmLog.Error("HSM is not yet initialized or opensession\n")
		return nil, fmt.Errorf("HSM is not yet initialized or opensession")
	}

	// Find Object
	dataTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_DATA),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, keyID),
	}

	objHandle, err := FindAnObject(dataTemplate)
	if objHandle == 0 && err != nil {
		hsmLog.Error("Failed to FindObject %s, %s\n", keyID, err)
		return nil, err
	}

	// Get Object Attribute Value
	attributeTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_VALUE, nil),
	}

	attributes, err := p.GetAttributeValue(s, objHandle, attributeTemplate)
	if err != nil {
		hsmLog.Error("Failed to GetAttributeValue %s, %s\n", keyID, err)
		return nil, err
	}

	for _, attribute := range attributes {
		if attribute.Type == pkcs11.CKA_VALUE {
			return attribute.Value, nil
		}
	}

	return nil, nil
}

// Store/Load Public Key
func StorePublicKey(keyID string, publicKey []byte) (err error) {
	hsmLog.Info("Store Public Key")

	if p == nil || s == 0 {
		hsmLog.Error("HSM is not yet initialized or opensession\n")
		return fmt.Errorf("HSM is not yet initialized or opensession")
	}

	// Find Object
	objTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_DATA),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, keyID),
	}

	// If key is already there, destroy first (TODO: to improve)
	objHandle, err := FindAnObject(objTemplate)
	if objHandle != 0 {
		err := p.DestroyObject(s, objHandle)
		if err != nil {
			hsmLog.Error("Failed to destroy object for key %s, %s\n", keyID, err)
			return err
		}
	}

	dataTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_DATA),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE, publicKey),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, keyID),
	}

	_, err = p.CreateObject(s, dataTemplate)
	if err != nil {
		hsmLog.Error("Failed to create object for key %s, %s\n", keyID, err)
		return err
	}

	return nil
}

func LoadPublicKey(keyID string) (privateKey []byte, err error) {
	hsmLog.Info("Load Public Key")

	if p == nil || s == 0 {
		hsmLog.Error("HSM is not yet initialized or opensession\n")
		return nil, fmt.Errorf("HSM is not yet initialized or opensession")
	}

	// Find Object
	dataTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_DATA),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, keyID),
	}

	objHandle, err := FindAnObject(dataTemplate)
	if objHandle == 0 && err != nil {
		hsmLog.Error("Failed to FindObject %s, %s\n", keyID, err)
		return nil, err
	}

	// Get Object Attribute Value
	attributeTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_VALUE, nil),
	}

	attributes, err := p.GetAttributeValue(s, objHandle, attributeTemplate)
	if err != nil {
		hsmLog.Error("Failed to GetAttributeValue %s, %s\n", keyID, err)
		return nil, err
	}

	for _, attribute := range attributes {
		if attribute.Type == pkcs11.CKA_VALUE {
			return attribute.Value, nil
		}
	}

	return nil, nil
}

// Store/Load Key
func StoreKey(keyID string, key []byte) (err error) {
	hsmLog.Info("Store Key")

	if p == nil || s == 0 {
		hsmLog.Error("HSM is not yet initialized or opensession\n")
		return fmt.Errorf("HSM is not yet initialized or opensession")
	}

	// Find Object
	objTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_DATA),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, keyID),
	}

	// If key is already there, destroy first (TODO: to improve)
	objHandle, err := FindAnObject(objTemplate)
	if objHandle != 0 {
		err := p.DestroyObject(s, objHandle)
		if err != nil {
			hsmLog.Error("Failed to destroy object for key %s, %s\n", keyID, err)
			return err
		}
	}

	dataTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_DATA),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE, key),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, keyID),
	}

	_, err = p.CreateObject(s, dataTemplate)
	if err != nil {
		hsmLog.Error("Failed to create object for key %s, %s\n", keyID, err)
		return err
	}

	return nil
}

func LoadKey(keyID string) (key []byte, err error) {
	hsmLog.Info("Load Key")

	if p == nil || s == 0 {
		hsmLog.Error("HSM is not yet initialized or opensession\n")
		return nil, fmt.Errorf("HSM is not yet initialized or opensession")
	}

	// Find Object
	dataTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_DATA),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, keyID),
	}

	objHandle, err := FindAnObject(dataTemplate)
	if objHandle == 0 && err != nil {
		hsmLog.Error("Failed to FindObject %s, %s\n", keyID, err)
		return nil, err
	}

	// Get Object Attribute Value
	attributeTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_VALUE, nil),
	}

	attributes, err := p.GetAttributeValue(s, objHandle, attributeTemplate)
	if err != nil {
		hsmLog.Error("Failed to GetAttributeValue %s, %s\n", keyID, err)
		return nil, err
	}

	for _, attribute := range attributes {
		if attribute.Type == pkcs11.CKA_VALUE {
			return attribute.Value, nil
		}
	}

	return nil, nil
}

// Store/Load Cert
func StoreCert(certID string, pem []byte) (err error) {
	hsmLog.Info("Store Cert")

	if p == nil || s == 0 {
		hsmLog.Error("HSM is not yet initialized or opensession\n")
		return fmt.Errorf("HSM is not yet initialized or opensession")
	}

	// Find Object
	objTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_DATA),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, certID),
	}

	// If key is already there, destroy first (TODO: to improve)
	objHandle, err := FindAnObject(objTemplate)
	if objHandle != 0 {
		err := p.DestroyObject(s, objHandle)
		if err != nil {
			hsmLog.Error("Failed to destroy object for key %s, %s\n", certID, err)
			return err
		}
	}

	dataTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_DATA),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE, pem),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, certID),
	}

	_, err = p.CreateObject(s, dataTemplate)
	if err != nil {
		hsmLog.Error("Failed to create object for key %s, %s\n", certID, err)
		return err
	}

	return nil
}

func LoadCert(certID string) (pem []byte, err error) {
	hsmLog.Info("Load Cert")

	if p == nil || s == 0 {
		hsmLog.Error("HSM is not yet initialized or opensession\n")
		return nil, fmt.Errorf("HSM is not yet initialized or opensession")
	}

	// Find Object
	dataTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_DATA),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, certID),
	}

	objHandle, err := FindAnObject(dataTemplate)
	if objHandle == 0 && err != nil {
		hsmLog.Error("Failed to FindObject %s, %s\n", certID, err)
		return nil, err
	}

	// Get Object Attribute Value
	attributeTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_VALUE, nil),
	}

	attributes, err := p.GetAttributeValue(s, objHandle, attributeTemplate)
	if err != nil {
		hsmLog.Error("Failed to GetAttributeValue %s, %s\n", certID, err)
		return nil, err
	}

	for _, attribute := range attributes {
		if attribute.Type == pkcs11.CKA_VALUE {
			return attribute.Value, nil
		}
	}

	return nil, nil
}

func GenerateECDSAKeypair(keyID string, level int) (publicKey []byte, err error) {

	var l sync.Mutex
	l.Lock()

	hsmLog.Info("GenerateECDSAKeypair %s", keyID)

	if p == nil || s == 0 {
		hsmLog.Error("HSM is not yet initialized or opensession\n")
		return nil, fmt.Errorf("HSM is not yet initialized or opensession")
	}

	// Find Object
	privKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, keyID+"_privatekey"),
	}

	hsmLog.Info("GenerateECDSAKeypair find private key")

	// If key is already there, destroy first (TODO: to improve)
	keyHandle, err := FindAnObject(privKeyTemplate)
	if keyHandle != 0 {

		hsmLog.Info("GenerateECDSAKeypair destroy object")

		err := p.DestroyObject(s, keyHandle)
		if err != nil {
			hsmLog.Error("Failed to destroy object for key %s, %s\n", keyID, err)
			return nil, err
		}
	}

	pubKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, keyID+"_publickey"),
	}

	hsmLog.Info("GenerateECDSAKeypair find public key")

	// If key is already there, destroy first (TODO: to improve)
	keyHandle, err = FindAnObject(pubKeyTemplate)
	if keyHandle != 0 {
		err := p.DestroyObject(s, keyHandle)
		if err != nil {
			hsmLog.Error("Failed to destroy object for key %s, %s\n", keyID, err)
			return nil, err
		}
	}

	hsmLog.Info("GenerateECDSAKeypair find public key done")

	//https://www.ietf.org/rfc/rfc6637.txt
	//https://www.viathinksoft.com/~daniel-marschall/asn.1/oid-converter/online.php
	//https://flexiprovider.de/CurveOIDs.html

	//ecParams := []byte{0x06,0x05,0x2B,0x81,0x04,0x00,0x0A} //secp256k1
	//ecParams := []byte{0x06,0x05,0x2B,0x81,0x04,0x00,0x22} //secp384k1

	var ecParams []byte

	switch level {
	case 256:
		ecParams = []byte{0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07} //NIST curve p-256
	case 384:
		ecParams = []byte{0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22} //NIST curve p-384
	default:
		hsmLog.Error("Security level not supported [%d]", level)
		err = fmt.Errorf("Security level not supported [%d]", level)
		return nil, err
	}

	publicKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, ecParams),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, keyID+"_publickey"),
	}
	privateKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, keyID+"_privatekey"),
	}
	publicKeyHandle, _, err := p.GenerateKeyPair(s, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_EC_KEY_PAIR_GEN, nil)},
		publicKeyTemplate,
		privateKeyTemplate)
	if err != nil {
		hsmLog.Error("Failed to generate ECDSA keypair [%s], [%s]", keyID, err)
		return nil, err
	}

	// Get Public Key Value
	attributeTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, nil),
	}

	attributes, err := p.GetAttributeValue(s, publicKeyHandle, attributeTemplate)
	if err != nil {
		hsmLog.Error("Failed to GetAttributeValue [%s], [%s]", keyID, err)
		return nil, err
	}

	for _, attribute := range attributes {
		if attribute.Type == pkcs11.CKA_EC_POINT {
			return attribute.Value, nil
		}
	}

	//
	l.Unlock()

	return nil, nil
}

func ECDSASign(keyID string, message []byte) (signature []byte, err error) {
	var l sync.Mutex
	l.Lock()
	hsmLog.Info("ECDSASign")

	if p == nil || s == 0 {
		hsmLog.Error("HSM is not yet initialized or opensession")
		return nil, fmt.Errorf("HSM is not yet initialized or opensession")
	}

	// Find Object
	privateKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, keyID+"_privatekey"),
	}

	privateKeyHandle, err := FindAnObject(privateKeyTemplate)
	if privateKeyHandle == 0 && err != nil {
		hsmLog.Error("ECDSA PrivateKey Not Found [%s], [%s]\n", keyID, err)
		return nil, err
	}

	err = p.SignInit(s, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_ECDSA, nil)}, privateKeyHandle)
	if err != nil {
		hsmLog.Error("ECDSA SignInit Failed [%s], [%s]\n", keyID, err)
		return nil, err
	}

	signature, err = p.Sign(s, message)
	if err != nil {
		hsmLog.Error("ECDSA Sign Failed [%s], [%s]\n", keyID, err)
		return nil, err
	}

	hsmLog.Info("ECDSA Signature [%x]", signature)

	//
	l.Unlock()

	return signature, nil
}

func ECDSAVerify(keyID string, message []byte, signature []byte) (status bool, err error) {
	var l sync.Mutex
	l.Lock()
	hsmLog.Info("ECDSAVerify")

	if p == nil || s == 0 {
		hsmLog.Error("HSM is not yet initialized or opensession")
		return false, fmt.Errorf("HSM is not yet initialized or opensession")
	}

	// Find Object
	publicKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, keyID+"_publickey"),
	}

	publicKeyHandle, err := FindAnObject(publicKeyTemplate)
	if publicKeyHandle == 0 && err != nil {
		hsmLog.Error("ECDSA PublicKey Not Found [%s], [%s]\n", keyID, err)
		return false, err
	}

	err = p.VerifyInit(s, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_ECDSA, nil)}, publicKeyHandle)
	if err != nil {
		hsmLog.Error("ECDSA VerifyInit Failed [%s], [%s]\n", keyID, err)
		return false, err
	}

	err = p.Verify(s, message, signature)
	if err != nil {
		hsmLog.Error("ECDSA Verify Failed [%s], [%s]\n", keyID, err)
		return false, err
	}

	hsmLog.Info("ECDSAVerify Success")

	//
	l.Unlock()

	return true, nil
}

func ECDSARawtoPubKey(rawPubKey []byte, level int) (ecdsaPubKey *ecdsa.PublicKey, err error) {
	hsmLog.Info("ECDSARawtoPubKey")

	var ecp []byte

	_, err = asn1.Unmarshal(rawPubKey, &ecp)
	if err != nil {
		hsmLog.Error("Failed to decode ASN.1 encoded ECDSA Public Key (CKA_EC_POINT) - (%s)", err)
		return nil, err
	} else {

		var pubKey ecdsa.PublicKey

		switch level {
		case 256:
			pubKey.Curve = elliptic.P256()
		case 384:
			pubKey.Curve = elliptic.P384()
		default:
			hsmLog.Error("Security level not supported [%d]", level)
			err = fmt.Errorf("Security level not supported [%d]", level)
			return nil, err
		}

		pointLength := pubKey.Curve.Params().BitSize/8*2 + 1

		hsmLog.Info("Point Length %d", pointLength)

		if len(ecp) != pointLength {
			hsmLog.Error("ECDSA Public Key (CKA_EC_POINT) (%d) does not fit used curve (%d)", len(ecp), pointLength)
			err = fmt.Errorf("ECDSA Public Key (CKA_EC_POINT) (%d) does not fit used curve (%d)", len(ecp), pointLength)
			return nil, err
		}

		pubKey.X, pubKey.Y = elliptic.Unmarshal(pubKey.Curve, ecp[:pointLength])

		if pubKey.X == nil || pubKey.Y == nil {
			hsmLog.Error("Failed to decode ECDSA Public Key (CKA_EC_POINT)")
			err = fmt.Errorf("Failed to decode ECDSA Public Key (CKA_EC_POINT)")
			return nil, err
		}

		if !pubKey.Curve.IsOnCurve(pubKey.X, pubKey.Y) {
			hsmLog.Error("ECDSA Public Key (CKA_EC_POINT) is not on curve.")
			err = fmt.Errorf("ECDSA Public Key (CKA_EC_POINT) is not on curve.")
			return nil, err
		}

		return &pubKey, nil
	}
}

func ECDSASigtoRS(signature []byte) (r, s *big.Int, err error) {
	hsmLog.Info("ECDSASigtoRS")

	hsmLog.Info("Signature %x", signature)

	if len(signature)%2 == 0 {
		r = new(big.Int).SetBytes(signature[:len(signature)/2])
		s = new(big.Int).SetBytes(signature[len(signature)/2:])

		return r, s, nil
	} else {
		err = fmt.Errorf("ECDSA Signature R and S is not same length. (Not Implemented)")

		return nil, nil, err
	}
}
