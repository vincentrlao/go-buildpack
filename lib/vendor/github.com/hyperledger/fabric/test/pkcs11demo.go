package main

import "github.com/miekg/pkcs11"
import (
	"fmt"
	"log"
)

func main() {
	fmt.Println("Hello, World!")
	p := pkcs11.New("/usr/safenet/lunaclient/lib/libCryptoki2_64.so")
	err := p.Initialize()
	if err != nil {
		panic(err)
	}

	defer p.Destroy()
	defer p.Finalize()

	slots, err := p.GetSlotList(true)
	if err != nil {
		panic(err)
	}

	session, err := p.OpenSession(slots[0], pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		panic(err)
	}
	defer p.CloseSession(session)

	err = p.Login(session, pkcs11.CKU_USER, "S@fenet123")
	if err != nil {
		panic(err)
	}
	defer p.Logout(session)

	p.DigestInit(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_SHA_1, nil)})
	hash, err := p.Digest(session, []byte("this is a string"))
	if err != nil {
		panic(err)
	}

	for _, d := range hash {
		fmt.Printf("%x", d)
	}
	fmt.Println()

	// RSA Key Generation/Signing/Verification
	publicKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, []byte{3}),
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS_BITS, 1024),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, "MyPublicKey"),
	}
	privateKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, "MyPrivateKey"),
	}
	pub, priv, err := p.GenerateKeyPair(session,
		[]*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_KEY_PAIR_GEN, nil)},
		publicKeyTemplate, privateKeyTemplate)
	if err != nil {
		log.Fatal(err)
	}
	p.SignInit(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_SHA1_RSA_PKCS, nil)}, priv)
	// Sign something with the private key.
	data := []byte("Lets sign this data")
	mydata := []byte("Lets sign this data")

	signature, err := p.Sign(session, data)
	if err != nil {
		log.Fatal(err)
	}

	for _, d := range signature {
		fmt.Printf("%x", d)
	}
	fmt.Println()

	p.VerifyInit(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_SHA1_RSA_PKCS, nil)}, pub)

	err = p.Verify(session, mydata, signature)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("RSA works!")
	fmt.Println()

	// ECDSA Key Generation/Signing/Verification
	//https://flexiprovider.de/CurveOIDs.html
	//https://www.viathinksoft.com/~daniel-marschall/asn.1/oid-converter/online.php
	//ecParams := []byte{0x06,0x05,0x2B,0x81,0x04,0x00,0x0A} //secp256k1
	ecParams := []byte{0x06,0x05,0x2B,0x81,0x04,0x00,0x22} //secp384k1

	eccpublicKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, ecParams),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, "MyECDSAPubKey"),
	}
	eccprivateKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, "MyECDSAPriKey"),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, true),
	}
	pub, priv, err = p.GenerateKeyPair(session,
		[]*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_EC_KEY_PAIR_GEN, nil)},
		eccpublicKeyTemplate, eccprivateKeyTemplate)
	if err != nil {
		fmt.Printf("ECDSA generate failed")
		log.Fatal(err)
	}
	p.SignInit(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_ECDSA, nil)}, priv)
	// Sign something with the private key.
	//data := []byte("Lets sign this data")
	//mydata := []byte("Lets sign this data")

	signature, err = p.Sign(session, data)
	if err != nil {
		log.Fatal(err)
	}

	for _, d := range signature {
		fmt.Printf("%x", d)
	}
	fmt.Println()
	
	p.VerifyInit(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_ECDSA, nil)}, pub)

	err = p.Verify(session, mydata, signature)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("ECDSA works!")
	fmt.Println()

	template := []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_VALUE, nil)}

	_, err11 := p.GetAttributeValue(session, priv, template)
	if err11 != nil {
		log.Fatal("err %s\n", err11)
	}

	fmt.Printf("Done")
	
}
