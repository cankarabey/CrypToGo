package main

import (
	"bytes"
	"crypto"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/packet"
)

func main() {
	var rootCmd = &cobra.Command{Use: "pgptool"}

	var name, comment, email string
	var generateKeysCmd = &cobra.Command{
		Use:   "generate-keys",
		Short: "Generate PGP key pair",
		Run: func(cmd *cobra.Command, args []string) {
			if err := generateKeys(name, comment, email); err != nil {
				log.Fatalf("Error generating keys: %v", err)
			}
		},
	}
	generateKeysCmd.Flags().StringVarP(&name, "name", "n", "", "Name for the key")
	generateKeysCmd.Flags().StringVarP(&comment, "comment", "c", "", "Comment for the key")
	generateKeysCmd.Flags().StringVarP(&email, "email", "e", "", "Email for the key")

	var publicKeyFile, privateKeyFile string
	var encryptCmd = &cobra.Command{
		Use:   "encrypt [filename]",
		Short: "Encrypt a file",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			if err := encryptFile(args[0], publicKeyFile); err != nil {
				log.Fatalf("Error encrypting file: %v", err)
			}
		},
	}
	encryptCmd.Flags().StringVarP(&publicKeyFile, "pubkey", "p", "public.key", "Public key file")

	var decryptCmd = &cobra.Command{
		Use:   "decrypt [filename]",
		Short: "Decrypt a file",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			if err := decryptFile(args[0], privateKeyFile); err != nil {
				log.Fatalf("Error decrypting file: %v", err)
			}
		},
	}
	decryptCmd.Flags().StringVarP(&privateKeyFile, "privkey", "k", "private.key", "Private key file")

	rootCmd.AddCommand(generateKeysCmd, encryptCmd, decryptCmd)
	if err := rootCmd.Execute(); err != nil {
		log.Fatal(err)
	}
}

func generateKeys(name, comment, email string) error {
	config := &packet.Config{
		DefaultHash:            crypto.SHA256,
		DefaultCipher:          packet.CipherAES256,
		DefaultCompressionAlgo: packet.CompressionZLIB,
		CompressionConfig:      &packet.CompressionConfig{Level: 9},
	}

	entity, err := openpgp.NewEntity(name, comment, email, config)
	if err != nil {
		return err
	}

	privFile, err := os.Create("private.key")
	if err != nil {
		return err
	}
	defer privFile.Close()
	privWriter, err := armor.Encode(privFile, openpgp.PrivateKeyType, nil)
	if err != nil {
		return err
	}
	defer privWriter.Close()
	entity.SerializePrivate(privWriter, nil)

	pubFile, err := os.Create("public.key")
	if err != nil {
		return err
	}
	defer pubFile.Close()
	pubWriter, err := armor.Encode(pubFile, openpgp.PublicKeyType, nil)
	if err != nil {
		return err
	}
	defer pubWriter.Close()
	entity.Serialize(pubWriter)

	fmt.Println("PGP key pair generated successfully.")
	return nil
}

func encryptFile(filename, publicKeyFile string) error {
	pubKeyData, err := ioutil.ReadFile(publicKeyFile)
	if err != nil {
		return err
	}
	entityList, err := readEntityList(pubKeyData)
	if err != nil {
		return err
	}

	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return err
	}

	buf := new(bytes.Buffer)
	w, err := openpgp.Encrypt(buf, entityList, nil, nil, nil)
	if err != nil {
		return err
	}
	_, err = w.Write(data)
	if err != nil {
		return err
	}
	err = w.Close()
	if err != nil {
		return err
	}

	err = ioutil.WriteFile(filename+".pgp", buf.Bytes(), 0600)
	if err != nil {
		return err
	}

	fmt.Printf("File '%s' encrypted to '%s.pgp'\n", filename, filename)
	return nil
}

func decryptFile(filename, privateKeyFile string) error {
	privKeyData, err := ioutil.ReadFile(privateKeyFile)
	if err != nil {
		return err
	}
	entityList, err := readEntityList(privKeyData)
	if err != nil {
		return err
	}

	encData, err := ioutil.ReadFile(filename)
	if err != nil {
		return err
	}

	decbuf := bytes.NewBuffer(encData)
	result, err := openpgp.ReadMessage(decbuf, entityList, nil, nil)
	if err != nil {
		return err
	}
	decData, err := ioutil.ReadAll(result.UnverifiedBody)
	if err != nil {
		return err
	}

	decFilename := filename + ".dec"
	err = ioutil.WriteFile(decFilename, decData, 0600)
	if err != nil {
		return err
	}

	fmt.Printf("File '%s' decrypted to '%s'\n", filename, decFilename)
	return nil
}

func readEntityList(keyData []byte) (openpgp.EntityList, error) {
	keyBlock, err := armor.Decode(bytes.NewBuffer(keyData))
	if err != nil {
		return nil, err
	}
	return openpgp.ReadKeyRing(keyBlock.Body)
}
