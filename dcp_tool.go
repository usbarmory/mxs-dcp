// NXP Data Co-Processor (DCP)
// https://github.com/f-secure-foundry/mxs-dcp
//
// userspace driver reference example
//
// Copyright (c) F-Secure Corporation
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU General Public License as published by the Free
// Software Foundation under version 3 of the License.
//
// This program is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
// more details.
//
// See accompanying LICENSE file for full details.
//
// IMPORTANT: the unique OTPMK internal key is available only when Secure Boot
// (HAB) is enabled, otherwise a Non-volatile Test Key (NVTK), identical for
// each SoC, is used. The secure operation of the DCP and SNVS, in production
// deployments, should always be paired with Secure Boot activation.
//
//+build linux

package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"io"
	"log"
	"os"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Symmetric file encryption using AES-128-OFB, key is derived from a known
// diversifier encrypted with AES-128-CBC through the NXP Data Co-Processor
// (DCP) with its device specific secret key. This uniquely ties the derived
// key to the specific hardware unit being used.
//
// The initialization vector is prepended to the encrypted file, the HMAC for
// authentication is appended:
//
// iv (16 bytes) || ciphertext || hmac (32 bytes)

type af_alg_iv struct {
	ivlen uint32
	iv    [aes.BlockSize]byte
}

// NIST AES-128-CBC test vector
const TEST_KEY = "\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c"

var test bool

func init() {
	log.SetFlags(0)
	log.SetOutput(os.Stdout)

	flag.BoolVar(&test, "t", false, "test mode (skcipher cbc(aes) w/ test key)")

	flag.Usage = func() {
		log.Println("usage: [enc|dec] [cleartext file] [blob file] [diversifier]")
	}
}

func main() {
	var err error

	var inputPath string
	var outputPath string

	flag.Parse()

	if len(flag.Args()) != 4 {
		flag.Usage()
		os.Exit(1)
	}

	op := flag.Arg(0)

	switch op {
	case "enc":
		inputPath = flag.Arg(1)
		outputPath = flag.Arg(2)
	case "dec":
		outputPath = flag.Arg(1)
		inputPath = flag.Arg(2)
	default:
		log.Fatal("dcp_tool: error, invalid operation")
	}

	defer func() {
		if err != nil {
			log.Fatalf("dcp_tool: error, %v", err)
		}
	}()

	diversifier, err := hex.DecodeString(flag.Arg(3))

	if err != nil {
		return
	}

	if len(diversifier) > 1 {
		log.Fatalf("dcp_tool: error, diversifier must be a single byte value in hex format (e.g. ab)")
	}

	input, err := os.OpenFile(inputPath, os.O_RDONLY|os.O_EXCL, 0600)

	if err != nil {
		return
	}
	defer input.Close()

	output, err := os.OpenFile(outputPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL|os.O_TRUNC, 0600)

	if err != nil {
		return
	}
	defer output.Close()

	log.Printf("dcp_tool: %s %s to %s", op, inputPath, outputPath)

	switch op {
	case "enc":
		err = encrypt(input, output, diversifier)
	case "dec":
		err = decrypt(input, output, diversifier)
	}

	if err == nil {
		log.Println("dcp_tool: done")
	}
}

func encrypt(input *os.File, output *os.File, diversifier []byte) (err error) {
	// It is advised to use only deterministic input data for key
	// derivation, therefore we use the empty allocated IV before it being
	// filled.
	iv := make([]byte, aes.BlockSize)
	key, err := DCPDeriveKey(diversifier, iv)

	if err != nil {
		return
	}
	_, err = io.ReadFull(rand.Reader, iv)

	if err != nil {
		return
	}

	err = encryptOFB(key, iv, input, output)

	return
}

func decrypt(input *os.File, output *os.File, diversifier []byte) (err error) {
	// It is advised to use only deterministic input data for key
	// derivation, therefore we use the empty allocated IV before it being
	// filled.
	iv := make([]byte, aes.BlockSize)
	key, err := DCPDeriveKey(diversifier, iv)

	if err != nil {
		return
	}

	_, err = io.ReadFull(input, iv)

	if err != nil {
		return
	}

	err = decryptOFB(key, iv, input, output)

	return
}

// equivalent to PKCS#11 C_DeriveKey with CKM_AES_CBC_ENCRYPT_DATA
func DCPDeriveKey(diversifier []byte, iv []byte) (key []byte, err error) {
	log.Printf("dcp_tool: deriving key, diversifier %x", diversifier)

	fd, err := unix.Socket(unix.AF_ALG, unix.SOCK_SEQPACKET, 0)

	if err != nil {
		return
	}
	defer unix.Close(fd)

	addr := &unix.SockaddrALG{
		Type: "skcipher",
		Name: "cbc-aes-dcp",
	}

	if test {
		addr.Type = "skcipher"
		addr.Name = "cbc(aes)"
	}

	err = unix.Bind(fd, addr)

	if err != nil {
		return
	}

	if test {
		err = syscall.SetsockoptString(fd, unix.SOL_ALG, unix.ALG_SET_KEY, TEST_KEY)
	} else {
		// https://github.com/golang/go/issues/31277
		// SetsockoptString does not allow empty strings
		_, _, e1 := syscall.Syscall6(syscall.SYS_SETSOCKOPT, uintptr(fd), uintptr(unix.SOL_ALG), uintptr(unix.ALG_SET_KEY), uintptr(0), uintptr(0), 0)

		if e1 != 0 {
			err = errors.New("setsockopt failed")
			return
		}
	}

	if err != nil {
		return
	}

	apifd, _, _ := unix.Syscall(unix.SYS_ACCEPT, uintptr(fd), 0, 0)

	return cryptoAPI(apifd, unix.ALG_OP_ENCRYPT, iv, pad(diversifier, false))
}

// adapted from github.com/f-secure-foundry/interlock/internal/aes
func encryptOFB(key []byte, iv []byte, input *os.File, output *os.File) (err error) {
	block, err := aes.NewCipher(key)

	if err != nil {
		return
	}

	_, err = output.Write(iv)

	if err != nil {
		return
	}

	mac := hmac.New(sha256.New, key)
	mac.Write(iv)

	stream := cipher.NewOFB(block, iv)
	buf := make([]byte, 32*1024)

	for {
		n, er := input.Read(buf)

		if n > 0 {
			c := make([]byte, n)
			stream.XORKeyStream(c, buf[0:n])

			mac.Write(c)
			output.Write(c)
		}

		if er == io.EOF {
			break
		}

		if er != nil {
			err = er
			break
		}
	}

	if err != nil {
		return
	}

	_, err = output.Write(mac.Sum(nil))

	return
}

// adapted from github.com/f-secure-foundry/interlock/internal/aes
func decryptOFB(key []byte, iv []byte, input *os.File, output *os.File) (err error) {
	block, err := aes.NewCipher(key)

	if err != nil {
		return
	}

	stat, err := input.Stat()

	if err != nil {
		return
	}

	headerSize, err := input.Seek(0, 1)

	if err != nil {
		return
	}

	mac := hmac.New(sha256.New, key)
	mac.Write(iv)

	macSize := int64(mac.Size())
	limit := stat.Size() - headerSize - macSize

	ciphertextReader := io.LimitReader(input, limit)
	_, err = io.Copy(mac, ciphertextReader)

	if err != nil {
		return
	}

	inputMac := make([]byte, mac.Size())
	_, err = input.ReadAt(inputMac, stat.Size()-macSize)

	if err != nil {
		return
	}

	if !hmac.Equal(inputMac, mac.Sum(nil)) {
		return errors.New("invalid HMAC")
	}

	stream := cipher.NewOFB(block, iv)
	writer := &cipher.StreamWriter{S: stream, W: output}

	_, err = input.Seek(headerSize, 0)

	if err != nil {
		return
	}

	ciphertextReader = io.LimitReader(input, limit)

	_, err = io.Copy(writer, ciphertextReader)

	return
}

func pad(buf []byte, extraBlock bool) []byte {
	padLen := 0
	r := len(buf) % aes.BlockSize

	if r != 0 {
		padLen = aes.BlockSize - r
	} else if extraBlock {
		padLen = aes.BlockSize
	}

	padding := []byte{(byte)(padLen)}
	padding = bytes.Repeat(padding, padLen)
	buf = append(buf, padding...)

	return buf
}

//lint:ignore U1000 unused but left for reference
func unpad(buf []byte) []byte {
	return buf[:(len(buf) - int(buf[len(buf)-1]))]
}

func cryptoAPI(fd uintptr, mode uint32, iv []byte, input []byte) (output []byte, err error) {
	api := os.NewFile(fd, "cryptoAPI")

	cmsg := buildCmsg(mode, iv)

	output = make([]byte, len(input))
	err = syscall.Sendmsg(int(fd), input, cmsg, nil, 0)

	if err != nil {
		return
	}

	_, err = api.Read(output)

	return
}

func buildCmsg(mode uint32, iv []byte) []byte {
	cbuf := make([]byte, syscall.CmsgSpace(4)+syscall.CmsgSpace(20))

	cmsg := (*syscall.Cmsghdr)(unsafe.Pointer(&cbuf[0]))
	cmsg.Level = unix.SOL_ALG
	cmsg.Type = unix.ALG_SET_OP
	cmsg.SetLen(syscall.CmsgLen(4))

	op := (*uint32)(unsafe.Pointer(CMSG_DATA(cmsg)))
	*op = mode

	cmsg = (*syscall.Cmsghdr)(unsafe.Pointer(&cbuf[syscall.CmsgSpace(4)]))
	cmsg.Level = unix.SOL_ALG
	cmsg.Type = unix.ALG_SET_IV
	cmsg.SetLen(syscall.CmsgLen(20))

	alg_iv := (*af_alg_iv)(unsafe.Pointer(CMSG_DATA(cmsg)))
	alg_iv.ivlen = uint32(len(iv))
	copy(alg_iv.iv[:], iv)

	return cbuf
}

func CMSG_DATA(cmsg *syscall.Cmsghdr) unsafe.Pointer {
	return unsafe.Pointer(uintptr(unsafe.Pointer(cmsg)) + uintptr(syscall.SizeofCmsghdr))
}
