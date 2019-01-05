package handshake

import (
	"encoding/hex"
	"math/rand"
	"strings"

	"github.com/lucas-clemente/quic-go/internal/protocol"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Initial AEAD using AES-GCM", func() {
	split := func(s string) (slice []byte) {
		for _, ss := range strings.Split(s, " ") {
			if ss[0:2] == "0x" {
				ss = ss[2:]
			}
			d, err := hex.DecodeString(ss)
			Expect(err).ToNot(HaveOccurred())
			slice = append(slice, d...)
		}
		return
	}

	It("converts the string representation used in the draft into byte slices", func() {
		Expect(split("0xdeadbeef")).To(Equal([]byte{0xde, 0xad, 0xbe, 0xef}))
		Expect(split("deadbeef")).To(Equal([]byte{0xde, 0xad, 0xbe, 0xef}))
		Expect(split("dead beef")).To(Equal([]byte{0xde, 0xad, 0xbe, 0xef}))
	})

	// values taken from https://github.com/quicwg/base-drafts/wiki/Test-Vector-for-the-Clear-Text-AEAD-key-derivation
	Context("using the test vector from the QUIC draft", func() {
		var connID protocol.ConnectionID

		BeforeEach(func() {
			connID = protocol.ConnectionID(split("0x8394c8f03e515708"))
		})

		It("computes the client key and IV", func() {
			clientSecret, _ := computeSecrets(connID)
			Expect(clientSecret).To(Equal(split("8a3515a14ae3c31b9c2d6d5bc58538ca 5cd2baa119087143e60887428dcb52f6")))
			key, pnKey, iv := computeInitialKeyAndIV(clientSecret)
			Expect(key).To(Equal(split("98b0d7e5e7a402c67c33f350fa65ea54")))
			Expect(iv).To(Equal(split("19e94387805eb0b46c03a788")))
			Expect(pnKey).To(Equal(split("0edd982a6ac527f2eddcbb7348dea5d7")))
		})

		It("computes the server key and IV", func() {
			_, serverSecret := computeSecrets(connID)
			Expect(serverSecret).To(Equal(split("47b2eaea6c266e32c0697a9e2a898bdf 5c4fb3e5ac34f0e549bf2c58581a3811")))
			key, pnKey, iv := computeInitialKeyAndIV(serverSecret)
			Expect(key).To(Equal(split("9a8be902a9bdd91d16064ca118045fb4")))
			Expect(iv).To(Equal(split("0a82086d32205ba22241d8dc")))
			Expect(pnKey).To(Equal(split("94b9452d2b3c7c7f6da7fdd8593537fd")))
		})

		It("encrypts the client's Initial", func() {
			sealer, _, err := newInitialAEAD(connID, protocol.PerspectiveClient)
			Expect(err).ToNot(HaveOccurred())
			header := split("c3ff000012508394c8f03e51570800449f00000000")
			data := split("060040c4010000c003036660261ff947 cea49cce6cfad687f457cf1b14531ba1 4131a0e8f309a1d0b9c4000006130113 031302010000910000000b0009000006 736572766572ff01000100000a001400 12001d00170018001901000101010201 03010400230000003300260024001d00 204cfdfcd178b784bf328cae793b136f 2aedce005ff183d7bb14952072366470 37002b0003020304000d0020001e0403 05030603020308040805080604010501 060102010402050206020202002d0002 0101001c00024001")
			data = append(data, make([]byte, 1163-len(data))...) // add PADDING
			sealed := sealer.Seal(nil, data, 0, header)
			sample := sealed[0:16]
			Expect(sample).To(Equal(split("819836c8042daceb739f1fa1fa76c82b")))
			sealer.EncryptHeader(sample, &header[0], header[len(header)-4:])
			Expect(header[0]).To(Equal(byte(0xc0)))
			Expect(header[17:21]).To(Equal(split("ddef27af")))
			packet := append(header, sealed...)
			Expect(packet).To(Equal(split("c0ff000012508394c8f03e5157080044 9fddef27af819836c8042daceb739f1f a1fa76c82b2419eb0f33d87dacb88437 6ec11ef544388472f4446262af71ec6e f2c571f7979d1c3deb06ccf85a16178d 1712d124e18bd80b2038736f1c233a55 77d79d9eeefd617bec8fe2b57655e446 8fa62c12c3362308dd136b494b7c257d af0a8343fd8c228f06fd77f032d038ba 018cecfc0e8e22d1c0fabf45e1b46e11 03cbaf3edc82e76f22202ef8de0d90af d3753e38a1e830fc2d5cd5faf583a1af 62b9d0db001b7fe9c5901a9e7befeb44 ee27fb46eaab7c38a9e4373a8a249175 4e2a99ed6bf33879b8b983b0e3d1d075 b42e68693a4a4f4a37a59b33881c77c4 ab11027101eb1ebf0a7e1fecc0d225a6 b808a7a793529f2b19bf82a533784449 988da4cb0d884ca4a30546c5706798a8 e4aeb5bd4847f29084347b90b0853003 c753784b6523ab026116c39f8ec33683 9a19ebcd9bab1fb384c073ec9b92ae2a 5b23d26602609b6639692b23e59b1847 732dfb03f381fd81200691c6d82424a6 a4f9e586dbe9e6c1310924a35e487acf c93feb032a0462baf4248a02c26a1846 0f082d46118899059a0fa1b2e44750e4 7ac2ab802ff6e53afbfcd5b38fb543bb 317b57def7b81dc230f7c37e2807433e db7f18e2ebc2da3742fd2fd061109685 fe09d2c4cf4d5cfcddf3079bec24a613 1a3146fda9010e8f8db0478b265ea875 e055d587da61ae8c88c854861b41e38e 4a720863d4cbad1de2a7a57195b9cebc bb5273e944beb1a13db9328a97b20b02 ab53613f1e120a42ac6474f555923452 220e791ab99b251b79b7f07ed11916e3 f8309925d85558097e2c4c86ba445f25 0db2bb3ee7d5813256a86af9882a26b9 45d7555283de6a9f88ee07e93fa99378 d213fbc17670725380999dbcba21a7f6 d683591944910e500c81a65f7df10320 215888038fbfb1c7d6a050748271302f f3ccf5ab7db3f9d8b99b56af48ba9d49 e49bf590b57b23f981a27a2b4a90383a f45614a7dcff57cc8aec881eaf0732f3 c6db0326b05350be8d4761631bd3a1a0 a47e9ca4903b8ac1a2e146dc50ca8cd1 1a248b159c8d694ec15ba3e3631b1a03 4370400c8e9d047990a6c630a6a7a8c2 da55cc08785317620b537cd0eeb771eb 05cd8d9285df6a67f42272034f7e130f c4357a88627519d1855613ecdcaeb6f4 e85f442ea78c72ff6b5e6db917ace3fd a8b124597d7bdc69b77753b03b1d47a7 3f39c2ed9477d573b6af2f25a2ca2685 4a0fc77474b9d7b2cb02c0ab555a8446 398f77f829f8504fdcd7ad6a76e978aa 87a71dcda2bcc187ccb37624e9ab19c2 810f5036cd96904cfe74ca1aed2a8c3e b6164247f5e7dcfbc5476a7d57b9b151 adbab45c5fe08ad41b39f21fe99359de 9ff08fce075cb3821d1e835a893a79bb 6b4c5867ef7473846ac106510ba11a85 b9bd555cf3dda2607aa720b884bf1616 6db955f0a0cd69049e81e4ec51c55679 876b34f608345845d947114fcc705d3c ac7455cdb187a0a4785c3fea269d6def f57c0f9bb47dd9da0a00bd19e1ed1790 ad4995bb54607c6821a113925f727448 c58f3d5917c121092ee59393adbcfc67 9019c4e6048b3991a6c5bfc4c3db7238 71e9eee7a05727414c98061eec591df6 f95d2097ace4ccbef236ba300d3aea2b 06aaa7b486262919d041d18e79d8b24c")))
		})

		It("encrypt the server's Initial", func() {
			sealer, _, err := newInitialAEAD(connID, protocol.PerspectiveServer)
			Expect(err).ToNot(HaveOccurred())
			header := split("c1ff00001205f067a5502a4262b50040740000")
			data := split("0d0000000018410a020000560303eefc e7f7b37ba1d1632e96677825ddf73988 cfc79825df566dc5430b9a045a120013 0100002e00330024001d00209d3c940d 89690b84d08a60993c144eca684d1081 287c834d5311bcf32bb9da1a002b0002 0304")
			sealed := sealer.Seal(nil, data, 0, header)
			sample := sealed[2:18]
			Expect(sample).To(Equal(split("bf65a03e3e7ce041087cb11fd7ba338b")))
			sealer.EncryptHeader(sample, &header[0], header[len(header)-2:])
			Expect(header).To(Equal(split("c2ff00001205f067a5502a4262b500407428f6")))
			packet := append(header, sealed...)
			Expect(packet).To(Equal(split("c2ff00001205f067a5502a4262b50040 7428f63f2abf65a03e3e7ce041087cb1 1fd7ba338b4fcd9e22bbdb5cff66218a 8ac48269098d73577222d3e02af7eb40 1796a2d67c1c9e89d0dc5a5dfc6ceead f4ebd4eae0e3185dfe99a7f59288afaa 75539cfad2bab440126a57213325f86d 3b8a5cb13b33f73a6317e34f73ac35ba 3d7a1f0b5c")))
		})
	})

	It("seals and opens", func() {
		connectionID := protocol.ConnectionID{0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef}
		clientSealer, clientOpener, err := newInitialAEAD(connectionID, protocol.PerspectiveClient)
		Expect(err).ToNot(HaveOccurred())
		serverSealer, serverOpener, err := newInitialAEAD(connectionID, protocol.PerspectiveServer)
		Expect(err).ToNot(HaveOccurred())

		clientMessage := clientSealer.Seal(nil, []byte("foobar"), 42, []byte("aad"))
		m, err := serverOpener.Open(nil, clientMessage, 42, []byte("aad"))
		Expect(err).ToNot(HaveOccurred())
		Expect(m).To(Equal([]byte("foobar")))
		serverMessage := serverSealer.Seal(nil, []byte("raboof"), 99, []byte("daa"))
		m, err = clientOpener.Open(nil, serverMessage, 99, []byte("daa"))
		Expect(err).ToNot(HaveOccurred())
		Expect(m).To(Equal([]byte("raboof")))
	})

	It("doesn't work if initialized with different connection IDs", func() {
		c1 := protocol.ConnectionID{0, 0, 0, 0, 0, 0, 0, 1}
		c2 := protocol.ConnectionID{0, 0, 0, 0, 0, 0, 0, 2}
		clientSealer, _, err := newInitialAEAD(c1, protocol.PerspectiveClient)
		Expect(err).ToNot(HaveOccurred())
		_, serverOpener, err := newInitialAEAD(c2, protocol.PerspectiveServer)
		Expect(err).ToNot(HaveOccurred())

		clientMessage := clientSealer.Seal(nil, []byte("foobar"), 42, []byte("aad"))
		_, err = serverOpener.Open(nil, clientMessage, 42, []byte("aad"))
		Expect(err).To(MatchError("cipher: message authentication failed"))
	})

	It("encrypts und decrypts the header", func() {
		connID := protocol.ConnectionID{0xde, 0xca, 0xfb, 0xad}
		clientSealer, clientOpener, err := newInitialAEAD(connID, protocol.PerspectiveClient)
		Expect(err).ToNot(HaveOccurred())
		serverSealer, serverOpener, err := newInitialAEAD(connID, protocol.PerspectiveServer)
		Expect(err).ToNot(HaveOccurred())

		// the first byte and the last 4 bytes should be encrypted
		header := []byte{0x5e, 0, 1, 2, 3, 4, 0xde, 0xad, 0xbe, 0xef}
		sample := make([]byte, 16)
		rand.Read(sample)
		clientSealer.EncryptHeader(sample, &header[0], header[6:10])
		// only the last 4 bits of the first byte are encrypted. Check that the first 4 bits are unmodified
		Expect(header[0] & 0xf0).To(Equal(byte(0x5e & 0xf0)))
		Expect(header[1:6]).To(Equal([]byte{0, 1, 2, 3, 4}))
		Expect(header[6:10]).ToNot(Equal([]byte{0xde, 0xad, 0xbe, 0xef}))
		serverOpener.DecryptHeader(sample, &header[0], header[6:10])
		Expect(header[0]).To(Equal(byte(0x5e)))
		Expect(header[1:6]).To(Equal([]byte{0, 1, 2, 3, 4}))
		Expect(header[6:10]).To(Equal([]byte{0xde, 0xad, 0xbe, 0xef}))

		serverSealer.EncryptHeader(sample, &header[0], header[6:10])
		// only the last 4 bits of the first byte are encrypted. Check that the first 4 bits are unmodified
		Expect(header[0] & 0xf0).To(Equal(byte(0x5e & 0xf0)))
		Expect(header[1:6]).To(Equal([]byte{0, 1, 2, 3, 4}))
		Expect(header[6:10]).ToNot(Equal([]byte{0xde, 0xad, 0xbe, 0xef}))
		clientOpener.DecryptHeader(sample, &header[0], header[6:10])
		Expect(header[0]).To(Equal(byte(0x5e)))
		Expect(header[1:6]).To(Equal([]byte{0, 1, 2, 3, 4}))
		Expect(header[6:10]).To(Equal([]byte{0xde, 0xad, 0xbe, 0xef}))
	})
})
