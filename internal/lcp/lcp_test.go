package lcp

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestParseLCP(t *testing.T) {
	tests := []struct {
		desc        string
		raw         []byte
		want        *Packet
		wantErr     bool
		skipUnparse bool
	}{
		{
			desc: "minimal Configure-Request",
			raw:  []byte{0xc0, 0x21, 1, 1, 0, 4},
			want: &Packet{
				Code:           typeConfigureRequest,
				ID:             1,
				UnknownOptions: map[uint8][]byte{},
			},
		},

		{
			desc: "Configure-Request with all options",
			raw: []byte{
				0xc0, 0x21, // Frame type = LCP
				1,     // Configure-Request
				1,     // ID = 1
				0, 22, // Packet length
				1, 4, 5, 220, // MRU = 1500
				3, 5, 0xc2, 0x23, 5, // AuthProto = CHAP-MD5
				5, 6, 1, 2, 3, 4, // Magic = 0x01020304
				42, 3, 1, // Some unknown option = 1
			},
			want: &Packet{
				Code:          typeConfigureRequest,
				ID:            1,
				MRU:           1500,
				Magic:         0x01020304,
				AuthProto:     0xc223,
				CHAPAlgorithm: 5,
				UnknownOptions: map[uint8][]byte{
					42: []byte{1},
				},
			},
		},

		{
			desc: "Configure-Ack with all options",
			raw: []byte{
				0xc0, 0x21, // Frame type = LCP
				2,     // Configure-Ack
				1,     // ID = 1
				0, 22, // Packet length
				1, 4, 5, 220, // MRU = 1500
				3, 5, 0xc2, 0x23, 5, // AuthProto = CHAP-MD5
				5, 6, 1, 2, 3, 4, // Magic = 0x01020304
				42, 3, 1, // Some unknown option = 1
			},
			want: &Packet{
				Code:          typeConfigureAck,
				ID:            1,
				MRU:           1500,
				Magic:         0x01020304,
				AuthProto:     0xc223,
				CHAPAlgorithm: 5,
				UnknownOptions: map[uint8][]byte{
					42: []byte{1},
				},
			},
		},

		{
			desc: "Configure-Nak with all options",
			raw: []byte{
				0xc0, 0x21, // Frame type = LCP
				3,     // Configure-Nak
				1,     // ID = 1
				0, 22, // Packet length
				1, 4, 5, 220, // MRU = 1500
				3, 5, 0xc2, 0x23, 5, // AuthProto = CHAP-MD5
				5, 6, 1, 2, 3, 4, // Magic = 0x01020304
				42, 3, 1, // Some unknown option = 1
			},
			want: &Packet{
				Code:          typeConfigureNak,
				ID:            1,
				MRU:           1500,
				Magic:         0x01020304,
				AuthProto:     0xc223,
				CHAPAlgorithm: 5,
				UnknownOptions: map[uint8][]byte{
					42: []byte{1},
				},
			},
		},

		{
			desc: "Configure-Reject with all options",
			raw: []byte{
				0xc0, 0x21, // Frame type = LCP
				4,     // Configure-Reject
				1,     // ID = 1
				0, 22, // Packet length
				1, 4, 5, 220, // MRU = 1500
				3, 5, 0xc2, 0x23, 5, // AuthProto = CHAP-MD5
				5, 6, 1, 2, 3, 4, // Magic = 0x01020304
				42, 3, 1, // Some unknown option = 1
			},
			want: &Packet{
				Code:          typeConfigureReject,
				ID:            1,
				MRU:           1500,
				Magic:         0x01020304,
				AuthProto:     0xc223,
				CHAPAlgorithm: 5,
				UnknownOptions: map[uint8][]byte{
					42: []byte{1},
				},
			},
		},

		{
			desc: "Protocol-Reject",
			raw: []byte{
				0xc0, 0x21, // Frame type = LCP
				8,     // Protocol-Reject
				1,     // ID = 1
				0, 12, // Packet length
				0x12, 0x34, // Rejected proto = 0x1234
				1, 2, 3, 4, 5, 6, // Rejected packet, mirrored back
			},
			want: &Packet{
				Code:             typeProtocolReject,
				ID:               1,
				RejectedProtocol: 0x1234,
				Data:             []byte{1, 2, 3, 4, 5, 6},
			},
		},

		{
			desc: "Code-Reject",
			raw: []byte{
				0xc0, 0x21, // Frame type = LCP
				7,     // Code-Reject
				1,     // ID = 1
				0, 12, // Packet length
				1, 2, 3, 4, 5, 6, 7, 8, // Rejected packet, mirrored back
			},
			want: &Packet{
				Code: typeCodeReject,
				ID:   1,
				Data: []byte{1, 2, 3, 4, 5, 6, 7, 8},
			},
		},

		{
			desc: "Terminate-Request",
			raw: []byte{
				0xc0, 0x21, // Frame type = LCP
				5,     // Terminate-Request
				1,     // ID = 1
				0, 12, // Packet length
				1, 2, 3, 4, 5, 6, 7, 8, // Some explanation for the terminate
			},
			want: &Packet{
				Code: typeTerminateRequest,
				ID:   1,
				Data: []byte{1, 2, 3, 4, 5, 6, 7, 8},
			},
		},

		{
			desc: "Terminate-Ack",
			raw: []byte{
				0xc0, 0x21, // Frame type = LCP
				6,     // Terminate-Ack
				1,     // ID = 1
				0, 12, // Packet length
				1, 2, 3, 4, 5, 6, 7, 8, // Some explanation for the terminate
			},
			want: &Packet{
				Code: typeTerminateAck,
				ID:   1,
				Data: []byte{1, 2, 3, 4, 5, 6, 7, 8},
			},
		},

		{
			desc: "Echo-Request",
			raw: []byte{
				0xc0, 0x21, // Frame type = LCP
				9,     // Echo-Request
				1,     // ID = 1
				0, 12, // Packet length
				1, 2, 3, 4, // Magic
				5, 6, 7, 8, // Some data
			},
			want: &Packet{
				Code:  typeEchoRequest,
				ID:    1,
				Magic: 0x01020304,
				Data:  []byte{5, 6, 7, 8},
			},
		},

		{
			desc: "Echo-Reply",
			raw: []byte{
				0xc0, 0x21, // Frame type = LCP
				10,    // Echo-Reply
				1,     // ID = 1
				0, 12, // Packet length
				1, 2, 3, 4, // Magic
				5, 6, 7, 8, // Some data
			},
			want: &Packet{
				Code:  typeEchoReply,
				ID:    1,
				Magic: 0x01020304,
				Data:  []byte{5, 6, 7, 8},
			},
		},

		{
			desc: "Discard-Request",
			raw: []byte{
				0xc0, 0x21, // Frame type = LCP
				11,    // Discard-Request
				1,     // ID = 1
				0, 12, // Packet length
				1, 2, 3, 4, // Magic
				5, 6, 7, 8, // Some data
			},
			want: &Packet{
				Code:  typeDiscardRequest,
				ID:    1,
				Magic: 0x01020304,
				Data:  []byte{5, 6, 7, 8},
			},
		},

		// Frames taken from a real pppd talking to us
		{
			desc: "ISP Configure-Request",
			raw:  []byte{0xc0, 0x21, 0x01, 0x01, 0x00, 0x13, 0x01, 0x04, 0x05, 0xd4, 0x03, 0x05, 0xc2, 0x23, 0x05, 0x05, 0x06, 0x28, 0xa2, 0x88, 0x93},
			want: &Packet{
				Code:           typeConfigureRequest,
				ID:             1,
				MRU:            1492,
				Magic:          0x28a28893,
				AuthProto:      0xc223,
				CHAPAlgorithm:  5,
				UnknownOptions: map[uint8][]byte{},
			},
		},

		{
			desc: "ISP Terminate-Request",
			raw:  []byte{0xc0, 0x21, 0x05, 0x02, 0x00, 0x10, 0x55, 0x73, 0x65, 0x72, 0x20, 0x72, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74},
			want: &Packet{
				Code: typeTerminateRequest,
				ID:   2,
				Data: []byte("User request"),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			got, gotErr := Parse(test.raw)
			if gotErr != nil && !test.wantErr {
				t.Fatalf("unexpected error %v", gotErr)
			} else if gotErr == nil && test.wantErr {
				t.Fatalf("unexpected success")
			}
			if test.wantErr {
				return
			}

			if diff := cmp.Diff(test.want, got); diff != "" {
				t.Fatalf("wrong parse: (-want +got)\n%s", diff)
			}

			if test.skipUnparse {
				return
			}

			gotRaw := got.Bytes()
			if diff := cmp.Diff(test.raw, gotRaw); diff != "" {
				t.Fatalf("wrong unparse: (-want +got)\n%s", diff)
			}
		})
	}
}
