package pppoe

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestParseDiscovery(t *testing.T) {
	tests := []struct {
		desc        string
		raw         []byte
		want        *discoveryPacket
		wantErr     bool
		skipUnparse bool
	}{
		{
			desc: "PADO",
			raw:  []byte{0x11, 7, 0, 0, 0, 4, 1, 1, 0, 0},
			want: &discoveryPacket{
				Code: 7,
				Tags: map[int][]byte{
					pppoeTagServiceName: []byte{},
				},
			},
		},
		{
			desc: "PADO with cookie",
			raw:  []byte{0x11, 7, 0, 0, 0, 11, 1, 1, 0, 0, 1, 4, 0, 3, 'N', 'O', 'M'},
			want: &discoveryPacket{
				Code: 7,
				Tags: map[int][]byte{
					pppoeTagServiceName: []byte{},
					pppoeTagCookie:      []byte("NOM"),
				},
			},
		},

		{
			desc: "PADS",
			raw:  []byte{0x11, 0x65, 0x42, 0x43, 0, 4, 1, 1, 0, 0},
			want: &discoveryPacket{
				Code:      0x65,
				SessionID: 0x4243,
				Tags: map[int][]byte{
					pppoeTagServiceName: []byte{},
				},
			},
		},

		{
			desc:    "short",
			raw:     []byte{0x11},
			wantErr: true,
		},
		{
			desc:    "not pppoe",
			raw:     []byte{0, 0, 0, 0, 0, 0, 0, 0, 0},
			wantErr: true,
		},
		{
			desc:    "short Tags array length",
			raw:     []byte{0x11, 7, 0, 0, 0, 2, 1, 1, 0, 0},
			wantErr: true,
		},
		{
			desc:    "long Tags array length",
			raw:     []byte{0x11, 7, 0, 0, 200, 200, 1, 1, 0, 0},
			wantErr: true,
		},
		{
			desc:    "Tags trailing garbage",
			raw:     []byte{0x11, 7, 0, 0, 0, 5, 1, 1, 0, 0, 0},
			wantErr: true,
		},
		{
			desc:    "wrong service name",
			raw:     []byte{0x11, 7, 0, 0, 0, 5, 1, 1, 0, 1, 'A'},
			wantErr: true,
		},
		{
			desc:    "overflowing Tags",
			raw:     []byte{0x11, 7, 0, 0, 0, 4, 1, 1, 200, 200},
			wantErr: true,
		},

		// These are some real packets, stolen from real ISP
		// handshakes.
		{
			desc: "real isp PADI",
			raw:  []byte{0x11, 0x09, 0x00, 0x00, 0x00, 0x04, 0x01, 0x01, 0x00, 0x00},
			want: &discoveryPacket{
				Code: 0x09,
				Tags: map[int][]byte{
					pppoeTagServiceName: []byte{},
				},
			},
		},
		{
			desc: "real isp PADO",
			raw: []byte{
				0x11, 0x07, 0x00, 0x00, 0x00, 0x38, 0x01, 0x02, 0x00, 0x1c,
				0x74, 0x75, 0x6b, 0x77, 0x2d, 0x64, 0x73, 0x6c, 0x2d, 0x67,
				0x77, 0x30, 0x31, 0x2e, 0x74, 0x75, 0x6b, 0x77, 0x2e, 0x71,
				0x77, 0x65, 0x73, 0x74, 0x2e, 0x6e, 0x65, 0x74, 0x01, 0x01,
				0x00, 0x00, 0x01, 0x04, 0x00, 0x10, 0x64, 0xb1, 0x40, 0x19,
				0xe3, 0x6e, 0x03, 0xb6, 0x5c, 0x2f, 0xdb, 0x9e, 0x63, 0x88,
				0x34, 0xdb,
			},
			want: &discoveryPacket{
				Code:      0x07,
				SessionID: 0,
				Tags: map[int][]byte{
					pppoeTagServiceName: []byte{},
					pppoeTagACName:      []byte("tukw-dsl-gw01.tukw.qwest.net"),
					pppoeTagCookie: []byte{
						0x64, 0xb1, 0x40, 0x19, 0xe3, 0x6e, 0x03, 0xb6,
						0x5c, 0x2f, 0xdb, 0x9e, 0x63, 0x88, 0x34, 0xdb,
					},
				},
			},
			skipUnparse: true, // Not idempotent due to ordering of Tags
		},
		{
			desc: "real isp PADR",
			raw: []byte{
				0x11, 0x19, 0x00, 0x00, 0x00, 0x18, 0x01, 0x01, 0x00, 0x00,
				0x01, 0x04, 0x00, 0x10, 0x64, 0xb1, 0x40, 0x19, 0xe3, 0x6e,
				0x03, 0xb6, 0x5c, 0x2f, 0xdb, 0x9e, 0x63, 0x88, 0x34, 0xdb,
			},
			want: &discoveryPacket{
				Code:      0x19,
				SessionID: 0,
				Tags: map[int][]byte{
					pppoeTagServiceName: []byte{},
					pppoeTagCookie: []byte{
						0x64, 0xb1, 0x40, 0x19, 0xe3, 0x6e, 0x03, 0xb6,
						0x5c, 0x2f, 0xdb, 0x9e, 0x63, 0x88, 0x34, 0xdb,
					},
				},
			},
		},
		{
			desc: "real isp PADS",
			raw: []byte{
				0x11, 0x65, 0x01, 0xeb, 0x00, 0x38, 0x01, 0x01, 0x00, 0x00,
				0x01, 0x02, 0x00, 0x1c, 0x74, 0x75, 0x6b, 0x77, 0x2d, 0x64,
				0x73, 0x6c, 0x2d, 0x67, 0x77, 0x30, 0x31, 0x2e, 0x74, 0x75,
				0x6b, 0x77, 0x2e, 0x71, 0x77, 0x65, 0x73, 0x74, 0x2e, 0x6e,
				0x65, 0x74, 0x01, 0x04, 0x00, 0x10, 0x64, 0xb1, 0x40, 0x19,
				0xe3, 0x6e, 0x03, 0xb6, 0x5c, 0x2f, 0xdb, 0x9e, 0x63, 0x88,
				0x34, 0xdb,
			},
			want: &discoveryPacket{
				Code:      0x65,
				SessionID: 0x01eb,
				Tags: map[int][]byte{
					pppoeTagServiceName: []byte{},
					pppoeTagACName:      []byte("tukw-dsl-gw01.tukw.qwest.net"),
					pppoeTagCookie: []byte{
						0x64, 0xb1, 0x40, 0x19, 0xe3, 0x6e, 0x03, 0xb6,
						0x5c, 0x2f, 0xdb, 0x9e, 0x63, 0x88, 0x34, 0xdb,
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			got, gotErr := parseDiscoveryPacket(test.raw)
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

			// Also test that we can unparse the parsed packet back
			// into their original form.
			if !test.skipUnparse {
				gotRaw := encodeDiscoveryPacket(got)
				if diff := cmp.Diff(test.raw, gotRaw); diff != "" {
					t.Fatalf("wrong unparse: (-want, +got)\n%s", diff)
				}
			}
		})
	}
}
