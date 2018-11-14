package ppp

import (
	"bytes"
	"context"
	"testing"
	"time"
)

func TestPADIPADO(t *testing.T) {
	if err := canTest(); err != nil {
		t.Skipf("can't run privileged tests: %v", err)
	}

	close, err := startServer()
	if err != nil {
		t.Fatalf("couldn't start pppd container: %v", err)
	}
	defer close()

	conn, err := newDiscoveryConn("docker0")
	if err != nil {
		t.Fatal(err)
	}
	if err := sendPADI(conn); err != nil {
		t.Fatalf("sending PADI: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, cookie, err := readPADO(ctx, conn)
	if err != nil {
		t.Fatalf("reading PADO: %v", err)
	}
	// Our test container sends PPPoE cookies. Did we get one?
	if len(cookie) == 0 {
		t.Fatal("didn't get PPPoE cookie in PADO")
	}
}

func TestParsePADO(t *testing.T) {
	tests := []struct {
		desc       string
		raw        []byte
		wantCookie []byte
		wantErr    bool
	}{
		{
			desc:       "good",
			raw:        []byte{0x11, 7, 0, 0, 0, 4, 1, 1, 0, 0},
			wantCookie: []byte{},
		},
		{
			desc:       "good with cookie",
			raw:        []byte{0x11, 7, 0, 0, 0, 11, 1, 1, 0, 0, 1, 4, 0, 3, 'N', 'O', 'M'},
			wantCookie: []byte("NOM"),
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
			desc:    "not pado",
			raw:     padiPacket,
			wantErr: true,
		},
		{
			desc:    "has session ID",
			raw:     []byte{0x11, 7, 42, 42, 0, 4, 1, 1, 0, 0},
			wantErr: true,
		},
		{
			desc:    "short TLV array length",
			raw:     []byte{0x11, 7, 0, 0, 0, 2, 1, 1, 0, 0},
			wantErr: true,
		},
		{
			desc:    "long TLV array length",
			raw:     []byte{0x11, 7, 0, 0, 200, 200, 1, 1, 0, 0},
			wantErr: true,
		},
		{
			desc:    "TLV trailing garbage",
			raw:     []byte{0x11, 7, 0, 0, 0, 5, 1, 1, 0, 0, 0},
			wantErr: true,
		},
		{
			desc:    "wrong service name",
			raw:     []byte{0x11, 7, 0, 0, 0, 5, 1, 1, 0, 1, 'A'},
			wantErr: true,
		},
		{
			desc:    "overflowing TLV",
			raw:     []byte{0x11, 7, 0, 0, 0, 4, 1, 1, 200, 200},
			wantErr: true,
		},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			gotCookie, gotErr := parsePADO(test.raw)
			if gotErr != nil && !test.wantErr {
				t.Fatalf("unexpected error %v", gotErr)
			} else if gotErr == nil && test.wantErr {
				t.Fatalf("unexpected success")
			}

			if !bytes.Equal(gotCookie, test.wantCookie) {
				t.Fatalf("wrong cookie. got %v, want %v", gotCookie, test.wantCookie)
			}
		})
	}
}
