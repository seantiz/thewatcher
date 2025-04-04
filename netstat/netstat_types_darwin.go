//lint:file-ignore U1000 Ignore all unused code

package netstat

const (
	sizeofPtr      = 0x8
	sizeofShort    = 0x2
	sizeofInt      = 0x4
	sizeofLong     = 0x8
	sizeofLongLong = 0x8
)

type (
	_C_short     int16
	_C_int       int32
	_C_long      int64
	_C_long_long int64
)

type In6Addr struct {
	X__u6_addr [16]byte
}

type InAddr4in6 struct {
	Pad32 [3]uint32
	Addr4 [4]byte /* in_addr */
}

type XSockbuf struct {
	Cc    uint32
	Hiwat uint32
	Mbcnt uint32
	Mbmax uint32
	Lowat int32
	Flags int16
	Timeo int16
}

type XSocket64 struct {
	Xso_len      uint32
	Pad_cgo_0    [8]byte
	So_type      int16
	So_options   int16
	So_linger    int16
	So_state     int16
	Pad_cgo_1    [8]byte
	Xso_protocol int32
	Xso_family   int32
	So_qlen      int16
	So_incqlen   int16
	So_qlimit    int16
	So_timeo     int16
	So_error     uint16
	So_pgid      int32
	So_oobmark   uint32
	So_rcv       XSockbuf
	So_snd       XSockbuf
	So_uid       uint32
}

type Xinpgen struct {
	Len   uint32
	Count uint32
	Gen   uint64
	Sogen uint64
}

type InPCB64ListEntry struct {
	Next uint64
	Prev uint64
}

type Xinpcb64 struct {
	Xi_len          uint64
	Xi_inpp         uint64
	Inp_fport       uint16
	Inp_lport       uint16
	Pad_cgo_0       [64]byte
	Inp_flags       int32
	Inp_flow        uint32
	Inp_vflag       uint8
	Inp_ip_ttl      uint8
	Inp_ip_p        uint8
	Pad_cgo_1       [1]byte
	Inp_dependfaddr [16]byte
	Inp_dependladdr [16]byte
	// Inp_depend4	_Ctype_struct___3
	// Inp_depend6	_Ctype_struct___4
	Xi_socket XSocket64
	Pad_cgo_2 [8]byte
}

type XTCPcb64 struct {
	Xt_len            uint32
	Pad_cgo_0         [256]byte
	T_segq            uint64
	T_dupacks         int32
	T_timer           [4]int32
	T_state           int32
	T_flags           uint32
	T_force           int32
	Snd_una           uint32
	Snd_max           uint32
	Snd_nxt           uint32
	Snd_up            uint32
	Snd_wl1           uint32
	Snd_wl2           uint32
	Iss               uint32
	Irs               uint32
	Rcv_nxt           uint32
	Rcv_adv           uint32
	Rcv_wnd           uint32
	Rcv_up            uint32
	Snd_wnd           uint32
	Snd_cwnd          uint32
	Snd_ssthresh      uint32
	T_maxopd          uint32
	T_rcvtime         uint32
	T_starttime       uint32
	T_rtttime         int32
	T_rtseq           uint32
	T_rxtcur          int32
	T_maxseg          uint32
	T_srtt            int32
	T_rttvar          int32
	T_rxtshift        int32
	T_rttmin          uint32
	T_rttupdated      uint32
	Max_sndwnd        uint32
	T_softerror       int32
	T_oobflags        int8
	T_iobc            int8
	Snd_scale         uint8
	Rcv_scale         uint8
	Request_r_scale   uint8
	Requested_s_scale uint8
	Ts_recent         uint32
	Ts_recent_age     uint32
	Last_ack_sent     uint32
	Cc_send           uint32
	Cc_recv           uint32
	Snd_recover       uint32
	Snd_cwnd_prev     uint32
	Snd_ssthresh_prev uint32
	T_badrxtwin       uint32
	Xt_alignment_hack uint64
}
