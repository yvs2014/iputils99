#ifndef PO_H
#define PO_H

#ifdef USE_NLS
#include <locale.h>
#include <libintl.h>
#define BIND_NLS do {                            \
	setlocale(LC_ALL, "");                   \
	bindtextdomain(PACKAGE_NAME, LOCALEDIR); \
	textdomain(PACKAGE_NAME);                \
} while (0)
#define _(text) gettext(text)
#define _n(singular, plural, number) ngettext((singular), (plural), (number))
#else
#define BIND_NLS NOOP
#define _(text) text
#define _n(singular, plural, number) plural
#endif

#define WARN  "WARNING"
#define _WARN _(WARN)

#define _PING   _("PING")
#define _ARPING _("ARPING")

#define _FOR    _("for")
#define _FROM   _("from")
#define _FROM_H _("From")
#define _SEQ    _("seq")
#define _ID     _("id")
#define _TIME   _("time")
#define _MSEC   _("ms")
#define _RTT    _("rtt")

#define _PINGSTAT   _("ping statistics")
#define _RECV       _("received")
#define _DUPLICAT   _("duplicates")
#define _CORRUPT    _("corrupted")
#define _ERRORS	    _("errors")
#define _LOST       _("lost")
#define _UNINDENT   _("unidentified")
#define _REFUSED    _("refused")
#define _TRUNCATED  _("truncated")
#define _DUP        _("DUP")
#define _BAD_CSUM   _("BAD CHECKSUM")
#define _DIFF_ADDR  _("DIFFERENT ADDRESS")
#define _REACHED    _("reached")
#define _RECV_REPLY _("reply received")
#define _SEND_FAIL  _("send fail")

#define _PACKETS   _("packets")
#define _DATABYTES _("data bytes")
#define _BRDCAST   _("Broadcast")
#define _UNICAST   _("Unicast")
#define _PING_MC   _("Multicast ping")
#define _PING_BRD  _("Broadcast ping")

#define _PING_STATUS _("min/avg/ewma/max")
#define _TIMESTAT    _("rtt min/avg/max/mdev")
#define _ADAPTSTAT   _("ipg/ewma")
#define _PIPE        _("pipe")
#define _INFLIGHT    _("in-flight")
#define _MINIMAL     _("minimal")
#define _PROBLY      _("probably")
#define _HOPS_AWAY   _("hops away")

#define _PATTERN     _("PATTERN")
#define _PAYLOAD     _("PAYLOAD")
#define _MEASURE     _("measure")
#define _DELTA       _("delta")
#define _UNKNOWN     _("unknown")
#define _UNKN_CODE   _("unknown code")
#define _UNKN_QTYP   _("unknown qtype")
#define _UNKN_FAIL   _("Unknown failure")
#define _WRONG_BYTE  _("wrong byte #")
#define _EXP_0X      _("expected 0x")
#define _GOT_0X      _("got 0x")
#define _SEE_OPT_I   _("see -i option for details")

#define _NO_GOAL        _("No goal")
#define _TARGET         _("TARGET")
#define _HOST           _("HOST")
#define _HOST_L         _("host")
#define _LOCALHOST      _("LOCALHOST")
#define _USAGE          _("Usage")
#define _OPTIONS        _("options")
#define _OPTIONS_H      _("Options")
#define _FOR_MORE       _("For more details see")
#define _EXCL_OPTS      _("Mutually exclusive options")
#define _MISS_CAP       _("=> missing capability")
#define _LOCAL_ERR      _("Local error")
#define _NET_ERROR      _("Net error")
#define _MSG_TOOLONG    _("Message too long")
#define _PKT_SHORT      _("Packet too short")
#define _TIME_BACK      _("Time runs backwards")
#define _WRONG_PATT     _("Pattern must be specified as hex digits")
#define _BLANK_PATT     _("Blank pattern")
#define _NO_ANSWER      _("No answer yet")
#define _CANNOT_FLOOD   _("Cannot flood")
#define _MIN_OPT_I      _("Minimal user interval must be >=")
#define _ILL_PREINT     _("Illegal preload and/or interval")
#define _UNFILTERED     _("non-filtered out")
#define _NOT_FRAGM      _("does not fragment")
#define _MIN_MC         _("Minimal user interval for multicast ping must be >=")
#define _MIN_BRD        _("Minimal user interval for broadcast ping must be >=")
#define _NODIS_MC_LO    _("Cannot disable multicast loopback")
#define _SETMARK_FAIL   _("failed to set mark")
#define _SMALL_RCVBUF   _("Probably, rcvbuf is not enough to hold preload")
#define _SO_TS2IOCG     _("no SO_TIMESTAMP support, falling back to SIOCGSTAMP")
#define _CANNOT_COPY    _("Cannot copy")
#define _INV_SRCADDR    _("Invalid source address")
#define _INV_SRC        _("Invalid source")
#define _BAD_TIMING     _("Bad timing interval")
#define _VALUE_GT_3     _("Cannot set preload to value greater than 3")
#define _INV_TS_TYPE    _("Invalid timestamp type")
#define _WRONG_TS_LEN   _("timestamp length is not a multiple of 4")
#define _BAD_LINGER     _("Bad linger time")
#define _FORCE_RAW      _("ident 0 => forcing raw socket")
#define _EMBEDDED_ADDR4 _("Embedded IPv4 Address")
#define _TOOMANY_HOPS   _("Too many intermediate hops")
#define _WANT_BRD       _("Do you want to ping broadcast? Then -b. If not, check your local firewall rules")
#define _PINGING_BRD    _("Pinging broadcast address")
#define _ONLY_TSPRESPEC _("Only TSPRESPEC is allowed with intermediate hops")
#define _TOOMANY_TSHOPS _("Too many intermediate TS hops")
#define _NO_TS_HOPS     _("No intermediate hops for TSPRESPEC")
#define _SCOPE_DISCR    _("Scope discrepancy among the nodes")
#define _NI_ONLY_HDR    _("Nodeinfo packet can only have a header")
#define _NI_NOT_OVER4   _("Nodeinfo query cannot be sent over IPv4")
#define _NI_OPT_NOSET   _("Cannot set nodeinfo option")
#define _NI_ERR_QTYPE   _("Qtype conflict")
#define _NI_ERR_SUBJ    _("Subject type conflict")
#define _NI_ERR_IDN     _("IDN encoding error")
#define _NI_LONG_SCOPE  _("Too long scope name")
#define _NI_BAD_SUBJ    _("Inappropriate subject name")
#define _NI_DN_TOO_LONG _("dn_comp() returned too long result")

#define _CODE           _("code")
#define _INFO           _("info")
#define _NO_INFO        _("No info")
#define _MAX            _("max")

#define _ECHO_REPLY       _("Echo Reply")
#define _ECHO_REQUEST     _("Echo Request")
#define _EXTENSION        _("extension")
#define _UNREACH_DEST     _("Destination Unreachable")
#define _UNREACH_ADDR     _("Address Unreachable")
#define _UNREACH_NET      _("Net Unreachable")
#define _UNREACH_PROTO    _("Protocol Unreachable")
#define _UNREACH_PORT     _("Port unreachable")
#define _UNREACH_TOS_NET  _("Net Unreachable for ToS")
#define _UNREACH_TOS_HOST _("Host Unreachable for ToS")
#define _UNKN_NET         _("Net Unknown")
#define _UNKN_HOST        _("Host Unknown")
#define _PROH_NET         _("Net Prohibited")
#define _PROH_HOST        _("Host Prohibited")
#define _PROH_ADMIN       _("Administratively prohibited")
#define _SRC_HOST_ISOL    _("Source Host Isolated")
#define _SRC_ADDR_POLICY  _("Source address failed ingress/egress policy")
#define _NO_ROUTE         _("No route")
#define _SRC_ROUTE_FAIL   _("Source Route Failed")
#define _REJECT_ROUTE     _("Reject route to destination")
#define _NEED_FRAG        _("Frag needed and DF set")
#define _PKT_TOO_BIG      _("Packet too big")
#define _PKT_FILTERED     _("Packet filtered")
#define _PREC_VIOLATED    _("Precedence Violation")
#define _PREC_CUTOFF      _("Precedence Cutoff")
#define _SRC_BEYOND       _("Beyond scope of source address")
#define _SRC_QUENCH       _("Source Quench")
#define _REDIRECT         _("Redirect")
#define _NET              _("Network")
#define _HOST_H           _("Host")
#define _TOS_NET          _("ToS and Network")
#define _TOS_HOST         _("ToS and Host")
#define _NEW_NEXTHOP      _("New nexthop")
#define _TIME_EXCEED      _("Time exceeded")
#define _TTL_U            _("TTL")
#define _DEFRAG_FAIL      _("Defragmentation failure")
#define _PARAM_PROBLEM    _("Parameter problem")
#define _WRONG_HDR_FLD    _("Wrong header field")
#define _UNKN_HDR         _("Unknown header")
#define _UNKN_OPT         _("Unknown option")
#define _TIMESTAMP        _("Timestamp")
#define _TS_REPLY         _("Timestamp Reply")
#define _INFO_QUERY       _("Information Request")
#define _INFO_REPLY       _("Information Reply")
#define _ADDRMASK_QUERY   _("Address Mask Request")
#define _ADDRMASK_REPLY   _("Address Mask Reply")
#define _MLQ_QUERY        _("MLD Query")
#define _MLQ_REPORT       _("MLD Report")
#define _MLQ_REDUCT       _("MLD Reduction")
#define _UNKN_ICMP_TYPE   _("Unknown ICMP type")
#define _PARSE_ERR        _("parse error")
#define _UNEXP_ERR        _("unexpected error")

#define _TS_OPT           _("timestamp option")
#define __RECORD_ROUTE    "record route"
#define _RECORD_ROUTE     _(__RECORD_ROUTE)
#define _SAME_ROUTE       _("same route")
#define _NOT_STD          _("not-standard")
#define _ABS_NOT_STD      _("absolute not-standard")
#define _ABSOLUTE         _("absolute")
#define _UNREC_HOPS       _("Unrecorded hops")
#define _OVER_HOPS        _("Overflow hops")

#define _SENT_PROB     _("Sent probes")
#define _RECV_RESP     _("Received responses")
#define _IFACE_DOWN    _("Interface is down")
#define _IFACE_IGN     _("Interface is ignored")
#define _NO_ARP_IFACE  _("Interface is not ARPable")
#define _USING_BRD     _("Using default broadcast address")
#define _NO_LL_ADDR    _("no ll address")
#define _NOSRC_IN_DAD  _("No source address in not-DAD mode")
#define _UNSOLICITED   _("UNSOLICITED")

#define _WRONG_TS      _("Wrong timestamp")
#define _NON_STD_TIME  _("Non-standard time format")

#define _PLD_CORRUPT   _("corrupted payload")
#define _ASYMM         _("asymm")
#define _RESUME        _("Resume")
#define _BACK          _("back")

#define __TOS       "tos"
#define __TTL       "ttl"
#define _TTL        _(__TTL)
#define __HOPS      "hops"
#define _HOPS       _(__HOPS)
#define __PMTU      "pmtu"
#define _PMTU       _(__PMTU)
#define __PORT      "port"
#define __SIZE      "size"
#define __MARK      "mark"
#define __FLOW      "flow"
#define _FLOW       _(__FLOW)
#define __VALUE     "value"
#define __MACRO     "macro"
#define __COUNT     "count"
#define __IDENT     "ident"
#define __LENGTH    "length"
#define __DEVICE    "device"
#define __SOURCE    "source"
#define __PATTERN   "pattern"
#define __PRELOAD   "preload"
#define __TIMEOUT   "timeout"
#define __INTERVAL  "interval"
#define __DEADLINE  "deadline"
#define __NODEINFO  "nodeinfo"
#define __INTERFACE "interface"
#define __TIMESTAMP "timestamp"

#define _PKT_LENGTH    _("Packet length")
#define _NO_REPLY      _("no reply")
#define _TOO_MANY_HOPS _("Too many hops")

#define _BIND_SOCKADDR _("Socket address for bind()")
#define _CANONNAME_Q   _("Request for canonical name")
#define _DONT_USE_RRES _("Don't use host resolution")
#define _IP4MAP_ACCEPT _("IPv4 mapped addresses are acceptable")
#define _IP46MAP       _("IPv4 mapped and IPv6 addresses")
#define _USE_HOSTCONF  _("Use host configuration to choose address type")
#define _IDN_IF_NEEDED _("Convert to IDN format if necessary")
#define _IDN2CANON     _("Translate canonical name from IDN format")
#define _DONT_USE_SRES _("Don't use service resolution")
#define _NO_NEED_OPT_I _("no need in -i, IDN is transparently supported")
#define _DEPRECATED    _("deprecated")

#define _N_BYTES(bytes)       _n("byte", "bytes", (bytes))
#define _N_PKT_TRANSMIT(pkts) _n("packet transmitted", "packets transmitted", (pkts))
#define _N_HOP_AWAY(hops)     _n("hop away", "hops away", (hops))
#define _N_BRD(brds)          _n("broadcast", "broadcasts", (brds))
#define _N_REQUEST(reqs)      _n("request", "requests", (reqs))

// usage strings
//

#define HDR_OPT '_'
// common
#define __OPT_4 "use IPv4"
#define __OPT_6 "use IPv6"
#define __OPT_h "print help"
#define __OPT_q "quiet output"
#define __OPT_v "verbose output"
#define __OPT_V "print version"
#define __OPT_Y "disable color output"

// ping
#define __PING_OPT_a  "use audible ping"
#define __PING_OPT_A  "use adaptive ping"
#define __PING_OPT_B  "sticky source address"
#define __PING_OPT_c  "stop after 'count' replies"
#define __PING_OPT_C  "call connect() syscall on socket creation"
#define __PING_OPT_d  "use SO_DEBUG socket option"
#define __PING_OPT_D  "print timestamps"
#define __PING_OPT_e1 "define ident for ping session,"
#define __PING_OPT_e2 "default is random for SOCK_RAW and kernel defined for SOCK_DGRAM,"
#define __PING_OPT_e3 "imply using SOCK_RAW (for IPv4 only for ident 0)"
#define __PING_OPT_f  "flood ping"
#define __PING_OPT_H1 "force reverse DNS name resolution, override -n"
#define __PING_OPT_H2 "(useful for numeric destinations or for -f)"
#define __PING_OPT_i  "seconds between sending each packet"
#define __PING_OPT_I  "either interface name or address"
#define __PING_OPT_l  "send 'preload' number of packages while waiting replies"
#define __PING_OPT_L  "suppress loopback of multicast packets"
#define __PING_OPT_m  "tag the packets going out"
#define __PING_OPT_M  "define path MTU discovery, can be one of do|dont|want|probe"
#define __PING_OPT_n  "no reverse DNS name resolution, override -H"
#define __PING_OPT_O  "report outstanding replies"
#define __PING_OPT_p  "content of padding bytes"
#define __PING_OPT_Q  "quality of service bits (ToS IPv4, TClass IPv6)"
#define __PING_OPT_s  "payload size"
#define __PING_OPT_S  "use 'size' as SO_SNDBUF socket option value"
#define __PING_OPT_t  "define 'ttl' (time to live)"
#define __PING_OPT_U  "print user-to-user latency"
#define __PING_OPT_w  "reply wait 'deadline' in seconds"
#define __PING_OPT_W  "time to wait for response"
// ping4 only
#define __PING_HDR_4  "IPv4 options"
#define __PING_OPT_b  "allow broadcast pings"
#define __PING_OPT_T  "define timestamp, can be one of TSONLY|TSANDADDR|TSPRESPEC"
// ping6 only
#define __PING_HDR_6  "IPv6 options"
#define __PING_OPT_F  "define flow label, default is random"
#define __PING_OPT_N  "use IPv6 node info query, try '-N help', details in ping(8)"

// arping
#define __ARPING_OPT_A "ARP answer mode, update your neighbours"
#define __ARPING_OPT_b "keep on broadcasting, do not unicast"
#define __ARPING_OPT_c "how many packets to send"
#define __ARPING_OPT_D "duplicate address detection mode"
#define __ARPING_OPT_f "quit on first reply"
#define __ARPING_OPT_i "set interval between packets (default: 1 second)"
#define __ARPING_OPT_I "which ethernet device to use"
#define __ARPING_OPT_s "source IP address"
#define __ARPING_OPT_U "unsolicited ARP mode, update your neighbours"
#define __ARPING_OPT_w "how long to wait for a reply"

// tracepath
#define __TRACEPATH_OPT_b "print both name and IP"
#define __TRACEPATH_OPT_l "packet length"
#define __TRACEPATH_OPT_m "maximum hops"
#define __TRACEPATH_OPT_n "no reverse DNS name resolution"
#define __TRACEPATH_OPT_p "destination port"

// clockdiff
#define __CLOCKDIFF_PRE_2 "by default, ICMP timestamps are only used (see RFC792, page 16)"
#define __CLOCKDIFF_OPT_2 "use IP timestamp and ICMP echo"
#define __CLOCKDIFF_OPT_3 "use three-term IP timestamp and ICMP echo"
#define __CLOCKDIFF_PRE_I "by default, 'ctime' format is used"
#define __CLOCKDIFF_OPT_I "use ISO time format"

// gai
#define __GAI_OPT_f0 "ai_flags decimal or hex value"
#define __GAI_OPT_f1 "use -f multiple times to combine flags"
#define __GAI_OPT_F0 "ai_flags macro like AI_IDN"
#define __GAI_OPT_F1 "use -F multiple times to combine flags"
#define __GAI_OPT_i0 "convert IDN names using libidn2"
#define __GAI_OPT_i1 "(available if IDN is not transparently supported)"
#define __GAI_OPT_l  "list AI_xxx constants"

#endif
