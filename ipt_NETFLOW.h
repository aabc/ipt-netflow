/*
 *   This file is part of NetFlow exporting module.
 *
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#ifndef _IPT_NETFLOW_H
#define _IPT_NETFLOW_H

/*
 * Some tech info:
 * http://www.cisco.com/en/US/products/ps6601/prod_white_papers_list.html
 * http://www.cisco.com/en/US/products/sw/netmgtsw/ps1964/products_implementation_design_guide09186a00800d6a11.html
 */

#define NETFLOW5_RECORDS_MAX 30

struct netflow5_record {
	__be32		s_addr;
	__be32		d_addr;
	__be32		nexthop;
	__be16		i_ifc;
	__be16		o_ifc;
	__be32		nr_packets;
	__be32		nr_octets;
	__be32		first_ms;
	__be32		last_ms;
	__be16		s_port;
	__be16		d_port;
	__u8		reserved;
	__u8		tcp_flags;
	__u8		protocol;
	__u8		tos;
	__be16		s_as;
	__be16		d_as;
	__u8		s_mask;
	__u8		d_mask;
	__u16		padding;
} __attribute__ ((packed));

/* NetFlow v5 packet */
struct netflow5_pdu {
	__be16			version;
	__be16			nr_records;
	__be32			ts_uptime; /* ms */
	__be32			ts_usecs;  /* s  */
	__be32			ts_unsecs; /* ns */
	__be32			seq;
	__u8			eng_type;
	__u8			eng_id;
	__u16			sampling;
	struct netflow5_record	flow[NETFLOW5_RECORDS_MAX];
} __attribute__ ((packed));
#define NETFLOW5_HEADER_SIZE (sizeof(struct netflow5_pdu) - NETFLOW5_RECORDS_MAX * sizeof(struct netflow5_record))

#define IF_NAME_SZ	IFNAMSIZ
#define IF_DESC_SZ	32

/* NetFlow v9	http://www.ietf.org/rfc/rfc3954.txt */
/* IPFIX	http://www.iana.org/assignments/ipfix/ipfix.xhtml */
/* v9 elements are uppercased, IPFIX camel cased. */
#define one(id, name, len) name = id,
#define two(id, a, b, len)		\
		one(id, a, len)	\
		one(id, b, len)
#define Elements \
	two(1,   IN_BYTES, octetDeltaCount, 4) \
	two(2,   IN_PKTS, packetDeltaCount, 4) \
	two(4,   PROTOCOL, protocolIdentifier, 1) \
	two(5,   TOS, ipClassOfService, 1) \
	two(6,   TCP_FLAGS, tcpControlBits, 1) \
	two(7,   L4_SRC_PORT, sourceTransportPort, 2) \
	two(8,   IPV4_SRC_ADDR, sourceIPv4Address, 4) \
	two(9,   SRC_MASK, sourceIPv4PrefixLength, 1) \
	two(10,  INPUT_SNMP, ingressInterface, 2) \
	two(11,  L4_DST_PORT, destinationTransportPort, 2) \
	two(12,  IPV4_DST_ADDR, destinationIPv4Address, 4) \
	two(13,  DST_MASK, destinationIPv4PrefixLength, 1) \
	two(14,  OUTPUT_SNMP, egressInterface, 2) \
	two(15,  IPV4_NEXT_HOP, ipNextHopIPv4Address, 4) \
	two(21,  LAST_SWITCHED, flowEndSysUpTime, 4) \
	two(22,  FIRST_SWITCHED, flowStartSysUpTime, 4) \
	one(25,  minimumIpTotalLength, 2) \
	one(26,  maximumIpTotalLength, 2) \
	two(27,  IPV6_SRC_ADDR, sourceIPv6Address, 16) \
	two(28,  IPV6_DST_ADDR, destinationIPv6Address, 16) \
	two(31,  IPV6_FLOW_LABEL, flowLabelIPv6, 3) \
	two(32,  ICMP_TYPE, icmpTypeCodeIPv4, 2) \
	two(33,  MUL_IGMP_TYPE, igmpType, 1) \
	two(40,  TOTAL_BYTES_EXP, exportedOctetTotalCount, 8) \
	two(41,  TOTAL_PKTS_EXP, exportedMessageTotalCount, 8) \
	two(42,  TOTAL_FLOWS_EXP, exportedFlowRecordTotalCount, 8) \
	two(48,  FLOW_SAMPLER_ID, samplerId, 1) \
	two(49,  FLOW_SAMPLER_MODE, samplerMode, 1) \
	two(50,  FLOW_SAMPLER_RANDOM_INTERVAL, samplerRandomInterval, 2) \
	one(52,  minimumTTL, 1) \
	one(53,  maximumTTL, 1) \
	two(56,  SRC_MAC, sourceMacAddress, 6) \
	two(57,  DST_MAC, postDestinationMacAddress, 6) \
	two(58,  SRC_VLAN, vlanId, 2) \
	two(61,  DIRECTION, flowDirection, 1) \
	two(62,  IPV6_NEXT_HOP, ipNextHopIPv6Address, 16) \
	two(64,  IPV6_OPTION_HEADERS, ipv6ExtensionHeaders, 2) \
	two(70,  MPLS_LABEL_1,  mplsTopLabelStackSection, 3) \
	two(71,  MPLS_LABEL_2,  mplsLabelStackSection2,   3) \
	two(72,  MPLS_LABEL_3,  mplsLabelStackSection3,   3) \
	two(73,  MPLS_LABEL_4,  mplsLabelStackSection4,   3) \
	two(74,  MPLS_LABEL_5,  mplsLabelStackSection5,   3) \
	two(75,  MPLS_LABEL_6,  mplsLabelStackSection6,   3) \
	two(76,  MPLS_LABEL_7,  mplsLabelStackSection7,   3) \
	two(77,  MPLS_LABEL_8,  mplsLabelStackSection8,   3) \
	two(78,  MPLS_LABEL_9,  mplsLabelStackSection9,   3) \
	two(79,  MPLS_LABEL_10, mplsLabelStackSection10,  3) \
	one(80,  destinationMacAddress, 6) \
	two(82,  IF_NAME, interfaceName, IF_NAME_SZ) \
	two(83,  IF_DESC, interfaceDescription, IF_DESC_SZ) \
	one(136, flowEndReason, 1) \
	one(138, observationPointId, 4) \
	one(139, icmpTypeCodeIPv6, 2) \
	one(141, LineCardId, 4) \
	one(142, portId, 4) \
	one(143, meteringProcessId, 4) \
	one(144, exportingProcessId, 4) \
	one(145, TemplateId, 2) \
	one(149, observationDomainId, 4) \
	one(152, flowStartMilliseconds, 8) \
	one(153, flowEndMilliseconds, 8) \
	one(154, flowStartMicroseconds, 8) \
	one(155, flowEndMicroseconds, 8) \
	one(160, systemInitTimeMilliseconds, 8) \
	one(163, observedFlowTotalCount, 8) \
	one(164, ignoredPacketTotalCount, 8) \
	one(165, ignoredOctetTotalCount, 8) \
	one(166, notSentFlowTotalCount, 8) \
	one(167, notSentPacketTotalCount, 8) \
	one(168, notSentOctetTotalCount, 8) \
	one(200, mplsTopLabelTTL, 1) \
	one(201, mplsLabelStackLength, 1) \
	one(202, mplsLabelStackDepth, 1) \
	one(208, ipv4Options, 4) \
	one(209, tcpOptions, 4) \
	one(225, postNATSourceIPv4Address, 4) \
	one(226, postNATDestinationIPv4Address, 4) \
	one(227, postNAPTSourceTransportPort, 2) \
	one(228, postNAPTDestinationTransportPort, 2) \
	one(230, natEvent, 1) \
	one(243, dot1qVlanId, 2) \
	one(244, dot1qPriority, 1) \
	one(245, dot1qCustomerVlanId, 2) \
	one(246, dot1qCustomerPriority, 1) \
	one(252, ingressPhysicalInterface, 2) \
	one(253, egressPhysicalInterface, 2) \
	one(256, ethernetType, 2) \
	one(295, IPSecSPI, 4) \
	one(300, observationDomainName, 128) \
	one(302, selectorId, 1) \
	one(309, samplingSize, 1) \
	one(310, samplingPopulation, 2) \
	one(318, selectorIdTotalPktsObserved, 8) \
	one(319, selectorIdTotalPktsSelected, 8) \
	one(323, observationTimeMilliseconds, 8) \
	one(324, observationTimeMicroseconds, 8) \
	one(325, observationTimeNanoseconds, 8) \
	one(390, flowSelectorAlgorithm, 1) \
	one(394, selectorIDTotalFlowsObserved, 8) \
	one(395, selectorIDTotalFlowsSelected, 8) \
	one(396, samplingFlowInterval, 1) \
	one(397, samplingFlowSpacing, 2)

enum {
	Elements
};
#undef one
#undef two

enum {
	FLOWSET_TEMPLATE = 0,
	FLOWSET_OPTIONS = 1,
	IPFIX_TEMPLATE = 2,
	IPFIX_OPTIONS = 3,
	FLOWSET_DATA_FIRST = 256,
};

enum {				/* v9 scopes */
	SCOPE_SYSTEM = 1,
	SCOPE_INTERFACE = 2,
	SCOPE_LINECARD = 3,
	SCOPE_CACHE = 4,
	SCOPE_TEMPLATE = 5,
};

struct flowset_template {
	__be16	flowset_id;
	__be16	length;		/* (bytes) */
	__be16	template_id;
	__be16	field_count;	/* (items) */
} __attribute__ ((packed));

struct flowset_data {
	__be16	flowset_id;	/* corresponds to template_id */
	__be16	length;		/* (bytes) */
} __attribute__ ((packed));

/* http://tools.ietf.org/html/rfc3954#section-6.1 */
struct flowset_opt_tpl_v9 {
	__be16	flowset_id;
	__be16	length;
	__be16	template_id;
	__be16	scope_len;	/* (bytes) */
	__be16	opt_len;	/* (bytes) */
} __attribute__ ((packed));

/* http://tools.ietf.org/html/rfc5101#section-3.4.2.2 */
struct flowset_opt_tpl_ipfix {
	__be16	flowset_id;
	__be16	length;
	__be16	template_id;
	__be16	field_count;	/* total (items) */
	__be16	scope_count;	/* (items) must not be zero */
} __attribute__ ((packed));

/* NetFlow v9 packet. */
struct netflow9_pdu {
	__be16		version;
	__be16		nr_records;	/* (items) */
	__be32		sys_uptime_ms;
	__be32		export_time_s;
	__be32		seq;
	__be32		source_id;	/* Exporter Observation Domain */
	__u8		data[1400];
} __attribute__ ((packed));

/* IPFIX packet. */
struct ipfix_pdu {
	__be16		version;
	__be16		length;		/* (bytes) */
	__be32		export_time_s;
	__be32		seq;
	__be32		odomain_id;	/* Observation Domain ID */
	__u8		data[1400];
} __attribute__ ((packed));

/* Maximum bytes flow can have, after it's reached flow will become
 * not searchable and will be exported soon. */
#define FLOW_FULL_WATERMARK 0xffefffff

#define EXTRACT_SPI(tuple)	((tuple.s_port << 16) | tuple.d_port)
#define SAVE_SPI(tuple, spi)	{ tuple.s_port = spi >> 16; \
				  tuple.d_port = spi; }
#define MAX_VLAN_TAGS	2

/* hashed data which identify unique flow */
/* 16+16 + 2+2 + 2+1+1+1 = 41 */
struct ipt_netflow_tuple {
	union nf_inet_addr src;
	union nf_inet_addr dst;
	__be16		s_port; // Network byte order
	__be16		d_port; // -"-
#ifdef MPLS_DEPTH
	__be32		mpls[MPLS_DEPTH]; /* Network byte order */
#endif
	__u16		i_ifc;	// Host byte order
#ifdef ENABLE_VLAN
	__be16		tag[MAX_VLAN_TAGS]; // Network byte order (outer tag first)
#endif
	__u8		protocol;
	__u8		tos;
	__u8		l3proto;
#ifdef ENABLE_MAC
	__u8		h_dst[ETH_ALEN];
	__u8		h_src[ETH_ALEN];
#endif
} __attribute__ ((packed));

/* hlist[2] + tuple[]: 8+8 + 41 = 57 (less than usual cache line, 64) */
struct ipt_netflow {
	struct hlist_node hlist; // hashtable search chain

	/* unique per flow data (hashed, NETFLOW_TUPLE_SIZE) */
	struct ipt_netflow_tuple tuple;

	/* volatile data */
	union nf_inet_addr nh;
#if defined(ENABLE_MAC) || defined(ENABLE_VLAN)
	__be16		ethernetType; /* Network byte order */
#endif
	__u16		o_ifc;
#ifdef ENABLE_PHYSDEV
	__u16		i_ifphys;
	__u16		o_ifphys;
#endif
#ifdef SNMP_RULES
	__u16		i_ifcr;	/* translated interface numbers*/
	__u16		o_ifcr;
#endif
	__u8		s_mask;
	__u8		d_mask;
	__u8		tcp_flags; /* `OR' of all tcp flags */
	__u8		flowEndReason;
#ifdef ENABLE_DIRECTION
	__u8		hooknumx; /* hooknum + 1 */
#endif
	/* flow statistics */
	u_int32_t	nr_packets;
	u_int32_t	nr_bytes;
#ifdef ENABLE_SAMPLER
	unsigned int	sampler_count; /* for deterministic sampler only */
#endif
	union {
		struct {
			unsigned long first;
			unsigned long last;
		} ts;
		ktime_t	ts_obs;
	} _ts_un;
#define nf_ts_first _ts_un.ts.first
#define nf_ts_last  _ts_un.ts.last
#define nf_ts_obs   _ts_un.ts_obs
	u_int32_t	flow_label; /* IPv6 */
	u_int32_t	options; /* IPv4(16) & IPv6(32) Options */
	u_int32_t	tcpoptions;
#ifdef CONFIG_NF_NAT_NEEDED
	__be32		s_as;
	__be32		d_as;
	struct nat_event *nat;
#endif
	union {
		struct list_head list; /* all flows in ipt_netflow_list */
#ifdef HAVE_LLIST
		struct llist_node llnode; /* purged flows */
#endif
	} _flow_list;
#define flows_list  _flow_list.list
#define flows_llnode _flow_list.llnode
};

#ifdef CONFIG_NF_NAT_NEEDED
enum {
	NAT_CREATE = 1, NAT_DESTROY = 2, NAT_POOLEXHAUSTED = 3
};
struct nat_event {
	struct list_head list;
	struct {
		__be32	s_addr;
		__be32	d_addr;
		__be16	s_port;
		__be16	d_port;
	} pre, post;
	ktime_t		ts_ktime;
	unsigned long	ts_jiffies;
	__u8	protocol;
	__u8	nat_event;
};
#define IS_DUMMY_FLOW(nf) (nf->nat)
#else
#define IS_DUMMY_FLOW(nf) 0
#endif

static inline int ipt_netflow_tuple_equal(const struct ipt_netflow_tuple *t1,
				    const struct ipt_netflow_tuple *t2)
{
	return (!memcmp(t1, t2, sizeof(struct ipt_netflow_tuple)));
}

struct ipt_netflow_sock {
	struct list_head list;
	struct socket *sock;
	struct sockaddr_storage addr;	// destination
	atomic_t wmem_peak;		// sk_wmem_alloc peak value
	unsigned int err_connect;	// connect errors
	unsigned int err_full;		// socket filled error
	unsigned int err_other;		// other socket errors
	unsigned int err_cberr;		// async errors, icmp
	unsigned int pkt_exp;		// pkts expoted to this dest
	u64 bytes_exp;			// bytes -"-
	u64 bytes_exp_old;		// for rate calculation
	unsigned int bytes_rate;	// bytes per second
	unsigned int pkt_sent;		// pkts sent to this dest
	unsigned int pkt_fail;		// pkts failed to send to this dest
};

struct netflow_aggr_n {
	struct list_head list;
	atomic_t usage;
	__u32 mask;
	__u32 addr;
	__u32 aggr_mask;
	__u8 prefix;
};

struct netflow_aggr_p {
	struct list_head list;
	atomic_t usage;
	__u16 port1;
	__u16 port2;
	__u16 aggr_port;
};

#define NETFLOW_STAT_INC(count) (__get_cpu_var(ipt_netflow_stat).count++)
#define NETFLOW_STAT_ADD(count, val) (__get_cpu_var(ipt_netflow_stat).count += (unsigned long long)val)
#define NETFLOW_STAT_SET(count, val) (__get_cpu_var(ipt_netflow_stat).count = (unsigned long long)val)
#define NETFLOW_STAT_TS(count)							 \
	do {									 \
		ktime_t kts = ktime_get_real();					 \
		if (!(__get_cpu_var(ipt_netflow_stat)).count.first.tv64)	 \
			__get_cpu_var(ipt_netflow_stat).count.first = kts;	 \
		__get_cpu_var(ipt_netflow_stat).count.last = kts;		 \
	} while (0);

#define NETFLOW_STAT_INC_ATOMIC(count)				\
	do {							\
		preempt_disable();				\
		(__get_cpu_var(ipt_netflow_stat).count++);	\
		preempt_enable();				\
	} while (0);

#define NETFLOW_STAT_ADD_ATOMIC(count, val)			\
	do {							\
		preempt_disable();				\
		(__get_cpu_var(ipt_netflow_stat).count += (unsigned long long)val); \
		preempt_enable();				\
	} while (0);
#define NETFLOW_STAT_READ(count) ({					\
		unsigned int _tmp = 0, _cpu;				\
		for_each_present_cpu(_cpu)				\
			 _tmp += per_cpu(ipt_netflow_stat, _cpu).count;	\
		_tmp;							\
	})

struct duration {
	ktime_t first;
	ktime_t last;
};

/* statistics */
struct ipt_netflow_stat {
	u64 searched;			// hash stat
	u64 found;			// hash stat
	u64 notfound;			// hash stat (new flows)
	u64  pkt_total;			// packets metered
	u64 traf_total;			// traffic metered
#ifdef ENABLE_PROMISC
	u64 pkt_promisc;		// how much packets passed promisc code
	u64 pkt_promisc_drop;		// how much packets discarded
#endif
	/* above is grouped for cache */
	unsigned int truncated;		// packets stat (drop)
	unsigned int frags;		// packets stat (drop)
	unsigned int maxflows_err;	// maxflows reached (drop)
	unsigned int alloc_err;		// failed to allocate memory (drop & lost)
	struct duration drop;
	unsigned int send_success;	// sendmsg() ok
	unsigned int send_failed;	// sendmsg() failed
	unsigned int sock_cberr;	// socket error callback called (got icmp refused)
	unsigned int exported_rate;	// netflow traffic itself
	u64 exported_pkt;		// netflow traffic itself
	u64 exported_flow;		// netflow traffic itself
	u64 exported_traf;		// netflow traffic itself
	u64 exported_trafo;		// netflow traffic itself
	u64  pkt_total_prev;		// packets metered previous interval
	u32  pkt_total_rate;		// packet rate for this cpu
	u64  pkt_drop;			// packets not metered
	u64 traf_drop;			// traffic not metered
	u64 flow_lost;			// flows not sent to collector
	u64  pkt_lost;			// packets not sent to collector
	u64 traf_lost;			// traffic not sent to collector
	struct duration lost;
	u64  pkt_out;			// packets out of the hash
	u64 traf_out;			// traffic out of the hash
#ifdef ENABLE_SAMPLER
	u64 pkts_observed;		// sampler stat
	u64 pkts_selected;		// sampler stat
#endif
	u64 old_searched;		// previous hash stat
	u64 old_found;			// for calculation per cpu metric
	u64 old_notfound;
	int metric;			// one minute ewma of hash efficiency
};

#endif
/* vim: set sw=8: */
