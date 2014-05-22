/*
 *   This file is part of NetFlow exporting module.
 *
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
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

#ifndef _IP_NETFLOW_H
#define _IP_NETFLOW_H

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
	__u16			padding;
	struct netflow5_record	flow[NETFLOW5_RECORDS_MAX];
} __attribute__ ((packed));
#define NETFLOW5_HEADER_SIZE (sizeof(struct netflow5_pdu) - NETFLOW5_RECORDS_MAX * sizeof(struct netflow5_record))

/* NetFlow v9 RFC http://www.ietf.org/rfc/rfc3954.txt */
enum {
	IN_BYTES = 1,
	IN_PKTS = 2,
	PROTOCOL = 4,
	TOS = 5,
	TCP_FLAGS = 6,
	L4_SRC_PORT = 7,
	IPV4_SRC_ADDR = 8,
	SRC_MASK = 9,
	INPUT_SNMP = 10,
	L4_DST_PORT = 11,
	IPV4_DST_ADDR = 12,
	DST_MASK = 13,
	OUTPUT_SNMP = 14,
	IPV4_NEXT_HOP = 15,
	//SRC_AS = 16,
	//DST_AS = 17,
	//BGP_IPV4_NEXT_HOP = 18,
	//MUL_DST_PKTS = 19,
	//MUL_DST_BYTES = 20,
	LAST_SWITCHED = 21,
	FIRST_SWITCHED = 22,
	IPV6_SRC_ADDR = 27,
	IPV6_DST_ADDR = 28,
	IPV6_FLOW_LABEL = 31,
	ICMP_TYPE = 32,
	MUL_IGMP_TYPE = 33,
	//TOTAL_BYTES_EXP = 40,
	//TOTAL_PKTS_EXP = 41,
	//TOTAL_FLOWS_EXP = 42,
	IPV6_NEXT_HOP = 62,
	IPV6_OPTION_HEADERS = 64,
	commonPropertiesId = 137, /* for MARK */
	ipv4Options = 208,
	tcpOptions = 209,
	postNATSourceIPv4Address = 225,
	postNATDestinationIPv4Address = 226,
	postNAPTSourceTransportPort = 227,
	postNAPTDestinationTransportPort = 228,
	natEvent = 230,
	postNATSourceIPv6Address = 281,
	postNATDestinationIPv6Address = 282,
	IPSecSPI = 295,
	observationTimeMilliseconds = 323,
	observationTimeMicroseconds = 324,
	observationTimeNanoseconds = 325,
};

enum {
	FLOWSET_TEMPLATE = 0,
	FLOWSET_OPTIONS = 1,
	IPFIX_TEMPLATE = 2,
	IPFIX_OPTIONS = 3,
	FLOWSET_DATA_FIRST = 256,
};

struct flowset_template {
	__be16	flowset_id;
	__be16	length;
	__be16	template_id;
	__be16	field_count;
} __attribute__ ((packed));

struct flowset_data {
	__be16	flowset_id;
	__be16	length;
} __attribute__ ((packed));

/* NetFlow v9 packet. */
struct netflow9_pdu {
	__be16		version;
	__be16		nr_records;
	__be32		sys_uptime_ms;
	__be32		export_time_s;
	__be32		seq;
	__be32		source_id; /* Exporter Observation Domain */
	__u8		data[1400];
} __attribute__ ((packed));

/* IPFIX packet. */
struct ipfix_pdu {
	__be16		version;
	__be16		length;
	__be32		export_time_s;
	__be32		seq;
	__be32		odomain_id; /* Observation Domain ID */
	__u8		data[1400];
} __attribute__ ((packed));

/* Maximum bytes flow can have, after it's reached flow will become
 * not searchable and will be exported soon. */
#define FLOW_FULL_WATERMARK 0xffefffff

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25)
union nf_inet_addr {
	__be32          ip;
	__be32          ip6[4];
	struct in_addr  in;
	struct in6_addr in6;
};
#endif

/* hashed data which identify unique flow */
/* 16+16 + 2+2 + 2+1+1+1 = 41 */
struct ipt_netflow_tuple {
	union nf_inet_addr src;
	union nf_inet_addr dst;
	__be16		s_port; // Network byte order
	__be16		d_port; // -"-
	__u16		i_ifc;	// Host byte order
	__u8		protocol;
	__u8		tos;
	__u8		l3proto;
} __attribute__ ((packed));

/* hlist[2] + tuple[]: 8+8 + 41 = 57 (less than usual cache line, 64) */
struct ipt_netflow {
	struct hlist_node hlist; // hashtable search chain

	/* unique per flow data (hashed, NETFLOW_TUPLE_SIZE) */
	struct ipt_netflow_tuple tuple;

	/* volatile data */
	union nf_inet_addr nh;
	__u16		o_ifc;
	__u8		s_mask;
	__u8		d_mask;
	__u8		tcp_flags; /* `OR' of all tcp flags */

	/* flow statistics */
	u_int32_t	nr_packets;
	u_int32_t	nr_bytes;
	union {
		struct {
			unsigned long first;
			unsigned long last;
		} ts;
		ktime_t	ts_obs;
	} _ts_un;
#define ts_first _ts_un.ts.first
#define ts_last  _ts_un.ts.last
#define ts_obs   _ts_un.ts_obs
	u_int32_t	flow_label; /* IPv6 */
	u_int32_t	options; /* IPv4(16) & IPv6(32) Options */
	u_int32_t	tcpoptions;
#ifdef CONFIG_NF_CONNTRACK_MARK
	u_int32_t	mark; /* Exported as commonPropertiesId */
#endif
#ifdef CONFIG_NF_NAT_NEEDED
	__be32		s_as;
	__be32		d_as;
	struct nat_event *nat;
#endif
	struct list_head list; // all flows chain
	spinlock_t	*lock;
};

#ifdef CONFIG_NF_NAT_NEEDED
enum {
	NAT_CREATE, NAT_DESTROY, NAT_POOLEXHAUSTED
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
	__be32 ipaddr;
	unsigned short port;
	atomic_t wmem_peak;	// sk_wmem_alloc peak value
	atomic_t err_full;	// socket filled error
	atomic_t err_connect;	// connect errors
	atomic_t err_other;	// other socket errors
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

#define NETFLOW_STAT_INC_ATOMIC(count)				\
	do {							\
		preempt_disable();				\
		(__get_cpu_var(ipt_netflow_stat).count++);	\
		preempt_enable();				\
	} while(0);

#define NETFLOW_STAT_ADD_ATOMIC(count, val)			\
	do {							\
		preempt_disable();				\
		(__get_cpu_var(ipt_netflow_stat).count += (unsigned long long)val); \
		preempt_enable();				\
	} while(0);


/* statistics */
struct ipt_netflow_stat {
	u64 searched;			// hash stat
	u64 found;			// hash stat
	u64 notfound;			// hash stat
	unsigned int truncated;		// packets stat
	unsigned int frags;		// packets stat
	unsigned int alloc_err;		// failed to allocate flow mem
	unsigned int maxflows_err;	// maxflows reached
	unsigned int send_success;	// sendmsg() ok
	unsigned int send_failed;	// sendmsg() failed
	unsigned int sock_errors;	// socket error callback called (got icmp refused)
	u64 exported_size;		// netflow traffic itself
	u64 pkt_total;			// packets accounted total
	u64 traf_total;			// traffic accounted total
	u64 pkt_drop;			// packets not accounted total
	u64 traf_drop;			// traffic not accounted total
	u64 pkt_out;			// packets out of the memory
	u64 traf_out;			// traffic out of the memory
};

#ifndef list_first_entry
#define list_first_entry(ptr, type, member) \
	list_entry((ptr)->next, type, member)
#endif

#endif
/* vim: set sw=8: */
