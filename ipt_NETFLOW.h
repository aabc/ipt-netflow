
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
	__be32		ts_first;
	__be32		ts_last;
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
	__be32			ts_uptime;
	__be32			ts_usecs;
	__be32			ts_unsecs;
	__be32			seq;
	__u8			eng_type;
	__u8			eng_id;
	__u16			padding;
	struct netflow5_record	flow[NETFLOW5_RECORDS_MAX];
} __attribute__ ((packed));
#define NETFLOW5_HEADER_SIZE (sizeof(struct netflow5_pdu) - NETFLOW5_RECORDS_MAX * sizeof(struct netflow5_record))

/* hashed data which identify unique flow */
struct ipt_netflow_tuple {
	__be32		s_addr;	// Network byte order
	__be32		d_addr; // -"-
	__be16		s_port; // -"-
	__be16		d_port; // -"-
	__be16		i_ifc;	// Local byte order
	__u8		protocol;
	__u8		tos;
};
/* tuple size is rounded to u32s */
#define NETFLOW_TUPLE_SIZE (sizeof(struct ipt_netflow_tuple) / 4)

/* maximum bytes flow can have, after it reached flow become not searchable and will be exported soon */
#define FLOW_FULL_WATERMARK 0xffefffff

/* flow entry */
struct ipt_netflow {
	struct hlist_node hlist; // hashtable search chain
	struct list_head list; // all flows chain

	/* unique per flow data (hashed, NETFLOW_TUPLE_SIZE) */
	struct ipt_netflow_tuple tuple;

	/* volatile data */
	__be16		o_ifc;
	__u8		s_mask;
	__u8		d_mask;

	/* flow statistics */
	u_int32_t	nr_packets;
	u_int32_t	nr_bytes;
	unsigned long	ts_first;
	unsigned long	ts_last;
	__u8		tcp_flags; /* `OR' of all tcp flags */
};

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
	atomic_t err_other;	// other socket errors
};

struct netflow_aggr_n {
	struct list_head list;
	__u32 mask;
	__u32 addr;
	__u32 aggr_mask;
	__u8 prefix;
};

struct netflow_aggr_p {
	struct list_head list;
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
