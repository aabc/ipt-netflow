/*
 * This is NetFlow exporting module (NETFLOW target)
 * (c) 2008 <abc@telekom.ru>
 *
 */

//#define RAW_PROMISC_HACK

#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/proc_fs.h>
#include <linux/vmalloc.h>
#include <linux/seq_file.h>
#include <linux/random.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/igmp.h>
#include <linux/inetdevice.h>
#include <linux/jhash.h>
#include <net/icmp.h>
#include <net/ip.h>
#include <net/tcp.h>
#include <net/route.h>
#include <net/dst.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#include <linux/version.h>
#include <asm/unaligned.h>
#include "ipt_NETFLOW.h"
#ifdef CONFIG_BRIDGE_NETFILTER
#include <linux/netfilter_bridge.h>
#endif
#ifdef CONFIG_SYSCTL
#include <linux/sysctl.h>
#endif

#define IPT_NETFLOW_VERSION "1.3"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("<abc@telekom.ru>");
MODULE_DESCRIPTION("iptables NETFLOW target module");
MODULE_VERSION(IPT_NETFLOW_VERSION);

#define DST_SIZE 256
static char destination_buf[DST_SIZE] = "127.0.0.1:2055";
static char *destination = destination_buf;
module_param(destination, charp, 0400);
MODULE_PARM_DESC(destination, "export destination ipaddress:port");

static int inactive_timeout = 15;
module_param(inactive_timeout, int, 0600);
MODULE_PARM_DESC(inactive_timeout, "inactive flows timeout in seconds");

static int active_timeout = 30 * 60;
module_param(active_timeout, int, 0600);
MODULE_PARM_DESC(active_timeout, "active flows timeout in seconds");

static int debug = 0;
module_param(debug, int, 0600);
MODULE_PARM_DESC(debug, "debug verbosity level");

static int sndbuf;
module_param(sndbuf, int, 0400);
MODULE_PARM_DESC(sndbuf, "udp socket SNDBUF size");

static int hashsize;
module_param(hashsize, int, 0400);
MODULE_PARM_DESC(hashsize, "hash table size");

static int maxflows = 2000000;
module_param(maxflows, int, 0600);
MODULE_PARM_DESC(maxflows, "maximum number of flows");
static int peakflows = 0;
static __u32 peakflows_at;

#define AGGR_SIZE 1024
static char aggregation_buf[AGGR_SIZE] = "none";
static char *aggregation = aggregation_buf;
module_param(aggregation, charp, 0400);
MODULE_PARM_DESC(aggregation, "aggregation ruleset");

static DEFINE_PER_CPU(struct ipt_netflow_stat, ipt_netflow_stat);
static LIST_HEAD(usock_list);
static DEFINE_RWLOCK(sock_lock);

static unsigned int ipt_netflow_hash_rnd;
struct hlist_head *ipt_netflow_hash __read_mostly; /* hash table memory */
static unsigned int ipt_netflow_hash_size __read_mostly = 0;
static LIST_HEAD(ipt_netflow_list); /* all flows */
static LIST_HEAD(aggr_n_list);
static LIST_HEAD(aggr_p_list);
static DEFINE_RWLOCK(aggr_lock);
static struct kmem_cache *ipt_netflow_cachep __read_mostly; /* ipt_netflow memory */
static atomic_t ipt_netflow_count = ATOMIC_INIT(0);
static DEFINE_SPINLOCK(ipt_netflow_lock);

static DEFINE_SPINLOCK(pdu_lock);
static long long pdu_packets = 0, pdu_traf = 0;
static struct netflow5_pdu pdu;
static __be32 pdu_ts_mod;
static void netflow_work_fn(struct work_struct *work);
static DECLARE_DELAYED_WORK(netflow_work, netflow_work_fn);
static struct timer_list rate_timer;

#define TCP_FIN_RST 0x05

static long long sec_prate = 0, sec_brate = 0;
static long long min_prate = 0, min_brate = 0;
static long long min5_prate = 0, min5_brate = 0;
static unsigned int metric = 10, min15_metric = 10, min5_metric = 10, min_metric = 10; /* hash metrics */

static int set_hashsize(int new_size);
static void destination_fini(void);
static int add_destinations(char *ptr);
static void aggregation_fini(struct list_head *list);
static int add_aggregation(char *ptr);

static inline __be32 bits2mask(int bits) {
	return (bits? 0xffffffff << (32 - bits) : 0);
}

static inline int mask2bits(__be32 mask) {
	int n;

	for (n = 0; mask; n++)
		mask = (mask << 1) & 0xffffffff;
	return n;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)
#define INIT_NET(x) x
#else
#define INIT_NET(x) init_net.x
#endif

#ifdef CONFIG_PROC_FS
/* procfs statistics /proc/net/stat/ipt_netflow */
static int nf_seq_show(struct seq_file *seq, void *v)
{
	unsigned int nr_flows = atomic_read(&ipt_netflow_count);
	int cpu;
	unsigned long long searched = 0, found = 0, notfound = 0;
	unsigned int truncated = 0, frags = 0, alloc_err = 0, maxflows_err = 0;
	unsigned int sock_errors = 0, send_failed = 0, send_success = 0;
	unsigned long long pkt_total = 0, traf_total = 0, exported_size = 0;
	unsigned long long pkt_drop = 0, traf_drop = 0;
	unsigned long long pkt_out = 0, traf_out = 0;
	struct ipt_netflow_sock *usock;
	struct netflow_aggr_n *aggr_n;
	struct netflow_aggr_p *aggr_p;
	int snum = 0;
	int peak = (jiffies - peakflows_at) / HZ;

	seq_printf(seq, "Flows: active %u (peak %u reached %ud%uh%um ago), mem %uK\n",
		   nr_flows,
		   peakflows,
		   peak / (60 * 60 * 24), (peak / (60 * 60)) % 24, (peak / 60) % 60,
		   (unsigned int)((nr_flows * sizeof(struct ipt_netflow)) >> 10));

	for_each_present_cpu(cpu) {
		struct ipt_netflow_stat *st = &per_cpu(ipt_netflow_stat, cpu);

		searched += st->searched;
		found += st->found;
		notfound += st->notfound;
		truncated += st->truncated;
		frags += st->frags;
		alloc_err += st->alloc_err;
		maxflows_err += st->maxflows_err;
		send_success += st->send_success;
		send_failed += st->send_failed;
		sock_errors += st->sock_errors;
		exported_size += st->exported_size;
		pkt_total += st->pkt_total;
		traf_total += st->traf_total;
		pkt_drop += st->pkt_drop;
		traf_drop += st->traf_drop;
		pkt_out += st->pkt_out;
		traf_out += st->traf_out;
	}

#define FFLOAT(x, prec) (int)(x) / prec, (int)(x) % prec
	seq_printf(seq, "Hash: size %u (mem %uK), metric %d.%d, %d.%d, %d.%d, %d.%d. MemTraf: %llu pkt, %llu K (pdu %llu, %llu).\n",
		   ipt_netflow_hash_size, 
		   (unsigned int)((ipt_netflow_hash_size * sizeof(struct hlist_head)) >> 10),
		   FFLOAT(metric, 10),
		   FFLOAT(min_metric, 10),
		   FFLOAT(min5_metric, 10),
		   FFLOAT(min15_metric, 10),
		   pkt_total - pkt_out + pdu_packets,
		   (traf_total - traf_out + pdu_traf) >> 10,
		   pdu_packets,
		   pdu_traf);

	seq_printf(seq, "Timeout: active %d, inactive %d. Maxflows %u\n",
		   active_timeout,
		   inactive_timeout,
		   maxflows);

	seq_printf(seq, "Rate: %llu bits/sec, %llu packets/sec; Avg 1 min: %llu bps, %llu pps; 5 min: %llu bps, %llu pps\n",
		   sec_brate, sec_prate, min_brate, min_prate, min5_brate, min5_prate);

	seq_printf(seq, "cpu#  stat: <search found new, trunc frag alloc maxflows>, sock: <ok fail cberr, bytes>, traffic: <pkt, bytes>, drop: <pkt, bytes>\n");

	seq_printf(seq, "Total stat: %6llu %6llu %6llu, %4u %4u %4u %4u, sock: %6u %u %u, %llu K, traffic: %llu, %llu MB, drop: %llu, %llu K\n",
		   (unsigned long long)searched,
		   (unsigned long long)found,
		   (unsigned long long)notfound,
		   truncated, frags, alloc_err, maxflows_err,
		   send_success, send_failed, sock_errors,
		   (unsigned long long)exported_size >> 10,
		   (unsigned long long)pkt_total, (unsigned long long)traf_total >> 20,
		   (unsigned long long)pkt_drop, (unsigned long long)traf_drop >> 10);

	if (num_present_cpus() > 1) {
		for_each_present_cpu(cpu) {
			struct ipt_netflow_stat *st;

			st = &per_cpu(ipt_netflow_stat, cpu);
			seq_printf(seq, "cpu%u  stat: %6llu %6llu %6llu, %4u %4u %4u %4u, sock: %6u %u %u, %llu K, traffic: %llu, %llu MB, drop: %llu, %llu K\n",
				   cpu,
				   (unsigned long long)st->searched,
				   (unsigned long long)st->found,
				   (unsigned long long)st->notfound,
				   st->truncated, st->frags, st->alloc_err, st->maxflows_err,
				   st->send_success, st->send_failed, st->sock_errors,
				   (unsigned long long)st->exported_size >> 10,
				   (unsigned long long)st->pkt_total, (unsigned long long)st->traf_total >> 20,
				   (unsigned long long)st->pkt_drop, (unsigned long long)st->traf_drop >> 10);
		}
	}

	read_lock(&sock_lock);
	list_for_each_entry(usock, &usock_list, list) {
		struct sock *sk = usock->sock->sk;

		seq_printf(seq, "sock%d: %u.%u.%u.%u:%u, sndbuf %u, filled %u, peak %u; err: sndbuf reached %u, other %u\n",
			   snum,
			   usock->ipaddr >> 24,
			   (usock->ipaddr >> 16) & 255,
			   (usock->ipaddr >> 8) & 255,
			   usock->ipaddr & 255,
			   usock->port,
			   sk->sk_sndbuf,
			   atomic_read(&sk->sk_wmem_alloc),
			   atomic_read(&usock->wmem_peak),
			   atomic_read(&usock->err_full),
			   atomic_read(&usock->err_other));
		snum++;
	}
	read_unlock(&sock_lock);

	read_lock_bh(&aggr_lock);
	snum = 0;
	list_for_each_entry(aggr_n, &aggr_n_list, list) {
		seq_printf(seq, "aggr#%d net: match %u.%u.%u.%u/%d strip %d\n",
			   snum,
			   HIPQUAD(aggr_n->addr),
			   mask2bits(aggr_n->mask),
			   mask2bits(aggr_n->aggr_mask));
		snum++;
	}
	snum = 0;
	list_for_each_entry(aggr_p, &aggr_p_list, list) {
		seq_printf(seq, "aggr#%d port: ports %u-%u replace %u\n",
			   snum,
			   aggr_p->port1,
			   aggr_p->port2,
			   aggr_p->aggr_port);
		snum++;
	}
	read_unlock_bh(&aggr_lock);
	return 0;
}

static int nf_seq_open(struct inode *inode, struct file *file)
{
	return single_open(file, nf_seq_show, NULL);
}

static struct file_operations nf_seq_fops = {
	.owner	 = THIS_MODULE,
	.open	 = nf_seq_open,
	.read	 = seq_read,
	.llseek	 = seq_lseek,
	.release = single_release,
};
#endif /* CONFIG_PROC_FS */

#ifdef CONFIG_SYSCTL
/* sysctl /proc/sys/net/netflow */
static int hsize_procctl(ctl_table *ctl, int write, struct file *filp,
			 void __user *buffer, size_t *lenp, loff_t *fpos)
{
	void *orig = ctl->data;
	int ret, hsize;

	if (write)
		ctl->data = &hsize;
	ret = proc_dointvec(ctl, write, filp, buffer, lenp, fpos);
	if (write) {
		ctl->data = orig;
		if (hsize < 1)
			return -EPERM;
		return set_hashsize(hsize)?:ret;
	} else
		return ret;
}

static int sndbuf_procctl(ctl_table *ctl, int write, struct file *filp,
			 void __user *buffer, size_t *lenp, loff_t *fpos)
{
	int ret;
	struct ipt_netflow_sock *usock;
       
	read_lock(&sock_lock);
	if (list_empty(&usock_list)) {
		read_unlock(&sock_lock);
		return -ENOENT;
	}
	usock = list_first_entry(&usock_list, struct ipt_netflow_sock, list);
	sndbuf = usock->sock->sk->sk_sndbuf;
	read_unlock(&sock_lock);

	ctl->data = &sndbuf;
	ret = proc_dointvec(ctl, write, filp, buffer, lenp, fpos);
	if (!write)
		return ret;
	if (sndbuf < SOCK_MIN_SNDBUF)
		sndbuf = SOCK_MIN_SNDBUF;
	write_lock(&sock_lock);
	list_for_each_entry(usock, &usock_list, list) {
		usock->sock->sk->sk_sndbuf = sndbuf;
	}
	write_unlock(&sock_lock);
	return ret;
}

static int destination_procctl(ctl_table *ctl, int write, struct file *filp,
			 void __user *buffer, size_t *lenp, loff_t *fpos)
{
	int ret;

	ret = proc_dostring(ctl, write, filp, buffer, lenp, fpos);
	if (ret >= 0 && write) {
		destination_fini();
		add_destinations(destination_buf);
	}
	return ret;
}

static int aggregation_procctl(ctl_table *ctl, int write, struct file *filp,
			 void __user *buffer, size_t *lenp, loff_t *fpos)
{
	int ret;

	if (debug > 1)
		printk(KERN_INFO "aggregation_procctl (%d) %u %llu\n", write, (unsigned int)(*lenp), *fpos);
	ret = proc_dostring(ctl, write, filp, buffer, lenp, fpos);
	if (ret >= 0 && write) {
		add_aggregation(aggregation_buf);
	}
	return ret;
}

static struct ctl_table_header *netflow_sysctl_header;

static struct ctl_table netflow_sysctl_table[] = {
	{
		.procname	= "active_timeout",
		.mode		= 0644,
		.data		= &active_timeout,
		.maxlen		= sizeof(int),
		.proc_handler	= &proc_dointvec,
	},
	{
		.procname	= "inactive_timeout",
		.mode		= 0644,
		.data		= &inactive_timeout,
		.maxlen		= sizeof(int),
		.proc_handler	= &proc_dointvec,
	},
	{
		.procname	= "debug",
		.mode		= 0644,
		.data		= &debug,
		.maxlen		= sizeof(int),
		.proc_handler	= &proc_dointvec,
	},
	{
		.procname	= "hashsize",
		.mode		= 0644,
		.data		= &ipt_netflow_hash_size,
		.maxlen		= sizeof(int),
		.proc_handler	= &hsize_procctl,
	},
	{
		.procname	= "sndbuf",
		.mode		= 0644,
		.maxlen		= sizeof(int),
		.proc_handler	= &sndbuf_procctl,
	},
	{
		.procname	= "destination",
		.mode		= 0644,
		.data		= &destination_buf,
		.maxlen		= sizeof(destination_buf),
		.proc_handler	= &destination_procctl,
	},
	{
		.procname	= "aggregation",
		.mode		= 0644,
		.data		= &aggregation_buf,
		.maxlen		= sizeof(aggregation_buf),
		.proc_handler	= &aggregation_procctl,
	},
	{
		.procname	= "maxflows",
		.mode		= 0644,
		.data		= &maxflows,
		.maxlen		= sizeof(int),
		.proc_handler	= &proc_dointvec,
	},
	{ .ctl_name = 0 }
};

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25)
static struct ctl_table netflow_sysctl_root[] = {
	{
		.procname	= "netflow",
		.mode		= 0555,
		.child		= netflow_sysctl_table,
	},
	{ .ctl_name = 0 }
};

static struct ctl_table netflow_net_table[] = {
	{
		.ctl_name	= CTL_NET,
		.procname	= "net",
		.mode		= 0555,
		.child		= netflow_sysctl_root,
	},
	{ .ctl_name = 0 }
};
#else /* 2.6.25 */
static struct ctl_path netflow_sysctl_path[] = {
	{ .procname = "net", .ctl_name = CTL_NET },
	{ .procname = "netflow" },
	{ }
};
#endif /* 2.6.25 */
#endif /* CONFIG_SYSCTL */

/* socket code */
static void sk_error_report(struct sock *sk)
{
	/* clear connection refused errors if any */
	write_lock_bh(&sk->sk_callback_lock);
	if (debug > 1)
		printk(KERN_INFO "NETFLOW: socket error <%d>\n", sk->sk_err);
	sk->sk_err = 0;
	write_unlock_bh(&sk->sk_callback_lock);
	NETFLOW_STAT_INC(sock_errors);
	return;
}

// return numbers of sends succeded, 0 if none
static int netflow_send_pdu(void *buffer, int len)
{
	struct msghdr msg = { .msg_flags = MSG_DONTWAIT|MSG_NOSIGNAL };
	struct kvec iov = { buffer, len };
	int retok = 0, ret;
	int snum = 0;
	struct ipt_netflow_sock *usock;

	read_lock(&sock_lock);
	list_for_each_entry(usock, &usock_list, list) {
		if (debug)
			printk(KERN_INFO "netflow_send_pdu: sendmsg(%d, %d) [%u %u]\n",
			       snum,
			       len,
			       atomic_read(&usock->sock->sk->sk_wmem_alloc),
			       usock->sock->sk->sk_sndbuf);
		ret = kernel_sendmsg(usock->sock, &msg, &iov, 1, (size_t)len);
		if (ret < 0) {
			char *suggestion = "";

			NETFLOW_STAT_INC(send_failed);
			if (ret == -EAGAIN) {
				atomic_inc(&usock->err_full);
				suggestion = ": increase sndbuf!";
			} else
				atomic_inc(&usock->err_other);
			printk(KERN_ERR "netflow_send_pdu[%d]: sendmsg error %d: data loss %llu pkt, %llu bytes%s\n",
			       snum, ret, pdu_packets, pdu_traf, suggestion);
		} else {
			unsigned int wmem = atomic_read(&usock->sock->sk->sk_wmem_alloc);
			if (wmem > atomic_read(&usock->wmem_peak))
				atomic_set(&usock->wmem_peak, wmem);
			NETFLOW_STAT_INC(send_success);
			NETFLOW_STAT_ADD(exported_size, ret);
			retok++;
		}
		snum++;
	}
	read_unlock(&sock_lock);
	return retok;
}

static void usock_free(struct ipt_netflow_sock *usock)
{
	printk(KERN_INFO "netflow: remove destination %u.%u.%u.%u:%u (%p)\n",
	       HIPQUAD(usock->ipaddr),
	       usock->port,
	       usock->sock);
	if (usock->sock)
		sock_release(usock->sock);
	usock->sock = NULL;
	vfree(usock); 
}

static void destination_fini(void)
{
	write_lock(&sock_lock);
	while (!list_empty(&usock_list)) {
		struct ipt_netflow_sock *usock;

		usock = list_entry(usock_list.next, struct ipt_netflow_sock, list);
		list_del(&usock->list);
		write_unlock(&sock_lock);
		usock_free(usock);
		write_lock(&sock_lock);
	}
	write_unlock(&sock_lock);
}

static void add_usock(struct ipt_netflow_sock *usock)
{
	struct ipt_netflow_sock *sk;

	/* don't need empty sockets */
	if (!usock->sock) {
		usock_free(usock);
		return;
	}

	write_lock(&sock_lock);
	/* don't need duplicated sockets */
	list_for_each_entry(sk, &usock_list, list) {
		if (sk->ipaddr == usock->ipaddr &&
		    sk->port == usock->port) {
			write_unlock(&sock_lock);
			usock_free(usock);
			return;
		}
	}
	list_add_tail(&usock->list, &usock_list);
	printk(KERN_INFO "netflow: added destination %u.%u.%u.%u:%u\n",
	       HIPQUAD(usock->ipaddr),
	       usock->port);
	write_unlock(&sock_lock);
}

static struct socket *usock_alloc(__be32 ipaddr, unsigned short port)
{
	struct sockaddr_in sin;
	struct socket *sock;
	int error;

	if ((error = sock_create_kern(PF_INET, SOCK_DGRAM, IPPROTO_UDP, &sock)) < 0) {
		printk(KERN_ERR "netflow: sock_create_kern error %d\n", error);
		return NULL;
	}
	sock->sk->sk_allocation = GFP_ATOMIC;
	sock->sk->sk_prot->unhash(sock->sk); /* hidden from input */
	sock->sk->sk_error_report = &sk_error_report; /* clear ECONNREFUSED */
	if (sndbuf)
		sock->sk->sk_sndbuf = sndbuf;
	else
		sndbuf = sock->sk->sk_sndbuf;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family      = AF_INET;
	sin.sin_addr.s_addr = htonl(ipaddr);
	sin.sin_port        = htons(port);
	if ((error = sock->ops->connect(sock, (struct sockaddr *)&sin,
				  sizeof(sin), 0)) < 0) {
		printk(KERN_ERR "netflow: error connecting UDP socket %d\n", error);
		sock_release(sock);
		return NULL;
	}
	return sock;
}

#define SEPARATORS " ,;\t\n"
static int add_destinations(char *ptr)
{
	while (ptr) {
		unsigned char ip[4]; 
		unsigned short port;

		ptr += strspn(ptr, SEPARATORS);

		if (sscanf(ptr, "%hhu.%hhu.%hhu.%hhu:%hu",
			   ip, ip + 1, ip + 2, ip + 3, &port) == 5) {
			struct ipt_netflow_sock *usock;

			if (!(usock = vmalloc(sizeof(*usock)))) {
				printk(KERN_ERR "netflow: can't vmalloc socket\n");
				return -ENOMEM;
			}

			memset(usock, 0, sizeof(*usock));
			usock->ipaddr = ntohl(*(__be32 *)ip);
			usock->port = port;
			usock->sock = usock_alloc(usock->ipaddr, port);
			atomic_set(&usock->wmem_peak, 0);
			atomic_set(&usock->err_full, 0);
			atomic_set(&usock->err_other, 0);
			add_usock(usock);
		} else
			break;

		ptr = strpbrk(ptr, SEPARATORS);
	}
	return 0;
}

static void aggregation_fini(struct list_head *list)
{
	write_lock_bh(&aggr_lock);
	while (!list_empty(list)) {
		struct netflow_aggr_n *aggr; /* match netflow_aggr_p too */

		aggr = list_entry(list->next, struct netflow_aggr_n, list);
		list_del(&aggr->list);
		write_unlock_bh(&aggr_lock);
		vfree(aggr);
		write_lock_bh(&aggr_lock);
	}
	write_unlock_bh(&aggr_lock);
}

static int add_aggregation(char *ptr)
{
	struct netflow_aggr_n *aggr_n, *aggr, *tmp;
	struct netflow_aggr_p *aggr_p;
	LIST_HEAD(new_aggr_n_list);
	LIST_HEAD(new_aggr_p_list);
	LIST_HEAD(old_aggr_list);

	while (ptr) {
		unsigned char ip[4]; 
		unsigned int mask;
		unsigned int port1, port2;
		unsigned int aggr_to;

		ptr += strspn(ptr, SEPARATORS);

		if (sscanf(ptr, "%hhu.%hhu.%hhu.%hhu/%u=%u",
			   ip, ip + 1, ip + 2, ip + 3, &mask, &aggr_to) == 6) {

			if (!(aggr_n = vmalloc(sizeof(*aggr_n)))) {
				printk(KERN_ERR "netflow: can't vmalloc aggr\n");
				return -ENOMEM;
			}
			memset(aggr_n, 0, sizeof(*aggr_n));

			aggr_n->addr = ntohl(*(__be32 *)ip);
			aggr_n->mask = bits2mask(mask);
			aggr_n->aggr_mask = bits2mask(aggr_to);
			aggr_n->prefix = mask;
			printk(KERN_INFO "netflow: add aggregation [%u.%u.%u.%u/%u=%u]\n",
			       HIPQUAD(aggr_n->addr), mask, aggr_to);
			list_add_tail(&aggr_n->list, &new_aggr_n_list);

		} else if (sscanf(ptr, "%u-%u=%u", &port1, &port2, &aggr_to) == 3 ||
			   sscanf(ptr, "%u=%u", &port2, &aggr_to) == 2) {

			if (!(aggr_p = vmalloc(sizeof(*aggr_p)))) {
				printk(KERN_ERR "netflow: can't vmalloc aggr\n");
				return -ENOMEM;
			}
			memset(aggr_p, 0, sizeof(*aggr_p));

			aggr_p->port1 = port1;
			aggr_p->port2 = port2;
			aggr_p->aggr_port = aggr_to;
			printk(KERN_INFO "netflow: add aggregation [%u-%u=%u]\n",
			       port1, port2, aggr_to);
			list_add_tail(&aggr_p->list, &new_aggr_p_list);
		} else {
			printk(KERN_ERR "netflow: bad aggregation rule: %s (ignoring)\n", ptr);
			break;
		}

		ptr = strpbrk(ptr, SEPARATORS);
	}

	/* swap lists */
	write_lock_bh(&aggr_lock);
	list_for_each_entry_safe(aggr, tmp, &aggr_n_list, list)
		list_move(&aggr->list, &old_aggr_list);
	list_for_each_entry_safe(aggr, tmp, &aggr_p_list, list)
		list_move(&aggr->list, &old_aggr_list);

	list_for_each_entry_safe(aggr, tmp, &new_aggr_n_list, list)
		list_move_tail(&aggr->list, &aggr_n_list);
	list_for_each_entry_safe(aggr, tmp, &new_aggr_p_list, list)
		list_move_tail(&aggr->list, &aggr_p_list);
	write_unlock_bh(&aggr_lock);
	aggregation_fini(&old_aggr_list);
	return 0;
}

static inline u_int32_t hash_netflow(const struct ipt_netflow_tuple *tuple)
{
	/* tuple is rounded to u32s */
	return jhash2((u32 *)tuple, NETFLOW_TUPLE_SIZE, ipt_netflow_hash_rnd) % ipt_netflow_hash_size;
}

static struct ipt_netflow *
ipt_netflow_find(const struct ipt_netflow_tuple *tuple)
{
	struct ipt_netflow *nf;
	unsigned int hash = hash_netflow(tuple);
	struct hlist_node *pos;

	hlist_for_each_entry(nf, pos, &ipt_netflow_hash[hash], hlist) {
		if (ipt_netflow_tuple_equal(tuple, &nf->tuple) &&
		    nf->nr_bytes < FLOW_FULL_WATERMARK) {
			NETFLOW_STAT_INC(found);
			return nf;
		}
		NETFLOW_STAT_INC(searched);
	}
	NETFLOW_STAT_INC(notfound);
	return NULL;
}

static struct hlist_head *alloc_hashtable(int size)
{
	struct hlist_head *hash;

	hash = vmalloc(sizeof(struct list_head) * size);
	if (hash) {
		int i;

		for (i = 0; i < size; i++)
			INIT_HLIST_HEAD(&hash[i]);
	} else
		printk(KERN_ERR "netflow: unable to vmalloc hash table.\n");

	return hash;
}

static int set_hashsize(int new_size)
{
	struct hlist_head *new_hash, *old_hash;
	unsigned int hash;
	struct ipt_netflow *nf;
	int rnd;

	printk(KERN_INFO "netflow: allocating new hash table %u -> %u buckets\n",
	       ipt_netflow_hash_size, new_size);
	new_hash = alloc_hashtable(sizeof(struct list_head) * new_size);
	if (!new_hash)
		return -ENOMEM;

	get_random_bytes(&rnd, 4);

	/* rehash */
	spin_lock_bh(&ipt_netflow_lock);
	old_hash = ipt_netflow_hash;
	ipt_netflow_hash = new_hash;
	ipt_netflow_hash_size = new_size;
	ipt_netflow_hash_rnd = rnd;
	/* hash_netflow() is dependent on ipt_netflow_hash_* values */
	list_for_each_entry(nf, &ipt_netflow_list, list) {
		hash = hash_netflow(&nf->tuple);
		/* hlist_add_head overwrites hlist pointers for this node
		 * so it's good */
		hlist_add_head(&nf->hlist, &new_hash[hash]);
	}
	spin_unlock_bh(&ipt_netflow_lock);

	vfree(old_hash);

	return 0;
}

static struct ipt_netflow *
ipt_netflow_alloc(struct ipt_netflow_tuple *tuple)
{
	struct ipt_netflow *nf;
	long count;

	nf = kmem_cache_alloc(ipt_netflow_cachep, GFP_ATOMIC);
	if (!nf) {
		printk(KERN_ERR "Can't allocate netflow.\n");
		return NULL;
	}

	memset(nf, 0, sizeof(*nf));
	nf->tuple = *tuple;

	count = atomic_inc_return(&ipt_netflow_count);
	if (count > peakflows) {
		peakflows = count;
		peakflows_at = jiffies;
	}

	return nf;
}

static void ipt_netflow_free(struct ipt_netflow *nf)
{
	atomic_dec(&ipt_netflow_count);
	kmem_cache_free(ipt_netflow_cachep, nf);
}

static struct ipt_netflow *
init_netflow(struct ipt_netflow_tuple *tuple,
	     struct sk_buff *skb)
{
	struct ipt_netflow *nf;
	unsigned int hash;

	nf = ipt_netflow_alloc(tuple);
	if (!nf)
		return NULL;

	hash = hash_netflow(&nf->tuple);
	hlist_add_head(&nf->hlist, &ipt_netflow_hash[hash]);
	list_add(&nf->list, &ipt_netflow_list);

	return nf;
}

/* cook pdu, send, and clean */
static void __netflow_export_pdu(void)
{
	struct timeval tv;
	int pdusize;

	if (!pdu.nr_records)
		return;

	if (debug > 1)
		printk(KERN_INFO "netflow_export_pdu with %d records\n", pdu.nr_records);
	do_gettimeofday(&tv);

	pdu.version	= htons(5);
	pdu.ts_uptime	= htonl(jiffies_to_msecs(jiffies));
	pdu.ts_usecs	= htonl(tv.tv_sec);
	pdu.ts_unsecs	= htonl(tv.tv_usec);
	//pdu.eng_type	= 0;
	//pdu.eng_id	= 0;
	//pdu.padding	= 0;

	pdu.seq = htonl(ntohl(pdu.seq) + pdu.nr_records);
	pdusize = NETFLOW5_HEADER_SIZE + sizeof(struct netflow5_record) * pdu.nr_records;

	/* especially fix nr_records before export */
	pdu.nr_records	= htons(pdu.nr_records);

	if (netflow_send_pdu(&pdu, pdusize) == 0) {
		/* not least one send succeded, account stat for dropped packets */
		NETFLOW_STAT_ADD(pkt_drop, pdu_packets);
		NETFLOW_STAT_ADD(traf_drop, pdu_traf);
	}

	pdu.nr_records	= 0;
	pdu_packets = 0;
	pdu_traf = 0;
}

static void netflow_export_flow(struct ipt_netflow *nf)
{
	struct netflow5_record *rec;

	spin_lock(&pdu_lock);
	if (debug > 2)
		printk(KERN_INFO "adding flow to export (%d)\n", pdu.nr_records);

	pdu_packets += nf->nr_packets;
	pdu_traf += nf->nr_bytes;
	pdu_ts_mod = jiffies;
	rec = &pdu.flow[pdu.nr_records++];

	/* make V5 flow record */
	rec->s_addr	= nf->tuple.s_addr;
	rec->d_addr	= nf->tuple.d_addr;
	//rec->nexthop	= 0;
	rec->i_ifc	= htons(nf->tuple.i_ifc);
	rec->o_ifc	= htons(nf->o_ifc);
	rec->nr_packets = htonl(nf->nr_packets);
	rec->nr_octets	= htonl(nf->nr_bytes);
	rec->ts_first	= htonl(jiffies_to_msecs(nf->ts_first));
	rec->ts_last	= htonl(jiffies_to_msecs(nf->ts_last));
	rec->s_port	= nf->tuple.s_port;
	rec->d_port	= nf->tuple.d_port;
	//rec->reserved	= 0;
	rec->tcp_flags	= nf->tcp_flags;
	rec->protocol	= nf->tuple.protocol;
	rec->tos	= nf->tuple.tos;
	//rec->s_as	= 0;
	//rec->d_as	= 0;
	rec->s_mask	= nf->s_mask;
	rec->d_mask	= nf->d_mask;
	//rec->padding	= 0;
	ipt_netflow_free(nf);

	if (pdu.nr_records == NETFLOW5_RECORDS_MAX)
		__netflow_export_pdu();
	spin_unlock(&pdu_lock);
}

static inline int active_needs_export(struct ipt_netflow *nf, long a_timeout)
{
	/* active too long, finishing, or having too much bytes */
	return ((jiffies - nf->ts_first) > a_timeout) ||
		(nf->tuple.protocol == IPPROTO_TCP &&
		 (nf->tcp_flags & TCP_FIN_RST) &&
		 (jiffies - nf->ts_last) > (1 * HZ)) ||
		nf->nr_bytes >= FLOW_FULL_WATERMARK;
}

/* could be called with zero to flush cache and pdu */
static void netflow_scan_inactive_timeout(long timeout)
{
	long i_timeout = timeout * HZ;
	long a_timeout = active_timeout * HZ;

	spin_lock_bh(&ipt_netflow_lock);
	while (!list_empty(&ipt_netflow_list)) {
		struct ipt_netflow *nf;
	       
		nf = list_entry(ipt_netflow_list.prev, struct ipt_netflow, list);
		/* Note: i_timeout checked with >= to allow specifying zero timeout
		 * to purge all flows on module unload */
		if (((jiffies - nf->ts_last) >= i_timeout) ||
		    active_needs_export(nf, a_timeout)) {
			hlist_del(&nf->hlist);
			list_del(&nf->list);
			spin_unlock_bh(&ipt_netflow_lock);
			NETFLOW_STAT_ADD(pkt_out, nf->nr_packets);
			NETFLOW_STAT_ADD(traf_out, nf->nr_bytes);
			netflow_export_flow(nf);
			spin_lock_bh(&ipt_netflow_lock);
		} else {
			/* all flows which need to be exported is always at the tail
			 * so if no more exportable flows we can break */
			break;
		}
	}
	spin_unlock_bh(&ipt_netflow_lock);

	/* flush flows stored in pdu if there no new flows for too long */
	/* Note: using >= to allow flow purge on zero timeout */
	if ((jiffies - pdu_ts_mod) >= i_timeout) {
		spin_lock(&pdu_lock);
		__netflow_export_pdu();
		spin_unlock(&pdu_lock);
	}
}

static void netflow_work_fn(struct work_struct *dummy)
{
	netflow_scan_inactive_timeout(inactive_timeout);
	schedule_delayed_work(&netflow_work, HZ / 10);
}

#define RATESHIFT 2
#define SAMPLERATE (RATESHIFT*RATESHIFT)
#define NUMSAMPLES(minutes) (minutes * 60 / SAMPLERATE)
#define _A(v, m) (v) * (1024 * 2 / (NUMSAMPLES(m) + 1)) >> 10
// x * (1024 / y) >> 10 is because I can not just divide long long integer
#define CALC_RATE(ewma, cur, minutes) ewma += _A(cur - ewma, minutes)
// calculate EWMA throughput rate for whole module
static void rate_timer_calc(unsigned long dummy)
{
	static u64 old_pkt_total = 0;
	static u64 old_traf_total = 0;
	static u64 old_searched = 0;
	static u64 old_found = 0;
	static u64 old_notfound = 0;
	u64 searched = 0;
	u64 found = 0;
	u64 notfound = 0;
	unsigned int dsrch, dfnd, dnfnd;
	u64 pkt_total = 0;
	u64 traf_total = 0;
	int cpu;

	for_each_present_cpu(cpu) {
		struct ipt_netflow_stat *st = &per_cpu(ipt_netflow_stat, cpu);

		pkt_total += st->pkt_total;
		traf_total += st->traf_total;
		searched += st->searched;
		found += st->found;
		notfound += st->notfound;
	}

	sec_prate = (pkt_total - old_pkt_total) >> RATESHIFT;
	CALC_RATE(min5_prate, sec_prate, 5);
	CALC_RATE(min_prate, sec_prate, 1);
	old_pkt_total = pkt_total;

	sec_brate = ((traf_total - old_traf_total) * 8) >> RATESHIFT;
	CALC_RATE(min5_brate, sec_brate, 5);
	CALC_RATE(min_brate, sec_brate, 1);
	old_traf_total = traf_total;

	dsrch = searched - old_searched;
	dfnd = found - old_found;
	dnfnd = notfound - old_notfound;
	old_searched = searched;
	old_found = found;
	old_notfound = notfound;
	/* if there is no access to hash keep rate steady */
	metric = (dfnd + dnfnd)? 10 * (dsrch + dfnd + dnfnd) / (dfnd + dnfnd) : metric;
	CALC_RATE(min15_metric, (unsigned long long)metric, 15);
	CALC_RATE(min5_metric, (unsigned long long)metric, 5);
	CALC_RATE(min_metric, (unsigned long long)metric, 1);

	mod_timer(&rate_timer, jiffies + (HZ * SAMPLERATE));
}

/* packet receiver */
static unsigned int netflow_target(
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)
			   struct sk_buff **pskb,
#else
			   struct sk_buff *skb,
#endif
			   const struct net_device *if_in,
			   const struct net_device *if_out,
			   unsigned int hooknum,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,17)
			   const struct xt_target *target,
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,19)
			   const void *targinfo,
			   void *userinfo)
#else
			   const void *targinfo)
#endif

{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)
	struct sk_buff *skb = *pskb;
#endif
	struct iphdr _iph, *iph;
	struct ipt_netflow_tuple tuple;
	struct ipt_netflow *nf;
	__u8 tcp_flags;
	struct netflow_aggr_n *aggr_n;
	struct netflow_aggr_p *aggr_p;
	__u8 s_mask, d_mask;

	iph = skb_header_pointer(skb, 0, sizeof(_iph), &_iph); //iph = ip_hdr(skb);

	if (iph == NULL) {
		NETFLOW_STAT_INC(truncated);
		NETFLOW_STAT_INC(pkt_drop);
		return IPT_CONTINUE;
	}

	tuple.s_addr	= iph->saddr;
	tuple.d_addr	= iph->daddr;
	tuple.s_port	= 0;
	tuple.d_port	= 0;
	tuple.i_ifc	= if_in? if_in->ifindex : -1;
	tuple.protocol	= iph->protocol;
	tuple.tos	= iph->tos;
	tcp_flags	= 0; /* Cisco sometimes have TCP ACK for non TCP packets, don't get it */
	s_mask		= 0;
	d_mask		= 0;

	if (iph->frag_off & htons(IP_OFFSET))
		NETFLOW_STAT_INC(frags);
	else {
		switch (tuple.protocol) {
		    case IPPROTO_TCP: {
			struct tcphdr _hdr, *hp;

			if ((hp = skb_header_pointer(skb, iph->ihl * 4, 14, &_hdr))) {
				tuple.s_port = hp->source;
				tuple.d_port = hp->dest;
				tcp_flags = (u_int8_t)(ntohl(tcp_flag_word(hp)) >> 16);
			}
			break;
		    }
		    case IPPROTO_UDP: {
			struct udphdr _hdr, *hp;

			if ((hp = skb_header_pointer(skb, iph->ihl * 4, 4, &_hdr))) {
				tuple.s_port = hp->source;
				tuple.d_port = hp->dest;
			}
			break;
		    }
		    case IPPROTO_ICMP: {
			struct icmphdr _hdr, *hp;

			if ((hp = skb_header_pointer(skb, iph->ihl * 4, 2, &_hdr)))
				tuple.d_port = (hp->type << 8) | hp->code;
			break;
		    }
		    case IPPROTO_IGMP: {
			struct igmphdr *_hdr, *hp;

			if ((hp = skb_header_pointer(skb, iph->ihl * 4, 1, &_hdr)))
				tuple.d_port = hp->type;
			}
			break;
	       	}
	} /* not fragmented */

	/* aggregate networks */
	read_lock_bh(&aggr_lock);
	list_for_each_entry(aggr_n, &aggr_n_list, list)
		if ((ntohl(tuple.s_addr) & aggr_n->mask) == aggr_n->addr) {
			tuple.s_addr &= htonl(aggr_n->aggr_mask);
			s_mask = aggr_n->prefix;
			break; 
		}
	list_for_each_entry(aggr_n, &aggr_n_list, list)
		if ((ntohl(tuple.d_addr) & aggr_n->mask) == aggr_n->addr) {
			tuple.d_addr &= htonl(aggr_n->aggr_mask);
			d_mask = aggr_n->prefix;
			break; 
		}

	/* aggregate ports */
	list_for_each_entry(aggr_p, &aggr_p_list, list)
		if (ntohs(tuple.s_port) >= aggr_p->port1 &&
		    ntohs(tuple.s_port) <= aggr_p->port2) {
			tuple.s_port = htons(aggr_p->aggr_port);
			break;
		}

	list_for_each_entry(aggr_p, &aggr_p_list, list)
		if (ntohs(tuple.d_port) >= aggr_p->port1 &&
		    ntohs(tuple.d_port) <= aggr_p->port2) {
			tuple.d_port = htons(aggr_p->aggr_port);
			break;
		}
	read_unlock_bh(&aggr_lock);

	spin_lock_bh(&ipt_netflow_lock);
	/* record */
	nf = ipt_netflow_find(&tuple);
	if (!nf) {
		if (maxflows > 0 && atomic_read(&ipt_netflow_count) >= maxflows) {
			/* This is DOS attack prevention */
			NETFLOW_STAT_INC(maxflows_err);
			NETFLOW_STAT_INC(pkt_drop);
			NETFLOW_STAT_ADD(traf_drop, ntohs(iph->tot_len));
			spin_unlock_bh(&ipt_netflow_lock);
			return IPT_CONTINUE;
		}

		nf = init_netflow(&tuple, skb);
		if (!nf || IS_ERR(nf)) {
			NETFLOW_STAT_INC(alloc_err);
			NETFLOW_STAT_INC(pkt_drop);
			NETFLOW_STAT_ADD(traf_drop, ntohs(iph->tot_len));
			spin_unlock_bh(&ipt_netflow_lock);
			return IPT_CONTINUE;
		}

		nf->ts_first = jiffies;
		nf->tcp_flags = tcp_flags;
		nf->o_ifc = if_out? if_out->ifindex : -1;
		nf->s_mask = s_mask;
		nf->d_mask = d_mask;

		if (debug > 2)
			printk(KERN_INFO "ipt_netflow: new (%u) %hd:%hd SRC=%u.%u.%u.%u:%u DST=%u.%u.%u.%u:%u\n",
			       atomic_read(&ipt_netflow_count),
			       tuple.i_ifc, nf->o_ifc,
			       NIPQUAD(tuple.s_addr), ntohs(tuple.s_port),
			       NIPQUAD(tuple.d_addr), ntohs(tuple.d_port));
	} else {
		/* ipt_netflow_list is sorted by access time:
		 * most recently accessed flows are at head, old flows remain at tail
		 * this function bubble up flow to the head */
		list_move(&nf->list, &ipt_netflow_list);
	}

	nf->nr_packets++;
	nf->nr_bytes += ntohs(iph->tot_len);
	nf->ts_last = jiffies;
	nf->tcp_flags |= tcp_flags;

	NETFLOW_STAT_INC(pkt_total);
	NETFLOW_STAT_ADD(traf_total, ntohs(iph->tot_len));

	if (active_needs_export(nf, active_timeout * HZ)) {
		/* ok, if this active flow to be exported
		 * bubble it to the tail */
		list_move_tail(&nf->list, &ipt_netflow_list);

		/* Blog: I thought about forcing timer to wake up sooner if we have
		 * enough exportable flows, but in fact this doesn't have much sense,
		 * becasue this would only move flow data from one memory to another
		 * (from our buffers to socket buffers, and socket buffers even have
		 * limited size). But yes, this is disputable. */
	}

	spin_unlock_bh(&ipt_netflow_lock);

	return IPT_CONTINUE;
}

static struct ipt_target ipt_netflow_reg = {
	.name		= "NETFLOW",
	.target		= netflow_target,
	.family		= AF_INET,
#ifndef RAW_PROMISC_HACK
	.table		= "filter",
#ifndef NF_IP_LOCAL_IN /* 2.6.25 */
	.hooks		= (1 << NF_INET_LOCAL_IN) | (1 << NF_INET_FORWARD) |
				(1 << NF_INET_LOCAL_OUT),
#else
	.hooks		= (1 << NF_IP_LOCAL_IN) | (1 << NF_IP_FORWARD) |
				(1 << NF_IP_LOCAL_OUT),
#endif /* NF_IP_LOCAL_IN */
#else
	.table          = "raw",
#ifndef NF_IP_LOCAL_IN
	.hooks          = (1 << NF_INET_LOCAL_IN) | (1 << NF_INET_FORWARD) |
				(1 << NF_INET_LOCAL_OUT) | (1 << NF_INET_PRE_ROUTING),
#else
	.hooks          = (1 << NF_IP_LOCAL_IN) | (1 << NF_IP_FORWARD) |
				(1 << NF_IP_LOCAL_OUT) | (1 << NF_IP_PRE_ROUTING),
#endif /* NF_IP_LOCAL_IN */
#endif /* !RAW_PROMISC_HACK */
	.me		= THIS_MODULE
};

static int __init ipt_netflow_init(void)
{
#ifdef CONFIG_PROC_FS
	struct proc_dir_entry *proc_stat;
#endif

	get_random_bytes(&ipt_netflow_hash_rnd, 4);

	/* determine hash size (idea from nf_conntrack_core.c) */
	if (!hashsize) {
		hashsize = (((num_physpages << PAGE_SHIFT) / 16384)
					 / sizeof(struct list_head));
		if (num_physpages > (1024 * 1024 * 1024 / PAGE_SIZE))
			hashsize = 8192;
	}
	if (hashsize < 16)
		hashsize = 16;
	printk(KERN_INFO "ipt_netflow version %s (%u buckets)\n",
		IPT_NETFLOW_VERSION, hashsize);

	ipt_netflow_hash_size = hashsize;
	ipt_netflow_hash = alloc_hashtable(ipt_netflow_hash_size);
	if (!ipt_netflow_hash) {
		printk(KERN_ERR "Unable to create ipt_neflow_hash\n");
		goto err;
	}

	ipt_netflow_cachep = kmem_cache_create("ipt_netflow",
						sizeof(struct ipt_netflow), 0,
						0, NULL
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,23)
						, NULL
#endif
					      );
	if (!ipt_netflow_cachep) {
		printk(KERN_ERR "Unable to create ipt_netflow slab cache\n");
		goto err_free_hash;
	}

#ifdef CONFIG_PROC_FS
	proc_stat = create_proc_entry("ipt_netflow", S_IRUGO, INIT_NET(proc_net_stat));
	if (!proc_stat) {
		printk(KERN_ERR "Unable to create /proc/net/stat/ipt_netflow entry\n");
		goto err_free_netflow_slab;
	}
	proc_stat->proc_fops = &nf_seq_fops;
	proc_stat->owner = THIS_MODULE;
	printk(KERN_INFO "netflow: registered: /proc/net/stat/ipt_netflow\n");
#endif

#ifdef CONFIG_SYSCTL
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25)
	netflow_sysctl_header = register_sysctl_table(netflow_net_table
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,21)
						      , 0 /* insert_at_head */
#endif
						      );
#else /* 2.6.25 */
	netflow_sysctl_header = register_sysctl_paths(netflow_sysctl_path, netflow_sysctl_table);
#endif
	if (!netflow_sysctl_header) {
		printk(KERN_ERR "netflow: can't register to sysctl\n");
		goto err_free_proc_stat;
	} else
		printk(KERN_INFO "netflow: registered: sysctl net.netflow\n");
#endif

	if (destination != destination_buf) {
		strlcpy(destination_buf, destination, sizeof(destination_buf));
		destination = destination_buf;
	}
	if (add_destinations(destination) < 0)
		goto err_free_sysctl;

	if (aggregation != aggregation_buf) {
		strlcpy(aggregation_buf, aggregation, sizeof(aggregation_buf));
		aggregation = aggregation_buf;
	}
	add_aggregation(aggregation);

	schedule_delayed_work(&netflow_work, HZ / 10);
	setup_timer(&rate_timer, rate_timer_calc, 0);
	mod_timer(&rate_timer, jiffies + (HZ * SAMPLERATE));

	if (xt_register_target(&ipt_netflow_reg))
		goto err_stop_timer;

	peakflows_at = jiffies;

	printk(KERN_INFO "ipt_netflow loaded.\n");
	return 0;

err_stop_timer:
	cancel_delayed_work(&netflow_work);
	flush_scheduled_work();
	del_timer_sync(&rate_timer);
	destination_fini();

	aggregation_fini(&aggr_n_list);
	aggregation_fini(&aggr_p_list);
	destination_fini();
err_free_sysctl:
#ifdef CONFIG_SYSCTL
	unregister_sysctl_table(netflow_sysctl_header);
err_free_proc_stat:
#endif
#ifdef CONFIG_PROC_FS
	remove_proc_entry("ipt_netflow", INIT_NET(proc_net_stat));
err_free_netflow_slab:
#endif  
	kmem_cache_destroy(ipt_netflow_cachep);
err_free_hash:
	vfree(ipt_netflow_hash);
err:
	return -ENOMEM;
}

static void __exit ipt_netflow_fini(void)
{
	printk(KERN_INFO "ipt_netflow unloading..\n");

	xt_unregister_target(&ipt_netflow_reg);
	cancel_delayed_work(&netflow_work);
	flush_scheduled_work();
	del_timer_sync(&rate_timer);

	synchronize_sched();

#ifdef CONFIG_SYSCTL
	unregister_sysctl_table(netflow_sysctl_header);
#endif
#ifdef CONFIG_PROC_FS
	remove_proc_entry("ipt_netflow", INIT_NET(proc_net_stat));
#endif

	netflow_scan_inactive_timeout(0); /* flush cache and pdu */
	destination_fini();
	aggregation_fini(&aggr_n_list);
	aggregation_fini(&aggr_p_list);

	kmem_cache_destroy(ipt_netflow_cachep);
	vfree(ipt_netflow_hash);

	printk(KERN_INFO "ipt_netflow unloaded.\n");
}

module_init(ipt_netflow_init);
module_exit(ipt_netflow_fini);

/* vim: set sw=8: */
