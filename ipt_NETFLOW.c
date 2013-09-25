/*
 * This is NetFlow exporting module (NETFLOW target) for linux
 * (c) 2008-2013 <abc@telekom.ru>
 *
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

#ifndef NIPQUAD
#define NIPQUAD(addr) \
	((unsigned char *)&addr)[0], \
	((unsigned char *)&addr)[1], \
	((unsigned char *)&addr)[2], \
	((unsigned char *)&addr)[3]
#endif
#ifndef HIPQUAD
#if defined(__LITTLE_ENDIAN)
#define HIPQUAD(addr) \
	((unsigned char *)&addr)[3], \
	((unsigned char *)&addr)[2], \
	((unsigned char *)&addr)[1], \
	((unsigned char *)&addr)[0]
#elif defined(__BIG_ENDIAN)
#define HIPQUAD NIPQUAD
#else
#error "Please fix asm/byteorder.h"
#endif /* __LITTLE_ENDIAN */
#endif

#ifndef IPT_CONTINUE
#define IPT_CONTINUE XT_CONTINUE
#define ipt_target xt_target
#endif

#define IPT_NETFLOW_VERSION "1.8.1"

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

static int protocol = 5;
module_param(protocol, int, 0400);
MODULE_PARM_DESC(protocol, "netflow protocol version (5, 9)");

static int refresh_rate = 20;
module_param(refresh_rate, int, 0400);
MODULE_PARM_DESC(refresh_rate, "netflow v9 refresh rate (packets)");

//static int timeout_rate = 30;
//module_param(timeout_rate, int, 0400);
//MODULE_PARM_DESC(timeout_rate, "netflow v9 timeout rate (minutes)");

static int hashsize;
module_param(hashsize, int, 0400);
MODULE_PARM_DESC(hashsize, "hash table size");

static int maxflows = 2000000;
module_param(maxflows, int, 0600);
MODULE_PARM_DESC(maxflows, "maximum number of flows");
static int peakflows = 0;
static unsigned long peakflows_at;

#define AGGR_SIZE 1024
static char aggregation_buf[AGGR_SIZE] = "";
static char *aggregation = aggregation_buf;
module_param(aggregation, charp, 0400);
MODULE_PARM_DESC(aggregation, "aggregation ruleset");

static DEFINE_PER_CPU(struct ipt_netflow_stat, ipt_netflow_stat);
static LIST_HEAD(usock_list);
static DEFINE_RWLOCK(sock_lock);

static unsigned int ipt_netflow_hash_rnd;
struct hlist_head *ipt_netflow_hash __read_mostly; /* hash table memory */
static unsigned int ipt_netflow_hash_size __read_mostly = 0; /* buckets */
static LIST_HEAD(ipt_netflow_list); /* all flows */
static LIST_HEAD(aggr_n_list);
static LIST_HEAD(aggr_p_list);
static DEFINE_RWLOCK(aggr_lock);
static struct kmem_cache *ipt_netflow_cachep __read_mostly; /* ipt_netflow memory */
static atomic_t ipt_netflow_count = ATOMIC_INIT(0);
static DEFINE_SPINLOCK(ipt_netflow_lock); /* hash table lock */

static long long pdu_packets = 0, pdu_traf = 0; /* how much accounted traffic in pdu */
static unsigned int pdu_seq = 0;
static unsigned long pdu_ts_mod; /* ts of last flow */
static struct netflow5_pdu pdu5;
static struct netflow9_pdu pdu9;
static void (*netflow_export_flow)(struct ipt_netflow *nf);
static void (*netflow_export_pdu)(void); /* called if timeout */
static void netflow_switch_version(int ver);

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,20)
static void netflow_work_fn(void *work);
static DECLARE_WORK(netflow_work, netflow_work_fn, NULL);
#else
static void netflow_work_fn(struct work_struct *work);
static DECLARE_DELAYED_WORK(netflow_work, netflow_work_fn);
#endif
static struct timer_list rate_timer;

#define TCP_FIN_RST 0x05

static long long sec_prate = 0, sec_brate = 0;
static long long min_prate = 0, min_brate = 0;
static long long min5_prate = 0, min5_brate = 0;
static unsigned int metric = 100, min15_metric = 100, min5_metric = 100, min_metric = 100; /* hash metrics */

static int set_hashsize(int new_size);
static void destination_removeall(void);
static int add_destinations(char *ptr);
static void aggregation_remove(struct list_head *list);
static int add_aggregation(char *ptr);
static void netflow_scan_and_export(int flush);
enum {
	DONT_FLUSH, AND_FLUSH
};
static int template_ids = FLOWSET_DATA_FIRST;


static inline __be32 bits2mask(int bits) {
	return (bits? 0xffffffff << (32 - bits) : 0);
}

static inline int mask2bits(__be32 mask) {
	int n;

	for (n = 0; mask; n++)
		mask = (mask << 1) & 0xffffffff;
	return n;
}

/* under that lock worker is always stopped and not rescheduled,
 * and we can call worker sub-functions manually */
static DEFINE_MUTEX(worker_lock);
static inline void __start_scan_worker(void)
{
	schedule_delayed_work(&netflow_work, HZ / 10);
}

static inline void start_scan_worker(void)
{
	__start_scan_worker();
	mutex_unlock(&worker_lock);
}

/* we always stop scanner before write_lock(&sock_lock)
 * to let it never hold that spin lock */
static inline void __stop_scan_worker(void)
{
	cancel_delayed_work_sync(&netflow_work);
}

static inline void stop_scan_worker(void)
{
	mutex_lock(&worker_lock);
	__stop_scan_worker();
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
	seq_printf(seq, "Hash: size %u (mem %uK), metric %d.%02d [%d.%02d, %d.%02d, %d.%02d]."
	    " MemTraf: %llu pkt, %llu K (pdu %llu, %llu).\n",
	    ipt_netflow_hash_size, 
	    (unsigned int)((ipt_netflow_hash_size * sizeof(struct hlist_head)) >> 10),
	    FFLOAT(metric, 100),
	    FFLOAT(min_metric, 100),
	    FFLOAT(min5_metric, 100),
	    FFLOAT(min15_metric, 100),
	    pkt_total - pkt_out + pdu_packets,
	    (traf_total - traf_out + pdu_traf) >> 10,
	    pdu_packets,
	    pdu_traf);

	seq_printf(seq, "NetFlow protocol version %d", protocol);
	if (protocol == 9)
		seq_printf(seq, ", refresh-rate %d, (templates %d)",
		    refresh_rate, template_ids - FLOWSET_DATA_FIRST);

	seq_printf(seq, ". Timeouts: active %d, inactive %d. Maxflows %u\n",
	    active_timeout,
	    inactive_timeout,
	    maxflows);

	seq_printf(seq, "Rate: %llu bits/sec, %llu packets/sec;"
	    " Avg 1 min: %llu bps, %llu pps; 5 min: %llu bps, %llu pps\n",
	    sec_brate, sec_prate, min_brate, min_prate, min5_brate, min5_prate);

	seq_printf(seq, "cpu#  stat: <search found new [metric], trunc frag alloc maxflows>,"
	    " sock: <ok fail cberr, bytes>, traffic: <pkt, bytes>, drop: <pkt, bytes>\n");

#define SAFEDIV(x,y) ((y)? (x) / (y) : 0)
	seq_printf(seq, "Total stat: %6llu %6llu %6llu [%d.%02d], %4u %4u %4u %4u,"
	    " sock: %6u %u %u, %llu K, traffic: %llu, %llu MB, drop: %llu, %llu K\n",
	    searched,
	    (unsigned long long)found,
	    (unsigned long long)notfound,
	    FFLOAT(SAFEDIV(100LL * (searched + found + notfound), (found + notfound)), 100),
	    truncated, frags, alloc_err, maxflows_err,
	    send_success, send_failed, sock_errors,
	    (unsigned long long)exported_size >> 10,
	    (unsigned long long)pkt_total, (unsigned long long)traf_total >> 20,
	    (unsigned long long)pkt_drop, (unsigned long long)traf_drop >> 10);

	if (num_present_cpus() > 1) {
		for_each_present_cpu(cpu) {
			struct ipt_netflow_stat *st;

			st = &per_cpu(ipt_netflow_stat, cpu);
			seq_printf(seq, "cpu%u  stat: %6llu %6llu %6llu [%d.%02d], %4u %4u %4u %4u,"
			    " sock: %6u %u %u, %llu K, traffic: %llu, %llu MB, drop: %llu, %llu K\n",
			    cpu,
			    (unsigned long long)st->searched,
			    (unsigned long long)st->found,
			    (unsigned long long)st->notfound,
			    FFLOAT(SAFEDIV(100LL * (st->searched + st->found + st->notfound), (st->found + st->notfound)), 100),
			    st->truncated, st->frags, st->alloc_err, st->maxflows_err,
			    st->send_success, st->send_failed, st->sock_errors,
			    (unsigned long long)st->exported_size >> 10,
			    (unsigned long long)st->pkt_total, (unsigned long long)st->traf_total >> 20,
			    (unsigned long long)st->pkt_drop, (unsigned long long)st->traf_drop >> 10);
		}
	}

	read_lock(&sock_lock);
	list_for_each_entry(usock, &usock_list, list) {
		seq_printf(seq, "sock%d: %u.%u.%u.%u:%u",
		    snum,
		    HIPQUAD(usock->ipaddr),
		    usock->port);
		if (usock->sock) {
			struct sock *sk = usock->sock->sk;

			seq_printf(seq, ", sndbuf %u, filled %u, peak %u;"
			    " err: sndbuf reached %u, connect %u, other %u\n",
			    sk->sk_sndbuf,
			    atomic_read(&sk->sk_wmem_alloc),
			    atomic_read(&usock->wmem_peak),
			    atomic_read(&usock->err_full),
			    atomic_read(&usock->err_connect),
			    atomic_read(&usock->err_other));
		} else
			seq_printf(seq, " unconnected (%u attempts).\n",
			    atomic_read(&usock->err_connect));
		snum++;
	}
	read_unlock(&sock_lock);

	read_lock_bh(&aggr_lock);
	snum = 0;
	list_for_each_entry(aggr_n, &aggr_n_list, list) {
		seq_printf(seq, "aggr#%d net: match %u.%u.%u.%u/%d strip %d (usage %u)\n",
		    snum,
		    HIPQUAD(aggr_n->addr),
		    mask2bits(aggr_n->mask),
		    mask2bits(aggr_n->aggr_mask),
		    atomic_read(&aggr_n->usage));
		snum++;
	}
	snum = 0;
	list_for_each_entry(aggr_p, &aggr_p_list, list) {
		seq_printf(seq, "aggr#%d port: ports %u-%u replace %u (usage %u)\n",
		    snum,
		    aggr_p->port1,
		    aggr_p->port2,
		    aggr_p->aggr_port,
		    atomic_read(&aggr_p->usage));
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

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,32)
#define BEFORE2632(x,y) x,y
#else /* since 2.6.32 */
#define BEFORE2632(x,y)
#endif

/* sysctl /proc/sys/net/netflow */
static int hsize_procctl(ctl_table *ctl, int write, BEFORE2632(struct file *filp,)
			 void __user *buffer, size_t *lenp, loff_t *fpos)
{
	void *orig = ctl->data;
	int ret, hsize;

	if (write)
		ctl->data = &hsize;
	ret = proc_dointvec(ctl, write, BEFORE2632(filp,) buffer, lenp, fpos);
	if (write) {
		ctl->data = orig;
		if (hsize < 1)
			return -EPERM;
		return set_hashsize(hsize)?:ret;
	} else
		return ret;
}

static int sndbuf_procctl(ctl_table *ctl, int write, BEFORE2632(struct file *filp,)
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
	if (usock->sock)
		sndbuf = usock->sock->sk->sk_sndbuf;
	read_unlock(&sock_lock);

	ctl->data = &sndbuf;
	ret = proc_dointvec(ctl, write, BEFORE2632(filp,) buffer, lenp, fpos);
	if (!write)
		return ret;
	if (sndbuf < SOCK_MIN_SNDBUF)
		sndbuf = SOCK_MIN_SNDBUF;
	stop_scan_worker();
	write_lock(&sock_lock);
	list_for_each_entry(usock, &usock_list, list) {
		if (usock->sock)
			usock->sock->sk->sk_sndbuf = sndbuf;
	}
	write_unlock(&sock_lock);
	start_scan_worker();
	return ret;
}

static int destination_procctl(ctl_table *ctl, int write, BEFORE2632(struct file *filp,)
			 void __user *buffer, size_t *lenp, loff_t *fpos)
{
	int ret;

	ret = proc_dostring(ctl, write, BEFORE2632(filp,) buffer, lenp, fpos);
	if (ret >= 0 && write) {
		stop_scan_worker();
		destination_removeall();
		add_destinations(destination_buf);
		start_scan_worker();
	}
	return ret;
}

static int aggregation_procctl(ctl_table *ctl, int write, BEFORE2632(struct file *filp,)
			 void __user *buffer, size_t *lenp, loff_t *fpos)
{
	int ret;

	if (debug > 1)
		printk(KERN_INFO "aggregation_procctl (%d) %u %llu\n", write, (unsigned int)(*lenp), *fpos);
	ret = proc_dostring(ctl, write, BEFORE2632(filp,) buffer, lenp, fpos);
	if (ret >= 0 && write) {
		add_aggregation(aggregation_buf);
	}
	return ret;
}

static int flush_procctl(ctl_table *ctl, int write, BEFORE2632(struct file *filp,)
			 void __user *buffer, size_t *lenp, loff_t *fpos)
{
	int ret;
	int val;

	val = 0;
	ctl->data = &val;
	ret = proc_dointvec(ctl, write, BEFORE2632(filp,) buffer, lenp, fpos);

	if (!write)
		return ret;

	if (val > 0) {
		printk(KERN_INFO "ipt_NETFLOW: forced flush\n");
		stop_scan_worker();
		netflow_scan_and_export(AND_FLUSH);
		start_scan_worker();
	}

	return ret;
}

static int protocol_procctl(ctl_table *ctl, int write, BEFORE2632(struct file *filp,)
			 void __user *buffer, size_t *lenp, loff_t *fpos)
{
	int ret;
	int ver = protocol;

	ctl->data = &ver;
	ret = proc_dointvec(ctl, write, BEFORE2632(filp,) buffer, lenp, fpos);

	if (!write)
		return ret;

	switch (ver) {
		case 5:
		case 9:
			printk(KERN_INFO "ipt_NETFLOW: forced flush (protocol version change)\n");
			stop_scan_worker();
			netflow_scan_and_export(AND_FLUSH);
			netflow_switch_version(ver);
			start_scan_worker();
			break;
		default:
			return -EPERM;
	}

	return ret;
}

static struct ctl_table_header *netflow_sysctl_header;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,20)
#define _CTL_NAME(x) .ctl_name = x,
#else
#define _CTL_NAME(x)
#endif
static struct ctl_table netflow_sysctl_table[] = {
	{
		_CTL_NAME(1)
		.procname	= "active_timeout",
		.mode		= 0644,
		.data		= &active_timeout,
		.maxlen		= sizeof(int),
		.proc_handler	= &proc_dointvec,
	},
	{
		_CTL_NAME(2)
		.procname	= "inactive_timeout",
		.mode		= 0644,
		.data		= &inactive_timeout,
		.maxlen		= sizeof(int),
		.proc_handler	= &proc_dointvec,
	},
	{
		_CTL_NAME(3)
		.procname	= "debug",
		.mode		= 0644,
		.data		= &debug,
		.maxlen		= sizeof(int),
		.proc_handler	= &proc_dointvec,
	},
	{
		_CTL_NAME(4)
		.procname	= "hashsize",
		.mode		= 0644,
		.data		= &ipt_netflow_hash_size,
		.maxlen		= sizeof(int),
		.proc_handler	= &hsize_procctl,
	},
	{
		_CTL_NAME(5)
		.procname	= "sndbuf",
		.mode		= 0644,
		.maxlen		= sizeof(int),
		.proc_handler	= &sndbuf_procctl,
	},
	{
		_CTL_NAME(6)
		.procname	= "destination",
		.mode		= 0644,
		.data		= &destination_buf,
		.maxlen		= sizeof(destination_buf),
		.proc_handler	= &destination_procctl,
	},
	{
		_CTL_NAME(7)
		.procname	= "aggregation",
		.mode		= 0644,
		.data		= &aggregation_buf,
		.maxlen		= sizeof(aggregation_buf),
		.proc_handler	= &aggregation_procctl,
	},
	{
		_CTL_NAME(8)
		.procname	= "maxflows",
		.mode		= 0644,
		.data		= &maxflows,
		.maxlen		= sizeof(int),
		.proc_handler	= &proc_dointvec,
	},
	{
		_CTL_NAME(9)
		.procname	= "flush",
		.mode		= 0644,
		.maxlen		= sizeof(int),
		.proc_handler	= &flush_procctl,
	},
	{
		_CTL_NAME(9)
		.procname	= "protocol",
		.mode		= 0644,
		.maxlen		= sizeof(int),
		.proc_handler	= &protocol_procctl,
	},
	{
		_CTL_NAME(9)
		.procname	= "refresh-rate",
		.mode		= 0644,
		.data		= &refresh_rate,
		.maxlen		= sizeof(int),
		.proc_handler	= &proc_dointvec,
	},
	{ }
};

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25)
static struct ctl_table netflow_sysctl_root[] = {
	{
		_CTL_NAME(33)
		.procname	= "netflow",
		.mode		= 0555,
		.child		= netflow_sysctl_table,
	},
	{ }
};

static struct ctl_table netflow_net_table[] = {
	{
		.ctl_name	= CTL_NET,
		.procname	= "net",
		.mode		= 0555,
		.child		= netflow_sysctl_root,
	},
	{ }
};
#else /* >= 2.6.25 */
static struct ctl_path netflow_sysctl_path[] = {
	{
		.procname = "net",
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
		.ctl_name = CTL_NET
#endif
	},
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
	NETFLOW_STAT_INC(sock_errors);
	write_unlock_bh(&sk->sk_callback_lock);
	return;
}

static struct socket *_usock_alloc(__be32 ipaddr, unsigned short port)
{
	struct sockaddr_in sin;
	struct socket *sock;
	int error;

	if ((error = sock_create_kern(PF_INET, SOCK_DGRAM, IPPROTO_UDP, &sock)) < 0) {
		printk(KERN_ERR "netflow: sock_create_kern error %d\n", -error);
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
		printk(KERN_ERR "netflow: error connecting UDP socket %d,"
		    " don't worry, will try reconnect later.\n", -error);
		/* ENETUNREACH when no interfaces */
		sock_release(sock);
		return NULL;
	}
	return sock;
}

static void usock_connect(struct ipt_netflow_sock *usock, int sendmsg)
{
	usock->sock = _usock_alloc(usock->ipaddr, usock->port);
	if (usock->sock) {
		if (sendmsg || debug)
			printk(KERN_INFO "netflow: connected %u.%u.%u.%u:%u\n",
			    HIPQUAD(usock->ipaddr),
			    usock->port);
	} else {
		atomic_inc(&usock->err_connect);
		if (debug)
			printk(KERN_INFO "netflow: connect to %u.%u.%u.%u:%u failed%s.\n",
			    HIPQUAD(usock->ipaddr),
			    usock->port,
			    (sendmsg)? " (pdu lost)" : "");
	}
	atomic_set(&usock->wmem_peak, 0);
	atomic_set(&usock->err_full, 0);
	atomic_set(&usock->err_other, 0);
}

// return numbers of sends succeded, 0 if none
/* only called in scan worker path */
static void netflow_sendmsg(void *buffer, int len)
{
	struct msghdr msg = { .msg_flags = MSG_DONTWAIT|MSG_NOSIGNAL };
	struct kvec iov = { buffer, len };
	int retok = 0, ret;
	int snum = 0;
	struct ipt_netflow_sock *usock;

	list_for_each_entry(usock, &usock_list, list) {
		if (!usock->sock)
			usock_connect(usock, 1);
		if (!usock->sock) {
			NETFLOW_STAT_INC_ATOMIC(send_failed);
			continue;
		}
		if (debug)
			printk(KERN_INFO "netflow_sendmsg: sendmsg(%d, %d) [%u %u]\n",
			       snum,
			       len,
			       atomic_read(&usock->sock->sk->sk_wmem_alloc),
			       usock->sock->sk->sk_sndbuf);
		ret = kernel_sendmsg(usock->sock, &msg, &iov, 1, (size_t)len);
		if (ret < 0) {
			char *suggestion = "";

			NETFLOW_STAT_INC_ATOMIC(send_failed);
			if (ret == -EAGAIN) {
				atomic_inc(&usock->err_full);
				suggestion = ": increase sndbuf!";
			} else
				atomic_inc(&usock->err_other);
			printk(KERN_ERR "netflow_sendmsg[%d]: sendmsg error %d: data loss %llu pkt, %llu bytes%s\n",
			       snum, ret, pdu_packets, pdu_traf, suggestion);
		} else {
			unsigned int wmem = atomic_read(&usock->sock->sk->sk_wmem_alloc);
			if (wmem > atomic_read(&usock->wmem_peak))
				atomic_set(&usock->wmem_peak, wmem);
			NETFLOW_STAT_INC_ATOMIC(send_success);
			NETFLOW_STAT_ADD_ATOMIC(exported_size, ret);
			retok++;
		}
		snum++;
	}
	if (retok == 0) {
		/* not least one send succeded, account stat for dropped packets */
		NETFLOW_STAT_ADD_ATOMIC(pkt_drop, pdu_packets);
		NETFLOW_STAT_ADD_ATOMIC(traf_drop, pdu_traf);
	}
}

static void usock_close_free(struct ipt_netflow_sock *usock)
{
	printk(KERN_INFO "netflow: removed destination %u.%u.%u.%u:%u\n",
	       HIPQUAD(usock->ipaddr),
	       usock->port);
	if (usock->sock)
		sock_release(usock->sock);
	usock->sock = NULL;
	vfree(usock); 
}

static void destination_removeall(void)
{
	write_lock(&sock_lock);
	while (!list_empty(&usock_list)) {
		struct ipt_netflow_sock *usock;

		usock = list_entry(usock_list.next, struct ipt_netflow_sock, list);
		list_del(&usock->list);
		write_unlock(&sock_lock);
		usock_close_free(usock);
		write_lock(&sock_lock);
	}
	write_unlock(&sock_lock);
}

static void add_usock(struct ipt_netflow_sock *usock)
{
	struct ipt_netflow_sock *sk;

	write_lock(&sock_lock);
	/* don't need duplicated sockets */
	list_for_each_entry(sk, &usock_list, list) {
		if (sk->ipaddr == usock->ipaddr &&
		    sk->port == usock->port) {
			write_unlock(&sock_lock);
			usock_close_free(usock);
			return;
		}
	}
	list_add_tail(&usock->list, &usock_list);
	printk(KERN_INFO "netflow: added destination %u.%u.%u.%u:%u%s\n",
	       HIPQUAD(usock->ipaddr),
	       usock->port,
	       (!usock->sock)? " (unconnected)" : "");
	write_unlock(&sock_lock);
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
			atomic_set(&usock->err_connect, 0);
			usock->ipaddr = ntohl(*(__be32 *)ip);
			usock->port = port;
			usock_connect(usock, 0);
			add_usock(usock);
		} else
			break;

		ptr = strpbrk(ptr, SEPARATORS);
	}
	return 0;
}

static void aggregation_remove(struct list_head *list)
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

	while (ptr && *ptr) {
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

			aggr_n->mask = bits2mask(mask);
			aggr_n->addr = ntohl(*(__be32 *)ip) & aggr_n->mask;
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
	aggregation_remove(&old_aggr_list);
	return 0;
}

static inline u_int32_t hash_netflow(const struct ipt_netflow_tuple *tuple)
{
	/* tuple is rounded to u32s */
	return jhash2((u32 *)tuple, NETFLOW_TUPLE_SIZE, ipt_netflow_hash_rnd) % ipt_netflow_hash_size;
}

static struct ipt_netflow *
ipt_netflow_find(const struct ipt_netflow_tuple *tuple, unsigned int hash)
{
	struct ipt_netflow *nf;
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,9,0)
#define BEFORE390(x) x
	struct hlist_node *pos;
#else /* since 3.9.0 */
#define BEFORE390(x)
#endif

	hlist_for_each_entry(nf, BEFORE390(pos), &ipt_netflow_hash[hash], hlist) {
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

	hash = vmalloc(sizeof(struct hlist_head) * size);
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
	new_hash = alloc_hashtable(new_size);
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
	     struct sk_buff *skb, unsigned int hash)
{
	struct ipt_netflow *nf;

	nf = ipt_netflow_alloc(tuple);
	if (!nf)
		return NULL;

	hlist_add_head(&nf->hlist, &ipt_netflow_hash[hash]);
	list_add(&nf->list, &ipt_netflow_list);

	return nf;
}

/* cook pdu, send, and clean */
/* only called in scan worker path */
static void netflow_export_pdu5(void)
{
	struct timeval tv;
	int pdusize;

	if (!pdu5.nr_records)
		return;

	if (debug > 1)
		printk(KERN_INFO "netflow_export_pdu5 with %d records\n", pdu5.nr_records);
	do_gettimeofday(&tv);

	pdu5.version	= htons(5);
	pdu5.ts_uptime	= htonl(jiffies_to_msecs(jiffies));
	pdu5.ts_usecs	= htonl(tv.tv_sec);
	pdu5.ts_unsecs	= htonl(tv.tv_usec);
	//pdu5.eng_type	= 0;
	//pdu5.eng_id	= 0;
	//pdu5.padding	= 0;

	pdusize = NETFLOW5_HEADER_SIZE + sizeof(struct netflow5_record) * pdu5.nr_records;

	/* especially fix nr_records before export */
	pdu5.nr_records	= htons(pdu5.nr_records);

	netflow_sendmsg(&pdu5, pdusize);

	pdu_seq = pdu_seq + ntohs(pdu5.nr_records);
	pdu5.seq = htonl(pdu_seq);

	pdu5.nr_records	= 0;
	pdu_packets = 0;
	pdu_traf    = 0;
}

/* only called in scan worker path */
static void netflow_export_flow5(struct ipt_netflow *nf)
{
	struct netflow5_record *rec;

	if (debug > 2)
		printk(KERN_INFO "adding flow to export (%d)\n", pdu5.nr_records);

	pdu_packets += nf->nr_packets;
	pdu_traf += nf->nr_bytes;
	pdu_ts_mod = jiffies;
	rec = &pdu5.flow[pdu5.nr_records++];

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

	if (pdu5.nr_records == NETFLOW5_RECORDS_MAX)
		netflow_export_pdu5();
}

static __u8 *pdu9_data_used = pdu9.data; /* up to */
static struct flowset_data *pdu9_flowset = NULL; /* current data flowset */

/* pdu is initially blank, export current pdu, and prepare next for filling. */
static void netflow_export_pdu9(void)
{
	struct timeval tv;
	int pdusize;

	if (!pdu9.nr_records)
		return;

	if (debug > 1)
		printk(KERN_INFO "netflow_export_pdu9 with %d records\n", pdu9.nr_records);

	pdu9.version		= htons(9);
	/* fix nr_records before export */
	pdu9.nr_records		= htons(pdu9.nr_records);
	pdu9.sys_uptime_ms	= htonl(jiffies_to_msecs(jiffies));
	do_gettimeofday(&tv);
	pdu9.export_time_s	= htonl(tv.tv_sec);
	// pdu9.source_id	= 0;

	pdusize = pdu9_data_used - (unsigned char *)&pdu9;

	netflow_sendmsg(&pdu9, pdusize);

	pdu_seq++;
	pdu9.seq = htonl(pdu_seq);

	pdu_packets = 0;
	pdu_traf    = 0;
	pdu9_data_used = pdu9.data;
	pdu9_flowset = NULL;
	pdu9.nr_records = 0;
}

static inline int pdu9_have_space(size_t size)
{
	return ((pdu9_data_used + size) <= (((unsigned char *)&pdu9) + sizeof(pdu9)));
}

static inline unsigned char *pdu9_grab_space(size_t size)
{
	unsigned char *ptr = pdu9_data_used;
	pdu9_data_used += size;
	return ptr;
}

// allocate data space in pdu, or fail if pdu is reallocated.
static inline unsigned char *pdu9_alloc_fail(size_t size)
{
	if (!pdu9_have_space(size)) {
		netflow_export_pdu9();
		return NULL;
	}
	return pdu9_grab_space(size);
}

/* doesn't fail, but can provide empty pdu. */
static unsigned char *pdu9_alloc(size_t size)
{
	return pdu9_alloc_fail(size) ?: pdu9_grab_space(size);
}

/* global table of sizes of template field types */
static u_int8_t tpl_element_sizes[] = {
	[IN_BYTES]	= 4,
	[IN_PKTS]	= 4,
	[PROTOCOL]	= 1,
	[TOS]		= 1,
	[TCP_FLAGS]	= 1,
	[L4_SRC_PORT]	= 2,
	[IPV4_SRC_ADDR]	= 4,
	[SRC_MASK]	= 1,
	[INPUT_SNMP]	= 2,
	[L4_DST_PORT]	= 2,
	[IPV4_DST_ADDR]	= 4,
	[DST_MASK]	= 1,
	[OUTPUT_SNMP]	= 2,
	[LAST_SWITCHED]	= 4,
	[FIRST_SWITCHED] = 4,
	[TOTAL_BYTES_EXP] = 4,
	[TOTAL_PKTS_EXP]  = 4,
	[TOTAL_FLOWS_EXP] = 4,
	[IP_PROTOCOL_VERSION] = 1
};

struct data_template {
	int length; /* number of elements in template */
	int tpl_size; /* summary size of template */
	int rec_size; /* summary size of all recods of template */
	int template_id_n; /* assigned from template_ids, network order. */
	int		exported_seq;
	unsigned long	exported_ts; /* jiffies */
	u_int16_t fields[]; /* {type, size} pairs */
} __attribute__ ((packed));

/* default template w/o aggregation */
static struct data_template template_ipv4 = {
	.fields = {
		IPV4_SRC_ADDR, 0,
		IPV4_DST_ADDR, 0,
		INPUT_SNMP, 0,
		OUTPUT_SNMP, 0,
		IN_PKTS, 0,
		IN_BYTES, 0,
		FIRST_SWITCHED, 0,
		LAST_SWITCHED, 0,
		L4_SRC_PORT, 0,
		L4_DST_PORT, 0,
		TCP_FLAGS, 0,
		PROTOCOL, 0,
		TOS, 0,
		0 /* terminator */
	}
};
/* template with aggregation */
static struct data_template template_ipv4_aggr = {
	.fields = {
		IPV4_SRC_ADDR, 0,
		IPV4_DST_ADDR, 0,
		INPUT_SNMP, 0,
		OUTPUT_SNMP, 0,
		IN_PKTS, 0,
		IN_BYTES, 0,
		FIRST_SWITCHED, 0,
		LAST_SWITCHED, 0,
		L4_SRC_PORT, 0,
		L4_DST_PORT, 0,
		TCP_FLAGS, 0,
		PROTOCOL, 0,
		TOS, 0,
		SRC_MASK, 0,
		DST_MASK, 0,
		0 /* terminator */
	}
};
#define TPL_FIELD_NSIZE 4 /* one complete template field's network size */

static void pdu9_add_template(struct data_template *tpl)
{
	int i;
	unsigned char *ptr;
	struct flowset_template *ntpl;
	__be16 *sptr;

	/* calc and cache template dimensions */
	if (!tpl->template_id_n) {
		tpl->template_id_n = htons(template_ids++);
		tpl->length = 0;
		tpl->rec_size = 0;
		tpl->tpl_size = 0;
		for (i = 0; ; ) {
			int type = tpl->fields[i++];
			int size;

			if (!type)
				break;
			size = tpl_element_sizes[type];
			tpl->fields[i++] = size;
			tpl->rec_size += size;
			tpl->length++;
		}
		tpl->tpl_size = sizeof(struct flowset_template) + tpl->length * TPL_FIELD_NSIZE;
	}


	ptr = pdu9_alloc(tpl->tpl_size);
	ntpl = (struct flowset_template *)ptr;
	ntpl->flowset_id  = htons(FLOWSET_TEMPLATE);
	ntpl->length	  = htons(tpl->tpl_size);
	ntpl->template_id = tpl->template_id_n;
	ntpl->field_count = htons(tpl->length);
	ptr += sizeof(struct flowset_template);
	sptr = (__be16 *)ptr;
	for (i = 0; ; ) {
		int type = tpl->fields[i++];
		if (!type)
			break;
		*sptr++ = htons(type);
		*sptr++ = htons(tpl->fields[i++]);
	}

	tpl->exported_seq = pdu_seq;
	tpl->exported_ts = jiffies;

	pdu9_flowset = NULL;
	pdu9.nr_records++;
}

/* encode one field */
static inline void add_ipv4_field(void *ptr, int type, struct ipt_netflow *nf)
{
	switch (type) {
		case IN_BYTES:	     *(__be32 *)ptr = htonl(nf->nr_bytes); break;
		case IN_PKTS:	     *(__be32 *)ptr = htonl(nf->nr_packets); break;
		case FIRST_SWITCHED: *(__be32 *)ptr = htonl(jiffies_to_msecs(nf->ts_first)); break;
		case LAST_SWITCHED:  *(__be32 *)ptr = htonl(jiffies_to_msecs(nf->ts_last)); break;
		case IPV4_SRC_ADDR:  *(__be32 *)ptr = nf->tuple.s_addr; break;
		case IPV4_DST_ADDR:  *(__be32 *)ptr = nf->tuple.d_addr; break;
		case L4_SRC_PORT:    *(__be16 *)ptr = nf->tuple.s_port; break;
		case L4_DST_PORT:    *(__be16 *)ptr = nf->tuple.d_port; break;
		case INPUT_SNMP:     *(__be16 *)ptr = htons(nf->tuple.i_ifc); break;
		case OUTPUT_SNMP:    *(__be16 *)ptr = htons(nf->o_ifc); break;
		case PROTOCOL:	       *(__u8 *)ptr = nf->tuple.protocol; break;
		case TCP_FLAGS:	       *(__u8 *)ptr = nf->tcp_flags; break;
		case TOS:	       *(__u8 *)ptr = nf->tuple.tos; break;
		case SRC_MASK:	       *(__u8 *)ptr = nf->s_mask; break;
		case DST_MASK:	       *(__u8 *)ptr = nf->d_mask; break;
		default:
					memset(ptr, 0, tpl_element_sizes[type]);
	}
}

#define PAD_SIZE 4 /* rfc prescribes flowsets to be padded */

static void netflow_export_flow9(struct ipt_netflow *nf)
{
	unsigned char *ptr;
	int i;
	struct data_template *tpl;

	if (debug > 2)
		printk(KERN_INFO "adding flow to export (%d)\n", pdu9.nr_records);

	if (unlikely(nf->s_mask || nf->d_mask))
		tpl = &template_ipv4_aggr;
	else
		tpl = &template_ipv4;

	if (!pdu9_flowset ||
	    pdu9_flowset->flowset_id != tpl->template_id_n ||
	    !(ptr = pdu9_alloc_fail(tpl->rec_size))) {

		/* if there was previous data template we should pad it to 4 bytes */
		if (pdu9_flowset) {
			int padding = (PAD_SIZE - ntohs(pdu9_flowset->length) % PAD_SIZE) % PAD_SIZE;
			if (padding && (ptr = pdu9_alloc_fail(padding))) {
				pdu9_flowset->length = htons(ntohs(pdu9_flowset->length) + padding);
				for (; padding; padding--)
					*ptr++ = 0;
			}
		}

		if (!tpl->template_id_n ||
		    pdu_seq > tpl->exported_seq + refresh_rate)
			pdu9_add_template(tpl);

		ptr = pdu9_alloc(sizeof(struct flowset_data) + tpl->rec_size);
		pdu9_flowset = (struct flowset_data *)ptr;
		pdu9_flowset->flowset_id = tpl->template_id_n;
		pdu9_flowset->length	 = htons(sizeof(struct flowset_data));
		ptr += sizeof(struct flowset_data);
	}

	/* encode all fields */
	for (i = 0; ; ) {
		int type = tpl->fields[i++];

		if (!type)
			break;
		add_ipv4_field(ptr, type, nf);
		ptr += tpl->fields[i++];
	}
	ipt_netflow_free(nf);

	pdu9.nr_records++;
	pdu9_flowset->length = htons(ntohs(pdu9_flowset->length) + tpl->rec_size);

	pdu_packets += nf->nr_packets;
	pdu_traf    += nf->nr_bytes;
	pdu_ts_mod = jiffies;
}

static void netflow_switch_version(int ver)
{
	protocol = ver;
	if (protocol == 5) {
		netflow_export_flow = &netflow_export_flow5;
		netflow_export_pdu = &netflow_export_pdu5;
	} else {
		netflow_export_flow = &netflow_export_flow9;
		netflow_export_pdu = &netflow_export_pdu9;
		/* renew templates */
		template_ipv4.template_id_n = 0;
		template_ipv4_aggr.template_id_n = 0;
	}
	printk(KERN_INFO "netflow protocol version %d enabled.\n", protocol);
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
/* this function is guaranteed to be called non-concurrently */
static void netflow_scan_and_export(int flush)
{
	long i_timeout = inactive_timeout * HZ;
	long a_timeout = active_timeout * HZ;

	if (flush)
		i_timeout = 0;

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
			NETFLOW_STAT_ADD(pkt_out, nf->nr_packets);
			NETFLOW_STAT_ADD(traf_out, nf->nr_bytes);
			spin_unlock_bh(&ipt_netflow_lock);
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
	if ((jiffies - pdu_ts_mod) >= i_timeout)
		netflow_export_pdu();
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,20)
static void netflow_work_fn(void *dummy)
#else
static void netflow_work_fn(struct work_struct *dummy)
#endif
{
	netflow_scan_and_export(DONT_FLUSH);
	__start_scan_worker();
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
	metric = (dfnd + dnfnd)? 100 * (dsrch + dfnd + dnfnd) / (dfnd + dnfnd) : metric;
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
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,28)
			   const struct net_device *if_in,
			   const struct net_device *if_out,
			   unsigned int hooknum,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,17)
			   const struct xt_target *target,
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,19)
			   const void *targinfo,
			   void *userinfo
#else
			   const void *targinfo
#endif
#else /* since 2.6.28 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,35)
			   const struct xt_target_param *par
#else
			   const struct xt_action_param *par
#endif
#endif
		)
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
	unsigned int hash;

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
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,28)
	tuple.i_ifc	= if_in? if_in->ifindex : -1;
#else
	tuple.i_ifc	= par->in? par->in->ifindex : -1;
#endif
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
			atomic_inc(&aggr_n->usage);
			break; 
		}
	list_for_each_entry(aggr_n, &aggr_n_list, list)
		if ((ntohl(tuple.d_addr) & aggr_n->mask) == aggr_n->addr) {
			tuple.d_addr &= htonl(aggr_n->aggr_mask);
			d_mask = aggr_n->prefix;
			atomic_inc(&aggr_n->usage);
			break; 
		}

	/* aggregate ports */
	list_for_each_entry(aggr_p, &aggr_p_list, list)
		if (ntohs(tuple.s_port) >= aggr_p->port1 &&
		    ntohs(tuple.s_port) <= aggr_p->port2) {
			tuple.s_port = htons(aggr_p->aggr_port);
			atomic_inc(&aggr_p->usage);
			break;
		}

	list_for_each_entry(aggr_p, &aggr_p_list, list)
		if (ntohs(tuple.d_port) >= aggr_p->port1 &&
		    ntohs(tuple.d_port) <= aggr_p->port2) {
			tuple.d_port = htons(aggr_p->aggr_port);
			atomic_inc(&aggr_p->usage);
			break;
		}
	read_unlock_bh(&aggr_lock);

	hash = hash_netflow(&tuple);
	spin_lock_bh(&ipt_netflow_lock);
	/* record */
	nf = ipt_netflow_find(&tuple, hash);
	if (!nf) {
		if (maxflows > 0 && atomic_read(&ipt_netflow_count) >= maxflows) {
			/* This is DOS attack prevention */
			NETFLOW_STAT_INC(maxflows_err);
			NETFLOW_STAT_INC(pkt_drop);
			NETFLOW_STAT_ADD(traf_drop, ntohs(iph->tot_len));
			spin_unlock_bh(&ipt_netflow_lock);
			return IPT_CONTINUE;
		}

		nf = init_netflow(&tuple, skb, hash);
		if (!nf || IS_ERR(nf)) {
			NETFLOW_STAT_INC(alloc_err);
			NETFLOW_STAT_INC(pkt_drop);
			NETFLOW_STAT_ADD(traf_drop, ntohs(iph->tot_len));
			spin_unlock_bh(&ipt_netflow_lock);
			return IPT_CONTINUE;
		}

		nf->ts_first = jiffies;
		nf->tcp_flags = tcp_flags;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,28)
		nf->o_ifc = if_out? if_out->ifindex : -1;
#else
		nf->o_ifc = par->out? par->out->ifindex : -1;
#endif
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
					 / sizeof(struct hlist_head));
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
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
	proc_stat = create_proc_entry("ipt_netflow", S_IRUGO, INIT_NET(proc_net_stat));
#else
	proc_stat = proc_create("ipt_netflow", S_IRUGO, INIT_NET(proc_net_stat), &nf_seq_fops);
#endif
	if (!proc_stat) {
		printk(KERN_ERR "Unable to create /proc/net/stat/ipt_netflow entry\n");
		goto err_free_netflow_slab;
	}
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
	proc_stat->proc_fops = &nf_seq_fops;
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,30)
	proc_stat->owner = THIS_MODULE;
#endif
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

	if (!destination)
		destination = aggregation_buf;
	if (destination != destination_buf) {
		strlcpy(destination_buf, destination, sizeof(destination_buf));
		destination = destination_buf;
	}
	if (add_destinations(destination) < 0)
		goto err_free_sysctl;

	if (!aggregation)
		aggregation = aggregation_buf;
	if (aggregation != aggregation_buf) {
		strlcpy(aggregation_buf, aggregation, sizeof(aggregation_buf));
		aggregation = aggregation_buf;
	}
	add_aggregation(aggregation);

	netflow_switch_version(protocol);
	__start_scan_worker();
	setup_timer(&rate_timer, rate_timer_calc, 0);
	mod_timer(&rate_timer, jiffies + (HZ * SAMPLERATE));

	if (xt_register_target(&ipt_netflow_reg))
		goto err_stop_timer;

	peakflows_at = jiffies;

	printk(KERN_INFO "ipt_netflow loaded.\n");
	return 0;

err_stop_timer:
	__stop_scan_worker();
	del_timer_sync(&rate_timer);
	destination_removeall();
	aggregation_remove(&aggr_n_list);
	aggregation_remove(&aggr_p_list);
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

#ifdef CONFIG_SYSCTL
	unregister_sysctl_table(netflow_sysctl_header);
#endif
#ifdef CONFIG_PROC_FS
	remove_proc_entry("ipt_netflow", INIT_NET(proc_net_stat));
#endif

	xt_unregister_target(&ipt_netflow_reg);
	__stop_scan_worker();
	netflow_scan_and_export(AND_FLUSH);
	del_timer_sync(&rate_timer);

	synchronize_sched();

	destination_removeall();
	aggregation_remove(&aggr_n_list);
	aggregation_remove(&aggr_p_list);

	kmem_cache_destroy(ipt_netflow_cachep);
	vfree(ipt_netflow_hash);

	printk(KERN_INFO "ipt_netflow unloaded.\n");
}

module_init(ipt_netflow_init);
module_exit(ipt_netflow_fini);

/* vim: set sw=8: */
