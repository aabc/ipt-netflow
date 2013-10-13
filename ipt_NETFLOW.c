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
#include <linux/hash.h>
#include <linux/delay.h>
#include <linux/spinlock_types.h>
#include <net/icmp.h>
#include <net/ip.h>
#include <net/ipv6.h>
#include <net/tcp.h>
#include <net/route.h>
#include <net/ip6_fib.h>
#include <net/dst.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#if defined(CONFIG_NF_NAT_NEEDED) || defined(CONFIG_NF_CONNTRACK_MARK)
#include <linux/notifier.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_core.h>
#endif
#include <linux/version.h>
#include <asm/unaligned.h>
#include "ipt_NETFLOW.h"
#include "murmur3.h"
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
MODULE_ALIAS("ip6t_NETFLOW");

#define DST_SIZE 256
static char destination_buf[DST_SIZE] = "127.0.0.1:2055";
static char *destination = destination_buf;
module_param(destination, charp, 0444);
MODULE_PARM_DESC(destination, "export destination ipaddress:port");

static int inactive_timeout = 15;
module_param(inactive_timeout, int, 0644);
MODULE_PARM_DESC(inactive_timeout, "inactive flows timeout in seconds");

static int active_timeout = 30 * 60;
module_param(active_timeout, int, 0644);
MODULE_PARM_DESC(active_timeout, "active flows timeout in seconds");

static int debug = 0;
module_param(debug, int, 0644);
MODULE_PARM_DESC(debug, "debug verbosity level");

static int sndbuf;
module_param(sndbuf, int, 0444);
MODULE_PARM_DESC(sndbuf, "udp socket SNDBUF size");

static int protocol = 5;
module_param(protocol, int, 0444);
MODULE_PARM_DESC(protocol, "netflow protocol version (5, 9)");

static unsigned int refresh_rate = 20;
module_param(refresh_rate, uint, 0644);
MODULE_PARM_DESC(refresh_rate, "NetFlow v9/IPFIX refresh rate (packets)");

static unsigned int timeout_rate = 30;
module_param(timeout_rate, uint, 0644);
MODULE_PARM_DESC(timeout_rate, "NetFlow v9/IPFIX timeout rate (minutes)");

#ifdef CONFIG_NF_NAT_NEEDED
static int natevents = 0;
module_param(natevents, int, 0444);
MODULE_PARM_DESC(natevents, "send NAT Events");
#endif

static int hashsize;
module_param(hashsize, int, 0444);
MODULE_PARM_DESC(hashsize, "hash table size");

static int maxflows = 2000000;
module_param(maxflows, int, 0644);
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
#define LOCK_COUNT (1<<9)
#define LOCK_COUNT_MASK (LOCK_COUNT-1)
static spinlock_t htable_locks[LOCK_COUNT] = {
	[0 ... LOCK_COUNT - 1] = __SPIN_LOCK_UNLOCKED(htable_locks)
};
static struct hlist_head *ipt_netflow_hash __read_mostly; /* hash table memory */
static unsigned int ipt_netflow_hash_size __read_mostly = 0; /* buckets */
static LIST_HEAD(ipt_netflow_list); /* all flows */
static DEFINE_SPINLOCK(hlist_lock);
static LIST_HEAD(aggr_n_list);
static LIST_HEAD(aggr_p_list);
static DEFINE_RWLOCK(aggr_lock);
#ifdef CONFIG_NF_NAT_NEEDED
static LIST_HEAD(nat_list); /* nat events */
static DEFINE_RWLOCK(nat_lock);
static unsigned long nat_events_start = 0;
static unsigned long nat_events_stop = 0;
#endif
static struct kmem_cache *ipt_netflow_cachep __read_mostly; /* ipt_netflow memory */
static atomic_t ipt_netflow_count = ATOMIC_INIT(0);

static long long pdu_packets = 0, pdu_traf = 0; /* how much accounted traffic in pdu */
static unsigned int pdu_count = 0;
static unsigned int pdu_seq = 0;
static unsigned int pdu_data_records = 0;
static unsigned int pdu_tpl_records = 0;
static unsigned long pdu_ts_mod; /* ts of last flow */
static union {
	struct netflow5_pdu v5;
	struct netflow9_pdu v9;
	struct ipfix_pdu ipfix;
} pdu;
static int engine_id = 0; /* Observation Domain */
static __u8 *pdu_data_used;
static __u8 *pdu_high_wm; /* high watermark */
static unsigned int pdu_max_size; /* sizeof pdu */
static struct flowset_data *pdu_flowset = NULL; /* current data flowset */

static void (*netflow_export_flow)(struct ipt_netflow *nf);
static void (*netflow_export_pdu)(void); /* called on timeout */
static void netflow_switch_version(int ver);

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,20)
static void netflow_work_fn(void *work);
static DECLARE_WORK(netflow_work, netflow_work_fn, NULL);
#else
static void netflow_work_fn(struct work_struct *work);
static DECLARE_DELAYED_WORK(netflow_work, netflow_work_fn);
#endif
static struct timer_list rate_timer;

#define TCP_SYN_ACK 0x12
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
static int netflow_scan_and_export(int flush);
enum {
	DONT_FLUSH, AND_FLUSH
};
static int template_ids = FLOWSET_DATA_FIRST;
static int tpl_count = 0; /* how much active templates */


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
#define MIN_DELAY 1
#define MAX_DELAY (HZ / 10)
static int worker_delay = HZ / 10;
static inline void _schedule_scan_worker(int status)
{
	/* rudimentary congestion avoidance */
	if (status > 0)
		worker_delay -= status;
	else if (status < 0)
		worker_delay /= 2;
	else
		worker_delay++;
	if (worker_delay < MIN_DELAY)
		worker_delay = MIN_DELAY;
	else if (worker_delay > MAX_DELAY)
		worker_delay = MAX_DELAY;
	schedule_delayed_work(&netflow_work, worker_delay);
}

static inline void start_scan_worker(void)
{
	_schedule_scan_worker(0);
	mutex_unlock(&worker_lock);
}

/* we always stop scanner before write_lock(&sock_lock)
 * to let it never hold that spin lock */
static inline void _unschedule_scan_worker(void)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,23)
	cancel_rearming_delayed_work(&netflow_work);
#else
	cancel_delayed_work_sync(&netflow_work);
#endif
}

static inline void stop_scan_worker(void)
{
	mutex_lock(&worker_lock);
	_unschedule_scan_worker();
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

	seq_printf(seq, "Flows: active %u (peak %u reached %ud%uh%um ago), mem %uK, worker delay %d/%d.\n",
		   nr_flows,
		   peakflows,
		   peak / (60 * 60 * 24), (peak / (60 * 60)) % 24, (peak / 60) % 60,
		   (unsigned int)((nr_flows * sizeof(struct ipt_netflow)) >> 10),
		   worker_delay, HZ);

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

	seq_printf(seq, "Protocol version %d", protocol);
	if (protocol == 10)
		seq_printf(seq, " (ipfix)");
	else
		seq_printf(seq, " (netflow)");
	if (protocol >= 9)
		seq_printf(seq, ", refresh-rate %u, timeout-rate %u, (templates %d, active %d)",
		    refresh_rate, timeout_rate, template_ids - FLOWSET_DATA_FIRST, tpl_count);

	seq_printf(seq, ". Timeouts: active %d, inactive %d. Maxflows %u\n",
	    active_timeout,
	    inactive_timeout,
	    maxflows);

	seq_printf(seq, "Rate: %llu bits/sec, %llu packets/sec;"
	    " Avg 1 min: %llu bps, %llu pps; 5 min: %llu bps, %llu pps\n",
	    sec_brate, sec_prate, min_brate, min_prate, min5_brate, min5_prate);

	seq_printf(seq, "cpu#  stat: <search found new [metric], trunc frag alloc maxflows>,"
	    " sock: <ok fail cberr, bytes>, traffic: <pkt, bytes>, drop: <pkt, bytes>\n");

#define SAFEDIV(x,y) ((y)? ({ u64 __tmp = x; do_div(__tmp, y); (int)__tmp; }) : 0)
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

#ifdef CONFIG_NF_NAT_NEEDED
	seq_printf(seq, "Natevents %s, count start %lu, stop %lu.\n", natevents? "enabled" : "disabled",
	    nat_events_start, nat_events_stop);
#endif

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
	int val = 0;

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
		case 10:
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

#ifdef CONFIG_NF_NAT_NEEDED
static void register_ct_events(void);
static void unregister_ct_events(void);
static int natevents_procctl(ctl_table *ctl, int write, BEFORE2632(struct file *filp,)
			 void __user *buffer, size_t *lenp, loff_t *fpos)
{
	int ret;
	int val = natevents;

	ctl->data = &val;
	ret = proc_dointvec(ctl, write, BEFORE2632(filp,) buffer, lenp, fpos);

	if (!write)
		return ret;

	if (natevents && !val)
		unregister_ct_events();
	else if (!natevents && val)
		register_ct_events();

	return ret;
}
#endif

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
		_CTL_NAME(10)
		.procname	= "protocol",
		.mode		= 0644,
		.maxlen		= sizeof(int),
		.proc_handler	= &protocol_procctl,
	},
	{
		_CTL_NAME(11)
		.procname	= "refresh-rate",
		.mode		= 0644,
		.data		= &refresh_rate,
		.maxlen		= sizeof(int),
		.proc_handler	= &proc_dointvec,
	},
	{
		_CTL_NAME(12)
		.procname	= "timeout-rate",
		.mode		= 0644,
		.data		= &timeout_rate,
		.maxlen		= sizeof(int),
		.proc_handler	= &proc_dointvec,
	},
#ifdef CONFIG_NF_NAT_NEEDED
	{
		_CTL_NAME(13)
		.procname	= "natevents",
		.mode		= 0644,
		.maxlen		= sizeof(int),
		.proc_handler	= &natevents_procctl,
	},
#endif
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
		printk(KERN_INFO "ipt_NETFLOW: socket error <%d>\n", sk->sk_err);
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
		printk(KERN_ERR "ipt_NETFLOW: sock_create_kern error %d\n", -error);
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
		printk(KERN_ERR "ipt_NETFLOW: error connecting UDP socket %d,"
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
			printk(KERN_INFO "ipt_NETFLOW: connected %u.%u.%u.%u:%u\n",
			    HIPQUAD(usock->ipaddr),
			    usock->port);
	} else {
		atomic_inc(&usock->err_connect);
		if (debug)
			printk(KERN_INFO "ipt_NETFLOW: connect to %u.%u.%u.%u:%u failed%s.\n",
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
			printk(KERN_ERR "ipt_NETFLOW: sendmsg[%d] error %d: data loss %llu pkt, %llu bytes%s\n",
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
	printk(KERN_INFO "ipt_NETFLOW: removed destination %u.%u.%u.%u:%u\n",
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
	printk(KERN_INFO "ipt_NETFLOW: added destination %u.%u.%u.%u:%u%s\n",
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
				printk(KERN_ERR "ipt_NETFLOW: can't vmalloc socket\n");
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
				printk(KERN_ERR "ipt_NETFLOW: can't vmalloc aggr\n");
				return -ENOMEM;
			}
			memset(aggr_n, 0, sizeof(*aggr_n));

			aggr_n->mask = bits2mask(mask);
			aggr_n->addr = ntohl(*(__be32 *)ip) & aggr_n->mask;
			aggr_n->aggr_mask = bits2mask(aggr_to);
			aggr_n->prefix = mask;
			printk(KERN_INFO "ipt_NETFLOW: add aggregation [%u.%u.%u.%u/%u=%u]\n",
			       HIPQUAD(aggr_n->addr), mask, aggr_to);
			list_add_tail(&aggr_n->list, &new_aggr_n_list);

		} else if (sscanf(ptr, "%u-%u=%u", &port1, &port2, &aggr_to) == 3 ||
			   sscanf(ptr, "%u=%u", &port2, &aggr_to) == 2) {

			if (!(aggr_p = vmalloc(sizeof(*aggr_p)))) {
				printk(KERN_ERR "ipt_NETFLOW: can't vmalloc aggr\n");
				return -ENOMEM;
			}
			memset(aggr_p, 0, sizeof(*aggr_p));

			aggr_p->port1 = port1;
			aggr_p->port2 = port2;
			aggr_p->aggr_port = aggr_to;
			printk(KERN_INFO "ipt_NETFLOW: add aggregation [%u-%u=%u]\n",
			       port1, port2, aggr_to);
			list_add_tail(&aggr_p->list, &new_aggr_p_list);
		} else {
			printk(KERN_ERR "ipt_NETFLOW: bad aggregation rule: %s (ignoring)\n", ptr);
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
	return murmur3(tuple, sizeof(struct ipt_netflow_tuple), ipt_netflow_hash_rnd) % ipt_netflow_hash_size;
}

static struct ipt_netflow *
ipt_netflow_find(const struct ipt_netflow_tuple *tuple, unsigned int hash)
{
	struct ipt_netflow *nf;
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,9,0)
#define compat_hlist_for_each_entry		      hlist_for_each_entry
#define compat_hlist_for_each_entry_safe	      hlist_for_each_entry_safe
	struct hlist_node *pos;
#else /* since 3.9.0 */
#define compat_hlist_for_each_entry(a,pos,c,d)	      hlist_for_each_entry(a,c,d)
#define compat_hlist_for_each_entry_safe(a,pos,c,d,e) hlist_for_each_entry_safe(a,c,d,e)
#endif

	compat_hlist_for_each_entry(nf, pos, &ipt_netflow_hash[hash], hlist) {
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

enum { LOCKALL, UNLOCKALL };
/* Only used in set_hashsize() */
static void htable_lock_bh(int op)
{
	int i;

	if (op == LOCKALL)
		local_bh_disable();
	for (i = 0; i < LOCK_COUNT; i++) {
		if (op == LOCKALL)
			spin_lock(&htable_locks[i]);
		else
			spin_unlock(&htable_locks[i]);
	}
	if (op == UNLOCKALL)
		local_bh_enable();
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
		printk(KERN_ERR "ipt_NETFLOW: unable to vmalloc hash table.\n");

	return hash;
}

static int set_hashsize(int new_size)
{
	struct hlist_head *new_hash, *old_hash;
	struct ipt_netflow *nf;
	int rnd;

	printk(KERN_INFO "ipt_NETFLOW: allocating new hash table %u -> %u buckets\n",
	       ipt_netflow_hash_size, new_size);
	new_hash = alloc_hashtable(new_size);
	if (!new_hash)
		return -ENOMEM;

	get_random_bytes(&rnd, 4);

	/* rehash */
	htable_lock_bh(LOCKALL);
	old_hash = ipt_netflow_hash;
	ipt_netflow_hash = new_hash;
	ipt_netflow_hash_size = new_size;
	ipt_netflow_hash_rnd = rnd;
	/* hash_netflow() is dependent on ipt_netflow_hash_* values */
	spin_lock_bh(&hlist_lock);
	list_for_each_entry(nf, &ipt_netflow_list, list) {
		unsigned int hash;

		hash = hash_netflow(&nf->tuple);
		/* hlist_add_head overwrites hlist pointers for this node
		 * so it's good */
		hlist_add_head(&nf->hlist, &new_hash[hash]);
		nf->lock = &htable_locks[hash & LOCK_COUNT_MASK];
	}
	spin_unlock_bh(&hlist_lock);
	htable_lock_bh(UNLOCKALL);

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
		printk(KERN_ERR "ipt_NETFLOW: Can't allocate flow.\n");
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
	if (IS_DUMMY_FLOW(nf))
		return;
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

	nf->lock = &htable_locks[hash & LOCK_COUNT_MASK];
	hlist_add_head(&nf->hlist, &ipt_netflow_hash[hash]);
	spin_lock_bh(&hlist_lock);
	list_add(&nf->list, &ipt_netflow_list);
	spin_unlock_bh(&hlist_lock);

	return nf;
}

/* cook pdu, send, and clean */
/* only called in scan worker path */
static void netflow_export_pdu_v5(void)
{
	struct timeval tv;
	int pdusize;

	if (!pdu_data_records)
		return;

	if (debug > 1)
		printk(KERN_INFO "netflow_export_pdu_v5 with %d records\n", pdu_data_records);

	pdu.v5.version		= htons(5);
	pdu.v5.nr_records	= htons(pdu_data_records);
	pdu.v5.ts_uptime	= htonl(jiffies_to_msecs(jiffies));
	do_gettimeofday(&tv);
	pdu.v5.ts_usecs		= htonl(tv.tv_sec);
	pdu.v5.ts_unsecs	= htonl(tv.tv_usec);
	pdu.v5.seq		= htonl(pdu_seq);
	//pdu.v5.eng_type	= 0;
	pdu.v5.eng_id		= engine_id;
	//pdu.v5.padding	= 0;

	pdusize = NETFLOW5_HEADER_SIZE + sizeof(struct netflow5_record) * pdu_data_records;

	netflow_sendmsg(&pdu.v5, pdusize);

	pdu_packets = 0;
	pdu_traf    = 0;

	pdu_seq += pdu_data_records;
	pdu_count++;
	pdu_data_records = 0;
}

/* only called in scan worker path */
static void netflow_export_flow_v5(struct ipt_netflow *nf)
{
	struct netflow5_record *rec;

	if (unlikely(debug > 2))
		printk(KERN_INFO "adding flow to export (%d)\n", pdu_data_records);

	pdu_packets += nf->nr_packets;
	pdu_traf += nf->nr_bytes;
	pdu_ts_mod = jiffies;
	rec = &pdu.v5.flow[pdu_data_records++];

	/* make V5 flow record */
	rec->s_addr	= nf->tuple.src.ip;
	rec->d_addr	= nf->tuple.dst.ip;
	rec->nexthop	= nf->nh.ip;
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

	if (pdu_data_records == NETFLOW5_RECORDS_MAX)
		netflow_export_pdu_v5();
}

/* pdu is initially blank, export current pdu, and prepare next for filling. */
static void netflow_export_pdu_v9(void)
{
	struct timeval tv;
	int pdusize;

	if (pdu_data_used <= pdu.v9.data)
		return;

	if (debug > 1)
		printk(KERN_INFO "netflow_export_pdu_v9 with %d records\n",
		    pdu_data_records + pdu_tpl_records);

	pdu.v9.version		= htons(9);
	pdu.v9.nr_records	= htons(pdu_data_records + pdu_tpl_records);
	pdu.v9.sys_uptime_ms	= htonl(jiffies_to_msecs(jiffies));
	do_gettimeofday(&tv);
	pdu.v9.export_time_s	= htonl(tv.tv_sec);
	pdu.v9.seq		= htonl(pdu_seq);
	pdu.v9.source_id	= engine_id;

	pdusize = pdu_data_used - (unsigned char *)&pdu.v9;

	netflow_sendmsg(&pdu.v9, pdusize);

	pdu_packets = 0;
	pdu_traf    = 0;

	pdu_seq++;
	pdu_count++;
	pdu_data_records = pdu_tpl_records = 0;
	pdu_data_used = pdu.v9.data;
	pdu_flowset = NULL;
}

static void netflow_export_pdu_ipfix(void)
{
	struct timeval tv;
	int pdusize;

	if (pdu_data_used <= pdu.ipfix.data)
		return;

	if (debug > 1)
		printk(KERN_INFO "netflow_export_pduX with %d records\n",
		    pdu_data_records);

	pdu.ipfix.version	= htons(10);
	do_gettimeofday(&tv);
	pdu.ipfix.export_time_s	= htonl(tv.tv_sec);
	pdu.ipfix.seq		= htonl(pdu_seq);
	pdu.ipfix.odomain_id	= engine_id;
	pdusize = pdu_data_used - (unsigned char *)&pdu;
	pdu.ipfix.length	= htons(pdusize);

	netflow_sendmsg(&pdu.ipfix, pdusize);

	pdu_packets = 0;
	pdu_traf    = 0;

	pdu_seq += pdu_data_records;
	pdu_count++;
	pdu_data_records = pdu_tpl_records = 0;
	pdu_data_used = pdu.ipfix.data;
	pdu_flowset = NULL;
}

static inline int pdu_have_space(size_t size)
{
	return ((pdu_data_used + size) <= pdu_high_wm);
}

static inline unsigned char *pdu_grab_space(size_t size)
{
	unsigned char *ptr = pdu_data_used;
	pdu_data_used += size;
	return ptr;
}

// allocate data space in pdu, or fail if pdu is reallocated.
static inline unsigned char *pdu_alloc_fail(size_t size)
{
	if (!pdu_have_space(size)) {
		netflow_export_pdu();
		return NULL;
	}
	return pdu_grab_space(size);
}

/* doesn't fail, but can provide empty pdu. */
static unsigned char *pdu_alloc(size_t size)
{
	return pdu_alloc_fail(size) ?: pdu_grab_space(size);
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
	[IPV4_NEXT_HOP]	= 4,
	//[SRC_AS]		= 2,
	//[DST_AS]		= 2,
	//[BGP_IPV4_NEXT_HOP]	= 4,
	//[MUL_DST_PKTS]	= 4,
	//[MUL_DST_BYTES]	= 4,
	[LAST_SWITCHED]	= 4,
	[FIRST_SWITCHED]= 4,
	[IPV6_SRC_ADDR]	= 16,
	[IPV6_DST_ADDR]	= 16,
	[IPV6_FLOW_LABEL] = 3,
	[ICMP_TYPE]	= 2,
	[MUL_IGMP_TYPE]	= 1,
	//[TOTAL_BYTES_EXP]	= 4,
	//[TOTAL_PKTS_EXP]	= 4,
	//[TOTAL_FLOWS_EXP]	= 4,
	//[IP_PROTOCOL_VERSION]	= 1,
	[IPV6_NEXT_HOP]	= 16,
	[IPV6_OPTION_HEADERS]		   = 2,
	[commonPropertiesId]		   = 4,
	[ipv4Options]			   = 4,
	[postNATSourceIPv4Address]	   = 4,
	[postNATDestinationIPv4Address]	   = 4,
	[postNAPTSourceTransportPort]	   = 2,
	[postNAPTDestinationTransportPort] = 2,
	[natEvent]			   = 1,
	[postNATSourceIPv6Address]	   = 16,
	[postNATDestinationIPv6Address]	   = 16,
	[IPSecSPI]			   = 4,
};

#define TEMPLATES_HASH_BSIZE	8
#define TEMPLATES_HASH_SIZE	(1<<TEMPLATES_HASH_BSIZE)
static struct hlist_head templates_hash[TEMPLATES_HASH_SIZE];

struct base_template {
	int length; /* number of elements in template */
	u_int16_t types[]; /* {type, size} pairs */
};

/* base templates */
#define BTPL_BASE	0x00000001	/* base stat */
#define BTPL_IP4	0x00000002	/* IPv4 */
#define BTPL_MASK4	0x00000004	/* Aggregated */
#define BTPL_PORTS	0x00000008	/* UDP&TCP */
#define BTPL_IP6	0x00000010	/* IPv6 */
#define BTPL_ICMP	0x00000020	/* ICMP */
#define BTPL_IGMP	0x00000040	/* IGMP */
#define BTPL_IPSEC	0x00000080	/* AH&ESP */
#define BTPL_NAT4	0x00000100	/* NAT IPv4 */
#define BTPL_NAT6	0x00000200	/* NAT IPv6 */
#define BTPL_MARK	0x00000400	/* connmark */
#define BTPL_LABEL6	0x00000800	/* IPv6 flow label */
#define BTPL_OPTIONS4	0x00001000	/* IPv4 Options */
#define BTPL_MAX	32

static struct base_template template_base = {
	.types = {
		INPUT_SNMP,
		OUTPUT_SNMP,
		IN_PKTS,
		IN_BYTES,
		FIRST_SWITCHED,
		LAST_SWITCHED,
		PROTOCOL,
		TOS,
		0
	}
};
static struct base_template template_ipv4 = {
	.types = {
		IPV4_SRC_ADDR,
		IPV4_DST_ADDR,
		IPV4_NEXT_HOP,
		0
	}
};
static struct base_template template_options4 = {
	.types = { ipv4Options, 0 }
};
static struct base_template template_ipv6 = {
	.types = {
		IPV6_SRC_ADDR,
		IPV6_DST_ADDR,
		IPV6_NEXT_HOP,
		IPV6_OPTION_HEADERS,
		0
	}
};
static struct base_template template_label6 = {
	.types = { IPV6_FLOW_LABEL, 0 }
};
static struct base_template template_ipv4_mask = {
	.types = {
		SRC_MASK,
		DST_MASK,
		0
	}
};
static struct base_template template_ports = {
	.types = {
		L4_SRC_PORT,
		L4_DST_PORT,
		TCP_FLAGS,
		0
	}
};
static struct base_template template_icmp = {
	.types = { ICMP_TYPE, 0 }
};
static struct base_template template_igmp = {
	.types = { MUL_IGMP_TYPE, 0 }
};
static struct base_template template_ipsec = {
	.types = { IPSecSPI, 0 }
};
static struct base_template template_nat4 = {
	.types = {
		IPV4_SRC_ADDR,
		IPV4_DST_ADDR,
		postNATSourceIPv4Address,
		postNATDestinationIPv4Address,
		postNAPTSourceTransportPort,
		postNAPTDestinationTransportPort,
		PROTOCOL,
		natEvent,
		0
	}
};
static struct base_template template_nat6 = {
	.types = {
		IPV6_SRC_ADDR,
		IPV6_DST_ADDR,
		postNATSourceIPv6Address,
		postNATDestinationIPv6Address,
		postNAPTSourceTransportPort,
		postNAPTDestinationTransportPort,
		PROTOCOL,
		natEvent,
		0
	}
};
static struct base_template template_mark = {
	.types = { commonPropertiesId, 0 }
};

struct data_template {
	struct hlist_node hlist;
	int tpl_mask;

	int length; /* number of elements in template */
	int tpl_size; /* summary size of template with flowset header */
	int rec_size; /* summary size of all recods of template (w/o flowset header) */
	int template_id_n; /* assigned from template_ids, network order. */
	int		exported_cnt;
	unsigned long	exported_ts; /* jiffies */
	u_int16_t fields[]; /* {type, size} pairs */
} __attribute__ ((packed));

#define TPL_FIELD_NSIZE 4 /* one complete template field's network size */

static void free_templates(void)
{
	int i;
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,9,0)
	struct hlist_node *pos;
#endif
	struct hlist_node *tmp;

	for (i = 0; i < TEMPLATES_HASH_SIZE; i++) {
		struct hlist_head *thead = &templates_hash[i];
		struct data_template *tpl;

		compat_hlist_for_each_entry_safe(tpl, pos, tmp, thead, hlist)
			kfree(tpl);
		INIT_HLIST_HEAD(thead);
	}
	tpl_count = 0;
}

/* create combined template from mask */
static struct data_template *get_template(int tmask)
{
	struct base_template *tlist[BTPL_MAX];
	struct data_template *tpl;
	int tnum;
	int length;
	int i, j, k;
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,9,0)
	struct hlist_node *pos;
#endif
	int hash = hash_long(tmask, TEMPLATES_HASH_BSIZE);

	compat_hlist_for_each_entry(tpl, pos, &templates_hash[hash], hlist)
		if (tpl->tpl_mask == tmask)
			return tpl;

	tnum = 0;
	if (tmask & BTPL_IP4)
		tlist[tnum++] = &template_ipv4;
	if (tmask & BTPL_IP6)
		tlist[tnum++] = &template_ipv6;
	if (tmask & BTPL_PORTS)
		tlist[tnum++] = &template_ports;
	if (tmask & BTPL_BASE)
		tlist[tnum++] = &template_base;
	if (tmask & BTPL_LABEL6)
		tlist[tnum++] = &template_label6;
	if (tmask & BTPL_OPTIONS4)
		tlist[tnum++] = &template_options4;
	if (tmask & BTPL_MASK4)
		tlist[tnum++] = &template_ipv4_mask;
	if (tmask & BTPL_ICMP)
		tlist[tnum++] = &template_icmp;
	if (tmask & BTPL_IGMP)
		tlist[tnum++] = &template_igmp;
	if (tmask & BTPL_IPSEC)
		tlist[tnum++] = &template_ipsec;
	if (tmask & BTPL_NAT4)
		tlist[tnum++] = &template_nat4;
	if (tmask & BTPL_NAT6)
		tlist[tnum++] = &template_nat6;
	if (tmask & BTPL_MARK)
		tlist[tnum++] = &template_mark;

	/* calc memory size */
	length = 0;
	for (i = 0; i < tnum; i++) {
		if (!tlist[i]->length) {
			for (k = 0; tlist[i]->types[k]; k++);
			tlist[i]->length = k;
		}
		length += tlist[i]->length;
	}
	/* elements are pairs + one termiantor */
	tpl = kmalloc(sizeof(struct data_template) + (length * 2 + 1) * sizeof(u_int16_t), GFP_KERNEL);
	if (!tpl) {
		printk(KERN_ERR "ipt_NETFLOW: unable to kmalloc template.\n");
		return NULL;
	}
	tpl->tpl_mask = tmask;
	tpl->length = length;
	tpl->tpl_size = sizeof(struct flowset_template);
	tpl->rec_size = 0;
	tpl->template_id_n = htons(template_ids++);
	tpl->exported_cnt = 0;
	tpl->exported_ts = 0;

	j = 0;
	for (i = 0; i < tnum; i++) {
		struct base_template *btpl = tlist[i];

		for (k = 0; k < btpl->length; k++) {
			int size;
			int type = btpl->types[k];

			tpl->fields[j++] = type;
			size = tpl_element_sizes[type];
			tpl->fields[j++] = size;
			tpl->rec_size += size;
		}
		tpl->tpl_size += btpl->length * TPL_FIELD_NSIZE;
	}
	tpl->fields[j++] = 0;

	hlist_add_head(&tpl->hlist, &templates_hash[hash]);
	tpl_count++;

	return tpl;
}

static void pdu_add_template(struct data_template *tpl)
{
	int i;
	unsigned char *ptr;
	struct flowset_template *ntpl;
	__be16 *sptr;

	ptr = pdu_alloc(tpl->tpl_size);
	ntpl = (struct flowset_template *)ptr;
	ntpl->flowset_id  = protocol == 9? htons(FLOWSET_TEMPLATE) : htons(IPFIX_TEMPLATE);
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

	tpl->exported_cnt = pdu_count;
	tpl->exported_ts = jiffies;

	pdu_flowset = NULL;
	pdu_tpl_records++;
}

/* encode one field */
typedef struct in6_addr in6_t;
static inline void add_ipv4_field(__u8 *ptr, int type, struct ipt_netflow *nf)
{
	switch (type) {
		case IN_BYTES:	     *(__be32 *)ptr = htonl(nf->nr_bytes); break;
		case IN_PKTS:	     *(__be32 *)ptr = htonl(nf->nr_packets); break;
		case FIRST_SWITCHED: *(__be32 *)ptr = htonl(jiffies_to_msecs(nf->ts_first)); break;
		case LAST_SWITCHED:  *(__be32 *)ptr = htonl(jiffies_to_msecs(nf->ts_last)); break;
		case IPV4_SRC_ADDR:  *(__be32 *)ptr = nf->tuple.src.ip; break;
		case IPV4_DST_ADDR:  *(__be32 *)ptr = nf->tuple.dst.ip; break;
		case IPV4_NEXT_HOP:  *(__be32 *)ptr = nf->nh.ip; break;
		case L4_SRC_PORT:    *(__be16 *)ptr = nf->tuple.s_port; break;
		case L4_DST_PORT:    *(__be16 *)ptr = nf->tuple.d_port; break;
		case INPUT_SNMP:     *(__be16 *)ptr = htons(nf->tuple.i_ifc); break;
		case OUTPUT_SNMP:    *(__be16 *)ptr = htons(nf->o_ifc); break;
		case PROTOCOL:	               *ptr = nf->tuple.protocol; break;
		case TCP_FLAGS:	               *ptr = nf->tcp_flags; break;
		case TOS:	               *ptr = nf->tuple.tos; break;
		case IPV6_SRC_ADDR:   *(in6_t *)ptr = nf->tuple.src.in6; break;
		case IPV6_DST_ADDR:   *(in6_t *)ptr = nf->tuple.dst.in6; break;
		case IPV6_NEXT_HOP:   *(in6_t *)ptr = nf->nh.in6; break;
		case IPV6_FLOW_LABEL:        *ptr++ = nf->flow_label >> 16;
				     *(__be16 *)ptr = nf->flow_label;
				      break;
		case ipv4Options:    *(__be32 *)ptr = htonl(nf->options); break;
		case IPV6_OPTION_HEADERS: *(__be16 *)ptr = htons(nf->options); break;
#ifdef CONFIG_NF_CONNTRACK_MARK
		case commonPropertiesId:
				     *(__be32 *)ptr = htonl(nf->mark); break;
#endif
		case SRC_MASK:	               *ptr = nf->s_mask; break;
		case DST_MASK:	               *ptr = nf->d_mask; break;
		case ICMP_TYPE:	     *(__be16 *)ptr = nf->tuple.d_port; break;
		case MUL_IGMP_TYPE:            *ptr = nf->tuple.d_port; break;
#ifdef CONFIG_NF_NAT_NEEDED
		case postNATSourceIPv4Address:	       *(__be32 *)ptr = nf->nat->post.s_addr; break;
		case postNATDestinationIPv4Address:    *(__be32 *)ptr = nf->nat->post.d_addr; break;
//		case postNATSourceIPv6Address:	        *(in6_t *)ptr = nf->nat->post.s_addr6; break;
//		case postNATDestinationIPv6Address:     *(in6_t *)ptr = nf->nat->post.d_addr6; break;
		case postNAPTSourceTransportPort:      *(__be16 *)ptr = nf->nat->post.s_port; break;
		case postNAPTDestinationTransportPort: *(__be16 *)ptr = nf->nat->post.d_port; break;
		case natEvent:				         *ptr = nf->nat->nat_event; break;
#endif
		case IPSecSPI:        *(__u32 *)ptr = (nf->tuple.s_port << 16) | nf->tuple.d_port; break;
		default:
					memset(ptr, 0, tpl_element_sizes[type]);
	}
}

#define PAD_SIZE 4 /* rfc prescribes flowsets to be padded */

/* cache timeout_rate in jiffies */
static inline unsigned long timeout_rate_j(void)
{
	static unsigned int t_rate = 0;
	static unsigned long t_rate_j;

	if (unlikely(timeout_rate != t_rate)) {
		struct timeval tv = { .tv_sec = timeout_rate * 60, .tv_usec = 0 };

		t_rate = timeout_rate;
		t_rate_j = timeval_to_jiffies(&tv);
	}
	return t_rate_j;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,20)
#define IPPROTO_UDPLITE 136
#endif

#ifndef time_is_before_jiffies
#define time_is_before_jiffies(a) time_after(jiffies, a)
#endif

static void netflow_export_flow_tpl(struct ipt_netflow *nf)
{
	unsigned char *ptr;
	int i;
	struct data_template *tpl;
	int tpl_mask = BTPL_BASE;

	if (unlikely(debug > 2))
		printk(KERN_INFO "adding flow to export (%d)\n",
		    pdu_data_records + pdu_tpl_records);

	if (likely(nf->tuple.l3proto == AF_INET)) {
		tpl_mask |= BTPL_IP4;
		if (unlikely(nf->options))
			tpl_mask |= BTPL_OPTIONS4;
	} else {
		tpl_mask |= BTPL_IP6;
		if (nf->flow_label)
			tpl_mask |= BTPL_LABEL6;
	}
	if (unlikely(nf->s_mask || nf->d_mask))
		tpl_mask |= BTPL_MASK4;
	if (likely(nf->tuple.protocol == IPPROTO_TCP ||
		    nf->tuple.protocol == IPPROTO_UDP ||
		    nf->tuple.protocol == IPPROTO_SCTP ||
		    nf->tuple.protocol == IPPROTO_UDPLITE))
		tpl_mask |= BTPL_PORTS;
	else if (nf->tuple.protocol == IPPROTO_ICMP)
		tpl_mask |= BTPL_ICMP;
	else if (nf->tuple.protocol == IPPROTO_IGMP)
		tpl_mask |= BTPL_IGMP;
#ifdef CONFIG_NF_CONNTRACK_MARK
	if (nf->mark)
		tpl_mask |= BTPL_MARK;
#endif
#ifdef CONFIG_NF_NAT_NEEDED
	if (nf->nat)
		tpl_mask = likely(nf->tuple.l3proto == AF_INET)? BTPL_NAT4 : BTPL_NAT6;
#endif

	tpl = get_template(tpl_mask);
	if (unlikely(!tpl)) {
		printk(KERN_INFO "ipt_NETFLOW: template allocation failed.\n");
		NETFLOW_STAT_INC(alloc_err);
		NETFLOW_STAT_ADD_ATOMIC(pkt_drop, nf->nr_packets);
		NETFLOW_STAT_ADD_ATOMIC(traf_drop, nf->nr_bytes);
		ipt_netflow_free(nf);
		return;
	}

	if (unlikely(!pdu_flowset ||
	    pdu_flowset->flowset_id != tpl->template_id_n ||
	    !(ptr = pdu_alloc_fail(tpl->rec_size)))) {

		/* if there was previous data template we should pad it to 4 bytes */
		if (pdu_flowset) {
			int padding = (PAD_SIZE - ntohs(pdu_flowset->length) % PAD_SIZE) % PAD_SIZE;
			if (padding && (ptr = pdu_alloc_fail(padding))) {
				pdu_flowset->length = htons(ntohs(pdu_flowset->length) + padding);
				for (; padding; padding--)
					*ptr++ = 0;
			}
		}

		if (!tpl->exported_ts ||
		    pdu_count > (tpl->exported_cnt + refresh_rate) ||
		    time_is_before_jiffies(tpl->exported_ts + timeout_rate_j())) {
			pdu_add_template(tpl);
		}

		ptr = pdu_alloc(sizeof(struct flowset_data) + tpl->rec_size);
		pdu_flowset = (struct flowset_data *)ptr;
		pdu_flowset->flowset_id = tpl->template_id_n;
		pdu_flowset->length	 = htons(sizeof(struct flowset_data));
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

	pdu_data_records++;
	pdu_flowset->length = htons(ntohs(pdu_flowset->length) + tpl->rec_size);

	pdu_packets += nf->nr_packets;
	pdu_traf    += nf->nr_bytes;

	ipt_netflow_free(nf);
	pdu_ts_mod = jiffies;
}

static void netflow_switch_version(int ver)
{
	protocol = ver;
	if (protocol == 5) {
		memset(&pdu, 0, sizeof(pdu));
		netflow_export_flow = &netflow_export_flow_v5;
		netflow_export_pdu = &netflow_export_pdu_v5;
	} else if (protocol == 9) {
		pdu_data_used = pdu.v9.data;
		pdu_max_size = sizeof(pdu.v9);
		pdu_high_wm = (unsigned char *)&pdu + pdu_max_size;
		netflow_export_flow = &netflow_export_flow_tpl;
		netflow_export_pdu = &netflow_export_pdu_v9;
	} else { /* IPFIX */
		pdu_data_used = pdu.ipfix.data;
		pdu_max_size = sizeof(pdu.ipfix);
		pdu_high_wm = (unsigned char *)&pdu + pdu_max_size;
		netflow_export_flow = &netflow_export_flow_tpl;
		netflow_export_pdu = &netflow_export_pdu_ipfix;
	}
	if (protocol != 5)
		free_templates();
	pdu_data_records = pdu_tpl_records = 0;
	pdu_flowset = NULL;
	printk(KERN_INFO "ipt_NETFLOW protocol version %d (%s) enabled.\n",
	    protocol, protocol == 10? "IPFIX" : "NetFlow");
}

#ifdef CONFIG_NF_NAT_NEEDED
static void export_nat_event(struct nat_event *nel)
{
	static struct ipt_netflow nf = { { 0 } };

	nf.tuple.l3proto = AF_INET;
	nf.tuple.protocol = nel->protocol;
	nf.ts_first = nel->ts;
	nf.ts_last = nel->ts;
	nf.nat = nel; /* this is also flag of dummy flow */
	nf.tcp_flags = (nel->nat_event == NAT_DESTROY)? TCP_FIN_RST : TCP_SYN_ACK;
	if (protocol >= 9) {
		nf.tuple.src.ip = nel->pre.s_addr;
		nf.tuple.dst.ip = nel->pre.d_addr;
		nf.tuple.s_port = nel->pre.s_port;
		nf.tuple.d_port = nel->pre.d_port;
		netflow_export_flow(&nf);
	} else {
		/* The weird v5 packet(s).
		 * src and dst will be same as in data flow from the FORWARD chain
		 * where src is pre-nat src ip and dst is post-nat dst ip.
		 * What we lacking here is external src ip for SNAT, or
		 * pre-nat dst ip for DNAT. We will put this into Nexthop field
		 * with port into src/dst AS field. tcp_flags will distinguish it's
		 * start or stop event. Two flows in case of full nat. */
		nf.tuple.src.ip = nel->pre.s_addr;
		nf.tuple.s_port = nel->pre.s_port;
		nf.tuple.dst.ip = nel->post.d_addr;
		nf.tuple.d_port = nel->post.d_port;

		if (nel->pre.s_addr != nel->post.s_addr ||
		    nel->pre.s_port != nel->post.s_port) {
			nf.nh.ip = nel->post.s_addr;
			nf.s_as  = nel->post.s_port;
			netflow_export_flow(&nf);
		}
		if (nel->pre.d_addr != nel->post.d_addr ||
		    nel->pre.d_port != nel->post.d_port) {
			nf.nh.ip = nel->pre.d_addr;
			nf.d_as  = nel->pre.d_port;
			netflow_export_flow(&nf);
		}
	}
	kfree(nel);
}
#endif /* CONFIG_NF_NAT_NEEDED */

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
/* return -1 is trylockfailed, 0 if nothin gexported, >=1 if exported something */
static int netflow_scan_and_export(int flush)
{
	long i_timeout = inactive_timeout * HZ;
	long a_timeout = active_timeout * HZ;
	int trylock_failed = 0;
	int pdu_c = pdu_count;

	if (flush)
		i_timeout = 0;

	spin_lock_bh(&hlist_lock);
	/* This is different order of locking than elsewhere,
	 * so we trylock&break to avoid deadlock. */

	while (likely(!list_empty(&ipt_netflow_list))) {
		struct ipt_netflow *nf;

		/* Last entry, which is usually oldest. */
		nf = list_entry(ipt_netflow_list.prev, struct ipt_netflow, list);
		if (!spin_trylock_bh(nf->lock)) {
			trylock_failed = 1;
			break;
		}
		/* Note: i_timeout checked with >= to allow specifying zero timeout
		 * to purge all flows on module unload */
		if (((jiffies - nf->ts_last) >= i_timeout) ||
		    active_needs_export(nf, a_timeout)) {
			hlist_del(&nf->hlist);
			spin_unlock_bh(nf->lock);

			list_del(&nf->list);
			spin_unlock_bh(&hlist_lock);

			NETFLOW_STAT_ADD(pkt_out, nf->nr_packets);
			NETFLOW_STAT_ADD(traf_out, nf->nr_bytes);
			netflow_export_flow(nf);
			spin_lock_bh(&hlist_lock);
		} else {
			spin_unlock_bh(nf->lock);
			/* all flows which need to be exported is always at the tail
			 * so if no more exportable flows we can break */
			break;
		}
	}
	spin_unlock_bh(&hlist_lock);

#ifdef CONFIG_NF_NAT_NEEDED
	write_lock_bh(&nat_lock);
	while (!list_empty(&nat_list)) {
		struct nat_event *nel;

		nel = list_entry(nat_list.next, struct nat_event, list);
		list_del(&nel->list);
		write_unlock_bh(&nat_lock);
		export_nat_event(nel);
		write_lock_bh(&nat_lock);
	}
	write_unlock_bh(&nat_lock);
#endif
	/* flush flows stored in pdu if there no new flows for too long */
	/* Note: using >= to allow flow purge on zero timeout */
	if ((jiffies - pdu_ts_mod) >= i_timeout)
		netflow_export_pdu();

	return trylock_failed? -1 : pdu_count - pdu_c;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,20)
static void netflow_work_fn(void *dummy)
#else
static void netflow_work_fn(struct work_struct *dummy)
#endif
{
	int status;

	status = netflow_scan_and_export(DONT_FLUSH);
	_schedule_scan_worker(status);
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

#ifdef CONFIG_NF_NAT_NEEDED
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,31)
struct nf_ct_event_notifier *saved_event_cb __read_mostly = NULL;
#endif
static int netflow_conntrack_event(unsigned int events, struct nf_ct_event *item)
{
	struct nf_conn *ct = item->ct;
	struct nat_event *nel;
	const struct nf_conntrack_tuple *t;
	int ret = NOTIFY_DONE;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,31)
	struct nf_ct_event_notifier *notifier;

	/* Call netlink first. */
	notifier = rcu_dereference(saved_event_cb);
	if (notifier != NULL)
		ret = notifier->fcn(events, item);
#endif
	if (!natevents)
		return ret;

	if (!(events & ((1 << IPCT_NEW) | (1 << IPCT_RELATED) | (1 << IPCT_DESTROY))))
		return ret;

	if (!(ct->status & IPS_NAT_MASK))
		return ret;

	if (ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.l3num != AF_INET ||
	    ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.l3num != AF_INET)
		return ret;

	if (!(nel = kmalloc(sizeof(struct nat_event), GFP_ATOMIC))) {
		printk(KERN_ERR "ipt_NETFLOW: can't kmalloc nat event\n");
		return ret;
	}
	memset(nel, 0, sizeof(struct nat_event));
	nel->ts = jiffies;
	t = &ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple;
	nel->protocol = t->dst.protonum;
	nel->pre.s_addr = t->src.u3.ip;
	nel->pre.d_addr = t->dst.u3.ip;
	nel->pre.s_port = t->src.u.all;
	nel->pre.d_port = t->dst.u.all;
	t = &ct->tuplehash[IP_CT_DIR_REPLY].tuple;
	/* reply is reversed */
	nel->post.s_addr = t->dst.u3.ip;
	nel->post.d_addr = t->src.u3.ip;
	nel->post.s_port = t->dst.u.all;
	nel->post.d_port = t->src.u.all;
	if (events & (1 << IPCT_DESTROY)) {
		nel->nat_event = NAT_DESTROY;
		nat_events_stop++;
	} else {
		nel->nat_event = NAT_CREATE;
		nat_events_start++;
	}

	write_lock_bh(&nat_lock);
	list_add_tail(&nel->list, &nat_list);
	write_unlock_bh(&nat_lock);

	return ret;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,31)
static struct notifier_block ctnl_notifier = {
	.notifier_call = netflow_conntrack_event
};
#else
static struct nf_ct_event_notifier ctnl_notifier = {
	.fcn = netflow_conntrack_event
};
#endif /* since 2.6.31 */
#endif /* CONFIG_NF_NAT_NEEDED */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,23) && \
    LINUX_VERSION_CODE < KERNEL_VERSION(2,6,35)
static bool
#else
static int
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,28)
netflow_target_check(const char *tablename, const void *entry, const struct xt_target *target,
    void *targinfo, unsigned int targinfosize, unsigned int hook_mask)
{
#else
netflow_target_check(const struct xt_tgchk_param *par)
{
	const char *tablename = par->table;
	const struct xt_target *target = par->target;
#endif
	if (strcmp("nat", tablename) == 0) {
		/* In the nat table we only see single packet per flow, which is useless. */
		printk(KERN_ERR "%s target: is not valid in %s table\n", target->name, tablename);
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,35)
#define CHECK_FAIL	0
#define CHECK_OK	1
#else
#define CHECK_FAIL	-EINVAL
#define CHECK_OK	0
#endif
		return CHECK_FAIL;
	}
	return CHECK_OK;
}

static inline __u32 observed_hdrs(__u8 currenthdr)
{
	switch (currenthdr) {
	case IPPROTO_DSTOPTS:  return 1;
	case IPPROTO_HOPOPTS:  return 1<<1;
	case IPPROTO_ROUTING:  return 1<<5;
	case IPPROTO_ESP:      return 1<<13;
	case IPPROTO_AH:       return 1<<14;
	case IPPROTO_MH:       return 1<<12;
	case 108:              return 1<<15;
	case IPPROTO_FRAGMENT: return 0; /* Handled elsewhere. */
	}
	return 1<<3;
}

/* http://www.iana.org/assignments/ip-parameters/ip-parameters.xhtml */
static const __u8 ip4_opt_table[] = {
	[7]	= 0,	/* RR */
	[134]	= 1,	/* CIPSO */
	[133]	= 2,	/* E-SEC */
	[68]	= 3,	/* TS */
	[131]	= 4,	/* LSR */
	[130]	= 5,	/* SEC */
	[1]	= 6,	/* NOP */
	[0]	= 7,	/* EOOL */
	[15]	= 8,	/* ENCODE */
	[142]	= 9,	/* VISA */
	[205]	= 10,	/* FINN */
	[12]	= 11,	/* MTUR */
	[11]	= 12,	/* MTUP */
	[10]	= 13,	/* ZSU */
	[137]	= 14,	/* SSR */
	[136]	= 15,	/* SID */
	[151]	= 16,	/* DPS */
	[150]	= 17,	/* NSAPA */
	[149]	= 18,	/* SDB */
	[147]	= 19,	/* ADDEXT */
	[148]	= 20,	/* RTRALT */
	[82]	= 21,	/* TR */
	[145]	= 22,	/* EIP */
	[144]	= 23,	/* IMITD */
	[30]	= 25,	/* EXP */
	[94]	= 25,	/* EXP */
	[158]	= 25,	/* EXP */
	[222]	= 25,	/* EXP */
	[25]	= 30,	/* QS */
	[152]	= 31,	/* UMP */
};
/* Parse IPv4 Options array int ipv4Options IPFIX value. */
static inline __u32 ip4_options(const unsigned char *p, const int optsize)
{
	__u32 ret = 0;
	int i;

	for (i = 0; i < optsize; ) {
		__u8 op = p[i++];
		if (op < ARRAY_SIZE(ip4_opt_table))
			ret |= 1 << ip4_opt_table[op];
		if (i >= optsize || op == 0)
			break;
		else if (op == 1)
			continue;
		i += p[i] - 1;
	}
	return ret;
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
	const struct sk_buff *skb = *pskb;
#endif
	union {
		struct iphdr ip;
		struct ipv6hdr ip6;
	} _iph, *iph;
	unsigned int hash;
	spinlock_t *lock;
	const int family = par->family;
	struct ipt_netflow_tuple tuple;
	struct ipt_netflow *nf;
	__u8 tcp_flags;
	struct netflow_aggr_n *aggr_n;
	struct netflow_aggr_p *aggr_p;
	__u8 s_mask, d_mask;
	unsigned int ptr;
	int fragment;
	size_t pkt_len;
	int options = 0;

	iph = skb_header_pointer(skb, 0, (likely(family == AF_INET))? sizeof(_iph.ip) : sizeof(_iph.ip6), &iph);
	if (unlikely(iph == NULL)) {
		NETFLOW_STAT_INC(truncated);
		NETFLOW_STAT_INC(pkt_drop);
		return IPT_CONTINUE;
	}

	tuple.l3proto	= family;
	tuple.s_port	= 0;
	tuple.d_port	= 0;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,28)
	tuple.i_ifc	= if_in? if_in->ifindex : -1;
#else
	tuple.i_ifc	= par->in? par->in->ifindex : -1;
#endif
	tcp_flags	= 0; /* Cisco sometimes have TCP ACK for non TCP packets, don't get it */
	s_mask		= 0;
	d_mask		= 0;

	if (likely(family == AF_INET)) {
		tuple.src	= (union nf_inet_addr){ .ip = iph->ip.saddr };
		tuple.dst	= (union nf_inet_addr){ .ip = iph->ip.daddr };
		tuple.tos	= iph->ip.tos;
		tuple.protocol	= iph->ip.protocol;
		fragment	= unlikely(iph->ip.frag_off & htons(IP_OFFSET));
		ptr		= iph->ip.ihl * 4;
		pkt_len		= ntohs(iph->ip.tot_len);

#define IPHDR_MAXSIZE (4 * 15)
		if (iph->ip.ihl * 4 > sizeof(struct iphdr)) {
			unsigned char _opt[IPHDR_MAXSIZE - sizeof(struct iphdr)];
			const unsigned char *op;
			unsigned int optsize = iph->ip.ihl * 4 - sizeof(struct iphdr);

			op = skb_header_pointer(skb, sizeof(_iph), optsize, _opt);
			if (op != NULL)
				options = ip4_options(op, optsize);
		}
	} else {
		__u8 currenthdr;

		tuple.src.in6	= iph->ip6.saddr;
		tuple.dst.in6	= iph->ip6.daddr;
		tuple.tos	= iph->ip6.priority;
		fragment	= 0;
		ptr		= sizeof(struct ipv6hdr);
		pkt_len		= ntohs(iph->ip6.payload_len) + sizeof(struct ipv6hdr);

		currenthdr	= iph->ip6.nexthdr;
		while (currenthdr != NEXTHDR_NONE && ipv6_ext_hdr(currenthdr)) {
			struct ipv6_opt_hdr _hdr;
			const struct ipv6_opt_hdr *hp;
			unsigned int hdrlen = 0;

			options |= observed_hdrs(currenthdr);
			hp = skb_header_pointer(skb, ptr, sizeof(_hdr), &_hdr);
			if (hp == NULL) {
				/* We have src/dst, so must account something. */
				tuple.protocol = currenthdr;
				fragment = 3;
				goto do_protocols;
			}

			switch (currenthdr) {
			case IPPROTO_FRAGMENT: {
				struct frag_hdr _fhdr;
				const struct frag_hdr *fh;

				fh = skb_header_pointer(skb, ptr, sizeof(_fhdr),
						&_fhdr);
				if (fh == NULL) {
					tuple.protocol = currenthdr;
					fragment = 2;
					goto do_protocols;
				}
				fragment = 1;
#define FRA0 (1<<4) /* Fragment header - first fragment */
#define FRA1 (1<<6) /* Fragmentation header - not first fragment */
				options |= (ntohs(fh->frag_off) & 0xFFF8)? FRA1 : FRA0;
				hdrlen = 8;
				break;
			}
			case IPPROTO_AH: {
				struct ip_auth_hdr _hdr, *hp;

				if (likely(hp = skb_header_pointer(skb, ptr, 8, &_hdr))) {
					tuple.s_port = hp->spi >> 16;
					tuple.d_port = hp->spi;
				}
				hdrlen = (hp->hdrlen + 2) << 2;
				break;
			}
			default:
				hdrlen = ipv6_optlen(hp);
			}
			currenthdr = hp->nexthdr;
			ptr += hdrlen;
		}
		tuple.protocol	= currenthdr;
		options |= observed_hdrs(currenthdr);
	}

do_protocols:
	if (fragment) {
		/* if conntrack is enabled it should defrag on pre-routing and local-out */
		NETFLOW_STAT_INC(frags);
	} else {
		switch (tuple.protocol) {
		    case IPPROTO_TCP: {
			struct tcphdr _hdr, *hp;

			if (likely(hp = skb_header_pointer(skb, ptr, 14, &_hdr))) {
				tuple.s_port = hp->source;
				tuple.d_port = hp->dest;
				tcp_flags = (u_int8_t)(ntohl(tcp_flag_word(hp)) >> 16);
			}
			break;
		    }
		    case IPPROTO_UDP:
		    case IPPROTO_UDPLITE:
		    case IPPROTO_SCTP: {
			struct udphdr _hdr, *hp;

			if (likely(hp = skb_header_pointer(skb, ptr, 4, &_hdr))) {
				tuple.s_port = hp->source;
				tuple.d_port = hp->dest;
			}
			break;
		    }
		    case IPPROTO_ICMP: {
			struct icmphdr _hdr, *hp;

			if (likely(family == AF_INET &&
				    (hp = skb_header_pointer(skb, ptr, 2, &_hdr))))
				tuple.d_port = htons((hp->type << 8) | hp->code);
			break;
		    }
		    case IPPROTO_ICMPV6: {
			    struct icmp6hdr _icmp6h, *ic;

			    if (likely(family == AF_INET6 &&
					(ic = skb_header_pointer(skb, ptr, 2, &_icmp6h))))
				    tuple.d_port = htons((ic->icmp6_type << 8) | ic->icmp6_code);
			    break;
		    }
		    case IPPROTO_IGMP: {
			struct igmphdr _hdr, *hp;

			if (likely(hp = skb_header_pointer(skb, ptr, 1, &_hdr)))
				tuple.d_port = hp->type;
			}
			break;
		    case IPPROTO_AH: { /* IPSEC */
			struct ip_auth_hdr _hdr, *hp;

			if (likely(family == AF_INET && /* For IPv6 it's parsed above. */
				    (hp = skb_header_pointer(skb, ptr, 8, &_hdr)))) {
				tuple.s_port = hp->spi >> 16;
				tuple.d_port = hp->spi;
			}
			break;
		    }
		    case IPPROTO_ESP: {
			struct ip_esp_hdr _hdr, *hp;

			if (likely(hp = skb_header_pointer(skb, ptr, 4, &_hdr)))
				tuple.s_port = hp->spi >> 16;
				tuple.d_port = hp->spi;
			}
			break;
	       	}
	} /* not fragmented */

	/* aggregate networks */
	read_lock_bh(&aggr_lock);
	if (family == AF_INET) {
		list_for_each_entry(aggr_n, &aggr_n_list, list)
			if (unlikely((ntohl(tuple.src.ip) & aggr_n->mask) == aggr_n->addr)) {
				tuple.src.ip &= htonl(aggr_n->aggr_mask);
				s_mask = aggr_n->prefix;
				atomic_inc(&aggr_n->usage);
				break;
			}
		list_for_each_entry(aggr_n, &aggr_n_list, list)
			if (unlikely((ntohl(tuple.dst.ip) & aggr_n->mask) == aggr_n->addr)) {
				tuple.dst.ip &= htonl(aggr_n->aggr_mask);
				d_mask = aggr_n->prefix;
				atomic_inc(&aggr_n->usage);
				break;
			}
	}

	if (tuple.protocol == IPPROTO_TCP ||
	    tuple.protocol == IPPROTO_UDP ||
	    tuple.protocol == IPPROTO_SCTP ||
	    tuple.protocol == IPPROTO_UDPLITE) {
		/* aggregate ports */
		list_for_each_entry(aggr_p, &aggr_p_list, list)
			if (unlikely(ntohs(tuple.s_port) >= aggr_p->port1 &&
			    ntohs(tuple.s_port) <= aggr_p->port2)) {
				tuple.s_port = htons(aggr_p->aggr_port);
				atomic_inc(&aggr_p->usage);
				break;
			}

		list_for_each_entry(aggr_p, &aggr_p_list, list)
			if (unlikely(ntohs(tuple.d_port) >= aggr_p->port1 &&
			    ntohs(tuple.d_port) <= aggr_p->port2)) {
				tuple.d_port = htons(aggr_p->aggr_port);
				atomic_inc(&aggr_p->usage);
				break;
			}
	}
	read_unlock_bh(&aggr_lock);

	hash = hash_netflow(&tuple);
	lock = &htable_locks[hash & LOCK_COUNT_MASK];
	spin_lock_bh(lock);
	/* record */
	nf = ipt_netflow_find(&tuple, hash);
	if (unlikely(!nf)) {
		struct rtable *rt;

		if (unlikely(maxflows > 0 && atomic_read(&ipt_netflow_count) >= maxflows)) {
			/* This is DOS attack prevention */
			NETFLOW_STAT_INC(maxflows_err);
			NETFLOW_STAT_INC(pkt_drop);
			NETFLOW_STAT_ADD(traf_drop, pkt_len);
			spin_unlock_bh(lock);
			return IPT_CONTINUE;
		}

		nf = init_netflow(&tuple, skb, hash);
		if (unlikely(!nf || IS_ERR(nf))) {
			NETFLOW_STAT_INC(alloc_err);
			NETFLOW_STAT_INC(pkt_drop);
			NETFLOW_STAT_ADD(traf_drop, pkt_len);
			spin_unlock_bh(lock);
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

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,26)
		rt = (struct rtable *)skb->dst;
#else
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,21)
		rt = skb->rtable;
#else
		rt = skb_rtable(skb);
#endif
#endif
		if (likely(family == AF_INET)) {
			if (rt)
				nf->nh.ip = rt->rt_gateway;
		} else {
			if (rt)
				nf->nh.in6 = ((struct rt6_info *)rt)->rt6i_gateway;
			nf->flow_label = (iph->ip6.flow_lbl[0] << 16) |
			       	(iph->ip6.flow_lbl[1] << 8) | (iph->ip6.flow_lbl[2]);
		}
#if 0
		if (unlikely(debug > 2))
			printk(KERN_INFO "ipt_NETFLOW: new (%u) %hd:%hd SRC=%u.%u.%u.%u:%u DST=%u.%u.%u.%u:%u\n",
			       atomic_read(&ipt_netflow_count),
			       tuple.i_ifc, nf->o_ifc,
			       NIPQUAD(tuple.s_addr), ntohs(tuple.s_port),
			       NIPQUAD(tuple.d_addr), ntohs(tuple.d_port));
#endif
	} else {
		/* ipt_netflow_list is sorted by access time:
		 * most recently accessed flows are at head, old flows remain at tail
		 * this function bubble up flow to the head */
		spin_lock_bh(&hlist_lock);
		list_move(&nf->list, &ipt_netflow_list);
		spin_unlock_bh(&hlist_lock);
	}

#ifdef CONFIG_NF_CONNTRACK_MARK
	{
		struct nf_conn *ct;
		enum ip_conntrack_info ctinfo;
		ct = nf_ct_get(skb, &ctinfo);
		if (ct)
			nf->mark = ct->mark;
	}
#endif

	nf->nr_packets++;
	nf->nr_bytes += pkt_len;
	nf->ts_last = jiffies;
	nf->tcp_flags |= tcp_flags;
	nf->options |= options;

	NETFLOW_STAT_INC(pkt_total);
	NETFLOW_STAT_ADD(traf_total, ntohs(pkt_len));

	if (likely(active_needs_export(nf, active_timeout * HZ))) {
		/* ok, if this active flow to be exported
		 * bubble it to the tail */
		spin_lock_bh(&hlist_lock);
		list_move_tail(&nf->list, &ipt_netflow_list);
		spin_unlock_bh(&hlist_lock);

		/* Blog: I thought about forcing timer to wake up sooner if we have
		 * enough exportable flows, but in fact this doesn't have much sense,
		 * becasue this would only move flow data from one memory to another
		 * (from our buffers to socket buffers, and socket buffers even have
		 * limited size). But yes, this is disputable. */
	}

	spin_unlock_bh(lock);

	return IPT_CONTINUE;
}

#ifdef CONFIG_NF_NAT_NEEDED
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,2,0)
#define NET_STRUCT struct net *net
#define NET_ARG net,
#define nf_conntrack_event_cb net->ct.nf_conntrack_event_cb
#else
#define NET_STRUCT void
#define NET_ARG
#endif
static int set_notifier_cb(NET_STRUCT)
{
	struct nf_ct_event_notifier *notifier;

	notifier = rcu_dereference(nf_conntrack_event_cb);
	if (notifier == NULL) {
		/* Polite mode. */
		nf_conntrack_register_notifier(NET_ARG &ctnl_notifier);
	} else if (notifier != &ctnl_notifier) {
		if (!saved_event_cb)
			saved_event_cb = notifier;
		else if (saved_event_cb != notifier)
			printk(KERN_ERR "natevents_net_init: %p != %p (report error.)\n",
			    saved_event_cb, notifier);
		rcu_assign_pointer(nf_conntrack_event_cb, &ctnl_notifier);
	} else
		printk(KERN_ERR "ipt_NETFLOW: natevents already enabled.\n");
	return 0;
}
static void unset_notifier_cb(NET_STRUCT)
{
	struct nf_ct_event_notifier *notifier;

	notifier = rcu_dereference(nf_conntrack_event_cb);
	if (notifier == &ctnl_notifier) {
		if (saved_event_cb == NULL)
			nf_conntrack_unregister_notifier(NET_ARG &ctnl_notifier);
		else
			rcu_assign_pointer(nf_conntrack_event_cb, saved_event_cb);
	} else
		printk(KERN_ERR "ipt_NETFLOW: natevents already disabled.\n");
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,2,0)
#undef nf_conntrack_event_cb
static struct pernet_operations natevents_net_ops = {
	.init = set_notifier_cb,
	.exit = unset_notifier_cb
};
#endif
static DEFINE_MUTEX(events_lock);
/* Both functions may be called multiple times. */
static void register_ct_events(void)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,31)
#define NETLINK_M "nf_conntrack_netlink"
	struct module *netlink_m;
	static int referenced = 0;
#endif

	printk(KERN_INFO "ipt_NETFLOW: enable natevents.\n");
	mutex_lock(&events_lock);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,31)
	/* Pre-load netlink module who will be first notifier
	 * user, and then hijack nf_conntrack_event_cb from it. */
	if (
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,2,0)
	    !rcu_dereference(nf_conntrack_event_cb) ||
#endif
	    !(netlink_m = find_module(NETLINK_M))) {
		printk("Loading " NETLINK_M "\n");
		request_module(NETLINK_M);
	}
	/* Reference netlink module to prevent it's unsafe unload before us. */
	if (!referenced && (netlink_m = find_module(NETLINK_M))) {
		referenced++;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,35)
#define use_module ref_module
#endif
		use_module(THIS_MODULE, netlink_m);
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,2,0)
	register_pernet_subsys(&natevents_net_ops);
#else
	set_notifier_cb();
#endif
#else /* < v2.6.31 */
	if (!natevents && nf_conntrack_register_notifier(&ctnl_notifier) < 0)
		printk(KERN_ERR "Can't register conntrack notifier, natevents disabled.\n");
	else
#endif
	natevents = 1;
	mutex_unlock(&events_lock);
}

static void unregister_ct_events(void)
{
	printk(KERN_INFO "ipt_NETFLOW: disable natevents.\n");
	mutex_lock(&events_lock);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,31)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,2,0)
	unregister_pernet_subsys(&natevents_net_ops);
#else /* < v3.2 */
	unset_notifier_cb();
#endif /* v3.2 */
	rcu_assign_pointer(saved_event_cb, NULL);
#else /* < v2.6.31 */
	nf_conntrack_unregister_notifier(&ctnl_notifier);
#endif
	natevents = 0;
	mutex_unlock(&events_lock);
}
#endif /* CONFIG_NF_NAT_NEEDED */

#ifndef NF_IP_LOCAL_IN /* 2.6.25 */
#define NF_IP_PRE_ROUTING	NF_INET_PRE_ROUTING
#define NF_IP_LOCAL_IN		NF_INET_LOCAL_IN
#define NF_IP_FORWARD		NF_INET_FORWARD
#define NF_IP_LOCAL_OUT		NF_INET_LOCAL_OUT
#define NF_IP_POST_ROUTING	NF_INET_POST_ROUTING
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,19)
/* net/netfilter/x_tables.c */
static void xt_unregister_targets(struct xt_target *target, unsigned int n)
{
	unsigned int i;
	for (i = 0; i < n; n++)
		xt_unregister_target(&target[i]);
}
static int xt_register_targets(struct xt_target *target, unsigned int n)
{
	unsigned int i;
	int err = 0;
	for (i = 0; i < n; n++)
		if ((err = xt_register_target(&target[i])))
			goto err;
	return err;
err:
	if (i > 0)
		xt_unregister_targets(target, i);
	return err;

}
#endif

static struct ipt_target ipt_netflow_reg[] __read_mostly = {
	{
		.name		= "NETFLOW",
		.target		= netflow_target,
		.checkentry	= netflow_target_check,
		.family		= AF_INET,
		.hooks		=
		       	(1 << NF_IP_PRE_ROUTING) |
		       	(1 << NF_IP_LOCAL_IN) |
		       	(1 << NF_IP_FORWARD) |
			(1 << NF_IP_LOCAL_OUT) |
			(1 << NF_IP_POST_ROUTING),
		.me		= THIS_MODULE
	},
	{
		.name		= "NETFLOW",
		.target		= netflow_target,
		.checkentry	= netflow_target_check,
		.family		= AF_INET6,
		.hooks		=
		       	(1 << NF_IP_PRE_ROUTING) |
		       	(1 << NF_IP_LOCAL_IN) |
		       	(1 << NF_IP_FORWARD) |
			(1 << NF_IP_LOCAL_OUT) |
			(1 << NF_IP_POST_ROUTING),
		.me		= THIS_MODULE
	},
};

static int __init ipt_netflow_init(void)
{
#ifdef CONFIG_PROC_FS
	struct proc_dir_entry *proc_stat;
#endif

	get_random_bytes(&ipt_netflow_hash_rnd, 4);

	/* determine hash size (idea from nf_conntrack_core.c) */
	if (!hashsize) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,11,0)
#define num_physpages totalram_pages
#endif
		hashsize = (((num_physpages << PAGE_SHIFT) / 16384)
					 / sizeof(struct hlist_head));
		if (num_physpages > (1024 * 1024 * 1024 / PAGE_SIZE))
			hashsize = 8192;
	}
	if (hashsize < 16)
		hashsize = 16;
	printk(KERN_INFO "ipt_NETFLOW version %s (%u buckets)\n",
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
	_schedule_scan_worker(0);
	setup_timer(&rate_timer, rate_timer_calc, 0);
	mod_timer(&rate_timer, jiffies + (HZ * SAMPLERATE));

	peakflows_at = jiffies;
	if (xt_register_targets(ipt_netflow_reg, ARRAY_SIZE(ipt_netflow_reg)))
		goto err_stop_timer;

#ifdef CONFIG_NF_NAT_NEEDED
	if (natevents)
		register_ct_events();
#endif

	printk(KERN_INFO "ipt_NETFLOW is loaded.\n");
	return 0;

err_stop_timer:
	_unschedule_scan_worker();
	netflow_scan_and_export(AND_FLUSH);
	del_timer_sync(&rate_timer);
	free_templates();
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
	printk(KERN_INFO "ipt_NETFLOW is not loaded.\n");
	return -ENOMEM;
}

static void __exit ipt_netflow_fini(void)
{
	printk(KERN_INFO "ipt_NETFLOW unloading..\n");

#ifdef CONFIG_SYSCTL
	unregister_sysctl_table(netflow_sysctl_header);
#endif
#ifdef CONFIG_PROC_FS
	remove_proc_entry("ipt_netflow", INIT_NET(proc_net_stat));
#endif
	xt_unregister_targets(ipt_netflow_reg, ARRAY_SIZE(ipt_netflow_reg));
#ifdef CONFIG_NF_NAT_NEEDED
	if (natevents)
		unregister_ct_events();
#endif
	_unschedule_scan_worker();
	netflow_scan_and_export(AND_FLUSH);
	del_timer_sync(&rate_timer);

	synchronize_sched();

	free_templates();
	destination_removeall();
	aggregation_remove(&aggr_n_list);
	aggregation_remove(&aggr_p_list);

	kmem_cache_destroy(ipt_netflow_cachep);
	vfree(ipt_netflow_hash);

	printk(KERN_INFO "ipt_NETFLOW unloaded.\n");
}

module_init(ipt_netflow_init);
module_exit(ipt_netflow_fini);

/* vim: set sw=8: */
