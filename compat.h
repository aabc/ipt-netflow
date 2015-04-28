#ifndef COMPAT_NETFLOW_H
#define COMPAT_NETFLOW_H


#ifndef NIPQUAD
# define NIPQUAD(addr) \
	((unsigned char *)&addr)[0], \
	((unsigned char *)&addr)[1], \
	((unsigned char *)&addr)[2], \
	((unsigned char *)&addr)[3]
#endif
#ifndef HIPQUAD
# if defined(__LITTLE_ENDIAN)
#  define HIPQUAD(addr) \
	((unsigned char *)&addr)[3], \
	((unsigned char *)&addr)[2], \
	((unsigned char *)&addr)[1], \
	((unsigned char *)&addr)[0]
# elif defined(__BIG_ENDIAN)
#  define HIPQUAD NIPQUAD
# else
#  error "Please fix asm/byteorder.h"
# endif /* __LITTLE_ENDIAN */
#endif

#ifndef IPT_CONTINUE
# define IPT_CONTINUE XT_CONTINUE
# define ipt_target xt_target
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25)
union nf_inet_addr {
	__be32		ip;
	__be32		ip6[4];
	struct in_addr	in;
	struct in6_addr	in6;
};
#endif

#ifndef list_first_entry
#define list_first_entry(ptr, type, member) \
	list_entry((ptr)->next, type, member)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)
# define INIT_NET(x) x
#else
# define INIT_NET(x) init_net.x
#endif

#ifndef ETH_P_8021AD
# define ETH_P_8021AD	0x88A8	/* 802.1ad Service VLAN */
#endif

#ifndef ETH_P_QINQ1
# define ETH_P_QINQ1	0x9100	/* deprecated QinQ VLAN */
# define ETH_P_QINQ2	0x9200	/* deprecated QinQ VLAN */
# define ETH_P_QINQ3	0x9300	/* deprecated QinQ VLAN */
#endif

#ifndef IPPROTO_MH
# define IPPROTO_MH	135
#endif

#ifdef CONFIG_SYSCTL
# if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,32)
#  define BEFORE2632(x,y) x,y
# else /* since 2.6.32 */
#  define BEFORE2632(x,y)
# endif

# if LINUX_VERSION_CODE >= KERNEL_VERSION(3,17,0)
#  define ctl_table struct ctl_table
# endif

# ifndef CONFIG_GRKERNSEC
#  define ctl_table_no_const ctl_table
# endif
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,9,0)
# define compat_hlist_for_each_entry			hlist_for_each_entry
# define compat_hlist_for_each_entry_safe		hlist_for_each_entry_safe
#else /* since 3.9.0 */
# define compat_hlist_for_each_entry(a,pos,c,d)		hlist_for_each_entry(a,c,d)
# define compat_hlist_for_each_entry_safe(a,pos,c,d,e)	hlist_for_each_entry_safe(a,c,d,e)
#endif

#ifndef WARN_ONCE
#define WARN_ONCE(x,fmt...) ({ if (x) printk(KERN_WARNING fmt); })
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,20)
# define IPPROTO_UDPLITE 136
#endif

#ifndef time_is_before_jiffies
# define time_is_before_jiffies(a) time_after(jiffies, a)
#endif
#ifndef time_is_after_jiffies
# define time_is_after_jiffies(a) time_before(jiffies, a)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,14,0)
# if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,19)
#  define prandom_u32 get_random_int
# elif LINUX_VERSION_CODE < KERNEL_VERSION(3,8,0)
#  define prandom_u32 random32
#endif
#define prandom_u32_max compat_prandom_u32_max
static inline u32 prandom_u32_max(u32 ep_ro)
{
	return (u32)(((u64) prandom_u32() * ep_ro) >> 32);
}
#endif

#ifndef min_not_zero
# define min_not_zero(x, y) ({			\
	typeof(x) __x = (x);			\
	typeof(y) __y = (y);			\
	__x == 0 ? __y : ((__y == 0) ? __x : min(__x, __y)); })
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,2,0)
static int __ethtool_get_settings(struct net_device *dev, struct ethtool_cmd *cmd)
{
	ASSERT_RTNL();

	if (!dev->ethtool_ops->get_settings)
		return -EOPNOTSUPP;

	memset(cmd, 0, sizeof(struct ethtool_cmd));
	cmd->cmd = ETHTOOL_GSET;
	return dev->ethtool_ops->get_settings(dev, cmd);
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,27)
# define ethtool_cmd_speed(x) (x)->speed
#endif

#ifndef ARPHRD_PHONET
# define ARPHRD_PHONET		820
# define ARPHRD_PHONET_PIPE	821
#endif
#ifndef ARPHRD_IEEE802154
# define ARPHRD_IEEE802154	804
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,22)
# define for_each_netdev_ns(net, dev) for (dev = dev_base; dev; dev = dev->next)
#elif LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)
# define for_each_netdev_ns(net, d) for_each_netdev(d)
#else
# define for_each_netdev_ns(net, d) for_each_netdev(net, d)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,35)
# define CHECK_FAIL	0
# define CHECK_OK	1
#else
# define CHECK_FAIL	-EINVAL
# define CHECK_OK	0
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,35)
# define use_module	ref_module
#endif

#ifndef NF_IP_LOCAL_IN /* 2.6.25 */
# define NF_IP_PRE_ROUTING	NF_INET_PRE_ROUTING
# define NF_IP_LOCAL_IN		NF_INET_LOCAL_IN
# define NF_IP_FORWARD		NF_INET_FORWARD
# define NF_IP_LOCAL_OUT	NF_INET_LOCAL_OUT
# define NF_IP_POST_ROUTING	NF_INET_POST_ROUTING
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,19)
/* net/netfilter/x_tables.c */
static void xt_unregister_targets(struct xt_target *target, unsigned int n)
{
	unsigned int i;

	for (i = 0; i < n; i++)
		xt_unregister_target(&target[i]);
}
static int xt_register_targets(struct xt_target *target, unsigned int n)
{
	unsigned int i;

	int err = 0;
	for (i = 0; i < n; i++)
		if ((err = xt_register_target(&target[i])))
			goto err;
	return err;
err:
	if (i > 0)
		xt_unregister_targets(target, i);
	return err;
}
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,11,0)
#define num_physpages	totalram_pages
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,35)
static inline s64 portable_ktime_to_ms(const ktime_t kt)
{
	struct timeval tv = ktime_to_timeval(kt);
	return (s64) tv.tv_sec * MSEC_PER_SEC + tv.tv_usec / USEC_PER_MSEC;
}
#define ktime_to_ms portable_ktime_to_ms
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,22)
static inline s64 portable_ktime_to_us(const ktime_t kt)
{
	struct timeval tv = ktime_to_timeval(kt);
	return (s64) tv.tv_sec * USEC_PER_SEC + tv.tv_usec;
}
#define ktime_to_us portable_ktime_to_us
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,26)
static inline void put_unaligned_be16(u16 val, void *p)
{
	put_unaligned(cpu_to_be16(val), (__be16 *)p);
}
static inline void put_unaligned_be32(u32 val, void *p)
{
	put_unaligned(cpu_to_be32(val), (__be32 *)p);
}
static inline void put_unaligned_be64(u64 val, void *p)
{
	put_unaligned(cpu_to_be64(val), (__be64 *)p);
}
#endif

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,24) && !defined(RHEL_MAJOR)
static void *__seq_open_private(struct file *f, struct seq_operations *ops,
    int psize)
{
	int rc;
	void *private;
	struct seq_file *seq;

	private = kzalloc(psize, GFP_KERNEL);
	if (private == NULL)
		goto out;

	rc = seq_open(f, ops);
	if (rc < 0)
		goto out_free;

	seq = f->private_data;
	seq->private = private;
	return private;

out_free:
	kfree(private);
out:
	return NULL;
}
#endif

/* disappeared in v3.19 */
#ifndef __get_cpu_var
#define __get_cpu_var(var)	(*this_cpu_ptr(&(var)))
#endif

#ifndef MPLS_HLEN
#define MPLS_HLEN 4
static inline int eth_p_mpls(__be16 eth_type)
{
	return eth_type == htons(ETH_P_MPLS_UC) ||
		eth_type == htons(ETH_P_MPLS_MC);
}
#endif
#ifndef MPLS_LS_S_MASK
struct mpls_label {
	__be32 entry;
};
#define MPLS_LS_S_MASK		0x00000100

#endif

#endif /* COMPAT_NETFLOW_H */
