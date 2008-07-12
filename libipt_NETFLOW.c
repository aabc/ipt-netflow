// iptables helper for NETFLOW target
// <abc@telekom.ru>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>
#include <iptables.h>
#include <net/if.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <iptables.h>
//#include <linux/netfilter_ipv4/ip_tables.h>
//#include "ipt_NETFLOW.h"

static struct option opts[] = {
  {0}
};

static void help(void)
{
	printf( "NETFLOW target\n");
}

static int parse(int c, char **argv, int invert, unsigned int *flags,
      const struct ipt_entry *entry,
      struct ipt_entry_target **target)
{

	return 1;
}

static void final_check(unsigned int flags)
{
}

static void save(const struct ipt_ip *ip, const struct ipt_entry_target *match)
{
}

static void print(const struct ipt_ip *ip,
      const struct ipt_entry_target *target,
      int numeric)
{
	printf("NETFLOW ");
}

static struct iptables_target netflow = { 
	.next		= NULL,
	.name		= "NETFLOW",
	.version	= IPTABLES_VERSION,
	.size           = IPT_ALIGN(0),
	.userspacesize  = IPT_ALIGN(0),
	.help		= &help,
	.parse		= &parse,
	.final_check    = &final_check,
	.print		= &print,
	.save		= &save,
	.extra_opts     = opts
};

void _init(void)
{
	register_target(&netflow);
}
