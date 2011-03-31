// iptables helper for NETFLOW target
// <abc@telekom.ru>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>
#include <net/if.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define __EXPORTED_HEADERS__
#ifdef XTABLES
#include <xtables.h>
#else
#include <iptables.h>
#endif

#ifdef XTABLES_VERSION_CODE	// since 1.4.1
#define MOD140
#define iptables_target         xtables_target
#endif

#ifdef iptables_target		// only in 1.4.0
#define MOD140
#endif

#ifdef MOD140
#define ipt_entry_target	xt_entry_target
#define register_target		xtables_register_target
#define _IPT_ENTRY		void
#define _IPT_IP			void
#ifndef IPT_ALIGN
#define IPT_ALIGN		XT_ALIGN
#endif
#else // before 1.3.x
#define _IPT_ENTRY struct ipt_entry
#define _IPT_IP struct ipt_ip
#endif

static struct option opts[] = {
  {0}
};

static void help(void)
{
	printf( "NETFLOW target\n");
}

//static int parse(int c, char **argv, int invert, unsigned int *flags,
//      const _IPT_ENTRY *entry,
//      struct ipt_entry_target **target)
static int parse(int c, char **argv, int invert, unsigned int *flags,
	     const _IPT_ENTRY  *entry,
	     struct ipt_entry_target **targetinfo)

{

	return 1;
}

static void final_check(unsigned int flags)
{
}

static void save(const _IPT_IP *ip, const struct ipt_entry_target *match)
{
}

static void print(const _IPT_IP *ip,
      const struct ipt_entry_target *target,
      int numeric)
{
	printf("NETFLOW ");
}

static struct iptables_target netflow = { 
#ifdef MOD140
	.family		= AF_INET,
#endif
	.next		= NULL,
	.name		= "NETFLOW",
#ifdef XTABLES_VERSION
	.version	= XTABLES_VERSION,
#else
	.version	= IPTABLES_VERSION,
#endif
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
