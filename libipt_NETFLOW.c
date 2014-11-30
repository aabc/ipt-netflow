/*
 * iptables helper for NETFLOW target
 * <abc@telekom.ru>
 *
 *
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

#ifndef IPTABLES_VERSION
#define IPTABLES_VERSION XTABLES_VERSION
#endif

static struct option opts[] = {
  { 0 }
};

static void help(void)
{
	printf("NETFLOW target\n");
}

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

#ifndef _init
#define _init __attribute__((constructor)) _INIT
#endif
void _init(void)
{
	register_target(&netflow);
}
