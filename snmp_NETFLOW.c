/*
 * dlmod plugin for net-snmp for monitoring
 * ipt_NETFLOW module via IPT-NETFLOW-MIB.
 *
 * (c) 2014 <abc@telekom.ru>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>

#define iptNetflowMIB_oid 1, 3, 6, 1, 4, 1, 37476, 9000, 10, 1 /* .1.3.6.1.4.1.37476.9000.10.1 */

/* iptNetflowObjects */
static oid iptNetflowModule_oid[]    = { iptNetflowMIB_oid, 1, 1 };
static oid iptNetflowSysctl_oid[]    = { iptNetflowMIB_oid, 1, 2 };
/* iptNetflowStatistics */
static oid iptNetflowTotals_oid[]    = { iptNetflowMIB_oid, 2, 1 };
static oid iptNetflowCpuTable_oid[]  = { iptNetflowMIB_oid, 2, 2 };
static oid iptNetflowSockTable_oid[] = { iptNetflowMIB_oid, 2, 3 };

struct snmp_vars {
	int obj;
	int type;
	char *name;

	time_t ts; /* when value last read */
	long long val64;
};

struct snmp_vars modinfos[] = {
	{1, ASN_OCTET_STR, "name"},
	{2, ASN_OCTET_STR, "version"},
	{3, ASN_OCTET_STR, "srcversion"},
	{4, ASN_OCTET_STR, "loadTime"}, /* DateAndTime */
	{5, ASN_INTEGER,   "refcnt"},
	{ 0 }
};
#define MODINFO_NAME "ipt_NETFLOW"
#define MODINFO_NAME_ID 1
#define MODINFO_DATE_ID 4

struct snmp_vars sysctls[] = {
	{1,  ASN_INTEGER,   "protocol"},
	{2,  ASN_INTEGER,   "hashsize"},
	{3,  ASN_INTEGER,   "maxflows"},
	{4,  ASN_INTEGER,   "active_timeout"},
	{5,  ASN_INTEGER,   "inactive_timeout"},
	{6,  ASN_INTEGER,   "sndbuf"},
	{7,  ASN_OCTET_STR, "destination"},
	{8,  ASN_OCTET_STR, "aggregation"},
	{9,  ASN_OCTET_STR, "sampler"},
	{10, ASN_INTEGER,   "natevents"},
	{11, ASN_INTEGER,   "promisc"},
	{12, ASN_OCTET_STR, "snmp-rules"},
	{13, ASN_INTEGER,   "scan-min"},
	{ 0 }
};

struct snmp_vars totals[] = {
	{1,  ASN_COUNTER64, "inBitRate"},
	{2,  ASN_GAUGE,     "inPacketRate"},
	{3,  ASN_COUNTER64, "inFlows"},
	{4,  ASN_COUNTER64, "inPackets"},
	{5,  ASN_COUNTER64, "inBytes"},
	{6,  ASN_GAUGE,     "hashMetric"},
	{7,  ASN_GAUGE,     "hashMemory"},
	{8,  ASN_GAUGE,     "hashFlows"},
	{9,  ASN_GAUGE,     "hashPackets"},
	{10, ASN_COUNTER64, "hashBytes"},
	{11, ASN_COUNTER64, "dropPackets"},
	{12, ASN_COUNTER64, "dropBytes"},
	{13, ASN_GAUGE,     "outByteRate"},
	{14, ASN_COUNTER64, "outFlows"},
	{15, ASN_COUNTER64, "outPackets"},
	{16, ASN_COUNTER64, "outBytes"},
	{17, ASN_COUNTER64, "lostFlows"},
	{18, ASN_COUNTER64, "lostPackets"},
	{19, ASN_COUNTER64, "lostBytes"},
	{20, ASN_COUNTER,   "errTotal"},
	{21, ASN_COUNTER,   "sndbufPeak"},
	{ 0 }
};
#define TOTALS_METRIC_ID 6

static netsnmp_table_data_set *cpu_data_set;
static netsnmp_cache *stat_cache = NULL;

struct snmp_vars cputable[] = {
	{1,  ASN_INTEGER,   "cpuIndex"},
	{2,  ASN_GAUGE,     "cpuInPacketRate"},
	{3,  ASN_COUNTER64, "cpuInFlows"},
	{4,  ASN_COUNTER64, "cpuInPackets"},
	{5,  ASN_COUNTER64, "cpuInBytes"},
	{6,  ASN_GAUGE,     "cpuHashMetric"},
	{7,  ASN_COUNTER64, "cpuDropPackets"},
	{8,  ASN_COUNTER64, "cpuDropBytes"},
	{9,  ASN_COUNTER,   "cpuErrTrunc"},
	{10, ASN_COUNTER,   "cpuErrFrag"},
	{11, ASN_COUNTER,   "cpuErrAlloc"},
	{12, ASN_COUNTER,   "cpuErrMaxflows"},
	{ 0 }
};

static netsnmp_table_data_set *sock_data_set;
struct snmp_vars socktable[] = {
	{1,  ASN_INTEGER,   "sockIndex"},
	{2,  ASN_OCTET_STR, "sockDestination"},
	{3,  ASN_INTEGER,   "sockActive"},
	{4,  ASN_COUNTER,   "sockErrConnect"},
	{5,  ASN_COUNTER,   "sockErrFull"},
	{6,  ASN_COUNTER,   "sockErrCberr"},
	{7,  ASN_COUNTER,   "sockErrOther"},
	{8,  ASN_GAUGE,     "sockSndbuf"},
	{9,  ASN_GAUGE,     "sockSndbufFill"},
	{10, ASN_GAUGE,     "sockSndbufPeak"},
	{ 0 }
};

static time_t totals_ts; /* when statistics last read from kernel */

static int var_max(struct snmp_vars *head)
{
	struct snmp_vars *sys;
	int max = 0;

	for (sys = head; sys->obj; sys++)
		if (max < sys->obj)
			max = sys->obj;
	return max;
}

static struct snmp_vars *find_varinfo(struct snmp_vars *head, const int obj)
{
	struct snmp_vars *sys;

	for (sys = head; sys->obj; sys++) {
		if (sys->obj == obj)
			return sys;
	}
	return NULL;
}

static struct snmp_vars *find_varinfo_str(struct snmp_vars *head, const char *name)
{
	struct snmp_vars *sys;

	for (sys = head; sys->obj; sys++) {
		if (!strcmp(sys->name, name))
			return sys;
	}
	return NULL;
}

static void modinfo_fname(char *name, char *fname, size_t flen)
{
	snprintf(fname, flen, "/sys/module/" MODINFO_NAME "/%s", name);
}

static void sysctl_fname(char *name, char *fname, size_t flen)
{
	snprintf(fname, flen, "/proc/sys/net/netflow/%s", name);
}

static int sysctl_access_ok(char *name)
{
	char fname[64];

	sysctl_fname(name, fname, sizeof(fname));
	if (access(fname, W_OK) < 0)
		return 0;
	return 1;
}

static char *file_read_string(char *name, char *buf, size_t size)
{
	int fd = open(name, O_RDONLY);
	if (fd < 0)
		return NULL;
	int n = read(fd, buf, size - 1);
	if (n < 0) {
		close(fd);
		return NULL;
	}
	buf[n] = '\0';
	close(fd);
	return buf;
}

static char *modinfo_read_string(char *name, char *buf, size_t size)
{
	char fname[64];

	modinfo_fname(name, fname, sizeof(fname));
	return file_read_string(fname, buf, size);
}

static char *sysctl_read_string(char *name, char *buf, size_t size)
{
	char fname[64];

	sysctl_fname(name, fname, sizeof(fname));
	return file_read_string(fname, buf, size);
}

static int sysctl_write_string(char *name, char *buf, size_t size)
{
	char fname[64];
	int fd;
	int n;

	sysctl_fname(name, fname, sizeof(fname));
	fd = open(fname, O_RDWR, 0644);
	if (fd < 0)
		return fd;
	n = write(fd, buf, size);
	close(fd);
	return n;
}

static int sysctl_read(netsnmp_request_info *request, int obj)
{
	struct snmp_vars *sys = find_varinfo(sysctls, obj);
	char buf[225];
	char *p;
	long value;

	if (!sys)
		goto nosuchobject;

	p = sysctl_read_string(sys->name, buf, sizeof(buf));
	if (!p)
		goto nosuchobject;

	switch (sys->type) {
	case ASN_INTEGER:
		value = atoi(p);
		snmp_set_var_typed_value(request->requestvb,
		    sys->type,
		    (u_char *)&value, sizeof(value));
		return SNMP_ERR_NOERROR;
	case ASN_OCTET_STR:
		snmp_set_var_typed_value(request->requestvb,
		    sys->type,
		    (u_char *)p, strcspn(p, "\n"));
		return SNMP_ERR_NOERROR;
	}
nosuchobject:
	netsnmp_request_set_error(request, SNMP_NOSUCHOBJECT);
	return SNMP_ERR_NOERROR;
}

static int sysctl_write(netsnmp_request_info *request, int obj)
{
	struct snmp_vars *sys = find_varinfo(sysctls, obj);
	char buf[225];
	int len;

	if (!sys) {
		netsnmp_request_set_error(request, SNMP_NOSUCHOBJECT);
		return SNMP_ERR_NOERROR;
	}
	switch (sys->type) {
	case ASN_INTEGER:
		snprintf(buf, sizeof(buf), "%ld\n", *(request->requestvb->val.integer));
		break;
	case ASN_UNSIGNED:
		snprintf(buf, sizeof(buf), "%lu\n", *(request->requestvb->val.integer));
		break;
	case ASN_OCTET_STR:
		snprintf(buf, sizeof(buf), "%s\n", request->requestvb->val.string);
		break;
	default:
		netsnmp_request_set_error(request, SNMP_ERR_WRONGTYPE);
		return SNMP_ERR_NOERROR;
	}
	len = strlen(buf);
	if (sysctl_write_string(sys->name, buf, len) < len)
		netsnmp_request_set_error(request, SNMP_ERR_BADVALUE);
	return SNMP_ERR_NOERROR;
}

static int iptNetflowModule_handler(
    netsnmp_mib_handler          *handler,
    netsnmp_handler_registration *reginfo,
    netsnmp_agent_request_info   *reqinfo,
    netsnmp_request_info         *request)
{
	struct snmp_vars *sys;
	oid obj;
	char buf[225];
	char *p = NULL;
	long value;

	obj = request->requestvb->name[request->requestvb->name_length - 2];
	sys = find_varinfo(modinfos, obj);
	if (!sys) {
		netsnmp_request_set_error(request, SNMP_ERR_NOSUCHNAME);
		return SNMP_ERR_NOERROR;
	}
	if (reqinfo->mode != MODE_GET) {
		netsnmp_request_set_error(request, SNMP_ERR_READONLY);
		return SNMP_ERR_NOERROR;
	}
	switch (obj) {
	case MODINFO_NAME_ID:
		p = MODINFO_NAME;
		break;
	case MODINFO_DATE_ID: {
		size_t len;
		struct stat st;

		modinfo_fname(".", buf, sizeof(buf));
		if (stat(buf, &st) < 0)
			break;
		p = (char *)date_n_time(&st.st_mtime, &len);
		snmp_set_var_typed_value(request->requestvb, ASN_OCTET_STR, p, len);
		return SNMP_ERR_NOERROR;
	}
	default:
		p = modinfo_read_string(sys->name, buf, sizeof(buf));
	}
	if (!p) {
		netsnmp_request_set_error(request, SNMP_ERR_NOSUCHNAME);
		return SNMP_ERR_NOERROR;
	}

	switch (sys->type) {
	case ASN_INTEGER:
		value = atoi(p);
		snmp_set_var_typed_value(request->requestvb,
		    sys->type,
		    (u_char *)&value, sizeof(value));
		break;
	case ASN_OCTET_STR:
		snmp_set_var_typed_value(request->requestvb,
		    sys->type,
		    (u_char *)p, strcspn(p, "\n"));
		break;
	default:
		netsnmp_request_set_error(request, SNMP_ERR_WRONGTYPE);

	}
	return SNMP_ERR_NOERROR;
}

static int iptNetflowSysctl_handler(
    netsnmp_mib_handler          *handler,
    netsnmp_handler_registration *reginfo,
    netsnmp_agent_request_info   *reqinfo,
    netsnmp_request_info         *request)
{
	struct snmp_vars *sys;
	oid obj;

	obj = request->requestvb->name[request->requestvb->name_length - 2];
	switch (reqinfo->mode) {
	case MODE_GET:
		return sysctl_read(request, obj);
	case MODE_SET_RESERVE1:
		sys = find_varinfo(sysctls, obj);
		if (request->requestvb->type != sys->type)
			netsnmp_request_set_error(request, SNMP_ERR_WRONGTYPE);
		if (!sysctl_access_ok(sys->name))
			netsnmp_request_set_error(request, SNMP_ERR_NOSUCHNAME);
		break;
	case MODE_SET_RESERVE2:
	case MODE_SET_FREE:
	case MODE_SET_UNDO:
	case MODE_SET_COMMIT:
		return SNMP_ERR_NOERROR;
	case MODE_SET_ACTION:
		return sysctl_write(request, obj);
	default:
		return SNMP_ERR_GENERR;

	}
	return SNMP_ERR_NOERROR;
}

#define TOTAL_INTERVAL 1

static void clear_data_set(netsnmp_table_data_set *data_set)
{
	netsnmp_table_row *row, *nextrow;

	for (row = netsnmp_table_data_set_get_first_row(data_set); row; row = nextrow) {
		nextrow = netsnmp_table_data_set_get_next_row(data_set, row);
		netsnmp_table_dataset_remove_and_delete_row(data_set, row);
	}
}

static void parse_table_row(
    int			    cpu,
    char		    *p,
    struct snmp_vars	    *sys,
    netsnmp_table_data_set  *data_set)
{
	netsnmp_table_row *row;

	row = netsnmp_create_table_data_row();
	netsnmp_table_row_add_index(row, ASN_INTEGER, (u_char *)&cpu, sizeof(cpu));

	if (sys == cputable) {
		/* add cpuIndex as column too to break SMIv2 */
		netsnmp_set_row_column(row, 1, sys->type, (char *)&cpu, sizeof(cpu));
	}
	for (++sys; p && sys->obj; sys++) {
		char		 *val;
		long long	 val64;
		unsigned int	 uval32;
		int		 val32;
		struct counter64 c64;

		p += strspn(p, " \t");
		val = p;
		if ((p = strpbrk(p, " \t")))
			*p++ = '\0';
		if (index(val, '.')) {
			double d = strtod(val, NULL);

			val64 = (long long)(d * 100);
		} else
			val64 = strtoll(val, NULL, 10);

		switch (sys->type) {
		case ASN_OCTET_STR:
			netsnmp_set_row_column(row, sys->obj,
			    sys->type, (char *)val, strlen(val));
			break;
		case ASN_INTEGER:
		case ASN_GAUGE:
			val32 = (int)val64;
			netsnmp_set_row_column(row, sys->obj,
			    sys->type, (char *)&val32, sizeof(val32));
			break;
		case ASN_COUNTER:
			uval32 = (unsigned int)val64;
			netsnmp_set_row_column(row, sys->obj,
			    sys->type, (char *)&uval32, sizeof(uval32));
			break;
		case ASN_COUNTER64:
			c64.low = (uint32_t)val64;
			c64.high = val64 >> 32;
			netsnmp_set_row_column(row, sys->obj,
			    sys->type, (char *)&c64, sizeof(c64));
			break;
		default:
			netsnmp_table_dataset_delete_row(row);
			continue;
		}

	}
	netsnmp_table_data_add_row(data_set->table, row);
}

static void grab_ipt_netflow_snmp(time_t now)
{
	static char buf[4096];
	int fd;
	int n;
	char *p = buf;

	if ((now - totals_ts) < (TOTAL_INTERVAL + 1))
		return;

	if ((fd = open("/proc/net/stat/ipt_netflow_snmp", O_RDONLY)) < 0)
		return;

	n = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (n <= 0)
		return;
	buf[n] = '\0';

	DEBUGMSGTL(("netflow", "%s\n", buf));
	clear_data_set(cpu_data_set);
	clear_data_set(sock_data_set);
	while (*p) {
		struct snmp_vars *sys;
		char *name = p;
		char *val;

		if (!(p = strpbrk(p, " \t")))
			break;
		*p++ = '\0';
		val = p + strspn(p, " \t");
		p = index(p, '\n');
		*p++ = '\0';

		if (!strncmp(name, "cpu", 3)) {
			parse_table_row(atoi(name + 3), val, cputable, cpu_data_set);
			continue;
		} else if (!strncmp(name, "sock", 4)) {
			parse_table_row(atoi(name + 4), val, socktable, sock_data_set);
			continue;
		}
		if (!(sys = find_varinfo_str(totals, name)))
		    continue;
		if (index(val, '.')) {
			double d = strtod(val, NULL);
			sys->val64 = (long long)(d * 100);
		} else
			sys->val64 = strtoll(val, NULL, 10);
		sys->ts = now;
	}
	totals_ts = now;
}

static int iptNetflowTotals_handler(
    netsnmp_mib_handler          *handler,
    netsnmp_handler_registration *reginfo,
    netsnmp_agent_request_info   *reqinfo,
    netsnmp_request_info         *request)
{
	struct snmp_vars *sys;
	time_t now = time(NULL);
	oid obj;
	unsigned int	 uval32;
	int		 val32;
	struct counter64 c64;

	grab_ipt_netflow_snmp(now);

	obj = request->requestvb->name[request->requestvb->name_length - 2];
	sys = find_varinfo(totals, obj);
	if (!sys || ((now - sys->ts) > (TOTAL_INTERVAL * 2 + 3))) {
		netsnmp_request_set_error(request, SNMP_ERR_NOSUCHNAME);
		return SNMP_ERR_NOERROR;
	}
	if (reqinfo->mode != MODE_GET) {
		netsnmp_request_set_error(request, SNMP_ERR_READONLY);
		return SNMP_ERR_NOERROR;
	}
	switch (sys->type) {
	case ASN_GAUGE:
		val32 = (int)sys->val64;
		snmp_set_var_typed_value(request->requestvb,
		    sys->type, (u_char *)&val32, sizeof(val32));
		break;
	case ASN_COUNTER:
		uval32 = (unsigned int)sys->val64;
		snmp_set_var_typed_value(request->requestvb,
		    sys->type, (u_char *)&uval32, sizeof(uval32));
		break;
	case ASN_COUNTER64:
		c64.low = (uint32_t)sys->val64;
		c64.high = sys->val64 >> 32;
		snmp_set_var_typed_value(request->requestvb,
		    ASN_COUNTER64, (u_char *)&c64, sizeof(c64));
		break;
	default:
		return SNMP_ERR_GENERR;
	}
	return SNMP_ERR_NOERROR;
}

static int stat_cache_load(netsnmp_cache *cache, void *x)
{
	grab_ipt_netflow_snmp(time(NULL));
	return 0;
}

static void dummy_cache_free(netsnmp_cache *cache, void *x)
{
	/* free_cache callback is not always checked for NULL
	 * pointer. */
}

void init_netflow(void)
{
	netsnmp_handler_registration *reg;
	struct snmp_vars *sys;

	/* snmpd -f -L -Dnetflow,dlmod */
	DEBUGMSGTL(("netflow", "init_netflow\n"));

	netsnmp_register_scalar_group(
	    netsnmp_create_handler_registration(
		    "iptNetflowModule",
		    iptNetflowModule_handler,
		    iptNetflowModule_oid,
		    OID_LENGTH(iptNetflowModule_oid),
		    HANDLER_CAN_RONLY),
	    1, var_max(modinfos));

	netsnmp_register_scalar_group(
	    netsnmp_create_handler_registration(
		    "iptNetflowSysctl",
		    iptNetflowSysctl_handler,
		    iptNetflowSysctl_oid,
		    OID_LENGTH(iptNetflowSysctl_oid),
		    HANDLER_CAN_RWRITE),
	    1, var_max(sysctls));

	netsnmp_register_scalar_group(
	    netsnmp_create_handler_registration(
		    "iptNetflowTotals",
		    iptNetflowTotals_handler,
		    iptNetflowTotals_oid,
		    OID_LENGTH(iptNetflowTotals_oid),
		    HANDLER_CAN_RONLY),
	    1, var_max(totals));

	/* Register first table. */
	reg = netsnmp_create_handler_registration(
	    "iptNetflowCpuTable", /* no handler */ NULL,
	    iptNetflowCpuTable_oid, OID_LENGTH(iptNetflowCpuTable_oid),
	    HANDLER_CAN_RONLY);

	/* set up columns */
	cpu_data_set = netsnmp_create_table_data_set("iptNetflowCpuDataSet");
	netsnmp_table_set_add_indexes(cpu_data_set, ASN_INTEGER, 0);
	/* I include cpuIndex into columns, which is not SMIv2'ish */
	for (sys = cputable; sys->obj; sys++)
		netsnmp_table_set_add_default_row(cpu_data_set, sys->obj, sys->type, 0, NULL, 0);
	netsnmp_register_table_data_set(reg, cpu_data_set, NULL);

	/* cache handler will load actual data, and it needs to be
	 * injected in front of dataset handler to be called first */
	stat_cache = netsnmp_cache_create(
	    /* no timeout */ -1,
	    stat_cache_load, dummy_cache_free,
	    iptNetflowCpuTable_oid, OID_LENGTH(iptNetflowCpuTable_oid));
	netsnmp_inject_handler(reg, netsnmp_cache_handler_get(stat_cache));

	/* Register second table. */
	reg = netsnmp_create_handler_registration(
	    "iptNetflowSockTable", /* no handler */ NULL,
	    iptNetflowSockTable_oid, OID_LENGTH(iptNetflowSockTable_oid),
	    HANDLER_CAN_RONLY);

	/* set up columns */
	sock_data_set = netsnmp_create_table_data_set("iptNetflowSockDataSet");
	/* I don't include sockIndex into columns, which is more SMIv2'ish */
	netsnmp_table_set_add_indexes(sock_data_set, ASN_INTEGER, 0);
	for (sys = &socktable[1]; sys->obj; sys++)
		netsnmp_table_set_add_default_row(sock_data_set, sys->obj, sys->type, 0, NULL, 0);
	netsnmp_register_table_data_set(reg, sock_data_set, NULL);

	/* as before, cache handler will load actual data, and it needs
	 * to be injected in front of dataset handler to be called first */
	stat_cache = netsnmp_cache_create(
	    /* no timeout */ -1,
	    stat_cache_load, dummy_cache_free,
	    iptNetflowSockTable_oid, OID_LENGTH(iptNetflowSockTable_oid));
	netsnmp_inject_handler(reg, netsnmp_cache_handler_get(stat_cache));
}

void deinit_netflow(void)
{
	DEBUGMSGTL(("netflow", "deinit_netflow\n"));
}

