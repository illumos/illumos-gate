/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

/*
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <alloca.h>
#include <assert.h>
#include <errno.h>
#include <langinfo.h>
#include <libintl.h>
#include <libscf.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <sys/fxpriocntl.h>
#include <sys/priocntl.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <zonestat.h>

extern char *optarg;
extern int optind, opterr, optopt;

#define	ZSTAT_OK		0
#define	ZSTAT_ERROR		1
#define	ZSTAT_USAGE		2

#define	ZSTAT_UNIX_TIMESTAMP	1
#define	ZSTAT_ISO_TIMESTAMP	2
#define	ZSTAT_DATE_TIMESTAMP	3

#define	ZSTAT_RES_PHYSICAL_MEMORY	0x1
#define	ZSTAT_RES_VIRTUAL_MEMORY	0x2
#define	ZSTAT_RES_LOCKED_MEMORY		0x4
#define	ZSTAT_RES_MEMORY		0x7

#define	ZSTAT_RES_DEFAULT_PSET		0x10
#define	ZSTAT_RES_PSETS			0x20
#define	ZSTAT_RES_SUMMARY		0x40

#define	ZSTAT_RES_PROCESSES		0x100
#define	ZSTAT_RES_LWPS			0x200
#define	ZSTAT_RES_LOFI			0x400
#define	ZSTAT_RES_LIMITS		0x700

#define	ZSTAT_RES_SHM_MEMORY		0x1000
#define	ZSTAT_RES_SHM_IDS		0x2000
#define	ZSTAT_RES_SEM_IDS		0x4000
#define	ZSTAT_RES_MSG_IDS		0x8000
#define	ZSTAT_RES_SYSV			0xF000

#define	ZSTAT_RES_ALL			0xF777

#define	ZONESTAT_PHYSICAL_MEMORY	"physical-memory"
#define	ZONESTAT_VIRTUAL_MEMORY		"virtual-memory"
#define	ZONESTAT_LOCKED_MEMORY		"locked-memory"
#define	ZONESTAT_MEMORY			"memory"

#define	ZONESTAT_DEFAULT_PSET		"default-pset"
#define	ZONESTAT_POOL_PSET		"pool-pset"
#define	ZONESTAT_PSRSET_PSET		"psrset-pset"
#define	ZONESTAT_DEDICATED_CPU		"dedicated-cpu"
#define	ZONESTAT_PROCESSOR_SET		"processor-set"
#define	ZONESTAT_PSETS			"psets"
#define	ZONESTAT_SUMMARY		"summary"

#define	ZONESTAT_PROCESSES		"processes"
#define	ZONESTAT_LWPS			"lwps"
#define	ZONESTAT_LOFI			"lofi"
#define	ZONESTAT_LIMITS			"limits"

#define	ZONESTAT_SHM_MEMORY		"shm-memory"
#define	ZONESTAT_SHM_IDS		"shm-ids"
#define	ZONESTAT_SEM_IDS		"sem-ids"
#define	ZONESTAT_MSG_IDS		"msg-ids"
#define	ZONESTAT_SYSV			"sysv"

#define	ZONESTAT_ALL			"all"

#define	ZONESTAT_NAME_MEM_DEFAULT	"mem_default"
#define	ZONESTAT_NAME_VM_DEFAULT	"vm_default"

#define	ZONESTAT_NAME_AVERAGE		"average"
#define	ZONESTAT_NAME_HIGH		"high"

#define	ZONESTAT_NAME_RESOURCE		"resource"
#define	ZONESTAT_NAME_TOTAL		"total"
#define	ZONESTAT_NAME_SYSTEM		"system"
#define	ZONESTAT_NAME_ZONES		"zones"
#define	ZONESTAT_NAME_HEADER		"header"
#define	ZONESTAT_NAME_FOOTER		"footer"

#define	ZONESTAT_NAME_NAME		"name"
#define	ZONESTAT_NAME_USED		"used"
#define	ZONESTAT_NAME_CAP		"cap"
#define	ZONESTAT_NAME_PCAP		"pcap"
#define	ZONESTAT_NAME_SHR		"shr"
#define	ZONESTAT_NAME_PSHRU		"pshru"
#define	ZONESTAT_NAME_CPU		"cpu"
#define	ZONESTAT_NAME_PHYSICAL_MEMORY	ZONESTAT_PHYSICAL_MEMORY
#define	ZONESTAT_NAME_VIRTUAL_MEMORY	ZONESTAT_VIRTUAL_MEMORY

#define	ZONESTAT_NAME_SYSTEM_LIMIT	"system-limit"

#define	ZSTAT_REPORT_FMT_INTERVAL	0
#define	ZSTAT_REPORT_FMT_TOTAL		1
#define	ZSTAT_REPORT_FMT_AVERAGE	2
#define	ZSTAT_REPORT_FMT_HIGH		3
#define	ZSTAT_REPORT_FMT_END		4

#define	ZSTAT_REPORT_TEXT_INTERVAL	"interval"
#define	ZSTAT_REPORT_TEXT_TOTAL		"report-total"
#define	ZSTAT_REPORT_TEXT_AVERAGE	"report-average"
#define	ZSTAT_REPORT_TEXT_HIGH		"report-high"
#define	ZSTAT_REPORT_TEXT_END		"footer"

#define	ZSTAT_DURATION_INF	((int)INT_MAX)
#define	ZSTAT_INTERVAL_DEFAULT	((int)INT_MAX)
#define	ZSTAT_REPORT_END	((int)INT_MAX)

#define	ZSTAT_SORT_CPU		1
#define	ZSTAT_SORT_PHYSICAL	2
#define	ZSTAT_SORT_VIRTUAL	3
#define	ZSTAT_SORT_USED		4
#define	ZSTAT_SORT_CAP		5
#define	ZSTAT_SORT_PCAP		6
#define	ZSTAT_SORT_SHR		7
#define	ZSTAT_SORT_PSHRU	8
#define	ZSTAT_SORT_NAME		9
#define	ZSTAT_SORT_MAX		10

#define	ZSTAT_SUM_MIN_ZONENAME 19
#define	ZSTAT_SUM_HDR_FORMAT "%23s %17s %17s\n"
#define	ZSTAT_SUM_ZONE_FORMAT "%5s %5s %5s %5s %5s %5s %5s %5s %5s %5s\n"

#define	ZSTAT_CPU_MIN_PSETNAME 22
#define	ZSTAT_CPU_MIN_ZONENAME 36
#define	ZSTAT_CPU_RES_FORMAT "%13s  %11s %11s\n"
#define	ZSTAT_CPU_ZONE_FORMAT "%5s %5s %5s %5s %6s %5s %5s\n"

#define	ZSTAT_RESOURCE_MIN_RESNAME 28
#define	ZSTAT_RESOURCE_MIN_ZONENAME 36
#define	ZSTAT_RESOURCE_FORMAT "%13s\n"
#define	ZSTAT_RESOURCE_ZONE_FORMAT "%5s %5s %5s %5s\n"

#define	ZS_UINT64_STRLEN 20
#define	ZS_PCT_STRLEN	10
#define	ZS_TIME_STRLEN	20
#define	ZS_NAME_STRLEN	10

time_t g_now_time;
time_t g_boot_time;
time_t g_start_time;
time_t g_end_time;
int g_interval;
int g_count;
int g_report_count;
time_t g_seconds;

int g_resources;
zs_ctl_t *g_zsctl;
boolean_t g_quit = B_FALSE;
zs_zone_t **g_zone_list;
int g_zone_num;
zs_pset_zone_t **g_pz_list;
int g_pz_num;
zs_pset_t **g_pset_list;
int g_pset_num;
int g_sort_by;
int g_sorts[ZSTAT_SORT_MAX];
int g_sort_summary;
size_t g_max_zonename;

/* Storage for command line arguments. */
char **arg_zonenames;
int arg_zonename_count;
char **arg_resnames;
int arg_resname_count;
char **arg_restypes;
int arg_restype_count;
char ** arg_reports;
int arg_report_count;
char ** arg_sort_list;
int arg_sort_count;
char ** arg_line_list;
int arg_line_count;

time_t arg_starttime;
time_t arg_endtime;
uint_t arg_timestamp = ZSTAT_DATE_TIMESTAMP;
int arg_interval = 5;
int arg_duration = -1;
int arg_report = -1;

/* Options with or as arguments */
boolean_t opt_zonenames = B_FALSE;
boolean_t opt_resnames = B_FALSE;
boolean_t opt_restypes = B_FALSE;
boolean_t opt_start = B_FALSE;
boolean_t opt_end = B_FALSE;
boolean_t opt_in = B_FALSE;
boolean_t opt_out = B_FALSE;
boolean_t opt_timestamp = B_FALSE;
boolean_t opt_report = B_FALSE;
boolean_t opt_sort = B_FALSE;

boolean_t opt_report_high = B_FALSE;
boolean_t opt_report_total = B_FALSE;
boolean_t opt_report_average = B_FALSE;

boolean_t opt_line_resource = B_FALSE;
boolean_t opt_line_total = B_FALSE;
boolean_t opt_line_system = B_FALSE;
boolean_t opt_line_zones = B_FALSE;
boolean_t opt_line_header = B_FALSE;
boolean_t opt_line_any = B_FALSE;

/* Options without arguments */
boolean_t opt_quiet_intervals = B_FALSE;
boolean_t opt_parseable = B_FALSE;
boolean_t opt_debug = B_FALSE;

static int
zonestat_usage(boolean_t explicit)
{
	FILE *fd = explicit ? stdout : stderr;

	(void) fprintf(fd, gettext("Usage:\n"));
	(void) fprintf(fd,
"    zonestat [-z zonelist] [-r reslist] [-n namelist]\n"
"             [-T u | d | i] [-R reports] [-q] [-p [-P lines]] [-S cols]\n"
"             interval [duration [report]]\n"
"\n");
	(void) fprintf(fd, gettext(
"    Options:\n"
"    %s    Report resources of specified types.\n"
"	    Valid resource types are:\n"
"	      \"%s\"\n"
"	      \"%s\"\n"
"	      \"%s\"\n"
"	      \"%s\"\n"
"	      \"%s\", \"%s\", \"%s\"\n"
"	      \"%s\", \"%s\", \"%s\", \"%s\"\n"),
	    "-r",
	    ZONESTAT_VIRTUAL_MEMORY, ZONESTAT_PHYSICAL_MEMORY,
	    ZONESTAT_LOCKED_MEMORY, ZONESTAT_PROCESSOR_SET,
	    ZONESTAT_PROCESSES, ZONESTAT_LWPS, ZONESTAT_LOFI,
	    ZONESTAT_SHM_MEMORY, ZONESTAT_SHM_IDS, ZONESTAT_SEM_IDS,
	    ZONESTAT_MSG_IDS);

	(void) fprintf(fd, gettext(
"	    The following resource nicknames can also be specified:\n"
"	      \"%s\"\n"
"	      \"%s\"\n"
"	      \"%s\"\n"
"	      \"%s\"\n"
"	      \"%s\"\n"
"	      \"%s\"\n"),
	    ZONESTAT_SUMMARY, ZONESTAT_MEMORY, ZONESTAT_PSETS,
	    ZONESTAT_DEFAULT_PSET, ZONESTAT_LIMITS, ZONESTAT_SYSV);
	(void) fprintf(fd, gettext(
"    %s    Report resources used by zones\n"
"    %s    Report resources with specific names.\n"
"	    Valid resource names are:\n"
"	      \"%s\"\n"
"	      \"%s\"\n"
"	      Name of a pool processor set\n"
"	      Id of a processor set created with psrset(1m)\n"
"	      Name of a zone using dedicated-cpu\n"),
	    "-z", "-n",
	    ZONESTAT_NAME_MEM_DEFAULT, ZONESTAT_NAME_VM_DEFAULT);
	(void) fprintf(fd, gettext(
"    %s    Print timestamp. Valid timestamps are:\n"
"	      \"%s\"\tDate as specifed by date(1) command\n"
"	      \"%s\"\tUnix time as returned by time(2)\n"
"	      \"%s\"\tISO 8601 timestamp \"%s\"\n"
"    %s    Print reports at end or after each report interval.\n"
"	    Valid reports are:\n"
"	      \"%s\"\tUsage of each zone\n"
"	      \"%s\"\tUsage of each zone while running\n"
"	      \"%s\"\tMaximum usage of each zone\n"
"    %s    Quiet.  Do not print intervals.  Only print reports.\n"
"    %s    Machine parseable output.\n"),
	    "-T", "d", "u", "i", "YYYYMMDDThhmmssZ",
	    "-R", ZONESTAT_NAME_TOTAL, ZONESTAT_NAME_AVERAGE,
	    ZONESTAT_NAME_HIGH,
	    "-q", "-p");

	(void) fprintf(fd, gettext(
"    %s    Select desired lines in parseable output.\n"
"	      \"%s\"\tLines describing each resource\n"
"	      \"%s\"\tTotal usage of each resource\n"
"	      \"%s\"\tSystem usage of each resource\n"
"	      \"%s\"\tPer-zone usage of each resource\n"
"	      \"%s\"\tHeader lines between intervals and reports\n"),
	    "-P", ZONESTAT_NAME_RESOURCE, ZONESTAT_NAME_TOTAL,
	    ZONESTAT_NAME_SYSTEM, ZONESTAT_NAME_ZONES, ZONESTAT_NAME_HEADER);

	(void) fprintf(fd, gettext(
"    %s    Sort output by the specified columns:\n"
"	      \"%s\"\tby name alphanumerically\n"
"	      \"%s\"\tby percent of resource used\n"
"	      \"%s\"\tby configured cap\n"
"	      \"%s\"\tby percent of cap used\n"
"	      \"%s\"\tby shares configured\n"
"	      \"%s\"\tby percent of share used\n"
"	      \"%s\"\tSort summary by cpu\n"
"	      \"%s\"\tSort summary by physical memory\n"
"	      \"%s\"\tSort summary by virtual memory\n"),
	    "-S", ZONESTAT_NAME_NAME, ZONESTAT_NAME_USED, ZONESTAT_NAME_CAP,
	    ZONESTAT_NAME_PCAP, ZONESTAT_NAME_SHR, ZONESTAT_NAME_PSHRU,
	    ZONESTAT_NAME_CPU, ZONESTAT_NAME_PHYSICAL_MEMORY,
	    ZONESTAT_NAME_VIRTUAL_MEMORY);

	if (!explicit)
		(void) fputs("\n", fd);
	return (ZSTAT_USAGE);
}

/* PRINTFLIKE1 */
static int
zonestat_error(const char *fmt, ...)
{
	va_list alist;

	va_start(alist, fmt);

	(void) fprintf(stderr, "zonestat: Error: ");
	(void) vfprintf(stderr, fmt, alist);
	(void) fprintf(stderr, "\n");
	va_end(alist);
	return (ZSTAT_ERROR);
}

static void
zonestat_determine_lines()
{
	int i;
	boolean_t fail = B_FALSE;

	if (arg_line_count == 0) {
		opt_line_resource = B_TRUE;
		opt_line_total = B_TRUE;
		opt_line_system = B_TRUE;
		opt_line_zones = B_TRUE;
		opt_line_header = B_TRUE;
	}
	for (i = 0; i < arg_line_count; i++) {
		if (strcmp(arg_line_list[i], ZONESTAT_NAME_RESOURCE) == 0)
			opt_line_resource = B_TRUE;
		else if (strcmp(arg_line_list[i], ZONESTAT_NAME_TOTAL) == 0)
			opt_line_total = B_TRUE;
		else if (strcmp(arg_line_list[i], ZONESTAT_NAME_SYSTEM) == 0)
			opt_line_system = B_TRUE;
		else if (strcmp(arg_line_list[i], ZONESTAT_NAME_ZONES) == 0)
			opt_line_zones = B_TRUE;
		else if (strcmp(arg_line_list[i], ZONESTAT_NAME_HEADER) == 0)
			opt_line_header = B_TRUE;
		else {
			(void) zonestat_error(gettext("Unknown -O arg: %s"),
			    arg_line_list[i]);
			fail = B_TRUE;
		}
	}
	if (fail == B_TRUE)
		exit(zonestat_usage(B_FALSE));
}

static void
zonestat_determine_reports()
{
	int i;
	boolean_t fail = B_FALSE;

	for (i = 0; i < arg_report_count; i++) {
		if (strcmp(arg_reports[i], ZONESTAT_NAME_TOTAL) == 0)
			opt_report_total = B_TRUE;
		else if (strcmp(arg_reports[i], ZONESTAT_NAME_AVERAGE) == 0)
			opt_report_average = B_TRUE;
		else if (strcmp(arg_reports[i], ZONESTAT_NAME_HIGH) == 0)
			opt_report_high = B_TRUE;
		else {
			(void) zonestat_error(gettext("Unknown -R arg: %s"),
			    arg_reports[i]);
			fail = B_TRUE;
		}
	}
	if (fail == B_TRUE)
		exit(zonestat_usage(B_FALSE));
}

/*
 * Compares list of -S sort arguments to the list of known sorts.  Only
 * one of cpu, physical memory, and virtual memory can be specified.
 */
static void
zonestat_determine_sort()
{
	int i, count = 0;
	boolean_t fail = B_FALSE;

	if (arg_sort_count == 0) {
		g_sort_summary = ZS_RESOURCE_CPU;
		g_sorts[0] = ZSTAT_SORT_USED;
		g_sorts[1] = ZSTAT_SORT_NAME;
		arg_sort_count = 2;
		return;
	}

	if (arg_sort_count > ZSTAT_SORT_MAX)
		exit(zonestat_error(gettext(
		    "Too many -S sort columns specified")));

	for (i = 0; i < arg_sort_count; i++) {
		if (strcmp(arg_sort_list[i], ZONESTAT_NAME_NAME) == 0)
			g_sorts[count++] = ZSTAT_SORT_NAME;
		else if (strcmp(arg_sort_list[i], ZONESTAT_NAME_USED) == 0)
			g_sorts[count++] = ZSTAT_SORT_USED;
		else if (strcmp(arg_sort_list[i], ZONESTAT_NAME_CAP) == 0)
			g_sorts[count++] = ZSTAT_SORT_CAP;
		else if (strcmp(arg_sort_list[i], ZONESTAT_NAME_PCAP) == 0)
			g_sorts[count++] = ZSTAT_SORT_PCAP;
		else if (strcmp(arg_sort_list[i], ZONESTAT_NAME_SHR) == 0)
			g_sorts[count++] = ZSTAT_SORT_SHR;
		else if (strcmp(arg_sort_list[i], ZONESTAT_NAME_PSHRU) == 0)
			g_sorts[count++] = ZSTAT_SORT_PSHRU;
		else if (strcmp(arg_sort_list[i], ZONESTAT_NAME_CPU) == 0) {
			if (g_sort_summary != 0)
				fail = B_TRUE;
			g_sort_summary = ZS_RESOURCE_CPU;
		} else if (strcmp(arg_sort_list[i],
		    ZONESTAT_NAME_PHYSICAL_MEMORY) == 0) {
			if (g_sort_summary != 0)
				fail = B_TRUE;
			g_sort_summary = ZS_RESOURCE_RAM_RSS;
		} else if (strcmp(arg_sort_list[i],
		    ZONESTAT_NAME_VIRTUAL_MEMORY) == 0) {
			if (g_sort_summary != 0)
				fail = B_TRUE;
			g_sort_summary = ZS_RESOURCE_VM;
		} else {
			(void) zonestat_error(gettext("Unknown -S arg: %s"),
			    arg_sort_list[i]);
			fail = B_TRUE;
		}
	}
	if (g_sort_summary == 0)
		g_sort_summary = ZS_RESOURCE_CPU;

	if (fail == B_TRUE) {
		(void) zonestat_error(gettext(
		    "-S: only one of \"%s\", \"%s\", or "
		    "\"%s\" permitted"), "-S", ZONESTAT_NAME_CPU,
		    ZONESTAT_NAME_PHYSICAL_MEMORY,
		    ZONESTAT_NAME_VIRTUAL_MEMORY);
		exit(zonestat_usage(B_FALSE));
	}
}

typedef struct zonestat_resource_struct {
	char *zr_name;
	uint_t zr_flag;
} zonestat_resource_t;


/* Used to map resource name strings to resource flags */
zonestat_resource_t g_resource_list[] = {
	ZONESTAT_PHYSICAL_MEMORY, ZSTAT_RES_PHYSICAL_MEMORY,
	ZONESTAT_VIRTUAL_MEMORY, ZSTAT_RES_VIRTUAL_MEMORY,
	ZONESTAT_LOCKED_MEMORY, ZSTAT_RES_LOCKED_MEMORY,
	ZONESTAT_MEMORY, ZSTAT_RES_MEMORY,
	ZONESTAT_PROCESSOR_SET, ZSTAT_RES_PSETS,
	ZONESTAT_PSETS, ZSTAT_RES_PSETS,
	ZONESTAT_DEFAULT_PSET, ZSTAT_RES_DEFAULT_PSET,
	ZONESTAT_PROCESSES, ZSTAT_RES_PROCESSES,
	ZONESTAT_LWPS, ZSTAT_RES_LWPS,
	ZONESTAT_LOFI, ZSTAT_RES_LOFI,
	ZONESTAT_LIMITS, ZSTAT_RES_LIMITS,
	ZONESTAT_SHM_MEMORY, ZSTAT_RES_SHM_MEMORY,
	ZONESTAT_SHM_IDS, ZSTAT_RES_SHM_IDS,
	ZONESTAT_SEM_IDS, ZSTAT_RES_SEM_IDS,
	ZONESTAT_MSG_IDS, ZSTAT_RES_MSG_IDS,
	ZONESTAT_SYSV, ZSTAT_RES_SYSV,
	ZONESTAT_SUMMARY, ZSTAT_RES_SUMMARY,
	ZONESTAT_ALL, ZSTAT_RES_ALL
};

/*
 * Compares list of resources passed to -r to the known list of
 * resources.
 */
static void
zonestat_determine_resources()
{
	int i, j, count;
	boolean_t found, fail = B_FALSE;

	if (arg_restype_count == 0) {
		g_resources = ZSTAT_RES_SUMMARY;
		return;
	}

	count = sizeof (g_resource_list) / sizeof (zonestat_resource_t);

	for (i = 0; i < arg_restype_count; i++) {
		found = B_FALSE;
		for (j = 0; j < count; j++) {
			if (strcmp(arg_restypes[i], g_resource_list[j].zr_name)
			    == 0) {
				g_resources |= g_resource_list[j].zr_flag;
				found = B_TRUE;
				break;
			}
		}
		if (found == B_FALSE) {
			(void) zonestat_error(gettext("Unknown resource: %s"),
			    arg_restypes[i]);
			fail = B_TRUE;
		}
	}
	if (fail == B_TRUE)
		exit(zonestat_usage(B_FALSE));
}

/*
 * Returns 1 if the name matches one of the specified zone names.  0
 * otherwise.  Always matches if no zone names were specified.
 */
static int
zonestat_match_zonename(char *name)
{
	int i;

	if (arg_zonename_count == 0)
		return (1);
	for (i = 0; i < arg_zonename_count; i++) {
		if (strcmp(name, arg_zonenames[i]) == 0)
			return (1);
	}
	return (0);
}

/*
 * compare name to base, ignoring prefix on name.
 */
static int
zonestat_match_with_prefix(char *prefix, char *name, char *base)
{
	size_t prefix_len;

	prefix_len = strlen(prefix);
	if (strncmp(name, prefix, prefix_len) == 0) {
		name += prefix_len;
		if (strcmp(name, base) == 0)
			return (1);
	}
	return (0);
}
/*
 * Returns 1 if the resource matches one of the specified resource names.  0
 * otherwise.  Always matches if no resource names were specified.
 */
static int
zonestat_match_resname(char *name)
{
	int i;

	if (arg_resname_count == 0)
		return (1);
	for (i = 0; i < arg_resname_count; i++) {

		if (strcmp(name, arg_resnames[i]) == 0)
			return (1);

		if (zonestat_match_with_prefix("SUNWtmp_", name,
		    arg_resnames[i]))
			return (1);

		if (zonestat_match_with_prefix("SUNWlegacy_pset_", name,
		    arg_resnames[i]))
			return (1);
	}
	return (0);
}

/*
 * Format unsigned uint64_t
 *
 * 9999  9999
 * 99.9K 99999
 * 9999K 9999999
 * 99.9M 99999999
 * 9999M 9999999999
 * 99.9G 99999999999
 * 9999G 9999999999999
 * 99.9T 99999999999999
 * 9999T 9999999999999999
 * 99.9P 99999999999999999
 * 9999P 9999999999999999999
 * 99.9E UINT64_MAX
 */
static void
format_uint64(uint64_t val, char *str, size_t len)
{
	uint64_t high;
	uint64_t low;

	if (val == UINT64_MAX) {
		(void) snprintf(str, len, "-");
		return;
	}
	if (val <= 9999) {
		(void) snprintf(str, len, "%llu", val);
		return;
	}
	if (val <= 99999) {
		high = val / 1024;
		low = val * 10 / 1024 - (high * 10);
		(void) snprintf(str, len, "%llu%1.1lluK", high, low);
		return;
	}
	val = val / 1024;
	if (val <= 9999 || opt_parseable) {
		high = val;
		(void) snprintf(str, len, "%lluK", high);
		return;
	}
	if (val <= 99999) {
		high = val / 1024;
		low = val * 10 / 1024 - (high * 10);
		(void) snprintf(str, len, "%llu.%1.1lluM", high, low);
		return;
	}
	val = val / 1024;
	if (val <= 9999) {
		high = val;
		(void) snprintf(str, len, "%lluM", high);
		return;
	}
	if (val <= 99999) {
		high = val / 1024;
		low = val * 10 / 1024 - (high * 10);
		(void) snprintf(str, len, "%llu.%1.1lluG", high, low);
		return;
	}
	val = val / 1024;
	if (val <= 9999) {
		high = val;
		(void) snprintf(str, len, "%lluG", high);
		return;
	}
	if (val <= 99999) {
		high = val / 1024;
		low = val * 10 / 1024 - (high * 10);
		(void) snprintf(str, len, "%llu.%1.1lluT", high, low);
		return;
	}
	val = val / 1024;
	if (val <= 9999) {
		high = val;
		(void) snprintf(str, len, "%lluT", high);
		return;
	}
	if (val <= 99999) {
		high = val / 1024;
		low = val * 10 / 1024 - (high * 10);
		(void) snprintf(str, len, "%llu.%1.1lluP", high, low);
		return;
	}
	val = val / 1024;
	if (val <= 9999) {
		high = val;
		(void) snprintf(str, len, "%lluP", high);
		return;
	}
	high = val / 1024;
	low = val * 10 / 1024 - (high * 10);
	(void) snprintf(str, len, "%llu.%1.1lluE", high, low);
}


static void
format_pct(uint_t pct, char *str, size_t len)
{
	uint_t high;
	uint_t low;

	if (pct == ZS_PCT_NONE) {
		(void) snprintf(str, len, "-");
		return;
	}
	/*
	 * pct's are printed as one of:
	 *	#.##%
	 *	##.#%
	 *	 ###%
	 *	####%
	 *
	 * The value is fixed decimal.  10000 equals 100.00 percent.
	 * Percents can exceed 100.00 percent.  Percents greater than
	 * 9999% will exceed the 5 column width.
	 */
	if (pct <= 999 || opt_parseable) {
		high = pct / 100;
		low = pct - (high * 100);
		(void) snprintf(str, len, "%u.%2.2u%%", high, low);
	} else if (pct <= 9999) {
		pct = pct / 10;
		high = pct / 10;
		low = pct - (high * 10);
		(void) snprintf(str, len, "%u.%1.1u%%", high, low);
	} else {
		pct = pct / 100;
		(void) snprintf(str, len, "%u%%", pct);
	}
}
/*
 * Cpu cap is 100 times the number of cpus allocated.  It is formatted as a
 * decimal.  Example, a cpu-cap of 50 is 0.50 cpus.
 *
 * The cpu cap value can go up to UINT_MAX, so handle all cases even though
 * the higher ones are nonsense.
 *
 * Format  Max cpu-cap value for format.
 * 42.9M   4294967296
 * 9999K   999999999
 * 99.9K   9999999
 *  9999   999999
 * 999.9   99999
 *  9.99   999
 */
void
format_cpu(uint64_t cpu, char *str, size_t len)
{

	uint64_t high;
	uint64_t low;

	/* #.## cpus */
	if (cpu <= 999 || opt_parseable) {
		high = cpu / 100;
		low = cpu - (high * 100);
		(void) snprintf(str, len, "%llu.%2.2llu", high, low);
		return;
	}
	/* ##.# cpus */
	if (cpu <= 99999) {
		high = cpu / 100;
		low = cpu - (high * 100);
		(void) snprintf(str, len, "%llu.%1.1llu", high, low);
		return;
	}
	/* #### cpus */
	if (cpu <= 999999) {
		cpu = cpu / 100;
		(void) snprintf(str, len, "%llu", cpu);
		return;
	}
	/* ##.#K cpus */
	cpu = cpu / 1000;
	if (cpu <= 99999) {
		high = cpu / 100;
		low = cpu - (high * 100);
		(void) snprintf(str, len, "%llu.%1.1lluK", high, low);
		return;
	}
	/* ####K cpus */
	if (cpu <= 999999) {
		cpu = cpu / 100;
		(void) snprintf(str, len, "%lluK", cpu);
		return;
	}
	/* ##.#M cpus */
	cpu = cpu / 1000;
	if (cpu <= UINT_MAX) {
		high = cpu / 100;
		low = cpu - (high * 100);
		(void) snprintf(str, len, "%llu.%1.1lluM", high, low);
		return;
	}
	(void) snprintf(str, len, "error", high, low);
}

/*
 * Format a timetruct as:
 * HH:MM:SS.SS
 *
 * Human readable format omits the fractional seconds.
 */
static void
format_ts(timestruc_t *ts, char *str, size_t len, boolean_t human_readable)
{
	uint64_t secs, mins, hours, pct;

	hours = 0;
	mins = 0;

	secs = ts->tv_sec;
	pct = ts->tv_nsec / 1000 / 1000 / 10;
	while (pct >= 100) {
		pct -= 100;
		secs++;
	}
	if (secs >= 60) {
		mins = secs / 60;
		secs = secs % 60;
	}
	if (mins >= 60) {
		hours = mins / 60;
		mins = mins % 60;
	}
	if (human_readable)
		(void) snprintf(str, len, "%llu:%2.2llu:%2.2llu", hours,
		    mins, secs);
	else
		(void) snprintf(str, len, "%llu-%2.2llu-%2.2llu.%2.2llu", hours,
		    mins, secs, pct);
}

char *g_report_formats[] = {
	ZSTAT_REPORT_TEXT_INTERVAL,
	ZSTAT_REPORT_TEXT_TOTAL,
	ZSTAT_REPORT_TEXT_AVERAGE,
	ZSTAT_REPORT_TEXT_HIGH,
	ZSTAT_REPORT_TEXT_END
};

/* Get the label for the current report type */
static char *
zonestat_get_plabel(int format)
{
	if (format >= sizeof (g_report_formats) / sizeof (char *))
		exit(zonestat_error(gettext(
		    "Internal error, invalid report format")));

	return (g_report_formats[format]);
}

#define	ZSTAT_CPULINE "----------CPU----------"
#define	ZSTAT_MEMLINE "----PHYSICAL-----"
#define	ZSTAT_VMLINE  "-----VIRTUAL-----"

static void
zonestat_print_summary_header(size_t namewidth, int report_fmt, uint64_t cpu,
    uint64_t online, uint64_t mem, uint64_t vm)
{
	char str_cpu[ZS_UINT64_STRLEN];
	char str_online[ZS_UINT64_STRLEN];
	char str_mem[ZS_UINT64_STRLEN];
	char str_vm[ZS_UINT64_STRLEN];
	char name_format[ZS_NAME_STRLEN];
	char tot_cpu[sizeof (ZSTAT_CPULINE)];
	char tot_mem[sizeof (ZSTAT_MEMLINE)];
	char tot_vm[sizeof (ZSTAT_VMLINE)];

	char *label;

	format_uint64(cpu, str_cpu, sizeof (str_cpu));
	format_uint64(online, str_online, sizeof (str_online));
	format_uint64(mem, str_mem, sizeof (str_mem));
	format_uint64(vm, str_vm, sizeof (str_vm));

	if (opt_parseable) {
		label = zonestat_get_plabel(report_fmt);
		(void) printf("%s:%s:[%s]:%s:%s:%s:%s\n", label,
		    ZONESTAT_SUMMARY, ZONESTAT_NAME_RESOURCE, str_cpu,
		    str_online, str_mem, str_vm);
		return;
	}

	(void) snprintf(tot_cpu, sizeof (tot_cpu), "Cpus/Online: %s/%s",
	    str_cpu, str_online);

	(void) snprintf(tot_mem, sizeof (tot_mem), "Physical: %s", str_mem);

	(void) snprintf(tot_vm, sizeof (tot_vm), "Virtual: %s", str_vm);

	/* Make first column as wide as longest zonename */
	(void) snprintf(name_format, sizeof (name_format), "%%-%ds ",
	    namewidth);
	/* LINTED */
	(void) printf(name_format, "SUMMARY");
	(void) printf(ZSTAT_SUM_HDR_FORMAT, tot_cpu, tot_mem,
	    tot_vm);

	/* LINTED */
	(void) printf(name_format, "");
	(void) printf(ZSTAT_SUM_HDR_FORMAT, ZSTAT_CPULINE,
	    ZSTAT_MEMLINE, ZSTAT_VMLINE);

	(void) snprintf(name_format, sizeof (name_format), "%%%ds ",
	    namewidth);
	/* LINTED */
	(void) printf(name_format, "ZONE");

	(void) printf(ZSTAT_SUM_ZONE_FORMAT, "USED", "%PART", "%CAP",
	    "%SHRU", "USED", "PCT", "%CAP", "USED", "PCT", "%CAP");
}

static void
zonestat_print_resource__header(size_t namelen, char *restype, char *size)
{
	char name_format[ZS_NAME_STRLEN];

	if (opt_parseable)
		return;

	(void) snprintf(name_format, sizeof (name_format), "%%-%ds ", namelen);
	/* LINTED */
	(void) printf(name_format, restype);
	(void) printf(ZSTAT_RESOURCE_FORMAT, size);
}

static void
zonestat_print_resource_zone_header(size_t namelen)
{
	char name_format[ZS_NAME_STRLEN];

	if (opt_parseable)
		return;

	(void) snprintf(name_format, sizeof (name_format), "%%%ds ", namelen);
	/* LINTED */
	(void) printf(name_format, "ZONE");

	(void) printf(ZSTAT_RESOURCE_ZONE_FORMAT, "USED", "PCT", "CAP", "%CAP");
}

static void
zonestat_print_timestamp(time_t t)
{
	static char *fmt = NULL;
	int len;
	char dstr[64];

	/* We only need to retrieve this once per invocation */

	if (arg_timestamp == ZSTAT_UNIX_TIMESTAMP) {
		(void) printf("%ld", t);
	} else if (arg_timestamp == ZSTAT_ISO_TIMESTAMP) {

		len = strftime(dstr, sizeof (dstr), "%Y%m%dT%H%M%SZ",
		    gmtime(&t));
		if (len > 0)
			(void) printf("%s", dstr);

	} else {

		if (fmt == NULL)
			fmt = nl_langinfo(_DATE_FMT);

		len = strftime(dstr, sizeof (dstr), fmt, localtime(&t));
		if (len > 0)
			(void) printf("%s", dstr);
	}
}

static void
zonestat_print_summary_zone(size_t namewidth, int report_fmt, char *name,
    uint64_t cused, uint_t ppart, uint_t pccap, uint_t pshru, uint64_t mused,
    uint_t mpct, uint_t pmcap, uint64_t vused, uint_t vpct, uint_t pvcap)
{
	char *label;

	char str_cused[ZS_UINT64_STRLEN];
	char str_ppart[ZS_PCT_STRLEN];
	char str_pccap[ZS_PCT_STRLEN];
	char str_pshru[ZS_PCT_STRLEN];
	char str_mused[ZS_UINT64_STRLEN];
	char str_mpct[ZS_PCT_STRLEN];
	char str_pmcap[ZS_PCT_STRLEN];
	char str_vused[ZS_UINT64_STRLEN];
	char str_vpct[ZS_PCT_STRLEN];
	char str_pvcap[ZS_PCT_STRLEN];
	char name_format[ZS_NAME_STRLEN];

	format_cpu(cused, str_cused, sizeof (str_cused));
	format_pct(ppart, str_ppart, sizeof (str_ppart));
	format_pct(pccap, str_pccap, sizeof (str_pccap));
	format_pct(pshru, str_pshru, sizeof (str_pshru));
	format_uint64(mused, str_mused, sizeof (str_mused));
	format_pct(mpct, str_mpct, sizeof (str_mpct));
	format_pct(pmcap, str_pmcap, sizeof (str_pmcap));
	format_uint64(vused, str_vused, sizeof (str_vused));
	format_pct(vpct, str_vpct, sizeof (str_vpct));
	format_pct(pvcap, str_pvcap, sizeof (str_pvcap));

	if (opt_parseable) {
		if (opt_timestamp) {
			zonestat_print_timestamp(g_now_time);
			(void) printf(":");
		}
		label = zonestat_get_plabel(report_fmt);
		(void) printf("%s:%s:%s:%s:%s:%s:%s:%s:%s:%s:%s:%s:%s\n",
		    label, ZONESTAT_SUMMARY, name, str_cused, str_ppart,
		    str_pccap, str_pshru, str_mused, str_mpct, str_pmcap,
		    str_vused, str_vpct, str_pvcap);
		return;
	}
	(void) snprintf(name_format, sizeof (name_format), "%%%ds ",
	    namewidth);
	/* LINTED */
	(void) printf(name_format, name);
	(void) printf(ZSTAT_SUM_ZONE_FORMAT, str_cused, str_ppart,
	    str_pccap, str_pshru, str_mused, str_mpct, str_pmcap, str_vused,
	    str_vpct, str_pvcap);
}

static void
zonestat_print_resource_(size_t namelen, int report_fmt, char *res,
    char *name, uint64_t size)
{
	char strsize[ZS_UINT64_STRLEN];
	char *label;
	char name_format[ZS_NAME_STRLEN];

	format_uint64(size, strsize, sizeof (strsize));
	if (opt_parseable) {
		if (opt_timestamp) {
			zonestat_print_timestamp(g_now_time);
			(void) printf(":");
		}
		label = zonestat_get_plabel(report_fmt);
		(void) printf("%s:%s:%s:[%s]:%s\n", label, res, name,
		    ZONESTAT_NAME_RESOURCE, strsize);
		return;
	}

	(void) snprintf(name_format, sizeof (name_format), "%%-%ds ", namelen);
	/* LINTED */
	(void) printf(name_format, name);
	(void) printf(ZSTAT_RESOURCE_FORMAT, strsize);
}

static void
zonestat_print_resource_zone(size_t namelen, int report_fmt, char *restype,
    char *resname, char *name, uint64_t used, uint_t pct, uint64_t cap,
    uint_t pctcap)
{
	char strused[ZS_UINT64_STRLEN];
	char strpct[ZS_PCT_STRLEN];
	char strcap[ZS_UINT64_STRLEN];
	char strpctcap[ZS_PCT_STRLEN];
	char name_format[ZS_NAME_STRLEN];

	char *label;

	format_uint64(used, strused, sizeof (strused));
	format_pct(pct, strpct, sizeof (strpct));
	if (cap == ZS_LIMIT_NONE)
		(void) strlcpy(strcap, "-", sizeof (strcap));
	else
		format_uint64(cap, strcap, sizeof (strcap));

	if (pctcap == ZS_PCT_NONE)
		(void) strlcpy(strpctcap, "-", sizeof (strpctcap));
	else
		format_pct(pctcap, strpctcap, sizeof (strpctcap));

	if (opt_parseable) {
		if (opt_timestamp) {
			zonestat_print_timestamp(g_now_time);
			(void) printf(":");
		}
		label = zonestat_get_plabel(report_fmt);
		(void) printf("%s:%s:%s:%s:%s:%s:%s:%s\n", label, restype,
		    resname, name, strused, strpct, strcap, strpctcap);
		return;
	}

	(void) snprintf(name_format, sizeof (name_format), "%%%ds ", namelen);
	/* LINTED */
	(void) printf(name_format, name);
	(void) printf(ZSTAT_RESOURCE_ZONE_FORMAT, strused, strpct, strcap,
	    strpctcap);
}

/*
 * Not thread safe.
 */
static void
zonestat_qsort(void *base, size_t nel, size_t width,
    int (*compar)(const void *, const void *), int by)
{
	g_sort_by = by;
	g_max_zonename = 0;
	qsort(base, nel, width, compar);
}

static int
zonestat_zone_compare_resource(const void *a, const void *b)
{
	zs_zone_t *zonea = *(zs_zone_t **)a;
	zs_zone_t *zoneb = *(zs_zone_t **)b;
	zs_property_t *prop, *propb;
	uint64_t resa, resb;
	uint_t uinta, uintb;
	int i, res;

	prop = alloca(zs_property_size());
	propb = alloca(zs_property_size());

	for (i = 0; i < arg_sort_count; i++) {

		/* Sort by order of selection */
		switch (g_sorts[i]) {
		case ZSTAT_SORT_USED:
			resa = zs_resource_used_zone_uint64(zonea, g_sort_by);
			resb = zs_resource_used_zone_uint64(zoneb, g_sort_by);
			break;
		case ZSTAT_SORT_CAP:
			resa = zs_zone_limit_uint64(zonea, g_sort_by);
			if (resa == ZS_LIMIT_NONE)
				resa = 0;
			resb = zs_zone_limit_uint64(zoneb, g_sort_by);
			if (resb == ZS_LIMIT_NONE)
				resb = 0;
			break;
		case ZSTAT_SORT_PCAP:
			uinta = zs_zone_limit_used_pct(zonea, g_sort_by);
			uintb = zs_zone_limit_used_pct(zoneb, g_sort_by);
			if (uinta == ZS_PCT_NONE)
				resa = 0;
			else
				resa = uinta;
			if (uintb == ZS_PCT_NONE)
				resb = 0;
			else
				resb = uintb;
			break;
		case ZSTAT_SORT_SHR:
			zs_zone_property(zonea, ZS_PZ_PROP_CPU_SHARES, prop);
			resa = zs_property_uint64(prop);
			if (resa == ZS_LIMIT_NONE)
				resa = 0;
			zs_zone_property(zoneb, ZS_PZ_PROP_CPU_SHARES, prop);
			resb = zs_property_uint64(prop);
			if (resb == ZS_LIMIT_NONE)
				resb = 0;
			break;
		case ZSTAT_SORT_PSHRU:
			uinta = zs_zone_limit_used_pct(zonea,
			    ZS_LIMIT_CPU_SHARES);
			uintb = zs_zone_limit_used_pct(zoneb,
			    ZS_LIMIT_CPU_SHARES);
			if (uinta == ZS_PCT_NONE)
				resa = 0;
			else
				resa = uinta;
			if (uintb == ZS_PCT_NONE)
				resb = 0;
			else
				resb = uintb;
			break;
		case ZSTAT_SORT_NAME:
			zs_zone_property(zonea, ZS_ZONE_PROP_NAME, prop);
			zs_zone_property(zoneb, ZS_ZONE_PROP_NAME, propb);

			res = strcmp(zs_property_string(prop),
			    zs_property_string(propb));
			if (res != 0)
				return (res);
			break;
		default:
			exit(zonestat_error(gettext("Internal sort error")));
		}
		if (resa < resb)
			return (1);
		if (resb < resa)
			return (-1);
	}
	/* No difference, return 0 */
	return (0);
}
/*
 * Sort psets.  Default pset first, then shared psets, then dedicated
 * psets.
 */
static int
zonestat_pset_compare(const void *a, const void *b)
{
	zs_pset_t *pseta = *(zs_pset_t **)a;
	zs_pset_t *psetb = *(zs_pset_t **)b;
	zs_property_t *p;
	uint_t typea, typeb;


	p = (zs_property_t *)alloca(zs_property_size());
	zs_pset_property(pseta, ZS_PSET_PROP_CPUTYPE, p);
	typea = zs_property_uint(p);
	zs_pset_property(psetb, ZS_PSET_PROP_CPUTYPE, p);
	typeb = zs_property_uint(p);

	if (typea == ZS_CPUTYPE_DEFAULT_PSET)
		return (-1);
	if (typeb == ZS_CPUTYPE_DEFAULT_PSET)
		return (1);
	if (typea == ZS_CPUTYPE_POOL_PSET)
		return (-1);
	if (typeb == ZS_CPUTYPE_POOL_PSET)
		return (1);
	if (typea == ZS_CPUTYPE_PSRSET_PSET)
		return (-1);
	if (typeb == ZS_CPUTYPE_PSRSET_PSET)
		return (1);

	return (0);
}

static int
zonestat_pz_compare_usage(const void *a, const void *b)
{
	zs_pset_zone_t *zonea = *(zs_pset_zone_t **)a;
	zs_pset_zone_t *zoneb = *(zs_pset_zone_t **)b;
	zs_property_t *prop, *propb;
	uint64_t resa, resb;
	uint_t uinta, uintb;
	int i, res;

	prop = alloca(zs_property_size());
	propb = alloca(zs_property_size());

	for (i = 0; i < arg_sort_count; i++) {

		/* Sort by order of selection */
		switch (g_sorts[i]) {
		case ZSTAT_SORT_USED:
			resa = zs_pset_zone_used_cpus(zonea);
			resb = zs_pset_zone_used_cpus(zoneb);
			break;
		case ZSTAT_SORT_CAP:
			zs_pset_zone_property(zonea, ZS_PZ_PROP_CPU_CAP,
			    prop);
			resa = zs_property_uint64(prop);
			if (resa == ZS_LIMIT_NONE)
				resa = 0;
			zs_pset_zone_property(zoneb, ZS_PZ_PROP_CPU_CAP,
			    prop);
			resb = zs_property_uint64(prop);
			if (resb == ZS_LIMIT_NONE)
				resb = 0;
			break;
		case ZSTAT_SORT_PCAP:
			uinta = zs_pset_zone_used_pct(zonea, ZS_PZ_PCT_CPU_CAP);
			uintb = zs_pset_zone_used_pct(zoneb, ZS_PZ_PCT_CPU_CAP);
			if (uinta == ZS_PCT_NONE)
				resa = 0;
			else
				resa = uinta;
			if (uintb == ZS_PCT_NONE)
				resb = 0;
			else
				resb = uintb;
			break;
		case ZSTAT_SORT_SHR:
			zs_pset_zone_property(zonea, ZS_PZ_PROP_CPU_SHARES,
			    prop);
			resa = zs_property_uint64(prop);
			if (resa == ZS_LIMIT_NONE)
				resa = 0;
			zs_pset_zone_property(zoneb, ZS_PZ_PROP_CPU_SHARES,
			    prop);
			resb = zs_property_uint64(prop);
			if (resb == ZS_LIMIT_NONE)
				resb = 0;
			break;
		case ZSTAT_SORT_PSHRU:
			uinta = zs_pset_zone_used_pct(zonea,
			    ZS_PZ_PCT_CPU_SHARES);
			uintb = zs_pset_zone_used_pct(zoneb,
			    ZS_PZ_PCT_CPU_SHARES);
			if (uinta == ZS_PCT_NONE)
				resa = 0;
			else
				resa = uinta;
			if (uintb == ZS_PCT_NONE)
				resb = 0;
			else
				resb = uintb;
			break;
		case ZSTAT_SORT_NAME:
			zs_zone_property(zs_pset_zone_get_zone(zonea),
			    ZS_ZONE_PROP_NAME, prop);
			zs_zone_property(zs_pset_zone_get_zone(zoneb),
			    ZS_ZONE_PROP_NAME, propb);

			res = strcmp(zs_property_string(prop),
			    zs_property_string(propb));
			if (res != 0)
				return (res);
			break;
		default:
			exit(zonestat_error(gettext("Internal sort error")));
		}
		if (resa < resb)
			return (1);
		if (resb < resa)
			return (-1);
	}
	/* No difference, return 0 */
	return (0);
}


static void
zonestat_print_summary(int report_fmt, zs_usage_t *u)
{
	int num, i;
	zs_zone_t *z;
	uint64_t cpus, online, tot_mem, tot_vm;
	uint64_t cused, mused, vused;
	uint_t ppart, pshru, pccap, mpct, pmcap, vpct, pvcap;
	char zonename[ZS_ZONENAME_MAX];
	zs_property_t *prop;
	size_t namewidth = 0, len;

	prop = (zs_property_t *)alloca(zs_property_size());

	zs_resource_property(u, ZS_RESOURCE_CPU, ZS_RESOURCE_PROP_CPU_TOTAL,
	    prop);
	cpus = zs_property_uint64(prop);

	zs_resource_property(u, ZS_RESOURCE_CPU,
	    ZS_RESOURCE_PROP_CPU_ONLINE, prop);
	online = zs_property_uint64(prop);

	tot_mem = zs_resource_total_uint64(u, ZS_RESOURCE_RAM_RSS);
	tot_vm = zs_resource_total_uint64(u, ZS_RESOURCE_VM);

again:
	num = zs_zone_list(u, g_zone_list, g_zone_num);
	if (num > g_zone_num) {
		if (g_zone_list != NULL)
			free(g_zone_list);
		g_zone_list = (zs_zone_t **) malloc(sizeof (zs_zone_t *) * num);
		g_zone_num = num;
		goto again;
	}

	/* Find the longest zone name to set output width. */
	namewidth = ZSTAT_SUM_MIN_ZONENAME;
	for (i = 0; i < num; i++) {
		z = g_zone_list[i];
		(void) zs_zone_property(z, ZS_ZONE_PROP_NAME, prop);
		len = strlen(zs_property_string(prop));
		if (len > namewidth)
			namewidth = len;
	}
	zonestat_print_summary_header(namewidth, report_fmt, cpus, online,
	    tot_mem, tot_vm);

	zonestat_qsort(g_zone_list, num, sizeof (zs_zone_t *),
	    zonestat_zone_compare_resource, g_sort_summary);

	cused = zs_resource_used_uint64(u, ZS_RESOURCE_CPU, ZS_USER_ALL);
	mused = zs_resource_used_uint64(u, ZS_RESOURCE_RAM_RSS, ZS_USER_ALL);
	vused = zs_resource_used_uint64(u, ZS_RESOURCE_VM, ZS_USER_ALL);

	ppart = zs_resource_used_pct(u, ZS_RESOURCE_CPU, ZS_USER_ALL);
	mpct = zs_resource_used_pct(u, ZS_RESOURCE_RAM_RSS, ZS_USER_ALL);
	vpct = zs_resource_used_pct(u, ZS_RESOURCE_VM, ZS_USER_ALL);

	if (opt_line_total) {
		(void) snprintf(zonename, sizeof (zonename), "[%s]",
		    ZONESTAT_NAME_TOTAL);
		zonestat_print_summary_zone(namewidth, report_fmt, zonename,
		    cused, ppart, ZS_PCT_NONE, ZS_PCT_NONE, mused, mpct,
		    ZS_PCT_NONE, vused, vpct, ZS_PCT_NONE);
	}
	cused = zs_resource_used_uint64(u, ZS_RESOURCE_CPU, ZS_USER_KERNEL);
	mused = zs_resource_used_uint64(u, ZS_RESOURCE_RAM_RSS, ZS_USER_KERNEL);
	vused = zs_resource_used_uint64(u, ZS_RESOURCE_VM, ZS_USER_KERNEL);

	ppart = zs_resource_used_pct(u, ZS_RESOURCE_CPU, ZS_USER_KERNEL);
	mpct = zs_resource_used_pct(u, ZS_RESOURCE_RAM_RSS, ZS_USER_KERNEL);
	vpct = zs_resource_used_pct(u, ZS_RESOURCE_VM, ZS_USER_KERNEL);

	if (opt_line_system) {
		(void) snprintf(zonename, sizeof (zonename), "[%s]",
		    ZONESTAT_NAME_SYSTEM);
		zonestat_print_summary_zone(namewidth, report_fmt, zonename,
		    cused, ppart, ZS_PCT_NONE, ZS_PCT_NONE, mused, mpct,
		    ZS_PCT_NONE, vused, vpct, ZS_PCT_NONE);
	}
	for (i = 0; i < num; i++) {

		z = g_zone_list[i];

		zs_zone_property(z, ZS_ZONE_PROP_NAME, prop);
		(void) strlcpy(zonename, zs_property_string(prop),
		    sizeof (zonename));

		cused = zs_resource_used_zone_uint64(z, ZS_RESOURCE_CPU);
		mused = zs_resource_used_zone_uint64(z, ZS_RESOURCE_RAM_RSS);
		vused = zs_resource_used_zone_uint64(z, ZS_RESOURCE_VM);

		ppart = zs_resource_used_zone_pct(z, ZS_RESOURCE_CPU);
		mpct = zs_resource_used_zone_pct(z, ZS_RESOURCE_RAM_RSS);
		vpct = zs_resource_used_zone_pct(z, ZS_RESOURCE_VM);

		pshru = zs_zone_limit_used_pct(z, ZS_LIMIT_CPU_SHARES);
		pccap = zs_zone_limit_used_pct(z, ZS_LIMIT_CPU);
		pmcap = zs_zone_limit_used_pct(z, ZS_LIMIT_RAM_RSS);
		pvcap = zs_zone_limit_used_pct(z, ZS_LIMIT_VM);

		zonestat_print_summary_zone(namewidth, report_fmt, zonename,
		    cused, ppart, pccap, pshru, mused, mpct, pmcap, vused, vpct,
		    pvcap);
	}

	if (!opt_parseable)
		(void) printf("\n");
	(void) fflush(stdout);
}

static void
zonestat_print_res(int report_fmt, char *header, char *sizename, char *resname,
    char *name, zs_usage_t *u, int res, int limit)
{
	zs_zone_t *zone;
	char zonename[ZS_ZONENAME_MAX];
	uint64_t size;
	uint64_t used;
	uint64_t cap;
	uint_t pct;
	uint_t pctcap;
	zs_property_t *prop;
	int num, i;
	size_t namelen, len;

	prop = (zs_property_t *)alloca(zs_property_size());

	/* See if resource matches specified resource names */
	if (zonestat_match_resname(name) == 0)
		return;

	namelen = strlen(resname);
	if (ZSTAT_RESOURCE_MIN_RESNAME > namelen)
		namelen = ZSTAT_RESOURCE_MIN_RESNAME;

	zonestat_print_resource__header(namelen, header, sizename);

	size = zs_resource_total_uint64(u, res);

	if (opt_line_resource)
		zonestat_print_resource_(namelen, report_fmt, resname, name,
		    size);

again:
	num = zs_zone_list(u, g_zone_list, g_zone_num);
	if (num > g_zone_num) {
		if (g_zone_list != NULL)
			free(g_zone_list);
		g_zone_list = (zs_zone_t **) malloc(sizeof (zs_zone_t *) * num);
		g_zone_num = num;
		goto again;
	}
	namelen = ZSTAT_RESOURCE_MIN_ZONENAME;
	for (i = 0; i < num; i++) {
		zone = g_zone_list[i];
		(void) zs_zone_property(zone, ZS_ZONE_PROP_NAME, prop);
		len = strlen(zs_property_string(prop));
		if (len > namelen)
			namelen = len;
	}

	zonestat_print_resource_zone_header(namelen);

	used = zs_resource_used_uint64(u, res, ZS_USER_ALL);
	pct = zs_resource_used_pct(u, res, ZS_USER_ALL);

	if (opt_line_total) {
		(void) snprintf(zonename, sizeof (zonename), "[%s]",
		    ZONESTAT_NAME_TOTAL);
		zonestat_print_resource_zone(namelen, report_fmt, resname,
		    name, zonename, used, pct, ZS_LIMIT_NONE, ZS_PCT_NONE);
	}
	used = zs_resource_used_uint64(u, res, ZS_USER_KERNEL);
	pct = zs_resource_used_pct(u, res, ZS_USER_KERNEL);

	if (opt_line_system) {
		(void) snprintf(zonename, sizeof (zonename), "[%s]",
		    ZONESTAT_NAME_SYSTEM);
		zonestat_print_resource_zone(namelen, report_fmt, resname, name,
		    zonename, used, pct, ZS_LIMIT_NONE, ZS_PCT_NONE);
	}
	zonestat_qsort(g_zone_list, num, sizeof (zs_zone_t *),
	    zonestat_zone_compare_resource, res);

	for (i = 0; i < num; i++) {

		zone = g_zone_list[i];
		zs_zone_property(zone, ZS_ZONE_PROP_NAME, prop);
		(void) strlcpy(zonename, zs_property_string(prop),
		    sizeof (zonename));

		if (zonestat_match_zonename(zonename) == 0)
			continue;

		used = zs_resource_used_zone_uint64(zone, res);
		pct = zs_resource_used_zone_pct(zone, res);

		cap = zs_zone_limit_uint64(zone, limit);
		pctcap = zs_zone_limit_used_pct(zone, limit);

		if (opt_line_zones)
			zonestat_print_resource_zone(namelen, report_fmt,
			    resname, name, zonename, used, pct, cap, pctcap);
	}
	if (!opt_parseable)
		(void) printf("\n");
}

static void
zonestat_print_cpu_res_header(size_t namelen)
{
	char name_format[ZS_NAME_STRLEN];

	if (opt_parseable)
		return;

	(void) snprintf(name_format, sizeof (name_format), "%%-%ds ", namelen);
	/* LINTED */
	(void) printf(name_format, "PROCESSOR_SET");
	(void) printf(ZSTAT_CPU_RES_FORMAT, "TYPE", "ONLINE/CPUS", "MIN/MAX");
}
static void
zonestat_print_cpu_zone_header(size_t namelen)
{
	char name_format[ZS_NAME_STRLEN];

	if (opt_parseable)
		return;

	(void) snprintf(name_format, sizeof (name_format), "%%%ds ", namelen);
	/* LINTED */
	(void) printf(name_format, "ZONE");

	(void) printf(ZSTAT_CPU_ZONE_FORMAT, "USED", "PCT", "CAP",
	    "%CAP", "SHRS", "%SHR", "%SHRU");
}

static void
zonestat_print_cpu_res(size_t namelen, int report_fmt, char *cputype,
    char *name, uint64_t online, uint64_t size, uint64_t min, uint64_t max,
    timestruc_t *ts)
{
	char online_str[ZS_UINT64_STRLEN];
	char size_str[ZS_UINT64_STRLEN];
	char min_str[ZS_UINT64_STRLEN];
	char max_str[ZS_UINT64_STRLEN];
	char cpus_str[ZS_UINT64_STRLEN + ZS_UINT64_STRLEN + 1];
	char minmax_str[ZS_UINT64_STRLEN + ZS_UINT64_STRLEN + 1];
	char ts_str[ZS_TIME_STRLEN];
	char name_format[ZS_NAME_STRLEN];

	char *label;

	format_uint64(online, online_str, sizeof (online_str));
	format_uint64(size, size_str, sizeof (size_str));
	format_uint64(min, min_str, sizeof (min_str));
	format_uint64(max, max_str, sizeof (max_str));
	format_ts(ts, ts_str, sizeof (ts_str), B_FALSE);

	if (opt_parseable) {
		if (opt_timestamp) {
			zonestat_print_timestamp(g_now_time);
			(void) printf(":");
		}
		label = zonestat_get_plabel(report_fmt);

		(void) printf("%s:%s:%s:%s:[%s]:%s:%s:%s:%s:%s\n", label,
		    ZONESTAT_PROCESSOR_SET, cputype, name,
		    ZONESTAT_NAME_RESOURCE, online_str, size_str, min_str,
		    max_str, ts_str);
		return;
	}

	(void) snprintf(cpus_str, sizeof (cpus_str), "%s/%s", online_str,
	    size_str);
	(void) snprintf(minmax_str, sizeof (minmax_str), "%s/%s", min_str,
	    max_str);

	(void) snprintf(name_format, sizeof (name_format), "%%-%ds ", namelen);
	/* LINTED */
	(void) printf(name_format, name);
	(void) printf(ZSTAT_CPU_RES_FORMAT, cputype, cpus_str, minmax_str);
}

static void
zonestat_print_cpu_zone(size_t namelen, int report_fmt, char *cputype,
    char *name, char *zonename, uint64_t used, uint_t pct, uint64_t cap,
    uint_t pct_cap, uint64_t shares, uint_t scheds, uint_t pct_shares,
    uint_t pct_shares_used, timestruc_t *ts, boolean_t report_conflict)
{
	char used_str[ZS_UINT64_STRLEN];
	char pct_str[ZS_PCT_STRLEN];
	char cap_str[ZS_UINT64_STRLEN];
	char pct_cap_str[ZS_PCT_STRLEN];
	char shares_str[ZS_UINT64_STRLEN];
	char pct_shares_str[ZS_PCT_STRLEN];
	char pct_shares_used_str[ZS_PCT_STRLEN];
	char ts_str[ZS_TIME_STRLEN];
	char name_format[ZS_NAME_STRLEN];
	char *label;

	format_cpu(used, used_str, sizeof (used_str));
	format_pct(pct, pct_str, sizeof (pct_str));
	format_ts(ts, ts_str, sizeof (ts_str), B_FALSE);

	if (cap == ZS_LIMIT_NONE)
		(void) strlcpy(cap_str, "-", sizeof (cap_str));
	else
		format_cpu(cap, cap_str, sizeof (cap_str));

	if (pct_cap == ZS_PCT_NONE)
		(void) strlcpy(pct_cap_str, "-", sizeof (pct_cap_str));
	else
		format_pct(pct_cap, pct_cap_str, sizeof (pct_cap_str));

	if ((scheds & ZS_SCHED_CONFLICT) &&
	    (!(scheds & ZS_SCHED_FSS)))
		(void) strlcpy(shares_str, "no-fss", sizeof (shares_str));
	else if (shares == ZS_LIMIT_NONE)
		(void) strlcpy(shares_str, "-", sizeof (shares_str));
	else if (shares == ZS_SHARES_UNLIMITED)
		(void) strlcpy(shares_str, "inf", sizeof (shares_str));
	else
		format_uint64(shares, shares_str, sizeof (shares_str));

	if (pct_shares == ZS_PCT_NONE)
		(void) strlcpy(pct_shares_str, "-", sizeof (pct_shares_str));
	else
		format_pct(pct_shares, pct_shares_str,
		    sizeof (pct_shares_str));

	if (pct_shares_used == ZS_PCT_NONE) {
		(void) strlcpy(pct_shares_used_str, "-",
		    sizeof (pct_shares_used_str));
	} else {
		format_pct(pct_shares_used, pct_shares_used_str,
		    sizeof (pct_shares_used_str));
	}
	if (opt_parseable) {
		if (opt_timestamp) {
			zonestat_print_timestamp(g_now_time);
			(void) printf(":");
		}
		label = zonestat_get_plabel(report_fmt);

		(void) printf("%s:%s:%s:%s:%s:%s:%s:%s:%s:%s:%s:%s:%s\n", label,
		    ZONESTAT_PROCESSOR_SET, cputype, name, zonename, used_str,
		    pct_str, cap_str, pct_cap_str, shares_str, pct_shares_str,
		    pct_shares_used_str, ts_str);
		return;
	} else {
		(void) snprintf(name_format, sizeof (name_format), "%%%ds ",
		    namelen);
		/* LINTED */
		(void) printf(name_format, zonename);

		(void) printf(ZSTAT_CPU_ZONE_FORMAT, used_str,
		    pct_str, cap_str, pct_cap_str, shares_str, pct_shares_str,
		    pct_shares_used_str);
	}
	/* Report if zone has mix of schedulers conflicting with FSS */
	if (report_conflict && (scheds & ZS_SCHED_CONFLICT) &&
	    (scheds & ZS_SCHED_FSS)) {
		/* LINTED */
		(void) printf(name_format, "");
		(void) printf(" mixed schedulers found:");
		(void) printf(" FSS");
		if (scheds & ZS_SCHED_TS)
			(void) printf(", TS");
		if (scheds & ZS_SCHED_IA)
			(void) printf(", IA");
		if (scheds & ZS_SCHED_FX)
			(void) printf(", FX");
		(void) printf("\n");
	}
}

static void
zonestat_print_pset(int report_fmt, zs_pset_t *pset, char *cputype)
{
	zs_pset_zone_t *pz;
	zs_zone_t *zone;
	uint64_t cpus;
	uint64_t size;
	uint64_t min;
	uint64_t max;
	uint_t scheds;
	uint64_t used;
	uint_t pct;
	uint64_t cap;
	uint_t pct_cap;
	uint64_t shares;
	uint_t pct_shares;
	uint_t pct_shares_used;
	char psetname[ZS_PSETNAME_MAX];
	char zonename[ZS_PSETNAME_MAX];
	char *name;
	zs_property_t *prop;
	boolean_t zone_match;
	int num, i;
	timestruc_t ts;
	size_t namelen, len;

	prop = (zs_property_t *)alloca(zs_property_size());

	zs_pset_property(pset, ZS_PSET_PROP_NAME, prop);
	(void) strlcpy(psetname, zs_property_string(prop), sizeof (psetname));

	/* Check if pset contains specified zone */
	if (arg_zonename_count > 0) {
		zone_match = B_FALSE;
		for (pz = zs_pset_zone_first(pset); pz != NULL;
		    pz = zs_pset_zone_next(pset, pz)) {
			zone = zs_pset_zone_get_zone(pz);
			(void) zs_zone_property(zone, ZS_ZONE_PROP_NAME, prop);
			(void) strlcpy(zonename, zs_property_string(prop),
			    sizeof (zonename));

			if (zonestat_match_zonename(zonename) == 1) {
				zone_match = B_TRUE;
				break;
			}
		}
		if (zone_match == B_FALSE)
			return;
	}

	if (zonestat_match_resname(psetname) == 0)
		return;

	zs_pset_property(pset, ZS_PSET_PROP_ONLINE, prop);
	cpus = zs_property_uint64(prop);
	zs_pset_property(pset, ZS_PSET_PROP_SIZE, prop);
	size = zs_property_uint64(prop);
	zs_pset_property(pset, ZS_PSET_PROP_MIN, prop);
	min = zs_property_uint64(prop);
	zs_pset_property(pset, ZS_PSET_PROP_MAX, prop);
	max = zs_property_uint64(prop);
	zs_pset_total_time(pset, &ts);

	/* Strip off SUNWtmp_ from pset name */
	name = psetname;
	if (strncmp(psetname, "SUNWtmp_", strlen("SUNWtmp_")) == 0) {
		name = strchr(psetname, '_');
		name++;
	}

	/* Strip off SUNWlegacy_pst for psrset psets */
	if (strncmp(psetname, "SUNWlegacy_pset_",
	    strlen("SUNWlegacy_pset_")) == 0) {
		name = strrchr(psetname, '_');
		name++;
	}

	namelen = strlen(name);
	if (ZSTAT_CPU_MIN_PSETNAME > namelen)
		namelen = ZSTAT_CPU_MIN_PSETNAME;

	zonestat_print_cpu_res_header(namelen);

	if (opt_line_resource)
		zonestat_print_cpu_res(namelen, report_fmt, cputype, name, cpus,
		    size, min, max, &ts);

again:
	num = zs_pset_zone_list(pset, g_pz_list, g_pz_num);
	if (num > g_pz_num) {
		if (g_pz_list != NULL)
			free(g_pz_list);
		g_pz_list = (zs_pset_zone_t **)malloc(
		    sizeof (zs_pset_zone_t *) * num);
		g_pz_num = num;
		goto again;
	}

	/* Find longest zone name in pset */
	namelen = ZSTAT_CPU_MIN_ZONENAME;
	for (i = 0; i < num; i++) {
		pz = g_pz_list[i];
		zone = zs_pset_zone_get_zone(pz);
		zs_zone_property(zone, ZS_ZONE_PROP_NAME, prop);
		len = strlen(zs_property_string(prop));
		if (len > namelen)
			namelen = len;
	}

	qsort(g_pz_list, num, sizeof (zs_pset_zone_t *),
	    zonestat_pz_compare_usage);

	zonestat_print_cpu_zone_header(namelen);

	zs_pset_property(pset, ZS_PSET_PROP_CPU_SHARES, prop);
	shares = zs_property_uint64(prop);
	zs_pset_property(pset, ZS_PSET_PROP_SCHEDULERS, prop);
	scheds = zs_property_uint(prop);

	zs_pset_used_time(pset, ZS_USER_ALL, &ts);
	used = zs_pset_used_cpus(pset, ZS_USER_ALL);
	pct = zs_pset_used_pct(pset, ZS_USER_ALL);

	if (opt_line_total) {
		(void) snprintf(zonename, sizeof (zonename), "[%s]",
		    ZONESTAT_NAME_TOTAL);
		zonestat_print_cpu_zone(namelen, report_fmt, cputype, name,
		    zonename, used, pct, ZS_LIMIT_NONE, ZS_PCT_NONE, shares,
		    scheds, ZS_PCT_NONE, ZS_PCT_NONE, &ts, B_FALSE);
	}
	zs_pset_used_time(pset, ZS_USER_KERNEL, &ts);
	used = zs_pset_used_cpus(pset, ZS_USER_KERNEL);
	pct = zs_pset_used_pct(pset, ZS_USER_KERNEL);

	if (opt_line_system) {
		(void) snprintf(zonename, sizeof (zonename), "[%s]",
		    ZONESTAT_NAME_SYSTEM);
		zonestat_print_cpu_zone(namelen, report_fmt, cputype, name,
		    zonename, used, pct, ZS_LIMIT_NONE, ZS_PCT_NONE,
		    ZS_LIMIT_NONE, 0, ZS_PCT_NONE, ZS_PCT_NONE, &ts, B_FALSE);
	}
	for (i = 0; i < num; i++) {

		pz = g_pz_list[i];
		zone = zs_pset_zone_get_zone(pz);
		zs_zone_property(zone, ZS_ZONE_PROP_NAME, prop);
		(void) strlcpy(zonename, zs_property_string(prop),
		    sizeof (zonename));

		if (zonestat_match_zonename(zonename) == 0)
			continue;

		zs_pset_zone_property(pz, ZS_PZ_PROP_CPU_CAP, prop);
		cap = zs_property_uint64(prop);

		zs_pset_zone_property(pz, ZS_PZ_PROP_CPU_SHARES, prop);
		shares = zs_property_uint64(prop);
		zs_pset_zone_property(pz, ZS_PZ_PROP_SCHEDULERS, prop);
		scheds = zs_property_uint(prop);

		used = zs_pset_zone_used_cpus(pz);
		zs_pset_zone_used_time(pz, &ts);
		pct = zs_pset_zone_used_pct(pz, ZS_PZ_PCT_PSET);
		pct_cap = zs_pset_zone_used_pct(pz, ZS_PZ_PCT_CPU_CAP);
		pct_shares = zs_pset_zone_used_pct(pz, ZS_PZ_PCT_PSET_SHARES);
		pct_shares_used = zs_pset_zone_used_pct(pz,
		    ZS_PZ_PCT_CPU_SHARES);

		if (opt_line_zones)
			zonestat_print_cpu_zone(namelen, report_fmt, cputype,
			    name, zonename, used, pct, cap, pct_cap, shares,
			    scheds, pct_shares, pct_shares_used, &ts, B_TRUE);
	}
	if (!opt_parseable)
		(void) printf("\n");
}

/* ARGSUSED */
static void
zonestat_quithandler(int sig)
{
	g_quit = B_TRUE;
}

static void
zonestat_print_footer(int report_fmt)
{
	char *label;

	if (!opt_parseable)
		return;

	if (opt_timestamp) {
		zonestat_print_timestamp(g_now_time);
		(void) printf(":");
	}
	label = zonestat_get_plabel(report_fmt);
	(void) printf("%s:%s:", label, ZONESTAT_NAME_FOOTER);
	zonestat_print_timestamp(g_now_time);
	(void) printf("%d:%ld\n", g_interval, g_seconds);
	(void) fflush(stdout);
}

static void
zonestat_print_header(int report_fmt)
{
	char *label;
	timestruc_t ts;
	char string[ZS_TIME_STRLEN];

	if (!opt_parseable) {

		/* Human readable header */
		if (opt_timestamp) {
			zonestat_print_timestamp(g_now_time);
			(void) printf(", ");
		}
		if (report_fmt == ZSTAT_REPORT_FMT_INTERVAL) {
			ts.tv_sec = g_seconds;
			ts.tv_nsec = 0;
			format_ts(&ts, string, sizeof (string), B_TRUE);
			(void) printf("Interval: %d, Duration: %s\n", g_count,
			    string);
			(void) fflush(stdout);
			return;
		} else {
			switch (report_fmt) {
			case ZSTAT_REPORT_FMT_TOTAL:
				label = "Report: Total Usage";
				break;
			case ZSTAT_REPORT_FMT_AVERAGE:
				label = "Report: Average Usage";
				break;
			case ZSTAT_REPORT_FMT_HIGH:
				label = "Report: High Usage";
				break;
			default:
				exit(zonestat_error(gettext(
				    "Internal error, invalid header")));
			}
			/* Left are the report header formats */
			(void) printf("%s\n", label);
			(void) printf("    Start: ");
			zonestat_print_timestamp(g_start_time);
			(void) printf("\n      End: ");
			zonestat_print_timestamp(g_end_time);
			(void) printf("\n");
			ts.tv_sec = g_seconds;
			ts.tv_nsec = 0;
			format_ts(&ts, string, sizeof (string), B_TRUE);
			(void) printf("    Intervals: %d, Duration: %s\n",
			    g_count, string);

			(void) fflush(stdout);
			return;
		}
	}

	if (!opt_line_header)
		return;

	/* Parseable header */
	if (opt_timestamp) {
		zonestat_print_timestamp(g_now_time);
		(void) printf(":");
	}
	label = zonestat_get_plabel(report_fmt);

	(void) printf("%s:%s:", label, ZONESTAT_NAME_HEADER);
	if (report_fmt == ZSTAT_REPORT_FMT_INTERVAL) {
		(void) printf("since-last-interval:");
		zonestat_print_timestamp(g_now_time);
		(void) printf(":%d:%ld\n", g_count, g_seconds);
		(void) fflush(stdout);
		return;
	}

	/* Left are the report header formats */
	zonestat_print_timestamp(g_start_time);
	(void) printf(":");
	zonestat_print_timestamp(g_end_time);
	(void) printf(":");
	(void) printf("%d:%ld\n", g_interval, g_seconds);
	(void) fflush(stdout);
}

static void
zonestat_print_psets(int report_fmt, zs_usage_t *u)
{
	zs_pset_t *pset;
	char *psettype;
	uint_t cputype, num, i;
	zs_property_t *p;

again:
	num = zs_pset_list(u, g_pset_list, g_pset_num);
	if (num > g_pset_num) {
		if (g_pset_list != NULL)
			free(g_pset_list);
		g_pset_list = (zs_pset_t **)malloc(
		    sizeof (zs_pset_t *) * num);
		g_pset_num = num;
		goto again;
	}

	/* Sort, default pset first, then pool, psrset, and dedicated psets */
	qsort(g_pset_list, num, sizeof (zs_pset_t *), zonestat_pset_compare);

	p = (zs_property_t *)alloca(zs_property_size());
	for (i = 0; i < num; i++) {
		pset = g_pset_list[i];
		(void) zs_pset_property(pset, ZS_PSET_PROP_CPUTYPE, p);
		cputype = zs_property_uint(p);
		if (cputype == ZS_CPUTYPE_DEFAULT_PSET &&
		    (g_resources & (ZSTAT_RES_PSETS |
		    ZSTAT_RES_DEFAULT_PSET))) {
			psettype = ZONESTAT_DEFAULT_PSET;
		} else if (cputype == ZS_CPUTYPE_POOL_PSET &&
		    (g_resources & ZSTAT_RES_PSETS)) {
			psettype = ZONESTAT_POOL_PSET;
		} else if (cputype == ZS_CPUTYPE_PSRSET_PSET &&
		    (g_resources & ZSTAT_RES_PSETS)) {
			psettype = ZONESTAT_PSRSET_PSET;
		} else if (cputype == ZS_CPUTYPE_DEDICATED &&
		    (g_resources & ZSTAT_RES_PSETS)) {
			psettype = ZONESTAT_DEDICATED_CPU;
		} else {
			continue;
		}
		zonestat_print_pset(report_fmt, pset, psettype);
	}
}

static void
zonestat_print_resources(int report_fmt, zs_usage_t *usage)
{
	if (g_resources & ZSTAT_RES_SUMMARY)
		zonestat_print_summary(report_fmt, usage);

	if (g_resources & ZSTAT_RES_PHYSICAL_MEMORY)
		zonestat_print_res(report_fmt, "PHYSICAL-MEMORY",
		    "SYSTEM MEMORY", ZONESTAT_PHYSICAL_MEMORY,
		    ZONESTAT_NAME_MEM_DEFAULT, usage,
		    ZS_RESOURCE_RAM_RSS, ZS_LIMIT_RAM_RSS);
	if (g_resources & ZSTAT_RES_VIRTUAL_MEMORY)
		zonestat_print_res(report_fmt, "VIRTUAL-MEMORY",
		    "SYSTEM MEMORY", ZONESTAT_VIRTUAL_MEMORY,
		    ZONESTAT_NAME_VM_DEFAULT, usage,
		    ZS_RESOURCE_VM, ZS_LIMIT_VM);
	if (g_resources & ZSTAT_RES_LOCKED_MEMORY)
		zonestat_print_res(report_fmt, "LOCKED-MEMORY", "SYSTEM MEMORY",
		    ZONESTAT_LOCKED_MEMORY, ZONESTAT_NAME_MEM_DEFAULT, usage,
		    ZS_RESOURCE_RAM_LOCKED, ZS_LIMIT_RAM_LOCKED);

	if (g_resources & (ZSTAT_RES_PSETS | ZSTAT_RES_DEFAULT_PSET))
			zonestat_print_psets(report_fmt, usage);

	if (g_resources & ZSTAT_RES_PROCESSES)
		zonestat_print_res(report_fmt, "PROCESSES", "SYSTEM LIMIT",
		    ZONESTAT_PROCESSES, ZONESTAT_NAME_SYSTEM_LIMIT,
		    usage, ZS_RESOURCE_PROCESSES, ZS_LIMIT_PROCESSES);

	if (g_resources & ZSTAT_RES_LWPS)
		zonestat_print_res(report_fmt, "LWPS", "SYSTEM LIMIT",
		    ZONESTAT_LWPS, ZONESTAT_NAME_SYSTEM_LIMIT, usage,
		    ZS_RESOURCE_LWPS, ZS_LIMIT_LWPS);
	if (g_resources & ZSTAT_RES_LOFI)
		zonestat_print_res(report_fmt, "LOFI", "SYSTEM LIMIT",
		    ZONESTAT_LOFI, ZONESTAT_NAME_SYSTEM_LIMIT,
		    usage, ZS_RESOURCE_LOFI, ZS_LIMIT_LOFI);

	if (g_resources & ZSTAT_RES_SHM_MEMORY)
		zonestat_print_res(report_fmt, "SHM_MEMORY", "SYSTEM LIMIT",
		    ZONESTAT_SHM_MEMORY, ZONESTAT_NAME_SYSTEM_LIMIT,
		    usage, ZS_RESOURCE_SHM_MEMORY, ZS_LIMIT_SHM_MEMORY);

	if (g_resources & ZSTAT_RES_SHM_IDS)
		zonestat_print_res(report_fmt, "SHM_IDS", "SYSTEM LIMIT",
		    ZONESTAT_SHM_IDS, ZONESTAT_NAME_SYSTEM_LIMIT,
		    usage, ZS_RESOURCE_SHM_IDS, ZS_LIMIT_SHM_IDS);

	if (g_resources & ZSTAT_RES_SEM_IDS)
		zonestat_print_res(report_fmt, "SEM_IDS", "SYSTEM LIMIT",
		    ZONESTAT_SEM_IDS, ZONESTAT_NAME_SYSTEM_LIMIT,
		    usage, ZS_RESOURCE_SEM_IDS, ZS_LIMIT_SEM_IDS);

	if (g_resources & ZSTAT_RES_MSG_IDS)
		zonestat_print_res(report_fmt, "MSG_IDS", "SYSTEM LIMIT",
		    ZONESTAT_MSG_IDS, ZONESTAT_NAME_SYSTEM_LIMIT,
		    usage, ZS_RESOURCE_MSG_IDS, ZS_LIMIT_MSG_IDS);
}

/*
 * Adds comma seperated list of names to array of names
 * Returns new total number of names.
 */
static size_t
zonestat_parse_names(char *names, char ***namelist, size_t count)
{
	size_t num, i;
	char *next, *string;

	string = strdup(names);
	if (string == NULL)
		exit(zonestat_error(gettext("Out of Memory")));

	/* count names, delimiting with '\0'. */
	next = string;
	num = 1;
	while ((next = strchr(next, ',')) != NULL) {
		*next++ = '\0';
		num++;
	}

	/* Resise names array */
	*namelist = realloc(*namelist, sizeof (char *) * (num + count));
	if (*namelist == NULL)
		exit(zonestat_error(gettext("Out of Memory")));

	/* add names to names array */
	next = string;
	for (i = 0; i < num; i++) {
		(*namelist)[count + i] = next;
		next += strlen(next) + 1;
	}
	return (count + num);
}

static int
zonestat_extract_int(char *start, char *end, char **tail)
{
	int val;
	int save;

	save = *end;
	*end = '\0';
	errno = 0;
	val = strtol(start, tail, 0);
	*end = save;
	if (errno != 0 || *tail == start)
		return (-1);

	return (val);
}

/*
 * parses and [nh][nm][hs] notation into seconds
 */
static int
zonestat_parse_time(char *string, boolean_t *formatted)
{
	int seconds = 0;
	int minutes = 0;
	int hours = 0;
	char *this, *next, *end;

	*formatted = B_FALSE;

	/* Look for special tokens */
	if (strcmp("default", string) == 0)
		return (ZSTAT_INTERVAL_DEFAULT);

	if (strcmp("inf", string) == 0)
		return (ZSTAT_DURATION_INF);

	/* Look for hours */
	this = string;
	next = strchr(this, 'h');
	if (next != NULL) {
		if ((hours = zonestat_extract_int(this, next, &end)) == -1)
			return (-1);

		*formatted = B_TRUE;
		this = next + 1;
		end++;
	}

	/* Look for minutes delimiter */
	next = strrchr(this, 'm');
	if (next != NULL) {
		if ((minutes = zonestat_extract_int(this, next, &end)) == -1)
			return (-1);

		*formatted = B_TRUE;
		this = next + 1;
		end++;
	}

	/* Look for seconds delimiter */
	next = strrchr(this, 's');
	if (next != NULL) {
		if ((seconds = zonestat_extract_int(this, next, &end)) == -1)
			return (-1);

		*formatted = B_TRUE;
		this = next + 1;
		end++;
	}

	/* No delimiter found.  Treat as seconds */
	if (*formatted == B_FALSE) {
		errno = 0;
		seconds = strtol(this, &end, 0);
		if (errno != 0 || end == this)
			return (-1);
	}

	if (*end != '\0')
		return (-1);

	seconds += (minutes * 60);
	seconds += (hours * 60 * 60);

	return (seconds);
}

static void
zonestat_print_reports(zs_usage_set_t *set)
{
	zs_usage_t *usage_print;

	if (opt_report_total == B_TRUE) {
		usage_print = zs_usage_set_compute(set,
		    ZS_COMPUTE_SET_TOTAL);
		zonestat_print_header(ZSTAT_REPORT_FMT_TOTAL);
		zonestat_print_resources(ZSTAT_REPORT_FMT_TOTAL, usage_print);
		zonestat_print_footer(ZSTAT_REPORT_FMT_TOTAL);
		(void) fflush(stdout);
	}
	if (opt_report_average == B_TRUE) {
		usage_print = zs_usage_set_compute(set,
		    ZS_COMPUTE_SET_AVERAGE);
		zonestat_print_header(ZSTAT_REPORT_FMT_AVERAGE);
		zonestat_print_resources(ZSTAT_REPORT_FMT_AVERAGE, usage_print);
		zonestat_print_footer(ZSTAT_REPORT_FMT_AVERAGE);
		(void) fflush(stdout);
	}
	if (opt_report_high == B_TRUE) {
		usage_print = zs_usage_set_compute(set,
		    ZS_COMPUTE_SET_HIGH);
		zonestat_print_header(ZSTAT_REPORT_FMT_HIGH);
		zonestat_print_resources(ZSTAT_REPORT_FMT_HIGH, usage_print);
		zonestat_print_footer(ZSTAT_REPORT_FMT_HIGH);
		(void) fflush(stdout);
	}
}

static void
zonestat_set_fx()
{
	pcinfo_t pcinfo;
	pcparms_t pcparms;

	(void) strlcpy(pcinfo.pc_clname, "FX", sizeof (pcinfo.pc_clname));
	if (priocntl(0, 0, PC_GETCID, (caddr_t)&pcinfo) == -1) {
		return;
	}
	pcparms.pc_cid = pcinfo.pc_cid;
	((fxparms_t *)pcparms.pc_clparms)->fx_upri = 60;
	((fxparms_t *)pcparms.pc_clparms)->fx_uprilim = 60;
	((fxparms_t *)pcparms.pc_clparms)->fx_tqsecs = 0;
	((fxparms_t *)pcparms.pc_clparms)->fx_tqnsecs = FX_NOCHANGE;
	(void) priocntl(P_PID, getpid(), PC_SETPARMS, (caddr_t)&pcparms);
}

static time_t
zonestat_time()
{
	time_t t;

	t = time(NULL);
	if (t < 0 && g_quit == B_FALSE)
		exit(zonestat_error(gettext(
		    "Unable to fetch current time")));

	return (t);
}

int
main(int argc, char *argv[])
{
	int arg;
	time_t now, next, start, next_report;
	zs_usage_t *usage, *usage_last = NULL, *usage_print;
	zs_usage_set_t *set;
	boolean_t formatted;
	scf_simple_prop_t *prop;
	uint64_t *intervalp;
	char *not_responding;

	/* Process command line options and args */
	while ((arg = getopt(argc, argv, "z:r:n:T:R:qpP:S:D?"))
	    != EOF) {
		switch (arg) {
		case 'z':
			opt_zonenames = B_TRUE;
			arg_zonename_count = zonestat_parse_names(optarg,
			    &arg_zonenames, arg_zonename_count);
			break;
		case 'r':
			arg_restype_count = zonestat_parse_names(optarg,
			    &arg_restypes, arg_restype_count);
			opt_restypes = B_TRUE;
			break;
		case 'n':
			opt_resnames = B_TRUE;
			arg_resname_count = zonestat_parse_names(optarg,
			    &arg_resnames, arg_resname_count);
			break;
		case 'R':
			opt_report = B_TRUE;
			arg_report_count = zonestat_parse_names(optarg,
			    &arg_reports, arg_report_count);
			break;
		case 'S':
			opt_sort = B_TRUE;
			arg_sort_count = zonestat_parse_names(optarg,
			    &arg_sort_list, arg_sort_count);
			break;
		case 'T':
			opt_timestamp = B_TRUE;
			if (strcmp(optarg, "u") == 0) {
				arg_timestamp = ZSTAT_UNIX_TIMESTAMP;
			} else if (strcmp(optarg, "d") == 0) {
				arg_timestamp = ZSTAT_DATE_TIMESTAMP;
			} else if (strcmp(optarg, "i") == 0) {
				arg_timestamp = ZSTAT_ISO_TIMESTAMP;
			} else {
				(void) zonestat_error(gettext(
				    "Invalid -T arg \"%s\". "
				    "Must be 'u', 'i', or 'd'."), optarg);
				return (zonestat_usage(B_FALSE));
			}
			break;
		case 'q':
			opt_quiet_intervals = B_TRUE;
			break;
		case 'p':
			opt_parseable = B_TRUE;
			break;
		case 'P':
			opt_line_any = B_TRUE;
			arg_line_count = zonestat_parse_names(optarg,
			    &arg_line_list, arg_line_count);
			break;
		case 'D':
			opt_debug = B_TRUE;
			break;
		case '?':
			return (zonestat_usage(B_TRUE));
		default:
			return (zonestat_usage(B_FALSE));
		}
	}

	if (opt_line_any && (!opt_parseable)) {
		(void) zonestat_error(gettext("-P requires -p"));
		return (zonestat_usage(B_FALSE));
	}

	if (opt_timestamp && arg_timestamp == ZSTAT_DATE_TIMESTAMP &&
	    opt_parseable) {
		(void) zonestat_error(gettext(
		    "-T d invalid with -p.  Use -T [u | i]"));
		return (zonestat_usage(B_FALSE));

	}
	/* Default to ISO timetamp in parseable output */
	if (!opt_timestamp && opt_parseable)
		arg_timestamp = ZSTAT_ISO_TIMESTAMP;

	/* Get the interval and count */
	optind++;
	if (argc >= optind) {
		if ((arg_interval = zonestat_parse_time(argv[optind - 1],
		    &formatted)) < 0 || arg_interval == 0)  {
			(void) zonestat_error(gettext(
			    "Invalid interval: \"%s\""), argv[optind - 1]);
			return (zonestat_usage(B_FALSE));
		}
	} else {
		(void) zonestat_error(gettext("Interval required."));
		return (zonestat_usage(B_FALSE));
	}

	if (arg_interval == ZSTAT_INTERVAL_DEFAULT) {
		/* Get the configured sample interval */
		prop = scf_simple_prop_get(NULL,
		    "svc:/system/zones-monitoring:default", "config",
		    "sample_interval");

		if (prop == NULL) {
			return (zonestat_error(gettext(
			    "Unable to fetch SMF property "
			    "\"config/sample_interval\"")));
	}
		if (scf_simple_prop_type(prop) != SCF_TYPE_COUNT) {
			return (zonestat_error(gettext("Malformed SMF property "
			    "\"config/sample_interval\".  Must be of type "
			    "\"count\"")));
	}
		intervalp = scf_simple_prop_next_count(prop);
		arg_interval = *intervalp;
		if (arg_interval == 0)
			return (zonestat_error(gettext("Malformed SMF property "
			    "\"config/sample_interval\".  Must be greater than"
			    "zero")));

		scf_simple_prop_free(prop);
	}
	optind++;
	if (argc >= optind) {
		if ((arg_duration = zonestat_parse_time(argv[optind - 1],
		    &formatted)) < 0 || arg_duration == 0)  {
			(void) zonestat_error(gettext(
			    "Invalid duration: \"%s\""), argv[optind - 1]);
			return (zonestat_usage(B_FALSE));
		}
		/* If not formatted [nh][nm][ns], treat as count */
		if (arg_duration != ZSTAT_DURATION_INF &&
		    formatted == B_FALSE)
			arg_duration *= arg_interval;
	} else {
		arg_duration = ZSTAT_DURATION_INF;
	}
	optind++;
	if (argc >= optind) {
		if ((arg_report = zonestat_parse_time(argv[optind - 1],
		    &formatted)) < 0 || arg_report == 0)  {
			(void) zonestat_error(gettext(
			    "Invalid report period: \"%s\""), argv[optind - 1]);
			return (zonestat_usage(B_FALSE));
		}
		/* If not formatted as [nh][nm][ns] treat as count */
		if (formatted == B_FALSE)
			arg_report *= arg_interval;
	} else {
		arg_report = ZSTAT_REPORT_END;
	}

	if (opt_quiet_intervals && (!opt_report)) {
		(void) zonestat_error(gettext("-q requires -R"));
		return (zonestat_usage(B_FALSE));
	}

	/* Figure out what resources to report on */
	zonestat_determine_resources();
	zonestat_determine_reports();
	zonestat_determine_lines();
	zonestat_determine_sort();

	/* Done parsing args beyond this point */

	(void) signal(SIGINT, zonestat_quithandler);
	(void) signal(SIGTERM, zonestat_quithandler);
	(void) signal(SIGHUP, zonestat_quithandler);

	/* Run at high priority to keep up with busy system */
	zonestat_set_fx();

	not_responding = gettext(
	    "Zones monitoring service \"svc:/system/zones-monitoring:default\" "
	    "not enabled or responding.");

	/* Open zone statistics */
	g_zsctl = zs_open();
	if (g_zsctl == NULL) {
		if (errno == EPERM)
			return (zonestat_error(gettext("Permission denied")));
		if (errno == EINTR || errno == ESRCH) {
			(void) zonestat_error(not_responding);
			return (3);
		}
		if (errno == ENOTSUP)
			return (zonestat_error(gettext(
			    "Mismatched zonestat version. "
			    "Re-install system/zones package.")));

		return (zonestat_error(gettext(
		    "Unexpected error.  Unable to open zone statistics.")));
	}
	usage_last = zs_usage_read(g_zsctl);
	if (usage_last == NULL) {
		if (errno == EINTR && g_quit == B_TRUE)
			return (0);
		(void) zonestat_error(not_responding);
		return (3);
	}
	set = zs_usage_set_alloc(g_zsctl);

	g_start_time = g_now_time = start = now = zonestat_time();
	g_interval = arg_interval;
	g_report_count = g_count = g_seconds = 0;

	if (opt_quiet_intervals == B_FALSE && opt_parseable == B_FALSE)
		(void) printf(gettext(
		    "Collecting data for first interval...\n"));

	for (;;) {
		time_t tosleep;

		g_now_time = now = zonestat_time();

		if (arg_report != ZSTAT_REPORT_END)
			next_report = start + ((g_report_count + 1) *
			    arg_report);

		/*
		 * Sleep till next interval.
		 */
		g_count++;
		next = g_start_time + (g_count) * g_interval;
		/*
		 * Skip to next interval if due to busy system, zonestat did
		 * not complete in time.
		 */
		while (now >= g_start_time + ((g_count + 1) * g_interval))
			g_count++;

		while (now < next) {
			/* Sleep until at next interval */
			tosleep = next - now;
			(void) sleep(tosleep);
			now = zonestat_time();
			if (g_quit == B_TRUE)
				goto interval_loop_done;
		}

		g_seconds = now - start;
		g_now_time = now;
		if ((usage = zs_usage_read(g_zsctl)) == NULL) {
			if (errno == EINTR && g_quit == B_TRUE)
				break;
			(void) zonestat_error(not_responding);
			return (3);
		}

		/* Compute cpu used since last interval */
		usage_print = zs_usage_compute(NULL, usage_last,
		    usage, ZS_COMPUTE_USAGE_INTERVAL);
		if (usage_print == NULL)
			(void) zonestat_error(gettext("Out of Memory"));


		if (opt_quiet_intervals == B_TRUE)
			goto interval_print_end;

		zonestat_print_header(ZSTAT_REPORT_FMT_INTERVAL);
		zonestat_print_resources(ZSTAT_REPORT_FMT_INTERVAL,
		    usage_print);
		zonestat_print_footer(ZSTAT_REPORT_FMT_INTERVAL);
		(void) fflush(stdout);

interval_print_end:
		(void) zs_usage_set_add(set, usage_print);


		/* Print reports if they are due */
		if (opt_report && arg_report != ZSTAT_REPORT_END &&
		    now >= next_report) {
			g_end_time  = now;
			zonestat_print_reports(set);
			zs_usage_set_free(set);
			set = zs_usage_set_alloc();
			g_start_time = now;
			g_report_count++;
		}
		zs_usage_free(usage_last);
		usage_last = usage;
		if (arg_duration != ZSTAT_DURATION_INF &&
		    g_seconds >= arg_duration)
			break;
	}
interval_loop_done:

	/* Print last reports if due */
	g_end_time = g_now_time;
	if (opt_report && zs_usage_set_count(set) > 0 &&
	    (arg_report == ZSTAT_REPORT_END || now < next_report))
		zonestat_print_reports(set);

	zs_usage_set_free(set);
	if (usage_last != NULL)
		zs_usage_free(usage_last);

	if (g_zsctl != NULL)
		zs_close(g_zsctl);

	return (0);
}
