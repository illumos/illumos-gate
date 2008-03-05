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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <search.h>
#include <stdlib.h>

#include <sys/utsname.h>
#include "rdprot.h"
#include "rdutil.h"
/*
 * This file works out the protocol layer of the bidirectional data interface
 * between the rds and the client. In the server mode rds writes greetings and
 * a protocol header to the output stream.
 * pheader  == { "@RDS-MAG@"  PROTV }
 * PROTV    == { protocol version }
 * Then it sends a prompt and waits for command from client.
 * PROMPT   == { "@RDS@>" }
 * COMMAND  == { "command"  cmd }
 * cmd	    == { "-pUuJjS" | "-p" | "-u" | "-U" |
 *		 "-j" | "-J" | "-S" | "-i100" | "alive"| "exit" }
 * The answer from rds is always a lists of data. The header of the answer data
 * contains the number of lists in the package. Each list has a header and
 * some elements, which have again a header and some fields of data:
 * answer   == { lshead,  n * list }
 * lshead   == { number of lists }
 * list     == { lheader, n * element }
 * lheader  == { LISTT, ELEMN }
 * LISTT    == { type of the list }
 * ELEMN    == { number of elements in the list }
 * element  == { eheader, field }
 * eheader  == { ELMID, FILDN }
 * ELMID    == { element id, like pid, uid, project name }
 * field    == { KEY, VALUE }
 * All protocol elements have a key and a value separated by one space.
 * The value begins after the first space and ends with the new line character.
 * Protocol keys are: "@RDS-MAG@", PROTV, LISTN,  LISTT, ELEMN ELMID, FILDN,
 * RDERR. The special key RDERR can occur in any line and indicates that an
 * error condition occurred, where the VALUE is the error message.
 */

static char line[P_MAXLEN];
static char error[P_MAXLEN];
static char value[P_MAXVAL];
static char key[P_MAXKEY];

static char *nullstr = "";
static FILE *wstream, *rstream;

static int format_int64(int, char *, char *, int);
static int format_int32(int, char *, char *, int);
static int format_ulong(int, char *, char *, int);
static int format_float(int, char *, char *, int);
static int format_double(int, char *, char *, int);
static int format_string(int, char *, char *, int);
static int format_timestruc(int, char *, char *, int);

/*
 * The kv_pair_t represents an field in a  c-sturcture. An filed
 * is defined by a key 'field name', format function and an offset
 * in this structure
 */

/*
 * Array of fields from id_info_t structure, that are sent/received
 * in a process/user/project utilization list.
 */
static kv_pair_t id_stub[] =
{
{ "id_pid",	{ format_int32, offsetof(id_info_t, id_pid) }},
{ "id_uid",	{ format_int32, offsetof(id_info_t, id_uid) }},
{ "id_projid",	{ format_int32, offsetof(id_info_t, id_projid) }},
{ "id_usr", 	{ format_double, offsetof(id_info_t, id_usr) }},
{ "id_sys", 	{ format_double, offsetof(id_info_t, id_sys) }},
{ "id_ttime", 	{ format_double, offsetof(id_info_t, id_ttime) }},
{ "id_tpftime", { format_double, offsetof(id_info_t, id_tpftime) }},
{ "id_dpftime", { format_double, offsetof(id_info_t, id_dpftime) }},
{ "id_kpftime", { format_double, offsetof(id_info_t, id_kpftime) }},
{ "id_lck", 	{ format_double, offsetof(id_info_t, id_lck) }},
{ "id_slp", 	{ format_double, offsetof(id_info_t, id_slp) }},
{ "id_lat", 	{ format_double, offsetof(id_info_t, id_lat) }},
{ "id_stime", 	{ format_double, offsetof(id_info_t, id_stime) }},
{ "id_minf", 	{ format_int64, offsetof(id_info_t, id_minf) }},
{ "id_majf", 	{ format_int64, offsetof(id_info_t, id_majf) }},
{ "id_nswap", 	{ format_int64, offsetof(id_info_t, id_nswap) }},
{ "id_inblk", 	{ format_int64, offsetof(id_info_t, id_inblk) }},
{ "id_oublk", 	{ format_int64, offsetof(id_info_t, id_oublk) }},
{ "id_msnd", 	{ format_int64, offsetof(id_info_t, id_msnd) }},
{ "id_mrcv", 	{ format_int64, offsetof(id_info_t, id_mrcv) }},
{ "id_sigs", 	{ format_int64, offsetof(id_info_t, id_sigs) }},
{ "id_vctx", 	{ format_int64, offsetof(id_info_t, id_vctx) }},
{ "id_ictx", 	{ format_int64, offsetof(id_info_t, id_ictx) }},
{ "id_scl", 	{ format_int64, offsetof(id_info_t, id_scl) }},
{ "id_ioch", 	{ format_int64, offsetof(id_info_t, id_ioch) }},
{ "id_hpsize", 	{ format_int64, offsetof(id_info_t, id_hpsize) }},
{ "id_size", 	{ format_int64, offsetof(id_info_t, id_size) }},
{ "id_rssize", 	{ format_int64, offsetof(id_info_t, id_rssize) }},
{ "id_pctcpu", 	{ format_float, offsetof(id_info_t, id_pctcpu) }},
{ "id_pctmem", 	{ format_float, offsetof(id_info_t, id_pctmem) }},
{ "id_time", 	{ format_int64, offsetof(id_info_t, id_time) }},
{ "id_nlwps", 	{ format_int32, offsetof(id_info_t, id_nlwps) }},
{ "id_timestamp", { format_int64, offsetof(id_info_t, id_timestamp) }},
{ "id_nproc", 	{ format_int32, offsetof(id_info_t, id_nproc) }},
{ "id_inpkg", 	{ format_int64, offsetof(id_info_t, id_inpkg) }},
{ "id_oupkg", 	{ format_int64, offsetof(id_info_t, id_oupkg) }},
{ "id_name", 	{ format_string, offsetof(id_info_t, id_name) }}
};

static kv_pair_t lwp_stub[] =
{
{"li_usage",	{ format_ulong, offsetof(lwp_info_t, li_usr) }},
{"li_usr",	{ format_ulong, offsetof(lwp_info_t, li_usr) }},
{"li_sys",	{ format_ulong, offsetof(lwp_info_t, li_sys) }},
{"li_ttime",	{ format_ulong, offsetof(lwp_info_t, li_ttime) }},
{"li_tpftime",	{ format_ulong, offsetof(lwp_info_t, li_tpftime) }},
{"li_dpftime",	{ format_ulong, offsetof(lwp_info_t, li_dpftime) }},
{"li_kpftime",	{ format_ulong, offsetof(lwp_info_t, li_kpftime) }},
{"li_lck",	{ format_ulong, offsetof(lwp_info_t, li_lck) }},
{"li_slp",	{ format_ulong, offsetof(lwp_info_t, li_slp) }},
{"li_lat",	{ format_ulong, offsetof(lwp_info_t, li_lat) }},
{"li_stime",	{ format_ulong, offsetof(lwp_info_t, li_stime) }},
{"li_minf",	{ format_ulong, offsetof(lwp_info_t, li_minf) }},
{"li_majf",	{ format_ulong, offsetof(lwp_info_t, li_majf) }},
{"li_nswap",	{ format_ulong, offsetof(lwp_info_t, li_nswap) }},
{"li_inblk",	{ format_ulong, offsetof(lwp_info_t, li_inblk) }},
{"li_oublk",	{ format_ulong, offsetof(lwp_info_t, li_oublk) }},
{"li_msnd",	{ format_ulong, offsetof(lwp_info_t, li_msnd) }},
{"li_mrcv",	{ format_ulong, offsetof(lwp_info_t, li_mrcv) }},
{"li_sigs",	{ format_ulong, offsetof(lwp_info_t, li_sigs) }},
{"li_vctx",	{ format_ulong, offsetof(lwp_info_t, li_vctx) }},
{"li_ictx",	{ format_ulong, offsetof(lwp_info_t, li_ictx) }},
{"li_scl",	{ format_ulong, offsetof(lwp_info_t, li_scl) }},
{"li_ioch",	{ format_ulong, offsetof(lwp_info_t, li_ioch) }},
{"li_hpsize",	{ format_ulong, offsetof(lwp_info_t, li_hpsize) }},
{"li_timestamp", { format_ulong, offsetof(lwp_info_t, li_timestamp) }},
};

static kv_pair_t lwpinfo_stub[] =
{
{"lwpr_pid",	{ format_int32, offsetof(lwpinfo_t, pr_pid) }},
{"lwpr_lwpid",	{ format_int32, offsetof(lwpinfo_t, pr_lwpid) }},
};

static kv_pair_t prusage_stub[] =
{
{"pr_tstamp",	{ format_timestruc, offsetof(prusage_t, pr_tstamp) }},
{"pr_create",	{ format_timestruc, offsetof(prusage_t, pr_create) }},
{"pr_term",	{ format_timestruc, offsetof(prusage_t, pr_term) }},
{"pr_rtime",	{ format_timestruc, offsetof(prusage_t, pr_rtime) }},
{"pr_utime",	{ format_timestruc, offsetof(prusage_t, pr_utime) }},
{"pr_stime",	{ format_timestruc, offsetof(prusage_t, pr_stime) }},
{"pr_ttime",	{ format_timestruc, offsetof(prusage_t, pr_ttime) }},
{"pr_tftime",	{ format_timestruc, offsetof(prusage_t, pr_tftime) }},
{"pr_dftime",	{ format_timestruc, offsetof(prusage_t, pr_dftime) }},
{"pr_kftime",	{ format_timestruc, offsetof(prusage_t, pr_kftime) }},
{"pr_ltime",	{ format_timestruc, offsetof(prusage_t, pr_ltime) }},
{"pr_slptime",	{ format_timestruc, offsetof(prusage_t, pr_slptime) }},
{"pr_wtime",	{ format_timestruc, offsetof(prusage_t, pr_wtime) }},
{"pr_stoptime", { format_timestruc, offsetof(prusage_t, pr_stoptime) }},
{"pr_minf",	{ format_ulong, offsetof(prusage_t, pr_minf) }},
{"pr_majf",	{ format_ulong, offsetof(prusage_t, pr_majf) }},
{"pr_nswap",	{ format_ulong, offsetof(prusage_t, pr_nswap) }},
{"pr_inblk",	{ format_ulong, offsetof(prusage_t, pr_inblk) }},
{"pr_oublk",	{ format_ulong, offsetof(prusage_t, pr_oublk) }},
{"pr_msnd",	{ format_ulong, offsetof(prusage_t, pr_msnd) }},
{"pr_mrcv",	{ format_ulong, offsetof(prusage_t, pr_mrcv) }},
{"pr_sigs",	{ format_ulong, offsetof(prusage_t, pr_sigs) }},
{"pr_vctx",	{ format_ulong, offsetof(prusage_t, pr_vctx) }},
{"pr_ictx",	{ format_ulong, offsetof(prusage_t, pr_ictx) }},
{"pr_sysc",	{ format_ulong, offsetof(prusage_t, pr_sysc) }},
{"pr_ioch",	{ format_ulong, offsetof(prusage_t, pr_ioch) }},
};

/*
 * Array of fields in id_info_t structure, that are sent/received
 * in an active user list.
 */
static kv_pair_t usr_stub[] =
{
{ "usr_id", 	{ format_int32, offsetof(id_info_t, id_uid) }},
{ "usr_name", 	{ format_string, offsetof(id_info_t, id_name) }}
};

/*
 * Array of fields in id_info_t structure, that are sent/received
 * in an active project list.
 */
static kv_pair_t prj_stub[] =
{
{ "prj_id", 	{ format_int32, offsetof(id_info_t, id_projid) }},
{ "prj_name", 	{ format_string, offsetof(id_info_t, id_name)   }}
};

/*
 * Array of fields in id_info_t structure, that are sent/received
 * in a system list.
 */
static kv_pair_t sys_stub[] =
{
{ "sys_nodename", { format_string, offsetof(sys_info_t, nodename) }},
{ "sys_name",	{ format_string, offsetof(sys_info_t, name) }}
};

/*
 * Array of fields in id_info_t structure, that are sent/received
 * in command.
 */
static kv_pair_t cmd_stub[] =
{
{ "command",	{ format_int32, offsetof(cmd_t, command) }}
};

#define	stubsize(stub) ((sizeof (stub))/(sizeof (kv_pair_t)))

/*
 * Each list type has its own fields description, the list type is
 * the index into this table:
 * L_PRC_SI - processes statistical information
 * L_USR_SI - useres statistical information
 * L_PRJ_SI - projects statistical information
 * L_AC_USR - active users
 * L_AC_PRJ - active projects
 * L_SYSTEM - system
 */
#define	NOF_STUBS   10
static stub_t stubs[NOF_STUBS + 1] = {
{ 0, NULL},
{ stubsize(id_stub), id_stub},
{ stubsize(id_stub), id_stub},
{ stubsize(id_stub), id_stub},
{ stubsize(usr_stub), usr_stub},
{ stubsize(prj_stub), prj_stub},
{ stubsize(sys_stub), sys_stub},
{ stubsize(cmd_stub), cmd_stub},
{ stubsize(lwp_stub), lwp_stub},
{ stubsize(lwpinfo_stub), lwpinfo_stub},
{ stubsize(prusage_stub), prusage_stub},
};

/*
 * read a protocol line, do some checks and extract its key
 * and value part.
 */
static int
r_line() {
	size_t len;

	if (fgets(line, P_MAXLEN, rstream) == NULL) {
		format_err("can't read line");
		return (-1);
	}
	len = strlen(line);
	if (len > P_MAXLEN) {
		format_err("%s: \"%s\"", "wrong line length", line);
		return (-1);
	}
	/* carriage return */
	if (len == 1) {
		value[0] = line[0];
		return (0);
	}
	/* see P_MAXKEY and P_MAXVAL for string sizes */
	if (sscanf(line, "%19s %58s", key, value) != 2) {
		format_err("%s: \"%s\"", "wrong line format", line);
		return (-1);
	}
	if (strcmp(key, RDERR) == 0) {
		(void) strcpy(error, line + strlen(RDERR) + 1);
		return (-1);
	}
	return (0);
}

#define	STRUCT_TO_STR	1
#define	STR_TO_STRUCT	2

/*
 * if STR_TO_STRUCT read a 64 bit value from string buffer, format it and
 * write it into the structure.
 * if STRUCT_TO_STR read a 64 bit value from structure and write it as
 * a string into buffer.
 */
static int
format_int64(int set, char *buf, char *strct, int off)
{
	int64_t v;

	if (set == STR_TO_STRUCT) {
		if (sscanf(buf, "%" SCNd64, &v) != 1) {
			format_err("%s: \"%s\"", "wrong line format", line);
			return (-1);
		}
		*(int64_t *)(void *)(strct + off) = v;

	} else {
		v = *((int64_t *)(void *)(strct + off));
		(void) sprintf(buf, "%" PRId64, v);

	}
	return (0);
}

/*
 * if STR_TO_STRUCT read a 32 bit value from string buffer, format it and
 * write it into the structure.
 * if STRUCT_TO_STR read a 32 bit value from structure and write it as
 * a string into buffer.
 */
static int
format_int32(int set, char *buf, char *id, int off)
{
	int32_t v;

	if (set == STR_TO_STRUCT) {
		if (sscanf(buf, "%d", &v) != 1) {
			format_err("%s: \"%s\"", "wrong line format", line);
			return (-1);
		}
		*(int32_t *)(void *)(id + off) = v;

	} else {
		v = *((int32_t *)(void *)(id + off));
		(void) sprintf(buf, "%d", v);

	}
	return (0);
}

/*
 */
static int
format_ulong(int set, char *buf, char *id, int off)
{
	ulong_t v;

	if (set == STR_TO_STRUCT) {
		if (sscanf(buf, "%lu", &v) != 1) {
			format_err("%s: \"%s\"", "wrong line format", line);
			return (-1);
		}
		*(ulong_t *)(void *)(id + off) = v;

	} else {
		v = *((ulong_t *)(void *)(id + off));
		(void) sprintf(buf, "%ld", v);

	}
	return (0);
}

/*
 * if STR_TO_STRUCT read a float value from string buffer, format it and
 * write it into the structure.
 * if STRUCT_TO_STR read a float value from structure and write it as
 * a string into buffer.
 */
static int
format_float(int set, char *buf, char *id, int off)
{
	float v;

	if (set == STR_TO_STRUCT) {
		if (sscanf(buf, "%f", &v) != 1) {
			format_err("%s: \"%s\"", "wrong line format", line);
			return (-1);
		}
		*(float *)(void *)(id + off) = v;

	} else {
		v = *((float *)(void *)(id + off));
		(void) sprintf(buf, "%f", v);

	}
	return (0);
}

/*
 * if STR_TO_STRUCT read a double value from string buffer, format it and
 * write it into the structure.
 * if STRUCT_TO_STR read a double value from structure and write it as
 * a string into buffer.
 */
static int
format_double(int set, char *buf, char *id, int off)
{
	double v;

	if (set == STR_TO_STRUCT) {
		if (sscanf(buf, "%lf", &v) != 1) {
			format_err("wrong line format: \"%s\"", line);
			return (-1);
		}
		*(double *)(void *)(id + off) = v;

	} else {
		v = *((double *)(void *)(id + off));
		(void) sprintf(buf, "%f", v);

	}
	return (0);
}

/*
 * if STR_TO_STRUCT read a string from string buffer, format it and
 * write it into the structure.
 * if STRUCT_TO_STR read a string from structure and write it as
 * a string into buffer.
 */
static int
format_string(int set, char *buf, char *id, int off)
{
	char *v;

	if (set == STR_TO_STRUCT) {
		if ((v = (char *)malloc(strlen(buf) + 1))  != 0) {
			(void) strcpy(v, buf);
		} else {
			v = nullstr;
			return (-1);
		}
		*(char **)(void *)(id + off) = v;
	} else {
		if ((*((char **)(void *)(id + off))) != NULL) {
			(void) snprintf(buf, P_MAXVAL, "%s",
			    *((char **)(void *)(id + off)));
		}
	}
	return (0);
}

static int
format_timestruc(int set, char *buf, char *strct, int off)
{
	int64_t v1;
	int64_t v2;

	if (set == STR_TO_STRUCT) {
		if (sscanf(buf, "%" SCNd64 ",%" SCNd64, &v1, &v2) != 2) {
			format_err("%s: \"%s\"", "wrong line format", line);
			return (-1);
		}
		((timestruc_t *)(void *)(strct + off))->tv_sec = v1;
		((timestruc_t *)(void *)(strct + off))->tv_nsec = v2;

	} else {
		v1 = ((timestruc_t *)(void *)(strct + off))->tv_sec;
		/*
		 * Since the times in prusage start with millisecond
		 * precision after the micro state accounting was enabled
		 * discard the nano/micro second fraction in the saved
		 * values otherwise we will get negative values in next run.
		 */
		v2 = ((((timestruc_t *)(void *)(strct + off))->tv_nsec) /
			MICROSEC) * MICROSEC;
		(void) sprintf(buf, "%" PRId64 ",%" PRId64, v1, v2);

	}
	return (0);
}

/*
 * A hash table of keys == names and data == { formats and offsets }.
 */
static int
init_hashtab() {
	ENTRY item;
	int   i, j, size = 0;

	for (i = 0; i < NOF_STUBS + 1; i++) {
		size += stubs[i].size;
	}
	if (hcreate(size) == 0) {
		format_err("can't create hash table");
		return (-1);
	}
	for (i = 0; i < NOF_STUBS + 1; i++) {
		for (j = 0; j < stubs[i].size; j++) {
			item.key = stubs[i].stub[j].key;
			item.data = (void *) &(stubs[i].stub[j].info);
			if (hsearch(item, ENTER) == NULL) {
				format_err("can't insert into hash table");
				return (-1);
			}
		}
	}
	return (0);
}

int
open_prot(int fd, char *rw)
{
	if (strcmp(rw, "r") == 0) {
		if ((rstream = fdopen(fd, rw)) == NULL) {
			format_err("can't open read stream");
			return (-1);
		}
		if (init_hashtab() != 0) {
			format_err("can't initialize hashtab");
			return (-1);
		}
	} else if (strcmp(rw, "w") == 0) {
		if ((wstream = fdopen(fd, rw)) == NULL) {
			format_err("can't open write stream");
			return (-1);
		}
	} else {
		format_err("open_prot(), wrong argument  %s", rw);
			return (-1);
	}
	return (0);
}

void
close_prot()
{

	(void) fclose(rstream);
	(void) fclose(wstream);
	hdestroy();
}

/*
 * @RDS-MAG@
 * PROTV 100
 */
int
wr_phead()
{
	(void) fprintf(wstream, "%s\n%s %d\n",
	    PROTM, PROTV, PROT_VERSION);
	(void) fflush(wstream);
	return (0);
}
/*
 * @RDS@> [code]
 */
int
wr_prompt(char *code) {

	(void) fprintf(wstream, "%s%s\n", PROMPT, code);
	(void) fflush(wstream);
	return (0);
}

int
wr_lshead(int n)
{
	(void) fprintf(wstream, "%s %d\n", LISTN, n);
	(void) fflush(wstream);
	return (0);
}

/*
 * LISTT [type]
 * ELEMN [n]
 */
int
wr_lhead(int type, int n)
{
	(void) fprintf(wstream, "%s %d\n%s %d\n", LISTT, type, ELEMN, n);
	(void) fflush(wstream);
	return (0);
}
/*
 * ELMID [elemid]
 * FILDN [number of elements]
 * e.g.
 * id_usr 11050000000
 * id_sys 7850000000
 * id_ttime 0
 * id_tpftime 0
 *
 * Write all fields defined by stub[stubidx]. The src is the source pointer.
 * For each element read the key, grab the format function and the offset.
 * Read and format the element from the source and write it out as a string.
 */
int
wr_element(int stubidx, char *src, char *elemid)
{
	int i;

	(void) fprintf(wstream, "%s %s\n%s %d\n",
	    ELMID, elemid, FILDN, stubs[stubidx].size);
	for (i = 0; i < stubs[stubidx].size; i++) {
		stubs[stubidx].stub[i].info.format(STRUCT_TO_STR,
		    value, src, stubs[stubidx].stub[i].info.off);
		(void) fprintf(wstream, "%s %s\n",
		    stubs[stubidx].stub[i].key, value);
	}
	(void) fflush(wstream);
	return (0);
}

int
wr_string(char *str)
{

	(void) fprintf(wstream, "%s", str);
	(void) fflush(wstream);
	return (0);
}

int
wr_value(char *key, int64_t v)
{

	(void) fprintf(wstream, "%s %" PRId64 "\n", key, v);
	(void) fflush(wstream);
	return (0);
}
/*
 * RDERR [err]
 */
void
wr_error(char *err)
{
	size_t len = strlen(RDERR + 1);
	if (strlen(err) > P_MAXLEN - len) {
		*(err + P_MAXLEN - len - 4) = '.';
		*(err + P_MAXLEN - len - 3) = '.';
		*(err + P_MAXLEN - len - 2) = '.';
		*(err + P_MAXLEN - len - 1) = 0;
	}
	len = strlen(err) - 1;
	if (strlen(err) == 0) {
		return;
	}
	while (len-- > 0) {
		if (*(err + len) == '\n')
			*(err + len) = ' ';
	}

	(void) fprintf(wstream, "%s %s\n", RDERR, err);
	(void) fflush(wstream);
}

/*
 * read a protocol line, check the key and return the value associated
 * with it.
 */
int64_t
r_value(char *check_key) {
	int64_t v = -1;

	if ((r_line() == -1) ||
			(strcmp(check_key, key) != 0) ||
			(sscanf(value, "%" SCNd64, &v) != 1)) {
		return (-1);
	}
	return (v);
}

char *
r_cmd()
{

	if (r_line() == -1) {
		format_err("can't read command");
		return (NULL);
	}
	return (value);
}

int
r_phead()
{
	int protv;
	size_t len = strlen(PROTM);
	size_t errorlen = strlen(RDERR);
	int i = 0;

	while (i++ < MAX_RETRIES) {
		if (fgets(line, P_MAXLEN, rstream) == NULL) {
			format_err("can't read prot. head");
			return (-1);
		}
		len = strlen(line);
		if (len > P_MAXLEN)
			continue;
		if (strcmp(line, PROTM) == 0)
			break;
		if (strncmp(line, RDERR, errorlen) == 0) {
			(void) strcpy(error, line + strlen(RDERR) + 1);
			return (-1);
		}
	}
	if ((protv = r_value(PROTV)) == -1) {
		format_err("can't read prot. version");
		return (-1);
	}
	if (protv != PROT_VERSION) {
		format_err("unsupported prot. version");
		return (-1);
	}
	return (0);
}

int
r_lshead()
{
	int  ret;

	if ((ret = r_value(LISTN)) == -1) {
		format_err("can't read number of lists");
		return (-1);
	}
	return (ret);
}

int
r_lhead(int *type)
{

	if ((*type = r_value(LISTT)) == -1) {
		format_err("can't read list type");
		return (-1);
	}
	return (r_value(ELEMN));
}

int
r_element(char *src, char *elemid)
{
	int fn, i;
	ENTRY item, *fitem;

	if (r_line() == -1) {
		format_err("can't read element id");
		return (-1);
	} else {
		(void) strcpy(elemid, value);
	}
	if ((fn = r_value(FILDN)) == -1) {
		format_err("can't read number of fields");
		return (-1);
	}
	for (i = 0; i < fn; i++) {
		if (r_line() == -1) {
			return (-1);
		} else {
			item.key = key;
			if ((fitem = hsearch(item, FIND)) == NULL) {
				format_err("%s: \"%s\" ",
						"unknown key ", line);
				return (-1);
			}
			((info_t *)(void *)fitem->data)->
				format(STR_TO_STRUCT, value, src,
					((info_t *)(void *)fitem->data)->off);
			}
	}
	return (0);
}

int
skip_line()
{
	if (r_line() == -1) {
		format_err("can't read element id");
		return (-1);
	} else {
		return (0);
	}
}
