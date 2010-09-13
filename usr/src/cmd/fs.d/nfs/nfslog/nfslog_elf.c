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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * nfs log - read buffer file and print structs in user-readable form
 */

#define	_REENTRANT

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <sys/utsname.h>
#include <errno.h>
#include <time.h>
#include <limits.h>
#include <libintl.h>
#include <pwd.h>
#include <netdb.h>
#include <syslog.h>
#include <rpc/rpc.h>
#include <netconfig.h>
#include <netdir.h>
#include <nfs/nfs_sec.h>
#include <nfs/export.h>
#include <rpc/auth.h>
#include <rpc/svc.h>
#include <rpc/xdr.h>
#include <rpc/clnt.h>
#include <nfs/nfs.h>
#include <nfs/nfs_log.h>
#include "fhtab.h"
#include "nfslogd.h"

static char	empty_name[4] = "-";

static char ftype3_names[NF3FIFO + 1][20] = {
	"\"none\"", "\"file\"", "\"dir\"", "\"blk device\"",
	"\"chr device\"", "\"link\"", "\"socket\"", "\"fifo\""
};

#define	NFSL_FTYPE3(ftype)						\
	((((ftype) >= 0) && ((ftype) <= NF3FIFO)) ?			\
	ftype3_names[ftype] : empty_name)

static char createmode3_names[EXCLUSIVE + 1][20] = {
	"\"unchecked", "\"guarded\"", "\"exclusive\""
};

#define	NFSL_CREATEMODE3(createmode)					\
	((((createmode) >= 0) && ((createmode) <= EXCLUSIVE)) ?		\
	createmode3_names[createmode] : empty_name)

static char	auth_flavor_name[RPCSEC_GSS + 1][20] = {
	"\"auth_null\"", "\"auth_unix\"", "\"auth_short\"", "\"auth_des\"",
	"\"auth_kerb\"", "\"none\"", "\"rpcsec_gss\""
};

#define	NFSL_AUTH_FLAVOR_PRINT(auth_flavor)				\
	(((auth_flavor) <= RPCSEC_GSS) ?				\
	auth_flavor_name[auth_flavor] : empty_name)

#define	NFSL_ERR_CNT		31	/* Actual err numbers */

/*
 * Two arrays - one short ints containing err codes, the other the strings
 * (merged codes for both v2 and v3
 */
static char	nfsl_status_name[NFSL_ERR_CNT][30] = {
	"\"ok\"", "\"perm\"", "\"noent\"", "\"io\"",
	"\"nxio\"", "\"access\"", "\"exist\"", "\"xdev\"",
	"\"nodev\"", "\"notdir\"", "\"isdir\"", "\"inval\"",
	"\"fbig\"", "\"nospc\"", "\"rofs\"", "\"mlink\"",
	"\"notsupp\"", "\"nametoolong\"", "\"notempty\"", "\"dquot\"",
	"\"stale\"", "\"remote\"", "\"wflush\"", "\"badhandle\"",
	"\"not_sync\"", "\"bad_cookie\"", "\"notsupp\"", "\"toosmall\"",
	"\"serverfault\"", "\"badtype\"", "\"jukebox\"",
};

static short	nfsl_status[NFSL_ERR_CNT] = {
	0, 1, 2, 5, 6, 13, 17, 18,
	19, 20, 21, 22, 27, 28, 30, 31,
	45, 63, 66, 69, 70, 71, 99, 10001,
	10002, 10003, 10004, 10005, 10006, 10007, 10008
};

/* list of open elf files */
static struct nfsl_log_file	*elf_file_list = NULL;

/* Imported functions */
extern void bcopy(const void *s1, void *s2, size_t n);

/* Static functions */
static void nfsl_log_file_free(struct nfsl_log_file *elfrec);
static void nfsl_log_file_add(struct nfsl_log_file *elfrec,
	struct nfsl_log_file **elf_listp);
static struct nfsl_log_file *nfsl_log_file_find(struct nfsl_log_file *elfrec,
	struct nfsl_log_file *elf_list);
static struct nfsl_log_file *nfsl_log_file_del(struct nfsl_log_file *elfrec,
	struct nfsl_log_file **elf_listp);

static char *nfsl_get_time(time_t tt);
static char *nfsl_get_date(time_t tt);
static char *nfsl_get_date_nq(time_t tt);
static int nfsl_write_elfbuf(struct nfsl_log_file *elfrec);
static void nfsl_ipaddr_print(struct nfsl_log_file *, struct netbuf *);
static void nfsl_elf_record_header_print(struct nfsl_log_file *,
		nfslog_record_header *, char *, char *,
		struct nfsl_proc_disp *, char *);
static void nfsl_elf_buffer_header_print(struct nfsl_log_file *,
		nfslog_buffer_header *);
static struct nfsl_proc_disp *nfsl_find_elf_dispatch(
		nfslog_request_record *, char **);
static void nfsl_elf_rpc_print(struct nfsl_log_file *,
		nfslog_request_record *, struct nfsl_proc_disp *,
		char *, char *, char *);
static void nfslog_size3_print(struct nfsl_log_file *, set_size3 *);

static void nfslog_null_args(struct nfsl_log_file *, caddr_t *);
static void nfslog_null_res(struct nfsl_log_file *, caddr_t *);


/*
 * NFS VERSION 2
 */

/* Functions for elf print of the arguments */
static void nfslog_fhandle_print(struct nfsl_log_file *, fhandle_t *);
static void nfslog_diropargs_print(struct nfsl_log_file *, nfslog_diropargs *);
static void nfslog_setattrargs_print(struct nfsl_log_file *,
	nfslog_setattrargs *);
static void nfslog_sattr_print(struct nfsl_log_file *,
	nfslog_sattr *);
static void nfslog_nfsreadargs_print(struct nfsl_log_file *,
	nfslog_nfsreadargs *);
static void nfslog_writeargs_print(struct nfsl_log_file *,
	nfslog_writeargs *);
static void nfslog_writeresult_print(struct nfsl_log_file *,
	nfslog_writeresult *, bool_t);
static void nfslog_creatargs_print(struct nfsl_log_file *,
	nfslog_createargs *);
static void nfslog_rddirargs_print(struct nfsl_log_file *, nfslog_rddirargs *);
static void nfslog_linkargs_print(struct nfsl_log_file *, nfslog_linkargs *);
static void nfslog_rnmargs_print(struct nfsl_log_file *, nfslog_rnmargs *);
static void nfslog_symlinkargs_print(struct nfsl_log_file *,
	nfslog_symlinkargs *);

static void nfslog_sharefsargs_print(struct nfsl_log_file *,
	nfslog_sharefsargs *);
static void nfslog_getfhargs_print(struct nfsl_log_file *,
	nfslog_getfhargs *);

/* Functions for elf print of the response */
static void nfslog_nfsstat_print(struct nfsl_log_file *, enum nfsstat *,
	bool_t);
static void nfslog_diropres_print(struct nfsl_log_file *, nfslog_diropres *,
	bool_t);
static void nfslog_rdlnres_print(struct nfsl_log_file *, nfslog_rdlnres *,
	bool_t);
static void nfslog_rdresult_print(struct nfsl_log_file *,
	nfslog_rdresult *, bool_t);
static void nfslog_rddirres_print(struct nfsl_log_file *, nfslog_rddirres *,
	bool_t);

/*
 * NFS VERSION 3
 */

/* Functions for elf print of the arguments */
static void nfslog_fh3_print(struct nfsl_log_file *, nfs_fh3 *);
static void nfslog_diropargs3_print(struct nfsl_log_file *,
	nfslog_diropargs3 *);
static void nfslog_SETATTR3args_print(struct nfsl_log_file *,
	nfslog_SETATTR3args *);
static void nfslog_READ3args_print(struct nfsl_log_file *, nfslog_READ3args *);
static void nfslog_WRITE3args_print(struct nfsl_log_file *,
	nfslog_WRITE3args *);
static void nfslog_CREATE3args_print(struct nfsl_log_file *,
	nfslog_CREATE3args *);
static void nfslog_MKDIR3args_print(struct nfsl_log_file *,
	nfslog_MKDIR3args *);
static void nfslog_SYMLINK3args_print(struct nfsl_log_file *,
	nfslog_SYMLINK3args *);
static void nfslog_MKNOD3args_print(struct nfsl_log_file *,
	nfslog_MKNOD3args *);
static void nfslog_REMOVE3args_print(struct nfsl_log_file *,
	nfslog_REMOVE3args *);
static void nfslog_RMDIR3args_print(struct nfsl_log_file *,
	nfslog_RMDIR3args *);
static void nfslog_RENAME3args_print(struct nfsl_log_file *,
	nfslog_RENAME3args *);
static void nfslog_LINK3args_print(struct nfsl_log_file *,
	nfslog_LINK3args *);
static void nfslog_COMMIT3args_print(struct nfsl_log_file *,
	nfslog_COMMIT3args *);
static void nfslog_READDIRPLUS3args_print(struct nfsl_log_file *,
	nfslog_READDIRPLUS3args *);

/* Functions for elf print of the response */
static void nfslog_nfsstat3_print(struct nfsl_log_file *,
	nfsstat3 *, bool_t);
static void nfslog_LOOKUP3res_print(struct nfsl_log_file *,
	nfslog_LOOKUP3res *, bool_t);
static void nfslog_READLINK3res_print(struct nfsl_log_file *,
	nfslog_READLINK3res *, bool_t);
static void nfslog_READ3res_print(struct nfsl_log_file *,
	nfslog_READ3res *, bool_t);
static void nfslog_WRITE3res_print(struct nfsl_log_file *,
	nfslog_WRITE3res *, bool_t);
static void nfslog_CREATE3res_print(struct nfsl_log_file *,
	nfslog_CREATE3res *, bool_t);
static void nfslog_MKDIR3res_print(struct nfsl_log_file *,
	nfslog_MKDIR3res *, bool_t);
static void nfslog_SYMLINK3res_print(struct nfsl_log_file *,
	nfslog_SYMLINK3res *, bool_t);
static void nfslog_MKNOD3res_print(struct nfsl_log_file *,
	nfslog_MKNOD3res *, bool_t);
static void nfslog_READDIRPLUS3res_print(struct nfsl_log_file *,
	nfslog_READDIRPLUS3res *, bool_t);

extern int debug;
static bool_t nfsl_print_fh = FALSE;		/* print file handles? */

#define	DFLT_BUFFERSIZE		8192
#define	DFLT_OVFSIZE		3072	/* Maximum logged or buffered size */

static char hostname[MAXHOSTNAMELEN];	/* name of host */


/*
 * Define the actions taken per prog/vers/proc:
 *
 * In some cases, the nl types are the same as the nfs types and a simple
 * bcopy should suffice. Rather that define tens of identical procedures,
 * simply define these to bcopy. Similarly this takes care of different
 * procs that use same parameter struct.
 */

static struct nfsl_proc_disp nfsl_elf_proc_v2[] = {
	/*
	 * NFS VERSION 2
	 */

	/* RFS_NULL = 0 */
	{nfslog_null_args, nfslog_null_res, "\"null\""},

	/* RFS_GETATTR = 1 */
	{nfslog_fhandle_print, nfslog_nfsstat_print, "\"getattr\""},

	/* RFS_SETATTR = 2 */
	{nfslog_setattrargs_print, nfslog_nfsstat_print, "\"setattr\""},

	/* RFS_ROOT = 3 *** NO LONGER SUPPORTED *** */
	{nfslog_null_args, nfslog_null_res, "\"root\""},

	/* RFS_LOOKUP = 4 */
	{nfslog_diropargs_print, nfslog_diropres_print, "\"lookup\""},

	/* RFS_READLINK = 5 */
	{nfslog_fhandle_print, nfslog_rdlnres_print, "\"readlink\""},

	/* RFS_READ = 6 */
	{nfslog_nfsreadargs_print, nfslog_rdresult_print, "\"read\""},

	/* RFS_WRITECACHE = 7 *** NO LONGER SUPPORTED *** */
	{nfslog_null_args, nfslog_null_res, "\"writecache\""},

	/* RFS_WRITE = 8 */
	{nfslog_writeargs_print, nfslog_writeresult_print, "\"write\""},

	/* RFS_CREATE = 9 */
	{nfslog_creatargs_print, nfslog_diropres_print, "\"create\""},

	/* RFS_REMOVE = 10 */
	{nfslog_diropargs_print, nfslog_nfsstat_print, "\"remove\""},

	/* RFS_RENAME = 11 */
	{nfslog_rnmargs_print, nfslog_nfsstat_print, "\"rename\""},

	/* RFS_LINK = 12 */
	{nfslog_linkargs_print, nfslog_nfsstat_print, "\"link\""},

	/* RFS_SYMLINK = 13 */
	{nfslog_symlinkargs_print, nfslog_nfsstat_print, "\"symlink\""},

	/* RFS_MKDIR = 14 */
	{nfslog_creatargs_print, nfslog_diropres_print, "\"mkdir\""},

	/* RFS_RMDIR = 15 */
	{nfslog_diropargs_print, nfslog_nfsstat_print, "\"rmdir\""},

	/* RFS_READDIR = 16 */
	{nfslog_rddirargs_print, nfslog_rddirres_print, "\"readdir\""},

	/* RFS_STATFS = 17 */
	{nfslog_fhandle_print, nfslog_nfsstat_print, "\"statfs\""},
};


/*
 * NFS VERSION 3
 */

static struct nfsl_proc_disp nfsl_elf_proc_v3[] = {

	/* NFSPROC3_NULL = 0 */
	{nfslog_null_args, nfslog_null_res, "\"null\""},

	/* NFSPROC3_GETATTR = 1 */
	{nfslog_fh3_print, nfslog_nfsstat3_print, "\"getattr\""},

	/* NFSPROC3_SETATTR = 2 */
	{nfslog_SETATTR3args_print, nfslog_nfsstat3_print, "\"setattr\""},

	/* NFSPROC3_LOOKUP = 3 */
	{nfslog_diropargs3_print, nfslog_LOOKUP3res_print, "\"lookup\""},

	/* NFSPROC3_ACCESS = 4 */
	{nfslog_fh3_print, nfslog_nfsstat3_print, "\"access\""},

	/* NFSPROC3_READLINK = 5 */
	{nfslog_fh3_print, nfslog_READLINK3res_print, "\"readlink\""},

	/* NFSPROC3_READ = 6 */
	{nfslog_READ3args_print, nfslog_READ3res_print, "\"read\""},

	/* NFSPROC3_WRITE = 7 */
	{nfslog_WRITE3args_print, nfslog_WRITE3res_print, "\"write\""},

	/* NFSPROC3_CREATE = 8 */
	{nfslog_CREATE3args_print, nfslog_CREATE3res_print, "\"create\""},

	/* NFSPROC3_MKDIR = 9 */
	{nfslog_MKDIR3args_print, nfslog_MKDIR3res_print, "\"mkdir\""},

	/* NFSPROC3_SYMLINK = 10 */
	{nfslog_SYMLINK3args_print, nfslog_SYMLINK3res_print, "\"symlink\""},

	/* NFSPROC3_MKNOD = 11 */
	{nfslog_MKNOD3args_print, nfslog_MKNOD3res_print, "\"mknod\""},

	/* NFSPROC3_REMOVE = 12 */
	{nfslog_REMOVE3args_print, nfslog_nfsstat3_print, "\"remove\""},

	/* NFSPROC3_RMDIR = 13 */
	{nfslog_RMDIR3args_print, nfslog_nfsstat3_print, "\"rmdir\""},

	/* NFSPROC3_RENAME = 14 */
	{nfslog_RENAME3args_print, nfslog_nfsstat3_print, "\"rename\""},

	/* NFSPROC3_LINK = 15 */
	{nfslog_LINK3args_print, nfslog_nfsstat3_print, "\"link\""},

	/* NFSPROC3_READDIR = 16 */
	{nfslog_fh3_print, nfslog_nfsstat3_print, "\"readdir\""},

	/* NFSPROC3_READDIRPLUS = 17 */
	{nfslog_READDIRPLUS3args_print, nfslog_READDIRPLUS3res_print,
		"\"readdirplus\""},

	/* NFSPROC3_FSSTAT = 18 */
	{nfslog_fh3_print, nfslog_nfsstat3_print, "\"fsstat\""},

	/* NFSPROC3_FSINFO = 19 */
	{nfslog_fh3_print, nfslog_nfsstat3_print, "\"fsinfo\""},

	/* NFSPROC3_PATHCONF = 20 */
	{nfslog_fh3_print, nfslog_nfsstat3_print, "\"pathconf\""},

	/* NFSPROC3_COMMIT = 21 */
	{nfslog_COMMIT3args_print, nfslog_nfsstat3_print, "\"commit\""},
};

/*
 * NFSLOG VERSION 1
 */

static struct nfsl_proc_disp nfsl_log_elf_proc_v1[] = {

	/* NFSLOG_NULL = 0 */
	{nfslog_null_args, nfslog_null_res, "\"null\""},

	/* NFSLOG_SHARE = 1 */
	{nfslog_sharefsargs_print, nfslog_nfsstat_print, "\"log_share\""},

	/* NFSLOG_UNSHARE = 2 */
	{nfslog_sharefsargs_print, nfslog_nfsstat_print, "\"log_unshare\""},

	/* NFSLOG_LOOKUP = 3 */
	{nfslog_diropargs3_print, nfslog_LOOKUP3res_print, "\"lookup\""},

	/* NFSLOG_GETFH = 4 */
	{nfslog_getfhargs_print, nfslog_nfsstat_print, "\"log_getfh\""},
};

static struct nfsl_vers_disp nfsl_elf_vers_disptable[] = {
	{sizeof (nfsl_elf_proc_v2) / sizeof (nfsl_elf_proc_v2[0]),
	    nfsl_elf_proc_v2},
	{sizeof (nfsl_elf_proc_v3) / sizeof (nfsl_elf_proc_v3[0]),
	    nfsl_elf_proc_v3},
};

static struct nfsl_vers_disp nfsl_log_elf_vers_disptable[] = {
	{sizeof (nfsl_log_elf_proc_v1) / sizeof (nfsl_log_elf_proc_v1[0]),
	    nfsl_log_elf_proc_v1},
};

static struct nfsl_prog_disp nfsl_elf_dispatch_table[] = {
	{NFS_PROGRAM,
	    NFS_VERSMIN,
	    sizeof (nfsl_elf_vers_disptable) /
		sizeof (nfsl_elf_vers_disptable[0]),
	    nfsl_elf_vers_disptable, "nfs"},
	{NFSLOG_PROGRAM,
	    NFSLOG_VERSMIN,
	    sizeof (nfsl_log_elf_vers_disptable) /
		sizeof (nfsl_log_elf_vers_disptable[0]),
	    nfsl_log_elf_vers_disptable, "nfslog"},
};

static int	nfsl_elf_dispatch_table_arglen =
			sizeof (nfsl_elf_dispatch_table) /
			sizeof (nfsl_elf_dispatch_table[0]);

static char *
nfslog_get_status(short status)
{
	int	low, mid, high;
	short	errstat;

	/* Usually status is 0... */
	if (status == 0)
		return (nfsl_status_name[0]);

	low = 0;
	high = NFSL_ERR_CNT;
	mid = NFSL_ERR_CNT / 2;
	/* binary search for status string */
	while (((errstat = nfsl_status[mid]) != status) && (low < mid) &&
		(mid < high)) {
		if (errstat > status) {	/* search bottom half */
			high = mid;
		} else {		/* search upper half */
			low = mid;
		}
		mid = low + ((high - low) / 2);
	}
	if (errstat == status) {	/* found it */
		return (nfsl_status_name[mid]);
	}
	return (NULL);
}

/* nfsl_get_time - return string with time formatted as hh:mm:ss */
static char *
nfsl_get_time(time_t tt)
{
	static char	timestr[20];
	static time_t	lasttime;
	struct tm	tmst;

	if (tt == lasttime)
		return (timestr);
	if (localtime_r(&tt, &tmst) == NULL) {
		return (empty_name);
	}
	(void) sprintf(timestr, "%02d:%02d:%02d",
		tmst.tm_hour, tmst.tm_min, tmst.tm_sec);
	lasttime = tt;
	return (timestr);
}

/* nfsl_get_date - return date string formatted as "yyyy-mm-dd hh:mm:ss" */
static char *
nfsl_get_date(time_t tt)
{
	static char	timestr[30];
	static time_t	lasttime;
	struct tm	tmst;

	if (tt == lasttime)
		return (timestr);
	if (localtime_r(&tt, &tmst) == NULL) {
		return (empty_name);
	}
	(void) sprintf(timestr, "\"%04d-%02d-%02d %02d:%02d:%02d\"",
		tmst.tm_year + 1900, tmst.tm_mon + 1, tmst.tm_mday,
		tmst.tm_hour, tmst.tm_min, tmst.tm_sec);
	lasttime = tt;
	return (timestr);
}

/*
 * nfsl_get_date_nq - return date string formatted as yyyy-mm-dd hh:mm:ss
 * (no quotes)
 */
static char *
nfsl_get_date_nq(time_t tt)
{
	static char	timestr[30];
	static time_t	lasttime;
	struct tm	tmst;

	if (tt == lasttime)
		return (timestr);
	if (localtime_r(&tt, &tmst) == NULL) {
		return (empty_name);
	}
	(void) sprintf(timestr, "%04d-%02d-%02d %02d:%02d:%02d",
		tmst.tm_year + 1900, tmst.tm_mon + 1, tmst.tm_mday,
		tmst.tm_hour, tmst.tm_min, tmst.tm_sec);
	return (timestr);
}

/* write log buffer out to file */
static int
nfsl_write_elfbuf(struct nfsl_log_file *elfrec)
{
	int	rc;
	char	*elfbuf = elfrec->buf;
	int	elfbufoffset = elfrec->bufoffset;

	if (debug > 1)
		(void) printf("nfsl_write_elfbuf: bufoffset %d\n",
			elfbufoffset);
	if (elfbufoffset <= 0)
		return (0);
	elfbuf[elfbufoffset] = '\0';
	if ((rc = fputs(elfbuf, elfrec->fp)) < 0) {
		syslog(LOG_ERR, gettext("Write to %s failed: %s\n"),
			elfrec->path, strerror(errno));
		return (-1);
	}
	if (rc != elfbufoffset) {
		syslog(LOG_ERR, gettext("Write %d bytes to %s returned %d\n"),
			elfbufoffset, elfrec->path, rc);
		return (-1);
	}
	elfrec->bufoffset = 0;
	return (0);
}

/*ARGSUSED*/
static void
nfslog_null_args(struct nfsl_log_file *elfrec, caddr_t *nfsl_args)
{
}

/*ARGSUSED*/
static void
nfslog_null_res(struct nfsl_log_file *elfrec, caddr_t *nfsl_res)
{
}

static void
nfslog_fh3_print(struct nfsl_log_file *elfrec, nfs_fh3 *fh3)
{
	if (!nfsl_print_fh)
		return;
	if (fh3->fh3_length == sizeof (fhandle_t)) {
		nfslog_fhandle_print(elfrec, (fhandle_t *)&fh3->fh3_u.data);
	} else {
		nfslog_opaque_print_buf(fh3->fh3_u.data, fh3->fh3_length,
			elfrec->buf, &elfrec->bufoffset,
			DFLT_BUFFERSIZE + DFLT_OVFSIZE);
	}
}

/*
 * NFS VERSION 2
 */


/* Functions that elf print the arguments */

static void
nfslog_fhandle_print(struct nfsl_log_file *elfrec, fhandle_t *args)
{
	if (!nfsl_print_fh)
		return;
	nfslog_opaque_print_buf(args, sizeof (*args),
			elfrec->buf, &elfrec->bufoffset,
			DFLT_BUFFERSIZE + DFLT_OVFSIZE);
}

static void
nfslog_diropargs_print(struct nfsl_log_file *elfrec, nfslog_diropargs *args)
{
	char	*elfbuf = elfrec->buf;
	int	elfbufoffset = elfrec->bufoffset;

	if (nfsl_print_fh) {
		nfslog_fhandle_print(elfrec, &args->da_fhandle);
		elfbufoffset = elfrec->bufoffset;
		if (args->da_name != NULL) {
			elfbufoffset += sprintf(&elfbuf[elfbufoffset],
				" \"%s\"", args->da_name);
		} else {
			elfbufoffset += sprintf(&elfbuf[elfbufoffset], " %s",
				empty_name);
		}
	}
	elfrec->bufoffset = elfbufoffset;
}

static void
nfslog_sattr_print(struct nfsl_log_file *elfrec, nfslog_sattr *args)
{
	char	*elfbuf = elfrec->buf;
	int	elfbufoffset = elfrec->bufoffset;

/* BEGIN CSTYLED */
	if (args->sa_mode != (uint32_t)-1) {
		elfbufoffset += sprintf(&elfbuf[elfbufoffset],
			" \"mode=0%o\"", args->sa_mode);
	}
	if (args->sa_uid != (uint32_t)-1) {
		elfbufoffset += sprintf(&elfbuf[elfbufoffset],
			" \"uid=0x%x\"", args->sa_uid);
	}
	if (args->sa_gid != (uint32_t)-1) {
		elfbufoffset += sprintf(&elfbuf[elfbufoffset],
			" \"gid=0x%x\"", args->sa_gid);
	}
	if (args->sa_size != (uint32_t)-1) {
		elfbufoffset += sprintf(&elfbuf[elfbufoffset],
			" \"size=0x%x\"", args->sa_size);
	}
	if (args->sa_atime.tv_sec != (uint32_t)-1) {
		elfbufoffset += sprintf(&elfbuf[elfbufoffset],
			" \"atime=%s\"",
		    nfsl_get_date_nq((time_t)args->sa_atime.tv_sec));
	}
	if (args->sa_mtime.tv_sec != (uint32_t)-1) {
		elfbufoffset += sprintf(&elfbuf[elfbufoffset],
			" \"mtime=%s\"",
		    nfsl_get_date_nq((time_t)args->sa_mtime.tv_sec));
	}
/* END CSTYLED */
	elfrec->bufoffset = elfbufoffset;
}

static void
nfslog_setattrargs_print(struct nfsl_log_file *elfrec, nfslog_setattrargs *args)
{
	nfslog_fhandle_print(elfrec, &args->saa_fh);
	nfslog_sattr_print(elfrec, &args->saa_sa);
}

static void
nfslog_nfsreadargs_print(struct nfsl_log_file *elfrec,
	nfslog_nfsreadargs *args)
{
	char	*elfbuf = elfrec->buf;
	int	elfbufoffset;

	nfslog_fhandle_print(elfrec, &args->ra_fhandle);
	elfbufoffset = elfrec->bufoffset;
	elfbufoffset += sprintf(&elfbuf[elfbufoffset], " 0x%x",
		args->ra_offset);
	elfbufoffset += sprintf(&elfbuf[elfbufoffset], " 0x%x",
		args->ra_count);
	elfbufoffset += sprintf(&elfbuf[elfbufoffset], " 0x%x",
		args->ra_totcount);
	elfrec->bufoffset = elfbufoffset;
}

static void
nfslog_writeargs_print(struct nfsl_log_file *elfrec, nfslog_writeargs *args)
{
	char	*elfbuf = elfrec->buf;
	int	elfbufoffset = elfrec->bufoffset;

	nfslog_fhandle_print(elfrec, &args->waargs_fhandle);
	elfbufoffset = elfrec->bufoffset;
	elfbufoffset += sprintf(&elfbuf[elfbufoffset], " 0x%x",
		args->waargs_begoff);
	elfbufoffset += sprintf(&elfbuf[elfbufoffset], " 0x%x",
		args->waargs_offset);
	elfbufoffset += sprintf(&elfbuf[elfbufoffset], " 0x%x",
		args->waargs_totcount);
	elfrec->bufoffset += sprintf(&elfrec->buf[elfrec->bufoffset], " 0x%x",
		args->waargs_count);
}

static void
nfslog_writeresult_print(struct nfsl_log_file *elfrec, nfslog_writeresult *res,
	bool_t print_status)
{
	char	*elfbuf = elfrec->buf;
	int	elfbufoffset = elfrec->bufoffset;

	if (print_status) {
		nfslog_nfsstat_print(elfrec, &res->wr_status, print_status);
	} else if (res->wr_status == NFS_OK) {
		elfbufoffset += sprintf(&elfbuf[elfbufoffset], " 0x%x",
			res->nfslog_writeresult_u.wr_size);
		elfrec->bufoffset = elfbufoffset;
	}
}

static void
nfslog_creatargs_print(struct nfsl_log_file *elfrec, nfslog_createargs *args)
{
	nfslog_diropargs_print(elfrec, &args->ca_da);
	nfslog_sattr_print(elfrec, &args->ca_sa);
}


static void
nfslog_rddirargs_print(struct nfsl_log_file *elfrec, nfslog_rddirargs *args)
{
	char	*elfbuf = elfrec->buf;
	int	elfbufoffset;

	nfslog_fhandle_print(elfrec, &args->rda_fh);
	elfbufoffset = elfrec->bufoffset;
	elfbufoffset += sprintf(&elfbuf[elfbufoffset], " 0x%x",
		args->rda_offset);
	elfbufoffset += sprintf(&elfbuf[elfbufoffset], " 0x%x",
		args->rda_count);
	elfrec->bufoffset = elfbufoffset;
}

static void
nfslog_rnmargs_print(struct nfsl_log_file *elfrec, nfslog_rnmargs *args)
{
	nfslog_diropargs_print(elfrec, &args->rna_from);
	nfslog_diropargs_print(elfrec, &args->rna_to);
}

static void
nfslog_linkargs_print(struct nfsl_log_file *elfrec, nfslog_linkargs *args)
{
	nfslog_fhandle_print(elfrec, &args->la_from);
	nfslog_diropargs_print(elfrec, &args->la_to);
}

static void
nfslog_symlinkargs_print(struct nfsl_log_file *elfrec, nfslog_symlinkargs *args)
{
	char	*elfbuf = elfrec->buf;
	int	elfbufoffset;

	nfslog_diropargs_print(elfrec, &args->sla_from);
	elfbufoffset = elfrec->bufoffset;
	elfbufoffset += sprintf(&elfbuf[elfbufoffset], " \"%s\"",
		args->sla_tnm);
	elfrec->bufoffset = elfbufoffset;
	nfslog_sattr_print(elfrec, &args->sla_sa);
}

/*
 * SHARE/UNSHARE fs log args copy
 */
static void
nfslog_sharefsargs_print(struct nfsl_log_file *elfrec,
	nfslog_sharefsargs *args)
{
	unsigned int	elfbufoffset;
	char		*elfbuf = elfrec->buf;

	nfslog_fhandle_print(elfrec, &args->sh_fh_buf);

	elfbufoffset = elfrec->bufoffset;
	elfbufoffset += sprintf(&elfbuf[elfbufoffset], " 0x%x",
		args->sh_flags);
	elfbufoffset += sprintf(&elfbuf[elfbufoffset], " 0x%x",
		args->sh_anon);
	if (nfsl_print_fh) {
		if (args->sh_path != NULL) {
			elfbufoffset += sprintf(&elfbuf[elfbufoffset],
				" \"%s\"", args->sh_path);
		} else {
			elfbufoffset += sprintf(&elfbuf[elfbufoffset], " %s",
				empty_name);
		}
	}
	elfrec->bufoffset = elfbufoffset;
}

static void
nfslog_getfhargs_print(struct nfsl_log_file *elfrec,
	nfslog_getfhargs *args)
{
	unsigned int	elfbufoffset;
	char		*elfbuf = elfrec->buf;

	nfslog_fhandle_print(elfrec, &args->gfh_fh_buf);

	elfbufoffset = elfrec->bufoffset;
	if (nfsl_print_fh) {
		if (args->gfh_path != NULL) {
			elfbufoffset += sprintf(&elfbuf[elfbufoffset],
				" \"%s\"", args->gfh_path);
		} else {
			elfbufoffset += sprintf(&elfbuf[elfbufoffset], " %s",
				empty_name);
		}
	}
	elfrec->bufoffset = elfbufoffset;
}

static void
nfslog_nfsstat_print(struct nfsl_log_file *elfrec, enum nfsstat *res,
	bool_t print_status)
{
	if (print_status) {
		char	*statp = nfslog_get_status((short)(*res));

		if (statp != NULL)
			elfrec->bufoffset +=
				sprintf(&elfrec->buf[elfrec->bufoffset], " %s",
						statp);
		else
			elfrec->bufoffset +=
				sprintf(&elfrec->buf[elfrec->bufoffset], " %5d",
						*res);
	}
}

static void
nfslog_diropres_print(struct nfsl_log_file *elfrec, nfslog_diropres *res,
	bool_t print_status)
{
	if (print_status) {
		nfslog_nfsstat_print(elfrec, &res->dr_status, print_status);
	} else if (res->dr_status == NFS_OK) {
		nfslog_fhandle_print(elfrec,
			&res->nfslog_diropres_u.dr_ok.drok_fhandle);
	}
}

static void
nfslog_rdlnres_print(struct nfsl_log_file *elfrec, nfslog_rdlnres *res,
	bool_t print_status)
{
	if (print_status) {
		nfslog_nfsstat_print(elfrec, &res->rl_status, print_status);
	} else if (res->rl_status == NFS_OK) {
		elfrec->bufoffset += sprintf(&elfrec->buf[elfrec->bufoffset],
			" \"%s\"", res->nfslog_rdlnres_u.rl_ok);
	}
}

static void
nfslog_rdresult_print(struct nfsl_log_file *elfrec, nfslog_rdresult *res,
	bool_t print_status)
{
	if (print_status) {
		nfslog_nfsstat_print(elfrec, &res->r_status, print_status);
	} else if (res->r_status == NFS_OK) {
		elfrec->bufoffset += sprintf(&elfrec->buf[elfrec->bufoffset],
			" 0x%x", res->nfslog_rdresult_u.r_ok.filesize);
		elfrec->bufoffset += sprintf(&elfrec->buf[elfrec->bufoffset],
			" 0x%x", res->nfslog_rdresult_u.r_ok.rrok_count);
	}
}

static void
nfslog_rddirres_print(struct nfsl_log_file *elfrec, nfslog_rddirres *res,
	bool_t print_status)
{
	if (print_status) {
		nfslog_nfsstat_print(elfrec, &res->rd_status, print_status);
	} else if (res->rd_status == NFS_OK) {
		char	*elfbuf = elfrec->buf;
		int	elfbufoffset = elfrec->bufoffset;

		elfbufoffset += sprintf(&elfbuf[elfbufoffset], " 0x%x",
			res->nfslog_rddirres_u.rd_ok.rdok_offset);
		elfbufoffset += sprintf(&elfbuf[elfbufoffset], " 0x%x",
			res->nfslog_rddirres_u.rd_ok.rdok_size);
		elfbufoffset += sprintf(&elfbuf[elfbufoffset], " 0x%x",
			res->nfslog_rddirres_u.rd_ok.rdok_eof);
		elfrec->bufoffset = elfbufoffset;
	}
}

/*
 * NFS VERSION 3
 */

static void
nfslog_diropargs3_print(struct nfsl_log_file *elfrec,
	nfslog_diropargs3 *args)
{
	if (nfsl_print_fh) {
		nfslog_fh3_print(elfrec, &args->dir);
		elfrec->bufoffset += sprintf(&elfrec->buf[elfrec->bufoffset],
			" \"%s\"", args->name);
	}
}

static void
nfslog_size3_print(struct nfsl_log_file *elfrec, set_size3 *args)
{
	char	*elfbuf = elfrec->buf;
	int	elfbufoffset = elfrec->bufoffset;

	if (args->set_it) {
		elfbufoffset += sprintf(&elfbuf[elfbufoffset],
		/* CSTYLED */
			" \"size=0x%llx\"", args->size);
	}
	elfrec->bufoffset = elfbufoffset;
}

static void
nfslog_SETATTR3args_print(struct nfsl_log_file *elfrec,
	nfslog_SETATTR3args *args)
{
	nfslog_fh3_print(elfrec, &args->object);
	nfslog_size3_print(elfrec, &args->size);
}

static void
nfslog_READ3args_print(struct nfsl_log_file *elfrec, nfslog_READ3args *args)
{
	nfslog_fh3_print(elfrec, &args->file);
	elfrec->bufoffset += sprintf(&elfrec->buf[elfrec->bufoffset], " 0x%llx",
		args->offset);
	elfrec->bufoffset += sprintf(&elfrec->buf[elfrec->bufoffset], " 0x%x",
		args->count);
}

static void
nfslog_WRITE3args_print(struct nfsl_log_file *elfrec,
	nfslog_WRITE3args *args)
{
	char	*elfbuf = elfrec->buf;
	int	elfbufoffset;

	nfslog_fh3_print(elfrec, &args->file);
	elfbufoffset = elfrec->bufoffset;
	elfbufoffset += sprintf(&elfbuf[elfbufoffset], " 0x%llx",
		args->offset);
	elfbufoffset += sprintf(&elfbuf[elfbufoffset], " 0x%x",
		args->count);
	elfbufoffset += sprintf(&elfbuf[elfbufoffset], " 0x%x",
		args->stable);
	elfrec->bufoffset = elfbufoffset;
}

static void
nfslog_CREATE3args_print(struct nfsl_log_file *elfrec,
	nfslog_CREATE3args *args)
{
	nfslog_diropargs3_print(elfrec, &args->where);
	elfrec->bufoffset += sprintf(&elfrec->buf[elfrec->bufoffset], " %s",
		NFSL_CREATEMODE3(args->how.mode));
	if (args->how.mode != EXCLUSIVE) {
		nfslog_size3_print(elfrec,
			&args->how.nfslog_createhow3_u.size);
	}
}

static void
nfslog_MKDIR3args_print(struct nfsl_log_file *elfrec,
	nfslog_MKDIR3args *args)
{
	nfslog_diropargs3_print(elfrec, &args->where);
}

static void
nfslog_SYMLINK3args_print(struct nfsl_log_file *elfrec,
	nfslog_SYMLINK3args *args)
{
	nfslog_diropargs3_print(elfrec, &args->where);
	elfrec->bufoffset += sprintf(&elfrec->buf[elfrec->bufoffset],
		" \"%s\"", args->symlink_data);
}

static void
nfslog_MKNOD3args_print(struct nfsl_log_file *elfrec,
	nfslog_MKNOD3args *args)
{
	nfslog_diropargs3_print(elfrec, &args->where);
	elfrec->bufoffset += sprintf(&elfrec->buf[elfrec->bufoffset], " %s",
		NFSL_FTYPE3(args->type));
}

static void
nfslog_REMOVE3args_print(struct nfsl_log_file *elfrec,
	nfslog_REMOVE3args *args)
{
	nfslog_diropargs3_print(elfrec, &args->object);
}

static void
nfslog_RMDIR3args_print(struct nfsl_log_file *elfrec,
	nfslog_RMDIR3args *args)
{
	nfslog_diropargs3_print(elfrec, &args->object);
}

static void
nfslog_RENAME3args_print(struct nfsl_log_file *elfrec,
	nfslog_RENAME3args *args)
{
	nfslog_diropargs3_print(elfrec, &args->from);
	nfslog_diropargs3_print(elfrec, &args->to);
}

static void
nfslog_LINK3args_print(struct nfsl_log_file *elfrec, nfslog_LINK3args *args)
{
	nfslog_fh3_print(elfrec, &args->file);
	nfslog_diropargs3_print(elfrec, &args->link);
}

static void
nfslog_READDIRPLUS3args_print(struct nfsl_log_file *elfrec,
	nfslog_READDIRPLUS3args *args)
{
	nfslog_fh3_print(elfrec, &args->dir);
	elfrec->bufoffset += sprintf(&elfrec->buf[elfrec->bufoffset], " 0x%x",
		args->dircount);
	elfrec->bufoffset += sprintf(&elfrec->buf[elfrec->bufoffset], " 0x%x",
		args->maxcount);
}

static void
nfslog_COMMIT3args_print(struct nfsl_log_file *elfrec,
	nfslog_COMMIT3args *args)
{
	nfslog_fh3_print(elfrec, &args->file);
	elfrec->bufoffset += sprintf(&elfrec->buf[elfrec->bufoffset], " 0x%llx",
		args->offset);
	elfrec->bufoffset += sprintf(&elfrec->buf[elfrec->bufoffset], " 0x%x",
		args->count);
}

static void
nfslog_nfsstat3_print(struct nfsl_log_file *elfrec, enum nfsstat3 *res,
	bool_t print_status)
{
	if (print_status) {
		char	*statp = nfslog_get_status((short)(*res));

		if (statp != NULL)
			elfrec->bufoffset +=
				sprintf(&elfrec->buf[elfrec->bufoffset], " %s",
					statp);
		else
			elfrec->bufoffset +=
				sprintf(&elfrec->buf[elfrec->bufoffset], " %5d",
					*res);
	}
}

static void
nfslog_LOOKUP3res_print(struct nfsl_log_file *elfrec,
	nfslog_LOOKUP3res *res, bool_t print_status)
{
	if (print_status) {
		nfslog_nfsstat3_print(elfrec, &res->status, print_status);
	} else if (res->status == NFS3_OK) {
		nfslog_fh3_print(elfrec, &res->nfslog_LOOKUP3res_u.object);
	}
}

static void
nfslog_READLINK3res_print(struct nfsl_log_file *elfrec,
	nfslog_READLINK3res *res, bool_t print_status)
{
	if (print_status) {
		nfslog_nfsstat3_print(elfrec, &res->status, print_status);
	} else if (res->status == NFS3_OK) {
		elfrec->bufoffset += sprintf(&elfrec->buf[elfrec->bufoffset],
			" %s", res->nfslog_READLINK3res_u.data);
	}
}

static void
nfslog_READ3res_print(struct nfsl_log_file *elfrec, nfslog_READ3res *res,
	bool_t print_status)
{
	if (print_status) {
		nfslog_nfsstat3_print(elfrec, &res->status, print_status);
	} else if (res->status == NFS3_OK) {
		char	*elfbuf = elfrec->buf;
		int	elfbufoffset = elfrec->bufoffset;

		elfbufoffset += sprintf(&elfbuf[elfbufoffset], " 0x%llx",
			res->nfslog_READ3res_u.ok.filesize);
		elfbufoffset += sprintf(&elfbuf[elfbufoffset], " 0x%x",
			res->nfslog_READ3res_u.ok.count);
		elfbufoffset += sprintf(&elfbuf[elfbufoffset], " 0x%x",
			res->nfslog_READ3res_u.ok.eof);
		elfbufoffset += sprintf(&elfbuf[elfbufoffset], " 0x%x",
			res->nfslog_READ3res_u.ok.size);
		elfrec->bufoffset = elfbufoffset;
	}
}

static void
nfslog_WRITE3res_print(struct nfsl_log_file *elfrec, nfslog_WRITE3res *res,
	bool_t print_status)
{
	if (print_status) {
		nfslog_nfsstat3_print(elfrec, &res->status, print_status);
	} else if (res->status == NFS3_OK) {
		char	*elfbuf = elfrec->buf;
		int	elfbufoffset = elfrec->bufoffset;

		elfbufoffset += sprintf(&elfbuf[elfbufoffset], " 0x%llx",
			res->nfslog_WRITE3res_u.ok.filesize);
		elfbufoffset += sprintf(&elfbuf[elfbufoffset],
			" 0x%x", res->nfslog_WRITE3res_u.ok.count);
		elfbufoffset += sprintf(&elfrec->buf[elfbufoffset],
			" 0x%x", res->nfslog_WRITE3res_u.ok.committed);
		elfrec->bufoffset = elfbufoffset;
	}
}

static void
nfslog_CREATE3res_print(struct nfsl_log_file *elfrec, nfslog_CREATE3res *res,
	bool_t print_status)
{
	if (print_status) {
		nfslog_nfsstat3_print(elfrec, &res->status, print_status);
	} else if (res->status == NFS3_OK) {
		if (res->nfslog_CREATE3res_u.ok.obj.handle_follows) {
			nfslog_fh3_print(elfrec,
				&res->nfslog_CREATE3res_u.ok.obj.handle);
		}
	}
}

static void
nfslog_MKDIR3res_print(struct nfsl_log_file *elfrec, nfslog_MKDIR3res *res,
	bool_t print_status)
{
	if (print_status) {
		nfslog_nfsstat3_print(elfrec, &res->status, print_status);
	} else if (res->status == NFS3_OK) {
		if (res->nfslog_MKDIR3res_u.obj.handle_follows) {
			nfslog_fh3_print(elfrec,
				&res->nfslog_MKDIR3res_u.obj.handle);
		}
	}
}

static void
nfslog_SYMLINK3res_print(struct nfsl_log_file *elfrec, nfslog_SYMLINK3res *res,
	bool_t print_status)
{
	if (print_status) {
		nfslog_nfsstat3_print(elfrec, &res->status, print_status);
	} else if (res->status == NFS3_OK) {
		if (res->nfslog_SYMLINK3res_u.obj.handle_follows) {
			nfslog_fh3_print(elfrec,
				&res->nfslog_SYMLINK3res_u.obj.handle);
		}
	}
}

static void
nfslog_MKNOD3res_print(struct nfsl_log_file *elfrec, nfslog_MKNOD3res *res,
	bool_t print_status)
{
	if (print_status) {
		nfslog_nfsstat3_print(elfrec, &res->status, print_status);
	} else if (res->status == NFS3_OK) {
		if (res->nfslog_MKNOD3res_u.obj.handle_follows) {
			nfslog_fh3_print(elfrec,
				&res->nfslog_MKNOD3res_u.obj.handle);
		}
	}
}

static void
nfslog_READDIRPLUS3res_print(struct nfsl_log_file *elfrec,
	nfslog_READDIRPLUS3res *res, bool_t print_status)
{
	if (print_status) {
		nfslog_nfsstat3_print(elfrec, &res->status, print_status);
	}
}

/*
 * **** End of table functions for logging specific procs ****
 *
 * Hereafter are the general logging management and dispatcher.
 */


/*
 * nfsl_ipaddr_print - extracts sender ip address from transport struct
 * and prints it in legible form.
 */
static void
nfsl_ipaddr_print(struct nfsl_log_file *elfrec, struct netbuf *ptr)
{
	struct hostent	*hp;
	extern char	*inet_ntop();
	int		size, sin_family, error;
	char		*elfbuf = elfrec->buf;
	char		*addrp;
	int		elfbufoffset = elfrec->bufoffset;

	if (ptr->len == 0) {
		elfbufoffset += sprintf(&elfbuf[elfbufoffset], " %s",
			empty_name);
		elfbufoffset += sprintf(&elfbuf[elfbufoffset], " %s",
			empty_name);
		elfrec->bufoffset = elfbufoffset;
		return;
	}
	elfbufoffset += sprintf(&elfbuf[elfbufoffset], " ");
	/* LINTED */
	sin_family = ((struct sockaddr_in *)ptr->buf)->sin_family;
	switch (sin_family) {
	case (AF_INET):
		/* LINTED */
		addrp = (char *)&((struct sockaddr_in *)ptr->buf)->sin_addr;
		size = sizeof (struct in_addr);
		break;
	case (AF_INET6):
		/* LINTED */
		addrp = (char *)&((struct sockaddr_in6 *)ptr->buf)->sin6_addr;
		size = sizeof (struct in6_addr);
		break;
	default:
		/* unknown protocol: print address in hex form */
		for (size = ptr->len, addrp = ptr->buf; size > 0; size--) {
			elfbufoffset += sprintf(&elfbuf[elfbufoffset], "%02x",
				*addrp);
		}
		elfbufoffset += sprintf(&elfbuf[elfbufoffset], " %s",
			empty_name);
		elfrec->bufoffset = elfbufoffset;
		return;
	}
	if (inet_ntop(sin_family, addrp, &elfbuf[elfbufoffset],
		(size_t)(DFLT_BUFFERSIZE + DFLT_OVFSIZE - elfbufoffset))
		    == NULL) {
		/* Not enough space to print - should never happen */
		elfbuf[elfrec->bufoffset] = '\0';	/* just in case */
		return;
	}
	/* inet_ntop copied address into elfbuf, so update offset */
	elfbufoffset += strlen(&elfbuf[elfbufoffset]);
	/* get host name and log it as well */
	hp = getipnodebyaddr(addrp, size, sin_family, &error);
	if (hp != NULL) {
		elfbufoffset += sprintf(&elfbuf[elfbufoffset], " \"%s\"",
			hp->h_name);
	} else {
		elfbufoffset += sprintf(&elfbuf[elfbufoffset], " %s",
			empty_name);
	}
	elfrec->bufoffset = elfbufoffset;
}

static void
nfsl_elf_record_header_print(struct nfsl_log_file *elfrec,
	nfslog_record_header *lhp, char *principal_name, char *tag,
	struct nfsl_proc_disp *disp, char *progname)
{
	struct passwd	*pwp = NULL;
	char	*elfbuf = elfrec->buf;
	int	elfbufoffset = elfrec->bufoffset;

	/*
	 * Fields: time bytes tag rpc-program rpc-version rpc-procedure
	 *	   auth-flavor s-user-name s-uid uid u-name gid net-id
	 *   c-ip c-dns s-dns status rpcarg-path <arguments> <response>
	 */
	elfbufoffset += sprintf(&elfbuf[elfbufoffset], "%s",
		nfsl_get_time((time_t)lhp->rh_timestamp.tv_sec));
	elfbufoffset += sprintf(&elfbuf[elfbufoffset], " 0x%x",
		lhp->rh_reclen);
	if ((tag != NULL) && (tag[0] != '\0')) {
		elfbufoffset += sprintf(&elfbuf[elfbufoffset], " \"%s\"", tag);
	} else {
		elfbufoffset += sprintf(&elfbuf[elfbufoffset], " %s",
					empty_name);
	}
	elfbufoffset += sprintf(&elfbuf[elfbufoffset], " %s 0x%x %s",
				progname, lhp->rh_version, disp->procname);
	elfbufoffset += sprintf(&elfbuf[elfbufoffset], " %s",
		NFSL_AUTH_FLAVOR_PRINT(lhp->rh_auth_flavor));
	if ((principal_name != NULL) && (principal_name[0] != '\0')) {
		elfbufoffset += sprintf(&elfbuf[elfbufoffset], " \"%s\"",
			principal_name);
		if ((pwp = getpwnam(principal_name)) != NULL) {
			elfbufoffset += sprintf(&elfbuf[elfbufoffset],
				" 0x%lx", pwp->pw_uid);
		} else {
			elfbufoffset += sprintf(&elfbuf[elfbufoffset],
				" %s", empty_name);
		}
	} else {
		elfbufoffset += sprintf(&elfbuf[elfbufoffset], " %s",
			empty_name);
		elfbufoffset += sprintf(&elfbuf[elfbufoffset], " %s",
			empty_name);
	}
	elfbufoffset += sprintf(&elfbuf[elfbufoffset], " 0x%lx", lhp->rh_uid);
	if (((pwp = getpwuid(lhp->rh_uid)) != NULL) && (pwp->pw_name != NULL)) {
		elfbufoffset += sprintf(&elfbuf[elfbufoffset], " \"%s\"",
			pwp->pw_name);
	} else {
		elfbufoffset += sprintf(&elfbuf[elfbufoffset], " %s",
			empty_name);
	}
	elfbufoffset += sprintf(&elfbuf[elfbufoffset], " 0x%lx", lhp->rh_gid);
	elfrec->bufoffset = elfbufoffset;
}

static void
nfsl_elf_buffer_header_print(struct nfsl_log_file *elfrec,
	nfslog_buffer_header *bufhdr)
{
	int	rc;
	struct utsname	name;
	char	*elfbuf = elfrec->buf;
	int	elfbufoffset = elfrec->bufoffset;

	rc = uname(&name);
	elfbufoffset += sprintf(&elfbuf[elfbufoffset],
		"#Version %d.0\n#Software \"%s\"\n",
		bufhdr->bh_version, ((rc >= 0) ? name.sysname : empty_name));
	elfbufoffset += sprintf(&elfbuf[elfbufoffset], "#Date %s\n",
		nfsl_get_date((time_t)bufhdr->bh_timestamp.tv_sec));
	elfbufoffset += sprintf(&elfbuf[elfbufoffset], "#Remark %s\n",
		empty_name);
	elfbufoffset += sprintf(&elfbuf[elfbufoffset],
		"#Fields: time bytes tag");
	elfbufoffset += sprintf(&elfbuf[elfbufoffset],
		" rpc-program rpc-version rpc-procedure");
	elfbufoffset += sprintf(&elfbuf[elfbufoffset],
		" auth-flavor s-user-name s-uid uid u-name gid net-id c-ip");
	elfbufoffset += sprintf(&elfbuf[elfbufoffset],
		" c-dns s-dns status rpcarg-path");
	elfbufoffset += sprintf(&elfbuf[elfbufoffset],
		" rpc-arguments... rpc-response...\n");
	elfrec->bufoffset = elfbufoffset;
}

/*
 * nfsl_find_elf_dispatch - get the dispatch struct for this request
 */
static struct nfsl_proc_disp *
nfsl_find_elf_dispatch(nfslog_request_record *logrec, char **prognamep)
{
	nfslog_record_header	*logrechdr = &logrec->re_header;
	struct nfsl_prog_disp	*progtable;	/* prog struct */
	struct nfsl_vers_disp	*verstable;	/* version struct */
	int			i, vers;

	/* Find prog element - search because can't use prog as array index */
	for (i = 0; (i < nfsl_elf_dispatch_table_arglen) &&
	    (logrechdr->rh_prognum != nfsl_elf_dispatch_table[i].nfsl_dis_prog);
		i++);
	if (i >= nfsl_elf_dispatch_table_arglen) {	/* program not logged */
		/* not an error */
		return (NULL);
	}
	progtable = &nfsl_elf_dispatch_table[i];
	/* Find vers element - no validity check - if here it's valid vers */
	vers = logrechdr->rh_version - progtable->nfsl_dis_versmin;
	verstable = &progtable->nfsl_dis_vers_table[vers];
	/* Find proc element - no validity check - if here it's valid proc */
	*prognamep = progtable->progname;
	return (&verstable->nfsl_dis_proc_table[logrechdr->rh_procnum]);
}

/*
 * nfsl_elf_rpc_print - Print the record buffer.
 */
static void
nfsl_elf_rpc_print(struct nfsl_log_file *elfrec,
	nfslog_request_record *logrec, struct nfsl_proc_disp *disp,
	char *progname, char *path1, char *path2)
{
	if (debug > 1) {
		(void) printf("%s %d %s", progname,
			logrec->re_header.rh_version, disp->procname);
		(void) printf(": '%s', '%s'\n",
			((path1 != NULL) ? path1 : empty_name),
			((path2 != NULL) ? path2 : empty_name));
	}
	/*
	 * XXXX programs using this file to get a usable record should
	 * take "record" struct.
	 */
	/*
	 * Print the variable fields:
	 *	principal name
	 *	netid
	 *	ip address
	 *	rpc args
	 *	rpc res
	 * Use the displacements calculated earlier...
	 */

	/*
	 * Fields: time bytes tag rpc-program rpc-version rpc-procedure
	 *	   auth-flavor s-user-name s-uid uid u-name gid net-id c-ip
	 *	 c-dns s-dns status rpcarg-path <arguments> <response>
	 */
	nfsl_elf_record_header_print(elfrec, &logrec->re_header,
			logrec->re_principal_name, logrec->re_tag,
			disp, progname);
	if ((logrec->re_netid != NULL) && (logrec->re_netid[0] != '\0')) {
		elfrec->bufoffset += sprintf(&elfrec->buf[elfrec->bufoffset],
			" \"%s\"", logrec->re_netid);
	} else {
		elfrec->bufoffset += sprintf(&elfrec->buf[elfrec->bufoffset],
			" %s", empty_name);
	}
	nfsl_ipaddr_print(elfrec, &logrec->re_ipaddr);
	elfrec->bufoffset += sprintf(&elfrec->buf[elfrec->bufoffset],
		" \"%s\"", hostname);
	/* Next is return status */
	(*disp->nfsl_dis_res)(elfrec, logrec->re_rpc_res, TRUE);
	/* Next is argpath */
	if (path1 != NULL) {
		elfrec->bufoffset += sprintf(&elfrec->buf[elfrec->bufoffset],
			" \"%s\"", path1);
	} else {
		elfrec->bufoffset += sprintf(&elfrec->buf[elfrec->bufoffset],
			" %s", empty_name);
	}
	/*
	 * path2 is non-empty for rename/link type operations. If it is non-
	 * empty print it here as it's a part of the args
	 */
	if (path2 != NULL) {
		elfrec->bufoffset += sprintf(&elfrec->buf[elfrec->bufoffset],
			" \"%s\"", path2);
	}
	/* Next print formatted rpc args */
	(*disp->nfsl_dis_args)(elfrec, logrec->re_rpc_arg);
	/* Next print formatted rpc res (minus status) */
	(*disp->nfsl_dis_res)(elfrec, logrec->re_rpc_res, FALSE);
	elfrec->bufoffset += sprintf(&elfrec->buf[elfrec->bufoffset], "\n");
}

/*
 * nfsl_log_file_add - add a new record to the list
 */
static void
nfsl_log_file_add(struct nfsl_log_file *elfrec,
	struct nfsl_log_file **elf_listp)
{
	elfrec->next = *elf_listp;
	elfrec->prev = NULL;
	if (*elf_listp != NULL) {
		(*elf_listp)->prev = elfrec;
	}
	*elf_listp = elfrec;
}

/*
 * nfsl_log_file_find - finds a record in the list, given a cookie (== elfrec)
 * Returns the record.
 */
static struct nfsl_log_file *
nfsl_log_file_find(struct nfsl_log_file *elfrec,
	struct nfsl_log_file *elf_list)
{
	struct nfsl_log_file	*rec;

	for (rec = elf_list; (rec != NULL) && (rec != elfrec);
		rec = rec->next);
	return (rec);
}

/*
 * nfsl_log_file_del - delete a record from the list, does not free rec.
 * Returns the deleted record.
 */
static struct nfsl_log_file *
nfsl_log_file_del(struct nfsl_log_file *elfrec,
	struct nfsl_log_file **elf_listp)
{
	struct nfsl_log_file	*rec;

	if ((rec = nfsl_log_file_find(elfrec, *elf_listp)) == NULL) {
		return (NULL);
	}
	if (rec->prev != NULL) {
		rec->prev->next = rec->next;
	} else {
		*elf_listp = rec->next;
	}
	if (rec->next != NULL) {
		rec->next->prev = rec->prev;
	}
	return (rec);
}

/*
 * nfsl_log_file_free - frees a record
 */
static void
nfsl_log_file_free(struct nfsl_log_file *elfrec)
{
	if (elfrec == NULL)
		return;
	if (elfrec->path != NULL)
		free(elfrec->path);
	if (elfrec->buf != NULL)
		free(elfrec->buf);
	free(elfrec);
}

/*
 * Exported Functions
 */

/*
 * nfslog_open_elf_file - open the output elf file and mallocs needed buffers
 * Returns a pointer to the nfsl_log_file on success, NULL on error.
 *
 * *error contains the last error encountered on this object, It can
 * be used to avoid reporting the same error endlessly, by comparing
 * the current error to the last error. It is reset to the current error
 * code on return.
 */
void *
nfslog_open_elf_file(char *elfpath, nfslog_buffer_header *bufhdr, int *error)
{
	struct nfsl_log_file *elfrec;
	struct stat stat_buf;
	int preverror = *error;

	if ((elfrec = malloc(sizeof (*elfrec))) == NULL) {
		*error = errno;
		if (*error != preverror) {
			syslog(LOG_ERR, gettext("nfslog_open_elf_file: %s"),
				strerror(*error));
		}
		return (NULL);
	}
	bzero(elfrec, sizeof (*elfrec));

	elfrec->buf = (char *)malloc(DFLT_BUFFERSIZE + DFLT_OVFSIZE);
	if (elfrec->buf == NULL) {
		*error = errno;
		if (*error != preverror) {
			syslog(LOG_ERR, gettext("nfslog_open_elf_file: %s"),
				strerror(*error));
		}
		nfsl_log_file_free(elfrec);
		return (NULL);
	}

	if ((elfrec->path = strdup(elfpath)) == NULL) {
		*error = errno;
		if (*error != preverror) {
			syslog(LOG_ERR, gettext("nfslog_open_elf_file: %s"),
				strerror(*error));
		}
		nfsl_log_file_free(elfrec);
		return (NULL);
	}

	if ((elfrec->fp = fopen(elfpath, "a")) == NULL) {
		*error = errno;
		if (*error != preverror) {
			syslog(LOG_ERR, gettext("Cannot open '%s': %s"),
				elfpath, strerror(*error));
		}
		nfsl_log_file_free(elfrec);
		return (NULL);
	}

	if (stat(elfpath, &stat_buf) == -1) {
		*error = errno;
		if (*error != preverror) {
			syslog(LOG_ERR, gettext("Cannot stat '%s': %s"),
				elfpath, strerror(*error));
		}
		(void) fclose(elfrec->fp);
		nfsl_log_file_free(elfrec);
		return (NULL);
	}

	nfsl_log_file_add(elfrec, &elf_file_list);

	if (stat_buf.st_size == 0) {
		/*
		 * Print header unto logfile
		 */
		nfsl_elf_buffer_header_print(elfrec, bufhdr);
	}

	if (hostname[0] == '\0') {
		(void) gethostname(hostname, MAXHOSTNAMELEN);
	}

	return (elfrec);
}

/*
 * nfslog_close_elf_file - close elffile and write out last buffer
 */
void
nfslog_close_elf_file(void **elfcookie)
{
	struct nfsl_log_file	*elfrec;

	if ((*elfcookie == NULL) || ((elfrec = nfsl_log_file_del(
	    *elfcookie, &elf_file_list)) == NULL)) {
		*elfcookie = NULL;
		return;
	}
	if (elfrec->fp != NULL) {
		/* Write the last output buffer to disk */
		(void) nfsl_write_elfbuf(elfrec);
		(void) fclose(elfrec->fp);
	}
	nfsl_log_file_free(elfrec);
	*elfcookie = NULL;
}

/*
 * nfslog_process_elf_rec - processes the record in the buffer and outputs
 *	to the elf log.
 * Return 0 for success, errno else.
 */
int
nfslog_process_elf_rec(void *elfcookie, nfslog_request_record *logrec,
	char *path1, char *path2)
{
	struct nfsl_log_file	*elfrec;
	struct nfsl_proc_disp	*disp;
	char			*progname;

	if ((elfrec = nfsl_log_file_find(elfcookie, elf_file_list)) == NULL) {
		return (EINVAL);
	}
	/* Make sure there is room */
	if (elfrec->bufoffset > DFLT_BUFFERSIZE) {
		if (nfsl_write_elfbuf(elfrec) < 0) {
			return (errno);
		}
	}
	if ((disp = nfsl_find_elf_dispatch(logrec, &progname)) != NULL) {
		nfsl_elf_rpc_print(elfrec, logrec, disp, progname,
			path1, path2);
	}
	return (0);
}
