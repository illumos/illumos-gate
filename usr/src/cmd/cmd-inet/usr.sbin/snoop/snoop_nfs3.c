/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright (c) 1991, 1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ident	"%Z%%M%	%I%	%E% SMI"	/* SunOS	*/

#include <sys/types.h>
#include <sys/errno.h>
#include <sys/tiuser.h>
#include <setjmp.h>
#include <string.h>

#include <rpc/types.h>
#include <rpc/xdr.h>
#include <rpc/auth.h>
#include <rpc/clnt.h>
#include <rpc/rpc_msg.h>
#include "snoop.h"
#include "snoop_nfs.h"

#include <sys/stat.h>
#include <sys/param.h>
#include <rpcsvc/nfs_prot.h>

#ifndef MIN
#define	MIN(a, b)	((a) < (b) ? (a) : (b))
#endif

extern jmp_buf xdr_err;

static void nfscall3(int);
static void nfsreply3(int);
static char *perms(int);
static char *filetype(int);
static char *sum_access(void);
static char *sum_readdirres(void);
static char *sum_readdirplusres(void);
static char *sum_createhow(void);
static char *sum_stablehow(void);
static void detail_sattr3(void);
static void detail_diropargs3(void);
static void detail_readdirres(void);
static void detail_readdirplusres(void);
static void detail_fattr3(void);
static void detail_access(void);
static void detail_mode(int);
static void detail_wcc_attr(void);
static void detail_pre_op_attr(char *);
static void detail_wcc_data(char *);
static void skip_postop(void);
static void skip_wcc_data(void);
static void skip_sattr3(void);

#define	DONT_CHANGE		0
#define	SET_TO_SERVER_TIME	1
#define	SET_TO_CLIENT_TIME	2

#define	UNCHECKED	0
#define	GUARDED		1
#define	EXCLUSIVE	2

#define	ACCESS3_READ	0x0001
#define	ACCESS3_LOOKUP	0x0002
#define	ACCESS3_MODIFY	0x0004
#define	ACCESS3_EXTEND	0x0008
#define	ACCESS3_DELETE	0x0010
#define	ACCESS3_EXECUTE	0x0020

#define	UNSTABLE	0
#define	DATA_SYNC	1
#define	FILE_SYNC	2

#define	NF3REG		1	/* regular file */
#define	NF3DIR		2	/* directory */
#define	NF3BLK		3	/* block special */
#define	NF3CHR		4	/* character special */
#define	NF3LNK		5	/* symbolic link */
#define	NF3SOCK		6	/* unix domain socket */
#define	NF3FIFO		7	/* named pipe */

#define	NFS3_FHSIZE	64

static char *procnames_short[] = {
	"NULL3",	/*  0 */
	"GETATTR3",	/*  1 */
	"SETATTR3",	/*  2 */
	"LOOKUP3",	/*  3 */
	"ACCESS3",	/*  4 */
	"READLINK3",	/*  5 */
	"READ3",	/*  6 */
	"WRITE3",	/*  7 */
	"CREATE3",	/*  8 */
	"MKDIR3",	/*  9 */
	"SYMLINK3",	/* 10 */
	"MKNOD3",	/* 11 */
	"REMOVE3",	/* 12 */
	"RMDIR3",	/* 13 */
	"RENAME3",	/* 14 */
	"LINK3",	/* 15 */
	"READDIR3",	/* 16 */
	"READDIRPLUS3",	/* 17 */
	"FSSTAT3",	/* 18 */
	"FSINFO3",	/* 19 */
	"PATHCONF3",	/* 20 */
	"COMMIT3",	/* 21 */
};

static char *procnames_long[] = {
	"Null procedure",		/*  0 */
	"Get file attributes",		/*  1 */
	"Set file attributes",		/*  2 */
	"Look up file name",		/*  3 */
	"Check access permission",	/*  4 */
	"Read from symbolic link",	/*  5 */
	"Read from file",		/*  6 */
	"Write to file",		/*  7 */
	"Create file",			/*  8 */
	"Make directory",		/*  9 */
	"Make symbolic link",		/* 10 */
	"Make special file",		/* 11 */
	"Remove file",			/* 12 */
	"Remove directory",		/* 13 */
	"Rename",			/* 14 */
	"Link",				/* 15 */
	"Read from directory",		/* 16 */
	"Read from directory - plus",	/* 17 */
	"Get filesystem statistics",	/* 18 */
	"Get filesystem information",	/* 19 */
	"Get POSIX information",	/* 20 */
	"Commit to stable storage",	/* 21 */
};

#define	MAXPROC	21

void
interpret_nfs3(flags, type, xid, vers, proc, data, len)
	int flags, type, xid, vers, proc;
	char *data;
	int len;
{
	char *line;
	char buff[NFS_MAXPATHLEN + 1];	/* protocol allows longer */
	u_longlong_t off;
	int sz, how;
	char *fh, *name;

	if (proc < 0 || proc > MAXPROC)
		return;

	if (flags & F_SUM) {
		line = get_sum_line();

		if (type == CALL) {
			(void) sprintf(line, "NFS C %s",
				procnames_short[proc]);
			line += strlen(line);
			switch (proc) {
			case NFSPROC3_GETATTR:
			case NFSPROC3_READLINK:
			case NFSPROC3_FSSTAT:
			case NFSPROC3_FSINFO:
			case NFSPROC3_PATHCONF:
				(void) sprintf(line, sum_nfsfh3());
				break;
			case NFSPROC3_SETATTR:
				(void) sprintf(line, sum_nfsfh3());
				break;
			case NFSPROC3_READDIR:
				fh = sum_nfsfh3();
				off = getxdr_u_longlong();
				(void) getxdr_u_longlong();
				sz = getxdr_u_long();
				(void) sprintf(line, "%s Cookie=%llu for %lu",
					fh, off, sz);
				break;
			case NFSPROC3_READDIRPLUS:
				fh = sum_nfsfh3();
				off = getxdr_u_longlong();
				(void) getxdr_u_longlong();
				sz = getxdr_u_long();
				(void) sprintf(line,
						"%s Cookie=%llu for %lu/%lu",
						fh, off, sz, getxdr_u_long());
				break;
			case NFSPROC3_ACCESS:
				fh = sum_nfsfh3();
				(void) sprintf(line, "%s (%s)",
					fh, sum_access());
				break;
			case NFSPROC3_LOOKUP:
			case NFSPROC3_REMOVE:
			case NFSPROC3_RMDIR:
			case NFSPROC3_MKDIR:
				fh = sum_nfsfh3();
				(void) sprintf(line, "%s %s",
					fh, getxdr_string(buff,
						NFS_MAXPATHLEN));
				break;
			case NFSPROC3_CREATE:
				fh = sum_nfsfh3();
				name = getxdr_string(buff, NFS_MAXPATHLEN);
				(void) sprintf(line, "%s (%s) %s",
					fh, sum_createhow(), name);
				break;
			case NFSPROC3_MKNOD:
				fh = sum_nfsfh3();
				name = getxdr_string(buff, NFS_MAXPATHLEN);
				how = getxdr_long();
				(void) sprintf(line, "%s (%s) %s",
					fh, filetype(how), name);
				break;
			case NFSPROC3_READ:
				fh = sum_nfsfh3();
				off = getxdr_u_longlong();
				sz = getxdr_u_long();
				(void) sprintf(line, "%s at %llu for %lu",
					fh, off, sz);
				break;
			case NFSPROC3_WRITE:
				fh = sum_nfsfh3();
				off = getxdr_u_longlong();
				sz = getxdr_u_long();
				(void) sprintf(line, "%s at %llu for %lu (%s)",
					fh, off, sz, sum_stablehow());
				break;
			case NFSPROC3_SYMLINK:
				fh = sum_nfsfh3();
				(void) sprintf(line, "%s %s",
					fh, getxdr_string(buff,
						NFS_MAXPATHLEN));
				skip_sattr3();
				line += strlen(line);
				(void) sprintf(line, " to %s",
					getxdr_string(buff, NFS_MAXPATHLEN));
				break;
			case NFSPROC3_RENAME:
				fh = sum_nfsfh3();
				(void) sprintf(line, "%s %s",
					fh, getxdr_string(buff,
						NFS_MAXPATHLEN));
				line += strlen(line);
				fh = sum_nfsfh3();
				(void) sprintf(line, " to%s %s",
					fh, getxdr_string(buff,
						NFS_MAXPATHLEN));
				break;
			case NFSPROC3_LINK:
				fh = sum_nfsfh3();
				(void) sprintf(line, "%s", fh);
				line += strlen(line);
				fh = sum_nfsfh3();
				(void) sprintf(line, " to%s %s",
					fh, getxdr_string(buff,
						NFS_MAXPATHLEN));
				break;
			case NFSPROC3_COMMIT:
				fh = sum_nfsfh3();
				off = getxdr_u_longlong();
				sz  = getxdr_u_long();
				(void) sprintf(line, "%s at %llu for %lu",
					fh, off, sz);
				break;
			default:
				break;
			}

			check_retransmit(line, xid);
		} else {
			(void) sprintf(line, "NFS R %s ",
				procnames_short[proc]);
			line += strlen(line);
			switch (proc) {
			case NFSPROC3_LOOKUP:
				if (sum_nfsstat3(line) == NFS3_OK)
					(void) strcat(line, sum_nfsfh3());
				break;
			case NFSPROC3_CREATE:
			case NFSPROC3_MKDIR:
			case NFSPROC3_SYMLINK:
			case NFSPROC3_MKNOD:
				if (sum_nfsstat3(line) == NFS3_OK) {
					if (getxdr_bool())
						(void) strcat(line,
							    sum_nfsfh3());
				}
				break;
			case NFSPROC3_READLINK:
				if (sum_nfsstat3(line) == NFS3_OK) {
					line += strlen(line);
					skip_postop();
					(void) sprintf(line, " (Path=%s)",
						getxdr_string(buff,
						    NFS_MAXPATHLEN));
				}
				break;
			case NFSPROC3_GETATTR:
			case NFSPROC3_SETATTR:
			case NFSPROC3_REMOVE:
			case NFSPROC3_RMDIR:
			case NFSPROC3_RENAME:
			case NFSPROC3_LINK:
			case NFSPROC3_FSSTAT:
			case NFSPROC3_FSINFO:
			case NFSPROC3_PATHCONF:
				(void) sum_nfsstat3(line);
				break;
			case NFSPROC3_ACCESS:
				if (sum_nfsstat3(line) == NFS3_OK) {
					line += strlen(line);
					skip_postop();
					(void) sprintf(line, " (%s)",
						sum_access());
				}
				break;
			case NFSPROC3_WRITE:
				if (sum_nfsstat3(line) == NFS3_OK) {
					line += strlen(line);
					skip_wcc_data();
					sz = getxdr_u_long();
					(void) sprintf(line, " %d (%s)",
						sz, sum_stablehow());
				}
				break;
			case NFSPROC3_READDIR:
				if (sum_nfsstat3(line) == NFS3_OK)
					(void) strcat(line, sum_readdirres());
				break;
			case NFSPROC3_READ:
				if (sum_nfsstat3(line) == NFS3_OK) {
					line += strlen(line);
					skip_postop();
					(void) sprintf(line, " (%lu bytes)",
						getxdr_u_long());
					if (getxdr_bool())
						(void) strcat(line, " EOF");
				}
				break;
			case NFSPROC3_READDIRPLUS:
				if (sum_nfsstat3(line) == NFS3_OK)
					(void) strcat(line,
						    sum_readdirplusres());
				break;
			case NFSPROC3_COMMIT:
				(void) sum_nfsstat3(line);
				break;
			default:
				break;
			}
		}
	}

	if (flags & F_DTAIL) {
		show_header("NFS:  ", "Sun NFS", len);
		show_space();
		(void) sprintf(get_line(0, 0), "Proc = %d (%s)",
			proc, procnames_long[proc]);
		if (type == CALL)
			nfscall3(proc);
		else
			nfsreply3(proc);
		show_trailer();
	}
}

/*
 *  Print out version 3 NFS call packets
 */
static void
nfscall3(proc)
	int proc;
{
	int h;

	switch (proc) {
	case NFSPROC3_GETATTR:
	case NFSPROC3_READLINK:
	case NFSPROC3_FSINFO:
	case NFSPROC3_FSSTAT:
	case NFSPROC3_PATHCONF:
		detail_nfsfh3();
		break;
	case NFSPROC3_SETATTR:
		detail_nfsfh3();
		detail_sattr3();
		if (getxdr_bool())
			(void) showxdr_date_ns("Guard = %s");
		break;
	case NFSPROC3_LOOKUP:
	case NFSPROC3_REMOVE:
	case NFSPROC3_RMDIR:
		detail_diropargs3();
		break;
	case NFSPROC3_ACCESS:
		detail_nfsfh3();
		detail_access();
		break;
	case NFSPROC3_MKDIR:
		detail_diropargs3();
		detail_sattr3();
		break;
	case NFSPROC3_CREATE:
		detail_diropargs3();
		h = getxdr_u_long();
		if (h == EXCLUSIVE)
			showxdr_hex(8, "Guard = %s");
		else {
			(void) sprintf(get_line(0, 0), "Method = %s",
			h == UNCHECKED ? "Unchecked" : "Guarded");
			detail_sattr3();
		}
		break;
	case NFSPROC3_MKNOD:
		detail_diropargs3();
		h = getxdr_u_long();
		(void) sprintf(get_line(0, 0), "File type = %s",
			filetype(h));
		switch (h) {
		case NF3CHR:
		case NF3BLK:
			detail_sattr3();
			showxdr_u_long("Major = %lu");
			showxdr_u_long("Minor = %lu");
			break;
		case NF3SOCK:
		case NF3FIFO:
			detail_sattr3();
			break;
		}
		break;
	case NFSPROC3_WRITE:
		detail_nfsfh3();
		(void) showxdr_u_longlong("Offset = %llu");
		(void) showxdr_u_long("Size   = %lu");
		(void) sprintf(get_line(0, 0), "Stable = %s",
				sum_stablehow());
		break;
	case NFSPROC3_RENAME:
		detail_diropargs3();
		detail_diropargs3();
		break;
	case NFSPROC3_LINK:
		detail_nfsfh3();
		detail_diropargs3();
		break;
	case NFSPROC3_SYMLINK:
		detail_diropargs3();
		detail_sattr3();
		(void) showxdr_string(MAXPATHLEN, "Path = %s");
		break;
	case NFSPROC3_READDIR:
		detail_nfsfh3();
		(void) showxdr_u_longlong("Cookie   = %llu");
		(void) showxdr_hex(8, "Verifier = %s");
		(void) showxdr_u_long("Count = %lu");
		break;
	case NFSPROC3_READDIRPLUS:
		detail_nfsfh3();
		(void) showxdr_u_longlong("Cookie   = %llu");
		(void) showxdr_hex(8, "Verifier = %s");
		(void) showxdr_u_long("Dircount = %lu");
		(void) showxdr_u_long("Maxcount = %lu");
		break;
	case NFSPROC3_READ:
	case NFSPROC3_COMMIT:
		detail_nfsfh3();
		(void) showxdr_u_longlong("Offset = %llu");
		(void) showxdr_long("Count = %lu");
		break;
	default:
		break;
	}
}

/*
 *  Print out version 3 NFS reply packets
 */
static void
nfsreply3(proc)
	int proc;
{
	int bits;

	switch (proc) {
	case NFSPROC3_GETATTR:
		if (detail_nfsstat3() == NFS3_OK) {
			detail_fattr3();
		}
		break;
	case NFSPROC3_SETATTR:
		(void) detail_nfsstat3();
		detail_wcc_data("");
		break;
	case NFSPROC3_WRITE:
		if (detail_nfsstat3() == NFS3_OK) {
			detail_wcc_data("");
			(void) showxdr_u_long("Count = %lu bytes written");
			(void) sprintf(get_line(0, 0), "Stable = %s",
					sum_stablehow());
			(void) showxdr_hex(8, "Verifier = %s");
		} else
			detail_wcc_data("");
		break;
	case NFSPROC3_LOOKUP:
		if (detail_nfsstat3() == NFS3_OK) {
			detail_nfsfh3();
			detail_post_op_attr("(object)");
		}
		detail_post_op_attr("(directory)");
		break;
	case NFSPROC3_CREATE:
	case NFSPROC3_MKDIR:
	case NFSPROC3_SYMLINK:
	case NFSPROC3_MKNOD:
		if (detail_nfsstat3() == NFS3_OK) {
			if (getxdr_bool())
				detail_nfsfh3();
			else
				(void) sprintf(get_line(0, 0),
						"(No file handle available)");
			detail_post_op_attr("");
		}
		detail_wcc_data("");
		break;
	case NFSPROC3_READLINK:
		if (detail_nfsstat3() == NFS3_OK) {
			detail_post_op_attr("");
			(void) showxdr_string(MAXPATHLEN, "Path = %s");
		} else
			detail_post_op_attr("");
		break;
	case NFSPROC3_READ:
		if (detail_nfsstat3() == NFS3_OK) {
			detail_post_op_attr("");
			(void) showxdr_u_long("Count = %lu bytes read");
			(void) showxdr_bool("End of file = %s");
		} else
			detail_post_op_attr("");
		break;
	case NFSPROC3_ACCESS:
		if (detail_nfsstat3() == NFS3_OK) {
			detail_post_op_attr("");
			(void) sprintf(get_line(0, 0), "Access = %s",
					sum_access());
		} else
			detail_post_op_attr("");
		break;
	case NFSPROC3_REMOVE:
	case NFSPROC3_RMDIR:
		(void) detail_nfsstat3();
		detail_wcc_data("");
		break;
	case NFSPROC3_RENAME:
		(void) detail_nfsstat3();
		detail_wcc_data("(from directory)");
		detail_wcc_data("(to directory)");
		break;
	case NFSPROC3_LINK:
		(void) detail_nfsstat3();
		detail_post_op_attr("");
		detail_wcc_data("");
		break;
	case NFSPROC3_READDIR:
		if (detail_nfsstat3() == NFS3_OK) {
			detail_readdirres();
		} else
			detail_post_op_attr("");
		break;
	case NFSPROC3_READDIRPLUS:
		if (detail_nfsstat3() == NFS3_OK) {
			detail_readdirplusres();
		} else
			detail_post_op_attr("");
		break;
	case NFSPROC3_FSSTAT:
		if (detail_nfsstat3() == NFS3_OK) {
			detail_post_op_attr("");
			(void) showxdr_u_longlong(
				"Total space = %llu bytes");
			(void) showxdr_u_longlong(
				"Available space = %llu bytes");
			(void) showxdr_u_longlong(
				"Available space - this user = %llu bytes");
			(void) showxdr_u_longlong(
				"Total file slots = %llu");
			(void) showxdr_u_longlong(
				"Available file slots = %llu");
			(void) showxdr_u_longlong(
				"Available file slots - this user = %llu");
			(void) showxdr_u_long("Invariant time = %lu sec");
		} else
			detail_post_op_attr("");
		break;
	case NFSPROC3_FSINFO:
		if (detail_nfsstat3() == NFS3_OK) {
			detail_post_op_attr("");
			(void) show_line("Read transfer sizes:");
			(void) showxdr_u_long("   Maximum = %lu bytes");
			(void) showxdr_u_long("   Preferred = %lu bytes");
			(void) showxdr_u_long(
			    "   Suggested multiple = %lu bytes");
			(void) show_line("Write transfer sizes:");
			(void) showxdr_u_long("   Maximum = %lu bytes");
			(void) showxdr_u_long("   Preferred = %lu bytes");
			(void) showxdr_u_long(
			    "   Suggested multiple = %lu bytes");
			(void) show_line("Directory read size:");
			(void) showxdr_u_long("   Preferred = %lu bytes");
			(void) show_line("File system limits:");
			(void) showxdr_u_longlong(
			    "   Max file size = %llu bytes");
			(void) showxdr_date_ns(
			    "   Server minimum time discrimination = %s sec");
			bits = showxdr_u_long("Properties = 0x%02x");
			(void) sprintf(get_line(0, 0), "	%s",
				getflag(bits, FSF3_LINK,
				"Hard links supported",
				"(hard links not supported)"));
			(void) sprintf(get_line(0, 0), "	%s",
				getflag(bits, FSF3_SYMLINK,
				"Symbolic links supported",
				"(symbolic links not supported)"));
			(void) sprintf(get_line(0, 0), "	%s",
				getflag(bits, FSF3_HOMOGENEOUS,
				"Pathconf cannot vary per file",
				"(pathconf can vary per file)"));
			(void) sprintf(get_line(0, 0), "	%s",
				getflag(bits, FSF3_CANSETTIME,
				"Server can always set file times",
				"(server cannot always set file times)"));
		} else
			detail_post_op_attr("");
		break;
	case NFSPROC3_PATHCONF:
		if (detail_nfsstat3() == NFS3_OK) {
			detail_post_op_attr("");
			(void) showxdr_u_long("Link max = %lu");
			(void) showxdr_u_long("Name max = %lu");
			(void) showxdr_bool("No trunc         = %s");
			(void) showxdr_bool("Chown restricted = %s");
			(void) showxdr_bool("Case insensitive = %s");
			(void) showxdr_bool("Case preserving  = %s");
		} else
			detail_post_op_attr("");
		break;
	case NFSPROC3_COMMIT:
		if (detail_nfsstat3() == NFS3_OK) {
			detail_wcc_data("");
			(void) showxdr_hex(8, "Verifier = %s");
		} else
			detail_wcc_data("");
		break;
	default:
		break;
	}
}

static void
detail_diropargs3()
{

	detail_nfsfh3();
	(void) showxdr_string(MAXPATHLEN, "File name = %s");
}

int
sum_nfsstat3(line)
	char *line;
{
	ulong_t status;
	char *p;

	status = getxdr_long();
	switch (status) {
	case NFS3_OK:		p = "OK"; break;
	case NFS3ERR_PERM:	p = "Not owner"; break;
	case NFS3ERR_NOENT:	p = "No such file or directory"; break;
	case NFS3ERR_IO:	p = "I/O error"; break;
	case NFS3ERR_NXIO:	p = "No such device or address"; break;
	case NFS3ERR_ACCES:	p = "Permission denied"; break;
	case NFS3ERR_EXIST:	p = "File exists"; break;
	case NFS3ERR_XDEV:	p = "Attempted cross-device link"; break;
	case NFS3ERR_NODEV:	p = "No such device"; break;
	case NFS3ERR_NOTDIR:	p = "Not a directory"; break;
	case NFS3ERR_ISDIR:	p = "Is a directory"; break;
	case NFS3ERR_INVAL:	p = "Invalid argument"; break;
	case NFS3ERR_FBIG:	p = "File too large"; break;
	case NFS3ERR_NOSPC:	p = "No space left on device"; break;
	case NFS3ERR_ROFS:	p = "Read-only file system"; break;
	case NFS3ERR_MLINK:	p = "Too many links"; break;
	case NFS3ERR_NAMETOOLONG:p = "File name too long"; break;
	case NFS3ERR_NOTEMPTY:	p = "Directory not empty"; break;
	case NFS3ERR_DQUOT:	p = "Disc quota exceeded"; break;
	case NFS3ERR_STALE:	p = "Stale NFS file handle"; break;
	case NFS3ERR_REMOTE:	p = "Too many levels of remote in path"; break;
	case NFS3ERR_BADHANDLE:	p = "Illegal NFS file handle"; break;
	case NFS3ERR_NOT_SYNC:	p = "Update synch mismatch"; break;
	case NFS3ERR_BAD_COOKIE:p = "Readdir cookie is stale"; break;
	case NFS3ERR_NOTSUPP:	p = "Operation not supported"; break;
	case NFS3ERR_TOOSMALL:	p = "Buffer/request too small"; break;
	case NFS3ERR_SERVERFAULT:p = "Server fault"; break;
	case NFS3ERR_BADTYPE:	p = "Bad type"; break;
	case NFS3ERR_JUKEBOX:	p = "File is temporarily unavailable"; break;
	default:		p = "(unknown error)"; break;
	}

	(void) strcpy(line, p);
	return (status);
}

int
detail_nfsstat3()
{
	ulong_t status;
	char buff[64];
	int pos;

	pos = getxdr_pos();
	status = sum_nfsstat3(buff);

	(void) sprintf(get_line(pos, getxdr_pos()), "Status = %d (%s)",
		status, buff);

	return ((int)status);
}

static void
skip_postop()
{

	if (getxdr_bool())
		xdr_skip(21 * 4);	/* XDR size of fattr3 */
}

static void
skip_wcc_data()
{

	if (getxdr_bool() > 0)
		xdr_skip(3 * 8);
	skip_postop();
}

static void
skip_sattr3()
{

	if (getxdr_bool() > 0)
		xdr_skip(4);		/* mode */
	if (getxdr_bool() > 0)
		xdr_skip(4);		/* uid */
	if (getxdr_bool() > 0)
		xdr_skip(4);		/* gid */
	if (getxdr_bool() > 0)
		xdr_skip(8);		/* size */
	if (getxdr_bool() > 0)
		xdr_skip(8);		/* atime */
	if (getxdr_bool() > 0)
		xdr_skip(8);		/* mtime */
}

char *
sum_nfsfh3()
{
	int len;
	int fh;
	static char buff[16];

	len = getxdr_long();
	fh = sum_filehandle(len);
	(void) sprintf(buff, " FH=%04X", fh & 0xFFFF);
	return (buff);
}

void
detail_nfsfh3()
{
	int pos;
	int i, l, len;
	int fh;

	len = getxdr_long();
	pos = getxdr_pos();
	fh = sum_filehandle(len);
	setxdr_pos(pos);
	(void) sprintf(get_line(0, 0), "File handle = [%04X]", fh & 0xFFFF);
	i = 0;
	while (i < len) {
		l = MIN(len - i, 32);
		(void) showxdr_hex(l, " %s");
		i += l;
	}
}

static char *
sum_access()
{
	int bits;
	static char buff[64];

	bits = getxdr_u_long();
	buff[0] = '\0';

	if (bits & ACCESS3_READ)
		(void) strcat(buff, "read,");
	if (bits & ACCESS3_LOOKUP)
		(void) strcat(buff, "lookup,");
	if (bits & ACCESS3_MODIFY)
		(void) strcat(buff, "modify,");
	if (bits & ACCESS3_EXTEND)
		(void) strcat(buff, "extend,");
	if (bits & ACCESS3_DELETE)
		(void) strcat(buff, "delete,");
	if (bits & ACCESS3_EXECUTE)
		(void) strcat(buff, "execute,");
	if (buff[0] != '\0')
		buff[strlen(buff) - 1] = '\0';

	return (buff);
}

static void
detail_access()
{
	uint_t bits;

	bits = showxdr_u_long("Access bits = 0x%08x");
	(void) sprintf(get_line(0, 0), "	%s",
		getflag(bits, ACCESS3_READ, "Read", "(no read)"));
	(void) sprintf(get_line(0, 0), "	%s",
		getflag(bits, ACCESS3_LOOKUP, "Lookup", "(no lookup)"));
	(void) sprintf(get_line(0, 0), "	%s",
		getflag(bits, ACCESS3_MODIFY, "Modify", "(no modify)"));
	(void) sprintf(get_line(0, 0), "	%s",
		getflag(bits, ACCESS3_EXTEND, "Extend", "(no extend)"));
	(void) sprintf(get_line(0, 0), "	%s",
		getflag(bits, ACCESS3_DELETE, "Delete", "(no delete)"));
	(void) sprintf(get_line(0, 0), "	%s",
		getflag(bits, ACCESS3_EXECUTE, "Execute", "(no execute)"));
}

static void
detail_mode(mode)
	int mode;
{

	(void) sprintf(get_line(0, 0), "  Mode = 0%o", mode);
	(void) sprintf(get_line(0, 0),
		"   Setuid = %d, Setgid = %d, Sticky = %d",
		(mode & S_ISUID) != 0,
		(mode & S_ISGID) != 0,
		(mode & S_ISVTX) != 0);
	(void) sprintf(get_line(0, 0), "   Owner's permissions = %s",
		perms(mode >> 6 & 0x7));
	(void) sprintf(get_line(0, 0), "   Group's permissions = %s",
		perms(mode >> 3 & 0x7));
	(void) sprintf(get_line(0, 0), "   Other's permissions = %s",
		perms(mode & 0x7));
}

static void
detail_fattr3()
{
	uint_t fltype, mode, nlinks, uid, gid;
	uint_t major, minor;
	u_longlong_t size, used, fsid, fileid;

	fltype  = getxdr_u_long();
	mode	= getxdr_u_long();
	nlinks	= getxdr_u_long();
	uid	= getxdr_u_long();
	gid	= getxdr_u_long();
	size	= getxdr_u_longlong();
	used 	= getxdr_u_longlong();
	major	= getxdr_u_long();
	minor	= getxdr_u_long();
	fsid	= getxdr_u_longlong();
	fileid	= getxdr_u_longlong();

	(void) sprintf(get_line(0, 0),
		"  File type = %d (%s)",
		fltype, filetype(fltype));
	detail_mode(mode);
	(void) sprintf(get_line(0, 0),
		"  Link count = %u, User ID = %u, Group ID = %u",
		nlinks, uid, gid);
	(void) sprintf(get_line(0, 0),
		"  File size = %llu, Used = %llu",
		size, used);
	(void) sprintf(get_line(0, 0),
		"  Special: Major = %u, Minor = %u",
		major, minor);
	(void) sprintf(get_line(0, 0),
		"  File system id = %llu, File id = %llu",
		fsid, fileid);
	(void) showxdr_date_ns("  Last access time      = %s");
	(void) showxdr_date_ns("  Modification time     = %s");
	(void) showxdr_date_ns("  Attribute change time = %s");
	(void) show_line("");
}

static void
detail_sattr3()
{
	int t;

	if (getxdr_bool())
		detail_mode(getxdr_u_long());
	else
		(void) sprintf(get_line(0, 0), "Mode = (not set)");
	if (getxdr_bool())
		(void) showxdr_long("User ID = %d");
	else
		(void) sprintf(get_line(0, 0), "User ID = (not set)");
	if (getxdr_bool())
		(void) showxdr_long("Group ID = %d");
	else
		(void) sprintf(get_line(0, 0), "Group ID = (not set)");
	if (getxdr_bool())
		(void) showxdr_u_longlong("Size = %llu");
	else
		(void) sprintf(get_line(0, 0), "Size = (not set)");

	if ((t = getxdr_u_long()) == SET_TO_CLIENT_TIME)
		(void) showxdr_date("Access time = %s (set to client time)");
	else if (t == SET_TO_SERVER_TIME)
		(void) sprintf(get_line(0, 0),
				"Access time = (set to server time)");
	else
		(void) sprintf(get_line(0, 0), "Access time = (do not set)");

	if ((t = getxdr_u_long()) == SET_TO_CLIENT_TIME) {
		(void) showxdr_date(
				"Modification time = %s (set to client time)");
	} else if (t == SET_TO_SERVER_TIME)
		(void) sprintf(get_line(0, 0),
				"Modification time = (set to server time)");
	else
		(void) sprintf(get_line(0, 0),
				"Modification time = (do not set)");
	(void) show_line("");
}

static char *
filetype(n)
	int n;
{

	switch (n) {
	case NF3REG:
		return ("Regular File");
	case NF3DIR:
		return ("Directory");
	case NF3BLK:
		return ("Block special");
	case NF3CHR:
		return ("Character special");
	case NF3LNK:
		return ("Symbolic Link");
	case NF3SOCK:
		return ("Unix domain socket");
	case NF3FIFO:
		return ("Named pipe");
	default:
		return ("?");
	}
	/* NOTREACHED */
}

static char *
perms(n)
	int n;
{
	static char buff[4];

	buff[0] = n & 4 ? 'r' : '-';
	buff[1] = n & 2 ? 'w' : '-';
	buff[2] = n & 1 ? 'x' : '-';
	buff[3] = '\0';
	return (buff);
}

static void
detail_wcc_attr()
{

	(void) showxdr_u_longlong("  Size = %llu bytes");
	(void) showxdr_date_ns("  Modification time      = %s");
	(void) showxdr_date_ns("  Attribute change time  = %s");
	(void) show_line("");
}

static void
detail_pre_op_attr(str)
	char *str;
{

	if (getxdr_bool()) {
		(void) sprintf(get_line(0, 0),
			"Pre-operation attributes: %s", str);
		detail_wcc_attr();
	} else
		(void) sprintf(get_line(0, 0),
			"Pre-operation attributes: %s (not available)", str);
}

void
detail_post_op_attr(str)
	char *str;
{

	if (getxdr_bool()) {
		(void) sprintf(get_line(0, 0),
			"Post-operation attributes: %s", str);
		detail_fattr3();
	} else
		(void) sprintf(get_line(0, 0),
			"Post-operation attributes: %s (not available)", str);
}

static void
detail_wcc_data(str)
	char *str;
{

	detail_pre_op_attr(str);
	detail_post_op_attr(str);
}

static char *
sum_readdirres()
{
	static char buff[NFS_MAXNAMLEN + 1]; /* protocol allows longer names */
	static int entries;

	entries = 0;
	if (setjmp(xdr_err)) {
		(void) sprintf(buff, " %d+ entries (incomplete)", entries);
		return (buff);
	}
	skip_postop();
	xdr_skip(8);	/* cookieverf */
	while (getxdr_bool()) {
		entries++;
		xdr_skip(8);				/* fileid */
		(void) getxdr_string(buff, NFS_MAXNAMLEN); /* name */
		xdr_skip(8);				/* cookie */
	}

	(void) sprintf(buff, " %d entries (%s)",
		entries, getxdr_bool() ? "No more" : "More");
	return (buff);
}

static char *
sum_readdirplusres()
{
	static char buff[NFS_MAXNAMLEN + 1]; /* protocol allows longer */
	static int entries;
	int skip;

	entries = 0;
	if (setjmp(xdr_err)) {
		(void) sprintf(buff, " %d+ entries (incomplete)", entries);
		return (buff);
	}
	skip_postop();
	xdr_skip(8);	/* cookieverf */
	while (getxdr_bool()) {
		entries++;
		xdr_skip(8);				/* fileid */
		(void) getxdr_string(buff, NFS_MAXNAMLEN); /* name */
		xdr_skip(8);				/* cookie */
		skip_postop();				/* post-op */
		if (getxdr_bool()) {
			skip = getxdr_long();
			xdr_skip(RNDUP(skip));		/* fhandle */
		}
	}

	(void) sprintf(buff, " %d entries (%s)",
		entries, getxdr_bool() ? "No more" : "More");
	return (buff);
}

static void
detail_readdirres()
{
	static int entries;
	u_longlong_t fileid, cookie;
	char *name;
	char buff[NFS_MAXNAMLEN + 1];	/* protocol allows longer names */

	entries = 0;
	detail_post_op_attr("");
	(void) showxdr_hex(8, "Cookie verifier = %s");
	(void) show_line("");
	(void) sprintf(get_line(0, 0), "   File id    Cookie   Name");

	if (setjmp(xdr_err)) {
		(void) sprintf(get_line(0, 0),
			"  %d+ entries. (Frame is incomplete)",
			entries);
		return;
	}
	while (getxdr_bool()) {
		entries++;
		fileid = getxdr_u_longlong();
		name = (char *)getxdr_string(buff, NFS_MAXNAMLEN);
		cookie = getxdr_u_longlong();
		(void) sprintf(get_line(0, 0),
			" %10llu %10llu %s",
			fileid, cookie, name);
	}

	(void) sprintf(get_line(0, 0), "  %d entries", entries);
	(void) showxdr_bool("EOF = %s");
}

static void
detail_readdirplusres()
{
	static int entries;

	entries = 0;
	detail_post_op_attr("");
	(void) showxdr_hex(8, "Cookie verifier = %s");
	(void) show_line("");

	if (setjmp(xdr_err)) {
		(void) sprintf(get_line(0, 0),
			"  %d+ entries. (Frame is incomplete)",
			entries);
		return;
	}
	while (getxdr_bool()) {
		entries++;
		(void) sprintf(get_line(0, 0),
			"------------------ entry #%d",
			entries);
		(void) showxdr_u_longlong("File ID = %llu");
		(void) showxdr_string(NFS_MAXNAMLEN, "Name = %s");
		(void) showxdr_u_longlong("Cookie = %llu");
		detail_post_op_attr("");
		if (getxdr_bool())
			detail_nfsfh3();
		else
			(void) sprintf(get_line(0, 0),
					"(No file handle available)");
	}

	(void) show_line("");
	(void) sprintf(get_line(0, 0), "  %d entries", entries);
	(void) showxdr_bool("EOF = %s");
}

static char *
sum_createhow()
{
	long how;

	how = getxdr_long();
	switch (how) {
	case UNCHECKED:
		return ("UNCHECKED");
	case GUARDED:
		return ("GUARDED");
	case EXCLUSIVE:
		return ("EXCLUSIVE");
	default:
		return ("?");
	}
	/* NOTREACHED */
}

static char *
sum_stablehow()
{
	long stable;

	stable = getxdr_long();
	switch (stable) {
	case UNSTABLE:
		return ("ASYNC");
	case DATA_SYNC:
		return ("DSYNC");
	case FILE_SYNC:
		return ("FSYNC");
	default:
		return ("?");
	}
	/* NOTREACHED */
}
