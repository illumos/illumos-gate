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
 * Copyright 1991-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/errno.h>
#include <sys/tiuser.h>
#include <setjmp.h>

#include <rpc/types.h>
#include <rpc/xdr.h>
#include <rpc/auth.h>
#include <rpc/clnt.h>
#include <rpc/rpc_msg.h>
#include <string.h>
#include "snoop.h"
#include "snoop_nfs.h"

#include <sys/stat.h>
#include <rpcsvc/nfs_prot.h>

static char *perms(int);
static char *filetype(int);
static char *sum_readdirres(void);
static void detail_readdirres(void);
static void detail_diroparg(void);
static void nfscall2(int);
static void nfsreply2(int);
static void detail_mode(int);
static void detail_sattr(void);
static void interpret_nfs2(int, int, int, int, int, char *, int);

extern jmp_buf xdr_err;

static char *procnames_short[] = {
	"NULL2",	/*  0 */
	"GETATTR2",	/*  1 */
	"SETATTR2",	/*  2 */
	"ROOT2",	/*  3 */
	"LOOKUP2",	/*  4 */
	"READLINK2",	/*  5 */
	"READ2",	/*  6 */
	"WRITECACHE2",	/*  7 */
	"WRITE2",	/*  8 */
	"CREATE2",	/*  9 */
	"REMOVE2",	/* 10 */
	"RENAME2",	/* 11 */
	"LINK2",	/* 12 */
	"SYMLINK2",	/* 13 */
	"MKDIR2",	/* 14 */
	"RMDIR2",	/* 15 */
	"READDIR2",	/* 16 */
	"STATFS2",	/* 17 */
};

static char *procnames_long[] = {
	"Null procedure",		/*  0 */
	"Get file attributes",		/*  1 */
	"Set file attributes",		/*  2 */
	"Get root filehandle",		/*  3 */
	"Look up file name",		/*  4 */
	"Read from symbolic link",	/*  5 */
	"Read from file",		/*  6 */
	"Write to cache",		/*  7 */
	"Write to file",		/*  8 */
	"Create file",			/*  9 */
	"Remove file",			/* 10 */
	"Rename",			/* 11 */
	"Link",				/* 12 */
	"Make symbolic link",		/* 13 */
	"Make directory",		/* 14 */
	"Remove directory",		/* 15 */
	"Read from directory",		/* 16 */
	"Get filesystem attributes",	/* 17 */
};

#define	MAXPROC	17

/* ARGSUSED */
void
interpret_nfs(flags, type, xid, vers, proc, data, len)
	int flags, type, xid, vers, proc;
	char *data;
	int len;
{

	if (vers == 2) {
		interpret_nfs2(flags, type, xid, vers, proc, data, len);
		return;
	}

	if (vers == 3) {
		interpret_nfs3(flags, type, xid, vers, proc, data, len);
		return;
	}

	if (vers == 4) {
		interpret_nfs4(flags, type, xid, vers, proc, data, len);
		return;
	}
}

static void
interpret_nfs2(flags, type, xid, vers, proc, data, len)
	int flags, type, xid, vers, proc;
	char *data;
	int len;
{
	char *line;
	char buff[NFS_MAXPATHLEN + 1];
	int off, sz;
	char *fh;

	if (proc < 0 || proc > MAXPROC)
		return;

	if (flags & F_SUM) {
		line = get_sum_line();

		if (type == CALL) {
			(void) sprintf(line,
				"NFS C %s",
				procnames_short[proc]);
			line += strlen(line);
			switch (proc) {
			case NFSPROC_GETATTR:
			case NFSPROC_READLINK:
			case NFSPROC_STATFS:
			case NFSPROC_SETATTR:
				(void) sprintf(line, sum_nfsfh());
				break;
			case NFSPROC_LOOKUP:
			case NFSPROC_REMOVE:
			case NFSPROC_RMDIR:
			case NFSPROC_CREATE:
			case NFSPROC_MKDIR:
				fh = sum_nfsfh();
				(void) sprintf(line, "%s %s",
					fh,
					getxdr_string(buff, NFS_MAXNAMLEN));
				break;
			case NFSPROC_WRITE:
				fh = sum_nfsfh();
				(void) getxdr_long();	/* beginoff */
				off = getxdr_long();
				(void) getxdr_long();	/* totalcount */
				sz  = getxdr_long();
				(void) sprintf(line, "%s at %d for %d",
					fh, off, sz);
				break;
			case NFSPROC_RENAME:
				fh = sum_nfsfh();
				(void) sprintf(line, "%s %s",
					fh,
					getxdr_string(buff, NFS_MAXNAMLEN));
				line += strlen(line);
				fh = sum_nfsfh();
				(void) sprintf(line, " to%s %s",
					fh,
					getxdr_string(buff, NFS_MAXNAMLEN));
				break;
			case NFSPROC_LINK:
				fh = sum_nfsfh();
				(void) sprintf(line, "%s", fh);
				line += strlen(line);
				fh = sum_nfsfh();
				(void) sprintf(line, " to%s %s",
					fh,
					getxdr_string(buff, NFS_MAXNAMLEN));
				break;
			case NFSPROC_SYMLINK:
				fh = sum_nfsfh();
				(void) sprintf(line, "%s %s",
					fh,
					getxdr_string(buff, NFS_MAXNAMLEN));
				line += strlen(line);
				(void) sprintf(line, " to %s",
					getxdr_string(buff, NFS_MAXPATHLEN));
				break;
			case NFSPROC_READDIR:
				fh = sum_nfsfh();
				(void) sprintf(line, "%s Cookie=%lu",
					fh, getxdr_u_long());
				break;
			case NFSPROC_READ:
				fh = sum_nfsfh();
				off = getxdr_long();
				sz  = getxdr_long();
				(void) sprintf(line, "%s at %d for %d",
					fh, off, sz);
				break;
			default:
				break;
			}

			check_retransmit(line, (ulong_t)xid);
		} else {
			(void) sprintf(line, "NFS R %s ",
				procnames_short[proc]);
			line += strlen(line);
			switch (proc) {
			case NFSPROC_CREATE:
			case NFSPROC_MKDIR:
			case NFSPROC_LOOKUP:
				if (sum_nfsstat(line) == 0) {
					line += strlen(line);
					(void) sprintf(line, sum_nfsfh());
				}
				break;
			case NFSPROC_READLINK:
				if (sum_nfsstat(line) == 0) {
					line += strlen(line);
					(void) sprintf(line, " (Path=%s)",
						getxdr_string(buff,
							NFS_MAXPATHLEN));
				}
				break;
			case NFSPROC_GETATTR:
			case NFSPROC_SYMLINK:
			case NFSPROC_STATFS:
			case NFSPROC_SETATTR:
			case NFSPROC_REMOVE:
			case NFSPROC_RMDIR:
			case NFSPROC_WRITE:
			case NFSPROC_RENAME:
			case NFSPROC_LINK:
				(void) sum_nfsstat(line);
				break;
			case NFSPROC_READDIR:
				if (sum_nfsstat(line) == 0) {
					line += strlen(line);
					(void) strcat(line, sum_readdirres());
				}
				break;
			case NFSPROC_READ:
				if (sum_nfsstat(line) == 0) {
					line += strlen(line);
					xdr_skip(68); /* fattrs */
					(void) sprintf(line, " (%ld bytes)",
						getxdr_long());
				}
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
			nfscall2(proc);
		else
			nfsreply2(proc);
		show_trailer();
	}
}

/*
 *  Print out version 2 NFS call packets
 */
static void
nfscall2(proc)
	int proc;
{
	switch (proc) {
	case NFSPROC_GETATTR:
	case NFSPROC_READLINK:
	case NFSPROC_STATFS:
		detail_nfsfh();
		break;
	case NFSPROC_SETATTR:
		detail_nfsfh();
		detail_sattr();
		break;
	case NFSPROC_LOOKUP:
	case NFSPROC_REMOVE:
	case NFSPROC_RMDIR:
		detail_diroparg();
		break;
	case NFSPROC_MKDIR:
	case NFSPROC_CREATE:
		detail_diroparg();
		detail_sattr();
		break;
	case NFSPROC_WRITE:
		detail_nfsfh();
		(void) getxdr_long();	/* begoff */
		(void) showxdr_long("Offset = %d");
		(void) getxdr_long();	/* totalcount */
		(void) showxdr_long("(%d bytes(s) of data)");
		break;
	case NFSPROC_RENAME:
		detail_diroparg();
		detail_diroparg();
		break;
	case NFSPROC_LINK:
		detail_nfsfh();
		detail_diroparg();
		break;
	case NFSPROC_SYMLINK:
		detail_diroparg();
		(void) showxdr_string(NFS_MAXPATHLEN, "Path = %s");
		detail_sattr();
		break;
	case NFSPROC_READDIR:
		detail_nfsfh();
		(void) showxdr_u_long("Cookie = %lu");
		(void) showxdr_long("Count = %d");
		break;
	case NFSPROC_READ:
		detail_nfsfh();
		(void) showxdr_long("Offset = %d");
		(void) showxdr_long("Count = %d");
		break;
	default:
		break;
	}
}

/*
 *  Print out version 2 NFS reply packets
 */
static void
nfsreply2(proc)
	int proc;
{
	switch (proc) {
	    case NFSPROC_GETATTR:
	    case NFSPROC_SETATTR:
	    case NFSPROC_WRITE:
		/* attrstat */
		if (detail_nfsstat() == 0) {
			detail_fattr();
		}
		break;
	    case NFSPROC_LOOKUP:
	    case NFSPROC_CREATE:
	    case NFSPROC_MKDIR:
		/* diropres */
		if (detail_nfsstat() == 0) {
			detail_nfsfh();
			detail_fattr();
		}
		break;
	    case NFSPROC_READLINK:
		/* readlinkres */
		if (detail_nfsstat() == 0) {
			(void) showxdr_string(NFS_MAXPATHLEN, "Path = %s");
		}
		break;
	    case NFSPROC_READ:
		/* readres */
		if (detail_nfsstat() == 0) {
			detail_fattr();
			(void) showxdr_long("(%d byte(s) of data)");
		}
		break;
	    case NFSPROC_REMOVE:
	    case NFSPROC_RENAME:
	    case NFSPROC_LINK:
	    case NFSPROC_SYMLINK:
	    case NFSPROC_RMDIR:
		/* stat */
		detail_nfsstat();
		break;
	    case NFSPROC_READDIR:
		/* readdirres */
		if (detail_nfsstat() == 0)
			detail_readdirres();
		break;
	    case NFSPROC_STATFS:
		/* statfsres */
		if (detail_nfsstat() == 0) {
			(void) showxdr_long("Transfer size = %d");
			(void) showxdr_long("Block size = %d");
			(void) showxdr_long("Total blocks = %d");
			(void) showxdr_long("Free blocks = %d");
			(void) showxdr_long("Available blocks = %d");
		}
		break;
	    default:
		break;
	}
}

static void
detail_diroparg()
{
	detail_nfsfh();
	(void) showxdr_string(NFS_MAXPATHLEN, "File name = %s");
}

/*
 * V2 NFS protocol was implicitly linked with SunOS errnos.
 * Some of the errno values changed in SVr4.
 * Need to map errno value so that SVr4 snoop will interpret
 * them correctly.
 */
static char *
statusmsg(status)
	ulong_t status;
{
	switch (status) {
	case NFS_OK: return ("OK");
	case NFSERR_PERM: return ("Not owner");
	case NFSERR_NOENT: return ("No such file or directory");
	case NFSERR_IO: return ("I/O error");
	case NFSERR_NXIO: return ("No such device or address");
	case NFSERR_ACCES: return ("Permission denied");
	case NFSERR_EXIST: return ("File exists");
	case NFSERR_XDEV: return ("Cross-device link");
	case NFSERR_NODEV: return ("No such device");
	case NFSERR_NOTDIR: return ("Not a directory");
	case NFSERR_ISDIR: return ("Is a directory");
	case NFSERR_INVAL: return ("Invalid argument");
	case NFSERR_FBIG: return ("File too large");
	case NFSERR_NOSPC: return ("No space left on device");
	case NFSERR_ROFS: return ("Read-only file system");
	case NFSERR_OPNOTSUPP: return ("Operation not supported");
	case NFSERR_NAMETOOLONG: return ("File name too long");
	case NFSERR_NOTEMPTY: return ("Directory not empty");
	case NFSERR_DQUOT: return ("Disc quota exceeded");
	case NFSERR_STALE: return ("Stale NFS file handle");
	case NFSERR_REMOTE: return ("Object is remote");
	case NFSERR_WFLUSH: return ("write cache flushed");
	default: return ("(unknown error)");
	}
	/* NOTREACHED */
}

int
sum_nfsstat(line)
	char *line;
{
	ulong_t status;

	status = getxdr_long();
	(void) strcpy(line, statusmsg(status));
	return (status);
}

int
detail_nfsstat()
{
	ulong_t status;
	int pos;

	pos = getxdr_pos();
	status = getxdr_long();
	(void) sprintf(get_line(pos, getxdr_pos()),
		"Status = %lu (%s)",
		status, statusmsg(status));

	return ((int)status);
}

int
sum_filehandle(len)
	int len;
{
	int i, l;
	int fh = 0;

	for (i = 0; i < len; i += 4) {
		l = getxdr_long();
		fh ^= (l >> 16) ^ l;
	}

	return (fh);
}

char *
sum_nfsfh()
{
	int fh;
	static char buff[16];

	fh = sum_filehandle(NFS_FHSIZE);
	(void) sprintf(buff, " FH=%04X", fh & 0xFFFF);
	return (buff);
}

void
detail_nfsfh()
{
	int pos;
	int fh;

	pos = getxdr_pos();
	fh = sum_filehandle(NFS_FHSIZE);
	setxdr_pos(pos);
	(void) sprintf(get_line(0, 0), "File handle = [%04X]", fh & 0xFFFF);
	(void) showxdr_hex(NFS_FHSIZE, " %s");
}

static void
detail_mode(mode)
	int mode;
{
	char *str;

	switch (mode & S_IFMT) {
	case S_IFDIR: str = "Directory";	break;
	case S_IFCHR: str = "Character";	break;
	case S_IFBLK: str = "Block";		break;
	case S_IFREG: str = "Regular file";	break;
	case S_IFLNK: str = "Link";		break;
	case S_IFSOCK: str = "Socket";		break;
	case S_IFIFO: str = "Fifo";		break;
	default: str = "?";			break;
	}

	(void) sprintf(get_line(0, 0), "Mode = 0%o", mode);
	(void) sprintf(get_line(0, 0), " Type = %s", str);
	(void) sprintf(get_line(0, 0),
		" Setuid = %d, Setgid = %d, Sticky = %d",
		(mode & S_ISUID) != 0,
		(mode & S_ISGID) != 0,
		(mode & S_ISVTX) != 0);
	(void) sprintf(get_line(0, 0), " Owner's permissions = %s",
		perms(mode >> 6 & 0x7));
	(void) sprintf(get_line(0, 0), " Group's permissions = %s",
		perms(mode >> 3 & 0x7));
	(void) sprintf(get_line(0, 0), " Other's permissions = %s",
		perms(mode & 0x7));
}

void
detail_fattr()
{
	int fltype, mode, nlinks, uid, gid, size, blksz;
	int rdev, blocks, fsid, fileid;

	fltype = getxdr_long();
	mode = getxdr_long();
	nlinks = getxdr_long();
	uid = getxdr_long();
	gid = getxdr_long();
	size = getxdr_long();
	blksz = getxdr_long();
	rdev = getxdr_long();
	blocks = getxdr_long();
	fsid = getxdr_long();
	fileid = getxdr_long();

	(void) sprintf(get_line(0, 0),
		"File type = %d (%s)",
		fltype, filetype(fltype));
	detail_mode(mode);
	(void) sprintf(get_line(0, 0),
		"Link count = %d, UID = %d, GID = %d, Rdev = 0x%x",
		nlinks, uid, gid, rdev);
	(void) sprintf(get_line(0, 0),
		"File size = %d, Block size = %d, No. of blocks = %d",
		size, blksz, blocks);
	(void) sprintf(get_line(0, 0),
		"File system id = %d, File id = %d",
		fsid, fileid);
	(void) showxdr_date("Access time       = %s");
	(void) showxdr_date("Modification time = %s");
	(void) showxdr_date("Inode change time = %s");
}

static void
detail_sattr()
{
	int mode;

	mode = getxdr_long();
	detail_mode(mode);
	(void) showxdr_long("UID = %d");
	(void) showxdr_long("GID = %d");
	(void) showxdr_long("Size = %d");
	(void) showxdr_date("Access time       = %s");
	(void) showxdr_date("Modification time = %s");
}

static char *
filetype(n)
	int n;
{
	switch (n) {
	    case NFREG: return ("Regular File");
	    case NFDIR: return ("Directory");
	    case NFBLK: return ("Block special");
	    case NFCHR: return ("Character special");
	    case NFLNK: return ("Symbolic Link");
	    default:	return ("?");
	}
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

static char *
sum_readdirres()
{
	static char buff[NFS_MAXNAMLEN + 1];
	int entries = 0;

	if (setjmp(xdr_err)) {
		(void) sprintf(buff, " %d+ entries (incomplete)", entries);
		return (buff);
	}
	while (getxdr_long()) {
		entries++;
		(void) getxdr_long();			/* fileid */
		(void) getxdr_string(buff, NFS_MAXNAMLEN); /* name */
		(void) getxdr_u_long();			/* cookie */
	}

	(void) sprintf(buff, " %d entries (%s)",
		entries,
		getxdr_long() ? "No more" : "More");
	return (buff);
}

static void
detail_readdirres()
{
	ulong_t fileid, cookie;
	int entries = 0;
	char *name;
	char buff[NFS_MAXNAMLEN + 1];

	(void) sprintf(get_line(0, 0), " File id  Cookie Name");

	if (setjmp(xdr_err)) {
		(void) sprintf(get_line(0, 0),
			"  %d+ entries. (Frame is incomplete)",
			entries);
		return;
	}
	while (getxdr_long()) {
		entries++;
		fileid = getxdr_long();
		name = (char *)getxdr_string(buff, NFS_MAXNAMLEN);
		cookie = getxdr_u_long();
		(void) sprintf(get_line(0, 0),
			" %7lu %7lu %s",
			fileid, cookie, name);
	}

	(void) sprintf(get_line(0, 0), "  %d entries", entries);
	(void) showxdr_long("EOF = %d");
}

void
skip_fattr()
{

	xdr_skip(17 * 4);	/* XDR sizeof nfsfattr */
}
