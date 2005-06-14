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
 * Copyright (c) 1991, 1999-2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ident	"%Z%%M%	%I%	%E% SMI"	/* SunOS	*/

#include <sys/types.h>
#include <sys/errno.h>
#include <setjmp.h>
#include <sys/tiuser.h>

#include <rpc/types.h>
#include <rpc/xdr.h>
#include <rpc/auth.h>
#include <rpc/clnt.h>
#include <rpc/rpc_msg.h>
#include <nfs/nfs.h>
#include <rpcsvc/mount.h>
#include <string.h>
#include "snoop.h"
#include "snoop_nfs.h"

#ifndef MIN
#define	MIN(a, b) ((a) < (b) ? (a) : (b))
#endif

extern char *dlc_header;
extern jmp_buf xdr_err;

static void mountcall(int, int);
static void mountreply(int, int);

static void sum_mountstat(char *);
static void sum_mountstat3(char *);
static char *sum_mountfh(void);
static char *sum_mountfh3(void);
static char *sum_exports(void);
static char *sum_mounts(void);

static int detail_mountstat(void);
static void detail_mountstat3(void);
static void detail_mountfh(void);
static void detail_mountfh3(void);
static void detail_exports(void);
static void detail_mounts(void);

static char *statusmsg3(ulong_t);

static char *procnames_short[] = {
	"Null",			/*  0 */
	"Mount",		/*  1 */
	"Get mount list",	/*  2 */
	"Unmount",		/*  3 */
	"Unmountall",		/*  4 */
	"Get export list",	/*  5 */
	"Get export list",	/*  6 */
	"PATHCONF",		/*  7 */
};

static char *procnames_long[] = {
	"Null procedure",		/*  0 */
	"Add mount entry",		/*  1 */
	"Return mount entries",		/*  2 */
	"Remove mount entry",		/*  3 */
	"Remove all mount entries",	/*  4 */
	"Return export list",		/*  5 */
	"Return export list",		/*  6 */
	"Get POSIX Pathconf info",	/*  7 */
};

#define	MAXPROC	7

void
interpret_mount(flags, type, xid, vers, proc, data, len)
	int flags, type, xid, vers, proc;
	char *data;
	int len;
{
	char *line;
	char buff[MNTPATHLEN + 1];

	if (proc < 0 || proc > MAXPROC)
		return;

	if (flags & F_SUM) {
		if (setjmp(xdr_err)) {
			return;
		}

		line = get_sum_line();

		if (type == CALL) {
			(void) sprintf(line, "MOUNT%d C %s",
				vers, procnames_short[proc]);
			line += strlen(line);
			switch (proc) {
			case MOUNTPROC_MNT:
			case MOUNTPROC_UMNT:
				(void) sprintf(line, " %s",
					getxdr_string(buff, MNTPATHLEN));
				break;
			case MOUNTPROC_DUMP:
			case MOUNTPROC_UMNTALL:
			case MOUNTPROC_EXPORT:
			case MOUNTPROC_EXPORTALL:
#ifdef MOUNTPROC_PATHCONF
			case MOUNTPROC_PATHCONF:
				if (vers != 3)
					(void) sprintf(line, " %s",
						getxdr_string(buff,
						    MNTPATHLEN));
#endif
				break;
			default:
				break;
			}

			check_retransmit(line, xid);
		} else {
			(void) sprintf(line, "MOUNT%d R %s ",
				vers, procnames_short[proc]);
			line += strlen(line);
			switch (proc) {
			case MOUNTPROC_MNT:
				if (vers == 3)
					sum_mountstat3(line);
				else
					sum_mountstat(line);
				break;
			case MOUNTPROC_DUMP:
				(void) sprintf(line, sum_mounts());
				break;
			case MOUNTPROC_UMNT:
			case MOUNTPROC_UMNTALL:
				(void) sprintf(line, "reply");
				break;
			case MOUNTPROC_EXPORTALL:
				/*
				 * EXPORTALL is the same as EXPORT in v1
				 * and v2, and it doesn't exist in v3.
				 */
				if (vers == 3)
					break;
				/*FALLTHROUGH*/
			case MOUNTPROC_EXPORT:
				(void) sprintf(line, sum_exports());
				break;
#ifdef MOUNTPROC_PATHCONF
			case MOUNTPROC_PATHCONF:
				if (vers != 2)
					break;
#ifdef notyet
				(void) sprintf(line, sum_ppathcnf());
#endif
				break;
#endif
			default:
				break;
			}
		}
	}

	if (flags & F_DTAIL) {
		show_header("MOUNT:", "NFS MOUNT", len);
		show_space();
		if (setjmp(xdr_err)) {
			return;
		}
		(void) sprintf(get_line(0, 0),
			"Proc = %d (%s)",
			proc, procnames_long[proc]);
		if (type == CALL)
			mountcall(proc, vers);
		else
			mountreply(proc, vers);
		show_trailer();
	}
}

/*
 *  Interpret call packets in detail
 */

static void
mountcall(proc, vers)
	int proc, vers;
{

	switch (proc) {
	case MOUNTPROC_MNT:
	case MOUNTPROC_UMNT:
		(void) showxdr_string(MNTPATHLEN, "Directory = %s");
		break;
	case MOUNTPROC_DUMP:
		break;
	case MOUNTPROC_UMNTALL:
		break;
	case MOUNTPROC_EXPORTALL:
		if (vers == 3)
			break;
		break;
	case MOUNTPROC_EXPORT:
		break;
#ifdef MOUNTPROC_PATHCONF
	case MOUNTPROC_PATHCONF:
		if (vers != 2)
			break;
		(void) showxdr_string(MNTPATHLEN, "File = %s");
#endif
		break;
	default:
		break;
	}
}

/*
 *  Interpret reply packets in detail
 */

static void
mountreply(proc, vers)
	int proc, vers;
{

	switch (proc) {
	case MOUNTPROC_MNT:
		if (vers == 3) {
			detail_mountstat3();
		} else {
			if (detail_mountstat() == 0) {
				detail_mountfh();
			}
		}
		break;
	case MOUNTPROC_DUMP:
		detail_mounts();
		break;
	case MOUNTPROC_UMNT:
	case MOUNTPROC_UMNTALL:
		(void) detail_mountstat();
		break;
	case MOUNTPROC_EXPORTALL:
		if (vers == 3)
			break;
		/*FALLTHROUGH*/
	case MOUNTPROC_EXPORT:
		detail_exports();
		break;
#ifdef MOUNTPROC_PATHCONF
	case MOUNTPROC_PATHCONF:
#ifdef notyet
		(void) detail_ppathcnf();
#endif
		break;
#endif
	default:
		break;
	}
}

static void
sum_mountstat(line)
	char *line;
{
	ulong_t status;
	char *str;

	status = getxdr_u_long();
	if (status == 0)
		str = "OK";
	else if ((str = strerror(status)) == (char *)NULL)
		str = "";
	(void) strcpy(line, str);
	if (status == 0) {
		(void) strcat(line, sum_mountfh());
	}
}

static int
detail_mountstat()
{
	ulong_t status;
	char *str;

	status = getxdr_u_long();
	if (status == 0)
		str = "OK";
	else if ((str = strerror(status)) == (char *)NULL)
		str = "";

	(void) sprintf(get_line(0, 0), "Status = %d (%s)", status, str);

	return ((int)status);
}

char *
sum_mountfh()
{
	int fh;
	static char buff[8];

	fh = sum_filehandle(NFS_FHSIZE);
	(void) sprintf(buff, " FH=%04X", fh & 0xFFFF);
	return (buff);
}

static void
detail_mountfh()
{
	int pos;
	int fh;

	pos = getxdr_pos();
	fh = sum_filehandle(NFS_FHSIZE);
	setxdr_pos(pos);
	(void) sprintf(get_line(0, 0), "File handle = [%04X]", fh & 0xFFFF);
	(void) showxdr_hex(NFS_FHSIZE, " %s");
}

static char *
print_auth()
{
	int i, auth, flavors;
	char *p;
	static char buff[64];

	buff[0] = '\0';
	flavors = getxdr_long();
	for (i = 0; i < flavors; i++) {
		if (i > 0)
			(void) strlcat(buff, ",", sizeof (buff));
		switch (auth = getxdr_u_long()) {
		case AUTH_NONE:
			(void) strlcat(buff, "none", sizeof (buff));
			break;
		case AUTH_UNIX:
			(void) strlcat(buff, "unix", sizeof (buff));
			break;
		case AUTH_SHORT:
			(void) strlcat(buff, "short", sizeof (buff));
			break;
		case AUTH_DES:
			(void) strlcat(buff, "des", sizeof (buff));
			break;
		default:
			p = buff + strlen(buff);
			if (p < &buff[sizeof (buff)])
				(void) snprintf(p, sizeof (buff) - strlen(buff),
					"%d", auth);
			break;
		}
	}
	return (buff);
}

static void
sum_mountstat3(line)
	char *line;
{
	ulong_t status;

	status = getxdr_u_long();
	(void) strcpy(line, statusmsg3(status));
	if (status == 0) {
		(void) strcat(line, sum_mountfh3());
		(void) strcat(line, " Auth=");
		(void) strcat(line, print_auth());
	}
}

static void
detail_mountstat3()
{
	ulong_t status;

	status = getxdr_u_long();
	(void) sprintf(get_line(0, 0), "Status = %d (%s)", status,
			statusmsg3(status));
	if (status == 0) {
		detail_mountfh3();
		(void) sprintf(get_line(0, 0), "Authentication flavor = %s",
				print_auth());
	}
}

char *
sum_mountfh3()
{
	int len;
	int fh;
	static char buff[8];

	len = getxdr_long();
	fh = sum_filehandle(len);
	(void) sprintf(buff, " FH=%04X", fh & 0xFFFF);
	return (buff);
}

static void
detail_mountfh3()
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
sum_exports()
{
	static char buff[MNTPATHLEN + 1];
	int entries = 0;

	if (setjmp(xdr_err)) {
		(void) sprintf(buff, "%d+ entries", entries);
		return (buff);
	}

	while (getxdr_long()) {
		(void) getxdr_string(buff, MNTPATHLEN);
		while (getxdr_long()) {
			(void) getxdr_string(buff, MNTNAMLEN);
		}
		entries++;
	}

	(void) sprintf(buff, "%d entries", entries);
	return (buff);
}

static void
detail_exports()
{
	int entries = 0;
	char *dirpath, *grpname;
	char buff[MNTPATHLEN + 1];

	if (setjmp(xdr_err)) {
		(void) sprintf(get_line(0, 0),
			" %d+ entries. (Frame is incomplete)",
			entries);
		return;
	}

	while (getxdr_long()) {
		dirpath = (char *)getxdr_string(buff, MNTPATHLEN);
		(void) sprintf(get_line(0, 0), "Directory = %s", dirpath);
		entries++;
		while (getxdr_long()) {
			grpname = (char *)getxdr_string(buff, MNTNAMLEN);
			(void) sprintf(get_line(0, 0), " Group = %s", grpname);
		}
	}
}

static char *
sum_mounts()
{
	int entries = 0;
	static char buff[MNTPATHLEN + 1];

	if (setjmp(xdr_err)) {
		(void) sprintf(buff, "%d+ entries", entries);
		return (buff);
	}

	while (getxdr_long()) {
		(void) getxdr_string(buff, MNTNAMLEN);
		(void) getxdr_string(buff, MNTPATHLEN);
		entries++;
	}

	(void) sprintf(buff, "%d entries", entries);
	return (buff);
}

static void
detail_mounts()
{
	int entries = 0;
	char *hostname, *directory;
	char buff1[MNTNAMLEN + 1], buff2[MNTPATHLEN + 1];

	if (setjmp(xdr_err)) {
		(void) sprintf(get_line(0, 0),
			" %d+ entries. (Frame is incomplete)",
			entries);
		return;
	}

	(void) sprintf(get_line(0, 0), "Mount list");

	while (getxdr_long()) {
		hostname  = (char *)getxdr_string(buff1, MNTNAMLEN);
		directory = (char *)getxdr_string(buff2, MNTPATHLEN);
		(void) sprintf(get_line(0, 0), "   %s:%s", hostname, directory);
		entries++;
	}
}

char *
statusmsg3(status)
	ulong_t status;
{

	switch (status) {
	case MNT_OK:
		return ("OK");
	case MNT3ERR_PERM:
		return ("Not owner");
	case MNT3ERR_NOENT:
		return ("No such file or directory");
	case MNT3ERR_IO:
		return ("I/O error");
	case MNT3ERR_ACCES:
		return ("Permission denied");
	case MNT3ERR_NOTDIR:
		return ("Not a directory");
	case MNT3ERR_INVAL:
		return ("Invalid argument");
	case MNT3ERR_NAMETOOLONG:
		return ("File name too long");
	case MNT3ERR_NOTSUPP:
		return ("Operation not supported");
	case MNT3ERR_SERVERFAULT:
		return ("Server error");
	default:
		return ("(unknown error)");
	}
}
