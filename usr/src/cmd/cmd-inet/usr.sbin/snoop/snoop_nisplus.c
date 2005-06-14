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
 * Copyright (c) 1991, 1999, 2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <ctype.h>
#include <sys/types.h>
#include <sys/errno.h>
#include <setjmp.h>
#include <string.h>

#include <netinet/in.h>
#include <rpc/types.h>
#include <rpc/rpc.h>
#include <rpc/xdr.h>
#include <rpc/auth.h>
#include <rpc/clnt.h>
#include <rpc/rpc_msg.h>
#include <rpcsvc/nis.h>
#include <rpcsvc/nis_callback.h>

#include "snoop.h"
#include "nis_clnt.h"

extern char *dlc_header;
extern jmp_buf xdr_err;

/*
 * Number of spaces for each level of indentation.  Since this value is
 *   assumed in most of the strings below, defining it is pretty quixotic.
 */
#define	INDENT_SPACES	4

/*
 * ==== Old (pre Sep '91) format for public keys in NIS+ directories, now
 *	removed from the header files.  Should be removed from snoop once
 *	we're sure we won't see old-style packets
 */
#ifndef SZ_PKEY
#define	SZ_PKEY 64
#endif /* SZ_PKEY */

/*
 * ==== New (Aug '91) NIS+ remote procedure, which hasn't made into our
 *	header files yet.  When it does, nuke this stuff.
 */
#ifndef	NIS_UPDKEYS
#define	NIS_UPDKEYS	24
#endif	/* NIS_UPDKEYS */

/*
 * ==== Constants for public keys.  We should use NIS_MAXKEYLEN and the
 *	key-type constants from the NIS+ header files, but at present (Aug '91)
 *	we're ahead of the header files.
 */
#define	KEYLEN_FIRST	0
#define	KEYLEN_LIMIT	1024
#define	KEYTYPE_FIRST	0
#define	KEYTYPE_LIMIT	3


static char *procnames_short[] = {
	"Null",		/*  0 */
	"Lookup",	/*  1 */
	"Add",		/*  2 */
	"Modify",	/*  3 */
	"Remove",	/*  4 */
	"IBlist",	/*  5 */
	"IBadd",	/*  6 */
	"IBmodify",	/*  7 */
	"IBremove",	/*  8 */
	"IBfirst",	/*  9 */
	"IBnext",	/*  10 */
	"** Unused 11",	/*  11 */
	"FindDir",	/*  12 */
	"** Unused 13",	/*  13 */
	"Status",	/*  14 */
	"DumpLog",	/*  15 */
	"Dump",		/*  16 */
	"Callback",	/*  17 */
	"CheckpointTime",	/*  18 */
	"Checkpoint",	/*  19 */
	"Ping",		/*  20 */
	"ServerState",	/*  21 */
	"MakeDir",	/*  22 */
	"RemoveDir",	/*  23 */
	"UpdateKeys",	/*  24 */
};

static char *procnames_long[] = {
	"Null procedure",		/*  0 */
	"Lookup",			/*  1 */
	"Add",				/*  2 */
	"Modify",			/*  3 */
	"Remove",			/*  4 */
	"List IBase",			/*  5 */
	"Add to IBase",			/*  6 */
	"Modify IBase",			/*  7 */
	"Remove from IBase",		/*  8 */
	"IBase First Entry",		/*  9 */
	"IBase Next Entry",		/*  10 */
	"** 11 (Unused) **",		/*  11 */
	"Find Directory",		/*  12 */
	"** 13 (Unused) **",		/*  13 */
	"Get/Reset Statistics",		/*  14 */
	"Dump Directory Log",		/*  15 */
	"Dump Directory Contents",	/*  16 */
	"Check Callback Thread",	/*  17 */
	"Get Checkpoint Time",		/*  18 */
	"Establish Checkpoint",		/*  19 */
	"Ping Replicas",		/*  20 */
	"Change Server State",		/*  21 */
	"Make Directory",		/*  22 */
	"Remove Directory",		/*  23 */
	"Update Public Keys",		/*  24 */
};

#define	MAXPROC	24

static void detail_bool(void);
static void detail_callback(void);
static void detail_cback_data(void);
static void detail_cookie(void);
static void detail_cp_result(void);
static void detail_cptime(void);
static void detail_dump_args(void);
static void detail_ib_request(void);
static void detail_fd_args(void);
static void detail_fd_result(void);
static void detail_log_entry(void);
static void detail_log_result(void);
static void detail_nis_attrs(int);
static void detail_nis_error(void);
static void detail_nis_name(void);
static void detail_nis_result(void);
static void detail_nis_taglist(void);
static void detail_ns_request(void);
static void detail_ping_args(void);
static int is_printable(char *, unsigned int);
static void sum_bool(char *);
static void sum_callback(char *);
static void sum_cback_data(char *);
static void sum_cp_result(char *);
static void sum_cptime(char *);
static void sum_dump_args(char *);
static void sum_ib_request(char *);
static void sum_fd_args(char *);
static void sum_fd_result(char *);
static void sum_log_result(char *);
static void sum_nis_error(char *);
static void sum_nis_name(char *);
static void sum_nis_result(char *);
static void sum_nis_taglist(char *);
static void sum_ns_request(char *);
static void sum_ping_args(char *);

void
interpret_nisplus(flags, type, xid, vers, proc, data, len)
	int flags, type, xid, vers, proc;
	char *data;
	int len;
{
	char *line;

	if (proc < 0 || proc > MAXPROC)
		return;

	if (flags & F_SUM) {
		if (setjmp(xdr_err)) {
			return;
		}

		line = get_sum_line();

		if (type == CALL) {
			(void) sprintf(line,
				"NIS+ C %s",
				procnames_short[proc]);
			line += strlen(line);

			switch (proc) {
			case NIS_LOOKUP:
			case NIS_ADD:
			case NIS_MODIFY:
			case NIS_REMOVE:
				sum_ns_request(line);
				break;
			case NIS_IBLIST:
			case NIS_IBADD:
			case NIS_IBMODIFY:
			case NIS_IBREMOVE:
			case NIS_IBFIRST:
			case NIS_IBNEXT:
				sum_ib_request(line);
				break;
			case NIS_FINDDIRECTORY:
				sum_fd_args(line);
				break;
			case NIS_STATUS:
			case NIS_SERVSTATE:
				sum_nis_taglist(line);
				break;
			case NIS_DUMPLOG:
			case NIS_DUMP:
				sum_dump_args(line);
				break;
			case NIS_CALLBACK:
				sum_callback(line);
				break;
			case NIS_PING:
				sum_ping_args(line);
				break;
			case NIS_CPTIME:
			case NIS_CHECKPOINT:
			case NIS_MKDIR:
			case NIS_RMDIR:
			case NIS_UPDKEYS:
				sum_nis_name(line);
				break;
			default:
				/* === mutter about bogus procnums? */
				break;
			}

			check_retransmit(line, xid);
		} else {
			(void) sprintf(line, "NIS+ R %s ",
				procnames_short[proc]);
			line += strlen(line);
			switch (proc) {
			case NIS_LOOKUP:
			case NIS_ADD:
			case NIS_MODIFY:
			case NIS_REMOVE:
			case NIS_IBLIST:
			case NIS_IBADD:
			case NIS_IBMODIFY:
			case NIS_IBREMOVE:
			case NIS_IBFIRST:
			case NIS_IBNEXT:
				sum_nis_result(line);
				break;
			case NIS_FINDDIRECTORY:
				sum_fd_result(line);
				break;
			case NIS_STATUS:
			case NIS_SERVSTATE:
				sum_nis_taglist(line);
				break;
			case NIS_DUMPLOG:
			case NIS_DUMP:
				sum_log_result(line);
				break;
			case NIS_CALLBACK:
				sum_bool(line);
				break;
			case NIS_CPTIME:
				sum_cptime(line);
				break;
			case NIS_CHECKPOINT:
				sum_cp_result(line);
				break;
			case NIS_PING:
				break;
			case NIS_MKDIR:
			case NIS_RMDIR:
			case NIS_UPDKEYS:
				sum_nis_error(line);
				break;
			default:
				/* === mutter about bogus procnums? */
				break;
			}
		}
	}

	if (flags & F_DTAIL) {
		show_header("NIS+:  ", "NIS+ Name Service", len);
		show_space();
		if (setjmp(xdr_err)) {
			return;
		}
		(void) sprintf(get_line(0, 0),
			"Proc = %d (%s)",
			proc, procnames_long[proc]);

		if (type == CALL) {
			switch (proc) {
			case NIS_LOOKUP:
			case NIS_ADD:
			case NIS_MODIFY:
			case NIS_REMOVE:
				detail_ns_request();
				break;
			case NIS_IBLIST:
			case NIS_IBADD:
			case NIS_IBMODIFY:
			case NIS_IBREMOVE:
			case NIS_IBFIRST:
			case NIS_IBNEXT:
				detail_ib_request();
				break;
			case NIS_FINDDIRECTORY:
				detail_fd_args();
				break;
			case NIS_STATUS:
			case NIS_SERVSTATE:
				detail_nis_taglist();
				break;
			case NIS_DUMPLOG:
			case NIS_DUMP:
				detail_dump_args();
				break;
			case NIS_CALLBACK:
				detail_callback();
				break;
			case NIS_PING:
				detail_ping_args();
				break;
			case NIS_CPTIME:
			case NIS_CHECKPOINT:
			case NIS_MKDIR:
			case NIS_RMDIR:
			case NIS_UPDKEYS:
				detail_nis_name();
				break;
			default:
				/* === mutter about bogus procnums? */
				break;
			}
		} else {
			switch (proc) {
			case NIS_LOOKUP:
			case NIS_ADD:
			case NIS_MODIFY:
			case NIS_REMOVE:
			case NIS_IBLIST:
			case NIS_IBADD:
			case NIS_IBMODIFY:
			case NIS_IBREMOVE:
			case NIS_IBFIRST:
			case NIS_IBNEXT:
				detail_nis_result();
				break;
			case NIS_FINDDIRECTORY:
				detail_fd_result();
				break;
			case NIS_STATUS:
			case NIS_SERVSTATE:
				detail_nis_taglist();
				break;
			case NIS_DUMPLOG:
			case NIS_DUMP:
				detail_log_result();
				break;
			case NIS_CALLBACK:
				detail_bool();
				break;
			case NIS_CPTIME:
				detail_cptime();
				break;
			case NIS_CHECKPOINT:
				detail_cp_result();
				break;
			case NIS_PING:
				break;
			case NIS_MKDIR:
			case NIS_RMDIR:
			case NIS_UPDKEYS:
				detail_nis_error();
				break;
			default:
				/* === mutter about bogus procnums? */
				break;
			}
		}

		show_trailer();
	}
}

static char *cbnames_short[] = {
	"Null",		/*  0 */
	"Receive",	/*  1 */
	"Finish",	/*  2 */
	"Error",	/*  3 */
};

static char *cbnames_long[] = {
	"Null procedure",		/*  0 */
	"Receive Callback Data",	/*  1 */
	"Finish Callback",		/*  2 */
	"Callback Error",		/*  3 */
};

void
interpret_nisp_cb(flags, type, xid, vers, proc, data, len)
	int flags, type, xid, vers, proc;
	char *data;
	int len;
{
	char *line;

	if (flags & F_SUM) {
		if (setjmp(xdr_err)) {
			return;
		}

		line = get_sum_line();

		if (type == CALL) {
			(void) sprintf(line,
				"NIS+ Callback C %s",
				cbnames_short[proc]);
			line += strlen(line);

			switch (proc) {
			    case CBPROC_RECEIVE:
				sum_cback_data(line);
				break;
			    case CBPROC_FINISH:
				/* void: nothing to do */
				break;
			    case CBPROC_ERROR:
				sum_nis_error(line);
				break;
			    default:
				/* === mutter about bogus procnums? */
				break;
			}

			check_retransmit(line, xid);
		} else {
			(void) sprintf(line, "NIS+ Callback R %s ",
				cbnames_short[proc]);
			line += strlen(line);
			switch (proc) {
			    case CBPROC_RECEIVE:
				sum_bool(line);
				break;
			    case CBPROC_FINISH:
			    case CBPROC_ERROR:
				/* void: nothing to do */
				break;
			    default:
				/* === mutter about bogus procnums? */
				break;
			}
		}
	}

	if (flags & F_DTAIL) {
		show_header("NIS+ CB:  ", "NIS+ Name Service Callback", len);
		show_space();
		if (setjmp(xdr_err)) {
			return;
		}
		(void) sprintf(get_line(0, 0),
			"Proc = %d (%s)",
			proc, cbnames_long[proc]);

		if (type == CALL) {
			switch (proc) {
			    case CBPROC_RECEIVE:
				detail_cback_data();
				break;
			    case CBPROC_FINISH:
				/* void: nothing to do */
				break;
			    case CBPROC_ERROR:
				detail_nis_error();
				break;
			    default:
				/* === mutter about bogus procnums? */
				break;
			}
		} else {
			switch (proc) {
			    case CBPROC_RECEIVE:
				detail_bool();
				break;
			    case CBPROC_FINISH:
			    case CBPROC_ERROR:
				/* void: nothing to do */
				break;
			    default:
				/* === mutter about bogus procnums? */
				break;
			}
		}

		show_trailer();
	}
}

/*
 * stringof_XXX() routines -- return printable representations of various
 *	numeric values.  Would be nice if we could get this from the NIS+
 *	library instead of reinventing them.
 * N.B.  Mucho use of pointer-to-static result types (ugh); don't expect the
 *	return value to stay good for long.
 */

#ifndef RIGHTS_FORMAT
#define	RIGHTS_FORMAT	1
#endif	/* RIGHTS_FORMAT */

static struct {
	int shift;
	char *name;
} rightsclasses[] = {
#if	RIGHTS_FORMAT == 1
	24,	"",
	16,	"",
	8,	"",
	0,	"",
#elif	RIGHTS_FORMAT == 2
	16,	"o:",
	8,	"g:",
	0,	"w:",
	24,	"u:",
#else	/* RIGHTS_FORMAT == 3 */
	16,	"owner:",
	8,	"group:",
	0,	"world:",
	24,	"unauth:",
#endif	/* RIGHTS_FORMAT */
};

char *
stringof_rights(rights)
	unsigned rights;
{
	static char rightsbuf[100];
	char *p;
	int i;

	sprintf(rightsbuf, "%08x (", rights);
	p = rightsbuf + strlen(rightsbuf);

	for (i = 0; i < 4; i++) {
		int shift = rightsclasses[i].shift;
		strcpy(p, rightsclasses[i].name);
		p += strlen(p);
		*p++ = (rights >> shift) & NIS_READ_ACC    ? 'r' : '-';
		*p++ = (rights >> shift) & NIS_MODIFY_ACC  ? 'm' : '-';
		*p++ = (rights >> shift) & NIS_CREATE_ACC  ? 'c' : '-';
		*p++ = (rights >> shift) & NIS_DESTROY_ACC ? 'd' : '-';
		*p++ = ' ';
		rights &= ~((NIS_READ_ACC   | NIS_MODIFY_ACC  |
				NIS_CREATE_ACC | NIS_DESTROY_ACC) << shift);
	}
	if (rights == 0) {
		p[-1] = ')';		/* Nuke that last space */
		p[ 0] = 0;
	} else {
		sprintf(p, "+ Unknown bits: %08x **)", rights);
	}
	return (rightsbuf);
}

char *
stringof_ib_flags(flags)
	unsigned flags;
{
	static char flagsbuf[120];

	if (flags == 0) {
		sprintf(flagsbuf, "%08x", flags);
		return (flagsbuf);
	}
	sprintf(flagsbuf,
		"%08x (%s%s%s%s",
		flags,
		flags & MOD_SAMEOBJ		? "MOD_SAMEOBJ, "	: "",
		flags & REM_MULTIPLE		? "REM_MULTIPLE, "	: "",
		flags & ADD_OVERWRITE		? "ADD_OVERWRITE, "	: "",
		flags & RETURN_RESULT		? "RETURN_RESULT, "	: "");
	flags &= ~(MOD_SAMEOBJ | REM_MULTIPLE | ADD_OVERWRITE | RETURN_RESULT);
	if (flags != 0) {
		sprintf(flagsbuf + strlen(flagsbuf),
			"** Unknown bits %08x **, ", flags);
	}
	/* Replace the trailing ", " with ")" */
	sprintf(flagsbuf + strlen(flagsbuf) - 2, ")");
	return (flagsbuf);
}

char *
stringof_colflags(flags)
	unsigned flags;
{
	static char flagsbuf[120];

	if (flags == 0) {
		sprintf(flagsbuf, "%08x", flags);
		return (flagsbuf);
	}
	sprintf(flagsbuf,
		"%08x (%s%s%s%s%s",
		flags,
		flags & TA_CASE		? "Case-insensitive, "	: "",
		flags & TA_SEARCHABLE	? "Searchable, "	: "",
		flags & TA_XDR		? "XDR Encoded, "	: "",
		flags & TA_CRYPT	? "Encrypted, "		: "",
		flags & TA_BINARY	? "Binary, " 		: "");
	flags &= ~(TA_CASE | TA_SEARCHABLE | TA_XDR | TA_CRYPT | TA_BINARY);
	if (flags != 0) {
		sprintf(flagsbuf + strlen(flagsbuf),
			"** Unknown bits %08x **, ", flags);
	}
	/* Replace the trailing ", " with ")" */
	sprintf(flagsbuf + strlen(flagsbuf) - 2, ")");
	return (flagsbuf);
}

char *
stringof_entryflags(flags)
	unsigned flags;
{
	static char flagsbuf[100];

	if (flags == 0) {
		sprintf(flagsbuf, "%08x", flags);
		return (flagsbuf);
	}
	sprintf(flagsbuf,
		"%08x (%s%s%s%s",
		flags,
		flags & EN_MODIFIED	? "Modified, "		: "",
		flags & EN_XDR		? "XDR Encoded, "	: "",
		flags & EN_CRYPT	? "Encrypted, "		: "",
		flags & EN_BINARY	? "Binary, " 		: "");
	flags &= ~(EN_MODIFIED | EN_XDR | EN_CRYPT | EN_BINARY);
	if (flags != 0) {
		sprintf(flagsbuf + strlen(flagsbuf),
			"** Unknown bits %08x **, ", flags);
	}
	/* Replace the trailing ", " with ")" */
	sprintf(flagsbuf + strlen(flagsbuf) - 2, ")");
	return (flagsbuf);
}

char *
stringof_groupflags(flags)
	unsigned flags;
{
	static char flagsbuf[80];

	if (flags == 0) {
		sprintf(flagsbuf, "%08x", flags);
		return (flagsbuf);
	}
	sprintf(flagsbuf,
		"%08x (%s%s%s",
		flags,
		flags & NEGMEM_GROUPS	? "Negative, "		: "",
		flags & RECURS_GROUPS	? "Recursive, "		: "",
		flags & IMPMEM_GROUPS	? "Implicit, "		: "");
	flags &= ~(NEGMEM_GROUPS | RECURS_GROUPS | IMPMEM_GROUPS);
	if (flags != 0) {
		sprintf(flagsbuf + strlen(flagsbuf),
			"** Unknown bits %08x **, ", flags);
	}
	/* Replace the trailing ", " with ")" */
	sprintf(flagsbuf + strlen(flagsbuf) - 2, ")");
	return (flagsbuf);
}

char *
stringof_tag(ttype)
	int ttype;
{
	switch (ttype) {
	    case TAG_DEBUG:	return ("DEBUG");
	    case TAG_STATS:	return ("STATS");
	    case TAG_GCACHE:	return ("GCACHE");
	    case TAG_DCACHE:	return ("DCACHE");
	    case TAG_OCACHE:	return ("OCACHE");
	    case TAG_SECURE:	return ("SECURE");

#ifdef undef
/*
 * Old tags, removed September '91 (some of the tag-numbers have been
 *   reassigned, just to make things completely confusing).
 */
	    case TAG_LOOKUPS:	return ("LOOKUPS";
	    case TAG_S_LOOKUPS:	return ("S_LOOKUPS";
	    case TAG_U_LOOKUPS:	return ("U_LOOKUPS";
#endif /* undef */
	    case TAG_OPSTATS:	return ("OPSTATS");
	    case TAG_THREADS:	return ("THREADS");
	    case TAG_UPDATES:	return ("UPDATES");
	    case TAG_VISIBLE:	return ("VISIBLE");
	    case TAG_S_DCACHE:	return ("S_DCACHE");
	    case TAG_S_OCACHE:	return ("S_OCACHE");
	    case TAG_S_GCACHE:	return ("S_GCACHE");
	    case TAG_S_STORAGE:	return ("S_STORAGE");

	    default:		return ("*Unknown*");
	}
}

char *
stringof_otype(otype)
	int otype;
{
	static char buf[30];

	switch (otype) {
	    case NIS_BOGUS_OBJ:	return ("BOGUS (uninitialized?)");
	    case NIS_NO_OBJ:	return ("NULL");
	    case NIS_DIRECTORY_OBJ:	return ("DIRECTORY");
	    case NIS_GROUP_OBJ:	return ("GROUP");
	    case NIS_TABLE_OBJ:	return ("TABLE");
	    case NIS_ENTRY_OBJ:	return ("ENTRY");
	    case NIS_LINK_OBJ:	return ("LINK");
	    case NIS_PRIVATE_OBJ:	return ("PRIVATE");
	    default:		sprintf(buf, "** Unknown (%d) **", otype);
				return (buf);
	}
}

char *
stringof_entry_t(et)
	int et;
{
	static char buf[30];

	switch (et) {
	    case LOG_NOP:	return ("LOG_NOP");	/* === lowercase? */
	    case ADD_NAME:	return ("ADD_NAME");
	    case REM_NAME:	return ("REM_NAME");
	    case MOD_NAME_OLD:	return ("MOD_NAME_OLD");
	    case MOD_NAME_NEW:	return ("MOD_NAME_NEW");
	    case ADD_IBASE:	return ("ADD_IBASE");
	    case REM_IBASE:	return ("REM_IBASE");
	    case MOD_IBASE:	return ("MOD_IBASE");
	    case UPD_STAMP:	return ("UPD_STAMP");
	    default:		sprintf(buf, "** Unknown (%d) **", et);
				return (buf);
	}
}

char *
stringof_ktype(ktype)
	unsigned ktype;
{
	static char buf[40];
	char *p;

	sprintf(buf, "%d ", ktype);
	p = buf + strlen(buf);
	switch (ktype) {
	    case 0:	strcpy(p, "(None)");		break;
	    case 1:	strcpy(p, "(Diffie-Hellman)");	break;
	    case 2:	strcpy(p, "(RSA)");		break;
	    case 4:	strcpy(p, "(Diffie-Hellman Ext)"); break;
	    default:	strcpy(p, "(** Unknown **)");	break;
	}
	return (buf);
}

static void
sumxdr_nis_name(line)
	char *line;
{
	char buff[NIS_MAXNAMELEN + 1];

	(void) sprintf(line, " \"%s\"", getxdr_string(buff, NIS_MAXNAMELEN));
	/* ==== ? could/should truncate long names a la showxdr_string() ? */
}

static unsigned
sumxdr_nis_error(line)
	char *line;
{
	unsigned err = getxdr_u_long();
	sprintf(line, "[%s]", nis_sperrno(err));
	return (err);
}

static void
sum_ns_request(line)
	char *line;
{
	sumxdr_nis_name(line);
	/* Leave the optional object for detailed listings */
}

int nchars_attrval = 32;

static void
sum_ib_request(line)
	char *line;
{
	unsigned long nattrs;
	unsigned long len;
	int pos;
	char *val;
	char buff[NIS_MAXATTRNAME + 1];

	sumxdr_nis_name(line);
	line += strlen(line);
	nattrs = getxdr_u_long();
	switch (nattrs) {
	    case 0:
		/* === Could print "No attrs " */
		break;
	    case 1:
		sprintf(line, " [%s = ", getxdr_string(buff, NIS_MAXATTRNAME));
		line += strlen(line);
		pos = getxdr_pos();
		val = getxdr_bytes((uint_t *)&len);
		if (is_printable(val, len)) {
			if (len - 1 > nchars_attrval) {
				sprintf(line, "(%d-character value)", len);
			} else {
				sprintf(line, "\"%s\"", val);
			}
		} else {
			if ((len - 1) * 2 > nchars_attrval) {
				sprintf(line, "(%d-byte value)", len);
			} else {
				/*
				 * Too lazy to print hex ourselves; instead,
				 *   back up and use snoop's hex-printer
				 */
				setxdr_pos(pos);
				len = getxdr_u_long(); /* Yes, we did know it */
				strcpy(line, getxdr_hex(len));
			}
		}
		line += strlen(line);
		*line++ = ']';
		*line = 0;
		break;
	    default:
		sprintf(line, " (Num attrs = %lu)", nattrs);
		/* === Note that we haven't skipped the attrs */
		break;
	}
	/* === Don't bother with flags, obj, cbhost, bufsize, cookie */
}

static void
sum_fd_args(line)
	char *line;
{
	sumxdr_nis_name(line);
#ifdef LESS_TERSE
	strcat(line, " for");
	sumxdr_nis_name(line + strlen(line));
#endif /* LESS_TERSE */
}

#define	MAXTAGLEN	1024		/* num chars of tag to display */

static void
sum_nis_taglist(line)
	char *line;
{
	char buff[MAXTAGLEN + 1];
	unsigned ntags;
	unsigned ttype;

	ntags = getxdr_u_long();
	if (ntags == 0) {
		strcpy(line, " [But no tags !?]");
		return;
	}
	ttype = getxdr_u_long();
	sprintf(line,
		" %s=\"%s\"", stringof_tag(ttype),
		getxdr_string(buff, MAXTAGLEN));
	if (ntags > 1) {
		sprintf(line + strlen(line), " [and %lu more tags]", ntags - 1);
	}
}

static void
sum_dump_args(line)
	char *line;
{
	sumxdr_nis_name(line);
	strcat(line, " from ");
	strcat(line, getxdr_time());
}

/*ARGSUSED*/
static void
sum_callback(line)	/* i.e. the netobj argument to NIS_CALLBACK */
	char *line;
{
	/* netobjs are pretty opaque, so don't try to summarize */
}

static void
sum_ping_args(line)
	char *line;
{
	sumxdr_nis_name(line);
	strcat(line, " at ");
	strcat(line, getxdr_time());
}

static void
sum_nis_name(line)
	char *line;
{
	sumxdr_nis_name(line);
}

static void
sum_cback_data(line)
	char *line;
{
	(void) sprintf(line, " (%lu entries)", getxdr_u_long());
}

static void
sum_nis_result(line)
	char *line;
{
	unsigned nobjs;

	(void) sumxdr_nis_error(line);
	nobjs = getxdr_u_long();
	if (nobjs != 0) {
		sprintf(line + strlen(line),
			" and %lu object%s", nobjs, (nobjs == 1) ? "" : "s");
	}
}

static void
sum_fd_result(line)
	char *line;
{
	(void) sumxdr_nis_error(line);
#ifdef LESS_TERSE
	strcat(line, " from");
	sumxdr_nis_name(line + strlen(line));
#endif /* LESS_TERSE */
}

static void
sum_log_result(line)
	char *line;
{
	uint_t dummy;
	unsigned nents;

	(void) sumxdr_nis_error(line);
	(void) getxdr_bytes(&dummy);	/* Skip netobj lr_cookie */
	nents = getxdr_u_long();
	sprintf(line + strlen(line),
		" and %lu log entr%s", nents, (nents == 1) ? "y" : "ies");
}

static void
sum_bool(line)
	char *line;
{
	(void) sprintf(line, getxdr_u_long() ? "true" : "false");
}

static void
sum_cptime(line)
	char *line;
{
	(void) sprintf(line, " %s", getxdr_time());
}

static void
sum_cp_result(line)
	char *line;
{
	(void) sumxdr_nis_error(line);
}

static void
sum_nis_error(line)
	char *line;
{
	(void) sumxdr_nis_error(line);
}

#define	SHOW_NIS_NAME(format)	(void) showxdr_string(NIS_MAXNAMELEN, format)
#define	SHOW_NAME()		SHOW_NIS_NAME("Name = %s")

/*
 * showxdr_longhex() -- ersatz wrapper around showxdr_hex() to ensure we
 *	don't display too much on one line.  Multi-line results will
 *  ===	probably look pretty awful, but we may at least prevent core-dumps
 */
int nwords_longhex = 8;

static void
showxdr_longhex(len, fmt)
	int len;
	char *fmt;
{
	int nbytes_longhex = 4 * nwords_longhex;

	while (len > nbytes_longhex) {
		showxdr_hex(nbytes_longhex, fmt);
		len -= nbytes_longhex;
	}
	showxdr_hex(len, fmt);
}

static void
detail_nis_error()
{
	enum nis_error status;
	int pos;

	pos = getxdr_pos();
	status = (enum nis_error) getxdr_u_long();
	sprintf(get_line(pos, getxdr_pos()),
		"Status = %lu (%s)", status, nis_sperrno(status));
}

void
detail_nis_oid()
{
	showxdr_time("    Object created at %s");
	showxdr_time("     last modified at %s");
}

static void
detail_nis_server(outdent)
	int outdent;	/* Crock to get indentation right.  Normally zero; */
			/*   set to four instead to remove leading spaces  */
{
	unsigned nep;
	unsigned ktype;
	int pos1;

	SHOW_NIS_NAME(outdent + "        Hostname = %s");
	nep = getxdr_u_long();
	while (nep-- > 0) { /* list of endpoints */
		(void) showxdr_string(1024,
					outdent + "            Uaddr    = %s");
		(void) showxdr_string(1024,
					outdent + "            Family   = %s");
		(void) showxdr_string(1024,
					outdent + "            Protocol = %s");
	}
	/*
	 * The format of the public-key information has changed (Aug '91).
	 *   Ye olde style was a u_char[64] (which XDR's pretty inefficiently,
	 *   but that's another matter).  The new format has a key-type
	 *   enumeration followed by an opaque<NIS_MAXKEYLEN>.  For now
	 *   (hence probably for all time) we'll hard-code the values of the
	 *   enumeration and of NIS_MAXKEYLEN here rather than getting them
	 *   from a header file.  Tsk.  Also for now, we'll try to guess
	 *   whether we're looking at the new format or the old.
	 */
	pos1 = getxdr_pos();
	ktype = getxdr_u_long();
	if (ktype < KEYTYPE_LIMIT || ktype == NIS_PK_DHEXT) {
		int	 pos2;
		unsigned klen;

		pos2 = getxdr_pos();
		klen = getxdr_u_long();
		if (klen < KEYLEN_LIMIT) {
			/*
			 * Smells like new-style key; let's hope so.  If we're
			 *   wrong, it may cause XDR underflow.  Ugh.  ====
			 */
			sprintf(get_line(pos1, pos2),
				outdent + "        Key type   = %s",
				stringof_ktype(ktype));
			sprintf(get_line(pos2, getxdr_pos()),
				outdent + "        Key length = %lu", klen);
			if (klen != 0) {
				if (ktype == NIS_PK_DHEXT) {
					int marker;
					int key_count;
					marker = getxdr_pos();
					key_count = 1;
					while (getxdr_pos() < marker + klen) {
						ulong_t  a_u_long;
						ushort_t keylen;
						ushort_t algtype;
						size_t  binlen;
						size_t  binpadlen;

						a_u_long = getxdr_u_long();
						keylen = a_u_long >> 16;
						algtype = a_u_long &
							((ushort_t)0xffff);
						binlen = (keylen + 7) / 8;
						binpadlen = ((binlen + 3) / 4)
								* 4;
						sprintf(get_line(0, 0),
					"            Key %d length = %hu bits",
							key_count, keylen);
						sprintf(get_line(0, 0),
					"            Algorithm type = %hu",
							algtype);
						if (keylen != 0)
							showxdr_hex(binpadlen,
					"            Key value = %s");
						key_count++;
					}
					setxdr_pos(marker + klen);
				} else {
					showxdr_hex(klen, outdent +
					    "        Key value  = %s");
				}
			}
			return;
		}
	}
	/*
	 * It didn't smell new, so assume it's the old u_char[64], which
	 *   XDR's as 64 32-bit words (ouch).
	 */
	setxdr_pos(4*SZ_PKEY + pos1);
	sprintf(get_line(pos1, getxdr_pos()),
		outdent + "        [Public Key not displayed]");
}

void
detail_directory_obj()
{
	unsigned nstyp;
	unsigned nserv, nar;
	int pos;
	char *line;

	SHOW_NIS_NAME("    Name    = %s");
	pos = getxdr_pos();
	nstyp = getxdr_u_long();
	line = get_line(pos, getxdr_pos());
	(void) sprintf(line, "    NStype  = %lu", nstyp);
	line += strlen(line);

	switch (nstyp) {
	    case NIS:
		sprintf(line, " (NIS+)");
		break;
	    case SUNYP:
		sprintf(line, " (NIS/YP)");
		break;
	    case DNS:
		sprintf(line, " (DNS)");
		break;
	    default:
		break;
	}

	nserv = showxdr_u_long("    Servers = %lu");
	while (nserv-- > 0) {	/* array of servers */
		detail_nis_server(0);
	}
	(void) showxdr_u_long("    Time to live  = %lu (seconds)");
	/* === show time in more useful form too? */
	nar = showxdr_u_long("    Access Rights = %lu");
	while (nar-- > 0) {	/* list of ar masks */
		unsigned ar, otype;
		pos = getxdr_pos();
		ar = getxdr_u_long();
		otype = getxdr_u_long();
		sprintf(get_line(pos, getxdr_pos()), "        %s for %s",
			stringof_rights(ar), stringof_otype(otype));
	}
}

void
detail_group_obj()
{
	unsigned val;
	int pos;

	pos = getxdr_pos();
	val = getxdr_u_long();
	sprintf(get_line(pos, getxdr_pos()),
		"    Flags    = %s", stringof_groupflags(val));
	val = showxdr_u_long("    Number of Members = %lu");
	while (val-- > 0) {
		SHOW_NIS_NAME("        %s");
	}
}

void
detail_table_obj()
{
	unsigned ncols;
	unsigned col;
	(void) showxdr_string(1024, "    Table Type  = %s");
	(void) showxdr_long  ("    Max Columns = %d");
	(void) showxdr_char  ("    Separator   = '%c'"); /* ==== improve */
	ncols = showxdr_u_long("    Num Columns = %lu");
	for (col = 1; col <= ncols; col++) {
		int pos1, pos2;
		unsigned val;
		char format[23];
		/* === Print all three on one line? */
		sprintf(format, "%6d: ColName = \"%%s\"", col);
		(void) showxdr_string(NIS_MAXATTRNAME, format);
		pos1 = getxdr_pos();
		val = getxdr_u_long();
		pos2 = getxdr_pos();
		sprintf(get_line(pos1, pos2),
			"        Flags   = %s", stringof_colflags(val));
		val = getxdr_u_long();
		sprintf(get_line(pos2, getxdr_pos()),
			"        Rights  = %s", stringof_rights(val));
	}
	(void) showxdr_string(NIS_MAXPATH, "    Search Path = \"%s\"");
}

void
detail_entry_obj()
{
	unsigned col, ncols;
	char *entyp;
	int is_nis_object = 0;

	entyp = showxdr_string(1024, "    Entry Type  = \"%s\"");
	is_nis_object = (entyp != 0 && strcmp(entyp, "NIS object") == 0);
	/* Don't rely on entyp[] remaining valid */
	ncols = showxdr_u_long("    Num Columns = %lu");
	for (col = 1; col <= ncols; col++) {
		int pos1, pos2, len;
		unsigned flags;
		/* === Print both on one line? */
		pos1 = getxdr_pos();
		flags = getxdr_u_long();
		pos2 = getxdr_pos();
		if (ncols == 1) {
			sprintf(get_line(pos1, pos2),
				"        Flags = %s",
				stringof_entryflags(flags));
		} else {
			sprintf(get_line(pos1, pos2),
				"%6d: Flags = %s",
				col, stringof_entryflags(flags));
		}
		if (flags & (EN_BINARY | EN_CRYPT | EN_XDR)) {
			len = getxdr_u_long();
			if (is_nis_object &&
			    len == sizeof (unsigned long) &&
			    (flags & EN_CRYPT) == 0) {
				/* Special case for type = "NIS object" */
				unsigned otype = getxdr_u_long();
				sprintf(get_line(pos2, getxdr_pos()),
					"        Value = %08x (ObjType = %s)",
					otype, stringof_otype(otype));
			} else {
				showxdr_longhex(len,
						"        Value = Binary %s");
			}
		} else {
			showxdr_string(NIS_MAXATTRVAL,
					"        Value = ASCII \"%s\"");
		}
	}
}

void
detail_link_obj()
{
	int pos;
	int val;

	pos = getxdr_pos();
	val = getxdr_long();
	sprintf(get_line(pos, getxdr_pos()),
		"    Real Type= %08x (%s)", val, stringof_otype(val));
	detail_nis_attrs(0);
	SHOW_NIS_NAME("    Real Name= %s");
}

void
detail_private_obj()
{
	/* ==== Need something fancier than this to be really useful */
	showxdr_longhex(getxdr_u_long(), "    Data     = Binary %s");
}

void
detail_nis_object()
{
	unsigned rights, otype;
	int pos;

	detail_nis_oid();
	SHOW_NIS_NAME("    Name     = %s");
	SHOW_NIS_NAME("    Owner    = %s");
	SHOW_NIS_NAME("    Group    = %s");
	SHOW_NIS_NAME("    Domain   = %s");
	pos = getxdr_pos();
	rights = getxdr_u_long();
	sprintf(get_line(pos, getxdr_pos()), "    Rights   = %s",
		stringof_rights(rights));
	(void) showxdr_u_long("    Lifetime = %8lu (seconds)");

	/* ?? show_space(); */
	pos = getxdr_pos();
	otype = getxdr_u_long();
	(void) sprintf(get_line(pos, getxdr_pos()),
			"    ObjType  = %08x (%s)",
			otype, stringof_otype(otype));
	switch (otype) {
	    case NIS_DIRECTORY_OBJ:
		detail_directory_obj();
		break;
	    case NIS_GROUP_OBJ:
		detail_group_obj();
		break;
	    case NIS_TABLE_OBJ:
		detail_table_obj();
		break;
	    case NIS_ENTRY_OBJ:
		detail_entry_obj();
		break;
	    case NIS_LINK_OBJ:
		detail_link_obj();
		break;
	    case NIS_PRIVATE_OBJ:
		detail_private_obj();
		break;
	    default:
		/* ==== Can't do anything clever, right? */
		break;
	}
}

static void
detail_ns_request()
{
	unsigned nobjs;

	SHOW_NAME();
	nobjs = getxdr_u_long();
	/* nobjs should be 0 or 1 only; === should check it ? */
	if (nobjs != 0) {
		sprintf(get_line(0, 0), "Object included:");
	}
	while (nobjs-- > 0) {
		detail_nis_object();
	}
}

static void
detail_ib_request()
{
	unsigned len;
	unsigned flags;
	int pos;

	SHOW_NAME();
	detail_nis_attrs(INDENT_SPACES);
	pos = getxdr_pos();
	flags = getxdr_u_long();
	sprintf(get_line(pos, getxdr_pos()),
		"Flags = %s", stringof_ib_flags(flags));
	pos = getxdr_pos();
	len = getxdr_u_long();
	if (len == 0) {
		sprintf(get_line(pos, getxdr_pos()), "No included object");
	} else {
		/* len should be 0 or 1 only; === should check it ? */
		sprintf(get_line(pos, getxdr_pos()), "Included object:");
		while (len-- > 0) {
			detail_nis_object();
		}
	}
	pos = getxdr_pos();
	len = getxdr_u_long();
	if (len == 0) {
		sprintf(get_line(pos, getxdr_pos()), "No callback");
	} else {
		/* len should be 0 or 1 only; === should check it ? */
		sprintf(get_line(pos, getxdr_pos()), "Callback info:");
		while (len-- > 0) {
			detail_nis_server(INDENT_SPACES);
		}
	}
	(void) showxdr_u_long("Bufsize = %lu");
	detail_cookie();
}

static void
detail_fd_args()
{
	SHOW_NAME();
	SHOW_NIS_NAME("Requester = %s");
}

static void
detail_nis_taglist()
{
	unsigned ntags;
	unsigned tagn;

	ntags = showxdr_u_long("Number of tags = %lu");
	for (tagn = 1; tagn < ntags; tagn++) {
		unsigned ttype;
		int pos;

		if (ntags != 1) {
			sprintf(get_line(0, 0), "  Tag %d:", tagn);
		}
		pos = getxdr_pos();
		ttype = getxdr_u_long();
		sprintf(get_line(pos, getxdr_pos()),
			"    Tag name  = %08x (%s)",
			ttype, stringof_tag(ttype));
		showxdr_string(1024, "    Tag value = \"%s\"");
		/* ^ ==== nis.x says it's a string rather than an opaque, */
		/*	  but is it really?				  */
	}
}

static void
detail_dump_args()
{
	unsigned nserv;
	int pos;

	SHOW_NAME();
	showxdr_time("Time = %s");

	pos = getxdr_pos();
	nserv = getxdr_u_long();
	if (nserv == 1) {
		sprintf(get_line(pos, getxdr_pos()), "Callback:");
	} else if (nserv > 1) {
		sprintf(get_line(pos, getxdr_pos()),
			"Num callbacks = %lu (!?):", nserv);
	}
	while (nserv-- > 0) {
		detail_nis_server(INDENT_SPACES);
	}
}

static void
detail_callback()	/* i.e. the netobj argument to NIS_CALLBACK */
{
	detail_cookie();
}

static void
detail_cookie()
{
	unsigned len;
	int pos;

	pos = getxdr_pos();
	len = getxdr_u_long();
	if (len == 0) {
		sprintf(get_line(pos, getxdr_pos()), "Cookie = NULL");
	} else {
		showxdr_longhex(len, "Cookie = %s");
	}
}

static void
detail_ping_args()
{
	SHOW_NAME();
	showxdr_time("Time = %s");
}

static void
detail_nis_name()
{
	SHOW_NAME();
}

static void
detail_cback_data()
{
	unsigned nobjs, no;
	nobjs = showxdr_u_long("Number of entries = %lu");
	for (no = 1; no <= nobjs; no++) {
		if (getxdr_long() == 0) {
			sprintf(get_line(0, 0), "  Entry %d is NULL (!?)", no);
		} else {
			if (nobjs != 1) {

				sprintf(get_line(0, 0), "  Entry %d:", no);
			}
			detail_nis_object();
		}
	}
}

static void
detail_nis_result()
{
	int pos;
	unsigned no, nobjs;

	detail_nis_error();
	pos = getxdr_pos();
	nobjs = getxdr_u_long();
	sprintf(get_line(pos, getxdr_pos()), "Number of objects = %lu", nobjs);
	for (no = 1; no <= nobjs; no++) {
		if (nobjs != 1) {
			sprintf(get_line(0, 0), "  Object %d:", no);
		}
		detail_nis_object();
	}
	detail_cookie();
	showxdr_u_long("Server   ticks = %8lu");
	showxdr_u_long("Database ticks = %8lu");
	showxdr_u_long("Cache    ticks = %8lu"); /* These should always be   */
	showxdr_u_long("Client   ticks = %8lu"); /*   zero on the wire, yes? */
}

static void
detail_fd_result()
{
	int pos;
	unsigned len;
	int dir_pos;
	unsigned dir_len;
	int dir_end;

	detail_nis_error();
	SHOW_NAME();
	/* nis.x doesn't say so, but the opaque contains a directory_obj */
	dir_len = getxdr_u_long(); /* Byte-count at start of opaque */
	if (dir_len == 0) {
		sprintf(get_line(0, 0), "Directory object = NULL");
	} else {
		sprintf(get_line(0, 0), "Directory object:");
		dir_pos = getxdr_pos();
		dir_end = ((dir_len + 3) & ~3) + dir_pos;
		/*		^^^^^^^^^^ Did XDR do this already? */
		detail_directory_obj();
		pos = getxdr_pos();
		if (pos != dir_end) {
			sprintf(get_line(pos, dir_end),
			"(Skipping %d unused bytes at end of directory object)",
				dir_end - pos);
			setxdr_pos(dir_end);
		}
	}
	len = getxdr_u_long();
	if (len == 0) {
		sprintf(get_line(pos, getxdr_pos()),
			"Signature = NULL");
	} else {
		if (len > 8) {
			sprintf(get_line(pos, getxdr_pos()),
				"Signature length is %lu, expected <= 8 bytes",
				len);
		}
		showxdr_longhex(len, "Signature = %s");
	}
}

/*
 * is_printable() -- looks for a string of (len-1) printable characters
 *	followed by a NUL.  Characters are deemed printable iff ctype's
 *	isprint() macro says so, thus tab (^I) is regarded as unprintable.
 * === Is this test more stringent than we want, esp wrt placement of NUL?
 */
static int
is_printable(str, len)
	char	 *str;
	unsigned len;
{
	while (len > 1) {
		if (!isprint(*str)) {
			return (0);
		}
		str++, len--;
	}
	return (len == 1 && *str == 0);
}

static void
detail_nis_attrs(outdent)
	int outdent;	/* Crock to get indentation right.  Normally zero; */
			/*   set to four instead to remove leading spaces  */
{
	unsigned nattrs;

	nattrs = showxdr_u_long(outdent + "    Number of attributes = %lu");
	while (nattrs-- > 0) {
		char	 *str;
		unsigned len;
		int pos;

		showxdr_string(NIS_MAXATTRNAME,
				outdent + "        AttrName = %s");
		pos = getxdr_pos();
		str = getxdr_bytes(&len);
		if (is_printable(str, len)) {
			setxdr_pos(pos);
			showxdr_string(NIS_MAXATTRVAL, outdent +
					"        AttrVal  = ASCII \"%s\"");
		} else {
			setxdr_pos(pos);
			len = getxdr_u_long();	/* Yes, we knew it already */
			showxdr_longhex(len, outdent +
					"        AttrVal  = Binary %s");
		}
	}
}

static void
detail_log_entry()
{
	int pos;
	long val;

	showxdr_time("    Log Time  = %s");
	pos = getxdr_pos();
	val = getxdr_long();
	sprintf(get_line(pos, getxdr_pos()), "    Log Type  = %d (%s)",
		val, stringof_entry_t(val));
	SHOW_NIS_NAME("    Principal = %s");
	SHOW_NIS_NAME("    Table/dir = %s");
	detail_nis_attrs(0);
	sprintf(get_line(0, 0), "    Object Value:");
	detail_nis_object();
}

static void
detail_log_result()
{
	unsigned len, nents, en;
	int pos;

	detail_nis_error();
	pos = getxdr_pos();
	len = getxdr_u_long();
	detail_cookie();
	nents = showxdr_u_long("Number of log entries = %lu");
	for (en = 1; en <= nents; en++) {
		if (nents != 1) {
			sprintf(get_line(0, 0), "  Log Entry %d", en);
		}
		detail_log_entry();
	}
}

static void
detail_bool()
{
	int pos;
	unsigned val;

	pos = getxdr_pos();
	val = getxdr_u_long();
	sprintf(get_line(pos, getxdr_pos()),
		"Result = %s", val ? "true" : "false");
}

static void
detail_cptime()
{
	showxdr_time("Time = %s");
}

static void
detail_cp_result()
{
	detail_nis_error();
	showxdr_u_long("Ticks (Server) = %lu");
	showxdr_u_long("    (Database) = %lu");
}
