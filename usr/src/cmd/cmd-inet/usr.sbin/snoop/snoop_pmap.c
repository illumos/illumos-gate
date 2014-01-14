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
/*
 * Copyright 2014 Nexenta Systems, Inc.  All rights reserved.
 */

#include <sys/types.h>
#include <sys/errno.h>
#include <setjmp.h>
#include <sys/tiuser.h>
#include <string.h>

#include <rpc/types.h>
#include <rpc/xdr.h>
#include <rpc/auth.h>
#include <rpc/clnt.h>
#include <rpc/rpc_msg.h>
#include <rpc/pmap_prot.h>
#include "snoop.h"

/*
 * Number of bytes to display from a string (address, netid, etc.).
 */
#define	MAXSTRINGLEN	64

extern char *dlc_header;
extern jmp_buf xdr_err;

static void interpret_pmap_2(int, int, int, int, int, char *, int);
static void interpret_pmap_4(int, int, int, int, int, char *, int);
static void stash_callit(ulong_t, int, int, int, int);

void
interpret_pmap(flags, type, xid, vers, proc, data, len)
	int flags, type, xid, vers, proc;
	char *data;
	int len;
{
	switch (vers) {
	case 2:	interpret_pmap_2(flags, type, xid, vers, proc, data, len);
		break;

	/* Version 3 is a subset of version 4 */
	case 3:
	case 4:	interpret_pmap_4(flags, type, xid, vers, proc, data, len);
		break;
	}
}

void show_pmap();
char *sum_pmaplist();
void show_pmaplist();

static char *procnames_short_2[] = {
	"Null",		/* 0 */
	"SET",		/* 1 */
	"UNSET",	/* 2 */
	"GETPORT",	/* 3 */
	"DUMP",		/* 4 */
	"CALLIT",	/* 5 */
};

static char *procnames_long_2[] = {
	"Null procedure",	/* 0 */
	"Set port",		/* 1 */
	"Unset port",		/* 2 */
	"Get port number",	/* 3 */
	"Dump the mappings",	/* 4 */
	"Indirect call",	/* 5 */
};

#define	MAXPROC_2	5

void
interpret_pmap_2(flags, type, xid, vers, proc, data, len)
	int flags, type, xid, vers, proc;
	char *data;
	int len;
{
	char *line;
	unsigned port, proto;
	unsigned iprog, ivers, iproc, ilen;
	extern int pi_frame;
	struct cache_struct *x, *find_callit();
	int trailer_done = 0;

	if (proc < 0 || proc > MAXPROC_2)
		return;

	if (proc == PMAPPROC_CALLIT) {
		if (type == CALL) {
			iprog = getxdr_u_long();
			ivers = getxdr_u_long();
			iproc = getxdr_u_long();
			stash_callit(xid, pi_frame, iprog, ivers, iproc);
		} else {
			x = find_callit(xid);
		}
	}

	if (flags & F_SUM) {
		if (setjmp(xdr_err)) {
			return;
		}

		line = get_sum_line();

		if (type == CALL) {
			(void) sprintf(line, "PORTMAP C %s",
			    procnames_short_2[proc]);
			line += strlen(line);
			switch (proc) {
			case PMAPPROC_GETPORT:
				iprog = getxdr_u_long();
				ivers = getxdr_u_long();
				proto = getxdr_u_long();
				(void) sprintf(line,
				    " prog=%d (%s) vers=%d proto=%s",
				    iprog, nameof_prog(iprog),
				    ivers,
				    getproto(proto));
				break;
			case PMAPPROC_CALLIT:
				(void) sprintf(line,
				    " prog=%s vers=%d proc=%d",
				    nameof_prog(iprog),
				    ivers, iproc);
				if (flags & F_ALLSUM) {
					(void) getxdr_u_long(); /* length */
					data += 16; /* prog+ver+proc+len */
					len -= 16;
					protoprint(flags, type, xid,
					    iprog, ivers, iproc,
					    data, len);
				}
				break;
			default:
				break;
			}
			check_retransmit(line, xid);
		} else {
			(void) sprintf(line, "PORTMAP R %s ",
			    procnames_short_2[proc]);
			line += strlen(line);
			switch (proc) {
			case PMAPPROC_GETPORT:
				port = getxdr_u_long();
				(void) sprintf(line, "port=%d", port);
				break;
			case PMAPPROC_DUMP:
				(void) sprintf(line, "%s", sum_pmaplist());
				break;
			case PMAPPROC_CALLIT:
				port = getxdr_u_long();
				ilen = getxdr_u_long();
				(void) sprintf(line, "port=%d len=%d",
				    port, ilen);
				if (flags & F_ALLSUM && x != NULL) {
					data += 8; /* port+len */
					len -= 8;
					protoprint(flags, type, xid,
					    x->xid_prog,
					    x->xid_vers,
					    x->xid_proc,
					    data, len);
				}
				break;
			default:
				break;
			}
		}
	}

	if (flags & F_DTAIL) {
		show_header("PMAP:  ", "Portmapper", len);
		show_space();
		if (setjmp(xdr_err)) {
			return;
		}
		(void) sprintf(get_line(0, 0),
			"Proc = %d (%s)",
			proc, procnames_long_2[proc]);
		if (type == CALL) {
			switch (proc) {
			case PMAPPROC_NULL:
			case PMAPPROC_SET:
			case PMAPPROC_UNSET:
				break;
			case PMAPPROC_GETPORT:
				iprog = getxdr_u_long();
				(void) sprintf(get_line(0, 0),
				    "Program = %d (%s)",
				    iprog, nameof_prog(iprog));
				(void) showxdr_u_long("Version = %d");
				proto = getxdr_u_long();
				(void) sprintf(get_line(0, 0),
				    "Protocol = %d (%s)",
				    proto, getproto(proto));
				break;
			case PMAPPROC_DUMP:
				break;
			case PMAPPROC_CALLIT:
				(void) sprintf(get_line(0, 0),
				    "Program = %d (%s)",
				    iprog, nameof_prog(iprog));
				(void) sprintf(get_line(0, 0),
				    "Version = %d", ivers);
				(void) sprintf(get_line(0, 0),
				    "Proc    = %d", iproc);
				(void) showxdr_u_long("Callit data = %d bytes");
				show_trailer();
				trailer_done = 1;
				data += 16; /* prog+ver+proc+len */
				len -= 16;
				protoprint(flags, type, xid,
				    iprog, ivers, iproc,
				    data, len);
				break;
			}
		} else {
			switch (proc) {
			case PMAPPROC_NULL:
			case PMAPPROC_SET:
			case PMAPPROC_UNSET:
				break;
			case PMAPPROC_GETPORT:
				(void) showxdr_u_long("Port = %d");
				break;
			case PMAPPROC_DUMP:
				show_pmaplist();
				break;
			case PMAPPROC_CALLIT:
				(void) showxdr_u_long("Port = %d");
				(void) showxdr_u_long("Length = %d bytes");
				show_trailer();
				trailer_done = 1;
				if (x != NULL) {
					protoprint(flags, type, xid,
					    x->xid_prog,
					    x->xid_vers,
					    x->xid_proc,
					    data, len);
				}
				break;
			}
		}
		if (!trailer_done)
			show_trailer();
	}
}

char *
sum_pmaplist()
{
	int maps = 0;
	static char buff[16];

	if (setjmp(xdr_err)) {
		(void) sprintf(buff, "%d+ map(s) found", maps);
		return (buff);
	}

	while (getxdr_u_long()) {
		(void) getxdr_u_long();	/* program */
		(void) getxdr_u_long();	/* version */
		(void) getxdr_u_long();	/* protocol */
		(void) getxdr_u_long();	/* port */
		maps++;
	}

	(void) sprintf(buff, "%d map(s) found", maps);
	return (buff);
}

void
show_pmaplist()
{
	unsigned prog, vers, proto, port;
	int maps = 0;

	if (setjmp(xdr_err)) {
		(void) sprintf(get_line(0, 0),
		    " %d+ maps. (Frame is incomplete)",
		    maps);
		return;
	}

	(void) sprintf(get_line(0, 0), " Program Version Protocol   Port");

	while (getxdr_u_long()) {
		prog  = getxdr_u_long();
		vers  = getxdr_u_long();
		proto = getxdr_u_long();
		port  = getxdr_u_long();
		(void) sprintf(get_line(0, 0),
		    "%8d%8d%9d%7d  %s",
		    prog, vers, proto, port, nameof_prog(prog));
		maps++;
	}

	(void) sprintf(get_line(0, 0), " %d maps", maps);
}

/*
 * ******************************************
 */
char *sum_rpcblist();
void show_rpcblist();
char *sum_rpcb_entry_list();
void show_rpcb_entry_list();

static char *procnames_short_4[] = {
	/*
	 * version 3 and 4 procs
	 */
	"Null",		/* 0 */
	"SET",		/* 1 */
	"UNSET",	/* 2 */
	"GETADDR",	/* 3 */
	"DUMP",		/* 4 */
	"BCAST",	/* 5 */
	"GETTIME",	/* 6 */
	"UADDR2TADDR",	/* 7 */
	"TADDR2UADDR",	/* 8 */
	/*
	 * version 4 procs only
	 */
	"GETVERSADDR",	/* 9 */
	"INDIRECT",	/* 10 */
	"GETADDRLIST",	/* 11 */
	"GETSTAT",	/* 12 */
};

static char *procnames_long_4[] = {
	/*
	 * version 3 and 4 procs
	 */
	"Null procedure",			/* 0 */
	"Set address",				/* 1 */
	"Unset address",			/* 2 */
	"Get address",				/* 3 */
	"Dump the mappings",			/* 4 */
	"Broadcast call (no error)",		/* 5 */
	"Get the time",				/* 6 */
	"Universal to transport address",	/* 7 */
	"Transport to universal address",	/* 8 */
	/*
	 * version 4 procs only
	 */
	"Get address of specific version",	/* 9 */
	"Indirect call (return error)",		/* 10 */
	"Return addresses of prog/vers",	/* 11 */
	"Get statistics",			/* 12 */
};

#define	MAXPROC_3		8
#define	MAXPROC_4		12
#define	RPCBPROC_NULL		0

void
interpret_pmap_4(flags, type, xid, vers, proc, data, len)
	int flags, type, xid, vers, proc;
	char *data;
	int len;
{
	char *line;
	unsigned prog, ver;
	char buff1[MAXSTRINGLEN + 1];
	int iprog, ivers, iproc, ilen;
	extern int pi_frame;
	struct cache_struct *x, *find_callit();
	int trailer_done = 0;

	if (proc < 0 || proc > MAXPROC_4 || (vers == 3 && proc > MAXPROC_3))
		return;

	if (proc == RPCBPROC_BCAST || proc == RPCBPROC_INDIRECT) {
		if (type == CALL) {
			iprog = getxdr_u_long();
			ivers = getxdr_u_long();
			iproc = getxdr_u_long();
			stash_callit(xid, pi_frame,
				iprog, ivers, iproc);
		} else {
			x = find_callit(xid);
		}
	}

	if (flags & F_SUM) {
		if (setjmp(xdr_err)) {
			return;
		}

		line = get_sum_line();

		if (type == CALL) {
			(void) sprintf(line,
				"RPCBIND C %s",
				procnames_short_4[proc]);
			line += strlen(line);
			switch (proc) {
			case RPCBPROC_SET:
			case RPCBPROC_UNSET:
			case RPCBPROC_GETADDR:
			case RPCBPROC_GETVERSADDR:
			case RPCBPROC_GETADDRLIST:
				prog = getxdr_u_long();
				ver  = getxdr_u_long();
				(void) sprintf(line,
					" prog=%d (%s) vers=%d",
					prog, nameof_prog(prog),
					ver);
				break;
			case RPCBPROC_BCAST:
			case RPCBPROC_INDIRECT:
				(void) sprintf(line,
					" prog=%s vers=%d proc=%d",
					nameof_prog(iprog),
					ivers, iproc);
				if (flags & F_ALLSUM) {
					(void) getxdr_u_long(); /* length */
					data += 16; /* prog+ver+proc+len */
					len -= 16;
					protoprint(flags, type, xid,
						iprog, ivers, iproc,
						data, len);
				}
				break;
			default:
				break;
			}

			check_retransmit(line, xid);
		} else {
			int pos;

			(void) sprintf(line, "RPCBIND R %s ",
				procnames_short_4[proc]);
			line += strlen(line);
			switch (proc) {
			case RPCBPROC_GETADDR:
			case RPCBPROC_TADDR2UADDR:
			case RPCBPROC_GETVERSADDR:
				(void) getxdr_string(buff1, MAXSTRINGLEN);
				(void) sprintf(line,
					" Uaddr=%s",
					buff1);
				break;
			case RPCBPROC_BCAST:
			case RPCBPROC_INDIRECT:
				pos = getxdr_pos();
				(void) getxdr_string(buff1, MAXSTRINGLEN);
				ilen = getxdr_u_long();
				(void) sprintf(line, "Uaddr=%s len=%d",
					buff1, ilen);
				if (flags & F_ALLSUM && x != NULL) {
					pos = getxdr_pos() - pos;
					data += pos; /* uaddr+len */
					len -= pos;
					protoprint(flags, type, xid,
						x->xid_prog,
						x->xid_vers,
						x->xid_proc,
						data, len);
				}
				break;
			case RPCBPROC_DUMP:
				(void) sprintf(line, "%s",
					sum_rpcblist());
				break;
			case RPCBPROC_GETTIME:
				{
					time_t sec = getxdr_long();
					struct tm *tmp = gmtime(&sec);
					(void) strftime(line, MAXLINE,
					    "%d-%h-%y %T GMT", tmp);
				}
				break;
			case RPCBPROC_GETADDRLIST:
				(void) sprintf(line, "%s",
					sum_rpcb_entry_list());
				break;
			default:
				break;
			}
		}
	}

	if (flags & F_DTAIL) {
		show_header("RPCB:  ", "RPC Bind", len);
		show_space();
		if (setjmp(xdr_err)) {
			return;
		}
		(void) sprintf(get_line(0, 0),
			"Proc = %d (%s)",
			proc, procnames_long_4[proc]);
		if (type == CALL) {
			switch (proc) {
			case RPCBPROC_NULL:
				break;
			case RPCBPROC_SET:
			case RPCBPROC_UNSET:
			case RPCBPROC_GETADDR:
			case RPCBPROC_GETVERSADDR:
			case RPCBPROC_GETADDRLIST:
				(void) showxdr_u_long("Program = %d");
				(void) showxdr_u_long("Version = %d");
				(void) showxdr_string(64, "Netid   = %s");
				break;
			case RPCBPROC_DUMP:
				break;
			case RPCBPROC_BCAST:
			case RPCBPROC_INDIRECT:
				(void) sprintf(get_line(0, 0),
					"Program = %d (%s)",
					iprog, nameof_prog(iprog));
				(void) sprintf(get_line(0, 0),
					"Version = %d", ivers);
				(void) sprintf(get_line(0, 0),
					"Proc    = %d", iproc);
				(void) showxdr_u_long(
					"Callit data = %d bytes");
				show_trailer();
				trailer_done = 1;
				data += 16; /* prog+ver+proc+len */
				len -= 16;
				protoprint(flags, type, xid,
					iprog, ivers, iproc,
					data, len);
				break;
			case RPCBPROC_GETTIME:
				break;
			case RPCBPROC_UADDR2TADDR:
			case RPCBPROC_TADDR2UADDR:
				break;
			}
		} else {
			switch (proc) {
			case RPCBPROC_NULL:
			case RPCBPROC_SET:
			case RPCBPROC_UNSET:
				break;
			case RPCBPROC_GETADDR:
			case RPCBPROC_TADDR2UADDR:
			case RPCBPROC_GETVERSADDR:
				(void) showxdr_string(64, "Uaddr = %s");
				break;
			case RPCBPROC_DUMP:
				show_rpcblist();
				break;
			case RPCBPROC_BCAST:
			case RPCBPROC_INDIRECT:
				(void) showxdr_string(64, "Uaddr = %s");
				(void) showxdr_u_long("Length = %d bytes");
				show_trailer();
				trailer_done = 1;
				if (x != NULL) {
					protoprint(flags, type, xid,
						x->xid_prog,
						x->xid_vers,
						x->xid_proc,
						data, len);
				}
				break;
			case RPCBPROC_GETTIME:
				{
					int pos = getxdr_pos();
					time_t sec = getxdr_long();
					struct tm *tmp = gmtime(&sec);
					(void) strftime(get_line(pos,
					    getxdr_pos()), MAXLINE,
					    "Time = %d-%h-%y %T GMT", tmp);
				}
				break;
			case RPCBPROC_UADDR2TADDR:
				break;
			case RPCBPROC_GETADDRLIST:
				show_rpcb_entry_list();
				break;
			}
		}
		if (!trailer_done)
			show_trailer();
	}
}

char *
sum_rpcblist()
{
	int maps = 0;
	static char buff[MAXSTRINGLEN + 1];

	if (setjmp(xdr_err)) {
		(void) sprintf(buff, "%d+ map(s) found", maps);
		return (buff);
	}

	while (getxdr_u_long()) {
		(void) getxdr_u_long();		/* program */
		(void) getxdr_u_long();		/* version */
		(void) getxdr_string(buff, MAXSTRINGLEN); /* netid */
		(void) getxdr_string(buff, MAXSTRINGLEN); /* uaddr */
		(void) getxdr_string(buff, MAXSTRINGLEN); /* owner */
		maps++;
	}

	(void) sprintf(buff, "%d map(s) found", maps);
	return (buff);
}

void
show_rpcblist()
{
	unsigned prog, vers;
	char netid[MAXSTRINGLEN + 1], uaddr[MAXSTRINGLEN + 1];
	char owner[MAXSTRINGLEN + 1];
	int maps = 0;

	if (setjmp(xdr_err)) {
		(void) sprintf(get_line(0, 0),
		    " %d+ maps. (Frame is incomplete)",
		    maps);
		return;
	}

	show_space();
	(void) sprintf(get_line(0, 0),
	    " Program Vers Netid        Uaddr              Owner");

	while (getxdr_u_long()) {
		prog  = getxdr_u_long();
		vers  = getxdr_u_long();
		(void) getxdr_string(netid, MAXSTRINGLEN);
		(void) getxdr_string(uaddr, MAXSTRINGLEN);
		(void) getxdr_string(owner, MAXSTRINGLEN);
		(void) sprintf(get_line(0, 0),
		    "%8d%5d %-12s %-18s %-10s (%s)",
		    prog, vers,
		    netid, uaddr, owner,
		    nameof_prog(prog));
		maps++;
	}

	(void) sprintf(get_line(0, 0), " (%d maps)", maps);
}

char *
sum_rpcb_entry_list()
{
	int maps = 0;
	static char buff[MAXSTRINGLEN + 1];

	if (setjmp(xdr_err)) {
		(void) sprintf(buff, "%d+ map(s) found", maps);
		return (buff);
	}

	while (getxdr_u_long()) {
		(void) getxdr_string(buff, MAXSTRINGLEN); /* maddr	*/
		(void) getxdr_string(buff, MAXSTRINGLEN); /* nc_netid	*/
		(void) getxdr_u_long();			  /* nc_semantics */
		(void) getxdr_string(buff, MAXSTRINGLEN); /* nc_protofmly */
		(void) getxdr_string(buff, MAXSTRINGLEN); /* nc_proto	*/
		maps++;
	}

	(void) sprintf(buff, "%d map(s) found", maps);
	return (buff);
}

char *semantics_strs[] = {"", "CLTS", "COTS", "COTS-ORD", "RAW"};

void
show_rpcb_entry_list()
{
	char maddr[MAXSTRINGLEN + 1], netid[MAXSTRINGLEN + 1];
	char protofmly[MAXSTRINGLEN + 1], proto[MAXSTRINGLEN + 1];
	unsigned sem;
	int maps = 0;

	if (setjmp(xdr_err)) {
		(void) sprintf(get_line(0, 0),
		    " %d+ maps. (Frame is incomplete)",
		    maps);
		return;
	}

	show_space();
	(void) sprintf(get_line(0, 0),
	    " Maddr      Netid        Semantics Protofmly Proto");

	while (getxdr_u_long()) {
		(void) getxdr_string(maddr, MAXSTRINGLEN);
		(void) getxdr_string(netid, MAXSTRINGLEN);
		sem  = getxdr_u_long();
		(void) getxdr_string(protofmly, MAXSTRINGLEN);
		(void) getxdr_string(proto, MAXSTRINGLEN);
		(void) sprintf(get_line(0, 0),
		    "%-12s %-12s %-8s %-8s %-8s",
		    maddr, netid,
		    semantics_strs[sem],
		    protofmly, proto);
		maps++;
	}

	(void) sprintf(get_line(0, 0), " (%d maps)", maps);
}

#define	CXID_CACHE_SIZE	16
struct cache_struct cxid_cache[CXID_CACHE_SIZE];
struct cache_struct *cxcpfirst	= &cxid_cache[0];
struct cache_struct *cxcp	= &cxid_cache[0];
struct cache_struct *cxcplast   = &cxid_cache[CXID_CACHE_SIZE - 1];

struct cache_struct *
find_callit(xid)
	ulong_t xid;
{
	struct cache_struct *x;

	for (x = cxcp; x >= cxcpfirst; x--)
		if (x->xid_num == xid)
			return (x);
	for (x = cxcplast; x > cxcp; x--)
		if (x->xid_num == xid)
			return (x);
	return (NULL);
}

static void
stash_callit(xid, frame, prog, vers, proc)
	ulong_t xid;
	int frame, prog, vers, proc;
{
	struct cache_struct *x;

	x = find_callit(xid);
	if (x == NULL) {
		x = cxcp++;
		if (cxcp > cxcplast)
			cxcp = cxcpfirst;
		x->xid_num = xid;
		x->xid_frame = frame;
	}
	x->xid_prog = prog;
	x->xid_vers = vers;
	x->xid_proc = proc;
}
