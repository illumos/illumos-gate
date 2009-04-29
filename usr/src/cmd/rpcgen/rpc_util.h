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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/* Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T */
/* All Rights Reserved */
/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

#ifndef _RPC_UTIL_H
#define	_RPC_UTIL_H

#include <sys/types.h>
#include <stdlib.h>
#include "rpc_scan.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * rpc_util.h, Useful definitions for the RPC protocol compiler
 */


/* Current version number of rpcgen. */
#define	RPCGEN_MAJOR 1
#define	RPCGEN_MINOR 1

#define	f_print (void) fprintf

struct list {
	definition *val;
	struct list *next;
};
typedef struct list list;

struct xdrfunc {
	char *name;
	int pointerp;
	struct xdrfunc *next;
};
typedef struct xdrfunc xdrfunc;

struct commandline {
	int cflag;		/* xdr C routines */
	int hflag;		/* header file */
	int lflag;		/* client side stubs */
	int mflag;		/* server side stubs */
	int nflag;		/* netid flag */
	int sflag;		/* server stubs for the given transport */
	int tflag;		/* dispatch Table file */
	int Ssflag;		/* produce server sample code */
	int Scflag;		/* produce client sample code */
	int makefileflag;	/* Generate a template Makefile */
	char *infile;		/* input module name */
	char *outfile;		/* output module name */
};

#define	PUT 1
#define	GET 2

/*
 * Global variables
 */
#define	MAXLINESIZE 1024
extern char curline[MAXLINESIZE];
extern char *where;
extern int linenum;

extern char *infilename;
extern FILE *fout;
extern FILE *fin;

extern list *defined;

extern bas_type *typ_list_h;
extern bas_type *typ_list_t;
extern xdrfunc *xdrfunc_head, *xdrfunc_tail;

/*
 * All the option flags
 */
extern int inetdflag;
extern int pmflag;
extern int tblflag;
extern int logflag;
extern int newstyle;
extern int Cflag;	/* ANSI-C/C++ flag */
extern int CCflag;	/* C++ flag */
extern int tirpcflag;	/* flag for generating tirpc code */
extern int inlinelen;	/* if this is 0, then do not generate inline code */
extern int mtflag;
extern int mtauto;
extern int rflag;

/*
 * Other flags related with inetd jumpstart.
 */
extern int indefinitewait;
extern int exitnow;
extern int timerflag;

extern int nonfatalerrors;

extern pid_t childpid;

/*
 * rpc_util routines
 */
extern void storeval(list **, definition *);

#define	STOREVAL(list, item)	\
	storeval(list, item)

extern definition *findval(list *, char *, int (*)());

#define	FINDVAL(list, item, finder) \
	findval(list, item, finder)

extern char *fixtype(char *);
extern char *stringfix(char *);
extern char *locase(char *);
extern void pvname_svc(char *, char *);
extern void pvname(char *, char *);
extern void ptype(char *, char *, int);
extern int isvectordef(char *, relation);
extern int streq(char *, char *);
extern void error(char *);
extern void expected1(tok_kind);
extern void expected2(tok_kind, tok_kind);
extern void expected3(tok_kind, tok_kind, tok_kind);
extern void tabify(FILE *, int);
extern void record_open(char *);
extern bas_type *find_type(char *);

/*
 * rpc_cout routines
 */
extern void emit(definition *);

/*
 * rpc_hout routines
 */
extern void print_datadef(definition *);
extern void print_funcdef(definition *);
extern void print_xdr_func_def(char *, int, int);

/*
 * rpc_svcout routines
 */
extern void write_most(char *, int, int);
extern void write_rest(void);
extern void write_inetd_register(char *);
extern void write_netid_register(char *);
extern void write_nettype_register(char *);

/*
 * rpc_clntout routines
 */
extern void write_stubs(void);

/*
 * rpc_tblout routines
 */
extern void write_tables(void);

#ifdef __cplusplus
}
#endif

#endif	/* !_RPC_UTIL_H */
