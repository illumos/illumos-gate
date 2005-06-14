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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * rpc_util.h, Useful definitions for the RPC protocol compiler
 */


/* Current version number of rpcgen. */
#define	RPCGEN_MAJOR 1
#define	RPCGEN_MINOR 1

#define	alloc(size)		malloc((unsigned)(size))
#define	ALLOC(object)   (object *) calloc(1, sizeof (object))

#define	s_print	(void) sprintf
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
void storeval();

#define	STOREVAL(list, item)	\
	storeval(list, item)

definition *findval();

#define	FINDVAL(list, item, finder) \
	findval(list, item, finder)

char *fixtype();
char *stringfix();
char *locase();
void pvname_svc();
void pvname();
void ptype();
int isvectordef();
int streq();
void error();
void expected1();
void expected2();
void expected3();
void tabify();
void record_open();
bas_type *find_type();
/*
 * rpc_cout routines
 */
void cprint();
void emit();

/*
 * rpc_hout routines
 */
void print_datadef();
void print_funcdef();
void print_xdr_func_def();

/*
 * rpc_svcout routines
 */
void write_most();
void write_register();
void write_rest();
void write_programs();
void write_svc_aux();
void write_inetd_register();
void write_netid_register();
void write_nettype_register();
/*
 * rpc_clntout routines
 */
void write_stubs();

/*
 * rpc_tblout routines
 */
void write_tables();

#ifdef __cplusplus
}
#endif

#endif	/* !_RPC_UTIL_H */
