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

/*
 * rpc_tblout.c, Dispatch table outputter for the RPC protocol compiler
 */
#include <stdio.h>
#include <string.h>
#include "rpc_parse.h"
#include "rpc_util.h"

extern int nullproc(proc_list *);

static void write_table(definition *);
static void printit(char *, char *);

#define	TABSIZE		8
#define	TABCOUNT	5
#define	TABSTOP		(TABSIZE*TABCOUNT)

static char tabstr[TABCOUNT+1] = "\t\t\t\t\t";

static char tbl_hdr[] = "struct rpcgen_table %s_table[] = {\n";
static char tbl_end[] = "};\n";

static char null_entry_b[] = "\n\t(char *(*)())0,\n"
			" \t(xdrproc_t)xdr_void,\t\t\t0,\n"
			" \t(xdrproc_t)xdr_void,\t\t\t0,\n";

static char null_entry[] = "\n\t(void *(*)())0,\n"
			" \t(xdrproc_t)xdr_void,\t\t\t0,\n"
			" \t(xdrproc_t)xdr_void,\t\t\t0,\n";


static char tbl_nproc[] = "int %s_nproc =\n\tsizeof(%s_table)"
				"/sizeof(%s_table[0]);\n\n";

void
write_tables(void)
{
	list *l;
	definition *def;

	f_print(fout, "\n");
	for (l = defined; l != NULL; l = l->next) {
		def = (definition *)l->val;
		if (def->def_kind == DEF_PROGRAM) {
			write_table(def);
		}
	}
}

static void
write_table(definition *def)
{
	version_list *vp;
	proc_list *proc;
	int current;
	int expected;
	char progvers[100];
	int warning;

	for (vp = def->def.pr.versions; vp != NULL; vp = vp->next) {
		warning = 0;
		(void) snprintf(progvers, sizeof (progvers), "%s_%s",
		    locase(def->def_name), vp->vers_num);
		/* print the table header */
		f_print(fout, tbl_hdr, progvers);

		if (nullproc(vp->procs)) {
			expected = 0;
		} else {
			expected = 1;
			if (tirpcflag)
				f_print(fout, null_entry);
			else
				f_print(fout, null_entry_b);
		}
		for (proc = vp->procs; proc != NULL; proc = proc->next) {
			current = atoi(proc->proc_num);
			if (current != expected++) {
				f_print(fout,
			"\n/*\n * WARNING: table out of order\n */\n");
				if (warning == 0) {
					f_print(stderr,
				    "WARNING %s table is out of order\n",
					    progvers);
					warning = 1;
					nonfatalerrors = 1;
				}
				expected = current + 1;
			}
			if (tirpcflag)
				f_print(fout,
				    "\n\t(void *(*)())RPCGEN_ACTION(");
			else
				f_print(fout,
				    "\n\t(char *(*)())RPCGEN_ACTION(");

			/* routine to invoke */
			if (Cflag && !newstyle)
				pvname_svc(proc->proc_name, vp->vers_num);
			else {
				if (newstyle) /* calls internal func */
					f_print(fout, "_");
				pvname(proc->proc_name, vp->vers_num);
			}
			f_print(fout, "),\n");

			/* argument info */
			if (proc->arg_num > 1)
				printit(NULL, proc->args.argname);
			else
			/* do we have to do something special for newstyle */
				printit(proc->args.decls->decl.prefix,
				    proc->args.decls->decl.type);
			/* result info */
			printit(proc->res_prefix, proc->res_type);
		}

		/* print the table trailer */
		f_print(fout, tbl_end);
		f_print(fout, tbl_nproc, progvers, progvers, progvers);
	}
}

static void
printit(char *prefix, char *type)
{
	int len;
	int tabs;


	if (streq(type, "oneway"))
		len = fprintf(fout, "\t(xdrproc_t)xdr_void,");
	else
		len = fprintf(fout, "\t(xdrproc_t)xdr_%s,", stringfix(type));
	/* account for leading tab expansion */
	len += TABSIZE - 1;
	if (len >= TABSTOP) {
		f_print(fout, "\n");
		len = 0;
	}
	/* round up to tabs required */
	tabs = (TABSTOP - len + TABSIZE - 1)/TABSIZE;
	f_print(fout, "%s", &tabstr[TABCOUNT-tabs]);

	if (streq(type, "void") || streq(type, "oneway")) {
		f_print(fout, "0");
	} else {
		f_print(fout, "sizeof ( ");
		/* XXX: should "follow" be 1 ??? */
		ptype(prefix, type, 0);
		f_print(fout, ")");
	}
	f_print(fout, ",\n");
}
