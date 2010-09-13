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
 * rpc_clntout.c, Client-stub outputter for the RPC protocol compiler
 */
#include <stdio.h>
#include <string.h>
#include <rpc/types.h>
#include "rpc_parse.h"
#include "rpc_util.h"

extern void pdeclaration(char *, declaration *, int, char *);
extern void printarglist(proc_list *, char *, char *, char *);

static void write_program(definition *);
static void printbody(proc_list *);

static char RESULT[] = "clnt_res";

#define	DEFAULT_TIMEOUT 25	/* in seconds */

void
write_stubs(void)
{
	list *l;
	definition *def;

	f_print(fout,
	    "\n/* Default timeout can be changed using clnt_control() */\n");
	f_print(fout, "static struct timeval TIMEOUT = { %d, 0 };\n",
	    DEFAULT_TIMEOUT);
	for (l = defined; l != NULL; l = l->next) {
		def = (definition *) l->val;
		if (def->def_kind == DEF_PROGRAM) {
			write_program(def);
		}
	}
}

static void
write_program(definition *def)
{
	version_list *vp;
	proc_list *proc;

	for (vp = def->def.pr.versions; vp != NULL; vp = vp->next) {
		for (proc = vp->procs; proc != NULL; proc = proc->next) {
			f_print(fout, "\n");
			if (mtflag == 0) {
				ptype(proc->res_prefix, proc->res_type, 1);
				f_print(fout, "*\n");
				pvname(proc->proc_name, vp->vers_num);
				printarglist(proc, RESULT, "clnt", "CLIENT *");
			} else {
				f_print(fout, "enum clnt_stat \n");
				pvname(proc->proc_name, vp->vers_num);
				printarglist(proc, RESULT,  "clnt", "CLIENT *");

			}
			f_print(fout, "{\n");
			printbody(proc);

			f_print(fout, "}\n");
		}
	}
}

/*
 * Writes out declarations of procedure's argument list.
 * In either ANSI C style, in one of old rpcgen style (pass by reference),
 * or new rpcgen style (multiple arguments, pass by value);
 */

/* sample addargname = "clnt"; sample addargtype = "CLIENT * " */

void
printarglist(proc_list *proc, char *result, char *addargname, char *addargtype)
{
	bool_t oneway = streq(proc->res_type, "oneway");
	decl_list *l;

	if (!newstyle) {
		/* old style: always pass argument by reference */
		if (Cflag) {	/* C++ style heading */
			f_print(fout, "(");
			ptype(proc->args.decls->decl.prefix,
			    proc->args.decls->decl.type, 1);

			if (mtflag) {	/* Generate result field */
				f_print(fout, "*argp, ");
				if (!oneway) {
					ptype(proc->res_prefix,
					    proc->res_type, 1);
					f_print(fout, "*%s, ", result);
				}
				f_print(fout, "%s%s)\n",
				    addargtype, addargname);
			} else
				f_print(fout, "*argp, %s%s)\n",
				    addargtype, addargname);
		} else {
			if (!mtflag)
				f_print(fout, "(argp, %s)\n", addargname);
			else {
				f_print(fout, "(argp, ");
				if (!oneway) {
					f_print(fout, "%s, ",
					    result);
				}
				f_print(fout, "%s)\n",
				    addargname);
			}
			f_print(fout, "\t");
			ptype(proc->args.decls->decl.prefix,
			    proc->args.decls->decl.type, 1);
			f_print(fout, "*argp;\n");
			if (mtflag && !oneway) {
				f_print(fout, "\t");
				ptype(proc->res_prefix, proc->res_type, 1);
				f_print(fout, "*%s;\n", result);
			}
		}
	} else if (streq(proc->args.decls->decl.type, "void")) {
		/* newstyle, 0 argument */
		if (mtflag) {
			f_print(fout, "(");

			if (Cflag) {
				if (!oneway) {
					ptype(proc->res_prefix,
					    proc->res_type, 1);
					f_print(fout, "*%s, ", result);
				}
				f_print(fout, "%s%s)\n",
				    addargtype, addargname);
			} else
				f_print(fout, "(%s)\n", addargname);

		} else
		if (Cflag)
			f_print(fout, "(%s%s)\n", addargtype, addargname);
		else
			f_print(fout, "(%s)\n", addargname);
	} else {
		/* new style, 1 or multiple arguments */
		if (!Cflag) {
			f_print(fout, "(");
			for (l = proc->args.decls;  l != NULL; l = l->next)
				f_print(fout, "%s, ", l->decl.name);
			if (mtflag && !oneway)
				f_print(fout, "%s, ", result);

			f_print(fout, "%s)\n", addargname);
			for (l = proc->args.decls; l != NULL; l = l->next) {
				pdeclaration(proc->args.argname,
				    &l->decl, 1, ";\n");
			}
			if (mtflag && !oneway) {
				f_print(fout, "\t");
				ptype(proc->res_prefix, proc->res_type, 1);
				f_print(fout, "*%s;\n", result);
			}

		} else {	/* C++ style header */
			f_print(fout, "(");
			for (l = proc->args.decls; l != NULL; l = l->next) {
				pdeclaration(proc->args.argname, &l->decl, 0,
				    ", ");
			}
			if (mtflag && !oneway) {
				ptype(proc->res_prefix, proc->res_type, 1);
				f_print(fout, "*%s, ", result);

			}
			f_print(fout, "%s%s)\n", addargtype, addargname);
		}
	}

	if (!Cflag)
		f_print(fout, "\t%s%s;\n", addargtype, addargname);
}



static char *
ampr(char *type)
{
	if (isvectordef(type, REL_ALIAS)) {
		return ("");
	} else {
		return ("&");
	}
}

static void
printbody(proc_list *proc)
{
	decl_list *l;
	bool_t args2 = (proc->arg_num > 1);
	bool_t oneway = streq(proc->res_type, "oneway");

	/*
	 * For new style with multiple arguments, need a structure in which
	 *  to stuff the arguments.
	 */
	if (newstyle && args2) {
		f_print(fout, "\t%s", proc->args.argname);
		f_print(fout, " arg;\n");
	}
	if (!oneway) {
		if (!mtflag) {
			f_print(fout, "\tstatic ");
			if (streq(proc->res_type, "void")) {
				f_print(fout, "char ");
			} else {
				ptype(proc->res_prefix, proc->res_type, 0);
			}
			f_print(fout, "%s;\n", RESULT);
			f_print(fout, "\n");
			f_print(fout,
			    "\t(void) memset(%s%s, 0, sizeof (%s));\n",
			    ampr(proc->res_type), RESULT, RESULT);

		}
		if (newstyle && !args2 &&
		    (streq(proc->args.decls->decl.type, "void"))) {
			/* newstyle, 0 arguments */

			if (mtflag)
				f_print(fout, "\t return ");
			else
				f_print(fout, "\t if ");

			f_print(fout,
			    "(clnt_call(clnt, %s,\n\t\t(xdrproc_t)xdr_void, ",
			    proc->proc_name);
			f_print(fout,
			    "NULL,\n\t\t(xdrproc_t)xdr_%s, "
			    "(caddr_t)%s%s,",
			    stringfix(proc->res_type),
			    (mtflag)?"":ampr(proc->res_type),
			    RESULT);

			if (mtflag)
				f_print(fout, "\n\t\tTIMEOUT));\n");
			else
				f_print(fout,
				    "\n\t\tTIMEOUT) != RPC_SUCCESS) {\n");

		} else if (newstyle && args2) {
			/*
			 * Newstyle, multiple arguments
			 * stuff arguments into structure
			 */
			for (l = proc->args.decls;  l != NULL; l = l->next) {
				f_print(fout, "\targ.%s = %s;\n",
				    l->decl.name, l->decl.name);
			}
			if (mtflag)
				f_print(fout, "\treturn ");
			else
				f_print(fout, "\tif ");
			f_print(fout,
			    "(clnt_call(clnt, %s,\n\t\t(xdrproc_t)xdr_%s",
			    proc->proc_name, proc->args.argname);
			f_print(fout,
			    ", (caddr_t)&arg,\n\t\t(xdrproc_t)xdr_%s, "
			    "(caddr_t)%s%s,",
			    stringfix(proc->res_type),
			    (mtflag)?"":ampr(proc->res_type),
			    RESULT);
			if (mtflag)
				f_print(fout, "\n\t\tTIMEOUT));\n");
			else
				f_print(fout,
				    "\n\t\tTIMEOUT) != RPC_SUCCESS) {\n");
		} else {		/* single argument, new or old style */
			if (!mtflag)
				f_print(fout,
				    "\tif (clnt_call(clnt, "
				    "%s,\n\t\t(xdrproc_t)xdr_%s, "
				    "(caddr_t)%s%s,\n\t\t(xdrproc_t)xdr_%s, "
				    "(caddr_t)%s%s,\n\t\tTIMEOUT) != "
				    "RPC_SUCCESS) {\n",
				    proc->proc_name,
				    stringfix(proc->args.decls->decl.type),
				    (newstyle ? "&" : ""),
				    (newstyle ?
				    proc->args.decls->decl.name :
				    "argp"),
				    stringfix(proc->res_type),
				    ampr(proc->res_type),
				    RESULT);
			else
				f_print(fout,
				    "\treturn (clnt_call(clnt, "
				    "%s,\n\t\t(xdrproc_t)xdr_%s, "
				    "(caddr_t)%s%s,\n\t\t(xdrproc_t)xdr_%s, "
				    "(caddr_t)%s%s,\n\t\tTIMEOUT));\n",
				    proc->proc_name,
				    stringfix(proc->args.decls->decl.type),
				    (newstyle ? "&" : ""),
				    (newstyle ?
				    proc->args.decls->decl.name :
				    "argp"),
				    stringfix(proc->res_type), "",
				    RESULT);
		}
		if (!mtflag) {
			f_print(fout, "\t\treturn (NULL);\n");
			f_print(fout, "\t}\n");

			if (streq(proc->res_type, "void")) {
				f_print(fout, "\treturn ((void *)%s%s);\n",
				    ampr(proc->res_type), RESULT);
			} else {
				f_print(fout, "\treturn (%s%s);\n",
				    ampr(proc->res_type), RESULT);
			}
		}
	} else {
		/* oneway call */
		if (!mtflag) {
			f_print(fout, "\tstatic enum clnt_stat ");
			f_print(fout, "%s;\n", RESULT);
			f_print(fout, "\n");
			f_print(fout,
			    "\t(void) memset(&%s, 0, sizeof (%s));\n",
			    RESULT, RESULT);

		}
		if (newstyle && !args2 &&
		    (streq(proc->args.decls->decl.type, "void"))) {
			/* newstyle, 0 arguments */

			if (mtflag)
				f_print(fout, "\t return (");
			else
				f_print(fout, "\t if ((%s = ", RESULT);

			f_print(fout,
			    "clnt_send(clnt, %s,\n\t\t(xdrproc_t)xdr_void, ",
			    proc->proc_name);
			f_print(fout, "NULL)");

			if (mtflag)
				f_print(fout, ");\n");
			else
				f_print(fout, ") != RPC_SUCCESS) {\n");

		} else if (newstyle && args2) {
			/*
			 * Newstyle, multiple arguments
			 * stuff arguments into structure
			 */
			for (l = proc->args.decls;  l != NULL; l = l->next) {
				f_print(fout, "\targ.%s = %s;\n",
				    l->decl.name, l->decl.name);
			}
			if (mtflag)
				f_print(fout, "\treturn (");
			else
				f_print(fout, "\tif ((%s =", RESULT);
			f_print(fout,
			    "clnt_send(clnt, %s,\n\t\t(xdrproc_t)xdr_%s",
			    proc->proc_name, proc->args.argname);
			f_print(fout,
			    ", (caddr_t)&arg)");
			if (mtflag)
				f_print(fout, ");\n");
			else
				f_print(fout, ") != RPC_SUCCESS) {\n");
		} else {		/* single argument, new or old style */
			if (!mtflag)
				f_print(fout,
				    "\tif ((%s = clnt_send(clnt, "
				    "%s,\n\t\t(xdrproc_t)xdr_%s, "
				    "(caddr_t)%s%s)) != RPC_SUCCESS) {\n",
				    RESULT,
				    proc->proc_name,
				    stringfix(proc->args.decls->decl.type),
				    (newstyle ? "&" : ""),
				    (newstyle ?
				    proc->args.decls->decl.name :
				    "argp"));
			else

				f_print(fout,
				    "\treturn (clnt_send(clnt, "
				    "%s,\n\t\t(xdrproc_t)xdr_%s, "
				    "(caddr_t)%s%s));\n",
				    proc->proc_name,
				    stringfix(proc->args.decls->decl.type),
				    (newstyle ? "&" : ""),
				    (newstyle ?
				    proc->args.decls->decl.name :
				    "argp"));
		}
		if (!mtflag) {
			f_print(fout, "\t\treturn (NULL);\n");
			f_print(fout, "\t}\n");

			f_print(fout, "\treturn ((void *)&%s);\n",
			    RESULT);
		}
	}
}
