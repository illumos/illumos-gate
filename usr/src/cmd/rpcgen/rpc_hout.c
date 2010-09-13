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
 * rpc_hout.c, Header file outputter for the RPC protocol compiler
 */
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include "rpc_parse.h"
#include "rpc_util.h"

extern void pprocdef(proc_list *, version_list *, char *, int, int);
extern void pdeclaration(char *, declaration *, int, char *);

static void storexdrfuncdecl(char *, int);
static void pconstdef(definition *);
static void pstructdef(definition *);
static void puniondef(definition *);
static void pdefine(char *, char *);
static void pprogramdef(definition *);
static void parglist(proc_list *, char *);
static void penumdef(definition *);
static void ptypedef(definition *);
static uint_t undefined2(char *, char *);

enum rpc_gvc {
	PROGRAM,
	VERSION,
	PROCEDURE
};

/*
 * Print the C-version of an xdr definition
 */
void
print_datadef(definition *def)
{
	if (def->def_kind == DEF_PROGRAM)  /* handle data only */
		return;

	if (def->def_kind != DEF_CONST)
		f_print(fout, "\n");
	switch (def->def_kind) {
	case DEF_STRUCT:
		pstructdef(def);
		break;
	case DEF_UNION:
		puniondef(def);
		break;
	case DEF_ENUM:
		penumdef(def);
		break;
	case DEF_TYPEDEF:
		ptypedef(def);
		break;
	case DEF_PROGRAM:
		pprogramdef(def);
		break;
	case DEF_CONST:
		pconstdef(def);
		break;
	}
	if (def->def_kind != DEF_PROGRAM && def->def_kind != DEF_CONST)
		storexdrfuncdecl(def->def_name, def->def_kind != DEF_TYPEDEF ||
		    !isvectordef(def->def.ty.old_type, def->def.ty.rel));
}


void
print_funcdef(definition *def)
{
	switch (def->def_kind) {
	case DEF_PROGRAM:
		f_print(fout, "\n");
		pprogramdef(def);
		break;
	}
}

/*
 * store away enough information to allow the XDR functions to be spat
 * out at the end of the file
 */
static void
storexdrfuncdecl(char *name, int pointerp)
{
	xdrfunc *xdrptr;

	xdrptr = malloc(sizeof (struct xdrfunc));

	xdrptr->name = name;
	xdrptr->pointerp = pointerp;
	xdrptr->next = NULL;

	if (xdrfunc_tail == NULL) {
		xdrfunc_head = xdrptr;
		xdrfunc_tail = xdrptr;
	} else {
		xdrfunc_tail->next = xdrptr;
		xdrfunc_tail = xdrptr;
	}


}

void
print_xdr_func_def(char *name, int pointerp, int i)
{
	if (i == 2)
		f_print(fout, "extern bool_t xdr_%s();\n", name);
	else
		f_print(fout, "extern  bool_t xdr_%s(XDR *, %s%s);\n", name,
		    name, pointerp ? "*" : "");
}


static void
pconstdef(definition *def)
{
	pdefine(def->def_name, def->def.co);
}

/*
 * print out the definitions for the arguments of functions in the
 * header file
 */
static void
pargdef(definition *def)
{
	decl_list *l;
	version_list *vers;
	char *name;
	proc_list *plist;

	for (vers = def->def.pr.versions; vers != NULL; vers = vers->next) {
		for (plist = vers->procs; plist != NULL; plist = plist->next) {
			if (!newstyle || plist->arg_num < 2)
				continue; /* old style or single args */
			name = plist->args.argname;
			f_print(fout, "struct %s {\n", name);
			for (l = plist->args.decls; l != NULL; l = l->next)
				pdeclaration(name, &l->decl, 1, ";\n");
			f_print(fout, "};\n");
			f_print(fout, "typedef struct %s %s;\n", name, name);
			storexdrfuncdecl(name, 1);
			f_print(fout, "\n");
		}
	}
}


static void
pstructdef(definition *def)
{
	decl_list *l;
	char *name = def->def_name;

	f_print(fout, "struct %s {\n", name);
	for (l = def->def.st.decls; l != NULL; l = l->next)
		pdeclaration(name, &l->decl, 1, ";\n");
	f_print(fout, "};\n");
	f_print(fout, "typedef struct %s %s;\n", name, name);
}

static void
puniondef(definition *def)
{
	case_list *l;
	char *name = def->def_name;
	declaration *decl;

	f_print(fout, "struct %s {\n", name);
	decl = &def->def.un.enum_decl;
	if (streq(decl->type, "bool"))
		f_print(fout, "\tbool_t %s;\n", decl->name);
	else
		f_print(fout, "\t%s %s;\n", decl->type, decl->name);
	f_print(fout, "\tunion {\n");
	for (l = def->def.un.cases; l != NULL; l = l->next) {
		if (l->contflag == 0)
			pdeclaration(name, &l->case_decl, 2, ";\n");
	}
	decl = def->def.un.default_decl;
	if (decl && !streq(decl->type, "void"))
		pdeclaration(name, decl, 2, ";\n");
	f_print(fout, "\t} %s_u;\n", name);
	f_print(fout, "};\n");
	f_print(fout, "typedef struct %s %s;\n", name, name);
}

static void
pdefine(char *name, char *num)
{
	f_print(fout, "#define\t%s %s\n", name, num);
}

static void
puldefine(char *name, char *num, enum rpc_gvc which)
{
	switch (which) {
	case PROGRAM:
	case VERSION:
	case PROCEDURE:
		f_print(fout, "#define\t%s\t%s\n", name, num);
		break;
	default:
		break;
	}
}

static uint_t
define_printed(proc_list *stop, version_list *start)
{
	version_list *vers;
	proc_list *proc;

	for (vers = start; vers != NULL; vers = vers->next) {
		for (proc = vers->procs; proc != NULL; proc = proc->next) {
			if (proc == stop)
				return (0);
			if (streq(proc->proc_name, stop->proc_name))
				return (1);
		}
	}
	abort();
	/* NOTREACHED */
}

static void
pfreeprocdef(char *name, char *vers, int mode)
{
	f_print(fout, "extern int ");
	pvname(name, vers);
	if (mode == 1)
		f_print(fout, "_freeresult(SVCXPRT *, xdrproc_t, caddr_t);\n");
	else
		f_print(fout, "_freeresult();\n");
}

static void
pprogramdef(definition *def)
{
	version_list *vers;
	proc_list *proc;
	int i;
	char *ext;

	pargdef(def);

	puldefine(def->def_name, def->def.pr.prog_num, PROGRAM);
	for (vers = def->def.pr.versions; vers != NULL; vers = vers->next) {
		if (tblflag) {
			f_print(fout,
			    "extern struct rpcgen_table %s_%s_table[];\n",
			    locase(def->def_name), vers->vers_num);
			f_print(fout,
			    "extern int %s_%s_nproc;\n",
			    locase(def->def_name), vers->vers_num);
		}
		puldefine(vers->vers_name, vers->vers_num, VERSION);

		/*
		 * Print out 2 definitions, one for ANSI-C, another for
		 * old K & R C
		 */

		if (!Cflag) {
			ext = "extern  ";
			for (proc = vers->procs; proc != NULL;
			    proc = proc->next) {
				if (!define_printed(proc, def->def.pr.versions))
					puldefine(proc->proc_name,
					    proc->proc_num, PROCEDURE);
				f_print(fout, "%s", ext);
				pprocdef(proc, vers, NULL, 0, 2);

				if (mtflag) {
					f_print(fout, "%s", ext);
					pprocdef(proc, vers, NULL, 1, 2);
				}
			}
			pfreeprocdef(def->def_name, vers->vers_num, 2);
		} else {
			for (i = 1; i < 3; i++) {
				if (i == 1) {
					f_print(fout, "\n#if defined(__STDC__)"
					    " || defined(__cplusplus)\n");
					ext = "extern  ";
				} else {
					f_print(fout, "\n#else /* K&R C */\n");
					ext = "extern  ";
				}

				for (proc = vers->procs; proc != NULL;
				    proc = proc->next) {
					if (!define_printed(proc,
					    def->def.pr.versions)) {
						puldefine(proc->proc_name,
						    proc->proc_num, PROCEDURE);
					}
					f_print(fout, "%s", ext);
					pprocdef(proc, vers, "CLIENT *", 0, i);
					f_print(fout, "%s", ext);
					pprocdef(proc, vers,
					    "struct svc_req *", 1, i);
				}
				pfreeprocdef(def->def_name, vers->vers_num, i);
			}
			f_print(fout, "#endif /* K&R C */\n");
		}
	}
}

void
pprocdef(proc_list *proc, version_list *vp, char *addargtype, int server_p,
								int mode)
{
	if (mtflag) {
		/* Print MT style stubs */
		if (server_p)
			f_print(fout, "bool_t ");
		else
			f_print(fout, "enum clnt_stat ");
	} else {
		ptype(proc->res_prefix, proc->res_type, 1);
		f_print(fout, "* ");
	}
	if (server_p)
		pvname_svc(proc->proc_name, vp->vers_num);
	else
		pvname(proc->proc_name, vp->vers_num);

	/*
	 *  mode  1 = ANSI-C, mode 2 = K&R C
	 */
	if (mode == 1)
		parglist(proc, addargtype);
	else
		f_print(fout, "();\n");
}

/* print out argument list of procedure */
static void
parglist(proc_list *proc, char *addargtype)
{
	decl_list *dl;
	int oneway = streq(proc->res_type, "oneway");

	f_print(fout, "(");
	if (proc->arg_num < 2 && newstyle &&
	    streq(proc->args.decls->decl.type, "void")) {
		/* 0 argument in new style:  do nothing */
		/* EMPTY */
	} else {
		for (dl = proc->args.decls; dl != NULL; dl = dl->next) {
			ptype(dl->decl.prefix, dl->decl.type, 1);
			if (!newstyle || (dl->decl.rel == REL_POINTER))
				f_print(fout, "*");
			/* old style passes by reference */
			f_print(fout, ", ");
		}
	}

	if (mtflag && !oneway)  {
		ptype(proc->res_prefix, proc->res_type, 1);
		f_print(fout, "*, ");
	}

	f_print(fout, "%s);\n", addargtype);
}

static void
penumdef(definition *def)
{
	char *name = def->def_name;
	enumval_list *l;
	char *last = NULL;
	int count = 0;

	f_print(fout, "enum %s {\n", name);
	for (l = def->def.en.vals; l != NULL; l = l->next) {
		f_print(fout, "\t%s", l->name);
		if (l->assignment) {
			f_print(fout, " = %s", l->assignment);
			last = l->assignment;
			count = 1;
		} else {
			if (last == NULL)
				f_print(fout, " = %d", count++);
			else
				f_print(fout, " = %s + %d", last, count++);
		}
		if (l->next)
			f_print(fout, ",\n");
		else
			f_print(fout, "\n");
	}
	f_print(fout, "};\n");
	f_print(fout, "typedef enum %s %s;\n", name, name);
}

static void
ptypedef(definition *def)
{
	char *name = def->def_name;
	char *old = def->def.ty.old_type;
	char prefix[8];	/* enough to contain "struct ", including NUL */
	relation rel = def->def.ty.rel;


	if (!streq(name, old)) {
		if (streq(old, "string")) {
			old = "char";
			rel = REL_POINTER;
		} else if (streq(old, "opaque")) {
			old = "char";
		} else if (streq(old, "bool")) {
			old = "bool_t";
		}
		if (undefined2(old, name) && def->def.ty.old_prefix)
			(void) snprintf(prefix, sizeof (prefix), "%s ",
			    def->def.ty.old_prefix);
		else
			prefix[0] = 0;
		f_print(fout, "typedef ");
		switch (rel) {
		case REL_ARRAY:
			f_print(fout, "struct {\n");
			f_print(fout, "\tu_int %s_len;\n", name);
			f_print(fout, "\t%s%s *%s_val;\n", prefix, old, name);
			f_print(fout, "} %s", name);
			break;
		case REL_POINTER:
			f_print(fout, "%s%s *%s", prefix, old, name);
			break;
		case REL_VECTOR:
			f_print(fout, "%s%s %s[%s]", prefix, old, name,
			    def->def.ty.array_max);
			break;
		case REL_ALIAS:
			f_print(fout, "%s%s %s", prefix, old, name);
			break;
		}
		f_print(fout, ";\n");
	}
}

void
pdeclaration(char *name, declaration *dec, int tab, char *separator)
{
	char buf[8];	/* enough to hold "struct ", include NUL */
	char *prefix;
	char *type;

	if (streq(dec->type, "void"))
		return;
	tabify(fout, tab);
	if (streq(dec->type, name) && !dec->prefix)
		f_print(fout, "struct ");
	if (streq(dec->type, "string")) {
		f_print(fout, "char *%s", dec->name);
	} else {
		prefix = "";
		if (streq(dec->type, "bool")) {
			type = "bool_t";
		} else if (streq(dec->type, "opaque")) {
			type = "char";
		} else {
			if (dec->prefix) {
				(void) snprintf(buf, sizeof (buf),
				    "%s ", dec->prefix);
				prefix = buf;
			}
			type = dec->type;
		}
		switch (dec->rel) {
		case REL_ALIAS:
			f_print(fout, "%s%s %s", prefix, type, dec->name);
			break;
		case REL_VECTOR:
			f_print(fout, "%s%s %s[%s]", prefix, type, dec->name,
			    dec->array_max);
			break;
		case REL_POINTER:
			f_print(fout, "%s%s *%s", prefix, type, dec->name);
			break;
		case REL_ARRAY:
			f_print(fout, "struct {\n");
			tabify(fout, tab);
			f_print(fout, "\tu_int %s_len;\n", dec->name);
			tabify(fout, tab);
			f_print(fout,
			    "\t%s%s *%s_val;\n", prefix, type, dec->name);
			tabify(fout, tab);
			f_print(fout, "} %s", dec->name);
			break;
		}
	}
	/* LINTED variable format */
	f_print(fout, separator);
}

static uint_t
undefined2(char *type, char *stop)
{
	list *l;
	definition *def;

	for (l = defined; l != NULL; l = l->next) {
		def = (definition *) l->val;
		if (def->def_kind != DEF_PROGRAM) {
			if (streq(def->def_name, stop))
				return (1);
			if (streq(def->def_name, type))
				return (0);
		}
	}
	return (1);
}
