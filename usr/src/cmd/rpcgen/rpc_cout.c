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
 * rpc_cout.c, XDR routine outputter for the RPC protocol compiler
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "rpc_parse.h"
#include "rpc_util.h"

extern void crash(void);

static void print_header(definition *);
static void print_trailer(void);
static void emit_enum(definition *);
static void emit_program(definition *);
static void emit_union(definition *);
static void emit_struct(definition *);
static void emit_typedef(definition *);
static void print_stat(int, declaration *);
static void emit_inline(int, declaration *, int);
static void emit_inline64(int, declaration *, int);
static void emit_single_in_line(int, declaration *, int, relation);
static void emit_single_in_line64(int, declaration *, int, relation);
static char *upcase(char *);

/*
 * Emit the C-routine for the given definition
 */
void
emit(definition *def)
{
	if (def->def_kind == DEF_CONST)
		return;
	if (def->def_kind == DEF_PROGRAM) {
		emit_program(def);
		return;
	}
	if (def->def_kind == DEF_TYPEDEF) {
		/*
		 * now we need to handle declarations like
		 * struct typedef foo foo;
		 * since we dont want this to be expanded into 2 calls
		 * to xdr_foo
		 */

		if (strcmp(def->def.ty.old_type, def->def_name) == 0)
			return;
	};
	print_header(def);
	switch (def->def_kind) {
	case DEF_UNION:
		emit_union(def);
		break;
	case DEF_ENUM:
		emit_enum(def);
		break;
	case DEF_STRUCT:
		emit_struct(def);
		break;
	case DEF_TYPEDEF:
		emit_typedef(def);
		break;
	}
	print_trailer();
}

static int
findtype(definition *def, char *type)
{

	if (def->def_kind == DEF_PROGRAM || def->def_kind == DEF_CONST)
		return (0);
	return (streq(def->def_name, type));
}

static int
undefined(char *type)
{
	definition *def;

	def = (definition *)FINDVAL(defined, type, findtype);
	return (def == NULL);
}


static void
print_generic_header(char *procname, int pointerp)
{
	f_print(fout, "\n");
	f_print(fout, "bool_t\n");
	if (Cflag) {
		f_print(fout, "xdr_%s(", procname);
		f_print(fout, "XDR *xdrs, ");
		f_print(fout, "%s ", procname);
		if (pointerp)
			f_print(fout, "*");
		f_print(fout, "objp)\n{\n\n");
	} else {
		f_print(fout, "xdr_%s(xdrs, objp)\n", procname);
		f_print(fout, "\tXDR *xdrs;\n");
		f_print(fout, "\t%s ", procname);
		if (pointerp)
			f_print(fout, "*");
		f_print(fout, "objp;\n{\n\n");
	}
}

static void
print_header(definition *def)
{
	print_generic_header(def->def_name,
	    def->def_kind != DEF_TYPEDEF ||
	    !isvectordef(def->def.ty.old_type, def->def.ty.rel));
	/* Now add Inline support */

	if (inlinelen == 0)
		return;
	/* May cause lint to complain. but  ... */
	f_print(fout, "\trpc_inline_t *buf;\n\n");
}

static void
print_prog_header(proc_list *plist)
{
	print_generic_header(plist->args.argname, 1);
}

static void
print_trailer(void)
{
	f_print(fout, "\treturn (TRUE);\n");
	f_print(fout, "}\n");
}


static void
print_ifopen(int indent, char *name)
{
	tabify(fout, indent);
	if (streq(name, "rpcprog_t") ||
	    streq(name, "rpcvers_t") ||
	    streq(name, "rpcproc_t") ||
	    streq(name, "rpcprot_t") ||
	    streq(name, "rpcport_t"))
		(void) strtok(name, "_");
	f_print(fout, "if (!xdr_%s(xdrs", name);
}

static void
print_ifarg(char *arg)
{
	f_print(fout, ", %s", arg);
}

static void
print_ifsizeof(int indent, char *prefix, char *type)
{
	if (indent) {
		f_print(fout, ",\n");
		tabify(fout, indent);
	} else {
		f_print(fout, ", ");
	}
	if (streq(type, "bool")) {
		f_print(fout, "sizeof (bool_t), (xdrproc_t)xdr_bool");
	} else {
		f_print(fout, "sizeof (");
		if (undefined(type) && prefix) {
			f_print(fout, "%s ", prefix);
		}
		f_print(fout, "%s), (xdrproc_t)xdr_%s", type, type);
	}
}

static void
print_ifclose(int indent)
{
	f_print(fout, "))\n");
	tabify(fout, indent);
	f_print(fout, "\treturn (FALSE);\n");
}

static void
print_ifstat(int indent, char *prefix, char *type, relation rel,
					char *amax, char *objname, char *name)
{
	char *alt = NULL;

	switch (rel) {
	case REL_POINTER:
		print_ifopen(indent, "pointer");
		print_ifarg("(char **)");
		f_print(fout, "%s", objname);
		print_ifsizeof(0, prefix, type);
		break;
	case REL_VECTOR:
		if (streq(type, "string"))
			alt = "string";
		else if (streq(type, "opaque"))
			alt = "opaque";
		if (alt) {
			print_ifopen(indent, alt);
			print_ifarg(objname);
		} else {
			print_ifopen(indent, "vector");
			print_ifarg("(char *)");
			f_print(fout, "%s", objname);
		}
		print_ifarg(amax);
		if (!alt)
			print_ifsizeof(indent + 1, prefix, type);
		break;
	case REL_ARRAY:
		if (streq(type, "string"))
			alt = "string";
		else if (streq(type, "opaque"))
			alt = "bytes";
		if (streq(type, "string")) {
			print_ifopen(indent, alt);
			print_ifarg(objname);
		} else {
			if (alt)
				print_ifopen(indent, alt);
			else
				print_ifopen(indent, "array");
			print_ifarg("(char **)");
			if (*objname == '&')
				f_print(fout, "%s.%s_val, (u_int *) %s.%s_len",
				    objname, name, objname, name);
			else
				f_print(fout,
				    "&%s->%s_val, (u_int *) &%s->%s_len",
				    objname, name, objname, name);
		}
		print_ifarg(amax);
		if (!alt)
			print_ifsizeof(indent + 1, prefix, type);
		break;
	case REL_ALIAS:
		print_ifopen(indent, type);
		print_ifarg(objname);
		break;
	}
	print_ifclose(indent);
}

/* ARGSUSED */
static void
emit_enum(definition *def)
{
	print_ifopen(1, "enum");
	print_ifarg("(enum_t *)objp");
	print_ifclose(1);
}

static void
emit_program(definition *def)
{
	decl_list *dl;
	version_list *vlist;
	proc_list *plist;

	for (vlist = def->def.pr.versions; vlist != NULL; vlist = vlist->next)
		for (plist = vlist->procs; plist != NULL; plist = plist->next) {
			if (!newstyle || plist->arg_num < 2)
				continue; /* old style, or single argument */
			print_prog_header(plist);
			for (dl = plist->args.decls; dl != NULL;
			    dl = dl->next)
				print_stat(1, &dl->decl);
			print_trailer();
		}
}


static void
emit_union(definition *def)
{
	declaration *dflt;
	case_list *cl;
	declaration *cs;
	char *object;

	print_stat(1, &def->def.un.enum_decl);
	f_print(fout, "\tswitch (objp->%s) {\n", def->def.un.enum_decl.name);
	for (cl = def->def.un.cases; cl != NULL; cl = cl->next) {

		f_print(fout, "\tcase %s:\n", cl->case_name);
		if (cl->contflag == 1) /* a continued case statement */
			continue;
		cs = &cl->case_decl;
		if (!streq(cs->type, "void")) {
			size_t len = strlen(def->def_name) +
			    strlen("&objp->%s_u.%s") +
			    strlen(cs->name) + 1;
			object = malloc(len);
			if (isvectordef(cs->type, cs->rel))
				(void) snprintf(object, len, "objp->%s_u.%s",
				    def->def_name, cs->name);
			else
				(void) snprintf(object, len, "&objp->%s_u.%s",
				    def->def_name, cs->name);
			print_ifstat(2, cs->prefix, cs->type, cs->rel,
			    cs->array_max, object, cs->name);
			free(object);
		}
		f_print(fout, "\t\tbreak;\n");
	}
	dflt = def->def.un.default_decl;
	if (dflt != NULL) {
		if (!streq(dflt->type, "void")) {
			size_t len = strlen(def->def_name) +
			    strlen("&objp->%s_u.%s") +
			    strlen(dflt->name) + 1;
			f_print(fout, "\tdefault:\n");
			object = malloc(len);
			if (isvectordef(dflt->type, dflt->rel))
				(void) snprintf(object, len, "objp->%s_u.%s",
				    def->def_name, dflt->name);
			else
				(void) snprintf(object, len, "&objp->%s_u.%s",
				    def->def_name, dflt->name);

			print_ifstat(2, dflt->prefix, dflt->type, dflt->rel,
			    dflt->array_max, object, dflt->name);
			free(object);
			f_print(fout, "\t\tbreak;\n");
		}
	} else {
		f_print(fout, "\tdefault:\n");
		f_print(fout, "\t\treturn (FALSE);\n");
	}

	f_print(fout, "\t}\n");
}

static void
expand_inline(int indent, const char *sizestr,
    int size, int flag, decl_list *dl, decl_list *cur)
{
	decl_list *psav;

	/*
	 * were already looking at a xdr_inlineable structure
	 */
	tabify(fout, indent + 1);
	if (sizestr == NULL)
		f_print(fout,
		    "buf = XDR_INLINE(xdrs, %d * BYTES_PER_XDR_UNIT);",
		    size);
	else if (size == 0)
		f_print(fout,
		    "buf = XDR_INLINE(xdrs, (%s) * BYTES_PER_XDR_UNIT);",
		    sizestr);
	else
		f_print(fout,
		    "buf = XDR_INLINE(xdrs, (%d + (%s)) "
		    "* BYTES_PER_XDR_UNIT);", size, sizestr);

	f_print(fout, "\n");
	tabify(fout, indent + 1);
	f_print(fout, "if (buf == NULL) {\n");

	psav = cur;
	while (cur != dl) {
		print_stat(indent + 2,
		    &cur->decl);
		cur = cur->next;
	}

	tabify(fout, indent+1);
	f_print(fout, "} else {\n");

	f_print(fout, "#if defined(_LP64) || defined(_KERNEL)\n");
	cur = psav;
	while (cur != dl) {
		emit_inline64(indent + 2, &cur->decl, flag);
		cur = cur->next;
	}
	f_print(fout, "#else\n");
	cur = psav;
	while (cur != dl) {
		emit_inline(indent + 2, &cur->decl, flag);
		cur = cur->next;
	}
	f_print(fout, "#endif\n");

	tabify(fout, indent + 1);
	f_print(fout, "}\n");
}

/*
 * An inline type is a base type (interger type) or a vector of base types.
 */
static int
inline_type(declaration *dc, int *size)
{
	bas_type *ptr;

	*size = 0;

	if (dc->prefix == NULL &&
	    (dc->rel == REL_ALIAS || dc->rel == REL_VECTOR)) {
		ptr = find_type(dc->type);
		if (ptr != NULL) {
			*size = ptr->length;
			return (1);
		}
	}

	return (0);
}

static char *
arraysize(char *sz, declaration *dc, int elsize)
{
	int len;
	int elsz = elsize;
	int digits;
	int slen = 0;
	char *plus = "";
	char *tmp;
	size_t tlen;

	/*
	 * Calculate the size of a string to hold the size of all arrays
	 * to be inlined.
	 *
	 * We have the string representation of the total size that has already
	 * been seen. (Null if this is the first array).
	 * We have the string representation of array max from the declaration,
	 * optionally the plus string, " + ", if this is not the first array,
	 * and the number of digits for the element size for this declaration.
	 */
	if (sz != NULL) {
		plus = " + ";
		slen = strlen(sz);
	}

	/* Calculate the number of digits to hold the element size */
	for (digits = 1; elsz >= 10; digits++)
		elsz /= 10;

	/*
	 * If elsize != 1 the allocate 3 extra bytes for the times
	 * string, " * ", the "()" below,  and the digits. One extra
	 * for the trailing NULL
	 */
	len = strlen(dc->array_max) +  (elsize == 1 ? 0 : digits + 5) + 1;
	tlen = slen + len + strlen(plus);
	tmp = realloc(sz, tlen);
	if (tmp == NULL) {
		f_print(stderr, "Fatal error : no memory\n");
		crash();
	}

	if (elsize == 1)
		(void) snprintf(tmp + slen, tlen - slen, "%s%s",
		    plus, dc->array_max);
	else
		(void) snprintf(tmp + slen, tlen - slen, "%s(%s) * %d",
		    plus, dc->array_max, elsize);

	return (tmp);
}

static void
inline_struct(decl_list *dl, decl_list *last, int flag, int indent)
{
	int size, tsize;
	decl_list *cur;
	char *sizestr;

	cur = NULL;
	tsize = 0;
	sizestr = NULL;
	for (; dl != last; dl = dl->next) {
		if (inline_type(&dl->decl, &size)) {
			if (cur == NULL)
				cur = dl;

			if (dl->decl.rel == REL_ALIAS)
				tsize += size;
			else {
				/* this code is required to handle arrays */
				sizestr = arraysize(sizestr, &dl->decl, size);
			}
		} else {
			if (cur != NULL)
				if (sizestr == NULL && tsize < inlinelen) {
					/*
					 * don't expand into inline code
					 * if tsize < inlinelen
					 */
					while (cur != dl) {
						print_stat(indent + 1,
						    &cur->decl);
						cur = cur->next;
					}
				} else {
					expand_inline(indent, sizestr,
					    tsize, flag, dl, cur);
				}
			tsize = 0;
			cur = NULL;
			sizestr = NULL;
			print_stat(indent + 1, &dl->decl);
		}
	}

	if (cur == NULL)
		return;
	if (sizestr == NULL && tsize < inlinelen) {
		/* don't expand into inline code if tsize < inlinelen */
		while (cur != dl) {
			print_stat(indent + 1, &cur->decl);
			cur = cur->next;
		}
	} else {
		expand_inline(indent, sizestr, tsize, flag, dl, cur);
	}
}

/*
 * Check if we can inline this structure. While we are at it check if the
 * declaration list has any vectors defined of "basic" types.
 */
static int
check_inline(decl_list *dl, int inlinelen, int *have_vector)
{
	int tsize = 0;
	int size;
	int doinline = 0;

	*have_vector = 0;
	if (inlinelen == 0)
		return (0);

	for (; dl != NULL; dl = dl->next) {
		if (!inline_type(&dl->decl, &size)) {
			tsize = 0;
			continue;
		}
		if (dl->decl.rel == REL_VECTOR) {
			*have_vector = 1;
			return (1);
		}
		tsize += size;
		if (tsize >= inlinelen)
			doinline = 1;
	}

	return (doinline);
}


static void
emit_struct_tail_recursion(definition *defp, int can_inline)
{
	int indent = 3;
	struct_def *sp = &defp->def.st;
	decl_list *dl;


	f_print(fout, "\t%s *tmp_%s;\n",
	    defp->def_name, defp->def_name);

	f_print(fout, "\tbool_t more_data = TRUE;\n");
	f_print(fout, "\tbool_t first_objp = TRUE;\n\n");

	f_print(fout, "\n\tif (xdrs->x_op == XDR_DECODE) {\n");
	f_print(fout, "\n\t\twhile (more_data) {\n");
	f_print(fout, "\n\t\t\tvoid bzero();\n\n");

	if (can_inline)
		inline_struct(sp->decls, sp->tail, GET, indent);
	else
		for (dl = sp->decls; dl != NULL && dl != sp->tail;
		    dl = dl->next)
			print_stat(indent, &dl->decl);

	f_print(fout, "\t\t\tif (!xdr_bool(xdrs, "
	    "&more_data))\n\t\t\t\treturn (FALSE);\n");

	f_print(fout, "\n\t\t\tif (!more_data) {\n");
	f_print(fout, "\t\t\t\tobjp->%s = NULL;\n", sp->tail->decl.name);
	f_print(fout, "\t\t\t\tbreak;\n");
	f_print(fout, "\t\t\t}\n\n");
	f_print(fout, "\t\t\tif (objp->%s == NULL) {\n", sp->tail->decl.name);
	f_print(fout, "\t\t\t\tobjp->%s = "
	    "(%s *)\n\t\t\t\t\tmem_alloc(sizeof (%s));\n",
	    sp->tail->decl.name, defp->def_name, defp->def_name);

	f_print(fout, "\t\t\t\tif (objp->%s == NULL)\n"
	    "\t\t\t\t\treturn (FALSE);\n", sp->tail->decl.name);
	f_print(fout, "\t\t\t\tbzero(objp->%s, sizeof (%s));\n",
	    sp->tail->decl.name, defp->def_name);
	f_print(fout, "\t\t\t}\n");
	f_print(fout, "\t\t\tobjp = objp->%s;\n", sp->tail->decl.name);
	f_print(fout, "\t\t}\n");

	f_print(fout, "\n\t} else if (xdrs->x_op == XDR_ENCODE) {\n");
	f_print(fout, "\n\t\twhile (more_data) {\n");

	if (can_inline)
		inline_struct(sp->decls, sp->tail, PUT, indent);
	else
		for (dl = sp->decls; dl != NULL && dl != sp->tail;
		    dl = dl->next)
			print_stat(indent, &dl->decl);

	f_print(fout, "\t\t\tobjp = objp->%s;\n", sp->tail->decl.name);
	f_print(fout, "\t\t\tif (objp == NULL)\n");
	f_print(fout, "\t\t\t\tmore_data = FALSE;\n");

	f_print(fout, "\t\t\tif (!xdr_bool(xdrs, &more_data))\n"
	    "\t\t\t\treturn (FALSE);\n");

	f_print(fout, "\t\t}\n");

	f_print(fout, "\n\t} else {\n");
	f_print(fout, "\n\t\twhile (more_data) {\n");

	for (dl = sp->decls; dl != NULL && dl != sp->tail; dl = dl->next)
		print_stat(indent, &dl->decl);

	f_print(fout, "\t\t\ttmp_%s = objp;\n", defp->def_name);
	f_print(fout, "\t\t\tobjp = objp->%s;\n", sp->tail->decl.name);

	f_print(fout, "\t\t\tif (objp == NULL)\n");
	f_print(fout, "\t\t\t\tmore_data = FALSE;\n");

	f_print(fout, "\t\t\tif (!first_objp)\n");

	f_print(fout, "\t\t\t\tmem_free(tmp_%s, sizeof (%s));\n",
	    defp->def_name, defp->def_name);

	f_print(fout, "\t\t\telse\n\t\t\t\tfirst_objp = FALSE;\n\t\t}\n");

	f_print(fout, "\n\t}\n");
}

static void
emit_struct(definition *def)
{
	decl_list *dl = def->def.st.decls;
	int can_inline, have_vector;


	can_inline = check_inline(dl, inlinelen, &have_vector);
	if (have_vector)
		f_print(fout, "\tint i;\n");


	if (rflag && def->def.st.self_pointer) {
		/* Handle tail recursion elimination */
		emit_struct_tail_recursion(def, can_inline);
		return;
	}


	if (can_inline) {
		f_print(fout, "\n\tif (xdrs->x_op == XDR_ENCODE) {\n");
		inline_struct(dl, NULL, PUT, 1);

		f_print(fout, "\t\treturn (TRUE);\n\t}"
		    " else if (xdrs->x_op == XDR_DECODE) {\n");

		inline_struct(dl, NULL, GET, 1);
		f_print(fout, "\t\treturn (TRUE);\n\t}\n\n");
	}

	/* now take care of XDR_FREE inline  case or the non-inline cases */

	for (dl = def->def.st.decls; dl != NULL; dl = dl->next)
		print_stat(1, &dl->decl);

}

static void
emit_typedef(definition *def)
{
	char *prefix = def->def.ty.old_prefix;
	char *type = def->def.ty.old_type;
	char *amax = def->def.ty.array_max;
	relation rel = def->def.ty.rel;

	print_ifstat(1, prefix, type, rel, amax, "objp", def->def_name);
}

static void
print_stat(int indent, declaration *dec)
{
	char *prefix = dec->prefix;
	char *type = dec->type;
	char *amax = dec->array_max;
	relation rel = dec->rel;
	char name[256];

	if (isvectordef(type, rel))
		(void) snprintf(name, sizeof (name), "objp->%s", dec->name);
	else
		(void) snprintf(name, sizeof (name), "&objp->%s", dec->name);
	print_ifstat(indent, prefix, type, rel, amax, name, dec->name);
}


static void
emit_inline(int indent, declaration *decl, int flag)
{
	switch (decl->rel) {
	case  REL_ALIAS :
		emit_single_in_line(indent, decl, flag, REL_ALIAS);
		break;
	case REL_VECTOR :
		tabify(fout, indent);
		f_print(fout, "{\n");
		tabify(fout, indent + 1);
		f_print(fout, "%s *genp;\n\n", decl->type);
		tabify(fout, indent + 1);
		f_print(fout,
		    "for (i = 0, genp = objp->%s;\n", decl->name);
		tabify(fout, indent + 2);
		f_print(fout, "i < %s; i++) {\n", decl->array_max);
		emit_single_in_line(indent + 2, decl, flag, REL_VECTOR);
		tabify(fout, indent + 1);
		f_print(fout, "}\n");
		tabify(fout, indent);
		f_print(fout, "}\n");
	}
}

static void
emit_inline64(int indent, declaration *decl, int flag)
{
	switch (decl->rel) {
	case  REL_ALIAS :
		emit_single_in_line64(indent, decl, flag, REL_ALIAS);
		break;
	case REL_VECTOR :
		tabify(fout, indent);
		f_print(fout, "{\n");
		tabify(fout, indent + 1);
		f_print(fout, "%s *genp;\n\n", decl->type);
		tabify(fout, indent + 1);
		f_print(fout,
		    "for (i = 0, genp = objp->%s;\n", decl->name);
		tabify(fout, indent + 2);
		f_print(fout, "i < %s; i++) {\n", decl->array_max);
		emit_single_in_line64(indent + 2, decl, flag, REL_VECTOR);
		tabify(fout, indent + 1);
		f_print(fout, "}\n");
		tabify(fout, indent);
		f_print(fout, "}\n");
	}
}

static void
emit_single_in_line(int indent, declaration *decl, int flag, relation rel)
{
	char *upp_case;
	int freed = 0;

	tabify(fout, indent);
	if (flag == PUT)
		f_print(fout, "IXDR_PUT_");
	else
		if (rel == REL_ALIAS)
			f_print(fout, "objp->%s = IXDR_GET_", decl->name);
		else
			f_print(fout, "*genp++ = IXDR_GET_");

	upp_case = upcase(decl->type);

	/* hack	 - XX */
	if (strcmp(upp_case, "INT") == 0) {
		free(upp_case);
		freed = 1;
		upp_case = "LONG";
	}
	if ((strcmp(upp_case, "U_INT") == 0) ||
	    (strcmp(upp_case, "RPCPROG") == 0) ||
	    (strcmp(upp_case, "RPCVERS") == 0) ||
	    (strcmp(upp_case, "RPCPROC") == 0) ||
	    (strcmp(upp_case, "RPCPROT") == 0) ||
	    (strcmp(upp_case, "RPCPORT") == 0)) {
		free(upp_case);
		freed = 1;
		upp_case = "U_LONG";
	}

	if (flag == PUT)
		if (rel == REL_ALIAS)
			f_print(fout,
			    "%s(buf, objp->%s);\n", upp_case, decl->name);
		else
			f_print(fout, "%s(buf, *genp++);\n", upp_case);

	else
		f_print(fout, "%s(buf);\n", upp_case);
	if (!freed)
		free(upp_case);
}

static void
emit_single_in_line64(int indent, declaration *decl, int flag, relation rel)
{
	char *upp_case;
	int freed = 0;

	tabify(fout, indent);
	if (flag == PUT)
		f_print(fout, "IXDR_PUT_");
	else
		if (rel == REL_ALIAS)
			f_print(fout, "objp->%s = IXDR_GET_", decl->name);
		else
			f_print(fout, "*genp++ = IXDR_GET_");

	upp_case = upcase(decl->type);

	/* hack	 - XX */
	if ((strcmp(upp_case, "INT") == 0)||(strcmp(upp_case, "LONG") == 0)) {
		free(upp_case);
		freed = 1;
		upp_case = "INT32";
	}
	if ((strcmp(upp_case, "U_INT") == 0) ||
	    (strcmp(upp_case, "U_LONG") == 0) ||
	    (strcmp(upp_case, "RPCPROG") == 0) ||
	    (strcmp(upp_case, "RPCVERS") == 0) ||
	    (strcmp(upp_case, "RPCPROC") == 0) ||
	    (strcmp(upp_case, "RPCPROT") == 0) ||
	    (strcmp(upp_case, "RPCPORT") == 0)) {
		free(upp_case);
		freed = 1;
		upp_case = "U_INT32";
	}

	if (flag == PUT)
		if (rel == REL_ALIAS)
			f_print(fout,
			    "%s(buf, objp->%s);\n", upp_case, decl->name);
		else
			f_print(fout, "%s(buf, *genp++);\n", upp_case);

	else
		f_print(fout, "%s(buf);\n", upp_case);
	if (!freed)
		free(upp_case);
}

static char *
upcase(char *str)
{
	char *ptr, *hptr;

	ptr = malloc(strlen(str)+1);
	if (ptr == NULL) {
		f_print(stderr, "malloc failed\n");
		exit(1);
	};

	hptr = ptr;
	while (*str != '\0')
		*ptr++ = toupper(*str++);

	*ptr = '\0';
	return (hptr);
}
