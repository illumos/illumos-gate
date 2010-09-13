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
 * rpc_parse.c, Parser for the RPC protocol compiler
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "rpc/types.h"
#include "rpc_scan.h"
#include "rpc_parse.h"
#include "rpc_util.h"

#define	ARGNAME "arg"

extern char *make_argname(char *, char *);

static void isdefined(definition *);
static void def_struct(definition *);
static void def_program(definition *);
static void def_enum(definition *);
static void def_const(definition *);
static void def_union(definition *);
static void def_typedef(definition *);
static void get_declaration(declaration *, defkind);
static void get_prog_declaration(declaration *, defkind, int);
static void get_type(char **, char **, defkind);
static void unsigned_dec(char **);

/*
 * return the next definition you see
 */
definition *
get_definition(void)
{
	definition *defp;
	token tok;

	defp = calloc(1, sizeof (definition));
	get_token(&tok);
	switch (tok.kind) {
	case TOK_STRUCT:
		def_struct(defp);
		break;
	case TOK_UNION:
		def_union(defp);
		break;
	case TOK_TYPEDEF:
		def_typedef(defp);
		break;
	case TOK_ENUM:
		def_enum(defp);
		break;
	case TOK_PROGRAM:
		def_program(defp);
		break;
	case TOK_CONST:
		def_const(defp);
		break;
	case TOK_EOF:
		return (NULL);
	default:
		error("definition keyword expected");
	}
	scan(TOK_SEMICOLON, &tok);
	isdefined(defp);
	return (defp);
}

static void
isdefined(definition *defp)
{
	STOREVAL(&defined, defp);
}

/*
 * We treat s == NULL the same as *s == '\0'
 */
static int
streqn(const char *s1, const char *s2)
{
	if (s1 == NULL)
		s1 = "";
	if (s2 == NULL)
		s2 = "";
	if (s1 == s2)
		return (1);

	return (strcmp(s1, s2) == 0);
}

static int
cmptype(definition *defp, char *type)
{
	/* We only want typedef definitions */
	if (streq(defp->def_name, type) && defp->def_kind == DEF_TYPEDEF)
		return (1);
	return (0);
}

static int
check_self_reference(const char *name, const declaration *decp, int first)
{
	/*
	 * Now check for the following special case if first is true:
	 *
	 * struct foo {
	 *	...
	 *	foo *next;
	 * };
	 *
	 *
	 * In the above cases foo has not yet been entered in the type list,
	 * defined. So there is no typedef entry. The prefix in that case
	 * could be empty.
	 */
	if (decp->rel == REL_POINTER &&
	    (streqn(decp->prefix, "struct") ||
	    (first && streqn(decp->prefix, ""))) &&
	    streqn(name, decp->type))
		return (1);
	return (0);
}

static int
is_self_reference(definition *defp, declaration *decp)
{
	declaration current;
	definition *dp;

	if (check_self_reference(defp->def_name, decp, 1))
		return (1);

	/*
	 * Check for valid declaration:
	 * Only prefixes allowed are none and struct.
	 * Only relations allowed are pointer or alias.
	 */
	if (!streqn(decp->prefix, "struct") && !streqn(decp->prefix, ""))
		return (0);
	if (decp->rel != REL_POINTER && decp->rel != REL_ALIAS)
		return (0);

	current.rel = decp->rel;
	current.prefix = decp->prefix;
	current.type = decp->type;
	current.name = decp->name;
	decp = &current;
	while (!check_self_reference(defp->def_name, decp, 0)) {
		dp = FINDVAL(defined, decp->type, cmptype);

		/*
		 * Check if we found a definition.
		 */
		if (dp == NULL)
			return (0);

		/*
		 * Check for valid prefix. We eventually need to see one
		 * and only one struct.
		 */
		if (streqn(decp->prefix, "")) {
			/*
			 * If the current declaration prefix in empty
			 * then the definition found must have an empty
			 * prefix or a struct prefix
			 */
			if (!streqn(dp->def.ty.old_prefix, "") &&
			    !streqn(dp->def.ty.old_prefix, "struct"))
				return (0);
		} else if (streqn(decp->prefix, "struct") &&
		    !streqn(dp->def.ty.old_prefix, ""))
			/*
			 * if the current prefix is struct tne new prefix
			 * must be empty
			 */
			return (0);
		else if (!streqn(decp->prefix, "struct"))
			/* Should never get here */
			return (0);

		/*
		 * Check for valid relation. We need to see one and
		 * only one REL_POINTER. The only valid relation types
		 * are REL_POINTER and REL_ALIAS.
		 */
		if (decp->rel == REL_POINTER && dp->def.ty.rel != REL_ALIAS)
			return (0);
		if (decp->rel == REL_ALIAS &&
		    (dp->def.ty.rel != REL_ALIAS &&
		    dp->def.ty.rel != REL_POINTER))
			return (0);
		if (decp->rel != REL_ALIAS && decp->rel != REL_POINTER)
			/* Should never get here */
			return (0);

		/* Set up the current declaration */
		if (streqn(decp->prefix, ""))
			decp->prefix = dp->def.ty.old_prefix;
		decp->type = dp->def.ty.old_type;
		if (decp->rel == REL_ALIAS)
			decp->rel = dp->def.ty.rel;
	}

	/* We have a self reference type */
	return (1);
}

static void
def_struct(definition *defp)
{
	token tok;
	declaration dec;
	decl_list *decls;
	decl_list **tailp, *endp;

	defp->def_kind = DEF_STRUCT;

	scan(TOK_IDENT, &tok);
	defp->def_name = tok.str;
	scan(TOK_LBRACE, &tok);
	tailp = &defp->def.st.decls;
	defp->def.st.tail = NULL;
	do {
		get_declaration(&dec, DEF_STRUCT);
		decls = calloc(1, sizeof (decl_list));
		decls->decl = dec;
		/*
		 * Keep a referenct to the last declaration to check for
		 * tail recurrsion.
		 */
		endp = *tailp = decls;
		tailp = &decls->next;
		scan(TOK_SEMICOLON, &tok);
		peek(&tok);
	} while (tok.kind != TOK_RBRACE);
	*tailp = NULL;
	/*
	 * Check for tail recurse. If the last declaration refers to this
	 * structure then mark this stucture to convert the tail recursion
	 * to itteration.
	 */
	defp->def.st.self_pointer = is_self_reference(defp, &endp->decl);
	get_token(&tok);
	defp->def.st.tail = endp;
}

static void
def_program(definition *defp)
{
	token tok;
	declaration dec;
	decl_list *decls;
	decl_list **tailp;
	version_list *vlist;
	version_list **vtailp;
	proc_list *plist;
	proc_list **ptailp;
	int num_args;
	bool_t isvoid = FALSE;	/* whether first argument is void */
	defp->def_kind = DEF_PROGRAM;
	scan(TOK_IDENT, &tok);
	defp->def_name = tok.str;
	scan(TOK_LBRACE, &tok);
	vtailp = &defp->def.pr.versions;
	tailp = &defp->def.st.decls;
	scan(TOK_VERSION, &tok);
	do {
		scan(TOK_IDENT, &tok);
		vlist = calloc(1, sizeof (version_list));
		vlist->vers_name = tok.str;
		scan(TOK_LBRACE, &tok);
		ptailp = &vlist->procs;
		do {
			/* get result type */
			plist = calloc(1, sizeof (proc_list));
			get_type(&plist->res_prefix, &plist->res_type,
			    DEF_RESULT);
			if (streq(plist->res_type, "opaque")) {
				error("illegal result type");
			}
			scan(TOK_IDENT, &tok);
			plist->proc_name = tok.str;
			scan(TOK_LPAREN, &tok);
			/* get args - first one */
			num_args = 1;
			isvoid = FALSE;
			/*
			 * type of DEF_PROGRAM in the first
			 * get_prog_declaration and DEF_STURCT in the next
			 * allows void as argument if it is the only argument
			 */
			get_prog_declaration(&dec, DEF_PROGRAM, num_args);
			if (streq(dec.type, "void"))
				isvoid = TRUE;
			decls = calloc(1, sizeof (decl_list));
			plist->args.decls = decls;
			decls->decl = dec;
			tailp = &decls->next;
			/* get args */
			while (peekscan(TOK_COMMA, &tok)) {
				num_args++;
				get_prog_declaration(&dec, DEF_STRUCT,
				    num_args);
				decls = calloc(1, sizeof (decl_list));
				decls->decl = dec;
				*tailp = decls;
				if (streq(dec.type, "void"))
					isvoid = TRUE;
				tailp = &decls->next;
			}
			/* multiple arguments are only allowed in newstyle */
			if (!newstyle && num_args > 1) {
				error("only one argument is allowed");
			}
			if (isvoid && num_args > 1) {
				error("illegal use of void "
				    "in program definition");
			}
			*tailp = NULL;
			scan(TOK_RPAREN, &tok);
			scan(TOK_EQUAL, &tok);
			scan_num(&tok);
			scan(TOK_SEMICOLON, &tok);
			plist->proc_num = tok.str;
			plist->arg_num = num_args;
			*ptailp = plist;
			ptailp = &plist->next;
			peek(&tok);
		} while (tok.kind != TOK_RBRACE);
		*ptailp = NULL;
		*vtailp = vlist;
		vtailp = &vlist->next;
		scan(TOK_RBRACE, &tok);
		scan(TOK_EQUAL, &tok);
		scan_num(&tok);
		vlist->vers_num = tok.str;
		/* make the argument structure name for each arg */
		for (plist = vlist->procs; plist != NULL; plist = plist->next) {
			plist->args.argname = make_argname(plist->proc_name,
			    vlist->vers_num);
			/* free the memory ?? */
		}
		scan(TOK_SEMICOLON, &tok);
		scan2(TOK_VERSION, TOK_RBRACE, &tok);
	} while (tok.kind == TOK_VERSION);
	scan(TOK_EQUAL, &tok);
	scan_num(&tok);
	defp->def.pr.prog_num = tok.str;
	*vtailp = NULL;
}

static void
def_enum(definition *defp)
{
	token tok;
	enumval_list *elist;
	enumval_list **tailp;

	defp->def_kind = DEF_ENUM;
	scan(TOK_IDENT, &tok);
	defp->def_name = tok.str;
	scan(TOK_LBRACE, &tok);
	tailp = &defp->def.en.vals;
	do {
		scan(TOK_IDENT, &tok);
		elist = calloc(1, sizeof (enumval_list));
		elist->name = tok.str;
		elist->assignment = NULL;
		scan3(TOK_COMMA, TOK_RBRACE, TOK_EQUAL, &tok);
		if (tok.kind == TOK_EQUAL) {
			scan_num(&tok);
			elist->assignment = tok.str;
			scan2(TOK_COMMA, TOK_RBRACE, &tok);
		}
		*tailp = elist;
		tailp = &elist->next;
	} while (tok.kind != TOK_RBRACE);
	*tailp = NULL;
}

static void
def_const(definition *defp)
{
	token tok;

	defp->def_kind = DEF_CONST;
	scan(TOK_IDENT, &tok);
	defp->def_name = tok.str;
	scan(TOK_EQUAL, &tok);
	scan2(TOK_IDENT, TOK_STRCONST, &tok);
	defp->def.co = tok.str;
}

static void
def_union(definition *defp)
{
	token tok;
	declaration dec;
	case_list *cases;
	case_list **tailp;
	int flag;

	defp->def_kind = DEF_UNION;
	scan(TOK_IDENT, &tok);
	defp->def_name = tok.str;
	scan(TOK_SWITCH, &tok);
	scan(TOK_LPAREN, &tok);
	get_declaration(&dec, DEF_UNION);
	defp->def.un.enum_decl = dec;
	tailp = &defp->def.un.cases;
	scan(TOK_RPAREN, &tok);
	scan(TOK_LBRACE, &tok);
	scan(TOK_CASE, &tok);
	while (tok.kind == TOK_CASE) {
		scan2(TOK_IDENT, TOK_CHARCONST, &tok);
		cases = calloc(1, sizeof (case_list));
		cases->case_name = tok.str;
		scan(TOK_COLON, &tok);
		/* now peek at next token */
		flag = 0;
		if (peekscan(TOK_CASE, &tok)) {
			do {
				scan2(TOK_IDENT, TOK_CHARCONST, &tok);
				cases->contflag = 1;
				/* continued case statement */
				*tailp = cases;
				tailp = &cases->next;
				cases = calloc(1, sizeof (case_list));
				cases->case_name = tok.str;
				scan(TOK_COLON, &tok);
			} while (peekscan(TOK_CASE, &tok));
		} else if (flag) {
			*tailp = cases;
			tailp = &cases->next;
			cases = calloc(1, sizeof (case_list));
		}

		get_declaration(&dec, DEF_UNION);
		cases->case_decl = dec;
		cases->contflag = 0; /* no continued case statement */
		*tailp = cases;
		tailp = &cases->next;
		scan(TOK_SEMICOLON, &tok);

		scan3(TOK_CASE, TOK_DEFAULT, TOK_RBRACE, &tok);
	}
	*tailp = NULL;
	if (tok.kind == TOK_DEFAULT) {
		scan(TOK_COLON, &tok);
		get_declaration(&dec, DEF_UNION);
		defp->def.un.default_decl = calloc(1, sizeof (declaration));
		*defp->def.un.default_decl = dec;
		scan(TOK_SEMICOLON, &tok);
		scan(TOK_RBRACE, &tok);
	} else {
		defp->def.un.default_decl = NULL;
	}
}

static char *reserved_words[] = {
	"array",
	"bytes",
	"destroy",
	"free",
	"getpos",
	"inline",
	"pointer",
	"reference",
	"setpos",
	"sizeof",
	"union",
	"vector",
	NULL
};

static char *reserved_types[] = {
	"opaque",
	"string",
	NULL
};

/*
 * check that the given name is not one that would eventually result in
 * xdr routines that would conflict with internal XDR routines.
 */
static void
check_type_name(char *name, int new_type)
{
	int i;
	char tmp[100];

	for (i = 0; reserved_words[i] != NULL; i++) {
		if (strcmp(name, reserved_words[i]) == 0) {
			(void) snprintf(tmp, sizeof (tmp),
			    "illegal (reserved) name :\'%s\' "
			    "in type definition",
			    name);
			error(tmp);
		}
	}
	if (new_type) {
		for (i = 0; reserved_types[i] != NULL; i++) {
			if (strcmp(name, reserved_types[i]) == 0) {
				(void) snprintf(tmp, sizeof (tmp),
				    "illegal (reserved) name :\'%s\' "
				    "in type definition",
				    name);
				error(tmp);
			}
		}
	}
}

static void
def_typedef(definition *defp)
{
	declaration dec;

	defp->def_kind = DEF_TYPEDEF;
	get_declaration(&dec, DEF_TYPEDEF);
	defp->def_name = dec.name;
	check_type_name(dec.name, 1);
	defp->def.ty.old_prefix = dec.prefix;
	defp->def.ty.old_type = dec.type;
	defp->def.ty.rel = dec.rel;
	defp->def.ty.array_max = dec.array_max;
}

static void
get_declaration(declaration *dec, defkind dkind)
{
	token tok;

	get_type(&dec->prefix, &dec->type, dkind);
	dec->rel = REL_ALIAS;
	if (streq(dec->type, "void"))
		return;

	check_type_name(dec->type, 0);
	scan2(TOK_STAR, TOK_IDENT, &tok);
	if (tok.kind == TOK_STAR) {
		dec->rel = REL_POINTER;
		scan(TOK_IDENT, &tok);
	}
	dec->name = tok.str;
	if (peekscan(TOK_LBRACKET, &tok)) {
		if (dec->rel == REL_POINTER)
			error("no array-of-pointer declarations "
			    "-- use typedef");
		dec->rel = REL_VECTOR;
		scan_num(&tok);
		dec->array_max = tok.str;
		scan(TOK_RBRACKET, &tok);
	} else if (peekscan(TOK_LANGLE, &tok)) {
		if (dec->rel == REL_POINTER)
			error("no array-of-pointer declarations "
			    "-- use typedef");
		dec->rel = REL_ARRAY;
		if (peekscan(TOK_RANGLE, &tok)) {
			dec->array_max = "~0";	/* unspecified size, use max */
		} else {
			scan_num(&tok);
			dec->array_max = tok.str;
			scan(TOK_RANGLE, &tok);
		}
	}
	if (streq(dec->type, "opaque")) {
		if (dec->rel != REL_ARRAY && dec->rel != REL_VECTOR) {
			error("array declaration expected");
		}
	} else if (streq(dec->type, "string")) {
		if (dec->rel != REL_ARRAY) {
			error("variable-length array declaration expected");
		}
	}
}

static void
get_prog_declaration(declaration *dec, defkind dkind, int num)
{
	token tok;
	char name[sizeof (ARGNAME) + 10];

	if (dkind == DEF_PROGRAM) {
		peek(&tok);
		if (tok.kind == TOK_RPAREN) { /* no arguments */
			dec->rel = REL_ALIAS;
			dec->type = "void";
			dec->prefix = NULL;
			dec->name = NULL;
			return;
		}
	}
	get_type(&dec->prefix, &dec->type, dkind);
	dec->rel = REL_ALIAS;
	if (peekscan(TOK_IDENT, &tok)) /* optional name of argument */
		dec->name = strdup(tok.str);
	else {
		/* default name of argument */
		(void) snprintf(name, sizeof (name), "%s%d", ARGNAME, num);
		dec->name = strdup(name);
	}
	if (dec->name == NULL)
		error("internal error -- out of memory");

	if (streq(dec->type, "void"))
		return;

	if (streq(dec->type, "opaque"))
		error("opaque -- illegal argument type");
	if (peekscan(TOK_STAR, &tok)) {
		if (streq(dec->type, "string")) {
			error("pointer to string not allowed "
			    "in program arguments\n");
		}
		dec->rel = REL_POINTER;
		if (peekscan(TOK_IDENT, &tok))
			/* optional name of argument */
			dec->name = strdup(tok.str);
	}
	if (peekscan(TOK_LANGLE, &tok)) {
		if (!streq(dec->type, "string")) {
			error("arrays cannot be declared as arguments "
			    "to procedures -- use typedef");
		}
		dec->rel = REL_ARRAY;
		if (peekscan(TOK_RANGLE, &tok)) {
			dec->array_max = "~0";
			/* unspecified size, use max */
		} else {
			scan_num(&tok);
			dec->array_max = tok.str;
			scan(TOK_RANGLE, &tok);
		}
	}
	if (streq(dec->type, "string")) {
		if (dec->rel != REL_ARRAY) {
			/*
			 * .x specifies just string as
			 * type of argument
			 * - make it string<>
			 */
			dec->rel = REL_ARRAY;
			dec->array_max = "~0"; /* unspecified size, use max */
		}
	}
}

static void
get_type(char **prefixp, char **typep, defkind dkind)
{
	token tok;

	*prefixp = NULL;
	get_token(&tok);
	switch (tok.kind) {
	case TOK_IDENT:
		*typep = tok.str;
		break;
	case TOK_STRUCT:
	case TOK_ENUM:
	case TOK_UNION:
		*prefixp = tok.str;
		scan(TOK_IDENT, &tok);
		*typep = tok.str;
		break;
	case TOK_UNSIGNED:
		unsigned_dec(typep);
		break;
	case TOK_SHORT:
		*typep = "short";
		(void) peekscan(TOK_INT, &tok);
		break;
	case TOK_LONG:
		*typep = "long";
		(void) peekscan(TOK_INT, &tok);
		break;
	case TOK_HYPER:
		*typep = "longlong_t";
		(void) peekscan(TOK_INT, &tok);
		break;

	case TOK_VOID:
		if (dkind != DEF_UNION && dkind != DEF_PROGRAM &&
		    dkind != DEF_RESULT) {
			error("voids allowed only inside union and "
			    "program definitions with one argument");
		}
		*typep = tok.str;
		break;
	case TOK_ONEWAY:
		if (dkind != DEF_RESULT) {
			error("oneways allowed only inside result definitions");
		}
		*typep = tok.str;
		break;
	case TOK_STRING:
	case TOK_OPAQUE:
	case TOK_CHAR:
	case TOK_INT:
	case TOK_FLOAT:
	case TOK_DOUBLE:
	case TOK_BOOL:
	case TOK_QUAD:
		*typep = tok.str;
		break;
	default:
		error("expected type specifier");
	}
}

static void
unsigned_dec(char **typep)
{
	token tok;

	peek(&tok);
	switch (tok.kind) {
	case TOK_CHAR:
		get_token(&tok);
		*typep = "u_char";
		break;
	case TOK_SHORT:
		get_token(&tok);
		*typep = "u_short";
		(void) peekscan(TOK_INT, &tok);
		break;
	case TOK_LONG:
		get_token(&tok);
		*typep = "u_long";
		(void) peekscan(TOK_INT, &tok);
		break;
	case TOK_HYPER:
		get_token(&tok);
		*typep = "u_longlong_t";
		(void) peekscan(TOK_INT, &tok);
		break;
	case TOK_INT:
		get_token(&tok);
		*typep = "u_int";
		break;
	default:
		*typep = "u_int";
		break;
	}
}
