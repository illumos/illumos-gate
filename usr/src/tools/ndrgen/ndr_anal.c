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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <strings.h>
#include <string.h>
#include "ndrgen.h"
#include "y.tab.h"


#define	ALLOW_NOTHING	0
#define	ALLOW_VARSIZE	1
#define	ALLOW_INOUT	2
#define	ALLOW_CASE	4
#define	ALLOW_NO_UNIONS	8		/* for topmost structures */
#define	ALLOW_NO_SWITCH 16

struct tup {
	struct tup		*up;
	ndr_typeinfo_t		*ti;
};

static void type_ident_decl(ndr_typeinfo_t *, char *, size_t, char *);
static void type_ident_decl1(struct tup *, char *, size_t, char *);
static void analyze_typeinfo_list(void);
static void analyze_typeinfo_typedef(ndr_typeinfo_t *);
static void analyze_typeinfo_struct(ndr_typeinfo_t *);
static void analyze_typeinfo_union(ndr_typeinfo_t *);
static void analyze_typeinfo_aggregate_finish(ndr_typeinfo_t *);
static void analyze_member(ndr_node_t *, ndr_member_t *, unsigned long *, int);
static void seed_basic_types(void);
static void seed_construct_types(void);
static void append_typeinfo(ndr_typeinfo_t *);
static ndr_typeinfo_t *bind_typeinfo(ndr_typeinfo_t *);
static ndr_typeinfo_t *find_typeinfo_by_name(ndr_node_t *);
static void determine_advice(ndr_advice_t *, ndr_node_t *);
static ndr_node_t *find_advice(ndr_node_t *advice_list, int label);


void
analyze(void)
{
	seed_basic_types();
	seed_construct_types();

	analyze_typeinfo_list();
}

void
show_typeinfo_list(void)
{
	ndr_typeinfo_t		*ti;
	ndr_typeinfo_t		*tdti;
	int			i;
	ndr_member_t		*mem;
	char			*p;
	char			fname_type[NDLBUFSZ];

	for (ti = typeinfo_list; ti; ti = ti->next) {
		switch (ti->type_op) {
		case STRUCT_KW:
			p = "struct";
			break;

		case UNION_KW:
			p = "union";
			break;

		case TYPEDEF_KW:
			p = "typedef";
			break;

		case STRING_KW:
		case STAR:
		case LB:
		case BASIC_TYPE:
			type_extern_suffix(ti, fname_type, NDLBUFSZ);
			if (ti->is_extern) {
				(void) printf("extern ndr_%s()\n",
				    fname_type);
			} else if (!ti->is_referenced) {
				(void) printf("implied ndr_%s\n", fname_type);
			}
			continue;

		default:
			(void) printf("show_typeinfo skipping %d\n",
			    ti->type_op);
			continue;
		}

		(void) printf("\n\n");
		show_advice(&ti->advice, 0);
		(void) printf("%s %s {\n", p, ti->type_name->n_sym->name);

		for (i = 0; i < ti->n_member; i++) {
			mem = &ti->member[i];
			show_advice(&mem->advice, 2);
			type_extern_suffix(mem->type, fname_type, NDLBUFSZ);
			(void) printf("    %-16s ndr_%-13s",
			    mem->name, fname_type);

			tdti = mem->type;
			(void) printf(" fsiz=%d vsiz=%d algn=%d off=%d\n",
			    tdti->size_fixed_part,
			    tdti->size_variable_part,
			    tdti->alignment,
			    mem->pdu_offset);
		}

		(void) printf("} fsiz=%d vsiz=%d algn=%d comp=%d ptrs=%d\n",
		    ti->size_fixed_part,
		    ti->size_variable_part,
		    ti->alignment,
		    ti->complete,
		    ti->has_pointers);
	}
}

void
type_extern_suffix(ndr_typeinfo_t *tsti, char *funcbuf, size_t buflen)
{
	ndr_typeinfo_t		*ti;
	char			*p_fb = funcbuf;

	*p_fb = 0;

	for (ti = tsti; ti; ti = ti->type_down) {
		switch (ti->type_op) {
		case BASIC_TYPE:
		case STRUCT_KW:
		case TYPEDEF_KW:
		case UNION_KW:
			(void) snprintf(p_fb, buflen, "_%s",
			    ti->type_name->n_sym->name);
			break;

		case STAR:
			(void) strlcpy(p_fb, "p", buflen);
			break;

		case LB:
			if (ti->type_dim) {
				(void) snprintf(p_fb, buflen, "a%ld",
				    ti->type_dim->n_int);
			} else {
				(void) snprintf(p_fb, buflen, "ac");
			}
			break;

		case STRING_KW:
			(void) strlcpy(p_fb, "s", buflen);
			break;

		default:
			(void) snprintf(p_fb, buflen, "?<%d>", ti->type_op);
			break;
		}
		while (*p_fb)
			p_fb++;
	}
}

static void
type_ident_decl1(struct tup *tup, char *funcbuf, size_t buflen, char *ident)
{
	ndr_typeinfo_t		*ti;
	char			fb[NDLBUFSZ];
	char			*p;

	if (!tup) {
		(void) strlcpy(funcbuf, ident, buflen);
		return;
	}
	ti = tup->ti;

	switch (ti->type_op) {
	case BASIC_TYPE:
	case TYPEDEF_KW:
		type_ident_decl1(tup->up, fb, NDLBUFSZ, ident);
		(void) snprintf(funcbuf, buflen, "%s%s%s%s",
		    "", ti->type_name->n_sym->name, *fb ? " " : "", fb);
		break;

	case STRUCT_KW:
		type_ident_decl1(tup->up, fb, NDLBUFSZ, ident);
		(void) snprintf(funcbuf, buflen, "%s%s%s%s",
		    "struct ", ti->type_name->n_sym->name, *fb ? " " : "", fb);
		break;

	case UNION_KW:
		type_ident_decl1(tup->up, fb, NDLBUFSZ, ident);
		(void) snprintf(funcbuf, buflen, "%s%s%s%s",
		    "union ", ti->type_name->n_sym->name, *fb ? " " : "", fb);
		break;

	case STAR:
		*funcbuf = '*';
		type_ident_decl1(tup->up, funcbuf+1, buflen - 1, ident);
		break;

	case LB:
		p = fb;
		*p++ = '(';
		type_ident_decl1(tup->up, p, NDLBUFSZ - 1, ident);
		if (*p == '*') {
			p = fb;
			(void) strlcat(p, ")", NDLBUFSZ);
		}
		if (ti->type_dim) {
			(void) snprintf(funcbuf, buflen, "%s[%ld]",
			    p, ti->type_dim->n_int);
		} else {
			(void) snprintf(funcbuf, buflen,
			    "%s[NDR_ANYSIZE_DIM]", p);
		}
		break;

	case STRING_KW:
		p = fb;
		*p++ = '(';
		type_ident_decl1(tup->up, p, NDLBUFSZ - 1, ident);
		if (*p == '*') {
			p = fb;
			(void) strlcat(p, ")", NDLBUFSZ);
		}
		(void) snprintf(funcbuf, buflen, "%s[NDR_STRING_DIM]", p);
		break;

	default:
		compile_error("unknown type or keyword <%d>", ti->type_op);
		break;
	}
}

static void
type_ident_decl(ndr_typeinfo_t *tsti, char *funcbuf, size_t buflen, char *ident)
{
	ndr_typeinfo_t		*ti;
	struct tup		tup_tab[40];
	struct tup		*tup;
	struct tup		*up = 0;
	int			n_tt = 0;

	for (ti = tsti; ti; ti = ti->type_down, n_tt++) {
		tup = &tup_tab[n_tt];
		tup->up = up;
		tup->ti = ti;
		up = tup;
	}

	type_ident_decl1(up, funcbuf, buflen, ident);
}

void
type_null_decl(ndr_typeinfo_t *tsti, char *funcbuf, size_t buflen)
{
	funcbuf[0] = '(';
	type_ident_decl(tsti, funcbuf+1, buflen, "");
	(void) strlcat(funcbuf, ")", buflen);
}

void
type_name_decl(ndr_typeinfo_t *tsti, char *funcbuf, size_t buflen, char *name)
{
	type_ident_decl(tsti, funcbuf, buflen, name);
}

void
show_advice(ndr_advice_t *adv, int indent)
{
	int		i;
	int		n = 0;

	for (i = 0; i < N_ADVICE; i++) {
		if (!adv->a_nodes[i])
			continue;

		if (n++ == 0)
			(void) printf("%-*s[", indent, "");
		else
			(void) printf(" ");

		print_node(adv->a_nodes[i]);
	}

	if (n)
		(void) printf("]\n");
}

static void
analyze_typeinfo_list(void)
{
	ndr_typeinfo_t		*ti;

	for (ti = typeinfo_list; ti; ti = ti->next) {
		switch (ti->type_op) {
		case STRUCT_KW:
			analyze_typeinfo_struct(ti);
			break;

		case UNION_KW:
			analyze_typeinfo_union(ti);
			break;

		case TYPEDEF_KW:
			analyze_typeinfo_typedef(ti);
			break;
		}
	}
}

static void
analyze_typeinfo_typedef(ndr_typeinfo_t *ti)
{
	ndr_node_t		*mem_np;
	ndr_member_t		*mem;
	int			i;
	int			allow;
	unsigned long		offset;

	assert(ti->type_op == TYPEDEF_KW);

	/*
	 * Snarf the advice.
	 */
	determine_advice(&ti->advice, ti->definition->n_c_advice);

	/*
	 * Convert the members to table.
	 * Determine layout metrics along the way.
	 */
	mem_np = ti->definition->n_c_members;
	i = 0;
	offset = 0;
	assert(i < ti->n_member);
	mem = &ti->member[i];

	allow = ALLOW_NO_SWITCH;

	analyze_member(mem_np, mem,
	    &offset,		/* progress offset */
	    allow);		/* see above */

	assert(1 == ti->n_member);

	analyze_typeinfo_aggregate_finish(ti);

	/* Align offset to determine overall size */
	while (offset & ti->alignment)
		offset++;

	ti->size_fixed_part = offset;
}

static void
analyze_typeinfo_struct(ndr_typeinfo_t *ti)
{
	ndr_node_t		*mem_np;
	ndr_member_t		*mem;
	int			i;
	int			allow;
	unsigned long		offset;

	assert(ti->type_op == STRUCT_KW);

	/*
	 * Snarf the advice. Only recognize [operation()] for
	 * struct definitions.
	 */
	determine_advice(&ti->advice, ti->definition->n_c_advice);

	/*
	 * Convert the members from list to table.
	 * Determine layout metrics along the way.
	 */
	mem_np = ti->definition->n_c_members;
	i = 0;
	offset = 0;
	for (; mem_np; i++, mem_np = mem_np->n_next) {
		assert(i < ti->n_member);
		mem = &ti->member[i];

		if (!ti->advice.a_operation /* no var-size in op param */ &&
		    i == ti->n_member-1)  /* only last mem may be var-size */
			allow = ALLOW_VARSIZE;
		else
			allow = 0;

		analyze_member(mem_np, mem, &offset, allow);
	}
	assert(i == ti->n_member);

	analyze_typeinfo_aggregate_finish(ti);	/* align,complete,ptrs,etc */

	/* Align offset to determine overall size */
	while (offset & ti->alignment)
		offset++;

	ti->size_fixed_part = offset;

	/* If last member is var-sized, so is this struct */
	mem = &ti->member[ti->n_member-1];
	ti->size_variable_part = mem->type->size_variable_part;

	if (ti->size_variable_part)
		ti->is_conformant = 1;
}

static void
analyze_typeinfo_union(ndr_typeinfo_t *ti)
{
	ndr_node_t		*mem_np;
	ndr_member_t		*mem;
	int			i;
	unsigned long		offset;
	unsigned long		size;

	assert(ti->type_op == UNION_KW);

	/*
	 * Snarf the advice. None supported for union definitions.
	 * Only [switch_is()] supported for union instances.
	 */
	determine_advice(&ti->advice, ti->definition->n_c_advice);

	/*
	 * Convert the members from list to table.
	 * Determine layout metrics along the way.
	 */
	mem_np = ti->definition->n_c_members;
	i = 0;
	size = 0;
	for (; mem_np; i++, mem_np = mem_np->n_next) {
		assert(i < ti->n_member);
		mem = &ti->member[i];

		offset = 0;			/* all members offset=0 */
		analyze_member(mem_np, mem,
		    &offset,
		    ALLOW_CASE+ALLOW_NO_UNIONS); /* var-size disallowed */

		if (size < mem->type->size_fixed_part)
			size = mem->type->size_fixed_part;
	}
	assert(i == ti->n_member);

	analyze_typeinfo_aggregate_finish(ti);	/* align,complete,ptrs,etc */

	/* align size to determine overall size */
	while (size & ti->alignment)
		size++;

	ti->size_fixed_part = size;
}

static void
analyze_typeinfo_aggregate_finish(ndr_typeinfo_t *ti)
{
	int			i;
	ndr_member_t		*mem;
	int			complete = 1;
	int			has_pointers = 0;

	for (i = 0; i < ti->n_member; i++) {
		mem = &ti->member[i];

		complete &= mem->type->complete;
		has_pointers |= mem->type->has_pointers;
		ti->alignment |= mem->type->alignment;
	}

	ti->complete = complete;
	ti->has_pointers = has_pointers;
}

static void
analyze_member(ndr_node_t *mem_np, ndr_member_t *mem,
    unsigned long *offsetp, int allow)
{
	int			i, n_decl_ops;
	ndr_node_t		*decl_ops[NDLBUFSZ];
	ndr_typeinfo_t		*type_down;
	ndr_typeinfo_t		proto_ti;
	ndr_node_t		*np;

	/*
	 * Set line_number for error reporting (so we know where to look)
	 */
	line_number = mem_np->line_number;

	/*
	 * Simple parts of member
	 */
	mem->definition = mem_np;
	determine_advice(&mem->advice, mem_np->n_m_advice);

	/*
	 * The node list for the declarator is in outside-to-inside
	 * order. It is also decorated with the LP nodes for
	 * precedence, which are in our way at this point.
	 *
	 * These two loops reverse the list, which is easier
	 * to analyze. For example, the declaration:
	 *
	 *	ulong *		(id[100]);
	 *
	 * will have the node list (=> indicates n_d_descend):
	 *
	 *	ulong  =>  STAR  =>  LP  =>  LB[100]  =>  id
	 *
	 * and the conversion will result in type info (=> indicates
	 * type_down):
	 *
	 *	id  =>  LB[100]  =>  STAR  =>  ulong
	 *
	 * which is closer to how you would pronounce the declaration:
	 *
	 *	id is an array size 100 of pointers to ulong.
	 */

	/* first pass -- turn the list into a table */
	n_decl_ops = 0;
	for (np = mem_np->n_m_decl; np; np = np->n_d_descend) {
		if (np->label == IDENTIFIER) {
			break;		/* done */
		}

		if (np->label == LP)
			continue;	/* ignore precedence nodes */

		decl_ops[n_decl_ops++] = np;
	}
	if (!np) {
		compile_error("declaration error");
		print_node(mem_np->n_m_decl);
		(void) printf("\n");
	} else {
		mem->name = np->n_sym->name;
	}

	/* second pass -- turn the table into push-back list */
	type_down = find_typeinfo_by_name(mem_np->n_m_type);

	if (type_down->type_op == TYPEDEF_KW)
		type_down = type_down->member[0].type;

	if (mem->advice.a_string) {
		bzero(&proto_ti, sizeof (proto_ti));
		proto_ti.type_op = STRING_KW;
		proto_ti.type_down = type_down;
		type_down = bind_typeinfo(&proto_ti);
	}

	for (i = n_decl_ops; i-- > 0; ) {
		np = decl_ops[i];

		bzero(&proto_ti, sizeof (proto_ti));

		proto_ti.type_op = np->label;
		proto_ti.type_down = type_down;

		switch (np->label) {
		case LB:
			proto_ti.type_dim = np->n_d_dim;
			break;
		}

		/*
		 * bind_typeinfo() reuses (interns) typeinfo's to
		 * make later code generation easier. It will report
		 * some errors.
		 */
		type_down = bind_typeinfo(&proto_ti);
	}

	/* bind the member to its type info */
	mem->type = type_down;
	type_down->is_referenced = 1;	/* we handle first-level indirection */

	/*
	 * Now, apply the type info to the member layout metrics.
	 */

	/* alignment */
	while (*offsetp & type_down->alignment)
		++*offsetp;

	mem->pdu_offset = *offsetp;

	*offsetp += type_down->size_fixed_part;

	if (mem->advice.a_length_is)
		compile_error("[length_is()] is not supported");

	if (mem->advice.a_transmit_as)
		compile_error("[transmit_as()] is not supported");

	if (mem->advice.a_arg_is)
		compile_error("[arg_is()] is not supported");

	/*
	 * Disallow
	 *	[case(x)] TYPE	xxx;
	 *	[default] TYPE	xxx;
	 *
	 * These only make sense within unions.
	 */
	if (allow & ALLOW_CASE) {
		int		n = 0;

		if (mem->advice.a_case)
			n++;
		if (mem->advice.a_default)
			n++;

		if (n == 0)
			compile_error("no [case/default] advice");
		else if (n > 1)
			compile_error("too many [case/default] advice");
	} else {
		if (mem->advice.a_case && mem->advice.a_default)
			compile_error("[case/default] advice not allowed");
	}

	/*
	 * Disallow
	 *	[operation(x)]	TYPE	foo;
	 *	[interface(x)]	TYPE	foo;
	 *	[uuid(x)]	TYPE	foo;
	 *
	 * The [operation()] advice may only appear on a struct to
	 * indicate that the structure is a top-most (parameter)
	 * structure, and the opcode associated with the parameters.
	 */
	if (mem->advice.a_operation)
		compile_error("[operation()] advice not allowed");

	if (mem->advice.a_interface)
		compile_error("[interface()] advice not allowed");

	if (mem->advice.a_uuid)
		compile_error("[uuid()] advice not allowed");

	/*
	 * Allow
	 *	[switch_is(x)] union foo	xxx;
	 *
	 * Disallow [switch_is] on anything which is not a union.
	 */
	if (mem->advice.a_switch_is && type_down->type_op != UNION_KW) {
		compile_error("[switch_is()] advice not allowed");
	}

	/*
	 * Allow
	 *	[size_is(x)] TYPE *	ptr;
	 *	[size_is(x)] TYPE	arr[];
	 *
	 * Disallow [size_is()] on anything other than pointer and
	 * variable length array.
	 */
	if (mem->advice.a_size_is &&
	    type_down->type_op != STAR &&
	    !(type_down->type_op == LB &&
	    type_down->type_dim == 0)) {
		compile_error("[size_is()] advice not allowed");
	}

	/*
	 * Allow
	 *	[string] char *		ptr_string;
	 *
	 * Disallow [string] on anything else. The determination
	 * of size (for the outer header) on anything else is
	 * impossible.
	 */
	if (mem->advice.a_string && type_down->type_op != STAR) {
		compile_error("[string] advice not allowed");
	}

	if (type_down->type_op == LB &&
	    type_down->type_dim == 0) { /* var-length array of some sort */

		int		n = 0;

		/*
		 * Requires [size_is()] directive
		 *	[size_is(x)] TYPE	array[]
		 */

		if (mem->advice.a_size_is)
			n++;

		if (!n)
			compile_error("var-size missing sizing directive");
		else if (n > 1)
			compile_error("var-size too many sizing directives");
	}

	/*
	 * Nested unions and struct members, other than the last one,
	 * cannot contain variable sized members.
	 */
	if (type_down->size_variable_part && !(allow & ALLOW_VARSIZE)) {
		compile_error("var-size member not allowed");
	}

	/*
	 * Disallow unions in operations (i.e. [operation()] struct ...),
	 * The switch_is() value is not reliably available. DCE/RPC
	 * automatically synthesizes an encapsulated union for
	 * these situations, which we have to do by hand:
	 *
	 *	struct { long switch_value; union foo x; } synth;
	 *
	 * We also can not allow unions within unions because
	 * there is no way to pass the separate [switch_is(x)] selector.
	 */
	if (type_down->type_op == UNION_KW) {
		if (allow & ALLOW_NO_UNIONS) {
			compile_error("unencapsulated union not allowed");
		} else if (!mem->advice.a_switch_is &&
		    !(allow & ALLOW_NO_SWITCH)) {
			compile_error("union instance without selector");
		}
	}
}

static void
seed_basic_types(void)
{
	ndr_symbol_t		*sym;
	ndr_typeinfo_t		*ti;
	ndr_typeinfo_t		proto_ti;

	for (sym = symbol_list; sym; sym = sym->next) {
		if (!sym->kw)
			continue;

		if (sym->kw->token != BASIC_TYPE)
			continue;

		ti = ndr_alloc(1, sizeof (ndr_typeinfo_t));

		ti->type_op = BASIC_TYPE;
		ti->definition = &sym->s_node;
		ti->type_name = &sym->s_node;
		ti->size_fixed_part = sym->kw->value;
		ti->alignment = ti->size_fixed_part - 1;
		ti->complete = 1;
		ti->is_extern = 1;

		append_typeinfo(ti);

		bzero(&proto_ti, sizeof (proto_ti));
		proto_ti.type_op = STRING_KW;
		proto_ti.type_down = ti;

		ti = bind_typeinfo(&proto_ti);
		ti->is_extern = 1;
	}
}

static void
seed_construct_types(void)
{
	ndr_node_t		*construct;
	ndr_node_t		*np;
	unsigned		n_member;
	ndr_typeinfo_t		*ti;

	construct = construct_list;
	for (; construct; construct = construct->n_next) {
		ti = ndr_alloc(1, sizeof (ndr_typeinfo_t));

		ti->type_op = construct->label;
		ti->definition = construct;

		switch (ti->type_op) {
		case TYPEDEF_KW:
		case STRUCT_KW:
		case UNION_KW:
			ti->type_name = construct->n_c_typename;

			np = construct->n_c_members;
			n_member = 0;
			for (; np; np = np->n_next)
				n_member++;

			ti->n_member = n_member;
			if (n_member > 0)
				ti->member = ndr_alloc(n_member,
				    sizeof (ndr_member_t));
			break;

		default:
			fatal_error("seed_construct unknown %d\n", ti->type_op);
			break;
		}

		determine_advice(&ti->advice, construct->n_c_advice);

		ti->is_referenced = 1;	/* always generate */

		append_typeinfo(ti);
	}
}

static void
append_typeinfo(ndr_typeinfo_t *ti)
{
	ndr_typeinfo_t		**pp;

	for (pp = &typeinfo_list; *pp; pp = &(*pp)->next)
		;

	*pp = ti;
	ti->next = 0;
}

static ndr_typeinfo_t *
bind_typeinfo(ndr_typeinfo_t *proto_ti)
{
	ndr_typeinfo_t		*ti;
	ndr_typeinfo_t		*tdti = proto_ti->type_down;

	for (ti = typeinfo_list; ti; ti = ti->next) {
		if (ti->type_op != proto_ti->type_op)
			continue;

		switch (ti->type_op) {
		case STAR:
			if (ti->type_down != proto_ti->type_down)
				continue;
			break;

		case STRING_KW:
			if (ti->type_down != proto_ti->type_down)
				continue;
			break;

		case LB:
			if (ti->type_down != proto_ti->type_down)
				continue;
			if (ti->type_dim != proto_ti->type_dim)
				continue;
			break;

		case BASIC_TYPE:
		case STRUCT_KW:
		case TYPEDEF_KW:
		case UNION_KW:
			if (ti->type_name != proto_ti->type_name)
				continue;
			break;

		default:
			fatal_error("bind_typeinfo unknown %d\n", ti->type_op);
			break;
		}

		return (ti);
	}

	ti = ndr_alloc(1, sizeof (ndr_typeinfo_t));

	*ti = *proto_ti;
	append_typeinfo(ti);

	switch (ti->type_op) {
	case STAR:
		ti->size_fixed_part = 4;
		ti->alignment = 3;
		ti->complete = 1;
		ti->has_pointers = 1;
		break;

	case STRING_KW:
	case LB:
		if (tdti->complete) {
			ti->alignment = tdti->alignment;
			if (tdti->size_variable_part) {
				compile_error("array of var-size type");
			} else if (ti->type_dim) {
				ti->size_fixed_part = tdti->size_fixed_part *
				    ti->type_dim->n_int;
			} else {
				ti->size_variable_part = tdti->size_fixed_part;
				ti->is_conformant = 1;
			}
		} else {
			compile_error("array of incomplete type");
		}

		ti->has_pointers = tdti->has_pointers;
		ti->complete = 1;
		break;

	default:
		compile_error("bind_type internal error op=%d", ti->type_op);
		break;
	}

	/*
	 * Disallow
	 *	union foo	*ptrfoo;
	 * There is no way to pass the selector (switch_is)in
	 */
	if (ti->type_op == STAR && ti->type_down->type_op == UNION_KW) {
		compile_error("pointers to unions not allowed");
	}

	/*
	 * Disallow
	 *	union foo	fooarr[n];
	 * Each element needs a distinct selector
	 */
	if (ti->type_op == LB && ti->type_down->type_op == UNION_KW) {
		compile_error("arrays of unions not allowed");
	}

	return (ti);
}

static ndr_typeinfo_t *
find_typeinfo_by_name(ndr_node_t *typename)
{
	ndr_typeinfo_t		*ti;

	for (ti = typeinfo_list; ti; ti = ti->next) {
		if (ti->type_name == typename)
			return (ti);
	}

	compile_error("unknown type %s", typename->n_sym->name);

	/* fake BASIC_TYPE */
	ti = ndr_alloc(1, sizeof (ndr_typeinfo_t));
	ti->type_op = BASIC_TYPE;
	ti->definition = typename;
	ti->type_name = typename;
	ti->size_fixed_part = 0;
	ti->alignment = 0;

	append_typeinfo(ti);
	return (ti);
}

static void
determine_advice(ndr_advice_t *advice, ndr_node_t *advice_list)
{
	/* alias for basic types */
	advice->a_transmit_as = find_advice(advice_list, TRANSMIT_AS_KW);

	/* arg used for size, union, or generic purpose */
	advice->a_arg_is = find_advice(advice_list, ARG_IS_KW);

	/* operation parameter in/out stuff */
	advice->a_operation = find_advice(advice_list, OPERATION_KW);
	advice->a_in = find_advice(advice_list, IN_KW);
	advice->a_out = find_advice(advice_list, OUT_KW);

	/* size stuff */
	advice->a_string = find_advice(advice_list, STRING_KW);
	advice->a_size_is = find_advice(advice_list, SIZE_IS_KW);
	advice->a_length_is = find_advice(advice_list, LENGTH_IS_KW);

	/* union stuff */
	advice->a_case = find_advice(advice_list, CASE_KW);
	advice->a_default = find_advice(advice_list, DEFAULT_KW);
	advice->a_switch_is = find_advice(advice_list, SWITCH_IS_KW);

	/* interface stuff */
	advice->a_interface = find_advice(advice_list, INTERFACE_KW);
	advice->a_uuid = find_advice(advice_list, UUID_KW);
	advice->a_no_reorder = find_advice(advice_list, _NO_REORDER_KW);
	advice->a_extern = find_advice(advice_list, EXTERN_KW);

	advice->a_reference = find_advice(advice_list, REFERENCE_KW);
	advice->a_align = find_advice(advice_list, ALIGN_KW);
}

static ndr_node_t *
find_advice(ndr_node_t *advice_list, int label)
{
	ndr_node_t		*np;

	for (np = advice_list; np; np = np->n_next)
		if (np->label == label)
			break;

	return (np);
}

void
member_fixup(ndr_node_t *member_np)
{
	ndr_node_t		*np;

	for (np = member_np->n_m_decl; np; np = np->n_d_descend)
		if (np->label == IDENTIFIER)
			break;

	member_np->n_m_name = np;
}

void
construct_fixup(ndr_node_t *construct_np)
{
	construct_np->n_c_typename->n_sym->typedefn = construct_np;
}
