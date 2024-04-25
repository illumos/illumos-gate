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

/*
 * Copyright 2020 Tintri by DDN, Inc. All rights reserved.
 * Copyright 2024 OmniOS Community Edition (OmniOSce) Association.
 */

#include <string.h>
#include "ndrgen.h"
#include "y.tab.h"


static void generate_struct(ndr_typeinfo_t *);
static void generate_params(ndr_typeinfo_t *);
static void generate_union(ndr_typeinfo_t *);
static void generate_arg(ndr_node_t *);
static void generate_member_macro(char *, char *, ndr_member_t *,
    ndr_typeinfo_t *);
static void generate_member_macro_with_arg(char *, char *, ndr_member_t *,
    ndr_typeinfo_t *, ndr_node_t *);
static void generate_prototypes(ndr_typeinfo_t *, char *);
static void generate_member_prototypes(ndr_typeinfo_t *, ndr_member_t *,
    char *);
static void generate_member(ndr_typeinfo_t *, ndr_member_t *);
static void generate_aggregate_common_begin(ndr_typeinfo_t *);
static void generate_aggregate_common_finish(ndr_typeinfo_t *);
static void generate_typeinfo_packing(ndr_typeinfo_t *);
static void generate_typeinfo_typeinfo(ndr_typeinfo_t *, int, char *);


void
generate(void)
{
	ndr_typeinfo_t		*ti;
	char			fname_type[NDLBUFSZ];

	(void) printf("\n");

	for (ti = typeinfo_list; ti; ti = ti->next) {
		if (ti->is_extern || ti->advice.a_extern) {
			type_extern_suffix(ti, fname_type, NDLBUFSZ);
			(void) printf(
			    "extern struct ndr_typeinfo ndt_%s;\n",
			    fname_type);
			continue;
		}

		switch (ti->type_op) {
		case STRUCT_KW:
			if (ti->advice.a_operation)
				generate_params(ti);
			else
				generate_struct(ti);
			break;

		case UNION_KW:
			generate_union(ti);
			break;

		case TYPEDEF_KW:
			/* silently skip */
			continue;

		case STRING_KW:
		case STAR:
		case LB:
		case BASIC_TYPE:
			if (!ti->is_referenced) {
				type_extern_suffix(ti, fname_type, NDLBUFSZ);
				(void) printf("extern ndt_%s\n", fname_type);
				type_null_decl(ti, fname_type, NDLBUFSZ);
				(void) printf("/* %s */\n", fname_type);
			}
			break;

		default:
			continue;
		}
	}
}

static void
generate_struct(ndr_typeinfo_t *ti)
{
	int		i;
	ndr_member_t	*mem;

	if (ti->advice.a_no_reorder) {
		/* just use generate_params(), which can safely do this */
		generate_params(ti);
		return;
	}

	generate_aggregate_common_begin(ti);

	(void) printf("	/* do all basic elements first */\n");
	for (i = 0; i < ti->n_member; i++) {
		mem = &ti->member[i];
		if (mem->type->type_op != BASIC_TYPE)
			continue;

		generate_member(ti, mem);
	}

	(void) printf("\n");
	(void) printf("	/* do all constructed elements w/o pointers */\n");
	for (i = 0; i < ti->n_member; i++) {
		mem = &ti->member[i];
		if (mem->type->type_op == BASIC_TYPE)
			continue;

		if (mem->type->has_pointers)
			continue;

		generate_member(ti, mem);
	}

	(void) printf("\n");
	(void) printf("	/* do members with pointers in order */\n");
	for (i = 0; i < ti->n_member; i++) {
		mem = &ti->member[i];
		if (mem->type->type_op == BASIC_TYPE)
			continue;

		if (!mem->type->has_pointers)
			continue;

		generate_member(ti, mem);
	}

	generate_aggregate_common_finish(ti);
}

static void
generate_params(ndr_typeinfo_t *ti)
{
	int		i;
	ndr_member_t	*mem;

	generate_aggregate_common_begin(ti);

	(void) printf("	/* do all members in order */\n");
	for (i = 0; i < ti->n_member; i++) {
		mem = &ti->member[i];

		generate_member(ti, mem);
	}

	generate_aggregate_common_finish(ti);
}

static void
generate_union(ndr_typeinfo_t *ti)
{
	int		i;
	ndr_member_t	*mem;
	int		have_default = 0;
	ndr_node_t	*np;

	generate_aggregate_common_begin(ti);

	(void) printf("    switch (encl_ref->switch_is) {\n");

	for (i = 0; i < ti->n_member; i++) {
		mem = &ti->member[i];

		if ((np = mem->advice.a_case) != 0) {
			(void) printf("    case ");
			print_node(np->n_a_arg);
			(void) printf(":\n");
		} else if ((np = mem->advice.a_default) != 0) {
			(void) printf("    default:\n");
			if (have_default++) {
				compile_error("multiple defaults");
			}
		} else {
			compile_error("syntax error");
		}

		generate_member(ti, mem);
		(void) printf("	break;\n\n");
	}

	if (!have_default) {
		(void) printf("    default:\n");
		(void) printf("	NDR_SET_ERROR(encl_ref, "
		    "NDR_ERR_SWITCH_VALUE_INVALID);\n");
		(void) printf("	return 0;\n");
		(void) printf("	break;\n");
	}

	(void) printf("    }\n");
	(void) printf("\n");

	generate_aggregate_common_finish(ti);
}

static void
generate_arg(ndr_node_t *np)
{
	ndr_node_t	*arg = np;

	if (np == NULL) {
		compile_error("invalid node pointer <null>");
		return;
	}

	if (np->label != IDENTIFIER && np->label != INTEGER)
		arg = np->n_a_arg;

	switch (np->label) {
	case SIZE_IS_KW:
	case LENGTH_IS_KW:
	case SWITCH_IS_KW:
		(void) printf("val->");
		print_field_attr(np);
		break;
	default:
		if (arg->label == IDENTIFIER)
			(void) printf("val->%s", arg->n_sym->name);
		else
			print_node(arg);
		break;
	}
}

static void
generate_member_macro(char *memkind, char *macro, ndr_member_t *mem,
    ndr_typeinfo_t *ti)
{
	char	fname_type[NDLBUFSZ];

	if (!macro)
		macro = "";
	if (!ti)
		ti = mem->type;

	type_extern_suffix(ti, fname_type, NDLBUFSZ);

	if (memkind) {
		(void) printf("	NDR_%sMEMBER%s (%s, %s);\n",
		    memkind, macro, fname_type, mem->name);
	} else {
		(void) printf("	NDR_MEMBER%s (%s, %s, %uUL);\n",
		    macro, fname_type, mem->name, mem->pdu_offset);
	}
}

static void
generate_member_macro_with_arg(char *memkind, char *macro,
    ndr_member_t *mem, ndr_typeinfo_t *ti, ndr_node_t *np)
{
	char	fname_type[NDLBUFSZ];

	if (!macro)
		macro = "_WITH_ARG";
	if (!ti)
		ti = mem->type;

	type_extern_suffix(ti, fname_type, NDLBUFSZ);

	if (memkind) {
		(void) printf("	NDR_%sMEMBER%s (%s, %s,\n",
		    memkind, macro, fname_type, mem->name);
	} else {
		(void) printf("	NDR_MEMBER%s (%s, %s, %uUL,\n",
		    macro, fname_type, mem->name, mem->pdu_offset);
	}

	(void) printf("\t\t");
	generate_arg(np);
	(void) printf(");\n");
}

static void
generate_prototypes(ndr_typeinfo_t *ti, char *fname_type)
{
	ndr_member_t *mem;
	int i;

	if (ti->type_op == STRUCT_KW && ti->advice.a_operation) {
		for (i = 0; i < ti->n_member; i++) {
			mem = &ti->member[i];

			generate_member_prototypes(ti, mem, fname_type);
		}
	}
}

static void
generate_member_prototypes(ndr_typeinfo_t *ti,
    ndr_member_t *mem, char *fname_type)
{
	char val_buf[NDLBUFSZ];
	ndr_typeinfo_t ptr;

	if (mem->type->type_op == UNION_KW) {
		if (!mem->advice.a_in && mem->advice.a_out) {
			ptr.type_op = STAR;
			ptr.type_down = ti;
			type_name_decl(&ptr, val_buf, NDLBUFSZ, "val");

			(void) printf("\nextern void fixup%s(%s);\n",
			    fname_type, val_buf);
		}
	}
}

static void
generate_member(ndr_typeinfo_t *ti, ndr_member_t *mem)
{
	static char *fixup[] = {
		"/*",
		" * Cannot use the canned offsets to unmarshall multiple",
		" * entry discriminated unions.  The service must provide",
		" * this function to patch the offsets at runtime.",
		" */"
	};

	char		fname_type[NDLBUFSZ];
	ndr_node_t	*np;
	int		is_reference = 0;
	char		*memkind = 0;
	int		cond_pending = 0;
	int		i;

	if (ti->advice.a_operation)
		memkind = "TOPMOST_";
	else if (ti->advice.a_interface)
		memkind = "PARAMS_";

	if (mem->advice.a_in && !mem->advice.a_out) {
		cond_pending = 1;
		(void) printf("    if (NDR_DIR_IS_IN) {\n");
	}

	if (!mem->advice.a_in && mem->advice.a_out) {
		cond_pending = 1;
		(void) printf("    if (NDR_DIR_IS_OUT) {\n");
	}

	type_extern_suffix(ti, fname_type, NDLBUFSZ);

	switch (mem->type->type_op) {
	case BASIC_TYPE:
	case STRUCT_KW:
		generate_member_macro(memkind, 0, mem, 0);
		break;

	case UNION_KW:
		np = mem->advice.a_switch_is;

		if (!mem->advice.a_in && mem->advice.a_out) {
			for (i = 0; i < sizeof (fixup)/sizeof (fixup[0]); ++i)
				(void) printf("\t%s\n", fixup[i]);

			(void) printf("\tfixup%s(val);\n", fname_type);
		}

		generate_member_macro_with_arg(memkind,
		    "_WITH_SWITCH_IS", mem, 0, np);
		break;

	case STAR:
		if (mem->advice.a_reference)
			is_reference = 1;
		else
			is_reference = 0;

		np = mem->advice.a_size_is;
		if (np) {
			generate_member_macro_with_arg(memkind,
			    is_reference ?
			    "_REF_WITH_SIZE_IS" : "_PTR_WITH_SIZE_IS",
			    mem, mem->type->type_down, np);
			break;
		}

		np = mem->advice.a_length_is;
		if (np) {
			generate_member_macro_with_arg(memkind,
			    is_reference ?
			    "_REF_WITH_LENGTH_IS" : "_PTR_WITH_LENGTH_IS",
			    mem, mem->type->type_down, np);
			break;
		}

		generate_member_macro(memkind,
		    is_reference ? "_REF" : "_PTR",
		    mem, mem->type->type_down);
		break;

	case LB:
		np = mem->advice.a_size_is;
		if (np) {
			generate_member_macro_with_arg(memkind,
			    "_ARR_WITH_SIZE_IS",
			    mem, mem->type->type_down, np);
			break;
		}

		np = mem->advice.a_length_is;
		if (np) {
			generate_member_macro_with_arg(memkind,
			    "_WITH_LENGTH_IS",
			    mem, mem->type->type_down, np);
			break;
		}

		generate_member_macro_with_arg(memkind,
		    "_ARR_WITH_DIMENSION",
		    mem, mem->type->type_down, mem->type->type_dim);
		break;

	default:
		generate_member_macro(memkind, "_???", mem, 0);
		break;
	}

	if (cond_pending)
		(void) printf("    }\n");
}

static void
generate_aggregate_common_begin(ndr_typeinfo_t *ti)
{
	char			val_buf[NDLBUFSZ];
	char			cast_buf[NDLBUFSZ];
	char			fname_type[NDLBUFSZ];
	ndr_typeinfo_t		ptr;

	type_extern_suffix(ti, fname_type, NDLBUFSZ);
	generate_typeinfo_typeinfo(ti, 0, fname_type);
	generate_prototypes(ti, fname_type);

	(void) printf("\n");
	(void) printf("/*\n * ");
	show_advice(&ti->advice, 0);
	(void) printf(" */\n");
	(void) printf("int\n");
	(void) printf("ndr_%s (struct ndr_reference *encl_ref)\n",
	    fname_type);
	(void) printf("{\n");

	ptr.type_op = STAR;
	ptr.type_down = ti;

	type_name_decl(&ptr, val_buf, NDLBUFSZ, "val");
	type_null_decl(&ptr, cast_buf, NDLBUFSZ);

	(void) printf("	%s = %s encl_ref->datum;\n", val_buf, cast_buf);

	(void) printf("	struct ndr_reference myref;\n");
	(void) printf("\n");
	(void) printf("	(void) bzero(&myref, sizeof (myref));\n");
	(void) printf("	myref.enclosing = encl_ref;\n");
	(void) printf("	myref.stream = encl_ref->stream;\n");
	generate_typeinfo_packing(ti);
	(void) printf("\n");
}

/* ARGSUSED */
static void
generate_aggregate_common_finish(ndr_typeinfo_t *ti)
{
	(void) printf("\n");
	(void) printf("	return 1;\n");
	(void) printf("}\n");
}

/*
 * Structures are normally 4-byte (dword) aligned but the align directive
 * can be used to pack on a 2-byte (word) boundary.  An align value of
 * zero is taken to mean use default (dword) alignment.  Default packing
 * doesn't need to be flagged.
 */
static void
generate_typeinfo_packing(ndr_typeinfo_t *ti)
{
	ndr_node_t *np;
	unsigned long packing;

	if ((np = ti->advice.a_align) == NULL)
		return;

	if ((np = np->n_a_arg) == NULL)
		return;

	packing = np->n_int;
	if ((packing == 0) || (packing == 4)) {
		/* default alignment */
		return;
	}

	if (packing != 2) {
		fatal_error("invalid align directive: %lu", packing);
		/* NOTREACHED */
	}

	(void) printf("	myref.packed_alignment = %lu;\n", packing);
}

static void
generate_typeinfo_typeinfo(ndr_typeinfo_t *ti, int is_static, char *fname_type)
{
	char		flags[NDLBUFSZ];

	*flags = 0;
	if (ti->is_conformant)
		(void) strlcat(flags, "|NDR_F_CONFORMANT", NDLBUFSZ);

	if (ti->advice.a_fake)
		(void) strlcat(flags, "|NDR_F_FAKE", NDLBUFSZ);

	if (ti->type_op == STRUCT_KW) {
		if (ti->advice.a_operation)
			(void) strlcat(flags, "|NDR_F_OPERATION", NDLBUFSZ);
		else
			(void) strlcat(flags, "|NDR_F_STRUCT", NDLBUFSZ);
	}

	if (ti->type_op == UNION_KW) {
		if (ti->advice.a_interface)
			(void) strlcat(flags, "|NDR_F_INTERFACE", NDLBUFSZ);
		else
			(void) strlcat(flags, "|NDR_F_UNION", NDLBUFSZ);
	}

	if (ti->type_op == STRING_KW)
		(void) strlcat(flags, "|NDR_F_STRING", NDLBUFSZ);
	if (ti->type_op == LB)
		(void) strlcat(flags, "|NDR_F_ARRAY", NDLBUFSZ);
	if (ti->type_op == STAR)
		(void) strlcat(flags, "|NDR_F_POINTER", NDLBUFSZ);

	if (*flags == 0)
		(void) strlcpy(flags, "NDR_F_NONE", NDLBUFSZ);
	else
		(void) memmove(flags, flags + 1, NDLBUFSZ - 1);

	(void) printf("\n\n\n");
	if (is_static)
		(void) printf("static ");

	(void) printf("int ndr_%s (struct ndr_reference *encl_ref);\n",
	    fname_type);
	if (is_static)
		(void) printf("static ");

	(void) printf("struct ndr_typeinfo ndt_%s = {\n", fname_type);
	(void) printf("\t1,		/* NDR version */\n");
	(void) printf("\t%d,		/* alignment */\n", ti->alignment);
	(void) printf("\t%s,	/* flags */\n", flags);
	(void) printf("\tndr_%s,	/* ndr_func */\n", fname_type);
	(void) printf("\t%d,		/* pdu_size_fixed_part */\n",
	    ti->size_fixed_part);
	(void) printf("\t%d,		/* pdu_size_variable_part */\n",
	    ti->size_variable_part);

	(void) printf("\t%d,		/* c_size_fixed_part */\n",
	    ti->size_fixed_part);
	(void) printf("\t%d,		/* c_size_variable_part */\n",
	    ti->size_variable_part);
	(void) printf("};\n\n");
}
