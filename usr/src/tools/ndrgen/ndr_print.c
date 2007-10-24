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

#include "ndrgen.h"
#include "y.tab.h"


static void print_declaration(ndr_node_t *);
static void print_advice_list(ndr_node_t *);
static void print_node_list(ndr_node_t *);


void
tdata_dump(void)
{
	print_node_list(construct_list);
}

void
print_node(ndr_node_t *np)
{
	char		*nm;

	if (!np) {
		(void) printf("<null>");
		return;
	}

	switch (np->label) {
	case ALIGN_KW:		nm = "align";		break;
	case STRUCT_KW:		nm = "struct";		break;
	case UNION_KW:		nm = "union";		break;
	case TYPEDEF_KW:	nm = "typedef";		break;
	case INTERFACE_KW:	nm = "interface";	break;
	case IN_KW:		nm = "in";		break;
	case OUT_KW:		nm = "out";		break;
	case SIZE_IS_KW:	nm = "size_is";		break;
	case LENGTH_IS_KW:	nm = "length_is";	break;
	case STRING_KW:		nm = "string";		break;
	case TRANSMIT_AS_KW:	nm = "transmit_as";	break;
	case OPERATION_KW:	nm = "operation";	break;
	case UUID_KW:		nm = "uuid";		break;
	case _NO_REORDER_KW:	nm = "_no_reorder";	break;
	case EXTERN_KW:		nm = "extern";		break;
	case ARG_IS_KW:		nm = "arg_is";		break;
	case CASE_KW:		nm = "case";		break;
	case DEFAULT_KW:	nm = "default";		break;
	case BASIC_TYPE:	nm = "<btype>";		break;
	case TYPENAME:		nm = "<tname>";		break;
	case IDENTIFIER:	nm = "<ident>";		break;
	case INTEGER:		nm = "<intg>";		break;
	case STRING:		nm = "<string>";	break;
	case STAR:		nm = "<*>";		break;
	case LB:		nm = "<[>";		break;
	case LP:		nm = "<(>";		break;
	case L_MEMBER:		nm = "<member>";	break;
	default:
		(void) printf("<<lab=%d>>", np->label);
		return;
	}

	switch (np->label) {
	case STRUCT_KW:
	case UNION_KW:
	case TYPEDEF_KW:
		(void) printf("\n");
		if (np->n_c_advice) {
			print_advice_list(np->n_c_advice);
			(void) printf("\n");
		}
		(void) printf("%s ", nm);
		print_node(np->n_c_typename);
		(void) printf(" {\n");
		print_node_list(np->n_c_members);
		(void) printf("};\n");
		break;

	case IN_KW:
	case OUT_KW:
	case STRING_KW:
	case DEFAULT_KW:
	case _NO_REORDER_KW:
	case EXTERN_KW:
		(void) printf("%s", nm);
		break;

	case ALIGN_KW:
		/*
		 * Don't output anything for default alignment.
		 */
		if ((np->n_a_arg == NULL) || (np->n_a_arg->n_int == 0))
			break;
		(void) printf("%s(", nm);
		print_node(np->n_a_arg);
		(void) printf(")");
		break;

	case INTERFACE_KW:
	case SIZE_IS_KW:
	case LENGTH_IS_KW:
	case TRANSMIT_AS_KW:
	case ARG_IS_KW:
	case CASE_KW:
	case OPERATION_KW:
	case UUID_KW:
		(void) printf("%s(", nm);
		print_node(np->n_a_arg);
		(void) printf(")");
		break;

	case BASIC_TYPE:
	case TYPENAME:
	case IDENTIFIER:
		(void) printf("%s", np->n_sym->name);
		break;

	case INTEGER:
		(void) printf("%ld", np->n_int);
		break;

	case STRING:
		(void) printf("\"%s\"", np->n_str);
		break;

	case STAR:
		(void) printf("*");
		print_node(np->n_d_descend);
		break;

	case LB:
		print_node(np->n_d_descend);
		(void) printf("[");
		if (np->n_d_dim)
			print_node(np->n_d_dim);
		(void) printf("]");
		break;

	case LP:
		(void) printf("(");
		print_node(np->n_d_descend);
		(void) printf(")");
		break;

	case L_MEMBER:
		if (np->n_m_advice) {
			(void) printf("    ");
			print_advice_list(np->n_m_advice);
			(void) printf("\n");
		}
		(void) printf("\t");
		print_declaration(np);
		(void) printf(";\n");
		break;

	default:
		return;
	}
}

static void
print_declaration(ndr_node_t *np)
{
	ndr_node_t	*dnp = np->n_m_decl;
	char		buf[NDLBUFSZ];
	char		*p = buf;

	if (np->n_m_type &&
	    (np->n_m_type->label == IDENTIFIER ||
	    np->n_m_type->label == TYPENAME)) {
		(void) snprintf(buf, NDLBUFSZ, "%s", np->n_m_type->n_sym->name);

		while (*p)
			p++;

		if (dnp && dnp->label == STAR) {
			*p++ = ' ';
			while (dnp && dnp->label == STAR) {
				*p++ = '*';
				dnp = dnp->n_d_descend;
			}
		}
		*p = 0;
		(void) printf("%-23s ", buf);
	} else {
		print_node(np->n_m_type);
		(void) printf(" ");
	}

	print_node(dnp);
}

static void
print_advice_list(ndr_node_t *np)
{
	if (!np)
		return;

	(void) printf("[");
	for (; np; np = np->n_next) {
		print_node(np);
		if (np->n_next)
			(void) printf(" ");
	}
	(void) printf("]");
}

static void
print_node_list(ndr_node_t *np)
{
	for (; np; np = np->n_next) {
		print_node(np);
	}
}
