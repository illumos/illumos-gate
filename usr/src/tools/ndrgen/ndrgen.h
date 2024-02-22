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
 */

#ifndef _NDRGEN_H
#define	_NDRGEN_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

typedef struct node {
	int		label;
	int		line_number;
	struct symbol	*file_name;
	struct node	*n_next;		/* handy for lists */

	union {
		struct symbol		*nu_sym;
		unsigned long		nu_int;
		char			*nu_str;
		void			*nu_ptr;
		struct node		*nu_node[4];	/* descendents */
		void			*nu_arg[4];	/* utility */
	}	n_u;
#define	n_ptr n_u.nu_ptr
#define	n_sym n_u.nu_sym
#define	n_str n_u.nu_str
#define	n_int n_u.nu_int
#define	n_arg n_u.nu_arg
#define	n_node n_u.nu_node

#define	n_c_advice	n_node[0]
#define	n_c_typename	n_node[1]
#define	n_c_members	n_node[2]

#define	n_m_advice	n_node[0]
#define	n_m_type	n_node[1]
#define	n_m_decl	n_node[2]
#define	n_m_name	n_node[3]

#define	n_a_arg		n_node[0]
#define	n_a_arg1	n_node[1]
#define	n_a_arg2	n_node[2]

#define	n_d_descend	n_node[0]
#define	n_d_dim		n_node[1]
} ndr_node_t;

typedef struct keyword {
	char		*name;
	int		token;
	long		value;
} ndr_keyword_t;

typedef struct symbol {
	struct symbol	*next;
	char		*name;
	ndr_keyword_t	*kw;
	struct node	*typedefn;
	struct node	s_node;
} ndr_symbol_t;

typedef struct integer {
	struct integer	*next;
	long		value;
	struct node	s_node;
} ndr_integer_t;

#define	NDLBUFSZ	100

/* This makes certain things much easier */
#define	N_ADVICE	19

typedef struct advice {
	struct node		*a_nodes[N_ADVICE];

/* alias for basic types */
#define	a_transmit_as	a_nodes[0]

/* arg used for size, union or generic purpose */
#define	a_arg_is	a_nodes[1]

/* operation parameter in/out stuff */
#define	a_operation	a_nodes[2]
#define	a_in		a_nodes[3]
#define	a_out		a_nodes[4]

/* size stuff */
#define	a_string	a_nodes[5]
#define	a_size_is	a_nodes[6]
#define	a_length_is	a_nodes[7]

/* union stuff */
#define	a_case		a_nodes[8]
#define	a_default	a_nodes[9]
#define	a_switch_is	a_nodes[10]

/* interface stuff */
#define	a_interface	a_nodes[11]
#define	a_uuid		a_nodes[12]
#define	a_no_reorder	a_nodes[13]
#define	a_extern	a_nodes[14]
#define	a_reference	a_nodes[15]
#define	a_align		a_nodes[16]
#define	a_fake		a_nodes[17]
} ndr_advice_t;

typedef struct typeinfo {
	struct typeinfo		*next;

	unsigned int		alignment	: 3;	/* mask */
	unsigned int		is_conformant	: 1;
	unsigned int		is_varying	: 1;
	unsigned int		is_string	: 1;
	unsigned int		max_given	: 1;
	unsigned int		min_given	: 1;
	unsigned int		complete	: 1;
	unsigned int		has_pointers	: 1;
	unsigned int		is_referenced	: 1;
	unsigned int		is_extern	: 1;

	unsigned short		type_op;	/* STAR LB */
						/* STRUCT BASIC_TYPE */
	struct node		*type_dim;	/* for LB */
	struct typeinfo		*type_down;	/* for STAR LB */
	struct node		*definition;
	struct node		*type_name;	/* symbol */
	ndr_advice_t		advice;
	unsigned int		size_fixed_part;
	unsigned int		size_variable_part;

	/* size_is(n_members) */
	struct member		*member;		/* array */
	int			n_member;
} ndr_typeinfo_t;

typedef struct member {
	char			*name;
	struct typeinfo		*type;
	int			is_conformant;
	struct node		*definition;
	ndr_advice_t		advice;
	unsigned int		pdu_offset;
} ndr_member_t;

extern ndr_typeinfo_t	*typeinfo_list;
extern struct node	*construct_list;

/* ndr_anal.c */
extern void	analyze(void);
extern void	show_typeinfo_list(void);
extern void	type_extern_suffix(ndr_typeinfo_t *, char *, size_t);
extern void	type_null_decl(ndr_typeinfo_t *, char *, size_t);
extern void	type_name_decl(ndr_typeinfo_t *, char *, size_t, char *);
extern void	show_advice(ndr_advice_t *, int);
extern void	member_fixup(ndr_node_t *);
extern void	construct_fixup(ndr_node_t *);

/* ndr_gen.c */
extern void	generate(void);

/* ndr_lex.c */
extern ndr_symbol_t	*symbol_list;
extern int		line_number;
extern int		n_compile_error;
extern struct node	*yylval;
extern void		set_lex_input(FILE *, char *);
extern int		yylex(void);
extern void *		ndr_alloc(size_t nelem, size_t elsize);
extern void		compile_error(const char *, ...);
extern void		fatal_error(const char *, ...);
extern struct node	*n_cons(int, ...);
extern void		n_splice(struct node *, struct node *);

/* ndr_print.c */
extern void	tdata_dump(void);
extern void	print_node(ndr_node_t *);
extern void	print_field_attr(ndr_node_t *);

/* ndr_parse.y */
extern int	yyparse(void);

/* ndr_main.c */
extern int	yyerror(const char *);

#ifdef __cplusplus
}
#endif

#endif /* _NDRGEN_H */
