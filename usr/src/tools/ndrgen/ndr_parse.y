%{
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

#include "ndrgen.h"

typedef struct node *node_ptr;
#define YYSTYPE node_ptr
%}

/* keywords */
%token STRUCT_KW UNION_KW TYPEDEF_KW

/* advice keywords */
%token ALIGN_KW OPERATION_KW IN_KW OUT_KW
%token INTERFACE_KW UUID_KW _NO_REORDER_KW EXTERN_KW
%token SIZE_IS_KW LENGTH_IS_KW STRING_KW REFERENCE_KW
%token CASE_KW DEFAULT_KW SWITCH_IS_KW
%token TRANSMIT_AS_KW ARG_IS_KW FAKE_KW

/* composite keywords */
%token BASIC_TYPE TYPENAME

/* symbols and punctuation */
%token IDENTIFIER INTEGER STRING
%token LC RC SEMI STAR DIV MOD PLUS MINUS AND OR XOR LB RB LP RP


%token L_MEMBER


%%

defn	:	/* empty */
	|	construct_list	{ construct_list = (struct node *)$1; }
	;

construct_list:	construct
	|	construct_list construct { n_splice ($1,$2); }
	;

construct:	struct
	|	union
	|	typedef
	;

struct	:	advice STRUCT_KW typename LC members RC SEMI
		{ $$ = n_cons (STRUCT_KW, $1, $3, $5);
		   construct_fixup ($$);
		}
	;

union	:	advice UNION_KW typename LC members RC SEMI
		{ $$ = n_cons (UNION_KW, $1, $3, $5);
		   construct_fixup ($$);
		}
	;

typedef	:	TYPEDEF_KW member
		{ $$ = n_cons (TYPEDEF_KW, 0, $2->n_m_name, $2);
		   construct_fixup ($$);
		}
	;

members	:	member
	|	members member		 { n_splice ($1,$2); }
	;

member	:	advice type declarator SEMI
		{ $$ = n_cons (L_MEMBER, $1, $2, $3);
		   member_fixup ($$);
		}
	;

advice	:	/* empty */		{ $$ = 0; }
	|	adv_list
	;

adv_list:	LB adv_attrs RB		{ $$ = $2; }
	|	adv_list LB adv_attrs RB { n_splice ($1,$3); }
	;

adv_attrs:	adv_attr
	|	adv_attr adv_attr	{ n_splice ($1,$2); }
	;

adv_attr:	IN_KW			{ $$ = n_cons (IN_KW); }
	|	OUT_KW			{ $$ = n_cons (OUT_KW); }
	|	OPERATION_KW LP arg RP	{ $$ = n_cons (OPERATION_KW, $3); }
	|	ALIGN_KW LP arg RP	{ $$ = n_cons (ALIGN_KW, $3); }
	|	STRING_KW		{ $$ = n_cons (STRING_KW); }
	|	FAKE_KW			{ $$ = n_cons (FAKE_KW); }

	|	SIZE_IS_KW LP arg RP
				{ $$ = n_cons (SIZE_IS_KW, $3, $3, $3); }
	|	SIZE_IS_KW LP arg operator INTEGER RP
				{ $$ = n_cons (SIZE_IS_KW, $3, $4, $5); }

	|	LENGTH_IS_KW LP arg RP
				{ $$ = n_cons (LENGTH_IS_KW, $3, $3, $3); }
	|	LENGTH_IS_KW LP arg operator INTEGER RP
				{ $$ = n_cons (LENGTH_IS_KW, $3, $4, $5); }

	|	SWITCH_IS_KW LP arg RP
				{ $$ = n_cons (SWITCH_IS_KW, $3, $3, $3); }
	|	SWITCH_IS_KW LP arg operator INTEGER RP
				{ $$ = n_cons (SWITCH_IS_KW, $3, $4, $5); }

	|	CASE_KW LP arg RP	{ $$ = n_cons (CASE_KW, $3); }
	|	DEFAULT_KW		{ $$ = n_cons (DEFAULT_KW); }

	|	ARG_IS_KW LP arg RP	{ $$ = n_cons (ARG_IS_KW, $3); }
	|	TRANSMIT_AS_KW LP BASIC_TYPE RP
					{ $$ = n_cons (TRANSMIT_AS_KW, $3); }

	|	INTERFACE_KW LP arg RP	{ $$ = n_cons (INTERFACE_KW, $3); }
	|	UUID_KW LP arg RP	{ $$ = n_cons (UUID_KW, $3); }
	|	_NO_REORDER_KW		{ $$ = n_cons (_NO_REORDER_KW); }
	|	EXTERN_KW		{ $$ = n_cons (EXTERN_KW); }
	|	REFERENCE_KW		{ $$ = n_cons (REFERENCE_KW); }
	;

arg	:	IDENTIFIER
	|	INTEGER
	|	STRING
	;

type	:	BASIC_TYPE
	|	typename
	|	STRUCT_KW typename	{ $$ = $2; }
	|	UNION_KW  typename	{ $$ = $2; }
	;

typename:	TYPENAME
	|	IDENTIFIER
	;

operator:	STAR
	|	DIV
	|	MOD
	|	PLUS
	|	MINUS
	|	AND
	|	OR
	|	XOR
	;

declarator:	decl1
	;

decl1	:	decl2
	|	STAR decl1		{ $$ = n_cons (STAR, $2); }
	;

decl2	:	decl3
	|	decl3 LB RB		{ $$ = n_cons (LB, $1, 0); }
	|	decl3 LB STAR RB	{ $$ = n_cons (LB, $1, 0); }
	|	decl3 LB INTEGER RB	{ $$ = n_cons (LB, $1, $3); }
	;

decl3	:	IDENTIFIER
	|	LP decl1 RP		{ $$ = n_cons (LP, $2); }
	;



%%
