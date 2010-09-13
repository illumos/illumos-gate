%{
/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 *
 * Copyright (c) 1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <libintl.h>
#include <errno.h>

#include "iconv_tm.h"
#include "itmcomp.h"
#include "itm_util.h"

%}

%start itm_def

%union		yystacktype
{
	int		intval;

	itm_num_t	num;
	itm_data_t	*name;
	itm_data_t	*data;

	itm_tbl_hdr_t	*tbl_hdr;
	itm_direc_t	*direc_unit;
	itm_expr_t	*expr;

	itmc_action_t	action;
	itmc_obj_t	*obj;
	itmc_map_t	*map_list;
	itmc_ref_t	*itmc_ref;
	itmc_map_attr_t	*map_attr;
}

%type <intval>		itm_def
%type <obj>		def_element_list
%type <tbl_hdr>		def_element

%type <tbl_hdr>		direction
%type <obj>		direction_unit_list
%type <obj>		direction_unit

%type <action>		action

%type <itmc_ref>	condition
%type <obj>		condition_list
%type <obj>		condition_expr

%type <obj>		range_list
%type <obj>		range_pair

%type <obj>		escseq_list
%type <obj>		escseq

%type <tbl_hdr>		map
%type <map_list>	map_list
%type <map_list>	map_pair
%type <map_attr>	map_attribute
%type <intval>		map_resultlen
%type <map_attr>	map_type
%type <name>		map_type_names

%type <tbl_hdr>		operation
%type <obj>		op_list
%type <obj>		op_unit
%type <obj>		op_if_else

%type <data>		name

%type <expr>		expr
%type <expr>		itm_in

%token	<name> ITMNAME
%token	<name> NAME
%token	<name> MAPTYPE_NAME
%token	<data> HEXADECIMAL
%token	<num>  DECIMAL

%token ITM_DEFAULT
%token ITM_IDENTICAL

%token BETWEEN
%token BREAK
%token CONDITION
%token DIRECTION
%token DISCARD
%token ERROR
%token ITM_ELSE
%token ITM_INIT
%token ITM_FALSE
%token ITM_IF
%token ITM_IN
%token ITM_INSIZE
%token NOP
%token OPERATION
%token ITM_OUT
%token ITM_OUTSIZE
%token PRINTCHR
%token PRINTHD
%token PRINTINT
%token MAP
%token RESET
%token RETURN
%token ITM_TRUE
%token ESCAPESEQ
%token MAPTYPE
%token RESULTLEN


%token MAPTYPE_AUTO
%token MAPTYPE_INDEX
%token MAPTYPE_DENSE
%token MAPTYPE_HASH
%token MAPTYPE_BINARY

%token ELLIPSES
%token CBO CBC
%token SBO SBC
%token PO PC
%token SC
%token COMMA
%token COLON

%right ASSIGN 
%left LOR
%left LAND
%left OR
%left XOR
%left AND
%left EQ NE
%left LT LE GT GE
%left SHL SHR
%left PLUS MINUS
%left MUL DIV MOD
%right NOT NEG UMINUS

%%

itm_def
	: ITMNAME CBO def_element_list CBC
	{
		itm_def_process($1);
	}
	;

def_element_list
	: def_element SC
	{
		TRACE_MESSAGE('y', ("def_element_list: def_element ;\n"));
		$$ = NULL;
	}
	| def_element_list def_element SC
	{
		TRACE_MESSAGE('y',
			("def_element_list: def_element_list def_element ;\n"));
		$$ = NULL;
	}
	;

def_element
	: direction
	{
		TRACE_MESSAGE('y', ("def_element: direction\n"));
		(void) obj_register(ITMC_OBJ_DIREC, (itm_data_t *)($1->name.itm_ptr),
			$1, $1->size,
			NULL, OBJ_REG_TAIL);
		$$ = $1;
	}
	| condition
	{
		TRACE_MESSAGE('y', ("def_element: condition\n"));
		$$ = (itm_tbl_hdr_t *)($1->referencee);
	}
	| map
	{
		TRACE_MESSAGE('y', ("def_element: map\n"));
		if (NULL != $1) {
			(void) obj_register(ITMC_OBJ_MAP,
				(itm_data_t *)($1->name.itm_ptr),
				$1, $1->size,
				NULL, OBJ_REG_TAIL);
	}
		$$ = $1;
	}
	| operation
	{
		TRACE_MESSAGE('y', ("def_element: operation\n"));
		(void) obj_register(ITMC_OBJ_OP, (itm_data_t *)($1->name.itm_ptr),
			$1, $1->size,
			NULL, OBJ_REG_TAIL);
		$$ = $1;
	}
	;

direction
	: DIRECTION name CBO direction_unit_list CBC
	{
		TRACE_MESSAGE('y', ("direction name (direction_unit_list)\n"));
		$$ = obj_table(ITM_TBL_DIREC, $2,
			$4, sizeof (itm_direc_t));
	}
	| DIRECTION CBO direction_unit_list CBC
	{
		TRACE_MESSAGE('y', ("direction name (direction_unit_list)\n"));
		$$ = obj_table(ITM_TBL_DIREC, NULL,
			$3, sizeof (itm_direc_t));
	}
	;

direction_unit_list
	: direction_unit
	{
		TRACE_MESSAGE('y', ("direction_unit_list: direction_unit\n"));
		$$ = obj_list_append(NULL, $1);
	}
	| direction_unit_list direction_unit
	{
		TRACE_MESSAGE('y', ("direction_unit_list: "
			"direction_unit_list direction_unit\n"));
		$$ = obj_list_append($1, $2);
	}
	;

direction_unit
	: condition action SC
	{
		TRACE_MESSAGE('y', ("direction_unit: condition action ;\n"));
		$$ = direction_unit($1, NULL, &($2), NULL);
	}
	| condition name SC
	{
		itm_direc_t	*direc;
		TRACE_MESSAGE('y', ("direction_unit: condition NAME ;\n"));
		$$ = direction_unit($1, NULL, NULL, $2);
	}
	| name action SC
	{
		itm_direc_t	*direc;
		TRACE_MESSAGE('y', ("direction_unit: NAME action ;\n"));
		$$ = direction_unit(NULL, $1, &($2), NULL);
	}
	| name name SC
	{
		itm_direc_t	*direc;
		TRACE_MESSAGE('y', ("direction_unit: NAME NAME ;\n"));
		$$ = direction_unit(NULL, $1, NULL, $2);
	}
	| ITM_TRUE action SC
	{
		itm_direc_t	*direc;
		$$ = direction_unit(NULL, NULL, &($2), NULL);
	}
	| ITM_TRUE name SC
	{
		itm_direc_t	*direc;
		TRACE_MESSAGE('y', ("direction_unit: TRUE NAME ;\n"));
		$$ = direction_unit(NULL, NULL, NULL, $2);
	}
	;

action
	: direction
	{
		TRACE_MESSAGE('y', ("action: direction\n"));
		$$.type = ITMC_OBJ_DIREC;
		$$.tbl_hdr = $1;
	}
	| map
	{
		TRACE_MESSAGE('y', ("action: map\n"));
		$$.type = ITMC_OBJ_MAP;
		$$.tbl_hdr = $1;
	}
	| operation
	{
		TRACE_MESSAGE('y', ("action: operation\n"));
		$$.type = ITMC_OBJ_OP;
		$$.tbl_hdr = $1;
	}
	;

condition
	: CONDITION name CBO condition_list CBC
	{
		itm_tbl_hdr_t	*tbl_hdr;
		TRACE_MESSAGE('y', ("condition\n"));
		tbl_hdr = obj_table(ITM_TBL_COND, $2,
				    $4, sizeof (itm_cond_t));
		$$ = obj_register(ITMC_OBJ_COND, $2,
				tbl_hdr, tbl_hdr->size,
				NULL, OBJ_REG_TAIL);
	}
	| CONDITION CBO condition_list CBC
	{
		itm_tbl_hdr_t	*tbl_hdr;
		TRACE_MESSAGE('y', ("condition\n"));
		tbl_hdr = obj_table(ITM_TBL_COND, NULL,
				    $3, sizeof (itm_cond_t));
		$$ = obj_register(ITMC_OBJ_COND, NULL,
				tbl_hdr, tbl_hdr->size,
				NULL, OBJ_REG_TAIL);
	}
	;

condition_list
	: condition_expr SC
	{
		TRACE_MESSAGE('y', ("condition_list: condition_expr;\n"));
		$$ = obj_list_append(NULL, $1);
	}
	| condition_list condition_expr SC
	{
		TRACE_MESSAGE('y', ("condition_list: "
			"condition_list condition_expr;\n"));
		$$ = obj_list_append($1, $2);
	}
	;

condition_expr
	: BETWEEN range_list
	{
		itm_tbl_hdr_t	*range;
		itm_cond_t	*cond;
		TRACE_MESSAGE('y', ("condition_expr: between\n"));
		range = range_table(NULL, $2);
		if (range == NULL) {
			$$ = NULL;
		} else {
			$$ = malloc_vital(sizeof (itmc_obj_t));
			$$->type = ITMC_OBJ_RANGE;
			$$->name = NULL;
			cond = malloc_vital(sizeof (itm_cond_t));
			$$->obj = cond;
			cond->type = ITM_COND_BETWEEN;
			cond->operand.place.itm_ptr = (itm_place2_t)range;
			$$->ref[0] = obj_register(ITMC_OBJ_RANGE, NULL,
					range, range->size,
					&(cond->operand.place),
					OBJ_REG_TAIL);
			$$->ref[1] = NULL;
			$$->ref[2] = NULL;
			$$->next = $$->last = NULL;
		}
	}
	| expr
	{
		itm_cond_t	*cond;
		TRACE_MESSAGE('y', ("condition_expr: expr\n"));
		$$ = malloc_vital(sizeof (itmc_obj_t));
		$$->type = ITMC_OBJ_EXPR;
		$$->name = NULL;
		cond = malloc_vital(sizeof (itm_cond_t));
		$$->obj = cond;
		cond->type = ITM_COND_EXPR;
		cond->operand.place.itm_ptr = (itm_place2_t)($1);
		$$->ref[0] = obj_register(ITMC_OBJ_EXPR, NULL,
					$1, sizeof (itm_expr_t),
					&(cond->operand.place),
					OBJ_REG_TAIL);
		$$->ref[1] = NULL;
		$$->ref[2] = NULL;
		$$->next = $$->last = NULL;
	}
	| ESCAPESEQ escseq_list
	{
		itm_tbl_hdr_t	*escseq;
		itm_cond_t	*cond;
		TRACE_MESSAGE('y', ("condition_expr:  escseq {escseq_list;}\n"));
		escseq = escseq_table(NULL, $2);
		if (escseq == NULL) {
			$$ = NULL;
		} else {
			$$ = malloc_vital(sizeof (itmc_obj_t));
			$$->type = ITMC_OBJ_ESCAPESEQ;
			$$->name = NULL;
			cond = malloc_vital(sizeof (itm_cond_t));
			$$->obj = cond;
			cond->type = ITM_COND_ESCAPESEQ;
			cond->operand.place.itm_ptr = (itm_place2_t)escseq;
			$$->ref[0] = obj_register(ITMC_OBJ_ESCAPESEQ, NULL,
					escseq, escseq->size,
					&(cond->operand.place),
					OBJ_REG_TAIL);
			$$->ref[1] = NULL;
			$$->ref[2] = NULL;
			$$->next = $$->last = NULL;
		}
	}
	;

range_list
	: range_pair
	{
		TRACE_MESSAGE('y', ("range_list: range_pair\n"));
		$$ = obj_list_append(NULL, $1);
	}
	| range_list COMMA range_pair
	{
		TRACE_MESSAGE('y', ("range_list: range_list, range_pair\n"));
		$$ = obj_list_append($1, $3);
	}
	;

range_pair
	: HEXADECIMAL ELLIPSES HEXADECIMAL
	{
		itmc_data_pair_t	*range;
		TRACE_MESSAGE('y', ("range_pair: HEXADECIMAL...HEXADECIMAL\n"));
		$$ = malloc_vital(sizeof (itmc_obj_t));
		$$->type = ITMC_OBJ_RANGE;
		$$->name = NULL;
		range = malloc_vital(sizeof (itmc_data_pair_t));
		$$->obj = range;
		if (data_compare($1, $3) < 0) {
			range->data0 = *($1);
			range->data1 = *($3);
		} else {
			range->data0 = *($3);
			range->data1 = *($1);
		}
	}
	;
escseq_list
	: escseq
	{
		TRACE_MESSAGE('y', ("escseq_list: escseq\n"));
		$$ = obj_list_append(NULL, $1);
	}
	| escseq_list COMMA escseq
	{
		TRACE_MESSAGE('y', ("escseq_list: escseq_list; escseq\n"));
		$$ = obj_list_append($1, $3);
	}
	;

escseq
	: HEXADECIMAL
	{
		itm_data_t	*escseq;
		TRACE_MESSAGE('y', ("escseq: HEXADECIMAL\n"));
		$$ = malloc_vital(sizeof (itmc_obj_t));
		$$->type = ITMC_OBJ_ESCAPESEQ;
		$$->name = NULL;
		escseq = malloc_vital(sizeof (itm_data_t));
		$$->obj = escseq;
		*escseq = *($1);
	}
	;

map	: MAP name CBO map_list CBC
	{
		TRACE_MESSAGE('y', ("map: map name {map_list}\n"));
		$$ = map_table($2, $4, NULL);
	}
	| MAP CBO map_list CBC
	{
		TRACE_MESSAGE('y', ("map: map {map_list}\n"));
		$$ = map_table(NULL, $3, NULL);
	}
	| MAP name map_attribute CBO map_list CBC
	{
		TRACE_MESSAGE('y', ("map: map name attribute {map_list}\n"));
		$$ = map_table($2, $5, $3);
	}
	| MAP map_attribute CBO map_list CBC
	{
		TRACE_MESSAGE('y', ("map: map attribute {map_list}\n"));
		$$ = map_table(NULL, $4, $2);
	}
	;

map_attribute
	:map_type COMMA map_resultlen
	{
		TRACE_MESSAGE('y', ("map_attribute: map_type map_resultlen\n"));
		$$ = $1;
		$$->resultlen = $3;
	}
	|map_type
	{
		TRACE_MESSAGE('y', ("map_attribute: map_type\n"));
		$$ = $1;
		$$->resultlen = 0;
	}
	|map_resultlen COMMA map_type
	{
		TRACE_MESSAGE('y', ("map_attribute: map_resultlen map_type\n"));
		$$ = $3;
		$$->resultlen = $1;
	}
	|map_resultlen
	{
		TRACE_MESSAGE('y', ("map_attribute: map_resultlen\n"));
		$$ = malloc_vital(sizeof (itmc_map_attr_t));
		$$->resultlen = $1;
		$$->type = NULL;
		$$->hash_factor = 0;
	}
	;

map_type
	: MAPTYPE ASSIGN map_type_names COLON DECIMAL
	{
		TRACE_MESSAGE('y', ("map_type: maptype=type:factor(%d)\n",
			$5));
		$$ = malloc_vital(sizeof (itmc_map_attr_t));
		$$->type = $3;
		$$->hash_factor = $5;
	}
	| MAPTYPE ASSIGN map_type_names
	{
		TRACE_MESSAGE('y', ("map_type: maptype=type\n"));
		$$ = malloc_vital(sizeof (itmc_map_attr_t));
		$$->type  = $3;
		$$->hash_factor = 0;
	}
	;

map_type_names
	: MAPTYPE_NAME
	{
		TRACE_MESSAGE('y', ("map_type_names: size=%*s\n",
				yylval.data->size, NSPTR(yylval.data)));
		$$ = yylval.data;
	}
	;


map_resultlen
	: RESULTLEN ASSIGN DECIMAL
	{
		TRACE_MESSAGE('y', ("map_resultlen(%d)\n", $3));
		$$ = $3;
	}
	;

map_list
	: map_pair
	{
		TRACE_MESSAGE('y', ("map_list: map_pair\n"));
		$$ = map_list_append(NULL, $1);
	}
	| map_list map_pair
	{
		TRACE_MESSAGE('y', ("map_list: map_list map_pair\n"));
		$$ = map_list_append($1, $2);
	}
	;

map_pair
	: HEXADECIMAL HEXADECIMAL
	{
		TRACE_MESSAGE('y', ("map_pair: HEXADECIMAL HEXADECIMAL\n"));
		$$ = malloc_vital(sizeof (itmc_map_t));
		$$->data_pair.data0 = *($1);
		free($1);
		$$->data_pair.data1 = *($2);
		free($2);
	}
	| HEXADECIMAL ELLIPSES HEXADECIMAL HEXADECIMAL
	{
		TRACE_MESSAGE('y', ("map_pair: "
			"HEXADECIMAL ELLIPSES HEXADECIMAL\n"));
		$$ = malloc_vital(sizeof (itmc_map_t));
		$$->data_pair.data0 = *($1);
		$$->data_pair.range = *($3);
		free($1);
		free($3);
		$$->data_pair.data1 = *($4);
		free($4);
	}
	| ITM_DEFAULT  HEXADECIMAL
	{
		TRACE_MESSAGE('y', ("map_pair: default HEXADECIMAL\n"));
		$$ = malloc_vital(sizeof (itmc_map_t));
		$$->data_pair.data0.size = 0;
		$$->data_pair.data1 = *($2);
		free($2);
	}
	| ITM_DEFAULT  ITM_IDENTICAL
	{
		TRACE_MESSAGE('y', ("map_pair: default default\n"));
		$$ = malloc_vital(sizeof (itmc_map_t));
		$$->data_pair.data0.size = 0;
		$$->data_pair.data1.size = 0;
	}
	| HEXADECIMAL ERROR /* NO RANGE */
	{
		TRACE_MESSAGE('y', ("map_pair: hexadecimal error\n"));
		$$ = malloc_vital(sizeof (itmc_map_t));
		$$->data_pair.data0 = *($1);
		free($1);
		$$->data_pair.data1.size = 0;
	}
	;

operation
	: OPERATION name CBO op_list CBC
	{
		TRACE_MESSAGE('y', ("operation: operation name {op_list}\n"));
		$$ = obj_table(ITM_TBL_OP, $2,
			$4, sizeof (itm_op_t));
	}
	| OPERATION CBO op_list CBC
	{
		TRACE_MESSAGE('y', ("operation: operation {op_list}\n"));
		$$ = obj_table(ITM_TBL_OP, NULL,
				$3, sizeof (itm_op_t));
	}
	| OPERATION ITM_INIT CBO op_list CBC
	{
		TRACE_MESSAGE('y', ("operation: operation init {op_list}\n"));
		$$ = obj_table(ITM_TBL_OP_INIT, NULL,
			$4, sizeof (itm_op_t));
	}
	| OPERATION RESET CBO op_list CBC
	{
		TRACE_MESSAGE('y', ("operation: operation reset {op_list}\n"));
		$$ = obj_table(ITM_TBL_OP_RESET, NULL,
			$4, sizeof (itm_op_t));
	}
	;

op_list	: op_unit
	{
		TRACE_MESSAGE('y', ("op_list: op_unit\n"));
		$$ = obj_list_append(NULL, $1);
	}
	| op_list op_unit
	{
		TRACE_MESSAGE('y', ("op_list: op_list op_unit\n"));
		$$ = obj_list_append($1, $2);
	}
	;

op_unit	: /* */ SC
	{
		TRACE_MESSAGE('y', ("op_unit: /	*null */;\n"));
		$$ = NULL;
	}
	| expr SC
	{
		TRACE_MESSAGE('y', ("op_unit: expr;\n"));
		$$ = op_unary(ITM_OP_EXPR, $1, sizeof (itm_expr_t));
	}
	| ERROR SC
	{
		TRACE_MESSAGE('y', ("expr: error;\n"));
		$$ = op_self_num(ITM_OP_ERROR_D, EINVAL);
	}
	| ERROR expr SC
	{
		TRACE_MESSAGE('y', ("expr: error;\n"));
		if (ITM_EXPR_INT == $2->type) {
			$$ = op_self_num(ITM_OP_ERROR_D, $2->data.itm_exnum);
		} else {
			$$ = op_unary(ITM_OP_ERROR, $2, sizeof (itm_expr_t));
		}
	}
	| DISCARD SC
	{
		TRACE_MESSAGE('y', ("discard expr;\n"));
		$$ = op_self_num(ITM_OP_DISCARD_D, 1);
	}
	| DISCARD expr SC
	{
		TRACE_MESSAGE('y', ("discard expr;\n"));
		if (ITM_EXPR_INT == $2->type) {
			$$ = op_self_num(ITM_OP_DISCARD_D, $2->data.itm_exnum);
		} else {
			$$ = op_unary(ITM_OP_DISCARD, $2, sizeof (itm_expr_t));
		}
	}
	| ITM_OUT ASSIGN expr SC
	{
		TRACE_MESSAGE('y', ("out = expr;\n"));
		switch ($3->type) {
		case ITM_EXPR_INT:
			$$ = op_unary(ITM_OP_OUT_D, $3, sizeof (itm_expr_t));
			break;
		case ITM_EXPR_SEQ:
			$$ = op_unary(ITM_OP_OUT_S, $3, sizeof (itm_expr_t));
			break;
		case ITM_EXPR_REG:
			$$ = op_unary(ITM_OP_OUT_R, $3, sizeof (itm_expr_t));
			break;
		case ITM_EXPR_IN_VECTOR_D:
			$$ = op_unary(ITM_OP_OUT_INVD, $3, sizeof (itm_expr_t));
			break;
		default:
			$$ = op_unary(ITM_OP_OUT, $3, sizeof (itm_expr_t));
			break;
		}
	}
	| DIRECTION name SC
	{
		itm_op_t	*op;
		TRACE_MESSAGE('y', ("direction NAME;\n"));
		$$ = op_unit(ITM_OP_DIRECTION, NULL, 0, NULL, 0, NULL, 0);
		op = (itm_op_t *)($$->obj);
		op->data.operand[0].itm_ptr = (itm_place2_t)($2);
		$$->ref[0] = obj_register(ITMC_OBJ_DIREC, $2,
					NULL, 0,
					&(op->data.operand[0]), OBJ_REG_TAIL);
	}
	| OPERATION name SC
	{
		itm_op_t	*op;
		TRACE_MESSAGE('y', ("operation NAME;\n"));
		$$ = op_unit(ITM_OP_OPERATION, NULL, 0, NULL, 0, NULL, 0);
		op = (itm_op_t *)($$->obj);
		op->data.operand[0].itm_ptr = (itm_place2_t)($2);
		$$->ref[0] = obj_register(ITMC_OBJ_OP, $2,
					NULL, 0,
					&(op->data.operand[0]), OBJ_REG_TAIL);
	}
	| OPERATION ITM_INIT SC
	{
		itm_op_t	*op;
		TRACE_MESSAGE('y', ("operation init;\n"));
		$$ = op_self(ITM_OP_INIT);
	}
	| OPERATION RESET SC
	{
		itm_op_t	*op;
		TRACE_MESSAGE('y', ("operation reset;\n"));
		$$ = op_self(ITM_OP_RESET);
	}
	| MAP name SC
	{
		itm_op_t	*op;
		TRACE_MESSAGE('y', ("map NAME;\n"));
		$$ = op_unit(ITM_OP_MAP, NULL, 0, NULL, 0, NULL, 0);
		op = (itm_op_t *)($$->obj);
		op->data.operand[0].itm_ptr = (itm_place2_t)($2);
		$$->ref[0] = obj_register(ITMC_OBJ_MAP, $2,
					NULL, 0,
					&(op->data.operand[0]), OBJ_REG_TAIL);
	}
	| MAP name expr SC
	{
		itm_op_t	*op;
		TRACE_MESSAGE('y', ("map NAME expr;\n"));
		$$ = op_unit(ITM_OP_MAP, NULL, 0, $3,
			sizeof (itm_expr_t), NULL, 0);
		op = (itm_op_t *)($$->obj);
		op->data.operand[0].itm_ptr = (itm_place2_t)($2);
		$$->ref[0] = obj_register(ITMC_OBJ_MAP, $2,
					NULL, 0,
					&(op->data.operand[0]), OBJ_REG_TAIL);
	}
	| op_if_else
	{
		TRACE_MESSAGE('y', ("op_unit: op_if_else\n"));
		$$ = $1;
	}
	| BREAK SC
	{
		TRACE_MESSAGE('y', ("break;\n"));
		$$ = op_self(ITM_OP_BREAK);
	}
	| RETURN SC
	{
		TRACE_MESSAGE('y', ("return;\n"));
		$$ = op_self(ITM_OP_RETURN);
	}
	| PRINTCHR expr SC
	{
		TRACE_MESSAGE('y', ("printchr expr;\n"));
		$$ = op_unary(ITM_OP_PRINTCHR, $2, sizeof (itm_expr_t));
	}
	| PRINTHD expr SC
	{
		TRACE_MESSAGE('y', ("printchr expr;\n"));
		$$ = op_unary(ITM_OP_PRINTHD, $2, sizeof (itm_expr_t));
	}
	| PRINTINT expr SC
	{
		TRACE_MESSAGE('y', ("printint expr;\n"));
		$$ = op_unary(ITM_OP_PRINTINT, $2, sizeof (itm_expr_t));
	}
	;

op_if_else
	: ITM_IF PO expr PC CBO op_list CBC
	{
		itm_tbl_hdr_t	*tbl_hdr;
		TRACE_MESSAGE('y', ("op_if_else: if (expr) {op_list}\n"));
		tbl_hdr = obj_table(ITM_TBL_OP, NULL,
				    $6, sizeof (itm_op_t));
		$$ = op_unit(ITM_OP_IF,
				$3, sizeof (itm_expr_t),
				tbl_hdr, tbl_hdr->size,
				NULL, 0);
	}
	| ITM_IF PO expr PC CBO op_list CBC ITM_ELSE op_if_else
	{
		itm_tbl_hdr_t	*tbl_hdr1;
		itm_tbl_hdr_t	*tbl_hdr2;
		TRACE_MESSAGE('y', ("op_if_else: "
			"if (expr) {op_list} else op_if_else\n"));
		tbl_hdr1 = obj_table(ITM_TBL_OP, NULL,
				    $6, sizeof (itm_op_t));
		tbl_hdr2 = obj_table(ITM_TBL_OP, NULL,
				    $9, sizeof (itm_op_t));
		$$ = op_unit(ITM_OP_IF_ELSE,
				$3, sizeof (itm_expr_t),
				tbl_hdr1, tbl_hdr1->size,
				tbl_hdr2, tbl_hdr2->size);
	}
	| ITM_IF PO expr PC CBO op_list CBC ITM_ELSE CBO op_list CBC
	{
		itm_tbl_hdr_t	*tbl_hdr1;
		itm_tbl_hdr_t	*tbl_hdr2;
		TRACE_MESSAGE('y', ("op_if_else: "
			"if (expr) {op_list} else {op_list}\n"));
		tbl_hdr1 = obj_table(ITM_TBL_OP, NULL,
				    $6, sizeof (itm_op_t));
		tbl_hdr2 = obj_table(ITM_TBL_OP, NULL,
				    $10, sizeof (itm_op_t));
		$$ = op_unit(ITM_OP_IF_ELSE,
				$3, sizeof (itm_expr_t),
				tbl_hdr1, tbl_hdr1->size,
				tbl_hdr2, tbl_hdr2->size);
	}
	;

name	: NAME
	{
		TRACE_MESSAGE('y', ("name: size=%*s\n",
				yylval.data->size, NSPTR(yylval.data)));
		$$ = yylval.data;
	}
	;

itm_in	: ITM_IN
	{
		TRACE_MESSAGE('y', ("in\n"));
		$$ = expr_self(ITM_EXPR_IN, NULL);
	}
	;

expr	: PO expr PC
	{
		TRACE_MESSAGE('y', ("expr: (expr)\n"));
		$$ = $2;
	}
	| name
	{
		TRACE_MESSAGE('y', ("expr: NAME\n"));
		$$ = expr_self(ITM_EXPR_NAME, $1);
	}
	| HEXADECIMAL
	{
		TRACE_MESSAGE('y', ("expr: HEXADECIMAL\n"));
		$$ = expr_self(ITM_EXPR_SEQ, yylval.data);
	}
	| DECIMAL
	{
		TRACE_MESSAGE('y', ("expr: DECIMAL\n"));
		$$ = expr_self_num(ITM_EXPR_INT, yylval.num);
	}
	| itm_in SBO expr SBC
	{
		if (ITM_EXPR_INT == $3->type) {
			TRACE_MESSAGE('y', ("expr: in[%ld]\n",
				$3->data.itm_exnum));
			$$ = expr_self_num(ITM_EXPR_IN_VECTOR_D,
				$3->data.itm_exnum);
		} else {
			TRACE_MESSAGE('y', ("expr: in[expr]\n"));
			$$ = expr_unary(ITM_EXPR_IN_VECTOR, $3);
		}
	}
	| ITM_OUTSIZE
	{
		TRACE_MESSAGE('y', ("expr: outsize\n"));
		$$ = expr_self_num(ITM_EXPR_OUT, 0);
	}
	| ITM_INSIZE
	{
		TRACE_MESSAGE('y', ("expr: inputsize\n"));
		$$ = expr_self_num(ITM_EXPR_IN_VECTOR_D, (size_t)-1);
	}
	| ITM_TRUE
	{
		TRACE_MESSAGE('y', ("expr: true\n"));
		$$ = expr_self_num(ITM_EXPR_TRUE, 1);
	}
	| ITM_FALSE
	{
		TRACE_MESSAGE('y', ("expr: false\n"));
		$$ = expr_self_num(ITM_EXPR_FALSE, 0);
	}
	| itm_in EQ expr
	{
		TRACE_MESSAGE('y', ("expr: in == expr\n"));
		$$ = expr_unary(ITM_EXPR_IN_EQ, $3);
	}
	| expr EQ itm_in
	{
		TRACE_MESSAGE('y', ("expr: expr == in\n"));
		$$ = expr_unary(ITM_EXPR_IN_EQ, $1);
	}
	| NOT expr
	{
		TRACE_MESSAGE('y', ("expr: ! expr\n"));

		if (ITM_EXPR_INT == $2->type) {
			$$ = expr_self_num(ITM_EXPR_INT, !($2->data.itm_exnum));
		} else {
			$$ = expr_unary(ITM_EXPR_NOT, $2);
		}
	}
	| NEG expr
	{
		TRACE_MESSAGE('y', ("expr: ~ expr\n"));
		if (ITM_EXPR_INT == $2->type) {
			$$ = expr_self_num(ITM_EXPR_INT, ~($2->data.itm_exnum));
		} else {
			$$ = expr_unary(ITM_EXPR_NEG, $2);
		}
	}
	| MINUS expr %prec MUL
	{
		TRACE_MESSAGE('y', ("expr: - expr\n"));
		if (ITM_EXPR_INT == $2->type) {
			$$ = expr_self_num(ITM_EXPR_INT,
				(-1) * ($2->data.itm_exnum));
		} else {
			$$ = expr_unary(ITM_EXPR_UMINUS, $2);
		}
	}
	| expr PLUS expr
	{
		TRACE_MESSAGE('y', ("expr: expr + expr\n"));
		$$ = expr_binary(ITM_EXPR_PLUS, $1, $3);
		$1 = expr_seq_to_int($1);
		$3 = expr_seq_to_int($3);
		switch ($1->type) {
		case ITM_EXPR_INT:
			switch ($3->type) {
			case ITM_EXPR_INT:
				$$ = expr_binary2(ITM_EXPR_PLUS_D_D, $1, $3);
				break;
			case ITM_EXPR_REG:
				$$ = expr_binary2(ITM_EXPR_PLUS_D_R, $1, $3);
				break;
			case ITM_EXPR_IN_VECTOR_D:
				$$ = expr_binary2(ITM_EXPR_PLUS_D_INVD, $1, $3);
				break;
			default:
				$$ = expr_binary2(ITM_EXPR_PLUS_D_E, $1, $3);
				break;
		}
			break;
		case ITM_EXPR_REG:
			switch ($3->type) {
			case ITM_EXPR_INT:
				$$ = expr_binary2(ITM_EXPR_PLUS_R_D, $1, $3);
				break;
			case ITM_EXPR_REG:
				$$ = expr_binary2(ITM_EXPR_PLUS_R_R, $1, $3);
				break;
			case ITM_EXPR_IN_VECTOR_D:
				$$ = expr_binary2(ITM_EXPR_PLUS_R_INVD, $1, $3);
				break;
			default:
				$$ = expr_binary2(ITM_EXPR_PLUS_R_E, $1, $3);
				break;
		}
			break;
		case ITM_EXPR_IN_VECTOR_D:
			switch ($3->type) {
			case ITM_EXPR_INT:
				$$ = expr_binary2(ITM_EXPR_PLUS_INVD_D, $1, $3);
				break;
			case ITM_EXPR_REG:
				$$ = expr_binary2(ITM_EXPR_PLUS_INVD_R, $1, $3);
				break;
			case ITM_EXPR_IN_VECTOR_D:
				$$ = expr_binary2(ITM_EXPR_PLUS_INVD_INVD,
					$1, $3);
				break;
			default:
				$$ = expr_binary2(ITM_EXPR_PLUS_INVD_E, $1, $3);
				break;
		}
			break;
		default:
			switch ($3->type) {
			case ITM_EXPR_INT:
				$$ = expr_binary2(ITM_EXPR_PLUS_E_D, $1, $3);
				break;
			case ITM_EXPR_REG:
				$$ = expr_binary2(ITM_EXPR_PLUS_E_R, $1, $3);
				break;
			case ITM_EXPR_IN_VECTOR_D:
				$$ = expr_binary2(ITM_EXPR_PLUS_E_INVD, $1, $3);
				break;
			default:
				$$ = expr_binary2(ITM_EXPR_PLUS, $1, $3);
				break;
			}
			break;
		}
	}
	| expr MINUS expr
	{
		TRACE_MESSAGE('y', ("expr: expr - expr\n"));
		$$ = expr_binary(ITM_EXPR_MINUS, $1, $3);
		$1 = expr_seq_to_int($1);
		$3 = expr_seq_to_int($3);
		switch ($1->type) {
		case ITM_EXPR_INT:
			switch ($3->type) {
			case ITM_EXPR_INT:
				$$ = expr_binary2(ITM_EXPR_MINUS_D_D, $1, $3);
				break;
			case ITM_EXPR_REG:
				$$ = expr_binary2(ITM_EXPR_MINUS_D_R, $1, $3);
				break;
			case ITM_EXPR_IN_VECTOR_D:
				$$ = expr_binary2(ITM_EXPR_MINUS_D_INVD,
					$1, $3);
				break;
			default:
				$$ = expr_binary2(ITM_EXPR_MINUS_D_E, $1, $3);
				break;
			}
			break;
		case ITM_EXPR_REG:
			switch ($3->type) {
			case ITM_EXPR_INT:
				$$ = expr_binary2(ITM_EXPR_MINUS_R_D, $1, $3);
				break;
			case ITM_EXPR_REG:
				$$ = expr_binary2(ITM_EXPR_MINUS_R_R, $1, $3);
				break;
			case ITM_EXPR_IN_VECTOR_D:
				$$ = expr_binary2(ITM_EXPR_MINUS_R_INVD,
					$1, $3);
				break;
			default:
				$$ = expr_binary2(ITM_EXPR_MINUS_R_E, $1, $3);
				break;
			}
			break;
		case ITM_EXPR_IN_VECTOR_D:
			switch ($3->type) {
			case ITM_EXPR_INT:
				$$ = expr_binary2(ITM_EXPR_MINUS_INVD_D,
					$1, $3);
				break;
			case ITM_EXPR_REG:
				$$ = expr_binary2(ITM_EXPR_MINUS_INVD_R,
					$1, $3);
				break;
			case ITM_EXPR_IN_VECTOR_D:
				$$ = expr_binary2(ITM_EXPR_MINUS_INVD_INVD,
					$1, $3);
				break;
			default:
				$$ = expr_binary2(ITM_EXPR_MINUS_INVD_E,
					$1, $3);
				break;
			}
			break;
		default:
			switch ($3->type) {
			case ITM_EXPR_INT:
				$$ = expr_binary2(ITM_EXPR_MINUS_E_D, $1, $3);
				break;
			case ITM_EXPR_REG:
				$$ = expr_binary2(ITM_EXPR_MINUS_E_R, $1, $3);
				break;
			case ITM_EXPR_IN_VECTOR_D:
				$$ = expr_binary2(ITM_EXPR_MINUS_E_INVD,
					$1, $3);
				break;
			default:
				$$ = expr_binary2(ITM_EXPR_MINUS, $1, $3);
				break;
			}
			break;
		}
	}
	| expr MUL expr
	{
		TRACE_MESSAGE('y', ("expr: expr		*expr\n"));
		$$ = expr_binary(ITM_EXPR_MUL, $1, $3);
		$1 = expr_seq_to_int($1);
		$3 = expr_seq_to_int($3);
		switch ($1->type) {
		case ITM_EXPR_INT:
			switch ($3->type) {
			case ITM_EXPR_INT:
				$$ = expr_binary2(ITM_EXPR_MUL_D_D, $1, $3);
				break;
			case ITM_EXPR_REG:
				$$ = expr_binary2(ITM_EXPR_MUL_D_R, $1, $3);
				break;
			case ITM_EXPR_IN_VECTOR_D:
				$$ = expr_binary2(ITM_EXPR_MUL_D_INVD, $1, $3);
				break;
			default:
				$$ = expr_binary2(ITM_EXPR_MUL_D_E, $1, $3);
				break;
			}
			break;
		case ITM_EXPR_REG:
			switch ($3->type) {
			case ITM_EXPR_INT:
				$$ = expr_binary2(ITM_EXPR_MUL_R_D, $1, $3);
				break;
			case ITM_EXPR_REG:
				$$ = expr_binary2(ITM_EXPR_MUL_R_R, $1, $3);
				break;
			case ITM_EXPR_IN_VECTOR_D:
				$$ = expr_binary2(ITM_EXPR_MUL_R_INVD, $1, $3);
				break;
			default:
				$$ = expr_binary2(ITM_EXPR_MUL_R_E, $1, $3);
				break;
			}
			break;
		case ITM_EXPR_IN_VECTOR_D:
			switch ($3->type) {
			case ITM_EXPR_INT:
				$$ = expr_binary2(ITM_EXPR_MUL_INVD_D, $1, $3);
				break;
			case ITM_EXPR_REG:
				$$ = expr_binary2(ITM_EXPR_MUL_INVD_R, $1, $3);
				break;
			case ITM_EXPR_IN_VECTOR_D:
				$$ = expr_binary2(ITM_EXPR_MUL_INVD_INVD,
					$1, $3);
				break;
			default:
				$$ = expr_binary2(ITM_EXPR_MUL_INVD_E, $1, $3);
				break;
			}
			break;
		default:
			switch ($3->type) {
			case ITM_EXPR_INT:
				$$ = expr_binary2(ITM_EXPR_MUL_E_D, $1, $3);
				break;
			case ITM_EXPR_REG:
				$$ = expr_binary2(ITM_EXPR_MUL_E_R, $1, $3);
				break;
			case ITM_EXPR_IN_VECTOR_D:
				$$ = expr_binary2(ITM_EXPR_MUL_E_INVD, $1, $3);
				break;
			default:
				$$ = expr_binary2(ITM_EXPR_MUL, $1, $3);
				break;
			}
			break;
		}
	}
	| expr DIV expr
	{
		TRACE_MESSAGE('y', ("expr: expr / expr\n"));
		$$ = expr_binary(ITM_EXPR_DIV, $1, $3);
		$1 = expr_seq_to_int($1);
		$3 = expr_seq_to_int($3);
		switch ($1->type) {
		case ITM_EXPR_INT:
			switch ($3->type) {
			case ITM_EXPR_INT:
				$$ = expr_binary2(ITM_EXPR_DIV_D_D, $1, $3);
				break;
			case ITM_EXPR_REG:
				$$ = expr_binary2(ITM_EXPR_DIV_D_R, $1, $3);
				break;
			case ITM_EXPR_IN_VECTOR_D:
				$$ = expr_binary2(ITM_EXPR_DIV_D_INVD, $1, $3);
				break;
			default:
				$$ = expr_binary2(ITM_EXPR_DIV_D_E, $1, $3);
				break;
			}
			break;
		case ITM_EXPR_REG:
			switch ($3->type) {
			case ITM_EXPR_INT:
				$$ = expr_binary2(ITM_EXPR_DIV_R_D, $1, $3);
				break;
			case ITM_EXPR_REG:
				$$ = expr_binary2(ITM_EXPR_DIV_R_R, $1, $3);
				break;
			case ITM_EXPR_IN_VECTOR_D:
				$$ = expr_binary2(ITM_EXPR_DIV_R_INVD, $1, $3);
				break;
			default:
				$$ = expr_binary2(ITM_EXPR_DIV_R_E, $1, $3);
				break;
			}
			break;
		case ITM_EXPR_IN_VECTOR_D:
			switch ($3->type) {
			case ITM_EXPR_INT:
				$$ = expr_binary2(ITM_EXPR_DIV_INVD_D, $1, $3);
				break;
			case ITM_EXPR_REG:
				$$ = expr_binary2(ITM_EXPR_DIV_INVD_R, $1, $3);
				break;
			case ITM_EXPR_IN_VECTOR_D:
				$$ = expr_binary2(ITM_EXPR_DIV_INVD_INVD,
					$1, $3);
				break;
			default:
				$$ = expr_binary2(ITM_EXPR_DIV_INVD_E, $1, $3);
				break;
			}
			break;
		default:
			switch ($3->type) {
			case ITM_EXPR_INT:
				$$ = expr_binary2(ITM_EXPR_DIV_E_D, $1, $3);
				break;
			case ITM_EXPR_REG:
				$$ = expr_binary2(ITM_EXPR_DIV_E_R, $1, $3);
				break;
			case ITM_EXPR_IN_VECTOR_D:
				$$ = expr_binary2(ITM_EXPR_DIV_E_INVD, $1, $3);
				break;
			default:
				$$ = expr_binary2(ITM_EXPR_DIV, $1, $3);
				break;
			}
			break;
		}
	}
	| expr MOD expr
	{
		TRACE_MESSAGE('y', ("expr: expr % expr\n"));
		$$ = expr_binary(ITM_EXPR_MOD, $1, $3);
		$1 = expr_seq_to_int($1);
		$3 = expr_seq_to_int($3);
		switch ($1->type) {
		case ITM_EXPR_INT:
			switch ($3->type) {
			case ITM_EXPR_INT:
				$$ = expr_binary2(ITM_EXPR_MOD_D_D, $1, $3);
				break;
			case ITM_EXPR_REG:
				$$ = expr_binary2(ITM_EXPR_MOD_D_R, $1, $3);
				break;
			case ITM_EXPR_IN_VECTOR_D:
				$$ = expr_binary2(ITM_EXPR_MOD_D_INVD, $1, $3);
				break;
			default:
				$$ = expr_binary2(ITM_EXPR_MOD_D_E, $1, $3);
				break;
			}
			break;
		case ITM_EXPR_REG:
			switch ($3->type) {
			case ITM_EXPR_INT:
				$$ = expr_binary2(ITM_EXPR_MOD_R_D, $1, $3);
				break;
			case ITM_EXPR_REG:
				$$ = expr_binary2(ITM_EXPR_MOD_R_R, $1, $3);
				break;
			case ITM_EXPR_IN_VECTOR_D:
				$$ = expr_binary2(ITM_EXPR_MOD_R_INVD, $1, $3);
				break;
			default:
				$$ = expr_binary2(ITM_EXPR_MOD_R_E, $1, $3);
				break;
			}
			break;
		case ITM_EXPR_IN_VECTOR_D:
			switch ($3->type) {
			case ITM_EXPR_INT:
				$$ = expr_binary2(ITM_EXPR_MOD_INVD_D, $1, $3);
				break;
			case ITM_EXPR_REG:
				$$ = expr_binary2(ITM_EXPR_MOD_INVD_R, $1, $3);
				break;
			case ITM_EXPR_IN_VECTOR_D:
				$$ = expr_binary2(ITM_EXPR_MOD_INVD_INVD,
					$1, $3);
				break;
			default:
				$$ = expr_binary2(ITM_EXPR_MOD_INVD_E, $1, $3);
				break;
			}
			break;
		default:
			switch ($3->type) {
			case ITM_EXPR_INT:
				$$ = expr_binary2(ITM_EXPR_MOD_E_D, $1, $3);
				break;
			case ITM_EXPR_REG:
				$$ = expr_binary2(ITM_EXPR_MOD_E_R, $1, $3);
				break;
			case ITM_EXPR_IN_VECTOR_D:
				$$ = expr_binary2(ITM_EXPR_MOD_E_INVD, $1, $3);
				break;
			default:
				$$ = expr_binary2(ITM_EXPR_MOD, $1, $3);
				break;
			}
			break;
		}
	}
	| expr SHL expr
	{
		TRACE_MESSAGE('y', ("expr: expr << expr\n"));
		$$ = expr_binary(ITM_EXPR_SHIFT_L, $1, $3);
		$1 = expr_seq_to_int($1);
		$3 = expr_seq_to_int($3);
		switch ($1->type) {
		case ITM_EXPR_INT:
			switch ($3->type) {
			case ITM_EXPR_INT:
				$$ = expr_binary2(ITM_EXPR_SHIFT_L_D_D, $1, $3);
				break;
			case ITM_EXPR_REG:
				$$ = expr_binary2(ITM_EXPR_SHIFT_L_D_R, $1, $3);
				break;
			case ITM_EXPR_IN_VECTOR_D:
				$$ = expr_binary2(ITM_EXPR_SHIFT_L_D_INVD,
					$1, $3);
				break;
			default:
				$$ = expr_binary2(ITM_EXPR_SHIFT_L_D_E, $1, $3);
				break;
			}
			break;
		case ITM_EXPR_REG:
			switch ($3->type) {
			case ITM_EXPR_INT:
				$$ = expr_binary2(ITM_EXPR_SHIFT_L_R_D, $1, $3);
				break;
			case ITM_EXPR_REG:
				$$ = expr_binary2(ITM_EXPR_SHIFT_L_R_R, $1, $3);
				break;
			case ITM_EXPR_IN_VECTOR_D:
				$$ = expr_binary2(ITM_EXPR_SHIFT_L_R_INVD,
					$1, $3);
				break;
			default:
				$$ = expr_binary2(ITM_EXPR_SHIFT_L_R_E, $1, $3);
				break;
			}
			break;
		case ITM_EXPR_IN_VECTOR_D:
			switch ($3->type) {
			case ITM_EXPR_INT:
				$$ = expr_binary2(ITM_EXPR_SHIFT_L_INVD_D,
					$1, $3);
				break;
			case ITM_EXPR_REG:
				$$ = expr_binary2(ITM_EXPR_SHIFT_L_INVD_R,
					$1, $3);
				break;
			case ITM_EXPR_IN_VECTOR_D:
				$$ = expr_binary2(ITM_EXPR_SHIFT_L_INVD_INVD,
					$1, $3);
				break;
			default:
				$$ = expr_binary2(ITM_EXPR_SHIFT_L_INVD_E,
					$1, $3);
				break;
			}
			break;
		default:
			switch ($3->type) {
			case ITM_EXPR_INT:
				$$ = expr_binary2(ITM_EXPR_SHIFT_L_E_D, $1, $3);
				break;
			case ITM_EXPR_REG:
				$$ = expr_binary2(ITM_EXPR_SHIFT_L_E_R, $1, $3);
				break;
			case ITM_EXPR_IN_VECTOR_D:
				$$ = expr_binary2(ITM_EXPR_SHIFT_L_E_INVD,
					$1, $3);
				break;
			default:
				$$ = expr_binary2(ITM_EXPR_SHIFT_L, $1, $3);
				break;
			}
			break;
		}
	}
	| expr SHR expr
	{
		TRACE_MESSAGE('y', ("expr: expr >> expr\n"));
		$$ = expr_binary(ITM_EXPR_SHIFT_R, $1, $3);
		$1 = expr_seq_to_int($1);
		$3 = expr_seq_to_int($3);
		switch ($1->type) {
		case ITM_EXPR_INT:
			switch ($3->type) {
			case ITM_EXPR_INT:
				$$ = expr_binary2(ITM_EXPR_SHIFT_R_D_D, $1, $3);
				break;
			case ITM_EXPR_REG:
				$$ = expr_binary2(ITM_EXPR_SHIFT_R_D_R, $1, $3);
				break;
			case ITM_EXPR_IN_VECTOR_D:
				$$ = expr_binary2(ITM_EXPR_SHIFT_R_D_INVD,
					$1, $3);
				break;
			default:
				$$ = expr_binary2(ITM_EXPR_SHIFT_R_D_E, $1, $3);
				break;
			}
			break;
		case ITM_EXPR_REG:
			switch ($3->type) {
			case ITM_EXPR_INT:
				$$ = expr_binary2(ITM_EXPR_SHIFT_R_R_D, $1, $3);
				break;
			case ITM_EXPR_REG:
				$$ = expr_binary2(ITM_EXPR_SHIFT_R_R_R, $1, $3);
				break;
			case ITM_EXPR_IN_VECTOR_D:
				$$ = expr_binary2(ITM_EXPR_SHIFT_R_R_INVD,
					$1, $3);
				break;
			default:
				$$ = expr_binary2(ITM_EXPR_SHIFT_R_R_E, $1, $3);
				break;
			}
			break;
		case ITM_EXPR_IN_VECTOR_D:
			switch ($3->type) {
			case ITM_EXPR_INT:
				$$ = expr_binary2(ITM_EXPR_SHIFT_R_INVD_D,
					$1, $3);
				break;
			case ITM_EXPR_REG:
				$$ = expr_binary2(ITM_EXPR_SHIFT_R_INVD_R,
					$1, $3);
				break;
			case ITM_EXPR_IN_VECTOR_D:
				$$ = expr_binary2(ITM_EXPR_SHIFT_R_INVD_INVD,
					$1, $3);
				break;
			default:
				$$ = expr_binary2(ITM_EXPR_SHIFT_R_INVD_E,
					$1, $3);
				break;
			}
			break;
		default:
			switch ($3->type) {
			case ITM_EXPR_INT:
				$$ = expr_binary2(ITM_EXPR_SHIFT_R_E_D, $1, $3);
				break;
			case ITM_EXPR_REG:
				$$ = expr_binary2(ITM_EXPR_SHIFT_R_E_R, $1, $3);
				break;
			case ITM_EXPR_IN_VECTOR_D:
				$$ = expr_binary2(ITM_EXPR_SHIFT_R_E_INVD,
					$1, $3);
				break;
			default:
				$$ = expr_binary2(ITM_EXPR_SHIFT_R, $1, $3);
				break;
			}
			break;
		}
	}
	| expr OR expr
	{
		TRACE_MESSAGE('y', ("expr: expr | expr\n"));
		$$ = expr_binary(ITM_EXPR_OR, $1, $3);
		$1 = expr_seq_to_int($1);
		$3 = expr_seq_to_int($3);
		switch ($1->type) {
		case ITM_EXPR_INT:
			switch ($3->type) {
			case ITM_EXPR_INT:
				$$ = expr_binary2(ITM_EXPR_OR_D_D, $1, $3);
				break;
			case ITM_EXPR_REG:
				$$ = expr_binary2(ITM_EXPR_OR_D_R, $1, $3);
				break;
			case ITM_EXPR_IN_VECTOR_D:
				$$ = expr_binary2(ITM_EXPR_OR_D_INVD, $1, $3);
				break;
			default:
				$$ = expr_binary2(ITM_EXPR_OR_D_E, $1, $3);
				break;
			}
			break;
		case ITM_EXPR_REG:
			switch ($3->type) {
			case ITM_EXPR_INT:
				$$ = expr_binary2(ITM_EXPR_OR_R_D, $1, $3);
				break;
			case ITM_EXPR_REG:
				$$ = expr_binary2(ITM_EXPR_OR_R_R, $1, $3);
				break;
			case ITM_EXPR_IN_VECTOR_D:
				$$ = expr_binary2(ITM_EXPR_OR_R_INVD, $1, $3);
				break;
			default:
				$$ = expr_binary2(ITM_EXPR_OR_R_E, $1, $3);
				break;
			}
			break;
		case ITM_EXPR_IN_VECTOR_D:
			switch ($3->type) {
			case ITM_EXPR_INT:
				$$ = expr_binary2(ITM_EXPR_OR_INVD_D, $1, $3);
				break;
			case ITM_EXPR_REG:
				$$ = expr_binary2(ITM_EXPR_OR_INVD_R, $1, $3);
				break;
			case ITM_EXPR_IN_VECTOR_D:
				$$ = expr_binary2(ITM_EXPR_OR_INVD_INVD,
					$1, $3);
				break;
			default:
				$$ = expr_binary2(ITM_EXPR_OR_INVD_E, $1, $3);
				break;
			}
			break;
		default:
			switch ($3->type) {
			case ITM_EXPR_INT:
				$$ = expr_binary2(ITM_EXPR_OR_E_D, $1, $3);
				break;
			case ITM_EXPR_REG:
				$$ = expr_binary2(ITM_EXPR_OR_E_R, $1, $3);
				break;
			case ITM_EXPR_IN_VECTOR_D:
				$$ = expr_binary2(ITM_EXPR_OR_E_INVD, $1, $3);
				break;
			default:
				$$ = expr_binary2(ITM_EXPR_OR, $1, $3);
				break;
			}
			break;
		}
	}
	| expr XOR expr
	{
		TRACE_MESSAGE('y', ("expr: expr ^ expr\n"));
		$$ = expr_binary(ITM_EXPR_XOR, $1, $3);
		$1 = expr_seq_to_int($1);
		$3 = expr_seq_to_int($3);
		switch ($1->type) {
		case ITM_EXPR_INT:
			switch ($3->type) {
			case ITM_EXPR_INT:
				$$ = expr_binary2(ITM_EXPR_XOR_D_D, $1, $3);
				break;
			case ITM_EXPR_REG:
				$$ = expr_binary2(ITM_EXPR_XOR_D_R, $1, $3);
				break;
			case ITM_EXPR_IN_VECTOR_D:
				$$ = expr_binary2(ITM_EXPR_XOR_D_INVD, $1, $3);
				break;
			default:
				$$ = expr_binary2(ITM_EXPR_XOR_D_E, $1, $3);
				break;
			}
			break;
		case ITM_EXPR_REG:
			switch ($3->type) {
			case ITM_EXPR_INT:
				$$ = expr_binary2(ITM_EXPR_XOR_R_D, $1, $3);
				break;
			case ITM_EXPR_REG:
				$$ = expr_binary2(ITM_EXPR_XOR_R_R, $1, $3);
				break;
			case ITM_EXPR_IN_VECTOR_D:
				$$ = expr_binary2(ITM_EXPR_XOR_R_INVD, $1, $3);
				break;
			default:
				$$ = expr_binary2(ITM_EXPR_XOR_R_E, $1, $3);
				break;
			}
			break;
		case ITM_EXPR_IN_VECTOR_D:
			switch ($3->type) {
			case ITM_EXPR_INT:
				$$ = expr_binary2(ITM_EXPR_XOR_INVD_D, $1, $3);
				break;
			case ITM_EXPR_REG:
				$$ = expr_binary2(ITM_EXPR_XOR_INVD_R, $1, $3);
				break;
			case ITM_EXPR_IN_VECTOR_D:
				$$ = expr_binary2(ITM_EXPR_XOR_INVD_INVD,
					$1, $3);
				break;
			default:
				$$ = expr_binary2(ITM_EXPR_XOR_INVD_E, $1, $3);
				break;
			}
			break;
		default:
			switch ($3->type) {
			case ITM_EXPR_INT:
				$$ = expr_binary2(ITM_EXPR_XOR_E_D, $1, $3);
				break;
			case ITM_EXPR_REG:
				$$ = expr_binary2(ITM_EXPR_XOR_E_R, $1, $3);
				break;
			case ITM_EXPR_IN_VECTOR_D:
				$$ = expr_binary2(ITM_EXPR_XOR_E_INVD, $1, $3);
				break;
			default:
				$$ = expr_binary2(ITM_EXPR_XOR, $1, $3);
				break;
			}
			break;
		}
	}
	| expr AND expr
	{
		TRACE_MESSAGE('y', ("expr: expr & expr\n"));
		$$ = expr_binary(ITM_EXPR_AND, $1, $3);
		$1 = expr_seq_to_int($1);
		$3 = expr_seq_to_int($3);
		switch ($1->type) {
		case ITM_EXPR_INT:
			switch ($3->type) {
			case ITM_EXPR_INT:
				$$ = expr_binary2(ITM_EXPR_AND_D_D, $1, $3);
				break;
			case ITM_EXPR_REG:
				$$ = expr_binary2(ITM_EXPR_AND_D_R, $1, $3);
				break;
			case ITM_EXPR_IN_VECTOR_D:
				$$ = expr_binary2(ITM_EXPR_AND_D_INVD, $1, $3);
				break;
			default:
				$$ = expr_binary2(ITM_EXPR_AND_D_E, $1, $3);
				break;
	}
			break;
		case ITM_EXPR_REG:
			switch ($3->type) {
			case ITM_EXPR_INT:
				$$ = expr_binary2(ITM_EXPR_AND_R_D, $1, $3);
				break;
			case ITM_EXPR_REG:
				$$ = expr_binary2(ITM_EXPR_AND_R_R, $1, $3);
				break;
			case ITM_EXPR_IN_VECTOR_D:
				$$ = expr_binary2(ITM_EXPR_AND_R_INVD, $1, $3);
				break;
			default:
				$$ = expr_binary2(ITM_EXPR_AND_R_E, $1, $3);
				break;
			}
			break;
		case ITM_EXPR_IN_VECTOR_D:
			switch ($3->type) {
			case ITM_EXPR_INT:
				$$ = expr_binary2(ITM_EXPR_AND_INVD_D, $1, $3);
				break;
			case ITM_EXPR_REG:
				$$ = expr_binary2(ITM_EXPR_AND_INVD_R, $1, $3);
				break;
			case ITM_EXPR_IN_VECTOR_D:
				$$ = expr_binary2(ITM_EXPR_AND_INVD_INVD,
					$1, $3);
				break;
			default:
				$$ = expr_binary2(ITM_EXPR_AND_INVD_E, $1, $3);
				break;
			}
			break;
		default:
			switch ($3->type) {
			case ITM_EXPR_INT:
				$$ = expr_binary2(ITM_EXPR_AND_E_D, $1, $3);
				break;
			case ITM_EXPR_REG:
				$$ = expr_binary2(ITM_EXPR_AND_E_R, $1, $3);
				break;
			case ITM_EXPR_IN_VECTOR_D:
				$$ = expr_binary2(ITM_EXPR_AND_E_INVD, $1, $3);
				break;
			default:
				$$ = expr_binary2(ITM_EXPR_AND, $1, $3);
				break;
			}
			break;
		}
	}
	| expr EQ expr
	{
		TRACE_MESSAGE('y', ("expr: expr == expr\n"));
		$$ = expr_binary(ITM_EXPR_EQ, $1, $3);
		$1 = expr_seq_to_int($1);
		$3 = expr_seq_to_int($3);
		switch ($1->type) {
		case ITM_EXPR_INT:
			switch ($3->type) {
			case ITM_EXPR_INT:
				$$ = expr_binary2(ITM_EXPR_EQ_D_D, $1, $3);
				break;
			case ITM_EXPR_REG:
				$$ = expr_binary2(ITM_EXPR_EQ_D_R, $1, $3);
				break;
			case ITM_EXPR_IN_VECTOR_D:
				$$ = expr_binary2(ITM_EXPR_EQ_D_INVD, $1, $3);
				break;
			default:
				$$ = expr_binary2(ITM_EXPR_EQ_D_E, $1, $3);
				break;
			}
			break;
		case ITM_EXPR_REG:
			switch ($3->type) {
			case ITM_EXPR_INT:
				$$ = expr_binary2(ITM_EXPR_EQ_R_D, $1, $3);
				break;
			case ITM_EXPR_REG:
				$$ = expr_binary2(ITM_EXPR_EQ_R_R, $1, $3);
				break;
			case ITM_EXPR_IN_VECTOR_D:
				$$ = expr_binary2(ITM_EXPR_EQ_R_INVD, $1, $3);
				break;
			default:
				$$ = expr_binary2(ITM_EXPR_EQ_R_E, $1, $3);
				break;
			}
			break;
		case ITM_EXPR_IN_VECTOR_D:
			switch ($3->type) {
			case ITM_EXPR_INT:
				$$ = expr_binary2(ITM_EXPR_EQ_INVD_D, $1, $3);
				break;
			case ITM_EXPR_REG:
				$$ = expr_binary2(ITM_EXPR_EQ_INVD_R, $1, $3);
				break;
			case ITM_EXPR_IN_VECTOR_D:
				$$ = expr_binary2(ITM_EXPR_EQ_INVD_INVD,
					$1, $3);
				break;
			default:
				$$ = expr_binary2(ITM_EXPR_EQ_INVD_E, $1, $3);
				break;
			}
			break;
		default:
			switch ($3->type) {
			case ITM_EXPR_INT:
				$$ = expr_binary2(ITM_EXPR_EQ_E_D, $1, $3);
				break;
			case ITM_EXPR_REG:
				$$ = expr_binary2(ITM_EXPR_EQ_E_R, $1, $3);
				break;
			case ITM_EXPR_IN_VECTOR_D:
				$$ = expr_binary2(ITM_EXPR_EQ_E_INVD, $1, $3);
				break;
			default:
				$$ = expr_binary2(ITM_EXPR_EQ, $1, $3);
				break;
			}
			break;
		}
	}
	| expr NE expr
	{
		TRACE_MESSAGE('y', ("expr: expr != expr\n"));
		$$ = expr_binary(ITM_EXPR_NE, $1, $3);
		$1 = expr_seq_to_int($1);
		$3 = expr_seq_to_int($3);
		switch ($1->type) {
		case ITM_EXPR_INT:
			switch ($3->type) {
			case ITM_EXPR_INT:
				$$ = expr_binary2(ITM_EXPR_NE_D_D, $1, $3);
				break;
			case ITM_EXPR_REG:
				$$ = expr_binary2(ITM_EXPR_NE_D_R, $1, $3);
				break;
			case ITM_EXPR_IN_VECTOR_D:
				$$ = expr_binary2(ITM_EXPR_NE_D_INVD, $1, $3);
				break;
			default:
				$$ = expr_binary2(ITM_EXPR_NE_D_E, $1, $3);
				break;
			}
			break;
		case ITM_EXPR_REG:
			switch ($3->type) {
			case ITM_EXPR_INT:
				$$ = expr_binary2(ITM_EXPR_NE_R_D, $1, $3);
				break;
			case ITM_EXPR_REG:
				$$ = expr_binary2(ITM_EXPR_NE_R_R, $1, $3);
				break;
			case ITM_EXPR_IN_VECTOR_D:
				$$ = expr_binary2(ITM_EXPR_NE_R_INVD, $1, $3);
				break;
			default:
				$$ = expr_binary2(ITM_EXPR_NE_R_E, $1, $3);
				break;
			}
			break;
		case ITM_EXPR_IN_VECTOR_D:
			switch ($3->type) {
			case ITM_EXPR_INT:
				$$ = expr_binary2(ITM_EXPR_NE_INVD_D, $1, $3);
				break;
			case ITM_EXPR_REG:
				$$ = expr_binary2(ITM_EXPR_NE_INVD_R, $1, $3);
				break;
			case ITM_EXPR_IN_VECTOR_D:
				$$ = expr_binary2(ITM_EXPR_NE_INVD_INVD,
					$1, $3);
				break;
			default:
				$$ = expr_binary2(ITM_EXPR_NE_INVD_E, $1, $3);
				break;
			}
			break;
		default:
			switch ($3->type) {
			case ITM_EXPR_INT:
				$$ = expr_binary2(ITM_EXPR_NE_E_D, $1, $3);
				break;
			case ITM_EXPR_REG:
				$$ = expr_binary2(ITM_EXPR_NE_E_R, $1, $3);
				break;
			case ITM_EXPR_IN_VECTOR_D:
				$$ = expr_binary2(ITM_EXPR_NE_E_INVD, $1, $3);
				break;
			default:
				$$ = expr_binary2(ITM_EXPR_NE, $1, $3);
				break;
			}
			break;
		}
	}
	| expr GT  expr
	{
		TRACE_MESSAGE('y', ("expr: expr > expr\n"));
		$$ = expr_binary(ITM_EXPR_GT, $1, $3);
		$1 = expr_seq_to_int($1);
		$3 = expr_seq_to_int($3);
		switch ($1->type) {
		case ITM_EXPR_INT:
			switch ($3->type) {
			case ITM_EXPR_INT:
				$$ = expr_binary2(ITM_EXPR_GT_D_D, $1, $3);
				break;
			case ITM_EXPR_REG:
				$$ = expr_binary2(ITM_EXPR_GT_D_R, $1, $3);
				break;
			case ITM_EXPR_IN_VECTOR_D:
				$$ = expr_binary2(ITM_EXPR_GT_D_INVD, $1, $3);
				break;
			default:
				$$ = expr_binary2(ITM_EXPR_GT_D_E, $1, $3);
				break;
			}
			break;
		case ITM_EXPR_REG:
			switch ($3->type) {
			case ITM_EXPR_INT:
				$$ = expr_binary2(ITM_EXPR_GT_R_D, $1, $3);
				break;
			case ITM_EXPR_REG:
				$$ = expr_binary2(ITM_EXPR_GT_R_R, $1, $3);
				break;
			case ITM_EXPR_IN_VECTOR_D:
				$$ = expr_binary2(ITM_EXPR_GT_R_INVD, $1, $3);
				break;
			default:
				$$ = expr_binary2(ITM_EXPR_GT_R_E, $1, $3);
				break;
			}
			break;
		case ITM_EXPR_IN_VECTOR_D:
			switch ($3->type) {
			case ITM_EXPR_INT:
				$$ = expr_binary2(ITM_EXPR_GT_INVD_D, $1, $3);
				break;
			case ITM_EXPR_REG:
				$$ = expr_binary2(ITM_EXPR_GT_INVD_R, $1, $3);
				break;
			case ITM_EXPR_IN_VECTOR_D:
				$$ = expr_binary2(ITM_EXPR_GT_INVD_INVD,
					$1, $3);
				break;
			default:
				$$ = expr_binary2(ITM_EXPR_GT_INVD_E, $1, $3);
				break;
			}
			break;
		default:
			switch ($3->type) {
			case ITM_EXPR_INT:
				$$ = expr_binary2(ITM_EXPR_GT_E_D, $1, $3);
				break;
			case ITM_EXPR_REG:
				$$ = expr_binary2(ITM_EXPR_GT_E_R, $1, $3);
				break;
			case ITM_EXPR_IN_VECTOR_D:
				$$ = expr_binary2(ITM_EXPR_GT_E_INVD, $1, $3);
				break;
			default:
				$$ = expr_binary2(ITM_EXPR_GT, $1, $3);
				break;
			}
			break;
		}
	}
	| expr GE  expr
	{
		TRACE_MESSAGE('y', ("expr: expr >= expr\n"));
		$$ = expr_binary(ITM_EXPR_GE, $1, $3);
		$1 = expr_seq_to_int($1);
		$3 = expr_seq_to_int($3);
		switch ($1->type) {
		case ITM_EXPR_INT:
			switch ($3->type) {
			case ITM_EXPR_INT:
				$$ = expr_binary2(ITM_EXPR_GE_D_D, $1, $3);
				break;
			case ITM_EXPR_REG:
				$$ = expr_binary2(ITM_EXPR_GE_D_R, $1, $3);
				break;
			case ITM_EXPR_IN_VECTOR_D:
				$$ = expr_binary2(ITM_EXPR_GE_D_INVD, $1, $3);
				break;
			default:
				$$ = expr_binary2(ITM_EXPR_GE_D_E, $1, $3);
				break;
			}
			break;
		case ITM_EXPR_REG:
			switch ($3->type) {
			case ITM_EXPR_INT:
				$$ = expr_binary2(ITM_EXPR_GE_R_D, $1, $3);
				break;
			case ITM_EXPR_REG:
				$$ = expr_binary2(ITM_EXPR_GE_R_R, $1, $3);
				break;
			case ITM_EXPR_IN_VECTOR_D:
				$$ = expr_binary2(ITM_EXPR_GE_R_INVD, $1, $3);
				break;
			default:
				$$ = expr_binary2(ITM_EXPR_GE_R_E, $1, $3);
				break;
			}
			break;
		case ITM_EXPR_IN_VECTOR_D:
			switch ($3->type) {
			case ITM_EXPR_INT:
				$$ = expr_binary2(ITM_EXPR_GE_INVD_D, $1, $3);
				break;
			case ITM_EXPR_REG:
				$$ = expr_binary2(ITM_EXPR_GE_INVD_R, $1, $3);
				break;
			case ITM_EXPR_IN_VECTOR_D:
				$$ = expr_binary2(ITM_EXPR_GE_INVD_INVD,
					$1, $3);
				break;
			default:
				$$ = expr_binary2(ITM_EXPR_GE_INVD_E, $1, $3);
				break;
			}
			break;
		default:
			switch ($3->type) {
			case ITM_EXPR_INT:
				$$ = expr_binary2(ITM_EXPR_GE_E_D, $1, $3);
				break;
			case ITM_EXPR_REG:
				$$ = expr_binary2(ITM_EXPR_GE_E_R, $1, $3);
				break;
			case ITM_EXPR_IN_VECTOR_D:
				$$ = expr_binary2(ITM_EXPR_GE_E_INVD, $1, $3);
				break;
			default:
				$$ = expr_binary2(ITM_EXPR_GE, $1, $3);
				break;
			}
			break;
		}
	}
	| expr LT  expr
	{
		TRACE_MESSAGE('y', ("expr: expr < expr\n"));
		$$ = expr_binary(ITM_EXPR_LT, $1, $3);
		$1 = expr_seq_to_int($1);
		$3 = expr_seq_to_int($3);
		switch ($1->type) {
		case ITM_EXPR_INT:
			switch ($3->type) {
			case ITM_EXPR_INT:
				$$ = expr_binary2(ITM_EXPR_LT_D_D, $1, $3);
				break;
			case ITM_EXPR_REG:
				$$ = expr_binary2(ITM_EXPR_LT_D_R, $1, $3);
				break;
			case ITM_EXPR_IN_VECTOR_D:
				$$ = expr_binary2(ITM_EXPR_LT_D_INVD, $1, $3);
				break;
			default:
				$$ = expr_binary2(ITM_EXPR_LT_D_E, $1, $3);
				break;
			}
			break;
		case ITM_EXPR_REG:
			switch ($3->type) {
			case ITM_EXPR_INT:
				$$ = expr_binary2(ITM_EXPR_LT_R_D, $1, $3);
				break;
			case ITM_EXPR_REG:
				$$ = expr_binary2(ITM_EXPR_LT_R_R, $1, $3);
				break;
			case ITM_EXPR_IN_VECTOR_D:
				$$ = expr_binary2(ITM_EXPR_LT_R_INVD, $1, $3);
				break;
			default:
				$$ = expr_binary2(ITM_EXPR_LT_R_E, $1, $3);
				break;
			}
			break;
		case ITM_EXPR_IN_VECTOR_D:
			switch ($3->type) {
			case ITM_EXPR_INT:
				$$ = expr_binary2(ITM_EXPR_LT_INVD_D, $1, $3);
				break;
			case ITM_EXPR_REG:
				$$ = expr_binary2(ITM_EXPR_LT_INVD_R, $1, $3);
				break;
			case ITM_EXPR_IN_VECTOR_D:
				$$ = expr_binary2(ITM_EXPR_LT_INVD_INVD,
					$1, $3);
				break;
			default:
				$$ = expr_binary2(ITM_EXPR_LT_INVD_E, $1, $3);
				break;
			}
			break;
		default:
			switch ($3->type) {
			case ITM_EXPR_INT:
				$$ = expr_binary2(ITM_EXPR_LT_E_D, $1, $3);
				break;
			case ITM_EXPR_REG:
				$$ = expr_binary2(ITM_EXPR_LT_E_R, $1, $3);
				break;
			case ITM_EXPR_IN_VECTOR_D:
				$$ = expr_binary2(ITM_EXPR_LT_E_INVD, $1, $3);
				break;
			default:
				$$ = expr_binary2(ITM_EXPR_LT, $1, $3);
				break;
				}
			break;
		}
	}
	| expr LE  expr
	{
		TRACE_MESSAGE('y', ("expr: expr <= expr\n"));
		$$ = expr_binary(ITM_EXPR_LE, $1, $3);
		$1 = expr_seq_to_int($1);
		$3 = expr_seq_to_int($3);
		switch ($1->type) {
		case ITM_EXPR_INT:
			switch ($3->type) {
			case ITM_EXPR_INT:
				$$ = expr_binary2(ITM_EXPR_LE_D_D, $1, $3);
				break;
			case ITM_EXPR_REG:
				$$ = expr_binary2(ITM_EXPR_LE_D_R, $1, $3);
				break;
			case ITM_EXPR_IN_VECTOR_D:
				$$ = expr_binary2(ITM_EXPR_LE_D_INVD, $1, $3);
				break;
			default:
				$$ = expr_binary2(ITM_EXPR_LE_D_E, $1, $3);
				break;
			}
			break;
		case ITM_EXPR_REG:
			switch ($3->type) {
			case ITM_EXPR_INT:
				$$ = expr_binary2(ITM_EXPR_LE_R_D, $1, $3);
				break;
			case ITM_EXPR_REG:
				$$ = expr_binary2(ITM_EXPR_LE_R_R, $1, $3);
				break;
			case ITM_EXPR_IN_VECTOR_D:
				$$ = expr_binary2(ITM_EXPR_LE_R_INVD, $1, $3);
				break;
			default:
				$$ = expr_binary2(ITM_EXPR_LE_R_E, $1, $3);
				break;
			}
			break;
		case ITM_EXPR_IN_VECTOR_D:
			switch ($3->type) {
			case ITM_EXPR_INT:
				$$ = expr_binary2(ITM_EXPR_LE_INVD_D, $1, $3);
				break;
			case ITM_EXPR_REG:
				$$ = expr_binary2(ITM_EXPR_LE_INVD_R, $1, $3);
				break;
			case ITM_EXPR_IN_VECTOR_D:
				$$ = expr_binary2(ITM_EXPR_LE_INVD_INVD,
					$1, $3);
				break;
			default:
				$$ = expr_binary2(ITM_EXPR_LE_INVD_E, $1, $3);
				break;
			}
			break;
		default:
			switch ($3->type) {
			case ITM_EXPR_INT:
				$$ = expr_binary2(ITM_EXPR_LE_E_D, $1, $3);
				break;
			case ITM_EXPR_REG:
				$$ = expr_binary2(ITM_EXPR_LE_E_R, $1, $3);
				break;
			case ITM_EXPR_IN_VECTOR_D:
				$$ = expr_binary2(ITM_EXPR_LE_E_INVD, $1, $3);
				break;
			default:
				$$ = expr_binary2(ITM_EXPR_LE, $1, $3);
				break;
			}
			break;
		}
	}
	| name ASSIGN expr
	{
		TRACE_MESSAGE('y', ("expr: NAME = expr\n"));
		$$ = expr_assign(ITM_EXPR_ASSIGN, $1, $3);
	}
	| expr LOR expr
	{
		TRACE_MESSAGE('y', ("expr: expr || expr\n"));
		$$ = expr_binary(ITM_EXPR_LOR, $1, $3);
	}
	| expr LAND expr
	{
		TRACE_MESSAGE('y', ("expr: expr && expr\n"));
		$$ = expr_binary(ITM_EXPR_LAND, $1, $3);
	}
	;

%%
