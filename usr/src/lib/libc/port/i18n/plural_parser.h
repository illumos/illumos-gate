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
 */
/*
 * Copyright (c) 2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_LIBC_PORT_I18N_PLURAL_PARSER_H
#define	_LIBC_PORT_I18N_PLURAL_PARSER_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#define	PEEK_TOKEN	0
#define	GET_TOKEN	1

#define	NARY	0
#define	UNARY	1
#define	BINARY	2
#define	TRINARY	3

#define	T_NULL	0x00000000
#define	T_INIT	0x00000001
#define	T_EXP	0x00000002
#define	T_NUM	0x00000003
#define	T_VAR	0x00000004
#define	T_CONDC	0x00000005
#define	T_CONDQ	0x00000006
#define	T_LOR	0x00000007
#define	T_LAND	0x00000008
#define	T_EQ	0x00000009
#define	T_NEQ	0x0000000a
#define	T_GT	0x0000000b
#define	T_LT	0x0000000c
#define	T_GE	0x0000000d
#define	T_LE	0x0000000e
#define	T_ADD	0x0000000f
#define	T_SUB	0x00000010
#define	T_MUL	0x00000011
#define	T_DIV	0x00000012
#define	T_MOD	0x00000013
#define	T_LNOT	0x00000014
#define	T_LPAR	0x00000015
#define	T_RPAR	0x00000016
#define	T_ERR	0x00000017

#define	GETTYPE(op)	((op) & 0x000fffff)
#define	GETPRIO(op)	(((op) & 0x0ff00000) >> 20)
#define	GETOPNUM(op)	(((op) & 0xf0000000) >> 28)

#define	MAX_STACK_SIZE	128

struct expr {
	unsigned int	op;		/* operator */
	unsigned int	num;	/* T_NUM */
	unsigned int	flag;	/* flag for the previous op */
	struct expr	*nodes[3];	/* operands */
};

struct stack {
	int	index;
	struct expr	**ptr;
};

#ifdef	__cplusplus
}
#endif

#endif	/* _LIBC_PORT_I18N_PLURAL_PARSER_H */
