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

#ifndef _RPC_SCAN_H
#define	_RPC_SCAN_H

/*
 * rpc_scan.h, Definitions for the RPCL scanner
 */

#ifdef __cplusplus
extern "C" {
#endif

/*
 * kinds of tokens
 */
enum tok_kind {
	TOK_IDENT,
	TOK_CHARCONST,
	TOK_STRCONST,
	TOK_LPAREN,
	TOK_RPAREN,
	TOK_LBRACE,
	TOK_RBRACE,
	TOK_LBRACKET,
	TOK_RBRACKET,
	TOK_LANGLE,
	TOK_RANGLE,
	TOK_STAR,
	TOK_COMMA,
	TOK_EQUAL,
	TOK_COLON,
	TOK_SEMICOLON,
	TOK_CONST,
	TOK_STRUCT,
	TOK_UNION,
	TOK_SWITCH,
	TOK_CASE,
	TOK_DEFAULT,
	TOK_ENUM,
	TOK_TYPEDEF,
	TOK_INT,
	TOK_SHORT,
	TOK_LONG,
	TOK_HYPER,
	TOK_UNSIGNED,
	TOK_FLOAT,
	TOK_DOUBLE,
	TOK_QUAD,
	TOK_OPAQUE,
	TOK_CHAR,
	TOK_STRING,
	TOK_BOOL,
	TOK_VOID,
	TOK_ONEWAY,
	TOK_PROGRAM,
	TOK_VERSION,
	TOK_EOF
};
typedef enum tok_kind tok_kind;

/*
 * a token
 */
struct token {
	tok_kind kind;
	char *str;
};
typedef struct token token;

/*
 * routine interface
 */
extern void scan(tok_kind, token *);
extern void scan2(tok_kind, tok_kind, token *);
extern void scan3(tok_kind, tok_kind, tok_kind, token *);
extern void scan_num(token *);
extern void peek(token *);
extern int peekscan(tok_kind, token *);
extern void get_token(token *);

#ifdef __cplusplus
}
#endif

#endif /* _RPC_SCAN_H */
