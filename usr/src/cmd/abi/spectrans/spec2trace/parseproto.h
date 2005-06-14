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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_PARSEPROTO_H
#define	_PARSEPROTO_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * DECL - parse C type declarations.
 *
 * 1) Does not understand struct, union or enum definitions.
 * 2) Does not understand auto, static, extern or typedef storage class
 *    specifiers.
 * 3) Does not support initialization.
 * 4) Does not support type definition.
 * 5) Only understands array dimension specified as constant decimal
 *    integer or identifier.
 *
 * Supported Operations
 *
 *    decl_Parse        convert string to a decl_t.
 *    decl_Destroy      Free space associated with a (previously returned)
 *                      decl_t. The function follows the argument list.
 *    decl_SetName      set identifier.
 *    decl_GetName      return identifier.
 *    decl_ToString     convert a (previously returned) decl_t into a
 *                      printable representation.
 *    decl_GetArgLength return length of argument list.
 *    decl_GetNext      return the next decl_t associated with the given
 *                      decl_t.
 *    decl_GetDeclSpec	return the declaration specifier.
 *    decl_GetDSName    return identifier associated with a
 *			declaration specifier.
 *    decl_GetType      return the type_t associated with a decl_t.
 *    decl_IsVarargs    return true if the given decl_t is a varargs function.
 *    decl_IsFunction   return true if the given decl_t is a function.
 *
 *    type_GetNext      return the next type_t associated with a given type_t.
 *    type_IsArray      return true if the given type_t is an array.
 *    type_GetArraySize return size of array.
 *
 *    type_IsPtrTo      return true if the given type_t is a pointer to ... .
 *    type_GetPtrToTypeQual    return type qualifiers for a pointer to ... .
 *
 *    type_IsFunction   return true if the given type_t is a function.
 *    type_GetArgLength return length of argument list.
 *    type_IsVarargs    return true if function signature includes ... .
 *    type_GetArg       return the decl_t associated with a given type_t.
 *    type_IsPtrFun     return true if the given type_t is a pointer* to a
 *                      function.
 */

/* Include Files */

#include <stdio.h>
#include <ctype.h>
#include <string.h>

/* Macros and Constants */

#define	loop	for (;;)

#define	STT_isvoid(s)	((s) & (TS_VOID))
#define	STT_isfloat(s)	((s) & (TS_FLOAT | TS_DOUBLE))
#define	STT_ischar(s)	((s) & (TS_CHAR))
#define	STT_isint(s)	((s) & \
			(TS_SHORT | TS_INT | TS_LONG | TS_LONGLONG | TS_CHAR))
#define	STT_isarith(s)	(STT_isfloat(s) || STT_isint(s))
#define	STT_isbasic(s)	(STT_isarith(s) || STT_isvoid(s))
#define	STT_isderived(s) ((s) & (TS_STRUCT | TS_UNION | TS_ENUM | TS_TYPEDEF))
#define	STT_has_explicit_sign(s)	((s) & (TS_SIGNED | TS_UNSIGNED))

/* Data Declarations */

/*
 * The overall type encoding is thus:
 *
 *    decl_t encodes a declaration which consists of:
 *        identifier
 *            declaration specifier (storage class specifier, type specifier,
 *              type qualifier)
 *            type modifiers (array, function, pointer to)
 *              ancillary (varargs?, argument list)
 *
 *    The argument list is an ordered, NULL terminated, linked list.
 *
 *    An empty argument list (== NULL) indicates an unknown argument
 *       list, i.e. "()".
 *
 *    declaration specifiers are encoded as bits in an enum (stt_t).
 *
 *    type modifiers are encoded as a linked list of variant records,
 *        i.e. "array of ..."
 *		"function returning ..." and "pointer to ...".
 *
 *    An empty list of type modifiers (== NULL) indicates a "plain" type.
 *
 *
 * OK, here goes some ASCII art...
 *
 *
 * base object
 *     |
 *     |
 *     V
 *
 * ----------      ----------      ----------       ----------
 * |        |      |        |      |        |       |        |
 * | decl_t |  --> | type_t |  --> | type_t |  ...  | type_t |  --> NULL
 * |        |      |        |      |(DD_FUN)|       |        |
 * ----------      ----------      ----------       ----------
 *     |                               |
 *     |                               |
 *     V                               V
 *                           A     ----------      ----------
 *    NULL                   r     |        |      |        |
 *                           g     | decl_t |  --> | type_t |  ... --> NULL
 *                           u     |        |      |        |
 *                           m     ----------      ----------
 *                           e         |
 *                           n         |
 *                           t         V
 *                                 ----------
 *                           L     |        |
 *                           i     | decl_t |  ... --> NULL
 *                           s     |        |
 *                           t     ----------
 *
 *                                    ...
 *
 *                                     |
 *	                               |
 *	                               V
 *
 *	                              NULL
 */

/*
 * The encoding of a declaration specifier is done primarily with an
 * stt_t type.
 * This type must support bit-wise operations.
 */

typedef enum {
	SCS_MASK	= 0x000000ff,	/* storage class specifiers */
	SCS_NONE	= 0x00000000,
	SCS_REGISTER	= 0x00000001,
	SCS_TYPEDEF	= 0x00000002,
	SCS_EXTERN	= 0x00000004,
	SCS_AUTO	= 0x00000008,
	SCS_STATIC	= 0x00000010,

	TS_MASK		= 0x00ffff00,	/* type specifiers */
	TS_NO_TS	= 0x00000000,
	TS_CHAR		= 0x00000100,
	TS_SHORT	= 0x00000200,
	TS_INT		= 0x00000400,
	TS_LONG		= 0x00000800,
	TS_SIGNED	= 0x00001000,
	TS_UNSIGNED	= 0x00002000,
	TS_ENUM		= 0x00004000,
	TS_FLOAT	= 0x00010000,
	TS_DOUBLE	= 0x00020000,
	TS_STRUCT	= 0x00040000,
	TS_UNION	= 0x00080000,
	TS_TYPEDEF	= 0x00100000,
	TS_VOID		= 0x00200000,
	TS_LONGLONG	= 0x00400000,	/* non-ANSI type: long long */

	TQ_MASK		= 0x0f000000,	/* type qualifiers */
	TQ_NONE		= 0x00000000,
	TQ_CONST	= 0x01000000,
	TQ_VOLATILE	= 0x02000000,
	TQ_RESTRICT	= 0x04000000,
	TQ_RESTRICT_KYWD = 0x08000000
} stt_t;

typedef enum {			/* declarator options */
	DD_NONE	= 0,
	DD_ARY	= 1,		/* array of [size] ... */
	DD_FUN	= 2,		/* function [taking and] returning ... */
	DD_PTR	= 3		/* [tq] pointer to ... */
} decl_type_t;

typedef enum {
	DTS_DECL = 0,
	DTS_CAST = 1,
	DTS_RET  = 3
} decl_dts_t;

typedef struct {
	stt_t	 ds_stt;	/* scs|ts|tq */
	char	*ds_id;		/* id for struct|union|enum|typedef */
} decl_spec_t;

typedef struct _declarator	decl_t;

typedef struct _type {
	struct _type	*t_next;	/* next type_t or NULL */
	decl_type_t	 t_dt;		/* oneof DD_* */
	/* DD_FUN */
	int		 t_nargs;	/* number of arguments */
	int		 t_ellipsis;	/* a varargs? */
	decl_t		*t_args;	/* list of arguments */
	/* DD_PTR */
	stt_t		 t_stt;		/* type qualifier, TQ_* */
	/* DD_ARY */
	char		*t_sizestr;	/* size as a string */
} type_t;

struct _declarator {
	char		*d_name;	/* name of declarator */
	decl_spec_t	*d_ds;		/* ts|scs|tq */
	type_t		*d_type;	/* list of attributes or NULL */
	int		 d_ellipsis;	/* a varargs? */
	decl_t		*d_next;	/* next link in chain (arglist) */
};

/* External Declarations */

extern	char		*declspec_ToString(char *, decl_spec_t *);

extern	void		decl_Destroy(decl_t *);
extern	int		decl_GetArgLength(decl_t *);
extern	decl_t		*decl_SetName(decl_t *, char *);
extern	char		*decl_GetName(decl_t *);
extern	type_t		*decl_GetType(decl_t *);
extern	int		decl_IsVarargs(decl_t *dp);
extern	char		*decl_ToString(char *, decl_dts_t, decl_t *,
			    const char *);
extern	const char	*decl_Parse(char *, decl_t **);
extern	void		decl_GetTraceInfo(decl_t *, char *, char *, decl_t **);
extern	char 		*decl_ToFormal(decl_t *);
extern	int		type_IsArray(type_t *);
extern	int		type_IsPtrTo(type_t *);
extern	int		type_IsFunction(type_t *);
extern	int		type_IsVarargs(type_t *);
extern	int		type_IsPtrFun(type_t *);
extern	decl_t		*decl_AddArgNames(decl_t *);

#ifdef	__cplusplus
}
#endif

#endif	/* _PARSEPROTO_H */
