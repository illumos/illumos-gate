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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright (c)  * Copyright (c) 2001 Tadpole Technology plc
 * All rights reserved.
 */

#ifndef	_SYS_CARDBUS_IMPL_H
#define	_SYS_CARDBUS_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef  __cplusplus
extern "C" {
#endif

/*
 * Device property initialization structures and defines
 */
struct cb_deviceset_props {
	struct cb_deviceset_props *next;
	char	*binding_name;
	uint16_t	venid;
	uint16_t	devid;
	char	*nodename;
	ddi_prop_t	*prop_list;
};

typedef struct {
	char	*token;	/* token to look for */
	int	state;	/* state machine state */
} cb_props_parse_tree_t;

#define	PARSE_QUOTE		'\''
#define	PARSE_COMMENT		'#'
#define	PARSE_ESCAPE		'\\'
#define	PARSE_UNDERSCORE	'_'
#define	PARSE_DASH		'-'
#define	PARSE_SEMICOLON		';'
#define	PARSE_COMMA		','
#define	PARSE_EQUALS		'='

/*
 * state defines for the valued variable state machine
 */
#define	PT_STATE_UNKNOWN	0
#define	PT_STATE_TOKEN		1
#define	PT_STATE_STRING_VAR	2
#define	PT_STATE_HEX_VAR	3
#define	PT_STATE_DEC_VAR	4
#define	PT_STATE_ESCAPE		5
#define	PT_STATE_CHECK		6

#undef	isalpha
#undef	isxdigit
#undef	ixdigit
#undef	toupper

#define	isalpha(ch)	(((ch) >= 'a' && (ch) <= 'z') || \
			((ch) >= 'A' && (ch) <= 'Z'))
#define	isxdigit(ch)	(isdigit(ch) || ((ch) >= 'a' && (ch) <= 'f') || \
			((ch) >= 'A' && (ch) <= 'F'))
#define	isx(ch)		((ch) == 'x' || (ch) == 'X')
#define	isdigit(ch)	((ch) >= '0' && (ch) <= '9')
#define	toupper(C)	(((C) >= 'a' && (C) <= 'z')? (C) - 'a' + 'A': (C))

#ifdef  __cplusplus
}
#endif

#endif	/* _SYS_CARDBUS_IMPL_H */
