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

#ifndef	_SAVEARGS_H
#define	_SAVEARGS_H

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>

/*
 * The longest instruction sequence in bytes before all 6 arguments are
 * saved on the stack.  This value depends on compiler implementation,
 * therefore it should be examined periodically to guarantee accuracy.
 */
#define	SAVEARGS_INSN_SEQ_LEN	256

#define	SAVEARGS_NO_ARGS	0	/* no saved arguments */
#define	SAVEARGS_TRAD_ARGS	1	/* traditionally located arguments */
#define	SAVEARGS_STRUCT_ARGS	2	/* struct return addr pushed as arg0 */

int saveargs_has_args(uint8_t *, size_t, uint_t, int);

#ifdef __cplusplus
}
#endif

#endif	/* _SAVEARGS_H */
