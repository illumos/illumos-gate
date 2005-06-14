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
 * Copyright (c) 1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_FCODE_DEBUG_H
#define	_FCODE_DEBUG_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#define	DEBUG_CONTEXT		0x00000001
#define	DEBUG_BYTELOAD_DS	0x00000002
#define	DEBUG_BYTELOAD_RS	0x00000004
#define	DEBUG_BYTELOAD_TOKENS	0x00000008
#define	DEBUG_NEW_TOKEN		0x00000010
#define	DEBUG_EXEC_TRACE	0x00000020
#define	DEBUG_EXEC_SHOW_VITALS	0x00000040
#define	DEBUG_EXEC_DUMP_DS	0x00000080
#define	DEBUG_EXEC_DUMP_RS	0x00000100
#define	DEBUG_COMMA		0x00000200
#define	DEBUG_HEADER		0x00000400
#define	DEBUG_EXIT_WORDS	0x00000800
#define	DEBUG_EXIT_DUMP		0x00001000
#define	DEBUG_DUMP_TOKENS	0x00002000
#define	DEBUG_COLON		0x00004000
#define	DEBUG_NEXT_VITALS	0x00008000
#define	DEBUG_UPLOAD		0x00010000
#define	DEBUG_VOC_FIND		0x00020000
#define	DEBUG_DUMP_DICT_TOKENS	0x00040000
#define	DEBUG_TOKEN_USAGE	0x00080000
#define	DEBUG_DUMP_TOKEN_TABLE	0x00100000
#define	DEBUG_SHOW_STACK	0x00200000
#define	DEBUG_SHOW_RS		0x00400000
#define	DEBUG_TRACING		0x00800000
#define	DEBUG_TRACE_STACK	0x01000000
#define	DEBUG_CALL_METHOD	0x02000000
#define	DEBUG_ACTIONS		0x04000000
#define	DEBUG_STEPPING		0x08000000
#define	DEBUG_REG_ACCESS	0x10000000
#define	DEBUG_ADDR_ABUSE	0x20000000
#define	DEBUG_FIND_FCODE	0x40000000

#define	DEBUG_ANY		0xffffffff

#ifdef	__cplusplus
}
#endif

#endif /* _FCODE_DEBUG_H */
