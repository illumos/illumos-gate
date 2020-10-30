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
 * Copyright (c) 1995, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <stdio.h>
#include "rdb.h"

typedef char *(*FUNCPTR)();

/*
 * stub routine until I can figure out what to plug in here.
 */
/* ARGSUSED 1 */
char *
disassemble(unsigned int instr, unsigned long pc, FUNCPTR prtAddress,
    unsigned int next, unsigned int prev, int vers)
{
	static char	buf[256];

	(void) snprintf(buf, 256, "0x%x", instr);

	return (buf);
}
