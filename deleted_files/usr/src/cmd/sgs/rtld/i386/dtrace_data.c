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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>

/*
 * In order to let the DTrace fasttrap provider trace processes before libc
 * is initialized, we place this structure in the thread pointer register.
 * This is communicated to the kernel (in the elfexec() function) by
 * placing the address of this structure in the PT_SUNWDTRACE program header
 * with the -zdtrace_data=<object> option to ld.
 *
 * The fields of the program header are set as follows:
 *	p_type:         PT_SUNWDTRACE
 *	p_vaddr:        address of dtrace_data
 *	p_memsz:        size of dtrace_data
 *	p_flags:        flags of segment dtrace_data is assigned to
 *	p_paddr:        <reserved>
 *	p_filesz:       <reserved>
 *	p_offset:       <reserved>
 *	p_align:        <reserved>
 *
 * See the comment in fasttrap.h for information on how to safely change
 * this data structure and the other places that need to be kept in sync.
 */
#pragma align 64(dtrace_data)
uint8_t	dtrace_data[64] = {
	0, 0, 0, 0,			/* self pointer (must be zero)  */
	0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0
};
