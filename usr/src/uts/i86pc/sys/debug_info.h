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

#ifndef _SYS_DEBUG_INFO_H
#define	_SYS_DEBUG_INFO_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#define	DEBUG_INFO_MAGIC 0xdeb116ed
#define	DEBUG_INFO_VERSION 0x1

/*
 * We place this structure at a well-known DEBUG_INFO_VA to allow 'external'
 * debuggers to bootstrap themselves; in particular libkvm when applied to
 * hypervisor domains or their core files.
 */
typedef struct debug_info {
	uint32_t di_magic;
	uint32_t di_version;
	/* address of 'modules' */
	uintptr_t di_modules;
	uintptr_t di_s_text;
	uintptr_t di_e_text;
	uintptr_t di_s_data;
	uintptr_t di_e_data;
	size_t di_hat_htable_off;
	size_t di_ht_pfn_off;
} debug_info_t;

#ifdef	__cplusplus
}
#endif

#endif /* _SYS_DEBUG_INFO_H */
