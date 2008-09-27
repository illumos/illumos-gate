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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_ROCKASI_H
#define	_SYS_ROCKASI_H

/*
 * alternate address space identifiers
 *
 * 0x00 - 0x2F are privileged
 * 0x30 - 0x7f are hyperprivileged
 * 0x80 - 0xFF can be used by non-privileged, privileged & hyperprivileged
 */

#ifdef __cplusplus
extern "C" {
#endif

/*
 * ROCK specific ASIs
 */
#define	ASI_CACHE_SPARING_P	0xF4	/* Cache sparing */

#ifndef	_ASM
struct	cpsregs {
	uint64_t	fails;
	uint64_t	exog;
	uint64_t	coh;
	uint64_t	tcc;
	uint64_t	instr;
	uint64_t	precise;
	uint64_t	async;
	uint64_t	size;
	uint64_t	ld;
	uint64_t	st;
	uint64_t	cti;
	uint64_t	fp;
	uint64_t	zeros;
};
#endif	/* _ASM */
#ifdef __cplusplus
}
#endif

#endif /* _SYS_ROCKASI_H */
