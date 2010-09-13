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

#ifndef _LPAD_H
#define	_LPAD_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * sun4v Landing Pad
 */

#ifdef __cplusplus
extern "C" {
#endif

#ifndef _ASM

#include <sys/pte.h>

typedef union {
	struct {
		unsigned int	rsvd0:32;
		unsigned int	rsvd1:29;
		unsigned int	perm:1;
		unsigned int	mmuflags:2;
	} flag_bits;
	uint64_t	ll;
} lpad_map_flag_t;

typedef struct lpad_map {
	lpad_map_flag_t	flags;
	uint64_t	va;
	tte_t		tte;
} lpad_map_t;

#define	flag_mmuflags	flags.flag_bits.mmuflags
#define	flag_perm	flags.flag_bits.perm

typedef struct lpad_data {
	uint64_t	magic;		/* magic value for sanity checking */
	uint64_t	*inuse;		/* clear flag when done with lpad */
	uint64_t	mmfsa_ra;	/* RA of MMU fault status area */
	uint64_t	pc;		/* VA of CPU startup function */
	uint64_t	arg;		/* argument to startup function */
	uint64_t	nmap;		/* number of mappings */
	lpad_map_t	map[1];		/* array of mappings */
} lpad_data_t;

extern uint64_t *lpad_setup(int cpuid, uint64_t pc, uint64_t arg);

#endif /* ! _ASM */

/*
 * General landing pad constants
 */
#define	LPAD_TEXT_SIZE		1024
#define	LPAD_DATA_SIZE		1024
#define	LPAD_SIZE		(LPAD_TEXT_SIZE + LPAD_DATA_SIZE)
#define	LPAD_MAGIC_VAL		0x4C502D4D41474943	/* "LP-MAGIC" */

/*
 * Masks for the lpad_map_t flag bitfield
 */
#define	FLAG_MMUFLAGS_MASK	0x3
#define	FLAG_LOCK_MASK		0x4

#ifdef __cplusplus
}
#endif

#endif /* _LPAD_H */
