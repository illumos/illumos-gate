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

#ifndef _FB_RANDOM_H
#define	_FB_RANDOM_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "config.h"

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * probability table entry, used while parsing the supplied
 * probability table
 */
typedef struct probtabent {
	struct probtabent	*pte_next;
	avd_t			pte_percent;
	avd_t			pte_segmin;
	avd_t			pte_segmax;
} probtabent_t;

/*
 * The supplied probability table is converted into a probability funtion
 * lookup table at initialization time. This is the definition for each
 * entry in the table.
 */
typedef struct randfunc {
	double		rf_base;
	double		rf_range;
} randfunc_t;

/* Number of entries in the probability function table */
#define	PF_TAB_SIZE	100

/*
 * Random Distribution definition object. Includes a pointer to the
 * appropriate function to access the distribution defined by the object,
 * as well as a function pointer to the specified source of random
 * numbers.
 */
typedef struct randdist {
	double		(*rnd_get)(struct randdist *);
	double		(*rnd_src)(unsigned short *);
	struct randdist *rnd_next;
	struct var	*rnd_var;
	avd_t		rnd_seed;
	avd_t		rnd_mean;
	avd_t		rnd_gamma;
	avd_t		rnd_min;
	avd_t		rnd_round;
	double		rnd_dbl_mean;
	double		rnd_dbl_gamma;
	fbint_t		rnd_vint_min;
	fbint_t		rnd_vint_round;
	probtabent_t	*rnd_probtabs;
	randfunc_t	rnd_rft[PF_TAB_SIZE];
	uint16_t	rnd_xi[3];
	uint16_t	rnd_type;
} randdist_t;

#define	RAND_TYPE_UNIFORM	0x1
#define	RAND_TYPE_GAMMA		0x2
#define	RAND_TYPE_TABLE		0x3
#define	RAND_TYPE_MASK		0x0fff
#define	RAND_SRC_URANDOM	0x0000
#define	RAND_SRC_GENERATOR	0x1000

#define	RAND_PARAM_TYPE		1
#define	RAND_PARAM_SRC		2
#define	RAND_PARAM_SEED		3
#define	RAND_PARAM_MIN		4
#define	RAND_PARAM_MEAN		5
#define	RAND_PARAM_GAMMA	6
#define	RAND_PARAM_ROUND	7

randdist_t *randdist_alloc(void);
void randdist_init(void);
int filebench_randomno32(uint32_t *, uint32_t, uint32_t, avd_t);
int filebench_randomno64(uint64_t *, uint64_t, uint64_t, avd_t);
void fb_random_init(void);

#ifdef	__cplusplus
}
#endif

#endif	/* _FB_RANDOM_H */
