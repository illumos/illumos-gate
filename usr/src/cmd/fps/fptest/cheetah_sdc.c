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
 * Copyright 2008 Sun Microsystems, Inc.
 * All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <unistd.h>
#include <fps_ereport.h>

extern void	iflush(void);
extern int	g1(unsigned long, unsigned long *, unsigned long *);
extern int	g2(unsigned long, unsigned long *, unsigned long *);
extern int	g3(unsigned long, unsigned long *, unsigned long *);
extern int	g4(unsigned long, unsigned long *, unsigned long *);
extern int	l0(unsigned long, unsigned long *, unsigned long *);
extern int	l1(unsigned long, unsigned long *, unsigned long *);
extern int	l2(unsigned long, unsigned long *, unsigned long *);
extern int	l3(unsigned long, unsigned long *, unsigned long *);
extern int	l4(unsigned long, unsigned long *, unsigned long *);
extern int	l5(unsigned long, unsigned long *, unsigned long *);
extern int	l6(unsigned long, unsigned long *, unsigned long *);
extern int	l7(unsigned long, unsigned long *, unsigned long *);
extern int	o0(unsigned long, unsigned long *, unsigned long *);
extern int	o1(unsigned long, unsigned long *, unsigned long *);
extern int	o2(unsigned long, unsigned long *, unsigned long *);
extern int	o3(unsigned long, unsigned long *, unsigned long *);
extern int	o4(unsigned long, unsigned long *, unsigned long *);
extern int	o5(unsigned long, unsigned long *, unsigned long *);
extern int	o7(unsigned long, unsigned long *, unsigned long *);

typedef struct {
	char	*reg;
	int	(*test_func) (unsigned long, unsigned long *,\
		unsigned long *);
}reg_info;

/* Registers to be tested and the functions to be used for it. */
static
reg_info	reg_func[] =
{
	{"g1", g1},
	{"g2", g2},
	{"g3", g3},
	{"g4", g4},
	{"l0", l0},
	{"l1", l1},
	{"l2", l2},
	{"l3", l3},
	{"l4", l4},
	{"l5", l5},
	{"l6", l6},
	{"l7", l7},
	{"o0", o0},
	{"o1", o1},
	{"o2", o2},
	{"o3", o3},
	{"o4", o4},
	{"o5", o5},
	/* %o6 is not tested as it is the %sp */
	{"o7", o7}
};

#define	N_REGS (sizeof (reg_func)/sizeof (*reg_func))

/*
 * cheetah_sdc_test(int limit, int unit, struct fps_test_ereport *report)
 * tests for silent data corruption first unearthed in a 750 Mhz Cheetah
 * (Toshiba). Returns if successful or not. If an error, relevant data
 * is stored in report. The test calls an assembly routine with
 * different target registers but essentially the same code sequence
 */
int
cheetah_sdc_test(int limit, struct fps_test_ereport *report)
{
	char err_data[MAX_INFO_SIZE];
	int iter;
	int regs;
	int rval;
	uint64_t expect;
	uint64_t observe;
	unsigned long tmp1 = 0;
	unsigned long tmp2 = 0;

	unsigned long pattern = 0xDEADDEADDEADDEAD;

	for (regs = 0; regs < N_REGS; regs++) {
		for (iter = 0; iter < limit; iter++) {
			iflush();
			rval = reg_func[regs].test_func(pattern, &tmp1, &tmp2);

			if (rval != 0) {
				snprintf(err_data, sizeof (err_data),
				    "Test:%d, reg:%s", iter,
				    reg_func[regs].reg);
				expect = (uint64_t)0;
				observe = (uint64_t)rval;
				setup_fps_test_struct(IS_EREPORT_INFO,
				    report,	6357, &observe,
				    &expect, 1, 1, err_data);

				return (-1);
			}
		}
	}

	return (0);
}
