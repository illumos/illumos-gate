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
#include <stdlib.h>
#include <fp.h>
#include <fps_ereport.h>

#pragma align 64(datain1, datain2, dataout)

int cbbcopy(struct fps_test_ereport *report);
static void	asi_bcopy_f0(uint32_t *out, uint32_t *in);
static void	asi_bcopy_f16(uint32_t *out, uint32_t *in);
static void	ax_bcopy(uint32_t *out, uint32_t *in);

static uint32_t dataout[64];

static uint32_t datain1[64] = {
0x55555500, 0x55555501, 0xaaaaaa02, 0xaaaaaa03,
0x55555504, 0x55555505, 0xaaaaaa06, 0xaaaaaa07,
0x55555508, 0x55555509, 0xaaaaaa0a, 0xaaaaaa0b,
0x5555550c, 0x5555550d, 0xaaaaaa0e, 0xaaaaaa0f,
0x55555510, 0x55555511, 0xaaaaaa12, 0xaaaaaa13,
0x55555514, 0x55555515, 0xaaaaaa16, 0xaaaaaa17,
0x55555518, 0x55555519, 0xaaaaaa1a, 0xaaaaaa1b,
0x5555551c, 0x5555551d, 0xaaaaaa1e, 0xaaaaaa1f,
0x55555520, 0x55555521, 0xaaaaaa22, 0xaaaaaa23,
0x55555524, 0x55555525, 0xaaaaaa26, 0xaaaaaa27,
0x55555528, 0x55555529, 0xaaaaaa2a, 0xaaaaaa2b,
0x5555552c, 0x5555552d, 0xaaaaaa2e, 0xaaaaaa2f,
0x55555530, 0x55555531, 0xaaaaaa32, 0xaaaaaa33,
0x55555534, 0x55555535, 0xaaaaaa36, 0xaaaaaa37,
0x55555538, 0x55555539, 0xaaaaaa3a, 0xaaaaaa3b,
0x5555553c, 0x5555553d, 0xaaaaaa3e, 0xaaaaaa3f
};

static uint32_t datain2[64] = {
0xaaaaaaff, 0xaaaaaafe, 0x555555fd, 0x555555fc,
0xaaaaaafb, 0xaaaaaafa, 0x555555f9, 0x555555f8,
0xaaaaaaf7, 0xaaaaaaf6, 0x555555f5, 0x555555f4,
0xaaaaaaf3, 0xaaaaaaf2, 0x555555f1, 0x555555f0,
0xaaaaaaef, 0xaaaaaaee, 0x555555ed, 0x555555ec,
0xaaaaaaeb, 0xaaaaaaea, 0x555555e9, 0x555555e8,
0xaaaaaae7, 0xaaaaaae6, 0x555555e5, 0x555555e4,
0xaaaaaae3, 0xaaaaaae2, 0x555555e1, 0x555555e0,
0xaaaaaadf, 0xaaaaaade, 0x555555dd, 0x555555dc,
0xaaaaaadb, 0xaaaaaada, 0x555555d9, 0x555555d8,
0xaaaaaad7, 0xaaaaaad6, 0x555555d5, 0x555555d4,
0xaaaaaad3, 0xaaaaaad2, 0x555555d1, 0x555555d0,
0xaaaaaacf, 0xaaaaaace, 0x555555cd, 0x555555cc,
0xaaaaaacb, 0xaaaaaaca, 0x555555c9, 0x555555c8,
0xaaaaaac7, 0xaaaaaac6, 0x555555c5, 0x555555c4,
0xaaaaaac3, 0xaaaaaac2, 0x555555c1, 0x555555c0
};

/*
 * cbbcopy(int unit, struct fps_test_ereport *report)
 * exercises block load and store path thru floating point
 * registers. Returns whether load/store was successful.
 * If an error, all relevant data is stored in report.
 * Purpose: FRF integraty check thru both block ld/st and P$
 * ax/ms pipe for health check online check utility. The utility is intented
 * to detect simple stuck at fault not timing related faults.
 */
int
cbbcopy(struct fps_test_ereport *report)
{
	int i;
	uint64_t expect;
	uint64_t observe;

	ax_bcopy(dataout, datain1);
	asi_bcopy_f0(dataout, dataout);

	for (i = 0; i < 64; i++) {
		if (dataout[i] != datain1[i]) {
			expect = (uint64_t)datain1[i];
			observe = (uint64_t)dataout[i];
			setup_fps_test_struct(NO_EREPORT_INFO, report,
			    6337, &observe, &expect, 1, 1);

			return (FPU_FOROFFLINE);
		}
	}

	ax_bcopy(dataout, datain2);
	asi_bcopy_f16(dataout, dataout);

	for (i = 0; i < 64; i++) {
		if (dataout[i] != datain2[i]) {
			expect = (uint64_t)datain2[i];
			observe = (uint64_t)dataout[i];
			setup_fps_test_struct(NO_EREPORT_INFO, report,
			    6338, &observe, &expect, 1, 1);

			return (FPU_FOROFFLINE);
		}
	}

	return (FPU_OK);
}

/*
 * asi_bcopy_f0(uint32_t *out, uint32_t *in)
 * does the assembly load/store of in to out
 */
/* ARGSUSED */
static void
asi_bcopy_f0(uint32_t *out, uint32_t *in)
{
	asm("ldda	[%i1]0xf8,%f0");
	asm("membar	#Sync");
	asm("stda	%f0,[%i0]0xf0");
	asm("membar	#Sync");
}

/*
 * asi_bcopy_f16(uint32_t *out, uint32_t *in)
 * does the assembly load/store of in to out
 */
/* ARGSUSED */
static void
asi_bcopy_f16(uint32_t *out, uint32_t *in)
{
	asm("ldda	[%i1]0xf0,%f16");
	asm("membar	#Sync");
	asm("stda	%f16,[%i0]0xf8");
	asm("membar	#Sync");
}

/*
 * ax_bcopy(uint32_t *out, uint32_t *in)
 * does the assembly load/store of in to out
 */
/* ARGSUSED */
static void
ax_bcopy(uint32_t *out, uint32_t *in)
{
	asm("prefetch	[%i1],21");
	asm("prefetch	[%i1+0x40],21");
	asm("ldd	[%i1],%f16");
	asm("ldd	[%i1+8],%f18");
	asm("ldd	[%i1+0x10],%f20");
	asm("ldd	[%i1+0x18],%f22");
	asm("ldd	[%i1+0x20],%f24");
	asm("ldd	[%i1+0x28],%f26");
	asm("ldd	[%i1+0x30],%f28");
	asm("ldd	[%i1+0x38],%f30");
	asm("ldd	[%i1+0x40],%f32");

	asm("prefetch	[%i1+0x80],21");
	asm("ldd	[%i1+0x48],%f34");
	asm("ldd	[%i1+0x50],%f36");
	asm("ldd	[%i1+0x58],%f38");
	asm("ldd	[%i1+0x60],%f40");
	asm("ldd	[%i1+0x68],%f42");
	asm("ldd	[%i1+0x70],%f44");
	asm("ldd	[%i1+0x78],%f46");

	asm("prefetch	[%i1+0xc0],21");
	asm("ldd	[%i1+0x80],%f0");
	asm("ldd	[%i1+0x88],%f2");
	asm("ldd	[%i1+0x90],%f4");
	asm("ldd	[%i1+0x98],%f6");
	asm("ldd	[%i1+0xa0],%f8");
	asm("ldd	[%i1+0xa8],%f10");
	asm("ldd	[%i1+0xb0],%f12");
	asm("ldd	[%i1+0xb8],%f14");

	asm("ldd	[%i1+0xc0],%f48");
	asm("ldd	[%i1+0xc8],%f50");
	asm("ldd	[%i1+0xd0],%f52");
	asm("ldd	[%i1+0xd8],%f54");
	asm("ldd	[%i1+0xe0],%f56");
	asm("ldd	[%i1+0xe8],%f58");
	asm("ldd	[%i1+0xf0],%f60");
	asm("ldd	[%i1+0xf8],%f62");

	asm("membar	#Sync");
	asm("stda	%f16,[%i0]0xf8");
	asm("add	%i0,0x40,%i0");
	asm("stda	%f32,[%i0]0xf0");
	asm("add	%i0,0x40,%i0");
	asm("stda	%f0,[%i0]0xf0");
	asm("add	%i0,0x40,%i0");
	asm("stda	%f48,[%i0]0xf0");
	asm("membar	#Sync");
}
