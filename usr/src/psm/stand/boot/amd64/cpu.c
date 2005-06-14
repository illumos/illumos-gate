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
#include <sys/psw.h>

#include <amd64/print.h>
#include <amd64/debug.h>
#include <amd64/cpu.h>
#include <amd64/amd64.h>
#include <amd64/msr.h>
#include "../i386/common/biosint.h"

#ifdef	DEBUG
static void
amd64_dump_cpuid(uint32_t eaxmin, uint32_t eaxmax)
{
	uint32_t eax;
	struct amd64_cpuid_regs __vcr, *vcr = &__vcr;

	printf("\t%8s | %8s %8s %8s %8s\n",
	    "eax in", "eax", "ebx", "ecx", "edx");
	for (eax = eaxmin; eax <= eaxmax; eax++) {
		amd64_cpuid_insn(eax, vcr);
		printf("\t%8x | %8x %8x %8x %8x\n", eax,
		    vcr->r_eax, vcr->r_ebx, vcr->r_ecx, vcr->r_edx);
	}
}

#define	cmprintf	printf

#else	/* !DEBUG */

#ifdef	lint
#define	cmprintf	printf
#else
#define	cmprintf
#endif	/* lint */

#endif	/* DEBUG */

static int detect_target_operating_mode();

int is_amd64;

/*ARGSUSED*/
int
amd64_config_cpu(void)
{
	struct amd64_cpuid_regs __vcr, *vcr = &__vcr;
	uint32_t maxeax;
	uint32_t max_maxeax = 0x100;
	char vendor[13];
	int isamd64 = 0;
	uint32_t stdfeatures = 0, xtdfeatures = 0;
	uint64_t efer;

	/*
	 * This check may seem silly, but if the C preprocesor symbol __amd64
	 * is #defined during compilation, something that may outwardly seem
	 * like a good idea, uts/common/sys/isa_defs.h will #define _LP64,
	 * which will cause uts/common/sys/int_types.h to typedef uint64_t as
	 * an unsigned long - which is only 4 bytes in size when using a 32-bit
	 * compiler.
	 *
	 * If that happens, all the page table translation routines will fail
	 * horribly, so check the size of uint64_t just to insure some degree
	 * of sanity in future operations.
	 */
	/*LINTED [sizeof result is invarient]*/
	if (sizeof (uint64_t) != 8)
		prom_panic("multiboot compiled improperly, unable to boot "
		    "64-bit AMD64 executables");

	/*
	 * If the CPU doesn't support the CPUID instruction, it's definitely
	 * not an AMD64.
	 */
	if (amd64_cpuid_supported() == 0)
		return (0);

	amd64_cpuid_insn(0, vcr);

	maxeax = vcr->r_eax;
	{
		/*LINTED [vendor string from cpuid data]*/
		uint32_t *iptr = (uint32_t *)vendor;

		*iptr++ = vcr->r_ebx;
		*iptr++ = vcr->r_edx;
		*iptr++ = vcr->r_ecx;

		vendor[12] = '\0';
	}

	if (maxeax > max_maxeax) {
		cmprintf("cpu: warning, maxeax was 0x%x -> 0x%x\n",
		    maxeax, max_maxeax);
		maxeax = max_maxeax;
	}

	if (maxeax < 1)
		return (0);	/* no additional functions, not an AMD64 */
	else {
		uint_t family, model, step;

		amd64_cpuid_insn(1, vcr);

		/*
		 * All AMD64/IA32e processors technically SHOULD report
		 * themselves as being in family 0xf, but for some reason
		 * Simics doesn't, and this may change in the future, so
		 * don't error out if it's not true.
		 */
		if ((family = BITX(vcr->r_eax, 11, 8)) == 0xf)
			family += BITX(vcr->r_eax, 27, 20);

		if ((model = BITX(vcr->r_eax, 7, 4)) == 0xf)
			model += BITX(vcr->r_eax, 19, 16) << 4;
		step = BITX(vcr->r_eax, 3, 0);

		cmprintf("cpu: '%s' family %d model %d step %d\n",
		    vendor, family, model, step);
		stdfeatures = vcr->r_edx;
	}

#ifdef	DEBUG
	if (amd64_debug) {
		cmprintf("cpu: standard cpuid data:\n");
		amd64_dump_cpuid(0, maxeax);
	}
#endif	/* DEBUG */

	amd64_cpuid_insn(0x80000000, vcr);

	if (vcr->r_eax & 0x80000000) {
		uint32_t xmaxeax = vcr->r_eax;
		const uint32_t max_xmaxeax = 0x80000100;

		if (xmaxeax > max_xmaxeax) {
			cmprintf("amd64: warning, xmaxeax was 0x%x -> 0x%x\n",
			    xmaxeax, max_xmaxeax);
			xmaxeax = max_xmaxeax;
		}

#ifdef	DEBUG
		if (amd64_debug) {
			cmprintf("amd64: extended cpuid data:\n");
			amd64_dump_cpuid(0x80000000, xmaxeax);
		}
#endif	/* DEBUG */

		if (xmaxeax >= 0x80000001) {
			amd64_cpuid_insn(0x80000001, vcr);
			xtdfeatures = vcr->r_edx;
		}
	}

	if (BITX(xtdfeatures, 29, 29))		/* long mode */
		isamd64++;
	else
		cmprintf("amd64: CPU does NOT support long mode\n");

	if (!BITX(stdfeatures, 0, 0)) {
		cmprintf("amd64: CPU does NOT support FPU\n");
		isamd64--;
	}

	if (!BITX(stdfeatures, 3, 3)) {
		cmprintf("amd64: CPU does NOT support PSE\n");
		isamd64--;
	}

	if (!BITX(stdfeatures, 4, 4)) {
		cmprintf("amd64: CPU does NOT support TSC\n");
		isamd64--;
	}

	if (!BITX(stdfeatures, 5, 5)) {
		cmprintf("amd64: CPU does NOT support MSRs\n");
		isamd64--;
	}

	if (!BITX(stdfeatures, 6, 6)) {
		cmprintf("amd64: CPU does NOT support PAE\n");
		isamd64--;
	}

	if (!BITX(stdfeatures, 8, 8)) {
		cmprintf("amd64: CPU does NOT support CX8\n");
		isamd64--;
	}

	if (!BITX(stdfeatures, 13, 13)) {
		cmprintf("amd64: CPU does NOT support PGE\n");
		isamd64--;
	}

	if (!BITX(stdfeatures, 17, 17)) {
		cmprintf("amd64: CPU does NOT support PSE\n");
		isamd64--;
	}

	if (!BITX(stdfeatures, 19, 19)) {
		cmprintf("amd64: CPU does NOT support CLFSH\n");
		isamd64--;
	}

	if (!BITX(stdfeatures, 23, 23)) {
		cmprintf("amd64: CPU does NOT support MMX\n");
		isamd64--;
	}

	if (!BITX(stdfeatures, 24, 24)) {
		cmprintf("amd64: CPU does NOT support FXSR\n");
		isamd64--;
	}

	if (!BITX(stdfeatures, 25, 25)) {
		cmprintf("amd64: CPU does NOT support SSE\n");
		isamd64--;
	}

	if (!BITX(stdfeatures, 26, 26)) {
		cmprintf("amd64: CPU does NOT support SSE2\n");
		isamd64--;
	}

	if (isamd64 < 1) {
		cmprintf("amd64: CPU does not support amd64 executables.\n");
		return (0);
	}

	amd64_rdmsr(MSR_AMD_EFER, &efer);
	if (efer & AMD_EFER_SCE)
		cmprintf("amd64: EFER_SCE (syscall/sysret) already enabled\n");
	if (efer & AMD_EFER_NXE)
		cmprintf("amd64: EFER_NXE (no-exec prot) already enabled\n");
	if (efer & AMD_EFER_LME)
		cmprintf("amd64: EFER_LME (long mode) already enabled\n");

	return (detect_target_operating_mode());
}

/*
 * Issue 'Detect Target Operating Mode' callback to the BIOS
 */
static int
detect_target_operating_mode()
{
	struct int_pb ic = {0};
	int ret, ah;

	ic.ax = 0xec00;	/* Detect Target Operating Mode */
	ic.bx = 0x03;		/* mixed mode target */

	ret = bios_doint(0x15, &ic);

	ah = ic.ax >> 8;
	if (ah == 0x86 && (ret & PS_C) != 0) {
		dprintf("[BIOS 'Detect Target Operating Mode' "
		    "callback unsupported on this platform]\n");
		return (1);	/* unsupported, ignore */
	}

	if (ah == 0x0 && (ret & PS_C) == 0) {
		dprintf("[BIOS accepted mixed-mode target setting!]\n");
		return (1);	/* told the bios what we're up to */
	}

	if (ah == 0 && ret & PS_C) {
		printf("fatal: BIOS reports this machine CANNOT run in mixed "
		    "32/64-bit mode!\n");
		return (0);
	}

	dprintf("warning: BIOS Detect Target Operating Mode callback "
	    "confused.\n         %%ax = 0x%x, carry = %d\n", ic.ax,
	    ret & PS_C ? 1 : 0);

	return (1);
}
