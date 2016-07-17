/*
 * Copyright (c) 1998 Michael Smith <msmith@freebsd.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/cdefs.h>

#include <stand.h>
/*
#include <sys/param.h>
#include <sys/reboot.h>
#include <sys/linker.h>
#include <machine/bootinfo.h>
#include <machine/metadata.h>
#include "bootstrap.h"
*/
#include <machine/psl.h>
#include <machine/cpufunc.h>
#include <machine/specialreg.h>
#include "libi386.h"

/*
 * Check to see if this CPU supports long mode.
 */
int
bi_checkcpu(void)
{
	unsigned long flags;
	unsigned int regs[4];
	unsigned int maxeax;
	unsigned int max_maxeax = 0x100;
	unsigned int stdfeatures = 0, xtdfeatures = 0;
	int amd64 = 0;

	/* Check for presence of "cpuid". */
#if defined(__LP64__)
	flags = read_rflags();
	write_rflags(flags ^ PSL_ID);
	if (!((flags ^ read_rflags()) & PSL_ID))
		return (0);
#else
	flags = read_eflags();
	write_eflags(flags ^ PSL_ID);
	if (!((flags ^ read_eflags()) & PSL_ID))
		return (0);
#endif /* __LP64__ */

	/* Fetch the vendor string. */
	do_cpuid(0, regs);
	maxeax = regs[0];

	/*
	 * Limit the range in case of weird hardware
	 */
	if (maxeax > max_maxeax)
		maxeax = max_maxeax;
	if (maxeax < 1)
		return (0);
	else {
		do_cpuid(1, regs);
		stdfeatures = regs[3];
	}

	/* Has to support AMD features. */
	do_cpuid(0x80000000, regs);
	if (regs[0] & 0x80000000) {
		maxeax = regs[0];
		max_maxeax = 0x80000100;
		if (maxeax > max_maxeax)
			maxeax = max_maxeax;
		if (maxeax >= 0x80000001) {
			do_cpuid(0x80000001, regs);
			xtdfeatures = regs[3];
		}
	}

	/* Check for long mode. */
	if (xtdfeatures & AMDID_LM)
		amd64++;

	/* Check for FPU. */
	if ((stdfeatures & CPUID_FPU) == 0)
		amd64 = 0;

	if ((stdfeatures & CPUID_TSC) == 0)
		amd64 = 0;

	if ((stdfeatures & CPUID_MSR) == 0)
		amd64 = 0;

	if ((stdfeatures & CPUID_PAE) == 0)
		amd64 = 0;

	if ((stdfeatures & CPUID_CX8) == 0)
		amd64 = 0;

	if ((stdfeatures & CPUID_PGE) == 0)
		amd64 = 0;

	if ((stdfeatures & CPUID_CLFSH) == 0)
		amd64 = 0;

	if ((stdfeatures & CPUID_MMX) == 0)
		amd64 = 0;

	if ((stdfeatures & CPUID_FXSR) == 0)
		amd64 = 0;

	if ((stdfeatures & CPUID_SSE) == 0)
		amd64 = 0;

        if ((stdfeatures & CPUID_SSE2) == 0)
		amd64 = 0;

	return (amd64);
}

void
bi_isadir(void)
{
	int rc;

	if (bi_checkcpu())
		rc = setenv("ISADIR", "amd64", 1);
	else
		rc = setenv("ISADIR", "", 1);

	if (rc != 0) {
		printf("Warning: failed to set ISADIR environment "
		    "variable: %d\n", rc);
	}
}
