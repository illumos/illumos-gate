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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/mca_x86.h>
#include <sys/cpu_module_impl.h>
#include <sys/cmn_err.h>
#include <sys/cpuvar.h>
#include <sys/x86_archext.h>
#include <sys/controlregs.h>
#include <sys/sysmacros.h>
#include <sys/regset.h>
#include <sys/privregs.h>
#include <sys/systm.h>
#include <sys/types.h>
#include <sys/log.h>
#include <sys/psw.h>

#include "gcpu.h"

/*
 * x86 architecture standard banks for IA32 and compatible processors.  These
 * are effectively the lowest common denominators for the MCA architecture.
 */
static const gcpu_mca_bank_t gcpu_mca_banks_ia32[] = {
{ IA32_MSR_MC0_CTL, IA32_MSR_MC0_STATUS, IA32_MSR_MC0_ADDR, IA32_MSR_MC0_MISC },
{ IA32_MSR_MC1_CTL, IA32_MSR_MC1_STATUS, IA32_MSR_MC1_ADDR, IA32_MSR_MC1_MISC },
{ IA32_MSR_MC2_CTL, IA32_MSR_MC2_STATUS, IA32_MSR_MC2_ADDR, IA32_MSR_MC2_MISC },
{ IA32_MSR_MC3_CTL, IA32_MSR_MC3_STATUS, IA32_MSR_MC3_ADDR, IA32_MSR_MC3_MISC },
};

/*
 * The P6-family processors have a different layout for their banks.  Note that
 * MC4 comes *before* MC3 by design here (Intel's design that is, not ours).
 */
static const gcpu_mca_bank_t gcpu_mca_banks_p6[] = {
{ P6_MSR_MC0_CTL, P6_MSR_MC0_STATUS, P6_MSR_MC0_ADDR, P6_MSR_MC0_MISC },
{ P6_MSR_MC1_CTL, P6_MSR_MC1_STATUS, P6_MSR_MC1_ADDR, P6_MSR_MC1_MISC },
{ P6_MSR_MC2_CTL, P6_MSR_MC2_STATUS, P6_MSR_MC2_ADDR, P6_MSR_MC2_MISC },
{ P6_MSR_MC4_CTL, P6_MSR_MC4_STATUS, P6_MSR_MC4_ADDR, P6_MSR_MC4_MISC },
{ P6_MSR_MC3_CTL, P6_MSR_MC3_STATUS, P6_MSR_MC3_ADDR, P6_MSR_MC3_MISC },
};

/*
 * Initialize the Machine Check Architecture (MCA) for a generic x86 CPU.
 * Refer to the IA-32 Intel Architecture Software Developer's Manual,
 * Volume 3: System Programming Guide, Section 14.5 for more information.
 */
void
gcpu_mca_init(void *data)
{
	gcpu_data_t *gcpu = data;
	gcpu_mca_t *mca = &gcpu->gcpu_mca;
	cpu_t *cp = CPU;

	uint64_t cap;
	uint_t nbanks;
	int i;

	/*
	 * We're only prepared to handle processors that have an MCG_CAP
	 * register.  P5, K6, and earlier processors, which have their own
	 * more primitive way of doing machine checks, are not supported.
	 */
	ASSERT(x86_feature & X86_MCA);
	cap = rdmsr(IA32_MSR_MCG_CAP);

	if (!(cap & MCG_CAP_CTL_P))
		return; /* do nothing if IA32_MCG_CTL register is missing */

	if (strcmp(cpuid_getvendorstr(cp), "GenuineIntel") == 0 &&
	    cpuid_getfamily(cp) == 6) {
		mca->gcpu_mca_banks = gcpu_mca_banks_p6;
		mca->gcpu_mca_nbanks = sizeof (gcpu_mca_banks_p6) /
		    sizeof (gcpu_mca_bank_t);
	} else {
		mca->gcpu_mca_banks = gcpu_mca_banks_ia32;
		mca->gcpu_mca_nbanks = sizeof (gcpu_mca_banks_ia32) /
		    sizeof (gcpu_mca_bank_t);
	}

	mca->gcpu_mca_data = kmem_alloc(
	    mca->gcpu_mca_nbanks * sizeof (gcpu_mca_data_t), KM_SLEEP);

	/*
	 * Unlike AMD's approach of assigning one MCG_CTL bit to each machine
	 * check register bank, Intel doesn't describe the layout of MCG_CTL or
	 * promise that each bit corresponds to a bank.  The generic guidance
	 * is simply to write all ones to MCG_CTL, enabling everything that is
	 * present (h/w ignores writes to the undefined bit positions).  The
	 * code right now only handles the original four banks or the P6 banks,
	 * so we may enable more than we know how to read on a future CPU.
	 * This code can be enhanced to dynamically allocate bank state based
	 * upon MCG_CAP.Count if RAS ever becomes important on non-AMD CPUs.
	 */
	nbanks = cap & MCG_CAP_COUNT_MASK;
	mca->gcpu_mca_nbanks = MIN(nbanks, mca->gcpu_mca_nbanks);
	wrmsr(IA32_MSR_MCG_CTL, 0ULL); /* disable features while we configure */

	for (i = 0; i < mca->gcpu_mca_nbanks; i++) {
		const gcpu_mca_bank_t *bank = &mca->gcpu_mca_banks[i];
		wrmsr(bank->bank_ctl, -1ULL);
		wrmsr(bank->bank_status, 0ULL);
	}

	wrmsr(IA32_MSR_MCG_CTL, -1ULL); /* enable all machine-check features */
	setcr4(getcr4() | CR4_MCE);	/* enable machine-check exceptions */
}

/*
 * Initialize the Machine Check Architecture (MCA) for a generic x86 CPU.
 * Refer to the IA-32 Intel Architecture Software Developer's Manual,
 * Volume 3: System Programming Guide, Section 14.7 for more information.
 */
int
gcpu_mca_trap(void *data, struct regs *rp)
{
	gcpu_data_t *gcpu = data;
	gcpu_mca_t *mca = &gcpu->gcpu_mca;
	uint64_t gstatus = rdmsr(IA32_MSR_MCG_STATUS);
	int i, fatal = !(gstatus & MCG_STATUS_RIPV);

	if (!(gstatus & MCG_STATUS_MCIP))
		return (0); /* spurious machine check trap */

	/*
	 * Read out the bank status values, and the address and misc registers
	 * if they are valid.  Update our fatal status based on each bank.
	 * Clear the MCG_STATUS register when we're done reading the h/w state.
	 */
	for (i = 0; i < mca->gcpu_mca_nbanks; i++) {
		const gcpu_mca_bank_t *bank = &mca->gcpu_mca_banks[i];
		gcpu_mca_data_t *data = &mca->gcpu_mca_data[i];
		uint64_t bstatus = rdmsr(bank->bank_status);

		data->bank_status_data = bstatus;
		data->bank_addr_data = 0;
		data->bank_misc_data = 0;

		if (!(bstatus & MSR_MC_STATUS_VAL))
			continue;

		if (bstatus & MSR_MC_STATUS_ADDRV)
			data->bank_addr_data = rdmsr(bank->bank_addr);
		if (bstatus & MSR_MC_STATUS_MISCV)
			data->bank_misc_data = rdmsr(bank->bank_misc);

		if (bstatus & (MSR_MC_STATUS_PCC | MSR_MC_STATUS_O))
			fatal = 1; /* context corrupt or overflow */

		wrmsr(bank->bank_status, 0ULL);
	}

	wrmsr(IA32_MSR_MCG_STATUS, 0);

	log_enter();

	if (gstatus & MCG_STATUS_EIPV) {
		cmn_err(CE_WARN, "Machine-Check Exception at 0x%lx in %s mode",
		    (ulong_t)rp->r_pc, USERMODE(rp->r_cs) ? "user" : "kernel");
	} else {
		cmn_err(CE_WARN, "Machine-Check Exception in %s mode",
		    USERMODE(rp->r_cs) ? "user" : "kernel");
	}

	/*
	 * Now go back through our saved state and report it using cmn_err().
	 * We don't bother attempting any kind of decoding here as the actual
	 * values are entirely specific to the actual processor in use.  We
	 * could break out the generic bit-fields, but you're only here if
	 * we didn't care enough to implement FMA support for this processor.
	 */
	for (i = 0; i < mca->gcpu_mca_nbanks; i++) {
		gcpu_mca_data_t *bank = &mca->gcpu_mca_data[i];
		uint64_t bstatus = bank->bank_status_data;

		if (!(bstatus & MSR_MC_STATUS_VAL))
			continue;

		switch (bstatus & (MSR_MC_STATUS_ADDRV | MSR_MC_STATUS_MISCV)) {
		case MSR_MC_STATUS_ADDRV | MSR_MC_STATUS_MISCV:
			cmn_err(CE_WARN, "%d STAT 0x%016llx ADDR 0x%016llx "
			    "MISC 0x%016llx", i, (u_longlong_t)bstatus,
			    (u_longlong_t)bank->bank_addr_data,
			    (u_longlong_t)bank->bank_misc_data);
			break;
		case MSR_MC_STATUS_ADDRV:
			cmn_err(CE_WARN, "%d STAT 0x%016llx ADDR 0x%016llx",
			    i, (u_longlong_t)bstatus,
			    (u_longlong_t)bank->bank_addr_data);
			break;
		case MSR_MC_STATUS_MISCV:
			cmn_err(CE_WARN, "%d STAT 0x%016llx MISC 0x%016llx",
			    i, (u_longlong_t)bstatus,
			    (u_longlong_t)bank->bank_misc_data);
			break;
		default:
			cmn_err(CE_WARN, "%d STAT 0x%016llx",
			    i, (u_longlong_t)bstatus);
		}
	}

	log_exit();
	return (fatal);
}
