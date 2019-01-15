/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2019 Joyent, Inc.
 */

#ifndef _COMPAT_FREEBSD_AMD64_MACHINE_SPECIALREG_H_
#define	_COMPAT_FREEBSD_AMD64_MACHINE_SPECIALREG_H_

#ifdef _SYS_X86_ARCHEXT_H
/* Our x86_archext conflicts with BSD header for the XFEATURE_ defines */
#undef	XFEATURE_AVX
#undef	XFEATURE_MPX
#undef	XFEATURE_AVX512
#endif

#ifdef _SYS_CONTROLREGS_H
/* Our CR4 defines conflict with BSD header */
#undef	CR4_VME
#undef	CR4_PVI
#undef	CR4_TSD
#undef	CR4_DE
#undef	CR4_PSE
#undef	CR4_PAE
#undef	CR4_MCE
#undef	CR4_PGE
#undef	CR4_PCE
#undef	CR4_VMXE
#undef	CR4_SMEP
#undef	CR4_SMAP
#undef	CR4_PKE
#undef	CR4_FSGSBASE
#undef	CR4_PCIDE
#endif /* _SYS_CONTROLREGS_H */

#ifdef _SYS_X86_ARCHEXT_H
/* Our IA32 speculation-related defines conflict with BSD header */
#undef	IA32_ARCH_CAP_RDCL_NO
#undef	IA32_ARCH_CAP_IBRS_ALL
#undef	IA32_ARCH_CAP_RSBA
#undef	IA32_ARCH_CAP_SKIP_L1DFL_VMENTRY
#undef	IA32_ARCH_CAP_SSB_NO
#undef	IA32_ARCH_CAP_MDS_NO
#undef	IA32_SPEC_CTRL_IBRS
#undef	IA32_SPEC_CTRL_STIBP
#undef	IA32_SPEC_CTRL_SSBD
#undef	IA32_FLUSH_CMD_L1D
#undef	MSR_IA32_SPEC_CTRL
#undef	MSR_IA32_PRED_CMD
#endif /* _SYS_X86_ARCHEXT_H */

#include <x86/specialreg.h>
#endif /* _COMPAT_FREEBSD_AMD64_MACHINE_SPECIALREG_H_ */
