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
 * Copyright 2017 Joyent, Inc.
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
#undef	CR4_PCIDE
#endif /* _SYS_CONTROLREGS_H */

#include <x86/specialreg.h>
#endif /* _COMPAT_FREEBSD_AMD64_MACHINE_SPECIALREG_H_ */
