/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2011 NetApp, Inc.
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
 * THIS SOFTWARE IS PROVIDED BY NETAPP, INC ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL NETAPP, INC OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
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
/* This file is dual-licensed; see usr/src/contrib/bhyve/LICENSE */

/*
 * Copyright 2014 Pluribus Networks Inc.
 * Copyright 2018 Joyent, Inc.
 * Copyright 2020 Oxide Computer Company
 */

#include <sys/cdefs.h>

#include <sys/param.h>
#include <sys/pcpu.h>
#include <sys/systm.h>
#include <sys/sysctl.h>
#include <sys/x86_archext.h>

#include <machine/clock.h>
#include <machine/cpufunc.h>
#include <machine/md_var.h>
#include <machine/segments.h>
#include <machine/specialreg.h>

#include <machine/vmm.h>
#include <sys/vmm_kernel.h>

#include "vmm_host.h"
#include "vmm_util.h"

/*
 * Return 'true' if the capability 'cap' is enabled in this virtual cpu
 * and 'false' otherwise.
 */
bool
vm_cpuid_capability(struct vm *vm, int vcpuid, enum vm_cpuid_capability cap)
{
	bool rv;

	KASSERT(cap > 0 && cap < VCC_LAST, ("%s: invalid vm_cpu_capability %d",
	    __func__, cap));

	/*
	 * Simply passthrough the capabilities of the host cpu for now.
	 */
	rv = false;
	switch (cap) {
#ifdef __FreeBSD__
	case VCC_NO_EXECUTE:
		if (amd_feature & AMDID_NX)
			rv = true;
		break;
	case VCC_FFXSR:
		if (amd_feature & AMDID_FFXSR)
			rv = true;
		break;
	case VCC_TCE:
		if (amd_feature2 & AMDID2_TCE)
			rv = true;
		break;
#else
	case VCC_NO_EXECUTE:
		if (is_x86_feature(x86_featureset, X86FSET_NX))
			rv = true;
		break;
	/* XXXJOY: No kernel detection for FFXR or TCE at present, so ignore */
	case VCC_FFXSR:
	case VCC_TCE:
		break;
#endif
	default:
		panic("%s: unknown vm_cpu_capability %d", __func__, cap);
	}
	return (rv);
}

bool
validate_guest_xcr0(uint64_t val, uint64_t limit_mask)
{
	/* x87 feature must be enabled */
	if ((val & XFEATURE_ENABLED_X87) == 0) {
		return (false);
	}
	/* AVX cannot be enabled without SSE */
	if ((val & (XFEATURE_ENABLED_SSE | XFEATURE_ENABLED_AVX)) ==
	    XFEATURE_ENABLED_SSE) {
		return (false);
	}
	/* No bits should be outside what we dictate to be allowed */
	if ((val & ~limit_mask) != 0) {
		return (false);
	}

	return (true);
}
