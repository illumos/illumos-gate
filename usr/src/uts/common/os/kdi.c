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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/cpuvar.h>
#include <sys/kdi_impl.h>
#include <sys/reboot.h>
#include <sys/errno.h>
#include <sys/atomic.h>
#include <sys/kmem.h>

kdi_debugvec_t	*kdi_dvec;
struct modctl	*kdi_dmods;

static kdi_dtrace_state_t kdi_dtrace_state = KDI_DTSTATE_IDLE;

void
kdi_dvec_vmready(void)
{
	kdi_dvec->dv_kctl_vmready();
	kdi_dvec->dv_vmready();
}

void
kdi_dvec_memavail(void)
{
	/*
	 * The driver will allocate more memory (if requested), and will call
	 * dv_memavail itself.
	 */
	kdi_dvec->dv_kctl_memavail();
}

#if defined(__x86)
void
kdi_dvec_handle_fault(greg_t trapno, greg_t pc, greg_t sp, int cpuid)
{
	kdi_dvec->dv_handle_fault(trapno, pc, sp, cpuid);
}
#endif

#if defined(__sparc)
/*
 * Called on the CPU being initialized
 */
void
kdi_dvec_cpu_init(struct cpu *cp)
{
	kdi_dvec->dv_kctl_cpu_init();
	kdi_dvec->dv_cpu_init(cp);
}

void
kdi_dvec_cpr_restart(void)
{
	kdi_dvec->dv_kctl_cpu_init();
	kdi_dvec->dv_cpr_restart();
}
#endif	/* __sparc */

void
kdi_dvec_modavail(void)
{
	kdi_dvec->dv_kctl_modavail();
}

void
kdi_dvec_thravail(void)
{
	kdi_dvec->dv_kctl_thravail();
}

void
kdi_dvec_mod_loaded(struct modctl *modp)
{
	kdi_dvec->dv_mod_loaded(modp);
}

void
kdi_dvec_mod_unloading(struct modctl *modp)
{
	kdi_dvec->dv_mod_unloading(modp);
}

kdi_dtrace_state_t
kdi_dtrace_get_state(void)
{
	return (kdi_dtrace_state);
}

int
kdi_dtrace_set(kdi_dtrace_set_t transition)
{
	kdi_dtrace_state_t new, cur;

	do {
		cur = kdi_dtrace_state;

		switch (transition) {
		case KDI_DTSET_DTRACE_ACTIVATE:
			if (cur == KDI_DTSTATE_KMDB_BPT_ACTIVE)
				return (EBUSY);
			if (cur == KDI_DTSTATE_DTRACE_ACTIVE)
				return (0);
			new = KDI_DTSTATE_DTRACE_ACTIVE;
			break;
		case KDI_DTSET_DTRACE_DEACTIVATE:
			if (cur == KDI_DTSTATE_KMDB_BPT_ACTIVE)
				return (EBUSY);
			if (cur == KDI_DTSTATE_IDLE)
				return (0);
			new = KDI_DTSTATE_IDLE;
			break;
		case KDI_DTSET_KMDB_BPT_ACTIVATE:
			if (cur == KDI_DTSTATE_DTRACE_ACTIVE)
				return (EBUSY);
			if (cur == KDI_DTSTATE_KMDB_BPT_ACTIVE)
				return (0);
			new = KDI_DTSTATE_KMDB_BPT_ACTIVE;
			break;
		case KDI_DTSET_KMDB_BPT_DEACTIVATE:
			if (cur == KDI_DTSTATE_DTRACE_ACTIVE)
				return (EBUSY);
			if (cur == KDI_DTSTATE_IDLE)
				return (0);
			new = KDI_DTSTATE_IDLE;
			break;
		default:
			return (EINVAL);
		}
	} while (atomic_cas_32((uint_t *)&kdi_dtrace_state, cur, new) != cur);

	return (0);
}
