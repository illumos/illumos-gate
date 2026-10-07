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
 * Copyright 2026 Oxide Computer Company
 */

#ifndef _SYS_VMM_VCPUSET_H
#define	_SYS_VMM_VCPUSET_H

/*
 * A set of the vCPUs of a VM.
 *
 * The set is sized by the greatest number of vCPUs a VM may have rather than
 * by the number of CPUs in the host. A vCPU is identified by its vcpuid, which
 * must be below VM_MAXCPU.
 *
 * Where a set is shared between threads without a lock, members are added
 * and removed with the atomic operations. Reads of such a set are not
 * synchronised with those updates and generally may not make inferences about
 * bits in the set before or after an operation.
 */

#include <sys/types.h>
#include <sys/stdbool.h>
#include <sys/systm.h>
#include <sys/bitmap.h>
#include <sys/debug.h>
#include <sys/vmm.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct vcpuset {
	ulong_t	vcs_bits[BT_BITOUL(VM_MAXCPU)];
} vcpuset_t;

static inline void
vcpuset_zero(vcpuset_t *set)
{
	bzero(set, sizeof (*set));
}

static inline void
vcpuset_add(vcpuset_t *set, int vcpuid)
{
	ASSERT3S(vcpuid, >=, 0);
	ASSERT3S(vcpuid, <, VM_MAXCPU);
	BT_SET(set->vcs_bits, vcpuid);
}

static inline void
vcpuset_del(vcpuset_t *set, int vcpuid)
{
	ASSERT3S(vcpuid, >=, 0);
	ASSERT3S(vcpuid, <, VM_MAXCPU);
	BT_CLEAR(set->vcs_bits, vcpuid);
}

/* Make the set contain only the given vCPU. */
static inline void
vcpuset_only(vcpuset_t *set, int vcpuid)
{
	vcpuset_zero(set);
	vcpuset_add(set, vcpuid);
}

static inline void
vcpuset_atomic_add(vcpuset_t *set, int vcpuid)
{
	ASSERT3S(vcpuid, >=, 0);
	ASSERT3S(vcpuid, <, VM_MAXCPU);
	BT_ATOMIC_SET(set->vcs_bits, vcpuid);
}

static inline void
vcpuset_atomic_del(vcpuset_t *set, int vcpuid)
{
	ASSERT3S(vcpuid, >=, 0);
	ASSERT3S(vcpuid, <, VM_MAXCPU);
	BT_ATOMIC_CLEAR(set->vcs_bits, vcpuid);
}

static inline bool
vcpuset_isset(const vcpuset_t *set, int vcpuid)
{
	ASSERT3S(vcpuid, >=, 0);
	ASSERT3S(vcpuid, <, VM_MAXCPU);
	return (BT_TEST(set->vcs_bits, vcpuid) != 0);
}

static inline bool
vcpuset_isequal(const vcpuset_t *a, const vcpuset_t *b)
{
	return (bcmp(a, b, sizeof (*a)) == 0);
}

/*
 * Return the lowest member of the set whose vcpuid is at least 'start', or -1
 * if there is none. The members of a set can be visited in order with
 *
 *	for (id = vcpuset_find(set, 0); id != -1;
 *	    id = vcpuset_find(set, id + 1))
 */
static inline int
vcpuset_find(const vcpuset_t *set, int start)
{
	ASSERT3S(start, >=, 0);
	if (start >= VM_MAXCPU)
		return (-1);
	return (bt_getlowbit(set->vcs_bits, start, VM_MAXCPU - 1));
}

#ifdef __cplusplus
}
#endif

#endif /* _SYS_VMM_VCPUSET_H */
