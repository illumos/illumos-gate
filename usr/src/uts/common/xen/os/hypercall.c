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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Provides basic C wrappers around hypervisor invocation.
 *
 * i386: eax = vector: ebx, ecx, edx, esi, edi = args 1-5
 *	 eax = return value
 *	 (argument registers may be clobbered on return)
 *
 * amd64:rax = vector: rdi, rsi, rdx, r10, r8, r9 = args 1-6
 *	 rax = return value
 *	 (arguments registers not clobbered on return; rcx, r11 are)
 */

#include <sys/types.h>
#ifndef __xpv
#include <sys/xpv_support.h>
#else
#include <sys/xpv_user.h>
#endif

#include <sys/hypervisor.h>
#include <xen/public/sched.h>
#include <sys/debug.h>
#include <sys/archsystm.h>

long
HYPERVISOR_set_trap_table(trap_info_t *table)
{
	return (__hypercall1(__HYPERVISOR_set_trap_table, (ulong_t)table));
}

int
HYPERVISOR_mmu_update(mmu_update_t *req, int count, int *success_count,
    domid_t domain_id)
{
	return (__hypercall4_int(__HYPERVISOR_mmu_update,
	    (ulong_t)req, (long)count, (ulong_t)success_count,
	    (ulong_t)domain_id));
}

long
HYPERVISOR_set_gdt(ulong_t *frame_list, int entries)
{
	return (__hypercall2(
	    __HYPERVISOR_set_gdt, (ulong_t)frame_list, (long)entries));
}

/*
 * XXPV Seems like "sp" would be a better name for both amd64 and i386?
 * For now stay consistent with xen project source.
 */
long
HYPERVISOR_stack_switch(ulong_t ss, ulong_t esp)
{
	return (__hypercall2(__HYPERVISOR_stack_switch, ss, esp));
}

#if defined(__amd64)

long
HYPERVISOR_set_callbacks(ulong_t event_address, ulong_t failsafe_address,
    ulong_t syscall_address)
{
	return (__hypercall3(__HYPERVISOR_set_callbacks,
	    event_address, failsafe_address, syscall_address));
}

#elif defined(__i386)

long
HYPERVISOR_set_callbacks(
    ulong_t event_selector, ulong_t event_address,
    ulong_t failsafe_selector, ulong_t failsafe_address)
{
	return (__hypercall4(__HYPERVISOR_set_callbacks,
	    event_selector, event_address,
	    failsafe_selector, failsafe_address));
}

#endif	/* __amd64 */

long
HYPERVISOR_fpu_taskswitch(int set)
{
	return (__hypercall1(__HYPERVISOR_fpu_taskswitch, (long)set));
}

/* *** __HYPERVISOR_sched_op_compat *** OBSOLETED */

long
HYPERVISOR_platform_op(xen_platform_op_t *platform_op)
{
	return (__hypercall1(__HYPERVISOR_platform_op, (ulong_t)platform_op));
}

/* *** __HYPERVISOR_set_debugreg *** NOT IMPLEMENTED */

/* *** __HYPERVISOR_get_debugreg *** NOT IMPLEMENTED */

long
HYPERVISOR_update_descriptor(maddr_t ma, uint64_t desc)
{
#if defined(__amd64)

	return (__hypercall2(__HYPERVISOR_update_descriptor, ma, desc));

#elif defined(__i386)

	return (__hypercall4(__HYPERVISOR_update_descriptor,
	    (ulong_t)ma, (ulong_t)(ma >>32),
	    (ulong_t)desc, (ulong_t)(desc >> 32)));

#endif
}

long
HYPERVISOR_memory_op(int cmd, void *arg)
{
	return (__hypercall2(__HYPERVISOR_memory_op, (long)cmd,
	    (ulong_t)arg));
}

long
HYPERVISOR_multicall(void *call_list, uint_t nr_calls)
{
	return (__hypercall2(__HYPERVISOR_multicall,
	    (ulong_t)call_list, (ulong_t)nr_calls));
}

int
HYPERVISOR_update_va_mapping(ulong_t va, uint64_t new_pte, ulong_t flags)
{
#if !defined(_BOOT)
	if (IN_XPV_PANIC())
		return (0);
#endif
#if defined(__amd64)

	return (__hypercall3_int(__HYPERVISOR_update_va_mapping, va,
	    new_pte, flags));

#elif defined(__i386)

	return (__hypercall4_int(__HYPERVISOR_update_va_mapping, va,
	    (ulong_t)new_pte, (ulong_t)(new_pte >> 32), flags));

#endif	/* __i386 */
}

/*
 * Note: this timeout must be the Xen system time not hrtime (see
 * xpv_timestamp.c).
 */
long
HYPERVISOR_set_timer_op(uint64_t timeout)
{
#if defined(__amd64)

	return (__hypercall1(__HYPERVISOR_set_timer_op, timeout));

#elif defined(__i386)

	uint32_t timeout_hi = (uint32_t)(timeout >> 32);
	uint32_t timeout_lo = (uint32_t)timeout;
	return (__hypercall2(__HYPERVISOR_set_timer_op,
	    (ulong_t)timeout_lo, (ulong_t)timeout_hi));

#endif	/* __i386 */
}

/* *** __HYPERVISOR_event_channel_op_compat *** OBSOLETED */

long
HYPERVISOR_xen_version(int cmd, void *arg)
{
	return (__hypercall2(__HYPERVISOR_xen_version, (long)cmd,
	    (ulong_t)arg));
}

long
HYPERVISOR_console_io(int cmd, int count, char *str)
{
	return (__hypercall3(__HYPERVISOR_console_io, (long)cmd, (long)count,
	    (ulong_t)str));
}

/* *** __HYPERVISOR_physdev_op_compat *** OBSOLETED */

/*
 * ****
 * NOTE: this hypercall should not be called directly for a
 * GNTTABOP_map_grant_ref. Instead xen_map_gref() should be called.
 * ****
 */
long
HYPERVISOR_grant_table_op(uint_t cmd, void *uop, uint_t count)
{
	int ret_val;
	ret_val = __hypercall3(__HYPERVISOR_grant_table_op,
	    (long)cmd, (ulong_t)uop, (ulong_t)count);
	return (ret_val);
}

long
HYPERVISOR_vm_assist(uint_t cmd, uint_t type)
{
	return (__hypercall2(__HYPERVISOR_vm_assist,
	    (ulong_t)cmd, (ulong_t)type));
}

int
HYPERVISOR_update_va_mapping_otherdomain(ulong_t va,
    uint64_t new_pte, ulong_t flags, domid_t domain_id)
{
#if defined(__amd64)

	return (__hypercall4_int(__HYPERVISOR_update_va_mapping_otherdomain,
	    va, new_pte, flags, (ulong_t)domain_id));

#elif defined(__i386)

	return (__hypercall5_int(__HYPERVISOR_update_va_mapping_otherdomain,
	    va, (ulong_t)new_pte, (ulong_t)(new_pte >> 32), flags,
	    (ulong_t)domain_id));

#endif	/* __i386 */
}

/*
 * *** __HYPERVISOR_iret ***
 *   see HYPERVISOR_IRET() macro in i86xpv/sys/machprivregs.h
 */

long
HYPERVISOR_vcpu_op(int cmd, int vcpuid, void *extra_args)
{
	return (__hypercall3(__HYPERVISOR_vcpu_op, (long)cmd, (long)vcpuid,
	    (ulong_t)extra_args));
}

#if defined(__amd64)

long
HYPERVISOR_set_segment_base(int reg, ulong_t value)
{
	return (__hypercall2(__HYPERVISOR_set_segment_base, (long)reg, value));
}

#endif	/* __amd64 */

int
HYPERVISOR_mmuext_op(struct mmuext_op *req, int count, uint_t *success_count,
    domid_t domain_id)
{
	return (__hypercall4_int(__HYPERVISOR_mmuext_op,
	    (ulong_t)req, (long)count, (ulong_t)success_count,
	    (ulong_t)domain_id));
}

long
HYPERVISOR_nmi_op(int cmd, void *arg)
{
	return (__hypercall2(__HYPERVISOR_nmi_op, (long)cmd, (ulong_t)arg));
}

long
HYPERVISOR_sched_op(int cmd, void *arg)
{
	return (__hypercall2(__HYPERVISOR_sched_op,
	    (ulong_t)cmd, (ulong_t)arg));
}

long
HYPERVISOR_callback_op(int cmd, void *arg)
{
	return (__hypercall2(__HYPERVISOR_callback_op,
	    (ulong_t)cmd, (ulong_t)arg));
}

/* *** __HYPERVISOR_xenoprof_op *** NOT IMPLEMENTED */

long
HYPERVISOR_event_channel_op(int cmd, void *arg)
{
	return (__hypercall2(__HYPERVISOR_event_channel_op, (long)cmd,
	    (ulong_t)arg));
}

long
HYPERVISOR_physdev_op(int cmd, void *arg)
{
	return (__hypercall2(__HYPERVISOR_physdev_op, (long)cmd,
	    (ulong_t)arg));
}

long
HYPERVISOR_hvm_op(int cmd, void *arg)
{
	return (__hypercall2(__HYPERVISOR_hvm_op, (long)cmd, (ulong_t)arg));
}

#if defined(__xpv)
long
HYPERVISOR_xsm_op(struct xen_acmctl *arg)
{
	return (__hypercall1(__HYPERVISOR_xsm_op, (ulong_t)arg));
}

long
HYPERVISOR_sysctl(xen_sysctl_t *sysctl)
{
	return (__hypercall1(__HYPERVISOR_sysctl, (ulong_t)sysctl));
}

long
HYPERVISOR_domctl(xen_domctl_t *domctl)
{
	return (__hypercall1(__HYPERVISOR_domctl, (ulong_t)domctl));
}
#endif /* __xpv */

/* *** __HYPERVISOR_kexec_op *** NOT IMPLEMENTED */

/*
 *
 * HYPERCALL HELPER ROUTINES
 *    These don't have there own unique hypercalls.
 *
 */

long
HYPERVISOR_yield(void)
{
	return (HYPERVISOR_sched_op(SCHEDOP_yield, NULL));
}

long
HYPERVISOR_block(void)
{
	return (HYPERVISOR_sched_op(SCHEDOP_block, NULL));
}

long
HYPERVISOR_shutdown(uint_t reason)
{
	struct sched_shutdown sched_shutdown;

	sched_shutdown.reason = reason;

	return (HYPERVISOR_sched_op(SCHEDOP_shutdown, &sched_shutdown));
}

/*
 * Poll one or more event-channel ports, and return when pending.
 * An optional timeout (in nanoseconds, absolute time since boot) may be
 * specified. Note: this timeout must be the Xen system time not hrtime (see
 * xpv_timestamp.c).
 */
long
HYPERVISOR_poll(evtchn_port_t *ports, uint_t nr_ports, uint64_t timeout)
{
	struct sched_poll sched_poll;

	/*LINTED: constant in conditional context*/
	set_xen_guest_handle(sched_poll.ports, ports);
	sched_poll.nr_ports = nr_ports;
	sched_poll.timeout = timeout;

	return (HYPERVISOR_sched_op(SCHEDOP_poll, &sched_poll));
}

long
HYPERVISOR_suspend(ulong_t start_info_mfn)
{
	struct sched_shutdown sched_shutdown;

	sched_shutdown.reason = SHUTDOWN_suspend;

	return (__hypercall3(__HYPERVISOR_sched_op, SCHEDOP_shutdown,
	    (ulong_t)&sched_shutdown, start_info_mfn));
}

long
HYPERVISOR_mca(uint32_t cmd, xen_mc_t *xmcp)
{
	long rv;

	switch (cmd) {
	case XEN_MC_fetch:
	case XEN_MC_physcpuinfo:
	case XEN_MC_msrinject:
	case XEN_MC_mceinject:
		break;

	case XEN_MC_notifydomain:
		return (ENOTSUP);

	default:
		return (EINVAL);
	}

	xmcp->interface_version = XEN_MCA_INTERFACE_VERSION;
	xmcp->cmd = cmd;

	rv = __hypercall1(__HYPERVISOR_mca, (ulong_t)xmcp);

	return (rv);
}
