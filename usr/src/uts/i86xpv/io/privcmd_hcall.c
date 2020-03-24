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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/xpv_user.h>

#include <sys/types.h>
#include <sys/file.h>
#include <sys/errno.h>
#include <sys/open.h>
#include <sys/cred.h>
#include <sys/conf.h>
#include <sys/stat.h>
#include <sys/modctl.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/vmsystm.h>
#include <sys/hypervisor.h>
#include <sys/xen_errno.h>
#include <sys/sysmacros.h>
#include <sys/sdt.h>

#include <xen/sys/privcmd.h>
#include <sys/privcmd_impl.h>

typedef struct import_export {
	void *			ie_uaddr;
	void *			ie_kaddr;
	size_t			ie_size;
	uint32_t		ie_flags;
} import_export_t;

static import_export_t null_ie = {NULL, NULL, 0, 0};

#define	IE_IMPORT	0x0001		/* Data needs to be copied in */
#define	IE_EXPORT	0x0002		/* Data needs to be copied out */
#define	IE_FREE		0x0004
#define	IE_IMPEXP	(IE_IMPORT | IE_EXPORT)

static void *
uaddr_from_handle(void *field)
{
	struct { void *p; } *hdl = field;
	void *ptr;

	/*LINTED: constant in conditional context*/
	get_xen_guest_handle(ptr, (*hdl));
	return (ptr);
}


/*
 * Import a buffer from user-space.  If the caller provides a kernel
 * address, we import to that address.  If not, we kmem_alloc() the space
 * ourselves.
 */
static int
import_buffer(import_export_t *iep, void *uaddr, void *kaddr, size_t size,
    uint32_t flags)
{
	iep->ie_uaddr = uaddr;
	iep->ie_size = size;
	iep->ie_flags = flags & IE_EXPORT;

	if (size == 0 || uaddr == NULL) {
		*iep = null_ie;
		return (0);
	}

	if (kaddr == NULL) {
		iep->ie_kaddr = kmem_alloc(size, KM_SLEEP);
		iep->ie_flags |= IE_FREE;
	} else {
		iep->ie_kaddr = kaddr;
		iep->ie_flags &= ~IE_FREE;
	}

	if ((flags & IE_IMPORT) &&
	    (ddi_copyin(uaddr, iep->ie_kaddr, size, 0) != 0)) {
		if (iep->ie_flags & IE_FREE) {
			kmem_free(iep->ie_kaddr, iep->ie_size);
			iep->ie_kaddr = NULL;
			iep->ie_flags = 0;
		}
		return (-X_EFAULT);
	}

	return (0);
}

static void
export_buffer(import_export_t *iep, int *error)
{
	int copy_err = 0;

	if (iep->ie_size == 0 || iep->ie_uaddr == NULL)
		return;

	/*
	 * If the buffer was marked for export initially, and if the
	 * hypercall completed successfully, resync the user-space buffer
	 * with our in-kernel buffer.
	 */
	if ((iep->ie_flags & IE_EXPORT) && (*error >= 0) &&
	    (ddi_copyout(iep->ie_kaddr, iep->ie_uaddr, iep->ie_size, 0) != 0))
		copy_err = -X_EFAULT;
	if (iep->ie_flags & IE_FREE) {
		kmem_free(iep->ie_kaddr, iep->ie_size);
		iep->ie_kaddr = NULL;
		iep->ie_flags = 0;
	}

	if (copy_err != 0 && *error >= 0)
		*error = copy_err;
}

/*
 * Xen 'op' structures often include pointers disguised as 'handles', which
 * refer to addresses in user space.  This routine copies a buffer
 * associated with an embedded pointer into kernel space, and replaces the
 * pointer to userspace with a pointer to the new kernel buffer.
 *
 * Note: if Xen ever redefines the structure of a 'handle', this routine
 * (specifically the definition of 'hdl') will need to be updated.
 */
static int
import_handle(import_export_t *iep, void *field, size_t size, int flags)
{
	struct { void *p; } *hdl = field;
	void *ptr;
	int err;

	ptr = uaddr_from_handle(field);
	err = import_buffer(iep, ptr, NULL, size, (flags));
	if (err == 0) {
		/*LINTED: constant in conditional context*/
		set_xen_guest_handle((*hdl), (void *)((iep)->ie_kaddr));
	}
	return (err);
}

static int
privcmd_HYPERVISOR_mmu_update(mmu_update_t *ureq, int count, int *scount,
    domid_t domid)
{
	mmu_update_t *kreq, single_kreq;
	import_export_t cnt_ie, req_ie;
	int error, kscount, bytes;

	bytes = count * sizeof (*kreq);
	kreq = (count == 1) ? &single_kreq : kmem_alloc(bytes, KM_SLEEP);

	error = import_buffer(&cnt_ie, scount, &kscount, sizeof (kscount),
	    IE_IMPEXP);
	if (error != 0)
		req_ie = null_ie;
	else
		error = import_buffer(&req_ie, ureq, kreq, bytes, IE_IMPEXP);

	DTRACE_XPV3(mmu__update__start, int, domid, int, count, mmu_update_t *,
	    ((error == -X_EFAULT) ? ureq : kreq));

	if (error == 0)
		error = HYPERVISOR_mmu_update(kreq, count, &kscount, domid);
	export_buffer(&cnt_ie, &error);
	export_buffer(&req_ie, &error);
	if (count != 1)
		kmem_free(kreq, bytes);

	DTRACE_XPV1(mmu__update__end, int, error);
	return (error);
}

static int
privcmd_HYPERVISOR_domctl(xen_domctl_t *opp)
{
	xen_domctl_t op;
	import_export_t op_ie, sub_ie;
	int error = 0;

	if ((error = import_buffer(&op_ie, opp, &op, sizeof (op),
	    IE_IMPEXP)) != 0)
		return (error);

	sub_ie = null_ie;

	/*
	 * Check this first because our wrapper will forcibly overwrite it.
	 */
	if (op.interface_version != XEN_DOMCTL_INTERFACE_VERSION) {
#ifdef DEBUG
		printf("domctl vers mismatch (cmd %d, found 0x%x, need 0x%x\n",
		    op.cmd, op.interface_version, XEN_DOMCTL_INTERFACE_VERSION);
#endif
		error = -X_EACCES;
		export_buffer(&op_ie, &error);
		return (error);
	}

	/*
	 * Now handle any domctl ops with embedded pointers elsewhere
	 * in the user address space that also need to be tacked down
	 * while the hypervisor futzes with them.
	 */
	switch (op.cmd) {
	case XEN_DOMCTL_createdomain:
		DTRACE_XPV1(dom__create__start, xen_domctl_t *,
		    &op.u.createdomain);
		break;

	case XEN_DOMCTL_destroydomain:
		DTRACE_XPV1(dom__destroy__start, domid_t, op.domain);
		break;

	case XEN_DOMCTL_pausedomain:
		DTRACE_XPV1(dom__pause__start, domid_t, op.domain);
		break;

	case XEN_DOMCTL_unpausedomain:
		DTRACE_XPV1(dom__unpause__start, domid_t, op.domain);
		break;

	case XEN_DOMCTL_getmemlist: {
		error = import_handle(&sub_ie, &op.u.getmemlist.buffer,
		    op.u.getmemlist.max_pfns * sizeof (xen_pfn_t), IE_EXPORT);
		break;
	}

	case XEN_DOMCTL_getpageframeinfo2: {
		error = import_handle(&sub_ie, &op.u.getpageframeinfo2.array,
		    op.u.getpageframeinfo2.num * sizeof (ulong_t), IE_IMPEXP);
		break;
	}

	case XEN_DOMCTL_shadow_op: {
		size_t size;

		size = roundup(howmany(op.u.shadow_op.pages, NBBY),
		    sizeof (ulong_t));
		error = import_handle(&sub_ie,
		    &op.u.shadow_op.dirty_bitmap, size, IE_IMPEXP);
		break;
	}

	case XEN_DOMCTL_setvcpucontext: {
		vcpu_guest_context_t *taddr;
		error = import_handle(&sub_ie, &op.u.vcpucontext.ctxt,
		    sizeof (vcpu_guest_context_t), IE_IMPORT);
		if (error == -X_EFAULT)
			/*LINTED: constant in conditional context*/
			get_xen_guest_handle_u(taddr, op.u.vcpucontext.ctxt);
		else
			taddr = sub_ie.ie_kaddr;
		DTRACE_XPV2(setvcpucontext__start, domid_t, op.domain,
		    vcpu_guest_context_t *, taddr);
		break;
	}

	case XEN_DOMCTL_getvcpucontext: {
		error = import_handle(&sub_ie, &op.u.vcpucontext.ctxt,
		    sizeof (vcpu_guest_context_t), IE_EXPORT);
		break;
	}


	case XEN_DOMCTL_sethvmcontext: {
		error = import_handle(&sub_ie, &op.u.hvmcontext.buffer,
		    op.u.hvmcontext.size, IE_IMPORT);
		break;
	}

	case XEN_DOMCTL_gethvmcontext: {
#if !defined(__GNUC__) && defined(__i386__)
		if (op.u.hvmcontext.buffer.u.p != NULL)
#else
		if (op.u.hvmcontext.buffer.p != NULL)
#endif
			error = import_handle(&sub_ie, &op.u.hvmcontext.buffer,
			    op.u.hvmcontext.size, IE_EXPORT);
		break;
	}

	case XEN_DOMCTL_getdomaininfo:
	case XEN_DOMCTL_getpageframeinfo:
	case XEN_DOMCTL_max_mem:
	case XEN_DOMCTL_resumedomain:
	case XEN_DOMCTL_getvcpuinfo:
	case XEN_DOMCTL_setvcpuaffinity:
	case XEN_DOMCTL_getvcpuaffinity:
	case XEN_DOMCTL_max_vcpus:
	case XEN_DOMCTL_scheduler_op:
	case XEN_DOMCTL_setdomainhandle:
	case XEN_DOMCTL_setdebugging:
	case XEN_DOMCTL_irq_permission:
	case XEN_DOMCTL_iomem_permission:
	case XEN_DOMCTL_ioport_permission:
	case XEN_DOMCTL_hypercall_init:
	case XEN_DOMCTL_arch_setup:
	case XEN_DOMCTL_settimeoffset:
	case XEN_DOMCTL_real_mode_area:
	case XEN_DOMCTL_sendtrigger:
	case XEN_DOMCTL_assign_device:
	case XEN_DOMCTL_bind_pt_irq:
	case XEN_DOMCTL_get_address_size:
	case XEN_DOMCTL_set_address_size:
	case XEN_DOMCTL_get_ext_vcpucontext:
	case XEN_DOMCTL_set_ext_vcpucontext:
	case XEN_DOMCTL_set_opt_feature:
	case XEN_DOMCTL_memory_mapping:
	case XEN_DOMCTL_ioport_mapping:
	case XEN_DOMCTL_pin_mem_cacheattr:
	case XEN_DOMCTL_test_assign_device:
	case XEN_DOMCTL_set_target:
	case XEN_DOMCTL_deassign_device:
	case XEN_DOMCTL_set_cpuid:
	case XEN_DOMCTL_get_device_group:
	case XEN_DOMCTL_get_machine_address_size:
	case XEN_DOMCTL_set_machine_address_size:
	case XEN_DOMCTL_suppress_spurious_page_faults:
		break;

	default:
#ifdef DEBUG
		printf("unrecognized HYPERVISOR_domctl %d\n", op.cmd);
#endif
		error = -X_EINVAL;
	}

	if (error == 0)
		error = HYPERVISOR_domctl(&op);

	export_buffer(&op_ie, &error);
	export_buffer(&sub_ie, &error);

	switch (op.cmd) {
	case XEN_DOMCTL_createdomain:
		DTRACE_XPV1(dom__create__end, int, error);
		break;
	case XEN_DOMCTL_destroydomain:
		DTRACE_XPV1(dom__destroy__end, int, error);
		break;
	case XEN_DOMCTL_pausedomain:
		DTRACE_XPV1(dom__pause__end, int, error);
		break;
	case XEN_DOMCTL_unpausedomain:
		DTRACE_XPV1(dom__unpause__end, int, error);
		break;
	case XEN_DOMCTL_setvcpucontext:
		DTRACE_XPV1(setvcpucontext__end, int, error);
		break;
	default:
		;
	}

	return (error);
}

static int
privcmd_HYPERVISOR_sysctl(xen_sysctl_t *opp)
{
	xen_sysctl_t op, dop;
	import_export_t op_ie, sub_ie, sub2_ie;
	int error = 0;

	if (import_buffer(&op_ie, opp, &op, sizeof (op), IE_IMPEXP) != 0)
		return (-X_EFAULT);

	sub_ie = null_ie;
	sub2_ie = null_ie;

	/*
	 * Check this first because our wrapper will forcibly overwrite it.
	 */
	if (op.interface_version != XEN_SYSCTL_INTERFACE_VERSION) {
		error = -X_EACCES;
		export_buffer(&op_ie, &error);
		return (error);
	}

	switch (op.cmd) {
	case XEN_SYSCTL_readconsole: {
		error = import_handle(&sub_ie, &op.u.readconsole.buffer,
		    op.u.readconsole.count, IE_EXPORT);
		break;
	}

	case XEN_SYSCTL_debug_keys: {
		error = import_handle(&sub_ie, &op.u.debug_keys.keys,
		    op.u.debug_keys.nr_keys, IE_IMPORT);
		break;
	}

	case XEN_SYSCTL_tbuf_op:
	case XEN_SYSCTL_physinfo: {
		if (uaddr_from_handle(&op.u.physinfo.cpu_to_node) != NULL &&
		    op.u.physinfo.max_cpu_id != 0) {
			error = import_handle(&sub_ie,
			    &op.u.physinfo.cpu_to_node,
			    op.u.physinfo.max_cpu_id * sizeof (uint32_t),
			    IE_EXPORT);
		}
		break;
	}
	case XEN_SYSCTL_sched_id:
	case XEN_SYSCTL_availheap:
	case XEN_SYSCTL_cpu_hotplug:
		break;
	case XEN_SYSCTL_get_pmstat: {
		unsigned int maxs;

		switch (op.u.get_pmstat.type) {
		case PMSTAT_get_pxstat:
			/*
			 * This interface is broken. Xen always copies out
			 * all the state information, and the interface
			 * does not specify how much space the caller has
			 * reserved. So, the only thing to do is just mirror
			 * the hypervisor and libxc behavior, and use the
			 * maximum amount of data.
			 */
			dop.cmd = XEN_SYSCTL_get_pmstat;
			dop.interface_version = XEN_SYSCTL_INTERFACE_VERSION;
			dop.u.get_pmstat.cpuid = op.u.get_pmstat.cpuid;
			dop.u.get_pmstat.type = PMSTAT_get_max_px;
			error = HYPERVISOR_sysctl(&dop);
			if (error != 0)
				break;

			maxs = dop.u.get_pmstat.u.getpx.total;
			if (maxs == 0) {
				error = -X_EINVAL;
				break;
			}

			error = import_handle(&sub_ie,
			    &op.u.get_pmstat.u.getpx.trans_pt,
			    maxs * maxs * sizeof (uint64_t), IE_EXPORT);
			if (error != 0)
				break;

			error = import_handle(&sub2_ie,
			    &op.u.get_pmstat.u.getpx.pt,
			    maxs * sizeof (pm_px_val_t), IE_EXPORT);
			break;
		case PMSTAT_get_cxstat:
			/* See above */
			dop.cmd = XEN_SYSCTL_get_pmstat;
			dop.interface_version = XEN_SYSCTL_INTERFACE_VERSION;
			dop.u.get_pmstat.cpuid = op.u.get_pmstat.cpuid;
			dop.u.get_pmstat.type = PMSTAT_get_max_cx;
			error = HYPERVISOR_sysctl(&dop);
			if (error != 0)
				break;

			maxs = dop.u.get_pmstat.u.getcx.nr;
			if (maxs == 0) {
				error = -X_EINVAL;
				break;
			}

			error = import_handle(&sub_ie,
			    &op.u.get_pmstat.u.getcx.triggers,
			    maxs * sizeof (uint64_t), IE_EXPORT);
			if (error != 0)
				break;
			error = import_handle(&sub2_ie,
			    &op.u.get_pmstat.u.getcx.residencies,
			    maxs * sizeof (uint64_t), IE_EXPORT);
			break;

		case PMSTAT_get_max_px:
		case PMSTAT_reset_pxstat:
		case PMSTAT_get_max_cx:
		case PMSTAT_reset_cxstat:
			break;
		default:
			error = -X_EINVAL;
			break;
		}
		break;
	}

	case XEN_SYSCTL_perfc_op: {
		xen_sysctl_perfc_desc_t *scdp;
		/*
		 * If 'desc' is NULL, then the caller is asking for
		 * the number of counters.  If 'desc' is non-NULL,
		 * then we need to know how many counters there are
		 * before wiring down the output buffer appropriately.
		 */
		/*LINTED: constant in conditional context*/
		get_xen_guest_handle_u(scdp, op.u.perfc_op.desc);
		if (scdp != NULL) {
			static int numcounters = -1;
			static int numvals = -1;

			if (numcounters == -1) {
				dop.cmd = XEN_SYSCTL_perfc_op;
				dop.interface_version =
				    XEN_SYSCTL_INTERFACE_VERSION;
				dop.u.perfc_op.cmd = XEN_SYSCTL_PERFCOP_query;
				/*LINTED: constant in conditional context*/
				set_xen_guest_handle_u(dop.u.perfc_op.desc,
				    NULL);
				/*LINTED: constant in conditional context*/
				set_xen_guest_handle_u(dop.u.perfc_op.val,
				    NULL);

				error = HYPERVISOR_sysctl(&dop);
				if (error != 0)
					break;
				numcounters = dop.u.perfc_op.nr_counters;
				numvals = dop.u.perfc_op.nr_vals;
			}
			ASSERT(numcounters != -1);
			ASSERT(numvals != -1);
			error = import_handle(&sub_ie, &op.u.perfc_op.desc,
			    (sizeof (xen_sysctl_perfc_desc_t) * numcounters),
			    IE_EXPORT);
			error = import_handle(&sub2_ie, &op.u.perfc_op.val,
			    (sizeof (xen_sysctl_perfc_val_t) * numvals),
			    IE_EXPORT);
		}
		break;
	}

	case XEN_SYSCTL_getdomaininfolist: {
		error = import_handle(&sub_ie, &op.u.getdomaininfolist.buffer,
		    (op.u.getdomaininfolist.max_domains *
		    sizeof (xen_domctl_getdomaininfo_t)), IE_EXPORT);
		break;
	}

	case XEN_SYSCTL_getcpuinfo:
		error = import_handle(&sub_ie, &op.u.getcpuinfo.info,
		    op.u.getcpuinfo.max_cpus *
		    sizeof (xen_sysctl_cpuinfo_t), IE_EXPORT);
		break;
	default:
#ifdef DEBUG
		printf("unrecognized HYPERVISOR_sysctl %d\n", op.cmd);
#endif
		error = -X_EINVAL;
	}

	if (error == 0)
		error = HYPERVISOR_sysctl(&op);

	export_buffer(&op_ie, &error);
	export_buffer(&sub_ie, &error);
	export_buffer(&sub2_ie, &error);

	return (error);
}

static int
privcmd_HYPERVISOR_platform_op(xen_platform_op_t *opp)
{
	import_export_t op_ie, sub_ie, sub2_ie;
	xen_platform_op_t op;
	int error;

	if (import_buffer(&op_ie, opp, &op, sizeof (op), IE_IMPEXP) != 0)
		return (-X_EFAULT);

	sub_ie = null_ie;
	sub2_ie = null_ie;

	/*
	 * Check this first because our wrapper will forcibly overwrite it.
	 */
	if (op.interface_version != XENPF_INTERFACE_VERSION) {
		error = -X_EACCES;
		export_buffer(&op_ie, &error);
		return (error);
	}

	/*
	 * Now handle any platform ops with embedded pointers elsewhere
	 * in the user address space that also need to be tacked down
	 * while the hypervisor futzes with them.
	 */
	switch (op.cmd) {
	case XENPF_settime:
	case XENPF_add_memtype:
	case XENPF_del_memtype:
	case XENPF_read_memtype:
	case XENPF_platform_quirk:
	case XENPF_enter_acpi_sleep:
	case XENPF_change_freq:
	case XENPF_panic_init:
		break;

	case XENPF_microcode_update:
		error = import_handle(&sub_ie, &op.u.microcode.data,
		    op.u.microcode.length, IE_IMPORT);
		break;
	case XENPF_getidletime:
		error = import_handle(&sub_ie, &op.u.getidletime.cpumap_bitmap,
		    op.u.getidletime.cpumap_nr_cpus, IE_IMPEXP);
		if (error != 0)
			break;

		error = import_handle(&sub2_ie, &op.u.getidletime.idletime,
		    op.u.getidletime.cpumap_nr_cpus * sizeof (uint64_t),
		    IE_EXPORT);
		break;

	case XENPF_set_processor_pminfo: {
		size_t s;

		switch (op.u.set_pminfo.type) {
		case XEN_PM_PX:
			s = op.u.set_pminfo.u.perf.state_count *
			    sizeof (xen_processor_px_t);
			if (op.u.set_pminfo.u.perf.flags & XEN_PX_PSS) {
				error = import_handle(&sub_ie,
				    &op.u.set_pminfo.u.perf.states, s,
				    IE_IMPORT);
			}
			break;
		case XEN_PM_CX:
			s = op.u.set_pminfo.u.power.count *
			    sizeof (xen_processor_cx_t);
			error = import_handle(&sub_ie,
			    &op.u.set_pminfo.u.power.states, s, IE_IMPORT);
			break;
		case XEN_PM_TX:
			break;
		default:
			error = -X_EINVAL;
			break;
		}
		break;
	}
	case XENPF_firmware_info: {
		uint16_t len;
		void *uaddr;

		switch (op.u.firmware_info.type) {
		case XEN_FW_DISK_INFO:
			/*
			 * Ugh.. another hokey interface. The first 16 bits
			 * of the buffer are also used as the (input) length.
			 */
			uaddr = uaddr_from_handle(
			    &op.u.firmware_info.u.disk_info.edd_params);
			error = ddi_copyin(uaddr, &len, sizeof (len), 0);
			if (error != 0)
				break;
			error = import_handle(&sub_ie,
			    &op.u.firmware_info.u.disk_info.edd_params, len,
			    IE_IMPEXP);
			break;
		case XEN_FW_VBEDDC_INFO:
			error = import_handle(&sub_ie,
			    &op.u.firmware_info.u.vbeddc_info.edid, 128,
			    IE_EXPORT);
			break;
		case XEN_FW_DISK_MBR_SIGNATURE:
		default:
			break;
		}
		break;
	}
	default:
		/* FIXME: see this with non-existed ID 38 ???? */
#ifdef DEBUG
		printf("unrecognized HYPERVISOR_platform_op %d pid %d\n",
		    op.cmd, curthread->t_procp->p_pid);
#endif
		return (-X_EINVAL);
	}

	if (error == 0)
		error = HYPERVISOR_platform_op(&op);

	export_buffer(&op_ie, &error);
	export_buffer(&sub_ie, &error);
	export_buffer(&sub2_ie, &error);

	return (error);
}

static int
privcmd_HYPERVISOR_memory_op(int cmd, void *arg)
{
	int error = 0;
	import_export_t op_ie, sub_ie, gpfn_ie, mfn_ie;
	union {
		domid_t domid;
		struct xen_memory_reservation resv;
		struct xen_machphys_mfn_list xmml;
		struct xen_add_to_physmap xatp;
		struct xen_memory_map mm;
		struct xen_foreign_memory_map fmm;
		struct xen_pod_target pd;
	} op_arg;

	op_ie = sub_ie = gpfn_ie = mfn_ie = null_ie;

	switch (cmd) {
	case XENMEM_increase_reservation:
	case XENMEM_decrease_reservation:
	case XENMEM_populate_physmap: {
		ulong_t *taddr;

		if (import_buffer(&op_ie, arg, &op_arg, sizeof (op_arg.resv),
		    IE_IMPEXP) != 0)
			return (-X_EFAULT);

		error = import_handle(&sub_ie, &op_arg.resv.extent_start,
		    (op_arg.resv.nr_extents * sizeof (ulong_t)), IE_IMPEXP);

		if (error == -X_EFAULT)
			/*LINTED: constant in conditional context*/
			get_xen_guest_handle(taddr, op_arg.resv.extent_start);
		else
			taddr = sub_ie.ie_kaddr;

		switch (cmd) {
		case XENMEM_increase_reservation:
			DTRACE_XPV4(increase__reservation__start,
			    domid_t, op_arg.resv.domid,
			    ulong_t, op_arg.resv.nr_extents,
			    uint_t, op_arg.resv.extent_order,
			    ulong_t *, taddr);
			break;
		case XENMEM_decrease_reservation:
			DTRACE_XPV4(decrease__reservation__start,
			    domid_t, op_arg.resv.domid,
			    ulong_t, op_arg.resv.nr_extents,
			    uint_t, op_arg.resv.extent_order,
			    ulong_t *, taddr);
			break;
		case XENMEM_populate_physmap:
			DTRACE_XPV3(populate__physmap__start,
			    domid_t, op_arg.resv.domid,
			    ulong_t, op_arg.resv.nr_extents,
			    ulong_t *, taddr);
			break;
		}

		break;
	}

	case XENMEM_maximum_ram_page:
		break;

	case XENMEM_current_reservation:
	case XENMEM_maximum_reservation:
	case XENMEM_maximum_gpfn:
		if (import_buffer(&op_ie, arg, &op_arg, sizeof (op_arg.domid),
		    IE_IMPEXP) != 0)
			return (-X_EFAULT);
		break;

	case XENMEM_machphys_mfn_list: {
		if (import_buffer(&op_ie, arg, &op_arg, sizeof (op_arg.xmml),
		    IE_IMPEXP) != 0)
			return (-X_EFAULT);

		error = import_handle(&sub_ie, &op_arg.xmml.extent_start,
		    (op_arg.xmml.max_extents * sizeof (ulong_t)), IE_IMPEXP);
		break;
	}

	case XENMEM_add_to_physmap:
		if (import_buffer(&op_ie, arg, &op_arg, sizeof (op_arg.xatp),
		    IE_IMPEXP) != 0)
			return (-X_EFAULT);
		DTRACE_XPV4(add__to__physmap__start, domid_t,
		    op_arg.xatp.domid, uint_t, op_arg.xatp.space, ulong_t,
		    op_arg.xatp.idx, ulong_t, op_arg.xatp.gpfn);
		break;

	case XENMEM_memory_map:
	case XENMEM_machine_memory_map: {
		if (import_buffer(&op_ie, arg, &op_arg, sizeof (op_arg.mm),
		    IE_EXPORT) != 0)
			return (-X_EFAULT);

		/*
		 * XXPV: ugh. e820entry is packed, but not in the kernel, since
		 * we remove all attributes; seems like this is a nice way to
		 * break mysteriously.
		 */
		error = import_handle(&sub_ie, &op_arg.mm.buffer,
		    (op_arg.mm.nr_entries * 20), IE_IMPEXP);
		break;
	}

	case XENMEM_set_memory_map: {
		struct xen_memory_map *taddr;
		if (import_buffer(&op_ie, arg, &op_arg, sizeof (op_arg.fmm),
		    IE_IMPORT) != 0)
			return (-X_EFAULT);

		/*
		 * As above.
		 */
		error = import_handle(&sub_ie, &op_arg.fmm.map.buffer,
		    (op_arg.fmm.map.nr_entries * 20), IE_IMPEXP);

		if (error == -X_EFAULT)
			/*LINTED: constant in conditional context*/
			get_xen_guest_handle(taddr, op_arg.fmm.map.buffer);
		else
			taddr = sub_ie.ie_kaddr;
		DTRACE_XPV3(set__memory__map__start, domid_t,
		    op_arg.fmm.domid, int, op_arg.fmm.map.nr_entries,
		    struct xen_memory_map *, taddr);
		break;
	}

	case XENMEM_set_pod_target:
	case XENMEM_get_pod_target:
		if (import_buffer(&op_ie, arg, &op_arg, sizeof (op_arg.pd),
		    IE_IMPEXP) != 0)
			return (-X_EFAULT);
		break;

	default:
#ifdef DEBUG
		printf("unrecognized HYPERVISOR_memory_op %d\n", cmd);
#endif
		return (-X_EINVAL);
	}

	if (error == 0)
		error = HYPERVISOR_memory_op(cmd,
		    (arg == NULL) ? NULL: &op_arg);

	export_buffer(&op_ie, &error);
	export_buffer(&sub_ie, &error);
	export_buffer(&gpfn_ie, &error);
	export_buffer(&mfn_ie, &error);

	switch (cmd) {
	case XENMEM_increase_reservation:
		DTRACE_XPV1(increase__reservation__end, int, error);
		break;
	case XENMEM_decrease_reservation:
		DTRACE_XPV1(decrease__reservation__end, int, error);
		break;
	case XENMEM_populate_physmap:
		DTRACE_XPV1(populate__physmap__end, int, error);
		break;
	case XENMEM_add_to_physmap:
		DTRACE_XPV1(add__to__physmap__end, int, error);
		break;
	case XENMEM_set_memory_map:
		DTRACE_XPV1(set__memory__map__end, int, error);
		break;
	}
	return (error);
}

static int
privcmd_HYPERVISOR_event_channel_op(int cmd, void *arg)
{
	int error;
	size_t size;
	import_export_t op_ie;
	uint32_t flags;

	switch (cmd) {
	case EVTCHNOP_alloc_unbound:
		size = sizeof (evtchn_alloc_unbound_t);
		flags = IE_IMPEXP;
		break;
	case EVTCHNOP_bind_interdomain:
		size = sizeof (evtchn_bind_interdomain_t);
		flags = IE_IMPEXP;
		break;
	case EVTCHNOP_bind_virq:
		size = sizeof (evtchn_bind_virq_t);
		flags = IE_IMPEXP;
		break;
	case EVTCHNOP_bind_pirq:
		size = sizeof (evtchn_bind_pirq_t);
		flags = IE_IMPEXP;
		break;
	case EVTCHNOP_bind_ipi:
		size = sizeof (evtchn_bind_ipi_t);
		flags = IE_IMPEXP;
		break;
	case EVTCHNOP_close:
		size = sizeof (evtchn_close_t);
		flags = IE_IMPORT;
		break;
	case EVTCHNOP_send:
		size = sizeof (evtchn_send_t);
		flags = IE_IMPORT;
		break;
	case EVTCHNOP_status:
		size = sizeof (evtchn_status_t);
		flags = IE_IMPEXP;
		break;
	case EVTCHNOP_bind_vcpu:
		size = sizeof (evtchn_bind_vcpu_t);
		flags = IE_IMPORT;
		break;
	case EVTCHNOP_unmask:
		size = sizeof (evtchn_unmask_t);
		flags = IE_IMPORT;
		break;
	case EVTCHNOP_reset:
		size = sizeof (evtchn_reset_t);
		flags = IE_IMPORT;
		break;

	default:
#ifdef DEBUG
		printf("unrecognized HYPERVISOR_event_channel op %d\n", cmd);
#endif
		return (-X_EINVAL);
	}

	error = import_buffer(&op_ie, arg, NULL, size, flags);

	/*
	 * If there is sufficient demand, we can replace this void * with
	 * the proper op structure pointer.
	 */
	DTRACE_XPV2(evtchn__op__start, int, cmd, void *,
	    ((error == -X_EFAULT) ? arg : op_ie.ie_kaddr));

	if (error == 0)
		error = HYPERVISOR_event_channel_op(cmd, op_ie.ie_kaddr);
	export_buffer(&op_ie, &error);

	DTRACE_XPV1(evtchn__op__end, int, error);

	return (error);
}

static int
privcmd_HYPERVISOR_xen_version(int cmd, void *arg)
{
	int error;
	int size = 0;
	import_export_t op_ie;
	uint32_t flags = IE_EXPORT;

	switch (cmd) {
	case XENVER_version:
		break;
	case XENVER_extraversion:
		size = sizeof (xen_extraversion_t);
		break;
	case XENVER_compile_info:
		size = sizeof (xen_compile_info_t);
		break;
	case XENVER_capabilities:
		size = sizeof (xen_capabilities_info_t);
		break;
	case XENVER_changeset:
		size = sizeof (xen_changeset_info_t);
		break;
	case XENVER_platform_parameters:
		size = sizeof (xen_platform_parameters_t);
		break;
	case XENVER_get_features:
		flags = IE_IMPEXP;
		size = sizeof (xen_feature_info_t);
		break;
	case XENVER_pagesize:
		break;
	case XENVER_guest_handle:
		size = sizeof (xen_domain_handle_t);
		break;

	default:
#ifdef DEBUG
		printf("unrecognized HYPERVISOR_xen_version op %d\n", cmd);
#endif
		return (-X_EINVAL);
	}

	error = import_buffer(&op_ie, arg, NULL, size, flags);
	if (error == 0)
		error = HYPERVISOR_xen_version(cmd, op_ie.ie_kaddr);
	export_buffer(&op_ie, &error);

	return (error);
}

static int
privcmd_HYPERVISOR_xsm_op(void *uacmctl)
{
	int error;
	struct xen_acmctl *acmctl;
	import_export_t op_ie;

	error = import_buffer(&op_ie, uacmctl, NULL, sizeof (*acmctl),
	    IE_IMPEXP);
	if (error != 0)
		return (error);

	acmctl = op_ie.ie_kaddr;

	if (acmctl->interface_version != ACM_INTERFACE_VERSION) {
#ifdef DEBUG
		printf("acm vers mismatch (cmd %d, found 0x%x, need 0x%x\n",
		    acmctl->cmd, acmctl->interface_version,
		    ACM_INTERFACE_VERSION);
#endif
		error = -X_EACCES;
		export_buffer(&op_ie, &error);
		return (error);
	}

	/* FIXME: flask ops??? */

	switch (acmctl->cmd) {
	case ACMOP_setpolicy:
	case ACMOP_getpolicy:
	case ACMOP_dumpstats:
	case ACMOP_getssid:
	case ACMOP_getdecision:
	case ACMOP_chgpolicy:
	case ACMOP_relabeldoms:
		/* flags = IE_IMPEXP; */
		break;
	default:
#ifdef DEBUG
		printf("unrecognized HYPERVISOR_xsm_op op %d\n", acmctl->cmd);
#endif
		return (-X_EINVAL);
	}

	if (error == 0)
		error = HYPERVISOR_xsm_op(acmctl);
	export_buffer(&op_ie, &error);

	return (error);
}

static int
privcmd_HYPERVISOR_mmuext_op(struct mmuext_op *op, int count, uint_t *scount,
    domid_t domid)
{
	int error, bytes;
	uint_t kscount;
	struct mmuext_op *kop, single_kop;
	import_export_t op_ie, scnt_ie;

	kop = NULL;
	op_ie = scnt_ie = null_ie;
	error = 0;

	if (count >= 1) {
		bytes = count * sizeof (*kop);
		kop = (count == 1) ? &single_kop : kmem_alloc(bytes, KM_SLEEP);
		error = import_buffer(&op_ie, op, kop, bytes, IE_IMPORT);
	}

	DTRACE_XPV2(mmu__ext__op__start, int, count, struct mmuext_op *,
	    ((error == -X_EFAULT) ? op : kop));

	if (scount != NULL && error == 0)
		error = import_buffer(&scnt_ie, scount, &kscount,
		    sizeof (kscount), IE_EXPORT);

	if (error == 0)
		error = HYPERVISOR_mmuext_op(kop, count, &kscount, domid);
	export_buffer(&op_ie, &error);
	export_buffer(&scnt_ie, &error);

	DTRACE_XPV1(mmu__ext__op__end, int, error);

	if (count > 1)
		kmem_free(kop, bytes);
	return (error);
}

static int
privcmd_HYPERVISOR_hvm_op(int cmd, void *arg)
{
	int error;
	int size = 0;
	import_export_t arg_ie;
	uint32_t flags = IE_IMPORT;

	switch (cmd) {
	case HVMOP_set_param:
	case HVMOP_get_param:
		size = sizeof (struct xen_hvm_param);
		flags = IE_IMPEXP;
		break;
	case HVMOP_set_pci_intx_level:
		size = sizeof (struct xen_hvm_set_pci_intx_level);
		break;
	case HVMOP_set_isa_irq_level:
		size = sizeof (struct xen_hvm_set_isa_irq_level);
		break;
	case HVMOP_set_pci_link_route:
		size = sizeof (struct xen_hvm_set_pci_link_route);
		break;
	case HVMOP_track_dirty_vram:
		size = sizeof (struct xen_hvm_track_dirty_vram);
		break;
	case HVMOP_modified_memory:
		size = sizeof (struct xen_hvm_modified_memory);
		break;
	case HVMOP_set_mem_type:
		size = sizeof (struct xen_hvm_set_mem_type);
		break;

	default:
#ifdef DEBUG
		printf("unrecognized HVM op 0x%x\n", cmd);
#endif
		return (-X_EINVAL);
	}

	error = import_buffer(&arg_ie, arg, NULL, size, flags);
	if (error == 0)
		error = HYPERVISOR_hvm_op(cmd, arg_ie.ie_kaddr);
	export_buffer(&arg_ie, &error);

	return (error);
}

static int
privcmd_HYPERVISOR_sched_op(int cmd, void *arg)
{
	int error;
	int size = 0;
	import_export_t op_ie;
	struct sched_remote_shutdown op;

	switch (cmd) {
	case SCHEDOP_remote_shutdown:
		size = sizeof (struct sched_remote_shutdown);
		break;
	default:
#ifdef DEBUG
		printf("unrecognized sched op 0x%x\n", cmd);
#endif
		return (-X_EINVAL);
	}

	error = import_buffer(&op_ie, arg, &op, size, IE_IMPORT);
	if (error == 0)
		error = HYPERVISOR_sched_op(cmd, (arg == NULL) ? NULL : &op);
	export_buffer(&op_ie, &error);

	return (error);
}

int allow_all_hypercalls = 0;
int privcmd_efault_debug = 0;

/*ARGSUSED*/
int
do_privcmd_hypercall(void *uarg, int mode, cred_t *cr, int *rval)
{
	privcmd_hypercall_t __hc, *hc = &__hc;
	int error;

	if (ddi_copyin(uarg, hc, sizeof (*hc), mode))
		return (EFAULT);

	switch (hc->op) {
	case __HYPERVISOR_mmu_update:
		error = privcmd_HYPERVISOR_mmu_update(
		    (mmu_update_t *)hc->arg[0], (int)hc->arg[1],
		    (int *)hc->arg[2], (domid_t)hc->arg[3]);
		break;
	case __HYPERVISOR_domctl:
		error = privcmd_HYPERVISOR_domctl(
		    (xen_domctl_t *)hc->arg[0]);
		break;
	case __HYPERVISOR_sysctl:
		error = privcmd_HYPERVISOR_sysctl(
		    (xen_sysctl_t *)hc->arg[0]);
		break;
	case __HYPERVISOR_platform_op:
		error = privcmd_HYPERVISOR_platform_op(
		    (xen_platform_op_t *)hc->arg[0]);
		break;
	case __HYPERVISOR_memory_op:
		error = privcmd_HYPERVISOR_memory_op(
		    (int)hc->arg[0], (void *)hc->arg[1]);
		break;
	case __HYPERVISOR_event_channel_op:
		error = privcmd_HYPERVISOR_event_channel_op(
		    (int)hc->arg[0], (void *)hc->arg[1]);
		break;
	case __HYPERVISOR_xen_version:
		error = privcmd_HYPERVISOR_xen_version(
		    (int)hc->arg[0], (void *)hc->arg[1]);
		break;
	case __HYPERVISOR_mmuext_op:
		error = privcmd_HYPERVISOR_mmuext_op(
		    (struct mmuext_op *)hc->arg[0], (int)hc->arg[1],
		    (uint_t *)hc->arg[2], (domid_t)hc->arg[3]);
		break;
	case __HYPERVISOR_xsm_op:
		error = privcmd_HYPERVISOR_xsm_op((void *)hc->arg[0]);
		break;
	case __HYPERVISOR_hvm_op:
		error = privcmd_HYPERVISOR_hvm_op(
		    (int)hc->arg[0], (void *)hc->arg[1]);
		break;
	case __HYPERVISOR_sched_op:
		error = privcmd_HYPERVISOR_sched_op(
		    (int)hc->arg[0], (void *)hc->arg[1]);
		break;
	default:
		if (allow_all_hypercalls)
			error = __hypercall5(hc->op, hc->arg[0], hc->arg[1],
			    hc->arg[2], hc->arg[3], hc->arg[4]);
		else {
#ifdef DEBUG
			printf("unrecognized hypercall %ld\n", hc->op);
#endif
			error = -X_EPERM;
		}
		break;
	}

	if (error > 0) {
		*rval = error;
		error = 0;
	} else if (error != 0)
		error = xen_xlate_errcode(error);

	return (error);
}
