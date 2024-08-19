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

/*
 * Exercise the userspace-initiated changes to the LAPIC mode of a vCPU: INIT
 * and full resets via VM_RESET_CPU, and import of LAPIC state via
 * VM_DATA_WRITE.  Unlike guest writes to IA32_APIC_BASE, imports may request
 * any (valid) state regardless of the current one, and the vLAPIC must arrive
 * there with its mode-dependent registers (ID, LDR) correct.
 *
 * VM_SET_X2APIC_STATE is also checked to control only whether x2APIC support is
 * advertised in CPUID, leaving the current LAPIC mode alone.
 *
 * vCPU 17 is used, so that its xAPIC ID, x2APIC ID and logical x2APIC ID
 * (including the cluster) are distinct and non-zero.
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <libgen.h>
#include <errno.h>
#include <err.h>
#include <stdbool.h>
#include <sys/sysmacros.h>

#include <sys/vmm.h>
#include <sys/vmm_dev.h>
#include <sys/vmm_data.h>
#include <vmmapi.h>

#include "common.h"

#define	TEST_VCPUID	17

#define	APICBASE_X2APIC		(1UL << 10)
#define	APICBASE_ENABLED	(1UL << 11)
#define	APICBASE_STATE_MASK	(APICBASE_ENABLED | APICBASE_X2APIC)

#define	CPUID1_ECX_X2APIC	(1U << 21)

static void
read_lapic(int vmfd, struct vdi_lapic_v1 *lapic)
{
	struct vm_data_xfer xfer = {
		.vdx_vcpuid = TEST_VCPUID,
		.vdx_class = VDC_LAPIC,
		.vdx_version = 1,
		.vdx_len = sizeof (*lapic),
		.vdx_data = lapic,
	};

	if (ioctl(vmfd, VM_DATA_READ, &xfer) != 0) {
		err(EXIT_FAILURE, "VM_DATA_READ of lapic failed");
	}
}

static int
write_lapic(int vmfd, const struct vdi_lapic_v1 *lapic)
{
	struct vm_data_xfer xfer = {
		.vdx_vcpuid = TEST_VCPUID,
		.vdx_class = VDC_LAPIC,
		.vdx_version = 1,
		.vdx_len = sizeof (*lapic),
		.vdx_data = (void *)lapic,
	};

	return (ioctl(vmfd, VM_DATA_WRITE, &xfer));
}

static void
reset_vcpu(int vmfd, enum vcpu_reset_kind kind)
{
	struct vm_vcpu_reset vvr = {
		.vcpuid = TEST_VCPUID,
		.kind = kind,
	};

	if (ioctl(vmfd, VM_RESET_CPU, &vvr) != 0) {
		err(EXIT_FAILURE, "VM_RESET_CPU (kind %d) failed", kind);
	}
}

static void
set_x2apic_state(struct vcpu *vcpu, enum x2apic_state state)
{
	if (vm_set_x2apic_state(vcpu, state) != 0) {
		err(EXIT_FAILURE, "VM_SET_X2APIC_STATE (%d) failed", state);
	}
}

static bool
cpuid_x2apic_enabled(int vmfd)
{
	struct vm_legacy_cpuid vlc = {
		.vlc_vcpuid = TEST_VCPUID,
		.vlc_eax = 1,
		.vlc_ecx = 0,
	};

	if (ioctl(vmfd, VM_LEGACY_CPUID, &vlc) != 0) {
		err(EXIT_FAILURE, "VM_LEGACY_CPUID failed");
	}
	return ((vlc.vlc_ecx & CPUID1_ECX_X2APIC) != 0);
}

static uint32_t
x2apic_ldr(uint32_t id)
{
	return (((id >> 4) << 16) | (1U << (id & 0xf)));
}

/*
 * Check that the LAPIC is enabled in the expected mode, with the ID and LDR
 * set appropriately for that mode.
 */
static void
check_mode(int vmfd, bool x2apic, const char *desc)
{
	struct vdi_lapic_v1 lapic;

	read_lapic(vmfd, &lapic);

	const uint64_t state = lapic.vl_msr_apicbase & APICBASE_STATE_MASK;
	const uint64_t exp_state =
	    APICBASE_ENABLED | (x2apic ? APICBASE_X2APIC : 0);
	if (state != exp_state) {
		errx(EXIT_FAILURE, "%s: unexpected APICBASE 0x%lx (state 0x%lx,"
		    " expected 0x%lx)", desc, lapic.vl_msr_apicbase, state,
		    exp_state);
	}

	const uint32_t exp_id = x2apic ? TEST_VCPUID : (TEST_VCPUID << 24);
	if (lapic.vl_lapic.vlp_id != exp_id) {
		errx(EXIT_FAILURE, "%s: unexpected ID 0x%x != 0x%x", desc,
		    lapic.vl_lapic.vlp_id, exp_id);
	}

	const uint32_t exp_ldr = x2apic ? x2apic_ldr(TEST_VCPUID) : 0;
	if (lapic.vl_lapic.vlp_ldr != exp_ldr) {
		errx(EXIT_FAILURE, "%s: unexpected LDR 0x%x != 0x%x", desc,
		    lapic.vl_lapic.vlp_ldr, exp_ldr);
	}
}

int
main(int argc, char *argv[])
{
	const char *suite_name = basename(argv[0]);
	struct vmctx *ctx;
	struct vcpu *vcpu;
	enum x2apic_state state;

	ctx = create_test_vm(suite_name);
	if (ctx == NULL) {
		errx(EXIT_FAILURE, "could not open test VM");
	}

	if ((vcpu = vm_vcpu_open(ctx, TEST_VCPUID)) == NULL) {
		err(EXIT_FAILURE, "Could not open vcpu%d", TEST_VCPUID);
	}
	if (vm_activate_cpu(vcpu) != 0) {
		err(EXIT_FAILURE, "could not activate vcpu%d", TEST_VCPUID);
	}

	const int vmfd = vm_get_device_fd(ctx);
	struct vdi_lapic_v1 xapic_data, x2apic_data, disabled_data;

	/* A fresh vCPU starts in xAPIC mode, without x2APIC support */
	check_mode(vmfd, false, "initial state");
	if (cpuid_x2apic_enabled(vmfd)) {
		errx(EXIT_FAILURE, "x2APIC advertised in CPUID by default");
	}
	read_lapic(vmfd, &xapic_data);

	/*
	 * VM_SET_X2APIC_STATE only controls whether x2APIC support is
	 * advertised: the LAPIC remains in xAPIC mode.
	 */
	set_x2apic_state(vcpu, X2APIC_ENABLED);
	check_mode(vmfd, false, "VM_SET_X2APIC_STATE (enabled) from xAPIC");
	if (!cpuid_x2apic_enabled(vmfd)) {
		errx(EXIT_FAILURE,
		    "x2APIC not advertised in CPUID once enabled");
	}

	/* xAPIC -> x2APIC via import */
	x2apic_data = xapic_data;
	x2apic_data.vl_msr_apicbase |= APICBASE_X2APIC;
	x2apic_data.vl_lapic.vlp_id = TEST_VCPUID;
	x2apic_data.vl_lapic.vlp_ldr = x2apic_ldr(TEST_VCPUID);
	if (write_lapic(vmfd, &x2apic_data) != 0) {
		err(EXIT_FAILURE, "VM_DATA_WRITE of x2APIC lapic failed");
	}
	check_mode(vmfd, true, "import of x2APIC state from xAPIC");
	read_lapic(vmfd, &x2apic_data);

	/* x2APIC -> x2APIC via import is a no-op */
	if (write_lapic(vmfd, &x2apic_data) != 0) {
		err(EXIT_FAILURE, "VM_DATA_WRITE of x2APIC lapic failed");
	}
	check_mode(vmfd, true, "import of x2APIC state from x2APIC");

	/*
	 * Toggling x2APIC support leaves the LAPIC in x2APIC mode, with only
	 * the CPUID bit changing.
	 */
	set_x2apic_state(vcpu, X2APIC_ENABLED);
	check_mode(vmfd, true, "VM_SET_X2APIC_STATE (enabled) from x2APIC");
	set_x2apic_state(vcpu, X2APIC_DISABLED);
	check_mode(vmfd, true, "VM_SET_X2APIC_STATE (disabled) from x2APIC");
	if (cpuid_x2apic_enabled(vmfd)) {
		errx(EXIT_FAILURE, "x2APIC advertised in CPUID once disabled");
	}
	set_x2apic_state(vcpu, X2APIC_ENABLED);

	/* x2APIC mode persists across INIT */
	reset_vcpu(vmfd, VRK_INIT);
	check_mode(vmfd, true, "INIT in x2APIC mode");

	/*
	 * A full reset returns the LAPIC to xAPIC mode, but leaves x2APIC
	 * support (as advertised in legacy CPUID handling) intact.
	 */
	reset_vcpu(vmfd, VRK_RESET);
	check_mode(vmfd, false, "RESET in x2APIC mode");
	if (vm_get_x2apic_state(vcpu, &state) != 0) {
		err(EXIT_FAILURE, "VM_GET_X2APIC_STATE failed");
	}
	if (state != X2APIC_ENABLED || !cpuid_x2apic_enabled(vmfd)) {
		errx(EXIT_FAILURE, "x2APIC support lost across RESET");
	}

	/* Disabled -> x2APIC via import (passing through xAPIC) */
	disabled_data = xapic_data;
	disabled_data.vl_msr_apicbase &= ~APICBASE_ENABLED;
	if (write_lapic(vmfd, &disabled_data) != 0) {
		err(EXIT_FAILURE, "VM_DATA_WRITE of disabled lapic failed");
	}
	read_lapic(vmfd, &disabled_data);
	if ((disabled_data.vl_msr_apicbase & APICBASE_STATE_MASK) != 0) {
		errx(EXIT_FAILURE, "LAPIC not disabled by import: %lx",
		    disabled_data.vl_msr_apicbase);
	}
	if (write_lapic(vmfd, &x2apic_data) != 0) {
		err(EXIT_FAILURE, "VM_DATA_WRITE of x2APIC lapic failed");
	}
	check_mode(vmfd, true, "import of x2APIC state from Disabled");

	/* x2APIC -> xAPIC via import (passing through Disabled) */
	if (write_lapic(vmfd, &xapic_data) != 0) {
		err(EXIT_FAILURE, "VM_DATA_WRITE of xAPIC lapic failed");
	}
	check_mode(vmfd, false, "import of xAPIC state from x2APIC");

	/*
	 * The imported ID must match the vCPU in the mode being imported:
	 * x2APIC state carrying an xAPIC-format ID is rejected, leaving the
	 * existing state untouched.
	 */
	struct vdi_lapic_v1 bad_data = x2apic_data;
	bad_data.vl_lapic.vlp_id = TEST_VCPUID << 24;
	if (write_lapic(vmfd, &bad_data) == 0) {
		errx(EXIT_FAILURE,
		    "VM_DATA_WRITE of lapic with mismatched ID should fail");
	}
	check_mode(vmfd, false, "rejected import");

	vm_destroy(ctx);
	(void) printf("%s\tPASS\n", suite_name);
	return (EXIT_SUCCESS);
}
