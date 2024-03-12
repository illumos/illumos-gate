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
 * Copyright 2024 Oxide Computer Company
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <libgen.h>
#include <sys/stat.h>
#include <errno.h>
#include <err.h>
#include <assert.h>
#include <sys/sysmacros.h>
#include <stdbool.h>

#include <sys/vmm.h>
#include <sys/vmm_dev.h>
#include <sys/vmm_data.h>
#include <vmmapi.h>

#include "common.h"

static void
should_eq_u32(const char *field_name, uint32_t a, uint32_t b)
{
	if (a != b) {
		errx(EXIT_FAILURE, "unexpected %s %u != %u",
		    field_name, a, b);
	}
}

static void
test_size_boundaries(int vmfd)
{
	uint8_t buf[sizeof (struct vdi_atpic_v1) + sizeof (int)];
	struct vm_data_xfer vdx = {
		.vdx_class = VDC_ATPIC,
		.vdx_version = 1,
		.vdx_len = sizeof (struct vdi_atpic_v1),
		.vdx_data = buf,
	};

	/* Attempt a valid-sized read first */
	if (ioctl(vmfd, VM_DATA_READ, &vdx) != 0) {
		err(EXIT_FAILURE, "valid VM_DATA_READ failed");
	}
	should_eq_u32("vdx_result_len", vdx.vdx_result_len,
	    sizeof (struct vdi_atpic_v1));

	/* And check that we can write it back */
	vdx.vdx_result_len = 0;
	if (ioctl(vmfd, VM_DATA_WRITE, &vdx) != 0) {
		err(EXIT_FAILURE, "valid VM_DATA_WRITE failed");
	}

	/* ... then too-small ... */
	vdx.vdx_len = sizeof (struct vdi_atpic_v1) - sizeof (int);
	vdx.vdx_result_len = 0;
	if (ioctl(vmfd, VM_DATA_READ, &vdx) == 0) {
		errx(EXIT_FAILURE, "invalid VM_DATA_READ should have failed");
	}
	int error = errno;
	if (error != ENOSPC) {
		errx(EXIT_FAILURE, "expected ENOSPC errno, got %d", error);
	}
	/* the "correct" vdx_result_len should still be communicated out */
	should_eq_u32("vdx_result_len", vdx.vdx_result_len,
	    sizeof (struct vdi_atpic_v1));

	/* Repeat with too-small write */
	vdx.vdx_result_len = 0;
	if (ioctl(vmfd, VM_DATA_WRITE, &vdx) == 0) {
		errx(EXIT_FAILURE, "invalid VM_DATA_WRITE should have failed");
	}
	error = errno;
	if (error != ENOSPC) {
		errx(EXIT_FAILURE, "expected ENOSPC errno, got %d", error);
	}
	should_eq_u32("vdx_result_len", vdx.vdx_result_len,
	    sizeof (struct vdi_atpic_v1));

	/*
	 * ... and too-big to round it out.
	 *
	 * This should pass, but still set vdx_result_len to the actual length
	 */
	vdx.vdx_len = sizeof (struct vdi_atpic_v1) + sizeof (int);
	vdx.vdx_result_len = 0;
	if (ioctl(vmfd, VM_DATA_READ, &vdx) != 0) {
		err(EXIT_FAILURE, "too-large (but valid) VM_DATA_READ failed");
	}
	should_eq_u32("vdx_result_len", vdx.vdx_result_len,
	    sizeof (struct vdi_atpic_v1));

	/* ... and repeated as a write */
	vdx.vdx_len = sizeof (struct vdi_atpic_v1) + sizeof (int);
	vdx.vdx_result_len = 0;
	if (ioctl(vmfd, VM_DATA_WRITE, &vdx) != 0) {
		err(EXIT_FAILURE,
		    "too-large (but valid) VM_DATA_WRITE failed");
	}
	should_eq_u32("vdx_result_len", vdx.vdx_result_len,
	    sizeof (struct vdi_atpic_v1));
}

struct class_test_case {
	uint16_t	ctc_class;
	uint16_t	ctc_version;
};

static void
test_vm_classes(int vmfd)
{
	const struct class_test_case cases[] = {
		{ VDC_VERSION, 1 },
		{ VDC_VMM_ARCH, 1 },
		{ VDC_IOAPIC, 1 },
		{ VDC_ATPIT, 1 },
		{ VDC_ATPIC, 1 },
		{ VDC_HPET, 1 },
		{ VDC_PM_TIMER, 1 },
		{ VDC_RTC, 2 },
		{ VDC_VMM_TIME, 1 },
	};

	/* A page should be large enough for all classes (for now) */
	const size_t bufsz = PAGESIZE;
	uint8_t *buf = malloc(bufsz);

	for (uint_t i = 0; i < ARRAY_SIZE(cases); i++) {
		struct vm_data_xfer vdx = {
			.vdx_class = cases[i].ctc_class,
			.vdx_version = cases[i].ctc_version,
			.vdx_len = bufsz,
			.vdx_data = buf,
			.vdx_vcpuid = -1,
		};

		/* First do a read */
		if (ioctl(vmfd, VM_DATA_READ, &vdx) != 0) {
			err(EXIT_FAILURE,
			    "VM_DATA_READ failed class:%u version:%u",
			    vdx.vdx_class, vdx.vdx_version);
		}
		if (vdx.vdx_class == VDC_VERSION ||
		    vdx.vdx_class == VDC_VMM_ARCH) {
			/*
			 * Skip classes which contain some (or all) bits which
			 * are read-only.
			 */
			continue;
		}

		/* Write the same data back */
		vdx.vdx_len = vdx.vdx_result_len;
		if (ioctl(vmfd, VM_DATA_WRITE, &vdx) != 0) {
			err(EXIT_FAILURE,
			    "VM_DATA_WRITE failed class:%u version:%u",
			    vdx.vdx_class, vdx.vdx_version);
		}
	}
	free(buf);
}

static void
test_vcpu_classes(int vmfd)
{
	const struct class_test_case cases[] = {
		{ VDC_MSR, 1 },
		{ VDC_LAPIC, 1 },
		{ VDC_VMM_ARCH, 1 },

		/*
		 * Although these classes are per-vCPU, they have not yet been
		 * implemented in the vmm-data system, so are ignored for now:
		 *
		 * - VDC_REGISTER
		 * - VDC_FPU
		 * - VDC_LAPIC
		 */
	};

	/* A page should be large enough for all classes (for now) */
	const size_t bufsz = PAGESIZE;
	uint8_t *buf = malloc(bufsz);

	for (uint_t i = 0; i < ARRAY_SIZE(cases); i++) {
		struct vm_data_xfer vdx = {
			.vdx_class = cases[i].ctc_class,
			.vdx_version = cases[i].ctc_version,
			.vdx_len = bufsz,
			.vdx_data = buf,
			.vdx_vcpuid = 0,
		};

		/* First do a read */
		if (ioctl(vmfd, VM_DATA_READ, &vdx) != 0) {
			err(EXIT_FAILURE,
			    "VM_DATA_READ failed class:%u version:%u",
			    vdx.vdx_class, vdx.vdx_version);
		}

		if (vdx.vdx_class == VDC_VMM_ARCH) {
			/*
			 * There are some read-only fields in VMM_ARCH which we
			 * do not want to attempt to write back.
			 */
			continue;
		}

		/* Write the same data back */
		vdx.vdx_len = vdx.vdx_result_len;
		if (ioctl(vmfd, VM_DATA_WRITE, &vdx) != 0) {
			err(EXIT_FAILURE,
			    "VM_DATA_WRITE failed class:%u version:%u",
			    vdx.vdx_class, vdx.vdx_version);
		}
	}
	free(buf);
}

static void
test_bogus_class(int vmfd)
{
	const size_t bufsz = PAGESIZE;
	uint8_t *buf = malloc(bufsz);

	struct vm_data_xfer vdx = {
		.vdx_class = 10000,
		.vdx_version = 1,
		.vdx_len = bufsz,
		.vdx_data = buf,
	};

	/* Try to read with an absurd data class */
	if (ioctl(vmfd, VM_DATA_READ, &vdx) == 0) {
		errx(EXIT_FAILURE,
		    "VM_DATA_READ should fail for absurd vdx_class");
	}

	/* Same for data version */
	vdx.vdx_class = VDC_VERSION;
	vdx.vdx_version = 10000;
	if (ioctl(vmfd, VM_DATA_READ, &vdx) == 0) {
		errx(EXIT_FAILURE,
		    "VM_DATA_READ should fail for absurd vdx_version");
	}

	free(buf);
}

static void
test_vcpuid_combos(int vmfd)
{
	const size_t bufsz = PAGESIZE;
	uint8_t *buf = malloc(bufsz);

	struct vm_data_xfer vdx = {
		.vdx_class = VDC_LAPIC,
		.vdx_version = 1,
		.vdx_len = bufsz,
		.vdx_data = buf,
	};

	/* Try with -1 sentinel, too-negative, and too-positive values */
	const int bad_per_vcpu[] = { -1, -5, 1000 };
	for (uint_t i = 0; i < ARRAY_SIZE(bad_per_vcpu); i++) {
		vdx.vdx_vcpuid = bad_per_vcpu[i];
		if (ioctl(vmfd, VM_DATA_READ, &vdx) == 0) {
			errx(EXIT_FAILURE,
			    "VM_DATA_READ should fail for bad vcpuid %d",
			    vdx.vdx_vcpuid);
		}
	}

	/*
	 * Valid vcpuid should be fine still.  Reading valid data into the
	 * buffer will be useful to subsequently test writes.
	 */
	vdx.vdx_vcpuid = 0;
	if (ioctl(vmfd, VM_DATA_READ, &vdx) != 0) {
		err(EXIT_FAILURE, "failed VM_DATA_READ with valid vcpuid");
	}

	/* Repeat the same checks for writes */
	for (uint_t i = 0; i < ARRAY_SIZE(bad_per_vcpu); i++) {
		vdx.vdx_vcpuid = bad_per_vcpu[i];
		if (ioctl(vmfd, VM_DATA_WRITE, &vdx) == 0) {
			errx(EXIT_FAILURE,
			    "VM_DATA_WRITE should fail for bad vcpuid %d",
			    vdx.vdx_vcpuid);
		}
	}

	vdx.vdx_vcpuid = 0;
	if (ioctl(vmfd, VM_DATA_WRITE, &vdx) != 0) {
		err(EXIT_FAILURE, "failed VM_DATA_WRITE with valid vcpuid");
	}

	vdx.vdx_class = VDC_VERSION;
	vdx.vdx_version = 1;

	/*
	 * VM-wide classes should work fine with the -1 sentinel.  For now,
	 * passing an otherwise valid vcpuid will still work, but that id is
	 * ignored.
	 */
	const int good_vm_wide[] = { -1, 0, 1 };
	for (uint_t i = 0; i < ARRAY_SIZE(good_vm_wide); i++) {
		vdx.vdx_vcpuid = good_vm_wide[i];
		if (ioctl(vmfd, VM_DATA_READ, &vdx) != 0) {
			err(EXIT_FAILURE,
			    "failed VM-wide VM_DATA_READ with vcpuid %d",
			    vdx.vdx_vcpuid);
		}
	}

	/* Bogus values should still fail */
	const int bad_vm_wide[] = { -5, 1000 };
	for (uint_t i = 0; i < ARRAY_SIZE(bad_vm_wide); i++) {
		vdx.vdx_vcpuid = bad_vm_wide[i];
		if (ioctl(vmfd, VM_DATA_READ, &vdx) == 0) {
			errx(EXIT_FAILURE,
			    "VM_DATA_READ should fail for bad vcpuid %d",
			    vdx.vdx_vcpuid);
		}
	}

	free(buf);
}

static void
test_vcpuid_time(int vmfd)
{
	struct vdi_time_info_v1 data;
	struct vm_data_xfer vdx = {
		.vdx_class = VDC_VMM_TIME,
		.vdx_version = 1,
		.vdx_len = sizeof (data),
		.vdx_data = &data,
	};

	/* This should work with the system-wide vcpuid */
	vdx.vdx_vcpuid = -1;
	if (ioctl(vmfd, VM_DATA_READ, &vdx) != 0) {
		err(EXIT_FAILURE, "VM_DATA_READ failed for valid vcpuid");
	}

	/* But fail for other vcpuids */
	vdx.vdx_vcpuid = 0;
	if (ioctl(vmfd, VM_DATA_READ, &vdx) == 0) {
		err(EXIT_FAILURE, "VM_DATA_READ should fail for vcpuid %d",
		    vdx.vdx_vcpuid);
	}

	/*
	 * Perform same check for writes
	 *
	 * Normally this would require care to handle hosts which lack frequency
	 * scaling functionality, but since we are writing back the same data,
	 * the guest frequency should match that of the host, requiring no real
	 * scaling be done for the instance.
	 */
	vdx.vdx_vcpuid = -1;
	if (ioctl(vmfd, VM_DATA_WRITE, &vdx) != 0) {
		err(EXIT_FAILURE, "VM_DATA_WRITE failed for valid vcpuid");
	}
	vdx.vdx_vcpuid = 0;
	if (ioctl(vmfd, VM_DATA_WRITE, &vdx) == 0) {
		errx(EXIT_FAILURE, "VM_DATA_READ should fail for vcpuid %d",
		    vdx.vdx_vcpuid);
	}
}

int
main(int argc, char *argv[])
{
	const char *suite_name = basename(argv[0]);
	struct vmctx *ctx;

	ctx = create_test_vm(suite_name);
	if (ctx == NULL) {
		errx(EXIT_FAILURE, "could not open test VM");
	}

	/*
	 * Check that vmm_data import/export facility is robust in the face of
	 * potentially invalid inputs
	 */
	const int vmfd = vm_get_device_fd(ctx);

	/* Test varies edge cases around data transfer sizes */
	test_size_boundaries(vmfd);

	/* Check that known VM-wide data classes can be accessed */
	test_vm_classes(vmfd);

	/* Check that known per-vCPU data classes can be accessed */
	test_vcpu_classes(vmfd);

	/* Try some bogus class/version combos */
	test_bogus_class(vmfd);

	/* Try some weird vdx_vcpuid cases */
	test_vcpuid_combos(vmfd);

	/* VMM_TIME is picky about vcpuid */
	test_vcpuid_time(vmfd);

	vm_destroy(ctx);
	(void) printf("%s\tPASS\n", suite_name);
	return (EXIT_SUCCESS);
}
