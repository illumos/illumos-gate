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
 * Copyright 2023 Oxide Computer Company
 */

/*
 * VMM Time Data interface tests
 *
 * Note: requires `vmm_allow_state_writes` to be set
 */

#include <unistd.h>
#include <stdlib.h>
#include <libgen.h>
#include <errno.h>
#include <err.h>

#include <sys/vmm_dev.h>
#include <sys/vmm_data.h>
#include <vmmapi.h>

#include "common.h"


/*
 * Constants from svm.c, redefined here for convenience
 */
#define	AMD_TSC_MIN_FREQ	500000000
#define	AMD_TSC_MAX_FREQ_RATIO	15


static void
should_eq_u32(const char *field_name, uint32_t a, uint32_t b)
{
	if (a != b) {
		errx(EXIT_FAILURE, "unexpected %s %u != %u",
		    field_name, a, b);
	}
}

static void
should_eq_u64(const char *field_name, uint64_t a, uint64_t b)
{
	if (a != b) {
		errx(EXIT_FAILURE, "unexpected %s %lu != %lu",
		    field_name, a, b);
	}
}

/* a should be >= b */
static void
should_geq_u64(const char *field_name, uint64_t a, uint64_t b)
{
	if (a < b) {
		errx(EXIT_FAILURE, "unexpected %s %lu < %lu",
		    field_name, a, b);
	}
}
static void
should_geq_i64(const char *field_name, int64_t a, int64_t b)
{
	if (a < b) {
		errx(EXIT_FAILURE, "unexpected %s %ld < %ld",
		    field_name, a, b);
	}
}

/*
 * Test a valid VMM_DATA_READ of time data
 */
static void
test_valid_read_time_data(int vmfd, struct vdi_time_info_v1 *time_info)
{
	struct vm_data_xfer xfer = {
		.vdx_class = VDC_VMM_TIME,
		.vdx_version = 1,
		.vdx_len = sizeof (struct vdi_time_info_v1),
		.vdx_data = time_info,
	};

	if (ioctl(vmfd, VM_DATA_READ, &xfer) != 0) {
		errx(EXIT_FAILURE, "VMM_DATA_READ of time info failed");
	}
}

/*
 * Test valid VMM_DATA_WRITE of time data
 */
static void
test_valid_write_time_data(int vmfd, struct vdi_time_info_v1 *time_info)
{
	struct vm_data_xfer xfer = {
		.vdx_class = VDC_VMM_TIME,
		.vdx_version = 1,
		.vdx_len = sizeof (struct vdi_time_info_v1),
		.vdx_data = time_info,
	};

	if (ioctl(vmfd, VM_DATA_WRITE, &xfer) != 0) {
		int error;
		error = errno;

		if (error == EPERM) {
			warn("VMM_DATA_WRITE got EPERM: is "
			    "vmm_allow_state_writes set?");
		}

		errx(EXIT_FAILURE, "VMM_DATA_WRITE of time info failed");
	}
}

/*
 * Test malformed VMM_DATA_READ time data requests
 */
static void
test_invalid_read_time_data(int vmfd)
{
	struct vdi_time_info_v1 res;

	/* check error case: invalid vdr_len */
	struct vm_data_xfer xfer = {
		.vdx_class = VDC_VMM_TIME,
		.vdx_version = 1,
		.vdx_len = 0,
		.vdx_data = &res,
	};
	int error;

	if (ioctl(vmfd, VM_DATA_READ, &xfer) == 0) {
		errx(EXIT_FAILURE,
		    "invalid VMM_DATA_READ of time info should fail");
	}
	error = errno;
	if (error != ENOSPC) {
		errx(EXIT_FAILURE, "test_invalid_read_time_data: "
		    "expected ENOSPC errno, got %d", error);
	}
	/* expected vdx_result_len should be communicated out */
	should_eq_u32("vdx_result_len", xfer.vdx_result_len,
	    sizeof (struct vdi_time_info_v1));
}

/*
 * Test malformed VMM_DATA_WRITE time data requests
 */
static void
test_invalid_write_time_data(int vmfd, struct vdi_time_info_v1 *src)
{
	/* invalid vdx_len */
	struct vm_data_xfer xfer = {
		.vdx_class = VDC_VMM_TIME,
		.vdx_version = 1,
		.vdx_len = 0,
		.vdx_data = src,
	};
	int error;

	if (ioctl(vmfd, VM_DATA_WRITE, &xfer) == 0) {
		errx(EXIT_FAILURE,
		    "invalid VMM_DATA_WRITE of time info should fail");
	}
	error = errno;
	if (error != ENOSPC) {
		errx(EXIT_FAILURE, "test_invalid_write_time_data: "
		    "expected ENOSPC errno, got %d", error);
	}
	/* expected vdx_result_len should be communicated out */
	should_eq_u32("vdx_result_len", xfer.vdx_result_len,
	    sizeof (struct vdi_time_info_v1));
}

/*
 * Test platform-independent invalid frequency ratio requests
 */
static void
test_invalid_freq(int vmfd, struct vdi_time_info_v1 *src)
{
	/* guest frequency of 0 always invalid */
	struct vdi_time_info_v1 invalid = {
		.vt_guest_freq = 0,
		.vt_guest_tsc = src->vt_guest_tsc,
		.vt_boot_hrtime = src->vt_boot_hrtime,
		.vt_hrtime = src->vt_hrtime,
		.vt_hres_sec = src->vt_hres_sec,
		.vt_hres_ns = src->vt_hres_ns,
	};
	struct vm_data_xfer xfer = {
		.vdx_class = VDC_VMM_TIME,
		.vdx_version = 1,
		.vdx_len = sizeof (struct vdi_time_info_v1),
		.vdx_data = &invalid,
	};
	int error;

	if (ioctl(vmfd, VM_DATA_WRITE, &xfer) == 0) {
		errx(EXIT_FAILURE,
		    "invalid VMM_DATA_WRITE of time info (vt_guest_freq = 0) "
		    "should fail");
	}
	error = errno;
	if (error != EINVAL) {
		errx(EXIT_FAILURE, "test_invalid_freq: \
		    expected EINVAL errno, got %d", error);
	}
}

/*
 * Test invalid AMD-specific frequency ratio requests
 */
static void
test_invalid_freq_amd(int vmfd, struct vdi_time_info_v1 *src)
{
	struct vdi_time_info_v1 invalid = {
		.vt_guest_freq = src->vt_guest_freq,
		.vt_guest_tsc = src->vt_guest_tsc,
		.vt_boot_hrtime = src->vt_boot_hrtime,
		.vt_hrtime = src->vt_hrtime,
		.vt_hres_sec = src->vt_hres_sec,
		.vt_hres_ns = src->vt_hres_ns,
	};
	struct vm_data_xfer xfer = {
		.vdx_class = VDC_VMM_TIME,
		.vdx_version = 1,
		.vdx_len = sizeof (struct vdi_time_info_v1),
		.vdx_data = &invalid,
	};
	int error;

	/* minimum guest frequency - 1 */
	invalid.vt_guest_freq = AMD_TSC_MIN_FREQ - 1;
	if (ioctl(vmfd, VM_DATA_WRITE, &xfer) == 0) {
		errx(EXIT_FAILURE, "invalid VMM_DATA_WRITE of time info "
		    "(min AMD guest freq) should fail");
	}
	error = errno;
	if (error != EINVAL) {
		errx(EXIT_FAILURE, "test_invalid_freq_amd (< min freq) "
		    "expected EINVAL errno, got %d", error);
	}

	/* ratio >= max ratio */
	invalid.vt_guest_freq = src->vt_guest_freq * AMD_TSC_MAX_FREQ_RATIO;
	if (ioctl(vmfd, VM_DATA_WRITE, &xfer) == 0) {
		errx(EXIT_FAILURE, "invalid VMM_DATA_WRITE of time info "
		    "(AMD guest freq ratio too large) should fail");
	}
	error = errno;
	if (error != EINVAL) {
		errx(EXIT_FAILURE, "test_invalid_freq_amd (> max freq) "
		    "expected EINVAL errno, got %d", error);
	}
}

/*
 * Test valid AMD-specific frequency ratio requests
 */
static void
test_valid_freq_amd(int vmfd, struct vdi_time_info_v1 *src)
{
	struct vdi_time_info_v1 res;
	int error;

	/* minimum frequency */
	struct vdi_time_info_v1 valid = {
		.vt_guest_freq = AMD_TSC_MIN_FREQ,
		.vt_guest_tsc = src->vt_guest_tsc,
		.vt_boot_hrtime = src->vt_boot_hrtime,
		.vt_hrtime = src->vt_hrtime,
		.vt_hres_sec = src->vt_hres_sec,
		.vt_hres_ns = src->vt_hres_ns,
	};
	struct vm_data_xfer xfer = {
		.vdx_class = VDC_VMM_TIME,
		.vdx_version = 1,
		.vdx_len = sizeof (struct vdi_time_info_v1),
		.vdx_data = &valid,
	};
	if (ioctl(vmfd, VM_DATA_WRITE, &xfer) != 0) {
		error = errno;
		errx(EXIT_FAILURE, "valid VMM_DATA_WRITE of time info "
		    "(min AMD guest frequency) should succeed, errno=%d",
		    error);
	}
	/* verify the frequency was changed */
	test_valid_read_time_data(vmfd, &res);
	should_eq_u64("vt_guest_freq", res.vt_guest_freq, valid.vt_guest_freq);


	/* maximum frequency */
	valid.vt_guest_freq = src->vt_guest_freq * AMD_TSC_MAX_FREQ_RATIO - 1;
	if (ioctl(vmfd, VM_DATA_WRITE, &xfer) != 0) {
		error = errno;
		errx(EXIT_FAILURE, "valid VMM_DATA_WRITE of time info "
		    "(max AMD guest frequency) should succeed, errno=%d",
		    error);
	}
	/* verify the frequency was changed */
	test_valid_read_time_data(vmfd, &res);
	should_eq_u64("vt_guest_freq", res.vt_guest_freq, valid.vt_guest_freq);
}

/*
 * Test invalid Intel-specific frequency ratio requests
 */
static void
test_invalid_freq_intel(int vmfd, struct vdi_time_info_v1 *src)
{
	/*
	 * As Intel is not currently supported, any frequency that differs from
	 * the host should be rejected.
	 */
	struct vdi_time_info_v1 invalid = {
		.vt_guest_freq = src->vt_guest_freq + 1,
		.vt_guest_tsc = src->vt_guest_tsc,
		.vt_boot_hrtime = src->vt_boot_hrtime,
		.vt_hrtime = src->vt_hrtime,
		.vt_hres_sec = src->vt_hres_sec,
		.vt_hres_ns = src->vt_hres_ns,
	};
	struct vm_data_xfer xfer = {
		.vdx_class = VDC_VMM_TIME,
		.vdx_version = 1,
		.vdx_len = sizeof (struct vdi_time_info_v1),
		.vdx_data = &invalid,
	};
	int error;

	if (ioctl(vmfd, VM_DATA_WRITE, &xfer) == 0) {
		errx(EXIT_FAILURE, "invalid VMM_DATA_WRITE of time info "
		    "(intel scaling required) should fail");
	}
	error = errno;
	if (error != EPERM) {
		errx(EXIT_FAILURE, "test_invalid_freq_intel: "
		    "expected EPERM errno, got %d", error);
	}
}

/*
 * Test that an hrtime from the future is not accepted
 */
static void
test_invalid_host_times(int vmfd, struct vdi_time_info_v1 *src)
{
	struct vdi_time_info_v1 invalid = {
		.vt_guest_freq = src->vt_guest_freq,
		.vt_guest_tsc = src->vt_guest_tsc,
		.vt_boot_hrtime = src->vt_boot_hrtime,
		.vt_hrtime = src->vt_hrtime,
		.vt_hres_sec = src->vt_hres_sec,
		.vt_hres_ns = src->vt_hres_ns,
	};
	struct vm_data_xfer xfer = {
		.vdx_class = VDC_VMM_TIME,
		.vdx_version = 1,
		.vdx_len = sizeof (struct vdi_time_info_v1),
		.vdx_data = &invalid,
	};
	int error;

	/* hrtime + 500 seconds */
	invalid.vt_hrtime += 500000000000;
	if (ioctl(vmfd, VM_DATA_WRITE, &xfer) == 0) {
		errx(EXIT_FAILURE, "invalid VMM_DATA_WRITE of time info "
		    "(hrtime in the future) should fail");
	}
	error = errno;
	if (error != EINVAL) {
		errx(EXIT_FAILURE, "test_invalid_host_times: "
		    "expected EINVAL errno, got %d", error);
	}
}

/*
 * Test that a boot_hrtime from the future is not accepted
 */
static void
test_invalid_boot_hrtime(int vmfd, struct vdi_time_info_v1 *src)
{
	struct vdi_time_info_v1 invalid = {
		.vt_guest_freq = src->vt_guest_freq,
		.vt_guest_tsc = src->vt_guest_tsc,
		.vt_boot_hrtime = src->vt_boot_hrtime,
		.vt_hrtime = src->vt_hrtime,
		.vt_hres_sec = src->vt_hres_sec,
		.vt_hres_ns = src->vt_hres_ns,
	};
	struct vm_data_xfer xfer = {
		.vdx_class = VDC_VMM_TIME,
		.vdx_version = 1,
		.vdx_len = sizeof (struct vdi_time_info_v1),
		.vdx_data = &invalid,
	};
	int error;

	/* boot_hrtime = hrtime + 500 seconds */
	invalid.vt_boot_hrtime += src->vt_hrtime + 500000000000;
	if (ioctl(vmfd, VM_DATA_WRITE, &xfer) == 0) {
		errx(EXIT_FAILURE, "invalid VMM_DATA_WRITE of time info "
		    "(boot_hrtime in the future) should fail");
	}
	error = errno;
	if (error != EINVAL) {
		errx(EXIT_FAILURE, "test_invalid_boot_hrtime: "
		    "expected EINVAL errno, got %d", error);
	}
}

/*
 * Test that a different guest TSC is accepted. There are no constraints on what
 * this value can be.
 */
static void
test_valid_guest_tsc(int vmfd, struct vdi_time_info_v1 *src)
{
	/* arbitrary guest TSC in the future */
	struct vdi_time_info_v1 valid = {
		.vt_guest_freq = src->vt_guest_freq,
		.vt_guest_tsc = src->vt_guest_tsc + 500000000000,
		.vt_boot_hrtime = src->vt_boot_hrtime,
		.vt_hrtime = src->vt_hrtime,
		.vt_hres_sec = src->vt_hres_sec,
		.vt_hres_ns = src->vt_hres_ns,
	};
	test_valid_write_time_data(vmfd, &valid);

	/* read it back */
	struct vdi_time_info_v1 res;
	test_valid_read_time_data(vmfd, &res);

	/*
	 * The guest TSC may have been adjusted by the kernel, but it should
	 * be at least what was supplied.
	 */
	should_geq_u64("vt_guest_tsc", res.vt_guest_tsc, valid.vt_guest_tsc);

}

/*
 * Test that a different boot_hrtime is accepted.
 */
static void
test_valid_boot_hrtime(int vmfd, struct vdi_time_info_v1 *src)
{
	struct vdi_time_info_v1 res;

	/* boot_hrtime < 0 */
	struct vdi_time_info_v1 valid = {
		.vt_guest_freq = src->vt_guest_freq,
		.vt_guest_tsc = src->vt_guest_tsc,
		.vt_boot_hrtime = -100000000000,
		.vt_hrtime = src->vt_hrtime,
		.vt_hres_sec = src->vt_hres_sec,
		.vt_hres_ns = src->vt_hres_ns,
	};
	test_valid_write_time_data(vmfd, &valid);

	/* read it back */
	test_valid_read_time_data(vmfd, &res);

	/*
	 * The boot_hrtime may have been adjusted by the kernel, but it should
	 * be at least what was supplied.
	 */
	should_geq_i64("boot_hrtime", res.vt_boot_hrtime, valid.vt_boot_hrtime);


	/* repeat for boot_hrtime = 0 */
	valid.vt_boot_hrtime = 0;
	test_valid_write_time_data(vmfd, &valid);
	test_valid_read_time_data(vmfd, &res);
	should_geq_i64("boot_hrtime", res.vt_boot_hrtime, valid.vt_boot_hrtime);

	/* repeat for boot_hrtime > 0 */
	valid.vt_boot_hrtime = src->vt_boot_hrtime + 1;
	test_valid_write_time_data(vmfd, &valid);
	test_valid_read_time_data(vmfd, &res);
	should_geq_i64("boot_hrtime", res.vt_boot_hrtime, valid.vt_boot_hrtime);
}

/*
 * Coarsely test that interface is making adjustments to the host times and
 * guest time values.
 */
static void
test_adjust(int vmfd, struct vdi_time_info_v1 *src)
{
	struct vdi_time_info_v1 res;
	test_valid_write_time_data(vmfd, src);

	/* read it back */
	test_valid_read_time_data(vmfd, &res);

	/*
	 * hrtime, hrestime, and guest TSC should all have moved forward
	 */
	should_geq_i64("vt_hrtime", res.vt_hrtime, src->vt_hrtime);

	if (src->vt_hres_sec == res.vt_hres_sec) {
		/* ns should be higher */
		should_geq_u64("vt_hres_ns", res.vt_hres_ns, src->vt_hres_ns);
	} else if (src->vt_hres_sec > res.vt_hres_sec) {
		errx(EXIT_FAILURE, "test_adjust: hrestime went backwards");
	}

	should_geq_u64("vt_guest_tsc", res.vt_guest_tsc, src->vt_guest_tsc);

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
	if (vm_activate_cpu(ctx, 0) != 0) {
		err(EXIT_FAILURE, "could not activate vcpu0");
	}

	const int vmfd = vm_get_device_fd(ctx);
	const bool is_svm = cpu_vendor_amd();
	struct vdi_time_info_v1 time_info;

	/*
	 * Reads
	 */
	/* do a valid read */
	test_valid_read_time_data(vmfd, &time_info);

	/* malformed read request */
	test_invalid_read_time_data(vmfd);

	/*
	 * Writes
	 *
	 * For the test writes, we reuse the data from the successful read,
	 * and change the request parameters as necessary to test specific
	 * behavior. This is sufficient for testing validation of individual
	 * parameters, as writing the exact data back from a read is allowed.
	 *
	 * The only platform-specific behavior is around changing the guest
	 * TSC frequency. If the guest frequency is the same as the host's,
	 * as it is for all VMs at boot, then no scaling is required, and thus
	 * the CPU vendor of the system, or its capability to scale a guest TSC,
	 * does not matter.
	 */

	/* try writing back the data from the read */
	test_valid_write_time_data(vmfd, &time_info);

	/* malformed write request */
	test_invalid_write_time_data(vmfd, &time_info);

	/* invalid host time requests */
	test_invalid_host_times(vmfd, &time_info);

	/* invalid guest frequency requests */
	test_invalid_freq(vmfd, &time_info);
	if (is_svm) {
		test_invalid_freq_amd(vmfd, &time_info);
	} else {
		test_invalid_freq_intel(vmfd, &time_info);
	}

	/* invalid boot_hrtime request */
	test_invalid_boot_hrtime(vmfd, &time_info);

	/* valid frequency scaling requests */
	if (is_svm) {
		test_valid_freq_amd(vmfd, &time_info);
	}

	/* valid guest TSC values */
	test_valid_guest_tsc(vmfd, &time_info);

	/* valid boot_hrtime values */
	test_valid_boot_hrtime(vmfd, &time_info);

	/* observe that host times and guest data are updated after a write */
	test_adjust(vmfd, &time_info);

	vm_destroy(ctx);
	(void) printf("%s\tPASS\n", suite_name);
	return (EXIT_SUCCESS);
}
