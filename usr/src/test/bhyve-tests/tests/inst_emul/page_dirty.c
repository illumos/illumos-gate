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
 * Copyright 2022 Oxide Computer Company
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <strings.h>
#include <libgen.h>
#include <assert.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/debug.h>
#include <sys/mman.h>
#include <sys/vmm.h>
#include <sys/vmm_dev.h>
#include <vmmapi.h>

#include "common.h"
#include "in_guest.h"

#define	PAGE_SZ	4096

#define	DIRTY_BITMAP_SZ	(MEM_TOTAL_SZ / (PAGE_SZ * 8))

static void
read_dirty_bitmap(struct vmctx *ctx, uint8_t *bitmap)
{
	struct vmm_dirty_tracker track = {
		.vdt_start_gpa = 0,
		.vdt_len = MEM_TOTAL_SZ,
		.vdt_pfns = (void *)bitmap,
	};
	int err = ioctl(vm_get_device_fd(ctx), VM_TRACK_DIRTY_PAGES, &track);
	if (err != 0) {
		test_fail_errno(errno, "Could not get dirty page bitmap");
	}
}

static uint8_t
popc8(uint8_t val)
{
	uint8_t cnt;

	for (cnt = 0; val != 0; val &= (val - 1)) {
		cnt++;
	}
	return (cnt);
}

static uint_t
count_dirty_pages(const uint8_t *bitmap)
{
	uint_t count = 0;
	for (uint_t i = 0; i < DIRTY_BITMAP_SZ; i++) {
		count += popc8(bitmap[i]);
	}
	return (count);
}

void
check_supported(const char *test_suite_name)
{
	char name[VM_MAX_NAMELEN];
	int err;

	name_test_vm(test_suite_name, name);

	err = vm_create(name, VCF_TRACK_DIRTY);
	if (err == 0) {
		/*
		 * We created the VM successfully, so we know that dirty page
		 * tracking is supported.
		 */
		err = destroy_instance(test_suite_name);
		if (err != 0) {
			(void) fprintf(stderr,
			    "Could not destroy VM: %s\n", strerror(errno));
			(void) printf("FAIL %s\n", test_suite_name);
			exit(EXIT_FAILURE);
		}
	} else if (errno == ENOTSUP) {
		(void) printf(
		    "Skipping test: dirty page tracking not supported\n");
		(void) printf("PASS %s\n", test_suite_name);
		exit(EXIT_SUCCESS);
	} else {
		/*
		 * Ignore any other errors, they'll be caught by subsequent
		 * test routines.
		 */
	}
}

void
test_dirty_tracking_disabled(const char *test_suite_name)
{
	struct vmctx *ctx = NULL;
	struct vcpu *vcpu;
	int err;

	uint8_t dirty_bitmap[DIRTY_BITMAP_SZ] = { 0 };
	struct vmm_dirty_tracker track = {
		.vdt_start_gpa = 0,
		.vdt_len = MEM_TOTAL_SZ,
		.vdt_pfns = (void *)dirty_bitmap,
	};

	/* Create VM without VCF_TRACK_DIRTY flag */
	ctx = test_initialize_flags(test_suite_name, 0);

	if ((vcpu = vm_vcpu_open(ctx, 0)) == NULL) {
		test_fail_errno(errno, "Could not open vcpu0");
	}

	err = test_setup_vcpu(vcpu, MEM_LOC_PAYLOAD, MEM_LOC_STACK);
	if (err != 0) {
		test_fail_errno(err, "Could not initialize vcpu0");
	}

	/* Try to query for dirty pages */
	err = ioctl(vm_get_device_fd(ctx), VM_TRACK_DIRTY_PAGES, &track);
	if (err == 0) {
		test_fail_msg("VM_TRACK_DIRTY_PAGES succeeded unexpectedly\n");
	} else if (errno != EPERM) {
		test_fail_errno(errno,
		    "VM_TRACK_DIRTY_PAGES failed with unexpected error");
	}

	test_cleanup(false);
}

int
main(int argc, char *argv[])
{
	const char *test_suite_name = basename(argv[0]);
	struct vmctx *ctx = NULL;
	struct vcpu *vcpu;
	int err;

	/* Skip test if CPU doesn't support HW A/D tracking */
	check_supported(test_suite_name);

	if ((vcpu = vm_vcpu_open(ctx, 0)) == NULL) {
		test_fail_errno(errno, "Could not open vcpu0");
	}

	/* Test for expected error with dirty tracking disabled */
	test_dirty_tracking_disabled(test_suite_name);

	ctx = test_initialize_flags(test_suite_name, VCF_TRACK_DIRTY);

	err = test_setup_vcpu(vcpu, MEM_LOC_PAYLOAD, MEM_LOC_STACK);
	if (err != 0) {
		test_fail_errno(err, "Could not initialize vcpu0");
	}

	uint8_t dirty_bitmap[DIRTY_BITMAP_SZ] = { 0 };

	/* Clear pages which were dirtied as part of initialization */
	read_dirty_bitmap(ctx, dirty_bitmap);
	if (count_dirty_pages(dirty_bitmap) == 0) {
		test_fail_msg("no pages dirtied during setup\n");
	}

	/*
	 * With nothing running, and the old dirty bits cleared, the NPT should
	 * now be devoid of pages marked dirty.
	 */
	read_dirty_bitmap(ctx, dirty_bitmap);
	if (count_dirty_pages(dirty_bitmap) != 0) {
		test_fail_msg("pages still dirty after clear\n");
	}

	/* Dirty a page through the segvmm mapping. */
	uint8_t *dptr = vm_map_gpa(ctx, MEM_LOC_STACK, 1);
	*dptr = 1;

	/* Check that it was marked as such */
	read_dirty_bitmap(ctx, dirty_bitmap);
	if (count_dirty_pages(dirty_bitmap) != 1) {
		test_fail_msg("direct access did not dirty page\n");
	}
	if (dirty_bitmap[MEM_LOC_STACK / (PAGE_SZ * 8)] == 0) {
		test_fail_msg("unexpected page dirtied\n");
	}


	/* Dirty it again to check shootdown logic */
	*dptr = 2;
	if (count_dirty_pages(dirty_bitmap) != 1) {
		test_fail_msg("subsequent direct access did not dirty page\n");
	}

	struct vm_entry ventry = { 0 };
	struct vm_exit vexit = { 0 };
	do {
		const enum vm_exit_kind kind =
		    test_run_vcpu(vcpu, &ventry, &vexit);
		switch (kind) {
		case VEK_REENTR:
			break;
		case VEK_TEST_PASS:
			/*
			 * By now, the guest should have dirtied that page
			 * directly via hardware-accelerated path.
			 */
			read_dirty_bitmap(ctx, dirty_bitmap);
			/*
			 * The guest will dirty more than the page it is
			 * explicitly writing to: it must mark its own page
			 * tables with accessed/dirty bits too.
			 */
			if (count_dirty_pages(dirty_bitmap) <= 1) {
				test_fail_msg(
				    "in-guest access did not dirty page\n");
			}
			if (dirty_bitmap[MEM_LOC_STACK / (PAGE_SZ * 8)] == 0) {
				test_fail_msg("expected page not dirtied\n");
			}
			test_pass();
			break;
		default:
			test_fail_vmexit(&vexit);
			break;
		}
	} while (true);
}
