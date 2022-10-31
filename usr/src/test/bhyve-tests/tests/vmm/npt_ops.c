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

#define	PAGESZ		4096
#define	TEST_PAGE_COUNT	256
#define	TEST_MEM_SZ	(PAGESZ * 256)

static struct vmctx *
check_vmm_capability(const char *tname)
{
	char vmname[VM_MAX_NAMELEN];

	name_test_vm(tname, vmname);
	int res = vm_create(vmname, VCF_TRACK_DIRTY);

	if (res != 0) {
		if (errno == ENOTSUP) {
			(void) fprintf(stderr,
			    "VMM lacks dirty page tracking capability");
			(void) printf("%s\tSKIP\n", tname);
			exit(EXIT_SUCCESS);
		}
		err(EXIT_FAILURE, "could not create VM");
	}
	struct vmctx *ctx = vm_open(vmname);
	if (ctx == NULL) {
		err(EXIT_FAILURE, "could not open test VM");
	}

	return (ctx);
}

static void
expect_errno(int expected)
{
	if (errno != expected) {
		errx(EXIT_FAILURE, "unexpected errno %d != %d",
		    errno, expected);
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
legacy_clear_dirty(struct vmctx *ctx)
{
	uint8_t bitmap[TEST_PAGE_COUNT / 8] = { 0 };
	struct vmm_dirty_tracker req = {
		.vdt_start_gpa = 0,
		.vdt_len = TEST_MEM_SZ,
		.vdt_pfns = bitmap,
	};

	if (ioctl(vm_get_device_fd(ctx), VM_TRACK_DIRTY_PAGES, &req) != 0) {
		err(EXIT_FAILURE, "VM_TRACK_DIRTY_PAGES failed");
	}

	uint_t bits_set = 0;
	for (uint_t i = 0; i < (TEST_PAGE_COUNT / 8); i++) {
		bits_set += popc8(bitmap[i]);
	}
	return (bits_set);
}

static void
do_npt_op(int vmfd, struct vm_npt_operation *vno)
{
	if (ioctl(vmfd, VM_NPT_OPERATION, vno) != 0) {
		err(EXIT_FAILURE, "VM_NPT_OPERATION failed");
	}
}

static void
test_legacy(struct vmctx *ctx)
{
	const int vmfd = vm_get_device_fd(ctx);
	uint8_t *datap = vm_map_gpa(ctx, 0, PAGESZ);

	/* dirty the first page */
	*datap = 0xff;

	uint8_t bitmap[TEST_PAGE_COUNT / 8] = { 0 };
	struct vmm_dirty_tracker req = {
		.vdt_start_gpa = 0,
		.vdt_len = TEST_MEM_SZ,
		.vdt_pfns = bitmap,
	};

	if (ioctl(vmfd, VM_TRACK_DIRTY_PAGES, &req) != 0) {
		err(EXIT_FAILURE, "VM_TRACK_DIRTY_PAGES failed");
	}

	if (bitmap[0] != 1) {
		errx(EXIT_FAILURE, "first page not marked dirty");
	}
	for (uint_t i = 1; i < (TEST_PAGE_COUNT / 8); i++) {
		if (bitmap[i] != 0) {
			errx(EXIT_FAILURE,
			    "unexpected non-zero entry: bitmap[%u] = %x\n",
			    i, bitmap[i]);
		}
	}
}

static void
test_toggle_tracking(struct vmctx *ctx)
{
	const int vmfd = vm_get_device_fd(ctx);
	struct vm_npt_operation vno = {
		.vno_operation = VNO_OP_GET_TRACK_DIRTY,
		.vno_gpa = 0,
		.vno_len = 0,
	};

	/*
	 * Since the VM was created with VCF_TRACK_DIRTY set, dirty tracking
	 * should already be active.
	 */
	if (ioctl(vmfd, VM_NPT_OPERATION, &vno) != 1) {
		errx(EXIT_FAILURE, "expected dirty tracking to be active");
	}

	vno.vno_operation = VNO_OP_DIS_TRACK_DIRTY;
	if (ioctl(vmfd, VM_NPT_OPERATION, &vno) != 0) {
		err(EXIT_FAILURE, "VM_NPT_OPERATION failed");
	}

	vno.vno_operation = VNO_OP_GET_TRACK_DIRTY;
	if (ioctl(vmfd, VM_NPT_OPERATION, &vno) != 0) {
		errx(EXIT_FAILURE, "expected dirty tracking to be inactive");
	}

	vno.vno_operation = VNO_OP_EN_TRACK_DIRTY;
	if (ioctl(vmfd, VM_NPT_OPERATION, &vno) != 0) {
		err(EXIT_FAILURE, "VM_NPT_OPERATION failed");
	}

	vno.vno_operation = VNO_OP_GET_TRACK_DIRTY;
	if (ioctl(vmfd, VM_NPT_OPERATION, &vno) != 1) {
		errx(EXIT_FAILURE,
		    "expected dirty tracking to be active again");
	}
}

static void
test_inval_args(struct vmctx *ctx)
{
	const int vmfd = vm_get_device_fd(ctx);
	struct vm_npt_operation vno = { 0 };

	/* invalid vno_operation */
	vno.vno_operation = ~0;
	if (ioctl(vmfd, VM_NPT_OPERATION, &vno) == 0) {
		err(EXIT_FAILURE, "unexpected VM_NPT_OPERATION success");
	}
	expect_errno(EINVAL);

	/* valid operation, but gpa which is not page-aligned */
	vno.vno_operation = VNO_OP_GET_DIRTY | VNO_FLAG_BITMAP_IN;
	vno.vno_gpa = 0x100;
	vno.vno_len = PAGESZ;

	if (ioctl(vmfd, VM_NPT_OPERATION, &vno) == 0) {
		err(EXIT_FAILURE, "unexpected VM_NPT_OPERATION success");
	}
	expect_errno(EINVAL);

	/* gpa is page-aligned, but len isn't */
	vno.vno_gpa = 0;
	vno.vno_len = PAGESZ + 0x100;

	if (ioctl(vmfd, VM_NPT_OPERATION, &vno) == 0) {
		err(EXIT_FAILURE, "unexpected VM_NPT_OPERATION success");
	}
	expect_errno(EINVAL);

	/* overflowing region */
	vno.vno_gpa = 0xffffffffffffe000;
	vno.vno_len = 512 * PAGESZ;

	if (ioctl(vmfd, VM_NPT_OPERATION, &vno) == 0) {
		err(EXIT_FAILURE, "unexpected VM_NPT_OPERATION success");
	}
	expect_errno(EOVERFLOW);
}

static void
test_op_get_dirty(struct vmctx *ctx)
{
	const int vmfd = vm_get_device_fd(ctx);
	uint8_t *datap = vm_map_gpa(ctx, 0, TEST_MEM_SZ);

	/* Use legacy mechanism to ensure dirty bits are clear to start */
	(void) legacy_clear_dirty(ctx);

	/* Dirty the first page out of every 8 */
	for (uint_t i = 0; i < TEST_MEM_SZ; i += (PAGESZ * 8)) {
		datap[i] = 0xff;
	}

	uint8_t bits[TEST_PAGE_COUNT / 8] = { 0 };
	struct vm_npt_operation vno = {
		.vno_gpa = 0,
		.vno_len = TEST_MEM_SZ,
		.vno_operation = VNO_OP_GET_DIRTY | VNO_FLAG_BITMAP_OUT,
		.vno_bitmap = bits,
	};
	do_npt_op(vmfd, &vno);

	for (uint_t i = 0; i < TEST_PAGE_COUNT / 8; i++) {
		if (bits[i] != 0x01) {
			errx(EXIT_FAILURE,
			    "unexpected dirty bits %02x at base gpa %08x",
			    bits[i], i * PAGESZ * 8);
		}
	}

	/* Clear those bits again */
	(void) legacy_clear_dirty(ctx);

	/* And check that they are zeroed now */
	do_npt_op(vmfd, &vno);
	for (uint_t i = 0; i < TEST_PAGE_COUNT / 8; i++) {
		if (bits[i] != 0) {
			errx(EXIT_FAILURE,
			    "unexpected dirty bits %02x at base gpa %08x",
			    bits[i], i * PAGESZ * 8);
		}
	}
}

static void
test_op_set_dirty(struct vmctx *ctx)
{
	const int vmfd = vm_get_device_fd(ctx);

	/* Use legacy mechanism to ensure dirty bits are clear to start */
	(void) legacy_clear_dirty(ctx);

	/* Mark first 17 pages as dirty */
	uint8_t bits[TEST_PAGE_COUNT / 8] = { 0xff, 0xff, 0x80 };
	struct vm_npt_operation vno = {
		.vno_gpa = 0,
		.vno_len = TEST_MEM_SZ,
		.vno_operation = VNO_OP_SET_DIRTY | VNO_FLAG_BITMAP_IN,
		.vno_bitmap = bits,
	};
	do_npt_op(vmfd, &vno);

	uint_t legacy_dirty = legacy_clear_dirty(ctx);
	if (legacy_dirty != 17) {
		errx(EXIT_FAILURE, "unexpected dirty count after OP_SET_DIRTY");
	}
}

#define	BMAP_IDX(gpa)	((gpa) / (PAGESZ * 8))
#define	BMAP_BIT(gpa)	(((gpa) / PAGESZ) % 8)

static void
test_op_reset_dirty(struct vmctx *ctx)
{
	const int vmfd = vm_get_device_fd(ctx);
	uint8_t *datap = vm_map_gpa(ctx, 0, TEST_MEM_SZ);

	/* Use legacy mechanism to ensure dirty bits are clear to start */
	(void) legacy_clear_dirty(ctx);

	/* Dirty the front half of memory */
	for (uintptr_t gpa = 0; gpa < (TEST_MEM_SZ / 2); gpa += PAGESZ) {
		datap[gpa] = 0xff;
	}

	uint8_t bits[TEST_PAGE_COUNT / 8] = { 0 };
	/* Mark bitmap for every other page, starting at 0 */
	for (uintptr_t gpa = 0; gpa < TEST_MEM_SZ; gpa += (2 * PAGESZ)) {
		bits[BMAP_IDX(gpa)] |= (1 << BMAP_BIT(gpa));
	}

	struct vm_npt_operation vno = {
		.vno_gpa = 0,
		.vno_len = TEST_MEM_SZ,
		.vno_operation = VNO_OP_RESET_DIRTY |
		    VNO_FLAG_BITMAP_IN | VNO_FLAG_BITMAP_OUT,
		.vno_bitmap = bits,
	};
	do_npt_op(vmfd, &vno);

	/* Check that pages marked dirty were reported back as such */
	for (uintptr_t gpa = 0; gpa < TEST_MEM_SZ; gpa += PAGESZ) {
		const bool is_even_page = (BMAP_BIT(gpa) % 2) == 0;
		const bool is_dirty =
		    (bits[BMAP_IDX(gpa)] & (1 << BMAP_BIT(gpa))) != 0;

		/* Even pages in the first half should be set */
		if (is_even_page && gpa < (TEST_MEM_SZ / 2) && !is_dirty) {
			errx(EXIT_FAILURE,
			    "missing dirty bit set at gpa %08lx", gpa);
		}

		/* Odd pages and even pages in second half should be unset */
		if (is_dirty && (!is_even_page || gpa >= (TEST_MEM_SZ / 2))) {
			errx(EXIT_FAILURE,
			    "unexpected dirty bit set at gpa %08lx", gpa);
		}
	}

	/*
	 * With half of the pages dirtied at first, and then half of those reset
	 * from dirty in the NPT operation, we expect 1/4 to be remaining.
	 */
	uint_t remaining_dirty = legacy_clear_dirty(ctx);
	if (remaining_dirty != (TEST_PAGE_COUNT / 4)) {
		errx(EXIT_FAILURE,
		    "expected %u pages remaining dirty, found %u",
		    TEST_PAGE_COUNT / 2, remaining_dirty);
	}
}

int
main(int argc, char *argv[])
{
	const char *suite_name = basename(argv[0]);
	struct vmctx *ctx;

	ctx = check_vmm_capability(suite_name);

	if (vm_setup_memory(ctx, TEST_MEM_SZ, VM_MMAP_ALL) != 0) {
		err(EXIT_FAILURE, "could not setup VM memory");
	}

	/* Test "legacy" VM_TRACK_DIRTY_PAGES mechanism first */
	test_legacy(ctx);

	/* Confirm that dirty tracking can be queried and toggled on/off */
	test_toggle_tracking(ctx);

	/* Check some invalid argument conditions */
	test_inval_args(ctx);

	/* Can dirty bits be queried with VNO_OP_GET_DIRTY */
	test_op_get_dirty(ctx);

	/* Can dirty bits be set with VNO_OP_SET_DIRTY */
	test_op_set_dirty(ctx);

	/*
	 * Can dirty bits be reset (simultaneously queried and cleared )
	 * with VNO_OP_RESET_DIRTY
	 */
	test_op_reset_dirty(ctx);

	vm_destroy(ctx);
	(void) printf("%s\tPASS\n", suite_name);
	return (EXIT_SUCCESS);
}
