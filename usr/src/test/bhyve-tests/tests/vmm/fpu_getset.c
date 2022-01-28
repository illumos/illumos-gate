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
#include <stropts.h>
#include <strings.h>
#include <signal.h>
#include <setjmp.h>
#include <libgen.h>
#include <sys/debug.h>
#include <sys/fp.h>

#include <sys/vmm.h>
#include <sys/vmm_dev.h>
#include <sys/x86_archext.h>
#include <vmmapi.h>

#include "common.h"

/* Minimal xsave state area (sans any AVX storage) */
struct xsave_min {
	struct fxsave_state	legacy;
	struct xsave_header	header;
};

CTASSERT(sizeof (struct xsave_min) == MIN_XSAVE_SIZE);

struct avx_state {
	/* 16 x 128-bit: high portions of the ymm registers */
	uint64_t	ymm[32];
};

static bool
get_fpu(int fd, struct vm_fpu_state *req)
{
	int res = ioctl(fd, VM_GET_FPU, req);
	if (res != 0) {
		perror("could not read FPU for vCPU");
		return (false);
	}
	return (true);
}

static bool
set_fpu(int fd, struct vm_fpu_state *req)
{
	int res = ioctl(fd, VM_SET_FPU, req);
	if (res != 0) {
		perror("could not write FPU for vCPU");
		return (false);
	}
	return (true);
}

static bool
check_sse(int fd, const struct vm_fpu_desc *desc, void *fpu_area,
    size_t fpu_size)
{
	/* Make sure the x87/MMX/SSE state is described as present */
	bool found_fp = false, found_sse = false;
	for (uint_t i = 0; i < desc->vfd_num_entries; i++) {
		const struct vm_fpu_desc_entry *ent = &desc->vfd_entry_data[i];

		switch (ent->vfde_feature) {
		case XFEATURE_LEGACY_FP:
			found_fp = true;
			if (ent->vfde_off != 0 ||
			    ent->vfde_size != sizeof (struct fxsave_state)) {
				(void) fprintf(stderr,
				    "unexpected entity for %x: "
				    "size=%x off=%x\n", ent->vfde_feature,
				    ent->vfde_size, ent->vfde_off);
				return (false);
			}
			break;
		case XFEATURE_SSE:
			found_sse = true;
			if (ent->vfde_off != 0 ||
			    ent->vfde_size != sizeof (struct fxsave_state)) {
				(void) fprintf(stderr,
				    "unexpected entity for %x: "
				    "size=%x off=%x\n", ent->vfde_feature,
				    ent->vfde_size, ent->vfde_off);
				return (false);
			}
			break;
		}
	}

	if (!found_fp || !found_sse) {
		(void) fprintf(stderr, "did not find x87 and SSE area "
		    "descriptors as expected in initial FPU\n");
		return (false);
	}

	struct vm_fpu_state req = {
		.vcpuid = 0,
		.buf = fpu_area,
		.len = fpu_size,
	};

	if (!get_fpu(fd, &req)) {
		return (false);
	}

	struct xsave_min *xs = fpu_area;
	/*
	 * Executing this test on a freshly-created instance, we expect the FPU
	 * to only have the legacy and SSE features present in its active state.
	 */
	if (xs->header.xsh_xstate_bv != (XFEATURE_LEGACY_FP | XFEATURE_SSE)) {
		(void) fprintf(stderr, "bad xstate_bv %lx, expected %lx",
		    xs->header.xsh_xstate_bv,
		    (XFEATURE_LEGACY_FP | XFEATURE_SSE));
		return (false);
	}

	/* load some SSE values to check for a get/set cycle */
	uint64_t *xmm = (void *)&xs->legacy.fx_xmm[0];
	xmm[0] = UINT64_MAX;
	xmm[2] = 1;

	if (!set_fpu(fd, &req)) {
		return (false);
	}

	/* check that those values made it in/out of the guest FPU */
	bzero(fpu_area, fpu_size);
	if (!get_fpu(fd, &req)) {
		return (false);
	}
	if (xmm[0] != UINT64_MAX || xmm[2] != 1) {
		(void) fprintf(stderr, "SSE test registers not saved\n");
		return (false);
	}

	/* Make sure that a bogus MXCSR value is rejected */
	xs->legacy.fx_mxcsr = UINT32_MAX;
	int res = ioctl(fd, VM_SET_FPU, &req);
	if (res == 0) {
		(void) fprintf(stderr,
		    "write of invalid MXCSR erroneously allowed\n");
		return (false);
	}

	return (true);
}

static bool
check_avx(int fd, const struct vm_fpu_desc *desc, void *fpu_area,
    size_t fpu_size)
{
	bool found_avx = false;
	size_t avx_size, avx_off;
	for (uint_t i = 0; i < desc->vfd_num_entries; i++) {
		const struct vm_fpu_desc_entry *ent = &desc->vfd_entry_data[i];

		if (ent->vfde_feature == XFEATURE_AVX) {
			found_avx = true;
			avx_size = ent->vfde_size;
			avx_off = ent->vfde_off;
			break;
		}
	}

	if (!found_avx) {
		(void) printf("AVX capability not found on host CPU, "
		    "skipping related tests\n");
		return (true);
	}

	if (avx_size != sizeof (struct avx_state)) {
		(void) fprintf(stderr, "unexpected AVX state size: %x, "
		    "expected %x\n", avx_size, sizeof (struct avx_state));
		return (false);
	}
	if ((avx_off + avx_size) > fpu_size) {
		(void) fprintf(stderr, "AVX data falls outside fpu size: "
		    "%x > %x\n", avx_off + avx_size, fpu_size);
		return (false);
	}

	struct xsave_min *xs = fpu_area;
	struct avx_state *avx = fpu_area + avx_off;

	/* do a simple data round-trip */
	struct vm_fpu_state req = {
		.vcpuid = 0,
		.buf = fpu_area,
		.len = fpu_size,
	};
	if (!get_fpu(fd, &req)) {
		return (false);
	}

	/* With AVX unused so far, we expect it to be absent from the BV */
	if (xs->header.xsh_xstate_bv != (XFEATURE_LEGACY_FP | XFEATURE_SSE)) {
		(void) fprintf(stderr, "bad xstate_bv %lx, expected %lx\n",
		    xs->header.xsh_xstate_bv,
		    (XFEATURE_LEGACY_FP | XFEATURE_SSE));
		return (false);
	}

	avx->ymm[0] = UINT64_MAX;
	avx->ymm[2] = 2;

	/* first write without asserting AVX in BV */
	if (!set_fpu(fd, &req)) {
		return (false);
	}

	/* And check that the AVX state stays empty */
	bzero(fpu_area, fpu_size);
	if (!get_fpu(fd, &req)) {
		return (false);
	}
	if (xs->header.xsh_xstate_bv != (XFEATURE_LEGACY_FP | XFEATURE_SSE)) {
		(void) fprintf(stderr, "xstate_bv changed unexpectedly %lx\n",
		    xs->header.xsh_xstate_bv);
		return (false);
	}
	if (avx->ymm[0] != 0 || avx->ymm[2] != 0) {
		(void) fprintf(stderr, "YMM state changed unexpectedly "
		    "%lx %lx\n", avx->ymm[0], avx->ymm[2]);
		return (false);
	}

	/* Now write YMM and set the appropriate AVX BV state */
	avx->ymm[0] = UINT64_MAX;
	avx->ymm[2] = 2;
	xs->header.xsh_xstate_bv |= XFEATURE_AVX;
	if (!set_fpu(fd, &req)) {
		return (false);
	}

	/* ... and now check that it stuck */
	bzero(fpu_area, fpu_size);
	if (!get_fpu(fd, &req)) {
		return (false);
	}
	if ((xs->header.xsh_xstate_bv & XFEATURE_AVX) == 0) {
		(void) fprintf(stderr, "AVX missing from xstate_bv %lx\n",
		    xs->header.xsh_xstate_bv);
		return (false);
	}
	if (avx->ymm[0] != UINT64_MAX || avx->ymm[2] != 2) {
		(void) fprintf(stderr, "YMM state not preserved "
		    "%lx != %lx | %lx != %lx\n",
		    avx->ymm[0], UINT64_MAX, avx->ymm[2], 2);
		return (false);
	}


	return (true);
}

int
main(int argc, char *argv[])
{
	struct vmctx *ctx;
	int res, fd;
	const char *suite_name = basename(argv[0]);

	ctx = create_test_vm(suite_name);
	if (ctx == NULL) {
		perror("could not open test VM");
		return (EXIT_FAILURE);
	}
	fd = vm_get_device_fd(ctx);

	struct vm_fpu_desc_entry entries[64];
	struct vm_fpu_desc desc = {
		.vfd_entry_data = entries,
		.vfd_num_entries = 64,
	};

	res = ioctl(fd, VM_DESC_FPU_AREA, &desc);
	if (res != 0) {
		perror("could not query fpu area description");
		goto bail;
	}

	/* Make sure the XSAVE area described for this machine is reasonable */
	if (desc.vfd_num_entries == 0) {
		(void) fprintf(stderr, "no FPU description entries found\n");
		goto bail;
	}
	if (desc.vfd_req_size < MIN_XSAVE_SIZE) {
		(void) fprintf(stderr, "required XSAVE size %lu < "
		    "expected %lu\n", desc.vfd_req_size, MIN_XSAVE_SIZE);
		goto bail;
	}

	const size_t fpu_size = desc.vfd_req_size;
	void *fpu_area = malloc(fpu_size);
	if (fpu_area == NULL) {
		perror("could not allocate fpu area");
		goto bail;
	}
	bzero(fpu_area, fpu_size);

	if (!check_sse(fd, &desc, fpu_area, fpu_size)) {
		goto bail;
	}
	if (!check_avx(fd, &desc, fpu_area, fpu_size)) {
		goto bail;
	}

	/* mission accomplished */
	vm_destroy(ctx);
	(void) printf("%s\tPASS\n", suite_name);
	return (EXIT_SUCCESS);

bail:
	vm_destroy(ctx);
	(void) printf("%s\tFAIL\n", suite_name);
	return (EXIT_FAILURE);
}
