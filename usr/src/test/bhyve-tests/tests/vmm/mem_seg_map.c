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
#include <stropts.h>
#include <strings.h>
#include <signal.h>
#include <setjmp.h>
#include <libgen.h>

#include <sys/vmm.h>
#include <sys/vmm_dev.h>
#include <sys/mman.h>
#include <vmmapi.h>

#include "common.h"

#define	TEST_SEGID	0
#define	PAGE_CNT	1024
#define	PAGE_SZ		4096
#define	SEG_SZ	(PAGE_CNT * PAGE_SZ)

int
main(int argc, char *argv[])
{
	struct vmctx *ctx;
	int res, fd;
	void *seg_obj, *guest_mem;

	ctx = create_test_vm();
	if (ctx == NULL) {
		perror("could open test VM");
		return (1);
	}
	fd = vm_get_device_fd(ctx);

	res = alloc_memseg(ctx, TEST_SEGID, SEG_SZ, "test_seg");
	if (res != 0) {
		perror("could not alloc memseg");
		goto bail;
	}
	off_t seg_obj_off;
	res = vm_get_devmem_offset(ctx, TEST_SEGID, &seg_obj_off);
	if (res != 0) {
		perror("could not find mapping offset for seg object");
		goto bail;
	}

	seg_obj = mmap(NULL, SEG_SZ, PROT_READ | PROT_WRITE, MAP_SHARED,
	    fd, seg_obj_off);
	if (seg_obj == MAP_FAILED) {
		perror("could not mmap seg object");
		goto bail;
	}

	/* populate with initial data */
	for (uint_t i = 0; i < PAGE_CNT; i++) {
		uint64_t *p = (uint64_t *)((uintptr_t)seg_obj + i * PAGE_SZ);

		*p = i;
	}

	res = vm_mmap_memseg(ctx, 0, TEST_SEGID, 0, SEG_SZ, PROT_ALL);
	if (res != 0) {
		perror("could not map memseg into vmspace");
		goto bail;
	}
	guest_mem = mmap(NULL, SEG_SZ, PROT_READ | PROT_WRITE, MAP_SHARED,
	    fd, 0);
	if (seg_obj == MAP_FAILED) {
		perror("could not mmap vmspace");
		goto bail;
	}

	/* check data and access though vmspace */
	for (uint_t i = 0; i < PAGE_CNT; i++) {
		const uint64_t off = i * PAGE_SZ;
		uint64_t *p = (uint64_t *)((uintptr_t)guest_mem + off);

		const uint64_t val = *p;
		if (val != i) {
			(void) printf("%lu != %u at gpa:%lx\n", val, i, off);
			goto bail;
		}

		/* leave a change behind */
		*p = val * 2;
	}

	/* check changes made through vmspace */
	for (uint_t i = 0; i < PAGE_CNT; i++) {
		const uint64_t off = i * PAGE_SZ;
		uint64_t *p = (uint64_t *)((uintptr_t)seg_obj + off);

		const uint_t expected = i * 2;
		const uint64_t val = *p;
		if (val != expected) {
			(void) printf("%lu != %u at gpa:%lx\n", val, expected,
			    off);
			goto bail;
		}
	}

	/* unmap access mappings */
	res = munmap(guest_mem, SEG_SZ);
	if (res != 0) {
		perror("could not munmap vmspace");
		goto bail;
	}
	res = munmap(seg_obj, SEG_SZ);
	if (res != 0) {
		perror("could not munmap seg object");
		goto bail;
	}

	/* mission accomplished */
	vm_destroy(ctx);
	(void) printf("%s\tPASS\n", basename(argv[0]));
	return (0);

bail:
	vm_destroy(ctx);
	return (1);
}
