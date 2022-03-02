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

enum test_segs {
	SEG_LOWMEM = 0,
	SEG_BOOTROM = 1,
};
#define	PAGE_CNT	2
#define	PAGE_SZ		4096
#define	SEG_SZ		(PAGE_CNT * PAGE_SZ)
#define	WHOLE_SZ	(SEG_SZ * 2)

#define	TESTVAL_LOWMEM	0x1000ffff
#define	TESTVAL_BOOTROM	0x2000eeee

int
main(int argc, char *argv[])
{
	struct vmctx *ctx;
	int res, fd;
	const char *suite_name = basename(argv[0]);

	ctx = create_test_vm(suite_name);
	if (ctx == NULL) {
		perror("could open test VM");
		return (1);
	}
	fd = vm_get_device_fd(ctx);

	res = alloc_memseg(ctx, SEG_LOWMEM, SEG_SZ, "");
	if (res != 0) {
		perror("could not alloc lowmem seg");
		goto bail;
	}
	res = alloc_memseg(ctx, SEG_BOOTROM, SEG_SZ, "bootrom");
	if (res != 0) {
		perror("could not alloc bootrom seg");
		goto bail;
	}

	res = vm_mmap_memseg(ctx, 0, SEG_LOWMEM, 0, SEG_SZ, PROT_ALL);
	if (res != 0) {
		perror("could not map lowmem into vmspace");
		goto bail;
	}
	res = vm_mmap_memseg(ctx, SEG_SZ, SEG_BOOTROM, 0, SEG_SZ, PROT_READ);
	if (res != 0) {
		perror("could not map bootrom into vmspace");
		goto bail;
	}

	void *guest_mem;
	guest_mem = mmap(NULL, WHOLE_SZ, PROT_READ, MAP_SHARED, fd, 0);
	if (guest_mem == MAP_FAILED) {
		perror("could not mmap guest-physical memory");
		goto bail;
	}

	void *direct_lowmem, *direct_bootrom;
	off_t seg_obj_off;

	res = vm_get_devmem_offset(ctx, SEG_LOWMEM, &seg_obj_off);
	if (res != 0) {
		perror("could not find mapping offset for lowmem seg");
		goto bail;
	}
	direct_lowmem = mmap(NULL, SEG_SZ, PROT_READ | PROT_WRITE, MAP_SHARED,
	    fd, seg_obj_off);
	if (direct_lowmem == MAP_FAILED) {
		perror("could not mmap lowmem directly");
		goto bail;
	}

	res = vm_get_devmem_offset(ctx, SEG_BOOTROM, &seg_obj_off);
	if (res != 0) {
		perror("could not find mapping offset for lowmem seg");
		goto bail;
	}
	direct_bootrom = mmap(NULL, SEG_SZ, PROT_READ | PROT_WRITE, MAP_SHARED,
	    fd, seg_obj_off);
	if (direct_bootrom == MAP_FAILED) {
		perror("could not mmap bootrom directly");
		goto bail;
	}

	uint32_t *datap;

	datap = direct_lowmem;
	*datap = TESTVAL_LOWMEM;
	datap = direct_bootrom;
	*datap = TESTVAL_BOOTROM;

	/* check that data written though direct access is as expected */
	datap = guest_mem;
	if (*datap != TESTVAL_LOWMEM) {
		(void) fprintf(stderr, "unexpected data in lowmem %x != %x\n",
		    *datap, TESTVAL_LOWMEM);
		goto bail;
	}
	datap = (guest_mem + SEG_SZ);
	if (*datap != TESTVAL_BOOTROM) {
		(void) fprintf(stderr, "unexpected data in bootrom %x != %x\n",
		    *datap, TESTVAL_BOOTROM);
		goto bail;
	}

	/* unmap access mappings */
	res = munmap(guest_mem, WHOLE_SZ);
	if (res != 0) {
		perror("could not munmap vmspace");
		goto bail;
	}
	res = munmap(direct_lowmem, SEG_SZ);
	if (res != 0) {
		perror("could not munmap lowmem object");
		goto bail;
	}
	res = munmap(direct_bootrom, SEG_SZ);
	if (res != 0) {
		perror("could not munmap bootrom object");
		goto bail;
	}

	/* mission accomplished */
	vm_destroy(ctx);
	(void) printf("%s\tPASS\n", suite_name);
	return (0);

bail:
	vm_destroy(ctx);
	return (1);
}
