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
 * Copyright 2025 Oxide Computer Company
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
#define	PAGE_SZ		4096
#define	MBYTE		(1024 * 1024)
#define	GBYTE		(1024 * MBYTE)

#define	MAP_OFF		((512UL * GBYTE) - PAGE_SZ)
#define	SEG_SZ		(4 * MBYTE)
#define	PAGE_CNT	(SEG_SZ / PAGE_SZ)

int
main(int argc, char *argv[])
{
	struct vmctx *ctx;
	int res;
	const char *suite_name = basename(argv[0]);

	ctx = create_test_vm(suite_name);
	if (ctx == NULL) {
		perror("could open test VM");
		return (1);
	}

	res = alloc_memseg(ctx, TEST_SEGID, SEG_SZ, "test_seg");
	if (res != 0) {
		perror("could not alloc memseg");
		goto bail;
	}

	res = vm_mmap_memseg(ctx, MAP_OFF, TEST_SEGID, 0, SEG_SZ, PROT_ALL);
	if (res != 0) {
		perror("could not map memseg into vmspace");
		goto bail;
	}

	res = vm_munmap_memseg(ctx, MAP_OFF, SEG_SZ);
	if (res != 0) {
		perror("could not unmap memseg");
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
