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

#include <sys/vmm.h>
#include <sys/vmm_dev.h>
#include <sys/mman.h>
#include <vmmapi.h>

/* Half of a leaf page table is 256 pages */
#define	LOWER_SZ	(256 * 4096)
#define	UPPER_SZ	LOWER_SZ
#define	TOTAL_SZ	(LOWER_SZ + UPPER_SZ)

#define	LOWER_OFF	0
#define	UPPER_OFF	LOWER_SZ

#define	PROT_ALL	(PROT_READ | PROT_WRITE | PROT_EXEC)

enum test_memsegs {
	MSEG_LOW = 0,
	MSEG_HIGH = 1,
};

struct vmctx *
create_test_vm()
{
	char name[VM_MAX_NAMELEN];
	int res;

	(void) snprintf(name, sizeof (name), "bhyve-test-memmap-%d", getpid());

	res = vm_create(name, 0);
	if (res != 0) {
		return (NULL);
	}

	return (vm_open(name));
}

int
alloc_memseg(struct vmctx *ctx, int segid, size_t len, const char *name)
{
	struct vm_memseg memseg = {
		.segid = segid,
		.len = len,
	};
	(void) strlcpy(memseg.name, name, sizeof (memseg.name));

	int fd = vm_get_device_fd(ctx);

	return (ioctl(fd, VM_ALLOC_MEMSEG, &memseg));
}

static sigjmp_buf segv_env;

void
sigsegv_handler(int sig)
{
	siglongjmp(segv_env, 1);
}


int
main(int argc, char *argv[])
{
	struct vmctx *ctx;
	int res, fd;
	void *guest_mem;

	ctx = create_test_vm();
	fd = vm_get_device_fd(ctx);

	res = alloc_memseg(ctx, MSEG_LOW, LOWER_SZ, "mseg_low");
	if (res != 0) {
		perror("could not alloc low memseg");
		goto bail;
	}
	res = alloc_memseg(ctx, MSEG_HIGH, UPPER_SZ, "mseg_high");
	if (res != 0) {
		perror("could not alloc high memseg");
		goto bail;
	}


	res = vm_mmap_memseg(ctx, LOWER_OFF, MSEG_LOW, 0, LOWER_SZ, PROT_ALL);
	if (res != 0) {
		perror("could not map low memseg");
		goto bail;
	}
	res = vm_mmap_memseg(ctx, UPPER_OFF, MSEG_HIGH, 0, UPPER_SZ, PROT_ALL);
	if (res != 0) {
		perror("could not map high memseg");
		goto bail;
	}

	guest_mem = mmap(NULL, TOTAL_SZ, PROT_READ | PROT_WRITE, MAP_SHARED,
	    fd, 0);
	if (guest_mem == MAP_FAILED) {
		perror("could not mmap guest memory");
		goto bail;
	}

	/* Fill memory with 0xff */
	for (uintptr_t gpa = 0; gpa < TOTAL_SZ; gpa++) {
		uint8_t *ptr = guest_mem + gpa;
		*ptr = 0xff;
	}

	/* Unmap the lower memseg */
	res = vm_munmap_memseg(ctx, LOWER_OFF, LOWER_SZ);
	if (guest_mem == NULL) {
		perror("could not unmap lower memseg");
		goto bail;
	}

	/* Confirm upper contents are still correct/accessible */
	for (uintptr_t gpa = UPPER_OFF; gpa < UPPER_OFF + UPPER_SZ; gpa++) {
		uint8_t *ptr = guest_mem + gpa;
		if (*ptr != 0xff) {
			(void) printf("invalid mem contents at GPA %lx: %x\n",
			    gpa, *ptr);
			goto bail;
		}
		*ptr = 0xee;
	}

	/*
	 * Attempt to access the lower contents, which should result in an
	 * expected (and thus handled) SIGSEGV.
	 */
	struct sigaction sa = {
		.sa_handler = sigsegv_handler,
	};
	struct sigaction old_sa;
	res = sigaction(SIGSEGV, &sa, &old_sa);
	if (res != 0) {
		perror("could not prep signal handling for bad access");
		goto bail;
	}

	if (sigsetjmp(segv_env, 1) == 0) {
		volatile uint8_t *ptr = guest_mem;

		/*
		 * This access to the guest space should fail, since the memseg
		 * covering the lower part of the VM space has been unmapped.
		 */
		uint8_t tmp = *ptr;

		(void) printf("access to %p (%x) should have failed\n", tmp);
		goto bail;
	}

	/*
	 * Unmap and remap the space so any cached entries are dropped for the
	 * portion we expect is still accessible.
	 */
	res = munmap(guest_mem, TOTAL_SZ);
	if (res != 0) {
		perror("could not unmap lower memseg");
		goto bail;
	}
	guest_mem = mmap(NULL, TOTAL_SZ, PROT_READ | PROT_WRITE, MAP_SHARED,
	    fd, 0);
	if (guest_mem == MAP_FAILED) {
		perror("could not re-mmap guest memory");
		goto bail;
	}

	/* Check the upper portion for accessibility. */
	if (sigsetjmp(segv_env, 1) == 0) {
		volatile uint8_t *ptr = guest_mem + UPPER_OFF;

		uint8_t tmp = *ptr;
		if (tmp != 0xee) {
			(void) printf("unexpected value at %p (%x)\n", ptr,
			    tmp);
			goto bail;
		}

		res = sigaction(SIGSEGV, &old_sa, NULL);
		if (res != 0) {
			perror("could not restore SIGSEGV handler");
			goto bail;
		}
	} else {
		(void) printf("unexpected fault in upper mapping\n");
		goto bail;
	}


	/* Unmap the upper memseg */
	res = vm_munmap_memseg(ctx, UPPER_OFF, UPPER_SZ);
	if (guest_mem == NULL) {
		perror("could not unmap upper memseg");
		goto bail;
	}

	/* mission accomplished */
	vm_destroy(ctx);
	return (0);

bail:
	vm_destroy(ctx);
	return (1);
}
