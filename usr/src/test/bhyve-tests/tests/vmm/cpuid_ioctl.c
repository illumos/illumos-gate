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
#include <fcntl.h>
#include <libgen.h>
#include <err.h>
#include <errno.h>
#include <strings.h>

#include <sys/vmm.h>
#include <sys/vmm_dev.h>
#include <vmmapi.h>

#include "common.h"

int
main(int argc, char *argv[])
{
	const char *suite_name = basename(argv[0]);
	struct vmctx *ctx;

	ctx = create_test_vm(suite_name);
	if (ctx == NULL) {
		perror("could open test VM");
		return (EXIT_FAILURE);
	}
	int vmfd = vm_get_device_fd(ctx);

	struct vm_vcpu_cpuid_config cfg = { 0 };
	struct vcpu_cpuid_entry *entries = NULL;

	if (ioctl(vmfd, VM_GET_CPUID, &cfg) != 0) {
		err(EXIT_FAILURE, "ioctl(VM_GET_CPUID) failed");
	}
	if (cfg.vvcc_flags != VCC_FLAG_LEGACY_HANDLING) {
		errx(EXIT_FAILURE,
		    "cpuid handling did not default to legacy-style");
	}

	cfg.vvcc_flags = ~VCC_FLAG_LEGACY_HANDLING;
	if (ioctl(vmfd, VM_SET_CPUID, &cfg) == 0) {
		errx(EXIT_FAILURE,
		    "ioctl(VM_SET_CPUID) did not reject invalid flags");
	}

	entries = calloc(VMM_MAX_CPUID_ENTRIES + 1,
	    sizeof (struct vcpu_cpuid_entry));
	if (entries == NULL) {
		errx(EXIT_FAILURE, "could not allocate cpuid entries");
	}

	cfg.vvcc_flags = VCC_FLAG_LEGACY_HANDLING;
	cfg.vvcc_nent = 1;
	cfg.vvcc_entries = entries;
	if (ioctl(vmfd, VM_SET_CPUID, &cfg) == 0) {
		errx(EXIT_FAILURE,
		    "ioctl(VM_SET_CPUID) did not reject entries when "
		    "legacy-style handling was requested");
	}

	cfg.vvcc_flags = 0;
	cfg.vvcc_nent = VMM_MAX_CPUID_ENTRIES + 1;
	if (ioctl(vmfd, VM_SET_CPUID, &cfg) == 0) {
		errx(EXIT_FAILURE,
		    "ioctl(VM_SET_CPUID) did not reject excessive entry count");
	}

	cfg.vvcc_nent = 1;
	entries[0].vce_flags = ~0;
	if (ioctl(vmfd, VM_SET_CPUID, &cfg) == 0) {
		errx(EXIT_FAILURE,
		    "ioctl(VM_SET_CPUID) did not invalid entry flags");
	}
	entries[0].vce_flags = 0;

	/* Actually set some entries to use for GET_CPUID testing */
	const uint_t valid_entries = (VMM_MAX_CPUID_ENTRIES / 2);
	for (uint_t i = 0; i < valid_entries; i++) {
		entries[i].vce_function = i;
	}
	cfg.vvcc_nent = valid_entries;
	if (ioctl(vmfd, VM_SET_CPUID, &cfg) != 0) {
		err(EXIT_FAILURE,
		    "ioctl(VM_SET_CPUID) unable to set valid entries");
	}

	/* Try with no entries buffer */
	bzero(&cfg, sizeof (cfg));
	if (ioctl(vmfd, VM_GET_CPUID, &cfg) == 0 || errno != E2BIG) {
		errx(EXIT_FAILURE,
		    "ioctl(VM_GET_CPUID) did not fail absent buffer");
	}
	if (cfg.vvcc_nent != valid_entries) {
		errx(EXIT_FAILURE,
		    "ioctl(VM_GET_CPUID) did not emit entry count "
		    "(expected %u, got %u)", valid_entries, cfg.vvcc_nent);
	}

	/* Try with too-small entries buffer */
	cfg.vvcc_nent = 1;
	cfg.vvcc_entries = entries;
	bzero(entries, valid_entries * sizeof (struct vcpu_cpuid_entry));
	if (ioctl(vmfd, VM_GET_CPUID, &cfg) == 0 || errno != E2BIG) {
		errx(EXIT_FAILURE,
		    "ioctl(VM_GET_CPUID) did not fail too-small buffer");
	}
	if (cfg.vvcc_nent != valid_entries) {
		errx(EXIT_FAILURE,
		    "ioctl(VM_GET_CPUID) did not emit entry count "
		    "(expected %u, got %u)", valid_entries, cfg.vvcc_nent);
	}

	/* Try with adequate entries buffer */
	cfg.vvcc_nent = valid_entries;
	if (ioctl(vmfd, VM_GET_CPUID, &cfg) != 0) {
		err(EXIT_FAILURE, "ioctl(VM_GET_CPUID) failed");
	}
	if (cfg.vvcc_nent != valid_entries) {
		errx(EXIT_FAILURE,
		    "ioctl(VM_GET_CPUID) did not emit entry count "
		    "(expected %u, got %u)", valid_entries, cfg.vvcc_nent);
	}
	for (uint_t i = 0; i < valid_entries; i++) {
		if (entries[i].vce_function != i) {
			errx(EXIT_FAILURE, "unexpected entry contents");
		}
	}

	/*
	 * The legacy handling is simply using the host values with certain
	 * modifications (masking, etc) applied.  The base leaf should be
	 * exactly the same as we read from the host.
	 *
	 * Since a bhyve compat header has an inline-asm cpuid wrapper, use that
	 * for now for querying the host
	 */
	struct vm_legacy_cpuid legacy  = { 0 };
	if (ioctl(vmfd, VM_LEGACY_CPUID, &legacy) != 0) {
		err(EXIT_FAILURE, "ioctl(VM_CPUID_LEGACY) failed");
	}

	uint32_t basic_cpuid[4];
	cpuid_count(0, 0, basic_cpuid);
	if (basic_cpuid[0] != legacy.vlc_eax ||
	    basic_cpuid[1] != legacy.vlc_ebx ||
	    basic_cpuid[2] != legacy.vlc_ecx ||
	    basic_cpuid[3] != legacy.vlc_edx) {
		errx(EXIT_FAILURE, "legacy cpuid mismatch");
	}

	vm_destroy(ctx);
	(void) printf("%s\tPASS\n", suite_name);
	return (EXIT_SUCCESS);
}
