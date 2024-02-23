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

/*
 * Test a few different bits of the status code string generation and see that
 * we get something expected. Note, we try to avoid using the existing constants
 * that we have for the sct / sc when testing the corresponding entries so
 * someone can more so copy and paste entries from the spec and be less tempted
 * to copy data from the implementation.
 */

#include <stdbool.h>
#include <stdlib.h>
#include <err.h>
#include <stdio.h>
#include <strings.h>
#include <sys/sysmacros.h>
#include <libnvme.h>

typedef struct {
	uint32_t st_code;
	const char *st_str;
} sct_test_t;

static const sct_test_t sct_tests[] = { {
	.st_code = 0,
	.st_str = "generic command status",
}, {
	.st_code = 7,
	.st_str = "vendor specific"
}, {
	.st_code = 0x23,
	.st_str = "unknown status type"
}, {
	.st_code = 0x169,
	.st_str = "unknown status type"
} };

typedef struct {
	nvme_csi_t sc_csi;
	uint32_t sc_sct;
	uint32_t sc_sc;
	const char *sc_str;
} sc_test_t;

static const sc_test_t sc_tests[] = { {
	.sc_csi = NVME_CSI_NVM,
	.sc_sct = NVME_CQE_SCT_GENERIC,
	.sc_sc = 0x0,
	.sc_str = "successful completion"
}, {
	.sc_csi = NVME_CSI_NVM,
	.sc_sct = NVME_CQE_SCT_GENERIC,
	.sc_sc = 0x2,
	.sc_str = "invalid field in command"
}, {
	.sc_csi = NVME_CSI_NVM,
	.sc_sct = NVME_CQE_SCT_GENERIC,
	.sc_sc = 0xb,
	.sc_str = "invalid namespace or format"
}, {
	/*
	 * This is a purposefully bad CSI, but the CSI shouldn't matter for this
	 * code.
	 */
	.sc_csi = 0xff,
	.sc_sct = NVME_CQE_SCT_GENERIC,
	.sc_sc = 0xb,
	.sc_str = "invalid namespace or format"
}, {
	.sc_csi = NVME_CSI_NVM,
	.sc_sct = NVME_CQE_SCT_GENERIC,
	.sc_sc = 0x7f,
	.sc_str = "unknown status code",
}, {
	.sc_csi = NVME_CSI_NVM,
	.sc_sct = NVME_CQE_SCT_GENERIC,
	.sc_sc = 0x80,
	.sc_str = "lba out of range"
}, {
	.sc_csi = NVME_CSI_NVM,
	.sc_sct = NVME_CQE_SCT_GENERIC,
	.sc_sc = 0x82,
	.sc_str = "namespace not ready"
}, {
	.sc_csi = NVME_CSI_NVM,
	.sc_sct = NVME_CQE_SCT_GENERIC,
	.sc_sc = 0xbf,
	.sc_str = "unknown command set specific general status code"

}, {
	.sc_csi = NVME_CSI_NVM,
	.sc_sct = NVME_CQE_SCT_GENERIC,
	.sc_sc = 0xff,
	.sc_str = "generic vendor specific status code"
}, {
	.sc_csi = NVME_CSI_NVM,
	.sc_sct = NVME_CQE_SCT_SPECIFIC,
	.sc_sc = 0x6,
	.sc_str = "invalid firmware slot"
}, {
	.sc_csi = NVME_CSI_NVM,
	.sc_sct = NVME_CQE_SCT_SPECIFIC,
	.sc_sc = 0x9,
	.sc_str = "invalid log page"
}, {
	.sc_csi = NVME_CSI_NVM,
	.sc_sct = NVME_CQE_SCT_SPECIFIC,
	.sc_sc = 0x6f,
	.sc_str = "unknown generic command status code"
}, {
	.sc_csi = NVME_CSI_NVM,
	.sc_sct = NVME_CQE_SCT_SPECIFIC,
	.sc_sc = 0x80,
	.sc_str = "conflicting attributes"
}, {
	.sc_csi = NVME_CSI_NVM,
	.sc_sct = NVME_CQE_SCT_SPECIFIC,
	.sc_sc = 0xbf,
	.sc_str = "unknown command specific, I/O command set specific status "
	    "code",
}, {
	.sc_csi = NVME_CSI_NVM,
	.sc_sct = NVME_CQE_SCT_SPECIFIC,
	.sc_sc = 0xff,
	.sc_str = "command specific vendor specific status code"
}, {
	.sc_csi = NVME_CSI_NVM,
	.sc_sct = NVME_CQE_SCT_INTEGRITY,
	.sc_sc = 0x80,
	.sc_str = "write fault"
}, {
	.sc_csi = 0x23,
	.sc_sct = NVME_CQE_SCT_INTEGRITY,
	.sc_sc = 0x80,
	.sc_str = "write fault"
}, {
	.sc_csi = NVME_CSI_NVM,
	.sc_sct = NVME_CQE_SCT_INTEGRITY,
	.sc_sc = 0x0,
	.sc_str = "unknown media and data integrity status code"
}, {
	.sc_csi = NVME_CSI_NVM,
	.sc_sct = NVME_CQE_SCT_INTEGRITY,
	.sc_sc = 0xff,
	.sc_str = "vendor specific media and data integrity status code"
} };

static bool
sct_test_one(const sct_test_t *test)
{
	const char *str = nvme_scttostr(NULL, test->st_code);
	if (strcmp(str, test->st_str) != 0) {
		warnx("TEST FAILED: sct 0x%x was translated to string %s, "
		    "not %s", test->st_code, str, test->st_str);
		return (false);
	}

	(void) printf("TEST PASSED: sct 0x%x successfully translated\n",
	    test->st_code);
	return (true);
}

static bool
sc_test_one(const sc_test_t *test)
{
	const char *str = nvme_sctostr(NULL, test->sc_csi, test->sc_sct,
	    test->sc_sc);
	if (strcmp(str, test->sc_str) != 0) {
		warnx("TEST FAILED: csi/sct/sc 0x%x/0x%x/0x%x was translated "
		    "to string %s, not %s", test->sc_csi, test->sc_sct,
		    test->sc_sc, str, test->sc_str);
		return (false);
	}

	(void) printf("TEST PASSED: csi/sct/sc 0x%x/0x%x/0x%x successfully "
	    "translated\n", test->sc_csi, test->sc_sct, test->sc_sc);

	return (true);
}

int
main(void)
{
	int ret = EXIT_SUCCESS;

	for (size_t i = 0; i < ARRAY_SIZE(sct_tests); i++) {
		if (!sct_test_one(&sct_tests[i])) {
			ret = EXIT_FAILURE;
		}
	}

	for (size_t i = 0; i < ARRAY_SIZE(sc_tests); i++) {
		if (!sc_test_one(&sc_tests[i])) {
			ret = EXIT_FAILURE;
		}
	}

	return (ret);
}
