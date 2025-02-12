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

/*
 * Namespace Management unit tests.
 */

#include <stdlib.h>
#include <sys/sysmacros.h>
#include <err.h>

#include "nvme_unit.h"

static const nvme_unit_field_test_t ns_attach_field_tests[] = { {
	.nu_desc = "invalid selector (1)",
	.nu_fields = nvme_ns_attach_fields,
	.nu_index = NVME_NS_ATTACH_REQ_FIELD_SEL,
	.nu_data = &nvme_ctrl_ns_1v2,
	.nu_value = 0x7777,
	.nu_ret = NVME_FIELD_ERR_BAD_VALUE
}, {
	.nu_desc = "invalid selector (2)",
	.nu_fields = nvme_ns_attach_fields,
	.nu_index = NVME_NS_ATTACH_REQ_FIELD_SEL,
	.nu_data = &nvme_ctrl_ns_1v2,
	.nu_value = NVME_NS_ATTACH_CTRL_DETACH + 1,
	.nu_ret = NVME_FIELD_ERR_BAD_VALUE
}, {
	.nu_desc = "valid selector (1)",
	.nu_fields = nvme_ns_attach_fields,
	.nu_index = NVME_NS_ATTACH_REQ_FIELD_SEL,
	.nu_data = &nvme_ctrl_ns_1v2,
	.nu_value = NVME_NS_ATTACH_CTRL_DETACH,
	.nu_ret = NVME_FIELD_ERR_OK
}, {
	.nu_desc = "valid selector (2)",
	.nu_fields = nvme_ns_attach_fields,
	.nu_index = NVME_NS_ATTACH_REQ_FIELD_SEL,
	.nu_data = &nvme_ctrl_ns_1v2,
	.nu_value = NVME_NS_ATTACH_CTRL_ATTACH,
	.nu_ret = NVME_FIELD_ERR_OK
}, {
	.nu_desc = "invalid NSID (1)",
	.nu_fields = nvme_ns_attach_fields,
	.nu_index = NVME_NS_ATTACH_REQ_FIELD_NSID,
	.nu_data = &nvme_ctrl_ns_1v2,
	.nu_value = 0x0,
	.nu_ret = NVME_FIELD_ERR_BAD_VALUE
}, {
	.nu_desc = "invalid NSID (2)",
	.nu_fields = nvme_ns_attach_fields,
	.nu_index = NVME_NS_ATTACH_REQ_FIELD_NSID,
	.nu_data = &nvme_ctrl_ns_1v2,
	.nu_value = 0x7777,
	.nu_ret = NVME_FIELD_ERR_BAD_VALUE
}, {
	.nu_desc = "valid NSID (1)",
	.nu_fields = nvme_ns_attach_fields,
	.nu_index = NVME_NS_ATTACH_REQ_FIELD_NSID,
	.nu_data = &nvme_ctrl_ns_1v2,
	.nu_value = 0x1,
	.nu_ret = NVME_FIELD_ERR_OK
}, {
	.nu_desc = "valid NSID (2)",
	.nu_fields = nvme_ns_attach_fields,
	.nu_index = NVME_NS_ATTACH_REQ_FIELD_NSID,
	.nu_data = &nvme_ctrl_ns_1v2,
	.nu_value = NVME_NSID_BCAST,
	.nu_ret = NVME_FIELD_ERR_OK
} };

static const nvme_unit_field_test_t ns_delete_field_tests[] = { {
	.nu_desc = "invalid NSID (1)",
	.nu_fields = nvme_ns_delete_fields,
	.nu_index = NVME_NS_DELETE_REQ_FIELD_NSID,
	.nu_data = &nvme_ctrl_ns_1v4,
	.nu_value = 0x0,
	.nu_ret = NVME_FIELD_ERR_BAD_VALUE
}, {
	.nu_desc = "invalid NSID (2)",
	.nu_fields = nvme_ns_delete_fields,
	.nu_index = NVME_NS_DELETE_REQ_FIELD_NSID,
	.nu_data = &nvme_ctrl_ns_1v4,
	.nu_value = 0x7777,
	.nu_ret = NVME_FIELD_ERR_BAD_VALUE
}, {
	.nu_desc = "valid NSID (1)",
	.nu_fields = nvme_ns_delete_fields,
	.nu_index = NVME_NS_DELETE_REQ_FIELD_NSID,
	.nu_data = &nvme_ctrl_ns_1v4,
	.nu_value = 0x1,
	.nu_ret = NVME_FIELD_ERR_OK
}, {
	.nu_desc = "valid NSID (2)",
	.nu_fields = nvme_ns_delete_fields,
	.nu_index = NVME_NS_DELETE_REQ_FIELD_NSID,
	.nu_data = &nvme_ctrl_ns_1v4,
	.nu_value = NVME_NSID_BCAST,
	.nu_ret = NVME_FIELD_ERR_OK
} };

static const nvme_unit_field_test_t ns_create_field_tests[] = { {
	.nu_desc = "valid CSI (1)",
	.nu_fields = nvme_ns_create_fields,
	.nu_index = NVME_NS_CREATE_REQ_FIELD_CSI,
	.nu_data = &nvme_ctrl_ns_2v0,
	.nu_value = NVME_CSI_NVM,
	.nu_ret = NVME_FIELD_ERR_OK
}, {
	.nu_desc = "valid CSI (2)",
	.nu_fields = nvme_ns_create_fields,
	.nu_index = NVME_NS_CREATE_REQ_FIELD_CSI,
	.nu_data = &nvme_ctrl_ns_2v0,
	.nu_value = NVME_CSI_ZNS,
	.nu_ret = NVME_FIELD_ERR_OK
}, {
	.nu_desc = "invalid CSI (1)",
	.nu_fields = nvme_ns_create_fields,
	.nu_index = NVME_NS_CREATE_REQ_FIELD_CSI,
	.nu_data = &nvme_ctrl_ns_2v0,
	.nu_value = 0x7777,
	.nu_ret = NVME_FIELD_ERR_BAD_VALUE
}, {
	.nu_desc = "invalid CSI (2)",
	.nu_fields = nvme_ns_create_fields,
	.nu_index = NVME_NS_CREATE_REQ_FIELD_CSI,
	.nu_data = &nvme_ctrl_ns_1v2,
	.nu_value = NVME_CSI_ZNS,
	.nu_ret = NVME_FIELD_ERR_UNSUP_VERSION
}, {
	.nu_desc = "invalid CSI (3)",
	.nu_fields = nvme_ns_create_fields,
	.nu_index = NVME_NS_CREATE_REQ_FIELD_CSI,
	.nu_data = &nvme_ctrl_ns_1v4,
	.nu_value = NVME_CSI_NVM,
	.nu_ret = NVME_FIELD_ERR_UNSUP_VERSION
}, {
	.nu_desc = "invalid NSZE (1)",
	.nu_fields = nvme_ns_create_fields,
	.nu_index = NVME_NS_CREATE_REQ_FIELD_NSZE,
	.nu_data = &nvme_ctrl_ns_2v0,
	.nu_value = 0,
	.nu_ret = NVME_FIELD_ERR_BAD_VALUE
}, {
	.nu_desc = "valid NSZE (1)",
	.nu_fields = nvme_ns_create_fields,
	.nu_index = NVME_NS_CREATE_REQ_FIELD_NSZE,
	.nu_data = &nvme_ctrl_ns_2v0,
	.nu_value = 1,
	.nu_ret = NVME_FIELD_ERR_OK
}, {
	.nu_desc = "valid NSZE (2)",
	.nu_fields = nvme_ns_create_fields,
	.nu_index = NVME_NS_CREATE_REQ_FIELD_NSZE,
	.nu_data = &nvme_ctrl_ns_2v0,
	.nu_value = UINT64_MAX,
	.nu_ret = NVME_FIELD_ERR_OK
}, {
	.nu_desc = "valid NSZE (3)",
	.nu_fields = nvme_ns_create_fields,
	.nu_index = NVME_NS_CREATE_REQ_FIELD_NSZE,
	.nu_data = &nvme_ctrl_ns_2v0,
	.nu_value = 0xaabbccddeeff,
	.nu_ret = NVME_FIELD_ERR_OK
}, {
	.nu_desc = "valid NSZE (4)",
	.nu_fields = nvme_ns_create_fields,
	.nu_index = NVME_NS_CREATE_REQ_FIELD_NSZE,
	.nu_data = &nvme_ctrl_ns_2v0,
	.nu_value = 0x7777,
	.nu_ret = NVME_FIELD_ERR_OK
}, {
	.nu_desc = "invalid NCAP (1)",
	.nu_fields = nvme_ns_create_fields,
	.nu_index = NVME_NS_CREATE_REQ_FIELD_NCAP,
	.nu_data = &nvme_ctrl_ns_2v0,
	.nu_value = 0,
	.nu_ret = NVME_FIELD_ERR_BAD_VALUE
}, {
	.nu_desc = "valid NCAP (1)",
	.nu_fields = nvme_ns_create_fields,
	.nu_index = NVME_NS_CREATE_REQ_FIELD_NCAP,
	.nu_data = &nvme_ctrl_ns_2v0,
	.nu_value = 1,
	.nu_ret = NVME_FIELD_ERR_OK
}, {
	.nu_desc = "valid NCAP (2)",
	.nu_fields = nvme_ns_create_fields,
	.nu_index = NVME_NS_CREATE_REQ_FIELD_NCAP,
	.nu_data = &nvme_ctrl_ns_2v0,
	.nu_value = UINT64_MAX,
	.nu_ret = NVME_FIELD_ERR_OK
}, {
	.nu_desc = "valid NCAP (3)",
	.nu_fields = nvme_ns_create_fields,
	.nu_index = NVME_NS_CREATE_REQ_FIELD_NCAP,
	.nu_data = &nvme_ctrl_ns_2v0,
	.nu_value = 0xaabbccddeeff,
	.nu_ret = NVME_FIELD_ERR_OK
}, {
	.nu_desc = "valid NCAP (4)",
	.nu_fields = nvme_ns_create_fields,
	.nu_index = NVME_NS_CREATE_REQ_FIELD_NCAP,
	.nu_data = &nvme_ctrl_ns_2v0,
	.nu_value = 0x7777,
	.nu_ret = NVME_FIELD_ERR_OK
}, {
	.nu_desc = "invalid FLBAS (1)",
	.nu_fields = nvme_ns_create_fields,
	.nu_index = NVME_NS_CREATE_REQ_FIELD_FLBAS,
	.nu_data = &nvme_ctrl_ns_2v0,
	.nu_value = 0x2bb2,
	.nu_ret = NVME_FIELD_ERR_BAD_VALUE
}, {
	.nu_desc = "invalid FLBAS (2)",
	.nu_fields = nvme_ns_create_fields,
	.nu_index = NVME_NS_CREATE_REQ_FIELD_FLBAS,
	.nu_data = &nvme_ctrl_ns_2v0,
	.nu_value = UINT32_MAX,
	.nu_ret = NVME_FIELD_ERR_BAD_VALUE
}, {
	.nu_desc = "valid FLBAS (1)",
	.nu_fields = nvme_ns_create_fields,
	.nu_index = NVME_NS_CREATE_REQ_FIELD_FLBAS,
	.nu_data = &nvme_ctrl_ns_2v0,
	.nu_value = 0,
	.nu_ret = NVME_FIELD_ERR_OK
}, {
	.nu_desc = "valid FLBAS (2)",
	.nu_fields = nvme_ns_create_fields,
	.nu_index = NVME_NS_CREATE_REQ_FIELD_FLBAS,
	.nu_data = &nvme_ctrl_ns_2v0,
	.nu_value = 0xf,
	.nu_ret = NVME_FIELD_ERR_OK
}, {
	.nu_desc = "valid FLBAS (3)",
	.nu_fields = nvme_ns_create_fields,
	.nu_index = NVME_NS_CREATE_REQ_FIELD_FLBAS,
	.nu_data = &nvme_ctrl_ns_2v0,
	.nu_value = 0x7,
	.nu_ret = NVME_FIELD_ERR_OK
}, {
	.nu_desc = "valid NMIC (1)",
	.nu_fields = nvme_ns_create_fields,
	.nu_index = NVME_NS_CREATE_REQ_FIELD_NMIC,
	.nu_data = &nvme_ctrl_ns_1v2,
	.nu_value = 0x0,
	.nu_ret = NVME_FIELD_ERR_OK
}, {
	.nu_desc = "valid NMIC (1)",
	.nu_fields = nvme_ns_create_fields,
	.nu_index = NVME_NS_CREATE_REQ_FIELD_NMIC,
	.nu_data = &nvme_ctrl_ns_1v2,
	.nu_value = 0x1,
	.nu_ret = NVME_FIELD_ERR_OK
}, {
	.nu_desc = "valid NMIC (2)",
	.nu_fields = nvme_ns_create_fields,
	.nu_index = NVME_NS_CREATE_REQ_FIELD_NMIC,
	.nu_data = &nvme_ctrl_ns_1v2,
	.nu_value = 0x1,
	.nu_ret = NVME_FIELD_ERR_OK
}, {
	.nu_desc = "invalid NMIC (1)",
	.nu_fields = nvme_ns_create_fields,
	.nu_index = NVME_NS_CREATE_REQ_FIELD_NMIC,
	.nu_data = &nvme_ctrl_ns_1v2,
	.nu_value = 0x23,
	.nu_ret = NVME_FIELD_ERR_BAD_VALUE
}, {
	.nu_desc = "invalid NMIC (2)",
	.nu_fields = nvme_ns_create_fields,
	.nu_index = NVME_NS_CREATE_REQ_FIELD_NMIC,
	.nu_data = &nvme_ctrl_ns_1v2,
	.nu_value = 0x400,
	.nu_ret = NVME_FIELD_ERR_BAD_VALUE
}, {
	.nu_desc = "invalid NMIC (3)",
	.nu_fields = nvme_ns_create_fields,
	.nu_index = NVME_NS_CREATE_REQ_FIELD_NMIC,
	.nu_data = &nvme_ctrl_ns_1v2,
	.nu_value = UINT32_MAX,
	.nu_ret = NVME_FIELD_ERR_BAD_VALUE
}, {
	.nu_desc = "invalid NMIC (4)",
	.nu_fields = nvme_ns_create_fields,
	.nu_index = NVME_NS_CREATE_REQ_FIELD_NMIC,
	.nu_data = &nvme_ctrl_ns_1v2,
	.nu_value = 0x2,
	.nu_ret = NVME_FIELD_ERR_BAD_VALUE
} };

typedef struct {
	const char *nii_desc;
	const nvme_valid_ctrl_data_t *nii_data;
	bool nii_impl;
} nsmgmt_impl_test_t;

static const nsmgmt_impl_test_t nsmgmt_impl_tests[] = { {
	.nii_desc = "Basic 1.0 controller unsupported",
	.nii_data = &nvme_ctrl_base_1v0,
	.nii_impl = false
}, {
	.nii_desc = "Basic 1.1 controller unsupported",
	.nii_data = &nvme_ctrl_base_1v1,
	.nii_impl = false
}, {
	.nii_desc = "Basic 1.2 controller unsupported",
	.nii_data = &nvme_ctrl_base_1v2,
	.nii_impl = false
}, {
	.nii_desc = "Basic 2.0 controller unsupported",
	.nii_data = &nvme_ctrl_base_2v0,
	.nii_impl = false
}, {
	.nii_desc = "Fancy 1.2 controller supported",
	.nii_data = &nvme_ctrl_ns_1v2,
	.nii_impl = true
}, {
	.nii_desc = "Fancy 1.3 controller supported",
	.nii_data = &nvme_ctrl_ns_1v3,
	.nii_impl = true
}, {
	.nii_desc = "Fancy 1.4 controller supported",
	.nii_data = &nvme_ctrl_ns_1v4,
	.nii_impl = true
}, {
	.nii_desc = "Fancy 2.0 controller supported",
	.nii_data = &nvme_ctrl_ns_1v4,
	.nii_impl = true
}, {
	.nii_desc = "Fancy 1.4 w/o nsmgmt unsupported",
	.nii_data = &nvme_ctrl_nons_1v4,
	.nii_impl = false
} };

static bool
nsmgmt_impl_test_one(const nsmgmt_impl_test_t *test)
{
	bool impl = nvme_nsmgmt_cmds_supported(test->nii_data);

	if (impl != test->nii_impl) {
		warnx("TEST FAILED: %s: expected impl %u, found %u",
		    test->nii_desc, test->nii_impl, impl);
		return (false);
	}

	(void) printf("TEST PASSED: %s: got correct impl\n", test->nii_desc);
	return (true);
}

int
main(void)
{
	int ret = EXIT_SUCCESS;

	if (!nvme_unit_field_test(ns_attach_field_tests,
	    ARRAY_SIZE(ns_attach_field_tests))) {
		ret = EXIT_FAILURE;
	}

	if (!nvme_unit_field_test(ns_delete_field_tests,
	    ARRAY_SIZE(ns_delete_field_tests))) {
		ret = EXIT_FAILURE;
	}

	if (!nvme_unit_field_test(ns_create_field_tests,
	    ARRAY_SIZE(ns_create_field_tests))) {
		ret = EXIT_FAILURE;
	}

	for (size_t i = 0; i < ARRAY_SIZE(nsmgmt_impl_tests); i++) {
		if (!nsmgmt_impl_test_one(&nsmgmt_impl_tests[i])) {
			ret = EXIT_FAILURE;
		}
	}

	if (ret == EXIT_SUCCESS) {
		(void) printf("All tests passed successfully!\n");
	}

	return (ret);
}
