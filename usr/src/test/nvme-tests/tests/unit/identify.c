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
 * NVMe Identify unit tests. This validates both fields and also whether certain
 * cases are supported.
 */

#include <stdlib.h>
#include <sys/sysmacros.h>
#include <err.h>

#include "nvme_unit.h"

static const nvme_unit_field_test_t identify_field_tests[] = { {
	.nu_desc = "valid CNS (1.0) (1)",
	.nu_fields = nvme_identify_fields,
	.nu_index = NVME_ID_REQ_F_CNS,
	.nu_data = &nvme_ctrl_base_1v0,
	.nu_value = 0x0,
	.nu_ret = NVME_FIELD_ERR_OK
}, {
	.nu_desc = "valid CNS (1.0) (2)",
	.nu_fields = nvme_identify_fields,
	.nu_index = NVME_ID_REQ_F_CNS,
	.nu_data = &nvme_ctrl_base_1v0,
	.nu_value = 0x1,
	.nu_ret = NVME_FIELD_ERR_OK
}, {
	.nu_desc = "invalid CNS (1.0) (1)",
	.nu_fields = nvme_identify_fields,
	.nu_index = NVME_ID_REQ_F_CNS,
	.nu_data = &nvme_ctrl_base_1v0,
	.nu_value = 0x2,
	.nu_ret = NVME_FIELD_ERR_BAD_VALUE
}, {
	.nu_desc = "invalid CNS (1.0) (2)",
	.nu_fields = nvme_identify_fields,
	.nu_index = NVME_ID_REQ_F_CNS,
	.nu_data = &nvme_ctrl_base_1v0,
	.nu_value = 0x55,
	.nu_ret = NVME_FIELD_ERR_BAD_VALUE
}, {
	.nu_desc = "valid CNS (1.1) (1)",
	.nu_fields = nvme_identify_fields,
	.nu_index = NVME_ID_REQ_F_CNS,
	.nu_data = &nvme_ctrl_base_1v1,
	.nu_value = 0x0,
	.nu_ret = NVME_FIELD_ERR_OK
}, {
	.nu_desc = "valid CNS (1.1) (2)",
	.nu_fields = nvme_identify_fields,
	.nu_index = NVME_ID_REQ_F_CNS,
	.nu_data = &nvme_ctrl_base_1v1,
	.nu_value = 0x1,
	.nu_ret = NVME_FIELD_ERR_OK
}, {
	.nu_desc = "valid CNS (1.1) (3)",
	.nu_fields = nvme_identify_fields,
	.nu_index = NVME_ID_REQ_F_CNS,
	.nu_data = &nvme_ctrl_base_1v1,
	.nu_value = 0x2,
	.nu_ret = NVME_FIELD_ERR_OK
},  {
	.nu_desc = "valid CNS (1.1) (3)",
	.nu_fields = nvme_identify_fields,
	.nu_index = NVME_ID_REQ_F_CNS,
	.nu_data = &nvme_ctrl_base_1v1,
	.nu_value = 0x3,
	.nu_ret = NVME_FIELD_ERR_OK
},  {
	.nu_desc = "invalid CNS (1.1) (1)",
	.nu_fields = nvme_identify_fields,
	.nu_index = NVME_ID_REQ_F_CNS,
	.nu_data = &nvme_ctrl_base_1v1,
	.nu_value = 0x4,
	.nu_ret = NVME_FIELD_ERR_BAD_VALUE
}, {
	.nu_desc = "invalid CNS (1.1) (2)",
	.nu_fields = nvme_identify_fields,
	.nu_index = NVME_ID_REQ_F_CNS,
	.nu_data = &nvme_ctrl_base_1v1,
	.nu_value = 0x55,
	.nu_ret = NVME_FIELD_ERR_BAD_VALUE
}, {
	.nu_desc = "invalid CNS (1.1) (2)",
	.nu_fields = nvme_identify_fields,
	.nu_index = NVME_ID_REQ_F_CNS,
	.nu_data = &nvme_ctrl_base_1v1,
	.nu_value = 0x121,
	.nu_ret = NVME_FIELD_ERR_BAD_VALUE
}, {
	.nu_desc = "valid CNS (1.2) (1)",
	.nu_fields = nvme_identify_fields,
	.nu_index = NVME_ID_REQ_F_CNS,
	.nu_data = &nvme_ctrl_base_1v2,
	.nu_value = 0x0,
	.nu_ret = NVME_FIELD_ERR_OK
}, {
	.nu_desc = "valid CNS (1.2) (2)",
	.nu_fields = nvme_identify_fields,
	.nu_index = NVME_ID_REQ_F_CNS,
	.nu_data = &nvme_ctrl_base_1v2,
	.nu_value = 0xff,
	.nu_ret = NVME_FIELD_ERR_OK
}, {
	.nu_desc = "valid CNS (1.2) (3)",
	.nu_fields = nvme_identify_fields,
	.nu_index = NVME_ID_REQ_F_CNS,
	.nu_data = &nvme_ctrl_base_1v2,
	.nu_value = 0x74,
	.nu_ret = NVME_FIELD_ERR_OK
},  {
	.nu_desc = "valid CNS (1.2) (3)",
	.nu_fields = nvme_identify_fields,
	.nu_index = NVME_ID_REQ_F_CNS,
	.nu_data = &nvme_ctrl_base_1v2,
	.nu_value = 0x23,
	.nu_ret = NVME_FIELD_ERR_OK
},  {
	.nu_desc = "invalid CNS (1.2) (1)",
	.nu_fields = nvme_identify_fields,
	.nu_index = NVME_ID_REQ_F_CNS,
	.nu_data = &nvme_ctrl_base_1v2,
	.nu_value = 0x100,
	.nu_ret = NVME_FIELD_ERR_BAD_VALUE
}, {
	.nu_desc = "invalid CNS (1.2) (2)",
	.nu_fields = nvme_identify_fields,
	.nu_index = NVME_ID_REQ_F_CNS,
	.nu_data = &nvme_ctrl_base_1v2,
	.nu_value = 0x3223,
	.nu_ret = NVME_FIELD_ERR_BAD_VALUE
}, {
	.nu_desc = "invalid CNS (1.2) (2)",
	.nu_fields = nvme_identify_fields,
	.nu_index = NVME_ID_REQ_F_CNS,
	.nu_data = &nvme_ctrl_base_1v2,
	.nu_value = 0x121,
	.nu_ret = NVME_FIELD_ERR_BAD_VALUE
}, {
	.nu_desc = "valid nsid (1.0/1) (1)",
	.nu_fields = nvme_identify_fields,
	.nu_index = NVME_ID_REQ_F_NSID,
	.nu_data = &nvme_ctrl_base_1v0,
	.nu_value = 0x1,
	.nu_ret = NVME_FIELD_ERR_OK
}, {
	.nu_desc = "valid nsid (1.0/1) (2)",
	.nu_fields = nvme_identify_fields,
	.nu_index = NVME_ID_REQ_F_NSID,
	.nu_data = &nvme_ctrl_base_1v0,
	.nu_value = NVME_NSID_BCAST,
	.nu_ret = NVME_FIELD_ERR_OK
}, {
	/*
	 * The namespace ID for identify commands varies in its allowed values
	 * based on the particular CNS. Some commands allow for a namespace ID
	 * that has nothing to do with the controller's valid range.
	 */
	.nu_desc = "invalid nsid (1)",
	.nu_fields = nvme_identify_fields,
	.nu_index = NVME_ID_REQ_F_NSID,
	.nu_data = &nvme_ctrl_base_1v0,
	.nu_value = UINT64_MAX,
	.nu_ret = NVME_FIELD_ERR_BAD_VALUE
}, {
	.nu_desc = "invalid nsid (2)",
	.nu_fields = nvme_identify_fields,
	.nu_index = NVME_ID_REQ_F_NSID,
	.nu_data = &nvme_ctrl_base_1v0,
	.nu_value = 0x100000000,
	.nu_ret = NVME_FIELD_ERR_BAD_VALUE
}, {
	.nu_desc = "unsupported ctrlid (1)",
	.nu_fields = nvme_identify_fields,
	.nu_index = NVME_ID_REQ_F_CTRLID,
	.nu_data = &nvme_ctrl_base_1v0,
	.nu_value = 0x0,
	.nu_ret = NVME_FIELD_ERR_UNSUP_VERSION
}, {
	.nu_desc = "unsupported ctrlid (2)",
	.nu_fields = nvme_identify_fields,
	.nu_index = NVME_ID_REQ_F_CTRLID,
	.nu_data = &nvme_ctrl_base_1v1,
	.nu_value = 0x0,
	.nu_ret = NVME_FIELD_ERR_UNSUP_VERSION
}, {
	.nu_desc = "valid ctrlid (1)",
	.nu_fields = nvme_identify_fields,
	.nu_index = NVME_ID_REQ_F_CTRLID,
	.nu_data = &nvme_ctrl_base_1v2,
	.nu_value = 0x0,
	.nu_ret = NVME_FIELD_ERR_OK
}, {
	.nu_desc = "valid ctrlid (2)",
	.nu_fields = nvme_identify_fields,
	.nu_index = NVME_ID_REQ_F_CTRLID,
	.nu_data = &nvme_ctrl_ns_1v4,
	.nu_value = 0xffff,
	.nu_ret = NVME_FIELD_ERR_OK
}, {
	.nu_desc = "valid ctrlid (3)",
	.nu_fields = nvme_identify_fields,
	.nu_index = NVME_ID_REQ_F_CTRLID,
	.nu_data = &nvme_ctrl_base_1v2,
	.nu_value = 0x4334,
	.nu_ret = NVME_FIELD_ERR_OK
}, {
	.nu_desc = "invalid ctrlid (1)",
	.nu_fields = nvme_identify_fields,
	.nu_index = NVME_ID_REQ_F_CTRLID,
	.nu_data = &nvme_ctrl_base_1v2,
	.nu_value = 0x10000,
	.nu_ret = NVME_FIELD_ERR_BAD_VALUE
}, {
	.nu_desc = "invalid ctrlid (2)",
	.nu_fields = nvme_identify_fields,
	.nu_index = NVME_ID_REQ_F_CTRLID,
	.nu_data = &nvme_ctrl_base_1v2,
	.nu_value = 0x43210,
	.nu_ret = NVME_FIELD_ERR_BAD_VALUE
}, {
	.nu_desc = "valid buffer length",
	.nu_fields = nvme_identify_fields,
	.nu_index = NVME_ID_REQ_F_BUF,
	.nu_data = &nvme_ctrl_base_1v0,
	.nu_value = 0x1000,
	.nu_ret = NVME_FIELD_ERR_OK
}, {
	.nu_desc = "invalid buffer length (1)",
	.nu_fields = nvme_identify_fields,
	.nu_index = NVME_ID_REQ_F_BUF,
	.nu_data = &nvme_ctrl_base_1v0,
	.nu_value = 0xfff,
	.nu_ret = NVME_FIELD_ERR_BAD_VALUE
}, {
	.nu_desc = "invalid buffer length (2)",
	.nu_fields = nvme_identify_fields,
	.nu_index = NVME_ID_REQ_F_BUF,
	.nu_data = &nvme_ctrl_base_1v0,
	.nu_value = 0x1001,
	.nu_ret = NVME_FIELD_ERR_BAD_VALUE
} };

typedef struct identify_impl_test {
	const char *iit_desc;
	uint32_t iit_cns;
	const nvme_valid_ctrl_data_t *iit_data;
	bool iit_impl;
} identify_impl_test_t;

static const identify_impl_test_t identify_impl_tests[] = { {
	.iit_desc = "identify namespace supported (1.0)",
	.iit_cns = NVME_IDENTIFY_NSID,
	.iit_data = &nvme_ctrl_base_1v0,
	.iit_impl = true
}, {
	.iit_desc = "identify namespace supported (1.4 No NS)",
	.iit_cns = NVME_IDENTIFY_NSID,
	.iit_data = &nvme_ctrl_nons_1v4,
	.iit_impl = true
}, {
	.iit_desc = "identify namespace supported (2.0)",
	.iit_cns = NVME_IDENTIFY_NSID,
	.iit_data = &nvme_ctrl_ns_2v0,
	.iit_impl = true
}, {
	.iit_desc = "identify controller supported (1.0)",
	.iit_cns = NVME_IDENTIFY_CTRL,
	.iit_data = &nvme_ctrl_base_1v0,
	.iit_impl = true
}, {
	.iit_desc = "identify controller supported (1.4 No NS)",
	.iit_cns = NVME_IDENTIFY_CTRL,
	.iit_data = &nvme_ctrl_nons_1v4,
	.iit_impl = true
}, {
	.iit_desc = "identify controller supported (2.0)",
	.iit_cns = NVME_IDENTIFY_CTRL,
	.iit_data = &nvme_ctrl_ns_2v0,
	.iit_impl = true
}, {
	.iit_desc = "identify controller supported (1.2 No NS)",
	.iit_cns = NVME_IDENTIFY_CTRL,
	.iit_data = &nvme_ctrl_base_1v2,
	.iit_impl = true
}, {
	.iit_desc = "active namespace list unsupported (1.0)",
	.iit_cns = NVME_IDENTIFY_NSID_LIST,
	.iit_data = &nvme_ctrl_base_1v0,
	.iit_impl = false
}, {
	.iit_desc = "active namespace list supported (1.1)",
	.iit_cns = NVME_IDENTIFY_NSID_LIST,
	.iit_data = &nvme_ctrl_base_1v1,
	.iit_impl = true
}, {
	.iit_desc = "active namespace list supported (1.3 No NS)",
	.iit_cns = NVME_IDENTIFY_NSID_LIST,
	.iit_data = &nvme_ctrl_nons_1v3,
	.iit_impl = true
}, {
	.iit_desc = "active namespace list supported (1.4)",
	.iit_cns = NVME_IDENTIFY_NSID_LIST,
	.iit_data = &nvme_ctrl_ns_1v4,
	.iit_impl = true
}, {
	.iit_desc = "namespace id desc unsupported (1.0)",
	.iit_cns = NVME_IDENTIFY_NSID_DESC,
	.iit_data = &nvme_ctrl_base_1v0,
	.iit_impl = false
}, {
	.iit_desc = "namespace id desc unsupported (1.1)",
	.iit_cns = NVME_IDENTIFY_NSID_DESC,
	.iit_data = &nvme_ctrl_base_1v1,
	.iit_impl = false
}, {
	.iit_desc = "namespace id desc supported (1.3 No NS)",
	.iit_cns = NVME_IDENTIFY_NSID_DESC,
	.iit_data = &nvme_ctrl_nons_1v3,
	.iit_impl = true
}, {
	.iit_desc = "namespace id desc supported (1.3)",
	.iit_cns = NVME_IDENTIFY_NSID_DESC,
	.iit_data = &nvme_ctrl_ns_1v3,
	.iit_impl = true
}, {
	.iit_desc = "namespace id desc supported (1.4)",
	.iit_cns = NVME_IDENTIFY_NSID_DESC,
	.iit_data = &nvme_ctrl_ns_1v4,
	.iit_impl = true
}, {
	.iit_desc = "allocated namespace list unsupported (1.0)",
	.iit_cns = NVME_IDENTIFY_NSID_ALLOC_LIST,
	.iit_data = &nvme_ctrl_base_1v0,
	.iit_impl = false
}, {
	.iit_desc = "allocated namespace list unsupported (1.2 No NS)",
	.iit_cns = NVME_IDENTIFY_NSID_ALLOC_LIST,
	.iit_data = &nvme_ctrl_base_1v2,
	.iit_impl = false
}, {
	.iit_desc = "allocated namespace list unsupported (1.4 No NS)",
	.iit_cns = NVME_IDENTIFY_NSID_ALLOC_LIST,
	.iit_data = &nvme_ctrl_nons_1v4,
	.iit_impl = false
}, {
	.iit_desc = "allocated namespace list supported (1.2)",
	.iit_cns = NVME_IDENTIFY_NSID_ALLOC_LIST,
	.iit_data = &nvme_ctrl_ns_1v2,
	.iit_impl = true
}, {
	.iit_desc = "allocated namespace list supported (1.4)",
	.iit_cns = NVME_IDENTIFY_NSID_ALLOC_LIST,
	.iit_data = &nvme_ctrl_ns_1v4,
	.iit_impl = true
}, {
	.iit_desc = "identify allocated namespace unsupported (1.0)",
	.iit_cns = NVME_IDENTIFY_NSID_ALLOC,
	.iit_data = &nvme_ctrl_base_1v0,
	.iit_impl = false
}, {
	.iit_desc = "identify allocated namespace unsupported (1.2 No NS)",
	.iit_cns = NVME_IDENTIFY_NSID_ALLOC,
	.iit_data = &nvme_ctrl_base_1v2,
	.iit_impl = false
}, {
	.iit_desc = "identify allocated namespace unsupported (1.4 No NS)",
	.iit_cns = NVME_IDENTIFY_NSID_ALLOC,
	.iit_data = &nvme_ctrl_nons_1v4,
	.iit_impl = false
}, {
	.iit_desc = "identify allocated namespace supported (1.2)",
	.iit_cns = NVME_IDENTIFY_NSID_ALLOC,
	.iit_data = &nvme_ctrl_ns_1v2,
	.iit_impl = true
}, {
	.iit_desc = "identify allocated namespace supported (1.4)",
	.iit_cns = NVME_IDENTIFY_NSID_ALLOC,
	.iit_data = &nvme_ctrl_ns_1v4,
	.iit_impl = true
}, {
	.iit_desc = "controller list by NS unsupported (1.0)",
	.iit_cns = NVME_IDENTIFY_NSID_CTRL_LIST,
	.iit_data = &nvme_ctrl_base_1v0,
	.iit_impl = false
}, {
	.iit_desc = "controller list by NS unsupported (1.2 No NS)",
	.iit_cns = NVME_IDENTIFY_NSID_CTRL_LIST,
	.iit_data = &nvme_ctrl_base_1v2,
	.iit_impl = false
}, {
	.iit_desc = "controller list by NS unsupported (1.4 No NS)",
	.iit_cns = NVME_IDENTIFY_NSID_CTRL_LIST,
	.iit_data = &nvme_ctrl_nons_1v4,
	.iit_impl = false
}, {
	.iit_desc = "controller list by NS supported (1.2)",
	.iit_cns = NVME_IDENTIFY_NSID_CTRL_LIST,
	.iit_data = &nvme_ctrl_ns_1v2,
	.iit_impl = true
}, {
	.iit_desc = "controller list by NS supported (1.4)",
	.iit_cns = NVME_IDENTIFY_NSID_CTRL_LIST,
	.iit_data = &nvme_ctrl_ns_1v4,
	.iit_impl = true
}, {
	.iit_desc = "controller list by NVM unsupported (1.0)",
	.iit_cns = NVME_IDENTIFY_CTRL_LIST,
	.iit_data = &nvme_ctrl_base_1v0,
	.iit_impl = false
}, {
	.iit_desc = "controller list by NVM unsupported (1.2 No NS)",
	.iit_cns = NVME_IDENTIFY_CTRL_LIST,
	.iit_data = &nvme_ctrl_base_1v2,
	.iit_impl = false
}, {
	.iit_desc = "controller list by NVM unsupported (1.4 No NS)",
	.iit_cns = NVME_IDENTIFY_CTRL_LIST,
	.iit_data = &nvme_ctrl_nons_1v4,
	.iit_impl = false
}, {
	.iit_desc = "controller list by NVM supported (1.2)",
	.iit_cns = NVME_IDENTIFY_CTRL_LIST,
	.iit_data = &nvme_ctrl_ns_1v2,
	.iit_impl = true
}, {
	.iit_desc = "controller list by NVM supported (1.4)",
	.iit_cns = NVME_IDENTIFY_CTRL_LIST,
	.iit_data = &nvme_ctrl_ns_1v4,
	.iit_impl = true
} };

static bool
identify_impl_test_one(const identify_impl_test_t *test)
{
	const nvme_identify_info_t *info = NULL;
	bool impl;

	for (size_t i = 0; i < nvme_identify_ncmds; i++) {
		if (nvme_identify_cmds[i].nii_csi == NVME_CSI_NVM &&
		    nvme_identify_cmds[i].nii_cns == test->iit_cns) {
			info = &nvme_identify_cmds[i];
			break;
		}
	}

	if (info == NULL) {
		errx(EXIT_FAILURE, "malformed test %s: cannot find CNS %u",
		    test->iit_desc, test->iit_cns);
	}

	impl = nvme_identify_info_supported(info, test->iit_data);
	if (impl != test->iit_impl) {
		warnx("TEST FAILED: %s: expected impl %u, found %u",
		    test->iit_desc, test->iit_impl, impl);
		return (false);
	}

	(void) printf("TEST PASSED: %s: got correct impl\n", test->iit_desc);
	return (true);
}

int
main(void)
{
	int ret = EXIT_SUCCESS;

	if (!nvme_unit_field_test(identify_field_tests,
	    ARRAY_SIZE(identify_field_tests))) {
		ret = EXIT_FAILURE;
	}

	for (size_t i = 0; i < ARRAY_SIZE(identify_impl_tests); i++) {
		if (!identify_impl_test_one(&identify_impl_tests[i])) {
			ret = EXIT_FAILURE;
		}
	}

	if (ret == EXIT_SUCCESS) {
		(void) printf("All tests passed successfully!\n");
	}

	return (ret);
}
