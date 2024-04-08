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
 * This file contains several synthetic controllers that we plan to use
 * throughout the rest of our various unit tests. We define rather minimal bits
 * of the identify controller data structures here. The relevant bits for these
 * tests are generally the following:
 *
 *  - Firmware Commit and Download -- id_oacs.oa_firmware (1.0)
 *  - Firmware Update Granularity -- ap_fwug (1.3)
 *  - Format NVM Support -- id_oacs.oa_format (1.0)
 *  - Volatile Write Cache Present -- id_vwc.vwc_present (1.0)
 *  - Autonomous Power State Suport -- id_apsta.ap_sup (1.1)
 *  - Namespace Count -- id_nn (1.0)
 *  - Namespace Management -- id_oacs.oa_nsmgmt (1.2)
 *  - Save/Select in Get/Set Feat -- id_oncs.on_save (1.1)
 *  - Extended Get Log Page -- id_lpa.lp_extsup (1.2)
 *  - Smart/Health Info per NS -- id_lpa.lp_smart (1.0)
 *  - Error Log Page Entries -- id_elpe (1.0) (Z)
 *  - Namespace Change Notices -- id_oaes.oaes_nsan (1.2)
 *
 * Note, we skip adding the controller version mostly because our common code
 * doesn't use it and that way we can reuse entries more often. Items that the
 * spec defines as zeros based are indicated with a trailing Z. That means that
 * software will treat the value as what's there + 1.
 */

#include <err.h>
#include <stdio.h>

#include "nvme_unit.h"

/*
 * We start with a basic controller. This has a single namespace and supports
 * the optional format and firmware commands. It doesn't have a volatile write
 * cache.
 */
static const nvme_identify_ctrl_t nvme_ctrl_base = {
	.id_oacs = {
		.oa_firmware = 1,
		.oa_format = 1
	},
	.id_nn = 1,
	.id_frmw = {
		.fw_nslot = 1
	},
	.id_elpe = 3
};

const nvme_valid_ctrl_data_t nvme_ctrl_base_1v0 = {
	.vcd_vers = &nvme_vers_1v0,
	.vcd_id = &nvme_ctrl_base
};

const nvme_valid_ctrl_data_t nvme_ctrl_base_1v1 = {
	.vcd_vers = &nvme_vers_1v1,
	.vcd_id = &nvme_ctrl_base
};

const nvme_valid_ctrl_data_t nvme_ctrl_base_1v2 = {
	.vcd_vers = &nvme_vers_1v2,
	.vcd_id = &nvme_ctrl_base
};

const nvme_valid_ctrl_data_t nvme_ctrl_base_2v0 = {
	.vcd_vers = &nvme_vers_2v0,
	.vcd_id = &nvme_ctrl_base
};


/*
 * An NVMe 1.0 version of the base controller with per-NS Health.
 */
static const nvme_identify_ctrl_t nvme_ctrl_base_health = {
	.id_oacs = {
		.oa_firmware = 1,
		.oa_format = 1
	},
	.id_lpa = {
		.lp_smart = 1
	},
	.id_nn = 1,
	.id_frmw = {
		.fw_nslot = 1
	},
	.id_elpe = 3
};

const nvme_valid_ctrl_data_t nvme_ctrl_health_1v0 = {
	.vcd_vers = &nvme_vers_1v0,
	.vcd_id = &nvme_ctrl_base_health
};

/*
 * Next, a more complex controller that has all the current optional features.
 * It has namespace support with 128 namespaces.
 */
static const nvme_identify_ctrl_t nvme_ctrl_fancy = {
	.id_oacs = {
		.oa_firmware = 1,
		.oa_format = 1,
		.oa_nsmgmt = 1
	},
	.id_oncs = {
		.on_save = 1,
	},
	.id_vwc = {
		.vwc_present = 1
	},
	.id_apsta = {
		.ap_sup = 1
	},
	.id_nn = 128,
	.id_frmw = {
		.fw_nslot = 1
	},
	.id_lpa = {
		.lp_extsup = 1,
		.lp_smart = 1,
		.lp_cmdeff = 1,
	},
	.id_oaes = {
		.oaes_nsan = 1
	}
};

const nvme_valid_ctrl_data_t nvme_ctrl_ns_1v2 = {
	.vcd_vers = &nvme_vers_1v2,
	.vcd_id = &nvme_ctrl_fancy
};

const nvme_valid_ctrl_data_t nvme_ctrl_ns_1v3 = {
	.vcd_vers = &nvme_vers_1v3,
	.vcd_id = &nvme_ctrl_fancy
};

const nvme_valid_ctrl_data_t nvme_ctrl_ns_1v4 = {
	.vcd_vers = &nvme_vers_1v4,
	.vcd_id = &nvme_ctrl_fancy
};

const nvme_valid_ctrl_data_t nvme_ctrl_ns_2v0 = {
	.vcd_vers = &nvme_vers_2v0,
	.vcd_id = &nvme_ctrl_fancy
};

/*
 * This next controller is designed to help test log size and offset properties.
 * A log offset is only allowed if the corresponding LPA is set. Similarly, the
 * length changes from 12 bits to 32 bits of dwords when that is present.
 */
static const nvme_identify_ctrl_t nvme_ctrl_nolpa = {
	.id_oacs = {
		.oa_firmware = 1,
		.oa_format = 1,
		.oa_nsmgmt = 1
	},
	.id_oncs = {
		.on_save = 1,
	},
	.id_vwc = {
		.vwc_present = 1
	},
	.id_apsta = {
		.ap_sup = 1
	},
	.id_nn = 128,
	.id_frmw = {
		.fw_nslot = 1
	},
	.id_oaes = {
		.oaes_nsan = 1
	}
};

const nvme_valid_ctrl_data_t nvme_ctrl_nolpa_1v4 = {
	.vcd_vers = &nvme_vers_1v4,
	.vcd_id = &nvme_ctrl_nolpa
};

/*
 * A variant on the fancy controller without namespace management.
 */
static const nvme_identify_ctrl_t nvme_ctrl_nons = {
	.id_oacs = {
		.oa_firmware = 1,
		.oa_format = 1,
	},
	.id_oncs = {
		.on_save = 1,
	},
	.id_vwc = {
		.vwc_present = 1
	},
	.id_apsta = {
		.ap_sup = 1
	},
	.id_nn = 1,
	.id_frmw = {
		.fw_nslot = 1
	},
	.id_lpa = {
		.lp_extsup = 1,
		.lp_smart = 1,
		.lp_cmdeff = 1
	},
	.id_oaes = {
		.oaes_nsan = 1
	}
};

const nvme_valid_ctrl_data_t nvme_ctrl_nons_1v3 = {
	.vcd_vers = &nvme_vers_1v3,
	.vcd_id = &nvme_ctrl_nons
};

const nvme_valid_ctrl_data_t nvme_ctrl_nons_1v4 = {
	.vcd_vers = &nvme_vers_1v4,
	.vcd_id = &nvme_ctrl_nons
};

const nvme_valid_ctrl_data_t nvme_ctrl_nons_2v0 = {
	.vcd_vers = &nvme_vers_2v0,
	.vcd_id = &nvme_ctrl_nons
};

/*
 * This is a controller that supports none of the optional features at all.
 */
static const nvme_identify_ctrl_t nvme_ctrl_nocmds = {
	.id_nn = 1,
	.id_frmw = {
		.fw_nslot = 1
	},
};

const nvme_valid_ctrl_data_t nvme_ctrl_nocmds_1v0 = {
	.vcd_vers = &nvme_vers_1v0,
	.vcd_id = &nvme_ctrl_nocmds
};

/*
 * Controllers with explicitly no granularity and one with 8k.
 */
static const nvme_identify_ctrl_t nvme_ctrl_nogran = {
	.id_oacs = {
		.oa_firmware = 1,
		.oa_format = 1,
	},
	.id_oncs = {
		.on_save = 1
	},
	.id_frmw = {
		.fw_nslot = 3
	},
	.id_nn = 1,
	.ap_fwug = 0xff
};

static const nvme_identify_ctrl_t nvme_ctrl_8kgran = {
	.id_oacs = {
		.oa_firmware = 1,
		.oa_format = 1,
	},
	.id_oncs = {
		.on_save = 1
	},
	.id_frmw = {
		.fw_nslot = 7
	},
	.id_nn = 1,
	.ap_fwug = 0x2
};

const nvme_valid_ctrl_data_t nvme_ctrl_nogran_1v3 = {
	.vcd_vers = &nvme_vers_1v3,
	.vcd_id = &nvme_ctrl_nogran
};

const nvme_valid_ctrl_data_t nvme_ctrl_8kgran_1v3 = {
	.vcd_vers = &nvme_vers_1v3,
	.vcd_id = &nvme_ctrl_8kgran
};

static const char *
nvme_field_error_to_str(nvme_field_error_t err)
{
	switch (err) {
	case NVME_FIELD_ERR_OK:
		return ("NVME_FIELD_ERR_OK");
	case NVME_FIELD_ERR_UNSUP_VERSION:
		return ("NVME_FIELD_ERR_UNSUP_VERSION");
	case NVME_FIELD_ERR_UNSUP_FIELD:
		return ("NVME_FIELD_ERR_UNSUP_FIELD");
	case NVME_FIELD_ERR_BAD_VALUE:
		return ("NVME_FIELD_ERR_BAD_VALUE");
	default:
		return ("unknown");
	}
}

static bool
nvme_unit_field_test_one(const nvme_unit_field_test_t *test)
{
	char buf[128];
	const nvme_field_info_t *field;
	nvme_field_error_t err;

	buf[0] = '\0';
	field = &test->nu_fields[test->nu_index];
	err = nvme_field_validate(field, test->nu_data, test->nu_value, buf,
	    sizeof (buf));

	if (err != test->nu_ret) {
		warnx("TEST FAILED: %s: found wrong return value %s (%u), "
		    "expected %s (%u)", test->nu_desc,
		    nvme_field_error_to_str(err), err,
		    nvme_field_error_to_str(test->nu_ret), test->nu_ret);
		return (false);
	}

	(void) printf("TEST PASSED: %s: got correct return value\n",
	    test->nu_desc);
	if (err != NVME_FIELD_ERR_OK && buf[0] == '\0') {
		warnx("TEST FAILED: %s: error buffer was empty", test->nu_desc);
		return (false);
	} else if (err == NVME_FIELD_ERR_OK && buf[0] != '\0') {
		warnx("TEST FAILED: %s: error buffer was not empty",
		    test->nu_desc);
		return (false);
	}

	(void) printf("TEST PASSED: %s: error buffer properly formed\n",
	    test->nu_desc);
	return (true);
}

bool
nvme_unit_field_test(const nvme_unit_field_test_t *tests, size_t ntests)
{
	bool ret = true;

	for (size_t i = 0; i < ntests; i++) {
		if (!nvme_unit_field_test_one(&tests[i])) {
			ret = false;
		}
	}

	return (ret);
}
