
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

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <libgen.h>
#include <strings.h>
#include <libnvpair.h>
#include <sys/sysmacros.h>

#include <sys/vmm.h>
#include <sys/viona_io.h>
#include <vmmapi.h>

#include "common.h"
#include "in_guest.h"
#include "viona_suite.h"

#define	PARAM_BUF_SZ	VIONA_MAX_PARAM_NVLIST_SZ

const char *expected_params[] = {
	"tx_copy_data",
	"tx_header_pad"
};

static void
print_errors(vioc_set_params_t *vsp)
{
	if (vsp->vsp_error_sz == 0) {
		return;
	}

	nvlist_t *nverr = NULL;
	if (nvlist_unpack(vsp->vsp_error, vsp->vsp_error_sz, &nverr, 0) != 0) {
		return;
	}

	(void) fprintf(stderr, "vioc_set_params errors:\n");
	nvlist_print(stderr, nverr);

	nvlist_free(nverr);
}

static void
test_set_param_errors(int vfd)
{
	vioc_set_params_t set_param = {
		.vsp_param_sz = VIONA_MAX_PARAM_NVLIST_SZ + 1,
	};

	if (ioctl(vfd, VNA_IOC_SET_PARAMS, &set_param) == 0) {
		test_fail_msg("SET_PARAMS should fail for too-big size");
	}

	char bogus_nvlist[256];
	arc4random_buf(bogus_nvlist, sizeof (bogus_nvlist));
	set_param.vsp_param = bogus_nvlist;
	set_param.vsp_param_sz = sizeof (bogus_nvlist);
	if (ioctl(vfd, VNA_IOC_SET_PARAMS, &set_param) == 0) {
		test_fail_msg("SET_PARAMS should fail invalid nvlist");
	}

	/*
	 * Assemble parameters which should be rejected:
	 * - One of the wrong nvpair data type
	 * - A tx_header_pad outside the valid range
	 * - A wholly unrecognized field
	 */
	nvlist_t *nvl = fnvlist_alloc();
	fnvlist_add_uint32(nvl, "tx_copy_data", 0);
	fnvlist_add_uint16(nvl, "tx_header_pad", UINT16_MAX);
	fnvlist_add_boolean_value(nvl, "widdly_scuds", false);

	uint8_t errbuf[512];
	set_param.vsp_param = fnvlist_pack(nvl, &set_param.vsp_param_sz);
	set_param.vsp_error = errbuf;
	set_param.vsp_error_sz = sizeof (errbuf);
	if (ioctl(vfd, VNA_IOC_SET_PARAMS, &set_param) == 0) {
		test_fail_msg("SET_PARAMS should fail on invalid params");
	}
	nvlist_free(nvl);
	free(set_param.vsp_param);

	nvlist_t *error_nvl =
	    fnvlist_unpack(set_param.vsp_error, set_param.vsp_error_sz);
	const char *err_params[] = {
		"tx_copy_data",
		"tx_header_pad",
		"widdly_scuds"
	};
	for (uint_t i = 0; i < ARRAY_SIZE(err_params); i++) {
		const char *name = err_params[i];

		if (!nvlist_exists(error_nvl, name)) {
			print_errors(&set_param);
			test_fail_msg("missing SET_PARAMS error for field %s\n",
			    name);
		}
	}
	nvlist_free(error_nvl);
}

int
main(int argc, char *argv[])
{
	const char *suite_name = basename(argv[0]);
	struct vmctx *ctx;

	ctx = test_initialize_plain(suite_name);
	if (ctx == NULL) {
		test_fail_errno(errno, "could not open test VM");
	}

	int vfd = open_viona();
	if (vfd < 0) {
		test_fail_errno(errno, "could not open viona device");
	}

	/*
	 * Getting default parameters should work before the viona device is
	 * associated with a link and vmm
	 */

	void *param_buf = malloc(PARAM_BUF_SZ);
	if (param_buf == NULL) {
		test_fail_errno(errno, "could not allocate param buffer");
	}
	vioc_get_params_t get_param = {
		.vgp_param = param_buf,
		.vgp_param_sz = PARAM_BUF_SZ,
	};
	if (ioctl(vfd, VNA_IOC_DEFAULT_PARAMS, &get_param) != 0) {
		test_fail_errno(errno, "ioctl(VNA_IOC_DEFAULT_PARAMS) failed");
	}

	nvlist_t *params = NULL;
	if (nvlist_unpack(param_buf, get_param.vgp_param_sz, &params, 0) != 0) {
		test_fail_errno(errno, "nvlist_unpack() failed");
	}

	/* Are all the presented default parameters ones we expect? */
	nvpair_t *nvp = NULL;
	while ((nvp = nvlist_next_nvpair(params, nvp)) != NULL) {
		bool found = false;
		const char *pname = nvpair_name(nvp);

		for (uint_t i = 0; i < ARRAY_SIZE(expected_params); i++) {
			if (strcmp(pname, expected_params[i]) == 0) {
				found = true;
				break;
			}
		}
		if (!found) {
			test_fail_msg("unexpected parameter %s", pname);
		}
	}

	datalink_id_t dlid;
	dladm_status_t dls = query_dlid(VIONA_TEST_IFACE_NAME, &dlid);
	if (dls != DLADM_STATUS_OK) {
		char errbuf[DLADM_STRSIZE];

		test_fail_msg("could not query datalink id for %s: %s",
		    VIONA_TEST_IFACE_NAME, dladm_status2str(dls, errbuf));
	}

	vioc_create_t create_ioc = {
		.c_linkid = dlid,
		.c_vmfd = vm_get_device_fd(ctx),
	};
	if (ioctl(vfd, VNA_IOC_CREATE, &create_ioc) != 0) {
		test_fail_errno(errno, "failed to create link on viona device");
	}

	/*
	 * Based on the parameters we got from the defaults, build a new set of
	 * parameters to set on the link which are slighly different.
	 */
	nvlist_t *new_params = fnvlist_alloc();
	fnvlist_add_boolean_value(new_params, "tx_copy_data",
	    !fnvlist_lookup_boolean_value(params, "tx_copy_data"));
	fnvlist_add_uint16(new_params, "tx_header_pad",
	    fnvlist_lookup_uint16(params, "tx_header_pad") + 32);

	uint8_t errbuf[256];
	vioc_set_params_t set_param = {
		.vsp_error = errbuf,
		.vsp_error_sz = sizeof (errbuf)
	};
	if (nvlist_pack(new_params, (char **)&set_param.vsp_param,
	    &set_param.vsp_param_sz, NV_ENCODE_NATIVE, 0) != 0) {
		test_fail_errno(errno, "nvlist_pack() failed");
	}
	nvlist_free(params);
	nvlist_free(new_params);

	if (ioctl(vfd, VNA_IOC_SET_PARAMS, &set_param) != 0) {
		print_errors(&set_param);
		test_fail_errno(errno, "ioctl(VNA_IOC_SET_PARAMS) failed");
	}
	free(set_param.vsp_param);

	test_set_param_errors(vfd);

	test_pass();
	return (EXIT_SUCCESS);
}
