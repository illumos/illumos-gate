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
 * NVMe Namespace Management Commands
 */

#include <err.h>
#include <string.h>
#include <sys/sysmacros.h>

#include "nvmeadm.h"

/*
 * Attempt to parse a string with a power of 2 unit suffix into a uint64_t. We
 * stop allowing suffixes at PiB as we're trying to fit this into a uint64_t and
 * there aren't really many valid values of EiB. In the future when we have
 * devices with such large capacities, we should change this to return a
 * uint128_t style value as it's possible that with a larger block size, that
 * this will make more sense. When we do that, we should probably also figure
 * out how we want to commonize this function across the tree.
 */
static uint64_t
nvmeadm_parse_units(const char *str, const char *desc)
{
	unsigned long long l;
	char *eptr;
	const char units[] = { 'B', 'K', 'M', 'G', 'T', 'P' };

	errno = 0;
	l = strtoull(str, &eptr, 0);
	if (errno != 0) {
		err(-1, "failed to parse %s: %s", desc, str);
	}

	if (*eptr == '\0') {
		return ((uint64_t)l);
	}

	if (eptr[1] != '\0') {
		errx(-1, "failed to parse %s unit suffix: %s", desc, eptr);
	}

	for (size_t i = 0; i < ARRAY_SIZE(units); i++) {
		if (strncasecmp(eptr, &units[i], 1) != 0) {
			continue;
		}

		for (; i > 0; i--) {
			const uint64_t max = UINT64_MAX / 1024;

			if (l > max) {
				errx(-1, "%s value %s would overflow a "
				    "uint64_t", desc, str);
			}

			l *= 1024;
		}

		return ((uint64_t)l);
	}

	errx(-1, "invalid %s unit suffix: %s", desc, eptr);
}

/*
 * Today create-namespace takes a limited number of arguments. Here is how we
 * expect it to continue to change over time:
 *
 * 1) First, we have a limited number of short options that we support. If we
 * ever support long options, these should match the NVMe name for the option,
 * e.g. --nsze, --ncap, --nmic, etc.
 *
 * 2) Today we require that this operates only when the namespace is already
 * detached from a controller. If we want to change this behavior then we should
 * add something such as a [-R] flag to indicate that it should take all the
 * other steps necessary recursively.
 *
 * 3) Most other options have a default that indicates that they're unused or
 * similar. This allows us to add additional option arguments. Some of these may
 * end up with aliases for the default case, e.g. -t nvm for the default NVM
 * CSI.
 *
 * 4) We only support specifying the size of a namespace in bytes today. If we
 * want to change this we should add a flag like a -B that specifies that all
 * sizes are in units of the logical block.
 */
void
usage_create_ns(const char *c_name)
{
	(void) fprintf(stderr, "%s -f flbas | -b block-size [-c cap] "
	    "[-n nmic]\n\t  [-t type] <ctl> <size>\n\n"
	    "  Create a new namespace on the specified controller of the "
	    "requested size. The\n  size is specified in bytes and may use "
	    "any suffix such as B (bytes), K\n  (kibibytes, 2^10), M "
	    "(mibibytes, 2^20), G (gibibytes, 2^30), T (tebibytes,\n  2^40), "
	    "etc. The size must be a multiple of the selected block size. The\n"
	    "  controller may impose additional alignment constraints.\n",
	    c_name);
}

void
optparse_create_ns(nvme_process_arg_t *npa)
{
	int c;
	nvmeadm_create_ns_t *ncn;
	const char *nmic = NULL, *type = NULL, *cap = NULL;
	const char *bs = NULL, *flbas = NULL;

	if ((ncn = calloc(1, sizeof (nvmeadm_create_ns_t))) == NULL) {
		err(-1, "failed to allocate memory to track create-namespace "
		    "information");
	}

	npa->npa_cmd_arg = ncn;

	while ((c = getopt(npa->npa_argc, npa->npa_argv, ":b:c:f:n:t:")) !=
	    -1) {
		switch (c) {
		case 'b':
			bs = optarg;
			break;
		case 'c':
			cap = optarg;
			break;
		case 'f':
			flbas = optarg;
			break;
		case 'n':
			nmic = optarg;
			break;
		case 't':
			type = optarg;
			break;
		case '?':
			errx(-1, "unknown option: -%c", optopt);
		case ':':
			errx(-1, "option -%c requires an argument", optopt);
		}
	}

	if (flbas != NULL && bs != NULL) {
		errx(-1, "only one of -b and -f may be specified");
	}

	if (flbas == NULL && bs == NULL) {
		errx(-1, "at least one of -b and -f must be specified");
	}

	if (flbas != NULL) {
		const char *err;
		ncn->ncn_use_flbas = B_TRUE;
		ncn->ncn_lba = strtonumx(flbas, 0, NVME_MAX_LBAF - 1, &err, 0);
		if (err != NULL) {
			errx(-1, "failed to parse formatted LBA index: %s is "
			    "%s, valid values are between 0 and %u",
			    flbas, err, NVME_MAX_LBAF - 1);
		}
	}

	if (bs != NULL) {
		ncn->ncn_use_flbas = B_FALSE;
		ncn->ncn_lba = nvmeadm_parse_units(bs, "block-size");
	}

	if (cap != NULL) {
		ncn->ncn_cap = nvmeadm_parse_units(cap, "block-size");
	} else {
		ncn->ncn_cap = UINT64_MAX;
	}

	if (type != NULL) {
		if (strcasecmp(type, "nvm") == 0) {
			ncn->ncn_csi = NVME_CSI_NVM;
		} else if (strcasecmp(type, "kv") == 0) {
			ncn->ncn_csi = NVME_CSI_KV;
		} else if (strcasecmp(type, "zns") == 0) {
			ncn->ncn_csi = NVME_CSI_ZNS;
		} else {
			errx(-1, "unknown CSI type string: '%s'; valid values "
			    "are 'nvm', 'kv', and 'zns'", type);
		}
	} else {
		ncn->ncn_csi = NVME_CSI_NVM;
	}

	if (nmic != NULL) {
		if (strcasecmp(nmic, "none") == 0) {
			ncn->ncn_nmic = NVME_NS_NMIC_T_NONE;
		} else if (strcasecmp(nmic, "shared") == 0) {
			ncn->ncn_nmic = NVME_NS_NMIC_T_SHARED;
		} else {
			errx(-1, "unknown nmic string: '%s'; valid values are "
			    "'none' and 'shared'", nmic);
		}
	} else {
		ncn->ncn_nmic = NVME_NS_NMIC_T_NONE;
	}

	if (npa->npa_argc - optind > 2) {
		errx(-1, "%s passed extraneous arguments starting with %s",
		    npa->npa_cmd->c_name, npa->npa_argv[optind + 2]);
	} else if (npa->npa_argc - optind != 2) {
		errx(-1, "missing required size parameter");
	}

	ncn->ncn_size = nvmeadm_parse_units(npa->npa_argv[optind + 1],
	    "namespace size");
	if (cap == NULL) {
		ncn->ncn_cap = ncn->ncn_size;
	}
}

static const nvme_nvm_lba_fmt_t *
do_create_ns_find_lba(const nvme_process_arg_t *npa,
    const nvmeadm_create_ns_t *ncn)
{
	const uint32_t nfmts = nvme_ctrl_info_nformats(npa->npa_ctrl_info);
	const nvme_nvm_lba_fmt_t *best = NULL;
	uint32_t best_rp = UINT32_MAX;

	for (size_t i = 0; i < nfmts; i++) {
		const nvme_nvm_lba_fmt_t *fmt;
		uint32_t rp;

		if (!nvme_ctrl_info_format(npa->npa_ctrl_info, i, &fmt)) {
			continue;
		}

		if (nvme_nvm_lba_fmt_meta_size(fmt) != 0)
			continue;

		if (nvme_nvm_lba_fmt_data_size(fmt) != ncn->ncn_lba)
			continue;

		rp = nvme_nvm_lba_fmt_rel_perf(fmt);
		if (rp < best_rp) {
			best_rp = rp;
			best = fmt;
		}
	}

	if (best == NULL) {
		errx(-1, "failed to find an LBA format with %u byte block size",
		    ncn->ncn_lba);
	}

	return (best);
}

int
do_create_ns(const nvme_process_arg_t *npa)
{
	const nvmeadm_create_ns_t *ncn = npa->npa_cmd_arg;
	nvme_ns_create_req_t *req;
	const nvme_nvm_lba_fmt_t *lba;
	uint32_t nsid, flbas, ds;
	uint64_t size;

	if (npa->npa_ns != NULL) {
		errx(-1, "%s cannot be used on namespaces",
		    npa->npa_cmd->c_name);
	}

	/*
	 * This should have been checked above.
	 */
	if (npa->npa_argc > 1) {
		errx(-1, "%s passed extraneous arguments starting with %s",
		    npa->npa_cmd->c_name, npa->npa_argv[1]);
	}

	/*
	 * If we were given a block size rather than the formatted LBA size, go
	 * deal with converting that now.
	 */
	if (!ncn->ncn_use_flbas) {
		lba = do_create_ns_find_lba(npa, ncn);
	} else {
		if (!nvme_ctrl_info_format(npa->npa_ctrl_info, ncn->ncn_lba,
		    &lba)) {
			nvmeadm_fatal(npa, "failed to look up LBA format index "
			    "%u", ncn->ncn_lba);
		}
	}

	if (!nvme_ns_create_req_init_by_csi(npa->npa_ctrl, ncn->ncn_csi,
	    &req)) {
		nvmeadm_fatal(npa, "failed to initialize namespace create "
		    "request");
	}

	ds = nvme_nvm_lba_fmt_data_size(lba);
	flbas = nvme_nvm_lba_fmt_id(lba);
	if (!nvme_ns_create_req_set_flbas(req, flbas)) {
		nvmeadm_fatal(npa, "failed to set namespace create request "
		    "formatted LBA index to %u", flbas);
	}

	if (ncn->ncn_size % ds != 0) {
		nvmeadm_fatal(npa, "requested namespace size 0x%lx is not a "
		    "multiple of the requested LBA block size (0x%x)",
		    ncn->ncn_size, ds);
	}
	size = ncn->ncn_size / ds;
	if (!nvme_ns_create_req_set_nsze(req, size)) {
		nvmeadm_fatal(npa, "failed to set namespace create request "
		    "namespace size to 0x%lx", size);
	}

	if (ncn->ncn_cap % ds != 0) {
		nvmeadm_fatal(npa, "requested namespace capacity 0x%lx is not "
		    "a multiple of the requested LBA block size (0x%x)",
		    ncn->ncn_cap, ds);
	}
	size = ncn->ncn_cap/ ds;
	if (!nvme_ns_create_req_set_ncap(req, size)) {
		nvmeadm_fatal(npa, "failed to set namespace create request "
		    "namespace capacity to 0x%lx", size);
	}

	if (!nvme_ns_create_req_set_nmic(req, ncn->ncn_nmic)) {
		nvmeadm_fatal(npa, "failed to set namespace multipath I/O and "
		    "sharing capabilities to 0x%x", ncn->ncn_nmic);
	}

	if (!nvme_ns_create_req_exec(req)) {
		nvmeadm_fatal(npa, "failed to execute namespace create "
		    "request");
	}

	if (!nvme_ns_create_req_get_nsid(req, &nsid)) {
		nvmeadm_fatal(npa, "Failed to retrieve the new namespace ID");
	}

	nvme_ns_create_req_fini(req);

	(void) printf("created namespace %s/%u\n", npa->npa_ctrl_name, nsid);
	return (EXIT_SUCCESS);
}

void
usage_delete_ns(const char *c_name)
{
	(void) fprintf(stderr, "%s <ctl>/<ns>\n\n"
	    "  Delete the specified namespace. It must be first detached from "
	    "all\n  controllers. Controllers can be detached from a namespace "
	    "with the\n  detach-namespace sub-command.\n", c_name);
}

int
do_delete_ns(const nvme_process_arg_t *npa)
{
	nvme_ns_delete_req_t *req;

	if (npa->npa_ns == NULL) {
		errx(-1, "%s cannot be used on controllers",
		    npa->npa_cmd->c_name);
	}

	if (npa->npa_argc > 0) {
		errx(-1, "%s passed extraneous arguments starting with %s",
		    npa->npa_cmd->c_name, npa->npa_argv[0]);
	}

	if (!nvme_ns_delete_req_init(npa->npa_ctrl, &req)) {
		nvmeadm_fatal(npa, "failed to initialize namespace delete "
		    "request");
	}

	const uint32_t nsid = nvme_ns_info_nsid(npa->npa_ns_info);
	if (!nvme_ns_delete_req_set_nsid(req, nsid)) {
		nvmeadm_fatal(npa, "failed to set namespace delete request "
		    "namespace ID to 0x%x", nsid);
	}

	if (!nvme_ns_delete_req_exec(req)) {
		nvmeadm_fatal(npa, "failed to execute namespace delete "
		    "request");
	}

	nvme_ns_delete_req_fini(req);
	return (EXIT_SUCCESS);
}

/*
 * Currently both attach namespace and detach namespace only will perform an
 * attach or detach of the namespace from the current controller in the system.
 * In the future, we should probably support an argument to provide an explicit
 * controller list either in the form of IDs or device names, probably with -c
 * or -C.
 */
void
usage_attach_ns(const char *c_name)
{
	(void) fprintf(stderr, "%s <ctl>/<ns>\n\n"
	    "  Attach the specified namespace to the current controller.\n",
	    c_name);
}

void
usage_detach_ns(const char *c_name)
{
	(void) fprintf(stderr, "%s <ctl>/<ns>\n\n"
	    "  Detach the specified namespace from its current controller. The "
	    "namespace\n  must have its blkdev instances detached with the "
	    "detach sub-command.\n", c_name);
}

static int
do_attach_ns_common(const nvme_process_arg_t *npa, uint32_t sel)
{
	const char *desc = sel == NVME_NS_ATTACH_CTRL_ATTACH ? "attach" :
	    "detach";
	nvme_ns_attach_req_t *req;

	if (npa->npa_ns == NULL) {
		errx(-1, "%s cannot be used on controllers",
		    npa->npa_cmd->c_name);
	}

	if (npa->npa_argc > 0) {
		errx(-1, "%s passed extraneous arguments starting with %s",
		    npa->npa_cmd->c_name, npa->npa_argv[0]);
	}

	if (!nvme_ns_attach_req_init_by_sel(npa->npa_ctrl, sel, &req)) {
		nvmeadm_fatal(npa, "failed to initialize controller "
		    "%s request for %s", desc, npa->npa_name);
	}

	const uint32_t nsid = nvme_ns_info_nsid(npa->npa_ns_info);
	if (!nvme_ns_attach_req_set_nsid(req, nsid)) {
		nvmeadm_fatal(npa, "failed to set namespace to %s to %u",
		    desc, nsid);
	}

	if (!nvme_ns_attach_req_set_ctrlid_self(req)) {
		nvmeadm_fatal(npa, "failed to set controller to %s for %s",
		    desc, npa->npa_name);
	}

	if (!nvme_ns_attach_req_exec(req)) {
		nvmeadm_fatal(npa, "failed to execute controller %s request",
		    desc);
	}

	nvme_ns_attach_req_fini(req);
	return (EXIT_SUCCESS);
}

int
do_attach_ns(const nvme_process_arg_t *npa)
{
	return (do_attach_ns_common(npa, NVME_NS_ATTACH_CTRL_ATTACH));
}

int
do_detach_ns(const nvme_process_arg_t *npa)
{
	return (do_attach_ns_common(npa, NVME_NS_ATTACH_CTRL_DETACH));
}
