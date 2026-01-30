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
 * Copyright 2026 Oxide Computer Company
 */

/*
 * NVMe Vendor Unique Command related functions.
 */

#include <getopt.h>
#include <err.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/debug.h>
#include <sys/sysmacros.h>

#include "nvmeadm.h"

/*
 * We choose 60 seconds as a reasonable enough default VUC timeout. This is a
 * fairly arbitrary selection but should be good enough for most non-formatting
 * related commands.
 */
#define	NVMEADM_VUC_TO_DEFAULT	60

/*
 * We need some upper bound on how much data we'll read in and zero. The kernel
 * may change its maximum that it'll allow. It'd probably be smart of us to ask
 * what the max is to help reduce hardcoding. For now we use 2x its current
 * value 32 MiB. We make the minimum 4 bytes because we need 4 byte alignment.
 */
#define	NVMEADM_VUC_LEN_MAX	(32 * 1024 * 1024)
#define	NVMEADM_VUC_LEN_ALIGN	4

typedef struct nvmeadm_vuc {
	uint8_t	vuc_opc;
	uint32_t vuc_nsid;
	uint32_t vuc_cdw12;
	uint32_t vuc_cdw13;
	uint32_t vuc_cdw14;
	uint32_t vuc_cdw15;
	uint32_t vuc_timeout;
	uint32_t vuc_dlen;
	const char *vuc_input;
	const char *vuc_output;
	nvme_lock_level_t vuc_lock;
	nvme_vuc_disc_impact_t vuc_impact;
} nvmeadm_vuc_t;

nvme_vuc_disc_t *
nvmeadm_vuc_init(const nvme_process_arg_t *npa, const char *name)
{
	nvme_vuc_disc_t *vuc;
	nvme_vuc_disc_lock_t lock;

	if (!nvme_vuc_discover_by_name(npa->npa_ctrl, name, 0, &vuc)) {
		nvmeadm_fatal(npa, "%s does not support operation %s: device "
		    "does not support vendor unique command %s", npa->npa_name,
		    npa->npa_cmd->c_name, name);
	}

	lock = nvme_vuc_disc_lock(vuc);
	switch (lock) {
	case NVME_VUC_DISC_LOCK_NONE:
		break;
	case NVME_VUC_DISC_LOCK_READ:
		nvmeadm_excl(npa, NVME_LOCK_L_READ);
		break;
	case NVME_VUC_DISC_LOCK_WRITE:
		nvmeadm_excl(npa, NVME_LOCK_L_WRITE);
		break;
	}

	return (vuc);
}

void
nvmeadm_vuc_fini(const nvme_process_arg_t *npa, nvme_vuc_disc_t *vuc)
{
	if (nvme_vuc_disc_lock(vuc) != NVME_VUC_DISC_LOCK_NONE) {
		if (npa->npa_ns != NULL) {
			nvme_ns_unlock(npa->npa_ns);
		} else if (npa->npa_ctrl != NULL) {
			nvme_ctrl_unlock(npa->npa_ctrl);
		}
	}

	nvme_vuc_disc_free(vuc);
}

void
usage_vendor_cmd(const char *c_name)
{
	(void) fprintf(stderr, "%s -O opcode [-n nsid] [--cdw12 cdw12] "
	    "[--cdw13 cdw13]\n\t  [--cdw14 cdw14] [--cdw15 cdw15] "
	    "[-l length [-i file | -o file]]\n\t  [-L lock] [-I impact] "
	    "[-t timeout] <ctl>[/<ns>]\n\n", c_name);
	(void) fprintf(stderr, "  Run a vendor-specific command against a "
	    "device\n");
}

/*
 * Most folks reasonably expect short options for all long options. We do have
 * these here for the various --cdw arguments, but there are no good short
 * options here depending on what we want to do. These are different from the
 * Linux nvme-cli, so we would have preferred not to have them at all, but the
 * mappings in that tool are not very usable either, e.g. --cdw12 is 6. When
 * we're doing documentation: usage statements, manuals, overviews, prefer the
 * --cdw form.
 */
static const struct option vendor_cmd_lopts[] = {
	{ "opcode",	required_argument,	NULL, 'O' },
	{ "nsid",	required_argument,	NULL, 'n' },
	{ "cdw12",	required_argument,	NULL, '2' },
	{ "cdw13",	required_argument,	NULL, '3' },
	{ "cdw14",	required_argument,	NULL, '4' },
	{ "cdw15",	required_argument,	NULL, '5' },
	{ "length",	required_argument,	NULL, 'l' },
	{ "input",	required_argument,	NULL, 'i' },
	{ "output",	required_argument,	NULL, 'o' },
	{ "lock",	required_argument,	NULL, 'L' },
	{ "impact",	required_argument,	NULL, 'I' },
	{ "timeout",	required_argument,	NULL, 't' },
	{ NULL, 0, NULL, 0 }
};

static long long
optparse_vendor_cmd_ui(const char *raw, const char *field, uint64_t min,
    uint64_t max)
{
	const char *errstr;
	long long l;

	l = strtonumx(raw, min, max, &errstr, 0);
	if (errstr != NULL) {
		errx(-1, "failed to parse %s: value %s is %s: valid values "
		    "are in the range [0x%" PRIx64 ", 0x%" PRIx64 "]", field,
		    raw, errstr, min, max);
	}

	return (l);
}

void
optparse_vendor_cmd(nvme_process_arg_t *npa)
{
	int c;
	nvmeadm_vuc_t *vuc;

	if ((vuc = calloc(1, sizeof (nvmeadm_vuc_t))) == NULL) {
		err(-1, "failed to allocate memory for option tracking");
	}
	vuc->vuc_timeout = NVMEADM_VUC_TO_DEFAULT;

	/*
	 * Normally we can reset optind to 0 to make sure that we can account
	 * for the fact that we've modified our arguments. Unfortunately
	 * getopt_long() tries to detect this as a case where some tools have
	 * used it as a way to ask for option processing to be reset and thus
	 * skip our first argument. As such we cheat a bit with the arguments we
	 * pass.
	 */
	while ((c = getopt_long(npa->npa_argc + 1, npa->npa_argv - 1,
	    ":O:n:l:i:I:o:L:t:2:3:4:5:", vendor_cmd_lopts, NULL)) != -1) {
		char *last;

		switch (c) {
		case 'O':
			vuc->vuc_opc = (uint8_t)optparse_vendor_cmd_ui(optarg,
			    "opcode", NVME_PASSTHRU_MIN_ADMIN_OPC,
			    NVME_PASSTHRU_MAX_ADMIN_OPC);
			break;
		case 'n':
			/*
			 * We don't use NVME_NSID_MIN here because we want to
			 * allow the invalid nsid 0 to be specified for this
			 * field.
			 */
			vuc->vuc_nsid = (uint8_t)optparse_vendor_cmd_ui(optarg,
			    "opcode", 0, NVME_NSID_BCAST);
			break;
		case 'l':
			vuc->vuc_dlen = (uint32_t)optparse_vendor_cmd_ui(optarg,
			    "length", 0, NVMEADM_VUC_LEN_MAX);
			if (vuc->vuc_dlen % NVMEADM_VUC_LEN_ALIGN != 0) {
				errx(-1, "invalid data length %u: must be a "
				    "multiple of 4 bytes", vuc->vuc_dlen);
			}
			break;
		case 'i':
			vuc->vuc_input = optarg;
			break;
		case 'o':
			vuc->vuc_output = optarg;
			break;
		case 'L':
			if (strcmp(optarg, "read") == 0) {
				vuc->vuc_lock = NVME_LOCK_L_READ;
			} else if (strcmp(optarg, "write") == 0) {
				vuc->vuc_lock = NVME_LOCK_L_WRITE;
			} else {
				errx(-1, "invalid lock value %s: valid values "
				    "are 'read' or 'write'", optarg);
			}
			break;
		case 'I':
			for (char *s = strtok_r(optarg, ",", &last); s != NULL;
			    s = strtok_r(NULL, ",", &last)) {
				if (strcmp(s, "data") == 0) {
					vuc->vuc_impact |=
					    NVME_VUC_DISC_IMPACT_DATA;
				} else if (strcmp(s, "namespace") == 0) {
					vuc->vuc_impact |=
					    NVME_VUC_DISC_IMPACT_NS;
				} else {
					errx(-1, "invalid impact string: %s",
					    s);
				}
			}
			break;
		case 't':
			/* This will be further constrained by libnvme */
			vuc->vuc_timeout = (uint32_t)optparse_vendor_cmd_ui(
			    optarg, "timeout", 1, UINT32_MAX);
			break;
		case '2':
			vuc->vuc_cdw12 = (uint32_t)optparse_vendor_cmd_ui(
			    optarg, "cdw12", 0, UINT32_MAX);
			break;
		case '3':
			vuc->vuc_cdw13 = (uint32_t)optparse_vendor_cmd_ui(
			    optarg, "cdw13", 0, UINT32_MAX);
			break;
		case '4':
			vuc->vuc_cdw14 = (uint32_t)optparse_vendor_cmd_ui(
			    optarg, "cdw14", 0, UINT32_MAX);
			break;
		case '5':
			vuc->vuc_cdw15 = (uint32_t)optparse_vendor_cmd_ui(
			    optarg, "cdw15", 0, UINT32_MAX);
			break;
		case '?':
			errx(-1, "unknown option: -%c", optopt);
		case ':':
			errx(-1, "option -%c requires an argument", optopt);
			break;
		}
	}

	/*
	 * Undo our optind lies.
	 */
	optind--;

	if (vuc->vuc_opc == 0) {
		errx(-1, "missing required command opcode");
	}

	if (vuc->vuc_input != NULL && vuc->vuc_output != NULL) {
		errx(-1, "cannot specify both an input file (-i) and an output "
		    "file (-o)");
	}

	if ((vuc->vuc_input != NULL || vuc->vuc_output != NULL) &&
	    vuc->vuc_dlen == 0) {
		errx(-1, "asked to transfer data (-%c) but missing required "
		    "data length (-l)", vuc->vuc_input != NULL ? 'i' : 'o');
	}

	if (vuc->vuc_input == NULL && vuc->vuc_output == NULL &&
	    vuc->vuc_dlen != 0) {
		errx(-1, "%u bytes of data transfer requested (-l), but no "
		    "input (-i) or output (-o) specified", vuc->vuc_dlen);
	}

	/*
	 * Only check if the namespace id matches if the user specified a
	 * namespace.
	 */
	if (npa->npa_ns != NULL) {
		uint32_t nsid = nvme_ns_info_nsid(npa->npa_ns_info);
		if (vuc->vuc_nsid != 0 && vuc->vuc_nsid != nsid) {
			errx(-1, "Requested namespace id (-n) %u does not "
			    "match the nsid of %s (%u): either remove the "
			    "-n argument or specify just a controller",
			    vuc->vuc_nsid, npa->npa_name, nsid);
		}

		vuc->vuc_nsid = nsid;
	}

	npa->npa_cmd_arg = vuc;
}

int
do_vendor_cmd(const nvme_process_arg_t *npa)
{
	const nvmeadm_vuc_t *vuc = npa->npa_cmd_arg;
	uint8_t *buf = NULL;
	nvme_vuc_req_t *req;
	int ofd = -1;

	/*
	 * Verify we can get a request. This is effectively our is this
	 * supported check.
	 */
	if (!nvme_vuc_req_init(npa->npa_ctrl, &req)) {
		nvmeadm_fatal(npa, "failed to initialize vendor unique "
		    "request");
	}

	if (vuc->vuc_dlen > 0) {
		if ((buf = calloc(sizeof (uint8_t), vuc->vuc_dlen)) == NULL) {
			nvmeadm_fatal(npa, "failed to allocate 0x%x byte "
			    "request data buffer", vuc->vuc_dlen);
		}

		/*
		 * If we have an input file, then we want to read data from it
		 * until we either hit EOF or we read sufficient bytes from it
		 * to fill our buffer. Anything we don't will be zero filled,
		 * which was already taken care of by using calloc.
		 */
		if (vuc->vuc_input != NULL) {
			int ifd = open(vuc->vuc_input, O_RDONLY);
			if (ifd < 0) {
				err(EXIT_FAILURE, "failed to open input file "
				    "%s", vuc->vuc_input);
			}

			size_t rem = vuc->vuc_dlen, off = 0;
			while (rem > 0) {
				size_t toread = MIN(16 * 1024, rem);
				ssize_t ret = read(ifd, buf + off, toread);
				if (ret < 0) {
					nvmeadm_fatal(npa, "failed to read %zu "
					    "bytes at offset %zu from %s",
					    toread, off, vuc->vuc_input);
				} else if (ret == 0) {
					break;
				}

				rem -= (size_t)ret;
				off += (size_t)ret;
			}

			VERIFY0(close(ifd));
		} else if (vuc->vuc_output != NULL) {
			ofd = open(vuc->vuc_output, O_RDWR | O_TRUNC | O_CREAT,
			    0644);
			if (ofd < 0) {
				err(-1, "failed to open output file %s",
				    vuc->vuc_output);
			}
		}
	}

	if (!nvme_vuc_req_set_opcode(req, vuc->vuc_opc) ||
	    !nvme_vuc_req_set_nsid(req, vuc->vuc_nsid) ||
	    !nvme_vuc_req_set_timeout(req, vuc->vuc_timeout) ||
	    !nvme_vuc_req_set_cdw12(req, vuc->vuc_cdw12) ||
	    !nvme_vuc_req_set_cdw13(req, vuc->vuc_cdw13) ||
	    !nvme_vuc_req_set_cdw14(req, vuc->vuc_cdw14) ||
	    !nvme_vuc_req_set_cdw15(req, vuc->vuc_cdw15) ||
	    !nvme_vuc_req_set_impact(req, vuc->vuc_impact)) {
		nvmeadm_fatal(npa, "failed to set request fields");
	}

	if (vuc->vuc_input != NULL) {
		if (!nvme_vuc_req_set_input(req, buf, vuc->vuc_dlen)) {
			nvmeadm_fatal(npa, "failed to set input buffer");
		}
	} else if (vuc->vuc_output != NULL) {
		if (!nvme_vuc_req_set_output(req, buf, vuc->vuc_dlen)) {
			nvmeadm_fatal(npa, "failed to set output buffer");
		}
	}

	if (vuc->vuc_lock != 0) {
		nvmeadm_excl(npa, vuc->vuc_lock);
	}

	if (!nvme_vuc_req_exec(req)) {
		nvmeadm_fatal(npa, "failed to execute request");
	}

	uint32_t cdw0;
	if (nvme_vuc_req_get_cdw0(req, &cdw0)) {
		(void) printf("Request cdw0: 0x%x\n", cdw0);
	}

	/*
	 * Remove the lock manually. npa->npa_excl isn't set, so we need to
	 * manually take care of this.
	 */
	if (vuc->vuc_lock != 0) {
		if (npa->npa_ns != NULL) {
			nvme_ns_unlock(npa->npa_ns);
		} else {
			nvme_ctrl_unlock(npa->npa_ctrl);
		}
	}

	if (vuc->vuc_output != NULL) {
		size_t rem = vuc->vuc_dlen, off = 0;
		while (rem > 0) {
			size_t towrite = MIN(16 * 1024, rem);
			ssize_t ret = write(ofd, buf + off, towrite);

			if (ret < 0) {
				nvmeadm_fatal(npa, "failed to write %zu bytes "
				    "of output data at offset %zu to %s",
				    towrite, off, vuc->vuc_output);
			}

			rem -= towrite;
			off += towrite;
		}
	}

	if (ofd >= 0) {
		VERIFY0(close(ofd));
	}
	nvme_vuc_req_fini(req);
	free(buf);
	return (0);
}
