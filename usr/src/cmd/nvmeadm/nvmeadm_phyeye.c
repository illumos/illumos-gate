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
 * Logic to gather the physical interface receiver eye opening measurement and
 * slice and dice it.
 */

#include <err.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/debug.h>
#include <sys/sysmacros.h>
#include <sys/mman.h>
#include <sys/bitext.h>
#include <ofmt.h>

#include "nvmeadm.h"

/*
 * Pick a reasonable buffer size that we think will fit within a device's
 * maximum payload. For now we use 64 KiB somewhat arbitrarily.
 */
#define	PHYEYE_BUFSIZE	(64 * 1024)

/*
 * Maximum values for PCIe lanes and eyes. We use 16 lanes for PCIe as while
 * most devices are only x4, that's the largest sized slot that's typically
 * implemented.
 *
 * For the maximum number of eyes there is only 1 for NRZ and today 3 for PAM4.
 * So we pick the PAM4 default.
 */
#define	PHYEYE_MAX_LANE	16
#define	PHYEYE_MAX_EYE	3

typedef struct {
	const char *pm_output;
	nvme_eom_lsp_mqual_t pm_qual;
} phyeye_measure_t;

typedef enum {
	PHYEYE_REPORT_M_ASCII,
	PHYEYE_REPORT_M_OED
} phyeye_report_mode_t;

typedef struct {
	nvme_process_arg_t *pr_npa;
	const char *pr_input;
	phyeye_report_mode_t pr_mode;
	uint8_t pr_lane;
	uint8_t pr_eye;
	bool pr_print;
} phyeye_report_t;

static const nvmeadm_field_bit_t phyeye_eom_odp_bits[] = { {
	.nfb_lowbit = 0, .nfb_hibit = 0,
	.nfb_short = "pefp",
	.nfb_desc = "Printable Eye Field Present",
	.nfb_type = NVMEADM_FT_STRMAP,
	.nfb_strs = { "not present", "present" }
}, {
	.nfb_lowbit = 1, .nfb_hibit = 1,
	.nfb_short = "edfp",
	.nfb_desc = "Eye Data Field Present",
	.nfb_type = NVMEADM_FT_STRMAP,
	.nfb_strs = { "not present", "present" }
} };

static const nvmeadm_field_bit_t phyeye_eom_lspfc_bits[] = { {
	.nfb_lowbit = 0, .nfb_hibit = 6,
	.nfb_short = "lspfv",
	.nfb_desc = "Log Specific Parameter Field Value",
	.nfb_type = NVMEADM_FT_HEX
} };

static const nvmeadm_field_bit_t phyeye_eom_linfo_bits[] = { {
	.nfb_lowbit = 0, .nfb_hibit = 3,
	.nfb_short = "mls",
	.nfb_desc = "Measurement Link Speed",
	.nfb_type = NVMEADM_FT_HEX
} };

#define	PHYEYE_F_EOM(f)	.nf_off = offsetof(nvme_eom_hdr_t, eom_##f), \
	.nf_len = sizeof (((nvme_eom_hdr_t *)NULL)->eom_##f), \
	.nf_short = #f

static const nvmeadm_field_t phyeye_eom_fields[] = { {
	PHYEYE_F_EOM(lid),
	.nf_desc = "Log Identifier",
	.nf_type = NVMEADM_FT_HEX
}, {
	PHYEYE_F_EOM(eomip),
	.nf_desc = "EOM In Progress",
	.nf_type = NVMEADM_FT_STRMAP,
	.nf_strs = { "no measurement", "in progress", "completed" },
}, {
	PHYEYE_F_EOM(hsize),
	.nf_desc = "Header Size",
	.nf_type = NVMEADM_FT_HEX
}, {
	PHYEYE_F_EOM(rsz),
	.nf_desc = "Result Size",
	.nf_type = NVMEADM_FT_HEX
}, {
	PHYEYE_F_EOM(edgn),
	.nf_desc = "EOM Data Generation Number",
	.nf_type = NVMEADM_FT_HEX
}, {
	PHYEYE_F_EOM(lrev),
	.nf_desc = "Log Revision",
	.nf_type = NVMEADM_FT_HEX
}, {
	PHYEYE_F_EOM(odp),
	.nf_desc = "Optional Data Present",
	NVMEADM_F_BITS(phyeye_eom_odp_bits)
}, {
	PHYEYE_F_EOM(lns),
	.nf_desc = "Lanes",
	.nf_type = NVMEADM_FT_HEX
}, {
	PHYEYE_F_EOM(epl),
	.nf_desc = "Eyes Per Lane",
	.nf_type = NVMEADM_FT_HEX
}, {
	PHYEYE_F_EOM(lspfc),
	.nf_desc = "Log Specific Parameter Field Copy",
	NVMEADM_F_BITS(phyeye_eom_lspfc_bits)
}, {
	PHYEYE_F_EOM(linfo),
	.nf_desc = "Link Information",
	NVMEADM_F_BITS(phyeye_eom_linfo_bits)
}, {
	PHYEYE_F_EOM(lsic),
	.nf_desc = "Log Specific Identifier Copy",
	.nf_type = NVMEADM_FT_HEX
}, {
	PHYEYE_F_EOM(ds),
	.nf_desc = "Descriptor Size",
	.nf_type = NVMEADM_FT_HEX
}, {
	PHYEYE_F_EOM(nd),
	.nf_desc = "Number of Descriptors",
	.nf_type = NVMEADM_FT_HEX
}, {
	PHYEYE_F_EOM(maxtb),
	.nf_desc = "Maximum Top Bottom",
	.nf_type = NVMEADM_FT_HEX
}, {
	PHYEYE_F_EOM(maxlr),
	.nf_desc = "Maximum Left Right",
	.nf_type = NVMEADM_FT_HEX
}, {
	PHYEYE_F_EOM(etgood),
	.nf_desc = "Estimated Time for Good Quality",
	.nf_type = NVMEADM_FT_HEX
}, {
	PHYEYE_F_EOM(etbetter),
	.nf_desc = "Estimated Time for Better Quality",
	.nf_type = NVMEADM_FT_HEX
}, {
	PHYEYE_F_EOM(etbest),
	.nf_desc = "Estimated Time for Best Quality",
	.nf_type = NVMEADM_FT_HEX
} };

static const nvmeadm_field_bit_t phyeye_eld_mstat_bits[] = { {
	.nfb_lowbit = 0, .nfb_hibit = 0,
	.nfb_short = "mscs",
	.nfb_desc = "Measurement Successful",
	.nfb_type = NVMEADM_FT_STRMAP,
	.nfb_strs = { "no", "yes" }
} };

#define	PHYEYE_F_ELD(f)	.nf_off = offsetof(nvme_eom_lane_desc_t, eld_##f), \
	.nf_len = sizeof (((nvme_eom_lane_desc_t *)NULL)->eld_##f), \
	.nf_short = #f

static const nvmeadm_field_t phyeye_elm_fields[] = { {
	PHYEYE_F_ELD(mstat),
	.nf_desc = "Measurement Status",
	NVMEADM_F_BITS(phyeye_eld_mstat_bits)
}, {
	PHYEYE_F_ELD(ln),
	.nf_desc = "Lane",
	.nf_type = NVMEADM_FT_HEX
}, {
	PHYEYE_F_ELD(eye),
	.nf_desc = "Eye",
	.nf_type = NVMEADM_FT_HEX
}, {
	PHYEYE_F_ELD(top),
	.nf_desc = "Top",
	.nf_type = NVMEADM_FT_HEX
}, {
	PHYEYE_F_ELD(btm),
	.nf_desc = "Bottom",
	.nf_type = NVMEADM_FT_HEX
}, {
	PHYEYE_F_ELD(lft),
	.nf_desc = "Left",
	.nf_type = NVMEADM_FT_HEX
}, {
	PHYEYE_F_ELD(rgt),
	.nf_desc = "Right",
	.nf_type = NVMEADM_FT_HEX
}, {
	PHYEYE_F_ELD(nrows),
	.nf_desc = "Number of Rows",
	.nf_type = NVMEADM_FT_HEX
}, {
	PHYEYE_F_ELD(ncols),
	.nf_desc = "Number of Columns",
	.nf_type = NVMEADM_FT_HEX
}, {
	/*
	 * The size of this field changed between revision 2 and 3 from 2 bytes
	 * to 4 bytes.
	 */
	.nf_off = offsetof(nvme_eom_lane_desc_t, eld_edlen),
	.nf_len = sizeof (uint16_t),
	.nf_short = "edlen",
	.nf_desc = "Eye Data Length",
	.nf_type = NVMEADM_FT_HEX,
	.nf_rev = 2
}, {
	PHYEYE_F_ELD(edlen),
	.nf_desc = "Eye Data Length",
	.nf_type = NVMEADM_FT_HEX,
	.nf_rev = 3
} };

void
usage_measure_phyeye_cmd(const char *c_name)
{
	(void) fprintf(stderr, "%s -o output [-Q good | better | best] "
	    "<ctl>\n\n", c_name);
	(void) fprintf(stderr, "  Gather physical eye opening measurements "
	    "from the named controller and save\n  them to the specified "
	    "output file. The best quality measurement is taken by\n  "
	    "default. No other administrative operations can be executed "
	    "during the eye\n  measurement.\n");
}

void
optparse_measure_phyeye_cmd(nvme_process_arg_t *npa)
{
	int c;
	phyeye_measure_t *phy;

	if ((phy = calloc(1, sizeof (phyeye_measure_t))) == NULL) {
		err(-1, "failed to allocate memory for option tracking");
	}

	/*
	 * Default to best quality if not otherwise requested.
	 */
	phy->pm_qual = NVME_EOM_LSP_MQUAL_BEST;

	while ((c = getopt(npa->npa_argc, npa->npa_argv, ":o:Q:")) != -1) {
		switch (c) {
		case 'o':
			phy->pm_output = optarg;
			break;
		case 'Q':
			if (strcasecmp(optarg, "good") == 0) {
				phy->pm_qual = NVME_EOM_LSP_MQUAL_GOOD;
			} else if (strcasecmp(optarg, "better") == 0) {
				phy->pm_qual = NVME_EOM_LSP_MQUAL_BETTER;

			} else if (strcasecmp(optarg, "best") == 0) {
				phy->pm_qual = NVME_EOM_LSP_MQUAL_BEST;

			} else {
				errx(-1, "invalid quality value %s: valid "
				    "values are 'good', 'better', or 'best'",
				    optarg);
			}
			break;
		case '?':
			errx(-1, "unknown option: -%c", optopt);
		case ':':
			errx(-1, "option -%c requires an argument", optopt);
		}
	}

	if (phy->pm_output == NULL) {
		errx(-1, "missing required output file (-o)");
	}

	npa->npa_cmd_arg = phy;
}

/*
 * Poll the log page until it is done and ready. We always do the initial wait.
 * The specification says that this may take longer due to activity on the
 * device. We will wait up to 3x the amount of time that was indicated for this
 * measurement. We will begin using a 1 second delay after this point.
 *
 * This explicitly uses a volatile pointer for 'eom' due to the fact that the
 * log page execution will update the data that it points to.
 */
static void
nvmeadm_phyeye_wait(const nvme_process_arg_t *npa, nvme_log_req_t *req,
    volatile nvme_eom_hdr_t *eom, uint16_t wait, const char *qual)
{
	hrtime_t start = gethrtime();
	hrtime_t end = start + wait * NANOSEC;
	hrtime_t now = start;
	hrtime_t max = start + wait * 3 * NANOSEC;
	const bool tty = isatty(STDOUT_FILENO);

	(void) printf("device indicates a minimum %u second wait for %s "
	    "quality phyeye measurement\n", wait, qual);
	while (now < end) {
		if (tty) {
			(void) printf("\r%u/%u seconds elapsed",
			    (now - start) / NANOSEC, wait);
			(void) fflush(stdout);
		}
		(void) sleep(1);
		now = gethrtime();
	}

	if (tty) {
		(void) printf("\r%u/%u seconds elapsed\n", wait, wait);
	}

	if (!nvme_log_req_exec(req)) {
		nvmeadm_fatal(npa, "failed to retrieve phyeye measurement log "
		    "request");
	}

	if (eom->eom_eomip == NVME_EOM_DONE) {
		return;
	}

	(void) printf("Measurement incomplete, proceeding to check over an "
	    "additional %u seconds\n", max - wait);
	uint32_t extra = 0;
	now = gethrtime();
	hrtime_t phase2 = now;
	while (now < max) {
		(void) sleep(1);

		if (!nvme_log_req_exec(req)) {
			nvmeadm_fatal(npa, "failed to issue start phyeye "
			    "measurement log request");
		}

		now = gethrtime();

		if (eom->eom_eomip == NVME_EOM_DONE) {
			return;
		}

		extra++;
		if (tty) {
			(void) printf("\rMeasurement still not available after "
			    "%u attempts (%u seconds)", extra, (now - phase2) /
			    NANOSEC);
			(void) fflush(stdout);
		}
	}

	errx(-1, "timed out waiting for the phyeye measurement to finish after "
	    "%u seconds: final measurement state: %u", wait * 3,
	    eom->eom_eomip);
}

static void
nvmeadm_phyeye_read(const nvme_process_arg_t *npa, nvme_log_req_t *req,
    void *buf, size_t len, uint64_t off)
{
	if (!nvme_log_req_set_output(req, buf, len)) {
		nvmeadm_fatal(npa, "failed to set output buffer");
	}

	if (!nvme_log_req_set_offset(req, off)) {
		nvmeadm_fatal(npa, "failed to set offset to 0x%lx", off);
	}

	if (!nvme_log_req_exec(req)) {
		nvmeadm_fatal(npa, "failed to read %zu bytes at 0x%lx", len,
		    off);
	}
}

static void
nvmeadm_phyeye_write(int fd, const void *buf, size_t len, off_t off)
{
	size_t loff = 0;

	while (len > 0) {
		ssize_t ret = pwrite(fd, buf + loff, len, off + loff);
		if (ret < 0) {
			err(EXIT_FAILURE, "failed to write to physical eye "
			    "measurement output file");
		}

		loff += (size_t)ret;
		len -= (size_t)ret;
	}
}

/*
 * Perform a physical eye measurement. This consists of a few different steps to
 * execute it successfully:
 *
 * 1. First determine that we can actually issue this command.
 * 2. Open the output file early. While this may mean we truncate something,
 *    given that this command may take some time, that's better than finding out
 *    after you've already done all the work.
 * 3. We issue the first phy eye get log page command with the request to begin
 *    a new measurement at the requested quality. We need to set the LSP, LSI,
 *    and output buffer for this.
 * 4. We wait for the requested number of seconds before beginning to query for
 *    result data.
 * 5. Once a second, we issue commands trying to see if it's done.
 * 6. Once it's finally done, then we'll go ahead and actually finish getting
 *    the log page data and write it out to disk.
 * 7. When we're done with all the data, confirm that the generation is still
 *    the same as when we started.
 */
int
do_measure_phyeye_cmd(const nvme_process_arg_t *npa)
{
	int fd = -1;
	nvme_log_req_t *req = NULL;
	nvme_log_disc_t *disc = NULL;
	nvme_eom_lsp_t lsp;
	const phyeye_measure_t *phy = npa->npa_cmd_arg;
	void *buf = NULL;
	uint64_t min_len;
	nvme_log_size_kind_t lkind;

	if (!nvme_log_req_init_by_name(npa->npa_ctrl, "phyeye", 0, &disc,
	    &req)) {
		nvmeadm_fatal(npa, "failed to initialize phyeye log request");
	}

	if ((fd = open(phy->pm_output, O_RDWR | O_CREAT | O_TRUNC, 0644)) < 0) {
		err(-1, "failed to open output file %s", phy->pm_output);
	}

	if ((buf = malloc(PHYEYE_BUFSIZE)) == NULL) {
		err(-1, "failed to allocate internal phy data buffer");
	}

	if (!nvme_log_req_set_lsi(req, npa->npa_idctl->id_cntlid)) {
		nvmeadm_fatal(npa, "failed to set lsi for phyeye measurement");
	}

	(void) memset(&lsp, 0, sizeof (lsp));
	lsp.nel_mqual = phy->pm_qual;
	lsp.nel_act = NVME_EOM_LSP_START;

	if (!nvme_log_req_set_lsp(req, lsp.r)) {
		nvmeadm_fatal(npa, "failed to set lsp for phyeye measurement");
	}

	lkind = nvme_log_disc_size(disc, &min_len);
	VERIFY3U(lkind, ==, NVME_LOG_SIZE_K_VAR);
	VERIFY3U(min_len, >=, sizeof (nvme_eom_hdr_t));

	if (!nvme_log_req_set_output(req, buf, min_len)) {
		nvmeadm_fatal(npa, "failed to set initial output buffer and "
		    "length");
	}

	if (!nvme_log_req_exec(req)) {
		nvmeadm_fatal(npa, "failed to issue start phyeye measurement "
		    "log request");
	}

	/*
	 * Update the request for the rest of this to always be a read request
	 * of the existing measurement.
	 */
	lsp.nel_act = NVME_EOM_LSP_READ;
	if (!nvme_log_req_set_lsp(req, lsp.r)) {
		nvmeadm_fatal(npa, "failed to update lsp for phyeye "
		    "measurement");
	}

	/*
	 * The use of volatile here is probably a little weird. But this is
	 * aliasing memory that the log req exec will constantly be updating.
	 */
	const volatile nvme_eom_hdr_t *eom = buf;
	if (eom->eom_eomip != NVME_EOM_IN_PROGRESS) {
		warnx("EOM in progress in header is not in-progress, found %u: "
		    "waiting the appropriate time regardless", eom->eom_eomip);
	}

	const uint8_t eom_gen = eom->eom_edgn;

	uint16_t wait;
	const char *desc;
	if (phy->pm_qual == NVME_EOM_LSP_MQUAL_GOOD) {
		wait = eom->eom_etgood;
		desc = "good";
	} else if (phy->pm_qual == NVME_EOM_LSP_MQUAL_BETTER) {
		wait = eom->eom_etbetter;
		desc = "better";
	} else {
		wait = eom->eom_etbest;
		desc = "best";
	}
	nvmeadm_phyeye_wait(npa, req, buf, wait, desc);

	/*
	 * Go ahead and calculate the final size. At this point we'll issue
	 * requests that adjust the overall offset until we read everything and
	 * write that out.
	 */
	uint64_t act_len, off = 0;
	if (!nvme_log_disc_calc_size(disc, &act_len, buf, min_len)) {
		errx(-1, "failed to determine full phyeye log length");
	}

	while (off < act_len) {
		size_t to_read = MIN(act_len - off, PHYEYE_BUFSIZE);
		nvmeadm_phyeye_read(npa, req, buf, to_read, off);
		nvmeadm_phyeye_write(fd, buf, to_read, off);
		off += to_read;
	}

	/*
	 * Now that we're done, get the initial header's worth of data again and
	 * verify its generation to make sure nothing has changed on us.
	 */
	nvmeadm_phyeye_read(npa, req, buf, sizeof (nvme_eom_hdr_t), 0);
	if (eom->eom_edgn != eom_gen) {
		(void) unlink(phy->pm_output);
		errx(-1, "PHY eye measurement generation unexpectedly changed: "
		    "was 0x%x, now is 0x%x: aborting", eom_gen, eom->eom_edgn);
	}

	/*
	 * Note we don't actually clear the data here and basically are willing
	 * to leave this in the controller at this point.
	 */
	(void) printf("phyeye successfully written to %s\n", phy->pm_output);

	free(buf);
	if (fd >= 0) {
		VERIFY0(close(fd));
	}
	nvme_log_disc_free(disc);
	nvme_log_req_fini(req);
	return (0);
}

void
usage_report_phyeye_cmd(const char *c_name)
{
	(void) fprintf(stderr, "%s -f file [-l lane] [-e eye] [-m mode] "
	    "<ctl>\n\n", c_name);
	(void) fprintf(stderr, "  Report information about a physical eye "
	    "measurement. Eye measurements can be\n  taken with \"nvmeadm "
	    "measure-phyeye\".\n");
}

void
optparse_report_phyeye_cmd(nvme_process_arg_t *npa)
{
	int c;
	phyeye_report_t *phy;

	if ((phy = calloc(1, sizeof (phyeye_report_t))) == NULL) {
		err(-1, "failed to allocate memory for option tracking");
	}

	phy->pr_npa = npa;
	phy->pr_mode = PHYEYE_REPORT_M_ASCII;
	phy->pr_lane = UINT8_MAX;
	phy->pr_eye = UINT8_MAX;

	while ((c = getopt(npa->npa_argc, npa->npa_argv, ":e:f:l:m:")) != -1) {
		const char *errstr;

		switch (c) {
		case 'e':
			phy->pr_eye = strtonumx(optarg, 0, PHYEYE_MAX_EYE,
			    &errstr, 0);
			if (errstr != NULL) {
				errx(-1, "failed to parse eye: value %s is "
				    "%s: valid values are in the range [%u, "
				    "%u]", optarg, errstr, 0, PHYEYE_MAX_EYE);
			}
			break;
		case 'f':
			phy->pr_input = optarg;
			break;
		case 'l':
			phy->pr_lane = strtonumx(optarg, 0, PHYEYE_MAX_LANE,
			    &errstr, 0);
			if (errstr != NULL) {
				errx(-1, "failed to parse lane: value %s is "
				    "%s: valid values are in the range [%u, "
				    "%u]", optarg, errstr, 0, PHYEYE_MAX_LANE);
			}
			break;
		case 'm':
			if (strcasecmp(optarg, "print-eye") == 0) {
				phy->pr_mode = PHYEYE_REPORT_M_ASCII;
			} else if (strcasecmp(optarg, "eye-data") == 0) {
				phy->pr_mode = PHYEYE_REPORT_M_OED;
			} else {
				errx(-1, "invalid mode value: %s: valid values "
				    "are 'print-eye' or 'eye-data'", optarg);
			}
			break;
		case '?':
			errx(-1, "unknown option: -%c", optopt);
		case ':':
			errx(-1, "option -%c requires an argument", optopt);

		}
	}

	if (phy->pr_input == NULL) {
		errx(-1, "missing required input file to process (-f)");
	}

	npa->npa_cmd_arg = phy;
}

/*
 * Normalize the optional eye data length. This is a uint32_t in revision 3
 * logs, but a uint16_t in revision 2 logs.
 */
static uint32_t
phyeye_eol_oed_len(const nvme_eom_hdr_t *hdr, const nvme_eom_lane_desc_t *desc)
{
	uint16_t u16;

	if (hdr->eom_lrev >= 3) {
		return (desc->eld_edlen);
	}

	(void) memcpy(&u16, &desc->eld_edlen, sizeof (uint16_t));
	return (u16);
}

typedef void (*phyeye_lane_iter_cb_f)(uint8_t, const nvme_eom_hdr_t *,
    const nvme_eom_lane_desc_t *, void *);

static bool
phyeye_lane_iter(const nvme_eom_hdr_t *hdr, off_t max,
    void *arg, phyeye_lane_iter_cb_f func, uint8_t lane, uint8_t eye)
{
	off_t cur_off = sizeof (nvme_eom_hdr_t);
	bool ret = true;

	for (uint16_t i = 0; i < hdr->eom_nd; i++) {
		const nvme_eom_lane_desc_t *desc = NULL;
		size_t dlen = sizeof (nvme_eom_lane_desc_t);

		if (cur_off + hdr->eom_ds > max) {
			errx(-1, "failed to iterate EOM Lane descriptors: "
			    "descriptor %u starts at offset 0x%lx, but its "
			    "size (0x%x) would exceed the maximum file length "
			    "of 0x%lx", i, cur_off, hdr->eom_ds, max);
		}

		desc = (const nvme_eom_lane_desc_t *)((uintptr_t)hdr + cur_off);

		if (hdr->eom_odp.odp_pefp != 0) {
			if (desc->eld_nrows == 0 || desc->eld_ncols == 0) {
				errx(-1, "printable eye feature present but "
				    "both NROWS (0x%x) and NCOLS (0x%x) are "
				    "not non-zero", desc->eld_nrows,
				    desc->eld_ncols);
			}

			dlen += desc->eld_nrows * desc->eld_ncols;
		} else if (desc->eld_nrows != 0 || desc->eld_ncols != 0) {
			errx(-1, "printable eye feature not present but both "
			    "NROWS (0x%x) and NCOLS (0x%x) are not zero",
			    desc->eld_nrows, desc->eld_ncols);
		}

		const uint32_t oed_len = phyeye_eol_oed_len(hdr, desc);
		if (hdr->eom_odp.odp_edfp != 0) {
			if (oed_len == 0) {
				errx(-1, "optional eye data feature present, "
				    "but eye data has a zero-length");
			}

			dlen += oed_len;
		} else if (oed_len != 0) {
			errx(-1, "optional eye data feature not present, but "
			    "eye data has a non-zero length (0x%x)", oed_len);
		}

		if (dlen > hdr->eom_ds) {
			errx(-1, "failed to iterate EOM Lane descriptors: "
			    "descriptor %u starts at offset 0x%lx, has a "
			    "calculated size (0x%zx) that exceeds the "
			    "header's max descriptor size (0x%x)", i, cur_off,
			    dlen, hdr->eom_ds);
		}

		/*
		 * Now that we've validated this we need to check a few things
		 * before we call the command:
		 *
		 * 1. This matches our eye and lane filter.
		 * 2. The data is valid.
		 */
		if (lane != UINT8_MAX && desc->eld_ln != lane)
			goto next;
		if (eye != UINT8_MAX && desc->eld_eye != eye)
			goto next;
		if (desc->eld_mstat.mstat_mcsc == 0) {
			warnx("lane %u, eye %u data does not have a successful "
			    "measurement", desc->eld_ln, desc->eld_eye);
			ret = false;
			goto next;
		}

		func(i, hdr, desc, arg);

next:
		cur_off += dlen;
	}

	return (ret);
}

/*
 * Validate the data that we have. In particular we need to confirm:
 *
 * 1. The data file covers the entire header.
 * 2. This is a log revision we know about.
 * 3. The measurement is completed.
 * 4. The header size reported is what we expect.
 * 5. The result size is covered by the file.
 * 6. If a specific mode requires optional data, it is present.
 * 7. There is a non-zero number of descriptors.
 * 8. The descriptor size covers at least the Lane descriptor structure.
 * 9. DS * NDS is within the result size.
 *
 * The specifics of each descriptor are checked when we iterate over them in
 * phyeye_eol_iter().
 */
static void
phyeye_report_sanity_check(const nvme_eom_hdr_t *hdr, off_t len,
    const phyeye_report_t *phy)
{
	if (len < sizeof (nvme_eom_hdr_t)) {
		errx(-1, "data file is too short: file does not cover the "
		    "0x%lx bytes required for the Eye Opening Measurement "
		    "header", sizeof (nvme_eom_hdr_t));
	}

	/*
	 * This specification was first introduced in the NVMe PCIe revision 1.1
	 * at log revision 2. It moved to version 3 with NVMe PCIe 1.2. However,
	 * some devices report log revision 1 which means they likely implement
	 * a draft version of the TP. We don't know what's different between
	 * version 1 and 2, but hope for the sake of understanding right now
	 * it doesn't impact our ability to translate this.
	 */
	if (hdr->eom_lrev < 1 || hdr->eom_lrev > 3) {
		errx(-1, "encountered unknown log header revision: 0x%x",
		    hdr->eom_lrev);
	}

	/*
	 * Only worry about complete measurements if we're doing a report, not
	 * if we're just printing the log.
	 */
	if (phy != NULL && hdr->eom_eomip != NVME_EOM_DONE) {
		errx(-1, "data file measurement in progress field does not "
		    "indicate a finished measurement (%u): found %u",
		    NVME_EOM_DONE, hdr->eom_eomip);
	}

	if (hdr->eom_hsize != sizeof (nvme_eom_hdr_t)) {
		errx(-1, "data file has unexpected header length: found 0x%x, "
		    "expected 0x%zx", hdr->eom_hsize, sizeof (nvme_eom_hdr_t));
	}

	if (hdr->eom_rsz > len) {
		errx(-1, "data file reports that the log is 0x%x bytes, but "
		    "file is only 0x%lx bytes", hdr->eom_rsz, len);
	}

	if (phy != NULL && phy->pr_mode == PHYEYE_REPORT_M_ASCII &&
	    hdr->eom_odp.odp_pefp == 0) {
		errx(-1, "Printable Eye requested, but field not present in "
		    "data file");
	}

	if (phy != NULL && phy->pr_mode == PHYEYE_REPORT_M_OED &&
	    hdr->eom_odp.odp_edfp == 0) {
		errx(-1, "Eye Data Field requested, but field not present in "
		    "data file");
	}

	if (phy != NULL && hdr->eom_nd == 0) {
		errx(-1, "data file reports no EOM lane descriptors present");
	}

	if (hdr->eom_nd > 0 && hdr->eom_ds < sizeof (nvme_eom_lane_desc_t)) {
		errx(-1, "data file reports the descriptor size is 0x%x, but "
		    "that is less than the base descriptor size of 0x%zx",
		    hdr->eom_ds, sizeof (nvme_eom_lane_desc_t));
	}
}

static void
phyeye_report_ascii(uint8_t descno, const nvme_eom_hdr_t *hdr,
    const nvme_eom_lane_desc_t *desc, void *arg)
{
	phyeye_report_t *phy = arg;

	phy->pr_print = true;
	(void) printf("Lane %u, Eye %u: Printable Eye\n", desc->eld_ln,
	    desc->eld_eye);
	for (uint16_t row = 0; row < desc->eld_nrows; row++) {
		for (uint16_t col = 0; col < desc->eld_ncols; col++) {
			const uint32_t off = row * desc->eld_ncols + col;
			uint8_t c = desc->eld_data[off];
			if (c != '0' && c != '1')
				c = '?';
			(void) putc(c, stdout);
		}
		(void) putc('\n', stdout);
	}
}

static void
phyeye_report_oed(uint8_t descno, const nvme_eom_hdr_t *hdr,
    const nvme_eom_lane_desc_t *desc, void *arg)
{
	phyeye_report_t *phy = arg;

	size_t off = desc->eld_nrows * desc->eld_ncols;

	phy->pr_print = true;
	(void) printf("Lane %u, Eye %u: Eye Data\n", desc->eld_ln,
	    desc->eld_eye);
	nvmeadm_dump_hex(&desc->eld_data[off], desc->eld_edlen);
}

int
do_report_phyeye_cmd(const nvme_process_arg_t *npa)
{
	int fd = -1, ret = EXIT_SUCCESS;
	struct stat st;
	void *data;
	phyeye_report_t *phy = npa->npa_cmd_arg;
	phyeye_lane_iter_cb_f func = NULL;

	if (npa->npa_argc > 0) {
		errx(-1, "extraneous arguments beginning with '%s'",
		    npa->npa_argv[0]);
	}

	if ((fd = open(phy->pr_input, O_RDONLY)) < 0) {
		err(-1, "failed to open input file %s", phy->pr_input);
	}

	if (fstat(fd, &st) != 0) {
		err(-1, "failed to stat %s", phy->pr_input);
	}

	if (st.st_size > NVMEADM_MAX_MMAP) {
		errx(-1, "%s file size of 0x%lx exceeds maximum allowed size "
		    "of 0x%llx", phy->pr_input, st.st_size, NVMEADM_MAX_MMAP);
	}

	data = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
	if (data == MAP_FAILED) {
		errx(-1, "failed to mmap %s", phy->pr_input);
	}

	phyeye_report_sanity_check(data, st.st_size, phy);

	switch (phy->pr_mode) {
	case PHYEYE_REPORT_M_ASCII:
		func = phyeye_report_ascii;
		break;
	case PHYEYE_REPORT_M_OED:
		func = phyeye_report_oed;
		break;
	}

	if (!phyeye_lane_iter(data, st.st_size, phy, func, phy->pr_lane,
	    phy->pr_eye)) {
		ret = -1;
	}

	/*
	 * If nothing was printed, warn and error about this if we had an eye
	 * constraint, a lane constraint, or the mode isn't decoding. We want to
	 * be able to decode a log that has no data.
	 */
	if (!phy->pr_print) {
		warnx("failed to match and print any data");
		ret = -1;
	}

	VERIFY0(munmap(data, st.st_size));
	if (fd >= 0) {
		VERIFY0(close(fd));
	}

	return (ret);
}

static uint32_t
phyeye_log_getrev(const void *data, size_t len)
{
	const nvme_eom_hdr_t *hdr = data;
	return (hdr->eom_lrev);
}

static void
phyeye_log_drive_lane_cb(uint8_t descno, const nvme_eom_hdr_t *hdr,
    const nvme_eom_lane_desc_t *desc, void *arg)
{
	char base[32];
	char header[128];
	nvmeadm_field_print_t *print = arg;

	(void) snprintf(base, sizeof (base), "eld%u", descno);
	(void) snprintf(header, sizeof (header), "EOM Lane Descriptor %u",
	    descno);

	print->fp_header = header;
	print->fp_fields = phyeye_elm_fields;
	print->fp_nfields = ARRAY_SIZE(phyeye_elm_fields);
	print->fp_base = base;
	print->fp_data = desc;
	print->fp_dlen = hdr->eom_ds;
	print->fp_off = (uintptr_t)desc - (uintptr_t)hdr;

	nvmeadm_field_print(print);
}

static bool
phyeye_log_drive(nvmeadm_field_print_t *print, const void *data, size_t len)
{
	print->fp_header = "EOM Header";
	print->fp_fields = phyeye_eom_fields;
	print->fp_nfields = ARRAY_SIZE(phyeye_eom_fields);
	print->fp_base = "eom";
	print->fp_data = data;
	print->fp_dlen = len;
	print->fp_off = 0;

	phyeye_report_sanity_check(data, len, NULL);
	nvmeadm_field_print(print);

	return (phyeye_lane_iter(data, len, print, phyeye_log_drive_lane_cb,
	    UINT8_MAX, UINT8_MAX));
}

const nvmeadm_log_field_info_t phyeye_field_info = {
	.nlfi_log = "phyeye",
	.nlfi_min = sizeof (nvme_eom_hdr_t),
	.nlfi_getrev = phyeye_log_getrev,
	.nlfi_drive = phyeye_log_drive
};
