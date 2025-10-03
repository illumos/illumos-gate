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
 * Logic to fetch and save an instance of the telemetry log page. The telemetry
 * log page consists of a 512-byte header followed by a number of data blocks.
 * The number of data blocks is indicated by the controller.
 *
 * Telemetry may either be host-initiated or device-initiated. When the
 * telemetry is host-initiated, the host specifies when to create the telemetry
 * using a flag in the log-specific parameter field (lsp). Whenever this is a 1,
 * then this data is created again. When telemetry is device-initiated, which
 * uses a different log page, then the data persists as long as the retain async
 * event flag is specified.
 *
 * In the telemetry header there are two things that we need to pay attention
 * to:
 *
 * 1. There are up to four indicators for the number of telemetry blocks that
 *    could exist. These are meant to be indicators of short, medium, and long.
 *    The 4th one requires the kernel to opt into it with a specific set
 *    features command. We basically always try to get the largest amount that
 *    exists in the header.
 *
 * 2. There are a series of generation numbers that exist. We need to ensure
 *    that these generation numbers are the same across everything that we find.
 *    So basically we read this initially at the start and then read it again at
 *    the end. If the values differ, then we throw an error or would otherwise
 *    have to start over. There are separate generation numbers for
 *    host-initiated and controller-initiated telemetry.
 *
 * The telemetry file may have a large number of blocks so we split this up into
 * multiple requests of up to 1 MiB (our default maximum size). We do not assume
 * that we will get the log all in one go. As such, we also will not assume that
 * we can buffer the entire log page in memory and will always write it out.
 * This means that the user will be required to use the output file option.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <err.h>
#include <unistd.h>
#include <sys/sysmacros.h>

#include "nvmeadm.h"

/*
 * We use a 64 KiB buffer here as that's usually within a device's maximum
 * payload.
 */
#define	TELEM_BLKSIZE	(64 * 1024)

static void
telemetry_read(const nvme_process_arg_t *npa, nvme_log_req_t *req, void *buf,
    size_t len, uint64_t off)
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
telemetry_write(int ofd, const void *buf, size_t len)
{
	size_t off = 0;

	while (len > 0) {
		ssize_t ret = write(ofd, buf + off, len - off);
		if (ret < 0) {
			err(EXIT_FAILURE, "failed to write to log telemetry "
			    "output file");
		}

		off += (size_t)ret;
		len -= (size_t)ret;
	}
}

int
do_get_logpage_telemetry(const nvme_process_arg_t *npa,
    const nvme_log_disc_t *disc, nvme_log_req_t *req)
{
	int ofd;
	const nvmeadm_get_logpage_t *log = npa->npa_cmd_arg;
	void *buf;
	nvme_telemetry_log_t hdr;
	uint64_t len;

	if (log->ngl_output == NULL) {
		errx(-1, "log page %s requires specifying an output file",
		    nvme_log_disc_name(disc));
	}

	ofd = open(log->ngl_output, O_WRONLY | O_TRUNC | O_CREAT, 0644);
	if (ofd < 0) {
		err(-1, "failed to create output file %s", log->ngl_output);
	}

	buf = calloc(TELEM_BLKSIZE, sizeof (uint8_t));
	if (buf == NULL) {
		err(-1, "failed to allocate %u bytes for interim data buffer",
		    TELEM_BLKSIZE);
	}

	/*
	 * First create a new request and read the first 512-bytes.
	 */
	if (!nvme_log_req_set_lsp(req, NVME_TELMCTRL_LSP_CTHID)) {
		nvmeadm_fatal(npa, "failed to set lsp to create host "
		    "telemetry");
	}

	telemetry_read(npa, req, &hdr, sizeof (hdr), 0);
	telemetry_write(ofd, &hdr, sizeof (hdr));

	/*
	 * Clear the request to create telemetry for the rest of our operation.
	 */
	if (!nvme_log_req_set_lsp(req, 0)) {
		nvmeadm_fatal(npa, "failed to set lsp to create host "
		    "telemetry");
	}

	if (!nvme_log_disc_calc_size(disc, &len, &hdr, sizeof (hdr))) {
		errx(-1, "failed to determine full %s log length",
		    npa->npa_argv[0]);
	}

	size_t off = sizeof (hdr);
	while (off < len) {
		size_t to_read = MIN(len - off, TELEM_BLKSIZE);
		telemetry_read(npa, req, buf, to_read, off);
		telemetry_write(ofd, buf, to_read);
		off += to_read;
	}

	telemetry_read(npa, req, buf, sizeof (hdr), 0);
	const nvme_telemetry_log_t *final = (const nvme_telemetry_log_t *)buf;
	if (hdr.ntl_thdgn != final->ntl_thdgn) {
		errx(-1, "log telemetry generation changed: originally was "
		    "0x%x, ended with 0x%x", hdr.ntl_thdgn, final->ntl_thdgn);
	}

	free(buf);
	(void) close(ofd);
	return (0);
}
