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
 * WDC vendor-specific commands
 */

#include <err.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/sysmacros.h>
#include <stdbool.h>
#include <endian.h>
#include <sys/nvme/wdc.h>

#include "nvmeadm.h"

/*
 * This is the default chunk size that we'll read the e6 log in. This generally
 * should fit within the maximum transfer size for a device. If we wanted to
 * improve this, we could expose what the kernel's maximum transfer size is for
 * a device and then use that as a larger upper bound. Currently the value is 64
 * KiB.
 */
#define	E6_BUFSIZE	0x10000

typedef struct nvmeadm_e6_dump {
	const char *e6_output;
} nvmeadm_e6_dump_t;

typedef struct nvmeadm_wdc_resize {
	bool wr_query;
	uint32_t wr_set;
} nvmeadm_wdc_resize_t;

void
usage_wdc_e6dump(const char *c_name)
{
	(void) fprintf(stderr, "%s -o output <ctl>\n\n"
	    "  Dump WDC e6 diagnostic log from a device.\n", c_name);
}

void
optparse_wdc_e6dump(nvme_process_arg_t *npa)
{
	int c;
	nvmeadm_e6_dump_t *e6;

	if ((e6 = calloc(1, sizeof (nvmeadm_e6_dump_t))) == NULL) {
		err(-1, "failed to allocate memory for e6 options structure");
	}

	while ((c = getopt(npa->npa_argc, npa->npa_argv, ":o:")) != -1) {
		switch (c) {
		case 'o':
			e6->e6_output = optarg;
			break;
		case '?':
			errx(-1, "unknown option: -%c", optopt);
		case ':':
			errx(-1, "option -%c requires an argument", optopt);
		}
	}

	if (e6->e6_output == NULL) {
		errx(-1, "missing required e6dump output file, specify with "
		    "-o");
	}

	npa->npa_cmd_arg = e6;
}

static void
wdc_e6_read(const nvme_process_arg_t *npa, nvme_wdc_e6_req_t *req,
    uint64_t off, void *buf, size_t len)
{
	if (!nvme_wdc_e6_req_set_offset(req, off)) {
		nvmeadm_fatal(npa, "failed to set e6 request offset to 0x%"
		    PRIx64, off);
	}

	if (!nvme_wdc_e6_req_set_output(req, buf, len)) {
		nvmeadm_fatal(npa, "failed to set e6 request output buffer");
	}

	if (!nvme_wdc_e6_req_exec(req)) {
		nvmeadm_fatal(npa, "failed to issue e6 request for %zu bytes "
		    "at offset 0x%" PRIx64, len, off);
	}
}

/*
 * Write out e6 data to a file. Because our read from the device has already
 * been constrained by size, we don't bother further chunking up the write out
 * to a file.
 */
static void
wdc_e6_write(int fd, const void *buf, size_t len)
{
	size_t off = 0;

	while (len > 0) {
		void *boff = (void *)((uintptr_t)buf + off);
		ssize_t ret = write(fd, boff, len);
		if (ret < 0) {
			/*
			 * We explicitly allow a signal that interrupts us to
			 * lead to a failure assuming someone has more likely
			 * than not issued a SIGINT or similar.
			 */
			err(-1, "failed to write e6 data to output file");
		}

		len -= (size_t)ret;
		off += (size_t)ret;
	}
}

int
do_wdc_e6dump(const nvme_process_arg_t *npa)
{
	int ofd;
	nvmeadm_e6_dump_t *e6 = npa->npa_cmd_arg;
	nvme_vuc_disc_t *vuc;
	void *buf;
	nvme_wdc_e6_req_t *req;
	const wdc_e6_header_t *header;
	uint64_t len, off;

	vuc = nvmeadm_vuc_init(npa, npa->npa_cmd->c_name);

	ofd = open(e6->e6_output, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (ofd < 0) {
		err(-1, "failed to open file %s", e6->e6_output);
	}

	if ((buf = calloc(1, E6_BUFSIZE)) == NULL) {
		err(-1, "failed to allocate 0x%x bytes for E6 transfer buffer",
		    E6_BUFSIZE);
	}

	if (!nvme_wdc_e6_req_init(npa->npa_ctrl, &req)) {
		nvmeadm_fatal(npa, "failed to initialize e6 request");
	}

	/*
	 * Begin by reading the header to determine the actual size. Note, as
	 * far as we can tell, the size of the header is included in the size we
	 * get.
	 */
	wdc_e6_read(npa, req, 0, buf, sizeof (wdc_e6_header_t));
	header = buf;
	len = be32toh(header->e6_size_be);

	if (len == UINT32_MAX) {
		errx(-1, "e6 header size 0x%" PRIx64 " looks like an invalid "
		    "PCI read, aborting", len);
	}

	if ((len % 4) != 0) {
		warnx("e6 header size 0x%zx is not 4 byte aligned, but "
		    "firmware claims it always will be, rounding up", len);
		len = P2ROUNDUP(len, 4);
	}

	if (len < sizeof (wdc_e6_header_t)) {
		errx(-1, "e6 header size is too small, 0x%zx bytes does not "
		    "even cover the header", len);
	}
	wdc_e6_write(ofd, buf, sizeof (wdc_e6_header_t));

	/*
	 * Account for the fact that we already read the header.
	 */
	off = sizeof (wdc_e6_header_t);
	len -= off;
	while (len > 0) {
		uint32_t toread = MIN(len, E6_BUFSIZE);
		wdc_e6_read(npa, req, off, buf, toread);
		wdc_e6_write(ofd, buf, toread);

		off += toread;
		len -= toread;
	}

	nvme_wdc_e6_req_fini(req);
	VERIFY0(close(ofd));
	nvmeadm_vuc_fini(npa, vuc);

	return (0);
}

void
usage_wdc_resize(const char *c_name)
{
	(void) fprintf(stderr, "%s -s size | -g <ctl>\n\n"
	    "  Resize a device to a new overall capacity in GB (not GiB) or "
	    "get its\n  current size. Resizing will cause all data and "
	    "namespaces to be lost.\n",
	    c_name);
}

void
optparse_wdc_resize(nvme_process_arg_t *npa)
{
	int c;
	nvmeadm_wdc_resize_t *resize;

	if ((resize = calloc(1, sizeof (nvmeadm_wdc_resize_t))) == NULL) {
		err(-1, "failed to allocate memory for resize options "
		    "structure");
	}

	while ((c = getopt(npa->npa_argc, npa->npa_argv, ":gs:")) != -1) {
		const char *err;

		switch (c) {
		case 'g':
			resize->wr_query = true;
			break;
		case 's':
			/*
			 * The size to set is in GB (not GiB). While WDC
			 * recommends specific size points depending on the
			 * drives initial capacity, we allow the user to set
			 * what they expect and will allow the command to
			 * succeed or fail as per the controller's whims. It
			 * would be better if we looked at the device and
			 * determined its underlying capacity and figured out
			 * what points made sense, but it's not clear on the
			 * best way to do that across a few different
			 * generations of WDC products.
			 */
			resize->wr_set = (uint32_t)strtonumx(optarg, 1,
			    UINT16_MAX, &err, 0);
			if (err != NULL) {
				errx(-1, "failed to parse resize size %s:"
				    "value is %s", optarg, err);
			}
			break;
		case '?':
			errx(-1, "unknown option: -%c", optopt);
		case ':':
			errx(-1, "option -%c requires an argument", optopt);
		}
	}

	if (resize->wr_query && resize->wr_set != 0) {
		errx(-1, "only one of -g and -s may be specified");
	}

	if (!resize->wr_query && resize->wr_set == 0) {
		errx(-1, "one of -g and -s must be specified");
	}

	npa->npa_cmd_arg = resize;
}

int
do_wdc_resize(const nvme_process_arg_t *npa)
{
	nvmeadm_wdc_resize_t *resize = npa->npa_cmd_arg;
	nvme_vuc_disc_t *vuc;

	vuc = nvmeadm_vuc_init(npa, npa->npa_cmd->c_name);

	/*
	 * The VUC for this generally recommends exclusive access. If this
	 * becomes problematic for folks issuing this query, then we should
	 * break the query into a separate VUC entry that we should discover
	 * instead.
	 */
	if (resize->wr_query) {
		uint32_t val;

		if (!nvme_wdc_resize_get(npa->npa_ctrl, &val)) {
			nvmeadm_fatal(npa, "failed to query current WDC "
			    "device capacity");
		}

		(void) printf("%u\n", val);
		nvmeadm_vuc_fini(npa, vuc);
		return (0);
	}

	if (!nvme_wdc_resize_set(npa->npa_ctrl, resize->wr_set)) {
		nvmeadm_fatal(npa, "failed to resize device to %u",
		    resize->wr_set);
	}

	(void) printf("%s resized to %u GB\n", npa->npa_name, resize->wr_set);
	nvmeadm_vuc_fini(npa, vuc);

	return (0);
}
