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
 * Copyright 2016 Joyent, Inc.
 */

/*
 * This is a general firmware flash plugin that does basic verification for
 * devices backed by sd(7D).
 *
 * The sd(7D) target for firmware flashing uses the general SCSI WRITE BUFFER
 * options with various modes to instruct the drive to download and install
 * microcode (what SPC-3 calls firmware). To verify that something fits, we can
 * use the READ BUFFER command with mode 03h to indicate that we want to
 * buffer's descriptor. This gives us both the buffer's total size and the
 * required alignment for writes.
 *
 * Unfortunately, it's impossible to know for certain if that size is supposed
 * to be equivalent to the microcode's. While a READ BUFFER is supposed to
 * return the same data as with a WRITE BUFFER command, experimental evidence
 * has shown that this isn't always the case. Especially as the firmware buffer
 * usually leverages buffer zero, but has custom modes to access it.
 */

#include <libintl.h>
#include <fwflash/fwflash.h>
#include <scsi/libscsi.h>

/*
 * The fwflash plugin interface is a bit odd for a modern committed interface
 * and requires us to refer to data objects in the parent explicitly to get
 * access to and set various information. It also doesn't allow us a means of
 * setting data for our transport layer.
 */
extern struct vrfyplugin *verifier;

/*
 * Declare the name of our vendor. This is required by the fwflash
 * plugin interface. Note it must be a character array. Using a pointer may
 * confuse the framework and its use of dlsym.
 */
char vendor[] = "GENERIC";

int
vendorvrfy(struct devicelist *dvp)
{
	libscsi_hdl_t *hdl = NULL;
	libscsi_target_t *targ = NULL;
	libscsi_action_t *act = NULL;
	libscsi_errno_t serr;
	spc3_read_buffer_cdb_t *rb_cdb;
	uint8_t descbuf[4];
	uint32_t size;

	int ret = FWFLASH_FAILURE;

	if ((hdl = libscsi_init(LIBSCSI_VERSION, &serr)) == NULL) {
		logmsg(MSG_ERROR, gettext("%s: failed to initialize "
		    "libscsi: %s\n"),
		    verifier->vendor, libscsi_strerror(serr));
		return (FWFLASH_FAILURE);
	}

	if ((targ = libscsi_open(hdl, NULL, dvp->access_devname)) ==
	    NULL) {
		logmsg(MSG_ERROR,
		    gettext("%s: unable to open device %s\n"),
		    verifier->vendor, dvp->access_devname);
		goto cleanup;
	}

	if ((act = libscsi_action_alloc(hdl, SPC3_CMD_READ_BUFFER,
	    LIBSCSI_AF_READ, descbuf, sizeof (descbuf))) == NULL) {
		logmsg(MSG_ERROR, "%s: failed to alloc scsi action: %s\n",
		    verifier->vendor, libscsi_errmsg(hdl));
		goto cleanup;
	}

	rb_cdb = (spc3_read_buffer_cdb_t *)libscsi_action_get_cdb(act);

	rb_cdb->rbc_mode = SPC3_RB_MODE_DESCRIPTOR;

	/*
	 * Microcode upgrade usually only uses the first buffer ID which are
	 * sequentially indexed from zero. Strictly speaking these are all
	 * vendor defined, but so far most vendors we've seen use index zero
	 * for this.
	 */
	rb_cdb->rbc_bufferid = 0;

	rb_cdb->rbc_allocation_len[0] = 0;
	rb_cdb->rbc_allocation_len[1] = 0;
	rb_cdb->rbc_allocation_len[2] = sizeof (descbuf);

	if (libscsi_exec(act, targ) != 0) {
		logmsg(MSG_ERROR, gettext("%s: failed to execute SCSI buffer "
		    "descriptor read: %s\n"), verifier->vendor,
		    libscsi_errmsg(hdl));
		goto cleanup;
	}

	if (libscsi_action_get_status(act) != SAM4_STATUS_GOOD) {
		logmsg(MSG_ERROR, gettext("%s: SCSI READ BUFFER command to "
		    "determine maximum image size failed\n"), verifier->vendor);
		goto cleanup;
	}

	if (descbuf[0] == 0 && descbuf[1] == 0 && descbuf[2] == 0 &&
	    descbuf[3] == 0) {
		logmsg(MSG_ERROR, gettext("%s: devices %s does not support "
		    "firmware upgrade\n"), verifier->vendor,
		    dvp->access_devname);
		goto cleanup;
	}

	size = (descbuf[1] << 16) | (descbuf[2] << 8) | descbuf[3];
	logmsg(MSG_INFO, gettext("%s: checking maximum image size %u against "
	    "actual image size: %u\n"), verifier->vendor, size,
	    verifier->imgsize);
	if (size < verifier->imgsize) {
		logmsg(MSG_ERROR, gettext("%s: supplied firmware image %s "
		    "exceeds maximum image size of %u\n"),
		    verifier->vendor, verifier->imgfile, size);
		goto cleanup;
	}

	logmsg(MSG_INFO, gettext("%s: successfully validated images %s\n"),
	    verifier->vendor, verifier->imgfile);

	verifier->flashbuf = 0;
	ret = FWFLASH_SUCCESS;
cleanup:
	if (act != NULL)
		libscsi_action_free(act);
	if (targ != NULL)
		libscsi_close(hdl, targ);
	if (hdl != NULL)
		libscsi_fini(hdl);

	return (ret);
}
