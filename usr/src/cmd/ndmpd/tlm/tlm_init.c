/*
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * BSD 3 Clause License
 *
 * Copyright (c) 2007, The Storage Networking Industry Association.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 	- Redistributions of source code must retain the above copyright
 *	  notice, this list of conditions and the following disclaimer.
 *
 * 	- Redistributions in binary form must reproduce the above copyright
 *	  notice, this list of conditions and the following disclaimer in
 *	  the documentation and/or other materials provided with the
 *	  distribution.
 *
 *	- Neither the name of The Storage Networking Industry Association (SNIA)
 *	  nor the names of its contributors may be used to endorse or promote
 *	  products derived from this software without specific prior written
 *	  permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
#include <sys/errno.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <sys/byteorder.h>
#include <sys/scsi/impl/uscsi.h>
#include <sys/scsi/scsi.h>
#include <tlm.h>
#include <pthread.h>
#include "tlm_proto.h"

/*
 * generic routine to read a SCSI page
 */
int
read_scsi_page(scsi_link_t *slink, union scsi_cdb *cdb,
    int command_size, caddr_t data, int size)
{
	struct uscsi_cmd uscsi_cmd;
	char *dname;
	int dev;

	if (slink == 0 || slink->sl_sa == 0)
		return (EINVAL);

	(void) memset(&uscsi_cmd, 0, sizeof (uscsi_cmd));

	/* Lun is in the 5th bit */
	cdb->scc_lun = slink->sl_lun;
	uscsi_cmd.uscsi_flags |= USCSI_READ | USCSI_ISOLATE;
	uscsi_cmd.uscsi_bufaddr = data;
	uscsi_cmd.uscsi_buflen = size;
	uscsi_cmd.uscsi_timeout = 1000;
	uscsi_cmd.uscsi_cdb = (char *)cdb;

	if (cdb->scc_cmd == SCMD_READ_ELEMENT_STATUS) {
		uscsi_cmd.uscsi_flags |= USCSI_RQENABLE;
		uscsi_cmd.uscsi_rqbuf = data;
		uscsi_cmd.uscsi_rqlen = size;
	}
	uscsi_cmd.uscsi_cdblen = command_size;

	dname = sasd_slink_name(slink);
	dev = open(dname, O_RDWR | O_NDELAY);
	if (dev == -1) {
		NDMP_LOG(LOG_DEBUG, "Open failed for %s err=%d",
		    dname, errno);
		return (errno);
	}
	if (tlm_ioctl(dev, USCSICMD, &uscsi_cmd) < 0) {
		NDMP_LOG(LOG_DEBUG, "SCSI cmd %d failed for %s err=%d",
		    cdb->scc_cmd, dname, errno);
		(void) close(dev);
		return (errno);
	}
	(void) close(dev);
	return (uscsi_cmd.uscsi_status);
}

/*
 * Read the Inquiry Page.
 */
static int
read_inquiry_page(scsi_link_t *slink, struct scsi_inquiry *inq)
{
	union scsi_cdb cdb;

	(void) memset(&cdb, 0, sizeof (union scsi_cdb));
	cdb.scc_cmd = SCMD_INQUIRY;
	cdb.g0_count0 = sizeof (struct scsi_inquiry);

	return (read_scsi_page(slink, &cdb, CDB_GROUP0,
	    (caddr_t)inq, sizeof (*inq)) ? -1 : 0);
}

/*
 * Read the Product Data Page.
 */
static int
read_data_page(scsi_link_t *slink, int pcode, char *snum, int size)
{
	char cmd[CDB_GROUP0];

	(void) memset(cmd, 0, sizeof (cmd));

	cmd[0] = SCMD_INQUIRY;
	cmd[1] = pcode ? 0x01 : 0x00;
	cmd[2] = pcode;
	cmd[4] = size;

	/* LINTED improper alignment */
	return (read_scsi_page(slink, (union scsi_cdb *)&cmd, CDB_GROUP0,
	    (caddr_t)snum, size) == -1 ? -1 : 0);
}


/*
 * Read the Serial Number Page.
 */
static int
read_serial_num_page(scsi_link_t *slink, char *snum, int size)
{
	scsi_serial_t serial;
	int rv;

	(void) memset(&serial, 0, sizeof (scsi_serial_t));
	rv = read_data_page(slink, SCSI_SERIAL_PAGE, (caddr_t)&serial,
	    sizeof (scsi_serial_t));
	(void) strlcpy(snum, serial.sr_num, size);

	return (rv == -1 ? -1 : 0);
}


/*
 * Read the Device Name Page.
 */
static int
read_dev_name_page(scsi_link_t *slink, device_ident_header_t *devp, int len)
{
	(void) memset(devp, 0, len);

	if (read_data_page(slink, SCSI_DEVICE_IDENT_PAGE, (caddr_t)devp,
	    len) == -1)
		return (-1);

	if (devp->di_page_code != SCSI_DEVICE_IDENT_PAGE)
		return (-1);

	return (0);
}

/*
 * Formatted print of WWN
 */
static void
snprintf_wwn(char *buf, int size, uint8_t *wwn)
{
	if (wwn == NULL || buf == NULL)
		return;

	(void) snprintf(buf, size, "0x%2.2X%2.2X%2.2X%2.2X%2.2X%2.2X%2.2X%2.2X",
	    wwn[0], wwn[1], wwn[2], wwn[3], wwn[4], wwn[5], wwn[6], wwn[7]);
}


/*
 * Extract and print the world wide name (WWN)
 */
int
read_device_wwn(scsi_link_t *slink, char *wwnp, int wsize)
{
	device_ident_header_t *header;
	name_ident_t *ident;
	uint16_t page_len = sizeof (device_ident_header_t);
	uint16_t act_len;
	int accessed;
	uint8_t *designator_data;

	(void) memset(wwnp, 0, wsize);
resize:
	header = malloc(page_len);
	if (header == NULL)
		return (-1);

	if (read_dev_name_page(slink, header, page_len) == -1) {
		free(header);
		return (-1);
	}

	act_len = BE_16(header->di_page_length);
	if (act_len > page_len) {
		free(header);
		page_len = act_len;
		goto resize;
	}

	ident = (name_ident_t *)&header[1];
	accessed = sizeof (device_ident_header_t);

	while (accessed < act_len) {

		accessed += sizeof (name_ident_t);
		accessed += ident->ni_ident_length;
		designator_data = (uint8_t *)&ident[1];
		/*
		 * Looking for code set 1 (Binary) ident type NAA 64 bit
		 * address that is associated with the node (0).
		 */
		if ((ident->ni_code_set == 1) &&
		    (ident->ni_ident_type == 3)) {
			snprintf_wwn(wwnp, wsize, designator_data);
			/*
			 * If assc is zero (Node) this is the one we want.
			 * If we find that we're done.
			 */
			if (ident->ni_asso == 0)
				break;
		}
		/*
		 * If we find a EUI-64 we can use that also.
		 */
		if ((ident->ni_code_set == 2) &&
		    (ident->ni_ident_type == 1) &&
		    (ident->ni_asso == 0) &&
		    (isprint(wwnp[0] == 0))) { /* Don't overwrite */
			/*
			 * This isn't our first choice but we'll print it
			 * in case there is nothing else to use.
			 */
			(void) snprintf(wwnp, wsize, "%.*s",
			    ident->ni_ident_length, designator_data);
		}
		ident =
		    (name_ident_t *)&designator_data[ident->ni_ident_length];
	}
	free(header);
	/*
	 * See if we found something.
	 * Memset above would leave wwnp not printable.
	 */
	if (isprint(wwnp[0]))
		return (0);
	return (-1);
}

/*
 * Add the tape library call back function (used while scanning the bus)
 */
static int
add_lib(scsi_link_t *slink, struct scsi_inquiry *sd, void *arg)
{
	int l;
	int *nlp; /* pointer to library counter */
	sasd_drive_t *ssd;

	if (!slink || !sd) {
		NDMP_LOG(LOG_DEBUG, "Invalid argument %x %x %x",
		    slink, sd, arg);
		return (-TLM_INVALID);
	}

	if (sd->inq_dtype == DTYPE_CHANGER) {
		/* This is a robot, which means this is also a library */
		nlp = (int *)arg;
		(*nlp)++;
		l = tlm_insert_new_library(slink);
		tlm_enable_barcode(l);

		NDMP_LOG(LOG_DEBUG, "lib %d sid %d lun %d",
		    l, slink->sl_sid, slink->sl_lun);

		if ((ssd = sasd_slink_drive(slink)) != NULL) {
			(void) strlcpy(ssd->sd_vendor, sd->inq_vid,
			    sizeof (ssd->sd_vendor));
			(void) strlcpy(ssd->sd_id, sd->inq_pid,
			    sizeof (ssd->sd_id));
			(void) strlcpy(ssd->sd_rev, sd->inq_revision,
			    sizeof (ssd->sd_rev));
			(void) read_serial_num_page(slink, ssd->sd_serial,
			    sizeof (ssd->sd_serial));
			(void) read_device_wwn(slink, ssd->sd_wwn,
			    sizeof (ssd->sd_wwn));
		}
	}

	return (TLM_NO_ERRORS);
}

/*
 * Create some virutal slots
 */
static int
make_virtual_slot(int l, tlm_drive_t *dp)
{
	int s;
	tlm_slot_t *sp;

	if (l <= 0 || !dp) {
		NDMP_LOG(LOG_DEBUG, "Invalid argument %d, %x", l, dp);
		return (-TLM_INVALID);
	}

	if ((s = tlm_insert_new_slot(l)) <= 0)
		return (-TLM_NO_MEMORY);

	if (!(sp = tlm_slot(l, s))) {
		NDMP_LOG(LOG_DEBUG, "Internal error: slot not found %d", s);
		return (-TLM_ERROR_INTERNAL);
	}
	/*
	 * For virtual slots element number is 0 and they are always full.
	 */
	sp->ts_element = 0;
	sp->ts_status_full = TRUE;
	return (TLM_NO_ERRORS);
}

/*
 * Make the tape drive not part of a tape library (stand alone)
 */
static int
make_stand_alone_drive(scsi_link_t *slink, int l)
{
	int d;
	tlm_drive_t *dp;

	if (!slink || l <= 0) {
		NDMP_LOG(LOG_DEBUG, "Invalid argument %x %d", slink, l);
		return (-TLM_INVALID);
	}

	d = tlm_insert_new_drive(l);
	if (!(dp = tlm_drive(l, d))) {
		NDMP_LOG(LOG_DEBUG, "Internal error: drive not found %d", d);
		return (-TLM_ERROR_INTERNAL);
	}

	/* For stand-alone drives, the element number is the drive number. */
	dp->td_element = d;
	dp->td_slink = slink;
	dp->td_scsi_id = slink->sl_sid;
	dp->td_lun = slink->sl_lun;
	dp->td_exists = TRUE;

	/*
	 * Note: There is no way to remove library elements.  We cannot clean
	 * up if make_virtual_slot() fails.
	 */
	(void) make_virtual_slot(l, dp);
	return (d);
}

/*
 * Find the LIBRARY structure that has control of this DRIVE.
 */
static int
new_drive(scsi_link_t *slink, int *lib)
{
	int d;
	tlm_drive_t *dp;
	tlm_library_t *lp;

	/* Walk through all libraries. */
	for (*lib = 1; *lib <= tlm_library_count(); (*lib)++) {
		if (!(lp = tlm_library(*lib)))
			continue;
		/* Walk through drives that are already found. */
		for (d = 1; d <= lp->tl_drive_count; d++) {
			if (!(dp = tlm_drive(*lib, d)))
				continue;
			if (dp->td_scsi_id == slink->sl_sid &&
			    dp->td_lun == slink->sl_lun)
				return (d);
		}
	}

	/* Not part of any library, this is a newly found tape drive. */
	return (0);
}


/*
 * Add the tape library call back function (used while scanning the bus)
 */
static int
add_drv(scsi_link_t *slink, struct scsi_inquiry *sd, void *arg)
{
	int l, d;
	int *vlp; /* pointer to virtual library number */
	sasd_drive_t *ssd;
	tlm_library_t *library;
	tlm_drive_t *drive;

	if (!slink || !sd) {
		NDMP_LOG(LOG_DEBUG, "Invalid argument %x %x %x",
		    slink, sd, arg);
		return (-TLM_INVALID);
	}

	if (sd->inq_dtype == DTYPE_SEQUENTIAL) {
		vlp = (int *)arg;
		d = new_drive(slink, &l);
		if (d == 0) {
			/* This tape drive was not found inside any robot. */
			if (*vlp == 0) {
				/*
				 * First, create a virtual library if it's not
				 * done yet.
				 */
				*vlp = tlm_insert_new_library(slink);
				if ((library = tlm_library(*vlp)) != NULL)
					library->tl_capability_robot = FALSE;
			}
			if ((d = make_stand_alone_drive(slink, *vlp)) < 0) {
				/* sorry, we can not clean up the vlib now * */
				return (-TLM_INVALID);
			}
			l = *vlp;
			NDMP_LOG(LOG_DEBUG, "vlib(%d, %d) sid %d lun %d",
			    l, d, slink->sl_sid, slink->sl_lun);
		} else
			NDMP_LOG(LOG_DEBUG, "(%d, %d) sid %d lun %d",
			    l, d, slink->sl_sid, slink->sl_lun);

		if ((drive = tlm_drive(l, d)) != NULL) {
			drive->td_exists = TRUE;
			drive->td_slink = slink;
		}
		if ((ssd = sasd_slink_drive(slink)) != NULL) {
			(void) strlcpy(ssd->sd_vendor,
			    sd->inq_vid, sizeof (ssd->sd_vendor));
			(void) strlcpy(ssd->sd_id, sd->inq_pid,
			    sizeof (ssd->sd_id));
			(void) strlcpy(ssd->sd_rev, sd->inq_revision,
			    sizeof (ssd->sd_rev));
			(void) read_serial_num_page(slink, ssd->sd_serial,
			    sizeof (ssd->sd_serial));
			(void) read_device_wwn(slink, ssd->sd_wwn,
			    sizeof (ssd->sd_wwn));
		}
	}

	return (TLM_NO_ERRORS);
}

/*
 * Scan the specified bus and call the handler function.
 */
static int
scan_bus(scsi_adapter_t *sa, int(*hndlr)(), void *args)
{
	int nerr;
	scsi_link_t *slink;
	struct scsi_inquiry scsi_data;

	nerr = 0;
	slink = sa->sa_link_head.sl_next;
	for (; slink != &sa->sa_link_head; slink = slink->sl_next) {
		(void) memset(&scsi_data, 0, sizeof (struct scsi_inquiry));
		if (read_inquiry_page(slink, &scsi_data) == -1)
			nerr++;
		else
			if ((*hndlr)(slink, &scsi_data, args) != TLM_NO_ERRORS)
				nerr++;
	}

	return (nerr);
}

/*
 * Marks the library/slots inaccessible if there are not enough drives
 * available on the library
 */
static void
inaccbl_drv_warn(int start, int max)
{
	char *dname;
	int l, d;
	tlm_library_t *lp;

	for (l = start; l < max; l++) {
		if (!(lp = tlm_library(l)))
			continue;
		if (lp->tl_drive_count <= 0)
			continue;

		NDMP_LOG(LOG_DEBUG,
		    "Warning: The following drives are not accessible:");
		for (d = 1; d <= lp->tl_drive_count; d++)
			if (!(dname = tlm_get_tape_name(l, d))) {
				NDMP_LOG(LOG_DEBUG,
				    "Error getting drive(%d, %d)", l, d);
			} else
				NDMP_LOG(LOG_DEBUG, "%s", dname);

		/*
		 * Note: Make the slots inaccessible to prevent running
		 * discovery on these libraries.  The better idea is
		 * removing these libraries, but we don't have that
		 * feature available now.
		 */
		lp->tl_slot_count = 0;
	}
}

/*
 * Initialize the tape library data structure, asks the libraries what
 * equipments they have.
 */
int
tlm_init(void)
{
	static int nlibs; /* number of found libraries */
	int i, nsa;
	int l, vlibs, d;
	int rv;
	scsi_adapter_t *sa;
	tlm_library_t *lp;
	tlm_drive_t *dp;

	/* Search through all SCSI adapters, look for tape robots. */
	nlibs = 0;

	/*
	 * We probe both changers and tape drives here
	 * but later on this needs to be removed as the
	 * probe will happen somewhere else.
	 */
	if (probe_scsi() < 0)
		return (-1);

	nsa = scsi_get_adapter_count();
	for (i = 0; i < nsa; i++)
		if ((sa = scsi_get_adapter(i)))
			(void) scan_bus(sa, add_lib, (void *)&nlibs);

	NDMP_LOG(LOG_DEBUG, "nlibs %d", nlibs);

	/* Search through all SCSI adapters, look for tape drives. */
	vlibs = 0;
	for (i = 0; i < nsa; i++)
		if ((sa = scsi_get_adapter(i)))
			(void) scan_bus(sa, add_drv, (void *)&vlibs);

	NDMP_LOG(LOG_DEBUG, "vlibs %d", vlibs);

	if (nlibs > 0 && vlibs > 0)
		inaccbl_drv_warn(nlibs + 1, vlibs + nlibs + 1);

	for (l = 1; l <= tlm_library_count(); l++) {
		if (!(lp = tlm_library(l))) {
			NDMP_LOG(LOG_DEBUG, "can't find lib %d", l);
			continue;
		}

		/*
		 * Make sure all libraries have tape drives.
		 */
		if (lp->tl_drive_count == 0)
			continue;

		/*
		 * Make sure all tape drives exist. A drive that is not
		 * linked into the SCSI chain will be seen by the library
		 * but we cannot talk to it.
		 */
		for (d = 1; d <= lp->tl_drive_count; d++) {
			dp = tlm_drive(l, d);
			if (dp && !dp->td_exists) {
				NDMP_LOG(LOG_DEBUG, "Ghost drive found %d.%d",
				    l, d);
				lp->tl_ghost_drives = TRUE;
				continue;
			}
		}
	}

	if (nlibs > 0)
		rv = (vlibs > 0) ? 0 : nlibs;
	else
		rv = vlibs;

	return (rv);
}
