/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright 2016 Joyent, Inc.
 */

/*
 * sd / ssd (SCSI Direct-attached Device) specific functions.
 */

#include <libnvpair.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/queue.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <scsi/libscsi.h>
#include <sys/scsi/scsi_types.h>
#include <libintl.h> /* for gettext(3c) */
#include <fwflash/fwflash.h>
#include <sys/debug.h>
#include <umem.h>

typedef struct sam4_statdesc {
	int sam_status;
	char *sam_message;
} sam4_statdesc_t;

static sam4_statdesc_t sam4_status[] = {
	{ SAM4_STATUS_GOOD, "Status: GOOD (success)" },
	{ SAM4_STATUS_CHECK_CONDITION, "Status: CHECK CONDITION" },
	{ SAM4_STATUS_CONDITION_MET, "Status: CONDITION MET" },
	{ SAM4_STATUS_BUSY, "Status: Device is BUSY" },
	{ SAM4_STATUS_RESERVATION_CONFLICT, "Status: Device is RESERVED" },
	{ SAM4_STATUS_TASK_SET_FULL,
	    "Status: TASK SET FULL (insufficient resources in command queue" },
	{ SAM4_STATUS_TASK_ABORTED, "Status: TASK ABORTED" }
};

#define	NSAM4_STATUS	(sizeof (sam4_status) / sizeof (sam4_status[0]))

#define	FW_SD_FREE_DEVPATH(devpath)	{	\
		di_devfs_path_free((devpath));	\
	}
#define	FW_SD_FREE_DEVICELIST(thisdev, devpath) {	\
		free((thisdev));	\
		FW_SD_FREE_DEVPATH((devpath))	\
	}
#define	FW_SD_FREE_DRV_NAME(thisdev, devpath) {	\
		free((thisdev)->drvname);	\
		FW_SD_FREE_DEVICELIST((thisdev), (devpath))	\
	}
#define	FW_SD_FREE_CLS_NAME(thisdev, devpath) {	\
		free((thisdev)->classname);	\
		FW_SD_FREE_DRV_NAME((thisdev), (devpath))	\
	}
#define	FW_SD_FREE_ACC_NAME(thisdev, devpath) {	\
		free((thisdev)->access_devname);	\
		FW_SD_FREE_CLS_NAME(thisdev, devpath)	\
	}
#define	FW_SD_FREE_ADDR(thisdev, devpath) {	\
		free((thisdev)->addresses[0]);	\
		FW_SD_FREE_ACC_NAME(thisdev, devpath)	\
	}
#define	FW_SD_FREE_IDENT(thisdev, devpath) {	\
		free((thisdev)->ident);	\
		FW_SD_FREE_ADDR((thisdev), (devpath))	\
	}
#define	FW_SD_FREE_IDENT_VID(thisdev, devpath) {	\
		free((thisdev)->ident->vid);	\
		FW_SD_FREE_IDENT((thisdev), (devpath))	\
	}
#define	FW_SD_FREE_IDENT_PID(thisdev, devpath) {	\
		free((thisdev)->ident->pid);	\
		FW_SD_FREE_IDENT_VID((thisdev), (devpath))	\
	}
#define	FW_SD_FREE_IDENT_ALL(thisdev, devpath) {	\
		free((thisdev)->ident->revid);	\
		FW_SD_FREE_IDENT_PID((thisdev), (devpath))	\
	}

/*
 * This is our default partial write size when we encounter a situation where we
 * need to upgrade disks whose firmware image cannot be done in a single write.
 * While in theory we should just use the maximum transfer size and make sure
 * it's aligned, that's proven to be problematic for some Seagate disks. Hence
 * we just make sure that if partial writes are required that this value fits in
 * the required alignment and in the actual maximum transfer size.
 */
#define	FW_SD_PARTIAL_WRITE_SIZE	(64 * 1024)

/*
 * Declarations required for fwflash
 */
char drivername[] = "sd\0";
int plugin_version = FWPLUGIN_VERSION_2;

/*
 * Data provided by fwflash
 */
extern di_node_t rootnode;
extern struct fw_plugin *self;
extern struct vrfyplugin *verifier;
extern int fwflash_debug;

static char *sdfw_devprefix = "/devices";

static char *sdfw_find_link(di_node_t bnode, char *acc_devname);
static int sdfw_link_cb(di_devlink_t devlink, void *arg);
static int sdfw_idtfy_custmz(struct devicelist *device, char *sp);

/*
 * We don't currently support reading firmware from a disk. If we do eventually
 * support it, we would use the scsi READ BUFFER command to do so.
 */
int
fw_readfw(struct devicelist *flashdev, char *filename)
{

	logmsg(MSG_INFO,
	    "%s: not writing firmware for device %s to file %s\n",
	    flashdev->drvname, flashdev->access_devname, filename);
	logmsg(MSG_ERROR,
	    gettext("\n\nReading of firmware images from %s-attached "
	    "devices is not supported\n\n"),
	    flashdev->drvname);

	return (FWFLASH_SUCCESS);
}


static int
sdfw_read_descriptor(struct devicelist *flashdev, libscsi_hdl_t *hdl,
    libscsi_target_t *targ, uint8_t *align)
{
	spc3_read_buffer_cdb_t *rb_cdb;
	size_t nwritten;
	libscsi_action_t *action = NULL;
	uint8_t descbuf[4];
	sam4_status_t samstatus;

	VERIFY3P(hdl, !=, NULL);
	VERIFY3P(targ, !=, NULL);
	VERIFY3P(align, !=, NULL);

	if ((action = libscsi_action_alloc(hdl, SPC3_CMD_READ_BUFFER,
	    LIBSCSI_AF_READ, descbuf, sizeof (descbuf))) == NULL) {
		logmsg(MSG_ERROR, gettext("%s: failed to alloc scsi action: "
		    "%s\n"),
		    flashdev->drvname, libscsi_errmsg(hdl));
		return (FWFLASH_FAILURE);
	}

	rb_cdb = (spc3_read_buffer_cdb_t *)libscsi_action_get_cdb(action);

	rb_cdb->rbc_mode = SPC3_RB_MODE_DESCRIPTOR;

	/*
	 * Microcode upgrade usually only uses the first buffer ID which is
	 * sequentially indexed from zero. Strictly speaking these are all
	 * vendor defined, but so far most vendors we've seen use index zero
	 * for this.
	 */
	rb_cdb->rbc_bufferid = 0;

	rb_cdb->rbc_allocation_len[0] = 0;
	rb_cdb->rbc_allocation_len[1] = 0;
	rb_cdb->rbc_allocation_len[2] = sizeof (descbuf);

	if (libscsi_exec(action, targ) != 0) {
		logmsg(MSG_ERROR, gettext("%s: failed to execute SCSI buffer "
		    "data read: %s\n"),
		    flashdev->drvname, libscsi_errmsg(hdl));
		libscsi_action_free(action);
		return (FWFLASH_FAILURE);
	}

	if ((samstatus = libscsi_action_get_status(action)) !=
	    SAM4_STATUS_GOOD) {
		int i;
		for (i = 0; i < NSAM4_STATUS; i++) {
			if (samstatus == sam4_status[i].sam_status) {
				logmsg(MSG_ERROR, gettext("%s: SCSI buffer "
				    "data read failed: %s\n"),
				    flashdev->drvname,
				    sam4_status[i].sam_message);
				libscsi_action_free(action);
				return (FWFLASH_FAILURE);
			}
		}
		logmsg(MSG_ERROR, gettext("%s: SCSI buffer data read failed: "
		    "unknown error: %d\n"), flashdev->drvname, samstatus);
		libscsi_action_free(action);
		return (FWFLASH_FAILURE);
	}

	if (libscsi_action_get_buffer(action, NULL, NULL, &nwritten) != 0) {
		logmsg(MSG_ERROR, gettext("%s: failed to get actual data "
		    "size: %s\n"),
		    flashdev->drvname, libscsi_errmsg(hdl));
		libscsi_action_free(action);
		return (FWFLASH_FAILURE);
	}
	libscsi_action_free(action);

	if (nwritten != sizeof (descbuf)) {
		logmsg(MSG_ERROR, gettext("%s: received a short read from the "
		    "SCSI READ BUFFER command, expected %u bytes, read %u\n"),
		    flashdev->drvname, sizeof (descbuf), nwritten);
		return (FWFLASH_FAILURE);
	}

	if (descbuf[0] == 0 && descbuf[1] == 0 && descbuf[2] == 0 &&
	    descbuf[3] == 0) {
		logmsg(MSG_ERROR, gettext("%s: devices %s does not support "
		    "firmware upgrade\n"), verifier->vendor,
		    flashdev->access_devname);
		return (FWFLASH_FAILURE);
	}

	*align = descbuf[0];

	return (FWFLASH_SUCCESS);
}

static int
sdfw_write(struct devicelist *flashdev, libscsi_hdl_t *handle,
    libscsi_target_t *target, size_t len, size_t off, void *buf)
{
	sam4_status_t samstatus;
	libscsi_action_t *action = NULL;
	spc3_write_buffer_cdb_t *wb_cdb;

	logmsg(MSG_INFO, "%s: writing %u bytes of image %s at offset %u from "
	    "address %p\n", flashdev->drvname, len, verifier->imgfile, off,
	    buf);
	logmsg(MSG_INFO, "%s: writing to buffer id %u\n",
	    flashdev->drvname, verifier->flashbuf);

	VERIFY3P(flashdev, !=, NULL);
	VERIFY3P(handle, !=, NULL);
	VERIFY3P(target, !=, NULL);
	VERIFY3P(buf, !=, NULL);
	VERIFY3U(len, >, 0);
	VERIFY3U(off + len, <=, verifier->imgsize);

	action = libscsi_action_alloc(handle, SPC3_CMD_WRITE_BUFFER,
	    LIBSCSI_AF_WRITE | LIBSCSI_AF_RQSENSE | LIBSCSI_AF_ISOLATE, buf,
	    len);
	if (action == NULL) {
		logmsg(MSG_ERROR, gettext("%s: failed to alloc scsi action: "
		    "%s\n"), flashdev->drvname, libscsi_errmsg(handle));
		goto err;
	}

	wb_cdb = (spc3_write_buffer_cdb_t *)libscsi_action_get_cdb(action);

	wb_cdb->wbc_mode = SPC3_WB_MODE_DL_UCODE_OFFS_SAVE;

	wb_cdb->wbc_buffer_offset[0] = (off >> 16) & 0xff;
	wb_cdb->wbc_buffer_offset[1] = (off >> 8) & 0xff;
	wb_cdb->wbc_buffer_offset[2] = off & 0xff;

	wb_cdb->wbc_bufferid = verifier->flashbuf;

	wb_cdb->wbc_parameter_list_len[0] = (len >> 16) & 0xff;
	wb_cdb->wbc_parameter_list_len[1] = (len >> 8) & 0xff;
	wb_cdb->wbc_parameter_list_len[2] = len & 0xff;

	logmsg(MSG_INFO, "%s: spc3_write_buffer_cdb_t opcode: %u\n",
	    flashdev->drvname, wb_cdb->wbc_opcode);

	if (libscsi_exec(action, target) != 0) {
		logmsg(MSG_ERROR, gettext("%s: failed to execute SCSI WRITE "
		    "BUFFER: %s\n"),
		    flashdev->drvname, libscsi_errmsg(handle));
		goto err;
	}

	if ((samstatus = libscsi_action_get_status(action)) ==
	    SAM4_STATUS_CHECK_CONDITION) {
		uint64_t asc = 0, ascq = 0, key = 0;
		const char *code, *keystr;

		if (libscsi_action_parse_sense(action, &key, &asc, &ascq,
		    NULL) != 0) {
			logmsg(MSG_ERROR, gettext("%s: failed to write "
			    "firmware. Received CHECK_CONDITION that cannot be "
			    "parsed.\n"),
			    flashdev->drvname);
			goto err;
		}

		code = libscsi_sense_code_name(asc, ascq);
		keystr = libscsi_sense_key_name(key);

		logmsg(MSG_ERROR, gettext("%s: failed to write firmware: "
		    "received sense key %llu (%s) additional sense code "
		    "0x%llx/0x%llx (%s)\n"), flashdev->drvname, key,
		    keystr != NULL ? keystr : "<unknown>",
		    asc, ascq, code != NULL ? code : "<unknown>");
		goto err;
	} else if (samstatus != SAM4_STATUS_GOOD) {
		int i;

		logmsg(MSG_ERROR, gettext("%s: SCSI buffer data write failed:"),
		    flashdev->drvname);
		for (i = 0; i < NSAM4_STATUS; i++) {
			if (samstatus == sam4_status[i].sam_status) {
				logmsg(MSG_ERROR, gettext("%s\n"),
				    sam4_status[i].sam_message);
				goto err;
			}
		}
		logmsg(MSG_ERROR, gettext("unknown error: %d\n"), samstatus);
		goto err;
	} else {
		logmsg(MSG_INFO, "%s: received STATUS GOOD\n",
		    flashdev->drvname);
	}

	libscsi_action_free(action);
	return (FWFLASH_SUCCESS);

err:
	if (action != NULL)
		libscsi_action_free(action);
	return (FWFLASH_FAILURE);
}

int
fw_writefw(struct devicelist *flashdev)
{
	libscsi_hdl_t	*handle;
	libscsi_target_t *target;
	libscsi_errno_t serr;
	size_t maxxfer, nwrite;
	uint8_t align;
	int ret = FWFLASH_FAILURE;

	if ((verifier == NULL) || (verifier->imgsize == 0) ||
	    (verifier->fwimage == NULL)) {
		/* should _NOT_ happen */
		logmsg(MSG_ERROR,
		    gettext("%s: Firmware image has not been verified\n"),
		    flashdev->drvname);
		return (FWFLASH_FAILURE);
	}

	if ((handle = libscsi_init(LIBSCSI_VERSION, &serr)) == NULL) {
		logmsg(MSG_ERROR, gettext("%s: failed to initialize libscsi\n"),
		    flashdev->drvname);
		return (FWFLASH_FAILURE);
	}

	if ((target = libscsi_open(handle, NULL, flashdev->access_devname)) ==
	    NULL) {
		logmsg(MSG_ERROR,
		    gettext("%s: unable to open device %s\n"),
		    flashdev->drvname, flashdev->access_devname);
		libscsi_fini(handle);
		return (FWFLASH_FAILURE);
	}

	if (libscsi_max_transfer(target, &maxxfer) != 0) {
		logmsg(MSG_ERROR, gettext("%s: failed to determine device "
		    "maximum transfer size: %s\n"), flashdev->drvname,
		    libscsi_errmsg(handle));
		goto err;
	}

	if (sdfw_read_descriptor(flashdev, handle, target, &align) !=
	    FWFLASH_SUCCESS) {
		goto err;
	}

	/*
	 * If the maximum transfer size is less than the maximum image size then
	 * we have to do some additional work. We need to read the descriptor
	 * via a READ BUFFER command and make sure that we support the required
	 * offset alignment. Note that an alignment of 0xff indicates that the
	 * device does not support partial writes and must receive the firmware
	 * in a single WRITE BUFFER.  Otherwise a value in align represents a
	 * required offset alignment of 2^off. From there, we make sure that
	 * this works for our partial write size and that our partial write size
	 * fits in the maximum transfer size.
	 */
	if (maxxfer < verifier->imgsize) {
		logmsg(MSG_INFO, "%s: Maximum transfer is %u, required "
		    "alignment is 2^%d\n", flashdev->drvname, maxxfer, align);
		if (FW_SD_PARTIAL_WRITE_SIZE > maxxfer) {
			logmsg(MSG_ERROR, gettext("%s: cannot write firmware "
			    "image: HBA enforces a maximum transfer size of "
			    "%u bytes, but the default partial transfer size "
			    "is %u bytes\n"), flashdev->drvname, maxxfer,
			    FW_SD_PARTIAL_WRITE_SIZE);
			goto err;
		}
		maxxfer = FW_SD_PARTIAL_WRITE_SIZE;

		if (ffsll(maxxfer) < align || align == 0xff) {
			logmsg(MSG_ERROR, gettext("%s: cannot write firmware "
			    "image: device requires partial writes aligned "
			    "to an unsupported value\n"), flashdev->drvname);
			goto err;
		}

		logmsg(MSG_INFO, "%s: final transfer block size is %u\n",
		    flashdev->drvname, maxxfer);
	}

	logmsg(MSG_INFO, "%s: Writing out %u bytes to %s\n", flashdev->drvname,
	    verifier->imgsize, flashdev->access_devname);
	nwrite = 0;
	for (;;) {
		uintptr_t buf;
		size_t towrite = MIN(maxxfer, verifier->imgsize - nwrite);

		if (towrite == 0)
			break;

		buf = (uintptr_t)verifier->fwimage;
		buf += nwrite;

		if (sdfw_write(flashdev, handle, target, towrite, nwrite,
		    (void *)buf) != FWFLASH_SUCCESS) {
			logmsg(MSG_ERROR, gettext("%s: failed to write to %s "
			    "successfully: %s\n"), flashdev->drvname,
			    flashdev->access_devname, libscsi_errmsg(handle));
			goto err;
		}

		nwrite += towrite;
	}

	logmsg(MSG_ERROR, gettext("Note: For flash based disks "
	    "(SSD, etc). You may need power off the system to wait a "
	    "few minutes for supercap to fully discharge, then power "
	    "on the system again to activate the new firmware\n"));
	ret = FWFLASH_SUCCESS;

err:
	if (target != NULL)
		libscsi_close(handle, target);
	if (handle != NULL)
		libscsi_fini(handle);

	return (ret);
}

/*
 * The fw_identify() function walks the device
 * tree trying to find devices which this plugin
 * can work with.
 *
 * The parameter "start" gives us the starting index number
 * to give the device when we add it to the fw_devices list.
 *
 * firstdev is allocated by us and we add space as needed
 *
 * When we store the desired information, inquiry-serial-no
 * goes in thisdev->addresses[1], and client-guid goes in
 * thisdev->addresses[2].
 */
int
fw_identify(int start)
{
	int idx = start;
	int fw_sata_disk = 0;
	int *exists;
	di_node_t thisnode;
	struct devicelist *newdev = NULL;
	char *devpath = NULL;
	char *driver = NULL;
	char *sp_temp;
	char *sp_temp_cut;

	/* We need to inquiry information manually by sending probe command */
	libscsi_hdl_t *handle;
	libscsi_target_t *target;
	libscsi_errno_t serr;

	/* Just in case we've got an FC-attached device on sparc */
	if (strcmp(self->drvname, "ssd") == 0) {
		driver = self->drvname;
	} else
		driver = drivername;

	thisnode = di_drv_first_node(driver, rootnode);

	if (thisnode == DI_NODE_NIL) {
		logmsg(MSG_INFO, "No %s nodes in this system\n", driver);
		return (FWFLASH_FAILURE);
	}

	if ((handle = libscsi_init(LIBSCSI_VERSION, &serr)) == NULL) {
		logmsg(MSG_ERROR, gettext("%s: failed to initialize "
		    "libscsi\n"), newdev->drvname);
		return (FWFLASH_FAILURE);
	}

	/* we've found one, at least */
	for (; thisnode != DI_NODE_NIL; thisnode = di_drv_next_node(thisnode)) {
		/* Need to free by di_devfs_path_free */
		if ((devpath = di_devfs_path(thisnode)) == NULL) {
			logmsg(MSG_INFO, "unable to get device path for "
			    "current node with errno %d\n", errno);
			continue;
		}
		/*
		 * We check if this is removable device, in which case
		 * we really aren't interested, so exit stage left
		 */
		if (di_prop_lookup_ints(DDI_DEV_T_ANY, thisnode,
		    "removable-media", &exists) > -1) {
			logmsg(MSG_INFO,
			    "%s: not interested in removable media device\n"
			    "%s\n", driver, devpath);
			FW_SD_FREE_DEVPATH(devpath)
			continue;
		}

		if ((newdev = calloc(1, sizeof (struct devicelist))) ==
		    NULL) {
			logmsg(MSG_ERROR,
			    gettext("%s: identification function unable "
			    "to allocate space for device entry\n"),
			    driver);
			libscsi_fini(handle);
			FW_SD_FREE_DEVPATH(devpath)
			return (FWFLASH_FAILURE);
		}

		if ((newdev->drvname = calloc(1, strlen(driver) + 1)) ==
		    NULL) {
			logmsg(MSG_ERROR,
			    gettext("%s: Unable to allocate space to store a "
			    "driver name\n"), driver);
			libscsi_fini(handle);
			FW_SD_FREE_DEVICELIST(newdev, devpath)
			return (FWFLASH_FAILURE);
		}
		(void) strlcpy(newdev->drvname, driver, strlen(driver) + 1);

		if ((newdev->classname = calloc(1, strlen(driver) + 1)) ==
		    NULL) {
			logmsg(MSG_ERROR,
			    gettext("%s: Unable to allocate space for a class "
			    "name\n"), drivername);
			libscsi_fini(handle);
			FW_SD_FREE_DRV_NAME(newdev, devpath)
			return (FWFLASH_FAILURE);
		}
		(void) strlcpy(newdev->classname, driver, strlen(driver) + 1);

		/* Get the access name for current node */
		if ((newdev->access_devname = calloc(1, MAXPATHLEN)) == NULL) {
			logmsg(MSG_ERROR,
			    gettext("%s: Unable to allocate space for a devfs "
			    "name\n"), driver);
			libscsi_fini(handle);
			FW_SD_FREE_CLS_NAME(newdev, devpath)
			return (FWFLASH_FAILURE);
		}

		/* The slice number may be 2 or 0, we will try 2 first */
		(void) snprintf(newdev->access_devname, MAXPATHLEN,
		    "%s%s:c,raw", sdfw_devprefix, devpath);
		if ((target = libscsi_open(handle, NULL,
		    newdev->access_devname)) == NULL) {
			/* try 0 for EFI label */
			(void) snprintf(newdev->access_devname, MAXPATHLEN,
			    "%s%s:a,raw", sdfw_devprefix, devpath);
			if ((target = libscsi_open(handle, NULL,
			    newdev->access_devname)) == NULL) {
				logmsg(MSG_INFO,
				    "%s: unable to open device %s\n",
				    newdev->drvname, newdev->access_devname);
				FW_SD_FREE_ACC_NAME(newdev, devpath)
				continue;
			}
		}

		/* and the /dev/rdsk/ name */
		if ((newdev->addresses[0] = sdfw_find_link(thisnode,
		    newdev->access_devname)) == NULL) {
			libscsi_fini(handle);
			FW_SD_FREE_ACC_NAME(newdev, devpath)
			return (FWFLASH_FAILURE);
		}

		/*
		 * Only alloc as much as we truly need, and DON'T forget
		 * that libdevinfo manages the memory!
		 */
		if ((newdev->ident = calloc(1, sizeof (struct vpr))) == NULL) {
			logmsg(MSG_ERROR,
			    gettext("%s: Unable to allocate space for SCSI "
			    "INQUIRY data\n"), driver);
			libscsi_fini(handle);
			FW_SD_FREE_ADDR(newdev, devpath)
			return (FWFLASH_FAILURE);
		}

		/* We don't use new->ident->encap_ident currently */

		/* Retrive information by using libscsi */
		/* Vendor ID */
		sp_temp = (char *)libscsi_vendor(target);
		if (strncmp(sp_temp, "ATA", 3) == 0) {
			/* We need to do customize the output for SATA disks */
			fw_sata_disk = 1;
		} else {
			fw_sata_disk = 0;
			if ((newdev->ident->vid =
			    calloc(1, strlen(sp_temp) + 1)) == NULL ||
			    sp_temp == NULL) {
				if (!sp_temp) {
					logmsg(MSG_ERROR, gettext("%s: unable "
					    "to get vendor id of %s\n"),
					    newdev->drvname,
					    newdev->access_devname);
				} else {
					logmsg(MSG_ERROR, gettext("Memory "
					    "allocation failure\n"));
				}

				libscsi_close(handle, target);
				libscsi_fini(handle);
				FW_SD_FREE_IDENT(newdev, devpath)
				return (FWFLASH_FAILURE);
			}
			strlcpy(newdev->ident->vid, sp_temp,
			    strlen(sp_temp) + 1);
		}

		/* Product ID */
		sp_temp = (char *)libscsi_product(target);
		if (fw_sata_disk) {
			sp_temp_cut = strchr(sp_temp, ' ');
			if (!sp_temp_cut) {
				/*
				 * There is no SPACE character in the PID field
				 * Customize strings for special SATA disks
				 */
				if (sdfw_idtfy_custmz(newdev, sp_temp)
				    != FWFLASH_SUCCESS) {
					libscsi_close(handle, target);
					libscsi_fini(handle);
					FW_SD_FREE_IDENT(newdev, devpath)
					return (FWFLASH_FAILURE);
				}
			} else {
				/* The first string is vendor id */
				if ((newdev->ident->vid = calloc(1,
				    (sp_temp_cut - sp_temp + 1))) == NULL) {
					logmsg(MSG_ERROR, gettext("%s: unable "
					    "to get sata vendor id of %s\n"),
					    newdev->drvname,
					    newdev->access_devname);

					libscsi_close(handle, target);
					libscsi_fini(handle);
					FW_SD_FREE_IDENT(newdev, devpath)
					return (FWFLASH_FAILURE);
				}
				strlcpy(newdev->ident->vid, sp_temp,
				    sp_temp_cut - sp_temp + 1);

				/* The second string is product id */
				if ((newdev->ident->pid =
				    calloc(1, strlen(sp_temp) -
				    strlen(newdev->ident->vid))) == NULL) {
					logmsg(MSG_ERROR, gettext("%s: unable "
					    "to get sata product id of %s\n"),
					    newdev->drvname,
					    newdev->access_devname);

					libscsi_close(handle, target);
					libscsi_fini(handle);
					FW_SD_FREE_IDENT_VID(newdev, devpath)
					return (FWFLASH_FAILURE);
				}
				strlcpy(newdev->ident->pid, sp_temp_cut + 1,
				    strlen(sp_temp) -
				    strlen(newdev->ident->vid));
			}
		} else {
			if ((newdev->ident->pid =
			    calloc(1, strlen(sp_temp) + 1)) == NULL ||
			    sp_temp == NULL) {
				logmsg(MSG_ERROR, gettext("%s: unable to get "
				    "product id of %s\n"), newdev->drvname,
				    newdev->access_devname);
				FW_SD_FREE_IDENT_VID(newdev, devpath)
				libscsi_close(handle, target);
				libscsi_fini(handle);
				return (FWFLASH_FAILURE);
			}
			strlcpy(newdev->ident->pid, sp_temp,
			    strlen(sp_temp) + 1);
		}

		/* Revision ID */
		sp_temp = (char *)libscsi_revision(target);
		if ((newdev->ident->revid = calloc(1, strlen(sp_temp) + 1)) ==
		    NULL || sp_temp == NULL) {
			logmsg(MSG_ERROR, gettext("%s: unable to get revision "
			    "id of %s\n"), newdev->drvname,
			    newdev->access_devname);
			libscsi_close(handle, target);
			libscsi_fini(handle);
			FW_SD_FREE_IDENT_PID(newdev, devpath)
			return (FWFLASH_FAILURE);
		}
		strlcpy(newdev->ident->revid, sp_temp, strlen(sp_temp) + 1);

		/* Finish using libscsi */
		libscsi_close(handle, target);

		if (di_prop_lookup_strings(DDI_DEV_T_ANY, thisnode,
		    "inquiry-serial-no", &newdev->addresses[1]) < 0) {
			logmsg(MSG_INFO,
			    "%s: no inquiry-serial-no property for %s\n",
			    driver, newdev->access_devname);
			logmsg(MSG_INFO, "The errno is %d\n", errno);
		}

		if ((di_prop_lookup_strings(DDI_DEV_T_ANY, thisnode,
		    "client-guid", &newdev->addresses[2])) < 0) {
			logmsg(MSG_INFO,
			    "%s: no client-guid property "
			    "for device %s\n",
			    driver, newdev->access_devname);
			/* try fallback */
			if ((di_prop_lookup_strings(DDI_DEV_T_ANY, thisnode,
			    "guid", &newdev->addresses[2])) < 0) {
				logmsg(MSG_INFO,
				    "%s: no guid property for device %s\n",
				    driver, newdev->access_devname);
			}
		} else {
			logmsg(MSG_INFO,
			    "client-guid property: %s\n",
			    newdev->addresses[2]);
		}

		newdev->index = idx;
		++idx;
		newdev->plugin = self;

		TAILQ_INSERT_TAIL(fw_devices, newdev, nextdev);
		FW_SD_FREE_DEVPATH(devpath)
	}
	libscsi_fini(handle);

	/* Check if sd targets presented are all unflashable. */
	if (idx == start)
		return (FWFLASH_FAILURE);

	if (fwflash_debug != 0) {
		struct devicelist *tempdev;

		TAILQ_FOREACH(tempdev, fw_devices, nextdev) {
			logmsg(MSG_INFO, "%s:fw_identify:\n",
			    driver);
			logmsg(MSG_INFO,
			    "\ttempdev @ 0x%lx\n"
			    "\t\taccess_devname: %s\n"
			    "\t\tdrvname: %s\tclassname: %s\n"
			    "\t\tident->vid:   %s\n"
			    "\t\tident->pid:   %s\n"
			    "\t\tident->revid: %s\n"
			    "\t\tindex:	%d\n"
			    "\t\taddress[0]:   %s\n"
			    "\t\taddress[1]:   %s\n"
			    "\t\taddress[2]:   %s\n"
			    "\t\tplugin @ 0x%lx\n\n",
			    &tempdev,
			    tempdev->access_devname,
			    tempdev->drvname, newdev->classname,
			    tempdev->ident->vid,
			    tempdev->ident->pid,
			    tempdev->ident->revid,
			    tempdev->index,
			    tempdev->addresses[0],
			    (tempdev->addresses[1] ? tempdev->addresses[1] :
			    "(not supported)"),
			    (tempdev->addresses[2] ? tempdev->addresses[2] :
			    "(not supported)"),
			    &tempdev->plugin);
		}
	}
	return (FWFLASH_SUCCESS);
}

int
fw_devinfo(struct devicelist *thisdev)
{
	fprintf(stdout, gettext("Device[%d]\t\t\t%s\n"
	    "  Class [%s]\t\t\t%s\n"),
	    thisdev->index, thisdev->access_devname,
	    thisdev->classname, thisdev->addresses[0]);

	fprintf(stdout,
	    gettext(
	    "\tVendor\t\t\t: %s\n"
	    "\tProduct\t\t\t: %s\n"
	    "\tFirmware revision\t: %-s\n"
	    "\tInquiry Serial Number   : %-s\n"
	    "\tGUID\t\t\t: %s\n"),
	    thisdev->ident->vid,
	    thisdev->ident->pid,
	    thisdev->ident->revid,
	    (thisdev->addresses[1] ? thisdev->addresses[1] :
	    "(not supported)"),
	    (thisdev->addresses[2] ? thisdev->addresses[2] :
	    "(not supported)"));

	fprintf(stdout, "\n\n");

	return (FWFLASH_SUCCESS);
}

void
fw_cleanup(struct devicelist *thisdev)
{
	/*
	 * Function to clean up all the memory allocated
	 * by this plugin, for thisdev.
	 */
	free(thisdev->access_devname);
	free(thisdev->drvname);
	free(thisdev->classname);

	/*
	 * Note that we DO NOT free addresses[1,2] because _IF_
	 * these elements are valid, they are managed by libdevinfo
	 * and we didn't allocate any space for them.
	 */
	free(thisdev->addresses[0]);

	/* what this points to is freed in common code */
	thisdev->plugin = NULL;

	free(thisdev->ident->vid);
	free(thisdev->ident->pid);
	free(thisdev->ident->revid);

	thisdev->ident = NULL;
}

/*
 * Helper functions
 */
static int
sdfw_link_cb(di_devlink_t devlink, void *arg)
{
	const char *result;

	result = di_devlink_path(devlink);
	if (result == NULL) {
		arg = (void *)"(null)";
	} else {
		(void) strlcpy(arg, result, strlen(result) + 1);
	}

	logmsg(MSG_INFO, "\nsdfw_link_cb::linkdata->resultstr = %s\n",
	    ((result != NULL) ? result : "(null)"));

	return (DI_WALK_CONTINUE);
}

static char *
sdfw_find_link(di_node_t bnode, char *acc_devname)
{
	di_minor_t devminor = DI_MINOR_NIL;
	di_devlink_handle_t hdl;
	char *cbresult = NULL;
	char linkname[] = "^rdsk/\0";

	if (bnode == DI_NODE_NIL) {
		logmsg(MSG_ERROR,
		    gettext("sdfw_find_link must be called with non-null "
		    "di_node_t\n"));
		return (NULL);
	}

	if ((cbresult = calloc(1, MAXPATHLEN)) == NULL) {
		logmsg(MSG_ERROR, gettext("unable to allocate space for dev "
		    "link\n"));
		return (NULL);
	}

	devminor = di_minor_next(bnode, devminor);
	errno = 0;
	hdl = di_devlink_init(di_devfs_minor_path(devminor), DI_MAKE_LINK);
	if (hdl == NULL) {
		if (errno == EPERM || errno == EACCES) {
			logmsg(MSG_ERROR,
			    gettext("%s: You must be super-user to use this "
			    "plugin.\n"), drivername);
		} else {
			logmsg(MSG_ERROR,
			    gettext("unable to take devlink snapshot: %s\n"),
			    strerror(errno));
		}
		free(cbresult);
		return (NULL);
	}

	errno = 0;
	if (di_devlink_walk(hdl, linkname, acc_devname + strlen(sdfw_devprefix),
	    DI_PRIMARY_LINK, (void *)cbresult, sdfw_link_cb) < 0) {
		logmsg(MSG_ERROR,
		    gettext("Unable to walk devlink snapshot for %s: %s\n"),
		    acc_devname, strerror(errno));
		free(cbresult);
		return (NULL);
	}

	if (di_devlink_fini(&hdl) < 0) {
		logmsg(MSG_ERROR,
		    gettext("Unable to close devlink snapshot: %s\n"),
		    strerror(errno));
	}

	logmsg(MSG_INFO, "cbresult: %s\n", cbresult);
	return (cbresult);
}

static int
sdfw_idtfy_custmz(struct devicelist *device, char *sp)
{
	/* vid customization */
	if (strncmp(sp, "ST", 2) == 0) {
		/* Customize retail Seagate disks */
		if ((device->ident->vid = strdup("SEAGATE")) == NULL) {
			return (FWFLASH_FAILURE);
		}
	} else if (strncmp(sp, "SSD", 3) == 0) {
		/* Customize retail INTEL disks */
		if ((device->ident->vid = strdup("INTEL")) == NULL) {
			return (FWFLASH_FAILURE);
		}
	} else {
		/* disks to do in the future, fill 'ATA' first */
		if ((device->ident->vid = strdup("ATA")) == NULL) {
			return (FWFLASH_FAILURE);
		}
	}

	/* pid customization */
	if ((device->ident->pid = calloc(1, strlen(sp) + 1)) == NULL) {
		logmsg(MSG_ERROR, gettext("Unable to allocate space for "
		    "product id\n"));
		free(device->ident->vid);
		return (FWFLASH_FAILURE);
	}
	strlcpy(device->ident->pid, sp, strlen(sp) + 1);

	return (FWFLASH_SUCCESS);
}
