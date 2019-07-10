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
 */

/*
 * ses (SCSI Generic Device) specific functions.
 */

#include <libnvpair.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/queue.h>
#include <fcntl.h>
#include <string.h>
#include <scsi/libscsi.h>
#include <scsi/libses.h>
#include <libintl.h> /* for gettext(3c) */
#include <fwflash/fwflash.h>


#define	VIDLEN		0x08
#define	PIDLEN		0x10
#define	REVLEN		0x04
#define	SASADDRLEN	0x10
#define	PCBUFLEN	0x40
#define	RQBUFLEN	0xfe
#define	STATBUFLEN	0xfe
#define	INQBUFLEN	0x80

/* useful defines */
#define	UCODE_CHECK_STATUS	0
#define	UCODE_CHECK_SUPPORTED	1

typedef struct ucode_statdesc {
	uint64_t	us_value;
	const char	*us_desc;
	boolean_t	us_pending;
	boolean_t	us_iserr;
} ucode_statdesc_t;

static ucode_statdesc_t ucode_statdesc_table[] = {
	{ SES2_DLUCODE_S_NOP,		"none",	B_FALSE, B_FALSE },
	{ SES2_DLUCODE_S_INPROGRESS,	"in progress", B_TRUE, B_FALSE },
	{ SES2_DLUCODE_S_SAVING,	"saved", B_TRUE, B_FALSE },
	{ SES2_DLUCODE_S_COMPLETE_NOW,	"completed (available)", B_FALSE,
	    B_FALSE },
	{ SES2_DLUCODE_S_COMPLETE_AT_RESET,
	    "completed (need reset or power on)", B_FALSE, B_FALSE },
	{ SES2_DLUCODE_S_COMPLETE_AT_POWERON,	"completed (need power on)",
	    B_FALSE, B_FALSE },
	{ SES2_DLUCODE_S_PAGE_ERR,	"page error (offset %d)",
	    B_FALSE, B_TRUE },
	{ SES2_DLUCODE_S_IMAGE_ERR,	"invalid image",
	    B_FALSE, B_TRUE },
	{ SES2_DLUCODE_S_TIMEOUT,	"download timeout",
	    B_FALSE, B_TRUE },
	{ SES2_DLUCODE_S_INTERNAL_NEEDIMAGE,
	    "internal error (NEED NEW IMAGE BEFORE RESET)",
	    B_FALSE, B_TRUE },
	{ SES2_DLUCODE_S_INTERNAL_SAFE,
	    "internal error (reset to revert to backup)",
	    B_FALSE, B_TRUE },
};

#define	NUCODE_STATUS	\
	(sizeof (ucode_statdesc_table) / sizeof (ucode_statdesc_table[0]))

typedef struct ucode_status {
	uint64_t	us_status;
	boolean_t	us_iserr;
	boolean_t	us_pending;
	char		us_desc[128];
} ucode_status_t;

typedef struct ucode_wait {
	uint64_t	uw_prevstatus;
	boolean_t	uw_pending;
	ses_node_t	*uw_oldnp;
} ucode_wait_t;


typedef struct sam4_statdesc {
	int status;
	char *message;
} sam4_statdesc_t;


static sam4_statdesc_t sam4_status[] = {
	{ SAM4_STATUS_GOOD, "Status: GOOD (success)" },
	{ SAM4_STATUS_CHECK_CONDITION, "Status: CHECK CONDITION" },
	{ SAM4_STATUS_CONDITION_MET, "Status: CONDITION MET" },
	{ SAM4_STATUS_BUSY, "Status: Device is BUSY" },
	{ SAM4_STATUS_RESERVATION_CONFLICT, "Status: Device is RESERVED" },
	{ SAM4_STATUS_TASK_SET_FULL,
	    "Status: TASK SET FULL (insufficient resources in command queue" },
	{ SAM4_STATUS_TASK_ABORTED, "Status: TASK ABORTED" },
	{ 0, NULL }
};

#define	NSAM4_STATUS	\
	(sizeof (sam4_status) / sizeof (sam4_status[0]))



char drivername[] = "ses\0";
static char *devprefix = "/devices";
static char *sessuffix = ":0";
static char *sgensuffix = ":ses";


static ses_target_t *ses_target;

extern di_node_t rootnode;
extern int errno;
extern struct fw_plugin *self;
extern struct vrfyplugin *verifier;
extern int fwflash_debug;


/* required functions for this plugin */
int fw_readfw(struct devicelist *device, char *filename);
int fw_writefw(struct devicelist *device);
int fw_identify(int start);
int fw_devinfo(struct devicelist *thisdev);


/* helper functions */
static int print_updated_status(ses_node_t *np, void *arg);
static int get_status(nvlist_t *props, ucode_status_t *sp);
static int sendimg(ses_node_t *np, void *data);
static int scsi_writebuf();

/*
 * We don't currently support reading firmware from a SAS
 * expander. If we do eventually support it, we would use
 * the scsi READ BUFFER command to do so.
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


/*
 * If we're invoking fw_writefw, then flashdev is a valid,
 * flashable device supporting the SES2 Download Microcode Diagnostic
 * Control page (0x0e).
 *
 * If verifier is null, then we haven't been called following a firmware
 * image verification load operation.
 *
 * *THIS* function uses scsi SEND DIAGNOSTIC/download microcode to
 * achieve the task... if you chase down to the bottom of libses you
 * can see that too.
 */
int
fw_writefw(struct devicelist *flashdev)
{
	int rv = FWFLASH_FAILURE;
	nvlist_t *nvl;
	ses_snap_t *snapshot;
	ses_node_t *targetnode;

	if ((verifier == NULL) || (verifier->imgsize == 0) ||
	    (verifier->fwimage == NULL)) {
		/* should _not_ happen */
		logmsg(MSG_ERROR,
		    gettext("%s: Firmware image has not "
		    "been verified.\n"),
		    flashdev->drvname);
		return (FWFLASH_FAILURE);
	}

	if (nvlist_alloc(&nvl, NV_UNIQUE_NAME, 0) != 0 ||
	    nvlist_add_uint64(nvl, SES_CTL_PROP_UCODE_MODE,
	    SES_DLUCODE_M_WITH_OFFS) != 0) {
		logmsg(MSG_ERROR,
		    gettext("%s: Unable to allocate "
		    "space for device prop list\n"),
		    flashdev->drvname);
		return (FWFLASH_FAILURE);
	}

	fprintf(stdout, "\n"); /* get a fresh line for progress updates */

	if (nvlist_add_uint64(nvl, SES_CTL_PROP_UCODE_BUFID,
	    verifier->flashbuf) != 0) {
		logmsg(MSG_ERROR,
		    gettext("%s: Unable to add buffer id "
		    "property, hence unable to flash device\n"),
		    flashdev->drvname);
		goto cancel;
	}

	if (nvlist_add_byte_array(nvl, SES_CTL_PROP_UCODE_DATA,
	    (uint8_t *)verifier->fwimage, verifier->imgsize) != 0) {
		logmsg(MSG_ERROR,
		    "%s: Out of memory for property addition\n",
		    flashdev->drvname);
		goto cancel;
	}

	if ((ses_target =
	    ses_open(LIBSES_VERSION, flashdev->access_devname)) == NULL) {
		logmsg(MSG_ERROR,
		    gettext("%s: Unable to open flashable device %s\n"),
		    flashdev->drvname, flashdev->access_devname);
		goto cancel;
	}

	snapshot = ses_snap_hold(ses_target);

	if ((targetnode = ses_snap_primary_enclosure(snapshot)) == NULL) {
		logmsg(MSG_ERROR,
		    gettext("%s: Unable to locate primary enclosure for "
		    "device %s\n"),
		    flashdev->access_devname);
	} else {
		rv = sendimg(targetnode, nvl);
		if (rv == FWFLASH_SUCCESS) {
			logmsg(MSG_ERROR,
			    gettext("%s: Done. New image will be active "
			    "after the system is rebooted.\n\n"),
			    flashdev->drvname);
		} else {
			logmsg(MSG_INFO,
			    "%s: unable to flash image %s to device %s\n\n",
			    flashdev->drvname, verifier->imgfile,
			    flashdev->access_devname);
		}
	}

	ses_snap_rele(snapshot);
	ses_close(ses_target);
cancel:
	nvlist_free(nvl);

	return (rv);
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
 */
int
fw_identify(int start)
{

	int rv = FWFLASH_FAILURE;
	di_node_t thisnode;
	struct devicelist *newdev;
	char *devpath;
	char *devsuffix;
	char *driver;
	int idx = start;
	size_t devlength = 0;
	nvlist_t *props;
	ses_snap_t *snapshot;
	ses_node_t *rootnodep, *nodep;


	if (strcmp(self->drvname, "sgen") == 0) {
		devsuffix = sgensuffix;
		driver = self->drvname;
	} else {
		devsuffix = sessuffix;
		driver = drivername;
	}

	thisnode = di_drv_first_node(driver, rootnode);

	if (thisnode == DI_NODE_NIL) {
		logmsg(MSG_INFO, gettext("No %s nodes in this system\n"),
		    driver);
		return (FWFLASH_FAILURE);
	}

	if ((devpath = calloc(1, MAXPATHLEN + 1)) == NULL) {
		logmsg(MSG_ERROR,
		    gettext("%s: Unable to allocate space "
		    "for a device node\n"),
		    driver);
		return (FWFLASH_FAILURE);
	}

	/* we've found one, at least */

	for (; thisnode != DI_NODE_NIL; thisnode = di_drv_next_node(thisnode)) {

		devpath = di_devfs_path(thisnode);

		if ((newdev = calloc(1, sizeof (struct devicelist)))
		    == NULL) {
			logmsg(MSG_ERROR,
			    gettext("%s: identification function unable "
			    "to allocate space for device entry\n"),
			    driver);
			free(devpath);
			return (FWFLASH_FAILURE);
		}

		/* calloc enough for /devices + devpath + devsuffix + '\0' */
		devlength = strlen(devpath) + strlen(devprefix) +
		    strlen(devsuffix) + 2;

		if ((newdev->access_devname = calloc(1, devlength)) == NULL) {
			logmsg(MSG_ERROR,
			    gettext("%s: Unable to allocate "
			    "space for a devfs name\n"),
			    driver);
			free(devpath);
			free(newdev);
			return (FWFLASH_FAILURE);
		}
		snprintf(newdev->access_devname, devlength,
		    "%s%s%s", devprefix, devpath, devsuffix);

		if ((newdev->drvname = calloc(1, strlen(driver) + 1))
		    == NULL) {
			logmsg(MSG_ERROR,
			    gettext("%s: Unable to allocate "
			    "space to store a driver name\n"),
			    driver);
			free(newdev->access_devname);
			free(newdev);
			free(devpath);
			return (FWFLASH_FAILURE);
		}
		(void) strlcpy(newdev->drvname, driver,
		    strlen(driver) + 1);

		if ((newdev->classname = calloc(1, strlen(driver) + 1))
		    == NULL) {
			logmsg(MSG_ERROR,
			    gettext("%s: Unable to malloc "
			    "space for a class name\n"),
			    drivername);
			free(newdev->access_devname);
			free(newdev->drvname);
			free(newdev);
			free(devpath);
			return (FWFLASH_FAILURE);
		}
		(void) strlcpy(newdev->classname, driver,
		    strlen(driver) + 1);

		/*
		 * Only alloc as much as we truly need, and DON'T forget
		 * that libnvpair manages the memory for property lookups!
		 * The same goes for libdevinfo properties.
		 *
		 * Also note that we're allocating here before we try to
		 * ses_open() the target, because if we can't allocate
		 * sufficient space then we might as well go home.
		 */
		newdev->ident = calloc(1, VIDLEN + PIDLEN + REVLEN + 3);
		if (newdev->ident == NULL) {
			logmsg(MSG_ERROR,
			    gettext("%s: Unable to malloc space for"
			    "SCSI INQUIRY data\n"), driver);
			free(newdev->classname);
			free(newdev->drvname);
			free(newdev->access_devname);
			free(newdev);
			free(devpath);
			return (FWFLASH_FAILURE);
		}

		if ((ses_target =
		    ses_open(LIBSES_VERSION, newdev->access_devname))
		    == NULL) {
			logmsg(MSG_INFO,
			    gettext("%s: Unable to open device %s\n"),
			    driver, newdev->access_devname);
			free(newdev->ident);
			free(newdev->classname);
			free(newdev->access_devname);
			free(newdev->drvname);
			free(newdev);
			free(devpath);
			continue;
		}
		snapshot = ses_snap_hold(ses_target);
		rootnodep = ses_root_node(snapshot);

		/*
		 * If the node has no properties, or the INQUIRY properties
		 * don't exist, this device does not comply with SES2 so we
		 * won't touch it.
		 */
		if ((props = ses_node_props(rootnodep)) == NULL) {
			free(newdev->ident);
			ses_snap_rele(snapshot);
			ses_close(ses_target);
			free(newdev->classname);
			free(newdev->access_devname);
			free(newdev->drvname);
			free(newdev);
			free(devpath);
			continue;
		}

		if ((nvlist_lookup_string(props, SCSI_PROP_VENDOR,
		    &newdev->ident->vid) != 0) ||
		    (nvlist_lookup_string(props, SCSI_PROP_PRODUCT,
		    &newdev->ident->pid) != 0) ||
		    (nvlist_lookup_string(props, SCSI_PROP_REVISION,
		    &newdev->ident->revid) != 0)) {
			free(newdev->ident);
			ses_snap_rele(snapshot);
			ses_close(ses_target);
			free(newdev->classname);
			free(newdev->access_devname);
			free(newdev->drvname);
			free(newdev);
			free(devpath);
			continue;
		}

		nodep = ses_snap_primary_enclosure(snapshot);

		if ((props = ses_node_props(nodep)) == NULL) {
			free(newdev->ident);
			ses_snap_rele(snapshot);
			ses_close(ses_target);
			free(newdev->classname);
			free(newdev->access_devname);
			free(newdev->drvname);
			free(newdev);
			free(devpath);
			continue;
		}

		logmsg(MSG_INFO,
		    "\nvid: %s\npid: %s\nrevid: %s\n",
		    newdev->ident->vid,
		    newdev->ident->pid,
		    newdev->ident->revid);

		if (nvlist_lookup_string(props, LIBSES_EN_PROP_CSN,
		    &newdev->addresses[0]) == 0) {
			logmsg(MSG_INFO,
			    "Chassis Serial Number: %s\n",
			    newdev->addresses[0]);
		} else
			logmsg(MSG_INFO,
			    "%s: no chassis-serial-number property "
			    "for device %s\n",
			    driver, newdev->access_devname);


		rv = di_prop_lookup_strings(DDI_DEV_T_ANY,
		    thisnode, "target-port", &newdev->addresses[1]);
		if (rv < 0) {
			logmsg(MSG_INFO,
			    "%s: no target-port property "
			    "for device %s\n",
			    driver, newdev->access_devname);
		} else
			logmsg(MSG_INFO,
			    "target-port property: %s\n",
			    newdev->addresses[1]);


		newdev->index = idx;
		++idx;
		newdev->plugin = self;

		ses_snap_rele(snapshot);
		TAILQ_INSERT_TAIL(fw_devices, newdev, nextdev);
	}


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
			    "\t\tindex:        %d\n"
			    "\t\taddress[0]:   %s\n"
			    "\t\taddress[1]:   %s\n"
			    "\t\tplugin @ 0x%lx\n\n",
			    &tempdev,
			    tempdev->access_devname,
			    tempdev->drvname, newdev->classname,
			    tempdev->ident->vid,
			    tempdev->ident->pid,
			    tempdev->ident->revid,
			    tempdev->index,
			    (tempdev->addresses[0] ? tempdev->addresses[0] :
			    "(not supported)"),
			    (tempdev->addresses[1] ? tempdev->addresses[1] :
			    "(not supported)"),
			    &tempdev->plugin);
		}
	}

	return (FWFLASH_SUCCESS);
}



int
fw_devinfo(struct devicelist *thisdev)
{

	fprintf(stdout, gettext("Device[%d] %s\n  Class [%s]\n"),
	    thisdev->index, thisdev->access_devname, thisdev->classname);

	fprintf(stdout,
	    gettext("\tVendor                 : %s\n"
	    "\tProduct                : %s\n"
	    "\tFirmware revision      : %s\n"
	    "\tChassis Serial Number  : %s\n"
	    "\tTarget-port identifier : %s\n"),
	    thisdev->ident->vid,
	    thisdev->ident->pid,
	    thisdev->ident->revid,
	    (thisdev->addresses[0] ? thisdev->addresses[0] :
	    "(not supported)"),
	    (thisdev->addresses[1] ? thisdev->addresses[1] :
	    "(not supported)"));

	fprintf(stdout, "\n\n");

	return (FWFLASH_SUCCESS);
}





/*ARGSUSED*/
static int
get_status(nvlist_t *props, ucode_status_t *sp)
{
	int i;
	uint64_t status, astatus;

	if (nvlist_lookup_uint64(props, SES_EN_PROP_UCODE, &status) != 0) {
		sp->us_status = -1ULL;
		(void) snprintf(sp->us_desc, sizeof (sp->us_desc),
		    "not supported");
		return (FWFLASH_FAILURE);
	}

	if (nvlist_lookup_uint64(props, SES_EN_PROP_UCODE_A,
	    &astatus) != 0) {
		logmsg(MSG_ERROR,
		    gettext("\nError: Unable to retrieve current status\n"));
		return (FWFLASH_FAILURE);
	}

	for (i = 0; i < NUCODE_STATUS; i++) {
		if (ucode_statdesc_table[i].us_value == status)
			break;
	}

	sp->us_status = status;

	if (i == NUCODE_STATUS) {
		(void) snprintf(sp->us_desc, sizeof (sp->us_desc),
		    "unknown (0x%02x)", (int)status);
		sp->us_iserr = sp->us_pending = B_TRUE;
		return (FWFLASH_FAILURE);
	} else {
		/* LINTED */
		(void) snprintf(sp->us_desc, sizeof (sp->us_desc),
		    ucode_statdesc_table[i].us_desc, (int)astatus);
		sp->us_iserr = ucode_statdesc_table[i].us_iserr;
		sp->us_pending = ucode_statdesc_table[i].us_pending;
	}

	return (FWFLASH_SUCCESS);
}


static int
print_updated_status(ses_node_t *np, void *arg)
{
	ucode_wait_t *uwp = arg;
	nvlist_t *props;
	ucode_status_t status;


	if ((props = ses_node_props(np)) == NULL) {
		return (FWFLASH_FAILURE);
	}

	if (get_status(props, &status) != FWFLASH_SUCCESS)
		return (FWFLASH_FAILURE);

	if (status.us_status != uwp->uw_prevstatus)
		(void) printf("%30s: %s\n", "status", status.us_desc);

	uwp->uw_prevstatus = status.us_status;
	uwp->uw_pending = status.us_pending;

	if (status.us_iserr) {
		logmsg(MSG_INFO,
		    "libses: status.us_iserr: 0x%0x\n",
		    status.us_iserr);
		return (FWFLASH_FAILURE);
	}
	return (FWFLASH_SUCCESS);
}

/*ARGSUSED*/
static int
sendimg(ses_node_t *np, void *data)
{
	nvlist_t *props;
	nvlist_t *arg = data;
	char *vendor, *product, *revision, *csn;
	char buf[128];
	ses_snap_t *newsnap;
	int ret;
	ucode_status_t statdesc;
	ucode_wait_t wait;
	uint8_t *imagedata;
	uint_t len;


	/* If we've been called without data, eject */
	if (nvlist_lookup_byte_array(arg, SES_CTL_PROP_UCODE_DATA,
	    &imagedata, &len) != 0) {
		return (FWFLASH_FAILURE);
	}

	props = ses_node_props(np);
	if ((props == NULL) ||
	    (nvlist_lookup_string(props, SES_EN_PROP_VID, &vendor) != 0) ||
	    (nvlist_lookup_string(props, SES_EN_PROP_PID, &product) != 0) ||
	    (nvlist_lookup_string(props, SES_EN_PROP_REV, &revision) != 0) ||
	    (nvlist_lookup_string(props, LIBSES_EN_PROP_CSN, &csn) != 0)) {
		return (FWFLASH_FAILURE);
	}

	(void) printf("%30s: %s\n", "vendor", vendor);
	(void) printf("%30s: %s\n", "product", product);
	(void) printf("%30s: %s\n", "revision", revision);
	(void) printf("%30s: %s\n", "serial", csn);

	ret = get_status(props, &statdesc);
	(void) printf("%30s: %s\n", "current status", statdesc.us_desc);
	if (ret != FWFLASH_SUCCESS) {
		return (FWFLASH_FAILURE);
	}

	(void) snprintf(buf, sizeof (buf), "downloading %u bytes", len);
	(void) printf("\n%30s: ", buf);

	/*
	 * If the bufferid isn't 2, then the verifier has already
	 * OK'd the image that the user has provided.
	 *
	 * At present the non-"standard" images need to be flashed
	 * using the scsi WRITE BUFFER command
	 */
	if (verifier->flashbuf != 2)
		return (scsi_writebuf());


	if (ses_node_ctl(np, SES_CTL_OP_DL_UCODE, arg) != FWFLASH_SUCCESS) {
		(void) printf("failed!\n");
		(void) printf("%s\n", ses_errmsg());
		return (FWFLASH_FAILURE);
	} else {
		(void) printf("ok\n");
	}

	wait.uw_prevstatus = -1ULL;
	wait.uw_oldnp = np;

	if ((newsnap = ses_snap_new(ses_target)) == NULL) {
		logmsg(MSG_ERROR,
		    "failed to update SES snapshot: %s",
		    ses_errmsg());
		return (FWFLASH_FAILURE);
	}

	print_updated_status(ses_snap_primary_enclosure(newsnap),
	    &wait);
	ses_snap_rele(newsnap);

	return (FWFLASH_SUCCESS);
}

static int
scsi_writebuf()
{
	int ret;
	int i = 0;
	libscsi_action_t *action;
	spc3_write_buffer_cdb_t *wb_cdb;
	libscsi_hdl_t	*handle;
	libscsi_target_t *target;
	sam4_status_t samstatus;


	target = ses_scsi_target(ses_target);
	handle = libscsi_get_handle(target);
	action = libscsi_action_alloc(handle, SPC3_CMD_WRITE_BUFFER,
	    LIBSCSI_AF_WRITE|LIBSCSI_AF_RQSENSE,
	    (void *)verifier->fwimage, (size_t)verifier->imgsize);

	wb_cdb = (spc3_write_buffer_cdb_t *)libscsi_action_get_cdb(action);

	wb_cdb->wbc_mode = SPC3_WB_MODE_DATA;
	wb_cdb->wbc_bufferid = verifier->flashbuf;

	wb_cdb->wbc_buffer_offset[0] = 0;
	wb_cdb->wbc_buffer_offset[1] = 0;
	wb_cdb->wbc_buffer_offset[2] = 0;

	wb_cdb->wbc_parameter_list_len[0] =
	    (verifier->imgsize & 0xff0000) >> 16;
	wb_cdb->wbc_parameter_list_len[1] = (verifier->imgsize & 0xff00) >> 8;
	wb_cdb->wbc_parameter_list_len[2] = (verifier->imgsize & 0xff);

	ret = libscsi_exec(action, target);
	samstatus = libscsi_action_get_status(action);

	logmsg(MSG_INFO,
	    "\nscsi_writebuffer: ret 0x%0x, samstatus 0x%0x\n",
	    ret, samstatus);

	if ((ret != FWFLASH_SUCCESS) || samstatus != SAM4_STATUS_GOOD) {
		libscsi_action_free(action);
		return (FWFLASH_FAILURE);
	} else {
		(void) printf("ok\n");
	}

	for (i = 0; i < NSAM4_STATUS; i++) {
		if (sam4_status[i].status == samstatus) {
			(void) printf("%s\n", (sam4_status[i].message));
			break;
		}
	}

	if (i == NSAM4_STATUS)
		(void) printf("Status: UNKNOWN\n");

	if (samstatus == SAM4_STATUS_GOOD) {
		return (FWFLASH_SUCCESS);
	}

	return (FWFLASH_FAILURE);
}
