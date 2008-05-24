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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * ses (SCSI Generic Device) specific functions.
 */


#include <assert.h>
#include <libnvpair.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/queue.h>
#include <fcntl.h>
#include <string.h>
#include <strings.h>
#include <scsi/libscsi.h>
#include <scsi/libses.h>
#include <sys/scsi/generic/commands.h>
#include <sys/scsi/impl/uscsi.h>
#include <libintl.h> /* for gettext(3c) */
#include <fwflash/fwflash.h>



#ifdef NDEBUG
#define	verify(EX)	((void)(EX))
#else
#define	verify(EX)	assert(EX)
#endif


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


char drivername[] = "ses\0";
static char *devprefix = "/devices";
static char *sessuffix = ":0";
static char *sgensuffix = ":ses";


static ses_target_t *ses_target;
static int internalstatus;

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
static ses_walk_action_t  print_updated_status(ses_node_t *np, void *arg);
static int get_status(nvlist_t *props, ucode_status_t *sp);
static ses_walk_action_t sendimg(ses_node_t *np, void *data);
static void tidyup(struct devicelist *thisdev);


/*
 * SES2 does not actually allow us to read a firmware
 * image from an SES device, so we just return success
 * if this is requested, after printing a message.
 */
int
fw_readfw(struct devicelist *flashdev, char *filename)
{

	logmsg(MSG_INFO,
	    "%s: not writing firmware for device %s to file %s\n",
	    flashdev->drvname, flashdev->access_devname, filename);
	logmsg(MSG_ERROR, gettext("\n\nReading of firmware images from "
	    "your device is not currently supported\n\n"));

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

	nvlist_t *nvl;
	ses_snap_t *snapshot;



	if (nvlist_alloc(&nvl, NV_UNIQUE_NAME, 0) != 0 ||
	    nvlist_add_uint64(nvl, SES_CTL_PROP_UCODE_MODE,
	    SES_DLUCODE_M_WITH_OFFS) != 0) {
		logmsg(MSG_ERROR,
		    gettext("%s: Unable to allocate "
		    "space for device prop list\n"),
		    flashdev->drvname);
		tidyup(flashdev);
		return (FWFLASH_FAILURE);
	}


	if ((verifier == NULL) || (verifier->imgsize == 0) ||
	    (verifier->fwimage == NULL)) {
		/* should _not_ happen */
		logmsg(MSG_ERROR,
		    gettext("%s: Firmware image has not "
		    "been verified.\n"),
		    flashdev->drvname);
		tidyup(flashdev);
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
		    gettext("%s: Unable to open flashable device\n%s\n"),
		    flashdev->drvname, flashdev->access_devname);
		goto cancel;
	}
	snapshot = ses_snap_hold(ses_target);

	/*
	 * We flash via a walker callback function, because it's easier
	 * to do it this way when using libses.
	 */

	internalstatus = FWFLASH_SUCCESS;
	(void) ses_walk(snapshot, sendimg, nvl);

	if (internalstatus == FWFLASH_SUCCESS) {
		logmsg(MSG_ERROR,
		    gettext("%s: Done. New image will be active "
		    "after the system is rebooted.\n"),
		    flashdev->drvname);
		fprintf(stdout, "\n");
	}

	ses_snap_rele(snapshot);
	ses_close(ses_target);

cancel:
	nvlist_free(nvl);
	tidyup(flashdev);

	return (internalstatus);
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
	int devlength = 0;
	nvlist_t *props;
	ses_snap_t *snapshot;
	ses_node_t *rootnodep, *nodep, *tnodep;


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

		return (rv);
	}

	if ((devpath = calloc(1, MAXPATHLEN + 1)) == NULL) {
		logmsg(MSG_ERROR,
		    gettext("%s: Unable to allocate space "
		    "for a device node\n"),
		    driver);
		return (rv);
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
			tidyup(newdev);
			free(devpath);
			return (rv);
		}

		/* calloc enough for /devices + devpath + devsuffix + '\0' */
		devlength = strlen(devpath) + strlen(devprefix) +
		    strlen(devsuffix) + 2;

		if ((newdev->access_devname = calloc(1, devlength)) == NULL) {
			logmsg(MSG_ERROR,
			    gettext("%s: Unable to allocate "
			    "space for a devfs name\n"),
			    driver);
			tidyup(newdev);
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
			tidyup(newdev);
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
			tidyup(newdev);
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
		 * That means we need to call tidyup() after fw_writefw()
		 * and fw_devinfo().
		 */
		newdev->ident = calloc(1, VIDLEN + PIDLEN + REVLEN + 3);
		if (newdev->ident == NULL) {
			logmsg(MSG_ERROR,
			    gettext("%s: Unable to malloc %d bytes "
			    "for SCSI INQUIRY data\n"),
			    driver, sizeof (struct vpr));
			tidyup(newdev);
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
			    gettext("%s: Unable to open device\n%s\n"),
			    driver,
			    newdev->access_devname);
			tidyup(newdev);
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
		 * The root node of the snapshot is likely to be of
		 * type SES_NODE_TARGET, so use Shank's Pony to get
		 * where we need to go
		 */
		nodep = ses_node_child(rootnodep);
		tnodep = nodep;

		if ((props = ses_node_props(rootnodep)) == NULL) {
			tidyup(newdev);
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

		/*
		 * If these properties don't exist, this device does
		 * not comply with SES2 so we won't touch it.
		 */
		if ((nvlist_lookup_string(props, SCSI_PROP_VENDOR,
		    &newdev->ident->vid) != 0) ||
		    (nvlist_lookup_string(props, SCSI_PROP_PRODUCT,
		    &newdev->ident->pid) != 0) ||
		    (nvlist_lookup_string(props, SCSI_PROP_REVISION,
		    &newdev->ident->revid) != 0)) {
			tidyup(newdev);
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


		while (ses_node_type(tnodep) != SES_NODE_ENCLOSURE) {
			tnodep = ses_node_child(nodep);
			nodep = tnodep;
		}

		if ((nodep == NULL) ||
		    (props = ses_node_props(nodep)) == NULL) {
			tidyup(newdev);
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
		} else {
			(void) strlcpy(newdev->addresses[0],
			    "(not supported)", 17);
		}


		if (di_prop_lookup_strings(DDI_DEV_T_ANY,
		    thisnode, "target-port",
		    &newdev->addresses[1]) < 0) {
			logmsg(MSG_INFO,
			    "%s: no target-port property "
			    "for device %s\n",
			    driver, newdev->access_devname);
			(void) strlcpy(newdev->addresses[1],
			    "(not supported)", 17);
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
			    tempdev->addresses[0],
			    tempdev->addresses[1],
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
	    thisdev->addresses[0],
	    thisdev->addresses[1]);

	fprintf(stdout, "\n\n");

	/* Don't leave any bits behind... */
	tidyup(thisdev);

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
		internalstatus = FWFLASH_FAILURE;
		return (-1);
	}

	if (nvlist_lookup_uint64(props, SES_EN_PROP_UCODE_A,
	    &astatus) != 0) {
		logmsg(MSG_ERROR,
		    gettext("\nError: Unable to retrieve current status\n"));
		internalstatus = FWFLASH_FAILURE;
		return (-1);
	}


	for (i = 0; i < NUCODE_STATUS; i++) {
		if (ucode_statdesc_table[i].us_value == status)
			break;
	}

	sp->us_status = status;

	if (i == NUCODE_STATUS) {
		(void) snprintf(sp->us_desc, sizeof (sp->us_desc),
		    "unknown (0x%02x)", (int)status);
		sp->us_iserr = sp->us_pending = B_FALSE;
		internalstatus = FWFLASH_FAILURE;
	} else {
		/* LINTED */
		(void) snprintf(sp->us_desc, sizeof (sp->us_desc),
		    ucode_statdesc_table[i].us_desc, (int)astatus);
		sp->us_iserr = ucode_statdesc_table[i].us_iserr;
		sp->us_pending = ucode_statdesc_table[i].us_pending;
	}

	return (0);
}


static ses_walk_action_t
print_updated_status(ses_node_t *np, void *arg)
{
	ucode_wait_t *uwp = arg;
	ses_node_t *oldnp = uwp->uw_oldnp;
	nvlist_t *props, *oldprops;
	uint64_t id, oldid;
	ucode_status_t status;

	if (ses_node_type(np) != SES_NODE_ENCLOSURE)
		return (SES_WALK_ACTION_CONTINUE);

	verify((props = ses_node_props(np)) != NULL);
	verify((oldprops = ses_node_props(oldnp)) != NULL);
	verify(nvlist_lookup_uint64(props, SES_EN_PROP_EID, &id) == 0);
	verify(nvlist_lookup_uint64(oldprops, SES_EN_PROP_EID, &oldid) == 0);

	if (oldid != id)
		return (SES_WALK_ACTION_CONTINUE);

	(void) get_status(props, &status);
	if (status.us_status != uwp->uw_prevstatus)
		(void) printf("%30s: %s\n", "status", status.us_desc);
	uwp->uw_prevstatus = status.us_status;
	uwp->uw_pending = status.us_pending;

	if (status.us_iserr) {
		logmsg(MSG_INFO,
		    "libses: status.us_iserr: 0x%0x\n",
		    status.us_iserr);
		internalstatus = FWFLASH_FAILURE;
	}

	return (SES_WALK_ACTION_CONTINUE);
}

/*ARGSUSED*/
static ses_walk_action_t
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

	if (ses_node_type(np) != SES_NODE_ENCLOSURE)
		return (SES_WALK_ACTION_CONTINUE);

	verify((props = ses_node_props(np)) != NULL);

	verify(nvlist_lookup_string(props, SES_EN_PROP_VID, &vendor) == 0);
	verify(nvlist_lookup_string(props, SES_EN_PROP_PID, &product) == 0);
	verify(nvlist_lookup_string(props, SES_EN_PROP_REV, &revision) == 0);
	verify(nvlist_lookup_string(props, LIBSES_EN_PROP_CSN, &csn) == 0);

	(void) printf("%30s: %s\n", "vendor", vendor);
	(void) printf("%30s: %s\n", "product", product);
	(void) printf("%30s: %s\n", "revision", revision);
	(void) printf("%30s: %s\n", "serial", csn);

	ret = get_status(props, &statdesc);
	(void) printf("%30s: %s\n", "current status", statdesc.us_desc);
	if (ret != 0) {
		/* internalstatus is already set */
		if (arg != NULL)
			return (SES_WALK_ACTION_TERMINATE);
		else
			return (SES_WALK_ACTION_CONTINUE);
	}

	verify(nvlist_lookup_byte_array(arg, SES_CTL_PROP_UCODE_DATA,
	    &imagedata, &len) == 0);
	(void) snprintf(buf, sizeof (buf), "downloading %u bytes", len);
	(void) printf("\n%30s: ", buf);
	if (ses_node_ctl(np, SES_CTL_OP_DL_UCODE, arg) != 0) {
		(void) printf("failed!\n");
		(void) printf("%s\n", ses_errmsg());
		internalstatus = FWFLASH_FAILURE;
	} else {
		(void) printf("ok\n");
	}

	wait.uw_prevstatus = -1ULL;
	wait.uw_oldnp = np;
	do {
		if ((newsnap = ses_snap_new(ses_target)) == NULL)
			logmsg(MSG_ERROR,
			    "failed to update SES snapshot: %s",
			    ses_errmsg());

		(void) ses_walk(newsnap, print_updated_status,
		    &wait);
		ses_snap_rele(newsnap);
	} while (wait.uw_pending);

	return (SES_WALK_ACTION_CONTINUE);
}

static void
tidyup(struct devicelist *thisdev)
{
	/*
	 * Since we didn't allocate the space for the ident->* and
	 * addresses[*], set them to NULL and let the libraries
	 * (libnvpair and libdevinfo) handle them.
	 */
	thisdev->ident->vid = NULL;
	thisdev->ident->pid = NULL;
	thisdev->ident->revid = NULL;
	thisdev->addresses[0] = NULL;
	thisdev->addresses[1] = NULL;
}
