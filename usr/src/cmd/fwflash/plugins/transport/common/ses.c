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
static char *devsuffix = ":0";
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
static struct vpr *inquiry(char *path);
static int ses_dl_ucode_check(struct devicelist *flashdev);
static ses_walk_action_t  print_updated_status(ses_node_t *np, void *arg);
static int get_status(nvlist_t *props, ucode_status_t *sp);
static ses_walk_action_t sendimg(ses_node_t *np, void *data);



/*
 * SES2 does not actually allow us to read a firmware
 * image from an SES device, so we just return success
 * if this is requested, after printing a message.
 */
int
fw_readfw(struct devicelist *flashdev, char *filename)
{
	int rv = FWFLASH_SUCCESS;

	logmsg(MSG_INFO,
	    "ses: not writing firmware for device %s to file %s\n",
	    flashdev->access_devname, filename);
	logmsg(MSG_ERROR, gettext("\n\nSES2 does not support retrieval "
	    "of firmware images\n\n"));

	return (rv);
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
		logmsg(MSG_ERROR, gettext("ses: Unable to allocate "
		    "space for device prop list\n"));
		return (FWFLASH_FAILURE);
	}


	if ((verifier == NULL) || (verifier->imgsize == 0) ||
	    (verifier->fwimage == NULL)) {
		/* should _not_ happen */
		logmsg(MSG_ERROR, gettext("ses: Firmware image has not "
		    "been verified.\n"));
		return (FWFLASH_FAILURE);
	}

	fprintf(stdout, "\n"); /* get a fresh line for progress updates */

	if (nvlist_add_uint64(nvl, SES_CTL_PROP_UCODE_BUFID,
	    verifier->flashbuf) != 0) {
		logmsg(MSG_ERROR, gettext("ses: Unable to add buffer id "
		    "property\n"));
		goto cancel;
	}

	if (nvlist_add_byte_array(nvl, SES_CTL_PROP_UCODE_DATA,
	    (uint8_t *)verifier->fwimage, verifier->imgsize) != 0) {
		logmsg(MSG_ERROR,
		    "%s: Out of memory for property addition\n",
		    drivername);
		goto cancel;
	}

	if ((ses_target =
	    ses_open(LIBSES_VERSION, flashdev->access_devname)) == NULL) {
		logmsg(MSG_ERROR,
		    gettext("ses: Unable to open flashable device\n%s\n"),
		    flashdev->access_devname);
		goto cancel;
	}
	snapshot = ses_snap_hold(ses_target);

	/*
	 * We flash via a walker callback function, because it's easier
	 * to do it this way when using libses.
	 */

	(void) ses_walk(snapshot, sendimg, nvl);


	logmsg(MSG_ERROR,
	    gettext("ses: Done. New image will be active "
	    "after the system is rebooted.\n"));

	fprintf(stdout, "\n");

	ses_snap_rele(snapshot);
	ses_close(ses_target);

cancel:
	nvlist_free(nvl);

	return (FWFLASH_SUCCESS);
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
	int idx = start;
	int devlength = 0;


	thisnode = di_drv_first_node(drivername, rootnode);

	if (thisnode == DI_NODE_NIL) {
		logmsg(MSG_INFO, gettext("No %s nodes in this system\n"),
		    drivername);

		return (rv);
	}

	if ((devpath = calloc(1, MAXPATHLEN + 1)) == NULL) {
		logmsg(MSG_ERROR, gettext("ses: Unable to malloc space "
		    "for a %s-attached device node\n"), drivername);
		return (rv);
	}
	bzero(devpath, MAXPATHLEN);

	/* we've found one, at least */

	for (; thisnode != DI_NODE_NIL; thisnode = di_drv_next_node(thisnode)) {

		devpath = di_devfs_path(thisnode);

		if ((newdev = calloc(1, sizeof (struct devicelist)))
		    == NULL) {
			logmsg(MSG_ERROR,
			    gettext("ses: identification function unable "
			    "to allocate space for device entry\n"));
			return (rv);
		}

		/* malloc enough for /devices + devpath + ":0" + '\0' */
		devlength = strlen(devpath) + strlen(devprefix) +
		    strlen(devsuffix) + 2;

		if ((newdev->access_devname = calloc(1, devlength)) == NULL) {
			logmsg(MSG_ERROR, gettext("ses: Unable to malloc "
			    "space for a devfs name\n"));
			free(devpath);
			return (FWFLASH_FAILURE);
		}
		snprintf(newdev->access_devname, devlength,
		    "%s%s%s", devprefix, devpath, devsuffix);

		if ((newdev->drvname = calloc(1, strlen(drivername) + 1))
		    == NULL) {
			logmsg(MSG_ERROR, gettext("ses: Unable to malloc "
			    "space for a driver name\n"));
			free(newdev->access_devname);
			free(newdev);
			return (FWFLASH_FAILURE);
		}
		(void) strlcpy(newdev->drvname, drivername,
		    strlen(drivername) + 1);

		if ((newdev->classname = calloc(1, strlen(drivername) + 1))
		    == NULL) {
			logmsg(MSG_ERROR, gettext("ses: Unable to malloc "
			    "space for a class name\n"));
			free(newdev->access_devname);
			free(newdev->drvname);
			free(newdev);
			return (FWFLASH_FAILURE);
		}
		(void) strlcpy(newdev->classname, drivername,
		    strlen(drivername) + 1);


		/*
		 * Check for friendly vendor names, and whether this device
		 * supports the Download Microcode Control page.
		 */

		newdev->ident = inquiry(newdev->access_devname);
		rv = ses_dl_ucode_check(newdev);
		if ((rv == FWFLASH_FAILURE) || (newdev->ident == NULL))
			continue;


		if (newdev->ident == NULL) {
			logmsg(MSG_INFO,
			    "ses: unable to inquire on potentially "
			    "flashable device\n%s\n",
			    newdev->access_devname);
			free(newdev->access_devname);
			free(newdev->drvname);
			free(newdev->classname);
			free(newdev);
			continue;
		}

		/*
		 * Look for the target-port property. We use addresses[1]
		 * because addresses[0] is already assigned by the inquiry
		 * function
		 */
		if ((newdev->addresses[1] = calloc(1, SASADDRLEN + 1))
		    == NULL) {
			logmsg(MSG_ERROR,
			    gettext("ses: Out of memory for target-port\n"));
			free(newdev->access_devname);
			free(newdev->drvname);
			free(newdev->classname);
			free(newdev);
			continue;
		} else {
			if (di_prop_lookup_strings(DDI_DEV_T_ANY, thisnode,
			    "target-port", &newdev->addresses[1]) < 0) {
				logmsg(MSG_INFO,
				    "ses: no target-port property for "
				    "device %s\n",
				    newdev->access_devname);
				strlcpy(newdev->addresses[1],
				    "0000000000000000", 17);
			}
		}


		newdev->index = idx;
		++idx;
		newdev->plugin = self;

		TAILQ_INSERT_TAIL(fw_devices, newdev, nextdev);
	}


	if (fwflash_debug != 0) {
		struct devicelist *tempdev;

		TAILQ_FOREACH(tempdev, fw_devices, nextdev) {
			logmsg(MSG_INFO, "ses:fw_writefw:\n");
			logmsg(MSG_INFO, "\ttempdev @ 0x%lx\n"
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
			    (tempdev->addresses[0] != NULL) ?
			    (char *)tempdev->addresses[0] : "NULL",
			    (tempdev->addresses[1] != NULL) ?
			    (char *)tempdev->addresses[1] : "NULL",
			    tempdev->plugin);
		}
	}

	return (FWFLASH_SUCCESS);
}



int
fw_devinfo(struct devicelist *thisdev)
{


	fprintf(stdout, gettext("Device[%d] %s\n  Class [%s]\n"),
	    thisdev->index, thisdev->access_devname, thisdev->classname);

	if (thisdev->addresses[0] != NULL) {
		fprintf(stdout,
		    gettext("\tChassis Serial Number  : %s\n"),
		    thisdev->addresses[0]);
	}

	fprintf(stdout,
	    gettext("\tVendor                 : %s\n"
	    "\tProduct                : %s\n"
	    "\tFirmware revision      : %s\n"
	    "\tTarget-port identifier : %s\n"),
	    thisdev->ident->vid,
	    thisdev->ident->pid,
	    thisdev->ident->revid,
	    thisdev->addresses[1]);

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
		return (-1);
	}

	verify(nvlist_lookup_uint64(props, SES_EN_PROP_UCODE_A, &astatus) == 0);

	for (i = 0; i < NUCODE_STATUS; i++) {
		if (ucode_statdesc_table[i].us_value == status)
			break;
	}

	sp->us_status = status;

	if (i == NUCODE_STATUS) {
		(void) snprintf(sp->us_desc, sizeof (sp->us_desc),
		    "unknown (0x%02x)", (int)status);
		sp->us_iserr = sp->us_pending = B_FALSE;
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

	if (status.us_iserr)
		logmsg(MSG_INFO,
		    "ses: status.us_iserr: 0x%0x\n",
		    status.us_iserr);

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
	size_t len;

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

/*
 * Simple function to sent a standard SCSI INQUIRY(6) cdb out
 * to thisnode and blat the response back into a struct vpr*
 */
static struct vpr *
inquiry(char *path) {

	struct uscsi_cmd *inqcmd;
	uchar_t inqbuf[INQBUFLEN];	/* inquiry response */
	uchar_t rqbuf[RQBUFLEN];	/* request sense data */
	struct vpr *inqvpr;
	int fd, rval;


	inqvpr = NULL;
	if ((inqcmd = calloc(1, sizeof (struct uscsi_cmd))) == NULL) {
		logmsg(MSG_ERROR,
		    gettext("ses: Unable to malloc %d bytes "
		    "for a SCSI INQUIRY(6) command\n"),
		    sizeof (struct uscsi_cmd));
		return (NULL);
	}

	if ((inqvpr = calloc(1, sizeof (struct vpr))) == NULL) {
		logmsg(MSG_ERROR,
		    gettext("ses: Unable to malloc %d bytes "
		    "for SCSI INQUIRY(6) response\n"),
		    sizeof (struct vpr));
		free(inqcmd);
		return (NULL);
	}

	if ((inqcmd->uscsi_cdb = calloc(1, CDB_GROUP0 * sizeof (caddr_t)))
	    == NULL) {
		logmsg(MSG_ERROR,
		    gettext("ses: Unable to malloc %d bytes "
		    "for SCSI INQUIRY(6)\n"),
		    CDB_GROUP0 * sizeof (caddr_t));
		free(inqcmd);
		free(inqvpr);
		return (NULL);
	}

	logmsg(MSG_INFO, "ses:inquiry:opening device %s\n",
	    path);

	if ((fd = open(path, O_RDONLY|O_SYNC)) < 0) {
		logmsg(MSG_INFO,
		    "ses: Unable to open device %s: %s\n",
		    path, strerror(errno));
		free(inqcmd->uscsi_cdb);
		free(inqcmd);
		free(inqvpr);
		return (NULL);
	}

	if (((inqvpr->vid = calloc(1, VIDLEN + 1))
	    == NULL) ||
	    ((inqvpr->pid = calloc(1, PIDLEN + 1))
		== NULL) ||
	    ((inqvpr->revid = calloc(1, REVLEN + 1))
		== NULL)) {
		logmsg(MSG_ERROR,
		    gettext("ses: Unable to malloc %d bytes "
		    "for %s identification function.\n"),
		    VIDLEN+PIDLEN+REVLEN, drivername);
		free(inqcmd->uscsi_cdb);
		free(inqcmd);
		free(inqvpr->vid);
		free(inqvpr->pid);
		free(inqvpr->revid);
		return (NULL);
	}

	/* just make sure these buffers are clean */
	bzero(inqbuf, INQBUFLEN);
	bzero(rqbuf, RQBUFLEN);
	bzero(inqcmd->uscsi_cdb, CDB_GROUP0);
	inqcmd->uscsi_flags = USCSI_READ;
	inqcmd->uscsi_timeout = 0;
	inqcmd->uscsi_bufaddr = (caddr_t)inqbuf;
	inqcmd->uscsi_buflen = INQBUFLEN;
	inqcmd->uscsi_cdblen = CDB_GROUP0; /* a GROUP 0 command */
	inqcmd->uscsi_cdb[0] = SCMD_INQUIRY;
	inqcmd->uscsi_cdb[1] = 0x00; /* EVPD = Enable Vital Product Data */
	inqcmd->uscsi_cdb[2] = 0x00; /* which pagecode to query? */
	inqcmd->uscsi_cdb[3] = 0x00; /* allocation length, msb */
	inqcmd->uscsi_cdb[4] = INQBUFLEN; /* allocation length, lsb */
	inqcmd->uscsi_cdb[5] = 0x0; /* control byte */
	inqcmd->uscsi_rqbuf = (caddr_t)&rqbuf;
	inqcmd->uscsi_rqlen = RQBUFLEN;


	rval = ioctl(fd, USCSICMD, inqcmd);

	if (rval < 0) {
		/* ioctl failed */
		logmsg(MSG_INFO,
		    gettext("ses: Unable to retrieve SCSI INQUIRY(6) data "
			"from device %s: %s\n"),
		    path, strerror(errno));
		free(inqcmd->uscsi_cdb);
		free(inqcmd);
		free(inqvpr->vid);
		free(inqvpr->pid);
		free(inqvpr->revid);
		return (NULL);
	}



	bcopy(&inqbuf[8], inqvpr->vid, VIDLEN);
	bcopy(&inqbuf[16], inqvpr->pid, PIDLEN);
	bcopy(&inqbuf[32], inqvpr->revid, REVLEN);

	(void) close(fd);

	logmsg(MSG_INFO,
	    "ses inquiry: vid %s ; pid %s ; revid %s\n",
	    inqvpr->vid, inqvpr->pid, inqvpr->revid);

	if ((strncmp(inqvpr->vid, "SUN", 3) != 0) &&
	    (strncmp(inqvpr->vid, "LSI", 3) != 0) &&
	    (strncmp(inqvpr->vid, "Quanta", 6) != 0) &&
	    (strncmp(inqvpr->vid, "QUANTA", 6) != 0)) {
		free(inqvpr->vid);
		free(inqvpr->pid);
		free(inqvpr->revid);
		inqvpr->vid = NULL;
		inqvpr->pid = NULL;
		inqvpr->revid = NULL;
		logmsg(MSG_INFO,
		    "ses inquiry: unrecognised device\n");
		return (NULL);
	}

	free(inqcmd->uscsi_cdb);
	free(inqcmd);

	return (inqvpr);
}


/*
 * ses_dl_ucode_check() lets us check whether SES2's Download
 * Microcode Control diagnostic and status pages are supported
 * by flashdev.
 */
int
ses_dl_ucode_check(struct devicelist *flashdev)
{
	int rv;
	int limit;
	int i = 0;
	int fd;
	struct uscsi_cmd *usc;
	uchar_t sensebuf[RQBUFLEN]; /* for the request sense data */
	uchar_t pagesup[PCBUFLEN]; /* should be less than 64 pages */


	if ((fd = open(flashdev->access_devname,
	    O_RDONLY|O_NDELAY)) < 0) {
		logmsg(MSG_INFO,
		    gettext("ses:ses_dl_ucode_check: Unable to open %s\n"),
		    flashdev->access_devname);
		return (FWFLASH_FAILURE);
	}

	if ((usc = calloc(1, sizeof (struct uscsi_cmd))) == NULL) {
		logmsg(MSG_ERROR,
		    gettext("ses: Unable to alloc %d bytes for "
		    "microcode download query: %s\n"),
		    sizeof (struct uscsi_cmd), strerror(errno));
		(void) close(fd);
		return (FWFLASH_FAILURE);
	}

	if ((usc->uscsi_cdb = calloc(1, CDB_GROUP0 * sizeof (caddr_t)))
	    == NULL) {
		logmsg(MSG_ERROR,
		    gettext("ses: Unable to alloc %d bytes for "
		    "microcode download query: %s\n"),
		    CDB_GROUP0 * sizeof (caddr_t), strerror(errno));
		(void) close(fd);
		free(usc);
		return (FWFLASH_FAILURE);
	}


	bzero(sensebuf, RQBUFLEN);

	usc->uscsi_flags = USCSI_READ | USCSI_RQENABLE;
	usc->uscsi_timeout = 0;
	usc->uscsi_cdblen = CDB_GROUP0;
	usc->uscsi_rqbuf = (caddr_t)&sensebuf;
	usc->uscsi_rqlen = RQBUFLEN;


	bzero(pagesup, PCBUFLEN);
	usc->uscsi_bufaddr = (caddr_t)&pagesup;
	usc->uscsi_buflen = PCBUFLEN;

	usc->uscsi_cdb[0] = SCMD_GDIAG; /* "Get" or receive */
	usc->uscsi_cdb[1] = 1; /* PCV = Page Code Valid */
	usc->uscsi_cdb[2] = 0x00; /* list all Supported diag pages */
	usc->uscsi_cdb[3] = 0x00;
	usc->uscsi_cdb[4] = PCBUFLEN;
	usc->uscsi_cdb[5] = 0; /* control byte, reserved */

	rv = ioctl(fd, USCSICMD, usc);
	if (rv < 0) {
		logmsg(MSG_INFO,
		    "ses: DL uCode checker ioctl error (%d): %s\n",
		    errno, strerror(errno));
		return (FWFLASH_FAILURE);
	}

	rv = FWFLASH_FAILURE;
	/* in SPC4, this is an "n-3" field */
	limit = (pagesup[2] << 8) + pagesup[3] + 4;
	while (i < limit) {
		if (pagesup[4 + i] == 0x0E) {
			i = limit;
			logmsg(MSG_INFO, "ses: device %s "
			    "supports the Download Microcode "
			    "diagnostic control page\n",
			    flashdev->access_devname);
			rv = FWFLASH_SUCCESS;
		}
		++i;
	}
	(void) close(fd);
	free(usc->uscsi_cdb);
	free(usc);

	return (rv);
}
