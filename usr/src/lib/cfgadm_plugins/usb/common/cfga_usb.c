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
 * Copyright 2018 OmniOS Community Edition (OmniOSce) Association.
 */


#include "cfga_usb.h"


/* function prototypes */
cfga_err_t		usb_err_msg(char **, cfga_usb_ret_t, const char *, int);
extern cfga_usb_ret_t	usb_rcm_offline(const char *, char **, char *,
			    cfga_flags_t);
extern cfga_usb_ret_t	usb_rcm_online(const char *, char **, char *,
			    cfga_flags_t);
extern cfga_usb_ret_t	usb_rcm_remove(const char *, char **, char *,
			    cfga_flags_t);
static int		usb_confirm(struct cfga_confirm *, char *);
static char		*usb_get_devicepath(const char *);

/*
 * This file contains the entry points to the plugin as defined in the
 * config_admin(3X) man page.
 */

/*
 * Set the version number for the cfgadm library's use.
 */
int cfga_version = CFGA_HSL_V2;

#define	HELP_HEADER		1
#define	HELP_CONFIG		2
#define	HELP_RESET_SLOT		3
#define	HELP_CONFIG_SLOT	4
#define	HELP_UNKNOWN		5

/* Help messages */
static char *
usb_help[] = {
NULL,
"USB specific commands:\n",
" cfgadm -c [configure|unconfigure|disconnect] ap_id [ap_id...]\n",
" cfgadm -x usb_reset ap_id [ap_id...]\n",
" cfgadm -x usb_config -o config=<index of desired configuration>  ap_id\n",
"\tunknown command or option: ",
NULL
};	/* End help messages */

/* Error messages */
static msgcvt_t
usb_error_msgs[] = {
	/* CFGA_USB_OK	*/
	{ CVT, CFGA_OK, "ok" },

	/* CFGA_USB_UNKNOWN	*/
	{ CVT, CFGA_LIB_ERROR, "Unknown message; internal error" },

	/* CFGA_USB_INTERNAL_ERROR	*/
	{ CVT, CFGA_LIB_ERROR, "Internal error" },

	/* CFGA_USB_OPTIONS	*/
	{ CVT, CFGA_ERROR, "Hardware specific options not supported" },

	/* CFGA_USB_DYNAMIC_AP	*/
	{ CVT, CFGA_INVAL, "Dynamic attachment points not supported" },

	/* CFGA_USB_AP	*/
	{ CVT, CFGA_APID_NOEXIST, "" },

	/* CFGA_USB_PORT	*/
	{ CVT, CFGA_LIB_ERROR, "Cannot determine hub port number for " },

	/* CFGA_USB_DEVCTL	*/
	{ CVT, CFGA_ERROR, "Cannot issue devctl to " },

	/* CFGA_USB_NOT_CONNECTED	*/
	{ CVT, CFGA_INVAL, "No device connected to " },

	/* CFGA_USB_NOT_CONFIGURED	*/
	{ CVT, CFGA_INVAL, "No device configured to " },

	/* CFGA_USB_ALREADY_CONNECTED	*/
	{ CVT, CFGA_INSUFFICENT_CONDITION,
		"Device already connected; cannot connect again " },

	/* CFGA_USB_ALREADY_CONFIGURED	*/
	{ CVT, CFGA_INVAL, "device already configured for " },

	/* CFGA_USB_OPEN	*/
	{ CVT, CFGA_LIB_ERROR, "Cannot open " },

	/* CFGA_USB_IOCTL	*/
	{ CVT, CFGA_ERROR, "Driver ioctl failed " },

	/* CFGA_USB_BUSY	*/
	{ CVT, CFGA_SYSTEM_BUSY, "" },

	/* CFGA_USB_ALLOC_FAIL	*/
	{ CVT, CFGA_LIB_ERROR, "Memory allocation failure" },

	/* CFGA_USB_OPNOTSUPP	*/
	{ CVT, CFGA_OPNOTSUPP, "Operation not supported" },

	/* CFGA_USB_DEVLINK	*/
	{ CVT, CFGA_LIB_ERROR, "Could not find /dev/cfg link for " },

	/* CFGA_USB_STATE	*/
	{ CVT, CFGA_LIB_ERROR, "Internal error: Unrecognized ap state" },

	/* CFGA_USB_CONFIG_INVAL	*/
	{ CVT, CFGA_ERROR,
		"Specified configuration index unrecognized or exceeds "
		"maximum available" },

	/* CFGA_USB_PRIV	*/
	{ CVT, CFGA_PRIV, "" },

	/* CFGA_USB_NVLIST	*/
	{ CVT, CFGA_ERROR, "Internal error (nvlist)" },

	/* CFGA_USB_ZEROLEN	*/
	{ CVT, CFGA_ERROR, "Internal error (zerolength string)" },

	/* CFGA_USB_CONFIG_FILE	*/
	{ CVT, CFGA_ERROR,
	"Cannot open/fstat/read USB system configuration file" },

	/* CFGA_USB_LOCK_FILE */
	{ CVT, CFGA_ERROR, "Cannot lock USB system configuration file" },

	/* CFGA_USB_UNLOCK_FILE */
	{ CVT, CFGA_ERROR, "Cannot unlock USB system configuration file" },

	/* CFGA_USB_ONE_CONFIG	*/
	{ CVT, CFGA_ERROR,
	"Operation not supported for devices with one configuration" },

	/* CFGA_USB_RCM_HANDLE Errors */
	{ CVT, CFGA_ERROR, "cannot get RCM handle"},

	/* CFGA_USB_RCM_ONLINE */
	{ CVT, CFGA_SYSTEM_BUSY,   "failed to online: "},

	/* CFGA_USB_RCM_OFFLINE */
	{ CVT, CFGA_SYSTEM_BUSY,   "failed to offline: "},

	/* CFGA_USB_RCM_INFO */
	{ CVT, CFGA_ERROR,   "failed to query: "}

};	/* End error messages */


/* ========================================================================= */
/*
 * The next two funcs imported verbatim from cfgadm_scsi.
 * physpath_to_devlink is the only func directly used by cfgadm_usb.
 * get_link supports it.
 */

/*
 * Routine to search the /dev directory or a subtree of /dev.
 */
static int
get_link(di_devlink_t devlink, void *arg)
{
	walk_link_t *larg = (walk_link_t *)arg;

	/*
	 * When path is specified, it's the node path without minor
	 * name. Therefore, the ../.. prefixes needs to be stripped.
	 */
	if (larg->path) {
		char *content = (char *)di_devlink_content(devlink);
		char *start = strstr(content, "/devices/");

		/* line content must have minor node */
		if (start == NULL ||
		    strncmp(start, larg->path, larg->len) != 0 ||
		    start[larg->len] != ':') {

			return (DI_WALK_CONTINUE);
		}
	}

	*(larg->linkpp) = strdup(di_devlink_path(devlink));

	return (DI_WALK_TERMINATE);
}


/* ARGSUSED */
static ucfga_ret_t
physpath_to_devlink(
	const char *basedir,
	const char *node_path,
	char **logpp,
	int *l_errnop,
	int match_minor)
{
	walk_link_t larg;
	di_devlink_handle_t hdl;
	char *minor_path;

	if ((hdl = di_devlink_init(NULL, 0)) == NULL) {
		*l_errnop = errno;
		return (UCFGA_LIB_ERR);
	}

	*logpp = NULL;
	larg.linkpp = logpp;
	if (match_minor) {
		minor_path = (char *)node_path + strlen("/devices");
		larg.path = NULL;
	} else {
		minor_path = NULL;
		larg.len = strlen(node_path);
		larg.path = (char *)node_path;
	}

	(void) di_devlink_walk(hdl, "^cfg/", minor_path, DI_PRIMARY_LINK,
	    (void *)&larg, get_link);

	(void) di_devlink_fini(&hdl);

	if (*logpp == NULL) {
		*l_errnop = errno;
		return (UCFGA_LIB_ERR);
	}

	return (UCFGA_OK);
}


/* ========================================================================= */
/* Utilities */

/*
 * Given the index into a table (msgcvt_t) of messages, get the message
 * string, converting it to the proper locale if necessary.
 * NOTE: See cfga_usb.h
 */
static const char *
get_msg(uint_t msg_index, msgcvt_t *msg_tbl, uint_t tbl_size)
{
	if (msg_index >= tbl_size) {
		DPRINTF("get_error_msg: bad error msg index: %d\n", msg_index);
		msg_index = CFGA_USB_UNKNOWN;
	}

	return ((msg_tbl[msg_index].intl) ?
	    dgettext(TEXT_DOMAIN, msg_tbl[msg_index].msgstr) :
	    msg_tbl[msg_index].msgstr);
}


/*
 * Allocates and creates a message string (in *ret_str),
 * by concatenating all the (char *) args together, in order.
 * Last arg MUST be NULL.
 */
static void
set_msg(char **ret_str, ...)
{
	char	*str;
	size_t	total_len;
	va_list	valist;

	va_start(valist, ret_str);

	total_len = (*ret_str == NULL) ? 0 : strlen(*ret_str);

	while ((str = va_arg(valist, char *)) != NULL) {
		size_t	len = strlen(str);
		char	*old_str = *ret_str;

		*ret_str = (char *)realloc(*ret_str, total_len + len + 1);
		if (*ret_str == NULL) {
			/* We're screwed */
			free(old_str);
			DPRINTF("set_msg: realloc failed.\n");
			va_end(valist);
			return;
		}

		(void) strcpy(*ret_str + total_len, str);
		total_len += len;
	}

	va_end(valist);
}


/*
 * Error message handling.
 * For the rv passed in, looks up the corresponding error message string(s),
 * internationalized it if necessary, and concatenates it into a new
 * memory buffer, and points *errstring to it.
 * Note not all rvs will result in an error message return, as not all
 * error conditions warrant a USB-specific error message.
 *
 * Some messages may display ap_id or errno, which is why they are passed
 * in.
 */
cfga_err_t
usb_err_msg(char **errstring, cfga_usb_ret_t rv, const char *ap_id, int l_errno)
{
	if (errstring == NULL) {

		return (usb_error_msgs[rv].cfga_err);
	}

	/*
	 * Generate the appropriate USB-specific error message(s) (if any).
	 */
	switch (rv) {
	case CFGA_USB_OK:
	/* Special case - do nothing.  */
		break;

	case CFGA_USB_UNKNOWN:
	case CFGA_USB_DYNAMIC_AP:
	case CFGA_USB_INTERNAL_ERROR:
	case CFGA_USB_OPTIONS:
	case CFGA_USB_ALLOC_FAIL:
	case CFGA_USB_STATE:
	case CFGA_USB_CONFIG_INVAL:
	case CFGA_USB_PRIV:
	case CFGA_USB_OPNOTSUPP:
	/* These messages require no additional strings passed. */
		set_msg(errstring, ERR_STR(rv), NULL);
		break;

	case CFGA_USB_AP:
	case CFGA_USB_PORT:
	case CFGA_USB_NOT_CONNECTED:
	case CFGA_USB_NOT_CONFIGURED:
	case CFGA_USB_ALREADY_CONNECTED:
	case CFGA_USB_ALREADY_CONFIGURED:
	case CFGA_USB_BUSY:
	case CFGA_USB_DEVLINK:
	case CFGA_USB_RCM_HANDLE:
	case CFGA_USB_RCM_ONLINE:
	case CFGA_USB_RCM_OFFLINE:
	case CFGA_USB_RCM_INFO:
	case CFGA_USB_DEVCTL:
	/* These messages also print ap_id.  */
		(void) set_msg(errstring, ERR_STR(rv),
		    "ap_id: ", ap_id, "", NULL);
		break;

	case CFGA_USB_IOCTL:
	case CFGA_USB_NVLIST:
	case CFGA_USB_CONFIG_FILE:
	case CFGA_USB_ONE_CONFIG:
	/* These messages also print errno.  */
	{
		char *errno_str = l_errno ? strerror(l_errno) : "";

		set_msg(errstring, ERR_STR(rv), errno_str,
		    l_errno ? "\n" : "", NULL);
		break;
	}

	case CFGA_USB_OPEN:
	/* These messages also apid and errno.  */
	{
		char *errno_str = l_errno ? strerror(l_errno) : "";

		set_msg(errstring, ERR_STR(rv), "ap_id: ", ap_id, "\n",
		    errno_str, l_errno ? "\n" : "", NULL);
		break;
	}

	default:
		DPRINTF("usb_err_msg: Unrecognized message index: %d\n", rv);
		set_msg(errstring, ERR_STR(CFGA_USB_INTERNAL_ERROR), NULL);

	}	/* end switch */

	/*
	 * Determine the proper error code to send back to the cfgadm library.
	 */
	return (usb_error_msgs[rv].cfga_err);
}


/*
 * Ensure the ap_id passed is in the correct (physical ap_id) form:
 *     path/device:xx[.xx]+
 * where xx is a one or two-digit number.
 *
 * Note the library always calls the plugin with a physical ap_id.
 */
static int
verify_valid_apid(const char *ap_id)
{
	char	*l_ap_id;

	if (ap_id == NULL) {
		return (-1);
	}

	l_ap_id = strrchr(ap_id, *MINOR_SEP);
	l_ap_id++;

	if (strspn(l_ap_id, "0123456789.") != strlen(l_ap_id)) {
		/* Bad characters in the ap_id. */
		return (-1);
	}

	if (strstr(l_ap_id, "..") != NULL) {
		/* ap_id has 1..2 or more than 2 dots */
		return (-1);
	}

	return (0);
}


/*
 * Verify the params passed in are valid.
 */
static cfga_usb_ret_t
verify_params(
	const char *ap_id,
	const char *options,
	char **errstring)
{
	if (errstring != NULL) {
		*errstring = NULL;
	}

	if (options != NULL) {
		DPRINTF("verify_params: hardware-specific options not "
		    "supported.\n");
		return (CFGA_USB_OPTIONS);
	}

	/* Dynamic attachment points not supported (yet). */
	if (GET_DYN(ap_id) != NULL) {
		DPRINTF("verify_params: dynamic ap_id passed\n");
		return (CFGA_USB_DYNAMIC_AP);
	}

	if (verify_valid_apid(ap_id) != 0) {
		DPRINTF("verify_params: not a USB ap_id.\n");
		return (CFGA_USB_AP);
	}

	return (CFGA_USB_OK);
}


/*
 * Takes a validated ap_id and extracts the port number.
 */
static cfga_usb_ret_t
get_port_num(const char *ap_id, uint_t *port)
{
	char *port_nbr_str;
	char *temp;

	port_nbr_str = strrchr(ap_id, *MINOR_SEP) + strlen(MINOR_SEP);
	if ((temp = strrchr(ap_id, (int)*PORT_SEPERATOR)) != 0) {
		port_nbr_str = temp + strlen(PORT_SEPERATOR);
	}

	errno = 0;
	*port = strtol(port_nbr_str, NULL, 10);
	if (errno) {
		DPRINTF("get_port_num: conversion of port str failed\n");
		return (CFGA_USB_PORT);
	}

	return (CFGA_USB_OK);
}


/*
 * Pair of routines to set up for/clean up after a devctl_ap_* lib call.
 */
static void
cleanup_after_devctl_cmd(devctl_hdl_t devctl_hdl, nvlist_t *user_nvlist)
{
	if (user_nvlist != NULL) {
		nvlist_free(user_nvlist);
	}
	if (devctl_hdl != NULL) {
		devctl_release(devctl_hdl);
	}
}


static cfga_usb_ret_t
setup_for_devctl_cmd(const char *ap_id, devctl_hdl_t *devctl_hdl,
    nvlist_t **user_nvlistp, uint_t oflag)
{
	uint32_t	port;
	cfga_usb_ret_t	rv = CFGA_USB_OK;

	DPRINTF("setup_for_devctl_cmd: oflag=%d\n", oflag);

	/* Get a handle to the ap */
	if ((*devctl_hdl = devctl_ap_acquire((char *)ap_id, oflag)) == NULL) {
		DPRINTF("setup_for_devctl_cmd: devctl_ap_acquire failed with "
		    "errno: %d\n", errno);
		rv = CFGA_USB_DEVCTL;
		goto bailout;
	}

	/* Set up to pass port number down to driver */
	if (nvlist_alloc(user_nvlistp, NV_UNIQUE_NAME_TYPE, NULL) != 0) {
		DPRINTF("setup_for_devctl: nvlist_alloc failed, errno: %d\n",
		    errno);
		*user_nvlistp = NULL;	/* Prevent possible incorrect free in */
					/* cleanup_after_devctl_cmd */
		rv = CFGA_USB_NVLIST;
		goto bailout;
	}

	if ((rv = get_port_num(ap_id, &port)) != CFGA_USB_OK) {
		DPRINTF("setup_for_devctl_cmd: get_port_num, errno: %d\n",
		    errno);
		goto bailout;
	}

	/* creates an int32_t entry */
	if (nvlist_add_int32(*user_nvlistp, PORT, port) == -1) {
		DPRINTF("setup_for_devctl_cmd: nvlist_add_int32 failed. "
		    "errno: %d\n", errno);
		rv = CFGA_USB_NVLIST;
		goto bailout;
	}

	return (rv);

bailout:
	cleanup_after_devctl_cmd(*devctl_hdl, *user_nvlistp);

	return (rv);
}


/*
 * Ensure that there's a device actually connected to the ap
 */
static cfga_usb_ret_t
device_configured(devctl_hdl_t hdl, nvlist_t *nvl, ap_rstate_t *rstate)
{
	cfga_usb_ret_t		rv;
	devctl_ap_state_t	devctl_ap_state;

	DPRINTF("device_configured:\n");
	if (devctl_ap_getstate(hdl, nvl, &devctl_ap_state) == -1) {
		DPRINTF("devctl_ap_getstate failed, errno: %d\n", errno);
		return (CFGA_USB_DEVCTL);
	}

	rv = CFGA_USB_ALREADY_CONFIGURED;
	*rstate = devctl_ap_state.ap_rstate;
	if (devctl_ap_state.ap_ostate != AP_OSTATE_CONFIGURED) {
		return (CFGA_USB_NOT_CONFIGURED);
	}

	return (rv);
}


/*
 * Ensure that there's a device actually connected to the ap
 */
static cfga_usb_ret_t
device_connected(devctl_hdl_t hdl, nvlist_t *list, ap_ostate_t *ostate)
{
	cfga_usb_ret_t		rv = CFGA_USB_ALREADY_CONNECTED;
	devctl_ap_state_t	devctl_ap_state;

	DPRINTF("device_connected:\n");

	if (devctl_ap_getstate(hdl, list, &devctl_ap_state) == -1) {
		DPRINTF("devctl_ap_getstate failed, errno: %d\n", errno);
		return (CFGA_USB_DEVCTL);
	}

	*ostate =  devctl_ap_state.ap_ostate;
	if (devctl_ap_state.ap_rstate != AP_RSTATE_CONNECTED) {
		return (CFGA_USB_NOT_CONNECTED);
	}

	return (rv);
}


/*
 * Given a subcommand to the DEVCTL_AP_CONTROL ioctl, rquest the size of
 * the data to be returned, allocate a buffer, then get the data.
 * Returns *descrp (which must be freed) and size.
 *
 * Note USB_DESCR_TYPE_STRING returns an ASCII NULL-terminated string,
 * not a string descr.
 */
cfga_usb_ret_t
do_control_ioctl(const char *ap_id, uint_t subcommand, uint_t arg,
    void **descrp, size_t *sizep)
{
	int			fd = -1;
	uint_t			port;
	uint32_t		local_size;
	cfga_usb_ret_t		rv = CFGA_USB_OK;
	struct hubd_ioctl_data	ioctl_data;

	assert(descrp != NULL);
	*descrp = NULL;
	assert(sizep != NULL);

	if ((rv = get_port_num(ap_id, &port)) != CFGA_USB_OK) {
		goto bailout;
	}

	if ((fd = open(ap_id, O_RDONLY)) == -1) {
		DPRINTF("do_control_ioctl: open failed: errno:%d\n", errno);
		rv = CFGA_USB_OPEN;
		if (errno == EBUSY) {
			rv = CFGA_USB_BUSY;
		}
		goto bailout;
	}

	ioctl_data.cmd = subcommand;
	ioctl_data.port = port;
	ioctl_data.misc_arg = (uint_t)arg;

	/*
	 * Find out how large a buf we need to get the data.
	 *
	 * Note the ioctls only accept/return a 32-bit int for a get_size
	 * to avoid 32/64 and BE/LE issues.
	 */
	ioctl_data.get_size = B_TRUE;
	ioctl_data.buf = (caddr_t)&local_size;
	ioctl_data.bufsiz = sizeof (local_size);

	if (ioctl(fd, DEVCTL_AP_CONTROL, &ioctl_data) != 0) {
		DPRINTF("do_control_ioctl: size ioctl failed: errno:%d\n",
		    errno);
		rv = CFGA_USB_IOCTL;
		goto bailout;
	}
	*sizep = local_size;

	if (subcommand == USB_DESCR_TYPE_STRING &&
	    arg == HUBD_CFG_DESCR_STR && local_size == 0) {
		/* Zero-length data - nothing to do.  */
		rv = CFGA_USB_ZEROLEN;
		goto bailout;
	}
	if (subcommand == HUBD_REFRESH_DEVDB) {
		/* Already done - no data transfer; nothing left to do. */
		goto bailout;
	}

	if ((*descrp = malloc(*sizep)) == NULL) {
		DPRINTF("do_control_ioctl: malloc failed\n");
		rv = CFGA_USB_ALLOC_FAIL;
		goto bailout;
	}

	/* Get the data */
	ioctl_data.get_size = B_FALSE;
	ioctl_data.buf = *descrp;
	ioctl_data.bufsiz = *sizep;

	if (ioctl(fd, DEVCTL_AP_CONTROL, &ioctl_data) != 0) {
		DPRINTF("do_control_ioctl: ioctl failed: errno:%d\n",
		    errno);
		rv = CFGA_USB_IOCTL;
		goto bailout;
	}

	(void) close(fd);

	return (rv);


bailout:
	if (fd != -1) {
		(void) close(fd);
	}
	if (*descrp != NULL) {
		free(*descrp);
		*descrp = NULL;
	}

	if (rv == CFGA_USB_IOCTL && errno == EBUSY) {
		rv = CFGA_USB_BUSY;	/* Provide more useful msg */
	}

	return (rv);
}


/* ========================================================================= */
/*
 * Support funcs called directly from cfga_* entry points.
 */


/*
 * Invoked from cfga_private_func.
 * Modify the USB persistant configuration file so that the device
 * represented by ap_id will henceforth be initialized to the desired
 * configuration setting (configuration index).
 */
static cfga_usb_ret_t
set_configuration(const char *ap_id, uint_t config, char *driver,
    usb_dev_descr_t *descrp, char **errstring)
{
	char		*serial_no = NULL;
	char		*dev_path = NULL;
	char		*tmp;
	size_t		size;
	cfga_usb_ret_t	rv = CFGA_USB_OK;

	DPRINTF("set_configuration: ap_id: %s, config:%d\n", ap_id, config);

	/* Only one bNumConfigurations, don't allow this operation */
	if (descrp->bNumConfigurations == 1) {
		DPRINTF("device supports %d configurations\n",
		    descrp->bNumConfigurations);
		rv = CFGA_USB_ONE_CONFIG;
		goto bailout;
	}

	/* get the serial number string if it exists */
	if (descrp->iSerialNumber != 0) {
		if ((rv = do_control_ioctl(ap_id, USB_DESCR_TYPE_STRING,
		    HUBD_SERIALNO_STR, (void **)&serial_no, &size)) !=
		    CFGA_USB_OK) {
			if (rv != CFGA_USB_ZEROLEN) {
				DPRINTF("set_configuration: get serial "
				    "no string failed\n");
				goto bailout;
			}
		}
	}

	dev_path = usb_get_devicepath(ap_id);
	if (dev_path == NULL) {
		DPRINTF("get device path failed\n");
		rv = CFGA_USB_DEVCTL;
		goto bailout;
	}

	DPRINTF("calling add_entry: vid: 0x%x pid:0x%x config:0x%x,",
	    descrp->idVendor, descrp->idProduct, config);
	DPRINTF("serial_no: %s\n\tdev_path: %s\n\tdriver: %s\n", serial_no ?
	    serial_no : "", dev_path ? dev_path : "", driver ? driver : "");

	/*
	 * the devicepath should be an absolute path.
	 * So, if path has leading "/devices" - nuke it.
	 */
	if (strncmp(dev_path, "/devices/", 9) == 0) {
		tmp = dev_path + 8;
	} else {
		tmp = dev_path;
	}

	/* Save an entry in the USBCONF_FILE  */
	if ((rv = add_entry(
	    "enable",		/* Always to "enable" */
	    descrp->idVendor,	/* vendorId */
	    descrp->idProduct,	/* ProductId */
	    config,		/* new cfgndx */
	    serial_no,		/* serial no string */
	    tmp,		/* device path */
	    driver,		/* Driver (optional) */
	    errstring))
	    != CFGA_USB_OK) {
		DPRINTF("set_configuration: add_entry failed\n");
		goto bailout;
	}

	/* Notify hubd that it needs to refresh its db.  */
	if ((rv = do_control_ioctl(ap_id, HUBD_REFRESH_DEVDB, NULL,
	    (void **)&dev_path, &size)) != CFGA_USB_OK) {
		DPRINTF("set_configuration: HUBD_REFRESH_DEVDB failed\n");
		goto bailout;
	}

bailout:
	if (dev_path) {
		free(dev_path);
	}
	if (serial_no) {
		free(serial_no);
	}

	return (rv);
}


/*
 * Invoked from cfga_private_func() and fill_in_ap_info().
 * Call into USBA and get the current configuration setting for this device,
 */
static cfga_usb_ret_t
get_config(const char *ap_id, uint_t *config)
{
	size_t		size;
	uint_t		*config_val = NULL;
	cfga_usb_ret_t	rv;

	if ((rv = do_control_ioctl(ap_id, HUBD_GET_CURRENT_CONFIG, NULL,
	    (void **)&config_val, &size)) != CFGA_USB_OK) {
		DPRINTF("get_config: get current config descr failed\n");
		goto bailout;
	}
	*config = *config_val;

bailout:
	free(config_val);
	return (rv);
}


/*
 * Invoked from cfga_private_func.
 * it does an unconfigure of the device followed by a configure,
 * thus essentially resetting the device.
 */
static cfga_usb_ret_t
reset_device(devctl_hdl_t devctl_hdl, nvlist_t *nvl)
{
	cfga_usb_ret_t	rv;

	DPRINTF("reset_device: \n");

	/*
	 * Disconnect and reconfigure the device.
	 * Note this forces the new default config to take effect.
	 */
	if (devctl_ap_disconnect(devctl_hdl, nvl) != 0) {
		DPRINTF("devctl_ap_unconfigure failed, errno: %d\n", errno);
		rv = CFGA_USB_DEVCTL;
		if (errno == EBUSY) {
			rv = CFGA_USB_BUSY;	/* Provide more useful msg */
		}

		return (rv);
	}

	if (devctl_ap_configure(devctl_hdl, nvl) != 0) {
		DPRINTF(" devctl_ap_configure failed, errno = %d\n", errno);
		return (CFGA_USB_DEVCTL);
	}

	return (CFGA_USB_OK);
}


/*
 * Called from cfga_list_ext.
 * Fills in the 'misc_info' field in the cfga buffer (displayed with -lv).
 */
static cfga_usb_ret_t
fill_in_ap_info(const char *ap_id, char *info_buf, size_t info_size)
{
	char			*mfg_str = NULL;	/* iManufacturer */
	char			*prod_str = NULL;	/* iProduct */
	char			*cfg_descr = NULL;	/* iConfiguration */
	uint_t			config;			/* curr cfg index */
	size_t			size;			/* tmp stuff */
	boolean_t		flag;		/* wether to print ":" or not */
	boolean_t		free_mfg_str = B_FALSE;
	boolean_t		free_prod_str = B_FALSE;
	boolean_t		free_cfg_str = B_FALSE;
	cfga_usb_ret_t		rv = CFGA_USB_OK;
	usb_dev_descr_t		*dev_descrp = NULL;	/* device descriptor */

	DPRINTF("fill_in_ap_info:\n");

	if ((rv = do_control_ioctl(ap_id, USB_DESCR_TYPE_DEV, NULL,
	    (void **)&dev_descrp, &size)) != CFGA_USB_OK) {
		DPRINTF("fill_in_ap_info: get dev descr failed\n");
		return (rv);
	}

	/* iManufacturer */
	mfg_str = USB_UNDEF_STR;
	if (dev_descrp->iManufacturer != 0) {
		if ((rv = do_control_ioctl(ap_id, USB_DESCR_TYPE_STRING,
		    HUBD_MFG_STR, (void **)&mfg_str, &size)) != CFGA_USB_OK) {
			if (rv == CFGA_USB_ZEROLEN) {
				rv = CFGA_USB_OK;
			} else {
				DPRINTF("get iManufacturer failed\n");
				goto bailout;
			}
		}
		free_mfg_str = B_TRUE;
	}

	/* iProduct */
	prod_str = USB_UNDEF_STR;
	if (dev_descrp->iProduct != 0) {
		if ((rv = do_control_ioctl(ap_id, USB_DESCR_TYPE_STRING,
		    HUBD_PRODUCT_STR, (void **)&prod_str,
		    &size)) != CFGA_USB_OK) {
			if (rv == CFGA_USB_ZEROLEN) {
				rv = CFGA_USB_OK;
			} else {
				DPRINTF("getting iProduct failed\n");
				goto bailout;
			}
		}
		free_prod_str = B_TRUE;
	}

	/* Current conifguration */
	if ((rv = get_config(ap_id, &config)) != CFGA_USB_OK) {
		DPRINTF("get_config failed\n");
		goto bailout;
	}

	/* Configuration string descriptor */
	cfg_descr = USB_NO_CFG_STR;
	if ((rv = do_control_ioctl(ap_id, USB_DESCR_TYPE_STRING,
	    HUBD_CFG_DESCR_STR, (void **)&cfg_descr, &size)) != CFGA_USB_OK) {
		if (rv == CFGA_USB_ZEROLEN) {
			rv = CFGA_USB_OK;
			flag = B_TRUE;
		} else {
			DPRINTF("HUBD_CFG_DESCR_STR failed\n");
			goto bailout;
		}
	}

	/* add ": " to output coz PSARC case says so */
	if ((cfg_descr != (char *)NULL) && rv != CFGA_USB_ZEROLEN) {
		flag = B_TRUE;
		free_cfg_str = B_TRUE;
	} else {
		flag = B_FALSE;
		cfg_descr = USB_NO_CFG_STR;
	}

	/* Dump local buf into passed-in buf. */
	(void) snprintf(info_buf, info_size,
	    "Mfg: %s  Product: %s  NConfigs: %d  Config: %d  %s%s", mfg_str,
	    prod_str, dev_descrp->bNumConfigurations, config,
	    (flag == B_TRUE) ? ": " : "", cfg_descr);

bailout:
	if (dev_descrp) {
		free(dev_descrp);
	}

	if ((free_mfg_str == B_TRUE) && mfg_str) {
		free(mfg_str);
	}

	if ((free_prod_str == B_TRUE) && prod_str) {
		free(prod_str);
	}

	if ((free_cfg_str == B_TRUE) && cfg_descr) {
		free(cfg_descr);
	}

	return (rv);
}


/* ========================================================================== */
/* Entry points */


/*ARGSUSED*/
cfga_err_t
cfga_change_state(
	cfga_cmd_t state_change_cmd,
	const char *ap_id,
	const char *options,
	struct cfga_confirm *confp,
	struct cfga_msg *msgp,
	char **errstring,
	cfga_flags_t flags)
{
	int		ret;
	int		len;
	char		*msg;
	char		*devpath;
	nvlist_t	*nvl = NULL;
	ap_rstate_t	rstate;
	ap_ostate_t	ostate;
	devctl_hdl_t	hdl = NULL;
	cfga_usb_ret_t	rv = CFGA_USB_OK;

	DPRINTF("cfga_change_state:\n");

	if ((rv = verify_params(ap_id, options, errstring)) != CFGA_USB_OK) {
		(void) cfga_help(msgp, options, flags);
		goto bailout;
	}

	/*
	 * All subcommands which can change state of device require
	 * root privileges.
	 */
	if (geteuid() != 0) {
		rv = CFGA_USB_PRIV;
		goto bailout;
	}

	if ((rv = setup_for_devctl_cmd(ap_id, &hdl, &nvl, 0)) !=
	    CFGA_USB_OK) {
		goto bailout;
	}

	switch (state_change_cmd) {
	case CFGA_CMD_CONFIGURE:
		if ((rv = device_configured(hdl, nvl, &rstate)) !=
		    CFGA_USB_NOT_CONFIGURED) {
			goto bailout;
		}

		if (rstate == AP_RSTATE_EMPTY) {
			goto bailout;
		}
		rv = CFGA_USB_OK;	/* Other statuses don't matter */

		if (devctl_ap_configure(hdl, nvl) != 0) {
			DPRINTF("cfga_change_state: devctl_ap_configure "
			    "failed.  errno: %d\n", errno);
			rv = CFGA_USB_DEVCTL;
		}

		devpath = usb_get_devicepath(ap_id);
		if (devpath == NULL) {
			int i;
			/*
			 * try for some time as USB hotplug thread
			 * takes a while to create the path
			 * and then eventually give up
			 */
			for (i = 0; i < 12 && (devpath == NULL); i++) {
				(void) sleep(6);
				devpath = usb_get_devicepath(ap_id);
			}

			if (devpath == NULL) {
				DPRINTF("cfga_change_state: get device "
				    "path failed i = %d\n", i);
				rv = CFGA_USB_DEVCTL;
				break;
			}
		}
		S_FREE(devpath);
		break;
	case CFGA_CMD_UNCONFIGURE:
		if ((rv = device_connected(hdl, nvl, &ostate)) !=
		    CFGA_USB_ALREADY_CONNECTED) {
			goto bailout;
		}

		/* check if it is already unconfigured */
		if ((rv = device_configured(hdl, nvl, &rstate)) ==
		    CFGA_USB_NOT_CONFIGURED) {
			goto bailout;
		}
		rv = CFGA_USB_OK;	/* Other statuses don't matter */

		len = strlen(USB_CONFIRM_0) + strlen(USB_CONFIRM_1) +
		    strlen("Unconfigure") + strlen(ap_id);
		if ((msg = (char *)calloc(len + 3, 1)) != NULL) {
			(void) snprintf(msg, len + 3, "Unconfigure %s%s\n%s",
			    USB_CONFIRM_0, ap_id, USB_CONFIRM_1);
		}
		if (!usb_confirm(confp, msg)) {
			free(msg);
			cleanup_after_devctl_cmd(hdl, nvl);
			return (CFGA_NACK);
		}
		free(msg);

		devpath = usb_get_devicepath(ap_id);
		if (devpath == NULL) {
			DPRINTF("cfga_change_state: get device path failed\n");
			rv = CFGA_USB_DEVCTL;
			break;
		}

		if ((rv = usb_rcm_offline(ap_id, errstring, devpath, flags)) !=
		    CFGA_USB_OK) {
			break;
		}

		ret = devctl_ap_unconfigure(hdl, nvl);
		if (ret != 0) {
			DPRINTF("cfga_change_state: devctl_ap_unconfigure "
			    "failed with errno: %d\n", errno);
			rv = CFGA_USB_DEVCTL;
			if (errno == EBUSY) {
				rv = CFGA_USB_BUSY;
			}
			(void) usb_rcm_online(ap_id, errstring, devpath, flags);
		} else {
			(void) usb_rcm_remove(ap_id, errstring, devpath, flags);
		}
		S_FREE(devpath);
		break;
	case CFGA_CMD_DISCONNECT:
		if ((rv = device_connected(hdl, nvl, &ostate)) !=
		    CFGA_USB_ALREADY_CONNECTED) {
			/*
			 * special case handling for
			 * SLM based cfgadm disconnects
			 */
			if (ostate == AP_OSTATE_UNCONFIGURED)
				goto bailout;
		}
		rv = CFGA_USB_OK;	/* Other statuses don't matter */

		len = strlen(USB_CONFIRM_0) + strlen(USB_CONFIRM_1) +
		    strlen("Disconnect") + strlen(ap_id);
		if ((msg = (char *)calloc(len + 3, 1)) != NULL) {
			(void) snprintf(msg, len + 3, "Disconnect %s%s\n%s",
			    USB_CONFIRM_0, ap_id, USB_CONFIRM_1);
		}
		if (!usb_confirm(confp, msg)) {
			free(msg);
			cleanup_after_devctl_cmd(hdl, nvl);
			return (CFGA_NACK);
		}
		free(msg);

		devpath = usb_get_devicepath(ap_id);
		if (devpath == NULL) {
			DPRINTF("cfga_change_state: get device path failed\n");
			rv = CFGA_USB_DEVCTL;
			break;
		}

		/* only call rcm_offline iff the state was CONFIGURED */
		if (ostate == AP_OSTATE_CONFIGURED) {
			if ((rv = usb_rcm_offline(ap_id, errstring,
			    devpath, flags)) != CFGA_USB_OK) {
				break;
			}
		}

		ret = devctl_ap_disconnect(hdl, nvl);
		if (ret != 0) {
			DPRINTF("cfga_change_state: devctl_ap_disconnect "
			    "failed with errno: %d\n", errno);
			rv = CFGA_USB_DEVCTL;
			if (errno == EBUSY) {
				rv = CFGA_USB_BUSY;
			}
			if (ostate == AP_OSTATE_CONFIGURED) {
				(void) usb_rcm_online(ap_id, errstring,
				    devpath, flags);
			}
		} else {
			if (ostate == AP_OSTATE_CONFIGURED) {
				(void) usb_rcm_remove(ap_id, errstring,
				    devpath, flags);
			}
		}
		S_FREE(devpath);
		break;
	case CFGA_CMD_CONNECT:
	case CFGA_CMD_LOAD:
	case CFGA_CMD_UNLOAD:
		(void) cfga_help(msgp, options, flags);
		rv = CFGA_USB_OPNOTSUPP;
		break;
	case CFGA_CMD_NONE:
	default:
		(void) cfga_help(msgp, options, flags);
		rv = CFGA_USB_INTERNAL_ERROR;
	}

bailout:
	cleanup_after_devctl_cmd(hdl, nvl);

	return (usb_err_msg(errstring, rv, ap_id, errno));
}


/*ARGSUSED*/
cfga_err_t
cfga_private_func(
	const char *func,
	const char *ap_id,
	const char *options,
	struct cfga_confirm *confp,
	struct cfga_msg *msgp,
	char **errstring,
	cfga_flags_t flags)
{
	int			len;
	char			*msg;
	nvlist_t		*list = NULL;
	ap_ostate_t		ostate;
	devctl_hdl_t		hdl = NULL;
	cfga_usb_ret_t		rv;
	usb_dev_descr_t		*dev_descrp = NULL;
	char			*driver = NULL;

	DPRINTF("cfga_private_func:\n");

	if ((rv = verify_params(ap_id, NULL, errstring)) != CFGA_USB_OK) {
		(void) cfga_help(msgp, options, flags);
		return (usb_err_msg(errstring, rv, ap_id, errno));
	}

	/*
	 * All subcommands which can change state of device require
	 * root privileges.
	 */
	if (geteuid() != 0) {
		rv = CFGA_USB_PRIV;
		goto bailout;
	}

	if (func == NULL) {
		rv = CFGA_USB_INTERNAL_ERROR;
		goto bailout;
	}

	if ((rv = setup_for_devctl_cmd(ap_id, &hdl, &list, 0)) !=
	    CFGA_USB_OK) {
		goto bailout;
	}

	if ((rv = device_connected(hdl, list, &ostate)) !=
	    CFGA_USB_ALREADY_CONNECTED) {
		goto bailout;
	}
	rv = CFGA_USB_OK;

	if (strcmp(func, RESET_DEVICE) == 0) {	/* usb_reset? */
		len = strlen(USB_CONFIRM_0) + strlen(USB_CONFIRM_1) +
		    strlen("Reset") + strlen(ap_id);
		if ((msg = (char *)calloc(len + 3, 1)) != NULL) {
			(void) snprintf(msg, len + 3, "Reset %s%s\n%s",
			    USB_CONFIRM_0, ap_id, USB_CONFIRM_1);
		} else {
			cleanup_after_devctl_cmd(hdl, list);
			return (CFGA_NACK);
		}

		if (!usb_confirm(confp, msg)) {
			cleanup_after_devctl_cmd(hdl, list);
			return (CFGA_NACK);
		}

		if ((rv = reset_device(hdl, list)) != CFGA_USB_OK) {
			goto bailout;
		}
	} else if (strncmp(func, USB_CONFIG, sizeof (USB_CONFIG)) == 0) {
		uint_t	config = 0;
		uint_t	actual_config;
		size_t	size;
		char	*subopts, *value;
		uint_t	cfg_opt_flag = B_FALSE;

		/* these are the only valid options */
		char *cfg_opts[] = {
			"config",	/* 0 */
			"drv",		/* 1 */
			NULL
		};

		/* return error if no options are specified */
		subopts = (char *)options;
		if (subopts == (char *)NULL) {
			DPRINTF("cfga_private_func: no options\n");
			rv = CFGA_USB_OPNOTSUPP;
			(void) cfga_help(msgp, options, flags);
			goto bailout;
		}

		/* parse options specified */
		while (*subopts != '\0') {
			switch (getsubopt(&subopts, cfg_opts, &value)) {
			case 0: /* config */
				if (value == NULL) {
					rv = CFGA_USB_OPNOTSUPP;
					(void) cfga_help(msgp,
					    options, flags);
					goto bailout;
				} else {
					errno = 0;
					config = strtol(value,
					    (char **)NULL, 10);
					if (errno) {
						DPRINTF(
						    "config conversion"
						    "failed\n");
						rv =
						    CFGA_USB_CONFIG_INVAL;
						goto bailout;
					}
				}
				cfg_opt_flag = B_TRUE;
				break;

			case 1: /* drv */
				if (value == NULL) {
					rv = CFGA_USB_OPNOTSUPP;
					(void) cfga_help(msgp,
					    options, flags);
					goto bailout;
				} else {
					S_FREE(driver);
					driver = strdup(value);
					if (driver == NULL) {
						rv =
						    CFGA_USB_INTERNAL_ERROR;
						goto bailout;
					}
				}
				break;

			default:
				rv = CFGA_USB_OPNOTSUPP;
				(void) cfga_help(msgp, options, flags);
				goto bailout;
			}
		}

		/* config is mandatory */
		if (cfg_opt_flag != B_TRUE) {
			rv = CFGA_USB_OPNOTSUPP;
			(void) cfga_help(msgp, options, flags);
			goto bailout;
		}
		DPRINTF("config = %x\n", config);

		len = strlen(USB_CONFIRM_0) + strlen(USB_CONFIRM_1) +
		    strlen("Setting") + strlen(ap_id) +
		    strlen("to USB configuration");
		/* len + 8 to account for config, \n and white space */
		if ((msg = (char *)calloc(len + 8, 1)) != NULL) {
			(void) snprintf(msg, len + 8,
			    "Setting %s%s\nto USB configuration %d\n%s",
			    USB_CONFIRM_0, ap_id, config, USB_CONFIRM_1);
		} else {
			rv = CFGA_USB_INTERNAL_ERROR;
			goto bailout;
		}

		if (!usb_confirm(confp, msg)) {
			S_FREE(driver);
			cleanup_after_devctl_cmd(hdl, list);
			return (CFGA_NACK);
		}

		/*
		 * Check that the option setting selected is in range.
		 */
		if ((rv = do_control_ioctl(ap_id, USB_DESCR_TYPE_DEV, NULL,
		    (void **)&dev_descrp, &size)) != CFGA_USB_OK) {
			DPRINTF("cfga_private_func: get dev descr failed\n");
			goto bailout;
		}

		if (config > dev_descrp->bNumConfigurations - 1) {
			DPRINTF("cfga_private_func: config index requested "
			    "(%d) exceeds bNumConfigurations - 1 (%d)\n",
			    config, dev_descrp->bNumConfigurations - 1);
			rv = CFGA_USB_CONFIG_INVAL;
			goto bailout;
		}

		/* Pass current setting to set_configuration */
		if ((rv = get_config(ap_id, &actual_config)) != CFGA_USB_OK) {
			goto bailout;
		}

		/* check if they match - yes, then nothing to do */
		if (actual_config == config) {
			DPRINTF("cfga_private_func: config index requested "
			    "(%d)  matches the actual config value %d\n",
			    config, actual_config);
			rv = CFGA_USB_OK;
			goto bailout;
		}

		/* Save the configuration settings  */
		if ((rv = set_configuration(ap_id, config, driver,
		    dev_descrp, errstring)) != CFGA_USB_OK) {
			goto bailout;
		}

		/* Reset device to force new config to take effect */
		if ((rv = reset_device(hdl, list)) != CFGA_USB_OK) {
			goto bailout;
		}

	} else {
		DPRINTF("cfga_private_func: unrecognized command.\n");
		(void) cfga_help(msgp, options, flags);
		errno = EINVAL;

		return (CFGA_INVAL);
	}

bailout:
	S_FREE(dev_descrp);
	S_FREE(driver);
	cleanup_after_devctl_cmd(hdl, list);

	return (usb_err_msg(errstring, rv, ap_id, errno));
}


/*ARGSUSED*/
cfga_err_t
cfga_test(
	const char *ap_id,
	const char *options,
	struct cfga_msg *msgp,
	char **errstring,
	cfga_flags_t flags)
{
	(void) cfga_help(msgp, options, flags);
	return (CFGA_OPNOTSUPP);
}


/*ARGSUSED*/
cfga_err_t
cfga_list_ext(
	const char *ap_id,
	cfga_list_data_t **ap_id_list,
	int *nlistp,
	const char *options,
	const char *listopts,
	char **errstring,
	cfga_flags_t flags)
{
	int			l_errno;
	char			*ap_id_log = NULL;
	size_t			size;
	nvlist_t		*user_nvlist = NULL;
	devctl_hdl_t		devctl_hdl = NULL;
	cfga_usb_ret_t		rv = CFGA_USB_OK;
	devctl_ap_state_t	devctl_ap_state;

	DPRINTF("cfga_list_ext:\n");

	if ((rv = verify_params(ap_id, options, errstring)) != CFGA_USB_OK) {
		goto bailout;
	}

	if (ap_id_list == NULL || nlistp == NULL) {
		DPRINTF("cfga_list_ext: list = NULL or nlistp = NULL\n");
		rv = CFGA_USB_INTERNAL_ERROR;
		goto bailout;
	}

	/* Get ap status */
	if ((rv = setup_for_devctl_cmd(ap_id, &devctl_hdl, &user_nvlist,
	    DC_RDONLY)) != CFGA_USB_OK) {
		goto bailout;
	}

	if (devctl_ap_getstate(devctl_hdl, user_nvlist, &devctl_ap_state) ==
	    -1) {
		DPRINTF("cfga_list_ext: devctl_ap_getstate failed. errno: %d\n",
		    errno);
		cleanup_after_devctl_cmd(devctl_hdl, user_nvlist);
		rv = CFGA_USB_DEVCTL;
		goto bailout;
	}
	cleanup_after_devctl_cmd(devctl_hdl, user_nvlist);

	/*
	 * Create cfga_list_data_t struct.
	 */
	if ((*ap_id_list =
	    (cfga_list_data_t *)malloc(sizeof (**ap_id_list))) == NULL) {
		DPRINTF("cfga_list_ext: malloc for cfga_list_data_t failed. "
		    "errno: %d\n", errno);
		rv = CFGA_USB_ALLOC_FAIL;
		goto bailout;
	}
	*nlistp = 1;


	/*
	 * Rest of the code fills in the cfga_list_data_t struct.
	 */

	/* Get /dev/cfg path to corresponding to the physical ap_id */
	/* Remember ap_id_log must be freed */
	rv = (cfga_usb_ret_t)physpath_to_devlink(CFGA_DEV_DIR, (char *)ap_id,
	    &ap_id_log, &l_errno, MATCH_MINOR_NAME);
	if (rv != 0) {
		rv = CFGA_USB_DEVLINK;
		goto bailout;
	}
	assert(ap_id_log != NULL);

	/* Get logical ap-id corresponding to the physical */
	if (strstr(ap_id_log, CFGA_DEV_DIR) == NULL) {
		DPRINTF("cfga_list_ext: devlink doesn't contain /dev/cfg\n");
		rv = CFGA_USB_DEVLINK;
		goto bailout;
	}
	(void) strlcpy((*ap_id_list)->ap_log_id,
	    /* Strip off /dev/cfg/ */ ap_id_log + strlen(CFGA_DEV_DIR)+ 1,
	    sizeof ((*ap_id_list)->ap_log_id));
	free(ap_id_log);
	ap_id_log = NULL;

	(void) strlcpy((*ap_id_list)->ap_phys_id, ap_id,
	    sizeof ((*ap_id_list)->ap_phys_id));

	switch (devctl_ap_state.ap_rstate) {
		case AP_RSTATE_EMPTY:
			(*ap_id_list)->ap_r_state = CFGA_STAT_EMPTY;
			break;
		case AP_RSTATE_DISCONNECTED:
			(*ap_id_list)->ap_r_state = CFGA_STAT_DISCONNECTED;
			break;
		case AP_RSTATE_CONNECTED:
			(*ap_id_list)->ap_r_state = CFGA_STAT_CONNECTED;
			break;
		default:
			rv = CFGA_USB_STATE;
			goto bailout;
	}

	switch (devctl_ap_state.ap_ostate) {
		case AP_OSTATE_CONFIGURED:
			(*ap_id_list)->ap_o_state = CFGA_STAT_CONFIGURED;
			break;
		case AP_OSTATE_UNCONFIGURED:
			(*ap_id_list)->ap_o_state = CFGA_STAT_UNCONFIGURED;
			break;
		default:
			rv = CFGA_USB_STATE;
			goto bailout;
	}

	switch (devctl_ap_state.ap_condition) {
		case AP_COND_OK:
			(*ap_id_list)->ap_cond = CFGA_COND_OK;
			break;
		case AP_COND_FAILING:
			(*ap_id_list)->ap_cond = CFGA_COND_FAILING;
			break;
		case AP_COND_FAILED:
			(*ap_id_list)->ap_cond = CFGA_COND_FAILED;
			break;
		case AP_COND_UNUSABLE:
			(*ap_id_list)->ap_cond = CFGA_COND_UNUSABLE;
			break;
		case AP_COND_UNKNOWN:
			(*ap_id_list)->ap_cond = CFGA_COND_UNKNOWN;
			break;
		default:
			rv = CFGA_USB_STATE;
			goto bailout;
	}

	(*ap_id_list)->ap_class[0] = '\0';	/* Filled by libcfgadm */
	(*ap_id_list)->ap_busy = devctl_ap_state.ap_in_transition;
	(*ap_id_list)->ap_status_time = devctl_ap_state.ap_last_change;
	(*ap_id_list)->ap_info[0] = NULL;

	if ((*ap_id_list)->ap_r_state == CFGA_STAT_CONNECTED) {
		char *str_p;
		size_t	str_len;

		/* Fill in the info for the -v option display.  */
		if ((rv = fill_in_ap_info(ap_id, (*ap_id_list)->ap_info,
		    sizeof ((*ap_id_list)->ap_info))) != CFGA_USB_OK) {
			DPRINTF("cfga_list_ext: fill_in_ap_info failed\n");
			goto bailout;
		}

		/* Fill in ap_type */
		if ((rv = do_control_ioctl(ap_id, HUBD_GET_CFGADM_NAME, NULL,
		    (void **)&str_p, &size)) != CFGA_USB_OK) {
			DPRINTF("cfga_list_ext: do_control_ioctl failed\n");
			goto bailout;
		}

		(void) strcpy((*ap_id_list)->ap_type, "usb-");
		str_len = strlen((*ap_id_list)->ap_type);

		/*
		 * NOTE: In the cfgadm display the "Type" column is only 12
		 * chars long. Most USB devices can be displayed here with a
		 * "usb-" prefix. Only USB keyboard cannot be displayed in
		 * its entirety as "usb-keybaord" is 13 chars in length.
		 * It will show up as "usb-kbd".
		 */
		if (strncasecmp(str_p, "keyboard", 8) != 0) {
			(void) strlcpy((*ap_id_list)->ap_type + str_len, str_p,
			    sizeof ((*ap_id_list)->ap_type) - str_len);
		} else {
			(void) strlcpy((*ap_id_list)->ap_type + str_len, "kbd",
			    sizeof ((*ap_id_list)->ap_type) - str_len);
		}

		free(str_p);
	} else {
		(void) strcpy((*ap_id_list)->ap_type,
		    USB_CFGADM_DEFAULT_AP_TYPE);
	}

	return (usb_err_msg(errstring, rv, ap_id, errno));
bailout:
	if (*ap_id_list != NULL) {
		free(*ap_id_list);
	}
	if (ap_id_log != NULL) {
		free(ap_id_log);
	}

	return (usb_err_msg(errstring, rv, ap_id, errno));
}


/*
 * This routine accepts a variable number of message IDs and constructs
 * a corresponding error string which is printed via the message print routine
 * argument.
 */
static void
cfga_msg(struct cfga_msg *msgp, const char *str)
{
	int len;
	char *q;

	if (msgp == NULL || msgp->message_routine == NULL) {
		DPRINTF("cfga_msg: msg\n");
		return;
	}

	if ((len = strlen(str)) == 0) {
		DPRINTF("cfga_msg: null str\n");
		return;
	}

	if ((q = (char *)calloc(len + 1, 1)) == NULL) {
		DPRINTF("cfga_msg: null q\n");
		return;
	}

	(void) strcpy(q, str);
	(*msgp->message_routine)(msgp->appdata_ptr, q);

	free(q);
}


/* ARGSUSED */
cfga_err_t
cfga_help(struct cfga_msg *msgp, const char *options, cfga_flags_t flags)
{
	DPRINTF("cfga_help:\n");
	if (options) {
		cfga_msg(msgp, dgettext(TEXT_DOMAIN, usb_help[HELP_UNKNOWN]));
		cfga_msg(msgp, options);
	}

	cfga_msg(msgp, dgettext(TEXT_DOMAIN, usb_help[HELP_HEADER]));
	cfga_msg(msgp, usb_help[HELP_CONFIG]);
	cfga_msg(msgp, usb_help[HELP_RESET_SLOT]);
	cfga_msg(msgp, usb_help[HELP_CONFIG_SLOT]);

	return (CFGA_OK);
}


static int
usb_confirm(struct cfga_confirm *confp, char *msg)
{
	int rval;

	if (confp == NULL || confp->confirm == NULL) {
		return (0);
	}

	rval = (*confp->confirm)(confp->appdata_ptr, msg);
	DPRINTF("usb_confirm: %d\n", rval);

	return (rval);
}


static char *
usb_get_devicepath(const char *ap_id)
{
	char		*devpath = NULL;
	size_t		size;
	cfga_usb_ret_t	rv;

	rv = do_control_ioctl(ap_id, HUBD_GET_DEVICE_PATH, NULL,
	    (void **)&devpath, &size);

	if (rv == CFGA_USB_OK) {
		DPRINTF("usb_get_devicepath: get device path ioctl ok\n");
		return (devpath);
	} else {
		DPRINTF("usb_get_devicepath: get device path ioctl failed\n");
		return ((char *)NULL);
	}
}
