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

#include <sys/param.h>
#include <sys/stat.h>
#include <errno.h>
#include <string.h>
#include <dirent.h>
#include "cfga_sdcard.h"

/*
 * This file contains the entry points to the plug-in as defined in the
 * config_admin(3X) man page.
 */

/*
 * Set the version number for the cfgadm library's use.
 */
int cfga_version = CFGA_HSL_V2;

enum {
	HELP_HEADER = 1,
	HELP_CONFIG,
	HELP_RESET_SLOT,
	HELP_UNKNOWN
};

/* SDCARD specific help messages */
static char *sdcard_help[] = {
	NULL,
	"SD card specific commands:\n",
	" cfgadm -c [configure|unconfigure|disconnect|connect] ap_id "
	"[ap_id...]\n",
	" cfgadm -x sdcard_reset_slot ap_id [ap_id...]\n",
	"\tunknown command or option:\n",
	NULL
};	/* End help messages */


/*
 * Messages.
 */
static msgcvt_t sdcard_msgs[] = {
	/* CFGA_SDCARD_OK */
	{ CVT, CFGA_OK, "" },

	/* CFGA_SDCARD_NACK */
	{ CVT, CFGA_NACK, "" },

	/* CFGA_SDCARD_UNKNOWN / CFGA_LIB_ERROR -> "Library error" */
	{ CVT, CFGA_LIB_ERROR, "Unknown message; internal error" },

	/* CFGA_SDCARD_PRIV / CFGA_PRIV -> "Insufficient privileges" */
	{ CVT, CFGA_PRIV, "" },

	/*
	 * CFGA_SDCARD_DYNAMIC_AP /
	 * CFGA_LIB_ERROR -> "Configuration operation invalid"
	 */
	{ CVT, CFGA_INVAL, "Cannot identify attached device" },

	/* CFGA_SDCARD_INTERNAL_ERROR / CFGA_LIB_ERROR -> "Library error" */
	{ CVT, CFGA_LIB_ERROR, "Internal error" },

	/* CFGA_SDCARD_ALLOC_FAIL / CFGA_LIB_ERROR -> "Library error" */
	{ CVT, CFGA_LIB_ERROR, "Memory allocation failure" },

	/* CFGA_SDCARD_IOCTL / CFGA_ERROR -> "Hardware specific failure"  */
	{ CVT, CFGA_ERROR, "Driver ioctl failed " },

	/* CFGA_SDCARD_DEVCTL / CFGA_LIB_ERROR -> "Library error" */
	{ CVT, CFGA_LIB_ERROR, "Internal error: "
	    "Cannot allocate devctl handle " },

	/* CFGA_SDCARD_AP / CFGA_APID_NOEXIST -> "Attachment point not found" */
	{ CVT, CFGA_APID_NOEXIST, "" },

	/*
	 * CFGA_SDCARD_BUSY /
	 * CFGA_SYSTEM_BUSY -> "System is busy, try again"
	 */
	{ CVT, CFGA_SYSTEM_BUSY, "" },

	/* CFGA_SDCARD_DEVLINK / CFGA_LIB_ERROR -> "Library error" */
	{ CVT, CFGA_LIB_ERROR, "Could not find /dev/cfg link for " },

	/*
	 * CFGA_SDCARD_INVALID_DEVNAME /
	 * CFGA_INVAL -> "Configuration operation invalid"
	 */
	{ CVT, CFGA_INVAL, "Cannot specify device name" },

	/* CFGA_SDCARD_DATA_ERROR / CFGA_DATA_ERROR -> "Data error" */
	{ CVT, CFGA_DATA_ERROR, "cfgadm data error" },

	/*
	 * CFGA_SDCARD_DEV_CONFIGURE /
	 * CFGA_ERROR -> "Hardware specific failure"
	 */
	{ CVT, CFGA_ERROR, "Failed to config device at " },

	/*
	 * CFGA_SDCARD_DEV_UNCONFIGURE /
	 * CFGA_ERROR -> "Hardware specific failure"
	 */
	{ CVT, CFGA_ERROR, "Failed to unconfig device at " },

	/*
	 * CFGA_SDCARD_NOT_CONNECTED
	 * CFGA_INVAL -> "Configuration operation invalid"
	 */
	{ CVT, CFGA_INVAL, "No device connected to " },

	/*
	 * CFGA_SDCARD_DISCONNECTED
	 * CFGA_INVAL -> "Configuration operation invalid"
	 */
	{ CVT, CFGA_INVAL, "Slot already disconnected at " },

	/*
	 * CFGA_SDCARD_NOT_CONFIGURED /
	 * CFGA_INVAL -> "Configuration operation invalid"
	 */
	{ CVT, CFGA_INVAL, "No device configured at " },

	/*
	 * CFGA_SDCARD_ALREADY_CONNECTED /
	 * CFGA_INVAL -> "Configuration operation invalid"
	 */
	{ CVT, CFGA_INVAL, "Device already connected to " },

	/*
	 * CFGA_SDCARD_ALREADY_CONFIGURED /
	 * CFGA_INVAL -> "Configuration operation invalid"
	 */
	{ CVT, CFGA_INVAL, "Device already configured at " },

	/* CFGA_SDCARD_DEVICE_UNCONFIGURED */
	{ CVT, CFGA_OK, "Device unconfigured prior to disconnect" },

	/*
	 * CFGA_SDCARD_OPNOTSUPP /
	 * CFGA_OPNOTSUPP -> "Configuration operation not supported"
	 */
	{ CVT, CFGA_OPNOTSUPP, "Operation not supported" },

	/*
	 * CFGA_SDCARD_HWOPNOTSUPP /
	 * CFGA_ERROR -> "Hardware specific failure"
	 */
	{ CVT, CFGA_ERROR, "Hardware specific operation not supported" },

	/* CFGA_SDCARD_OPTIONS / CFGA_ERROR -> "Hardware specific failure" */
	{ CVT, CFGA_ERROR, "Hardware specific option not supported" },

	/* CFGA_SDCARD_STATE / CFGA_LIB_ERROR -> "Library error" */
	{ CVT, CFGA_LIB_ERROR, "Internal error: Unrecognized ap state" },

	/* CFGA_SDCARD_OPEN / CFGA_LIB_ERROR -> "Library error" */
	{ CVT, CFGA_LIB_ERROR, "Cannot open " },

	/*
	 * CFGA_SDCARD_RCM_HANDLE /
	 * CFGA_ERROR -> "Hardware specific failure"
	 */
	{ CVT, CFGA_ERROR, "cannot get RCM handle"},

	/*
	 * CFGA_SDCARD_RCM_OFFLINE /
	 * CFGA_SYSTEM_BUSY -> "System is busy, try again"
	 */
	{ CVT, CFGA_SYSTEM_BUSY, "failed to offline: "},

	/*
	 * CFGA_SDCARD_RCM_REMOVE /
	 * CFGA_SYSTEM_BUSY -> "System is busy, try again"
	 */
	{ CVT, CFGA_SYSTEM_BUSY, "failed to remove: "},

	/*
	 * CFGA_SDCARD_RCM_ONLINE /
	 * CFGA_SYSTEM_BUSY -> "System is busy, try again"
	 */
	{ CVT, CFGA_ERROR, "failed to online: "},

	/* CFGA_SDCARD_CONFIRM_RESET */
	{ CVT, CFGA_OK, "Reset the device at %s?\n"
	    "This will operation will disrupt activity on the SD card.\n"
	    "Continue"
	},

	/* CFGA_SDCARD_CONFIRM_UNCONFIGURE */
	{ CVT, CFGA_OK, "Unconfigure the device at %s?\n"
	    "This will operation will disrupt activity on the SD card.\n"
	    "Continue"
	},

	/* CFGA_SDCARD_CONFIRM_DISCONNECT */
	{ CVT, CFGA_OK, "Disconnect the device at %s?\n"
	    "This will operation will disrupt activity on the SD card.\n"
	    "Continue"
	}
};

static cfga_err_t
sdcard_err_msg(char **errstring, cfga_sdcard_ret_t ret, const char *, int);

static cfga_sdcard_ret_t
verify_params(const char *ap_id, const char *options, char **errstring);

static cfga_sdcard_ret_t
setup_for_devctl_cmd(const char *ap_id, devctl_hdl_t *devctl_hdl, uint_t oflag);

static cfga_sdcard_ret_t
slot_state(devctl_hdl_t hdl, ap_rstate_t *rstate, ap_ostate_t *ostate);

static cfga_sdcard_ret_t
do_control_ioctl(const char *ap_id, int subcommand, void *data, size_t size);

static void
cleanup_after_devctl_cmd(devctl_hdl_t devctl_hdl);

static cfga_sdcard_ret_t
sdcard_get_devicepath(const char *ap_id, char *devpath);

static cfga_sdcard_ret_t
sdcard_reset_slot(const char *ap_id);

static int
sdcard_confirm(struct cfga_confirm *confp, char *msg);

static cfga_sdcard_ret_t
sdcard_rcm_offline(char *, char **, cfga_flags_t);

static void
sdcard_rcm_online(char *, char **);

static void
sdcard_rcm_remove(char *, char **);

static void
sdcard_rcm_info_table(rcm_info_t *, char **);

static cfga_sdcard_ret_t
sdcard_rcm_init(void);



/* Utilities */

static cfga_sdcard_ret_t
physpath_to_devlink(const char *basedir, const char *node_path,
    char **logpp, int *l_errnop)
{
	char *linkpath;
	char *buf;
	char *real_path;
	DIR *dp;
	struct dirent *dep, *newdep;
	int deplen;
	boolean_t found = B_FALSE;
	int err = 0;
	struct stat sb;
	char *p;
	cfga_sdcard_ret_t rv = CFGA_SDCARD_INTERNAL_ERROR;

	/*
	 * Using libdevinfo for this is overkill and kills performance
	 * when multiple consumers of libcfgadm are executing
	 * concurrently.
	 */
	if ((dp = opendir(basedir)) == NULL) {
		*l_errnop = errno;
		return (CFGA_SDCARD_INTERNAL_ERROR);
	}

	linkpath = malloc(PATH_MAX);
	buf = malloc(PATH_MAX);
	real_path = malloc(PATH_MAX);

	deplen = pathconf(basedir, _PC_NAME_MAX);
	deplen = (deplen <= 0 ? MAXNAMELEN : deplen) +
	    sizeof (struct dirent);
	dep = (struct dirent *)malloc(deplen);

	if (dep == NULL || linkpath == NULL || buf == NULL ||
	    real_path == NULL) {
		*l_errnop = ENOMEM;
		rv = CFGA_SDCARD_ALLOC_FAIL;
		goto pp_cleanup;
	}

	*logpp = NULL;

	while (!found && (err = readdir_r(dp, dep, &newdep)) == 0 &&
	    newdep != NULL) {

		assert(newdep == dep);

		if (strcmp(dep->d_name, ".") == 0 ||
		    strcmp(dep->d_name, "..") == 0)
			continue;

		(void) snprintf(linkpath, MAXPATHLEN,
		    "%s/%s", basedir, dep->d_name);

		if (lstat(linkpath, &sb) < 0)
			continue;

		if (S_ISDIR(sb.st_mode)) {

			if ((rv = physpath_to_devlink(linkpath, node_path,
			    logpp, l_errnop)) != CFGA_SDCARD_OK) {

				goto pp_cleanup;
			}

			if (*logpp != NULL)
				found = B_TRUE;

		} else if (S_ISLNK(sb.st_mode)) {

			bzero(buf, PATH_MAX);
			if (readlink(linkpath, buf, PATH_MAX) < 0)
				continue;


			/*
			 * realpath() is too darn slow, so fake
			 * it, by using what we know about /dev
			 * links: they are always of the form:
			 * <"../">+/devices/<path>
			 */
			p = buf;
			while (strncmp(p, "../", 3) == 0)
				p += 3;

			if (p != buf)
				p--;	/* back up to get a slash */

			assert (*p == '/');

			if (strcmp(p, node_path) == 0) {
				*logpp = strdup(linkpath);
				if (*logpp == NULL) {

					rv = CFGA_SDCARD_ALLOC_FAIL;
					goto pp_cleanup;
				}

				found = B_TRUE;
			}
		}
	}

	free(linkpath);
	free(buf);
	free(real_path);
	free(dep);
	(void) closedir(dp);

	if (err != 0) {
		*l_errnop = err;
		return (CFGA_SDCARD_INTERNAL_ERROR);
	}

	return (CFGA_SDCARD_OK);

pp_cleanup:

	if (dp)
		(void) closedir(dp);
	if (dep)
		free(dep);
	if (linkpath)
		free(linkpath);
	if (buf)
		free(buf);
	if (real_path)
		free(real_path);
	if (*logpp) {
		free(*logpp);
		*logpp = NULL;
	}
	return (rv);
}


/*
 * Given the index into a table (msgcvt_t) of messages, get the message
 * string, converting it to the proper locale if necessary.
 * NOTE: Indexes are defined in cfga_sdcard.h
 */
static const char *
get_msg(uint_t msg_index, msgcvt_t *msg_tbl, uint_t tbl_size)
{
	if (msg_index >= tbl_size) {
		msg_index = CFGA_SDCARD_UNKNOWN;
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
	char    *str;
	size_t  total_len;
	va_list valist;

	va_start(valist, ret_str);

	total_len = (*ret_str == NULL) ? 0 : strlen(*ret_str);

	while ((str = va_arg(valist, char *)) != NULL) {
		size_t  len = strlen(str);
		char    *old_str = *ret_str;

		*ret_str = (char *)realloc(*ret_str, total_len + len + 1);
		if (*ret_str == NULL) {
			/* We're screwed */
			free(old_str);
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
 * internationalized if necessary, and concatenates it into a new
 * memory buffer, and points *errstring to it.
 * Note not all rvs will result in an error message return, as not all
 * error conditions warrant an SD-specific error message - for those
 * conditions the cfgadm generic messages are sufficient.
 *
 * Some messages may display ap_id or errno, which is why they are passed
 * in.
 */
cfga_err_t
sdcard_err_msg(
	char **errstring,
	cfga_sdcard_ret_t rv,
	const char *ap_id,
	int l_errno)
{
	if (errstring == NULL) {
		return (sdcard_msgs[rv].cfga_err);
	}

	/*
	 * Generate the appropriate SDCARD-specific error message(s) (if any).
	 */
	switch (rv) {
	case CFGA_SDCARD_OK:
	case CFGA_NACK:
		/* Special case - do nothing.  */
		break;

	case CFGA_SDCARD_UNKNOWN:
	case CFGA_SDCARD_PRIV:
	case CFGA_SDCARD_DYNAMIC_AP:
	case CFGA_SDCARD_INTERNAL_ERROR:
	case CFGA_SDCARD_ALLOC_FAIL:
	case CFGA_SDCARD_DATA_ERROR:
	case CFGA_SDCARD_OPNOTSUPP:
	case CFGA_SDCARD_OPTIONS:
	case CFGA_SDCARD_STATE:

		/* These messages require no additional strings passed. */
		set_msg(errstring, ERR_STR(rv), NULL);
		break;

	case CFGA_SDCARD_HWOPNOTSUPP:
		/* hardware-specific help needed */
		set_msg(errstring, ERR_STR(rv), NULL);
		set_msg(errstring, "\n",
		    dgettext(TEXT_DOMAIN, sdcard_help[HELP_HEADER]), NULL);
		set_msg(errstring, sdcard_help[HELP_RESET_SLOT], NULL);
		break;

	case CFGA_SDCARD_AP:
	case CFGA_SDCARD_BUSY:
	case CFGA_SDCARD_DEVLINK:
	case CFGA_SDCARD_DEV_CONFIGURE:
	case CFGA_SDCARD_DEV_UNCONFIGURE:
	case CFGA_SDCARD_NOT_CONNECTED:
	case CFGA_SDCARD_DISCONNECTED:
	case CFGA_SDCARD_NOT_CONFIGURED:
	case CFGA_SDCARD_ALREADY_CONNECTED:
	case CFGA_SDCARD_ALREADY_CONFIGURED:

	case CFGA_SDCARD_RCM_HANDLE:
	case CFGA_SDCARD_RCM_ONLINE:
	case CFGA_SDCARD_RCM_OFFLINE:
	case CFGA_SDCARD_RCM_REMOVE:
		/* These messages also print ap_id.  */
		set_msg(errstring, ERR_STR(rv), "ap_id: ", ap_id, "", NULL);
		break;


	case CFGA_SDCARD_IOCTL:
		/* These messages also print errno.  */
		{
			char *errno_str = l_errno ? strerror(l_errno) : "";

			set_msg(errstring, ERR_STR(rv), errno_str,
			    l_errno ? "\n" : "", NULL);
			break;
		}

	case CFGA_SDCARD_OPEN:
		/* These messages also apid and errno.  */
		{
			char *errno_str = l_errno ? strerror(l_errno) : "";

			set_msg(errstring, ERR_STR(rv), "ap_id: ", ap_id, "\n",
			    errno_str, l_errno ? "\n" : "", NULL);
			break;
		}

	default:
		set_msg(errstring, ERR_STR(CFGA_SDCARD_INTERNAL_ERROR), NULL);

	} /* end switch */


	/*
	 * Determine the proper error code to send back to the cfgadm library.
	 */
	return (sdcard_msgs[rv].cfga_err);
}


/*
 * Entry points
 */
/* cfgadm entry point */
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
	ap_rstate_t	rstate;
	ap_ostate_t	ostate;
	devctl_hdl_t	hdl = NULL;
	cfga_sdcard_ret_t	rv = CFGA_SDCARD_OK;
	char		*pdyn;
	int		i;
	char		devpath[MAXPATHLEN];
	char		msg[256];

	/*
	 * All sub-commands which can change state of device require
	 * root privileges.
	 */
	if (geteuid() != 0) {
		rv = CFGA_SDCARD_PRIV;
		goto bailout;
	}

	if ((rv = verify_params(ap_id, options, errstring)) != CFGA_SDCARD_OK) {
		(void) cfga_help(msgp, options, flags);
		goto bailout;
	}

	if ((rv = setup_for_devctl_cmd(ap_id, &hdl, DC_RDONLY)) !=
	    CFGA_SDCARD_OK) {
		goto bailout;
	}

	switch (state_change_cmd) {
	case CFGA_CMD_CONFIGURE:
		if ((rv = slot_state(hdl, &rstate, &ostate)) != CFGA_SDCARD_OK)
			goto bailout;

		if (ostate == AP_OSTATE_CONFIGURED) {
			rv = CFGA_SDCARD_ALREADY_CONFIGURED;
			goto bailout;
		}
		/* Disallow dynamic AP name component */
		if (GET_DYN(ap_id) != NULL) {
			rv = CFGA_SDCARD_INVALID_DEVNAME;
			goto bailout;
		}

		if (rstate == AP_RSTATE_EMPTY) {
			rv = CFGA_SDCARD_NOT_CONNECTED;
			goto bailout;
		}
		rv = CFGA_SDCARD_OK;

		if (devctl_ap_configure(hdl, NULL) != 0) {
			rv = CFGA_SDCARD_DEV_CONFIGURE;
			goto bailout;
		}

		for (i = 0; i < 15; i++) {
			/*
			 * We wait up to ~30 seconds for this to complete.
			 * Hotplug is done asynchronously.
			 */
			rv = sdcard_get_devicepath(ap_id, devpath);
			if (rv == CFGA_SDCARD_OK)
				break;
			(void) sleep(2);
		}
		if (rv != CFGA_SDCARD_OK) {
			rv = CFGA_SDCARD_DEV_CONFIGURE;
			goto bailout;
		}

		break;

	case CFGA_CMD_UNCONFIGURE:
		if ((rv = slot_state(hdl, &rstate, &ostate)) != CFGA_SDCARD_OK)
			goto bailout;

		if (rstate != AP_RSTATE_CONNECTED) {
			rv = CFGA_SDCARD_NOT_CONNECTED;
			goto bailout;
		}

		if (ostate != AP_OSTATE_CONFIGURED) {
			rv = CFGA_SDCARD_NOT_CONFIGURED;
			goto bailout;
		}
		/* Strip off AP name dynamic component, if present */
		if ((pdyn = GET_DYN(ap_id)) != NULL) {
			*pdyn = '\0';
		}

		rv = CFGA_SDCARD_OK;

		/*LINTED E_SEC_PRINTF_VAR_FMT*/
		(void) snprintf(msg, sizeof (msg),
		    ERR_STR(CFGA_SDCARD_CONFIRM_UNCONFIGURE), ap_id);

		if (!sdcard_confirm(confp, msg)) {
			rv = CFGA_SDCARD_NACK;
			break;
		}

		if (sdcard_get_devicepath(ap_id, devpath) != CFGA_SDCARD_OK) {
			(void) printf("cfga_change_state: "
			    "get device path failed\n");
			rv = CFGA_SDCARD_DEV_UNCONFIGURE;
			break;
		}

		rv = sdcard_rcm_offline(devpath, errstring, flags);
		if (rv != CFGA_SDCARD_OK) {
			break;
		}

		ret = devctl_ap_unconfigure(hdl, NULL);

		if (ret != 0) {
			rv = CFGA_SDCARD_DEV_UNCONFIGURE;
			if (errno == EBUSY) {
				rv = CFGA_SDCARD_BUSY;
			}
			sdcard_rcm_online(devpath, errstring);
		} else {
			sdcard_rcm_remove(devpath, errstring);
		}

		break;

	case CFGA_CMD_DISCONNECT:
		if ((rv = slot_state(hdl, &rstate, &ostate)) != CFGA_SDCARD_OK)
			goto bailout;

		if (rstate == AP_RSTATE_DISCONNECTED) {
			rv = CFGA_SDCARD_DISCONNECTED;
			goto bailout;
		}

		/* Strip off AP name dynamic component, if present */
		if ((pdyn = GET_DYN(ap_id)) != NULL) {
			*pdyn = '\0';
		}


		rv = CFGA_SDCARD_OK; /* other statuses don't matter */


		/*
		 * If the port originally with device attached and was
		 * unconfigured already, the devicepath for the sd will be
		 * removed. sdcard_get_devicepath in this case is not necessary.
		 */

		/* only call rcm_offline if the state was CONFIGURED */
		if (ostate == AP_OSTATE_CONFIGURED) {
			if (sdcard_get_devicepath(ap_id, devpath) !=
			    CFGA_SDCARD_OK) {
				(void) printf(
				    "cfga_change_state: get path failed\n");
				rv = CFGA_SDCARD_DEV_UNCONFIGURE;
				break;
			}

			/*LINTED E_SEC_PRINTF_VAR_FMT*/
			(void) snprintf(msg, sizeof (msg),
			    ERR_STR(CFGA_SDCARD_CONFIRM_DISCONNECT), ap_id);
			if (!sdcard_confirm(confp, msg)) {
				rv = CFGA_SDCARD_NACK;
				break;
			}

			rv = sdcard_rcm_offline(devpath, errstring, flags);
			if (rv != CFGA_SDCARD_OK) {
				break;
			}

			ret = devctl_ap_unconfigure(hdl, NULL);
			if (ret != 0) {
				(void) printf(
				    "devctl_ap_unconfigure failed\n");
				rv = CFGA_SDCARD_DEV_UNCONFIGURE;
				if (errno == EBUSY)
					rv = CFGA_SDCARD_BUSY;
				sdcard_rcm_online(devpath, errstring);

				/*
				 * The current policy is that if unconfigure
				 * failed, do not continue with disconnect.
				 */
				break;
			} else {
				(void) printf("%s\n",
				    ERR_STR(CFGA_SDCARD_DEVICE_UNCONFIGURED));
				sdcard_rcm_remove(devpath, errstring);
			}
		} else if (rstate == AP_RSTATE_CONNECTED ||
		    rstate == AP_RSTATE_EMPTY) {
			/*LINTED E_SEC_PRINTF_VAR_FMT*/
			(void) snprintf(msg, sizeof (msg),
			    ERR_STR(CFGA_SDCARD_CONFIRM_DISCONNECT), ap_id);

			if (!sdcard_confirm(confp, msg)) {
				rv = CFGA_SDCARD_NACK;
				break;
			}
		}
		ret = devctl_ap_disconnect(hdl, NULL);
		if (ret != 0) {
			rv = CFGA_SDCARD_IOCTL;
			if (errno == EBUSY) {
				rv = CFGA_SDCARD_BUSY;
			}
		}
		break;

	case CFGA_CMD_CONNECT:
		if ((rv = slot_state(hdl, &rstate, &ostate)) != CFGA_SDCARD_OK)
			goto bailout;

		if (rstate == AP_RSTATE_CONNECTED) {
			rv = CFGA_SDCARD_ALREADY_CONNECTED;
			goto bailout;
		}

		/* Disallow dynamic AP name component */
		if (GET_DYN(ap_id) != NULL) {
			rv = CFGA_SDCARD_INVALID_DEVNAME;
			goto bailout;
		}

		ret = devctl_ap_connect(hdl, NULL);
		if (ret != 0) {
			rv = CFGA_SDCARD_IOCTL;
		} else {
			rv = CFGA_SDCARD_OK;
		}

		break;

	case CFGA_CMD_LOAD:
	case CFGA_CMD_UNLOAD:
		(void) cfga_help(msgp, options, flags);
		rv = CFGA_SDCARD_OPNOTSUPP;
		break;

	case CFGA_CMD_NONE:
	default:
		(void) cfga_help(msgp, options, flags);
		rv = CFGA_SDCARD_INTERNAL_ERROR;
	}

bailout:
	cleanup_after_devctl_cmd(hdl);

	return (sdcard_err_msg(errstring, rv, ap_id, errno));
}

/* cfgadm entry point */
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
	devctl_hdl_t		hdl = NULL;
	cfga_sdcard_ret_t	rv;
	char			*str_p;
	char			msg[256];

	if ((rv = verify_params(ap_id, NULL, errstring)) != CFGA_SDCARD_OK) {
		(void) cfga_help(msgp, options, flags);
		return (sdcard_err_msg(errstring, rv, ap_id, errno));
	}

	/*
	 * All subcommands which can change state of device require
	 * root privileges.
	 */
	if (geteuid() != 0) {
		rv = CFGA_SDCARD_PRIV;
		goto bailout;
	}

	if (func == NULL) {
		rv = CFGA_SDCARD_OPTIONS;
		goto bailout;
	}

	if ((rv = setup_for_devctl_cmd(ap_id, &hdl, 0)) != CFGA_SDCARD_OK) {
		goto bailout;
	}

	/* We do not care here about dynamic AP name component */
	if ((str_p = GET_DYN(ap_id)) != NULL) {
		*str_p = '\0';
	}

	if (strcmp(func, RESET_SLOT) == 0) {
		/*LINTED E_SEC_PRINTF_VAR_FMT*/
		(void) snprintf(msg, sizeof (msg),
		    ERR_STR(CFGA_SDCARD_CONFIRM_RESET), ap_id);

		if (!sdcard_confirm(confp, msg)) {
			rv = CFGA_SDCARD_NACK;
			goto bailout;
		}
		if ((rv = sdcard_reset_slot(ap_id)) != CFGA_SDCARD_OK) {
			goto bailout;
		}

		rv = CFGA_SDCARD_OK;
	} else {

		/* Unrecognized operation request */
		rv = CFGA_SDCARD_HWOPNOTSUPP;
	}

bailout:
	cleanup_after_devctl_cmd(hdl);

	return (sdcard_err_msg(errstring, rv, ap_id, errno));

}

/* cfgadm entry point */
/*ARGSUSED*/
cfga_err_t
cfga_test(
	const char *ap_id,
	const char *options,
	struct cfga_msg *msgp,
	char **errstring,
	cfga_flags_t flags)
{
	/* Should call ioctl for self test - phase 2 */
	return (CFGA_OPNOTSUPP);
}


struct chk_dev {
	int c_isblk;
	char *c_minor;
};

/*ARGSUSED*/
static int
chk_dev_fcn(di_node_t node, di_minor_t minor, void *arg)
{
	char	*mn;
	struct chk_dev *chkp = (struct chk_dev *)arg;

	mn = di_minor_name(minor);
	if (mn == NULL)
		return (DI_WALK_CONTINUE);

	if (strcmp(mn, chkp->c_minor) != 0)
		return (DI_WALK_CONTINUE);

	chkp->c_isblk = di_minor_spectype(minor) == S_IFBLK ? 1 : 0;

	return (DI_WALK_TERMINATE);
}

/*
 * Don't use devfs if stat() in /devices fails. Use libdevinfo instead.
 * Retired devices don't show up in devfs.
 *
 *	Returns:
 *		1 - minor exists and is of type BLK
 *		0 - minor does not exist or is not of type BLK.
 */
static int
is_devinfo_blk(char *minor_path)
{
	char	*minor_portion;
	struct chk_dev chk_dev;
	di_node_t node;
	int	rv;

	/*
	 * prune minor path for di_init() - no /devices prefix and no minor name
	 */
	if (strncmp(minor_path, "/devices/", strlen("/devices/")) != 0)
		return (0);

	minor_portion = strrchr(minor_path, MINOR_SEP);
	if (minor_portion == NULL)
		return (0);

	*minor_portion = 0;

	node = di_init(minor_path + strlen("/devices"), DINFOMINOR);

	*minor_portion = MINOR_SEP;

	if (node == DI_NODE_NIL)
		return (0);

	chk_dev.c_isblk = 0;
	chk_dev.c_minor = minor_portion + 1;

	rv = di_walk_minor(node, NULL, 0, &chk_dev, chk_dev_fcn);

	di_fini(node);

	if (rv == 0 && chk_dev.c_isblk)
		return (1);
	else
		return (0);
}

/*
 * The dynamic component buffer returned by this function has to be freed!
 */
cfga_sdcard_ret_t
sdcard_make_dyncomp(const char *ap_id, char **dyncomp)
{
	char	*cp = NULL;
	int	l_errno;
	char	devpath[MAXPATHLEN];
	char	minor_path[MAXPATHLEN];
	char	name_part[MAXNAMELEN];
	char	*devlink = NULL;
	char	*minor_portion = NULL;
	int	deplen;
	int	err;
	DIR	*dp = NULL;
	struct stat sb;
	struct dirent *dep = NULL;
	struct dirent *newdep = NULL;
	char	*p;

	assert(dyncomp != NULL);

	/*
	 * Get target node path
	 */
	if (sdcard_get_devicepath(ap_id, devpath) != CFGA_SDCARD_OK) {

		(void) printf("cfga_list_ext: cannot locate target device\n");
		return (CFGA_SDCARD_DYNAMIC_AP);

	} else {

		cp = strrchr(devpath, PATH_SEP);
		assert(cp != NULL);

		/*
		 * If the child node is the sdcard node, then what we really
		 * want is the grandchild.  But we know that the grandchild
		 * will always be disk@0,0.
		 */
		if (strstr(cp, "/sdcard@") == cp) {
			/* sdcard nodes have disk children, if any */
			(void) strlcat(devpath, "/disk@0,0", sizeof (devpath));
			cp = strrchr(cp, PATH_SEP);
		}
		*cp = 0;	/* terminate path for opendir() */

		(void) strncpy(name_part, cp + 1, MAXNAMELEN);

		/*
		 * Using libdevinfo for this is overkill and kills
		 * performance when many consumers are using libcfgadm
		 * concurrently.
		 */
		if ((dp = opendir(devpath)) == NULL) {
			goto bailout;
		}

		/*
		 * deplen is large enough to fit the largest path-
		 * struct dirent includes one byte (the terminator)
		 * so we don't add 1 to the calculation here.
		 */
		deplen = pathconf(devpath, _PC_NAME_MAX);
		deplen = ((deplen <= 0) ? MAXNAMELEN : deplen) +
		    sizeof (struct dirent);
		dep = (struct dirent *)malloc(deplen);
		if (dep == NULL)
			goto bailout;

		while ((err = readdir_r(dp, dep, &newdep)) == 0 &&
		    newdep != NULL) {

			assert(newdep == dep);

			if (strcmp(dep->d_name, ".") == 0 ||
			    strcmp(dep->d_name, "..") == 0 ||
			    (minor_portion = strchr(dep->d_name,
			    MINOR_SEP)) == NULL)
				continue;

			*minor_portion = 0;
			if (strcmp(dep->d_name, name_part) != 0)
				continue;
			*minor_portion = MINOR_SEP;

			(void) snprintf(minor_path, MAXPATHLEN,
			    "%s/%s", devpath, dep->d_name);

			/*
			 * If stat() fails, the device *may* be retired.
			 * Check via libdevinfo if the device has a BLK minor.
			 * We don't use libdevinfo all the time, since taking
			 * a snapshot is slower than a stat().
			 */
			if (stat(minor_path, &sb) < 0) {
				if (is_devinfo_blk(minor_path)) {
					break;
				} else {
					continue;
				}
			}

			if (S_ISBLK(sb.st_mode))
				break;
		}

		(void) closedir(dp);
		free(dep);

		dp = NULL;
		dep = NULL;

		/*
		 * If there was an error, or we didn't exit the loop
		 * by finding a block or character device, bail out.
		 */
		if (err != 0 || newdep == NULL)
			goto bailout;

		/*
		 * Look for links to the physical path in /dev/dsk,
		 * since we ONLY looked for BLOCK devices above.
		 */

		(void) physpath_to_devlink("/dev/dsk",
		    minor_path, &devlink, &l_errno);

		/* postprocess and copy logical name here */
		if (devlink != NULL) {
			/*
			 * For disks, remove partition/slice info
			 */
			if ((cp = strstr(devlink, "dsk/")) != NULL) {
				/* cXtYdZ[(s[0..15])|(p[0..X])] */
				if ((p = strchr(cp + 4, 'd')) != NULL) {
					p++;	/* Skip the 'd' */
					while (*p != 0 && isdigit(*p))
						p++;
					*p = 0;
				}
				*dyncomp = strdup(cp);
			}

			free(devlink);
		}

		return (CFGA_SDCARD_OK);
	}

bailout:
	if (dp)
		(void) closedir(dp);
	if (dep)
		free(dep);
	return (CFGA_SDCARD_DYNAMIC_AP);
}

void
sdcard_clean_string(char *s, int sz)
{
	int	len;
	char	*p;

	/* ensure null termination */
	s[sz - 1] = '\0';
	p = s;

	/* strip leading white space */
	while (*p == ' ') p++;
	(void) memmove(s, p, strlen(p));

	len = strlen(s) - 1;
	/* trim trailing space */
	while ((len >= 0) && (s[len] == ' ')) {
		s[len] = '\0';
		len--;
	}

	for (/* nop */; len >= 0; len--) {
		char	c = s[len];
		if (((c >= 'a') && (c <= 'z')) ||
		    ((c >= 'A') && (c <= 'Z')) ||
		    ((c >= '0') && (c <= '9')) ||
		    (c == '_') || (c == '+') || (c == '-'))
			continue;
		s[len] = '_';
	}
}

/* cfgadm entry point */
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
	devctl_hdl_t		devctl_hdl = NULL;
	cfga_sdcard_ret_t	rv = CFGA_SDCARD_OK;
	devctl_ap_state_t	devctl_ap_state;
	char			*pdyn;


	if ((rv = verify_params(ap_id, options, errstring)) != CFGA_SDCARD_OK) {
		(void) cfga_help(NULL, options, flags);
		goto bailout;
	}
	/* We do not care here about dynamic AP name component */
	if ((pdyn = GET_DYN(ap_id)) != NULL) {
		*pdyn = '\0';
	}

	if (ap_id_list == NULL || nlistp == NULL) {
		rv = CFGA_SDCARD_DATA_ERROR;
		(void) cfga_help(NULL, options, flags);
		goto bailout;
	}

	/* Get ap status */
	if ((rv = setup_for_devctl_cmd(ap_id, &devctl_hdl, DC_RDONLY)) !=
	    CFGA_SDCARD_OK) {
		goto bailout;
	}

	/* will call dc_cmd to send IOCTL to kernel */
	if (devctl_ap_getstate(devctl_hdl, NULL, &devctl_ap_state) == -1) {
		cleanup_after_devctl_cmd(devctl_hdl);
		rv = CFGA_SDCARD_IOCTL;
		goto bailout;
	}

	cleanup_after_devctl_cmd(devctl_hdl);

	/*
	 * Create cfga_list_data_t struct.
	 */
	if ((*ap_id_list =
	    (cfga_list_data_t *)malloc(sizeof (**ap_id_list))) == NULL) {
		rv = CFGA_SDCARD_ALLOC_FAIL;
		goto bailout;
	}
	*nlistp = 1;

	/*
	 * Rest of the code fills in the cfga_list_data_t struct.
	 */

	/* Get /dev/cfg path to corresponding to the physical ap_id */
	/* Remember ap_id_log must be freed */
	rv = physpath_to_devlink(CFGA_DEV_DIR, (char *)ap_id,
	    &ap_id_log, &l_errno);

	if (rv != 0) {
		rv = CFGA_SDCARD_DEVLINK;
		goto bailout;
	}

	/* Get logical ap_id corresponding to the physical */
	if (ap_id_log == NULL || strstr(ap_id_log, CFGA_DEV_DIR) == NULL) {
		rv = CFGA_SDCARD_DEVLINK;
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
			rv = CFGA_SDCARD_STATE;
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
			rv = CFGA_SDCARD_STATE;
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
			rv = CFGA_SDCARD_STATE;
			goto bailout;
	}

	(*ap_id_list)->ap_class[0] = '\0';	/* Filled by libcfgadm */
	(*ap_id_list)->ap_busy = devctl_ap_state.ap_in_transition;
	(*ap_id_list)->ap_status_time = devctl_ap_state.ap_last_change;
	(*ap_id_list)->ap_info[0] = NULL;

	if ((*ap_id_list)->ap_r_state == CFGA_STAT_CONNECTED) {
		sda_card_info_t		ci;
		char			*ct;

		/*
		 * Fill in the 'Information' field for the -v option
		 */
		rv = do_control_ioctl(ap_id, SDA_CFGA_GET_CARD_INFO,
		    &ci, sizeof (ci));
		if (rv != CFGA_SDCARD_OK) {
			goto bailout;
		}

		switch (ci.ci_type) {
		case SDA_CT_MMC:
		case SDA_CT_SDMEM:
		case SDA_CT_SDHC:
		case SDA_CT_SDCOMBO:
			/* these are all memory cards */
			sdcard_clean_string(ci.ci_pid, sizeof (ci.ci_pid));

			/*
			 * We don't display the mfg id, because we
			 * have no reliable way to look it up.
			 */
			(void) snprintf((*ap_id_list)->ap_info,
			    sizeof ((*ap_id_list)->ap_info),
			    "Mod: %s Rev: %d.%d Date: %d/%d SN: %X",
			    ci.ci_pid[0] ? ci.ci_pid : "?",
			    ci.ci_major, ci.ci_minor,
			    ci.ci_month, (int)ci.ci_year + 1900,
			    ci.ci_serial);
			break;
		default:
			/*
			 * we don't know what this is really... need to
			 * parse CIS later.
			 */
			(void) strlcpy((*ap_id_list)->ap_info, "",
			    sizeof ((*ap_id_list)->ap_info));
			break;
		}

		switch (ci.ci_type) {
		case SDA_CT_UNKNOWN:
			ct = "unknown";
			break;
		case SDA_CT_MMC:
			ct = "mmc";
			break;
		case SDA_CT_SDMEM:
			ct = "sdcard";
			break;
		case SDA_CT_SDHC:
			ct = "sdhc";
			break;
		case SDA_CT_SDCOMBO:
			ct = "sd-combo";
			break;
		case SDA_CT_SDIO:
			ct = "sdio";
			break;
		}

		(void) strlcpy((*ap_id_list)->ap_type, ct,
		    sizeof ((*ap_id_list)->ap_type));

		if ((*ap_id_list)->ap_o_state == CFGA_STAT_CONFIGURED) {

			char *dyncomp = NULL;

			/*
			 * This is the case where we need to generate
			 * a dynamic component of the ap_id, i.e. device.
			 */
			(void) sdcard_make_dyncomp(ap_id, &dyncomp);
			if (dyncomp != NULL) {
				(void) strcat((*ap_id_list)->ap_log_id,
				    DYN_SEP);
				(void) strlcat((*ap_id_list)->ap_log_id,
				    dyncomp,
				    sizeof ((*ap_id_list)->ap_log_id));
				free(dyncomp);
			}
		}

	} else {
		(void) strlcpy((*ap_id_list)->ap_type, "sdcard-slot",
		    sizeof ((*ap_id_list)->ap_type));
	}

	return (sdcard_err_msg(errstring, rv, ap_id, errno));

bailout:
	if (*ap_id_list != NULL) {
		free(*ap_id_list);
	}
	if (ap_id_log != NULL) {
		free(ap_id_log);
	}

	return (sdcard_err_msg(errstring, rv, ap_id, errno));
}

/*
 * This routine accepts a string and prints it using
 * the message print routine argument.
 */
static void
cfga_msg(struct cfga_msg *msgp, const char *str)
{
	int len;
	char *q;

	if (msgp == NULL || msgp->message_routine == NULL) {
		(void) printf("cfga_msg: NULL msgp\n");
		return;
	}

	if ((len = strlen(str)) == 0) {
		(void) printf("cfga_msg: null str\n");
		return;
	}

	if ((q = (char *)calloc(len + 1, 1)) == NULL) {
		perror("cfga_msg");
		return;
	}

	(void) strcpy(q, str);
	(*msgp->message_routine)(msgp->appdata_ptr, q);

	free(q);
}

/* cfgadm entry point */
/*ARGSUSED*/
cfga_err_t
cfga_help(struct cfga_msg *msgp, const char *options, cfga_flags_t flags)
{
	if (options != NULL) {
		cfga_msg(msgp,
		    dgettext(TEXT_DOMAIN, sdcard_help[HELP_UNKNOWN]));
		cfga_msg(msgp, options);
	}
	cfga_msg(msgp, dgettext(TEXT_DOMAIN, sdcard_help[HELP_HEADER]));
	cfga_msg(msgp, sdcard_help[HELP_CONFIG]);
	cfga_msg(msgp, sdcard_help[HELP_RESET_SLOT]);

	return (CFGA_OK);
}


/*
 * Ensure the ap_id passed is in the correct (physical ap_id) form:
 *     path/device:xx
 * where xx is a one or two-digit number.
 *
 * Note the library always calls the plugin with a physical ap_id.
 */
static int
verify_valid_apid(const char *ap_id)
{
	char	*l_ap_id;

	if (ap_id == NULL)
		return (-1);

	l_ap_id = strrchr(ap_id, MINOR_SEP);
	l_ap_id++;

	if (strspn(l_ap_id, "0123456789") != strlen(l_ap_id)) {
		/* Bad characters in the ap_id */
		return (-1);
	}

	return (0);
}



/*
 * Verify the params passed in are valid.
 */
static cfga_sdcard_ret_t
verify_params(const char *ap_id, const char *options, char **errstring)
{
	char *pdyn, *lap_id;
	int rv;

	if (errstring != NULL) {
		*errstring = NULL;
	}

	if (options != NULL) {
		return (CFGA_SDCARD_OPTIONS);
	}

	/* Strip dynamic AP name component if it is present. */
	lap_id = strdup(ap_id);
	if (lap_id == NULL) {
		return (CFGA_SDCARD_ALLOC_FAIL);
	}
	if ((pdyn = GET_DYN(lap_id)) != NULL) {
		*pdyn = '\0';
	}

	if (verify_valid_apid(lap_id) != 0) {
		rv = CFGA_SDCARD_AP;
	} else {
		rv = CFGA_SDCARD_OK;
	}
	free(lap_id);

	return (rv);
}

/*
 * Pair of routines to set up for/clean up after a devctl_ap_* lib call.
 */
static void
cleanup_after_devctl_cmd(devctl_hdl_t devctl_hdl)
{
	if (devctl_hdl != NULL) {
		devctl_release(devctl_hdl);
	}
}

static cfga_sdcard_ret_t
setup_for_devctl_cmd(const char *ap_id, devctl_hdl_t *devctl_hdl, uint_t oflag)
{
	char *lap_id, *pdyn;

	lap_id = strdup(ap_id);
	if (lap_id == NULL)
		return (CFGA_SDCARD_ALLOC_FAIL);
	if ((pdyn = GET_DYN(lap_id)) != NULL) {
		*pdyn = '\0';
	}

	/* Get a devctl handle to pass to the devctl_ap_XXX functions */
	if ((*devctl_hdl = devctl_ap_acquire(lap_id, oflag)) == NULL) {
		(void) fprintf(stderr, "[libcfgadm:sdcard] "
		    "setup_for_devctl_cmd: devctl_ap_acquire failed: %s\n",
		    strerror(errno));
		free(lap_id);
		return (CFGA_SDCARD_DEVCTL);
	}

	free(lap_id);
	return (CFGA_SDCARD_OK);
}


static cfga_sdcard_ret_t
slot_state(devctl_hdl_t hdl, ap_rstate_t *rstate, ap_ostate_t *ostate)
{
	devctl_ap_state_t	devctl_ap_state;

	if (devctl_ap_getstate(hdl, NULL, &devctl_ap_state) == -1) {
		(void) printf("devctl_ap_getstate failed, errno: %d\n", errno);
		return (CFGA_SDCARD_IOCTL);
	}
	*rstate = devctl_ap_state.ap_rstate;
	*ostate =  devctl_ap_state.ap_ostate;
	return (CFGA_SDCARD_OK);
}

/*
 * Given a subcommand to the DEVCTL_AP_CONTROL ioctl, rquest the size of
 * the data to be returned, allocate a buffer, then get the data.
 */
cfga_sdcard_ret_t
do_control_ioctl(const char *ap_id, int subcommand, void *data, size_t size)
{
	int			fd = -1;
	cfga_sdcard_ret_t	rv = CFGA_SDCARD_OK;
	struct sda_ap_control	apc;

	if ((fd = open(ap_id, O_RDONLY)) == -1) {
		(void) printf("do_control_ioctl: open: errno:%d\n", errno);
		rv = CFGA_SDCARD_OPEN;
		goto bailout;
	}

	apc.cmd = subcommand;
	apc.data = data;
	apc.size = size;

	/* Execute IOCTL */
	if (ioctl(fd, DEVCTL_AP_CONTROL, &apc) != 0) {
		rv = CFGA_SDCARD_IOCTL;
		goto bailout;
	}

	(void) close(fd);

	return (rv);

bailout:
	if (fd != -1) {
		(void) close(fd);
	}

	if ((rv != CFGA_SDCARD_OK) && (errno == EBUSY)) {
		rv = CFGA_SDCARD_BUSY;
	}

	return (rv);
}


static int
sdcard_confirm(struct cfga_confirm *confp, char *msg)
{
	int rval;

	if (confp == NULL || confp->confirm == NULL) {
		return (0);
	}
	rval = (*confp->confirm)(confp->appdata_ptr, msg);

	return (rval);
}


cfga_sdcard_ret_t
sdcard_get_devicepath(const char *ap_id, char *devpath)
{
	return (do_control_ioctl(ap_id, SDA_CFGA_GET_DEVICE_PATH,
	    devpath, MAXPATHLEN));
}

cfga_sdcard_ret_t
sdcard_reset_slot(const char *ap_id)
{
	return (do_control_ioctl(ap_id, SDA_CFGA_RESET_SLOT, NULL, 0));
}

static rcm_handle_t *rcm_handle = NULL;
static mutex_t rcm_handle_lock = DEFAULTMUTEX;

/*
 * sdcard_rcm_offline:
 *      Offline resource consumers.
 */
cfga_sdcard_ret_t
sdcard_rcm_offline(char *devpath, char **errstring, cfga_flags_t flags)
{
	int			rret;
	uint_t			rflags;
	rcm_info_t		*rinfo = NULL;
	cfga_sdcard_ret_t	ret;

	if ((ret = sdcard_rcm_init()) != CFGA_SDCARD_OK) {
		return (ret);
	}

	/* Translate the cfgadm flags to RCM flags */
	rflags = (flags & CFGA_FLAG_FORCE) ? RCM_FORCE : 0;

	rret = rcm_request_offline(rcm_handle, devpath, rflags, &rinfo);
	if (rret != RCM_SUCCESS) {
		if (rinfo) {
			sdcard_rcm_info_table(rinfo, errstring);
			rcm_free_info(rinfo);
			rinfo = NULL;
		}

		if (rret == RCM_FAILURE) {
			sdcard_rcm_online(devpath, errstring);
		}
		ret = CFGA_SDCARD_RCM_OFFLINE;
	}
	return (ret);
}


/*
 * sdcard_rcm_online:
 *      Online resource consumers that were previously offlined.
 */
void
sdcard_rcm_online(char *devpath, char **errstring)
{
	rcm_info_t		*rinfo = NULL;

	if (sdcard_rcm_init() != CFGA_SDCARD_OK) {
		return;
	}

	if (rcm_notify_online(rcm_handle, devpath, 0, &rinfo) !=
	    RCM_SUCCESS && (rinfo != NULL)) {
		sdcard_rcm_info_table(rinfo, errstring);
		rcm_free_info(rinfo);
		rinfo = NULL;
	}
}

/*
 * sdcard_rcm_remove:
 *      Remove resource consumers after their kernel removal.
 */
void
sdcard_rcm_remove(char *devpath, char **errstring)
{
	rcm_info_t		*rinfo = NULL;

	if (sdcard_rcm_init() != CFGA_SDCARD_OK) {
		return;
	}

	if (rcm_notify_remove(rcm_handle, devpath, 0, &rinfo) !=
	    RCM_SUCCESS && (rinfo != NULL)) {

		sdcard_rcm_info_table(rinfo, errstring);
		rcm_free_info(rinfo);
		rinfo = NULL;
	}
}


/*
 * sdcard_rcm_init:
 * Contains common initialization code for entering a sdcard_rcm_xx() routine.
 */
static cfga_sdcard_ret_t
sdcard_rcm_init(void)
{
	/* Get a handle for the RCM operations */
	(void) mutex_lock(&rcm_handle_lock);
	if (rcm_handle == NULL) {
		if (rcm_alloc_handle(NULL, RCM_NOPID, NULL, &rcm_handle) !=
		    RCM_SUCCESS) {
			(void) mutex_unlock(&rcm_handle_lock);

			return (CFGA_SDCARD_RCM_HANDLE);
		}
	}
	(void) mutex_unlock(&rcm_handle_lock);

	return (CFGA_SDCARD_OK);
}


#define	MAX_FORMAT	80	/* for info table */

/*
 * sdcard_rcm_info_table:
 * Takes an opaque rcm_info_t pointer and a character pointer,
 * and appends the rcm_info_t data in the form of a table to the
 * given character pointer.
 */
static void
sdcard_rcm_info_table(rcm_info_t *rinfo, char **table)
{
	int i;
	size_t w;
	size_t width = 0;
	size_t w_rsrc = 0;
	size_t w_info = 0;
	size_t table_size = 0;
	uint_t tuples = 0;
	rcm_info_tuple_t *tuple = NULL;
	char *rsrc;
	char *info;
	char *newtable;
	static char format[MAX_FORMAT];
	const char *infostr;

	/* Protect against invalid arguments */
	if (rinfo == NULL || table == NULL) {
		return;
	}

	/* Set localized table header strings */
	rsrc = dgettext(TEXT_DOMAIN, "Resource");
	info = dgettext(TEXT_DOMAIN, "Information");


	/* A first pass, to size up the RCM information */
	while (tuple = rcm_info_next(rinfo, tuple)) {
		if ((infostr = rcm_info_info(tuple)) != NULL) {
			tuples++;
			if ((w = strlen(rcm_info_rsrc(tuple))) > w_rsrc)
				w_rsrc = w;
			if ((w = strlen(infostr)) > w_info)
				w_info = w;
		}
	}

	/* If nothing was sized up above, stop early */
	if (tuples == 0) {
		return;
	}

	/* Adjust column widths for column headings */
	if ((w = strlen(rsrc)) > w_rsrc) {
		w_rsrc = w;
	} else if ((w_rsrc - w) % 2) {
		w_rsrc++;
	}

	if ((w = strlen(info)) > w_info) {
		w_info = w;
	} else if ((w_info - w) % 2) {
		w_info++;
	}


	/*
	 * Compute the total line width of each line,
	 * accounting for intercolumn spacing.
	 */
	width = w_info + w_rsrc + 4;

	/* Allocate space for the table */
	table_size = (2 + tuples) * (width + 1) + 2;
	if (*table == NULL) {
		/* zero fill for the strcat() call below */
		*table = calloc(table_size, sizeof (char));
		if (*table == NULL) {
			return;
		}
	} else {
		newtable = realloc(*table, strlen(*table) + table_size);
		if (newtable == NULL) {
			return;
		} else {
			*table = newtable;
		}
	}

	/* Place a table header into the string */


	/* The resource header */
	(void) strcat(*table, "\n");
	w = strlen(rsrc);

	for (i = 0; i < ((w_rsrc - w) / 2); i++) {
		(void) strcat(*table, " ");
	}
	(void) strcat(*table, rsrc);

	for (i = 0; i < ((w_rsrc - w) / 2); i++) {
		(void) strcat(*table, " ");
	}

	/* The information header */
	(void) strcat(*table, "  ");
	w = strlen(info);
	for (i = 0; i < ((w_info - w) / 2); i++) {
		(void) strcat(*table, " ");
	}
	(void) strcat(*table, info);

	for (i = 0; i < ((w_info - w) / 2); i++) {
		(void) strcat(*table, " ");
	}

	(void) strcat(*table, "\n");

	/* Underline the headers */
	for (i = 0; i < w_rsrc; i++) {
		(void) strcat(*table, "-");
	}

	(void) strcat(*table, "  ");
	for (i = 0; i < w_info; i++) {
		(void) strcat(*table, "-");
	}


	(void) strcat(*table, "\n");

	/* Construct the format string */
	(void) snprintf(format, MAX_FORMAT, "%%-%ds  %%-%ds",
	    (int)w_rsrc, (int)w_info);

	/* Add the tuples to the table string */
	tuple = NULL;
	while ((tuple = rcm_info_next(rinfo, tuple)) != NULL) {
		if ((infostr = rcm_info_info(tuple)) != NULL) {
			(void) sprintf(&((*table)[strlen(*table)]),
			    format, rcm_info_rsrc(tuple), infostr);
			(void) strcat(*table, "\n");
		}
	}
}
