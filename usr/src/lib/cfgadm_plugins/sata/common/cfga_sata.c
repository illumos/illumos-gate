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
 * Copyright 2018 OmniOS Community Edition (OmniOSce) Association.
 * Copyright (c) 2018, Joyent, Inc.
 */

#include <sys/param.h>
#include <sys/stat.h>
#include <errno.h>
#include <string.h>
#include <dirent.h>
#include "cfga_sata.h"

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
	HELP_RESET_PORT,
	HELP_RESET_DEVICE,
	HELP_RESET_ALL,
	HELP_PORT_DEACTIVATE,
	HELP_PORT_ACTIVATE,
	HELP_PORT_SELF_TEST,
	HELP_CNTRL_SELF_TEST,
	HELP_UNKNOWN
};

/* SATA specific help messages */
static char *sata_help[] = {
	NULL,
	"SATA specific commands:\n",
	" cfgadm -c [configure|unconfigure|disconnect|connect] ap_id "
	    "[ap_id...]\n",
	" cfgadm -x sata_reset_port ap_id  [ap_id...]\n",
	" cfgadm -x sata_reset_device ap_id [ap_id...]\n",
	" cfgadm -x sata_reset_all ap_id\n",
	" cfgadm -x sata_port_deactivate ap_id [ap_id...]\n",
	" cfgadm -x sata_port_activate ap_id [ap_id...]\n",
	" cfgadm -x sata_port_self_test ap_id [ap_id...]\n",
	" cfgadm -t ap_id\n",
	"\tunknown command or option:\n",
	NULL
};	/* End help messages */


/*
 * Messages.
 */
static msgcvt_t sata_msgs[] = {
	/* CFGA_SATA_OK */
	{ CVT, CFGA_OK, "" },

	/* CFGA_SATA_NACK */
	{ CVT, CFGA_NACK, "" },

	/* CFGA_SATA_DEVICE_UNCONFIGURED */
	{ CVT, CFGA_OK, "Device unconfigured prior to disconnect" },

	/* CFGA_SATA_UNKNOWN / CFGA_LIB_ERROR -> "Library error" */
	{ CVT, CFGA_LIB_ERROR, "Unknown message; internal error" },

	/* CFGA_SATA_INTERNAL_ERROR / CFGA_LIB_ERROR -> "Library error" */
	{ CVT, CFGA_LIB_ERROR, "Internal error" },

	/* CFGA_SATA_DATA_ERROR / CFGA_DATA_ERROR -> "Data error" */
	{ CVT, CFGA_DATA_ERROR, "cfgadm data error" },

	/* CFGA_SATA_OPTIONS / CFGA_ERROR -> "Hardware specific failure" */
	{ CVT, CFGA_ERROR, "Hardware specific option not supported" },

	/* CFGA_SATA_HWOPNOTSUPP / CFGA_ERROR -> "Hardware specific failure" */
	{ CVT, CFGA_ERROR, "Hardware specific operation not supported" },

	/*
	 * CFGA_SATA_DYNAMIC_AP /
	 * CFGA_LIB_ERROR -> "Configuration operation invalid"
	 */
	{ CVT, CFGA_INVAL, "Cannot identify attached device" },

	/* CFGA_SATA_AP / CFGA_APID_NOEXIST -> "Attachment point not found" */
	{ CVT, CFGA_APID_NOEXIST, "" },

	/* CFGA_SATA_PORT / CFGA_LIB_ERROR -> "Library error" */
	{ CVT, CFGA_LIB_ERROR, "Cannot determine sata port number for " },

	/* CFGA_SATA_DEVCTL / CFGA_LIB_ERROR -> "Library error" */
	{ CVT, CFGA_LIB_ERROR, "Internal error: "
		"Cannot allocate devctl handle " },

	/*
	 * CFGA_SATA_DEV_CONFIGURE /
	 * CFGA_ERROR -> "Hardware specific failure"
	 */
	{ CVT, CFGA_ERROR, "Failed to config device at " },

	/*
	 * CFGA_SATA_DEV_UNCONFIGURE /
	 * CFGA_ERROR -> "Hardware specific failure"
	 */
	{ CVT, CFGA_ERROR, "Failed to unconfig device at " },

	/*
	 * CFGA_SATA_DISCONNECTED
	 * CFGA_INVAL -> "Configuration operation invalid"
	 */
	{ CVT, CFGA_INVAL, "Port already disconnected " },

	/*
	 * CFGA_SATA_NOT_CONNECTED
	 * CFGA_INVAL -> "Configuration operation invalid"
	 */
	{ CVT, CFGA_INVAL, "No device connected to " },

	/*
	 * CFGA_SATA_NOT_CONFIGURED /
	 * CFGA_INVAL -> "Configuration operation invalid"
	 */
	{ CVT, CFGA_INVAL, "No device configured at " },

	/*
	 * CFGA_SATA_ALREADY_CONNECTED /
	 * CFGA_INVAL -> "Configuration operation invalid"
	 */
	{ CVT, CFGA_INVAL, "Device already connected to " },

	/*
	 * CFGA_SATA_ALREADY_CONFIGURED /
	 * CFGA_INVAL -> "Configuration operation invalid"
	 */
	{ CVT, CFGA_INVAL, "Device already configured at " },

	/*
	 * CFGA_SATA_INVALID_DEVNAME /
	 * CFGA_INVAL -> "Configuration operation invalid"
	 */
	{ CVT, CFGA_INVAL, "Cannot specify device name" },

	/* CFGA_SATA_OPEN / CFGA_LIB_ERROR -> "Library error" */
	{ CVT, CFGA_LIB_ERROR, "Cannot open " },

	/* CFGA_SATA_IOCTL / CFGA_ERROR -> "Hardware specific failure"  */
	{ CVT, CFGA_ERROR, "Driver ioctl failed " },

	/*
	 * CFGA_SATA_BUSY /
	 * CFGA_SYSTEM_BUSY -> "System is busy, try again"
	 */
	{ CVT, CFGA_SYSTEM_BUSY, "" },

	/* CFGA_SATA_ALLOC_FAIL / CFGA_LIB_ERROR -> "Library error" */
	{ CVT, CFGA_LIB_ERROR, "Memory allocation failure" },

	/*
	 * CFGA_SATA_OPNOTSUPP /
	 * CFGA_OPNOTSUPP -> "Configuration operation not supported"
	 */
	{ CVT, CFGA_OPNOTSUPP, "Operation not supported" },

	/* CFGA_SATA_DEVLINK / CFGA_LIB_ERROR -> "Library error" */
	{ CVT, CFGA_LIB_ERROR, "Could not find /dev/cfg link for " },

	/* CFGA_SATA_STATE / CFGA_LIB_ERROR -> "Library error" */
	{ CVT, CFGA_LIB_ERROR, "Internal error: Unrecognized ap state" },

	/* CFGA_SATA_PRIV / CFGA_PRIV -> "Insufficient privileges" */
	{ CVT, CFGA_PRIV, "" },

	/* CFGA_SATA_NVLIST / CFGA_ERROR -> "Hardware specific failure" */
	{ CVT, CFGA_ERROR, "Internal error (nvlist)" },

	/* CFGA_SATA_ZEROLEN / CFGA_ERROR -> "Hardware specific failure" */
	{ CVT, CFGA_ERROR, "Internal error (zerolength string)" },

	/* CFGA_SATA_RCM_HANDLE / CFGA_ERROR -> "Hardware specific failure" */
	{ CVT, CFGA_ERROR, "cannot get RCM handle"},

	/*
	 * CFGA_SATA_RCM_ONLINE /
	 * CFGA_SYSTEM_BUSY -> "System is busy, try again"
	 */
	{ CVT, CFGA_SYSTEM_BUSY, "failed to online: "},

	/*
	 * CFGA_SATA_RCM_OFFLINE /
	 * CFGA_SYSTEM_BUSY -> "System is busy, try again"
	 */
	{ CVT, CFGA_SYSTEM_BUSY, "failed to offline: "},

	/* CFGA_SATA_RCM_INFO / CFGA_ERROR -> "Hardware specific failure" */
	{ CVT, CFGA_ERROR, "failed to query: "}

};	/* End error messages */

static cfga_sata_ret_t
verify_params(const char *ap_id, const char *options, char **errstring);


static cfga_sata_ret_t
setup_for_devctl_cmd(const char *ap_id, devctl_hdl_t *devctl_hdl,
    nvlist_t **user_nvlistp, uint_t oflag);

static cfga_sata_ret_t
port_state(devctl_hdl_t hdl, nvlist_t *list,
    ap_rstate_t *rstate, ap_ostate_t *ostate);

static cfga_sata_ret_t
do_control_ioctl(const char *ap_id, sata_cfga_apctl_t subcommand, uint_t arg,
    void **descrp, size_t *sizep);

static void
cleanup_after_devctl_cmd(devctl_hdl_t devctl_hdl, nvlist_t *user_nvlist);

static char *
sata_get_devicepath(const char *ap_id);

static int
sata_confirm(struct cfga_confirm *confp, char *msg);

static cfga_sata_ret_t
get_port_num(const char *ap_id, uint32_t *port);

/* Utilities */

static cfga_sata_ret_t
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
	cfga_sata_ret_t rv = CFGA_SATA_INTERNAL_ERROR;

	/*
	 * Using libdevinfo for this is overkill and kills performance
	 * when multiple consumers of libcfgadm are executing
	 * concurrently.
	 */
	if ((dp = opendir(basedir)) == NULL) {
		*l_errnop = errno;
		return (CFGA_SATA_INTERNAL_ERROR);
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
		rv = CFGA_SATA_ALLOC_FAIL;
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
			    logpp, l_errnop)) != CFGA_SATA_OK) {

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

					rv = CFGA_SATA_ALLOC_FAIL;
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
		return (CFGA_SATA_INTERNAL_ERROR);
	}

	return (CFGA_SATA_OK);

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
 * NOTE: Indexes are defined in cfga_sata.h
 */
static const char *
get_msg(uint_t msg_index, msgcvt_t *msg_tbl, uint_t tbl_size)
{
	if (msg_index >= tbl_size) {
		msg_index = CFGA_SATA_UNKNOWN;
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
 * error conditions warrant a SATA-specific error message - for those
 * conditions the cfgadm generic messages are sufficient.
 *
 * Some messages may display ap_id or errno, which is why they are passed
 * in.
 */

cfga_err_t
sata_err_msg(
    char **errstring,
    cfga_sata_ret_t rv,
    const char *ap_id,
    int l_errno)
{
	if (errstring == NULL) {
		return (sata_msgs[rv].cfga_err);
	}

	/*
	 * Generate the appropriate SATA-specific error message(s) (if any).
	 */
	switch (rv) {
	case CFGA_SATA_OK:
	case CFGA_NACK:
		/* Special case - do nothing.  */
		break;

	case CFGA_SATA_UNKNOWN:
	case CFGA_SATA_DYNAMIC_AP:
	case CFGA_SATA_INTERNAL_ERROR:
	case CFGA_SATA_OPTIONS:
	case CFGA_SATA_ALLOC_FAIL:
	case CFGA_SATA_STATE:
	case CFGA_SATA_PRIV:
	case CFGA_SATA_OPNOTSUPP:
	case CFGA_SATA_DATA_ERROR:
		/* These messages require no additional strings passed. */
		set_msg(errstring, ERR_STR(rv), NULL);
		break;

	case CFGA_SATA_HWOPNOTSUPP:
		/* hardware-specific help needed */
		set_msg(errstring, ERR_STR(rv), NULL);
		set_msg(errstring, "\n",
		    dgettext(TEXT_DOMAIN, sata_help[HELP_HEADER]), NULL);
		set_msg(errstring, sata_help[HELP_RESET_PORT], NULL);
		set_msg(errstring, sata_help[HELP_RESET_DEVICE], NULL);
		set_msg(errstring, sata_help[HELP_RESET_ALL],  NULL);
		set_msg(errstring, sata_help[HELP_PORT_ACTIVATE], NULL);
		set_msg(errstring, sata_help[HELP_PORT_DEACTIVATE], NULL);
		set_msg(errstring, sata_help[HELP_PORT_SELF_TEST], NULL);
		set_msg(errstring, sata_help[HELP_CNTRL_SELF_TEST], NULL);
		break;

	case CFGA_SATA_AP:
	case CFGA_SATA_PORT:
	case CFGA_SATA_NOT_CONNECTED:
	case CFGA_SATA_NOT_CONFIGURED:
	case CFGA_SATA_ALREADY_CONNECTED:
	case CFGA_SATA_ALREADY_CONFIGURED:
	case CFGA_SATA_BUSY:
	case CFGA_SATA_DEVLINK:
	case CFGA_SATA_RCM_HANDLE:
	case CFGA_SATA_RCM_ONLINE:
	case CFGA_SATA_RCM_OFFLINE:
	case CFGA_SATA_RCM_INFO:
	case CFGA_SATA_DEV_CONFIGURE:
	case CFGA_SATA_DEV_UNCONFIGURE:
	case CFGA_SATA_DISCONNECTED:
		/* These messages also print ap_id.  */
		set_msg(errstring, ERR_STR(rv), "ap_id: ", ap_id, "", NULL);
		break;


	case CFGA_SATA_IOCTL:
	case CFGA_SATA_NVLIST:
		/* These messages also print errno.  */
		{
			char *errno_str = l_errno ? strerror(l_errno) : "";

			set_msg(errstring, ERR_STR(rv), errno_str,
			    l_errno ? "\n" : "", NULL);
			break;
		}

	case CFGA_SATA_OPEN:
		/* These messages also apid and errno.  */
		{
			char *errno_str = l_errno ? strerror(l_errno) : "";

			set_msg(errstring, ERR_STR(rv), "ap_id: ", ap_id, "\n",
			    errno_str, l_errno ? "\n" : "", NULL);
			break;
		}

	default:
		set_msg(errstring, ERR_STR(CFGA_SATA_INTERNAL_ERROR), NULL);

	} /* end switch */


	/*
	 * Determine the proper error code to send back to the cfgadm library.
	 */
	return (sata_msgs[rv].cfga_err);
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
	int		len;
	char		*msg;
	char		*devpath;
	nvlist_t	*nvl = NULL;
	ap_rstate_t	rstate;
	ap_ostate_t	ostate;
	devctl_hdl_t	hdl = NULL;
	cfga_sata_ret_t	rv = CFGA_SATA_OK;
	char		*pdyn;
	char		*str_type;
	size_t		size;
	boolean_t	pmult = B_FALSE;

	/*
	 * All sub-commands which can change state of device require
	 * root privileges.
	 */
	if (geteuid() != 0) {
		rv = CFGA_SATA_PRIV;
		goto bailout;
	}

	if ((rv = verify_params(ap_id, options, errstring)) != CFGA_SATA_OK) {
		(void) cfga_help(msgp, options, flags);
		goto bailout;
	}

	if ((rv = setup_for_devctl_cmd(ap_id, &hdl, &nvl,
	    DC_RDONLY)) != CFGA_SATA_OK) {
		goto bailout;
	}

	/*
	 * Checking device type. A port multiplier is not configurable - it is
	 * already configured as soon as it is connected.
	 */
	if ((rv = do_control_ioctl(ap_id, SATA_CFGA_GET_AP_TYPE, NULL,
	    (void **)&str_type, &size)) != CFGA_SATA_OK) {
		/* no such deivce */
		goto bailout;
	}
	if (strncmp(str_type, "sata-pmult", sizeof ("sata-pmult")) == 0) {
		pmult = B_TRUE;
	}

	switch (state_change_cmd) {
	case CFGA_CMD_CONFIGURE:
		if (pmult == B_TRUE) {
			rv = CFGA_SATA_HWOPNOTSUPP;
			goto bailout;
		}

		if ((rv = port_state(hdl, nvl, &rstate, &ostate)) !=
		    CFGA_SATA_OK)
			goto bailout;

		if (ostate == AP_OSTATE_CONFIGURED) {
			rv = CFGA_SATA_ALREADY_CONFIGURED;
			goto bailout;
		}
		/* Disallow dynamic AP name component */
		if (GET_DYN(ap_id) != NULL) {
			rv = CFGA_SATA_INVALID_DEVNAME;
			goto bailout;
		}

		if (rstate == AP_RSTATE_EMPTY) {
			rv = CFGA_SATA_NOT_CONNECTED;
			goto bailout;
		}
		rv = CFGA_SATA_OK;

		if (devctl_ap_configure(hdl, nvl) != 0) {
			rv = CFGA_SATA_DEV_CONFIGURE;
			goto bailout;
		}

		devpath = sata_get_devicepath(ap_id);
		if (devpath == NULL) {
			int i;
			/*
			 * Try for some time as SATA hotplug thread
			 * takes a while to create the path then
			 * eventually give up.
			 */
			for (i = 0; i < 12 && (devpath == NULL); i++) {
				(void) sleep(6);
				devpath = sata_get_devicepath(ap_id);
			}

			if (devpath == NULL) {
				rv = CFGA_SATA_DEV_CONFIGURE;
				break;
			}
		}

		S_FREE(devpath);
		break;

	case CFGA_CMD_UNCONFIGURE:
		if (pmult == B_TRUE) {
			rv = CFGA_SATA_HWOPNOTSUPP;
			goto bailout;
		}

		if ((rv = port_state(hdl, nvl, &rstate, &ostate)) !=
		    CFGA_SATA_OK)
			goto bailout;

		if (rstate != AP_RSTATE_CONNECTED) {
			rv = CFGA_SATA_NOT_CONNECTED;
			goto bailout;
		}

		if (ostate != AP_OSTATE_CONFIGURED) {
			rv = CFGA_SATA_NOT_CONFIGURED;
			goto bailout;
		}
		/* Strip off AP name dynamic component, if present */
		if ((pdyn = GET_DYN(ap_id)) != NULL) {
			*pdyn = '\0';
		}

		rv = CFGA_SATA_OK;

		len = strlen(SATA_CONFIRM_DEVICE) +
		    strlen(SATA_CONFIRM_DEVICE_SUSPEND) +
		    strlen("Unconfigure") + strlen(ap_id);
		if ((msg = (char *)calloc(len +3, 1)) != NULL) {
			(void) snprintf(msg, len + 3, "Unconfigure"
			    " %s%s\n%s",
			    SATA_CONFIRM_DEVICE, ap_id,
			    SATA_CONFIRM_DEVICE_SUSPEND);
		}

		if (!sata_confirm(confp, msg)) {
			free(msg);
			rv = CFGA_SATA_NACK;
			break;
		}
		free(msg);

		devpath = sata_get_devicepath(ap_id);
		if (devpath == NULL) {
			(void) printf(
			    "cfga_change_state: get device path failed\n");
			rv = CFGA_SATA_DEV_UNCONFIGURE;
			break;
		}

		if ((rv = sata_rcm_offline(ap_id, errstring, devpath, flags))
		    != CFGA_SATA_OK) {
			break;
		}

		ret = devctl_ap_unconfigure(hdl, nvl);

		if (ret != 0) {
			rv = CFGA_SATA_DEV_UNCONFIGURE;
			if (errno == EBUSY) {
				rv = CFGA_SATA_BUSY;
			}
			(void) sata_rcm_online(ap_id, errstring, devpath,
			    flags);
		} else {
			(void) sata_rcm_remove(ap_id, errstring, devpath,
			    flags);

		}
		S_FREE(devpath);

		break;

	case CFGA_CMD_DISCONNECT:
		if ((rv = port_state(hdl, nvl, &rstate, &ostate)) !=
		    CFGA_SATA_OK)
			goto bailout;

		if (rstate == AP_RSTATE_DISCONNECTED) {
			rv = CFGA_SATA_DISCONNECTED;
			goto bailout;
		}

		/* Strip off AP name dynamic component, if present */
		if ((pdyn = GET_DYN(ap_id)) != NULL) {
			*pdyn = '\0';
		}


		rv = CFGA_SATA_OK; /* other statuses don't matter */

		/*
		 * If the port originally with device attached and was
		 * unconfigured already, the devicepath for the sd will be
		 * removed. sata_get_devicepath in this case is not necessary.
		 */
		/* only call rcm_offline if the state was CONFIGURED */
		if (ostate == AP_OSTATE_CONFIGURED &&
		    pmult == B_FALSE) {
			devpath = sata_get_devicepath(ap_id);
			if (devpath == NULL) {
				(void) printf(
				    "cfga_change_state: get path failed\n");
				rv = CFGA_SATA_DEV_UNCONFIGURE;
				break;
			}

			len = strlen(SATA_CONFIRM_DEVICE) +
			    strlen(SATA_CONFIRM_DEVICE_SUSPEND) +
			    strlen("Disconnect") + strlen(ap_id);
			if ((msg = (char *)calloc(len +3, 1)) != NULL) {
				(void) snprintf(msg, len + 3,
				    "Disconnect"
				    " %s%s\n%s",
				    SATA_CONFIRM_DEVICE, ap_id,
				    SATA_CONFIRM_DEVICE_SUSPEND);
			}
			if (!sata_confirm(confp, msg)) {
				free(msg);
				rv = CFGA_SATA_NACK;
				break;
			}
			free(msg);

			if ((rv = sata_rcm_offline(ap_id, errstring,
			    devpath, flags)) != CFGA_SATA_OK) {
				break;
			}

			ret = devctl_ap_unconfigure(hdl, nvl);
			if (ret != 0) {
				(void) printf(
				    "devctl_ap_unconfigure failed\n");
				rv = CFGA_SATA_DEV_UNCONFIGURE;
				if (errno == EBUSY)
					rv = CFGA_SATA_BUSY;
				(void) sata_rcm_online(ap_id, errstring,
				    devpath, flags);
				S_FREE(devpath);

				/*
				 * The current policy is that if unconfigure
				 * failed, do not continue with disconnect.
				 * If the port needs to be forced into the
				 * disconnect (shutdown) state,
				 * the -x sata_port_poweroff command should be
				 * used instead of -c disconnect
				 */
				break;
			} else {
				(void) printf("%s\n",
				    ERR_STR(CFGA_SATA_DEVICE_UNCONFIGURED));
				(void) sata_rcm_remove(ap_id, errstring,
				    devpath, flags);
			}
			S_FREE(devpath);
		} else if (rstate == AP_RSTATE_CONNECTED ||
		    rstate == AP_RSTATE_EMPTY) {
			len = strlen(SATA_CONFIRM_PORT) +
			    strlen(SATA_CONFIRM_PORT_DISABLE) +
			    strlen("Deactivate Port") + strlen(ap_id);
			if ((msg = (char *)calloc(len +3, 1)) != NULL) {
				(void) snprintf(msg, len +3,
				    "Disconnect"
				    " %s%s\n%s",
				    SATA_CONFIRM_PORT, ap_id,
				    SATA_CONFIRM_PORT_DISABLE);
			}
			if (!sata_confirm(confp, msg)) {
				free(msg);
				rv = CFGA_SATA_NACK;
				break;
			}
		}
		ret = devctl_ap_disconnect(hdl, nvl);
		if (ret != 0) {
			rv = CFGA_SATA_IOCTL;
			if (errno == EBUSY) {
				rv = CFGA_SATA_BUSY;
			}
		}
		break;

	case CFGA_CMD_CONNECT:
		if ((rv = port_state(hdl, nvl, &rstate, &ostate)) !=
		    CFGA_SATA_OK)
			goto bailout;

		if (rstate == AP_RSTATE_CONNECTED) {
			rv = CFGA_SATA_ALREADY_CONNECTED;
			goto bailout;
		}

		len = strlen(SATA_CONFIRM_PORT) +
		    strlen(SATA_CONFIRM_PORT_ENABLE) +
		    strlen("Activate Port") + strlen(ap_id);
		if ((msg = (char *)calloc(len +3, 1)) != NULL) {
			(void) snprintf(msg, len +3, "Activate"
			    " %s%s\n%s",
			    SATA_CONFIRM_PORT, ap_id,
			    SATA_CONFIRM_PORT_ENABLE);
		}
		if (!sata_confirm(confp, msg)) {
			rv = CFGA_SATA_NACK;
			break;
		}

		/* Disallow dynamic AP name component */
		if (GET_DYN(ap_id) != NULL) {
			rv = CFGA_SATA_INVALID_DEVNAME;
			goto bailout;
		}

		ret = devctl_ap_connect(hdl, nvl);
		if (ret != 0) {
			rv = CFGA_SATA_IOCTL;
		} else {
			rv = CFGA_SATA_OK;
		}

		break;

	case CFGA_CMD_LOAD:
	case CFGA_CMD_UNLOAD:
		(void) cfga_help(msgp, options, flags);
		rv = CFGA_SATA_OPNOTSUPP;
		break;

	case CFGA_CMD_NONE:
	default:
		(void) cfga_help(msgp, options, flags);
		rv = CFGA_SATA_INTERNAL_ERROR;
	}

bailout:
	cleanup_after_devctl_cmd(hdl, nvl);

	return (sata_err_msg(errstring, rv, ap_id, errno));
}

/* cfgadm entry point */
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
	ap_rstate_t		rstate;
	devctl_hdl_t		hdl = NULL;
	cfga_sata_ret_t		rv;
	char			*str_p;
	size_t			size;

	if ((rv = verify_params(ap_id, NULL, errstring)) != CFGA_SATA_OK) {
		(void) cfga_help(msgp, options, flags);
		return (sata_err_msg(errstring, rv, ap_id, errno));
	}

	/*
	 * All subcommands which can change state of device require
	 * root privileges.
	 */
	if (geteuid() != 0) {
		rv = CFGA_SATA_PRIV;
		goto bailout;
	}

	if (func == NULL) {
		(void) printf("No valid option specified\n");
		rv = CFGA_SATA_OPTIONS;
		goto bailout;
	}

	if ((rv = setup_for_devctl_cmd(ap_id, &hdl, &list, 0)) !=
	    CFGA_SATA_OK) {
		goto bailout;
	}

	/* We do not care here about dynamic AP name component */
	if ((str_p = GET_DYN(ap_id)) != NULL) {
		*str_p = '\0';
	}

	rv = CFGA_SATA_OK;

	if (strcmp(func, SATA_RESET_PORT) == 0) {
		len = strlen(SATA_CONFIRM_PORT) +
		    strlen(SATA_CONFIRM_DEVICE_ABORT) +
		    strlen("Reset Port") + strlen(ap_id);

		if ((msg = (char *)calloc(len +3, 1)) != NULL) {
			(void) snprintf(msg, len +3, "Reset"
			    " %s%s\n%s",
			    SATA_CONFIRM_PORT, ap_id,
			    SATA_CONFIRM_DEVICE_ABORT);
		} else {
			rv = CFGA_SATA_NACK;
			goto bailout;
		}

		if (!sata_confirm(confp, msg)) {
			rv = CFGA_SATA_NACK;
			goto bailout;
		}

		rv = do_control_ioctl(ap_id, SATA_CFGA_RESET_PORT, NULL,
		    (void **)&str_p, &size);

	} else if (strcmp(func, SATA_RESET_DEVICE) == 0) {
		if ((rv = port_state(hdl, list, &rstate, &ostate)) !=
		    CFGA_SATA_OK)
			goto bailout;
		/*
		 * Reset device function requires device to be connected
		 */
		if (rstate != AP_RSTATE_CONNECTED) {
			rv = CFGA_SATA_NOT_CONNECTED;
			goto bailout;
		}

		len = strlen(SATA_CONFIRM_DEVICE) +
		    strlen(SATA_CONFIRM_DEVICE_ABORT) +
		    strlen("Reset Device") + strlen(ap_id);

		if ((msg = (char *)calloc(len +3, 1)) != NULL) {
			(void) snprintf(msg, len +3, "Reset"
			    " %s%s\n%s",
			    SATA_CONFIRM_DEVICE, ap_id,
			    SATA_CONFIRM_DEVICE_ABORT);
		} else {
			rv = CFGA_SATA_NACK;
			goto bailout;
		}

		if (!sata_confirm(confp, msg)) {
			rv = CFGA_SATA_NACK;
			goto bailout;
		}

		rv = do_control_ioctl(ap_id, SATA_CFGA_RESET_DEVICE, NULL,
		    (void **)&str_p, &size);

	} else if (strcmp(func, SATA_RESET_ALL) == 0) {
		len = strlen(SATA_CONFIRM_CONTROLLER) +
		    strlen(SATA_CONFIRM_CONTROLLER_ABORT) +
		    strlen("Reset All") + strlen(ap_id);

		if ((msg = (char *)calloc(len +3, 1)) != NULL) {
			(void) snprintf(msg, len +3, "Reset"
			    " %s%s\n%s",
			    SATA_CONFIRM_CONTROLLER, ap_id,
			    SATA_CONFIRM_CONTROLLER_ABORT);
		} else {
			rv = CFGA_SATA_NACK;
			goto bailout;
		}

		if (!sata_confirm(confp, msg)) {
			rv = CFGA_SATA_NACK;
			goto bailout;
		}
		rv = do_control_ioctl(ap_id, SATA_CFGA_RESET_ALL, NULL,
		    (void **)&str_p, &size);

	} else if (strcmp(func, SATA_PORT_DEACTIVATE) == 0) {
		len = strlen(SATA_CONFIRM_PORT) +
		    strlen(SATA_CONFIRM_PORT_DISABLE) +
		    strlen("Deactivate Port") + strlen(ap_id);

		if ((msg = (char *)calloc(len +3, 1)) != NULL) {
			(void) snprintf(msg, len +3, "Deactivate"
			    " %s%s\n%s",
			    SATA_CONFIRM_PORT, ap_id,
			    SATA_CONFIRM_PORT_DISABLE);
		} else {
			rv = CFGA_SATA_NACK;
			goto bailout;
		}
		if (!sata_confirm(confp, msg)) {
			rv = CFGA_SATA_NACK;
			goto bailout;
		}

		rv = do_control_ioctl(ap_id, SATA_CFGA_PORT_DEACTIVATE, NULL,
		    (void **)&str_p, &size);

	} else if (strcmp(func, SATA_PORT_ACTIVATE) == 0) {
		len = strlen(SATA_CONFIRM_PORT) +
		    strlen(SATA_CONFIRM_PORT_ENABLE) +
		    strlen("Activate Port") + strlen(ap_id);

		if ((msg = (char *)calloc(len +3, 1)) != NULL) {
			(void) snprintf(msg, len +3, "Activate"
			    " %s%s\n%s",
			    SATA_CONFIRM_PORT, ap_id,
			    SATA_CONFIRM_PORT_ENABLE);
		} else {
			rv = CFGA_SATA_NACK;
			goto bailout;
		}
		if (!sata_confirm(confp, msg)) {
			rv = CFGA_SATA_NACK;
			goto bailout;
		}

		rv = do_control_ioctl(ap_id, SATA_CFGA_PORT_ACTIVATE,
		    NULL, (void **)&str_p, &size);
		goto bailout;

	} else if (strcmp(func, SATA_PORT_SELF_TEST) == 0) {
		len = strlen(SATA_CONFIRM_PORT) +
		    strlen(SATA_CONFIRM_DEVICE_SUSPEND) +
		    strlen("Self Test Port") + strlen(ap_id);

		if ((msg = (char *)calloc(len +3, 1)) != NULL) {
			(void) snprintf(msg, len +3, "Self Test"
			    " %s%s\n%s",
			    SATA_CONFIRM_PORT, ap_id,
			    SATA_CONFIRM_DEVICE_SUSPEND);
		} else {
			rv = CFGA_SATA_NACK;
			goto bailout;
		}
		if (!sata_confirm(confp, msg)) {
			rv = CFGA_SATA_NACK;
			goto bailout;
		}

		rv = do_control_ioctl(ap_id, SATA_CFGA_PORT_SELF_TEST,
		    NULL, (void **)&str_p, &size);
	} else {
		/* Unrecognized operation request */
		rv = CFGA_SATA_HWOPNOTSUPP;
	}

bailout:
	cleanup_after_devctl_cmd(hdl, list);

	return (sata_err_msg(errstring, rv, ap_id, errno));

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


int
sata_check_target_node(di_node_t node, void *arg)
{
	char *minorpath;
	char *cp;

	minorpath = di_devfs_minor_path(di_minor_next(node, DI_MINOR_NIL));
	if (minorpath != NULL) {
		if (strstr(minorpath, arg) != NULL) {
			cp = strrchr(minorpath, (int)*MINOR_SEP);
			if (cp != NULL) {
				(void) strcpy(arg, cp);
			}
			free(minorpath);
			return (DI_WALK_TERMINATE);
		}
		free(minorpath);
	}
	return (DI_WALK_CONTINUE);
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

	minor_portion = strrchr(minor_path, *MINOR_SEP);
	if (minor_portion == NULL)
		return (0);

	*minor_portion = 0;

	node = di_init(minor_path + strlen("/devices"), DINFOMINOR);

	*minor_portion = *MINOR_SEP;

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
int
sata_make_dyncomp(const char *ap_id, char **dyncomp, const char *type)
{
	char	*devpath = NULL;
	char	*cp = NULL;
	int	l_errno;
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
	devpath = sata_get_devicepath(ap_id);
	if (devpath == NULL) {

		(void) printf("cfga_list_ext: cannot locate target device\n");
		return (CFGA_SATA_DYNAMIC_AP);

	} else {

		cp = strrchr(devpath, *PATH_SEP);
		assert(cp != NULL);
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
			    *MINOR_SEP)) == NULL)
				continue;

			*minor_portion = 0;
			if (strcmp(dep->d_name, name_part) != 0)
				continue;
			*minor_portion = *MINOR_SEP;

			(void) snprintf(minor_path, MAXPATHLEN,
			    "%s/%s", devpath, dep->d_name);

			/*
			 * Break directly for tape device
			 */
			if (strcmp(type, "tape") == 0)
				break;

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
		free(devpath);

		dp = NULL;
		dep = NULL;
		devpath = NULL;

		/*
		 * If there was an error, or we didn't exit the loop
		 * by finding a block or character device, bail out.
		 */
		if (err != 0 || newdep == NULL)
			goto bailout;

		/*
		 * Look for links to the physical path in /dev/dsk
		 * and /dev/rmt. So far, sata modue supports disk,
		 * dvd and tape devices, so we will first look for
		 * BLOCK devices, and then look for tape devices.
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
		} else if (strcmp(type, "tape") == 0) {

			/*
			 * For tape device, logical name looks like
			 * rmt/X
			 */
			(void) physpath_to_devlink("/dev/rmt",
			    minor_path, &devlink, &l_errno);

			if (devlink != NULL) {
				if ((cp = strstr(devlink, "rmt/")) != NULL) {
					*dyncomp = strdup(cp);
				}

				free(devlink);
			}
		}

		return (SATA_CFGA_OK);
	}

bailout:
	if (dp)
		(void) closedir(dp);
	if (devpath)
		free(devpath);
	if (dep)
		free(dep);
	return (CFGA_SATA_DYNAMIC_AP);
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
	size_t			size;
	nvlist_t		*user_nvlist = NULL;
	devctl_hdl_t		devctl_hdl = NULL;
	cfga_sata_ret_t		rv = CFGA_SATA_OK;
	devctl_ap_state_t	devctl_ap_state;
	char			*pdyn;
	boolean_t		pmult = B_FALSE;
	uint32_t		port;


	if ((rv = verify_params(ap_id, options, errstring)) != CFGA_SATA_OK) {
		goto bailout;
	}
	/* We do not care here about dynamic AP name component */
	if ((pdyn = GET_DYN(ap_id)) != NULL) {
		*pdyn = '\0';
	}

	if (ap_id_list == NULL || nlistp == NULL) {
		rv = CFGA_SATA_DATA_ERROR;
		goto bailout;
	}

	/* Get ap status */
	if ((rv = setup_for_devctl_cmd(ap_id, &devctl_hdl, &user_nvlist,
	    DC_RDONLY)) != CFGA_SATA_OK) {
		goto bailout;
	}

	/* will call dc_cmd to send IOCTL to kernel */
	if (devctl_ap_getstate(devctl_hdl, user_nvlist,
	    &devctl_ap_state) == -1) {
		cleanup_after_devctl_cmd(devctl_hdl, user_nvlist);
		rv = CFGA_SATA_IOCTL;
		goto bailout;
	}

	cleanup_after_devctl_cmd(devctl_hdl, user_nvlist);

	/*
	 * Create cfga_list_data_t struct.
	 */
	if ((*ap_id_list =
	    (cfga_list_data_t *)malloc(sizeof (**ap_id_list))) == NULL) {
		rv = CFGA_SATA_ALLOC_FAIL;
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
		rv = CFGA_SATA_DEVLINK;
		goto bailout;
	}

	/* Get logical ap_id corresponding to the physical */
	if (ap_id_log == NULL || strstr(ap_id_log, CFGA_DEV_DIR) == NULL) {
		rv = CFGA_SATA_DEVLINK;
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
		rv = CFGA_SATA_STATE;
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
		rv = CFGA_SATA_STATE;
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
		rv = CFGA_SATA_STATE;
		goto bailout;
	}

	(*ap_id_list)->ap_class[0] = '\0';	/* Filled by libcfgadm */
	(*ap_id_list)->ap_busy = devctl_ap_state.ap_in_transition;
	(*ap_id_list)->ap_status_time = devctl_ap_state.ap_last_change;
	(*ap_id_list)->ap_info[0] = NULL;

	if ((*ap_id_list)->ap_r_state == CFGA_STAT_CONNECTED) {
		char *str_p;
		int skip, i;

		/*
		 * Fill in the 'Information' field for the -v option
		 * Model (MOD:)
		 */
		if ((rv = do_control_ioctl(ap_id, SATA_CFGA_GET_MODEL_INFO,
		    NULL, (void **)&str_p, &size)) != CFGA_SATA_OK) {
			(void) printf(
			    "SATA_CFGA_GET_MODULE_INFO ioctl failed\n");
			goto bailout;
		}
		/* drop leading and trailing spaces */
		skip = strspn(str_p, " ");
		for (i = size - 1; i >= 0; i--) {
			if (str_p[i] == '\040')
				str_p[i] = '\0';
			else if (str_p[i] != '\0')
				break;
		}

		(void) strlcpy((*ap_id_list)->ap_info, "Mod: ",
		    sizeof ((*ap_id_list)->ap_info));
		(void) strlcat((*ap_id_list)->ap_info, str_p + skip,
		    sizeof ((*ap_id_list)->ap_info));

		free(str_p);

		/*
		 * Fill in the 'Information' field for the -v option
		 * Firmware revision (FREV:)
		 */
		if ((rv = do_control_ioctl(ap_id,
		    SATA_CFGA_GET_REVFIRMWARE_INFO,
		    NULL, (void **)&str_p, &size)) != CFGA_SATA_OK) {
			(void) printf(
			    "SATA_CFGA_GET_REVFIRMWARE_INFO ioctl failed\n");
			goto bailout;
		}
		/* drop leading and trailing spaces */
		skip = strspn(str_p, " ");
		for (i = size - 1; i >= 0; i--) {
			if (str_p[i] == '\040')
				str_p[i] = '\0';
			else if (str_p[i] != '\0')
				break;
		}
		(void) strlcat((*ap_id_list)->ap_info, " FRev: ",
		    sizeof ((*ap_id_list)->ap_info));
		(void) strlcat((*ap_id_list)->ap_info, str_p + skip,
		    sizeof ((*ap_id_list)->ap_info));

		free(str_p);


		/*
		 * Fill in the 'Information' field for the -v option
		 * Serial Number (SN:)
		 */
		if ((rv = do_control_ioctl(ap_id,
		    SATA_CFGA_GET_SERIALNUMBER_INFO,
		    NULL, (void **)&str_p, &size)) != CFGA_SATA_OK) {
			(void) printf(
			    "SATA_CFGA_GET_SERIALNUMBER_INFO ioctl failed\n");
			goto bailout;
		}
		/* drop leading and trailing spaces */
		skip = strspn(str_p, " ");
		for (i = size - 1; i >= 0; i--) {
			if (str_p[i] == '\040')
				str_p[i] = '\0';
			else if (str_p[i] != '\0')
				break;
		}
		(void) strlcat((*ap_id_list)->ap_info, " SN: ",
		    sizeof ((*ap_id_list)->ap_info));
		(void) strlcat((*ap_id_list)->ap_info, str_p + skip,
		    sizeof ((*ap_id_list)->ap_info));

		free(str_p);



		/* Fill in ap_type which is collected from HBA driver */
		/* call do_control_ioctl TBD */
		if ((rv = do_control_ioctl(ap_id, SATA_CFGA_GET_AP_TYPE, NULL,
		    (void **)&str_p, &size)) != CFGA_SATA_OK) {
			(void) printf(
			    "SATA_CFGA_GET_AP_TYPE ioctl failed\n");
			goto bailout;
		}

		(void) strlcpy((*ap_id_list)->ap_type, str_p,
		    sizeof ((*ap_id_list)->ap_type));

		free(str_p);

		/*
		 * Checking device type. Port multiplier has no dynamic
		 * suffix.
		 */
		if (strncmp((*ap_id_list)->ap_type, "sata-pmult",
		    sizeof ("sata-pmult")) == 0)
			pmult = B_TRUE;

		if ((*ap_id_list)->ap_o_state == CFGA_STAT_CONFIGURED &&
		    pmult == B_FALSE) {

			char *dyncomp = NULL;

			/*
			 * This is the case where we need to generate
			 * a dynamic component of the ap_id, i.e. device.
			 */
			rv = sata_make_dyncomp(ap_id, &dyncomp,
			    (*ap_id_list)->ap_type);
			if (rv != CFGA_SATA_OK)
				goto bailout;
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
		/* This is an empty port */
		if (get_port_num(ap_id, &port) != CFGA_SATA_OK) {
			goto bailout;
		}

		if (port & SATA_CFGA_PMPORT_QUAL) {
			(void) strlcpy((*ap_id_list)->ap_type, "pmult-port",
			    sizeof ((*ap_id_list)->ap_type));
		} else {
			(void) strlcpy((*ap_id_list)->ap_type, "sata-port",
			    sizeof ((*ap_id_list)->ap_type));
		}
	}

	return (sata_err_msg(errstring, rv, ap_id, errno));

bailout:
	if (*ap_id_list != NULL) {
		free(*ap_id_list);
	}
	if (ap_id_log != NULL) {
		free(ap_id_log);
	}

	return (sata_err_msg(errstring, rv, ap_id, errno));
}
/*
 * This routine accepts a string adn prints it using
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
	(void) (*msgp->message_routine)(msgp->appdata_ptr, q);

	free(q);
}

/* cfgadm entry point */
/* ARGSUSED */
cfga_err_t
cfga_help(struct cfga_msg *msgp, const char *options, cfga_flags_t flags)
{
	if (options != NULL) {
		cfga_msg(msgp, dgettext(TEXT_DOMAIN, sata_help[HELP_UNKNOWN]));
		cfga_msg(msgp, options);
	}
	cfga_msg(msgp, dgettext(TEXT_DOMAIN, sata_help[HELP_HEADER]));
	cfga_msg(msgp, sata_help[HELP_CONFIG]);
	cfga_msg(msgp, sata_help[HELP_RESET_PORT]);
	cfga_msg(msgp, sata_help[HELP_RESET_DEVICE]);
	cfga_msg(msgp, sata_help[HELP_RESET_ALL]);
	cfga_msg(msgp, sata_help[HELP_PORT_ACTIVATE]);
	cfga_msg(msgp, sata_help[HELP_PORT_DEACTIVATE]);
	cfga_msg(msgp, sata_help[HELP_PORT_SELF_TEST]);
	cfga_msg(msgp, sata_help[HELP_CNTRL_SELF_TEST]);

	return (CFGA_OK);
}


/*
 * Ensure the ap_id passed is in the correct (physical ap_id) form:
 *     path/device:xx[.xx]
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

	l_ap_id = strrchr(ap_id, (int)*MINOR_SEP);
	l_ap_id++;

	if (strspn(l_ap_id, "0123456789.") != strlen(l_ap_id)) {
		/* Bad characters in the ap_id */
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
static cfga_sata_ret_t
verify_params(
    const char *ap_id,
    const char *options,
    char **errstring)
{
	char *pdyn, *lap_id;
	int rv;

	if (errstring != NULL) {
		*errstring = NULL;
	}

	if (options != NULL) {
		return (CFGA_SATA_OPTIONS);
	}

	/* Strip dynamic AP name component if it is present. */
	lap_id = strdup(ap_id);
	if (lap_id == NULL) {
		return (CFGA_SATA_ALLOC_FAIL);
	}
	if ((pdyn = GET_DYN(lap_id)) != NULL) {
		*pdyn = '\0';
	}

	if (verify_valid_apid(lap_id) != 0) {
		rv = CFGA_SATA_AP;
	} else {
		rv = CFGA_SATA_OK;
	}
	free(lap_id);

	return (rv);
}

/*
 * Takes a validated ap_id and extracts the port number.
 * Port multiplier is supported now.
 */
static cfga_sata_ret_t
get_port_num(const char *ap_id, uint32_t *port)
{
	uint32_t	cport, pmport = 0, qual = 0;
	char		*cport_str, *pmport_str;

	/* Get the cport number */
	cport_str = strrchr(ap_id, (int)*MINOR_SEP) + strlen(MINOR_SEP);

	errno = 0;
	cport = strtol(cport_str, NULL, 10);
	if ((cport & ~SATA_CFGA_CPORT_MASK) != 0 || errno != 0) {
		return (CFGA_SATA_PORT);
	}

	/* Get pmport number if there is a PORT_SEPARATOR */
	errno = 0;
	if ((pmport_str = strrchr(ap_id, (int)*PORT_SEPARATOR)) != 0) {
		pmport_str += strlen(PORT_SEPARATOR);
		pmport = strtol(pmport_str, NULL, 10);
		qual = SATA_CFGA_PMPORT_QUAL;
		if ((pmport & ~SATA_CFGA_PMPORT_MASK) != 0 || errno != 0) {
			return (CFGA_SATA_PORT);
		}
	}

	*port = cport | (pmport << SATA_CFGA_PMPORT_SHIFT) | qual;
	return (CFGA_SATA_OK);
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

static cfga_sata_ret_t
setup_for_devctl_cmd(
    const char *ap_id,
    devctl_hdl_t *devctl_hdl,
    nvlist_t **user_nvlistp,
    uint_t oflag)
{

	uint_t	port;
	cfga_sata_ret_t	rv = CFGA_SATA_OK;
	char *lap_id, *pdyn;

	lap_id = strdup(ap_id);
	if (lap_id == NULL)
		return (CFGA_SATA_ALLOC_FAIL);
	if ((pdyn = GET_DYN(lap_id)) != NULL) {
		*pdyn = '\0';
	}

	/* Get a devctl handle to pass to the devctl_ap_XXX functions */
	if ((*devctl_hdl = devctl_ap_acquire((char *)lap_id, oflag)) == NULL) {
		(void) fprintf(stderr, "[libcfgadm:sata] "
		    "setup_for_devctl_cmd: devctl_ap_acquire failed: %s\n",
		    strerror(errno));
		rv = CFGA_SATA_DEVCTL;
		goto bailout;
	}

	/* Set up nvlist to pass the port number down to the driver */
	if (nvlist_alloc(user_nvlistp, NV_UNIQUE_NAME_TYPE, NULL) != 0) {
		*user_nvlistp = NULL;
		rv = CFGA_SATA_NVLIST;
		(void) printf("nvlist_alloc failed\n");
		goto bailout;
	}

	/*
	 * Get port id, for Port Multiplier port, things could be a little bit
	 * complicated because of "port.port" format in ap_id, thus for
	 * port multiplier port, port number should be coded as 32bit int
	 * with the sig 16 bit as sata channel number, least 16 bit as
	 * the port number of sata port multiplier port.
	 */
	if ((rv = get_port_num(lap_id, &port)) != CFGA_SATA_OK) {
		(void) printf(
		    "setup_for_devctl_cmd: get_port_num, errno: %d\n",
		    errno);
		goto bailout;
	}

	/* Creates an int32_t entry */
	if (nvlist_add_int32(*user_nvlistp, PORT, port) == -1) {
		(void) printf("nvlist_add_int32 failed\n");
		rv = CFGA_SATA_NVLIST;
		goto bailout;
	}

	free(lap_id);
	return (rv);

bailout:
	free(lap_id);
	(void) cleanup_after_devctl_cmd(*devctl_hdl, *user_nvlistp);

	return (rv);
}


static cfga_sata_ret_t
port_state(devctl_hdl_t hdl, nvlist_t *list,
    ap_rstate_t *rstate, ap_ostate_t *ostate)
{
	devctl_ap_state_t	devctl_ap_state;

	if (devctl_ap_getstate(hdl, list, &devctl_ap_state) == -1) {
		(void) printf("devctl_ap_getstate failed, errno: %d\n", errno);
		return (CFGA_SATA_IOCTL);
	}
	*rstate = devctl_ap_state.ap_rstate;
	*ostate =  devctl_ap_state.ap_ostate;
	return (CFGA_SATA_OK);
}


/*
 * Given a subcommand to the DEVCTL_AP_CONTROL ioctl, rquest the size of
 * the data to be returned, allocate a buffer, then get the data.
 * Returns *descrp (which must be freed) and size.
 *
 * Note SATA_DESCR_TYPE_STRING returns an ASCII NULL-terminated string,
 * not a string descr.
 */
cfga_sata_ret_t
do_control_ioctl(const char *ap_id, sata_cfga_apctl_t subcommand, uint_t arg,
    void **descrp, size_t *sizep)
{
	int			fd = -1;
	uint_t			port;
	uint32_t		local_size;
	cfga_sata_ret_t		rv = CFGA_SATA_OK;
	struct sata_ioctl_data	ioctl_data;

	assert(descrp != NULL);
	*descrp = NULL;
	assert(sizep != NULL);

	if ((rv = get_port_num(ap_id, &port)) != CFGA_SATA_OK) {
		goto bailout;
	}

	if ((fd = open(ap_id, O_RDONLY)) == -1) {
		(void) printf("do_control_ioctl: open failed: errno:%d\n",
		    errno);
		rv = CFGA_SATA_OPEN;
		if (errno == EBUSY) {
			rv = CFGA_SATA_BUSY;
		}
		goto bailout;
	}

	ioctl_data.cmd = subcommand;
	ioctl_data.port = port;
	ioctl_data.misc_arg = (uint_t)arg;

	/*
	 * Find out how large a buf we need to get the data.
	 * Note the ioctls only accept/return a 32-bit int for a get_size
	 * to avoid 32/64 and BE/LE issues.
	 */
	if ((subcommand == SATA_CFGA_GET_AP_TYPE) ||
	    (subcommand == SATA_CFGA_GET_DEVICE_PATH) ||
	    (subcommand == SATA_CFGA_GET_MODEL_INFO) ||
	    (subcommand == SATA_CFGA_GET_REVFIRMWARE_INFO) ||
	    (subcommand == SATA_CFGA_GET_SERIALNUMBER_INFO)) {
		ioctl_data.get_size = B_TRUE;
		ioctl_data.buf = (caddr_t)&local_size;
		ioctl_data.bufsiz = sizeof (local_size);

		if (ioctl(fd, DEVCTL_AP_CONTROL, &ioctl_data) != 0) {
			perror("ioctl failed (size)");
			rv = CFGA_SATA_IOCTL;
			goto bailout;
		}
		*sizep = local_size;

		if (local_size == 0) {
			(void) printf("zero length data\n");
			rv = CFGA_SATA_ZEROLEN;
			goto bailout;
		}
		if ((*descrp = malloc(*sizep)) == NULL) {
			(void) printf("do_control_ioctl: malloc failed\n");
			rv = CFGA_SATA_ALLOC_FAIL;
			goto bailout;
		}
	} else {
		*sizep = 0;
	}
	ioctl_data.get_size = B_FALSE;
	ioctl_data.buf = *descrp;
	ioctl_data.bufsiz = *sizep;

	/* Execute IOCTL */

	if (ioctl(fd, DEVCTL_AP_CONTROL, &ioctl_data) != 0) {
		rv = CFGA_SATA_IOCTL;
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

	if (rv == CFGA_SATA_IOCTL && errno == EBUSY) {
		rv = CFGA_SATA_BUSY;
	}

	return (rv);
}


static int
sata_confirm(struct cfga_confirm *confp, char *msg)
{
	int rval;

	if (confp == NULL || confp->confirm == NULL) {
		return (0);
	}
	rval = (*confp->confirm)(confp->appdata_ptr, msg);

	return (rval);
}


static char *
sata_get_devicepath(const char *ap_id)
{
	char		*devpath = NULL;
	size_t		size;
	cfga_sata_ret_t	rv;

	rv = do_control_ioctl(ap_id, SATA_CFGA_GET_DEVICE_PATH, NULL,
	    (void **)&devpath, &size);

	if (rv == CFGA_SATA_OK) {
		return (devpath);
	} else {
		return ((char *)NULL);
	}

}
