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

#include "cfga_ib.h"

/*
 * cfga_ib.c:
 *	All cfgadm entry points that are defined in the config_admin(3X)
 *	needed for InfiniBand support are described here. These cfgadm
 *	interfaces issue ioctl(s) to the IB nexus driver. Attachment points
 *	supported are - IOC, VPPA, Port, HCA_SVC and Pseudo dynamic ap_ids,
 *	the HCA static ap_id, and the IB static ap_id.
 *
 *	Given InfiniBand bus is fabric based, #of dynamic ap_ids present are
 *	unknown at any given point of time. Hence this plugin uses a
 *	packed nvlist data structure to hold ap_id related information.
 *	The IB nexus driver allocates the nvlist data in the kernel
 *	and this plugin processes the data (it is freed by IB nexus driver).
 */


/* function prototypes */
static int		ib_get_link(di_devlink_t, void *);
static icfga_ret_t	ib_physpath_to_devlink(char *, char **, int *);
static const char	*ib_get_msg(uint_t, msgcvt_t *, uint_t);
static void		ib_set_msg(char **, ...);
static cfga_err_t	ib_err_msg(char **, cfga_ib_ret_t, const char *, int);
static int		ib_verify_valid_apid(const char *);
static cfga_ib_ret_t	ib_verify_params(const char *, const char *, char **);
static void		ib_cleanup_after_devctl_cmd(devctl_hdl_t, nvlist_t *);
static cfga_ib_ret_t	ib_setup_for_devctl_cmd(char *, boolean_t,
			    devctl_hdl_t *, nvlist_t **);
static cfga_ib_ret_t	ib_device_configured(devctl_hdl_t, nvlist_t *,
			    ap_rstate_t *);
static cfga_ib_ret_t	ib_device_connected(devctl_hdl_t, nvlist_t *,
			    ap_ostate_t *);
static cfga_ib_ret_t	ib_do_control_ioctl(char *, uint_t, uint_t, uint_t,
			    void **, size_t *);
cfga_err_t		cfga_change_state(cfga_cmd_t, const char *,
			    const char *, struct cfga_confirm *,
			    struct cfga_msg *, char **, cfga_flags_t);
cfga_err_t		cfga_private_func(const char *, const char *,
			    const char *, struct cfga_confirm *,
			    struct cfga_msg *, char **, cfga_flags_t);
cfga_err_t		cfga_test(const char *, const char *, struct cfga_msg *,
			    char **, cfga_flags_t);
static cfga_ib_ret_t	ib_fill_static_apids(char *, cfga_list_data_t *);
cfga_err_t		cfga_list_ext(const char *, cfga_list_data_t **, int *,
			    const char *, const char *, char **, cfga_flags_t);
void			cfga_msg(struct cfga_msg *, const char *);
cfga_err_t		cfga_help(struct cfga_msg *, const char *,
			    cfga_flags_t);
static int		ib_confirm(struct cfga_confirm *, char *);
static char 		*ib_get_devicepath(const char *);


/* External function prototypes */
extern cfga_ib_ret_t	ib_rcm_offline(const char *, char **, char *,
			    cfga_flags_t);
extern cfga_ib_ret_t	ib_rcm_online(const char *, char **, char *,
			    cfga_flags_t);
extern cfga_ib_ret_t	ib_rcm_remove(const char *, char **, char *,
			    cfga_flags_t);
extern int		ib_add_service(char **);
extern int		ib_delete_service(char **);
extern int		ib_list_services(struct cfga_msg *, char **);


/* Globals */
int		cfga_version = CFGA_HSL_V2;	/* Set the version number for */
						/* the cfgadm library's use. */

static char	*ib_help[] = {	/* Help messages */
	NULL,
	/* CFGA_IB_HELP_HEADER */	"IB specific commands:\n",
	/* CFGA_IB_HELP_CONFIG */	"cfgadm -c [configure|unconfigure] "
	    "ap_id [ap_id...]\n",
	/* CFGA_IB_HELP_LIST */		"cfgadm -x list_clients hca_ap_id "
	    "[hca_ap_id...]\n",
	/* CFGA_IB_HELP_UPD_PKEY */	"cfgadm -x update_pkey_tbls ib\n",
	/* CFGA_IB_HELP_CONF_FILE1 */	"cfgadm -o comm=[port|vppa|hca-svc],"
	    "service=<name> -x [add_service|delete_service] ib\n",
	/* CFGA_IB_HELP_CONF_FILE2 */	"cfgadm -x list_services ib\n",
	/* CFGA_IB_HELP_UPD_IOC_CONF */ "cfgadm -x update_ioc_config "
	    "[ib | ioc_apid]\n",
	/* CFGA_IB_HELP_UNCFG_CLNTS */	"cfgadm -x unconfig_clients hca_ap_id "
	    "[hca_ap_id...]\n",
	/* CFGA_IB_HELP_UNKNOWN */	"\tunknown command or option: ",
	NULL
};

static msgcvt_t	ib_error_msgs[] = {	/* Error messages */
	/* CFGA_IB_OK */		{ CVT, CFGA_OK, "ok" },
	/* CFGA_IB_UNKNOWN */		{ CVT, CFGA_LIB_ERROR,
	    "Unknown message; internal error " },
	/* CFGA_IB_INTERNAL_ERR */	{ CVT, CFGA_LIB_ERROR,
	    "Internal error " },
	/* CFGA_IB_INVAL_ARG_ERR */	{ CVT, CFGA_LIB_ERROR,
	    "Invalid input args " },
	/* CFGA_IB_OPTIONS_ERR */	{ CVT, CFGA_ERROR,
	    "Hardware specific options not supported " },
	/* CFGA_IB_AP_ERR */		{ CVT, CFGA_APID_NOEXIST, "" },
	/* CFGA_IB_DEVCTL_ERR */	{ CVT, CFGA_LIB_ERROR,
	    "Cannot issue devctl to " },
	/* CFGA_IB_NOT_CONNECTED */	{ CVT, CFGA_INSUFFICENT_CONDITION,
	    "No device connected to " },
	/* CFGA_IB_NOT_CONFIGURED */	{ CVT, CFGA_INSUFFICENT_CONDITION,
	    "No device configured to " },
	/* CFGA_IB_ALREADY_CONNECTED */	{ CVT, CFGA_INSUFFICENT_CONDITION,
	    "already connected; cannot connect again " },
	/* CFGA_IB_ALREADY_CONFIGURED */ { CVT, CFGA_INSUFFICENT_CONDITION,
	    "already configured " },
	/* CFGA_IB_CONFIG_OP_ERR */	{ CVT, CFGA_ERROR,
	    "configure operation failed " },
	/* CFGA_IB_UNCONFIG_OP_ERR */	{ CVT, CFGA_ERROR,
	    "unconfigure operation failed " },
	/* CFGA_IB_OPEN_ERR */		{ CVT, CFGA_LIB_ERROR, "Cannot open " },
	/* CFGA_IB_IOCTL_ERR */		{ CVT, CFGA_LIB_ERROR,
	    "Driver ioctl failed " },
	/* CFGA_IB_BUSY_ERR */		{ CVT, CFGA_SYSTEM_BUSY, " " },
	/* CFGA_IB_ALLOC_FAIL */	{ CVT, CFGA_LIB_ERROR,
	    "Memory allocation failure " },
	/* CFGA_IB_OPNOTSUPP */		{ CVT, CFGA_OPNOTSUPP,
	    "Operation not supported " },
	/* CFGA_IB_INVAL_APID_ERR */	{ CVT, CFGA_LIB_ERROR,
	    "Invalid ap_id supplied " },
	/* CFGA_IB_DEVLINK_ERR */	{ CVT, CFGA_LIB_ERROR,
	    "Could not find /dev/cfg link for " },
	/* CFGA_IB_PRIV_ERR */		{ CVT, CFGA_PRIV, " " },
	/* CFGA_IB_NVLIST_ERR */	{ CVT, CFGA_ERROR,
	    "Internal error (nvlist) " },
	/* CFGA_IB_HCA_LIST_ERR */	{ CVT, CFGA_ERROR,
	    "Listing HCA's clients failed " },
	/* CFGA_IB_HCA_UNCONFIG_ERR */	{ CVT, CFGA_ERROR,
	    "Unconfiguring HCA's clients failed " },
	/* CFGA_IB_UPD_PKEY_TBLS_ERR */	{ CVT, CFGA_ERROR,
	    "Updating P_Key tables failed " },
	/* CFGA_IB_RCM_HANDLE_ERR */	{ CVT, CFGA_ERROR,
	    "Opening ib.conf file failed " },
	/* CFGA_IB_LOCK_FILE_ERR */	{ CVT, CFGA_LIB_ERROR,
	    "Locking ib.conf file failed " },
	/* CFGA_IB_UNLOCK_FILE_ERR */	{ CVT, CFGA_LIB_ERROR,
	    "Unlocking ib.conf file failed " },
	/* CFGA_IB_COMM_INVAL_ERR */	{ CVT, CFGA_INVAL,
	    "Communication type incorrectly specified " },
	/* CFGA_IB_SVC_INVAL_ERR */	{ CVT, CFGA_INVAL,
	    "Service name incorrectly specified " },
	/* CFGA_IB_SVC_LEN_ERR_ERR */	{ CVT, CFGA_INVAL,
	    "Service name len should be <= to 4, " },
	/* CFGA_IB_SVC_EXISTS_ERR */	{ CVT, CFGA_INVAL, " "},
	/* CFGA_IB_SVC_NO_EXIST_ERR */	{ CVT, CFGA_INVAL, " " },
	/* CFGA_IB_UCFG_CLNTS_ERR */	{ CVT, CFGA_INVAL,
	    "unconfig_clients failed for HCA " },
	/* CFGA_IB_INVALID_OP_ERR */	{ CVT, CFGA_OPNOTSUPP, "on " },
	/* CFGA_IB_RCM_HANDLE */	{ CVT, CFGA_ERROR,
	    "cannot get RCM handle "},
	/* CFGA_IB_RCM_ONLINE_ERR */	{ CVT, CFGA_SYSTEM_BUSY,
	    "failed to online: "},
	/* CFGA_IB_RCM_OFFLINE_ERR */	{ CVT, CFGA_SYSTEM_BUSY,
	    "failed to offline: "}
};

/*
 * these are the only valid sub-options for services.
 */
static char		*ib_service_subopts[] = {
				"comm",
				"service",
				NULL
			};

/* Communication Service name : "port" or "vppa" or "hca-svc" */
static char		*comm_name = NULL;

char 			*service_name = NULL;	/* service name */
ib_service_type_t	service_type = IB_NONE;	/* service type */


/* ========================================================================= */
/*
 * The next two funcs are imported from cfgadm_scsi.
 * ib_physpath_to_devlink is the only func directly used by cfgadm_ib.
 * ib_get_link supports it.
 */

/*
 * Function:
 *	ib_get_link
 * Input:
 *	devlink		- devlink for the device path
 *	arg		- argument passed to this "walker" function
 * Output:
 *	NONE
 * Returns:
 *	Continue "walking" or not
 * Description:
 *	Routine to search the /dev directory or a subtree of /dev.
 */
static int
ib_get_link(di_devlink_t devlink, void *arg)
{
	walk_link_t	*larg = (walk_link_t *)arg;

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


/*
 * Function:
 *	ib_physpath_to_devlink
 * Input:
 *	node_path	- Physical path of the ap_id node
 * Output:
 *	logpp		- Logical path to the ap_id node
 *	l_errnop	- "errno"
 * Returns:
 *	ICFGA_OK if everything was fine; otherwise an error with
 *	l_errnop set.
 * Description:
 *	Given a physical path to an ap_id ensure that it exists
 */
/* ARGSUSED */
static icfga_ret_t
ib_physpath_to_devlink(char *node_path, char **logpp, int *l_errnop)
{
	char			*minor_path;
	walk_link_t		larg;
	di_devlink_handle_t	hdl;

	if ((hdl = di_devlink_init(NULL, 0)) == NULL) {
		*l_errnop = errno;
		return (ICFGA_LIB_ERR);
	}

	*logpp = NULL;
	larg.linkpp = logpp;
	minor_path = (char *)node_path + strlen("/devices");
	larg.path = NULL;
	larg.len = 0;

	(void) di_devlink_walk(hdl, "^cfg/", minor_path, DI_PRIMARY_LINK,
	    (void *)&larg, ib_get_link);

	di_devlink_fini(&hdl);

	if (*logpp == NULL) {
		*l_errnop = errno;
		return (ICFGA_LIB_ERR);
	}

	return (ICFGA_OK);
}


/* ========================================================================= */
/* Utilities */

/*
 * Function:
 *	ib_get_msg
 * Input:
 *	msg_index	- Index into the message table
 *	msg_tbl		- the message table
 *	tbl_size	- size of the message table
 * Output:
 *	NONE
 * Returns:
 *	Message string if valid, otherwise an error
 * Description:
 *	Given the index into a table (msgcvt_t) of messages,
 *	get the message string, converting it to the proper
 *	locale if necessary.
 *
 *	NOTE: See cfga_ib.h
 */
static const char *
ib_get_msg(uint_t msg_index, msgcvt_t *msg_tbl, uint_t tbl_size)
{
	if (msg_index >= tbl_size) {
		DPRINTF("get_error_msg: bad error msg index: %d\n", msg_index);
		msg_index = CFGA_IB_UNKNOWN;
	}

	return ((msg_tbl[msg_index].intl) ?
	    dgettext(TEXT_DOMAIN, msg_tbl[msg_index].msgstr) :
	    msg_tbl[msg_index].msgstr);
}


/*
 * Function:
 *	ib_set_msg
 * Input:
 *	NONE
 * Output:
 *	ret_str	- Returned "message" string.
 * Returns:
 *	NONE
 * Description:
 *	Allocates and creates a message string (in *ret_str),
 *	by concatenating all the (char *) args together, in order.
 *	Last arg MUST be NULL.
 */
static void
ib_set_msg(char **ret_str, ...)
{
	char	*str;
	size_t	total_len, ret_str_len;
	va_list	valist;

	va_start(valist, ret_str);

	total_len = (*ret_str == NULL) ? 0 : strlen(*ret_str);

	while ((str = va_arg(valist, char *)) != NULL) {
		size_t	len = strlen(str);
		char	*old_str = *ret_str;

		ret_str_len = total_len + len + 1;
		*ret_str = (char *)realloc(*ret_str, ret_str_len);
		if (*ret_str == NULL) {
			free(old_str);
			DPRINTF("ib_set_msg: realloc failed.\n");
			va_end(valist);
			return;
		}

		(void) strlcpy(*ret_str + total_len, str, ret_str_len);
		total_len += len;
	}

	va_end(valist);
}


/*
 * Function:
 *	ib_err_msg
 * Input:
 *	ap_id		- The attachment point of an IB fabric
 * Output:
 *	errstring	- Fill in the error msg string
 *	l_errno		- The "errno" to be filled in.
 * Returns:
 *	CFGA_IB_OK if we are able to fill in error msg;
 *	otherwise emit an error.
 * Description:
 *	Error message handling.
 *
 *	For the rv passed in, looks up the corresponding error message
 *	string(s), internationalized it if necessary, and concatenates
 *	it into a new memory buffer, and points *errstring to it.
 *	Note not all "rv"s will result in an error message return, as
 *	not all error conditions warrant a IB-specific error message.
 *
 *	Some messages may display ap_id or errno, which is why they are
 *	passed in.
 */
static cfga_err_t
ib_err_msg(char **errstring, cfga_ib_ret_t rv, const char *ap_id, int l_errno)
{
	char *errno_str;

	if (errstring == NULL) {
		return (ib_error_msgs[rv].cfga_err);
	}

	/* Generate the appropriate IB-specific error message(s) (if any). */
	switch (rv) {
	case CFGA_IB_OK:	/* Special case - do nothing.  */
		break;
	case CFGA_IB_AP_ERR:
	case CFGA_IB_UNKNOWN:
	case CFGA_IB_INTERNAL_ERR:
	case CFGA_IB_OPTIONS_ERR:
	case CFGA_IB_ALLOC_FAIL:
		/* These messages require no additional strings passed. */
		ib_set_msg(errstring, ERR_STR(rv), NULL);
		break;
	case CFGA_IB_NOT_CONNECTED:
	case CFGA_IB_NOT_CONFIGURED:
	case CFGA_IB_ALREADY_CONNECTED:
	case CFGA_IB_ALREADY_CONFIGURED:
	case CFGA_IB_CONFIG_OP_ERR:
	case CFGA_IB_UNCONFIG_OP_ERR:
	case CFGA_IB_BUSY_ERR:
	case CFGA_IB_DEVLINK_ERR:
	case CFGA_IB_RCM_HANDLE_ERR:
	case CFGA_IB_RCM_ONLINE_ERR:
	case CFGA_IB_RCM_OFFLINE_ERR:
	case CFGA_IB_DEVCTL_ERR:
	case CFGA_IB_COMM_INVAL_ERR:
	case CFGA_IB_SVC_INVAL_ERR:
	case CFGA_IB_SVC_LEN_ERR:
	case CFGA_IB_SVC_EXISTS_ERR:
	case CFGA_IB_SVC_NO_EXIST_ERR:
	case CFGA_IB_LOCK_FILE_ERR:
	case CFGA_IB_CONFIG_FILE_ERR:
	case CFGA_IB_UNLOCK_FILE_ERR:
	case CFGA_IB_UCFG_CLNTS_ERR:
	case CFGA_IB_INVALID_OP_ERR:
		/* These messages also print ap_id.  */
		ib_set_msg(errstring, ERR_STR(rv), "ap_id: ", ap_id, "", NULL);
		break;
	case CFGA_IB_IOCTL_ERR:	/* These messages also print errno.  */
	case CFGA_IB_NVLIST_ERR:
		errno_str = l_errno ? strerror(l_errno) : "";
		ib_set_msg(errstring, ERR_STR(rv), errno_str,
		    l_errno ? "\n" : "", NULL);
		break;
	case CFGA_IB_OPEN_ERR: /* This messages also prints apid and errno.  */
	case CFGA_IB_PRIV_ERR:
	case CFGA_IB_HCA_LIST_ERR:
	case CFGA_IB_OPNOTSUPP:
	case CFGA_IB_INVAL_ARG_ERR:
	case CFGA_IB_INVAL_APID_ERR:
	case CFGA_IB_HCA_UNCONFIG_ERR:
	case CFGA_IB_UPD_PKEY_TBLS_ERR:
		errno_str = l_errno ? strerror(l_errno) : "";
		ib_set_msg(errstring, ERR_STR(rv), "ap_id: ", ap_id, "\n",
		    errno_str, l_errno ? "\n" : "", NULL);
		break;
	default:
		DPRINTF("ib_err_msg: Unrecognized message index: %d\n", rv);
		ib_set_msg(errstring, ERR_STR(CFGA_IB_INTERNAL_ERR), NULL);
	}

	/*
	 * Determine the proper error code to send back to the cfgadm library.
	 */
	return (ib_error_msgs[rv].cfga_err);
}


/*
 * Function:
 *	ib_verify_valid_apid
 * Input:
 *	ap_id		- The attachment point of an IB fabric
 * Output:
 *	NONE
 * Returns:
 *	0 if ap_id is valid; otherwise -1
 * Description:
 *	Check if ap_id is valid or not.
 *	Ensure the ap_id passed is in the correct (physical ap_id) form:
 *	path/device:xx[.xx]+
 *	where xx is a one or two-digit number.
 *
 *	Note the library always calls the plugin with a physical ap_id.
 *	Called by ib_verify_params().
 */
static int
ib_verify_valid_apid(const char *ap_id)
{
	char	*l_ap_id;

	if (ap_id == NULL) {
		return (-1);
	}

	l_ap_id = strchr(ap_id, *MINOR_SEP);
	l_ap_id++;

	/* fabric apids */
	if (strstr((char *)ap_id, IBNEX_FABRIC) != NULL) {
		DPRINTF("ib_valid_apid: l_apid = %s\n", l_ap_id);
		/* if the ap_id is "ib::" then report an error */
		if ((strlen(l_ap_id) == strlen(IBNEX_FABRIC) + 1) ||
		    (strlen(l_ap_id) == strlen(IBNEX_FABRIC) + 2)) {
			return (-1);
		}

		if (strstr(l_ap_id, "...") != NULL) {
			return (-1);
		}

	} else {	/* HCA ap_ids */
		/* ap_id has 1..2 or more than 2 dots */
		if (strstr(l_ap_id, "..") != NULL) {
			return (-1);
		}
	}

	return (0);
}


/*
 * Function:
 *	ib_verify_params
 * Input:
 *	ap_id		- The attachment point of an IB fabric
 *	options		- command options passed by the cfgadm(1M)
 *	errstring	- This contains error msg if command fails
 * Output:
 *	NONE
 * Returns:
 *	CFGA_IB_OK if parameters are valid; otherwise emit an error.
 * Description:
 *	Check if "options" and "errstring" are valid and if ap_id is
 *	valid or not.
 */
static cfga_ib_ret_t
ib_verify_params(const char *ap_id, const char *options, char **errstring)
{
	if (errstring != NULL) {
		*errstring = NULL;
	}

	if (options != NULL) {
		DPRINTF("ib_verify_params: h/w-specific options not "
		    "supported.\n");
		return (CFGA_IB_OPTIONS_ERR);
	}

	if (ib_verify_valid_apid(ap_id) != 0) {
		DPRINTF("ib_verify_params: not an IB ap_id.\n");
		return (CFGA_IB_AP_ERR);
	}
	return (CFGA_IB_OK);
}


/*
 * Function:
 *	ib_cleanup_after_devctl_cmd
 * Input:
 *	devctl_hdl	- Handler to devctl
 *	user_nvlistp	- Name-value-pair list pointer
 * Output:
 *	NONE
 * Returns:
 *	NONE
 * Description:
 *	Cleanup an initialization/setup done in the next function i.e.
 *	ib_setup_for_devctl_cmd().
 */
static void
ib_cleanup_after_devctl_cmd(devctl_hdl_t devctl_hdl, nvlist_t *user_nvlist)
{
	if (user_nvlist != NULL) {
		nvlist_free(user_nvlist);
	}

	if (devctl_hdl != NULL) {
		devctl_release(devctl_hdl);
	}
}


/*
 * Function:
 *	ib_setup_for_devctl_cmd
 * Input:
 *	ap_id		- Attachment point for the IB device in question
 *	use_static_ap_id - Whether to use static ap_id or not flag
 * Output:
 *	devctl_hdl	- Handler to devctl
 *	user_nvlistp	- Name-value-pair list pointer
 * Returns:
 *	CFGA_IB_OK if it succeeds or an appropriate error.
 * Description:
 *	For any IB device  that is doing a cfgadm operation this function
 *	sets up a devctl_hdl and allocates a nvlist_t. The devctl_hdl
 *	is acquired using libdevice APIs. The nvlist_t is filled up with
 *	the ap_id (as a string). This nvlist_t is looked up in the kernel
 *	to figure out which ap_id we are currently dealing with.
 *
 *	"use_static_ap_id" flag tells if one should do a devctl_ap_acquire
 *	with IB_STATIC_APID or not. NOTE: We need an actual file-system
 *	vnode to do a devctl_ap_acquire.
 *
 *	NOTE: always call ib_cleanup_after_devctl_cmd() after this function.
 */
static cfga_ib_ret_t
ib_setup_for_devctl_cmd(char *ap_id, boolean_t use_static_ap_id,
    devctl_hdl_t *devctl_hdl, nvlist_t **user_nvlistp)
{
	char	*apid = (use_static_ap_id == B_TRUE) ? IB_STATIC_APID : ap_id;

	/* Get a handle to the ap */
	if ((*devctl_hdl = devctl_ap_acquire(apid, NULL)) == NULL) {
		DPRINTF("ib_setup_for_devctl_cmd: devctl_ap_acquire "
		    "errno: %d\n", errno);
		ib_cleanup_after_devctl_cmd(*devctl_hdl, *user_nvlistp);
		return (CFGA_IB_DEVCTL_ERR);
	}

	/* Set up to pass dynamic ap_id down to driver */
	if (nvlist_alloc(user_nvlistp, NV_UNIQUE_NAME_TYPE, NULL) != 0) {
		DPRINTF("ib_setup_for_devctl: nvlist_alloc errno: %d\n", errno);
		*user_nvlistp = NULL;	/* Prevent possible incorrect free in */
					/* ib_cleanup_after_devctl_cmd */
		ib_cleanup_after_devctl_cmd(*devctl_hdl, *user_nvlistp);
		return (CFGA_IB_NVLIST_ERR);
	}

	/* create a "string" entry */
	if (nvlist_add_string(*user_nvlistp, IB_APID, ap_id) == -1) {
		DPRINTF("ib_setup_for_devctl_cmd: nvlist_add_string failed. "
		    "errno: %d\n", errno);
		ib_cleanup_after_devctl_cmd(*devctl_hdl, *user_nvlistp);
		return (CFGA_IB_NVLIST_ERR);
	}

	return (CFGA_IB_OK);
}


/*
 * Function:
 *	ib_device_configured
 * Input:
 *	hdl		- Handler to devctl
 *	nvl		- Name-value-pair list pointer
 * Output:
 *	rstate		- Receptacle state for the apid
 * Returns:
 *	CFGA_IB_OK if it succeeds or an appropriate error.
 * Description:
 *	Checks if there is a device actually configured to the ap? If so,
 *	issues a "devctl" to get the Receptacle state for that ap_id.
 *	If the ap_id is already configured it returns CFGA_IB_OK.
 *	Otherwise it returns a failure.
 */
static cfga_ib_ret_t
ib_device_configured(devctl_hdl_t hdl, nvlist_t *nvl, ap_rstate_t *rstate)
{
	cfga_ib_ret_t		rv;
	devctl_ap_state_t	devctl_ap_state;

	/* get ap_id's "devctl_ap_state" first */
	if (devctl_ap_getstate(hdl, nvl, &devctl_ap_state) == -1) {
		DPRINTF("ib_device_configured failed, errno: %d\n", errno);
		return (CFGA_IB_DEVCTL_ERR);
	}

	rv = CFGA_IB_ALREADY_CONFIGURED;
	*rstate = devctl_ap_state.ap_rstate;
	if (devctl_ap_state.ap_ostate != AP_OSTATE_CONFIGURED) {
		return (CFGA_IB_NOT_CONFIGURED);
	}

	return (rv);
}


/*
 * Function:
 *	ib_device_connected
 * Input:
 *	hdl		- Handler to devctl
 *	nvl		- Name-value-pair list pointer
 * Output:
 *	ostate		- Occupant state for the apid
 * Returns:
 *	CFGA_IB_OK if it succeeds or an appropriate error.
 * Description:
 *	Checks if there is a device actually connected to the ap? If so,
 *	issues a "devctl" to get the Occupant state for that ap_id.
 *	If the ap_id is already connected it returns CFGA_IB_OK.
 *	Otherwise it returns a failure.
 */
static cfga_ib_ret_t
ib_device_connected(devctl_hdl_t hdl, nvlist_t *list, ap_ostate_t *ostate)
{
	cfga_ib_ret_t		rv = CFGA_IB_ALREADY_CONNECTED;
	devctl_ap_state_t	devctl_ap_state;

	if (devctl_ap_getstate(hdl, list, &devctl_ap_state) == -1) {
		DPRINTF("ib_device_connected failed, errno: %d\n", errno);
		return (CFGA_IB_DEVCTL_ERR);
	}

	*ostate =  devctl_ap_state.ap_ostate;
	if (devctl_ap_state.ap_rstate != AP_RSTATE_CONNECTED) {
		return (CFGA_IB_NOT_CONNECTED);
	}

	return (rv);
}


/*
 * Function:
 *	ib_do_control_ioctl
 * Input:
 *	ap_id		- The dynamic attachment point of an IB device
 *	sub_cmd1	- Sub Command 1 to DEVCTL_AP_CONTROL devctl
 *	sub_cmd2	- Sub Command 2 to DEVCTL_AP_CONTROL devctl
 *				(Mandatory except for IBNEX_NUM_HCA_NODES,
 *				IBNEX_NUM_DEVICE_NODES,
 *				IBNEX_UPDATE_PKEY_TBLS &
 *				IBNEX_UPDATE_IOC_CONF)
 *	misc_arg	- optional arguments to DEVCTL_AP_CONTROL devctl
 * Output:
 *	descrp		- Buffer containing data back from kernel
 *	sizep		- Length of the buffer back from kernel
 * Returns:
 *	CFGA_IB_OK if it succeeds or an appropriate error.
 * Description:
 *	Issues DEVCTL_AP_CONTROL devctl with sub_cmd1 first which actually
 *	queries the IBNEX module in the kernel on the size of the data to
 *	be returned.
 *
 *	Next issues DEVCTL_AP_CONTROL devctl with a buffer of that much
 *	size and gets the actual data back.
 *	Passes the data and the size back to caller.
 */
static cfga_ib_ret_t
ib_do_control_ioctl(char *ap_id, uint_t sub_cmd1, uint_t sub_cmd2,
    uint_t misc_arg, void **descrp, size_t *sizep)
{
	int			fd = -1;
	uint32_t		local_size = 0;
	cfga_ib_ret_t		rv = CFGA_IB_OK;
	struct ibnex_ioctl_data	ioctl_data;

	/* try to open the ONLY static ap_id */
	if ((fd = open(IB_STATIC_APID, O_RDONLY)) == -1) {
		DPRINTF("ib_do_control_ioctl: open failed: "
		    "errno = %d\n", errno);
		/* Provides a more useful error msg */
		rv = (errno == EBUSY) ? CFGA_IB_BUSY_ERR : CFGA_IB_OPEN_ERR;
		return (rv);
	}

	/*
	 * Find out first how large a buffer is needed?
	 * NOTE: Ioctls only accept/return a 32-bit int for a get_size
	 * to avoid 32/64 and BE/LE issues.
	 */
	ioctl_data.cmd = sub_cmd1;
	ioctl_data.misc_arg = (uint_t)misc_arg;
	ioctl_data.buf = (caddr_t)&local_size;
	ioctl_data.bufsiz = sizeof (local_size);

	/* Pass "ap_id" up for all other commands */
	if (sub_cmd1 != IBNEX_NUM_DEVICE_NODES &&
	    sub_cmd1 != IBNEX_NUM_HCA_NODES &&
	    sub_cmd1 != IBNEX_UPDATE_PKEY_TBLS) {
		ioctl_data.ap_id = (caddr_t)ap_id;
		ioctl_data.ap_id_len = strlen(ap_id);

	} else {
		ioctl_data.ap_id = NULL;
		ioctl_data.ap_id_len = 0;
	}

	if (ioctl(fd, DEVCTL_AP_CONTROL, &ioctl_data) != 0) {
		DPRINTF("ib_do_control_ioctl: size ioctl ERR, errno: %d\n",
		    errno);
		(void) close(fd);
		rv = (errno == EBUSY) ? CFGA_IB_BUSY_ERR : CFGA_IB_IOCTL_ERR;
		return (rv);
	}
	*sizep = local_size;

	/*
	 * Don't do the second ioctl only in these cases
	 * (NOTE: the data is returned in the first ioctl itself; if any)
	 */
	if (sub_cmd1 == IBNEX_NUM_DEVICE_NODES ||
	    sub_cmd1 == IBNEX_NUM_HCA_NODES ||
	    sub_cmd1 == IBNEX_UPDATE_PKEY_TBLS ||
	    sub_cmd1 == IBNEX_UPDATE_IOC_CONF) {
		(void) close(fd);
		return (rv);
	}

	if (local_size == 0 || (*descrp = malloc(*sizep)) == NULL) {
		DPRINTF("ib_do_control_ioctl: malloc failed\n");
		(void) close(fd);
		return (CFGA_IB_ALLOC_FAIL);
	}

	/* Get the data */
	ioctl_data.cmd = sub_cmd2;
	ioctl_data.buf = (caddr_t)*descrp;
	ioctl_data.bufsiz = *sizep;

	if (ioctl(fd, DEVCTL_AP_CONTROL, &ioctl_data) != 0) {
		DPRINTF("ib_do_control_ioctl: ioctl failed: errno:%d\n", errno);
		if (*descrp != NULL) {
			free(*descrp);
			*descrp = NULL;
		}
		rv = (errno == EBUSY) ? CFGA_IB_BUSY_ERR : CFGA_IB_IOCTL_ERR;
	}

	(void) close(fd);
	return (rv);
}


/* ========================================================================== */
/* Entry points */

/*
 * Function:
 *	cfga_change_state
 * Input:
 *	state_change_cmd - Argument to the cfgadm -c command
 *	ap_id		- The attachment point of an IB fabric
 *	options		- State Change command options passed by the cfgadm(1M)
 *	confp		- Whether this command requires confirmation?
 *	msgp		- cfgadm error message for this plugin
 *	errstring	- This contains error msg if command fails
 *	flags		- Cfgadm(1m) flags
 * Output:
 *	NONE
 * Returns:
 *	If the command succeeded perform the cfgadm -c <cmd>;
 *	otherwise emit an error
 * Description:
 *	Do cfgadm -c <cmd>
 */
/*ARGSUSED*/
cfga_err_t
cfga_change_state(cfga_cmd_t state_change_cmd, const char *ap_id,
    const char *options, struct cfga_confirm *confp, struct cfga_msg *msgp,
    char **errstring, cfga_flags_t flags)
{
	int		ret;
	char		*devpath;
	nvlist_t	*nvl = NULL;
	boolean_t	static_ap_id = B_TRUE;
	ap_rstate_t	rstate;
	ap_ostate_t	ostate;
	devctl_hdl_t	hdl = NULL;
	cfga_ib_ret_t	rv = CFGA_IB_OK;

	if ((rv = ib_verify_params(ap_id, options, errstring)) != CFGA_IB_OK) {
		(void) cfga_help(msgp, options, flags);
		return (ib_err_msg(errstring, CFGA_IB_INVAL_APID_ERR,
		    ap_id, errno));
	}

	/*
	 * All subcommands which can change state of device require
	 * root privileges.
	 */
	if (geteuid() != 0) {
		return (ib_err_msg(errstring, CFGA_IB_PRIV_ERR, ap_id, errno));
	}

	if (strstr((char *)ap_id, IB_FABRIC_APID_STR) == NULL)
		static_ap_id = B_FALSE;

	if ((rv = ib_setup_for_devctl_cmd((char *)ap_id, static_ap_id,
	    &hdl, &nvl)) != CFGA_IB_OK) {
		ib_cleanup_after_devctl_cmd(hdl, nvl);
		return (ib_err_msg(errstring, rv, ap_id, errno));
	}

	switch (state_change_cmd) {
	case CFGA_CMD_CONFIGURE:
		rv = ib_device_connected(hdl, nvl, &ostate);
		if (rv != CFGA_IB_ALREADY_CONNECTED) {
			ret = (rv != CFGA_IB_NOT_CONNECTED) ?
			    CFGA_IB_CONFIG_OP_ERR : rv;
			ib_cleanup_after_devctl_cmd(hdl, nvl);
			return (ib_err_msg(errstring, ret, ap_id, errno));
		}

		if (rv == CFGA_IB_ALREADY_CONNECTED) {
			/*
			 * special case handling for
			 * SLM based cfgadm disconnects
			 */
			if (ostate == AP_OSTATE_CONFIGURED) {
				ib_cleanup_after_devctl_cmd(hdl, nvl);
				return (ib_err_msg(errstring,
				    CFGA_IB_ALREADY_CONFIGURED, ap_id,
				    errno));
			}
		}


		rv = CFGA_IB_OK;	/* Other status don't matter */

		if (devctl_ap_configure(hdl, nvl) != 0) {
			DPRINTF("cfga_change_state: devctl_ap_configure "
			    "failed. errno: %d\n", errno);
			rv = CFGA_IB_CONFIG_OP_ERR;
			break;
		}

		devpath = ib_get_devicepath(ap_id);
		if (devpath == NULL) {
			int i;

			/*
			 * try for some time as IB hotplug thread
			 * takes a while to create the path
			 * and then eventually give up
			 */
			for (i = 0;
			    i < IB_RETRY_DEVPATH && (devpath == NULL); i++) {
				sleep(IB_MAX_DEVPATH_DELAY);
				devpath = ib_get_devicepath(ap_id);
			}

			if (devpath == NULL) {
				DPRINTF("cfga_change_state: get device "
				    "path failed i = %d\n", i);
				rv = CFGA_IB_CONFIG_OP_ERR;
				break;
			}
		}
		S_FREE(devpath);
		break;

	case CFGA_CMD_UNCONFIGURE:
		if ((rv = ib_device_connected(hdl, nvl, &ostate)) !=
		    CFGA_IB_ALREADY_CONNECTED) {
			ib_cleanup_after_devctl_cmd(hdl, nvl);
			if (rv == CFGA_IB_DEVCTL_ERR)
				rv = CFGA_IB_INVALID_OP_ERR;
			return (ib_err_msg(errstring, rv, ap_id, errno));
		}

		/* check if it is already unconfigured */
		if ((rv = ib_device_configured(hdl, nvl, &rstate)) ==
		    CFGA_IB_NOT_CONFIGURED) {
			ib_cleanup_after_devctl_cmd(hdl, nvl);
			return (ib_err_msg(errstring, rv, ap_id, errno));
		}

		rv = CFGA_IB_OK;	/* Other statuses don't matter */

		if (!ib_confirm(confp, IB_CONFIRM1)) {
			ib_cleanup_after_devctl_cmd(hdl, nvl);
			return (CFGA_NACK);
		}

		devpath = ib_get_devicepath(ap_id);
		if (devpath == NULL) {
			DPRINTF("cfga_change_state: get device path failed\n");
			rv = CFGA_IB_UNCONFIG_OP_ERR;
			break;
		}

		if ((rv = ib_rcm_offline(ap_id, errstring, devpath, flags)) !=
		    CFGA_IB_OK) {
			S_FREE(devpath);
			break;
		}

		ret = devctl_ap_unconfigure(hdl, nvl);
		if (ret != 0) {
			DPRINTF("cfga_change_state: devctl_ap_unconfigure "
			    "failed with errno: %d\n", errno);
			rv = CFGA_IB_UNCONFIG_OP_ERR;
			if (errno == EBUSY) {
				rv = CFGA_IB_BUSY_ERR;
			}
			(void) ib_rcm_online(ap_id, errstring, devpath, flags);

		} else {
			(void) ib_rcm_remove(ap_id, errstring, devpath, flags);
		}

		S_FREE(devpath);
		break;

	case CFGA_CMD_LOAD:
	case CFGA_CMD_UNLOAD:
	case CFGA_CMD_CONNECT:
	case CFGA_CMD_DISCONNECT:
		(void) cfga_help(msgp, options, flags);
		rv = CFGA_IB_OPNOTSUPP;
		break;

	case CFGA_CMD_NONE:
	default:
		(void) cfga_help(msgp, options, flags);
		rv = CFGA_IB_INTERNAL_ERR;
	}

	ib_cleanup_after_devctl_cmd(hdl, nvl);
	return (ib_err_msg(errstring, rv, ap_id, errno));
}


/*
 * Function:
 *	cfga_private_func
 * Input:
 *	func		- The private function (passed w/ -x option)
 *	ap_id		- The attachment point of an IB fabric
 *	options		- Private function command options passed
 *				by the cfgadm(1M)
 *	confp		- Whether this command requires confirmation?
 *	msgp		- cfgadm error message for this plugin
 *	errstring	- This contains error msg if command fails
 *	flags		- Cfgadm(1m) flags
 * Output:
 *	NONE
 * Returns:
 *	If the command succeeded perform the 'cfgadm -x <func>'; otherwise
 *	return failure.
 * Description:
 *	Do cfgadm -x <func>
 */
/*ARGSUSED*/
cfga_err_t
cfga_private_func(const char *func, const char *ap_id, const char *options,
    struct cfga_confirm *confp, struct cfga_msg *msgp, char **errstring,
    cfga_flags_t flags)
{
	int		len, ret, count = 0;
	char		*clnt_name = NULL, *alt_hca = NULL;
	char		*clnt_apid = NULL, *clnt_devpath = NULL;
	char		*name, *msg = NULL;
	char		*fab_apid = strstr((char *)ap_id, IBNEX_FABRIC);
	size_t		info_len = 0;
	uchar_t		*info = NULL;
	nvlist_t	*nvl;
	nvpair_t	*nvp = NULL;
	ap_rstate_t	rstate;
	devctl_hdl_t	hdl = NULL;
	cfga_ib_ret_t	rv;

	if ((rv = ib_verify_params(ap_id, NULL, errstring)) != CFGA_IB_OK) {
		DPRINTF("cfga_private_func: ib_verify_params "
		    "failed with rv: %d\n", rv);
		return (ib_err_msg(errstring, rv, ap_id, errno));
	}

	if (func == NULL) {
		DPRINTF("cfga_private_func: func is NULL\n");
		return (ib_err_msg(errstring, CFGA_IB_INVAL_ARG_ERR, ap_id,
		    errno));
	}

	/*
	 * check first if IB static ap_id is "configured" for use
	 */
	if (fab_apid != NULL) {
		if ((rv = ib_setup_for_devctl_cmd(fab_apid, B_TRUE, &hdl,
		    &nvl)) != CFGA_IB_OK) {
			ib_cleanup_after_devctl_cmd(hdl, nvl);
			return (ib_err_msg(errstring, rv, ap_id, errno));
		}
		if ((rv = ib_device_configured(hdl, nvl, &rstate)) ==
		    CFGA_IB_NOT_CONFIGURED) {
			return (ib_err_msg(errstring, rv, ap_id, errno));
		}
		ib_cleanup_after_devctl_cmd(hdl, nvl);
	}

	rv = CFGA_IB_OK;
	DPRINTF("cfga_private_func: func is %s\n", func);
	if (strcmp(func, IB_LIST_HCA_CLIENTS) == 0) {	/* -x list_clients */

		/* only supported on HCA ap_ids */
		if (fab_apid != NULL) {
			DPRINTF("cfga_private_func: fabric apid supplied\n");
			return (ib_err_msg(errstring, CFGA_IB_INVALID_OP_ERR,
			    ap_id, errno));
		}

		if ((msg = (char *)calloc(256, 1)) == NULL) {
			DPRINTF("cfga_private_func: malloc for msg failed. "
			    "errno: %d\n", errno);
			return (ib_err_msg(errstring, CFGA_IB_ALLOC_FAIL,
			    ap_id, errno));
		}

		if ((rv = ib_do_control_ioctl((char *)ap_id, IBNEX_HCA_LIST_SZ,
		    IBNEX_HCA_LIST_INFO, 0, (void **)&info, &info_len)) != 0) {
			DPRINTF("cfga_private_func: "
			    "ib_do_control_ioctl list failed :%d\n", rv);
			S_FREE(msg);
			return (ib_err_msg(errstring, CFGA_IB_HCA_LIST_ERR,
			    ap_id, errno));
		}

		if (nvlist_unpack((char *)info, info_len, &nvl, 0)) {
			DPRINTF("cfga_private_func: "
			    "nvlist_unpack 2 failed %p\n", info);
			S_FREE(info);
			S_FREE(msg);
			return (ib_err_msg(errstring, CFGA_IB_NVLIST_ERR, ap_id,
			    errno));
		}

		(void) snprintf(msg, 256, "Ap_Id\t\t\t       IB Client\t\t "
		    "Alternate HCA\n");
		cfga_msg(msgp, msg);

		/* Walk the NVPAIR data */
		while (nvp = nvlist_next_nvpair(nvl, nvp)) {
			name = nvpair_name(nvp);
			if (strcmp(name, "Client") == 0) {
				(void) nvpair_value_string(nvp, &clnt_name);
				++count;
			} else if (strcmp(name, "Alt_HCA") == 0) {
				(void) nvpair_value_string(nvp, &alt_hca);
				++count;
			} else if (strcmp(name, "ApID") == 0) {
				(void) nvpair_value_string(nvp, &clnt_apid);
				++count;
			}

			/* check at the end; print message per client found */
			if (count == 3) {
				count = 0;
				(void) snprintf(msg, 256, "%-30s %-25s %s\n",
				    clnt_apid, clnt_name, alt_hca);
				cfga_msg(msgp, msg);
			}
		} /* end of while */

		S_FREE(info);
		S_FREE(msg);
		nvlist_free(nvl);

	/* -x unconfig_clients */
	} else if (strcmp(func, IB_UNCONFIG_HCA_CLIENTS) == 0) {
		/*
		 * -x unconfig_clients changes state by calling into RCM.
		 * It needs root privileges.
		 */
		if (geteuid() != 0) {
			return (ib_err_msg(errstring, CFGA_IB_PRIV_ERR, ap_id,
			    errno));
		}

		/* only supported on HCA ap_ids */
		if (fab_apid != NULL) {
			DPRINTF("cfga_private_func: fabric apid supplied\n");
			return (ib_err_msg(errstring, CFGA_IB_INVALID_OP_ERR,
			    ap_id, errno));
		}

		/*
		 * Check w/ user if it is ok to do this operation
		 * If the user fails to confirm, bailout
		 */
		if (!ib_confirm(confp, IB_CONFIRM3))
			return (CFGA_NACK);

		/* Get device-paths of all the IOC/Port/Pseudo devices */
		rv = ib_do_control_ioctl((char *)ap_id, IBNEX_UNCFG_CLNTS_SZ,
		    IBNEX_UNCFG_CLNTS_INFO, 0, (void **)&info, &info_len);
		if (rv != 0) {
			DPRINTF("cfga_private_func: ib_do_control_ioctl "
			    "failed :%d\n", rv);
			return (ib_err_msg(errstring, CFGA_IB_HCA_UNCONFIG_ERR,
			    ap_id, errno));
		}

		if (nvlist_unpack((char *)info, info_len, &nvl, 0)) {
			DPRINTF("cfga_private_func: nvlist_unpack failed %p\n",
			    info);
			S_FREE(info);
			return (ib_err_msg(errstring, CFGA_IB_NVLIST_ERR, ap_id,
			    errno));
		}

		ret = 0;

		/* Call RCM Offline on all device paths */
		while (nvp = nvlist_next_nvpair(nvl, nvp)) {
			name = nvpair_name(nvp);
			if (strcmp(name, "devpath") == 0) {
				(void) nvpair_value_string(nvp, &clnt_devpath);
				++count;
			} else if (strcmp(name, "ApID") == 0) {
				(void) nvpair_value_string(nvp, &clnt_apid);
				++count;
			}

			/* handle the client unconfigure now */
			if (count == 2) {
				count = 0;	/* reset count */

				DPRINTF("cfga_private_func: client apid = %s, "
				    "DevPath = %s\n", clnt_apid, clnt_devpath);
				if ((rv = ib_setup_for_devctl_cmd(clnt_apid,
				    B_TRUE, &hdl, &nvl)) != CFGA_IB_OK) {
					ib_cleanup_after_devctl_cmd(hdl, nvl);
					return (ib_err_msg(errstring, rv,
					    clnt_apid, errno));
				}

				if ((rv = ib_device_configured(hdl, nvl,
				    &rstate)) == CFGA_IB_NOT_CONFIGURED)
					continue;

				if ((rv = ib_rcm_offline(clnt_apid, errstring,
				    clnt_devpath, flags)) != CFGA_IB_OK) {
					DPRINTF("cfga_private_func: client rcm "
					    "offline failed for %s, with %d\n",
					    clnt_devpath, rv);
					ret = rv;
					continue;
				}

				if (devctl_ap_unconfigure(hdl, nvl) != 0) {
					DPRINTF("cfga_private_func: client "
					    "unconfigure failed: errno %d\n",
					    errno);
					ret = CFGA_IB_UNCONFIG_OP_ERR;
					if (errno == EBUSY)
						ret = CFGA_IB_BUSY_ERR;
					(void) ib_rcm_online(clnt_apid,
					    errstring, clnt_devpath, flags);
					continue;
				} else {
					(void) ib_rcm_remove(clnt_apid,
					    errstring, clnt_devpath, flags);
				}
				ib_cleanup_after_devctl_cmd(hdl, nvl);

			} /* end of if count == 2 */

		} /* end of while */

		S_FREE(info);
		nvlist_free(nvl);
		if (ret) {
			DPRINTF("cfga_private_func: unconfig_clients of %s "
			    "failed with %d\n", ap_id, ret);
			return (ib_err_msg(errstring, CFGA_IB_UCFG_CLNTS_ERR,
			    ap_id, errno));
		}

	/* -x update_pkey_tbls */
	} else if (strcmp(func, IB_UPDATE_PKEY_TBLS) == 0) {
		/*
		 * Check for root privileges.
		 */
		if (geteuid() != 0) {
			return (ib_err_msg(errstring, CFGA_IB_PRIV_ERR, ap_id,
			    errno));
		}

		/* CHECK: Only supported on fabric ap_ids */
		if (fab_apid == NULL || strcmp(fab_apid, IBNEX_FABRIC) != 0) {
			DPRINTF("cfga_private_func: fabric apid needed\n");
			return (ib_err_msg(errstring, CFGA_IB_INVALID_OP_ERR,
			    ap_id, errno));
		}

		/* Check w/ user if it is ok to do this operation */
		len = strlen(IB_CONFIRM4) + 10;
		if ((msg = (char *)calloc(len, 1)) != NULL) {
			(void) snprintf(msg, len, "%s\nContinue", IB_CONFIRM4);
		}

		/* If the user fails to confirm, return */
		if (!ib_confirm(confp, msg)) {
			free(msg);
			return (CFGA_NACK);
		}
		free(msg);

		/* Update P_Key tables for all ports of all HCAs */
		rv = ib_do_control_ioctl((char *)ap_id, IBNEX_UPDATE_PKEY_TBLS,
		    0, 0, 0, &info_len);

		if (rv != 0) {
			DPRINTF("cfga_private_func: ib_do_control_ioctl "
			    "failed :%d\n", rv);
			return (ib_err_msg(errstring, CFGA_IB_UPD_PKEY_TBLS_ERR,
			    ap_id, errno));
		}

	/* -x [add_service|delete_service] */
	} else if ((strncmp(func, IB_ADD_SERVICE, 12) == 0) ||
	    (strncmp(func, IB_DELETE_SERVICE, 15) == 0)) {
		char			*subopts, *val;
		uint8_t			cmd;

		/* check: Only supported on fabric ap_ids */
		if (fab_apid == NULL || strcmp(fab_apid, IBNEX_FABRIC) != 0) {
			DPRINTF("cfga_private_func: fabric apid needed\n");
			return (ib_err_msg(errstring, CFGA_IB_INVALID_OP_ERR,
			    ap_id, errno));
		}

		/* Check for root privileges. */
		if (geteuid() != 0) {
			return (ib_err_msg(errstring, CFGA_IB_PRIV_ERR, ap_id,
			    errno));
		}

		/* return error if no options are specified */
		subopts = (char *)options;
		if (subopts == (char *)NULL) {
			DPRINTF("cfga_private_func: no sub-options\n");
			(void) cfga_help(msgp, options, flags);
			return (ib_err_msg(errstring, CFGA_IB_INVAL_ARG_ERR,
			    ap_id, errno));
		}

		/* parse options specified */
		while (*subopts != '\0') {
			switch (getsubopt(&subopts, ib_service_subopts, &val)) {
			case 0: /* comm */
				if (val == NULL) {
					(void) cfga_help(msgp, options, flags);
					S_FREE(service_name);
					return (ib_err_msg(errstring,
					    CFGA_IB_INVAL_ARG_ERR,
					    ap_id, errno));
				} else {
					comm_name = strdup(val);
					if (comm_name == NULL) {
						DPRINTF("comm sub-opt invalid "
						    "arg\n");
						S_FREE(service_name);
						return (ib_err_msg(errstring,
						    CFGA_IB_COMM_INVAL_ERR,
						    ap_id, errno));
					}
				}
				break;

			case 1: /* service */
				if (val == NULL) {
					(void) cfga_help(msgp, options, flags);
					S_FREE(comm_name);
					return (ib_err_msg(errstring,
					    CFGA_IB_INVAL_ARG_ERR,
					    ap_id, errno));
				} else {
					/* service can be upto 4 long */
					if (strlen(val) == 0 ||
					    strlen(val) > 4) {
						DPRINTF("comm sub-opt invalid "
						    "service passed\n");
						S_FREE(comm_name);
						return (ib_err_msg(errstring,
						    CFGA_IB_SVC_LEN_ERR,
						    ap_id, errno));
					}
					service_name = strdup(val);
					if (service_name == NULL) {
						DPRINTF("comm sub-opt "
						    "internal error\n");
						S_FREE(comm_name);
						return (ib_err_msg(errstring,
						    CFGA_IB_SVC_INVAL_ERR,
						    ap_id, errno));
					}
				}
				break;

			default:
				(void) cfga_help(msgp, options, flags);
				S_FREE(comm_name);
				S_FREE(service_name);
				return (ib_err_msg(errstring,
				    CFGA_IB_INVAL_ARG_ERR, ap_id, errno));
			}
		}

		/* figure out the "operation" */
		if (strncasecmp(func, IB_ADD_SERVICE, 11) == 0)
			cmd = IBCONF_ADD_ENTRY;
		else if (strncasecmp(func, IB_DELETE_SERVICE, 14) == 0)
			cmd = IBCONF_DELETE_ENTRY;
		DPRINTF("Service = %s, Comm = %s, Operation = %s\n",
		    service_name, comm_name, func);

		if (strncasecmp(comm_name, IBNEX_PORT_STR, 4) == 0)
			service_type = IB_PORT_SERVICE;
		else if (strncasecmp(comm_name, IBNEX_VPPA_STR, 4) == 0)
			service_type = IB_VPPA_SERVICE;
		else if (strncasecmp(comm_name, IBNEX_HCASVC_STR, 4) == 0)
			service_type = IB_HCASVC_SERVICE;
		else {
			(void) cfga_help(msgp, options, flags);
			S_FREE(comm_name);
			S_FREE(service_name);
			return (ib_err_msg(errstring, CFGA_IB_INVAL_ARG_ERR,
			    ap_id, errno));
		}

		/* do the add/delete entry to the service */
		if (cmd == IBCONF_ADD_ENTRY) {
			if ((rv = ib_add_service(errstring)) != CFGA_IB_OK)
				DPRINTF("cfga_private_func: add failed\n");
		} else if (cmd == IBCONF_DELETE_ENTRY) {
			if ((rv = ib_delete_service(errstring)) != CFGA_IB_OK)
				DPRINTF("cfga_private_func: delete failed\n");
		}

		S_FREE(comm_name);
		S_FREE(service_name);
		return (ib_err_msg(errstring, rv, ap_id, errno));

	} else if (strncmp(func, IB_LIST_SERVICES, 13) == 0) {

		/* check: Only supported on fabric ap_ids */
		if (fab_apid == NULL || strcmp(fab_apid, IBNEX_FABRIC) != 0) {
			DPRINTF("cfga_private_func: fabric apid needed\n");
			return (ib_err_msg(errstring, CFGA_IB_INVALID_OP_ERR,
			    ap_id, errno));
		}

		/* do the list services */
		rv = ib_list_services(msgp, errstring);
		if (rv != CFGA_IB_OK) {
			DPRINTF("cfga_private_func: ib_list_services failed\n");
			return (ib_err_msg(errstring, rv, ap_id, errno));
		}

	/* -x update_ioc_conf */
	} else if (strncmp(func, IB_UPDATE_IOC_CONF, 17) == 0) {
		uint_t misc_arg;

		/* Supported only with root privilege */
		if (geteuid() != 0) {
			return (ib_err_msg(errstring, CFGA_IB_PRIV_ERR, ap_id,
			    errno));
		}

		/*
		 * check: Only supported on fabric ap_id or IOC APID
		 * IOC APID does not have any commas in it.
		 */
		if (fab_apid == NULL ||
		    (fab_apid != NULL && strstr(fab_apid, ",") != NULL)) {
			DPRINTF("cfga_private_func: fabric/IOC apid needed\n");
			return (ib_err_msg(errstring, CFGA_IB_INVALID_OP_ERR,
			    ap_id, errno));
		}

		/* Check w/ user if it is ok to do this operation */
		len = strlen(IB_CONFIRM5) + 10;
		if ((msg = (char *)calloc(len, 1)) != NULL) {
			(void) snprintf(msg, len, "%s\nContinue", IB_CONFIRM5);
		}

		/* If the user fails to confirm, return */
		if (!ib_confirm(confp, msg)) {
			free(msg);
			return (CFGA_NACK);
		}
		free(msg);

		misc_arg = (strcmp(fab_apid, IBNEX_FABRIC) == 0) ?
		    IBNEX_BASE_APID : IBNEX_DYN_APID;

		/* Reprobe and update IOC(s) configuration */
		rv = ib_do_control_ioctl((char *)ap_id, IBNEX_UPDATE_IOC_CONF,
		    0, misc_arg, 0, &info_len);

		if (rv != 0) {
			DPRINTF("cfga_private_func: ib_do_control_ioctl "
			    "failed :%d\n", rv);
			return (ib_err_msg(errstring, CFGA_IB_DEVCTL_ERR,
			    ap_id, errno));
		}
	} else {
		DPRINTF("cfga_private_func: unrecognized command.\n");
		(void) cfga_help(msgp, options, flags);
		errno = EINVAL;
		return (CFGA_INVAL);
	}

	return (ib_err_msg(errstring, rv, ap_id, errno));
}


/*
 * Function:
 *	cfga_test
 * Input:
 *	ap_id		- The attachment point of an IB fabric
 *	options		- Test command options passed by the cfgadm(1M)
 *	msgp		- cfgadm error message for this plugin
 *	errstring	- This contains error msg if command fails
 *	flags		- Cfgadm(1m) flags
 * Output:
 *	NONE
 * Returns:
 *	CFGA_OPNOTSUPP
 * Description:
 *	Do "cfgadm -t"
 */
/*ARGSUSED*/
cfga_err_t
cfga_test(const char *ap_id, const char *options, struct cfga_msg *msgp,
    char **errstring, cfga_flags_t flags)
{
	(void) cfga_help(msgp, options, flags);
	return (CFGA_OPNOTSUPP);
}


/*
 * Function:
 *	ib_fill_static_apids
 * Input:
 *	ap_id		- The static attachment point of an IB device
 *	clp		- The returned "list" information array
 * Output:
 *	NONE
 * Returns:
 *	Fills up the "list" information array for the static attachment point
 * Description:
 *	IB fabric supports two types of static attachment points.
 *	One is fabric and other is for the HCAs. This fills up
 *	"cfga_list_data_t" for static attachment points.
 */
static cfga_ib_ret_t
ib_fill_static_apids(char *ap_id, cfga_list_data_t *clp)
{
	int	rv, l_err;
	char	*ap_id_log = NULL;

	/* Get /dev/cfg path to corresponding to the physical ap_id */
	/* Remember ap_id_log must be freed */
	if (ib_physpath_to_devlink(ap_id, &ap_id_log,
	    &l_err) != ICFGA_OK) {
		DPRINTF("ib_fill_static_apids: "
		    "ib_physpath_to_devlink failed\n");
		return (CFGA_IB_DEVLINK_ERR);
	}
	assert(ap_id_log != NULL);

	/* Get logical ap-id corresponding to the physical */
	if (strstr(ap_id_log, CFGA_DEV_DIR) == NULL) {
		DPRINTF("ib_fill_static_apids: devlink doesn't contain "
		    "/dev/cfg\n");
		free(ap_id_log);
		return (CFGA_IB_DEVLINK_ERR);
	}

	clp->ap_cond = CFGA_COND_OK;
	clp->ap_r_state = CFGA_STAT_CONNECTED;
	clp->ap_o_state = CFGA_STAT_CONFIGURED;
	clp->ap_class[0] = '\0';	/* Filled by libcfgadm */
	clp->ap_busy = 0;
	clp->ap_status_time = (time_t)-1;
	(void) snprintf(clp->ap_log_id, sizeof (clp->ap_log_id), "%s",
	    /* Strip off /dev/cfg/ */ ap_id_log + strlen(CFGA_DEV_DIR) + 1);
	(void) strlcpy(clp->ap_phys_id, ap_id, sizeof (clp->ap_phys_id));

	/* Static IB apid */
	if (strstr((char *)ap_id, IB_FABRIC_APID_STR) != NULL)  {
		(void) strlcpy(clp->ap_type, IB_FABRIC_TYPE,
		    sizeof (clp->ap_type));	/* Fill in type */
		(void) strlcpy(clp->ap_info, IB_FABRIC_INFO,
		    sizeof (clp->ap_info));

	} else {	/* Static HCA apid */
		size_t	size = 0;
		uchar_t	*data = NULL;

		(void) strlcpy(clp->ap_type, IB_HCA_TYPE,
		    sizeof (clp->ap_type));	/* Fill in type */

		rv = ib_do_control_ioctl(ap_id, IBNEX_HCA_VERBOSE_SZ,
		    IBNEX_HCA_VERBOSE_INFO, 0, (void **)&data, &size);
		if (rv != 0) {
			DPRINTF("ib_fill_static_apids: ib_do_control_ioctl "
			    "failed :%d\n", rv);
			free(ap_id_log);
			S_FREE(data);
			return (CFGA_IB_IOCTL_ERR);
		}

		(void) strlcpy(clp->ap_info, (char *)data,
		    sizeof (clp->ap_info));
		S_FREE(data);
	}
	free(ap_id_log);
	return (CFGA_IB_OK);
}


/*
 * Function:
 *	cfga_list_ext
 * Input:
 *	ap_id		- The attachment point of an IB fabric
 *	ap_id_list	- The returned "list" information array
 *	nlistp		- Number of elements in the "list" information array
 *	options		- List command options passed by the cfgadm(1M)
 *	listopts	- "-s" specific options
 *	errstring	- This contains error msg if command fails
 *	flags		- Cfgadm(1m) flags
 * Output:
 *	NONE
 * Returns:
 *	If the command succeeded, cfgadm -l output otherwise an error
 * Description:
 *	Do cfgadm -l
 */
/*ARGSUSED*/
cfga_err_t
cfga_list_ext(const char *ap_id, cfga_list_data_t **ap_id_list, int *nlistp,
    const char *options, const char *listopts, char **errstring,
    cfga_flags_t flags)
{
	int			expand = 0;
	int			i, index, count;
	int			show_dynamic = 0;
	size_t			num_devices = 0;
	size_t			num_hcas = 0;
	size_t			snap_size = 0;
	uchar_t			*snap_data = NULL;
	nvpair_t		*nvp = NULL;	/* for lint purposes */
	nvlist_t		*nvl = NULL;
	boolean_t		apid_matched = B_FALSE;	/* for valid ap_id */
	cfga_ib_ret_t		rv = CFGA_IB_OK;
	cfga_list_data_t	*clp = NULL;

	if ((rv = ib_verify_params(ap_id, options, errstring)) != CFGA_IB_OK) {
		(void) cfga_help(NULL, options, flags);
		return (ib_err_msg(errstring, rv, ap_id, errno));
	}

	/* make sure we have a valid ap_id_list */
	if (ap_id_list == NULL || nlistp == NULL) {
		DPRINTF("cfga_list_ext: list = NULL or nlistp = NULL\n");
		(void) cfga_help(NULL, options, flags);
		return (ib_err_msg(errstring, CFGA_IB_INVAL_ARG_ERR,
		    ap_id, errno));
	}

	DPRINTF("cfga_list_ext: ap_id = %s\n", ap_id);

	if ((flags & CFGA_FLAG_LIST_ALL) == CFGA_FLAG_LIST_ALL) {
		expand = 1;		/* -a flag passed */
	}

	if (GET_DYN(ap_id) != NULL) {
		show_dynamic = 1;
	}

	if ((expand == 1) &&	/* -a option passed */
	    (strstr((char *)ap_id, IB_FABRIC_APID_STR) != NULL)) {
		/*
		 * Figure out how many IOC/Port/Pseudo
		 * devices exist in the system?
		 */
		if ((rv = ib_do_control_ioctl((char *)ap_id,
		    IBNEX_NUM_DEVICE_NODES, 0, 0, 0, &num_devices)) !=
		    CFGA_IB_OK) {
			DPRINTF("cfga_list_ext: ib_do_control_ioctl "
			    "IBNEX_NUM_DEVICE_NODES failed :%d\n", rv);
			if (errno == ENOENT)
				return (CFGA_APID_NOEXIST);
			return (ib_err_msg(errstring, rv, ap_id, errno));
		}

		DPRINTF("cfga_list_ext: num_devices = %d\n", num_devices);
	}

	/* Figure out how many HCA nodes exist in the system. */
	if ((rv = ib_do_control_ioctl((char *)ap_id, IBNEX_NUM_HCA_NODES, 0, 0,
	    0, &num_hcas)) != CFGA_IB_OK) {
		DPRINTF("cfga_list_ext: ib_do_control_ioctl "
		    "IBNEX_NUM_HCA_NODES failed :%d\n", rv);
		if (errno == ENOENT)
			return (CFGA_APID_NOEXIST);
		return (ib_err_msg(errstring, rv, ap_id, errno));
	}
	DPRINTF("cfga_list_ext: num_hcas = %d\n", num_hcas);

	/*
	 * No HCAs or IOC/VPPA/Port/HCA_SVC/Pseudo devices seen (non-IB system)
	 */
	if (!(num_hcas || num_devices)) {
		DPRINTF("cfga_list_ext: no IB devices found\n");
		return (CFGA_APID_NOEXIST);
	}

	/*
	 * *nlistp contains to how many APIDs to show w/ cfgadm -l.
	 * If ap_id is "fabric" then
	 * 	*nlistp is all Dynamic Apids + One more for "fabric"
	 * If ap_id is "HCA" ap_id then
	 *	*nlistp is 1
	 * Note that each HCA is a static APID, so nlistp will be 1 always
	 * and this function will be called N times for each of the N HCAs
	 * in the host.
	 */
	if (strstr((char *)ap_id, IB_FABRIC_APID_STR) != NULL) {
		*nlistp = num_devices + 1;

	} else {
		/* Assume it as a HCA ap_id */
		*nlistp = 1;
	}

	/* Allocate storage for passing "list" info back */
	if ((*ap_id_list = (cfga_list_data_t *)calloc(*nlistp,
	    sizeof (cfga_list_data_t))) == NULL) {
		DPRINTF("cfga_list_ext: malloc for cfga_list_data_t failed. "
		    "errno: %d\n", errno);
		return (ib_err_msg(errstring, CFGA_IB_ALLOC_FAIL,
		    ap_id, errno));
	}

	/*
	 * Only static ap_id is ib_fabric:
	 * If -a options isn't specified then only show the static ap_id.
	 */
	if (!show_dynamic) {
		clp = &(*ap_id_list[0]);

		if ((rv = ib_fill_static_apids((char *)ap_id, clp)) !=
		    CFGA_IB_OK) {
			S_FREE(*ap_id_list);
			return (ib_err_msg(errstring, rv, ap_id, errno));
		}
		apid_matched = B_TRUE;
	}

	/*
	 * No -a specified
	 * No HCAs or IOC/VPPA/HCA_SVC/Port/Pseudo devices seen (non-IB system)
	 */
	if (!expand || (!num_hcas && !num_devices)) {
		if (!show_dynamic)
			return (CFGA_OK);
	}

	if (strstr((char *)ap_id, IB_FABRIC_APID_STR) != NULL) {
		rv = ib_do_control_ioctl((char *)ap_id, IBNEX_SNAPSHOT_SIZE,
		    IBNEX_GET_SNAPSHOT, IBNEX_DONOT_PROBE_FLAG,
		    (void **)&snap_data, &snap_size);
		if (rv != 0) {
			DPRINTF("cfga_list_ext: ib_do_control_ioctl "
			    "failed :%d\n", rv);
			S_FREE(*ap_id_list);
			S_FREE(snap_data);
			return (ib_err_msg(errstring, rv, ap_id, errno));
		}

		if (nvlist_unpack((char *)snap_data, snap_size, &nvl, 0)) {
			DPRINTF("cfga_list_ext: nvlist_unpack 1 failed %p\n",
			    snap_data);
			S_FREE(*ap_id_list);
			S_FREE(snap_data);
			return (ib_err_msg(errstring, CFGA_IB_NVLIST_ERR,
			    ap_id, errno));
		}

		/*
		 * In kernel a nvlist is build per ap_id which contains
		 * information that is displayed using cfgadm -l.
		 * For IB devices only these 6 items are shown:
		 *	ap_id, type, occupant, receptacle, condition and info
		 *
		 * In addition, one could specify a dynamic ap_id from
		 * command-line. Then cfgadm -l should show only that
		 * ap_id and skip rest.
		 */
		index = 1; count = 0;
		while (nvp = nvlist_next_nvpair(nvl, nvp)) {
			int32_t intval = 0;
			int32_t node_type;
			char	*info;
			char	*nv_apid;
			char	*name = nvpair_name(nvp);

			/* start of with next device */
			if (count == IB_NUM_NVPAIRS) {
				count = 0;
				++index;
			}

			/*
			 * Check if the index doesn't go beyond the
			 * device number. If it goes, stop the loop
			 * here not to cause the heap corruption.
			 */
			if (show_dynamic == 0 && index > num_devices)
				break;

			/* fill up data into "clp" */
			clp =  (show_dynamic != 0) ? &(*ap_id_list[0]) :
			    &(ap_id_list[0][index]);

			/* First nvlist entry is "ap_id" always */
			if (strcmp(name, IBNEX_NODE_APID_NVL) == 0) {
				(void) nvpair_value_string(nvp, &nv_apid);
				DPRINTF("cfga_list_ext: Name = %s, apid = %s\n",
				    name, nv_apid);

				/*
				 * If a dynamic ap_id is specified in the
				 * command-line, skip all entries until
				 * the one needed matches.
				 */
				if (show_dynamic &&
				    strstr(ap_id, nv_apid) == NULL) {
					DPRINTF("cfga_list_ext: NO MATCH\n");

					/*
					 * skip rest of the entries of this
					 * device.
					 */
					for (i = 0; i < IB_NUM_NVPAIRS - 1; i++)
						nvp = nvlist_next_nvpair(nvl,
						    nvp);
					count = 0;	/* reset it */
					continue;
				}

				apid_matched = B_TRUE;

				/* build the physical ap_id */
				if (strstr(ap_id, DYN_SEP) == NULL) {
					(void) snprintf(clp->ap_phys_id,
					    sizeof (clp->ap_phys_id), "%s%s%s",
					    ap_id, DYN_SEP, nv_apid);
				} else {
					(void) snprintf(clp->ap_phys_id,
					    sizeof (clp->ap_phys_id), "%s",
					    ap_id);
				}

				/* ensure that this is a valid apid */
				if (ib_verify_valid_apid(clp->ap_phys_id) !=
				    0) {
					DPRINTF("cfga_list_ext: "
					    "not a valid IB ap_id\n");
					S_FREE(*ap_id_list);
					S_FREE(snap_data);
					nvlist_free(nvl);
					return (ib_err_msg(errstring,
					    CFGA_IB_AP_ERR, ap_id, errno));
				}

				/* build the logical ap_id */
				(void) snprintf(clp->ap_log_id,
				    sizeof (clp->ap_log_id), "ib%s%s",
				    DYN_SEP, nv_apid);
				DPRINTF("cfga_list_ext: ap_pi = %s, ap_li = %s,"
				    "\nap_info = %s\n", clp->ap_phys_id,
				    clp->ap_log_id, clp->ap_info);
				++count;

			} else if (strcmp(name, IBNEX_NODE_INFO_NVL) == 0) {
				(void) nvpair_value_string(nvp, &info);
				DPRINTF("cfga_list_ext: Name = %s, info = %s\n",
				    name, info);
				(void) snprintf(clp->ap_info,
				    sizeof (clp->ap_info), "%s", info);
				++count;

			} else if (strcmp(name, IBNEX_NODE_TYPE_NVL) == 0) {
				(void) nvpair_value_int32(nvp, &node_type);
				if (node_type == IBNEX_PORT_NODE_TYPE) {
					(void) snprintf(clp->ap_type,
					    sizeof (clp->ap_type), "%s",
					    IB_PORT_TYPE);
				} else if (node_type == IBNEX_VPPA_NODE_TYPE) {
					(void) snprintf(clp->ap_type,
					    sizeof (clp->ap_type), "%s",
					    IB_VPPA_TYPE);
				} else if (node_type ==
				    IBNEX_HCASVC_NODE_TYPE) {
					(void) snprintf(clp->ap_type,
					    sizeof (clp->ap_type), "%s",
					    IB_HCASVC_TYPE);
				} else if (node_type == IBNEX_IOC_NODE_TYPE) {
					(void) snprintf(clp->ap_type,
					    sizeof (clp->ap_type), "%s",
					    IB_IOC_TYPE);
				} else if (node_type ==
				    IBNEX_PSEUDO_NODE_TYPE) {
					(void) snprintf(clp->ap_type,
					    sizeof (clp->ap_type), "%s",
					    IB_PSEUDO_TYPE);
				}
				DPRINTF("cfga_list_ext: Name = %s, type = %x\n",
				    name, intval);
				++count;

			} else if (strcmp(name, IBNEX_NODE_RSTATE_NVL) == 0) {
				(void) nvpair_value_int32(nvp, &intval);

				if (intval == AP_RSTATE_EMPTY)
					clp->ap_r_state = CFGA_STAT_EMPTY;
				else if (intval == AP_RSTATE_DISCONNECTED)
					clp->ap_r_state =
					    CFGA_STAT_DISCONNECTED;
				else if (intval == AP_RSTATE_CONNECTED)
					clp->ap_r_state = CFGA_STAT_CONNECTED;
				DPRINTF("cfga_list_ext: Name = %s, "
				    "rstate = %x\n", name, intval);
				++count;

			} else if (strcmp(name, IBNEX_NODE_OSTATE_NVL) == 0) {
				(void) nvpair_value_int32(nvp, &intval);

				if (intval == AP_OSTATE_CONFIGURED)
					clp->ap_o_state = CFGA_STAT_CONFIGURED;
				else if (intval == AP_OSTATE_UNCONFIGURED)
					clp->ap_o_state =
					    CFGA_STAT_UNCONFIGURED;
				DPRINTF("cfga_list_ext: Name = %s, "
				    "ostate = %x\n", name, intval);
				++count;

			} else if (strcmp(name, IBNEX_NODE_COND_NVL) == 0) {
				(void) nvpair_value_int32(nvp, &intval);

				if (intval == AP_COND_OK)
					clp->ap_cond = CFGA_COND_OK;
				else if (intval == AP_COND_FAILING)
					clp->ap_cond = CFGA_COND_FAILING;
				else if (intval == AP_COND_FAILED)
					clp->ap_cond = CFGA_COND_FAILED;
				else if (intval == AP_COND_UNUSABLE)
					clp->ap_cond = CFGA_COND_UNUSABLE;
				else if (intval == AP_COND_UNKNOWN)
					clp->ap_cond = CFGA_COND_UNKNOWN;
				DPRINTF("cfga_list_ext: Name = %s, "
				    "condition = %x\n", name, intval);
				++count;
			}

			clp->ap_class[0] = '\0'; /* Filled by libcfgadm */
			clp->ap_busy = 0;
			clp->ap_status_time = (time_t)-1;
		} /* end of while */
	}

	S_FREE(snap_data);
	nvlist_free(nvl);

	/*
	 * if a cmdline specified ap_id doesn't match the known list of ap_ids
	 * then report an error right away
	 */
	rv = (apid_matched ==  B_TRUE) ? CFGA_IB_OK : CFGA_IB_AP_ERR;
	return (ib_err_msg(errstring, rv, ap_id, errno));
}


/*
 * Function:
 *	cfga_msg
 * Input:
 *	msgp		- cfgadm error message for this plugin
 *	str		- string to be passed on to the message
 * Output:
 *	NONE
 * Returns:
 *	NONE
 * Description:
 *	This routine accepts a variable number of message IDs and
 *	constructs a corresponding error string which is printed
 *	via the message print routine argument.
 */
void
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

	(void) strlcpy(q, str, len + 1);
	(*msgp->message_routine)(msgp->appdata_ptr, q);

	free(q);
}


/*
 * Function:
 *	cfga_help
 * Input:
 *	msgp		- Help message passed on to cfgadm(1M)
 *	options		- Help message options passed on to cfgadm(1M)
 *	flags		- Cfgadm(1m) flags
 * Output:
 *	NONE
 * Returns:
 *	Were we able to print cfgadm help or not for this plugin
 * Description:
 *	Print cfgadm help for this plugin
 */
/* ARGSUSED */
cfga_err_t
cfga_help(struct cfga_msg *msgp, const char *options, cfga_flags_t flags)
{
	DPRINTF("cfga_help:\n");

	if (options) {
		cfga_msg(msgp, dgettext(TEXT_DOMAIN, ib_help[
		    CFGA_IB_HELP_UNKNOWN]));
		cfga_msg(msgp, options);
	}

	/* Print messages array */
	cfga_msg(msgp, dgettext(TEXT_DOMAIN, ib_help[CFGA_IB_HELP_HEADER]));
	cfga_msg(msgp, ib_help[CFGA_IB_HELP_CONFIG]);
	cfga_msg(msgp, ib_help[CFGA_IB_HELP_LIST]);
	cfga_msg(msgp, ib_help[CFGA_IB_HELP_UPD_PKEY]);
	cfga_msg(msgp, ib_help[CFGA_IB_HELP_CONF_FILE1]);
	cfga_msg(msgp, ib_help[CFGA_IB_HELP_CONF_FILE2]);
	cfga_msg(msgp, ib_help[CFGA_IB_HELP_UPD_IOC_CONF]);
	cfga_msg(msgp, ib_help[CFGA_IB_HELP_UNCFG_CLNTS]);

	return (CFGA_OK);
}


/*
 * Function:
 *	ib_confirm
 * Input:
 *	confp		- The "cfga" structure that confirms a cfgadm query
 *	msg		- The message that needs confirmation
 * Output:
 *	None
 * Returns:
 *	If a user entered YES or NO
 * Description:
 *	Queries a user if it is ok to proceed with an operation or not.
 *	Returns user's response.
 */
static int
ib_confirm(struct cfga_confirm *confp, char *msg)
{
	int rval;

	/* check that "confirm" function exists */
	if (confp == NULL || confp->confirm == NULL) {
		return (0);
	}

	/* Call cfgadm provided "confirm" function */
	rval = (*confp->confirm)(confp->appdata_ptr, msg);
	DPRINTF("ib_confirm: %d\n", rval);

	return (rval);
}


/*
 * Function:
 *	ib_get_devicepath
 * Input:
 *	ap_id		- The dynamic attachment point of an IB device
 * Output:
 *	None
 * Returns:
 *	devpath if it exists; otherwise NULL
 * Description:
 *	Returns the devicepath for a dynamic attachment point of an IB device
 */
static char *
ib_get_devicepath(const char *ap_id)
{
	char		*devpath = NULL;
	size_t		size;

	/* Get device path sizes */
	if (ib_do_control_ioctl((char *)ap_id, IBNEX_DEVICE_PATH_SZ,
	    IBNEX_GET_DEVICE_PATH, 0, (void **)&devpath, &size) == CFGA_IB_OK) {
		DPRINTF("ib_get_devicepath: get device path ioctl ok\n");
		return (devpath);

	} else {
		DPRINTF("ib_get_devicepath: get device path ioctl failed\n");
		return ((char *)NULL);
	}
}
