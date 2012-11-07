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


#include "cfga_fp.h"

/*
 * This file contains helper routines for the FP plugin
 */

#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN	"SYS_TEST"
#endif

typedef struct strlist {
	const char *str;
	struct strlist *next;
} strlist_t;

typedef	struct {
	fpcfga_ret_t	fp_err;
	cfga_err_t	cfga_err;
} errcvt_t;

typedef struct {
	fpcfga_cmd_t cmd;
	int type;
	int (*fcn)(const devctl_hdl_t);
} set_state_cmd_t;

typedef struct {
	fpcfga_cmd_t cmd;
	int type;
	int (*state_fcn)(const devctl_hdl_t, uint_t *);
} get_state_cmd_t;

/* defines for nftw() */
#define	NFTW_DEPTH	1
#define	NFTW_CONTINUE	0
#define	NFTW_TERMINATE	1
#define	NFTW_ERROR	-1
#define	MAX_RETRIES	10

/* Function prototypes */
static int do_recurse_dev(const char *path, const struct stat *sbuf,
    int type, struct FTW *ftwp);
static fpcfga_recur_t lookup_dev(const char *lpath, void *arg);
static void msg_common(char **err_msgpp, int append_newline, int l_errno,
    va_list ap);
static void lunlist_free(struct luninfo_list *lunlist);

/* Globals */
struct {
	mutex_t mp;
	void *arg;
	fpcfga_recur_t (*fcn)(const char *lpath, void *arg);
} nftw_arg = {DEFAULTMUTEX};

/*
 * The string table contains most of the strings used by the fp cfgadm plugin.
 * All strings which are to be internationalized must be in this table.
 * Some strings which are not internationalized are also included here.
 * Arguments to messages are NOT internationalized.
 */
msgcvt_t str_tbl[] = {

/*
 * The first element (ERR_UNKNOWN) MUST always be present in the array.
 */
#define	UNKNOWN_ERR_IDX		0	/* Keep the index in sync */


/* msg_code	num_args, I18N	msg_string				*/

/* ERRORS */
{ERR_UNKNOWN,		0, 1,	"unknown error"},
{ERR_OP_FAILED,		0, 1,	"operation failed"},
{ERR_CMD_INVAL,		0, 1,	"invalid command"},
{ERR_NOT_BUSAPID,	0, 1,	"not a FP bus apid"},
{ERR_APID_INVAL,	0, 1,	"invalid FP ap_id"},
{ERR_NOT_BUSOP,		0, 1,	"operation not supported for FC bus"},
{ERR_NOT_DEVOP,		0, 1,	"operation not supported for FC device"},
{ERR_UNAVAILABLE,	0, 1,	"unavailable"},
{ERR_CTRLR_CRIT,	0, 1,	"critical partition controlled by FC HBA"},
{ERR_BUS_GETSTATE,	0, 1,	"failed to get state for FC bus"},
{ERR_BUS_NOTCONNECTED,	0, 1,	"FC bus not connected"},
{ERR_BUS_CONNECTED,	0, 1,	"FC bus not disconnected"},
{ERR_BUS_QUIESCE,	0, 1,	"FC bus quiesce failed"},
{ERR_BUS_UNQUIESCE,	0, 1,	"FC bus unquiesce failed"},
{ERR_BUS_CONFIGURE,	0, 1,	"failed to configure devices on FC bus"},
{ERR_BUS_UNCONFIGURE,	0, 1,	"failed to unconfigure FC bus"},
{ERR_DEV_CONFIGURE,	0, 1,	"failed to configure FC device"},
{ERR_DEV_UNCONFIGURE,	0, 1,	"failed to unconfigure FC device"},
{ERR_FCA_CONFIGURE,	0, 1,	"failed to configure ANY device on FCA port"},
{ERR_FCA_UNCONFIGURE,	0, 1,	"failed to unconfigure ANY device on FCA port"},
{ERR_DEV_REPLACE,	0, 1,	"replace operation failed"},
{ERR_DEV_INSERT,	0, 1,	"insert operation failed"},
{ERR_DEV_GETSTATE,	0, 1,	"failed to get state for FC device"},
{ERR_RESET,		0, 1,	"reset failed"},
{ERR_LIST,		0, 1,	"list operation failed"},
{ERR_SIG_STATE,		0, 1,	"could not restore signal disposition"},
{ERR_MAYBE_BUSY,	0, 1,	"device may be busy"},
{ERR_BUS_DEV_MISMATCH,	0, 1,	"mismatched FC bus and device"},
{ERR_MEM_ALLOC,		0, 1,	"Failed to allocated memory"},
{ERR_DEVCTL_OFFLINE,	0, 1,	"failed to offline device"},
{ERR_UPD_REP,		0, 1,	"Repository update failed"},
{ERR_CONF_OK_UPD_REP,	0, 1,
		"Configuration successful, but Repository update failed"},
{ERR_UNCONF_OK_UPD_REP,	0, 1,
		"Unconfiguration successful, but Repository update failed"},
{ERR_PARTIAL_SUCCESS,	0, 1,
			"Operation partially successful. Some failures seen"},
{ERR_HBA_LOAD_LIBRARY,	0, 1,
			"HBA load library failed"},
{ERR_MATCHING_HBA_PORT,	0, 1,
			"No match HBA port found"},
{ERR_NO_ADAPTER_FOUND,	0, 1,
			"No Fibre Channel adapters found"},

/* Errors with arguments */
{ERRARG_OPT_INVAL,	1, 1,	"invalid option: "},
{ERRARG_HWCMD_INVAL,	1, 1,	"invalid command: "},
{ERRARG_DEVINFO,	1, 1,	"libdevinfo failed on path: "},
{ERRARG_NOT_IN_DEVLIST,	1, 1,	"Device not found in fabric device list: "},
{ERRARG_NOT_IN_DEVINFO,	1, 1,	"Could not find entry in devinfo tree: "},
{ERRARG_DI_GET_PROP,	1, 1,	"Could not get libdevinfo property: "},
{ERRARG_DC_DDEF_ALLOC,	1, 1,	"failed to alloc ddef space: "},
{ERRARG_DC_BYTE_ARRAY,	1, 1,	"failed to add property: "},
{ERRARG_DC_BUS_ACQUIRE,	1, 1,	"failed to acquire bus handle: "},
{ERRARG_BUS_DEV_CREATE,	1, 1,	"failed to create device node: "},
{ERRARG_BUS_DEV_CREATE_UNKNOWN,	1, 1,
	"failed to create device node... Device may be unconfigurable: "},
{ERRARG_DEV_ACQUIRE,	1, 1,	"device acquire operation failed: "},
{ERRARG_DEV_REMOVE,	1, 1,	"remove operation failed: "},

/* Fibre Channel operation Errors */
{ERR_FC,		0, 1,	"FC error"},
{ERR_FC_GET_DEVLIST,	0, 1,	"Failed to get fabric device list"},
{ERR_FC_GET_NEXT_DEV,	0, 1,	"Failed to get next device on device map"},
{ERR_FC_GET_FIRST_DEV,	0, 1,	"Failed to get first device on device map"},
{ERRARG_FC_DEV_MAP_INIT,	1, 1,
	"Failed to initialize device map for: "},
{ERRARG_FC_PROP_LOOKUP_BYTES,	1, 1,	"Failed to get property of "},
{ERRARG_FC_INQUIRY,	1, 1,	"inquiry failed: "},
{ERRARG_FC_REP_LUNS,	1, 1,	"report LUNs failed: "},
{ERRARG_FC_TOPOLOGY,	1, 1,	"failed to get port topology: "},
{ERRARG_PATH_TOO_LONG,	1, 1,	"Path length exceeds max possible: "},
{ERRARG_INVALID_PATH,	1, 1,	"Invalid path: "},
{ERRARG_OPENDIR,	1, 1,	"failure opening directory: "},

/* MPXIO Errors */
{ERRARG_VHCI_GET_PATHLIST,	1, 1,	"failed to get path list from vHCI: "},
{ERRARG_XPORT_NOT_IN_PHCI_LIST,	1, 1,	"Transport not in pHCI list: "},

/* RCM Errors */
{ERR_RCM_HANDLE,	0, 1,	"cannot get RCM handle"},
{ERRARG_RCM_SUSPEND,	1, 1,	"failed to suspend: "},
{ERRARG_RCM_RESUME,	1, 1,	"failed to resume: "},
{ERRARG_RCM_OFFLINE,	1, 1,	"failed to offline: "},
{ERRARG_RCM_ONLINE,	1, 1,	"failed to online: "},
{ERRARG_RCM_REMOVE,	1, 1,	"failed to remove: "},
{ERRARG_RCM_INFO,	1, 1,	"failed to query: "},

/* Commands */
{CMD_INSERT_DEV,	0, 0,	"insert_device"},
{CMD_REMOVE_DEV,	0, 0,	"remove_device"},
{CMD_REPLACE_DEV,	0, 0,	"replace_device"},
{CMD_RESET_DEV,		0, 0,	"reset_device"},
{CMD_RESET_BUS,		0, 0,	"reset_bus"},
{CMD_RESET_ALL,		0, 0,	"reset_all"},

/* help messages */
{MSG_HELP_HDR,		0, 1,	"\nfp attachment point specific options:\n"},
{MSG_HELP_USAGE,	0, 0,
		"\t-c configure -o force_update ap_id [ap_id..]\n"
		"\t-c configure -o no_update ap_id [ap_id...]\n"
		"\t-c unconfigure -o force_update ap_id [ap_id... ]\n"
		"\t-c unconfigure -o no_update ap_id [ap_id... ]\n"},

/* hotplug messages */
{MSG_INSDEV,		1, 1,	"Adding device to FC HBA: "},
{MSG_RMDEV,		1, 1,	"Removing FC device: "},
{MSG_REPLDEV,		1, 1,	"Replacing FC device: "},

/* Hotplugging confirmation prompts */
{CONF_QUIESCE_1,	1, 1,
	"This operation will suspend activity on FC bus: "},

{CONF_QUIESCE_2,	0, 1,	"\nContinue"},

{CONF_UNQUIESCE,	0, 1,
	"FC bus quiesced successfully.\n"
	"It is now safe to proceed with hotplug operation."
	"\nEnter y if operation is complete or n to abort"},

/* Misc. */
{WARN_DISCONNECT,	0, 1,
	"WARNING: Disconnecting critical partitions may cause system hang."
	"\nContinue"}
};


#define	N_STRS	(sizeof (str_tbl) / sizeof (str_tbl[0]))

#define	GET_MSG_NARGS(i)	(str_tbl[msg_idx(i)].nargs)
#define	GET_MSG_INTL(i)		(str_tbl[msg_idx(i)].intl)

static errcvt_t err_cvt_tbl[] = {
	{ FPCFGA_OK,		CFGA_OK			},
	{ FPCFGA_LIB_ERR,	CFGA_LIB_ERROR		},
	{ FPCFGA_APID_NOEXIST,	CFGA_APID_NOEXIST	},
	{ FPCFGA_NACK,		CFGA_NACK		},
	{ FPCFGA_BUSY,		CFGA_BUSY		},
	{ FPCFGA_SYSTEM_BUSY,	CFGA_SYSTEM_BUSY	},
	{ FPCFGA_OPNOTSUPP,	CFGA_OPNOTSUPP		},
	{ FPCFGA_PRIV,		CFGA_PRIV		},
	{ FPCFGA_UNKNOWN_ERR,	CFGA_ERROR		},
	{ FPCFGA_ERR,		CFGA_ERROR		}
};

#define	N_ERR_CVT_TBL	(sizeof (err_cvt_tbl)/sizeof (err_cvt_tbl[0]))

#define	DEV_OP	0
#define	BUS_OP	1
static set_state_cmd_t set_state_cmds[] = {

{ FPCFGA_BUS_QUIESCE,		BUS_OP,		devctl_bus_quiesce	},
{ FPCFGA_BUS_UNQUIESCE,		BUS_OP,		devctl_bus_unquiesce	},
{ FPCFGA_BUS_CONFIGURE,		BUS_OP,		devctl_bus_configure	},
{ FPCFGA_BUS_UNCONFIGURE, 	BUS_OP,		devctl_bus_unconfigure	},
{ FPCFGA_RESET_BUS,		BUS_OP,		devctl_bus_reset	},
{ FPCFGA_RESET_ALL, 		BUS_OP,		devctl_bus_resetall	},
{ FPCFGA_DEV_CONFIGURE,		DEV_OP,		devctl_device_online	},
{ FPCFGA_DEV_UNCONFIGURE,	DEV_OP,		devctl_device_offline	},
{ FPCFGA_DEV_REMOVE,		DEV_OP,		devctl_device_remove	},
{ FPCFGA_RESET_DEV,		DEV_OP,		devctl_device_reset	}

};

#define	N_SET_STATE_CMDS (sizeof (set_state_cmds)/sizeof (set_state_cmds[0]))

static get_state_cmd_t get_state_cmds[] = {
{ FPCFGA_BUS_GETSTATE,		BUS_OP,		devctl_bus_getstate	},
{ FPCFGA_DEV_GETSTATE,		DEV_OP,		devctl_device_getstate	}
};

#define	N_GET_STATE_CMDS (sizeof (get_state_cmds)/sizeof (get_state_cmds[0]))

/* Order is important. Earlier directories are searched first */
static const char *dev_dir_hints[] = {
	CFGA_DEV_DIR,
	DEV_RMT,
	DEV_DSK,
	DEV_RDSK,
	DEV_DIR
};

#define	N_DEV_DIR_HINTS	(sizeof (dev_dir_hints) / sizeof (dev_dir_hints[0]))


/*
 * Routine to search the /dev directory or a subtree of /dev.
 * If the entire /dev hierarchy is to be searched, the most likely directories
 * are searched first.
 */
fpcfga_ret_t
recurse_dev(
	const char	*basedir,
	void		*arg,
	fpcfga_recur_t (*fcn)(const char *lpath, void *arg))
{
	int i, rv = NFTW_ERROR;

	(void) mutex_lock(&nftw_arg.mp);

	nftw_arg.arg = arg;
	nftw_arg.fcn = fcn;

	if (strcmp(basedir, DEV_DIR)) {
		errno = 0;
		rv = nftw(basedir, do_recurse_dev, NFTW_DEPTH, FTW_PHYS);
		goto out;
	}

	/*
	 * Search certain selected subdirectories first if basedir == "/dev".
	 * Ignore errors as some of these directories may not exist.
	 */
	for (i = 0; i < N_DEV_DIR_HINTS; i++) {
		errno = 0;
		if ((rv = nftw(dev_dir_hints[i], do_recurse_dev, NFTW_DEPTH,
		    FTW_PHYS)) == NFTW_TERMINATE) {
			break;
		}
	}

	/*FALLTHRU*/
out:
	(void) mutex_unlock(&nftw_arg.mp);
	return (rv == NFTW_ERROR ? FPCFGA_ERR : FPCFGA_OK);
}

/*ARGSUSED*/
static int
do_recurse_dev(
	const char *path,
	const struct stat *sbuf,
	int type,
	struct FTW *ftwp)
{
	/* We want only VALID symlinks */
	if (type != FTW_SL) {
		return (NFTW_CONTINUE);
	}

	assert(nftw_arg.fcn != NULL);

	if (nftw_arg.fcn(path, nftw_arg.arg) == FPCFGA_TERMINATE) {
		/* terminate prematurely, but may not be error */
		errno = 0;
		return (NFTW_TERMINATE);
	} else {
		return (NFTW_CONTINUE);
	}
}

cfga_err_t
err_cvt(fpcfga_ret_t fp_err)
{
	int i;

	for (i = 0; i < N_ERR_CVT_TBL; i++) {
		if (err_cvt_tbl[i].fp_err == fp_err) {
			return (err_cvt_tbl[i].cfga_err);
		}
	}

	return (CFGA_ERROR);
}

/*
 * Removes duplicate slashes from a pathname and any trailing slashes.
 * Returns "/" if input is "/"
 */
char *
pathdup(const char *path, int *l_errnop)
{
	int prev_was_slash = 0;
	char c, *dp = NULL, *dup = NULL;
	const char *sp = NULL;

	*l_errnop = 0;

	if (path == NULL) {
		return (NULL);
	}

	if ((dup = calloc(1, strlen(path) + 1)) == NULL) {
		*l_errnop = errno;
		return (NULL);
	}

	prev_was_slash = 0;
	for (sp = path, dp = dup; (c = *sp) != '\0'; sp++) {
		if (!prev_was_slash || c != '/') {
			*dp++ = c;
		}
		if (c == '/') {
			prev_was_slash = 1;
		} else {
			prev_was_slash = 0;
		}
	}

	/* Remove trailing slash except if it is the first char */
	if (prev_was_slash && dp != dup && dp - 1 != dup) {
		*(--dp) = '\0';
	} else {
		*dp = '\0';
	}

	return (dup);
}

fpcfga_ret_t
apidt_create(const char *ap_id, apid_t *apidp, char **errstring)
{
	char *xport_phys = NULL, *dyn = NULL;
	char *dyncomp = NULL;
	struct luninfo_list *lunlistp = NULL;
	int l_errno = 0;
	size_t len = 0;
	fpcfga_ret_t ret;

	if ((xport_phys = pathdup(ap_id, &l_errno)) == NULL) {
		cfga_err(errstring, l_errno, ERR_OP_FAILED, 0);
		return (FPCFGA_LIB_ERR);
	}

	/* Extract the base(hba) and dynamic(device) component if any */
	dyncomp = NULL;
	if ((dyn = GET_DYN(xport_phys)) != NULL) {
		len = strlen(DYN_TO_DYNCOMP(dyn)) + 1;
		dyncomp = calloc(1, len);
		if (dyncomp == NULL) {
			cfga_err(errstring, errno, ERR_OP_FAILED, 0);
			ret = FPCFGA_LIB_ERR;
			goto err;
		}
		(void) strcpy(dyncomp, DYN_TO_DYNCOMP(dyn));
		if (GET_LUN_DYN(dyncomp)) {
			ret = FPCFGA_APID_NOEXIST;
			goto err;
		}

		/* Remove the dynamic component from the base. */
		*dyn = '\0';
	}

	/* Get the path of dynamic attachment point if already configured. */
	if (dyncomp != NULL) {
		ret = dyn_apid_to_path(xport_phys, dyncomp,
		    &lunlistp, &l_errno);
		if ((ret != FPCFGA_OK) && (ret != FPCFGA_APID_NOCONFIGURE)) {
			cfga_err(errstring, l_errno, ERR_OP_FAILED, 0);
			goto err;
		}
	}

	assert(xport_phys != NULL);

	apidp->xport_phys = xport_phys;
	apidp->dyncomp = dyncomp;
	apidp->lunlist = lunlistp;
	apidp->flags = 0;

	return (FPCFGA_OK);

err:
	S_FREE(xport_phys);
	S_FREE(dyncomp);
	lunlist_free(lunlistp);
	return (ret);
}

static void
lunlist_free(struct luninfo_list *lunlist)
{
struct luninfo_list *lunp;

	while (lunlist != NULL) {
		lunp = lunlist->next;
		S_FREE(lunlist->path);
		S_FREE(lunlist);
		lunlist = lunp;
	}
}

void
apidt_free(apid_t *apidp)
{
	if (apidp == NULL)
		return;

	S_FREE(apidp->xport_phys);
	S_FREE(apidp->dyncomp);
	lunlist_free(apidp->lunlist);
}

fpcfga_ret_t
walk_tree(
	const char	*physpath,
	void		*arg,
	uint_t		init_flags,
	walkarg_t	*up,
	fpcfga_cmd_t	cmd,
	int		*l_errnop)
{
	int rv;
	di_node_t root, tree_root, fpnode;
	char *root_path, *cp = NULL;
	char *devfs_fp_path;
	size_t len;
	fpcfga_ret_t ret;
	int	found = 0;

	*l_errnop = 0;

	if ((root_path = strdup(physpath)) == NULL) {
		*l_errnop = errno;
		return (FPCFGA_LIB_ERR);
	}

	/* Fix up path for di_init() */
	len = strlen(DEVICES_DIR);
	if (strncmp(root_path, DEVICES_DIR SLASH,
	    len + strlen(SLASH)) == 0) {
		cp = root_path + len;
		(void) memmove(root_path, cp, strlen(cp) + 1);
	} else if (*root_path != '/') {
		*l_errnop = 0;
		ret = FPCFGA_ERR;
		goto out;
	}

	/* Remove dynamic component if any */
	if ((cp = GET_DYN(root_path)) != NULL) {
		*cp = '\0';
	}

	/* Remove minor name if any */
	if ((cp = strrchr(root_path, ':')) != NULL) {
		*cp = '\0';
	}

	/*
	 * If force_flag is set
	 * do di_init with DINFOFORCE flag and get to the input fp node
	 * from the device tree.
	 *
	 * In order to get the link between path_info node and scsi_vhci node
	 * it is required to take the snapshot of the whole device tree.
	 * this behavior of libdevinfo is inefficient.  For a specific
	 * fca port DINFOPROP was sufficient on the fca path prior to
	 * scsi_vhci node support.
	 *
	 */
	if ((up->flags & FLAG_DEVINFO_FORCE) == FLAG_DEVINFO_FORCE) {
		tree_root = di_init("/", init_flags | DINFOFORCE);
	} else {
		tree_root = di_init("/", init_flags);
	}

	if (tree_root == DI_NODE_NIL) {
		*l_errnop = errno;
		ret = FPCFGA_LIB_ERR;
		goto out;
	}

	fpnode = di_drv_first_node("fp", tree_root);

	while (fpnode) {
		devfs_fp_path = di_devfs_path(fpnode);
		if ((devfs_fp_path) && !(strncmp(devfs_fp_path,
		    root_path, strlen(root_path)))) {
			found = 1;
			di_devfs_path_free(devfs_fp_path);
			break;
		}
		di_devfs_path_free(devfs_fp_path);
		fpnode = di_drv_next_node(fpnode);
	}
	if (!(found)) {
		ret = FPCFGA_LIB_ERR;
		goto out;
	} else {
		root = fpnode;
	}

	/* Walk the tree */
	errno = 0;
	if (cmd == FPCFGA_WALK_NODE) {
		rv = di_walk_node(root, up->walkmode.node_args.flags, arg,
		    up->walkmode.node_args.fcn);
	} else {
		assert(cmd == FPCFGA_WALK_MINOR);
		rv = di_walk_minor(root, up->walkmode.minor_args.nodetype, 0,
		    arg, up->walkmode.minor_args.fcn);
	}

	if (rv != 0) {
		*l_errnop = errno;
		ret = FPCFGA_LIB_ERR;
	} else {
		if ((up->flags & FLAG_PATH_INFO_WALK) == FLAG_PATH_INFO_WALK) {
			ret = stat_path_info_node(root, arg, l_errnop);
		} else {
			*l_errnop = 0;
			ret = FPCFGA_OK;
		}
	}

	di_fini(tree_root);

	/*FALLTHRU*/
out:
	S_FREE(root_path);
	return (ret);
}


int
msg_idx(msgid_t msgid)
{
	int idx = 0;

	/* The string table index and the error id may or may not be same */
	if (msgid >= 0 && msgid <= N_STRS - 1 &&
	    str_tbl[msgid].msgid == msgid) {
		idx = msgid;
	} else {
		for (idx = 0; idx < N_STRS; idx++) {
			if (str_tbl[idx].msgid == msgid)
				break;
		}
		if (idx >= N_STRS) {
			idx =  UNKNOWN_ERR_IDX;
		}
	}

	return (idx);
}

/*
 * cfga_err() accepts a variable number of message IDs and constructs
 * a corresponding error string which is returned via the errstring argument.
 * cfga_err() calls dgettext() to internationalize proper messages.
 * May be called with a NULL argument.
 */
void
cfga_err(char **errstring, int l_errno, ...)
{
	va_list ap;
	int append_newline = 0;
	char *tmp_str, *tmp_err_str = NULL;

	if (errstring == NULL) {
		return;
	}

	/*
	 * Don't append a newline, the application (for example cfgadm)
	 * should do that.
	 */
	append_newline = 0;

	va_start(ap, l_errno);
	msg_common(&tmp_err_str, append_newline, l_errno, ap);
	va_end(ap);

	if (*errstring == NULL) {
		*errstring = tmp_err_str;
		return;
	}

	/*
	 * *errstring != NULL
	 * There was something in errstring prior to this call.
	 * So, concatenate the old and new strings
	 */
	if ((tmp_str = calloc(1,
	    strlen(*errstring) + strlen(tmp_err_str) + 2)) == NULL) {
		/* In case of error, retain only the earlier message */
		free(tmp_err_str);
		return;
	}

	sprintf(tmp_str, "%s\n%s", *errstring, tmp_err_str);
	free(tmp_err_str);
	free(*errstring);
	*errstring = tmp_str;
}

/*
 * This routine accepts a variable number of message IDs and constructs
 * a corresponding message string which is printed via the message print
 * routine argument.
 */
void
cfga_msg(struct cfga_msg *msgp, ...)
{
	char *p = NULL;
	int append_newline = 0, l_errno = 0;
	va_list ap;

	if (msgp == NULL || msgp->message_routine == NULL) {
		return;
	}

	/* Append a newline after message */
	append_newline = 1;
	l_errno = 0;

	va_start(ap, msgp);
	msg_common(&p, append_newline, l_errno, ap);
	va_end(ap);

	(void) (*msgp->message_routine)(msgp->appdata_ptr, p);

	S_FREE(p);
}

/*
 * Get internationalized string corresponding to message id
 * Caller must free the memory allocated.
 */
char *
cfga_str(int append_newline, ...)
{
	char *p = NULL;
	int l_errno = 0;
	va_list ap;

	va_start(ap, append_newline);
	msg_common(&p, append_newline, l_errno, ap);
	va_end(ap);

	return (p);
}

static void
msg_common(char **msgpp, int append_newline, int l_errno, va_list ap)
{
	int a = 0;
	size_t len = 0;
	int i = 0, n = 0;
	char *s = NULL, *t = NULL;
	strlist_t dummy;
	strlist_t *savep = NULL, *sp = NULL, *tailp = NULL;

	if (*msgpp != NULL) {
		return;
	}

	dummy.next = NULL;
	tailp = &dummy;
	for (len = 0; (a = va_arg(ap, int)) != 0; ) {
		n = GET_MSG_NARGS(a); /* 0 implies no additional args */
		for (i = 0; i <= n; i++) {
			sp = calloc(1, sizeof (*sp));
			if (sp == NULL) {
				goto out;
			}
			if (i == 0 && GET_MSG_INTL(a)) {
				sp->str = dgettext(TEXT_DOMAIN, GET_MSG_STR(a));
			} else if (i == 0) {
				sp->str = GET_MSG_STR(a);
			} else {
				sp->str = va_arg(ap, char *);
			}
			len += (strlen(sp->str));
			sp->next = NULL;
			tailp->next = sp;
			tailp = sp;
		}
	}

	len += 1;	/* terminating NULL */

	s = t = NULL;
	if (l_errno) {
		s = dgettext(TEXT_DOMAIN, ": ");
		t = S_STR(strerror(l_errno));
		if (s != NULL && t != NULL) {
			len += strlen(s) + strlen(t);
		}
	}

	if (append_newline) {
		len++;
	}

	if ((*msgpp = calloc(1, len)) == NULL) {
		goto out;
	}

	**msgpp = '\0';
	for (sp = dummy.next; sp != NULL; sp = sp->next) {
		(void) strcat(*msgpp, sp->str);
	}

	if (s != NULL && t != NULL) {
		(void) strcat(*msgpp, s);
		(void) strcat(*msgpp, t);
	}

	if (append_newline) {
		(void) strcat(*msgpp, dgettext(TEXT_DOMAIN, "\n"));
	}

	/* FALLTHROUGH */
out:
	sp = dummy.next;
	while (sp != NULL) {
		savep = sp->next;
		S_FREE(sp);
		sp = savep;
	}
}

fpcfga_ret_t
devctl_cmd(
	const char	*physpath,
	fpcfga_cmd_t	cmd,
	uint_t		*statep,
	int		*l_errnop)
{
	int rv = -1, i, type;
	devctl_hdl_t hdl = NULL;
	char *cp = NULL, *path = NULL;
	int (*func)(const devctl_hdl_t);
	int (*state_func)(const devctl_hdl_t, uint_t *);

	*l_errnop = 0;

	if (statep != NULL) *statep = 0;

	func = NULL;
	state_func = NULL;
	type = 0;

	for (i = 0; i < N_GET_STATE_CMDS; i++) {
		if (get_state_cmds[i].cmd == cmd) {
			state_func = get_state_cmds[i].state_fcn;
			type = get_state_cmds[i].type;
			assert(statep != NULL);
			break;
		}
	}

	if (state_func == NULL) {
		for (i = 0; i < N_SET_STATE_CMDS; i++) {
			if (set_state_cmds[i].cmd == cmd) {
				func = set_state_cmds[i].fcn;
				type = set_state_cmds[i].type;
				assert(statep == NULL);
				break;
			}
		}
	}

	assert(type == BUS_OP || type == DEV_OP);

	if (func == NULL && state_func == NULL) {
		return (FPCFGA_ERR);
	}

	/*
	 * Fix up path for calling devctl.
	 */
	if ((path = strdup(physpath)) == NULL) {
		*l_errnop = errno;
		return (FPCFGA_LIB_ERR);
	}

	/* Remove dynamic component if any */
	if ((cp = GET_DYN(path)) != NULL) {
		*cp = '\0';
	}

	/* Remove minor name */
	if ((cp = strrchr(path, ':')) != NULL) {
		*cp = '\0';
	}

	errno = 0;

	if (type == BUS_OP) {
		hdl = devctl_bus_acquire(path, 0);
	} else {
		hdl = devctl_device_acquire(path, 0);
	}
	*l_errnop = errno;

	S_FREE(path);

	if (hdl == NULL) {
		return (FPCFGA_ERR);
	}

	errno = 0;
	/* Only getstate functions require a second argument */
	if (func != NULL && statep == NULL) {
		rv = func(hdl);
		*l_errnop = errno;
	} else if (state_func != NULL && statep != NULL) {
		rv = state_func(hdl, statep);
		*l_errnop = errno;
	} else {
		rv = -1;
		*l_errnop = 0;
	}

	devctl_release(hdl);

	return ((rv == -1) ? FPCFGA_ERR : FPCFGA_OK);
}

/*
 * Is device in a known state ? (One of BUSY, ONLINE, OFFLINE)
 *	BUSY --> One or more device special files are open. Implies online
 *	ONLINE --> driver attached
 *	OFFLINE --> CF1 with offline flag set.
 *	UNKNOWN --> None of the above
 */
int
known_state(di_node_t node)
{
	uint_t state;

	state = di_state(node);

	/*
	 * CF1 without offline flag set is considered unknown state.
	 * We are in a known state if either CF2 (driver attached) or
	 * offline.
	 */
	if ((state & DI_DEVICE_OFFLINE) == DI_DEVICE_OFFLINE ||
	    (state & DI_DRIVER_DETACHED) != DI_DRIVER_DETACHED) {
		return (1);
	}

	return (0);
}

void
list_free(ldata_list_t **llpp)
{
	ldata_list_t *lp, *olp;

	lp = *llpp;
	while (lp != NULL) {
		olp = lp;
		lp = olp->next;
		S_FREE(olp);
	}

	*llpp = NULL;
}

/*
 * Obtain the devlink from a /devices path
 */
fpcfga_ret_t
physpath_to_devlink(
	const char *basedir,
	char *xport_phys,
	char **xport_logpp,
	int *l_errnop,
	int match_minor)
{
	pathm_t pmt = {NULL};
	fpcfga_ret_t ret;

	pmt.phys = xport_phys;
	pmt.ret = FPCFGA_NO_REC;
	pmt.match_minor = match_minor;

	/*
	 * Search the /dev hierarchy starting at basedir.
	 */
	ret = recurse_dev(basedir, &pmt, lookup_dev);
	if (ret == FPCFGA_OK && (ret = pmt.ret) == FPCFGA_OK) {
		assert(pmt.log != NULL);
		*xport_logpp  = pmt.log;
	} else {
		if (pmt.log != NULL) {
			S_FREE(pmt.log);
		}

		*xport_logpp = NULL;
		*l_errnop = pmt.l_errno;
	}

	return (ret);
}

static fpcfga_recur_t
lookup_dev(const char *lpath, void *arg)
{
	char ppath[PATH_MAX];
	pathm_t *pmtp = (pathm_t *)arg;

	if (realpath(lpath, ppath) == NULL) {
		return (FPCFGA_CONTINUE);
	}

	ppath[sizeof (ppath) - 1] = '\0';

	/* Is this the physical path we are looking for */
	if (dev_cmp(ppath, pmtp->phys, pmtp->match_minor))  {
		return (FPCFGA_CONTINUE);
	}

	if ((pmtp->log = strdup(lpath)) == NULL) {
		pmtp->l_errno = errno;
		pmtp->ret = FPCFGA_LIB_ERR;
	} else {
		pmtp->ret = FPCFGA_OK;
	}

	return (FPCFGA_TERMINATE);
}

/* Compare HBA physical ap_id and device path */
int
hba_dev_cmp(const char *hba, const char *devpath)
{
	char *cp = NULL;
	int rv;
	size_t hba_len, dev_len;
	char l_hba[MAXPATHLEN], l_dev[MAXPATHLEN];

	(void) snprintf(l_hba, sizeof (l_hba), "%s", hba);
	(void) snprintf(l_dev, sizeof (l_dev), "%s", devpath);

	/* Remove dynamic component if any */
	if ((cp = GET_DYN(l_hba)) != NULL) {
		*cp = '\0';
	}

	if ((cp = GET_DYN(l_dev)) != NULL) {
		*cp = '\0';
	}


	/* Remove minor names */
	if ((cp = strrchr(l_hba, ':')) != NULL) {
		*cp = '\0';
	}

	if ((cp = strrchr(l_dev, ':')) != NULL) {
		*cp = '\0';
	}

	hba_len = strlen(l_hba);
	dev_len = strlen(l_dev);

	/* Check if HBA path is component of device path */
	if (rv = strncmp(l_hba, l_dev, hba_len)) {
		return (rv);
	}

	/* devpath must have '/' and 1 char in addition to hba path */
	if (dev_len >= hba_len + 2 && l_dev[hba_len] == '/') {
		return (0);
	} else {
		return (-1);
	}
}

int
dev_cmp(const char *dev1, const char *dev2, int match_minor)
{
	char l_dev1[MAXPATHLEN], l_dev2[MAXPATHLEN];
	char *mn1, *mn2;
	int rv;

	(void) snprintf(l_dev1, sizeof (l_dev1), "%s", dev1);
	(void) snprintf(l_dev2, sizeof (l_dev2), "%s", dev2);

	if ((mn1 = GET_DYN(l_dev1)) != NULL) {
		*mn1 = '\0';
	}

	if ((mn2 = GET_DYN(l_dev2)) != NULL) {
		*mn2 = '\0';
	}

	/* Separate out the minor names */
	if ((mn1 = strrchr(l_dev1, ':')) != NULL) {
		*mn1++ = '\0';
	}

	if ((mn2 = strrchr(l_dev2, ':')) != NULL) {
		*mn2++ = '\0';
	}

	if ((rv = strcmp(l_dev1, l_dev2)) != 0 || !match_minor) {
		return (rv);
	}

	/*
	 * Compare minor names
	 */
	if (mn1 == NULL && mn2 == NULL) {
		return (0);
	} else if (mn1 == NULL) {
		return (-1);
	} else if (mn2 == NULL) {
		return (1);
	} else {
		return (strcmp(mn1, mn2));
	}
}

/*
 * Returns non-zero on failure (aka, HBA_STATUS_ERROR_*
 * Will handle retries if applicable.
 */
int
getAdapterAttrs(HBA_HANDLE handle, HBA_ADAPTERATTRIBUTES *attrs)
{
	int count = 0;
	HBA_STATUS status = HBA_STATUS_ERROR_TRY_AGAIN; /* force first pass */

	/* Loop as long as we have a retryable error */
	while ((status == HBA_STATUS_ERROR_TRY_AGAIN ||
	    status == HBA_STATUS_ERROR_BUSY) &&
	    count++ < HBA_MAX_RETRIES) {
		status = HBA_GetAdapterAttributes(handle, attrs);
		if (status == HBA_STATUS_OK) {
			break;
		}
		sleep(1);
	}
	return (status);
}

/*
 * Returns non-zero on failure (aka, HBA_STATUS_ERROR_*
 * Will handle retries if applicable.
 */
int
getPortAttrsByWWN(HBA_HANDLE handle, HBA_WWN wwn, HBA_PORTATTRIBUTES *attrs)
{
	int count = 0;
	HBA_STATUS status = HBA_STATUS_ERROR_TRY_AGAIN; /* force first pass */

	/* Loop as long as we have a retryable error */
	while ((status == HBA_STATUS_ERROR_TRY_AGAIN ||
	    status == HBA_STATUS_ERROR_BUSY) &&
	    count++ < HBA_MAX_RETRIES) {
		status = HBA_GetPortAttributesByWWN(handle, wwn, attrs);
		if (status == HBA_STATUS_OK) {
			break;
		}

		/* The odds of this occuring are very slim, but possible. */
		if (status == HBA_STATUS_ERROR_STALE_DATA) {
			/*
			 * If we hit a stale data scenario,
			 * we'll just tell the user to try again.
			 */
			status = HBA_STATUS_ERROR_TRY_AGAIN;
			break;
		}
		sleep(1);
	}
	return (status);
}

/*
 * Returns non-zero on failure (aka, HBA_STATUS_ERROR_*
 * Will handle retries if applicable.
 */
int
getAdapterPortAttrs(HBA_HANDLE handle, int portIndex,
	    HBA_PORTATTRIBUTES *attrs)
{
	int count = 0;
	HBA_STATUS status = HBA_STATUS_ERROR_TRY_AGAIN; /* force first pass */

	/* Loop as long as we have a retryable error */
	while ((status == HBA_STATUS_ERROR_TRY_AGAIN ||
	    status == HBA_STATUS_ERROR_BUSY) &&
	    count++ < HBA_MAX_RETRIES) {
		status = HBA_GetAdapterPortAttributes(handle, portIndex, attrs);
		if (status == HBA_STATUS_OK) {
			break;
		}

		/* The odds of this occuring are very slim, but possible. */
		if (status == HBA_STATUS_ERROR_STALE_DATA) {
			/*
			 * If we hit a stale data scenario,
			 * we'll just tell the user to try again.
			 */
			status = HBA_STATUS_ERROR_TRY_AGAIN;
			break;
		}
		sleep(1);
	}
	return (status);
}

/*
 * Returns non-zero on failure (aka, HBA_STATUS_ERROR_*
 * Will handle retries if applicable.
 */
int
getDiscPortAttrs(HBA_HANDLE handle, int portIndex, int discIndex,
	    HBA_PORTATTRIBUTES *attrs)
{
	int count = 0;
	HBA_STATUS status = HBA_STATUS_ERROR_TRY_AGAIN; /* force first pass */

	/* Loop as long as we have a retryable error */
	while ((status == HBA_STATUS_ERROR_TRY_AGAIN ||
	    status == HBA_STATUS_ERROR_BUSY) &&
	    count++ < HBA_MAX_RETRIES) {
		status = HBA_GetDiscoveredPortAttributes(handle, portIndex,
		    discIndex, attrs);
		if (status == HBA_STATUS_OK) {
			break;
		}

		/* The odds of this occuring are very slim, but possible. */
		if (status == HBA_STATUS_ERROR_STALE_DATA) {
			/*
			 * If we hit a stale data scenario, we'll just tell the
			 * user to try again.
			 */
			status = HBA_STATUS_ERROR_TRY_AGAIN;
			break;
		}
		sleep(1);
	}
	return (status);
}

/*
 * Find the Adapter port that matches the portPath.
 * When the matching port is found the caller have to close handle
 * and free library.
 */
fpcfga_ret_t
findMatchingAdapterPort(char *portPath, HBA_HANDLE *matchingHandle,
	int *matchingPortIndex, HBA_PORTATTRIBUTES *matchingPortAttrs,
	char **errstring)
{
	HBA_HANDLE	handle;
	HBA_ADAPTERATTRIBUTES	hbaAttrs;
	HBA_PORTATTRIBUTES	portAttrs;
	HBA_STATUS status = HBA_STATUS_OK;
	int count, retry = 0, l_errno = 0;
	int adapterIndex, portIndex;
	char			adapterName[256];
	char			*cfg_ptr, *tmpPtr;
	char			*logical_apid = NULL;

	status = HBA_LoadLibrary();
	if (status != HBA_STATUS_OK) {
		cfga_err(errstring, 0, ERR_HBA_LOAD_LIBRARY, 0);
		return (FPCFGA_LIB_ERR);
	}
	count = HBA_GetNumberOfAdapters();
	if (count == 0) {
		cfga_err(errstring, 0, ERR_NO_ADAPTER_FOUND, 0);
		HBA_FreeLibrary();
		return (FPCFGA_LIB_ERR);
	}

	/* Loop over all HBAs */
	for (adapterIndex = 0; adapterIndex < count; adapterIndex ++) {
		status = HBA_GetAdapterName(adapterIndex, (char *)&adapterName);
		if (status != HBA_STATUS_OK) {
			/* May have been DR'd */
			continue;
		}
		handle = HBA_OpenAdapter(adapterName);
		if (handle == 0) {
			/* May have been DR'd */
			continue;
		}

		do {
			if (getAdapterAttrs(handle, &hbaAttrs)) {
				/* Should never happen */
				HBA_CloseAdapter(handle);
				continue;
			}

			/* Loop over all HBA Ports */
			for (portIndex = 0;
			    portIndex < hbaAttrs.NumberOfPorts; portIndex++) {
				if ((status = getAdapterPortAttrs(handle,
				    portIndex,
				    &portAttrs)) != HBA_STATUS_OK) {
					/* Need to refresh adapter */
					if (status ==
					    HBA_STATUS_ERROR_STALE_DATA) {
						HBA_RefreshInformation(handle);
						break;
					} else {
						continue;
					}
				}

				/*
				 * check to see if OSDeviceName is a /dev/cfg
				 * link or the physical path
				 */
				if (strncmp(portAttrs.OSDeviceName,
				    CFGA_DEV_DIR,
				    strlen(CFGA_DEV_DIR)) != 0) {
					tmpPtr = strstr(portAttrs.OSDeviceName,
					    MINOR_SEP);
					if ((tmpPtr != NULL) &&
					    strncmp(portPath,
					    portAttrs.OSDeviceName,
					    strlen(portAttrs.OSDeviceName) -
					    strlen(tmpPtr)) == 0) {
						if (matchingHandle)
							*matchingHandle =
							    handle;
						if (matchingPortIndex)
							*matchingPortIndex =
							    portIndex;
						if (matchingPortAttrs)
							*matchingPortAttrs =
							    portAttrs;
						return (FPCFGA_OK);
					}
				} else {
					/*
					 * strip off the /dev/cfg/ portion of
					 * the OSDeviceName make sure that the
					 * OSDeviceName is at least
					 * strlen("/dev/cfg") + 1 + 1 long.
					 * first 1 is for the / after /dev/cfg
					 * second 1 is to make sure there is
					 * somthing after
					 */
					if (strlen(portAttrs.OSDeviceName) <
					    (strlen(CFGA_DEV_DIR) + 1 + 1))
						continue;
					cfg_ptr = portAttrs.OSDeviceName +
					    strlen(CFGA_DEV_DIR) + 1;
					if (logical_apid == NULL) {
						/*
						 * get the /dev/cfg link from
						 * the portPath
						 */
						if (make_xport_logid(portPath,
						    &logical_apid,
						    &l_errno) != FPCFGA_OK) {
							cfga_err(errstring,
							    l_errno,
							    ERR_LIST, 0);
							HBA_FreeLibrary();
							return
							    (FPCFGA_LIB_ERR);
						}
					}
					/* compare logical ap_id */
					if (strcmp(logical_apid,
					    cfg_ptr) == 0) {
						if (matchingHandle)
							*matchingHandle =
							    handle;
						if (matchingPortIndex)
							*matchingPortIndex =
							    portIndex;
						if (matchingPortAttrs)
							*matchingPortAttrs =
							    portAttrs;
						S_FREE(logical_apid);
						return (FPCFGA_OK);
					}
				}
			}
			if (logical_apid != NULL)
				S_FREE(logical_apid);
		} while ((status == HBA_STATUS_ERROR_STALE_DATA) &&
		    (retry++ < HBA_MAX_RETRIES));

		HBA_CloseAdapter(handle);
	}
	free(logical_apid);

	/* Got here. No matching adapter port found. */
	cfga_err(errstring, 0, ERR_MATCHING_HBA_PORT, 0);
	HBA_FreeLibrary();
	return (FPCFGA_LIB_ERR);
}
