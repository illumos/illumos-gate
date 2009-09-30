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

#include "cfga_scsi.h"
#include <libgen.h>
#include <limits.h>

/*
 * This file contains helper routines for the SCSI plugin
 */

#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN	"SYS_TEST"
#endif

typedef struct strlist {
	const char *str;
	struct strlist *next;
} strlist_t;

typedef	struct {
	scfga_ret_t scsi_err;
	cfga_err_t  cfga_err;
} errcvt_t;

typedef struct {
	scfga_cmd_t cmd;
	int type;
	int (*fcn)(const devctl_hdl_t);
} set_state_cmd_t;

typedef struct {
	scfga_cmd_t cmd;
	int type;
	int (*state_fcn)(const devctl_hdl_t, uint_t *);
} get_state_cmd_t;

/* Function prototypes */
static char *pathdup(const char *path, int *l_errnop);
static void msg_common(char **err_msgpp, int append_newline, int l_errno,
    va_list ap);

/*
 * The string table contains most of the strings used by the scsi cfgadm plugin.
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
{ERR_NOT_BUSAPID,	0, 1,	"not a SCSI bus apid"},
{ERR_APID_INVAL,	0, 1,	"invalid SCSI ap_id"},
{ERR_NOT_BUSOP,		0, 1,	"operation not supported for SCSI bus"},
{ERR_NOT_DEVOP,		0, 1,	"operation not supported for SCSI device"},
{ERR_UNAVAILABLE,	0, 1,	"unavailable"},
{ERR_CTRLR_CRIT,	0, 1,	"critical partition controlled by SCSI HBA"},
{ERR_BUS_GETSTATE,	0, 1,	"failed to get state for SCSI bus"},
{ERR_BUS_NOTCONNECTED,	0, 1,	"SCSI bus not connected"},
{ERR_BUS_CONNECTED,	0, 1,	"SCSI bus not disconnected"},
{ERR_BUS_QUIESCE,	0, 1,	"SCSI bus quiesce failed"},
{ERR_BUS_UNQUIESCE,	0, 1,	"SCSI bus unquiesce failed"},
{ERR_BUS_CONFIGURE,	0, 1,	"failed to configure devices on SCSI bus"},
{ERR_BUS_UNCONFIGURE,	0, 1,	"failed to unconfigure SCSI bus"},
{ERR_DEV_CONFIGURE,	0, 1,	"failed to configure SCSI device"},
{ERR_DEV_RECONFIGURE,	1, 1,	"failed to reconfigure device: "},
{ERR_DEV_UNCONFIGURE,	0, 1,	"failed to unconfigure SCSI device"},
{ERR_DEV_REMOVE,	0, 1,	"remove operation failed"},
{ERR_DEV_REPLACE,	0, 1,	"replace operation failed"},
{ERR_DEV_INSERT,	0, 1,	"insert operation failed"},
{ERR_DEV_GETSTATE,	0, 1,	"failed to get state for SCSI device"},
{ERR_RESET,		0, 1,	"reset failed"},
{ERR_LIST,		0, 1,	"list operation failed"},
{ERR_MAYBE_BUSY,	0, 1,	"device may be busy"},
{ERR_BUS_DEV_MISMATCH,	0, 1,	"mismatched SCSI bus and device"},
{ERR_VAR_RUN,		0, 1,	"/var/run is not mounted"},
{ERR_FORK,		0, 1,	"failed to fork cleanup handler"},

/* Errors with arguments */
{ERRARG_OPT_INVAL,	1, 1,	"invalid option: "},
{ERRARG_HWCMD_INVAL,	1, 1,	"invalid command: "},
{ERRARG_DEVINFO,	1, 1,	"libdevinfo failed on path: "},
{ERRARG_OPEN,		1, 1,	"open failed: "},
{ERRARG_LOCK,		1, 1,	"lock failed: "},
{ERRARG_QUIESCE_LOCK,	1, 1,	"cannot acquire quiesce lock: "},

/* RCM Errors */
{ERR_RCM_HANDLE,	0, 1,	"cannot get RCM handle"},
{ERRARG_RCM_SUSPEND,	0, 1,	"failed to suspend: "},
{ERRARG_RCM_RESUME,	0, 1,	"failed to resume: "},
{ERRARG_RCM_OFFLINE,	0, 1,	"failed to offline: "},
{ERRARG_RCM_CLIENT_OFFLINE,	0, 1,	"failed to offline a client device: "},
{ERRARG_RCM_ONLINE,	0, 1,	"failed to online: "},
{ERRARG_RCM_REMOVE,	0, 1,	"failed to remove: "},

/* Commands */
{CMD_INSERT_DEV,	0, 0,	"insert_device"},
{CMD_REMOVE_DEV,	0, 0,	"remove_device"},
{CMD_LED_DEV,		0, 0,	"led"},
{CMD_LOCATOR_DEV,	0, 0,	"locator"},
{CMD_REPLACE_DEV,	0, 0,	"replace_device"},
{CMD_RESET_DEV,		0, 0,	"reset_device"},
{CMD_RESET_BUS,		0, 0,	"reset_bus"},
{CMD_RESET_ALL,		0, 0,	"reset_all"},

/* help messages */
{MSG_HELP_HDR,		0, 1,	"\nSCSI specific commands and options:\n"},
{MSG_HELP_USAGE,	0, 0,	"\t-x insert_device ap_id [ap_id... ]\n"
				"\t-x remove_device ap_id [ap_id... ]\n"
				"\t-x replace_device ap_id [ap_id... ]\n"
				"\t-x locator[=on|off] ap_id [ap_id... ]\n"
				"\t-x led[=LED,mode=on|off|blink] "
				    "ap_id [ap_id... ]\n"
				"\t-x reset_device ap_id [ap_id... ]\n"
				"\t-x reset_bus ap_id [ap_id... ]\n"
				"\t-x reset_all ap_id [ap_id... ]\n"},

/* hotplug messages */
{MSG_INSDEV,		1, 1,	"Adding device to SCSI HBA: "},
{MSG_RMDEV,		1, 1,	"Removing SCSI device: "},
{MSG_REPLDEV,		1, 1,	"Replacing SCSI device: "},
{MSG_WAIT_LOCK,		0, 1,	"Waiting for quiesce lock... "},

/* Hotplugging confirmation prompts */
{CONF_QUIESCE_1,	1, 1,
	"This operation will suspend activity on SCSI bus: "},

{CONF_QUIESCE_2,	0, 1,	"\nContinue"},

{CONF_UNQUIESCE,	0, 1,
	"SCSI bus quiesced successfully.\n"
	"It is now safe to proceed with hotplug operation."
	"\nEnter y if operation is complete or n to abort"},

{CONF_NO_QUIESCE,	0, 1,
	"Proceed with hotplug operation."
	"\nEnter y if operation is complete or n to abort"},

/* Misc. */
{WARN_DISCONNECT,	0, 1,
	"WARNING: Disconnecting critical partitions may cause system hang."
	"\nContinue"},

/* LED messages */
{MSG_LED_HDR,		0, 1,	"Disk                    Led"},
{MSG_MISSING_LED_NAME,	0, 1,	"Missing LED name"},
{MSG_MISSING_LED_MODE,	0, 1,	"Missing LED mode"}
};

char *
led_strs[] = {
	"fault",
	"power",
	"attn",
	"active",
	"locator",
	NULL
};

char *
led_mode_strs[] = {
	"off",
	"on",
	"blink",
	"faulted",
	"unknown",
	NULL
};




#define	N_STRS	(sizeof (str_tbl) / sizeof (str_tbl[0]))

#define	GET_MSG_NARGS(i)	(str_tbl[msg_idx(i)].nargs)
#define	GET_MSG_INTL(i)		(str_tbl[msg_idx(i)].intl)

static errcvt_t err_cvt_tbl[] = {
	{ SCFGA_OK,		CFGA_OK			},
	{ SCFGA_LIB_ERR,	CFGA_LIB_ERROR		},
	{ SCFGA_APID_NOEXIST,	CFGA_APID_NOEXIST	},
	{ SCFGA_NACK,		CFGA_NACK		},
	{ SCFGA_BUSY,		CFGA_BUSY		},
	{ SCFGA_SYSTEM_BUSY,	CFGA_SYSTEM_BUSY	},
	{ SCFGA_OPNOTSUPP,	CFGA_OPNOTSUPP		},
	{ SCFGA_PRIV,		CFGA_PRIV		},
	{ SCFGA_UNKNOWN_ERR,	CFGA_ERROR		},
	{ SCFGA_ERR,		CFGA_ERROR		}
};

#define	N_ERR_CVT_TBL	(sizeof (err_cvt_tbl)/sizeof (err_cvt_tbl[0]))

#define	DEV_OP	0
#define	BUS_OP	1
static set_state_cmd_t set_state_cmds[] = {

{ SCFGA_BUS_QUIESCE,		BUS_OP,		devctl_bus_quiesce	},
{ SCFGA_BUS_UNQUIESCE,		BUS_OP,		devctl_bus_unquiesce	},
{ SCFGA_BUS_CONFIGURE,		BUS_OP,		devctl_bus_configure	},
{ SCFGA_BUS_UNCONFIGURE, 	BUS_OP,		devctl_bus_unconfigure	},
{ SCFGA_RESET_BUS,		BUS_OP,		devctl_bus_reset	},
{ SCFGA_RESET_ALL, 		BUS_OP,		devctl_bus_resetall	},
{ SCFGA_DEV_CONFIGURE,		DEV_OP,		devctl_device_online	},
{ SCFGA_DEV_UNCONFIGURE,	DEV_OP,		devctl_device_offline	},
{ SCFGA_DEV_REMOVE,		DEV_OP,		devctl_device_remove	},
{ SCFGA_RESET_DEV,		DEV_OP,		devctl_device_reset	}

};

#define	N_SET_STATE_CMDS (sizeof (set_state_cmds)/sizeof (set_state_cmds[0]))

static get_state_cmd_t get_state_cmds[] = {
{ SCFGA_BUS_GETSTATE,		BUS_OP,		devctl_bus_getstate	},
{ SCFGA_DEV_GETSTATE,		DEV_OP,		devctl_device_getstate	}
};

#define	N_GET_STATE_CMDS (sizeof (get_state_cmds)/sizeof (get_state_cmds[0]))

/*
 * SCSI hardware specific commands
 */
static hw_cmd_t hw_cmds[] = {
	/* Command string	Command ID		Function	*/

	{ CMD_INSERT_DEV,	SCFGA_INSERT_DEV,	dev_insert	},
	{ CMD_REMOVE_DEV,	SCFGA_REMOVE_DEV,	dev_remove	},
	{ CMD_REPLACE_DEV,	SCFGA_REPLACE_DEV,	dev_replace	},
	{ CMD_LED_DEV,		SCFGA_LED_DEV,		dev_led		},
	{ CMD_LOCATOR_DEV,	SCFGA_LOCATOR_DEV,	dev_led		},
	{ CMD_RESET_DEV,	SCFGA_RESET_DEV,	reset_common	},
	{ CMD_RESET_BUS,	SCFGA_RESET_BUS,	reset_common	},
	{ CMD_RESET_ALL,	SCFGA_RESET_ALL,	reset_common	},
};
#define	N_HW_CMDS (sizeof (hw_cmds) / sizeof (hw_cmds[0]))


cfga_err_t
err_cvt(scfga_ret_t s_err)
{
	int i;

	for (i = 0; i < N_ERR_CVT_TBL; i++) {
		if (err_cvt_tbl[i].scsi_err == s_err) {
			return (err_cvt_tbl[i].cfga_err);
		}
	}

	return (CFGA_ERROR);
}

/*
 * Removes duplicate slashes from a pathname and any trailing slashes.
 * Returns "/" if input is "/"
 */
static char *
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


scfga_ret_t
apidt_create(const char *ap_id, apid_t *apidp, char **errstring)
{
	char *hba_phys = NULL, *dyn = NULL;
	char *dyncomp = NULL, *path = NULL;
	int l_errno = 0;
	size_t len = 0;
	scfga_ret_t ret;

	if ((hba_phys = pathdup(ap_id, &l_errno)) == NULL) {
		cfga_err(errstring, l_errno, ERR_OP_FAILED, 0);
		return (SCFGA_LIB_ERR);
	}

	/* Extract the base(hba) and dynamic(device) component if any */
	dyncomp = NULL;
	if ((dyn = GET_DYN(hba_phys)) != NULL) {
		len = strlen(DYN_TO_DYNCOMP(dyn)) + 1;
		dyncomp = calloc(1, len);
		if (dyncomp == NULL) {
			cfga_err(errstring, errno, ERR_OP_FAILED, 0);
			ret = SCFGA_LIB_ERR;
			goto err;
		}
		(void) strcpy(dyncomp, DYN_TO_DYNCOMP(dyn));

		/* Remove the dynamic component from the base */
		*dyn = '\0';
	} else {
		apidp->dyntype = NODYNCOMP;
	}

	/* get dyn comp type */
	if (dyncomp != NULL) {
		if (strstr(dyncomp, PATH_APID_DYN_SEP) != NULL) {
			apidp->dyntype = PATH_APID;
		} else {
			apidp->dyntype = DEV_APID;
		}
	}

	/* Create the path */
	if ((ret = apid_to_path(hba_phys, dyncomp, &path,
	    &l_errno)) != SCFGA_OK) {
		cfga_err(errstring, l_errno, ERR_OP_FAILED, 0);
		goto err;
	}

	assert(path != NULL);
	assert(hba_phys != NULL);

	apidp->hba_phys = hba_phys;
	apidp->dyncomp = dyncomp;
	apidp->path = path;
	apidp->flags = 0;

	return (SCFGA_OK);

err:
	S_FREE(hba_phys);
	S_FREE(dyncomp);
	S_FREE(path);
	return (ret);
}

void
apidt_free(apid_t *apidp)
{
	if (apidp == NULL)
		return;

	S_FREE(apidp->hba_phys);
	S_FREE(apidp->dyncomp);
	S_FREE(apidp->path);
}

scfga_ret_t
walk_tree(
	const char	*physpath,
	void		*arg,
	uint_t		init_flags,
	walkarg_t	*up,
	scfga_cmd_t	cmd,
	int		*l_errnop)
{
	int rv;
	di_node_t root, walk_root;
	char *root_path, *cp = NULL, *init_path;
	size_t len;
	scfga_ret_t ret;

	*l_errnop = 0;

	if ((root_path = strdup(physpath)) == NULL) {
		*l_errnop = errno;
		return (SCFGA_LIB_ERR);
	}

	/* Fix up path for di_init() */
	len = strlen(DEVICES_DIR);
	if (strncmp(root_path, DEVICES_DIR SLASH,
	    len + strlen(SLASH)) == 0) {
		cp = root_path + len;
		(void) memmove(root_path, cp, strlen(cp) + 1);
	} else if (*root_path != '/') {
		*l_errnop = 0;
		ret = SCFGA_ERR;
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
	 * Cached snapshots are always rooted at "/"
	 */
	init_path = root_path;
	if ((init_flags & DINFOCACHE) == DINFOCACHE) {
		init_path = "/";
	}

	/* Get a snapshot */
	if ((root = di_init(init_path, init_flags)) == DI_NODE_NIL) {
		*l_errnop = errno;
		ret = SCFGA_LIB_ERR;
		goto out;
	}

	/*
	 * Lookup the subtree of interest
	 */
	walk_root = root;
	if ((init_flags & DINFOCACHE) == DINFOCACHE) {
		walk_root = di_lookup_node(root, root_path);
	}

	if (walk_root == DI_NODE_NIL) {
		*l_errnop = errno;
		di_fini(root);
		ret = SCFGA_LIB_ERR;
		goto out;
	}

	/* Walk the tree */
	errno = 0;
	if (cmd == SCFGA_WALK_NODE) {
		rv = di_walk_node(walk_root, up->node_args.flags, arg,
		    up->node_args.fcn);
	} else if (cmd == SCFGA_WALK_PATH) {
		rv = stat_path_info(walk_root, arg, l_errnop);
	} else {
		assert(cmd == SCFGA_WALK_MINOR);
		rv = di_walk_minor(walk_root, up->minor_args.nodetype, 0, arg,
		    up->minor_args.fcn);
	}

	if (rv != 0) {
		*l_errnop = errno;
		ret = SCFGA_LIB_ERR;
	} else {
		*l_errnop = 0;
		ret = SCFGA_OK;
	}

	di_fini(root);

	/*FALLTHRU*/
out:
	S_FREE(root_path);
	return (ret);
}

scfga_ret_t
invoke_cmd(
	const char *func,
	apid_t *apidtp,
	prompt_t *prp,
	cfga_flags_t flags,
	char **errstring)
{
	int i;
	int len;


	/*
	 * Determine if the func has an equal sign; only compare up to
	 * the equals
	 */
	for (len = 0; func[len] != 0 && func[len] != '='; len++) {
	};

	for (i = 0; i < N_HW_CMDS; i++) {
		const char *s = GET_MSG_STR(hw_cmds[i].str_id);
		if (strncmp(func, s, len) == 0 && s[len] == 0) {
			return (hw_cmds[i].fcn(func, hw_cmds[i].cmd, apidtp,
			    prp, flags, errstring));
		}
	}

	cfga_err(errstring, 0, ERRARG_HWCMD_INVAL, func, 0);
	return (SCFGA_ERR);
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

	if (errstring == NULL || *errstring != NULL) {
		return;
	}

	/*
	 * Don't append a newline, the application (for example cfgadm)
	 * should do that.
	 */
	append_newline = 0;

	va_start(ap, l_errno);
	msg_common(errstring, append_newline, l_errno, ap);
	va_end(ap);
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
 * This routine prints the value of an led for a disk.
 */
void
cfga_led_msg(struct cfga_msg *msgp, apid_t *apidp, led_strid_t led,
    led_modeid_t mode)
{
	char led_msg[MAX_INPUT];	/* 512 bytes */

	if ((msgp == NULL) || (msgp->message_routine == NULL)) {
		return;
	}
	if ((apidp == NULL) || (apidp->dyncomp == NULL)) {
		return;
	}
	(void) snprintf(led_msg, sizeof (led_msg), "%-23s\t%s=%s\n",
	    basename(apidp->dyncomp),
	    dgettext(TEXT_DOMAIN, led_strs[led]),
	    dgettext(TEXT_DOMAIN, led_mode_strs[mode]));
	(void) (*msgp->message_routine)(msgp->appdata_ptr, led_msg);
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

/*
 * Check to see if the given pi_node is the last path to the client device.
 *
 * Return:
 *	0: if there is another path avialable.
 *	-1: if no other paths available.
 */
static int
check_available_path(
	di_node_t client_node,
	di_path_t pi_node)
{
	di_path_state_t pi_state;
	di_path_t   next_pi = DI_PATH_NIL;

	if (((pi_state = di_path_state(pi_node)) != DI_PATH_STATE_ONLINE) &&
	    (pi_state != DI_PATH_STATE_STANDBY)) {
		/* it is not last available path */
		return (0);
	}

	while (next_pi = di_path_client_next_path(client_node, next_pi)) {
		/* if anohter pi node is avaialble, return 0 */
		if ((next_pi != pi_node) &&
		    (((pi_state = di_path_state(next_pi)) ==
		    DI_PATH_STATE_ONLINE) ||
		    pi_state == DI_PATH_STATE_STANDBY)) {
			return (0);
		}
	}
	return (-1);
}

scfga_ret_t
path_apid_state_change(
	apid_t		*apidp,
	scfga_cmd_t	cmd,
	cfga_flags_t	flags,
	char		**errstring,
	int		*l_errnop,
	msgid_t		errid)
{
	di_node_t   root, walk_root, client_node;
	di_path_t   pi_node = DI_PATH_NIL;
	char	    *root_path, *cp, *client_path, devpath[MAXPATHLEN];
	int	    len, found = 0;
	scfga_ret_t ret;
	char *dev_list[2] = {NULL};

	*l_errnop = 0;

	/* Make sure apid is pathinfo associated apid. */
	if ((apidp->dyntype != PATH_APID) || (apidp->dyncomp == NULL)) {
		return (SCFGA_LIB_ERR);
	}

	if ((cmd != SCFGA_DEV_CONFIGURE) && (cmd != SCFGA_DEV_UNCONFIGURE)) {
		return (SCFGA_LIB_ERR);
	}

	if ((root_path = strdup(apidp->hba_phys)) == NULL) {
		*l_errnop = errno;
		return (SCFGA_LIB_ERR);
	}

	/* Fix up path for di_init() */
	len = strlen(DEVICES_DIR);
	if (strncmp(root_path, DEVICES_DIR SLASH,
	    len + strlen(SLASH)) == 0) {
		cp = root_path + len;
		(void) memmove(root_path, cp, strlen(cp) + 1);
	} else if (*root_path != '/') {
		*l_errnop = 0;
		S_FREE(root_path);
		return (SCFGA_ERR);
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
	 * Cached snapshots are always rooted at "/"
	 */

	/* Get a snapshot */
	if ((root = di_init("/", DINFOCACHE)) == DI_NODE_NIL) {
		*l_errnop = errno;
		S_FREE(root_path);
		return (SCFGA_ERR);
	}

	/*
	 * Lookup the subtree of interest
	 */
	walk_root = di_lookup_node(root, root_path);

	if (walk_root == DI_NODE_NIL) {
		*l_errnop = errno;
		di_fini(root);
		S_FREE(root_path);
		return (SCFGA_LIB_ERR);
	}


	if ((pi_node = di_path_next_client(walk_root, pi_node)) ==
	    DI_PATH_NIL) {
		/* the path apid not found */
		di_fini(root);
		S_FREE(root_path);
		return (SCFGA_APID_NOEXIST);
	}

	do {
		/* check the length first. */
		if (strlen(di_path_bus_addr(pi_node)) !=
		    strlen(apidp->dyncomp)) {
			continue;
		}

		/* compare bus addr. */
		if (strcmp(di_path_bus_addr(pi_node), apidp->dyncomp) == 0) {
			found = 1;
			break;
		}
		pi_node = di_path_next_client(root, pi_node);
	} while (pi_node != DI_PATH_NIL);

	if (!found) {
		di_fini(root);
		S_FREE(root_path);
		return (SCFGA_APID_NOEXIST);
	}

	/* Get client node path. */
	client_node = di_path_client_node(pi_node);
	if (client_node == DI_NODE_NIL) {
		di_fini(root);
		S_FREE(root_path);
		return (SCFGA_ERR);
	} else {
		client_path = di_devfs_path(client_node);
		if (client_path == NULL) {
			di_fini(root);
			S_FREE(root_path);
			return (SCFGA_ERR);
		}

		if ((apidp->flags & FLAG_DISABLE_RCM) == 0) {
			if (cmd == SCFGA_DEV_UNCONFIGURE) {
				if (check_available_path(client_node,
				    pi_node) != 0) {
					/*
					 * last path. check if unconfiguring
					 * is okay.
					 */
					(void) snprintf(devpath,
					    strlen(DEVICES_DIR) +
					    strlen(client_path) + 1, "%s%s",
					    DEVICES_DIR, client_path);
					dev_list[0] = devpath;
					flags |= FLAG_CLIENT_DEV;
					ret = scsi_rcm_offline(dev_list,
					    errstring, flags);
					if (ret != SCFGA_OK) {
						di_fini(root);
						di_devfs_path_free(client_path);
						S_FREE(root_path);
						return (ret);
					}
				}
			}
		}
	}

	ret = devctl_cmd(apidp->path, cmd, NULL, l_errnop);
	if (ret != SCFGA_OK) {
		cfga_err(errstring, *l_errnop, errid, 0);

		/*
		 * If an unconfigure fails, cancel the RCM offline.
		 * Discard any RCM failures so that the devctl
		 * failure will still be reported.
		 */
		if ((apidp->flags & FLAG_DISABLE_RCM) == 0) {
			if (cmd == SCFGA_DEV_UNCONFIGURE)
				(void) scsi_rcm_online(dev_list,
				    errstring, flags);
		}
	}

	di_devfs_path_free(client_path);
	di_fini(root);
	S_FREE(root_path);

	return (ret);
}


scfga_ret_t
devctl_cmd(
	const char	*physpath,
	scfga_cmd_t	cmd,
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
		return (SCFGA_ERR);
	}

	/*
	 * Fix up path for calling devctl.
	 */
	if ((path = strdup(physpath)) == NULL) {
		*l_errnop = errno;
		return (SCFGA_LIB_ERR);
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
		return (SCFGA_ERR);
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

	return ((rv == -1) ? SCFGA_ERR : SCFGA_OK);
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
typedef struct walk_link {
	char *path;
	char len;
	char **linkpp;
} walk_link_t;

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
		    start[larg->len] != ':')
			return (DI_WALK_CONTINUE);
	}

	*(larg->linkpp) = strdup(di_devlink_path(devlink));
	return (DI_WALK_TERMINATE);
}

scfga_ret_t
physpath_to_devlink(
	char *node_path,
	char **logpp,
	int *l_errnop,
	int match_minor)
{
	walk_link_t larg;
	di_devlink_handle_t hdl;
	char *minor_path;

	if ((hdl = di_devlink_init(NULL, 0)) == NULL) {
		*l_errnop = errno;
		return (SCFGA_LIB_ERR);
	}

	*logpp = NULL;
	larg.linkpp = logpp;
	if (match_minor) {
		minor_path = node_path + strlen(DEVICES_DIR);
		larg.path = NULL;
	} else {
		minor_path = NULL;
		larg.len = strlen(node_path);
		larg.path = node_path;
	}

	(void) di_devlink_walk(hdl, NULL, minor_path, DI_PRIMARY_LINK,
	    (void *)&larg, get_link);

	(void) di_devlink_fini(&hdl);

	if (*logpp == NULL)
		return (SCFGA_LIB_ERR);

	return (SCFGA_OK);
}

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
