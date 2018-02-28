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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 *	Plugin Library for PCI Hot-Plug Controller
 */

#include <stddef.h>
#include <locale.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <locale.h>
#include <langinfo.h>
#include <time.h>
#include <sys/param.h>
#include <stdarg.h>
#include <libdevinfo.h>
#include <libdevice.h>

#define	CFGA_PLUGIN_LIB

#include <config_admin.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/dditypes.h>
#include <sys/devctl.h>
#include <sys/modctl.h>
#include <sys/hotplug/hpctrl.h>
#include <sys/pci.h>
#include <libintl.h>

#include <dirent.h>
#include <limits.h>
#include <sys/mkdev.h>
#include <librcm.h>
#include "../../../../common/pci/pci_strings.h"

extern const struct pci_class_strings_s class_pci[];
extern int class_pci_items;

/*
 * Set the version number
 */
int cfga_version = CFGA_HSL_V2;

#ifdef	DEBUG
#define	PCIHP_DBG	1
#endif

#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN	"SYS_TEST"
#endif

/*
 *	DEBUGING LEVEL
 *
 * 	External routines:  1 - 2
 *	Internal routines:  3 - 4
 */
#ifdef	PCIHP_DBG
int	pcihp_debug = 1;
#define	DBG(level, args) \
	{ if (pcihp_debug >= (level)) printf args; }
#define	DBG_F(level, args) \
	{ if (pcihp_debug >= (level)) fprintf args; }
#else
#define	DBG(level, args)	/* nothing */
#define	DBG_F(level, args)	/* nothing */
#endif

#define	CMD_ACQUIRE		0
#define	CMD_GETSTAT		1
#define	CMD_LIST		2
#define	CMD_SLOT_CONNECT	3
#define	CMD_SLOT_DISCONNECT	4
#define	CMD_SLOT_CONFIGURE	5
#define	CMD_SLOT_UNCONFIGURE	6
#define	CMD_SLOT_INSERT		7
#define	CMD_SLOT_REMOVE		8
#define	CMD_OPEN		9
#define	CMD_FSTAT		10
#define	ERR_CMD_INVAL		11
#define	ERR_AP_INVAL		12
#define	ERR_AP_ERR		13
#define	ERR_OPT_INVAL		14

static char *
cfga_errstrs[] = {
	/* n */ "acquire ",
	/* n */ "get-status ",
	/* n */ "list ",
	/* n */ "connect ",
	/* n */ "disconnect ",
	/* n */ "configure ",
	/* n */ "unconfigure ",
	/* n */ "insert ",
	/* n */ "remove ",
	/* n */ "open ",
	/* n */ "fstat ",
	/* y */ "invalid command ",
	/* y */ "invalid attachment point ",
	/* y */ "invalid transition ",
	/* y */ "invalid option ",
		NULL
};

#define	HELP_HEADER		1
#define	HELP_CONFIG		2
#define	HELP_ENABLE_SLOT	3
#define	HELP_DISABLE_SLOT	4
#define	HELP_ENABLE_AUTOCONF	5
#define	HELP_DISABLE_AUTOCONF	6
#define	HELP_LED_CNTRL		7
#define	HELP_UNKNOWN		8
#define	SUCCESS			9
#define	FAILED			10
#define	UNKNOWN			11

#define	MAXLINE			256

/* for type string assembly in get_type() */
#define	TPCT(s)	(void) strlcat(buf, (s), CFGA_TYPE_LEN)

extern int errno;

static void cfga_err(char **errstring, ...);
static cfga_err_t fix_ap_name(char *ap_log_id, const char *ap_id,
    char *slot_name, char **errstring);
static void build_control_data(struct hpc_control_data *iocdata, uint_t cmd,
    void *retdata);
static cfga_err_t check_options(const char *options);
static void cfga_msg(struct cfga_msg *msgp, const char *str);
static char *findlink(char *ap_phys_id);

static char *
cfga_strs[] = {
NULL,
"\nPCI hotplug specific commands:",
"\t-c [connect|disconnect|configure|unconfigure|insert|remove] "
"ap_id [ap_id...]",
"\t-x enable_slot  ap_id [ap_id...]",
"\t-x disable_slot ap_id [ap_id...]",
"\t-x enable_autoconfig  ap_id [ap_id...]",
"\t-x disable_autoconfig ap_id [ap_id...]",
"\t-x led[=[fault|power|active|attn],mode=[on|off|blink]] ap_id [ap_id...]",
"\tunknown command or option: ",
"success   ",
"failed   ",
"unknown",
NULL
};

#define	MAX_FORMAT 80

#define	ENABLE_SLOT	0
#define	DISABLE_SLOT	1
#define	ENABLE_AUTOCNF	2
#define	DISABLE_AUTOCNF	3
#define	LED		4
#define	MODE		5

/*
 * Board Type
 */
static char *
board_strs[] = {
	/* n */ "???",	/* HPC_BOARD_UNKNOWN */
	/* n */ "hp",	/* HPC_BOARD_PCI_HOTPLUG */
	/* n */ "nhs",	/* HPC_BOARD_CPCI_NON_HS */
	/* n */ "bhs",  /* HPC_BOARD_CPCI_BASIC_HS */
	/* n */ "fhs",	/* HPC_BOARD_CPCI_FULL_HS */
	/* n */ "hs",	/* HPC_BOARD_CPCI_HS */
	/* n */ NULL
};

/*
 * HW functions
 */
static char *
func_strs[] = {
	/* n */ "enable_slot",
	/* n */ "disable_slot",
	/* n */ "enable_autoconfig",
	/* n */ "disable_autoconfig",
	/* n */ "led",
	/* n */ "mode",
	/* n */ NULL
};

/*
 * LED strings
 */
static char *
led_strs[] = {
	/* n */ "fault",	/* HPC_FAULT_LED */
	/* n */ "power",	/* HPC_POWER_LED */
	/* n */ "attn",		/* HPC_ATTN_LED */
	/* n */ "active",	/* HPC_ACTIVE_LED */
	/* n */ NULL
};

#define	FAULT	0
#define	POWER	1
#define	ATTN	2
#define	ACTIVE	3

static char *
mode_strs[] = {
	/* n */ "off",		/* HPC_LED_OFF */
	/* n */ "on",		/* HPC_LED_ON */
	/* n */ "blink",	/* HPC_LED_BLINK */
	/* n */	NULL
};

#define	OFF	0
#define	ON	1
#define	BLINK	2

#define	cfga_errstrs(i)		cfga_errstrs[(i)]

#define	cfga_eid(a, b)		(((a) << 8) + (b))
#define	MAXDEVS			32

typedef enum {
	SOLARIS_SLT_NAME,
	PROM_SLT_NAME
} slt_name_src_t;

struct searcharg {
	char	*devpath;
	char	slotnames[MAXDEVS][MAXNAMELEN];
	int	minor;
	di_prom_handle_t	promp;
	slt_name_src_t	slt_name_src;
};

static void *private_check;

static int
get_occupants(const char *ap_id, hpc_occupant_info_t *occupant)
{
	int rv;
	int fd;
	di_node_t ap_node;
	char *prop_data;
	char *tmp;
	char *ptr;
	struct stat statbuf;
	dev_t devt;

	if ((fd = open(ap_id, O_RDWR)) == -1) {
		DBG(2, ("open = ap_id%s, fd%d\n", ap_id, fd));
		DBG_F(2, (stderr, "open on %s failed\n", ap_id));
		return (CFGA_ERROR);
	}

	if (fstat(fd, &statbuf) == -1) {
		DBG(1, ("stat failed: %i\n", errno));
		(void) close(fd);
		return (CFGA_ERROR);
	}
	(void) close(fd);

	devt = statbuf.st_rdev;

	tmp = (char *)(ap_id + sizeof ("/devices") - 1);
	if ((ptr = strrchr(tmp, ':')) != NULL)
		*ptr = '\0';

	ap_node = di_init(tmp, DINFOPROP | DINFOMINOR);
	if (ap_node == DI_NODE_NIL) {
		DBG(1, ("dead %i\n", errno));
		return (CFGA_ERROR);
	}

#ifdef	PCIHP_DBG
	ptr = di_devfs_path(ap_node);
	DBG(1, ("get_occupants: %s\n", ptr));
	di_devfs_path_free(ptr);
#endif

	if ((rv = di_prop_lookup_strings(devt, ap_node, "pci-occupant",
	    &prop_data)) == -1) {
		DBG(1, ("get_occupants: prop_lookup failed: %i\n", errno));
		di_fini(ap_node);
		return (CFGA_ERROR);
	}

	if (prop_data && (strcmp(prop_data, "") == 0)) {
		di_fini(ap_node);
		occupant->i = 0;
		occupant->id[0] = NULL;
		return (CFGA_OK);
	}

	DBG(1, ("get_occupants: %i devices found\n", rv));
	for (occupant->i = 0; occupant->i < rv; occupant->i++) {
		if (occupant->i >= (HPC_MAX_OCCUPANTS - 1)) {
			occupant->i--;
			break;
		}
		occupant->id[occupant->i] = (char *)malloc(
		    strlen(prop_data) + sizeof ("/devices"));
		(void) snprintf(occupant->id[occupant->i], strlen(prop_data) +
		    sizeof ("/devices"), "/devices%s", prop_data);
		DBG(1, ("%s\n", occupant->id[occupant->i]));
		prop_data += strlen(prop_data) + 1;
	}
	di_fini(ap_node);

	occupant->id[occupant->i] = NULL;

	return (CFGA_OK);
}

/*
 * let rcm know that the device has indeed been removed and clean
 * up rcm data
 */
static void
confirm_rcm(hpc_occupant_info_t *occupant, rcm_handle_t *rhandle)
{
	DBG(1, ("confirm_rcm\n"));

	if (occupant->i == 0) /* nothing was found to ask rcm about */
		return;

	(void) rcm_notify_remove_list(rhandle, occupant->id, 0, NULL);
	(void) rcm_free_handle(rhandle);

	for (; occupant->i >= 0; occupant->i--)
		free(occupant->id[occupant->i]);
}

static void
fail_rcm(hpc_occupant_info_t *occupant, rcm_handle_t *rhandle)
{
	DBG(1, ("fail_rcm\n"));

	if (occupant->i == 0) /* nothing was found to ask rcm about */
		return;

	(void) rcm_notify_online_list(rhandle, occupant->id, 0, NULL);
	(void) rcm_free_handle(rhandle);

	for (; occupant->i >= 0; occupant->i--)
		free(occupant->id[occupant->i]);
}

/*
 * copied from scsi_rcm_info_table
 *
 *      Takes an opaque rcm_info_t pointer and a character pointer, and appends
 * the rcm_info_t data in the form of a table to the given character pointer.
 */
static void
pci_rcm_info_table(rcm_info_t *rinfo, char **table)
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
	if (rinfo == NULL || table == NULL)
		return;

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
	if (tuples == 0)
		return;

	/* Adjust column widths for column headings */
	if ((w = strlen(rsrc)) > w_rsrc)
		w_rsrc = w;
	else if ((w_rsrc - w) % 2)
		w_rsrc++;
	if ((w = strlen(info)) > w_info)
		w_info = w;
	else if ((w_info - w) % 2)
		w_info++;

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
		if (*table == NULL)
			return;
	} else {
		newtable = realloc(*table, strlen(*table) + table_size);
		if (newtable == NULL)
			return;
		else
			*table = newtable;
	}

	/* Place a table header into the string */

	/* The resource header */
	(void) strcat(*table, "\n");
	w = strlen(rsrc);
	for (i = 0; i < ((w_rsrc - w) / 2); i++)
		(void) strcat(*table, " ");
	(void) strcat(*table, rsrc);
	for (i = 0; i < ((w_rsrc - w) / 2); i++)
		(void) strcat(*table, " ");

	/* The information header */
	(void) strcat(*table, "  ");
	w = strlen(info);
	for (i = 0; i < ((w_info - w) / 2); i++)
		(void) strcat(*table, " ");
	(void) strcat(*table, info);
	for (i = 0; i < ((w_info - w) / 2); i++)
		(void) strcat(*table, " ");
	/* Underline the headers */
	(void) strcat(*table, "\n");
	for (i = 0; i < w_rsrc; i++)
		(void) strcat(*table, "-");
	(void) strcat(*table, "  ");
	for (i = 0; i < w_info; i++)
		(void) strcat(*table, "-");

	/* Construct the format string */
	(void) snprintf(format, MAX_FORMAT, "%%-%ds  %%-%ds",
	    (int)w_rsrc, (int)w_info);

	/* Add the tuples to the table string */
	tuple = NULL;
	while ((tuple = rcm_info_next(rinfo, tuple)) != NULL) {
		if ((infostr = rcm_info_info(tuple)) != NULL) {
			(void) strcat(*table, "\n");
			(void) sprintf(&((*table)[strlen(*table)]),
			    format, rcm_info_rsrc(tuple),
			    infostr);
		}
	}
}

/*
 * Figure out what device is about to be unconfigured or disconnected
 * and make sure rcm is ok with it.
 * hangs on to a list of handles so they can then be confirmed or denied
 * if either getting the occupant list or talking to rcm fails
 * return CFGA_ERROR so that things can go on without rcm
 */
static int
check_rcm(const char *ap_id, hpc_occupant_info_t *occupant,
    rcm_handle_t **rhandlep, char **errstring, cfga_flags_t flags)
{
	int rv;
	rcm_info_t *rinfo;
	rcm_handle_t *rhandle;
	uint_t rcmflags;

	if (get_occupants(ap_id, occupant) != 0) {
		DBG(1, ("check_rcm: failed to get occupants\n"));
		return (CFGA_ERROR);
	}

	if (occupant->i == 0) {
		DBG(1, ("check_rcm: no drivers attaching to occupants\n"));
		return (CFGA_OK);
	}

	if (rcm_alloc_handle(NULL, 0, NULL, &rhandle)
	    != RCM_SUCCESS) {
		DBG(1, ("check_rcm: blocked by rcm failure\n"));
		return (CFGA_ERROR);
	}

	rcmflags = (flags & CFGA_FLAG_FORCE) ? RCM_FORCE : 0;
	rv = rcm_request_offline_list(rhandle, occupant->id, rcmflags, &rinfo);

	if (rv == RCM_FAILURE) {
		DBG(1, ("check_rcm: blocked by rcm failure 2\n"));
		pci_rcm_info_table(rinfo, errstring);
		rcm_free_info(rinfo);
		fail_rcm(occupant, rhandle);
		return (CFGA_BUSY);
	}
	if (rv == RCM_CONFLICT) {
		DBG(1, ("check_rcm: blocked by %i\n",
		    rcm_info_pid(rinfo)));
		pci_rcm_info_table(rinfo, errstring);
		rcm_free_info(rinfo);
		(void) rcm_free_handle(rhandle);
		for (; occupant->i >= 0; occupant->i--)
			free(occupant->id[occupant->i]);
		return (CFGA_BUSY);
	}

	rcm_free_info(rinfo);
	*rhandlep = rhandle;

	/* else */
	return (CFGA_OK);
}


/*
 * Transitional Diagram:
 *
 *  empty		unconfigure
 * (remove)	^|  (physically insert card)
 *			|V
 * disconnect	configure
 * "-c DISCONNECT"	^|	"-c CONNECT"
 *				|V	"-c CONFIGURE"
 * connect	unconfigure	->	connect    configure
 *						<-
 *					"-c UNCONFIGURE"
 *
 */
/*ARGSUSED*/
cfga_err_t
cfga_change_state(cfga_cmd_t state_change_cmd, const char *ap_id,
    const char *options, struct cfga_confirm *confp,
    struct cfga_msg *msgp, char **errstring, cfga_flags_t flags)
{
	int rv;
	devctl_hdl_t		dcp;
	devctl_ap_state_t	state;
	ap_rstate_t		rs;
	ap_ostate_t		os;
	hpc_occupant_info_t occupants;
	rcm_handle_t *rhandle;

	if ((rv = check_options(options)) != CFGA_OK) {
		return (rv);
	}

	if (errstring != NULL)
		*errstring = NULL;

	rv = CFGA_OK;
	DBG(1, ("cfga_change_state:(%s)\n", ap_id));

	if ((dcp = devctl_ap_acquire((char *)ap_id, 0)) == NULL) {
		if (rv == EBUSY) {
			cfga_err(errstring, CMD_ACQUIRE, ap_id, 0);
			DBG(1, ("cfga_change_state: device is busy\n"));
			rv = CFGA_BUSY;
		} else
			rv = CFGA_ERROR;
		return (rv);
	}

	if (devctl_ap_getstate(dcp, NULL, &state) == -1) {
		DBG(2, ("cfga_change_state: devctl ap getstate failed\n"));
		cfga_err(errstring, CMD_GETSTAT, ap_id, 0);
		devctl_release((devctl_hdl_t)dcp);
		if (rv == EBUSY)
			rv = CFGA_BUSY;
		else
			rv = CFGA_ERROR;
		return (rv);
	}

	rs = state.ap_rstate;
	os = state.ap_ostate;

	DBG(1, ("cfga_change_state: rs is %d\n", state.ap_rstate));
	DBG(1, ("cfga_change_state: os is %d\n", state.ap_ostate));
	switch (state_change_cmd) {
	case CFGA_CMD_CONNECT:
		if ((rs == AP_RSTATE_EMPTY) ||
		    (rs == AP_RSTATE_CONNECTED) ||
		    (os == AP_OSTATE_CONFIGURED)) {
			cfga_err(errstring, ERR_AP_ERR, 0);
			rv = CFGA_INVAL;
		} else {
			/* Lets connect the slot */
			if (devctl_ap_connect(dcp, NULL) == -1) {
				rv = CFGA_ERROR;
				cfga_err(errstring,
				    CMD_SLOT_CONNECT, 0);
			}
		}

		break;

	case CFGA_CMD_DISCONNECT:
		DBG(1, ("disconnect\n"));

		if (os == AP_OSTATE_CONFIGURED) {
			if ((rv = check_rcm(ap_id, &occupants, &rhandle,
			    errstring, flags)) == CFGA_BUSY) {
				break;
			} else if (rv == CFGA_OK) {
				if (devctl_ap_unconfigure(dcp, NULL) == -1) {
					if (errno == EBUSY)
						rv = CFGA_BUSY;
					else
						rv = CFGA_ERROR;
					cfga_err(errstring,
					    CMD_SLOT_DISCONNECT, 0);
					fail_rcm(&occupants, rhandle);
					break;
				} else {
					confirm_rcm(&occupants, rhandle);
				}
			} else { /* rv == CFGA_ERROR */
				if (devctl_ap_unconfigure(dcp, NULL) == -1) {
					if (errno == EBUSY)
						rv = CFGA_BUSY;
					else
						rv = CFGA_ERROR;
					break;
				} else {
					rv = CFGA_OK;
				}
			}
		}

		if (rs == AP_RSTATE_CONNECTED) {
			if (devctl_ap_disconnect(dcp, NULL) == -1) {
				rv = CFGA_ERROR;
				cfga_err(errstring, CMD_SLOT_DISCONNECT, 0);
				break;
			}
		} else {
			cfga_err(errstring, ERR_AP_ERR, 0);
			rv = CFGA_INVAL;
		}

		break;

	case CFGA_CMD_CONFIGURE:
		if (rs == AP_RSTATE_DISCONNECTED) {
			if (devctl_ap_connect(dcp, NULL) == -1) {
				rv = CFGA_ERROR;
				cfga_err(errstring, CMD_SLOT_CONNECT, 0);
				break;
			}
		}

		/*
		 * for multi-func device we allow multiple
		 * configure on the same slot because one
		 * func can be configured and other one won't
		 */
		if (devctl_ap_configure(dcp, NULL) == -1) {
			rv = CFGA_ERROR;
			cfga_err(errstring, CMD_SLOT_CONFIGURE, 0);
			if ((rs == AP_RSTATE_DISCONNECTED) &&
			    (devctl_ap_disconnect(dcp, NULL) == -1)) {
				rv = CFGA_ERROR;
				cfga_err(errstring,
				    CMD_SLOT_CONFIGURE, 0);
			}
			break;
		}

		break;

	case CFGA_CMD_UNCONFIGURE:
		DBG(1, ("unconfigure\n"));

		if (os == AP_OSTATE_CONFIGURED) {
			if ((rv = check_rcm(ap_id, &occupants, &rhandle,
			    errstring, flags)) == CFGA_BUSY) {
				break;
			} else if (rv == CFGA_OK) {
				if (devctl_ap_unconfigure(dcp, NULL) == -1) {
					if (errno == EBUSY)
						rv = CFGA_BUSY;
					else {
						if (errno == ENOTSUP)
							rv = CFGA_OPNOTSUPP;
						else
							rv = CFGA_ERROR;
					}
					cfga_err(errstring,
					    CMD_SLOT_UNCONFIGURE, 0);
					fail_rcm(&occupants, rhandle);
				} else {
					confirm_rcm(&occupants, rhandle);
				}
			} else { /* rv == CFGA_ERROR */
				if (devctl_ap_unconfigure(dcp, NULL) == -1) {
					if (errno == EBUSY)
						rv = CFGA_BUSY;
					else {
						if (errno == ENOTSUP)
							rv = CFGA_OPNOTSUPP;
						else
							rv = CFGA_ERROR;
					}
					cfga_err(errstring,
					    CMD_SLOT_UNCONFIGURE, 0);
				} else {
					rv = CFGA_OK;
				}
			}
		} else {
			cfga_err(errstring, ERR_AP_ERR, 0);
			rv = CFGA_INVAL;
		}

		DBG(1, ("uncofigure rv:(%i)\n", rv));
		break;

	case CFGA_CMD_LOAD:
		if ((os == AP_OSTATE_UNCONFIGURED) &&
		    (rs == AP_RSTATE_DISCONNECTED)) {
			if (devctl_ap_insert(dcp, NULL) == -1) {
				rv = CFGA_ERROR;
				cfga_err(errstring, CMD_SLOT_INSERT, 0);
			}
		} else {
			cfga_err(errstring, ERR_AP_ERR, 0);
			rv = CFGA_INVAL;
		}

		break;

	case CFGA_CMD_UNLOAD:
		if ((os == AP_OSTATE_UNCONFIGURED) &&
		    (rs == AP_RSTATE_DISCONNECTED)) {
			if (devctl_ap_remove(dcp, NULL) == -1) {
				rv = CFGA_ERROR;
				cfga_err(errstring, CMD_SLOT_REMOVE, 0);
			}
		} else {
				cfga_err(errstring, ERR_AP_ERR, 0);
				rv = CFGA_INVAL;
			}

		break;

	default:
		rv = CFGA_OPNOTSUPP;
		break;
	}

	devctl_release((devctl_hdl_t)dcp);
	return (rv);
}

/*
 * Building iocdatat to pass it to nexus
 *
 *	iocdata->cmd ==  HPC_CTRL_ENABLE_SLOT/HPC_CTRL_DISABLE_SLOT
 *			HPC_CTRL_ENABLE_AUTOCFG/HPC_CTRL_DISABLE_AUTOCFG
 *			HPC_CTRL_GET_LED_STATE/HPC_CTRL_SET_LED_STATE
 *			HPC_CTRL_GET_SLOT_STATE/HPC_CTRL_GET_SLOT_INFO
 *			HPC_CTRL_DEV_CONFIGURE/HPC_CTRL_DEV_UNCONFIGURE
 *			HPC_CTRL_GET_BOARD_TYPE
 *
 */
static void
build_control_data(struct hpc_control_data *iocdata, uint_t cmd,
    void *retdata)
{
	iocdata->cmd = cmd;
	iocdata->data = retdata;
}

/*
 * building logical name from ap_id
 */
/*ARGSUSED2*/
static void
get_logical_name(const char *ap_id, char *buf, dev_t rdev)
{
	char *bufptr, *bufptr2, *pci, *apid;

	DBG(1, ("get_logical_name: %s\n", ap_id));

	if ((apid = malloc(MAXPATHLEN)) == NULL) {
		DBG(1, ("malloc failed\n"));
		return;
	}

	(void) memset(apid, 0, MAXPATHLEN);
	(void) strncpy(apid, ap_id, strlen(ap_id));

	/* needs to look for last /, not first */
	bufptr = strrchr(apid, '/');

	bufptr2 = strrchr(apid, ':');
	pci = ++bufptr;
	bufptr = strchr(pci, ',');
	if (bufptr != NULL) {
		*bufptr = '\0';
	}

	bufptr = strchr(pci, '@');
	if (bufptr != NULL) {
		*bufptr = '\0';
		bufptr++;
	}

	DBG(1, ("%s\n%s\n%s\n", pci, bufptr, bufptr2));

	(void) strcat(buf, pci);
	(void) strcat(buf, bufptr);
	(void) strcat(buf, bufptr2);
	free(apid);
}

static cfga_err_t
prt_led_mode(const char *ap_id, int repeat, char **errstring,
    struct cfga_msg *msgp)
{
	hpc_led_info_t	power_led_info = {HPC_POWER_LED, 0};
	hpc_led_info_t	fault_led_info = {HPC_FAULT_LED, 0};
	hpc_led_info_t	attn_led_info = {HPC_ATTN_LED, 0};
	hpc_led_info_t	active_led_info = {HPC_ACTIVE_LED, 0};
	struct hpc_control_data iocdata;
	struct stat	statbuf;
	char  *buff;
	int	fd;
	hpc_slot_info_t		slot_info;
	char *cp, line[MAXLINE];
	int len = MAXLINE;

	DBG(1, ("prt_led_mod function\n"));
	if (!repeat)
		cfga_msg(msgp, "Ap_Id\t\t\tLed");

	if ((fd = open(ap_id, O_RDWR)) == -1) {
		DBG(2, ("open = ap_id%s, fd%d\n", ap_id, fd));
		DBG_F(2, (stderr, "open on %s failed\n", ap_id));
		cfga_err(errstring, CMD_OPEN,  ap_id, 0);
		return (CFGA_ERROR);
	}

	if (fstat(fd, &statbuf) == -1) {
		DBG(2, ("fstat = ap_id%s, fd%d\n", ap_id, fd));
		DBG_F(2, (stderr, "fstat on %s failed\n", ap_id));
		cfga_err(errstring, CMD_FSTAT, ap_id, 0);
		return (CFGA_ERROR);
	}

	if ((buff = malloc(MAXPATHLEN)) == NULL) {
		cfga_err(errstring, "malloc ", 0);
		return (CFGA_ERROR);
	}

	(void) memset(buff, 0, MAXPATHLEN);

	DBG(1, ("ioctl boardtype\n"));

	build_control_data(&iocdata, HPC_CTRL_GET_SLOT_INFO,
	    (void *)&slot_info);

	if (ioctl(fd, DEVCTL_AP_CONTROL, &iocdata) == -1) {
		get_logical_name(ap_id, slot_info.pci_slot_name, 0);
		DBG(1, ("ioctl failed slotinfo: %s\n",
		    slot_info.pci_slot_name));
	} else {

		/*
		 * the driver will report back things like hpc0_slot0
		 * this needs to be changed to things like pci1:hpc0_slot0
		 */
		if (fix_ap_name(buff, ap_id, slot_info.pci_slot_name,
		    errstring) != CFGA_OK) {
			free(buff);
			(void) close(fd);
			return (CFGA_ERROR);
		}
		DBG(1, ("ioctl slotinfo: %s\n", buff));
	}

	cp = line;
	(void) snprintf(cp, len, "%s\t\t", buff);
	len -= strlen(cp);
	cp += strlen(cp);

	free(buff);

	build_control_data(&iocdata, HPC_CTRL_GET_LED_STATE, &power_led_info);
	if (ioctl(fd, DEVCTL_AP_CONTROL, &iocdata) == -1) {
		(void) snprintf(cp, len, "%s=%s,",
		    led_strs[power_led_info.led], cfga_strs[UNKNOWN]);
		len -= strlen(cp);
		cp += strlen(cp);
	} else {
		(void) snprintf(cp, len, "%s=%s,", led_strs[power_led_info.led],
		    mode_strs[power_led_info.state]);
		len -= strlen(cp);
		cp += strlen(cp);
	}

	DBG(1, ("%s:%d\n", led_strs[power_led_info.led], power_led_info.state));

	build_control_data(&iocdata, HPC_CTRL_GET_LED_STATE, &fault_led_info);
	if (ioctl(fd, DEVCTL_AP_CONTROL, &iocdata) == -1) {
		(void) snprintf(cp, len, "%s=%s,",
		    led_strs[fault_led_info.led], cfga_strs[UNKNOWN]);
		len -= strlen(cp);
		cp += strlen(cp);
	} else {
		(void) snprintf(cp, len, "%s=%s,",
		    led_strs[fault_led_info.led],
		    mode_strs[fault_led_info.state]);
		len -= strlen(cp);
		cp += strlen(cp);
	}
	DBG(1, ("%s:%d\n", led_strs[fault_led_info.led], fault_led_info.state));

	build_control_data(&iocdata, HPC_CTRL_GET_LED_STATE, &attn_led_info);
	if (ioctl(fd, DEVCTL_AP_CONTROL, &iocdata) == -1) {
		(void) snprintf(cp, len, "%s=%s,",
		    led_strs[attn_led_info.led], cfga_strs[UNKNOWN]);
		len -= strlen(cp);
		cp += strlen(cp);
	} else {
		(void) snprintf(cp, len, "%s=%s,",
		    led_strs[attn_led_info.led],
		    mode_strs[attn_led_info.state]);
		len -= strlen(cp);
		cp += strlen(cp);
	}
	DBG(1, ("%s:%d\n", led_strs[attn_led_info.led], attn_led_info.state));

	build_control_data(&iocdata, HPC_CTRL_GET_LED_STATE, &active_led_info);
	if (ioctl(fd, DEVCTL_AP_CONTROL, &iocdata) == -1) {
		(void) snprintf(cp, len, "%s=%s", led_strs[active_led_info.led],
		    cfga_strs[UNKNOWN]);
	} else {
		(void) snprintf(cp, len, "%s=%s",
		    led_strs[active_led_info.led],
		    mode_strs[active_led_info.state]);
	}
	cfga_msg(msgp, line);	/* print the message */
	DBG(1, ("%s:%d\n", led_strs[active_led_info.led],
	    active_led_info.state));

	(void) close(fd);

	return (CFGA_OK);
}

/*ARGSUSED*/
cfga_err_t
cfga_private_func(const char *function, const char *ap_id,
    const char *options, struct cfga_confirm *confp,
    struct cfga_msg *msgp, char **errstring, cfga_flags_t flags)
{
	char *str;
	int   len, fd, i = 0, repeat = 0;
	char buf[MAXNAMELEN];
	char ptr;
	hpc_led_info_t	led_info;
	struct hpc_control_data	iocdata;
	cfga_err_t rv;

	DBG(1, ("cfgadm_private_func: ap_id:%s\n", ap_id));
	DBG(2, ("  options: %s\n", (options == NULL)?"null":options));
	DBG(2, ("  confp: %x\n", confp));
	DBG(2, ("  cfga_msg: %x\n", cfga_msg));
	DBG(2, ("  flag: %d\n", flags));

	if ((rv = check_options(options)) != CFGA_OK) {
		return (rv);
	}

	if (private_check == confp)
		repeat = 1;
	else
		private_check = (void*)confp;

	/* XXX change const 6 to func_str[i] != NULL */
	for (i = 0, str = func_strs[i], len = strlen(str); i < 6; i++) {
		str = func_strs[i];
		len = strlen(str);
		if (strncmp(function, str, len) == 0)
			break;
	}

	switch (i) {
		case ENABLE_SLOT:
			build_control_data(&iocdata,
			    HPC_CTRL_ENABLE_SLOT, 0);
			break;
		case DISABLE_SLOT:
			build_control_data(&iocdata,
			    HPC_CTRL_DISABLE_SLOT, 0);
			break;
		case ENABLE_AUTOCNF:
			build_control_data(&iocdata,
			    HPC_CTRL_ENABLE_AUTOCFG, 0);
			break;
		case DISABLE_AUTOCNF:
			build_control_data(&iocdata,
			    HPC_CTRL_DISABLE_AUTOCFG, 0);
			break;
		case LED:
			/* set mode */
			ptr = function[len++];
			if (ptr == '=') {
				str = (char *)function;
				for (str = (str+len++), i = 0; *str != ',';
				    i++, str++) {
					if (i == (MAXNAMELEN - 1))
						break;

					buf[i] = *str;
					DBG_F(2, (stdout, "%c\n", buf[i]));
				}
				buf[i] = '\0'; str++;
				DBG(2, ("buf = %s\n", buf));

				/* ACTIVE=3,ATTN=2,POWER=1,FAULT=0 */
				if (strcmp(buf, led_strs[POWER]) == 0)
					led_info.led = HPC_POWER_LED;
				else if (strcmp(buf, led_strs[FAULT]) == 0)
					led_info.led = HPC_FAULT_LED;
				else if (strcmp(buf, led_strs[ATTN]) == 0)
					led_info.led = HPC_ATTN_LED;
				else if (strcmp(buf, led_strs[ACTIVE]) == 0)
					led_info.led = HPC_ACTIVE_LED;
				else return (CFGA_INVAL);

				len = strlen(func_strs[MODE]);
				if ((strncmp(str, func_strs[MODE], len) == 0) &&
				    (*(str+(len)) == '=')) {
					for (str = (str+(++len)), i = 0;
					    *str != NULL; i++, str++) {
						buf[i] = *str;
					}
				}
				buf[i] = '\0';
				DBG(2, ("buf_mode= %s\n", buf));

				/* ON = 1, OFF = 0 */
				if (strcmp(buf, mode_strs[ON]) == 0)
					led_info.state = HPC_LED_ON;
				else if (strcmp(buf, mode_strs[OFF]) == 0)
					led_info.state = HPC_LED_OFF;
				else if (strcmp(buf, mode_strs[BLINK]) == 0)
					led_info.state = HPC_LED_BLINK;
				else return (CFGA_INVAL);

				/* sendin  */
				build_control_data(&iocdata,
				    HPC_CTRL_SET_LED_STATE,
				    (void *)&led_info);
				break;
			} else if (ptr == '\0') {
				/* print mode */
				DBG(1, ("Print mode\n"));
				return (prt_led_mode(ap_id, repeat, errstring,
				    msgp));
			}
			/* FALLTHROUGH */
		default:
			DBG(1, ("default\n"));
			errno = EINVAL;
			return (CFGA_INVAL);
	}

	if ((fd = open(ap_id, O_RDWR)) == -1) {
		DBG(1, ("open failed\n"));
		return (CFGA_ERROR);
	}

	DBG(1, ("open = ap_id=%s, fd=%d\n", ap_id, fd));

	if (ioctl(fd, DEVCTL_AP_CONTROL, &iocdata) == -1) {
		DBG(1, ("ioctl failed\n"));
		(void) close(fd);
		return (CFGA_ERROR);
	}

	(void) close(fd);

	return (CFGA_OK);
}

/*ARGSUSED*/
cfga_err_t cfga_test(const char *ap_id, const char *options,
    struct cfga_msg *msgp, char **errstring, cfga_flags_t flags)
{
	cfga_err_t rv;
	if (errstring != NULL)
		*errstring = NULL;

	if ((rv = check_options(options)) != CFGA_OK) {
		return (rv);
	}

	DBG(1, ("cfga_test:(%s)\n", ap_id));
	/* will need to implement pci CTRL command */
	return (CFGA_NOTSUPP);
}

static int
fixup_slotname(int rval, int *intp, struct searcharg *slotarg)
{

/*
 * The slot-names property describes the external labeling of add-in slots.
 * This property is an encoded array, an integer followed by a list of
 * strings. The return value from di_prop_lookup_ints for slot-names is -1.
 * The expected return value should be the number of elements.
 * Di_prop_decode_common does not decode encoded data from software,
 * such as the solaris device tree, unlike from the prom.
 * Di_prop_decode_common takes the size of the encoded data and mods
 * it with the size of int. The size of the encoded data for slot-names is 9
 * and the size of int is 4, yielding a non zero result. A value of -1 is used
 * to indicate that the number of elements can not be determined.
 * Di_prop_decode_common can be modified to decode encoded data from the solaris
 * device tree.
 */

	if ((slotarg->slt_name_src == PROM_SLT_NAME) && (rval == -1)) {
		return (DI_WALK_TERMINATE);
	} else {
		int i;
		char *tmptr = (char *)(intp+1);
		DBG(1, ("slot-bitmask: %x \n", *intp));

		rval = (rval -1) * 4;

		for (i = 0; i <= slotarg->minor; i++) {
			DBG(2, ("curr slot-name: %s \n", tmptr));

			if (i >= MAXDEVS)
				return (DI_WALK_TERMINATE);

			if ((*intp >> i) & 1) {
				/* assign tmptr */
				DBG(2, ("slot-name: %s \n", tmptr));
				if (i == slotarg->minor)
					(void) strcpy(slotarg->slotnames[i],
					    tmptr);
				/* wind tmptr to next \0 */
				while (*tmptr != '\0') {
					tmptr++;
				}
				tmptr++;
			} else {
				/* point at unknown string */
				if (i == slotarg->minor)
					(void) strcpy(slotarg->slotnames[i],
					    "unknown");
			}
		}
	}
	return (DI_WALK_TERMINATE);
}

static int
find_slotname(di_node_t din, di_minor_t dim, void *arg)
{
	struct searcharg *slotarg = (struct searcharg *)arg;
	di_prom_handle_t ph = (di_prom_handle_t)slotarg->promp;
	di_prom_prop_t	prom_prop;
	di_prop_t	solaris_prop;
	int *intp, rval;
	char *devname;
	char fulldevname[MAXNAMELEN];

	slotarg->minor = dim->dev_minor % 256;

	DBG(2, ("minor number:(%i)\n", slotarg->minor));
	DBG(2, ("hot plug slots found so far:(%i)\n", 0));

	if ((devname = di_devfs_path(din)) != NULL) {
		(void) snprintf(fulldevname, MAXNAMELEN,
		    "/devices%s:%s", devname, di_minor_name(dim));
		di_devfs_path_free(devname);
	}

	if (strcmp(fulldevname, slotarg->devpath) == 0) {

		/*
		 * Check the Solaris device tree first
		 * in the case of a DR operation
		 */
		solaris_prop = di_prop_hw_next(din, DI_PROP_NIL);
		while (solaris_prop != DI_PROP_NIL) {
			if (strcmp("slot-names", di_prop_name(solaris_prop))
			    == 0) {
				rval = di_prop_lookup_ints(DDI_DEV_T_ANY,
				    din, di_prop_name(solaris_prop), &intp);
				slotarg->slt_name_src = SOLARIS_SLT_NAME;

				return (fixup_slotname(rval, intp, slotarg));
			}
			solaris_prop = di_prop_hw_next(din, solaris_prop);
		}

		/*
		 * Check the prom device tree which is populated at boot.
		 * If this fails, give up and set the slot name to null.
		 */
		prom_prop = di_prom_prop_next(ph, din, DI_PROM_PROP_NIL);
		while (prom_prop != DI_PROM_PROP_NIL) {
			if (strcmp("slot-names", di_prom_prop_name(prom_prop))
			    == 0) {
				rval = di_prom_prop_lookup_ints(ph,
				    din, di_prom_prop_name(prom_prop), &intp);
				slotarg->slt_name_src = PROM_SLT_NAME;

				return (fixup_slotname(rval, intp, slotarg));
			}
			prom_prop = di_prom_prop_next(ph, din, prom_prop);
		}
		*slotarg->slotnames[slotarg->minor] = '\0';
		return (DI_WALK_TERMINATE);
	} else
		return (DI_WALK_CONTINUE);
}

static int
find_physical_slot_names(const char *devcomp, struct searcharg *slotarg)
{
	di_node_t root_node;

	DBG(1, ("find_physical_slot_names\n"));

	if ((root_node = di_init("/", DINFOCPYALL|DINFOPATH)) == DI_NODE_NIL) {
		DBG(1, ("di_init() failed\n"));
		return (NULL);
	}

	slotarg->devpath = (char *)devcomp;

	if ((slotarg->promp = di_prom_init()) == DI_PROM_HANDLE_NIL) {
		DBG(1, ("di_prom_init() failed\n"));
		di_fini(root_node);
		return (NULL);
	}

	(void) di_walk_minor(root_node, "ddi_ctl:attachment_point:pci",
	    0, (void *)slotarg, find_slotname);

	di_prom_fini(slotarg->promp);
	di_fini(root_node);
	if (slotarg->slotnames[0] != NULL)
		return (0);
	else
		return (-1);
}

static void
get_type(hpc_board_type_t boardtype, hpc_card_info_t cardinfo, char *buf)
{
	int i;

	DBG(1, ("class: %i\n", cardinfo.base_class));
	DBG(1, ("subclass: %i\n", cardinfo.sub_class));

	if (cardinfo.base_class == PCI_CLASS_NONE) {
		TPCT("unknown");
		return;
	}

	for (i = 0; i < class_pci_items; i++) {
		if ((cardinfo.base_class == class_pci[i].base_class) &&
		    (cardinfo.sub_class == class_pci[i].sub_class) &&
		    (cardinfo.prog_class == class_pci[i].prog_class)) {
			TPCT(class_pci[i].short_desc);
			break;
		}
	}

	if (i == class_pci_items)
		TPCT("unknown");

	TPCT("/");
	switch (boardtype) {
	case HPC_BOARD_PCI_HOTPLUG:
	case HPC_BOARD_CPCI_NON_HS:
	case HPC_BOARD_CPCI_BASIC_HS:
	case HPC_BOARD_CPCI_FULL_HS:
	case HPC_BOARD_CPCI_HS:
		TPCT(board_strs[boardtype]);
		break;
	case HPC_BOARD_UNKNOWN:
	default:
		TPCT(board_strs[HPC_BOARD_UNKNOWN]);
	}
}

/*
 * call-back function for di_devlink_walk
 * if the link lives in /dev/cfg copy its name
 */
static int
found_devlink(di_devlink_t link, void *ap_log_id)
{
	if (strncmp("/dev/cfg/", di_devlink_path(link), 9) == 0) {
		/* copy everything but /dev/cfg/ */
		(void) strcpy((char *)ap_log_id, di_devlink_path(link) + 9);
		DBG(1, ("found_devlink: %s\n", (char *)ap_log_id));
		return (DI_WALK_TERMINATE);
	}
	return (DI_WALK_CONTINUE);
}

/*
 * Walk throught the cached /dev link tree looking for links to the ap
 * if none are found return an error
 */
static cfga_err_t
check_devlinks(char *ap_log_id, const char *ap_id)
{
	di_devlink_handle_t hdl;

	DBG(1, ("check_devlinks: %s\n", ap_id));

	hdl = di_devlink_init(NULL, 0);

	if (strncmp("/devices/", ap_id, 9) == 0) {
		/* ap_id is a valid minor_path with /devices prepended */
		(void) di_devlink_walk(hdl, NULL, ap_id + 8, DI_PRIMARY_LINK,
		    (void *)ap_log_id, found_devlink);
	} else {
		DBG(1, ("check_devlinks: invalid ap_id: %s\n", ap_id));
		return (CFGA_ERROR);
	}

	(void) di_devlink_fini(&hdl);

	if (ap_log_id[0] != '\0')
		return (CFGA_OK);
	else
		return (CFGA_ERROR);
}

/*
 * most of this is needed to compensate for
 * differences between various platforms
 */
static cfga_err_t
fix_ap_name(char *ap_log_id, const char *ap_id, char *slot_name,
    char **errstring)
{
	char *buf;
	char *tmp;
	char *ptr;

	di_node_t ap_node;

	ap_log_id[0] = '\0';

	if (check_devlinks(ap_log_id, ap_id) == CFGA_OK)
		return (CFGA_OK);

	DBG(1, ("fix_ap_name: %s\n", ap_id));

	if ((buf = malloc(strlen(ap_id) + 1)) == NULL) {
		DBG(1, ("malloc failed\n"));
		return (CFGA_ERROR);
	}
	(void) strcpy(buf, ap_id);
	tmp = buf + sizeof ("/devices") - 1;

	ptr = strchr(tmp, ':');
	ptr[0] = '\0';

	DBG(1, ("fix_ap_name: %s\n", tmp));

	ap_node = di_init(tmp, DINFOMINOR);
	if (ap_node == DI_NODE_NIL) {
		cfga_err(errstring, "di_init ", 0);
		DBG(1, ("fix_ap_name: failed to snapshot node\n"));
		return (CFGA_ERROR);
	}

	(void) snprintf(ap_log_id, strlen(ap_id) + 1, "%s%i:%s",
	    di_driver_name(ap_node), di_instance(ap_node), slot_name);

	DBG(1, ("fix_ap_name: %s\n", ap_log_id));

	di_fini(ap_node);

	free(buf);
	return (CFGA_OK);
}


static int
findlink_cb(di_devlink_t devlink, void *arg)
{
	(*(char **)arg) = strdup(di_devlink_path(devlink));

	return (DI_WALK_TERMINATE);
}

/*
 * returns an allocated string containing the full path to the devlink for
 * <ap_phys_id> in the devlink database; we expect only one devlink per
 * <ap_phys_id> so we return the first encountered
 */
static char *
findlink(char *ap_phys_id)
{
	di_devlink_handle_t hdl;
	char *path = NULL;

	hdl = di_devlink_init(NULL, 0);

	if (strncmp("/devices/", ap_phys_id, 9) == 0)
		ap_phys_id += 8;

	(void) di_devlink_walk(hdl, "^cfg/.+$", ap_phys_id, DI_PRIMARY_LINK,
	    (void *)&path, findlink_cb);

	(void) di_devlink_fini(&hdl);
	return (path);
}


/*
 * returns CFGA_OK if it can succesfully retrieve the devlink info associated
 * with devlink for <ap_phys_id> which will be returned through <ap_info>
 */
cfga_err_t
get_dli(char *dlpath, char *ap_info, int ap_info_sz)
{
	int fd;

	fd = di_dli_openr(dlpath);
	if (fd < 0)
		return (CFGA_ERROR);

	(void) read(fd, ap_info, ap_info_sz);
	ap_info[ap_info_sz - 1] = '\0';

	di_dli_close(fd);
	return (CFGA_OK);
}


/*ARGSUSED*/
cfga_err_t
cfga_list_ext(const char *ap_id, cfga_list_data_t **cs,
    int *nlist, const char *options, const char *listopts, char **errstring,
    cfga_flags_t flags)
{
	devctl_hdl_t		dcp;
	struct hpc_control_data	iocdata;
	devctl_ap_state_t	state;
	hpc_board_type_t	boardtype;
	hpc_card_info_t		cardinfo;
	hpc_slot_info_t		slot_info;
	struct	searcharg	slotname_arg;
	int			fd;
	int			rv = CFGA_OK;
	char			*dlpath = NULL;

	if ((rv = check_options(options)) != CFGA_OK) {
		return (rv);
	}

	if (errstring != NULL)
		*errstring = NULL;

	(void) memset(&slot_info, 0, sizeof (hpc_slot_info_t));

	DBG(1, ("cfga_list_ext:(%s)\n", ap_id));

	if (cs == NULL || nlist == NULL) {
		rv = CFGA_ERROR;
		return (rv);
	}

	*nlist = 1;

	if ((*cs = malloc(sizeof (cfga_list_data_t))) == NULL) {
		cfga_err(errstring, "malloc ", 0);
		DBG(1, ("malloc failed\n"));
		rv = CFGA_ERROR;
		return (rv);
	}
	(void) memset(*cs, 0, sizeof (cfga_list_data_t));

	if ((dcp = devctl_ap_acquire((char *)ap_id, 0)) == NULL) {
		cfga_err(errstring, CMD_GETSTAT, 0);
		DBG(2, ("cfga_list_ext::(devctl_ap_acquire())\n"));
		rv = CFGA_ERROR;
		return (rv);
	}

	if (devctl_ap_getstate(dcp, NULL, &state) == -1) {
		cfga_err(errstring, ERR_AP_ERR, ap_id, 0);
		devctl_release((devctl_hdl_t)dcp);
		DBG(2, ("cfga_list_ext::(devctl_ap_getstate())\n"));
		rv = CFGA_ERROR;
		return (rv);
	}

	switch (state.ap_rstate) {
		case AP_RSTATE_EMPTY:
			(*cs)->ap_r_state = CFGA_STAT_EMPTY;
			DBG(2, ("ap_rstate = CFGA_STAT_EMPTY\n"));
			break;
		case AP_RSTATE_DISCONNECTED:
			(*cs)->ap_r_state = CFGA_STAT_DISCONNECTED;
			DBG(2, ("ap_rstate = CFGA_STAT_DISCONNECTED\n"));
			break;
		case AP_RSTATE_CONNECTED:
			(*cs)->ap_r_state = CFGA_STAT_CONNECTED;
			DBG(2, ("ap_rstate = CFGA_STAT_CONNECTED\n"));
			break;
	default:
		cfga_err(errstring, CMD_GETSTAT, ap_id, 0);
		rv = CFGA_ERROR;
		devctl_release((devctl_hdl_t)dcp);
		return (rv);
	}

	switch (state.ap_ostate) {
		case AP_OSTATE_CONFIGURED:
			(*cs)->ap_o_state = CFGA_STAT_CONFIGURED;
			DBG(2, ("ap_ostate = CFGA_STAT_CONFIGURED\n"));
			break;
		case AP_OSTATE_UNCONFIGURED:
			(*cs)->ap_o_state = CFGA_STAT_UNCONFIGURED;
			DBG(2, ("ap_ostate = CFGA_STAT_UNCONFIGURED\n"));
			break;
	default:
		cfga_err(errstring, CMD_GETSTAT, ap_id, 0);
		rv = CFGA_ERROR;
		devctl_release((devctl_hdl_t)dcp);
		return (rv);
	}

	switch (state.ap_condition) {
		case AP_COND_OK:
			(*cs)->ap_cond = CFGA_COND_OK;
			DBG(2, ("ap_cond = CFGA_COND_OK\n"));
			break;
		case AP_COND_FAILING:
			(*cs)->ap_cond = CFGA_COND_FAILING;
			DBG(2, ("ap_cond = CFGA_COND_FAILING\n"));
			break;
		case AP_COND_FAILED:
			(*cs)->ap_cond = CFGA_COND_FAILED;
			DBG(2, ("ap_cond = CFGA_COND_FAILED\n"));
			break;
		case AP_COND_UNUSABLE:
			(*cs)->ap_cond = CFGA_COND_UNUSABLE;
			DBG(2, ("ap_cond = CFGA_COND_UNUSABLE\n"));
			break;
		case AP_COND_UNKNOWN:
			(*cs)->ap_cond = CFGA_COND_UNKNOWN;
			DBG(2, ("ap_cond = CFGA_COND_UNKNOW\n"));
			break;
	default:
		cfga_err(errstring, CMD_GETSTAT, ap_id, 0);
		rv = CFGA_ERROR;
		devctl_release((devctl_hdl_t)dcp);
		return (rv);
	}
	(*cs)->ap_busy = (int)state.ap_in_transition;

	devctl_release((devctl_hdl_t)dcp);

	if ((fd = open(ap_id, O_RDWR)) == -1) {
		cfga_err(errstring, ERR_AP_ERR, ap_id, 0);
		(*cs)->ap_status_time = 0;
		boardtype = HPC_BOARD_UNKNOWN;
		cardinfo.base_class = PCI_CLASS_NONE;
		get_logical_name(ap_id, slot_info.pci_slot_name, 0);
		DBG(2, ("open on %s failed\n", ap_id));
		goto cont;
	}
	DBG(1, ("open = ap_id=%s, fd=%d\n", ap_id, fd));

	(*cs)->ap_status_time = state.ap_last_change;

	/* need board type and a way to get to hpc_slot_info */
	build_control_data(&iocdata, HPC_CTRL_GET_BOARD_TYPE,
	    (void *)&boardtype);

	if (ioctl(fd, DEVCTL_AP_CONTROL, &iocdata) == -1) {
		boardtype = HPC_BOARD_UNKNOWN;
	}
	DBG(1, ("ioctl boardtype\n"));

	build_control_data(&iocdata, HPC_CTRL_GET_SLOT_INFO,
	    (void *)&slot_info);

	if (ioctl(fd, DEVCTL_AP_CONTROL, &iocdata) == -1) {
		get_logical_name(ap_id, slot_info.pci_slot_name, 0);
		DBG(1, ("ioctl failed slotinfo: %s\n",
		    slot_info.pci_slot_name));
	} else {

		/*
		 * the driver will report back things like hpc0_slot0
		 * this needs to be changed to things like pci1:hpc0_slot0
		 */
		rv = fix_ap_name((*cs)->ap_log_id,
		    ap_id, slot_info.pci_slot_name, errstring);
		DBG(1, ("ioctl slotinfo: %s\n", (*cs)->ap_log_id));
	}

	build_control_data(&iocdata, HPC_CTRL_GET_CARD_INFO,
	    (void *)&cardinfo);

	if (ioctl(fd, DEVCTL_AP_CONTROL, &iocdata) == -1) {
		DBG(1, ("ioctl failed\n"));
		cardinfo.base_class = PCI_CLASS_NONE;
	}

	DBG(1, ("ioctl cardinfo: %d\n", cardinfo.base_class));
	DBG(1, ("ioctl subclass: %d\n", cardinfo.sub_class));
	DBG(1, ("ioctl headertype: %d\n", cardinfo.header_type));

	(void) close(fd);

cont:
	(void) strcpy((*cs)->ap_phys_id, ap_id);    /* physical path of AP */

	dlpath = findlink((*cs)->ap_phys_id);
	if (dlpath != NULL) {
		if (get_dli(dlpath, (*cs)->ap_info,
		    sizeof ((*cs)->ap_info)) != CFGA_OK)
			(*cs)->ap_info[0] = '\0';
		free(dlpath);
	}

	if ((*cs)->ap_log_id[0] == '\0')
		(void) strcpy((*cs)->ap_log_id, slot_info.pci_slot_name);

	if ((*cs)->ap_info[0] == '\0') {
		/* slot_names of bus node  */
		if (find_physical_slot_names(ap_id, &slotname_arg) != -1)
			(void) strcpy((*cs)->ap_info,
			    slotname_arg.slotnames[slotname_arg.minor]);
	}

	/* class_code/subclass/boardtype */
	get_type(boardtype, cardinfo, (*cs)->ap_type);

	DBG(1, ("cfga_list_ext return success\n"));
	rv = CFGA_OK;

	return (rv);
}

/*
 * This routine prints a single line of help message
 */
static void
cfga_msg(struct cfga_msg *msgp, const char *str)
{
	DBG(2, ("<%s>", str));

	if (msgp == NULL || msgp->message_routine == NULL)
		return;

	(*msgp->message_routine)(msgp->appdata_ptr, str);
	(*msgp->message_routine)(msgp->appdata_ptr, "\n");
}

static cfga_err_t
check_options(const char *options)
{
	struct cfga_msg *msgp = NULL;

	if (options) {
		cfga_msg(msgp, dgettext(TEXT_DOMAIN, cfga_strs[HELP_UNKNOWN]));
		cfga_msg(msgp, options);
		return (CFGA_INVAL);
	}
	return (CFGA_OK);
}

/*ARGSUSED*/
cfga_err_t
cfga_help(struct cfga_msg *msgp, const char *options, cfga_flags_t flags)
{
	if (options) {
		cfga_msg(msgp, dgettext(TEXT_DOMAIN, cfga_strs[HELP_UNKNOWN]));
		cfga_msg(msgp, options);
	}
	DBG(1, ("cfga_help\n"));

	cfga_msg(msgp, dgettext(TEXT_DOMAIN, cfga_strs[HELP_HEADER]));
	cfga_msg(msgp, cfga_strs[HELP_CONFIG]);
	cfga_msg(msgp, cfga_strs[HELP_ENABLE_SLOT]);
	cfga_msg(msgp, cfga_strs[HELP_DISABLE_SLOT]);
	cfga_msg(msgp, cfga_strs[HELP_ENABLE_AUTOCONF]);
	cfga_msg(msgp, cfga_strs[HELP_DISABLE_AUTOCONF]);
	cfga_msg(msgp, cfga_strs[HELP_LED_CNTRL]);
	return (CFGA_OK);
}

/*
 * cfga_err() accepts a variable number of message IDs and constructs
 * a corresponding error string which is returned via the errstring argument.
 * cfga_err() calls gettext() to internationalize proper messages.
 */
static void
cfga_err(char **errstring, ...)
{
	int a;
	int i;
	int n;
	int len;
	int flen;
	char *p;
	char *q;
	char *s[32];
	char *failed;
	va_list ap;

	/*
	 * If errstring is null it means user in not interested in getting
	 * error status. So we don't do all the work
	 */
	if (errstring == NULL) {
		return;
	}
	va_start(ap, errstring);

	failed = dgettext(TEXT_DOMAIN, cfga_strs[FAILED]);
	flen = strlen(failed);

	for (n = len = 0; (a = va_arg(ap, int)) != 0; n++) {
		switch (a) {
		case CMD_GETSTAT:
		case CMD_LIST:
		case CMD_SLOT_CONNECT:
		case CMD_SLOT_DISCONNECT:
		case CMD_SLOT_CONFIGURE:
		case CMD_SLOT_UNCONFIGURE:
			p =  cfga_errstrs(a);
			len += (strlen(p) + flen);
			s[n] = p;
			s[++n] = cfga_strs[FAILED];

			DBG(2, ("<%s>", p));
			DBG(2, (cfga_strs[FAILED]));
			break;

		case ERR_CMD_INVAL:
		case ERR_AP_INVAL:
		case ERR_OPT_INVAL:
		case ERR_AP_ERR:
			switch (a) {
			case ERR_CMD_INVAL:
				p = dgettext(TEXT_DOMAIN,
				    cfga_errstrs[ERR_CMD_INVAL]);
				break;
			case ERR_AP_INVAL:
				p = dgettext(TEXT_DOMAIN,
				    cfga_errstrs[ERR_AP_INVAL]);
				break;
			case ERR_OPT_INVAL:
				p = dgettext(TEXT_DOMAIN,
				    cfga_errstrs[ERR_OPT_INVAL]);
				break;
			case ERR_AP_ERR:
				p = dgettext(TEXT_DOMAIN,
				    cfga_errstrs[ERR_AP_ERR]);
				break;
			}

			if ((q = va_arg(ap, char *)) != NULL) {
				len += (strlen(p) + strlen(q));
				s[n] = p;
				s[++n] = q;
				DBG(2, ("<%s>", p));
				DBG(2, ("<%s>", q));
				break;
			} else {
				len += strlen(p);
				s[n] = p;

			}
			DBG(2, ("<%s>", p));
			break;

		default:
			n--;
			break;
		}
	}

	DBG(2, ("\n"));
	va_end(ap);

	if ((p = calloc(len + 1, 1)) == NULL)
		return;

	for (i = 0; i < n; i++) {
		(void) strlcat(p, s[i], len + 1);
		DBG(2, ("i:%d, %s\n", i, s[i]));
	}

	*errstring = p;
#ifdef	DEBUG
	printf("%s\n", *errstring);
	free(*errstring);
#endif
}

/*
 * cfga_ap_id_cmp -- use default_ap_id_cmp() in libcfgadm
 */
