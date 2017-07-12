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
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2016 by Delphix. All rights reserved.
 */

/*
 *	Plugin library for PCI Express and PCI (SHPC) hotplug controller
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

#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/dditypes.h>
#include <sys/pci.h>
#include <libintl.h>

#include <dirent.h>
#include <limits.h>
#include <sys/mkdev.h>
#include "../../../../uts/common/sys/hotplug/pci/pcie_hp.h"
#include "../../../../common/pci/pci_strings.h"
#include <libhotplug.h>

extern const struct pci_class_strings_s class_pci[];
extern int class_pci_items;

#define	MSG_HOTPLUG_DISABLED \
	"Error: hotplug service is probably not running, " \
	"please use 'svcadm enable hotplug' to enable the service. " \
	"See cfgadm_shp(1M) for more details."

#define	DEVICES_DIR		"/devices"
#define	SLASH			"/"
#define	GET_DYN(a)	(strstr((a), CFGA_DYN_SEP))

/*
 * Set the version number
 */
int cfga_version = CFGA_HSL_V2;

#ifdef	DEBUG
#define	SHP_DBG	1
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
#ifdef	SHP_DBG
int	shp_debug = 1;
#define	DBG(level, args) \
	{ if (shp_debug >= (level)) printf args; }
#define	DBG_F(level, args) \
	{ if (shp_debug >= (level)) fprintf args; }
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

extern int errno;

static void cfga_err(char **errstring, ...);
static cfga_err_t fix_ap_name(char *ap_log_id, const char *ap_id,
    char *slot_name, char **errstring);
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

typedef	enum { PCIEHPC_FAULT_LED, PCIEHPC_POWER_LED, PCIEHPC_ATTN_LED,
	PCIEHPC_ACTIVE_LED} pciehpc_led_t;

typedef	enum { PCIEHPC_BOARD_UNKNOWN, PCIEHPC_BOARD_PCI_HOTPLUG }
	pciehpc_board_type_t;

/*
 * Board Type
 */
static char *
board_strs[] = {
	/* n */ "???",	/* PCIEHPC_BOARD_UNKNOWN */
	/* n */ "hp",	/* PCIEHPC_BOARD_PCI_HOTPLUG */
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
	/* n */ "fault",	/* PCIEHPC_FAULT_LED */
	/* n */ "power",	/* PCIEHPC_POWER_LED */
	/* n */ "attn",		/* PCIEHPC_ATTN_LED */
	/* n */ "active",	/* PCIEHPC_ACTIVE_LED */
	/* n */ NULL
};

static char *
led_strs2[] = {
	/* n */ PCIEHPC_PROP_LED_FAULT,		/* PCIEHPC_FAULT_LED */
	/* n */ PCIEHPC_PROP_LED_POWER,		/* PCIEHPC_POWER_LED */
	/* n */ PCIEHPC_PROP_LED_ATTN,		/* PCIEHPC_ATTN_LED */
	/* n */ PCIEHPC_PROP_LED_ACTIVE,	/* PCIEHPC_ACTIVE_LED */
	/* n */ NULL
};

#define	FAULT	0
#define	POWER	1
#define	ATTN	2
#define	ACTIVE	3

static char *
mode_strs[] = {
	/* n */ "off",		/* OFF */
	/* n */ "on",		/* ON */
	/* n */ "blink",	/* BLINK */
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

/*
 * Return the corresponding hp node for a given ap_id, it is the caller's
 * responsibility to call hp_fini() to free the snapshot.
 */
static cfga_err_t
physpath2node(const char *physpath, char **errstring, hp_node_t *nodep)
{
	char *rpath;
	char *cp;
	hp_node_t node;
	size_t len;
	char *errmsg;

	if (getuid() != 0 && geteuid() != 0)
		return (CFGA_ERROR);

	if ((rpath = malloc(strlen(physpath) + 1)) == NULL)
		return (CFGA_ERROR);

	(void) strcpy(rpath, physpath);

	/* Remove devices prefix (if any) */
	len = strlen(DEVICES_DIR);
	if (strncmp(rpath, DEVICES_DIR SLASH, len + strlen(SLASH)) == 0) {
		(void) memmove(rpath, rpath + len,
		    strlen(rpath + len) + 1);
	}

	/* Remove dynamic component if any */
	if ((cp = GET_DYN(rpath)) != NULL) {
		*cp = '\0';
	}

	/* Remove minor name (if any) */
	if ((cp = strrchr(rpath, ':')) == NULL) {
		free(rpath);
		return (CFGA_INVAL);
	}

	*cp = '\0';
	cp++;

	DBG(1, ("rpath=%s,cp=%s\n", rpath, cp));
	if ((node = hp_init(rpath, cp, 0)) == NULL) {
		if (errno == EBADF) {
			/* No reponse to operations on the door file. */
			assert(errstring != NULL);
			*errstring = strdup(MSG_HOTPLUG_DISABLED);
			free(rpath);
			return (CFGA_NOTSUPP);
		}
		free(rpath);
		return (CFGA_ERROR);
	}

	free(rpath);

	*nodep = node;
	return (CFGA_OK);
}

typedef struct error_size_cb_arg {
	size_t	rsrc_width;
	size_t	info_width;
	int	cnt;
} error_size_cb_arg_t;

/*
 * Callback function for hp_traverse(), to sum up the
 * maximum length for error message display.
 */
static int
error_sizeup_cb(hp_node_t node, void *arg)
{
	error_size_cb_arg_t	*sizearg = (error_size_cb_arg_t *)arg;
	size_t 			len;

	/* Only process USAGE nodes */
	if (hp_type(node) != HP_NODE_USAGE)
		return (HP_WALK_CONTINUE);

	sizearg->cnt++;

	/* size up resource name */
	len = strlen(hp_name(node));
	if (sizearg->rsrc_width < len)
		sizearg->rsrc_width = len;

	/* size up usage description */
	len = strlen(hp_usage(node));
	if (sizearg->info_width < len)
		sizearg->info_width = len;

	return (HP_WALK_CONTINUE);
}

typedef struct error_sum_cb_arg {
	char **table;
	char *format;
} error_sum_cb_arg_t;

/*
 * Callback function for hp_traverse(), to add the error
 * message to the table.
 */
static int
error_sumup_cb(hp_node_t node, void *arg)
{
	error_sum_cb_arg_t *sumarg = (error_sum_cb_arg_t *)arg;
	char **table = sumarg->table;
	char *format = sumarg->format;

	/* Only process USAGE nodes */
	if (hp_type(node) != HP_NODE_USAGE)
		return (HP_WALK_CONTINUE);

	(void) strcat(*table, "\n");
	(void) sprintf(&((*table)[strlen(*table)]),
	    format, hp_name(node), hp_usage(node));

	return (HP_WALK_CONTINUE);
}

/*
 * Takes an opaque rcm_info_t pointer and a character pointer, and appends
 * the rcm_info_t data in the form of a table to the given character pointer.
 */
static void
pci_rcm_info_table(hp_node_t node, char **table)
{
	int i;
	size_t w;
	size_t width = 0;
	size_t w_rsrc = 0;
	size_t w_info = 0;
	size_t table_size = 0;
	uint_t tuples = 0;
	char *rsrc;
	char *info;
	char *newtable;
	static char format[MAX_FORMAT];
	const char *infostr;
	error_size_cb_arg_t sizearg;
	error_sum_cb_arg_t sumarg;

	/* Protect against invalid arguments */
	if (table == NULL)
		return;

	/* Set localized table header strings */
	rsrc = dgettext(TEXT_DOMAIN, "Resource");
	info = dgettext(TEXT_DOMAIN, "Information");

	/* A first pass, to size up the RCM information */
	sizearg.rsrc_width = strlen(rsrc);
	sizearg.info_width = strlen(info);
	sizearg.cnt = 0;
	(void) hp_traverse(node, &sizearg, error_sizeup_cb);

	/* If nothing was sized up above, stop early */
	if (sizearg.cnt == 0)
		return;

	w_rsrc = sizearg.rsrc_width;
	w_info = sizearg.info_width;
	tuples = sizearg.cnt;

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
	sumarg.table = table;
	sumarg.format = format;
	(void) hp_traverse(node, &sumarg, error_sumup_cb);
}

/*
 * Figure out the target kernel state for a given cfgadm
 * change-state operation.
 */
static cfga_err_t
cfga_target_state(cfga_cmd_t state_change_cmd, int *state)
{
	switch (state_change_cmd) {
	case CFGA_CMD_CONNECT:
		*state = DDI_HP_CN_STATE_POWERED;
		break;
	case CFGA_CMD_DISCONNECT:
		*state = DDI_HP_CN_STATE_PRESENT;
		break;
	case CFGA_CMD_CONFIGURE:
		*state = DDI_HP_CN_STATE_ENABLED;
		break;
	case CFGA_CMD_UNCONFIGURE:
		*state = DDI_HP_CN_STATE_POWERED;
		break;
	default:
		return (CFGA_ERROR);
	}

	return (CFGA_OK);
}

/*
 * Translate kernel state to cfgadm receptacle state and occupant state.
 */
static cfga_err_t
cfga_get_state(hp_node_t connector, ap_rstate_t *rs, ap_ostate_t *os)
{
	int state;
	hp_node_t port;

	state = hp_state(connector);

	/* Receptacle state */
	switch (state) {
	case DDI_HP_CN_STATE_EMPTY:
		*rs = AP_RSTATE_EMPTY;
		break;
	case DDI_HP_CN_STATE_PRESENT:
		*rs = AP_RSTATE_DISCONNECTED;
		break;
	case DDI_HP_CN_STATE_POWERED:
	case DDI_HP_CN_STATE_ENABLED:
		*rs = AP_RSTATE_CONNECTED;
		break;
		/*
		 * Connector state can only be one of
		 * Empty, Present, Powered, Enabled.
		 */
	default:
		return (CFGA_ERROR);
	}

	/*
	 * Occupant state
	 */
	port = hp_child(connector);
	while (port != NULL) {
		DBG(1, ("cfga_get_state:(%x)\n", hp_state(port)));

		/*
		 * Mark occupant state as "configured" if at least one of the
		 * associated ports is at state "offline" or above. Driver
		 * attach ("online" state) is not necessary here.
		 */
		if (hp_state(port) >= DDI_HP_CN_STATE_OFFLINE)
			break;

		port = hp_sibling(port);
	}

	if (port != NULL)
		*os = AP_OSTATE_CONFIGURED;
	else
		*os = AP_OSTATE_UNCONFIGURED;

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
	int		rv, state, new_state;
	uint_t		hpflags = 0;
	hp_node_t	node;
	hp_node_t	results = NULL;

	if ((rv = check_options(options)) != CFGA_OK) {
		return (rv);
	}

	if (errstring != NULL)
		*errstring = NULL;

	rv = CFGA_OK;
	DBG(1, ("cfga_change_state:(%s)\n", ap_id));

	rv = physpath2node(ap_id, errstring, &node);
	if (rv != CFGA_OK)
		return (rv);

	/*
	 * Check for the FORCE flag.  It is only used
	 * for DISCONNECT or UNCONFIGURE state changes.
	 */
	if (flags & CFGA_FLAG_FORCE)
		hpflags |= HPFORCE;

	state = hp_state(node);

	/*
	 * Which state should we drive to ?
	 */
	if ((state_change_cmd != CFGA_CMD_LOAD) &&
	    (state_change_cmd != CFGA_CMD_UNLOAD)) {
		if (cfga_target_state(state_change_cmd,
		    &new_state) != CFGA_OK) {
			hp_fini(node);
			return (CFGA_ERROR);
		}
	}

	DBG(1, ("cfga_change_state: state is %d\n", state));
	switch (state_change_cmd) {
	case CFGA_CMD_CONNECT:
		DBG(1, ("connect\n"));
		if (state == DDI_HP_CN_STATE_EMPTY) {
			cfga_err(errstring, ERR_AP_ERR, 0);
			rv = CFGA_INVAL;
		} else if (state == DDI_HP_CN_STATE_PRESENT) {
			/* Connect the slot */
			if (hp_set_state(node, 0, new_state, &results) != 0) {
				rv = CFGA_ERROR;
				cfga_err(errstring, CMD_SLOT_CONNECT, 0);
			}
		}
		break;

	case CFGA_CMD_DISCONNECT:
		DBG(1, ("disconnect\n"));
		if (state == DDI_HP_CN_STATE_EMPTY) {
			cfga_err(errstring, ERR_AP_ERR, 0);
			rv = CFGA_INVAL;
		} else if (state > DDI_HP_CN_STATE_PRESENT) {
			/* Disconnect the slot */
			rv = hp_set_state(node, hpflags, new_state, &results);
			if (rv != 0) {
				if (rv == EBUSY)
					rv = CFGA_BUSY;
				else
					rv = CFGA_ERROR;

				if (results) {
					pci_rcm_info_table(results, errstring);
					hp_fini(results);
				} else {
					cfga_err(errstring,
					    CMD_SLOT_DISCONNECT, 0);
				}
			}
		}
		break;

	case CFGA_CMD_CONFIGURE:
		/*
		 * for multi-func device we allow multiple
		 * configure on the same slot because one
		 * func can be configured and other one won't
		 */
		DBG(1, ("configure\n"));
		if (state == DDI_HP_CN_STATE_EMPTY) {
			cfga_err(errstring, ERR_AP_ERR, 0);
			rv = CFGA_INVAL;
		} else if (hp_set_state(node, 0, new_state, &results) != 0) {
			rv = CFGA_ERROR;
			cfga_err(errstring, CMD_SLOT_CONFIGURE, 0);
		}
		break;

	case CFGA_CMD_UNCONFIGURE:
		DBG(1, ("unconfigure\n"));
		if (state == DDI_HP_CN_STATE_EMPTY) {
			cfga_err(errstring, ERR_AP_ERR, 0);
			rv = CFGA_INVAL;
		} else if (state >= DDI_HP_CN_STATE_ENABLED) {
			rv = hp_set_state(node, hpflags, new_state, &results);
			if (rv != 0) {
				if (rv == EBUSY)
					rv = CFGA_BUSY;
				else
					rv = CFGA_ERROR;

				if (results) {
					pci_rcm_info_table(results, errstring);
					hp_fini(results);
				} else {
					cfga_err(errstring,
					    CMD_SLOT_UNCONFIGURE, 0);
				}
			}
		}
		DBG(1, ("unconfigure rv:(%i)\n", rv));
		break;

	case CFGA_CMD_LOAD:
		/* do nothing, just produce error msg as is */
		if (state < DDI_HP_CN_STATE_POWERED) {
			rv = CFGA_ERROR;
			cfga_err(errstring, CMD_SLOT_INSERT, 0);
		} else {
			cfga_err(errstring, ERR_AP_ERR, 0);
			rv = CFGA_INVAL;
		}
		break;

	case CFGA_CMD_UNLOAD:
		/* do nothing, just produce error msg as is */
		if (state < DDI_HP_CN_STATE_POWERED) {
			rv = CFGA_ERROR;
			cfga_err(errstring, CMD_SLOT_REMOVE, 0);
		} else {
			cfga_err(errstring, ERR_AP_ERR, 0);
			rv = CFGA_INVAL;
		}
		break;

	default:
		rv = CFGA_OPNOTSUPP;
		break;
	}

	hp_fini(node);
	return (rv);
}

char *
get_val_from_result(char *result)
{
	char *tmp;

	tmp = strchr(result, '=');
	if (tmp == NULL)
		return (NULL);

	tmp++;
	return (tmp);
}

static cfga_err_t
prt_led_mode(const char *ap_id, int repeat, char **errstring,
    struct cfga_msg *msgp)
{
	pciehpc_led_t led;
	hp_node_t node;
	char *buff;
	char *buf;
	char *cp, line[MAXLINE];
	char *tmp;
	char *format;
	char *result;
	int i, n, rv;
	int len = MAXLINE;

	pciehpc_led_t states[] = {
		PCIEHPC_POWER_LED,
		PCIEHPC_FAULT_LED,
		PCIEHPC_ATTN_LED,
		PCIEHPC_ACTIVE_LED
	};

	DBG(1, ("prt_led_mod function\n"));
	if (!repeat)
		cfga_msg(msgp, "Ap_Id\t\t\tLed");

	rv = physpath2node(ap_id, errstring, &node);
	if (rv != CFGA_OK)
		return (rv);

	if ((buff = malloc(MAXPATHLEN)) == NULL) {
		hp_fini(node);
		cfga_err(errstring, "malloc ", 0);
		return (CFGA_ERROR);
	}

	(void) memset(buff, 0, MAXPATHLEN);

	if (fix_ap_name(buff, ap_id, hp_name(node),
	    errstring) != CFGA_OK) {
		hp_fini(node);
		free(buff);
		return (CFGA_ERROR);
	}

	cp = line;
	(void) snprintf(cp, len, "%s\t\t", buff);
	len -= strlen(cp);
	cp += strlen(cp);

	free(buff);

	n = sizeof (states)/sizeof (pciehpc_led_t);
	for (i = 0; i < n; i++) {
		led = states[i];

		format = (i == n - 1) ? "%s=%s" : "%s=%s,";
		if (hp_get_private(node, led_strs2[led], &result) != 0) {
			(void) snprintf(cp, len, format,
			    led_strs[led], cfga_strs[UNKNOWN]);
			len -= strlen(cp);
			cp += strlen(cp);
			DBG(1, ("%s:%s\n", led_strs[led], cfga_strs[UNKNOWN]));
		} else {
			/*
			 * hp_get_private() will return back things like
			 * "led_fault=off", transform it to cfgadm desired
			 * format.
			 */
			tmp = get_val_from_result(result);
			if (tmp == NULL) {
				free(result);
				hp_fini(node);
				return (CFGA_ERROR);
			}

			(void) snprintf(cp, len, format,
			    led_strs[led], tmp);
			len -= strlen(cp);
			cp += strlen(cp);
			DBG(1, ("%s:%s\n", led_strs[led], tmp));
			free(result);
		}
	}

	cfga_msg(msgp, line);	/* print the message */

	hp_fini(node);

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
	cfga_err_t rv;
	char *led, *mode;
	hp_node_t node;
	char *result;

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

	for (i = 0, str = func_strs[i], len = strlen(str);
	    func_strs[i] != NULL; i++) {
		str = func_strs[i];
		len = strlen(str);
		if (strncmp(function, str, len) == 0)
			break;
	}

	switch (i) {
		case ENABLE_SLOT:
		case DISABLE_SLOT:
			/* pass through */
		case ENABLE_AUTOCNF:
		case DISABLE_AUTOCNF:
			/* no action needed */
			return (CFGA_OK);
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
					led = PCIEHPC_PROP_LED_POWER;
				else if (strcmp(buf, led_strs[FAULT]) == 0)
					led = PCIEHPC_PROP_LED_FAULT;
				else if (strcmp(buf, led_strs[ATTN]) == 0)
					led = PCIEHPC_PROP_LED_ATTN;
				else if (strcmp(buf, led_strs[ACTIVE]) == 0)
					led = PCIEHPC_PROP_LED_ACTIVE;
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
					mode = PCIEHPC_PROP_VALUE_ON;
				else if (strcmp(buf, mode_strs[OFF]) == 0)
					mode = PCIEHPC_PROP_VALUE_OFF;
				else if (strcmp(buf, mode_strs[BLINK]) == 0)
					mode = PCIEHPC_PROP_VALUE_BLINK;
				else return (CFGA_INVAL);

				/* sendin  */
				memset(buf, 0, sizeof (buf));
				snprintf(buf, sizeof (buf), "%s=%s",
				    led, mode);
				buf[MAXNAMELEN - 1] = '\0';

				break;
			} else if (ptr == '\0') {
				/* print mode */
				DBG(1, ("Print mode\n"));
				return (prt_led_mode(ap_id, repeat, errstring,
				    msgp));
			}
		default:
			DBG(1, ("default\n"));
			errno = EINVAL;
			return (CFGA_INVAL);
	}

	rv = physpath2node(ap_id, errstring, &node);
	if (rv != CFGA_OK)
		return (rv);

	if (hp_set_private(node, buf, &result) != 0) {
		hp_fini(node);
		return (CFGA_ERROR);
	}

	hp_fini(node);
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
static int
fixup_slotname(int rval, int *intp, struct searcharg *slotarg)
{
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

	if ((root_node = di_init("/", DINFOCPYALL|DINFOPATH))
	    == DI_NODE_NIL) {
		DBG(1, ("di_init() failed\n"));
		return (-1);
	}

	slotarg->devpath = (char *)devcomp;

	if ((slotarg->promp = di_prom_init()) == DI_PROM_HANDLE_NIL) {
		DBG(1, ("di_prom_init() failed\n"));
		di_fini(root_node);
		return (-1);
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
get_type(const char *boardtype, const char *cardtype, char *buf)
{
/* for type string assembly in get_type() */
#define	TPCT(s)	(void) strlcat(buf, (s), CFGA_TYPE_LEN)

	int i;

	if (strcmp(cardtype, "unknown") == 0) {
		TPCT("unknown");
		return;
	}

	TPCT(cardtype);
	TPCT("/");

	if (strcmp(boardtype, PCIEHPC_PROP_VALUE_PCIHOTPLUG) == 0)
		TPCT(board_strs[PCIEHPC_BOARD_PCI_HOTPLUG]);
	else
		TPCT(board_strs[PCIEHPC_BOARD_UNKNOWN]);
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

static cfga_err_t
cfga_get_condition(hp_node_t node, ap_condition_t *cond)
{
	char *condition;
	char *tmpc;
	cfga_err_t ret = CFGA_OK;

	/* "condition" bus specific commands */
	if (hp_get_private(node, PCIEHPC_PROP_SLOT_CONDITION,
	    &tmpc) != 0) {
		*cond = AP_COND_UNKNOWN;
		return (CFGA_ERROR);
	}

	condition = get_val_from_result(tmpc);

	if (strcmp(condition, PCIEHPC_PROP_COND_OK) == 0)
		*cond = AP_COND_OK;
	else if (strcmp(condition, PCIEHPC_PROP_COND_FAILING) == 0)
		*cond = AP_COND_FAILING;
	else if (strcmp(condition, PCIEHPC_PROP_COND_FAILED) == 0)
		*cond = AP_COND_FAILED;
	else if (strcmp(condition, PCIEHPC_PROP_COND_UNUSABLE) == 0)
		*cond = AP_COND_UNUSABLE;
	else if (strcmp(condition, PCIEHPC_PROP_COND_UNKNOWN) == 0)
		*cond = AP_COND_UNKNOWN;
	else
		ret = CFGA_ERROR;

	free(tmpc);
	return (ret);
}

/*ARGSUSED*/
cfga_err_t
cfga_list_ext(const char *ap_id, cfga_list_data_t **cs,
    int *nlist, const char *options, const char *listopts, char **errstring,
    cfga_flags_t flags)
{
	char			*boardtype;
	char			*cardtype;
	char			*tmpb = NULL, *tmpc = NULL;
	struct	searcharg	slotname_arg;
	int			fd;
	int			rv = CFGA_OK;
	char			*dlpath = NULL;
	hp_node_t		node;
	ap_rstate_t		rs;
	ap_ostate_t		os;
	ap_condition_t		cond;

	if ((rv = check_options(options)) != CFGA_OK) {
		return (rv);
	}

	if (errstring != NULL)
		*errstring = NULL;

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

	rv = physpath2node(ap_id, errstring, &node);
	if (rv != CFGA_OK) {
		DBG(1, ("physpath2node failed\n"));
		return (rv);
	}

	if (cfga_get_state(node, &rs, &os) != CFGA_OK) {
		DBG(1, ("cfga_get_state failed\n"));
		hp_fini(node);
		return (CFGA_ERROR);
	}

	switch (rs) {
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
		hp_fini(node);
		return (rv);
	}

	switch (os) {
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
		hp_fini(node);
		return (rv);
	}

	(void) cfga_get_condition(node, &cond);

	switch (cond) {
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
		hp_fini(node);
		return (rv);
	}
	/*
	 * We're not busy since the entrance into the kernel has been
	 * sync'ed via libhotplug.
	 */
	(*cs)->ap_busy = 0;

	/* last change */
	(*cs)->ap_status_time = hp_last_change(node);

	/* board type */
	if (hp_get_private(node, PCIEHPC_PROP_BOARD_TYPE, &tmpb) != 0)
		boardtype = PCIEHPC_PROP_VALUE_UNKNOWN;
	else
		boardtype = get_val_from_result(tmpb);

	/* card type */
	if (hp_get_private(node, PCIEHPC_PROP_CARD_TYPE, &tmpc) != 0)
		cardtype = PCIEHPC_PROP_VALUE_UNKNOWN;
	else
		cardtype = get_val_from_result(tmpc);

	/* logical ap_id */
	rv = fix_ap_name((*cs)->ap_log_id, ap_id,
	    hp_name(node), errstring);
	DBG(1, ("logical id: %s\n", (*cs)->ap_log_id));
	/* physical ap_id */
	(void) strcpy((*cs)->ap_phys_id, ap_id);    /* physical path of AP */

	/* information */
	dlpath = findlink((*cs)->ap_phys_id);
	if (dlpath != NULL) {
		if (get_dli(dlpath, (*cs)->ap_info,
		    sizeof ((*cs)->ap_info)) != CFGA_OK)
			(*cs)->ap_info[0] = '\0';
		free(dlpath);
	}

	if ((*cs)->ap_log_id[0] == '\0')
		(void) strcpy((*cs)->ap_log_id, hp_name(node));

	if ((*cs)->ap_info[0] == '\0') {
		/* slot_names of bus node  */
		if (find_physical_slot_names(ap_id, &slotname_arg) != -1)
			(void) strcpy((*cs)->ap_info,
			    slotname_arg.slotnames[slotname_arg.minor]);
	}

	/* class_code/subclass/boardtype */
	get_type(boardtype, cardtype, (*cs)->ap_type);

	DBG(1, ("cfga_list_ext return success\n"));
	rv = CFGA_OK;

	free(tmpb);
	free(tmpc);
	hp_fini(node);
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
	 * If errstring is null it means user is not interested in getting
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
	DBG(2, ("%s\n", *errstring));
}

/*
 * cfga_ap_id_cmp -- use default_ap_id_cmp() in libcfgadm
 */
