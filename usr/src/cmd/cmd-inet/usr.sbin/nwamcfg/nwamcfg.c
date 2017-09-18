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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2016, Chris Fraire <cfraire@me.com>.
 */

/*
 * nwamcfg is a lex/yacc based command interpreter used to manage network
 * configurations.  The lexer (see nwamcfg_lex.l) builds up tokens, which
 * the grammar (see nwamcfg_grammar.y) builds up into commands, some of
 * which takes resources and/or properties as arguments.
 */

#include <arpa/inet.h>
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <libnwam.h>
#include <libtecla.h>
#include <locale.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <unistd.h>

#include "nwamcfg.h"

#if !defined(TEXT_DOMAIN)		/* should be defined by cc -D */
#define	TEXT_DOMAIN	"SYS_TEST"	/* Use this only if it wasn't */
#endif

struct help {
	uint_t		cmd_num;
	const char	*cmd_name;
	const char	*cmd_usage;
};

extern int yyparse(void);
extern int lex_lineno;

#define	MAX_LINE_LEN	1024
#define	MAX_CMD_HIST	1024

/* usage of commands */
#define	SHELP_CANCEL	"cancel"
#define	SHELP_CLEAR	"clear <prop-name>"
#define	SHELP_COMMIT	"commit"
#define	SHELP_CREATE	"create [-t <template>] <object-type> [<class>] " \
			"<object-name>"
#define	SHELP_DESTROY	"destroy {-a | <object-type> [<class>] <object-name>}"
#define	SHELP_END	"end"
#define	SHELP_EXIT	"exit"
#define	SHELP_EXPORT	"export [-d] [-f <output-file>] " \
			"[<object-type> [<class>] <object-name>]"
#define	SHELP_GET	"get [-V] <prop-name>"
#define	SHELP_HELP	"help [command-name]"
#define	SHELP_LIST	"list [-a] [<object-type> [<class>] <object-name>]"
#define	SHELP_REVERT	"revert"
#define	SHELP_SELECT	"select <object-type> [<class>] <object-name>"
#define	SHELP_SET	"set <prop-name>=<value1>[,<value2>...]"
#define	SHELP_VERIFY	"verify"
#define	SHELP_WALK	"walkprop [-a]"

/*
 * Scope Definitions:
 * Locations, ENMs, NCPs and Known WLANs are one scope level below global (GBL).
 * NCUs are one more level beneath the NCP scope.
 * Because the commands in Locations/ENM/Known WLAN and NCP level are different,
 * the scope are divided accordingly.
 *     GBL->LOC, GBL->ENM, GBL->WLAN or GBL->NCP->NCU
 */
#define	NWAM_SCOPE_GBL	0
#define	NWAM_SCOPE_LOC	1
#define	NWAM_SCOPE_ENM	2
#define	NWAM_SCOPE_WLAN	3
#define	NWAM_SCOPE_NCP	4
#define	NWAM_SCOPE_NCU	5

/* delimiter used for list of values */
#define	NWAM_VALUE_DELIMITER_CHAR	','
#define	NWAM_VALUE_DELIMITER_STR	","

/* the max number of values for an enum used by some properties in libnwam */

/*
 * All arrays/tables are null-terminated, rather than defining the length of
 * the array.  When looping, check for NULL rather than using the size.
 */

static struct help helptab[] = {
	{ CMD_CANCEL,	"cancel",	SHELP_CANCEL	},
	{ CMD_CLEAR,	"clear",	SHELP_CLEAR	},
	{ CMD_COMMIT,	"commit",	SHELP_COMMIT	},
	{ CMD_CREATE,	"create",	SHELP_CREATE	},
	{ CMD_DESTROY,	"destroy",	SHELP_DESTROY	},
	{ CMD_END,	"end",		SHELP_END	},
	{ CMD_EXIT,	"exit",		SHELP_EXIT	},
	{ CMD_EXPORT,	"export",	SHELP_EXPORT	},
	{ CMD_GET,	"get",		SHELP_GET	},
	{ CMD_HELP,	"help",		SHELP_HELP	},
	{ CMD_LIST,	"list",		SHELP_LIST	},
	{ CMD_REVERT,	"revert",	SHELP_REVERT	},
	{ CMD_SELECT,	"select",	SHELP_SELECT	},
	{ CMD_SET,	"set",		SHELP_SET	},
	{ CMD_VERIFY,	"verify",	SHELP_VERIFY	},
	{ CMD_WALKPROP,	"walkprop",	SHELP_WALK	},
	{ 0, NULL, NULL }
};

/* These *must* match the order of the RT1_ define's from nwamcfg.h */
static char *res1_types[] = {
	"unknown",
	"loc",
	"ncp",
	"enm",
	"wlan",
	NULL
};

/* These *must* match the order of the RT2_ define's from nwamcfg.h */
static char *res2_types[] = {
	"unknown",
	"ncu",
	NULL
};

/*
 * No array for NCU_CLASS_.  The #define's in nwamcfg.h matches the
 * enum nwam_ncu_class_t in libnwam and thus uses libnwam functions to
 * retrieve the string representation.
 */

/* These *MUST* match the order of the PT_ define's from nwamcfg.h */
static char *pt_types[] = {
	"unknown",
	NWAM_NCU_PROP_ACTIVATION_MODE,
	NWAM_NCU_PROP_ENABLED,
	NWAM_NCU_PROP_TYPE,
	NWAM_NCU_PROP_CLASS,
	NWAM_NCU_PROP_PARENT_NCP,
	NWAM_NCU_PROP_PRIORITY_GROUP,
	NWAM_NCU_PROP_PRIORITY_MODE,
	NWAM_NCU_PROP_LINK_MAC_ADDR,
	NWAM_NCU_PROP_LINK_AUTOPUSH,
	NWAM_NCU_PROP_LINK_MTU,
	NWAM_NCU_PROP_IP_VERSION,
	NWAM_NCU_PROP_IPV4_ADDRSRC,
	NWAM_NCU_PROP_IPV4_ADDR,
	NWAM_NCU_PROP_IPV4_DEFAULT_ROUTE,
	NWAM_NCU_PROP_IPV6_ADDRSRC,
	NWAM_NCU_PROP_IPV6_ADDR,
	NWAM_NCU_PROP_IPV6_DEFAULT_ROUTE,
	NWAM_LOC_PROP_CONDITIONS,
	NWAM_ENM_PROP_FMRI,
	NWAM_ENM_PROP_START,
	NWAM_ENM_PROP_STOP,
	NWAM_LOC_PROP_NAMESERVICES,
	NWAM_LOC_PROP_NAMESERVICES_CONFIG_FILE,
	NWAM_LOC_PROP_DNS_NAMESERVICE_CONFIGSRC,
	NWAM_LOC_PROP_DNS_NAMESERVICE_DOMAIN,
	NWAM_LOC_PROP_DNS_NAMESERVICE_SERVERS,
	NWAM_LOC_PROP_DNS_NAMESERVICE_SEARCH,
	NWAM_LOC_PROP_NIS_NAMESERVICE_CONFIGSRC,
	NWAM_LOC_PROP_NIS_NAMESERVICE_SERVERS,
	NWAM_LOC_PROP_LDAP_NAMESERVICE_CONFIGSRC,
	NWAM_LOC_PROP_LDAP_NAMESERVICE_SERVERS,
	NWAM_LOC_PROP_DEFAULT_DOMAIN,
	NWAM_LOC_PROP_NFSV4_DOMAIN,
	NWAM_LOC_PROP_IPFILTER_CONFIG_FILE,
	NWAM_LOC_PROP_IPFILTER_V6_CONFIG_FILE,
	NWAM_LOC_PROP_IPNAT_CONFIG_FILE,
	NWAM_LOC_PROP_IPPOOL_CONFIG_FILE,
	NWAM_LOC_PROP_IKE_CONFIG_FILE,
	NWAM_LOC_PROP_IPSECPOLICY_CONFIG_FILE,
	NWAM_KNOWN_WLAN_PROP_BSSIDS,
	NWAM_KNOWN_WLAN_PROP_PRIORITY,
	NWAM_KNOWN_WLAN_PROP_KEYNAME,
	NWAM_KNOWN_WLAN_PROP_KEYSLOT,
	NWAM_KNOWN_WLAN_PROP_SECURITY_MODE,
	NWAM_NCU_PROP_IP_PRIMARY,
	NWAM_NCU_PROP_IP_REQHOST
};

/* properties table: maps PT_* constants to property names */
typedef struct prop_table_entry {
	int			pte_type;
	const char		*pte_name;
} prop_table_entry_t;

/* NCU properties table */
static prop_table_entry_t ncu_prop_table[] = {
	{ PT_TYPE, 			NWAM_NCU_PROP_TYPE },
	{ PT_CLASS, 			NWAM_NCU_PROP_CLASS },
	{ PT_PARENT, 			NWAM_NCU_PROP_PARENT_NCP },
	{ PT_ACTIVATION_MODE,		NWAM_NCU_PROP_ACTIVATION_MODE },
	{ PT_ENABLED, 			NWAM_NCU_PROP_ENABLED },
	{ PT_PRIORITY_GROUP, 		NWAM_NCU_PROP_PRIORITY_GROUP },
	{ PT_PRIORITY_MODE,		NWAM_NCU_PROP_PRIORITY_MODE },
	{ PT_LINK_MACADDR, 		NWAM_NCU_PROP_LINK_MAC_ADDR },
	{ PT_LINK_AUTOPUSH, 		NWAM_NCU_PROP_LINK_AUTOPUSH },
	{ PT_LINK_MTU, 			NWAM_NCU_PROP_LINK_MTU },
	{ PT_IP_VERSION, 		NWAM_NCU_PROP_IP_VERSION },
	{ PT_IPV4_ADDRSRC, 		NWAM_NCU_PROP_IPV4_ADDRSRC },
	{ PT_IPV4_ADDR, 		NWAM_NCU_PROP_IPV4_ADDR },
	{ PT_IPV4_DEFAULT_ROUTE,	NWAM_NCU_PROP_IPV4_DEFAULT_ROUTE },
	{ PT_IPV6_ADDRSRC, 		NWAM_NCU_PROP_IPV6_ADDRSRC },
	{ PT_IPV6_ADDR, 		NWAM_NCU_PROP_IPV6_ADDR },
	{ PT_IPV6_DEFAULT_ROUTE,	NWAM_NCU_PROP_IPV6_DEFAULT_ROUTE },
	{ PT_IP_PRIMARY,		NWAM_NCU_PROP_IP_PRIMARY },
	{ PT_IP_REQHOST,		NWAM_NCU_PROP_IP_REQHOST },
	{ 0, NULL }
};

/* ENM properties table */
static prop_table_entry_t enm_prop_table[] = {
	{ PT_ENM_FMRI, 		NWAM_ENM_PROP_FMRI },
	{ PT_ENM_START, 	NWAM_ENM_PROP_START },
	{ PT_ENM_STOP, 		NWAM_ENM_PROP_STOP },
	{ PT_ACTIVATION_MODE, 	NWAM_ENM_PROP_ACTIVATION_MODE },
	{ PT_CONDITIONS, 	NWAM_ENM_PROP_CONDITIONS },
	{ PT_ENABLED, 		NWAM_ENM_PROP_ENABLED },
	{ 0, NULL }
};

/* LOCation properties table */
static prop_table_entry_t loc_prop_table[] = {
	{ PT_ACTIVATION_MODE, 	NWAM_LOC_PROP_ACTIVATION_MODE },
	{ PT_CONDITIONS, 	NWAM_LOC_PROP_CONDITIONS },
	{ PT_ENABLED, 		NWAM_LOC_PROP_ENABLED },
	{ PT_LOC_NAMESERVICES, 	NWAM_LOC_PROP_NAMESERVICES },
	{ PT_LOC_NAMESERVICES_CONFIG, NWAM_LOC_PROP_NAMESERVICES_CONFIG_FILE },
	{ PT_LOC_DNS_CONFIGSRC, NWAM_LOC_PROP_DNS_NAMESERVICE_CONFIGSRC },
	{ PT_LOC_DNS_DOMAIN, 	NWAM_LOC_PROP_DNS_NAMESERVICE_DOMAIN },
	{ PT_LOC_DNS_SERVERS, 	NWAM_LOC_PROP_DNS_NAMESERVICE_SERVERS },
	{ PT_LOC_DNS_SEARCH, 	NWAM_LOC_PROP_DNS_NAMESERVICE_SEARCH },
	{ PT_LOC_NIS_CONFIGSRC, NWAM_LOC_PROP_NIS_NAMESERVICE_CONFIGSRC },
	{ PT_LOC_NIS_SERVERS, 	NWAM_LOC_PROP_NIS_NAMESERVICE_SERVERS },
	{ PT_LOC_LDAP_CONFIGSRC, NWAM_LOC_PROP_LDAP_NAMESERVICE_CONFIGSRC },
	{ PT_LOC_LDAP_SERVERS,	NWAM_LOC_PROP_LDAP_NAMESERVICE_SERVERS },
	{ PT_LOC_DEFAULT_DOMAIN, NWAM_LOC_PROP_DEFAULT_DOMAIN },
	{ PT_LOC_NFSV4_DOMAIN, 	NWAM_LOC_PROP_NFSV4_DOMAIN },
	{ PT_LOC_IPF_CONFIG, 	NWAM_LOC_PROP_IPFILTER_CONFIG_FILE },
	{ PT_LOC_IPF_V6_CONFIG, NWAM_LOC_PROP_IPFILTER_V6_CONFIG_FILE },
	{ PT_LOC_IPNAT_CONFIG, 	NWAM_LOC_PROP_IPNAT_CONFIG_FILE },
	{ PT_LOC_IPPOOL_CONFIG, NWAM_LOC_PROP_IPPOOL_CONFIG_FILE },
	{ PT_LOC_IKE_CONFIG, 	NWAM_LOC_PROP_IKE_CONFIG_FILE },
	{ PT_LOC_IPSECPOL_CONFIG, NWAM_LOC_PROP_IPSECPOLICY_CONFIG_FILE },
	{ 0, NULL }
};

/* Known WLAN properties table */
static prop_table_entry_t wlan_prop_table[] = {
	{ PT_WLAN_BSSIDS, 	NWAM_KNOWN_WLAN_PROP_BSSIDS },
	{ PT_WLAN_PRIORITY, 	NWAM_KNOWN_WLAN_PROP_PRIORITY },
	{ PT_WLAN_KEYNAME, 	NWAM_KNOWN_WLAN_PROP_KEYNAME },
	{ PT_WLAN_KEYSLOT, 	NWAM_KNOWN_WLAN_PROP_KEYSLOT },
	{ PT_WLAN_SECURITY_MODE, NWAM_KNOWN_WLAN_PROP_SECURITY_MODE },
	{ 0, NULL }
};

/* Returns the appropriate properties table for the given object type */
static prop_table_entry_t *
get_prop_table(nwam_object_type_t object_type)
{
	switch (object_type) {
	case NWAM_OBJECT_TYPE_NCU:
		return (ncu_prop_table);
	case NWAM_OBJECT_TYPE_LOC:
		return (loc_prop_table);
	case NWAM_OBJECT_TYPE_ENM:
		return (enm_prop_table);
	case NWAM_OBJECT_TYPE_KNOWN_WLAN:
		return (wlan_prop_table);
	}
	return (NULL);
}

/* Global variables */

/* set early in main(), never modified thereafter, used all over the place */
static char *execname;

/* set in modifying functions, checked in read_input() */
boolean_t saw_error = B_FALSE;

/* set in yacc parser, checked in read_input() */
boolean_t newline_terminated;

/* set in main(), checked in lex error handler */
boolean_t cmd_file_mode = B_FALSE;

/* set in exit_func(), checked in read_input() */
static boolean_t time_to_exit = B_FALSE;

/* used in nerr() and nwamerr() */
static char *cmd_file_name = NULL;

/* used with cmd_file to destroy all configurations */
static boolean_t remove_all_configurations = B_FALSE;

/* checked in read_input() and other places */
static boolean_t ok_to_prompt = B_FALSE;

/* initialized in do_interactive(), checked in initialize() */
static boolean_t interactive_mode;

static boolean_t need_to_commit = B_FALSE;

/* The gl_get_line() resource object */
static GetLine *gl;

/* set when create or read objects, used by other func */
static nwam_loc_handle_t loc_h = NULL;
static nwam_enm_handle_t enm_h = NULL;
static nwam_known_wlan_handle_t wlan_h = NULL;
static nwam_ncu_handle_t ncu_h = NULL;
static nwam_ncp_handle_t ncp_h = NULL;

static int current_scope = NWAM_SCOPE_GBL;

/* obj1_* are used in NWAM_SCOPE_{NCP,LOC,ENM,WLAN} */
static int obj1_type;
static char obj1_name[NWAM_MAX_NAME_LEN + 1];

/* obj2_* are used in NWAM_SCOPE_NCU only */
static int obj2_type;
static char obj2_name[NWAM_MAX_NAME_LEN + 1];

/* arrays for tab-completion */
/* commands at NWAM_SCOPE_GBL */
static const char *global_scope_cmds[] = {
	"create ",
	"destroy ",
	"end ",
	"exit ",
	"export ",
	"help ",
	"list ",
	"select ",
	NULL
};

static const char *global_create_cmds[] = {
	"create loc ",
	"create enm ",
	"create ncp ",
	"create wlan ",
	"create -t ",		/* template */
	NULL
};

static const char *global_destroy_cmds[] = {
	"destroy -a ",
	"destroy loc ",
	"destroy enm ",
	"destroy ncp ",
	"destroy wlan ",
	NULL
};

static const char *global_export_cmds[] = {
	"export ",
	"export -d ",		/* add destroy -a */
	"export -f ",		/* to file */
	"export -d -f ",	/* add destroy -a to file */
	"export loc ",
	"export enm ",
	"export ncp ",
	"export wlan ",
	NULL
};

static const char *global_list_cmds[] = {
	"list ",
	"list loc ",
	"list enm ",
	"list ncp ",
	"list wlan ",
	"list -a loc ",
	"list -a enm ",
	"list -a wlan ",
	NULL
};

static const char *global_select_cmds[] = {
	"select loc ",
	"select enm ",
	"select ncp ",
	"select wlan ",
	NULL
};

/* commands at NWAM_SCOPE_LOC, _ENM, _WLAN and _NCU */
static const char *non_ncp_scope_cmds[] = {
	"cancel ",
	"clear ",
	"commit ",
	"end ",
	"exit ",
	"export ",
	"export -f ",
	"get ",
	"get -V ",	/* value only */
	"help ",
	"list ",
	"list -a ",	/* all properties */
	"revert ",
	"set ",
	"verify ",
	"walkprop ",
	"walkprop -a ",	/* all properties */
	NULL
};

/* commands at NWAM_SCOPE_NCP */
static const char *ncp_scope_cmds[] = {
	"cancel ",
	"create ",
	"destroy ",
	"end ",
	"exit ",
	"export ",
	"help ",
	"list ",
	"select ",
	NULL
};

static const char *ncp_create_cmds[] = {
	"create ncu ip ",
	"create ncu phys ",
	"create -t ",		/* template */
	NULL
};

static const char *ncp_destroy_cmds[] = {
	"destroy ncu ",
	"destroy ncu ip ",
	"destroy ncu phys ",
	NULL
};

static const char *ncp_export_cmds[] = {
	"export ",
	"export -f ",		/* to file */
	"export ncu ",
	"export ncu ip ",
	"export ncu phys ",
	NULL
};

static const char *ncp_list_cmds[] = {
	"list ",
	"list ncu ",
	"list ncu ip ",
	"list ncu phys ",
	"list -a ncu ",
	"list -a ncu ip ",
	"list -a ncu phys ",
	NULL
};

static const char *ncp_select_cmds[] = {
	"select ncu ",
	"select ncu ip ",
	"select ncu phys ",
	NULL
};

/* Functions begin here */

cmd_t *
alloc_cmd(void)
{
	cmd_t *cmd = calloc(1, sizeof (cmd_t));
	if (cmd == NULL) {
		nerr("Out of memory");
		return (NULL);
	}
	cmd->cmd_argc = 0;
	cmd->cmd_argv[0] = NULL;

	return (cmd);
}

void
free_cmd(cmd_t *cmd)
{
	int i;

	for (i = 0; i < cmd->cmd_argc; i++)
		free(cmd->cmd_argv[i]);
	free(cmd);
}

void
array_free(void **array, int nelem)
{
	int i;
	for (i = 0; i < nelem; i++)
		free(array[i]);
	free(array);
}

static boolean_t
initial_match(const char *line1, const char *line2, int word_end)
{
	if (word_end <= 0)
		return (B_TRUE);
	return (strncmp(line1, line2, word_end) == 0);
}

static int
add_stuff(WordCompletion *cpl, const char *line1, const char **list,
    int word_end)
{
	int i, err;

	for (i = 0; list[i] != NULL; i++) {
		if (initial_match(line1, list[i], word_end)) {
			err = cpl_add_completion(cpl, line1, 0, word_end,
			    list[i] + word_end, "", "");
			if (err != 0)
				return (err);
		}
	}
	return (0);
}

/*
 * To fill in the rest of a string when user types the tab key.
 * First digital number is the length of the string, the second digital number
 * is the min number of chars that is needed to uniquely identify a string.
 */
#define	MINI_STR(l, s, m, n) strncmp(l, s, MAX(MIN(sizeof (s) - 1, m), n))

/* ARGSUSED */
static
CPL_MATCH_FN(cmd_cpl_fn)
{
	/* tab-complete according to the current scope */
	switch (current_scope) {
	case NWAM_SCOPE_GBL:
		if (MINI_STR(line, "create ", word_end, 2) == 0)
			return (add_stuff(cpl, line, global_create_cmds,
			    word_end));
		if (MINI_STR(line, "destroy ", word_end, 1) == 0)
			return (add_stuff(cpl, line, global_destroy_cmds,
			    word_end));
		if (MINI_STR(line, "export ", word_end, 3) == 0)
			return (add_stuff(cpl, line, global_export_cmds,
			    word_end));
		if (MINI_STR(line, "list ", word_end, 1) == 0)
			return (add_stuff(cpl, line, global_list_cmds,
			    word_end));
		if (MINI_STR(line, "select ", word_end, 1) == 0)
			return (add_stuff(cpl, line, global_select_cmds,
			    word_end));
		return (add_stuff(cpl, line, global_scope_cmds, word_end));
	case NWAM_SCOPE_LOC:
	case NWAM_SCOPE_ENM:
	case NWAM_SCOPE_WLAN:
	case NWAM_SCOPE_NCU:
		return (add_stuff(cpl, line, non_ncp_scope_cmds, word_end));
	case NWAM_SCOPE_NCP:
		if (MINI_STR(line, "create ", word_end, 2) == 0)
			return (add_stuff(cpl, line, ncp_create_cmds,
			    word_end));
		if (MINI_STR(line, "destroy ", word_end, 1) == 0)
			return (add_stuff(cpl, line, ncp_destroy_cmds,
			    word_end));
		if (MINI_STR(line, "export ", word_end, 3) == 0)
			return (add_stuff(cpl, line, ncp_export_cmds,
			    word_end));
		if (MINI_STR(line, "list ", word_end, 1) == 0)
			return (add_stuff(cpl, line, ncp_list_cmds, word_end));
		if (MINI_STR(line, "select ", word_end, 1) == 0)
			return (add_stuff(cpl, line, ncp_select_cmds,
			    word_end));
		return (add_stuff(cpl, line, ncp_scope_cmds, word_end));
	}
	/* should never get here */
	return (NULL);
}

const char *
cmd_to_str(int cmd_num)
{
	assert(cmd_num >= CMD_MIN && cmd_num <= CMD_MAX);
	return (helptab[cmd_num].cmd_name);
}

/* Returns "loc", "enm", "wlan" or "ncp" as string */
static const char *
rt1_to_str(int res_type)
{
	assert(res_type >= RT1_MIN && res_type <= RT1_MAX);
	return (res1_types[res_type]);
}

/* Returns "ncu" as string */
static const char *
rt2_to_str(int res_type)
{
	assert(res_type >= RT2_MIN && res_type <= RT2_MAX);
	return (res2_types[res_type]);
}

/* Returns "ncp, "ncu", "loc", "enm", or "wlan" according to the scope */
static const char *
scope_to_str(int scope)
{
	switch (scope) {
	case NWAM_SCOPE_GBL:
		return ("global");
	case NWAM_SCOPE_NCP:
		return ("ncp");
	case NWAM_SCOPE_NCU:
		return ("ncu");
	case NWAM_SCOPE_LOC:
		return ("loc");
	case NWAM_SCOPE_ENM:
		return ("enm");
	case NWAM_SCOPE_WLAN:
		return ("wlan");
	default:
		return ("invalid");
	}
}

/* Given an enm property and value, returns it as a string */
static const char *
propval_to_str(const char *propname, uint64_t value)
{
	const char *str;

	if (nwam_uint64_get_value_string(propname, value, &str) == NWAM_SUCCESS)
		return (str);
	return (NULL);
}

/* Given an int for a prop, returns it as string */
static const char *
pt_to_str(int prop_type)
{
	assert(prop_type >= PT_MIN && prop_type <= PT_MAX);
	return (pt_types[prop_type]);
}

/*
 * Return B_TRUE if string starts with "t" or "on" or is 1;
 * B_FALSE otherwise
 */
static boolean_t
str_to_boolean(const char *str)
{
	if (strncasecmp(str, "t", 1) == 0 || strncasecmp(str, "on", 2) == 0 ||
	    atoi(str) == 1)
		return (B_TRUE);
	else
		return (B_FALSE);
}

/*
 * This is a separate function rather than a set of define's because of the
 * gettext() wrapping.
 */

/*
 * TRANSLATION_NOTE
 * Each string below should have \t follow \n whenever needed; the
 * initial \t and the terminal \n will be provided by the calling function.
 */

static const char *
long_help(int cmd_num)
{
	assert(cmd_num >= CMD_MIN && cmd_num <= CMD_MAX);
	switch (cmd_num) {
		case CMD_CANCEL:
			return (gettext("Cancels the current configuration "
			    "changes."));
		case CMD_CLEAR:
			return (gettext("Clears the value for the specified "
			    "property."));
		case CMD_COMMIT:
			return (gettext("Commits the current configuration."));
		case CMD_CREATE:
			return (gettext("Creates a new profile or resource."));
		case CMD_DESTROY:
			return (gettext("Destroys the specified profile or "
			    "resource."));
		case CMD_END:
			return (gettext("Ends specification of a resource."));
		case CMD_EXIT:
			return (gettext("Exits the program."));
		case CMD_EXPORT:
			return (gettext("Exports the configuration."));
		case CMD_GET:
			return (gettext("Gets the value of the specified "
			    "property."));
		case CMD_HELP:
			return (gettext("Prints help message."));
		case CMD_LIST:
			return (gettext("Lists existing objects."));
		case CMD_REVERT:
			return (gettext("Reverts to the previous "
			    "configuration."));
		case CMD_SELECT:
			return (gettext("Selects a resource to modify."));
		case CMD_SET:
			return (gettext("Sets the value of the specified "
			    "property."));
		case CMD_VERIFY:
			return (gettext("Verifies an object."));
		case CMD_WALKPROP:
			return (gettext("Iterates over properties."));
		default:
			return (gettext("Unknown command."));
	}
}

void
command_usage(int command)
{
	if (command < CMD_MIN || command > CMD_MAX) {
		nerr("Unknown command");
	} else {
		nerr("%s: %s: %s", gettext("Error"), gettext("usage"),
		    helptab[command].cmd_usage);
	}
}

static void
long_usage(uint_t cmd_num)
{
	(void) printf("%s: %s\n", gettext("usage"),
	    helptab[cmd_num].cmd_usage);
	(void) printf("\t%s\n", long_help(cmd_num));
}

/* Prints usage for command line options */
static void
cmd_line_usage()
{
	(void) printf("%s:\t%s\t\t\t\t(%s)\n", gettext("usage"), execname,
	    gettext("interactive-mode"));
	(void) printf("\t%s <%s> [%s...]\n", execname, gettext("command"),
	    gettext("options"));
	(void) printf("\t%s [-d] -f <%s>\n", execname, gettext("command-file"));
	(void) printf("\t%s %s [<%s>]\n", execname, cmd_to_str(CMD_HELP),
	    gettext("command"));
}

/* Prints the line number of the current command if in command-file mode */
static void
print_lineno()
{
	static int last_lineno;

	/* lex_lineno has already been incremented in the lexer; compensate */
	if (cmd_file_mode && lex_lineno > last_lineno) {
		if (strcmp(cmd_file_name, "-") == 0)
			(void) fprintf(stderr, gettext("On line %d:\n"),
			    lex_lineno - 1);
		else
			(void) fprintf(stderr, gettext("On line %d of %s:\n"),
			    lex_lineno - 1, cmd_file_name);
		last_lineno = lex_lineno;
	}
}

/* PRINTFLIKE1 */
void
nerr(const char *format, ...)
{
	va_list	alist;

	print_lineno();

	format = gettext(format);
	va_start(alist, format);
	(void) vfprintf(stderr, format, alist);
	va_end(alist);
	(void) fprintf(stderr, "\n");

	saw_error = B_TRUE;
}

/* PRINTFLIKE2 */
static void
nwamerr(nwam_error_t err, const char *format, ...)
{
	va_list	alist;

	print_lineno();

	format = gettext(format);
	va_start(alist, format);
	(void) vfprintf(stderr, format, alist);
	va_end(alist);
	(void) fprintf(stderr, ": %s\n", nwam_strerror(err));

	saw_error = B_TRUE;
}

void
properr(const char *prop)
{
	nerr("Invalid property: '%s'", prop);
}

/*
 * If free_ncu_only == B_TRUE, only ncu handle is freed, ncp handle remains the
 * same.  Since nwam_ncp_free() takes care of its ncus, no need to explicitly
 * call nwam_ncu_free() afterwards.
 */
static void
free_handle(boolean_t free_ncu_only)
{
	if (ncp_h != NULL) {
		if (!free_ncu_only) {
			nwam_ncp_free(ncp_h);
			ncp_h = NULL;
			ncu_h = NULL;
		} else if (ncu_h != NULL) {
			nwam_ncu_free(ncu_h);
			ncu_h = NULL;
		}
	}

	if (enm_h != NULL) {
		nwam_enm_free(enm_h);
		enm_h = NULL;
	}

	if (loc_h != NULL) {
		nwam_loc_free(loc_h);
		loc_h = NULL;
	}

	if (wlan_h != NULL) {
		nwam_known_wlan_free(wlan_h);
		wlan_h = NULL;
	}
}

/*
 * On input, TRUE => yes, FALSE => no.
 * On return, TRUE => 1, FALSE => no, could not ask => -1.
 */
static int
ask_yesno(boolean_t default_answer, const char *question)
{
	char line[64];  /* should be enough to answer yes or no */

	if (!ok_to_prompt) {
		saw_error = B_TRUE;
		return (-1);
	}
	for (;;) {
		if (printf("%s (%s)? ", gettext(question),
		    default_answer ? "[y]/n" : "y/[n]") < 0)
			return (-1);
		if (fgets(line, sizeof (line), stdin) == NULL)
			return (-1);

		if (line[0] == '\n')
			return (default_answer ? 1 : 0);
		if (tolower(line[0]) == 'y')
			return (1);
		if (tolower(line[0]) == 'n')
			return (0);
	}
}

/* This is the back-end helper function for read_input() below. */
static int
cleanup()
{
	int answer;

	if (!interactive_mode && !cmd_file_mode) {
		/*
		 * If we're not in interactive mode, and we're not in command
		 * file mode, then we must be in commands-from-the-command-line
		 * mode.  As such, we can't loop back and ask for more input.
		 * It was OK to prompt for such things as whether or not to
		 * really delete something in the command handler called from
		 * yyparse() above, but "really quit?" makes no sense in this
		 * context.  So disable prompting.
		 */
		ok_to_prompt = B_FALSE;
	}
	if (need_to_commit) {
		answer = ask_yesno(B_FALSE,
		    "Configuration not saved; really quit");
		switch (answer) {
		case -1:
			/* issue error here */
			return (NWAM_ERR);
		case 1:
			/*
			 * don't want to save, just exit. handles are freed at
			 * end_func() or exit_func().
			 */
			return (NWAM_OK);
		default:
			/* loop back to read input */
			time_to_exit = B_FALSE;
			yyin = stdin;
			return (NWAM_REPEAT);
		}
	}
	return (saw_error ? NWAM_ERR : NWAM_OK);
}

static int
string_to_yyin(char *string)
{
	if ((yyin = tmpfile()) == NULL)
		goto error;
	if (fwrite(string, strlen(string), 1, yyin) != 1)
		goto error;
	if (fseek(yyin, 0, SEEK_SET) != 0)
		goto error;

	return (NWAM_OK);

error:
	nerr("problem creating temporary file");
	return (NWAM_ERR);
}

/*
 * read_input() is the driver of this program.  It is a wrapper around
 * yyparse(), printing appropriate prompts when needed, checking for
 * exit conditions and reacting appropriately.  This function is
 * called when in interactive mode or command-file mode.
 */
static int
read_input(void)
{
	boolean_t yyin_is_a_tty = isatty(fileno(yyin));
	/*
	 * The prompt is "e> " or "e:t1:o1> " or "e:t1:o1:t2:o2> " where e is
	 * execname, t is resource type, o is object name.
	 */
	char prompt[MAXPATHLEN + (2 * (NWAM_MAX_TYPE_LEN + NWAM_MAX_NAME_LEN))
	    + sizeof ("::::> ")];
	char *line;

	/* yyin should have been set to the appropriate (FILE *) if not stdin */
	newline_terminated = B_TRUE;
	for (;;) {
		if (yyin_is_a_tty) {
			if (newline_terminated) {
				switch (current_scope) {
				case NWAM_SCOPE_GBL:
					(void) snprintf(prompt, sizeof (prompt),
					    "%s> ", execname);
					break;
				case NWAM_SCOPE_LOC:
				case NWAM_SCOPE_ENM:
				case NWAM_SCOPE_WLAN:
				case NWAM_SCOPE_NCP:
					(void) snprintf(prompt, sizeof (prompt),
					    "%s:%s:%s> ", execname,
					    rt1_to_str(obj1_type), obj1_name);

					break;
				case NWAM_SCOPE_NCU:
					(void) snprintf(prompt, sizeof (prompt),
					    "%s:%s:%s:%s:%s> ", execname,
					    rt1_to_str(obj1_type), obj1_name,
					    rt2_to_str(obj2_type), obj2_name);
				}
			}
			/*
			 * If the user hits ^C then we want to catch it and
			 * start over.  If the user hits EOF then we want to
			 * bail out.
			 */
			line = gl_get_line(gl, prompt, NULL, -1);
			if (gl_return_status(gl) == GLR_SIGNAL) {
				gl_abandon_line(gl);
				continue;
			}
			if (line == NULL)
				break;
			if (string_to_yyin(line) != NWAM_OK)
				break;
			while (!feof(yyin)) {
				yyparse();

				/*
				 * If any command on a list of commands
				 * give an error, don't continue with the
				 * remaining commands.
				 */
				if (saw_error || time_to_exit)
					break;
			}
		} else {
			yyparse();
		}

		/* Bail out on an error in command-file mode. */
		if (saw_error && cmd_file_mode && !interactive_mode)
			time_to_exit = B_TRUE;
		if (time_to_exit || (!yyin_is_a_tty && feof(yyin)))
			break;
	}
	return (cleanup());
}

/*
 * This function is used in the interactive-mode scenario: it just calls
 * read_input() until we are done.
 */
static int
do_interactive(void)
{
	int err;

	interactive_mode = B_TRUE;
	do {
		err = read_input();
	} while (err == NWAM_REPEAT);
	return (err);
}

/* Calls the help_func() to print the usage of all commands */
void
help_wrap()
{
	cmd_t *help_cmd;

	if ((help_cmd = alloc_cmd()) == NULL)
		exit(NWAM_ERR);
	help_func(help_cmd);
	free_cmd(help_cmd);
}

/* Check if the given command is allowed in the current scope */
boolean_t
check_scope(int cmd)
{
	/* allowed in all scopes */
	switch (cmd) {
	case CMD_END:
	case CMD_EXIT:
	case CMD_HELP:
	case CMD_LIST:
	case CMD_EXPORT:
		return (B_TRUE);
	}
	/* scope-specific */
	switch (current_scope) {
	case NWAM_SCOPE_GBL:
		switch (cmd) {
		case CMD_CREATE:
		case CMD_DESTROY:
		case CMD_SELECT:
			return (B_TRUE);
		}
		break;
	case NWAM_SCOPE_LOC:
	case NWAM_SCOPE_ENM:
	case NWAM_SCOPE_WLAN:
	case NWAM_SCOPE_NCU:
		switch (cmd) {
		case CMD_CANCEL:
		case CMD_CLEAR:
		case CMD_COMMIT:
		case CMD_GET:
		case CMD_REVERT:
		case CMD_SET:
		case CMD_VERIFY:
		case CMD_WALKPROP:
			return (B_TRUE);
		}
		break;
	case NWAM_SCOPE_NCP:
		switch (cmd) {
		case CMD_CANCEL:
		case CMD_CREATE:
		case CMD_DESTROY:
		case CMD_SELECT:
			return (B_TRUE);
		}
		break;
	default:
		nerr("Invalid scope");
	}
	nerr("'%s' is not allowed at this scope", cmd_to_str(cmd));
	return (B_FALSE);
}

/* Returns the active object type depending on which handle is not NULL */
static nwam_object_type_t
active_object_type()
{
	/* Check ncu_h before ncp_h, ncp_h must be loaded before ncu_h */
	if (ncu_h != NULL)
		return (NWAM_OBJECT_TYPE_NCU);
	else if (ncp_h != NULL)
		return (NWAM_OBJECT_TYPE_NCP);
	else if (loc_h != NULL)
		return (NWAM_OBJECT_TYPE_LOC);
	else if (enm_h != NULL)
		return (NWAM_OBJECT_TYPE_ENM);
	else if (wlan_h != NULL)
		return (NWAM_OBJECT_TYPE_KNOWN_WLAN);
	else
		return (NWAM_OBJECT_TYPE_UNKNOWN);
}

/* Retrive the name of the object from its handle */
static nwam_error_t
object_name_from_handle(nwam_object_type_t object_type, void *handle,
    char **namep)
{
	switch (object_type) {
	case NWAM_OBJECT_TYPE_NCP:
		return (nwam_ncp_get_name(handle, namep));
	case NWAM_OBJECT_TYPE_NCU:
		return (nwam_ncu_get_name(handle, namep));
	case NWAM_OBJECT_TYPE_LOC:
		return (nwam_loc_get_name(handle, namep));
	case NWAM_OBJECT_TYPE_ENM:
		return (nwam_enm_get_name(handle, namep));
	case NWAM_OBJECT_TYPE_KNOWN_WLAN:
		return (nwam_known_wlan_get_name(handle, namep));
	}
	return (NWAM_INVALID_ARG);
}

static void
do_commit()
{
	nwam_error_t	ret = NWAM_SUCCESS;
	const char	*errprop;

	if (!need_to_commit)
		return;

	switch (active_object_type()) {
	case NWAM_OBJECT_TYPE_NCU:
		ret = nwam_ncu_commit(ncu_h, 0);
		break;
	case NWAM_OBJECT_TYPE_ENM:
		ret = nwam_enm_commit(enm_h, 0);
		break;
	case NWAM_OBJECT_TYPE_LOC:
		ret = nwam_loc_commit(loc_h, 0);
		break;
	case NWAM_OBJECT_TYPE_KNOWN_WLAN:
		ret = nwam_known_wlan_commit(wlan_h, 0);
		break;
	}

	if (ret == NWAM_SUCCESS) {
		need_to_commit = B_FALSE;
		if (interactive_mode)
			(void) printf(gettext("Committed changes\n"));
	} else {
		nwam_error_t verr;

		/* Find property that caused failure */
		switch (active_object_type()) {
		case NWAM_OBJECT_TYPE_NCU:
			verr = nwam_ncu_validate(ncu_h, &errprop);
			break;
		case NWAM_OBJECT_TYPE_ENM:
			verr = nwam_enm_validate(enm_h, &errprop);
			break;
		case NWAM_OBJECT_TYPE_LOC:
			verr = nwam_loc_validate(loc_h, &errprop);
			break;
		case NWAM_OBJECT_TYPE_KNOWN_WLAN:
			verr = nwam_known_wlan_validate(wlan_h, &errprop);
			break;
		}

		if (verr != NWAM_SUCCESS)
			nwamerr(ret, "Commit error on property '%s'", errprop);
		else
			nwamerr(ret, "Commit error");
	}
}

/*
 * Saves the current configuration to persistent storage.
 */
/* ARGSUSED */
void
commit_func(cmd_t *cmd)
{
	if (!need_to_commit) {
		if (interactive_mode)
			(void) printf(gettext("Nothing to commit\n"));
	} else {
		do_commit();
	}
}

static void
do_cancel()
{
	switch (current_scope) {
	case NWAM_SCOPE_NCU:
		current_scope = NWAM_SCOPE_NCP;
		obj2_type = 0;
		free_handle(B_TRUE);
		break;
	case NWAM_SCOPE_NCP:
	case NWAM_SCOPE_ENM:
	case NWAM_SCOPE_WLAN:
	case NWAM_SCOPE_LOC:
		current_scope = NWAM_SCOPE_GBL;
		obj1_type = 0;
		free_handle(B_FALSE);
		break;
	case NWAM_SCOPE_GBL:
		free_handle(B_FALSE);
		break;
	default:
		nerr("Invalid scope");
		return;
	}
	need_to_commit = B_FALSE;
}

/*
 * End operation on current scope and go up one scope.
 * Changes are not saved, no prompt either.
 */
/* ARGSUSED */
void
cancel_func(cmd_t *cmd)
{
	do_cancel();
}

/*
 * Removes leading and trailing quotes from a string.
 * Caller must free returned string.
 */
static char *
trim_quotes(const char *quoted_str)
{
	char *str;
	int end;

	/* export_func() and list_func() can pass NULL here */
	if (quoted_str == NULL)
		return (NULL);

	/* remove leading quote */
	if (quoted_str[0] == '"')
		str = strdup(quoted_str + 1);
	else
		str = strdup(quoted_str);
	if (str == NULL)
		return (NULL);

	/* remove trailing quote and newline */
	end = strlen(str) - 1;
	while (end >= 0 && (str[end] == '"' || str[end] == '\n'))
		end--;
	str[end+1] = 0;

	return (str);
}

/*
 * Creates a new resource and enters the scope of that resource.
 * The new resource can also be a copy of an existing resource (-t option).
 * If in interactive mode, then after creation call walkprop_func()
 * to do walk the properties for the new object.
 */
void
create_func(cmd_t *cmd)
{
	nwam_error_t	ret = NWAM_SUCCESS;
	int		c;
	boolean_t	template = B_FALSE;
	char		*newname = NULL, *oldname = NULL;
	cmd_t		*walkprop_cmd;

	/* make sure right command at the right scope */
	if (current_scope == NWAM_SCOPE_GBL &&
	    cmd->cmd_res2_type == RT2_NCU) {
		nerr("cannot create ncu at global scope");
		return;
	}
	if (current_scope == NWAM_SCOPE_NCP &&
	    cmd->cmd_res2_type != RT2_NCU) {
		nerr("Cannot create given object at this scope");
		return;
	}

	assert(cmd->cmd_argc > 0);
	optind = 0;
	while ((c = getopt(cmd->cmd_argc, cmd->cmd_argv, "t:")) != EOF) {
		switch (c) {
		case 't':
			template = B_TRUE;
			break;
		default:
			command_usage(CMD_CREATE);
			return;
		}
	}

	if (!template) {
		/* no template given */
		/* argv[0] is name */
		newname = trim_quotes(cmd->cmd_argv[0]);
		if (cmd->cmd_res1_type == RT1_ENM) {
			ret = nwam_enm_create(newname, NULL, &enm_h);
		} else if (cmd->cmd_res1_type == RT1_LOC) {
			ret = nwam_loc_create(newname, &loc_h);
		} else if (cmd->cmd_res1_type == RT1_WLAN) {
			ret = nwam_known_wlan_create(newname, &wlan_h);
		} else if (cmd->cmd_res1_type == RT1_NCP &&
		    current_scope == NWAM_SCOPE_GBL) {
			ret = nwam_ncp_create(newname, 0, &ncp_h);
		} else if (cmd->cmd_res2_type == RT2_NCU) {
			nwam_ncu_type_t		ncu_type;
			nwam_ncu_class_t	ncu_class;

			/* ncp must already be read */
			if (ncp_h == NULL) {
				nerr("Create error: NCP has not been read");
				goto done;
			}

			ncu_class = (nwam_ncu_class_t)cmd->cmd_ncu_class_type;
			ncu_type = nwam_ncu_class_to_type(ncu_class);
			ret = nwam_ncu_create(ncp_h, newname, ncu_type,
			    ncu_class, &ncu_h);
		}

		if (ret != NWAM_SUCCESS) {
			nwamerr(ret, "Create error");
			goto done;
		}

	} else {
		/* template given */
		/* argv[0] is -t, argv[1] is old name, argv[2] is new name */
		oldname = trim_quotes(cmd->cmd_argv[1]);
		newname = trim_quotes(cmd->cmd_argv[2]);
		if (cmd->cmd_res1_type == RT1_ENM) {
			nwam_enm_handle_t oldenm_h;

			ret = nwam_enm_read(oldname, 0, &oldenm_h);
			if (ret != NWAM_SUCCESS)
				goto read_error;
			ret = nwam_enm_copy(oldenm_h, newname, &enm_h);
			nwam_enm_free(oldenm_h);
		} else if (cmd->cmd_res1_type == RT1_LOC) {
			nwam_loc_handle_t oldloc_h;

			ret = nwam_loc_read(oldname, 0, &oldloc_h);
			if (ret != NWAM_SUCCESS)
				goto read_error;
			ret = nwam_loc_copy(oldloc_h, newname, &loc_h);
			nwam_loc_free(oldloc_h);
		} else if (cmd->cmd_res1_type == RT1_WLAN) {
			nwam_known_wlan_handle_t oldwlan_h;

			ret = nwam_known_wlan_read(oldname, 0, &oldwlan_h);
			if (ret != NWAM_SUCCESS)
				goto read_error;
			ret = nwam_known_wlan_copy(oldwlan_h, newname, &wlan_h);
			nwam_known_wlan_free(oldwlan_h);
		} else if (cmd->cmd_res1_type == RT1_NCP &&
		    current_scope == NWAM_SCOPE_GBL) {
			nwam_ncp_handle_t oldncp_h;

			ret = nwam_ncp_read(oldname, 0, &oldncp_h);
			if (ret != NWAM_SUCCESS)
				goto read_error;
			ret = nwam_ncp_copy(oldncp_h, newname, &ncp_h);
			nwam_ncp_free(oldncp_h);
		} else if (cmd->cmd_res2_type == RT2_NCU) {
			nwam_ncu_handle_t	oldncu_h;
			nwam_ncu_type_t		ncu_type;
			nwam_ncu_class_t	ncu_class;

			/* ncp must already be read */
			if (ncp_h == NULL) {
				nerr("Copy error: NCP has not been read");
				goto done;
			}
			ncu_class = (nwam_ncu_class_t)cmd->cmd_ncu_class_type;
			ncu_type = nwam_ncu_class_to_type(ncu_class);
			ret = nwam_ncu_read(ncp_h, oldname, ncu_type, 0,
			    &oldncu_h);
			if (ret != NWAM_SUCCESS)
				goto read_error;
			ret = nwam_ncu_copy(oldncu_h, newname, &ncu_h);
			nwam_ncu_free(oldncu_h);
		}

		if (ret != NWAM_SUCCESS) {
			nwamerr(ret, "Copy error");
			goto done;
		}
	}

	if (current_scope == NWAM_SCOPE_GBL) {
		(void) strlcpy(obj1_name, newname, sizeof (obj1_name));
		obj1_type = cmd->cmd_res1_type;
		if (obj1_type == RT1_ENM)
			current_scope = NWAM_SCOPE_ENM;
		else if (obj1_type == RT1_LOC)
			current_scope = NWAM_SCOPE_LOC;
		else if (obj1_type == RT1_WLAN)
			current_scope = NWAM_SCOPE_WLAN;
		else if (obj1_type == RT1_NCP)
			current_scope = NWAM_SCOPE_NCP;
	} else {
		(void) strlcpy(obj2_name, newname, sizeof (obj2_name));
		current_scope = NWAM_SCOPE_NCU;
		obj2_type = cmd->cmd_res2_type;
	}
	if (current_scope != NWAM_SCOPE_NCP)
		need_to_commit = B_TRUE;

	/* do a walk of the properties if in interactive mode */
	if (interactive_mode && current_scope != NWAM_SCOPE_NCP) {
		(void) printf(gettext("Created %s '%s'.  "
		    "Walking properties ...\n"),
		    scope_to_str(current_scope), newname);
		if ((walkprop_cmd = alloc_cmd()) == NULL)
			goto done;
		walkprop_func(walkprop_cmd);
		free(walkprop_cmd);
	}

read_error:
	if (ret != NWAM_SUCCESS)
		nwamerr(ret, "Copy error reading '%s'", oldname);

done:
	free(oldname);
	free(newname);
}

/* Processing of return value for destroy_*_callback() */
static int
destroy_ret(nwam_object_type_t object_type, nwam_error_t ret, void *handle)
{
	if (ret == NWAM_ENTITY_NOT_DESTROYABLE) {
		/* log a message to stderr, but don't consider it an error */
		char *name;
		if (object_name_from_handle(object_type, handle, &name)
		    == NWAM_SUCCESS) {
			(void) fprintf(stderr,
			    gettext("%s '%s' cannot be removed\n"),
			    nwam_object_type_to_string(object_type), name);
			free(name);
		}
		return (0);
	}

	if (ret == NWAM_SUCCESS || ret == NWAM_ENTITY_IN_USE)
		return (0);

	return (1);
}

/*
 * NWAM_FLAG_DO_NOT_FREE is passed to nwam_*_destory() so that it does not
 * free the handle.  The calling nwam_walk_*() function frees this handle
 * as it is the function that created the handle.
 *
 * Objects that are not destroyable or are active cannot be destroyed.
 * Don't return error in these situations so the walk can continue.
 */
/* ARGSUSED */
static int
destroy_ncp_callback(nwam_ncp_handle_t ncp, void *arg)
{
	/* The file is deleted, so NCUs are also removed */
	nwam_error_t ret = nwam_ncp_destroy(ncp, NWAM_FLAG_DO_NOT_FREE);
	return (destroy_ret(NWAM_OBJECT_TYPE_NCP, ret, ncp));
}

/* ARGSUSED */
static int
destroy_loc_callback(nwam_loc_handle_t loc, void *arg)
{
	nwam_error_t ret = nwam_loc_destroy(loc, NWAM_FLAG_DO_NOT_FREE);
	return (destroy_ret(NWAM_OBJECT_TYPE_LOC, ret, loc));
}

/* ARGSUSED */
static int
destroy_enm_callback(nwam_enm_handle_t enm, void *arg)
{
	nwam_error_t ret = nwam_enm_destroy(enm, NWAM_FLAG_DO_NOT_FREE);
	return (destroy_ret(NWAM_OBJECT_TYPE_ENM, ret, enm));
}

/* ARGSUSED */
static int
destroy_wlan_callback(nwam_known_wlan_handle_t wlan, void *arg)
{
	nwam_error_t ret = nwam_known_wlan_destroy(wlan, NWAM_FLAG_DO_NOT_FREE);
	return (destroy_ret(NWAM_OBJECT_TYPE_KNOWN_WLAN, ret, wlan));
}

/*
 * Remove all existing configuration that are not read-only.
 * walk through all ncps, locs, enms, wlans and destroy each one.
 */
static nwam_error_t
destroy_all(void)
{
	nwam_error_t	ret;

	assert(remove_all_configurations);

	ret = nwam_walk_ncps(destroy_ncp_callback, NULL, 0, NULL);
	if (ret != NWAM_SUCCESS)
		goto done;

	ret = nwam_walk_enms(destroy_enm_callback, NULL,
	    NWAM_FLAG_ACTIVATION_MODE_ALL, NULL);
	if (ret != NWAM_SUCCESS)
		goto done;

	ret = nwam_walk_locs(destroy_loc_callback, NULL,
	    NWAM_FLAG_ACTIVATION_MODE_ALL, NULL);
	if (ret != NWAM_SUCCESS)
		goto done;

	ret = nwam_walk_known_wlans(destroy_wlan_callback, NULL, 0, NULL);
	if (ret != NWAM_SUCCESS)
		goto done;

	if (interactive_mode)
		(void) printf(gettext("All user-defined entities destroyed\n"));
	remove_all_configurations = B_FALSE;

done:
	if (ret != NWAM_SUCCESS) {
		nwamerr(ret, "Destroy error: "
		    "could not destroy all configurations");
	}
	return (ret);
}

/*
 * Destroys an instance in persistent repository, and is permanent.
 * If interactive mode, it is allowed at global scope only
 * option -a destroys everything.
 */
void
destroy_func(cmd_t *cmd)
{
	nwam_error_t	ret;
	char		*name, *realname = NULL;

	if (current_scope == NWAM_SCOPE_NCP &&
	    (cmd->cmd_res1_type == RT1_ENM || cmd->cmd_res1_type == RT1_LOC ||
	    cmd->cmd_res1_type == RT1_WLAN)) {
		nerr("Destroy error: only NCUs can be destroyed in NCP scope");
		return;
	}

	assert(cmd->cmd_argc > 0);

	/* res1_type is -1 if -a flag is used */
	if (cmd->cmd_res1_type == -1) {
		int c;

		if (current_scope != NWAM_SCOPE_GBL) {
			nerr("Cannot destroy all configurations in a "
			    "non-global scope");
			return;
		}

		optind = 0;
		while ((c = getopt(cmd->cmd_argc, cmd->cmd_argv, "a")) != EOF) {
			switch (c) {
			case 'a':
				remove_all_configurations = B_TRUE;
				break;
			default:
				command_usage(CMD_DESTROY);
				return;
			}
		}
		if (remove_all_configurations) {
			(void) destroy_all();
			return;
		}
	}

	/* argv[0] is name */
	name = trim_quotes(cmd->cmd_argv[0]);
	if (cmd->cmd_res2_type == RT2_NCU) {
		nwam_ncu_type_t		ncu_type;
		nwam_ncu_class_t	ncu_class;

		/* ncp must already be read */
		if (ncp_h == NULL) {
			nerr("Destroy ncu error: NCP has not been read");
			return;
		}
		ncu_class = (nwam_ncu_class_t)cmd->cmd_ncu_class_type;
		ncu_type = nwam_ncu_class_to_type(ncu_class);
		ret = nwam_ncu_read(ncp_h, name, ncu_type, 0, &ncu_h);
		if (ret != NWAM_SUCCESS)
			goto done;
		(void) object_name_from_handle(NWAM_OBJECT_TYPE_NCU, ncu_h,
		    &realname);
		ret = nwam_ncu_destroy(ncu_h, 0);
		ncu_h = NULL;
	} else if (cmd->cmd_res1_type == RT1_ENM) {
		if ((ret = nwam_enm_read(name, 0, &enm_h)) != NWAM_SUCCESS)
			goto done;
		(void) object_name_from_handle(NWAM_OBJECT_TYPE_ENM, enm_h,
		    &realname);
		ret = nwam_enm_destroy(enm_h, 0);
		enm_h = NULL;
	} else if (cmd->cmd_res1_type == RT1_LOC) {
		if ((ret = nwam_loc_read(name, 0, &loc_h)) != NWAM_SUCCESS)
			goto done;
		(void) object_name_from_handle(NWAM_OBJECT_TYPE_LOC, loc_h,
		    &realname);
		ret = nwam_loc_destroy(loc_h, 0);
		loc_h = NULL;
	} else if (cmd->cmd_res1_type == RT1_WLAN) {
		if ((ret = nwam_known_wlan_read(name, 0, &wlan_h))
		    != NWAM_SUCCESS)
			goto done;
		(void) object_name_from_handle(NWAM_OBJECT_TYPE_KNOWN_WLAN,
		    wlan_h, &realname);
		ret = nwam_known_wlan_destroy(wlan_h, 0);
		wlan_h = NULL;
	} else if (cmd->cmd_res1_type == RT1_NCP) {
		if ((ret = nwam_ncp_read(name, 0, &ncp_h)) != NWAM_SUCCESS)
			goto done;
		(void) object_name_from_handle(NWAM_OBJECT_TYPE_NCP, ncp_h,
		    &realname);
		ret = nwam_ncp_destroy(ncp_h, 0);
		ncp_h = NULL;
	} else {
		nerr("Destroy error: unknown object-type");
	}

done:
	if (ret == NWAM_ENTITY_IN_USE)  {
		nerr("Destroy error: active entity cannot be destroyed");
	} else if (ret != NWAM_SUCCESS) {
		nwamerr(ret, "Destroy error");
	} else if (interactive_mode) {
		(void) printf(gettext("Destroyed %s '%s'\n"),
		    (cmd->cmd_res2_type == RT2_NCU ?
		    rt2_to_str(cmd->cmd_res2_type) :
		    rt1_to_str(cmd->cmd_res1_type)),
		    realname != NULL ? realname : name);
	}
	free(name);
	free(realname);
}

/*
 * End operation on current scope and go up one scope.
 * Changes are saved.
 */
/* ARGSUSED */
void
end_func(cmd_t *cmd)
{
	/* if need_to_commit is set, commit changes */
	if (need_to_commit)
		do_commit();

	/*
	 * Call do_cancel() to go up one scope.  If commit fails,
	 * need_to_commit is not reset and users are asked if they want to end.
	 */
	if (!need_to_commit ||
	    (need_to_commit && (ask_yesno(B_FALSE,
	    "Configuration not saved; really end")) == 1)) {
		/* set time_to_exit if in global scope */
		if (current_scope == NWAM_SCOPE_GBL)
			time_to_exit = B_TRUE;
		/* call do_cancel() to go up one scope */
		do_cancel();
	}
}

/*
 * Exit immediately.  Configuration changes are saved by calling end_func().
 */
/* ARGSUSED */
void
exit_func(cmd_t *cmd)
{
	cmd_t *end_cmd;

	if (need_to_commit) {
		if ((end_cmd = alloc_cmd()) == NULL) {
			nerr("Exit error");
			return;
		}
		end_func(end_cmd);
		free_cmd(end_cmd);
	}

	/*
	 * If need_to_commit is still set, then the commit failed.
	 * Otherwise, exit.
	 */
	if (!need_to_commit)
		time_to_exit = B_TRUE;
}

void
help_func(cmd_t *cmd)
{
	int i;

	if (cmd->cmd_argc == 0) {
		(void) printf(gettext("commands:\n"));
		for (i = CMD_MIN; i <= CMD_MAX; i++)
			(void) printf("\t%s\n", helptab[i].cmd_usage);
		return;
	}

	for (i = CMD_MIN; i <= CMD_MAX; i++) {
		if (strcmp(cmd->cmd_argv[0], cmd_to_str(i)) == 0) {
			long_usage(i);
			return;
		}
	}
	(void) fprintf(stderr, gettext("Unknown command: '%s'\n"),
	    cmd->cmd_argv[0]);
	help_wrap();
}

/*
 * Revert configuration of an instance to latest previous version.
 * Free the handle and read again.
 */
/* ARGSUSED */
void
revert_func(cmd_t *cmd)
{
	nwam_error_t		ret;
	char			*name = NULL;
	nwam_ncu_type_t		ncu_type;
	nwam_object_type_t	object_type = active_object_type();

	switch (object_type) {
	case NWAM_OBJECT_TYPE_NCU:
		/* retrieve name and type to use later */
		if ((ret = nwam_ncu_get_ncu_type(ncu_h, &ncu_type))
		    != NWAM_SUCCESS) {
			nwamerr(ret, "Revert error: Get ncu type error");
			return;
		}
		if ((ret = nwam_ncu_get_name(ncu_h, &name)) != NWAM_SUCCESS)
			goto name_error;
		nwam_ncu_free(ncu_h);
		ncu_h = NULL;
		ret = nwam_ncu_read(ncp_h, name, ncu_type, 0, &ncu_h);
		break;
	case NWAM_OBJECT_TYPE_ENM:
		if ((ret = nwam_enm_get_name(enm_h, &name)) != NWAM_SUCCESS)
			goto name_error;
		nwam_enm_free(enm_h);
		enm_h = NULL;
		ret = nwam_enm_read(name, 0, &enm_h);
		break;
	case NWAM_OBJECT_TYPE_LOC:
		if ((ret = nwam_loc_get_name(loc_h, &name)) != NWAM_SUCCESS)
			goto name_error;
		nwam_loc_free(loc_h);
		loc_h = NULL;
		ret = nwam_loc_read(name, 0, &loc_h);
		break;
	case NWAM_OBJECT_TYPE_KNOWN_WLAN:
		if ((ret = nwam_known_wlan_get_name(wlan_h, &name))
		    != NWAM_SUCCESS)
			goto name_error;
		nwam_known_wlan_free(wlan_h);
		wlan_h = NULL;
		ret = nwam_known_wlan_read(name, 0, &wlan_h);
		break;
	}

	/* Exit this scope because handle already freed (call do_cancel()) */
	need_to_commit = B_FALSE;

	if (ret != NWAM_SUCCESS) {
		if (ret == NWAM_ENTITY_NOT_FOUND) {
			nerr("%s '%s' does not exist to revert to, removing it",
			    nwam_object_type_to_string(object_type), name);
		} else {
			nwamerr(ret, "Revert error");
		}
		do_cancel();
	}
	free(name);
	return;

name_error:
	if (ret != NWAM_SUCCESS)
		nwamerr(ret, "Revert error: get name error");
}

/*
 * Load a resource from persistent repository and enter the scope
 * of that resource.
 */
void
select_func(cmd_t *cmd)
{
	nwam_error_t	ret;
	char		*name, *realname = NULL;

	assert(cmd->cmd_argc > 0);
	if (current_scope == NWAM_SCOPE_NCP && cmd->cmd_res2_type != RT2_NCU) {
		nerr("cannot select '%s' at this scope",
		    rt1_to_str(cmd->cmd_res1_type));
		return;
	}

	/* argv[0] is name */
	name = trim_quotes(cmd->cmd_argv[0]);
	switch (cmd->cmd_res1_type) {
	case RT1_LOC:
		ret = nwam_loc_read(name, 0, &loc_h);
		if (ret == NWAM_SUCCESS) {
			current_scope = NWAM_SCOPE_LOC;
			(void) object_name_from_handle(NWAM_OBJECT_TYPE_LOC,
			    loc_h, &realname);
		}
		break;
	case RT1_ENM:
		ret = nwam_enm_read(name, 0, &enm_h);
		if (ret == NWAM_SUCCESS) {
			current_scope = NWAM_SCOPE_ENM;
			(void) object_name_from_handle(NWAM_OBJECT_TYPE_ENM,
			    enm_h, &realname);
		}
		break;
	case RT1_WLAN:
		ret = nwam_known_wlan_read(name, 0, &wlan_h);
		if (ret == NWAM_SUCCESS) {
			current_scope = NWAM_SCOPE_WLAN;
			(void) object_name_from_handle
			    (NWAM_OBJECT_TYPE_KNOWN_WLAN, wlan_h, &realname);
		}
		break;
	case RT1_NCP:
		if (cmd->cmd_res2_type == RT2_NCU) {
			nwam_ncu_type_t		ncu_type;
			nwam_ncu_class_t	ncu_class;

			/* ncp must already be read */
			if (ncp_h == NULL) {
				nerr("Select error: NCP has not been read");
				free(name);
				return;
			}
			ncu_class = (nwam_ncu_class_t)cmd->cmd_ncu_class_type;
			ncu_type = nwam_ncu_class_to_type(ncu_class);
			ret = nwam_ncu_read(ncp_h, name, ncu_type, 0, &ncu_h);
			if (ret == NWAM_SUCCESS) {
				current_scope = NWAM_SCOPE_NCU;
				(void) object_name_from_handle
				    (NWAM_OBJECT_TYPE_NCU, ncu_h, &realname);
			}
		} else {
			ret = nwam_ncp_read(name, 0, &ncp_h);
			if (ret == NWAM_SUCCESS) {
				current_scope = NWAM_SCOPE_NCP;
				(void) object_name_from_handle
				    (NWAM_OBJECT_TYPE_NCP, ncp_h, &realname);
			}
		}
		break;
	default:
		nerr("Select error: unknown object-type");
		free(name);
		return;
	}

	if (ret != NWAM_SUCCESS) {
		nwamerr(ret, "Select error");
	} else {
		/* set the obj*_name or obj*_type depending on current scope */
		if (current_scope == NWAM_SCOPE_NCU) {
			obj2_type = RT2_NCU;
			(void) strlcpy(obj2_name,
			    realname != NULL ? realname : name,
			    sizeof (obj2_name));
		} else {
			(void) strlcpy(obj1_name,
			    realname != NULL ? realname : name,
			    sizeof (obj1_name));
			obj1_type = cmd->cmd_res1_type;
		}
	}
	free(name);
	free(realname);
}

/* Given an int for prop, returns it as string */
static const char *
pt_to_prop_name(nwam_object_type_t object_type, int pt_type)
{
	int i;
	prop_table_entry_t *prop_table = get_prop_table(object_type);

	for (i = 0; prop_table[i].pte_name != NULL; i++) {
		if (pt_type == prop_table[i].pte_type)
			return (prop_table[i].pte_name);
	}
	return (NULL);
}

/* Given a prop as a string, returns it as an int */
static int
prop_to_pt(nwam_object_type_t object_type, const char *prop)
{
	int i;
	prop_table_entry_t *prop_table = get_prop_table(object_type);

	for (i = 0; prop_table[i].pte_name != NULL; i++) {
		if (strcmp(prop, prop_table[i].pte_name) == 0)
			return (prop_table[i].pte_type);
	}
	return (-1);
}

/* Given a prop as an int, returns its type (nwam_value_type_t) */
static nwam_value_type_t
prop_value_type(nwam_object_type_t object_type, const char *prop)
{
	nwam_error_t		ret;
	nwam_value_type_t	value_type;

	switch (object_type) {
	case NWAM_OBJECT_TYPE_NCU:
		ret = nwam_ncu_get_prop_type(prop, &value_type);
		break;
	case NWAM_OBJECT_TYPE_LOC:
		ret = nwam_loc_get_prop_type(prop, &value_type);
		break;
	case NWAM_OBJECT_TYPE_ENM:
		ret = nwam_enm_get_prop_type(prop, &value_type);
		break;
	case NWAM_OBJECT_TYPE_KNOWN_WLAN:
		ret = nwam_known_wlan_get_prop_type(prop, &value_type);
		break;
	}

	if (ret != NWAM_SUCCESS)
		value_type = NWAM_VALUE_TYPE_UNKNOWN;

	return (value_type);
}

/*
 * Converts input_str to an array nwam_value.
 * If is_list_prop, break input_str into array of strings first.
 */
static nwam_value_t
str_to_nwam_value(nwam_object_type_t object_type, char *input_str, int pt_type,
    boolean_t is_list_prop)
{
	int		i, n = 0, ret;
	nwam_value_t	data;
	char		**val;
	int		max_str_num;

	nwam_value_type_t	value_type;
	int64_t			*int_vals;
	uint64_t		*uint_vals;
	boolean_t		*boolean_vals;

	/*
	 * Worst case is that each char separated by DELIMITER, so the
	 * max number of sub strings is half of string length + 1.
	 */
	max_str_num = strlen(input_str) / 2 + 1;

	val = calloc(max_str_num, sizeof (char *));
	if (val == NULL) {
		nerr("Out of memory");
		return (NULL);
	}

	if (is_list_prop) {
		char *tmp, *next;
		/*
		 * Break down input_str and save as array of sub strings.
		 * Set num as the number of the sub strings.
		 * Use nwam_tokenize_by_unescaped_delim() rather than strtok()
		 * because DELIMITER may be escaped
		 */
		tmp = (char *)input_str;
		while ((tmp = nwam_tokenize_by_unescaped_delim(tmp,
		    NWAM_VALUE_DELIMITER_CHAR, &next)) != NULL) {
			val[n++] = trim_quotes(tmp);
			tmp = next;
		}
	} else {
		val[n++] = trim_quotes(input_str);
	}

	/* initialize int_vals or booleans_vals depending on pt_type */
	value_type = prop_value_type(object_type,
	    pt_to_prop_name(object_type, pt_type));
	if (value_type == NWAM_VALUE_TYPE_INT64) {
		int_vals = calloc(n, sizeof (int64_t));
		if (int_vals == NULL) {
			nerr("Out of memory");
			array_free((void **)val, max_str_num);
			return (NULL);
		}
	} else if (value_type == NWAM_VALUE_TYPE_UINT64) {
		uint_vals = calloc(n, sizeof (uint64_t));
		if (uint_vals == NULL) {
			nerr("Out of memory");
			array_free((void **)val, max_str_num);
			return (NULL);
		}
	} else if (value_type == NWAM_VALUE_TYPE_BOOLEAN) {
		boolean_vals = calloc(n, sizeof (boolean_t));
		if (boolean_vals == NULL) {
			nerr("Out of memory");
			array_free((void **)val, max_str_num);
			return (NULL);
		}
	}
	/* set the appropriate array */
	for (i = 0; i < n; i++) {
		switch (value_type) {
		case NWAM_VALUE_TYPE_STRING:
			/* nothing to do - val already has the char** array */
			break;
		case NWAM_VALUE_TYPE_INT64:
		{
			int_vals[i] = (int64_t)atoi(val[i]);
			break;
		}
		case NWAM_VALUE_TYPE_UINT64:
		{
			uint64_t str_as_enum;
			char *endptr;

			ret = nwam_value_string_get_uint64(
			    pt_to_prop_name(object_type, pt_type),
			    val[i], &str_as_enum);
			/*
			 * Returns _SUCCESS if value for enum is valid.
			 * Returns _INVALID_ARG if property is not an enum.
			 */
			if (ret == NWAM_SUCCESS) {
				uint_vals[i] = str_as_enum;
			} else if (ret == NWAM_INVALID_ARG) {
				uint_vals[i] = strtoul(val[i], &endptr, 10);
				/* verify conversion is valid */
				if (endptr == val[i]) {
					free(uint_vals);
					array_free((void **)val, max_str_num);
					return (NULL);
				}
			} else {
				free(uint_vals);
				array_free((void **)val, max_str_num);
				return (NULL);
			}
			break;
		}
		case NWAM_VALUE_TYPE_BOOLEAN:
			boolean_vals[i] = str_to_boolean(val[i]);
			break;
		default:
			array_free((void **)val, max_str_num);
			return (NULL);
		}
	}

	/* create nwam_value_t */
	if (value_type == NWAM_VALUE_TYPE_STRING) {
		ret = nwam_value_create_string_array(val, n, &data);
	} else if (value_type == NWAM_VALUE_TYPE_INT64) {
		ret = nwam_value_create_int64_array(int_vals, n, &data);
		free(int_vals);
	} else if (value_type == NWAM_VALUE_TYPE_UINT64) {
		ret = nwam_value_create_uint64_array(uint_vals, n, &data);
		free(uint_vals);
	} else if (value_type == NWAM_VALUE_TYPE_BOOLEAN) {
		ret = nwam_value_create_boolean_array(boolean_vals, n, &data);
		free(boolean_vals);
	}
	array_free((void **)val, max_str_num);

	if (ret != NWAM_SUCCESS) {
		nwamerr(ret, "Failed creating nwam_value");
		return (NULL);
	}

	return (data);
}

/*
 * Displaying/Skipping of properties
 * ---------------------------------
 *
 * This table shows if a specific property should be shown if some
 * other property has a specific value.  This table is used by
 * show_prop_test(), which is called by set_func() and walkprop_func().
 *
 * An entry in the table looks like:
 *	{ property1, property2, { val1, val2, -1 } }
 * This is read as:
 *	"show property1 only if property2 has value val1 or val2"
 *
 * NB: If a property does not appear in this table, then that implies
 * that the property is always shown.
 *
 * A property can have more than one rule.  In such a case, the property is
 * displayed only any of the rules is satisfied.  This checking, however,
 * is recursive.  If a rule says that a property can be displayed, then the
 * property that's checked should also satisfy its rules.  In the above
 * example, if property1 is to be displayed, then property2 should also
 * satisfy its rules and be displayable.  This recursion is necessary as
 * properties that are not displayed (because rules are not satisfied) are
 * not deleted.
 */

/* The most number of values in pde_checkvals below */
#define	NWAM_CHECKVALS_MAX	5

typedef struct prop_display_entry {
	const char	*pde_name;		/* property to show */
	const char	*pde_checkname;		/* property to check */
	int64_t	pde_checkvals[NWAM_CHECKVALS_MAX]; /* show prop for these */
} prop_display_entry_t;

/* Rules for showing properties: commented for clarity */

/*
 * Rules for NCUs
 * NB: There is no need to have an entry if a property is for IP only.
 *     This is taken care of in libnwam_ncp.c
 */
static prop_display_entry_t ncu_prop_display_entry_table[] = {
	/* show priority-{group,mode} if activation == prioritized */
	{ NWAM_NCU_PROP_PRIORITY_GROUP, NWAM_NCU_PROP_ACTIVATION_MODE,
	    { NWAM_ACTIVATION_MODE_PRIORITIZED, -1 } },
	{ NWAM_NCU_PROP_PRIORITY_MODE, NWAM_NCU_PROP_ACTIVATION_MODE,
	    { NWAM_ACTIVATION_MODE_PRIORITIZED, -1 } },
	/* show ipv4-addrsrc if ip-version == ipv4 */
	{ NWAM_NCU_PROP_IPV4_ADDRSRC, NWAM_NCU_PROP_IP_VERSION,
	    { IPV4_VERSION, -1 } },
	/* show ipv4-addr if ipv4-addrsrc == static */
	{ NWAM_NCU_PROP_IPV4_ADDR, NWAM_NCU_PROP_IPV4_ADDRSRC,
	    { NWAM_ADDRSRC_STATIC, -1 } },
	/* show ipv4-default-route if ip-version == ipv4 */
	{ NWAM_NCU_PROP_IPV4_DEFAULT_ROUTE, NWAM_NCU_PROP_IP_VERSION,
	    { IPV4_VERSION, -1 } },
	/* show ipv6-addrsrc if ip-version == ipv6 */
	{ NWAM_NCU_PROP_IPV6_ADDRSRC, NWAM_NCU_PROP_IP_VERSION,
	    { IPV6_VERSION, -1 } },
	/* show ipv6-addr if ipv6-addrsrc == static */
	{ NWAM_NCU_PROP_IPV6_ADDR, NWAM_NCU_PROP_IPV6_ADDRSRC,
	    { NWAM_ADDRSRC_STATIC, -1 } },
	/* show ipv6-default-route if ip-version == ipv6 */
	{ NWAM_NCU_PROP_IPV6_DEFAULT_ROUTE, NWAM_NCU_PROP_IP_VERSION,
	    { IPV6_VERSION, -1 } },
	/* show ip-primary if ipv4-addrsrc == dhcp */
	{ NWAM_NCU_PROP_IP_PRIMARY, NWAM_NCU_PROP_IPV4_ADDRSRC,
	    { NWAM_ADDRSRC_DHCP, -1 } },
	/* show ip-reqhost if ipv4-addrsrc == dhcp */
	{ NWAM_NCU_PROP_IP_REQHOST, NWAM_NCU_PROP_IPV4_ADDRSRC,
	    { NWAM_ADDRSRC_DHCP, -1 } },
	{ NULL, NULL, { -1 } }
};

/* Rules for ENMs */
static prop_display_entry_t enm_prop_display_entry_table[] = {
	/* show conditions if activation-mode == conditional-{all,any} */
	{ NWAM_ENM_PROP_CONDITIONS, NWAM_ENM_PROP_ACTIVATION_MODE,
	    { NWAM_ACTIVATION_MODE_CONDITIONAL_ALL,
	    NWAM_ACTIVATION_MODE_CONDITIONAL_ANY, -1 } },
	{ NULL, NULL, { -1 } }
};

/* Rules for LOCations */
static prop_display_entry_t loc_prop_display_entry_table[] = {
	/* show conditions if activation-mode == conditional-{all,any} */
	{ NWAM_LOC_PROP_CONDITIONS, NWAM_LOC_PROP_ACTIVATION_MODE,
	    { NWAM_ACTIVATION_MODE_CONDITIONAL_ALL,
	    NWAM_ACTIVATION_MODE_CONDITIONAL_ANY, -1 } },
	/* show dns-nameservice-configsrc if nameservices == dns */
	{ NWAM_LOC_PROP_DNS_NAMESERVICE_CONFIGSRC, NWAM_LOC_PROP_NAMESERVICES,
	    { NWAM_NAMESERVICES_DNS, -1 } },
	/* show other DNS options if dns-nameservices-configsrc == manual */
	{ NWAM_LOC_PROP_DNS_NAMESERVICE_DOMAIN,
	    NWAM_LOC_PROP_DNS_NAMESERVICE_CONFIGSRC,
	    { NWAM_CONFIGSRC_MANUAL, -1 } },
	{ NWAM_LOC_PROP_DNS_NAMESERVICE_SERVERS,
	    NWAM_LOC_PROP_DNS_NAMESERVICE_CONFIGSRC,
	    { NWAM_CONFIGSRC_MANUAL, -1 } },
	{ NWAM_LOC_PROP_DNS_NAMESERVICE_SEARCH,
	    NWAM_LOC_PROP_DNS_NAMESERVICE_CONFIGSRC,
	    { NWAM_CONFIGSRC_MANUAL, -1 } },
	/* show nis-nameservice-configsrc if nameservices == nis */
	{ NWAM_LOC_PROP_NIS_NAMESERVICE_CONFIGSRC, NWAM_LOC_PROP_NAMESERVICES,
	    { NWAM_NAMESERVICES_NIS, -1 } },
	/* show nis-nameservice-servers if nis-nameservice-configsrc = manual */
	{ NWAM_LOC_PROP_NIS_NAMESERVICE_SERVERS,
	    NWAM_LOC_PROP_NIS_NAMESERVICE_CONFIGSRC,
	    { NWAM_CONFIGSRC_MANUAL, -1 } },
	/* show ldap-nameservice-configsrc if nameservices == ldap */
	{ NWAM_LOC_PROP_LDAP_NAMESERVICE_CONFIGSRC, NWAM_LOC_PROP_NAMESERVICES,
	    { NWAM_NAMESERVICES_LDAP, -1 } },
	/* show ldap-nameservice-servers if ldap-nameservice-configsrc=manual */
	{ NWAM_LOC_PROP_LDAP_NAMESERVICE_SERVERS,
	    NWAM_LOC_PROP_LDAP_NAMESERVICE_CONFIGSRC,
	    { NWAM_CONFIGSRC_MANUAL, -1 } },
	/* show default-domain if {nis,ldap}-nameservice-configsrc == manual */
	{ NWAM_LOC_PROP_DEFAULT_DOMAIN, NWAM_LOC_PROP_NIS_NAMESERVICE_CONFIGSRC,
	    { NWAM_CONFIGSRC_MANUAL, -1 } },
	{ NWAM_LOC_PROP_DEFAULT_DOMAIN,
	    NWAM_LOC_PROP_LDAP_NAMESERVICE_CONFIGSRC,
	    { NWAM_CONFIGSRC_MANUAL, -1 } },
	{ NULL, NULL, { -1 } }
};

/* Rules for Known WLANs */
static prop_display_entry_t wlan_prop_display_entry_table[] = {
	/* no rules for WLANs */
	{ NULL, NULL, { -1 } }
};

/* Returns the appropriate rules table for the given object type */
static prop_display_entry_t *
get_prop_display_table(nwam_object_type_t object_type)
{
	switch (object_type) {
	case NWAM_OBJECT_TYPE_NCU:
		return (ncu_prop_display_entry_table);
	case NWAM_OBJECT_TYPE_LOC:
		return (loc_prop_display_entry_table);
	case NWAM_OBJECT_TYPE_ENM:
		return (enm_prop_display_entry_table);
	case NWAM_OBJECT_TYPE_KNOWN_WLAN:
		return (wlan_prop_display_entry_table);
	}
	return (NULL);
}

/*
 * Tests whether prop must be shown during a walk depending on the
 * value of a different property.
 *
 * This function is also used by set_func() to determine whether the
 * property being set should be allowed or not.  If the property
 * would not be displayed in a walk, then it should not be set.
 *
 * The checked_props and num_checked arguments are used to avoid circular
 * dependencies between properties.  When this function recursively calls
 * itself, it adds the property that it just checked to the checked_props
 * list.
 */
static boolean_t
show_prop_test(nwam_object_type_t object_type, const char *prop,
    prop_display_entry_t *display_list, char **checked_props, int num_checked)
{
	nwam_error_t		ret;
	nwam_value_t		prop_val;
	nwam_value_type_t	prop_type;
	int			i, j, k;
	boolean_t		prop_found = B_FALSE, show_prop = B_FALSE;

	/*
	 * Check if this property has already been checked previously in
	 * the recursion.  If so, return B_FALSE so that the initial prop
	 * is not displayed.
	 */
	for (i = 0; i < num_checked; i++) {
		if (strcmp(prop, checked_props[i]) == 0) {
			free(checked_props);
			return (B_FALSE);
		}
	}

	for (i = 0; display_list[i].pde_name != NULL; i++) {
		if (strcmp(prop, display_list[i].pde_name) != 0)
			continue;
		prop_found = B_TRUE;

		/* get the value(s) of the (other) property to check */
		switch (object_type) {
		case NWAM_OBJECT_TYPE_NCU:
			ret = nwam_ncu_get_prop_value(ncu_h,
			    display_list[i].pde_checkname, &prop_val);
			break;
		case NWAM_OBJECT_TYPE_LOC:
			ret = nwam_loc_get_prop_value(loc_h,
			    display_list[i].pde_checkname, &prop_val);
			break;
		case NWAM_OBJECT_TYPE_ENM:
			ret = nwam_enm_get_prop_value(enm_h,
			    display_list[i].pde_checkname, &prop_val);
			break;
		case NWAM_OBJECT_TYPE_KNOWN_WLAN:
			return (B_TRUE);
		}
		if (ret != NWAM_SUCCESS)
			continue;

		/* prop_val may contain a uint64 array or a boolean */
		if (nwam_value_get_type(prop_val, &prop_type) != NWAM_SUCCESS)
			continue;

		if (prop_type == NWAM_VALUE_TYPE_UINT64) {
			uint64_t	*prop_uvals;
			int64_t		*check_uvals;
			uint_t		numvals;

			if (nwam_value_get_uint64_array(prop_val, &prop_uvals,
			    &numvals) != NWAM_SUCCESS) {
				nwam_value_free(prop_val);
				continue;
			}

			/* for each value in uvals, check each value in table */
			for (j = 0; j < numvals; j++) {
				check_uvals = display_list[i].pde_checkvals;
				for (k = 0; check_uvals[k] != -1; k++) {
					/* show if uvals[j] matches */
					if (prop_uvals[j] ==
					    (uint64_t)check_uvals[k]) {
						show_prop = B_TRUE;
						goto next_rule;
					}
				}
			}
		} else if (prop_type == NWAM_VALUE_TYPE_BOOLEAN) {
			boolean_t bval;

			if (nwam_value_get_boolean(prop_val, &bval) !=
			    NWAM_SUCCESS) {
				nwam_value_free(prop_val);
				continue;
			}

			for (k = 0;
			    display_list[i].pde_checkvals[k] != -1;
			    k++) {
				/* show if bval matches */
				if (bval == (boolean_t)
				    display_list[i].pde_checkvals[k]) {
					show_prop = B_TRUE;
					goto next_rule;
				}
			}
		}

next_rule:
		nwam_value_free(prop_val);
		/*
		 * If show_prop is set, then a rule is satisfied; no need to
		 * check other rules for this prop.  However, recursively
		 * check if the checked prop (pde_checkname) satisfies its
		 * rules.  Also, update the check_props array with this prop.
		 */
		if (show_prop) {
			char **newprops = realloc(checked_props,
			    ++num_checked * sizeof (char *));
			if (newprops == NULL) {
				free(checked_props);
				return (B_FALSE);
			}
			checked_props = newprops;
			checked_props[num_checked - 1] = (char *)prop;

			return (show_prop_test(object_type,
			    display_list[i].pde_checkname, display_list,
			    checked_props, num_checked));
		}
	}

	/*
	 * If we are here and prop_found is set, it means that no rules were
	 * satisfied by prop; return B_FALSE.  If prop_found is not set, then
	 * prop did not have a rule so it must be displayed; return B_TRUE.
	 */
	free(checked_props);
	if (prop_found)
		return (B_FALSE);
	else
		return (B_TRUE);
}

/*
 * Returns true if the given property is read-only and cannot be modified.
 */
static boolean_t
is_prop_read_only(nwam_object_type_t object_type, const char *prop)
{
	boolean_t ro;

	switch (object_type) {
	case NWAM_OBJECT_TYPE_NCU:
		if (nwam_ncu_prop_read_only(prop, &ro) == NWAM_SUCCESS && ro)
			return (B_TRUE);
		break;
	case NWAM_OBJECT_TYPE_ENM:
		if (nwam_enm_prop_read_only(prop, &ro) == NWAM_SUCCESS && ro)
			return (B_TRUE);
		break;
	case NWAM_OBJECT_TYPE_LOC:
		if (nwam_loc_prop_read_only(prop, &ro) == NWAM_SUCCESS && ro)
			return (B_TRUE);
		break;
	case NWAM_OBJECT_TYPE_KNOWN_WLAN:
		/* no read-only properties for WLANs */
		return (B_FALSE);
	}
	return (B_FALSE);
}

/* Returns true if the property is multi-valued */
static boolean_t
is_prop_multivalued(nwam_object_type_t object_type, const char *prop)
{
	nwam_error_t	ret;
	boolean_t	multi;

	switch (object_type) {
	case NWAM_OBJECT_TYPE_NCU:
		ret = nwam_ncu_prop_multivalued(prop, &multi);
		break;
	case NWAM_OBJECT_TYPE_LOC:
		ret = nwam_loc_prop_multivalued(prop, &multi);
		break;
	case NWAM_OBJECT_TYPE_ENM:
		ret = nwam_enm_prop_multivalued(prop, &multi);
		break;
	case NWAM_OBJECT_TYPE_KNOWN_WLAN:
		ret = nwam_known_wlan_prop_multivalued(prop, &multi);
		break;
	}

	if (ret != NWAM_SUCCESS)
		multi = B_FALSE;
	return (multi);
}

/*
 * Prints out error message specific to property that could not be set.
 * Property description is used to help guide user in entering correct value.
 */
static void
invalid_set_prop_msg(const char *prop, nwam_error_t err)
{
	const char *description;

	if (err == NWAM_SUCCESS)
		return;

	if (err != NWAM_ENTITY_INVALID_VALUE) {
		nwamerr(err, "Set error");
		return;
	}

	switch (active_object_type()) {
	case NWAM_OBJECT_TYPE_NCU:
		(void) nwam_ncu_get_prop_description(prop, &description);
		break;
	case NWAM_OBJECT_TYPE_LOC:
		(void) nwam_loc_get_prop_description(prop, &description);
		break;
	case NWAM_OBJECT_TYPE_ENM:
		(void) nwam_enm_get_prop_description(prop, &description);
		break;
	case NWAM_OBJECT_TYPE_KNOWN_WLAN:
		(void) nwam_known_wlan_get_prop_description(prop,
		    &description);
		break;
	}
	nerr("Set error: invalid value\n'%s' %s", prop, description);
}

/*
 * Sets the property value.
 * Read-only properties and objects cannot be set.
 * "read-only" is a special in that it can be set on a read-only object.
 * The object has to be committed before other properties can be set.
 * Also uses show_prop_test() to test if the property being set would
 * be skipped during a walk (as determined by the value of some other
 * property).  If so, then it cannot be set.
 */
void
set_func(cmd_t *cmd)
{
	int			pt_type = cmd->cmd_prop_type;
	nwam_error_t		ret = NWAM_SUCCESS;
	nwam_value_t		prop_value;
	const char		*prop;
	boolean_t		is_listprop = B_FALSE;
	nwam_object_type_t	object_type;
	prop_display_entry_t	*prop_table;
	char			**checked = NULL;

	assert(cmd->cmd_argc > 0);

	object_type = active_object_type();
	prop_table = get_prop_display_table(object_type);

	/* argv[0] is property value */
	if ((prop = pt_to_prop_name(object_type, pt_type)) == NULL) {
		nerr("Set error: invalid %s property: '%s'",
		    scope_to_str(current_scope), pt_to_str(pt_type));
		return;
	}

	/* check if property can be set */
	if (is_prop_read_only(object_type, prop)) {
		nerr("Set error: property '%s' is read-only", prop);
		return;
	}
	if (!show_prop_test(object_type, prop, prop_table, checked, 0)) {
		if (interactive_mode) {
			(void) printf(gettext("setting property '%s' "
			    "has no effect\n"), prop);
		}
	}

	is_listprop = is_prop_multivalued(object_type, prop);
	prop_value = str_to_nwam_value(object_type, cmd->cmd_argv[0], pt_type,
	    is_listprop);
	if (prop_value == NULL) {
		invalid_set_prop_msg(prop, NWAM_ENTITY_INVALID_VALUE);
		return;
	}

	/* set the property value */
	switch (object_type) {
	case NWAM_OBJECT_TYPE_NCU:
		ret = nwam_ncu_set_prop_value(ncu_h, prop, prop_value);
		break;
	case NWAM_OBJECT_TYPE_LOC:
		ret = nwam_loc_set_prop_value(loc_h, prop, prop_value);
		break;
	case NWAM_OBJECT_TYPE_ENM:
		ret = nwam_enm_set_prop_value(enm_h, prop, prop_value);
		break;
	case NWAM_OBJECT_TYPE_KNOWN_WLAN:
		ret = nwam_known_wlan_set_prop_value(wlan_h, prop, prop_value);
		break;
	}
	nwam_value_free(prop_value);

	/* delete other properties if needed */
	if (ret == NWAM_SUCCESS)
		need_to_commit = B_TRUE;
	else
		invalid_set_prop_msg(prop, ret);
}

static int
list_callback(nwam_object_type_t object_type, void *handle,
    boolean_t *list_msgp, const char *msg)
{
	nwam_error_t		ret;
	char			*name;
	nwam_ncu_class_t	class;

	if (*list_msgp) {
		(void) printf("%s:\n", msg);
		*list_msgp = B_FALSE;
	}

	ret = object_name_from_handle(object_type, handle, &name);
	if (ret != NWAM_SUCCESS) {
		nwamerr(ret, "List error: failed to get name");
		return (1);
	}

	/* If NCU, get its class and print */
	if (object_type == NWAM_OBJECT_TYPE_NCU) {
		if ((ret = nwam_ncu_get_ncu_class(handle, &class))
		    != NWAM_SUCCESS) {
			nwamerr(ret, "List error: failed to get ncu class");
			free(name);
			return (1);
		} else {
			(void) printf("\t%s",
			    propval_to_str(NWAM_NCU_PROP_CLASS, class));
		}
	}
	(void) printf("\t%s\n", name);

	free(name);
	return (0);
}

/* Print out name, type and status */
static int
list_loc_callback(nwam_loc_handle_t loc, void *arg)
{
	return (list_callback(NWAM_OBJECT_TYPE_LOC, loc, arg, "Locations"));
}

static int
list_enm_callback(nwam_enm_handle_t enm, void *arg)
{
	return (list_callback(NWAM_OBJECT_TYPE_ENM, enm, arg, "ENMs"));
}

static int
list_wlan_callback(nwam_known_wlan_handle_t wlan, void *arg)
{
	return (list_callback(NWAM_OBJECT_TYPE_KNOWN_WLAN, wlan, arg, "WLANs"));
}

static int
list_ncp_callback(nwam_ncp_handle_t ncp, void *arg)
{
	return (list_callback(NWAM_OBJECT_TYPE_NCP, ncp, arg, "NCPs"));
}

static int
list_ncu_callback(nwam_ncu_handle_t ncu, void *arg)
{
	return (list_callback(NWAM_OBJECT_TYPE_NCU, ncu, arg, "NCUs"));
}

/* functions to convert a value to a string */
/* ARGSUSED */
static const char *
str2str(void *s, const char *prop, char *str)
{
	(void) snprintf(str, NWAM_MAX_VALUE_LEN, "%s", s);
	return (str);
}

/* ARGSUSED */
static const char *
str2qstr(void *s, const char *prop, char *qstr)
{
	/* quoted strings */
	(void) snprintf(qstr, NWAM_MAX_VALUE_LEN, "\"%s\"", s);
	return (qstr);
}

/* ARGSUSED */
static const char *
int2str(void *in, const char *prop, char *instr)
{
	(void) snprintf(instr, NWAM_MAX_VALUE_LEN, "%lld", *((int64_t *)in));
	return (instr);
}

static const char *
uint2str(void *uin, const char *prop, char *uintstr)
{
	/* returns NWAM_SUCCESS if prop is enum with string in uintstr */
	if (nwam_uint64_get_value_string(prop, *((uint64_t *)uin),
	    (const char **)&uintstr) != NWAM_SUCCESS) {
		(void) snprintf(uintstr, NWAM_MAX_VALUE_LEN, "%lld",
		    *((uint64_t *)uin));
	}
	return (uintstr);
}

/* ARGSUSED */
static const char *
bool2str(void *bool, const char *prop, char *boolstr)
{
	(void) snprintf(boolstr, NWAM_MAX_VALUE_LEN, "%s",
	    *((boolean_t *)bool) ? "true" : "false");
	return (boolstr);
}

/*
 * Print the value (enums are converted to string), use DELIMITER for
 * array.  If strings are to be "quoted", pass B_TRUE for quoted_strings.
 */
static void
output_prop_val(const char *prop_name, nwam_value_t value, FILE *wf,
    boolean_t quoted_strings)
{
	nwam_value_type_t	value_type;
	uint_t			num;

	/* arrays for values retrieved according to the type of value */
	char		**svals;
	uint64_t	*uvals;
	int64_t		*ivals;
	boolean_t	*bvals;

	/* pointer to function to generate string representation of value */
	const char	*(*tostr)(void *, const char *, char *);
	char		str[NWAM_MAX_VALUE_LEN]; /* to store the string */
	int		i;

	if (nwam_value_get_type(value, &value_type) != NWAM_SUCCESS) {
		nerr("Get value type error");
		return;
	}

	if (value_type == NWAM_VALUE_TYPE_STRING) {
		if (nwam_value_get_string_array(value, &svals, &num) !=
		    NWAM_SUCCESS) {
			nerr("Get string array error");
			return;
		}
		tostr = quoted_strings ? str2qstr : str2str;
	} else if (value_type == NWAM_VALUE_TYPE_INT64) {
		if (nwam_value_get_int64_array(value, &ivals, &num) !=
		    NWAM_SUCCESS) {
			nerr("Get int64 array error");
			return;
		}
		tostr = int2str;
	} else if (value_type == NWAM_VALUE_TYPE_UINT64) {
		if (nwam_value_get_uint64_array(value, &uvals, &num) !=
		    NWAM_SUCCESS) {
			nerr("Get uint64 array error");
			return;
		}
		tostr = uint2str;
	} else if (value_type == NWAM_VALUE_TYPE_BOOLEAN) {
		if (nwam_value_get_boolean_array(value, &bvals, &num) !=
		    NWAM_SUCCESS) {
			nerr("Get boolean array error");
			return;
		}
		tostr = bool2str;
	}

	/* now, loop and print each value */
	for (i = 0; i < num; i++) {
		void *val;

		/* get the pointer to the ith value to pass to func() */
		if (value_type == NWAM_VALUE_TYPE_STRING)
			val = svals[i];
		else if (value_type == NWAM_VALUE_TYPE_UINT64)
			val = &(uvals[i]);
		else if (value_type == NWAM_VALUE_TYPE_INT64)
			val = &(ivals[i]);
		else if (value_type == NWAM_VALUE_TYPE_BOOLEAN)
			val = &(bvals[i]);

		(void) fprintf(wf, "%s%s", tostr(val, prop_name, str),
		    i != num-1 ? NWAM_VALUE_DELIMITER_STR : "");
	}
}

/* Prints the property names aligned (for list/get) or "prop=" (for export) */
static int
output_propname_common(const char *prop, nwam_value_t values, void *arg,
    int width)
{
	FILE *of = (arg == NULL) ? stdout : arg;

	/* arg is NULL for list/get, not NULL for export */
	if (arg == NULL)
		(void) fprintf(of, "\t%-*s\t", width, prop);
	else
		(void) fprintf(of, "%s=", prop);

	if (values != NULL)
		output_prop_val(prop, values, of, B_TRUE);

	(void) fprintf(of, "\n");
	return (0);
}

static int
output_propname(const char *prop, nwam_value_t values, void *arg)
{
	return (output_propname_common(prop, values, arg, 16));
}

/* For locations because of longer property names */
static int
output_loc_propname(const char *prop, nwam_value_t values, void *arg)
{
	return (output_propname_common(prop, values, arg, 25));
}

/*
 * all_props specifies whether properties that have not been set should be
 * printed or not.  ncp and ncu_type are used only when the object_type is
 * NCU.
 */
static nwam_error_t
listprop(nwam_object_type_t object_type, void *handle, const char *name,
    boolean_t all_props, nwam_ncp_handle_t ncp, nwam_ncu_type_t ncu_type)
{
	nwam_error_t	ret;
	char		*lname = NULL, *realname = NULL;
	boolean_t	lhandle = B_FALSE;
	const char	**props = NULL;
	uint_t		prop_num;
	int		i;
	nwam_value_t	vals;

	/*
	 * handle is NULL if called from a scope higher than the object's
	 * scope, but name must be given; so get the handle.
	 */
	if (handle == NULL) {
		lname = trim_quotes(name); /* name may have quotes */
		switch (object_type) {
		case NWAM_OBJECT_TYPE_NCP:
			if ((ret = nwam_ncp_read(lname, 0,
			    (nwam_ncp_handle_t *)&handle)) != NWAM_SUCCESS)
				goto readfail;
			break;
		case NWAM_OBJECT_TYPE_NCU:
			ret = nwam_ncu_read(ncp, lname, ncu_type, 0,
			    (nwam_ncu_handle_t *)&handle);
			if (ret == NWAM_ENTITY_MULTIPLE_VALUES) {
				/*
				 * Multiple NCUs with the given name exists.
				 * Call listprop() for each NCU type.
				 */
				if ((ret = listprop(object_type, NULL, lname,
				    all_props, ncp, NWAM_NCU_TYPE_LINK))
				    != NWAM_SUCCESS)
					goto done;
				ret = listprop(object_type, NULL, lname,
				    all_props, ncp, NWAM_NCU_TYPE_INTERFACE);
				goto done;
			} else if (ret != NWAM_SUCCESS) {
				goto readfail;
			}
			break;
		case NWAM_OBJECT_TYPE_LOC:
			if ((ret = nwam_loc_read(lname, 0,
			    (nwam_loc_handle_t *)&handle)) != NWAM_SUCCESS)
				goto readfail;
			break;
		case NWAM_OBJECT_TYPE_ENM:
			if ((ret = nwam_enm_read(lname, 0,
			    (nwam_enm_handle_t *)&handle)) != NWAM_SUCCESS)
				goto readfail;
			break;
		case NWAM_OBJECT_TYPE_KNOWN_WLAN:
			if ((ret = nwam_known_wlan_read(lname, 0,
			    (nwam_known_wlan_handle_t *)&handle))
			    != NWAM_SUCCESS)
				goto readfail;
			break;
		}
		lhandle = B_TRUE;
	}

	if ((ret = object_name_from_handle(object_type, handle, &realname))
	    != NWAM_SUCCESS)
		goto done;

	/* get the property list */
	switch (object_type) {
	case NWAM_OBJECT_TYPE_NCP:
	{
		/* walk NCUs */
		boolean_t list_msg = B_TRUE;
		ret = nwam_ncp_walk_ncus(handle, list_ncu_callback, &list_msg,
		    NWAM_FLAG_NCU_TYPE_CLASS_ALL, NULL);
		goto done;
	}
	case NWAM_OBJECT_TYPE_NCU:
	{
		nwam_ncu_type_t		ncu_type;
		nwam_ncu_class_t	ncu_class;

		if ((ret = nwam_ncu_get_ncu_type(handle, &ncu_type))
		    != NWAM_SUCCESS)
			goto done;
		if ((ret = nwam_ncu_get_ncu_class(handle, &ncu_class))
		    != NWAM_SUCCESS)
			goto done;

		ret = nwam_ncu_get_default_proplist(ncu_type, ncu_class, &props,
		    &prop_num);
		break;
	}
	case NWAM_OBJECT_TYPE_LOC:
		ret = nwam_loc_get_default_proplist(&props, &prop_num);
		break;
	case NWAM_OBJECT_TYPE_ENM:
		ret = nwam_enm_get_default_proplist(&props, &prop_num);
		break;
	case NWAM_OBJECT_TYPE_KNOWN_WLAN:
		ret = nwam_known_wlan_get_default_proplist(&props, &prop_num);
		break;
	}
	if (ret != NWAM_SUCCESS)
		goto done;

	/* print object type and name */
	(void) printf("%s:%s\n", nwam_object_type_to_string(object_type),
	    realname);

	/* Loop through the properties and print */
	for (i = 0; i < prop_num; i++) {
		/* get the existing value for this property */
		switch (object_type) {
		case NWAM_OBJECT_TYPE_NCU:
			ret = nwam_ncu_get_prop_value(handle, props[i], &vals);
			break;
		case NWAM_OBJECT_TYPE_LOC:
			ret = nwam_loc_get_prop_value(handle, props[i], &vals);
			break;
		case NWAM_OBJECT_TYPE_ENM:
			ret = nwam_enm_get_prop_value(handle, props[i], &vals);
			break;
		case NWAM_OBJECT_TYPE_KNOWN_WLAN:
			ret = nwam_known_wlan_get_prop_value(handle, props[i],
			    &vals);
			break;
		}
		if (ret != NWAM_SUCCESS) {
			/* _ENTITY_NOT_FOUND is ok if listing for all props */
			if (!all_props)
				continue;
			else if (ret != NWAM_ENTITY_NOT_FOUND)
				continue;
		}

		/* print property and value */
		if (object_type == NWAM_OBJECT_TYPE_LOC)
			output_loc_propname(props[i], vals, NULL);
		else
			output_propname(props[i], vals, NULL);
		nwam_value_free(vals);
	}

done:
	free(lname);
	free(realname);
	if (props != NULL)
		free(props);
	if (lhandle) {
		switch (object_type) {
		case NWAM_OBJECT_TYPE_NCP:
			nwam_ncp_free(handle);
			break;
		case NWAM_OBJECT_TYPE_NCU:
			nwam_ncu_free(handle);
			break;
		case NWAM_OBJECT_TYPE_LOC:
			nwam_loc_free(handle);
			break;
		case NWAM_OBJECT_TYPE_ENM:
			nwam_enm_free(handle);
			break;
		case NWAM_OBJECT_TYPE_KNOWN_WLAN:
			nwam_known_wlan_free(handle);
			break;
		}
	}
	/* don't treat _ENTITY_NOT_FOUND as an error */
	if (ret == NWAM_ENTITY_NOT_FOUND)
		ret = NWAM_SUCCESS;
	return (ret);

readfail:
	/* When nwam_*_read() fails */
	free(lname);
	return (ret);
}

/*
 * List profiles or property and its values.
 * If the -a option is specified, all properties are listed.
 */
void
list_func(cmd_t *cmd)
{
	nwam_error_t	ret = NWAM_SUCCESS;
	boolean_t	list_msg = B_TRUE;

	boolean_t	list_loc = B_FALSE, list_enm = B_FALSE;
	boolean_t	list_ncp = B_FALSE, list_ncu = B_FALSE;
	boolean_t	list_wlan = B_FALSE;

	/* whether all properties should be listed, given by the -a option */
	boolean_t	all_props = B_FALSE;

	/*
	 * list_props says whether the properties should be listed.
	 * Note that, here NCUs are treated as properties of NCPs.
	 */
	boolean_t	list_props = B_FALSE;

	/* determine which properties to list, also validity tests */
	if (current_scope == NWAM_SCOPE_GBL) {
		/* res1_type is -1 if only "list -a" is used */
		if (cmd->cmd_res1_type == -1) {
			nerr("'list' requires an object to be specified with "
			    "the -a option in the global scope");
			return;
		}
		if (cmd->cmd_res1_type == RT1_LOC) {
			list_props = B_TRUE;
			list_loc = B_TRUE;
		} else if (cmd->cmd_res1_type == RT1_ENM) {
			list_props = B_TRUE;
			list_enm = B_TRUE;
		} else if (cmd->cmd_res1_type == RT1_WLAN) {
			list_props = B_TRUE;
			list_wlan = B_TRUE;
		} else if (cmd->cmd_res1_type == RT1_NCP) {
			list_ncp = B_TRUE;
			list_props = B_TRUE;
		} else {
			list_loc = B_TRUE;
			list_enm = B_TRUE;
			list_wlan = B_TRUE;
			list_ncp = B_TRUE;
		}
	}
	if ((current_scope == NWAM_SCOPE_LOC ||
	    current_scope == NWAM_SCOPE_ENM ||
	    current_scope == NWAM_SCOPE_WLAN ||
	    current_scope == NWAM_SCOPE_NCU) &&
	    (cmd->cmd_argc >= 1 && cmd->cmd_res1_type != -1)) {
		nerr("Additional options are not allowed with the -a option "
		    "at this scope");
		return;
	}
	if (current_scope == NWAM_SCOPE_LOC) {
		list_loc = B_TRUE;
		list_props = B_TRUE;
	}
	if (current_scope == NWAM_SCOPE_ENM) {
		list_enm = B_TRUE;
		list_props = B_TRUE;
	}
	if (current_scope == NWAM_SCOPE_WLAN) {
		list_wlan = B_TRUE;
		list_props = B_TRUE;
	}
	if (current_scope == NWAM_SCOPE_NCP) {
		if (cmd->cmd_res1_type == RT1_ENM ||
		    cmd->cmd_res1_type == RT1_LOC ||
		    cmd->cmd_res1_type == RT1_WLAN) {
			nerr("only ncu can be listed at this scope");
			return;
		}
		if (cmd->cmd_res2_type == RT2_NCU) {
			list_ncu = B_TRUE;
			list_props = B_TRUE;
		} else {
			list_ncp = B_TRUE;
			list_props = B_TRUE;
		}
	}
	if (current_scope == NWAM_SCOPE_NCU) {
		list_ncu = B_TRUE;
		list_props = B_TRUE;
	}

	/* Check if the -a option is specified to list all properties */
	if (cmd->cmd_res1_type == -1 || cmd->cmd_argc == 2) {
		int c, argc = 1;
		char **argv;
		optind = 0;

		/* if res1_type is -1, option is in argv[0], else in argv[1] */
		if (cmd->cmd_res1_type == -1)
			argv = cmd->cmd_argv;
		else
			argv = &(cmd->cmd_argv[1]);
		while ((c = getopt(argc, argv, "a")) != EOF) {
			switch (c) {
			case 'a':
				all_props = B_TRUE;
				break;
			default:
				command_usage(CMD_LIST);
				return;
			}
		}
		if (cmd->cmd_res1_type == -1)
			cmd->cmd_argv[0] = NULL;
	}

	/*
	 * Now, print objects and/or according to the flags set.
	 * name, if requested, is in argv[0].
	 */
	if (list_ncp) {
		list_msg = B_TRUE;
		if (list_props) {
			ret = listprop(NWAM_OBJECT_TYPE_NCP, ncp_h,
			    cmd->cmd_argv[0], all_props, NULL, -1);
		} else {
			ret = nwam_walk_ncps(list_ncp_callback, &list_msg, 0,
			    NULL);
		}
		if (ret != NWAM_SUCCESS)
			goto done;
	}

	if (list_ncu) {
		list_msg = B_TRUE;
		if (ncp_h == NULL) {
			nerr("NCP has not been read");
			return;
		}
		if (list_props) {
			nwam_ncu_class_t	ncu_class;
			nwam_ncu_type_t		ncu_type;

			/* determine the NCU type first */
			if (ncu_h == NULL) {
				ncu_class = (nwam_ncu_class_t)
				    cmd->cmd_ncu_class_type;
				ncu_type = nwam_ncu_class_to_type(ncu_class);
			} else {
				if ((ret = nwam_ncu_get_ncu_type(ncu_h,
				    &ncu_type)) != NWAM_SUCCESS)
					goto done;
			}
			ret = listprop(NWAM_OBJECT_TYPE_NCU, ncu_h,
			    cmd->cmd_argv[0], all_props, ncp_h, ncu_type);
			if (ret != NWAM_SUCCESS)
				goto done;
		}
	}

	if (list_loc) {
		list_msg = B_TRUE;
		if (list_props) {
			ret = listprop(NWAM_OBJECT_TYPE_LOC, loc_h,
			    cmd->cmd_argv[0], all_props, NULL, -1);
		} else {
			ret = nwam_walk_locs(list_loc_callback, &list_msg,
			    NWAM_FLAG_ACTIVATION_MODE_ALL, NULL);
		}
		if (ret != NWAM_SUCCESS)
			goto done;
	}

	if (list_enm) {
		list_msg = B_TRUE;
		if (list_props) {
			ret = listprop(NWAM_OBJECT_TYPE_ENM, enm_h,
			    cmd->cmd_argv[0], all_props, NULL, -1);
		} else {
			ret = nwam_walk_enms(list_enm_callback, &list_msg,
			    NWAM_FLAG_ACTIVATION_MODE_ALL, NULL);
		}
		if (ret != NWAM_SUCCESS)
			goto done;
	}

	if (list_wlan) {
		list_msg = B_TRUE;
		if (list_props) {
			ret = listprop(NWAM_OBJECT_TYPE_KNOWN_WLAN, wlan_h,
			    cmd->cmd_argv[0], all_props, NULL, -1);
		} else {
			ret = nwam_walk_known_wlans(list_wlan_callback,
			    &list_msg, NWAM_FLAG_KNOWN_WLAN_WALK_PRIORITY_ORDER,
			    NULL);
		}
		if (ret != NWAM_SUCCESS)
			goto done;
	}

done:
	if (ret != NWAM_SUCCESS)
		nwamerr(ret, "List error");
}

static int
write_export_command(nwam_object_type_t object_type, const char *prop,
    nwam_value_t values, FILE *of)
{
	/* exclude read-only properties */
	if (is_prop_read_only(object_type, prop))
		return (0);

	(void) fprintf(of, "set ");
	output_propname(prop, values, of);
	return (0);
}

static int
export_ncu_callback(nwam_ncu_handle_t ncu, void *arg)
{
	char		*name;
	const char	**props;
	nwam_ncu_type_t type;
	nwam_ncu_class_t class;
	nwam_value_t	vals;
	nwam_error_t	ret;
	uint_t		num;
	int		i;
	FILE		*of = arg;

	assert(of != NULL);

	/* get the NCU's type and class */
	if ((ret = nwam_ncu_get_ncu_type(ncu, &type)) != NWAM_SUCCESS)
		return (ret);
	if ((ret = nwam_ncu_get_ncu_class(ncu, &class)) != NWAM_SUCCESS)
		return (ret);

	if ((ret = nwam_ncu_get_name(ncu, &name)) != NWAM_SUCCESS)
		return (ret);

	(void) fprintf(of, "create ncu %s \"%s\"\n",
	    propval_to_str(NWAM_NCU_PROP_CLASS, class), name);
	free(name);
	/*
	 * Because of dependencies between properties, they have to be
	 * exported in the same order as when they are walked.
	 */
	if ((ret = nwam_ncu_get_default_proplist(type, class, &props, &num))
	    != NWAM_SUCCESS)
		return (ret);
	for (i = 0; i < num; i++) {
		ret = nwam_ncu_get_prop_value(ncu, props[i], &vals);
		if (ret == NWAM_SUCCESS) {
			write_export_command(NWAM_OBJECT_TYPE_NCU, props[i],
			    vals, of);
			nwam_value_free(vals);
		}
	}
	(void) fprintf(of, "end\n");

	free(props);
	return (0);
}

static int
export_ncp_callback(nwam_ncp_handle_t ncp, void *arg)
{
	char		*name;
	nwam_error_t	ret;
	FILE		*of = arg;

	assert(of != NULL);

	if ((ret = nwam_ncp_get_name(ncp, &name)) != NWAM_SUCCESS)
		return (ret);

	/* Do not export "automatic" NCP */
	if (NWAM_NCP_AUTOMATIC(name)) {
		free(name);
		return (0);
	}

	(void) fprintf(of, "create ncp \"%s\"\n", name);
	free(name);

	/* now walk NCUs for this ncp */
	ret = nwam_ncp_walk_ncus(ncp, export_ncu_callback, of,
	    NWAM_FLAG_NCU_TYPE_CLASS_ALL, NULL);
	if (ret != NWAM_SUCCESS) {
		nwamerr(ret, "Export ncp error: failed to walk ncus");
		return (ret);
	}
	(void) fprintf(of, "end\n");
	return (0);
}

static int
export_enm_callback(nwam_enm_handle_t enm, void *arg)
{
	char		*name;
	const char	**props;
	nwam_value_t	vals;
	nwam_error_t	ret;
	uint_t		num;
	int		i;
	FILE		*of = arg;

	assert(of != NULL);

	if ((ret = nwam_enm_get_name(enm, &name)) != NWAM_SUCCESS)
		return (ret);

	(void) fprintf(of, "create enm \"%s\"\n", name);
	free(name);
	/*
	 * Because of dependencies between properties, they have to be
	 * exported in the same order as when they are walked.
	 */
	if ((ret = nwam_enm_get_default_proplist(&props, &num)) != NWAM_SUCCESS)
		return (ret);
	for (i = 0; i < num; i++) {
		ret = nwam_enm_get_prop_value(enm, props[i], &vals);
		if (ret == NWAM_SUCCESS) {
			write_export_command(NWAM_OBJECT_TYPE_ENM, props[i],
			    vals, of);
			nwam_value_free(vals);
		}
	}
	(void) fprintf(of, "end\n");

	free(props);
	return (0);
}

static int
export_loc_callback(nwam_loc_handle_t loc, void *arg)
{
	char		*name;
	const char	**props;
	nwam_value_t	vals;
	nwam_error_t	ret;
	uint_t		num;
	int		i;
	FILE		*of = arg;

	assert(of != NULL);

	if ((ret = nwam_loc_get_name(loc, &name)) != NWAM_SUCCESS)
		return (ret);

	/* Do not export Automatic, NoNet or Legacy locations */
	if (NWAM_LOC_NAME_PRE_DEFINED(name)) {
		free(name);
		return (0);
	}

	(void) fprintf(of, "create loc \"%s\"\n", name);
	free(name);
	/*
	 * Because of dependencies between properties, they have to be
	 * exported in the same order as when they are walked.
	 */
	if ((ret = nwam_loc_get_default_proplist(&props, &num)) != NWAM_SUCCESS)
		return (ret);
	for (i = 0; i < num; i++) {
		ret = nwam_loc_get_prop_value(loc, props[i], &vals);
		if (ret == NWAM_SUCCESS) {
			write_export_command(NWAM_OBJECT_TYPE_LOC, props[i],
			    vals, of);
			nwam_value_free(vals);
		}
	}
	(void) fprintf(of, "end\n");

	free(props);
	return (0);
}

static int
export_wlan_callback(nwam_known_wlan_handle_t wlan, void *arg)
{
	char		*name;
	const char	**props;
	nwam_value_t	vals;
	nwam_error_t	ret;
	uint_t		num;
	int		i;
	FILE		*of = arg;

	assert(of != NULL);

	if ((ret = nwam_known_wlan_get_name(wlan, &name)) != NWAM_SUCCESS)
		return (ret);

	(void) fprintf(of, "create wlan \"%s\"\n", name);
	free(name);
	/*
	 * Because of dependencies between properties, they have to be
	 * exported in the same order as when they are walked.
	 */
	if ((ret = nwam_known_wlan_get_default_proplist(&props, &num))
	    != NWAM_SUCCESS)
		return (ret);
	for (i = 0; i < num; i++) {
		ret = nwam_known_wlan_get_prop_value(wlan, props[i], &vals);
		if (ret == NWAM_SUCCESS) {
			write_export_command(NWAM_OBJECT_TYPE_KNOWN_WLAN,
			    props[i], vals, of);
			nwam_value_free(vals);
		}
	}
	(void) fprintf(of, "end\n");

	free(props);
	return (0);
}

/*
 * Writes configuration to screen or file (with -f option).
 * Writes a "destroy -a" if option -d is given.
 */
void
export_func(cmd_t *cmd)
{
	int		c;
	boolean_t	need_to_close = B_FALSE, write_to_file = B_FALSE;
	boolean_t	add_destroy = B_FALSE, lhandle = B_FALSE;
	char		filepath[MAXPATHLEN];
	nwam_error_t	ret = NWAM_SUCCESS;
	FILE		*of = NULL; /* either filename or stdout */

	/* what to export */
	boolean_t export_ncp = B_FALSE, export_ncu = B_FALSE;
	boolean_t export_loc = B_FALSE, export_enm = B_FALSE;
	boolean_t export_wlan = B_FALSE;
	char *name = NULL;

	/* check for -d and -f flags */
	filepath[0] = '\0';
	optind = 0;
	while ((c = getopt(cmd->cmd_argc, cmd->cmd_argv, "df:")) != EOF) {
		switch (c) {
		case 'f':
			write_to_file = B_TRUE;
			break;
		case 'd':
			add_destroy = B_TRUE;
			break;
		default:
			command_usage(CMD_EXPORT);
			return;
		}
	}

	/* determine where to export */
	if (!write_to_file) {
		of = stdout;
	} else {
		/*
		 * If -d was specified with -f, then argv[2] is filename,
		 * otherwise, argv[1] is filename.
		 */
		(void) strlcpy(filepath,
		    (add_destroy ? cmd->cmd_argv[2] : cmd->cmd_argv[1]),
		    sizeof (filepath));
		if ((of = fopen(filepath, "w")) == NULL) {
			nerr(gettext("opening file '%s': %s"), filepath,
			    strerror(errno));
			goto done;
		}
		setbuf(of, NULL);
		need_to_close = B_TRUE;
	}

	if (add_destroy) {
		/* only possible in global scope */
		if (current_scope == NWAM_SCOPE_GBL) {
			(void) fprintf(of, "destroy -a\n");
		} else {
			nerr("Option -d is not allowed in non-global scope");
			goto done;
		}
	}

	/* In the following scopes, only the -f argument is valid */
	if (((current_scope == NWAM_SCOPE_LOC ||
	    current_scope == NWAM_SCOPE_ENM ||
	    current_scope == NWAM_SCOPE_WLAN ||
	    current_scope == NWAM_SCOPE_NCU) &&
	    cmd->cmd_argc != 0 && !write_to_file)) {
		nerr("'export' does not take arguments at this scope");
		goto done;
	}
	if (current_scope == NWAM_SCOPE_NCP) {
		if (cmd->cmd_res1_type == RT1_ENM ||
		    cmd->cmd_res1_type == RT1_LOC ||
		    cmd->cmd_res1_type == RT1_WLAN) {
			nerr("only ncu can be exported at this scope");
			goto done;
		}
	}

	/*
	 * Determine what objects to export depending on scope and command
	 * arguments.  If -f is specified, then the object name is argv[2].
	 * Otherwise, argv[0] is name, unless exporting all in global
	 * scope in which case name is set back to NULL.
	 */
	switch (current_scope) {
	case NWAM_SCOPE_GBL:
		name = (write_to_file ? trim_quotes(cmd->cmd_argv[2]) :
		    trim_quotes(cmd->cmd_argv[0]));
		switch (cmd->cmd_res1_type) {
		case RT1_LOC:
			export_loc = B_TRUE;
			break;
		case RT1_ENM:
			export_enm = B_TRUE;
			break;
		case RT1_WLAN:
			export_wlan = B_TRUE;
			break;
		case RT1_NCP:
			export_ncp = B_TRUE;
			if (cmd->cmd_res2_type == RT2_NCU) {
				nerr("cannot export ncu at from global scope");
				goto done;
			}
			break;
		default:
			/* export everything */
			export_loc = B_TRUE;
			export_enm = B_TRUE;
			export_wlan = B_TRUE;
			export_ncp = B_TRUE; /* NCP will export the NCUs */
			free(name);
			name = NULL; /* exporting all, undo name */
			break;
		}
		break;
	case NWAM_SCOPE_LOC:
		export_loc = B_TRUE;
		ret = nwam_loc_get_name(loc_h, &name);
		if (ret != NWAM_SUCCESS)
			goto fail;
		break;
	case NWAM_SCOPE_ENM:
		export_enm = B_TRUE;
		ret = nwam_enm_get_name(enm_h, &name);
		if (ret != NWAM_SUCCESS)
			goto fail;
		break;
	case NWAM_SCOPE_WLAN:
		export_wlan = B_TRUE;
		ret = nwam_known_wlan_get_name(wlan_h, &name);
		if (ret != NWAM_SUCCESS)
			goto fail;
		break;
	case NWAM_SCOPE_NCP:
		if (cmd->cmd_res2_type == RT2_NCU) {
			export_ncu = B_TRUE;
			name = (write_to_file ? trim_quotes(cmd->cmd_argv[2]) :
			    trim_quotes(cmd->cmd_argv[0]));
		} else {
			export_ncp = B_TRUE;
			ret = nwam_ncp_get_name(ncp_h, &name);
			if (ret != NWAM_SUCCESS)
				goto fail;
		}
		break;
	case NWAM_SCOPE_NCU:
		export_ncu = B_TRUE;
		ret = nwam_ncu_get_name(ncu_h, &name);
		if (ret != NWAM_SUCCESS)
			goto fail;
		break;
	default:
		nerr("Invalid scope");
		goto done;
	}

	/* Now, export objects according to the flags set */
	if (export_ncp) {
		lhandle = B_FALSE;
		if (name == NULL) {
			/* export all NCPs */
			ret = nwam_walk_ncps(export_ncp_callback, of, 0, NULL);
		} else if (NWAM_NCP_AUTOMATIC(name)) {
			nerr("'%s' ncp cannot be exported", name);
			goto fail;
		} else {
			if (ncp_h == NULL) {
				ret = nwam_ncp_read(name, 0, &ncp_h);
				if (ret != NWAM_SUCCESS)
					goto fail;
				lhandle = B_TRUE;
			}
			/* will export NCUs also */
			ret = export_ncp_callback(ncp_h, of);
			if (lhandle) {
				nwam_ncp_free(ncp_h);
				ncp_h = NULL;
			}
		}
		if (ret != NWAM_SUCCESS)
			goto fail;
	}

	if (export_ncu) {
		if (name == NULL) {
			/* export all NCUs */
			ret = nwam_ncp_walk_ncus(ncp_h, export_ncu_callback, of,
			    NWAM_FLAG_NCU_TYPE_CLASS_ALL, NULL);
		} else {
			if (ncu_h == NULL) {
				/* no NCU handle -> called from NCP scope */
				nwam_ncu_type_t		ncu_type;
				nwam_ncu_class_t	ncu_class;

				ncu_class = (nwam_ncu_class_t)
				    cmd->cmd_ncu_class_type;
				ncu_type = nwam_ncu_class_to_type(ncu_class);
				ret = nwam_ncu_read(ncp_h, name,
				    ncu_type, 0, &ncu_h);
				if (ret == NWAM_SUCCESS) {
					/* one NCU with given name */
					ret = export_ncu_callback(ncu_h, of);
					nwam_ncu_free(ncu_h);
					ncu_h = NULL;
				} else if (ret == NWAM_ENTITY_MULTIPLE_VALUES) {
					/* multiple NCUs with given name */
					ret = nwam_ncu_read(ncp_h, name,
					    NWAM_NCU_TYPE_LINK, 0, &ncu_h);
					if (ret != NWAM_SUCCESS)
						goto fail;
					ret = export_ncu_callback(ncu_h, of);
					nwam_ncu_free(ncu_h);
					ncu_h = NULL;

					ret = nwam_ncu_read(ncp_h, name,
					    NWAM_NCU_TYPE_INTERFACE, 0, &ncu_h);
					if (ret != NWAM_SUCCESS)
						goto fail;
					ret = export_ncu_callback(ncu_h, of);
					nwam_ncu_free(ncu_h);
					ncu_h = NULL;
				} else {
					goto fail;
				}
			} else {
				/* NCU handle exists */
				ret = export_ncu_callback(ncu_h, of);
			}
		}
		if (ret != NWAM_SUCCESS)
			goto fail;
	}

	if (export_loc) {
		lhandle = B_FALSE;
		if (name == NULL) {
			/* export all locations */
			ret = nwam_walk_locs(export_loc_callback, of,
			    NWAM_FLAG_ACTIVATION_MODE_ALL, NULL);
		} else if (NWAM_LOC_NAME_PRE_DEFINED(name)) {
			nerr("'%s' loc cannot be exported", name);
			goto fail;
		} else {
			if (loc_h == NULL) {
				ret = nwam_loc_read(name, 0, &loc_h);
				if (ret != NWAM_SUCCESS)
					goto fail;
				lhandle = B_TRUE;
			}
			ret = export_loc_callback(loc_h, of);
			if (lhandle) {
				nwam_loc_free(loc_h);
				loc_h = NULL;
			}
		}
		if (ret != NWAM_SUCCESS)
			goto fail;
	}

	if (export_enm) {
		lhandle = B_FALSE;
		if (name == NULL) {
			/* export all ENMs */
			ret = nwam_walk_enms(export_enm_callback, of,
			    NWAM_FLAG_ACTIVATION_MODE_ALL, NULL);
		} else {
			if (enm_h == NULL) {
				ret = nwam_enm_read(name, 0, &enm_h);
				if (ret != NWAM_SUCCESS)
					goto fail;
				lhandle = B_TRUE;
			}
			ret = export_enm_callback(enm_h, of);
			if (lhandle) {
				nwam_enm_free(enm_h);
				enm_h = NULL;
			}
		}
		if (ret != NWAM_SUCCESS)
			goto fail;
	}

	if (export_wlan) {
		lhandle = B_FALSE;
		if (name == NULL) {
			/* export all WLANs */
			ret = nwam_walk_known_wlans(export_wlan_callback, of,
			    NWAM_FLAG_KNOWN_WLAN_WALK_PRIORITY_ORDER, NULL);
		} else {
			if (wlan_h == NULL) {
				ret = nwam_known_wlan_read(name, 0,
				    &wlan_h);
				if (ret != NWAM_SUCCESS)
					goto fail;
				lhandle = B_TRUE;
			}
			ret = export_wlan_callback(wlan_h, of);
			if (lhandle) {
				nwam_known_wlan_free(wlan_h);
				wlan_h = NULL;
			}
		}
		if (ret != NWAM_SUCCESS)
			goto fail;
	}

fail:
	free(name);
	if (ret != NWAM_SUCCESS)
		nwamerr(ret, "Export error");

done:
	if (need_to_close)
		(void) fclose(of);
}

/*
 * Get property value.  If the -V option is specified, only the value is
 * printed without the property name.
 */
void
get_func(cmd_t *cmd)
{
	nwam_error_t		ret = NWAM_SUCCESS;
	nwam_value_t		prop_value;
	const char		*prop;
	boolean_t		value_only = B_FALSE;
	nwam_object_type_t	object_type = active_object_type();

	/* check if option is -V to print value only */
	if (cmd->cmd_argc == 1) {
		int c;

		optind = 0;
		while ((c = getopt(cmd->cmd_argc, cmd->cmd_argv, "V")) != EOF) {
			switch (c) {
			case 'V':
				value_only = B_TRUE;
				break;
			default:
				command_usage(CMD_GET);
				return;
			}
		}
	}

	/* property to get is in cmd->cmd_prop_type */
	if ((prop = pt_to_prop_name(object_type, cmd->cmd_prop_type)) == NULL) {
		nerr("Get error: invalid %s property: '%s'",
		    scope_to_str(current_scope), pt_to_str(cmd->cmd_prop_type));
		return;
	}

	switch (object_type) {
	case NWAM_OBJECT_TYPE_NCU:
		ret = nwam_ncu_get_prop_value(ncu_h, prop, &prop_value);
		break;
	case NWAM_OBJECT_TYPE_LOC:
		ret = nwam_loc_get_prop_value(loc_h, prop, &prop_value);
		break;
	case NWAM_OBJECT_TYPE_ENM:
		ret = nwam_enm_get_prop_value(enm_h, prop, &prop_value);
		break;
	case NWAM_OBJECT_TYPE_KNOWN_WLAN:
		ret = nwam_known_wlan_get_prop_value(wlan_h, prop, &prop_value);
		break;
	}

	if (ret != NWAM_SUCCESS) {
		if (ret == NWAM_ENTITY_NOT_FOUND)
			nerr("Get error: property '%s' has not been set", prop);
		else
			nwamerr(ret, "Get error");
		return;
	}

	if (value_only) {
		output_prop_val(prop, prop_value, stdout, B_FALSE);
		(void) printf("\n");
	} else {
		output_propname(prop, prop_value, NULL);
	}
	nwam_value_free(prop_value);
}

/*
 * Clears value of a property.
 * Read-only properties cannot be cleared.
 * If clearing a property invalidates the object, then that property
 * cannot be cleared.
 */
void
clear_func(cmd_t *cmd)
{
	nwam_error_t		ret;
	const char		*prop;
	nwam_object_type_t	object_type = active_object_type();

	/* property to clear is in cmd->cmd_prop_type */
	if ((prop = pt_to_prop_name(object_type, cmd->cmd_prop_type)) == NULL) {
		nerr("Clear error: invalid %s property: '%s'",
		    scope_to_str(current_scope), pt_to_str(cmd->cmd_prop_type));
		return;
	}
	if (is_prop_read_only(object_type, prop)) {
		nerr("Clear error: property '%s' is read-only", prop);
		return;
	}

	switch (object_type) {
	case NWAM_OBJECT_TYPE_NCU:
		ret = nwam_ncu_delete_prop(ncu_h, prop);
		break;
	case NWAM_OBJECT_TYPE_LOC:
		ret = nwam_loc_delete_prop(loc_h, prop);
		break;
	case NWAM_OBJECT_TYPE_ENM:
		ret = nwam_enm_delete_prop(enm_h, prop);
		break;
	case NWAM_OBJECT_TYPE_KNOWN_WLAN:
		ret = nwam_known_wlan_delete_prop(wlan_h, prop);
		break;
	}

	if (ret != NWAM_SUCCESS) {
		if (ret == NWAM_INVALID_ARG || ret == NWAM_ENTITY_NOT_FOUND) {
			nerr("Clear error: property '%s' has not been set",
			    prop);
		} else {
			nwamerr(ret, "Clear error");
		}
		return;
	}

	need_to_commit = B_TRUE;
}

/*
 * Prints all the choices available for an enum property [c1|c2|c3].
 * Prints [true|false] for a boolean property.
 */
static void
print_all_prop_choices(nwam_object_type_t object_type, const char *prop)
{
	uint64_t		i = 0;
	const char		*str;
	boolean_t		choices = B_FALSE;
	nwam_value_type_t	value_type;
	nwam_error_t		ret;

	/* Special case: print object-specific options for activation-mode */
	if (strcmp(prop, NWAM_NCU_PROP_ACTIVATION_MODE) == 0) {
		/* "manual" for all objects */
		(void) printf(" [%s|",
		    propval_to_str(NWAM_NCU_PROP_ACTIVATION_MODE,
		    NWAM_ACTIVATION_MODE_MANUAL));
		if (object_type == NWAM_OBJECT_TYPE_NCU) {
			(void) printf("%s]",
			    propval_to_str(NWAM_NCU_PROP_ACTIVATION_MODE,
			    NWAM_ACTIVATION_MODE_PRIORITIZED));
		} else {
			(void) printf("%s|%s]",
			    propval_to_str(NWAM_NCU_PROP_ACTIVATION_MODE,
			    NWAM_ACTIVATION_MODE_CONDITIONAL_ANY),
			    propval_to_str(NWAM_NCU_PROP_ACTIVATION_MODE,
			    NWAM_ACTIVATION_MODE_CONDITIONAL_ALL));
		}
		return;
	}

	/* Special case: only "manual" configsrc is allowed for LDAP */
	if (strcmp(prop, NWAM_LOC_PROP_LDAP_NAMESERVICE_CONFIGSRC) == 0) {
		(void) printf(" [%s]",
		    propval_to_str(NWAM_LOC_PROP_LDAP_NAMESERVICE_CONFIGSRC,
		    NWAM_CONFIGSRC_MANUAL));
		return;
	}

	value_type = prop_value_type(object_type, prop);
	switch (value_type) {
	case NWAM_VALUE_TYPE_UINT64:
		/* uint64 may be an enum, will print nothing if not an enum */
		while ((ret = nwam_uint64_get_value_string(prop, i++, &str))
		    == NWAM_SUCCESS || ret == NWAM_ENTITY_INVALID_VALUE) {
			/* No string representation for i, continue. */
			if (ret == NWAM_ENTITY_INVALID_VALUE)
				continue;

			if (!choices)
				(void) printf("%s", " [");
			(void) printf("%s%s", choices ? "|" : "", str);
			choices = B_TRUE;
		}
		if (choices)
			(void) putchar(']');
		break;
	case NWAM_VALUE_TYPE_BOOLEAN:
		(void) printf(" [%s|%s]", "true", "false");
		break;
	case NWAM_VALUE_TYPE_STRING:
		break;
	}
}

/*
 * Walk through object properties.
 * For newly-created object, the property name with no value is displayed, and
 * the user can input a value for each property.
 * For existing object, the current value is displayed and user input overwrites
 * the existing one. If no input is given, the existing value remains.
 * Read-only properties are not displayed.
 * Read-only objects cannot be walked.
 * If the -a option is specified, no properties are skipped.
 */
void
walkprop_func(cmd_t *cmd)
{
	nwam_error_t	ret = NWAM_SUCCESS;
	nwam_value_t	vals = NULL; /* freed in _wait_input() */
	int		i;
	uint_t		prop_num;
	const char	**props;
	boolean_t	read_only = B_FALSE, all_props = B_FALSE;

	nwam_object_type_t object_type;
	prop_display_entry_t *prop_table;

	if (!interactive_mode) {
		nerr("'walkprop' is only allowed in interactive mode");
		return;
	}

	/* check if option -a is specified to show all properties */
	if (cmd->cmd_argc == 1) {
		int c;
		optind = 0;
		while ((c = getopt(cmd->cmd_argc, cmd->cmd_argv, "a")) != EOF) {
			switch (c) {
			case 'a':
				all_props = B_TRUE;
				break;
			default:
				command_usage(CMD_WALKPROP);
				return;
			}
		}
	}

	/* read-only objects cannot be walked */
	if (obj1_type == RT1_NCP) {
		/* must be in NCU scope, NCP scope doesn't get here */
		(void) nwam_ncu_get_read_only(ncu_h, &read_only);
	}
	if (read_only) {
		nerr("'walkprop' cannot be used in read-only objects");
		return;
	}

	/* get the current object type and the prop_display_table */
	object_type = active_object_type();
	prop_table = get_prop_display_table(object_type);

	/* get the property list depending on the object type */
	switch (object_type) {
	case NWAM_OBJECT_TYPE_NCU:
	{
		nwam_ncu_type_t		ncu_type;
		nwam_ncu_class_t	ncu_class;

		if ((ret = nwam_ncu_get_ncu_type(ncu_h, &ncu_type))
		    != NWAM_SUCCESS)
			break;
		if ((ret = nwam_ncu_get_ncu_class(ncu_h, &ncu_class))
		    != NWAM_SUCCESS)
			break;

		ret = nwam_ncu_get_default_proplist(ncu_type, ncu_class, &props,
		    &prop_num);
		break;
	}
	case NWAM_OBJECT_TYPE_LOC:
		ret = nwam_loc_get_default_proplist(&props, &prop_num);
		break;
	case NWAM_OBJECT_TYPE_ENM:
		ret = nwam_enm_get_default_proplist(&props, &prop_num);
		break;
	case NWAM_OBJECT_TYPE_KNOWN_WLAN:
		ret = nwam_known_wlan_get_default_proplist(&props, &prop_num);
		break;
	}
	if (ret != NWAM_SUCCESS) {
		nwamerr(ret, "Walkprop error: could not get property list");
		return;
	}

	/* Loop through the properties */
	if (all_props)
		(void) printf(gettext("Walking all properties ...\n"));
	for (i = 0; i < prop_num; i++) {
		char line[NWAM_MAX_VALUE_LEN];
		char **checked = NULL;

		/* check if this property should be displayed */
		if (is_prop_read_only(object_type, props[i]))
			continue;
		if (!all_props &&
		    !show_prop_test(object_type, props[i], prop_table,
		    checked, 0))
			continue;

		/* get the existing value for this property */
		switch (object_type) {
		case NWAM_OBJECT_TYPE_NCU:
			ret = nwam_ncu_get_prop_value(ncu_h, props[i], &vals);
			break;
		case NWAM_OBJECT_TYPE_LOC:
			ret = nwam_loc_get_prop_value(loc_h, props[i], &vals);
			break;
		case NWAM_OBJECT_TYPE_ENM:
			ret = nwam_enm_get_prop_value(enm_h, props[i], &vals);
			break;
		case NWAM_OBJECT_TYPE_KNOWN_WLAN:
			ret = nwam_known_wlan_get_prop_value(wlan_h, props[i],
			    &vals);
			break;
		}
		/* returns NWAM_ENTITY_NOT_FOUND if no existing value */
		if (ret != NWAM_SUCCESS && ret != NWAM_ENTITY_NOT_FOUND)
			continue;

		/* print property */
		(void) printf("%s", props[i]);
		/* print the existing value(s) if they exist */
		if (ret == NWAM_SUCCESS) {
			(void) printf(" (");
			output_prop_val(props[i], vals, stdout, B_TRUE);
			(void) putchar(')');
			nwam_value_free(vals);
		}
		/* print choices, won't print anything if there aren't any */
		print_all_prop_choices(object_type, props[i]);
		(void) printf("> ");

		/* wait for user input */
		if (fgets(line, sizeof (line), stdin) == NULL)
			continue;

		/* if user input new value, existing value is overrode */
		if (line[0] != '\n') {
			boolean_t is_listprop;
			int pt_type = prop_to_pt(object_type, props[i]);

			is_listprop = is_prop_multivalued(object_type,
			    props[i]);
			vals = str_to_nwam_value(object_type, line, pt_type,
			    is_listprop);
			if (vals == NULL) {
				ret = NWAM_ENTITY_INVALID_VALUE;
				goto repeat;
			}

			/* set the new value for the property */
			switch (object_type) {
			case NWAM_OBJECT_TYPE_NCU:
				ret = nwam_ncu_set_prop_value(ncu_h, props[i],
				    vals);
				break;
			case NWAM_OBJECT_TYPE_LOC:
				ret = nwam_loc_set_prop_value(loc_h, props[i],
				    vals);
				break;
			case NWAM_OBJECT_TYPE_ENM:
				ret = nwam_enm_set_prop_value(enm_h, props[i],
				    vals);
				break;
			case NWAM_OBJECT_TYPE_KNOWN_WLAN:
				ret = nwam_known_wlan_set_prop_value(wlan_h,
				    props[i], vals);
				break;
			}
			nwam_value_free(vals);

			if (ret != NWAM_SUCCESS)
				goto repeat;

			need_to_commit = B_TRUE;
			continue;

repeat:
			invalid_set_prop_msg(props[i], ret);
			i--; /* decrement i to repeat */
		}
	}

	free(props);
}

/*
 * Verify whether all properties of a resource are valid.
 */
/* ARGSUSED */
void
verify_func(cmd_t *cmd)
{
	nwam_error_t	ret;
	const char	*errprop;

	switch (active_object_type()) {
	case NWAM_OBJECT_TYPE_NCU:
		ret = nwam_ncu_validate(ncu_h, &errprop);
		break;
	case NWAM_OBJECT_TYPE_LOC:
		ret = nwam_loc_validate(loc_h, &errprop);
		break;
	case NWAM_OBJECT_TYPE_ENM:
		ret = nwam_enm_validate(enm_h, &errprop);
		break;
	case NWAM_OBJECT_TYPE_KNOWN_WLAN:
		ret = nwam_known_wlan_validate(wlan_h, &errprop);
		break;
	}
	if (ret != NWAM_SUCCESS)
		nwamerr(ret, "Verify error on property '%s'", errprop);
	else if (interactive_mode)
		(void) printf(gettext("All properties verified\n"));
}

/*
 * command-line mode (# nwamcfg list or # nwamcfg "select loc test; list")
 */
static int
one_command_at_a_time(int argc, char *argv[])
{
	char *command;
	size_t len = 2; /* terminal \n\0 */
	int i, err;

	for (i = 0; i < argc; i++)
		len += strlen(argv[i]) + 1;
	if ((command = malloc(len)) == NULL) {
		nerr("Out of memory");
		return (NWAM_ERR);
	}
	(void) strlcpy(command, argv[0], len);
	for (i = 1; i < argc; i++) {
		(void) strlcat(command, " ", len);
		(void) strlcat(command, argv[i], len);
	}
	(void) strlcat(command, "\n", len);
	err = string_to_yyin(command);
	free(command);
	if (err != NWAM_OK)
		return (err);
	while (!feof(yyin)) {
		yyparse();

		/*
		 * If any command on a list of commands give an error,
		 * don't continue with the remaining commands.
		 */
		if (saw_error || time_to_exit)
			return (cleanup());
	}

	/* if there are changes to commit, commit it */
	if (need_to_commit) {
		do_commit();
		/* if need_to_commit is not set, then there was a error */
		if (need_to_commit)
			return (NWAM_ERR);
	}

	if (!interactive_mode)
		return (cleanup());
	else {
		yyin = stdin;
		return (read_input());
	}
}

/*
 * cmd_file is slightly more complicated, as it has to open the command file
 * and set yyin appropriately.  Once that is done, though, it just calls
 * read_input(), and only once, since prompting is not possible.
 */
static int
cmd_file(char *file)
{
	FILE *infile;
	int err;
	struct stat statbuf;
	boolean_t using_real_file = (strcmp(file, "-") != 0);

	if (using_real_file) {
		/*
		 * nerr() prints a line number in cmd_file_mode, which we do
		 * not want here, so temporarily unset it.
		 */
		cmd_file_mode = B_FALSE;
		if ((infile = fopen(file, "r")) == NULL) {
			nerr(gettext("could not open file '%s': %s"),
			    file, strerror(errno));
			return (1);
		}
		if ((err = fstat(fileno(infile), &statbuf)) != 0) {
			nerr(gettext("could not stat file '%s': %s"),
			    file, strerror(errno));
			err = 1;
			goto done;
		}
		if (!S_ISREG(statbuf.st_mode)) {
			nerr(gettext("'%s' is not a regular file."), file);
			err = 1;
			goto done;
		}

		/*
		 * If -d was passed on the command-line, we need to
		 * start by removing any existing configuration.
		 * Alternatively, the file may begin with 'destroy -a';
		 * but in that case, the line will go through the lexer
		 * and be processed as it's encountered in the file.
		 */
		if (remove_all_configurations && destroy_all() != NWAM_SUCCESS)
			goto done;

		/* set up for lexer */
		yyin = infile;
		cmd_file_mode = B_TRUE;
		ok_to_prompt = B_FALSE;
	} else {
		/*
		 * "-f -" is essentially the same as interactive mode,
		 * so treat it that way.
		 */
		interactive_mode = B_TRUE;
	}
	/* NWAM_REPEAT is for interactive mode; treat it like NWAM_ERR here. */
	if ((err = read_input()) == NWAM_REPEAT)
		err = NWAM_ERR;
	if (err == NWAM_OK)
		(void) printf(gettext("Configuration read.\n"));

done:
	if (using_real_file)
		(void) fclose(infile);
	return (err);
}

int
main(int argc, char *argv[])
{
	int	err;
	char	c;

	/* This must be before anything goes to stdout. */
	setbuf(stdout, NULL);

	if ((execname = strrchr(argv[0], '/')) == NULL)
		execname = argv[0];
	else
		execname++;

	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);

	while ((c = getopt(argc, argv, "?hf:d")) != EOF) {
		switch (c) {
		case 'f':
			cmd_file_name = optarg;
			cmd_file_mode = B_TRUE;
			break;
		case '?':
		case 'h':
			cmd_line_usage();
			return (NWAM_OK);
		case 'd':
			remove_all_configurations = B_TRUE;
			break;
		default:
			cmd_line_usage();
			return (NWAM_ERR);
		}
	}
	/* -d can only be used with -f */
	if (remove_all_configurations && !cmd_file_mode) {
		nerr("Option -d can only be used with -f");
		return (NWAM_ERR);
	}

	/*
	 * This may get set back to FALSE again in cmd_file() if cmd_file_name
	 * is a "real" file as opposed to "-" (i.e. meaning use stdin).
	 */
	if (isatty(STDIN_FILENO))
		ok_to_prompt = B_TRUE;
	if ((gl = new_GetLine(MAX_LINE_LEN, MAX_CMD_HIST)) == NULL)
		exit(NWAM_ERR);
	if (gl_customize_completion(gl, NULL, cmd_cpl_fn) != 0)
		exit(NWAM_ERR);
	(void) sigset(SIGINT, SIG_IGN);

	if (optind == argc) {
		/* interactive or command-file mode */
		if (!cmd_file_mode)
			err = do_interactive();
		else
			err = cmd_file(cmd_file_name);
	} else {
		/* command-line mode */
		err = one_command_at_a_time(argc - optind, &(argv[optind]));
	}
	(void) del_GetLine(gl);

	return (err);
}
