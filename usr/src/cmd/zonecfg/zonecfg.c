/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * zonecfg is a lex/yacc based command interpreter used to manage zone
 * configurations.  The lexer (see zonecfg_lex.l) builds up tokens, which
 * the grammar (see zonecfg_grammar.y) builds up into commands, some of
 * which takes resources and/or properties as arguments.  See the block
 * comments near the end of zonecfg_grammar.y for how the data structures
 * which keep track of these resources and properties are built up.
 *
 * The resource/property data structures are inserted into a command
 * structure (see zonecfg.h), which also keeps track of command names,
 * miscellaneous arguments, and function handlers.  The grammar selects
 * the appropriate function handler, each of which takes a pointer to a
 * command structure as its sole argument, and invokes it.  The grammar
 * itself is "entered" (a la the Matrix) by yyparse(), which is called
 * from read_input(), our main driving function.  That in turn is called
 * by one of do_interactive(), cmd_file() or one_command_at_a_time(), each
 * of which is called from main() depending on how the program was invoked.
 *
 * The rest of this module consists of the various function handlers and
 * their helper functions.  Some of these functions, particularly the
 * X_to_str() functions, which maps command, resource and property numbers
 * to strings, are used quite liberally, as doing so results in a better
 * program w/rt I18N, reducing the need for translation notes.
 */

#include <sys/mntent.h>
#include <sys/varargs.h>
#include <sys/sysmacros.h>

#include <errno.h>
#include <strings.h>
#include <unistd.h>
#include <ctype.h>
#include <stdlib.h>
#include <assert.h>
#include <sys/stat.h>
#include <zone.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <locale.h>
#include <libintl.h>
#include <alloca.h>
#include <regex.h>
#include <signal.h>
#include <libtecla.h>

#include <libzonecfg.h>
#include "zonecfg.h"

#if !defined(TEXT_DOMAIN)		/* should be defined by cc -D */
#define	TEXT_DOMAIN	"SYS_TEST"	/* Use this only if it wasn't */
#endif

#define	PAGER	"/usr/bin/more"

struct help {
	uint_t	cmd_num;
	char	*cmd_name;
	uint_t	flags;
	char	*short_usage;
};

extern int yyparse(void);
extern int lex_lineno;

#define	MAX_LINE_LEN	1024
#define	MAX_CMD_HIST	1024

/*
 * Each SHELP_ should be a simple string.
 */

#define	SHELP_ADD	"add <resource-type>\n\t(global scope)\n" \
	"add <property-name> <property-value>\n\t(resource scope)"
#define	SHELP_CANCEL	"cancel"
#define	SHELP_COMMIT	"commit"
#define	SHELP_CREATE	"create [-F] [ -b | -t <template> ]"
#define	SHELP_DELETE	"delete [-F]"
#define	SHELP_END	"end"
#define	SHELP_EXIT	"exit [-F]"
#define	SHELP_EXPORT	"export [-f output-file]"
#define	SHELP_HELP	"help [commands] [syntax] [usage] [<command-name>]"
#define	SHELP_INFO	"info [<resource-type> [property-name=property-value]*]"
#define	SHELP_REMOVE	"remove <resource-type> { <property-name>=<property-" \
	"value> }\n\t(global scope)\nremove <property-name>=<property-value>" \
	"\n\t(resource scope)"
#define	SHELP_REVERT	"revert [-F]"
#define	SHELP_SELECT	"select <resource-type> { <property-name>=" \
	"<property-value> }"
#define	SHELP_SET	"set <property-name>=<property-value>"
#define	SHELP_VERIFY	"verify"

static struct help helptab[] = {
	{ CMD_ADD,	"add",		HELP_RES_PROPS,	SHELP_ADD, },
	{ CMD_CANCEL,	"cancel",	0,		SHELP_CANCEL, },
	{ CMD_COMMIT,	"commit",	0,		SHELP_COMMIT, },
	{ CMD_CREATE,	"create",	0,		SHELP_CREATE, },
	{ CMD_DELETE,	"delete",	0,		SHELP_DELETE, },
	{ CMD_END,	"end",		0,		SHELP_END, },
	{ CMD_EXIT,	"exit",		0,		SHELP_EXIT, },
	{ CMD_EXPORT,	"export",	0,		SHELP_EXPORT, },
	{ CMD_HELP,	"help",		0,		SHELP_HELP },
	{ CMD_INFO,	"info",		HELP_RES_PROPS,	SHELP_INFO, },
	{ CMD_REMOVE,	"remove",	HELP_RES_PROPS,	SHELP_REMOVE, },
	{ CMD_REVERT,	"revert",	0,		SHELP_REVERT, },
	{ CMD_SELECT,	"select",	HELP_RES_PROPS,	SHELP_SELECT, },
	{ CMD_SET,	"set",		HELP_PROPS,	SHELP_SET, },
	{ CMD_VERIFY,	"verify",	0,		SHELP_VERIFY, },
	{ 0 },
};

#define	MAX_RT_STRLEN	16

/* These *must* match the order of the RT_ define's from zonecfg.h */
static char *res_types[] = {
	"unknown",
	"zonepath",
	"autoboot",
	"pool",
	"fs",
	"inherit-pkg-dir",
	"net",
	"device",
	"rctl",
	"attr",
	NULL
};

/* These *must* match the order of the PT_ define's from zonecfg.h */
static char *prop_types[] = {
	"unknown",
	"zonepath",
	"autoboot",
	"pool",
	"dir",
	"special",
	"type",
	"options",
	"address",
	"physical",
	"name",
	"value",
	"match",
	"priv",
	"limit",
	"action",
	"raw",
	NULL
};

/* These *must* match the order of the PT_ define's from zonecfg.h */
static char *prop_val_types[] = {
	"simple",
	"complex",
	"list",
};

/*
 * The various _cmds[] lists below are for command tab-completion.
 */

/*
 * remove has a space afterwards because it has qualifiers; the other commands
 * that have qualifiers (add, select and set) don't need a space here because
 * they have their own _cmds[] lists below.
 */
static const char *global_scope_cmds[] = {
	"add",
	"commit",
	"create",
	"delete",
	"exit",
	"export",
	"help",
	"info",
	"remove ",
	"revert",
	"select",
	"set",
	"verify",
	NULL
};

static const char *add_cmds[] = {
	"add fs",
	"add inherit-pkg-dir",
	"add net",
	"add device",
	"add rctl",
	"add attr",
	NULL
};

static const char *select_cmds[] = {
	"select fs",
	"select inherit-pkg-dir",
	"select net",
	"select device",
	"select rctl",
	"select attr",
	NULL
};

static const char *set_cmds[] = {
	"set zonepath",
	"set autoboot",
	"set pool",
	NULL
};

static const char *fs_res_scope_cmds[] = {
	"add options ",
	"cancel",
	"end",
	"exit",
	"help",
	"info",
	"set dir=",
	"set raw=",
	"set special=",
	"set type=",
	NULL
};

static const char *net_res_scope_cmds[] = {
	"cancel",
	"end",
	"exit",
	"help",
	"info",
	"set address=",
	"set physical=",
	NULL
};

static const char *ipd_res_scope_cmds[] = {
	"cancel",
	"end",
	"exit",
	"help",
	"info",
	"set dir=",
	NULL
};

static const char *device_res_scope_cmds[] = {
	"cancel",
	"end",
	"exit",
	"help",
	"info",
	"set match=",
	NULL
};

static const char *attr_res_scope_cmds[] = {
	"cancel",
	"end",
	"exit",
	"help",
	"info",
	"set name=",
	"set type=",
	"set value=",
	NULL
};

static const char *rctl_res_scope_cmds[] = {
	"add value ",
	"cancel",
	"end",
	"exit",
	"help",
	"info",
	"set name=",
	NULL
};

/* Global variables */

/* set early in main(), never modified thereafter, used all over the place */
static char *execname;

/* set in main(), used all over the place */
static zone_dochandle_t handle;

/* used all over the place */
static char *zone;

/* set in modifying functions, checked in read_input() */
static bool need_to_commit = FALSE;
bool saw_error;

/* set in yacc parser, checked in read_input() */
bool newline_terminated;

/* set in main(), checked in lex error handler */
bool cmd_file_mode;

/* set in exit_func(), checked in read_input() */
static bool time_to_exit = FALSE, force_exit = FALSE;

/* used in short_usage() and zerr() */
static char *cmd_file_name = NULL;

/* checked in read_input() and other places */
static bool ok_to_prompt = FALSE;

/* set and checked in initialize() */
static bool got_handle = FALSE;

/* initialized in do_interactive(), checked in initialize() */
static bool interactive_mode;

/* set in main(), checked in multiple places */
static bool read_only_mode;

/* set in check_if_zone_already_exists(), checked in save_it() */
static bool new_zone = FALSE;

static bool global_scope = TRUE; /* scope is outer/global or inner/resource */
static int resource_scope;	/* should be in the RT_ list from zonecfg.h */
static int end_op = -1;		/* operation on end is either add or modify */

int num_prop_vals;		/* for grammar */

/*
 * These are for keeping track of resources as they are specified as part of
 * the multi-step process.  They should be initialized by add_resource() or
 * select_func() and filled in by add_property() or set_func().
 */
static struct zone_fstab	old_fstab, in_progress_fstab;
static struct zone_fstab	old_ipdtab, in_progress_ipdtab;
static struct zone_nwiftab	old_nwiftab, in_progress_nwiftab;
static struct zone_devtab	old_devtab, in_progress_devtab;
static struct zone_rctltab	old_rctltab, in_progress_rctltab;
static struct zone_attrtab	old_attrtab, in_progress_attrtab;

static GetLine *gl;	/* The gl_get_line() resource object */

/* Functions begin here */

static bool
initial_match(const char *line1, const char *line2, int word_end)
{
	if (word_end <= 0)
		return (TRUE);
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

static
/* ARGSUSED */
CPL_MATCH_FN(cmd_cpl_fn)
{
	if (global_scope) {
		/*
		 * The MAX/MIN tests below are to make sure we have at least
		 * enough characters to distinguish from other prefixes (MAX)
		 * but only check MIN(what we have, what we're checking).
		 */
		if (strncmp(line, "add ", MAX(MIN(word_end, 4), 1)) == 0)
			return (add_stuff(cpl, line, add_cmds, word_end));
		if (strncmp(line, "select ", MAX(MIN(word_end, 7), 3)) == 0)
			return (add_stuff(cpl, line, select_cmds, word_end));
		if (strncmp(line, "set ", MAX(MIN(word_end, 4), 3)) == 0)
			return (add_stuff(cpl, line, set_cmds, word_end));
		return (add_stuff(cpl, line, global_scope_cmds, word_end));
	}
	switch (resource_scope) {
	case RT_FS:
		return (add_stuff(cpl, line, fs_res_scope_cmds, word_end));
	case RT_IPD:
		return (add_stuff(cpl, line, ipd_res_scope_cmds, word_end));
	case RT_NET:
		return (add_stuff(cpl, line, net_res_scope_cmds, word_end));
	case RT_DEVICE:
		return (add_stuff(cpl, line, device_res_scope_cmds, word_end));
	case RT_RCTL:
		return (add_stuff(cpl, line, rctl_res_scope_cmds, word_end));
	case RT_ATTR:
		return (add_stuff(cpl, line, attr_res_scope_cmds, word_end));
	}
	return (0);
}

/*
 * For the main CMD_func() functions below, several of them call getopt()
 * then check optind against argc to make sure an extra parameter was not
 * passed in.  The reason this is not caught in the grammar is that the
 * grammar just checks for a miscellaneous TOKEN, which is *expected* to
 * be "-F" (for example), but could be anything.  So (for example) this
 * check will prevent "create bogus".
 */

cmd_t *
alloc_cmd(void)
{
	return (calloc(1, sizeof (cmd_t)));
}

void
free_cmd(cmd_t *cmd)
{
	int i;

	for (i = 0; i < MAX_EQ_PROP_PAIRS; i++)
		if (cmd->cmd_property_ptr[i] != NULL) {
			property_value_ptr_t pp = cmd->cmd_property_ptr[i];

			switch (pp->pv_type) {
			case PROP_VAL_SIMPLE:
				free(pp->pv_simple);
				break;
			case PROP_VAL_COMPLEX:
				free_complex(pp->pv_complex);
				break;
			case PROP_VAL_LIST:
				free_list(pp->pv_list);
				break;
			}
		}
	for (i = 0; i < cmd->cmd_argc; i++)
		free(cmd->cmd_argv[i]);
	free(cmd);
}

complex_property_ptr_t
alloc_complex(void)
{
	return (calloc(1, sizeof (complex_property_t)));
}

void
free_complex(complex_property_ptr_t complex)
{
	if (complex == NULL)
		return;
	free_complex(complex->cp_next);
	if (complex->cp_value != NULL)
		free(complex->cp_value);
	free(complex);
}

list_property_ptr_t
alloc_list(void)
{
	return (calloc(1, sizeof (list_property_t)));
}

void
free_list(list_property_ptr_t list)
{
	if (list == NULL)
		return;
	if (list->lp_simple != NULL)
		free(list->lp_simple);
	free_complex(list->lp_complex);
	free_list(list->lp_next);
	free(list);
}

void
free_outer_list(list_property_ptr_t list)
{
	if (list == NULL)
		return;
	free_outer_list(list->lp_next);
	free(list);
}

static struct zone_rctlvaltab *
alloc_rctlvaltab(void)
{
	return (calloc(1, sizeof (struct zone_rctlvaltab)));
}

static char *
rt_to_str(int res_type)
{
	assert(res_type >= RT_MIN && res_type <= RT_MAX);
	return (res_types[res_type]);
}

static char *
pt_to_str(int prop_type)
{
	assert(prop_type >= PT_MIN && prop_type <= PT_MAX);
	return (prop_types[prop_type]);
}

static char *
pvt_to_str(int pv_type)
{
	assert(pv_type >= PROP_VAL_MIN && pv_type <= PROP_VAL_MAX);
	return (prop_val_types[pv_type]);
}

static char *
cmd_to_str(int cmd_num)
{
	assert(cmd_num >= CMD_MIN && cmd_num <= CMD_MAX);
	return (helptab[cmd_num].cmd_name);
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

static char *
long_help(int cmd_num)
{
	static char line[1024];	/* arbitrary large amount */

	assert(cmd_num >= CMD_MIN && cmd_num <= CMD_MAX);
	switch (cmd_num) {
		case CMD_HELP:
			return (gettext("Prints help message."));
		case CMD_CREATE:
			(void) snprintf(line, sizeof (line),
			    gettext("Creates a configuration for the "
			    "specified zone.  %s should be\n\tused to "
			    "begin configuring a new zone.  If overwriting an "
			    "existing\n\tconfiguration, the -F flag can be "
			    "used to force the action.  If\n\t-t template is "
			    "given, creates a configuration identical to the\n"
			    "\tspecified template, except that the zone name "
			    "is changed from\n\ttemplate to zonename.  '%s -b' "
			    "results in a blank configuration.\n\t'%s' with no "
			    "arguments applies the Sun default settings."),
			    cmd_to_str(CMD_CREATE), cmd_to_str(CMD_CREATE),
			    cmd_to_str(CMD_CREATE));
			return (line);
		case CMD_EXIT:
			return (gettext("Exits the program.  The -F flag can "
			    "be used to force the action."));
		case CMD_EXPORT:
			return (gettext("Prints configuration to standard "
			    "output, or to output-file if\n\tspecified, in "
			    "a form suitable for use in a command-file."));
		case CMD_ADD:
			return (gettext("Add specified resource to "
			    "configuration."));
		case CMD_DELETE:
			return (gettext("Deletes the specified zone.  The -F "
			    "flag can be used to force the\n\taction."));
		case CMD_REMOVE:
			return (gettext("Remove specified resource from "
			    "configuration.  Note that the curly\n\tbraces "
			    "('{', '}') mean one or more of whatever "
			    "is between them."));
		case CMD_SELECT:
			(void) snprintf(line, sizeof (line),
			    gettext("Selects a resource to modify.  "
			    "Resource modification is completed\n\twith the "
			    "command \"%s\".  The property name/value pairs "
			    "must uniquely\n\tidentify a resource.  Note that "
			    "the curly braces ('{', '}') mean one\n\tor more "
			    "of whatever is between them."),
			    cmd_to_str(CMD_END));
			return (line);
		case CMD_SET:
			return (gettext("Sets property values."));
		case CMD_INFO:
			return (gettext("Displays information about the "
			    "current configuration.  If resource\n\ttype is "
			    "specified, displays only information about "
			    "resources of\n\tthe relevant type.  If resource "
			    "id is specified, displays only\n\tinformation "
			    "about that resource."));
		case CMD_VERIFY:
			return (gettext("Verifies current configuration "
			    "for correctness (some resource types\n\thave "
			    "required properties)."));
		case CMD_COMMIT:
			(void) snprintf(line, sizeof (line),
			    gettext("Commits current configuration.  "
			    "Configuration must be committed to\n\tbe used by "
			    "%s.  Until the configuration is committed, "
			    "changes \n\tcan be removed with the %s "
			    "command.  This operation is\n\tattempted "
			    "automatically upon completion of a %s "
			    "session."), "zoneadm", cmd_to_str(CMD_REVERT),
			    "zonecfg");
			return (line);
		case CMD_REVERT:
			return (gettext("Reverts configuration back to the "
			    "last committed state.  The -F flag\n\tcan be "
			    "used to force the action."));
		case CMD_CANCEL:
			return (gettext("Cancels resource/property "
			    "specification."));
		case CMD_END:
			return (gettext("Ends resource/property "
			    "specification."));
	}
	/* NOTREACHED */
}

/*
 * Called with verbose TRUE when help is explicitly requested, FALSE for
 * unexpected errors.
 */

void
usage(bool verbose, uint_t flags)
{
	FILE *fp = verbose ? stdout : stderr, *newfp;
	bool need_to_close = FALSE;
	char *pager;
	int i;

	/* don't page error output */
	if (verbose && interactive_mode) {
		if ((pager = getenv("PAGER")) == NULL)
			pager = PAGER;
		if ((newfp = popen(pager, "w")) != NULL) {
			need_to_close = TRUE;
			fp = newfp;
		}
	}
	if (flags & HELP_META) {
		(void) fprintf(fp, gettext("More help is available for the "
		    "following:\n"));
		(void) fprintf(fp, "\n\tcommands ('%s commands')\n",
		    cmd_to_str(CMD_HELP));
		(void) fprintf(fp, "\tsyntax ('%s syntax')\n",
		    cmd_to_str(CMD_HELP));
		(void) fprintf(fp, "\tusage ('%s usage')\n\n",
		    cmd_to_str(CMD_HELP));
		(void) fprintf(fp, gettext("You may also obtain help on any "
		    "command by typing '%s <command-name>.'\n"),
		    cmd_to_str(CMD_HELP));
	}
	if (flags & HELP_RES_SCOPE) {
		switch (resource_scope) {
		case RT_FS:
			(void) fprintf(fp, gettext("The '%s' resource scope is "
			    "used to configure a file-system.\n"),
			    rt_to_str(resource_scope));
			(void) fprintf(fp, gettext("Valid commands:\n"));
			(void) fprintf(fp, "\t%s %s=%s\n", cmd_to_str(CMD_SET),
			    pt_to_str(PT_DIR), gettext("<path>"));
			(void) fprintf(fp, "\t%s %s=%s\n", cmd_to_str(CMD_SET),
			    pt_to_str(PT_SPECIAL), gettext("<path>"));
			(void) fprintf(fp, "\t%s %s=%s\n", cmd_to_str(CMD_SET),
			    pt_to_str(PT_RAW), gettext("<raw-device>"));
			(void) fprintf(fp, "\t%s %s=%s\n", cmd_to_str(CMD_SET),
			    pt_to_str(PT_TYPE), gettext("<file-system type>"));
			(void) fprintf(fp, "\t%s %s %s\n", cmd_to_str(CMD_ADD),
			    pt_to_str(PT_OPTIONS),
			    gettext("<file-system options>"));
			(void) fprintf(fp, gettext("Consult the file-system "
			    "specific manual page, such as mount_ufs(1M), "
			    "for\ndetails about file-system options.  Note "
			    "that any file-system options with an\nembedded "
			    "'=' character must be enclosed in double quotes, "
			    /*CSTYLED*/
			    "such as \"%s=5\".\n"), MNTOPT_RETRY);
			break;
		case RT_IPD:
			(void) fprintf(fp, gettext("The '%s' resource scope is "
			    "used to configure a directory\ninherited from the "
			    "global zone into a non-global zone in read-only "
			    "mode.\n"), rt_to_str(resource_scope));
			(void) fprintf(fp, gettext("Valid commands:\n"));
			(void) fprintf(fp, "\t%s %s=%s\n", cmd_to_str(CMD_SET),
			    pt_to_str(PT_DIR), gettext("<path>"));
			break;
		case RT_NET:
			(void) fprintf(fp, gettext("The '%s' resource scope is "
			    "used to configure a network interface.\n"),
			    rt_to_str(resource_scope));
			(void) fprintf(fp, gettext("Valid commands:\n"));
			(void) fprintf(fp, "\t%s %s=%s\n", cmd_to_str(CMD_SET),
			    pt_to_str(PT_ADDRESS), gettext("<IP-address>"));
			(void) fprintf(fp, "\t%s %s=%s\n", cmd_to_str(CMD_SET),
			    pt_to_str(PT_PHYSICAL), gettext("<interface>"));
			(void) fprintf(fp, gettext("See ifconfig(1M) for "
			    "details of the <interface> string.\n"));
			break;
		case RT_DEVICE:
			(void) fprintf(fp, gettext("The '%s' resource scope is "
			    "used to configure a device node.\n"),
			    rt_to_str(resource_scope));
			(void) fprintf(fp, gettext("Valid commands:\n"));
			(void) fprintf(fp, "\t%s %s=%s\n", cmd_to_str(CMD_SET),
			    pt_to_str(PT_MATCH), gettext("<device-path>"));
			break;
		case RT_RCTL:
			(void) fprintf(fp, gettext("The '%s' resource scope is "
			    "used to configure a resource control.\n"),
			    rt_to_str(resource_scope));
			(void) fprintf(fp, gettext("Valid commands:\n"));
			(void) fprintf(fp, "\t%s %s=%s\n", cmd_to_str(CMD_SET),
			    pt_to_str(PT_NAME), gettext("<string>"));
			(void) fprintf(fp, "\t%s %s (%s=%s,%s=%s,%s=%s)\n",
			    cmd_to_str(CMD_ADD), pt_to_str(PT_VALUE),
			    pt_to_str(PT_PRIV), gettext("<priv-value>"),
			    pt_to_str(PT_LIMIT), gettext("<number>"),
			    pt_to_str(PT_ACTION), gettext("<action-value>"));
			(void) fprintf(fp, "%s\n\t%s := privileged\n"
			    "\t%s := none | deny\n", gettext("Where"),
			    gettext("<priv-value>"), gettext("<action-value>"));
			break;
		case RT_ATTR:
			(void) fprintf(fp, gettext("The '%s' resource scope is "
			    "used to configure a generic attribute.\n"),
			    rt_to_str(resource_scope));
			(void) fprintf(fp, gettext("Valid commands:\n"));
			(void) fprintf(fp, "\t%s %s=%s\n", cmd_to_str(CMD_SET),
			    pt_to_str(PT_NAME), gettext("<name>"));
			(void) fprintf(fp, "\t%s %s=boolean\n",
			    cmd_to_str(CMD_SET), pt_to_str(PT_TYPE));
			(void) fprintf(fp, "\t%s %s=true | false\n",
			    cmd_to_str(CMD_SET), pt_to_str(PT_VALUE));
			(void) fprintf(fp, gettext("or\n"));
			(void) fprintf(fp, "\t%s %s=int\n", cmd_to_str(CMD_SET),
			    pt_to_str(PT_TYPE));
			(void) fprintf(fp, "\t%s %s=%s\n", cmd_to_str(CMD_SET),
			    pt_to_str(PT_VALUE), gettext("<integer>"));
			(void) fprintf(fp, gettext("or\n"));
			(void) fprintf(fp, "\t%s %s=string\n",
			    cmd_to_str(CMD_SET), pt_to_str(PT_TYPE));
			(void) fprintf(fp, "\t%s %s=%s\n", cmd_to_str(CMD_SET),
			    pt_to_str(PT_VALUE), gettext("<string>"));
			(void) fprintf(fp, gettext("or\n"));
			(void) fprintf(fp, "\t%s %s=uint\n",
			    cmd_to_str(CMD_SET), pt_to_str(PT_TYPE));
			(void) fprintf(fp, "\t%s %s=%s\n", cmd_to_str(CMD_SET),
			    pt_to_str(PT_VALUE), gettext("<unsigned integer>"));
			break;
		}
		(void) fprintf(fp, gettext("And from any resource scope, you "
		    "can:\n"));
		(void) fprintf(fp, "\t%s\t%s\n", cmd_to_str(CMD_END),
		    gettext("(to conclude this operation)"));
		(void) fprintf(fp, "\t%s\t%s\n", cmd_to_str(CMD_CANCEL),
		    gettext("(to cancel this operation)"));
		(void) fprintf(fp, "\t%s\t%s\n", cmd_to_str(CMD_EXIT),
		    gettext("(to exit the zonecfg utility)"));
	}
	if (flags & HELP_USAGE) {
		(void) fprintf(fp, "%s:\t%s %s\n", gettext("usage"),
		    execname, cmd_to_str(CMD_HELP));
		(void) fprintf(fp, "\t%s -z <zone>\t\t\t(%s)\n",
		    execname, gettext("interactive"));
		(void) fprintf(fp, "\t%s -z <zone> <command>\n", execname);
		(void) fprintf(fp, "\t%s -z <zone> -f <command-file>\n",
		    execname);
	}
	if (flags & HELP_SUBCMDS) {
		(void) fprintf(fp, "%s:\n\n", gettext("Commands"));
		for (i = 0; i <= CMD_MAX; i++) {
			(void) fprintf(fp, "%s\n", helptab[i].short_usage);
			if (verbose)
				(void) fprintf(fp, "\t%s\n\n", long_help(i));
		}
	}
	if (flags & HELP_SYNTAX) {
		if (!verbose)
			(void) fprintf(fp, "\n");
		(void) fprintf(fp, "<zone> := [A-Za-z0-9][A-Za-z0-9_.-]*\n");
		(void) fprintf(fp, gettext("\t(except the reserved words "
		    "'%s' and anything starting with '%s')\n"), "global",
		    "SUNW");
		(void) fprintf(fp,
		    gettext("\tName must be less than %d characters.\n"),
		    ZONENAME_MAX);
		if (verbose)
			(void) fprintf(fp, "\n");
	}
	if (flags & HELP_NETADDR) {
		(void) fprintf(fp, gettext("\n<net-addr> :="));
		(void) fprintf(fp,
		    gettext("\t<IPv4-address>[/<IPv4-prefix-length>] |\n"));
		(void) fprintf(fp,
		    gettext("\t\t<IPv6-address>/<IPv6-prefix-length> |\n"));
		(void) fprintf(fp,
		    gettext("\t\t<hostname>[/<IPv4-prefix-length>]\n"));
		(void) fprintf(fp, gettext("See inet(3SOCKET) for IPv4 and "
		    "IPv6 address syntax.\n"));
		(void) fprintf(fp, gettext("<IPv4-prefix-length> := [0-32]\n"));
		(void) fprintf(fp,
		    gettext("<IPv6-prefix-length> := [0-128]\n"));
		(void) fprintf(fp,
		    gettext("<hostname> := [A-Za-z0-9][A-Za-z0-9-.]*\n"));
	}
	if (flags & HELP_RESOURCES) {
		(void) fprintf(fp, "<%s> := %s | %s | %s | %s | %s | %s\n\n",
		    gettext("resource type"), rt_to_str(RT_FS),
		    rt_to_str(RT_IPD), rt_to_str(RT_NET), rt_to_str(RT_DEVICE),
		    rt_to_str(RT_RCTL), rt_to_str(RT_ATTR));
	}
	if (flags & HELP_PROPS) {
		(void) fprintf(fp, gettext("For resource type ... there are "
		    "property types ...:\n"));
		(void) fprintf(fp, "\t%s\t%s\n", gettext("(global)"),
		    pt_to_str(PT_ZONEPATH));
		(void) fprintf(fp, "\t%s\t%s\n", gettext("(global)"),
		    pt_to_str(PT_AUTOBOOT));
		(void) fprintf(fp, "\t%s\t%s\n", gettext("(global)"),
		    pt_to_str(PT_POOL));
		(void) fprintf(fp, "\t%s\t\t%s, %s, %s, %s\n", rt_to_str(RT_FS),
		    pt_to_str(PT_DIR), pt_to_str(PT_SPECIAL),
		    pt_to_str(PT_RAW), pt_to_str(PT_TYPE),
		    pt_to_str(PT_OPTIONS));
		(void) fprintf(fp, "\t%s\t%s\n", rt_to_str(RT_IPD),
		    pt_to_str(PT_DIR));
		(void) fprintf(fp, "\t%s\t\t%s, %s\n", rt_to_str(RT_NET),
		    pt_to_str(PT_ADDRESS), pt_to_str(PT_PHYSICAL));
		(void) fprintf(fp, "\t%s\t\t%s\n", rt_to_str(RT_DEVICE),
		    pt_to_str(PT_MATCH));
		(void) fprintf(fp, "\t%s\t\t%s, %s\n", rt_to_str(RT_RCTL),
		    pt_to_str(PT_NAME), pt_to_str(PT_VALUE));
		(void) fprintf(fp, "\t%s\t\t%s, %s, %s\n", rt_to_str(RT_ATTR),
		    pt_to_str(PT_NAME), pt_to_str(PT_TYPE),
		    pt_to_str(PT_VALUE));
	}
	if (need_to_close)
		(void) pclose(fp);
}

/* PRINTFLIKE1 */
static void
zerr(const char *fmt, ...)
{
	va_list alist;
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
	va_start(alist, fmt);
	(void) vfprintf(stderr, fmt, alist);
	(void) fprintf(stderr, "\n");
	va_end(alist);
}

static void
zone_perror(char *prefix, int err, bool set_saw)
{
	zerr("%s: %s", prefix, zonecfg_strerror(err));
	if (set_saw)
		saw_error = TRUE;
}

/*
 * zone_perror() expects a single string, but for remove and select
 * we have both the command and the resource type, so this wrapper
 * function serves the same purpose in a slightly different way.
 */

static void
z_cmd_rt_perror(int cmd_num, int res_num, int err, bool set_saw)
{
	zerr("%s %s: %s", cmd_to_str(cmd_num), rt_to_str(res_num),
	    zonecfg_strerror(err));
	if (set_saw)
		saw_error = TRUE;
}

/* returns Z_OK if successful, Z_foo from <libzonecfg.h> otherwise */
static int
initialize(bool handle_expected)
{
	int err;

	if (zonecfg_check_handle(handle) != Z_OK) {
		if ((err = zonecfg_get_handle(zone, handle)) == Z_OK) {
			got_handle = TRUE;
		} else {
			zone_perror(zone, err, handle_expected || got_handle);
			if (err == Z_NO_ZONE && !got_handle &&
			    interactive_mode && !read_only_mode)
				(void) printf(gettext("Use '%s' to begin "
				    "configuring a new zone.\n"),
				    cmd_to_str(CMD_CREATE));
			return (err);
		}
	}
	return (Z_OK);
}

/*
 * short_usage() is for bad syntax: getopt() issues, too many arguments, etc.
 */

void
short_usage(int command)
{
	/* lex_lineno has already been incremented in the lexer; compensate */
	if (cmd_file_mode) {
		if (strcmp(cmd_file_name, "-") == 0)
			(void) fprintf(stderr,
			    gettext("syntax error on line %d\n"),
			    lex_lineno - 1);
		else
			(void) fprintf(stderr,
			    gettext("syntax error on line %d of %s\n"),
			    lex_lineno - 1, cmd_file_name);
	}
	(void) fprintf(stderr, "%s:\n%s\n", gettext("usage"),
	    helptab[command].short_usage);
	saw_error = TRUE;
}

/*
 * long_usage() is for bad semantics: e.g., wrong property type for a given
 * resource type.  It is also used by longer_usage() below.
 */

void
long_usage(uint_t cmd_num, bool set_saw)
{
	(void) fprintf(set_saw ? stderr : stdout, "%s:\n%s\n", gettext("usage"),
	    helptab[cmd_num].short_usage);
	(void) fprintf(set_saw ? stderr : stdout, "\t%s\n", long_help(cmd_num));
	if (set_saw)
		saw_error = TRUE;
}

/*
 * longer_usage() is for 'help foo' and 'foo -?': call long_usage() and also
 * any extra usage() flags as appropriate for whatever command.
 */

void
longer_usage(uint_t cmd_num)
{
	long_usage(cmd_num, FALSE);
	if (helptab[cmd_num].flags != 0) {
		(void) printf("\n");
		usage(TRUE, helptab[cmd_num].flags);
	}
}

/*
 * scope_usage() is simply used when a command is called from the wrong scope.
 */

static void
scope_usage(uint_t cmd_num)
{
	zerr(gettext("The %s command only makes sense in the %s scope."),
	    cmd_to_str(cmd_num),
	    global_scope ?  gettext("resource") : gettext("global"));
	saw_error = TRUE;
}

/*
 * On input, TRUE => yes, FALSE => no.
 * On return, TRUE => 1, FALSE => no, could not ask => -1.
 */

static int
ask_yesno(bool default_answer, const char *question)
{
	char line[64];	/* should be enough to answer yes or no */

	if (!ok_to_prompt) {
		saw_error = TRUE;
		return (-1);
	}
	for (;;) {
		(void) printf("%s (%s)? ", question,
		    default_answer ? "[y]/n" : "y/[n]");
		if (fgets(line, sizeof (line), stdin) == NULL ||
		    line[0] == '\n')
			return (default_answer ? 1 : 0);
		if (tolower(line[0]) == 'y')
			return (1);
		if (tolower(line[0]) == 'n')
			return (0);
	}
}

/*
 * Prints warning if zone already exists.
 * In interactive mode, prompts if we should continue anyway and returns Z_OK
 * if so, Z_ERR if not.  In non-interactive mode, exits with Z_ERR.
 *
 * Note that if a zone exists and its state is >= INSTALLED, an error message
 * will be printed and this function will return Z_ERR regardless of mode.
 */

static int
check_if_zone_already_exists(bool force)
{
	char line[ZONENAME_MAX + 128];	/* enough to ask a question */
	zone_state_t state_num;
	zone_dochandle_t tmphandle;
	int res, answer;

	if ((tmphandle = zonecfg_init_handle()) == NULL) {
		zone_perror(execname, Z_NOMEM, TRUE);
		exit(Z_ERR);
	}
	res = zonecfg_get_handle(zone, tmphandle);
	zonecfg_fini_handle(tmphandle);
	if (res != Z_OK) {
		new_zone = TRUE;
		return (Z_OK);
	}
	if (zone_get_state(zone, &state_num) == Z_OK &&
	    state_num >= ZONE_STATE_INSTALLED) {
		zerr(gettext("Zone %s already installed; %s not allowed."),
		    zone, cmd_to_str(CMD_CREATE));
		return (Z_ERR);
	}

	if (force) {
		(void) printf(gettext("Zone %s already exists; overwriting.\n"),
		    zone);
		return (Z_OK);
	}
	(void) snprintf(line, sizeof (line),
	    gettext("Zone %s already exists; %s anyway"), zone,
	    cmd_to_str(CMD_CREATE));
	if ((answer = ask_yesno(FALSE, line)) == -1) {
		zerr(gettext("Zone exists, input not from terminal and -F not "
		    "specified:\n%s command ignored, exiting."),
		    cmd_to_str(CMD_CREATE));
		exit(Z_ERR);
	}
	return (answer == 1 ? Z_OK : Z_ERR);
}

static bool
zone_is_read_only(int cmd_num)
{
	if (strncmp(zone, "SUNW", 4) == 0) {
		zerr(gettext("%s: zones beginning with SUNW are read-only."),
		    zone);
		saw_error = TRUE;
		return (TRUE);
	}
	if (read_only_mode) {
		zerr(gettext("%s: cannot %s in read-only mode."), zone,
		    cmd_to_str(cmd_num));
		saw_error = TRUE;
		return (TRUE);
	}
	return (FALSE);
}

/*
 * Create a new configuration.
 */
void
create_func(cmd_t *cmd)
{
	int err, arg;
	char zone_template[ZONENAME_MAX];
	zone_dochandle_t tmphandle;
	bool force = FALSE;

	assert(cmd != NULL);

	/* This is the default if no arguments are given. */
	(void) strlcpy(zone_template, "SUNWdefault", sizeof (zone_template));

	optind = 0;
	while ((arg = getopt(cmd->cmd_argc, cmd->cmd_argv, "?bFt:")) != EOF) {
		switch (arg) {
		case '?':
			if (optopt == '?')
				longer_usage(CMD_CREATE);
			else
				short_usage(CMD_CREATE);
			return;
		case 'b':
			(void) strlcpy(zone_template, "SUNWblank",
			    sizeof (zone_template));
			break;
		case 'F':
			force = TRUE;
			break;
		case 't':
			(void) strlcpy(zone_template, optarg,
			    sizeof (zone_template));
			break;
		default:
			short_usage(CMD_CREATE);
			return;
		}
	}
	if (optind != cmd->cmd_argc) {
		short_usage(CMD_CREATE);
		return;
	}

	if (zone_is_read_only(CMD_CREATE))
		return;

	if (check_if_zone_already_exists(force) != Z_OK)
		return;

	/*
	 * Get a temporary handle first.  If that fails, the old handle
	 * will not be lost.  Then finish whichever one we don't need,
	 * to avoid leaks.  Then get the handle for zone_template, and
	 * set the name to zone: this "copy, rename" method is how
	 * create -[b|t] works.
	 */
	if ((tmphandle = zonecfg_init_handle()) == NULL) {
		zone_perror(execname, Z_NOMEM, TRUE);
		exit(Z_ERR);
	}
	if ((err = zonecfg_get_handle(zone_template, tmphandle)) != Z_OK) {
		zonecfg_fini_handle(tmphandle);
		zone_perror(zone_template, err, TRUE);
		return;
	}
	zonecfg_fini_handle(handle);
	handle = tmphandle;
	if ((err = zonecfg_set_name(handle, zone)) == Z_OK)
		need_to_commit = TRUE;
	else
		zone_perror(zone, err, TRUE);
}

/*
 * This malloc()'s memory, which must be freed by the caller.
 */
static char *
quoteit(char *instr)
{
	char *outstr;
	size_t outstrsize = strlen(instr) + 3;	/* 2 quotes + '\0' */

	if ((outstr = malloc(outstrsize)) == NULL) {
		zone_perror(zone, Z_NOMEM, FALSE);
		exit(Z_ERR);
	}
	if (strchr(instr, ' ') == NULL) {
		(void) strlcpy(outstr, instr, outstrsize);
		return (outstr);
	}
	(void) snprintf(outstr, outstrsize, "\"%s\"", instr);
	return (outstr);
}

static void
export_prop(FILE *of, int prop_num, char *prop_id)
{
	char *quote_str;

	if (strlen(prop_id) == 0)
		return;
	quote_str = quoteit(prop_id);
	(void) fprintf(of, "%s %s=%s\n", cmd_to_str(CMD_SET),
	    pt_to_str(prop_num), quote_str);
	free(quote_str);
}

void
export_func(cmd_t *cmd)
{
	struct zone_nwiftab nwiftab;
	struct zone_fstab fstab;
	struct zone_devtab devtab;
	struct zone_attrtab attrtab;
	struct zone_rctltab rctltab;
	struct zone_rctlvaltab *valptr;
	int err, arg;
	char zonepath[MAXPATHLEN], outfile[MAXPATHLEN], pool[MAXNAMELEN];
	FILE *of;
	boolean_t autoboot;
	bool need_to_close = FALSE;

	assert(cmd != NULL);

	outfile[0] = '\0';
	optind = 0;
	while ((arg = getopt(cmd->cmd_argc, cmd->cmd_argv, "?f:")) != EOF) {
		switch (arg) {
		case '?':
			if (optopt == '?')
				longer_usage(CMD_EXPORT);
			else
				short_usage(CMD_EXPORT);
			return;
		case 'f':
			(void) strlcpy(outfile, optarg, sizeof (outfile));
			break;
		default:
			short_usage(CMD_EXPORT);
			return;
		}
	}
	if (optind != cmd->cmd_argc) {
		short_usage(CMD_EXPORT);
		return;
	}
	if (strlen(outfile) == 0) {
		of = stdout;
	} else {
		if ((of = fopen(outfile, "w")) == NULL) {
			zerr(gettext("opening file %s: %s"),
			    outfile, strerror(errno));
			goto done;
		}
		setbuf(of, NULL);
		need_to_close = TRUE;
	}

	if ((err = initialize(TRUE)) != Z_OK)
		goto done;

	(void) fprintf(of, "%s -b\n", cmd_to_str(CMD_CREATE));

	if (zonecfg_get_zonepath(handle, zonepath, sizeof (zonepath)) == Z_OK &&
	    strlen(zonepath) > 0)
		(void) fprintf(of, "%s %s=%s\n", cmd_to_str(CMD_SET),
		    pt_to_str(PT_ZONEPATH), zonepath);

	if (zonecfg_get_autoboot(handle, &autoboot) == Z_OK)
		(void) fprintf(of, "%s %s=%s\n", cmd_to_str(CMD_SET),
		    pt_to_str(PT_AUTOBOOT), autoboot ? "true" : "false");

	if (zonecfg_get_pool(handle, pool, sizeof (pool)) == Z_OK &&
	    strlen(pool) > 0)
		(void) fprintf(of, "%s %s=%s\n", cmd_to_str(CMD_SET),
		    pt_to_str(PT_POOL), pool);

	if ((err = zonecfg_setipdent(handle)) != Z_OK) {
		zone_perror(zone, err, FALSE);
		goto done;
	}
	while (zonecfg_getipdent(handle, &fstab) == Z_OK) {
		(void) fprintf(of, "%s %s\n", cmd_to_str(CMD_ADD),
		    rt_to_str(RT_IPD));
		export_prop(of, PT_DIR, fstab.zone_fs_dir);
		(void) fprintf(of, "%s\n", cmd_to_str(CMD_END));
	}
	(void) zonecfg_endipdent(handle);

	if ((err = zonecfg_setfsent(handle)) != Z_OK) {
		zone_perror(zone, err, FALSE);
		goto done;
	}
	while (zonecfg_getfsent(handle, &fstab) == Z_OK) {
		zone_fsopt_t *optptr;

		(void) fprintf(of, "%s %s\n", cmd_to_str(CMD_ADD),
		    rt_to_str(RT_FS));
		export_prop(of, PT_DIR, fstab.zone_fs_dir);
		export_prop(of, PT_SPECIAL, fstab.zone_fs_special);
		export_prop(of, PT_RAW, fstab.zone_fs_raw);
		export_prop(of, PT_TYPE, fstab.zone_fs_type);
		for (optptr = fstab.zone_fs_options; optptr != NULL;
		    optptr = optptr->zone_fsopt_next) {
			/*
			 * Simple property values with embedded equal signs
			 * need to be quoted to prevent the lexer from
			 * mis-parsing them as complex name=value pairs.
			 */
			if (strchr(optptr->zone_fsopt_opt, '='))
				(void) fprintf(of, "%s %s \"%s\"\n",
				    cmd_to_str(CMD_ADD),
				    pt_to_str(PT_OPTIONS),
				    optptr->zone_fsopt_opt);
			else
				(void) fprintf(of, "%s %s %s\n",
				    cmd_to_str(CMD_ADD),
				    pt_to_str(PT_OPTIONS),
				    optptr->zone_fsopt_opt);
		}
		(void) fprintf(of, "%s\n", cmd_to_str(CMD_END));
		zonecfg_free_fs_option_list(fstab.zone_fs_options);
	}
	(void) zonecfg_endfsent(handle);

	if ((err = zonecfg_setnwifent(handle)) != Z_OK) {
		zone_perror(zone, err, FALSE);
		goto done;
	}
	while (zonecfg_getnwifent(handle, &nwiftab) == Z_OK) {
		(void) fprintf(of, "%s %s\n", cmd_to_str(CMD_ADD),
		    rt_to_str(RT_NET));
		export_prop(of, PT_ADDRESS, nwiftab.zone_nwif_address);
		export_prop(of, PT_PHYSICAL, nwiftab.zone_nwif_physical);
		(void) fprintf(of, "%s\n", cmd_to_str(CMD_END));
	}
	(void) zonecfg_endnwifent(handle);

	if ((err = zonecfg_setdevent(handle)) != Z_OK) {
		zone_perror(zone, err, FALSE);
		goto done;
	}
	while (zonecfg_getdevent(handle, &devtab) == Z_OK) {
		(void) fprintf(of, "%s %s\n", cmd_to_str(CMD_ADD),
		    rt_to_str(RT_DEVICE));
		export_prop(of, PT_MATCH, devtab.zone_dev_match);
		(void) fprintf(of, "%s\n", cmd_to_str(CMD_END));
	}
	(void) zonecfg_enddevent(handle);

	if ((err = zonecfg_setrctlent(handle)) != Z_OK) {
		zone_perror(zone, err, FALSE);
		goto done;
	}
	while (zonecfg_getrctlent(handle, &rctltab) == Z_OK) {
		(void) fprintf(of, "%s rctl\n", cmd_to_str(CMD_ADD));
		export_prop(of, PT_NAME, rctltab.zone_rctl_name);
		for (valptr = rctltab.zone_rctl_valptr; valptr != NULL;
		    valptr = valptr->zone_rctlval_next) {
			fprintf(of, "%s %s (%s=%s,%s=%s,%s=%s)\n",
			    cmd_to_str(CMD_ADD), pt_to_str(PT_VALUE),
			    pt_to_str(PT_PRIV), valptr->zone_rctlval_priv,
			    pt_to_str(PT_LIMIT), valptr->zone_rctlval_limit,
			    pt_to_str(PT_ACTION), valptr->zone_rctlval_action);
		}
		(void) fprintf(of, "%s\n", cmd_to_str(CMD_END));
		zonecfg_free_rctl_value_list(rctltab.zone_rctl_valptr);
	}
	(void) zonecfg_endrctlent(handle);

	if ((err = zonecfg_setattrent(handle)) != Z_OK) {
		zone_perror(zone, err, FALSE);
		goto done;
	}
	while (zonecfg_getattrent(handle, &attrtab) == Z_OK) {
		(void) fprintf(of, "%s %s\n", cmd_to_str(CMD_ADD),
		    rt_to_str(RT_ATTR));
		export_prop(of, PT_NAME, attrtab.zone_attr_name);
		export_prop(of, PT_TYPE, attrtab.zone_attr_type);
		export_prop(of, PT_VALUE, attrtab.zone_attr_value);
		(void) fprintf(of, "%s\n", cmd_to_str(CMD_END));
	}
	(void) zonecfg_endattrent(handle);

done:
	if (need_to_close)
		(void) fclose(of);
}

void
exit_func(cmd_t *cmd)
{
	int arg, answer;

	optind = 0;
	while ((arg = getopt(cmd->cmd_argc, cmd->cmd_argv, "?F")) != EOF) {
		switch (arg) {
		case '?':
			longer_usage(CMD_EXIT);
			return;
		case 'F':
			force_exit = TRUE;
			break;
		default:
			short_usage(CMD_EXIT);
			return;
		}
	}
	if (optind < cmd->cmd_argc) {
		short_usage(CMD_EXIT);
		return;
	}

	if (global_scope || force_exit) {
		time_to_exit = TRUE;
		return;
	}

	answer = ask_yesno(FALSE, "Resource incomplete; really quit");
	if (answer == -1) {
		zerr(gettext("Resource incomplete, input "
		    "not from terminal and -F not specified:\n%s command "
		    "ignored, but exiting anyway."), cmd_to_str(CMD_EXIT));
		exit(Z_ERR);
	} else if (answer == 1) {
		time_to_exit = TRUE;
	}
	/* (answer == 0) => just return */
}

static int
validate_zonepath_syntax(char *path)
{
	if (path[0] != '/') {
		zerr(gettext("%s is not an absolute path."), path);
		return (Z_ERR);
	}
	if (strcmp(path, "/") == 0) {
		zerr(gettext("/ is not allowed as a %s."),
		    pt_to_str(PT_ZONEPATH));
		return (Z_ERR);
	}
	return (Z_OK);
}

static void
add_resource(cmd_t *cmd)
{
	int type;
	zone_state_t state_num;

	if ((type = cmd->cmd_res_type) == RT_UNKNOWN) {
		long_usage(CMD_ADD, TRUE);
		goto bad;
	}

	switch (type) {
	case RT_FS:
		bzero(&in_progress_fstab, sizeof (in_progress_fstab));
		return;
	case RT_IPD:
		if (zone_get_state(zone, &state_num) == Z_OK &&
		    state_num >= ZONE_STATE_INSTALLED) {
			zerr(gettext("Zone %s already installed; %s %s not "
			    "allowed."), zone, cmd_to_str(CMD_ADD),
			    rt_to_str(RT_IPD));
			goto bad;
		}
		bzero(&in_progress_ipdtab, sizeof (in_progress_ipdtab));
		return;
	case RT_NET:
		bzero(&in_progress_nwiftab, sizeof (in_progress_nwiftab));
		return;
	case RT_DEVICE:
		bzero(&in_progress_devtab, sizeof (in_progress_devtab));
		return;
	case RT_RCTL:
		bzero(&in_progress_rctltab, sizeof (in_progress_rctltab));
		return;
	case RT_ATTR:
		bzero(&in_progress_attrtab, sizeof (in_progress_attrtab));
		return;
	default:
		zone_perror(rt_to_str(type), Z_NO_RESOURCE_TYPE, TRUE);
		long_usage(CMD_ADD, TRUE);
		usage(FALSE, HELP_RESOURCES);
	}
bad:
	global_scope = TRUE;
	end_op = -1;
}

static void
do_complex_rctl_val(complex_property_ptr_t cp)
{
	struct zone_rctlvaltab *rctlvaltab;
	complex_property_ptr_t cx;
	bool seen_priv = FALSE, seen_limit = FALSE, seen_action = FALSE;
	rctlblk_t *rctlblk;
	int err;

	if ((rctlvaltab = alloc_rctlvaltab()) == NULL) {
		zone_perror(zone, Z_NOMEM, TRUE);
		exit(Z_ERR);
	}
	for (cx = cp; cx != NULL; cx = cx->cp_next) {
		switch (cx->cp_type) {
		case PT_PRIV:
			if (seen_priv) {
				zerr(gettext("%s already specified"),
				    pt_to_str(PT_PRIV));
				goto bad;
			}
			(void) strlcpy(rctlvaltab->zone_rctlval_priv,
			    cx->cp_value,
			    sizeof (rctlvaltab->zone_rctlval_priv));
			seen_priv = TRUE;
			break;
		case PT_LIMIT:
			if (seen_limit) {
				zerr(gettext("%s already specified"),
				    pt_to_str(PT_LIMIT));
				goto bad;
			}
			(void) strlcpy(rctlvaltab->zone_rctlval_limit,
			    cx->cp_value,
			    sizeof (rctlvaltab->zone_rctlval_limit));
			seen_limit = TRUE;
			break;
		case PT_ACTION:
			if (seen_action) {
				zerr(gettext("%s already specified"),
				    pt_to_str(PT_ACTION));
				goto bad;
			}
			(void) strlcpy(rctlvaltab->zone_rctlval_action,
			    cx->cp_value,
			    sizeof (rctlvaltab->zone_rctlval_action));
			seen_action = TRUE;
			break;
		default:
			zone_perror(pt_to_str(PT_VALUE),
			    Z_NO_PROPERTY_TYPE, TRUE);
			long_usage(CMD_ADD, TRUE);
			usage(FALSE, HELP_PROPS);
			zonecfg_free_rctl_value_list(rctlvaltab);
			return;
		}
	}
	if (!seen_priv)
		zerr(gettext("%s not specified"), pt_to_str(PT_PRIV));
	if (!seen_limit)
		zerr(gettext("%s not specified"), pt_to_str(PT_LIMIT));
	if (!seen_action)
		zerr(gettext("%s not specified"), pt_to_str(PT_ACTION));
	if (!seen_priv || !seen_limit || !seen_action)
		goto bad;
	rctlvaltab->zone_rctlval_next = NULL;
	rctlblk = alloca(rctlblk_size());
	/*
	 * Make sure the rctl value looks roughly correct; we won't know if
	 * it's truly OK until we verify the configuration on the target
	 * system.
	 */
	if (zonecfg_construct_rctlblk(rctlvaltab, rctlblk) != Z_OK ||
	    !zonecfg_valid_rctlblk(rctlblk)) {
		zerr(gettext("Invalid %s %s specification"), rt_to_str(RT_RCTL),
		    pt_to_str(PT_VALUE));
		goto bad;
	}
	err = zonecfg_add_rctl_value(&in_progress_rctltab, rctlvaltab);
	if (err != Z_OK)
		zone_perror(pt_to_str(PT_VALUE), err, TRUE);
	return;

bad:
	zonecfg_free_rctl_value_list(rctlvaltab);
}

static void
add_property(cmd_t *cmd)
{
	char *prop_id;
	int err, res_type, prop_type;
	property_value_ptr_t pp;
	list_property_ptr_t l;

	res_type = resource_scope;
	prop_type = cmd->cmd_prop_name[0];
	if (res_type == RT_UNKNOWN || prop_type == PT_UNKNOWN) {
		long_usage(CMD_ADD, TRUE);
		return;
	}

	if (cmd->cmd_prop_nv_pairs != 1) {
		long_usage(CMD_ADD, TRUE);
		return;
	}

	if (initialize(TRUE) != Z_OK)
		return;

	switch (res_type) {
	case RT_FS:
		if (prop_type != PT_OPTIONS) {
			zone_perror(pt_to_str(prop_type), Z_NO_PROPERTY_TYPE,
			    TRUE);
			long_usage(CMD_ADD, TRUE);
			usage(FALSE, HELP_PROPS);
			return;
		}
		pp = cmd->cmd_property_ptr[0];
		if (pp->pv_type != PROP_VAL_SIMPLE &&
		    pp->pv_type != PROP_VAL_LIST) {
			zerr(gettext("A %s or %s value was expected here."),
			    pvt_to_str(PROP_VAL_SIMPLE),
			    pvt_to_str(PROP_VAL_LIST));
			saw_error = TRUE;
			return;
		}
		if (pp->pv_type == PROP_VAL_SIMPLE) {
			if (pp->pv_simple == NULL) {
				long_usage(CMD_ADD, TRUE);
				return;
			}
			prop_id = pp->pv_simple;
			err = zonecfg_add_fs_option(&in_progress_fstab,
			    prop_id);
			if (err != Z_OK)
				zone_perror(pt_to_str(prop_type), err, TRUE);
		} else {
			list_property_ptr_t list;

			for (list = pp->pv_list; list != NULL;
			    list = list->lp_next) {
				prop_id = list->lp_simple;
				if (prop_id == NULL)
					break;
				err = zonecfg_add_fs_option(
				    &in_progress_fstab, prop_id);
				if (err != Z_OK)
					zone_perror(pt_to_str(prop_type), err,
					    TRUE);
			}
		}
		return;
	case RT_RCTL:
		if (prop_type != PT_VALUE) {
			zone_perror(pt_to_str(prop_type), Z_NO_PROPERTY_TYPE,
			    TRUE);
			long_usage(CMD_ADD, TRUE);
			usage(FALSE, HELP_PROPS);
			return;
		}
		pp = cmd->cmd_property_ptr[0];
		if (pp->pv_type != PROP_VAL_COMPLEX &&
		    pp->pv_type != PROP_VAL_LIST) {
			zerr(gettext("A %s or %s value was expected here."),
			    pvt_to_str(PROP_VAL_COMPLEX),
			    pvt_to_str(PROP_VAL_LIST));
			saw_error = TRUE;
			return;
		}
		if (pp->pv_type == PROP_VAL_COMPLEX) {
			do_complex_rctl_val(pp->pv_complex);
			return;
		}
		for (l = pp->pv_list; l != NULL; l = l->lp_next)
			do_complex_rctl_val(l->lp_complex);
		return;
	default:
		zone_perror(rt_to_str(res_type), Z_NO_RESOURCE_TYPE, TRUE);
		long_usage(CMD_ADD, TRUE);
		usage(FALSE, HELP_RESOURCES);
		return;
	}
}

void
add_func(cmd_t *cmd)
{
	int arg;

	assert(cmd != NULL);

	optind = 0;
	if ((arg = getopt(cmd->cmd_argc, cmd->cmd_argv, "?")) != EOF) {
		switch (arg) {
		case '?':
			longer_usage(CMD_ADD);
			return;
		default:
			short_usage(CMD_ADD);
			return;
		}
	}
	if (optind != cmd->cmd_argc) {
		short_usage(CMD_ADD);
		return;
	}

	if (zone_is_read_only(CMD_ADD))
		return;

	if (initialize(TRUE) != Z_OK)
		return;
	if (global_scope) {
		global_scope = FALSE;
		resource_scope = cmd->cmd_res_type;
		end_op = CMD_ADD;
		add_resource(cmd);
	} else
		add_property(cmd);
}

void
delete_func(cmd_t *cmd)
{
	int err, arg, answer;
	char line[ZONENAME_MAX + 128];	/* enough to ask a question */
	bool force = FALSE;
	zone_state_t state_num;

	optind = 0;
	while ((arg = getopt(cmd->cmd_argc, cmd->cmd_argv, "?F")) != EOF) {
		switch (arg) {
		case '?':
			longer_usage(CMD_DELETE);
			return;
		case 'F':
			force = TRUE;
			break;
		default:
			short_usage(CMD_DELETE);
			return;
		}
	}
	if (optind != cmd->cmd_argc) {
		short_usage(CMD_DELETE);
		return;
	}

	if (zone_is_read_only(CMD_DELETE))
		return;

	if (zone_get_state(zone, &state_num) == Z_OK &&
	    state_num >= ZONE_STATE_INCOMPLETE) {
		zerr(gettext("Zone %s not in %s state; %s not allowed."),
		    zone, zone_state_str(ZONE_STATE_CONFIGURED),
		    cmd_to_str(CMD_DELETE));
		saw_error = TRUE;
		return;
	}

	if (initialize(TRUE) != Z_OK)
		return;

	if (!force) {
		(void) snprintf(line, sizeof (line),
		    gettext("Are you sure you want to delete zone %s"), zone);
		if ((answer = ask_yesno(FALSE, line)) == -1) {
			zerr(gettext("Input not from "
			    "terminal and -F not specified:\n%s command "
			    "ignored, exiting."), cmd_to_str(CMD_DELETE));
			exit(Z_ERR);
		}
		if (answer != 1)
			return;
	}

	if ((err = zonecfg_delete_index(zone)) != Z_OK) {
		zone_perror(zone, err, TRUE);
		return;
	}

	need_to_commit = FALSE;
	if ((err = zonecfg_destroy(zone)) != Z_OK)
		zone_perror(zone, err, TRUE);

	/*
	 * Time for a new handle: finish the old one off first
	 * then get a new one properly to avoid leaks.
	 */
	zonecfg_fini_handle(handle);
	if ((handle = zonecfg_init_handle()) == NULL) {
		zone_perror(execname, Z_NOMEM, TRUE);
		exit(Z_ERR);
	}
	if ((err = zonecfg_get_handle(zone, handle)) != Z_OK) {
		/* If there was no zone before, that's OK */
		if (err != Z_NO_ZONE)
			zone_perror(zone, err, TRUE);
		got_handle = FALSE;
	}
}

static int
fill_in_fstab(cmd_t *cmd, struct zone_fstab *fstab, bool fill_in_only)
{
	int err, i;
	property_value_ptr_t pp;

	if ((err = initialize(TRUE)) != Z_OK)
		return (err);

	fstab->zone_fs_dir[0] = '\0';
	fstab->zone_fs_special[0] = '\0';
	fstab->zone_fs_type[0] = '\0';
	fstab->zone_fs_options = NULL;
	for (i = 0; i < cmd->cmd_prop_nv_pairs; i++) {
		pp = cmd->cmd_property_ptr[i];
		if (pp->pv_type != PROP_VAL_SIMPLE || pp->pv_simple == NULL) {
			zerr(gettext("A simple value was expected here."));
			saw_error = TRUE;
			return (Z_INSUFFICIENT_SPEC);
		}
		switch (cmd->cmd_prop_name[i]) {
		case PT_DIR:
			(void) strlcpy(fstab->zone_fs_dir, pp->pv_simple,
			    sizeof (fstab->zone_fs_dir));
			break;
		case PT_SPECIAL:
			(void) strlcpy(fstab->zone_fs_special, pp->pv_simple,
			    sizeof (fstab->zone_fs_special));
			break;
		case PT_RAW:
			(void) strlcpy(fstab->zone_fs_raw, pp->pv_simple,
			    sizeof (fstab->zone_fs_raw));
			break;
		case PT_TYPE:
			(void) strlcpy(fstab->zone_fs_type, pp->pv_simple,
			    sizeof (fstab->zone_fs_type));
			break;
		default:
			zone_perror(pt_to_str(cmd->cmd_prop_name[i]),
			    Z_NO_PROPERTY_TYPE, TRUE);
			return (Z_INSUFFICIENT_SPEC);
		}
	}
	if (fill_in_only)
		return (Z_OK);
	return (zonecfg_lookup_filesystem(handle, fstab));
}

static int
fill_in_ipdtab(cmd_t *cmd, struct zone_fstab *ipdtab, bool fill_in_only)
{
	int err, i;
	property_value_ptr_t pp;

	if ((err = initialize(TRUE)) != Z_OK)
		return (err);

	ipdtab->zone_fs_dir[0] = '\0';
	for (i = 0; i < cmd->cmd_prop_nv_pairs; i++) {
		pp = cmd->cmd_property_ptr[i];
		if (pp->pv_type != PROP_VAL_SIMPLE || pp->pv_simple == NULL) {
			zerr(gettext("A simple value was expected here."));
			saw_error = TRUE;
			return (Z_INSUFFICIENT_SPEC);
		}
		switch (cmd->cmd_prop_name[i]) {
		case PT_DIR:
			(void) strlcpy(ipdtab->zone_fs_dir, pp->pv_simple,
			    sizeof (ipdtab->zone_fs_dir));
			break;
		default:
			zone_perror(pt_to_str(cmd->cmd_prop_name[i]),
			    Z_NO_PROPERTY_TYPE, TRUE);
			return (Z_INSUFFICIENT_SPEC);
		}
	}
	if (fill_in_only)
		return (Z_OK);
	return (zonecfg_lookup_ipd(handle, ipdtab));
}

static int
fill_in_nwiftab(cmd_t *cmd, struct zone_nwiftab *nwiftab, bool fill_in_only)
{
	int err, i;
	property_value_ptr_t pp;

	if ((err = initialize(TRUE)) != Z_OK)
		return (err);

	nwiftab->zone_nwif_address[0] = '\0';
	nwiftab->zone_nwif_physical[0] = '\0';
	for (i = 0; i < cmd->cmd_prop_nv_pairs; i++) {
		pp = cmd->cmd_property_ptr[i];
		if (pp->pv_type != PROP_VAL_SIMPLE || pp->pv_simple == NULL) {
			zerr(gettext("A simple value was expected here."));
			saw_error = TRUE;
			return (Z_INSUFFICIENT_SPEC);
		}
		switch (cmd->cmd_prop_name[i]) {
		case PT_ADDRESS:
			(void) strlcpy(nwiftab->zone_nwif_address,
			    pp->pv_simple, sizeof (nwiftab->zone_nwif_address));
			break;
		case PT_PHYSICAL:
			(void) strlcpy(nwiftab->zone_nwif_physical,
			    pp->pv_simple,
			    sizeof (nwiftab->zone_nwif_physical));
			break;
		default:
			zone_perror(pt_to_str(cmd->cmd_prop_name[i]),
			    Z_NO_PROPERTY_TYPE, TRUE);
			return (Z_INSUFFICIENT_SPEC);
		}
	}
	if (fill_in_only)
		return (Z_OK);
	err = zonecfg_lookup_nwif(handle, nwiftab);
	return (err);
}

static int
fill_in_devtab(cmd_t *cmd, struct zone_devtab *devtab, bool fill_in_only)
{
	int err, i;
	property_value_ptr_t pp;

	if ((err = initialize(TRUE)) != Z_OK)
		return (err);

	devtab->zone_dev_match[0] = '\0';
	for (i = 0; i < cmd->cmd_prop_nv_pairs; i++) {
		pp = cmd->cmd_property_ptr[i];
		if (pp->pv_type != PROP_VAL_SIMPLE || pp->pv_simple == NULL) {
			zerr(gettext("A simple value was expected here."));
			saw_error = TRUE;
			return (Z_INSUFFICIENT_SPEC);
		}
		switch (cmd->cmd_prop_name[i]) {
		case PT_MATCH:
			(void) strlcpy(devtab->zone_dev_match, pp->pv_simple,
			    sizeof (devtab->zone_dev_match));
			break;
		default:
			zone_perror(pt_to_str(cmd->cmd_prop_name[i]),
			    Z_NO_PROPERTY_TYPE, TRUE);
			return (Z_INSUFFICIENT_SPEC);
		}
	}
	if (fill_in_only)
		return (Z_OK);
	err = zonecfg_lookup_dev(handle, devtab);
	return (err);
}

static int
fill_in_rctltab(cmd_t *cmd, struct zone_rctltab *rctltab, bool fill_in_only)
{
	int err, i;
	property_value_ptr_t pp;

	if ((err = initialize(TRUE)) != Z_OK)
		return (err);

	rctltab->zone_rctl_name[0] = '\0';
	for (i = 0; i < cmd->cmd_prop_nv_pairs; i++) {
		pp = cmd->cmd_property_ptr[i];
		if (pp->pv_type != PROP_VAL_SIMPLE || pp->pv_simple == NULL) {
			zerr(gettext("A simple value was expected here."));
			saw_error = TRUE;
			return (Z_INSUFFICIENT_SPEC);
		}
		switch (cmd->cmd_prop_name[i]) {
		case PT_NAME:
			(void) strlcpy(rctltab->zone_rctl_name, pp->pv_simple,
			    sizeof (rctltab->zone_rctl_name));
			break;
		default:
			zone_perror(pt_to_str(cmd->cmd_prop_name[i]),
			    Z_NO_PROPERTY_TYPE, TRUE);
			return (Z_INSUFFICIENT_SPEC);
		}
	}
	if (fill_in_only)
		return (Z_OK);
	err = zonecfg_lookup_rctl(handle, rctltab);
	return (err);
}

static int
fill_in_attrtab(cmd_t *cmd, struct zone_attrtab *attrtab, bool fill_in_only)
{
	int err, i;
	property_value_ptr_t pp;

	if ((err = initialize(TRUE)) != Z_OK)
		return (err);

	attrtab->zone_attr_name[0] = '\0';
	attrtab->zone_attr_type[0] = '\0';
	attrtab->zone_attr_value[0] = '\0';
	for (i = 0; i < cmd->cmd_prop_nv_pairs; i++) {
		pp = cmd->cmd_property_ptr[i];
		if (pp->pv_type != PROP_VAL_SIMPLE || pp->pv_simple == NULL) {
			zerr(gettext("A simple value was expected here."));
			saw_error = TRUE;
			return (Z_INSUFFICIENT_SPEC);
		}
		switch (cmd->cmd_prop_name[i]) {
		case PT_NAME:
			(void) strlcpy(attrtab->zone_attr_name, pp->pv_simple,
			    sizeof (attrtab->zone_attr_name));
			break;
		case PT_TYPE:
			(void) strlcpy(attrtab->zone_attr_type, pp->pv_simple,
			    sizeof (attrtab->zone_attr_type));
			break;
		case PT_VALUE:
			(void) strlcpy(attrtab->zone_attr_value, pp->pv_simple,
			    sizeof (attrtab->zone_attr_value));
			break;
		default:
			zone_perror(pt_to_str(cmd->cmd_prop_name[i]),
			    Z_NO_PROPERTY_TYPE, TRUE);
			return (Z_INSUFFICIENT_SPEC);
		}
	}
	if (fill_in_only)
		return (Z_OK);
	err = zonecfg_lookup_attr(handle, attrtab);
	return (err);
}

static void
remove_resource(cmd_t *cmd)
{
	int err, type;
	struct zone_fstab fstab;
	struct zone_nwiftab nwiftab;
	struct zone_devtab devtab;
	struct zone_attrtab attrtab;
	struct zone_rctltab rctltab;
	zone_state_t state_num;

	if ((type = cmd->cmd_res_type) == RT_UNKNOWN) {
		long_usage(CMD_REMOVE, TRUE);
		return;
	}

	if (initialize(TRUE) != Z_OK)
		return;

	switch (type) {
	case RT_FS:
		if ((err = fill_in_fstab(cmd, &fstab, FALSE)) != Z_OK) {
			z_cmd_rt_perror(CMD_REMOVE, RT_FS, err, TRUE);
			return;
		}
		if ((err = zonecfg_delete_filesystem(handle, &fstab)) != Z_OK)
			z_cmd_rt_perror(CMD_REMOVE, RT_FS, err, TRUE);
		else
			need_to_commit = TRUE;
		zonecfg_free_fs_option_list(fstab.zone_fs_options);
		return;
	case RT_IPD:
		if (zone_get_state(zone, &state_num) == Z_OK &&
		    state_num >= ZONE_STATE_INSTALLED) {
			zerr(gettext("Zone %s already installed; %s %s not "
			    "allowed."), zone, cmd_to_str(CMD_REMOVE),
			    rt_to_str(RT_IPD));
			return;
		}
		if ((err = fill_in_ipdtab(cmd, &fstab, FALSE)) != Z_OK) {
			z_cmd_rt_perror(CMD_REMOVE, RT_IPD, err, TRUE);
			return;
		}
		if ((err = zonecfg_delete_ipd(handle, &fstab)) != Z_OK)
			z_cmd_rt_perror(CMD_REMOVE, RT_IPD, err, TRUE);
		else
			need_to_commit = TRUE;
		return;
	case RT_NET:
		if ((err = fill_in_nwiftab(cmd, &nwiftab, FALSE)) != Z_OK) {
			z_cmd_rt_perror(CMD_REMOVE, RT_NET, err, TRUE);
			return;
		}
		if ((err = zonecfg_delete_nwif(handle, &nwiftab)) != Z_OK)
			z_cmd_rt_perror(CMD_REMOVE, RT_NET, err, TRUE);
		else
			need_to_commit = TRUE;
		return;
	case RT_DEVICE:
		if ((err = fill_in_devtab(cmd, &devtab, FALSE)) != Z_OK) {
			z_cmd_rt_perror(CMD_REMOVE, RT_DEVICE, err, TRUE);
			return;
		}
		if ((err = zonecfg_delete_dev(handle, &devtab)) != Z_OK)
			z_cmd_rt_perror(CMD_REMOVE, RT_DEVICE, err, TRUE);
		else
			need_to_commit = TRUE;
		return;
	case RT_RCTL:
		if ((err = fill_in_rctltab(cmd, &rctltab, FALSE)) != Z_OK) {
			z_cmd_rt_perror(CMD_REMOVE, RT_RCTL, err, TRUE);
			return;
		}
		if ((err = zonecfg_delete_rctl(handle, &rctltab)) != Z_OK)
			z_cmd_rt_perror(CMD_REMOVE, RT_RCTL, err, TRUE);
		else
			need_to_commit = TRUE;
		zonecfg_free_rctl_value_list(rctltab.zone_rctl_valptr);
		return;
	case RT_ATTR:
		if ((err = fill_in_attrtab(cmd, &attrtab, FALSE)) != Z_OK) {
			z_cmd_rt_perror(CMD_REMOVE, RT_ATTR, err, TRUE);
			return;
		}
		if ((err = zonecfg_delete_attr(handle, &attrtab)) != Z_OK)
			z_cmd_rt_perror(CMD_REMOVE, RT_ATTR, err, TRUE);
		else
			need_to_commit = TRUE;
		return;
	default:
		zone_perror(rt_to_str(type), Z_NO_RESOURCE_TYPE, TRUE);
		long_usage(CMD_REMOVE, TRUE);
		usage(FALSE, HELP_RESOURCES);
		return;
	}
}

static void
remove_property(cmd_t *cmd)
{
	char *prop_id;
	int err, res_type, prop_type;
	property_value_ptr_t pp;
	struct zone_rctlvaltab *rctlvaltab;
	complex_property_ptr_t cx;

	res_type = resource_scope;
	prop_type = cmd->cmd_prop_name[0];
	if (res_type == RT_UNKNOWN || prop_type == PT_UNKNOWN) {
		long_usage(CMD_REMOVE, TRUE);
		return;
	}

	if (cmd->cmd_prop_nv_pairs != 1) {
		long_usage(CMD_ADD, TRUE);
		return;
	}

	if (initialize(TRUE) != Z_OK)
		return;

	switch (res_type) {
	case RT_FS:
		if (prop_type != PT_OPTIONS) {
			zone_perror(pt_to_str(prop_type), Z_NO_PROPERTY_TYPE,
			    TRUE);
			long_usage(CMD_REMOVE, TRUE);
			usage(FALSE, HELP_PROPS);
			return;
		}
		pp = cmd->cmd_property_ptr[0];
		if (pp->pv_type == PROP_VAL_COMPLEX) {
			zerr(gettext("A %s or %s value was expected here."),
			    pvt_to_str(PROP_VAL_SIMPLE),
			    pvt_to_str(PROP_VAL_LIST));
			saw_error = TRUE;
			return;
		}
		if (pp->pv_type == PROP_VAL_SIMPLE) {
			if (pp->pv_simple == NULL) {
				long_usage(CMD_ADD, TRUE);
				return;
			}
			prop_id = pp->pv_simple;
			err = zonecfg_remove_fs_option(&in_progress_fstab,
			    prop_id);
			if (err != Z_OK)
				zone_perror(pt_to_str(prop_type), err, TRUE);
		} else {
			list_property_ptr_t list;

			for (list = pp->pv_list; list != NULL;
			    list = list->lp_next) {
				prop_id = list->lp_simple;
				if (prop_id == NULL)
					break;
				err = zonecfg_remove_fs_option(
				    &in_progress_fstab, prop_id);
				if (err != Z_OK)
					zone_perror(pt_to_str(prop_type), err,
					    TRUE);
			}
		}
		return;
	case RT_RCTL:
		if (prop_type != PT_VALUE) {
			zone_perror(pt_to_str(prop_type), Z_NO_PROPERTY_TYPE,
			    TRUE);
			long_usage(CMD_REMOVE, TRUE);
			usage(FALSE, HELP_PROPS);
			return;
		}
		pp = cmd->cmd_property_ptr[0];
		if (pp->pv_type != PROP_VAL_COMPLEX) {
			zerr(gettext("A %s value was expected here."),
			    pvt_to_str(PROP_VAL_COMPLEX));
			saw_error = TRUE;
			return;
		}
		if ((rctlvaltab = alloc_rctlvaltab()) == NULL) {
			zone_perror(zone, Z_NOMEM, TRUE);
			exit(Z_ERR);
		}
		for (cx = pp->pv_complex; cx != NULL; cx = cx->cp_next) {
			switch (cx->cp_type) {
			case PT_PRIV:
				(void) strlcpy(rctlvaltab->zone_rctlval_priv,
				    cx->cp_value,
				    sizeof (rctlvaltab->zone_rctlval_priv));
				break;
			case PT_LIMIT:
				(void) strlcpy(rctlvaltab->zone_rctlval_limit,
				    cx->cp_value,
				    sizeof (rctlvaltab->zone_rctlval_limit));
				break;
			case PT_ACTION:
				(void) strlcpy(rctlvaltab->zone_rctlval_action,
				    cx->cp_value,
				    sizeof (rctlvaltab->zone_rctlval_action));
				break;
			default:
				zone_perror(pt_to_str(prop_type),
				    Z_NO_PROPERTY_TYPE, TRUE);
				long_usage(CMD_ADD, TRUE);
				usage(FALSE, HELP_PROPS);
				zonecfg_free_rctl_value_list(rctlvaltab);
				return;
			}
		}
		rctlvaltab->zone_rctlval_next = NULL;
		err = zonecfg_remove_rctl_value(&in_progress_rctltab,
		    rctlvaltab);
		if (err != Z_OK)
			zone_perror(pt_to_str(prop_type), err, TRUE);
		zonecfg_free_rctl_value_list(rctlvaltab);
		return;
	default:
		zone_perror(rt_to_str(res_type), Z_NO_RESOURCE_TYPE, TRUE);
		long_usage(CMD_REMOVE, TRUE);
		usage(FALSE, HELP_RESOURCES);
		return;
	}
}

void
remove_func(cmd_t *cmd)
{
	if (zone_is_read_only(CMD_REMOVE))
		return;

	assert(cmd != NULL);

	if (global_scope)
		remove_resource(cmd);
	else
		remove_property(cmd);
}

void
select_func(cmd_t *cmd)
{
	int type, err;
	zone_state_t state_num;

	if (zone_is_read_only(CMD_SELECT))
		return;

	assert(cmd != NULL);

	if (global_scope) {
		global_scope = FALSE;
		resource_scope = cmd->cmd_res_type;
		end_op = CMD_SELECT;
	} else {
		scope_usage(CMD_SELECT);
		return;
	}

	if ((type = cmd->cmd_res_type) == RT_UNKNOWN) {
		long_usage(CMD_SELECT, TRUE);
		return;
	}

	if (initialize(TRUE) != Z_OK)
		return;

	switch (type) {
	case RT_FS:
		if ((err = fill_in_fstab(cmd, &old_fstab, FALSE)) != Z_OK) {
			z_cmd_rt_perror(CMD_SELECT, RT_FS, err, TRUE);
			global_scope = TRUE;
		}
		bcopy(&old_fstab, &in_progress_fstab,
		    sizeof (struct zone_fstab));
		return;
	case RT_IPD:
		if (zone_get_state(zone, &state_num) == Z_OK &&
		    state_num >= ZONE_STATE_INCOMPLETE) {
			zerr(gettext("Zone %s not in %s state; %s %s not "
			    "allowed."), zone,
			    zone_state_str(ZONE_STATE_CONFIGURED),
			    cmd_to_str(CMD_SELECT), rt_to_str(RT_IPD));
			global_scope = TRUE;
			end_op = -1;
			return;
		}
		if ((err = fill_in_ipdtab(cmd, &old_ipdtab, FALSE)) != Z_OK) {
			z_cmd_rt_perror(CMD_SELECT, RT_IPD, err, TRUE);
			global_scope = TRUE;
		}
		bcopy(&old_ipdtab, &in_progress_ipdtab,
		    sizeof (struct zone_fstab));
		return;
	case RT_NET:
		if ((err = fill_in_nwiftab(cmd, &old_nwiftab, FALSE)) != Z_OK) {
			z_cmd_rt_perror(CMD_SELECT, RT_NET, err, TRUE);
			global_scope = TRUE;
		}
		bcopy(&old_nwiftab, &in_progress_nwiftab,
		    sizeof (struct zone_nwiftab));
		return;
	case RT_DEVICE:
		if ((err = fill_in_devtab(cmd, &old_devtab, FALSE)) != Z_OK) {
			z_cmd_rt_perror(CMD_SELECT, RT_DEVICE, err, TRUE);
			global_scope = TRUE;
		}
		bcopy(&old_devtab, &in_progress_devtab,
		    sizeof (struct zone_devtab));
		return;
	case RT_RCTL:
		if ((err = fill_in_rctltab(cmd, &old_rctltab, FALSE)) != Z_OK) {
			z_cmd_rt_perror(CMD_SELECT, RT_RCTL, err, TRUE);
			global_scope = TRUE;
		}
		bcopy(&old_rctltab, &in_progress_rctltab,
		    sizeof (struct zone_rctltab));
		return;
	case RT_ATTR:
		if ((err = fill_in_attrtab(cmd, &old_attrtab, FALSE)) != Z_OK) {
			z_cmd_rt_perror(CMD_SELECT, RT_ATTR, err, TRUE);
			global_scope = TRUE;
		}
		bcopy(&old_attrtab, &in_progress_attrtab,
		    sizeof (struct zone_attrtab));
		return;
	default:
		zone_perror(rt_to_str(type), Z_NO_RESOURCE_TYPE, TRUE);
		long_usage(CMD_SELECT, TRUE);
		usage(FALSE, HELP_RESOURCES);
		return;
	}
}

/*
 * Network "addresses" can be one of the following forms:
 *	<IPv4 address>
 *	<IPv4 address>/<prefix length>
 *	<IPv6 address>/<prefix length>
 *	<host name>
 *	<host name>/<prefix length>
 * In other words, the "/" followed by a prefix length is allowed but not
 * required for IPv4 addresses and host names, and required for IPv6 addresses.
 * If a prefix length is given, it must be in the allowable range: 0 to 32 for
 * IPv4 addresses and host names, 0 to 128 for IPv6 addresses.
 * Host names must start with an alpha-numeric character, and all subsequent
 * characters must be either alpha-numeric or "-".
 */

static int
validate_net_address_syntax(char *address)
{
	char *slashp, part1[MAXHOSTNAMELEN];
	struct in6_addr in6;
	struct in_addr in4;
	int prefixlen, i;

	/*
	 * Copy the part before any '/' into part1 or copy the whole
	 * thing if there is no '/'.
	 */
	if ((slashp = strchr(address, '/')) != NULL) {
		*slashp = '\0';
		(void) strlcpy(part1, address, sizeof (part1));
		*slashp = '/';
		prefixlen = atoi(++slashp);
	} else {
		(void) strlcpy(part1, address, sizeof (part1));
	}

	if (inet_pton(AF_INET6, part1, &in6) == 1) {
		if (slashp == NULL) {
			zerr(gettext("%s: IPv6 addresses "
			    "require /prefix-length suffix."), address);
			return (Z_ERR);
		}
		if (prefixlen < 0 || prefixlen > 128) {
			zerr(gettext("%s: IPv6 address "
			    "prefix lengths must be 0 - 128."), address);
			return (Z_ERR);
		}
		return (Z_OK);
	}

	/* At this point, any /prefix must be for IPv4. */
	if (slashp != NULL) {
		if (prefixlen < 0 || prefixlen > 32) {
			zerr(gettext("%s: IPv4 address "
			    "prefix lengths must be 0 - 32."), address);
			return (Z_ERR);
		}
	}
	if (inet_pton(AF_INET, part1, &in4) == 1)
		return (Z_OK);

	/* address may also be a host name */
	if (!isalnum(part1[0])) {
		zerr(gettext("%s: bogus host name or network address syntax"),
		    part1);
		saw_error = TRUE;
		usage(FALSE, HELP_NETADDR);
		return (Z_ERR);
	}
	for (i = 1; part1[i]; i++)
		if (!isalnum(part1[i]) && part1[i] != '-' && part1[i] != '.') {
			zerr(gettext("%s: bogus host name or "
			    "network address syntax"), part1);
			saw_error = TRUE;
			usage(FALSE, HELP_NETADDR);
			return (Z_ERR);
		}
	return (Z_OK);
}

static int
validate_net_physical_syntax(char *ifname)
{
	if (strchr(ifname, ':') == NULL)
		return (Z_OK);
	zerr(gettext("%s: physical interface name required; "
	    "logical interface name not allowed"), ifname);
	return (Z_ERR);
}

static boolean_t
valid_fs_type(const char *type)
{
	/*
	 * Is this a valid path component?
	 */
	if (strlen(type) + 1 > MAXNAMELEN)
		return (B_FALSE);
	/*
	 * Make sure a bad value for "type" doesn't make
	 * /usr/lib/fs/<type>/mount turn into something else.
	 */
	if (strchr(type, '/') != NULL || type[0] == '\0' ||
	    strcmp(type, ".") == 0 || strcmp(type, "..") == 0)
	    return (B_FALSE);
	/*
	 * More detailed verification happens later by zoneadm(1m).
	 */
	return (B_TRUE);
}

void
set_func(cmd_t *cmd)
{
	char *prop_id;
	int err, res_type, prop_type;
	property_value_ptr_t pp;
	zone_state_t state_num;
	boolean_t autoboot;

	if (zone_is_read_only(CMD_SET))
		return;

	assert(cmd != NULL);

	prop_type = cmd->cmd_prop_name[0];
	if (global_scope) {
		if (prop_type == PT_ZONEPATH) {
			res_type = RT_ZONEPATH;
		} else if (prop_type == PT_AUTOBOOT) {
			res_type = RT_AUTOBOOT;
		} else if (prop_type == PT_POOL) {
			res_type = RT_POOL;
		} else {
			zerr(gettext("Cannot set a resource-specific property "
			    "from the global scope."));
			saw_error = TRUE;
			return;
		}
	} else {
		res_type = resource_scope;
	}

	pp = cmd->cmd_property_ptr[0];
	/*
	 * A nasty expression but not that complicated:
	 * 1. fs options are simple or list (tested below)
	 * 2. rctl value's are complex or list (tested below)
	 * Anything else should be simple.
	 */
	if (!(res_type == RT_FS && prop_type == PT_OPTIONS) &&
	    !(res_type == RT_RCTL && prop_type == PT_VALUE) &&
	    (pp->pv_type != PROP_VAL_SIMPLE ||
	    (prop_id = pp->pv_simple) == NULL)) {
		zerr(gettext("A %s value was expected here."),
		    pvt_to_str(PROP_VAL_SIMPLE));
		saw_error = TRUE;
		return;
	}
	if (prop_type == PT_UNKNOWN) {
		long_usage(CMD_SET, TRUE);
		return;
	}

	if (initialize(TRUE) != Z_OK)
		return;

	switch (res_type) {
	case RT_ZONEPATH:
		if (zone_get_state(zone, &state_num) == Z_OK &&
		    state_num >= ZONE_STATE_INSTALLED) {
			zerr(gettext("Zone %s already installed; %s %s not "
			    "allowed."), zone, cmd_to_str(CMD_SET),
			    rt_to_str(RT_ZONEPATH));
			return;
		}
		if (validate_zonepath_syntax(prop_id) != Z_OK) {
			saw_error = TRUE;
			return;
		}
		if ((err = zonecfg_set_zonepath(handle, prop_id)) != Z_OK)
			zone_perror(zone, err, TRUE);
		else
			need_to_commit = TRUE;
		return;
	case RT_AUTOBOOT:
		if (strcmp(prop_id, "true") == 0) {
			autoboot = B_TRUE;
		} else if (strcmp(prop_id, "false") == 0) {
			autoboot = B_FALSE;
		} else {
			zerr(gettext("%s value must be '%s' or '%s'."),
			    pt_to_str(PT_AUTOBOOT), "true", "false");
			saw_error = TRUE;
			return;
		}
		if ((err = zonecfg_set_autoboot(handle, autoboot)) != Z_OK)
			zone_perror(zone, err, TRUE);
		else
			need_to_commit = TRUE;
		return;
	case RT_POOL:
		if ((err = zonecfg_set_pool(handle, prop_id)) != Z_OK)
			zone_perror(zone, err, TRUE);
		else
			need_to_commit = TRUE;
		return;
	case RT_FS:
		switch (prop_type) {
		case PT_DIR:
			(void) strlcpy(in_progress_fstab.zone_fs_dir, prop_id,
			    sizeof (in_progress_fstab.zone_fs_dir));
			return;
		case PT_SPECIAL:
			(void) strlcpy(in_progress_fstab.zone_fs_special,
			    prop_id,
			    sizeof (in_progress_fstab.zone_fs_special));
			return;
		case PT_RAW:
			(void) strlcpy(in_progress_fstab.zone_fs_raw,
			    prop_id, sizeof (in_progress_fstab.zone_fs_raw));
			return;
		case PT_TYPE:
			if (!valid_fs_type(prop_id)) {
				zerr(gettext("\"%s\" is not a valid %s."),
				    prop_id, pt_to_str(PT_TYPE));
				saw_error = TRUE;
				return;
			}
			(void) strlcpy(in_progress_fstab.zone_fs_type, prop_id,
			    sizeof (in_progress_fstab.zone_fs_type));
			return;
		case PT_OPTIONS:
			if (pp->pv_type != PROP_VAL_SIMPLE &&
			    pp->pv_type != PROP_VAL_LIST) {
				zerr(gettext("A %s or %s value was expected "
				    "here."), pvt_to_str(PROP_VAL_SIMPLE),
				    pvt_to_str(PROP_VAL_LIST));
				saw_error = TRUE;
				return;
			}
			zonecfg_free_fs_option_list(
			    in_progress_fstab.zone_fs_options);
			in_progress_fstab.zone_fs_options = NULL;
			if (!(pp->pv_type == PROP_VAL_LIST &&
			    pp->pv_list == NULL))
				add_property(cmd);
			return;
		default:
			break;
		}
		zone_perror(pt_to_str(prop_type), Z_NO_PROPERTY_TYPE, TRUE);
		long_usage(CMD_SET, TRUE);
		usage(FALSE, HELP_PROPS);
		return;
	case RT_IPD:
		switch (prop_type) {
		case PT_DIR:
			(void) strlcpy(in_progress_ipdtab.zone_fs_dir, prop_id,
			    sizeof (in_progress_ipdtab.zone_fs_dir));
			return;
		default:
			break;
		}
		zone_perror(pt_to_str(prop_type), Z_NO_PROPERTY_TYPE, TRUE);
		long_usage(CMD_SET, TRUE);
		usage(FALSE, HELP_PROPS);
		return;
	case RT_NET:
		switch (prop_type) {
		case PT_ADDRESS:
			if (validate_net_address_syntax(prop_id) != Z_OK) {
				saw_error = TRUE;
				return;
			}
			(void) strlcpy(in_progress_nwiftab.zone_nwif_address,
			    prop_id,
			    sizeof (in_progress_nwiftab.zone_nwif_address));
			break;
		case PT_PHYSICAL:
			if (validate_net_physical_syntax(prop_id) != Z_OK) {
				saw_error = TRUE;
				return;
			}
			(void) strlcpy(in_progress_nwiftab.zone_nwif_physical,
			    prop_id,
			    sizeof (in_progress_nwiftab.zone_nwif_physical));
			break;
		default:
			zone_perror(pt_to_str(prop_type), Z_NO_PROPERTY_TYPE,
			    TRUE);
			long_usage(CMD_SET, TRUE);
			usage(FALSE, HELP_PROPS);
			return;
		}
		return;
	case RT_DEVICE:
		switch (prop_type) {
		case PT_MATCH:
			(void) strlcpy(in_progress_devtab.zone_dev_match,
			    prop_id,
			    sizeof (in_progress_devtab.zone_dev_match));
			break;
		default:
			zone_perror(pt_to_str(prop_type), Z_NO_PROPERTY_TYPE,
			    TRUE);
			long_usage(CMD_SET, TRUE);
			usage(FALSE, HELP_PROPS);
			return;
		}
		return;
	case RT_RCTL:
		switch (prop_type) {
		case PT_NAME:
			if (!zonecfg_valid_rctlname(prop_id)) {
				zerr(gettext("'%s' is not a valid zone %s "
				    "name."), prop_id, rt_to_str(RT_RCTL));
				return;
			}
			(void) strlcpy(in_progress_rctltab.zone_rctl_name,
			    prop_id,
			    sizeof (in_progress_rctltab.zone_rctl_name));
			break;
		case PT_VALUE:
			if (pp->pv_type != PROP_VAL_COMPLEX &&
			    pp->pv_type != PROP_VAL_LIST) {
				zerr(gettext("A %s or %s value was expected "
				    "here."), pvt_to_str(PROP_VAL_COMPLEX),
				    pvt_to_str(PROP_VAL_LIST));
				saw_error = TRUE;
				return;
			}
			zonecfg_free_rctl_value_list(
			    in_progress_rctltab.zone_rctl_valptr);
			in_progress_rctltab.zone_rctl_valptr = NULL;
			if (!(pp->pv_type == PROP_VAL_LIST &&
			    pp->pv_list == NULL))
				add_property(cmd);
			break;
		default:
			zone_perror(pt_to_str(prop_type), Z_NO_PROPERTY_TYPE,
			    TRUE);
			long_usage(CMD_SET, TRUE);
			usage(FALSE, HELP_PROPS);
			return;
		}
		return;
	case RT_ATTR:
		switch (prop_type) {
		case PT_NAME:
			(void) strlcpy(in_progress_attrtab.zone_attr_name,
			    prop_id,
			    sizeof (in_progress_attrtab.zone_attr_name));
			break;
		case PT_TYPE:
			(void) strlcpy(in_progress_attrtab.zone_attr_type,
			    prop_id,
			    sizeof (in_progress_attrtab.zone_attr_type));
			break;
		case PT_VALUE:
			(void) strlcpy(in_progress_attrtab.zone_attr_value,
			    prop_id,
			    sizeof (in_progress_attrtab.zone_attr_value));
			break;
		default:
			zone_perror(pt_to_str(prop_type), Z_NO_PROPERTY_TYPE,
			    TRUE);
			long_usage(CMD_SET, TRUE);
			usage(FALSE, HELP_PROPS);
			return;
		}
		return;
	default:
		zone_perror(rt_to_str(res_type), Z_NO_RESOURCE_TYPE, TRUE);
		long_usage(CMD_SET, TRUE);
		usage(FALSE, HELP_RESOURCES);
		return;
	}
}

static void
output_prop(FILE *fp, int pnum, char *pval, bool print_notspec)
{
	char *qstr;

	if (*pval != '\0') {
		qstr = quoteit(pval);
		(void) fprintf(fp, "\t%s: %s\n", pt_to_str(pnum), qstr);
		free(qstr);
	} else if (print_notspec)
		(void) fprintf(fp, "\t%s %s\n", pt_to_str(pnum),
		    gettext("not specified"));
}

static void
info_zonepath(zone_dochandle_t handle, FILE *fp)
{
	char zonepath[MAXPATHLEN];

	if (zonecfg_get_zonepath(handle, zonepath, sizeof (zonepath)) == Z_OK)
		(void) fprintf(fp, "%s: %s\n", pt_to_str(PT_ZONEPATH),
		    zonepath);
	else
		(void) fprintf(fp, "%s %s\n", pt_to_str(PT_ZONEPATH),
		    gettext("not specified"));
}

static void
info_autoboot(zone_dochandle_t handle, FILE *fp)
{
	boolean_t autoboot;
	int err;

	if ((err = zonecfg_get_autoboot(handle, &autoboot)) == Z_OK)
		(void) fprintf(fp, "%s: %s\n", pt_to_str(PT_AUTOBOOT),
		    autoboot ? "true" : "false");
	else
		zone_perror(zone, err, TRUE);
}

static void
info_pool(zone_dochandle_t handle, FILE *fp)
{
	char pool[MAXNAMELEN];
	int err;

	if ((err = zonecfg_get_pool(handle, pool, sizeof (pool))) == Z_OK)
		(void) fprintf(fp, "%s: %s\n", pt_to_str(PT_POOL), pool);
	else
		zone_perror(zone, err, TRUE);
}

static void
output_fs(FILE *fp, struct zone_fstab *fstab)
{
	zone_fsopt_t *this;

	(void) fprintf(fp, "%s:\n", rt_to_str(RT_FS));
	output_prop(fp, PT_DIR, fstab->zone_fs_dir, B_TRUE);
	output_prop(fp, PT_SPECIAL, fstab->zone_fs_special, B_TRUE);
	output_prop(fp, PT_RAW, fstab->zone_fs_raw, B_TRUE);
	output_prop(fp, PT_TYPE, fstab->zone_fs_type, B_TRUE);
	(void) fprintf(fp, "\t%s: [", pt_to_str(PT_OPTIONS));
	for (this = fstab->zone_fs_options; this != NULL;
	    this = this->zone_fsopt_next) {
		if (strchr(this->zone_fsopt_opt, '='))
			(void) fprintf(fp, "\"%s\"", this->zone_fsopt_opt);
		else
			(void) fprintf(fp, "%s", this->zone_fsopt_opt);
		if (this->zone_fsopt_next != NULL)
			(void) fprintf(fp, ",");
	}
	(void) fprintf(fp, "]\n");
}

static void
output_ipd(FILE *fp, struct zone_fstab *ipdtab)
{
	(void) fprintf(fp, "%s:\n", rt_to_str(RT_IPD));
	output_prop(fp, PT_DIR, ipdtab->zone_fs_dir, B_TRUE);
}

static void
info_fs(zone_dochandle_t handle, FILE *fp, cmd_t *cmd)
{
	struct zone_fstab lookup, user;
	bool output = FALSE;

	if (zonecfg_setfsent(handle) != Z_OK)
		return;
	while (zonecfg_getfsent(handle, &lookup) == Z_OK) {
		if (cmd->cmd_prop_nv_pairs == 0) {
			output_fs(fp, &lookup);
			goto loopend;
		}
		if (fill_in_fstab(cmd, &user, TRUE) != Z_OK)
			goto loopend;
		if (strlen(user.zone_fs_dir) > 0 &&
		    strcmp(user.zone_fs_dir, lookup.zone_fs_dir) != 0)
			goto loopend;	/* no match */
		if (strlen(user.zone_fs_special) > 0 &&
		    strcmp(user.zone_fs_special, lookup.zone_fs_special) != 0)
			goto loopend;	/* no match */
		if (strlen(user.zone_fs_type) > 0 &&
		    strcmp(user.zone_fs_type, lookup.zone_fs_type) != 0)
			goto loopend;	/* no match */
		output_fs(fp, &lookup);
		output = TRUE;
loopend:
		zonecfg_free_fs_option_list(lookup.zone_fs_options);
	}
	(void) zonecfg_endfsent(handle);
	/*
	 * If a property n/v pair was specified, warn the user if there was
	 * nothing to output.
	 */
	if (!output && cmd->cmd_prop_nv_pairs > 0)
		(void) printf(gettext("No such %s resource.\n"),
		    rt_to_str(RT_FS));
}

static void
info_ipd(zone_dochandle_t handle, FILE *fp, cmd_t *cmd)
{
	struct zone_fstab lookup, user;
	bool output = FALSE;

	if (zonecfg_setipdent(handle) != Z_OK)
		return;
	while (zonecfg_getipdent(handle, &lookup) == Z_OK) {
		if (cmd->cmd_prop_nv_pairs == 0) {
			output_ipd(fp, &lookup);
			continue;
		}
		if (fill_in_ipdtab(cmd, &user, TRUE) != Z_OK)
			continue;
		if (strlen(user.zone_fs_dir) > 0 &&
		    strcmp(user.zone_fs_dir, lookup.zone_fs_dir) != 0)
			continue;	/* no match */
		output_ipd(fp, &lookup);
		output = TRUE;
	}
	(void) zonecfg_endipdent(handle);
	/*
	 * If a property n/v pair was specified, warn the user if there was
	 * nothing to output.
	 */
	if (!output && cmd->cmd_prop_nv_pairs > 0)
		(void) printf(gettext("No such %s resource.\n"),
		    rt_to_str(RT_IPD));
}

static void
output_net(FILE *fp, struct zone_nwiftab *nwiftab)
{
	(void) fprintf(fp, "%s:\n", rt_to_str(RT_NET));
	output_prop(fp, PT_ADDRESS, nwiftab->zone_nwif_address, B_TRUE);
	output_prop(fp, PT_PHYSICAL, nwiftab->zone_nwif_physical, B_TRUE);
}

static void
info_net(zone_dochandle_t handle, FILE *fp, cmd_t *cmd)
{
	struct zone_nwiftab lookup, user;
	bool output = FALSE;

	if (zonecfg_setnwifent(handle) != Z_OK)
		return;
	while (zonecfg_getnwifent(handle, &lookup) == Z_OK) {
		if (cmd->cmd_prop_nv_pairs == 0) {
			output_net(fp, &lookup);
			continue;
		}
		if (fill_in_nwiftab(cmd, &user, TRUE) != Z_OK)
			continue;
		if (strlen(user.zone_nwif_physical) > 0 &&
		    strcmp(user.zone_nwif_physical,
		    lookup.zone_nwif_physical) != 0)
			continue;	/* no match */
		if (strlen(user.zone_nwif_address) > 0 &&
		    !zonecfg_same_net_address(user.zone_nwif_address,
		    lookup.zone_nwif_address))
			continue;	/* no match */
		output_net(fp, &lookup);
		output = TRUE;
	}
	(void) zonecfg_endnwifent(handle);
	/*
	 * If a property n/v pair was specified, warn the user if there was
	 * nothing to output.
	 */
	if (!output && cmd->cmd_prop_nv_pairs > 0)
		(void) printf(gettext("No such %s resource.\n"),
		    rt_to_str(RT_NET));
}

static void
output_dev(FILE *fp, struct zone_devtab *devtab)
{
	(void) fprintf(fp, "%s\n", rt_to_str(RT_DEVICE));
	output_prop(fp, PT_MATCH, devtab->zone_dev_match, B_TRUE);
}

static void
info_dev(zone_dochandle_t handle, FILE *fp, cmd_t *cmd)
{
	struct zone_devtab lookup, user;
	bool output = FALSE;

	if (zonecfg_setdevent(handle) != Z_OK)
		return;
	while (zonecfg_getdevent(handle, &lookup) == Z_OK) {
		if (cmd->cmd_prop_nv_pairs == 0) {
			output_dev(fp, &lookup);
			continue;
		}
		if (fill_in_devtab(cmd, &user, TRUE) != Z_OK)
			continue;
		if (strlen(user.zone_dev_match) > 0 &&
		    strcmp(user.zone_dev_match, lookup.zone_dev_match) != 0)
			continue;	/* no match */
		output_dev(fp, &lookup);
		output = TRUE;
	}
	(void) zonecfg_enddevent(handle);
	/*
	 * If a property n/v pair was specified, warn the user if there was
	 * nothing to output.
	 */
	if (!output && cmd->cmd_prop_nv_pairs > 0)
		(void) printf(gettext("No such %s resource.\n"),
		    rt_to_str(RT_DEVICE));
}

static void
output_rctl(FILE *fp, struct zone_rctltab *rctltab)
{
	struct zone_rctlvaltab *valptr;

	(void) fprintf(fp, "%s:\n", rt_to_str(RT_RCTL));
	output_prop(fp, PT_NAME, rctltab->zone_rctl_name, B_TRUE);
	for (valptr = rctltab->zone_rctl_valptr; valptr != NULL;
	    valptr = valptr->zone_rctlval_next) {
		fprintf(fp, "\t%s: (%s=%s,%s=%s,%s=%s)\n",
		    pt_to_str(PT_VALUE),
		    pt_to_str(PT_PRIV), valptr->zone_rctlval_priv,
		    pt_to_str(PT_LIMIT), valptr->zone_rctlval_limit,
		    pt_to_str(PT_ACTION), valptr->zone_rctlval_action);
	}
}

static void
info_rctl(zone_dochandle_t handle, FILE *fp, cmd_t *cmd)
{
	struct zone_rctltab lookup, user;
	bool output = FALSE;

	if (zonecfg_setrctlent(handle) != Z_OK)
		return;
	while (zonecfg_getrctlent(handle, &lookup) == Z_OK) {
		if (cmd->cmd_prop_nv_pairs == 0) {
			output_rctl(fp, &lookup);
		} else if (fill_in_rctltab(cmd, &user, TRUE) == Z_OK &&
		    (strlen(user.zone_rctl_name) == 0 ||
		    strcmp(user.zone_rctl_name, lookup.zone_rctl_name) == 0)) {
			output_rctl(fp, &lookup);
			output = TRUE;
		}
		zonecfg_free_rctl_value_list(lookup.zone_rctl_valptr);
	}
	(void) zonecfg_endrctlent(handle);
	/*
	 * If a property n/v pair was specified, warn the user if there was
	 * nothing to output.
	 */
	if (!output && cmd->cmd_prop_nv_pairs > 0)
		(void) printf(gettext("No such %s resource.\n"),
		    rt_to_str(RT_RCTL));
}

static void
output_attr(FILE *fp, struct zone_attrtab *attrtab)
{
	(void) fprintf(fp, "%s:\n", rt_to_str(RT_ATTR));
	output_prop(fp, PT_NAME, attrtab->zone_attr_name, B_TRUE);
	output_prop(fp, PT_TYPE, attrtab->zone_attr_type, B_TRUE);
	output_prop(fp, PT_VALUE, attrtab->zone_attr_value, B_TRUE);
}

static void
info_attr(zone_dochandle_t handle, FILE *fp, cmd_t *cmd)
{
	struct zone_attrtab lookup, user;
	bool output = FALSE;

	if (zonecfg_setattrent(handle) != Z_OK)
		return;
	while (zonecfg_getattrent(handle, &lookup) == Z_OK) {
		if (cmd->cmd_prop_nv_pairs == 0) {
			output_attr(fp, &lookup);
			continue;
		}
		if (fill_in_attrtab(cmd, &user, TRUE) != Z_OK)
			continue;
		if (strlen(user.zone_attr_name) > 0 &&
		    strcmp(user.zone_attr_name, lookup.zone_attr_name) != 0)
			continue;	/* no match */
		if (strlen(user.zone_attr_type) > 0 &&
		    strcmp(user.zone_attr_type, lookup.zone_attr_type) != 0)
			continue;	/* no match */
		if (strlen(user.zone_attr_value) > 0 &&
		    strcmp(user.zone_attr_value, lookup.zone_attr_value) != 0)
			continue;	/* no match */
		output_attr(fp, &lookup);
		output = TRUE;
	}
	(void) zonecfg_endattrent(handle);
	/*
	 * If a property n/v pair was specified, warn the user if there was
	 * nothing to output.
	 */
	if (!output && cmd->cmd_prop_nv_pairs > 0)
		(void) printf(gettext("No such %s resource.\n"),
		    rt_to_str(RT_ATTR));
}

void
info_func(cmd_t *cmd)
{
	FILE *fp = stdout;
	bool need_to_close = FALSE;
	char *pager;

	assert(cmd != NULL);

	if (initialize(TRUE) != Z_OK)
		return;

	/* don't page error output */
	if (interactive_mode) {
		if ((pager = getenv("PAGER")) == NULL)
			pager = PAGER;
		if ((fp = popen(pager, "w")) != NULL)
			need_to_close = TRUE;
		else
			fp = stdout;
		setbuf(fp, NULL);
	}

	if (!global_scope) {
		switch (resource_scope) {
		case RT_FS:
			output_fs(fp, &in_progress_fstab);
			break;
		case RT_IPD:
			output_ipd(fp, &in_progress_ipdtab);
			break;
		case RT_NET:
			output_net(fp, &in_progress_nwiftab);
			break;
		case RT_DEVICE:
			output_dev(fp, &in_progress_devtab);
			break;
		case RT_RCTL:
			output_rctl(fp, &in_progress_rctltab);
			break;
		case RT_ATTR:
			output_attr(fp, &in_progress_attrtab);
			break;
		}
		goto cleanup;
	}

	switch (cmd->cmd_res_type) {
	case RT_UNKNOWN:
		info_zonepath(handle, fp);
		info_autoboot(handle, fp);
		info_pool(handle, fp);
		info_ipd(handle, fp, cmd);
		info_fs(handle, fp, cmd);
		info_net(handle, fp, cmd);
		info_dev(handle, fp, cmd);
		info_rctl(handle, fp, cmd);
		info_attr(handle, fp, cmd);
		break;
	case RT_ZONEPATH:
		info_zonepath(handle, fp);
		break;
	case RT_AUTOBOOT:
		info_autoboot(handle, fp);
		break;
	case RT_POOL:
		info_pool(handle, fp);
		break;
	case RT_FS:
		info_fs(handle, fp, cmd);
		break;
	case RT_IPD:
		info_ipd(handle, fp, cmd);
		break;
	case RT_NET:
		info_net(handle, fp, cmd);
		break;
	case RT_DEVICE:
		info_dev(handle, fp, cmd);
		break;
	case RT_RCTL:
		info_rctl(handle, fp, cmd);
		break;
	case RT_ATTR:
		info_attr(handle, fp, cmd);
		break;
	default:
		zone_perror(rt_to_str(cmd->cmd_res_type), Z_NO_RESOURCE_TYPE,
		    TRUE);
	}

cleanup:
	if (need_to_close)
		(void) pclose(fp);
}

static int
save_it(char *zonepath)
{
	int err;

	if (new_zone) {
		err = zonecfg_add_index(zone, zonepath);
		if (err != Z_OK) {
			zone_perror(zone, err, TRUE);
			return (err);
		}
		new_zone = FALSE;
	}
	if ((err = zonecfg_save(handle)) == Z_OK)
		need_to_commit = FALSE;
	return (err);
}

/*
 * See the DTD for which attributes are required for which resources.
 *
 * This function can be called by commit_func(), which needs to save things,
 * in addition to the general call from parse_and_run(), which doesn't need
 * things saved.  Since the parameters are standardized, we distinguish by
 * having commit_func() call here with cmd->cmd_arg set to "save" to indicate
 * that a save is needed.
 */
void
verify_func(cmd_t *cmd)
{
	struct zone_nwiftab nwiftab;
	struct zone_fstab fstab;
	struct zone_attrtab attrtab;
	struct zone_rctltab rctltab;
	char zonepath[MAXPATHLEN];
	int err, ret_val = Z_OK, arg;
	bool save = FALSE;

	optind = 0;
	if ((arg = getopt(cmd->cmd_argc, cmd->cmd_argv, "?")) != EOF) {
		switch (arg) {
		case '?':
			longer_usage(CMD_VERIFY);
			return;
		default:
			short_usage(CMD_VERIFY);
			return;
		}
	}
	if (optind > cmd->cmd_argc) {
		short_usage(CMD_VERIFY);
		return;
	}

	if (zone_is_read_only(CMD_VERIFY))
		return;

	assert(cmd != NULL);

	if (cmd->cmd_argc > 0 && (strcmp(cmd->cmd_argv[0], "save") == 0))
		save = TRUE;
	if (initialize(TRUE) != Z_OK)
		return;

	if (zonecfg_get_zonepath(handle, zonepath, sizeof (zonepath)) != Z_OK) {
		zerr("%s %s", pt_to_str(PT_ZONEPATH), gettext("not specified"));
		ret_val = Z_REQD_RESOURCE_MISSING;
		saw_error = TRUE;
	}
	if (strlen(zonepath) == 0) {
		zerr("%s %s", pt_to_str(PT_ZONEPATH),
		    gettext("cannot be empty."));
		ret_val = Z_REQD_RESOURCE_MISSING;
		saw_error = TRUE;
	}

	if ((err = zonecfg_setipdent(handle)) != Z_OK) {
		zone_perror(zone, err, TRUE);
		return;
	}
	while (zonecfg_getipdent(handle, &fstab) == Z_OK) {
		if (strlen(fstab.zone_fs_dir) == 0) {
			zerr("%s: %s %s", rt_to_str(RT_IPD), pt_to_str(PT_DIR),
			    gettext("not specified"));
			saw_error = TRUE;
			if (ret_val == Z_OK)
				ret_val = Z_REQD_PROPERTY_MISSING;
		}
	}
	(void) zonecfg_endipdent(handle);

	if ((err = zonecfg_setfsent(handle)) != Z_OK) {
		zone_perror(zone, err, TRUE);
		return;
	}
	while (zonecfg_getfsent(handle, &fstab) == Z_OK) {
		if (strlen(fstab.zone_fs_dir) == 0) {
			zerr("%s: %s %s", rt_to_str(RT_FS), pt_to_str(PT_DIR),
			    gettext("not specified"));
			saw_error = TRUE;
			if (ret_val == Z_OK)
				ret_val = Z_REQD_PROPERTY_MISSING;
		}
		if (strlen(fstab.zone_fs_special) == 0) {
			zerr("%s: %s %s", rt_to_str(RT_FS),
			    pt_to_str(PT_SPECIAL), gettext("not specified"));
			saw_error = TRUE;
			if (ret_val == Z_OK)
				ret_val = Z_REQD_PROPERTY_MISSING;
		}
		if (strlen(fstab.zone_fs_type) == 0) {
			zerr("%s: %s %s", rt_to_str(RT_FS), pt_to_str(PT_TYPE),
			    gettext("not specified"));
			saw_error = TRUE;
			if (ret_val == Z_OK)
				ret_val = Z_REQD_PROPERTY_MISSING;
		}
		zonecfg_free_fs_option_list(fstab.zone_fs_options);
	}
	(void) zonecfg_endfsent(handle);

	if ((err = zonecfg_setnwifent(handle)) != Z_OK) {
		zone_perror(zone, err, TRUE);
		return;
	}
	while (zonecfg_getnwifent(handle, &nwiftab) == Z_OK) {
		if (strlen(nwiftab.zone_nwif_address) == 0) {
			zerr("%s: %s %s", rt_to_str(RT_NET),
			    pt_to_str(PT_ADDRESS), gettext("not specified"));
			saw_error = TRUE;
			if (ret_val == Z_OK)
				ret_val = Z_REQD_PROPERTY_MISSING;
		}
		if (strlen(nwiftab.zone_nwif_physical) == 0) {
			zerr("%s: %s %s", rt_to_str(RT_NET),
			    pt_to_str(PT_PHYSICAL), gettext("not specified"));
			saw_error = TRUE;
			if (ret_val == Z_OK)
				ret_val = Z_REQD_PROPERTY_MISSING;
		}
	}
	(void) zonecfg_endnwifent(handle);

	if ((err = zonecfg_setrctlent(handle)) != Z_OK) {
		zone_perror(zone, err, TRUE);
		return;
	}
	while (zonecfg_getrctlent(handle, &rctltab) == Z_OK) {
		if (strlen(rctltab.zone_rctl_name) == 0) {
			zerr("%s: %s %s", rt_to_str(RT_RCTL),
			    pt_to_str(PT_NAME), gettext("not specified"));
			saw_error = TRUE;
			if (ret_val == Z_OK)
				ret_val = Z_REQD_PROPERTY_MISSING;
		}
		if (rctltab.zone_rctl_valptr == NULL) {
			zerr(gettext("%s: no %s specified"),
			    rt_to_str(RT_RCTL), pt_to_str(PT_VALUE));
			saw_error = TRUE;
			if (ret_val == Z_OK)
				ret_val = Z_REQD_PROPERTY_MISSING;
		} else {
			zonecfg_free_rctl_value_list(rctltab.zone_rctl_valptr);
		}
	}
	(void) zonecfg_endrctlent(handle);

	if ((err = zonecfg_setattrent(handle)) != Z_OK) {
		zone_perror(zone, err, TRUE);
		return;
	}
	while (zonecfg_getattrent(handle, &attrtab) == Z_OK) {
		if (strlen(attrtab.zone_attr_name) == 0) {
			zerr("%s: %s %s", rt_to_str(RT_ATTR),
			    pt_to_str(PT_NAME), gettext("not specified"));
			saw_error = TRUE;
			if (ret_val == Z_OK)
				ret_val = Z_REQD_PROPERTY_MISSING;
		}
		if (strlen(attrtab.zone_attr_type) == 0) {
			zerr("%s: %s %s", rt_to_str(RT_ATTR),
			    pt_to_str(PT_TYPE), gettext("not specified"));
			saw_error = TRUE;
			if (ret_val == Z_OK)
				ret_val = Z_REQD_PROPERTY_MISSING;
		}
		if (strlen(attrtab.zone_attr_value) == 0) {
			zerr("%s: %s %s", rt_to_str(RT_ATTR),
			    pt_to_str(PT_VALUE), gettext("not specified"));
			saw_error = TRUE;
			if (ret_val == Z_OK)
				ret_val = Z_REQD_PROPERTY_MISSING;
		}
	}
	(void) zonecfg_endattrent(handle);

	if (!global_scope) {
		zerr(gettext("resource specification incomplete"));
		saw_error = TRUE;
		if (ret_val == Z_OK)
			ret_val = Z_INSUFFICIENT_SPEC;
	}

	if (save) {
		if (ret_val == Z_OK)
			ret_val = save_it(zonepath);
		else
			zerr("zone %s %s", zone, gettext("failed to verify"));
	}
	if (ret_val != Z_OK)
		zone_perror(zone, ret_val, TRUE);
}

void
cancel_func(cmd_t *cmd)
{
	int arg;

	assert(cmd != NULL);

	optind = 0;
	if ((arg = getopt(cmd->cmd_argc, cmd->cmd_argv, "?")) != EOF) {
		switch (arg) {
		case '?':
			longer_usage(CMD_CANCEL);
			return;
		default:
			short_usage(CMD_CANCEL);
			return;
		}
	}
	if (optind != cmd->cmd_argc) {
		short_usage(CMD_CANCEL);
		return;
	}

	if (global_scope)
		scope_usage(CMD_CANCEL);
	global_scope = TRUE;
	zonecfg_free_fs_option_list(in_progress_fstab.zone_fs_options);
	bzero(&in_progress_fstab, sizeof (in_progress_fstab));
	bzero(&in_progress_nwiftab, sizeof (in_progress_nwiftab));
	bzero(&in_progress_devtab, sizeof (in_progress_devtab));
	zonecfg_free_rctl_value_list(in_progress_rctltab.zone_rctl_valptr);
	bzero(&in_progress_rctltab, sizeof (in_progress_rctltab));
	bzero(&in_progress_attrtab, sizeof (in_progress_attrtab));
}

static int
validate_attr_name(char *name)
{
	int i;

	if (!isalnum(name[0])) {
		zerr(gettext("Invalid %s %s %s: must start with an alpha-"
		    "numeric character."), rt_to_str(RT_ATTR),
		    pt_to_str(PT_NAME), name);
		return (Z_INVAL);
	}
	for (i = 1; name[i]; i++)
		if (!isalnum(name[i]) && name[i] != '-' && name[i] != '.') {
			zerr(gettext("Invalid %s %s %s: can only contain "
			    "alpha-numeric characters, plus '-' and '.'."),
			    rt_to_str(RT_ATTR), pt_to_str(PT_NAME), name);
			return (Z_INVAL);
		}
	return (Z_OK);
}

static int
validate_attr_type_val(struct zone_attrtab *attrtab)
{
	boolean_t boolval;
	int64_t intval;
	char strval[MAXNAMELEN];
	uint64_t uintval;

	if (strcmp(attrtab->zone_attr_type, "boolean") == 0) {
		if (zonecfg_get_attr_boolean(attrtab, &boolval) == Z_OK)
			return (Z_OK);
		zerr(gettext("invalid %s value for %s=%s"),
		    rt_to_str(RT_ATTR), pt_to_str(PT_TYPE), "boolean");
		return (Z_ERR);
	}

	if (strcmp(attrtab->zone_attr_type, "int") == 0) {
		if (zonecfg_get_attr_int(attrtab, &intval) == Z_OK)
			return (Z_OK);
		zerr(gettext("invalid %s value for %s=%s"),
		    rt_to_str(RT_ATTR), pt_to_str(PT_TYPE), "int");
		return (Z_ERR);
	}

	if (strcmp(attrtab->zone_attr_type, "string") == 0) {
		if (zonecfg_get_attr_string(attrtab, strval,
		    sizeof (strval)) == Z_OK)
			return (Z_OK);
		zerr(gettext("invalid %s value for %s=%s"),
		    rt_to_str(RT_ATTR), pt_to_str(PT_TYPE), "string");
		return (Z_ERR);
	}

	if (strcmp(attrtab->zone_attr_type, "uint") == 0) {
		if (zonecfg_get_attr_uint(attrtab, &uintval) == Z_OK)
			return (Z_OK);
		zerr(gettext("invalid %s value for %s=%s"),
		    rt_to_str(RT_ATTR), pt_to_str(PT_TYPE), "uint");
		return (Z_ERR);
	}

	zerr(gettext("invalid %s %s '%s'"), rt_to_str(RT_ATTR),
	    pt_to_str(PT_TYPE), attrtab->zone_attr_type);
	return (Z_ERR);
}

void
end_func(cmd_t *cmd)
{
	bool validation_failed = FALSE;
	struct zone_fstab tmp_fstab;
	struct zone_nwiftab tmp_nwiftab;
	struct zone_devtab tmp_devtab;
	struct zone_rctltab tmp_rctltab;
	struct zone_attrtab tmp_attrtab;
	int err, arg;

	assert(cmd != NULL);

	optind = 0;
	if ((arg = getopt(cmd->cmd_argc, cmd->cmd_argv, "?")) != EOF) {
		switch (arg) {
		case '?':
			longer_usage(CMD_END);
			return;
		default:
			short_usage(CMD_END);
			return;
		}
	}
	if (optind != cmd->cmd_argc) {
		short_usage(CMD_END);
		return;
	}

	if (global_scope) {
		scope_usage(CMD_END);
		return;
	}

	assert(end_op == CMD_ADD || end_op == CMD_SELECT);

	switch (resource_scope) {
	case RT_FS:
		/* First make sure everything was filled in. */
		if (strlen(in_progress_fstab.zone_fs_dir) == 0) {
			zerr("dir %s", gettext("not specified"));
			saw_error = TRUE;
			validation_failed = TRUE;
		} else if (in_progress_fstab.zone_fs_dir[0] != '/') {
			zerr("dir %s %s", in_progress_fstab.zone_fs_dir,
			    gettext("is not an absolute path."));
			saw_error = TRUE;
			validation_failed = TRUE;
		}
		if (strlen(in_progress_fstab.zone_fs_special) == 0) {
			zerr("special %s", gettext("not specified"));
			saw_error = TRUE;
			validation_failed = TRUE;
		}
		if (in_progress_fstab.zone_fs_raw[0] != '\0' &&
		    in_progress_fstab.zone_fs_raw[0] != '/') {
			zerr("raw device %s %s",
			    in_progress_fstab.zone_fs_raw,
			    gettext("is not an absolute path."));
			saw_error = TRUE;
			validation_failed = TRUE;
		}
		if (strlen(in_progress_fstab.zone_fs_type) == 0) {
			zerr("type %s", gettext("not specified"));
			saw_error = TRUE;
			validation_failed = TRUE;
		}
		if (validation_failed)
			return;
		if (end_op == CMD_ADD) {
			/* Make sure there isn't already one like this. */
			bzero(&tmp_fstab, sizeof (tmp_fstab));
			(void) strlcpy(tmp_fstab.zone_fs_dir,
			    in_progress_fstab.zone_fs_dir,
			    sizeof (tmp_fstab.zone_fs_dir));
			err = zonecfg_lookup_filesystem(handle, &tmp_fstab);
			zonecfg_free_fs_option_list(tmp_fstab.zone_fs_options);
			if (err == Z_OK) {
				zerr(gettext("A %s resource "
				    "with the %s '%s' already exists."),
				    rt_to_str(RT_FS), pt_to_str(PT_DIR),
				    in_progress_fstab.zone_fs_dir);
				saw_error = TRUE;
				return;
			}
			err = zonecfg_add_filesystem(handle,
			    &in_progress_fstab);
		} else {
			err = zonecfg_modify_filesystem(handle, &old_fstab,
			    &in_progress_fstab);
		}
		zonecfg_free_fs_option_list(in_progress_fstab.zone_fs_options);
		in_progress_fstab.zone_fs_options = NULL;
		break;
	case RT_IPD:
		/* First make sure everything was filled in. */
		if (strlen(in_progress_ipdtab.zone_fs_dir) == 0) {
			zerr("dir %s", gettext("not specified"));
			saw_error = TRUE;
			validation_failed = TRUE;
		} else if (in_progress_ipdtab.zone_fs_dir[0] != '/') {
			zerr("dir %s %s", in_progress_ipdtab.zone_fs_dir,
			    gettext("is not an absolute path."));
			saw_error = TRUE;
			validation_failed = TRUE;
		}
		if (validation_failed)
			return;
		if (end_op == CMD_ADD) {
			/* Make sure there isn't already one like this. */
			bzero(&tmp_fstab, sizeof (tmp_fstab));
			(void) strlcpy(tmp_fstab.zone_fs_dir,
			    in_progress_ipdtab.zone_fs_dir,
			    sizeof (tmp_fstab.zone_fs_dir));
			err = zonecfg_lookup_ipd(handle, &tmp_fstab);
			if (err == Z_OK) {
				zerr(gettext("An %s resource "
				    "with the %s '%s' already exists."),
				    rt_to_str(RT_IPD), pt_to_str(PT_DIR),
				    in_progress_ipdtab.zone_fs_dir);
				saw_error = TRUE;
				return;
			}
			err = zonecfg_add_ipd(handle, &in_progress_ipdtab);
		} else {
			err = zonecfg_modify_ipd(handle, &old_ipdtab,
			    &in_progress_ipdtab);
		}
		break;
	case RT_NET:
		/* First make sure everything was filled in. */
		if (strlen(in_progress_nwiftab.zone_nwif_physical) == 0) {
			zerr("physical %s", gettext("not specified"));
			saw_error = TRUE;
			validation_failed = TRUE;
		}
		if (strlen(in_progress_nwiftab.zone_nwif_address) == 0) {
			zerr("address %s", gettext("not specified"));
			saw_error = TRUE;
			validation_failed = TRUE;
		}
		if (validation_failed)
			return;
		if (end_op == CMD_ADD) {
			/* Make sure there isn't already one like this. */
			bzero(&tmp_nwiftab, sizeof (tmp_nwiftab));
			(void) strlcpy(tmp_nwiftab.zone_nwif_address,
			    in_progress_nwiftab.zone_nwif_address,
			    sizeof (tmp_nwiftab.zone_nwif_address));
			if (zonecfg_lookup_nwif(handle, &tmp_nwiftab) == Z_OK) {
				zerr(gettext("A %s resource "
				    "with the %s '%s' already exists."),
				    rt_to_str(RT_NET), pt_to_str(PT_ADDRESS),
				    in_progress_nwiftab.zone_nwif_address);
				saw_error = TRUE;
				return;
			}
			err = zonecfg_add_nwif(handle, &in_progress_nwiftab);
		} else {
			err = zonecfg_modify_nwif(handle, &old_nwiftab,
			    &in_progress_nwiftab);
		}
		break;
	case RT_DEVICE:
		/* First make sure everything was filled in. */
		if (strlen(in_progress_devtab.zone_dev_match) == 0) {
			zerr("match %s", gettext("not specified"));
			saw_error = TRUE;
			validation_failed = TRUE;
		}
		if (validation_failed)
			return;
		if (end_op == CMD_ADD) {
			/* Make sure there isn't already one like this. */
			(void) strlcpy(tmp_devtab.zone_dev_match,
			    in_progress_devtab.zone_dev_match,
			    sizeof (tmp_devtab.zone_dev_match));
			if (zonecfg_lookup_dev(handle, &tmp_devtab) == Z_OK) {
				zerr(gettext("A %s resource with the %s '%s' "
				    "already exists."), rt_to_str(RT_DEVICE),
				    pt_to_str(PT_MATCH),
				    in_progress_devtab.zone_dev_match);
				saw_error = TRUE;
				return;
			}
			err = zonecfg_add_dev(handle, &in_progress_devtab);
		} else {
			err = zonecfg_modify_dev(handle, &old_devtab,
			    &in_progress_devtab);
		}
		break;
	case RT_RCTL:
		/* First make sure everything was filled in. */
		if (strlen(in_progress_rctltab.zone_rctl_name) == 0) {
			zerr("name %s", gettext("not specified"));
			saw_error = TRUE;
			validation_failed = TRUE;
		}
		if (in_progress_rctltab.zone_rctl_valptr == NULL) {
			zerr(gettext("no %s specified"), pt_to_str(PT_VALUE));
			saw_error = TRUE;
			validation_failed = TRUE;
		}
		if (validation_failed)
			return;
		if (end_op == CMD_ADD) {
			/* Make sure there isn't already one like this. */
			(void) strlcpy(tmp_rctltab.zone_rctl_name,
			    in_progress_rctltab.zone_rctl_name,
			    sizeof (tmp_rctltab.zone_rctl_name));
			tmp_rctltab.zone_rctl_valptr = NULL;
			err = zonecfg_lookup_rctl(handle, &tmp_rctltab);
			zonecfg_free_rctl_value_list(
			    tmp_rctltab.zone_rctl_valptr);
			if (err == Z_OK) {
				zerr(gettext("A %s resource "
				    "with the %s '%s' already exists."),
				    rt_to_str(RT_RCTL), pt_to_str(PT_NAME),
				    in_progress_rctltab.zone_rctl_name);
				saw_error = TRUE;
				return;
			}
			err = zonecfg_add_rctl(handle, &in_progress_rctltab);
		} else {
			err = zonecfg_modify_rctl(handle, &old_rctltab,
			    &in_progress_rctltab);
		}
		if (err == Z_OK) {
			zonecfg_free_rctl_value_list(
			    in_progress_rctltab.zone_rctl_valptr);
			in_progress_rctltab.zone_rctl_valptr = NULL;
		}
		break;
	case RT_ATTR:
		/* First make sure everything was filled in. */
		if (strlen(in_progress_attrtab.zone_attr_name) == 0) {
			zerr("name %s", gettext("not specified"));
			saw_error = TRUE;
			validation_failed = TRUE;
		}
		if (strlen(in_progress_attrtab.zone_attr_type) == 0) {
			zerr("type %s", gettext("not specified"));
			saw_error = TRUE;
			validation_failed = TRUE;
		}
		if (strlen(in_progress_attrtab.zone_attr_value) == 0) {
			zerr("value %s", gettext("not specified"));
			saw_error = TRUE;
			validation_failed = TRUE;
		}
		if (validate_attr_name(in_progress_attrtab.zone_attr_name) !=
		    Z_OK) {
			saw_error = TRUE;
			validation_failed = TRUE;
		}
		if (validate_attr_type_val(&in_progress_attrtab) != Z_OK) {
			saw_error = TRUE;
			validation_failed = TRUE;
		}
		if (validation_failed)
			return;
		if (end_op == CMD_ADD) {
			/* Make sure there isn't already one like this. */
			bzero(&tmp_attrtab, sizeof (tmp_attrtab));
			(void) strlcpy(tmp_attrtab.zone_attr_name,
			    in_progress_attrtab.zone_attr_name,
			    sizeof (tmp_attrtab.zone_attr_name));
			if (zonecfg_lookup_attr(handle, &tmp_attrtab) == Z_OK) {
				zerr(gettext("An %s resource "
				    "with the %s '%s' already exists."),
				    rt_to_str(RT_ATTR), pt_to_str(PT_NAME),
				    in_progress_attrtab.zone_attr_name);
				saw_error = TRUE;
				return;
			}
			err = zonecfg_add_attr(handle, &in_progress_attrtab);
		} else {
			err = zonecfg_modify_attr(handle, &old_attrtab,
			    &in_progress_attrtab);
		}
		break;
	default:
		zone_perror(rt_to_str(resource_scope), Z_NO_RESOURCE_TYPE,
		    TRUE);
		saw_error = TRUE;
		return;
	}

	if (err != Z_OK) {
		zone_perror(zone, err, TRUE);
	} else {
		need_to_commit = TRUE;
		global_scope = TRUE;
		end_op = -1;
	}
}

void
commit_func(cmd_t *cmd)
{
	int arg;

	optind = 0;
	if ((arg = getopt(cmd->cmd_argc, cmd->cmd_argv, "?")) != EOF) {
		switch (arg) {
		case '?':
			longer_usage(CMD_COMMIT);
			return;
		default:
			short_usage(CMD_COMMIT);
			return;
		}
	}
	if (optind != cmd->cmd_argc) {
		short_usage(CMD_COMMIT);
		return;
	}

	if (zone_is_read_only(CMD_COMMIT))
		return;

	assert(cmd != NULL);

	cmd->cmd_argc = 1;
	/*
	 * cmd_arg normally comes from a strdup() in the lexer, and the
	 * whole cmd structure and its (char *) attributes are freed at
	 * the completion of each command, so the strdup() below is needed
	 * to match this and prevent a core dump from trying to free()
	 * something that can't be.
	 */
	if ((cmd->cmd_argv[0] = strdup("save")) == NULL) {
		zone_perror(zone, Z_NOMEM, TRUE);
		exit(Z_ERR);
	}
	cmd->cmd_argv[1] = NULL;
	verify_func(cmd);
}

void
revert_func(cmd_t *cmd)
{
	char line[128];	/* enough to ask a question */
	bool force = FALSE;
	int err, arg, answer;

	optind = 0;
	while ((arg = getopt(cmd->cmd_argc, cmd->cmd_argv, "?F")) != EOF) {
		switch (arg) {
		case '?':
			longer_usage(CMD_REVERT);
			return;
		case 'F':
			force = TRUE;
			break;
		default:
			short_usage(CMD_REVERT);
			return;
		}
	}
	if (optind != cmd->cmd_argc) {
		short_usage(CMD_REVERT);
		return;
	}

	if (zone_is_read_only(CMD_REVERT))
		return;

	if (zonecfg_check_handle(handle) != Z_OK) {
		zerr(gettext("No changes to revert."));
		saw_error = TRUE;
		return;
	}

	if (!force) {
		(void) snprintf(line, sizeof (line),
		    gettext("Are you sure you want to revert"));
		if ((answer = ask_yesno(FALSE, line)) == -1) {
			zerr(gettext("Input not from terminal and -F not "
			    "specified:\n%s command ignored, exiting."),
			    cmd_to_str(CMD_REVERT));
			exit(Z_ERR);
		}
		if (answer != 1)
			return;
	}

	/*
	 * Time for a new handle: finish the old one off first
	 * then get a new one properly to avoid leaks.
	 */
	zonecfg_fini_handle(handle);
	if ((handle = zonecfg_init_handle()) == NULL) {
		zone_perror(execname, Z_NOMEM, TRUE);
		exit(Z_ERR);
	}
	if ((err = zonecfg_get_handle(zone, handle)) != Z_OK) {
		saw_error = TRUE;
		got_handle = FALSE;
		if (err == Z_NO_ZONE)
			zerr(gettext("%s: no such saved zone to revert to."),
			    zone);
		else
			zone_perror(zone, err, TRUE);
	}
}

void
help_func(cmd_t *cmd)
{
	int i;

	assert(cmd != NULL);

	if (cmd->cmd_argc == 0) {
		usage(TRUE, global_scope ? HELP_SUBCMDS : HELP_RES_SCOPE);
		return;
	}
	if (strcmp(cmd->cmd_argv[0], "usage") == 0) {
		usage(TRUE, HELP_USAGE);
		return;
	}
	if (strcmp(cmd->cmd_argv[0], "commands") == 0) {
		usage(TRUE, HELP_SUBCMDS);
		return;
	}
	if (strcmp(cmd->cmd_argv[0], "syntax") == 0) {
		usage(TRUE, HELP_SYNTAX | HELP_RES_PROPS);
		return;
	}
	if (strcmp(cmd->cmd_argv[0], "-?") == 0) {
		longer_usage(CMD_HELP);
		return;
	}

	for (i = 0; i <= CMD_MAX; i++) {
		if (strcmp(cmd->cmd_argv[0], cmd_to_str(i)) == 0) {
			longer_usage(i);
			return;
		}
	}
	/* We do not use zerr() here because we do not want its extra \n. */
	(void) fprintf(stderr, gettext("Unknown help subject %s.  "),
	    cmd->cmd_argv[0]);
	usage(FALSE, HELP_META);
}

static int
string_to_yyin(char *string)
{
	if ((yyin = tmpfile()) == NULL) {
		zone_perror(execname, Z_TEMP_FILE, TRUE);
		return (Z_ERR);
	}
	if (fwrite(string, strlen(string), 1, yyin) != 1) {
		zone_perror(execname, Z_TEMP_FILE, TRUE);
		return (Z_ERR);
	}
	if (fseek(yyin, 0, SEEK_SET) != 0) {
		zone_perror(execname, Z_TEMP_FILE, TRUE);
		return (Z_ERR);
	}
	return (Z_OK);
}

/* This is the back-end helper function for read_input() below. */

static int
cleanup()
{
	int answer;
	cmd_t *cmd;

	if (!interactive_mode && !cmd_file_mode) {
		/*
		 * If we're not in interactive mode, and we're not in command
		 * file mode, then we must be in commands-from-the-command-line
		 * mode.  As such, we can't loop back and ask for more input.
		 * It was OK to prompt for such things as whether or not to
		 * really delete a zone in the command handler called from
		 * yyparse() above, but "really quit?" makes no sense in this
		 * context.  So disable prompting.
		 */
		ok_to_prompt = FALSE;
	}
	if (!global_scope) {
		if (!time_to_exit) {
			/*
			 * Just print a simple error message in the -1 case,
			 * since exit_func() already handles that case, and
			 * EOF means we are finished anyway.
			 */
			answer = ask_yesno(FALSE,
			    gettext("Resource incomplete; really quit"));
			if (answer == -1) {
				zerr(gettext("Resource incomplete."));
				return (Z_ERR);
			}
			if (answer != 1) {
				yyin = stdin;
				return (Z_REPEAT);
			}
		} else {
			saw_error = TRUE;
		}
	}
	/*
	 * Make sure we tried something and that the handle checks
	 * out, or we would get a false error trying to commit.
	 */
	if (need_to_commit && zonecfg_check_handle(handle) == Z_OK) {
		if ((cmd = alloc_cmd()) == NULL) {
			zone_perror(zone, Z_NOMEM, TRUE);
			return (Z_ERR);
		}
		cmd->cmd_argc = 0;
		cmd->cmd_argv[0] = NULL;
		commit_func(cmd);
		free_cmd(cmd);
		/*
		 * need_to_commit will get set back to FALSE if the
		 * configuration is saved successfully.
		 */
		if (need_to_commit) {
			if (force_exit) {
				zerr(gettext("Configuration not saved."));
				return (Z_ERR);
			}
			answer = ask_yesno(FALSE,
			    gettext("Configuration not saved; really quit"));
			if (answer == -1) {
				zerr(gettext("Configuration not saved."));
				return (Z_ERR);
			}
			if (answer != 1) {
				time_to_exit = FALSE;
				yyin = stdin;
				return (Z_REPEAT);
			}
		}
	}
	return ((need_to_commit || saw_error) ? Z_ERR : Z_OK);
}

/*
 * read_input() is the driver of this program.  It is a wrapper around
 * yyparse(), printing appropriate prompts when needed, checking for
 * exit conditions and reacting appropriately [the latter in its cleanup()
 * helper function].
 *
 * Like most zonecfg functions, it returns Z_OK or Z_ERR, *or* Z_REPEAT
 * so do_interactive() knows that we are not really done (i.e, we asked
 * the user if we should really quit and the user said no).
 */
static int
read_input()
{
	bool yyin_is_a_tty = isatty(fileno(yyin));
	/*
	 * The prompt is "e:z> " or "e:z:r> " where e is execname, z is zone
	 * and r is resource_scope: 5 is for the two ":"s + "> " + terminator.
	 */
	char prompt[MAXPATHLEN + ZONENAME_MAX + MAX_RT_STRLEN + 5], *line;

	/* yyin should have been set to the appropriate (FILE *) if not stdin */
	newline_terminated = TRUE;
	for (;;) {
		if (yyin_is_a_tty) {
			if (newline_terminated) {
				if (global_scope)
					(void) snprintf(prompt, sizeof (prompt),
					    "%s:%s> ", execname, zone);
				else
					(void) snprintf(prompt, sizeof (prompt),
					    "%s:%s:%s> ", execname, zone,
					    rt_to_str(resource_scope));
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
			(void) string_to_yyin(line);
			while (!feof(yyin))
				yyparse();
		} else {
			yyparse();
		}
		/* Bail out on an error in command file mode. */
		if (saw_error && cmd_file_mode && !interactive_mode)
			time_to_exit = TRUE;
		if (time_to_exit || (!yyin_is_a_tty && feof(yyin)))
			break;
	}
	return (cleanup());
}

/*
 * This function is used in the zonecfg-interactive-mode scenario: it just
 * calls read_input() until we are done.
 */

static int
do_interactive(void)
{
	int err;

	interactive_mode = TRUE;
	if (!read_only_mode) {
		/*
		 * Try to set things up proactively in interactive mode, so
		 * that if the zone in question does not exist yet, we can
		 * provide the user with a clue.
		 */
		(void) initialize(FALSE);
	}
	do
		err = read_input();
	while (err == Z_REPEAT);
	return (err);
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
	bool using_real_file = (strcmp(file, "-") != 0);

	if (using_real_file) {
		/*
		 * zerr() prints a line number in cmd_file_mode, which we do
		 * not want here, so temporarily unset it.
		 */
		cmd_file_mode = FALSE;
		if ((infile = fopen(file, "r")) == NULL) {
			zerr(gettext("could not open file %s: %s"),
			    file, strerror(errno));
			return (Z_ERR);
		}
		if ((err = fstat(fileno(infile), &statbuf)) != 0) {
			zerr(gettext("could not stat file %s: %s"),
			    file, strerror(errno));
			err = Z_ERR;
			goto done;
		}
		if (!S_ISREG(statbuf.st_mode)) {
			zerr(gettext("%s is not a regular file."), file);
			err = Z_ERR;
			goto done;
		}
		yyin = infile;
		cmd_file_mode = TRUE;
		ok_to_prompt = FALSE;
	} else {
		/*
		 * "-f -" is essentially the same as interactive mode,
		 * so treat it that way.
		 */
		interactive_mode = TRUE;
	}
	/* Z_REPEAT is for interactive mode; treat it like Z_ERR here. */
	if ((err = read_input()) == Z_REPEAT)
		err = Z_ERR;
done:
	if (using_real_file)
		(void) fclose(infile);
	return (err);
}

/*
 * Since yacc is based on reading from a (FILE *) whereas what we get from
 * the command line is in argv format, we need to convert when the user
 * gives us commands directly from the command line.  That is done here by
 * concatenating the argv list into a space-separated string, writing it
 * to a temp file, and rewinding the file so yyin can be set to it.  Then
 * we call read_input(), and only once, since prompting about whether to
 * continue or quit would make no sense in this context.
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
		zone_perror(execname, Z_NOMEM, TRUE);
		return (Z_ERR);
	}
	(void) strlcpy(command, argv[0], len);
	for (i = 1; i < argc; i++) {
		(void) strlcat(command, " ", len);
		(void) strlcat(command, argv[i], len);
	}
	(void) strlcat(command, "\n", len);
	err = string_to_yyin(command);
	free(command);
	if (err != Z_OK)
		return (err);
	while (!feof(yyin))
		yyparse();
	return (cleanup());
}

static char *
get_execbasename(char *execfullname)
{
	char *last_slash, *execbasename;

	/* guard against '/' at end of command invocation */
	for (;;) {
		last_slash = strrchr(execfullname, '/');
		if (last_slash == NULL) {
			execbasename = execfullname;
			break;
		} else {
			execbasename = last_slash + 1;
			if (*execbasename == '\0') {
				*last_slash = '\0';
				continue;
			}
			break;
		}
	}
	return (execbasename);
}

static void
validate_zone_name()
{
	regex_t reg;
	char *locale = NULL, locale_buf[MAXPATHLEN];

	if (strcmp(zone, GLOBAL_ZONENAME) == 0)
		goto err;

	/*
	 * The regex(5) functions below are locale-sensitive, so save the
	 * user's locale, then set it to "C" for the regex's, and restore
	 * it afterwards.
	 */
	if ((locale = setlocale(LC_ALL, NULL)) != NULL) {
		(void) strlcpy(locale_buf, locale, sizeof (locale_buf));
		locale = locale_buf;
	}
	(void) setlocale(LC_ALL, "C");
	if (regcomp(&reg, "^" ZONENAME_REGEXP "$", REG_EXTENDED|REG_NOSUB) != 0)
		goto err;

	if (regexec(&reg, zone, (size_t)0, NULL, 0) != 0)
		goto err;

	regfree(&reg);
	(void) setlocale(LC_ALL, locale);
	return;

err:
	(void) setlocale(LC_ALL, locale);
	zone_perror(zone, Z_BOGUS_ZONE_NAME, TRUE);
	usage(FALSE, HELP_SYNTAX);
	exit(Z_USAGE);
}

int
main(int argc, char *argv[])
{
	int err, arg;

	/* This must be before anything goes to stdout. */
	setbuf(stdout, NULL);

	saw_error = FALSE;
	cmd_file_mode = FALSE;
	execname = get_execbasename(argv[0]);

	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);

	if (getzoneid() != GLOBAL_ZONEID) {
		zerr(gettext("%s can only be run from the global zone."),
		    execname);
		exit(Z_ERR);
	}

	if (argc < 2) {
		usage(FALSE, HELP_USAGE | HELP_SUBCMDS);
		exit(Z_USAGE);
	}
	if (strcmp(argv[1], cmd_to_str(CMD_HELP)) == 0) {
		(void) one_command_at_a_time(argc - 1, &(argv[1]));
		exit(Z_OK);
	}

	zone = NULL;
	while ((arg = getopt(argc, argv, "?f:z:")) != EOF) {
		switch (arg) {
		case '?':
			if (optopt == '?')
				usage(TRUE, HELP_USAGE | HELP_SUBCMDS);
			else
				usage(FALSE, HELP_USAGE);
			exit(Z_USAGE);
			/* NOTREACHED */
		case 'f':
			cmd_file_name = optarg;
			cmd_file_mode = TRUE;
			break;
		case 'z':
			zone = optarg;
			break;
		default:
			usage(FALSE, HELP_USAGE);
			exit(Z_USAGE);
		}
	}

	if (optind > argc || zone == NULL) {
		usage(FALSE, HELP_USAGE);
		exit(Z_USAGE);
	}

	validate_zone_name();
	if (zonecfg_access(zone, W_OK) == Z_OK) {
		read_only_mode = FALSE;
	} else {
		read_only_mode = TRUE;
		/* skip this message in one-off from command line mode */
		if (optind == argc)
			(void) fprintf(stderr, gettext("WARNING: you do not "
			    "have write access to this zone's configuration "
			    "file;\ngoing into read-only mode.\n"));
	}

	if ((handle = zonecfg_init_handle()) == NULL) {
		zone_perror(execname, Z_NOMEM, TRUE);
		exit(Z_ERR);
	}

	/*
	 * This may get set back to FALSE again in cmd_file() if cmd_file_name
	 * is a "real" file as opposed to "-" (i.e. meaning use stdin).
	 */
	if (isatty(STDIN_FILENO))
		ok_to_prompt = TRUE;
	if ((gl = new_GetLine(MAX_LINE_LEN, MAX_CMD_HIST)) == NULL)
		exit(Z_ERR);
	if (gl_customize_completion(gl, NULL, cmd_cpl_fn) != 0)
		exit(Z_ERR);
	(void) sigset(SIGINT, SIG_IGN);
	if (optind == argc) {
		if (!cmd_file_mode)
			err = do_interactive();
		else
			err = cmd_file(cmd_file_name);
	} else {
		err = one_command_at_a_time(argc - optind, &(argv[optind]));
	}
	zonecfg_fini_handle(handle);
	(void) del_GetLine(gl);
	return (err);
}
