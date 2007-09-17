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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <locale.h>
#include <strings.h>
#include <errno.h>
#include <limits.h>
#include <sys/varargs.h>
#include "idmap_engine.h"
#include "idmap_priv.h"

/* Initialization values for pids/rids: */

#define	UNDEFINED_UID (uid_t)-1
#define	UNDEFINED_GID (gid_t)-1
#define	UNDEFINED_RID (idmap_rid_t)-1;

/* is_user values */

#define	I_YES 1
#define	I_NO 0
#define	I_UNKNOWN -1

/*
 * used in do_show for the type of argument, which can be winname,
 * unixname, uid, gid, sid or not given at all:
 */

#define	TYPE_SID	0x010	/* sid */
#define	TYPE_WN		0x110	/* winname */
#define	TYPE_WU		0x111	/* winuser */
#define	TYPE_WG		0x112	/* wingroup */
#define	TYPE_UID	0x001	/* uid */
#define	TYPE_GID	0x002	/* gid */
#define	TYPE_PID	0x000	/* pid */
#define	TYPE_UN		0x100	/* unixname */
#define	TYPE_UU		0x101	/* unixuser */
#define	TYPE_UG		0x102	/* unixgroup */

#define	IS_WIN		0x010	/* mask for the windows types */
#define	IS_NAME		0x100	/* mask for string name types */
#define	IS_USER		0x001	/* mask for user types */
#define	IS_GROUP	0x002	/* mask for group types */


/* Identity type strings */

#define	ID_WINNAME	"winname"
#define	ID_UNIXNAME	"unixname"
#define	ID_UNIXUSER	"unixuser"
#define	ID_UNIXGROUP	"unixgroup"
#define	ID_WINUSER	"winuser"
#define	ID_WINGROUP	"wingroup"
#define	ID_SID	"sid"
#define	ID_UID	"uid"
#define	ID_GID	"gid"

/* Flags */

#define	f_FLAG	'f'
#define	t_FLAG	't'
#define	d_FLAG	'd'
#define	F_FLAG	'F'
#define	a_FLAG	'a'
#define	n_FLAG	'n'
#define	c_FLAG	'c'


/* used in the function do_import */
#define	MAX_INPUT_LINE_SZ 2047


typedef struct {
	int is_user;
	int direction;
	boolean_t is_nt4;
	char *unixname;
	char *winname;
	char *windomain;
	char *sidprefix;
	idmap_rid_t rid;
	uid_t pid;
} name_mapping_t;

/*
 * Formats of the output:
 *
 * Idmap reads/prints mappings in several formats: ordinary mappings,
 * name mappings in Samba username map format (smbusers), Netapp
 * usermap.cfg.
 *
 * DEFAULT_FORMAT are in fact the idmap subcommands suitable for
 * piping to idmap standart input. For example
 * add -d winuser:bob@foo.com unixuser:fred
 * add -d winuser:bob2bar.com unixuser:fred
 *
 * SMBUSERS is the format of Samba username map (smbusers). For full
 * documentation, search for "username map" in smb.conf manpage.
 * The format is for example
 *    fred = bob@foo.com bob2@bar.com
 *
 * USERMAP_CFG is the format of Netapp usermap.cfg file. Search
 * http://www.netapp.com/ for more documentation. IP qualifiers are not
 * supported.
 * The format is for example
 *    bob@foo.com => fred
 *    "Bob With Spaces"@bar.com => fred  #comment
 *
 * The previous formats were for name rules. MAPPING_NAME and
 * MAPPING_ID are for the actual mappings, as seen in show/dump
 * commands. MAPPING_NAME prefers the string names of the user over
 * their numerical identificators. MAPPING_ID prints just the
 * identificators.
 * Example of the MAPPING_NAME:
 *   winname:bob@foo.com -> unixname:fred
 *
 * Example of the MAPPING_ID:
 *   sid:S-1-2-3-4 -> uid:5678
 */

typedef enum {
	UNDEFINED_FORMAT = -1,
	DEFAULT_FORMAT = 0,
	MAPPING_ID,
	MAPPING_NAME,
	USERMAP_CFG,
	SMBUSERS
} format_t;

/* Gives the format to use. Set in print_mapping_init  */
static format_t pnm_format;

/* The file for print_mapping_init output. Mostly just stdout. */
static FILE *pnm_file;

/* In smbusers format, more unixnames can be aggregated to one line. */
static char *pnm_last_unixname;

/*
 * idmap_api batch related variables:
 *
 * idmap can operate in two modes. It the batch mode, the idmap_api
 * batch is commited at the end of a batch of several
 * commands. At the end of input file, typically. This mode is used
 * for processing input from a file.
 *  In the non-batch mode, each command is commited immediately. This
 * mode is used for tty input.
 */

/* Are we in the batch mode? */
static int batch_mode = 0;

/* Self describing stricture for positions */
struct pos_sds {
	int size;
	int last;
	cmd_pos_t *pos[1];
};

static struct pos_sds *positions;

/* Handles for idmap_api batch */
static idmap_handle_t *handle = NULL;
static idmap_udt_handle_t *udt = NULL;

/* Do we need to commit the udt batch at the end? */
static int udt_used;

/* Command handlers */

static int do_show_mapping(flag_t *f, int argc, char **argv, cmd_pos_t *pos);
static int do_dump(flag_t *f, int argc, char **argv, cmd_pos_t *pos);
static int do_import(flag_t *f, int argc, char **argv, cmd_pos_t *pos);
static int do_list_name_mappings(flag_t *f, int argc, char **argv,
    cmd_pos_t *pos);
static int do_add_name_mapping(flag_t *f, int argc, char **argv,
    cmd_pos_t *pos);
static int do_remove_name_mapping(flag_t *f, int argc, char **argv,
    cmd_pos_t *pos);
static int do_exit(flag_t *f, int argc, char **argv, cmd_pos_t *pos);
static int do_export(flag_t *f, int argc, char **argv, cmd_pos_t *pos);
static int do_help(flag_t *f, int argc, char **argv, cmd_pos_t *pos);

/* Command names and their hanlers to be passed to idmap_engine */

static cmd_ops_t commands[] = {
	{
		"show",
		"c(create)",
		do_show_mapping
	},
	{
		"dump",
		"n(names)",
		do_dump
	},
	{
		"import",
		"F(flush)f:(file)",
		do_import
	},
	{
		"export",
		"f:(file)",
		do_export
	},
	{
		"list",
		"",
		do_list_name_mappings
	},
	{
		"add",
		"d(directional)",
		do_add_name_mapping
	},
	{
		"remove",
		"a(all)t(to)f(from)d(directional)",
		do_remove_name_mapping
	},
	{
		"exit",
		"",
		do_exit
	},
	{
		"help",
		"",
		do_help
	}
};

/* Print error message, possibly with a position */
/* printflike */
static void
print_error(cmd_pos_t *pos, const char *format, ...) {
	size_t length;

	va_list ap;

	va_start(ap, format);

	if (pos != NULL) {
		length = strlen(pos->line);

		/* Skip newlines etc at the end: */
		while (length > 0 && isspace(pos->line[length - 1]))
			length--;

		(void) fprintf(stderr,
		    gettext("Error at line %d: %.*s\n"),
		    pos->linenum,
		    length,
		    pos->line);
	}
	(void) vfprintf(stderr, format, ap);

	va_end(ap);
}

/* Inits positions sds. 0 means everything went OK, -1 for errors */
static int
init_positions() {
	int init_size = 32; /* Initial size of the positions array */

	positions = (struct pos_sds *) malloc(sizeof (struct pos_sds) +
	    (init_size - 1) * sizeof (cmd_pos_t *));

	if (positions == NULL) {
		print_error(NULL, gettext("Not enough memory.\n"));
		return (-1);
	}

	positions->size = init_size;
	positions->last = 0;
	return (0);
}

/* Free the positions array */
static void
fini_positions() {
	int i;
	for (i = 0; i < positions->last; i++) {
		if (positions->pos[i] == NULL)
			continue;
		free(positions->pos[i]->line);
		free(positions->pos[i]);
	}
	free(positions);

	positions = NULL;
}

/*
 * Add another position to the positions array. 0 means everything
 * went OK, -1 for errors
 */
static int
positions_add(cmd_pos_t *pos) {
	if (positions->last >= positions->size) {
		positions->size *= 2;
		positions = (struct pos_sds *)realloc(positions,
		    sizeof (struct pos_sds) +
		    (positions->size - 1) * sizeof (cmd_pos_t *));
		if (positions == NULL)
			goto nomemory;
	}

	if (pos == NULL)
		positions->pos[positions->last] = NULL;
	else {
		positions->pos[positions->last] = (cmd_pos_t *)calloc(1,
		    sizeof (cmd_pos_t));
		if (positions->pos[positions->last] == NULL)
			goto nomemory;

		*positions->pos[positions->last] = *pos;
		positions->pos[positions->last]->line = strdup(pos->line);
		if (positions->pos[positions->last]->line == NULL)
			goto nomemory;
	}

	positions->last++;
	return (0);

nomemory:
	print_error(NULL, gettext("Not enough memory.\n"));
	return (-1);
}




/*
 * Compare two strings just like strcmp, but stop before the end of
 * the s2
 */
static int
strcmp_no0(const char *s1, const char *s2) {
	return (strncmp(s1, s2, strlen(s2)));
}

/* The same as strcmp_no0, but case insensitive. */
static int
strcasecmp_no0(const char *s1, const char *s2) {
	return (strncasecmp(s1, s2, strlen(s2)));
}


/* Print help message */
static void
help() {
	(void) fprintf(stderr,
	    "idmap\n"
	    "idmap -f command-file\n"
	    "idmap show [-c] identity [targettype]\n"
	    "idmap dump [-n]\n"
	    "idmap add [-d] name1 name2\n"
	    "idmap remove -a\n"
	    "idmap remove name\n"
	    "idmap remove [-d] name1 name2\n"
	    "idmap list\n"
	    "idmap import [-F] [-f file] format\n"
	    "idmap export [-f file] format\n"
	    "idmap help\n");
}

/* The handler for the "help" command. */
static int
/* LINTED E_FUNC_ARG_UNUSED */
do_help(flag_t *f, int argc, char **argv, cmd_pos_t *pos)
{
	help();
	return (0);
}

/* Initialization of the idmap api batch */
static int
init_batch() {
	idmap_stat stat;

	stat = idmap_init(&handle);
	if (stat < 0) {
		print_error(NULL,
		    gettext("Connection not established (%s)\n"),
		    idmap_stat2string(NULL, stat));
		return (-1);
	}

	return (0);
}

/* Initialization common to all commands */
static int
init_command() {
	if (batch_mode)
		return (0);

	return (init_batch());
}

/* Finalization common to all commands */
static void
fini_command() {
	if (batch_mode)
		return;
	(void) idmap_fini(handle);
	handle = NULL;
}

/* Initialization of the commands which perform write operations  */
static int
init_udt_batch() {
	idmap_stat stat;

	if (init_batch())
		return (-1);

	stat = idmap_udt_create(handle, &udt);
	if (stat < 0) {
		print_error(NULL,
		    gettext("Error initiating transaction (%s)"),
		    idmap_stat2string(handle, stat));
		return (-1);
	}

	if (init_positions() < 0)
		return (-1);

	return (0);
}


/* Finalization of the write commands  */
static int
init_udt_command() {
	udt_used = 1;
	if (batch_mode)
		return (0);

	return (init_udt_batch());
}


/* If everythings is OK, send the udt batch to idmapd  */
static int
fini_udt_command(int ok, cmd_pos_t *pos) {
	int rc = 0;
	int64_t failpos;
	idmap_stat stat, stat1;
	cmd_pos_t *reported_pos;

	if (batch_mode)
		return (0);
	if (udt == NULL) {
		print_error(pos,
		    gettext("Internal error: uninitiated batch.\n"));
		return (-1);
	}

	if (ok && udt_used) {
		stat = idmap_udt_commit(udt);
		if (stat == IDMAP_SUCCESS)
			goto out;

		rc = -1;

		stat1 = idmap_udt_get_error_index(udt, &failpos);
		if (stat1 != IDMAP_SUCCESS) {
			print_error(NULL,
			    gettext("Error diagnosing transaction (%s)\n"),
			    idmap_stat2string(handle, stat1));
			goto out;
		}


		if (failpos < 0)
			reported_pos = pos;
		else
			reported_pos = positions->pos[failpos];

		print_error(reported_pos,
		    gettext("Error commiting transaction (%s)\n"),
		    idmap_stat2string(handle, stat));
	}

out:
	idmap_udt_destroy(udt);
	udt = NULL;
	udt_used = 0;
	fini_command();
	fini_positions();
	return (rc);
}

/* Convert numeric expression of the direction to it's string form */
static char *
direction2string(int direction) {
	switch (direction) {
	case IDMAP_DIRECTION_BI:
		return ("==");
	case IDMAP_DIRECTION_W2U:
		return ("=>");
	case IDMAP_DIRECTION_U2W:
		return ("<=");
	default:
		/* This can never happen: */
		print_error(NULL,
		    gettext("Internal error: invalid direction.\n"));
		return ("");
	}
	/* never reached */
}

/* Do we need quotation marks around winname in the USERMAP_CFG format? */
static int
needs_protection(char *what) {
	if (strchr(what, ' ') != NULL)
		return (1);

	if (strchr(what, '\t') != NULL)
		return (1);

	if (strchr(what, '#') != NULL)
		return (1);

	return (0);
}


/*
 * Returns 1 if c is a shell-meta-character requiring quoting, 0
 * otherwise.
 *
 * We don't quote '*' and ':' because they cannot do any harm
 * a) they have no meaning to idmap_engine b) even ifsomebody copy &
 * paste idmap output to a shell commandline, there is the identity
 * type string in front of them. On the other hand, '*' and ':' are
 * everywhere.
 */
static int
is_shell_special(char c) {
	if (isspace(c))
		return (1);

	if (strchr("&^{}#;'\"\\`!$()[]><|~", c) != NULL)
		return (1);

	return (0);
}

/*
 * Returns 1 if c is a shell-meta-character requiring quoting even
 * inside double quotes, 0 otherwise. It means \, " and $ .
 *
 * This set of characters is a subset of those in is_shell_special().
 */
static int
is_dq_special(char c) {
	if (strchr("\\\"$", c) != NULL)
		return (1);
	return (0);
}




/*
 * Quote any shell meta-characters in the given string.  If 'quote' is
 * true then use double-quotes to quote the whole string, else use
 * back-slash to quote each individual meta-character.
 *
 * The resulting string is placed in *res.  Callers must free *res if the
 * return value isn't 0 (even if the given string had no meta-chars).
 * If there are any errors this returns -1, else 0.
 */
static int
shell_app(char **res, char *string, int quote) {
	int i, j;
	uint_t noss = 0; /* Number Of Shell Special chars in the input */
	uint_t noqb = 0; /* Number Of Quotes and Backslahes in the input */
	char *out;
	size_t len_orig = strlen(string);
	size_t len;

	/* First, let us count how many characters we need to quote: */
	for (i = 0; i < len_orig; i++) {
		if (is_shell_special(string[i])) {
			noss++;
			if (is_dq_special(string[i]))
				noqb++;
		}

	}

	/* Do we need to quote at all? */
	if (noss == 0) {
		out = strdup(string);
		if (out == NULL) {
			print_error(NULL, gettext("Not enough memory.\n"));
			return (-1);
		}
		*res = out;
		return (0);
	}

	/* What is the length of the result? */
	if (quote)
		len = strlen(string) + 2 + noqb + 1; /* 2 for quotation marks */
	else
		len = strlen(string) + noss + 1;

	out = (char *)malloc(len * sizeof (char));
	if (out == NULL) {
		print_error(NULL, gettext("Not enough memory.\n"));
		return (-1);
	}

	j = 0;
	if (quote)
		out[j++] = '"';

	for (i = 0; i < len_orig; i++) {
		/* Quote the dangerous chars by a backslash */
		if (quote && is_dq_special(string[i]) ||
			(!quote && is_shell_special(string[i]))) {
			out[j++] = '\\';
		}
		out[j++] = string[i];
	}

	if (quote)
		out[j++] = '"';

	out[j] = '\0';
	*res = out;
	return (0);
}

/* Assemble string form sid */
static char *
sid_format(char *sidprefix, idmap_rid_t rid) {
	char *to;
	size_t len;

	/* 'sid:' + sidprefix + '-' + rid + '\0' */
	len = strlen(sidprefix) + 6 + 3 * sizeof (rid);
	to = (char *)malloc(len * sizeof (char));
	if (to == NULL)
		return (NULL);

	(void) snprintf(to, len, "sid:%s-%u", sidprefix, rid);
	return (to);
}

/* Assemble string form uid or gid */
static char *
pid_format(uid_t from, int is_user) {
	char *to;
	size_t len;

	/* ID_UID ":" + uid + '\0' */
	len = 5 + 3 * sizeof (uid_t);
	to = (char *)malloc(len * sizeof (char));
	if (to == NULL)
		return (NULL);

	(void) snprintf(to, 16, "%s:%u", is_user ? ID_UID : ID_GID, from);
	return (to);
}

/* Assemble winname, e.g. "winuser:bob@foo.sun.com", from name_mapping_t */
static int
nm2winqn(name_mapping_t *nm, char **winqn) {
	char *out;
	size_t length = 0;
	int is_domain = 1;
	char *prefix;

	/* Sometimes there are no text names. Return a sid, then. */
	if (nm->winname == NULL) {
		if (nm->sidprefix == NULL)
			return (-1);

		*winqn = sid_format(nm->sidprefix, nm->rid);
		return (0);
	}

	switch (nm->is_user) {
	case I_YES:
		prefix = ID_WINUSER ":";
		break;
	case I_NO:
		prefix = ID_WINGROUP ":";
		break;
	case I_UNKNOWN:
		prefix = ID_WINNAME ":";
		break;

	}

	length = strlen(prefix) + strlen(nm->winname);

	/* Windomain is not mandatory: */
	if (nm->windomain == NULL ||
	    *nm->winname == '\0' ||
	    strcmp(nm->winname, "\"\"") == 0)
		is_domain = 0;
	else
		length += strlen(nm->windomain) + 1;

	out = (char *)malloc((length + 1) * sizeof (char));
	if (out == NULL) {
		print_error(NULL,
		    gettext("Not enough memory.\n"));
		return (-1);
	}

	(void) strcpy(out, prefix);

	if (!is_domain)
		(void) strcat(out, nm->winname);
	else if (nm->is_nt4) {
		(void) strcat(out, nm->windomain);
		(void) strcat(out, "\\");
		(void) strcat(out, nm->winname);
	} else {
		(void) strcat(out, nm->winname);
		(void) strcat(out, "@");
		(void) strcat(out, nm->windomain);
	}

	*winqn = out;
	return (0);
}

/* Assemble a text unixname, e.g. unixuser:fred */
static int
nm2unixname(name_mapping_t *nm, char **unixname) {
	size_t length = 0;
	char *out;
	char *it;
	char *prefix;

	/* Sometimes there is no name, just pid: */
	if (nm->unixname == NULL) {
		if (nm->pid == UNDEFINED_UID)
			return (-1);

		*unixname = pid_format(nm->pid, nm->is_user);
		return (0);
	}

	if (shell_app(&it, nm->unixname, 0))
		return (-1);


	switch (nm->is_user) {
	case I_YES:
		prefix = ID_UNIXUSER ":";
		break;
	case I_NO:
		prefix = ID_UNIXGROUP ":";
		break;
	case I_UNKNOWN:
		prefix = ID_UNIXNAME ":";
		break;

	}

	length = strlen(prefix) + strlen(it);

	out = (char *)malloc((length + 1) * sizeof (char));
	if (out == NULL) {
		print_error(NULL,
		    gettext("Not enough memory.\n"));
		free(it);
		return (-1);
	}

	(void) strcpy(out, prefix);
	(void) strcat(out, it);
	free(it);

	*unixname = out;
	return (0);
}

/* Initialize print_mapping variables. Must be called before print_mapping */
static int
print_mapping_init(format_t f, FILE *fi) {
	pnm_format = f;
	pnm_file = fi;

	switch (pnm_format) {
	case SMBUSERS:
		pnm_last_unixname = NULL;
		break;
	default:
		;
	}

	return (0);
}

/* Finalize print_mapping. */
static int
print_mapping_fini() {
	switch (pnm_format) {
	case SMBUSERS:
		if (pnm_last_unixname != NULL) {
			(void) fprintf(pnm_file, "\n");
			free(pnm_last_unixname);
		}
		break;
	default:
		;
	}

	pnm_file = stderr;
	pnm_format = UNDEFINED_FORMAT;

	return (0);
}

/*
 * This prints both name rules and ordinary mappings, based on the pnm_format
 * set in print_mapping_init().
 */

static int
print_mapping(name_mapping_t *nm)
{
	char *dirstring;
	char *winname_qm, *windomain_qm, *unixname_qm;
	char *winname = NULL;
	char *winname1 = NULL;
	char *unixname = NULL;
	FILE *f = pnm_file;


	switch (pnm_format) {
	case MAPPING_NAME:
		if (nm2winqn(nm, &winname) < 0)
			return (-1);
		if (nm2unixname(nm, &unixname) < 0) {
			free(winname);
			return (-1);
		}
	/* LINTED E_CASE_FALLTHRU */
	case MAPPING_ID:
		if (pnm_format == MAPPING_ID) {
			if (nm->sidprefix == NULL) {
				print_error(NULL,
				    gettext("SID not given.\n"));
				return (-1);
			}
			winname = sid_format(nm->sidprefix, nm->rid);
			if (winname == NULL)
				return (-1);
			unixname = pid_format(nm->pid, nm->is_user);
			if (unixname == NULL) {
				free(winname);
				return (-1);
			}
		}

		dirstring = direction2string(nm->direction);

		(void) fprintf(f, "%s\t%s\t%s\n", winname, dirstring,
		    unixname);

		free(winname);
		free(unixname);
		break;
	case SMBUSERS:
		if (!nm->is_user) {
			print_error(NULL,
			    gettext("Group rule: "));
			f = stderr;
		} else 	if (nm->direction == IDMAP_DIRECTION_U2W) {
			print_error(NULL,
			    gettext("Opposite direction of the mapping: "));
			f = stderr;
		}
		if (shell_app(&winname, nm->winname, 1))
			return (-1);

		if (pnm_file != f) {
			(void) fprintf(f, "%s=%s\n", nm->unixname, winname);
		} else if (pnm_last_unixname != NULL &&
		    strcmp(pnm_last_unixname, nm->unixname) == 0) {
			(void) fprintf(f, " %s", winname);
		} else {
			if (pnm_last_unixname != NULL) {
				(void) fprintf(f, "\n");
				free(pnm_last_unixname);
			}
			pnm_last_unixname = strdup(nm->unixname);
			(void) fprintf(f, "%s=%s", nm->unixname, winname);
		}

		free(winname);

		break;
	case USERMAP_CFG:
		if (!nm->is_user) {
			print_error(NULL,
			    gettext("Group rule: "));
			f = stderr;
		}

		dirstring = direction2string(nm->direction);

		winname_qm = needs_protection(nm->winname) ? "\"" : "";
		windomain_qm =  nm->windomain &&
		    needs_protection(nm->windomain) ? "\"" : "";
		unixname_qm = needs_protection(nm->unixname) ? "\"" : "";

		if (nm->windomain == NULL)
			(void) fprintf(f, "%s%s%s\t%s\t%s%s%s\n",
			    winname_qm,
			    nm->winname, winname_qm, dirstring,
			    unixname_qm, nm->unixname, unixname_qm);
		else
			(void) fprintf(f, nm->is_nt4 ?
			    "%s%s%1$s\\%3$s%4$s%3$s\t%5$s\t%6$s%7$s%6$s\n" :
			    "%3$s%4$s%3$s@%1$s%2$s%1$s\t%5$s\t%6$s%7$s%6$s\n",
			    windomain_qm, nm->windomain,
			    winname_qm, nm->winname,
			    dirstring,
			    unixname_qm, nm->unixname);
		break;

	case DEFAULT_FORMAT:
		if (nm2winqn(nm, &winname1) < 0)
			return (-1);

		if (shell_app(&winname, winname1, 1)) {
			free(winname1);
			return (-1);
		}

		free(winname1);

		if (nm2unixname(nm, &unixname)) {
			free(winname);
			return (-1);
		}

		if (nm->direction == IDMAP_DIRECTION_U2W) {
			(void) fprintf(f,
			    "add -d\t%s\t%s\n",
			    unixname, winname);
		} else {
			(void) fprintf(f,
			    "add %s\t%s\t%s\n",
			    nm->direction == IDMAP_DIRECTION_BI? "" : "-d",
			    winname, unixname);
		}
		free(winname);
		free(unixname);
		break;
	default:
		/* This can never happen: */
		print_error(NULL,
		    gettext("Internal error: invalid print format.\n"));
		return (-1);
	}

	return (0);
}

/* Allocate a new name_mapping_t and initialize the values. */
static name_mapping_t *
name_mapping_init() {
	name_mapping_t *nm = (name_mapping_t *)malloc(sizeof (name_mapping_t));
	if (nm == NULL) {
		print_error(NULL, gettext("Not enough memory.\n"));
		return (NULL);
	}
	nm->winname = nm->windomain = nm->unixname = nm->sidprefix = NULL;
	nm->rid = UNDEFINED_RID;
	nm->is_nt4 = B_FALSE;
	nm->is_user = I_UNKNOWN;
	nm->direction = IDMAP_DIRECTION_UNDEF;
	nm->pid = UNDEFINED_UID;
	return (nm);
}

/* Free name_mapping_t */
static void
name_mapping_fini(name_mapping_t *nm) {

	free(nm->winname);
	free(nm->windomain);
	free(nm->unixname);
	free(nm->sidprefix);

	free(nm);
}


/* dump command handler */
static int
/* LINTED E_FUNC_ARG_UNUSED */
do_dump(flag_t *f, int argc, char **argv, cmd_pos_t *pos)
{
	idmap_stat stat;
	idmap_iter_t *ihandle;
	int is_user;
	int rc = 0;

	if (init_command())
		return (-1);

	(void) print_mapping_init(f[n_FLAG] != NULL ? MAPPING_NAME : MAPPING_ID,
	    stdout);

	for (is_user = I_YES; is_user >= I_NO; is_user--) {
		stat = idmap_iter_mappings(handle, is_user, &ihandle);
		if (stat < 0) {
			print_error(pos,
			    gettext("Iteration handle not obtained (%s)\n"),
			    idmap_stat2string(handle, stat));
			rc = -1;
			goto cleanup;
		}

		do {
			name_mapping_t *nm = name_mapping_init();
			if (nm == NULL) {
				rc = -1;
				goto cleanup;
			}
			nm->is_user = is_user;


			stat = idmap_iter_next_mapping(ihandle,
			    &nm->sidprefix, &nm->rid, &nm->pid,
			    &nm->winname, &nm->windomain,
			    &nm->unixname, &nm->direction);

			if (stat >= 0)
				(void) print_mapping(nm);

			name_mapping_fini(nm);

		} while (stat > 0);

		/* IDMAP_ERR_NOTFOUND indicates end of the list */
		if (stat < 0 && stat != IDMAP_ERR_NOTFOUND) {
			print_error(pos,
			    gettext("Error during iteration (%s)\n"),
			    idmap_stat2string(handle, stat));
			rc = -1;
			goto cleanup;
		}

		idmap_iter_destroy(ihandle);
	}
cleanup:
	(void) print_mapping_fini();
	fini_command();
	return (rc);
}

/*
 * The same as strdup, but length chars is duplicated, no matter on
 * '\0'. The caller must guarantee "length" chars in "from".
 */
static char *
strndup(char *from, size_t length) {
	char *out = (char *)malloc((length + 1) * sizeof (char));
	if (out == NULL) {
		print_error(NULL, gettext("Not enough memory\n"));
		return (NULL);
	}
	(void) strncpy(out, from, length);
	out[length] = '\0';
	return (out);
}

/*
 * Convert pid from string to it's numerical representation. If it is
 * a valid string, i.e. number of a proper length, return 1. Otherwise
 * print an error message and return 0.
 */
static int
pid_convert(char *string, uid_t *number, int type, cmd_pos_t *pos) {
	int i;
	long long ll;
	char *type_string;
	size_t len = strlen(string);

	if (type == TYPE_GID)
		type_string = ID_GID;
	else if (type == TYPE_UID)
		type_string = ID_UID;
	else
		return (0);

	for (i = 0; i < len; i++) {
		if (!isdigit(string[i])) {
			print_error(pos,
			    gettext("\"%s\" is not a valid %s: the non-digit"
				" character '%c' found.\n"), string,
			    type_string, string[i]);
			return (0);
		}
	}

	ll = atoll(string);

	/* Isn't it too large? */
	if (type == TYPE_UID && (uid_t)ll != ll ||
	    type == TYPE_GID && (gid_t)ll != ll) {
		print_error(pos,
		    gettext("%llu: too large for a %s.\n"), ll,
		    type_string);
		return (0);
	}

	*number = (uid_t)ll;
	return (1);
}

/*
 * Convert SID from string to prefix and rid. If it has a valid
 * format, i.e. S(\-\d+)+, return 1. Otherwise print an error
 * message and return 0.
 */
static int
sid_convert(char *from, char **prefix, idmap_rid_t *rid, cmd_pos_t *pos) {
	int i, j;
	char *cp;
	char *ecp;
	char *prefix_end;
	u_longlong_t	a;
	unsigned long	r;

	if (strcmp_no0(from, "S-1-") != 0) {
		print_error(pos,
		    gettext("Invalid %s \"%s\": it doesn't start "
			"with \"%s\".\n"), ID_SID, from, "S-1-");
		return (0);
	}

	if (strlen(from) <= strlen("S-1-")) {
		print_error(pos,
		    gettext("Invalid %s \"%s\": the authority and RID parts are"
			" missing.\n"),
		    ID_SID, from);
		return (0);
	}

	/* count '-'s */
	for (j = 0, cp = strchr(from, '-');
		cp != NULL;
		j++, cp = strchr(cp + 1, '-')) {
		/* can't end on a '-' */
		if (*(cp + 1) == '\0') {
			print_error(pos,
			    gettext("Invalid %s \"%s\": '-' at the end.\n"),
			    ID_SID, from);
			return (0);
		} else 	if (*(cp + 1) == '-') {
			print_error(pos,
			    gettext("Invalid %s \"%s\": double '-'.\n"),
			    ID_SID, from);
			return (0);
		}
	}


	/* check that we only have digits and '-' */
	i = strspn(from + 1, "0123456789-") + 1;
	if (i < strlen(from)) {
		print_error(pos,
		    gettext("Invalid %s \"%s\": invalid character '%c'.\n"),
		    ID_SID, from, from[i]);
		return (0);
	}


	cp = from + strlen("S-1-");

	/* 64-bit safe parsing of unsigned 48-bit authority value */
	errno = 0;
	a = strtoull(cp, &ecp, 10);

	/* errors parsing the authority or too many bits */
	if (cp == ecp || (a == 0 && errno == EINVAL)) {
			print_error(pos,
			gettext("Invalid %s \"%s\": unable to parse the "
			    "authority \"%.*s\".\n"), ID_SID, from, ecp - cp,
			cp);
		    return (0);
	}

	if ((a == ULLONG_MAX && errno == ERANGE) ||
	    (a & 0x0000ffffffffffffULL) != a) {
		print_error(pos,
		    gettext("Invalid %s \"%s\": the authority "
			"\"%.*s\" is too large.\n"), ID_SID, from,
		    ecp - cp, cp);
		return (0);
	}

	cp = ecp;

	if (j < 3) {
		print_error(pos,
		    gettext("Invalid %s \"%s\": must have at least one RID.\n"),
		    ID_SID, from);
		return (0);
	}

	for (i = 2; i < j; i++) {
		if (*cp++ != '-') {
			/* Should never happen */
			print_error(pos,
			    gettext("Invalid %s \"%s\": internal error:"
				" '-' missing.\n"),
			    ID_SID, from);
			return (0);
		}
		/* 32-bit safe parsing of unsigned 32-bit RID */
		errno = 0;
		r = strtoul(cp, &ecp, 10);

		/* errors parsing the RID */
		if (cp == ecp || (r == 0 && errno == EINVAL)) {
			/* should never happen */
			    print_error(pos,
				gettext("Invalid %s \"%s\": internal error: "
				    "unable to parse the RID "
				    "after \"%.*s\".\n"), ID_SID,
				from, cp - from, from);
			    return (0);
		}

		if (r == ULONG_MAX && errno == ERANGE) {
			print_error(pos,
			    gettext("Invalid %s \"%s\": the RID \"%.*s\""
				" is too large.\n"), ID_SID,
			    from, ecp - cp, cp);
			return (0);
		}
		prefix_end = cp;
		cp = ecp;
	}

	/* check that all of the string SID has been consumed */
	if (*cp != '\0') {
		/* Should never happen */
		print_error(pos,
		    gettext("Invalid %s \"%s\": internal error: "
			"something is still left.\n"),
		    ID_SID, from);
		return (0);
	}

	*rid = (idmap_rid_t)r;

	/* -1 for the '-' at the end: */
	*prefix = strndup(from, prefix_end - from - 1);
	if (*prefix == NULL) {
		print_error(pos,
		    gettext("Not enough memory.\n"));
		return (0);
	}

	return (1);
}

/* Does the line start with USERMAP_CFG IP qualifier? */
static int
ucp_is_IP_qualifier(char *line) {
	char *it;
	it = line + strcspn(line, " \t\n#:");
	return (*(it + 1) == ':' ? 1 : 0);
}


/*
 * returns interior of quotation marks in USERMAP_CFG. In this format,
 * there cannot be a protected quotation mark inside.
 */
static char *
ucp_qm_interior(char **line, cmd_pos_t *pos) {
	char *out;
	char *qm = strchr(*line + 1, '"');
	if (qm == NULL) {
		print_error(pos,
		    gettext("Unclosed quotations\n"));
		return (NULL);
	}

	out = strndup(*line + 1, qm - *line - 1);
	*line = qm + 1;
	return (out);
}

/*
 * Grab next token from the line in USERMAP_CFG format. terminators,
 * the 3rd parameter, contains all the characters which can terminate
 * the token. line_num is the line number of input used for error
 * reporting.
 */
static char *
ucp_grab_token(char **line, cmd_pos_t *pos, const char *terminators) {
	char *token;
	if (**line == '"')
		token = ucp_qm_interior(line, pos);
	else {
		int length = strcspn(*line, terminators);
		token = strndup(*line, length);
		*line += length;
	}

	return (token);
}


/*
 * Convert a line in usermap.cfg format to name_mapping.
 *
 * Return values: -1 for error, 0 for empty line, 1 for a mapping
 * found.
 */
static int
ucp_line2nm(char *line, cmd_pos_t *pos, name_mapping_t *nm) {
	char *it;
	char *token;
	char *token2;
	char separator;
	int is_direction = 0;

	it = line + strspn(line, " \t\n");

	/* empty or comment lines are OK: */
	if (*it == '\0' || *it == '#')
		return (0);

	/* We do not support network qualifiers */
	if (ucp_is_IP_qualifier(it)) {
		print_error(pos,
		    gettext("Unable to handle network qualifier.\n"));
		return (-1);
	}

	/* The windows name: */
	token = ucp_grab_token(&it, pos, " \t#\\\n@=<");
	if (token == NULL)
		return (-1);

	separator = *it;

	/* Didn't we bump to the end of line? */
	if (separator == '\0' || separator == '#') {
		free(token);
		print_error(pos,
		    gettext("UNIX_name not found.\n"));
		return (-1);
	}

	/* Do we have a domainname? */
	if (separator == '\\' || separator == '@') {
		it ++;
		token2 = ucp_grab_token(&it, pos, " \t\n#");
		if (token2 == NULL) {
			free(token);
			return (-1);
		} else if (*it == '\0' || *it == '#') {
			free(token);
			free(token2);
			print_error(pos,
			    gettext("UNIX_name not found.\n"));
		}

		if (separator == '\\') {
			nm->windomain = token;
			nm->winname = token2;
			nm->is_nt4 = 1;
		} else {
			nm->windomain = token2;
			nm->winname = token;
			nm->is_nt4 = 0;

		}
	} else {
		nm->windomain = NULL;
		nm->winname = token;
		nm->is_nt4 = 0;
	}


	it = it + strspn(it, " \t\n");

	/* Direction string is optional: */
	if (strncmp(it, "==", 2) == 0) {
		nm->direction = IDMAP_DIRECTION_BI;
		is_direction = 1;
	} else if (strncmp(it, "<=", 2) == 0) {
		nm->direction = IDMAP_DIRECTION_U2W;
		is_direction = 1;
	} else if (strncmp(it, "=>", 2) == 0) {
		nm->direction = IDMAP_DIRECTION_W2U;
		is_direction = 1;
	} else {
		nm->direction = IDMAP_DIRECTION_BI;
		is_direction = 0;
	}

	if (is_direction) {
		it += 2;
		it += strspn(it, " \t\n");

		if (*it == '\0' || *it == '#') {
			print_error(pos,
			    gettext("UNIX_name not found.\n"));
			return (-1);
		}
	}

	/* Now unixname: */
	it += strspn(it, " \t\n");
	token = ucp_grab_token(&it, pos, " \t\n#");

	if (token == NULL)
		/* nm->winname to be freed by name_mapping_fini */
		return (-1);

	/* Neither here we support IP qualifiers */
	if (ucp_is_IP_qualifier(token)) {
		print_error(pos,
		    gettext("Unable to handle network qualifier.\n"));
		free(token);
		return (-1);
	}

	nm->unixname = token;

	it += strspn(it, " \t\n");

	/* Does something remain on the line */
	if (*it  != '\0' && *it != '#') {
		print_error(pos,
		    gettext("Unrecognized parameters \"%s\".\n"), it);
		return (-1);
	}

	return (1);
}

/*
 * Parse SMBUSERS line to name_mapping_t. if line is NULL, then
 * pasrsing of the previous line is continued. line_num is input line
 * number used for error reporting.
 * Return values:
 *    rc -1: error
 *    rc = 0: mapping found and the line is finished,
 *    rc = 1: mapping found and there remains other on the line
 */
static int
sup_line2nm(char *line, cmd_pos_t *pos, name_mapping_t *nm) {
	static char *ll = NULL;
	static char *unixname = NULL;
	static size_t unixname_l = 0;
	char *token;

	if (line != NULL) {
		ll = line;

		unixname = ll += strspn(ll, " \t");
		if (*ll == '\0' || *ll == '#')
			return (0);

		unixname_l = strcspn(ll, " \t:=#\n");
		ll += unixname_l;

		if (*ll == '\0'|| *ll == '#')
			return (0);

		ll +=  strspn(ll, " \t:=#\n");

	}

	if (*ll == '\0'|| *ll == '#')
		return (0);

	token = ucp_grab_token(&ll, pos, " \t\n");
	if (token == NULL)
		return (-1);

	nm->is_nt4 = 0;
	nm->direction = IDMAP_DIRECTION_W2U;

	nm->windomain = NULL;
	nm->winname = token;
	nm->unixname = strndup(unixname, unixname_l);
	if (nm->unixname == NULL)
		return (-1);

	ll += strspn(ll, " \t\n");
	return (1);
}

/* Parse line to name_mapping_t. Basicaly just a format switch. */
static int
line2nm(char *line, cmd_pos_t *pos, name_mapping_t *nm, format_t f) {
	switch (f) {
	case USERMAP_CFG:
		if (line == NULL)
			return (0);
		else
			return (ucp_line2nm(line, pos, nm));
	case SMBUSERS:
		return (sup_line2nm(line, pos, nm));
	default:
		/* This can never happen */
		print_error(pos,
		    gettext("Internal error: invalid line format.\n"));
	}

	return (-1);
}


/* Examine -f flag and return the appropriate format_t */
static format_t
ff2format(char *ff, int is_mandatory) {

	if (ff == NULL && is_mandatory) {
		print_error(NULL, gettext("Format not given.\n"));
		return (UNDEFINED_FORMAT);
	}

	if (ff == NULL)
		return (DEFAULT_FORMAT);

	if (strcasecmp(ff, "usermap.cfg") == 0)
		return (USERMAP_CFG);

	if (strcasecmp(ff, "smbusers") == 0)
		return (SMBUSERS);

	print_error(NULL,
		    gettext("The only known formats are: \"usermap.cfg\" and "
			"\"smbusers\".\n"));
	return (UNDEFINED_FORMAT);
}

/* Delete all namerules of the given type */
static int
flush_nm(boolean_t is_user, cmd_pos_t *pos)
{
	idmap_stat stat;

	stat = idmap_udt_flush_namerules(udt, is_user);
	if (stat < 0) {
		print_error(pos,
		    is_user ? gettext("Unable to flush users (%s).\n")
		    : gettext("Unable to flush groups (%s).\n"),
		    idmap_stat2string(handle, stat));
		return (-1);
	}

	if (positions_add(pos) < 0)
		return (-1);

	return (0);
}

/* import command handler */
static int
/* LINTED E_FUNC_ARG_UNUSED */
do_import(flag_t *f, int argc, char **argv, cmd_pos_t *pos)
{
	name_mapping_t *nm;
	cmd_pos_t pos2;
	char line[MAX_INPUT_LINE_SZ];
	format_t format;
	int rc = 0;
	idmap_stat stat;
	FILE *file = NULL;

	if (batch_mode) {
		print_error(pos,
		    gettext("Import is not allowed in the batch mode.\n"));
		return (-1);
	}

	format = ff2format(argv[0], 1);
	if (format == UNDEFINED_FORMAT)
		return (-1);

	if (init_udt_command())
		return (-1);

	/* We don't flush groups in the usermap.cfg nor smbusers format */
	if (f[F_FLAG] != NULL &&
	    flush_nm(B_TRUE, pos) < 0 &&
	    (format == USERMAP_CFG || format == SMBUSERS ||
	    flush_nm(B_FALSE, pos) < 0)) {
		rc = -1;
		goto cleanup;
	}

	/* Where we import from? */
	if (f[f_FLAG] == NULL)
		file = stdin;
	else {
		file = fopen(f[f_FLAG], "r");
		if (file == NULL) {
			perror(f[f_FLAG]);
			goto cleanup;
		}
	}

	pos2.linenum = 0;
	pos2.line = line;

	while (fgets(line, MAX_INPUT_LINE_SZ, file)) {
		char *line2 = line;
		pos2.linenum++;

		/*
		 * In SMBUSERS format there can be more mappings on
		 * each line. So we need the internal cycle for each line.
		 */
		do {
			nm = name_mapping_init();
			if (nm == NULL) {
				rc = -1;
				goto cleanup;
			}

			rc = line2nm(line2, &pos2, nm, format);
			line2 = NULL;

			if (rc < 1) {
				name_mapping_fini(nm);
				break;
			}

			stat = idmap_udt_add_namerule(udt, nm->windomain,
			    nm->is_user ? B_TRUE : B_FALSE, nm->winname,
			    nm->unixname, nm->is_nt4, nm->direction);
			if (stat < 0) {
				print_error(&pos2,
				    gettext("Transaction error (%s)\n"),
				    idmap_stat2string(handle, stat));
				rc = -1;
			}

			if (rc >= 0)
				rc = positions_add(&pos2);

			name_mapping_fini(nm);

		} while (rc >= 0);

		if (rc < 0) {
			print_error(NULL,
			    gettext("Import canceled.\n"));
			break;
		}
	}

cleanup:
	if (fini_udt_command((rc < 0 ? 0 : 1), pos))
		rc = -1;
	if (file != NULL && file != stdin)
		(void) fclose(file);
	return (rc);
}


/*
 * List name mappings in the format specified. list_users /
 * list_groups determine which type to list. The output goes to the
 * file fi.
 */
static int
list_name_mappings(format_t format, FILE *fi)
{
	idmap_stat stat;
	idmap_iter_t *ihandle;
	name_mapping_t *nm;
	int is_user;

	for (is_user = I_YES; is_user >= I_NO; is_user--) {
		/* Only users can be in USERMAP_CFG format, not a group */
		if (!is_user && format == USERMAP_CFG)
			continue;

		stat = idmap_iter_namerules(handle, NULL, is_user, NULL,
		    NULL, &ihandle);
		if (stat < 0) {
			print_error(NULL,
			    gettext("Iteration handle not obtained (%s)\n"),
			    idmap_stat2string(handle, stat));
			idmap_iter_destroy(ihandle);
			return (-1);
		}

		(void) print_mapping_init(format, fi);

		do {
			nm = name_mapping_init();
			if (nm == NULL) {
				idmap_iter_destroy(ihandle);
				return (-1);
			}

			stat = idmap_iter_next_namerule(ihandle, &nm->windomain,
			    &nm->winname, &nm->unixname, &nm->is_nt4,
			    &nm->direction);
			if (stat >= 0) {
				nm->is_user = is_user;
				(void) print_mapping(nm);
			}

			name_mapping_fini(nm);

		} while (stat > 0);

		(void) print_mapping_fini();

		if (stat < 0 && stat !=  IDMAP_ERR_NOTFOUND) {
			print_error(NULL,
			    gettext("Error during iteration (%s)\n"),
			    idmap_stat2string(handle, stat));
			idmap_iter_destroy(ihandle);
			return (-1);
		}

		idmap_iter_destroy(ihandle);
	}
	return (0);
}

/* Export command handler  */
static int
/* LINTED E_FUNC_ARG_UNUSED */
do_export(flag_t *f, int argc, char **argv, cmd_pos_t *pos) {
	int rc;
	format_t format;
	FILE *fi;

	format = ff2format(argv[0], 1);
	if (format == UNDEFINED_FORMAT)
		return (-1);

	/* Where do we output to? */
	if (f[f_FLAG] == NULL)
		fi = stdout;
	else {
		fi = fopen(f[f_FLAG], "w");
		if (fi == NULL) {
			perror(f[f_FLAG]);
			return (-1);
		}
	}

	if (init_command() < 0) {
		rc = -1;
		goto cleanup;
	}

	/* List the requested types: */
	rc = list_name_mappings(format, fi);

	fini_command();

cleanup:
	if (fi != NULL && fi != stdout)
		(void) fclose(fi);
	return (rc);
}

/* List command handler */
static int
/* LINTED E_FUNC_ARG_UNUSED */
do_list_name_mappings(flag_t *f, int argc, char **argv, cmd_pos_t *pos)
{
	int rc;

	if (init_command()) {
		return (-1);
	}

	/* List the requested types: */
	rc = list_name_mappings(DEFAULT_FORMAT, stdout);

	fini_command();
	return (rc);
}

/* This is just a debug function for dumping flags */
static void
print_flags(flag_t *f)
{
	int c;
	for (c = 0; c < FLAG_ALPHABET_SIZE; c++) {
		if (f[c] == FLAG_SET)
			(void) printf("FLAG: -%c, VALUE: %p\n", c,
			    (void *) f[c]);
		else if (f[c])
			(void) printf("FLAG: -%c, VALUE: %s\n", c, f[c]);
	}
}

/*
 * This function splits name to the relevant pieces: is_user, winname,
 * windomain unixname. Sometimes it is not possible to determine OS
 * side, because it could be determined by the opposite name in idmap
 * show. So this function must be called several times.
 *
 * Return values: -1 ... clear syntax error
 *                0  ... it wasnt possible to determine
 *                1  ... determined
 */
static int
name2parts(char *name, name_mapping_t *nm, cmd_pos_t *pos) {
	char *it;
	int is_win = I_NO;
	int is_unix = I_NO;

	if (nm->winname != NULL && nm->unixname != NULL)
		return (0);

	/* If it starts with type string, that is easy: */
	if (it = strchr(name, ':')) {
		if (strcmp_no0(name, ID_UNIXUSER ":") == 0) {
			if (nm->is_user == I_NO) {
				print_error(pos,
				    gettext("%s - invalid combination of user"
					" and group identity types.\n"),
				    ID_UNIXUSER);
				return (-1);
			}
			if (nm->unixname != NULL)
				return (0);

			nm->is_user = I_YES;
			is_unix = I_YES;

		} else if (strcmp_no0(name, ID_UNIXGROUP ":") == 0) {
			if (nm->is_user == I_YES) {
				print_error(pos,
				    gettext("%s - invalid combination of user"
					" and group identity types.\n"),
				    ID_UNIXGROUP);
				return (-1);
			}
			if (nm->unixname != NULL)
				return (0);

			nm->is_user = I_NO;
			is_unix = I_YES;

		} else if (strcmp_no0(name, ID_WINUSER ":") == 0) {
			if (nm->is_user == I_NO) {
				print_error(pos,
				    gettext("%s - invalid combination of user"
					" and group identity types.\n"),
				    ID_WINUSER);
				return (-1);
			}
			if (nm->winname != NULL)
				return (0);

			nm->is_user = I_YES;
			is_win = I_YES;

		} else if (strcmp_no0(name, ID_WINGROUP ":") == 0) {
			if (nm->is_user == I_YES) {
				print_error(pos,
				    gettext("%s - invalid combination of user"
					" and group identity types.\n"),
				    ID_WINGROUP);
				return (-1);
			}
			if (nm->winname != NULL)
				return (0);

			nm->is_user = I_NO;
			is_win = I_YES;

		} else if (strcmp_no0(name, ID_WINNAME ":") == 0) {
			if (nm->winname != NULL)
				return (0);
			is_win = I_YES;
		} else {
			print_error(pos,
			    gettext("Error: invalid identity type \"%.*s\"\n"),
			    it - name, name);
			return (-1);
		}
		name = it + 1;
	}

	/* If it contains '@' or '\\', then it is a winname with domain */
	if (!is_unix && nm->winname == NULL) {
		if ((it = strchr(name, '@')) != NULL) {
			int length = it - name + 1;
			nm->winname = (char *)malloc(length * sizeof (char));
			(void) strncpy(nm->winname, name, length - 1);
			nm->winname[length - 1] = '\0';
			nm->windomain = strdup(it + 1);
			return (1);
		} else if ((it = strrchr(name, '\\')) != NULL) {
			int length = it - name + 1;
			nm->windomain = (char *)malloc(length * sizeof (char));
			(void) strncpy(nm->windomain, name, length - 1);
			nm->windomain[length - 1] = '\0';
			nm->winname = strdup(it + 1);
			nm->is_nt4 = B_TRUE;
			return (1);
		}
	}

	/*
	 * if is_unix/is_win is not yet determined, then the last
	 * hope is that the opposite side is known already. In that
	 * case, it is the only remaining side.
	 */
	if (is_unix || nm->unixname == NULL && nm->winname != NULL) {
		if (strlen(name) == 0)
			nm->unixname = strdup("\"\"");
		else
			nm->unixname = strdup(name);
		return (1);
	} else if (is_win || nm->unixname != NULL && nm->winname == NULL) {
		if (strlen(name) == 0)
			nm->winname = strdup("\"\"");
		else
			nm->winname = strdup(name);
		nm->windomain = NULL;
		return (1);
	}

	return (0);
}

/* add command handler. */
static int
do_add_name_mapping(flag_t *f, int argc, char **argv, cmd_pos_t *pos)
{
	name_mapping_t *nm;
	int rc = 0;
	int i;
	int is_argv0_unix = -1;
	idmap_stat stat;


	/* Exactly two arguments must be specified */
	if (argc < 2) {
		print_error(pos, gettext("Not enough arguments.\n"));
		return (-1);
	} else if (argc > 2)  {
		print_error(pos, gettext("Too many arguments.\n"));
		return (-1);
	}

	/*
	 * Direction can be determined by the opposite name, so we
	 * need to run name2parts twice for the first name, i.e. 3x in
	 * total.
	 */
	nm = name_mapping_init();
	if (nm == NULL)
		return (-1);

	for (i = 0; i < 3; i++) {
		switch (name2parts(argv[i % 2], nm, pos)) {
		case -1:
			name_mapping_fini(nm);
			return (-1);
		case 1:
			if (is_argv0_unix < 0)
				is_argv0_unix =
				    i % 2 ^ (nm->unixname != NULL ? 1 : 0);
			break;
		}
	}

	if (nm->winname == NULL || nm->unixname == NULL) {
		print_error(pos, gettext("Name types not determined.\n"));
		name_mapping_fini(nm);
		return (-1);
	}

	if (f[d_FLAG] != NULL)
		nm->direction = is_argv0_unix
		    ? IDMAP_DIRECTION_U2W
		    : IDMAP_DIRECTION_W2U;
	else
		nm->direction = IDMAP_DIRECTION_BI;

	/* Now let us write it: */

	if (init_udt_command()) {
		name_mapping_fini(nm);
		return (-1);
	}

	stat = idmap_udt_add_namerule(udt, nm->windomain,
	    nm->is_user ? B_TRUE : B_FALSE, nm->winname, nm->unixname,
	    nm->is_nt4, nm->direction);

	/* We echo the mapping */
	(void) print_mapping_init(DEFAULT_FORMAT, stdout);
	(void) print_mapping(nm);
	(void) print_mapping_fini();

	if (stat < 0) {
		print_error(pos,
		    gettext("Mapping not created (%s)\n"),
		    idmap_stat2string(handle, stat));
		rc = -1;
	}

	if (rc == 0)
		rc = positions_add(pos);

cleanup:
	name_mapping_fini(nm);
	if (fini_udt_command(1, pos))
		rc = -1;
	return (rc);
}

/* remove command handler */
static int
do_remove_name_mapping(flag_t *f, int argc, char **argv, cmd_pos_t *pos)
{
	name_mapping_t *nm;
	int rc = 0;
	int i;
	int is_argv0_unix = -1;
	idmap_stat stat;
	int is_user;

	/* "-a" means we flush all of them */
	if (f[a_FLAG] != NULL) {
		if (argc) {
			print_error(pos,
			    gettext("Too many arguments.\n"));
			return (-1);
		}

		if (init_udt_command())
			return (-1);
		rc = flush_nm(B_TRUE, pos);

		if (rc >= 0)
			rc = flush_nm(B_FALSE, pos);

		if (fini_udt_command(rc ? 0 : 1, pos))
			rc = -1;
		return (rc);
	}

	/* Contrary to add_name_mapping, we can have only one argument */
	if (argc < 1) {
		print_error(pos, gettext("Not enough arguments.\n"));
		return (-1);
	} else if (argc > 2) {
		print_error(pos, gettext("Too many arguments.\n"));
		return (-1);
	} else if (
		/* both -f and -t: */
	    f[f_FLAG] != NULL && f[t_FLAG] != NULL ||
		/* -d with a single argument: */
	    argc == 1 && f[d_FLAG] != NULL ||
		/* -f or -t with two arguments: */
	    argc == 2 && (f[f_FLAG] != NULL || f[t_FLAG] != NULL)) {
		print_error(pos,
		    gettext("Direction ambiguous.\n"));
		return (-1);
	}


	/*
	 * Similar to do_add_name_mapping - see the comments
	 * there. Except we may have only one argument here.
	 */
	nm = name_mapping_init();
	if (nm == NULL)
		return (-1);

	for (i = 0; i < 2 * argc - 1; i++) {
		switch (name2parts(argv[i % 2], nm, pos)) {
		case -1:
			name_mapping_fini(nm);
			return (-1);
		case 1:
			if (is_argv0_unix < 0)
				is_argv0_unix = i % 2 ^ (nm->unixname ? 1 : 0);
			break;
		}
	}


	if (nm->winname == NULL && nm->unixname == NULL) {
		print_error(pos, gettext("Name types not determined.\n"));
		name_mapping_fini(nm);
		return (-1);
	}

	/*
	 * If the direction is not specified by a -d/-f/-t flag, then it
	 * is IDMAP_DIRECTION_UNDEF, because in that case we want to
	 * remove any mapping. If it was IDMAP_DIRECTION_BI, idmap_api would
	 * delete a bidirectional one only.
	 */
	if (f[d_FLAG] != NULL || f[f_FLAG] != NULL)
		nm->direction = is_argv0_unix
		    ? IDMAP_DIRECTION_U2W
		    : IDMAP_DIRECTION_W2U;
	else if (f[t_FLAG] != NULL)
		nm->direction = is_argv0_unix
		    ? IDMAP_DIRECTION_W2U
		    : IDMAP_DIRECTION_U2W;
	else
		nm->direction = IDMAP_DIRECTION_UNDEF;

	if (init_udt_command()) {
		name_mapping_fini(nm);
		return (-1);
	}

	for (is_user = I_YES; is_user >= I_NO; is_user--) {
		if ((is_user == I_YES && nm->is_user == I_NO) ||
		    (is_user == I_NO && nm->is_user == I_YES))
			continue;

		stat = idmap_udt_rm_namerule(udt, is_user ? B_TRUE : B_FALSE,
		    nm->windomain, nm->winname, nm->unixname, nm->direction);

		if (stat < 0) {
			print_error(pos,
			    gettext("Mapping not deleted (%s)\n"),
			    idmap_stat2string(handle, stat));
			rc = -1;
			break;
		}
	}

	if (rc == 0)
		rc = positions_add(pos);

cleanup:
	name_mapping_fini(nm);
	if (fini_udt_command(1, pos))
		rc = -1;
	return (rc);
}


/* exit command handler */
static int
/* LINTED E_FUNC_ARG_UNUSED */
do_exit(flag_t *f, int argc, char **argv, cmd_pos_t *pos) {
	return (0);
}


/* debug command handler: just print the parameters */
static int
/* LINTED E_STATIC_UNUSED */
debug_print_params(flag_t *f, int argc, char **argv, cmd_pos_t *pos)
{
	int i;
#if 0
	char *leaktest = (char *)malloc(100);
#endif

	print_flags(f);

	for (i = 0; i < argc; i++) {
		(void) printf("Argument %d: %s\n", i, argv[i]);
	}

	(void) fflush(stdout);
	return (0);
}

/*
 * Return a pointer after a given prefix. If there is no such prefix,
 * return NULL
 */
static char *
get_root(char *string, char *typestring) {
	if (strcasecmp_no0(string, typestring) != 0)
		return (NULL);
	return (string + strlen(typestring));
}

/*
 * From name_mapping_t, asseble a string containing identity of the
 * given type.
 */
static int
nm2type(name_mapping_t *nm, int type, char **to) {
	switch (type) {
	case TYPE_SID:
		if (nm->sidprefix == NULL)
			return (-1);
		*to = sid_format(nm->sidprefix, nm->rid);
		return (0);
	case TYPE_WN:
	case TYPE_WU:
	case TYPE_WG:
		return (nm2winqn(nm, to));
	case TYPE_UID:
	case TYPE_GID:
	case TYPE_PID:
		*to = pid_format(nm->pid, nm->is_user);
		if (*to == NULL)
			return (-1);
		else
			return (0);
	case TYPE_UN:
	case TYPE_UU:
	case TYPE_UG:
		return (nm2unixname(nm, to));
	default:
		/* This can never happen: */
		print_error(NULL,
		    gettext("Internal error: invalid name type.\n"));
		return (-1);
	}
	/* never reached */
}

/* show command handler */
static int
do_show_mapping(flag_t *f, int argc, char **argv, cmd_pos_t *pos)
{
	idmap_stat stat = 0;
	int flag;
	idmap_stat map_stat = 0;
	int type_from;
	int type_to;
	char *root;
	name_mapping_t *nm = NULL;
	char *fromname;
	char *toname;

	if (argc == 0) {
		print_error(pos,
		    gettext("No identity given\n"));
		return (-1);
	} else if (argc > 2) {
		print_error(pos,
		    gettext("Too many arguments.\n"));
		return (-1);
	}

	flag = f[c_FLAG] != NULL ? 0 : IDMAP_REQ_FLG_NO_NEW_ID_ALLOC;

	if (init_command())
		return (-1);

	nm = name_mapping_init();
	if (nm == NULL)
		goto cleanup;

	/* First, determine type_from: */
	if ((root = get_root(argv[0], ID_UID ":")) != NULL)
		type_from = TYPE_UID;
	else if ((root = get_root(argv[0], ID_GID ":")) != NULL)
		type_from = TYPE_GID;
	else if ((root = get_root(argv[0], ID_SID ":")) != NULL)
		type_from = TYPE_SID;
	else
		switch (name2parts(argv[0], nm, pos)) {
		case 1:		/* name2parts determined the type */
			if (nm->unixname != NULL)
				switch (nm->is_user) {
				case I_YES:
					type_from = TYPE_UU;
					break;
				case I_NO:
					type_from = TYPE_UG;
					break;
				default:
					type_from = TYPE_UN;
				}
			else
				switch (nm->is_user) {
				case I_YES:
					type_from = TYPE_WU;
					break;
				case I_NO:
					type_from = TYPE_WG;
					break;
				default:
					type_from = TYPE_WN;
				}
			break;
		case 0:		/* name2parts didn't determine the type: */
			print_error(pos, gettext("Invalid type.\n"));
			/* LINTED E_CASE_FALLTHRU */
		case -1:
			stat = IDMAP_ERR_ARG;
			goto cleanup;
		}

	/* Second, determine type_to: */
	if (argc < 2) {
		type_to = type_from & IS_WIN ? TYPE_PID : TYPE_SID;
		if (type_from & IS_NAME)
			type_to |= IS_NAME;
	} else if (strcasecmp(argv[1], ID_UID) == 0)
		type_to = TYPE_UID;
	else if (strcasecmp(argv[1], ID_GID) == 0)
		type_to = TYPE_GID;
	else if (strcasecmp(argv[1], ID_SID) == 0)
		type_to = TYPE_SID;
	else if (strcmp(argv[1], ID_UNIXUSER) == 0)
		type_to = TYPE_UU;
	else if (strcmp(argv[1], ID_UNIXGROUP) == 0)
		type_to = TYPE_UG;
	else if (strcmp(argv[1], ID_WINNAME) == 0)
		type_to = TYPE_WN;
	else if (strcmp(argv[1], ID_WINUSER) == 0)
		type_to = TYPE_WU;
	else if (strcmp(argv[1], ID_WINGROUP) == 0)
		type_to = TYPE_WG;
	else {
		print_error(pos,
		    gettext("Invalid target type.\n"));
		stat = IDMAP_ERR_ARG;
		goto cleanup;
	}

	/* Are both arguments the same OS side? */
	if (!(type_from & IS_WIN ^ type_to & IS_WIN)) {
		print_error(pos,
		    gettext("Direction ambiguous.\n"));
		stat = IDMAP_ERR_ARG;
		goto cleanup;
	}

	/* Are both arguments the same userness/groupness? */
	if ((type_from & IS_USER) && (type_to & IS_GROUP)) {
		print_error(pos,
		    gettext("Mapping of user to group impossible.\n"));
		stat = IDMAP_ERR_ARG;
		goto cleanup;
	} else if ((type_from & IS_GROUP) && (type_to & IS_USER)) {
		print_error(pos,
		    gettext("Mapping of group to user impossible.\n"));
		stat = IDMAP_ERR_ARG;
		goto cleanup;
	}

	if (type_from == TYPE_SID) {
		if (!sid_convert(root, &nm->sidprefix, &nm->rid, pos)) {
			stat = IDMAP_ERR_ARG;
			goto cleanup;
		}
	} else if (type_from == TYPE_UID || type_from == TYPE_GID) {
		if (!pid_convert(root, &nm->pid, type_from, pos)) {
			stat = IDMAP_ERR_ARG;
			goto cleanup;
		}
	}

/*
 * We have two interfaces for retrieving the mappings:
 * idmap_get_sidbyuid & comp (the batch interface) and
 * idmap_get_w2u_mapping & comp. We  want to use both of them, because
 * the former mimicks kernel interface better and the later offers the
 * string names. In the batch case, our batch has always size 1.
 */
	if (type_from & IS_NAME || type_to & IS_NAME) {
		if (type_from & IS_WIN) {
			if (type_to == TYPE_UID)
				nm->is_user = I_YES;
			else if (type_to == TYPE_GID)
			nm->is_user = I_NO;

			map_stat = idmap_get_w2u_mapping(handle,
			    nm->sidprefix,
			    &nm->rid,
			    nm->winname,
			    nm->windomain,
			    flag,
			    &nm->is_user,
			    &nm->pid,
			    &nm->unixname,
			    &nm->direction);
		} else {
			if (type_from == TYPE_UID)
				nm->is_user = I_YES;
			else if (type_from == TYPE_GID)
				nm->is_user = I_NO;

			map_stat = idmap_get_u2w_mapping(handle,
			    &nm->pid,
			    nm->unixname,
			    flag,
			    nm->is_user,
			    &nm->sidprefix,
			    &nm->rid,
			    &nm->winname,
			    &nm->windomain,
			    &nm->direction);
		}

	} else {
		/* batch handle */
		idmap_get_handle_t *ghandle = NULL;
		/* To be passed to idmap_get_uidbysid  */
		gid_t gid = UNDEFINED_GID;
		/* To be passed to idmap_get_gidbysid  */
		uid_t uid = UNDEFINED_UID;


		/* Create an in-memory structure for all the batch: */
		stat = idmap_get_create(handle, &ghandle);
		if (stat < 0) {
			print_error(pos,
			    gettext("Unable to create handle for communicating"
			    " with idmapd(1M) (%s)\n"),
			    idmap_stat2string(handle, stat));
			idmap_get_destroy(ghandle);
			goto cleanup;
		}

		/* Schedule the request: */
		if (type_from == TYPE_SID && type_to == TYPE_UID) {
			stat = idmap_get_uidbysid(ghandle,
			    nm->sidprefix,
			    nm->rid,
			    flag,
			    &uid,
			    &map_stat);
			nm->is_user = I_YES;
		} else if (type_from == TYPE_SID && type_to == TYPE_GID) {
			stat =  idmap_get_gidbysid(ghandle,
			    nm->sidprefix,
			    nm->rid,
			    flag,
			    &gid,
			    &map_stat);
			nm->is_user = I_NO;
		} else if (type_from == TYPE_SID && type_to == TYPE_PID)
			stat = idmap_get_pidbysid(ghandle,
			    nm->sidprefix,
			    nm->rid,
			    flag,
			    &nm->pid,
			    &nm->is_user,
			    &map_stat);
		else if (type_from == TYPE_UID && type_to == TYPE_SID) {
			stat = idmap_get_sidbyuid(ghandle,
			    nm->pid,
			    flag,
			    &nm->sidprefix,
			    &nm->rid,
			    &map_stat);
			nm->is_user = I_YES;
		} else if (type_from == TYPE_GID && type_to == TYPE_SID) {
			stat = idmap_get_sidbygid(ghandle,
			    (gid_t)nm->pid,
			    flag,
			    &nm->sidprefix,
			    &nm->rid,
			    &map_stat);
			nm->is_user = I_NO;
		} else {
			/* This can never happen: */
			print_error(pos,
			    gettext("Internal error in show.\n"));
			exit(1);
		}

		if (stat < 0) {
			print_error(pos,
			    gettext("Request for %.3s not sent (%s)\n"),
			    argv[0], idmap_stat2string(handle, stat));
			idmap_get_destroy(ghandle);
			goto cleanup;
		}

		/* Send the batch to idmapd and obtain results: */
		stat = idmap_get_mappings(ghandle);
		if (stat < 0) {
			print_error(pos,
			    gettext("Mappings not obtained because of"
			    " RPC problem (%s)\n"),
			    idmap_stat2string(handle, stat));
			idmap_get_destroy(ghandle);
			goto cleanup;
		}

		/* Destroy the batch handle: */
		idmap_get_destroy(ghandle);

		if (type_to == TYPE_UID)
			nm->pid = uid;
		else if (type_to == TYPE_GID)
			nm->pid = (uid_t)gid;

	}

	/*
	 * If there was -c flag, we do output whatever we can even in
	 * the case of error:
	 */
	if (map_stat < 0) {
		print_error(pos,
		    gettext("%s\n"),
		    idmap_stat2string(handle, map_stat));
		if (flag == IDMAP_REQ_FLG_NO_NEW_ID_ALLOC)
			goto cleanup;
	}


	/*
	 * idmapd returns fallback uid/gid in case of errors. However
	 * it uses special sentinel value i.e 4294967295 (or -1) to
	 * indicate that falbback pid is not available either. In such
	 * case idmap(1M) should not display the mapping because there
	 * is no fallback mapping.
	 */

	if (type_to == TYPE_UID && nm->pid == UNDEFINED_UID ||
	    type_to == TYPE_GID && nm->pid == (uid_t)UNDEFINED_GID) {
		goto cleanup;
	}

	if (nm2type(nm, type_from, &fromname) < 0)
		goto cleanup;

	if (nm2type(nm, type_to, &toname) < 0) {
		if (flag == 0)
			(void) printf("%s -> %s:%u\n",
			    fromname,
			    (type_from | type_to) & IS_GROUP ? ID_GID : ID_UID,
			    UID_NOBODY);
		free(fromname);
		goto cleanup;
	}

	(void) printf("%s -> %s\n", fromname, toname);
	free(fromname);
	free(toname);

cleanup:
	if (nm != NULL)
		name_mapping_fini(nm);
	fini_command();
	return (stat < 0 || map_stat < 0 ? -1 : 0);
}

/* main function. Returns 1 for error, 0 otherwise */
int
main(int argc, char *argv[]) {
	int rc;

	/* set locale and domain for internationalization */
	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);

	/* idmap_engine determines the batch_mode: */
	rc = engine_init(sizeof (commands) / sizeof (cmd_ops_t),
		commands,
		argc - 1,
		argv + 1,
		&batch_mode);

	if (rc < 0) {
		(void) engine_fini();
		if (rc == IDMAP_ENG_ERROR_SILENT)
			help();
		return (1);
	}

	udt_used = 0;
	if (batch_mode) {
		if (init_udt_batch() < 0)
			return (1);
	}

	rc = run_engine(argc - 1, argv + 1);

	if (batch_mode) {
		batch_mode = 0;
		if (fini_udt_command(rc == 0 ? 1 : 0, NULL))
			rc = -1;
	}

	(void) engine_fini();
	return (rc == 0 ? 0 : 1);
}
