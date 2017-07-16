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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <locale.h>
#include <strings.h>
#include <errno.h>
#include <limits.h>
#include <syslog.h>
#include <stdarg.h>
#include <note.h>
#include "idmap_engine.h"
#include "idmap_priv.h"
#include "namemaps.h"
#include "libadutils.h"

/* Initialization values for pids/rids: */

#define	UNDEFINED_UID (uid_t)-1
#define	UNDEFINED_GID (gid_t)-1
#define	UNDEFINED_RID (idmap_rid_t)-1;

#define	CHECK_NULL(s)	(s != NULL ? s : "null")
/*
 * used in do_show for the type of argument, which can be winname,
 * unixname, uid, gid, sid or not given at all:
 */

#define	TYPE_SID	0x010	/* sid */
#define	TYPE_USID	0x011	/* usid */
#define	TYPE_GSID	0x012	/* gsid */
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

#define	TYPE_INVALID    0x1000	/* Invalid input */
#define	TYPE_AUTO	0xaaa	/* Autodetection required */

/* Identity type strings */

#define	ID_WINNAME	"winname"
#define	ID_UNIXUSER	"unixuser"
#define	ID_UNIXGROUP	"unixgroup"
#define	ID_WINUSER	"winuser"
#define	ID_WINGROUP	"wingroup"
#define	ID_USID	"usid"
#define	ID_GSID	"gsid"
#define	ID_SID	"sid"
#define	ID_UID	"uid"
#define	ID_GID	"gid"

#define	ID_UNKNOWN	"unknown"

#define	INHIBITED(str)	(str == NULL || *str == 0 || strcmp(str, "\"\"") == 0)

typedef struct {
	char *identity;
	int code;
} id_code_t;

id_code_t identity2code[] = {
	{ID_WINNAME,	TYPE_WN},
	{ID_UNIXUSER,	TYPE_UU},
	{ID_UNIXGROUP,	TYPE_UG},
	{ID_WINUSER,	TYPE_WU},
	{ID_WINGROUP,	TYPE_WG},
	{ID_USID,	TYPE_USID},
	{ID_GSID,	TYPE_GSID},
	{ID_SID,	TYPE_SID},
	{ID_UID,	TYPE_UID},
	{ID_GID,	TYPE_GID}
};


/* Flags */

#define	f_FLAG	'f'
#define	t_FLAG	't'
#define	d_FLAG	'd'
#define	D_FLAG	'D'
#define	F_FLAG	'F'
#define	a_FLAG	'a'
#define	n_FLAG	'n'
#define	c_FLAG	'c'
#define	v_FLAG	'v'
#define	V_FLAG	'V'
#define	j_FLAG	'j'


/* used in the function do_import */
#define	MAX_INPUT_LINE_SZ 2047


typedef struct {
	int is_user;
	int is_wuser;
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


typedef struct {
	format_t format;
	FILE *file;
	name_mapping_t *last;
} print_handle_t;

/*
 * idmap_api batch related variables:
 *
 * idmap can operate in two modes. It the batch mode, the idmap_api
 * batch is committed at the end of a batch of several
 * commands. At the end of input file, typically. This mode is used
 * for processing input from a file.
 *  In the non-batch mode, each command is committed immediately. This
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
static idmap_udt_handle_t *udt = NULL;

typedef struct {
	char *user;
	char *passwd;
	char *auth;
	char *windomain;
	int direction;
	idmap_nm_handle_t *handle;
} namemaps_t;

static namemaps_t namemaps = {NULL, NULL, NULL, NULL, 0, NULL};


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
static int do_flush(flag_t *f, int argc, char **argv, cmd_pos_t *pos);
static int do_exit(flag_t *f, int argc, char **argv, cmd_pos_t *pos);
static int do_export(flag_t *f, int argc, char **argv, cmd_pos_t *pos);
static int do_help(flag_t *f, int argc, char **argv, cmd_pos_t *pos);
static int do_set_namemap(flag_t *f, int argc, char **argv, cmd_pos_t *pos);
static int do_unset_namemap(flag_t *f, int argc, char **argv, cmd_pos_t *pos);
static int do_get_namemap(flag_t *f, int argc, char **argv, cmd_pos_t *pos);


/* Command names and their handlers to be passed to idmap_engine */

static cmd_ops_t commands[] = {
	{
		"show",
		"c(create)v(verbose)V(trace)",
		do_show_mapping
	},
	{
		"dump",
		"n(names)v(verbose)",
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
		"flush",
		"a(all)",
		do_flush
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
	},
	{
		"set-namemap",
		"a:(authentication)D:(bindDN)j:(passwd-file)",
		do_set_namemap
	},
	{
		"get-namemap",
		"",
		do_get_namemap
	},
	{
		"unset-namemap",
		"a:(authentication)D:(bindDN)j:(passwd-file):",
		do_unset_namemap
	}
};


/* Print error message, possibly with a position */
/* printflike */
static void
print_error(cmd_pos_t *pos, const char *format, ...)
{
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
init_positions()
{
	int init_size = 32; /* Initial size of the positions array */

	positions = (struct pos_sds *) malloc(sizeof (struct pos_sds) +
	    (init_size - 1) * sizeof (cmd_pos_t *));

	if (positions == NULL) {
		print_error(NULL, "%s.\n", strerror(ENOMEM));
		return (-1);
	}

	positions->size = init_size;
	positions->last = 0;
	return (0);
}

/* Free the positions array */
static void
fini_positions()
{
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
positions_add(cmd_pos_t *pos)
{
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
	print_error(NULL, "%s.\n", strerror(ENOMEM));
	return (-1);
}




/*
 * Compare two strings just like strcmp, but stop before the end of
 * the s2
 */
static int
strcmp_no0(const char *s1, const char *s2)
{
	return (strncmp(s1, s2, strlen(s2)));
}

/* Print help message */
static void
help()
{
	(void) fprintf(stderr,
	    "idmap\n"
	    "idmap -f command-file\n"
	    "idmap add [-d] name1 name2\n"
	    "idmap dump [-n] [-v]\n"
	    "idmap export [-f file] format\n"
	    "idmap flush [-a]\n"
	    "idmap get-namemap name\n"
	    "idmap help\n"
	    "idmap import [-F] [-f file] format\n"
	    "idmap list\n"
	    "idmap remove -a\n"
	    "idmap remove [-f|-t] name\n"
	    "idmap remove [-d] name1 name2\n"
	    "idmap set-namemap [-a authenticationMethod] [-D bindDN]\n"
	    "    [-j passwdfile] name1 name2\n"
	    "idmap show [-c] [-v] identity [targettype]\n"
	    "idmap unset-namemap [-a authenticationMethod] [-D bindDN]\n"
	    "    [-j passwdfile] name [targettype]\n");
}

/* The handler for the "help" command. */
static int
/* LINTED E_FUNC_ARG_UNUSED */
do_help(flag_t *f, int argc, char **argv, cmd_pos_t *pos)
{
	help();
	return (0);
}

/* Initialization of the commands which perform write operations  */
static int
init_udt_batch()
{
	idmap_stat stat;

	stat = idmap_udt_create(&udt);
	if (stat != IDMAP_SUCCESS) {
		print_error(NULL,
		    gettext("Error initiating transaction (%s)"),
		    idmap_stat2string(stat));
		return (-1);
	}

	if (init_positions() < 0)
		return (-1);

	return (0);
}


/* Finalization of the write commands  */
static int
init_udt_command()
{
	udt_used = 1;
	if (batch_mode)
		return (0);

	return (init_udt_batch());
}


/* If everythings is OK, send the udt batch to idmapd  */
static int
fini_udt_command(int ok, cmd_pos_t *pos)
{
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
			    idmap_stat2string(stat1));
			goto out;
		}


		if (failpos < 0)
			reported_pos = pos;
		else
			reported_pos = positions->pos[failpos];

		print_error(reported_pos,
		    gettext("Error commiting transaction (%s)\n"),
		    idmap_stat2string(stat));
	}

out:
	idmap_udt_destroy(udt);
	udt = NULL;
	udt_used = 0;
	fini_positions();
	return (rc);
}


/*
 * Compare two possibly NULL strings
 */
static int
strcasecmp_null(char *a, char *b)
{
	if (a == NULL && b == NULL)
		return (0);
	if (a == NULL)
		return (-1);
	if (b == NULL)
		return (1);
	return (strcasecmp(a, b));
}

/*
 * Compare two possibly NULL strings
 */
static int
strcmp_null(char *a, char *b)
{
	if (a == NULL && b == NULL)
		return (0);
	if (a == NULL)
		return (-1);
	if (b == NULL)
		return (1);
	return (strcmp(a, b));
}

static void
free_null(char **ptr)
{
	if (*ptr != NULL) {
		free(*ptr);
		*ptr = NULL;
	}
}

static
void
namemaps_free()
{
	free_null(&namemaps.user);

	if (namemaps.passwd != NULL)
		(void) memset(namemaps.passwd, 0, strlen(namemaps.passwd));

	free_null(&namemaps.passwd);
	free_null(&namemaps.auth);
	free_null(&namemaps.windomain);

	namemaps.direction = IDMAP_DIRECTION_UNDEF;
	if (namemaps.handle != NULL) {
		idmap_fini_namemaps(namemaps.handle);
		namemaps.handle = NULL;
	}
}

/* Initialization of the commands which perform write operations  */
static
int
init_nm_command(char *user, char *passwd, char *auth, char *windomain,
    int direction, cmd_pos_t *pos)
{
	idmap_stat stat;

	if (namemaps.handle != NULL && (
	    strcmp_null(user, namemaps.user) != 0 ||
	    strcmp_null(passwd, namemaps.passwd) != 0 ||
	    strcasecmp_null(auth, namemaps.auth) != 0 ||
	    strcasecmp_null(windomain, namemaps.windomain) != 0 ||
	    direction != namemaps.direction)) {
		namemaps_free();
	}

	if (namemaps.handle == NULL) {
		stat = idmap_init_namemaps(&namemaps.handle, user,
		    passwd, auth, windomain, direction);
		if (stat != IDMAP_SUCCESS) {
			print_error(pos,
			    gettext("Error: could not perform directory-based "
			    "name mapping operation (%s)"),
			    idmap_stat2string(stat));
			namemaps_free();
			return (-1);
		}

		if (user != NULL && (namemaps.user = strdup(user)) == NULL ||
		    passwd != NULL && (namemaps.passwd =
		    strdup(passwd)) == NULL ||
		    auth != NULL && (namemaps.auth = strdup(auth)) == NULL ||
		    windomain != NULL && (namemaps.windomain =
		    strdup(windomain)) == NULL) {
			print_error(pos, "%s.\n", strerror(ENOMEM));
			namemaps_free();
			return (-1);
		}
		namemaps.direction = direction;

	}

	return (0);
}


/* Cleanup after the xxx-namemaps commands  */
static void
fini_nm_command()
{
	if (batch_mode)
		return;

	namemaps_free();
}


/* Convert numeric expression of the direction to it's string form */
static char *
direction2string(int direction)
{
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
is_shell_special(char c)
{
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
is_dq_special(char c)
{
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
shell_app(char **res, char *string, int quote)
{
	int i, j;
	uint_t noss = 0; /* Number Of Shell Special chars in the input */
	uint_t noqb = 0; /* Number Of Quotes and Backslahes in the input */
	char *out;
	size_t len_orig = strlen(string);
	size_t len;

	if (INHIBITED(string)) {
		out = strdup("\"\"");
		if (out == NULL) {
			print_error(NULL, "%s.\n", strerror(ENOMEM));
			return (-1);
		}
		*res = out;
		return (0);
	}

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
			print_error(NULL, "%s.\n", strerror(ENOMEM));
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

	out = (char *)malloc(len);
	if (out == NULL) {
		print_error(NULL, "%s.\n", strerror(ENOMEM));
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
sid_format(name_mapping_t *nm)
{
	char *to;
	size_t len;
	char *typestring;

	switch (nm->is_wuser) {
	case IDMAP_YES:
		typestring = ID_USID;
		break;
	case IDMAP_NO:
		typestring = ID_GSID;
		break;
	default:
		typestring = ID_SID;
		break;
	}

	/* 'usid:' + sidprefix + '-' + rid + '\0' */
	len = strlen(nm->sidprefix) + 7 + 3 * sizeof (nm->rid);
	to = (char *)malloc(len);
	if (to == NULL)
		return (NULL);

	(void) snprintf(to, len, "%s:%s-%u", typestring, nm->sidprefix,
	    nm->rid);
	return (to);
}

/* Assemble string form uid or gid */
static char *
pid_format(uid_t from, int is_user)
{
	char *to;
	size_t len;

	/* ID_UID ":" + uid + '\0' */
	len = 5 + 3 * sizeof (uid_t);
	to = (char *)malloc(len);
	if (to == NULL)
		return (NULL);

	(void) snprintf(to, len, "%s:%u", is_user ? ID_UID : ID_GID, from);
	return (to);
}

/* Assemble winname, e.g. "winuser:bob@foo.sun.com", from name_mapping_t */
static int
nm2winqn(name_mapping_t *nm, char **winqn)
{
	char *out;
	size_t length = 0;
	int is_domain = 1;
	char *prefix;

	/* Sometimes there are no text names. Return a sid, then. */
	if (nm->winname == NULL && nm->sidprefix != NULL) {
		*winqn = sid_format(nm);
		return (0);
	}

	switch (nm->is_wuser) {
	case IDMAP_YES:
		prefix = ID_WINUSER ":";
		break;
	case IDMAP_NO:
		prefix = ID_WINGROUP ":";
		break;
	case IDMAP_UNKNOWN:
		prefix = ID_WINNAME ":";
		break;

	}

	length = strlen(prefix);

	if (nm->winname != NULL)
		length += strlen(nm->winname);

	/* Windomain is not mandatory: */
	if (nm->windomain == NULL || INHIBITED(nm->winname))
		is_domain = 0;
	else
		length += strlen(nm->windomain) + 1;

	out = (char *)malloc(length + 1);
	if (out == NULL) {
		print_error(NULL,
		    "%s.\n", strerror(ENOMEM));
		return (-1);
	}

	(void) strcpy(out, prefix);

	/* LINTED E_NOP_IF_STMT */
	if (nm->winname == NULL)
		;
	else if (!is_domain)
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

/*
 * Assemble a text unixname, e.g. unixuser:fred. Use only for
 * mapping, not namerules - there an empty name means inhibited
 * mappings, while here pid is printed if there is no name.
 */
static
int
nm2unixname(name_mapping_t *nm, char **unixname)
{
	size_t length = 0;
	char *out, *it, *prefix;

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
	case IDMAP_YES:
		prefix = ID_UNIXUSER ":";
		break;
	case IDMAP_NO:
		prefix = ID_UNIXGROUP ":";
		break;
	case IDMAP_UNKNOWN:
		prefix = ID_UNIXUSER ":";
		break;

	}

	length = strlen(prefix) + strlen(it);

	out = (char *)malloc(length + 1);
	if (out == NULL) {
		print_error(NULL,
		    "%s.\n", strerror(ENOMEM));
		free(it);
		return (-1);
	}

	(void) strcpy(out, prefix);
	(void) strcat(out, it);
	free(it);

	*unixname = out;
	return (0);
}

/* Allocate a new name_mapping_t and initialize the values. */
static name_mapping_t *
name_mapping_init()
{
	name_mapping_t *nm = (name_mapping_t *)malloc(sizeof (name_mapping_t));
	if (nm == NULL) {
		print_error(NULL, "%s.\n", strerror(ENOMEM));
		return (NULL);
	}
	nm->winname = nm->windomain = nm->unixname = nm->sidprefix = NULL;
	nm->rid = UNDEFINED_RID;
	nm->is_nt4 = B_FALSE;
	nm->is_user = IDMAP_UNKNOWN;
	nm->is_wuser = IDMAP_UNKNOWN;
	nm->direction = IDMAP_DIRECTION_UNDEF;
	nm->pid = UNDEFINED_UID;
	return (nm);
}

/* Free name_mapping_t */
static void
name_mapping_fini(name_mapping_t *nm)
{

	free(nm->winname);
	free(nm->windomain);
	free(nm->unixname);
	free(nm->sidprefix);

	free(nm);
}

static int
name_mapping_cpy(name_mapping_t *to, name_mapping_t *from)
{
	free(to->winname);
	free(to->windomain);
	free(to->unixname);
	free(to->sidprefix);

	(void) memcpy(to, from, sizeof (name_mapping_t));
	to->winname = to->windomain = to->unixname = to->sidprefix = NULL;

	if (from->winname != NULL) {
		to->winname = strdup(from->winname);
		if (to->winname == NULL) {
			print_error(NULL, "%s.\n", strerror(ENOMEM));
			return (-1);
		}
	}

	if (from->windomain != NULL) {
		to->windomain = strdup(from->windomain);
		if (to->windomain == NULL)  {
			print_error(NULL, "%s.\n", strerror(ENOMEM));
			return (-1);
		}
	}

	if (from->unixname != NULL) {
		to->unixname = strdup(from->unixname);
		if (to->unixname == NULL)  {
			print_error(NULL, "%s.\n", strerror(ENOMEM));
			return (-1);
		}
	}

	if (from->sidprefix != NULL) {
		to->sidprefix = strdup(from->sidprefix);
		if (to->sidprefix == NULL)  {
			print_error(NULL, "%s.\n", strerror(ENOMEM));
			return (-1);
		}
	}

	return (0);
}

static int
name_mapping_format(name_mapping_t *nm, char **out)
{
	char *winname = NULL;
	char *winname1 = NULL;
	char *unixname = NULL;
	int maxlen;

	*out = NULL;

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

	/* 10 is strlen("add -d\t\t\n") + 1 */
	maxlen = 10 + strlen(unixname) + strlen(winname);

	*out = (char *)malloc(maxlen);

	if (nm->direction == IDMAP_DIRECTION_U2W) {
		(void) snprintf(*out, maxlen, "add -d\t%s\t%s\n",
		    unixname, winname);
	} else {
		(void) snprintf(*out, maxlen, "add %s\t%s\t%s\n",
		    nm->direction == IDMAP_DIRECTION_BI? "" : "-d",
		    winname, unixname);
	}
	free(winname);
	free(unixname);
	return (0);
}

/* Initialize print_mapping variables. Must be called before print_mapping */
static print_handle_t *
print_mapping_init(format_t f, FILE *fi)
{
	print_handle_t *out;

	out = (print_handle_t *)malloc(sizeof (print_handle_t));
	if (out == NULL) {
		print_error(NULL, "%s.\n", strerror(ENOMEM));
		return (NULL);
	}

	out->format = f;
	out->file = fi;
	out->last = name_mapping_init();

	if (out->last == NULL)
		return (NULL);

	return (out);
}

/* Finalize print_mapping. */
static int
print_mapping_fini(print_handle_t *pnm)
{
	char *out = NULL;
	int rc = 0;

	switch (pnm->format) {
	case SMBUSERS:
		if (pnm->last->unixname != NULL) {
			(void) fprintf(pnm->file, "\n");
		}
		break;
	case DEFAULT_FORMAT:
		if (pnm->last->unixname == NULL)
			break;
		rc = name_mapping_format(pnm->last, &out);
		if (rc >= 0) {
			(void) fprintf(pnm->file, "%s", out);
			free(out);
		}
		break;
	default:
		;
	}

	name_mapping_fini(pnm->last);
	free(pnm);

	return (rc);
}

static char *
usermap_cfg_string(char *in)
{
	int len;
	char *out;

	if (INHIBITED(in))
		return (strdup("\"\""));

	len = strlen(in);
	if (len == strcspn(in, " \t#"))
		return (strdup(in));

	out = malloc(len + 3);
	if (out == NULL)
		return (NULL);

	(void) snprintf(out, len + 3, "\"%s\"", in);
	return (out);
}

/*
 * This prints both name rules and ordinary mappings, based on the pnm_format
 * set in print_mapping_init().
 */

static int
print_mapping(print_handle_t *pnm, name_mapping_t *nm)
{
	char *dirstring;
	char *winname = NULL;
	char *windomain = NULL;
	char *unixname = NULL;
	FILE *f = pnm->file;

	switch (pnm->format) {
	case MAPPING_NAME:
		if (nm2winqn(nm, &winname) < 0)
			return (-1);
		if (nm2unixname(nm, &unixname) < 0) {
			free(winname);
			return (-1);
		}
		/* FALLTHROUGH */
	case MAPPING_ID:
		if (pnm->format == MAPPING_ID) {
			if (nm->sidprefix == NULL) {
				print_error(NULL,
				    gettext("SID not given.\n"));
				return (-1);
			}
			winname = sid_format(nm);
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

		break;
	case SMBUSERS:
		if (nm->is_user != IDMAP_YES || nm->is_wuser != IDMAP_YES) {
			print_error(NULL,
			    gettext("Group rule: "));
			f = stderr;
		} else 	if (nm->direction == IDMAP_DIRECTION_U2W) {
			print_error(NULL,
			    gettext("Opposite direction of the mapping: "));
			f = stderr;
		} else if (INHIBITED(nm->winname) || INHIBITED(nm->unixname)) {
			print_error(NULL, gettext("Inhibited rule: "));
			f = stderr;
		}

		if (shell_app(&winname, nm->winname, 1))
			return (-1);

		unixname = INHIBITED(nm->unixname) ? "\"\"" : nm->unixname;

		if (pnm->file != f) {
			(void) fprintf(f, "%s=%s\n", unixname, winname);
		} else if (pnm->last->unixname != NULL &&
		    strcmp(pnm->last->unixname, unixname) == 0) {
			(void) fprintf(f, " %s", winname);
		} else {
			if (pnm->last->unixname != NULL) {
				(void) fprintf(f, "\n");
				free(pnm->last->unixname);
			}
			pnm->last->unixname = strdup(unixname);
			if (pnm->last->unixname == NULL) {
				print_error(NULL,
				    "%s.\n", strerror(ENOMEM));
			}

			(void) fprintf(f, "%s=%s", unixname, winname);
		}

		unixname = NULL;
		break;
	case USERMAP_CFG:
		if (nm->is_user != IDMAP_YES || nm->is_wuser != IDMAP_YES) {
			print_error(NULL,
			    gettext("Group rule: "));
			f = stderr;
		}

		dirstring = direction2string(nm->direction);

		if ((winname = usermap_cfg_string(nm->winname)) == NULL ||
		    (unixname = usermap_cfg_string(nm->unixname)) == NULL ||
		    (windomain = usermap_cfg_string(nm->windomain)) == NULL) {
			print_error(NULL, "%s.\n", strerror(ENOMEM));
			free(winname);
			free(unixname);
			free(windomain);
			return (-1);
		}


		if (nm->windomain == NULL) {
			(void) fprintf(f, "%s\t%s\t%s\n",
			    winname, dirstring, unixname);
		} else
			(void) fprintf(f, nm->is_nt4 ?
			    "%s\\%s\t%s\t%s\n" :
			    "%2$s@%1$s\t%3$s\t%4$s\n",
			    windomain, winname, dirstring, unixname);

		break;

	/* This is a format for namerules */
	case DEFAULT_FORMAT:
		/*
		 * If nm is the same as the last one except is_wuser, we combine
		 * winuser & wingroup to winname
		 */
		if (nm->direction == pnm->last->direction &&
		    nm->is_user == pnm->last->is_user &&

		    strcmp_null(pnm->last->unixname, nm->unixname) == 0 &&
		    strcmp_null(pnm->last->winname, nm->winname) == 0 &&
		    strcmp_null(pnm->last->windomain, nm->windomain) == 0) {
			pnm->last->is_wuser = IDMAP_UNKNOWN;
		} else {
			if (pnm->last->unixname != NULL ||
			    pnm->last->winname != NULL) {
				char *out = NULL;
				if (name_mapping_format(pnm->last, &out) < 0)
					return (-1);
				(void) fprintf(f, "%s", out);
				free(out);
			}
			if (name_mapping_cpy(pnm->last, nm) < 0)
				return (-1);
		}
		break;
	default:
		/* This can never happen: */
		print_error(NULL,
		    gettext("Internal error: invalid print format.\n"));
		return (-1);
	}

	free(winname);
	free(unixname);
	free(windomain);
	return (0);
}


static
void
print_how(idmap_how *how)
{
	idmap_namerule	*rule;
	name_mapping_t	nm;
	char		*rule_text;

	switch (how->map_type) {
	case IDMAP_MAP_TYPE_DS_AD:
		(void) printf(gettext("Method:\tAD Directory\n"));
		(void) printf(gettext("DN:\t%s\n"),
		    CHECK_NULL(how->idmap_how_u.ad.dn));
		(void) printf(gettext("Attribute:\t%s=%s\n"),
		    CHECK_NULL(how->idmap_how_u.ad.attr),
		    CHECK_NULL(how->idmap_how_u.ad.value));
		break;

	case IDMAP_MAP_TYPE_DS_NLDAP:
		(void) printf(gettext("Method:\tNative LDAP Directory\n"));
		(void) printf(gettext("DN:\t%s\n"),
		    CHECK_NULL(how->idmap_how_u.nldap.dn));
		(void) printf(gettext("Attribute:\t%s=%s\n"),
		    CHECK_NULL(how->idmap_how_u.nldap.attr),
		    CHECK_NULL(how->idmap_how_u.nldap.value));
		break;

	case IDMAP_MAP_TYPE_RULE_BASED:
		(void) printf(gettext("Method:\tName Rule\n"));
		rule = &how->idmap_how_u.rule;
		/*
		 * The name rules as specified by the user can have a
		 * "winname", "winuser" or "wingroup". "Winname" rules are
		 * decomposed to a "winuser" and "wingroup" rules by idmap.
		 * Currently is_wuser  is a boolean. Due to these reasons
		 * the returned is_wuser does not represent the original rule.
		 * It is therefore better set is_wuser to unknown.
		 */
		nm.is_user = rule->is_user;
		nm.is_wuser = IDMAP_UNKNOWN;
		nm.direction = rule->direction;
		nm.winname = rule->winname;
		nm.windomain = rule->windomain;
		nm.unixname = rule->unixname;
		nm.is_nt4 = rule->is_nt4;
		if (name_mapping_format(&nm, &rule_text) == 0) {
			(void) printf(gettext("Rule:\t%s"), rule_text);
			free(rule_text);
		}
		break;

	case IDMAP_MAP_TYPE_EPHEMERAL:
		(void) printf(gettext("Method:\tEphemeral\n"));
		break;

	case IDMAP_MAP_TYPE_LOCAL_SID:
		(void) printf(gettext("Method:\tLocal SID\n"));
		break;

	case IDMAP_MAP_TYPE_KNOWN_SID:
		(void) printf(gettext("Method:\tWell-Known mapping\n"));
		break;

	case IDMAP_MAP_TYPE_IDMU:
		(void) printf(gettext("Method:\tIDMU\n"));
		(void) printf(gettext("DN:\t%s\n"),
		    CHECK_NULL(how->idmap_how_u.idmu.dn));
		(void) printf(gettext("Attribute:\t%s=%s\n"),
		    CHECK_NULL(how->idmap_how_u.idmu.attr),
		    CHECK_NULL(how->idmap_how_u.idmu.value));
		break;
	}
}


static
void
print_info(idmap_info *info)
{
	if (info->how.map_type != IDMAP_MAP_TYPE_UNKNOWN) {
		switch (info->src) {
		case IDMAP_MAP_SRC_NEW:
			(void) printf(gettext("Source:\tNew\n"));
			break;

		case IDMAP_MAP_SRC_CACHE:
			(void) printf(gettext("Source:\tCache\n"));
			break;

		case IDMAP_MAP_SRC_HARD_CODED:
			(void) printf(gettext("Source:\tHard Coded\n"));
			break;

		case IDMAP_MAP_SRC_ALGORITHMIC:
			(void) printf(gettext("Source:\tAlgorithmic\n"));
			break;
		}
		print_how(&info->how);
	}

	if (info->trace != NULL) {
		(void) printf(gettext("Trace:\n"));
		idmap_trace_print(stdout, "\t", info->trace);
	}
}


static
void
print_error_info(idmap_info *info)
{
	idmap_how	*how = &info->how;
	idmap_namerule	*rule;
	name_mapping_t	nm;
	char		*rule_text;

	(void) memset(&nm, 0, sizeof (nm));

	switch (how->map_type) {
	case IDMAP_MAP_TYPE_DS_AD:
		(void) fprintf(stderr,
		    gettext("Failed Method:\tAD Directory\n"));
		(void) fprintf(stderr, gettext("DN:\t%s\n"),
		    how->idmap_how_u.ad.dn);
		(void) fprintf(stderr, gettext("Attribute:\t%s=%s\n"),
		    how->idmap_how_u.ad.attr,
		    how->idmap_how_u.ad.value);
		break;

	case IDMAP_MAP_TYPE_DS_NLDAP:
		(void) fprintf(stderr,
		    gettext("Failed Method:\tNative LDAP Directory\n"));
		(void) fprintf(stderr, gettext("DN:\t%s\n"),
		    how->idmap_how_u.nldap.dn);
		(void) fprintf(stderr, gettext("Attribute:\t%s=%s\n"),
		    how->idmap_how_u.nldap.attr,
		    how->idmap_how_u.nldap.value);
		break;

	case IDMAP_MAP_TYPE_RULE_BASED:
		(void) fprintf(stderr, gettext("Failed Method:\tName Rule\n"));
		rule = &how->idmap_how_u.rule;
		/*
		 * The name rules as specified by the user can have a
		 * "winname", "winuser" or "wingroup". "Winname" rules are
		 * decomposed to a "winuser" and "wingroup" rules by idmap.
		 * Currently is_wuser  is a boolean. Due to these reasons
		 * the returned is_wuser does not represent the original rule.
		 * It is therefore better to set is_wuser to unknown.
		 */
		nm.is_user = rule->is_user;
		nm.is_wuser = IDMAP_UNKNOWN;
		nm.direction = rule->direction;
		nm.winname = rule->winname;
		nm.windomain = rule->windomain;
		nm.unixname = rule->unixname;
		nm.is_nt4 = rule->is_nt4;
		if (name_mapping_format(&nm, &rule_text) == 0) {
			(void) fprintf(stderr, gettext("Rule:\t%s"), rule_text);
			free(rule_text);
		}
		break;

	case IDMAP_MAP_TYPE_EPHEMERAL:
		(void) fprintf(stderr, gettext("Failed Method:\tEphemeral\n"));
		break;

	case IDMAP_MAP_TYPE_LOCAL_SID:
		(void) fprintf(stderr, gettext("Failed Method:\tLocal SID\n"));
		break;

	case IDMAP_MAP_TYPE_KNOWN_SID:
		(void) fprintf(stderr,
		    gettext("Failed Method:\tWell-Known mapping\n"));
		break;

	case IDMAP_MAP_TYPE_IDMU:
		(void) fprintf(stderr,
		    gettext("Failed Method:\tIDMU\n"));
		(void) fprintf(stderr, gettext("DN:\t%s\n"),
		    CHECK_NULL(how->idmap_how_u.idmu.dn));
		(void) fprintf(stderr, gettext("Attribute:\t%s=%s\n"),
		    CHECK_NULL(how->idmap_how_u.idmu.attr),
		    CHECK_NULL(how->idmap_how_u.idmu.value));
		break;
	}

	if (info->trace != NULL) {
		(void) printf(gettext("Trace:\n"));
		idmap_trace_print(stderr, "\t", info->trace);
	}
}



/* dump command handler */
static int
/* LINTED E_FUNC_ARG_UNUSED */
do_dump(flag_t *f, int argc, char **argv, cmd_pos_t *pos)
{
	idmap_stat	stat;
	idmap_iter_t	*ihandle;
	int		rc = 0;
	boolean_t	is_user;
	boolean_t	is_wuser;
	print_handle_t	*ph;
	int		flag = 0;
	idmap_info	info;

	ph = print_mapping_init(f[n_FLAG] != NULL ? MAPPING_NAME : MAPPING_ID,
	    stdout);
	if (ph == NULL)
		return (-1);

	if (f[v_FLAG] != NULL)
		flag = IDMAP_REQ_FLG_MAPPING_INFO;

	stat = idmap_iter_mappings(&ihandle, flag);
	if (stat < 0) {
		print_error(pos,
		    gettext("Iteration handle not obtained (%s)\n"),
		    idmap_stat2string(stat));
		rc = -1;
		goto cleanup;
	}

	do {
		name_mapping_t *nm = name_mapping_init();
		if (nm == NULL) {
			rc = -1;
			goto cleanup;
		}

		stat = idmap_iter_next_mapping(ihandle,
		    &nm->sidprefix, &nm->rid, &nm->pid,
		    &nm->winname, &nm->windomain,
		    &nm->unixname, &is_user, &is_wuser,
		    &nm->direction, &info);

		nm->is_user = is_user ? IDMAP_YES : IDMAP_NO;
		nm->is_wuser = is_wuser ? IDMAP_YES : IDMAP_NO;

		if (stat >= 0) {
			(void) print_mapping(ph, nm);
			print_how(&info.how);
			idmap_info_free(&info);
		}
		name_mapping_fini(nm);

	} while (stat > 0);

	/* IDMAP_ERR_NOTFOUND indicates end of the list */
	if (stat < 0 && stat != IDMAP_ERR_NOTFOUND) {
		print_error(pos,
		    gettext("Error during iteration (%s)\n"),
		    idmap_stat2string(stat));
		rc = -1;
		goto cleanup;
	}

	idmap_iter_destroy(ihandle);

cleanup:
	(void) print_mapping_fini(ph);
	return (rc);
}

/*
 * Convert pid from string to it's numerical representation. If it is
 * a valid string, i.e. number of a proper length, return 1. Otherwise
 * print an error message and return 0.
 */
static int
pid_convert(char *string, uid_t *number, int type, cmd_pos_t *pos)
{
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
sid_convert(char *from, char **prefix, idmap_rid_t *rid, cmd_pos_t *pos)
{
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
		    "%s.\n", strerror(ENOMEM));
		return (0);
	}

	return (1);
}

/* Does the line start with USERMAP_CFG IP qualifier? */
static int
ucp_is_IP_qualifier(char *line)
{
	char *it;
	it = line + strcspn(line, " \t\n#:");
	return (*(it + 1) == ':' ? 1 : 0);
}


/*
 * returns interior of quotation marks in USERMAP_CFG. In this format,
 * there cannot be a protected quotation mark inside.
 */
static char *
ucp_qm_interior(char **line, cmd_pos_t *pos)
{
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
ucp_grab_token(char **line, cmd_pos_t *pos, const char *terminators)
{
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
ucp_line2nm(char *line, cmd_pos_t *pos, name_mapping_t *nm)
{
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
sup_line2nm(char *line, cmd_pos_t *pos, name_mapping_t *nm)
{
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
line2nm(char *line, cmd_pos_t *pos, name_mapping_t *nm, format_t f)
{
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
ff2format(char *ff, int is_mandatory)
{

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

	stat = idmap_udt_flush_namerules(udt);
	if (stat < 0) {
		print_error(pos,
		    is_user ? gettext("Unable to flush users (%s).\n")
		    : gettext("Unable to flush groups (%s).\n"),
		    idmap_stat2string(stat));
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
			    nm->is_user ? B_TRUE : B_FALSE,
			    nm->is_wuser ? B_TRUE : B_FALSE,
			    nm->winname,
			    nm->unixname, nm->is_nt4, nm->direction);
			if (stat < 0) {
				print_error(&pos2,
				    gettext("Transaction error (%s)\n"),
				    idmap_stat2string(stat));
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
	boolean_t is_user;
	boolean_t is_wuser;
	print_handle_t *ph;

	stat = idmap_iter_namerules(NULL, 0, 0, NULL, NULL, &ihandle);
	if (stat < 0) {
		print_error(NULL,
		    gettext("Iteration handle not obtained (%s)\n"),
		    idmap_stat2string(stat));
		idmap_iter_destroy(ihandle);
		return (-1);
	}

	ph = print_mapping_init(format, fi);
	if (ph == NULL)
		return (-1);

	do {
		nm = name_mapping_init();
		if (nm == NULL) {
			idmap_iter_destroy(ihandle);
			return (-1);
		}

		stat = idmap_iter_next_namerule(ihandle, &nm->windomain,
		    &nm->winname, &nm->unixname, &is_user, &is_wuser,
		    &nm->is_nt4, &nm->direction);
		if (stat >= 0) {
			nm->is_user = is_user ? IDMAP_YES : IDMAP_NO;
			nm->is_wuser = is_wuser ? IDMAP_YES : IDMAP_NO;
			(void) print_mapping(ph, nm);
		}

		name_mapping_fini(nm);

	} while (stat > 0);

	(void) print_mapping_fini(ph);

	if (stat < 0 && stat !=  IDMAP_ERR_NOTFOUND) {
		print_error(NULL,
		    gettext("Error during iteration (%s)\n"),
		    idmap_stat2string(stat));
		idmap_iter_destroy(ihandle);
		return (-1);
	}

	idmap_iter_destroy(ihandle);
	return (0);
}

/* Export command handler  */
static int
/* LINTED E_FUNC_ARG_UNUSED */
do_export(flag_t *f, int argc, char **argv, cmd_pos_t *pos)
{
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

	/* List the requested types: */
	rc = list_name_mappings(format, fi);

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

	/* List the requested types: */
	rc = list_name_mappings(DEFAULT_FORMAT, stdout);

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

/* Convert string like sid or winname to the identity type code */

static int
string2type(char *str, cmd_pos_t *pos)
{
	int i;
	int code = TYPE_INVALID;

	for (i = 0; i < sizeof (identity2code) / sizeof (id_code_t); i++) {
		if (strcasecmp(identity2code[i].identity, str) == 0) {
			code = identity2code[i].code;
			break;
		}
	}

	if (code == TYPE_INVALID) {
		print_error(pos,
		    gettext("Error: invalid identity type \"%s\"\n"), str);
	}

	return (code);
}




/*
 * Split argument to its identity code and a name part
 * return values:
 *    TYPE_INVALID for unknown identity
 *    TYPE_AUTO for no identity (to be autodetected)
 *    <TYPE_XXX> for known identity
 */

static int
get_identity(char *arg, char **name, cmd_pos_t *pos)
{
	char *it;
	int code = TYPE_INVALID;

	if ((it = strchr(arg, ':')) == NULL) {
		*name = arg;
		return (TYPE_AUTO);
	}


	*it = '\0';
	code = string2type(arg, pos);
	*it = ':'; /* restore the original string: */

	*name = it + 1;
	return (code);
}

/*
 * This function splits name to the relevant pieces: is_user, winname,
 * windomain unixname. E.g. for winname, it strdups nm->winname and possibly
 * nm->windomain and return TYPE_WN.
 *
 * If there is already one of the text fields allocated, it is OK.
 * Return values:
 *     -1 ... syntax error
 *     0 ... it wasnt possible to determine
 *     <TYPE_XXX> otherwise
 */

static int
name2parts(char *name, name_mapping_t *nm, cmd_pos_t *pos)
{
	char *it;
	int code;

	code = get_identity(name, &it, pos);

	switch (code) {
	case TYPE_INVALID:
		/* syntax error: */
		return (-1);
	case TYPE_AUTO:
		/* autodetection: */
		if (nm->winname != NULL && nm->is_wuser != IDMAP_UNKNOWN)
			code = nm->is_wuser == IDMAP_YES ? TYPE_UU : TYPE_UG;
		else if (nm->unixname != NULL ||
		    strchr(name, '@') != NULL ||
		    strchr(name, '\\') != NULL)
			/* btw, nm->is_user can never be IDMAP_UNKNOWN here */
			code = TYPE_WN;
		else
			return (0);
		/* If the code was guessed succesfully, we are OK. */
		break;
	default:
		name = it;
	}

	if (code & IS_WIN) {
		if (code & IS_USER)
			nm->is_wuser = IDMAP_YES;
		else if (code & IS_GROUP)
			nm->is_wuser = IDMAP_NO;
	} else {
		if (code & IS_USER)
			nm->is_user = IDMAP_YES;
		else if (code & IS_GROUP)
			nm->is_user = IDMAP_NO;
	}

	if (code & IS_WIN && code & IS_NAME) {
		if (nm->winname != NULL || nm->windomain != NULL)
			return (code);

		if ((it = strchr(name, '@')) != NULL) {
			int length = it - name + 1;
			nm->winname = (char *)malloc(length);
			(void) strncpy(nm->winname, name, length - 1);
			nm->winname[length - 1] = '\0';
			nm->windomain = strdup(it + 1);
		} else if ((it = strrchr(name, '\\')) != NULL) {
			int length = it - name + 1;
			nm->windomain = (char *)malloc(length);
			(void) strncpy(nm->windomain, name, length - 1);
			nm->windomain[length - 1] = '\0';
			nm->winname = strdup(it + 1);
			nm->is_nt4 = B_TRUE;
		} else
			nm->winname = strdup(name);

		return (code);
	}


	if (!(code & IS_WIN) && code & IS_NAME) {
		if (nm->unixname != NULL)
			return (code);

		if (strlen(name) == 0)
			nm->unixname = strdup("\"\"");
		else
			nm->unixname = strdup(name);
		return (code);
	}


	if (code & IS_WIN && !(code & IS_NAME)) {
		if (!sid_convert(name, &nm->sidprefix, &nm->rid, pos))
			return (-1);
		else
			return (code);
	}

/*
 * it is (!(code & TYPE_WIN) &&  !(code & TYPE_NAME)) here - the other
 * possiblities are exhausted.
 */

	if (!pid_convert(name, &nm->pid, code, pos))
			return (-1);
		else
			return (code);

}

/*
 * Cycle through add/remove arguments until they are identified or found
 * invalid.
 */
static
name_mapping_t *
args2nm(int *is_first_win, int argc, char **argv,
    cmd_pos_t *pos)
{
	int code;
	int i;
	name_mapping_t *nm;

	nm = name_mapping_init();
	if (nm == NULL)
		return (NULL);

	for (i = 0; i < 2 * argc - 1; i++) {
		code = name2parts(argv[i % 2], nm, pos);
		switch (code) {
			case -1:
				goto fail;
		case 0:
			if (i > 0) {
				print_error(pos,
				    gettext("Missing identity type"
				    " cannot be determined for %s.\n"),
				    argv[i % 2]);
				goto fail;
			}
			break;
		default:
			if (!(code & IS_NAME)) {
				print_error(pos,
				    gettext("%s is not a valid name\n"),
				    argv[i % 2]);
				goto fail;
			}
		}
	}

	if (argc == 2 && nm->winname == NULL) {
		print_error(pos, gettext("No windows identity found.\n"));
		goto fail;
	}
	if (argc == 2 && nm->unixname == NULL) {
		print_error(pos, gettext("No unix identity found.\n"));
		goto fail;
	}
	if (argc == 1 && nm->winname == NULL && nm->unixname == NULL) {
		print_error(pos, gettext("No identity type determined.\n"));
		goto fail;
	}

	if (is_first_win != NULL)
		*is_first_win = code & IS_WIN;
	return (nm);
fail:
	name_mapping_fini(nm);
	return (NULL);
}



/* add command handler. */
static int
do_add_name_mapping(flag_t *f, int argc, char **argv, cmd_pos_t *pos)
{
	name_mapping_t *nm;
	int rc = 0;
	int is_first_win;
	idmap_stat stat;
	int is_wuser;
	print_handle_t *ph;



	/* Exactly two arguments must be specified */
	if (argc < 2) {
		print_error(pos, gettext("Not enough arguments.\n"));
		return (-1);
	} else if (argc > 2)  {
		print_error(pos, gettext("Too many arguments.\n"));
		return (-1);
	}

	nm = args2nm(&is_first_win, argc, argv, pos);
	if (nm == NULL)
		return (-1);

	if (f[d_FLAG] != NULL)
		nm->direction = is_first_win
		    ? IDMAP_DIRECTION_W2U
		    : IDMAP_DIRECTION_U2W;
	else
		nm->direction = IDMAP_DIRECTION_BI;

	/* Now let us write it: */

	if (init_udt_command()) {
		name_mapping_fini(nm);
		return (-1);
	}

	for (is_wuser = IDMAP_YES; is_wuser >= IDMAP_NO; is_wuser--) {
		/* nm->is_wuser can be IDMAP_YES, IDMAP_NO or IDMAP_UNKNOWN */
		if ((is_wuser == IDMAP_YES && nm->is_wuser == IDMAP_NO) ||
		    (is_wuser == IDMAP_NO && nm->is_wuser == IDMAP_YES))
			continue;

		stat = idmap_udt_add_namerule(udt, nm->windomain,
		    nm->is_user ? B_TRUE : B_FALSE,
		    is_wuser ? B_TRUE : B_FALSE,
		    nm->winname, nm->unixname, nm->is_nt4, nm->direction);
	}

	/* We echo the mapping */
	ph = print_mapping_init(DEFAULT_FORMAT, stdout);
	if (ph == NULL) {
		rc = -1;
		goto cleanup;
	}
	(void) print_mapping(ph, nm);
	(void) print_mapping_fini(ph);

	if (stat != IDMAP_SUCCESS) {
		print_error(pos,
		    gettext("Mapping not created (%s)\n"),
		    idmap_stat2string(stat));
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
	idmap_stat stat;
	int is_first_win;
	int is_wuser;

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
	nm = args2nm(&is_first_win, argc, argv, pos);
	if (nm == NULL)
		return (-1);

	/*
	 * If the direction is not specified by a -d/-f/-t flag, then it
	 * is IDMAP_DIRECTION_UNDEF, because in that case we want to
	 * remove any mapping. If it was IDMAP_DIRECTION_BI, idmap_api would
	 * delete a bidirectional one only.
	 */
	if (f[d_FLAG] != NULL || f[f_FLAG] != NULL)
		nm->direction = is_first_win
		    ? IDMAP_DIRECTION_W2U
		    : IDMAP_DIRECTION_U2W;
	else if (f[t_FLAG] != NULL)
		nm->direction = is_first_win
		    ? IDMAP_DIRECTION_U2W
		    : IDMAP_DIRECTION_W2U;
	else
		nm->direction = IDMAP_DIRECTION_UNDEF;

	if (init_udt_command()) {
		name_mapping_fini(nm);
		return (-1);
	}

	for (is_wuser = IDMAP_YES; is_wuser >= IDMAP_NO; is_wuser--) {
		if ((is_wuser == IDMAP_YES && nm->is_wuser == IDMAP_NO) ||
		    (is_wuser == IDMAP_NO && nm->is_wuser == IDMAP_YES))
			continue;

		stat = idmap_udt_rm_namerule(udt,
		    nm->is_user ? B_TRUE : B_FALSE,
		    is_wuser ? B_TRUE : B_FALSE,
		    nm->windomain, nm->winname, nm->unixname, nm->direction);

		if (stat != IDMAP_SUCCESS) {
			print_error(pos,
			    gettext("Mapping not deleted (%s)\n"),
			    idmap_stat2string(stat));
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

/* flush command handler */
static int
do_flush(flag_t *f, int argc, char **argv, cmd_pos_t *pos)
{
	NOTE(ARGUNUSED(argv))
	idmap_flush_op op;
	idmap_stat stat;
	int rc = 0;

	if (argc > 0) {
		print_error(pos,
		    gettext("Too many arguments.\n"));
		return (-1);
	}
	if (f[a_FLAG] != NULL)
		op = IDMAP_FLUSH_DELETE;
	else
		op = IDMAP_FLUSH_EXPIRE;

	stat = idmap_flush(op);
	if (stat != IDMAP_SUCCESS) {
		print_error(pos,
		    gettext("%s\n"),
		    idmap_stat2string(stat));
		rc = -1;
	}

	return (rc);
}


/* exit command handler */
static int
/* LINTED E_FUNC_ARG_UNUSED */
do_exit(flag_t *f, int argc, char **argv, cmd_pos_t *pos)
{
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
 * From name_mapping_t, asseble a string containing identity of the
 * given type.
 */
static int
nm2type(name_mapping_t *nm, int type, char **to)
{
	switch (type) {
	case TYPE_SID:
	case TYPE_USID:
	case TYPE_GSID:
		if (nm->sidprefix == NULL)
			return (-1);
		*to = sid_format(nm);
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
	name_mapping_t *nm = NULL;
	char *fromname;
	char *toname;
	idmap_info info;

	(void) memset(&info, 0, sizeof (info));

	if (argc == 0) {
		print_error(pos,
		    gettext("No identity given\n"));
		return (-1);
	} else if (argc > 2) {
		print_error(pos,
		    gettext("Too many arguments.\n"));
		return (-1);
	}

	flag = 0;
	if (f[c_FLAG] == NULL)
		flag |= IDMAP_REQ_FLG_NO_NEW_ID_ALLOC;
	if (f[v_FLAG] != NULL)
		flag |= IDMAP_REQ_FLG_MAPPING_INFO;
	if (f[V_FLAG] != NULL)
		flag |= IDMAP_REQ_FLG_TRACE;

	nm = name_mapping_init();
	if (nm == NULL)
		goto cleanup;

	type_from = name2parts(argv[0], nm, pos);
	if (type_from <= 0) {
		stat = IDMAP_ERR_ARG;
		goto cleanup;
	}


	/* Second, determine type_to: */
	if (argc < 2) {
		type_to = type_from & IS_WIN ? TYPE_PID : TYPE_SID;
		if (type_from & IS_NAME)
			type_to |= IS_NAME;
	} else {
		type_to = string2type(argv[1], pos);
		if (type_to == TYPE_INVALID) {
			stat = IDMAP_ERR_ARG;
			goto cleanup;
		}
	}

	if (type_to & IS_WIN) {
		if (type_to & IS_USER)
			nm->is_wuser = IDMAP_YES;
		else if (type_to & IS_GROUP)
			nm->is_wuser = IDMAP_NO;
		else
			nm->is_wuser = IDMAP_UNKNOWN;
	} else {
		if (type_to & IS_USER)
			nm->is_user = IDMAP_YES;
		else if (type_to & IS_GROUP)
			nm->is_user = IDMAP_NO;
	}

	/* Are both arguments the same OS side? */
	if (!(type_from & IS_WIN ^ type_to & IS_WIN)) {
		print_error(pos,
		    gettext("Direction ambiguous.\n"));
		stat = IDMAP_ERR_ARG;
		goto cleanup;
	}

/*
 * We have two interfaces for retrieving the mappings:
 * idmap_get_sidbyuid & comp (the batch interface) and
 * idmap_get_w2u_mapping & comp. We  want to use both of them, because
 * the former mimicks kernel interface better and the later offers the
 * string names. In the batch case, our batch has always size 1.
 *
 * Btw, type_from cannot be IDMAP_PID, because there is no type string
 * for it.
 */

	if (type_from & IS_NAME || type_to & IS_NAME ||
	    type_from  == TYPE_GSID || type_from  == TYPE_USID ||
	    type_to  == TYPE_GSID || type_to  == TYPE_USID) {
		if (type_from & IS_WIN) {
			map_stat = idmap_get_w2u_mapping(
			    nm->sidprefix,
			    &nm->rid,
			    nm->winname,
			    nm->windomain,
			    flag,
			    &nm->is_user, &nm->is_wuser,
			    &nm->pid,
			    &nm->unixname,
			    &nm->direction,
			    &info);
		} else {
			map_stat = idmap_get_u2w_mapping(
			    &nm->pid,
			    nm->unixname,
			    flag,
			    nm->is_user, &nm->is_wuser,
			    &nm->sidprefix,
			    &nm->rid,
			    &nm->winname,
			    &nm->windomain,
			    &nm->direction,
			    &info);
		}

	} else {
		/* batch handle */
		idmap_get_handle_t *ghandle = NULL;
		/* To be passed to idmap_get_uidbysid  */
		gid_t gid = UNDEFINED_GID;
		/* To be passed to idmap_get_gidbysid  */
		uid_t uid = UNDEFINED_UID;


		/* Create an in-memory structure for all the batch: */
		stat = idmap_get_create(&ghandle);
		if (stat != IDMAP_SUCCESS) {
			print_error(pos,
			    gettext("Unable to create handle for communicating"
			    " with idmapd(1M) (%s)\n"),
			    idmap_stat2string(stat));
			idmap_get_destroy(ghandle);
			goto cleanup;
		}

		/* Schedule the request: */
		if (type_to == TYPE_UID) {
			stat = idmap_getext_uidbysid(ghandle,
			    nm->sidprefix,
			    nm->rid,
			    flag,
			    &uid,
			    &info,
			    &map_stat);
		} else if (type_to == TYPE_GID) {
			stat =  idmap_getext_gidbysid(ghandle,
			    nm->sidprefix,
			    nm->rid,
			    flag,
			    &gid,
			    &info,
			    &map_stat);
		} else if (type_to == TYPE_PID) {
			stat = idmap_getext_pidbysid(ghandle,
			    nm->sidprefix,
			    nm->rid,
			    flag,
			    &nm->pid,
			    &nm->is_user,
			    &info,
			    &map_stat);
		} else if (type_from == TYPE_UID) {
			stat = idmap_getext_sidbyuid(ghandle,
			    nm->pid,
			    flag,
			    &nm->sidprefix,
			    &nm->rid,
			    &info,
			    &map_stat);
		} else if (type_from == TYPE_GID) {
			stat = idmap_getext_sidbygid(ghandle,
			    (gid_t)nm->pid,
			    flag,
			    &nm->sidprefix,
			    &nm->rid,
			    &info,
			    &map_stat);
		} else {
			/* This can never happen: */
			print_error(pos,
			    gettext("Internal error in show.\n"));
			exit(1);
		}

		if (stat < 0) {
			print_error(pos,
			    gettext("Request for %.3s not sent (%s)\n"),
			    argv[0], idmap_stat2string(stat));
			idmap_get_destroy(ghandle);
			goto cleanup;
		}

		/* Send the batch to idmapd and obtain results: */
		stat = idmap_get_mappings(ghandle);
		if (stat < 0) {
			print_error(pos,
			    gettext("Mappings not obtained because of"
			    " RPC problem (%s)\n"),
			    idmap_stat2string(stat));
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
	if (map_stat < 0 && flag & IDMAP_REQ_FLG_NO_NEW_ID_ALLOC)
		goto errormsg;

	/*
	 * idmapd returns fallback uid/gid in case of errors. However
	 * it uses special sentinel value i.e 4294967295 (or -1) to
	 * indicate that falbback pid is not available either. In such
	 * case idmap(1M) should not display the mapping because there
	 * is no fallback mapping.
	 */

	if ((type_to == TYPE_UID || type_to == TYPE_GID ||
	    type_to == TYPE_PID) && nm->pid == UNDEFINED_UID)
		goto errormsg;

	if (nm2type(nm, type_from, &fromname) < 0)
		goto errormsg;

	if (nm2type(nm, type_to, &toname) < 0) {
		if (!(flag & IDMAP_REQ_FLG_NO_NEW_ID_ALLOC))
			(void) printf("%s -> %s:%u\n",
			    fromname,
			    type_to & IS_GROUP ? ID_GID : ID_UID,
			    UID_NOBODY);
		free(fromname);
	} else {
		(void) printf("%s -> %s\n", fromname, toname);
		free(fromname);
		free(toname);
	}

errormsg:
	if (map_stat < 0) {
		print_error(pos, gettext("Error:\t%s\n"),
		    idmap_stat2string(map_stat));
		print_error_info(&info);
	} else {
		print_info(&info);
	}
	idmap_info_free(&info);

cleanup:
	if (nm != NULL)
		name_mapping_fini(nm);
	return (stat < 0 || map_stat < 0 ? -1 : 0);
}


static int
flags2cred(flag_t *f, char **user, char **passwd,  cmd_pos_t *pos)
{

	*user = NULL;
	*passwd = NULL;

	if (f[D_FLAG] == NULL)
		return (0); /* GSSAPI authentification => OK */

	*user = strdup(f[D_FLAG]);
	if (*user == NULL) {
		print_error(pos, "%s.\n", strerror(ENOMEM));
		return (-1);
	}

	/* Password: */

	if (f[j_FLAG] != NULL) {
		char line[MAX_INPUT_LINE_SZ];
		int i;
		FILE *file = fopen(f[j_FLAG], "r");

		if (file == NULL) {
			print_error(pos,
			    gettext("Failed to open password file \"%s\": (%s)"
			    ".\n"), f[j_FLAG], strerror(errno));
			goto fail;
		}

		/* The password is the fist line, we ignore the rest: */
		if (fgets(line, MAX_INPUT_LINE_SZ, file) == NULL) {
			print_error(pos,
			    gettext("The password file \"%s\" is empty.\n"),
			    f[j_FLAG]);
			(void) fclose(file);
			goto fail;
		}

		if (fclose(file) != 0) {
			print_error(pos,
			    gettext("Unable to close the password file \"%s\""
			    ".\n"), f[j_FLAG], strerror(errno));
			goto fail;
		}

		/* Trim the eol: */
		for (i = strlen(line) - 1;
		    i >= 0 && (line[i] == '\r' || line[i] == '\n');
		    i--)
			line[i] = '\0';

		*passwd = strdup(line);
		if (*passwd == NULL) {
			print_error(pos, "%s.\n", strerror(ENOMEM));
			goto fail;
		}
	} else if (!batch_mode) {
		/* If in the interactive mode, read the terminal input: */
		char *it = getpassphrase("Enter password:");
		if (it == NULL) {
			print_error(NULL,
			    gettext("Failed to get password (%s).\n"),
			    strerror(errno));
			goto fail;
		}

		*passwd = strdup(it);
		(void) memset(it, 0, strlen(it));

		if (*passwd == NULL) {
			print_error(pos, "%s.\n", strerror(ENOMEM));
			goto fail;
		}
	} else {
		print_error(pos, gettext("No password given.\n"));
		goto fail;
	}

	return (0);
fail:
	if (*passwd != NULL) {
		(void) memset(*passwd, 0, strlen(*passwd));
		free(*passwd);
		*passwd = NULL;
	}

	free(*user);
	return (-1);
}


static int
do_set_namemap(flag_t *f, int argc, char **argv, cmd_pos_t *pos)
{
	idmap_stat stat;
	name_mapping_t *nm;
	int is_first_win;
	char *user;
	char *passwd;

	if (argc < 2) {
		print_error(pos,
		    gettext("Not enough arguments: two names needed for a "
		    "namemap.\n"));
		return (-1);
	} else if (argc > 2) {
		print_error(pos,
		    gettext("Too many arguments: two names needed for a "
		    "namemap.\n"));
		return (-1);
	}

	nm = args2nm(&is_first_win, argc, argv, pos);
	if (nm == NULL)
		return (-1);

	if (flags2cred(f, &user, &passwd, pos) < 0)
		return (-1);

	nm->direction = is_first_win ? IDMAP_DIRECTION_W2U
	    : IDMAP_DIRECTION_U2W;

	if (init_nm_command(user, passwd, f[a_FLAG], nm->windomain,
	    nm->direction, pos) < 0)
		return (-1);


	stat = idmap_set_namemap(namemaps.handle, nm->winname, nm->unixname,
	    nm->is_user, nm->is_wuser, nm->direction);

	if (stat != IDMAP_SUCCESS) {
		print_error(pos,
		    gettext("Failed to set namemap (%s).\n"),
		    idmap_stat2string(stat));
	}

	if (passwd != NULL) {
		(void) memset(passwd, 0, strlen(passwd));
		free(passwd);
	}

	free(user);

	fini_nm_command();
	name_mapping_fini(nm);
	return (stat != IDMAP_SUCCESS ? -1 : 0);
}

static int
do_unset_namemap(flag_t *f, int argc, char **argv, cmd_pos_t *pos)
{
	idmap_stat stat;
	name_mapping_t *nm;
	int is_first_win;
	char *user;
	char *passwd;

	if (argc < 1) {
		print_error(pos,
		    gettext("Not enough arguments: a name needed to unset a "
		    "namemap.\n"));
		return (-1);
	} else if (argc > 2) {
		print_error(pos,
		    gettext("Too many arguments: Only target name and type is "
		    "needed to unset namemap.\n"));
		return (-1);
	}

	nm = args2nm(&is_first_win, 1, argv, pos);
	if (nm == NULL)
		return (-1);

	if (flags2cred(f, &user, &passwd, pos) < 0)
		return (-1);

	nm->direction = is_first_win ? IDMAP_DIRECTION_W2U
	    : IDMAP_DIRECTION_U2W;

	if (argc > 1 && !is_first_win) {
			print_error(pos,
			    gettext("Target type \"%s\" is redundant.\n"),
			    argv[1]);
			stat = IDMAP_ERR_ARG;
			goto cleanup;
	} else	if (argc > 1) {
		switch (string2type(argv[1], pos)) {
		case TYPE_INVALID:
			name_mapping_fini(nm);
			return (-1);
		case TYPE_UU:
			nm->is_user = IDMAP_YES;
			break;
		case TYPE_UG:
			nm->is_user = IDMAP_NO;
			break;
		default:
			print_error(pos,
			    gettext("Invalid target type \"%s\": here the "
			    "possible target type is unixuser or "
			    "unixgroup.\n"), argv[1]);
			stat = IDMAP_ERR_ARG;
			goto cleanup;
		}
	}

	if (init_nm_command(user, passwd, f[a_FLAG], nm->windomain,
	    nm->direction, pos) < 0)
		return (-1);

	stat = idmap_unset_namemap(namemaps.handle, nm->winname, nm->unixname,
	    nm->is_user, nm->is_wuser, nm->direction);

	if (stat != IDMAP_SUCCESS) {
		print_error(pos,
		    gettext("Failed to unset namemap (%s).\n"),
		    idmap_stat2string(stat));
	}

cleanup:
	if (passwd != NULL) {
		(void) memset(passwd, 0, strlen(passwd));
		free(passwd);
	}

	free(user);

	fini_nm_command();
	name_mapping_fini(nm);
	return (stat == IDMAP_SUCCESS ? 0 : -1);
}

static int
/* LINTED E_FUNC_ARG_UNUSED */
do_get_namemap(flag_t *f, int argc, char **argv, cmd_pos_t *pos)
{
	idmap_stat stat;
	name_mapping_t *nm;
	int is_first_win;
	int is_source_ad;
	char *winname = NULL;
	char *unixname = NULL;
	char *unixuser = NULL;
	char *unixgroup = NULL;

	if (argc < 1) {
		print_error(pos,
		    gettext("Not enough arguments: a name needed to get a "
		    "namemap.\n"));
		return (-1);
	} else if (argc > 1) {
		print_error(pos,
		    gettext("Too many arguments: just one name needed to get "
		    "a namemap.\n"));
		return (-1);
	}

	nm = args2nm(&is_first_win, argc, argv, pos);
	if (nm == NULL)
		return (-1);

	nm->direction = is_first_win ? IDMAP_DIRECTION_W2U
	    : IDMAP_DIRECTION_U2W;

	/* nm->is_user is IDMAP_UNKNOWN for IDMAP_DIRECTION_W2U */
	if (nm->is_user == IDMAP_YES) {
		unixuser = strdup(nm->unixname);
		if (unixuser == NULL) {
			print_error(pos, "%s.\n", strerror(ENOMEM));
			goto cleanup;
		}
	} else if (nm->is_user == IDMAP_NO) {
		unixgroup = strdup(nm->unixname);
		if (unixgroup == NULL) {
			print_error(pos, "%s.\n", strerror(ENOMEM));
			goto cleanup;
		}
	}

	if (init_nm_command(NULL, NULL, NULL, nm->windomain,
	    nm->direction, pos) < 0)
		return (-1);

	stat = idmap_get_namemap(namemaps.handle, &is_source_ad, &nm->winname,
	    &nm->windomain, &nm->is_wuser, &unixuser, &unixgroup);

	if (stat != IDMAP_SUCCESS) {
		print_error(pos,
		    gettext("Failed to get namemap info (%s).\n"),
		    idmap_stat2string(stat));
		goto cleanup;
	}

	if (nm2winqn(nm, &winname) < 0)
			goto cleanup;

	switch (is_source_ad) {
	case IDMAP_YES:
		if (unixuser == NULL && unixgroup == NULL)
			(void) printf(gettext("\t\tNo namemap found in AD.\n"));
		else {
			(void) printf(gettext("AD namemaps for %s\n"), winname);
			if (unixuser != NULL)
				(void) printf(gettext("\t\t->\t%s:%s\n"),
				    ID_UNIXUSER, unixuser);

			if (unixgroup != NULL)
				(void) printf(gettext("\t\t->\t%s:%s\n"),
				    ID_UNIXGROUP, unixgroup);
		}
		break;
	case IDMAP_NO:
		if (nm2unixname(nm, &unixname) < 0)
			goto cleanup;

		if (nm->winname == NULL)
			(void) printf(gettext("\t\tNo namemap found in "
			    "native LDAP.\n"));
		else {
			(void) printf(gettext("Native LDAP namemap for %s\n"),
			    unixname);
			(void) printf(gettext("\t\t->\t%s\n"), winname);
		}
		break;
	default:
		/*
		 * This can never happen; the error must be recognized in
		 * args2nm
		 */
		print_error(pos,
		    gettext("Internal error: unknown source of namemaps.\n"));
	}

cleanup:
	fini_nm_command();
	name_mapping_fini(nm);
	if (winname != NULL)
		free(winname);
	if (unixuser != NULL)
		free(unixuser);
	if (unixgroup != NULL)
		free(unixgroup);
	return (stat == IDMAP_SUCCESS ? 0 : -1);
}


/* printflike */
static
void
idmap_cli_logger(int pri, const char *format, ...)
{
	va_list args;

	if (pri == LOG_DEBUG)
		return;

	va_start(args, format);

	(void) vfprintf(stderr, format, args);
	(void) fprintf(stderr, "\n");

	va_end(args);
}


/* main function. Returns 1 for error, 0 otherwise */
int
main(int argc, char *argv[])
{
	int rc;

	/* set locale and domain for internationalization */
	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);

	/* Redirect logging */
	idmap_set_logger(idmap_cli_logger);
	adutils_set_logger(idmap_cli_logger);

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
		fini_nm_command();
	}

	(void) engine_fini();
	return (rc == 0 ? 0 : 1);
}
