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
 * Use is subject to license terms..
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include	<stdio.h>
#include	<stdlib.h>
#include	<string.h>
#include	<sys/param.h>
#include	<sys/types.h>
#include	<sys/stat.h>
#include	<sys/file.h>
#include	<sys/time.h>
#include	<sys/mnttab.h>
#include	<rpc/types.h>
#include	<rpc/auth.h>
#include	<rpc/auth_unix.h>
#include	<rpc/xdr.h>
#include	<sys/tiuser.h>
#include	<rpc/clnt.h>
#include	<netinet/in.h>
#include	<rpcsvc/nfs_prot.h>
#include	<locale.h>

#include	"vold.h"


static bool_t	conf_use(int, char **, uint_t);
static bool_t	conf_unsafe(int, char **, uint_t);
static bool_t	conf_db(int, char **, uint_t);
static bool_t	conf_action(int, char **, uint_t);
static bool_t	conf_label(int, char **, uint_t);
/*
 * the "present" field below is set to true (if not already true)
 * when a particular command is seen
 *
 * when all config file commands are seen then the list of all commands
 * is scanned, and any with the "present" flag *not* set will cause
 * vold to die (hopefull) a clean death (using "quit()")
 */
static struct cmds {
	char	*name;			/* config file "command" string */
	bool_t	(*func)(int argc, char **argv, uint_t ln); /* funct to call */
	bool_t	present;		/* must be TRUE when done scanning */
	char	*emsg_fmt;		/* error msg if not TRUE when done */
} cmd_list[] = {
	{"use", conf_use, FALSE,
"Need at least one matching \"%s\" directive in config file \"%s\"\n" },
	{ "eject", conf_action, TRUE, NULL },
	{ "insert", conf_action, TRUE, NULL },
	{ "notify", conf_action, TRUE, NULL },
	{ "remount", conf_action, TRUE, NULL },
	{ "error", conf_action, TRUE, NULL },
	{ "label", conf_label, FALSE,
	    "Need at least one \"%s\" directive in config file \"%s\"\n" },
	{ "db", conf_db, FALSE,
	    "Need one \"%s\" directive in config file \"%s\"\n" },
	{ "unsafe", conf_unsafe, TRUE, NULL },
	{ 0, 0}
};

/*
 * The "flags" are really quite easy to use.  To add a new one, just
 * create a new entry in base_flags for your flag, add a FLAG_XXX tag
 * name so you can access it with getflag, and you're off.
 */

/* Tags to allow access to flags through getflag */
#define	FLAG_UID	1
#define	FLAG_GID	2
#define	FLAG_TEMP	3
#define	FLAG_MODE	4
#define	FLAG_MAPTTY	5
#define	FLAG_FORCE	6

/* different types of flags */
#define	FLAGTYPE_INT	0
#define	FLAGTYPE_STRING	1
#define	FLAGTYPE_BOOL	2

typedef union valu_t {
	char	*s;
	bool_t	b;
	uint_t	ui;
} valu_t;

static struct flags {
	char	*fl_name;	/* name of the flag */
	valu_t	fl_value;
	valu_t	fl_default;	/* default value of the flag */
	uint_t	fl_tag;		/* internal number for it */
	uint_t	fl_type;	/* type of flag */
	bool_t	fl_set;		/* has been set? */
} base_flags[] = {
	{"user", 0, (void *)"nobody",		/* user id */
	    FLAG_UID, FLAGTYPE_STRING, FALSE},
	{"group", 0, (void *)"nobody",		/* group id */
	    FLAG_GID, FLAGTYPE_STRING, FALSE},
	{"temp", 0, (void *)FALSE,		/* rm obj on eject */
	    FLAG_TEMP, FLAGTYPE_BOOL, FALSE},
	{"mode", 0, (void *)"0666",		/* access modes */
	    FLAG_MODE, FLAGTYPE_STRING, FALSE},
	{"maptty", 0, (void *)FALSE,		/* pass on tty actions */
	    FLAG_MAPTTY, FLAGTYPE_BOOL, FALSE},
	{"forceload", 0, (void *)FALSE,		/* load even if not present */
	    FLAG_FORCE, FLAGTYPE_BOOL, FALSE },
	{ "", 0, 0, 0, 0, 0},
};

static char 	*getflag_ptr(uint_t, struct flags *);
static bool_t 	getflag_bool(uint_t, struct flags *);
static uint_t 	getflag_uint(uint_t, struct flags *);
static uint_t	parseflags(uint_t, char **, uint_t, struct flags **);
static void	parseflagvalue(struct flags *, char *);
static void	cleanupflags(struct flags *);

/*
 * read the config file
 */
bool_t
config_read(void)
{
	extern void	unsafe_flush(void);
	extern void	action_flush(void);
	extern void	dev_configstart(void);
	extern void	makeargv(int *, char **, char *);
	extern void	dev_configend(void);
	struct	cmds	*cmd;
	struct stat	sb;
	FILE		*cfp;
	char		buf[BUFSIZ], *wholeline = 0;
	char		*av[MAXARGC];
	int		ac;
	bool_t		found;
	uint_t		lineno = 0;
	size_t		len, linelen = 0;
	bool_t		rval;


	debug(1, "reading config file: %s\n", vold_config);
	if ((cfp = fopen(vold_config, "r")) == NULL) {
		warning(gettext(
		    "config_read: can't open config file \"%s\"; %m\n"),
		    vold_config);
		return (FALSE);
	}

	unsafe_flush();		/* clear the way for new unsafe things */
	action_flush();		/* clear the way for new actions */

	/*
	 * If we are rereading the config file, the drivers will get
	 * called again.  It is up to them to deal with any changes.
	 * If they were configured in, and they aren't in the
	 * config file now, the code in vold_dev will call dev_close
	 * on them.  dev_configstart(), and dev_configend() allow
	 * dev_use to do the right thing.
	 */
	dev_configstart();

	while (fgets(buf, BUFSIZ, cfp) != NULL) {
		lineno++;
		/* skip comment lines (starting with #) and blanks */
		if (buf[0] == '#' || buf[0] == '\n') {
			continue;
		}
		len = strlen(buf);
		if (buf[len-2] == '\\') {
			if (wholeline == NULL) {
				buf[len-2] = NULLC;
				wholeline = strdup(buf);
				linelen = len-2;
				continue;
			} else {
				buf[len-2] = NULLC;
				len -= 2;
				wholeline = (char *)realloc(wholeline,
				    linelen+len+1);
				(void) strcpy(&wholeline[linelen], buf);
				linelen += len;
				continue;
			}
		} else {
			if (wholeline == NULL) {
				/* just a one liner */
				wholeline = buf;
			} else {
				wholeline = (char *)realloc(wholeline,
				    linelen+len+1);
				(void) strcpy(&wholeline[linelen], buf);
				linelen += len;
			}
		}

		/* make a nice argc, argv thing for the commands */
		makeargv(&ac, av, wholeline);

		found = FALSE;
		for (cmd = cmd_list; cmd->name; cmd++) {
			if (strcmp(cmd->name, av[0]) == 0) {
				rval = (*cmd->func)(ac, av, lineno);
				if ((cmd->present == FALSE) &&
				    (rval != FALSE)) {
					cmd->present = TRUE;
				}
				found = TRUE;
			}
		}
		if (!found) {
			/* no match for this directive! */
			warning(gettext(
			"config_read: unknown directive \"%s\", line %d\n"),
			    av[0], lineno);
		}
		if (wholeline != buf) {
			free(wholeline);
		}
		wholeline = NULL;
		linelen = 0;
	}

	(void) fclose(cfp);
	dev_configend();

	return (TRUE);
}


/*
 *	argv[0] = "use"
 *	argv[1] = devices: "mo", "cdrom", "floppy", "tape", "worm", "test",
 *			"pcmem", ...
 *	argv[2] = type: "drive", "test"
 *	argv[3] = name: '/dev/xxx'
 *	argv[4] = shared object name (in /usr/lib/vold)
 *	argv[5] = symbolic name (e.g. "floppy%d")
 *	argv[...] = flags
 *
 * flags we may care about:
 *	uid=UID		use UID as default user id
 *	gid=GID		use GID as default group id
 *	mode=MODE	use MODE as default node mode
 *	temp=BOOL	remove from namespace/database when physically removed
 *	force=BOOL	work even if not present
 */
static bool_t
conf_use(int argc, char **argv, uint_t ln)
{
	bool_t		rval;
	struct flags *flagp = NULL;


	/* ensure enough args */
	if (argc < 6) {
		warning(gettext(
		    "config file (%s) line %d: insufficient arguments\n"),
		    vold_config, ln);
		return (FALSE);
	}

	/* at least one database must be configured */
	if (db_configured_cnt() == 0) {
		fatal(gettext(
		    "Need at least one database configured in %s\n"),
		    vold_config);
	}

	/* load the shared library */
	if (dso_load(argv[4], DEV_SYM, DEV_VERS) == FALSE) {
		return (FALSE);
	}

	/* get all of the "flag=value" flags */
	(void) parseflags(argc, argv, 6, &flagp);

	/* register this device class */
	rval = dev_use(argv[1], argv[2], argv[3], argv[5],
	    getflag_ptr(FLAG_UID, flagp), getflag_ptr(FLAG_GID, flagp),
	    getflag_ptr(FLAG_MODE, flagp), getflag_bool(FLAG_TEMP, flagp),
	    getflag_bool(FLAG_FORCE, flagp));

			if (flagp)
				cleanupflags(flagp);

			return (rval);
}




/*
 *	argv[0] = "unsafe"
 *	argv[1..N] = <fstype>
 */
static bool_t
conf_unsafe(int argc, char **argv, uint_t ln)
{
	extern bool_t	add_to_unsafe_list(char *);
	int		i;


	/* ensure we have enough args */
	if (argc < 2) {
		warning(gettext(
		    "config file (%s) line %d: insufficient arguments\n"),
		    vold_config, ln);
		return (FALSE);
	}

	/* put our unsafe fs'es in the list */
	for (i = 1; i < argc; i++) {
		if (!add_to_unsafe_list(argv[i])) {
			warning(gettext(
		"config file (%s) line %d: unsafe max (%d) exceeded\n"),
		    vold_config, ln, DEFAULT_UNSAFE);
			return (FALSE);
		}
	}

	return (TRUE);
}


/*
 *	argv[0] = "db"
 *	argv[1] = <filename>
 *	argv[n] = <filename>
 */
static bool_t
conf_db(int argc, char **argv, uint_t ln)
{
	int		i;
	bool_t		gotone = FALSE;


	if (argc < 2) {
		warning(gettext(
		    "config file (%s) line %d: insufficient arguments\n"),
		    vold_config, ln);
		return (FALSE);
	}

	for (i = 1; i < argc; i++) {
		if (dso_load(argv[i], DB_SYM, 1) == FALSE) {
			warning(gettext(
			    "config file (%s) line %d: error loading %s\n"),
			    vold_config, ln, argv[i]);
			/* if there's another one */
			if (i+1 < argc) {
				warning(
			    gettext("Switching to alternate database %s\n"),
					argv[i+1]);
			}
		} else {
			gotone = TRUE;
		}
	}
	return (gotone);
}


/*
 * handle "label ..." line from vold.conf
 *
 * argv[0]:	"label"
 * argv[1]:	label_type	(e.g. "dos", "cdrom", "sun")
 * argv[2]:	shared_object	(in /usr/lib/vold)
 * argv[3...]:	media_type	(e.g. "floppy", "cdrom", "pcmem")
 */
static bool_t
conf_label(int argc, char **argv, uint_t ln)
{
	int		i;
	int		n;
	struct labsw	*lsw;


	if (argc < 2) {
		warning(gettext(
		    "config file (%s) line %d: insufficient arguments\n"),
		    vold_config, ln);
		return (FALSE);
	}

	/*
	 * Load the dso into memory.
	 */
	if (dso_load(argv[2], LABEL_SYM, LABEL_VERS) == FALSE) {
		return (FALSE);
	}

	/*
	 * This is a bit ugly, but what we do here is get the lsw
	 * for the most recently loaded label code.
	 */
	lsw = label_getlast();

	/*
	 * Build the list of devices that this label may reside on.
	 */
	if (argc > 3) {
		/* does a list already exist ?? */
		if (lsw->l_devlist != NULL) {
			/* list already exists -- free it */
			for (i = 0; lsw->l_devlist[i]; i++) {
				free(lsw->l_devlist[i]);
			}
			free(lsw->l_devlist);
		}
		lsw->l_devlist = (char **)calloc(argc-2, sizeof (char *));
		for (i = 3, n = 0; i < argc; i++, n++) {
			lsw->l_devlist[n] = strdup(argv[i]);
		}
		lsw->l_devlist[n] = 0;
	}
	return (TRUE);
}


/*
 * argv[0]:	action ("insert", "eject", "notify")
 * argv[1]:	path_name (e.g. "/vol/dev/...")
 * argv[2...]:	command to execute with execv, and optional args
 *
 * NOTE: options (e.g. "user=root") have already been stripped
 */
static bool_t
conf_action(int argc, char **argv, uint_t ln)
{
	extern bool_t	action_new(uint_t, char *, struct actprog *);
	extern uid_t	network_uid(char *);
	extern uid_t	network_gid(char *);
	char		*re, *shre;
	actprog_t	*ap;
	uint_t		act, nargs, i, nextarg, parg;
	struct stat	sb;
	char		*pname;
	struct flags *flagp = NULL;


	if (argc < 3) {
		warning(gettext(
			"config file (%s) line %d: insufficient arguments\n"),
			vold_config, ln);
		return (FALSE);
	}

	if (strcmp(argv[0], "notify") == 0) {
		act = ACT_NOTIFY;
	} else if (strcmp(argv[0], "insert") == 0) {
		act = ACT_INSERT;
	} else if (strcmp(argv[0], "eject") == 0) {
		act = ACT_EJECT;
	} else if (strcmp(argv[0], "error") == 0) {
		act = ACT_ERROR;
	} else if (strcmp(argv[0], "remount") == 0) {
		act = ACT_REMOUNT;
	} else {
		warning(gettext(
		    "config file (%s) line %d: unknown action %s\n"),
		    vold_config, ln, argv[0]);
		return (FALSE);
	}

	shre = argv[1];
	nextarg = parseflags(argc, argv, 2, &flagp) + 2;
	parg = nextarg;
	pname = argv[nextarg++];

	if (stat(pname, &sb) < 0) {
		/* probably ENOENT */
		warning(gettext("config file (%s) line %d: %s; %m\n"),
		    vold_config, ln, pname);
		return (FALSE);
	}

	if (!(S_IFREG & sb.st_mode)) {
		warning(gettext(
		    "config file (%s) line %d: %s not a regular file\n"),
		    vold_config, ln, pname);
		return (FALSE);
	}

	/*
	 * XXX: Now check the modes.  This is pretty crude... I need to
	 * XXX: be more complete.  I should really check the execute
	 * XXX: bit for the user and group that's going to execute the
	 * XXX: file.  For now, I assume that if the owner of the
	 * XXX: file can execute it, so can we.  A fair bet in most
	 * XXX: cases.
	 */
	if (!(S_IXUSR & sb.st_mode)) {
		warning(gettext(
		    "config file (%s) line %d: %s not executable\n"),
		    vold_config, ln, pname);
		return (FALSE);
	}

	ap = (actprog_t *)calloc(1, sizeof (actprog_t));

	if (*shre != '/') {
		char	*shre2;

		/* relatvie path name -- prepend vol root */
		shre2 = malloc(strlen(vold_root) + strlen(shre) + 2);
		if (shre2 == NULL) {
			warning(gettext(
		"can't allocate memory for config file scanning\n"));
			(void) free(ap);
			return (FALSE);
		}
		(void) sprintf(shre2, "%s/%s", vold_root, shre);
		re = sh_to_regex(shre2);
		(void) free(shre2);
	} else {
		re = sh_to_regex(shre);
	}

	if (action_new(act, re, ap) == FALSE) {
		warning(gettext(
			"config file (%s) line %d: bad regular expr\n"),
			vold_config, ln);
		free(ap);
		free(re);
		return (FALSE);
	}
	free(re);

	/*
	 * We handed the pointer to ap off, but we can still make changes.
	 * This makes error recovery easier.
	 */
	ap->ap_prog = strdup(pname);

	nargs = argc - parg;
	/* add 3 for read only on mount if media is read only */
	ap->ap_args = (char **)calloc(nargs + 3, sizeof (char *));
	for (i = 0; i < nargs; i++) {
		ap->ap_args[i] = strdup(argv[i + parg]);
	}
	ap->ap_args[i] = 0;
	ap->ap_uid = network_uid(getflag_ptr(FLAG_UID, flagp));
	ap->ap_gid = network_gid(getflag_ptr(FLAG_GID, flagp));
	ap->ap_line = ln;
	ap->ap_maptty = getflag_uint(FLAG_MAPTTY, flagp);

	if (flagp)
		cleanupflags(flagp);

	return (TRUE);
}


/*
 * search the flag list "flagp" for the tag "tag", returning the string
 * value found, or NULL if an error is found
 */
static char *
getflag_ptr(uint_t tag, struct flags *flagp)
{
	struct flags	*fp;


	for (fp = flagp; fp->fl_tag != 0; fp++) {
		if (fp->fl_tag == tag) {
			if (fp->fl_set == TRUE) {
				return (fp->fl_value.s);
			}
			return (fp->fl_default.s);
		}
	}

	debug(1, "getflag_ptr: unknown flag tag %d\n", fp->fl_tag);
	return (NULL);
}


/*
 * search the flag list "flagp" for the tag "tag", returning the bool
 * value found, or FALSE if an error is found
 */
static bool_t
getflag_bool(uint_t tag, struct flags *flagp)
{
	struct flags	*fp;


	for (fp = flagp; fp->fl_tag != 0; fp++) {
		if (fp->fl_tag == tag) {
			if (fp->fl_set == TRUE) {
				return (fp->fl_value.b);
			}
			return (fp->fl_default.b);
		}
	}

	debug(1, "getflag_bool: unknown flag tag %d\n", fp->fl_tag);
	return (FALSE);
}


/*
 * search the flag list "flagp" for the tag "tag", returning the u_int
 * value found, or 0 if an error is found
 */
static uint_t
getflag_uint(uint_t tag, struct flags *flagp)
{
	struct flags	*fp;


	for (fp = flagp; fp->fl_tag != 0; fp++) {
		if (fp->fl_tag == tag) {
			if (fp->fl_set == TRUE) {
				return (fp->fl_value.ui);
			}
			return (fp->fl_default.ui);
		}
	}

	debug(1, "getflag_uint: unknown flag tag %d\n", fp->fl_tag);
	return (0);
}


/*
 * flags take the **required** form "flag=value" (no spaces!!).  Returns how
 * many "argc's" we've eaten.
 */
static uint_t
parseflags(uint_t argc, char **argv, uint_t start, struct flags **flagp)
{
	int		i, n;
	struct flags 	*fp;
	char		*p = NULL;


	*flagp = (struct flags *)malloc(sizeof (base_flags));
	(void) memcpy(*flagp, &base_flags, sizeof (base_flags));

	for (i = start, n = 0; i < argc; i++) {
		if ((p = strchr(argv[i], '=')) != NULL) {
			*p++ = NULLC;
		}
		for (fp = *flagp; fp->fl_tag != 0; fp++) {
			if (strcmp(argv[i], fp->fl_name) == 0) {
				parseflagvalue(fp, p);
				n++;
				break;
			}
		}
		if (p != NULL) {
			*(p-1) = '=';
		}
	}
	return (n);
}


static void
parseflagvalue(struct flags *fp, char *value)
{
	switch (fp->fl_type) {
	case FLAGTYPE_INT:
		if (value != NULL) {
			fp->fl_value.ui = atoi(value);
			fp->fl_set = TRUE;
		}
		break;
	case FLAGTYPE_STRING:
		if (value != NULL) {
			fp->fl_value.s = strdup(value);
			fp->fl_set = TRUE;
		}
		break;
	case FLAGTYPE_BOOL:
		if ((value == NULL) ||
		    (strcmp(value, "true") == 0) ||
		    (*value == NULLC)) {
			fp->fl_value.b = TRUE;
		} else {
			fp->fl_value.b = FALSE;
		}
		fp->fl_set = TRUE;
		break;
	default:
		debug(1, "parseflagvalue: unknown flag type %d\n",
		    fp->fl_type);
		break;
	}
}

static void
cleanupflags(struct flags *flagp)
{

	struct flags *fp;

	for (fp = flagp; fp->fl_tag != 0; fp++) {
	if (fp->fl_type == FLAGTYPE_STRING && fp->fl_set == TRUE)
		if (fp->fl_value.s != NULL)
			free(fp->fl_value.s);
	}
	free(flagp);
}
