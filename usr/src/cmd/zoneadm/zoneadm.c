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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * zoneadm is a command interpreter for zone administration.  It is all in
 * C (i.e., no lex/yacc), and all the argument passing is argc/argv based.
 * main() calls parse_and_run() which calls cmd_match(), then invokes the
 * appropriate command's handler function.  The rest of the program is the
 * handler functions and their helper functions.
 *
 * Some of the helper functions are used largely to simplify I18N: reducing
 * the need for translation notes.  This is particularly true of many of
 * the zerror() calls: doing e.g. zerror(gettext("%s failed"), "foo") rather
 * than zerror(gettext("foo failed")) with a translation note indicating
 * that "foo" need not be translated.
 */

#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <stdarg.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <wait.h>
#include <zone.h>
#include <priv.h>
#include <locale.h>
#include <libintl.h>
#include <libzonecfg.h>
#include <bsm/adt.h>
#include <sys/utsname.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <assert.h>
#include <sys/sockio.h>
#include <sys/mntent.h>
#include <limits.h>
#include <libzfs.h>

#include <fcntl.h>
#include <door.h>
#include <macros.h>
#include <libgen.h>
#include <fnmatch.h>

#include <pool.h>
#include <sys/pool.h>

#define	MAXARGS	8

/* Reflects kernel zone entries */
typedef struct zone_entry {
	zoneid_t	zid;
	char		zname[ZONENAME_MAX];
	char		*zstate_str;
	zone_state_t	zstate_num;
	char		zroot[MAXPATHLEN];
} zone_entry_t;

static zone_entry_t *zents;
static size_t nzents;

#if !defined(TEXT_DOMAIN)		/* should be defined by cc -D */
#define	TEXT_DOMAIN	"SYS_TEST"	/* Use this only if it wasn't */
#endif

#define	Z_ERR	1
#define	Z_USAGE	2

/* 0755 is the default directory mode. */
#define	DEFAULT_DIR_MODE \
	(S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH)

#define	CMD_HELP	0
#define	CMD_BOOT	1
#define	CMD_HALT	2
#define	CMD_READY	3
#define	CMD_REBOOT	4
#define	CMD_LIST	5
#define	CMD_VERIFY	6
#define	CMD_INSTALL	7
#define	CMD_UNINSTALL	8
#define	CMD_MOUNT	9
#define	CMD_UNMOUNT	10
#define	CMD_CLONE	11
#define	CMD_MOVE	12
#define	CMD_DETACH	13
#define	CMD_ATTACH	14

#define	CMD_MIN		CMD_HELP
#define	CMD_MAX		CMD_ATTACH

#define	SINGLE_USER_RETRY	30

struct cmd {
	uint_t	cmd_num;				/* command number */
	char	*cmd_name;				/* command name */
	char	*short_usage;				/* short form help */
	int	(*handler)(int argc, char *argv[]);	/* function to call */

};

#define	SHELP_HELP	"help"
#define	SHELP_BOOT	"boot [-s]"
#define	SHELP_HALT	"halt"
#define	SHELP_READY	"ready"
#define	SHELP_REBOOT	"reboot"
#define	SHELP_LIST	"list [-cipv]"
#define	SHELP_VERIFY	"verify"
#define	SHELP_INSTALL	"install"
#define	SHELP_UNINSTALL	"uninstall [-F]"
#define	SHELP_CLONE	"clone [-m method] zonename"
#define	SHELP_MOVE	"move zonepath"
#define	SHELP_DETACH	"detach"
#define	SHELP_ATTACH	"attach [-F]"

static int help_func(int argc, char *argv[]);
static int ready_func(int argc, char *argv[]);
static int boot_func(int argc, char *argv[]);
static int halt_func(int argc, char *argv[]);
static int reboot_func(int argc, char *argv[]);
static int list_func(int argc, char *argv[]);
static int verify_func(int argc, char *argv[]);
static int install_func(int argc, char *argv[]);
static int uninstall_func(int argc, char *argv[]);
static int mount_func(int argc, char *argv[]);
static int unmount_func(int argc, char *argv[]);
static int clone_func(int argc, char *argv[]);
static int move_func(int argc, char *argv[]);
static int detach_func(int argc, char *argv[]);
static int attach_func(int argc, char *argv[]);
static int sanity_check(char *zone, int cmd_num, boolean_t running,
    boolean_t unsafe_when_running);
static int cmd_match(char *cmd);
static int verify_details(int);

static struct cmd cmdtab[] = {
	{ CMD_HELP,		"help",		SHELP_HELP,	help_func },
	{ CMD_BOOT,		"boot",		SHELP_BOOT,	boot_func },
	{ CMD_HALT,		"halt",		SHELP_HALT,	halt_func },
	{ CMD_READY,		"ready",	SHELP_READY,	ready_func },
	{ CMD_REBOOT,		"reboot",	SHELP_REBOOT,	reboot_func },
	{ CMD_LIST,		"list",		SHELP_LIST,	list_func },
	{ CMD_VERIFY,		"verify",	SHELP_VERIFY,	verify_func },
	{ CMD_INSTALL,		"install",	SHELP_INSTALL,	install_func },
	{ CMD_UNINSTALL,	"uninstall",	SHELP_UNINSTALL,
	    uninstall_func },
	/* mount and unmount are private commands for admin/install */
	{ CMD_MOUNT,		"mount",	NULL,		mount_func },
	{ CMD_UNMOUNT,		"unmount",	NULL,		unmount_func },
	{ CMD_CLONE,		"clone",	SHELP_CLONE,	clone_func },
	{ CMD_MOVE,		"move",		SHELP_MOVE,	move_func },
	{ CMD_DETACH,		"detach",	SHELP_DETACH,	detach_func },
	{ CMD_ATTACH,		"attach",	SHELP_ATTACH,	attach_func }
};

/* global variables */

/* set early in main(), never modified thereafter, used all over the place */
static char *execname;
static char *target_zone;
static char *locale;

/* used in do_subproc() and signal handler */
static volatile boolean_t child_killed;

static char *
cmd_to_str(int cmd_num)
{
	assert(cmd_num >= CMD_MIN && cmd_num <= CMD_MAX);
	return (cmdtab[cmd_num].cmd_name);
}

/* This is a separate function because of gettext() wrapping. */
static char *
long_help(int cmd_num)
{
	assert(cmd_num >= CMD_MIN && cmd_num <= CMD_MAX);
	switch (cmd_num) {
		case CMD_HELP:
			return (gettext("Print usage message."));
		case CMD_BOOT:
			return (gettext("Activates (boots) specified zone.  "
			    "The -s flag can be used\n\tto boot the zone in "
			    "the single-user state."));
		case CMD_HALT:
			return (gettext("Halts specified zone, bypassing "
			    "shutdown scripts and removing runtime\n\t"
			    "resources of the zone."));
		case CMD_READY:
			return (gettext("Prepares a zone for running "
			    "applications but does not start any user\n\t"
			    "processes in the zone."));
		case CMD_REBOOT:
			return (gettext("Restarts the zone (equivalent to a "
			    "halt / boot sequence).\n\tFails if the zone is "
			    "not active."));
		case CMD_LIST:
			return (gettext("Lists the current zones, or a "
			    "specific zone if indicated.  By default,\n\tall "
			    "running zones are listed, though this can be "
			    "expanded to all\n\tinstalled zones with the -i "
			    "option or all configured zones with the\n\t-c "
			    "option.  When used with the general -z <zone> "
			    "option, lists only the\n\tspecified zone, but "
			    "lists it regardless of its state, and the -i "
			    "and -c\n\toptions are disallowed.  The -v option "
			    "can be used to display verbose\n\tinformation: "
			    "zone name, id, current state, root directory and "
			    "options.\n\tThe -p option can be used to request "
			    "machine-parsable output.  The -v\n\tand -p "
			    "options are mutually exclusive.  If neither -v "
			    "nor -p is used,\n\tjust the zone name is "
			    "listed."));
		case CMD_VERIFY:
			return (gettext("Check to make sure the configuration "
			    "can safely be instantiated\n\ton the machine: "
			    "physical network interfaces exist, etc."));
		case CMD_INSTALL:
			return (gettext("Install the configuration on to the "
			    "system."));
		case CMD_UNINSTALL:
			return (gettext("Uninstall the configuration from the "
			    "system.  The -F flag can be used\n\tto force the "
			    "action."));
		case CMD_CLONE:
			return (gettext("Clone the installation of another "
			    "zone."));
		case CMD_MOVE:
			return (gettext("Move the zone to a new zonepath."));
		default:
			return ("");
	}
	/* NOTREACHED */
	return (NULL);
}

/*
 * Called with explicit B_TRUE when help is explicitly requested, B_FALSE for
 * unexpected errors.
 */

static int
usage(boolean_t explicit)
{
	int i;
	FILE *fd = explicit ? stdout : stderr;

	(void) fprintf(fd, "%s:\t%s help\n", gettext("usage"), execname);
	(void) fprintf(fd, "\t%s [-z <zone>] list\n", execname);
	(void) fprintf(fd, "\t%s -z <zone> <%s>\n", execname,
	    gettext("subcommand"));
	(void) fprintf(fd, "\n%s:\n\n", gettext("Subcommands"));
	for (i = CMD_MIN; i <= CMD_MAX; i++) {
		if (cmdtab[i].short_usage == NULL)
			continue;
		(void) fprintf(fd, "%s\n", cmdtab[i].short_usage);
		if (explicit)
			(void) fprintf(fd, "\t%s\n\n", long_help(i));
	}
	if (!explicit)
		(void) fputs("\n", fd);
	return (Z_USAGE);
}

static void
sub_usage(char *short_usage, int cmd_num)
{
	(void) fprintf(stderr, "%s:\t%s\n", gettext("usage"), short_usage);
	(void) fprintf(stderr, "\t%s\n", long_help(cmd_num));
}

/*
 * zperror() is like perror(3c) except that this also prints the executable
 * name at the start of the message, and takes a boolean indicating whether
 * to call libc'c strerror() or that from libzonecfg.
 */

static void
zperror(const char *str, boolean_t zonecfg_error)
{
	(void) fprintf(stderr, "%s: %s: %s\n", execname, str,
	    zonecfg_error ? zonecfg_strerror(errno) : strerror(errno));
}

/*
 * zperror2() is very similar to zperror() above, except it also prints a
 * supplied zone name after the executable.
 *
 * All current consumers of this function want libzonecfg's strerror() rather
 * than libc's; if this ever changes, this function can be made more generic
 * like zperror() above.
 */

static void
zperror2(const char *zone, const char *str)
{
	(void) fprintf(stderr, "%s: %s: %s: %s\n", execname, zone, str,
	    zonecfg_strerror(errno));
}

/* PRINTFLIKE1 */
static void
zerror(const char *fmt, ...)
{
	va_list alist;

	va_start(alist, fmt);
	(void) fprintf(stderr, "%s: ", execname);
	if (target_zone != NULL)
		(void) fprintf(stderr, "zone '%s': ", target_zone);
	(void) vfprintf(stderr, fmt, alist);
	(void) fprintf(stderr, "\n");
	va_end(alist);
}

static void *
safe_calloc(size_t nelem, size_t elsize)
{
	void *r = calloc(nelem, elsize);

	if (r == NULL) {
		zerror(gettext("failed to allocate %lu bytes: %s"),
		    (ulong_t)nelem * elsize, strerror(errno));
		exit(Z_ERR);
	}
	return (r);
}

static void
zone_print(zone_entry_t *zent, boolean_t verbose, boolean_t parsable)
{
	static boolean_t firsttime = B_TRUE;

	assert(!(verbose && parsable));
	if (firsttime && verbose) {
		firsttime = B_FALSE;
		(void) printf("%*s %-16s %-14s %-30s\n", ZONEID_WIDTH, "ID",
		    "NAME", "STATUS", "PATH");
	}
	if (!verbose) {
		if (!parsable) {
			(void) printf("%s\n", zent->zname);
			return;
		}
		if (zent->zid == ZONE_ID_UNDEFINED)
			(void) printf("-");
		else
			(void) printf("%lu", zent->zid);
		(void) printf(":%s:%s:%s\n", zent->zname, zent->zstate_str,
		    zent->zroot);
		return;
	}
	if (zent->zstate_str != NULL) {
		if (zent->zid == ZONE_ID_UNDEFINED)
			(void) printf("%*s", ZONEID_WIDTH, "-");
		else
			(void) printf("%*lu", ZONEID_WIDTH, zent->zid);
		(void) printf(" %-16s %-14s %-30s\n", zent->zname,
		    zent->zstate_str, zent->zroot);
	}
}

static int
lookup_zone_info(const char *zone_name, zoneid_t zid, zone_entry_t *zent)
{
	char root[MAXPATHLEN];
	int err;

	(void) strlcpy(zent->zname, zone_name, sizeof (zent->zname));
	(void) strlcpy(zent->zroot, "???", sizeof (zent->zroot));
	zent->zstate_str = "???";

	zent->zid = zid;

	if ((err = zone_get_zonepath(zent->zname, root, sizeof (root))) !=
	    Z_OK) {
		errno = err;
		zperror2(zent->zname, gettext("could not get zone path"));
		return (Z_ERR);
	}
	(void) strlcpy(zent->zroot, root, sizeof (zent->zroot));

	if ((err = zone_get_state(zent->zname, &zent->zstate_num)) != Z_OK) {
		errno = err;
		zperror2(zent->zname, gettext("could not get state"));
		return (Z_ERR);
	}
	zent->zstate_str = zone_state_str(zent->zstate_num);

	return (Z_OK);
}

/*
 * fetch_zents() calls zone_list(2) to find out how many zones are running
 * (which is stored in the global nzents), then calls zone_list(2) again
 * to fetch the list of running zones (stored in the global zents).  This
 * function may be called multiple times, so if zents is already set, we
 * return immediately to save work.
 */

static int
fetch_zents(void)
{
	zoneid_t *zids = NULL;
	uint_t nzents_saved;
	int i, retv;
	FILE *fp;
	boolean_t inaltroot;
	zone_entry_t *zentp;

	if (nzents > 0)
		return (Z_OK);

	if (zone_list(NULL, &nzents) != 0) {
		zperror(gettext("failed to get zoneid list"), B_FALSE);
		return (Z_ERR);
	}

again:
	if (nzents == 0)
		return (Z_OK);

	zids = safe_calloc(nzents, sizeof (zoneid_t));
	nzents_saved = nzents;

	if (zone_list(zids, &nzents) != 0) {
		zperror(gettext("failed to get zone list"), B_FALSE);
		free(zids);
		return (Z_ERR);
	}
	if (nzents != nzents_saved) {
		/* list changed, try again */
		free(zids);
		goto again;
	}

	zents = safe_calloc(nzents, sizeof (zone_entry_t));

	inaltroot = zonecfg_in_alt_root();
	if (inaltroot)
		fp = zonecfg_open_scratch("", B_FALSE);
	else
		fp = NULL;
	zentp = zents;
	retv = Z_OK;
	for (i = 0; i < nzents; i++) {
		char name[ZONENAME_MAX];
		char altname[ZONENAME_MAX];

		if (getzonenamebyid(zids[i], name, sizeof (name)) < 0) {
			zperror(gettext("failed to get zone name"), B_FALSE);
			retv = Z_ERR;
			continue;
		}
		if (zonecfg_is_scratch(name)) {
			/* Ignore scratch zones by default */
			if (!inaltroot)
				continue;
			if (fp == NULL ||
			    zonecfg_reverse_scratch(fp, name, altname,
			    sizeof (altname), NULL, 0) == -1) {
				zerror(gettext("could not resolve scratch "
				    "zone %s"), name);
				retv = Z_ERR;
				continue;
			}
			(void) strcpy(name, altname);
		} else {
			/* Ignore non-scratch when in an alternate root */
			if (inaltroot && strcmp(name, GLOBAL_ZONENAME) != 0)
				continue;
		}
		if (lookup_zone_info(name, zids[i], zentp) != Z_OK) {
			zerror(gettext("failed to get zone data"));
			retv = Z_ERR;
			continue;
		}
		zentp++;
	}
	nzents = zentp - zents;
	if (fp != NULL)
		zonecfg_close_scratch(fp);

	free(zids);
	return (retv);
}

static int
zone_print_list(zone_state_t min_state, boolean_t verbose, boolean_t parsable)
{
	int i;
	zone_entry_t zent;
	FILE *cookie;
	char *name;

	/*
	 * First get the list of running zones from the kernel and print them.
	 * If that is all we need, then return.
	 */
	if ((i = fetch_zents()) != Z_OK) {
		/*
		 * No need for error messages; fetch_zents() has already taken
		 * care of this.
		 */
		return (i);
	}
	for (i = 0; i < nzents; i++)
		zone_print(&zents[i], verbose, parsable);
	if (min_state >= ZONE_STATE_RUNNING)
		return (Z_OK);
	/*
	 * Next, get the full list of zones from the configuration, skipping
	 * any we have already printed.
	 */
	cookie = setzoneent();
	while ((name = getzoneent(cookie)) != NULL) {
		for (i = 0; i < nzents; i++) {
			if (strcmp(zents[i].zname, name) == 0)
				break;
		}
		if (i < nzents) {
			free(name);
			continue;
		}
		if (lookup_zone_info(name, ZONE_ID_UNDEFINED, &zent) != Z_OK) {
			free(name);
			continue;
		}
		free(name);
		if (zent.zstate_num >= min_state)
			zone_print(&zent, verbose, parsable);
	}
	endzoneent(cookie);
	return (Z_OK);
}

static zone_entry_t *
lookup_running_zone(char *str)
{
	zoneid_t zoneid;
	char *cp;
	int i;

	if (fetch_zents() != Z_OK)
		return (NULL);

	for (i = 0; i < nzents; i++) {
		if (strcmp(str, zents[i].zname) == 0)
			return (&zents[i]);
	}
	errno = 0;
	zoneid = strtol(str, &cp, 0);
	if (zoneid < MIN_ZONEID || zoneid > MAX_ZONEID ||
	    errno != 0 || *cp != '\0')
		return (NULL);
	for (i = 0; i < nzents; i++) {
		if (zoneid == zents[i].zid)
			return (&zents[i]);
	}
	return (NULL);
}

/*
 * Check a bit in a mode_t: if on is B_TRUE, that bit should be on; if
 * B_FALSE, it should be off.  Return B_TRUE if the mode is bad (incorrect).
 */
static boolean_t
bad_mode_bit(mode_t mode, mode_t bit, boolean_t on, char *file)
{
	char *str;

	assert(bit == S_IRUSR || bit == S_IWUSR || bit == S_IXUSR ||
	    bit == S_IRGRP || bit == S_IWGRP || bit == S_IXGRP ||
	    bit == S_IROTH || bit == S_IWOTH || bit == S_IXOTH);
	/*
	 * TRANSLATION_NOTE
	 * The strings below will be used as part of a larger message,
	 * either:
	 * (file name) must be (owner|group|world) (read|writ|execut)able
	 * or
	 * (file name) must not be (owner|group|world) (read|writ|execut)able
	 */
	switch (bit) {
	case S_IRUSR:
		str = gettext("owner readable");
		break;
	case S_IWUSR:
		str = gettext("owner writable");
		break;
	case S_IXUSR:
		str = gettext("owner executable");
		break;
	case S_IRGRP:
		str = gettext("group readable");
		break;
	case S_IWGRP:
		str = gettext("group writable");
		break;
	case S_IXGRP:
		str = gettext("group executable");
		break;
	case S_IROTH:
		str = gettext("world readable");
		break;
	case S_IWOTH:
		str = gettext("world writable");
		break;
	case S_IXOTH:
		str = gettext("world executable");
		break;
	}
	if ((mode & bit) == (on ? 0 : bit)) {
		/*
		 * TRANSLATION_NOTE
		 * The first parameter below is a file name; the second
		 * is one of the "(owner|group|world) (read|writ|execut)able"
		 * strings from above.
		 */
		/*
		 * The code below could be simplified but not in a way
		 * that would easily translate to non-English locales.
		 */
		if (on) {
			(void) fprintf(stderr, gettext("%s must be %s.\n"),
			    file, str);
		} else {
			(void) fprintf(stderr, gettext("%s must not be %s.\n"),
			    file, str);
		}
		return (B_TRUE);
	}
	return (B_FALSE);
}

/*
 * We want to make sure that no zone has its zone path as a child node
 * (in the directory sense) of any other.  We do that by comparing this
 * zone's path to the path of all other (non-global) zones.  The comparison
 * in each case is simple: add '/' to the end of the path, then do a
 * strncmp() of the two paths, using the length of the shorter one.
 */

static int
crosscheck_zonepaths(char *path)
{
	char rpath[MAXPATHLEN];		/* resolved path */
	char path_copy[MAXPATHLEN];	/* copy of original path */
	char rpath_copy[MAXPATHLEN];	/* copy of original rpath */
	struct zoneent *ze;
	int res, err;
	FILE *cookie;

	cookie = setzoneent();
	while ((ze = getzoneent_private(cookie)) != NULL) {
		/* Skip zones which are not installed. */
		if (ze->zone_state < ZONE_STATE_INSTALLED) {
			free(ze);
			continue;
		}
		/* Skip the global zone and the current target zone. */
		if (strcmp(ze->zone_name, GLOBAL_ZONENAME) == 0 ||
		    strcmp(ze->zone_name, target_zone) == 0) {
			free(ze);
			continue;
		}
		if (strlen(ze->zone_path) == 0) {
			/* old index file without path, fall back */
			if ((err = zone_get_zonepath(ze->zone_name,
			    ze->zone_path, sizeof (ze->zone_path))) != Z_OK) {
				errno = err;
				zperror2(ze->zone_name,
				    gettext("could not get zone path"));
				free(ze);
				continue;
			}
		}
		(void) snprintf(path_copy, sizeof (path_copy), "%s%s",
		    zonecfg_get_root(), ze->zone_path);
		res = resolvepath(path_copy, rpath, sizeof (rpath));
		if (res == -1) {
			if (errno != ENOENT) {
				zperror(path_copy, B_FALSE);
				free(ze);
				return (Z_ERR);
			}
			(void) printf(gettext("WARNING: zone %s is installed, "
			    "but its %s %s does not exist.\n"), ze->zone_name,
			    "zonepath", path_copy);
			free(ze);
			continue;
		}
		rpath[res] = '\0';
		(void) snprintf(path_copy, sizeof (path_copy), "%s/", path);
		(void) snprintf(rpath_copy, sizeof (rpath_copy), "%s/", rpath);
		if (strncmp(path_copy, rpath_copy,
		    min(strlen(path_copy), strlen(rpath_copy))) == 0) {
			/*
			 * TRANSLATION_NOTE
			 * zonepath is a literal that should not be translated.
			 */
			(void) fprintf(stderr, gettext("%s zonepath (%s) and "
			    "%s zonepath (%s) overlap.\n"),
			    target_zone, path, ze->zone_name, rpath);
			free(ze);
			return (Z_ERR);
		}
		free(ze);
	}
	endzoneent(cookie);
	return (Z_OK);
}

static int
validate_zonepath(char *path, int cmd_num)
{
	int res;			/* result of last library/system call */
	boolean_t err = B_FALSE;	/* have we run into an error? */
	struct stat stbuf;
	struct statvfs vfsbuf;
	char rpath[MAXPATHLEN];		/* resolved path */
	char ppath[MAXPATHLEN];		/* parent path */
	char rppath[MAXPATHLEN];	/* resolved parent path */
	char rootpath[MAXPATHLEN];	/* root path */
	zone_state_t state;

	if (path[0] != '/') {
		(void) fprintf(stderr,
		    gettext("%s is not an absolute path.\n"), path);
		return (Z_ERR);
	}
	if ((res = resolvepath(path, rpath, sizeof (rpath))) == -1) {
		if ((errno != ENOENT) ||
		    (cmd_num != CMD_VERIFY && cmd_num != CMD_INSTALL &&
		    cmd_num != CMD_CLONE && cmd_num != CMD_MOVE)) {
			zperror(path, B_FALSE);
			return (Z_ERR);
		}
		if (cmd_num == CMD_VERIFY) {
			/*
			 * TRANSLATION_NOTE
			 * zoneadm is a literal that should not be translated.
			 */
			(void) fprintf(stderr, gettext("WARNING: %s does not "
			    "exist, so it could not be verified.\nWhen "
			    "'zoneadm %s' is run, '%s' will try to create\n%s, "
			    "and '%s' will be tried again,\nbut the '%s' may "
			    "fail if:\nthe parent directory of %s is group- or "
			    "other-writable\nor\n%s overlaps with any other "
			    "installed zones.\n"), path,
			    cmd_to_str(CMD_INSTALL), cmd_to_str(CMD_INSTALL),
			    path, cmd_to_str(CMD_VERIFY),
			    cmd_to_str(CMD_VERIFY), path, path);
			return (Z_OK);
		}
		/*
		 * The zonepath is supposed to be mode 700 but its
		 * parent(s) 755.  So use 755 on the mkdirp() then
		 * chmod() the zonepath itself to 700.
		 */
		if (mkdirp(path, DEFAULT_DIR_MODE) < 0) {
			zperror(path, B_FALSE);
			return (Z_ERR);
		}
		/*
		 * If the chmod() fails, report the error, but might
		 * as well continue the verify procedure.
		 */
		if (chmod(path, S_IRWXU) != 0)
			zperror(path, B_FALSE);
		/*
		 * Since the mkdir() succeeded, we should not have to
		 * worry about a subsequent ENOENT, thus this should
		 * only recurse once.
		 */
		return (validate_zonepath(path, cmd_num));
	}
	rpath[res] = '\0';
	if (strcmp(path, rpath) != 0) {
		errno = Z_RESOLVED_PATH;
		zperror(path, B_TRUE);
		return (Z_ERR);
	}
	if ((res = stat(rpath, &stbuf)) != 0) {
		zperror(rpath, B_FALSE);
		return (Z_ERR);
	}
	if (!S_ISDIR(stbuf.st_mode)) {
		(void) fprintf(stderr, gettext("%s is not a directory.\n"),
		    rpath);
		return (Z_ERR);
	}
	if ((strcmp(stbuf.st_fstype, MNTTYPE_TMPFS) == 0) ||
	    (strcmp(stbuf.st_fstype, MNTTYPE_XMEMFS) == 0)) {
		(void) printf(gettext("WARNING: %s is on a temporary "
		    "file-system.\n"), rpath);
	}
	if (crosscheck_zonepaths(rpath) != Z_OK)
		return (Z_ERR);
	/*
	 * Try to collect and report as many minor errors as possible
	 * before returning, so the user can learn everything that needs
	 * to be fixed up front.
	 */
	if (stbuf.st_uid != 0) {
		(void) fprintf(stderr, gettext("%s is not owned by root.\n"),
		    rpath);
		err = B_TRUE;
	}
	err |= bad_mode_bit(stbuf.st_mode, S_IRUSR, B_TRUE, rpath);
	err |= bad_mode_bit(stbuf.st_mode, S_IWUSR, B_TRUE, rpath);
	err |= bad_mode_bit(stbuf.st_mode, S_IXUSR, B_TRUE, rpath);
	err |= bad_mode_bit(stbuf.st_mode, S_IRGRP, B_FALSE, rpath);
	err |= bad_mode_bit(stbuf.st_mode, S_IWGRP, B_FALSE, rpath);
	err |= bad_mode_bit(stbuf.st_mode, S_IXGRP, B_FALSE, rpath);
	err |= bad_mode_bit(stbuf.st_mode, S_IROTH, B_FALSE, rpath);
	err |= bad_mode_bit(stbuf.st_mode, S_IWOTH, B_FALSE, rpath);
	err |= bad_mode_bit(stbuf.st_mode, S_IXOTH, B_FALSE, rpath);

	(void) snprintf(ppath, sizeof (ppath), "%s/..", path);
	if ((res = resolvepath(ppath, rppath, sizeof (rppath))) == -1) {
		zperror(ppath, B_FALSE);
		return (Z_ERR);
	}
	rppath[res] = '\0';
	if ((res = stat(rppath, &stbuf)) != 0) {
		zperror(rppath, B_FALSE);
		return (Z_ERR);
	}
	/* theoretically impossible */
	if (!S_ISDIR(stbuf.st_mode)) {
		(void) fprintf(stderr, gettext("%s is not a directory.\n"),
		    rppath);
		return (Z_ERR);
	}
	if (stbuf.st_uid != 0) {
		(void) fprintf(stderr, gettext("%s is not owned by root.\n"),
		    rppath);
		err = B_TRUE;
	}
	err |= bad_mode_bit(stbuf.st_mode, S_IRUSR, B_TRUE, rppath);
	err |= bad_mode_bit(stbuf.st_mode, S_IWUSR, B_TRUE, rppath);
	err |= bad_mode_bit(stbuf.st_mode, S_IXUSR, B_TRUE, rppath);
	err |= bad_mode_bit(stbuf.st_mode, S_IWGRP, B_FALSE, rppath);
	err |= bad_mode_bit(stbuf.st_mode, S_IWOTH, B_FALSE, rppath);
	if (strcmp(rpath, rppath) == 0) {
		(void) fprintf(stderr, gettext("%s is its own parent.\n"),
		    rppath);
		err = B_TRUE;
	}

	if (statvfs(rpath, &vfsbuf) != 0) {
		zperror(rpath, B_FALSE);
		return (Z_ERR);
	}
	if (strcmp(vfsbuf.f_basetype, MNTTYPE_NFS) == 0) {
		/*
		 * TRANSLATION_NOTE
		 * Zonepath and NFS are literals that should not be translated.
		 */
		(void) fprintf(stderr, gettext("Zonepath %s is on an NFS "
		    "mounted file-system.\n"
		    "\tA local file-system must be used.\n"), rpath);
		return (Z_ERR);
	}
	if (vfsbuf.f_flag & ST_NOSUID) {
		/*
		 * TRANSLATION_NOTE
		 * Zonepath and nosuid are literals that should not be
		 * translated.
		 */
		(void) fprintf(stderr, gettext("Zonepath %s is on a nosuid "
		    "file-system.\n"), rpath);
		return (Z_ERR);
	}

	if ((res = zone_get_state(target_zone, &state)) != Z_OK) {
		errno = res;
		zperror2(target_zone, gettext("could not get state"));
		return (Z_ERR);
	}
	/*
	 * The existence of the root path is only bad in the configured state,
	 * as it is *supposed* to be there at the installed and later states.
	 * However, the root path is expected to be there if the zone is
	 * detached.
	 * State/command mismatches are caught earlier in verify_details().
	 */
	if (state == ZONE_STATE_CONFIGURED && cmd_num != CMD_ATTACH) {
		if (snprintf(rootpath, sizeof (rootpath), "%s/root", rpath) >=
		    sizeof (rootpath)) {
			/*
			 * TRANSLATION_NOTE
			 * Zonepath is a literal that should not be translated.
			 */
			(void) fprintf(stderr,
			    gettext("Zonepath %s is too long.\n"), rpath);
			return (Z_ERR);
		}
		if ((res = stat(rootpath, &stbuf)) == 0) {
			if (zonecfg_detached(rpath))
				(void) fprintf(stderr,
				    gettext("Cannot %s detached "
				    "zone.\nUse attach or remove %s "
				    "directory.\n"), cmd_to_str(cmd_num),
				    rpath);
			else
				(void) fprintf(stderr,
				    gettext("Rootpath %s exists; "
				    "remove or move aside prior to %s.\n"),
				    rootpath, cmd_to_str(cmd_num));
			return (Z_ERR);
		}
	}

	return (err ? Z_ERR : Z_OK);
}

static void
release_lock_file(int lockfd)
{
	(void) close(lockfd);
}

static int
grab_lock_file(const char *zone_name, int *lockfd)
{
	char pathbuf[PATH_MAX];
	struct flock flock;

	if (snprintf(pathbuf, sizeof (pathbuf), "%s%s", zonecfg_get_root(),
	    ZONES_TMPDIR) >= sizeof (pathbuf)) {
		zerror(gettext("alternate root path is too long"));
		return (Z_ERR);
	}
	if (mkdir(pathbuf, S_IRWXU) < 0 && errno != EEXIST) {
		zerror(gettext("could not mkdir %s: %s"), pathbuf,
		    strerror(errno));
		return (Z_ERR);
	}
	(void) chmod(pathbuf, S_IRWXU);

	/*
	 * One of these lock files is created for each zone (when needed).
	 * The lock files are not cleaned up (except on system reboot),
	 * but since there is only one per zone, there is no resource
	 * starvation issue.
	 */
	if (snprintf(pathbuf, sizeof (pathbuf), "%s%s/%s.zoneadm.lock",
	    zonecfg_get_root(), ZONES_TMPDIR, zone_name) >= sizeof (pathbuf)) {
		zerror(gettext("alternate root path is too long"));
		return (Z_ERR);
	}
	if ((*lockfd = open(pathbuf, O_RDWR|O_CREAT, S_IRUSR|S_IWUSR)) < 0) {
		zerror(gettext("could not open %s: %s"), pathbuf,
		    strerror(errno));
		return (Z_ERR);
	}
	/*
	 * Lock the file to synchronize with other zoneadmds
	 */
	flock.l_type = F_WRLCK;
	flock.l_whence = SEEK_SET;
	flock.l_start = (off_t)0;
	flock.l_len = (off_t)0;
	if (fcntl(*lockfd, F_SETLKW, &flock) < 0) {
		zerror(gettext("unable to lock %s: %s"), pathbuf,
		    strerror(errno));
		release_lock_file(*lockfd);
		return (Z_ERR);
	}
	return (Z_OK);
}

static boolean_t
get_doorname(const char *zone_name, char *buffer)
{
	return (snprintf(buffer, PATH_MAX, "%s" ZONE_DOOR_PATH,
	    zonecfg_get_root(), zone_name) < PATH_MAX);
}

/*
 * system daemons are not audited.  For the global zone, this occurs
 * "naturally" since init is started with the default audit
 * characteristics.  Since zoneadmd is a system daemon and it starts
 * init for a zone, it is necessary to clear out the audit
 * characteristics inherited from whomever started zoneadmd.  This is
 * indicated by the audit id, which is set from the ruid parameter of
 * adt_set_user(), below.
 */

static void
prepare_audit_context()
{
	adt_session_data_t	*ah;
	char			*failure = gettext("audit failure: %s");

	if (adt_start_session(&ah, NULL, 0)) {
		zerror(failure, strerror(errno));
		return;
	}
	if (adt_set_user(ah, ADT_NO_AUDIT, ADT_NO_AUDIT,
	    ADT_NO_AUDIT, ADT_NO_AUDIT, NULL, ADT_NEW)) {
		zerror(failure, strerror(errno));
		(void) adt_end_session(ah);
		return;
	}
	if (adt_set_proc(ah))
		zerror(failure, strerror(errno));

	(void) adt_end_session(ah);
}

static int
start_zoneadmd(const char *zone_name)
{
	char doorpath[PATH_MAX];
	pid_t child_pid;
	int error = Z_ERR;
	int doorfd, lockfd;
	struct door_info info;

	if (!get_doorname(zone_name, doorpath))
		return (Z_ERR);

	if (grab_lock_file(zone_name, &lockfd) != Z_OK)
		return (Z_ERR);

	/*
	 * Now that we have the lock, re-confirm that the daemon is
	 * *not* up and working fine.  If it is still down, we have a green
	 * light to start it.
	 */
	if ((doorfd = open(doorpath, O_RDONLY)) < 0) {
		if (errno != ENOENT) {
			zperror(doorpath, B_FALSE);
			goto out;
		}
	} else {
		if (door_info(doorfd, &info) == 0 &&
		    ((info.di_attributes & DOOR_REVOKED) == 0)) {
			error = Z_OK;
			(void) close(doorfd);
			goto out;
		}
		(void) close(doorfd);
	}

	if ((child_pid = fork()) == -1) {
		zperror(gettext("could not fork"), B_FALSE);
		goto out;
	} else if (child_pid == 0) {
		const char *argv[6], **ap;

		/* child process */
		prepare_audit_context();

		ap = argv;
		*ap++ = "zoneadmd";
		*ap++ = "-z";
		*ap++ = zone_name;
		if (zonecfg_in_alt_root()) {
			*ap++ = "-R";
			*ap++ = zonecfg_get_root();
		}
		*ap = NULL;

		(void) execv("/usr/lib/zones/zoneadmd", (char * const *)argv);
		/*
		 * TRANSLATION_NOTE
		 * zoneadmd is a literal that should not be translated.
		 */
		zperror(gettext("could not exec zoneadmd"), B_FALSE);
		_exit(Z_ERR);
	} else {
		/* parent process */
		pid_t retval;
		int pstatus = 0;

		do {
			retval = waitpid(child_pid, &pstatus, 0);
		} while (retval != child_pid);
		if (WIFSIGNALED(pstatus) || (WIFEXITED(pstatus) &&
		    WEXITSTATUS(pstatus) != 0)) {
			zerror(gettext("could not start %s"), "zoneadmd");
			goto out;
		}
	}
	error = Z_OK;
out:
	release_lock_file(lockfd);
	return (error);
}

static int
ping_zoneadmd(const char *zone_name)
{
	char doorpath[PATH_MAX];
	int doorfd;
	struct door_info info;

	if (!get_doorname(zone_name, doorpath))
		return (Z_ERR);

	if ((doorfd = open(doorpath, O_RDONLY)) < 0) {
		return (Z_ERR);
	}
	if (door_info(doorfd, &info) == 0 &&
	    ((info.di_attributes & DOOR_REVOKED) == 0)) {
		(void) close(doorfd);
		return (Z_OK);
	}
	(void) close(doorfd);
	return (Z_ERR);
}

static int
call_zoneadmd(const char *zone_name, zone_cmd_arg_t *arg)
{
	char doorpath[PATH_MAX];
	int doorfd, result;
	door_arg_t darg;

	zoneid_t zoneid;
	uint64_t uniqid = 0;

	zone_cmd_rval_t *rvalp;
	size_t rlen;
	char *cp, *errbuf;

	rlen = getpagesize();
	if ((rvalp = malloc(rlen)) == NULL) {
		zerror(gettext("failed to allocate %lu bytes: %s"), rlen,
		    strerror(errno));
		return (-1);
	}

	if ((zoneid = getzoneidbyname(zone_name)) != ZONE_ID_UNDEFINED) {
		(void) zone_getattr(zoneid, ZONE_ATTR_UNIQID, &uniqid,
		    sizeof (uniqid));
	}
	arg->uniqid = uniqid;
	(void) strlcpy(arg->locale, locale, sizeof (arg->locale));
	if (!get_doorname(zone_name, doorpath)) {
		zerror(gettext("alternate root path is too long"));
		free(rvalp);
		return (-1);
	}

	/*
	 * Loop trying to start zoneadmd; if something goes seriously
	 * wrong we break out and fail.
	 */
	for (;;) {
		if (start_zoneadmd(zone_name) != Z_OK)
			break;

		if ((doorfd = open(doorpath, O_RDONLY)) < 0) {
			zperror(gettext("failed to open zone door"), B_FALSE);
			break;
		}

		darg.data_ptr = (char *)arg;
		darg.data_size = sizeof (*arg);
		darg.desc_ptr = NULL;
		darg.desc_num = 0;
		darg.rbuf = (char *)rvalp;
		darg.rsize = rlen;
		if (door_call(doorfd, &darg) != 0) {
			(void) close(doorfd);
			/*
			 * We'll get EBADF if the door has been revoked.
			 */
			if (errno != EBADF) {
				zperror(gettext("door_call failed"), B_FALSE);
				break;
			}
			continue;	/* take another lap */
		}
		(void) close(doorfd);

		if (darg.data_size == 0) {
			/* Door server is going away; kick it again. */
			continue;
		}

		errbuf = rvalp->errbuf;
		while (*errbuf != '\0') {
			/*
			 * Remove any newlines since zerror()
			 * will append one automatically.
			 */
			cp = strchr(errbuf, '\n');
			if (cp != NULL)
				*cp = '\0';
			zerror("%s", errbuf);
			if (cp == NULL)
				break;
			errbuf = cp + 1;
		}
		result = rvalp->rval == 0 ? 0 : -1;
		free(rvalp);
		return (result);
	}

	free(rvalp);
	return (-1);
}

static int
ready_func(int argc, char *argv[])
{
	zone_cmd_arg_t zarg;
	int arg;

	if (zonecfg_in_alt_root()) {
		zerror(gettext("cannot ready zone in alternate root"));
		return (Z_ERR);
	}

	optind = 0;
	if ((arg = getopt(argc, argv, "?")) != EOF) {
		switch (arg) {
		case '?':
			sub_usage(SHELP_READY, CMD_READY);
			return (optopt == '?' ? Z_OK : Z_USAGE);
		default:
			sub_usage(SHELP_READY, CMD_READY);
			return (Z_USAGE);
		}
	}
	if (argc > optind) {
		sub_usage(SHELP_READY, CMD_READY);
		return (Z_USAGE);
	}
	if (sanity_check(target_zone, CMD_READY, B_FALSE, B_FALSE) != Z_OK)
		return (Z_ERR);
	if (verify_details(CMD_READY) != Z_OK)
		return (Z_ERR);

	zarg.cmd = Z_READY;
	if (call_zoneadmd(target_zone, &zarg) != 0) {
		zerror(gettext("call to %s failed"), "zoneadmd");
		return (Z_ERR);
	}
	return (Z_OK);
}

static int
boot_func(int argc, char *argv[])
{
	zone_cmd_arg_t zarg;
	int arg;

	if (zonecfg_in_alt_root()) {
		zerror(gettext("cannot boot zone in alternate root"));
		return (Z_ERR);
	}

	zarg.bootbuf[0] = '\0';

	/*
	 * At the current time, the only supported subargument to the
	 * "boot" subcommand is "-s" which specifies a single-user boot.
	 * In the future, other boot arguments should be supported
	 * including "-m" for specifying alternate smf(5) milestones.
	 */
	optind = 0;
	if ((arg = getopt(argc, argv, "?s")) != EOF) {
		switch (arg) {
		case '?':
			sub_usage(SHELP_BOOT, CMD_BOOT);
			return (optopt == '?' ? Z_OK : Z_USAGE);
		case 's':
			(void) strlcpy(zarg.bootbuf, "-s",
			    sizeof (zarg.bootbuf));
			break;
		default:
			sub_usage(SHELP_BOOT, CMD_BOOT);
			return (Z_USAGE);
		}
	}
	if (argc > optind) {
		sub_usage(SHELP_BOOT, CMD_BOOT);
		return (Z_USAGE);
	}
	if (sanity_check(target_zone, CMD_BOOT, B_FALSE, B_FALSE) != Z_OK)
		return (Z_ERR);
	if (verify_details(CMD_BOOT) != Z_OK)
		return (Z_ERR);
	zarg.cmd = Z_BOOT;
	if (call_zoneadmd(target_zone, &zarg) != 0) {
		zerror(gettext("call to %s failed"), "zoneadmd");
		return (Z_ERR);
	}
	return (Z_OK);
}

static void
fake_up_local_zone(zoneid_t zid, zone_entry_t *zeptr)
{
	ssize_t result;

	zeptr->zid = zid;
	/*
	 * Since we're looking up our own (non-global) zone name,
	 * we can be assured that it will succeed.
	 */
	result = getzonenamebyid(zid, zeptr->zname, sizeof (zeptr->zname));
	assert(result >= 0);
	(void) strlcpy(zeptr->zroot, "/", sizeof (zeptr->zroot));
	zeptr->zstate_str = "running";
}

static int
list_func(int argc, char *argv[])
{
	zone_entry_t *zentp, zent;
	int arg, retv;
	boolean_t output = B_FALSE, verbose = B_FALSE, parsable = B_FALSE;
	zone_state_t min_state = ZONE_STATE_RUNNING;
	zoneid_t zone_id = getzoneid();

	if (target_zone == NULL) {
		/* all zones: default view to running but allow override */
		optind = 0;
		while ((arg = getopt(argc, argv, "?cipv")) != EOF) {
			switch (arg) {
			case '?':
				sub_usage(SHELP_LIST, CMD_LIST);
				return (optopt == '?' ? Z_OK : Z_USAGE);
				/*
				 * The 'i' and 'c' options are not mutually
				 * exclusive so if 'c' is given, then min_state
				 * is set to 0 (ZONE_STATE_CONFIGURED) which is
				 * the lowest possible state.  If 'i' is given,
				 * then min_state is set to be the lowest state
				 * so far.
				 */
			case 'c':
				min_state = ZONE_STATE_CONFIGURED;
				break;
			case 'i':
				min_state = min(ZONE_STATE_INSTALLED,
				    min_state);

				break;
			case 'p':
				parsable = B_TRUE;
				break;
			case 'v':
				verbose = B_TRUE;
				break;
			default:
				sub_usage(SHELP_LIST, CMD_LIST);
				return (Z_USAGE);
			}
		}
		if (parsable && verbose) {
			zerror(gettext("%s -p and -v are mutually exclusive."),
			    cmd_to_str(CMD_LIST));
			return (Z_ERR);
		}
		if (zone_id == GLOBAL_ZONEID) {
			retv = zone_print_list(min_state, verbose, parsable);
		} else {
			retv = Z_OK;
			fake_up_local_zone(zone_id, &zent);
			zone_print(&zent, verbose, parsable);
		}
		return (retv);
	}

	/*
	 * Specific target zone: disallow -i/-c suboptions.
	 */
	optind = 0;
	while ((arg = getopt(argc, argv, "?pv")) != EOF) {
		switch (arg) {
		case '?':
			sub_usage(SHELP_LIST, CMD_LIST);
			return (optopt == '?' ? Z_OK : Z_USAGE);
		case 'p':
			parsable = B_TRUE;
			break;
		case 'v':
			verbose = B_TRUE;
			break;
		default:
			sub_usage(SHELP_LIST, CMD_LIST);
			return (Z_USAGE);
		}
	}
	if (parsable && verbose) {
		zerror(gettext("%s -p and -v are mutually exclusive."),
		    cmd_to_str(CMD_LIST));
		return (Z_ERR);
	}
	if (argc > optind) {
		sub_usage(SHELP_LIST, CMD_LIST);
		return (Z_USAGE);
	}
	if (zone_id != GLOBAL_ZONEID) {
		fake_up_local_zone(zone_id, &zent);
		/*
		 * main() will issue a Z_NO_ZONE error if it cannot get an
		 * id for target_zone, which in a non-global zone should
		 * happen for any zone name except `zonename`.  Thus we
		 * assert() that here but don't otherwise check.
		 */
		assert(strcmp(zent.zname, target_zone) == 0);
		zone_print(&zent, verbose, parsable);
		output = B_TRUE;
	} else if ((zentp = lookup_running_zone(target_zone)) != NULL) {
		zone_print(zentp, verbose, parsable);
		output = B_TRUE;
	} else if (lookup_zone_info(target_zone, ZONE_ID_UNDEFINED,
	    &zent) == Z_OK) {
		zone_print(&zent, verbose, parsable);
		output = B_TRUE;
	}
	return (output ? Z_OK : Z_ERR);
}

static void
sigterm(int sig)
{
	/*
	 * Ignore SIG{INT,TERM}, so we don't end up in an infinite loop,
	 * then propagate the signal to our process group.
	 */
	(void) sigset(SIGINT, SIG_IGN);
	(void) sigset(SIGTERM, SIG_IGN);
	(void) kill(0, sig);
	child_killed = B_TRUE;
}

static int
do_subproc(char *cmdbuf)
{
	char inbuf[1024];	/* arbitrary large amount */
	FILE *file;

	child_killed = B_FALSE;
	/*
	 * We use popen(3c) to launch child processes for [un]install;
	 * this library call does not return a PID, so we have to kill
	 * the whole process group.  To avoid killing our parent, we
	 * become a process group leader here.  But doing so can wreak
	 * havoc with reading from stdin when launched by a non-job-control
	 * shell, so we close stdin and reopen it as /dev/null first.
	 */
	(void) close(STDIN_FILENO);
	(void) open("/dev/null", O_RDONLY);
	(void) setpgid(0, 0);
	(void) sigset(SIGINT, sigterm);
	(void) sigset(SIGTERM, sigterm);
	file = popen(cmdbuf, "r");
	for (;;) {
		if (child_killed || fgets(inbuf, sizeof (inbuf), file) == NULL)
			break;
		(void) fputs(inbuf, stdout);
	}
	(void) sigset(SIGINT, SIG_DFL);
	(void) sigset(SIGTERM, SIG_DFL);
	return (pclose(file));
}

static int
subproc_status(const char *cmd, int status)
{
	if (WIFEXITED(status)) {
		int exit_code = WEXITSTATUS(status);

		if (exit_code == 0)
			return (Z_OK);
		zerror(gettext("'%s' failed with exit code %d."), cmd,
		    exit_code);
	} else if (WIFSIGNALED(status)) {
		int signal = WTERMSIG(status);
		char sigstr[SIG2STR_MAX];

		if (sig2str(signal, sigstr) == 0) {
			zerror(gettext("'%s' terminated by signal SIG%s."), cmd,
			    sigstr);
		} else {
			zerror(gettext("'%s' terminated by an unknown signal."),
			    cmd);
		}
	} else {
		zerror(gettext("'%s' failed for unknown reasons."), cmd);
	}
	return (Z_ERR);
}

/*
 * Various sanity checks; make sure:
 * 1. We're in the global zone.
 * 2. The calling user has sufficient privilege.
 * 3. The target zone is neither the global zone nor anything starting with
 *    "SUNW".
 * 4a. If we're looking for a 'not running' (i.e., configured or installed)
 *     zone, the name service knows about it.
 * 4b. For some operations which expect a zone not to be running, that it is
 *     not already running (or ready).
 */
static int
sanity_check(char *zone, int cmd_num, boolean_t running,
    boolean_t unsafe_when_running)
{
	zone_entry_t *zent;
	priv_set_t *privset;
	zone_state_t state;
	char kernzone[ZONENAME_MAX];
	FILE *fp;

	if (getzoneid() != GLOBAL_ZONEID) {
		zerror(gettext("must be in the global zone to %s a zone."),
		    cmd_to_str(cmd_num));
		return (Z_ERR);
	}

	if ((privset = priv_allocset()) == NULL) {
		zerror(gettext("%s failed"), "priv_allocset");
		return (Z_ERR);
	}

	if (getppriv(PRIV_EFFECTIVE, privset) != 0) {
		zerror(gettext("%s failed"), "getppriv");
		priv_freeset(privset);
		return (Z_ERR);
	}

	if (priv_isfullset(privset) == B_FALSE) {
		zerror(gettext("only a privileged user may %s a zone."),
		    cmd_to_str(cmd_num));
		priv_freeset(privset);
		return (Z_ERR);
	}
	priv_freeset(privset);

	if (zone == NULL) {
		zerror(gettext("no zone specified"));
		return (Z_ERR);
	}

	if (strcmp(zone, GLOBAL_ZONENAME) == 0) {
		zerror(gettext("%s operation is invalid for the global zone."),
		    cmd_to_str(cmd_num));
		return (Z_ERR);
	}

	if (strncmp(zone, "SUNW", 4) == 0) {
		zerror(gettext("%s operation is invalid for zones starting "
		    "with SUNW."), cmd_to_str(cmd_num));
		return (Z_ERR);
	}

	if (!zonecfg_in_alt_root()) {
		zent = lookup_running_zone(zone);
	} else if ((fp = zonecfg_open_scratch("", B_FALSE)) == NULL) {
		zent = NULL;
	} else {
		if (zonecfg_find_scratch(fp, zone, zonecfg_get_root(),
		    kernzone, sizeof (kernzone)) == 0)
			zent = lookup_running_zone(kernzone);
		else
			zent = NULL;
		zonecfg_close_scratch(fp);
	}

	/*
	 * Look up from the kernel for 'running' zones.
	 */
	if (running) {
		if (zent == NULL) {
			zerror(gettext("not running"));
			return (Z_ERR);
		}
	} else {
		int err;

		if (unsafe_when_running && zent != NULL) {
			/* check whether the zone is ready or running */
			if ((err = zone_get_state(zent->zname,
			    &zent->zstate_num)) != Z_OK) {
				errno = err;
				zperror2(zent->zname,
				    gettext("could not get state"));
				/* can't tell, so hedge */
				zent->zstate_str = "ready/running";
			} else {
				zent->zstate_str =
				    zone_state_str(zent->zstate_num);
			}
			zerror(gettext("%s operation is invalid for %s zones."),
			    cmd_to_str(cmd_num), zent->zstate_str);
			return (Z_ERR);
		}
		if ((err = zone_get_state(zone, &state)) != Z_OK) {
			errno = err;
			zperror2(zone, gettext("could not get state"));
			return (Z_ERR);
		}
		switch (cmd_num) {
		case CMD_UNINSTALL:
			if (state == ZONE_STATE_CONFIGURED) {
				zerror(gettext("is already in state '%s'."),
				    zone_state_str(ZONE_STATE_CONFIGURED));
				return (Z_ERR);
			}
			break;
		case CMD_ATTACH:
		case CMD_CLONE:
		case CMD_INSTALL:
			if (state == ZONE_STATE_INSTALLED) {
				zerror(gettext("is already %s."),
				    zone_state_str(ZONE_STATE_INSTALLED));
				return (Z_ERR);
			} else if (state == ZONE_STATE_INCOMPLETE) {
				zerror(gettext("zone is %s; %s required."),
				    zone_state_str(ZONE_STATE_INCOMPLETE),
				    cmd_to_str(CMD_UNINSTALL));
				return (Z_ERR);
			}
			break;
		case CMD_DETACH:
		case CMD_MOVE:
		case CMD_READY:
		case CMD_BOOT:
		case CMD_MOUNT:
			if (state < ZONE_STATE_INSTALLED) {
				zerror(gettext("must be %s before %s."),
				    zone_state_str(ZONE_STATE_INSTALLED),
				    cmd_to_str(cmd_num));
				return (Z_ERR);
			}
			break;
		case CMD_VERIFY:
			if (state == ZONE_STATE_INCOMPLETE) {
				zerror(gettext("zone is %s; %s required."),
				    zone_state_str(ZONE_STATE_INCOMPLETE),
				    cmd_to_str(CMD_UNINSTALL));
				return (Z_ERR);
			}
			break;
		case CMD_UNMOUNT:
			if (state != ZONE_STATE_MOUNTED) {
				zerror(gettext("must be %s before %s."),
				    zone_state_str(ZONE_STATE_MOUNTED),
				    cmd_to_str(cmd_num));
				return (Z_ERR);
			}
			break;
		}
	}
	return (Z_OK);
}

static int
halt_func(int argc, char *argv[])
{
	zone_cmd_arg_t zarg;
	int arg;

	if (zonecfg_in_alt_root()) {
		zerror(gettext("cannot halt zone in alternate root"));
		return (Z_ERR);
	}

	optind = 0;
	if ((arg = getopt(argc, argv, "?")) != EOF) {
		switch (arg) {
		case '?':
			sub_usage(SHELP_HALT, CMD_HALT);
			return (optopt == '?' ? Z_OK : Z_USAGE);
		default:
			sub_usage(SHELP_HALT, CMD_HALT);
			return (Z_USAGE);
		}
	}
	if (argc > optind) {
		sub_usage(SHELP_HALT, CMD_HALT);
		return (Z_USAGE);
	}
	/*
	 * zoneadmd should be the one to decide whether or not to proceed,
	 * so even though it seems that the fourth parameter below should
	 * perhaps be B_TRUE, it really shouldn't be.
	 */
	if (sanity_check(target_zone, CMD_HALT, B_FALSE, B_FALSE) != Z_OK)
		return (Z_ERR);

	zarg.cmd = Z_HALT;
	return ((call_zoneadmd(target_zone, &zarg) == 0) ? Z_OK : Z_ERR);
}

static int
reboot_func(int argc, char *argv[])
{
	zone_cmd_arg_t zarg;
	int arg;

	if (zonecfg_in_alt_root()) {
		zerror(gettext("cannot reboot zone in alternate root"));
		return (Z_ERR);
	}

	optind = 0;
	if ((arg = getopt(argc, argv, "?")) != EOF) {
		switch (arg) {
		case '?':
			sub_usage(SHELP_REBOOT, CMD_REBOOT);
			return (optopt == '?' ? Z_OK : Z_USAGE);
		default:
			sub_usage(SHELP_REBOOT, CMD_REBOOT);
			return (Z_USAGE);
		}
	}
	if (argc > 0) {
		sub_usage(SHELP_REBOOT, CMD_REBOOT);
		return (Z_USAGE);
	}
	/*
	 * zoneadmd should be the one to decide whether or not to proceed,
	 * so even though it seems that the fourth parameter below should
	 * perhaps be B_TRUE, it really shouldn't be.
	 */
	if (sanity_check(target_zone, CMD_REBOOT, B_TRUE, B_FALSE) != Z_OK)
		return (Z_ERR);
	if (verify_details(CMD_REBOOT) != Z_OK)
		return (Z_ERR);

	zarg.cmd = Z_REBOOT;
	return ((call_zoneadmd(target_zone, &zarg) == 0) ? Z_OK : Z_ERR);
}

static int
verify_rctls(zone_dochandle_t handle)
{
	struct zone_rctltab rctltab;
	size_t rbs = rctlblk_size();
	rctlblk_t *rctlblk;
	int error = Z_INVAL;

	if ((rctlblk = malloc(rbs)) == NULL) {
		zerror(gettext("failed to allocate %lu bytes: %s"), rbs,
		    strerror(errno));
		return (Z_NOMEM);
	}

	if (zonecfg_setrctlent(handle) != Z_OK) {
		zerror(gettext("zonecfg_setrctlent failed"));
		free(rctlblk);
		return (error);
	}

	rctltab.zone_rctl_valptr = NULL;
	while (zonecfg_getrctlent(handle, &rctltab) == Z_OK) {
		struct zone_rctlvaltab *rctlval;
		const char *name = rctltab.zone_rctl_name;

		if (!zonecfg_is_rctl(name)) {
			zerror(gettext("WARNING: Ignoring unrecognized rctl "
			    "'%s'."),  name);
			zonecfg_free_rctl_value_list(rctltab.zone_rctl_valptr);
			rctltab.zone_rctl_valptr = NULL;
			continue;
		}

		for (rctlval = rctltab.zone_rctl_valptr; rctlval != NULL;
		    rctlval = rctlval->zone_rctlval_next) {
			if (zonecfg_construct_rctlblk(rctlval, rctlblk)
			    != Z_OK) {
				zerror(gettext("invalid rctl value: "
				    "(priv=%s,limit=%s,action%s)"),
				    rctlval->zone_rctlval_priv,
				    rctlval->zone_rctlval_limit,
				    rctlval->zone_rctlval_action);
				goto out;
			}
			if (!zonecfg_valid_rctl(name, rctlblk)) {
				zerror(gettext("(priv=%s,limit=%s,action=%s) "
				    "is not a valid value for rctl '%s'"),
				    rctlval->zone_rctlval_priv,
				    rctlval->zone_rctlval_limit,
				    rctlval->zone_rctlval_action,
				    name);
				goto out;
			}
		}
		zonecfg_free_rctl_value_list(rctltab.zone_rctl_valptr);
	}
	rctltab.zone_rctl_valptr = NULL;
	error = Z_OK;
out:
	zonecfg_free_rctl_value_list(rctltab.zone_rctl_valptr);
	(void) zonecfg_endrctlent(handle);
	free(rctlblk);
	return (error);
}

static int
verify_pool(zone_dochandle_t handle)
{
	char poolname[MAXPATHLEN];
	pool_conf_t *poolconf;
	pool_t *pool;
	int status;
	int error;

	/*
	 * This ends up being very similar to the check done in zoneadmd.
	 */
	error = zonecfg_get_pool(handle, poolname, sizeof (poolname));
	if (error == Z_NO_ENTRY || (error == Z_OK && strlen(poolname) == 0)) {
		/*
		 * No pool specified.
		 */
		return (0);
	}
	if (error != Z_OK) {
		zperror(gettext("Unable to retrieve pool name from "
		    "configuration"), B_TRUE);
		return (error);
	}
	/*
	 * Don't do anything if pools aren't enabled.
	 */
	if (pool_get_status(&status) != PO_SUCCESS || status != POOL_ENABLED) {
		zerror(gettext("WARNING: pools facility not active; "
		    "zone will not be bound to pool '%s'."), poolname);
		return (Z_OK);
	}
	/*
	 * Try to provide a sane error message if the requested pool doesn't
	 * exist.  It isn't clear that pools-related failures should
	 * necessarily translate to a failure to verify the zone configuration,
	 * hence they are not considered errors.
	 */
	if ((poolconf = pool_conf_alloc()) == NULL) {
		zerror(gettext("WARNING: pool_conf_alloc failed; "
		    "using default pool"));
		return (Z_OK);
	}
	if (pool_conf_open(poolconf, pool_dynamic_location(), PO_RDONLY) !=
	    PO_SUCCESS) {
		zerror(gettext("WARNING: pool_conf_open failed; "
		    "using default pool"));
		pool_conf_free(poolconf);
		return (Z_OK);
	}
	pool = pool_get_pool(poolconf, poolname);
	(void) pool_conf_close(poolconf);
	pool_conf_free(poolconf);
	if (pool == NULL) {
		zerror(gettext("WARNING: pool '%s' not found. "
		    "using default pool"), poolname);
	}

	return (Z_OK);
}

static int
verify_ipd(zone_dochandle_t handle)
{
	int return_code = Z_OK;
	struct zone_fstab fstab;
	struct stat st;
	char specdir[MAXPATHLEN];

	if (zonecfg_setipdent(handle) != Z_OK) {
		/*
		 * TRANSLATION_NOTE
		 * inherit-pkg-dirs is a literal that should not be translated.
		 */
		(void) fprintf(stderr, gettext("could not verify "
		    "inherit-pkg-dirs: unable to enumerate mounts\n"));
		return (Z_ERR);
	}
	while (zonecfg_getipdent(handle, &fstab) == Z_OK) {
		/*
		 * Verify fs_dir exists.
		 */
		(void) snprintf(specdir, sizeof (specdir), "%s%s",
		    zonecfg_get_root(), fstab.zone_fs_dir);
		if (stat(specdir, &st) != 0) {
			/*
			 * TRANSLATION_NOTE
			 * inherit-pkg-dir is a literal that should not be
			 * translated.
			 */
			(void) fprintf(stderr, gettext("could not verify "
			    "inherit-pkg-dir %s: %s\n"),
			    fstab.zone_fs_dir, strerror(errno));
			return_code = Z_ERR;
		}
		if (strcmp(st.st_fstype, MNTTYPE_NFS) == 0) {
			/*
			 * TRANSLATION_NOTE
			 * inherit-pkg-dir and NFS are literals that should
			 * not be translated.
			 */
			(void) fprintf(stderr, gettext("cannot verify "
			    "inherit-pkg-dir %s: NFS mounted file-system.\n"
			    "\tA local file-system must be used.\n"),
			    fstab.zone_fs_dir);
			return_code = Z_ERR;
		}
	}
	(void) zonecfg_endipdent(handle);

	return (return_code);
}

/* ARGSUSED */
static void
zfs_fs_err_handler(const char *fmt, va_list ap)
{
	/*
	 * Do nothing - do not print the libzfs error messages.
	 */
}

/*
 * Verify that the ZFS dataset exists, and its mountpoint
 * property is set to "legacy".
 */
static int
verify_fs_zfs(struct zone_fstab *fstab)
{
	zfs_handle_t *zhp;
	char propbuf[ZFS_MAXPROPLEN];

	zfs_set_error_handler(zfs_fs_err_handler);

	if ((zhp = zfs_open(fstab->zone_fs_special, ZFS_TYPE_ANY)) == NULL) {
		(void) fprintf(stderr, gettext("could not verify fs %s: "
			"could not access zfs dataset '%s'\n"),
			fstab->zone_fs_dir, fstab->zone_fs_special);
		return (Z_ERR);
	}

	if (zfs_get_type(zhp) != ZFS_TYPE_FILESYSTEM) {
		(void) fprintf(stderr, gettext("cannot verify fs %s: "
			"'%s' is not a filesystem\n"),
			fstab->zone_fs_dir, fstab->zone_fs_special);
		zfs_close(zhp);
		return (Z_ERR);
	}

	if (zfs_prop_get(zhp, ZFS_PROP_MOUNTPOINT, propbuf, sizeof (propbuf),
	    NULL, NULL, 0, 0) != 0 || strcmp(propbuf, "legacy") != 0) {
		(void) fprintf(stderr, gettext("could not verify fs %s: "
			"zfs '%s' mountpoint is not \"legacy\"\n"),
			fstab->zone_fs_dir, fstab->zone_fs_special);
		zfs_close(zhp);
		return (Z_ERR);
	}

	zfs_close(zhp);
	return (Z_OK);
}

/*
 * Verify that the special device/filesystem exists and is valid.
 */
static int
verify_fs_special(struct zone_fstab *fstab)
{
	struct stat st;

	if (strcmp(fstab->zone_fs_type, MNTTYPE_ZFS) == 0)
		return (verify_fs_zfs(fstab));

	if (stat(fstab->zone_fs_special, &st) != 0) {
		(void) fprintf(stderr, gettext("could not verify fs "
		    "%s: could not access %s: %s\n"), fstab->zone_fs_dir,
		    fstab->zone_fs_special, strerror(errno));
		return (Z_ERR);
	}

	if (strcmp(st.st_fstype, MNTTYPE_NFS) == 0) {
		/*
		 * TRANSLATION_NOTE
		 * fs and NFS are literals that should
		 * not be translated.
		 */
		(void) fprintf(stderr, gettext("cannot verify "
		    "fs %s: NFS mounted file-system.\n"
		    "\tA local file-system must be used.\n"),
		    fstab->zone_fs_special);
		return (Z_ERR);
	}

	return (Z_OK);
}

static int
verify_filesystems(zone_dochandle_t handle)
{
	int return_code = Z_OK;
	struct zone_fstab fstab;
	char cmdbuf[MAXPATHLEN];
	struct stat st;

	/*
	 * No need to verify inherit-pkg-dir fs types, as their type is
	 * implicitly lofs, which is known.  Therefore, the types are only
	 * verified for regular filesystems below.
	 *
	 * Since the actual mount point is not known until the dependent mounts
	 * are performed, we don't attempt any path validation here: that will
	 * happen later when zoneadmd actually does the mounts.
	 */
	if (zonecfg_setfsent(handle) != Z_OK) {
		(void) fprintf(stderr, gettext("could not verify file-systems: "
		    "unable to enumerate mounts\n"));
		return (Z_ERR);
	}
	while (zonecfg_getfsent(handle, &fstab) == Z_OK) {
		if (!zonecfg_valid_fs_type(fstab.zone_fs_type)) {
			(void) fprintf(stderr, gettext("cannot verify fs %s: "
			    "type %s is not allowed.\n"), fstab.zone_fs_dir,
			    fstab.zone_fs_type);
			return_code = Z_ERR;
			goto next_fs;
		}
		/*
		 * Verify /usr/lib/fs/<fstype>/mount exists.
		 */
		if (snprintf(cmdbuf, sizeof (cmdbuf), "/usr/lib/fs/%s/mount",
		    fstab.zone_fs_type) > sizeof (cmdbuf)) {
			(void) fprintf(stderr, gettext("cannot verify fs %s: "
			    "type %s is too long.\n"), fstab.zone_fs_dir,
			    fstab.zone_fs_type);
			return_code = Z_ERR;
			goto next_fs;
		}
		if (stat(cmdbuf, &st) != 0) {
			(void) fprintf(stderr, gettext("could not verify fs "
			    "%s: could not access %s: %s\n"), fstab.zone_fs_dir,
			    cmdbuf, strerror(errno));
			return_code = Z_ERR;
			goto next_fs;
		}
		if (!S_ISREG(st.st_mode)) {
			(void) fprintf(stderr, gettext("could not verify fs "
			    "%s: %s is not a regular file\n"),
			    fstab.zone_fs_dir, cmdbuf);
			return_code = Z_ERR;
			goto next_fs;
		}
		/*
		 * Verify /usr/lib/fs/<fstype>/fsck exists iff zone_fs_raw is
		 * set.
		 */
		if (snprintf(cmdbuf, sizeof (cmdbuf), "/usr/lib/fs/%s/fsck",
		    fstab.zone_fs_type) > sizeof (cmdbuf)) {
			(void) fprintf(stderr, gettext("cannot verify fs %s: "
			    "type %s is too long.\n"), fstab.zone_fs_dir,
			    fstab.zone_fs_type);
			return_code = Z_ERR;
			goto next_fs;
		}
		if (fstab.zone_fs_raw[0] == '\0' && stat(cmdbuf, &st) == 0) {
			(void) fprintf(stderr, gettext("could not verify fs "
			    "%s: must specify 'raw' device for %s "
			    "file-systems\n"),
			    fstab.zone_fs_dir, fstab.zone_fs_type);
			return_code = Z_ERR;
			goto next_fs;
		}
		if (fstab.zone_fs_raw[0] != '\0' &&
		    (stat(cmdbuf, &st) != 0 || !S_ISREG(st.st_mode))) {
			(void) fprintf(stderr, gettext("cannot verify fs %s: "
			    "'raw' device specified but "
			    "no fsck executable exists for %s\n"),
			    fstab.zone_fs_dir, fstab.zone_fs_type);
			return_code = Z_ERR;
			goto next_fs;
		}

		/* Verify fs_special. */
		if ((return_code = verify_fs_special(&fstab)) != Z_OK)
			goto next_fs;

		/* Verify fs_raw. */
		if (fstab.zone_fs_raw[0] != '\0' &&
		    stat(fstab.zone_fs_raw, &st) != 0) {
			/*
			 * TRANSLATION_NOTE
			 * fs is a literal that should not be translated.
			 */
			(void) fprintf(stderr, gettext("could not verify fs "
			    "%s: could not access %s: %s\n"), fstab.zone_fs_dir,
			    fstab.zone_fs_raw, strerror(errno));
			return_code = Z_ERR;
			goto next_fs;
		}
next_fs:
		zonecfg_free_fs_option_list(fstab.zone_fs_options);
	}
	(void) zonecfg_endfsent(handle);

	return (return_code);
}

const char *current_dataset;

/*
 * Custom error handler for errors incurred as part of the checks below.  We
 * want to trim off the leading 'cannot open ...' to create a better error
 * message.  The only other way this can fail is if we fail to set the 'zoned'
 * property.  In this case we just pass the error on verbatim.
 */
static void
zfs_error_handler(const char *fmt, va_list ap)
{
	char buf[1024];

	(void) vsnprintf(buf, sizeof (buf), fmt, ap);

	if (strncmp(gettext("cannot open "), buf,
	    strlen(gettext("cannot open "))) == 0)
		/*
		 * TRANSLATION_NOTE
		 * zfs and dataset are literals that should not be translated.
		 */
		(void) fprintf(stderr, gettext("could not verify zfs "
		    "dataset %s%s\n"), current_dataset, strchr(buf, ':'));
	else
		(void) fprintf(stderr, gettext("could not verify zfs dataset "
		    "%s: %s\n"), current_dataset, buf);
}

/* ARGSUSED */
static int
check_zvol(zfs_handle_t *zhp, void *unused)
{
	int ret;

	if (zfs_get_type(zhp) == ZFS_TYPE_VOLUME) {
		/*
		 * TRANSLATION_NOTE
		 * zfs and dataset are literals that should not be translated.
		 */
		(void) fprintf(stderr, gettext("cannot verify zfs dataset %s: "
		    "volumes cannot be specified as a zone dataset resource\n"),
		    zfs_get_name(zhp));
		ret = -1;
	} else {
		ret = zfs_iter_children(zhp, check_zvol, NULL);
	}

	zfs_close(zhp);

	return (ret);
}

/*
 * Validate that the given dataset exists on the system, and that neither it nor
 * its children are zvols.
 *
 * Note that we don't do anything with the 'zoned' property here.  All
 * management is done in zoneadmd when the zone is actually rebooted.  This
 * allows us to automatically set the zoned property even when a zone is
 * rebooted by the administrator.
 */
static int
verify_datasets(zone_dochandle_t handle)
{
	int return_code = Z_OK;
	struct zone_dstab dstab;
	zfs_handle_t *zhp;
	char propbuf[ZFS_MAXPROPLEN];
	char source[ZFS_MAXNAMELEN];
	zfs_source_t srctype;

	if (zonecfg_setdsent(handle) != Z_OK) {
		/*
		 * TRANSLATION_NOTE
		 * zfs and dataset are literals that should not be translated.
		 */
		(void) fprintf(stderr, gettext("could not verify zfs datasets: "
		    "unable to enumerate datasets\n"));
		return (Z_ERR);
	}

	zfs_set_error_handler(zfs_error_handler);

	while (zonecfg_getdsent(handle, &dstab) == Z_OK) {

		current_dataset = dstab.zone_dataset_name;

		if ((zhp = zfs_open(dstab.zone_dataset_name,
		    ZFS_TYPE_FILESYSTEM | ZFS_TYPE_VOLUME)) == NULL) {
			return_code = Z_ERR;
			continue;
		}

		if (zfs_prop_get(zhp, ZFS_PROP_MOUNTPOINT, propbuf,
		    sizeof (propbuf), &srctype, source,
		    sizeof (source), 0) == 0 &&
		    (srctype == ZFS_SRC_INHERITED)) {
			(void) fprintf(stderr, gettext("could not verify zfs "
			    "dataset %s: mountpoint cannot be inherited\n"),
			    dstab.zone_dataset_name);
			return_code = Z_ERR;
			zfs_close(zhp);
			continue;
		}

		if (zfs_get_type(zhp) == ZFS_TYPE_VOLUME) {
			(void) fprintf(stderr, gettext("cannot verify zfs "
			    "dataset %s: volumes cannot be specified as a "
			    "zone dataset resource\n"),
			    dstab.zone_dataset_name);
			return_code = Z_ERR;
		}

		if (zfs_iter_children(zhp, check_zvol, NULL) != 0)
			return_code = Z_ERR;

		zfs_close(zhp);
	}
	(void) zonecfg_enddsent(handle);

	return (return_code);
}

static int
verify_details(int cmd_num)
{
	zone_dochandle_t handle;
	struct zone_nwiftab nwiftab;
	char zonepath[MAXPATHLEN], checkpath[MAXPATHLEN];
	int return_code = Z_OK;
	int err;
	boolean_t in_alt_root;

	if ((handle = zonecfg_init_handle()) == NULL) {
		zperror(cmd_to_str(cmd_num), B_TRUE);
		return (Z_ERR);
	}
	if ((err = zonecfg_get_handle(target_zone, handle)) != Z_OK) {
		errno = err;
		zperror(cmd_to_str(cmd_num), B_TRUE);
		zonecfg_fini_handle(handle);
		return (Z_ERR);
	}
	if ((err = zonecfg_get_zonepath(handle, zonepath, sizeof (zonepath))) !=
	    Z_OK) {
		errno = err;
		zperror(cmd_to_str(cmd_num), B_TRUE);
		zonecfg_fini_handle(handle);
		return (Z_ERR);
	}
	/*
	 * zonecfg_get_zonepath() gets its data from the XML repository.
	 * Verify this against the index file, which is checked first by
	 * zone_get_zonepath().  If they don't match, bail out.
	 */
	if ((err = zone_get_zonepath(target_zone, checkpath,
	    sizeof (checkpath))) != Z_OK) {
		errno = err;
		zperror2(target_zone, gettext("could not get zone path"));
		return (Z_ERR);
	}
	if (strcmp(zonepath, checkpath) != 0) {
		/*
		 * TRANSLATION_NOTE
		 * XML and zonepath are literals that should not be translated.
		 */
		(void) fprintf(stderr, gettext("The XML repository has "
		    "zonepath '%s',\nbut the index file has zonepath '%s'.\n"
		    "These must match, so fix the incorrect entry.\n"),
		    zonepath, checkpath);
		return (Z_ERR);
	}
	if (validate_zonepath(zonepath, cmd_num) != Z_OK) {
		(void) fprintf(stderr, gettext("could not verify zonepath %s "
		    "because of the above errors.\n"), zonepath);
		return_code = Z_ERR;
	}

	in_alt_root = zonecfg_in_alt_root();
	if (in_alt_root)
		goto no_net;

	if ((err = zonecfg_setnwifent(handle)) != Z_OK) {
		errno = err;
		zperror(cmd_to_str(cmd_num), B_TRUE);
		zonecfg_fini_handle(handle);
		return (Z_ERR);
	}
	while (zonecfg_getnwifent(handle, &nwiftab) == Z_OK) {
		struct lifreq lifr;
		sa_family_t af;
		int so, res;

		/* skip any loopback interfaces */
		if (strcmp(nwiftab.zone_nwif_physical, "lo0") == 0)
			continue;
		if ((res = zonecfg_valid_net_address(nwiftab.zone_nwif_address,
		    &lifr)) != Z_OK) {
			(void) fprintf(stderr, gettext("could not verify %s "
			    "%s=%s %s=%s: %s\n"), "net", "address",
			    nwiftab.zone_nwif_address, "physical",
			    nwiftab.zone_nwif_physical, zonecfg_strerror(res));
			return_code = Z_ERR;
			continue;
		}
		af = lifr.lifr_addr.ss_family;
		(void) memset(&lifr, 0, sizeof (lifr));
		(void) strlcpy(lifr.lifr_name, nwiftab.zone_nwif_physical,
		    sizeof (lifr.lifr_name));
		lifr.lifr_addr.ss_family = af;
		if ((so = socket(af, SOCK_DGRAM, 0)) < 0) {
			(void) fprintf(stderr, gettext("could not verify %s "
			    "%s=%s %s=%s: could not get socket: %s\n"), "net",
			    "address", nwiftab.zone_nwif_address, "physical",
			    nwiftab.zone_nwif_physical, strerror(errno));
			return_code = Z_ERR;
			continue;
		}
		if (ioctl(so, SIOCGLIFFLAGS, (caddr_t)&lifr) < 0) {
			(void) fprintf(stderr,
			    gettext("could not verify %s %s=%s %s=%s: %s\n"),
			    "net", "address", nwiftab.zone_nwif_address,
			    "physical", nwiftab.zone_nwif_physical,
			    strerror(errno));
			return_code = Z_ERR;
		}
		(void) close(so);
	}
	(void) zonecfg_endnwifent(handle);
no_net:

	if (verify_filesystems(handle) != Z_OK)
		return_code = Z_ERR;
	if (verify_ipd(handle) != Z_OK)
		return_code = Z_ERR;
	if (!in_alt_root && verify_rctls(handle) != Z_OK)
		return_code = Z_ERR;
	if (!in_alt_root && verify_pool(handle) != Z_OK)
		return_code = Z_ERR;
	if (!in_alt_root && verify_datasets(handle) != Z_OK)
		return_code = Z_ERR;
	zonecfg_fini_handle(handle);
	if (return_code == Z_ERR)
		(void) fprintf(stderr,
		    gettext("%s: zone %s failed to verify\n"),
		    execname, target_zone);
	return (return_code);
}

static int
verify_func(int argc, char *argv[])
{
	int arg;

	optind = 0;
	if ((arg = getopt(argc, argv, "?")) != EOF) {
		switch (arg) {
		case '?':
			sub_usage(SHELP_VERIFY, CMD_VERIFY);
			return (optopt == '?' ? Z_OK : Z_USAGE);
		default:
			sub_usage(SHELP_VERIFY, CMD_VERIFY);
			return (Z_USAGE);
		}
	}
	if (argc > optind) {
		sub_usage(SHELP_VERIFY, CMD_VERIFY);
		return (Z_USAGE);
	}
	if (sanity_check(target_zone, CMD_VERIFY, B_FALSE, B_FALSE) != Z_OK)
		return (Z_ERR);
	return (verify_details(CMD_VERIFY));
}

#define	LUCREATEZONE	"/usr/lib/lu/lucreatezone"

static int
install_func(int argc, char *argv[])
{
	/* 9: "exec " and " -z " */
	char cmdbuf[sizeof (LUCREATEZONE) + ZONENAME_MAX + 9];
	int lockfd;
	int err, arg;
	char zonepath[MAXPATHLEN];
	int status;

	if (zonecfg_in_alt_root()) {
		zerror(gettext("cannot install zone in alternate root"));
		return (Z_ERR);
	}

	optind = 0;
	if ((arg = getopt(argc, argv, "?")) != EOF) {
		switch (arg) {
		case '?':
			sub_usage(SHELP_INSTALL, CMD_INSTALL);
			return (optopt == '?' ? Z_OK : Z_USAGE);
		default:
			sub_usage(SHELP_INSTALL, CMD_INSTALL);
			return (Z_USAGE);
		}
	}
	if (argc > optind) {
		sub_usage(SHELP_INSTALL, CMD_INSTALL);
		return (Z_USAGE);
	}
	if (sanity_check(target_zone, CMD_INSTALL, B_FALSE, B_TRUE) != Z_OK)
		return (Z_ERR);
	if (verify_details(CMD_INSTALL) != Z_OK)
		return (Z_ERR);

	if (grab_lock_file(target_zone, &lockfd) != Z_OK) {
		zerror(gettext("another %s may have an operation in progress."),
		    "zoneadm");
		return (Z_ERR);
	}
	err = zone_set_state(target_zone, ZONE_STATE_INCOMPLETE);
	if (err != Z_OK) {
		errno = err;
		zperror2(target_zone, gettext("could not set state"));
		goto done;
	}

	/*
	 * According to the Application Packaging Developer's Guide, a
	 * "checkinstall" script when included in a package is executed as
	 * the user "install", if such a user exists, or by the user
	 * "nobody".  In order to support this dubious behavior, the path
	 * to the zone being constructed is opened up during the life of
	 * the command laying down the zone's root file system.  Once this
	 * has completed, regardless of whether it was successful, the
	 * path to the zone is again restricted.
	 */
	if ((err = zone_get_zonepath(target_zone, zonepath,
	    sizeof (zonepath))) != Z_OK) {
		errno = err;
		zperror2(target_zone, gettext("could not get zone path"));
		goto done;
	}
	if (chmod(zonepath, DEFAULT_DIR_MODE) != 0) {
		zperror(zonepath, B_FALSE);
		err = Z_ERR;
		goto done;
	}

	/*
	 * "exec" the command so that the returned status is that of
	 * LUCREATEZONE and not the shell.
	 */
	(void) snprintf(cmdbuf, sizeof (cmdbuf), "exec " LUCREATEZONE " -z %s",
	    target_zone);
	status = do_subproc(cmdbuf);
	if (chmod(zonepath, S_IRWXU) != 0) {
		zperror(zonepath, B_FALSE);
		err = Z_ERR;
		goto done;
	}
	if ((err = subproc_status(LUCREATEZONE, status)) != Z_OK)
		goto done;

	if ((err = zone_set_state(target_zone, ZONE_STATE_INSTALLED)) != Z_OK) {
		errno = err;
		zperror2(target_zone, gettext("could not set state"));
		goto done;
	}

done:
	release_lock_file(lockfd);
	return ((err == Z_OK) ? Z_OK : Z_ERR);
}

/*
 * Check that the inherited pkg dirs are the same for the clone and its source.
 * The easiest way to do that is check that the list of ipds is the same
 * by matching each one against the other.  This algorithm should be fine since
 * the list of ipds should not be that long.
 */
static int
valid_ipd_clone(zone_dochandle_t s_handle, char *source_zone,
	zone_dochandle_t t_handle, char *target_zone)
{
	int err;
	int res = Z_OK;
	int s_cnt = 0;
	int t_cnt = 0;
	struct zone_fstab s_fstab;
	struct zone_fstab t_fstab;

	/*
	 * First check the source of the clone against the target.
	 */
	if ((err = zonecfg_setipdent(s_handle)) != Z_OK) {
		errno = err;
		zperror2(source_zone, gettext("could not enumerate "
		    "inherit-pkg-dirs"));
		return (Z_ERR);
	}

	while (zonecfg_getipdent(s_handle, &s_fstab) == Z_OK) {
		boolean_t match = B_FALSE;

		s_cnt++;

		if ((err = zonecfg_setipdent(t_handle)) != Z_OK) {
			errno = err;
			zperror2(target_zone, gettext("could not enumerate "
			    "inherit-pkg-dirs"));
			(void) zonecfg_endipdent(s_handle);
			return (Z_ERR);
		}

		while (zonecfg_getipdent(t_handle, &t_fstab) == Z_OK) {
			if (strcmp(s_fstab.zone_fs_dir, t_fstab.zone_fs_dir)
			    == 0) {
				match = B_TRUE;
				break;
			}
		}
		(void) zonecfg_endipdent(t_handle);

		if (!match) {
			(void) fprintf(stderr, gettext("inherit-pkg-dir "
			    "'%s' is not configured in zone %s.\n"),
			    s_fstab.zone_fs_dir, target_zone);
			res = Z_ERR;
		}
	}

	(void) zonecfg_endipdent(s_handle);

	/* skip the next check if we already have errors */
	if (res == Z_ERR)
		return (res);

	/*
	 * Now check the number of ipds in the target so we can verify
	 * that the source is not a subset of the target.
	 */
	if ((err = zonecfg_setipdent(t_handle)) != Z_OK) {
		errno = err;
		zperror2(target_zone, gettext("could not enumerate "
		    "inherit-pkg-dirs"));
		return (Z_ERR);
	}

	while (zonecfg_getipdent(t_handle, &t_fstab) == Z_OK)
		t_cnt++;

	(void) zonecfg_endipdent(t_handle);

	if (t_cnt != s_cnt) {
		(void) fprintf(stderr, gettext("Zone %s is configured "
		    "with inherit-pkg-dirs that are not configured in zone "
		    "%s.\n"), target_zone, source_zone);
		res = Z_ERR;
	}

	return (res);
}

static void
warn_dev_match(zone_dochandle_t s_handle, char *source_zone,
	zone_dochandle_t t_handle, char *target_zone)
{
	int err;
	struct zone_devtab s_devtab;
	struct zone_devtab t_devtab;

	if ((err = zonecfg_setdevent(t_handle)) != Z_OK) {
		errno = err;
		zperror2(target_zone, gettext("could not enumerate devices"));
		return;
	}

	while (zonecfg_getdevent(t_handle, &t_devtab) == Z_OK) {
		if ((err = zonecfg_setdevent(s_handle)) != Z_OK) {
			errno = err;
			zperror2(source_zone,
			    gettext("could not enumerate devices"));
			(void) zonecfg_enddevent(t_handle);
			return;
		}

		while (zonecfg_getdevent(s_handle, &s_devtab) == Z_OK) {
			/*
			 * Use fnmatch to catch the case where wildcards
			 * were used in one zone and the other has an
			 * explicit entry (e.g. /dev/dsk/c0t0d0s6 vs.
			 * /dev/\*dsk/c0t0d0s6).
			 */
			if (fnmatch(t_devtab.zone_dev_match,
			    s_devtab.zone_dev_match, FNM_PATHNAME) == 0 ||
			    fnmatch(s_devtab.zone_dev_match,
			    t_devtab.zone_dev_match, FNM_PATHNAME) == 0) {
				(void) fprintf(stderr,
				    gettext("WARNING: device '%s' "
				    "is configured in both zones.\n"),
				    t_devtab.zone_dev_match);
				break;
			}
		}
		(void) zonecfg_enddevent(s_handle);
	}

	(void) zonecfg_enddevent(t_handle);
}

/*
 * Check if the specified mount option (opt) is contained within the
 * options string.
 */
static boolean_t
opt_match(char *opt, char *options)
{
	char *p;
	char *lastp;

	if ((p = strtok_r(options, ",", &lastp)) != NULL) {
		if (strcmp(p, opt) == 0)
			return (B_TRUE);
		while ((p = strtok_r(NULL, ",", &lastp)) != NULL) {
			if (strcmp(p, opt) == 0)
				return (B_TRUE);
		}
	}

	return (B_FALSE);
}

#define	RW_LOFS	"WARNING: read-write lofs file-system on '%s' is configured " \
	"in both zones.\n"

static void
print_fs_warnings(struct zone_fstab *s_fstab, struct zone_fstab *t_fstab)
{
	/*
	 * It is ok to have shared lofs mounted fs but we want to warn if
	 * either is rw since this will effect the other zone.
	 */
	if (strcmp(t_fstab->zone_fs_type, "lofs") == 0) {
		zone_fsopt_t *optp;

		/* The default is rw so no options means rw */
		if (t_fstab->zone_fs_options == NULL ||
		    s_fstab->zone_fs_options == NULL) {
			(void) fprintf(stderr, gettext(RW_LOFS),
			    t_fstab->zone_fs_special);
			return;
		}

		for (optp = s_fstab->zone_fs_options; optp != NULL;
		    optp = optp->zone_fsopt_next) {
			if (opt_match("rw", optp->zone_fsopt_opt)) {
				(void) fprintf(stderr, gettext(RW_LOFS),
				    s_fstab->zone_fs_special);
				return;
			}
		}

		for (optp = t_fstab->zone_fs_options; optp != NULL;
		    optp = optp->zone_fsopt_next) {
			if (opt_match("rw", optp->zone_fsopt_opt)) {
				(void) fprintf(stderr, gettext(RW_LOFS),
				    t_fstab->zone_fs_special);
				return;
			}
		}

		return;
	}

	/*
	 * TRANSLATION_NOTE
	 * The first variable is the file-system type and the second is
	 * the file-system special device.  For example,
	 * WARNING: ufs file-system on '/dev/dsk/c0t0d0s0' ...
	 */
	(void) fprintf(stderr, gettext("WARNING: %s file-system on '%s' "
	    "is configured in both zones.\n"), t_fstab->zone_fs_type,
	    t_fstab->zone_fs_special);
}

static void
warn_fs_match(zone_dochandle_t s_handle, char *source_zone,
	zone_dochandle_t t_handle, char *target_zone)
{
	int err;
	struct zone_fstab s_fstab;
	struct zone_fstab t_fstab;

	if ((err = zonecfg_setfsent(t_handle)) != Z_OK) {
		errno = err;
		zperror2(target_zone,
		    gettext("could not enumerate file-systems"));
		return;
	}

	while (zonecfg_getfsent(t_handle, &t_fstab) == Z_OK) {
		if ((err = zonecfg_setfsent(s_handle)) != Z_OK) {
			errno = err;
			zperror2(source_zone,
			    gettext("could not enumerate file-systems"));
			(void) zonecfg_endfsent(t_handle);
			return;
		}

		while (zonecfg_getfsent(s_handle, &s_fstab) == Z_OK) {
			if (strcmp(t_fstab.zone_fs_special,
			    s_fstab.zone_fs_special) == 0) {
				print_fs_warnings(&s_fstab, &t_fstab);
				break;
			}
		}
		(void) zonecfg_endfsent(s_handle);
	}

	(void) zonecfg_endfsent(t_handle);
}

/*
 * We don't catch the case where you used the same IP address but
 * it is not an exact string match.  For example, 192.9.0.128 vs. 192.09.0.128.
 * However, we're not going to worry about that but we will check for
 * a possible netmask on one of the addresses (e.g. 10.0.0.1 and 10.0.0.1/24)
 * and handle that case as a match.
 */
static void
warn_ip_match(zone_dochandle_t s_handle, char *source_zone,
	zone_dochandle_t t_handle, char *target_zone)
{
	int err;
	struct zone_nwiftab s_nwiftab;
	struct zone_nwiftab t_nwiftab;

	if ((err = zonecfg_setnwifent(t_handle)) != Z_OK) {
		errno = err;
		zperror2(target_zone,
		    gettext("could not enumerate network interfaces"));
		return;
	}

	while (zonecfg_getnwifent(t_handle, &t_nwiftab) == Z_OK) {
		char *p;

		/* remove an (optional) netmask from the address */
		if ((p = strchr(t_nwiftab.zone_nwif_address, '/')) != NULL)
			*p = '\0';

		if ((err = zonecfg_setnwifent(s_handle)) != Z_OK) {
			errno = err;
			zperror2(source_zone,
			    gettext("could not enumerate network interfaces"));
			(void) zonecfg_endnwifent(t_handle);
			return;
		}

		while (zonecfg_getnwifent(s_handle, &s_nwiftab) == Z_OK) {
			/* remove an (optional) netmask from the address */
			if ((p = strchr(s_nwiftab.zone_nwif_address, '/'))
			    != NULL)
				*p = '\0';

			if (strcmp(t_nwiftab.zone_nwif_address,
			    s_nwiftab.zone_nwif_address) == 0) {
				(void) fprintf(stderr,
				    gettext("WARNING: network address '%s' "
				    "is configured in both zones.\n"),
				    t_nwiftab.zone_nwif_address);
				break;
			}
		}
		(void) zonecfg_endnwifent(s_handle);
	}

	(void) zonecfg_endnwifent(t_handle);
}

static void
warn_dataset_match(zone_dochandle_t s_handle, char *source_zone,
	zone_dochandle_t t_handle, char *target_zone)
{
	int err;
	struct zone_dstab s_dstab;
	struct zone_dstab t_dstab;

	if ((err = zonecfg_setdsent(t_handle)) != Z_OK) {
		errno = err;
		zperror2(target_zone, gettext("could not enumerate datasets"));
		return;
	}

	while (zonecfg_getdsent(t_handle, &t_dstab) == Z_OK) {
		if ((err = zonecfg_setdsent(s_handle)) != Z_OK) {
			errno = err;
			zperror2(source_zone,
			    gettext("could not enumerate datasets"));
			(void) zonecfg_enddsent(t_handle);
			return;
		}

		while (zonecfg_getdsent(s_handle, &s_dstab) == Z_OK) {
			if (strcmp(t_dstab.zone_dataset_name,
			    s_dstab.zone_dataset_name) == 0) {
				(void) fprintf(stderr,
				    gettext("WARNING: dataset '%s' "
				    "is configured in both zones.\n"),
				    t_dstab.zone_dataset_name);
				break;
			}
		}
		(void) zonecfg_enddsent(s_handle);
	}

	(void) zonecfg_enddsent(t_handle);
}

static int
validate_clone(char *source_zone, char *target_zone)
{
	int err = Z_OK;
	zone_dochandle_t s_handle;
	zone_dochandle_t t_handle;

	if ((t_handle = zonecfg_init_handle()) == NULL) {
		zperror(cmd_to_str(CMD_CLONE), B_TRUE);
		return (Z_ERR);
	}
	if ((err = zonecfg_get_handle(target_zone, t_handle)) != Z_OK) {
		errno = err;
		zperror(cmd_to_str(CMD_CLONE), B_TRUE);
		zonecfg_fini_handle(t_handle);
		return (Z_ERR);
	}

	if ((s_handle = zonecfg_init_handle()) == NULL) {
		zperror(cmd_to_str(CMD_CLONE), B_TRUE);
		zonecfg_fini_handle(t_handle);
		return (Z_ERR);
	}
	if ((err = zonecfg_get_handle(source_zone, s_handle)) != Z_OK) {
		errno = err;
		zperror(cmd_to_str(CMD_CLONE), B_TRUE);
		goto done;
	}

	/* verify new zone has same inherit-pkg-dirs */
	err = valid_ipd_clone(s_handle, source_zone, t_handle, target_zone);

	/* warn about imported fs's which are the same */
	warn_fs_match(s_handle, source_zone, t_handle, target_zone);

	/* warn about imported IP addresses which are the same */
	warn_ip_match(s_handle, source_zone, t_handle, target_zone);

	/* warn about imported devices which are the same */
	warn_dev_match(s_handle, source_zone, t_handle, target_zone);

	/* warn about imported datasets which are the same */
	warn_dataset_match(s_handle, source_zone, t_handle, target_zone);

done:
	zonecfg_fini_handle(t_handle);
	zonecfg_fini_handle(s_handle);

	return ((err == Z_OK) ? Z_OK : Z_ERR);
}

static int
copy_zone(char *src, char *dst)
{
	boolean_t out_null = B_FALSE;
	int status;
	int err;
	char *outfile;
	char cmdbuf[MAXPATHLEN * 2 + 128];

	if ((outfile = tempnam("/var/log", "zone")) == NULL) {
		outfile = "/dev/null";
		out_null = B_TRUE;
	}

	(void) snprintf(cmdbuf, sizeof (cmdbuf),
	    "cd %s && /usr/bin/find . -depth -print | "
	    "/usr/bin/cpio -pdmuP@ %s > %s 2>&1",
	    src, dst, outfile);

	status = do_subproc(cmdbuf);

	if ((err = subproc_status("copy", status)) != Z_OK) {
		if (!out_null)
			(void) fprintf(stderr, gettext("\nThe copy failed.\n"
			    "More information can be found in %s\n"), outfile);
		return (err);
	}

	if (!out_null)
		(void) unlink(outfile);

	return (Z_OK);
}

/*
 * Wait until the target_zone has booted to single-user.  Return Z_OK once
 * the zone has booted to that level or return Z_BAD_ZONE_STATE if the zone
 * has not booted to single-user after the timeout.
 */
static int
zone_wait_single_user()
{
	char cmdbuf[ZONENAME_MAX + 256];
	int retry;

	(void) snprintf(cmdbuf, sizeof (cmdbuf),
	    "test \"`/usr/sbin/zlogin -S %s /usr/bin/svcprop -p "
	    "restarter/state svc:/milestone/single-user:default 2>/dev/null`\" "
	    "= \"online\"",
	    target_zone);

	for (retry = 0; retry < SINGLE_USER_RETRY; retry++) {
		int status;

		status = do_subproc(cmdbuf);
		if (WIFEXITED(status)) {
			if (WEXITSTATUS(status) == 0)
				return (Z_OK);

			(void) sleep(2);
		} else {
			return (Z_BAD_ZONE_STATE);
		}
	}

	return (Z_BAD_ZONE_STATE);
}


/* ARGSUSED */
int
zfm_print(const char *p, void *r) {
	zerror("  %s\n", p);
	return (0);
}

static int
clone_func(int argc, char *argv[])
{
	char cmdbuf[MAXPATHLEN];
	char *source_zone = NULL;
	int lockfd;
	int err, arg;
	char zonepath[MAXPATHLEN];
	char source_zonepath[MAXPATHLEN];
	int status;
	zone_state_t state;
	zone_entry_t *zent;
	char *method = "copy";
	char *boot_args[] = { "-s", NULL };
	char *halt_args[] = { NULL };
	struct stat unconfig_buf;
	boolean_t revert;

	if (zonecfg_in_alt_root()) {
		zerror(gettext("cannot clone zone in alternate root"));
		return (Z_ERR);
	}

	optind = 0;
	if ((arg = getopt(argc, argv, "?m:")) != EOF) {
		switch (arg) {
		case '?':
			sub_usage(SHELP_CLONE, CMD_CLONE);
			return (optopt == '?' ? Z_OK : Z_USAGE);
		case 'm':
			method = optarg;
			break;
		default:
			sub_usage(SHELP_CLONE, CMD_CLONE);
			return (Z_USAGE);
		}
	}
	if (argc != (optind + 1) || strcmp(method, "copy") != 0) {
		sub_usage(SHELP_CLONE, CMD_CLONE);
		return (Z_USAGE);
	}
	source_zone = argv[optind];
	if (sanity_check(target_zone, CMD_CLONE, B_FALSE, B_TRUE) != Z_OK)
		return (Z_ERR);
	if (verify_details(CMD_CLONE) != Z_OK)
		return (Z_ERR);

	/*
	 * We also need to do some extra validation on the source zone.
	 */

	if (strcmp(source_zone, GLOBAL_ZONENAME) == 0) {
		zerror(gettext("%s operation is invalid for the global zone."),
		    cmd_to_str(CMD_CLONE));
		return (Z_ERR);
	}

	if (strncmp(source_zone, "SUNW", 4) == 0) {
		zerror(gettext("%s operation is invalid for zones starting "
		    "with SUNW."), cmd_to_str(CMD_CLONE));
		return (Z_ERR);
	}

	zent = lookup_running_zone(source_zone);
	if (zent != NULL) {
		/* check whether the zone is ready or running */
		if ((err = zone_get_state(zent->zname, &zent->zstate_num))
		    != Z_OK) {
			errno = err;
			zperror2(zent->zname, gettext("could not get state"));
			/* can't tell, so hedge */
			zent->zstate_str = "ready/running";
		} else {
			zent->zstate_str = zone_state_str(zent->zstate_num);
		}
		zerror(gettext("%s operation is invalid for %s zones."),
		    cmd_to_str(CMD_CLONE), zent->zstate_str);
		return (Z_ERR);
	}

	if ((err = zone_get_state(source_zone, &state)) != Z_OK) {
		errno = err;
		zperror2(source_zone, gettext("could not get state"));
		return (Z_ERR);
	}
	if (state != ZONE_STATE_INSTALLED) {
		(void) fprintf(stderr,
		    gettext("%s: zone %s is %s; %s is required.\n"),
		    execname, source_zone, zone_state_str(state),
		    zone_state_str(ZONE_STATE_INSTALLED));
		return (Z_ERR);
	}

	/*
	 * The source zone checks out ok, continue with the clone.
	 */

	if (validate_clone(source_zone, target_zone) != Z_OK)
		return (Z_ERR);

	if (grab_lock_file(target_zone, &lockfd) != Z_OK) {
		zerror(gettext("another %s may have an operation in progress."),
		    "zoneadm");
		return (Z_ERR);
	}

	if ((err = zone_get_zonepath(source_zone, source_zonepath,
	    sizeof (source_zonepath))) != Z_OK) {
		errno = err;
		zperror2(source_zone, gettext("could not get zone path"));
		goto done;
	}

	if ((err = zone_get_zonepath(target_zone, zonepath, sizeof (zonepath)))
	    != Z_OK) {
		errno = err;
		zperror2(target_zone, gettext("could not get zone path"));
		goto done;
	}

	/* Don't clone the zone if anything is still mounted there */
	if (zonecfg_find_mounts(source_zonepath, NULL, NULL)) {
		zerror(gettext("These file-systems are mounted on "
		    "subdirectories of %s.\n"), source_zonepath);
		(void) zonecfg_find_mounts(source_zonepath, zfm_print, NULL);
		err = Z_ERR;
		goto done;
	}

	if ((err = zone_set_state(target_zone, ZONE_STATE_INCOMPLETE))
	    != Z_OK) {
		errno = err;
		zperror2(target_zone, gettext("could not set state"));
		goto done;
	}

	(void) printf(gettext("Cloning zonepath %s..."), source_zonepath);
	(void) fflush(stdout);

	if ((err = copy_zone(source_zonepath, zonepath)) != Z_OK)
		goto done;

	/*
	 * We have to set the state of the zone to installed so that we
	 * can boot it and sys-unconfig it from within the zone.  However,
	 * if something fails during the boot/sys-unconfig, we want to set
	 * the state back to incomplete.  We use the revert flag to keep
	 * track of this.
	 */
	revert = B_TRUE;

	if ((err = zone_set_state(target_zone, ZONE_STATE_INSTALLED)) != Z_OK) {
		errno = err;
		zperror2(target_zone, gettext("\ncould not set state"));
		goto done;
	}

	/*
	 * Check if the zone is already sys-unconfiged.  This saves us
	 * the work of booting the zone so we can unconfigure it.
	 */
	(void) snprintf(cmdbuf, sizeof (cmdbuf), "%s/root/etc/.UNCONFIGURED",
	    zonepath);
	if (stat(cmdbuf, &unconfig_buf) == -1) {
		if ((err = boot_func(1, boot_args)) != Z_OK) {
			errno = err;
			zperror2(target_zone, gettext("\nCould not boot zone "
			    "for sys-unconfig\n"));
			goto done;
		}

		if ((err = zone_wait_single_user()) != Z_OK) {
			errno = err;
			zperror2(target_zone, gettext("\nCould not boot zone "
			    "for sys-unconfig\n"));
			(void) halt_func(0, halt_args);
			goto done;
		}

		(void) snprintf(cmdbuf, sizeof (cmdbuf),
		    "echo y | /usr/sbin/zlogin -S %s /usr/sbin/sys-unconfig",
		    target_zone);

		status = do_subproc(cmdbuf);
		if ((err = subproc_status("sys-unconfig", status)) != Z_OK) {
			errno = err;
			zperror2(target_zone,
			    gettext("\nsys-unconfig failed\n"));
			/*
			 * The sys-unconfig halts the zone but if it failed,
			 * for some reason, we'll try to halt it now.
			 */
			(void) halt_func(0, halt_args);
			goto done;
		}
	}

	revert = B_FALSE;

done:
	(void) printf("\n");

	if (revert)
		(void) zone_set_state(target_zone, ZONE_STATE_INCOMPLETE);

	release_lock_file(lockfd);
	return ((err == Z_OK) ? Z_OK : Z_ERR);
}

#define	RMCOMMAND	"/usr/bin/rm -rf"

static int
move_func(int argc, char *argv[])
{
	/* 6: "exec " and " " */
	char cmdbuf[sizeof (RMCOMMAND) + MAXPATHLEN + 6];
	char *new_zonepath = NULL;
	int lockfd;
	int err, arg;
	char zonepath[MAXPATHLEN];
	zone_dochandle_t handle;
	boolean_t fast;
	boolean_t revert;
	struct stat zonepath_buf;
	struct stat new_zonepath_buf;

	if (zonecfg_in_alt_root()) {
		zerror(gettext("cannot move zone in alternate root"));
		return (Z_ERR);
	}

	optind = 0;
	if ((arg = getopt(argc, argv, "?")) != EOF) {
		switch (arg) {
		case '?':
			sub_usage(SHELP_MOVE, CMD_MOVE);
			return (optopt == '?' ? Z_OK : Z_USAGE);
		default:
			sub_usage(SHELP_MOVE, CMD_MOVE);
			return (Z_USAGE);
		}
	}
	if (argc != (optind + 1)) {
		sub_usage(SHELP_MOVE, CMD_MOVE);
		return (Z_USAGE);
	}
	new_zonepath = argv[optind];
	if (sanity_check(target_zone, CMD_MOVE, B_FALSE, B_TRUE) != Z_OK)
		return (Z_ERR);
	if (verify_details(CMD_MOVE) != Z_OK)
		return (Z_ERR);

	/*
	 * Check out the new zonepath.  This has the side effect of creating
	 * a directory for the new zonepath.  We depend on this later when we
	 * stat to see if we are doing a cross file-system move or not.
	 */
	if (validate_zonepath(new_zonepath, CMD_MOVE) != Z_OK)
		return (Z_ERR);

	if ((err = zone_get_zonepath(target_zone, zonepath, sizeof (zonepath)))
	    != Z_OK) {
		errno = err;
		zperror2(target_zone, gettext("could not get zone path"));
		return (Z_ERR);
	}

	if (stat(zonepath, &zonepath_buf) == -1) {
		zperror(gettext("could not stat zone path"), B_FALSE);
		return (Z_ERR);
	}

	if (stat(new_zonepath, &new_zonepath_buf) == -1) {
		zperror(gettext("could not stat new zone path"), B_FALSE);
		return (Z_ERR);
	}

	/* Don't move the zone if anything is still mounted there */
	if (zonecfg_find_mounts(zonepath, NULL, NULL)) {
		zerror(gettext("These file-systems are mounted on "
		    "subdirectories of %s.\n"), zonepath);
		(void) zonecfg_find_mounts(zonepath, zfm_print, NULL);
		return (Z_ERR);
	}

	/*
	 * Check if we are moving in the same filesystem and can do a fast
	 * move or if we are crossing filesystems and have to copy the data.
	 */
	fast = (zonepath_buf.st_dev == new_zonepath_buf.st_dev);

	if ((handle = zonecfg_init_handle()) == NULL) {
		zperror(cmd_to_str(CMD_MOVE), B_TRUE);
		return (Z_ERR);
	}

	if ((err = zonecfg_get_handle(target_zone, handle)) != Z_OK) {
		errno = err;
		zperror(cmd_to_str(CMD_MOVE), B_TRUE);
		zonecfg_fini_handle(handle);
		return (Z_ERR);
	}

	if (grab_lock_file(target_zone, &lockfd) != Z_OK) {
		zerror(gettext("another %s may have an operation in progress."),
		    "zoneadm");
		zonecfg_fini_handle(handle);
		return (Z_ERR);
	}

	/*
	 * We're making some file-system changes now so we have to clean up
	 * the file-system before we are done.  This will either clean up the
	 * new zonepath if the zonecfg update failed or it will clean up the
	 * old zonepath if everything is ok.
	 */
	revert = B_TRUE;

	if (fast) {
		/* same filesystem, use rename for a quick move */

		/*
		 * Remove the new_zonepath directory that got created above
		 * during the validation.  It gets in the way of the rename.
		 */
		if (rmdir(new_zonepath) != 0) {
			zperror(gettext("could not rmdir new zone path"),
			    B_FALSE);
			zonecfg_fini_handle(handle);
			release_lock_file(lockfd);
			return (Z_ERR);
		}

		if (rename(zonepath, new_zonepath) != 0) {
			/*
			 * If this fails we don't need to do all of the
			 * cleanup that happens for the rest of the code
			 * so just return from this error.
			 */
			zperror(gettext("could not move zone"), B_FALSE);
			zonecfg_fini_handle(handle);
			release_lock_file(lockfd);
			return (Z_ERR);
		}

	} else {
		(void) printf(gettext(
		    "Moving across file-systems; copying zonepath %s..."),
		    zonepath);
		(void) fflush(stdout);

		err = copy_zone(zonepath, new_zonepath);

		(void) printf("\n");
		if (err != Z_OK)
			goto done;
	}

	if ((err = zonecfg_set_zonepath(handle, new_zonepath)) != Z_OK) {
		errno = err;
		zperror(gettext("could not set new zonepath"), B_TRUE);
		goto done;
	}

	if ((err = zonecfg_save(handle)) != Z_OK) {
		errno = err;
		zperror(gettext("zonecfg save failed"), B_TRUE);
		goto done;
	}

	revert = B_FALSE;

done:
	zonecfg_fini_handle(handle);
	release_lock_file(lockfd);

	/*
	 * Clean up the file-system based on how things went.  We either
	 * clean up the new zonepath if the operation failed for some reason
	 * or we clean up the old zonepath if everything is ok.
	 */
	if (revert) {
		/* The zonecfg update failed, cleanup the new zonepath. */
		if (fast) {
			if (rename(new_zonepath, zonepath) != 0) {
				zperror(gettext("could not restore zonepath"),
				    B_FALSE);
				/*
				 * err is already != Z_OK since we're reverting
				 */
			}
		} else {
			int status;

			(void) printf(gettext("Cleaning up zonepath %s..."),
			    new_zonepath);
			(void) fflush(stdout);

			/*
			 * "exec" the command so that the returned status is
			 * that of rm and not the shell.
			 */
			(void) snprintf(cmdbuf, sizeof (cmdbuf),
			    "exec " RMCOMMAND " %s", new_zonepath);

			status = do_subproc(cmdbuf);

			(void) printf("\n");

			if ((err = subproc_status("rm", status)) != Z_OK) {
				errno = err;
				zperror(gettext("could not remove new "
				    "zonepath"), B_TRUE);
			} else {
				/*
				 * Because we're reverting we know the mainline
				 * code failed but we just reused the err
				 * variable so we reset it back to Z_ERR.
				 */
				err = Z_ERR;
			}
		}

	} else {
		/* The move was successful, cleanup the old zonepath. */
		if (!fast) {
			int status;

			(void) printf(
			    gettext("Cleaning up zonepath %s..."), zonepath);
			(void) fflush(stdout);

			/*
			 * "exec" the command so that the returned status is
			 * that of rm and not the shell.
			 */
			(void) snprintf(cmdbuf, sizeof (cmdbuf),
			    "exec " RMCOMMAND " %s", zonepath);

			status = do_subproc(cmdbuf);

			(void) printf("\n");

			if ((err = subproc_status("rm", status)) != Z_OK) {
				errno = err;
				zperror(gettext("could not remove zonepath"),
				    B_TRUE);
			}
		}
	}

	return ((err == Z_OK) ? Z_OK : Z_ERR);
}

static int
detach_func(int argc, char *argv[])
{
	int lockfd;
	int err, arg;
	char zonepath[MAXPATHLEN];
	zone_dochandle_t handle;

	if (zonecfg_in_alt_root()) {
		zerror(gettext("cannot detach zone in alternate root"));
		return (Z_ERR);
	}

	optind = 0;
	if ((arg = getopt(argc, argv, "?")) != EOF) {
		switch (arg) {
		case '?':
			sub_usage(SHELP_DETACH, CMD_DETACH);
			return (optopt == '?' ? Z_OK : Z_USAGE);
		default:
			sub_usage(SHELP_DETACH, CMD_DETACH);
			return (Z_USAGE);
		}
	}
	if (sanity_check(target_zone, CMD_DETACH, B_FALSE, B_TRUE) != Z_OK)
		return (Z_ERR);
	if (verify_details(CMD_DETACH) != Z_OK)
		return (Z_ERR);

	if ((err = zone_get_zonepath(target_zone, zonepath, sizeof (zonepath)))
	    != Z_OK) {
		errno = err;
		zperror2(target_zone, gettext("could not get zone path"));
		return (Z_ERR);
	}

	/* Don't detach the zone if anything is still mounted there */
	if (zonecfg_find_mounts(zonepath, NULL, NULL)) {
		zerror(gettext("These file-systems are mounted on "
		    "subdirectories of %s.\n"), zonepath);
		(void) zonecfg_find_mounts(zonepath, zfm_print, NULL);
		return (Z_ERR);
	}

	if ((handle = zonecfg_init_handle()) == NULL) {
		zperror(cmd_to_str(CMD_DETACH), B_TRUE);
		return (Z_ERR);
	}

	if ((err = zonecfg_get_handle(target_zone, handle)) != Z_OK) {
		errno = err;
		zperror(cmd_to_str(CMD_DETACH), B_TRUE);
		zonecfg_fini_handle(handle);
		return (Z_ERR);
	}

	if (grab_lock_file(target_zone, &lockfd) != Z_OK) {
		zerror(gettext("another %s may have an operation in progress."),
		    "zoneadm");
		zonecfg_fini_handle(handle);
		return (Z_ERR);
	}

	if ((err = zonecfg_get_detach_info(handle, B_TRUE)) != Z_OK) {
		errno = err;
		zperror(gettext("getting the detach information failed"),
		    B_TRUE);
		goto done;
	}

	if ((err = zonecfg_detach_save(handle)) != Z_OK) {
		errno = err;
		zperror(gettext("saving the detach manifest failed"), B_TRUE);
		goto done;
	}

	if ((err = zone_set_state(target_zone, ZONE_STATE_CONFIGURED))
	    != Z_OK) {
		errno = err;
		zperror(gettext("could not reset state"), B_TRUE);
	}

done:
	zonecfg_fini_handle(handle);
	release_lock_file(lockfd);

	return ((err == Z_OK) ? Z_OK : Z_ERR);
}

/*
 * Find the specified package in the sw inventory on the handle and check
 * if the version matches what is passed in.
 * Return 0 if the packages match
 *        1 if the package is found but we have a version mismatch
 *        -1 if the package is not found
 */
static int
pkg_cmp(zone_dochandle_t handle, char *pkg_name, char *pkg_vers,
    char *return_vers, int vers_size)
{
	int res = -1;
	struct zone_pkgtab pkgtab;

	if (zonecfg_setpkgent(handle) != Z_OK) {
		(void) fprintf(stderr,
		    gettext("unable to enumerate packages\n"));
		return (Z_ERR);
	}

	while (zonecfg_getpkgent(handle, &pkgtab) == Z_OK) {
		if (strcmp(pkg_name, pkgtab.zone_pkg_name) != 0)
			continue;

		if (strcmp(pkg_vers, pkgtab.zone_pkg_version) == 0) {
			res = 0;
			break;
		}

		(void) strlcpy(return_vers, pkgtab.zone_pkg_version, vers_size);
		res = 1;
		break;
	}

	(void) zonecfg_endpkgent(handle);
	return (res);
}

/*
 * Used in software comparisons to check the packages between the two zone
 * handles.  The packages have to match or we print a message telling the
 * user what is out of sync.  The src_cmp flag tells us if the first handle
 * is the source machine global zone or not.  This is used to enable the
 * right messages to be printed and also to enable extra version checking
 * that is not needed for the opposite comparison.
 */
static int
pkg_check(char *header, zone_dochandle_t handle1, zone_dochandle_t handle2,
    boolean_t src_cmp)
{
	int			err;
	int			res = Z_OK;
	boolean_t		do_header = B_TRUE;
	char			other_vers[ZONE_PKG_VERSMAX];
	struct zone_pkgtab	pkgtab;

	if (zonecfg_setpkgent(handle1) != Z_OK) {
		(void) fprintf(stderr,
		    gettext("unable to enumerate packages\n"));
		return (Z_ERR);
	}

	while (zonecfg_getpkgent(handle1, &pkgtab) == Z_OK) {
		if ((err = pkg_cmp(handle2, pkgtab.zone_pkg_name,
		    pkgtab.zone_pkg_version, other_vers, sizeof (other_vers)))
		    != 0) {
			if (do_header && (err < 0 || src_cmp)) {
				/* LINTED E_SEC_PRINTF_VAR_FMT */
				(void) fprintf(stderr, header);
				do_header = B_FALSE;
			}
			if (err < 0) {
				(void) fprintf(stderr,
				    (src_cmp == B_TRUE) ?
				    gettext("\t%s: not installed\n\t\t(%s)\n") :
				    gettext("\t%s (%s)\n"),
				    pkgtab.zone_pkg_name,
				    pkgtab.zone_pkg_version);
				res = Z_ERR;
			} else if (src_cmp) {
				(void) fprintf(stderr, gettext(
				    "\t%s: version mismatch\n\t\t(%s)"
				    "\n\t\t(%s)\n"),
				    pkgtab.zone_pkg_name,
				    pkgtab.zone_pkg_version, other_vers);
				res = Z_ERR;
			}
		}
	}

	(void) zonecfg_endpkgent(handle1);

	return (res);
}

/*
 * Find the specified patch in the sw inventory on the handle and check
 * if the version matches what is passed in.
 * Return 0 if the patches match
 *        1 if the patches is found but we have a version mismatch
 *        -1 if the patches is not found
 */
static int
patch_cmp(zone_dochandle_t handle, char *patch_id, char *patch_vers,
    char *return_vers, int vers_size)
{
	int			res = -1;
	struct zone_patchtab	patchtab;

	if (zonecfg_setpatchent(handle) != Z_OK) {
		(void) fprintf(stderr,
		    gettext("unable to enumerate patches\n"));
		return (Z_ERR);
	}

	while (zonecfg_getpatchent(handle, &patchtab) == Z_OK) {
		char *p;

		if ((p = strchr(patchtab.zone_patch_id, '-')) != NULL)
			*p++ = '\0';
		else
			p = "";

		if (strcmp(patch_id, patchtab.zone_patch_id) != 0)
			continue;

		if (strcmp(patch_vers, p) == 0) {
			res = 0;
			break;
		}

		(void) strlcpy(return_vers, p, vers_size);
		/*
		 * Keep checking.  This handles the case where multiple
		 * versions of the same patch is installed.
		 */
		res = 1;
	}

	(void) zonecfg_endpatchent(handle);
	return (res);
}

/*
 * Used in software comparisons to check the patches between the two zone
 * handles.  The patches have to match or we print a message telling the
 * user what is out of sync.  The src_cmp flag tells us if the first handle
 * is the source machine global zone or not.  This is used to enable the
 * right messages to be printed and also to enable extra version checking
 * that is not needed for the opposite comparison.
 */
static int
patch_check(char *header, zone_dochandle_t handle1, zone_dochandle_t handle2,
    boolean_t src_cmp)
{
	int			err;
	int			res = Z_OK;
	boolean_t		do_header = B_TRUE;
	char			other_vers[MAXNAMELEN];
	struct zone_patchtab	patchtab;

	if (zonecfg_setpatchent(handle1) != Z_OK) {
		(void) fprintf(stderr,
		    gettext("unable to enumerate patches\n"));
		return (Z_ERR);
	}

	while (zonecfg_getpatchent(handle1, &patchtab) == Z_OK) {
		char *patch_vers;

		if ((patch_vers = strchr(patchtab.zone_patch_id, '-')) != NULL)
			*patch_vers++ = '\0';
		else
			patch_vers = "";

		if ((err = patch_cmp(handle2, patchtab.zone_patch_id,
		    patch_vers, other_vers, sizeof (other_vers))) != 0) {
			if (do_header && (err < 0 || src_cmp)) {
				/* LINTED E_SEC_PRINTF_VAR_FMT */
				(void) fprintf(stderr, header);
				do_header = B_FALSE;
			}
			if (err < 0) {
				(void) fprintf(stderr,
				    (src_cmp == B_TRUE) ?
				    gettext("\t%s: not installed\n") :
				    gettext("\t%s\n"),
				    patchtab.zone_patch_id);
				res = Z_ERR;
			} else if (src_cmp) {
				(void) fprintf(stderr,
				    gettext("\t%s: version mismatch\n\t\t(%s) "
				    "(%s)\n"), patchtab.zone_patch_id,
				    patch_vers, other_vers);
				res = Z_ERR;
			}
		}
	}

	(void) zonecfg_endpatchent(handle1);

	return (res);
}

/*
 * Compare the software on the local global zone and source system global
 * zone.  Used when we are trying to attach a zone during migration.
 * l_handle is for the local system and s_handle is for the source system.
 * These have a snapshot of the appropriate packages and patches in the global
 * zone for the two machines.
 * The functions called here will print any messages that are needed to
 * inform the user about package or patch problems.
 */
static int
sw_cmp(zone_dochandle_t l_handle, zone_dochandle_t s_handle)
{
	char		*hdr;
	int		res = Z_OK;

	/*
	 * Check the source host for pkgs (and versions) that are not on the
	 * local host.
	 */
	hdr = gettext("These packages installed on the source system are "
	    "inconsistent with this system:\n");
	if (pkg_check(hdr, s_handle, l_handle, B_TRUE) != Z_OK)
		res = Z_ERR;

	/*
	 * Now check the local host for pkgs that were not on the source host.
	 * We already handled version mismatches in the loop above.
	 */
	hdr = gettext("These packages installed on this system were "
	    "not installed on the source system:\n");
	if (pkg_check(hdr, l_handle, s_handle, B_FALSE) != Z_OK)
		res = Z_ERR;

	/*
	 * Check the source host for patches that are not on the local host.
	 */
	hdr = gettext("These patches installed on the source system are "
	    "inconsistent with this system:\n");
	if (patch_check(hdr, s_handle, l_handle, B_TRUE) != Z_OK)
		res = Z_ERR;

	/*
	 * Check the local host for patches that were not on the source host.
	 * We already handled version mismatches in the loop above.
	 */
	hdr = gettext("These patches installed on this system were "
	    "not installed on the source system:\n");
	if (patch_check(hdr, l_handle, s_handle, B_FALSE) != Z_OK)
		res = Z_ERR;

	return (res);
}

/*
 * During attach we go through and fix up the /dev entries for the zone
 * we are attaching.  In order to regenerate /dev with the correct devices,
 * the old /dev will be removed, the zone readied (which generates a new
 * /dev) then halted, then we use the info from the manifest to update
 * the modes, owners, etc. on the new /dev.
 */
static int
dev_fix(zone_dochandle_t handle)
{
	int			res;
	int			err;
	int			status;
	struct zone_devpermtab	devtab;
	zone_cmd_arg_t		zarg;
	char			devpath[MAXPATHLEN];
				/* 6: "exec " and " " */
	char			cmdbuf[sizeof (RMCOMMAND) + MAXPATHLEN + 6];

	if ((res = zonecfg_get_zonepath(handle, devpath, sizeof (devpath)))
	    != Z_OK)
		return (res);

	if (strlcat(devpath, "/dev", sizeof (devpath)) >= sizeof (devpath))
		return (Z_TOO_BIG);

	/*
	 * "exec" the command so that the returned status is that of
	 * RMCOMMAND and not the shell.
	 */
	(void) snprintf(cmdbuf, sizeof (cmdbuf), "exec " RMCOMMAND " %s",
	    devpath);
	status = do_subproc(cmdbuf);
	if ((err = subproc_status(RMCOMMAND, status)) != Z_OK) {
		(void) fprintf(stderr,
		    gettext("could not remove existing /dev\n"));
		return (Z_ERR);
	}

	/* In order to ready the zone, it must be in the installed state */
	if ((err = zone_set_state(target_zone, ZONE_STATE_INSTALLED)) != Z_OK) {
		errno = err;
		zperror(gettext("could not reset state"), B_TRUE);
		return (Z_ERR);
	}

	/* We have to ready the zone to regen the dev tree */
	zarg.cmd = Z_READY;
	if (call_zoneadmd(target_zone, &zarg) != 0) {
		zerror(gettext("call to %s failed"), "zoneadmd");
		return (Z_ERR);
	}

	zarg.cmd = Z_HALT;
	if (call_zoneadmd(target_zone, &zarg) != 0) {
		zerror(gettext("call to %s failed"), "zoneadmd");
		return (Z_ERR);
	}

	if (zonecfg_setdevperment(handle) != Z_OK) {
		(void) fprintf(stderr,
		    gettext("unable to enumerate device entries\n"));
		return (Z_ERR);
	}

	while (zonecfg_getdevperment(handle, &devtab) == Z_OK) {
		int err;

		if ((err = zonecfg_devperms_apply(handle,
		    devtab.zone_devperm_name, devtab.zone_devperm_uid,
		    devtab.zone_devperm_gid, devtab.zone_devperm_mode,
		    devtab.zone_devperm_acl)) != Z_OK && err != Z_INVAL)
			(void) fprintf(stderr, gettext("error updating device "
			    "%s: %s\n"), devtab.zone_devperm_name,
			    zonecfg_strerror(err));

		free(devtab.zone_devperm_acl);
	}

	(void) zonecfg_enddevperment(handle);

	return (Z_OK);
}

static int
attach_func(int argc, char *argv[])
{
	int lockfd;
	int err, arg;
	boolean_t force = B_FALSE;
	zone_dochandle_t handle;
	zone_dochandle_t athandle = NULL;
	char zonepath[MAXPATHLEN];

	if (zonecfg_in_alt_root()) {
		zerror(gettext("cannot attach zone in alternate root"));
		return (Z_ERR);
	}

	optind = 0;
	if ((arg = getopt(argc, argv, "?F")) != EOF) {
		switch (arg) {
		case '?':
			sub_usage(SHELP_ATTACH, CMD_ATTACH);
			return (optopt == '?' ? Z_OK : Z_USAGE);
		case 'F':
			force = B_TRUE;
			break;
		default:
			sub_usage(SHELP_ATTACH, CMD_ATTACH);
			return (Z_USAGE);
		}
	}
	if (sanity_check(target_zone, CMD_ATTACH, B_FALSE, B_TRUE) != Z_OK)
		return (Z_ERR);
	if (verify_details(CMD_ATTACH) != Z_OK)
		return (Z_ERR);

	if ((err = zone_get_zonepath(target_zone, zonepath, sizeof (zonepath)))
	    != Z_OK) {
		errno = err;
		zperror2(target_zone, gettext("could not get zone path"));
		return (Z_ERR);
	}

	if ((handle = zonecfg_init_handle()) == NULL) {
		zperror(cmd_to_str(CMD_ATTACH), B_TRUE);
		return (Z_ERR);
	}

	if ((err = zonecfg_get_handle(target_zone, handle)) != Z_OK) {
		errno = err;
		zperror(cmd_to_str(CMD_ATTACH), B_TRUE);
		zonecfg_fini_handle(handle);
		return (Z_ERR);
	}

	if (grab_lock_file(target_zone, &lockfd) != Z_OK) {
		zerror(gettext("another %s may have an operation in progress."),
		    "zoneadm");
		zonecfg_fini_handle(handle);
		return (Z_ERR);
	}

	if (force)
		goto forced;

	if ((athandle = zonecfg_init_handle()) == NULL) {
		zperror(cmd_to_str(CMD_ATTACH), B_TRUE);
		goto done;
	}

	if ((err = zonecfg_get_attach_handle(zonepath, target_zone, B_TRUE,
	    athandle)) != Z_OK) {
		if (err == Z_NO_ZONE)
			zerror(gettext("Not a detached zone"));
		else if (err == Z_INVALID_DOCUMENT)
			zerror(gettext("Cannot attach to an earlier release "
			    "of the operating system"));
		else
			zperror(cmd_to_str(CMD_ATTACH), B_TRUE);
		goto done;
	}

	/* Get the detach information for the locally defined zone. */
	if ((err = zonecfg_get_detach_info(handle, B_FALSE)) != Z_OK) {
		errno = err;
		zperror(gettext("getting the attach information failed"),
		    B_TRUE);
		goto done;
	}

	/* sw_cmp prints error msgs as necessary */
	if ((err = sw_cmp(handle, athandle)) != Z_OK)
		goto done;

	if ((err = dev_fix(athandle)) != Z_OK)
		goto done;

forced:

	zonecfg_rm_detached(handle, force);

	if ((err = zone_set_state(target_zone, ZONE_STATE_INSTALLED)) != Z_OK) {
		errno = err;
		zperror(gettext("could not reset state"), B_TRUE);
	}

done:
	zonecfg_fini_handle(handle);
	release_lock_file(lockfd);
	if (athandle != NULL)
		zonecfg_fini_handle(athandle);

	return ((err == Z_OK) ? Z_OK : Z_ERR);
}

/*
 * On input, TRUE => yes, FALSE => no.
 * On return, TRUE => 1, FALSE => 0, could not ask => -1.
 */

static int
ask_yesno(boolean_t default_answer, const char *question)
{
	char line[64];	/* should be large enough to answer yes or no */

	if (!isatty(STDIN_FILENO))
		return (-1);
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

static int
uninstall_func(int argc, char *argv[])
{
	/* 6: "exec " and " " */
	char cmdbuf[sizeof (RMCOMMAND) + MAXPATHLEN + 6];
	char line[ZONENAME_MAX + 128];	/* Enough for "Are you sure ..." */
	char rootpath[MAXPATHLEN], devpath[MAXPATHLEN];
	boolean_t force = B_FALSE;
	int lockfd, answer;
	int err, arg;
	int status;

	if (zonecfg_in_alt_root()) {
		zerror(gettext("cannot uninstall zone in alternate root"));
		return (Z_ERR);
	}

	optind = 0;
	while ((arg = getopt(argc, argv, "?F")) != EOF) {
		switch (arg) {
		case '?':
			sub_usage(SHELP_UNINSTALL, CMD_UNINSTALL);
			return (optopt == '?' ? Z_OK : Z_USAGE);
		case 'F':
			force = B_TRUE;
			break;
		default:
			sub_usage(SHELP_UNINSTALL, CMD_UNINSTALL);
			return (Z_USAGE);
		}
	}
	if (argc > optind) {
		sub_usage(SHELP_UNINSTALL, CMD_UNINSTALL);
		return (Z_USAGE);
	}

	if (sanity_check(target_zone, CMD_UNINSTALL, B_FALSE, B_TRUE) != Z_OK)
		return (Z_ERR);

	if (!force) {
		(void) snprintf(line, sizeof (line),
		    gettext("Are you sure you want to %s zone %s"),
		    cmd_to_str(CMD_UNINSTALL), target_zone);
		if ((answer = ask_yesno(B_FALSE, line)) == 0) {
			return (Z_OK);
		} else if (answer == -1) {
			zerror(gettext("Input not from terminal and -F "
			    "not specified: %s not done."),
			    cmd_to_str(CMD_UNINSTALL));
			return (Z_ERR);
		}
	}

	if ((err = zone_get_zonepath(target_zone, devpath,
	    sizeof (devpath))) != Z_OK) {
		errno = err;
		zperror2(target_zone, gettext("could not get zone path"));
		return (Z_ERR);
	}
	(void) strlcat(devpath, "/dev", sizeof (devpath));
	if ((err = zone_get_rootpath(target_zone, rootpath,
	    sizeof (rootpath))) != Z_OK) {
		errno = err;
		zperror2(target_zone, gettext("could not get root path"));
		return (Z_ERR);
	}

	/*
	 * If there seems to be a zoneadmd running for this zone, call it
	 * to tell it that an uninstall is happening; if all goes well it
	 * will then shut itself down.
	 */
	if (ping_zoneadmd(target_zone) == Z_OK) {
		zone_cmd_arg_t zarg;
		zarg.cmd = Z_NOTE_UNINSTALLING;
		/* we don't care too much if this fails... just plow on */
		(void) call_zoneadmd(target_zone, &zarg);
	}

	if (grab_lock_file(target_zone, &lockfd) != Z_OK) {
		zerror(gettext("another %s may have an operation in progress."),
		    "zoneadm");
		return (Z_ERR);
	}

	/* Don't uninstall the zone if anything is mounted there */
	err = zonecfg_find_mounts(rootpath, NULL, NULL);
	if (err) {
		zerror(gettext("These file-systems are mounted on "
			"subdirectories of %s.\n"), rootpath);
		(void) zonecfg_find_mounts(rootpath, zfm_print, NULL);
		return (Z_ERR);
	}

	err = zone_set_state(target_zone, ZONE_STATE_INCOMPLETE);
	if (err != Z_OK) {
		errno = err;
		zperror2(target_zone, gettext("could not set state"));
		goto bad;
	}

	/*
	 * "exec" the command so that the returned status is that of
	 * RMCOMMAND and not the shell.
	 */
	(void) snprintf(cmdbuf, sizeof (cmdbuf), "exec " RMCOMMAND " %s",
	    devpath);
	status = do_subproc(cmdbuf);
	if ((err = subproc_status(RMCOMMAND, status)) != Z_OK)
		goto bad;
	(void) snprintf(cmdbuf, sizeof (cmdbuf), "exec " RMCOMMAND " %s",
	    rootpath);
	status = do_subproc(cmdbuf);
	if ((err = subproc_status(RMCOMMAND, status)) != Z_OK)
		goto bad;
	err = zone_set_state(target_zone, ZONE_STATE_CONFIGURED);
	if (err != Z_OK) {
		errno = err;
		zperror2(target_zone, gettext("could not reset state"));
	}
bad:
	release_lock_file(lockfd);
	return (err);
}

/* ARGSUSED */
static int
mount_func(int argc, char *argv[])
{
	zone_cmd_arg_t zarg;

	if (argc > 0)
		return (Z_USAGE);
	if (sanity_check(target_zone, CMD_MOUNT, B_FALSE, B_FALSE) != Z_OK)
		return (Z_ERR);
	if (verify_details(CMD_MOUNT) != Z_OK)
		return (Z_ERR);

	zarg.cmd = Z_MOUNT;
	if (call_zoneadmd(target_zone, &zarg) != 0) {
		zerror(gettext("call to %s failed"), "zoneadmd");
		return (Z_ERR);
	}
	return (Z_OK);
}

/* ARGSUSED */
static int
unmount_func(int argc, char *argv[])
{
	zone_cmd_arg_t zarg;

	if (argc > 0)
		return (Z_USAGE);
	if (sanity_check(target_zone, CMD_UNMOUNT, B_FALSE, B_FALSE) != Z_OK)
		return (Z_ERR);

	zarg.cmd = Z_UNMOUNT;
	if (call_zoneadmd(target_zone, &zarg) != 0) {
		zerror(gettext("call to %s failed"), "zoneadmd");
		return (Z_ERR);
	}
	return (Z_OK);
}

static int
help_func(int argc, char *argv[])
{
	int arg, cmd_num;

	if (argc == 0) {
		(void) usage(B_TRUE);
		return (Z_OK);
	}
	optind = 0;
	if ((arg = getopt(argc, argv, "?")) != EOF) {
		switch (arg) {
		case '?':
			sub_usage(SHELP_HELP, CMD_HELP);
			return (optopt == '?' ? Z_OK : Z_USAGE);
		default:
			sub_usage(SHELP_HELP, CMD_HELP);
			return (Z_USAGE);
		}
	}
	while (optind < argc) {
		/* Private commands have NULL short_usage; omit them */
		if ((cmd_num = cmd_match(argv[optind])) < 0 ||
		    cmdtab[cmd_num].short_usage == NULL) {
			sub_usage(SHELP_HELP, CMD_HELP);
			return (Z_USAGE);
		}
		sub_usage(cmdtab[cmd_num].short_usage, cmd_num);
		optind++;
	}
	return (Z_OK);
}

/*
 * Returns: CMD_MIN thru CMD_MAX on success, -1 on error
 */

static int
cmd_match(char *cmd)
{
	int i;

	for (i = CMD_MIN; i <= CMD_MAX; i++) {
		/* return only if there is an exact match */
		if (strcmp(cmd, cmdtab[i].cmd_name) == 0)
			return (cmdtab[i].cmd_num);
	}
	return (-1);
}

static int
parse_and_run(int argc, char *argv[])
{
	int i = cmd_match(argv[0]);

	if (i < 0)
		return (usage(B_FALSE));
	return (cmdtab[i].handler(argc - 1, &(argv[1])));
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

int
main(int argc, char **argv)
{
	int arg;
	zoneid_t zid;
	struct stat st;

	if ((locale = setlocale(LC_ALL, "")) == NULL)
		locale = "C";
	(void) textdomain(TEXT_DOMAIN);
	setbuf(stdout, NULL);
	(void) sigset(SIGHUP, SIG_IGN);
	execname = get_execbasename(argv[0]);
	target_zone = NULL;
	if (chdir("/") != 0) {
		zerror(gettext("could not change directory to /."));
		exit(Z_ERR);
	}

	while ((arg = getopt(argc, argv, "?z:R:")) != EOF) {
		switch (arg) {
		case '?':
			return (usage(B_TRUE));
		case 'z':
			target_zone = optarg;
			break;
		case 'R':	/* private option for admin/install use */
			if (*optarg != '/') {
				zerror(gettext("root path must be absolute."));
				exit(Z_ERR);
			}
			if (stat(optarg, &st) == -1 || !S_ISDIR(st.st_mode)) {
				zerror(
				    gettext("root path must be a directory."));
				exit(Z_ERR);
			}
			zonecfg_set_root(optarg);
			break;
		default:
			return (usage(B_FALSE));
		}
	}

	if (optind >= argc)
		return (usage(B_FALSE));
	if (target_zone != NULL && zone_get_id(target_zone, &zid) != 0) {
		errno = Z_NO_ZONE;
		zperror(target_zone, B_TRUE);
		exit(Z_ERR);
	}
	return (parse_and_run(argc - optind, &argv[optind]));
}
