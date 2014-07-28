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
/* Copyright (c) 2012 by Delphix. All rights reserved */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <sys/task.h>
#include <sys/contract.h>

#include <signal.h>
#include <unistd.h>
#include <dirent.h>
#include <stdlib.h>
#include <string.h>

#include <libintl.h>
#include <locale.h>
#include <stdio.h>
#include <fcntl.h>
#include <ctype.h>
#include <wchar.h>
#include <limits.h>
#include <libuutil.h>
#include <libcontract_priv.h>

#include <procfs.h>
#include <project.h>
#include <pwd.h>
#include <grp.h>
#include <zone.h>

#include "psexp.h"
#include "pgrep.h"

#ifndef	TEXT_DOMAIN
#define	TEXT_DOMAIN	"SYS_TEST"
#endif

#define	OPT_SETB 	0x0001	/* Set the bits specified by o_bits */
#define	OPT_CLRB 	0x0002	/* Clear the bits specified by o_bits */
#define	OPT_FUNC 	0x0004	/* Call the function specified by o_func */
#define	OPT_STR  	0x0008	/* Set the string specified by o_ptr */
#define	OPT_CRIT 	0x0010	/* Option is part of selection criteria */

#define	F_LONG_FMT	0x0001	/* Match against long format cmd */
#define	F_NEWEST	0x0002	/* Match only newest pid */
#define	F_REVERSE	0x0004	/* Reverse matching criteria */
#define	F_EXACT_MATCH	0x0008	/* Require exact match */
#define	F_HAVE_CRIT	0x0010	/* Criteria specified */
#define	F_OUTPUT	0x0020	/* Some output has been printed */
#define	F_KILL		0x0040	/* Pkill semantics active (vs pgrep) */
#define	F_LONG_OUT	0x0080	/* Long output format (pgrep -l) */
#define	F_OLDEST	0x0100	/* Match only oldest pid */

static int opt_euid(char, char *);
static int opt_uid(char, char *);
static int opt_gid(char, char *);
static int opt_ppid(char, char *);
static int opt_pgrp(char, char *);
static int opt_sid(char, char *);
static int opt_term(char, char *);
static int opt_projid(char, char *);
static int opt_taskid(char, char *);
static int opt_zoneid(char, char *);
static int opt_ctid(char, char *);

static const char *g_procdir = "/proc";	/* Default procfs mount point */
static const char *g_delim = "\n";	/* Default output delimiter */
static const char *g_pname;		/* Program name for error messages */
static ushort_t g_flags;		/* Miscellaneous flags */

static optdesc_t g_optdtab[] = {
	{ 0, 0, 0, 0 },					/* 'A' */
	{ 0, 0, 0, 0 },					/* 'B' */
	{ 0, 0, 0, 0 },					/* 'C' */
	{ OPT_STR, 0, 0, &g_procdir },			/* -D procfsdir */
	{ 0, 0, 0, 0 },					/* 'E' */
	{ 0, 0, 0, 0 },					/* 'F' */
	{ OPT_FUNC | OPT_CRIT, 0, opt_gid, 0 },		/* -G gid */
	{ 0, 0, 0, 0 },					/* 'H' */
	{ 0, 0, 0, 0 },					/* 'I' */
	{ OPT_FUNC | OPT_CRIT, 0, opt_projid, 0 },	/* -J projid */
	{ 0, 0, 0, 0 },					/* 'K' */
	{ 0, 0, 0, 0 },					/* 'L' */
	{ 0, 0, 0, 0 },					/* 'M' */
	{ 0, 0, 0, 0 },					/* 'N' */
	{ 0, 0, 0, 0 },					/* 'O' */
	{ OPT_FUNC | OPT_CRIT, 0, opt_ppid, 0 },	/* -P ppid */
	{ 0, 0, 0, 0 },					/* 'Q' */
	{ 0, 0, 0, 0 },					/* 'R' */
	{ 0, 0, 0, 0 },					/* 'S' */
	{ OPT_FUNC | OPT_CRIT, 0, opt_taskid, 0 },	/* -T taskid */
	{ OPT_FUNC | OPT_CRIT, 0, opt_uid, 0 },		/* -U uid */
	{ 0, 0, 0, 0 },					/* 'V' */
	{ 0, 0, 0, 0 },					/* 'W' */
	{ 0, 0, 0, 0 },					/* 'X' */
	{ 0, 0, 0, 0 },					/* 'Y' */
	{ 0, 0, 0, 0 },					/* 'Z' */
	{ 0, 0, 0, 0 },					/* '[' */
	{ 0, 0, 0, 0 },					/* '\\' */
	{ 0, 0, 0, 0 },					/* ']' */
	{ 0, 0, 0, 0 },					/* '^' */
	{ 0, 0, 0, 0 },					/* '_' */
	{ 0, 0, 0, 0 },					/* '`' */
	{ 0, 0, 0, 0 },					/* 'a' */
	{ 0, 0, 0, 0 },					/* 'b' */
	{ OPT_FUNC | OPT_CRIT, 0, opt_ctid, 0 },	/* -c ctid */
	{ OPT_STR, 0, 0, &g_delim },			/* -d delim */
	{ 0, 0, 0, 0 },					/* 'e' */
	{ OPT_SETB, F_LONG_FMT, 0, &g_flags },		/* -f */
	{ OPT_FUNC | OPT_CRIT, 0, opt_pgrp, 0 },	/* -g pgrp */
	{ 0, 0, 0, 0 },					/* 'h' */
	{ 0, 0, 0, 0 },					/* 'i' */
	{ 0, 0, 0, 0 },					/* 'j' */
	{ 0, 0, 0, 0 },					/* 'k' */
	{ OPT_SETB, F_LONG_OUT, 0, &g_flags },		/* 'l' */
	{ 0, 0, 0, 0 },					/* 'm' */
	{ OPT_SETB, F_NEWEST, 0, &g_flags },    	/* -n */
	{ OPT_SETB, F_OLDEST, 0, &g_flags },		/* -o */
	{ 0, 0, 0, 0 },					/* 'p' */
	{ 0, 0, 0, 0 },					/* 'q' */
	{ 0, 0, 0, 0 },					/* 'r' */
	{ OPT_FUNC | OPT_CRIT, 0, opt_sid, 0 },		/* -s sid */
	{ OPT_FUNC | OPT_CRIT, 0, opt_term, 0 },	/* -t term */
	{ OPT_FUNC | OPT_CRIT, 0, opt_euid, 0 },	/* -u euid */
	{ OPT_SETB, F_REVERSE, 0, &g_flags },		/* -v */
	{ 0, 0, 0, 0 },					/* 'w' */
	{ OPT_SETB, F_EXACT_MATCH, 0, &g_flags },	/* -x */
	{ 0, 0, 0, 0 },					/* 'y' */
	{ OPT_FUNC | OPT_CRIT, 0, opt_zoneid, 0 }	/* -z zoneid */
};

static const char PGREP_USAGE[] = "\
Usage: %s [-flnovx] [-d delim] [-P ppidlist] [-g pgrplist] [-s sidlist]\n\
	[-u euidlist] [-U uidlist] [-G gidlist] [-J projidlist]\n\
	[-T taskidlist] [-t termlist] [-z zonelist] [-c ctidlist] [pattern]\n";

static const char PKILL_USAGE[] = "\
Usage: %s [-signal] [-fnovx] [-P ppidlist] [-g pgrplist] [-s sidlist]\n\
	[-u euidlist] [-U uidlist] [-G gidlist] [-J projidlist]\n\
	[-T taskidlist] [-t termlist] [-z zonelist] [-c ctidlist] [pattern]\n";

static const char PGREP_OPTS[] = ":flnovxc:d:D:u:U:G:P:g:s:t:z:J:T:";
static const char PKILL_OPTS[] = ":fnovxc:D:u:U:G:P:g:s:t:z:J:T:";

static const char LSEP[] = ",\t ";	/* Argument list delimiter chars */

static psexp_t g_psexp;			/* Process matching expression */
static pid_t g_pid;			/* Current pid */
static int g_signal = SIGTERM;		/* Signal to send */

static void
print_proc(psinfo_t *psinfo)
{
	if (g_flags & F_OUTPUT)
		(void) printf("%s%d", g_delim, (int)psinfo->pr_pid);
	else {
		(void) printf("%d", (int)psinfo->pr_pid);
		g_flags |= F_OUTPUT;
	}
}

static char *
mbstrip(char *buf, size_t nbytes)
{
	wchar_t wc;
	char *p;
	int n;

	buf[nbytes - 1] = '\0';
	p = buf;

	while (*p != '\0') {
		n = mbtowc(&wc, p, MB_LEN_MAX);

		if (n < 0 || !iswprint(wc)) {
			if (n < 0)
				n = sizeof (char);

			if (nbytes <= n) {
				*p = '\0';
				break;
			}

			(void) memmove(p, p + n, nbytes - n);

		} else {
			nbytes -= n;
			p += n;
		}
	}

	return (buf);
}

static void
print_proc_long(psinfo_t *psinfo)
{
	char *name;

	if (g_flags & F_LONG_FMT)
		name = mbstrip(psinfo->pr_psargs, PRARGSZ);
	else
		name = psinfo->pr_fname;

	if (g_flags & F_OUTPUT)
		(void) printf("%s%5d %s", g_delim, (int)psinfo->pr_pid, name);
	else {
		(void) printf("%5d %s", (int)psinfo->pr_pid, name);
		g_flags |= F_OUTPUT;
	}
}

static void
kill_proc(psinfo_t *psinfo)
{
	if (psinfo->pr_pid > 0 && kill(psinfo->pr_pid, g_signal) == -1)
		uu_warn(gettext("Failed to signal pid %d"),
		    (int)psinfo->pr_pid);
}

static DIR *
open_proc_dir(const char *dirpath)
{
	struct stat buf;
	DIR *dirp;

	if ((dirp = opendir(dirpath)) == NULL) {
		uu_warn(gettext("Failed to open %s"), dirpath);
		return (NULL);
	}

	if (fstat(dirp->dd_fd, &buf) == -1) {
		uu_warn(gettext("Failed to stat %s"), dirpath);
		(void) closedir(dirp);
		return (NULL);
	}

	if (strcmp(buf.st_fstype, "proc") != 0) {
		uu_warn(gettext("%s is not a procfs mount point\n"), dirpath);
		(void) closedir(dirp);
		return (NULL);
	}

	return (dirp);
}

#define	NEWER(ps1, ps2) \
	((ps1.pr_start.tv_sec > ps2.pr_start.tv_sec) || \
	    (ps1.pr_start.tv_sec == ps2.pr_start.tv_sec && \
	    ps1.pr_start.tv_nsec > ps2.pr_start.tv_nsec))

static int
scan_proc_dir(const char *dirpath, DIR *dirp, psexp_t *psexp,
	void (*funcp)(psinfo_t *))
{
	char procpath[MAXPATHLEN];
	psinfo_t ps, ops;
	dirent_t *dent;
	int procfd;

	int reverse = (g_flags & F_REVERSE) ? 1 : 0;
	int ovalid = 0, nmatches = 0, flags = 0;

	if (g_flags & F_LONG_FMT)
		flags |= PSEXP_PSARGS;

	if (g_flags & F_EXACT_MATCH)
		flags |= PSEXP_EXACT;

	while ((dent = readdir(dirp)) != NULL) {

		if (dent->d_name[0] == '.')
			continue;

		(void) snprintf(procpath, sizeof (procpath), "%s/%s/psinfo",
		    dirpath, dent->d_name);

		if ((procfd = open(procpath, O_RDONLY)) == -1)
			continue;

		if ((read(procfd, &ps, sizeof (ps)) == sizeof (psinfo_t)) &&
		    (ps.pr_nlwp != 0) && (ps.pr_pid != g_pid) &&
		    (psexp_match(psexp, &ps, flags) ^ reverse)) {

			if (g_flags & F_NEWEST) {
				/* LINTED - opsinfo use ok */
				if (!ovalid || NEWER(ps, ops)) {
					(void) memcpy(&ops, &ps,
					    sizeof (psinfo_t));
					ovalid = 1;
				}
			} else if (g_flags & F_OLDEST) {
				if (!ovalid || NEWER(ops, ps)) {
					(void) memcpy(&ops, &ps,
					    sizeof (psinfo_t));
					ovalid = 1;
				}
			} else {
				(*funcp)(&ps);
				nmatches++;
			}
		}

		(void) close(procfd);
	}

	if ((g_flags & (F_NEWEST | F_OLDEST)) && ovalid) {
		(*funcp)(&ops);
		nmatches++;
	}

	return (nmatches);
}

static int
parse_ids(idtab_t *idt, char *arg, int base, int opt, idkey_t zero)
{
	char *ptr, *next;
	idkey_t id;

	for (ptr = strtok(arg, LSEP); ptr != NULL; ptr = strtok(NULL, LSEP)) {
		if ((id = (idkey_t)strtoul(ptr, &next, base)) != 0)
			idtab_append(idt, id);
		else
			idtab_append(idt, zero);

		if (next == ptr || *next != 0) {
			uu_warn("invalid argument for option '%c' -- %s\n",
			    opt, ptr);
			return (-1);
		}
	}

	return (0);
}

static int
parse_uids(idtab_t *idt, char *arg)
{
	char *ptr, *next;
	struct passwd *pwent;
	idkey_t id;

	for (ptr = strtok(arg, LSEP); ptr != NULL; ptr = strtok(NULL, LSEP)) {
		if (isdigit(ptr[0])) {
			id = strtol(ptr, &next, 10);

			if (next != ptr && *next == '\0') {
				idtab_append(idt, id);
				continue;
			}
		}

		if ((pwent = getpwnam(ptr)) != NULL)
			idtab_append(idt, pwent->pw_uid);
		else
			goto err;
	}

	return (0);

err:
	uu_warn(gettext("invalid user name -- %s\n"), ptr);
	return (-1);
}

static int
parse_gids(idtab_t *idt, char *arg)
{
	char *ptr, *next;
	struct group *grent;
	idkey_t id;

	for (ptr = strtok(arg, LSEP); ptr != NULL; ptr = strtok(NULL, LSEP)) {
		if (isdigit(ptr[0])) {
			id = strtol(ptr, &next, 10);

			if (next != ptr && *next == '\0') {
				idtab_append(idt, id);
				continue;
			}
		}

		if ((grent = getgrnam(ptr)) != NULL)
			idtab_append(idt, grent->gr_gid);
		else
			goto err;
	}

	return (0);

err:
	uu_warn(gettext("invalid group name -- %s\n"), ptr);
	return (-1);
}

static int
parse_ttys(idtab_t *idt, char *arg)
{
	char devpath[MAXPATHLEN];
	struct stat buf;
	char *ptr;

	int seen_console = 0; /* Flag so we only stat syscon and systty once */

	for (ptr = strtok(arg, LSEP); ptr != NULL; ptr = strtok(NULL, LSEP)) {
		if (strcmp(ptr, "none") == 0) {
			idtab_append(idt, (idkey_t)PRNODEV);
			continue;
		}

		if (strcmp(ptr, "console") == 0) {
			if (seen_console)
				continue;

			if (stat("/dev/syscon", &buf) == 0)
				idtab_append(idt, (idkey_t)buf.st_rdev);

			if (stat("/dev/systty", &buf) == 0)
				idtab_append(idt, (idkey_t)buf.st_rdev);

			seen_console++;
		}

		(void) snprintf(devpath, MAXPATHLEN - 1, "/dev/%s", ptr);

		if (stat(devpath, &buf) == -1)
			goto err;

		idtab_append(idt, (idkey_t)buf.st_rdev);
	}

	return (0);

err:
	uu_warn(gettext("unknown terminal name -- %s\n"), ptr);
	return (-1);
}

static int
parse_projects(idtab_t *idt, char *arg)
{
	char *ptr, *next;
	projid_t projid;
	idkey_t id;

	for (ptr = strtok(arg, LSEP); ptr != NULL; ptr = strtok(NULL, LSEP)) {
		if (isdigit(ptr[0])) {
			id = strtol(ptr, &next, 10);

			if (next != ptr && *next == '\0') {
				idtab_append(idt, id);
				continue;
			}
		}

		if ((projid = getprojidbyname(ptr)) != -1)
			idtab_append(idt, projid);
		else
			goto err;
	}

	return (0);

err:
	uu_warn(gettext("invalid project name -- %s\n"), ptr);
	return (-1);
}

static int
parse_zones(idtab_t *idt, char *arg)
{
	char *ptr;
	zoneid_t id;

	for (ptr = strtok(arg, LSEP); ptr != NULL; ptr = strtok(NULL, LSEP)) {
		if (zone_get_id(ptr, &id) != 0) {
			uu_warn(gettext("invalid zone name -- %s\n"), ptr);
			return (-1);
		}
		idtab_append(idt, id);
	}

	return (0);
}

/*ARGSUSED*/
static int
opt_euid(char c, char *arg)
{
	return (parse_uids(&g_psexp.ps_euids, arg));
}

/*ARGSUSED*/
static int
opt_uid(char c, char *arg)
{
	return (parse_uids(&g_psexp.ps_ruids, arg));
}

/*ARGSUSED*/
static int
opt_gid(char c, char *arg)
{
	return (parse_gids(&g_psexp.ps_rgids, arg));
}

static int
opt_ppid(char c, char *arg)
{
	return (parse_ids(&g_psexp.ps_ppids, arg, 10, c, 0));
}

static int
opt_pgrp(char c, char *arg)
{
	return (parse_ids(&g_psexp.ps_pgids, arg, 10, c, getpgrp()));
}

static int
opt_sid(char c, char *arg)
{
	return (parse_ids(&g_psexp.ps_sids, arg, 10, c, getsid(0)));
}

/*ARGSUSED*/
static int
opt_term(char c, char *arg)
{
	return (parse_ttys(&g_psexp.ps_ttys, arg));
}

/*ARGSUSED*/
static int
opt_projid(char c, char *arg)
{
	return (parse_projects(&g_psexp.ps_projids, arg));
}

static int
opt_taskid(char c, char *arg)
{
	return (parse_ids(&g_psexp.ps_taskids, arg, 10, c, gettaskid()));
}

/*ARGSUSED*/
static int
opt_zoneid(char c, char *arg)
{
	return (parse_zones(&g_psexp.ps_zoneids, arg));
}

static int
opt_ctid(char c, char *arg)
{
	return (parse_ids(&g_psexp.ps_ctids, arg, 10, c, getctid()));
}

static void
print_usage(FILE *stream)
{
	if (g_flags & F_KILL)
		(void) fprintf(stream, gettext(PKILL_USAGE), g_pname);
	else
		(void) fprintf(stream, gettext(PGREP_USAGE), g_pname);
}

int
main(int argc, char *argv[])
{
	void (*funcp)(psinfo_t *);

	const char *optstr;
	optdesc_t *optd;
	int nmatches, c;
	const char *zroot;
	char buf[PATH_MAX];

	DIR *dirp;

	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);

	UU_EXIT_FATAL = E_ERROR;

	g_pname = uu_setpname(argv[0]);
	g_pid = getpid();

	psexp_create(&g_psexp);

	if (strcmp(g_pname, "pkill") == 0) {

		if (argc > 1 && argv[1][0] == '-' &&
		    str2sig(&argv[1][1], &g_signal) == 0) {
			argv[1] = argv[0];
			argv++;
			argc--;
		}

		optstr = PKILL_OPTS;
		g_flags |= F_KILL;
	} else
		optstr = PGREP_OPTS;

	opterr = 0;

	zroot = zone_get_nroot();
	if (zroot != NULL) {
		(void) snprintf(buf, sizeof (buf), "%s/%s", zroot, g_procdir);
		g_procdir = buf;
	}

	while (optind < argc) {
		while ((c = getopt(argc, argv, optstr)) != (int)EOF) {

			if (c == ':' || c == '?' ||
			    g_optdtab[c - 'A'].o_opts == 0) {
				if (c == ':') {
					uu_warn(
					    gettext("missing argument -- %c\n"),
					    optopt);
				} else if (optopt != '?') {
					uu_warn(
					    gettext("illegal option -- %c\n"),
					    optopt);
				}

				print_usage(stderr);
				return (E_USAGE);
			}

			optd = &g_optdtab[c - 'A'];

			if (optd->o_opts & OPT_SETB)
				*((ushort_t *)optd->o_ptr) |= optd->o_bits;

			if (optd->o_opts & OPT_CLRB)
				*((ushort_t *)optd->o_ptr) &= ~optd->o_bits;

			if (optd->o_opts & OPT_STR)
				*((char **)optd->o_ptr) = optarg;

			if (optd->o_opts & OPT_CRIT)
				g_flags |= F_HAVE_CRIT;

			if (optd->o_opts & OPT_FUNC) {
				if (optd->o_func(c, optarg) == -1)
					return (E_USAGE);
			}
		}

		if (optind < argc) {
			if (g_psexp.ps_pat != NULL) {
				uu_warn(gettext("illegal argument -- %s\n"),
				    argv[optind]);
				print_usage(stderr);
				return (E_USAGE);
			}

			g_psexp.ps_pat = argv[optind++];
			g_flags |= F_HAVE_CRIT;
		}
	}

	if ((g_flags & F_NEWEST) && (g_flags & F_OLDEST)) {
		uu_warn(gettext("-n and -o are mutually exclusive\n"));
		print_usage(stderr);
		return (E_USAGE);
	}

	if ((g_flags & F_HAVE_CRIT) == 0) {
		uu_warn(gettext("No matching criteria specified\n"));
		print_usage(stderr);
		return (E_USAGE);
	}

	if (psexp_compile(&g_psexp) == -1) {
		psexp_destroy(&g_psexp);
		return (E_USAGE);
	}

	if ((dirp = open_proc_dir(g_procdir)) == NULL)
		return (E_ERROR);

	if (g_flags & F_KILL)
		funcp = kill_proc;
	else if (g_flags & F_LONG_OUT)
		funcp = print_proc_long;
	else
		funcp = print_proc;

	nmatches = scan_proc_dir(g_procdir, dirp, &g_psexp, funcp);

	if (g_flags & F_OUTPUT)
		(void) fputc('\n', stdout);

	psexp_destroy(&g_psexp);
	return (nmatches ? E_MATCH : E_NOMATCH);
}
