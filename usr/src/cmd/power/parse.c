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

#include "pmconfig.h"
#include <deflt.h>
#include <pwd.h>

#ifdef sparc
#include <libdevinfo.h>
static char sf_cmt[] = "# Statefile\t\tPath\n";
#endif

static char as_cmt[] =
	"# Auto-Shutdown\t\tIdle(min)\tStart/Finish(hh:mm)\tBehavior\n";

char **line_args;
int lineno = 0;

/*
 * cpr and pm combined permission/update status
 */
prmup_t cpr_status = { 0, OKUP, "cpr" };
prmup_t pm_status  = { 0, OKUP, "pm" };


/*
 * For config file parsing to work correctly/efficiently, this table
 * needs to be sorted by .keyword and any longer string like "device"
 * must appear before a substring like "dev".
 */
static cinfo_t conftab[] = {
	"S3-support",		S3sup,   &pm_status,	NULL,	2, 0, 1,
	"autoS3",		autoS3,  &pm_status,	NULL,	2, 0, 1,
	"autopm",		autopm,  &pm_status,	NULL,	2, 0, 1,
	"autoshutdown",		autosd,  &cpr_status,	as_cmt,	5, 0, 1,
	"cpu-threshold",	cputhr,  &pm_status,	NULL,	2, 0, 1,
	"cpu_deep_idle",	cpuidle, &pm_status,	NULL,	2, 0, 1,
	"cpupm",		cpupm,   &pm_status,	NULL,	2, 1, 1,
	"device-dependency-property",
				ddprop,  &pm_status,	NULL,	3, 1, 1,
	"device-dependency",	devdep,  &pm_status,	NULL,	3, 1, 1,
	"device-thresholds",	devthr,  &pm_status,	NULL,	3, 1, 1,
	"diskreads",		dreads,  &cpr_status,	NULL,	2, 0, 1,
	"idlecheck",		idlechk, &cpr_status,	NULL,	2, 0, 0,
	"loadaverage",		loadavg, &cpr_status,	NULL,	2, 0, 1,
	"nfsreqs",		nfsreq,  &cpr_status,	NULL,	2, 0, 1,
#ifdef  sparc
	"statefile",		sfpath,  &cpr_status,	sf_cmt,	2, 0, 0,
#endif
	"system-threshold",	systhr,  &pm_status,	NULL,	2, 0, 1,
	"ttychars",		tchars,  &cpr_status,	NULL,	2, 0, 1,
	NULL,			NULL,	 NULL,		NULL,	0, 0, 0,
};


/*
 * Set cpr/pm permission from default file info.
 */
static void
set_perm(char *defstr, char *user, int *perm, int cons)
{
	char *dinfo, *tk;

	/*
	 * /etc/default/power entries are:
	 *	all			(all users + root)
	 *	-			(none + root)
	 *	<user1[, user2...>	(list users + root)
	 *	console-owner		(console onwer + root)
	 * Any error in reading/parsing the file limits the
	 * access requirement to root.
	 */
	dinfo = defread(defstr);
	mesg(MDEBUG, "set_perm: \"%s\", value \"%s\"\n",
	    defstr, dinfo ? dinfo : "NULL");
	if (dinfo == NULL)
		return;
	else if (strcmp(dinfo, "all") == 0)
		*perm = 1;
	else if (strcmp(dinfo, "console-owner") == 0)
		*perm = cons;
	else if (user != NULL &&
	    (*dinfo == '<') && (tk = strrchr(++dinfo, '>'))) {
		/* Scan dinfo for a matching user. */
		for (*tk = '\0'; (tk = strtok(dinfo, ", ")) != NULL;
		    dinfo = NULL) {
			mesg(MDEBUG, "match_user: cmp (\"%s\", \"%s\")\n",
			    tk, user);
			if (strcmp(tk, user) == 0) {
				*perm = 1;
				break;
			}
		}
	}
}


/*
 * Lookup cpr/pm user permissions in "/etc/default/power".
 */
void
lookup_perms(void)
{
	struct passwd *pent;
	struct stat stbuf;
	int cons_perm;
	char *user;

	if ((ruid = getuid()) == 0) {
		cpr_status.perm = pm_status.perm = 1;
		return;
	} else if ((pent = getpwuid(ruid)) != NULL) {
		user = pent->pw_name;
	} else {
		user = NULL;
	}

	if (defopen("/etc/default/power") == -1)
		return;
	if (stat("/dev/console", &stbuf) == -1)
		cons_perm = 0;
	else
		cons_perm = (ruid == stbuf.st_uid);

	set_perm("PMCHANGEPERM=", user, &pm_status.perm, cons_perm);
	set_perm("CPRCHANGEPERM=", user, &cpr_status.perm, cons_perm);

	(void) defopen(NULL);
}


#ifdef sparc
/*
 * Lookup energystar-v[23] property and set estar_vers.
 */
void
lookup_estar_vers(void)
{
	char es_prop[] = "energystar-v?", *fmt = "%s init/access error\n";
	di_prom_handle_t ph;
	di_node_t node;
	uchar_t *prop_data;
	int last;
	char ch;

	if ((node = di_init("/", DINFOPROP)) == DI_NODE_NIL) {
		mesg(MERR, fmt, "di_init");
		return;
	} else if ((ph = di_prom_init()) == DI_PROM_HANDLE_NIL) {
		mesg(MERR, fmt, "di_prom_init");
		di_fini(node);
		return;
	}
	last = strlen(es_prop) - 1;
	for (ch = ESTAR_V2; ch <= ESTAR_V3; ch++) {
		es_prop[last] = ch;
		if (di_prom_prop_lookup_bytes(ph, node,
		    es_prop, &prop_data) == 0) {
			mesg(MDEBUG, "get_estar_vers: %s prop found\n",
			    es_prop);
			estar_vers = ch;
			break;
		}
	}
	di_prom_fini(ph);
	di_fini(node);
}
#endif /* sparc */


/*
 * limit open() to the real user
 */
static int
pmc_open(char *name, int oflag)
{
	uid_t euid;
	int fd;

	euid = geteuid();
	if (seteuid(ruid) == -1)
		mesg(MEXIT, "cannot reset euid to %d, %s\n",
		    ruid, strerror(errno));
	fd = open(name, oflag);
	(void) seteuid(euid);
	return (fd);
}


/*
 * Alloc space and read a config file; caller needs to free the space.
 */
static char *
get_conf_data(char *name)
{
	struct stat stbuf;
	ssize_t nread;
	size_t size;
	char *buf;
	int fd;

	if ((fd = pmc_open(name, O_RDONLY)) == -1)
		mesg(MEXIT, "cannot open %s\n", name);
	else if (fstat(fd, &stbuf) == -1)
		mesg(MEXIT, "cannot stat %s\n", name);
	size = (size_t)stbuf.st_size;
	def_src = (stbuf.st_ino == def_info.st_ino &&
	    stbuf.st_dev == def_info.st_dev);
	if ((buf = malloc(size + 1)) == NULL)
		mesg(MEXIT, "cannot allocate %u for \"%s\"\n", size + 1, name);
	nread = read(fd, buf, size);
	(void) close(fd);
	if (nread != (ssize_t)size)
		mesg(MEXIT, "read error, expect %u, got %d, file \"%s\"\n",
		    size, nread, name);
	*(buf + size) = '\0';
	return (buf);
}


/*
 * Add an arg to line_args, adding space if needed.
 */
static void
newarg(char *arg, int index)
{
	static int alcnt;
	size_t size;

	if ((index + 1) > alcnt) {
		alcnt += 4;
		size = alcnt * sizeof (*line_args);
		if ((line_args = realloc(line_args, size)) == NULL)
			mesg(MEXIT, "cannot alloc %u for line args\n", size);
	}
	*(line_args + index) = arg;
}


/*
 * Convert blank-delimited words into an arg vector and return
 * the arg count; character strings get null-terminated in place.
 */
static int
build_args(char *cline, char *tail)
{
	extern int debug;
	char **vec, *arg, *cp;
	int cnt = 0;

	/*
	 * Search logic: look for "\\\n" as a continuation marker,
	 * treat any other "\\*" as ordinary arg data, scan until a
	 * white-space delimiter is found, and if the arg has length,
	 * null-terminate and save arg to line_args.  The scan includes
	 * tail so the last arg is found without any special-case code.
	 */
	for (arg = cp = cline; cp <= tail; cp++) {
		if (*cp == '\\') {
			if (*(cp + 1) && *(cp + 1) != '\n') {
				cp++;
				continue;
			}
		} else if (strchr(" \t\n", *cp) == NULL)
			continue;
		if (cp - arg) {
			*cp = '\0';
			newarg(arg, cnt++);
		}
		arg = cp + 1;
	}
	newarg(NULL, cnt);

	if (debug) {
		mesg(MDEBUG, "\nline %d, found %d args:\n", lineno, cnt);
		for (vec = line_args; *vec; vec++)
			mesg(MDEBUG, "    \"%s\"\n", *vec);
	}

	return (cnt);
}


/*
 * Match leading keyword from a conf line and
 * return a reference to a config info struct.
 */
static cinfo_t *
get_cinfo(void)
{
	cinfo_t *cip, *info = NULL;
	char *keyword;
	int chr_diff;

	/*
	 * Scan the config table for a matching keyword; since the table
	 * is sorted by keyword strings, a few optimizations can be done:
	 * first compare only the first byte of the keyword, skip any
	 * table string that starts with a lower ASCII value, compare the
	 * full string only when the first byte matches, and stop checking
	 * if the table string starts with a higher ASCII value.
	 */
	keyword = LINEARG(0);
	for (cip = conftab; cip->keyword; cip++) {
		chr_diff = (int)(*cip->keyword - *keyword);
#if 0
		mesg(MDEBUG, "line %d, ('%c' - '%c') = %d\n",
		    lineno, *cip->keyword, *line, chr_diff);
#endif
		if (chr_diff < 0)
			continue;
		else if (chr_diff == 0) {
			if (strcmp(keyword, cip->keyword) == 0) {
				info = cip;
				break;
			}
		} else
			break;
	}
	return (info);
}


/*
 * Find the end of a [possibly continued] conf line
 * and record the real/lf-delimited line count at *lcnt.
 */
static char *
find_line_end(char *line, int *lcnt)
{
	char *next, *lf;

	*lcnt = 0;
	next = line;
	while ((lf = strchr(next, '\n')) != NULL) {
		(*lcnt)++;
		if (lf == line || (*(lf - 1) != '\\') || *(lf + 1) == '\0')
			break;
		next = lf + 1;
	}
	return (lf);
}


/*
 * Parse the named conf file and for each conf line
 * call the action routine or conftab handler routine.
 */
void
parse_conf_file(char *name, vact_t action, boolean_t first_parse)
{
	char *file_buf, *cline, *line, *lend;
	cinfo_t *cip;
	int linc, cnt;
	size_t llen;
	int dontcare;

	/*
	 * Do the "implied default" for autoS3, but only before we
	 * start parsing the first conf file.
	 */
	if (first_parse) {
		(void) S3_helper("S3-support-enable", "S3-support-disable",
		    PM_ENABLE_S3, PM_DISABLE_S3, "S3-support", "default",
		    &dontcare, -1);
	}

	file_buf = get_conf_data(name);
	mesg(MDEBUG, "\nnow parsing \"%s\"...\n", name);

	lineno = 1;
	line = file_buf;
	while ((lend = find_line_end(line, &linc)) != NULL) {
		/*
		 * Each line should start with valid data
		 * but leading white-space can be ignored
		 */
		while (line < lend) {
			if (*line != ' ' && *line != '\t')
				break;
			line++;
		}

		/*
		 * Copy line into allocated space and null-terminate
		 * without the trailing line-feed.
		 */
		if ((llen = (lend - line)) != 0) {
			if ((cline = malloc(llen + 1)) == NULL)
				mesg(MEXIT, "cannot alloc %u bytes "
				    "for line copy\n", llen);
			(void) memcpy(cline, line, llen);
			*(cline + llen) = '\0';
		} else
			cline = NULL;

		/*
		 * For blank and comment lines: possibly show a debug
		 * message and otherwise ignore them.  For other lines:
		 * parse into an arg vector and try to match the first
		 * arg with conftab keywords.  When a match is found,
		 * check for exact or minimum arg count, and call the
		 * action or handler routine; if handler does not return
		 * OKUP, set the referenced update value to NOUP so that
		 * later CPR or PM updates are skipped.
		 */
		if (llen == 0)
			mesg(MDEBUG, "\nline %d, blank...\n", lineno);
		else if (*line == '#')
			mesg(MDEBUG, "\nline %d, comment...\n", lineno);
		else if ((cnt = build_args(cline, cline + llen)) != 0) {
			if ((cip = get_cinfo()) == NULL) {
				mesg(MEXIT, "unrecognized keyword \"%s\"\n",
				    LINEARG(0));
			} else if (cnt != cip->argc &&
			    (cip->any == 0 || cnt < cip->argc)) {
				mesg(MEXIT, "found %d args, expect %d%s\n",
				    cnt, cip->argc, cip->any ? "+" : "");
			} else if (action)
				(*action)(line, llen + 1, cip);
			else if (cip->status->perm && (def_src || cip->alt)) {
				if ((*cip->handler)() != OKUP)
					cip->status->update = NOUP;
			} else {
				mesg(MDEBUG,
				    "==> handler skipped: %s_perm %d, "
				    "def_src %d, alt %d\n", cip->status->set,
				    cip->status->perm, def_src, cip->alt);
			}
		}

		if (cline)
			free(cline);
		line = lend + 1;
		lineno += linc;
	}
	lineno = 0;

	free(file_buf);

	if (verify) {
		int ret = ioctl(pm_fd, PM_GET_PM_STATE, NULL);
		if (ret < 0) {
			mesg(MDEBUG, "Cannot get PM state: %s\n",
			    strerror(errno));
		}
		switch (ret) {
		case PM_SYSTEM_PM_ENABLED:
			mesg(MDEBUG, "Autopm Enabled\n");
			break;
		case PM_SYSTEM_PM_DISABLED:
			mesg(MDEBUG, "Autopm Disabled\n");
			break;
		}
		ret = ioctl(pm_fd, PM_GET_S3_SUPPORT_STATE, NULL);
		if (ret < 0) {
			mesg(MDEBUG, "Cannot get PM state: %s\n",
			    strerror(errno));
		}
		switch (ret) {
		case PM_S3_SUPPORT_ENABLED:
			mesg(MDEBUG, "S3 support Enabled\n");
			break;
		case PM_S3_SUPPORT_DISABLED:
			mesg(MDEBUG, "S3 support Disabled\n");
			break;
		}
		ret = ioctl(pm_fd, PM_GET_AUTOS3_STATE, NULL);
		if (ret < 0) {
			mesg(MDEBUG, "Cannot get PM state: %s\n",
			    strerror(errno));
		}
		switch (ret) {
		case PM_AUTOS3_ENABLED:
			mesg(MDEBUG, "AutoS3 Enabled\n");
			break;
		case PM_AUTOS3_DISABLED:
			mesg(MDEBUG, "AutoS3  Disabled\n");
			break;
		}
	}
}
