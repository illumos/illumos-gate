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

/*
 * "pmconfig" performs a mixture of Energy-Star configuration tasks
 * for both CheckPoint-Resume and Power-Management services.
 * Tasks include parsing a config file (usually "/etc/power.conf"),
 * updating CPR and PM config files, and setting various PM options
 * via ioctl requests.  From the mix, pmconfig should have a more
 * generalized name similar to "estarconfig".
 *
 * OPTIONS:
 * "-r"		reset CPR and PM options to default and exit.
 * "-f file"	specify an alternate config file; this is a
 *		private/non-advertised option used by "dtpower".
 */

#include "pmconfig.h"
#include <sys/wait.h>
#include <signal.h>
#include <stdarg.h>
#include <locale.h>
#include "powerd.h"


#define	MCCPY_FIELD(dst, src, field) \
	(void) memccpy(&dst.field, &src.field, 0, sizeof (dst.field) - 1)


static char conf_header[] =
"#\n"
"# Copyright 1996-2002 Sun Microsystems, Inc.  All rights reserved.\n"
"# Use is subject to license terms.\n"
"#\n"
"#pragma ident	\"@(#)power.conf	2.1	02/03/04 SMI\"\n"
"#\n"
"# Power Management Configuration File\n"
"#\n\n";

static char *prog;
static char *cpr_conf = CPR_CONFIG;
static char tmp_conf[] = "/etc/.tmp.conf.XXXXXX";
static char orig_conf[] = "/etc/power.conf-Orig";
static char default_conf[] = "/etc/power.conf";
static char *power_conf = default_conf;
static pid_t powerd_pid;
static prmup_t *checkup;
static int tmp_fd;

char estar_vers = ESTAR_VNONE;
int ua_err = 0;
int debug = 0;

static struct cprconfig disk_cc;
struct cprconfig new_cc;
struct stat def_info;
static int fflag, rflag;
int pm_fd;
uid_t ruid;
int def_src;
/*
 * Until we get more graphics driver support, we only enable autopm,
 * S3 support and autoS3 by default on X86 systems that are on our whitelist.
 */
int whitelist_only = 1;

int verify = 0;


static void
cleanup(void)
{
	free(line_args);
	if (access(tmp_conf, F_OK) == 0)
		(void) unlink(tmp_conf);
}


/*
 * Multi-purpose message output routine; also exits when
 * (status == MEXIT), other status is non-fatal.
 * VARARGS2
 */
void
mesg(int code, char *fmt, ...)
{
	va_list vargs;

	/*
	 * debug is checked once here, avoiding N duplicate checks
	 * before each MDEBUG caller and unnecessary text dupduplication.
	 */
	if (debug == 0) {
		/*
		 * If debug is not enabled, skip a debug message;
		 * lead with the program name for an error message,
		 * and follow with a filename and line number if an
		 * error occurs while parsing a conf file.
		 */
		if (code == MDEBUG)
			return;
		fprintf(stderr, "%s: ", prog);
		if (lineno)
			fprintf(stderr, "\"%s\" line %d, ", power_conf, lineno);
	}

	va_start(vargs, fmt);
	(void) vfprintf(stderr, gettext(fmt), vargs);
	va_end(vargs);

	if (code == MEXIT) {
		cleanup();
		exit(MEXIT);
	}
}


static void
usage(void)
{
	(void) fprintf(stderr, gettext("Usage: %s [-r]\n"), prog);
	exit(1);
}


/*
 * Lookup estar version, check if uadmin() service is supported,
 * and read cpr_config info from disk.
 */
static void
get_cpr_info(void)
{
	ssize_t nread;
	char *err_fmt;
	int fd;

#ifdef sparc
	lookup_estar_vers();
	if (estar_vers == ESTAR_V2)
		new_cc.is_cpr_default = 1;
	else if (estar_vers == ESTAR_V3)
		new_cc.is_autopm_default = 1;

	if (uadmin(A_FREEZE, AD_CHECK, 0) == 0)
		new_cc.is_cpr_capable = 1;
	else
		ua_err = errno;

	if ((fd = open("/dev/tod", O_RDONLY)) != -1) {
		new_cc.is_autowakeup_capable = 1;
		(void) close(fd);
	}
#endif /* sparc */

	/*
	 * Read in the cpr conf file.  If any open or read error occurs,
	 * display an error message only for a non-root user.  The file
	 * may not exist on a newly installed system.
	 */
	err_fmt = "%s %s; please rerun %s as root\n";
	if ((fd = open(cpr_conf, O_RDONLY)) == -1) {
		if (ruid)
			mesg(MEXIT, err_fmt, gettext("cannot open"),
			    cpr_conf, prog);
	} else {
		nread = read(fd, &disk_cc, sizeof (disk_cc));
		(void) close(fd);
		if (nread != (ssize_t)sizeof (disk_cc)) {
			if (ruid)
				mesg(MEXIT, err_fmt, cpr_conf,
				    gettext("file corrupted"), prog);
			else {
				(void) unlink(cpr_conf);
				bzero(&disk_cc, sizeof (disk_cc));
			}
		}
	}
}


/*
 * Unconfigure and reset PM, device is left open for later use.
 */
static void
pm_rem_reset(void)
{
	char *err_fmt = NULL;

	if ((pm_fd = open("/dev/pm", O_RDWR)) == -1)
		err_fmt = "cannot open \"/dev/pm\": %s\n";
	else if (ioctl(pm_fd, PM_RESET_PM, 0) == -1)
		err_fmt = "cannot reset pm state: %s\n";
	if (err_fmt)
		mesg(MEXIT, err_fmt, strerror(errno));
}


static void
get_powerd_pid(void)
{
	char pidstr[16];
	int fd;

	if ((fd = open(PIDPATH, O_RDONLY)) == -1)
		return;
	bzero(pidstr, sizeof (pidstr));
	if (read(fd, pidstr, sizeof (pidstr)) > 0) {
		powerd_pid = atoi(pidstr);
		mesg(MDEBUG, "got powerd pid %ld\n", powerd_pid);
	}
	(void) close(fd);
}


/*
 * Write revised cprconfig struct to disk based on perms;
 * returns 1 if any error, otherwise 0.
 */
static int
update_cprconfig(void)
{
	struct cprconfig *wrt_cc = &new_cc;
	char *err_fmt = NULL;
	int fd;

	if (rflag) {
		/* For "pmconfig -r" case, copy select cpr-related fields. */
		new_cc.cf_magic = disk_cc.cf_magic;
		new_cc.cf_type = disk_cc.cf_type;
		MCCPY_FIELD(new_cc, disk_cc, cf_path);
		MCCPY_FIELD(new_cc, disk_cc, cf_fs);
		MCCPY_FIELD(new_cc, disk_cc, cf_devfs);
		MCCPY_FIELD(new_cc, disk_cc, cf_dev_prom);
	}

	if (!pm_status.perm) {
		if (cpr_status.update == NOUP)
			return (1);
		/* save new struct data with old autopm setting */
		MCCPY_FIELD(new_cc, disk_cc, apm_behavior);
	} else if (!cpr_status.perm) {
		if (pm_status.update == NOUP)
			return (1);
		/* save original struct with new autopm setting */
		MCCPY_FIELD(disk_cc, new_cc, apm_behavior);
		wrt_cc = &disk_cc;
	} else if (cpr_status.update == NOUP || pm_status.update == NOUP)
		return (1);

	if ((fd = open(cpr_conf, O_CREAT | O_TRUNC | O_WRONLY, 0644)) == -1)
		err_fmt = "cannot open/create \"%s\", %s\n";
	else if (write(fd, wrt_cc, sizeof (*wrt_cc)) != sizeof (*wrt_cc))
		err_fmt = "error writing \"%s\", %s\n";
	(void) close(fd);
	if (err_fmt)
		mesg(MERR, err_fmt, cpr_conf, strerror(errno));
	return (err_fmt != NULL);
}


/*
 * Signal old powerd when there's a valid pid, or start a new one;
 * returns 1 if any error, otherwise 0.
 */
static int
restart_powerd(void)
{
	char *powerd = "/usr/lib/power/powerd";
	int status = 0;
	pid_t pid, wp;

	if (powerd_pid > 0) {
		if (sigsend(P_PID, powerd_pid, SIGHUP) == 0)
			return (0);
		else if (errno != ESRCH) {
			mesg(MERR, "cannot deliver hangup to powerd\n");
			return (1);
		}
	}

	if ((pid = fork()) == NOPID)
		wp = -1;
	else if (pid == P_MYPID) {
		(void) setreuid(0, 0);
		(void) setregid(0, 0);
		(void) setgroups(0, NULL);
		if (debug)
			(void) execle(powerd, powerd, "-d", NULL, NULL);
		else
			(void) execle(powerd, powerd, NULL, NULL);
		exit(1);
	} else {
		do {
			wp = waitpid(pid, &status, 0);
		} while (wp == -1 && errno == EINTR);
	}

	if (wp == -1)
		mesg(MERR, "could not start %s\n", powerd);
	return (wp == -1 || status != 0);
}


static void
save_orig(void)
{
	static char *args[] = { "/usr/bin/cp", default_conf, orig_conf, NULL };
	struct stat stbuf;
	int pid;

	if (stat(orig_conf, &stbuf) == 0 && stbuf.st_size)
		return;
	pid = fork();
	if (pid == NOPID)
		return;
	else if (pid == P_MYPID) {
		(void) execve(args[0], args, NULL);
		exit(1);
	} else
		(void) waitpid(pid, NULL, 0);
}


static void
tmp_write(void *buf, size_t len)
{
	if (write(tmp_fd, buf, len) != (ssize_t)len)
		mesg(MEXIT, "error writing tmp file, %s\n", strerror(errno));
}


static void
tmp_save_line(char *line, size_t len, cinfo_t *cip)
{
	if (cip && cip->cmt)
		tmp_write(cip->cmt, strlen(cip->cmt));
	tmp_write(line, len);
}


/*
 * Filter conf lines and write them to the tmp file.
 */
static void
filter(char *line, size_t len, cinfo_t *cip)
{
	int selected;

	/*
	 * Lines from an alt conf file are selected when either:
	 * cip is NULL (keyword not matched, probably an old-style device),
	 * OR: it's both OK to accept the conf line (alt) AND either:
	 * preference is not set (NULL checkup) OR the cpr/pm preference
	 * (checkup) matches conftab status.
	 */
	selected = (cip == NULL || (cip->alt &&
	    (checkup == NULL || checkup == cip->status)));
	mesg(MDEBUG, "filter: set \"%s\", selected %d\n",
	    cip ? cip->status->set : "none", selected);
	if (selected)
		tmp_save_line(line, len, cip);
}


/*
 * Set checkup for conf line selection and parse a conf file with filtering.
 * When pref is NULL, filter selects all conf lines from the new conf file;
 * otherwise filter selects only cpr or pm related lines from the new or
 * default conf file based on cpr or pm perm.
 */
static void
conf_scanner(prmup_t *pref)
{
	mesg(MDEBUG, "\nscanning set is %s\n", pref ? pref->set : "both");
	checkup = pref;
	parse_conf_file((pref == NULL || pref->perm)
	    ? power_conf : default_conf, filter);
}


/*
 * Search for any non-alt entries, call the handler routine,
 * and write entries to the tmp file.
 */
static void
search(char *line, size_t len, cinfo_t *cip)
{
	int skip;

	skip = (cip == NULL || cip->alt);
	mesg(MDEBUG, "search: %s\n", skip ? "skipped" : "retained");
	if (skip)
		return;
	if (cip->status->perm)
		(void) (*cip->handler)();
	tmp_save_line(line, len, cip);
}


/*
 * When perm and update status are OK, write a new conf file
 * and rename to default_conf with the original attributes;
 * returns 1 if any error, otherwise 0.
 */
static int
write_conf(void)
{
	char *name, *err_str = NULL;
	struct stat stbuf;

	if ((cpr_status.perm && cpr_status.update != OKUP) ||
	    (pm_status.perm && pm_status.update != OKUP)) {
		mesg(MDEBUG, "\nconf not written, "
		    "(cpr perm %d update %d), (pm perm %d update %d)\n",
		    cpr_status.perm, cpr_status.update,
		    pm_status.perm, pm_status.update);
		return (1);
	}

	save_orig();
	if ((tmp_fd = mkstemp(tmp_conf)) == -1) {
		mesg(MERR, "cannot open/create tmp file \"%s\"\n", tmp_conf);
		return (1);
	}
	tmp_write(conf_header, sizeof (conf_header) - 1);

	/*
	 * When both perms are set, save selected lines from the new file;
	 * otherwise save selected subsets from the new and default files.
	 */
	if (cpr_status.perm && pm_status.perm)
		conf_scanner(NULL);
	else {
		conf_scanner(&cpr_status);
		conf_scanner(&pm_status);
	}

	/*
	 * "dtpower" will craft an alt conf file with modified content from
	 * /etc/power.conf, but any alt conf file is not a trusted source;
	 * since some alt conf lines may be skipped, the trusted source is
	 * searched for those lines to retain their functionality.
	 */
	parse_conf_file(default_conf, search);

	(void) close(tmp_fd);

	if (stat(name = default_conf, &stbuf) == -1)
		err_str = "stat";
	else if (chmod(name = tmp_conf, stbuf.st_mode) == -1)
		err_str = "chmod";
	else if (chown(tmp_conf, stbuf.st_uid, stbuf.st_gid) == -1)
		err_str = "chown";
	else if (rename(tmp_conf, default_conf) == -1)
		err_str = "rename";
	else
		mesg(MDEBUG, "\n\"%s\" renamed to \"%s\"\n",
		    tmp_conf, default_conf);
	if (err_str)
		mesg(MERR, "cannot %s \"%s\", %s\n",
		    err_str, name, strerror(errno));

	return (err_str != NULL);
}


/* ARGSUSED */
int
main(int cnt, char **vec)
{
	int rval = 0;

	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);

	for (prog = *vec++; *vec && **vec == '-'; vec++) {
		if (strlen(*vec) > 2)
			usage();
		switch (*(*vec + 1)) {
		case 'd':
			debug = 1;
			break;
		case 'f':
			fflag = 1;
			if ((power_conf = *++vec) == NULL)
				usage();
			break;
		case 'r':
			rflag = 1;
			break;
		case 'W':
			whitelist_only = 0;
			break;
		case 'v':
			verify = 1;
			break;
		default:
			usage();
			break;
		}
	}
	if (rflag && fflag)
		usage();

	lookup_perms();
	mesg(MDEBUG, "ruid %d, perms: cpr %d, pm %d\n",
	    ruid, cpr_status.perm, pm_status.perm);

	if ((!cpr_status.perm && !pm_status.perm) ||
	    (rflag && !(cpr_status.perm && pm_status.perm)))
		mesg(MEXIT, "%s\n", strerror(EACCES));
	if (rflag == 0 && access(power_conf, R_OK))
		mesg(MEXIT, "\"%s\" is not readable\n", power_conf);

	get_cpr_info();

	if (pm_status.perm)
		pm_rem_reset();
	get_powerd_pid();
	(void) umask(022);
	if (rflag)
		return (update_cprconfig() || restart_powerd());
	if (stat(default_conf, &def_info) == -1)
		mesg(MEXIT, "cannot stat %s, %s\n", default_conf,
		    strerror(errno));
	new_cc.loadaverage_thold = DFLT_THOLD;
	parse_conf_file(power_conf, NULL);
	if (pm_status.perm)
		(void) close(pm_fd);
	if (fflag)
		rval = write_conf();
	cleanup();
	if (rval == 0)
		rval = (update_cprconfig() || restart_powerd());

	return (rval);
}
