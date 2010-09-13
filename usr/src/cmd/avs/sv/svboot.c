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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mkdev.h>
#include <sys/param.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdlib.h>
#include <strings.h>
#include <errno.h>
#include <stdio.h>
#include <locale.h>
#include <unistd.h>
#include <libgen.h>
#include <nsctl.h>

#include <sys/unistat/spcs_s.h>
#include <sys/unistat/spcs_s_u.h>
#include <sys/unistat/spcs_errors.h>

#include <sys/nsctl/sv.h>
#include <sys/nsctl/sv_impl.h>

#include <sys/nsctl/cfg.h>


static int sv_max_devices;


/*
 * Pathnames.
 */

static const caddr_t sv_rpath = SV_DEVICE;

/*
 * Functions.
 */

static void resume_dev(int, sv_name_t *);
static void suspend_dev(int, const caddr_t);
static int read_libcfg(sv_name_t svn[]);
static void resume_sv();
static void suspend_sv();
static void prepare_unload_sv();


/*
 * support for the special cluster tag "local" to be used with -C in a
 * cluster for local volumes.
 */

#define	SV_LOCAL_TAG	"local"

static caddr_t program;
static caddr_t cfg_cluster_tag;


static void
usage(void)
{
	(void) fprintf(stderr, gettext("usage:\n"));

	(void) fprintf(stderr, gettext(
	    "\t%s -h                     help\n"), program);

	(void) fprintf(stderr, gettext(
	    "\t%s [-C tag] -r            resume all sv devices\n"), program);

	(void) fprintf(stderr, gettext(
	    "\t%s [-C tag] -s            suspend all sv devices\n"), program);

	(void) fprintf(stderr, gettext(
	    "\t%s -u                     prepare for sv unload\n"), program);
}


static void
message(caddr_t prefix, spcs_s_info_t *status, caddr_t string, va_list ap)
{
	(void) fprintf(stderr, "%s: %s: ", program, prefix);
	(void) vfprintf(stderr, string, ap);
	(void) fprintf(stderr, "\n");

	if (status) {
		spcs_s_report(*status, stderr);
		spcs_s_ufree(status);
	}
}


static void
error(spcs_s_info_t *status, caddr_t string, ...)
{
	va_list ap;
	va_start(ap, string);

	message(gettext("error"), status, string, ap);

	va_end(ap);
	exit(1);
}


static void
warn(spcs_s_info_t *status, caddr_t string, ...)
{
	va_list ap;
	va_start(ap, string);

	message(gettext("warning"), status, string, ap);

	va_end(ap);
}


static void
sv_get_maxdevs(void)
{
	sv_name_t svn[1];
	sv_list_t svl;
	int fd;

	if (sv_max_devices > 0)
		return;

	fd = open(sv_rpath, O_RDONLY);
	if (fd < 0)
		error(NULL, gettext("unable to open %s: %s"),
			sv_rpath, strerror(errno));

	bzero(&svl, sizeof (svl));
	bzero(&svn[0], sizeof (svn));

	svl.svl_names = &svn[0];
	svl.svl_error = spcs_s_ucreate();

	if (ioctl(fd, SVIOC_LIST, &svl) < 0)
		error(&svl.svl_error, gettext("unable to get max devs"));

	spcs_s_ufree(&svl.svl_error);
	sv_max_devices = svl.svl_maxdevs;

	(void) close(fd);
}


static sv_name_t *
sv_alloc_svnames(void)
{
	sv_name_t *svn = NULL;

	sv_get_maxdevs();

	svn = calloc(sv_max_devices, sizeof (*svn));
	if (svn == NULL) {
		error(NULL, "unable to allocate %ld bytes of memory",
		    sv_max_devices * sizeof (*svn));
	}

	return (svn);
}

int
main(int argc, char *argv[])
{
	extern int optind;
	extern char *optarg;
	int Cflag, resume, suspend, unload;
	int opt;

	(void) setlocale(LC_ALL, "");
	(void) textdomain("svboot");

	program = strdup(basename(argv[0]));

	Cflag = unload = resume = suspend = 0;

	while ((opt = getopt(argc, argv, "C:hrsu")) != EOF) {
		switch (opt) {

		case 'C':
			if (Cflag) {
				warn(NULL,
				    gettext("-C specified multiple times"));
				usage();
				exit(2);
				/* NOTREACHED */
			}

			Cflag++;
			cfg_cluster_tag = optarg;
			break;

		case 'r':
			resume++;
			break;

		case 's':
			suspend++;
			break;

		case 'u':
			unload++;
			break;

		case 'h':
			usage();
			exit(0);

		case '?':	/* FALLTHRU */

		default:
			usage();
			exit(2);
			/* NOTREACHED */
		}
	}


	/*
	 * Usage checks
	 */

	if ((resume + suspend + unload) > 1) {
		warn(NULL, gettext("-r , -s and -u are mutually exclusive"));
		usage();
		exit(2);
	}

	if (!resume && !suspend && !unload) {
		warn(NULL, gettext("option required"));
		usage();
		exit(2);
	}

	if (optind != argc) {
		usage();
		exit(2);
	}


	/*
	 * Check for the special (local) cluster tag
	 */

	if (cfg_cluster_tag != NULL &&
	    strcmp(cfg_cluster_tag, SV_LOCAL_TAG) == 0)
		cfg_cluster_tag = "-";

	/*
	 * Process commands
	 */

	if (resume)
		resume_sv();
	else if (suspend)
		suspend_sv();
	else if (unload)
		prepare_unload_sv();

	return (0);
}


static void
resume_sv()
{
	int index;
	sv_name_t *svn;
	int cnt;
	int fd;

	svn = sv_alloc_svnames();

	index = read_libcfg(svn);

	fd = open(sv_rpath, O_RDONLY);
	if (fd < 0) {
		warn(NULL, gettext("unable to open %s: %s"),
			svn->svn_path, strerror(errno));
		return;
	}

	for (cnt = 0; cnt < index; cnt++) {

		/*
		 * Check for more data.
		 */
		if (svn[cnt].svn_path[0] == '\0') {
			/*
			 * This was set when reading sv.conf.  After the last
			 * line svn_path was set to \0, so we are finished.
			 * We shouldn't get here, but put this in just in
			 * case.
			 */
			break;
		}
		resume_dev(fd, &svn[cnt]);
	}
	(void) close(fd);
}


static void
resume_dev(int fd, sv_name_t *svn)
{
	struct stat stb;
	sv_conf_t svc;

	bzero(&svc, sizeof (svc));

	if (stat(svn->svn_path, &stb) != 0) {
		warn(NULL, gettext("unable to access %s: %s"),
			svn->svn_path, strerror(errno));
		return;
	}

	svc.svc_major = major(stb.st_rdev);
	svc.svc_minor = minor(stb.st_rdev);
	(void) strncpy(svc.svc_path, svn->svn_path, sizeof (svc.svc_path));

	svc.svc_flag = svn->svn_mode;
	svc.svc_error = spcs_s_ucreate();

	if (ioctl(fd, SVIOC_ENABLE, &svc) < 0) {
		spcs_log("sv", &svc.svc_error,
		    gettext("%s: unable to resume %s"),
		    program, svn->svn_path);

		warn(&svc.svc_error, gettext("unable to resume %s"),
			svn->svn_path);
		return;
	}

	spcs_log("sv", NULL, gettext("%s: resume %s"),
	    program, svn->svn_path);

	spcs_s_ufree(&svc.svc_error);
}


/*
 * This routine parses the config file and
 * stores the data in the svn array.  The return value is the number
 * of entries read from conf_file.  If an error occurs the error()
 * routine is called (which exits the program).
 */
static int
read_libcfg(sv_name_t svn[])
{
	char rdev[CFG_MAX_BUF];
	char key[CFG_MAX_KEY];
	struct stat stb;
	int i;
	int setnumber;
	int index = 0;		/* Current location in svn array	*/
	sv_name_t *cur_svn;	/* Pointer to svn[index]		*/
	CFGFILE *cfg;

	if ((cfg = cfg_open("")) == NULL) {
		error(NULL, gettext("Error opening config: %s"),
		    strerror(errno));
	}

	cfg_resource(cfg, cfg_cluster_tag);
	if (!cfg_lock(cfg, CFG_RDLOCK)) {
		error(NULL, gettext("Error locking config: %s"),
		    strerror(errno));
	}

	for (i = 0; /*CSTYLED*/; i++) {
		setnumber = i + 1;

		bzero(rdev, CFG_MAX_BUF);
		(void) snprintf(key, sizeof (key), "sv.set%d.vol", setnumber);
		if (cfg_get_cstring(cfg, key, rdev, sizeof (rdev)) < 0)
			break;

		/* Check to see if the raw device is present */
		if (stat(rdev, &stb) != 0) {
			warn(NULL, gettext("unable to access %s: %s"),
			    rdev, strerror(errno));
			continue;
		}

		if (!S_ISCHR(stb.st_mode)) {
			warn(NULL, gettext("%s is not a character device"),
			    rdev);
			continue;
		}

		cur_svn = &svn[index];  /* For easier reading below */

		if (strlen(rdev) >= sizeof (cur_svn->svn_path)) {
			warn(NULL, gettext(
			    "raw device name (%s) longer than %d characters"),
			    rdev,
			    (sizeof (cur_svn->svn_path) - 1));
			continue;
		}

		(void) strcpy(cur_svn->svn_path, rdev);
		cur_svn->svn_mode = (NSC_DEVICE | NSC_CACHE);

		index++;
	}

	cfg_close(cfg);

	/* Set the last path to NULL */
	svn[index].svn_path[0] = '\0';

	return (index);
}


static void
suspend_dev(int fd, const caddr_t path)
{
	struct stat stb;
	sv_conf_t svc;

	if (stat(path, &stb) < 0) {
		svc.svc_major = (major_t)-1;
		svc.svc_minor = (minor_t)-1;
	} else {
		svc.svc_major = major(stb.st_rdev);
		svc.svc_minor = minor(stb.st_rdev);
	}

	(void) strcpy(svc.svc_path, path);
	svc.svc_error = spcs_s_ucreate();

	if (ioctl(fd, SVIOC_DISABLE, &svc) < 0) {
		if (errno != SV_EDISABLED) {
			spcs_log("sv", &svc.svc_error,
			    gettext("%s: unable to suspend %s"),
			    program, path);

			warn(&svc.svc_error,
				gettext("unable to suspend %s"), path);
			return;
		}
	}

	spcs_log("sv", NULL, gettext("%s: suspend %s"), program, path);

	spcs_s_ufree(&svc.svc_error);
}


static void
suspend_sv(void)
{
	sv_name_t *svn, *svn_system;	/* Devices in system */
	sv_list_t svl_system;
	int i;
	int fd;

	svn_system = sv_alloc_svnames();

	svl_system.svl_count = read_libcfg(svn_system);

	if ((fd = open(sv_rpath, O_RDONLY)) < 0) {
		warn(NULL, gettext("unable to open %s: %s"),
			sv_rpath, strerror(errno));
		return;
	}

	for (i = 0; i < svl_system.svl_count; i++) {
		if (*svn_system[i].svn_path == '\0')
			break;

		svn = &svn_system[i];
		suspend_dev(fd, svn->svn_path);
	}

	(void) close(fd);
}


/*
 * Check kernel's sv_ndevices and thread sets,
 * if empty then change kernel state to allow unload,
 * and sleep SV_WAIT_UNLAOD (10 seconds).
 *
 * Only called in pkgrm time.
 */
static void
prepare_unload_sv(void)
{
	int fd;
	int rc = 0;

	if ((fd = open(sv_rpath, O_RDONLY)) < 0) {
		warn(NULL, gettext("unable to open %s: %s"),
			sv_rpath, strerror(errno));
		return;
	}

	if (ioctl(fd, SVIOC_UNLOAD, &rc) < 0)
		error(NULL, gettext("unable to unload"));

	if (rc != 0)
		error(NULL, gettext("still has active devices or threads"));

	(void) close(fd);
}
