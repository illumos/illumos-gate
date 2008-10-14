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
#include <sys/wait.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdlib.h>
#include <strings.h>
#include <errno.h>
#include <stdio.h>
#include <locale.h>
#include <unistd.h>
#include <search.h>
#include <libgen.h>
#include <nsctl.h>

#include <sys/unistat/spcs_s.h>
#include <sys/unistat/spcs_s_u.h>
#include <sys/unistat/spcs_errors.h>

#include <sys/nsctl/sv.h>
#include <sys/nsctl/sv_impl.h>

#include <sys/nsctl/cfg.h>
#include <sys/nsctl/nsc_hash.h>

#include "../sv/svadm.h"


static int sv_max_devices;


/*
 * support for the special cluster tag "local" to be used with -C in a
 * cluster for local volumes.
 */

#define	SV_LOCAL_TAG	"local"

static int sv_islocal;

/*
 * libcfg access.
 */

static CFGFILE *cfg;		/* libcfg file pointer */
static int cfg_changed;		/* set to 1 if we need to commit changes */

static char *cfg_cluster_tag;	/* local cluster tag */

static char *implicit_tag;	/* implicit cluster tag */


/*
 * Print width for print_sv() output.
 */

#define	STATWIDTH	(SV_MAXPATH / 2)

/*
 * Pathnames.
 */

static const caddr_t sv_rpath = SV_DEVICE;

/*
 * Functions.
 */

static int read_config_file(const caddr_t, sv_name_t []);
static int enable_dev(sv_name_t *);
static int disable_dev(const caddr_t);
static void error(spcs_s_info_t *, caddr_t, ...);
static void create_cfg_hash();
static int find_in_hash(char *path);
static void destroy_hashtable();
static void remove_from_cfgfile(char *path, int setnumber);

static caddr_t program;

static void
sv_cfg_open(CFGLOCK mode)
{
	if (cfg != NULL)
		return;

	cfg = cfg_open(NULL);
	if (cfg == NULL) {
		error(NULL, gettext("unable to access the configuration"));
		/* NOTREACHED */
	}

	if (cfg_cluster_tag && *cfg_cluster_tag) {
		cfg_resource(cfg, cfg_cluster_tag);
	} else {
		cfg_resource(cfg, NULL);
	}
	if (!cfg_lock(cfg, mode)) {
		error(NULL, gettext("unable to lock the configuration"));
		/* NOTREACHED */
	}
}


static void
sv_cfg_close(void)
{
	if (cfg == NULL)
		return;

	if (cfg_changed) {
		(void) cfg_commit(cfg);
		cfg_changed = 0;
	}

	cfg_close(cfg);
	cfg = NULL;
}



static void
usage(void)
{
	(void) fprintf(stderr, gettext("usage:\n"));

	(void) fprintf(stderr, gettext(
	    "\t%s -h                                 help\n"), program);

	(void) fprintf(stderr, gettext(
	    "\t%s [-C tag]                           display status\n"),
	    program);

	(void) fprintf(stderr, gettext(
	    "\t%s [-C tag] -i                        display "
	    "extended status\n"), program);

	(void) fprintf(stderr, gettext(
	    "\t%s [-C tag] -v                        display "
	    "version number\n"), program);

	(void) fprintf(stderr, gettext(
	    "\t%s [-C tag] -e { -f file | volume }   enable\n"), program);

	(void) fprintf(stderr, gettext(
	    "\t%s [-C tag] -d { -f file | volume }   disable\n"), program);

	(void) fprintf(stderr, gettext(
	    "\t%s [-C tag] -r { -f file | volume }   reconfigure\n"), program);

	sv_cfg_close();
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

	sv_cfg_close();
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

	if (ioctl(fd, SVIOC_LIST, &svl) < 0) {
		(void) close(fd);
		error(&svl.svl_error, gettext("unable to get max devs"));
	}

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


static void
sv_check_dgislocal(char *dgname)
{
	char *othernode;
	int rc;

	/*
	 * check where this disk service is mastered
	 */

	rc = cfg_dgname_islocal(dgname, &othernode);
	if (rc < 0) {
		error(NULL, gettext("unable to find "
		    "disk service, %s: %s"), dgname, strerror(errno));
	}

	if (rc == 0) {
		error(NULL, gettext("disk service, %s, is "
		    "active on node \"%s\"\nPlease re-issue "
		    "the command on that node"), dgname, othernode);
	}
}


/*
 * Carry out cluster based checks for a specified volume, or just
 * global options.
 */
static void
sv_check_cluster(char *path)
{
	char dgname[CFG_MAX_BUF];
	static int sv_iscluster = -1;	/* set to 1 if running in a cluster */

	/*
	 * Find out if we are running in a cluster
	 */
	if (sv_iscluster == -1) {
		if ((sv_iscluster = cfg_iscluster()) < 0) {
			error(NULL, gettext("unable to ascertain environment"));
		}
	}

	if (!sv_iscluster && cfg_cluster_tag != NULL) {
		error(NULL, gettext("-C is not valid when not in a cluster"));
	}

	if (!sv_iscluster || sv_islocal || path == NULL) {
		return;
	}


	/*
	 * Cluster-only checks on pathname
	 */
	if (cfg_dgname(path, dgname, sizeof (dgname)) == NULL) {
		error(NULL, gettext("unable to determine "
		    "disk group name for %s"), path);
		return;
	}

	if (cfg_cluster_tag != NULL) {
		/*
		 * Do dgislocal check now in case path did not contain
		 * a dgname.
		 *
		 * E.g. adding a /dev/did/ device to a disk service.
		 */

		sv_check_dgislocal(cfg_cluster_tag);
	}

	if (strcmp(dgname, "") == 0)
		return;		/* NULL dgname is valid */

	if (cfg_cluster_tag == NULL) {
		/*
		 * Implicitly set the cluster tag to dgname
		 */

		sv_check_dgislocal(dgname);

		if (implicit_tag) {
			free(implicit_tag);
			implicit_tag = NULL;
		}

		implicit_tag = strdup(dgname);
		if (implicit_tag == NULL) {
			error(NULL,
			    gettext("unable to allocate memory "
			    "for cluster tag"));
		}
	} else {
		/*
		 * Check dgname and cluster tag from -C are the same.
		 */

		if (strcmp(dgname, cfg_cluster_tag) != 0) {
			error(NULL,
			    gettext("-C (%s) does not match disk group "
			    "name (%s) for %s"), cfg_cluster_tag,
			    dgname, path);
		}

		/*
		 * sv_check_dgislocal(cfg_cluster_tag) was called above.
		 */
	}
}


static void
print_version(void)
{
	sv_version_t svv;
	int fd;

	bzero(&svv, sizeof (svv));
	svv.svv_error = spcs_s_ucreate();

	fd = open(sv_rpath, O_RDONLY);
	if (fd < 0) {
		warn(NULL, gettext("unable to open %s: %s"),
			sv_rpath, strerror(errno));
		return;
	}

	if (ioctl(fd, SVIOC_VERSION, &svv) != 0) {
		error(&svv.svv_error,
		    gettext("unable to read the version number"));
		/* NOTREACHED */
	}

	spcs_s_ufree(&svv.svv_error);
#ifdef DEBUG
	(void) printf(gettext("Storage Volume version %d.%d.%d.%d\n"),
	    svv.svv_major_rev, svv.svv_minor_rev,
	    svv.svv_micro_rev, svv.svv_baseline_rev);
#else
	if (svv.svv_micro_rev) {
		(void) printf(gettext("Storage Volume version %d.%d.%d\n"),
		    svv.svv_major_rev, svv.svv_minor_rev, svv.svv_micro_rev);
	} else {
		(void) printf(gettext("Storage Volume version %d.%d\n"),
		    svv.svv_major_rev, svv.svv_minor_rev);
	}
#endif

	(void) close(fd);
}

int
main(int argc, char *argv[])
{
	extern int optind;
	extern char *optarg;
	char *conf_file = NULL;
	int enable, disable, compare, print, version;
	int opt, Cflag, fflag, iflag;
	int rc;

	(void) setlocale(LC_ALL, "");
	(void) textdomain("svadm");

	program = strdup(basename(argv[0]));

	Cflag = fflag = iflag = 0;
	compare = enable = disable = version = 0;

	print = 1;

	while ((opt = getopt(argc, argv, "C:def:hirv")) != EOF) {
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

		case 'e':
			print = 0;
			enable++;
			break;

		case 'd':
			print = 0;
			disable++;
			break;

		case 'f':
			fflag++;
			conf_file = optarg;
			break;

		case 'i':
			iflag++;
			break;

		case 'r':
			/* Compare running system with sv.cf */
			print = 0;
			compare++;
			break;

		case 'v':
			print = 0;
			version++;
			break;

		case 'h':
			usage();
			exit(0);

		default:
			usage();
			exit(2);
			/* NOTREACHED */
		}
	}


	/*
	 * Usage checks
	 */

	if ((enable + disable + compare) > 1) {
		warn(NULL, gettext("-d, -e and -r are mutually exclusive"));
		usage();
		exit(2);
	}

	if (fflag && (print || version)) {
		warn(NULL, gettext("-f is only valid with -d, -e or -r"));
		usage();
		exit(2);
	}

	if (fflag && optind != argc) {
		usage();
		exit(2);
	}

	if (print || version) {
		/* check for no more args */

		if (optind != argc) {
			usage();
			exit(2);
		}
	} else {
		/* check for inline args */

		if (!fflag && (argc - optind) != 1) {
			usage();
			exit(2);
		}
	}

	if (!print && iflag) {
		usage();
		exit(2);
	}


	/*
	 * Check for the special cluster tag and convert into the
	 * internal representation.
	 */

	if (cfg_cluster_tag != NULL &&
	    strcmp(cfg_cluster_tag, SV_LOCAL_TAG) == 0) {
		cfg_cluster_tag = "-";
		sv_islocal = 1;
	}


	/*
	 * Process commands
	 */

	if (optind != argc) {
		/* deal with inline volume argument */

		rc = 0;
		if (enable)
			rc = enable_one_sv(argv[optind]);
		else if (disable)
			rc = disable_one_sv(argv[optind]);
		else /* if (compare) */
			compare_one_sv(argv[optind]);

		if (rc != 0)
			return (1);

		return (0);
	}

	rc = 0;
	if (enable)
		rc = enable_sv(conf_file);
	else if (disable)
		rc = disable_sv(conf_file);
	else if (compare)
		compare_sv(conf_file);
	else if (print)
		print_sv(iflag);
	else /* if (version) */
		print_version();

	if (rc != 0)
		return (1);

	return (0);
}



/* LINT - not static as fwcadm uses it */
static int
enable_sv(char *conf_file)
{
	int index;
	sv_name_t *svn;
	int cnt;
	int rc, ret;

	svn = sv_alloc_svnames();

	index = read_config_file(conf_file, svn);

	rc = ret = 0;

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
		rc = enable_dev(&svn[cnt]);
		if (rc && !ret)
			ret = rc;
	}

	sv_cfg_close();

	return (ret);
}


/* LINT - not static as fwcadm uses it */
static int
enable_one_sv(caddr_t path)
{
	sv_name_t svn;
	int rc;

	sv_get_maxdevs();

	bzero(&svn, sizeof (svn));
	(void) strncpy(svn.svn_path, path, sizeof (svn.svn_path));
	svn.svn_mode = (NSC_DEVICE | NSC_CACHE);

	/* force NULL termination */
	svn.svn_path[sizeof (svn.svn_path) - 1] = '\0';

	rc = enable_dev(&svn);
	sv_cfg_close();

	return (rc);
}


static int
enable_dev(sv_name_t *svn)
{
	char buf[CFG_MAX_BUF];
	struct stat stb;
	sv_conf_t svc;
	int fd;
	int sev;
	int rc;
	char *lcltag;
	char *altname;

	sv_check_cluster(svn->svn_path);
	sv_cfg_open(CFG_WRLOCK);

	bzero(&svc, sizeof (svc));

	if (stat(svn->svn_path, &stb) != 0) {
		warn(NULL, gettext("unable to access %s: %s"),
			svn->svn_path, strerror(errno));
		return (1);
	}

	if (!S_ISCHR(stb.st_mode)) {
		warn(NULL, gettext("%s is not a character device - ignored"),
		    svn->svn_path);
		return (1);
	}

	svc.svc_major = major(stb.st_rdev);
	svc.svc_minor = minor(stb.st_rdev);
	(void) strncpy(svc.svc_path, svn->svn_path, sizeof (svc.svc_path));

	fd = open(sv_rpath, O_RDONLY);
	if (fd < 0) {
		warn(NULL, gettext("unable to open %s: %s"),
			svn->svn_path, strerror(errno));
		return (1);
	}

	svc.svc_flag = svn->svn_mode;
	svc.svc_error = spcs_s_ucreate();

	/* first, check for duplicates */
	rc = cfg_get_canonical_name(cfg, svn->svn_path, &altname);
	if (rc < 0) {
		spcs_log("sv", NULL, gettext("Unable to parse config file"));
		warn(NULL, gettext("Unable to parse config file"));
		(void) close(fd);
		return (1);
	}
	if (rc) {
		error(NULL, gettext("'%s' has already been configured as "
		    "'%s'.  Re-enter command with the latter name."),
		    svn->svn_path, altname);
	}

	/* secondly, try to insert it into the dsvol config */
	if (implicit_tag && *implicit_tag) {
		lcltag = implicit_tag;
	} else if (cfg_cluster_tag && *cfg_cluster_tag) {
		lcltag = cfg_cluster_tag;
	} else {
		lcltag = "-";
	}
	rc = cfg_add_user(cfg, svn->svn_path, lcltag, "sv");
	if (CFG_USER_ERR == rc) {
		spcs_log("sv", NULL,
		    gettext("%s: unable to put %s into dsvol cfg"),
		    program, svn->svn_path);
		warn(NULL, gettext("unable to put %s into dsvol cfg"),
		    svn->svn_path);
		(void) close(fd);
		return (1);
	}
	cfg_changed = 1;

	if (CFG_USER_OK == rc) {
		/* success */
		(void) close(fd);
		return (0);
	}

	if (ioctl(fd, SVIOC_ENABLE, &svc) < 0) {
		if ((CFG_USER_REPEAT == rc) && (SV_EENABLED == errno)) {
			/* it's ok -- we were just double-checking */
			(void) close(fd);
			return (0);
		}

		spcs_log("sv", &svc.svc_error,
		    gettext("%s: unable to enable %s"),
		    program, svn->svn_path);

		warn(&svc.svc_error, gettext("unable to enable %s"),
			svn->svn_path);

		/* remove it from dsvol, if we're the ones who put it in */
		if (CFG_USER_FIRST == rc) {
			(void) cfg_rem_user(cfg, svn->svn_path, lcltag, "sv");
		}
		(void) close(fd);
		return (1);
	}

	spcs_log("sv", NULL, gettext("%s: enabled %s"),
	    program, svn->svn_path);

	if (implicit_tag != NULL) {
#ifdef DEBUG
		if (cfg_cluster_tag != NULL) {
			error(NULL,
			    gettext("enable_dev: -C %s AND implicit_tag %s!"),
			    cfg_cluster_tag, implicit_tag);
		}
#endif

		(void) snprintf(buf, sizeof (buf), "%s - %s",
		    svc.svc_path, implicit_tag);
	} else {
		(void) strcpy(buf, svc.svc_path);
	}

	rc = 0;
	if (cfg_put_cstring(cfg, "sv", buf, sizeof (buf)) < 0) {
		warn(NULL,
		    gettext("unable to add %s to configuration storage: %s"),
		    svc.svc_path, cfg_error(&sev));
		rc = 1;
	}

	cfg_changed = 1;
	spcs_s_ufree(&svc.svc_error);
	(void) close(fd);

	return (rc);
}


/*
 * This routine parses the config file passed in via conf_file and
 * stores the data in the svn array.  The return value is the number
 * of entries read from conf_file.  If an error occurs the error()
 * routine is called (which exits the program).
 */
static int
read_config_file(const caddr_t conf_file, sv_name_t svn[])
{
	char line[1024], rdev[1024], junk[1024];
	struct stat stb;
	int lineno;
	int cnt, i;
	int index = 0;		/* Current location in svn array	*/
	sv_name_t *cur_svn;	/* Pointer to svn[index]		*/
	FILE *fp;

	if (access(conf_file, R_OK) != 0 ||
	    stat(conf_file, &stb) != 0 ||
	    !S_ISREG(stb.st_mode)) {
		error(NULL, gettext("cannot read config file %s"), conf_file);
	}

	if ((fp = fopen(conf_file, "r")) == NULL) {
		error(NULL, gettext("unable to open config file %s: %s"),
			conf_file, strerror(errno));
	}

	lineno = 0;

	while (fgets(line, sizeof (line), fp) != NULL) {
		lineno++;

		i = strlen(line);

		if (i < 1)
			continue;

		if (line[i-1] == '\n')
			line[i-1] = '\0';
		else if (i == (sizeof (line) - 1)) {
			warn(NULL, gettext(
		"line %d: line too long -- should be less than %d characters"),
				lineno, (sizeof (line) - 1));
			warn(NULL, gettext("line %d: ignored"), lineno);
		}

		/*
		 * check for comment line.
		 */
		if (line[0] == '#')
			continue;

		cnt = sscanf(line, "%s %s", rdev, junk);

		if (cnt != 1 && cnt != 2) {
			if (cnt > 0) {
				warn(NULL, gettext("line %d: invalid format"),
					lineno);
				warn(NULL, gettext("line %d: ignored"), lineno);
			}
			continue;
		}

		rdev[sizeof (rdev) - 1] = '\0';

		cur_svn = &svn[index];  /* For easier reading below */

		if (strlen(rdev) >= sizeof (cur_svn->svn_path)) {
			warn(NULL, gettext(
		"line %d: raw device name (%s) longer than %d characters"),
				lineno, rdev,
				(sizeof (cur_svn->svn_path) - 1));
			warn(NULL, gettext("line %d: ignored"), lineno);
			continue;
		}

		(void) strcpy(cur_svn->svn_path, rdev);
		cur_svn->svn_mode = (NSC_DEVICE | NSC_CACHE);

		index++;
	}

	/* Set the last path to NULL */
	svn[index].svn_path[0] = '\0';

	(void) fclose(fp);

	return (index);
}


/*
 * Disable the device from the kernel configuration.
 *
 * RETURN:
 *   0 on success
 *   non-zero on failure.
 *
 * Failures are reported to the user.
 */
static int
disable_dev(const caddr_t path)
{
	struct stat stb;
	sv_conf_t svc;
	int fd;

	sv_check_cluster(path);

	if (stat(path, &stb) < 0) {
		svc.svc_major = (major_t)-1;
		svc.svc_minor = (minor_t)-1;
	} else {
		svc.svc_major = major(stb.st_rdev);
		svc.svc_minor = minor(stb.st_rdev);
	}

	if ((fd = open(sv_rpath, O_RDONLY)) < 0) {
		warn(NULL, gettext("unable to open %s: %s"),
			sv_rpath, strerror(errno));
		return (-1);
	}

	(void) strcpy(svc.svc_path, path);
	svc.svc_error = spcs_s_ucreate();

	/*
	 * Issue the ioctl to attempt to disable this device.  Note that all
	 * the libdscfg details are handled elsewhere.
	 */
	if (ioctl(fd, SVIOC_DISABLE, &svc) < 0) {
		if (errno != SV_EDISABLED) {
			spcs_log("sv", &svc.svc_error,
					gettext("%s: unable to disable %s"),
					program, path);

			warn(&svc.svc_error,
					gettext("unable to disable %s"), path);
			(void) close(fd);
			return (-1);
		}
	}

	spcs_log("sv", NULL, gettext("%s: disabled %s"), program, path);

	spcs_s_ufree(&svc.svc_error);
	(void) close(fd);

	return (0);
}


static void
print_cluster_tag(const int setnumber)
{
	char buf[CFG_MAX_BUF];
	char key[CFG_MAX_KEY];

	bzero(buf, sizeof (buf));
	(void) snprintf(key, sizeof (key), "sv.set%d.cnode", setnumber);

	(void) cfg_get_cstring(cfg, key, buf, sizeof (buf));

	if (*buf != '\0') {
		if (strcmp(buf, "-") == 0) {
			(void) printf(" [%s]", gettext("local to node"));
		} else {
			(void) printf(" [%s: %s]", gettext("cluster"), buf);
		}
	}
}


/* LINT - not static as fwcadm uses it */
static void
print_sv(int verbose)
{
	sv_name_t *svn, *svn_system;	/* Devices in system */
	sv_list_t svl_system;
	int fd, i;
	int setnumber;

	sv_check_cluster(NULL);
	sv_cfg_open(CFG_RDLOCK);

	svn_system = sv_alloc_svnames();

	if ((fd = open(sv_rpath, O_RDONLY)) < 0) {
		(void) printf(gettext("unable to open %s: %s"),
			sv_rpath, strerror(errno));
		return;
	}

	/* Grab the system list from the driver */
	svl_system.svl_count = sv_max_devices;
	svl_system.svl_names = &svn_system[0];
	svl_system.svl_error = spcs_s_ucreate();

	if (ioctl(fd, SVIOC_LIST, &svl_system) < 0) {
		error(&svl_system.svl_error, gettext("unable to get list"));
	}

	spcs_s_ufree(&svl_system.svl_error);
	(void) close(fd);

	/*
	 * We build a hashmap out of the entries from the config file to make
	 * searching faster. We end up taking a performance hit when the # of
	 * volumes is small, but for larger configurations it's a
	 * HUGE improvement.
	 */

	/* build the hashtable */
	cfg_rewind(cfg, CFG_SEC_CONF);
	create_cfg_hash();

	/*
	 * For each volume found from the kernel, print out
	 * info about it from the kernel.
	 */
	for (i = 0; i < svl_system.svl_count; i++) {
		if (*svn_system[i].svn_path == '\0') {
			break;
		}

		svn = &svn_system[i];
		if (svn->svn_mode == 0) {
#ifdef DEBUG
			(void) printf(gettext("%s [kernel guard]\n"),
			    svn->svn_path);
#endif
			continue;
		}
		/* get sv entry from the hashtable */
		if ((setnumber = find_in_hash(svn->svn_path)) != -1) {
			(void) printf("%-*s", STATWIDTH, svn->svn_path);

			if (verbose) {
				print_cluster_tag(setnumber);
			}

			(void) printf("\n");

		} else {
			/*
			 * We didn't find the entry in the hashtable.  Let
			 * the user know that the persistent storage is
			 * inconsistent with the kernel configuration.
			 */
			if (cfg_cluster_tag == NULL)
				warn(NULL, gettext(
					"%s is configured, but not in the "
					"config storage"), svn->svn_path);
		}
	}

	/* free up the hashtable */
	destroy_hashtable();

	sv_cfg_close();
}


/* LINT - not static as fwcadm uses it */
static int
disable_sv(char *conf_file)
{
	sv_name_t *svn, *svn_system;	/* Devices in system */
	sv_list_t svl_system;
	int fd, i, setnumber;
	int rc, ret;

	svn_system = sv_alloc_svnames();

	rc = ret = 0;

	if (conf_file == NULL) {
		if ((fd = open(sv_rpath, O_RDONLY)) < 0) {
			(void) printf(gettext("unable to open %s: %s"),
				sv_rpath, strerror(errno));
			return (1);
		}

		/* Grab the system list from the driver */
		svl_system.svl_count = sv_max_devices;
		svl_system.svl_names = &svn_system[0];
		svl_system.svl_error = spcs_s_ucreate();

		if (ioctl(fd, SVIOC_LIST, &svl_system) < 0) {
			error(&(svl_system.svl_error),
					gettext("unable to get list"));
		}

		spcs_s_ufree(&(svl_system.svl_error));
		(void) close(fd);
	} else {
		svl_system.svl_count = read_config_file(conf_file, svn_system);
	}


	for (i = 0; i < svl_system.svl_count; i++) {
		if (*svn_system[i].svn_path == '\0')
			break;

		svn = &svn_system[i];

		sv_check_cluster(svn->svn_path);
		sv_cfg_open(CFG_WRLOCK);
		create_cfg_hash();
		rc = 0;
		if ((setnumber = find_in_hash(svn->svn_path)) != -1) {
			if ((rc = disable_dev(svn->svn_path)) != -1) {
				remove_from_cfgfile(svn->svn_path, setnumber);
			} else if (errno == SV_ENODEV) {
				remove_from_cfgfile(svn->svn_path, setnumber);
			}
		} else {
			/* warn the user that we didn't find it in cfg file */
			warn(NULL, gettext(
				"%s was not found in the config storage"),
				svn->svn_path);
			/* try to disable anyway */
			(void) disable_dev(svn->svn_path);
			rc = 1;
		}

		sv_cfg_close();
		destroy_hashtable();

		if (rc && !ret)
			ret = rc;
	}

	return (ret);
}


/* LINT - not static as fwcadm uses it */
static int
disable_one_sv(char *path)
{
	int setnumber;
	int rc;

	sv_get_maxdevs();
	sv_check_cluster(path);
	sv_cfg_open(CFG_WRLOCK);

	create_cfg_hash();
	if ((setnumber = find_in_hash(path)) != -1) {
		/* remove from kernel */
		if ((rc = disable_dev(path)) == 0) {
			/* remove the cfgline */
			remove_from_cfgfile(path, setnumber);
		} else if (errno == SV_ENODEV) {
			remove_from_cfgfile(path, setnumber);
		}
	} else {
		/* warn the user that we didn't find it in cfg file */
		warn(NULL,
		    gettext("%s was not found in the config storage"), path);
		/* still attempt to remove */
		(void) disable_dev(path);
		rc = 1;
	}
	destroy_hashtable();

	sv_cfg_close();
	return (rc);
}


static void
compare_tag(char *path)
{
	char buf[CFG_MAX_BUF], vol[CFG_MAX_BUF], cnode[CFG_MAX_BUF];
	char key[CFG_MAX_KEY];
	int found, setnumber, i;
	char *tag;

	sv_check_cluster(path);
	cfg_resource(cfg, (char *)NULL);	/* reset */
	cfg_rewind(cfg, CFG_SEC_CONF);

#ifdef DEBUG
	if (cfg_cluster_tag != NULL && implicit_tag != NULL) {
		error(NULL, gettext("compare_tag: -C %s AND implicit_tag %s!"),
		    cfg_cluster_tag, implicit_tag);
	}
#endif

	if (cfg_cluster_tag != NULL)
		tag = cfg_cluster_tag;
	else if (implicit_tag != NULL)
		tag = implicit_tag;
	else
		tag = "-";

	found = 0;
	for (i = 0; i < sv_max_devices; i++) {
		setnumber = i + 1;
		(void) snprintf(key, sizeof (key), "sv.set%d", setnumber);
		if (cfg_get_cstring(cfg, key, buf, sizeof (buf)) < 0) {
			break;
		}

		if (sscanf(buf, "%s - %s", vol, cnode) != 2) {
			continue;
		}

		if (strcmp(path, vol) == 0) {
			found = 1;
			break;
		}
	}

	if (!found) {
		warn(NULL, gettext("unable to find %s in the configuration"),
		    path);
		return;
	}

	/* have name match, compare cnode to new tag */

	if (strcmp(tag, cnode) == 0) {
		/* cluster tags match */
		return;
	}

	/* need to change the cluster tag */

	(void) snprintf(key, sizeof (key), "sv.set%d.cnode", setnumber);
	if (cfg_put_cstring(cfg, key, tag, strlen(tag)) < 0) {
		warn(NULL,
		    gettext("unable to change cluster tag for %s"), path);
		return;
	}

	cfg_changed = 1;

	/* change "-" tags to "" for display purposes */

	if (strcmp(tag, "-") == 0)
		tag = "";

	if (strcmp(cnode, "-") == 0)
		(void) strcpy(cnode, "");

	(void) printf(
	    gettext("%s: changed cluster tag for %s from \"%s\" to \"%s\"\n"),
	    program, path, cnode, tag);

	spcs_log("sv", NULL,
	    gettext("%s: changed cluster tag for %s from \"%s\" to \"%s\""),
	    program, path, cnode, tag);
}


/* LINT - not static as fwcadm uses it */
static void
compare_sv(char *conf_file)
{
	sv_name_t *svn_config;		/* Devices in config file */
	sv_name_t *svn_system;		/* Devices in system */
	sv_name_t *enable;		/* Devices that need enabled */
	sv_list_t svl_system;
	int config_cnt;
	int sys_cnt = 0;
	int setnumber, i, j;
	int index = 0;	/* Index in enable[] */
	int found;
	int fd0;

	svn_config = sv_alloc_svnames();
	svn_system = sv_alloc_svnames();
	enable = sv_alloc_svnames();

	bzero(svn_system, sizeof (svn_system));
	bzero(&svl_system, sizeof (svl_system));
	bzero(enable, sizeof (enable));

	/*
	 * Read the configuration file
	 * The return value is the number of entries
	 */
	config_cnt = read_config_file(conf_file, svn_config);

	if ((fd0 = open(sv_rpath, O_RDONLY)) < 0)
		error(NULL, gettext("unable to open %s: %s"),
			sv_rpath, strerror(errno));

	/* Grab the system list from the driver */
	svl_system.svl_count = sv_max_devices;
	svl_system.svl_names = &svn_system[0];
	svl_system.svl_error = spcs_s_ucreate();

	if (ioctl(fd0, SVIOC_LIST, &svl_system) < 0) {
		error(&svl_system.svl_error, gettext("unable to get list"));
	}

	spcs_s_ufree(&svl_system.svl_error);
	(void) close(fd0);

	/*
	 * Count the number of devices in the system.
	 * The last entry in the array has '\0' for a path name.
	 */
	for (j = 0; j < sv_max_devices; j++) {
		if (svn_system[j].svn_path[0] != '\0') {
			sys_cnt++;
		} else {
			break;
		}
	}
	/*
	 * Compare the configuration array with the system array.
	 * Mark any differences and disable conflicting devices.
	 */
	for (i = 0; i < config_cnt; i++) {
		found = 0;
		for (j = 0; j < sys_cnt; j++) {
			if (svn_system[j].svn_path[0] == '\0' ||
			    svn_system[j].svn_mode == 0)
				continue;

			/*  Check to see if path matches */
			if (strcmp(svn_system[j].svn_path,
			    svn_config[i].svn_path) == 0) {
				/*  Found a match  */
				svn_system[j].svn_path[0] = '\0';
				found++;
				break;
			}
		}

		if (!found) {
			/* Minor number not in system  = > enable device */
			enable[index].svn_mode = svn_config[i].svn_mode;
			(void) strcpy(enable[index].svn_path,
			    svn_config[i].svn_path);
			index++;
		}
	}

	/* Disable any devices that weren't in the config file */
	for (j = 0; j < sys_cnt; j++) {
		sv_check_cluster(NULL);
		sv_cfg_open(CFG_WRLOCK);
		create_cfg_hash();
		if (svn_system[j].svn_path[0] != '\0' &&
		    svn_system[j].svn_mode != 0) {
			(void) printf(gettext("%s: disabling sv: %s\n"),
			    program, svn_system[j].svn_path);
			if (disable_dev(svn_system[j].svn_path) == 0) {
				setnumber =
					find_in_hash(svn_system[j].svn_path);
				if (setnumber != -1) {
					/* the volume was found in cfg store */
					remove_from_cfgfile(
					svn_system[j].svn_path, setnumber);
				}
			}
		}
		sv_cfg_close();
		destroy_hashtable();
	}

	while (index) {
		/*
		 * Config file doesn't match system => enable the devices
		 * in enable[]
		 */
		index--;
		(void) printf(gettext("%s: enabling new sv: %s\n"),
		    program, enable[index].svn_path);
		(void) enable_dev(&enable[index]);
	}

	/*
	 * Search for entries where the cluster tag has changed.
	 */
	sv_check_cluster(NULL);
	sv_cfg_open(CFG_WRLOCK);

	for (i = 0; i < sv_max_devices; i++) {
		if (svn_config[i].svn_path[0] == '\0')
			break;

		compare_tag(svn_config[i].svn_path);
	}

	sv_cfg_close();
}


/*
 * We assume that the volume is already enabled and we can only
 * be changing the cluster tag.  Anything else is an error.
 */
/* LINT - not static as fwcadm uses it */
static void
compare_one_sv(char *path)
{
	sv_get_maxdevs();
	sv_check_cluster(NULL);
	sv_cfg_open(CFG_WRLOCK);

	compare_tag(path);

	sv_cfg_close();
}

/*
 * Read all sets from the libdscfg configuration file, and store everything in
 * the hashfile.
 *
 * We assume that the config file has been opened & rewound for us.  We store
 * the volume name as the key, and the setnumber where we found it as the data.
 *
 * The caller can pass in a pointer to the maximum number of volumes, or
 * a pointer to NULL, specifying we want 'all' the volumes.  The table is
 * searched using find_in_hash.
 */
static void
create_cfg_hash()
{
	char key[CFG_MAX_KEY], buf[CFG_MAX_BUF];
	char vol[CFG_MAX_BUF], cnode[CFG_MAX_BUF];
	int setnumber;
	ENTRY item;

	if (hcreate((size_t)sv_max_devices) == 0)
		error(NULL, gettext("unable to create hash table"));

	for (setnumber = 1; /* CSTYLED */; setnumber++) {
		(void) snprintf(key, sizeof (key), "sv.set%d", setnumber);
		if (cfg_get_cstring(cfg, key, buf, sizeof (buf)) < 0)
			break;

		if (sscanf(buf, "%s - %s", vol, cnode) != 2) {
			continue;
		}

		item.key = strdup(vol);
		item.data = (void *)setnumber;
		if (hsearch(item, ENTER) == NULL) {
			error(NULL,
			    gettext("unable to add entry to hash table"));
		}
	}
}

/*
 * Function to search the hash for a specific volume.  If it is found,
 * we return the set number.  If it isn't found, we return -1
 */
static int
find_in_hash(char *path)
{
	ENTRY *found_entry, item;
	int retval = -1;

	item.key = path;

	if ((found_entry = hsearch(item, FIND)) != NULL) {
		retval = (int)found_entry->data;
	}

	return (retval);
}

/*
 * Just a wrapper to destory the hashtable.  At some point in the future we
 * might want to do something more....  For instance, verify that the cfg
 * database and the kernel configuration match (?)  Just an idea.
 */
static void
destroy_hashtable()
{
	hdestroy();
}

/*
 * This function will remove a particular set from the config file.
 *
 * We make a whole host of assumptions:
 *   o the hashfile is up to date;
 *   o The config file has been opened with a WRLOCK for us.
 */
static void
remove_from_cfgfile(char *path, int setnumber)
{
	char key[CFG_MAX_KEY];
	int sev;
	char *lcltag;

	/* attempt to remove the volume from config storage */
	(void) snprintf(key, sizeof (key), "sv.set%d", setnumber);
	if (cfg_put_cstring(cfg, key, NULL, 0) < 0) {
		warn(NULL, gettext("unable to remove %s from "
		    "config storage: %s"), path, cfg_error(&sev));
	} else {
		if (implicit_tag && *implicit_tag) {
			lcltag = implicit_tag;
		} else if (cfg_cluster_tag && *cfg_cluster_tag) {
			lcltag = cfg_cluster_tag;
		} else {
			lcltag = "-";
		}
		if (cfg_rem_user(cfg, path, lcltag, "sv") != CFG_USER_LAST) {
			warn(NULL, gettext("unable to remove %s from dsvol"),
			    path);
		}
		cfg_changed = 1;
	}
}
