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
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2014 Nexenta Systems, Inc. All rights reserved.
 */

/*
 * zoneadmd manages zones; one zoneadmd process is launched for each
 * non-global zone on the system.  This daemon juggles four jobs:
 *
 * - Implement setup and teardown of the zone "virtual platform": mount and
 *   unmount filesystems; create and destroy network interfaces; communicate
 *   with devfsadmd to lay out devices for the zone; instantiate the zone
 *   console device; configure process runtime attributes such as resource
 *   controls, pool bindings, fine-grained privileges.
 *
 * - Launch the zone's init(1M) process.
 *
 * - Implement a door server; clients (like zoneadm) connect to the door
 *   server and request zone state changes.  The kernel is also a client of
 *   this door server.  A request to halt or reboot the zone which originates
 *   *inside* the zone results in a door upcall from the kernel into zoneadmd.
 *
 *   One minor problem is that messages emitted by zoneadmd need to be passed
 *   back to the zoneadm process making the request.  These messages need to
 *   be rendered in the client's locale; so, this is passed in as part of the
 *   request.  The exception is the kernel upcall to zoneadmd, in which case
 *   messages are syslog'd.
 *
 *   To make all of this work, the Makefile adds -a to xgettext to extract *all*
 *   strings, and an exclusion file (zoneadmd.xcl) is used to exclude those
 *   strings which do not need to be translated.
 *
 * - Act as a console server for zlogin -C processes; see comments in zcons.c
 *   for more information about the zone console architecture.
 *
 * DESIGN NOTES
 *
 * Restart:
 *   A chief design constraint of zoneadmd is that it should be restartable in
 *   the case that the administrator kills it off, or it suffers a fatal error,
 *   without the running zone being impacted; this is akin to being able to
 *   reboot the service processor of a server without affecting the OS instance.
 */

#include <sys/param.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>

#include <bsm/adt.h>
#include <bsm/adt_event.h>

#include <alloca.h>
#include <assert.h>
#include <errno.h>
#include <door.h>
#include <fcntl.h>
#include <locale.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <synch.h>
#include <syslog.h>
#include <thread.h>
#include <unistd.h>
#include <wait.h>
#include <limits.h>
#include <zone.h>
#include <libbrand.h>
#include <sys/brand.h>
#include <libcontract.h>
#include <libcontract_priv.h>
#include <sys/brand.h>
#include <sys/contract/process.h>
#include <sys/ctfs.h>
#include <libdladm.h>
#include <sys/dls_mgmt.h>
#include <libscf.h>

#include <libzonecfg.h>
#include <zonestat_impl.h>
#include "zoneadmd.h"

static char *progname;
char *zone_name;	/* zone which we are managing */
char pool_name[MAXNAMELEN];
char default_brand[MAXNAMELEN];
char brand_name[MAXNAMELEN];
boolean_t zone_isnative;
boolean_t zone_iscluster;
boolean_t zone_islabeled;
boolean_t shutdown_in_progress;
static zoneid_t zone_id;
dladm_handle_t dld_handle = NULL;

static char pre_statechg_hook[2 * MAXPATHLEN];
static char post_statechg_hook[2 * MAXPATHLEN];
char query_hook[2 * MAXPATHLEN];

zlog_t logsys;

mutex_t	lock = DEFAULTMUTEX;	/* to serialize stuff */
mutex_t	msglock = DEFAULTMUTEX;	/* for calling setlocale() */

static sema_t scratch_sem;	/* for scratch zones */

static char	zone_door_path[MAXPATHLEN];
static int	zone_door = -1;

boolean_t in_death_throes = B_FALSE;	/* daemon is dying */
boolean_t bringup_failure_recovery = B_FALSE; /* ignore certain failures */

#if !defined(TEXT_DOMAIN)		/* should be defined by cc -D */
#define	TEXT_DOMAIN	"SYS_TEST"	/* Use this only if it wasn't */
#endif

#define	DEFAULT_LOCALE	"C"

static const char *
z_cmd_name(zone_cmd_t zcmd)
{
	/* This list needs to match the enum in sys/zone.h */
	static const char *zcmdstr[] = {
		"ready", "boot", "forceboot", "reboot", "halt",
		"note_uninstalling", "mount", "forcemount", "unmount",
		"shutdown"
	};

	if (zcmd >= sizeof (zcmdstr) / sizeof (*zcmdstr))
		return ("unknown");
	else
		return (zcmdstr[(int)zcmd]);
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
usage(void)
{
	(void) fprintf(stderr, gettext("Usage: %s -z zonename\n"), progname);
	(void) fprintf(stderr,
	    gettext("\tNote: %s should not be run directly.\n"), progname);
	exit(2);
}

/* ARGSUSED */
static void
sigchld(int sig)
{
}

char *
localize_msg(char *locale, const char *msg)
{
	char *out;

	(void) mutex_lock(&msglock);
	(void) setlocale(LC_MESSAGES, locale);
	out = gettext(msg);
	(void) setlocale(LC_MESSAGES, DEFAULT_LOCALE);
	(void) mutex_unlock(&msglock);
	return (out);
}

/* PRINTFLIKE3 */
void
zerror(zlog_t *zlogp, boolean_t use_strerror, const char *fmt, ...)
{
	va_list alist;
	char buf[MAXPATHLEN * 2]; /* enough space for err msg with a path */
	char *bp;
	int saved_errno = errno;

	if (zlogp == NULL)
		return;
	if (zlogp == &logsys)
		(void) snprintf(buf, sizeof (buf), "[zone '%s'] ",
		    zone_name);
	else
		buf[0] = '\0';
	bp = &(buf[strlen(buf)]);

	/*
	 * In theory, the locale pointer should be set to either "C" or a
	 * char array, so it should never be NULL
	 */
	assert(zlogp->locale != NULL);
	/* Locale is per process, but we are multi-threaded... */
	fmt = localize_msg(zlogp->locale, fmt);

	va_start(alist, fmt);
	(void) vsnprintf(bp, sizeof (buf) - (bp - buf), fmt, alist);
	va_end(alist);
	bp = &(buf[strlen(buf)]);
	if (use_strerror)
		(void) snprintf(bp, sizeof (buf) - (bp - buf), ": %s",
		    strerror(saved_errno));
	if (zlogp == &logsys) {
		(void) syslog(LOG_ERR, "%s", buf);
	} else if (zlogp->logfile != NULL) {
		(void) fprintf(zlogp->logfile, "%s\n", buf);
	} else {
		size_t buflen;
		size_t copylen;

		buflen = snprintf(zlogp->log, zlogp->loglen, "%s\n", buf);
		copylen = MIN(buflen, zlogp->loglen);
		zlogp->log += copylen;
		zlogp->loglen -= copylen;
	}
}

/*
 * Emit a warning for any boot arguments which are unrecognized.  Since
 * Solaris boot arguments are getopt(3c) compatible (see kernel(1m)), we
 * put the arguments into an argv style array, use getopt to process them,
 * and put the resultant argument string back into outargs.
 *
 * During the filtering, we pull out any arguments which are truly "boot"
 * arguments, leaving only those which are to be passed intact to the
 * progenitor process.  The one we support at the moment is -i, which
 * indicates to the kernel which program should be launched as 'init'.
 *
 * A return of Z_INVAL indicates specifically that the arguments are
 * not valid; this is a non-fatal error.  Except for Z_OK, all other return
 * values are treated as fatal.
 */
static int
filter_bootargs(zlog_t *zlogp, const char *inargs, char *outargs,
    char *init_file, char *badarg)
{
	int argc = 0, argc_save;
	int i;
	int err;
	char *arg, *lasts, **argv = NULL, **argv_save;
	char zonecfg_args[BOOTARGS_MAX];
	char scratchargs[BOOTARGS_MAX], *sargs;
	char c;

	bzero(outargs, BOOTARGS_MAX);
	bzero(badarg, BOOTARGS_MAX);

	/*
	 * If the user didn't specify transient boot arguments, check
	 * to see if there were any specified in the zone configuration,
	 * and use them if applicable.
	 */
	if (inargs == NULL || inargs[0] == '\0')  {
		zone_dochandle_t handle;
		if ((handle = zonecfg_init_handle()) == NULL) {
			zerror(zlogp, B_TRUE,
			    "getting zone configuration handle");
			return (Z_BAD_HANDLE);
		}
		err = zonecfg_get_snapshot_handle(zone_name, handle);
		if (err != Z_OK) {
			zerror(zlogp, B_FALSE,
			    "invalid configuration snapshot");
			zonecfg_fini_handle(handle);
			return (Z_BAD_HANDLE);
		}

		bzero(zonecfg_args, sizeof (zonecfg_args));
		(void) zonecfg_get_bootargs(handle, zonecfg_args,
		    sizeof (zonecfg_args));
		inargs = zonecfg_args;
		zonecfg_fini_handle(handle);
	}

	if (strlen(inargs) >= BOOTARGS_MAX) {
		zerror(zlogp, B_FALSE, "boot argument string too long");
		return (Z_INVAL);
	}

	(void) strlcpy(scratchargs, inargs, sizeof (scratchargs));
	sargs = scratchargs;
	while ((arg = strtok_r(sargs, " \t", &lasts)) != NULL) {
		sargs = NULL;
		argc++;
	}

	if ((argv = calloc(argc + 1, sizeof (char *))) == NULL) {
		zerror(zlogp, B_FALSE, "memory allocation failed");
		return (Z_NOMEM);
	}

	argv_save = argv;
	argc_save = argc;

	(void) strlcpy(scratchargs, inargs, sizeof (scratchargs));
	sargs = scratchargs;
	i = 0;
	while ((arg = strtok_r(sargs, " \t", &lasts)) != NULL) {
		sargs = NULL;
		if ((argv[i] = strdup(arg)) == NULL) {
			err = Z_NOMEM;
			zerror(zlogp, B_FALSE, "memory allocation failed");
			goto done;
		}
		i++;
	}

	/*
	 * We preserve compatibility with the Solaris system boot behavior,
	 * which allows:
	 *
	 * 	# reboot kernel/unix -s -m verbose
	 *
	 * In this example, kernel/unix tells the booter what file to
	 * boot.  We don't want reboot in a zone to be gratuitously different,
	 * so we silently ignore the boot file, if necessary.
	 */
	if (argv[0] == NULL)
		goto done;

	assert(argv[0][0] != ' ');
	assert(argv[0][0] != '\t');

	if (argv[0][0] != '-' && argv[0][0] != '\0') {
		argv = &argv[1];
		argc--;
	}

	optind = 0;
	opterr = 0;
	err = Z_OK;
	while ((c = getopt(argc, argv, "fi:m:s")) != -1) {
		switch (c) {
		case 'i':
			/*
			 * -i is handled by the runtime and is not passed
			 * along to userland
			 */
			(void) strlcpy(init_file, optarg, MAXPATHLEN);
			break;
		case 'f':
			/* This has already been processed by zoneadm */
			break;
		case 'm':
		case 's':
			/* These pass through unmolested */
			(void) snprintf(outargs, BOOTARGS_MAX,
			    "%s -%c %s ", outargs, c, optarg ? optarg : "");
			break;
		case '?':
			/*
			 * We warn about unknown arguments but pass them
			 * along anyway-- if someone wants to develop their
			 * own init replacement, they can pass it whatever
			 * args they want.
			 */
			err = Z_INVAL;
			(void) snprintf(outargs, BOOTARGS_MAX,
			    "%s -%c", outargs, optopt);
			(void) snprintf(badarg, BOOTARGS_MAX,
			    "%s -%c", badarg, optopt);
			break;
		}
	}

	/*
	 * For Solaris Zones we warn about and discard non-option arguments.
	 * Hence 'boot foo bar baz gub' --> 'boot'.  However, to be similar
	 * to the kernel, we concat up all the other remaining boot args.
	 * and warn on them as a group.
	 */
	if (optind < argc) {
		err = Z_INVAL;
		while (optind < argc) {
			(void) snprintf(badarg, BOOTARGS_MAX, "%s%s%s",
			    badarg, strlen(badarg) > 0 ? " " : "",
			    argv[optind]);
			optind++;
		}
		zerror(zlogp, B_FALSE, "WARNING: Unused or invalid boot "
		    "arguments `%s'.", badarg);
	}

done:
	for (i = 0; i < argc_save; i++) {
		if (argv_save[i] != NULL)
			free(argv_save[i]);
	}
	free(argv_save);
	return (err);
}


static int
mkzonedir(zlog_t *zlogp)
{
	struct stat st;
	/*
	 * We must create and lock everyone but root out of ZONES_TMPDIR
	 * since anyone can open any UNIX domain socket, regardless of
	 * its file system permissions.  Sigh...
	 */
	if (mkdir(ZONES_TMPDIR, S_IRWXU) < 0 && errno != EEXIST) {
		zerror(zlogp, B_TRUE, "could not mkdir '%s'", ZONES_TMPDIR);
		return (-1);
	}
	/* paranoia */
	if ((stat(ZONES_TMPDIR, &st) < 0) || !S_ISDIR(st.st_mode)) {
		zerror(zlogp, B_TRUE, "'%s' is not a directory", ZONES_TMPDIR);
		return (-1);
	}
	(void) chmod(ZONES_TMPDIR, S_IRWXU);
	return (0);
}

/*
 * Run the brand's pre-state change callback, if it exists.
 */
static int
brand_prestatechg(zlog_t *zlogp, int state, int cmd)
{
	char cmdbuf[2 * MAXPATHLEN];
	const char *altroot;

	if (pre_statechg_hook[0] == '\0')
		return (0);

	altroot = zonecfg_get_root();
	if (snprintf(cmdbuf, sizeof (cmdbuf), "%s %d %d %s", pre_statechg_hook,
	    state, cmd, altroot) > sizeof (cmdbuf))
		return (-1);

	if (do_subproc(zlogp, cmdbuf, NULL) != 0)
		return (-1);

	return (0);
}

/*
 * Run the brand's post-state change callback, if it exists.
 */
static int
brand_poststatechg(zlog_t *zlogp, int state, int cmd)
{
	char cmdbuf[2 * MAXPATHLEN];
	const char *altroot;

	if (post_statechg_hook[0] == '\0')
		return (0);

	altroot = zonecfg_get_root();
	if (snprintf(cmdbuf, sizeof (cmdbuf), "%s %d %d %s", post_statechg_hook,
	    state, cmd, altroot) > sizeof (cmdbuf))
		return (-1);

	if (do_subproc(zlogp, cmdbuf, NULL) != 0)
		return (-1);

	return (0);
}

/*
 * Notify zonestatd of the new zone.  If zonestatd is not running, this
 * will do nothing.
 */
static void
notify_zonestatd(zoneid_t zoneid)
{
	int cmd[2];
	int fd;
	door_arg_t params;

	fd = open(ZS_DOOR_PATH, O_RDONLY);
	if (fd < 0)
		return;

	cmd[0] = ZSD_CMD_NEW_ZONE;
	cmd[1] = zoneid;
	params.data_ptr = (char *)&cmd;
	params.data_size = sizeof (cmd);
	params.desc_ptr = NULL;
	params.desc_num = 0;
	params.rbuf = NULL;
	params.rsize = NULL;
	(void) door_call(fd, &params);
	(void) close(fd);
}

/*
 * Bring a zone up to the pre-boot "ready" stage.  The mount_cmd argument is
 * 'true' if this is being invoked as part of the processing for the "mount"
 * subcommand.
 */
static int
zone_ready(zlog_t *zlogp, zone_mnt_t mount_cmd, int zstate)
{
	int err;

	if (brand_prestatechg(zlogp, zstate, Z_READY) != 0)
		return (-1);

	if ((err = zonecfg_create_snapshot(zone_name)) != Z_OK) {
		zerror(zlogp, B_FALSE, "unable to create snapshot: %s",
		    zonecfg_strerror(err));
		goto bad;
	}

	if ((zone_id = vplat_create(zlogp, mount_cmd)) == -1) {
		if ((err = zonecfg_destroy_snapshot(zone_name)) != Z_OK)
			zerror(zlogp, B_FALSE, "destroying snapshot: %s",
			    zonecfg_strerror(err));
		goto bad;
	}
	if (vplat_bringup(zlogp, mount_cmd, zone_id) != 0) {
		bringup_failure_recovery = B_TRUE;
		(void) vplat_teardown(NULL, (mount_cmd != Z_MNT_BOOT), B_FALSE);
		if ((err = zonecfg_destroy_snapshot(zone_name)) != Z_OK)
			zerror(zlogp, B_FALSE, "destroying snapshot: %s",
			    zonecfg_strerror(err));
		goto bad;
	}

	if (brand_poststatechg(zlogp, zstate, Z_READY) != 0)
		goto bad;

	return (0);

bad:
	/*
	 * If something goes wrong, we up the zones's state to the target
	 * state, READY, and then invoke the hook as if we're halting.
	 */
	(void) brand_poststatechg(zlogp, ZONE_STATE_READY, Z_HALT);
	return (-1);
}

int
init_template(void)
{
	int fd;
	int err = 0;

	fd = open64(CTFS_ROOT "/process/template", O_RDWR);
	if (fd == -1)
		return (-1);

	/*
	 * For now, zoneadmd doesn't do anything with the contract.
	 * Deliver no events, don't inherit, and allow it to be orphaned.
	 */
	err |= ct_tmpl_set_critical(fd, 0);
	err |= ct_tmpl_set_informative(fd, 0);
	err |= ct_pr_tmpl_set_fatal(fd, CT_PR_EV_HWERR);
	err |= ct_pr_tmpl_set_param(fd, CT_PR_PGRPONLY | CT_PR_REGENT);
	if (err || ct_tmpl_activate(fd)) {
		(void) close(fd);
		return (-1);
	}

	return (fd);
}

typedef struct fs_callback {
	zlog_t		*zlogp;
	zoneid_t	zoneid;
	boolean_t	mount_cmd;
} fs_callback_t;

static int
mount_early_fs(void *data, const char *spec, const char *dir,
    const char *fstype, const char *opt)
{
	zlog_t *zlogp = ((fs_callback_t *)data)->zlogp;
	zoneid_t zoneid = ((fs_callback_t *)data)->zoneid;
	boolean_t mount_cmd = ((fs_callback_t *)data)->mount_cmd;
	char rootpath[MAXPATHLEN];
	pid_t child;
	int child_status;
	int tmpl_fd;
	int rv;
	ctid_t ct;

	/* determine the zone rootpath */
	if (mount_cmd) {
		char zonepath[MAXPATHLEN];
		char luroot[MAXPATHLEN];

		if (zone_get_zonepath(zone_name,
		    zonepath, sizeof (zonepath)) != Z_OK) {
			zerror(zlogp, B_FALSE, "unable to determine zone path");
			return (-1);
		}

		(void) snprintf(luroot, sizeof (luroot), "%s/lu", zonepath);
		resolve_lofs(zlogp, luroot, sizeof (luroot));
		(void) strlcpy(rootpath, luroot, sizeof (rootpath));
	} else {
		if (zone_get_rootpath(zone_name,
		    rootpath, sizeof (rootpath)) != Z_OK) {
			zerror(zlogp, B_FALSE, "unable to determine zone root");
			return (-1);
		}
	}

	if ((rv = valid_mount_path(zlogp, rootpath, spec, dir, fstype)) < 0) {
		zerror(zlogp, B_FALSE, "%s%s is not a valid mount point",
		    rootpath, dir);
		return (-1);
	} else if (rv > 0) {
		/* The mount point path doesn't exist, create it now. */
		if (make_one_dir(zlogp, rootpath, dir,
		    DEFAULT_DIR_MODE, DEFAULT_DIR_USER,
		    DEFAULT_DIR_GROUP) != 0) {
			zerror(zlogp, B_FALSE, "failed to create mount point");
			return (-1);
		}

		/*
		 * Now this might seem weird, but we need to invoke
		 * valid_mount_path() again.  Why?  Because it checks
		 * to make sure that the mount point path is canonical,
		 * which it can only do if the path exists, so now that
		 * we've created the path we have to verify it again.
		 */
		if ((rv = valid_mount_path(zlogp, rootpath, spec, dir,
		    fstype)) < 0) {
			zerror(zlogp, B_FALSE,
			    "%s%s is not a valid mount point", rootpath, dir);
			return (-1);
		}
	}

	if ((tmpl_fd = init_template()) == -1) {
		zerror(zlogp, B_TRUE, "failed to create contract");
		return (-1);
	}

	if ((child = fork()) == -1) {
		(void) ct_tmpl_clear(tmpl_fd);
		(void) close(tmpl_fd);
		zerror(zlogp, B_TRUE, "failed to fork");
		return (-1);

	} else if (child == 0) {	/* child */
		char opt_buf[MAX_MNTOPT_STR];
		int optlen = 0;
		int mflag = MS_DATA;

		(void) ct_tmpl_clear(tmpl_fd);
		/*
		 * Even though there are no procs running in the zone, we
		 * do this for paranoia's sake.
		 */
		(void) closefrom(0);

		if (zone_enter(zoneid) == -1) {
			_exit(errno);
		}
		if (opt != NULL) {
			/*
			 * The mount() system call is incredibly annoying.
			 * If options are specified, we need to copy them
			 * into a temporary buffer since the mount() system
			 * call will overwrite the options string.  It will
			 * also fail if the new option string it wants to
			 * write is bigger than the one we passed in, so
			 * you must pass in a buffer of the maximum possible
			 * option string length.  sigh.
			 */
			(void) strlcpy(opt_buf, opt, sizeof (opt_buf));
			opt = opt_buf;
			optlen = MAX_MNTOPT_STR;
			mflag = MS_OPTIONSTR;
		}
		if (mount(spec, dir, mflag, fstype, NULL, 0, opt, optlen) != 0)
			_exit(errno);
		_exit(0);
	}

	/* parent */
	if (contract_latest(&ct) == -1)
		ct = -1;
	(void) ct_tmpl_clear(tmpl_fd);
	(void) close(tmpl_fd);
	if (waitpid(child, &child_status, 0) != child) {
		/* unexpected: we must have been signalled */
		(void) contract_abandon_id(ct);
		return (-1);
	}
	(void) contract_abandon_id(ct);
	if (WEXITSTATUS(child_status) != 0) {
		errno = WEXITSTATUS(child_status);
		zerror(zlogp, B_TRUE, "mount of %s failed", dir);
		return (-1);
	}

	return (0);
}

/*
 * If retstr is not NULL, the output of the subproc is returned in the str,
 * otherwise it is output using zerror().  Any memory allocated for retstr
 * should be freed by the caller.
 */
int
do_subproc(zlog_t *zlogp, char *cmdbuf, char **retstr)
{
	char buf[1024];		/* arbitrary large amount */
	char *inbuf;
	FILE *file;
	int status;
	int rd_cnt;

	if (retstr != NULL) {
		if ((*retstr = malloc(1024)) == NULL) {
			zerror(zlogp, B_FALSE, "out of memory");
			return (-1);
		}
		inbuf = *retstr;
		rd_cnt = 0;
	} else {
		inbuf = buf;
	}

	file = popen(cmdbuf, "r");
	if (file == NULL) {
		zerror(zlogp, B_TRUE, "could not launch: %s", cmdbuf);
		return (-1);
	}

	while (fgets(inbuf, 1024, file) != NULL) {
		if (retstr == NULL) {
			if (zlogp != &logsys)
				zerror(zlogp, B_FALSE, "%s", inbuf);
		} else {
			char *p;

			rd_cnt += 1024 - 1;
			if ((p = realloc(*retstr, rd_cnt + 1024)) == NULL) {
				zerror(zlogp, B_FALSE, "out of memory");
				(void) pclose(file);
				return (-1);
			}

			*retstr = p;
			inbuf = *retstr + rd_cnt;
		}
	}
	status = pclose(file);

	if (WIFSIGNALED(status)) {
		zerror(zlogp, B_FALSE, "%s unexpectedly terminated due to "
		    "signal %d", cmdbuf, WTERMSIG(status));
		return (-1);
	}
	assert(WIFEXITED(status));
	if (WEXITSTATUS(status) == ZEXIT_EXEC) {
		zerror(zlogp, B_FALSE, "failed to exec %s", cmdbuf);
		return (-1);
	}
	return (WEXITSTATUS(status));
}

static int
zone_bootup(zlog_t *zlogp, const char *bootargs, int zstate)
{
	zoneid_t zoneid;
	struct stat st;
	char zpath[MAXPATHLEN], initpath[MAXPATHLEN], init_file[MAXPATHLEN];
	char nbootargs[BOOTARGS_MAX];
	char cmdbuf[MAXPATHLEN];
	fs_callback_t cb;
	brand_handle_t bh;
	zone_iptype_t iptype;
	boolean_t links_loaded = B_FALSE;
	dladm_status_t status;
	char errmsg[DLADM_STRSIZE];
	int err;
	boolean_t restart_init;

	if (brand_prestatechg(zlogp, zstate, Z_BOOT) != 0)
		return (-1);

	if ((zoneid = getzoneidbyname(zone_name)) == -1) {
		zerror(zlogp, B_TRUE, "unable to get zoneid");
		goto bad;
	}

	cb.zlogp = zlogp;
	cb.zoneid = zoneid;
	cb.mount_cmd = B_FALSE;

	/* Get a handle to the brand info for this zone */
	if ((bh = brand_open(brand_name)) == NULL) {
		zerror(zlogp, B_FALSE, "unable to determine zone brand");
		goto bad;
	}

	/*
	 * Get the list of filesystems to mount from the brand
	 * configuration.  These mounts are done via a thread that will
	 * enter the zone, so they are done from within the context of the
	 * zone.
	 */
	if (brand_platform_iter_mounts(bh, mount_early_fs, &cb) != 0) {
		zerror(zlogp, B_FALSE, "unable to mount filesystems");
		brand_close(bh);
		goto bad;
	}

	/*
	 * Get the brand's boot callback if it exists.
	 */
	if (zone_get_zonepath(zone_name, zpath, sizeof (zpath)) != Z_OK) {
		zerror(zlogp, B_FALSE, "unable to determine zone path");
		brand_close(bh);
		goto bad;
	}
	(void) strcpy(cmdbuf, EXEC_PREFIX);
	if (brand_get_boot(bh, zone_name, zpath, cmdbuf + EXEC_LEN,
	    sizeof (cmdbuf) - EXEC_LEN) != 0) {
		zerror(zlogp, B_FALSE,
		    "unable to determine branded zone's boot callback");
		brand_close(bh);
		goto bad;
	}

	/* Get the path for this zone's init(1M) (or equivalent) process.  */
	if (brand_get_initname(bh, init_file, MAXPATHLEN) != 0) {
		zerror(zlogp, B_FALSE,
		    "unable to determine zone's init(1M) location");
		brand_close(bh);
		goto bad;
	}

	/* See if this zone's brand should restart init if it dies. */
	restart_init = brand_restartinit(bh);

	brand_close(bh);

	err = filter_bootargs(zlogp, bootargs, nbootargs, init_file,
	    bad_boot_arg);
	if (err == Z_INVAL)
		eventstream_write(Z_EVT_ZONE_BADARGS);
	else if (err != Z_OK)
		goto bad;

	assert(init_file[0] != '\0');

	/* Try to anticipate possible problems: Make sure init is executable. */
	if (zone_get_rootpath(zone_name, zpath, sizeof (zpath)) != Z_OK) {
		zerror(zlogp, B_FALSE, "unable to determine zone root");
		goto bad;
	}

	(void) snprintf(initpath, sizeof (initpath), "%s%s", zpath, init_file);

	if (stat(initpath, &st) == -1) {
		zerror(zlogp, B_TRUE, "could not stat %s", initpath);
		goto bad;
	}

	if ((st.st_mode & S_IXUSR) == 0) {
		zerror(zlogp, B_FALSE, "%s is not executable", initpath);
		goto bad;
	}

	/*
	 * Exclusive stack zones interact with the dlmgmtd running in the
	 * global zone.  dladm_zone_boot() tells dlmgmtd that this zone is
	 * booting, and loads its datalinks from the zone's datalink
	 * configuration file.
	 */
	if (vplat_get_iptype(zlogp, &iptype) == 0 && iptype == ZS_EXCLUSIVE) {
		status = dladm_zone_boot(dld_handle, zoneid);
		if (status != DLADM_STATUS_OK) {
			zerror(zlogp, B_FALSE, "unable to load zone datalinks: "
			    " %s", dladm_status2str(status, errmsg));
			goto bad;
		}
		links_loaded = B_TRUE;
	}

	/*
	 * If there is a brand 'boot' callback, execute it now to give the
	 * brand one last chance to do any additional setup before the zone
	 * is booted.
	 */
	if ((strlen(cmdbuf) > EXEC_LEN) &&
	    (do_subproc(zlogp, cmdbuf, NULL) != Z_OK)) {
		zerror(zlogp, B_FALSE, "%s failed", cmdbuf);
		goto bad;
	}

	if (zone_setattr(zoneid, ZONE_ATTR_INITNAME, init_file, 0) == -1) {
		zerror(zlogp, B_TRUE, "could not set zone boot file");
		goto bad;
	}

	if (zone_setattr(zoneid, ZONE_ATTR_BOOTARGS, nbootargs, 0) == -1) {
		zerror(zlogp, B_TRUE, "could not set zone boot arguments");
		goto bad;
	}

	if (!restart_init && zone_setattr(zoneid, ZONE_ATTR_INITNORESTART,
	    NULL, 0) == -1) {
		zerror(zlogp, B_TRUE, "could not set zone init-no-restart");
		goto bad;
	}

	/*
	 * Inform zonestatd of a new zone so that it can install a door for
	 * the zone to contact it.
	 */
	notify_zonestatd(zone_id);

	if (zone_boot(zoneid) == -1) {
		zerror(zlogp, B_TRUE, "unable to boot zone");
		goto bad;
	}

	if (brand_poststatechg(zlogp, zstate, Z_BOOT) != 0)
		goto bad;

	return (0);

bad:
	/*
	 * If something goes wrong, we up the zones's state to the target
	 * state, RUNNING, and then invoke the hook as if we're halting.
	 */
	(void) brand_poststatechg(zlogp, ZONE_STATE_RUNNING, Z_HALT);
	if (links_loaded)
		(void) dladm_zone_halt(dld_handle, zoneid);
	return (-1);
}

static int
zone_halt(zlog_t *zlogp, boolean_t unmount_cmd, boolean_t rebooting, int zstate)
{
	int err;

	if (brand_prestatechg(zlogp, zstate, Z_HALT) != 0)
		return (-1);

	if (vplat_teardown(zlogp, unmount_cmd, rebooting) != 0) {
		if (!bringup_failure_recovery)
			zerror(zlogp, B_FALSE, "unable to destroy zone");
		return (-1);
	}

	if ((err = zonecfg_destroy_snapshot(zone_name)) != Z_OK)
		zerror(zlogp, B_FALSE, "destroying snapshot: %s",
		    zonecfg_strerror(err));

	if (brand_poststatechg(zlogp, zstate, Z_HALT) != 0)
		return (-1);

	return (0);
}

static int
zone_graceful_shutdown(zlog_t *zlogp)
{
	zoneid_t zoneid;
	pid_t child;
	char cmdbuf[MAXPATHLEN];
	brand_handle_t bh = NULL;
	char zpath[MAXPATHLEN];
	ctid_t ct;
	int tmpl_fd;
	int child_status;

	if (shutdown_in_progress) {
		zerror(zlogp, B_FALSE, "shutdown already in progress");
		return (-1);
	}

	if ((zoneid = getzoneidbyname(zone_name)) == -1) {
		zerror(zlogp, B_TRUE, "unable to get zoneid");
		return (-1);
	}

	/* Get a handle to the brand info for this zone */
	if ((bh = brand_open(brand_name)) == NULL) {
		zerror(zlogp, B_FALSE, "unable to determine zone brand");
		return (-1);
	}

	if (zone_get_zonepath(zone_name, zpath, sizeof (zpath)) != Z_OK) {
		zerror(zlogp, B_FALSE, "unable to determine zone path");
		brand_close(bh);
		return (-1);
	}

	/*
	 * If there is a brand 'shutdown' callback, execute it now to give the
	 * brand a chance to cleanup any custom configuration.
	 */
	(void) strcpy(cmdbuf, EXEC_PREFIX);
	if (brand_get_shutdown(bh, zone_name, zpath, cmdbuf + EXEC_LEN,
	    sizeof (cmdbuf) - EXEC_LEN) != 0 || strlen(cmdbuf) <= EXEC_LEN) {
		(void) strcat(cmdbuf, SHUTDOWN_DEFAULT);
	}
	brand_close(bh);

	if ((tmpl_fd = init_template()) == -1) {
		zerror(zlogp, B_TRUE, "failed to create contract");
		return (-1);
	}

	if ((child = fork()) == -1) {
		(void) ct_tmpl_clear(tmpl_fd);
		(void) close(tmpl_fd);
		zerror(zlogp, B_TRUE, "failed to fork");
		return (-1);
	} else if (child == 0) {
		(void) ct_tmpl_clear(tmpl_fd);
		if (zone_enter(zoneid) == -1) {
			_exit(errno);
		}
		_exit(execl("/bin/sh", "sh", "-c", cmdbuf, (char *)NULL));
	}

	if (contract_latest(&ct) == -1)
		ct = -1;
	(void) ct_tmpl_clear(tmpl_fd);
	(void) close(tmpl_fd);

	if (waitpid(child, &child_status, 0) != child) {
		/* unexpected: we must have been signalled */
		(void) contract_abandon_id(ct);
		return (-1);
	}

	(void) contract_abandon_id(ct);
	if (WEXITSTATUS(child_status) != 0) {
		errno = WEXITSTATUS(child_status);
		zerror(zlogp, B_FALSE, "unable to shutdown zone");
		return (-1);
	}

	shutdown_in_progress = B_TRUE;

	return (0);
}

static int
zone_wait_shutdown(zlog_t *zlogp)
{
	zone_state_t zstate;
	uint64_t *tm = NULL;
	scf_simple_prop_t *prop = NULL;
	int timeout;
	int tries;
	int rc = -1;

	/* Get default stop timeout from SMF framework */
	timeout = SHUTDOWN_WAIT;
	if ((prop = scf_simple_prop_get(NULL, SHUTDOWN_FMRI, "stop",
	    SCF_PROPERTY_TIMEOUT)) != NULL) {
		if ((tm = scf_simple_prop_next_count(prop)) != NULL) {
			if (tm != 0)
				timeout = *tm;
		}
		scf_simple_prop_free(prop);
	}

	/* allow time for zone to shutdown cleanly */
	for (tries = 0; tries < timeout; tries ++) {
		(void) sleep(1);
		if (zone_get_state(zone_name, &zstate) == Z_OK &&
		    zstate == ZONE_STATE_INSTALLED) {
			rc = 0;
			break;
		}
	}

	if (rc != 0)
		zerror(zlogp, B_FALSE, "unable to shutdown zone");

	shutdown_in_progress = B_FALSE;

	return (rc);
}



/*
 * Generate AUE_zone_state for a command that boots a zone.
 */
static void
audit_put_record(zlog_t *zlogp, ucred_t *uc, int return_val,
    char *new_state)
{
	adt_session_data_t	*ah;
	adt_event_data_t	*event;
	int			pass_fail, fail_reason;

	if (!adt_audit_enabled())
		return;

	if (return_val == 0) {
		pass_fail = ADT_SUCCESS;
		fail_reason = ADT_SUCCESS;
	} else {
		pass_fail = ADT_FAILURE;
		fail_reason = ADT_FAIL_VALUE_PROGRAM;
	}

	if (adt_start_session(&ah, NULL, 0)) {
		zerror(zlogp, B_TRUE, gettext("audit failure."));
		return;
	}
	if (adt_set_from_ucred(ah, uc, ADT_NEW)) {
		zerror(zlogp, B_TRUE, gettext("audit failure."));
		(void) adt_end_session(ah);
		return;
	}

	event = adt_alloc_event(ah, ADT_zone_state);
	if (event == NULL) {
		zerror(zlogp, B_TRUE, gettext("audit failure."));
		(void) adt_end_session(ah);
		return;
	}
	event->adt_zone_state.zonename = zone_name;
	event->adt_zone_state.new_state = new_state;

	if (adt_put_event(event, pass_fail, fail_reason))
		zerror(zlogp, B_TRUE, gettext("audit failure."));

	adt_free_event(event);

	(void) adt_end_session(ah);
}

/*
 * The main routine for the door server that deals with zone state transitions.
 */
/* ARGSUSED */
static void
server(void *cookie, char *args, size_t alen, door_desc_t *dp,
    uint_t n_desc)
{
	ucred_t *uc = NULL;
	const priv_set_t *eset;

	zone_state_t zstate;
	zone_cmd_t cmd;
	zone_cmd_arg_t *zargp;

	boolean_t kernelcall;

	int rval = -1;
	uint64_t uniqid;
	zoneid_t zoneid = -1;
	zlog_t zlog;
	zlog_t *zlogp;
	zone_cmd_rval_t *rvalp;
	size_t rlen = getpagesize(); /* conservative */
	fs_callback_t cb;
	brand_handle_t bh;
	boolean_t wait_shut = B_FALSE;

	/* LINTED E_BAD_PTR_CAST_ALIGN */
	zargp = (zone_cmd_arg_t *)args;

	/*
	 * When we get the door unref message, we've fdetach'd the door, and
	 * it is time for us to shut down zoneadmd.
	 */
	if (zargp == DOOR_UNREF_DATA) {
		/*
		 * See comment at end of main() for info on the last rites.
		 */
		exit(0);
	}

	if (zargp == NULL) {
		(void) door_return(NULL, 0, 0, 0);
	}

	rvalp = alloca(rlen);
	bzero(rvalp, rlen);
	zlog.logfile = NULL;
	zlog.buflen = zlog.loglen = rlen - sizeof (zone_cmd_rval_t) + 1;
	zlog.buf = rvalp->errbuf;
	zlog.log = zlog.buf;
	/* defer initialization of zlog.locale until after credential check */
	zlogp = &zlog;

	if (alen != sizeof (zone_cmd_arg_t)) {
		/*
		 * This really shouldn't be happening.
		 */
		zerror(&logsys, B_FALSE, "argument size (%d bytes) "
		    "unexpected (expected %d bytes)", alen,
		    sizeof (zone_cmd_arg_t));
		goto out;
	}
	cmd = zargp->cmd;

	if (door_ucred(&uc) != 0) {
		zerror(&logsys, B_TRUE, "door_ucred");
		goto out;
	}
	eset = ucred_getprivset(uc, PRIV_EFFECTIVE);
	if (ucred_getzoneid(uc) != GLOBAL_ZONEID ||
	    (eset != NULL ? !priv_ismember(eset, PRIV_SYS_CONFIG) :
	    ucred_geteuid(uc) != 0)) {
		zerror(&logsys, B_FALSE, "insufficient privileges");
		goto out;
	}

	kernelcall = ucred_getpid(uc) == 0;

	/*
	 * This is safe because we only use a zlog_t throughout the
	 * duration of a door call; i.e., by the time the pointer
	 * might become invalid, the door call would be over.
	 */
	zlog.locale = kernelcall ? DEFAULT_LOCALE : zargp->locale;

	(void) mutex_lock(&lock);

	/*
	 * Once we start to really die off, we don't want more connections.
	 */
	if (in_death_throes) {
		(void) mutex_unlock(&lock);
		ucred_free(uc);
		(void) door_return(NULL, 0, 0, 0);
		thr_exit(NULL);
	}

	/*
	 * Check for validity of command.
	 */
	if (cmd != Z_READY && cmd != Z_BOOT && cmd != Z_FORCEBOOT &&
	    cmd != Z_REBOOT && cmd != Z_SHUTDOWN && cmd != Z_HALT &&
	    cmd != Z_NOTE_UNINSTALLING && cmd != Z_MOUNT &&
	    cmd != Z_FORCEMOUNT && cmd != Z_UNMOUNT) {
		zerror(&logsys, B_FALSE, "invalid command %d", (int)cmd);
		goto out;
	}

	if (kernelcall && (cmd != Z_HALT && cmd != Z_REBOOT)) {
		/*
		 * Can't happen
		 */
		zerror(&logsys, B_FALSE, "received unexpected kernel upcall %d",
		    cmd);
		goto out;
	}
	/*
	 * We ignore the possibility of someone calling zone_create(2)
	 * explicitly; all requests must come through zoneadmd.
	 */
	if (zone_get_state(zone_name, &zstate) != Z_OK) {
		/*
		 * Something terribly wrong happened
		 */
		zerror(&logsys, B_FALSE, "unable to determine state of zone");
		goto out;
	}

	if (kernelcall) {
		/*
		 * Kernel-initiated requests may lose their validity if the
		 * zone_t the kernel was referring to has gone away.
		 */
		if ((zoneid = getzoneidbyname(zone_name)) == -1 ||
		    zone_getattr(zoneid, ZONE_ATTR_UNIQID, &uniqid,
		    sizeof (uniqid)) == -1 || uniqid != zargp->uniqid) {
			/*
			 * We're not talking about the same zone. The request
			 * must have arrived too late.  Return error.
			 */
			rval = -1;
			goto out;
		}
		zlogp = &logsys;	/* Log errors to syslog */
	}

	/*
	 * If we are being asked to forcibly mount or boot a zone, we
	 * pretend that an INCOMPLETE zone is actually INSTALLED.
	 */
	if (zstate == ZONE_STATE_INCOMPLETE &&
	    (cmd == Z_FORCEBOOT || cmd == Z_FORCEMOUNT))
		zstate = ZONE_STATE_INSTALLED;

	switch (zstate) {
	case ZONE_STATE_CONFIGURED:
	case ZONE_STATE_INCOMPLETE:
		/*
		 * Not our area of expertise; we just print a nice message
		 * and die off.
		 */
		zerror(zlogp, B_FALSE,
		    "%s operation is invalid for zones in state '%s'",
		    z_cmd_name(cmd), zone_state_str(zstate));
		break;

	case ZONE_STATE_INSTALLED:
		switch (cmd) {
		case Z_READY:
			rval = zone_ready(zlogp, Z_MNT_BOOT, zstate);
			if (rval == 0)
				eventstream_write(Z_EVT_ZONE_READIED);
			break;
		case Z_BOOT:
		case Z_FORCEBOOT:
			eventstream_write(Z_EVT_ZONE_BOOTING);
			if ((rval = zone_ready(zlogp, Z_MNT_BOOT, zstate))
			    == 0) {
				rval = zone_bootup(zlogp, zargp->bootbuf,
				    zstate);
			}
			audit_put_record(zlogp, uc, rval, "boot");
			if (rval != 0) {
				bringup_failure_recovery = B_TRUE;
				(void) zone_halt(zlogp, B_FALSE, B_FALSE,
				    zstate);
				eventstream_write(Z_EVT_ZONE_BOOTFAILED);
			}
			break;
		case Z_SHUTDOWN:
		case Z_HALT:
			if (kernelcall)	/* Invalid; can't happen */
				abort();
			/*
			 * We could have two clients racing to halt this
			 * zone; the second client loses, but his request
			 * doesn't fail, since the zone is now in the desired
			 * state.
			 */
			zerror(zlogp, B_FALSE, "zone is already halted");
			rval = 0;
			break;
		case Z_REBOOT:
			if (kernelcall)	/* Invalid; can't happen */
				abort();
			zerror(zlogp, B_FALSE, "%s operation is invalid "
			    "for zones in state '%s'", z_cmd_name(cmd),
			    zone_state_str(zstate));
			rval = -1;
			break;
		case Z_NOTE_UNINSTALLING:
			if (kernelcall)	/* Invalid; can't happen */
				abort();
			/*
			 * Tell the console to print out a message about this.
			 * Once it does, we will be in_death_throes.
			 */
			eventstream_write(Z_EVT_ZONE_UNINSTALLING);
			break;
		case Z_MOUNT:
		case Z_FORCEMOUNT:
			if (kernelcall)	/* Invalid; can't happen */
				abort();
			if (!zone_isnative && !zone_iscluster &&
			    !zone_islabeled) {
				/*
				 * -U mounts the zone without lofs mounting
				 * zone file systems back into the scratch
				 * zone.  This is required when mounting
				 * non-native branded zones.
				 */
				(void) strlcpy(zargp->bootbuf, "-U",
				    BOOTARGS_MAX);
			}

			rval = zone_ready(zlogp,
			    strcmp(zargp->bootbuf, "-U") == 0 ?
			    Z_MNT_UPDATE : Z_MNT_SCRATCH, zstate);
			if (rval != 0)
				break;

			eventstream_write(Z_EVT_ZONE_READIED);

			/*
			 * Get a handle to the default brand info.
			 * We must always use the default brand file system
			 * list when mounting the zone.
			 */
			if ((bh = brand_open(default_brand)) == NULL) {
				rval = -1;
				break;
			}

			/*
			 * Get the list of filesystems to mount from
			 * the brand configuration.  These mounts are done
			 * via a thread that will enter the zone, so they
			 * are done from within the context of the zone.
			 */
			cb.zlogp = zlogp;
			cb.zoneid = zone_id;
			cb.mount_cmd = B_TRUE;
			rval = brand_platform_iter_mounts(bh,
			    mount_early_fs, &cb);

			brand_close(bh);

			/*
			 * Ordinarily, /dev/fd would be mounted inside the zone
			 * by svc:/system/filesystem/usr:default, but since
			 * we're not booting the zone, we need to do this
			 * manually.
			 */
			if (rval == 0)
				rval = mount_early_fs(&cb,
				    "fd", "/dev/fd", "fd", NULL);
			break;
		case Z_UNMOUNT:
			if (kernelcall)	/* Invalid; can't happen */
				abort();
			zerror(zlogp, B_FALSE, "zone is already unmounted");
			rval = 0;
			break;
		}
		break;

	case ZONE_STATE_READY:
		switch (cmd) {
		case Z_READY:
			/*
			 * We could have two clients racing to ready this
			 * zone; the second client loses, but his request
			 * doesn't fail, since the zone is now in the desired
			 * state.
			 */
			zerror(zlogp, B_FALSE, "zone is already ready");
			rval = 0;
			break;
		case Z_BOOT:
			(void) strlcpy(boot_args, zargp->bootbuf,
			    sizeof (boot_args));
			eventstream_write(Z_EVT_ZONE_BOOTING);
			rval = zone_bootup(zlogp, zargp->bootbuf, zstate);
			audit_put_record(zlogp, uc, rval, "boot");
			if (rval != 0) {
				bringup_failure_recovery = B_TRUE;
				(void) zone_halt(zlogp, B_FALSE, B_TRUE,
				    zstate);
				eventstream_write(Z_EVT_ZONE_BOOTFAILED);
			}
			boot_args[0] = '\0';
			break;
		case Z_HALT:
			if (kernelcall)	/* Invalid; can't happen */
				abort();
			if ((rval = zone_halt(zlogp, B_FALSE, B_FALSE, zstate))
			    != 0)
				break;
			eventstream_write(Z_EVT_ZONE_HALTED);
			break;
		case Z_SHUTDOWN:
		case Z_REBOOT:
		case Z_NOTE_UNINSTALLING:
		case Z_MOUNT:
		case Z_UNMOUNT:
			if (kernelcall)	/* Invalid; can't happen */
				abort();
			zerror(zlogp, B_FALSE, "%s operation is invalid "
			    "for zones in state '%s'", z_cmd_name(cmd),
			    zone_state_str(zstate));
			rval = -1;
			break;
		}
		break;

	case ZONE_STATE_MOUNTED:
		switch (cmd) {
		case Z_UNMOUNT:
			if (kernelcall)	/* Invalid; can't happen */
				abort();
			rval = zone_halt(zlogp, B_TRUE, B_FALSE, zstate);
			if (rval == 0) {
				eventstream_write(Z_EVT_ZONE_HALTED);
				(void) sema_post(&scratch_sem);
			}
			break;
		default:
			if (kernelcall)	/* Invalid; can't happen */
				abort();
			zerror(zlogp, B_FALSE, "%s operation is invalid "
			    "for zones in state '%s'", z_cmd_name(cmd),
			    zone_state_str(zstate));
			rval = -1;
			break;
		}
		break;

	case ZONE_STATE_RUNNING:
	case ZONE_STATE_SHUTTING_DOWN:
	case ZONE_STATE_DOWN:
		switch (cmd) {
		case Z_READY:
			if ((rval = zone_halt(zlogp, B_FALSE, B_TRUE, zstate))
			    != 0)
				break;
			if ((rval = zone_ready(zlogp, Z_MNT_BOOT, zstate)) == 0)
				eventstream_write(Z_EVT_ZONE_READIED);
			else
				eventstream_write(Z_EVT_ZONE_HALTED);
			break;
		case Z_BOOT:
			/*
			 * We could have two clients racing to boot this
			 * zone; the second client loses, but his request
			 * doesn't fail, since the zone is now in the desired
			 * state.
			 */
			zerror(zlogp, B_FALSE, "zone is already booted");
			rval = 0;
			break;
		case Z_HALT:
			if ((rval = zone_halt(zlogp, B_FALSE, B_FALSE, zstate))
			    != 0)
				break;
			eventstream_write(Z_EVT_ZONE_HALTED);
			break;
		case Z_REBOOT:
			(void) strlcpy(boot_args, zargp->bootbuf,
			    sizeof (boot_args));
			eventstream_write(Z_EVT_ZONE_REBOOTING);
			if ((rval = zone_halt(zlogp, B_FALSE, B_TRUE, zstate))
			    != 0) {
				eventstream_write(Z_EVT_ZONE_BOOTFAILED);
				boot_args[0] = '\0';
				break;
			}
			if ((rval = zone_ready(zlogp, Z_MNT_BOOT, zstate))
			    != 0) {
				eventstream_write(Z_EVT_ZONE_BOOTFAILED);
				boot_args[0] = '\0';
				break;
			}
			rval = zone_bootup(zlogp, zargp->bootbuf, zstate);
			audit_put_record(zlogp, uc, rval, "reboot");
			if (rval != 0) {
				(void) zone_halt(zlogp, B_FALSE, B_TRUE,
				    zstate);
				eventstream_write(Z_EVT_ZONE_BOOTFAILED);
			}
			boot_args[0] = '\0';
			break;
		case Z_SHUTDOWN:
			if ((rval = zone_graceful_shutdown(zlogp)) == 0) {
				wait_shut = B_TRUE;
			}
			break;
		case Z_NOTE_UNINSTALLING:
		case Z_MOUNT:
		case Z_UNMOUNT:
			zerror(zlogp, B_FALSE, "%s operation is invalid "
			    "for zones in state '%s'", z_cmd_name(cmd),
			    zone_state_str(zstate));
			rval = -1;
			break;
		}
		break;
	default:
		abort();
	}

	/*
	 * Because the state of the zone may have changed, we make sure
	 * to wake the console poller, which is in charge of initiating
	 * the shutdown procedure as necessary.
	 */
	eventstream_write(Z_EVT_NULL);

out:
	(void) mutex_unlock(&lock);

	/* Wait for the Z_SHUTDOWN commands to complete */
	if (wait_shut)
		rval = zone_wait_shutdown(zlogp);

	if (kernelcall) {
		rvalp = NULL;
		rlen = 0;
	} else {
		rvalp->rval = rval;
	}
	if (uc != NULL)
		ucred_free(uc);
	(void) door_return((char *)rvalp, rlen, NULL, 0);
	thr_exit(NULL);
}

static int
setup_door(zlog_t *zlogp)
{
	if ((zone_door = door_create(server, NULL,
	    DOOR_UNREF | DOOR_REFUSE_DESC | DOOR_NO_CANCEL)) < 0) {
		zerror(zlogp, B_TRUE, "%s failed", "door_create");
		return (-1);
	}
	(void) fdetach(zone_door_path);

	if (fattach(zone_door, zone_door_path) != 0) {
		zerror(zlogp, B_TRUE, "fattach to %s failed", zone_door_path);
		(void) door_revoke(zone_door);
		(void) fdetach(zone_door_path);
		zone_door = -1;
		return (-1);
	}
	return (0);
}

/*
 * zoneadm(1m) will start zoneadmd if it thinks it isn't running; this
 * is where zoneadmd itself will check to see that another instance of
 * zoneadmd isn't already controlling this zone.
 *
 * The idea here is that we want to open the path to which we will
 * attach our door, lock it, and then make sure that no-one has beat us
 * to fattach(3c)ing onto it.
 *
 * fattach(3c) is really a mount, so there are actually two possible
 * vnodes we could be dealing with.  Our strategy is as follows:
 *
 * - If the file we opened is a regular file (common case):
 * 	There is no fattach(3c)ed door, so we have a chance of becoming
 * 	the managing zoneadmd. We attempt to lock the file: if it is
 * 	already locked, that means someone else raced us here, so we
 * 	lose and give up.  zoneadm(1m) will try to contact the zoneadmd
 * 	that beat us to it.
 *
 * - If the file we opened is a namefs file:
 * 	This means there is already an established door fattach(3c)'ed
 * 	to the rendezvous path.  We've lost the race, so we give up.
 * 	Note that in this case we also try to grab the file lock, and
 * 	will succeed in acquiring it since the vnode locked by the
 * 	"winning" zoneadmd was a regular one, and the one we locked was
 * 	the fattach(3c)'ed door node.  At any rate, no harm is done, and
 * 	we just return to zoneadm(1m) which knows to retry.
 */
static int
make_daemon_exclusive(zlog_t *zlogp)
{
	int doorfd = -1;
	int err, ret = -1;
	struct stat st;
	struct flock flock;
	zone_state_t zstate;

top:
	if ((err = zone_get_state(zone_name, &zstate)) != Z_OK) {
		zerror(zlogp, B_FALSE, "failed to get zone state: %s",
		    zonecfg_strerror(err));
		goto out;
	}
	if ((doorfd = open(zone_door_path, O_CREAT|O_RDWR,
	    S_IREAD|S_IWRITE)) < 0) {
		zerror(zlogp, B_TRUE, "failed to open %s", zone_door_path);
		goto out;
	}
	if (fstat(doorfd, &st) < 0) {
		zerror(zlogp, B_TRUE, "failed to stat %s", zone_door_path);
		goto out;
	}
	/*
	 * Lock the file to synchronize with other zoneadmd
	 */
	flock.l_type = F_WRLCK;
	flock.l_whence = SEEK_SET;
	flock.l_start = (off_t)0;
	flock.l_len = (off_t)0;
	if (fcntl(doorfd, F_SETLK, &flock) < 0) {
		/*
		 * Someone else raced us here and grabbed the lock file
		 * first.  A warning here is inappropriate since nothing
		 * went wrong.
		 */
		goto out;
	}

	if (strcmp(st.st_fstype, "namefs") == 0) {
		struct door_info info;

		/*
		 * There is already something fattach()'ed to this file.
		 * Lets see what the door is up to.
		 */
		if (door_info(doorfd, &info) == 0 && info.di_target != -1) {
			/*
			 * Another zoneadmd process seems to be in
			 * control of the situation and we don't need to
			 * be here.  A warning here is inappropriate
			 * since nothing went wrong.
			 *
			 * If the door has been revoked, the zoneadmd
			 * process currently managing the zone is going
			 * away.  We'll return control to zoneadm(1m)
			 * which will try again (by which time zoneadmd
			 * will hopefully have exited).
			 */
			goto out;
		}

		/*
		 * If we got this far, there's a fattach(3c)'ed door
		 * that belongs to a process that has exited, which can
		 * happen if the previous zoneadmd died unexpectedly.
		 *
		 * Let user know that something is amiss, but that we can
		 * recover; if the zone is in the installed state, then don't
		 * message, since having a running zoneadmd isn't really
		 * expected/needed.  We want to keep occurences of this message
		 * limited to times when zoneadmd is picking back up from a
		 * zoneadmd that died while the zone was in some non-trivial
		 * state.
		 */
		if (zstate > ZONE_STATE_INSTALLED) {
			zerror(zlogp, B_FALSE,
			    "zone '%s': WARNING: zone is in state '%s', but "
			    "zoneadmd does not appear to be available; "
			    "restarted zoneadmd to recover.",
			    zone_name, zone_state_str(zstate));
		}

		(void) fdetach(zone_door_path);
		(void) close(doorfd);
		goto top;
	}
	ret = 0;
out:
	(void) close(doorfd);
	return (ret);
}

/*
 * Setup the brand's pre and post state change callbacks, as well as the
 * query callback, if any of these exist.
 */
static int
brand_callback_init(brand_handle_t bh, char *zone_name)
{
	char zpath[MAXPATHLEN];

	if (zone_get_zonepath(zone_name, zpath, sizeof (zpath)) != Z_OK)
		return (-1);

	(void) strlcpy(pre_statechg_hook, EXEC_PREFIX,
	    sizeof (pre_statechg_hook));

	if (brand_get_prestatechange(bh, zone_name, zpath,
	    pre_statechg_hook + EXEC_LEN,
	    sizeof (pre_statechg_hook) - EXEC_LEN) != 0)
		return (-1);

	if (strlen(pre_statechg_hook) <= EXEC_LEN)
		pre_statechg_hook[0] = '\0';

	(void) strlcpy(post_statechg_hook, EXEC_PREFIX,
	    sizeof (post_statechg_hook));

	if (brand_get_poststatechange(bh, zone_name, zpath,
	    post_statechg_hook + EXEC_LEN,
	    sizeof (post_statechg_hook) - EXEC_LEN) != 0)
		return (-1);

	if (strlen(post_statechg_hook) <= EXEC_LEN)
		post_statechg_hook[0] = '\0';

	(void) strlcpy(query_hook, EXEC_PREFIX,
	    sizeof (query_hook));

	if (brand_get_query(bh, zone_name, zpath, query_hook + EXEC_LEN,
	    sizeof (query_hook) - EXEC_LEN) != 0)
		return (-1);

	if (strlen(query_hook) <= EXEC_LEN)
		query_hook[0] = '\0';

	return (0);
}

int
main(int argc, char *argv[])
{
	int opt;
	zoneid_t zid;
	priv_set_t *privset;
	zone_state_t zstate;
	char parents_locale[MAXPATHLEN];
	brand_handle_t bh;
	int err;

	pid_t pid;
	sigset_t blockset;
	sigset_t block_cld;

	struct {
		sema_t sem;
		int status;
		zlog_t log;
	} *shstate;
	size_t shstatelen = getpagesize();

	zlog_t errlog;
	zlog_t *zlogp;

	int ctfd;

	progname = get_execbasename(argv[0]);

	/*
	 * Make sure stderr is unbuffered
	 */
	(void) setbuffer(stderr, NULL, 0);

	/*
	 * Get out of the way of mounted filesystems, since we will daemonize
	 * soon.
	 */
	(void) chdir("/");

	/*
	 * Use the default system umask per PSARC 1998/110 rather than
	 * anything that may have been set by the caller.
	 */
	(void) umask(CMASK);

	/*
	 * Initially we want to use our parent's locale.
	 */
	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);
	(void) strlcpy(parents_locale, setlocale(LC_MESSAGES, NULL),
	    sizeof (parents_locale));

	/*
	 * This zlog_t is used for writing to stderr
	 */
	errlog.logfile = stderr;
	errlog.buflen = errlog.loglen = 0;
	errlog.buf = errlog.log = NULL;
	errlog.locale = parents_locale;

	/*
	 * We start off writing to stderr until we're ready to daemonize.
	 */
	zlogp = &errlog;

	/*
	 * Process options.
	 */
	while ((opt = getopt(argc, argv, "R:z:")) != EOF) {
		switch (opt) {
		case 'R':
			zonecfg_set_root(optarg);
			break;
		case 'z':
			zone_name = optarg;
			break;
		default:
			usage();
		}
	}

	if (zone_name == NULL)
		usage();

	/*
	 * Because usage() prints directly to stderr, it has gettext()
	 * wrapping, which depends on the locale.  But since zerror() calls
	 * localize() which tweaks the locale, it is not safe to call zerror()
	 * until after the last call to usage().  Fortunately, the last call
	 * to usage() is just above and the first call to zerror() is just
	 * below.  Don't mess this up.
	 */
	if (strcmp(zone_name, GLOBAL_ZONENAME) == 0) {
		zerror(zlogp, B_FALSE, "cannot manage the %s zone",
		    GLOBAL_ZONENAME);
		return (1);
	}

	if (zone_get_id(zone_name, &zid) != 0) {
		zerror(zlogp, B_FALSE, "could not manage %s: %s", zone_name,
		    zonecfg_strerror(Z_NO_ZONE));
		return (1);
	}

	if ((err = zone_get_state(zone_name, &zstate)) != Z_OK) {
		zerror(zlogp, B_FALSE, "failed to get zone state: %s",
		    zonecfg_strerror(err));
		return (1);
	}
	if (zstate < ZONE_STATE_INCOMPLETE) {
		zerror(zlogp, B_FALSE,
		    "cannot manage a zone which is in state '%s'",
		    zone_state_str(zstate));
		return (1);
	}

	if (zonecfg_default_brand(default_brand,
	    sizeof (default_brand)) != Z_OK) {
		zerror(zlogp, B_FALSE, "unable to determine default brand");
		return (1);
	}

	/* Get a handle to the brand info for this zone */
	if (zone_get_brand(zone_name, brand_name, sizeof (brand_name))
	    != Z_OK) {
		zerror(zlogp, B_FALSE, "unable to determine zone brand");
		return (1);
	}
	zone_isnative = (strcmp(brand_name, NATIVE_BRAND_NAME) == 0);
	zone_islabeled = (strcmp(brand_name, LABELED_BRAND_NAME) == 0);

	/*
	 * In the alternate root environment, the only supported
	 * operations are mount and unmount.  In this case, just treat
	 * the zone as native if it is cluster.  Cluster zones can be
	 * native for the purpose of LU or upgrade, and the cluster
	 * brand may not exist in the miniroot (such as in net install
	 * upgrade).
	 */
	if (strcmp(brand_name, CLUSTER_BRAND_NAME) == 0) {
		zone_iscluster = B_TRUE;
		if (zonecfg_in_alt_root()) {
			(void) strlcpy(brand_name, default_brand,
			    sizeof (brand_name));
		}
	} else {
		zone_iscluster = B_FALSE;
	}

	if ((bh = brand_open(brand_name)) == NULL) {
		zerror(zlogp, B_FALSE, "unable to open zone brand");
		return (1);
	}

	/* Get state change brand hooks. */
	if (brand_callback_init(bh, zone_name) == -1) {
		zerror(zlogp, B_TRUE,
		    "failed to initialize brand state change hooks");
		brand_close(bh);
		return (1);
	}

	brand_close(bh);

	/*
	 * Check that we have all privileges.  It would be nice to pare
	 * this down, but this is at least a first cut.
	 */
	if ((privset = priv_allocset()) == NULL) {
		zerror(zlogp, B_TRUE, "%s failed", "priv_allocset");
		return (1);
	}

	if (getppriv(PRIV_EFFECTIVE, privset) != 0) {
		zerror(zlogp, B_TRUE, "%s failed", "getppriv");
		priv_freeset(privset);
		return (1);
	}

	if (priv_isfullset(privset) == B_FALSE) {
		zerror(zlogp, B_FALSE, "You lack sufficient privilege to "
		    "run this command (all privs required)");
		priv_freeset(privset);
		return (1);
	}
	priv_freeset(privset);

	if (mkzonedir(zlogp) != 0)
		return (1);

	/*
	 * Pre-fork: setup shared state
	 */
	if ((shstate = (void *)mmap(NULL, shstatelen,
	    PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANON, -1, (off_t)0)) ==
	    MAP_FAILED) {
		zerror(zlogp, B_TRUE, "%s failed", "mmap");
		return (1);
	}
	if (sema_init(&shstate->sem, 0, USYNC_PROCESS, NULL) != 0) {
		zerror(zlogp, B_TRUE, "%s failed", "sema_init()");
		(void) munmap((char *)shstate, shstatelen);
		return (1);
	}
	shstate->log.logfile = NULL;
	shstate->log.buflen = shstatelen - sizeof (*shstate);
	shstate->log.loglen = shstate->log.buflen;
	shstate->log.buf = (char *)shstate + sizeof (*shstate);
	shstate->log.log = shstate->log.buf;
	shstate->log.locale = parents_locale;
	shstate->status = -1;

	/*
	 * We need a SIGCHLD handler so the sema_wait() below will wake
	 * up if the child dies without doing a sema_post().
	 */
	(void) sigset(SIGCHLD, sigchld);
	/*
	 * We must mask SIGCHLD until after we've coped with the fork
	 * sufficiently to deal with it; otherwise we can race and
	 * receive the signal before pid has been initialized
	 * (yes, this really happens).
	 */
	(void) sigemptyset(&block_cld);
	(void) sigaddset(&block_cld, SIGCHLD);
	(void) sigprocmask(SIG_BLOCK, &block_cld, NULL);

	/*
	 * The parent only needs stderr after the fork, so close other fd's
	 * that we inherited from zoneadm so that the parent doesn't have those
	 * open while waiting. The child will close the rest after the fork.
	 */
	closefrom(3);

	if ((ctfd = init_template()) == -1) {
		zerror(zlogp, B_TRUE, "failed to create contract");
		return (1);
	}

	/*
	 * Do not let another thread localize a message while we are forking.
	 */
	(void) mutex_lock(&msglock);
	pid = fork();
	(void) mutex_unlock(&msglock);

	/*
	 * In all cases (parent, child, and in the event of an error) we
	 * don't want to cause creation of contracts on subsequent fork()s.
	 */
	(void) ct_tmpl_clear(ctfd);
	(void) close(ctfd);

	if (pid == -1) {
		zerror(zlogp, B_TRUE, "could not fork");
		return (1);

	} else if (pid > 0) { /* parent */
		(void) sigprocmask(SIG_UNBLOCK, &block_cld, NULL);
		/*
		 * This marks a window of vulnerability in which we receive
		 * the SIGCLD before falling into sema_wait (normally we would
		 * get woken up from sema_wait with EINTR upon receipt of
		 * SIGCLD).  So we may need to use some other scheme like
		 * sema_posting in the sigcld handler.
		 * blech
		 */
		(void) sema_wait(&shstate->sem);
		(void) sema_destroy(&shstate->sem);
		if (shstate->status != 0)
			(void) waitpid(pid, NULL, WNOHANG);
		/*
		 * It's ok if we die with SIGPIPE.  It's not like we could have
		 * done anything about it.
		 */
		(void) fprintf(stderr, "%s", shstate->log.buf);
		_exit(shstate->status == 0 ? 0 : 1);
	}

	/*
	 * The child charges on.
	 */
	(void) sigset(SIGCHLD, SIG_DFL);
	(void) sigprocmask(SIG_UNBLOCK, &block_cld, NULL);

	/*
	 * SIGPIPE can be delivered if we write to a socket for which the
	 * peer endpoint is gone.  That can lead to too-early termination
	 * of zoneadmd, and that's not good eats.
	 */
	(void) sigset(SIGPIPE, SIG_IGN);
	/*
	 * Stop using stderr
	 */
	zlogp = &shstate->log;

	/*
	 * We don't need stdout/stderr from now on.
	 */
	closefrom(0);

	/*
	 * Initialize the syslog zlog_t.  This needs to be done after
	 * the call to closefrom().
	 */
	logsys.buf = logsys.log = NULL;
	logsys.buflen = logsys.loglen = 0;
	logsys.logfile = NULL;
	logsys.locale = DEFAULT_LOCALE;

	openlog("zoneadmd", LOG_PID, LOG_DAEMON);

	/*
	 * The eventstream is used to publish state changes in the zone
	 * from the door threads to the console I/O poller.
	 */
	if (eventstream_init() == -1) {
		zerror(zlogp, B_TRUE, "unable to create eventstream");
		goto child_out;
	}

	(void) snprintf(zone_door_path, sizeof (zone_door_path),
	    "%s" ZONE_DOOR_PATH, zonecfg_get_root(), zone_name);

	/*
	 * See if another zoneadmd is running for this zone.  If not, then we
	 * can now modify system state.
	 */
	if (make_daemon_exclusive(zlogp) == -1)
		goto child_out;


	/*
	 * Create/join a new session; we need to be careful of what we do with
	 * the console from now on so we don't end up being the session leader
	 * for the terminal we're going to be handing out.
	 */
	(void) setsid();

	/*
	 * This thread shouldn't be receiving any signals; in particular,
	 * SIGCHLD should be received by the thread doing the fork().
	 */
	(void) sigfillset(&blockset);
	(void) thr_sigsetmask(SIG_BLOCK, &blockset, NULL);

	/*
	 * Setup the console device and get ready to serve the console;
	 * once this has completed, we're ready to let console clients
	 * make an attempt to connect (they will block until
	 * serve_console_sock() below gets called, and any pending
	 * connection is accept()ed).
	 */
	if (!zonecfg_in_alt_root() && init_console(zlogp) < 0)
		goto child_out;

	/*
	 * Take the lock now, so that when the door server gets going, we
	 * are guaranteed that it won't take a request until we are sure
	 * that everything is completely set up.  See the child_out: label
	 * below to see why this matters.
	 */
	(void) mutex_lock(&lock);

	/* Init semaphore for scratch zones. */
	if (sema_init(&scratch_sem, 0, USYNC_THREAD, NULL) == -1) {
		zerror(zlogp, B_TRUE,
		    "failed to initialize semaphore for scratch zone");
		goto child_out;
	}

	/* open the dladm handle */
	if (dladm_open(&dld_handle) != DLADM_STATUS_OK) {
		zerror(zlogp, B_FALSE, "failed to open dladm handle");
		goto child_out;
	}

	/*
	 * Note: door setup must occur *after* the console is setup.
	 * This is so that as zlogin tests the door to see if zoneadmd
	 * is ready yet, we know that the console will get serviced
	 * once door_info() indicates that the door is "up".
	 */
	if (setup_door(zlogp) == -1)
		goto child_out;

	/*
	 * Things seem OK so far; tell the parent process that we're done
	 * with setup tasks.  This will cause the parent to exit, signalling
	 * to zoneadm, zlogin, or whatever forked it that we are ready to
	 * service requests.
	 */
	shstate->status = 0;
	(void) sema_post(&shstate->sem);
	(void) munmap((char *)shstate, shstatelen);
	shstate = NULL;

	(void) mutex_unlock(&lock);

	/*
	 * zlogp is now invalid, so reset it to the syslog logger.
	 */
	zlogp = &logsys;

	/*
	 * Now that we are free of any parents, switch to the default locale.
	 */
	(void) setlocale(LC_ALL, DEFAULT_LOCALE);

	/*
	 * At this point the setup portion of main() is basically done, so
	 * we reuse this thread to manage the zone console.  When
	 * serve_console() has returned, we are past the point of no return
	 * in the life of this zoneadmd.
	 */
	if (zonecfg_in_alt_root()) {
		/*
		 * This is just awful, but mounted scratch zones don't (and
		 * can't) have consoles.  We just wait for unmount instead.
		 */
		while (sema_wait(&scratch_sem) == EINTR)
			;
	} else {
		serve_console(zlogp);
		assert(in_death_throes);
	}

	/*
	 * This is the next-to-last part of the exit interlock.  Upon calling
	 * fdetach(), the door will go unreferenced; once any
	 * outstanding requests (like the door thread doing Z_HALT) are
	 * done, the door will get an UNREF notification; when it handles
	 * the UNREF, the door server will cause the exit.  It's possible
	 * that fdetach() can fail because the file is in use, in which
	 * case we'll retry the operation.
	 */
	assert(!MUTEX_HELD(&lock));
	for (;;) {
		if ((fdetach(zone_door_path) == 0) || (errno != EBUSY))
			break;
		yield();
	}

	for (;;)
		(void) pause();

child_out:
	assert(pid == 0);
	if (shstate != NULL) {
		shstate->status = -1;
		(void) sema_post(&shstate->sem);
		(void) munmap((char *)shstate, shstatelen);
	}

	/*
	 * This might trigger an unref notification, but if so,
	 * we are still holding the lock, so our call to exit will
	 * ultimately win the race and will publish the right exit
	 * code.
	 */
	if (zone_door != -1) {
		assert(MUTEX_HELD(&lock));
		(void) door_revoke(zone_door);
		(void) fdetach(zone_door_path);
	}

	if (dld_handle != NULL)
		dladm_close(dld_handle);

	return (1); /* return from main() forcibly exits an MT process */
}
