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

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Common code for halt(1M), poweroff(1M), and reboot(1M).  We use
 * argv[0] to determine which behavior to exhibit.
 */

#include <procfs.h>
#include <sys/types.h>
#include <sys/uadmin.h>
#include <alloca.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <libscf.h>
#include <locale.h>
#include <libintl.h>
#include <syslog.h>
#include <signal.h>
#include <strings.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <strings.h>
#include <time.h>
#include <utmpx.h>
#include <pwd.h>
#include <zone.h>
#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN	"SYS_TEST"
#endif

extern int audit_halt_setup(int, char **);
extern int audit_halt_success(void);
extern int audit_halt_fail(void);

extern int audit_reboot_setup(void);
extern int audit_reboot_success(void);
extern int audit_reboot_fail(void);

static char *cmdname;	/* basename(argv[0]), the name of the command */

typedef struct ctidlist_struct {
	ctid_t ctid;
	struct ctidlist_struct *next;
} ctidlist_t;

static ctidlist_t *ctidlist = NULL;
static ctid_t startdct = -1;

#define	FMRI_STARTD_CONTRACT \
	"svc:/system/svc/restarter:default/:properties/restarter/contract"

#define	ZONEADM_PROG "/usr/sbin/zoneadm"

static pid_t
get_initpid()
{
	static int init_pid = -1;

	if (init_pid == -1) {
		if (zone_getattr(getzoneid(), ZONE_ATTR_INITPID, &init_pid,
		    sizeof (init_pid)) != sizeof (init_pid)) {
			assert(errno == ESRCH);
			init_pid = -1;
		}
	}
	return (init_pid);
}

/*
 * Quiesce or resume init using /proc.  When stopping init, we can't send
 * SIGTSTP (since init ignores it) or SIGSTOP (since the kernel won't permit
 * it).
 */
static int
direct_init(long command)
{
	char ctlfile[MAXPATHLEN];
	pid_t pid;
	int ctlfd;

	assert(command == PCDSTOP || command == PCRUN);
	if ((pid = get_initpid()) == -1) {
		return (-1);
	}

	(void) snprintf(ctlfile, sizeof (ctlfile), "/proc/%d/ctl", pid);
	if ((ctlfd = open(ctlfile, O_WRONLY)) == -1)
		return (-1);

	if (command == PCDSTOP) {
		if (write(ctlfd, &command, sizeof (long)) == -1) {
			(void) close(ctlfd);
			return (-1);
		}
	} else {	/* command == PCRUN */
		long cmds[2];
		cmds[0] = command;
		cmds[1] = 0;
		if (write(ctlfd, cmds, sizeof (cmds)) == -1) {
			(void) close(ctlfd);
			return (-1);
		}
	}
	(void) close(ctlfd);
	return (0);
}

static void
stop_startd()
{
	scf_handle_t *h;
	scf_property_t *prop = NULL;
	scf_value_t *val = NULL;
	uint64_t uint64;

	if ((h = scf_handle_create(SCF_VERSION)) == NULL)
		return;

	if ((scf_handle_bind(h) != 0) ||
	    ((prop = scf_property_create(h)) == NULL) ||
	    ((val = scf_value_create(h)) == NULL))
		goto out;

	if (scf_handle_decode_fmri(h, FMRI_STARTD_CONTRACT,
	    NULL, NULL, NULL, NULL, prop, SCF_DECODE_FMRI_EXACT) != 0)
		goto out;

	if (scf_property_is_type(prop, SCF_TYPE_COUNT) != 0 ||
	    scf_property_get_value(prop, val) != 0 ||
	    scf_value_get_count(val, &uint64) != 0)
		goto out;

	startdct = (ctid_t)uint64;
	(void) sigsend(P_CTID, startdct, SIGSTOP);

out:
	scf_property_destroy(prop);
	scf_value_destroy(val);
	scf_handle_destroy(h);
}

static void
continue_startd()
{
	if (startdct != -1)
		(void) sigsend(P_CTID, startdct, SIGCONT);
}

#define	FMRI_RESTARTER_PROP "/:properties/general/restarter"
#define	FMRI_CONTRACT_PROP "/:properties/restarter/contract"

static int
save_ctid(ctid_t ctid)
{
	ctidlist_t *next;

	for (next = ctidlist; next != NULL; next = next->next)
		if (next->ctid == ctid)
			return (-1);

	next = (ctidlist_t *)malloc(sizeof (ctidlist_t));
	if (next == NULL)
		return (-1);

	next->ctid = ctid;
	next->next = ctidlist;
	ctidlist = next;
	return (0);
}

static void
stop_delegates()
{
	ctid_t ctid;
	scf_handle_t *h;
	scf_scope_t *sc = NULL;
	scf_service_t *svc = NULL;
	scf_instance_t *inst = NULL;
	scf_snapshot_t *snap = NULL;
	scf_snapshot_t *isnap = NULL;
	scf_propertygroup_t *pg = NULL;
	scf_property_t *prop = NULL;
	scf_value_t *val = NULL;
	scf_iter_t *siter = NULL;
	scf_iter_t *iiter = NULL;
	char *fmri;
	ssize_t length;

	uint64_t uint64;
	ssize_t bytes;

	length = scf_limit(SCF_LIMIT_MAX_FMRI_LENGTH);
	if (length <= 0)
		return;

	length++;
	fmri = alloca(length * sizeof (char));

	if ((h = scf_handle_create(SCF_VERSION)) == NULL)
		return;

	if (scf_handle_bind(h) != 0) {
		scf_handle_destroy(h);
		return;
	}

	if ((sc = scf_scope_create(h)) == NULL ||
	    (svc = scf_service_create(h)) == NULL ||
	    (inst = scf_instance_create(h)) == NULL ||
	    (snap = scf_snapshot_create(h)) == NULL ||
	    (pg = scf_pg_create(h)) == NULL ||
	    (prop = scf_property_create(h)) == NULL ||
	    (val = scf_value_create(h)) == NULL ||
	    (siter = scf_iter_create(h)) == NULL ||
	    (iiter = scf_iter_create(h)) == NULL)
		goto out;

	if (scf_handle_get_scope(h, SCF_SCOPE_LOCAL, sc) != 0)
		goto out;

	if (scf_iter_scope_services(siter, sc) != 0)
		goto out;

	while (scf_iter_next_service(siter, svc) == 1) {

		if (scf_iter_service_instances(iiter, svc) != 0)
			continue;

		while (scf_iter_next_instance(iiter, inst) == 1) {

			if ((scf_instance_get_snapshot(inst, "running",
			    snap)) != 0)
				isnap = NULL;
			else
				isnap = snap;

			if (scf_instance_get_pg_composed(inst, isnap,
			    SCF_PG_GENERAL, pg) != 0)
				continue;

			if (scf_pg_get_property(pg, SCF_PROPERTY_RESTARTER,
			    prop) != 0 ||
			    scf_property_get_value(prop, val) != 0)
				continue;

			bytes = scf_value_get_astring(val, fmri, length);
			if (bytes <= 0 || bytes >= length)
				continue;

			if (strlcat(fmri, FMRI_CONTRACT_PROP, length) >=
			    length)
				continue;

			if (scf_handle_decode_fmri(h, fmri, NULL, NULL,
			    NULL, NULL, prop, SCF_DECODE_FMRI_EXACT) != 0)
				continue;

			if (scf_property_is_type(prop, SCF_TYPE_COUNT) != 0 ||
			    scf_property_get_value(prop, val) != 0 ||
			    scf_value_get_count(val, &uint64) != 0)
				continue;

			ctid = (ctid_t)uint64;
			if (save_ctid(ctid) == 0) {
				(void) sigsend(P_CTID, ctid, SIGSTOP);
			}
		}
	}
out:
	scf_scope_destroy(sc);
	scf_service_destroy(svc);
	scf_instance_destroy(inst);
	scf_snapshot_destroy(snap);
	scf_pg_destroy(pg);
	scf_property_destroy(prop);
	scf_value_destroy(val);
	scf_iter_destroy(siter);
	scf_iter_destroy(iiter);

	(void) scf_handle_unbind(h);
	scf_handle_destroy(h);
}

static void
continue_delegates()
{
	ctidlist_t *next;
	for (next = ctidlist; next != NULL; next = next->next)
		(void) sigsend(P_CTID, next->ctid, SIGCONT);
}

static void
stop_restarters()
{
	stop_startd();
	stop_delegates();
}

static void
continue_restarters()
{
	continue_startd();
	continue_delegates();
}

/*
 * Copy an array of strings into buf, separated by spaces.  Returns 0 on
 * success.
 */
static int
gather_args(char **args, char *buf, size_t buf_sz)
{
	if (strlcpy(buf, *args, buf_sz) >= buf_sz)
		return (-1);

	for (++args; *args != NULL; ++args) {
		if (strlcat(buf, " ", buf_sz) >= buf_sz)
			return (-1);
		if (strlcat(buf, *args, buf_sz) >= buf_sz)
			return (-1);
	}

	return (0);
}

/*
 * Halt every zone on the system.  We are committed to doing a shutdown
 * even if something goes wrong here. If something goes wrong, we just
 * continue with the shutdown.  Return non-zero if we need to wait for zones to
 * halt later on.
 */
static int
halt_zones()
{
	pid_t pid;
	zoneid_t *zones;
	size_t nz = 0, old_nz;
	int i;
	char zname[ZONENAME_MAX];

	/*
	 * Get a list of zones. If the number of zones changes in between the
	 * two zone_list calls, try again.
	 */

	for (;;) {
		(void) zone_list(NULL, &nz);
		if (nz == 1)
			return (0);
		old_nz = nz;
		zones = calloc(sizeof (zoneid_t), nz);
		if (zones == NULL) {
			(void) fprintf(stderr,
			    gettext("%s: Could not halt zones"
			    " (out of memory).\n"), cmdname);
			return (0);
		}

		(void) zone_list(zones, &nz);
		if (old_nz == nz)
			break;
		free(zones);
	}

	if (nz == 2) {
		(void) fprintf(stderr, gettext("%s: Halting 1 zone.\n"),
		    cmdname);
	} else {
		(void) fprintf(stderr, gettext("%s: Halting %i zones.\n"),
		    cmdname, nz - 1);
	}

	for (i = 0; i < nz; i++) {
		if (zones[i] == GLOBAL_ZONEID)
			continue;
		if (getzonenamebyid(zones[i], zname, sizeof (zname)) < 0) {
			/*
			 * getzonenamebyid should only fail if we raced with
			 * another process trying to shut down the zone.
			 * We assume this happened and ignore the error.
			 */
			if (errno != EINVAL) {
				(void) fprintf(stderr,
				    gettext("%s: Unexpected error while "
				    "looking up zone %ul: %s.\n"),
				    cmdname, zones[i], strerror(errno));
			}

			continue;
		}
		pid = fork();
		if (pid < 0) {
			(void) fprintf(stderr,
			    gettext("%s: Zone \"%s\" could not be"
			    " halted (could not fork(): %s).\n"),
			    cmdname, zname, strerror(errno));
			continue;
		}
		if (pid == 0) {
			(void) execl(ZONEADM_PROG, ZONEADM_PROG,
			    "-z", zname, "halt", NULL);
			(void) fprintf(stderr,
			    gettext("%s: Zone \"%s\" could not be halted"
			    " (cannot exec(" ZONEADM_PROG "): %s).\n"),
			    cmdname, zname, strerror(errno));
			exit(0);
		}
	}

	return (1);
}

/*
 * This function tries to wait for all non-global zones to go away.
 * It will timeout if no progress is made for 5 seconds, or a total of
 * 30 seconds elapses.
 */

static void
check_zones_haltedness()
{
	int t = 0, t_prog = 0;
	size_t nz = 0, last_nz;

	do {
		last_nz = nz;
		(void) zone_list(NULL, &nz);
		if (nz == 1)
			return;

		(void) sleep(1);

		if (last_nz > nz)
			t_prog = 0;

		t++;
		t_prog++;

		if (t == 10) {
			if (nz == 2) {
				(void) fprintf(stderr,
				    gettext("%s: Still waiting for 1 zone to "
				    "halt. Will wait up to 20 seconds.\n"),
				    cmdname);
			} else {
				(void) fprintf(stderr,
				    gettext("%s: Still waiting for %i zones "
				    "to halt. Will wait up to 20 seconds.\n"),
				    cmdname, nz - 1);
			}
		}

	} while ((t < 30) && (t_prog < 5));
}

int
main(int argc, char *argv[])
{
	char *ttyn = ttyname(STDERR_FILENO);

	int qflag = 0, needlog = 1, nosync = 0;
	uintptr_t mdep = NULL;
	int cmd, fcn, c, aval, r;
	const char *usage;
	zoneid_t zoneid = getzoneid();
	int need_check_zones = 0;

	char bootargs_buf[BOOTARGS_MAX];

	const char * const resetting = "/etc/svc/volatile/resetting";

	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);

	cmdname = basename(argv[0]);

	if (strcmp(cmdname, "halt") == 0) {
		(void) audit_halt_setup(argc, argv);
		usage = gettext("usage: %s [ -dlnqy ]\n");
		cmd = A_SHUTDOWN;
		fcn = AD_HALT;
	} else if (strcmp(cmdname, "poweroff") == 0) {
		(void) audit_halt_setup(argc, argv);
		usage = gettext("usage: %s [ -dlnqy ]\n");
		cmd = A_SHUTDOWN;
		fcn = AD_POWEROFF;
	} else if (strcmp(cmdname, "reboot") == 0) {
		(void) audit_reboot_setup();
		usage = gettext("usage: %s [ -dlnq ] [ boot args ]\n");
		cmd = A_SHUTDOWN;
		fcn = AD_BOOT;
	} else {
		(void) fprintf(stderr,
		    gettext("%s: not installed properly\n"), cmdname);
		return (1);
	}

	while ((c = getopt(argc, argv, "dlnqy")) != EOF) {
		switch (c) {
		case 'd':
			if (zoneid == GLOBAL_ZONEID)
				cmd = A_DUMP;
			else {
				(void) fprintf(stderr,
				    gettext("%s: -d only valid from global"
				    " zone\n"), cmdname);
				return (1);
			}
			break;
		case 'l':
			needlog = 0;
			break;
		case 'n':
			nosync = 1;
			break;
		case 'q':
			qflag = 1;
			break;
		case 'y':
			ttyn = NULL;
			break;
		default:
			/*
			 * TRANSLATION_NOTE
			 * Don't translate the words "halt" or "reboot"
			 */
			(void) fprintf(stderr, usage, cmdname);
			return (1);
		}
	}

	argc -= optind;
	argv += optind;

	if (argc != 0) {
		if (fcn != AD_BOOT) {
			(void) fprintf(stderr, usage, cmdname);
			return (1);
		}

		/* Gather the arguments into bootargs_buf. */
		if (gather_args(argv, bootargs_buf, sizeof (bootargs_buf)) !=
		    0) {
			(void) fprintf(stderr,
			    gettext("%s: Boot arguments too long.\n"), cmdname);
			return (1);
		}
		mdep = (uintptr_t)bootargs_buf;
	}

	if (geteuid() != 0) {
		(void) fprintf(stderr,
		    gettext("%s: permission denied\n"), cmdname);
		goto fail;
	}

	if (fcn != AD_BOOT && ttyn != NULL &&
	    strncmp(ttyn, "/dev/term/", strlen("/dev/term/")) == 0) {
		/*
		 * TRANSLATION_NOTE
		 * Don't translate ``halt -y''
		 */
		(void) fprintf(stderr,
		    gettext("%s: dangerous on a dialup;"), cmdname);
		(void) fprintf(stderr,
		    gettext("use ``%s -y'' if you are really sure\n"), cmdname);
		goto fail;
	}

	if (needlog) {
		char *user = getlogin();
		struct passwd *pw;
		char *tty;

		openlog(cmdname, 0, LOG_AUTH);
		if (user == NULL && (pw = getpwuid(getuid())) != NULL)
			user = pw->pw_name;
		if (user == NULL)
			user = "root";

		tty = ttyname(1);

		if (tty == NULL)
			syslog(LOG_CRIT, "initiated by %s", user);
		else
			syslog(LOG_CRIT, "initiated by %s on %s", user, tty);
	}

	/*
	 * We must assume success and log it before auditd is terminated.
	 */
	if (fcn == AD_BOOT)
		aval = audit_reboot_success();
	else
		aval = audit_halt_success();

	if (aval == -1) {
		(void) fprintf(stderr,
		    gettext("%s: can't turn off auditd\n"), cmdname);
		if (needlog)
			(void) sleep(5); /* Give syslogd time to record this */
	}

	(void) signal(SIGHUP, SIG_IGN);	/* for remote connections */

	/*
	 * We start to fork a bunch of zoneadms to halt any active zones.
	 * This will proceed with halt in parallel until we call
	 * check_zone_haltedness later on.
	 */
	if (zoneid == GLOBAL_ZONEID && cmd != A_DUMP) {
		need_check_zones = halt_zones();
	}


	/* sync boot archive in the global zone */
	if (zoneid == GLOBAL_ZONEID && !nosync) {
		(void) system("/sbin/bootadm -a update_all");
	}

	/*
	 * If we're not forcing a crash dump, mark the system as quiescing for
	 * smf(5)'s benefit, and idle the init process.
	 */
	if (cmd != A_DUMP) {
		if (direct_init(PCDSTOP) == -1) {
			/*
			 * TRANSLATION_NOTE
			 * Don't translate the word "init"
			 */
			(void) fprintf(stderr,
			    gettext("%s: can't idle init\n"), cmdname);
			goto fail;
		}

		if (creat(resetting, 0755) == -1)
			(void) fprintf(stderr,
			    gettext("%s: could not create %s.\n"),
			    cmdname, resetting);

		/*
		 * Stop all restarters so they do not try to restart services
		 * that are terminated.
		 */
		stop_restarters();

		/*
		 * Wait a little while for zones to shutdown.
		 */
		if (need_check_zones) {
			check_zones_haltedness();

			(void) fprintf(stderr,
			    gettext("%s: Completing system halt.\n"),
			    cmdname);
		}
	}

	/*
	 * Make sure we don't get stopped by a jobcontrol shell
	 * once we start killing everybody.
	 */
	(void) signal(SIGTSTP, SIG_IGN);
	(void) signal(SIGTTIN, SIG_IGN);
	(void) signal(SIGTTOU, SIG_IGN);
	(void) signal(SIGTERM, SIG_IGN);

	/*
	 * If we're not forcing a crash dump, give everyone 5 seconds to
	 * handle a SIGTERM and clean up properly.
	 */
	if (cmd != A_DUMP) {
		(void) kill(-1, SIGTERM);
		(void) sleep(5);
	}

	if (!qflag && !nosync) {
		struct utmpx wtmpx;

		bzero(&wtmpx, sizeof (struct utmpx));
		(void) strcpy(wtmpx.ut_line, "~");
		(void) time(&wtmpx.ut_tv.tv_sec);

		if (cmd == A_DUMP)
			(void) strcpy(wtmpx.ut_name, "crash dump");
		else
			(void) strcpy(wtmpx.ut_name, "shutdown");

		(void) updwtmpx(WTMPX_FILE, &wtmpx);
		sync();
	}

	if (cmd == A_DUMP && nosync != 0)
		(void) uadmin(A_DUMP, AD_NOSYNC, NULL);

	if (uadmin(cmd, fcn, mdep) == -1)
		(void) fprintf(stderr, "%s: uadmin failed: %s\n",
		    cmdname, strerror(errno));
	else
		(void) fprintf(stderr, "%s: uadmin unexpectedly returned 0\n",
		    cmdname);

	do {
		r = remove(resetting);
	} while (r != 0 && errno == EINTR);

	if (r != 0 && errno != ENOENT)
		(void) fprintf(stderr, gettext("%s: could not remove %s.\n"),
		    cmdname, resetting);

	if (direct_init(PCRUN) == -1) {
		/*
		 * TRANSLATION_NOTE
		 * Don't translate the word "init"
		 */
		(void) fprintf(stderr,
		    gettext("%s: can't resume init\n"), cmdname);
	}

	continue_restarters();

	if (get_initpid() != -1)
		/* tell init to restate current level */
		(void) kill(get_initpid(), SIGHUP);

fail:
	if (fcn == AD_BOOT)
		(void) audit_reboot_fail();
	else
		(void) audit_halt_fail();

	return (1);
}
