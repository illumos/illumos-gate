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

#include <sys/stat.h>
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

typedef struct ctidlist_struct {
	ctid_t ctid;
	struct ctidlist_struct *next;
} ctidlist_t;

static ctidlist_t *ctidlist = NULL;
static ctid_t startdct = -1;

#define	FMRI_STARTD_CONTRACT \
	"svc:/system/svc/restarter:default/:properties/restarter/contract"

#define	ZONEADM_PROG "/usr/sbin/zoneadm"

static void
stop_startd()
{
	ctid_t ctid;

	scf_handle_t *h;
	scf_property_t *prop = NULL;
	scf_value_t *val = NULL;
	uint64_t uint64;
	int ret;

	h = scf_handle_create(SCF_VERSION);
	if (h == NULL)
		return;

	ret = scf_handle_bind(h);
	if (ret) {
		scf_handle_destroy(h);
		return;
	}

	prop = scf_property_create(h);
	val = scf_value_create(h);

	if (!(prop && val))
		goto out;

	ret = scf_handle_decode_fmri(h, FMRI_STARTD_CONTRACT,
	    NULL, NULL, NULL, NULL, prop, SCF_DECODE_FMRI_EXACT);
	if (ret)
		goto out;

	ret = scf_property_is_type(prop, SCF_TYPE_COUNT);
	if (ret)
		goto out;

	ret = scf_property_get_value(prop, val);
	if (ret)
		goto out;

	ret = scf_value_get_count(val, &uint64);
	if (ret)
		goto out;

	ctid = (ctid_t)uint64;
	startdct = ctid;
	(void) sigsend(P_CTID, ctid, SIGSTOP);

out:
	if (prop)
		scf_property_destroy(prop);
	if (val)
		scf_value_destroy(val);

	(void) scf_handle_unbind(h);
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
	int ret;

	length = scf_limit(SCF_LIMIT_MAX_FMRI_LENGTH);
	if (length <= 0)
		return;

	length++;
	fmri = alloca(length * sizeof (char));

	h = scf_handle_create(SCF_VERSION);
	if (!h)
		return;

	ret = scf_handle_bind(h);
	if (ret) {
		scf_handle_destroy(h);
		return;
	}

	sc = scf_scope_create(h);
	svc = scf_service_create(h);
	inst = scf_instance_create(h);
	snap = scf_snapshot_create(h);
	pg = scf_pg_create(h);
	prop = scf_property_create(h);
	val = scf_value_create(h);
	siter = scf_iter_create(h);
	iiter = scf_iter_create(h);

	if (!(sc && svc && inst && snap &&
	    pg && prop && val && siter && iiter))
		goto out;

	ret = scf_handle_get_scope(h, SCF_SCOPE_LOCAL, sc);
	if (ret)
		goto out;

	ret = scf_iter_scope_services(siter, sc);
	if (ret)
		goto out;

	while (scf_iter_next_service(siter, svc) == 1) {

		ret = scf_iter_service_instances(iiter, svc);
		if (ret)
			continue;

		while (scf_iter_next_instance(iiter, inst) == 1) {

			ret = scf_instance_get_snapshot(inst, "running", snap);
				if (ret)
					isnap = NULL;
				else
					isnap = snap;

			ret = scf_instance_get_pg_composed(inst, isnap,
			    SCF_PG_GENERAL, pg);
			if (ret)
				continue;

			ret = scf_pg_get_property(pg, "restarter", prop);
			if (ret)
				continue;

			ret = scf_property_is_type(prop, SCF_TYPE_ASTRING);
			if (ret)
				continue;

			ret = scf_property_get_value(prop, val);
			if (ret)
				continue;

			bytes = scf_value_get_astring(val, fmri, length);
			if (bytes <= 0 || bytes >= length)
				continue;

			if (strlcat(fmri, FMRI_CONTRACT_PROP, length) >=
			    length)
				continue;

			ret = scf_handle_decode_fmri(h, fmri, NULL, NULL,
			    NULL, NULL, prop, SCF_DECODE_FMRI_EXACT);
			if (ret)
				continue;

			ret = scf_property_is_type(prop, SCF_TYPE_COUNT);
			if (ret)
				continue;

			ret = scf_property_get_value(prop, val);
			if (ret)
				continue;

			ret = scf_value_get_count(val, &uint64);
			if (ret)
				continue;

			ctid = (ctid_t)uint64;
			if (save_ctid(ctid) == 0) {
				(void) sigsend(P_CTID, ctid, SIGSTOP);
			}
		}
	}
out:
	if (sc)
		scf_scope_destroy(sc);
	if (svc)
		scf_service_destroy(svc);
	if (inst)
		scf_instance_destroy(inst);
	if (snap)
		scf_snapshot_destroy(snap);
	if (pg)
		scf_pg_destroy(pg);
	if (prop)
		scf_property_destroy(prop);
	if (val)
		scf_value_destroy(val);
	if (siter)
		scf_iter_destroy(siter);
	if (iiter)
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
halt_zones(const char *name)
{
	pid_t pid;
	zoneid_t *zones;
	size_t nz, old_nz;
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
			    " (out of memory).\n"), name);
			return (0);
		}

		(void) zone_list(zones, &nz);
		if (old_nz == nz)
			break;
		free(zones);
	}

	if (nz == 2) {
		(void) fprintf(stderr,
		    gettext("%s: Halting 1 zone.\n"),
		    name);
	} else {
		(void) fprintf(stderr,
		    gettext("%s: Halting %i zones.\n"),
		    name, nz - 1);
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
				    name, zones[i], strerror(errno));
			}

			continue;
		}
		pid = fork();
		if (pid < 0) {
			(void) fprintf(stderr,
			    gettext("%s: Zone \"%s\" could not be"
			    " halted (could not fork(): %s).\n"),
			    name, zname, strerror(errno));
			continue;
		}
		if (pid == 0) {
			(void) execl(ZONEADM_PROG, ZONEADM_PROG,
			    "-z", zname, "halt", NULL);
			(void) fprintf(stderr,
			    gettext("%s: Zone \"%s\" could not be halted"
			    " (cannot exec(" ZONEADM_PROG "): %s).\n"),
			    name, zname, strerror(errno));
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
check_zones_haltedness(const char *name)
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
				    name);
			} else {
				(void) fprintf(stderr,
				    gettext("%s: Still waiting for %i zones "
				    "to halt. Will wait up to 20 seconds.\n"),
				    name, nz - 1);
			}
		}

	} while ((t < 30) && (t_prog < 5));
}

int
main(int argc, char *argv[])
{
	char *cmdname = basename(argv[0]);
	char *ttyn = ttyname(STDERR_FILENO);

	int qflag = 0, needlog = 1, nosync = 0;
	uintptr_t mdep = NULL;
	int cmd, fcn, c, aval, r;
	const char *usage;
	zoneid_t zoneid = getzoneid();
	pid_t init_pid = 1;
	int need_check_zones;

	char bootargs_buf[257];		/* uadmin()'s buffer is 257 bytes. */

	const char * const resetting = "/etc/svc/volatile/resetting";


	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);

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

	if (zone_getattr(getzoneid(), ZONE_ATTR_INITPID, &init_pid,
	    sizeof (init_pid)) != sizeof (init_pid)) {
		assert(errno == ESRCH);
		init_pid = -1;
	}

	/*
	 * We start to fork a bunch of zoneadms to halt any active zones.
	 * This will proceed with halt in parallel until we call
	 * check_zone_haltedness later on.
	 */
	if (zoneid == GLOBAL_ZONEID && cmd != A_DUMP) {
		need_check_zones = halt_zones(cmdname);
	}


	/* sync boot archive in the global zone */
	if (getzoneid() == GLOBAL_ZONEID && !nosync) {
		(void) system("/sbin/bootadm -a update_all");
	}

	/*
	 * If we're not forcing a crash dump, mark the system as quiescing for
	 * smf(5)'s benefit, and idle the init process.
	 */
	if (cmd != A_DUMP) {
		if (init_pid != -1 && kill(init_pid, SIGTSTP) == -1) {
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
			check_zones_haltedness(cmdname);

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

	(void) uadmin(cmd, fcn, mdep);
	perror(cmdname);
	do
		r = remove(resetting);
	while (r != 0 && errno == EINTR);
	if (r != 0 && errno != ENOENT)
		(void) fprintf(stderr, gettext("%s: could not remove %s.\n"),
		    cmdname, resetting);

	continue_restarters();

	if (init_pid != -1)
		/* tell init to restate current level */
		(void) kill(init_pid, SIGHUP);

fail:
	if (fcn == AD_BOOT)
		(void) audit_reboot_fail();
	else
		(void) audit_halt_fail();

	return (1);
}
