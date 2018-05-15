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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/types.h>
#include <sys/wait.h>
#include <stdio.h>
#include <errno.h>
#include <limits.h>
#include <fcntl.h>
#include <strings.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <thread.h>

#include <locale.h>
#include <langinfo.h>
#include <libintl.h>
#include <stdarg.h>

#include <sys/nsctl/rdc_io.h>
#include <sys/nsctl/rdc_ioctl.h>
#include <sys/nsctl/rdc_prot.h>

#include <sys/nsctl/cfg.h>

#include <sys/unistat/spcs_s.h>
#include <sys/unistat/spcs_s_u.h>
#include <sys/unistat/spcs_errors.h>

#include <sys/nsctl/librdc.h>

#include "rdcadm.h"


#define	RDCADM "/usr/sbin/sndradm"
#define	IIADM "/usr/sbin/iiadm"

#define	UPDATE "update"
#define	NOUPDATE "noupdate"

#define	RESYNC_SLEEP	(3 * 60)	/* Three minutes */
#define	MAIN_SLEEP	(5 * 60)	/* Five minutes */
#define	CFG_WAIT_SLEEP	(5)		/* 5 sec */

#define	MAXHOSTS 1024
mutex_t cfglock = DEFAULTMUTEX;
#define	LOCKCFG() (void) mutex_lock(&cfglock);
#define	UNLOCKCFG() (void) mutex_unlock(&cfglock);

typedef struct host_list_s {
	char *hosts[MAXHOSTS];
	int numhosts;
	int configured[MAXHOSTS];
	mutex_t hosts_mutex;
} host_list_t;

host_list_t *host_list;

extern char *basename(char *);
int rdc_maxsets;
char *program;

static int clustered = 0;

int isnewhost(char *host);
void *wait_sync_event();
void *wait_link_down(void *host);
void rdc_sync(char *tohost);
void remove_from_hostlist(char *host);
void sync_start(char *master);
void sync_complete(char *master);
void cleanup_hostlist();
void group_start(char *group);
void group_complete(char *group);


void
init_host_list(void)
{
	host_list = calloc(1, sizeof (host_list_t));
	if (host_list == NULL) {
		spcs_log("sndr", NULL,
		    gettext("host list not initialized, cannot run"));
		rdc_err(NULL, gettext("host list not initialized, cannot run"));
	}
	(void) mutex_init(&host_list->hosts_mutex, USYNC_THREAD, NULL);
}

/* ARGSUSED */
#ifdef lint
void
sndrsyncd_lintmain(argc, argv)
#else
int
main(argc, argv)
#endif
int argc;
char **argv;
{
	rdc_status_t *rdc_info;
	int size;
	int i;
	pid_t pid;
	spcs_s_info_t ustatus;
	int rc, trc;
	int first = 0;
	char *required;

	(void) setlocale(LC_ALL, "");
	(void) textdomain("rdc");

	ustatus = spcs_s_ucreate();

	program = basename(argv[0]);

	init_host_list();

	rc = rdc_check_release(&required);
	if (rc < 0) {
		rdc_err(NULL,
		    gettext("unable to determine the current "
		    "Solaris release: %s\n"), strerror(errno));
		/* NOTREACHED */
	} else if (rc == FALSE) {
		rdc_err(NULL,
		    gettext("incorrect Solaris release (requires %s)\n"),
		    required);
		/* NOTREACHED */
	}

	clustered = cfg_iscluster();
	if (clustered < 0) {
		rdc_err(NULL, gettext("unable to ascertain environment"));
	}

	rdc_maxsets = rdc_get_maxsets();
	if (rdc_maxsets == -1) {
		spcs_log("sndr", NULL,
		    gettext("%s: unable to get maxsets value from kernel"),
		    program);
		rdc_err(NULL,
		    gettext("unable to get maxsets value from kernel"));
	}
	size = sizeof (rdc_status_t) + (sizeof (rdc_set_t) * (rdc_maxsets - 1));
	rdc_info = malloc(size);
	if (rdc_info == NULL) {
		spcs_log("sndr", NULL,
		    gettext("%s: unable to allocate %ld bytes"),
		    program, size);
		rdc_err(NULL,
			gettext("unable to allocate %ld bytes"), size);
	}
	bzero(rdc_info, size);

	rdc_info->nset = rdc_maxsets;

	/*
	 * Fork off a child that becomes the daemon.
	 */
	if ((pid = fork()) > 0)
		exit(0);
	else if (pid < 0) {
		spcs_log("sndr", NULL,
		    gettext("%s: cannot fork: %s"),
		    program, strerror(errno));
		rdc_err(NULL, gettext("cannot fork: %s\n"),
		    strerror(errno));
	}

	/*
	 * In child - become daemon.
	 */

	for (i = 0; i < 3; i++)
		(void) close(i);

	(void) open("/dev/console", O_WRONLY|O_APPEND);
	(void) dup(0);
	(void) dup(0);
	(void) close(0);

	(void) setpgrp();

	(void) setlocale(LC_ALL, "");
	(void) textdomain("rdc");

	/* launch a thread to wait for sync start and sync stop events */

	if ((trc = thr_create(NULL, 0, wait_sync_event, NULL,
	    THR_BOUND|THR_DETACHED, NULL)) != 0) {
		spcs_log("sndr", NULL,
		    gettext("%s: unable to create thread wait_sync_event"),
		    program);
		rdc_warn(NULL,
		    gettext("%s unable to create thread wait_sync_event"),
		    program);
	} else {
#ifdef DEBUG
		spcs_log("sndr", NULL,
		    gettext("%s: thread wait_sync_event started"), program);
#endif
		;
	}

	for (;;) {
		if (!first) {
			first++;
			(void) sleep(15);
		} else
			(void) sleep(MAIN_SLEEP);

		bzero(rdc_info, size);
		rdc_info->nset = rdc_maxsets;
		if (RDC_IOCTL(RDC_STATUS, rdc_info, 0, 0, 0, 0, ustatus)
		    != SPCS_S_OK) {
			spcs_log("sndr", &ustatus,
			    gettext("%s: status ioctl"),
			    program);
			rdc_warn(&ustatus, gettext("status ioctl"));
			continue;
		}

		cleanup_hostlist(rdc_info); /* remove non-existent hosts */

		/*
		 * Check all enabled sets to see if a new remote host has
		 * appeared.
		 */
		for (i = 0; i < rdc_maxsets; i++) {
			if (!(rdc_info->rdc_set[i].flags & RDC_ENABLED))
				continue;
			/* spawn a new thread for each new host found */
			if (isnewhost(rdc_info->rdc_set[i].secondary.intf)) {
				/*
				 * right now, we could be here before
				 * the database did the write for this set
				 * I could check the lock on the database
				 * but I am just going to give up some time here
				 * instead. Why do the allocations etc, etc
				 * if the set is enabled in the kernel and not
				 * in the config, we know that this set has the
				 * lock. Why bother adding more contention to
				 * the lock.
				 * this is a daemon, afterall. its got time
				 */
				(void) sleep(CFG_WAIT_SLEEP);

				spcs_log("sndr", NULL,
				    gettext("%s: new host found (%s) starting "
				    "its autosync thread"), program,
				    rdc_info->rdc_set[i].secondary.intf);

				trc = thr_create(NULL, 0, wait_link_down,
				    (void *) rdc_info->rdc_set[i].\
secondary.intf, THR_BOUND|THR_DETACHED, NULL);

				if (trc != 0) {
					spcs_log("sndr", NULL,
					    gettext(
					    "%s create new autosync "
					    "thread failed"), program);
					rdc_warn(NULL, gettext(
					    "%s create new autosync "
					    "thread failed"), program);
				}
			}
		}
	}
	/* NOTREACHED */
}


/*
 * The kernel wakes up this function every time it detects the link to the
 * specified host has dropped.
 */
void *
wait_link_down(void *thehost)
{
	char *host = (char *)thehost;
	char tmphost[MAX_RDC_HOST_SIZE] = { '\0' };
	spcs_s_info_t ustatus;

	if (host)
		(void) strncpy(tmphost, host, MAX_RDC_HOST_SIZE);

	ustatus = spcs_s_ucreate();

	/* Never give up */
	for (;;) {
#ifdef DEBUG
		spcs_log("sndr", NULL,
		    gettext("%s: awaiting link down ioctl for %s"),
		    program, host[0] == '\0' ? tmphost : host);
#endif
		if (RDC_IOCTL(RDC_LINK_DOWN, host, 0, 0, 0, 0, ustatus)
		    != SPCS_S_OK) {
			spcs_log("sndr", &ustatus,
			    gettext("%s: link down ioctl"),
			    program);
			rdc_warn(&ustatus, gettext("link down ioctl"));
			continue;
		}
#ifdef DEBUG

		spcs_log("sndr", NULL,
		    gettext("%s: received link down ioctl for %s"),
		    program, host[0] == '\0' ? tmphost : host);
#endif
		rdc_sync(host[0] == '\0' ? tmphost : host);
	}
	/* LINTED */
}


/*
 * Called when the link to the specified host has dropped.
 * For all Remote Mirror sets using the link that have autosync on,
 * issue rdcadm -u commands until they complete successfully.
 */
void
rdc_sync(char *tohost)
{
	rdc_set_t *rdc_set = NULL;
	int *sync_done = NULL;
	int sets = 0;
	int syncs_done = 0;
	char cmd[256];
	rdc_config_t parms = { 0 };
	spcs_s_info_t ustatus;
	int i;
	int setnumber;
	int numfound = 0;
	char buf[CFG_MAX_BUF];
	char key[CFG_MAX_KEY];
	CFGFILE *cfg = NULL;
	int size;
	int first = 0;
	int death = 0;
	int cfglocked = 0;

	ustatus = spcs_s_ucreate();

	size = sizeof (rdc_set_t) * rdc_maxsets;
	rdc_set = malloc(size);
	if (rdc_set == NULL) {
		spcs_log("sndr", NULL,
		    gettext("%s: unable to allocate %ld bytes"),
		    program, size);
		rdc_warn(NULL,
			gettext("unable to allocate %ld bytes"), size);
		goto done;
	}
	bzero(rdc_set, size);
	size = sizeof (int) * rdc_maxsets;
	sync_done = malloc(size);
	if (sync_done == NULL) {
		spcs_log("sndr", NULL,
		    gettext("%s: unable to allocate %ld bytes"),
		    program, size);
		rdc_warn(NULL,
			gettext("unable to allocate %ld bytes"), size);
		goto done;
	}
	bzero(sync_done, size);

	/*
	 * Get all sndr entries with shost matching tohost, and save the
	 * details in an array.
	 */
	for (i = 0; i < rdc_maxsets; i++) {
		setnumber = i + 1;
		bzero(buf, sizeof (buf));
		bzero(key, sizeof (key));

		(void) snprintf(key, sizeof (key), "sndr.set%d.shost",
		    setnumber);

		if (!cfglocked) {
			LOCKCFG();
			if ((cfg = cfg_open(NULL)) == NULL) {
				spcs_log("sndr", NULL,
				    gettext("%s: error opening config"),
				    program);

				rdc_warn(NULL,
				    gettext("error opening config"));
				UNLOCKCFG();
				goto done;
			}

			if (!cfg_lock(cfg, CFG_RDLOCK)) {
				spcs_log("sndr", NULL,
				    gettext("%s: error locking config"),
				    program);
				rdc_warn(NULL, gettext("error locking config"));
				goto done;
			}
		}

		cfglocked = 1;

		if (cfg_get_cstring(cfg, key, buf, CFG_MAX_BUF) < 0) {
			if (numfound == 0) /* no matching hosts */
				death = 1; /* thread will exit */
			break;
		}
		if (strcmp(buf, tohost) != 0)
			continue;

		numfound++;
		(void) strncpy(rdc_set[sets].secondary.intf, buf,
		    MAX_RDC_HOST_SIZE);

		/* Got a matching entry */

		(void) snprintf(key, sizeof (key), "sndr.set%d.phost",
		    setnumber);
		if (cfg_get_cstring(cfg, key, buf, CFG_MAX_BUF) < 0)
			break;
		(void) strncpy(rdc_set[sets].primary.intf, buf,
		    MAX_RDC_HOST_SIZE);

		(void) snprintf(key, sizeof (key), "sndr.set%d.primary",
		    setnumber);
		if (cfg_get_cstring(cfg, key, buf, CFG_MAX_BUF) < 0)
			break;
		(void) strncpy(rdc_set[sets].primary.file, buf, NSC_MAXPATH);

		(void) snprintf(key, sizeof (key), "sndr.set%d.secondary",
		    setnumber);
		if (cfg_get_cstring(cfg, key, buf, CFG_MAX_BUF) < 0)
			break;
		(void) strncpy(rdc_set[sets].secondary.file, buf, NSC_MAXPATH);

		parms.command = RDC_CMD_STATUS;
		bcopy((void *)(&rdc_set[sets]), (void *)(&parms.rdc_set[0]),
		    sizeof (rdc_set_t));

		/*
		 * release cfg before diving into the kernel
		 * this prevents a possible deadlock when doing
		 * a reverse sync whick will wake up the sync_event
		 * thread which will try and iiadm -c and hang
		 * because we still have the cfg_lock. the timed
		 * wait cv in the kernel will fail the sync and things
		 * will undeadlock.
		 */

		cfg_close(cfg);
		cfg = NULL;
		cfglocked = 0;
		UNLOCKCFG();

		if (RDC_IOCTL(RDC_CONFIG, &parms, NULL, 0, 0, 0, ustatus) < 0) {
			continue;
		}
		if ((parms.rdc_set[0].autosync == 0) ||
		    (!(parms.rdc_set[0].flags & RDC_LOGGING))) {
			continue;
		}

		/* Found a suitable set with autosync on, in logging mode */
		sets++;
	}

	if (cfg) {
		cfg_close(cfg);
		cfg = NULL;
		UNLOCKCFG();
	}

	if (sets == 0) {
#ifdef DEBUG
		spcs_log("sndr", NULL,
		    gettext("%s: no sets requiring autosync found for %s"),
		    program, tohost);
#endif
		if (death) {
			spcs_log("sndr", NULL,
			    gettext("%s: autosync thread stopping for %s "
			    "(host deconfigured)"), program, tohost);
		}
		goto done;
	}

	/* Keep issuing rdcadm -u commands until they have all completed */
	for (;;) {
		if (!first)
			first++;
		else
			(void) sleep(RESYNC_SLEEP);

		/* Issue rdcadm -u commands for all remaining sets */
		for (i = 0; i < sets; i++) {
			if (sync_done[i])
				continue;

			/*
			 * Need to check if autosync was turned off for a set
			 * while we were sleeping. We could have the case where
			 * an update sync failed and autosync was disabled
			 * while we were sleeping and didn't detect the disable.
			 * See BugID 4814213.
			 */
			parms.command = RDC_CMD_STATUS;
			bcopy((void *)(&rdc_set[i]),
			    (void *)(&parms.rdc_set[0]), sizeof (rdc_set_t));
			if (RDC_IOCTL(RDC_CONFIG, &parms, NULL, 0, 0, 0,
			    ustatus) < 0) {
				spcs_log("sndr", &ustatus, gettext("%s: "
				    "status not available for %s:%s, stopping "
				    "this autosync attempt"), program, tohost,
				    rdc_set[i].secondary.file);
				sync_done[i] = 1;
				syncs_done++;
				continue;
			}
			if (!(parms.rdc_set[0].autosync)) {
#ifdef DEBUG
	spcs_log("sndr", NULL, gettext("%s: autosync disabled during sleep, "
	    "stopping attempt for set %s:%s"), program, tohost,
	    rdc_set[i].secondary.file);
#endif
				sync_done[i] = 1;
				syncs_done++;
				continue;
			}

			(void) sprintf(cmd, "%s -un %s:%s", RDCADM, tohost,
			    rdc_set[i].secondary.file);
			spcs_log("sndr", NULL,
			    gettext("%s: issuing update sync for %s:%s"),
			    program, tohost, rdc_set[i].secondary.file);
			(void) system(cmd);
		}

		/* Issue rdcadm -w commands to wait for updates to finish */
		for (i = 0; i < sets; i++) {
			if (sync_done[i])
				continue;

			(void) sprintf(cmd, "%s -wn %s:%s", RDCADM, tohost,
			    rdc_set[i].secondary.file);
			spcs_log("sndr", NULL,
			    gettext("%s: issuing wait for %s:%s"),
			    program, tohost, rdc_set[i].secondary.file);

			(void) system(cmd);

			parms.command = RDC_CMD_STATUS;
			bcopy((void *)(&rdc_set[i]),
			    (void *)(&parms.rdc_set[0]), sizeof (rdc_set_t));

			if (RDC_IOCTL(RDC_CONFIG, &parms, NULL, 0, 0, 0,
			    ustatus) < 0) {
				spcs_log("sndr", &ustatus,
				    gettext("%s: status not available for "
				    "%s:%s, stopping this autosync attempt"),
				    program, tohost, rdc_set[i].secondary.file);
				sync_done[i] = 1;
				syncs_done++;
				continue;
			}
			/* Check if completed OK, failed or autosync off */
			if (!(parms.rdc_set[0].autosync) ||
			    !(parms.rdc_set[0].flags & RDC_LOGGING) &&
			    !(parms.rdc_set[0].flags & RDC_SYNCING)) {
				sync_done[i] = 1;
				syncs_done++;
			}
		}

		if (syncs_done == sets)
			break;		/* All completed OK */
	}

done:
	if (cfg) {
		cfg_close(cfg);
		UNLOCKCFG();
	}
	spcs_s_ufree(&ustatus);
	if (sync_done)
		free(sync_done);
	if (rdc_set)
		free(rdc_set);
	if (death) { /* bye bye */
		/*
		 * if perhaps we lost some race, lets remove this entry from
		 * the list. Then, if something did go wrong, and we did kill
		 * a valid thread, it will be detected on the next go around
		 * of the thread who is looking for new hosts to spawn threads
		 */

		remove_from_hostlist(tohost);
		thr_exit(0);
	}

	(void) sleep(RESYNC_SLEEP);
}

/*
 * Wait for notification by the kernel of a sync start or a sync completed OK
 */
void *
wait_sync_event()
{
	spcs_s_info_t ustatus;
	char master[NSC_MAXPATH];
	char group[NSC_MAXPATH];
	int state;

	ustatus = spcs_s_ucreate();

	master[0] = '\0';
	group[0] = '\0';

	/* Never give up */
	for (;;) {
		/* Kernel tells us which volume and group the event is for */
		state = RDC_IOCTL(RDC_SYNC_EVENT, master, group, 0, 0, 0,
		    ustatus);
		if (state < SPCS_S_OK) {
			if (errno != EAGAIN) {
				spcs_log("sndr", &ustatus,
				    gettext("%s: update ioctl"),
				    program);
				rdc_warn(&ustatus, gettext("update ioctl"));
				continue;
			}
			master[0] = '\0';
			continue;
		}

		/*
		 * If target is mounted at the start of a sync or reverse sync,
		 * return a negative ack.
		 */
		if ((state == RDC_SYNC_START || state == RDC_RSYNC_START) &&
		    mounted(master)) {
			spcs_log("sndr", NULL,
			    gettext("%s: %s has a file system mounted"),
			    program, master);
			rdc_warn(NULL,
			    gettext("%s has a file system mounted"),
			    master);
			master[0] = '\0';	/* negative ack */
			continue;
		}

		switch (state) {
		case RDC_SYNC_START:
			if (group[0])
				group_start(group);
			else
				sync_start(master);
			break;

		case RDC_SYNC_DONE:
			if (group[0])
				group_complete(group);
			else
				sync_complete(master);
			break;

		default:
			break;
		}
	}
	/* LINTED */
}


/*
 * A sync has completed OK to a volume not belonging to a group.
 * Set the state of the ndr_ii config entry to "update".
 */
void
sync_complete(char *master)
{
	CFGFILE *cfg = NULL;
	char buf[CFG_MAX_BUF];
	char key[CFG_MAX_KEY];
	int i;
	int setnumber;
	int sev;

	LOCKCFG();
	if ((cfg = cfg_open(NULL)) == NULL) {
		spcs_log("sndr", NULL,
		    gettext("%s: error opening config"),
		    program);
		rdc_warn(NULL, gettext("error opening config"));
		UNLOCKCFG();
		return;
	}
	if (!cfg_lock(cfg, CFG_WRLOCK)) {
		spcs_log("sndr", NULL,
		    gettext("%s: error locking config"),
		    program);
		rdc_warn(NULL, gettext("error locking config"));
		cfg_close(cfg);
		UNLOCKCFG();
		return;
	}

	/* get ndr_ii entries until a match is found */
	for (i = 0; ; i++) {
		setnumber = i + 1;

		(void) snprintf(key, sizeof (key), "ndr_ii.set%d.secondary",
		    setnumber);
		if (cfg_get_cstring(cfg, key, buf, CFG_MAX_BUF) < 0)
			break;
		if (strcmp(buf, master) != 0)
			continue;

		/* Found the matching entry */

		/*
		 * Set state to "update" so that starting another sync will
		 * cause a new Point-in-Time Copy snapshot to be taken.
		 */
		(void) snprintf(key, sizeof (key), "ndr_ii.set%d.state",
		    setnumber);
		if ((cfg_put_cstring(cfg, key, UPDATE, strlen(UPDATE)) < 0) ||
		    (cfg_commit(cfg) < 0)) {
			spcs_log("sndr", NULL,
			    gettext("%s: unable to update \"%s\" "
			    "in configuration storage: %s"),
			    program, buf, cfg_error(&sev));
			rdc_warn(NULL,
			    gettext("unable to update \"%s\" "
			    "in configuration storage: %s"),
			    buf, cfg_error(&sev));
		}
		break;
	}

	cfg_close(cfg);
	UNLOCKCFG();
}


/*
 * Starting a sync to the specified master volume.
 * Check the ndr_ii config entries to see if a Point-in-Time Copy
 * snapshot should be taken.
 */
void
sync_start(char *master)
{
	char cmd[256];
	char buf[CFG_MAX_BUF];
	char key[CFG_MAX_KEY];
	CFGFILE *cfg = NULL;
	int i;
	int setnumber;
	int found;
	int sev;
	char shadow[NSC_MAXPATH];
	char bitmap[NSC_MAXPATH];
	char *ctag = NULL;

	LOCKCFG();
	if ((cfg = cfg_open(NULL)) == NULL) {
		spcs_log("sndr", NULL,
		    gettext("%s: error opening config"),
		    program);
		rdc_warn(NULL,
		    gettext("error opening config"));
		UNLOCKCFG();
		return;
	}
	if (!cfg_lock(cfg, CFG_RDLOCK)) {
		spcs_log("sndr", NULL,
		    gettext("%s: error locking config"),
		    program);
		rdc_warn(NULL, gettext("error locking config"));
		cfg_close(cfg);
		UNLOCKCFG();
		return;
	}

	found = 0;
	/* get ndr_ii entries until a match is found */
	for (i = 0; ; i++) {
		setnumber = i + 1;

		(void) snprintf(key, sizeof (key), "ndr_ii.set%d.secondary",
		    setnumber);
		if (cfg_get_cstring(cfg, key, buf, CFG_MAX_BUF) < 0)
			break;
		if (strcmp(buf, master) != 0)
			continue;

		/* Got a matching entry */

		(void) snprintf(key, sizeof (key), "ndr_ii.set%d.shadow",
		    setnumber);
		if (cfg_get_cstring(cfg, key, buf, CFG_MAX_BUF) < 0)
			break;
		(void) strncpy(shadow, buf, NSC_MAXPATH);

		(void) snprintf(key, sizeof (key), "ndr_ii.set%d.bitmap",
		    setnumber);
		if (cfg_get_cstring(cfg, key, buf, CFG_MAX_BUF) < 0)
			break;
		(void) strncpy(bitmap, buf, NSC_MAXPATH);

		(void) snprintf(key, sizeof (key), "ndr_ii.set%d.state",
		    setnumber);
		if (cfg_get_cstring(cfg, key, buf, CFG_MAX_BUF) < 0)
			break;

		/*
		 * If an PIT snapshot has already been taken, and syncing did
		 * not complete, the state will be "noupdate", to indicate we
		 * should not take another one at this point.
		 */
		if (strcmp(buf, NOUPDATE) != 0)
			found = 1;

		break;
	}

	if (!found) {
		cfg_close(cfg);
		UNLOCKCFG();
		return;
	}

	found = 0;
	/* get ii entries until a match is found */
	for (i = 0; ; i++) {
		setnumber = i + 1;

		(void) snprintf(key, sizeof (key), "ii.set%d.shadow",
		    setnumber);
		if (cfg_get_cstring(cfg, key, buf, CFG_MAX_BUF) < 0)
			break;
		if (strcmp(buf, shadow) != 0)
			continue;

		/* Matching shadow found, so ii already enabled */
		found = 1;
		break;
	}

	if (found) {
		/* Already PIT enabled, so just take a snapshot */

		/* Get cluster tag of matching entry */
		(void) snprintf(key, sizeof (key), "ii.set%d.cnode", setnumber);
		if (cfg_get_cstring(cfg, key, buf, CFG_MAX_BUF) >= 0)
			if ((strlen(buf) == 0) || (buf[0] == '-'))
					ctag = "-C local";
				else
					ctag = "";
		(void) sprintf(cmd, "%s %s -u s %s", IIADM, ctag, shadow);
	} else {
		/*
		 * If clustered, need to enable PIT Copy sets in the same
		 * cluster as the Remote Mirror set
		 */

		if (clustered) {
			/* Find a RM set with master as the local volume */

			for (i = 0; i < rdc_maxsets; i++) {
				setnumber = i + 1;
				(void) snprintf(key, sizeof (key),
				    "sndr.set%d.phost", setnumber);
				if (cfg_get_cstring(cfg, key, buf,
				    CFG_MAX_BUF) < 0)
					break;

				if (self_check(buf))
					(void) snprintf(key, sizeof (key),
					    "sndr.set%d.primary", setnumber);
				else
					(void) snprintf(key, sizeof (key),
					    "sndr.set%d.secondary", setnumber);
				if (cfg_get_cstring(cfg, key, buf,
				    CFG_MAX_BUF) < 0)
					break;

				if (strcmp(buf, master) != 0)
					continue;

				/* Get cluster tag of matching entry */

				(void) snprintf(key, sizeof (key),
				    "sndr.set%d.cnode", setnumber);
				if (cfg_get_cstring(cfg, key, buf,
				    CFG_MAX_BUF) < 0)
					break;
				if ((strlen(buf) == 0) || (buf[0] == '-'))
					ctag = strdup("local");
				else
					ctag = strdup(buf);
				break;
			}
		}

		/* Not already enabled, so enable a dependent */
		if (ctag) {
			(void) sprintf(cmd, "%s -C %s -e dep %s %s %s", IIADM,
			    ctag, master, shadow, bitmap);
			free(ctag);
		} else
			(void) sprintf(cmd, "%s -e dep %s %s %s", IIADM, master,
			    shadow, bitmap);
	}

	cfg_close(cfg);

	if (system(cmd) != 0) {
		spcs_log("sndr", NULL,
		    gettext("Point-in-Time Copy snapshot failed for %s %s %s."
		    " Please check validity of ndr_ii entry"),
		    master, shadow, bitmap);
		cfg_close(cfg);
		UNLOCKCFG();
		return;
	}

	/*
	 * PIT Copy enable or update was fine, so update the ndr_ii entry
	 * to "noupdate", to prevent invalid point in time copies.
	 */

	if ((cfg = cfg_open(NULL)) == NULL) {
		spcs_log("sndr", NULL,
		    gettext("%s: error opening config"),
		    program);
		rdc_warn(NULL,
		    gettext("error opening config"));
		UNLOCKCFG();
		return;
	}
	if (!cfg_lock(cfg, CFG_WRLOCK)) {
		spcs_log("sndr", NULL,
		    gettext("%s: error locking config"),
		    program);
		rdc_warn(NULL, gettext("error locking config"));
		cfg_close(cfg);
		UNLOCKCFG();
		return;
	}

	/* get ndr_ii entries until a match is found */
	for (i = 0; ; i++) {
		setnumber = i + 1;

		(void) snprintf(key, sizeof (key), "ndr_ii.set%d.shadow",
		    setnumber);
		if (cfg_get_cstring(cfg, key, buf, CFG_MAX_BUF) < 0)
			break;
		if (strcmp(buf, shadow) != 0)
			continue;

		/* Found the matching entry */

		(void) snprintf(key, sizeof (key), "ndr_ii.set%d.state",
		    setnumber);
		if ((cfg_put_cstring(cfg, key, NOUPDATE,
			strlen(NOUPDATE)) < 0) || (cfg_commit(cfg) < 0)) {
			spcs_log("sndr", NULL,
			    gettext("%s: unable to update \"%s\" "
			    "in configuration storage: %s"),
			    program, buf, cfg_error(&sev));
			rdc_warn(NULL,
			    gettext("unable to update \"%s\" "
			    "in configuration storage: %s"),
			    buf, cfg_error(&sev));
		}
		break;
	}
	cfg_close(cfg);
	UNLOCKCFG();
}

void
cleanup_hostlist(rdc_status_t *rdc_info)
{
	int i, j, k;
	char *host, *exhost;


	(void) mutex_lock(&host_list->hosts_mutex);
	for (i = 0; i < host_list->numhosts; i++) {
		int found = 0;
		for (j = 0; (j < rdc_maxsets) && !found; j++) {
			if (!rdc_info->rdc_set[j].flags & RDC_ENABLED)
				continue;
			if ((!host_list->configured[i]) ||
			    (host_list->hosts[i] == NULL)) {
				(void) mutex_unlock(&host_list->hosts_mutex);
				return;
			}

			host = rdc_info->rdc_set[j].secondary.intf;
			if (strcmp(host_list->hosts[i], host) == 0)
				found++;
		}
		if (j == rdc_maxsets) {
			/*
			 * this set is not in the kernel, so remove from list
			 */
			exhost = host_list->hosts[i];
			if (exhost) {
				free(exhost);
				exhost = NULL;
			}

			k = i;
			while (k < host_list->numhosts) {
			    host_list->hosts[k] = k < host_list->numhosts - 1 ?
				host_list->hosts[k+1] : NULL;
			    k++;
			}
			host_list->numhosts--;

			bcopy(&host_list->configured[i+1],
			    &host_list->configured[i],
			    (MAXHOSTS - i + 1) * sizeof (int));
			host_list->configured[MAXHOSTS - 1] = 0;
		}
	}
	(void) mutex_unlock(&host_list->hosts_mutex);
}

/*
 * explicity remove a host from the host list
 * also update the configured array
 * called in rdc_sync, just before exiting a thread.
 */
void
remove_from_hostlist(char *host)
{
	int i, k;
	char *exhost;

	/* why bother? */
	if ((!host) || (host[0] == '\0'))
		return;

	(void) mutex_lock(&host_list->hosts_mutex);
	for (i = 0; i < host_list->numhosts; i++) {
		if (strcmp(host, host_list->hosts[i]) == 0) { /* found it */
			exhost = host_list->hosts[i];
			if (exhost) {
				free(exhost);
				exhost = NULL;
			}
			k = i;
			while (k < host_list->numhosts) {
			    host_list->hosts[k] = k < host_list->numhosts - 1 ?
				host_list->hosts[k+1] : NULL;
			    k++;
			}
			host_list->numhosts--;
			bcopy(&host_list->configured[i+1],
			    &host_list->configured[i],
			    (MAXHOSTS - i + 1) * sizeof (int));
			host_list->configured[MAXHOSTS - 1] = 0;
		}

	}
	(void) mutex_unlock(&host_list->hosts_mutex);
}
/*
 * Check to see if this host isn't in our list, so needs a new rdcsyncd proc
 */
int
isnewhost(char *host)
{
	int i;
	int new;

	if (self_check(host)) {
		return (0);
	}

	(void) mutex_lock(&host_list->hosts_mutex);
	new = 1;
	for (i = 0; i < MAXHOSTS; i++) {
		if (host_list->configured[i] == 0) {
			host_list->configured[i] = 1;
			host_list->hosts[i] = strdup(host);
			host_list->numhosts++;
			break;
		}
		if (strcmp(host, host_list->hosts[i]) == 0) {
			new = 0;
			break;
		}
	}
	(void) mutex_unlock(&host_list->hosts_mutex);
	if (i == MAXHOSTS)
		new = 0;
	return (new);
}


/*
 * Look for a matching volume name in our remembered list.
 */
int
volume_match(char *buf, char **volume_list, int volumes)
{
	int i;
	char *vol;

	for (i = 0; i < volumes; i++) {
		vol = volume_list[i];
		if (strcmp(buf, vol) == 0) {
			return (1);
		}
	}
	return (0);
}


/*
 * A sync has completed to a group. We can only update the ndr_ii entries
 * if all the members of the group have completed their syncs OK.
 * It would be bad to allow some members of the group to have PIT Copy snapshots
 * taken and others not, as they need to be consistent.
 */
void
group_complete(char *group)
{
	char **volumes = NULL;
	spcs_s_info_t ustatus;
	rdc_config_t parms = { 0 };
	char buf[CFG_MAX_BUF];
	char key[CFG_MAX_KEY];
	CFGFILE *cfg = NULL;
	int i;
	int setnumber;
	int found;
	int replicating = 0;
	char primary[NSC_MAXPATH];
	char secondary[NSC_MAXPATH];
	char phost[MAX_RDC_HOST_SIZE];
	char shost[MAX_RDC_HOST_SIZE];
	rdc_set_t *rdc_set;
	int sev;
	char *local_file;
	int size;

	ustatus = spcs_s_ucreate();

	size = sizeof (char *) * rdc_maxsets;
	volumes = malloc(size);
	if (volumes == NULL) {
		spcs_log("sndr", NULL,
		    gettext("%s: unable to allocate %ld bytes"),
		    program, size);
		rdc_warn(NULL,
			gettext("unable to allocate %ld bytes"), size);
		goto done;
	}
	bzero(volumes, size);

	/*
	 * If all members of this group are replicating
	 * set ii_ndr state to "update". Otherwise leave them alone.
	 */
	LOCKCFG();
	if ((cfg = cfg_open(NULL)) == NULL) {
		spcs_log("sndr", NULL,
		    gettext("%s: error opening lconfig"),
		    program);
		rdc_warn(NULL, gettext("error opening config"));
		UNLOCKCFG();
		goto done;
	}

	if (!cfg_lock(cfg, CFG_RDLOCK)) {
		spcs_log("sndr", NULL,
		    gettext("%s: error locking config"),
		    program);
		rdc_warn(NULL, gettext("error locking config"));
		goto done;
	}

	found = 0;

	/* get all RM entries, with a matching group, that are replicating */
	for (i = 0; i < rdc_maxsets; i++) {
		setnumber = i + 1;

		(void) snprintf(key, sizeof (key),
		    "sndr.set%d.group", setnumber);
		if (cfg_get_cstring(cfg, key, buf, CFG_MAX_BUF) < 0)
			break;

		if (strcmp(buf, group) != 0)
			continue;

		/* Found a matching entry */

		(void) snprintf(key, sizeof (key),
		    "sndr.set%d.primary", setnumber);
		if (cfg_get_cstring(cfg, key, primary, sizeof (primary)) < 0)
			break;
		(void) strcpy(parms.rdc_set->primary.file, primary);

		(void) snprintf(key, sizeof (key),
		    "sndr.set%d.phost", setnumber);
		if (cfg_get_cstring(cfg, key, phost, sizeof (phost)) < 0)
			break;
		(void) strcpy(parms.rdc_set->primary.intf, phost);

		(void) snprintf(key, sizeof (key),
		    "sndr.set%d.secondary", setnumber);
		if (cfg_get_cstring(cfg, key, secondary,
				sizeof (secondary)) < 0)
			break;
		(void) strcpy(parms.rdc_set->secondary.file, secondary);

		(void) snprintf(key, sizeof (key),
		    "sndr.set%d.shost", setnumber);
		if (cfg_get_cstring(cfg, key, shost, sizeof (shost)) < 0)
			break;
		(void) strcpy(parms.rdc_set->secondary.intf, shost);

		parms.command = RDC_CMD_STATUS;
		if (RDC_IOCTL(RDC_CONFIG, &parms, NULL, 0, 0, 0, ustatus) < 0) {
			continue;
		}

		/* We found a matching set */
		found++;

		if (self_check(phost))
			local_file = primary;
		else
			local_file = secondary;

		rdc_set = &parms.rdc_set[0];
		if (!(rdc_set->flags & RDC_LOGGING) &&
		    !(rdc_set->flags & RDC_SYNCING)) {
			volumes[replicating] = strdup(local_file);
			if (volumes[replicating] == NULL) {
				size = strlen(local_file);
				spcs_log("sndr", NULL,
				    gettext("%s: unable to allocate %ld bytes"),
				    program, size);
				rdc_warn(NULL,
				    gettext("unable to allocate %ld bytes"),
				    size);
				goto done;
			}
			/* We remember all replicating sets */
			replicating++;
		} else
			break;		/* Not all replicating, so done */
	}

	if (found != replicating)
		goto done;

	/* All replicating, so update ndr_ii state fields */

	cfg_unlock(cfg);

	if (!cfg_lock(cfg, CFG_WRLOCK)) {
		spcs_log("sndr", NULL,
		    gettext("%s: error locking lconfig"),
		    program);
		rdc_warn(NULL, gettext("error locking config"));
		goto done;
	}

	/*
	 * Search through the ndr_ii entries for entries
	 * that match the saved secondary volume names.
	 * Set state to "update".
	 */

	for (i = 0; ; i++) {
		setnumber = i + 1;

		(void) snprintf(key, sizeof (key), "ndr_ii.set%d.secondary",
		    setnumber);
		if (cfg_get_cstring(cfg, key, buf, CFG_MAX_BUF) < 0)
			break;

		if (!volume_match(buf, volumes, found)) {
			continue;
		}

		/* Got a matching entry */

		(void) snprintf(key, sizeof (key),
		    "ndr_ii.set%d.state", setnumber);
		if ((cfg_put_cstring(cfg, key, UPDATE, strlen(UPDATE)) < 0) ||
		    (cfg_commit(cfg) < 0)) {
			spcs_log("sndr", NULL,
			    gettext("%s: unable to update \"%s\" "
			    "in configuration storage: %s"),
			    program, buf, cfg_error(&sev));
			rdc_warn(NULL,
			    gettext("unable to update \"%s\" "
			    "in configuration storage: %s"),
			    buf, cfg_error(&sev));
		}
	}


done:
	if (cfg) {
		cfg_close(cfg);
		UNLOCKCFG();
	}
	spcs_s_ufree(&ustatus);
	if (volumes) {
		for (i = 0; i < replicating; i++)
			free(volumes[i]);
		free(volumes);
	}
}


/*
 * Sync started to a member of a group.
 * If all members of the group are in ndr_ii state "update" then take an PIT
 * snapshot on all of them. This will provide a consistent point-in-time
 * copy until whatever syncs take place are all completed.
 */
void
group_start(char *group)
{
	char **masters = NULL;
	char **shadows = NULL;
	char **bitmaps = NULL;
	char cmd[256];
	char buf[CFG_MAX_BUF];
	char key[CFG_MAX_KEY];
	CFGFILE *cfg = NULL;
	int i;
	int j;
	int setnumber;
	int found;
	int sndr_sets = 0;
	int update_needed = 0;
	int sev;
	char *ctag = NULL;
	int commit = 0;
	int size;

	size = sizeof (char *) * rdc_maxsets;
	masters = malloc(size);
	if (masters == NULL) {
		spcs_log("sndr", NULL,
		    gettext("%s: unable to allocate %ld bytes"),
		    program, size);
		rdc_warn(NULL,
			gettext("unable to allocate %ld bytes"), size);
		goto done;
	}
	bzero(masters, size);
	shadows = malloc(size);
	if (shadows == NULL) {
		spcs_log("sndr", NULL,
		    gettext("%s: unable to allocate %ld bytes"),
		    program, size);
		rdc_warn(NULL,
			gettext("unable to allocate %ld bytes"), size);
		goto done;
	}
	bzero(shadows, size);
	bitmaps = malloc(size);
	if (bitmaps == NULL) {
		spcs_log("sndr", NULL,
		    gettext("%s: unable to allocate %ld bytes"),
		    program, size);
		rdc_warn(NULL,
			gettext("unable to allocate %ld bytes"), size);
		goto done;
	}
	bzero(bitmaps, size);

	LOCKCFG();
	if ((cfg = cfg_open(NULL)) == NULL) {
		spcs_log("sndr", NULL,
		    gettext("%s: error opening config"),
		    program);
		rdc_warn(NULL,
		    gettext("error opening config"));
		UNLOCKCFG();
		goto done;
	}

	if (!cfg_lock(cfg, CFG_WRLOCK)) {
		spcs_log("sndr", NULL,
		    gettext("%s: error locking config"),
		    program);
		rdc_warn(NULL, gettext("error locking config"));
		goto done;
	}

	/* Now get all Remote Mirror entries with a matching group */
	for (i = 0; i < rdc_maxsets; i++) {
		setnumber = i + 1;

		(void) snprintf(key, sizeof (key),
		    "sndr.set%d.group", setnumber);
		if (cfg_get_cstring(cfg, key, buf, CFG_MAX_BUF) < 0)
			break;

		if (strcmp(buf, group) != 0)
			continue;

		/* Found a matching entry */

		(void) snprintf(key, sizeof (key),
		    "sndr.set%d.phost", setnumber);
		if (cfg_get_cstring(cfg, key, buf, sizeof (buf)) < 0)
			break;

		if (self_check(buf)) {
			(void) snprintf(key, sizeof (key), "sndr.set%d.primary",
			    setnumber);
		} else {
			(void) snprintf(key, sizeof (key),
			    "sndr.set%d.secondary", setnumber);
		}
		if (cfg_get_cstring(cfg, key, buf, sizeof (buf)) < 0)
			break;

		masters[sndr_sets] = strdup(buf);
		if (masters[sndr_sets] == NULL) {
			size = strlen(buf);
			spcs_log("sndr", NULL,
			    gettext("%s: unable to allocate %ld bytes"),
			    program, size);
			rdc_warn(NULL,
				gettext("unable to allocate %ld bytes"), size);
			goto done;
		}
		sndr_sets++;

		if (ctag == NULL && clustered) {
			/* Get cluster tag of matching entry */

			(void) snprintf(key, sizeof (key), "sndr.set%d.cnode",
			    setnumber);
			if (cfg_get_cstring(cfg, key, buf, CFG_MAX_BUF) >= 0)
				ctag = strdup(buf);
		}
	}

	/*
	 * Search through the ndr_ii entries for entries
	 * that match the saved local volume names and are in "update" state.
	 */

	update_needed = 0;

	for (i = 0; ; i++) {
		setnumber = i + 1;

		(void) snprintf(key, sizeof (key), "ndr_ii.set%d.secondary",
		    setnumber);
		if (cfg_get_cstring(cfg, key, buf, CFG_MAX_BUF) < 0)
			break;

		if (!volume_match(buf, masters, sndr_sets))
			continue;

		/* Got a matching entry */

		(void) snprintf(key, sizeof (key), "ndr_ii.set%d.shadow",
		    setnumber);
		if (cfg_get_cstring(cfg, key, buf, CFG_MAX_BUF) < 0)
			break;
		shadows[update_needed] = strdup(buf);
		if (shadows[update_needed] == NULL) {
			size = strlen(buf);
			spcs_log("sndr", NULL,
			    gettext("%s: unable to allocate %ld bytes"),
			    program, size);
			rdc_warn(NULL,
				gettext("unable to allocate %ld bytes"), size);
			goto done;
		}

		(void) snprintf(key, sizeof (key), "ndr_ii.set%d.bitmap",
		    setnumber);
		if (cfg_get_cstring(cfg, key, buf, CFG_MAX_BUF) < 0) {
			break;
		}
		bitmaps[update_needed] = strdup(buf);
		if (bitmaps[update_needed] == NULL) {
			size = strlen(buf);
			spcs_log("sndr", NULL,
			    gettext("%s: unable to allocate %ld bytes"),
			    program, size);
			rdc_warn(NULL,
				gettext("unable to allocate %ld bytes"), size);
			goto done;
		}

		(void) snprintf(key, sizeof (key), "ndr_ii.set%d.state",
		    setnumber);
		if (cfg_get_cstring(cfg, key, buf, CFG_MAX_BUF) < 0) {
			break;
		}
		if (strcmp(buf, UPDATE) != 0) {
			break;
		}

		update_needed++;
	}

	if (update_needed != sndr_sets) {
#ifdef DEBUG
		spcs_log("sndr", NULL,
		    gettext("%s: group sync: no Point-in-Time Copy snapshot "
			    "for %s"), program, group);
#endif
		goto done;
	}

	/* All RM sets in the group have an ndr_ii entry in "update" state */

	/* Issue PIT Copy snapshot commands for all sets in the group */
	for (j = 0; j < sndr_sets; j++) {
		found = 0;

		/* get ii entries until a match is found */
		for (i = 0; ; i++) {
			setnumber = i + 1;

			(void) snprintf(key, sizeof (key), "ii.set%d.shadow",
			    setnumber);
			if (cfg_get_cstring(cfg, key, buf, CFG_MAX_BUF) < 0)
				break;
			if (strcmp(buf, shadows[j]) != 0)
				continue;

			/* Matching shadow found, so ii already enabled */
			found = 1;
			break;
		}

		if (commit)
			if (cfg_commit(cfg) < 0)
				rdc_warn(NULL, gettext("commit config error"));
		cfg_close(cfg);

		if (found) {
			(void) sprintf(cmd, "%s -u s %s", IIADM, shadows[j]);
		} else {
			if (ctag) {
				(void) sprintf(cmd, "%s -C %s -e dep %s %s %s",
				    IIADM, ctag, masters[j], shadows[j],
				    bitmaps[j]);
				free(ctag);
				ctag = NULL;
			} else
				(void) sprintf(cmd, "%s -e dep %s %s %s", IIADM,
				    masters[j], shadows[j], bitmaps[j]);
		}

		if (system(cmd) != 0) {
			spcs_log("sndr", NULL,
			    gettext("%s: group sync: Point-in-Time Copy"
			    " snapshot failed for %s"),
			    program, masters[j]);

			goto done;
		}

		if ((cfg = cfg_open(NULL)) == NULL) {
			spcs_log("sndr", NULL,
			    gettext("%s: error opening config"),
			    program);
			rdc_warn(NULL,
			    gettext("error opening config"));
			goto done;
		}
		if (!cfg_lock(cfg, CFG_WRLOCK)) {
			spcs_log("sndr", NULL,
			    gettext("%s: error locking config"),
			    program);
			rdc_warn(NULL, gettext("error locking config"));
			goto done;
		}
		commit = 0;

		/* PIT enable or update was fine, so update the ndr_ii entry */

		/* get ndr_ii entries until a match is found */
		for (i = 0; ; i++) {
			setnumber = i + 1;

			(void) snprintf(key, sizeof (key),
			    "ndr_ii.set%d.shadow", setnumber);
			if (cfg_get_cstring(cfg, key, buf, CFG_MAX_BUF) < 0)
				break;
			if (strcmp(buf, shadows[j]) != 0)
				continue;

			/* Found the matching entry */

			(void) snprintf(key, sizeof (key), "ndr_ii.set%d.state",
			    setnumber);
			if (cfg_put_cstring(cfg, key, NOUPDATE,
			    strlen(NOUPDATE)) < 0) {
				spcs_log("sndr", NULL,
				    gettext("%s: unable to update \"%s\" "
				    "in configuration storage: %s"),
				    program, buf, cfg_error(&sev));
				rdc_warn(NULL,
				    gettext("unable to update \"%s\" "
				    "in configuration storage: %s"),
				    buf, cfg_error(&sev));
			} else
				commit = 1;
			break;
		}
	}

	if (commit)
		if (cfg_commit(cfg) < 0)
			rdc_warn(NULL, gettext("commit config error"));

	spcs_log("sndr", NULL,
	    gettext("%s: group sync: Point-in-Time Copy snapshots completed "
		    "for %s"), program, group);

done:
	if (ctag)
		free(ctag);

	if (cfg) {
		cfg_close(cfg);
		UNLOCKCFG();
	}

	if (masters) {
		for (i = 0; i < sndr_sets; i++) {
			if (masters[i])
				free(masters[i]);
		}
		free(masters);
	}

	if (shadows) {
		for (i = 0; i < update_needed; i++) {
			if (shadows[i])
				free(shadows[i]);
		}
		free(shadows);
	}

	if (bitmaps) {
		for (i = 0; i < update_needed; i++) {
			if (bitmaps[i])
				free(bitmaps[i]);
		}
		free(bitmaps);
	}
}
