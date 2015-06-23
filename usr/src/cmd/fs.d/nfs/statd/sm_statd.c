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
 * Copyright 2015 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
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

/*
 * Copyright (c) 2012 by Delphix. All rights reserved.
 */

/*
 * sm_statd.c consists of routines used for the intermediate
 * statd implementation(3.2 rpc.statd);
 * it creates an entry in "current" directory for each site that it monitors;
 * after crash and recovery, it moves all entries in "current"
 * to "backup" directory, and notifies the corresponding statd of its recovery.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <syslog.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/param.h>
#include <arpa/inet.h>
#include <dirent.h>
#include <rpc/rpc.h>
#include <rpcsvc/sm_inter.h>
#include <rpcsvc/nsm_addr.h>
#include <errno.h>
#include <memory.h>
#include <signal.h>
#include <synch.h>
#include <thread.h>
#include <limits.h>
#include <strings.h>
#include "sm_statd.h"


int LOCAL_STATE;

sm_hash_t	mon_table[MAX_HASHSIZE];
static sm_hash_t	record_table[MAX_HASHSIZE];
static sm_hash_t	recov_q;

static name_entry *find_name(name_entry **namepp, char *name);
static name_entry *insert_name(name_entry **namepp, char *name,
				int need_alloc);
static void delete_name(name_entry **namepp, char *name);
static void remove_name(char *name, int op, int startup);
static int statd_call_statd(char *name);
static void pr_name(char *name, int flag);
static void *thr_statd_init(void);
static void *sm_try(void);
static void *thr_call_statd(void *);
static void remove_single_name(char *name, char *dir1, char *dir2);
static int move_file(char *fromdir, char *file, char *todir);
static int count_symlinks(char *dir, char *name, int *count);
static char *family2string(sa_family_t family);

/*
 * called when statd first comes up; it searches /etc/sm to gather
 * all entries to notify its own failure
 */
void
statd_init(void)
{
	struct dirent *dirp;
	DIR *dp;
	FILE *fp, *fp_tmp;
	int i, tmp_state;
	char state_file[MAXPATHLEN+SM_MAXPATHLEN];

	if (debug)
		(void) printf("enter statd_init\n");

	/*
	 * First try to open the file.  If that fails, try to create it.
	 * If that fails, give up.
	 */
	if ((fp = fopen(STATE, "r+")) == NULL) {
		if ((fp = fopen(STATE, "w+")) == NULL) {
			syslog(LOG_ERR, "can't open %s: %m", STATE);
			exit(1);
		} else
			(void) chmod(STATE, 0644);
	}
	if ((fscanf(fp, "%d", &LOCAL_STATE)) == EOF) {
		if (debug >= 2)
			(void) printf("empty file\n");
		LOCAL_STATE = 0;
	}

	/*
	 * Scan alternate paths for largest "state" number
	 */
	for (i = 0; i < pathix; i++) {
		(void) sprintf(state_file, "%s/statmon/state", path_name[i]);
		if ((fp_tmp = fopen(state_file, "r+")) == NULL) {
			if ((fp_tmp = fopen(state_file, "w+")) == NULL) {
				if (debug)
					syslog(LOG_ERR,
					    "can't open %s: %m",
					    state_file);
				continue;
			} else
				(void) chmod(state_file, 0644);
		}
		if ((fscanf(fp_tmp, "%d", &tmp_state)) == EOF) {
			if (debug)
				syslog(LOG_ERR,
				    "statd: %s: file empty\n", state_file);
			(void) fclose(fp_tmp);
			continue;
		}
		if (tmp_state > LOCAL_STATE) {
			LOCAL_STATE = tmp_state;
			if (debug)
				(void) printf("Update LOCAL STATE: %d\n",
				    tmp_state);
		}
		(void) fclose(fp_tmp);
	}

	LOCAL_STATE = ((LOCAL_STATE%2) == 0) ? LOCAL_STATE+1 : LOCAL_STATE+2;

	/* IF local state overflows, reset to value 1 */
	if (LOCAL_STATE < 0) {
		LOCAL_STATE = 1;
	}

	/* Copy the LOCAL_STATE value back to all stat files */
	if (fseek(fp, 0, 0) == -1) {
		syslog(LOG_ERR, "statd: fseek failed\n");
		exit(1);
	}

	(void) fprintf(fp, "%-10d", LOCAL_STATE);
	(void) fflush(fp);
	if (fsync(fileno(fp)) == -1) {
		syslog(LOG_ERR, "statd: fsync failed\n");
		exit(1);
	}
	(void) fclose(fp);

	for (i = 0; i < pathix; i++) {
		(void) sprintf(state_file, "%s/statmon/state", path_name[i]);
		if ((fp_tmp = fopen(state_file, "r+")) == NULL) {
			if ((fp_tmp = fopen(state_file, "w+")) == NULL) {
				syslog(LOG_ERR,
				    "can't open %s: %m", state_file);
				continue;
			} else
				(void) chmod(state_file, 0644);
		}
		(void) fprintf(fp_tmp, "%-10d", LOCAL_STATE);
		(void) fflush(fp_tmp);
		if (fsync(fileno(fp_tmp)) == -1) {
			syslog(LOG_ERR,
			    "statd: %s: fsync failed\n", state_file);
			(void) fclose(fp_tmp);
			exit(1);
		}
		(void) fclose(fp_tmp);
	}

	if (debug)
		(void) printf("local state = %d\n", LOCAL_STATE);

	if ((mkdir(CURRENT, SM_DIRECTORY_MODE)) == -1) {
		if (errno != EEXIST) {
			syslog(LOG_ERR, "statd: mkdir current, error %m\n");
			exit(1);
		}
	}
	if ((mkdir(BACKUP, SM_DIRECTORY_MODE)) == -1) {
		if (errno != EEXIST) {
			syslog(LOG_ERR, "statd: mkdir backup, error %m\n");
			exit(1);
		}
	}

	/* get all entries in CURRENT into BACKUP */
	if ((dp = opendir(CURRENT)) == NULL) {
		syslog(LOG_ERR, "statd: open current directory, error %m\n");
		exit(1);
	}

	while ((dirp = readdir(dp)) != NULL) {
		if (strcmp(dirp->d_name, ".") != 0 &&
		    strcmp(dirp->d_name, "..") != 0) {
			/* rename all entries from CURRENT to BACKUP */
			(void) move_file(CURRENT, dirp->d_name, BACKUP);
		}
	}

	(void) closedir(dp);

	/* Contact hosts' statd */
	if (thr_create(NULL, 0, (void *(*)(void *))thr_statd_init, NULL,
	    THR_DETACHED, NULL)) {
		syslog(LOG_ERR,
		    "statd: unable to create thread for thr_statd_init\n");
		exit(1);
	}
}

/*
 * Work thread which contacts hosts' statd.
 */
static void *
thr_statd_init(void)
{
	struct dirent *dirp;
	DIR 	*dp;
	int num_threads;
	int num_join;
	int i;
	char *name;
	char buf[MAXPATHLEN+SM_MAXPATHLEN];

	/* Go thru backup directory and contact hosts */
	if ((dp = opendir(BACKUP)) == NULL) {
		syslog(LOG_ERR, "statd: open backup directory, error %m\n");
		exit(1);
	}

	/*
	 * Create "UNDETACHED" threads for each symlink and (unlinked)
	 * regular file in backup directory to initiate statd_call_statd.
	 * NOTE: These threads are the only undetached threads in this
	 * program and thus, the thread id is not needed to join the threads.
	 */
	num_threads = 0;
	while ((dirp = readdir(dp)) != NULL) {
		/*
		 * If host file is not a symlink, don't bother to
		 * spawn a thread for it.  If any link(s) refer to
		 * it, the host will be contacted using the link(s).
		 * If not, we'll deal with it during the legacy pass.
		 */
		(void) sprintf(buf, "%s/%s", BACKUP, dirp->d_name);
		if (is_symlink(buf) == 0) {
			continue;
		}

		/*
		 * If the num_threads has exceeded, wait until
		 * a certain amount of threads have finished.
		 * Currently, 10% of threads created should be joined.
		 */
		if (num_threads > MAX_THR) {
			num_join = num_threads/PERCENT_MINJOIN;
			for (i = 0; i < num_join; i++)
				thr_join(0, 0, 0);
			num_threads -= num_join;
		}

		/*
		 * If can't alloc name then print error msg and
		 * continue to next item on list.
		 */
		name = strdup(dirp->d_name);
		if (name == NULL) {
			syslog(LOG_ERR,
			    "statd: unable to allocate space for name %s\n",
			    dirp->d_name);
			continue;
		}

		/* Create a thread to do a statd_call_statd for name */
		if (thr_create(NULL, 0, thr_call_statd, name, 0, NULL)) {
			syslog(LOG_ERR,
			    "statd: unable to create thr_call_statd() "
			    "for name %s.\n", dirp->d_name);
			free(name);
			continue;
		}
		num_threads++;
	}

	/*
	 * Join the other threads created above before processing the
	 * legacies.  This allows all symlinks and the regular files
	 * to which they correspond to be processed and deleted.
	 */
	for (i = 0; i < num_threads; i++) {
		thr_join(0, 0, 0);
	}

	/*
	 * The second pass checks for `legacies':  regular files which
	 * never had symlinks pointing to them at all, just like in the
	 * good old (pre-1184192 fix) days.  Once a machine has cleaned
	 * up its legacies they should only reoccur due to catastrophes
	 * (e.g., severed symlinks).
	 */
	rewinddir(dp);
	num_threads = 0;
	while ((dirp = readdir(dp)) != NULL) {
		if (strcmp(dirp->d_name, ".") == 0 ||
		    strcmp(dirp->d_name, "..") == 0) {
			continue;
		}

		(void) sprintf(buf, "%s/%s", BACKUP, dirp->d_name);
		if (is_symlink(buf)) {
			/*
			 * We probably couldn't reach this host and it's
			 * been put on the recovery queue for retry.
			 * Skip it and keep looking for regular files.
			 */
			continue;
		}

		if (debug) {
			(void) printf("thr_statd_init: legacy %s\n",
			    dirp->d_name);
		}

		/*
		 * If the number of threads exceeds the maximum, wait
		 * for some fraction of them to finish before
		 * continuing.
		 */
		if (num_threads > MAX_THR) {
			num_join = num_threads/PERCENT_MINJOIN;
			for (i = 0; i < num_join; i++)
				thr_join(0, 0, 0);
			num_threads -= num_join;
		}

		/*
		 * If can't alloc name then print error msg and
		 * continue to next item on list.
		 */
		name = strdup(dirp->d_name);
		if (name == NULL) {
			syslog(LOG_ERR,
			    "statd: unable to allocate space for name %s\n",
			    dirp->d_name);
			continue;
		}

		/* Create a thread to do a statd_call_statd for name */
		if (thr_create(NULL, 0, thr_call_statd, name, 0, NULL)) {
			syslog(LOG_ERR,
			    "statd: unable to create thr_call_statd() "
			    "for name %s.\n", dirp->d_name);
			free(name);
			continue;
		}
		num_threads++;
	}

	(void) closedir(dp);

	/*
	 * Join the other threads created above before creating thread
	 * to process items in recovery table.
	 */
	for (i = 0; i < num_threads; i++) {
		thr_join(0, 0, 0);
	}

	/*
	 * Need to only copy /var/statmon/sm.bak to alternate paths, since
	 * the only hosts in /var/statmon/sm should be the ones currently
	 * being monitored and already should be in alternate paths as part
	 * of insert_mon().
	 */
	for (i = 0; i < pathix; i++) {
		(void) sprintf(buf, "%s/statmon/sm.bak", path_name[i]);
		if ((mkdir(buf, SM_DIRECTORY_MODE)) == -1) {
			if (errno != EEXIST)
				syslog(LOG_ERR, "statd: mkdir %s error %m\n",
				    buf);
			else
				copydir_from_to(BACKUP, buf);
		} else
			copydir_from_to(BACKUP, buf);
	}


	/*
	 * Reset the die and in_crash variables.
	 */
	mutex_lock(&crash_lock);
	die = 0;
	in_crash = 0;
	mutex_unlock(&crash_lock);

	if (debug)
		(void) printf("Creating thread for sm_try\n");

	/* Continue to notify statd on hosts that were unreachable. */
	if (thr_create(NULL, 0, (void *(*)(void *))sm_try, NULL, THR_DETACHED,
	    NULL))
		syslog(LOG_ERR,
		    "statd: unable to create thread for sm_try().\n");
	thr_exit((void *) 0);
#ifdef lint
	return (0);
#endif
}

/*
 * Work thread to make call to statd_call_statd.
 */
void *
thr_call_statd(void *namep)
{
	char *name = (char *)namep;

	/*
	 * If statd of name is unreachable, add name to recovery table
	 * otherwise if statd_call_statd was successful, remove from backup.
	 */
	if (statd_call_statd(name) != 0) {
		int n;
		char *tail;
		char path[MAXPATHLEN];
		/*
		 * since we are constructing this pathname below we add
		 *  another space for the terminating NULL so we don't
		 *  overflow our buffer when we do the readlink
		 */
		char rname[MAXNAMELEN + 1];

		if (debug) {
			(void) printf(
			"statd call failed, inserting %s in recov_q\n", name);
		}
		mutex_lock(&recov_q.lock);
		(void) insert_name(&recov_q.sm_recovhdp, name, 0);
		mutex_unlock(&recov_q.lock);

		/*
		 * If we queued a symlink name in the recovery queue,
		 * we now clean up the regular file to which it referred.
		 * This may leave a severed symlink if multiple links
		 * referred to one regular file; this is unaesthetic but
		 * it works.  The big benefit is that it prevents us
		 * from recovering the same host twice (as symlink and
		 * as regular file) needlessly, usually on separate reboots.
		 */
		(void) strcpy(path, BACKUP);
		(void) strcat(path, "/");
		(void) strcat(path, name);
		if (is_symlink(path)) {
			n = readlink(path, rname, MAXNAMELEN);
			if (n <= 0) {
				if (debug >= 2) {
					(void) printf(
					    "thr_call_statd: can't read "
					    "link %s\n", path);
				}
			} else {
				rname[n] = '\0';

				tail = strrchr(path, '/') + 1;

				if ((strlen(BACKUP) + strlen(rname) + 2) <=
				    MAXPATHLEN) {
					(void) strcpy(tail, rname);
					delete_file(path);
				} else if (debug) {
					printf("thr_call_statd: path over"
					    "maxpathlen!\n");
				}
			}

		}

		if (debug)
			pr_name(name, 0);

	} else {
		/*
		 * If `name' is an IP address symlink to a name file,
		 * remove it now.  If it is the last such symlink,
		 * remove the name file as well.  Regular files with
		 * no symlinks to them are assumed to be legacies and
		 * are removed as well.
		 */
		remove_name(name, 1, 1);
		free(name);
	}
	thr_exit((void *) 0);
#ifdef lint
	return (0);
#endif
}

/*
 * Notifies the statd of host specified by name to indicate that
 * state has changed for this server.
 */
static int
statd_call_statd(char *name)
{
	enum clnt_stat clnt_stat;
	struct timeval tottimeout;
	CLIENT *clnt;
	char *name_or_addr;
	stat_chge ntf;
	int i;
	int rc;
	int dummy1, dummy2, dummy3, dummy4;
	char ascii_addr[MAXNAMELEN];
	size_t unq_len;

	ntf.mon_name = hostname;
	ntf.state = LOCAL_STATE;
	if (debug)
		(void) printf("statd_call_statd at %s\n", name);

	/*
	 * If it looks like an ASCII <address family>.<address> specifier,
	 * strip off the family - we just want the address when obtaining
	 * a client handle.
	 * If it's anything else, just pass it on to create_client().
	 */
	unq_len = strcspn(name, ".");

	if ((strncmp(name, SM_ADDR_IPV4, unq_len) == 0) ||
	    (strncmp(name, SM_ADDR_IPV6, unq_len) == 0)) {
		name_or_addr = strchr(name, '.') + 1;
	} else {
		name_or_addr = name;
	}

	/*
	 * NOTE: We depend here upon the fact that the RPC client code
	 * allows us to use ASCII dotted quad `names', i.e. "192.9.200.1".
	 * This may change in a future release.
	 */
	if (debug) {
		(void) printf("statd_call_statd: calling create_client(%s)\n",
		    name_or_addr);
	}

	tottimeout.tv_sec = SM_RPC_TIMEOUT;
	tottimeout.tv_usec = 0;

	if ((clnt = create_client(name_or_addr, SM_PROG, SM_VERS, NULL,
	    &tottimeout)) == NULL) {
		return (-1);
	}

	/* Perform notification to client */
	rc = 0;
	clnt_stat = clnt_call(clnt, SM_NOTIFY, xdr_stat_chge, (char *)&ntf,
	    xdr_void, NULL, tottimeout);
	if (debug) {
		(void) printf("clnt_stat=%s(%d)\n",
		    clnt_sperrno(clnt_stat), clnt_stat);
	}
	if (clnt_stat != (int)RPC_SUCCESS) {
		syslog(LOG_WARNING,
		    "statd: cannot talk to statd at %s, %s(%d)\n",
		    name_or_addr, clnt_sperrno(clnt_stat), clnt_stat);
		rc = -1;
	}

	/*
	 * Wait until the host_name is populated.
	 */
	(void) mutex_lock(&merges_lock);
	while (in_merges)
		(void) cond_wait(&merges_cond, &merges_lock);
	(void) mutex_unlock(&merges_lock);

	/* For HA systems and multi-homed hosts */
	ntf.state = LOCAL_STATE;
	for (i = 0; i < addrix; i++) {
		ntf.mon_name = host_name[i];
		if (debug)
			(void) printf("statd_call_statd at %s\n", name_or_addr);
		clnt_stat = clnt_call(clnt, SM_NOTIFY, xdr_stat_chge,
		    (char *)&ntf, xdr_void, NULL, tottimeout);
		if (clnt_stat != (int)RPC_SUCCESS) {
			syslog(LOG_WARNING,
			    "statd: cannot talk to statd at %s, %s(%d)\n",
			    name_or_addr, clnt_sperrno(clnt_stat), clnt_stat);
			rc = -1;
		}
	}
	clnt_destroy(clnt);
	return (rc);
}

/*
 * Continues to contact hosts in recovery table that were unreachable.
 * NOTE:  There should only be one sm_try thread executing and
 * thus locks are not needed for recovery table. Die is only cleared
 * after all the hosts has at least been contacted once.  The reader/writer
 * lock ensures to finish this code before an sm_crash is started.  Die
 * variable will signal it.
 */
void *
sm_try(void)
{
	name_entry *nl, *next;
	timestruc_t	wtime;
	int delay = 0;

	rw_rdlock(&thr_rwlock);
	if (mutex_trylock(&sm_trylock))
		goto out;
	mutex_lock(&crash_lock);

	while (!die) {
		wtime.tv_sec = delay;
		wtime.tv_nsec = 0;
		/*
		 * Wait until signalled to wakeup or time expired.
		 * If signalled to be awoken, then a crash has occurred
		 * or otherwise time expired.
		 */
		if (cond_reltimedwait(&retrywait, &crash_lock, &wtime) == 0) {
			break;
		}

		/* Exit loop if queue is empty */
		if ((next = recov_q.sm_recovhdp) == NULL)
			break;

		mutex_unlock(&crash_lock);

		while (((nl = next) != NULL) && (!die)) {
			next = next->nxt;
			if (statd_call_statd(nl->name) == 0) {
				/* remove name from BACKUP */
				remove_name(nl->name, 1, 0);
				mutex_lock(&recov_q.lock);
				/* remove entry from recovery_q */
				delete_name(&recov_q.sm_recovhdp, nl->name);
				mutex_unlock(&recov_q.lock);
			} else {
				/*
				 * Print message only once since unreachable
				 * host can be contacted forever.
				 */
				if (delay == 0)
					syslog(LOG_WARNING,
					    "statd: host %s is not "
					    "responding\n", nl->name);
			}
		}
		/*
		 * Increment the amount of delay before restarting again.
		 * The amount of delay should not exceed the MAX_DELAYTIME.
		 */
		if (delay <= MAX_DELAYTIME)
			delay += INC_DELAYTIME;
		mutex_lock(&crash_lock);
	}

	mutex_unlock(&crash_lock);
	mutex_unlock(&sm_trylock);
out:
	rw_unlock(&thr_rwlock);
	if (debug)
		(void) printf("EXITING sm_try\n");
	thr_exit((void *) 0);
#ifdef lint
	return (0);
#endif
}

/*
 * Malloc's space and returns the ptr to malloc'ed space. NULL if unsuccessful.
 */
char *
xmalloc(unsigned len)
{
	char *new;

	if ((new = malloc(len)) == 0) {
		syslog(LOG_ERR, "statd: malloc, error %m\n");
		return (NULL);
	} else {
		(void) memset(new, 0, len);
		return (new);
	}
}

/*
 * the following two routines are very similar to
 * insert_mon and delete_mon in sm_proc.c, except the structture
 * is different
 */
static name_entry *
insert_name(name_entry **namepp, char *name, int need_alloc)
{
	name_entry *new;

	new = (name_entry *)xmalloc(sizeof (name_entry));
	if (new == (name_entry *) NULL)
		return (NULL);

	/* Allocate name when needed which is only when adding to record_t */
	if (need_alloc) {
		if ((new->name = strdup(name)) == NULL) {
			syslog(LOG_ERR, "statd: strdup, error %m\n");
			free(new);
			return (NULL);
		}
	} else
		new->name = name;

	new->nxt = *namepp;
	if (new->nxt != NULL)
		new->nxt->prev = new;

	new->prev = (name_entry *) NULL;

	*namepp = new;
	if (debug) {
		(void) printf("insert_name: inserted %s at %p\n",
		    name, (void *)namepp);
	}

	return (new);
}

/*
 * Deletes name from specified list (namepp).
 */
static void
delete_name(name_entry **namepp, char *name)
{
	name_entry *nl;

	nl = *namepp;
	while (nl != NULL) {
		if (str_cmp_address_specifier(nl->name, name) == 0 ||
		    str_cmp_unqual_hostname(nl->name, name) == 0) {
			if (nl->prev != NULL)
				nl->prev->nxt = nl->nxt;
			else
				*namepp = nl->nxt;
			if (nl->nxt != NULL)
				nl->nxt->prev = nl->prev;
			free(nl->name);
			free(nl);
			return;
		}
		nl = nl->nxt;
	}
}

/*
 * Finds name from specified list (namep).
 */
static name_entry *
find_name(name_entry **namep, char *name)
{
	name_entry *nl;

	nl = *namep;

	while (nl != NULL) {
		if (str_cmp_unqual_hostname(nl->name, name) == 0) {
			return (nl);
		}
		nl = nl->nxt;
	}
	return (NULL);
}

/*
 * Creates a file.
 */

int
create_file(char *name)
{
	int fd;

	/*
	 * The file might already exist.  If it does, we ask for only write
	 * permission, since that's all the file was created with.
	 */
	if ((fd = open(name, O_CREAT | O_WRONLY, S_IWUSR)) == -1) {
		if (errno != EEXIST) {
			syslog(LOG_ERR, "can't open %s: %m", name);
			return (1);
		}
	}

	if (debug >= 2)
		(void) printf("%s is created\n", name);
	if (close(fd)) {
		syslog(LOG_ERR, "statd: close, error %m\n");
		return (1);
	}

	return (0);
}

/*
 * Deletes the file specified by name.
 */
void
delete_file(char *name)
{
	if (debug >= 2)
		(void) printf("Remove monitor entry %s\n", name);
	if (unlink(name) == -1) {
		if (errno != ENOENT)
			syslog(LOG_ERR, "statd: unlink of %s, error %m", name);
	}
}

/*
 * Return 1 if file is a symlink, else 0.
 */
int
is_symlink(char *file)
{
	int error;
	struct stat lbuf;

	do {
		bzero((caddr_t)&lbuf, sizeof (lbuf));
		error = lstat(file, &lbuf);
	} while (error == EINTR);

	if (error == 0) {
		return ((lbuf.st_mode & S_IFMT) == S_IFLNK);
	}

	return (0);
}

/*
 * Moves the file specified by `from' to `to' only if the
 * new file is guaranteed to be created (which is presumably
 * why we don't just do a rename(2)).  If `from' is a
 * symlink, the destination file will be a similar symlink
 * in the directory of `to'.
 *
 * Returns 0 for success, 1 for failure.
 */
static int
move_file(char *fromdir, char *file, char *todir)
{
	int n;
	char rname[MAXNAMELEN + 1]; /* +1 for the terminating NULL */
	char from[MAXPATHLEN];
	char to[MAXPATHLEN];

	(void) strcpy(from, fromdir);
	(void) strcat(from, "/");
	(void) strcat(from, file);
	if (is_symlink(from)) {
		/*
		 * Dig out the name of the regular file the link points to.
		 */
		n = readlink(from, rname, MAXNAMELEN);
		if (n <= 0) {
			if (debug >= 2) {
				(void) printf("move_file: can't read link %s\n",
				    from);
			}
			return (1);
		}
		rname[n] = '\0';

		/*
		 * Create the link.
		 */
		if (create_symlink(todir, rname, file) != 0) {
			return (1);
		}
	} else {
		/*
		 * Do what we've always done to move regular files.
		 */
		(void) strcpy(to, todir);
		(void) strcat(to, "/");
		(void) strcat(to, file);
		if (create_file(to) != 0) {
			return (1);
		}
	}

	/*
	 * Remove the old file if we've created the new one.
	 */
	if (unlink(from) < 0) {
		syslog(LOG_ERR, "move_file: unlink of %s, error %m", from);
		return (1);
	}

	return (0);
}

/*
 * Create a symbolic link named `lname' to regular file `rname'.
 * Both files should be in directory `todir'.
 */
int
create_symlink(char *todir, char *rname, char *lname)
{
	int error;
	char lpath[MAXPATHLEN];

	/*
	 * Form the full pathname of the link.
	 */
	(void) strcpy(lpath, todir);
	(void) strcat(lpath, "/");
	(void) strcat(lpath, lname);

	/*
	 * Now make the new symlink ...
	 */
	if (symlink(rname, lpath) < 0) {
		error = errno;
		if (error != 0 && error != EEXIST) {
			if (debug >= 2) {
				(void) printf("create_symlink: can't link "
				    "%s/%s -> %s\n", todir, lname, rname);
			}
			return (1);
		}
	}

	if (debug) {
		if (error == EEXIST) {
			(void) printf("link %s/%s -> %s already exists\n",
			    todir, lname, rname);
		} else {
			(void) printf("created link %s/%s -> %s\n",
			    todir, lname, rname);
		}
	}

	return (0);
}

/*
 * remove the name from the specified directory
 * op = 0: CURRENT
 * op = 1: BACKUP
 */
static void
remove_name(char *name, int op, int startup)
{
	int i;
	char *alt_dir;
	char *queue;

	if (op == 0) {
		alt_dir = "statmon/sm";
		queue = CURRENT;
	} else {
		alt_dir = "statmon/sm.bak";
		queue = BACKUP;
	}

	remove_single_name(name, queue, NULL);
	/*
	 * At startup, entries have not yet been copied to alternate
	 * directories and thus do not need to be removed.
	 */
	if (startup == 0) {
		for (i = 0; i < pathix; i++) {
			remove_single_name(name, path_name[i], alt_dir);
		}
	}
}

/*
 * Remove the name from the specified directory, which is dir1/dir2 or
 * dir1, depending on whether dir2 is NULL.
 */
static void
remove_single_name(char *name, char *dir1, char *dir2)
{
	int n, error;
	char path[MAXPATHLEN+MAXNAMELEN+SM_MAXPATHLEN];	/* why > MAXPATHLEN? */
	char dirpath[MAXPATHLEN];
	char rname[MAXNAMELEN + 1]; /* +1 for NULL term */

	if (strlen(name) + strlen(dir1) + (dir2 != NULL ? strlen(dir2) : 0) +
	    3 > MAXPATHLEN) {
		if (dir2 != NULL)
			syslog(LOG_ERR,
			    "statd: pathname too long: %s/%s/%s\n",
			    dir1, dir2, name);
		else
			syslog(LOG_ERR,
			    "statd: pathname too long: %s/%s\n",
			    dir1, name);

		return;
	}

	(void) strcpy(path, dir1);
	(void) strcat(path, "/");
	if (dir2 != NULL) {
		(void) strcat(path, dir2);
		(void) strcat(path, "/");
	}
	(void) strcpy(dirpath, path);	/* save here - we may need it shortly */
	(void) strcat(path, name);

	/*
	 * Despite the name of this routine :-@), `path' may be a symlink
	 * to a regular file.  If it is, and if that file has no other
	 * links to it, we must remove it now as well.
	 */
	if (is_symlink(path)) {
		n = readlink(path, rname, MAXNAMELEN);
		if (n > 0) {
			rname[n] = '\0';

			if (count_symlinks(dirpath, rname, &n) < 0) {
				return;
			}

			if (n == 1) {
				(void) strcat(dirpath, rname);
				error = unlink(dirpath);
				if (debug >= 2) {
					if (error < 0) {
						(void) printf(
						    "remove_name: can't "
						    "unlink %s\n",
						    dirpath);
					} else {
						(void) printf(
						    "remove_name: unlinked ",
						    "%s\n", dirpath);
					}
				}
			}
		} else {
			/*
			 * Policy: if we can't read the symlink, leave it
			 * here for analysis by the system administrator.
			 */
			syslog(LOG_ERR,
			    "statd: can't read link %s: %m\n", path);
		}
	}

	/*
	 * If it's a regular file, we can assume all symlinks and the
	 * files to which they refer have been processed already - just
	 * fall through to here to remove it.
	 */
	delete_file(path);
}

/*
 * Count the number of symlinks in `dir' which point to `name' (also in dir).
 * Passes back symlink count in `count'.
 * Returns 0 for success, < 0 for failure.
 */
static int
count_symlinks(char *dir, char *name, int *count)
{
	int cnt = 0;
	int n;
	DIR *dp;
	struct dirent *dirp;
	char lpath[MAXPATHLEN];
	char rname[MAXNAMELEN + 1]; /* +1 for term NULL */

	if ((dp = opendir(dir)) == NULL) {
		syslog(LOG_ERR, "count_symlinks: open %s dir, error %m\n",
		    dir);
		return (-1);
	}

	while ((dirp = readdir(dp)) != NULL) {
		if (strcmp(dirp->d_name, ".") == 0 ||
		    strcmp(dirp->d_name, "..") == 0) {
			continue;
		}

		(void) sprintf(lpath, "%s%s", dir, dirp->d_name);
		if (is_symlink(lpath)) {
			/*
			 * Fetch the name of the file the symlink refers to.
			 */
			n = readlink(lpath, rname, MAXNAMELEN);
			if (n <= 0) {
				if (debug >= 2) {
					(void) printf(
					    "count_symlinks: can't read link "
					    "%s\n", lpath);
				}
				continue;
			}
			rname[n] = '\0';

			/*
			 * If `rname' matches `name', bump the count.  There
			 * may well be multiple symlinks to the same name, so
			 * we must continue to process the entire directory.
			 */
			if (strcmp(rname, name) == 0) {
				cnt++;
			}
		}
	}

	(void) closedir(dp);

	if (debug) {
		(void) printf("count_symlinks: found %d symlinks\n", cnt);
	}
	*count = cnt;
	return (0);
}

/*
 * Manage the cache of hostnames.  An entry for each host that has recently
 * locked a file is kept.  There is an in-ram table (record_table) and an empty
 * file in the file system name space (/var/statmon/sm/<name>).  This
 * routine adds (deletes) the name to (from) the in-ram table and the entry
 * to (from) the file system name space.
 *
 * If op == 1 then the name is added to the queue otherwise the name is
 * deleted.
 */
void
record_name(char *name, int op)
{
	name_entry *nl;
	int i;
	char path[MAXPATHLEN+MAXNAMELEN+SM_MAXPATHLEN];
	name_entry **record_q;
	unsigned int hash;

	/*
	 * These names are supposed to be just host names, not paths or
	 * other arbitrary files.
	 * manipulating the empty pathname unlinks CURRENT,
	 * manipulating files with '/' would allow you to create and unlink
	 * files all over the system; LOG_AUTH, it's a security thing.
	 * Don't remove the directories . and ..
	 */
	if (name == NULL)
		return;

	if (name[0] == '\0' || strchr(name, '/') != NULL ||
	    strcmp(name, ".") == 0 || strcmp(name, "..") == 0) {
		syslog(LOG_ERR|LOG_AUTH, "statd: attempt to %s \"%s/%s\"",
		    op == 1 ? "create" : "remove", CURRENT, name);
		return;
	}

	SMHASH(name, hash);
	if (debug) {
		if (op == 1)
			(void) printf("inserting %s at hash %d,\n",
			    name, hash);
		else
			(void) printf("deleting %s at hash %d\n", name, hash);
		pr_name(name, 1);
	}


	if (op == 1) { /* insert */
		mutex_lock(&record_table[hash].lock);
		record_q = &record_table[hash].sm_rechdp;
		if ((nl = find_name(record_q, name)) == NULL) {

			int	path_len;

			if ((nl = insert_name(record_q, name, 1)) !=
			    (name_entry *) NULL)
				nl->count++;
			mutex_unlock(&record_table[hash].lock);
			/* make an entry in current directory */

			path_len = strlen(CURRENT) + strlen(name) + 2;
			if (path_len > MAXPATHLEN) {
				syslog(LOG_ERR,
				    "statd: pathname too long: %s/%s\n",
				    CURRENT, name);
				return;
			}
			(void) strcpy(path, CURRENT);
			(void) strcat(path, "/");
			(void) strcat(path, name);
			(void) create_file(path);
			if (debug) {
				(void) printf("After insert_name\n");
				pr_name(name, 1);
			}
			/* make an entry in alternate paths */
			for (i = 0; i < pathix; i++) {
				path_len = strlen(path_name[i]) +
				    strlen("/statmon/sm/") + strlen(name) + 1;

				if (path_len > MAXPATHLEN) {
					syslog(LOG_ERR, "statd: pathname too "
					    "long: %s/statmon/sm/%s\n",
					    path_name[i], name);
					continue;
				}
				(void) strcpy(path, path_name[i]);
				(void) strcat(path, "/statmon/sm/");
				(void) strcat(path, name);
				(void) create_file(path);
			}
			return;
		}
		nl->count++;
		mutex_unlock(&record_table[hash].lock);

	} else { /* delete */
		mutex_lock(&record_table[hash].lock);
		record_q = &record_table[hash].sm_rechdp;
		if ((nl = find_name(record_q, name)) == NULL) {
			mutex_unlock(&record_table[hash].lock);
			return;
		}
		nl->count--;
		if (nl->count == 0) {
			delete_name(record_q, name);
			mutex_unlock(&record_table[hash].lock);
			/* remove this entry from current directory */
			remove_name(name, 0, 0);
		} else
			mutex_unlock(&record_table[hash].lock);
		if (debug) {
			(void) printf("After delete_name \n");
			pr_name(name, 1);
		}
	}
}

/*
 * This routine adds a symlink in the form of an ASCII dotted quad
 * IP address that is linked to the name already recorded in the
 * filesystem name space by record_name().  Enough information is
 * (hopefully) provided to support other address types in the future.
 * The purpose of this is to cache enough information to contact
 * hosts in other domains during server crash recovery (see bugid
 * 1184192).
 *
 * The worst failure mode here is that the symlink is not made, and
 * statd falls back to the old buggy behavior.
 */
void
record_addr(char *name, sa_family_t family, struct netobj *ah)
{
	int i;
	int path_len;
	char *famstr;
	struct in_addr addr;
	char *addr6;
	char ascii_addr[MAXNAMELEN];
	char path[MAXPATHLEN];

	if (family == AF_INET) {
		if (ah->n_len != sizeof (struct in_addr))
			return;
		addr = *(struct in_addr *)ah->n_bytes;
	} else if (family == AF_INET6) {
			if (ah->n_len != sizeof (struct in6_addr))
				return;
			addr6 = (char *)ah->n_bytes;
	} else
		return;

	if (debug) {
		if (family == AF_INET)
			(void) printf("record_addr: addr= %x\n", addr.s_addr);
		else if (family == AF_INET6)
			(void) printf("record_addr: addr= %x\n",
			    ((struct in6_addr *)addr6)->s6_addr);
	}

	if (family == AF_INET) {
		if (addr.s_addr == INADDR_ANY ||
		    ((addr.s_addr && 0xff000000) == 0)) {
			syslog(LOG_DEBUG,
			    "record_addr: illegal IP address %x\n",
			    addr.s_addr);
			return;
		}
	}

	/* convert address to ASCII */
	famstr = family2string(family);
	if (famstr == NULL) {
		syslog(LOG_DEBUG,
		    "record_addr: unsupported address family %d\n",
		    family);
		return;
	}

	switch (family) {
		char abuf[INET6_ADDRSTRLEN];
	case AF_INET:
		(void) sprintf(ascii_addr, "%s.%s", famstr, inet_ntoa(addr));
		break;

	case AF_INET6:
		(void) sprintf(ascii_addr, "%s.%s", famstr,
		    inet_ntop(family, addr6, abuf, sizeof (abuf)));
		break;

	default:
		if (debug) {
			(void) printf(
			    "record_addr: family2string supports unknown "
			    "family %d (%s)\n", family, famstr);
		}
		free(famstr);
		return;
	}

	if (debug) {
		(void) printf("record_addr: ascii_addr= %s\n", ascii_addr);
	}
	free(famstr);

	/*
	 * Make the symlink in CURRENT.  The `name' file should have
	 * been created previously by record_name().
	 */
	(void) create_symlink(CURRENT, name, ascii_addr);

	/*
	 * Similarly for alternate paths.
	 */
	for (i = 0; i < pathix; i++) {
		path_len = strlen(path_name[i]) +
		    strlen("/statmon/sm/") +
		    strlen(name) + 1;

		if (path_len > MAXPATHLEN) {
			syslog(LOG_ERR,
			    "statd: pathname too long: %s/statmon/sm/%s\n",
			    path_name[i], name);
			continue;
		}
		(void) strcpy(path, path_name[i]);
		(void) strcat(path, "/statmon/sm");
		(void) create_symlink(path, name, ascii_addr);
	}
}

/*
 * SM_CRASH - simulate a crash of statd.
 */
void
sm_crash(void)
{
	name_entry *nl, *next;
	mon_entry *nl_monp, *mon_next;
	int k;
	my_id *nl_idp;

	for (k = 0; k < MAX_HASHSIZE; k++) {
		mutex_lock(&mon_table[k].lock);
		if ((mon_next = mon_table[k].sm_monhdp) ==
		    (mon_entry *) NULL) {
			mutex_unlock(&mon_table[k].lock);
			continue;
		} else {
			while ((nl_monp = mon_next) != NULL) {
				mon_next = mon_next->nxt;
				nl_idp = &nl_monp->id.mon_id.my_id;
				free(nl_monp->id.mon_id.mon_name);
				free(nl_idp->my_name);
				free(nl_monp);
			}
			mon_table[k].sm_monhdp = NULL;
		}
		mutex_unlock(&mon_table[k].lock);
	}

	/* Clean up entries in  record table */
	for (k = 0; k < MAX_HASHSIZE; k++) {
		mutex_lock(&record_table[k].lock);
		if ((next = record_table[k].sm_rechdp) ==
		    (name_entry *) NULL) {
			mutex_unlock(&record_table[k].lock);
			continue;
		} else {
			while ((nl = next) != NULL) {
				next = next->nxt;
				free(nl->name);
				free(nl);
			}
			record_table[k].sm_rechdp = NULL;
		}
		mutex_unlock(&record_table[k].lock);
	}

	/* Clean up entries in recovery table */
	mutex_lock(&recov_q.lock);
	if ((next = recov_q.sm_recovhdp) != NULL) {
		while ((nl = next) != NULL) {
			next = next->nxt;
			free(nl->name);
			free(nl);
		}
		recov_q.sm_recovhdp = NULL;
	}
	mutex_unlock(&recov_q.lock);
	statd_init();
}

/*
 * Initialize the hash tables: mon_table, record_table, recov_q and
 * locks.
 */
void
sm_inithash(void)
{
	int k;

	if (debug)
		(void) printf("Initializing hash tables\n");
	for (k = 0; k < MAX_HASHSIZE; k++) {
		mon_table[k].sm_monhdp = NULL;
		record_table[k].sm_rechdp = NULL;
		mutex_init(&mon_table[k].lock, USYNC_THREAD, NULL);
		mutex_init(&record_table[k].lock, USYNC_THREAD, NULL);
	}
	mutex_init(&recov_q.lock, USYNC_THREAD, NULL);
	recov_q.sm_recovhdp = NULL;

}

/*
 * Maps a socket address family to a name string, or NULL if the family
 * is not supported by statd.
 * Caller is responsible for freeing storage used by result string, if any.
 */
static char *
family2string(sa_family_t family)
{
	char *rc;

	switch (family) {
	case AF_INET:
		rc = strdup(SM_ADDR_IPV4);
		break;

	case AF_INET6:
		rc = strdup(SM_ADDR_IPV6);
		break;

	default:
		rc = NULL;
		break;
	}

	return (rc);
}

/*
 * Prints out list in record_table if flag is 1 otherwise
 * prints out each list in recov_q specified by name.
 */
static void
pr_name(char *name, int flag)
{
	name_entry *nl;
	unsigned int hash;

	if (!debug)
		return;
	if (flag) {
		SMHASH(name, hash);
		(void) printf("*****record_q: ");
		mutex_lock(&record_table[hash].lock);
		nl = record_table[hash].sm_rechdp;
		while (nl != NULL) {
			(void) printf("(%x), ", (int)nl);
			nl = nl->nxt;
		}
		mutex_unlock(&record_table[hash].lock);
	} else {
		(void) printf("*****recovery_q: ");
		mutex_lock(&recov_q.lock);
		nl = recov_q.sm_recovhdp;
		while (nl != NULL) {
			(void) printf("(%x), ", (int)nl);
			nl = nl->nxt;
		}
		mutex_unlock(&recov_q.lock);

	}
	(void) printf("\n");
}
