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

#include <sys/types.h>
#include <sys/resource.h>
#include <sys/loadavg.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/utsname.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <dirent.h>
#include <string.h>
#include <errno.h>
#include <poll.h>
#include <ctype.h>
#include <fcntl.h>
#include <limits.h>
#include <time.h>
#include <project.h>
#include <libintl.h>
#include <pthread.h>

#include "rdimpl.h"
#include "rdutil.h"
#include "rdtable.h"
#include "rdfile.h"
#include "rdlist.h"

/* global variables */

extern pthread_mutex_t listLock;

list_t	lwps;		/* list of lwps/processes */
list_t	users;		/* list of users */
list_t	projects;	/* list of projects */
list_t	processes;	/* list of processes */

sys_info_t sys_info;

jmp_buf dm_jmpbuffer;
char	errmsg[NL_TEXTMAX];	/* error message max 255 */

static float	total_mem;	/* total memory usage */
static float	total_cpu;	/* total cpu usage */
static char *nullstr = "null";
static double		loadavg[3];
static DIR		*procdir;


/*
 * Add a LWP entry to the specifed list.
 */
lwp_info_t *
list_add_lwp(list_t *list, pid_t pid, id_t lwpid)
{
	lwp_info_t *lwp;

	if (list->l_head == NULL) {
		list->l_head = list->l_tail = lwp = Zalloc(sizeof (lwp_info_t));
	} else {
		lwp = Zalloc(sizeof (lwp_info_t));
		lwp->li_prev = list->l_tail;
		((lwp_info_t *)list->l_tail)->li_next = lwp;
		list->l_tail = lwp;
	}
	lwp->li_lwpsinfo = Zalloc(sizeof (lwpsinfo_t));
	lwp->li_psinfo = Zalloc(sizeof (psinfo_t));
	lwp->li_psinfo->pr_pid = pid;
	lwp->li_lwpsinfo->pr_lwpid = lwpid;
	lwpid_add(lwp, pid, lwpid);
	list->l_count++;
	return (lwp);
}


/*
 * Remove an LWP entry from the specified list.
 */
static void
list_remove_lwp(list_t *list, lwp_info_t *lwp)
{

	if (lwp->li_prev)
		lwp->li_prev->li_next = lwp->li_next;
	else
		list->l_head = lwp->li_next;	/* removing the head */
	if (lwp->li_next)
		lwp->li_next->li_prev = lwp->li_prev;
	else
		list->l_tail = lwp->li_prev;	/* removing the tail */
	lwpid_del(lwp->li_psinfo->pr_pid, lwp->li_lwpsinfo->pr_lwpid);
	if (lwpid_pidcheck(lwp->li_psinfo->pr_pid) == 0)
		fds_rm(lwp->li_psinfo->pr_pid);
	list->l_count--;
	Free(lwp->li_lwpsinfo);
	Free(lwp->li_psinfo);
	Free(lwp);
}


/*
 * Remove entry from the specified list.
 */
static void
list_remove_id(list_t *list, id_info_t *id)
{

	if (id->id_prev)
		id->id_prev->id_next = id->id_next;
	else
		list->l_head = id->id_next;	/* removing the head */
	if (id->id_next)
		id->id_next->id_prev = id->id_prev;
	else
		list->l_tail = id->id_prev;	/* removing the tail */

	list->l_count--;
	/* anly free if doesn't point to static 'nullstr' def */
	if (id->id_name != nullstr)
		Free(id->id_name);
	Free(id);
}


/*
 * Empty the specified list.
 * If it's an LWP list, this will traverse /proc to
 * restore microstate accounting to its original value.
 */
void
list_clear(list_t *list)
{
	if (list->l_type == LT_LWPS) {
		lwp_info_t	*lwp = list->l_tail;
		lwp_info_t	*lwp_tmp;

		fd_closeall();
		while (lwp) {
			lwp_tmp = lwp;
			lwp = lwp->li_prev;
			list_remove_lwp(&lwps, lwp_tmp);
		}
	} else {
		id_info_t *id = list->l_head;
		id_info_t *nextid;
		while (id) {
			nextid = id->id_next;
			/* anly free if doesn't point to static 'nullstr' def */
			if (id->id_name != nullstr)
				Free(id->id_name);
			Free(id);
			id = nextid;
		}
		list->l_count = 0;
		list->l_head = list->l_tail = NULL;
	}
}


/*
 * Calculate a process' statistics from its lwp statistics.
 */
static void
id_update(id_info_t *id, lwp_info_t *lwp, int l_type) {
	char usrname[LOGNAME_MAX+1];
	char projname[PROJNAME_MAX+1];

	/*
	 * When an id is processed first time in an update run its
	 * id_alive flag set to false.
	 * The next values are gauges, their old values from the previous
	 * calculation should be set to null.
	 * The names and timestamp must be set once.
	 */
	if (id->id_alive == B_FALSE) {
		id->id_hpsize = 0;
		id->id_size = 0;
		id->id_rssize = 0;
		id->id_pctmem = 0;
		id->id_timestamp = 0;
		id->id_time = 0;
		id->id_pctcpu = 0;
		id->id_nlwps = 0;
		id->id_nproc = 0;
		id->id_pid = (int)-1;
		id->id_taskid	= lwp->li_psinfo->pr_taskid;
		id->id_projid	= lwp->li_psinfo->pr_projid;
		id->id_psetid	= lwp->li_lwpsinfo->pr_bindpset;
		id->id_uid	= lwp->li_psinfo->pr_uid;
		if (l_type == LT_USERS) {
			getusrname(id->id_uid, usrname, LOGNAME_MAX+1);
			id->id_name = Realloc(id->id_name,
					strlen(usrname) + 1);
			(void) strcpy(id->id_name, usrname);
		} else if (l_type == LT_PROJECTS) {
			getprojname(id->id_projid, projname, PROJNAME_MAX);
			id->id_name = Realloc(id->id_name,
					strlen(projname) + 1);
			(void) strcpy(id->id_name, projname);
		} else {
			id->id_name = nullstr;
		}
		id->id_timestamp = get_timestamp();
		/* mark this id as changed in this update run */
		id->id_alive = B_TRUE;
	}

	if (lwp->li_psinfo->pr_nlwp > 0) {
	    id->id_nlwps++;
	}

	/*
	 * The next values are calculated only one time for each pid.
	 */
	if ((id->id_pid != lwp->li_psinfo->pr_pid) &&
		(lwp->rlwpid == lwp->li_lwpsinfo->pr_lwpid)) {
		id->id_nproc++;
		id->id_hpsize	+= (lwp->li_hpsize/1024);
		id->id_size	+= lwp->li_psinfo->pr_size;
		id->id_rssize	+= lwp->li_psinfo->pr_rssize;
		id->id_pctmem	+= FRC2PCT(lwp->li_psinfo->pr_pctmem);
		id->id_pid	= lwp->li_psinfo->pr_pid;
		if (l_type == LT_PROCESS)
			total_mem += FRC2PCT(lwp->li_psinfo->pr_pctmem);
	}

	id->id_pctcpu	+= FRC2PCT(lwp->li_lwpsinfo->pr_pctcpu);
	if (l_type == LT_PROCESS)
		total_cpu += FRC2PCT(lwp->li_lwpsinfo->pr_pctcpu);
	id->id_time	+= TIME2SEC(lwp->li_lwpsinfo->pr_time);
	id->id_usr	+= lwp->li_usr;
	id->id_sys	+= lwp->li_sys;
	id->id_ttime	+= lwp->li_ttime;
	id->id_tpftime	+= lwp->li_tpftime;
	id->id_dpftime	+= lwp->li_dpftime;
	id->id_kpftime	+= lwp->li_kpftime;
	id->id_lck	+= lwp->li_lck;
	id->id_slp	+= lwp->li_slp;
	id->id_lat	+= lwp->li_lat;
	id->id_stime	+= lwp->li_stime;
	id->id_minf	+= lwp->li_minf;
	id->id_majf	+= lwp->li_majf;
	id->id_nswap	+= lwp->li_nswap;
	id->id_inblk	+= lwp->li_inblk;
	id->id_oublk	+= lwp->li_oublk;
	id->id_msnd	+= lwp->li_msnd;
	id->id_mrcv	+= lwp->li_mrcv;
	id->id_sigs	+= lwp->li_sigs;
	id->id_vctx	+= lwp->li_vctx;
	id->id_ictx	+= lwp->li_ictx;
	id->id_scl	+= lwp->li_scl;
	id->id_ioch	+= lwp->li_ioch;
}

static void
list_update(list_t *list, lwp_info_t *lwp)
{
	id_info_t *id;
	if (list->l_head == NULL) {			/* first element */
		list->l_head = list->l_tail = id = Zalloc(sizeof (id_info_t));
		id_update(id, lwp, list->l_type);
		list->l_count++;
		return;
	}

	for (id = list->l_head; id; id = id->id_next) {
		if ((list->l_type == LT_PROCESS) &&
		    (id->id_pid != lwp->li_psinfo->pr_pid))
			continue;
		if ((list->l_type == LT_USERS) &&
		    (id->id_uid != lwp->li_psinfo->pr_uid))
			continue;
		if ((list->l_type == LT_PROJECTS) &&
		    (id->id_projid != lwp->li_psinfo->pr_projid))
			continue;
		id_update(id, lwp, list->l_type);
		return;
	}

	/* a new element */
	id = list->l_tail;
	id->id_next = Zalloc(sizeof (id_info_t));
	id->id_next->id_prev = list->l_tail;
	id->id_next->id_next = NULL;
	list->l_tail = id->id_next;
	id = list->l_tail;
	id_update(id, lwp, list->l_type);
	list->l_count++;
}

/*
 * This procedure removes all dead procs/user/.. from the specified list.
 */
static void
list_refresh_id(list_t *list)
{
	id_info_t *id, *id_next;

	if (!(list->l_type & LT_PROCESS) && !(list->l_type & LT_USERS) &&
	    !(list->l_type & LT_TASKS) && !(list->l_type & LT_PROJECTS) &&
	    !(list->l_type & LT_PSETS)) {
		return;
	}
	id = list->l_head;

	while (id) {
		if (id->id_alive == B_FALSE) {	/* id is dead */
			id_next = id->id_next;
			list_remove_id(list, id);
			id = id_next;
		} else {

			/* normalize total mem and cpu across all processes. */
			if (total_mem >= 100)
				id->id_pctmem = (100 * id->id_pctmem) /
				    total_mem;
			if (total_cpu >= 100)
				id->id_pctcpu = (100 * id->id_pctcpu) /
				    total_cpu;

			id->id_alive = B_FALSE;
			id = id->id_next;
		}
	}
}

/*
 * This procedure removes all dead lwps from the specified lwp list.
 */
static void
list_refresh(list_t *list)
{
	lwp_info_t *lwp, *lwp_next;

	if (!(list->l_type & LT_LWPS))
		return;
	lwp = list->l_head;

	while (lwp) {
		if (lwp->li_alive == B_FALSE) {	/* lwp is dead */
			lwp_next = lwp->li_next;
			list_remove_lwp(&lwps, lwp);
			lwp = lwp_next;
		} else {
			lwp->li_alive = B_FALSE;
			lwp = lwp->li_next;
		}
	}
}


/*
 * Update a LWP entry according to the specified usage data.
 */
static void
lwp_update(lwp_info_t *lwp, struct prusage *usage_buf)
{
	lwp->li_usr	= (double)(TIME2NSEC(usage_buf->pr_utime) -
	    TIME2NSEC(lwp->li_usage.pr_utime)) / NANOSEC;
	lwp->li_sys	= (double)(TIME2NSEC(usage_buf->pr_stime) -
	    TIME2NSEC(lwp->li_usage.pr_stime)) / NANOSEC;
	lwp->li_ttime	= (double)(TIME2NSEC(usage_buf->pr_ttime) -
	    TIME2NSEC(lwp->li_usage.pr_ttime)) / NANOSEC;
	lwp->li_tpftime = (double)(TIME2NSEC(usage_buf->pr_tftime) -
	    TIME2NSEC(lwp->li_usage.pr_tftime)) / NANOSEC;
	lwp->li_dpftime = (double)(TIME2NSEC(usage_buf->pr_dftime) -
	    TIME2NSEC(lwp->li_usage.pr_dftime)) / NANOSEC;
	lwp->li_kpftime = (double)(TIME2NSEC(usage_buf->pr_kftime) -
	    TIME2NSEC(lwp->li_usage.pr_kftime)) / NANOSEC;
	lwp->li_lck	= (double)(TIME2NSEC(usage_buf->pr_ltime) -
	    TIME2NSEC(lwp->li_usage.pr_ltime)) / NANOSEC;
	lwp->li_slp	= (double)(TIME2NSEC(usage_buf->pr_slptime) -
	    TIME2NSEC(lwp->li_usage.pr_slptime)) / NANOSEC;
	lwp->li_lat	= (double)(TIME2NSEC(usage_buf->pr_wtime) -
	    TIME2NSEC(lwp->li_usage.pr_wtime)) / NANOSEC;
	lwp->li_stime	= (double)(TIME2NSEC(usage_buf->pr_stoptime) -
	    TIME2NSEC(lwp->li_usage.pr_stoptime)) / NANOSEC;
	lwp->li_minf = usage_buf->pr_minf - lwp->li_usage.pr_minf;
	lwp->li_majf = usage_buf->pr_majf - lwp->li_usage.pr_majf;
	lwp->li_nswap = usage_buf->pr_nswap - lwp->li_usage.pr_nswap;
	lwp->li_inblk = usage_buf->pr_inblk - lwp->li_usage.pr_inblk;
	lwp->li_oublk = usage_buf->pr_oublk -lwp->li_usage.pr_oublk;
	lwp->li_msnd = usage_buf->pr_msnd - lwp->li_usage.pr_msnd;
	lwp->li_mrcv = usage_buf->pr_mrcv - lwp->li_usage.pr_mrcv;
	lwp->li_sigs = usage_buf->pr_sigs - lwp->li_usage.pr_sigs;
	lwp->li_vctx = usage_buf->pr_vctx - lwp->li_usage.pr_vctx;
	lwp->li_ictx = usage_buf->pr_ictx - lwp->li_usage.pr_ictx;
	lwp->li_scl = usage_buf->pr_sysc - lwp->li_usage.pr_sysc;
	lwp->li_ioch = usage_buf->pr_ioch - lwp->li_usage.pr_ioch;
	lwp->li_timestamp = TIME2NSEC(usage_buf->pr_tstamp);
	(void) memcpy(&lwp->li_usage, usage_buf, sizeof (prusage_t));
}


/*
 * This is the meat of the /proc scanner.
 * It will visit every single LWP in /proc.
 */
static void
collect_lwp_data()
{
	char *pidstr;
	pid_t pid;
	id_t lwpid;
	size_t entsz;
	long nlwps, nent, i;
	char *buf, *ptr;
	char pfile[MAX_PROCFS_PATH];

	fds_t *fds;
	lwp_info_t *lwp;

	dirent_t *direntp;

	prheader_t	header_buf;
	psinfo_t	psinfo_buf;
	prusage_t	usage_buf;
	lwpsinfo_t	*lwpsinfo_buf;
	prusage_t	*lwpusage_buf;

	log_msg("->collect_lwp_data(): %d files open\n", fd_count());
	for (rewinddir(procdir); (direntp = readdir(procdir)); ) {
		pidstr = direntp->d_name;
		if (pidstr[0] == '.')	/* skip "." and ".."  */
			continue;
		pid = atoi(pidstr);
		if (pid == 0 || pid == 2 || pid == 3)
			continue;	/* skip sched, pageout and fsflush */

		fds = fds_get(pid);	/* get ptr to file descriptors */

		/*
		 * Here we are going to read information about
		 * current process (pid) from /proc/pid/psinfo file.
		 * If process has more than one lwp, we also should
		 * read /proc/pid/lpsinfo for information about all lwps.
		 */
		(void) snprintf(pfile, MAX_PROCFS_PATH,
		    "/proc/%s/psinfo", pidstr);
		if ((fds->fds_psinfo = fd_open(pfile, O_RDONLY,
		    fds->fds_psinfo)) == NULL)
			continue;
		if (pread(fd_getfd(fds->fds_psinfo), &psinfo_buf,
			sizeof (struct psinfo), 0) != sizeof (struct psinfo)) {
			fd_close(fds->fds_psinfo);
			continue;
		}

		fd_close(fds->fds_psinfo);

		nlwps = psinfo_buf.pr_nlwp + psinfo_buf.pr_nzomb;
		if (nlwps > 1) {
			(void) snprintf(pfile, MAX_PROCFS_PATH,
			    "/proc/%s/lpsinfo", pidstr);
			if ((fds->fds_lpsinfo = fd_open(pfile, O_RDONLY,
			    fds->fds_lpsinfo)) == NULL)
				continue;
			entsz = sizeof (struct prheader);
			if (pread(fd_getfd(fds->fds_lpsinfo), &header_buf,
			    entsz, 0) != entsz) {
				fd_close(fds->fds_lpsinfo);
				continue;
			}
			nent = header_buf.pr_nent;
			entsz = header_buf.pr_entsize * nent;
			ptr = buf = Malloc(entsz);
			if (pread(fd_getfd(fds->fds_lpsinfo), buf,
			    entsz, sizeof (struct prheader)) != entsz) {
				fd_close(fds->fds_lpsinfo);
				Free(buf);
				continue;
			}

			fd_close(fds->fds_lpsinfo);

			for (i = 0; i < nent;
			    i++, ptr += header_buf.pr_entsize) {
				/*LINTED ALIGNMENT*/
				lwpsinfo_buf = (lwpsinfo_t *)ptr;
				lwpid = lwpsinfo_buf->pr_lwpid;
				if ((lwp = lwpid_get(pid, lwpid)) == NULL) {
					lwp = list_add_lwp(&lwps, pid, lwpid);
				}
				if (i == 0)
					lwp->rlwpid = lwpid;
				(void) memcpy(lwp->li_psinfo, &psinfo_buf,
				    sizeof (psinfo_t) - sizeof (lwpsinfo_t));
				lwp->li_alive = B_TRUE;
				(void) memcpy(lwp->li_lwpsinfo,
				    lwpsinfo_buf, sizeof (lwpsinfo_t));
			}
			Free(buf);
		} else {
			lwpid = psinfo_buf.pr_lwp.pr_lwpid;
			if ((lwp = lwpid_get(pid, lwpid)) == NULL) {
				lwp = list_add_lwp(&lwps, pid, lwpid);
			}
			lwp->rlwpid = lwpid;
			(void) memcpy(lwp->li_psinfo, &psinfo_buf,
			    sizeof (psinfo_t) - sizeof (lwpsinfo_t));
			lwp->li_alive = B_TRUE;
			(void) memcpy(lwp->li_lwpsinfo,
			    &psinfo_buf.pr_lwp, sizeof (lwpsinfo_t));
			lwp->li_lwpsinfo->pr_pctcpu = lwp->li_psinfo->pr_pctcpu;
		}

		/*
		 * At this part of scandir we read additional information
		 * about processes from /proc/pid/usage file.
		 * Again, if process has more than one lwp, then we
		 * will get information about all its lwps from
		 * /proc/pid/lusage file.
		 */
		if (nlwps > 1) {
			(void) snprintf(pfile, MAX_PROCFS_PATH,
			    "/proc/%s/lusage", pidstr);
			if ((fds->fds_lusage = fd_open(pfile, O_RDONLY,
			    fds->fds_lusage)) == NULL)
				continue;
			entsz = sizeof (struct prheader);
			if (pread(fd_getfd(fds->fds_lusage), &header_buf,
			    entsz, 0) != entsz) {
				fd_close(fds->fds_lusage);
				continue;
			}

			nent = header_buf.pr_nent;
			entsz = header_buf.pr_entsize * nent;
			buf = Malloc(entsz);
			if (pread(fd_getfd(fds->fds_lusage), buf,
				entsz, sizeof (struct prheader)) != entsz) {
				fd_close(fds->fds_lusage);
				Free(buf);
				continue;
			}

			fd_close(fds->fds_lusage);

			for (i = 1, ptr = buf + header_buf.pr_entsize; i < nent;
			    i++, ptr += header_buf.pr_entsize) {
				/*LINTED ALIGNMENT*/
				lwpusage_buf = (prusage_t *)ptr;
				lwpid = lwpusage_buf->pr_lwpid;
				if ((lwp = lwpid_get(pid, lwpid)) == NULL)
					continue;
				lwp_update(lwp, lwpusage_buf);
			}
			Free(buf);
		} else {
			(void) snprintf(pfile, MAX_PROCFS_PATH,
			    "/proc/%s/usage", pidstr);
			if ((fds->fds_usage = fd_open(pfile, O_RDONLY,
			    fds->fds_usage)) == NULL)
				continue;
			entsz = sizeof (prusage_t);
			if (pread(fd_getfd(fds->fds_usage), &usage_buf,
			    entsz, 0) != entsz) {
				fd_close(fds->fds_usage);
				continue;
			}

			fd_close(fds->fds_usage);

			lwpid = psinfo_buf.pr_lwp.pr_lwpid;
			if ((lwp = lwpid_get(pid, lwpid)) == NULL)
				continue;
			lwp_update(lwp, &usage_buf);
		}
	}
	list_refresh(&lwps);
	fd_update();
	log_msg("<-collect_lwp_data(): %d files open\n", fd_count());
}


/*
 * Create linked lists of users, projects and sets.
 *
 * Updates of the process, users and projects lists are done in
 * a critical section so that the consumer of these lists will
 * always get consistent data.
 */
static void
list_create()
{
	struct utsname	utsn;
	lwp_info_t *lwp;
	hrtime_t t1, t2, t3;
	double d;
	int rv;

	lwp = lwps.l_head;
	total_mem = 0;
	total_cpu = 0;
	log_msg("->list_create()\n");
	t1 = gethrtime();
	if ((rv = pthread_mutex_lock(&listLock)) == 0) {
		t2 = gethrtime();
		d = (double)(t2 - t1) / 1000000000.0;
		log_msg("Scanner process lock wait was %1.5f sec\n", d);

		while (lwp) {
			list_update(&processes, lwp);
			list_update(&users, lwp);
			list_update(&projects, lwp);
			lwp = lwp->li_next;
		}
		list_refresh_id(&processes);
		list_refresh_id(&users);
		list_refresh_id(&projects);
		/* release the mutex */
		if ((rv = pthread_mutex_unlock(&listLock)) != 0)
			log_msg("pthread_mutex_unlock failed with %d\n", rv);

		t3 = gethrtime();

		d = (double)(t3 - t2) / 1000000000.0;
		log_msg("Scanner process lock time was %1.5f sec\n", d);

	} else {
		log_msg("pthread_mutex_lock failed with %d\n", rv);
	}

	if (uname(&utsn) != -1) {
		sys_info.name =
		    Realloc(sys_info.name, strlen(utsn.sysname) + 1);
		(void) strcpy(sys_info.name, utsn.sysname);
		sys_info.nodename =
		    Realloc(sys_info.nodename, strlen(utsn.nodename) + 1);
		(void) strcpy(sys_info.nodename, utsn.nodename);
	} else {
		log_err("uname()\n");
	}

	log_msg("<-list_create()\n");
}


static void
collect_data() {

	collect_lwp_data();
	if (getloadavg(loadavg, 3) == -1)
		dmerror("cannot get load average\n");
}


void
monitor_stop()
{
	/* store the list state */
	if (ltdb_file != NULL)
		(void) list_store(ltdb_file);
	list_clear(&lwps);
	list_clear(&processes);
	list_clear(&users);
	list_clear(&projects);
	fd_exit();
}


/*
 * Initialize the monitor.
 * Creates list data structures.
 * If a saved list data file exists it is loaded.
 * The /proc directory is opened.
 * No actual scanning of /proc is done.
 *
 * Returns 0 if OK or -1 on error (leaving errno unchanged)
 */
int
monitor_start()
{

	if (setjmp(dm_jmpbuffer) == 0) {
		lwpid_init();
		fd_init(Setrlimit());

		list_alloc(&lwps, LS_LWPS);
		list_alloc(&processes, LT_PROCESS);
		list_alloc(&users, LS_USERS);
		list_alloc(&projects, LS_PROJECTS);

		list_init(&lwps, LT_LWPS);
		list_init(&processes, LT_PROCESS);
		list_init(&users, LT_USERS);
		list_init(&projects, LT_PROJECTS);

		sys_info.name = NULL;
		sys_info.nodename = NULL;

		if ((procdir = opendir("/proc")) == NULL)
			dmerror("cannot open /proc directory\n");

		/* restore the lists state */
		if (ltdb_file != NULL)
			(void) list_restore(ltdb_file);

		return (0);
	} else {
		return (-1);
	}
}


/*
 * Update the monitor data lists.
 * return 0, or -1 on error and leave errno unchanged
 */
int
monitor_update()
{
	if (setjmp(dm_jmpbuffer) == 0) {
		collect_data();
		list_create();
		return (0);
	} else {
		return (-1);
	}
}
