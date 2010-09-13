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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdio_ext.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/time.h>
#include <fcntl.h>
#include <sys/fcntl.h>
#include <errno.h>
#include <string.h>
#include <limits.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <thread.h>
#include <tnf/probe.h>

#include <netinet/dhcp.h>
#include <locale.h>
#include <signal.h>
#include <tnf/probe.h>

#include <dhcp_svc_confopt.h>
#include <dhcp_svc_private.h>
#include <dhcp_impl.h>

#ifdef	DEBUG
#include <mtmalloc.h>
#endif				/* DEBUG */

/*
 * Global variables.
 */
int		verbose = 0;
thread_t	*tp;
cond_t		never;
volatile time_t *timp;
volatile int    tms;
char		*fl;
mutex_t		mtx;
mutex_t		thread_mtx;
volatile ulong_t ops_outstanding;

static volatile ulong_t tops, otops;
static volatile ulong_t minops[6];
static volatile time_t mintim[6];
static volatile int minind;
long		sample_time = 10L;
long		nsamples = 2;

static volatile time_t start, ostart;
volatile time_t ustart;
volatile int    time_to_go;
volatile int    spawn_helper;
char		b[1024 * 1024];
volatile double slp;
volatile int    worktype;
thread_t	sigthread;
volatile int    old, new, unstarted;
volatile uint_t	threads;
volatile unsigned int douwork = 0;
volatile int    dofsync = 0;
volatile int    domalloc = 0;
volatile int    dofork = 0;
thread_t	opnthread;
volatile int	doopen = 0;

dsvc_datastore_t datastore;	/* Datastore for container access */

#define	MAXTABLE	1024
int		ntable;

dn_rec_list_t  *thread_dncp[MAXTABLE];
dsvc_handle_t   dh[MAXTABLE];	/* data handle */
struct in_addr  net[MAXTABLE];
uint_t		nrecords[MAXTABLE];
char		*network;

typedef struct work {
	boolean_t	isthreaded;
	int		thread;
	cond_t		cv;
	mutex_t		mtx;
	dn_rec_t	*dnp;
}work_t;

void
free_work_t(work_t *wptr) {
	free(wptr->dnp);
	free(wptr);
}
/*
 * Simulated binary datastore work
 */
/* ARGSUSED */
static void    *
uwork(void *argp)
{
	int		i;
	int		err;
	int		fd;
	long		block;
	work_t		*wptr = argp;
	char		*ptr;
	size_t		size = ((random() & (domalloc - 1)) + 0x200) &
				~(0x200 - 1);
	int		wtype;

	if (domalloc)
		ptr = malloc(size);
	else
		ptr = b;

	if (wptr->isthreaded) {
		(void) mutex_lock(&wptr->mtx);
	}
	i = wptr->thread;

	TNF_PROBE_1(uwork, "work", "uwork%debug 'in function work'",
		    tnf_long, size, size);

	wtype = worktype == 0 ? random() & 0x7 : worktype;
	block = (random() & (douwork - 1)) + (tms / 0x200) + 1;

	/* prewrite legal records */
	if (timp[i] == NULL && ustart == 0) {
		ustart = time(NULL);
		wtype = 4;
		block = (tms / 0x200) + 1;
		size = sizeof (b);
		ptr = b;
	}
	timp[i] = time(NULL);
	fd = open(fl, O_RDWR);
	(void) write(fd, (char *)timp, tms);
	(void) close(fd);

	if (wtype == 4) {

		TNF_PROBE_2(uwork_write, "work",
			    "uwork_write%debug 'in function work'",
			    tnf_long, block, block,
			    tnf_long, size, size);

		fd = open(fl, O_RDWR);
		(void) lseek(fd, block * 0x200, 0L);
		err = write(fd, ptr, size);
		(void) close(fd);

		TNF_PROBE_1(uwork_write_end, "work",
			    "uwork_write_end%debug 'in function work'",
			    tnf_long, err, err);

	} else if (wtype == 3 && dofsync) {

		TNF_PROBE_0(uwork_fsync, "work",
			    "uwork_fsync%debug 'in function work'");

		fd = open(fl, O_RDWR);
		err = fsync(fd);
		(void) close(fd);

		TNF_PROBE_1(uwork_fsync_end, "work",
			    "uwork_fsync_end%debug 'in function work'",
			    tnf_long, err, err);
	} else {
		TNF_PROBE_2(uwork_read, "work",
			    "uwork_read%debug 'in function work'",
			    tnf_long, block, block,
			    tnf_long, size, size);

		fd = open(fl, O_RDWR);
		(void) lseek(fd, block * 0x200, 0L);
		err = read(fd, ptr, size);
		(void) close(fd);

		TNF_PROBE_1(uwork_read_end, "work",
			    "uwork_read_end%debug 'in function work'",
			    tnf_long, err, err);

	}
	if (domalloc && ptr != b)
		free(ptr);

	if (wptr->isthreaded) {
		(void) mutex_unlock(&wptr->mtx);
		cond_signal(&wptr->cv);
		TNF_PROBE_0(work_end, "work", "");
		thr_exit(NULL);
	}
	TNF_PROBE_0(uwork_end, "work", "");

	return ((void *) NULL);
}

/*
 * Simulated datastore work
 */
static void    *
work(void *argp)
{
	int		i, j;
	dn_rec_t	*dnp;
	int		err;
	work_t		*wptr = argp;
	uchar_t		cid_len;
	char		*ptr;
	uint32_t	query;
	dn_rec_t	dn, ndn;
	dn_rec_list_t	*dncp = NULL;
	uint_t		crecords, irecords;
	int		wtype;
	int		firsttime = 0;
	int		op;
	size_t		size = ((random() & (domalloc - 1)) + 0x100) &
			~(0x1000 - 1);
	int		table;

	if (domalloc)
		ptr = malloc(size);
	else
		ptr = b;

	irecords = (random() & 0xff) + 1;
	if (irecords == 12) {
		irecords = (uint_t)-1;
	}
	if (wptr->isthreaded) {
		(void) mutex_lock(&wptr->mtx);
	}
	i = wptr->thread;
	dnp = wptr->dnp;

	table = i % ntable;
	dn = *dnp;

	cid_len = 7;

	if (worktype == 0) {
		wtype = random() & 0x7;
		if (wtype == 4)
			wtype--;
	} else
		wtype = worktype;

	/* preload a legal record */
	if (timp[i] == NULL) {
		wtype = 3;
		firsttime = 1;
		irecords = threads * 2;
		(void) mutex_lock(&thread_mtx);
		if ((dncp = thread_dncp[table]) != NULL) {
			thread_dncp[table] = dncp->dnl_next;
			*dnp = *(dncp->dnl_rec);
			dncp->dnl_next = NULL;
			wtype = -1;
			(void) mutex_unlock(&thread_mtx);
		}
	}
	TNF_PROBE_2(work, "work", "work%debug 'in function work'",
		    tnf_ulong, worktype, wtype,
		    tnf_ulong, irecords, irecords);

	timp[i] = time(NULL);
	crecords = 0;
	DSVC_QINIT(query);
	switch (wtype) {
	case -1:
		break;
	case 1:
		switch (random() & 0x7) {
		case 1:
			for (j = 0; j < cid_len; j++)
				dn.dn_cid[j] = random() & 0xff;
			break;
		case 2:
			for (j = 0; j < cid_len; j++)
				dn.dn_cid[j] = '\0';
			dn.dn_cid_len = 1;
			break;
		}
		DSVC_QEQ(query, DN_QCID);

		/* LINTED */
		TNF_PROBE_2(work_cid, "work work_cid",
			    "work_cid%debug 'in function work'",
			    tnf_ulong, cid, *(ulong_t *)&dn.dn_cid,
			    tnf_ulong, cid_len, dn.dn_cid_len);

		err = lookup_dd(dh[table], B_TRUE, query, -1,
			    (const void *)&dn, (void **)&dncp, &crecords);

		TNF_PROBE_2(work_cid_end, "work work_cid",
			    "work_cid_end%debug 'in function work'",
			    tnf_ulong, err, err,
			    tnf_ulong, crecords, crecords);

		if (crecords > 0 && dncp)
			*dnp = *(dncp->dnl_rec);
		break;

	case 2:
		switch (random() & 0x7) {
		case 1:
			dn.dn_cip.s_addr = random();
			break;
		case 2:
			dn.dn_cip.s_addr = net[table].s_addr |
				(random() & (nrecords[table] - 1));
			break;
		}

		DSVC_QEQ(query, DN_QCIP);

		TNF_PROBE_1(work_cip, "work work_cip",
			    "work_cip%debug 'in function work'",
			    tnf_ulong, cip, dn.dn_cip.s_addr);

		err = lookup_dd(dh[table], B_TRUE, query, -1,
			    (const void *)&dn, (void **)&dncp, &crecords);

		TNF_PROBE_2(work_cip_end, "work work_cip",
			    "work_cip_end%debug 'in function work'",
			    tnf_ulong, err, err,
			    tnf_ulong, crecords, crecords);

		if (crecords > 0 && dncp)
			*dnp = *(dncp->dnl_rec);
		break;
	case 3:
		op = random() & 0x7;
		if (firsttime)
			op = 2;

		switch (op) {
		case 1:
			DSVC_QNEQ(query, DN_QLEASE);
			dn.dn_lease = 0;
			break;
		case 2:
			DSVC_QEQ(query, DN_QCID);
			for (j = 0; j < cid_len; j++)
				dn.dn_cid[j] = '\0';
			dn.dn_cid_len = 1;
			break;
		}

		TNF_PROBE_2(work_read, "work work_read",
			    "work_read%debug 'in function work'",
			    tnf_ulong, query, query,
			    tnf_ulong, cid_len, dn.dn_cid_len);

		err = lookup_dd(dh[table], B_TRUE, query, irecords,
			    (const void *)&dn, (void **)&dncp, &crecords);

		TNF_PROBE_2(work_read_end, "work work_read",
			    "work_read_end%debug 'in function work'",
			    tnf_ulong, err, err,
			    tnf_ulong, crecords, crecords);

		if (crecords > 0 && dncp) {
			*dnp = *(dncp->dnl_rec);
			if (firsttime) {
				thread_dncp[table] = dncp->dnl_next;
				dncp->dnl_next = NULL;
				mutex_unlock(&thread_mtx);
			}
		}
		break;
	case 4:
		op = dnp->dn_lease & 0x3;
		switch (op) {
		case 0:
			/* write record w/ cid */
			ndn = *dnp;
			ndn.dn_lease = (htonl(time(NULL)) & ~0x3) + 1;
			ndn.dn_cid_len = 14;
			for (j = 0; j < ndn.dn_cid_len; j++)
				ndn.dn_cid[j] = random() & 0xff;

			/* LINTED */
			TNF_PROBE_2(work1_modify, "work work1_modify",
				    "work1_modify%debug 'in function work'",
				    tnf_ulong, cid, *(ulong_t *)&ndn.dn_cid,
				    tnf_ulong, cid_len, ndn.dn_cid_len);

			err = modify_dd_entry(dh[table], dnp, &ndn);
			if (err != DSVC_SUCCESS && verbose) {
				fprintf(stderr, "work: %d %d error %d\n",
					wtype, op, err);
			}

			TNF_PROBE_1(work1_modify_end, "work work1_modify_end",
				    "work1_modify_end%debug 'in function work'",
				    tnf_ulong, err, err);
			*dnp = ndn;
			break;
		case 1:
			/* re-read record w/ cid */
			DSVC_QEQ(query, DN_QCID);
			TNF_PROBE_2(work_read1, "work work_read1",
				    "work_read1%debug 'in function work'",
				    tnf_ulong, query, query,
				    tnf_ulong, cid_len, dn.dn_cid_len);

			err = lookup_dd(dh[table], B_TRUE, query, - 1,
					(const void *)dnp, (void **)&dncp,
					&crecords);
			TNF_PROBE_2(work_read1_end, "work work_read1",
				    "work_read1_end%debug 'in function work'",
				    tnf_ulong, err, err,
				    tnf_ulong, crecords, crecords);

			if ((err != DSVC_SUCCESS || crecords < 1) && verbose) {
				fprintf(stderr, "work: %d %d error %d %d\n",
					wtype, op, err, crecords);
			}
			dnp->dn_lease++;
			break;
		case 2:
			/* write free record */
			dnp->dn_lease--;
			ndn = *dnp;
			DSVC_QEQ(query, DN_QCID);
			for (j = 0; j < cid_len; j++)
				ndn.dn_cid[j] = '\0';
			ndn.dn_cid_len = 1;
			ndn.dn_lease = 0;

			TNF_PROBE_2(work_modify2, "work work_modify2",
				    "work_modify2%debug 'in function work'",
				    tnf_ulong, cid, *(ulong_t *)&ndn.dn_cid,
				    tnf_ulong, cid_len, ndn.dn_cid_len);

			err = modify_dd_entry(dh[table], dnp, &ndn);

			TNF_PROBE_1(work_modify2_end, "work work_modify2_end",
			    "work_modify2_end%debug 'in function work'",
				    tnf_ulong, err, err);

			if (err != DSVC_SUCCESS && verbose) {
				fprintf(stderr, "work: %d %d error %d\n",
					wtype, op, err);
			}
			*dnp = ndn;
			break;
		}
		break;


	default:
		ndn = *dnp;
		ndn.dn_cid_len = cid_len;
		switch (random() & 0x1) {
		case 0:
			for (j = 0; j < cid_len; j++)
				ndn.dn_cid[j] = random() & 0xff;
			break;
		case 1:
			for (j = 0; j < cid_len; j++)
				ndn.dn_cid[j] = '\0';
			ndn.dn_cid_len = 1;
			break;
		}
		ndn.dn_lease = htonl(time(NULL));

		/* LINTED */
		TNF_PROBE_2(work_modify, "work work_modify",
			    "work_modify%debug 'in function work'",
			    tnf_ulong, cid, *(ulong_t *)&ndn.dn_cid,
			    tnf_ulong, cid_len, ndn.dn_cid_len);

		err = modify_dd_entry(dh[table], dnp, &ndn);
		if (err != DSVC_SUCCESS && err != DSVC_COLLISION) {
			if (verbose)
				fprintf(stderr, "modify: error %d\n", err);
		}

		TNF_PROBE_1(work_modify_end, "work work_modify_end",
			    "work_modify_end%debug 'in function work'",
			    tnf_ulong, err, err);

		*dnp = ndn;
		break;
	}

	if (domalloc)
		free(ptr);

	if (wptr->isthreaded) {
		(void) mutex_unlock(&wptr->mtx);
		cond_signal(&wptr->cv);
		TNF_PROBE_2(work_end, "work", "work_end%debug 'in function "
				"work'", tnf_ulong, err, err,
				tnf_ulong, crecords, crecords);
		thr_exit(NULL);
	}
	if (dncp)
		free_dd_list(dh[table], dncp);

	TNF_PROBE_2(work_end, "work", "work_end%debug 'in function work'",
		    tnf_ulong, err, err,
		    tnf_ulong, crecords, crecords);

	return ((void *) NULL);
}

/*
 * Worker thread.
 */
static void    *
dowork(void *argp)
{
	int		i = (int)argp;
	timestruc_t	to;
	work_t		*wptr;
	dn_rec_t 	dn;

	(void) memset((char *)&dn, '\0', sizeof (dn));
	(void) mutex_lock(&mtx);
	for (; time_to_go == 0; ) {
		TNF_PROBE_1(dowork, "dowork",
			    "dowork%debug 'in function dowork'",
			    tnf_long, thread_number, i);

		to.tv_sec = time(NULL) + random() & 0x3;
		to.tv_nsec = 0;

		if (slp > 0.0) {
			to.tv_sec = time(NULL) + slp;
			to.tv_nsec = (slp - (double)((int)slp)) * 1000000000.0;
		} else if (slp < 0.0) {
			to.tv_sec = time(NULL) + abs((int)slp);
			to.tv_nsec = (slp + abs((double)((int)slp))) *
				1000000000.0;
		}
		/* give up processor */
		if (slp != 0.0) {
			(void) mutex_unlock(&mtx);
			(void) cond_timedwait(&never, &mtx, &to);
		}
		ops_outstanding++;
		(void) mutex_unlock(&mtx);

		if (spawn_helper) {
			wptr = (work_t *)malloc(sizeof (work_t));
			wptr->thread = i * 2;
			wptr->isthreaded = B_TRUE;
			(void) cond_init(&wptr->cv, USYNC_THREAD, NULL);
			(void) mutex_init(&wptr->mtx, USYNC_THREAD, NULL);
			(void) mutex_lock(&wptr->mtx);

			/* fire up helper thread */
			if (thr_create(NULL, 0, douwork ? uwork : work,
					(void *)wptr, 0, &tp[i * 2]) != 0)
				fprintf(stderr, "can't spawn lthread %d\n", i);

			/* wait for completion */
			(void) cond_wait(&wptr->cv, &wptr->mtx);
			(void) mutex_unlock(&wptr->mtx);
			(void) thr_join(tp[i * 2], NULL, NULL);
			free_work_t(wptr);
		} else {
			wptr = (work_t *)malloc(sizeof (work_t));
			wptr->isthreaded = B_FALSE;
			wptr->thread = i;
			wptr->dnp = &dn;
			if (douwork) {
				(void) uwork((void *)wptr);
			} else {
				(void) work((void *)wptr);
			}
			free_work_t(wptr);
		}
		(void) mutex_lock(&mtx);
		tops++;
		ops_outstanding--;
		TNF_PROBE_0(dowork_end, "dowork", "");
	}
	(void) mutex_unlock(&mtx);
	thr_exit(NULL);

	return ((void *) NULL);
}

/*
 * Signal handler routine. All signals handled by calling thread.
 */
/* ARGSUSED */
static void    *
sig_handle(void *arg)
{
	int		i;
	int		sig;
	sigset_t	set;
	timespec_t	ts;
	siginfo_t	si;
	int		go;
	int		oldi;
	ulong_t		minavg;
	time_t		minstime;

	(void) sigfillset(&set); /* catch all signals */

	ts.tv_sec = sample_time;
	ts.tv_nsec = 0L;

	for (;;) {
		(void) mutex_lock(&mtx);
		go = time_to_go;
		(void) mutex_unlock(&mtx);
		if (go)
			break;

		switch (sig = sigtimedwait(&set, &si, &ts)) {
		case -1:
		case SIGHUP:
			old = time(NULL);
			oldi = new = unstarted = 0;
			for (i = 0; i < threads; i++) {
				if (timp[i] == NULL)
					unstarted++;
				if (timp[i] && timp[i] < old) {
					old = timp[i];
					oldi = i;
				}
				if (timp[i] && timp[i] > new)
					new = timp[i];
			}

			if (start == 0) {
				/* toss initial sample */
				ostart = start = time(NULL);
				(void) mutex_lock(&mtx);
				otops = tops = 0;
				(void) mutex_unlock(&mtx);
				minind = 0;
			} else {
				minops[minind] = tops - otops;
				mintim[minind] = ostart;
				otops = tops;
				ostart = time(NULL);
				minind = minind + 1 > nsamples - 1 ? 0 :
				    minind + 1;
				minstime = 0;
				minavg = 0;
				for (i = 0; i < nsamples; i++) {
					if (mintim[i])
						minavg += minops[i];
					if (minstime == 0)
						minstime = mintim[i];
					else if (mintim[i] &&
					    mintim[i] < minstime)
						minstime = mintim[i];
				}

				fprintf(stderr, "%9.9d: Totops %d Curr %d "\
				    "Persec %4.2f (%4.2f) Oldest %d (%d) "\
				    "Gap %d Unstarted %d\n",
					time(NULL),
					tops,
					ops_outstanding,
					(double)tops / (double)(time(NULL)
						- start),
					(double)minavg / (double)(time(NULL)
						- minstime),
					time(NULL) - old,
					oldi,
					new - old,
					unstarted);
			}
			break;
		default:
			(void) mutex_lock(&mtx);
			time_to_go++;
			(void) mutex_unlock(&mtx);
			break;
		}
	}
	thr_exit(NULL);
	return ((void *) sig);	/* NOTREACHED */
}

int	fd[0x10000];
/*
 * open handler routine.
 */
/* ARGSUSED */
static void    *
open_handle(void *arg)
{
	int	i;

	for (;;) {
		for (i = 0; i < doopen; i++)
			fd[i] = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
		for (i = 0; i < doopen; i++)
			if (fd[i] >= 0)
				(void) close(fd[i]);
	}
	return ((void *) NULL);	/* NOTREACHED */
}
/*
 * test_dstore network[,network] worktype[,worktype] <thr_create flags>
 *	 <spawn_helper> <nlwp> <nthread> <file> <sleeptype>
 *
 * network - list of network containers, comma-separated
 * worktypes:
 *	0 - random
 *	1 - cid reads
 *	2 - cip reads
 *	3 - whole db reads
 *	4 - write read write (simulate simple test)
 *	5 - modify writes
 * sleeptypes:
 * 	N == * condwait N sec.nsec period
 * 	-N == condwait a random 1-N sec.nsec period
 */
main(int c, char **v)
{
	int		i;
	timespec_t	to;
	uint_t		flags;
	int		err;
	sigset_t	set;
	dhcp_confopt_t *dsp = NULL;
	uint32_t	query;
	dn_rec_t	dn;
	dn_rec_list_t  *dncp = NULL;
	struct rlimit   rl;
	char		*np;

#ifdef	DEBUG
	mallocctl(MTDEBUGPATTERN, 1);
	mallocctl(MTINITBUFFER, 1);
#endif				/* DEBUG */

	srandom(time(NULL));

	if (dofork)
		if (fork() != 0)
			exit(0);

	if ((err = getrlimit(RLIMIT_NOFILE, &rl)) < 0) {
		(void) fprintf(stderr, "Cannot get open file limit: %s\n",
				strerror(errno));
	}
	/* handle cases where limit is infinity */
	if (rl.rlim_cur == RLIM_INFINITY) {
		rl.rlim_cur = (rl.rlim_max == RLIM_INFINITY) ?
			OPEN_MAX : rl.rlim_max;
	}
	/* set NOFILE to unlimited */
	rl.rlim_cur = rl.rlim_max = RLIM_INFINITY;
	if ((err = setrlimit(RLIMIT_NOFILE, &rl)) < 0) {
		(void) fprintf(stderr, "Cannot set open file limit: %s\n",
				strerror(errno));
	}
	(void) enable_extended_FILE_stdio(-1, -1);

	if (c == 1) {
		(void) fprintf(stderr,
				"/*\n"\
				" * test_dstore network[,network] worktype[,"\
					"worktype] <thr_create flags>\n"\
				" *	 <spawn_helper> <nlwp> <nthread> "\
					"<file> <sleeptype>\n"\
				" *\n"\
				" * network - list of network containers, "\
					"comma-separated\n"\
				" * worktypes:\n"\
				" *	0 - random\n"\
				" *	1 - cid reads\n"\
				" *	2 - cip reads\n"\
				" *	3 - whole db reads\n"\
				" *	4 - write read write (simulate simple"\
					" test)\n"\
				" *	5 - modify writes\n"\
				" * sleeptypes:\n"\
				" * 	N == * condwait N sec.nsec period\n"\
				" * 	-N == condwait a random 1-N sec.nsec "\
					"period\n"\
				" */\n");
		return (0);
	}
	network = v[1];

	worktype = strtoul(v[2], 0L, 0L);
	flags = strtoul(v[3], 0L, 0L);
	spawn_helper = strtoul(v[4], 0L, 0L);
	if (strtoul(v[5], 0L, 0L) > 0)
		(void) thr_setconcurrency(strtoul(v[5], 0L, 0L));
	threads = strtoul(v[6], 0L, 0L);
	fl = v[7];
	if (c > 8)
		slp = atof(v[8]);

	if (douwork == 0) {
		/* Load current datastore. */
		(void) read_dsvc_conf(&dsp);
		if ((i = confopt_to_datastore(dsp, &datastore))
			!= DSVC_SUCCESS) {
			(void) fprintf(stderr, "Invalid datastore: %s\n",
					dhcpsvc_errmsg(i));
			return (EINVAL);
		}
		for (i = 0, np = strtok(network, ","); np; i++,
			np = strtok(NULL, ",")) {
			net[i].s_addr = inet_addr(np);

			err = open_dd(&dh[i], &datastore, DSVC_DHCPNETWORK, np,
					DSVC_READ | DSVC_WRITE);

			if (err != DSVC_SUCCESS) {
				(void) fprintf(stderr, "Invalid network: "\
						"%s %s\n", np,
						dhcpsvc_errmsg(err));
				return (err);
			}
			/*
			 * XXXX: bug: currently can't get the count as
			 * advertised
			 */
			(void) memset(&dn, '\0', sizeof (dn));
			DSVC_QINIT(query);
			err = lookup_dd(dh[i], B_FALSE, query, -1,
				(const void *) &dn, (void **) &dncp,
				&nrecords[i]);
			if (dncp)
				free_dd_list(dh[i], dncp);

			if (err != DSVC_SUCCESS) {
				(void) fprintf(stderr, "Bad nrecords: %s "
					"[%d]\n", dhcpsvc_errmsg(err),
					nrecords[i]);
				return (err);
			}
		}
		ntable = i;
	}
	TNF_PROBE_2(main, "main",
		    "main%debug 'in function main'",
		    tnf_ulong, threads, threads,
		    tnf_ulong, nrecords, nrecords[i]);

	(void) sigfillset(&set);

	(void) sigdelset(&set, SIGABRT);	/* allow for user abort */

	(void) thr_sigsetmask(SIG_SETMASK, &set, NULL);

	tms = threads * sizeof (thread_t);
	if (spawn_helper)
		tms *= 2;
	tp = malloc(tms);
	tms = (threads * sizeof (time_t) + 0x200) & ~(0x200 - 1);
	if (spawn_helper)
		tms *= 2;
	timp = malloc(tms);
	(void) memset((char *)timp, NULL, tms);

	(void) mutex_init(&mtx, USYNC_THREAD, 0);

	/*
	 * Create signal handling thread. XXXX: due to threads library
	 * limitations, this must currently be directly called in the main
	 * program thread.
	 */
	if ((err = thr_create(NULL, 0, sig_handle, NULL,
				THR_NEW_LWP | THR_DAEMON | THR_BOUND |
				THR_DETACHED, &sigthread)) != 0) {
		(void) fprintf(stderr,
		gettext("Cannot start signal handling thread, error: %d\n"),
			err);
		return (err);
	}
	for (i = 0; i < threads; i++)
		/* fire up monitor thread */
		if (thr_create(NULL, 0, dowork, (void *) i,
			flags, &tp[i]) != 0)
			fprintf(stderr, "can't spawn thread %d\n", i);

	/*
	 * Create open handling thread.
	 */
	if (doopen && (err = thr_create(NULL, 0, open_handle, NULL,
			THR_NEW_LWP | THR_DAEMON | THR_BOUND | THR_DETACHED,
			&opnthread)) != 0) {
		(void) fprintf(stderr,
		gettext("Cannot start open handling thread, error: %d\n"),
			err);
		return (err);
	}

	(void) mutex_lock(&mtx);
	for (; time_to_go == 0; ) {
		to.tv_sec = time(NULL) + 10;
		to.tv_nsec = 0L;
		(void) cond_timedwait(&never, &mtx, &to);
		(void) mutex_unlock(&mtx);
	}

	/*
	 * Attempt to join threads.
	 */
	for (i = 0; i < threads; i++)
		(void) thr_join(tp[i], NULL, NULL);

	(void) sleep(5);

	TNF_PROBE_0(main_end, "main", "");

	return (0);
}
