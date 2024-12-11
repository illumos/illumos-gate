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
 *
 * Copyright 2024 Oxide Computer Company
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/

/*
 * ipcs - IPC status
 *
 * Examine and print certain things about
 * message queues, semaphores and shared memory.
 *
 * IPC information is obtained via msgctl64, semctl64 and shmctl64.
 * As of SunOS 5.8, the IPC identifiers are obtained from msgids(),
 * semids(), and shmids() rather than reading them from /dev/kmem.
 * This ensures that the information in each msgid_ds, semid_ds or
 * shmid_ds data structure that we obtain is complete and consistent,
 * and allows us not to be a setgid-sys isaexec process.
 */

#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/ipc_impl.h>
#include <sys/msg.h>
#include <sys/sem.h>
#include <sys/shm.h>
#include <sys/hexdump.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <grp.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <unistd.h>
#include <locale.h>
#include <langinfo.h>
#include <string.h>
#include <limits.h>
#include <project.h>
#include <zone.h>

#define	USAGE	\
	"usage: ipcs [-AabciJmopqstZ] [-D mtype] [-z zone]\n"

static char chdr[] = "T         ID      KEY        MODE        OWNER    GROUP";
						/* common header format */
static char chdr2[] = "  CREATOR   CGROUP";	/* c option header format */
static char chdr3[] = "         PROJECT";	/* J option header format */
static char opts[] = "AabciJmopqstD:z:Z";	/* getopt options */

static long	mtype;		/* -D: user-supplied message type */
static zoneid_t	zoneid;		/* -z: user-supplied zone id */

static int	bflg,		/* biggest size: */
				/*	segsz on m; qbytes on q; nsems on s */
		cflg,		/* creator's login and group names */
		Dflg,		/* dump contents of message queues */
		iflg,		/* ISM attaches */
		Jflg,		/* dump project name */
		mflg,		/* shared memory status */
		oflg,		/* outstanding data: */
				/*	nattch on m; cbytes, qnum on q */
		pflg,		/* process id's: lrpid, lspid on q; */
				/*	cpid, lpid on m */
		qflg,		/* message queue status */
		sflg,		/* semaphore status */
		tflg,		/* times: atime, ctime, dtime on m;	*/
				/*	ctime, rtime, stime on q;	*/
				/*	ctime, otime on s */
		zflg,		/* show only objects from specified zone */
		Zflg,		/* display zone name */
		err;		/* option error count */

static void hp(char, char *, struct ipc_perm64 *, int);
static void jp(struct ipc_perm64 *);
static void tp(ipc_time_t);
static void dumpmsgq(int);
static void dumpmsg(long, char *, size_t);
static zoneid_t getzone(char *);
static void printzone(zoneid_t);

int
main(int argc, char *argv[])
{
	static	int	*ids;	/* array of IPC identifiers from *ids() */
	static	uint_t	nids;	/* number of entries in ids */

	int	o;	/* option flag */
	int	id;	/* IPC identifier */
	int	i;
	uint_t	n;	/* table size */
	time_t	now;	/* date */
	char	tbuf[BUFSIZ];
	char	*dfmt;  /* date format pointer */
	char	*endptr;	/* terminator for strtol() */

	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);

	(void) memset(tbuf, 0, sizeof (tbuf));
	dfmt = nl_langinfo(_DATE_FMT);

	zoneid = getzoneid();	/* default zone id if -z and -Z not used */

	/* Go through the options and set flags. */
	while ((o = getopt(argc, argv, opts)) != EOF) {
		switch (o) {
		case 'A':
			bflg = cflg = iflg = oflg = pflg = tflg = Jflg = 1;
			break;
		case 'a':
			bflg = cflg = oflg = pflg = tflg = 1;
			break;
		case 'b':
			bflg = 1;
			break;
		case 'c':
			cflg = 1;
			break;
		case 'D':
			mtype = strtol(optarg, &endptr, 0);
			if (endptr == optarg || *endptr != '\0') {
				(void) fprintf(stderr,
				    gettext("ipcs: invalid message type: %s\n"),
				    optarg);
				err++;
				break;
			}
			Dflg = 1;
			break;
		case 'i':
			iflg = 1;
			break;
		case 'J':
			Jflg = 1;
			break;
		case 'm':
			mflg = 1;
			break;
		case 'o':
			oflg = 1;
			break;
		case 'p':
			pflg = 1;
			break;
		case 'q':
			qflg = 1;
			break;
		case 's':
			sflg = 1;
			break;
		case 't':
			tflg = 1;
			break;
		case 'z':
			zflg = 1;
			zoneid = getzone(optarg);
			break;
		case 'Z':
			Zflg = 1;
			break;
		case '?':
			err++;
			break;
		}
	}
	if (err || (optind < argc)) {
		(void) fprintf(stderr, gettext(USAGE));
		exit(1);
	}

	if ((mflg + qflg + sflg) == 0)
		mflg = qflg = sflg = 1;

	now = time(NULL);
	(void) strftime(tbuf, sizeof (tbuf), dfmt, localtime(&now));
	(void) printf(gettext("IPC status from <running system> as of %s\n"),
	    tbuf);

	/*
	 * Print Message Queue status report.
	 */
	if (qflg) {
		struct msqid_ds64 qds;

		for (;;) {
			if (msgids(ids, nids, &n) != 0) {
				perror("msgids");
				exit(1);
			}
			if (n <= nids)
				break;
			ids = realloc(ids, (nids = n) * sizeof (int));
		}

		(void) printf("%s%s%s%s%s%s%s%s\n", chdr,
		    cflg ? chdr2 : "",
		    oflg ? " CBYTES  QNUM" : "",
		    bflg ? " QBYTES" : "",
		    pflg ? " LSPID LRPID" : "",
		    tflg ? "   STIME    RTIME    CTIME " : "",
		    Jflg ? chdr3 : "",
		    Zflg ? "     ZONE" : "");

		(void) printf(gettext("Message Queues:\n"));

		for (i = 0; i < n; i++) {
			id = ids[i];
			if (msgctl64(id, IPC_STAT64, &qds) < 0)
				continue;
			/* ignore zone if -Z was used and -z wasn't */
			if ((zflg || !Zflg) &&
			    qds.msgx_perm.ipcx_zoneid != zoneid)
				continue;
			hp('q', "SRrw-rw-rw-", &qds.msgx_perm, id);
			if (oflg)
				(void) printf(" %6llu %5llu",
				    qds.msgx_cbytes, qds.msgx_qnum);
			if (bflg)
				(void) printf(" %6llu", qds.msgx_qbytes);
			if (pflg)
				(void) printf(" %5d %5d",
				    (int)qds.msgx_lspid, (int)qds.msgx_lrpid);
			if (tflg) {
				tp(qds.msgx_stime);
				tp(qds.msgx_rtime);
				tp(qds.msgx_ctime);
			}
			if (Jflg)
				jp(&qds.msgx_perm);
			if (Zflg)
				printzone(qds.msgx_perm.ipcx_zoneid);
			(void) printf("\n");
			if (Dflg)
				dumpmsgq(id);
		}
	}

	/*
	 * Print Shared Memory status report.
	 */
	if (mflg) {
		struct shmid_ds64 mds;

		for (;;) {
			if (shmids(ids, nids, &n) != 0) {
				perror("shmids");
				exit(1);
			}
			if (n <= nids)
				break;
			ids = realloc(ids, (nids = n) * sizeof (int));
		}

		if (!qflg || oflg || bflg || pflg || tflg || iflg)
			(void) printf("%s%s%s%s%s%s%s%s%s\n", chdr,
			    cflg ? chdr2 : "",
			    oflg ? " NATTCH" : "",
			    bflg ? "      SEGSZ" : "",
			    pflg ? "  CPID  LPID" : "",
			    tflg ? "   ATIME    DTIME    CTIME " : "",
			    iflg ? " ISMATTCH" : "",
			    Jflg ? chdr3 : "",
			    Zflg ? "     ZONE" : "");

		(void) printf(gettext("Shared Memory:\n"));

		for (i = 0; i < n; i++) {
			id = ids[i];
			if (shmctl64(id, IPC_STAT64, &mds) < 0)
				continue;
			/* ignore zone if -Z was used and -z wasn't */
			if ((zflg || !Zflg) &&
			    mds.shmx_perm.ipcx_zoneid != zoneid)
				continue;
			hp('m', "--rw-rw-rw-", &mds.shmx_perm, id);
			if (oflg)
				(void) printf(" %6llu", mds.shmx_nattch);
			if (bflg)
				(void) printf(" %10llu", mds.shmx_segsz);
			if (pflg)
				(void) printf(" %5d %5d",
				    (int)mds.shmx_cpid, (int)mds.shmx_lpid);
			if (tflg) {
				tp(mds.shmx_atime);
				tp(mds.shmx_dtime);
				tp(mds.shmx_ctime);
			}
			if (iflg)
				(void) printf(" %8llu", mds.shmx_cnattch);
			if (Jflg)
				jp(&mds.shmx_perm);
			if (Zflg)
				printzone(mds.shmx_perm.ipcx_zoneid);
			(void) printf("\n");
		}
	}

	/*
	 * Print Semaphore facility status.
	 */
	if (sflg) {
		struct semid_ds64 sds;
		union semun {
			int val;
			struct semid_ds64 *buf;
			ushort_t *array;
		} semarg;
		semarg.buf = &sds;

		for (;;) {
			if (semids(ids, nids, &n) != 0) {
				perror("semids");
				exit(1);
			}
			if (n <= nids)
				break;
			ids = realloc(ids, (nids = n) * sizeof (int));
		}

		if (bflg || tflg || (!qflg && !mflg))
			(void) printf("%s%s%s%s%s%s\n", chdr,
			    cflg ? chdr2 : "",
			    bflg ? " NSEMS" : "",
			    tflg ? "   OTIME    CTIME " : "",
			    Jflg ? chdr3 : "",
			    Zflg ? "     ZONE" : "");

		(void) printf(gettext("Semaphores:\n"));

		for (i = 0; i < n; i++) {
			id = ids[i];
			if (semctl64(id, 0, IPC_STAT64, semarg) < 0)
				continue;
			/* ignore zone if -Z was used and -z wasn't */
			if ((zflg || !Zflg) &&
			    sds.semx_perm.ipcx_zoneid != zoneid)
				continue;
			hp('s', "--ra-ra-ra-", &sds.semx_perm, id);
			if (bflg)
				(void) printf(" %5u", sds.semx_nsems);
			if (tflg) {
				tp(sds.semx_otime);
				tp(sds.semx_ctime);
			}
			if (Jflg)
				jp(&sds.semx_perm);
			if (Zflg)
				printzone(sds.semx_perm.ipcx_zoneid);
			(void) printf("\n");
		}
	}

	return (0);
}

/*
 * hp - common header print
 */
static void
hp(char type, char *modesp, struct ipc_perm64 *permp, int slot)
{
	int		i;	/* loop control */
	struct group	*g;	/* ptr to group group entry */
	struct passwd	*u;	/* ptr to user passwd entry */
	char		keyfield[16];

	(void) snprintf(keyfield, sizeof (keyfield), "  0x%x", permp->ipcx_key);
	(void) printf("%c %10d %-13s", type, slot, keyfield);

	for (i = 02000; i; modesp++, i >>= 1)
		(void) printf("%c", (permp->ipcx_mode & i) ? *modesp : '-');
	if ((u = getpwuid(permp->ipcx_uid)) == NULL)
		(void) printf("%9d", (int)permp->ipcx_uid);
	else
		(void) printf("%9.8s", u->pw_name);
	if ((g = getgrgid(permp->ipcx_gid)) == NULL)
		(void) printf("%9d", (int)permp->ipcx_gid);
	else
		(void) printf("%9.8s", g->gr_name);

	if (cflg) {
		if ((u = getpwuid(permp->ipcx_cuid)) == NULL)
			(void) printf("%9d", (int)permp->ipcx_cuid);
		else
			(void) printf("%9.8s", u->pw_name);
		if ((g = getgrgid(permp->ipcx_cgid)) == NULL)
			(void) printf("%9d", (int)permp->ipcx_cgid);
		else
			(void) printf("%9.8s", g->gr_name);
	}
}

/*
 * jp - project header print
 */
static void
jp(struct ipc_perm64 *permp)
{
	struct project	proj;
	char		buf[PROJECT_BUFSZ];

	if ((getprojbyid(permp->ipcx_projid, &proj, buf,
	    PROJECT_BUFSZ)) == NULL)
		(void) printf("%16ld", permp->ipcx_projid);
	else
		(void) printf("%16.15s", proj.pj_name);
}

/*
 * tp - time entry printer
 */
void
tp(ipc_time_t gmt64)
{
	struct tm *t;	/* ptr to converted time */
	time_t gmt = (time_t)gmt64;

	if (gmt && gmt64 <= UINT_MAX) {
		t = localtime(&gmt);
		(void) printf(" %2d:%2.2d:%2.2d",
		    t->tm_hour, t->tm_min, t->tm_sec);
	} else {
		(void) printf("%9s", gettext(" no-entry"));
	}
}

/* Round up to a sizeof (size_t) boundary */
#define	SZROUND(x)	(((x) + sizeof (size_t) - 1) & ~(sizeof (size_t) - 1))

/*
 * dumpmsgq - dump all messages on a message queue
 */
void
dumpmsgq(int msqid)
{
	static struct msgsnap_head *buf = NULL;
	static size_t bufsize;

	struct msgsnap_mhead *mhead;
	size_t i;

	/* allocate the minimum required buffer size on first time through */
	if (buf == NULL)
		buf = malloc(bufsize = sizeof (struct msgsnap_head));

	/*
	 * Fetch all messages specified by mtype from
	 * the queue while leaving the queue intact.
	 */
	for (;;) {
		if (msgsnap(msqid, buf, bufsize, mtype) != 0) {
			/*
			 * Don't complain; either the user does not have
			 * read permission on msqid or msqid was deleted.
			 */
			return;
		}
		if (bufsize >= buf->msgsnap_size) {
			/* we collected all of the messages */
			break;
		}
		/* The buffer is too small; allocate a bigger buffer */
		buf = realloc(buf, bufsize = buf->msgsnap_size);
	}

	/*
	 * Process each message in the queue (there may be none).
	 * The first message header starts just after the buffer header.
	 */
	mhead = (struct msgsnap_mhead *)(buf + 1);
	for (i = 0; i < buf->msgsnap_nmsg; i++) {
		size_t mlen = mhead->msgsnap_mlen;

		dumpmsg(mhead->msgsnap_mtype, (char *)(mhead + 1), mlen);

		/* advance to next message header */
		/* LINTED alignment */
		mhead = (struct msgsnap_mhead *)
		    ((caddr_t)(mhead + 1) + SZROUND(mlen));
	}
}

/*
 * dumpmsg - dump one message from a message queue.
 */
void
dumpmsg(long type, char *msg, size_t msgsize)
{
	const uint8_t *data = (const uint8_t *)msg;
	hexdump_t h;

	(void) printf(gettext("  message type %ld, size %lu\n"),
	    type, (ulong_t)msgsize);

	hexdump_init(&h);
	hexdump_set_indent(&h, 4);
	(void) hexdump_fileh(&h, data, msgsize, HDF_DEFAULT, stdout);
	hexdump_fini(&h);
}

/* convert string containing zone name or id to a numeric id */
static zoneid_t
getzone(char *arg)
{
	zoneid_t zoneid;

	if (zone_get_id(arg, &zoneid) != 0) {
		(void) fprintf(stderr,
		    gettext("ipcs: unknown zone: %s\n"), arg);
		exit(1);
	}
	return (zoneid);
}

static void
printzone(zoneid_t id)
{
	char zone_name[ZONENAME_MAX];

	if (getzonenamebyid(id, zone_name, sizeof (zone_name)) < 0)
		(void) printf("%9d", (int)id);
	else
		(void) printf("%9.8s", zone_name);
}
