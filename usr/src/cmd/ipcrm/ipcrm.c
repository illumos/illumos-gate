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
 * Copyright (c) 1988, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/



/*
 * ipcrm - IPC remove
 *
 * Remove specified message queues,
 * semaphore sets and shared memory ids.
 */

#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/sem.h>
#include <sys/shm.h>
#include <errno.h>
#include <sys/ipc_impl.h>
#include <zone.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <locale.h>

#define	NULL_MSG	((struct msqid_ds *)NULL)
#define	NULL_SEM	((struct semid_ds *)NULL)
#define	NULL_SHM	((struct shmid_ds *)NULL)

#define	USAGE	"usage: ipcrm [-z zone] [ [-q msqid] [-m shmid] " \
"[-s semid]\n\t [-Q msgkey] [-M shmkey] [-S semkey] ... ]\n"

#define	IPC_KEYMATCH(perm, zoneid, key) \
	((perm).ipcx_key == (key) && (perm).ipcx_zoneid == (zoneid))

static char opts[] = "z:q:m:s:Q:M:S:";	/* allowable options for getopt */
extern char	*optarg;	/* arg pointer for getopt */
extern int	optind;		/* option index for getopt */

static zoneid_t zoneid;
static int zflg;

static int *idlist, nids;

static void
oops(char *thing, char *arg)
{
	char *e;

	switch (errno) {
	case ENOENT:	/* key not found */
	case EINVAL:	/* id not found */
		e = "not found";
		break;

	case EPERM:
		e = "permission denied";
		break;
	default:
		e = "unknown error";
	}

	(void) fprintf(stderr, gettext("ipcrm: %s(%s): %s\n"), thing, arg, e);
}

/* convert string to numeric key */
static key_t
getkey(char *kp)
{
	key_t k;
	char *tp;	/* will point to char that terminates strtol scan */

	if ((k = (key_t)strtoul(kp, &tp, 0)) == IPC_PRIVATE || *tp != '\0') {
		(void) fprintf(stderr, gettext("ipcrm: illegal key: %s\n"),
		    kp);
		return (0);
	}
	return (k);
}

/*
 * Gets list of all IPC ids (of a particular type) visible in the
 * caller's zone.  Returns number of ids retrieved.  On return, idlist
 * is set to point to an array of ids at least as large as the number
 * retrieved.
 */
static uint_t
getids(int (*idsfunc)(int *, uint_t, uint_t *))
{
	uint_t n;

	for (;;) {
		if (idsfunc(idlist, nids, &n) != 0)
			goto err;	/* should never happen */
		if (n <= nids)
			break;
		idlist = realloc(idlist, (nids = n) * sizeof (int));
		if (idlist == NULL)
			goto err;
	}
	return (n);

err:
	perror("ipcrm");
	exit(1);
	/* NOTREACHED */
}

static int
msggetid(char *arg)
{
	int id = atol(arg);
	struct msqid_ds64 qds;

	if (!zflg)
		return (id);

	if (msgctl64(id, IPC_STAT64, &qds) < 0) {
		oops("msgctl", arg);
		return (-1);
	}
	if (qds.msgx_perm.ipcx_zoneid != zoneid) {
		/*
		 * Not in right zone, pretend the call failed.
		 * Message should be the same as that returned if
		 * msggetid succeeds but the subsequent IPC_RMID fails
		 * with EINVAL.
		 */
		errno = EINVAL;
		oops("msgctl", arg);
		return (-1);
	}
	return (id);
}

static int
msggetkey(char *kp)
{
	key_t k;
	int id, i;
	uint_t n;
	struct msqid_ds64 qds;

	if ((k = getkey(kp)) == 0)
		return (-1);

	if (!zflg) {
		/* lookup in local zone is simple */
		if ((id = msgget(k, 0)) == -1)
			oops("msgget", kp);
		return (id);
	}

	n = getids(msgids);

	/* search for right key and zone combination */
	for (i = 0; i < n; i++) {
		id = idlist[i];
		if (msgctl64(id, IPC_STAT64, &qds) < 0)
			continue;
		if (IPC_KEYMATCH(qds.msgx_perm, zoneid, k))
			return (id);	/* found it, no need to look further */
	}
	(void) fprintf(stderr, gettext("ipcrm: unknown key: %s\n"), kp);
	return (-1);
}

static int
semgetid(char *arg)
{
	int id = atol(arg);
	struct semid_ds64 sds;
	union semun {
		int val;
		struct semid_ds64 *buf;
		ushort_t *array;
	} semarg;

	if (!zflg)
		return (id);

	semarg.buf = &sds;
	if (semctl64(id, 0, IPC_STAT64, semarg) < 0) {
		oops("semctl", arg);
		return (-1);
	}
	if (sds.semx_perm.ipcx_zoneid != zoneid) {
		/*
		 * Not in right zone, pretend the call failed.
		 * Message should be the same as that returned if
		 * semgetid succeeds but the subsequent IPC_RMID fails
		 * with EINVAL.
		 */
		errno = EINVAL;
		oops("semctl", arg);
		return (-1);
	}
	return (id);
}

static int
semgetkey(char *kp)
{
	key_t k;
	int id, i;
	uint_t n;
	struct semid_ds64 sds;
	union semun {
		int val;
		struct semid_ds64 *buf;
		ushort_t *array;
	} semarg;

	if ((k = getkey(kp)) == 0)
		return (-1);

	if (!zflg) {
		/* lookup in local zone is simple */
		if ((id = semget(k, 0, 0)) == -1)
			oops("semget", kp);
		return (id);
	}

	n = getids(semids);

	semarg.buf = &sds;
	/* search for right key and zone combination */
	for (i = 0; i < n; i++) {
		int id;
		id = idlist[i];
		if (semctl64(id, 0, IPC_STAT64, semarg) < 0)
			continue;
		if (IPC_KEYMATCH(sds.semx_perm, zoneid, k))
			return (id);	/* found it, no need to look further */
	}

	(void) fprintf(stderr, gettext("ipcrm: unknown key: %s\n"), kp);
	return (-1);
}

static int
shmgetid(char *arg)
{
	int id = atol(arg);
	struct shmid_ds64 mds;

	if (!zflg)
		return (id);

	if (shmctl64(id, IPC_STAT64, &mds) < 0) {
		oops("shmctl", arg);
		return (-1);
	}
	if (mds.shmx_perm.ipcx_zoneid != zoneid) {
		/*
		 * Not in right zone, pretend the call failed.
		 * Message should be the same as that returned if
		 * shmgetid succeeds but the subsequent IPC_RMID fails
		 * with EINVAL.
		 */
		errno = EINVAL;
		oops("shmctl", arg);
		return (-1);
	}
	return (id);
}

static int
shmgetkey(char *kp)
{
	key_t k;
	int id, i;
	uint_t n;
	struct shmid_ds64 mds;

	if ((k = getkey(kp)) == 0)
		return (-1);

	if (!zflg) {
		/* lookup in local zone is simple */
		if ((id = shmget(k, 0, 0)) == -1)
			oops("shmget", kp);
		return (id);
	}

	n = getids(shmids);

	/* search for right key and zone combination */
	for (i = 0; i < n; i++) {
		int id;
		id = idlist[i];
		if (shmctl64(id, IPC_STAT64, &mds) < 0)
			continue;
		if (IPC_KEYMATCH(mds.shmx_perm, zoneid, k))
			return (id);	/* found it, no need to look further */
	}
	(void) fprintf(stderr, gettext("ipcrm: unknown key: %s\n"), kp);
	return (-1);
}


/* convert string containing zone name or id to a numeric id */
static zoneid_t
getzone(char *arg)
{
	zoneid_t zoneid;

	if (zone_get_id(arg, &zoneid) != 0) {
		(void) fprintf(stderr, gettext("ipcrm: unknown zone: %s\n"),
		    arg);
		exit(1);
	}
	return (zoneid);
}

int
main(int argc, char **argv)
{
	int	o;		/* option flag */
	int	err;		/* error count */
	int	ipc_id;		/* id to remove */

	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);
	/*
	 * If one or more of the IPC modules is not
	 * included in the kernel, the corresponding
	 * system calls will incur SIGSYS.  Ignoring
	 * that signal makes the system call appear
	 * to fail with errno == EINVAL, which can be
	 * interpreted appropriately in oops().
	 */

	(void) signal(SIGSYS, SIG_IGN);

	/*
	 * If no -z argument is specified, only objects in the current
	 * zone can be removed with keys.
	 */
	zoneid = getzoneid();

	/*
	 * Go through the options.  The first pass looks only for -z
	 * since this option can affect the processing of keys.  The
	 * second pass looks for the other options and ignores -z.
	 */
	err = 0;
	while ((o = getopt(argc, argv, opts)) != EOF) {
		switch (o) {
		case 'z':
			zflg++;
			zoneid = getzone(optarg);
			break;

		case 'q':	/* skip the rest of the flags */
		case 'm':
		case 's':
		case 'Q':
		case 'M':
		case 'S':
			break;

		case '?':	/* anything else is an error */
		default:
			err++;
			break;
		}
	}

	if (err || (optind < argc)) {
		(void) fprintf(stderr, gettext(USAGE));
		return (err);
	}

	if (zflg > 1) {
		(void) fprintf(stderr,
		    gettext("multiple -z options not allowed\n"));
		(void) fprintf(stderr, gettext(USAGE));
		return (1);
	}

	optind = 1;	/* rewind for pass 2 */
	while ((o = getopt(argc, argv, opts)) != EOF) {
		switch (o) {
		case 'z':	/* zone identifier */
			break;

		case 'q':	/* message queue */
			if ((ipc_id = msggetid(optarg)) < 0) {
				err++;
			} else if (msgctl(ipc_id, IPC_RMID, NULL_MSG) == -1) {
				oops("msgctl", optarg);
				err++;
			}
			break;

		case 'm':	/* shared memory */
			if ((ipc_id = shmgetid(optarg)) < 0) {
				err++;
			} else if (shmctl(ipc_id, IPC_RMID, NULL_SHM) == -1) {
				oops("shmctl", optarg);
				err++;
			}
			break;

		case 's':	/* semaphores */
			if ((ipc_id = semgetid(optarg)) < 0) {
				err++;
			} else if (semctl(ipc_id, 0, IPC_RMID, NULL_SEM) ==
			    -1) {
				oops("semctl", optarg);
				err++;
			}
			break;

		case 'Q':	/* message queue (by key) */
			if ((ipc_id = msggetkey(optarg)) == -1) {
				err++;
				break;
			}
			if (msgctl(ipc_id, IPC_RMID, NULL_MSG) == -1) {
				oops("msgctl", optarg);
				err++;
			}
			break;

		case 'M':	/* shared memory (by key) */
			if ((ipc_id = shmgetkey(optarg)) == -1) {
				err++;
				break;
			}
			if (shmctl(ipc_id, IPC_RMID, NULL_SHM) == -1) {
				oops("shmctl", optarg);
				err++;
			}
			break;

		case 'S':	/* semaphores (by key) */
			if ((ipc_id = semgetkey(optarg)) == -1) {
				err++;
				break;
			}
			if (semctl(ipc_id, 0, IPC_RMID, NULL_SEM) == -1) {
				oops("semctl", optarg);
				err++;
			}
			break;
		}
	}
	return (err);
}
