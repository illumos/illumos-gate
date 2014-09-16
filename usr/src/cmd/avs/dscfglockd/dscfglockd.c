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

#include <signal.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>
#include <string.h>
#include <memory.h>
#include <sys/param.h>
#include <sys/pathconf.h>
#include <netdir.h>
#include <netconfig.h>
#include <sys/sockio.h>
#include <net/if.h>
#include <sys/resource.h>
#include <stdio.h>
#include <errno.h>
#include <assert.h>
#include <locale.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/unistat/spcs_s.h>
#include <sys/unistat/spcs_s_u.h>
#include <sys/unistat/spcs_errors.h>

#include <sys/nsctl/cfg.h>
#include <sys/nsctl/cfg_lockd.h>

#ifdef DEBUG
#define	DPF(m)		if (debug) (void) fprintf m
#else
#define	DPF(m)
#endif

#ifdef	TTY_MESSAGES
#define	CLOSE_FD	3
#else
#define	CLOSE_FD	0
#endif

#define	MAX_LOCKQ	1024
#define	MAX_DAEMONS	1024
#define	MAX_LOCAL	1024
#define	MAX_UNLOCK	32
#define	MAX_TIMEOUTS	3
#define	TIMEOUT_SECS	5

static char program[] = "dscfglockd";
static int debug;
static int lstate;
static int msgtrace;
static FILE *debugfile = NULL;

struct lock_req {
	cfglockd_t	type;	/* read or write */
	pid_t	pid;		/* pid of read locker or local writer */
	daemonaddr_t	remote;	/* remote machine requesting write lock */
	int		state;	/* for write locks */
	int32_t		order;	/* who gets priority? */
} lock_queue[MAX_LOCKQ];

struct unlock_s {
	pid_t	pid;		/* pid of locker */
	uint8_t seq;		/* seq number of last lock request */
} unlock_buf[MAX_UNLOCK];

int next_req;
int32_t order;

#define	lock_wanted	lock_queue[0]
long	ticker	= 1l;

#define	ALIVE		0x10
#define	READ_LOCK	0x11
#define	WRITE_LOCK	0x12
#define	UNLOCK		0x13
#define	GRANTED		0x14

int next_q;

struct {
	cfglockd_t	type;
	int		nholders;
	int		state;
	daemonaddr_t	holder;
	struct lockdaemon	*remote_daemon;
	pid_t		holding_pid[MAX_LOCAL];
} the_lock;

daemonaddr_t	thishost;
daemonaddr_t	localhost;

#define	STATE_CLEAR	0
#define	STATE_ASKED	1
#define	STATE_OKAYED	2
#define	STATE_WANTS	3
#define	lockdaemon_dead(ldp)	((ticker - (ldp)->timeout) > MAX_TIMEOUTS)
#define	CRIT_BEGIN()	(void) sighold(SIGALRM)
#define	CRIT_END()	(void) sigrelse(SIGALRM)

#define	NORMAL_UNLOCK	0
#define	FORCE_UNLOCK	1

struct lockdaemon {
	daemonaddr_t	host;
	int	up;
	long	timeout;
	int	inuse;
	int	state;
	int32_t	order;
} daemon_list[MAX_DAEMONS];

unsigned short	lock_port = CFG_SERVER_PORT;
int	lock_soc = 0;
int	pf_inet = PF_INET;
#define	dp_addr(p)	inet_ntoa(((struct sockaddr_in *)p)->sin_addr)

#define	MAXIFS 32

static char *
lockd_type(cfglockd_t type)
{
	switch (type) {
	case LOCK_NOTLOCKED:	return "NotLocked";
	case LOCK_READ:		return "Read";
	case LOCK_WRITE:	return "Write";
	case LOCK_LOCKED:	return "Locked";
	case LOCK_LOCKEDBY:	return "LockedBy";
	case LOCK_STAT:		return "Stat";
	case LOCK_ACK:		return "Ack";
	default:		return "*unknown*";
	}
}

static char *
lockd_state(int state)
{
	switch (state) {
	case STATE_CLEAR:	return "Clear";
	case STATE_ASKED:	return "Asked";
	case STATE_OKAYED:	return "Okayed";
	case STATE_WANTS:	return "Wants";
	default:		return "*unknown*";
	}
}

static char *
lockd_msg(int message)
{
	switch (message) {
	case ALIVE:		return "Alive";
	case READ_LOCK:		return "ReadLock";
	case WRITE_LOCK:	return "WriteLock";
	case UNLOCK:		return "Unlock";
	case GRANTED:		return "Granted";
	default:		return lockd_type((cfglockd_t)message);
	}
}

/*
 * The following is stolen from autod_nfs.c
 */
static void
getmyaddrs(struct ifconf *ifc)
{
	int sock;
	int numifs;
	char *buf;
	int family;

	ifc->ifc_buf = NULL;
	ifc->ifc_len = 0;

#ifdef AF_INET6
	family = AF_INET6;
#else
	family = AF_INET;
#endif
	if ((sock = socket(family, SOCK_DGRAM, 0)) < 0) {
#ifdef DEBUG
		perror("getmyaddrs(): socket");
#endif
		return;
	}

	if (ioctl(sock, SIOCGIFNUM, (char *)&numifs) < 0) {
#ifdef DEBUG
		perror("getmyaddrs(): SIOCGIFNUM");
#endif
		numifs = MAXIFS;
	}

	buf = (char *)malloc(numifs * sizeof (struct ifreq));
	if (buf == NULL) {
#ifdef DEBUG
		(void) fprintf(stderr, "getmyaddrs(): malloc failed\n");
#endif
		(void) close(sock);
		return;
	}

	ifc->ifc_buf = buf;
	ifc->ifc_len = numifs * sizeof (struct ifreq);

	if (ioctl(sock, SIOCGIFCONF, (char *)ifc) < 0) {
#ifdef DEBUG
		perror("getmyaddrs(): SIOCGIFCONF");
#endif
	}

	(void) close(sock);
}

struct ifconf *ifc;

static int
cmp_addr(daemonaddr_t *a, daemonaddr_t *b)
{
	int rc;
	rc = memcmp(&(a->sin_addr), &(b->sin_addr), sizeof (a->sin_addr));
	DPF((stderr, "compare %s %hu with", dp_addr(a), a->sin_port));
	DPF((stderr, " %s %hu = %d\n", dp_addr(b), b->sin_port, rc));
	return (rc);
}

static int
addr_is_holder(int32_t order)
{
	return ((the_lock.nholders > 0) && the_lock.remote_daemon != NULL &&
	    (order == the_lock.remote_daemon->order));
}

static int
islocalhost(daemonaddr_t *host)
{
	int n;
	struct sockaddr_in *s1, *s2;
	struct ifreq *ifr;
	int retval = 0;

	ifr = ifc->ifc_req;
	n = ifc->ifc_len / sizeof (struct ifreq);
	s1 = host;
	s2 = NULL;
	for (; n > 0; n--, ifr++) {
		if (ifr->ifr_addr.sa_family != AF_INET)
			continue;

		/* LINTED pointer alignment */
		s2 = (struct sockaddr_in *)&ifr->ifr_addr;

		if (memcmp((char *)&s2->sin_addr,
		    (char *)&s1->sin_addr, sizeof (s1->sin_addr)) == 0) {
			retval = 1;
			/* it's me */
			break;
		}
	}
	return (retval);
}

static void
send_lockmsg(int cmd, pid_t pid, daemonaddr_t *dp, uint8_t seq)
{
	struct lock_msg message_buf;
	int rc;

	if (msgtrace && debugfile) {
		time_t t = time(0);
		(void) fprintf(debugfile, "%19.19s send %-9.9s to   %s\n",
		    ctime(&t), lockd_msg(cmd), dp_addr(dp));
	}
	DPF((stderr, "send %d to %s port %hu\n", cmd,
	    dp_addr(dp), dp->sin_port));
	message_buf.message = cmd;
	message_buf.pid = pid;
	message_buf.order = order;
	message_buf.seq = seq;
	do {
		rc = sendto(lock_soc, &message_buf, sizeof (message_buf), 0,
		    (struct sockaddr *)dp, sizeof (struct sockaddr));
	} while (rc == -1 && errno == EINTR);
	if (rc == -1)
		spcs_log("cfglockd", NULL, "sendto rc -1 errno %d", errno);
}

/*
 * send an alive message to all configured daemons so that they can tell
 * us if they are holding a write lock.
 */

static void
send_aliveall()
{
	struct lockdaemon *ldp;
	int i;
	for (i = 0, ldp = daemon_list; i < MAX_DAEMONS; i++, ldp++) {
		if (ldp->inuse == 0)
			break;
		send_lockmsg(ALIVE, (pid_t)0, &(ldp->host), 0);
	}
}

/* find the lock daemon structure for a give daemon address */

static struct lockdaemon *
find_lockdaemon(daemonaddr_t *d)
{
	struct lockdaemon *ldp;
	int i;
	for (i = 0, ldp = daemon_list; i < MAX_DAEMONS; i++, ldp++) {
		if (ldp->inuse == 0)
			break;
		if (cmp_addr(&(ldp->host), d) == 0)
			return (ldp);
	}
	return (NULL);
}

/*
 * a messge has been received from daemon, note this and if the daemon
 * was previously dead  and we have the write lock tell it that we do.
 */

static void
daemon_alive(daemonaddr_t *daemon, int32_t order)
{
	struct lockdaemon *ldp;
	int i;

	for (i = 0, ldp = daemon_list; i < MAX_DAEMONS; i++, ldp++) {
		if (ldp->inuse == 0)
			break;
		if (cmp_addr(&(ldp->host), daemon) == 0) {
			ldp->order = order;
			ldp->timeout = ticker;
			if (ldp->up == 0) {
				spcs_log("cfglockd", NULL,
				    "daemon restarted on %s\n",
				    dp_addr(daemon));
				DPF((stderr, "daemon restarted on %s\n",
				    dp_addr(daemon)));
				ldp->up = 1;
				goto come_up;
			}
			return;
		}
	}
	/* new daemon has announced itself */
	if (i < MAX_DAEMONS) {
		DPF((stderr, "new daemon on %s\n", dp_addr(daemon)));
		spcs_log("cfglockd", NULL,
		    "new daemon on %s\n", dp_addr(daemon));
		ldp->host = *daemon;
		ldp->inuse = 1;
		ldp->timeout = ticker;
		ldp->order = order;
	} else {
		/* problem, more daemons than expected */
		i++;
	}
come_up:
	if (the_lock.type == LOCK_WRITE && the_lock.remote_daemon == NULL)
		send_lockmsg(WRITE_LOCK, (pid_t)0, daemon, 0);
}

static void
delete_queue_entry(struct  lock_req *req)
{
	int i;

	for (i = (req - lock_queue); i++ < next_req; req++)
		*req = *(req+1);
	next_req--;
}

static void
take_lock(int ackmessage)
{
	send_lockmsg(ackmessage, (pid_t)0, &lock_wanted.remote, 0);
	delete_queue_entry(lock_queue);
}

static void
check_for_write_lock()
{
	struct lockdaemon *ldp;
	int i;
	int	wait = 0;

	DPF((stderr, "check for lock\n"));
	if (lock_wanted.state != STATE_ASKED)
		return;
	for (i = 0, ldp = daemon_list; i < MAX_DAEMONS; i++, ldp++) {
		if (ldp->inuse == 0)
			break;
		if (ldp->up && ldp->state != STATE_OKAYED) {
			wait = 1;
			break;
		}
	}
	if (wait == 0 && lock_wanted.type == LOCK_WRITE) {
		the_lock.type = LOCK_WRITE;
		the_lock.holding_pid[0] = lock_wanted.pid;
		the_lock.nholders = 1;
		the_lock.state = STATE_CLEAR;
		take_lock(LOCK_LOCKED);
	}
}

static void
lock_granted(daemonaddr_t *da)
{
	struct lockdaemon *ldp;

	if ((ldp = find_lockdaemon(da)) != NULL) {
		/* if we already own the lock, throw the msg away */
		if (the_lock.remote_daemon == NULL &&
		    the_lock.type == LOCK_WRITE) {
			return;
		}

		/*
		 * If the current lock isn't a write lock and we're not
		 * asking for one
		 * -OR-
		 * The current lock is a write lock and it's not owned by us
		 * -THEN-
		 * send back an unlocked message.
		 */
		if ((the_lock.type != LOCK_WRITE &&
		    the_lock.state != STATE_ASKED) ||
		    (the_lock.type == LOCK_WRITE &&
		    the_lock.remote_daemon != NULL)) {
			send_lockmsg(UNLOCK, (pid_t)0, &(ldp->host), 0);
			return;
		}
		ldp->state = STATE_OKAYED;
	}
	check_for_write_lock();
}

static int
try_lock()
{
	struct lockdaemon *ldp;
	int i;

	switch (the_lock.type) {
	case LOCK_READ:
		if (lock_wanted.type == LOCK_READ) {
			i = the_lock.nholders++;
			the_lock.holding_pid[i] = lock_wanted.pid;
			the_lock.state = STATE_CLEAR;
			DPF((stderr, "increment read lockers to %d\n",
			    the_lock.nholders));
			take_lock(LOCK_LOCKED);
			break;
		}
		/* write lock has to wait */
		break;
	case LOCK_WRITE:
		/* lock has to wait until write lock is cleared */
		break;
	case LOCK_NOTLOCKED:
		if (lock_wanted.type == LOCK_READ) {
			DPF((stderr, "local locker, 1 lock holder\n"));
			the_lock.holding_pid[0] = lock_wanted.pid;
			the_lock.nholders = 1;
			the_lock.type = LOCK_READ;
			the_lock.state = STATE_CLEAR;
			the_lock.remote_daemon = NULL;
			take_lock(LOCK_LOCKED);
			return (1);
		}
		if (islocalhost(&lock_wanted.remote)) {
			DPF((stderr, "local locker, take write lock\n"));
			/* tell everyone I'm locking */
			if (lock_wanted.state != STATE_ASKED) {
				for (i = 0, ldp = daemon_list; i < MAX_DAEMONS;
				    i++, ldp++) {
					if (ldp->inuse == 0)
						break;
					ldp->state = STATE_ASKED;
					send_lockmsg(WRITE_LOCK, (pid_t)0,
					    &(ldp->host), 0);
				}
			}
			lock_wanted.state = STATE_ASKED;
			check_for_write_lock();
			the_lock.remote_daemon = NULL;
			the_lock.state = STATE_ASKED;
			return (0);
		} else {
			DPF((stderr, "remote locker, take write lock\n"));
			the_lock.type = LOCK_WRITE;
			the_lock.holder = lock_wanted.remote;
			the_lock.nholders = 1;
			the_lock.remote_daemon =
			    find_lockdaemon(&the_lock.holder);
			the_lock.state = STATE_CLEAR;
			/* okay to remote */
			take_lock(GRANTED);
		}
		break;
	default:
		DPF((stderr, "weird lock type held - %d\n", the_lock.type));
		the_lock.type = LOCK_NOTLOCKED;
		break;
	}
	return (0);
}

static void
process_queue()
{
	if (next_req < 1)
		return;		/* no locks queued */
	while (try_lock())
		;
}

static int
lock_sort(const void *a, const void *b)
{
	struct lock_req *left = (struct lock_req *)a;
	struct lock_req *right = (struct lock_req *)b;

	return (left->order - right->order);
}

static void
queue_lock(cfglockd_t type, struct lock_msg *msg, daemonaddr_t *addr)
{
	int	i;
	struct lock_req *lrp;
	struct lockdaemon *ldp;

	/* first check if new lock matches current lock */
	if (the_lock.type == type && addr_is_holder(msg->order)) {
		/* remote daemon missed locked message */
		send_lockmsg(GRANTED, (pid_t)0, addr, msg->seq);
		return;
	}

	/* next search queue to check for duplicate */
	for (i = 0, lrp = lock_queue; i++ < next_req; lrp++) {
		if (lrp->type == type && lrp->pid == msg->pid &&
		    cmp_addr(addr, &(lrp->remote)) == 0)
			return;

	}

	/*
	 * It's a new lock request.  Are we in the middle of
	 * obtaining one for ourselves?
	 */

	if (the_lock.type == LOCK_NOTLOCKED && the_lock.state == STATE_ASKED) {
		/* did a higher priority request just come in? */
		if (msg->order < order) {
			/* requeue our request */
			the_lock.state = STATE_CLEAR;
			lock_wanted.state = STATE_CLEAR;

			/* let the other lockds know */
			for (i = 0, ldp = daemon_list; i < MAX_DAEMONS;
			    i++, ldp++) {
				if (ldp->inuse == 0)
					break;
				if (ldp->up && ldp->state == STATE_OKAYED) {
					send_lockmsg(UNLOCK, (pid_t)0,
					    &(ldp->host), 0);
				}
			}
		}
	}


	lrp = lock_queue;
	lrp += (next_req++);
	lrp->type = type;
	lrp->pid = msg->pid;
	lrp->state = STATE_CLEAR;
	lrp->order = msg->order;
	if (addr) {
		lrp->remote = *addr;
	}

	if (next_req > 1)
		qsort(lock_queue, next_req, sizeof (lock_queue[0]), lock_sort);

	if (the_lock.type != LOCK_WRITE)
		process_queue();
}

static void
lock_stat()
{
	char *lt = "Unknown";
	struct lockdaemon *ldp;
	int i;

	switch (the_lock.type) {
	case LOCK_NOTLOCKED:
		lt = "not locked";
		break;
	case LOCK_READ:
		lt = "read locked";
		break;
	case LOCK_WRITE:
		lt = "write locked";
		break;
	}
	spcs_log("cfglockd", NULL, "Lock is %s (%d)", lt, the_lock.type);
	spcs_log("cfglockd", NULL, "There are %d holders of the lock",
	    the_lock.nholders);
	if (the_lock.nholders > 0) {
		for (i = 0; i < the_lock.nholders; i++)
			spcs_log("cfglockd", NULL, "holding_pid[%d] = %6d", i,
			    the_lock.holding_pid[i]);
	}
	spcs_log("cfglockd", NULL, "holder daemon was %s port %hu, remote %x",
	    dp_addr(&the_lock.holder), the_lock.holder.sin_port,
	    the_lock.remote_daemon);
	spcs_log("cfglockd", NULL, "Lock queue, %d requests", next_req);
	for (i = 0; i < next_req; i++) {
		spcs_log("cfglockd", NULL, "request %d type %d order %d", i,
		    lock_queue[i].type, lock_queue[i].order);
		spcs_log("cfglockd", NULL, "  client %s port %hu, pid %d",
		    dp_addr(&lock_queue[i].remote),
		    lock_queue[i].remote.sin_port, lock_queue[i].pid);
	}
	spcs_log("cfglockd", NULL, "Daemon list");

	for (i = 0, ldp = daemon_list; i < MAX_DAEMONS; i++, ldp++) {
		if (ldp->inuse == 0)
			break;
		spcs_log("cfglockd", NULL, "daemon %d, %s port %hu", i,
		    dp_addr(&ldp->host), ldp->host.sin_port);
		spcs_log("cfglockd", NULL,
		    "  up %d timeout %ld missed %d state %d\n", ldp->up,
		    ldp->timeout, ticker - ldp->timeout, ldp->state);
	}
}

static int
is_duplicate(cfglockd_t type, pid_t pid, uint8_t seq)
{
	struct unlock_s *bufp;
	int i;

	if (!pid) {
		return (0);
	}

	for (i = 0, bufp = unlock_buf; bufp->pid && i < MAX_UNLOCK;
	    i++, bufp++) {
		if (bufp->pid == pid && bufp->seq == seq) {
			/* throw message away */
#ifdef DEBUG
			spcs_log("cfglockd", NULL,
			    "duplicate '%d' request received from %d",
			    type, pid);
#endif
			return (1);
		}
	}

	/* add it to the list */
	bcopy(unlock_buf, &unlock_buf[ 1 ],
	    sizeof (unlock_buf) - sizeof (struct unlock_s));
	(*unlock_buf).pid = pid;
	(*unlock_buf).seq = seq;

	return (0);
}

static void
local_lock(cfglockd_t type, struct lock_msg *msg, daemonaddr_t *client)
{
	if (is_duplicate(type, msg->pid, msg->seq)) {
		if (the_lock.remote_daemon == NULL &&
		    (the_lock.type == LOCK_WRITE ||
		    the_lock.type == LOCK_READ) &&
		    the_lock.holding_pid[0] == msg->pid) {
			send_lockmsg(LOCK_LOCKED, (pid_t)0, client, msg->seq);
		}
	} else {
		queue_lock(type, msg, client);
	}
}

static void
remote_lock(struct sockaddr_in *remote, struct lock_msg *msg)
{
	/* make sure remote knows we are alive */
	send_lockmsg(ALIVE, (pid_t)0, remote, 0);

	/* clear out pid as it is meaningless on this node */
	msg->pid = (pid_t)0;

	queue_lock(LOCK_WRITE, msg, (daemonaddr_t *)remote);
}

static void
unqueue_lock(daemonaddr_t *d, pid_t pid)
{
	int	i;
	struct lock_req *lrp, *xrp;
	int diff;

	/* search queue to delete ungranted locks */
	for (i = 0, xrp = lrp = lock_queue; i++ < next_req; lrp++) {
		*xrp = *lrp;
		diff = 0;
		if (pid != (pid_t)0 && lrp->pid != pid)
			diff = 1;
		if (d != NULL && cmp_addr(d, &(lrp->remote)) != 0)
			diff = 1;
		if (!diff)
			continue;

		xrp++;
	}
	next_req = xrp - lock_queue;
}

static void
xxunlock()
{
	DPF((stderr, "** UNLOCK **\n"));
	the_lock.remote_daemon = NULL;
	the_lock.type = LOCK_NOTLOCKED;
	the_lock.nholders = 0;
	the_lock.state = STATE_CLEAR;
	process_queue();
}


static void
local_unlock(pid_t pid, uint8_t seq, int method)
{
	struct lockdaemon *ldp;
	int i;

	if (method == NORMAL_UNLOCK && is_duplicate(LOCK_NOTLOCKED, pid, seq)) {
		return;
	}

	if (the_lock.type == LOCK_READ) {
		/* delete reference to pid of reading process */
		for (i = 0; i < the_lock.nholders; i++) {
			if (the_lock.holding_pid[i] == pid) {
				DPF((stderr, "decrement lockers from %d\n",
				    the_lock.nholders));
				--the_lock.nholders;
				break;
			}
		}
		for (; i < the_lock.nholders; i++) {
			the_lock.holding_pid[i] = the_lock.holding_pid[i+1];
		}
		if (the_lock.nholders > 0)
			return;
	} else {
		/* LOCK_WRITE */
		if (pid != the_lock.holding_pid[0])
			return;
		the_lock.holding_pid[0] = (pid_t)0;
		for (i = 0, ldp = daemon_list; i < MAX_DAEMONS; i++, ldp++) {
			if (ldp->inuse == 0)
				break;
			if (ldp->up)
				send_lockmsg(UNLOCK, (pid_t)0, &(ldp->host), 0);
		}
	}
	xxunlock();
}

static void
remote_unlock(int32_t order, daemonaddr_t *d)
{
	int	i;
	struct lock_req *lrp;

	DPF((stderr, "remote unlock from %s ", dp_addr(d)));
	DPF((stderr, "when %s holds lock\n", dp_addr(&the_lock.holder)));

	/* search queue to check for ungranted lock */
	for (i = 0, lrp = lock_queue; i++ < next_req; lrp++) {
		if (lrp->type == LOCK_WRITE &&
		    cmp_addr(d, &(lrp->remote)) == 0) {
			delete_queue_entry(lrp);
			return;
		}

	}
	if (addr_is_holder(order)) {
		xxunlock();
	}
}

static void
lockedby(daemonaddr_t *d, uint8_t seq)
{
	DPF((stderr, "lockby enquiry from %s ", dp_addr(d)));
	switch (the_lock.type) {
	case LOCK_NOTLOCKED:
		send_lockmsg(LOCK_NOTLOCKED, (pid_t)0, d, seq);
		break;
	case LOCK_READ:
		send_lockmsg(LOCK_READ, the_lock.holding_pid[0], d, seq);
		break;
	case LOCK_WRITE:
		send_lockmsg(LOCK_WRITE, the_lock.holding_pid[0], d, seq);
		break;
	}
}

/* ARGSUSED */
static void
keepalive(int signo)
{
	int i;
	struct lock_req *locker;
	struct lockdaemon *ldp;

	DPF((stderr, "keepalive...\n"));
	ticker++;

	/*
	 * tell any other daemon that has a lock request in our queue that
	 * this daemon is still alive.
	 */

	for (i = 0, locker = lock_queue; i < next_req; i++, locker++) {
		if (locker->pid == 0)	/* remote lock request */
			send_lockmsg(ALIVE, (pid_t)0, &(locker->remote), 0);
	}

	/*
	 * if a remote daemon holds the lock, check it is still alive and
	 * if the remote daemon is sent it a grant message in case the
	 * remote daemon missed our original grant.
	 */

	if (the_lock.remote_daemon) {
		if (lockdaemon_dead(the_lock.remote_daemon)) {
			DPF((stderr, "lock owner died\n"));
			the_lock.remote_daemon->up = 0;
			xxunlock();
		} else {
			send_lockmsg(GRANTED, (pid_t)0, &the_lock.holder, 0);
		}
	}

	/*
	 * check for response from daemons preventing this daemon
	 * from taking a write lock by not sending a grant message.
	 * if the remote daemon is alive send another lock request,
	 * otherwise mark it as dead.
	 * send alive message to any live remote daemons if this
	 * daemon has the write lock.
	 */
	if (lstate) {
		(void) printf("\nlock: %s\n", lockd_type(the_lock.type));
		(void) printf("    no. holders: %d\n", the_lock.nholders);
		(void) printf("    hold addr  : %s\n", the_lock.remote_daemon?
		    dp_addr(the_lock.remote_daemon): "0.0.0.0");
		(void) printf("    holding pid:");
		for (i = 0; i < the_lock.nholders; i++) {
			(void) printf(" %ld", the_lock.holding_pid[ i ]);
		}
		(void) printf("\n");
	}
	for (i = 0, ldp = daemon_list; i < MAX_DAEMONS; i++, ldp++) {
		if (ldp->inuse == 0)
			break;

		if (lstate) {
			(void) printf("%-15.15s ", dp_addr(&ldp->host));
			(void) printf("%-4.4s ", ldp->up? "up" : "down");
			(void) printf("%5ld ", ldp->timeout);
			(void) printf("%-10.10s ", lockd_state(ldp->state));
			(void) printf("%6d\n", ldp->order);
		}

		if (ldp->state == STATE_ASKED) {
			if (lockdaemon_dead(ldp)) {
				ldp->up = 0;
				ldp->state = STATE_CLEAR;
				continue;
			}
			send_lockmsg(WRITE_LOCK, (pid_t)0, &(ldp->host), 0);
			continue;
		}
		if (the_lock.type == LOCK_WRITE &&
		    the_lock.remote_daemon == NULL)
			send_lockmsg(ALIVE, (pid_t)0, &(ldp->host), 0);
	}
}

static void
dispatch(struct lock_msg *mp, daemonaddr_t *host)
{
	int message = mp->message;
	int localhost;

	localhost = islocalhost(host);
	if (msgtrace && debugfile) {
		time_t t = time(0);
		if (localhost) {
			(void) fprintf(debugfile,
			    "%19.19s recv %-9.9s from %s (%ld)\n", ctime(&t),
			    lockd_msg(message), dp_addr(host), mp->pid);
		} else {
			(void) fprintf(debugfile,
			    "%19.19s recv %-9.9s from %s order %d (%ld)\n",
			    ctime(&t), lockd_msg(message), dp_addr(host),
			    mp->order, mp->pid);
		}
	}
	DPF((stderr, "received message %d\n", message));
	DPF((stderr, "from %s port %hu\n", dp_addr(host), host->sin_port));
	if (!localhost)
		daemon_alive(host, mp->order);
	else
		mp->order = order;
	switch (message) {
	case ALIVE:
		DPF((stderr, "received ALIVE %s\n", dp_addr(host)));
		/* do nothing, general "not localhost" code above does this */
		break;
	case UNLOCK:
		DPF((stderr, "received UNLOCK\n"));
		remote_unlock(mp->order, host);
		break;
	case GRANTED:
		DPF((stderr, "received GRANTED\n"));
		lock_granted(host);
		break;
	case WRITE_LOCK:
		DPF((stderr, "received WRITE_LOCK\n"));
		assert(!localhost);
		remote_lock(host, mp);
		break;
	case READ_LOCK:
	case LOCK_READ:
		DPF((stderr, "received READ_LOCK\n"));
		assert(localhost);
		local_lock(LOCK_READ, mp, host);
		break;
	case LOCK_WRITE:
		DPF((stderr, "received LOCK_WRITE\n"));
		assert(localhost);
		local_lock(LOCK_WRITE, mp, host);
		break;
	case LOCK_NOTLOCKED:
		DPF((stderr, "received LOCK_NOTLOCKED\n"));
		send_lockmsg(LOCK_ACK, (pid_t)0, host, mp->seq);
		if (the_lock.type != LOCK_NOTLOCKED) {
			local_unlock(mp->pid, mp->seq, NORMAL_UNLOCK);
		}
		break;
	case LOCK_LOCKEDBY:
		lockedby(host, mp->seq);
		break;
	case LOCK_STAT:
		lock_stat();
		break;
	case LOCK_ACK:
		/* throw message away -- this is an error to receive */
		break;
	}
}

/*
 * unqueue any locks asked for by pid and unlock any locks held by pid.
 */

static void
purge_pid(pid_t pid)
{
	DPF((stderr, "purge locks for %ld\n", pid));
	unqueue_lock(NULL, pid);
	if (the_lock.type != LOCK_NOTLOCKED)
		local_unlock(pid, 0, FORCE_UNLOCK);
}

/*
 * Check for exit or exec of client processes.
 * The lock protecting the processes pid in the lockfile will
 * be removed by the kernel when a client exits or execs.
 */

static void
check_for_dead()
{
	int i, x;
	pid_t pid;

	for (i = 0; (x = cfg_filelock(i, 0)) != CFG_LF_EOF; i++) {
		if (x == CFG_LF_AGAIN)
			continue; /* can't take lock, must be still alive */
		cfg_readpid(i, &pid);
		cfg_writepid(i, (pid_t)0);
		(void) cfg_fileunlock(i);
		if (pid != (pid_t)0)
			purge_pid(pid);
	}
}

static void
build_daemon_list(char *cf_file, int exe)
{
	FILE *fp;
	char	host[1024];
	int	port;
	int	i;
	struct	hostent *hp;
	struct lockdaemon *ldp;

	if ((hp = gethostbyname("localhost")) == NULL) {
		(void) fprintf(stderr, "%s: Can't find hostent for %s\n",
		    program, "localhost");
		spcs_log("cfglockd", NULL, "couldn't find localhost");
		exit(1);
	}

	(void) memcpy(&(localhost.sin_addr.s_addr), *(hp->h_addr_list),
	    sizeof (localhost.sin_addr));
	if (cf_file == NULL) {
		(void) endhostent();
		return;
	}
	if (exe) {
		if ((fp = popen(cf_file, "r")) == NULL) {
			perror(cf_file);
			(void) fprintf(stderr,
			    "%s: Can't open config program\n", program);
			spcs_log("cfglockd", NULL, "couldn't read config");
			exit(1);
		}
	} else {
		if ((fp = fopen(cf_file, "r")) == NULL) {
			perror(cf_file);
			(void) fprintf(stderr, "%s: Can't open config file\n",
			    program);
			spcs_log("cfglockd", NULL, "couldn't read config");
			exit(1);
		}
	}
	ldp = daemon_list;
	while ((i = fscanf(fp, "%s %d\n", host, &port)) != EOF) {
		if (host[0] == '#')	/* line starting with # are comments */
			continue;
		if (i == 1) {
			port = lock_port;
		} else {
			if (strcmp(host, "localhost") == 0) {
				lock_port = port;
				continue;
			}
		}

		if ((hp = gethostbyname(host)) == NULL) {
			(void) fprintf(stderr,
			    "%s: Can't find hostent for %s\n", program, host);
			continue;
		}

		(void) memcpy(&(ldp->host.sin_addr.s_addr), *(hp->h_addr_list),
		    sizeof (ldp->host.sin_addr));
		DPF((stderr, "daemon: %s\t%s\n",
		    inet_ntoa(ldp->host.sin_addr), hp->h_name));
		if (islocalhost(&(ldp->host))) {
			DPF((stderr, "is an alias for this host, skipping\n"));
			continue;
		}
		ldp->host.sin_port = htons((short)port);
		ldp->host.sin_family = hp->h_addrtype;
		ldp->inuse = 1;
		ldp->up = 1;
		ldp++;
	}
	if (exe)
		(void) pclose(fp);
	else
		(void) fclose(fp);
	(void) endhostent();
}

static void
usage()
{
	(void) fprintf(stderr,
	    gettext("usage: %s [-d] [-f file]|[-e program]\n"), program);
	exit(1);
}

static void
unexpected(int sig)
{
	spcs_log("cfglockd", NULL, "pid %d unexpected signal %d, ignoring",
	    getpid(), sig);
}

static void
term(int sig)
{
	(void) unlink(CFG_PIDFILE);
	spcs_log("cfglockd", NULL, "pid %d terminate on signal %d", getpid(),
	    sig);
	exit(0);
}

static void
init(int argc, char *argv[])
{
#if defined(_SunOS_5_6) || defined(_SunOS_5_7) || defined(_SunOS_5_8)
	struct rlimit rl;
#endif
	int	c, i, x;
	int	rc;
	char	*cp = NULL;
	struct	itimerval	tv;
	struct	timeval		tp;
	socklen_t len = sizeof (thishost);
	int	exe = 0;
	pid_t	pid;
	FILE	*fp;

	lstate = (getenv("LOCKD_STATE") != NULL);
	msgtrace = (getenv("LOCKD_MSG") != NULL);

	/*
	 * Fork off a child that becomes the daemon.
	 */

#ifndef TTY_MESSAGES
	if ((rc = fork()) > 0)
		exit(0);
	else if (rc < 0) {
		spcs_log("cfglockd", NULL, "can't fork %d", errno);
		(void) fprintf(stderr, gettext("dscfglockd: cannot fork: %s\n"),
		    strerror(errno));
		exit(1);
	}
#endif

	/*
	 * In child - become daemon.
	 */

#if !defined(_SunOS_5_6) && !defined(_SunOS_5_7) && !defined(_SunOS_5_8)
	/* use closefrom(3C) from PSARC/2000/193 when possible */
	closefrom(CLOSE_FD);
#else
	(void) getrlimit(RLIMIT_NOFILE, &rl);
	for (i = CLOSE_FD; i < rl.rlim_max; i++)
		(void) close(i);
#endif

#ifdef DEBUG
#ifndef	TTY_MESSAGES
	(void) open("/dev/console", O_WRONLY|O_APPEND);
	(void) dup(0);
	(void) dup(0);
#endif
#endif
	(void) close(0);

	if (msgtrace || lstate) {
		debugfile = fopen("/var/tmp/dscfglockd.out", "a");
		if (debugfile) {
			time_t t = time(0);
			setbuf(debugfile, (char *)0);
			(void) fprintf(debugfile, "%19.19s dscfglockd start\n",
			    ctime(&t));
		}
	}

	(void) setpgrp();
	spcs_log("cfglockd", NULL, "new lock daemon, pid %d", getpid());

	/*
	 * Catch as unexpected all signals apart from SIGTERM.
	 */

	for (i = 1; i < _sys_nsig; i++)
		(void) sigset(i, unexpected);
	(void) sigset(SIGTERM, term);

	for (i = 0; (c = getopt(argc, argv, "df:e:")) != EOF; i++) {
		switch (c) {
		case 'd':
			debug = 1;
			break;
		case 'e':
			exe = 1;
			if (cp) {
				usage();
			}
			cp = optarg;
			break;
		case 'f':
			if (cp) {
				usage();
			}
			cp = optarg;
			break;
		default:
			usage();
			break;
		}
	}

	ifc = (struct ifconf *)malloc(sizeof (struct ifconf));
	if (ifc == NULL) {
		perror(CFG_PIDFILE);
		DPF((stderr, "Can't open pid file\n"));
		exit(1);
	}
	(void) memset((char *)ifc, 0, sizeof (struct ifconf));
	getmyaddrs(ifc);

	/*
	 * if (lockdaemonalive()) {
	 *	(void) fprintf(stderr, "%s: %s\n", program,
	 *		gettext("There is already a live lockdaemon"));
	 *	exit(1);
	 * }
	 */
	if ((fp = fopen(CFG_PIDFILE, "w")) == NULL) {
		perror(CFG_PIDFILE);
		DPF((stderr, "Can't open pid file\n"));
		exit(1);
	}
	(void) fprintf(fp, "%ld\n", getpid());
	(void) fclose(fp);

	/* order should be set to node number within cluster */
	order = cfg_iscluster();
	cfg_lfinit();

	if (!order) {
		(void) gettimeofday(&tp, NULL);
		srand48(tp.tv_usec);
		order = lrand48();
		if (debugfile) {
			(void) fprintf(debugfile, "WARNING: order number "
			    "is 0 -- changing randomly to %d\n", order);
		}
	}
	c = 0;
	for (i = 0; (x = cfg_filelock(i, 0)) != CFG_LF_EOF; i++) {
		if (x == CFG_LF_AGAIN) {
			cfg_readpid(i, &pid);
			if (c++ == 0)
				spcs_log("cfglockd", NULL,
				    "init .dscfg.lck slot %d pid %d locked",
				    i, pid);
			DPF((stderr, "client process %ld still alive\n", pid));
			continue; /* can't take lock, must be still alive */
		}
		cfg_writepid(i, 0);
		(void) cfg_fileunlock(i);
	}

	tv.it_interval.tv_sec = TIMEOUT_SECS;
	tv.it_interval.tv_usec = 0;
	tv.it_value = tv.it_interval;

	bzero(unlock_buf, sizeof (unlock_buf));
	next_q = 0;
	build_daemon_list(cp, exe);
	if ((lock_soc = socket(pf_inet, SOCK_DGRAM, 0)) < 0) {
		(void) fprintf(stderr, "%s: %s\n", program,
		    gettext("failed to create socket"));
		perror("socket");
		spcs_log("cfglockd", NULL, "couldn't create socket");
		exit(1);
	}
	thishost.sin_family = AF_INET;
	thishost.sin_addr.s_addr = INADDR_ANY;
	thishost.sin_port = htons(lock_port);
	rc = bind(lock_soc, (struct sockaddr *)&thishost, sizeof (thishost));
	if (rc < 0) {
		perror("bind");
		spcs_log("cfglockd", NULL, "couldn't bind");
		exit(1);
	}
	if (getsockname(lock_soc, (struct sockaddr *)&thishost, &len) < 0)
		perror("getsockname");
	send_aliveall();
	(void) sigset(SIGALRM, keepalive);
	(void) setitimer(ITIMER_REAL, &tv, NULL);
	/*
	 * wait 2 time outs before allowing a lock to find if someone else
	 * currently has the lock.
	 */
}

#ifdef lint
int
lintmain(int argc, char *argv[])
#else
int
main(int argc, char *argv[])
#endif
{
	struct lock_msg message_buf;
	daemonaddr_t from;
	int addrlen;
	int rc;
	int x = 1;		/* kludge to stop warnings from compiler */

	init(argc, argv);
	CRIT_BEGIN();
	while (x) {
		CRIT_END();
		addrlen = sizeof (from);
		DPF((stderr, "begin recvfrom\n"));
		rc = recvfrom(lock_soc, &message_buf, sizeof (message_buf),
		    0, (struct sockaddr *)&from, &addrlen);
		DPF((stderr, "end recvfrom rc = %d\n", rc));
		CRIT_BEGIN();
		if (rc == sizeof (message_buf))
			dispatch(&message_buf, &from);
		else
			check_for_write_lock();

		/* if we own the lock, check to see if the process died */
		if (the_lock.type != LOCK_NOTLOCKED &&
		    the_lock.remote_daemon == NULL)
			check_for_dead();
	}
	CRIT_END();
	return (0);
}
