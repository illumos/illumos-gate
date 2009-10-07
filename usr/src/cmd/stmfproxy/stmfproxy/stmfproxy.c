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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <errno.h>
#include <syslog.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/stat.h>
#include <sys/sdt.h>
#include <signal.h>
#include <fcntl.h>
#include <libnvpair.h>
#include <libstmf.h>
#include <door.h>
#include <pthread.h>
#include <libscf.h>
#include <locale.h>
#include <sys/stmf_ioctl.h>
#include <sys/pppt_ioctl.h>
#include <libstmfproxy.h>

#define	PPPT_NODE	"/devices/pseudo/pppt@0:pppt"
#define	USAGE	"Usage: %s [-d][-f][-n nodeid] nodename\n" \
		"Note: nodename must be the same on both nodes\n"


/*
 * static functions
 */
static void daemonInit(void);
static void killHandler();
static int postMsg(uint_t nelem, uchar_t *aluaMsg);


/*
 * globals
 */
void *t_handle;			/* transport handle */
char aluaNode[256];		/* one of the two alua peers */
char myNode[256];		/* this hostname */
int log_debug = 0;
int fore_ground = 0;
int proxy_hdl;
pt_ops_t *pt_ops;

/*
 * killHandler
 *
 * Terminates this process on SIGQUIT, SIGINT, SIGTERM
 */
/* ARGSUSED */
static void
killHandler(int sig)
{
	exit(0);
}

/*
 * doorHandler
 *
 * Recieve data from the local proxy port provider and relay
 * it to the peer node.
 */
/* ARGSUSED */
void
doorHandler(
	void		*cookie,
	char		*args,
	size_t		alen,
	door_desc_t	*ddp,
	uint_t		ndid)
{
	uint32_t result = 0;

	if (ddp != NULL || ndid != 0) {
		syslog(LOG_DAEMON|LOG_WARNING,
		    "descriptor passed to door %p %d", ddp, ndid);
		result = EINVAL;
	}

	if (args == NULL || alen == 0) {
		syslog(LOG_DAEMON|LOG_WARNING,
		    "empty message passed to door %p %d", args, alen);
		result = EFAULT;
	}

	if (result == 0)
		result = postMsg((uint_t)alen, (uchar_t *)args);
	(void) door_return((char *)&result, sizeof (result), NULL, 0);

	syslog(LOG_DAEMON|LOG_WARNING, "door_return FAILED %d", errno);
	exit(errno);
}

static int
postMsg(uint_t nelem, uchar_t *aluaMsg)
{
	uint32_t buflen;
	uchar_t *buf;
	int ret = 0;
	int ns;

	if (t_handle == NULL) {
		syslog(LOG_DAEMON|LOG_WARNING,
		    "postMsg() no transport handle");
		exit(1);
	}

	buf = malloc(nelem + sizeof (buflen));

	buflen = htonl(nelem);	/* length in network byte order */
	bcopy(&buflen, buf, sizeof (buflen));
	bcopy(aluaMsg, buf + sizeof (buflen), nelem);

	ns = pt_ops->stmf_proxy_send(t_handle, buf, nelem + sizeof (buflen));
	if (ns != nelem + sizeof (buflen)) {
		ret = errno;
		if (ret == 0)
			ret = ENOTTY;	/* something bogus */
		syslog(LOG_DAEMON|LOG_CRIT, "send() call failed: %d", ret);
	}
	free(buf);
	return (ret);
}

/*
 * Multi-thread the data path from the peer node to the local
 * proxy port provider. During discover, there can be a large
 * burst of messages from the peer node proportional to the number
 * of LUs. Multiple threads allow these messages to be processed
 * simultaneously.
 */
typedef struct pppt_drv_queue {
	struct pppt_drv_queue	*next;
	uint32_t		buflen;
	uchar_t			*buf;
} pppt_drv_queue_t;

pppt_drv_queue_t *pq_head = NULL;
pthread_mutex_t pq_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t pq_cond = PTHREAD_COND_INITIALIZER;
int pq_num_threads = 0;
int pq_avail_threads = 0;

/*ARGSUSED*/
void *
push_to_drv(void *arg)
{
	pppt_drv_queue_t	*pq;
	int rc;

	(void) pthread_mutex_lock(&pq_mutex);
	pq_num_threads++;
	(void) pthread_mutex_unlock(&pq_mutex);
	for (;;) {
		(void) pthread_mutex_lock(&pq_mutex);
		while (pq_head == NULL) {
			pq_avail_threads++;
			(void) pthread_cond_wait(&pq_cond, &pq_mutex);
			pq_avail_threads--;
		}
		pq = pq_head;
		pq_head = pq->next;
		pq->next = NULL;
		(void) pthread_mutex_unlock(&pq_mutex);
		/* Relay the message to the local kernel */
		rc = stmfPostProxyMsg(proxy_hdl, (void *)pq->buf, pq->buflen);
		if (rc != STMF_STATUS_SUCCESS) {
			/* XXX die ? */
			syslog(LOG_DAEMON|LOG_CRIT, "ioctl failed - %d", errno);
		}
		free(pq->buf);
		free(pq);
	}
	/*NOTREACHED*/
	return (NULL);
}

/*
 * Receive data from peer and queue it up for the proxy driver.
 */
int message_count = 0;
static void
relay_peer_msg()
{
	uint32_t		buflen;
	pppt_drv_queue_t	*pq, *tmpq;
	pthread_t		tid;
	int			rc;


	/* first receive the length of the message */
	if ((pt_ops->stmf_proxy_recv(t_handle, (uchar_t *)&buflen,
	    sizeof (buflen))) != sizeof (buflen)) {
		syslog(LOG_DAEMON|LOG_WARNING, "recv() call failed: %d",
		    errno);
		exit(1);
	}

	pq = malloc(sizeof (*pq));
	pq->next = NULL;
	pq->buflen = ntohl(buflen);
	pq->buf = malloc(pq->buflen+4);
	if (log_debug) {
		syslog(LOG_DAEMON|LOG_DEBUG,
		    "recvMsg: size of buffer - %d", (int)pq->buflen);
	}

	if ((pt_ops->stmf_proxy_recv(t_handle, pq->buf, pq->buflen)) !=
	    pq->buflen) {
		syslog(LOG_DAEMON|LOG_WARNING, "recv() call failed: %d",
		    errno);
		exit(1);
	}

	/* Eat the first message from peer */
	if (message_count++ == 0) {
		*(pq->buf+pq->buflen) = 0;
		free(pq->buf);
		free(pq);
		return;
	}

	/* Queue the message to the driver */
	(void) pthread_mutex_lock(&pq_mutex);
	if (pq_head == NULL) {
		pq_head = pq;
	} else {
		/* add to the tail */
		tmpq = pq_head;
		while (tmpq->next != NULL)
			tmpq = tmpq->next;
		tmpq->next = pq;
	}

	/* Make sure there is a thread to service this message */
	if (pq_avail_threads) {
		/* wake an available thread */
		(void) pthread_cond_signal(&pq_cond);
		(void) pthread_mutex_unlock(&pq_mutex);
	} else {
		/* no threads available, create a new thread */
		(void) pthread_mutex_unlock(&pq_mutex);
		rc = pthread_create(&tid, NULL, push_to_drv, NULL);
		if (rc != 0) {
			syslog(LOG_DAEMON|LOG_WARNING,
			    "pthread_create() call failed: %d", rc);
			if (pq_num_threads == 0) {
				/* never created a thread */
				exit(rc);
			}
		}
	}
}

/*
 * Initialization for a daemon process
 */
static void
daemonInit(void)
{
	pid_t	pid;
	int	devnull;

	if (fore_ground)
		return;

	if ((pid = fork()) < 0) {
		syslog(LOG_DAEMON|LOG_CRIT, "Could not fork(). Exiting");
		exit(1);
	} else if (pid != 0) {
		/*
		 * XXX
		 * Simple approach for now - let the service go online.
		 * Later, set-up a pipe to the child and wait until the
		 * child indicates service is setup.
		 */
		exit(SMF_EXIT_OK);
	}

	(void) setsid();

	(void) chdir("/");

	(void) umask(0);


	devnull = open("/dev/null", O_RDWR);
	if (devnull < 0) {
		syslog(LOG_DAEMON|LOG_CRIT,
		    "Failed to open /dev/null. Exiting");
		exit(1);
	}

	(void) dup2(devnull, STDIN_FILENO);
	(void) dup2(devnull, STDOUT_FILENO);
	(void) dup2(devnull, STDERR_FILENO);
	(void) close(devnull);
}

void
daemon_fini(int rc)
{
	/*
	 * XXX inform the parent about the service state
	 * For now, just exit on error.
	 */
	if (rc != 0)
		exit(rc);
}

static int
open_proxy_driver()
{
	int drv_door_fd;
	int stmf_ret;

	/*
	 * Create communication channel for the driver.
	 */
	if ((drv_door_fd = door_create(doorHandler, NULL, 0)) < 0) {
		perror("door_create");
		syslog(LOG_DAEMON|LOG_DEBUG,
		    "could not create door: errno %d", errno);
		return (SMF_EXIT_ERR_FATAL);
	}

	stmf_ret = stmfInitProxyDoor(&proxy_hdl, drv_door_fd);
	if (stmf_ret != STMF_STATUS_SUCCESS) {
		perror("pppt ioctl: door install");
		syslog(LOG_DAEMON|LOG_DEBUG,
		    "could not install door: errno %d", errno);
		return (SMF_EXIT_ERR_FATAL);
	}

	return (SMF_EXIT_OK);
}

/*
 * daemon entry
 *
 * parse arguments
 * create resources to talk to child
 * if !foreground
 *    daemonize, run as child
 * open proxy driver
 * install door in proxy driver
 * create socket
 * if server-side
 *     bind socket
 * if !foreground
 *    inform parent things aok
 * if parent
 *    exit(SMF_EXIT_OK)
 * if server-side
 *    accept
 * if client-side
 *    connect
 * send hello
 * recv hello
 * loop on recieve
 * XXX anyway to check in envp that we are started by SMF?
 */
int
main(int argc, char *argv[])
{
	struct	sockaddr_in sin;
	int	rc;
	struct sigaction 	act;
	sigset_t		sigmask;
	int	c;
	int	node = 0;
	int	node_override = 0;
	int	server_node = 0;
	int	server_match = 0;
	extern char *optarg;
	int stmf_ret;

	(void) setlocale(LC_ALL, "");
	openlog("stmfproxy", LOG_PID, LOG_DAEMON);
	(void) setlogmask(LOG_UPTO(LOG_INFO));

	while ((c = getopt(argc, argv, "dfn:")) != -1) {
		switch (c) {
			case 'd':
				(void) setlogmask(LOG_UPTO(LOG_DEBUG));
				log_debug = 1;
				break;
			case 'f':
				fore_ground = 1;
				break;
			case 'n':
				node_override = 1;
				node = atoi(optarg);
				break;
			default:
				/*
				 * Should never happen from smf
				 */
				(void) fprintf(stderr, USAGE, argv[0]);
				exit(SMF_EXIT_ERR_CONFIG);
				break;
		}
	}
	/*
	 * After the options, only the server argument should remain.
	 */
	if (optind != argc-1) {
		(void) fprintf(stderr, USAGE, argv[0]);
		exit(SMF_EXIT_ERR_CONFIG);
	}
	(void) strcpy(aluaNode, argv[optind]);
	syslog(LOG_DAEMON|LOG_DEBUG, "aluaNode %s", aluaNode);
	if (gethostname(myNode, 255)) {
		perror("gethostname");
		exit(1);
	}
	if ((inet_aton(aluaNode, &sin.sin_addr)) == 0) {
		/*
		 * Not ipaddr, try hostname match.
		 */
		server_match = (strcmp(aluaNode, myNode)) ? 0 : 1;
	} else {
		/*
		 * see if this is our ip address
		 */
		(void) fprintf(stderr, "Sorry, cannot use ip adress format\n");
	}
	if (server_match) {
		server_node = 1;
		if (!node_override)
			node = 1;
	}


	/*
	 * Allow SIGQUIT, SIGINT and SIGTERM signals to terminate us
	 */
	act.sa_handler = killHandler;
	(void) sigemptyset(&act.sa_mask);
	act.sa_flags = 0;

	/* Install the signal handler */
	(void) sigaction(SIGQUIT, &act, NULL);
	(void) sigaction(SIGINT, &act, NULL);
	(void) sigaction(SIGTERM, &act, NULL);
	(void) sigaction(SIGHUP, &act, NULL);

	/* block all signals */
	(void) sigfillset(&sigmask);

	/* unblock SIGQUIT, SIGINT, SIGTERM */
	(void) sigdelset(&sigmask, SIGQUIT);
	(void) sigdelset(&sigmask, SIGINT);
	(void) sigdelset(&sigmask, SIGTERM);
	(void) sigdelset(&sigmask, SIGHUP);

	(void) sigprocmask(SIG_SETMASK, &sigmask, NULL);

	/* time to go backstage */
	daemonInit();

	if ((rc = open_proxy_driver()) != 0)
		daemon_fini(rc);

	if ((rc = stmf_proxy_transport_init("sockets", &pt_ops)) != 0)
		daemon_fini(rc);

	/*
	 * Establish connection
	 *
	 * At this point, the parent has exited and the service
	 * is online. But there are no real proxy services until
	 * this connect call succeeds. That could take a long time if
	 * the peer node is down.
	 */
	t_handle = pt_ops->stmf_proxy_connect(server_node, aluaNode);
	if (t_handle == NULL) {
		syslog(LOG_DAEMON|LOG_WARNING,
		    "socket() call failed: %d", errno);
		exit(1);
	}

	/* The first message is a greeting */
	(void) postMsg((uint_t)strlen(myNode)+1, (uchar_t *)myNode);
	/* Read the greeting from peer node */
	relay_peer_msg();
	/*
	 * Set the alua state in stmf. No need to keep
	 * the device open since the proxy driver has a reference.
	 */
	stmf_ret = stmfSetAluaState(B_TRUE, node);
	if (stmf_ret != STMF_STATUS_SUCCESS) {
		syslog(LOG_DAEMON|LOG_CRIT, "stmf ioctl failed - %x", stmf_ret);
		exit(1);
	}

	/* service is online */
	daemon_fini(0);

	/*
	 * Loop relaying data from the peer daemon to the local kernel.
	 * Data coming from the local kernel is handled asynchronously
	 * by the door server.
	 */
	for (;;) { /* loop forever */
		relay_peer_msg();
	}
}
