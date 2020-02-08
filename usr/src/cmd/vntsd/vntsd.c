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

/*
 * VNTSD main
 *
 * VNTSD takes the following options:
 * -i	<device instance>
 *	VCC device instance to use, e.g. virtual-console-concentrator@0.
 *	Required option.
 * -p	<ip address>
 *	IP address VNTSD listens to.
 * -d
 *	Do not daemonize. This is only available in a DEBUG build.
 * -t	timeout for inactivity 0 = indefinite
 * -A	enable Authorization checking. Mutually exclusive with -p.
 */

#include <stdio.h>
#include <stdio_ext.h>
#include <sys/types.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <time.h>
#include <netinet/in.h>
#include <thread.h>
#include <signal.h>
#include <fcntl.h>
#include <ctype.h>
#include <libintl.h>
#include <locale.h>
#include <syslog.h>
#include <sys/socket.h>
#include <netdb.h>
#include "vntsd.h"
#include "chars.h"

#if !defined(TEXT_DOMAIN)	/* Should be defined by cc -D */
#define	TEXT_DOMAIN "SYS_TEST"	/* Use this only if it weren't. */
#endif

/* global variables */

#ifdef DEBUG
int vntsddbg = 0x8;
#endif

#define	MINUTE		60

#define	VNTSD_INVALID_LISTEN_ADDR	    ((in_addr_t)-1)

#define	LOCALHOST_IPv4	"127.0.0.1"
#define	LOCALHOST_IPv6	"::1"

static vntsd_t *vntsdp;


static void vntsd_exit(void);
/* Signal handler for SIGINT, SIGKILL and SIGHUP */
static void
exit_sig_handler(int sig)
{

	D1(stderr, "t@%d exit_sig_handler%d \n", thr_self(), sig);

	if (thr_self() != vntsdp->tid) {
		/* not main thread, pass to main thread */
		(void) thr_kill(vntsdp->tid, sig);
	} else {
		exit(0);
	}
}

/*
 * Before a thread reads in client's input, it attaches to vntsd timer so that
 * it can be waken up if a client does not access the connection for
 * VNTSD_INPUT_TIMEOUT(10) minutes.
 */

/* attach a thread to timer */
int
vntsd_attach_timer(vntsd_timeout_t *tmop)
{
	int	rv;

	if (vntsdp->timeout == 0) {
		return (VNTSD_SUCCESS);
	}

	(void) mutex_lock(&vntsdp->tmo_lock);
	rv = vntsd_que_append(&vntsdp->tmoq, (void *)tmop);
	(void) mutex_unlock(&vntsdp->tmo_lock);
	return (rv);
}

/* detach a thread from timer */
int
vntsd_detach_timer(vntsd_timeout_t *tmop)
{
	int	rv;

	if (vntsdp->timeout == 0) {
		return (VNTSD_SUCCESS);
	}

	(void) mutex_lock(&vntsdp->tmo_lock);
	rv = vntsd_que_rm(&vntsdp->tmoq, (void *)tmop);
	(void) mutex_unlock(&vntsdp->tmo_lock);

	return (rv);
}

/* check threadd's timeout */
static boolean_t
chk_timeout(vntsd_timeout_t *tmop)
{
	tmop->minutes++;

	if (tmop->minutes == vntsdp->timeout) {
		/* wake up the thread */
		tmop->clientp->status |= VNTSD_CLIENT_TIMEOUT;
		(void) thr_kill(tmop->tid, SIGALRM);
	}

	/* return false to walk the queue */
	return (B_FALSE);
}

/* reset timer */
static boolean_t
reset_timeout(vntsd_timeout_t *tmop, thread_t tid)
{
	if (tmop->tid == tid) {
		tmop->minutes = 0;
	}
	/* return false to walk the queue */
	return (B_FALSE);
}

void
vntsd_reset_timer(thread_t tid)
{
	if (vntsdp->timeout == 0) {
		return;
	}

	(void) mutex_lock(&vntsdp->tmo_lock);
	(void) vntsd_que_find(vntsdp->tmoq, (compare_func_t)reset_timeout,
	    (void*)tid);
	(void) mutex_unlock(&vntsdp->tmo_lock);
}

/*
 * When alarm goes off, wake up timeout threads. Alarm is set off every
 * minutes.
 */
static void
vntsd_alarm_sig_handler(int sig)
{
	static thread_t main_thread = 0;

	D1(stderr, "t@%d alarm signal %d\n", thr_self(), sig);
	if (vntsdp->timeout == 0) {
		DERR(stderr, "t@%d alarm signal should not recv %d\n",
		    thr_self(), sig);
		return;
	}


	if (main_thread == 0) {
		/* initialize thread id  */
		main_thread = thr_self();
	} else if (main_thread != thr_self()) {
		/* get signal because thread is timeout */
		return;
	}

	/* in main thread */
	(void) mutex_lock(&vntsdp->tmo_lock);

	/* wake up timeout threads */
	(void) vntsd_que_walk(vntsdp->tmoq, (el_func_t)chk_timeout);
	(void) mutex_unlock(&vntsdp->tmo_lock);

	/* reset alarm */
	(void) alarm(MINUTE);
}

/* got a  SIGUSER1 siginal */
static void
vntsd_sig_handler(int sig)
{
	char err_msg[VNTSD_LINE_LEN];

	(void) snprintf(err_msg, sizeof (err_msg), "sig_handler() sig=%d",
	    sig);

	if (sig != SIGUSR1) {
		vntsd_log(VNTSD_STATUS_SIG, err_msg);
	}
}

/* vntsd exits */
static void
vntsd_exit(void)
{
	D1(stderr, "t@%d vntsd_exit\n", thr_self());

	(void) mutex_lock(&vntsdp->lock);

	if (vntsdp->timeout > 0) {
		/* cancel the timer */
		(void) alarm(0);
	}
	/* delete all  groups */
	vntsd_free_que(&vntsdp->grouppq, (clean_func_t)vntsd_clean_group);

	/* close control port */
	(void) close(vntsdp->ctrl_fd);

	assert(vntsdp->tmoq == NULL);
	(void) mutex_unlock(&vntsdp->lock);

	/* clean up vntsdp */
	(void) mutex_destroy(&vntsdp->tmo_lock);
	(void) mutex_destroy(&vntsdp->lock);
	free(vntsdp);
	closelog();
}

/*
 * vntsd_help()
 * print out valid command line options
 */
static void
vntsd_help(void)
{
	(void) fprintf(stderr, gettext("Usage: vntsd -i <VCC device instance> "
	    "[-p <listen address>] [-t <timeout in minutes>] [-A]\n"));
}

/*
 * get_listen_ip_addr()
 * check for a valid control domain ip address in format of xxx.xxx.xxx.xxx.
 * if ip address is valid and is assigned to this host, return ip address
 * or else return VNTSD_INVALID_LISTEN_ADDR.
 */
static in_addr_t
get_listen_ip_addr(char *listen_addr)
{
	char host_name[MAXPATHLEN];
	in_addr_t addr;
	struct addrinfo hints;
	struct addrinfo *res, *infop;
	int err;
	struct sockaddr_in *sa;

	if (gethostname(host_name, MAXPATHLEN) != 0) {
		syslog(LOG_ERR, "Can not get host name!");
		return (VNTSD_INVALID_LISTEN_ADDR);
	}

	if ((int)(addr = inet_addr(listen_addr)) == -1)
		/* bad IP address format */
		return (VNTSD_INVALID_LISTEN_ADDR);

	bzero(&hints, sizeof (hints));
	hints.ai_family = PF_INET;
	hints.ai_socktype = SOCK_STREAM;

	err = getaddrinfo(host_name, NULL, &hints, &res);
	if (err != 0) {
		syslog(LOG_ERR, "getaddrinfo failed: %s", gai_strerror(err));
		return (VNTSD_INVALID_LISTEN_ADDR);
	}

	infop = res;
	while (infop != NULL) {
		/* LINTED E_BAD_PTR_CAST_ALIGN */
		sa = (struct sockaddr_in *)infop->ai_addr;
		if (sa->sin_addr.s_addr == addr) {
			/* ip address found */
			freeaddrinfo(res);
			return (addr);
		}
		infop = infop->ai_next;
	}

	/* ip address not found */
	freeaddrinfo(res);
	return (VNTSD_INVALID_LISTEN_ADDR);
}

#ifdef DEBUG
#define	DEBUG_OPTIONS	"d"
#else
#define	DEBUG_OPTIONS	""
#endif

int
main(int argc, char ** argv)
{
	char	    *path;
	struct	    pollfd poll_drv[1];
	struct	    sigaction act;
	struct	    rlimit rlim;
	char	    *listen_addr = NULL;
	pid_t	    pid;
	int	    i;
	int	    option;
	int	    sz;
	int	    fd;
	int	    n;

	/* internationalization */
	(void) setlocale(LC_MESSAGES, "");
	(void) textdomain(TEXT_DOMAIN);
	vntsd_init_esctable_msgs();

	/* initialization */
	bzero(&act, sizeof (act));

	/*
	 * ensure that we can obtain sufficient file descriptors for all
	 * the accept() calls when a machine contains many domains.
	 */
	(void) getrlimit(RLIMIT_NOFILE, &rlim);
	if (rlim.rlim_cur < rlim.rlim_max)
		rlim.rlim_cur = rlim.rlim_max;
	if (setrlimit(RLIMIT_NOFILE, &rlim) < 0)
		vntsd_log(VNTSD_STATUS_CONTINUE, "Unable to increase file "
		    "descriptor limit.");
	(void) enable_extended_FILE_stdio(-1, -1);

	vntsdp = calloc(1, sizeof (vntsd_t));
	if (vntsdp == NULL) {
		vntsd_log(VNTSD_ERR_NO_MEM, "main:vntsdp");
		exit(1);
	}

	vntsdp->ctrl_fd = -1;
	vntsdp->devinst = NULL;

	(void) mutex_init(&vntsdp->lock, USYNC_THREAD|LOCK_ERRORCHECK, NULL);
	(void) mutex_init(&vntsdp->tmo_lock, USYNC_THREAD|LOCK_ERRORCHECK,
	    NULL);

	/* get CLI options */
	while ((option = getopt(argc, argv, "i:t:p:A"DEBUG_OPTIONS)) != EOF) {
		switch (option) {
#ifdef DEBUG
		case 'd':
			vntsdp->options |= VNTSD_OPT_DAEMON_OFF;
			break;
#endif
		case 'i':
			vntsdp->devinst = optarg;
			break;
		case 'p':
			listen_addr = optarg;
			break;

		case 't':
			n = sscanf(optarg, "%d", &(vntsdp->timeout));
			if (n  != 1) {
				vntsdp->timeout = -1;
			}
			break;

		case 'A':
			/*
			 * This option enables authorization checking of the
			 * user for the console(s) being accessed. As the
			 * authorization checking can be done only for a local
			 * client process, it requires that vntsd listen only
			 * on the loopback address. It means while this option
			 * is enabled, vntsd cannot listen on either INADDR_ANY
			 * or a specific ip address and thus the telnet client
			 * must also run on the local machine in order to
			 * connect to vntsd. The '-p' option if specified while
			 * this option is enabled, will be ignored and the auth
			 * checking takes precedence forcing vntsd to listen on
			 * the loopback interface.
			 */
			vntsdp->options |= VNTSD_OPT_AUTH_CHECK;
			break;

		default:
			vntsd_help();
			exit(1);
		}
	}

	if ((vntsdp->devinst == NULL) || (vntsdp->timeout == -1)) {
		vntsd_help();
		exit(1);
	}

	if (listen_addr == NULL || strcmp(listen_addr, "localhost") == 0 ||
	    strcmp(listen_addr, LOCALHOST_IPv4) == 0 ||
	    strcmp(listen_addr, LOCALHOST_IPv6) == 0) {
		/* by default listen on loopback interface */
		vntsdp->ip_addr.s_addr = htonl(INADDR_LOOPBACK);
	} else if ((vntsdp->options & VNTSD_OPT_AUTH_CHECK) != 0) {
		vntsd_log(VNTSD_STATUS_AUTH_ENABLED,
		    "Listen address ignored as authorization checking "
		    "is enabled");
		vntsdp->ip_addr.s_addr = htonl(INADDR_LOOPBACK);
	} else if (strcmp(listen_addr, "any") == 0) {
		vntsdp->ip_addr.s_addr = htonl(INADDR_ANY);
	} else {
		vntsdp->ip_addr.s_addr = get_listen_ip_addr(listen_addr);
		if (vntsdp->ip_addr.s_addr == VNTSD_INVALID_LISTEN_ADDR) {
			syslog(LOG_ERR,
			    "Invalid listen address '%s'\n",
			    listen_addr);
			exit(2);
		}
	}

	D3(stderr, "options = %llx, instance = %s, listen = %s\n",
	    vntsdp->options, vntsdp->devinst,
	    listen_addr ? listen_addr : "<null>");

	/* open VCC driver control port */
	sz = strlen(VCC_DEVICE_CTL_PATH) + strlen(vntsdp->devinst) + 1;
	path = calloc(sz, 1);
	if (path == NULL) {
		vntsd_log(VNTSD_ERR_NO_MEM, "main(): alloc dev path");
		exit(1);
	}
	(void) snprintf(path, sz-1, VCC_DEVICE_CTL_PATH, vntsdp->devinst,
	    sizeof (vntsdp->devinst));
	vntsdp->ctrl_fd = open(path, O_RDWR);

	if (vntsdp->ctrl_fd == -1) {
		/* print error if device is not present */
		syslog(LOG_ERR,
		    "Error opening VCC device control port: %s",
		    path);
		/* tell SMF no retry */
		exit(2);
	}

	free(path);

	if ((vntsdp->options & VNTSD_OPT_DAEMON_OFF) == 0) {
		/* daemonize it */
		pid = fork();
		if (pid < 0) {
			perror("fork");
			exit(1);
		}
		if (pid > 0) {
			/* parent */
			exit(0);
		}

		/*
		 * child process (daemon)
		 *
		 * Close all file descriptors other than 2 and the ctrl fd.
		 */
		(void) close(0);
		(void) close(1);
		for (i = 3; i < vntsdp->ctrl_fd; i++) {
			(void) close(i);
		}
		closefrom(vntsdp->ctrl_fd + 1);

		/* obtain a new process group */
		(void) setsid();
		fd =  open("/dev/null", O_RDWR);
		if (fd < 0) {
			syslog(LOG_ERR, "Can not open /dev/null");
			exit(1);
		}
		/* handle standard I/O */
		if (dup2(fd, 0) < 0) {
			syslog(LOG_ERR, "Failed dup2()");
			exit(1);
		}

		if (dup2(fd, 1) < 0) {
			syslog(LOG_ERR, "Failed dup2()");
			exit(1);
		}

		/* ignore terminal signals */
		(void) signal(SIGTSTP, SIG_IGN);
		(void) signal(SIGTTOU, SIG_IGN);
		(void) signal(SIGTTIN, SIG_IGN);
	}


	/* set up signal handlers */

	/* exit signals */
	act.sa_handler = exit_sig_handler;

	(void) sigemptyset(&act.sa_mask);
	(void) sigaction(SIGINT, &act, NULL);
	(void) sigaction(SIGTERM, &act, NULL);
	(void) sigaction(SIGHUP, &act, NULL);

	/* vntsd internal signals */
	act.sa_handler = vntsd_sig_handler;
	(void) sigemptyset(&act.sa_mask);
	(void) sigaction(SIGUSR1, &act, NULL);


	act.sa_handler = vntsd_alarm_sig_handler;
	(void) sigemptyset(&act.sa_mask);
	(void) sigaction(SIGALRM, &act, NULL);


	/* setup exit */
	(void) atexit(vntsd_exit);



	/* initialization */
	openlog("vntsd", LOG_CONS, LOG_DAEMON);


	/* set alarm */
	if (vntsdp->timeout > 0) {
		(void) alarm(MINUTE);
	}

	vntsdp->tid = thr_self();

	/* get exiting consoles from vcc */
	vntsd_get_config(vntsdp);

	for (; ; ) {
		/* poll vcc for configuration change */
		bzero(poll_drv, sizeof (poll_drv));

		poll_drv[0].fd = vntsdp->ctrl_fd;
		poll_drv[0].events = POLLIN;

		if (poll(poll_drv, 1, -1) == -1) {
			if (errno == EINTR) {
				/* wake up because a consle was deleted */
				vntsd_delete_cons(vntsdp);
				continue;
			}
			vntsd_log(VNTSD_ERR_VCC_POLL,
			    "vcc control poll err! aborting..");
			exit(1);
		}

		D1(stderr, "t@%d driver event %x\n", thr_self(),
		    poll_drv[0].revents);

		vntsd_daemon_wakeup(vntsdp);
		/*
		 * Main thread may miss a console-delete signal when it is
		 * not polling vcc. check if any console is deleted.
		 */
		vntsd_delete_cons(vntsdp);

	}

	/*NOTREACHED*/
	return (0);
}

/* export ip_addr */
struct in_addr
vntsd_ip_addr(void)
{
	return (vntsdp->ip_addr);
}

/*
 * ioctl to vcc control port
 * Supported ioctls interface are:
 *		ioctl code	    parameters	   return data
 *		VCC_NUM_CONSOLE	    none	   uint_t  no consoles
 *		VCC_CONS_TBL	    none	   array of vcc_cons_t
 *		VCC_INQUIRY	    none	   vcc_response_t response
 *		VCC_CONS_INFO	    uint_t portno   vcc_cons_t
 *		VCC_CONS_STATUS	    uint_t portno
 *		VCC_FORCE_CLOSE	    uint_t portno
 */
int
vntsd_vcc_ioctl(int ioctl_code, uint_t portno, void *buf)
{
	D1(stderr, "t@%d vcc_ioctl@%d code=%x\n", thr_self(), portno,
	    ioctl_code);

	if ((ioctl_code == (VCC_CONS_INFO)) ||
	    (ioctl_code == (VCC_FORCE_CLOSE))) {
		/* construct vcc in buf */
		*((uint_t *)buf) = portno;
	}

	if (ioctl(vntsdp->ctrl_fd, ioctl_code, (caddr_t)buf)) {
		/*  ioctl request error */
		return (VNTSD_STATUS_VCC_IO_ERR);
	}

	return (VNTSD_SUCCESS);
}

/*
 * check if a vcc i/o error is caused by removal of a console. If so
 * wake up main thread to cleanup the console.
 */
int
vntsd_vcc_err(vntsd_cons_t *consp)
{
	vntsd_group_t *groupp;

	assert(consp);
	groupp = consp->group;
	assert(groupp);

	if (consp->status & VNTSD_CONS_DELETED) {
		/* console was deleted  */
		return (VNTSD_STATUS_VCC_IO_ERR);
	}

	if (vntsd_vcc_cons_alive(consp)) {
		/* console is ok */
		return (VNTSD_STATUS_CONTINUE);
	}

	/* console needs to be deleted */
	(void) mutex_lock(&consp->lock);
	consp->status |= VNTSD_CONS_DELETED;

	/*
	 * main thread will close all clients after receiving console
	 * delete signal.
	 */
	(void) mutex_unlock(&consp->lock);

	/* mark the group */
	(void) mutex_lock(&groupp->lock);
	groupp->status |= VNTSD_GROUP_CLEAN_CONS;
	(void) mutex_unlock(&groupp->lock);

	/* signal main thread to deleted console */
	(void) thr_kill(vntsdp->tid, SIGUSR1);

	return (VNTSD_STATUS_VCC_IO_ERR);
}
