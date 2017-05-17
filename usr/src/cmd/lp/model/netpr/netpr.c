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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <stdio.h>
#include <stdlib.h>
#include <libintl.h>
#include <locale.h>
#include <signal.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>
#include <syslog.h>
#include <sys/utsname.h>
#include "netpr.h"


static void usage_exit();

static void pipehandler(int);
char data_file_type = 0;

/*
 *  null() is to be used as a signal handler that does nothing.  It is used in
 *      place of SIG_IGN, because we want the signal to be delivered and
 *      interupt the current system call.
 */
static void
null(int i)
{
	syslog(LOG_DEBUG, "null(%d)", i);
}

/*
 *  net_open() opens a tcp connection to the printer port on the host specified
 *      in the arguments passed in.  If the connection is not made in the
 *      timeout (in seconds) passed in, an error it returned.  If the host is
 *      unknown, an error is returned.  If all is well, a file descriptor is
 *      returned to be used for future communications.
 */
int
net_open(char *host, int timeout)
{
	struct hostent *hp;
	struct servent *sp;
	struct sockaddr_in6 sin;
	void (*old_handler)();
	static struct utsname uts;

	int s;
	int lport;
	int err;
	int error_num;
	unsigned timo = 1;

	syslog(LOG_DEBUG, "net_open(%s, %d)", (host != NULL ? host : "NULL"),
	    timeout);
	/*
	 * Get the host address and port number to connect to.
	 */
	if (host == NULL) {
		return (-1);
	}

	(void) memset((char *)&sin, NULL, sizeof (sin));
	if ((hp = getipnodebyname(host, AF_INET6, AI_DEFAULT,
	    &error_num)) == NULL) {
		syslog(LOG_DEBUG|LOG_ERR, "unknown host %s "
		    "getipnodebyname() returned %d", host, error_num);
		return (NETWORK_ERROR_HOST);
	}
	(void) memcpy((caddr_t)&sin.sin6_addr, hp->h_addr, hp->h_length);
	sin.sin6_family = hp->h_addrtype;
	freehostent(hp);

	if ((sp = getservbyname("printer", "tcp")) == NULL) {
		syslog(LOG_DEBUG|LOG_ERR, "printer/tcp: unknown service");
		return (NETWORK_ERROR_SERVICE);
	}
	sin.sin6_port = sp->s_port;

retry:
	/*
	 * Try connecting to the server.
	 *
	 * Use 0 as lport means that rresvport_af() will bind to a port in
	 * the anonymous privileged port range.
	 */
	lport = 0;
	s = rresvport_af(&lport, AF_INET6);
	if (s < 0)
		return (NETWORK_ERROR_PORT);

	old_handler = signal(SIGALRM, null);
	(void) alarm(timeout);
	if (connect(s, (struct sockaddr *)&sin, sizeof (sin)) < 0) {
		(void) alarm(0);
		(void) signal(SIGALRM, old_handler);
		err = errno;
		(void) close(s);
		errno = err;
		if (errno == EADDRINUSE) {
			goto retry;
		}
		/*
		 * If connecting to the local system fails, try
		 * again with "localhost" address instead.
		 */
		if (uts.nodename[0] == '\0')
			(void) uname(&uts);
		if (strcmp(host, uts.nodename) == 0) {
			IN6_IPADDR_TO_V4MAPPED(htonl(INADDR_LOOPBACK),
			    &sin.sin6_addr);
			sin.sin6_family = AF_INET6;
			goto retry;
		}
		if (errno == ECONNREFUSED && timo <= 16) {
			(void) sleep(timo);
			timo *= 2;
			goto retry;
		}
		return (NETWORK_ERROR_UNKNOWN);
	}
	(void) alarm(0);
	(void) signal(SIGALRM, old_handler);
	return (s);
}

int
main(int argc, char *argv[])
{
	extern char *optarg;
	extern int optind;
	int opt;
	np_job_t *job_data;
	char *destination = NULL;
	np_bsdjob_t *bsdjob;
	np_tcpjob_t *tcpjob;
	int sockfd;
	int pr_order = CONTROL_FIRST;
	char *vendor_pr_name = NULL;
	char *tcp_port = NULL;
	size_t filesize;
	int fd;
	caddr_t pa;
	int jobstatus;
	int exit_status = 0;
	int on = 1;


	(void) setlocale(LC_ALL, "");
#if	!defined(TEXT_DOMAIN)   /* Should be defined by cc -D */
#define	TEXT_DOMAIN "SYS_TEST"  /* Use this only if it weren't */
#endif
	(void) textdomain(TEXT_DOMAIN);

	openlog("netpr", LOG_PID, LOG_LPR);
	(void) signal(SIGPIPE, pipehandler);

	/* reduce privileges until needed to open reserved port */
	if (seteuid(getuid())) {
		syslog(LOG_DEBUG, "seteuid failed, exiting netpr");
		exit(E_FAILURE);
	}

	if ((job_data = init_job()) == NULL) {
		fprintf(stderr, gettext("init_job(): out of memory\n"));
		exit(E_RETRY);
	}

	while ((opt = getopt(argc, argv, "f:I:p:d:T:P:t:U:c:b")) != EOF)
		switch (opt) {
		case 'f':
			data_file_type = optarg[0];
			break;
		case 'I': /* foo-49 */
			job_data->request_id = alloc_str((char *)optarg);
			syslog(LOG_DEBUG, "request_id: %s",
			    job_data->request_id);
			break;
		case 'U': /* awe172-126!wendyp */
			job_data->username = alloc_str((char *)optarg);
			syslog(LOG_DEBUG, "username: %s", job_data->username);
			break;
		case 'p': /* foo */
			job_data->printer = alloc_str((char *)optarg);
			syslog(LOG_DEBUG, "printer: %s", job_data->printer);
			break;
		case 'd': /* server for printer */
			job_data->dest = alloc_str((char *)optarg);
			syslog(LOG_DEBUG, "dest: %s", job_data->dest);
			break;
		case 'T': /* /tmp/file2 */
			job_data->title = alloc_str((char *)optarg);
			syslog(LOG_DEBUG, "title: %s", job_data->title);
			break;
		case 'P':
			if ((strcmp(optarg, "bsd")) == 0)
				job_data->protocol = BSD;
			else if ((strcmp(optarg, "tcp")) == 0)
				job_data->protocol = TCP;
			else
				usage_exit();

			syslog(LOG_DEBUG, "protocol: %d", job_data->protocol);
			break;
		case 't':
			job_data->timeout = atoi(optarg);
			if (job_data->timeout < 0)
				usage_exit();
			break;
		case 'c':
			if ((strcmp(optarg, "first")) == 0)
				pr_order = CONTROL_FIRST;
			else if ((strcmp(optarg, "last")) == 0)
				pr_order = DATA_FIRST;
			else
				usage_exit();

			syslog(LOG_DEBUG, "bsd print order: %d", pr_order);
			break;
		case 'b':
			job_data->banner = NOBANNER;
			syslog(LOG_DEBUG, "banner : %d", job_data->banner);
			break;
		case '?':
			usage_exit();
		}


	if ((job_data->dest == NULL) || (job_data->request_id == NULL) ||
	    (job_data->printer == NULL) || (job_data->username == NULL))
		usage_exit();

	/*
	 * Check that there is a file
	 */
	if (optind == argc) {
		usage_exit();
	}

	job_data->filename = alloc_str(argv[optind]);
	syslog(LOG_DEBUG, "filename : %s", job_data->filename);


	/*
	 * Sanity check the file
	 * returns filesize
	 */

	if ((filesize = check_file(job_data->filename)) == -1) {
		syslog(LOG_DEBUG, "Skipping file %s",
		    job_data->filename ?
		    job_data->filename : "Error NULL file");

		switch (errno) {
		case EISDIR:
			(void) fprintf(stderr,
			    gettext("Netpr: %s: Not a regular file\n"),
			    job_data->filename ?
			    job_data->filename : "Noname");
			syslog(LOG_DEBUG, "Not a regular file");
			break;
		case ESRCH:
			(void) fprintf(stderr,
			    gettext("Netpr: %s: Empty file\n"),
			    job_data->filename ?
			    job_data->filename : "Noname");
			syslog(LOG_DEBUG, "Empty file");
			break;
		default:
			perror(job_data->filename);
			(void) fprintf(stderr,
			    gettext("Netpr: Cannot access file %s\n"),
			    job_data->filename ?
			    job_data->filename : "Noname");
			syslog(LOG_DEBUG, "Cannot access file.");
			break;

		}

		/*
		 * This file not valid, so bail
		 * Exit with zero so system will keep printing
		 */
		exit(0);
	}

	/*
	 * file looks ok, open and mmap it
	 */
	if ((fd = open(job_data->filename, O_RDONLY)) < 0) {
		(void) fprintf(stderr, gettext("Netpr: Cannot open file %s\n"),
		    job_data->filename ?
		    job_data->filename : "Error: NULL file");
		syslog(LOG_DEBUG, "Cannot open file: %s",
		    job_data->filename ?
		    job_data->filename : "Error NULL file");
		exit(E_BAD_FILE);
	}

	if ((pa = mmap((caddr_t)0, filesize, PROT_READ,
	    (MAP_SHARED | MAP_NORESERVE), fd, (off_t)0)) == MAP_FAILED) {

		(void) close(fd);
		(void) fprintf(stderr, gettext("Netpr: Cannot mmap file %s"),
		    job_data->filename ?
		    job_data->filename : "Error: NULL file");

		syslog(LOG_DEBUG, "Cannot mmap file: %s",
		    job_data->filename ?
		    job_data->filename : "Error NULL file");

		exit(E_RETRY);
	}


	if (job_data->protocol == BSD) {
		bsdjob = (np_bsdjob_t *)
		    create_bsd_job(job_data, pr_order, filesize);
		if (bsdjob == NULL)
			exit(E_FAILURE);
	} else {
		tcpjob = (np_tcpjob_t *)create_tcp_job(job_data, filesize);
		if (tcpjob == NULL)
			exit(E_FAILURE);
	}

	/*
	 * Parse destination
	 */

	if ((strpbrk(job_data->dest, DEST_SEP)) != NULL) {
		if (job_data->protocol == BSD) {
			parse_dest(job_data->dest, &destination,
			    &vendor_pr_name, DEST_SEP);
			if (vendor_pr_name != NULL) {
				bsdjob->np_printer = vendor_pr_name;
				syslog(LOG_DEBUG, "bsd vendor name: %s",
				    bsdjob->np_printer);
			}
		} else {
			parse_dest(job_data->dest, &destination, &tcp_port,
			    DEST_SEP);
			if (tcp_port != NULL)
				tcpjob->np_port = tcp_port;
			syslog(LOG_DEBUG, "tcp_port %s", tcpjob->np_port);
		}
		if (destination == NULL ||
		    (job_data->protocol == TCP && tcp_port == NULL)) {
			(void) fprintf(stderr, gettext("Netpr: system error "
			    "parsing destination %s\n"), job_data->dest);
			syslog(LOG_DEBUG, "system error parsing destination %s",
			    job_data->dest);

			exit(E_FAILURE);
		}

	} else {
		destination = job_data->dest;
	}
	syslog(LOG_DEBUG, "destination : %s", destination);

	/*
	 * We are now ready to open a connection to the printer
	 * and print each of the files
	 */

	if (job_data->protocol == BSD) {

		/* set privileges to get reserved port */
		if (seteuid(0)) {
			syslog(LOG_DEBUG, "seteuid(0) failed, exiting netpr");
			exit(E_FAILURE);
		}
		if ((sockfd =  net_open(destination, 20)) < 0) {
			(void) fprintf(stderr,
			    gettext("Netpr: Cannot open connection to <%s>\n"),
			    destination);
			syslog(LOG_DEBUG,
			    "Cannot open connection to %s: retrying",
			    destination);
			exit(E_RETRY);
		}
	} else {
		if ((sockfd = tcp_open(destination, tcpjob, 20)) == -1) {
			exit(E_RETRY);
		}
	}

	/* lower privileges as we now have the reserved port */
	if (setuid(getuid())) {
		syslog(LOG_DEBUG, "setuid() failed, exiting netpr");
		exit(E_FAILURE);
	}


	/* Set SO_KEEPALIVE on socket to keep open */
	if ((setsockopt(sockfd, SOL_SOCKET, SO_KEEPALIVE,
	    (char *)&on, sizeof (on))) < 0) {
		syslog(LOG_DEBUG, "setsocket (SO_KEEPALIVE): %m");
	}

	if (job_data->protocol == BSD) {
		if ((jobstatus = bsd_print(sockfd, pa,  bsdjob)) != 0) {
			(void) fprintf(stderr, gettext("Netpr: Error return "
			    "from bsd_print <%d>\n"), jobstatus);
			syslog(LOG_DEBUG,
			    "Error return from bsd_print <%d>", jobstatus);
			exit_status = E_RETRY;
		}
	} else {
		if ((jobstatus =
		    tcp_print(sockfd, pa, tcpjob)) != 0) {
			(void) fprintf(stderr, gettext("Netpr: Error return "
			    "from tcp_print <%d>\n"), jobstatus);
			syslog(LOG_DEBUG,
			    "Error return from tcp_print <%d>", jobstatus);
			exit_status = E_RETRY;
		}
	}

	(void) close(fd);
	(void) close(sockfd);
	(void) munmap(pa, filesize);

	syslog(LOG_DEBUG, "exit status: %d", exit_status);
	return (exit_status);
}

static void
usage_exit()
{
	(void) fprintf(stderr,
	gettext("Usage: netpr -I request_id -p printer -d destination\n"));
	(void) fprintf(stderr,
	gettext("\t\t-U username [ -f type ] [ -T title ] [ -P protocol ]\n"));
	(void) fprintf(stderr,
	    gettext("\t\t[-t timeout] [ -c ] [ -b ]\n"));
	(void) fprintf(stderr, gettext("\t\tfiles\n"));
	exit(E_BAD_INPUT);
}

/*ARGSUSED*/
void
pipehandler(int i)
{
	(void) signal(SIGPIPE, pipehandler);
	syslog(LOG_DEBUG, "Received SIGPIPE, connection to printer broken");
	exit(E_SIGPIPE);
}
