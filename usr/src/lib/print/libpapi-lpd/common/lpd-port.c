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
 *
 */

/* $Id: lpd-port.c 155 2006-04-26 02:34:54Z ktou $ */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <config-site.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdarg.h>
#include <string.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>
#include <syslog.h>
#include <values.h>
#include <stropts.h>	/* for sendfd */
#include <sys/uio.h>	/* for sendmsg stuff */
#include <pwd.h>
#include <sys/sendfile.h>
#include <ctype.h>
#ifdef HAVE_PRIV_H
#include <priv.h>
#endif

#ifndef	JOB_ID_FILE
#define	JOB_ID_FILE	"/var/run/rfc-1179.seq"
#endif	/* JOB_ID_FILE */

static int
sendfd(int sockfd, int fd)
{
	syslog(LOG_DEBUG, "sendfd(%d, %d)", sockfd, fd);

#if defined(sun) && defined(unix) && defined(I_SENDFD)
	return (ioctl(sockfd, I_SENDFD, fd));
#else
	struct iovec	iov[1];
	struct msghdr	msg;
#ifdef CMSG_DATA
	struct cmsghdr cmp[1];
	char buf[2];    /* send/recv 2 byte protocol */

	iov[0].iov_base = buf;
	iov[0].iov_len = 2;

	cmp[0].cmsg_level = SOL_SOCKET;
	cmp[0].cmsg_type = SCM_RIGHTS;
	cmp[0].cmsg_len = sizeof (struct cmsghdr) + sizeof (int);
	* (int *)CMSG_DATA(cmp) = fd;

	buf[1] = 0;
	buf[0] = 0;
	msg.msg_control = cmp;
	msg.msg_controllen = sizeof (struct cmsghdr) + sizeof (int);
#else
	iov[0].iov_base = NULL;
	iov[0].iov_len = 0;
	msg.msg_accrights = (caddr_t)&fd;
	msg.msg_accrights = sizeof (fd);
#endif
	msg.msg_iov = iov;
	msg.msg_iovlen = 1;
	msg.msg_name = NULL;
	msg.msg_namelen = 0;

	return (sendmsg(sockfd, &msg, 0));
#endif
}

static void
null(int i)
{
}

static int
sock_connect(int sock, char *host, int timeout)
{
	struct hostent *hp;
	struct servent *sp;
#if defined(HAVE_GETIPNODEBYNAME) && defined(HAVE_RRESVPORT_AF)
	struct sockaddr_in6 sin;
#else
	struct sockaddr_in sin;
#endif
	static void (*old_handler)();
	int	err,
		error_num;
	unsigned timo = 1;

	/*
	 * Get the host address and port number to connect to.
	 */
	if (host == NULL) {
		return (-1);
	}

	/* linux style NULL usage */
	(void) memset((char *)&sin, (int)NULL, sizeof (sin));

#if defined(HAVE_GETIPNODEBYNAME) && defined(HAVE_RRESVPORT_AF)
	if ((hp = getipnodebyname(host, AF_INET6, AI_DEFAULT,
		    &error_num)) == NULL) {
		errno = ENOENT;
		return (-1);
	}
	(void) memcpy((caddr_t)&sin.sin6_addr, hp->h_addr, hp->h_length);
	sin.sin6_family = hp->h_addrtype;
#else
	if ((hp = gethostbyname(host)) == NULL) {
		errno = ENOENT;
		return (-1);
	}

	(void) memcpy((caddr_t)&sin.sin_addr, hp->h_addr, hp->h_length);
	sin.sin_family = hp->h_addrtype;
#endif

	if ((sp = getservbyname("printer", "tcp")) == NULL) {
		errno = ENOENT;
		return (-1);
	}

#if defined(HAVE_GETIPNODEBYNAME) && defined(HAVE_RRESVPORT_AF)
	sin.sin6_port = sp->s_port;
#else
	sin.sin_port = sp->s_port;
#endif

retry:
	old_handler = signal(SIGALRM, null);
	(void) alarm(timeout);

	if (connect(sock, (struct sockaddr *)&sin, sizeof (sin)) < 0) {
		(void) alarm(0);
		(void) signal(SIGALRM, old_handler);

		if (errno == ECONNREFUSED && timo <= 16) {
			(void) sleep(timo);
			timo *= 2;
			goto retry;
		}

		return (-1);
	}

	(void) alarm(0);
	(void) signal(SIGALRM, old_handler);
	return (sock);
}

static int
next_job_id()
{
	int fd, result = getpid() % 1000;

	/* gain back enough privilege to open the id file */
#ifdef	PRIV_ALLSETS
	if ((priv_set(PRIV_ON, PRIV_EFFECTIVE,
			PRIV_FILE_DAC_READ, PRIV_FILE_DAC_WRITE, NULL)) < 0) {
		syslog(LOG_ERR, "lpd_port:next_job_id:priv_set fails: : %m");
		return (-1);
	}
#else
	seteuid(0);
#endif

	/* open the sequence file */
	if (((fd = open(JOB_ID_FILE, O_RDWR)) < 0) && (errno == ENOENT))
		fd = open(JOB_ID_FILE, O_CREAT|O_EXCL|O_RDWR, 0644);

	syslog(LOG_DEBUG, "sequence file fd: %d", fd);

	/* drop our privilege again */
#ifdef	PRIV_ALLSETS
	/* drop file access privilege */
	priv_set(PRIV_OFF, PRIV_PERMITTED,
			PRIV_FILE_DAC_READ, PRIV_FILE_DAC_WRITE, NULL);
#else
	seteuid(getuid());
#endif

	if (fd >= 0) {
		/* wait for a lock on the file */
		if (lockf(fd, F_LOCK, 0) == 0) {
			char buf[8];
			int next;

			/* get the current id */
			(void) memset(buf, 0, sizeof (buf));
			if (read(fd, buf, sizeof (buf)) > 0)
				result = atoi(buf);

			next = ((result < 999) ? (result + 1) : 0);

			/* store the next id in the file */
			snprintf(buf, sizeof (buf), "%.3d", next);
			if ((lseek(fd, 0, SEEK_SET) == 0) &&
			    (ftruncate(fd, 0) == 0))
				write(fd, buf, strlen(buf));
		}
		close(fd);
	}
	syslog(LOG_DEBUG, "next_job_id() is %d", result);

	return (result);
}

static int
reserved_port()
{
	int result = -1;
	int port;

	/* gain back enough privilege to open a reserved port */
#ifdef	PRIV_ALLSETS
	if ((priv_set(
		PRIV_ON, PRIV_EFFECTIVE, PRIV_NET_PRIVADDR, NULL)) != 0) {
		syslog(LOG_ERR, "priv_set fails for net_privaddr %m");
		return (-1);
	}
#else
	seteuid(0);
#endif

#if defined(HAVE_GETIPNODEBYNAME) && defined(HAVE_RRESVPORT_AF)
	port = 0;	/* set to 0, rresvport_af() will find us one. */
	result = rresvport_af(&port, AF_INET6);
#else
	port = IPPORT_RESERVED - 1;
	while (((result = rresvport(&port)) < 0) && (port >= 0))
		port--;
#endif

	/* drop our privilege again */
#ifdef	PRIV_ALLSETS
	priv_set(PRIV_OFF, PRIV_PERMITTED, PRIV_NET_PRIVADDR, NULL);
#else
	seteuid(getuid());
#endif

	return (result);
}

static char *
get_user_name()
{
	static struct passwd *p = NULL;

	if ((p = getpwuid(getuid())) != NULL)
		return (p->pw_name);
	else
		return ("unknown");
}

static void
add_args(int ac, char **av, char *buf, size_t len)
{
	while (ac--) {
		strlcat(buf, " ", len);
		strlcat(buf, *(av++), len);
	}
}

static int
massage_control_data(char *data, int id)
{
	char *line, *iter = NULL;
	char *ptr;
	char host[BUFSIZ];

	gethostname(host, sizeof (host));

	for (ptr = strchr(data, '\n'); ptr != NULL; ptr = strchr(ptr, '\n')) {
		ptr++;

		if (ptr[0] == 'H') {
			if (strncmp(++ptr, host, strlen(host)) != 0)
				return (-1);
		} else if ((ptr[0] == 'P') || (ptr[0] == 'L')) {
			/* check the user name */
			uid_t uid = getuid();
			struct passwd *pw;
			int len;

			if (uid == 0)	/* let root do what they want */
				continue;
			if ((pw = getpwuid(uid)) == NULL)
				return (-1);	/* failed */
			len = strlen(pw->pw_name);
			if ((strncmp(++ptr, pw->pw_name, len) != 0) ||
			    (ptr[len] != '\n'))
				return (-1);	/* failed */
		} else if ((islower(ptr[0]) != 0) || (ptr[0] == 'U')) {
			/* check/fix df?XXXhostname */
			ptr++;

			if (strlen(ptr) < 6)
				return (-1);
			if ((ptr[0] == 'd') && (ptr[1] == 'f') &&
			    (ptr[3] == 'X') && (ptr[4] == 'X') &&
			    (ptr[5] == 'X')) {
				ptr[3] = '0' + (id / 100) % 10;
				ptr[4] = '0' + (id / 10) % 10;
				ptr[5] = '0' + id % 10;

			if (strncmp(&ptr[6], host, strlen(host)) != 0)
				return (-1);
			} else
				return (-1);
		}
	}
	return (1);
}

static int
send_lpd_message(int fd, char *fmt, ...)
{
	char buf[BUFSIZ];
	size_t size;
	va_list ap;

	va_start(ap, fmt);
	size = vsnprintf(buf, sizeof (buf), fmt, ap);
	va_end(ap);
	if (size == 0)
		size = 1;

	syslog(LOG_DEBUG, "lpd_messsage(%d, %s)", fd, buf);

	if (write(fd, buf, size) != size) {
		errno = EIO;
		return (-1);
	}

	if ((read(fd, buf, 1) != 1) || (buf[0] != 0))
		return (-1);

	return (0);
}

static int
send_data_file(int sock, char *dfname, char *name)
{
	size_t len;
	off_t off = 0;
	struct stat st;
	char buf[32];
	int fd = -1;

	if (strcmp(name, "standard input") != 0) {
		if ((fd = open(name, O_RDONLY)) < 0)
			return (-1);

		if (fstat(fd, &st) < 0)
			return (-1);
	} else
		st.st_size = MAXINT; /* should be 0 */

	/* request data file transfer, read ack/nack */
	errno = ENOSPC;
	if (send_lpd_message(sock, "\003%d %s\n", st.st_size, dfname) < 0)
		return (-1);

	if (fd != -1) {
		/* write the data */
		if (sendfile(sock, fd, &off, st.st_size) != st.st_size)
			return (-1);
		close(fd);

		/* request ack/nack after the data transfer */
		errno = EIO;
		if (send_lpd_message(sock, "") < 0)
			return (-1);
	}

	return (0);
}

static int
send_control_file(int sock, char *data, int id)
{
	int len;
	char buf[BUFSIZ];
	char *host = "localhost";

	len = strlen(data);

	/* request data file transfer, read ack/nack */
	errno = ENOSPC;
	if (send_lpd_message(sock, "\002%d cfA%.3d%s\n", len, id, host) < 0)
		return (-1);

	/* write the data */
	if (write(sock, data, len) != len)
		return (-1);

	/* request ack/nack after the data transfer */
	errno = EIO;
	if (send_lpd_message(sock, "") < 0)
		return (-1);

	return (0);
}


static int
submit_job(int sock, char *printer, int job_id, char *path)
{
	struct stat st;
	int current = 0;
	off_t off = 0;
	char *metadata = NULL;
	char *ptr, *iter = NULL;
	int fd, err;
	int sent_files = 0;
	char buf[BUFSIZ];
	size_t len;

	/* open the control file */
	if ((fd = open(path, O_RDONLY)) < 0) {
		syslog(LOG_ERR, "submit_job(%d, %s, %d, %s): open(): %m",
			sock, printer, job_id, path);
		return (-1);
	}

	/* get the size of the control file */
	if (fstat(fd, &st) < 0) {
		syslog(LOG_ERR, "submit_job(%d, %s, %d, %s): fstat(): %m",
			sock, printer, job_id, path);
		close(fd);
		return (-1);
	}

	/* allocate memory for the control file */
	if ((metadata = calloc(1, st.st_size + 1)) == NULL) {
		syslog(LOG_ERR, "submit_job(%d, %s, %d, %s): calloc(): %m",
			sock, printer, job_id, path);
		close(fd);
		return (-1);
	}

	/* read in the control file */
	if (read(fd, metadata, st.st_size) != st.st_size) {
		syslog(LOG_ERR, "submit_job(%d, %s, %d, %s): read(): %m",
			sock, printer, job_id, path);
		free(metadata);
		close(fd);
		return (-1);
	}

	/* massage the control file */
	if (massage_control_data(metadata, job_id) < 0) {
		/* bad control data, dump the job */
		syslog(LOG_ALERT,
			"bad control file, possible subversion attempt");
		free(metadata);
		close(fd);
		return (-1);
	}

	/* request to transfer the job */
	if (send_lpd_message(sock, "\002%s\n", printer) < 0) {
		/* no such (or disabled) queue, got to love rfc-1179 */
		errno = ENOENT;
		return (-1);
	}

	/* send the control data */
	if (send_control_file(sock, metadata, job_id) < 0) {
		err = errno;
		write(sock, "\001\n", 2); /* abort */
		errno = err;
		return (-1);
	}

	/* walk the control file sending the data files */
	for (ptr = strtok_r(metadata, "\n", &iter); ptr != NULL;
			ptr = strtok_r(NULL, "\n", &iter)) {
		char *name = NULL;

		if (ptr[0] != 'U')
			continue;

		name = strtok_r(NULL, "\n", &iter);
		if (name[0] != 'N')
			continue;

		ptr++;
		name++;

		if (send_data_file(sock, ptr, name) < 0) {
			err = errno;
			write(sock, "\001\n", 2); /* abort */
			errno = err;
			return (-1);
		}
		if (strcmp(name, "standard input") != 0)
			sent_files++;
	}

	/* write back the job-id */
	err = errno;
	if ((fd = open(path, O_WRONLY)) >= 0) {
		ftruncate(fd, 0);
		write(fd, &job_id, sizeof (job_id));
		close(fd);
	}
	errno = err;

	if (sent_files != 0) {
		err = errno;
		close(sock);
		errno = err;
	}

	return (0);
}
static int
query(int fd, char *printer, int ac, char **av)
{
	char buf[BUFSIZ];
	int rc, len;

	/* build the request */
	snprintf(buf, sizeof (buf), "\04%s", printer);
	add_args(ac, av, buf, sizeof (buf));
	strlcat(buf, "\n", sizeof (buf));
	len = strlen(buf);

	if (((rc = write(fd, buf, len)) >= 0) && (rc != len)) {
		errno = EMSGSIZE;
		rc = -1;
	} else
		rc = 0;

	return (rc);
}

static int
cancel(int fd, char *printer, int ac, char **av)
{
	char buf[BUFSIZ];
	int rc, len;

	/* build the request */
	snprintf(buf, sizeof (buf), "\05%s %s", printer, get_user_name());
	add_args(ac, av, buf, sizeof (buf));
	strlcat(buf, "\n", sizeof (buf));
	len = strlen(buf);

	if (((rc = write(fd, buf, len)) >= 0) && (rc != len)) {
		errno = EMSGSIZE;
		rc = -1;
	} else
		rc = 0;

	return (rc);
}

static void
usage(char *program)
{
	char *name;

	setreuid(getuid(), getuid());

	if ((name = strrchr(program, '/')) == NULL)
		name = program;
	else
		name++;

	fprintf(stderr, "usage:\t%s -H host [-t timeout] -s queue control ]\n",
			name);
	fprintf(stderr, "\t%s -H host [-t timeout] -c queue [user|job ...]\n",
			name);
	fprintf(stderr, "\t%s -H host [-t timeout] -q queue [user|job ...]\n",
			name);
	exit(EINVAL);
}

/*
 * The main program temporarily loses privilege while searching the command
 * line arguments.  It then allocates any resources it need privilege for
 * job-id, reserved port.  Once it has the resources it needs, it perminently
 * drops all elevated privilege.  It ghen connects to the remote print service
 * based on destination hostname.  Doing it this way reduces the potenential
 * opportunity for a breakout with elevated privilege, breakout with an
 * unconnected reserved port, and exploitation of the remote print service
 * by a calling program.
 */
int
main(int ac, char *av[])
{
	enum { OP_NONE, OP_SUBMIT, OP_QUERY, OP_CANCEL } operation = OP_NONE;
	int fd, c, timeout = 0, exit_code = 0;
	char *host = NULL, *queue = NULL;
	uid_t uid = getuid();
#ifdef	PRIV_ALLSETS
	priv_set_t *saveset = NULL;
#endif

	openlog("lpd-port", LOG_PID, LOG_LPR);

#ifdef	PRIV_ALLSETS

	/* lose as much as we can perminently and temporarily drop the rest. */

	if ((saveset = priv_str_to_set("PRIV_NET_PRIVADDR,"
			"PRIV_FILE_DAC_READ,PRIV_FILE_DAC_WRITE,",
			",", (const char **)NULL)) == NULL) {
		syslog(LOG_ERR,
		    "lpd_port: priv_str_to_set saveset failed: %m\n");
		return (-1);
	}

	if ((setppriv(PRIV_SET, PRIV_PERMITTED, saveset)) < 0) {
		syslog(LOG_ERR, "lpd_port:setppriv:priv_set failed: %m");
		return (-1);
	}

	/*
	 * These privileges permanently dropped in next_job_id() and
	 * reserved_port()
	 */

	if ((setppriv(PRIV_OFF, PRIV_EFFECTIVE, saveset)) < 0) {
		syslog(LOG_ERR, "lpd_port:setppriv:priv_off failed: %m");
		return (-1);
	}

	priv_freeset(saveset);

	syslog(LOG_DEBUG, "using privs");
#else

	syslog(LOG_DEBUG, "no  privs");
	seteuid(uid);
#endif

	while ((c = getopt(ac, av, "H:t:c:q:s:")) != EOF) {
		switch (c) {
		case 'H':
			host = optarg;
			break;
		case 't':
			timeout = atoi(optarg);
			break;
		case 'c':
			if (operation != OP_NONE)
				usage(av[0]);
			operation = OP_CANCEL;
			queue = optarg;
			break;
		case 'q':
			if (operation != OP_NONE)
				usage(av[0]);
			operation = OP_QUERY;
			queue = optarg;
			break;
		case 's':
			if (operation != OP_NONE)
				usage(av[0]);
			operation = OP_SUBMIT;
			queue = optarg;
			break;
		default:
			usage(av[0]);
			/* does not return */
		}
	}

	if ((host == NULL) || (queue == NULL) || (timeout < 0) ||
	    (operation == OP_NONE))
		usage(av[0]);

	if (operation == OP_SUBMIT)	/* get a job-id if we need it */
		if ((c = next_job_id()) < 0) {
			syslog(LOG_ERR, "lpd_port:main:next_job_id fails");
			return (-1);
		}

	if ((fd = reserved_port()) < 0) {
		syslog(LOG_ERR, "reserved_port() failed %m");
		return (errno);
	}

	/*
	 * we no longer want or need any elevated privilege, lose it all
	 * permanently.
	 */

	setreuid(uid, uid);

	/* connect to the print service */
	if ((fd = sock_connect(fd, host, timeout)) < 0)
		return (errno);

	/* perform the requested operation */
	switch (operation) {
	case OP_SUBMIT:	/* transfer the job, close the fd */
		if (submit_job(fd, queue, c, av[optind]) < 0)
			exit_code = errno;
		break;
	case OP_QUERY:	/* send the query string, return the fd */
		if (query(fd, queue, ac - optind, &av[optind]) < 0)
			exit_code = errno;
		break;
	case OP_CANCEL:	/* send the cancel string, return the fd */
		if (cancel(fd, queue, ac - optind, &av[optind]) < 0)
			exit_code = errno;
		break;
	default:	/* This should never happen */
		exit_code = EINVAL;
	}


	/* if the operation succeeded, send the fd to our parent */
	if ((exit_code == 0) && (sendfd(1, fd) < 0)) {
		char buf[BUFSIZ];

		exit_code = errno;

		/* sendfd() failed, dump the socket data for the heck of it */
		while ((c = read(fd, buf, sizeof (buf))) > 0)
			write(1, buf, c);
	}

	syslog(LOG_DEBUG, "exit code: %d", exit_code);
	return (exit_code);
}
