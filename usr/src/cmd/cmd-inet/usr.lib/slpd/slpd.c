/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"


/*
 * This is a proxy daemon for the real Java slpd. This deamon starts
 * at boot time, and listens for any incoming SLP messages only on
 * loopback -- this way, only local processes can start the real
 * daemon. When a message comes in, the proxy daemon dups the message
 * fds onto fds 0, 1, and 2, and execs the real Java slpd. The purpose
 * of this approach is for performance: boot time performance is
 * not degraded by cranking off the (huge) JVM, and systems take
 * the JVM resource hit only if they actually use SLP.
 */

#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>
#include <errno.h>
#include <sys/byteorder.h>
#include <sys/resource.h>
#include <netinet/in.h>
#include <unistd.h>
#include <slp.h>
#include <fcntl.h>
#include <stdlib.h>
#include <syslog.h>

/* This is an index which points into the args array at the conf file arg */
#define	CONF_INDEX	6

/* Location of the Java Virtual Machine */
#define	JAVA_VM	"/usr/java/jre/bin/java"

static char *slpd_args[] = {
	JAVA_VM,
	"-Xmx128m",
	"-classpath",
	"/usr/share/lib/slp/slpd.jar",
	"com.sun.slp.slpd",
	"-f",
	"/etc/inet/slp.conf",
	0
};

/*
 * These are global so they can be easily accessed from a signal
 * handler for cleanup.
 */

static void
run_slpd(void)
{
	closelog();

	if (execv(*slpd_args, slpd_args) == -1) {
		openlog("slpd", LOG_PID, LOG_DAEMON);
		syslog(LOG_ERR, "execv failed: %s", strerror(errno));
		closelog();
	}
}

/*
 * If an alternate config file was specified with -f, make sure slpd
 * uses that config file. Also, force libslp.so to use that new config
 * file when checking to see if slpd is a DA. If any other arguments
 * are given, they are ignored.
 */
static void
do_args(int argc, char *const *argv)
{
	int c;
	char *conf = NULL;

	while ((c = getopt(argc, argv, "f:")) != EOF)
		switch (c) {
		case 'f':
			conf = optarg;
			break;
		default:
			break;
		}

	if (conf != NULL) {
		char	*prefix = "SLP_CONF_FILE=";
		int	env_size;
		char	*conf_env;

		env_size = strlen(prefix) + strlen(conf) + 1;
		if ((conf_env = malloc(env_size)) == NULL) {
			syslog(LOG_ERR, "no memory");
			exit(1);
		}
		(void) strlcpy(conf_env, prefix, env_size);
		(void) strlcat(conf_env, conf, env_size);

		(void) putenv(conf_env);

		slpd_args[CONF_INDEX] = conf;
	}
}

static void
detachfromtty(void) {
	switch (fork()) {
	case -1:
		perror("slpd: can not fork");
		exit(1);
		/*NOTREACHED*/
	case 0:
		break;
	default:
		exit(0);
	}

	/*
	 * Close existing file descriptors, open "/dev/null" as
	 * standard input, output, and error, and detach from
	 * controlling terminal.
	 */
	closefrom(0);
	(void) open("/dev/null", O_RDONLY);
	(void) open("/dev/null", O_WRONLY);
	(void) dup(1);
	(void) setsid();
}

static void
cleanup_and_exit(int retval)
{
	closelog();
	exit(retval);
}

int
main(int argc, char *const *argv)
{
	struct sockaddr_in bindaddr;
	socklen_t addrlen;
	const char *isDA;
	const char *proxyReg;
	int connfd;
	int lfd;
	const int on = 1;

	detachfromtty();

	openlog("slpd", LOG_PID, LOG_DAEMON);

	do_args(argc, argv);

	/* If slpd has been configured to run as a DA, start it and exit */
	isDA = SLPGetProperty("net.slp.isDA");
	proxyReg = SLPGetProperty("net.slp.serializedRegURL");
	if ((isDA && (strcasecmp(isDA, "true") == 0)) || proxyReg) {
		run_slpd();
		return (1);
	}

	if ((lfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		syslog(LOG_ERR, "socket failed: %s", strerror(errno));
		cleanup_and_exit(1);
	}

	(void) setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof (on));

	(void) memset((void *)&bindaddr, 0, sizeof (bindaddr));
	bindaddr.sin_family = AF_INET;
	bindaddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	bindaddr.sin_port = htons(427);

	if (bind(lfd, (const struct sockaddr *)&bindaddr, sizeof (bindaddr))
	    < 0) {
		syslog(LOG_ERR, "bind failed: %s", strerror(errno));
		cleanup_and_exit(1);
	}

	if (listen(lfd, 1) < 0) {
		syslog(LOG_ERR, "listen failed: %s", strerror(errno));
		cleanup_and_exit(1);
	}

	addrlen = sizeof (bindaddr);
	if ((connfd = accept(lfd, (struct sockaddr *)&bindaddr, &addrlen))
	    < 0) {
		syslog(LOG_ERR, "accept failed: %s", strerror(errno));
		cleanup_and_exit(1);
	}

	(void) close(lfd);

	(void) dup2(connfd, 0);
	(void) close(connfd);
	(void) dup2(0, 1);
	(void) dup2(0, 2);

	run_slpd();

	return (1);
}
