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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * efdaemon - Emebbed Fcode Interpreter daemon.
 *
 * Opens /dev/fcode, detaches from tty and reads a request.  Upon successful
 * return, invokes the Fcode interpreter via the shell script:
 * /usr/lib/efcode/efcode.sh  Waits for completion of the interpreter.
 */

#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <strings.h>
#include <syslog.h>
#include <errno.h>
#include <sys/wait.h>
#include <sys/fcode.h>

char efcode_sh_file[] = "/usr/lib/efcode/efcode.sh";
char dev_fcode_file[] = "/dev/fcode";

int debug = 0;

int
main(int argc, char **argv)
{
	extern char *optarg;
	extern int optind, opterr, optopt;
	int c, fd, nbytes, status;
	char tc;
	pid_t pid, tpid;
	long nerr = 0;
	int error;

	openlog("efdaemon", LOG_PID|LOG_CONS, LOG_DAEMON);

	while ((c = getopt(argc, argv, "d")) != EOF) {
		switch (c) {

		case 'd':
			debug++;
			break;

		case '?':
			syslog(LOG_ERR, "Usage: efdaemon [ -d ]\n");
			exit(1);
		}
	}

	/*
	 * Ensure we can open /dev/fcode
	 */
	if ((fd = open(dev_fcode_file, O_RDONLY)) < 0) {
		/*
		 * Only output message if debug is on.  On most systems,
		 * /dev/fcode will not exist, so this message would pollute the
		 * console.
		 */
		if (debug)
			syslog(LOG_ERR, "Can't open %s: %s\n", dev_fcode_file,
			    strerror(errno));
		exit(1);
	}
	close(fd);

	/*
	 * Ensure that /usr/lib/efcode/efcode.sh exists and is executable.
	 */
	if (access(efcode_sh_file, X_OK | R_OK)) {
		syslog(LOG_ERR, "%s: %s\n", efcode_sh_file, strerror(errno));
		exit(1);
	}

	/*
	 * Fork a child then parent exits so we're a child of initd.
	 */
	if ((pid = fork()) < 0) {
		syslog(LOG_ERR, "Fork failed: %s\n", strerror(errno));
		exit(1);
	}
	if (pid)
		exit(0);


	/*
	 * detach from tty here.
	 */
	setpgrp();
	close(0);
	close(1);
	close(2);
	(void) open("/dev/null", O_RDWR);
	(void) dup(0);
	(void) dup(0);

	for (;;) {
		while ((fd = open(dev_fcode_file, O_RDONLY)) < 0) {
			nerr++;
			if (nerr == 1)
				syslog(LOG_ERR, "Can't open %s: %s\n",
				    dev_fcode_file, strerror(errno));
			sleep(1);
		}
		if (nerr > 1) {
			syslog(LOG_ERR, "Open on %s failed %d times\n",
			    dev_fcode_file, nerr);
		}
		nerr = 0;
		nbytes = read(fd, &tc, sizeof (tc));
		if (nbytes < 0) {
			syslog(LOG_ERR, "Read of %s: %s\n", dev_fcode_file,
			    strerror(errno));
			close(fd);
			continue;
		}
		if (debug)
			syslog(LOG_DEBUG, "Got request\n");
		while ((pid = fork()) < 0) {
			nerr++;
			if (nerr == 1)
				syslog(LOG_ERR, "Fork failed: %s\n",
				    strerror(errno));
			sleep(1);
		}
		if ((nerr > 1) && pid) {
			syslog(LOG_ERR, "Fork failed %d times\n", nerr);
		}
		nerr = 0;
		if (pid) {
			tpid = wait(&status);
			if (tpid < 0)
				syslog(LOG_ERR, "Wait error: %s\n",
				    strerror(errno));
			else if (pid != tpid)
				syslog(LOG_ERR, "Wait error, expect pid: %d"
				    " got %d, status: %x\n", pid, tpid, status);
			else if (status) {
				syslog(LOG_ERR, "Wait pid: %d status: %x\n",
				    pid, status);
				if (WIFEXITED(status) &&
				    (WEXITSTATUS(status) == 1)) {
					error = FC_FCODE_ABORT;
				} else {
					error = FC_EXEC_FAILED;
				}
				if (ioctl(fd, FC_SET_FCODE_ERROR, &error) < 0) {
					syslog(LOG_ERR,
					    "ioctl(FC_SET_FCODE_ERROR)"
					    " failed\n");
				}
			} else if (debug)
				syslog(LOG_DEBUG, "Wait: pid: %d\n", pid);
			close(fd);
			continue;
		}
		if (debug)
			syslog(LOG_DEBUG, "Child: %d processing request\n",
			    getpid());
		fcntl(fd, F_DUP2FD, 0);
		while (execl("/bin/sh", "sh", efcode_sh_file, NULL)) {
			nerr++;
			if (nerr == 1)
				syslog(LOG_ERR, "execl(/bin/sh) failed: %s\n",
				    strerror(errno));
			sleep(1);
		}
	}

	return (0);
}
