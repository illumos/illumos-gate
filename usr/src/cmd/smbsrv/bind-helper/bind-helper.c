/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * This program is installed with an RBAC exec_attr
 * that allows it to bind a reserved address.
 * (Or just make it setuid root.)
 *
 * To grant privileges to the program using RBAC,
 * add the following line to /etc/security/exec_attr
 *	Forced Privilege:solaris:cmd:::\
 *	/usr/lib/smbsrv/bind-helper:\
 *	privs=net_privaddr,sys_smb\
 *
 * Args: family address port
 * Does a bind on fileno(stdin)
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int
main(int argc, char **argv)
{
	struct sockaddr sa;
	/* LINTED E_BAD_PTR_CAST_ALIGN */
	struct sockaddr_in  *sin  = (struct sockaddr_in *)&sa;
	/* LINTED E_BAD_PTR_CAST_ALIGN */
	struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&sa;
	int rc, err = 0;

	if (argc < 4) {
		(void) fprintf(stderr, "usage: %s family address port\n",
		    argv[0]);
		exit(1);
	}

	(void) memset(&sa, 0, sizeof (sa));
	sa.sa_family = atoi(argv[1]);
	switch (sa.sa_family) {
	case AF_INET:
		rc = inet_pton(AF_INET, argv[2], &sin->sin_addr);
		sin->sin_port = htons(atoi(argv[3]));
		break;
	case AF_INET6:
		rc = inet_pton(AF_INET6, argv[2], &sin6->sin6_addr);
		sin6->sin6_port = htons(atoi(argv[3]));
		break;
	default:
		rc = 0;
		break;
	}

	if (rc > 0)
		err = 0;
	else if (rc == 0)
		err = EINVAL;
	else if (rc < 0)
		err = errno;
	if (err != 0) {
		(void) fprintf(stderr, "%s: bad proto addr %s %s %s\n",
		    argv[0], argv[1], argv[2], argv[3]);
		exit(1);
	}

	if (bind(0, &sa, sizeof (sa)) < 0) {
		err = errno;
		(void) fprintf(stderr, "%s: bind: %s\n",
		    argv[0], strerror(err));
		exit(2);
	}
	exit(0);
}
