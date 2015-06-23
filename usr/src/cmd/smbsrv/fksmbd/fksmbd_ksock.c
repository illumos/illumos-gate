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
 * fork/exec a privileged helper to do the bind.
 */

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/note.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int
ksocket_bind_helper(int fd, struct sockaddr *addr, uint_t addrlen)
{
	char familystr[8];
	char portstr[12];
	char addrstr[INET6_ADDRSTRLEN];
	char *argv[6];
	const char *p;
	/* LINTED E_BAD_PTR_CAST_ALIGN */
	struct sockaddr_in  *sin  = (struct sockaddr_in *)addr;
	/* LINTED E_BAD_PTR_CAST_ALIGN */
	struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)addr;
	int pid, err, stat;
	_NOTE(ARGUNUSED(addrlen));

	(void) snprintf(familystr, sizeof (familystr), "%d", addr->sa_family);
	switch (addr->sa_family) {
	case AF_INET:
		(void) snprintf(portstr, sizeof (portstr), "%d",
		    ntohs(sin->sin_port));
		p = inet_ntop(AF_INET, &sin->sin_addr,
		    addrstr, sizeof (addrstr));
		break;
	case AF_INET6:
		(void) snprintf(portstr, sizeof (portstr), "%d",
		    ntohs(sin6->sin6_port));
		p = inet_ntop(AF_INET6, &sin6->sin6_addr,
		    addrstr, sizeof (addrstr));
		break;
	default:
		p = NULL;
		break;
	}
	if (p == NULL) {
		err = errno;
		(void) fprintf(stdout, "ksocket_bind_helper, inet_ntop %s\n",
		    strerror(err));
		return (err);
	}

	(void) fprintf(stdout, "ksocket_bind_helper, "
	    "family=%s addr=%s port=%s\n",
	    familystr, addrstr, portstr);

	argv[0] = "/usr/bin/pfexec";
	argv[1] = "/usr/lib/smbsrv/bind-helper";
	argv[2] = familystr;
	argv[3] = addrstr;
	argv[4] = portstr;
	argv[5] = NULL;

	pid = vfork();
	if (pid == -1) {
		err = errno;
		perror("fork");
		return (err);
	}
	if (pid == 0) {
		(void) dup2(fd, 0);
		(void) execv(argv[0], argv);
		err = errno;
		perror("execv");
		return (err);
	}
	err = waitpid(pid, &stat, 0);
	if (err == -1) {
		err = errno;
		perror("waitpid");
		return (err);
	}
	if (WIFEXITED(stat)) {
		err = WEXITSTATUS(stat);
		if (err == 0)
			return (0);
		(void) fprintf(stderr, "helper exit %d\n", err);
	}
	return (EACCES);
}
