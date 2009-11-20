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

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

#include <limits.h>
#include <stdio.h>
#include <ctype.h>
#include <pwd.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/file.h>
#include <signal.h>
#include <libintl.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include <netinet/in.h>
#include <netinet/tcp.h>
#include <inet/common.h>

#include <netdb.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <grp.h>
#include <alloca.h>
#include <arpa/inet.h>

#include <priv_utils.h>

#ifdef SYSV
#define	bcopy(s1, s2, len)	(void) memcpy(s2, s1, len)
#define	bzero(s, len)		(void) memset(s, 0, len)
#define	index(s, c)		strchr(s, c)
char	*strchr();
#else
char	*index();
#endif /* SYSV */

extern int  usingypmap();

static int _validuser(FILE *hostf, char *rhost, const char *luser,
			const char *ruser, int baselen);
static int _checkhost(char *rhost, char *lhost, int len);


#ifdef NIS
static char *domain;
#endif

int rcmd(char **ahost, unsigned short rport, const char *locuser,
    const char *remuser, const char *cmd, int *fd2p)
{
	int rcmd_ret;

	rcmd_ret = rcmd_af(ahost, rport, locuser, remuser, cmd, fd2p,
	    AF_INET);
	return (rcmd_ret);
}

int rcmd_af(char **ahost, unsigned short rport, const char *locuser,
    const char *remuser, const char *cmd, int *fd2p, int af)
{
	int s, timo = 1;
	ssize_t retval;
	pid_t pid;
	struct sockaddr_storage caddr, faddr;
	struct sockaddr_in *sin;
	struct sockaddr_in6 *sin6;
	struct addrinfo hints;
	struct addrinfo *res, *resp;
	size_t addrlen;
	int rc;
#define	MAX_SHORTSTRLEN 6
	char aport[MAX_SHORTSTRLEN];
	char c;
	int lport = 0;
#ifdef SYSV
	sigset_t oldmask;
	sigset_t newmask;
	struct sigaction oldaction;
	struct sigaction newaction;
#else
	int oldmask;
#endif /* SYSV */
	fd_set fdset;
	int selret;
	char *addr;
	static char hostname[MAXHOSTNAMELEN];
	socklen_t len;
	char abuf[INET6_ADDRSTRLEN];

	if (!(af == AF_INET || af == AF_INET6 || af == AF_UNSPEC)) {
		errno = EAFNOSUPPORT;
		return (-1);
	}

	pid = getpid();
	memset(&hints, 0, sizeof (hints));
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_CANONNAME;
	if (af == AF_INET6) {
		hints.ai_flags |= AI_V4MAPPED;
		hints.ai_family = AF_UNSPEC;
	} else {
		hints.ai_family = af;
	}
	(void) snprintf(aport, MAX_SHORTSTRLEN, "%u", ntohs(rport));
	rc = getaddrinfo(*ahost, aport, &hints, &res);
	if (rc != 0) {
		(void) fprintf(stderr,
		    dgettext(TEXT_DOMAIN, "%s: unknown host%s\n"),
		    *ahost, rc == EAI_AGAIN ? " (try again later)" : "");
		return (-1);
	}
	resp = res;
	(void) strlcpy(hostname, res->ai_canonname, MAXHOSTNAMELEN);
	*ahost = hostname;
#ifdef SYSV
	/* ignore SIGPIPE */
	bzero((char *)&newaction, sizeof (newaction));
	newaction.sa_handler = SIG_IGN;
	(void) sigaction(SIGPIPE, &newaction, &oldaction);

	/* block SIGURG */
	bzero((char *)&newmask, sizeof (newmask));
	(void) sigaddset(&newmask, SIGURG);
	(void) sigprocmask(SIG_BLOCK, &newmask, &oldmask);
#else
	oldmask = _sigblock(sigmask(SIGURG));
#endif /* SYSV */
	for (;;) {
		s = rresvport_af(&lport, res->ai_family);
		if (s < 0) {
			int af = res->ai_family;

			/*
			 * See if we have any addresses of a different type
			 * to try.
			 */
			while (res != NULL && res->ai_family == af)
				res = res->ai_next;

			if (res != NULL)
				continue;

			if (errno == EAGAIN)
				(void) fprintf(stderr,
				    dgettext(TEXT_DOMAIN,
				    "socket: All ports in use\n"));
			else
				perror("rcmd: socket");
#ifdef SYSV
			/* restore original SIGPIPE handler */
			(void) sigaction(SIGPIPE, &oldaction,
			    (struct sigaction *)0);

			/* restore original signal mask */
			(void) sigprocmask(SIG_SETMASK, &oldmask,
			    (sigset_t *)0);
#else
			sigsetmask(oldmask);
#endif /* SYSV */
			freeaddrinfo(resp);
			return (-1);
		}
		bzero((char *)&caddr, sizeof (caddr));
		bcopy(res->ai_addr, &caddr, res->ai_addrlen);
		addrlen = res->ai_addrlen;
		if (af == AF_INET6 && res->ai_addr->sa_family == AF_INET) {
			struct in6_addr ia6;
			struct sockaddr_in6 *in6addr;
			IN6_INADDR_TO_V4MAPPED(&((struct sockaddr_in *)
			    res->ai_addr)->sin_addr, &ia6);
			in6addr = (struct sockaddr_in6 *)&caddr;
			in6addr->sin6_addr = ia6;
			in6addr->sin6_family = AF_INET6;
			addrlen = sizeof (struct sockaddr_in6);
		}
		(void) fcntl(s, F_SETOWN, pid);
		if (connect(s, (struct sockaddr *)&caddr, addrlen) >= 0)
			break;
		(void) close(s);
		if (errno == EADDRINUSE) {
			lport = 0;
			continue;
		}
		if (errno == ECONNREFUSED && timo <= 16) {
			(void) sleep(timo);
			timo *= 2;
			continue;
		}
		if (res->ai_next != NULL) {
			int oerrno = errno;
			if (res->ai_addr->sa_family == AF_INET6)
				addr = (char *)&((struct sockaddr_in6 *)
				    res->ai_addr)->sin6_addr;
			else
				addr = (char *)&((struct sockaddr_in *)
				    res->ai_addr)->sin_addr;
			(void) fprintf(stderr,
			    dgettext(TEXT_DOMAIN, "connect to address %s: "),
			    inet_ntop(res->ai_addr->sa_family, addr,
			    abuf, sizeof (abuf)));
			errno = oerrno;
			perror(0);
			res = res->ai_next;
			if (res->ai_addr->sa_family == AF_INET6)
				addr = (char *)&((struct sockaddr_in6 *)
				    res->ai_addr)->sin6_addr;
			else
				addr = (char *)&((struct sockaddr_in *)
				    res->ai_addr)->sin_addr;
			(void) fprintf(stderr,
			    dgettext(TEXT_DOMAIN, "Trying %s...\n"),
			    inet_ntop(res->ai_addr->sa_family, addr,
			    abuf, sizeof (abuf)));
			continue;
		}
		perror(*ahost);
		freeaddrinfo(resp);
#ifdef SYSV
		/* restore original SIGPIPE handler */
		(void) sigaction(SIGPIPE, &oldaction,
		    (struct sigaction *)0);

		/* restore original signal mask */
		(void) sigprocmask(SIG_SETMASK, &oldmask, (sigset_t *)0);
#else
		sigsetmask(oldmask);
#endif /* SYSV */
		return (-1);
	}
	lport = 0;
	if (fd2p == 0) {
		(void) write(s, "", 1);
	} else {
		int s2 = rresvport_af(&lport, res->ai_family), s3;

		len = (socklen_t)sizeof (faddr);

		if (s2 < 0)
			goto bad;
		(void) listen(s2, 1);
		(void) snprintf(aport, MAX_SHORTSTRLEN, "%d", lport);
		if (write(s, aport, strlen(aport)+1) != strlen(aport)+1) {
			perror(dgettext(TEXT_DOMAIN,
			    "write: setting up stderr"));
			(void) close(s2);
			goto bad;
		}
		FD_ZERO(&fdset);
		FD_SET(s, &fdset);
		FD_SET(s2, &fdset);
		while ((selret = select(FD_SETSIZE, &fdset, (fd_set *)0,
		    (fd_set *)0, (struct timeval *)0)) > 0) {
			if (FD_ISSET(s, &fdset)) {
				/*
				 *	Something's wrong:  we should get no
				 *	data on this connection at this point,
				 *	so we assume that the connection has
				 *	gone away.
				 */
				(void) close(s2);
				goto bad;
			}
			if (FD_ISSET(s2, &fdset)) {
				/*
				 *	We assume this is an incoming connect
				 *	request and proceed normally.
				 */
				s3 = accept(s2, (struct sockaddr *)&faddr,
				    &len);
				FD_CLR(s2, &fdset);
				(void) close(s2);
				if (s3 < 0) {
					perror("accept");
					lport = 0;
					goto bad;
				}
				else
					break;
			}
		}
		if (selret == -1) {
			/*
			 *	This should not happen, and we treat it as
			 *	a fatal error.
			 */
			(void) close(s2);
			goto bad;
		}

		*fd2p = s3;
		switch (faddr.ss_family) {
		case AF_INET:
			sin = (struct sockaddr_in *)&faddr;
			if (ntohs(sin->sin_port) >= IPPORT_RESERVED) {
				(void) fprintf(stderr,
				    dgettext(TEXT_DOMAIN,
				    "socket: protocol failure in circuit "
				    "setup.\n"));
				goto bad2;
			}
			break;
		case AF_INET6:
			sin6 = (struct sockaddr_in6 *)&faddr;
			if (ntohs(sin6->sin6_port) >= IPPORT_RESERVED) {
				(void) fprintf(stderr,
				    dgettext(TEXT_DOMAIN,
				    "socket: protocol failure in circuit "
				    "setup.\n"));
				goto bad2;
			}
			break;
		default:
			(void) fprintf(stderr,
			    dgettext(TEXT_DOMAIN,
			    "socket: protocol failure in circuit setup.\n"));
			goto bad2;
		}
	}
	(void) write(s, locuser, strlen(locuser)+1);
	(void) write(s, remuser, strlen(remuser)+1);
	(void) write(s, cmd, strlen(cmd)+1);
	retval = read(s, &c, 1);
	if (retval != 1) {
		if (retval == 0) {
			(void) fprintf(stderr,
			    dgettext(TEXT_DOMAIN,
			    "Protocol error, %s closed connection\n"),
			    *ahost);
		} else if (retval < 0) {
			perror(*ahost);
		} else {
			(void) fprintf(stderr,
			    dgettext(TEXT_DOMAIN,
			    "Protocol error, %s sent %d bytes\n"),
			    *ahost, retval);
		}
		goto bad2;
	}
	if (c != 0) {
		while (read(s, &c, 1) == 1) {
			(void) write(2, &c, 1);
			if (c == '\n')
				break;
		}
		goto bad2;
	}
#ifdef SYSV
	/* restore original SIGPIPE handler */
	(void) sigaction(SIGPIPE, &oldaction, (struct sigaction *)0);

	/* restore original signal mask */
	(void) sigprocmask(SIG_SETMASK, &oldmask, (sigset_t *)0);
#else
	sigsetmask(oldmask);
#endif /* SYSV */
	freeaddrinfo(resp);
	return (s);
bad2:
	if (lport)
		(void) close(*fd2p);
bad:
	(void) close(s);
#ifdef SYSV
	/* restore original SIGPIPE handler */
	(void) sigaction(SIGPIPE, &oldaction, (struct sigaction *)0);

	/* restore original signal mask */
	(void) sigprocmask(SIG_SETMASK, &oldmask, (sigset_t *)0);
#else
	sigsetmask(oldmask);
#endif /* SYSV */
	freeaddrinfo(resp);
	return (-1);
}

static int
_rresvport_addr(int *alport, struct sockaddr_storage *addr)
{
	struct sockaddr_in *sin;
	struct sockaddr_in6 *sin6;
	int s;
	socklen_t len;
	int on = 1;
	int off = 0;

	if (addr->ss_family == AF_INET) {
		sin = (struct sockaddr_in *)addr;
		len = sizeof (struct sockaddr_in);
	} else if (addr->ss_family == AF_INET6) {
		sin6 = (struct sockaddr_in6 *)addr;
		len = sizeof (struct sockaddr_in6);
	} else {
		errno = EAFNOSUPPORT;
		return (-1);
	}
	s = socket(addr->ss_family, SOCK_STREAM, 0);
	if (s < 0)
		return (-1);

	/*
	 * Set SO_EXCLBIND to get a "unique" port, which is not bound
	 * to any other sockets.
	 */
	if (setsockopt(s, SOL_SOCKET, SO_EXCLBIND, &on, sizeof (on)) < 0) {
		(void) close(s);
		return (-1);
	}

	/* Try to bind() to the given port first. */
	if (*alport != 0) {
		if (addr->ss_family == AF_INET) {
			sin->sin_port = htons((ushort_t)*alport);
		} else {
			sin6->sin6_port = htons((ushort_t)*alport);
		}
		if (bind(s, (struct sockaddr *)addr, len) >= 0) {
			/* To be safe, need to turn off SO_EXCLBIND. */
			(void) setsockopt(s, SOL_SOCKET, SO_EXCLBIND, &off,
			    sizeof (off));
			return (s);
		}
		if (errno != EADDRINUSE) {
			(void) close(s);
			return (-1);
		}
	}

	/*
	 * If no port is given or the above bind() does not succeed, set
	 * TCP_ANONPRIVBIND option to ask the kernel to pick a port in the
	 * priviledged range for us.
	 */
	if (setsockopt(s, IPPROTO_TCP, TCP_ANONPRIVBIND, &on,
	    sizeof (on)) < 0) {
		(void) close(s);
		return (-1);
	}
	if (addr->ss_family == AF_INET) {
		sin->sin_port = 0;
	} else {
		sin6->sin6_port = 0;
	}
	if (bind(s, (struct sockaddr *)addr, len) >= 0) {
		/*
		 * We need to tell the caller what the port is.
		 */
		if (getsockname(s, (struct sockaddr *)addr, &len) < 0) {
			(void) close(s);
			return (-1);
		}
		switch (addr->ss_family) {
		case AF_INET6:
			sin6 = (struct sockaddr_in6 *)addr;
			*alport = ntohs(sin6->sin6_port);
			break;
		case AF_INET:
			sin = (struct sockaddr_in *)addr;
			*alport = ntohs(sin->sin_port);
			break;
		}

		/*
		 * To be safe, always turn off these options when we are done.
		 */
		(void) setsockopt(s, IPPROTO_TCP, TCP_ANONPRIVBIND, &off,
		    sizeof (off));
		(void) setsockopt(s, SOL_SOCKET, SO_EXCLBIND, &off,
		    sizeof (off));
		return (s);
	}
	(void) close(s);
	return (-1);
}

int
rresvport_addr(int *alport, struct sockaddr_storage *addr)
{
	int res, err;

	(void) __priv_bracket(PRIV_ON);

	res = _rresvport_addr(alport, addr);

	err = errno;
	(void) __priv_bracket(PRIV_OFF);
	errno = err;

	return (res);
}

int
rresvport_af(int *alport, int af)
{
	struct sockaddr_storage laddr;

	bzero(&laddr, sizeof (laddr));
	if (af == AF_INET || af == AF_INET6) {
		laddr.ss_family = (sa_family_t)af;
	} else {
		errno = EAFNOSUPPORT;
		return (-1);
	}
	return (rresvport_addr(alport, &laddr));
}

int
rresvport(int *alport)
{
	return (rresvport_af(alport, AF_INET));
}

int
ruserok(const char *rhost, int superuser, const char *ruser, const char *luser)
{
	FILE *hostf;
	char fhost[MAXHOSTNAMELEN];
	const char *sp;
	char *p;
	int baselen = -1;

	struct stat64 sbuf;
	struct passwd *pwd;
	char pbuf[MAXPATHLEN];
	uid_t uid = (uid_t)-1;
	gid_t gid = (gid_t)-1;
	int maxgrp = getgroups(0, NULL);
	gid_t *grouplist = alloca(maxgrp * sizeof (gid_t));
	int ngroups;

	sp = rhost;
	p = fhost;
	while (*sp) {
		if (*sp == '.') {
			if (baselen == -1)
				baselen = (int)(sp - rhost);
			*p++ = *sp++;
		} else {
			*p++ = isupper(*sp) ? tolower(*sp++) : *sp++;
		}
	}
	*p = '\0';

	/* check /etc/hosts.equiv */
	if (!superuser) {
		if ((hostf = fopen("/etc/hosts.equiv", "rF")) != NULL) {
			if (!_validuser(hostf, fhost, luser, ruser, baselen)) {
				(void) fclose(hostf);
				return (0);
			}
			(void) fclose(hostf);
		}
	}

	/* check ~/.rhosts */

	if ((pwd = getpwnam(luser)) == NULL)
		return (-1);
	(void) strcpy(pbuf, pwd->pw_dir);
	(void) strcat(pbuf, "/.rhosts");

	/*
	 * Read .rhosts as the local user to avoid NFS mapping the root uid
	 * to something that can't read .rhosts.
	 */
	gid = getegid();
	uid = geteuid();
	if ((ngroups = getgroups(maxgrp, grouplist)) == -1)
		return (-1);

	(void) setegid(pwd->pw_gid);
	initgroups(pwd->pw_name, pwd->pw_gid);
	(void) seteuid(pwd->pw_uid);
	if ((hostf = fopen(pbuf, "rF")) == NULL) {
		if (gid != (gid_t)-1)
			(void) setegid(gid);
		if (uid != (uid_t)-1)
			(void) seteuid(uid);
		setgroups(ngroups, grouplist);
		return (-1);
	}
	(void) fstat64(fileno(hostf), &sbuf);
	if (sbuf.st_uid && sbuf.st_uid != pwd->pw_uid) {
		(void) fclose(hostf);
		if (gid != (gid_t)-1)
			(void) setegid(gid);
		if (uid != (uid_t)-1)
			(void) seteuid(uid);
		setgroups(ngroups, grouplist);
		return (-1);
	}

	if (!_validuser(hostf, fhost, luser, ruser, baselen)) {
		(void) fclose(hostf);
		if (gid != (gid_t)-1)
			(void) setegid(gid);
		if (uid != (uid_t)-1)
			(void) seteuid(uid);
		setgroups(ngroups, grouplist);
		return (0);
	}

	(void) fclose(hostf);
	if (gid != (gid_t)-1)
		(void) setegid(gid);
	if (uid != (uid_t)-1)
		(void) seteuid(uid);
	setgroups(ngroups, grouplist);
	return (-1);
}

static int
_validuser(FILE *hostf, char *rhost, const char *luser,
    const char *ruser, int baselen)
{
	char *user;
	char ahost[BUFSIZ];
	char *uchost = (char *)NULL;
	int hostmatch, usermatch;
	char *p;

#ifdef NIS
	if (domain == NULL) {
		(void) usingypmap(&domain, NULL);
	}
#endif /* NIS */

	while (fgets(ahost, (int)sizeof (ahost), hostf)) {
		uchost = (char *)NULL;
		hostmatch = usermatch = 0;
		p = ahost;
		/*
		 * We can get a line bigger than our buffer.  If so we skip
		 * the offending line.
		 */
		if (strchr(p, '\n') == NULL) {
			while (fgets(ahost, (int)sizeof (ahost), hostf) &&
			    strchr(ahost, '\n') == NULL)
				;
			continue;
		}
		while (*p != '\n' && *p != ' ' && *p != '\t' && *p != '\0') {
			/*
			 *	Both host and user ``names'' can be netgroups,
			 *	and must have their case preserved.  Case is
			 *	preserved for user names because we break out
			 *	of this loop when finding a field separator.
			 *	To do so for host names, we must make a copy of
			 *	the host name field.
			 */
			if (isupper(*p)) {
				if (uchost == (char *)NULL)
					uchost = strdup(ahost);
				*p = tolower(*p);
			}
			p++;
		}
		if (*p != '\0' && uchost != (char *)NULL)
			uchost[p - ahost] = '\0';
		if (*p == ' ' || *p == '\t') {
			*p++ = '\0';
			while (*p == ' ' || *p == '\t')
				p++;
			user = p;
			while (*p != '\n' && *p != ' ' && *p != '\t' &&
			    *p != '\0')
				p++;
		} else
			user = p;
		*p = '\0';
		if (ahost[0] == '+' && ahost[1] == 0)
			hostmatch = 1;
#ifdef NIS
		else if (ahost[0] == '+' && ahost[1] == '@')
			if (uchost != (char *)NULL)
				hostmatch = innetgr(uchost + 2, rhost,
				    NULL, domain);
			else
				hostmatch = innetgr(ahost + 2, rhost,
				    NULL, domain);
		else if (ahost[0] == '-' && ahost[1] == '@') {
			if (uchost != (char *)NULL) {
				if (innetgr(uchost + 2, rhost, NULL, domain))
					break;
			} else {
				if (innetgr(ahost + 2, rhost, NULL, domain))
					break;
			}
		}
#endif /* NIS */
		else if (ahost[0] == '-') {
			if (_checkhost(rhost, ahost+1, baselen))
				break;
		}
		else
			hostmatch = _checkhost(rhost, ahost, baselen);
		if (user[0]) {
			if (user[0] == '+' && user[1] == 0)
				usermatch = 1;
#ifdef NIS
			else if (user[0] == '+' && user[1] == '@')
				usermatch = innetgr(user+2, NULL,
				    ruser, domain);
			else if (user[0] == '-' && user[1] == '@') {
				if (hostmatch &&
				    innetgr(user+2, NULL, ruser, domain))
					break;
			}
#endif /* NIS */
			else if (user[0] == '-') {
				if (hostmatch && (strcmp(user+1, ruser) == 0))
					break;
			}
			else
				usermatch = (strcmp(user, ruser) == 0);
		}
		else
			usermatch = (strcmp(ruser, luser) == 0);
		if (uchost != (char *)NULL)
			free(uchost);
		if (hostmatch && usermatch)
			return (0);
	}

	if (uchost != (char *)NULL)
		free(uchost);
	return (-1);
}

static int
_checkhost(char *rhost, char *lhost, int len)
{
	static char *ldomain;
	static char *domainp;
	static int nodomain;
	char *cp;

	if (ldomain == NULL) {
		ldomain = (char *)malloc(MAXHOSTNAMELEN+1);
		if (ldomain == 0)
			return (0);
	}

	if (len == -1)
		return (strcmp(rhost, lhost) == 0);
	if (strncmp(rhost, lhost, len))
		return (0);
	if (strcmp(rhost, lhost) == 0)
		return (1);
	if (*(lhost + len) != '\0')
		return (0);
	if (nodomain)
		return (0);
	if (!domainp) {
		/*
		 * "domainp" points after the first dot in the host name
		 */
		if (gethostname(ldomain, MAXHOSTNAMELEN) == -1) {
			nodomain = 1;
			return (0);
		}
		ldomain[MAXHOSTNAMELEN] = NULL;
		if ((domainp = index(ldomain, '.')) == (char *)NULL) {
			nodomain = 1;
			return (0);
		}
		domainp++;
		cp = domainp;
		while (*cp) {
			*cp = isupper(*cp) ? tolower(*cp) : *cp;
			cp++;
		}
	}
	return (strcmp(domainp, rhost + len + 1) == 0);
}
