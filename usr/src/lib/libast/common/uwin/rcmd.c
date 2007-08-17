#include "FEATURE/uwin"

#if !_UWIN || _lib_rcmd

void _STUB_rcmd(){}

#else

/*
 * Copyright (c) 1983
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#if defined(LIBC_SCCS) && !defined(lint)
static char sccsid[] = "@(#)rcmd.c	5.17 (Berkeley) 6/27/88";
#endif /* LIBC_SCCS and not lint */

#include "rlib.h"
#include <pwd.h>
#include <sys/file.h>
#include <sys/signal.h>
#if 1
#define _PATH_HEQUIV	"/etc/hosts.equiv"
#endif
#include <sys/stat.h>

#if NLS
#include "nl_types.h"
#endif

#ifdef YP
#include <rpcsvc/ypclnt.h>
extern void setnetgrent(const char *);
extern void endnetgrent(void);
extern int getnetgrent(char **, char **, char **);
static char *nisdomain = NULL;
static int _checknetgrouphost(const char *, const char *, int);
static int _checknetgroupuser(const char *, const char *);
#endif

#if defined(__EXPORT__)
#define extern		__EXPORT__
#endif

extern int rresvport(int *alport)
{
	struct sockaddr_in sin;
	int s;

	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = INADDR_ANY;
	s = socket(AF_INET, SOCK_STREAM, 0);
	if (s < 0)
		return (-1);
	for (;;) {
		sin.sin_port = htons((u_short)*alport);
		if (bind(s, (struct sockaddr *)&sin, sizeof (sin)) >= 0)
			return (s);
		if (errno != EADDRINUSE) {
			(void) close(s);
			return (-1);
		}
		(*alport)--;
		if (*alport == IPPORT_RESERVED/2) {
			(void) close(s);
			errno = EAGAIN;		/* close */
			return (-1);
		}
	}
}

extern int rcmd(char **ahost, unsigned short rport, const char *locuser, const char *remuser, const char *cmd, int *fd2p)
{
	int s, timo = 1;
#ifdef F_SETOWN
	pid_t pid;
#endif
#ifdef _POSIX_SOURCE
	sigset_t set, oset;
#else
	long oldmask;
#endif
	struct sockaddr_in sin, from;
	char c;
	int lport = IPPORT_RESERVED - 1;
	struct hostent *hp;

#if NLS
	libc_nls_init();
#endif

#ifdef F_SETOWN
	pid = getpid();
#endif
	hp = gethostbyname(*ahost);
	if (hp == 0) {
#if NLS
		fprintf(stderr, "%s: %s\n", *ahost,
		    catgets(_libc_cat, HerrorListSet,
		    2, "unknown host"));
#else
		fprintf(stderr, "%s: unknown host\n", *ahost);
#endif
		return (-1);
	}
	*ahost = hp->h_name;
#ifdef SIGURG
#ifdef _POSIX_SOURCE
	sigemptyset (&set);
	sigaddset (&set, SIGURG);
	sigprocmask (SIG_BLOCK, &set, &oset);
#else
	oldmask = sigblock(sigmask(SIGURG));
#endif
#endif
	for (;;) {
		s = rresvport(&lport);
		if (s < 0) {
			if (errno == EAGAIN)
#if NLS
				fprintf(stderr, "socket: %s\n",
				    catgets(_libc_cat, NetMiscSet,
				    NetMiscAllPortsInUse,
				    "All ports in use"));
#else
			fprintf(stderr, "socket: All ports in use\n");
#endif
			else
#if NLS
	perror(catgets(_libc_cat, NetMiscSet,
	    NetMiscRcmdSocket,
	    "rcmd: socket"));
#else
perror("rcmd: socket");
#endif
#ifdef SIGURG
#ifdef _POSIX_SOURCE
sigprocmask (SIG_SETMASK, &oset,
(sigset_t *)NULL);
#else
sigsetmask(oldmask);
#endif
#endif
return (-1);
		}
#ifdef F_SETOWN
		fcntl(s, F_SETOWN, pid);
#endif
		sin.sin_family = hp->h_addrtype;
		bcopy(hp->h_addr_list[0], (caddr_t)&sin.sin_addr, hp->h_length);
		sin.sin_port = rport;
		if (connect(s, (struct sockaddr *)&sin, sizeof (sin)) >= 0)
			break;
		(void) close(s);
		if (errno == EADDRINUSE) {
			lport--;
			continue;
		}
		if (errno == ECONNREFUSED && timo <= 16) {
			sleep(timo);
			timo *= 2;
			continue;
		}
		if (hp->h_addr_list[1] != NULL) {
			int oerrno = errno;

			fprintf(stderr,
#if NLS
			    "%s %s: ", catgets(_libc_cat, NetMiscSet,
			    NetMiscAllPortsInUse,
			    "connect to address"),
			    inet_ntoa(sin.sin_addr));

#else

			"connect to address %s: ", inet_ntoa(sin.sin_addr));
#endif
			errno = oerrno;
			perror(0);
			hp->h_addr_list++;
			bcopy(hp->h_addr_list[0], (caddr_t)&sin.sin_addr,
			    hp->h_length);

#if NLS
			fprintf(stderr, catgets(_libc_cat, NetMiscSet,
			    NetMiscTrying,
			    "Trying %s...\n"),
#else
			    fprintf(stderr,	"Trying %s...\n",
#endif
			    inet_ntoa(sin.sin_addr));
			    continue;
		}
		perror(hp->h_name);
#ifdef SIGURG
#ifdef _POSIX_SOURCE
		    sigprocmask (SIG_SETMASK, &oset, (sigset_t *)NULL);
#else
		    sigsetmask(oldmask);
#endif
#endif
		    return (-1);
	}
	lport--;
	    if (fd2p == 0) {
		write(s, "", 1);
		    lport = 0;
	} else {
		char num[8];
		    int s2 = rresvport(&lport), s3;
		    int len = sizeof (from);

		    if (s2 < 0)
		    goto bad;
		    listen(s2, 1);
		    (void) snprintf(num, sizeof(num), "%d", lport);
		    if (write(s, num, strlen(num)+1) != strlen(num)+1) {
#if NLS
			perror(catgets(_libc_cat, NetMiscSet,
			    NetMiscSettingUpStderr,
			    "write: setting up stderr"));
#else
			    perror("write: setting up stderr");
#endif
			    (void) close(s2);
			    goto bad;
		}
		s3 = accept(s2, (struct sockaddr *)&from, &len);
		    (void) close(s2);
		    if (s3 < 0) {
#if NLS
			perror(catgets(_libc_cat, NetMiscSet,
			    NetMiscAccept,
			    "accept"));
#else
			    perror("accept");
#endif
			    lport = 0;
			    goto bad;
		}
		*fd2p = s3;
		    from.sin_port = ntohs((u_short)from.sin_port);
		    if (from.sin_family != AF_INET ||
		    from.sin_port >= IPPORT_RESERVED) {
			fprintf(stderr,
#if NLS
			    "%s\n",
			    catgets(_libc_cat, NetMiscSet,
			    NetMiscProtocolFailure,
			    "socket: protocol failure in circuit setup."));
#else
			    "socket: protocol failure in circuit setup.\n");
#endif
			goto bad2;
		}
	}
	(void) write(s, locuser, strlen(locuser)+1);
	(void) write(s, remuser, strlen(remuser)+1);
	(void) write(s, cmd, strlen(cmd)+1);
	if (read(s, &c, 1) != 1) {
		perror(*ahost);
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
#ifdef SIGURG
#ifdef _POSIX_SOURCE
	sigprocmask (SIG_SETMASK, &oset, (sigset_t *)NULL);
#else
	sigsetmask(oldmask);
#endif
#endif
	return (s);
bad2:
	if (lport)
		(void) close(*fd2p);
bad:
	(void) close(s);
#ifdef SIGURG
#ifdef _POSIX_SOURCE
	sigprocmask (SIG_SETMASK, &oset, (sigset_t *)NULL);
#else
	sigsetmask(oldmask);
#endif
#endif
	return (-1);
}

extern int ruserok(const char *rhost, int superuser, const char *ruser, const char *luser)
{
	FILE *hostf;
	char fhost[MAXHOSTNAMELEN];
	int first = 1;
	register const char *sp;
	register char *p;
	int baselen = -1;
	uid_t saveuid;

	saveuid = geteuid();
	sp = rhost;
	p = fhost;
	while (*sp) {
		if (*sp == '.') {
			if (baselen == -1)
				baselen = sp - rhost;
			*p++ = *sp++;
		} else {
			*p++ = isupper(*sp) ? tolower(*sp++) : *sp++;
		}
	}
	*p = '\0';
	hostf = superuser ? (FILE *)0 : fopen(_PATH_HEQUIV, "r");
again:
	if (hostf) {
		if (!_validuser(hostf, fhost, luser, ruser, baselen)) {
			(void) fclose(hostf);
			seteuid(saveuid);
			return(0);
		}
		(void) fclose(hostf);
	}
	if (first == 1) {
		struct stat sbuf;
		struct passwd *pwd;
		char pbuf[MAXPATHLEN];

		first = 0;
		if ((pwd = getpwnam(luser)) == NULL)
			return(-1);
		(void)strcpy(pbuf, pwd->pw_dir);
		(void)strcat(pbuf, "/.rhosts");
		(void)seteuid(pwd->pw_uid);
		if ((hostf = fopen(pbuf, "r")) == NULL) {
			seteuid(saveuid);
			return(-1);
		}
		(void)fstat(fileno(hostf), &sbuf);
		if (sbuf.st_uid && sbuf.st_uid != pwd->pw_uid) {
			fclose(hostf);
			seteuid(saveuid);
			return(-1);
		}
		goto again;
	}
	seteuid(saveuid);
	return (-1);
}

int
_validuser(FILE *hostf, const char *rhost, const char *luser,
const char *ruser, int baselen)
{
	char *user;
	char ahost[MAXHOSTNAMELEN];
	register char *p;
	int hostvalid = 0;
	int uservalid = 0;

	while (fgets(ahost, sizeof (ahost), hostf)) {
		/* We need to get rid of all comments. */
		p = strchr (ahost, '#');
		if (p) *p = '\0';
		p = ahost;
		while (*p != '\n' && *p != ' ' && *p != '\t' && *p != '\0') {
			*p = isupper(*p) ? tolower(*p) : *p;
			p++;
		}
		if (*p == ' ' || *p == '\t') {
			*p++ = '\0';
			while (*p == ' ' || *p == '\t')
				p++;
			user = p;
			while (*p != '\n' && *p != ' ' && *p != '\t' && *p != '\0')
				p++;
		} else
			user = p;
		*p = '\0';
	/* Adding new authentication -Nilendu */

		/* enable all host for + entry */
		if ('+' == ahost[0] && '\0' == ahost[1] )
			hostvalid = 1;

		/* enable all user for + entry */
		if ('+' == user[0] && '\0' == user[1] )
			uservalid = 1;

		/* disable all host for - entry */
		if ('-' == ahost[0] && '\0' == ahost[1] )
			hostvalid = 0;

		/* disable all user for - entry */
		if ('-' == user[0] && '\0' == user[1] )
			uservalid = 0;


#ifdef YP
		/* disable host from -hostname entry */
		if ('-' == ahost[0] && '@' != ahost[1]
		    && _checkhost(rhost, &ahost[1], baselen))
			return -1;
		/* disable host from -@netgroup entry for host */
		if ('-' == ahost[0] && '@' == ahost[1] && '\0' != ahost[2]
		    && _checknetgrouphost(rhost, &ahost[2], baselen))
			return -1;
		/* disable user from -user entry */
		if ('\0' != *user && user[0] == '-' && user[1] != '@'
		    && !strcmp(&user[1], ruser))
			return -1;
		/* disable user from -@netgroup entry for user */
		if ('\0' != *user && user[0] == '-' && user[1] == '@'
		    && user[2] != '\0' && _checknetgroupuser(ruser, &user[2]))
			return -1;
		/* enable host from +@netgroup entry for host */
		if ('+' == ahost[0] && '@' == ahost[1] && '\0' != ahost[2])
			hostvalid = _checknetgrouphost(rhost, &ahost[2], baselen);
			else
			hostvalid = _checkhost(rhost, ahost, baselen);
		/* enable user from +@netgroup entry for user */
		if ('\0' != *user && user[0] == '+'
		    && user[1] == '@' && user[2] != '\0')
			uservalid = _checknetgroupuser(ruser, &user[2]);
			else
			uservalid = !strcmp(ruser, *user ? user : luser);

		if (hostvalid && uservalid)
			return 0;
#else
		hostvalid = hostvalid ? 1 : _checkhost(rhost, ahost, baselen);
	 	uservalid = uservalid ? 1 :	!stricmp(ruser,*user ? user : luser);
		if (hostvalid && uservalid)
			return 0;

#endif /* YP */
		hostvalid = uservalid = 0;
	}
	return (-1);
}

int
_checkhost(const char *rhost, const char *lhost, int len)
{
	static char ldomain[MAXHOSTNAMELEN + 1];
	static char *domainp = NULL;
	static int nodomain = 0;
	register char *cp;

	if (len == -1)
		return(!strcmp(rhost, lhost));
	if (strncmp(rhost, lhost, len))
		return(0);
	if (!strcmp(rhost, lhost))
		return(1);
	if (*(lhost + len) != '\0')
		return(0);
	if (nodomain)
		return(0);
	if (!domainp) {
		if (gethostname(ldomain, sizeof(ldomain)) == -1) {
			nodomain = 1;
			return(0);
		}
		ldomain[MAXHOSTNAMELEN] = (char) 0;
		if ((domainp = index(ldomain, '.')) == (char *)NULL) {
			nodomain = 1;
			return(0);
		}
		for (cp = ++domainp; *cp; ++cp)
			if (isupper(*cp))
				*cp = tolower(*cp);
	}
	return(!strcmp(domainp, rhost + len +1));
}

#ifdef YP
static int
_checknetgrouphost(const char *rhost, const char *netgr, int baselen)
{
	char *host, *user, *domain;
	int status;

	if (NULL == nisdomain)
		yp_get_default_domain(&nisdomain);

	setnetgrent(netgr);
	while (1)
	{
		while (1 == (status = getnetgrent(&host, &user, &domain))
		    && NULL == host
		    && NULL != domain
		    && 0 != strcmp(domain, nisdomain))
			;  /* find valid host entry */

		if (0 == status || NULL == host)
		{
			endnetgrent();
			return 0;
		}

		if(1 == _checkhost(rhost, host, baselen))
		{
			endnetgrent();
			return 1;
		}
	}
}

static int
_checknetgroupuser(const char *ruser, const char *netgr)
{
	char *host, *user, *domain;
	int status;

	if (NULL == nisdomain)
		yp_get_default_domain(&nisdomain);

	setnetgrent(netgr);
	while (1)
	{
		while (1 == (status = getnetgrent(&host, &user, &domain))
		    && NULL == user
		    && NULL != domain
		    && 0 != strcmp(domain, nisdomain))
			;  /* find valid user entry */

		if (0 == status || NULL == user)
		{
			endnetgrent();
			return 0;
		}

		if(0 == strcmp(ruser, user))
		{
			endnetgrent();
			return 1;
		}
	}
}
#endif /* YP */

#endif
