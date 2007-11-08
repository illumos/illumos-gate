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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * util.c contains a set of miscellaneous utility functions which:
 * - syslog(LOG_DEBUG, ...) if debugging is enabled
 * - check for an IP interface being marked running
 * - look up all flags for an IP interface
 * - start a child process
 * - schedule a timer
 * - check to see if a user is logged in to a graphical console
 * - look up the zone name
 */

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <string.h>
#include <strings.h>
#include <stropts.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <net/if.h>
#include <spawn.h>
#include <wait.h>
#include <inetcfg.h>
#include <utmpx.h>
#include <pwd.h>
#include <limits.h>
#include <errno.h>
#include <zone.h>

#include "defines.h"
#include "structures.h"
#include "functions.h"
#include "variables.h"

extern char **environ;
boolean_t debug = B_FALSE;

/* PRINTFLIKE1 */
void
dprintf(const char *fmt, ...)
{
	va_list ap;
	char vbuf[1024];

	va_start(ap, fmt);
	if (debug) {
		(void) vsnprintf(vbuf, sizeof (vbuf), fmt, ap);
		syslog(LOG_DEBUG, "%d: %s", pthread_self(), vbuf);
	}
	va_end(ap);
}

boolean_t
is_plugged_in(struct interface *i)
{
	if (i->if_type == IF_WIRELESS)
		return (B_TRUE);

	return ((get_ifflags(i->if_name, i->if_family) & IFF_RUNNING) != 0);
}

uint64_t
get_ifflags(const char *name, sa_family_t family)
{
	icfg_if_t intf;
	icfg_handle_t h;
	uint64_t flags = 0;

	(void) strlcpy(intf.if_name, name, sizeof (intf.if_name));
	intf.if_protocol = family;

	if (icfg_open(&h, &intf) != ICFG_SUCCESS)
		return (0);

	if (icfg_get_flags(h, &flags) != ICFG_SUCCESS) {
		/*
		 * Interfaces can be ripped out from underneath us (for example
		 * by DHCP).  We don't want to spam the console for those.
		 */
		if (errno == ENOENT)
			dprintf("get_ifflags: icfg_get_flags failed for '%s'",
			    name);
		else
			syslog(LOG_ERR, "get_ifflags: icfg_get_flags %s af "
			    "%d: %m", name, family);
		/* just to be sure... */
		flags = 0;
	}
	icfg_close(h);

	return (flags);
}

/*
 *
 * This starts a child process determined by command.  If command contains a
 * slash then it is assumed to be a full path; otherwise the path is searched
 * for an executable file with the name command.  Command is also used as
 * argv[0] of the new process.  The rest of the arguments of the function
 * up to the first NULL make up pointers to arguments of the new process.
 *
 * This function returns child exit status on success and -1 on failure.
 *
 * NOTE: original_sigmask must be set before this function is called.
 */
int
start_childv(const char *command, char const * const *argv)
{
	posix_spawnattr_t attr;
	sigset_t fullset;
	int i, rc, status, n;
	pid_t pid;
	char vbuf[1024];

	vbuf[0] = 0;
	n = sizeof (vbuf);
	for (i = 1; argv[i] != NULL && n > 2; i++) {
		n -= strlcat(vbuf, " ", n);
		n -= strlcat(vbuf, argv[i], n);
	}
	if (argv[i] != NULL || n < 0)
		syslog(LOG_ERR, "start_childv can't log full arg vector");

	if ((rc = posix_spawnattr_init(&attr)) != 0) {
		dprintf("posix_spawnattr_init %d %s\n", rc, strerror(rc));
		return (-1);
	}
	(void) sigfillset(&fullset);
	if ((rc = posix_spawnattr_setsigdefault(&attr, &fullset)) != 0) {
		dprintf("setsigdefault %d %s\n", rc, strerror(rc));
		return (-1);
	}
	if ((rc = posix_spawnattr_setsigmask(&attr, &original_sigmask)) != 0) {
		dprintf("setsigmask %d %s\n", rc, strerror(rc));
		return (-1);
	}
	if ((rc = posix_spawnattr_setflags(&attr,
	    POSIX_SPAWN_SETSIGDEF|POSIX_SPAWN_SETSIGMASK)) != 0) {
		dprintf("setflags %d %s\n", rc, strerror(rc));
		return (-1);
	}

	if ((rc = posix_spawnp(&pid, command, NULL, &attr, (char * const *)argv,
	    environ)) > 0) {
		dprintf("posix_spawnp failed errno %d", rc);
		return (-1);
	}

	if ((rc = posix_spawnattr_destroy(&attr)) != 0) {
		dprintf("posix_spawn_attr_destroy %d %s\n", rc, strerror(rc));
		return (-1);
	}

	(void) waitpid(pid, &status, 0);
	if (WIFSIGNALED(status) || WIFSTOPPED(status)) {
		i = WIFSIGNALED(status) ? WTERMSIG(status) : WSTOPSIG(status);
		syslog(LOG_ERR, "'%s%s' %s with signal %d (%s)", command, vbuf,
		    (WIFSIGNALED(status) ? "terminated" : "stopped"), i,
		    strsignal(i));
		return (-2);
	} else {
		syslog(LOG_INFO, "'%s%s' completed normally: %d", command, vbuf,
		    WEXITSTATUS(status));
		return (WEXITSTATUS(status));
	}
}

int
start_child(const char *command, ...)
{
	const char **argv = NULL;
	int argv_len = 0;
	va_list ap;
	int i = 1, rc;

	va_start(ap, command);
	do {
		if (i >= argv_len) {
			void *p;

			argv_len = argv_len != 0 ? argv_len * 2 : 4;
			p = realloc(argv, sizeof (*argv)*argv_len);
			if (p != NULL) {
				argv = p;
			} else {
				syslog(LOG_ERR, "Out of memory in start_child");
				free(argv);
				return (-1);
			}
		}

		argv[i] = va_arg(ap, const char *);
	} while (argv[i++] != NULL);
	va_end(ap);
	argv[0] = command;

	rc = start_childv(command, argv);
	free(argv);

	return (rc);
}

uint32_t	timer_expire = TIMER_INFINITY;

/*
 * Schedules a SIGALRM in delay seconds, unless one is already
 * scheduled sooner.  If one is already scheduled later than
 * delay seconds from now, that one will be replaced.
 */
void
start_timer(uint32_t now, uint32_t delay)
{
	if (now + delay > timer_expire)
		return;

	timer_expire = now + delay;
	(void) alarm(delay);
}

boolean_t
valid_graphical_user(boolean_t query)
{
	struct utmpx *utp;
	char *user = NULL;
	const char HOMESTR[] = "HOME=";
	char buf[1024]; /* == sysconf(_SC_GETPW_R_SIZE_MAX) == NSS_BUFSIZ */
	static char home_dir[PATH_MAX + sizeof (HOMESTR)];
	struct passwd passwd;
	struct passwd *pw;
	boolean_t popup_ok;

	/*
	 * Check to see if our SMF property says popups are OK.
	 */
	if ((lookup_boolean_property(OUR_PG, query ? "popup_query" :
	    "popup_info", &popup_ok) == 0) && !popup_ok)
		return (B_FALSE);

	/*
	 * Look for someone logged into the console from host ":0" (i.e.,
	 * the X display.  Down the road, we should generalize this so
	 * ":0" is not hard-coded.  Note that the entry we want is usually
	 * an ordinary user process but sometimes if a session leader has
	 * exited, it can come from a DEAD_PROCESS, as is known to happen
	 * when the user logs in via gdm(1m).
	 */
	setutxent();
	while ((utp = getutxent()) != NULL) {
		if (((utp->ut_type == USER_PROCESS) ||
		    (utp->ut_type == DEAD_PROCESS)) &&
		    (strcmp(utp->ut_line, "console") == 0) &&
		    (strcmp(utp->ut_host, ":0") == 0)) {
			user = strdup(utp->ut_user);
			break;
		}
	}
	endutxent();
	dprintf("utmpx: done %s", user != NULL ? user : "");

	if (user == NULL)
		return (B_FALSE);

	pw = getpwnam_r(user, &passwd, buf, sizeof (buf));
	if (pw == NULL) {
		syslog(LOG_ERR, "couldn't get user %s: %m", user);
		free(user);
		return (B_FALSE);
	}
	free(user);

	/*
	 * We shouldn't be dumping this into our environment or changing
	 * our uid/gid but instead starting up the zenity processes with
	 * this display as this user.  RFE to change this.
	 */
	(void) putenv("DISPLAY=:0.0");

	(void) strlcpy(home_dir, HOMESTR, sizeof (home_dir));
	(void) strlcat(home_dir, pw->pw_dir, sizeof (home_dir));
	(void) putenv(home_dir);

	return (pw != NULL);
}

void
lookup_zonename(char *zonename, size_t zonesize)
{
	zoneid_t zoneid = getzoneid();

	if (getzonenamebyid(zoneid, zonename, zonesize) >= 0)
		return;
	syslog(LOG_ERR, "could not determine zone name");
	(void) strlcpy(zonename, GLOBAL_ZONENAME, zonesize);
}

/* return B_TRUE if sin_family and sin_addr are the same, B_FALSE if not */
boolean_t
cmpsockaddr(const struct sockaddr *addr1, const struct sockaddr *addr2)
{
	struct sockaddr_in *sina, *sinb;
	struct sockaddr_in6 *sin6a, *sin6b;

	if (addr1 == addr2)
		return (B_TRUE);

	if (addr1 == NULL || addr2 == NULL)
		return (B_FALSE);

	if (addr1->sa_family != addr2->sa_family)
		return (B_FALSE);

	switch (addr1->sa_family) {
	case AF_INET:
		/* LINTED E_BAD_PTR_CAST_ALIGN */
		sina = (struct sockaddr_in *)addr1;
		/* LINTED E_BAD_PTR_CAST_ALIGN */
		sinb = (struct sockaddr_in *)addr2;
		return (sina->sin_addr.s_addr == sinb->sin_addr.s_addr);
	case AF_INET6:
		/* LINTED E_BAD_PTR_CAST_ALIGN */
		sin6a = (struct sockaddr_in6 *)addr1;
		/* LINTED E_BAD_PTR_CAST_ALIGN */
		sin6b = (struct sockaddr_in6 *)addr2;
		return
		    (IN6_ARE_ADDR_EQUAL(&sin6a->sin6_addr, &sin6b->sin6_addr));
	default:
		dprintf("cmpsockaddr: unsupported af (%d)", addr1->sa_family);
		return (B_FALSE);
	}
}

/*
 * Duplicate a sockaddr. Caller will be responsible for freeing memory when it
 * is no longer needed. Currently only supports AF_INET and AF_INET6
 * (returns NULL otherwise).
 */
struct sockaddr *
dupsockaddr(const struct sockaddr *addr)
{
	struct sockaddr_in *t1, *ret1;
	struct sockaddr_in6 *t2, *ret2;

	switch (addr->sa_family) {
	case AF_INET:
		if ((ret1 = calloc(1, sizeof (struct sockaddr_in))) == NULL) {
			syslog(LOG_ERR, "dupsockaddr: calloc failed");
			return (NULL);
		}
		/* LINTED E_BAD_PTR_CAST_ALIGN */
		t1 = (struct sockaddr_in *)addr;
		ret1->sin_family = t1->sin_family;
		ret1->sin_addr.s_addr = t1->sin_addr.s_addr;
		return ((struct sockaddr *)ret1);
	case AF_INET6:
		if ((ret2 = calloc(1, sizeof (struct sockaddr_in6))) == NULL) {
			syslog(LOG_ERR, "dupsockaddr: calloc failed");
			return (NULL);
		}
		/* LINTED E_BAD_PTR_CAST_ALIGN */
		t2 = (struct sockaddr_in6 *)addr;
		ret2->sin6_family = t2->sin6_family;
		(void) memcpy((void *)&ret2->sin6_addr,
		    (const void *)&t2->sin6_addr, sizeof (struct in6_addr));
		return ((struct sockaddr *)ret2);
	default:
		dprintf("dupsockaddr: unsupported af (%d)", addr->sa_family);
		return (NULL);
	}
}
