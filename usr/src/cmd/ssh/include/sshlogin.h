/*	$OpenBSD: sshlogin.h,v 1.4 2002/08/29 15:57:25 stevesk Exp $	*/

#ifndef	_SSHLOGIN_H
#define	_SSHLOGIN_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif


/*
 * Author: Tatu Ylonen <ylo@cs.hut.fi>
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 */
/*
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

void
record_login(pid_t pid, const char *ttyname, const char *progname,
		const char *user);
void
record_logout(pid_t pid, const char *ttyname, const char *progname,
		const char *user);

u_long
get_last_login_time(uid_t uid, const char *logname, char *buf, u_int bufsize);

#ifdef LOGIN_NEEDS_UTMPX
void
record_utmp_only(pid_t pid, const char *ttyname, const char *user,
		const char *host, struct sockaddr *addr);
#endif

#ifdef __cplusplus
}
#endif

#endif /* _SSHLOGIN_H */
