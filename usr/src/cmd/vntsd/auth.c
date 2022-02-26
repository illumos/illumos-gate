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

/*
 * Authorization checking:
 *
 * These functions check 'vntsd' authorization to access guest consoles.
 * The mechanism used is Solaris authorizations. The local client (telnet)
 * process requesting the connection to a console is verified to have the
 * required authorization.
 *
 * Authorizations available are to access the console of any/all guests or to
 * access the consoles of a specific console group. A client connecting to the
 * console through telnet must have the appropriate authorization from file
 * /etc/security/auth_attr.
 *
 * The all-consoles authorization is added during vntsd installation:
 * solaris.vntsd.consoles:::Access All LDoms Guest Consoles::
 *
 * Example of a specific console group authorization based on the name of the
 * console group (added manually by a user with 'vntsd.grant' authorization,
 * such as 'root'); the group name in this example is "ldg1" :
 * solaris.vntsd.console-ldg1:::Access Specific LDoms Guest Console::
 *
 * Specific users are authorized with usermod(8). To add an authorization
 * (to /etc/user_attr) type a command similar to this (when user NOT
 * logged in):
 *
 *    To authorize a user 'user1' to access all guest consoles:
 *    # usermod -A solaris.vntsd.consoles user1
 *
 */

#include <sys/types.h>		/* uid_t */
#include <sys/param.h>		/* MAXNAMELEN */
#include <pwd.h>		/* getpw*() */
#include <auth_attr.h>		/* chkauthattr() */
#include <secdb.h>		/* chkauthattr() */
#include <ucred.h>		/* getpeerucred() */
#include <errno.h>		/* errno */

#define	VNTSD_AUTH_ALLCONS	"solaris.vntsd.consoles" /* all-consoles auth */
#define	VNTSD_AUTH_GRPCONS	"solaris.vntsd.console-" /* cons-group auth */
#define	VNTSD_AUTH_PREFIXLEN	32			 /* max len of prefix */

/*
 * socket_peer_euid()
 *
 * Return the effective UID (EUID) of the socket peer.
 * If none, return -1.
 *
 * Parameters:
 * sock_fd	The socket fd of a locally-connected socket (mapped to a pid)
 *
 * Returns:
 * EUID if OK
 * -1 on failure or unknown EUID (passed on from ucred_geteuid()).
 */
static uid_t
socket_peer_euid(int sock_fd)
{
	int		rc;
	uid_t		peer_euid;
	ucred_t		*ucredp = NULL;

	/* Get info on the peer on the other side of the socket */
	rc = getpeerucred(sock_fd, &ucredp);
	if (rc == -1) {
		/* If errno is EINVAL, it's probably a non-local socket peer */
		return ((uid_t)-1);
	}

	/* Extract effective UID (EUID) info for the socket peer process */
	peer_euid = ucred_geteuid(ucredp);
	ucred_free(ucredp);

	/* Return EUID */
	return (peer_euid);
}

/*
 * auth_check_username()
 *
 * Check vntsd console authorization, given a user account.
 *
 * Parameters:
 * username	The name of a user account to check authorization
 * group_name	The name of the console group to check authorization. The max
 *              length of group name is MAXPATHLEN.
 *
 * Returns:
 * 0 if OK (authorized), 1 on authorization failure.
 */
static int
auth_check_username(char *username, char *group_name)
{
	int	auth_granted = 0;
	char	authname[VNTSD_AUTH_PREFIXLEN + MAXPATHLEN];
	size_t	len = VNTSD_AUTH_PREFIXLEN + MAXPATHLEN;

	/* Sanity check: */
	if ((username == NULL) || (username[0] == '\0') ||
	    (group_name == NULL) || (group_name[0] == '\0')) {
		return (1); /* error (bad parameter) */
	}

	(void) snprintf(authname, len, VNTSD_AUTH_GRPCONS"%s", group_name);

	/*
	 * Do authorization checking.
	 * First, check if the user is authorized access to all consoles. If it
	 * fails, check authorization to the specific console group.
	 */
	auth_granted = chkauthattr(VNTSD_AUTH_ALLCONS, username);
	if (auth_granted)
		return (0);

	auth_granted = chkauthattr(authname, username);
	if (auth_granted)
		return (0);

	return (1);
}

/*
 * auth_check_euid()
 *
 * Check vntsd console authorization, given a EUID.
 *
 * Parameters:
 * euid		The effective UID of a user account to check authorization
 * group_name	The name of the console group to check authorization
 *
 * Returns:
 * 0 if OK (authorized), 1 on authorization failure.
 */
static int
auth_check_euid(uid_t euid, char *group_name)
{
	struct passwd	*passwdp = NULL;
	char		*username = NULL;

	/* If EUID is -1, then it's unknown, so fail */
	if (euid == (uid_t)-1) {
		return (1);
	}

	/* Map EUID to user name */
	passwdp = getpwuid(euid);
	if (passwdp == NULL) { /* lookup failed */
		return (1);
	}
	username = passwdp->pw_name;

	/* Do authorization check: */
	return (auth_check_username(username, group_name));
}

/*
 * auth_check_fd()
 *
 * Check vntsd authorization, given a fd of a socket. The socket fd is mapped
 * to a pid (and should not be used for remote connections).
 *
 * Parameters:
 * sock_fd	The socket fd of a locally-connected socket (mapped to a pid)
 * group_name	The name of the console group to check authorization
 *
 * Returns:
 * B_TRUE if OK (authorized), B_FALSE on authorization failure.
 */
boolean_t
auth_check_fd(int sock_fd, char *group_name)
{
	uid_t	peer_euid;
	int	rv;

	peer_euid = socket_peer_euid(sock_fd);
	if (peer_euid == (uid_t)-1) { /* unknown EUID */
		return (B_FALSE);
	}

	/* Do authorization check: */
	rv = auth_check_euid(peer_euid, group_name);
	if (rv != 0) {
		return (B_FALSE);
	}
	return (B_TRUE);
}
