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
 *  Routines to set gssd value of uid and replace getuid libsys call.
 */

#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <libintl.h>
#include <priv.h>
#include <errno.h>
#include <syslog.h>

static uid_t krb5_cc_uid;
#define	LOWPRIVS	"basic,!file_link_any,!proc_info,!proc_session," \
			"!proc_fork,!proc_exec"

static priv_set_t *lowprivs = NULL;
static priv_set_t *highprivs = NULL;

/*
 * NOTE WELL: This assumes gssd is NOT multi-threaded.  Do NOT add -A to
 * the rpcgen argument list in the Makefile unless you also remove this
 * assumption.
 */

void
set_gssd_uid(uid_t uid)
{
	/* Initialize */
	if (lowprivs == NULL) {
		/* L, P & I shall not change in gssd; we manipulate P though */
		if ((highprivs = priv_allocset()) == NULL ||
		    (lowprivs = priv_str_to_set(LOWPRIVS, ",", NULL)) == NULL) {
			printf(gettext(
			    "fatal: can't allocate privilege set (%s)\n"),
			    strerror(ENOMEM));
			syslog(LOG_ERR, "Fatal: can't allocate privilege "
			    "set (%s)"), strerror(ENOMEM);
			exit(1);
		}
		/* P has the privs we need when we need privs */
		(void) getppriv(PRIV_PERMITTED, highprivs);

		/*
		 * In case "basic" grows privs not excluded in LOWPRIVS
		 * but excluded in the service's method_context
		 */
		priv_intersect(highprivs, lowprivs);

		(void) setpflags(PRIV_AWARE, 1);
	}

	printf(gettext("set_gssd_uid called with uid = %d\n"), uid);

	/*
	 * nfsd runs as UID 1, so upcalls triggered by nfsd will cause uid to
	 * 1 here, but nfsd's upcalls need to run as root with privs here.
	 */
	if (uid == 1)
		uid = 0;

	/*
	 * Set the value of krb5_cc_uid, so it can be retrieved when
	 * app_krb5_user_uid() is called by the underlying mechanism
	 * libraries.  This should go away soon.
	 */
	krb5_cc_uid = uid;

	/* Claw privs back */
	(void) setppriv(PRIV_SET, PRIV_EFFECTIVE, highprivs);

	/*
	 * Switch uid and set the saved set-uid to 0 so setuid(0) will work
	 * later.
	 */
	if (setuid(0) != 0 ||
	    (uid != 0 && setreuid(uid, -1) != 0) ||
	    (uid != 0 && seteuid(uid) != 0)) {

		/* Not enough privs, so bail! */
		printf(gettext(
		    "fatal: gssd is running with insufficient privilege\n"));
		syslog(LOG_ERR, "Fatal: gssd is running with insufficient "
		    "privilege.");
		exit(1);
	}

	/* Temporarily drop privs, but only if uid != 0 */
	if (uid != 0)
		(void) setppriv(PRIV_SET, PRIV_EFFECTIVE, lowprivs);
}

uid_t
app_krb5_user_uid(void)
{
	/*
	 * return the value set when one of the gssd procedures was
	 * entered. This is the value of the uid under which the
	 * underlying mechanism library must operate in order to
	 * get the user's credentials. This call is necessary since
	 * gssd runs as root and credentials are many times stored
	 * in files and directories specific to the user
	 */
	printf(gettext(
	    "getuid called and returning krb5_cc_uid = %d\n"), krb5_cc_uid);
	return (krb5_cc_uid);
}
