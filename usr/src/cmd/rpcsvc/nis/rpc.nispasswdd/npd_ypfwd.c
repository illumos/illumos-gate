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
#include <syslog.h>
#include <rpc/rpc.h>
#include <rpc/clnt.h>
#include <rpcsvc/yppasswd.h>

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 *	npd_ypfwd.c
 *	NPD routine to forward password update request to YP
 *
 *	Copyright (c) 1997 Sun Microsystems, Inc.  All Rights Reserved.
 *
 *	This function is pretty much lifted from
 *	lib/scheme/pm_scheme/pam_update_authtok_nis.c:update_authtok_nis().
 *
 *	The only difference is that we are taking requests from NPD to
 *	forward a password change to a YP database after the NIS+ database
 *	has already been updated.  If this change fails, then we must undo
 *	the NIS+ change as well.  Only at Sun can something like this exist...
 *
 *	This function is called only from npd_svc.c:nispasswd_update_1_svc()
 *	or npd_svc.c:yppasswd_update_1_svc().  The set of variables are similar
 *	so I've provided a translation table below:
 *
 * variable	nispasswd		yppasswd		what is it?
 * --------	---------		--------		-----------
 * usrname	entry->ul_user		newpass->pw_name	user name
 * newpwe	newpass			newpass->pw_passwd	encr new passwd
 * XX oldpwe	old_pass		old_pass		encr old passwd
 * oldpwu	entry->ol_oldpass	yppass->oldpass		clear old passwd
 * XX newpwu	pass			<N/A>			clear new passwd
 * master	ypfwd			ypfwd			YP master to fwd
 * gecos	old_gecos		old_gecos		original gecos
 * shell	old_shell		old_shell		original shell
 */
int
update_authtok_nis_fwd(
	char	*usrname,	/* user name			*/
	char	*newpwe,	/* encrypted new passwd		*/
	char	*oldpwu,	/* clear old passwd		*/
	char 	*master,	/* passwd master YP machine	*/
	char 	*gecos,		/* (unchanged) general comments	*/
	char 	*shell)		/* (unchanged) login shell	*/
{
	int 			retval = 0;	/* value to return	*/
	int 			ok;		/* update return status	*/
	enum clnt_stat 		ans;		/* RPC return status	*/
	CLIENT 			*client;	/* RPC client handle	*/
	const char		*fnam = "update_authok_nis_fwd";
						/* function name	*/
	const struct timeval	timeout	= { 55, 0 };
						/* NPD uses 55 seconds	*/
	static struct yppasswd	yppwstruct;	/* YP passwd struct	*/
	static struct passwd	pwstruct;	/* passwd struct	*/

	/*
	 * ck_passwd() already checked the old passwd. It won't get here
	 * if the old passwd is not matched.  We are just preparing the
	 * yppasswd update packet here.
	 */
	pwstruct.pw_name   = usrname;	/* username is changing passwd	*/
	pwstruct.pw_passwd = newpwe;	/* encrypted new passwd		*/
	pwstruct.pw_gecos  = gecos;	/* unchanged general comments	*/
	pwstruct.pw_shell  = shell;	/* unchanged login shell	*/
	yppwstruct.oldpass = oldpwu;	/* unencrypted old passwd	*/
	yppwstruct.newpw   = pwstruct;	/* copy in yppasswd struct	*/

	if (!(client = clnt_create(master, YPPASSWDPROG, YPPASSWDVERS,
								"udp"))) {
		syslog(LOG_INFO, "%s: can't create YP client handle\n", fnam);
		return (-1);
	}

	ans = CLNT_CALL(client, YPPASSWDPROC_UPDATE, xdr_yppasswd,
		(char *)&yppwstruct, xdr_int, (char *)&ok, timeout);

	if ((ok != 0) || (ans != RPC_SUCCESS)) {
		syslog(LOG_ERR,
		    "%s: can't change NIS(YP) passwd for %s on %s (err: %d)\n",
		    fnam, usrname, master, ok);
		if (ans != RPC_SUCCESS) {
			clnt_perror(client,
			    "RPC call failed -- client may have timed-out.");
			syslog(LOG_INFO,
			    "%s: client could not make RPC call.\n", fnam);
			retval = -1;
		}
	} else {
		syslog(LOG_DEBUG, "%s: NIS(YP) passwd changed for %s on %s\n",
		    fnam, usrname, master);
	}

	(void) clnt_destroy(client);
	return (retval);
}
