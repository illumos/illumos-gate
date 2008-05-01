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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"


#include <pwd.h>
#include <locale.h>
#include <syslog.h>
#include <errno.h>
#include <com_err.h>
#include <k5-int.h>

extern uint_t kwarn_add_warning(char *, int);
extern uint_t kwarn_del_warning(char *);

/*
 * Store the forwarded creds in the user's local ccache and register
 * w/ktkt_warnd(1M).
 */
krb5_error_code
store_forw_creds(krb5_context context,
		    krb5_creds **creds,
		    krb5_ticket *ticket,
		    char *lusername,
		    krb5_ccache *ccache)
{
	krb5_error_code retval;
	char ccname[MAXPATHLEN];
	struct passwd *pwd;
	uid_t uid;
	char *client_name = NULL;

	*ccache = NULL;
	if (!(pwd = getpwnam(lusername)))
		return (ENOENT);

	uid = getuid();
	if (seteuid(pwd->pw_uid))
		return (-1);

	(void) snprintf(ccname, sizeof (ccname), "FILE:/tmp/krb5cc_%ld",
	    pwd->pw_uid);

	if ((retval = krb5_cc_resolve(context, ccname, ccache)) != 0) {
		krb5_set_error_message(context, retval,
		    gettext("failed to resolve cred cache %s"), ccname);
		goto cleanup;
	}

	if ((retval = krb5_cc_initialize(context, *ccache,
	    ticket->enc_part2->client)) != 0) {
		krb5_set_error_message(context, retval,
		    gettext("failed to initialize cred cache %s"), ccname);
		goto cleanup;
	}

	if ((retval = krb5_cc_store_cred(context, *ccache, *creds)) != 0) {
		krb5_set_error_message(context, retval,
		    gettext("failed to store cred in cache %s"), ccname);
		goto cleanup;
	}

	if ((retval = krb5_cc_close(context, *ccache)) != 0)
		goto cleanup;

	/* Register with ktkt_warnd(1M) */
	if ((retval = krb5_unparse_name(context, (*creds)->client,
	    &client_name)) != 0)
		goto cleanup;
	(void) kwarn_del_warning(client_name);
	if (kwarn_add_warning(client_name, (*creds)->times.endtime) != 0) {
		syslog(LOG_AUTH|LOG_NOTICE,
		    "store_forw_creds: kwarn_add_warning"
		    " failed: ktkt_warnd(1M) down? ");
	}
	free(client_name);
	client_name = NULL;

cleanup:
	(void) seteuid(uid);

	return (retval);
}
