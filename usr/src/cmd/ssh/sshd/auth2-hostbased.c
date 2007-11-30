/*
 * Copyright (c) 2000 Markus Friedl.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
/*
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include "includes.h"
RCSID("$OpenBSD: auth2-hostbased.c,v 1.2 2002/05/31 11:35:15 markus Exp $");

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "ssh2.h"
#include "xmalloc.h"
#include "packet.h"
#include "buffer.h"
#include "log.h"
#include "servconf.h"
#include "compat.h"
#include "bufaux.h"
#include "auth.h"

#ifdef USE_PAM
#include "auth-pam.h"
#endif /* USE_PAM */

#include "key.h"
#include "canohost.h"
#include "pathnames.h"

/* import */
extern ServerOptions options;
extern u_char *session_id2;
extern int session_id2_len;

static void
userauth_hostbased(Authctxt *authctxt)
{
	Buffer b;
	Key *key = NULL;
	char *pkalg, *cuser, *chost, *service;
	u_char *pkblob, *sig;
	u_int alen, blen, slen;
	int pktype;
	int authenticated = 0;

	if (!authctxt || !authctxt->method)
		fatal("%s: missing context", __func__);

	pkalg = packet_get_string(&alen);
	pkblob = packet_get_string(&blen);
	chost = packet_get_string(NULL);
	cuser = packet_get_string(NULL);
	sig = packet_get_string(&slen);

	debug("userauth_hostbased: cuser %s chost %s pkalg %s slen %d",
	    cuser, chost, pkalg, slen);
#ifdef DEBUG_PK
	debug("signature:");
	buffer_init(&b);
	buffer_append(&b, sig, slen);
	buffer_dump(&b);
	buffer_free(&b);
#endif
	pktype = key_type_from_name(pkalg);
	if (pktype == KEY_UNSPEC) {
		/* this is perfectly legal */
		log("userauth_hostbased: unsupported "
		    "public key algorithm: %s", pkalg);
		goto done;
	}
	key = key_from_blob(pkblob, blen);
	if (key == NULL) {
		error("userauth_hostbased: cannot decode key: %s", pkalg);
		goto done;
	}
	if (key->type != pktype) {
		error("userauth_hostbased: type mismatch for decoded key "
		    "(received %d, expected %d)", key->type, pktype);
		goto done;
	}
	service = datafellows & SSH_BUG_HBSERVICE ? "ssh-userauth" :
	    authctxt->service;
	buffer_init(&b);
	buffer_put_string(&b, session_id2, session_id2_len);
	/* reconstruct packet */
	buffer_put_char(&b, SSH2_MSG_USERAUTH_REQUEST);
	buffer_put_cstring(&b, authctxt->user);
	buffer_put_cstring(&b, service);
	buffer_put_cstring(&b, "hostbased");
	buffer_put_string(&b, pkalg, alen);
	buffer_put_string(&b, pkblob, blen);
	buffer_put_cstring(&b, chost);
	buffer_put_cstring(&b, cuser);
#ifdef DEBUG_PK
	buffer_dump(&b);
#endif
	/* test for allowed key and correct signature */
	authenticated = 0;
	if (hostbased_key_allowed(authctxt->pw, cuser, chost, key) &&
	    key_verify(key, sig, slen, buffer_ptr(&b), buffer_len(&b)) == 1)
		authenticated = 1;

	buffer_clear(&b);
done:
	/*
	 * XXX TODO: Add config options for specifying users for whom
	 *           this userauth is insufficient and what userauths
	 *           may continue.
	 *
	 *           NOTE: do_pam_non_initial_userauth() does this for
	 *                 users with expired passwords.
	 */
#ifdef USE_PAM
	if (authenticated) {
		authctxt->cuser = cuser;
		if (!do_pam_non_initial_userauth(authctxt))
			authenticated = 0;
		/* Make sure nobody else will use this pointer since we are
		 * going to free that string. */
		authctxt->cuser = NULL;
	}
#endif /* USE_PAM */

	if (authenticated)
		authctxt->method->authenticated = 1;

	debug2("userauth_hostbased: authenticated %d", authenticated);
	if (key != NULL)
		key_free(key);
	xfree(pkalg);
	xfree(pkblob);
	xfree(cuser);
	xfree(chost);
	xfree(sig);
	return;
}

/* return 1 if given hostkey is allowed */
int
hostbased_key_allowed(struct passwd *pw, const char *cuser, char *chost,
    Key *key)
{
	const char *resolvedname, *ipaddr, *lookup;
	HostStatus host_status;
	int len;

	resolvedname = get_canonical_hostname(options.verify_reverse_mapping);
	ipaddr = get_remote_ipaddr();

	debug2("userauth_hostbased: chost %s resolvedname %s ipaddr %s",
	    chost, resolvedname, ipaddr);

	if (pw == NULL)
		return 0;

	if (options.hostbased_uses_name_from_packet_only) {
		if (auth_rhosts2(pw, cuser, chost, chost) == 0)
			return 0;
		lookup = chost;
	} else {
		if (((len = strlen(chost)) > 0) && chost[len - 1] == '.') {
			debug2("stripping trailing dot from chost %s", chost);
			chost[len - 1] = '\0';
		}
		if (strcasecmp(resolvedname, chost) != 0)
			log("userauth_hostbased mismatch: "
			    "client sends %s, but we resolve %s to %s",
			    chost, ipaddr, resolvedname);
		if (auth_rhosts2(pw, cuser, resolvedname, ipaddr) == 0)
			return 0;
		lookup = resolvedname;
	}
	debug2("userauth_hostbased: access allowed by auth_rhosts2");

	host_status = check_key_in_hostfiles(pw, key, lookup,
	    _PATH_SSH_SYSTEM_HOSTFILE,
	    options.ignore_user_known_hosts ? NULL : _PATH_SSH_USER_HOSTFILE);

	/* backward compat if no key has been found. */
	if (host_status == HOST_NEW)
		host_status = check_key_in_hostfiles(pw, key, lookup,
		    _PATH_SSH_SYSTEM_HOSTFILE2,
		    options.ignore_user_known_hosts ? NULL :
		    _PATH_SSH_USER_HOSTFILE2);

	return (host_status == HOST_OK);
}

Authmethod method_hostbased = {
	"hostbased",
	&options.hostbased_authentication,
	userauth_hostbased,
	NULL,		    /* no abandon function */
	NULL, NULL,	    /* method data and hist data */
	0,		    /* is not initial userauth */
	0, 0, 0,	    /* counters */
	0, 0, 0, 0, 0, 0    /* state */
};
