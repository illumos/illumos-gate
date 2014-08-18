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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <dlfcn.h>

#include "includes.h"
RCSID("$OpenBSD: auth2-pubkey.c,v 1.2 2002/05/31 11:35:15 markus Exp $");

#include "ssh2.h"
#include "xmalloc.h"
#include "packet.h"
#include "buffer.h"
#include "log.h"
#include "servconf.h"
#include "compat.h"
#include "bufaux.h"
#include "auth.h"
#include "key.h"
#include "pathnames.h"
#include "uidswap.h"
#include "auth-options.h"
#include "canohost.h"

#ifdef USE_PAM
#include <security/pam_appl.h>
#include "auth-pam.h"
#endif /* USE_PAM */

/* import */
extern ServerOptions options;
extern u_char *session_id2;
extern int session_id2_len;

/* global plugin function requirements */
static const char *RSA_SYM_NAME = "sshd_user_rsa_key_allowed";
static const char *DSA_SYM_NAME = "sshd_user_rsa_key_allowed";
typedef int (*RSA_SYM)(struct passwd *, RSA *, const char *);
typedef int (*DSA_SYM)(struct passwd *, DSA *, const char *);


static void
userauth_pubkey(Authctxt *authctxt)
{
	Buffer b;
	Key *key = NULL;
	char *pkalg;
	u_char *pkblob, *sig;
	u_int alen, blen, slen;
	int have_sig, pktype;
	int authenticated = 0;

	if (!authctxt || !authctxt->method)
		fatal("%s: missing context", __func__);

	have_sig = packet_get_char();
	if (datafellows & SSH_BUG_PKAUTH) {
		debug2("userauth_pubkey: SSH_BUG_PKAUTH");
		/* no explicit pkalg given */
		pkblob = packet_get_string(&blen);
		buffer_init(&b);
		buffer_append(&b, pkblob, blen);
		/* so we have to extract the pkalg from the pkblob */
		pkalg = buffer_get_string(&b, &alen);
		buffer_free(&b);
	} else {
		pkalg = packet_get_string(&alen);
		pkblob = packet_get_string(&blen);
	}
	pktype = key_type_from_name(pkalg);
	if (pktype == KEY_UNSPEC) {
		/* this is perfectly legal */
		log("userauth_pubkey: unsupported public key algorithm: %s",
		    pkalg);
		goto done;
	}
	key = key_from_blob(pkblob, blen);
	if (key == NULL) {
		error("userauth_pubkey: cannot decode key: %s", pkalg);
		goto done;
	}
	if (key->type != pktype) {
		error("userauth_pubkey: type mismatch for decoded key "
		    "(received %d, expected %d)", key->type, pktype);
		goto done;
	}

	/* Detect and count abandonment */
	if (authctxt->method->method_data) {
		Key	*prev_key;
		unsigned char	*prev_pkblob;
		int	 prev_blen;

		/*
		 * Check for earlier test of a key that was allowed but
		 * not followed up with a pubkey req for the same pubkey
		 * and with a signature.
		 */
		prev_key = authctxt->method->method_data;
		if ((prev_blen = key_to_blob(prev_key,
			    &prev_pkblob, NULL))) {
			if (prev_blen != blen ||
			    memcmp(prev_pkblob, pkblob, blen) != 0) {
				authctxt->method->abandons++;
				authctxt->method->attempts++;
			}
		}
		key_free(prev_key);
		authctxt->method->method_data = NULL;
	}

	if (have_sig) {
		sig = packet_get_string(&slen);
		packet_check_eom();
		buffer_init(&b);
		if (datafellows & SSH_OLD_SESSIONID) {
			buffer_append(&b, session_id2, session_id2_len);
		} else {
			buffer_put_string(&b, session_id2, session_id2_len);
		}
		/* reconstruct packet */
		buffer_put_char(&b, SSH2_MSG_USERAUTH_REQUEST);
		buffer_put_cstring(&b, authctxt->user);
		buffer_put_cstring(&b,
		    datafellows & SSH_BUG_PKSERVICE ?
		    "ssh-userauth" :
		    authctxt->service);
		if (datafellows & SSH_BUG_PKAUTH) {
			buffer_put_char(&b, have_sig);
		} else {
			buffer_put_cstring(&b, "publickey");
			buffer_put_char(&b, have_sig);
			buffer_put_cstring(&b, pkalg);
		}
		buffer_put_string(&b, pkblob, blen);
#ifdef DEBUG_PK
		buffer_dump(&b);
#endif
		/* test for correct signature */
		if (user_key_allowed(authctxt->pw, key) &&
		    key_verify(key, sig, slen, buffer_ptr(&b),
		    buffer_len(&b)) == 1) {
			authenticated = 1;
		}
		authctxt->method->postponed = 0;
		buffer_free(&b);
		xfree(sig);
	} else {
		debug("test whether pkalg/pkblob are acceptable");
		packet_check_eom();

		/* XXX fake reply and always send PK_OK ? */
		/*
		 * XXX this allows testing whether a user is allowed
		 * to login: if you happen to have a valid pubkey this
		 * message is sent. the message is NEVER sent at all
		 * if a user is not allowed to login. is this an
		 * issue? -markus
		 */
		if (user_key_allowed(authctxt->pw, key)) {
			packet_start(SSH2_MSG_USERAUTH_PK_OK);
			packet_put_string(pkalg, alen);
			packet_put_string(pkblob, blen);
			packet_send();
			packet_write_wait();
			authctxt->method->postponed = 1;
			/*
			 * Remember key that was tried so we can
			 * correctly detect abandonment.  See above.
			 */
			authctxt->method->method_data = (void *) key;
			key = NULL;
		}
	}
	if (authenticated != 1)
		auth_clear_options();

done:
	/*
	 * XXX TODO: add config options for specifying users for whom
	 * this userauth is insufficient and what userauths may
	 * continue.
	 */
#ifdef USE_PAM
	if (authenticated) {
		if (!do_pam_non_initial_userauth(authctxt))
			authenticated = 0;
	}
#endif /* USE_PAM */

	debug2("userauth_pubkey: authenticated %d pkalg %s", authenticated, pkalg);
	if (key != NULL)
		key_free(key);
	xfree(pkalg);
	xfree(pkblob);
#ifdef HAVE_CYGWIN
	if (check_nt_auth(0, authctxt->pw) == 0)
		return;
#endif
	if (authenticated)
		authctxt->method->authenticated = 1;
}

/* return 1 if user allows given key */
static int
user_key_allowed2(struct passwd *pw, Key *key, char *file)
{
	char line[8192];
	int found_key = 0;
	FILE *f;
	u_long linenum = 0;
	struct stat st;
	Key *found;
	char *fp;

	if (pw == NULL)
		return 0;

	/* Temporarily use the user's uid. */
	temporarily_use_uid(pw);

	debug("trying public key file %s", file);

	/* Fail quietly if file does not exist */
	if (stat(file, &st) < 0) {
		/* Restore the privileged uid. */
		restore_uid();
		return 0;
	}
	/* Open the file containing the authorized keys. */
	f = fopen(file, "r");
	if (!f) {
		/* Restore the privileged uid. */
		restore_uid();
		return 0;
	}
	if (options.strict_modes &&
	    secure_filename(f, file, pw, line, sizeof(line)) != 0) {
		(void) fclose(f);
		log("Authentication refused: %s", line);
		restore_uid();
		return 0;
	}

	found_key = 0;
	found = key_new(key->type);

	while (fgets(line, sizeof(line), f)) {
		char *cp, *options = NULL;
		linenum++;
		/* Skip leading whitespace, empty and comment lines. */
		for (cp = line; *cp == ' ' || *cp == '\t'; cp++)
			;
		if (!*cp || *cp == '\n' || *cp == '#')
			continue;

		if (key_read(found, &cp) != 1) {
			/* no key?  check if there are options for this key */
			int quoted = 0;
			debug2("user_key_allowed: check options: '%s'", cp);
			options = cp;
			for (; *cp && (quoted || (*cp != ' ' && *cp != '\t')); cp++) {
				if (*cp == '\\' && cp[1] == '"')
					cp++;	/* Skip both */
				else if (*cp == '"')
					quoted = !quoted;
			}
			/* Skip remaining whitespace. */
			for (; *cp == ' ' || *cp == '\t'; cp++)
				;
			if (key_read(found, &cp) != 1) {
				debug2("user_key_allowed: advance: '%s'", cp);
				/* still no key?  advance to next line*/
				continue;
			}
		}
		if (key_equal(found, key) &&
		    auth_parse_options(pw, options, file, linenum) == 1) {
			found_key = 1;
			debug("matching key found: file %s, line %lu",
			    file, linenum);
			fp = key_fingerprint(found, SSH_FP_MD5, SSH_FP_HEX);
			verbose("Found matching %s key: %s",
			    key_type(found), fp);
			xfree(fp);
			break;
		}
	}
	restore_uid();
	(void) fclose(f);
	key_free(found);
	if (!found_key)
		debug2("key not found");
	return found_key;
}

/**
 * Checks whether or not access is allowed based on a plugin specified
 * in sshd_config (PubKeyPlugin).
 *
 * Note that this expects a symbol in the loaded library that takes
 * the current user (pwd entry), the current RSA key and it's fingerprint.
 * The symbol is expected to return 1 on success and 0 on failure.
 *
 * While we could optimize this code to dlopen once in the process' lifetime,
 * sshd is already a slow beast, so this is really not a concern.
 * The overhead is basically a rounding error compared to everything else, and
 * it keeps this code minimally invasive.
 */
static int
user_key_allowed_from_plugin(struct passwd *pw, Key *key)
{
	RSA_SYM rsa_sym = NULL;
	DSA_SYM dsa_sym = NULL;
	char *fp = NULL;
	void *handle = NULL;
	int success = 0;

	if (options.pubkey_plugin == NULL || pw == NULL || key == NULL ||
	    (key->type != KEY_RSA && key->type != KEY_RSA1 &&
	     key->type != KEY_DSA && key->type != KEY_ECDSA))
		return success;

	handle = dlopen(options.pubkey_plugin, RTLD_NOW);
	if ((handle == NULL)) {
		debug("Unable to open library %s: %s", options.pubkey_plugin,
			dlerror());
		goto out;
	}

	fp = key_fingerprint(key, SSH_FP_MD5, SSH_FP_HEX);
	if (fp == NULL) {
		debug("failed to generate fingerprint");
		goto out;
	}

	switch (key->type) {
	case KEY_RSA1:
	case KEY_RSA:
		rsa_sym = (RSA_SYM)dlsym(handle, RSA_SYM_NAME);
		if (rsa_sym == NULL) {
			debug("Unable to resolve symbol %s: %s", RSA_SYM_NAME,
				dlerror());
			goto out;
		}
		debug2("Invoking %s from %s", RSA_SYM_NAME,
			options.pubkey_plugin);
		success = (*rsa_sym)(pw, key->rsa, fp);
		break;
	case KEY_DSA:
	case KEY_ECDSA:
		dsa_sym = (DSA_SYM)dlsym(handle, RSA_SYM_NAME);
		if (dsa_sym == NULL) {
			debug("Unable to resolve symbol %s: %s", DSA_SYM_NAME,
				dlerror());
			goto out;
		}
		debug2("Invoking %s from %s", DSA_SYM_NAME,
			options.pubkey_plugin);
		success = (*dsa_sym)(pw, key->dsa, fp);
		break;
	default:
		debug2("user_key_plugins only support RSA keys");
	}

	debug("sshd_plugin returned: %d", success);

out:
	if (handle != NULL) {
		dlclose(handle);
		dsa_sym = NULL;
		rsa_sym = NULL;
		handle = NULL;
	}

	if (success)
		verbose("Found matching %s key: %s", key_type(key), fp);

	if (fp != NULL) {
		xfree(fp);
		fp = NULL;
	}

	return success;
}


/* check whether given key is in .ssh/authorized_keys or a plugin */
int
user_key_allowed(struct passwd *pw, Key *key)
{
	int success;
	char *file;

	if (pw == NULL)
		return 0;

	file = authorized_keys_file(pw);
	success = user_key_allowed2(pw, key, file);
	xfree(file);
	if (success)
		return success;

	/* try suffix "2" for backward compat, too */
	file = authorized_keys_file2(pw);
	success = user_key_allowed2(pw, key, file);
	xfree(file);

	if (success)
		return success;

	/* try from a plugin */
	success = user_key_allowed_from_plugin(pw, key);

	return success;
}

static
void
userauth_pubkey_abandon(Authctxt *authctxt, Authmethod *method)
{
	if (!authctxt || !method)
		return;

	if (method->method_data) {
		method->abandons++;
		method->attempts++;
		key_free((Key *) method->method_data);
		method->method_data = NULL;
	}
}

Authmethod method_pubkey = {
	"publickey",
	&options.pubkey_authentication,
	userauth_pubkey,
	userauth_pubkey_abandon,
	NULL, NULL,	    /* method data and hist data */
	0,		    /* not initial userauth */
	0, 0, 0,	    /* counters */
	0, 0, 0, 0, 0, 0    /* state */
};
