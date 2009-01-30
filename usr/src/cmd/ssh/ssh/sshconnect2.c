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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include "includes.h"
RCSID("$OpenBSD: sshconnect2.c,v 1.107 2002/07/01 19:48:46 markus Exp $");

#include "ssh.h"
#include "ssh2.h"
#include "xmalloc.h"
#include "buffer.h"
#include "packet.h"
#include "compat.h"
#include "bufaux.h"
#include "cipher.h"
#include "kex.h"
#include "myproposal.h"
#include "sshconnect.h"
#include "authfile.h"
#include "dh.h"
#include "authfd.h"
#include "log.h"
#include "readconf.h"
#include "readpass.h"
#include "match.h"
#include "dispatch.h"
#include "canohost.h"
#include "msg.h"
#include "pathnames.h"
#include "g11n.h"

#ifdef GSSAPI
#include "ssh-gss.h"
extern Gssctxt *xxx_gssctxt;
#endif /* GSSAPI */

/* import */
extern char *client_version_string;
extern char *server_version_string;
extern Options options;
extern Buffer command;

/*
 * SSH2 key exchange
 */

u_char *session_id2 = NULL;
int session_id2_len = 0;

char *xxx_host;
struct sockaddr *xxx_hostaddr;

Kex *xxx_kex = NULL;

static int
verify_host_key_callback(Key *hostkey)
{
	if (verify_host_key(xxx_host, xxx_hostaddr, hostkey) == -1)
		fatal("Host key verification failed.");
	return 0;
}

static int
accept_host_key_callback(Key *hostkey)
{
	if (accept_host_key(xxx_host, xxx_hostaddr, hostkey) == -1)
		log("GSS-API authenticated host key addition to "
			"known_hosts file failed");
	return 0;
}

void
ssh_kex2(char *host, struct sockaddr *hostaddr)
{
	Kex *kex;
	Kex_hook_func kex_hook = NULL;
	static char **myproposal;

	myproposal = my_clnt_proposal;

	xxx_host = host;
	xxx_hostaddr = hostaddr;

#ifdef GSSAPI
	/* Add the GSSAPI mechanisms currently supported on this client to
	 * the key exchange algorithm proposal */
	if (options.gss_keyex)
		kex_hook = ssh_gssapi_client_kex_hook;
#endif /* GSSAPI */
	if (options.ciphers == (char *)-1) {
		log("No valid ciphers for protocol version 2 given, using defaults.");
		options.ciphers = NULL;
	}
	if (options.ciphers != NULL) {
		myproposal[PROPOSAL_ENC_ALGS_CTOS] =
		myproposal[PROPOSAL_ENC_ALGS_STOC] = options.ciphers;
	}
	myproposal[PROPOSAL_ENC_ALGS_CTOS] =
	    compat_cipher_proposal(myproposal[PROPOSAL_ENC_ALGS_CTOS]);
	myproposal[PROPOSAL_ENC_ALGS_STOC] =
	    compat_cipher_proposal(myproposal[PROPOSAL_ENC_ALGS_STOC]);
	if (options.compression) {
		myproposal[PROPOSAL_COMP_ALGS_CTOS] =
		myproposal[PROPOSAL_COMP_ALGS_STOC] = "zlib,none";
	} else {
		myproposal[PROPOSAL_COMP_ALGS_CTOS] =
		myproposal[PROPOSAL_COMP_ALGS_STOC] = "none,zlib";
	}
	if (options.macs != NULL) {
		myproposal[PROPOSAL_MAC_ALGS_CTOS] =
		myproposal[PROPOSAL_MAC_ALGS_STOC] = options.macs;
	}
	if (options.hostkeyalgorithms != NULL)
		myproposal[PROPOSAL_SERVER_HOST_KEY_ALGS] =
		    options.hostkeyalgorithms;

	if (options.rekey_limit)
		packet_set_rekey_limit((u_int32_t)options.rekey_limit);

	if (datafellows & SSH_BUG_LOCALES_NOT_LANGTAGS) {
		char *locale = setlocale(LC_ALL, "");

		/* Solaris 9 SSHD expects a locale, not a langtag list */
		myproposal[PROPOSAL_LANG_CTOS] = "";
		if (locale != NULL && *locale != '\0' &&
		    strcmp(locale, "C") != 0)
			myproposal[PROPOSAL_LANG_CTOS] = locale;
	} else {
		myproposal[PROPOSAL_LANG_CTOS] = g11n_getlangs();
	}

	/* Same languages proposal for both directions */
	if (myproposal[PROPOSAL_LANG_CTOS] == NULL) {
		myproposal[PROPOSAL_LANG_CTOS] = "";
		myproposal[PROPOSAL_LANG_STOC] = "";
	} else {
		myproposal[PROPOSAL_LANG_STOC] =
			myproposal[PROPOSAL_LANG_CTOS];
	}

        /* start key exchange */
        kex = kex_setup(host, myproposal, kex_hook);
	kex_start(kex);
        kex->kex[KEX_DH_GRP1_SHA1] = kexdh_client;
        kex->kex[KEX_DH_GEX_SHA1] = kexgex_client;
#ifdef GSSAPI
	kex->kex[KEX_GSS_GRP1_SHA1] = kexgss_client;
	kex->options.gss_deleg_creds = options.gss_deleg_creds;
#endif /* GSSAPI */
        kex->client_version_string=client_version_string;
        kex->server_version_string=server_version_string;
        kex->verify_host_key=&verify_host_key_callback;
        kex->accept_host_key=&accept_host_key_callback;

	xxx_kex = kex;

	dispatch_run(DISPATCH_BLOCK, &kex->done, kex);

	session_id2 = kex->session_id;
	session_id2_len = kex->session_id_len;

#ifdef DEBUG_KEXDH
	/* send 1st encrypted/maced/compressed message */
	packet_start(SSH2_MSG_IGNORE);
	packet_put_cstring("markus");
	packet_send();
	packet_write_wait();
#endif
	debug("done: ssh_kex2.");
}

/*
 * Authenticate user
 */

typedef struct Authctxt Authctxt;
typedef struct Authmethod Authmethod;

typedef int sign_cb_fn(
    Authctxt *authctxt, Key *key,
    u_char **sigp, u_int *lenp, u_char *data, u_int datalen);

struct Authctxt {
	const char *server_user;
	const char *local_user;
	const char *host;
	const char *service;
	Authmethod *method;
	int success;
	char *authlist;
	/* pubkey */
	Key *last_key;
	sign_cb_fn *last_key_sign;
	int last_key_hint;
	AuthenticationConnection *agent;
	/* hostbased */
	Sensitive *sensitive;
	/* kbd-interactive */
	int info_req_seen;
	/* generic */
	void *methoddata;
};
struct Authmethod {
	char	*name;		/* string to compare against server's list */
	int	(*userauth)(Authctxt *authctxt);
	void	(*cleanup)(Authctxt *authctxt);
	int	*enabled;	/* flag in option struct that enables method */
	int	*batch_flag;	/* flag in option struct that disables method */
};

void	input_userauth_success(int, u_int32_t, void *);
void	input_userauth_failure(int, u_int32_t, void *);
void	input_userauth_banner(int, u_int32_t, void *);
void	input_userauth_error(int, u_int32_t, void *);
void	input_userauth_info_req(int, u_int32_t, void *);
void	input_userauth_pk_ok(int, u_int32_t, void *);
void	input_userauth_passwd_changereq(int, u_int32_t, void *);

int	userauth_none(Authctxt *);
int	userauth_pubkey(Authctxt *);
int	userauth_passwd(Authctxt *);
int	userauth_kbdint(Authctxt *);
int	userauth_hostbased(Authctxt *);

#ifdef GSSAPI
static	int	userauth_gssapi_keyex(Authctxt *authctxt);
static	int	userauth_gssapi(Authctxt *authctxt);
static	void	userauth_gssapi_cleanup(Authctxt *authctxt);
static	void	input_gssapi_response(int type, u_int32_t, void *);
static	void	input_gssapi_token(int type, u_int32_t, void *);
static	void	input_gssapi_hash(int type, u_int32_t, void *);
static	void	input_gssapi_error(int, u_int32_t, void *);
static	void	input_gssapi_errtok(int, u_int32_t, void *);
#endif /* GSSAPI */

void	userauth(Authctxt *, char *);

static int sign_and_send_pubkey(Authctxt *, Key *, sign_cb_fn *);
static void clear_auth_state(Authctxt *);

static Authmethod *authmethod_get(char *authlist);
static Authmethod *authmethod_lookup(const char *name);
static char *authmethods_get(void);

Authmethod authmethods[] = {
#ifdef GSSAPI
	{"gssapi-keyex",
		userauth_gssapi_keyex,
		userauth_gssapi_cleanup,
		&options.gss_keyex,
		NULL},
	{"gssapi-with-mic",
		userauth_gssapi,
		userauth_gssapi_cleanup,
		&options.gss_authentication,
		NULL},
#endif /* GSSAPI */
	{"hostbased",
		userauth_hostbased,
		NULL,
		&options.hostbased_authentication,
		NULL},
	{"publickey",
		userauth_pubkey,
		NULL,
		&options.pubkey_authentication,
		NULL},
	{"keyboard-interactive",
		userauth_kbdint,
		NULL,
		&options.kbd_interactive_authentication,
		&options.batch_mode},
	{"password",
		userauth_passwd,
		NULL,
		&options.password_authentication,
		&options.batch_mode},
	{"none",
		userauth_none,
		NULL,
		NULL,
		NULL},
	{NULL, NULL, NULL, NULL, NULL}
};

void
ssh_userauth2(const char *local_user, const char *server_user, char *host,
    Sensitive *sensitive)
{
	Authctxt authctxt;
	int type;

	if (options.challenge_response_authentication)
		options.kbd_interactive_authentication = 1;

	packet_start(SSH2_MSG_SERVICE_REQUEST);
	packet_put_cstring("ssh-userauth");
	packet_send();
	debug("send SSH2_MSG_SERVICE_REQUEST");
	packet_write_wait();
	type = packet_read();
	if (type != SSH2_MSG_SERVICE_ACCEPT)
		fatal("Server denied authentication request: %d", type);
	if (packet_remaining() > 0) {
		char *reply = packet_get_string(NULL);
		debug2("service_accept: %s", reply);
		xfree(reply);
	} else {
		debug2("buggy server: service_accept w/o service");
	}
	packet_check_eom();
	debug("got SSH2_MSG_SERVICE_ACCEPT");

	if (options.preferred_authentications == NULL)
		options.preferred_authentications = authmethods_get();

	/* setup authentication context */
	memset(&authctxt, 0, sizeof(authctxt));
	authctxt.agent = ssh_get_authentication_connection();
	authctxt.server_user = server_user;
	authctxt.local_user = local_user;
	authctxt.host = host;
	authctxt.service = "ssh-connection";		/* service name */
	authctxt.success = 0;
	authctxt.method = authmethod_lookup("none");
	authctxt.authlist = NULL;
	authctxt.methoddata = NULL;
	authctxt.sensitive = sensitive;
	authctxt.info_req_seen = 0;
	if (authctxt.method == NULL)
		fatal("ssh_userauth2: internal error: cannot send userauth none request");

	/* initial userauth request */
	userauth_none(&authctxt);

	dispatch_init(&input_userauth_error);
	dispatch_set(SSH2_MSG_USERAUTH_SUCCESS, &input_userauth_success);
	dispatch_set(SSH2_MSG_USERAUTH_FAILURE, &input_userauth_failure);
	dispatch_set(SSH2_MSG_USERAUTH_BANNER, &input_userauth_banner);
	dispatch_run(DISPATCH_BLOCK, &authctxt.success, &authctxt);	/* loop until success */

	if (authctxt.agent != NULL)
		ssh_close_authentication_connection(authctxt.agent);

	debug("Authentication succeeded (%s)", authctxt.method->name);
}
void
userauth(Authctxt *authctxt, char *authlist)
{
	if (authctxt->method != NULL &&
	    authctxt->method->cleanup != NULL)
		authctxt->method->cleanup(authctxt);
           
	if (authlist == NULL) {
		authlist = authctxt->authlist;
	} else {
		if (authctxt->authlist)
			xfree(authctxt->authlist);
		authctxt->authlist = authlist;
	}
	for (;;) {
		Authmethod *method = authmethod_get(authlist);
		if (method == NULL)
			fatal("Permission denied (%s).", authlist);
		authctxt->method = method;
		if (method->userauth(authctxt) != 0) {
			debug2("we sent a %s packet, wait for reply", method->name);
			break;
		} else {
			debug2("we did not send a packet, disable method");
			method->enabled = NULL;
		}
	}
}

void
input_userauth_error(int type, u_int32_t seq, void *ctxt)
{
	fatal("input_userauth_error: bad message during authentication: "
	   "type %d", type);
}

void
input_userauth_banner(int type, u_int32_t seq, void *ctxt)
{
	char *msg, *lang;

	debug3("input_userauth_banner");
	msg = packet_get_string(NULL);
	lang = packet_get_string(NULL);
	/*
	 * Banner is a warning message according to RFC 4252. So, never print
	 * a banner in error log level or lower. If the log level is higher,
	 * use DisableBanner option to decide whether to display it or not.
	 */
	if (options.log_level > SYSLOG_LEVEL_ERROR)
		if (options.disable_banner == 0 ||
		    (options.disable_banner == SSH_NO_BANNER_IN_EXEC_MODE &&
		    buffer_len(&command) == 0))
		fprintf(stderr, "%s", msg);
	xfree(msg);
	xfree(lang);
}

void
input_userauth_success(int type, u_int32_t seq, void *ctxt)
{
	Authctxt *authctxt = ctxt;
	if (authctxt == NULL)
		fatal("input_userauth_success: no authentication context");
	if (authctxt->authlist)
		xfree(authctxt->authlist);
	if (authctxt->method != NULL &&
	    authctxt->method->cleanup != NULL)
		authctxt->method->cleanup(authctxt);
	clear_auth_state(authctxt);
	authctxt->success = 1;			/* break out */
}

void
input_userauth_failure(int type, u_int32_t seq, void *ctxt)
{
	Authctxt *authctxt = ctxt;
	char *authlist = NULL;
	int partial;

	if (authctxt == NULL)
		fatal("input_userauth_failure: no authentication context");

	authlist = packet_get_string(NULL);
	partial = packet_get_char();
	packet_check_eom();

	if (partial != 0)
		log("Authenticated with partial success.");
	debug("Authentications that can continue: %s", authlist);

	clear_auth_state(authctxt);
	userauth(authctxt, authlist);
}
void
input_userauth_pk_ok(int type, u_int32_t seq, void *ctxt)
{
	Authctxt *authctxt = ctxt;
	Key *key = NULL;
	Buffer b;
	int pktype, sent = 0;
	u_int alen, blen;
	char *pkalg, *fp;
	u_char *pkblob;

	if (authctxt == NULL)
		fatal("input_userauth_pk_ok: no authentication context");
	if (datafellows & SSH_BUG_PKOK) {
		/* this is similar to SSH_BUG_PKAUTH */
		debug2("input_userauth_pk_ok: SSH_BUG_PKOK");
		pkblob = packet_get_string(&blen);
		buffer_init(&b);
		buffer_append(&b, pkblob, blen);
		pkalg = buffer_get_string(&b, &alen);
		buffer_free(&b);
	} else {
		pkalg = packet_get_string(&alen);
		pkblob = packet_get_string(&blen);
	}
	packet_check_eom();

	debug("Server accepts key: pkalg %s blen %u lastkey %p hint %d",
	    pkalg, blen, authctxt->last_key, authctxt->last_key_hint);

	do {
		if (authctxt->last_key == NULL ||
		    authctxt->last_key_sign == NULL) {
			debug("no last key or no sign cb");
			break;
		}
		if ((pktype = key_type_from_name(pkalg)) == KEY_UNSPEC) {
			debug("unknown pkalg %s", pkalg);
			break;
		}
		if ((key = key_from_blob(pkblob, blen)) == NULL) {
			debug("no key from blob. pkalg %s", pkalg);
			break;
		}
		if (key->type != pktype) {
			error("input_userauth_pk_ok: type mismatch "
			    "for decoded key (received %d, expected %d)",
			    key->type, pktype);
			break;
		}
		fp = key_fingerprint(key, SSH_FP_MD5, SSH_FP_HEX);
		debug2("input_userauth_pk_ok: fp %s", fp);
		xfree(fp);
		if (!key_equal(key, authctxt->last_key)) {
			debug("key != last_key");
			break;
		}
		sent = sign_and_send_pubkey(authctxt, key,
		   authctxt->last_key_sign);
	} while (0);

	if (key != NULL)
		key_free(key);
	xfree(pkalg);
	xfree(pkblob);

	/* unregister */
	clear_auth_state(authctxt);
	dispatch_set(SSH2_MSG_USERAUTH_PK_OK, NULL);

	/* try another method if we did not send a packet */
	if (sent == 0)
		userauth(authctxt, NULL);

}

#ifdef GSSAPI
int 
userauth_gssapi(Authctxt *authctxt)
{
	Gssctxt *gssctxt = NULL;
	static int initialized = 0;
	static int mech_idx = 0;
	static gss_OID_set supported = GSS_C_NULL_OID_SET;
	gss_OID mech = GSS_C_NULL_OID;

	/* Things work better if we send one mechanism at a time, rather
	 * than them all at once. This means that if we fail at some point
	 * in the middle of a negotiation, we can come back and try something
	 * different. */

	if (datafellows & SSH_OLD_GSSAPI) return 0;
	
	/* Before we offer a mechanism, check that we can support it. Don't
	 * bother trying to get credentials - as the standard fallback will
	 * deal with that kind of failure.
	 */

	if (!initialized) {
		initialized = 1;
		ssh_gssapi_client_mechs(authctxt->host, &supported);
		if (supported == GSS_C_NULL_OID_SET || supported->count == 0)
			return (0);
	} else if (supported != GSS_C_NULL_OID_SET) {
		/* Try next mech, if any */
		mech_idx++;

		if (mech_idx >= supported->count)
			return (0);
	} else {
		return (0);
	}

	mech = &supported->elements[mech_idx];

	ssh_gssapi_build_ctx(&gssctxt, 1, mech);
	authctxt->methoddata=(void *)gssctxt;
		
	packet_start(SSH2_MSG_USERAUTH_REQUEST);
	packet_put_cstring(authctxt->server_user);
	packet_put_cstring(authctxt->service);
        packet_put_cstring(authctxt->method->name);
	
	packet_put_int(1);

	/* The newest gsskeyex draft stipulates that OIDs should
	 * be DER encoded, so we need to add the object type and
	 * length information back on */
	if (datafellows & SSH_BUG_GSSAPI_BER) {
		packet_put_string(mech->elements, mech->length);
	} else {
		packet_put_int((mech->length)+2);
		packet_put_char(0x06);
		packet_put_char(mech->length);
		packet_put_raw(mech->elements, mech->length);
	}

        packet_send();
        packet_write_wait();

        dispatch_set(SSH2_MSG_USERAUTH_GSSAPI_RESPONSE,&input_gssapi_response);

        return 1;
}

void
input_gssapi_response(int type, u_int32_t plen, void *ctxt) 
{
	Authctxt *authctxt = ctxt;
	Gssctxt *gssctxt;
	OM_uint32 status,ms;
	u_int oidlen;
	char *oidv;
	gss_buffer_desc send_tok;
	
	if (authctxt == NULL)
		fatal("input_gssapi_response: no authentication context");
	gssctxt = authctxt->methoddata;
	
	/* Setup our OID */
	oidv=packet_get_string(&oidlen);
	
	if (datafellows & SSH_BUG_GSSAPI_BER) {
		if (!ssh_gssapi_check_mech_oid(gssctxt,oidv,oidlen)) {
			gss_OID oid;

			oid = ssh_gssapi_make_oid(oidlen, oidv);
			debug("Server returned different OID (%s) than expected (%s)",
				ssh_gssapi_oid_to_str(oid),
				ssh_gssapi_oid_to_str(gssctxt->desired_mech));
			ssh_gssapi_release_oid(&oid);
			clear_auth_state(authctxt);
			userauth(authctxt,NULL);
			return;
		}
	} else {
		if(oidv[0]!=0x06 || oidv[1]!=oidlen-2) {
			debug("Badly encoded mechanism OID received");
			clear_auth_state(authctxt);
			userauth(authctxt,NULL);
			return;
		}
		if (!ssh_gssapi_check_mech_oid(gssctxt,oidv+2,oidlen-2)) {
			gss_OID oid;

			oid = ssh_gssapi_make_oid(oidlen-2, oidv+2);
			debug("Server returned different OID (%s) than expected (%s)",
				ssh_gssapi_oid_to_str(oid),
				ssh_gssapi_oid_to_str(gssctxt->desired_mech));
			clear_auth_state(authctxt);
			userauth(authctxt,NULL);
			return;
		}
	}
		
	packet_check_eom();

        dispatch_set(SSH2_MSG_USERAUTH_GSSAPI_TOKEN,&input_gssapi_token);
	dispatch_set(SSH2_MSG_USERAUTH_GSSAPI_ERROR,&input_gssapi_error);
	dispatch_set(SSH2_MSG_USERAUTH_GSSAPI_ERRTOK,&input_gssapi_errtok);
	
	status = ssh_gssapi_init_ctx(gssctxt, authctxt->host,
					options.gss_deleg_creds,
					GSS_C_NO_BUFFER, &send_tok);
	if (GSS_ERROR(status)) {
		if (send_tok.length>0) {
			packet_start(SSH2_MSG_USERAUTH_GSSAPI_ERRTOK);
			packet_put_string(send_tok.value,send_tok.length);
			packet_send();
			packet_write_wait();
		}
		/* Start again with next method on list */
		debug("Trying to start again");
		clear_auth_state(authctxt);
		userauth(authctxt,NULL);
		return;
	}

	/* We must have data to send */					
	packet_start(SSH2_MSG_USERAUTH_GSSAPI_TOKEN);
	packet_put_string(send_tok.value,send_tok.length);
	packet_send();
	packet_write_wait();
	gss_release_buffer(&ms, &send_tok);
}

void
input_gssapi_token(int type, u_int32_t plen, void *ctxt)
{
	Authctxt *authctxt = ctxt;
	Gssctxt *gssctxt;
	gss_buffer_desc send_tok, recv_tok, g_mic_data;
	Buffer mic_data;
	OM_uint32 status;
	u_int slen;
	
	if (authctxt == NULL || authctxt->method == NULL)
		fatal("input_gssapi_response: no authentication context");
	gssctxt = authctxt->methoddata;
	
	recv_tok.value=packet_get_string(&slen);
	recv_tok.length=slen;	/* safe typecast */

	status=ssh_gssapi_init_ctx(gssctxt, authctxt->host,
					options.gss_deleg_creds,
					&recv_tok, &send_tok);

	packet_check_eom();
	
	if (GSS_ERROR(status)) {
		if (send_tok.length>0) {
			packet_start(SSH2_MSG_USERAUTH_GSSAPI_ERRTOK);
			packet_put_string(send_tok.value,send_tok.length);
			packet_send();
			packet_write_wait();
		}
		/* Start again with the next method in the list */
		clear_auth_state(authctxt);
		userauth(authctxt,NULL);
		return;
	}
	
	if (send_tok.length>0) {
		packet_start(SSH2_MSG_USERAUTH_GSSAPI_TOKEN);
		packet_put_string(send_tok.value,send_tok.length);
		packet_send();
		packet_write_wait();
	}

	if (status != GSS_S_COMPLETE)
		return;

	/* Make data buffer to MIC */
	buffer_init(&mic_data);
	buffer_put_string(&mic_data, session_id2, session_id2_len);
	buffer_put_char(&mic_data, SSH2_MSG_USERAUTH_REQUEST);
	buffer_put_cstring(&mic_data, authctxt->server_user);
	buffer_put_cstring(&mic_data, authctxt->service);
	buffer_put_cstring(&mic_data, authctxt->method->name);

	/* Make MIC */
	g_mic_data.value  = buffer_ptr(&mic_data);
	g_mic_data.length = buffer_len(&mic_data);

	status = ssh_gssapi_get_mic(gssctxt, &g_mic_data, &send_tok);
	buffer_clear(&mic_data);

	if (GSS_ERROR(status) || send_tok.length == 0) {
		/*
		 * Oops, now what?  There's no error token...
		 * Next userauth
		 */
		debug("GSS_GetMIC() failed! - "
		      "Abandoning GSSAPI userauth");
		clear_auth_state(authctxt);
		userauth(authctxt,NULL);
		return;
	}
	packet_start(SSH2_MSG_USERAUTH_GSSAPI_MIC);
	packet_put_string(send_tok.value,send_tok.length);
	packet_send();
	packet_write_wait();
}

void
input_gssapi_errtok(int type, u_int32_t plen, void *ctxt)
{
	OM_uint32 min_status;
	Authctxt *authctxt = ctxt;
	Gssctxt *gssctxt;
	gss_buffer_desc send_tok, recv_tok;
	
	if (authctxt == NULL)
		fatal("input_gssapi_response: no authentication context");
	gssctxt = authctxt->methoddata;
	
	recv_tok.value=packet_get_string(&recv_tok.length);

	/* Stick it into GSSAPI and see what it says */
	(void) ssh_gssapi_init_ctx(gssctxt, authctxt->host,
					options.gss_deleg_creds,
					&recv_tok, &send_tok);

	xfree(recv_tok.value);
	(void) gss_release_buffer(&min_status, &send_tok);

	debug("Server sent a GSS-API error token during GSS userauth -- %s",
		ssh_gssapi_last_error(gssctxt, NULL, NULL));

	packet_check_eom();
	
	/* We can't send a packet to the server */

	/* The draft says that we should wait for the server to fail 
	 * before starting the next authentication. So, we clear the
	 * state, but don't do anything else
	 */
	clear_auth_state(authctxt);
	return;
}

void
input_gssapi_error(int type, u_int32_t plen, void *ctxt)
{
	OM_uint32 maj,min;
	char *msg;
	char *lang;
	
	maj = packet_get_int();
	min = packet_get_int();
	msg = packet_get_string(NULL);
	lang = packet_get_string(NULL);

	packet_check_eom();
	
	fprintf(stderr, "Server GSSAPI Error:\n%s (%d, %d)\n", msg, maj, min);
	xfree(msg);
	xfree(lang);
}

int
userauth_gssapi_keyex(Authctxt *authctxt)
{
	Gssctxt *gssctxt;
	gss_buffer_desc send_tok;
	OM_uint32 status;
        static int attempt = 0;
	
	if (authctxt == NULL || authctxt->method == NULL)
		fatal("input_gssapi_response: no authentication context");

	if (xxx_gssctxt == NULL || xxx_gssctxt->context == GSS_C_NO_CONTEXT)
		return 0;

	if (strcmp(authctxt->method->name, "gssapi-keyex") == 0)
		authctxt->methoddata = gssctxt = xxx_gssctxt;
	
        if (attempt++ >= 1)
        	return 0;
                                
	if (strcmp(authctxt->method->name, "gssapi-keyex") == 0) {
		gss_buffer_desc g_mic_data;
		Buffer mic_data;

		debug2("Authenticating with GSS-API context from key exchange (w/ MIC)");

		/* Make data buffer to MIC */
		buffer_init(&mic_data);
		buffer_put_string(&mic_data, session_id2, session_id2_len);
		buffer_put_char(&mic_data, SSH2_MSG_USERAUTH_REQUEST);
		buffer_put_cstring(&mic_data, authctxt->server_user);
		buffer_put_cstring(&mic_data, authctxt->service);
		buffer_put_cstring(&mic_data, authctxt->method->name);

		/* Make MIC */
		g_mic_data.value  = buffer_ptr(&mic_data);
		g_mic_data.length = buffer_len(&mic_data);
		status = ssh_gssapi_get_mic(gssctxt, &g_mic_data, &send_tok);
		buffer_clear(&mic_data);

		if (GSS_ERROR(status) || send_tok.length == 0) {
			/*
			 * Oops, now what?  There's no error token...
			 * Next userauth
			 */
			debug("GSS_GetMIC() failed! - "
			      "Abandoning GSSAPI userauth");
			clear_auth_state(authctxt);
			userauth(authctxt,NULL);
			return 0;
		}
		packet_start(SSH2_MSG_USERAUTH_REQUEST);
		packet_put_cstring(authctxt->server_user);
		packet_put_cstring(authctxt->service);
		packet_put_cstring(authctxt->method->name);
		packet_put_string(send_tok.value,send_tok.length); /* MIC */
		packet_send();
		packet_write_wait();
		(void) gss_release_buffer(&status, &send_tok);
	} else if (strcmp(authctxt->method->name, "external-keyx") == 0) {
		debug2("Authentication with deprecated \"external-keyx\""
			" method not supported");
		return 0;
	}
        return 1;
}

static
void
userauth_gssapi_cleanup(Authctxt *authctxt)
{
	dispatch_set(SSH2_MSG_USERAUTH_GSSAPI_RESPONSE,NULL);
	dispatch_set(SSH2_MSG_USERAUTH_GSSAPI_TOKEN,NULL);
	dispatch_set(SSH2_MSG_USERAUTH_GSSAPI_ERROR,NULL);
	dispatch_set(SSH2_MSG_USERAUTH_GSSAPI_ERRTOK,NULL);

	if (authctxt == NULL ||
	    authctxt->method == NULL ||
	    authctxt->methoddata == NULL)
		return;

	if (strncmp(authctxt->method->name, "gssapi", strlen("gssapi")) == 0) {
		ssh_gssapi_delete_ctx((Gssctxt **)&authctxt->methoddata);
	}
}
#endif /* GSSAPI */

int
userauth_none(Authctxt *authctxt)
{
	/* initial userauth request */
	packet_start(SSH2_MSG_USERAUTH_REQUEST);
	packet_put_cstring(authctxt->server_user);
	packet_put_cstring(authctxt->service);
	packet_put_cstring(authctxt->method->name);
	packet_send();
	return 1;

}

int
userauth_passwd(Authctxt *authctxt)
{
	static int attempt = 0;
	char prompt[150];
	char *password;

	if (attempt++ >= options.number_of_password_prompts)
		return 0;

	if (attempt != 1)
		error("Permission denied, please try again.");

	snprintf(prompt, sizeof(prompt), gettext("%.30s@%.128s's password: "),
	    authctxt->server_user, authctxt->host);
	password = read_passphrase(prompt, 0);
	packet_start(SSH2_MSG_USERAUTH_REQUEST);
	packet_put_cstring(authctxt->server_user);
	packet_put_cstring(authctxt->service);
	packet_put_cstring(authctxt->method->name);
	packet_put_char(0);
	packet_put_cstring(password);
	memset(password, 0, strlen(password));
	xfree(password);
	packet_add_padding(64);
	packet_send();

	dispatch_set(SSH2_MSG_USERAUTH_PASSWD_CHANGEREQ,
	    &input_userauth_passwd_changereq);

	return 1;
}
/*
 * parse PASSWD_CHANGEREQ, prompt user and send SSH2_MSG_USERAUTH_REQUEST
 */
void
input_userauth_passwd_changereq(int type, u_int32_t seqnr, void *ctxt)
{
	Authctxt *authctxt = ctxt;
	char *info, *lang, *password = NULL, *retype = NULL;
	char prompt[150];

	debug2("input_userauth_passwd_changereq");

	if (authctxt == NULL)
		fatal("input_userauth_passwd_changereq: "
		    "no authentication context");

	info = packet_get_string(NULL);
	lang = packet_get_string(NULL);
	if (strlen(info) > 0)
		log("%s", info);
	xfree(info);
	xfree(lang);
	packet_start(SSH2_MSG_USERAUTH_REQUEST);
	packet_put_cstring(authctxt->server_user);
	packet_put_cstring(authctxt->service);
	packet_put_cstring(authctxt->method->name);
	packet_put_char(1);			/* additional info */
	snprintf(prompt, sizeof(prompt),
	    gettext("Enter %.30s@%.128s's old password: "),
	    authctxt->server_user, authctxt->host);
	password = read_passphrase(prompt, 0);
	packet_put_cstring(password);
	memset(password, 0, strlen(password));
	xfree(password);
	password = NULL;
	while (password == NULL) {
		snprintf(prompt, sizeof(prompt),
		    gettext("Enter %.30s@%.128s's new password: "),
		    authctxt->server_user, authctxt->host);
		password = read_passphrase(prompt, RP_ALLOW_EOF);
		if (password == NULL) {
			/* bail out */
			return;
		}
		snprintf(prompt, sizeof(prompt),
		    gettext("Retype %.30s@%.128s's new password: "),
		    authctxt->server_user, authctxt->host);
		retype = read_passphrase(prompt, 0);
		if (strcmp(password, retype) != 0) {
			memset(password, 0, strlen(password));
			xfree(password);
			log("Mismatch; try again, EOF to quit.");
			password = NULL;
		}
		memset(retype, 0, strlen(retype));
		xfree(retype);
	}
	packet_put_cstring(password);
	memset(password, 0, strlen(password));
	xfree(password);
	packet_add_padding(64);
	packet_send();

	dispatch_set(SSH2_MSG_USERAUTH_PASSWD_CHANGEREQ,
	    &input_userauth_passwd_changereq);
}

static void
clear_auth_state(Authctxt *authctxt)
{
	/* XXX clear authentication state */
	dispatch_set(SSH2_MSG_USERAUTH_PASSWD_CHANGEREQ, NULL);
#ifdef GSSAPI
	dispatch_set(SSH2_MSG_USERAUTH_GSSAPI_RESPONSE,NULL);
	dispatch_set(SSH2_MSG_USERAUTH_GSSAPI_TOKEN,NULL);
	dispatch_set(SSH2_MSG_USERAUTH_GSSAPI_ERROR,NULL);
#endif /* GSSAPI */
	
	if (authctxt->last_key != NULL && authctxt->last_key_hint == -1) {
		debug3("clear_auth_state: key_free %p", authctxt->last_key);
		key_free(authctxt->last_key);
	}
	authctxt->last_key = NULL;
	authctxt->last_key_hint = -2;
	authctxt->last_key_sign = NULL;
}

static int
sign_and_send_pubkey(Authctxt *authctxt, Key *k, sign_cb_fn *sign_callback)
{
	Buffer b;
	u_char *blob, *signature;
	u_int bloblen, slen;
	int skip = 0;
	int ret = -1;
	int have_sig = 1;

	debug3("sign_and_send_pubkey");

	if (key_to_blob(k, &blob, &bloblen) == 0) {
		/* we cannot handle this key */
		debug3("sign_and_send_pubkey: cannot handle key");
		return 0;
	}
	/* data to be signed */
	buffer_init(&b);
	if (datafellows & SSH_OLD_SESSIONID) {
		buffer_append(&b, session_id2, session_id2_len);
		skip = session_id2_len;
	} else {
		buffer_put_string(&b, session_id2, session_id2_len);
		skip = buffer_len(&b);
	}
	buffer_put_char(&b, SSH2_MSG_USERAUTH_REQUEST);
	buffer_put_cstring(&b, authctxt->server_user);
	buffer_put_cstring(&b,
	    datafellows & SSH_BUG_PKSERVICE ?
	    "ssh-userauth" :
	    authctxt->service);
	if (datafellows & SSH_BUG_PKAUTH) {
		buffer_put_char(&b, have_sig);
	} else {
		buffer_put_cstring(&b, authctxt->method->name);
		buffer_put_char(&b, have_sig);
		buffer_put_cstring(&b, key_ssh_name(k));
	}
	buffer_put_string(&b, blob, bloblen);

	/* generate signature */
	ret = (*sign_callback)(authctxt, k, &signature, &slen,
	    buffer_ptr(&b), buffer_len(&b));
	if (ret == -1) {
		xfree(blob);
		buffer_free(&b);
		return 0;
	}
#ifdef DEBUG_PK
	buffer_dump(&b);
#endif
	if (datafellows & SSH_BUG_PKSERVICE) {
		buffer_clear(&b);
		buffer_append(&b, session_id2, session_id2_len);
		skip = session_id2_len;
		buffer_put_char(&b, SSH2_MSG_USERAUTH_REQUEST);
		buffer_put_cstring(&b, authctxt->server_user);
		buffer_put_cstring(&b, authctxt->service);
		buffer_put_cstring(&b, authctxt->method->name);
		buffer_put_char(&b, have_sig);
		if (!(datafellows & SSH_BUG_PKAUTH))
			buffer_put_cstring(&b, key_ssh_name(k));
		buffer_put_string(&b, blob, bloblen);
	}
	xfree(blob);

	/* append signature */
	buffer_put_string(&b, signature, slen);
	xfree(signature);

	/* skip session id and packet type */
	if (buffer_len(&b) < skip + 1)
		fatal("userauth_pubkey: internal error");
	buffer_consume(&b, skip + 1);

	/* put remaining data from buffer into packet */
	packet_start(SSH2_MSG_USERAUTH_REQUEST);
	packet_put_raw(buffer_ptr(&b), buffer_len(&b));
	buffer_free(&b);
	packet_send();

	return 1;
}

static int
send_pubkey_test(Authctxt *authctxt, Key *k, sign_cb_fn *sign_callback,
    int hint)
{
	u_char *blob;
	u_int bloblen, have_sig = 0;

	debug3("send_pubkey_test");

	if (key_to_blob(k, &blob, &bloblen) == 0) {
		/* we cannot handle this key */
		debug3("send_pubkey_test: cannot handle key");
		return 0;
	}
	/* register callback for USERAUTH_PK_OK message */
	authctxt->last_key_sign = sign_callback;
	authctxt->last_key_hint = hint;
	authctxt->last_key = k;
	dispatch_set(SSH2_MSG_USERAUTH_PK_OK, &input_userauth_pk_ok);

	packet_start(SSH2_MSG_USERAUTH_REQUEST);
	packet_put_cstring(authctxt->server_user);
	packet_put_cstring(authctxt->service);
	packet_put_cstring(authctxt->method->name);
	packet_put_char(have_sig);
	if (!(datafellows & SSH_BUG_PKAUTH))
		packet_put_cstring(key_ssh_name(k));
	packet_put_string(blob, bloblen);
	xfree(blob);
	packet_send();
	return 1;
}

static Key *
load_identity_file(char *filename)
{
	Key *private;
	char prompt[300], *passphrase;
	int quit, i;
	struct stat st;

	if (stat(filename, &st) < 0) {
		debug3("no such identity: %s", filename);
		return NULL;
	}
	private = key_load_private_type(KEY_UNSPEC, filename, "", NULL);
	if (private == NULL) {
		if (options.batch_mode)
			return NULL;
		snprintf(prompt, sizeof prompt,
		    gettext("Enter passphrase for key '%.100s': "), filename);
		for (i = 0; i < options.number_of_password_prompts; i++) {
			passphrase = read_passphrase(prompt, 0);
			if (strcmp(passphrase, "") != 0) {
				private = key_load_private_type(KEY_UNSPEC, filename,
				    passphrase, NULL);
				quit = 0;
			} else {
				debug2("no passphrase given, try next key");
				quit = 1;
			}
			memset(passphrase, 0, strlen(passphrase));
			xfree(passphrase);
			if (private != NULL || quit)
				break;
			debug2("bad passphrase given, try again...");
		}
	}
	return private;
}

static int
identity_sign_cb(Authctxt *authctxt, Key *key, u_char **sigp, u_int *lenp,
    u_char *data, u_int datalen)
{
	Key *private;
	int idx, ret;

	idx = authctxt->last_key_hint;
	if (idx < 0)
		return -1;

	/* private key is stored in external hardware */
	if (options.identity_keys[idx]->flags & KEY_FLAG_EXT)
		return key_sign(options.identity_keys[idx], sigp, lenp, data, datalen);

	private = load_identity_file(options.identity_files[idx]);
	if (private == NULL)
		return -1;
	ret = key_sign(private, sigp, lenp, data, datalen);
	key_free(private);
	return ret;
}

static int
agent_sign_cb(Authctxt *authctxt, Key *key, u_char **sigp, u_int *lenp,
    u_char *data, u_int datalen)
{
	return ssh_agent_sign(authctxt->agent, key, sigp, lenp, data, datalen);
}

static int
key_sign_cb(Authctxt *authctxt, Key *key, u_char **sigp, u_int *lenp,
    u_char *data, u_int datalen)
{
	return key_sign(key, sigp, lenp, data, datalen);
}

static int
userauth_pubkey_agent(Authctxt *authctxt)
{
	static int called = 0;
	int ret = 0;
	char *comment;
	Key *k;

	if (called == 0) {
		if (ssh_get_num_identities(authctxt->agent, 2) == 0)
			debug2("userauth_pubkey_agent: no keys at all");
		called = 1;
	}
	k = ssh_get_next_identity(authctxt->agent, &comment, 2);
	if (k == NULL) {
		debug2("userauth_pubkey_agent: no more keys");
	} else {
		debug("Offering agent key: %s", comment);
		xfree(comment);
		ret = send_pubkey_test(authctxt, k, agent_sign_cb, -1);
		if (ret == 0)
			key_free(k);
	}
	if (ret == 0)
		debug2("userauth_pubkey_agent: no message sent");
	return ret;
}

int
userauth_pubkey(Authctxt *authctxt)
{
	static int idx = 0;
	int sent = 0;
	Key *key;
	char *filename;

	if (authctxt->agent != NULL) {
		do {
			sent = userauth_pubkey_agent(authctxt);
		} while (!sent && authctxt->agent->howmany > 0);
	}
	while (!sent && idx < options.num_identity_files) {
		key = options.identity_keys[idx];
		filename = options.identity_files[idx];
		if (key == NULL) {
			debug("Trying private key: %s", filename);
			key = load_identity_file(filename);
			if (key != NULL) {
				sent = sign_and_send_pubkey(authctxt, key,
				    key_sign_cb);
				key_free(key);
			}
		} else if (key->type != KEY_RSA1) {
			debug("Trying public key: %s", filename);
			sent = send_pubkey_test(authctxt, key,
			    identity_sign_cb, idx);
		}
		idx++;
	}
	return sent;
}

/*
 * Send userauth request message specifying keyboard-interactive method.
 */
int
userauth_kbdint(Authctxt *authctxt)
{
	static int attempt = 0;

	if (attempt++ >= options.number_of_password_prompts)
		return 0;
	/* disable if no SSH2_MSG_USERAUTH_INFO_REQUEST has been seen */
	if (attempt > 1 && !authctxt->info_req_seen) {
		debug3("userauth_kbdint: disable: no info_req_seen");
		dispatch_set(SSH2_MSG_USERAUTH_INFO_REQUEST, NULL);
		return 0;
	}

	debug2("userauth_kbdint");
	packet_start(SSH2_MSG_USERAUTH_REQUEST);
	packet_put_cstring(authctxt->server_user);
	packet_put_cstring(authctxt->service);
	packet_put_cstring(authctxt->method->name);
	packet_put_cstring("");					/* lang */
	packet_put_cstring(options.kbd_interactive_devices ?
	    options.kbd_interactive_devices : "");
	packet_send();

	dispatch_set(SSH2_MSG_USERAUTH_INFO_REQUEST, &input_userauth_info_req);
	return 1;
}

/*
 * parse INFO_REQUEST, prompt user and send INFO_RESPONSE
 */
void
input_userauth_info_req(int type, u_int32_t seq, void *ctxt)
{
	Authctxt *authctxt = ctxt;
	char *name, *inst, *lang, *prompt, *response;
	u_int num_prompts, i;
	int echo = 0;

	debug2("input_userauth_info_req");

	if (authctxt == NULL)
		fatal("input_userauth_info_req: no authentication context");

	authctxt->info_req_seen = 1;

	name = packet_get_string(NULL);
	inst = packet_get_string(NULL);
	lang = packet_get_string(NULL);
	if (strlen(name) > 0)
		log("%s", name);
	if (strlen(inst) > 0)
		log("%s", inst);
	xfree(name);
	xfree(inst);
	xfree(lang);

	num_prompts = packet_get_int();
	/*
	 * Begin to build info response packet based on prompts requested.
	 * We commit to providing the correct number of responses, so if
	 * further on we run into a problem that prevents this, we have to
	 * be sure and clean this up and send a correct error response.
	 */
	packet_start(SSH2_MSG_USERAUTH_INFO_RESPONSE);
	packet_put_int(num_prompts);

	debug2("input_userauth_info_req: num_prompts %d", num_prompts);
	for (i = 0; i < num_prompts; i++) {
		prompt = packet_get_string(NULL);
		echo = packet_get_char();

		response = read_passphrase(prompt, echo ? RP_ECHO : 0);

		packet_put_cstring(response);
		memset(response, 0, strlen(response));
		xfree(response);
		xfree(prompt);
	}
	packet_check_eom(); /* done with parsing incoming message. */

	packet_add_padding(64);
	packet_send();
}

static int
ssh_keysign(Key *key, u_char **sigp, u_int *lenp,
    u_char *data, u_int datalen)
{
	Buffer b;
	struct stat st;
	pid_t pid;
	int to[2], from[2], status, version = 2;

	debug2("ssh_keysign called");

	if (stat(_PATH_SSH_KEY_SIGN, &st) < 0) {
		error("ssh_keysign: no installed: %s", strerror(errno));
		return -1;
	}
	if (fflush(stdout) != 0)
		error("ssh_keysign: fflush: %s", strerror(errno));
	if (pipe(to) < 0) {
		error("ssh_keysign: pipe: %s", strerror(errno));
		return -1;
	}
	if (pipe(from) < 0) {
		error("ssh_keysign: pipe: %s", strerror(errno));
		return -1;
	}
	if ((pid = fork()) < 0) {
		error("ssh_keysign: fork: %s", strerror(errno));
		return -1;
	}
	if (pid == 0) {
		seteuid(getuid());
		setuid(getuid());
		close(from[0]);
		if (dup2(from[1], STDOUT_FILENO) < 0)
			fatal("ssh_keysign: dup2: %s", strerror(errno));
		close(to[1]);
		if (dup2(to[0], STDIN_FILENO) < 0)
			fatal("ssh_keysign: dup2: %s", strerror(errno));
		close(from[1]);
		close(to[0]);
		execl(_PATH_SSH_KEY_SIGN, _PATH_SSH_KEY_SIGN, (char *) 0);
		fatal("ssh_keysign: exec(%s): %s", _PATH_SSH_KEY_SIGN,
		    strerror(errno));
	}
	close(from[1]);
	close(to[0]);

	buffer_init(&b);
	buffer_put_int(&b, packet_get_connection_in()); /* send # of socket */
	buffer_put_string(&b, data, datalen);
	ssh_msg_send(to[1], version, &b);

	if (ssh_msg_recv(from[0], &b) < 0) {
		error("ssh_keysign: no reply");
		buffer_clear(&b);
		return -1;
	}
	close(from[0]);
	close(to[1]);

	while (waitpid(pid, &status, 0) < 0)
		if (errno != EINTR)
			break;

	if (buffer_get_char(&b) != version) {
		error("ssh_keysign: bad version");
		buffer_clear(&b);
		return -1;
	}
	*sigp = buffer_get_string(&b, lenp);
	buffer_clear(&b);

	return 0;
}

int
userauth_hostbased(Authctxt *authctxt)
{
	Key *private = NULL;
	Sensitive *sensitive = authctxt->sensitive;
	Buffer b;
	u_char *signature, *blob;
	char *chost, *pkalg, *p;
	const char *service;
	u_int blen, slen;
	int ok, i, len, found = 0;
	static int last_hostkey = -1;

	/* check for a useful key */
	for (i = 0; i < sensitive->nkeys; i++) {
		private = sensitive->keys[i];
		if (private && private->type != KEY_RSA1 && i > last_hostkey) {
			found = 1;
			last_hostkey = i;
			/* we take and free the key */
			sensitive->keys[i] = NULL;
			break;
		}
	}
	if (!found) {
		debug("No more client hostkeys for hostbased authentication");
		return 0;
	}
	if (key_to_blob(private, &blob, &blen) == 0) {
		key_free(private);
		return 0;
	}
	/* figure out a name for the client host */
	p = get_local_name(packet_get_connection_in());
	if (p == NULL) {
		error("userauth_hostbased: cannot get local ipaddr/name");
		key_free(private);
		return 0;
	}

	service = datafellows & SSH_BUG_HBSERVICE ? "ssh-userauth" :
	    authctxt->service;
	pkalg = xstrdup(key_ssh_name(private));

	len = strlen(p) + 2;
	chost = xmalloc(len);
	strlcpy(chost, p, len);
	strlcat(chost, ".", len);
	xfree(p);
	debug2("userauth_hostbased: chost %s, pkalg %s", chost, pkalg);

	buffer_init(&b);
	/* construct data */
	buffer_put_string(&b, session_id2, session_id2_len);
	buffer_put_char(&b, SSH2_MSG_USERAUTH_REQUEST);
	buffer_put_cstring(&b, authctxt->server_user);
	buffer_put_cstring(&b, service);
	buffer_put_cstring(&b, authctxt->method->name);
	buffer_put_cstring(&b, pkalg);
	buffer_put_string(&b, blob, blen);
	buffer_put_cstring(&b, chost);
	buffer_put_cstring(&b, authctxt->local_user);
#ifdef DEBUG_PK
	buffer_dump(&b);
#endif
	if (sensitive->external_keysign)
		ok = ssh_keysign(private, &signature, &slen,
		    buffer_ptr(&b), buffer_len(&b));
	else
		ok = key_sign(private, &signature, &slen,
		    buffer_ptr(&b), buffer_len(&b));
	key_free(private);
	buffer_free(&b);
	if (ok != 0) {
		error("key_sign failed");
		xfree(chost);
		xfree(pkalg);
		return 0;
	}
	packet_start(SSH2_MSG_USERAUTH_REQUEST);
	packet_put_cstring(authctxt->server_user);
	packet_put_cstring(authctxt->service);
	packet_put_cstring(authctxt->method->name);
	packet_put_cstring(pkalg);
	packet_put_string(blob, blen);
	packet_put_cstring(chost);
	packet_put_cstring(authctxt->local_user);
	packet_put_string(signature, slen);
	memset(signature, 's', slen);
	xfree(signature);
	xfree(chost);
	xfree(pkalg);

	packet_send();
	return 1;
}

/* find auth method */

/*
 * given auth method name, if configurable options permit this method fill
 * in auth_ident field and return true, otherwise return false.
 */
static int
authmethod_is_enabled(Authmethod *method)
{
	if (method == NULL)
		return 0;
	/* return false if options indicate this method is disabled */
	if  (method->enabled == NULL || *method->enabled == 0)
		return 0;
	/* return false if batch mode is enabled but method needs interactive mode */
	if  (method->batch_flag != NULL && *method->batch_flag != 0)
		return 0;
	return 1;
}

static Authmethod *
authmethod_lookup(const char *name)
{
	Authmethod *method = NULL;
	if (name != NULL) {
		for (method = authmethods; method->name != NULL; method++) {
			if (strcmp(name, method->name) == 0)
				return method;
		}
	}
	debug2("Unrecognized authentication method name: %s", name ? name : "NULL");
	return NULL;
}

/* XXX internal state */
static Authmethod *current = NULL;
static char *supported = NULL;
static char *preferred = NULL;

/*
 * Given the authentication method list sent by the server, return the
 * next method we should try.  If the server initially sends a nil list,
 * use a built-in default list.
 */
static Authmethod *
authmethod_get(char *authlist)
{

	char *name = NULL;
	u_int next;

	/* Use a suitable default if we're passed a nil list.  */
	if (authlist == NULL || strlen(authlist) == 0)
		authlist = options.preferred_authentications;

	if (supported == NULL || strcmp(authlist, supported) != 0) {
		debug3("start over, passed a different list %s", authlist);
		if (supported != NULL)
			xfree(supported);
		supported = xstrdup(authlist);
		preferred = options.preferred_authentications;
		debug3("preferred %s", preferred);
		current = NULL;
	} else if (current != NULL && authmethod_is_enabled(current))
		return current;

	for (;;) {
		if ((name = match_list(preferred, supported, &next)) == NULL) {
			debug("No more authentication methods to try.");
			current = NULL;
			return NULL;
		}
		preferred += next;
		debug3("authmethod_lookup %s", name);
		debug3("remaining preferred: %s", preferred);
		if ((current = authmethod_lookup(name)) != NULL &&
		    authmethod_is_enabled(current)) {
			debug3("authmethod_is_enabled %s", name);
			debug("Next authentication method: %s", name);
			return current;
		}
	}
}

static char *
authmethods_get(void)
{
	Authmethod *method = NULL;
	Buffer b;
	char *list;

	buffer_init(&b);
	for (method = authmethods; method->name != NULL; method++) {
		if (authmethod_is_enabled(method)) {
			if (buffer_len(&b) > 0)
				buffer_append(&b, ",", 1);
			buffer_append(&b, method->name, strlen(method->name));
		}
	}
	buffer_append(&b, "\0", 1);
	list = xstrdup(buffer_ptr(&b));
	buffer_free(&b);
	return list;
}
