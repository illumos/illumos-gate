/*	$OpenBSD: auth.h,v 1.41 2002/09/26 11:38:43 markus Exp $	*/

#ifndef	_AUTH_H
#define	_AUTH_H

#ifdef __cplusplus
extern "C" {
#endif


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
 *
 */
/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include "key.h"
#include "hostfile.h"
#include <openssl/rsa.h>

#ifdef USE_PAM
#include <security/pam_appl.h>
#endif /* USE_PAM */

#ifdef HAVE_LOGIN_CAP
#include <login_cap.h>
#endif
#ifdef BSD_AUTH
#include <bsd_auth.h>
#endif
#ifdef KRB5
#include <krb5.h>
#endif

typedef struct Authctxt Authctxt;
typedef struct Authmethod Authmethod;
typedef struct KbdintDevice KbdintDevice;

#ifdef USE_PAM
typedef struct pam_stuff pam_stuff;

struct pam_stuff {
	Authctxt	*authctxt;
	pam_handle_t	*h;
	int		state;
	int		last_pam_retval;
};

/* See auth-pam.h and auth-pam.c */

#define PAM_S_DONE_ACCT_MGMT		0x01 /* acct_mgmt done */
#define PAM_S_DONE_SETCRED		0x02 /* setcred done */
#define PAM_S_DONE_OPEN_SESSION		0x04 /* open_session done */
#define PAM_S_DONE			0x07 /* all done */
#endif /* USE_PAM */

struct Authctxt {
	int		 success;
	int		 valid;
	int		 attempt;	/* all userauth attempt count */
	int		 init_attempt;	/* passwd/kbd-int attempt count */
	int		 failures;
	int		 init_failures;
	int		 unwind_dispatch_loop;
	int		 v1_auth_type;
	char		*v1_auth_name;
	Authmethod	*method;
	char		*user;
	char		*service;
	struct passwd	*pw;
	char		*style;
	void		*kbdintctxt;	/* XXX Switch to method_data;
					   v1 still needs this*/
#ifdef USE_PAM
	pam_stuff	*pam;
	char		*cuser; /* client side user, needed for setting
				   PAM_AUSER for hostbased authentication
				   using roles */
	u_long		 last_login_time; /* need to get the time of
					     last login before calling
					     pam_open_session() */
	char		 last_login_host[MAXHOSTNAMELEN];
	int		 pam_retval;	/* pam_stuff is cleaned before
					   BSM login failure auditing */
#endif /* USE_PAM */
	
	/* SUNW - What follows remains to reduce diffs with OpenSSH but
	 *	  is not used in Solaris.  The Solaris SSH internal
	 *	  architecture requires that this stuff move into the
	 *	  Authmethod method_data.
	 */
#ifndef	SUNW_SSH
#ifdef BSD_AUTH
	auth_session_t	*as;
#endif
#ifdef KRB4
	char		*krb4_ticket_file;
#endif
#ifdef KRB5
	krb5_context	 krb5_ctx;
	krb5_auth_context krb5_auth_ctx;
	krb5_ccache	 krb5_fwd_ccache;
	krb5_principal	 krb5_user;
	char		*krb5_ticket_file;
#endif
	void *methoddata;
#endif /* SUNW_SSH */
};

struct Authmethod {
	char	*name;
	int	*enabled;
	/*
	 * Userauth method state tracking fields updated in
	 * input_userauth_request() and auth-pam.c.
	 *
	 * The "void (*userauth)(Authctxt *authctxt)" function
	 * communicates the userauth result (success, failure,
	 * "postponed," abandoned) through the 'authenticated',
	 * 'postponed' and 'abandoned' fields.  Partial success is
	 * indicated by requiring other userauths to be used by setting
	 * their 'required' or 'sufficient' fields.
	 *
	 * Individual methods should only ever set 'not_again' if it
	 * makes no sense to complete the same userauth more than once,
	 * and they should set any methods' sufficient or required flags
	 * in order to force partial authentication and require that
	 * more userauths be tried.  The (void *) 'method_data' and
	 * 'hist_method_data' pointers can be used by methods such as
	 * pubkey which may make sense to run more than once during
	 * userauth or which may require multiple round tripes (e.g.,
	 * keyboard-interactive) and which need to keep some state;
	 * 'hist_method_data' is there specifically for pubkey userauth
	 * where multiple successful attempts should all use different
	 * keys.
	 *
	 * The "attempts," "abandons," "successes" and "failures" fields
	 * count the number of times a method has been attempted,
	 * abandoned, and has succeeded or failed.  Note that pubkey
	 * userauth does not double-count sig-less probes that are
	 * followed by a pubkey request for the same pubkey anw with a
	 * signature.
	 */
	void		(*userauth)(Authctxt *authctxt);
	void		(*abandon)(Authctxt *, Authmethod *);
	void		*method_data;
	void		*hist_method_data;
	unsigned int	 is_initial;
	unsigned int	 attempts:8;
	unsigned int	 abandons:8;
	unsigned int	 successes:8;
	unsigned int	 failures:8;
	/*
	 * Post-attempt state booleans (authenticated, abandoned, etc...)
	 */
	unsigned int	 authenticated:1;
	unsigned int	 not_again:1;
	unsigned int	 sufficient:1;
	unsigned int	 required:1;
	unsigned int	 postponed:1;
	unsigned int	 abandoned:1;
	/*
	 * NOTE: multi-round-trip userauth methods can either
	 *       recursively call dispatch_run and detect abandonment
	 *       within their message handlers (as PAM kbd-int does) or
	 *       set the postponed flag and let input_userauth_request()
	 *       detect abandonment (i.e., initiation of some userauth
	 *       method before completion of a started, multi-round-trip
	 *       userauth method).
	 *
	 */
};

/*
 * Keyboard interactive device:
 * init_ctx	returns: non NULL upon success
 * query	returns: 0 - success, otherwise failure
 * respond	returns: 0 - success, 1 - need further interaction,
 *		otherwise - failure
 */
struct KbdintDevice
{
	const char *name;
	void*	(*init_ctx)(Authctxt*);
	int	(*query)(void *ctx, char **name, char **infotxt,
		    u_int *numprompts, char ***prompts, u_int **echo_on);
	int	(*respond)(void *ctx, u_int numresp, char **responses);
	void	(*free_ctx)(void *ctx);
};

int      auth_rhosts(struct passwd *, const char *);
int
auth_rhosts2(struct passwd *, const char *, const char *, const char *);

int	 auth_rhosts_rsa(struct passwd *, char *, Key *);
int      auth_password(Authctxt *, const char *);
int      auth_rsa(struct passwd *, BIGNUM *);
int      auth_rsa_challenge_dialog(Key *);
BIGNUM	*auth_rsa_generate_challenge(Key *);
int	 auth_rsa_verify_response(Key *, BIGNUM *, u_char[]);
int	 auth_rsa_key_allowed(struct passwd *, BIGNUM *, Key **);

int	 auth_rhosts_rsa_key_allowed(struct passwd *, char *, char *, Key *);
int	 hostbased_key_allowed(struct passwd *, const char *, char *, Key *);
int	 user_key_allowed(struct passwd *, Key *);

#ifdef KRB4
#include <krb.h>
int     auth_krb4(Authctxt *, KTEXT, char **, KTEXT);
int	auth_krb4_password(Authctxt *, const char *);
void    krb4_cleanup_proc(void *);

#ifdef AFS
#include <kafs.h>
int     auth_krb4_tgt(Authctxt *, const char *);
int     auth_afs_token(Authctxt *, const char *);
#endif /* AFS */

#endif /* KRB4 */

#ifdef KRB5
int	auth_krb5(Authctxt *authctxt, krb5_data *auth, char **client, krb5_data *);
int	auth_krb5_tgt(Authctxt *authctxt, krb5_data *tgt);
int	auth_krb5_password(Authctxt *authctxt, const char *password);
void	krb5_cleanup_proc(void *authctxt);
#endif /* KRB5 */

#include "auth-pam.h"
#include "auth2-pam.h"

Authctxt *do_authentication(void);
Authctxt *do_authentication2(void);

#ifdef HAVE_BSM
void	audit_failed_login_cleanup(void *);
#endif /* HAVE_BSM */

int	userauth_check_partial_failure(Authctxt *authctxt);
void	userauth_force_kbdint(void);

Authctxt *authctxt_new(void);
void	auth_log(Authctxt *, int, char *, char *);
void	userauth_finish(Authctxt *, char *);
void	userauth_user_svc_change(Authctxt *authctxt,
				 char *user,
				 char *service);
int	auth_root_allowed(char *);

char	*auth2_read_banner(void);

void	privsep_challenge_enable(void);

void	auth2_challenge(Authctxt *, char *);
void	auth2_challenge_abandon(Authctxt *);
int	bsdauth_query(void *, char **, char **, u_int *, char ***, u_int **);
int	bsdauth_respond(void *, u_int, char **);
int	skey_query(void *, char **, char **, u_int *, char ***, u_int **);
int	skey_respond(void *, u_int, char **);

struct passwd * getpwnamallow(const char *user);

int	run_auth_hook(const char *, const char *, const char *);

char	*get_challenge(Authctxt *);
int	verify_response(Authctxt *, const char *);

struct passwd * auth_get_user(void);

char	*authorized_keys_file(struct passwd *);
char	*authorized_keys_file2(struct passwd *);

int
secure_filename(FILE *, const char *, struct passwd *, char *, size_t);

HostStatus
check_key_in_hostfiles(struct passwd *, Key *, const char *,
    const char *, const char *);

/* hostkey handling */
#ifndef lint
Key	*get_hostkey_by_index(int);
Key	*get_hostkey_by_type(int);
int	 get_hostkey_index(Key *);
#endif /* lint */
int	 ssh1_session_key(BIGNUM *);

/* debug messages during authentication */
void	 auth_debug_add(const char *fmt,...) __attribute__((format(printf, 1, 2)));
void	 auth_debug_send(void);
void	 auth_debug_reset(void);

#define AUTH_FAIL_MAX 6
#define AUTH_FAIL_LOG (AUTH_FAIL_MAX/2)
#define AUTH_FAIL_MSG "Too many authentication failures for %.100s"

#define SKEY_PROMPT "\nS/Key Password: "

#ifdef __cplusplus
}
#endif

#endif /* _AUTH_H */
