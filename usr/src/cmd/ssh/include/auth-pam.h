/*
 * Copyright (c) 2000 Damien Miller.  All rights reserved.
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
 * Copyright (c) 2001, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/* $Id: auth-pam.h,v 1.16 2002/07/23 00:44:07 stevesk Exp $ */

#ifndef	_AUTH_PAM_H
#define	_AUTH_PAM_H

#ifdef __cplusplus
extern "C" {
#endif

#include "includes.h"
#ifdef USE_PAM

char * derive_pam_svc_name(Authmethod *method);
void new_start_pam(Authctxt *authctxt, struct pam_conv *conv);
int auth_pam_password(Authctxt *authctxt, const char *password);
int do_pam_non_initial_userauth(Authctxt *authctxt);
int finish_userauth_do_pam(Authctxt *authctxt);
void finish_pam(Authctxt *authctxt);
char **fetch_pam_environment(Authctxt *authctxt);
void free_pam_environment(char **env);
void message_cat(char **p, const char *a);
void print_pam_messages(void);

#define AUTHPAM_DONE(ac) (ac != NULL && \
			ac->pam != NULL && \
			ac->pam->h != NULL && \
			ac->pam->state == PAM_S_DONE)

#define AUTHPAM_RETVAL(ac, rv) ((ac != NULL && ac->pam != NULL) ? \
	ac->pam->last_pam_retval : rv)

#define AUTHPAM_ERROR(ac, rv) ((ac != NULL && ac->pam != NULL && \
				ac->pam->last_pam_retval != PAM_SUCCESS) ? \
			ac->pam->last_pam_retval : rv)

#endif	/* USE_PAM */

#ifdef __cplusplus
}
#endif

#endif /* _AUTH_PAM_H */
