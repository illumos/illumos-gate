/* $Id: auth2-pam.h,v 1.2 2001/02/09 01:55:36 djm Exp $ */
/*
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_AUTH2_PAM_H
#define	_AUTH2_PAM_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#include "includes.h"
#ifdef USE_PAM

typedef struct Convctxt Convctxt;

struct Convctxt {
	int abandoned, finished, num_received, num_expected;
	int *prompts;
	struct pam_response *responses;
};

int	kbdint_pam_abandon_chk(Authctxt *authctxt, Authmethod *method);
void	kbdint_pam_abandon(Authctxt *authctxt, Authmethod *method);

void	auth2_pam(Authctxt *authctxt);

#endif /* USE_PAM */

#ifdef __cplusplus
}
#endif

#endif /* _AUTH2_PAM_H */
