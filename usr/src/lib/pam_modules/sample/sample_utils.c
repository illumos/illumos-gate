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
/*
 * Copyright (c) 1992-1995, by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma	ident	"%Z%%M%	%I%	%E% SMI"

#include <security/pam_appl.h>
#include <string.h>
#include <stdlib.h>
#include <malloc.h>

#include "sample_utils.h"

/* ******************************************************************** */
/*									*/
/* 		Utilities Functions					*/
/*									*/
/* ******************************************************************** */

/*
 * __free_msg():
 *	free storage for messages used in the call back "pam_conv" functions
 */

void
__free_msg(num_msg, msg)
	int num_msg;
	struct pam_message *msg;
{
	int 			i;
	struct pam_message 	*m;

	if (msg) {
		m = msg;
		for (i = 0; i < num_msg; i++, m++) {
			if (m->msg)
				free(m->msg);
		}
		free(msg);
	}
}

/*
 * __free_resp():
 *	free storage for responses used in the call back "pam_conv" functions
 */

void
__free_resp(num_msg, resp)
	int num_msg;
	struct pam_response *resp;
{
	int			i;
	struct pam_response	*r;

	if (resp) {
		r = resp;
		for (i = 0; i < num_msg; i++, r++) {
			if (r->resp)
				free(r->resp);
		}
		free(resp);
	}
}

/*
 * __display_errmsg():
 *	display error message by calling the call back functions
 *	provided by the application through "pam_conv" structure
 */

int
__display_errmsg(conv_funp, num_msg, messages, conv_apdp)
	int (*conv_funp)();
	int num_msg;
	char messages[PAM_MAX_NUM_MSG][PAM_MAX_MSG_SIZE];
	void *conv_apdp;
{
	struct pam_message	*msg;
	struct pam_message	*m;
	struct pam_response	*resp;
	int			i;
	int			k;
	int			retcode;

	msg = (struct pam_message *)calloc(num_msg,
					sizeof (struct pam_message));
	if (msg == NULL) {
		return (PAM_CONV_ERR);
	}
	m = msg;

	i = 0;
	k = num_msg;
	resp = NULL;
	while (k--) {
		/*
		 * fill out the pam_message structure to display error message
		 */
		m->msg_style = PAM_ERROR_MSG;
		m->msg = (char *)malloc(PAM_MAX_MSG_SIZE);
		if (m->msg != NULL)
			(void) strcpy(m->msg, (const char *)messages[i]);
		else
			continue;
		m++;
		i++;
	}

	/*
	 * Call conv function to display the message,
	 * ignoring return value for now
	 */
	retcode = conv_funp(num_msg, &msg, &resp, conv_apdp);
	__free_msg(num_msg, msg);
	__free_resp(num_msg, resp);
	return (retcode);
}

/*
 * __get_authtok():
 *	get authentication token by calling the call back functions
 *	provided by the application through "pam_conv" structure
 */

int
__get_authtok(conv_funp, num_msg, messages, conv_apdp, ret_respp)
	int (*conv_funp)();
	int num_msg;
	char messages[PAM_MAX_NUM_MSG][PAM_MAX_MSG_SIZE];
	void *conv_apdp;
	struct pam_response	**ret_respp;
{
	struct pam_message	*msg;
	struct pam_message	*m;
	int			i;
	int			k;
	int			retcode;

	i = 0;
	k = num_msg;

	msg = (struct pam_message *)calloc(num_msg,
						sizeof (struct pam_message));
	if (msg == NULL) {
		return (PAM_CONV_ERR);
	}
	m = msg;

	while (k--) {
		/*
		 * fill out the message structure to display error message
		 */
		m->msg_style = PAM_PROMPT_ECHO_OFF;
		m->msg = (char *)malloc(PAM_MAX_MSG_SIZE);
		if (m->msg != NULL)
			(void) strcpy(m->msg, (char *)messages[i]);
		else
			continue;
		m++;
		i++;
	}

	/*
	 * Call conv function to display the prompt,
	 * ignoring return value for now
	 */
	retcode = conv_funp(num_msg, &msg, ret_respp, conv_apdp);
	__free_msg(num_msg, msg);
	return (retcode);
}
