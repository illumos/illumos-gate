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
 * This file has all of the PAM related code for sys-suspend.  It is
 * part of it's own file, as these could be part of some bigger item
 * that can handle generic PAM facilities (certainly the getinput()
 * function could be in a common library).  However, as that does not
 * yet exist, we replicate it here so we can get the job done.
 */

#define	__EXTENSIONS__	/* to expose flockfile and friends in stdio.h */
#include <errno.h>
#include <libgen.h>
#include <malloc.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <stropts.h>
#include <unistd.h>
#include <termio.h>

#include <security/pam_appl.h>

static int ctl_c;	/* was the conversation interrupted? */

/* ARGSUSED 1 */
static void
interrupt(int x)
{
	ctl_c = 1;
}

/*
 * getinput -- read user input from stdin abort on ^C
 *
 *	Entry	noecho == TRUE, don't echo input.
 *
 *	Exit	User's input.
 *		If interrupted, send SIGINT to caller for processing.
 */
static char *
getinput(int noecho)
{
	struct termio tty;
	unsigned short tty_flags = 0;
	char input[PAM_MAX_RESP_SIZE + 1];
	int c;
	int i = 0;
	void (*sig)(int);

	ctl_c = 0;
	sig = signal(SIGINT, interrupt);
	if (noecho) {
		(void) ioctl(fileno(stdin), TCGETA, &tty);
		tty_flags = tty.c_lflag;
		tty.c_lflag &= ~(ECHO | ECHOE | ECHOK | ECHONL);
		(void) ioctl(fileno(stdin), TCSETAF, &tty);
	}
	/* go to end, but don't overflow PAM_MAX_RESP_SIZE */
	flockfile(stdin);
	while (ctl_c == 0 &&
	    (c = getchar_unlocked()) != '\n' &&
	    c != '\r' &&
	    c != EOF) {
		if (i < PAM_MAX_RESP_SIZE) {
			input[i++] = (char)c;
		}
	}
	funlockfile(stdin);
	input[i] = '\0';
	if (noecho) {
		tty.c_lflag = tty_flags;
		(void) ioctl(fileno(stdin), TCSETAW, &tty);
		(void) fputc('\n', stdout);
	}
	(void) signal(SIGINT, sig);
	if (ctl_c == 1)
		(void) kill(getpid(), SIGINT);

	return (strdup(input));
}

/*
 * Service modules don't clean up responses if an error is returned.
 * Free responses here.
 */
static void
free_resp(int num_msg, struct pam_response *pr)
{
	int i;
	struct pam_response *r = pr;

	if (pr == NULL)
		return;

	for (i = 0; i < num_msg; i++, r++) {

		if (r->resp) {
			/* clear before freeing -- may be a password */
			bzero(r->resp, strlen(r->resp));
			free(r->resp);
			r->resp = NULL;
		}
	}
	free(pr);
}

/* ARGSUSED */
int
pam_tty_conv(int num_msg, struct pam_message **mess,
    struct pam_response **resp, void *my_data)
{
	struct pam_message *m = *mess;
	struct pam_response *r = calloc(num_msg, sizeof (struct pam_response));
	int i;

	if (num_msg >= PAM_MAX_NUM_MSG) {
		(void) fprintf(stderr, "too many messages %d >= %d\n",
		    num_msg, PAM_MAX_NUM_MSG);
		free(r);
		*resp = NULL;
		return (PAM_CONV_ERR);
	}

	/* Talk it out */
	*resp = r;
	for (i = 0; i < num_msg; i++) {
		int echo_off;

		/* bad message from service module */
		if (m->msg == NULL) {
			(void) fprintf(stderr, "message[%d]: %d/NULL\n",
			    i, m->msg_style);
			goto err;
		}

		/*
		 * fix up final newline:
		 * 	removed for prompts
		 * 	added back for messages
		 */
		if (m->msg[strlen(m->msg)] == '\n')
			m->msg[strlen(m->msg)] = '\0';

		r->resp = NULL;
		r->resp_retcode = 0;
		echo_off = 0;
		switch (m->msg_style) {

		case PAM_PROMPT_ECHO_OFF:
			echo_off = 1;
			/*FALLTHROUGH*/

		case PAM_PROMPT_ECHO_ON:
			(void) fputs(m->msg, stdout);

			r->resp = getinput(echo_off);
			break;

		case PAM_ERROR_MSG:
			(void) fputs(m->msg, stderr);
			(void) fputc('\n', stderr);
			break;

		case PAM_TEXT_INFO:
			(void) fputs(m->msg, stdout);
			(void) fputc('\n', stdout);
			break;

		default:
			(void) fprintf(stderr, "message[%d]: unknown type "
			    "%d/val=\"%s\"\n",
			    i, m->msg_style, m->msg);
			/* error, service module won't clean up */
			goto err;
		}
		if (errno == EINTR)
			goto err;

		/* next message/response */
		m++;
		r++;
	}
	return (PAM_SUCCESS);

err:
	free_resp(i, r);
	*resp = NULL;
	return (PAM_CONV_ERR);
}
