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
 * Copyright 2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * modem_setup.c: support for the scadm modem_setup option (access to the
 * service processor modem - if present)
 */

#include <curses.h>
#include <libintl.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <time.h>  /* required by librsc.h */
#include <unistd.h>

#include "librsc.h"
#include "adm.h"


extern char *ADM_Get_Var(char *Variable);

static void ADM_Send_Char(char  C);
static void *ADM_Modem_Listen(void *);
static void cleanup();


typedef enum {ST_RESET, ST_IDLE, ST_TILDA} ADM_state_t;

static int ADM_Continue;
static int winOn = 0;
static pthread_t modemListen;


void
ADM_Process_modem_setup(void)
{
	rscp_msg_t	msg;
	struct timespec	timeout;

	int		Input;
	ADM_state_t	State;
	int		exitLoop = 1;
	char		rsc_escape[2];
	char		string[40];


	ADM_Start();

	msg.type = DP_MODEM_CONNECT;
	msg.len  = 0;
	msg.data = NULL;
	ADM_Send(&msg);

	timeout.tv_nsec = 0;
	timeout.tv_sec  = ADM_TIMEOUT;
	ADM_Recv(&msg, &timeout, DP_MODEM_CONNECT_R,
	    sizeof (dp_modem_connect_r_t));
	if (*(int *)msg.data != DP_MODEM_PASS) {
		(void) fprintf(stderr, "\n%s\n\n",
		    gettext("scadm: could not connect to modem"));
		exit(-1);
	}
	ADM_Free(&msg);

	/* Get the escape char BEFORE starting up the "listen" thread */
	(void) strcpy(rsc_escape, ADM_Get_Var("escape_char"));


	/* Create Listening Thread */
	ADM_Continue = 1;
	if (pthread_create(&modemListen, NULL, ADM_Modem_Listen, NULL) != 0) {
		(void) fprintf(stderr, "\n%s\n\n",
		    gettext("scadm: couldn't create thread"));
		exit(-1);
	}

	if (signal(SIGINT, cleanup) == SIG_ERR) {
		(void) fprintf(stderr, "\n%s\n\n",
		    gettext("scadm: cleanup() registration failed"));
		ADM_Continue = 0;
		exit(-1);
	}


	(void) sprintf(string, gettext("... Type %s. to return to prompt ..."),
	    rsc_escape);
	Input = 0;
	State = ST_RESET;
	winOn = 1;
	initscr();
	noecho();
	printw("\n%s\n\n", string);

	while (exitLoop) {
		while ((Input = getch()) == ERR)
			;

		if (Input == 10) {
			State = ST_RESET;
			ADM_Send_Char('\n');
			ADM_Send_Char('\r');
			continue;
		}

		switch (State) {
			case ST_RESET:
				if ((char)Input == rsc_escape[0]) {
					State = ST_TILDA;
				} else {
					State = ST_IDLE;
					ADM_Send_Char((char)Input);
				}
				break;

			case ST_IDLE:
				ADM_Send_Char((char)Input);
				break;

			case ST_TILDA:
				if ((char)Input == '.') {
					ADM_Send_Char('~');
					ADM_Send_Char('.');
					exitLoop = 0;
				} else {
					State = ST_IDLE;
					ADM_Send_Char((char)Input);
				}
				break;

			default:
				State = ST_IDLE;
				ADM_Send_Char((char)Input);
		}
	}
	endwin();
	winOn = 0;

	/* Terminate Thread */
	ADM_Continue = 0;
	(void) sleep(3);	/* Make sure thread has time to 'see' */
				/* termination */

	msg.type = DP_MODEM_DISCONNECT;
	msg.len  = 0;
	msg.data = NULL;
	ADM_Send(&msg);

	timeout.tv_nsec = 0;
	timeout.tv_sec  = ADM_TIMEOUT;
	ADM_Recv(&msg, &timeout, DP_MODEM_DISCONNECT_R,
	    sizeof (dp_modem_disconnect_r_t));
	if (*(int *)msg.data != DP_MODEM_PASS) {
		(void) fprintf(stderr, "\n%s\n\n",
		    gettext("scadm: could not disconnect from modem"));
		ADM_Continue = 0;
		exit(-1);
	}
	ADM_Free(&msg);

	pthread_join(modemListen, NULL);

}


static void
ADM_Send_Char(char C)
{
	rscp_msg_t	Message;
	char		Data[2];

	Data[0] = C;
	Data[1] = 0x0;
	Message.type = DP_MODEM_DATA;
	Message.len  = 2;
	Message.data = Data;

	if (rscp_send(&Message) != 0) {
		(void) fprintf(stderr, "\n%s\n\n",
		    gettext("scadm: Unable to send modem data to SC"));
		if (winOn)
			endwin();
		ADM_Continue = 0;
		exit(-1);
	}
}


static void *
ADM_Modem_Listen(void *arg __unused)
{
	rscp_msg_t	Message;
	struct timespec	Timeout;


	while (ADM_Continue) {
		Timeout.tv_nsec = 500000000;
		Timeout.tv_sec  = 0;
		if (rscp_recv(&Message, &Timeout) != 0) {
			continue;
		}

		if (Message.type != DP_MODEM_DATA) {
			(void) fprintf(stderr, "\n%s: 0x%08x:0x%08lx\n\n",
			    gettext("scadm: SC returned garbage"),
			    Message.type, Message.len);
			exit(-1);
		}

		(void) printf("%s", (char *)Message.data);
		(void) fflush(stdout);
		ADM_Free(&Message);
	}
	return (NULL);
}


static void
cleanup()
{
	rscp_msg_t	msg;
	struct timespec	timeout;


	if (winOn)
		endwin();

	/* Terminate Thread */
	ADM_Continue = 0;

	msg.type = DP_MODEM_DISCONNECT;
	msg.len  = 0;
	msg.data = NULL;
	ADM_Send(&msg);

	timeout.tv_nsec = 0;
	timeout.tv_sec  = ADM_TIMEOUT;
	ADM_Recv(&msg, &timeout, DP_MODEM_DISCONNECT_R,
	    sizeof (dp_modem_disconnect_r_t));
	if (*(int *)msg.data != DP_MODEM_PASS) {
		(void) fprintf(stderr, "\n%s\n\n",
		    gettext("scadm: could not disconnect from modem"));
		exit(-1);
	}
	ADM_Free(&msg);

	pthread_join(modemListen, NULL);

	exit(-1);
}
