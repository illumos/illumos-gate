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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * user.c: support for the scadm useradd, userdel, usershow, userpassword,
 * userperm options (administration of service processor users)
 */

#include <libintl.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <termios.h>
#include <time.h>  /* required by librsc.h */

#include "librsc.h"
#include "adm.h"


static void ADM_Get_Password(char  *password);
static void ADM_Destroy_Password(char  *password);
static void max_username();
static void malformed_username();
static void wrong_response();
static void no_user();
static void no_info();
static void userperm_usage();
static void show_header();
static void cleanup();


/* Globals so that exit routine can clean up echo */
static int		echoOff = 0;
static struct termios	oldOpts;

typedef union {
	char	DataBuffer[DP_MAX_MSGLEN];
	void	*DataBuffer_p;
} data_buffer_t;


void
ADM_Process_useradd(int argc, char *argv[])
{
	static data_buffer_t	dataBuffer;
	rscp_msg_t		Message;
	struct timespec		Timeout;
	dp_user_adm_t		*admMessage;
	dp_user_adm_r_t		*admResponse;
	char			*userName;


	if (argc != 3) {
		(void) fprintf(stderr, "\n%s\n\n",
		    gettext("USAGE: scadm useradd <username>"));
		exit(-1);
	}

	ADM_Start();

	if (strlen(argv[2]) > DP_USER_NAME_SIZE) {
		max_username();
		exit(-1);
	}

	admMessage = (dp_user_adm_t *)&dataBuffer;
	userName   = (char *)(&((char *)admMessage)[sizeof (dp_user_adm_t)]);
	admMessage->command = DP_USER_CMD_ADD;
	(void) strcpy(userName, argv[2]);

	Message.type = DP_USER_ADM;
	Message.len  = sizeof (dp_user_adm_t) + strlen(userName) + 1;
	Message.data = admMessage;
	ADM_Send(&Message);

	Timeout.tv_nsec = 0;
	Timeout.tv_sec  = ADM_SEPROM_TIMEOUT;
	ADM_Recv(&Message, &Timeout, DP_USER_ADM_R, sizeof (dp_user_adm_r_t));

	admResponse = (dp_user_adm_r_t *)Message.data;
	if (admResponse->command != DP_USER_CMD_ADD) {
		wrong_response();
		exit(-1);
	}

	if (admResponse->status == DP_ERR_USER_FULL) {
		(void) fprintf(stderr, "\n%s\n\n",
		    gettext("scadm: all user slots are full"));
		exit(-1);
	} else if (admResponse->status == DP_ERR_USER_THERE) {
		(void) fprintf(stderr, "\n%s\n\n",
		    gettext("scadm: user already exists"));
		exit(-1);
	} else if (admResponse->status == DP_ERR_USER_WARNING) {
		(void) fprintf(stderr, "\n%s\n\n",
		    gettext("scadm: username did not start with letter\n"
		    "        or did not contain lower case letter\n"));
		exit(-1);
	} else if (admResponse->status == DP_ERR_USER_BAD) {
		malformed_username();
		exit(-1);
	} else if (admResponse->status != 0) {
		(void) fprintf(stderr, "\n%s\n\n",
		    gettext("scadm: couldn't add user"));
		exit(-1);
	}

	ADM_Free(&Message);
}


void
ADM_Process_userdel(int argc, char *argv[])
{
	static data_buffer_t	dataBuffer;
	rscp_msg_t		Message;
	struct timespec		Timeout;
	dp_user_adm_t		*admMessage;
	dp_user_adm_r_t		*admResponse;
	char			*userName;


	if (argc != 3) {
		(void) fprintf(stderr, "\n%s\n\n",
		    gettext("USAGE: scadm userdel <username>"));
		exit(-1);
	}

	ADM_Start();

	if (strlen(argv[2]) > DP_USER_NAME_SIZE) {
		max_username();
		exit(-1);
	}

	admMessage = (dp_user_adm_t *)&dataBuffer;
	userName   = (char *)(&((char *)admMessage)[sizeof (dp_user_adm_t)]);
	admMessage->command = DP_USER_CMD_DEL;
	(void) strcpy(userName, argv[2]);

	Message.type = DP_USER_ADM;
	Message.len  = sizeof (dp_user_adm_t) + strlen(userName) + 1;
	Message.data = admMessage;
	ADM_Send(&Message);

	Timeout.tv_nsec = 0;
	Timeout.tv_sec  = ADM_SEPROM_TIMEOUT;
	ADM_Recv(&Message, &Timeout, DP_USER_ADM_R, sizeof (dp_user_adm_r_t));

	admResponse = (dp_user_adm_r_t *)Message.data;
	if (admResponse->command != DP_USER_CMD_DEL) {
		wrong_response();
		exit(-1);
	}

	if (admResponse->status == DP_ERR_USER_NONE) {
		no_user();
		exit(-1);
	} else if (admResponse->status == DP_ERR_USER_BAD) {
		malformed_username();
		exit(-1);
	} else if (admResponse->status != 0) {
		(void) fprintf(stderr, "\n%s\n\n",
		    gettext("scadm: couldn't delete user"));
		exit(-1);
	}

	ADM_Free(&Message);
}


void
ADM_Process_usershow(int argc, char *argv[])
{
	static data_buffer_t	dataBuffer;
	rscp_msg_t		Message;
	struct timespec		Timeout;
	dp_user_adm_t		*admMessage;
	dp_user_adm_r_t		*admResponse;
	char			*userName;
	char			*permissions;
	char			*passwd;
	int			index;



	if ((argc != 2) && (argc != 3)) {
		(void) fprintf(stderr, "\n%s\n\n",
		    gettext("USAGE: scadm usershow [username]"));
		exit(-1);
	}

	ADM_Start();

	if (argc == 3) {
		admMessage = (dp_user_adm_t *)&dataBuffer;
		admMessage->command = DP_USER_CMD_SHOW;
		Message.type = DP_USER_ADM;
		Message.data = admMessage;

		if (strlen(argv[2]) > DP_USER_NAME_SIZE) {
			max_username();
			exit(-1);
		}
		userName = (char *)(&((char *)admMessage)[
		    sizeof (dp_user_adm_t)]);
		(void) strcpy(userName, argv[2]);
		admMessage->parm = DP_USER_SHOW_USERNAME;
		Message.len = sizeof (dp_user_adm_t) + strlen(userName) + 1;
		ADM_Send(&Message);

		Timeout.tv_nsec = 0;
		Timeout.tv_sec  = ADM_SEPROM_TIMEOUT;
		ADM_Recv(&Message, &Timeout,
		    DP_USER_ADM_R, sizeof (dp_user_adm_r_t));

		admResponse = (dp_user_adm_r_t *)Message.data;
		if (admResponse->command != DP_USER_CMD_SHOW) {
			wrong_response();
			exit(-1);
		}

		if (admResponse->status == DP_ERR_USER_NONE) {
			no_user();
			exit(-1);
		} else if (admResponse->status == DP_ERR_USER_BAD) {
			malformed_username();
			exit(-1);
		} else if (admResponse->status != 0) {
			no_info();
			exit(-1);
		}

		userName = &(((char *)admResponse)[
		    sizeof (dp_user_adm_r_t)]);
		permissions = &userName[strlen(userName)+1];
		passwd = &permissions[strlen(permissions)+1];
		show_header();
		(void) printf(" %-16s    %-15s    ", userName, permissions);
		if (strncmp(passwd, "Assigned", 12) == 0) {
			(void) printf("%s\n\n", gettext("Assigned"));
		} else if (strncmp(passwd, "None", 12) == 0) {
			(void) printf("%s\n\n", gettext("None"));
		} else {
			(void) printf("%-12s\n\n", passwd);
		}
		ADM_Free(&Message);
	} else {
		show_header();
		for (index = 1; index <= DP_USER_MAX; index++) {
			admMessage = (dp_user_adm_t *)&dataBuffer;
			admMessage->command = DP_USER_CMD_SHOW;
			admMessage->parm    = index;

			Message.type = DP_USER_ADM;
			Message.data = admMessage;
			Message.len  = sizeof (dp_user_adm_t);
			ADM_Send(&Message);

			Timeout.tv_nsec = 0;
			Timeout.tv_sec  = ADM_SEPROM_TIMEOUT;
			ADM_Recv(&Message, &Timeout,
			    DP_USER_ADM_R, sizeof (dp_user_adm_r_t));

			admResponse = (dp_user_adm_r_t *)Message.data;
			if (admResponse->command != DP_USER_CMD_SHOW) {
				wrong_response();
				exit(-1);
			}

			if (admResponse->status == DP_ERR_USER_NONE) {
				ADM_Free(&Message);
				continue;
			} else if (admResponse->status == DP_ERR_USER_BAD) {
				malformed_username();
				exit(-1);
			} else if (admResponse->status != 0) {
				no_info();
				exit(-1);
			}

			userName = &(((char *)admResponse)[
			    sizeof (dp_user_adm_r_t)]);
			permissions = &userName[strlen(userName)+1];
			passwd = &permissions[strlen(permissions)+1];
			(void) printf(" %-16s    %-15s    ",
			    userName, permissions);
			if (strncmp(passwd, "Assigned", 12) == 0) {
				(void) printf("%s\n", gettext("Assigned"));
			} else if (strncmp(passwd, "None", 12) == 0) {
				(void) printf("%s\n", gettext("None"));
			} else {
				(void) printf("%-12s\n", passwd);
			}

			ADM_Free(&Message);
		}
		(void) printf("\n");
	}
}


void
ADM_Process_userpassword(int argc, char *argv[])
{
	static data_buffer_t	dataBuffer;
	rscp_msg_t		Message;
	struct timespec		Timeout;
	dp_user_adm_t		*admMessage;
	dp_user_adm_r_t		*admResponse;
	char			*userName;
	char			*password;
	int			passTry;


	/* Try to set password up to 3 times on Malformed password */
	passTry = 3;

	if (argc != 3) {
		(void) fprintf(stderr, "\n%s\n\n",
		    gettext("USAGE: scadm userpassword <username>"));
		exit(-1);
	}

	ADM_Start();

	if (strlen(argv[2]) > DP_USER_NAME_SIZE) {
		max_username();
		exit(-1);
	}

	admMessage = (dp_user_adm_t *)&dataBuffer;
	admMessage->command = DP_USER_CMD_PASSWORD;
	userName = (&((char *)admMessage)[sizeof (dp_user_adm_t)]);
	(void) strcpy(userName, argv[2]);
	password = (&((char *)admMessage)[sizeof (dp_user_adm_t) +
	    strlen(userName) + 1]);

	for (;;) {
		ADM_Get_Password(password);

		Message.type = DP_USER_ADM;
		Message.len  = sizeof (dp_user_adm_t) + strlen(userName) +
		    strlen(password) + 2;
		Message.data = admMessage;
		ADM_Send(&Message);

		ADM_Destroy_Password(password);
		Timeout.tv_nsec = 0;
		Timeout.tv_sec  = ADM_SEPROM_TIMEOUT;
		ADM_Recv(&Message, &Timeout,
		    DP_USER_ADM_R, sizeof (dp_user_adm_r_t));

		admResponse = (dp_user_adm_r_t *)Message.data;
		if (admResponse->command != DP_USER_CMD_PASSWORD) {
			wrong_response();
			exit(-1);
		}

		if (admResponse->status == DP_ERR_USER_NONE) {
			no_user();
			exit(-1);
		} else if (admResponse->status == DP_ERR_USER_BAD) {
			malformed_username();
			exit(-1);
		} else if (admResponse->status == DP_ERR_USER_PASSWD) {
			(void) fprintf(stderr, "\n%s\n\n",
			    gettext("scadm: malformed password\n"
			    "        A valid password is between 6 and 8 "
			    "characters,\n"
			    "        has at least two alphabetic characters, "
			    "and at\n"
			    "        least one numeric or special character. "
			    "The\n"
			    "        password must differ from the user's "
			    "login name\n"
			    "        and any reverse or circular shift of that "
			    "login\n"
			    "        name.\n"));
			passTry--;
			if (passTry > 0) {
				ADM_Free(&Message);
				continue;
			} else
				exit(-1);
		} else if (admResponse->status != 0) {
			(void) fprintf(stderr, "\n%s\n\n",
			    gettext("scadm: couldn't change password"));
			exit(-1);
		}

		/* password was changed successfully, get out of while */
		break;
	}

	ADM_Free(&Message);
}


void
ADM_Process_userperm(int argc, char *argv[])
{
	static data_buffer_t	dataBuffer;
	rscp_msg_t		Message;
	struct timespec		Timeout;
	dp_user_adm_t		*admMessage;
	dp_user_adm_r_t		*admResponse;
	char			*userName;
	int			permissions;
	int			index;


	if ((argc != 3) && (argc != 4)) {
		userperm_usage();
		exit(-1);
	}

	if (argc == 3) {
		permissions = 0;
	} else {
		if ((strlen(argv[3]) > 4) || (strlen(argv[3]) < 1)) {
			userperm_usage();
			exit(-1);
		}

		permissions = 0;
		for (index = 0; index < strlen(argv[3]); index++) {
			if ((argv[3][index] != 'c') &&
			    (argv[3][index] != 'C') &&
			    (argv[3][index] != 'u') &&
			    (argv[3][index] != 'U') &&
			    (argv[3][index] != 'a') &&
			    (argv[3][index] != 'A') &&
			    (argv[3][index] != 'r') &&
			    (argv[3][index] != 'R')) {
				userperm_usage();
				exit(-1);
			}

			if ((argv[3][index] == 'c') ||
			    (argv[3][index] == 'C')) {
				/* See if this field was entered twice */
				if ((permissions & DP_USER_PERM_C) != 0) {
					userperm_usage();
					exit(-1);
				}
				permissions = permissions | DP_USER_PERM_C;
			}

			if ((argv[3][index] == 'u') ||
			    (argv[3][index] == 'U')) {
				/* See if this field was enetered twice */
				if ((permissions & DP_USER_PERM_U) != 0) {
					userperm_usage();
					exit(-1);
				}
				permissions = permissions | DP_USER_PERM_U;
			}

			if ((argv[3][index] == 'a') ||
			    (argv[3][index] == 'A')) {
				/* See if this field was enetered twice */
				if ((permissions & DP_USER_PERM_A) != 0) {
					userperm_usage();
					exit(-1);
				}
				permissions = permissions | DP_USER_PERM_A;
			}

			if ((argv[3][index] == 'r') ||
			    (argv[3][index] == 'R')) {
				/* See if this field was enetered twice */
				if ((permissions & DP_USER_PERM_R) != 0) {
					userperm_usage();
					exit(-1);
				}
				permissions = permissions | DP_USER_PERM_R;
			}
		}
	}

	ADM_Start();

	if (strlen(argv[2]) > DP_USER_NAME_SIZE) {
		max_username();
		exit(-1);
	}

	admMessage = (dp_user_adm_t *)&dataBuffer;
	admMessage->command = DP_USER_CMD_PERM;
	admMessage->parm    = permissions;
	userName   = (char *)(&((char *)admMessage)[sizeof (dp_user_adm_t)]);
	(void) strcpy(userName, argv[2]);

	Message.type = DP_USER_ADM;
	Message.len  = sizeof (dp_user_adm_t) + strlen(userName) + 1;
	Message.data = admMessage;
	ADM_Send(&Message);

	Timeout.tv_nsec = 0;
	Timeout.tv_sec  = ADM_SEPROM_TIMEOUT;
	ADM_Recv(&Message, &Timeout, DP_USER_ADM_R, sizeof (dp_user_adm_r_t));

	admResponse = (dp_user_adm_r_t *)Message.data;
	if (admResponse->command != DP_USER_CMD_PERM) {
		wrong_response();
		exit(-1);
	}

	if (admResponse->status == DP_ERR_USER_NONE) {
		no_user();
		exit(-1);
	} else if (admResponse->status == DP_ERR_USER_BAD) {
		malformed_username();
		exit(-1);
	} else if (admResponse->status != 0) {
		(void) fprintf(stderr, "\n%s\n\n",
		    gettext("scadm: couldn't change permissions"));
		exit(-1);
	}

	ADM_Free(&Message);
}


static void
ADM_Get_Password(char *password)
{
	static char		pass1[64];
	static char		pass2[64];
	static struct termios	newOpts;
	int			passTry;
	int			validPass;


	validPass = 0;
	passTry   = 3;

	if (signal(SIGINT, cleanup) == SIG_ERR) {
		(void) fprintf(stderr, "\n%s\n\n",
		    gettext("scadm: cleanup() registration failed"));
		exit(-1);
	}

	echoOff = 1;
	(void) tcgetattr(0, &oldOpts);
	newOpts = oldOpts;
	newOpts.c_lflag &= ~ECHO;
	(void) tcsetattr(0, TCSANOW, &newOpts);

	while ((passTry > 0) && (validPass == 0)) {
		passTry = passTry - 1;
		(void) printf("%s", gettext("Password: "));
		(void) scanf("%s", pass1);
		(void) printf("\n");
		(void) fflush(stdin);
		(void) printf("%s", gettext("Re-enter Password: "));
		(void) scanf("%s", pass2);
		(void) printf("\n");

		/* Truncate at 8 characters  */
		pass1[8] = pass2[8] = '\0';

		if ((strcmp(pass1, pass2) != 0) && (passTry > 0)) {
			ADM_Destroy_Password(pass1);
			ADM_Destroy_Password(pass2);
			(void) fprintf(stderr, "%s\n\n",
			    gettext("Passwords didn't match, try again"));
		} else if ((strcmp(pass1, pass2) != 0) && (passTry <= 0)) {
			ADM_Destroy_Password(pass1);
			ADM_Destroy_Password(pass2);
			(void) fprintf(stderr, "\n%s\n\n",
			    gettext("scadm: ERROR, passwords didn't match"));
			(void) tcsetattr(0, TCSANOW, &oldOpts);
			exit(-1);
		} else {
			validPass = 1;
		}
	}

	(void) tcsetattr(0, TCSANOW, &oldOpts);
	echoOff = 0;
	(void) strcpy(password, pass1);
	ADM_Destroy_Password(pass1);
	ADM_Destroy_Password(pass2);
}


static void
cleanup()
{
	if (echoOff)
		(void) tcsetattr(0, TCSANOW, &oldOpts);

	exit(-1);
}


static void
ADM_Destroy_Password(char *password)
{
	int index;

	for (index = 0; index < strlen(password); index++)
		password[index] = 0x1;
}


static void
max_username()
{
	(void) fprintf(stderr,
	    gettext("\nscadm: maximum username length is %d\n\n"),
	    DP_USER_NAME_SIZE);
}


static void
malformed_username()
{
	(void) fprintf(stderr,
	    "\n%s\n\n", gettext("scadm: malformed username"));
}


static void
wrong_response()
{
	(void) fprintf(stderr, "\n%s\n\n",
	    gettext("scadm: SC returned wrong response"));
}


static void
no_user()
{
	(void) fprintf(stderr,
	    "\n%s\n\n", gettext("scadm: username does not exist"));
}


static void
no_info()
{
	(void) fprintf(stderr, "\n%s\n\n",
	    gettext("scadm: couldn't get information on user"));
}


static void
userperm_usage()
{
	(void) fprintf(stderr, "\n%s\n\n",
	    gettext("USAGE: scadm userperm <username> [cuar]"));
}


static void
show_header()
{
	int i;
	int usernLen = strlen(gettext("username"));
	int permLen = strlen(gettext("permissions"));
	int pwdLen = strlen(gettext("password"));

	(void) printf("\n");
	(void) putchar(' ');
	(void) printf("%s", gettext("username"));
	for (i = 0; i < (20 - usernLen); i++)
		(void) putchar(' ');

	(void) printf("%s", gettext("permissions"));
	for (i = 0; i < (19 - permLen); i++)
		(void) putchar(' ');

	(void) printf("%s\n", gettext("password"));

	(void) putchar(' ');
	for (i = 0; i < usernLen; i++)
		(void) putchar('-');
	for (; i < 20; i++)
		(void) putchar(' ');

	for (i = 0; i < permLen; i++)
		(void) putchar('-');
	for (; i < 19; i++)
		(void) putchar(' ');

	for (i = 0; i < pwdLen; i++)
		(void) putchar('-');
	(void) printf("\n");
}
