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
 * Copyright 2002, 2003 by Sun Microsystems, Inc. All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <errno.h>
#include <syslog.h>
#include "impl.h"
#include "error.h"
#include "trace.h"
#include "signals.h"
#include "snmp.h"
#include "pdu.h"
#include "agent_msg.h"
#include "agent.h"
#include "config.h"

/***** DEFINES *****/

#define DEFAULT_POLL_INTERVAL		30

/***** IMPORTED VARIABLES *****/

/* user defined data */

extern char default_config_file[];
extern char default_sec_config_file[];
extern char default_error_file[];

/***** IMPORTED FUNCTIONS *****/

/* user defined functions */
extern void agent_init();
extern void agent_end();
extern void agent_loop();
extern void agent_select_info(fd_set *fdset, int *numfds);
extern void agent_select_callback(fd_set *fdset);

/***** STATIC VARIABLES *****/

static int sighup = False;
char *config_file = NULL;
char *sec_config_file = NULL;
int agent_port_number = -1;

int dont_read_config_file = FALSE;

static int poll_interval = DEFAULT_POLL_INTERVAL;
int max_agent_reg_retry = 10;

/***** LOCAL FUNCTIONS *****/

static void signals_sighup(int siq);
static void signals_exit(int siq);

static int snmpd_init(int port);
static void print_usage(char *command_name);
static void snmpd_loop(int sd);
static void sap_main(int, char **);


/********************************************************************/

static void
application_end()
{
	agent_end();
}


/********************************************************************/

static void
signals_sighup(int sig)
{
	if(trace_level > 0)
		trace("received signal SIGHUP(%d)\n\n", sig);

	error(MSG_SIGHUP, sig);

	sighup = True;
}


/********************************************************************/

static void
signals_exit(int sig)
{

	if (trace_level > 0)
		trace("received signal %d", sig);

	application_end();

	exit(1);
}


/********************************************************************/

static int
snmpd_init(int port)
{
	int sd;
	struct sockaddr_in me;

	/* init the config_file pointer and then parse the configuration file */

	if (port > 0)
		agent_port_number = port;

	if (dont_read_config_file == FALSE) {
		if (config_file == NULL)
			config_file = default_config_file;
		config_init(config_file);
	}

	if (sec_config_file == NULL)
		sec_config_file = default_sec_config_file;

	(void)sec_config_init(sec_config_file);

	/* successfully register the subagent, then set the operation status of
	 * subagent to run.
	 */
	sd = socket(AF_INET, SOCK_DGRAM, 0);
	if(sd < 0)
		error_exit(ERR_MSG_SOCKET, errno_string());

	/* evaluate the port to be used, the port priority is :
	  command port > config. file port > def. port */
	if(port == 0 && agent_port_number != 0){
		port = agent_port_number;
	}

	me.sin_family = AF_INET;
	me.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	me.sin_port = htons(port);
	if(bind(sd, (struct sockaddr *)&me, sizeof(me)) != 0)
		error_exit(ERR_MSG_BIND, port, errno_string());

	if(trace_level > 0)
		trace("Waiting for incoming SNMP requests on UDP port %d\n\n", port);

	return sd;
}

static void
snmpd_loop(int sd)
{
	int numfds;
	fd_set fdset;
	int count;
	long long timer;

	struct timeval expire;
	struct timeval timeout;
	struct timeval now;

	expire.tv_sec = 0;
	expire.tv_usec = 0;


	/* CONSTCOND */
	while (1) {
		if (sighup) {
			error(MSG_READING_CONFIG,
				config_file);

			config_init(config_file);

			error(MSG_READING_CONFIG, sec_config_file);

			(void) sec_config_init(sec_config_file);

			error(MSG_CONFIG_READED);

			sighup = False;
		}

		numfds = 0;
		FD_ZERO(&fdset);

		numfds = sd + 1;
		FD_SET(sd, &fdset);

		agent_select_info(&fdset, &numfds);

		(void) gettimeofday(&now, (struct timezone *)0);

		timer = (long long) (now.tv_sec - expire.tv_sec) * 1000000;
		timer += (long long) (now.tv_usec - expire.tv_usec);

		if (timer >= 0) {
			/* now > timeval + poll_interval */
			timeout.tv_sec = 0;
			timeout.tv_usec = 0;
		} else {
			timeout.tv_sec = -timer / 1000000;
			timeout.tv_usec = -timer % 1000000;
		}

		count = select(numfds, &fdset, 0, 0, &timeout);
		if (count > 0) {
			if (FD_ISSET(sd, &fdset)) {
				Address address;
				SNMP_pdu *pdu;

				if ((pdu = snmp_pdu_receive(sd, &address,
						error_label)) == NULL) {
					error(ERR_MSG_PDU_RECEIVED,
						address_string(&address),
						error_label);
					continue;
				}

				if (agent_process(&address, pdu) == -1) {
					error(ERR_MSG_PDU_PROCESS,
						address_string(&address));
					snmp_pdu_free(pdu);
					continue;
				}

				if (pdu->error_status ==
					SNMP_ERR_AUTHORIZATIONERROR) {
						snmp_pdu_free(pdu);
						continue;
				}

				if ((pdu->error_status != SNMP_ERR_NOERROR)
				&& (pdu->error_status != SNMP_ERR_NOSUCHNAME)) {
					error(ERR_MSG_SNMP_ERROR,
					error_status_string(pdu->error_status),
						pdu->error_index,
						address_string(&address));
				}

				if (snmp_pdu_send(sd, &address, pdu,
						error_label) == -1) {
					error(ERR_MSG_PDU_SEND,
						address_string(&address),
						error_label);
					snmp_pdu_free(pdu);
					continue;
				}

				snmp_pdu_free(pdu);
			}

			agent_select_callback(&fdset);
		} else {
			switch (count) {
				case 0:
					(void) gettimeofday(&expire,
						(struct timezone *) 0);
					expire.tv_sec = expire.tv_sec + poll_interval;
					agent_loop();
					break;

				case -1:
					if (errno == EINTR) {
						continue;
					} else if (errno == EBADF) {
					FD_CLR(sd, &fdset);
					fprintf(stderr, "select() failed %s\n",
						errno_string());
					continue;
					} else {
						error_exit(ERR_MSG_SELECT,
							errno_string());
					}
			}
		}
	}
}


static void print_usage(char *command_name)
{
	(void)fprintf(stderr, "Usage: %s [-h]\n\
\t[-k (don't read config file)]\n\
\t[-p port ]\n\
\t[-c config-file (default %s)]\n\
\t[-a sec-config-file (default %s)]\n\
\t[-i poll-interval (default %d seconds)]\n\
\t[-d trace-level (range 0..%d, default %d)]\n\n",
		command_name,
		default_config_file,
		default_sec_config_file,
		DEFAULT_POLL_INTERVAL,
		TRACE_LEVEL_MAX,
		trace_level);
	exit(1);
}


static void
sap_main(argc, argv)
	int argc;
	char *argv[];
{
	int arg;
	int port = 0;
	int sd;
	char *str;
	int level;
	char *error_file = NULL;



	error_init(argv[0], application_end);

	/* parse arguments */

	for(arg = 1; arg < argc; arg++)
	{
		if(argv[arg][0] == '-')
		{
			switch(argv[arg][1])
			{
                                case 'k':
                                        dont_read_config_file = TRUE;
                                        break;
				case 'h':
				case '?':
					print_usage(argv[0]);

					/* never reached */
					return;

				case 'p':
					arg++;
					if(arg >= argc)
					{
						(void)fprintf(stderr, "Must have another argument following the -p option\n");
						print_usage(argv[0]);
					}

					/* LINTED */
					port = (int32_t)strtol(argv[arg], &str, 10);
					if(argv[arg] == str)
					{
						(void)fprintf(stderr, "Not a valid integer following the -p option: %s\n", argv[arg]);
						print_usage(argv[0]);
					}

					break;

				case 'c':
					arg++;
					if(arg >= argc)
					{
						(void)fprintf(stderr, "Must have a configuration file name following the -c option\n");
						print_usage(argv[0]);
					}

					config_file = (char *) strdup(argv[arg]);
					if(config_file == NULL)
					{
						(void)fprintf(stderr, "%s\n", ERR_MSG_ALLOC);
						exit(1);
					}

					break;

				case 'a':
					arg++;
					if(arg >= argc)
					{
						(void)fprintf(stderr, "Must have a security configuration file name following the -a option\n");
						print_usage(argv[0]);
					}

					sec_config_file = (char *) strdup(argv[arg]);
					if(sec_config_file == NULL)
					{
						(void)fprintf(stderr, "%s\n", ERR_MSG_ALLOC);
						exit(1);
					}

					break;


				case 'i':
					arg++;
					if(arg >= argc)
					{
						(void)fprintf(stderr, "Must have another argument following the -i option\n");
						print_usage(argv[0]);
					}

					/* LINTED */
					poll_interval = (int32_t)strtol(argv[arg], &str, 10);
					if(argv[arg] == str)
					{
						(void)fprintf(stderr, "Not a valid integer following the -i option: %s\n", argv[arg]);
						print_usage(argv[0]);
					}
					if(poll_interval <= 0)
					{
						(void)fprintf(stderr, "The poll-interval must be greater than 0: %d\n", poll_interval);
						print_usage(argv[0]);
					}

					break;

				case 'd':
					arg++;
					if(arg >= argc)
					{
						(void)fprintf(stderr, "Must have another argument following the -d option\n");
						print_usage(argv[0]);
					}

					/* LINTED */
					level = (int32_t)strtol(argv[arg], &str, 10);
					if(argv[arg] == str)
					{
						(void)fprintf(stderr, "Not a valid integer following the -d option: %s\n", argv[arg]);
						print_usage(argv[0]);
					}
					if(trace_set(level, error_label))
					{
						print_usage(argv[0]);
					}

					break;

				default:
					(void)fprintf(stderr, "Invalid option: -%c\n", argv[arg][1]);
					print_usage(argv[0]);
			}
			continue;
		}
	}


	if(error_file == NULL)
	{
		error_file = default_error_file;
	}
	error_open(error_file);

	if(trace_level == 0)
	{
		/* run the daemon in backgound */

		pid_t pid; 

		pid = fork();
		switch(pid)
		{
			case -1:
				error_exit(ERR_MSG_FORK, errno_string());

				/* never reached */
				return;

			case 0: /* child process */
				break;

			default: /* parent process */
				exit(0);
		}
	}

	if(fclose(stdin) == EOF) 
	{
		error(ERR_MSG_FCLOSE, "stdin", errno_string());
	}

	sd = snmpd_init(port);

	if(signals_init(signals_sighup, signals_exit, error_label))
	{
		error_exit("signals_init() failed: %s", error_label);
	}

	if(trace_level == 0)
	{
		if(fclose(stdout) == EOF)
		{
			error(ERR_MSG_FCLOSE, "stdout", errno_string());
		}
	}

	if(trace_level == 0)
	{
		/* backgound */

		if(chdir("/") == -1)
		{
			error(ERR_MSG_CHDIR, "/", errno_string());
		}

		/* set process group ID */
		(void)setpgrp();

		error_close_stderr();
	}

	/* have to be called after error_open() and error_close_stderr() */
	agent_init();

	snmpd_loop(sd);

	/* never reached */
}

void 
SSAMain(int argc, char** argv)
{
	sap_main(argc,argv);
}
