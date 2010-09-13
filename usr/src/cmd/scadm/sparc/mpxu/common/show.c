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
 * show.c: support for scadm show <variable> option (to show the value of
 * a service processor NV variable)
 */

#include <libintl.h>
#include <stdio.h>
#include <string.h>
#include <time.h>  /* required by librsc.h */

#include "librsc.h"
#include "adm.h"



char *ADM_Get_Var(char *Variable);

static void ADM_Show_Var(char *Variable);
static int ADM_Get_Next_Var(char *oldVar, char *newVar, int maxSize);
static void command_line();


void
ADM_Process_show(int argc, char *argv[])
{
	char		*oldVar;
	static char	newVar[128];


	if ((argc != 2) && (argc != 3)) {
		(void) fprintf(stderr, "\n%s\n\n",
		    gettext("USAGE: scadm show [variable]"));
		exit(-1);
	}

	ADM_Start();

	if (argc == 2) {
		oldVar = NULL;
		newVar[0] = 0x0;
		while (ADM_Get_Next_Var(oldVar, newVar, 128) == 0) {
			ADM_Show_Var(newVar);
			oldVar = newVar;
		}
	} else {
		ADM_Show_Var(argv[2]);
	}
}

void
ADM_Process_show_network()
{
	rscp_msg_t		Message;
	struct timespec		Timeout;
	dp_get_network_cfg_r_t	*netParams;

	ADM_Start();

	Message.type = DP_GET_NETWORK_CFG;
	Message.len = 0;
	Message.data = NULL;

	ADM_Send(&Message);

	Timeout.tv_nsec = 0;
	Timeout.tv_sec = ADM_TIMEOUT;
	ADM_Recv(&Message, &Timeout,
	    DP_GET_NETWORK_CFG_R, sizeof (dp_get_network_cfg_r_t));

	netParams = (dp_get_network_cfg_r_t *)Message.data;

	/* Print the network configuration */
	if (netParams->status != 0) {
		(void) printf("%s \r\n", gettext("SC ethernet is disabled."));
	} else {
#if 0
		/* Include this if we want to display the IP mode */
		(void) printf("%s %s\r\n",
		    gettext("SC network configuration is:"),
		    netParams->ipMode);
#endif
	if (strcmp(netParams->ipMode, "dhcp") == 0)
		(void) printf("%s %s\r\n", gettext("DHCP server:"),
		    netParams->ipDHCPServer);
		(void) printf("%s %s\r\n", gettext("IP Address:"),
		    netParams->ipAddr);
		(void) printf("%s %s\r\n", gettext("Gateway address:"),
		    netParams->ipGateway);
		(void) printf("%s %s\r\n", gettext("Netmask:"),
		    netParams->ipMask);
		(void) printf("%s %s\r\n", gettext("Ethernet address:"),
		    netParams->ethAddr);
	}

	ADM_Free(&Message);

}

char
*ADM_Get_Var(char *Variable)
{
	rscp_msg_t	Message;
	struct timespec	Timeout;
	char		*varValue;

	varValue = NULL;

	Message.type = DP_GET_CFGVAR;
	Message.len = strlen(Variable) + 1; /* + 1 for string termination */
	if (Message.len > DP_MAX_MSGLEN-4) {
		command_line();
		exit(-1);
	}

	Message.data = Variable;
	ADM_Send(&Message);

	Timeout.tv_nsec = 0;
	Timeout.tv_sec = ADM_TIMEOUT;
	ADM_Recv(&Message, &Timeout,
	    DP_GET_CFGVAR_R, sizeof (dp_get_cfgvar_r_t));

	if (*(int *)Message.data != 0) {
		(void) fprintf(stderr, "\n%s - \"%s\"\n\n",
		    gettext("scadm: invalid variable"), Variable);
		exit(-1);
	}

	/* show variable setting */
	/* The variable setting is right after the Status of the message */
	varValue = (char *)(&((char *)Message.data)[
	    sizeof (dp_get_cfgvar_r_t)]);

	ADM_Free(&Message);

	return (varValue);
}

static void
ADM_Show_Var(char *Variable)
{
	char *varValue;

	varValue = ADM_Get_Var(Variable);
	(void) printf("%s=\"%s\"\n", Variable, varValue);
	(void) fflush(stdout);
}

static int
ADM_Get_Next_Var(char *oldVar, char *newVar, int maxSize)
{
	rscp_msg_t	Message;
	struct timespec	Timeout;
	char		*var;


	Message.type = DP_GET_CFGVAR_NAME;
	if (oldVar == NULL)
		Message.len = 0;
	else
		Message.len  = strlen(oldVar) + 1;	/* + 1 for string */
							/* termination */

	if (Message.len > DP_MAX_MSGLEN-4) {
		command_line();
		exit(-1);
	}

	Message.data = oldVar;
	ADM_Send(&Message);

	Timeout.tv_nsec = 0;
	Timeout.tv_sec  = ADM_TIMEOUT;
	ADM_Recv(&Message, &Timeout,
	    DP_GET_CFGVAR_NAME_R, sizeof (dp_get_cfgvar_name_r_t));
	if (*(int *)Message.data != 0) {
		/* Last variable read */
		return (-1);
	}

	/* The variable is right after the Status of the message */
	var = (char *)(&((char *)Message.data)[
	    sizeof (dp_get_cfgvar_name_r_t)]);
	(void) strncpy(newVar, var, maxSize);

	ADM_Free(&Message);

	return (0);
}


static void
command_line()
{
	(void) fprintf(stderr, "\n%s\n\n",
	    gettext("scadm: command line too long"));
}
