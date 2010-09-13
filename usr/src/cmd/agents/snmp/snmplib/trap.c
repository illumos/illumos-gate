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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <stdio.h>
#include <sys/socket.h>
#include <errno.h>
#include <syslog.h>
#include <string.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <nlist.h>
#include "snmp_msg.h"
#include "impl.h"
#include "trace.h"
#include "snmp.h"
#include "pdu.h"
#include "request.h"
#include "trap.h"
#include "error.h"


/***** GLOBAL VARIABLES *****/

char *trap_community = NULL;

Subid sun_subids[] = { 1, 3, 6, 1, 4, 1, 42, 2, 1, 1 };
Oid sun_oid = { sun_subids, 10 };


/***** LOCAL TYPES *****/

typedef struct _Trap_Destinator {
	struct _Trap_Destinator	*next_trap_destinator;
	char			*name;
	IPAddress		ip_address;
} Trap_Destinator;


/***** LOCAL VARIABLES *****/

static Oid *default_enterprise = NULL;

static Trap_Destinator *first_trap_destinator = NULL;


/********************************************************************/

int trap_init(Oid *enterprise, char *error_label)
{
	error_label[0] = '\0';

	if(enterprise == NULL)
	{
		sprintf(error_label, "BUG: trap_init(): enterprise is NULL");
		return -1;
	}

	SSAOidFree(default_enterprise);
	default_enterprise = NULL;

	default_enterprise = SSAOidDup(enterprise, error_label);
	if(default_enterprise == NULL)
	{
		return -1;
	}

	return 0;
}


/********************************************************************/

int trap_send(IPAddress *ip_address, Oid *enterprise, int generic, int specific, SNMP_variable *variables, char *error_label)
{
	static int my_ip_address_initialized = False;
	static IPAddress my_ip_address;
	struct sockaddr_in me;
	int sd;
	Address address;
	SNMP_pdu *pdu;
	SNMP_variable *last_variable = NULL;
	SNMP_variable *new_variable;


	error_label[0] = '\0';

	if(my_ip_address_initialized == False)
	{
		if(get_my_ip_address(&my_ip_address, error_label))
		{
			return -1;
		}
		
		my_ip_address_initialized = True;
	}

	pdu = snmp_pdu_new(error_label);
	if(pdu == NULL)
	{
		return -1;
	}

	/* version, community */
	pdu->version = SNMP_VERSION_1;
	if(trap_community == NULL)
	{
		pdu->community = strdup("public");
	}
	else
	{
		pdu->community = strdup(trap_community);
	}
	if(pdu->community == NULL)
	{
		sprintf(error_label, ERR_MSG_ALLOC);
		snmp_pdu_free(pdu);
		return -1;
	}

	/* type */
	pdu->type = TRP_REQ_MSG;

	/* enterprise */
	if(enterprise == NULL)
	{
		if(default_enterprise)
		{
			enterprise = default_enterprise;
		}
		else
		{
			enterprise = &sun_oid;
		}
	}
	if(SSAOidCpy(&(pdu->enterprise), enterprise, error_label))
	{
		snmp_pdu_free(pdu);
		return -1;
	}

	/* agent_addr */
	pdu->ip_agent_addr.s_addr = my_ip_address.s_addr;

	/* generic, specific */
	pdu->generic = generic;
	pdu->specific = specific;

	/* time_stamp */
	pdu->time_stamp = request_sysUpTime(error_label, NULL);

	/* first_variable */
	while(variables)
	{
		new_variable = snmp_variable_dup(variables, error_label);
		if(new_variable == NULL)
		{
			snmp_pdu_free(pdu);
			return -1;
		}

		if(last_variable)
		{
			last_variable->next_variable = new_variable;
		}
		else
		{
			pdu->first_variable = new_variable;
		}
		last_variable = new_variable;

		variables = variables->next_variable;
	}


	/* sd */
	sd = socket(AF_INET, SOCK_DGRAM, 0);
	if(sd < 0)
	{
		sprintf(error_label, ERR_MSG_SOCKET, errno_string());
		snmp_pdu_free(pdu);
		return -1;
	}
	me.sin_family = AF_INET;
	me.sin_addr.s_addr = INADDR_ANY;
	me.sin_port = htons(0);
	if(bind(sd, (struct sockaddr *)&me, sizeof(me)) != 0)
	{
		sprintf(error_label, ERR_MSG_BIND, errno_string());
		snmp_pdu_free(pdu);
		(void)close(sd);
		return -1;
	}


	/* address */
	address.sin_family = AF_INET;
	address.sin_addr.s_addr = ip_address->s_addr;
	address.sin_port = SNMP_TRAP_PORT;

	if(snmp_pdu_send(sd, &address, pdu, error_label))
	{
		snmp_pdu_free(pdu);
		(void)close(sd);
		return -1;
	}
	snmp_pdu_free(pdu);
	(void)close(sd);


	return 0;
}
/**********************************************************************/

int trap_send_raw(IPAddress *ip_address, IPAddress my_ip_addr, 
	char* community,int i_flag,Oid *enterprise,int generic,
	int specific,int trap_port,uint32_t time_stamp,
	SNMP_variable *variables,char *error_label)
{
	static int my_ip_address_initialized = False;
	static IPAddress my_ip_address; 
	struct sockaddr_in me;
	int sd;
	Address address;
	SNMP_pdu *pdu;
	SNMP_variable *last_variable = NULL;
	SNMP_variable *new_variable;


	error_label[0] = '\0';

	if (!i_flag) {
		if(my_ip_address_initialized == False)
		{
			if(get_my_ip_address(&my_ip_address, error_label))
			{
				return -1;
			}
		
			my_ip_address_initialized = True;
		}
	}

	pdu = snmp_pdu_new(error_label);
	if(pdu == NULL)
	{
		return -1;
	}

	/* version, community */
	pdu->version = SNMP_VERSION_1;

	if(community == NULL)
	{
		pdu->community = strdup("public");
	}
	else
	{
		pdu->community = strdup(community);
	}
	if(pdu->community == NULL)
	{
		sprintf(error_label, ERR_MSG_ALLOC);
		snmp_pdu_free(pdu);
		return -1;
	}

	/* type */
	pdu->type = TRP_REQ_MSG;

	/* enterprise */
	if(enterprise == NULL)
	{
		if(default_enterprise)
		{
			enterprise = default_enterprise;
		}
		else
		{
			enterprise = &sun_oid;
		}
	}
	if(SSAOidCpy(&(pdu->enterprise), enterprise, error_label))
	{
		snmp_pdu_free(pdu);
		return -1;
	}

 	/* agent_addr */
	if (!i_flag) {
		pdu->ip_agent_addr.s_addr = my_ip_address.s_addr;
	}
	else {
		pdu->ip_agent_addr.s_addr = my_ip_addr.s_addr;	
	}

	/* generic, specific */

	pdu->generic = generic;
	pdu->specific = specific;

	/* time_stamp */
	if (time_stamp == -1U)
		pdu->time_stamp = request_sysUpTime(error_label, community); /* default */
	else
		pdu->time_stamp = time_stamp; 

	/* first_variable */
	while(variables)
	{
		new_variable = snmp_variable_dup(variables, error_label);
		if(new_variable == NULL)
		{
			snmp_pdu_free(pdu);
			return -1;
		}

		if(last_variable)
		{
			last_variable->next_variable = new_variable;
		}
		else
		{
			pdu->first_variable = new_variable;
		}
		last_variable = new_variable;

		variables = variables->next_variable;
	}


	/* sd */
	sd = socket(AF_INET, SOCK_DGRAM, 0);
	if(sd < 0)
	{
		sprintf(error_label, ERR_MSG_SOCKET, errno_string());
		snmp_pdu_free(pdu);
		return -1;
	}
	me.sin_family = AF_INET;
	me.sin_addr.s_addr = INADDR_ANY;
	me.sin_port = htons(0);
	if(bind(sd, (struct sockaddr *)&me, sizeof(me)) != 0)
	{
		sprintf(error_label, ERR_MSG_BIND, errno_string());
		snmp_pdu_free(pdu);
		(void)close(sd);
		return -1;
	}


	/* address */
	address.sin_family = AF_INET;
	address.sin_addr.s_addr = ip_address->s_addr;
	if (trap_port == -1)
		address.sin_port = SNMP_TRAP_PORT; /* default */
	else
		/* LINTED */
		address.sin_port = (short)trap_port;

	if(snmp_pdu_send(sd, &address, pdu, error_label))
	{
		snmp_pdu_free(pdu);
		(void)close(sd);
		return -1;
	}
	snmp_pdu_free(pdu);
	(void)close(sd);


	return 0;
}

/**********************************************************************/
int trap_send_with_more_para(IPAddress *ip_address,
							 IPAddress my_ip_addr,
							 char *community,
							 int i_flag,
							 Oid *enterprise,
							 int generic,
							 int specific,
							 int trap_port,
							 uint32_t time_stamp,
							 SNMP_variable *variables,
							 char *error_label)
{
 return(trap_send_raw(ip_address,my_ip_addr,community,i_flag,enterprise,generic,
	specific,trap_port,time_stamp, variables,error_label));
}



/********************************************************************/

/*
 *	returns 0 if OK
 *		1 if error
 *		-1 if fatal error
 */

int trap_destinator_add(char *name, char *error_label)
{
	IPAddress ip_address;
	Trap_Destinator *new;
	Trap_Destinator *d;


	error_label[0] = '\0';

	if(name == NULL)
	{
		sprintf(error_label, "BUG: trap_destinator_add(): name is NULL");
		return -1;
	}

	if(name_to_ip_address(name, &ip_address, error_label))
	{
		return 1;
	}

	/* check if this trap destinator does not already exist */
	for(d = first_trap_destinator; d; d = d->next_trap_destinator)
	{
		if(ip_address.s_addr == d->ip_address.s_addr)
		{
			sprintf(error_label, ERR_MSG_TRAP_DEST_DUP,
				name);
			return 1;
		}
	}


	/* allocate, initialize and link the new trap destinator */
	new = (Trap_Destinator *) malloc(sizeof(Trap_Destinator));
	if(new == NULL)
	{
		sprintf(error_label, ERR_MSG_ALLOC);
		return -1;
	}
	new->next_trap_destinator = NULL;
	new->name = NULL;

	new->name = strdup(name);
	if(new->name == NULL)
	{
		sprintf(error_label, ERR_MSG_ALLOC);
		free(new);
		return -1;
	}

	new->ip_address.s_addr = ip_address.s_addr;

	new->next_trap_destinator = first_trap_destinator;
	first_trap_destinator = new;


	return 0;
}


/********************************************************************/

void delete_trap_destinator_list()
{
	Trap_Destinator *next;


	while(first_trap_destinator)
	{
		next = first_trap_destinator->next_trap_destinator;

		if(first_trap_destinator->name)
		{
			free(first_trap_destinator->name);
		}

		free(first_trap_destinator);

		first_trap_destinator = next;
	}

	first_trap_destinator = NULL;
}


/********************************************************************/

void trace_trap_destinators()
{
	Trap_Destinator *d;


	trace("TRAP RECIPIENTS:\n");
	trace("-----------------\n");
	for(d = first_trap_destinator; d; d = d->next_trap_destinator)
	{
		trace("%-30s %-20s\n",
			d->name,
			inet_ntoa(d->ip_address));
	}
	trace("\n");
}


/********************************************************************/
/* ARGSUSED */
int trap_send_to_all_destinators7( int i_flag, Oid *enterprise, int generic,
                                   int specific, uint32_t time_stamp,
                                   SNMP_variable *variables, char *error_label)
{
        Trap_Destinator *d;
        IPAddress my_ip_addr;

	(void)memset(&my_ip_addr, 0, sizeof(IPAddress)); 
 
        error_label[0] = '\0';
 
        for(d = first_trap_destinator; d; d = d->next_trap_destinator)
        {
                if(trap_send_with_more_para(&(d->ip_address), my_ip_addr, NULL, 0,enterprise, generic, specific, SNMP_TRAP_PORT,time_stamp,variables, error_label))
                {
                        return -1;
                }
        }

        return 0;
}
 


int trap_send_to_all_destinators(Oid *enterprise, int generic, int specific, SNMP_variable *variables, char *error_label)
{
	Trap_Destinator *d;


	error_label[0] = '\0';

	for(d = first_trap_destinator; d; d = d->next_trap_destinator)
	{
		if(trap_send(&(d->ip_address), enterprise, generic, specific, variables, error_label))
		{
			return -1;
		}
	}

	return 0;
}

