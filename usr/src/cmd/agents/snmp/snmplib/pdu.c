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

#include <stdlib.h>
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
#include <sys/uio.h>
#include "snmp_msg.h"
#include "impl.h"
#include "trace.h"
#include "asn1.h"
#include "snmp.h"
#include "pdu.h"
#include "error.h"

/***** LOCAL CONSTANTS *****/

/*It is practically feasible to have a packet up to around 9k bytes (less than 9.5k).*/
#define PACKET_LENGTH		9500             /* The SNMP recommendation is 1500! */
#define COMMUNITY_LENGTH	128


/***** LOCAL VARIABLES *****/

static char static_error_label[500] = "";


/***** LOCAL FUNCTIONS *****/

static void trace_packet(u_char *packet, int length);
static void trace_snmp_variable(SNMP_variable *variable);

static SNMP_pdu *snmp_pdu_decode(u_char *packet, int length, char *error_label);
static SNMP_variable *snmp_pdu_decode_variable(u_char **data, int *length, char *error_label);
static int snmp_pdu_encode(SNMP_pdu *pdu, u_char *packet, int *length, char *error_label);
static u_char *snmp_pdu_encode_variable(SNMP_variable *variable, u_char *data, int *length, char *error_label);

static void shift_array(u_char *begin, int length, int shift_amount);


/********************************************************************/

SNMP_variable *snmp_variable_new(char *error_label)
{
	SNMP_variable *new;


	error_label[0] = '\0';

	new = (SNMP_variable *) malloc(sizeof(SNMP_variable));
	if(new == NULL)
	{
		sprintf(error_label, ERR_MSG_ALLOC);
		return NULL;
	}
	memset(new, 0, sizeof(SNMP_variable));

	return new;
}


/********************************************************************/

SNMP_variable *snmp_typed_variable_new(Oid *name, u_char type, SNMP_value *value, char *error_label)
{
	SNMP_variable *new;


	error_label[0] = '\0';

	if(name == NULL)
	{
		sprintf(error_label, "BUG: snmp_typed_variable_new(): name is NULL");
		return NULL;
	}

	if(value == NULL)
	{
		sprintf(error_label, "BUG: snmp_typed_variable_new(): value is NULL");
		return NULL;
	}

	new = snmp_variable_new(error_label);
	if(new == NULL)
	{
		return NULL;
	}

	/* name */
	if(SSAOidCpy(&(new->name), name, error_label))
	{
		snmp_variable_free(new);
		return NULL;
	}

	/* type */
	new->type = type;

	/* val, val_len */
	switch(type)
	{
		case INTEGER:
		case COUNTER:
		case GAUGE:
		case TIMETICKS:
			new->val.integer = (int *) malloc(sizeof(int));
			if(new->val.integer == NULL)
			{
				sprintf(error_label, ERR_MSG_ALLOC);
				snmp_variable_free(new);
				return NULL;
			}

			*(new->val.integer) = value->v_integer;

			new->val_len = sizeof(int32_t);

			break;

		case IPADDRESS:
		case OPAQUE:
		case STRING:
			new->val.string = (u_char *) malloc(value->v_string.len);
			if(new->val.string == NULL)
			{
				sprintf(error_label, ERR_MSG_ALLOC);
				snmp_variable_free(new);
				return NULL;
			}

			memcpy(new->val.string,
				value->v_string.chars,
				value->v_string.len);

			new->val_len = value->v_string.len;

			break;

		case OBJID:
			new->val.objid = (Subid *) malloc(value->v_oid.len * sizeof(Subid));
			if(new->val.objid == NULL)
			{
				sprintf(error_label, ERR_MSG_ALLOC);
				snmp_variable_free(new);
				return NULL;
			}

/* Should * sizeof(Subid), yiru's fix*/
			memcpy(new->val.objid,
				value->v_oid.subids,
				value->v_oid.len*sizeof(Subid));

			new->val_len = value->v_oid.len * (int32_t)sizeof(Subid);

			break;

		default:
			sprintf(error_label, "BUG: snmp_typed_variable_new(): unsupported type (0x%x)", type);
			snmp_variable_free(new);
			return NULL;
	}


	return new;
}


/********************************************************************/

SNMP_variable *snmp_typed_variable_append(SNMP_variable *list, Oid *name, u_char type, SNMP_value *value, char *error_label)
{
	SNMP_variable *new;


	error_label[0] = '\0';

	new = snmp_typed_variable_new(name, type, value, error_label);
	if(new == NULL)
	{
		snmp_variable_list_free(list);
		return NULL;
	}

	if(list == NULL)
	{
		list = new;
	}
	else
	{
		SNMP_variable *last = NULL;
		SNMP_variable *v;

		
		for(v = list; v; v = v->next_variable)
		{
			last = v;
		}

		last->next_variable = new;
	}


	return list;
}


/********************************************************************/

SNMP_pdu *snmp_pdu_new(char *error_label)
{
	SNMP_pdu *new;


	error_label[0] = '\0';

	new = (SNMP_pdu *) malloc(sizeof(SNMP_pdu));
	if(new == NULL)
	{
		sprintf(error_label, ERR_MSG_ALLOC);
		return NULL;
	}
	new->community = NULL;
	new->enterprise.subids = NULL;
	new->enterprise.len = 0;
	new->first_variable = NULL;


	new->version = 0;
	new->type = 0;

	new->request_id = 0;
	new->error_status = 0;
	new->error_index = 0;

	new->ip_agent_addr.s_addr = 0;
	new->generic = 0;
	new->specific = 0;
	new->time_stamp = 0;


	return new;
}


/********************************************************************/

SNMP_pdu *snmp_pdu_receive(int sd, Address *address, char *error_label)
{
	SNMP_pdu *pdu;
	u_char * packet;
	int length;
	socklen_t address_length;
	Address network_address;


	error_label[0] = '\0';

	packet = (u_char *) malloc (PACKET_LENGTH * sizeof (u_char));
	if (packet == NULL) {
		sprintf(error_label, ERR_MSG_ALLOC);
		return NULL;
	}
	address_length = (socklen_t) sizeof(Address);
	/* LINTED */
	length = (int)recvfrom(sd, (char *) packet, PACKET_LENGTH, 0,
		(struct sockaddr *) &network_address, &address_length);
	if(length == -1)
	{
		sprintf(error_label, ERR_MSG_RECVFROM, errno_string());
		free (packet);
		return NULL;
	}
	address->sin_family = network_address.sin_family;
	address->sin_addr.s_addr = network_address.sin_addr.s_addr;
	address->sin_port = htons(network_address.sin_port);

	if(trace_flags & TRACE_TRAFFIC)
	{
		trace("<< received %d bytes from %s\n\n",
			length, address_string(address));
	}

	if(trace_flags & TRACE_PACKET)
	{
		trace_packet(packet, length);
	}

	pdu = snmp_pdu_decode(packet, length, error_label);
	free (packet);
	if(pdu == NULL)
	{
		return NULL;
	}

	if(trace_flags & TRACE_PDU)
	{
		trace_snmp_pdu(pdu);
	}


	return pdu;
}


/********************************************************************/

/* this function does not close sd and does not free pdu */

int snmp_pdu_send(int sd, Address *address, SNMP_pdu *pdu, char *error_label)
{
	u_char *packet;
	int length = PACKET_LENGTH;
	int bytes;
	Address network_address;


	packet = (u_char *) malloc (PACKET_LENGTH * sizeof (u_char));
	if (packet == NULL) {
		sprintf(error_label, ERR_MSG_ALLOC);
		return -1;
	}
	error_label[0] = '\0';

	if(pdu == NULL)
	{
		sprintf(error_label, "BUG: snmp_pdu_send(): pdu is NULL");
		return -1;
	}

	if(address == NULL)
	{
		sprintf(error_label, "BUG: snmp_pdu_send(): address is NULL");
		free (packet);
		return -1;
	}

	if(trace_flags & TRACE_PDU)
	{
		trace_snmp_pdu(pdu);
	}

	if(snmp_pdu_encode(pdu, packet, &length, error_label))
	{
		free (packet);
		return -1;
	}

	if(trace_flags & TRACE_PACKET)
	{
		trace_packet(packet, length);
	}

	network_address.sin_family = AF_INET;
	network_address.sin_addr.s_addr = address->sin_addr.s_addr;
	network_address.sin_port = htons(address->sin_port);

	/* LINTED */
	bytes = (int)sendto(sd, (char *) packet, length, 0,
		(struct sockaddr *) &network_address, sizeof(Address));
	free (packet);
	if(bytes == -1)
	{
		sprintf(error_label, ERR_MSG_SENDTO);
		return -1;
	}

	if(trace_flags & TRACE_TRAFFIC)
	{
		trace(">> sent %d bytes to %s\n\n",
			length, address_string(address));
	}


	return 0;
}


/********************************************************************/

void snmp_pdu_free(SNMP_pdu *pdu)
{
	if(pdu == NULL)
	{
		return;
	}

	if(pdu->community)
	{
		free(pdu->community);
	}
	if(pdu->enterprise.subids)
	{
		free(pdu->enterprise.subids);
	}

	snmp_variable_list_free(pdu->first_variable);

	free(pdu);
}


/********************************************************************/

void snmp_variable_list_free(SNMP_variable *variable_list)
{
	while(variable_list)
	{
		SNMP_variable *v;

		v = variable_list->next_variable;
		snmp_variable_free(variable_list);
		variable_list = v;
	}
}


/********************************************************************/

void snmp_variable_free(SNMP_variable *variable)
{
	if(variable == NULL)
	{
		return;
	}

	if(variable->name.subids)
	{
		free(variable->name.subids);
	}

	if(variable->val.string)
	{
		free(variable->val.string);
	}

	free(variable);
}


/********************************************************************/

static void trace_packet(u_char *packet, int length)
{
	int count;


	trace("PACKET:\n");
	trace("-------\n");
	for(count = 0; count < length; count++)
	{
		trace("%02X ", packet[count]);
		if((count % 16) == 15)
		{
			trace("\n");
		}
	}
	trace("\n\n");
}


/********************************************************************/

void trace_snmp_pdu(SNMP_pdu *pdu)
{
	SNMP_variable *variable;


	trace("PDU:\n");
	trace("----\n");
	if(pdu == NULL)
	{
		trace("pdu is NULL!\n\n");
		return;
	}

	trace("version:      %d\n", pdu->version);
	trace("community:    %s\n", pdu->community? pdu->community: "NULL");

	trace("type:         %s\n", pdu_type_string(pdu->type));

	switch(pdu->type)
	{
		case GET_REQ_MSG:
		case GETNEXT_REQ_MSG:
		case GET_RSP_MSG:
		case SET_REQ_MSG:
			trace("request id:   %d\n", pdu->request_id);
			trace("error status: %s\n",
				error_status_string(pdu->error_status));
			trace("error index:  %d\n", pdu->error_index);
			break;

		case TRP_REQ_MSG:
			trace("enterprise:   %s\n",
				SSAOidString(&(pdu->enterprise)));
			trace("IP agent addr: %s\n",
				ip_address_string(&(pdu->ip_agent_addr)));
			trace("generic:      %s\n",
				generic_trap_string(pdu->generic));
			trace("specific:     %d\n", pdu->specific);
			trace("time stamp:   %d\n", pdu->time_stamp);
			break;

		default:
			trace("\n");
			return;
	}

	variable = pdu->first_variable;
	while(variable)
	{
		trace("--------------------------------------------------\n");
		trace_snmp_variable(variable);
		variable = variable->next_variable;
	}
	trace("--------------------------------------------------\n\n");
}


/********************************************************************/

static void trace_snmp_variable(SNMP_variable *variable)
{
	Oid oid;
	int i;


	if(variable == NULL)
	{
		trace("variable is NULL\n");
	}

/*
	trace("variable 0x%x\n", variable);
	trace("next     0x%x\n", variable->next_variable);
*/
	trace("name:    %s\n", SSAOidString(&(variable->name)));
	trace("type:    %s\n", asn1_type_string(variable->type));
	trace("length:  %d\n", variable->val_len);
	trace("value:   ");
	switch(variable->type)
	{
		case INTEGER:
		case COUNTER:
		case GAUGE:
		case TIMETICKS:
			trace("%d\n", *(variable->val.integer));
			break;


		case IPADDRESS:
			if(variable->val_len != 4)
			{
				trace("val_len should be 4! (%d)\n", variable->val_len);
			}
			else
			{
				IPAddress ip_address;

				ip_address.s_addr = *(variable->val.integer);
				trace("%s\n", ip_address_string(&ip_address));
			}
			break;

		case OBJID:
			oid.subids = variable->val.objid;
			oid.len = variable->val_len / (int32_t)sizeof(Subid);
			trace("%s\n", SSAOidString(&oid));
			break;

		case STRING:
		case OPAQUE:
		case NULLOBJ:
		default:
			for(i = 0; i < variable->val_len; i++)
			{
				trace("%c", variable->val.string[i]);
			}
			trace(" ( ");
			for(i = 0; i < variable->val_len; i++)
			{
				trace("%02x ", variable->val.string[i]);
			}
			trace(")\n");
			break;
	}
}


/********************************************************************/

/*
 *	Parses the packet and places the data into the pdu.
 *	If any errors are encountered, NULL is returned.
 */

static SNMP_pdu *snmp_pdu_decode(u_char *packet, int packet_length, char *error_label)
{
	u_char *data = packet;
	int length = packet_length;
	u_char type;
	int len;
	Subid subids[MAX_OID_LEN];
	SNMP_pdu *pdu;
	SNMP_variable *last_variable = NULL;
	char community[COMMUNITY_LENGTH + 1];


	error_label[0] = '\0';

	pdu = snmp_pdu_new(error_label);
	if(pdu == NULL)
	{
		return NULL;
	}

/* header of message */
	data = asn_parse_header(data, (uint32_t *)&length, &type, static_error_label);
	if(data == NULL)
	{
		sprintf(error_label, "Decode the header of message failed: %s",
			static_error_label);
		snmp_pdu_free(pdu);
		return NULL;
	}
	if(type != (ASN_SEQUENCE | ASN_CONSTRUCTOR))
	{
		sprintf(error_label, "The message has a wrong header type (0x%x)", type);
		snmp_pdu_free(pdu);
		return NULL;
	}

/* version */
	data = asn_parse_int(data, (uint32_t *)&length, &type, (int32_t *) &pdu->version,
		sizeof(pdu->version), static_error_label);
	if(data == NULL)
	{
		sprintf(error_label, "Decode the version failed: %s",
			static_error_label);
		snmp_pdu_free(pdu);
		return NULL;
	}
	if(pdu->version != SNMP_VERSION_1)
	{
		sprintf(error_label, "The message has a wrong version (%d)",
			pdu->version);
		snmp_pdu_free(pdu);
		return NULL;
	}

/* parse community */
	len = COMMUNITY_LENGTH;
	data = asn_parse_string(data, (uint32_t *)&length, &type, (u_char *) community,
		(uint32_t *)&len, static_error_label);
	if(data == NULL)
	{
		sprintf(error_label, "Decode the community failed: %s",
			static_error_label);
		snmp_pdu_free(pdu);
		return NULL;
	}
	community[len] = '\0';
	pdu->community = strdup(community);
	if(pdu->community == NULL)
	{
		sprintf(error_label, ERR_MSG_ALLOC);
		snmp_pdu_free(pdu);
		return NULL;
	}

/* header od pdu */
	data = asn_parse_header(data, (uint32_t *)&length, &type, static_error_label);
	if(data == NULL)
	{
		sprintf(error_label, "Decode the header of pdu failed: %s",
			static_error_label);
		snmp_pdu_free(pdu);
		return NULL;
	}
	pdu->type = type;


	switch(pdu->type)
	{
		case GET_REQ_MSG:
		case GETNEXT_REQ_MSG:
		case GET_RSP_MSG:
		case SET_REQ_MSG:

		/* request id */
			data = asn_parse_int(data, (uint32_t *)&length, &type, (int32_t *) &pdu->request_id,
				sizeof(pdu->request_id), static_error_label);
			if(data == NULL)
			{
				sprintf(error_label, "Decode the request id failed: %s",
					static_error_label);
				snmp_pdu_free(pdu);
				return NULL;
			}

		/* error status */
			data = asn_parse_int(data, (uint32_t *)&length, &type, (int32_t *) &pdu->error_status,
				sizeof(pdu->error_status), static_error_label);
			if (data == NULL)
			{
				sprintf(error_label, "Decode the error status failed: %s",
					static_error_label);
				snmp_pdu_free(pdu);
				return NULL;
			}

		/* error index */
			data = asn_parse_int(data, (uint32_t *)&length, &type, (int32_t *)&pdu->error_index,
				sizeof(pdu->error_index), static_error_label);
			if (data == NULL)
			{
				sprintf(error_label, "Decode the error index failed: %s",
					static_error_label);
				snmp_pdu_free(pdu);
				return NULL;
			}

			break;


		case TRP_REQ_MSG:

		/* enterprise */
			pdu->enterprise.len = MAX_OID_LEN;
			data = asn_parse_objid(data, (uint32_t *)&length, &type, subids,
				&pdu->enterprise.len, static_error_label);
			if(data == NULL)
			{
				sprintf(error_label, "Decode the enterprise failed: %s",
					static_error_label);
				snmp_pdu_free(pdu);
				return NULL;
			}
			pdu->enterprise.subids = (Subid *) malloc(pdu->enterprise.len * sizeof(Subid));
			if(pdu->enterprise.subids == NULL)
			{
				sprintf(error_label, ERR_MSG_ALLOC);
				snmp_pdu_free(pdu);
				return NULL;
			}
			memcpy(pdu->enterprise.subids, subids, pdu->enterprise.len * sizeof(Subid));

		/* agent address */
			len = 4;
			data = asn_parse_string(data, (uint32_t *)&length, &type,
				(u_char *)&pdu->ip_agent_addr.s_addr, (uint32_t *)&len, static_error_label);
			if(data == NULL)
			{
				sprintf(error_label, "Decode the agent address failed: %s",
					static_error_label);
				snmp_pdu_free(pdu);
				return NULL;
			}

		/* generic trap */
			data = asn_parse_int(data, (uint32_t *)&length, &type, (int32_t *)&pdu->generic,
				sizeof(pdu->generic), static_error_label);
			if(data == NULL)
			{
				sprintf(error_label, "Decode the generic trap failed: %s",
					static_error_label);
				snmp_pdu_free(pdu);
				return NULL;
			}

		/* specific trap */
			data = asn_parse_int(data, (uint32_t *)&length, &type, (int32_t *)&pdu->specific,
				sizeof(pdu->specific), static_error_label);
			if(data == NULL)
			{
				sprintf(error_label, "Decode the specific trap failed: %s",
					static_error_label);
				snmp_pdu_free(pdu);
				return NULL;
			}

		/* time stamp */
			data = asn_parse_unsigned_int(data, (uint32_t *)&length, &type, (int32_t *)&pdu->time_stamp,
				sizeof(pdu->time_stamp), static_error_label);
			if(data == NULL)
			{
				sprintf(error_label, "Decode the time stamp failed: %s",
					static_error_label);
				snmp_pdu_free(pdu);
				return NULL;
			}

			break;


		default:
			sprintf(error_label, "The type of the pdu is wrong (%d)", pdu->type);
			snmp_pdu_free(pdu);
			return NULL;
	}


/* header of variables */
	data = asn_parse_header(data, (uint32_t *)&length, &type, static_error_label);
	if(data == NULL)
	{
		sprintf(error_label, "Decode the header of the variables failed: %s",
			static_error_label);
		snmp_pdu_free(pdu);
		return NULL;
	}
	if(type != (ASN_SEQUENCE | ASN_CONSTRUCTOR))
	{
		sprintf(error_label, "The header of the variables has a wrong type (%x)", type);
		snmp_pdu_free(pdu);
		return NULL;
	}



	while(length > 0)
	{
		SNMP_variable *variable;


		variable = snmp_pdu_decode_variable(&data , &length, error_label);
		if(variable == NULL)
		{
			snmp_pdu_free(pdu);
			return NULL;
		}

		if(pdu->first_variable == NULL)
		{
			pdu->first_variable = variable;
		}
		else
		{
			last_variable->next_variable = variable;
		}
		last_variable = variable;

	} /* while */


	return pdu;
}


/********************************************************************/

static SNMP_variable *snmp_pdu_decode_variable(u_char **data, int *length, char *error_label)
{
	u_char *d = *data;
	u_char *value_start;
	int len = *length;
	SNMP_variable *variable;
	u_char type;
	Subid subids[MAX_OID_LEN];


	error_label[0] = '\0';

	variable = snmp_variable_new(error_label);
	if(variable == NULL)
	{
		return NULL;
	}


/* header of variable */
	d = asn_parse_header(d, (uint32_t *)&len, &type, static_error_label);
	if(d == NULL)
	{
		sprintf(error_label, "Decode the header of a variable failed: %s",
			static_error_label);
		snmp_variable_free(variable);
		return NULL;
	}
	if(type != (ASN_SEQUENCE | ASN_CONSTRUCTOR))
	{
		sprintf(error_label, "The header of a variable has a wrong type (%x)", type);
		snmp_variable_free(variable);
		return NULL;
	}


/* name */
	variable->name.len = MAX_OID_LEN;
	d = asn_parse_objid(d, (uint32_t *)&len, &type, subids, &(variable->name.len), static_error_label);
	if(d == NULL)
	{
		sprintf(error_label, "Decode the name of a variable failed: %s",
			static_error_label);
		snmp_variable_free(variable);
		return NULL;
	}
	if(type != (u_char) OBJID)
	{
		sprintf(error_label, "The name of a variable has wrong type (%x)", type);
		snmp_variable_free(variable);
		return NULL;
	}
	variable->name.subids = (Subid *) malloc(variable->name.len * sizeof(Subid));
	if(variable->name.subids == NULL)
	{
		sprintf(error_label, ERR_MSG_ALLOC);
		snmp_variable_free(variable);
		return NULL;
	}
	memcpy(variable->name.subids, subids, variable->name.len * sizeof(Subid));


/* find out what type of object this is */
	variable->val_len = len;
	value_start = d;
	d = asn_parse_header(d, (uint32_t *)&variable->val_len, &variable->type, static_error_label);
	if(d == NULL)
	{
		sprintf(error_label, "Decode the type of a variable failed: %s",
			static_error_label);
		snmp_variable_free(variable);
		return NULL;
	}

	switch(variable->type)
	{
		case INTEGER:
		case COUNTER:
		case GAUGE:
		case TIMETICKS:
			variable->val.integer = (int32_t *) malloc(sizeof(int32_t));
			if(variable->val.integer == NULL)
			{
				sprintf(error_label, ERR_MSG_ALLOC);
				snmp_variable_free(variable);
				return NULL;
			}
			variable->val_len = sizeof(int32_t);
			d = asn_parse_unsigned_int(value_start, (uint32_t *)&len, &variable->type,
				(int32_t *)variable->val.integer, sizeof(int32_t), static_error_label);
			if(d == NULL)
			{
				sprintf(error_label, "Decode a variable of type integer failed: %s",
					static_error_label);
				snmp_variable_free(variable);
				return NULL;
			}
			break;

		case STRING:
		case IPADDRESS:
		case OPAQUE:
			variable->val.string = (u_char *) malloc(variable->val_len);
			if(variable->val.string == NULL)
			{
				sprintf(error_label, ERR_MSG_ALLOC);
				snmp_variable_free(variable);
				return NULL;
			}
			d = asn_parse_string(value_start, (uint32_t *)&len, &variable->type,
				variable->val.string, (uint32_t *)&variable->val_len, static_error_label);
			if(d == NULL)
			{
				sprintf(error_label, "Decode a variable of type octet string failed: %s",
					static_error_label);
				snmp_variable_free(variable);
				return NULL;
			}
			break;

		case OBJID:
			variable->val_len = MAX_OID_LEN;
			d = asn_parse_objid(value_start, (uint32_t *)&len, &variable->type,
				subids, &variable->val_len, static_error_label);
			if(d == NULL)
			{
				sprintf(error_label, "Decode a variable of type object identifier failed: %s",
					static_error_label);
				snmp_variable_free(variable);
				return NULL;
			}
			variable->val_len = variable->val_len * (int32_t)sizeof(Subid);
			variable->val.objid = (Subid *) malloc(variable->val_len);
			if(variable->val.objid == NULL)
			{
				sprintf(error_label, ERR_MSG_ALLOC);
				snmp_variable_free(variable);
				return NULL;
			}
			memcpy(variable->val.objid, subids, variable->val_len);
			break;

		case NULLOBJ:
			break;

		default:
			sprintf(error_label, "A variable has a wrong type (%x)", variable->type);
			snmp_variable_free(variable);
			return NULL;
	}

	/* LINTED */
	*length = *length - (uint32_t)(d - *data);
	*data = d;


	return variable;
}


/********************************************************************/

/*
 *	Takes a pdu and serializes the ASN PDU into the area
 *	pointed to by packet.  length is the size of the data area available.
 *	Returns the length of the completed packet in length.  If any errors
 *	occur, -1 is returned.  If all goes well, 0 is returned.
 */

static int snmp_pdu_encode(SNMP_pdu *pdu, u_char *packet, int *packet_length, char *error_label)
{
	u_char *buf;
	int buf_len;
	int len;
	SNMP_variable *variable;
	u_char *cp;
	int32_t total_length;


	buf = (u_char *) malloc (PACKET_LENGTH * sizeof (u_char));
	if (buf == NULL) {
		sprintf(error_label, ERR_MSG_ALLOC);
		return -1;
	}
	error_label[0] = '\0';

	cp = packet;
	len = *packet_length;

/* encode the variables in packet */
	for(variable = pdu->first_variable; variable; variable = variable->next_variable)
	{
		cp = snmp_pdu_encode_variable(variable, cp, &len, error_label);
		if(cp == NULL) {
			free (buf);
			return -1;
		}
	}
	/* LINTED */
	total_length = (int32_t)(cp - packet); /* Better fit in 32 bits */

/* encode the header for the variables in buf */
	buf_len = PACKET_LENGTH;
	cp = asn_build_header(buf, (uint32_t *)&buf_len, (u_char)(ASN_SEQUENCE | ASN_CONSTRUCTOR),
		total_length, static_error_label);
	if(cp == NULL)
	{
		sprintf(error_label, "Encode the header of the variables failed: %s",
			static_error_label);
		free (buf);
		return -1;
	}

/* copy the encoded variables from packet to buf */
	memcpy(cp, packet, total_length);
	/* LINTED */
	total_length += (int32_t)(cp - buf);


/* encode the pdu in packet */
	len = *packet_length;
	switch(pdu->type)
	{
		case GET_REQ_MSG:
		case GETNEXT_REQ_MSG:
		case GET_RSP_MSG:
		case SET_REQ_MSG:

		/* request id */
			cp = asn_build_int(packet, (uint32_t *)&len, (u_char) INTEGER,
				(int32_t *) &pdu->request_id, sizeof(pdu->request_id),
				static_error_label);
			if(cp == NULL)
			{
				sprintf(error_label, "Encode the request id failed: %s",
					static_error_label);
				free (buf);
				return -1;
			}

		/* error status */
			cp = asn_build_int(cp, (uint32_t *)&len, (u_char) INTEGER,
				(int32_t *) &pdu->error_status, sizeof(pdu->error_status),
				static_error_label);
			if(cp == NULL)
			{
				sprintf(error_label, "Encode the error status failed: %s",
					static_error_label);
				free (buf);
				return -1;
			}

		/* error index */
			cp = asn_build_int(cp, (uint32_t *)&len, (u_char) INTEGER,
				(int32_t *) &pdu->error_index, sizeof(pdu->error_index),
				static_error_label);
			if(cp == NULL)
			{
				sprintf(error_label, "Encode the error index failed: %s",
					static_error_label);
				free (buf);
				return -1;
			}

			break;


		case TRP_REQ_MSG:

		/* enterprise */
			cp = asn_build_objid(packet, (uint32_t *)&len, (u_char) OBJID,
				(Subid *) pdu->enterprise.subids, pdu->enterprise.len,
				static_error_label);
			if(cp == NULL)
			{
				sprintf(error_label, "Encode the enterprise failed: %s",
					static_error_label);
				free (buf);
				return -1;
			}

		/* agent-addr */
			cp = asn_build_string(cp, (uint32_t *)&len, (u_char) IPADDRESS,
				(u_char *) &pdu->ip_agent_addr.s_addr,
				sizeof(pdu->ip_agent_addr.s_addr),
				static_error_label);
			if(cp == NULL)
			{
				sprintf(error_label, "Encode the agent address failed: %s",
					static_error_label);
				free (buf);
				return -1;
			}

		/* generic trap */
			cp = asn_build_int(cp, (uint32_t *)&len, (u_char) INTEGER,
				(int32_t *) &pdu->generic, sizeof(pdu->generic),
				static_error_label);
			if(cp == NULL)
			{
				sprintf(error_label, "Encode the generic trap failed: %s",
					static_error_label);
				free (buf);
				return -1;
			}

		/* specific trap */
			cp = asn_build_int(cp, (uint32_t *)&len, (u_char) INTEGER,
				(int32_t *) &pdu->specific, sizeof(pdu->specific),
				static_error_label);
			if(cp == NULL)
			{
				sprintf(error_label, "Encode the specific trap failed: %s",
					static_error_label);
				free (buf);
				return -1;
			}

		/* time stamp  */
			cp = asn_build_unsigned_int(cp, (uint32_t *)&len, (u_char) TIMETICKS,
				(int32_t *) &pdu->time_stamp, sizeof(pdu->time_stamp),
				static_error_label);
			if(cp == NULL)
			{
				sprintf(error_label, "Encode the time stamp failed: %s",
					static_error_label);
				free (buf);
				return -1;
			}

			break;


		default:
			sprintf(error_label, "The pdu has a wrong type (%x)", pdu->type);
			free (buf);
			return -1;

	} /* switch */


/* copy the encoded variables and their header from buf to packet */
	if(len < total_length)
	{
		sprintf(error_label, "The buffer is too small");
		free (buf);
		return -1;
	}
	memcpy(cp, buf, total_length);
	/* LINTED */
	total_length += (int32_t)(cp - packet);


/* encode the header of the pdu in buf */
	len = PACKET_LENGTH;
	/* LINTED */
	cp = asn_build_header(buf, (uint32_t *)&len, (u_char)pdu->type, 
		total_length, static_error_label);
	if(cp == NULL)
	{
		sprintf(error_label, "Encode the header of the pdu failed: %s",
			static_error_label);
		free (buf);
		return -1;
	}


/* copy the pdu from packet to buf */
	if(len < total_length)
	{
		sprintf(error_label, "The buffer is too small");
		free (buf);
		return -1;
	}
	memcpy(cp, packet, total_length);
	/* LINTED */
	total_length += (int32_t)(cp - buf);

/* encode the message in packet */
	len = *packet_length;

	if(pdu->community == NULL)
	{
		sprintf(error_label, "BUG: snmp_pdu_encode(): community is NULL");
		free (buf);
		return -1;
	}

	cp = asn_build_header(packet, (uint32_t *)&len, (u_char)(ASN_SEQUENCE | ASN_CONSTRUCTOR),
		/* LINTED */
		total_length + (int32_t)strlen(pdu->community) + 5,
		static_error_label);
	if(cp == NULL)
	{
		sprintf(error_label, "Encode the header of the message failed: %s",
			static_error_label);
		free (buf);
		return -1;
	}

/* version */
	cp = asn_build_int(cp, (uint32_t *)&len, (u_char) INTEGER,
		(int32_t *) &pdu->version, sizeof(pdu->version),
		static_error_label);
	if(cp == NULL)
	{
		sprintf(error_label, "Encode the version failed: %s",
			static_error_label);
		free (buf);
		return -1;
	}

/* community */
	cp = asn_build_string(cp, (uint32_t *)&len, (u_char) STRING, 
		/* LINTED */
		(u_char *) pdu->community, (int32_t)strlen(pdu->community),
		static_error_label);
	if(cp == NULL)
	{
		sprintf(error_label, "Encode the community failed: %s",
			static_error_label);
		free (buf);
		return -1;
	}


/* copy the pdu and its header from buf to packet */
	if(len < total_length)
	{
		sprintf(error_label, "The buffer is too small");
		free (buf);
		return -1;
	}

	memcpy(cp, buf, total_length);
	/* LINTED */
	total_length += (int32_t)(cp - packet);
	*packet_length = total_length;

	free (buf);
	return 0;
}


/********************************************************************/

static u_char *snmp_pdu_encode_variable(SNMP_variable *variable, u_char *data, int *length, char *error_label)
{
	int dummy_len, header_len, header_shift;
	u_char *data_ptr;


	error_label[0] = '\0';

	dummy_len = *length;
	data_ptr = data;
	data = asn_build_header(data, (uint32_t *)&dummy_len, (u_char)(ASN_SEQUENCE | ASN_CONSTRUCTOR), 0,
		static_error_label);
	if(data == NULL) {
		sprintf(error_label, "Encode the header of a variable failed: %s",
			static_error_label);
		return NULL;
	}

	/* LINTED */
	header_len = (int32_t)(data - data_ptr);
	*length = *length - header_len;
	data = asn_build_objid(data, (uint32_t *)length, (u_char) OBJID,
	    variable->name.subids, variable->name.len, static_error_label);
	if(data == NULL)
	{
		sprintf(error_label, "Encode the name of a variable failed: %s",
			static_error_label);
		return NULL;
	}


	switch(variable->type)
	{
		case INTEGER:
		case GAUGE:
		case COUNTER:
		case TIMETICKS:
			if (variable->type == TIMETICKS)
	    			data = asn_build_unsigned_int(data, (uint32_t *)length, variable->type,
					(int32_t *) variable->val.integer, variable->val_len, static_error_label);
			else
	    			data = asn_build_int(data, (uint32_t *)length, variable->type,
					(int32_t *) variable->val.integer, variable->val_len, static_error_label);
			if(data == NULL)
			{
				sprintf(error_label, "Encode a variable of type integer failed: %s",
					static_error_label);
				return NULL;
			}
			break;

		case STRING:
		case IPADDRESS:
		case OPAQUE:
			data = asn_build_string(data, (uint32_t *)length, variable->type,
				variable->val.string, variable->val_len, static_error_label);
			if(data == NULL)
			{
				sprintf(error_label, "Encode a variable of type octet string failed: %s",
					static_error_label);
				return NULL;
			}
			break;

		case OBJID:
			data = asn_build_objid(data, (uint32_t *)length, variable->type, variable->val.objid,
				variable->val_len / (int32_t)sizeof(Subid), static_error_label);
			if(data == NULL)
			{
				sprintf(error_label, "Encode a variable of type object identifier failed: %s",
					static_error_label);
				return NULL;
			}
			break;

		case NULLOBJ:
			data = asn_build_null(data, (uint32_t *)length, variable->type, static_error_label);
			if(data == NULL)
			{
				sprintf(error_label, "Encode a variable of type null failed: %s",
					static_error_label);
				return NULL;
			}
			break;

		default:
			sprintf(error_label, "A variable has a wrong type (%x)", variable->type);
			return NULL;
	} /* switch */


	/* LINTED */
	dummy_len = (uint32_t)(data - data_ptr) - header_len;
	header_shift = 0;
	if(dummy_len >= 0x80)
	{
		header_shift++;
		if(dummy_len > 0xFF)
		{
			header_shift++;
		}
	}


	if(header_shift)
	{
		*length = *length - header_shift;
		if(*length < 0)
		{
			sprintf(error_label, "The buffer is too small");
			return NULL;
		}
		
		shift_array(data_ptr + header_len, dummy_len, header_shift);
		data = data + header_shift;
		header_len = header_len + header_shift;
	}


	if(asn_build_header(data_ptr, (uint32_t *)&dummy_len, (u_char)(ASN_SEQUENCE | ASN_CONSTRUCTOR),
		dummy_len, static_error_label) == NULL)
	{
		sprintf(error_label, "Encode the header of a variable failed: %s",
			static_error_label);
		return NULL;
	}


	return data;
}


/********************************************************************/

static void shift_array(u_char *begin, int length, int shift_amount)
{
	register u_char	*old, *new;

	if(shift_amount >= 0)
	{
		old = begin + length - 1;
		new = old + shift_amount;

		while(length--)
		{
			*new-- = *old--;
		}
	}
	else
	{
		old = begin;
		new = begin + shift_amount;

		while(length--)
		{
			*new++ = *old++;
		}
	}
}


/********************************************************************/

SNMP_pdu *snmp_pdu_dup(SNMP_pdu *pdu, char *error_label)
{
	SNMP_pdu *new;


	error_label[0] = '\0';

	new = snmp_pdu_new(error_label);
	if(new == NULL)
	{
		return NULL;
	}

	new->version = pdu->version;
	new->community = strdup(pdu->community);
	if(new->community == NULL)
	{
		sprintf(error_label, ERR_MSG_ALLOC);
		snmp_pdu_free(new);
		return NULL;
	}

	new->type = pdu->type;

	new->request_id = pdu->request_id;
	new->error_status = pdu->error_status;
	new->error_index = pdu->error_index;

	if(SSAOidCpy(&(new->enterprise), &(pdu->enterprise), error_label))
	{
		snmp_pdu_free(new);
		return NULL;
	}

	memcpy(&(new->ip_agent_addr), &(pdu->ip_agent_addr), sizeof(IPAddress));
	new->generic = pdu->generic;
	new->specific = pdu->specific;
	new->time_stamp = pdu->time_stamp;


	return new;
}


/********************************************************************/

SNMP_variable *
snmp_variable_dup(SNMP_variable *variable, char *error_label)
{
	SNMP_variable *new;


	error_label[0] = '\0';

	new = snmp_variable_new(error_label);
	if (new == NULL) {
		return (NULL);
	}

	if (SSAOidCpy(&(new->name), &(variable->name), error_label)) {
		snmp_variable_free(new);
		return (NULL);
	}

	new->type = variable->type;
	if (variable->val_len > 0) {
		new->val.string = (uchar_t *)malloc(variable->val_len);
		if (new->val.string == NULL) {
			sprintf(error_label, ERR_MSG_ALLOC);
			snmp_variable_free(new);
			return (NULL);
		}
		memcpy(new->val.string, variable->val.string,
			variable->val_len);
	} else {
		new->val.string = NULL;
	}

	new->val_len = variable->val_len;


	return (new);
}


/********************************************************************/

SNMP_variable *snmp_pdu_append_null_variable(SNMP_pdu *pdu, Oid *name, char *error_label)
{
	SNMP_variable *new;
	SNMP_variable *current, *last;


	error_label[0] = '\0';

	if(pdu == NULL)
	{
		sprintf(error_label, "BUG: snmp_pdu_append_null_variable(): pdu is NULL");
		return NULL;
	}

	if(name == NULL)
	{
		sprintf(error_label, "BUG: snmp_pdu_append_null_variable(): pdu is NULL");
		return NULL;
	}

	new = snmp_variable_new(error_label);
	if(new == NULL)
	{
		return NULL;
	}

	if(SSAOidCpy(&(new->name), name, error_label))
	{
		snmp_variable_free(new);
		return NULL;
	}

	new->type = NULLOBJ;

	last = NULL;
	for(current = pdu->first_variable; current; current = current->next_variable)
	{
		last = current;
	}

	if(last)
	{
		last->next_variable = new;
	}
	else
	{
		pdu->first_variable = new;
	}


	return new;
}

SNMP_variable *ssa_append_integer_variable(SNMP_variable *list, Oid *oid, int num,char *error_label,u_char asn1_type)
{
  SNMP_value value;
 
  value.v_integer = num;
  list = snmp_typed_variable_append(list,oid,asn1_type,&value,error_label);
  if(list == NULL){
        error("ssa_append_integer_variable failed: oid: %s, value: %d\n",
                SSAOidString(oid),num);
  }
  return(list);
}

SNMP_variable *
ssa_append_string_variable(SNMP_variable *list, Oid *oid, String str,
	char *error_label)
{
	SNMP_value value;

	if (str.chars == NULL)
		return (NULL);
	value.v_string.chars = (uchar_t *)str.chars;
	value.v_string.len = str.len;
	list = snmp_typed_variable_append(list, oid, STRING, &value,
		error_label);
	if (list == NULL) {
		error("ssa_append_string_variable failed: oid: %s, \
			value: %s\n", SSAOidString(oid), str);
	}
	return (list);
}

SNMP_variable *ssa_append_oid_variable(SNMP_variable *list, Oid *oid, Oid name, char *error_label)
{
  SNMP_value value;

  if(oid == NULL || name.subids == NULL || name.len == 0) return NULL;
  value.v_oid.subids = name.subids;
  value.v_oid.len = name.len;
  list = snmp_typed_variable_append(list,oid,OBJID,&value,error_label);
  if(list == NULL){
        error("ssa_append_oid_varaible(%s,%s) failed\n",
                SSAOidString(oid),SSAOidString(&name));
  }
  return(list);
}






