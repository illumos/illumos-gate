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
 * Copyright (c) 1998 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifndef _PDU_H_
#define _PDU_H_

#include <sys/types.h>
#include "impl.h"


/***** GLOBAL TYPES *****/

typedef struct _SNMP_value {
	union {
		Integer integer;
		String string;
		Oid oid;
	} val;
} SNMP_value;

#define v_integer val.integer
#define v_string val.string
#define v_oid val.oid

	
typedef struct _SNMP_variable {
	struct _SNMP_variable *next_variable;/* NULL for last variable */
	Oid		name;		/* Object identifier of variable */
	u_char		type;		/* ASN.1 type of variable */
	union {				/* value of variable */
		int32_t	*integer;
		u_char	*string;
		Subid	*objid;
	} val;
	int		val_len;	/* size of the buffer val in bytes */
} SNMP_variable;


typedef struct _SNMP_pdu {
	int version;
	char *community;

	int	type;			/* Type of this PDU */

	uint32_t	request_id;		/* Request id */
	uint32_t	error_status;		/* Error status */
	uint32_t	error_index;		/* Error index */


	/* Trap information */

	Oid	enterprise;		/* System Object Identifier */
	IPAddress ip_agent_addr;	/* Address of object generating trap */
	int	generic;		/* Generic trap */
	int	specific;		/* Specific trap */
	uint32_t	time_stamp;		/* Time stamp */

	SNMP_variable *first_variable;
} SNMP_pdu;


/***** GLOBAL FUNCTIONS *****/

extern SNMP_variable *snmp_pdu_append_null_variable(SNMP_pdu *pdu, Oid *name, char *error_label);
extern SNMP_variable *snmp_pdu_append_typed_variable(SNMP_pdu *pdu, Oid *name,
	u_char type, SNMP_value *value, char *error_label);


extern SNMP_pdu *snmp_pdu_receive(int sd, Address *address, char *error_label);
extern int snmp_pdu_send(int sd, Address *address, SNMP_pdu *pdu, char *error_label);

extern void snmp_pdu_free(SNMP_pdu *pdu);
extern void snmp_variable_free(SNMP_variable *variable);
extern void snmp_variable_list_free(SNMP_variable *variable_list);


extern SNMP_pdu *snmp_pdu_new(char *error_label);
extern SNMP_variable *snmp_variable_new(char *error_label);
extern SNMP_variable *snmp_typed_variable_new(Oid *name, u_char type, SNMP_value *value, char *error_label);

extern SNMP_variable *snmp_typed_variable_append(SNMP_variable *list, Oid *name, u_char type, SNMP_value *value, char *error_label);

extern SNMP_pdu *snmp_pdu_dup(SNMP_pdu *pdu, char *error_label);
extern SNMP_variable *snmp_variable_dup(SNMP_variable *variable, char *error_label);

extern SNMP_variable *ssa_append_integer_variable(SNMP_variable *list, Oid *oid,int num, char *error_label, u_char asn1_type); 
extern SNMP_variable *ssa_append_string_variable(SNMP_variable *list, Oid *oid, String str, char *error_label);
extern SNMP_variable *ssa_append_oid_variable(SNMP_variable *list, Oid *oid, Oid name, char *error_label); 



extern void trace_snmp_pdu(SNMP_pdu *pdu);


#endif




