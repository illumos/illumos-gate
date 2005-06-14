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

#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <limits.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "error.h"
#include "snmp.h"
#include "trap.h"
#include "madman_trap.h"


/***** LOCAL CONSTANTS *****/


/***** LOCAL VARIABLES *****/

static Subid applName_subids[] = { 1, 3, 6, 1, 2, 1, 27, 1, 1, 2, 0 };
static Oid applName_name = { applName_subids, 11 };

static Subid applOperStatus_subids[] = { 1, 3, 6, 1, 2, 1, 27, 1, 1, 6, 0 };
static Oid applOperStatus_name = { applOperStatus_subids, 11 };

static Subid alarmId_subids[] = { 1, 3, 6, 1, 4, 1, 42, 2, 8, 2, 3, 1, 0 };
static Oid alarmId_name = { alarmId_subids, 13 };

static Subid alarmSeverity_subids[] = { 1, 3, 6, 1, 4, 1, 42, 2, 8, 2, 3, 2, 0 };
static Oid alarmSeverity_name = { alarmSeverity_subids, 13 };

static Subid alarmDescr_subids[] = { 1, 3, 6, 1, 4, 1, 42, 2, 8, 2, 3, 3, 0 };
static Oid alarmDescr_name = { alarmDescr_subids, 13 };


/***********************************************************************/

void send_trap_appl_status_changed(int applIndex, char *applName, int applOperStatus)
{
	SNMP_variable *list = NULL;
        SNMP_value value;


	/* applName */
	value.v_string.chars = (u_char *) applName;
	if(applName == NULL)
		value.v_string.len = 0;
	else
		/* LINTED */
		value.v_string.len = (int32_t)strlen(applName);
	applName_name.subids[applName_name.len - 1] = applIndex;
	list = snmp_typed_variable_append(list, &applName_name,
		STRING, &value, error_label);
	if(list == NULL)
	{
                error("send_trap_appl_status_changed(%d, %s, %d) failed: %s",
			applIndex, applName, applOperStatus,
			error_label);
		return;
	}


	/* applOperStatus */
	value.v_integer = applOperStatus;
	applOperStatus_name.subids[applOperStatus_name.len - 1] = applIndex;
	list = snmp_typed_variable_append(list, &applOperStatus_name,
		INTEGER, &value, error_label);
	if(list == NULL)
	{
                error("send_trap_appl_status_changed(%d, %s, %d) failed: %s",
			applIndex, applName, applOperStatus,
			error_label);
		return;
	}


	if(trap_send_to_all_destinators(NULL,
		SNMP_TRAP_ENTERPRISESPECIFIC, TRAP_APPL_ALARM,
		list, error_label))
        {
                error("send_trap_appl_status_changed(%d, %s, %d) failed: %s",
			applIndex, applName, applOperStatus,
			error_label);
        	snmp_variable_list_free(list);
                return;
        }
        snmp_variable_list_free(list);
 
 
        return;
}


/***********************************************************************/

void send_trap_appl_alarm(int applIndex, char *applName, int alarmId, int alarmSeverity, char *alarmDescr)
{
	SNMP_variable *list = NULL;
        SNMP_value value;


	/* applName */
	value.v_string.chars = (u_char *) applName;
	if(applName == NULL)
		value.v_string.len = 0;
	else
		/* LINTED */
		value.v_string.len = (int32_t)strlen(applName);
	applName_name.subids[applName_name.len - 1] = applIndex;
	list = snmp_typed_variable_append(list, &applName_name,
		STRING, &value, error_label);
	if(list == NULL)
	{
                error("send_trap_appl_alarm(%d, %s, %d, %d, %s) failed: %s",
			applIndex, applName, alarmId, alarmSeverity, alarmDescr,
			error_label);
		return;
	}


	/* alarmId */
	value.v_integer = alarmId;
	list = snmp_typed_variable_append(list, &alarmId_name,
			INTEGER, &value, error_label);
	if(list == NULL)
	{
                error("send_trap_appl_alarm(%d, %s, %d, %d, %s) failed: %s",
			applIndex, applName, alarmId, alarmSeverity, alarmDescr,
			error_label);
		return;
	}


	/* alarmSeverity */
	value.v_integer = alarmSeverity;
	list = snmp_typed_variable_append(list, &alarmSeverity_name,
		INTEGER, &value, error_label);
	if(list == NULL)
	{
                error("send_trap_appl_alarm(%d, %s, %d, %d, %s) failed: %s",
			applIndex, applName, alarmId, alarmSeverity, alarmDescr,
			error_label);
		return;
	}


	/* alarmDescr */
	value.v_string.chars = (u_char *) alarmDescr;
	if(alarmDescr == NULL)
		value.v_string.len = 0;
	else
		/* LINTED */
		value.v_string.len = (int32_t)strlen(alarmDescr);
	list = snmp_typed_variable_append(list, &alarmDescr_name,
		STRING, &value, error_label);
	if(list == NULL)
	{
                error("send_trap_appl_alarm(%d, %s, %d, %d, %s) failed: %s",
			applIndex, applName, alarmId, alarmSeverity, alarmDescr,
			error_label);
		return;
	}


	if(trap_send_to_all_destinators(NULL,
		SNMP_TRAP_ENTERPRISESPECIFIC, TRAP_APPL_ALARM,
		list, error_label))
        {
                error("send_trap_appl_alarm(%d, %s, %d, %d, %s) failed: %s",
			applIndex, applName, alarmId, alarmSeverity, alarmDescr,
			error_label);
        	snmp_variable_list_free(list);
                return;
        }
        snmp_variable_list_free(list);
 
 
        return;
}


/***********************************************************************/

char *alarmSeverity_string(int severity)
{
	static char buffer[20] = "";


	switch(severity)
	{
		case SEVERITY_LOW:
			sprintf(buffer, "low");
			break;
		case SEVERITY_MEDIUM:
			sprintf(buffer, "medium");
			break;
		case SEVERITY_HIGH:
			sprintf(buffer, "high");
			break;
		default:
			sprintf(buffer, "unknown(%d)", severity);
			break;
	}

	return buffer;
}


