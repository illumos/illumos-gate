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

#ifndef _TRAP_H_
#define _TRAP_H_

#include <sys/types.h>
#include "pdu.h"

/***** GLOBAL VARIABLES *****/

extern char *trap_community;

extern Subid sun_subids[];
extern Oid sun_oid;

/***** GLOBAL FUNCTIONS *****/

extern int trap_init(Oid *default_enterprise, char *error_label);

extern int trap_send(IPAddress *ip_address, Oid *enterprise, int generic, int specific, SNMP_variable *variables, char *error_label);
extern int trap_send_with_more_para(IPAddress *ip_address,
									IPAddress my_ip_addr,
									char *community,
									int i_flag,
									Oid *enterprise,
									int generic,
									int specific,
									int trap_port,
									uint32_t time_stamp,
									SNMP_variable *variables,
									char *error_label);
extern int trap_destinator_add(char *name, char *error_label);
extern void delete_trap_destinator_list();
extern void trace_trap_destinators();
extern int trap_send_to_all_destinators(Oid *enterprise, int generic, int specific, SNMP_variable *variables, char *error_label);
extern int trap_send_to_all_destinators7(int i_flag, Oid *enterprise, int generic, int specific, uint32_t time_stamp, SNMP_variable *variables, char *error_label);
extern int trap_send_raw(IPAddress *ip_address, IPAddress my_ip_addr,
        char* community,int i_flag,Oid *enterprise,int generic,
        int specific,int trap_port,uint32_t time_stamp,
        SNMP_variable *variables,char *error_label);


#endif
