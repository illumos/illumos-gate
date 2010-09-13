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
 * Copyright 1996 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <netinet/in.h>

#include "impl.h"
#include "asn1.h"
#include "error.h"
#include "snmp.h"
#include "trap.h"
#include "pdu.h"

#include "snmprelay.stub.h"


/***** GLOBAL VARIABLES *****/

char default_config_file[] = "/etc/snmprelayd.snmprelay";
char default_sec_config_file[] = "/etc/snmprelayd.conf";
char default_error_file[] = "/tmp/snmprelayd.log";


/***********************************************************/

void agent_init()
{
}


/***********************************************************/

void agent_end()
{
}


/***********************************************************/

void agent_loop()
{
	int condition=FALSE;

	if(condition==TRUE){
	}
}


/***********************************************************/

void agent_select_info(fd_set *fdset, int *numfds)
{
}


/***********************************************************/

void agent_select_callback(fd_set *fdset)
{
}



