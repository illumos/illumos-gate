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
 *
 * Copyright 1996 Sun Microsystems, Inc.  All Rights Reserved.
 * Use is subject to license terms.
 */

/*
 * HISTORY
 * 5-20-96	Jerry Yeung	support security file and subtree reg.
 */

#ifndef _SNMPD_H_
#define _SNMPD_H_

#pragma ident	"%Z%%M%	%I%	%E% SMI"

extern char *config_file;
extern char *sec_config_file;
extern int agent_port_number;
extern int max_agent_reg_retry;

extern void SSAMain(int argc, char** argv);

#endif
