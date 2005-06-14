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
 * Copyright 1997 Sun Microsystems, Inc.  All Rights Reserved.
 * Use is subject to license terms.
 */

/*
 * HISTORY
 * 5-13-96      Jerry Yeung     support security file
 */

#ifndef _CONFIG_H_
#define _CONFIG_H_

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/***** GLOBAL VARIABLES *****/

extern char config_file_4_res[];
extern char default_sec_config_file[];


/***** GLOBAL FUNCTIONS *****/

extern int config_init(char *dirname);

/**** SNMP security(5-13-96) ***/
extern int sec_config_init(char *filename);


extern int personal_file_reading(char* dirname, char* filename, time_t *file_time);
extern int resource_update(char *filename);
extern int read_acl();
#endif

