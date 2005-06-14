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
 * Copyright 1990 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Portions of this source code were derived from Berkeley 4.3 BSD
 * under license from the Regents of the University of California.
 */

#ifndef	__YPDEFS_H
#define	__YPDEFS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * ypdefs.h
 * Special, internal keys to NIS maps.  These keys are used
 * by various maintain functions of the NIS and invisible
 * to yp clients.  By definition, any key beginning with yp_prefix is
 * an internal key.
 */

#define USE_YP_PREFIX \
	static char yp_prefix[] = "YP_"; \
	static int  yp_prefix_sz = sizeof (yp_prefix) - 1;

#define USE_YP_MASTER_NAME \
	static char yp_master_name[] = "YP_MASTER_NAME"; \
	static int  yp_master_name_sz = sizeof (yp_master_name) - 1;
#define MAX_MASTER_NAME 256

#define USE_YP_LAST_MODIFIED \
	static char yp_last_modified[] = "YP_LAST_MODIFIED"; \
	static int  yp_last_modified_sz = sizeof (yp_last_modified) - 1;

#define MAX_ASCII_ORDER_NUMBER_LENGTH 10

#define USE_YP_INPUT_FILE \
	static char yp_input_file[] = "YP_INPUT_FILE"; \
	static int  yp_input_file_sz = sizeof (yp_input_file) - 1;

#define USE_YP_OUTPUT_NAME \
	static char yp_output_file[] = "YP_OUTPUT_NAME"; \
	static int  yp_output_file_sz = sizeof (yp_output_file) - 1;

#define USE_YP_DOMAIN_NAME \
	static char yp_domain_name[] = "YP_DOMAIN_NAME"; \
	static int  yp_domain_name_sz = sizeof (yp_domain_name) - 1;

#define USE_YP_SECURE \
	static char yp_secure[] = "YP_SECURE"; \
	static int  yp_secure_sz = sizeof (yp_secure) - 1;

#define USE_YP_INTERDOMAIN \
	static char yp_interdomain[] = "YP_INTERDOMAIN"; \
	static int  yp_interdomain_sz = sizeof (yp_interdomain) - 1;

/*
 * Definitions of where the NIS servers keep their databases.
 * These are really only implementation details.
 */

#define USE_YPDBPATH \
	static char ypdbpath[] = "/var/yp"; \
	static int  ypdbpath_sz = sizeof (ypdbpath) - 1;

#define USE_DBM \
	static char dbm_dir[] = ".dir"; \
	static char dbm_pag[] = ".pag";

#ifdef	__cplusplus
}
#endif

#endif	/* __YPDEFS_H */
