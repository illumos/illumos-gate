/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_HOST_IDENT_H
#define	_HOST_IDENT_H


#include <netdb.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	MMS_HOST_IDENT_LEN MAXHOSTNAMELEN
#define	MMS_IP_IDENT_LEN 255

/* covert host name or ip mms_address to internal mm usage */
char *mms_host_ident(char *host_str, char *host, char *ip);

/* localhost info */
char *mms_host_info(char *host, char *ip);

#ifdef	__cplusplus
}
#endif


#endif	/* _HOST_IDENT_H */
