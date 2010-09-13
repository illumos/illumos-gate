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
 */
/*
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_PCP_UTILS_H
#define	_PCP_UTILS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Enum to differentiate supported transport types
 */
typedef enum {
	GLVC_NON_STREAM,
	VLDC_STREAMING
} pcp_xport_t;

/*
 * This file contains some auxiliary routines to enable libpcp to
 * automatically find the device pathname of a given SP service
 * (e.g. SUNW,sun4v-fma). In addition, glvc pathnames are
 * converted to a service name and then a device path to maintain
 * backward compatibility for applications still using full glvc
 * device paths. The routines are defined in a separate source
 * file, so any program can separately link with the .o file
 * directly instead of using libpcp.
 */

char *platsvc_extract_svc_name(char *devname);
char *platsvc_name_to_path(char *, pcp_xport_t *);

#ifdef	__cplusplus
}
#endif

#endif /* _PCP_UTILS_H */
