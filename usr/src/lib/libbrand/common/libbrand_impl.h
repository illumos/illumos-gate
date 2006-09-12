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

#ifndef	_LIBBRAND_IMPL_H
#define	_LIBBRAND_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <libxml/xmlmemory.h>
#include <libxml/parser.h>
#include <libbrand.h>

#ifdef	__cplusplus
extern "C" {
#endif

struct brand_handle {
	char		bh_name[MAXNAMELEN];
	xmlDocPtr	bh_config;
	xmlDocPtr	bh_platform;
};

#define	BRAND_DIR	"/usr/lib/brand"
#define	BRAND_CONFIG	"config.xml"
#define	BRAND_PLATFORM	"platform.xml"

#ifdef	__cplusplus
}
#endif

#endif	/* _LIBBRAND_IMPL_H */
