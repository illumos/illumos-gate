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
 *
 */

#ifndef _CONFIG_SITE_H
#define	_CONFIG_SITE_H

/* $Id: config-site.h.in 171 2006-05-20 06:00:32Z njacobs $ */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <config.h>

#ifdef __cplusplus
extern "C" {
#endif

/* the "default" destination for various commands and libraries */
#define DEFAULT_DEST	"_default"

/* the "default" server uri to fallback to */
#define DEFAULT_SERVICE_URI	"lpsched://localhost/printers"

/* the "default" IPP service to fallback to in the IPP psm */
#define DEFAULT_IPP_SERVICE_URI	"ipp://localhost/printers"

/* the name of the SUID lpd-port binary that hands psm-lpd a connected socket */
#define SUID_LPD_PORT	    "/usr/lib/print/lpd-port"

/* enable/disable printer-uri in enumeration results */
#define NEED_BROKEN_PRINTER_URI_SEMANTIC

#ifdef __cplusplus
}
#endif

#endif /* _CONFIG_SITE_H */
