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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _VOLUME_LAYOUT_H
#define	_VOLUME_LAYOUT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#include "volume_request.h"
#include "volume_defaults.h"

/*
 * FUNCTION:	get_layout(devconfig_t *request, defaults_t *defaults)
 *
 * INPUT:	request	- a devconfig_t pointer to the toplevel request
 *		defaults - a results_t pointer to the defaults
 *
 * RETURNS:	int	-  0 - on success
 *			  !0 - otherwise
 *
 * PURPOSE:	Public entry point to layout module.
 */
extern int get_layout(request_t *request, defaults_t *defaults);

/*
 * FUNCTION:	layout_clean_up()
 * INPUT:
 * OUTPUT:
 * SIDEEFFECTS:	releases all memory allocated during layout processing
 *
 * PURPOSE:	function which handles the details of cleaning up memory
 *		allocated while processing a request.
 *
 *		This function must be called explicitly if a call to
 *		get_layout() was terminated abnormally, for example,
 *		if the user terminates the calling process with a SIGINT.
 */
extern void layout_clean_up();

#ifdef __cplusplus
}
#endif

#endif /* _VOLUME_LAYOUT_H */
