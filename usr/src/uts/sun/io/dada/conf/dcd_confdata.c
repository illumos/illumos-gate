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
 * Copyright 1996-2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef _KERNEL

#include <sys/dada/conf/autoconf.h>

/*
 * AutoConfiguration Dependent data
 */


/*
 * DCD options word - defines are kept in <dada/conf/autoconf.h>
 *
 * All this options word does is to enable such capabilities. Each
 * implementation may disable this worf or ignore it entirely.
 * Changing this word after system autoconfiguration is not guarenteed
 * to cause any change in the operation of the system.
 */

int dcd_options = DCD_MULT_DMA_MODE5  | DCD_DMA_MODE | DCD_ULTRA_ATA;

#endif	/* _KERNEL */
