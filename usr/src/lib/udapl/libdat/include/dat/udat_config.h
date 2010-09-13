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
 * Copyright (c) 2002-2004, Network Appliance, Inc. All rights reserved.
 */

/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _UDAT_CONFIG_H_
#define	_UDAT_CONFIG_H_

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

/*
 *
 * HEADER: udat_config.h
 *
 * PURPOSE: provides uDAPL configuration information.
 *
 * Description: Header file for "uDAPL: User Direct Access Programming
 *		Library, Version: 1.2"
 *
 */


#define	DAT_VERSION_MAJOR 1
#define	DAT_VERSION_MINOR 2

/*
 * The official header files will default DAT_THREADSAFE to DAT_TRUE. If
 * your project does not wish to use this default, you must ensure that
 * DAT_THREADSAFE will be set to DAT_FALSE. This may be done by an
 * explicit #define in a common project header file that is included
 * before any DAT header files, or through command line directives to the
 * compiler (presumably controlled by the make environment).
 */

/*
 * A site, project or platform may consider setting an alternate default
 * via their make rules, but are discouraged from doing so by editing
 * the official header files.
 */

/*
 * The Reference Implementation is not Thread Safe.  The Reference
 * Implementation has chosen to go with the first method and define it
 * explicitly in the header file.
 */

#define	DAT_THREADSAFE DAT_FALSE

#ifndef DAT_THREADSAFE
#define	DAT_THREADSAFE DAT_TRUE
#endif /* DAT_THREADSAFE */

#ifdef __cplusplus
}
#endif

#endif /* _UDAT_CONFIG_H_ */
