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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_LDOMS_H
#define	_LDOMS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/param.h>	/* for MAXHOSTNAMELEN */

/*
 * Global LDoms definitions.
 */

/* Maximum number of logical domains supported */
#define	LDOMS_MAX_DOMAINS	32

/* maximum number of characters in the logical domain name */
#define	LDOMS_MAX_NAME_LEN	MAXHOSTNAMELEN

/*
 * Global flags that indicate what domaining features are
 * available, if any. The value is set at boot time based on
 * the value of the 'domaining-enabled' property in the MD
 * and the global override flag 'force_domaining_disabled'.
 * Updates to this variable after boot are not supported.
 */
extern uint_t domaining_capabilities;

/* values for domaining_capabilities word (above) */
#define	DOMAINING_SUPPORTED	0x1
#define	DOMAINING_ENABLED	0x2

#define	domaining_supported()						\
	((domaining_capabilities & DOMAINING_SUPPORTED) != 0)
#define	domaining_enabled()						\
	((domaining_capabilities & DOMAINING_ENABLED) != 0)


#ifdef	__cplusplus
}
#endif

#endif	/* _LDOMS_H */
