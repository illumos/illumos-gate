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
 * Copyright 2000-2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_SYSEVENT_DOMAIN_H
#define	_SYS_SYSEVENT_DOMAIN_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Event type EC_DOMAIN/ESC_DOMAIN_STATE_CHANGE schema
 *	Event Class	- EC_DOMAIN
 *	Event Sub-Class	- ESC_DOMAIN_STATE_CHANGE
 *	Event Publisher	- SUNW:kern:[domain env monitor]
 *	Attribute Name	- DOMAIN_VERSION
 *	Attribute Type	- SE_DATA_TYPE_UINT32
 *	Attribute Value	- [version of the schema]
 *	Attribute Name	- DOMAIN_WHAT_CHANGED
 *	Attribute Type	- SE_DATA_TYPE_STRING
 *	Attribute Value	- DOMAIN_RESERVED_ATTR | DOMAIN_KEYSWITCH | DOMAIN_FRU
 */
#define	DOMAIN_VERSION		"domain_version"
#define	DOMAIN_WHAT_CHANGED	"domain_what_changed"
#define	DOMAIN_KEYSWITCH	"domain_keyswitch"
#define	DOMAIN_FRU		"domain_fru"
#define	DOMAIN_RESERVED_ATTR	""

#ifdef	__cplusplus
}
#endif

#endif /* _SYS_SYSEVENT_DOMAIN_H */
