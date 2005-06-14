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
 * Copyright (c) 2000-2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_MESSAGE_REG_MOD_H
#define	_MESSAGE_REG_MOD_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif


#define	INIT_SUB_OPEN_CHAN_ERR	\
	gettext("sysevent_reg_mod: Can not open subscriber channel: %s\n")

#define	INIT_SUB_BIND_PUB_ERR	\
	gettext("sysevent_reg_mod: Can not bind publisher: %s\n")

#define	INIT_SUB_THR_CREATE_ERR	\
	gettext("sysevent_reg_mod: Can not create subscriber "	\
	    "deliver thread: %s\n")

#define	INIT_ACCESS_ERR \
	gettext("sysevent_reg_mod: syseventd channel permissions invalid\n")

#ifdef	__cplusplus
}
#endif

#endif	/* _MESSAGE_REG_MOD_H */
