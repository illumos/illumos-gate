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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SCF_TYPE_H
#define	_SCF_TYPE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <repcache_protocol.h>

#ifdef	__cplusplus
extern "C" {
#endif

int scf_validate_encoded_value(rep_protocol_value_type_t, const char *);

rep_protocol_value_type_t scf_proto_underlying_type(rep_protocol_value_type_t);

int scf_is_compatible_type(rep_protocol_value_type_t,
    rep_protocol_value_type_t);

#ifdef	__cplusplus
}
#endif

#endif	/* _SCF_TYPE_H */
