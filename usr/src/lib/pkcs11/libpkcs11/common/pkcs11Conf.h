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

#ifndef	_PKCS11_CONF_H
#define	_PKCS11_CONF_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <cryptoutil.h>
#include "pkcs11Slot.h"

extern CK_RV pkcs11_slot_mapping(uentrylist_t *pplist, CK_VOID_PTR pInitArgs);
extern CK_RV pkcs11_mech_parse(umechlist_t *str_list,
    CK_MECHANISM_TYPE_PTR *mech_list, int mech_count);
extern boolean_t pkcs11_is_dismech(CK_SLOT_ID slotid, CK_MECHANISM_TYPE mech);


#ifdef	__cplusplus
}
#endif

#endif	/* _PKCS11_CONF_H */
