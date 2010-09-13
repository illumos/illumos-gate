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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_LIBCONTRACT_IMPL_H
#define	_LIBCONTRACT_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/contract.h>
#include <libnvpair.h>
#include <libcontract.h>
#include <stdio.h>

#ifdef	__cplusplus
extern "C" {
#endif

struct ctlib_status_info {
	ct_status_t status;
	nvlist_t *nvl;
};

struct ctlib_event_info {
	ct_event_t event;
	nvlist_t *nvl;
};

extern int ct_tmpl_set_internal(int, uint_t, uintptr_t);
extern int ct_tmpl_set_internal_string(int, uint_t, const char *);
extern int ct_tmpl_get_internal(int, uint_t, uint_t *);
extern int ct_tmpl_get_internal_string(int, uint32_t, char *, size_t);

typedef struct contract_type {
	const char *type_name;
	void (*type_event)(FILE *, ct_evthdl_t, int);
} contract_type_t;

extern contract_type_t types[CTT_MAXTYPE];

#ifdef	__cplusplus
}
#endif

#endif	/* _LIBCONTRACT_IMPL_H */
