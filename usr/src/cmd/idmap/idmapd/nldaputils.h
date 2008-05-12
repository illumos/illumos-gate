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

#ifndef _NLDAPUTILS_H
#define	_NLDAPUTILS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <stdarg.h>
#include <synch.h>
#include <thread.h>
#include <libintl.h>
#include <strings.h>
#include <inttypes.h>
#include "idmap_prot.h"
#include "idmapd.h"
#include "idmap_config.h"

#ifdef __cplusplus
extern "C" {
#endif

extern idmap_retcode	nldap_lookup_one(lookup_state_t *, idmap_mapping *,
			idmap_id_res *);
extern idmap_retcode	nldap_lookup_batch(lookup_state_t *,
			idmap_mapping_batch *, idmap_ids_res *);
extern char		*sanitize_for_ldap_filter(const char *);

#ifdef __cplusplus
}
#endif

#endif /* _NLDAPUTILS_H */
