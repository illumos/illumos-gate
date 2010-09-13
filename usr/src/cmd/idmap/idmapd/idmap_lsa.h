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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef IDMAP_LSA_H
#define	IDMAP_LSA_H

/*
 * LSA lookups
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <rpcsvc/idmap_prot.h>

/* Given SID, look up name and type */
idmap_retcode
lookup_lsa_by_sid(const char *sidprefix, uint32_t rid, char **ret_name,
    char **ret_domain, idmap_id_type *ret_type);

/* Given name and optional domain, look up SID, type, and canonical name */
idmap_retcode lookup_lsa_by_name(const char *name, const char *domain,
    char **ret_sidprefix, uint32_t *ret_rid, char **ret_name,
    char **ret_domain, idmap_id_type *ret_type);

#ifdef __cplusplus
}
#endif

#endif /* IDMAP_LSA_H */
