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

#ifndef	_MIDLEVEL_IMPL_H
#define	_MIDLEVEL_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "libscf_impl.h"

#ifdef	__cplusplus
extern "C" {
#endif

union scf_simple_prop_val {
	uint8_t		pv_bool;
	uint64_t	pv_uint;
	int64_t		pv_int;
	char 		*pv_str;
	struct pv_time {
		int64_t	t_sec;
		int32_t	t_nsec;
	} pv_time;
	struct pv_opaque {
		void 	*o_value;
		size_t	o_size;
	} pv_opaque;
};

struct scf_simple_prop {
	uint32_t			pr_numvalues;
	uint32_t			pr_iter;
	scf_type_t			pr_type;
	char				*pr_propname;
	char				*pr_pgname;
	union scf_simple_prop_val	*pr_vallist;
	scf_simple_prop_t		*pr_next;
	struct scf_simple_pg		*pr_pg;
};

struct scf_simple_pg {
	char			*pg_name;
	scf_simple_prop_t	*pg_proplist;
	struct scf_simple_pg	*pg_next;
};

struct scf_simple_app_props {
	char 			*ap_fmri;
	struct scf_simple_pg	*ap_pglist;
};

#ifdef	__cplusplus
}
#endif

#endif	/* _MIDLEVEL_IMPL_H */
