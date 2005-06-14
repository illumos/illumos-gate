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
 * Copyright (c) 2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "_rtld.h"


/*
 * Note: for initialization of librtld_db - it's required that
 * the r_debug & rtlddb_priv structures be the *only data item*
 * in the .data section, this is the only way we can gain
 * full control over where it is placed.  This section is in turn
 * placed at the beginning of ld.so.1's data segment (which
 * AT_SUN_LDDATA points to :)).
 */

/*
 * Private structure for passing of information between librltd_db
 * and rtld.
 *
 * Note:  Any data that's being 'exported' to librtld_db must not
 *	  require any 'relocations' before it can be examined.  That's
 *	  because librtld_db will examine this structure before rtld has
 *	  started to execute (and before it's relocated itself).  So - all
 *	  data in this structure must be available at that point.
 */
struct rtld_db_priv r_debug = {
	{
		R_DEBUG_VERSION,			/* version no. */
		0,					/* r_map */
		(unsigned long)rtld_db_dlactivity,	/* r_brk */
		RT_CONSISTENT,				/* r_state */
		0,					/* r_ldbase */
		0,					/* r_ldsomap */
		RD_NONE,				/* r_rdevent */
		RD_FL_NONE				/* r_flags */
	},
	R_RTLDDB_VERSION,		/* rtd_version */
	0,				/* rtd_objpad */
	0				/* rtd_dynlmlst */
};
