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
 *	nis_callback.x
 *
 *	Copyright (c) 1988-1992 Sun Microsystems Inc
 *	All Rights Reserved.
 */

%#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * "@(#)zns_cback.x 1.2 90/09/10 Copyr 1990 Sun Micro" 
 *
 * RPCL description of the Callback Service.
 */

#ifdef RPC_HDR
%#include <rpcsvc/nis.h>
#endif
#ifdef RPC_XDR
%#include "nis_clnt.h"
#endif

typedef nis_object	*obj_p;

struct cback_data {
	obj_p		entries<>;	/* List of objects */
};

program CB_PROG {
	version CB_VERS {
		bool	CBPROC_RECEIVE(cback_data) = 1;
		void	CBPROC_FINISH(void) = 2;
		void	CBPROC_ERROR(nis_error) = 3;
	} = 1;
} = 100302;
