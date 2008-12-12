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

#include <sys/types.h>
#include <sys/t_lock.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/debug.h>
#include <sys/errno.h>
#include <sys/strsubr.h>
#include <sys/cmn_err.h>
#include <sys/sysmacros.h>

#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/strsun.h>
#include <sys/signal.h>

#include <inet/sdp_itf.h>
#include "socksdp.h"

/*
 * Inherit socket properties
 */
void
sosdp_so_inherit(struct sonode *lso, struct sonode *nso)
{
	nso->so_options = lso->so_options & (SO_DEBUG|SO_REUSEADDR|
	    SO_KEEPALIVE|SO_DONTROUTE|SO_BROADCAST|SO_USELOOPBACK|
	    SO_OOBINLINE|SO_DGRAM_ERRIND|SO_LINGER);
	nso->so_sndbuf = lso->so_sndbuf;
	nso->so_rcvbuf = lso->so_rcvbuf;
	nso->so_pgrp = lso->so_pgrp;

	nso->so_rcvlowat = lso->so_rcvlowat;
	nso->so_sndlowat = lso->so_sndlowat;
}
