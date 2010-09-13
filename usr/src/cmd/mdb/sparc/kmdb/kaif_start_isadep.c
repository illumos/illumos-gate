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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * The SPARC-specific interface to the main CPU-control loops
 */

#include <sys/types.h>
#include <sys/trap.h>

#include <kmdb/kaif.h>
#include <kmdb/kaif_regs.h>
#include <kmdb/kaif_start.h>
#include <kmdb/kmdb_asmutil.h>
#include <kmdb/kmdb_dpi_impl.h>
#include <kmdb/kmdb_kdi.h>
#include <mdb/mdb.h>

void
kaif_debugger_entry(kaif_cpusave_t *cpusave)
{
	kaif_wapt_clear_regs();

	(void) kaif_main_loop(cpusave);

	kaif_wapt_set_regs();
}
