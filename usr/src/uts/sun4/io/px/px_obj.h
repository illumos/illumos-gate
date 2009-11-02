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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_PX_OBJ_H
#define	_SYS_PX_OBJ_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/pcie_impl.h>
#include <sys/pci_impl.h>
#include <sys/fm/io/sun4_fire.h>
#include <sys/pci_intr_lib.h>
#include <sys/atomic.h>
#include "px_ioapi.h"
#include "px_lib.h"
#include "px_fm.h"
#include "px_mmu.h"
#include "px_space.h"
#include "px_dma.h"	/* Macros use perf counters in px_space.h */
#include "px_fdvma.h"
#include "px_msiq.h"
#include "px_msi.h"
#include "px_ib.h"
#include "px_pec.h"
#include "px_intr.h"	/* needs px_ib.h */
#include "px_var.h"
#include "px_util.h"
#include "px_debug.h"

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_PX_OBJ_H */
