/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at
 * http://www.opensource.org/licenses/cddl1.txt.
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
 * Copyright (c) 2004-2012 Emulex. All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_EMLXS_H
#define	_EMLXS_H

#ifdef	__cplusplus
extern "C" {
#endif

#define	DRIVER_NAME		"emlxs"

#include <emlxs_os.h>
#include <emlxs_fcio.h>
#include <emlxs_hw.h>
#include <emlxs_mbox.h>
#include <emlxs_queue.h>
#include <emlxs_iocb.h>
#include <emlxs_fw.h>
#include <emlxs_adapters.h>
#include <emlxs_msg.h>
#include <emlxs_events.h>
#include <emlxs_thread.h>
#include <emlxs_config.h>
#include <emlxs_dfclib.h>

#ifdef DHCHAP_SUPPORT
#include <emlxs_dhchap.h>
#endif /* DHCHAP_SUPPORT */

#ifdef SFCT_SUPPORT
#include <emlxs_fct.h>
#endif /* SFCT_SUPPORT */

#ifdef SAN_DIAG_SUPPORT
#include <emlxs_sdapi.h>
#endif /* SAN_DIAG_SUPPORT */

#ifdef DUMP_SUPPORT
#include <emlxs_dump.h>
#endif /* DUMP_SUPPORT */

#include <emlxs_fc.h>
#include <emlxs_device.h>
#include <emlxs_dfc.h>
#include <emlxs_fcio.h>

#ifdef MENLO_SUPPORT
#include <emlxs_menlo.h>
#endif /* MENLO_SUPPORT */

#include <emlxs_extern.h>

#ifdef	__cplusplus
}
#endif

#endif	/* _EMLXS_H */
