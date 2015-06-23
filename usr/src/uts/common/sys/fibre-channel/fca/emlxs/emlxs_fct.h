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
 * Copyright (c) 2004-2011 Emulex. All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _EMLXS_FCT_H
#define	_EMLXS_FCT_H

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef SFCT_SUPPORT

#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/stat.h>
#include <sys/pci.h>
#include <sys/sunddi.h>
#include <sys/modctl.h>

#ifdef FC_WELL_KNOWN_ADDR
#undef FC_WELL_KNOWN_ADDR
#endif /* FC_WELL_KNOWN_ADDR */

#include <sys/stmf.h>
#include <sys/fct.h>

#ifndef LINK_SPEED_8G
#define	LINK_SPEED_8G		5
#endif /* LINK_SPEED_8G */

#ifndef LINK_SPEED_10G
#define	LINK_SPEED_10G		6
#endif /* LINK_SPEED_10G */

#ifndef PORT_SPEED_10G
#define	PORT_SPEED_10G		0x10
#endif /* PORT_SPEED_10G */

#ifndef PORT_SPEED_16G
#define	PORT_SPEED_16G		0x20
#endif /* PORT_SPEED_16G */

/*
 * Number of ports that do not require a valid cmd handle
 * because they will not be sending any IO, ELS cmds ONLY.
 */
#define	EMLXS_FCT_NUM_ELS_ONLY		8

#ifndef MODSYM_SUPPORT
#pragma weak fct_alloc
#pragma weak fct_free
#pragma weak fct_scsi_task_alloc
#pragma weak fct_register_local_port
#pragma weak fct_deregister_local_port
#pragma weak fct_handle_event
#pragma weak fct_post_rcvd_cmd
#pragma weak fct_ctl
#pragma weak fct_queue_cmd_for_termination
#pragma weak fct_send_response_done
#pragma weak fct_send_cmd_done
#pragma weak fct_scsi_data_xfer_done
#pragma weak fct_handle_rcvd_flogi
#pragma weak fct_port_shutdown
#pragma weak fct_port_initialize
#pragma weak stmf_deregister_port_provider
#pragma weak stmf_free
#pragma weak stmf_alloc
#pragma weak stmf_register_port_provider
extern void* stmf_alloc();
extern void* fct_alloc();
#endif /* MODSYM_SUPPORT */

#endif	/* SFCT_SUPPORT */

#ifdef	__cplusplus
}
#endif

#endif	/* _EMLXS_FCT_H */
