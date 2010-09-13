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

#ifndef	_PICLSBL_H
#define	_PICLSBL_H

#ifdef	__cplusplus
extern "C" {
#endif

picl_nodehdl_t	root_node;

/* lookup struct for ptree callback */
typedef struct disk_lookup {
	char *path;
	picl_nodehdl_t disk;
	int result;
} disk_lookup_t;

#define	DISK_FOUND	0x00
#define	DISK_NOT_FOUND	0x01

#define	PCPLIB		"libpcp.so"
#define	LIB_PCP_PATH	"/usr/platform/sun4v/lib/"
#define	LED_CHANNEL	"/devices/virtual-devices@100/led@d:glvc"
#define	PCPINIT_TIMEOUT	0x05
#define	PCPCOMM_TIMEOUT	0x10

#define	NAC_DISK_PREFIX	"HDD"

/* sun4v platforms that do not need to handle SBL events */
#define	ERIE_PLATFORM	"SUNW,Sun-Fire-T1000"
#define	ERIE_PLATFORM2	"SUNW,SPARC-Enterprise-T1000"

/* message types */
#define	PCP_SBL_CONTROL		0x3
#define	PCP_SBL_CONTROL_R	0x4

/* pcp request structure */
typedef struct pcp_sbl_req {
	uint32_t sbl_id;
	uint32_t sbl_action;
} pcp_sbl_req_t;

/* sbl_action */
#define	PCP_SBL_ENABLE		0x1
#define	PCP_SBL_DISABLE		0x2

/* pcp response structure */
typedef struct pcp_sbl_resp {
	uint32_t  status;
	uint32_t  sbl_id;
	uint32_t  sbl_state;
} pcp_sbl_resp_t;

/* status */
#define	PCP_SBL_OK		0x1
#define	PCP_SBL_ERROR		0x2

/* sbl_state */
#define	SBL_STATE_ON		0x1
#define	SBL_STATE_OFF		0x2
#define	SBL_STATE_UNKNOWN	0x3

#ifdef	__cplusplus
}
#endif

#endif	/* _PICLSBL_H */
