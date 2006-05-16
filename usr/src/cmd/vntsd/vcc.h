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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


#ifndef _VCC_H
#define	_VCC_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif


#define	VCC_MAX_NAME		25

#define	VCC_NUM_CONSOLE		0x1	    /* total number of groups */
#define	VCC_PORT_TBL		0x2	    /* download all port in a group */

#define	VCC_INQUIRY		0x4	    /* inquiry evnts */
#define	VCC_PORT_CONFIG		0x8	    /* download one port */
#define	VCC_CLEAN_POLL		0x10	    /* vntsd exits */
#define	VCC_DEL_PORT_OK		0x20	    /* vntsd delete port ok */
#define	VCC_PORT_HELLO		0x1

typedef enum {
	VNTSD_MSG_ADD_PORT,
	VNTSD_MSG_DEL_PORT
} vntsd_msg_t;


#define	VCC_PORT_ON		0x40


typedef struct vntsd_console {
	int cons_no;
	uint64_t status;
	char domain_name[VCC_MAX_NAME];
} vntsd_console_t;

/* console configuration that is downloaded to vntsd */
typedef struct vntsd_vcc_console {
	vntsd_console_t	console;
	char 		group_name[VCC_MAX_NAME];
	uint64_t	tcp_port;
} vntsd_vcc_console_t;


#ifdef __cplusplus
}
#endif

#endif /* _VCC_H */
