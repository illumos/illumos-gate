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

#ifndef _VLDC_H
#define	_VLDC_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <sys/ioctl.h>

/* Channel IOCTL Commands */

#define	VLDC_IOCTL_SHIFT	8
#define	VLDC_IOCTL		('1' << VLDC_IOCTL_SHIFT)

#define	VLDC_IOCTL_OPT_OP	(VLDC_IOCTL | 0x1)	/* ctrl op */
#define	VLDC_IOCTL_READ_COOKIE	(VLDC_IOCTL | 0x2)   	/* read cookie */
#define	VLDC_IOCTL_WRITE_COOKIE	(VLDC_IOCTL | 0x3)   	/* write cookie */

/* supported ctrl operations */
#define	VLDC_OP_GET		0x1	    /* get specified value */
#define	VLDC_OP_SET		0x2	    /* set specified value */

/* supported ctrl operation options */
#define	VLDC_OPT_MTU_SZ		0x1	    /* MTU */
#define	VLDC_OPT_STATUS		0x2	    /* port status */
#define	VLDC_OPT_MODE		0x3	    /* port channel mode */

/* values returned by VLDC_OPT_OP_STATUS */
#define	VLDC_PORT_CLOSED	0x1	    /* port is closed */
#define	VLDC_PORT_OPEN		0x2	    /* port is already open */
#define	VLDC_PORT_READY		0x4	    /* port is open and ready */
#define	VLDC_PORT_RESET		0x8	    /* port has been reset */

/*
 * Values for VLDC_OPT_MODE are defined in ldc.h.
 */

/*
 * Structure that is used by vldc driver and all its clients to communicate
 * the type and nature of the option as well as for clients to get port
 * status.
 */
typedef struct vldc_opt_op {
	int32_t		op_sel;		/* operation selector(ex: GET) */
	int32_t		opt_sel;	/* option selector (ex: MTU) */
	uint32_t	opt_val;	/* option value to set or returned */
} vldc_opt_op_t;

/*
 * Structure that is used by the LDom manager to download instruction
 * sequences and read/write new machine descriptions.
 */
typedef struct vldc_data {
	uint64_t	src_addr;	/* source address */
	uint64_t	dst_addr;	/* destination address */
	uint64_t	length;		/* size of transfer */
} vldc_data_t;

#ifdef __cplusplus
}
#endif

#endif /* _VLDC_H */
