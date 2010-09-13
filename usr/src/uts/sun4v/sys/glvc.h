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

#ifndef	_GLVC_H
#define	_GLVC_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Service channel related Hypervisor function numbers.
 */
#define	SVC_SEND		0x80
#define	SVC_RECV		0x81
#define	SVC_GETSTATUS		0x82
#define	SVC_SETSTATUS		0x83
#define	SVC_CLRSTATUS		0x84

#ifndef _ASM

/*
 * VSC API versioning.
 *
 * Current glvc driver supports VSC API version 1.0.
 */
#define	GLVC_VSC_MAJOR_VER_1	0x1ull
#define	GLVC_VSC_MAJOR_VER	GLVC_VSC_MAJOR_VER_1

#define	GLVC_VSC_MINOR_VER_0	0x0ull
#define	GLVC_VSC_MINOR_VER	GLVC_VSC_MINOR_VER_0

/* for ioctl */
#define	GLVC_XPORT_IOCTL_DATA_PEEK		1
#define	GLVC_XPORT_IOCTL_OPT_OP			2

typedef struct glvc_xport_msg_peek {
	caddr_t		buf;	/* ptr to buffer to hold peeked data */
	size_t		buflen;	/* number of bytes of peeked data */
	uint16_t	flags;	/* future control flags - set to 0 */
} glvc_xport_msg_peek_t;

typedef struct glvc_xport_msg_peek32 {
	uint32_t	buf32;	/* 32 bit ptr to buffer to hold peeked data */
	uint32_t	buflen32;	/* number of bytes of peeked data */
	uint16_t	flags;		/* future control flags - set to 0 */
} glvc_xport_msg_peek32_t;

#define	GLVC_XPORT_OPT_GET			1
#define	GLVC_XPORT_OPT_SET			2

#define	GLVC_XPORT_OPT_MTU_SZ			1
#define	GLVC_XPORT_OPT_LINGER_TO			2
#define	GLVC_XPORT_OPT_REG_STATUS			3

typedef struct glvc_xport_opt_op {
	int32_t		op_sel;		/* operation selector(ex: GET) */
	int32_t		opt_sel;	/* option selector (ex: MTU) */
	uint32_t	opt_val;	/* option value to use */
} glvc_xport_opt_op_t;

#endif /* _ASM */

#ifdef __cplusplus
}
#endif

#endif /* _GLVC_H */
