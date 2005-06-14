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
 * Copyright (c) 1992-1995,1997-2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_SYS_ECPPIO_H
#define	_SYS_ECPPIO_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/bpp_io.h>
#include <sys/ecppsys.h>
#include <sys/note.h>

#define	ECPPIOC_SETREGS		_IOW('p', 73, struct ecpp_regs)
#define	ECPPIOC_GETREGS		_IOR('p', 74, struct ecpp_regs)
#define	ECPPIOC_SETPORT		_IOW('p', 77, uchar_t)
#define	ECPPIOC_GETPORT		_IOR('p', 78, uchar_t)
#define	ECPPIOC_SETDATA		_IOW('p', 79, uchar_t)
#define	ECPPIOC_GETDATA		_IOR('p', 80, uchar_t)

#define	ECPP_MAX_TIMEOUT 	604800	/* one week */
#define	ECPP_W_TIMEOUT_DEFAULT	60	/* 60 seconds */

struct ecpp_regs {
	uint8_t	dsr;	/* status reg */
	uint8_t	dcr;	/* control reg */
};

_NOTE(SCHEME_PROTECTS_DATA("unique per call", ecpp_regs))

/* Values for dsr field */
#define	ECPP_EPP_TMOUT		0x01
#define	ECPP_DSR_reserved1	0x02
#define	ECPP_IRQ_ST		0x04
#define	ECPP_nERR		0x08
#define	ECPP_SLCT		0x10
#define	ECPP_PE			0x20
#define	ECPP_nACK		0x40
#define	ECPP_nBUSY		0x80

/*  Values for the dcr field */
#define	ECPP_STB		0x01
#define	ECPP_AFX		0x02
#define	ECPP_nINIT		0x04
#define	ECPP_SLCTIN		0x08
#define	ECPP_INTR_EN		0x10	/* 1=enable */
#define	ECPP_REV_DIR		0x20	/* 1=reverse dir */
#define	ECPP_DCR_reserved6	0x40
#define	ECPP_DCR_reserved7	0x80
#define	ECPP_DCR_SET		(ECPP_DCR_reserved6 | ECPP_DCR_reserved7)

/* port types */
#define	ECPP_PORT_DMA		0x1	/* default */
#define	ECPP_PORT_PIO		0x2
#define	ECPP_PORT_TDMA		0x3	/* test fifo */

/* these bits are not modified by ECPPIOC_SETREGS/GETREGS */
#define	ECPP_SETREGS_DSR_MASK	\
			(ECPP_EPP_TMOUT | ECPP_DSR_reserved1 | ECPP_IRQ_ST)
#define	ECPP_SETREGS_DCR_MASK	\
			(ECPP_INTR_EN | ECPP_REV_DIR | ECPP_DCR_SET)

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_ECPPIO_H */
