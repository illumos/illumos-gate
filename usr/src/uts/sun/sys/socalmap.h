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
 * Copyright 1995 Sun Microsystems, Inc. All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_SOCALMAP_H
#define	_SYS_SOCALMAP_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

/*
 *	SOC EEPROM Map
 */
#define	SOCAL_PROM_4TH_SELF_TST	0x00000 /* 0x05000 thru 0x05fff forth code */
#define	SOCAL_PROM_4TH_OBP_DRV	0x01000	/* thru 0x09fff forth OBP driver */
#define	SOCAL_PROM_OBP_HDR	0x05000	/* thru 0x002ff */
#define	SOCAL_PROM_FW_DATE_CODE	0x05300	/* thru 0x00303 FW date code */
#define	SOCAL_PROM_SRVC_PARM	0x05304	/* thru 0x00343 SOC+ Service params */
#define	SOCAL_PROM_LA_BIT_MASK	0x05344	/* thru 0x0034b link app bit mask */
#define	SOCAL_PROM_RSRV1	0x0534c	/* thru 0x00fff */
#define	SOCAL_PROM_SOCAL_CODE	0x06000	/* thru 0x04fff SOC+ code */
#define	SOCAL_PROM_RSRV2	0x0f000	/* thru 0x0ffff */

/*
 *	SOC XRam Map
 */
#define	SOCAL_XRAM_REQ_DESC	0x00200	/* req circular que descriptors */
#define	SOCAL_XRAM_RSP_DESC	0x00220	/* req circular que descriptors */
#define	SOCAL_XRAM_LESB_P0	0x00240
#define	SOCAL_XRAM_LESB_P1	0x00258 /* thru 0x1026f */
#define	SOCAL_XRAM_SERV_PARAMS	0x00280
#define	SOCAL_XRAM_FW_DATE_STR	0x002dc	/* ctime() format date code */
#define	SOCAL_XRAM_FW_DATE_CODE	0x002f8	/* thru 0x002fb FW date code */
#define	SOCAL_XRAM_HW_REV	0x002fc	/* thru 0x002ff HW revision */
#define	SOCAL_XRAM_UCODE	0x00300	/* thru 0x03fff SOC+ microcode */
#define	SOCAL_XRAM_PORTA_WWN	0x00300	/* thru 0x00307, port A wwn */
#define	SOCAL_XRAM_PORTB_WWN	0x00308	/* thru 0x0030f, port B wwn */
#define	SOCAL_XRAM_NODE_WWN	0x00310	/* thru 0x00317, Node worldwide name */
#define	SOCAL_XRAM_PORTA_HRDA	0x00318 /* store port's hard address */
#define	SOCAL_XRAM_BUF_POOL	0x04000	/* thru 0x0bfff	soc+ buffer pool */
#define	SOCAL_XRAM_EXCH_POOL	0x0c000	/* thru 0x0ffff soc+ exchange pool */

#ifdef __cplusplus
}
#endif

#endif /* !_SYS_SOCALMAP_H */
