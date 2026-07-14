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

#ifndef	_VRRP_H
#define	_VRRP_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct vrrp_pkt_s {
	uint8_t		vp_vers_type;
	uint8_t		vp_vrid;
	uint8_t		vp_prio;
	uint8_t		vp_ipnum;
	uint16_t	vp_rsvd_adver_int;
	uint16_t	vp_chksum;
	/* then follows <vp_ipnum> IPvX addresses */
	/* then follows NO authentification data */
} vrrp_pkt_t;

#define	IPPROTO_VRRP		112	/* IP protocol number */
#define	VRRP_AUTH_LEN		0	/* XXX length of a chunk of Auth Data */

#define	VRRP_IP_TTL		255	/* IPv4 TTL, IPv6 hop limit */
#define	VRRP_VERSION		3	/* current version */
#define	VRRP_PKT_ADVERT		1	/* packet type */
#define	VRRP_VER_MASK		0xf0	/* version mask */
#define	VRRP_TYPE_MASK		0x0f	/* packet type mask */

#define	VRRP_PRI_OWNER		255	/* priority of IP address owner */
#define	VRRP_PRI_MIN		1	/* minimum priority */
#define	VRRP_PRIO_ZERO		0	/* stop participating VRRP */
#define	VRRP_PRI_DEFAULT	VRRP_PRI_OWNER	/* default priority */

#define	VRRP_VRID_NONE		0
#define	VRRP_VRID_MIN		1
#define	VRRP_VRID_MAX		255

#define	CENTISEC2MSEC(centisec)	((centisec) * 10)
#define	MSEC2CENTISEC(msec)	((msec) / 10)

/* Max advertisement interval, in msec */
#define	VRRP_MAX_ADVER_INT_MIN	CENTISEC2MSEC(1)
#define	VRRP_MAX_ADVER_INT_MAX	CENTISEC2MSEC(4095)	/* (2^12 -1) */
#define	VRRP_MAX_ADVER_INT_DFLT	CENTISEC2MSEC(100)	/* 1 sec */

#ifdef __cplusplus
}
#endif

#endif	/* _VRRP_H */
