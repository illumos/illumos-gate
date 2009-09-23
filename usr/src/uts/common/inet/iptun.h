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

#ifndef	_INET_IPTUN_H
#define	_INET_IPTUN_H

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/dld_ioc.h>
#include <netinet/in.h>
#include <netinet/ip6.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * from http://www.iana.org/assignments/ip-parameters
 */
#define	IPTUN_DEFAULT_HOPLIMIT		64
/* from RFC 2473 */
#define	IPTUN_DEFAULT_ENCAPLIMIT	4

#define	IPTUN_CREATE		IPTUNIOC(1)
#define	IPTUN_DELETE		IPTUNIOC(2)
#define	IPTUN_MODIFY		IPTUNIOC(3)
#define	IPTUN_INFO		IPTUNIOC(4)
#define	IPTUN_SET_6TO4RELAY	IPTUNIOC(9)
#define	IPTUN_GET_6TO4RELAY	IPTUNIOC(10)

typedef enum {
	IPTUN_TYPE_UNKNOWN = 0,
	IPTUN_TYPE_IPV4,
	IPTUN_TYPE_IPV6,
	IPTUN_TYPE_6TO4
} iptun_type_t;

/*
 * To maintain proper alignment of fields between 32bit user-land and 64bit
 * kernel, all fields in iptun_kparams_t after itk_fields must be in
 * descending order of size.  Due to strict structure size checks done in the
 * iptun ioctl processing, the structure size must be the same on 32 and 64
 * bit.  amd64 will pad the end of the structure to make the end 64bit
 * aligned, so we must add explicit padding to make sure that it's similarly
 * aligned when compiled in 32 bit mode.
 */
typedef struct iptun_kparams {
	datalink_id_t		iptun_kparam_linkid;
	uint32_t		iptun_kparam_flags;
	struct sockaddr_storage	iptun_kparam_laddr;	/* local address */
	struct sockaddr_storage	iptun_kparam_raddr;	/* remote address */
	ipsec_req_t		iptun_kparam_secinfo;
	iptun_type_t		iptun_kparam_type;
	uint32_t		_iptun_kparam_padding;
} iptun_kparams_t;

/* itk_flags */
#define	IPTUN_KPARAM_TYPE	0x00000001 /* itk_type is set */
#define	IPTUN_KPARAM_LADDR	0x00000002 /* itk_laddr is set */
#define	IPTUN_KPARAM_RADDR	0x00000004 /* itk_raddr is set */
#define	IPTUN_KPARAM_SECINFO	0x00000008 /* itk_secinfo is set */
#define	IPTUN_KPARAM_IMPLICIT	0x00000010 /* implicitly created IP tunnel */
#define	IPTUN_KPARAM_IPSECPOL	0x00000020 /* ipsecconf(1M) policy present */

#ifdef	__cplusplus
}
#endif

#endif	/* _INET_IPTUN_H */
