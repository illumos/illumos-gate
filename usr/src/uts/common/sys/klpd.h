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

#ifndef	_SYS_KLPD_H
#define	_SYS_KLPD_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/priv.h>
#include <sys/procset.h>

#ifdef _KERNEL
#include <sys/cred.h>
#include <sys/sysmacros.h>
#include <sys/varargs.h>
#endif

#ifdef	__cplusplus
extern "C" {
#endif

#define	KLPDCALL_VERS		1

#define	KLPDARG_NOMORE		0		/* End of argument List */
#define	KLPDARG_NONE		0		/* No argument */
#define	KLPDARG_VNODE		1		/* vnode_t * */
#define	KLPDARG_INT		2		/* int */
#define	KLPDARG_PORT		3		/* int, port number */
#define	KLPDARG_TCPPORT		4		/* int, tcp port number */
#define	KLPDARG_UDPPORT		5		/* int, udp port number */
#define	KLPDARG_SCTPPORT	6		/* int, sctp port number */
#define	KLPDARG_SDPPORT		7		/* int, sdp port number */

#ifdef _KERNEL

struct klpd_reg;
struct credklpd;

int klpd_reg(int, idtype_t, id_t, priv_set_t *);
int klpd_unreg(int, idtype_t, id_t);
void klpd_remove(struct klpd_reg **);
void klpd_rele(struct klpd_reg *);
int klpd_call(const cred_t *, const priv_set_t *, va_list);
void crklpd_hold(struct credklpd *);
void crklpd_rele(struct credklpd *);

#endif /* _KERNEL */

typedef struct klpd_head {
	uint32_t	klh_vers;		/* Version */
	uint32_t	klh_len;		/* Length of full packet */
	uint32_t	klh_argoff;		/* Offset of argument */
	uint32_t	klh_privoff;		/* Offset of privilege set */
} klpd_head_t;

#define	KLH_PRIVSET(kh)	((priv_set_t *)(((kh)->klh_privoff == 0 ? NULL : \
			(char *)(kh) + (kh)->klh_privoff)))
#define	KLH_ARG(kh)	((void *)((kh)->klh_argoff != 0 ? \
			(char *)(kh) + (kh)->klh_argoff : NULL))

typedef struct klpd_arg {
	uint_t	kla_type;
	uint_t	kla_dlen;
	union {
		char	__cdata[1];
		int	__idata;
		uint_t	__uidata;
	} kla_data;
} klpd_arg_t;

#define	kla_str		kla_data.__cdata
#define	kla_int		kla_data.__idata
#define	kla_uint	kla_data.__uidata

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_KLPD_H */
