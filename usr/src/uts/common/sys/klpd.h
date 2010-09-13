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
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef	_SYS_KLPD_H
#define	_SYS_KLPD_H

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
void klpd_freelist(struct klpd_reg **);
void klpd_rele(struct klpd_reg *);
int klpd_call(const cred_t *, const priv_set_t *, va_list);
void crklpd_hold(struct credklpd *);
void crklpd_rele(struct credklpd *);
int pfexec_reg(int);
int pfexec_unreg(int);
int pfexec_call(const cred_t *, struct pathname *, cred_t **, boolean_t *);
int get_forced_privs(const cred_t *, const char *, priv_set_t *);
int check_user_privs(const cred_t *, const priv_set_t *);

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

#define	PFEXEC_ARG_VERS			0x1
#define	PFEXEC_EXEC_ATTRS		0x1	/* pfexec_reply_t */
#define	PFEXEC_FORCED_PRIVS		0x2	/* priv_set_t */
#define	PFEXEC_USER_PRIVS		0x3	/* uint32_t */

#define	PFEXEC_ARG_SIZE(bufsize)	\
	(offsetof(pfexec_arg_t, pfa_data) + (bufsize))

typedef struct pfexec_arg {
	uint_t	pfa_vers;		/* Caller version */
	uint_t	pfa_call;		/* Call type */
	uint_t	pfa_len;		/* Length of data */
	uid_t	pfa_uid;		/* Real uid of subject */
	union {
		char		__pfa_path[1];
		uint32_t	__pfa_buf[1];
	} pfa_data;
} pfexec_arg_t;

#define	pfa_path	pfa_data.__pfa_path
#define	pfa_buf		pfa_data.__pfa_buf

#define	PFEXEC_NOTSET		((uid_t)-1)

typedef struct pfexec_reply {
	uint_t		pfr_vers;
	uint_t		pfr_len;
	uid_t		pfr_ruid, pfr_euid;
	gid_t		pfr_rgid, pfr_egid;
	boolean_t	pfr_setcred;
	boolean_t	pfr_scrubenv;
	boolean_t	pfr_clearflag;
	boolean_t	pfr_allowed;
	uint_t		pfr_ioff;
	uint_t		pfr_loff;
} pfexec_reply_t;

#define	PFEXEC_REPLY_IPRIV(pfr)	\
	((pfr)->pfr_ioff ? (priv_set_t *)((char *)(pfr) + (pfr)->pfr_ioff) \
	:  (priv_set_t *)0)
#define	PFEXEC_REPLY_LPRIV(pfr)	\
	((pfr)->pfr_loff ? (priv_set_t *)((char *)(pfr) + (pfr)->pfr_loff) \
	:  (priv_set_t *)0)

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_KLPD_H */
