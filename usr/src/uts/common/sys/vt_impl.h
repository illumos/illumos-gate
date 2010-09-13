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

#ifndef _SYS_VT_IMPL_H
#define	_SYS_VT_IMPL_H

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <sys/stream.h>
#include <sys/vt.h>
#include <sys/kd.h>
#include <sys/tem.h>
#include <sys/tty.h>
#include <sys/cred.h>
#include <sys/list.h>
#include <sys/avl.h>
#include <sys/note.h>

#define	WCS_INIT	0x00000001	/* tty is init */
#define	WCS_ISOPEN	0x00000002	/* open is complete */
#define	WCS_STOPPED	0x00000004	/* output is stopped */
#define	WCS_DELAY	0x00000008	/* waiting for delay to finish */
#define	WCS_BUSY	0x00000010	/* waiting for transmission to finish */

typedef struct vc_waitactive_msg {
	list_node_t	wa_list_node;
	int	wa_msg_minor;		/* minor number from which msg comes */
	int	wa_wait_minor;		/* which node we are waiting for */
	mblk_t *wa_mp;
} vc_waitactive_msg_t;

/* virtual console soft state associated with each vt */
typedef struct vc_state {
	minor_t	vc_minor;
	avl_node_t vc_avl_node;
	uchar_t	vc_switch_mode;		/* VT_AUTO or VT_PROCESS */
	char	vc_waitv;
	int	vc_relsig;
	int	vc_acqsig;
	pid_t	vc_pid;
	minor_t	vc_switchto;
	int	vc_flags;

	int	vc_dispnum;
	int	vc_login;

	tem_vt_state_t vc_tem;		/* Terminal emulator state */
	tty_common_t vc_ttycommon;	/* data common to all tty drivers */
	bufcall_id_t vc_bufcallid;	/* id returned by qbufcall */
	timeout_id_t vc_timeoutid;	/* id returned by qtimeout */

	queue_t	*vc_wq;			/* write queue */

#ifdef _HAVE_TEM_FIRMWARE
	int	vc_pendc;		/* pending output character */
#endif /* _HAVE_TEM_FIRMWARE */

	/*
	 * vc_state_lock is currently only used to protect vc_flags,
	 * more precisely, the state change of vc_state_t.
	 * The existence of this lock is because wc_modechg_cb().
	 * wc_modechg_cb() is a callback function which may result in
	 * multiple threads accessing vc_flags regardless the STREAMS
	 * periemters of wc module.
	 * Since wc_modechg_cb() only conducts read access to vc_flags,
	 * we only need to hold this lock when writing to vc_flags in
	 * wc module (except wc_modechg_cb()).
	 * See locking policy in wscons.c for more info.
	 */
	kmutex_t vc_state_lock;
} vc_state_t;
_NOTE(MUTEX_PROTECTS_DATA(vc_state_t::vc_state_lock, vc_state_t::vc_flags))

#define	VC_DEFAULT_COUNT	16

/* Invalid VT minor number */
#define	VT_MINOR_INVALID	((minor_t)-1)
/* Argument to vt_minor2vc to get the softstate of the active VT */
#define	VT_ACTIVE		VT_MINOR_INVALID

/*
 * VC_INSTANCES_COUNT should be regarded as reading access to vc_avl_root
 */
#define	VC_INSTANCES_COUNT	(avl_numnodes(&vc_avl_root))

void vt_ioctl(queue_t *q, mblk_t *mp);
void vt_miocdata(queue_t *qp, mblk_t *mp);
void vt_clean(queue_t *q, vc_state_t *pvc);
void vt_close(queue_t *q, vc_state_t *pvc, cred_t *crp);
int vt_open(minor_t minor, queue_t *rq, cred_t *crp);
int vt_check_hotkeys(mblk_t *mp);
vc_state_t *vt_minor2vc(minor_t);

extern dev_info_t *wc_dip;
extern avl_tree_t vc_avl_root;
extern minor_t	vc_active_console;
extern minor_t	vc_cons_user;
extern kmutex_t vc_lock;
extern minor_t vc_last_console;

major_t vt_wc_attached(void);
void vt_getactive(char *, int);
void vt_getconsuser(char *, int);
boolean_t vt_minor_valid(minor_t minor);
void vt_resize(uint_t);
void vt_attach(void);
void vt_init(void);

#ifdef __cplusplus
}
#endif

#endif /* _SYS_VT_IMPL_H */
