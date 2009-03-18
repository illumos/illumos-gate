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
/* Copyright (c) 1990 Mentat Inc. */

#ifndef	_INET_MI_H
#define	_INET_MI_H

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef _KERNEL

#include <sys/types.h>
#include <sys/vmem.h>
#include <sys/varargs.h>
#include <netinet/in.h>

#define	MI_MIN_DEV		INET_MIN_DEV /* minimum minor device number */
#define	MI_COPY_IN		1
#define	MI_COPY_OUT		2
#define	MI_COPY_DIRECTION(mp)	(*(int *)&(mp)->b_cont->b_next)
#define	MI_COPY_COUNT(mp)	(*(int *)&(mp)->b_cont->b_prev)
#define	MI_COPY_CASE(dir, cnt)	(((cnt)<<2)|dir)
#define	MI_COPY_STATE(mp)	MI_COPY_CASE(MI_COPY_DIRECTION(mp), \
					MI_COPY_COUNT(mp))

/*
 * Double linked list of type MI_O with a mi_head_t as the head.
 * Used for mi_open_comm etc.
 */
typedef struct mi_o_s {
	struct mi_o_s	*mi_o_next;
	struct mi_o_s	*mi_o_prev;
	boolean_t	mi_o_isdev;	/* Is this a device instance */
	dev_t		mi_o_dev;
} MI_O, *MI_OP;

/*
 * List head for MI_O doubly linked list.
 * The list contains unsorted driver, module and detached instances.
 *
 * Minor numbers are allocated from mh_arena which initially contains
 * [MI_MIN_DEV, mh_maxminor] numbers. When this arena is fully allocated, it is
 * extended to MAXMIN32.
 *
 * The module_dev is used to give almost unique numbers to module instances.
 * This is only needed for mi_strlog which uses the mi_o_dev field when
 * logging messages.
 */

typedef struct mi_head_s {
	struct mi_o_s	mh_o;	/* Contains head of doubly linked list */
	vmem_t *mh_arena;	/* Minor number arena */
	int	mh_module_dev;  /* Wraparound number for use when MODOPEN */
	minor_t mh_maxminor;	/* max minor number in the arena */
} mi_head_t;

extern void	*mi_alloc(size_t size, uint_t pri);
extern void	*mi_alloc_sleep(size_t size, uint_t pri);
extern void	mi_free(void *ptr);

extern int	mi_close_comm(void **mi_head, queue_t *q);
extern void	mi_close_free(IDP ptr);
extern void	mi_close_unlink(void **mi_head, IDP ptr);

extern void	mi_copyin(queue_t *q, MBLKP mp, char *uaddr, size_t len);
extern void	mi_copyin_n(queue_t *q, MBLKP mp, size_t offset, size_t len);
extern void	mi_copyout(queue_t *q, MBLKP mp);
extern MBLKP	mi_copyout_alloc(queue_t *q, MBLKP mp, char *uaddr, size_t len,
		    boolean_t free_on_error);
extern void	mi_copy_done(queue_t *q, MBLKP mp, int err);
extern int	mi_copy_state(queue_t *q, MBLKP mp, MBLKP *mpp);

/*PRINTFLIKE2*/
extern int	mi_mpprintf(MBLKP mp, char *fmt, ...)
	__KPRINTFLIKE(2);
/*PRINTFLIKE2*/
extern int	mi_mpprintf_nr(MBLKP mp, char *fmt, ...)
	__KPRINTFLIKE(2);
extern int	mi_mpprintf_putc(char *cookie, int ch);

extern IDP	mi_first_ptr(void **mi_head);
extern IDP	mi_first_dev_ptr(void **mi_head);
extern IDP	mi_next_ptr(void **mi_head, IDP ptr);
extern IDP	mi_next_dev_ptr(void **mi_head, IDP ptr);

extern IDP	mi_open_alloc(size_t size);
extern IDP	mi_open_alloc_sleep(size_t size);
extern int	mi_open_comm(void **mi_head, size_t size, queue_t *q,
		    dev_t *devp, int flag, int sflag, cred_t *credp);
extern int	mi_open_link(void **mi_head, IDP ptr, dev_t *devp, int flag,
		    int sflag, cred_t *credp);

extern uint8_t *mi_offset_param(mblk_t *mp, size_t offset, size_t len);
extern uint8_t *mi_offset_paramc(mblk_t *mp, size_t offset, size_t len);

/*PRINTFLIKE2*/
extern int	mi_sprintf(char *buf, char *fmt, ...)
	__KPRINTFLIKE(2);
extern int	mi_sprintf_putc(char *cookie, int ch);

extern int	mi_strcmp(const char *cp1, const char *cp2);
extern size_t	mi_strlen(const char *str);

/*PRINTFLIKE4*/
extern int	mi_strlog(queue_t *q, char level, ushort_t flags,
		    char *fmt, ...) __KPRINTFLIKE(4);
#pragma rarely_called(mi_strlog)

extern long	mi_strtol(const char *str, char **ptr, int base);

extern void	mi_timer(queue_t *q, MBLKP mp, clock_t tim);
extern MBLKP	mi_timer_alloc(size_t size);
extern void	mi_timer_free(MBLKP mp);
extern void	mi_timer_move(queue_t *, mblk_t *);
extern void	mi_timer_stop(mblk_t *);
extern boolean_t	mi_timer_valid(MBLKP mp);

extern MBLKP	mi_tpi_conn_con(MBLKP trailer_mp, char *src,
		    t_scalar_t src_length, char *opt, t_scalar_t opt_length);
extern MBLKP	mi_tpi_conn_ind(MBLKP trailer_mp, char *src,
		    t_scalar_t src_length, char *opt, t_scalar_t opt_length,
		    t_scalar_t seqnum);
extern MBLKP	mi_tpi_extconn_ind(MBLKP trailer_mp, char *src,
		    t_scalar_t src_length, char *opt, t_scalar_t opt_length,
		    char *dst, t_scalar_t dst_length, t_scalar_t seqnum);
extern MBLKP	mi_tpi_discon_ind(MBLKP trailer_mp, t_scalar_t reason,
		    t_scalar_t seqnum);
extern MBLKP	mi_tpi_err_ack_alloc(MBLKP mp, t_scalar_t tlierr, int unixerr);
extern MBLKP	mi_tpi_ok_ack_alloc(MBLKP mp);
extern MBLKP	mi_tpi_ok_ack_alloc_extra(MBLKP mp, int extra);
extern MBLKP	mi_tpi_ordrel_ind(void);
extern MBLKP	mi_tpi_uderror_ind(char *dest, t_scalar_t dest_length,
		    char *opt, t_scalar_t opt_length, t_scalar_t error);

extern IDP	mi_zalloc(size_t size);
extern IDP	mi_zalloc_sleep(size_t size);

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _INET_MI_H */
