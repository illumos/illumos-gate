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

#include <sys/types.h>
#include <inet/common.h>	/* for various inet/mi.h and inet/nd.h needs */
#include <sys/stream.h>
#include <sys/stropts.h>
#include <sys/strsun.h>
#include <sys/sysmacros.h>
#include <inet/nd.h>
#include <inet/mi.h>
#define	_SUN_TPI_VERSION 2
#include <sys/tihdr.h>
#include <sys/timod.h>
#include <sys/vtrace.h>
#include <sys/kmem.h>
#include <sys/mkdev.h>
#include <sys/strlog.h>
#include <sys/ddi.h>
#include <sys/suntpi.h>
#include <sys/cmn_err.h>
#include <sys/debug.h>
#include <sys/kobj.h>
#include <sys/stropts.h>
#include <sys/strsubr.h>
#include <inet/proto_set.h>

#define	ISDIGIT(ch)	((ch) >= '0' && (ch) <= '9')
#define	ISUPPER(ch)	((ch) >= 'A' && (ch) <= 'Z')
#define	tolower(ch)	('a' + ((ch) - 'A'))

#define	MI_IS_TRANSPARENT(mp)	(mp->b_cont && \
	(mp->b_cont->b_rptr != mp->b_cont->b_wptr))

/*
 * NOTE: Whenever anything is allocated by mi_alloc or mi_alloc_sleep (below),
 * the size of the requested allocation is increased by one word.  This extra
 * word is used to store the size of the object being allocated, and is located
 * at the beginning of the allocated block.  The pointer returned to the caller
 * is a pointer to the *second* word in the newly-allocated block.  The IP
 * module of mdb is aware of this, and will need to be changed if this
 * allocation strategy is changed.
 */

typedef	struct	stroptions *STROPTP;
typedef union T_primitives *TPRIMP;

/* Timer block states. */
#define	TB_RUNNING	1
#define	TB_IDLE		2
/*
 * Could not stop/free before putq
 */
#define	TB_RESCHED	3	/* mtb_time_left contains tick count */
#define	TB_CANCELLED	4
#define	TB_TO_BE_FREED	5

typedef struct mtb_s {
	int		mtb_state;
	timeout_id_t	mtb_tid;
	queue_t		*mtb_q;
	MBLKP		mtb_mp;
	clock_t		mtb_time_left;
} MTB, *MTBP;

static int mi_timer_fire(MTBP);
static int mi_iprintf(char *, va_list, pfi_t, char *);
static void mi_tpi_addr_and_opt(MBLKP, char *, t_scalar_t, char *, t_scalar_t);
static MBLKP mi_tpi_trailer_alloc(MBLKP, size_t, t_scalar_t);

/* ARGSUSED1 */
void *
mi_alloc(size_t size, uint_t pri)
{
	size_t *ptr;

	size += sizeof (size);
	if (ptr = kmem_alloc(size, KM_NOSLEEP)) {
		*ptr = size;
		return (ptr + 1);
	}
	return (NULL);
}

/* ARGSUSED1 */
void *
mi_alloc_sleep(size_t size, uint_t pri)
{
	size_t *ptr;

	size += sizeof (size);
	ptr = kmem_alloc(size, KM_SLEEP);
	*ptr = size;
	return (ptr + 1);
}

int
mi_close_comm(void **mi_headp, queue_t *q)
{
	IDP ptr;

	ptr = q->q_ptr;
	mi_close_unlink(mi_headp, ptr);
	mi_close_free(ptr);
	q->q_ptr = WR(q)->q_ptr = NULL;
	return (0);
}

void
mi_close_unlink(void **mi_headp, IDP ptr)
{
	mi_head_t	*mi_head = *(mi_head_t **)mi_headp;
	MI_OP		mi_o;
	dev_t		dev;

	mi_o = (MI_OP)ptr;
	if (!mi_o)
		return;
	mi_o--;

	if (mi_o->mi_o_next == NULL) {
		/* Not in list */
		ASSERT(mi_o->mi_o_prev == NULL);
		return;
	}

	/* Free minor number */
	dev = mi_o->mi_o_dev;
	if ((dev != OPENFAIL) && (dev != 0) && (dev <= MAXMIN))
		inet_minor_free(mi_head->mh_arena, dev);

	/* Unlink from list */
	ASSERT(mi_o->mi_o_next != NULL);
	ASSERT(mi_o->mi_o_prev != NULL);
	ASSERT(mi_o->mi_o_next->mi_o_prev == mi_o);
	ASSERT(mi_o->mi_o_prev->mi_o_next == mi_o);

	mi_o->mi_o_next->mi_o_prev = mi_o->mi_o_prev;
	mi_o->mi_o_prev->mi_o_next = mi_o->mi_o_next;
	mi_o->mi_o_next = mi_o->mi_o_prev = NULL;

	mi_o->mi_o_dev = (dev_t)OPENFAIL;

	/* If list now empty free the list head */
	if (mi_head->mh_o.mi_o_next == &mi_head->mh_o) {
		ASSERT(mi_head->mh_o.mi_o_prev == &mi_head->mh_o);
		if (mi_head->mh_arena != NULL)
			inet_minor_destroy(mi_head->mh_arena);
		mi_free((IDP)mi_head);
		*mi_headp = NULL;
	}
}

void
mi_close_free(IDP ptr)
{
	MI_OP		mi_o;

	mi_o = (MI_OP)ptr;
	if (!mi_o)
		return;
	mi_o--;

	ASSERT(mi_o->mi_o_next == NULL && mi_o->mi_o_prev == NULL);
	mi_free((IDP)mi_o);
}

/*
 * mi_copyin - takes care of transparent or non-transparent ioctl for the
 * calling function so that they have to deal with just M_IOCDATA type
 * and not worry about M_COPYIN.
 *
 * mi_copyin checks to see if the ioctl is transparent or non transparent.
 * In case of a non_transparent ioctl, it packs the data into a M_IOCDATA
 * message and puts it back onto the current queue for further processing.
 * In case of transparent ioctl, it sends a M_COPYIN message up to the
 * streamhead so that a M_IOCDATA with the information comes back down.
 */
void
mi_copyin(queue_t *q, MBLKP mp, char *uaddr, size_t len)
{
	struct 	iocblk *iocp = (struct iocblk *)mp->b_rptr;
	struct 	copyreq *cq = (struct copyreq *)mp->b_rptr;
	struct 	copyresp *cp = (struct copyresp *)mp->b_rptr;
	int    	err;
	MBLKP	mp1;

	ASSERT(mp->b_datap->db_type == M_IOCTL && !uaddr);

	/* A transparent ioctl. Send a M_COPYIN message to the streamhead. */
	if (iocp->ioc_count == TRANSPARENT) {
		MI_COPY_COUNT(mp) = 1;
		MI_COPY_DIRECTION(mp) = MI_COPY_IN;
		cq->cq_private = mp->b_cont;
		cq->cq_size = len;
		cq->cq_flag = 0;
		bcopy(mp->b_cont->b_rptr, &cq->cq_addr, sizeof (cq->cq_addr));
		mp->b_cont = NULL;
		mp->b_datap->db_type = M_COPYIN;
		qreply(q, mp);
		return;
	}

	/*
	 * A non-transparent ioctl. Need to convert into M_IOCDATA message.
	 *
	 * We allocate a 0 byte message block and put its address in
	 * cp_private. It also makes the b_prev field = 1 and b_next
	 * field = MI_COPY_IN for this 0 byte block. This is done to
	 * maintain compatibility with old code in mi_copy_state
	 * (which removes the empty block).
	 */
	err = miocpullup(mp, len);
	if (err != 0)
		goto err_ret;

	mp1 = allocb(0, BPRI_MED);
	if (mp1 == NULL) {
		err = ENOMEM;
		goto err_ret;
	}

	/*
	 * Temporarily insert mp1 between the M_IOCTL and M_DATA blocks so
	 * that we can use the MI_COPY_COUNT & MI_COPY_DIRECTION macros.
	 */
	mp1->b_cont = mp->b_cont;
	mp->b_cont = mp1;
	MI_COPY_COUNT(mp) = 1;
	MI_COPY_DIRECTION(mp) = MI_COPY_IN;
	mp->b_cont = mp1->b_cont;
	mp1->b_cont = NULL;

	/*
	 * Leave a pointer to the 0 byte block in cp_private field for
	 * future use by the mi_copy_* routines.
	 */
	mp->b_datap->db_type = M_IOCDATA;
	cp->cp_private = mp1;
	cp->cp_rval = NULL;
	put(q, mp);
	return;

err_ret:
	iocp->ioc_error = err;
	iocp->ioc_count = 0;
	if (mp->b_cont) {
		freemsg(mp->b_cont);
		mp->b_cont = NULL;
	}
	mp->b_datap->db_type = M_IOCACK;
	qreply(q, mp);
}

/*
 * Allows transparent IOCTLs to have multiple copyins.  This is needed
 * for some variable-length structures, where the total size is only known
 * after the first part is copied in. Rather than setting MI_COPY_COUNT to
 * 1, as in mi_coypin(), it is simply incremented here.  This value can
 * then be checked in the returned IOCBLK.
 *
 * As this deals with copyins that follow the initial copyin, the byte
 * offset into the user buffer from which copying should begin must be
 * passed in in the offset parameter.
 *
 * Unlike mi_coypin(), this function expects to be passed an mblk chain
 * headed by an M_IOCBLK, as that's the chain that will be in use for
 * copies after the first one (copies where n != 1).
 */
void
mi_copyin_n(queue_t *q, MBLKP mp, size_t offset, size_t len)
{
	struct 	copyreq *cq = (struct copyreq *)mp->b_rptr;

	ASSERT(mp->b_datap->db_type == M_IOCDATA);

	MI_COPY_COUNT(mp)++;
	MI_COPY_DIRECTION(mp) = MI_COPY_IN;
	cq->cq_private = mp->b_cont;
	cq->cq_size = len;
	cq->cq_flag = 0;
	bcopy(mp->b_cont->b_rptr, &cq->cq_addr, sizeof (cq->cq_addr));
	cq->cq_addr += offset;
	mp->b_cont = NULL;
	mp->b_datap->db_type = M_COPYIN;
	qreply(q, mp);
}

void
mi_copyout(queue_t *q, MBLKP mp)
{
	struct iocblk *iocp = (struct iocblk *)mp->b_rptr;
	struct copyreq *cq = (struct copyreq *)iocp;
	struct copyresp *cp = (struct copyresp *)cq;
	MBLKP	mp1;
	MBLKP	mp2;

	if (mp->b_datap->db_type != M_IOCDATA || !mp->b_cont) {
		mi_copy_done(q, mp, EPROTO);
		return;
	}
	/* Check completion of previous copyout operation. */
	mp1 = mp->b_cont;
	if ((int)(uintptr_t)cp->cp_rval || !mp1->b_cont) {
		mi_copy_done(q, mp, (int)(uintptr_t)cp->cp_rval);
		return;
	}
	if (!mp1->b_cont->b_cont && !MI_IS_TRANSPARENT(mp)) {
		mp1->b_next = NULL;
		mp1->b_prev = NULL;
		mp->b_cont = mp1->b_cont;
		freeb(mp1);
		mp1 = mp->b_cont;
		mp1->b_next = NULL;
		mp1->b_prev = NULL;
		iocp->ioc_count = mp1->b_wptr - mp1->b_rptr;
		iocp->ioc_error = 0;
		mp->b_datap->db_type = M_IOCACK;
		qreply(q, mp);
		return;
	}
	if (MI_COPY_DIRECTION(mp) == MI_COPY_IN) {
		/* Set up for first copyout. */
		MI_COPY_DIRECTION(mp) = MI_COPY_OUT;
		MI_COPY_COUNT(mp) = 1;
	} else {
		++MI_COPY_COUNT(mp);
	}
	cq->cq_private = mp1;
	/* Find message preceding last. */
	for (mp2 = mp1; mp2->b_cont->b_cont; mp2 = mp2->b_cont)
		;
	if (mp2 == mp1)
		bcopy((char *)mp1->b_rptr, (char *)&cq->cq_addr,
		    sizeof (cq->cq_addr));
	else
		cq->cq_addr = (char *)mp2->b_cont->b_next;
	mp1 = mp2->b_cont;
	mp->b_datap->db_type = M_COPYOUT;
	mp->b_cont = mp1;
	mp2->b_cont = NULL;
	mp1->b_next = NULL;
	cq->cq_size = mp1->b_wptr - mp1->b_rptr;
	cq->cq_flag = 0;
	qreply(q, mp);
}

MBLKP
mi_copyout_alloc(queue_t *q, MBLKP mp, char *uaddr, size_t len,
    boolean_t free_on_error)
{
	struct iocblk *iocp = (struct iocblk *)mp->b_rptr;
	MBLKP	mp1;

	if (mp->b_datap->db_type == M_IOCTL) {
		if (iocp->ioc_count != TRANSPARENT) {
			mp1 = allocb(0, BPRI_MED);
			if (mp1 == NULL) {
				if (free_on_error) {
					iocp->ioc_error = ENOMEM;
					iocp->ioc_count = 0;
					freemsg(mp->b_cont);
					mp->b_cont = NULL;
					mp->b_datap->db_type = M_IOCACK;
					qreply(q, mp);
				}
				return (NULL);
			}
			mp1->b_cont = mp->b_cont;
			mp->b_cont = mp1;
		}
		MI_COPY_COUNT(mp) = 0;
		MI_COPY_DIRECTION(mp) = MI_COPY_OUT;
		/* Make sure it looks clean to mi_copyout. */
		mp->b_datap->db_type = M_IOCDATA;
		((struct copyresp *)iocp)->cp_rval = NULL;
	}
	mp1 = allocb(len, BPRI_MED);
	if (mp1 == NULL) {
		if (free_on_error)
			mi_copy_done(q, mp, ENOMEM);
		return (NULL);
	}
	linkb(mp, mp1);
	mp1->b_next = (MBLKP)uaddr;
	return (mp1);
}

void
mi_copy_done(queue_t *q, MBLKP mp, int err)
{
	struct iocblk *iocp;
	MBLKP	mp1;

	if (!mp)
		return;
	if (!q || (mp->b_wptr - mp->b_rptr) < sizeof (struct iocblk)) {
		freemsg(mp);
		return;
	}
	iocp = (struct iocblk *)mp->b_rptr;
	mp->b_datap->db_type = M_IOCACK;
	iocp->ioc_error = err;

	iocp->ioc_count = 0;
	if ((mp1 = mp->b_cont) != NULL) {
		for (; mp1; mp1 = mp1->b_cont) {
			mp1->b_prev = NULL;
			mp1->b_next = NULL;
		}
		freemsg(mp->b_cont);
		mp->b_cont = NULL;
	}
	qreply(q, mp);
}

int
mi_copy_state(queue_t *q, MBLKP mp, MBLKP *mpp)
{
	struct iocblk *iocp = (struct iocblk *)mp->b_rptr;
	struct copyresp *cp = (struct copyresp *)iocp;
	MBLKP	mp1;

	mp1 = mp->b_cont;
	mp->b_cont = cp->cp_private;
	if (mp1) {
		if (mp1->b_cont && !pullupmsg(mp1, -1)) {
			mi_copy_done(q, mp, ENOMEM);
			return (-1);
		}
		linkb(mp->b_cont, mp1);
	}
	if ((int)(uintptr_t)cp->cp_rval) {
		mi_copy_done(q, mp, (int)(uintptr_t)cp->cp_rval);
		return (-1);
	}
	if (mpp && MI_COPY_DIRECTION(mp) == MI_COPY_IN)
		*mpp = mp1;
	return (MI_COPY_STATE(mp));
}

void
mi_free(void *ptr)
{
	size_t	size;

	if (!ptr)
		return;
	if ((size = ((size_t *)ptr)[-1]) <= 0)
		cmn_err(CE_PANIC, "mi_free");

	kmem_free((void *) ((size_t *)ptr - 1), size);
}

static int
mi_iprintf(char *fmt, va_list ap, pfi_t putc_func, char *cookie)
{
	int	base;
	char	buf[(sizeof (long) * 3) + 1];
	static char	hex_val[] = "0123456789abcdef";
	int	ch;
	int	count;
	char	*cp1;
	int	digits;
	char	*fcp;
	boolean_t	is_long;
	ulong_t	uval;
	long	val;
	boolean_t	zero_filled;

	if (!fmt)
		return (-1);
	count = 0;
	while (*fmt) {
		if (*fmt != '%' || *++fmt == '%') {
			count += (*putc_func)(cookie, *fmt++);
			continue;
		}
		if (*fmt == '0') {
			zero_filled = B_TRUE;
			fmt++;
			if (!*fmt)
				break;
		} else
			zero_filled = B_FALSE;
		base = 0;
		for (digits = 0; ISDIGIT(*fmt); fmt++) {
			digits *= 10;
			digits += (*fmt - '0');
		}
		if (!*fmt)
			break;
		is_long = B_FALSE;
		if (*fmt == 'l') {
			is_long = B_TRUE;
			fmt++;
		}
		if (!*fmt)
			break;
		ch = *fmt++;
		if (ISUPPER(ch)) {
			ch = tolower(ch);
			is_long = B_TRUE;
		}
		switch (ch) {
		case 'c':
			count += (*putc_func)(cookie, va_arg(ap, int *));
			continue;
		case 'd':
			base = 10;
			break;
		case 'm':	/* Print out memory, 2 hex chars per byte */
			if (is_long)
				fcp = va_arg(ap, char *);
			else {
				if ((cp1 = va_arg(ap, char *)) != NULL)
					fcp = (char *)cp1;
				else
					fcp = NULL;
			}
			if (!fcp) {
				for (fcp = (char *)"(NULL)"; *fcp; fcp++)
					count += (*putc_func)(cookie, *fcp);
			} else {
				while (digits--) {
					int u1 = *fcp++ & 0xFF;
					count += (*putc_func)(cookie,
					    hex_val[(u1>>4)& 0xF]);
					count += (*putc_func)(cookie,
					    hex_val[u1& 0xF]);
				}
			}
			continue;
		case 'o':
			base = 8;
			break;
		case 'p':
			is_long = B_TRUE;
			/* FALLTHRU */
		case 'x':
			base = 16;
			break;
		case 's':
			if (is_long)
				fcp = va_arg(ap, char *);
			else {
				if ((cp1 = va_arg(ap, char *)) != NULL)
					fcp = (char *)cp1;
				else
					fcp = NULL;
			}
			if (!fcp)
				fcp = (char *)"(NULL)";
			while (*fcp) {
				count += (*putc_func)(cookie, *fcp++);
				if (digits && --digits == 0)
					break;
			}
			while (digits > 0) {
				count += (*putc_func)(cookie, ' ');
				digits--;
			}
			continue;
		case 'u':
			base = 10;
			break;
		default:
			return (count);
		}
		if (is_long)
			val = va_arg(ap, long);
		else
			val = va_arg(ap, int);
		if (base == 10 && ch != 'u') {
			if (val < 0) {
				count += (*putc_func)(cookie, '-');
				val = -val;
			}
			uval = val;
		} else {
			if (is_long)
				uval = val;
			else
				uval = (uint_t)val;
		}
		/* Hand overload/restore the register variable 'fmt' */
		cp1 = fmt;
		fmt = A_END(buf);
		*--fmt = '\0';
		do {
			if (fmt > buf)
				*--fmt = hex_val[uval % base];
			if (digits && --digits == 0)
				break;
		} while (uval /= base);
		if (zero_filled) {
			while (digits > 0 && fmt > buf) {
				*--fmt = '0';
				digits--;
			}
		}
		while (*fmt)
			count += (*putc_func)(cookie, *fmt++);
		fmt = cp1;
	}
	return (count);
}

/* PRINTFLIKE2 */
int
mi_mpprintf(MBLKP mp, char *fmt, ...)
{
	va_list	ap;
	int	count = -1;

	va_start(ap, fmt);
	if (mp) {
		count = mi_iprintf(fmt, ap, (pfi_t)mi_mpprintf_putc,
		    (char *)mp);
		if (count != -1)
			(void) mi_mpprintf_putc((char *)mp, '\0');
	}
	va_end(ap);
	return (count);
}

/* PRINTFLIKE2 */
int
mi_mpprintf_nr(MBLKP mp, char *fmt, ...)
{
	va_list	ap;
	int	count = -1;

	va_start(ap, fmt);
	if (mp) {
		(void) adjmsg(mp, -1);
		count = mi_iprintf(fmt, ap, (pfi_t)mi_mpprintf_putc,
		    (char *)mp);
		if (count != -1)
			(void) mi_mpprintf_putc((char *)mp, '\0');
	}
	va_end(ap);
	return (count);
}

int
mi_mpprintf_putc(char *cookie, int ch)
{
	MBLKP	mp = (MBLKP)cookie;

	while (mp->b_cont)
		mp = mp->b_cont;
	if (mp->b_wptr >= mp->b_datap->db_lim) {
		mp->b_cont = allocb(1024, BPRI_HI);
		mp = mp->b_cont;
		if (!mp)
			return (0);
	}
	*mp->b_wptr++ = (unsigned char)ch;
	return (1);
}

IDP
mi_first_ptr(void **mi_headp)
{
	mi_head_t *mi_head = *(mi_head_t **)mi_headp;
	MI_OP	mi_op;

	mi_op = mi_head->mh_o.mi_o_next;
	if (mi_op && mi_op != &mi_head->mh_o)
		return ((IDP)&mi_op[1]);
	return (NULL);
}

/*
 * Clients can choose to have both module instances and device instances
 * in the same list. Return the first device instance in the list.
 */
IDP
mi_first_dev_ptr(void **mi_headp)
{
	mi_head_t *mi_head = *(mi_head_t **)mi_headp;
	MI_OP	mi_op;

	mi_op = mi_head->mh_o.mi_o_next;
	while ((mi_op != NULL) && (mi_op != &mi_head->mh_o)) {
		if (mi_op->mi_o_isdev)
			return ((IDP)&mi_op[1]);
		mi_op = mi_op->mi_o_next;
	}
	return (NULL);
}

IDP
mi_next_ptr(void **mi_headp, IDP ptr)
{
	mi_head_t *mi_head = *(mi_head_t **)mi_headp;
	MI_OP	mi_op = ((MI_OP)ptr) - 1;

	if ((mi_op = mi_op->mi_o_next) != NULL && mi_op != &mi_head->mh_o)
		return ((IDP)&mi_op[1]);
	return (NULL);
}

/*
 * Clients can choose to have both module instances and device instances
 * in the same list. Return the next device instance in the list.
 */
IDP
mi_next_dev_ptr(void **mi_headp, IDP ptr)
{
	mi_head_t *mi_head = *(mi_head_t **)mi_headp;
	MI_OP	mi_op = ((MI_OP)ptr) - 1;

	mi_op = mi_op->mi_o_next;
	while ((mi_op != NULL) && (mi_op != &mi_head->mh_o)) {
		if (mi_op->mi_o_isdev)
			return ((IDP)&mi_op[1]);
		mi_op = mi_op->mi_o_next;
	}
	return (NULL);
}

/*
 * Self clone the device
 * XXX - should we still support clone device
 */
/* ARGSUSED4 */
int
mi_open_comm(void **mi_headp, size_t size, queue_t *q, dev_t *devp,
    int flag, int sflag, cred_t *credp)
{
	int error;
	IDP ptr;

	if (q->q_ptr != NULL)
		return (0);

	ptr = mi_open_alloc_sleep(size);
	q->q_ptr = WR(q)->q_ptr = ptr;
	error = mi_open_link(mi_headp, ptr, devp, flag, sflag, credp);
	if (error != 0) {
		q->q_ptr = WR(q)->q_ptr = NULL;
		mi_close_free(ptr);
	}
	return (error);
}

IDP
mi_open_alloc_sleep(size_t size)
{
	MI_OP		mi_o;

	if (size > (UINT_MAX - sizeof (MI_O)))
		return (NULL);

	mi_o = (MI_OP)mi_zalloc_sleep(size + sizeof (MI_O));
	mi_o++;
	return ((IDP)mi_o);
}

IDP
mi_open_alloc(size_t size)
{
	MI_OP		mi_o;

	if (size > (UINT_MAX - sizeof (MI_O)))
		return (NULL);

	if ((mi_o = (MI_OP)mi_zalloc(size + sizeof (MI_O))) == NULL)
		return (NULL);
	mi_o++;
	return ((IDP)mi_o);
}

/*
 * MODOPEN means just link in without respect of mi_o_dev.
 * A NULL devp can be used to create a detached instance
 * Otherwise self-clone the device.
 */
/* ARGSUSED3 */
int
mi_open_link(void **mi_headp, IDP ptr, dev_t *devp, int flag, int sflag,
    cred_t *credp)
{
	mi_head_t	*mi_head = *(mi_head_t **)mi_headp;
	MI_OP		insert;
	MI_OP		mi_o;
	dev_t		dev;

	if (mi_head == NULL) {
		char arena_name[50];
		char *head_name;
		ulong_t offset;

		head_name = kobj_getsymname((uintptr_t)mi_headp, &offset);
		if (head_name != NULL && offset == 0) {
			(void) sprintf(arena_name, "%s_", head_name);
		} else {
			(void) sprintf(arena_name, "Hex0x%p_",
			    (void *)mi_headp);
		}
		(void) sprintf(strchr(arena_name, '_') + 1, "minor");
		mi_head = (mi_head_t *)mi_zalloc_sleep(sizeof (mi_head_t));
		*mi_headp = (void *)mi_head;
		/* Setup doubly linked list */
		mi_head->mh_o.mi_o_next = &mi_head->mh_o;
		mi_head->mh_o.mi_o_prev = &mi_head->mh_o;
		mi_head->mh_o.mi_o_dev = 0;	/* For asserts only */
		mi_head->mh_arena = (vmem_t *)inet_minor_create(arena_name,
		    INET_MIN_DEV, MAXMIN, KM_SLEEP);
	}
	ASSERT(ptr != NULL);
	mi_o = (MI_OP)ptr;
	mi_o--;

	if (sflag == MODOPEN) {
		devp = NULL;
		/*
		 * Set device number to MAXMIN + incrementing number.
		 */
		dev = MAXMIN + ++mi_head->mh_module_dev;
		/* check for wraparound */
		if (dev <= MAXMIN) {
			dev = MAXMIN + 1;
			mi_head->mh_module_dev = 1;
		}
	} else if (devp == NULL) {
		/* Detached open */
		dev = (dev_t)OPENFAIL;
	} else if ((dev = inet_minor_alloc(mi_head->mh_arena)) == 0) {
		return (EBUSY);
	}

	mi_o->mi_o_dev = dev;
	insert = (&mi_head->mh_o);
	mi_o->mi_o_next = insert;
	insert->mi_o_prev->mi_o_next = mi_o;
	mi_o->mi_o_prev = insert->mi_o_prev;
	insert->mi_o_prev = mi_o;

	if (sflag == MODOPEN)
		mi_o->mi_o_isdev = B_FALSE;
	else
		mi_o->mi_o_isdev = B_TRUE;

	if (devp)
		*devp = makedevice(getemajor(*devp), (minor_t)dev);
	return (0);
}

uint8_t *
mi_offset_param(mblk_t *mp, size_t offset, size_t len)
{
	size_t	msg_len;

	if (!mp)
		return (NULL);
	msg_len = mp->b_wptr - mp->b_rptr;
	if (msg_len == 0 || offset > msg_len || len > msg_len ||
	    (offset + len) > msg_len || len == 0)
		return (NULL);
	return (&mp->b_rptr[offset]);
}

uint8_t *
mi_offset_paramc(mblk_t *mp, size_t offset, size_t len)
{
	uint8_t	*param;

	for (; mp; mp = mp->b_cont) {
		int type = mp->b_datap->db_type;
		if (datamsg(type)) {
			if (param = mi_offset_param(mp, offset, len))
				return (param);
			if (offset < mp->b_wptr - mp->b_rptr)
				break;
			offset -= mp->b_wptr - mp->b_rptr;
		}
	}
	return (NULL);
}

int
mi_sprintf(char *buf, char *fmt, ...)
{
	va_list	ap;
	int	count = -1;
	va_start(ap, fmt);
	if (buf) {
		count = mi_iprintf(fmt, ap, (pfi_t)mi_sprintf_putc,
		    (char *)&buf);
		if (count != -1)
			(void) mi_sprintf_putc((char *)&buf, '\0');
	}
	va_end(ap);
	return (count);
}

/* Used to count without writing data */
/* ARGSUSED1 */
static int
mi_sprintf_noop(char *cookie, int ch)
{
	char	**cpp = (char **)cookie;

	(*cpp)++;
	return (1);
}

int
mi_sprintf_putc(char *cookie, int ch)
{
	char	**cpp = (char **)cookie;

	**cpp = (char)ch;
	(*cpp)++;
	return (1);
}

int
mi_strcmp(const char *cp1, const char *cp2)
{
	while (*cp1++ == *cp2++) {
		if (!cp2[-1])
			return (0);
	}
	return ((uint_t)cp2[-1]  & 0xFF) - ((uint_t)cp1[-1] & 0xFF);
}

size_t
mi_strlen(const char *str)
{
	const char *cp = str;

	while (*cp != '\0')
		cp++;
	return ((int)(cp - str));
}

int
mi_strlog(queue_t *q, char level, ushort_t flags, char *fmt, ...)
{
	va_list	ap;
	char	buf[200];
	char	*alloc_buf = buf;
	int	count = -1;
	char	*cp;
	short	mid;
	int	ret;
	short	sid;

	sid = 0;
	mid = 0;
	if (q != NULL) {
		mid = q->q_qinfo->qi_minfo->mi_idnum;
	}

	/* Find out how many bytes we need and allocate if necesary */
	va_start(ap, fmt);
	cp = buf;
	count = mi_iprintf(fmt, ap, mi_sprintf_noop, (char *)&cp);
	if (count > sizeof (buf) &&
	    !(alloc_buf = mi_alloc((uint_t)count + 2, BPRI_MED))) {
		va_end(ap);
		return (-1);
	}
	va_end(ap);

	va_start(ap, fmt);
	cp = alloc_buf;
	count = mi_iprintf(fmt, ap, mi_sprintf_putc, (char *)&cp);
	if (count != -1)
		(void) mi_sprintf_putc((char *)&cp, '\0');
	else
		alloc_buf[0] = '\0';
	va_end(ap);

	ret = strlog(mid, sid, level, flags, alloc_buf);
	if (alloc_buf != buf)
		mi_free(alloc_buf);
	return (ret);
}

long
mi_strtol(const char *str, char **ptr, int base)
{
	const char *cp;
	int	digits;
	long	value;
	boolean_t	is_negative;

	cp = str;
	while (*cp == ' ' || *cp == '\t' || *cp == '\n')
		cp++;
	is_negative = (*cp == '-');
	if (is_negative)
		cp++;
	if (base == 0) {
		base = 10;
		if (*cp == '0') {
			base = 8;
			cp++;
			if (*cp == 'x' || *cp == 'X') {
				base = 16;
				cp++;
			}
		}
	}
	value = 0;
	for (; *cp != '\0'; cp++) {
		if (*cp >= '0' && *cp <= '9')
			digits = *cp - '0';
		else if (*cp >= 'a' && *cp <= 'f')
			digits = *cp - 'a' + 10;
		else if (*cp >= 'A' && *cp <= 'F')
			digits = *cp - 'A' + 10;
		else
			break;
		if (digits >= base)
			break;
		value = (value * base) + digits;
	}
	/* Note: we cast away const here deliberately */
	if (ptr != NULL)
		*ptr = (char *)cp;
	if (is_negative)
		value = -value;
	return (value);
}

/*
 *		mi_timer mechanism.
 *
 * Each timer is represented by a timer mblk and a (streams) queue. When the
 * timer fires the timer mblk will be put on the associated streams queue
 * so that the streams module can process the timer even in its service
 * procedure.
 *
 * The interface consists of 4 entry points:
 *	mi_timer_alloc		- create a timer mblk
 *	mi_timer_free		- free a timer mblk
 *	mi_timer		- start, restart, stop, or move the
 *				  timer to a different queue
 *	mi_timer_valid		- called by streams module to verify that
 *				  the timer did indeed fire.
 */




/*
 * Start, restart, stop, or move the timer to a new queue.
 * If "tim" is -2 the timer is moved to a different queue.
 * If "tim" is -1 the timer is stopped.
 * Otherwise, the timer is stopped if it is already running, and
 * set to fire tim milliseconds from now.
 */

void
mi_timer(queue_t *q, MBLKP mp, clock_t tim)
{
	MTBP	mtb;
	int	state;

	ASSERT(tim >= -2);
	if (!q || !mp || (mp->b_rptr - mp->b_datap->db_base) != sizeof (MTB))
		return;
	mtb = (MTBP)mp->b_datap->db_base;
	ASSERT(mp->b_datap->db_type == M_PCSIG);
	if (tim >= 0) {
		mtb->mtb_q = q;
		state = mtb->mtb_state;
		tim = MSEC_TO_TICK(tim);
		if (state == TB_RUNNING) {
			if (untimeout(mtb->mtb_tid) < 0) {
				/* Message has already been putq */
				ASSERT(mtb->mtb_q->q_first == mp ||
				    mp->b_prev || mp->b_next);
				mtb->mtb_state = TB_RESCHED;
				mtb->mtb_time_left = tim;
				/* mi_timer_valid will start timer */
				return;
			}
		} else if (state != TB_IDLE) {
			ASSERT(state != TB_TO_BE_FREED);
			if (state == TB_CANCELLED) {
				ASSERT(mtb->mtb_q->q_first == mp ||
				    mp->b_prev || mp->b_next);
				mtb->mtb_state = TB_RESCHED;
				mtb->mtb_time_left = tim;
				/* mi_timer_valid will start timer */
				return;
			}
			if (state == TB_RESCHED) {
				ASSERT(mtb->mtb_q->q_first == mp ||
				    mp->b_prev || mp->b_next);
				mtb->mtb_time_left = tim;
				/* mi_timer_valid will start timer */
				return;
			}
		}
		mtb->mtb_state = TB_RUNNING;
		mtb->mtb_tid = timeout((pfv_t)mi_timer_fire, mtb, tim);
		return;
	}
	switch (tim) {
	case -1:
		mi_timer_stop(mp);
		break;
	case -2:
		mi_timer_move(q, mp);
		break;
	}
}

/*
 * Allocate an M_PCSIG timer message. The space between db_base and
 * b_rptr is used by the mi_timer mechanism, and after b_rptr there are
 * "size" bytes that the caller can use for its own purposes.
 *
 * Note that db_type has to be a priority message since otherwise
 * the putq will not cause the service procedure to run when
 * there is flow control.
 */
MBLKP
mi_timer_alloc(size_t size)
{
	MBLKP	mp;
	MTBP	mtb;

	if ((mp = allocb(size + sizeof (MTB), BPRI_HI)) != NULL) {
		mp->b_datap->db_type = M_PCSIG;
		mtb = (MTBP)mp->b_datap->db_base;
		mp->b_rptr = (uchar_t *)&mtb[1];
		mp->b_wptr = mp->b_rptr + size;
		mtb->mtb_state = TB_IDLE;
		mtb->mtb_mp = mp;
		mtb->mtb_q = NULL;
		return (mp);
	}
	return (NULL);
}

/*
 * timeout() callback function.
 * Put the message on the current queue.
 * If the timer is stopped or moved to a different queue after
 * it has fired then mi_timer() and mi_timer_valid() will clean
 * things up.
 */
static int
mi_timer_fire(MTBP mtb)
{
	ASSERT(mtb == (MTBP)mtb->mtb_mp->b_datap->db_base);
	ASSERT(mtb->mtb_mp->b_datap->db_type == M_PCSIG);
	return (putq(mtb->mtb_q, mtb->mtb_mp));
}

/*
 * Logically free a timer mblk (that might have a pending timeout().)
 * If the timer has fired and the mblk has been put on the queue then
 * mi_timer_valid will free the mblk.
 */

void
mi_timer_free(MBLKP mp)
{
	MTBP	mtb;
	int	state;

	if (!mp	|| (mp->b_rptr - mp->b_datap->db_base) != sizeof (MTB))
		return;
	mtb = (MTBP)mp->b_datap->db_base;
	state = mtb->mtb_state;
	if (state == TB_RUNNING) {
		if (untimeout(mtb->mtb_tid) < 0) {
			/* Message has already been putq */
			ASSERT(mtb->mtb_q->q_first == mp ||
			    mp->b_prev || mp->b_next);
			mtb->mtb_state = TB_TO_BE_FREED;
			/* mi_timer_valid will free the mblk */
			return;
		}
	} else if (state != TB_IDLE) {
		/* Message has already been putq */
		ASSERT(mtb->mtb_q->q_first == mp ||
		    mp->b_prev || mp->b_next);
		ASSERT(state != TB_TO_BE_FREED);
		mtb->mtb_state = TB_TO_BE_FREED;
		/* mi_timer_valid will free the mblk */
		return;
	}
	ASSERT(mtb->mtb_q ==  NULL || mtb->mtb_q->q_first != mp);
	freemsg(mp);
}

/*
 * Called from mi_timer(,,-2)
 */
void
mi_timer_move(queue_t *q, MBLKP mp)
{
	MTBP	mtb;
	clock_t	tim;

	if (!q || !mp || (mp->b_rptr - mp->b_datap->db_base) != sizeof (MTB))
		return;

	mtb = (MTBP)mp->b_datap->db_base;
	/*
	 * Need to untimeout and restart to make
	 * sure that the mblk is not about to be putq on the old queue
	 * by mi_timer_fire.
	 */
	if (mtb->mtb_state == TB_RUNNING) {
		if ((tim = untimeout(mtb->mtb_tid)) < 0) {
			/*
			 * Message has already been putq. Move from old queue
			 * to new queue.
			 */
			ASSERT(mtb->mtb_q->q_first == mp ||
			    mp->b_prev || mp->b_next);
			rmvq(mtb->mtb_q, mp);
			ASSERT(mtb->mtb_q->q_first != mp &&
			    mp->b_prev == NULL && mp->b_next == NULL);
			mtb->mtb_q = q;
			(void) putq(mtb->mtb_q, mp);
			return;
		}
		mtb->mtb_q = q;
		mtb->mtb_state = TB_RUNNING;
		mtb->mtb_tid = timeout((pfv_t)mi_timer_fire, mtb, tim);
	} else if (mtb->mtb_state != TB_IDLE) {
		ASSERT(mtb->mtb_state != TB_TO_BE_FREED);
		/*
		 * Message is already sitting on queue. Move to new queue.
		 */
		ASSERT(mtb->mtb_q->q_first == mp ||
		    mp->b_prev || mp->b_next);
		rmvq(mtb->mtb_q, mp);
		ASSERT(mtb->mtb_q->q_first != mp &&
		    mp->b_prev == NULL && mp->b_next == NULL);
		mtb->mtb_q = q;
		(void) putq(mtb->mtb_q, mp);
	} else
		mtb->mtb_q = q;
}

/*
 * Called from mi_timer(,,-1)
 */
void
mi_timer_stop(MBLKP mp)
{
	MTBP	mtb;
	int	state;

	if (!mp || (mp->b_rptr - mp->b_datap->db_base) != sizeof (MTB))
		return;

	mtb = (MTBP)mp->b_datap->db_base;
	state = mtb->mtb_state;
	if (state == TB_RUNNING) {
		if (untimeout(mtb->mtb_tid) < 0) {
			/* Message has already been putq */
			ASSERT(mtb->mtb_q->q_first == mp ||
			    mp->b_prev || mp->b_next);
			mtb->mtb_state = TB_CANCELLED;
		} else {
			mtb->mtb_state = TB_IDLE;
		}
	} else if (state == TB_RESCHED) {
		ASSERT(mtb->mtb_q->q_first == mp ||
		    mp->b_prev || mp->b_next);
		mtb->mtb_state = TB_CANCELLED;
	}
}

/*
 * The user of the mi_timer mechanism is required to call mi_timer_valid() for
 * each M_PCSIG message processed in the service procedures.
 * mi_timer_valid will return "true" if the timer actually did fire.
 */

boolean_t
mi_timer_valid(MBLKP mp)
{
	MTBP	mtb;
	int	state;

	if (!mp	|| (mp->b_rptr - mp->b_datap->db_base) != sizeof (MTB) ||
	    mp->b_datap->db_type != M_PCSIG)
		return (B_FALSE);
	mtb = (MTBP)mp->b_datap->db_base;
	state = mtb->mtb_state;
	if (state != TB_RUNNING) {
		ASSERT(state != TB_IDLE);
		if (state == TB_TO_BE_FREED) {
			/*
			 * mi_timer_free was called after the message
			 * was putq'ed.
			 */
			freemsg(mp);
			return (B_FALSE);
		}
		if (state == TB_CANCELLED) {
			/* The timer was stopped after the mblk was putq'ed */
			mtb->mtb_state = TB_IDLE;
			return (B_FALSE);
		}
		if (state == TB_RESCHED) {
			/*
			 * The timer was stopped and then restarted after
			 * the mblk was putq'ed.
			 * mtb_time_left contains the number of ticks that
			 * the timer was restarted with.
			 */
			mtb->mtb_state = TB_RUNNING;
			mtb->mtb_tid = timeout((pfv_t)mi_timer_fire,
			    mtb, mtb->mtb_time_left);
			return (B_FALSE);
		}
	}
	mtb->mtb_state = TB_IDLE;
	return (B_TRUE);
}

static void
mi_tpi_addr_and_opt(MBLKP mp, char *addr, t_scalar_t addr_length,
    char *opt, t_scalar_t opt_length)
{
	struct T_unitdata_ind	*tudi;

	/*
	 * This code is used more than just for unitdata ind
	 * (also for T_CONN_IND and T_CONN_CON) and
	 * relies on correct functioning on the happy
	 * coincidence that the address and option buffers
	 * represented by length/offset in all these primitives
	 * are isomorphic in terms of offset from start of data
	 * structure
	 */
	tudi = (struct T_unitdata_ind *)mp->b_rptr;
	tudi->SRC_offset = (t_scalar_t)(mp->b_wptr - mp->b_rptr);
	tudi->SRC_length = addr_length;
	if (addr_length > 0) {
		bcopy(addr, (char *)mp->b_wptr, addr_length);
		mp->b_wptr += addr_length;
	}
	tudi->OPT_offset = (t_scalar_t)(mp->b_wptr - mp->b_rptr);
	tudi->OPT_length = opt_length;
	if (opt_length > 0) {
		bcopy(opt, (char *)mp->b_wptr, opt_length);
		mp->b_wptr += opt_length;
	}
}

MBLKP
mi_tpi_conn_con(MBLKP trailer_mp, char *src, t_scalar_t src_length, char *opt,
    t_scalar_t opt_length)
{
	size_t	len;
	MBLKP	mp;

	len = sizeof (struct T_conn_con) + src_length + opt_length;
	if ((mp = mi_tpi_trailer_alloc(trailer_mp, len, T_CONN_CON)) != NULL) {
		mp->b_wptr = &mp->b_rptr[sizeof (struct T_conn_con)];
		mi_tpi_addr_and_opt(mp, src, src_length, opt, opt_length);
	}
	return (mp);
}

MBLKP
mi_tpi_conn_ind(MBLKP trailer_mp, char *src, t_scalar_t src_length, char *opt,
    t_scalar_t opt_length, t_scalar_t seqnum)
{
	size_t	len;
	MBLKP	mp;

	len = sizeof (struct T_conn_ind) + src_length + opt_length;
	if ((mp = mi_tpi_trailer_alloc(trailer_mp, len, T_CONN_IND)) != NULL) {
		mp->b_wptr = &mp->b_rptr[sizeof (struct T_conn_ind)];
		mi_tpi_addr_and_opt(mp, src, src_length, opt, opt_length);
		((struct T_conn_ind *)mp->b_rptr)->SEQ_number = seqnum;
		mp->b_datap->db_type = M_PROTO;
	}
	return (mp);
}

MBLKP
mi_tpi_extconn_ind(MBLKP trailer_mp, char *src, t_scalar_t src_length,
    char *opt, t_scalar_t opt_length, char *dst, t_scalar_t dst_length,
    t_scalar_t seqnum)
{
	size_t	len;
	MBLKP	mp;

	len = sizeof (struct T_extconn_ind) + src_length + opt_length +
	    dst_length;
	if ((mp = mi_tpi_trailer_alloc(trailer_mp, len, T_EXTCONN_IND)) !=
	    NULL) {
		mp->b_wptr = &mp->b_rptr[sizeof (struct T_extconn_ind)];
		mi_tpi_addr_and_opt(mp, src, src_length, opt, opt_length);
		((struct T_extconn_ind *)mp->b_rptr)->DEST_length = dst_length;
		((struct T_extconn_ind *)mp->b_rptr)->DEST_offset =
		    (t_scalar_t)(mp->b_wptr - mp->b_rptr);
		if (dst_length > 0) {
			bcopy(dst, (char *)mp->b_wptr, dst_length);
			mp->b_wptr += dst_length;
		}
		((struct T_extconn_ind *)mp->b_rptr)->SEQ_number = seqnum;
		mp->b_datap->db_type = M_PROTO;
	}
	return (mp);
}

MBLKP
mi_tpi_discon_ind(MBLKP trailer_mp, t_scalar_t reason, t_scalar_t seqnum)
{
	MBLKP	mp;
	struct T_discon_ind	*tdi;

	if ((mp = mi_tpi_trailer_alloc(trailer_mp,
	    sizeof (struct T_discon_ind), T_DISCON_IND)) != NULL) {
		tdi = (struct T_discon_ind *)mp->b_rptr;
		tdi->DISCON_reason = reason;
		tdi->SEQ_number = seqnum;
	}
	return (mp);
}

/*
 * Allocate and fill in a TPI err ack packet using the 'mp' passed in
 * for the 'error_prim' context as well as sacrifice.
 */
MBLKP
mi_tpi_err_ack_alloc(MBLKP mp, t_scalar_t tlierr, int unixerr)
{
	struct T_error_ack	*teackp;
	t_scalar_t error_prim;

	if (!mp)
		return (NULL);
	error_prim = ((TPRIMP)mp->b_rptr)->type;
	if ((mp = tpi_ack_alloc(mp, sizeof (struct T_error_ack),
	    M_PCPROTO, T_ERROR_ACK)) != NULL) {
		teackp = (struct T_error_ack *)mp->b_rptr;
		teackp->ERROR_prim = error_prim;
		teackp->TLI_error = tlierr;
		teackp->UNIX_error = unixerr;
	}
	return (mp);
}

MBLKP
mi_tpi_ok_ack_alloc_extra(MBLKP mp, int extra)
{
	t_scalar_t correct_prim;

	if (!mp)
		return (NULL);
	correct_prim = ((TPRIMP)mp->b_rptr)->type;
	if ((mp = tpi_ack_alloc(mp, sizeof (struct T_ok_ack) + extra,
	    M_PCPROTO, T_OK_ACK)) != NULL) {
		((struct T_ok_ack *)mp->b_rptr)->CORRECT_prim = correct_prim;
		mp->b_wptr -= extra;
	}
	return (mp);
}

MBLKP
mi_tpi_ok_ack_alloc(MBLKP mp)
{
	return (mi_tpi_ok_ack_alloc_extra(mp, 0));
}

MBLKP
mi_tpi_ordrel_ind(void)
{
	MBLKP	mp;

	if ((mp = allocb(sizeof (struct T_ordrel_ind), BPRI_HI)) != NULL) {
		mp->b_datap->db_type = M_PROTO;
		((struct T_ordrel_ind *)mp->b_rptr)->PRIM_type = T_ORDREL_IND;
		mp->b_wptr += sizeof (struct T_ordrel_ind);
	}
	return (mp);
}

static MBLKP
mi_tpi_trailer_alloc(MBLKP trailer_mp, size_t size, t_scalar_t type)
{
	MBLKP	mp;

	if ((mp = allocb(size, BPRI_MED)) != NULL) {
		mp->b_cont = trailer_mp;
		mp->b_datap->db_type = M_PROTO;
		((union T_primitives *)mp->b_rptr)->type = type;
		mp->b_wptr += size;
	}
	return (mp);
}

MBLKP
mi_tpi_uderror_ind(char *dest, t_scalar_t dest_length, char *opt,
    t_scalar_t opt_length, t_scalar_t error)
{
	size_t	len;
	MBLKP	mp;
	struct T_uderror_ind	*tudei;

	len = sizeof (struct T_uderror_ind) + dest_length + opt_length;
	if ((mp = allocb(len, BPRI_HI)) != NULL) {
		mp->b_datap->db_type = M_PROTO;
		tudei = (struct T_uderror_ind *)mp->b_rptr;
		tudei->PRIM_type = T_UDERROR_IND;
		tudei->ERROR_type = error;
		mp->b_wptr = &mp->b_rptr[sizeof (struct T_uderror_ind)];
		mi_tpi_addr_and_opt(mp, dest, dest_length, opt, opt_length);
	}
	return (mp);
}

IDP
mi_zalloc(size_t size)
{
	IDP	ptr;

	if (ptr = mi_alloc(size, BPRI_LO))
		bzero(ptr, size);
	return (ptr);
}

IDP
mi_zalloc_sleep(size_t size)
{
	IDP	ptr;

	if (ptr = mi_alloc_sleep(size, BPRI_LO))
		bzero(ptr, size);
	return (ptr);
}
