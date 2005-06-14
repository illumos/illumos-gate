/*
 * s_common.h - common definitions for Solaris PPP
 *
 * Copyright (c) 2000-2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_S_COMMON_H
#define	_S_COMMON_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <net/ppp_defs.h>
#include <net/pppio.h>

#ifdef	__cplusplus
extern "C" {
#endif

#ifndef MTYPE
#define	MTYPE(mp)	(mp->b_datap->db_type)
#endif

#ifndef Dim
#define	Dim(x)		(sizeof (x) / sizeof (*(x)))
#endif

/* Extract byte i of message mp */
#define	MSG_BYTE(mp, i)		\
	((i) < MBLKL(mp) ? (mp)->b_rptr[i] : msg_byte((mp), (i)))

extern int	putctl4(queue_t *, uchar_t, uchar_t, uint16_t);
extern int	putctl8(queue_t *, uchar_t, uchar_t, uint32_t);
extern int	msg_byte(mblk_t *, unsigned int);
extern mblk_t	*create_lsmsg(enum LSstat);

#ifdef	__cplusplus
}
#endif

#endif /* _S_COMMON_H */
