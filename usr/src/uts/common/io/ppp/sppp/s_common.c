/*
 * s_common.c - common utilities for Solaris PPP
 *
 * Copyright (c) 2000 by Sun Microsystems, Inc.
 * All rights reserved.
 *
 * Permission to use, copy, modify, and distribute this software and its
 * documentation is hereby granted, provided that the above copyright
 * notice appears in all copies.
 *
 * SUN MAKES NO REPRESENTATION OR WARRANTIES ABOUT THE SUITABILITY OF
 * THE SOFTWARE, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED
 * TO THE IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
 * PARTICULAR PURPOSE, OR NON-INFRINGEMENT.  SUN SHALL NOT BE LIABLE FOR
 * ANY DAMAGES SUFFERED BY LICENSEE AS A RESULT OF USING, MODIFYING OR
 * DISTRIBUTING THIS SOFTWARE OR ITS DERIVATIVES
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"
#define	RCSID	"$Id: s_common.c,v 1.0 2000/05/08 01:10:12 masputra Exp $"

#include <sys/types.h>
#include <sys/debug.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/stream.h>
#include <sys/stropts.h>
#include <sys/errno.h>
#include <sys/ioccom.h>
#include <sys/cmn_err.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/strsun.h>
#include <net/ppp_defs.h>
#include <net/pppio.h>
#include "s_common.h"

/*
 * putctl4()
 *
 * Description:
 *    Create and send a 4-byte message.
 */
int
putctl4(queue_t *q, uchar_t type, uchar_t code, uint16_t val)
{
	mblk_t	*mp;

	if ((mp = allocb(4, BPRI_HI)) == NULL) {
		return (0);
	}
	MTYPE(mp) = type;
	mp->b_wptr[0] = code;
	((uint16_t *)mp->b_wptr)[1] = val;
	mp->b_wptr += 4;

	putnext(q, mp);
	return (1);
}

/*
 * putctl8()
 *
 * Description:
 *    Create and send a 8-byte message.
 */
int
putctl8(queue_t *q, uchar_t type, uchar_t code, uint32_t val)
{
	mblk_t	*mp;

	if ((mp = allocb(8, BPRI_HI)) == NULL) {
		return (0);
	}
	MTYPE(mp) = type;
	mp->b_wptr[0] = code;
	((uint32_t *)mp->b_wptr)[1] = val;
	mp->b_wptr += 8;

	putnext(q, mp);
	return (1);
}

/*
 * msg_byte()
 *
 * Description:
 *    Helper routine to return a specific byte off a data buffer.
 */
int
msg_byte(mblk_t *mp, unsigned int i)
{
	while (mp != NULL) {
		if (i < MBLKL(mp)) {
			break;
		}
		i -= MBLKL(mp);
		mp = mp->b_cont;
	}
	if (mp == NULL) {
		return (-1);
	}
	return (mp->b_rptr[i]);
}

/*
 * sppp_create_lsmsg()
 *
 * Description:
 *    Create a PPP link status message.
 */
mblk_t *
create_lsmsg(enum LSstat ls_type)
{
	mblk_t		*mp;
	struct ppp_ls	*plt;

	if ((mp = allocb(sizeof (*plt), BPRI_HI)) == NULL) {
		return (NULL);
	}
	/*
	 * Make sure that this message is a control message, and contains
	 * a notification that the link has been terminated.
	 */
	MTYPE(mp) = M_PROTO;
	mp->b_wptr += sizeof (*plt);
	plt = (struct ppp_ls *)mp->b_rptr;
	plt->magic = PPPLSMAGIC;
	plt->ppp_message = ls_type;

	return (mp);
}
