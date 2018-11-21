/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright (c) 1994 by Sun Microsystems, Inc.
 */



#ifndef	_UTF2JOHAP_H_
#define	_UTF2JOHAP_H_


#include "hangulcode.h"

typedef struct __conv_desc {
	unsigned short          ci, v, cf;
	enum { E, CI, V, CF }   prev_state;
} _conv_desc;

#define RESET_CONV_DESC()\
			cd->ci = cd->v = cd->cf = CVC_FILL; cd->prev_state = E;
#define PROCESS_PRIOR_CVC()\
	{\
		unsigned short code;\
		\
		if (cd->prev_state != E)\
		{\
			if ((obtail - ob) < 2)\
			{\
				errno = E2BIG;\
				ret_val = (size_t)-1;\
				break;\
			}\
			\
			if ((cd->ci <= 18 || cd->ci == CVC_FILL) &&\
			    (cd->v <= 20 || cd->v == CVC_FILL) &&\
			    (cd->cf <= 28 || cd->cf == CVC_FILL))\
			{\
				code = (cd->ci == CVC_FILL) ? 9 :\
					cd->ci + 0xA;\
				code = (code<<5) | ((unsigned short)(cd->v ==\
					CVC_FILL) ? 1 : cd->v + \
					(short)(cd->v + 1) / 3 + 2);\
				code = (code<<5) | ((cd->cf == CVC_FILL) ? 1 : \
					cd->cf) | 0x8000;\
			}\
			else\
			{\
				/* Let's assume the code is non-identical. */\
				code = (((unsigned short)NON_IDENTICAL) << 8) |\
					((unsigned short)NON_IDENTICAL);\
				ret_val += 2;\
			}\
			*ob++ = (char)((code >> 8) & 0xFF);\
			*ob++ = (char)(code & 0xFF);\
			RESET_CONV_DESC();\
		}\
	}


#endif	/* _UTF2JOHAP_H_ */
