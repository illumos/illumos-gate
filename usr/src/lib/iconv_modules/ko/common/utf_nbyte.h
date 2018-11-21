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



#ifndef	_UTF2NBYTE_H_
#define	_UTF2NBYTE_H_


#include "hangulcode.h"

typedef struct __conv_desc {
	unsigned short          ci, v, cf;
	enum { E, CI, V, CF }   prev_state;
	enum { ASCII, WANSUNG }	state;
} _conv_desc;

#define RESET_CONV_DESC()\
			cd->ci = cd->v = cd->cf = CVC_FILL; cd->prev_state = E;
#define PROCESS_PRIOR_CVC()\
	{\
		int		i;\
		register int	j;\
		char		c[5];\
		\
		if (cd->prev_state != E)\
		{\
			i = 0;\
			if ((cd->ci <= 18 || cd->ci == CVC_FILL) &&\
			    (cd->v <= 20 || cd->v == CVC_FILL) &&\
			    (cd->cf <= 28 || cd->cf == CVC_FILL))\
			{\
				c[i] = (char)Y19_32[cd->ci != CVC_FILL ?\
					cd->ci + 1 : 0] + '@';\
				if (c[i] > '@')\
					i++;\
				c[i] = (char)Y21_32[cd->v != CVC_FILL ? cd->v +\
					(short)(cd->v + 1) / 3 + 2 : 1] + '`';\
				if (c[i] > 'a')\
					echo_vowel(c, &i);\
				c[i] = (char)Y28_32[cd->cf != CVC_FILL ?\
					cd->cf - 1 : 0] + '@';\
				if (c[i] > '@')\
					echo_consonant(c, &i);\
				\
				if ((obtail - ob) < (i + (cd->state == ASCII ?\
								1 : 0)))\
				{\
					errno = E2BIG;\
					ret_val = (size_t)-1;\
					break;\
				}\
				if (cd->state == ASCII)\
				{\
					*ob++ = SO;\
					cd->state = WANSUNG;\
				}\
				for (j = 0; j < i; j++)\
					*ob++ = c[j];\
			}\
			else\
			{\
				/* Let's assume the code is non-identical. */\
				if (cd->state == WANSUNG)\
				{\
					if ((obtail - ob) < 3)\
					{\
						errno = E2BIG;\
						ret_val = (size_t)-1;\
						break;\
					}\
					*ob++ = SI;\
					cd->state = ASCII;\
				}\
				else if ((obtail - ob) < 2)\
				{\
					errno = E2BIG;\
					ret_val = (size_t)-1;\
					break;\
				}\
				*ob++ = NON_IDENTICAL;\
				*ob++ = NON_IDENTICAL;\
				ret_val += 2;\
			}\
			RESET_CONV_DESC();\
		}\
	}


#endif	/* _UTF2NBYTE_H_ */
