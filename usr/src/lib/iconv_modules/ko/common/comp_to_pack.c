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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * $Id: comp_to_pack.c,v 1.13 1997/10/31 16:16:56 binz Exp $ SMI ALE.
 */

#include <stdio.h>
#include <ctype.h>
#include "kctype.h"
#include "kdefs.h"
#include "ktable.h"
#ifdef TESTP
#include <widec.h>
#include <locale.h>
#endif

KCHAR c2p();

KCHAR comptopack(comp)
KCHAR comp;
{
    int	c;
    KCHAR code;
    unsigned char cnv_buf[2];

#ifdef TESTP
    setlocale (LC_CTYPE, "");
#endif

#if defined(i386) || defined(__ppc)
    c = comp & 0x00ff;
#else
    c = comp>>8 & 0x00ff;
#endif
    if (iskorea1 (c)) {	/* output completion code */
#if defined(i386) || defined(__ppc)
	code = (comp >> 8 & 0x00ff) | (((comp & 0x00ff) << 8) & 0xff00);
#else
	code = comp;
#endif
	if (iskorea2(code&BYTE_MASK)) {
	    /* Output hangul character */
	    if (ishangul(c)) {
		if ((code = c2p(code)) == K_ILLEGAL) {
			return(K_ILLEGAL);
		} else {
			cnv_buf[0] = code>>8;
			cnv_buf[1] = code&BYTE_MASK;
		}

				/* output initial sound only case */
	    } else if (ishaninit(code)) {
		if (X32_19[code - 0xa4a0] == -1) {
		    return(K_ILLEGAL);
		} else {
		    cnv_buf[0] = (X32_19[code - 0xa4a0]<<2)|0x80;
		    cnv_buf[1] = 0x21; /* mid,last Fill */
		}

		/* output middle sound only case */
	    } else if (ishanmid(code)) {
		code -= 0xa4be;
		code = ((code + code/3 + 1)<<5)|0xa401;
		/* a401 is first,last Fill */
		cnv_buf[0] = code>>8;
		cnv_buf[1] = code&BYTE_MASK;

		/* output hanja character */
	    } else if (ishanja (c)) {
		return(K_ILLEGAL);

		/* other case */
	    } else {
		return(K_ILLEGAL);
		/*
		cnv_buf[0] = c;
		cnv_buf[1] = code&BYTE_MASK;
		*/
	    }

	} else {
	    return(K_ILLEGAL);
	}

    } else {
        /* output normal Ascii code */
	return(comp);
    }
#if defined(i386) || defined(__ppc)
    return(cnv_buf[1] << 8 | cnv_buf[0]);
#else
    return(cnv_buf[0] << 8 | cnv_buf[1]);
#endif
}

#ifdef TESTP
main()  /* This main portion is just for test */
{
	unsigned int comp2;
	unsigned short comb2;
	unsigned int wc;

	for(;;) {
		wc = getwchar();
		wctomb((char *)&comb2, wc);
		comp2 = comptopack(comb2);
		printf("completion, combination = 0x%x  0x%x\n",
				comb2, comp2);
	}
}
#endif
