/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 1989 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include "codeset.h"
#include "mbextern.h"
#include "euc.h"
#include <limits.h>

#define EUCMASK	0x8080		/* All id bits */
#define MASK0	0x0000		/* Code Set 0 */
#define MASK1	0x8080		/* Code Set 1 */
#define MASK2	0x0080		/* Code Set 2 */
#define MASK3	0x8000		/* Code Set 3 */

#define EUCWID1	eucinfo->_eucw1
#define EUCWID2	eucinfo->_eucw2
#define EUCWID3	eucinfo->_eucw3

int	_wctomb_euc(char *, wchar_t);

int
_mbtowc_euc(wchar_t *wchar, char *s, size_t n)
{
	int length;
	wchar_t intcode;
	int c;
	char *olds = (char *)s;
	wchar_t mask;
        eucwidth_t * eucinfo = (eucwidth_t *)_code_set_info.code_info;
	
	if(n <= 0)
		return(-1);
	if(s == (char *)0)
		return (0);
	c = (unsigned char)*s++;
	if(c < 0200) {
		if(wchar)
			*wchar = c;
		return (c ? 1 : 0);
	}
	intcode = 0;
	if (c == SS2) {
		if(!(length = EUCWID2)) {
			if(wchar)
				*wchar = c;
			return (1);
		}
		mask = MASK2;
	} else if(c == SS3) {
		if(!(length = EUCWID3)) {
			if(wchar)
				*wchar = c;
			return (1);
		}
		mask = MASK3;
	} else {
		if(iscntrl(c)) {
			if(wchar)
				*wchar = c;
			return (1);
		}
		length = EUCWID1 - 1;
		mask = MASK1;
		intcode = c & 0177;
	}
	if(length + 1 > n)
		return (-1);
	while(length--) {
		if((c = (unsigned char)*s++) < 0200 || iscntrl(c))
			return (-1);
		intcode = (intcode << 8) | (c & 0177);
	}
	if(wchar)
		*wchar = intcode | mask;
	return ((char *)s - olds);
}

	
size_t
_mbstowcs_euc(wchar_t *pwcs, char *s, size_t n)
{
	int		i, j;

	j=0;
	while(*s) {
		if(j>=n) 
			break; 
		i=_mbtowc_euc(pwcs+j, s, MB_LEN_MAX);
		if(i==-1) 
			return (-1);
		s+=i;
		++j;
	}
	if(j<n)
		pwcs[j]=0;
	return (j);
}


size_t
_wcstombs_euc(char *s, wchar_t *pwcs, size_t n)
{
	wchar_t	wc;
	int		i;
	int		r=n; /* Rest of bytes. */
	char		*t;
	char			mbbuf[MB_LEN_MAX+1];

	while(wc=(*pwcs++)) {
		i=_wctomb_euc(mbbuf, wc);

		if (i>r) 
			break; 
		if (i==-1) return (-1);

		r-=i;
		for (t=mbbuf;i>0;--i){
			/* Copy each byte. */
			*(s++)=*(t++);
		}
	}
	if (r>0)
		/* Has enough room for NUL. */
		*s=0;
	return (n-r);
}

int
_wctomb_euc(char *s, wchar_t wchar)
{
        eucwidth_t * eucinfo = (eucwidth_t *)_code_set_info.code_info;
	char *olds = s;
	int size, index;
	unsigned char d;
	if(!s)
		return(0);
	if( wchar <= 0177 || wchar <= 0377 && iscntrl(wchar)) {
		*s++ = wchar;
		return (wchar ? 1 : 0);
	}
	switch(wchar & EUCMASK) {
		
		case MASK1:
			size = EUCWID1;
			break;
		
		case MASK2:
			*s++ = SS2;
			size = EUCWID2;
			break;
		
		case MASK3:
			*s++ = SS3;
			size = EUCWID3;
			break;
		
		default:
			return (-1);
	}
	index = size;	
	while(index--) {
		d = wchar | 0200;
		wchar >>= 8;
		if(iscntrl(d))
			return (-1);
		s[index] = d;
	}
	return (s + size - olds);
}
