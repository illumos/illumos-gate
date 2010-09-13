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
 * Copyright 1988 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*      Copyright (c) 1984 AT&T */
/*        All Rights Reserved   */

#pragma ident	"%Z%%M%	%I%	%E% SMI"  /* from S5R2 2.1 */

/*LINTLIBRARY*/
#include <stdio.h>

int
ungetc(c, iop)
int	c;
register FILE *iop;
{
	if(c == EOF)
		return(EOF);
	if((iop->_flag & (_IOREAD|_IORW)) == 0)
		return(EOF);

	if (iop->_base == NULL)  /* get buffer if we don't have one */
		_findbuf(iop);

	if((iop->_flag & _IOREAD) == 0 || iop->_ptr <= iop->_base)
		if(iop->_ptr == iop->_base && iop->_cnt == 0)
			++iop->_ptr;
		else
			return(EOF);
	if (*--iop->_ptr != c) *iop->_ptr = c;  /* was *--iop->_ptr = c; */
	++iop->_cnt;
	return(c);
}
