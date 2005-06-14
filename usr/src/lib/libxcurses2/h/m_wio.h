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
 * Copyright (c) 1996-1998 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * m_wio.h
 *
 * Wide I/O Library
 *
 * Copyright 1990, 1995 by Mortice Kern Systems Inc.  All rights reserved.
 *
 * $Header: /rd/h/rcs/m_wio.h 1.3 1995/10/02 15:36:15 ant Exp $
 */

#ifndef __M_WIO_H__
#define	__M_WIO_H__

#include <stdlib.h>
#include <wchar.h>

typedef struct {
	/* Public. */
	void	*object;	/* I/O object (normally a stream). */
	int	(*get)(void *);	/* Get byte from input object. */
	int	(*put)(int, void *);	/* Put byte to output object. */
	int	(*unget)(int, void *);	/* Push byte onto input object. */
	int	(*iseof)(void *);	/* Eof last read? */
	int	(*iserror)(void *);	/* Error last read/write? */
	void	(*reset)(void *);	/* Reset error flags. */

	/* Private. */
	int	_next;
	int	_size;
	unsigned char	_mb[MB_LEN_MAX];
} t_wide_io;

extern wint_t	m_wio_get(t_wide_io *);
extern int	m_wio_put(wint_t, t_wide_io *);

#endif /* __M_WIO_H__ */
