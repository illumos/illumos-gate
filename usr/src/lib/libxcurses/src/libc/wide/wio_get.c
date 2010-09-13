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
 * Copyright (c) 1996, by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * wio_get.c
 * 
 * Wide I/O Library
 *
 * Copyright 1990, 1995 by Mortice Kern Systems Inc.  All rights reserved.
 *
 */

#if M_RCSID
#ifndef lint
static char rcsID[] = "$Header: /rd/src/libc/wide/rcs/wio_get.c 1.3 1995/07/26 17:50:45 ant Exp $";
#endif
#endif

#include <mks.h>
#include <errno.h>
#include <m_wio.h>

#ifdef M_I18N_LOCKING_SHIFT
/*
 * Eat one or more shift-out and/or shift-in bytes.
 * Return non-zero if an error occured on the stream.  
 * The stream's input state is updated accordingly.
 *
 * NOTE this function assumes that the shift-in and
 * shift-out are bytes.
 */
static int
eat_shift_bytes(wio)
t_wide_io *wio;
{
	char mb;
	int ch, prev;
	mbstate_t start_state;

	for (prev = EOF; (ch = (*wio->get)(wio->object)) != EOF; prev = ch) {
		/* Was it an insignificant shift byte, SI-SI or SO-SO? */
		if (ch != prev) {
			/* First iteration will always enter here looking 
			 * for a state change.  Subsequent iterations entering
			 * here are trying to identify redundant shifts, which
			 * are SO-SI or SI-SO pairs.
			 */
			mb = (char) ch;
			start_state = wio->_state;

			/* Convert byte and identify a state change. */
			if (mbrtowc((wchar_t *) 0, &mb, 1, &wio->_state) == -1
			|| mbsinit(&start_state) == mbsinit(&wio->_state)) {
				/* Encoding error or no state change. */
				if (wio->get != (int (*)(int, void *)) 0)
					(void) (*wio->unget)(ch, wio->object);
				wio->_state = start_state;
				break;
			}
		}
	}

	if (wio->iserror != (int (*)(void *)) 0)
		return !(*wio->iserror)(wio->object);       

	return 0;
}
#endif /* M_I18N_LOCKING_SHIFT */

/*
 * Return a wide character or WEOF for EOF or error.
 *
 * The function referenced by "get" is passed the pointer "object"
 * and returns an input byte or EOF if no further data available.
 *
 * This mechanism is used to do conversions of byte strings or 
 * streams into wide characters without loss of information in the
 * case of a bad multibyte character conversion.  The bad multibyte
 * sequence is passed through as individual bytes.
 */
wint_t
m_wio_get(wio)
t_wide_io *wio;
{
        int ch;
        wchar_t wc;
	mbstate_t start_state;
	static mbstate_t initial_state = { 0 };

	if (wio == (t_wide_io *) 0 || wio->get == (int (*)(void *)) 0) {
		errno = EINVAL;
		return -1;
	}

	/* Do still have bytes available? */ 
	if (wio->_next < wio->_size)
		return (wint_t) wio->_mb[wio->_next++];

        /* Read in enough bytes to convert a multibyte character. */
	wio->_size = 0;
	start_state = wio->_state;
        for (wio->_next = 0; wio->_next < MB_CUR_MAX; ) {
                if ((ch = (*wio->get)(wio->object)) == EOF)
                        break;

		wio->_mb[wio->_next] = ch;

		/* Attempt to convert multibyte character sequence. */ 
                wio->_size = mbrtowc(
			&wc, (char *) (wio->_mb + wio->_next), 1, &wio->_state
		);

		++wio->_next;

		if (0 <= wio->_size) {
#ifdef M_I18N_LOCKING_SHIFT
			/* Only eat shift bytes within a line, since in line
			 * canonical mode, attempting to eat shift bytes
			 * following a <newline> causes another read().
			 */
			if (ch != '\n') {
				/* When a valid character is found, consume 
				 * any trailing shift-in or shift-out bytes,
				 * updating the state accordingly.
				 */
				(void) eat_shift_bytes(wio);
			}
#endif /* M_I18N_LOCKING_SHIFT */

			/* Remember the number of bytes converted. */
			wio->_size = wio->_next;

			return (wint_t) wc;
                }
        }

	/* If we fill the multibyte character buffer or receive an
	 * EOF without recognising a multibyte character, then we
	 * will return individual bytes from the buffer.  The buffer
	 * is restored to its state before the bogus byte sequence 
	 * was read.
	 */ 
	wio->_state = start_state;
	wio->_size = wio->_next;
	wio->_next = 0;

	return 0 < wio->_size ? (wint_t) wio->_mb[wio->_next++] : WEOF;
}


