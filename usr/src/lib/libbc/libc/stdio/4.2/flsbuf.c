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
/*      Copyright (c) 1984 AT&T */
/*        All Rights Reserved   */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*LINTLIBRARY*/
#include <stdio.h>
#include "../common/stdiom.h"
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <malloc.h>
#include <unistd.h>

extern int	fclose();
extern unsigned char (*_smbuf)[_SBFSIZ];

void	_findbuf(FILE *);
void	_bufsync(FILE *);

/*
 * Flush buffers on exit
 */

void
_cleanup(void)
{

	_fwalk(fclose);
}
/*
 *	fclose() will flush (output) buffers for a buffered open
 *	FILE and then issue a system close on the _fileno.  The
 *	_base field will be reset to NULL for any but stdin and
 *	stdout, the _ptr field will be set the same as the _base
 *	field. The _flags and the _cnt field will be zeroed.
 *	If buffers had been obtained via malloc(), the space will
 *	be free()'d.  In case the FILE was not open, or fflush()
 *	or close() failed, an EOF will be returned, otherwise the
 *	return value is 0.
 */

int
fclose(FILE *iop)
{
	int rtn=EOF;

	if(iop == NULL)
		return(rtn);
	if(iop->_flag & (_IOREAD | _IOWRT | _IORW)
	   && (iop->_flag & _IOSTRG) == 0) {
		rtn = (iop->_flag & _IONBF)? 0: fflush(iop);
		if(close(fileno(iop)) < 0)
			rtn = EOF;
	}
	if(iop->_flag & _IOMYBUF) {
		free((char*)iop->_base);
		iop->_base = NULL;
	}
	iop->_flag = 0;
	iop->_cnt = 0;
	iop->_ptr = iop->_base;
	iop->_bufsiz = 0;
	return(rtn);
}

/*
 *	The fflush() routine must take care because of the
 *	possibility for recursion. The calling program might
 *	do IO in an interupt catching routine that is likely
 *	to interupt the write() call within fflush()
 */

int
fflush(FILE *iop)
{
	if (!(iop->_flag & _IOWRT)) {
		return(0);
	}
	while(!(iop->_flag & _IONBF) && (iop->_flag & _IOWRT) &&
			(iop->_base != NULL) && (iop->_ptr > iop->_base) )
		(void) _xflsbuf(iop);
	return(ferror(iop) ? EOF : 0);
}

/* The routine _flsbuf may or may not actually flush the output buffer.  If
 * the file is line-buffered, the fact that iop->_cnt has run below zero
 * is meaningless: it is always kept below zero so that invocations of putc
 * will consistently give control to _flsbuf, even if the buffer is far from
 * full.  _flsbuf, on seeing the "line-buffered" flag, determines whether the
 * buffer is actually full by comparing iop->_ptr to the end of the buffer
 * iop->_base + iop->_bufsiz.  If it is full, or if an output line is
 * completed (with a newline), the buffer is flushed.  (Note: the character
 * argument to _flsbuf is not flushed with the current buffer if the buffer
 * is actually full -- it goes into the buffer after flushing.)
 */

int
_flsbuf(unsigned char c, FILE *iop)
{
    unsigned char c1;

    do {
	/* check for linebuffered with write perm, but no EOF */
	if ( (iop->_flag & (_IOLBF | _IOWRT | _IOEOF)) == (_IOLBF | _IOWRT) ) {
		if ( iop->_ptr >= iop->_base + iop->_bufsiz )  /* if buffer full, */
			break;		    /* exit do-while, and flush buf. */
		if ( (*iop->_ptr++ = c) != '\n' )
			return(c);
		return(_xflsbuf(iop) == EOF ? EOF : c);
	}
	/* write out an unbuffered file, if have write perm, but no EOF */
	if ( (iop->_flag & (_IONBF | _IOWRT | _IOEOF)) == (_IONBF | _IOWRT) ) {
		c1 = c;
		iop->_cnt = 0;
		if (write(fileno(iop), (char *) &c1, 1) == 1)
			return(c);
		iop->_flag |= _IOERR;
		return(EOF);
	}
	/* The _wrtchk call is here rather than at the top of _flsbuf to re- */
	/* duce overhead for line-buffered I/O under normal circumstances.  */

	if (_WRTCHK(iop))			/* is writing legitimate? */
		return(EOF);
    } while ( (iop->_flag & (_IONBF | _IOLBF)) );


    (void) _xflsbuf(iop);   /* full buffer:  flush buffer */
    (void) putc((char) c, iop);  /* then put "c" in newly emptied buf */
			/* (which, because of signals, may NOT be empty) */
    return( ferror(iop) ? EOF : c);
}

/* The function _xflsbuf writes out the current contents of the output
 * buffer delimited by iop->_base and iop->_ptr.
 * iop->_cnt is reset appropriately, but its value on entry to _xflsbuf
 * is ignored.
 *
 * The following code is not strictly correct.  If a signal is raised,
 * invoking a signal-handler which generates output into the same buffer
 * being flushed, a peculiar output sequence may result (for example,
 * the output generated by the signal-handler may appear twice).  At
 * present no means has been found to guarantee correct behavior without
 * resorting to the disabling of signals, a means considered too expensive.
 * For now the code has been written with the intent of reducing the
 * probability of strange effects and, when they do occur, of confining
 * the damage.  Except under extremely pathological circumstances, this
 * code should be expected to respect buffer boundaries even in the face
 * of interrupts and other signals.
 */

int
_xflsbuf(FILE *iop)
{
	unsigned char *base;
	int n;

	n = iop->_ptr - (base = iop->_base);
	iop->_ptr = base;
	iop->_cnt = (iop->_flag &(_IONBF | _IOLBF)) ? 0 : iop->_bufsiz;
	_BUFSYNC(iop);
	if (n > 0 && n != write(fileno(iop),(char*)base,(unsigned)n) )  {
		iop->_flag |= _IOERR;
		return(EOF);
	}
	return(0);
}

/* The function _wrtchk checks to see whether it is legitimate to write
 * to the specified device.  If it is, _wrtchk sets flags in iop->_flag for
 * writing, assures presence of a buffer, and returns 0.  If writing is not
 * legitimate, EOF is returned.
 */

int
_wrtchk(FILE *iop)
{
	if ( (iop->_flag & (_IOWRT | _IOEOF)) != _IOWRT ) {
		if (!(iop->_flag & (_IOWRT | _IORW)))
			return(EOF);  /* bogus call--read-only file */
		iop->_flag = iop->_flag & ~_IOEOF | _IOWRT; /* fix flags */
	}
	if (iop->_flag & _IOSTRG)
		return(0);	/* not our business to monkey with buffers or counts */
	if (iop->_base == NULL)    /* this is first I/O to file--get buffer */
		_findbuf(iop);
	if (iop->_ptr == iop->_base && !(iop->_flag & (_IONBF | _IOLBF)) )  {
		iop->_cnt = iop->_bufsiz; /* first write since seek--set cnt */
		_BUFSYNC(iop);
	}
	return(0);
}

/*
 * _findbuf, called only when iop->_base == NULL, locates a predefined buffer
 * or allocates a buffer using malloc.  If a buffer is obtained from malloc,
 * the _IOMYBUF flag is set in iop->_flag.
 */

void
_findbuf(FILE *iop)
{
	int fno = fileno(iop); /* file number */
	struct stat statb;
	int size;

	/* allocate a small block for unbuffered, large for buffered */
	if (iop->_flag & _IONBF)  {
		iop->_base = _smbuf[fno];
		iop->_bufsiz = _SBFSIZ;
	}  else  {

		if ( isatty(fno) ) {
			iop->_flag |= _IOLBF;
			size = 128;
		} else {
			if (fstat(fno, &statb) < 0)
				size = BUFSIZ;
			else {
				if ((size = statb.st_blksize) <= 0)
					size = BUFSIZ;
			}
		}
		if ((iop->_base = (unsigned char *) malloc(size+8)) != NULL) {
			/* if  we got a buffer */
			iop->_flag |= _IOMYBUF;
			iop->_bufsiz = size;
		} else {
			/* if no room for buffer, use small buffer */
			iop->_base = _smbuf[fno];
			iop->_bufsiz = _SBFSIZ;
			iop->_flag &= ~_IOLBF;
			iop->_flag |= _IONBF;
		}
	}
	iop->_ptr = iop->_base;
}

/*
 * The function _bufsync is called because interrupts and other signals
 * which occur in between the decrementing of iop->_cnt and the incrementing
 * of iop->_ptr, or in other contexts as well, may upset the synchronization
 * of iop->_cnt and iop->ptr.  If this happens, calling _bufsync should
 * resynchronize the two quantities (this is not always possible).  Resyn-
 * chronization guarantees that putc invocations will not write beyond
 * the end of the buffer.  Note that signals during _bufsync can cause
 * _bufsync to do the wrong thing, but usually with benign effects.
 */

void
_bufsync(FILE *iop)
{
	int spaceleft;
	unsigned char *bufend = iop->_base + iop->_bufsiz;

	if ((spaceleft = bufend - iop->_ptr) < 0)
		iop->_ptr = bufend;
	else if (spaceleft < iop->_cnt)
		iop->_cnt = spaceleft;
}
