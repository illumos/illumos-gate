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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <mdb/mdb_dump.h>
#include <mdb/mdb_modapi.h>
#include <mdb/mdb_nv.h>
#include <mdb/mdb_err.h>
#include <mdb/mdb.h>
#include <limits.h>

#define	DUMP_PARAGRAPH	16
#define	DUMP_WIDTH(x)	(DUMP_PARAGRAPH * ((((x) >> 16) & 0xf) + 1))
#define	DUMP_GROUP(x)	((((x) >> 20) & 0xff) + 1)
#define	DUMP_MAXWIDTH	DUMP_WIDTH(MDB_DUMP_WIDTH(0x10))

/*
 * This is the implementation of mdb's generic hexdump facility (though
 * not named such in case we decide to add support for other radices).
 * While it is possible to call mdb_dump_internal directly, it is
 * recommended that you use mdb_dumpptr or mdb_dump64 instead.
 */


/*
 * Output the header for the dump.  pad is the width of the address
 * field, and offset is the index of the byte that we want highlighted.
 * If the output isn't MDB_DUMP_ALIGNed, we use offset to adjust the
 * labels to reflect the true least significant address nibble.
 */

static void
mdb_dump_header(int flags, int pad, int offset)
{
	int	nalign = !(flags & MDB_DUMP_ALIGN);
	int	group = DUMP_GROUP(flags);
	int	width = DUMP_WIDTH(flags);
	int	i;

	mdb_printf("%*s  ", pad, "");
	for (i = 0; i < width; i++) {
		if (!(i % group))
			mdb_printf((group == 1 && i && !(i % 8)) ? "  " : " ");
		if (i == offset && !nalign)
			mdb_printf("\\/");
		else
			mdb_printf("%2x", (i + (nalign * offset)) & 0xf);
	}

	if (flags & MDB_DUMP_ASCII) {
		mdb_printf("  ");
		for (i = 0; i < width; i++) {
			if (i == offset && !nalign)
				mdb_printf("v");
			else
				mdb_printf("%x", (i + (nalign * offset)) & 0xf);
		}
	}

	mdb_printf("\n");
}


/*
 * Output a line of data.  pad is as defined above.  A non-zero lmargin
 * and/or rmargin indicate a set of bytes that shouldn't be printed.
 */

static void
mdb_dump_data(uint64_t addr, uchar_t *buf, int flags, int pad,
	int lmargin, int rmargin)
{
	uchar_t	abuf[DUMP_MAXWIDTH + 1];
	int	group = DUMP_GROUP(flags);
	int	width = DUMP_WIDTH(flags);
	int	i;
#ifdef	_LITTLE_ENDIAN
	int	flip = FALSE;

	if (flags & MDB_DUMP_ENDIAN)
		flip = TRUE;
#endif

	mdb_printf("%0*llx: ", pad, addr);

	for (i = 0; i < width; i++) {
		if (!(i % group))
			mdb_printf((group == 1 && i && !(i % 8)) ? "  " : " ");
		if (i < lmargin || (width - i) <= rmargin) {
			mdb_printf("  ");
#ifdef	_LITTLE_ENDIAN
		} else if (flip) {
			int j = group * ((i / group) + 1) - (i % group) - 1;
			mdb_printf("%02x", buf[j]);
#endif
		} else {
			mdb_printf("%02x", buf[i]);
		}
	}

	if (flags & MDB_DUMP_ASCII) {
		for (i = 0; i < width; i++)
			if (i < lmargin || (width - i) <= rmargin)
				abuf[i] = ' ';
			else if (buf[i] < ' ' || buf[i] > '~')
				abuf[i] = '.';
			else
				abuf[i] = buf[i];
		abuf[width] = '\0';
		mdb_printf("  %s", abuf);
	}

	mdb_printf("\n");
}


/*
 * Given an address and a length, compute the number of characters
 * needed to display addresses within that range.
 */

static int
mdb_dump_pad(uint64_t addr, uint64_t len, int flags, int bytes)
{
	uint64_t x;
	int bits;

	if (flags & MDB_DUMP_PEDANT) {
		/*
		 * Assume full width pointers
		 */
		bits = NBBY * bytes;
	} else {
		/*
		 * Vary width based on address and length, but first
		 * check to see if the address is relevant.
		 */
		if (len > 1 || (addr && len == 1))
			len--;
		if (flags & MDB_DUMP_RELATIVE)
			x = len;
		else
			x = len + addr;

		bits = 0;
		while (x) {
			bits++;
			x >>= 1;
		}
	}

	return ((bits + 3) / 4);
}


/*
 * The main dump routine, called by mdb_dump64 and (indirectly) by
 * mdb_dumpptr.  Arguments:
 *   addr  - the address to start dumping at
 *   len   - the amount of data to dump
 *   flags - to tune operation (see mdb_modapi.h)
 *   func  - callback function used to obtain data
 *   arg   - argument to pass to callback function
 *   bytes - size of pointer type
 */

int
mdb_dump_internal(uint64_t addr, uint64_t len, int flags, mdb_dump64_cb_t func,
	void *arg, int bytes)
{
	uchar_t	buffers[2][DUMP_MAXWIDTH];
	uchar_t	*buf, *pbuf;
	uint64_t i;
	ssize_t	j;
	uint64_t addrmax;
	uint64_t offset;	/* bytes between first position and addr */
	uint64_t reqlen = len;	/* requested length */
	int	l, r;		/* left and right margins */
	int	pskip;		/* previous line was skipped */
	int	pvalid;		/* previous line was valid (we may skip) */
	int	bread, bwanted;	/* used to handle partial reads */
	int	pad, n;
	int	group, width;
	int	err = 0;

	addrmax = (1LL << (bytes * NBBY - 1)) - 1 + (1LL << (bytes * NBBY - 1));

	/*
	 * Ensure that len doesn't wrap around the end of addressable
	 * memory.  Note that because we take an address and a length,
	 * it isn't possible to dump from 0 to UINT64_MAX if
	 * MDB_DUMP_TRIM is set.
	 */
	if (len && (len - 1 > addrmax - addr)) {
		len = addrmax - addr;
		if (addr || (addrmax < UINT64_MAX))
			len++;
	}

	/*
	 * If a) the grouping isn't a power of two, or
	 *    b) the display width is not evenly divisible by the grouping
	 * we ignore the specified grouping (and default to 4).
	 */
	group = DUMP_GROUP(flags);
	width = DUMP_WIDTH(flags);
	if (((group - 1) & group) || (width % group)) {
		group = 4;
		flags = (flags & 0xfffff) | MDB_DUMP_GROUP(group);
	}

	/*
	 * If we are reordering bytes to adjust for endianness, turn
	 * off text output, headers, and alignment to cut down on the
	 * number of special cases (and confusing output).  For
	 * correctness, we will continue to observe MDB_DUMP_TRIM, but
	 * will truncate output if the specified length isn't a
	 * multiple of the grouping.
	 */
	if (flags & MDB_DUMP_ENDIAN) {
		flags &= ~(MDB_DUMP_ALIGN | MDB_DUMP_HEADER | MDB_DUMP_ASCII);
		if (flags & MDB_DUMP_TRIM)
			len -= len % group;
	}

	/*
	 * If we are interested in seeing the data indexed relative to
	 * the starting location, paragraph alignment is irrelevant.
	 * The left margin will always be 0.
	 */
	if (flags & MDB_DUMP_RELATIVE) {
		flags &= ~MDB_DUMP_ALIGN;
		l = 0;
	} else {
		l = addr % DUMP_PARAGRAPH;
	}

	/*
	 * Compute the width of our addresses, and adjust our starting
	 * point based on the address and the state of the alignment
	 * flag.
	 */
	pad = mdb_dump_pad(addr, len, flags, bytes);
	if (flags & MDB_DUMP_ALIGN) {
		len += l;
		addr -= l;
		offset = l;
	} else {
		offset = 0;
	}

	/*
	 * Display the header (if appropriate), using the left margin
	 * to determine what our column header offset should be.
	 */
	if (flags & MDB_DUMP_HEADER)
		mdb_dump_header(flags, pad, l);

	/*
	 * If we aren't trimming and aligning the output, the left
	 * margin is now irrelevant and should be zeroed.
	 */
	if (!(flags & MDB_DUMP_TRIM) || !(flags & MDB_DUMP_ALIGN))
		l = 0;

	/*
	 * We haven't skipped the previous line, it isn't valid to skip
	 * the current line, and we use buffer 0 first.  lint doesn't
	 * realize that this implies pbuf won't be accessed until after
	 * it is set, so we explicitly initialize that here, too.
	 */
	pskip = pvalid = FALSE;
	pbuf = NULL;
	n = 0;
	r = 0;

	for (i = 0; i < len && r == 0; i += width) {
		/*
		 * Select the current buffer.
		 */
		buf = buffers[n];

		/*
		 * We have a right margin only if we are on the last
		 * line and either (1) MDB_DUMP_TRIM is set or (2) our
		 * untrimmed output would require reading past the end
		 * of addressable memory.  In either case, we clear
		 * pvalid since we don't want to skip the last line.
		 */
		if ((uint64_t)width >= len - i) {
			pvalid = FALSE;
			if (flags & MDB_DUMP_TRIM)
				r = width - (len - i);
			if ((uint64_t)width - 1 > addrmax - (addr + i)) {
				int nr = width - (addrmax - (addr + i)) - 1;
				r = MAX(r, nr);
			}
		}

		/*
		 * Read data into the current buffer, obeying the left
		 * and right margins.
		 *
		 * We handle read(2)-style partial results by
		 * repeatedly calling the callback until we fill the
		 * buffer, we get a 0 (end of file), or we get a -1
		 * (error).  We take care to never read the same data
		 * twice, though.
		 *
		 * mdb(1)-style partial results (i.e. EMDB_PARTIAL) are
		 * treated like any other error.  If more exotic
		 * handling is desired, the caller is free to wrap
		 * their callback with an auxiliary function.  See
		 * mdb_dumpptr and mdb_dump64 for examples of this.
		 */
		bread = l;
		bwanted = width - r;
		while (bread < bwanted) {
			j = func(buf + bread, bwanted - bread,
			    addr + i + bread, arg);
			if (j <= 0) {
				if (i + bread < offset) {
					l++;
					j = 1;
				} else {
					r += bwanted - bread;
					pvalid = FALSE;
					if (j == -1)
						err = errno;
					if (bread == l) {
						i += width;
						goto out;
					}
					break;
				}
			}
			bread += j;
		}

		/*
		 * If we are eliminating repeated lines, AND it is
		 * valid to eliminate this line, AND the current line
		 * is the same as the previous line, don't print the
		 * current line.  If we didn't skip the previous line,
		 * print an asterisk and set the previous-line-skipped
		 * flag.
		 *
		 * Otherwise, print the line and clear the
		 * previous-line-skipped flag.
		 */
		if ((flags & MDB_DUMP_SQUISH) && pvalid &&
		    (memcmp(buf, pbuf, width) == 0)) {
			if (!pskip) {
				mdb_printf("*\n");
				pskip = TRUE;
			}
		} else {
			if (flags & MDB_DUMP_RELATIVE)
				mdb_dump_data(i, buf, flags, pad, l, r);
			else
				mdb_dump_data(addr + i, buf, flags, pad, l, r);
			pskip = FALSE;
		}

		/*
		 * If we have a non-zero left margin then we don't have
		 * a full buffer of data and we shouldn't try to skip
		 * the next line.  It doesn't matter if the right
		 * margin is non-zero since we'll fall out of the loop.
		 */
		if (!l)
			pvalid = TRUE;

		/*
		 * Swap buffers, and zero the left margin.
		 */
		n = (n + 1) % 2;
		pbuf = buf;
		l = 0;
	}

out:
	/*
	 * If we successfully dumped everything, update . to be the
	 * address following that of the last byte requested.
	 */
	if (i - r - offset >= reqlen) {
		if (flags & MDB_DUMP_NEWDOT)
			mdb_set_dot(addr + offset + reqlen);
	} else if (err) {
		errno = err;
		mdb_warn("failed to read data at %#llx", addr + i - r);
		return (-1);
	}

	return (0);
}
