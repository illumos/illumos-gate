/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 1999,2000,2001,2002,2003,2004  Free Software Foundation, Inc.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */
/*
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "fsys_zfs.h"


void
fletcher_2_native(const void *buf, uint64_t size, zio_cksum_t *zcp)
{
	const uint64_t *ip = buf;
	const uint64_t *ipend = ip + (size / sizeof (uint64_t));
	uint64_t a0, b0, a1, b1;

	for (a0 = b0 = a1 = b1 = 0; ip < ipend; ip += 2) {
		a0 += ip[0];
		a1 += ip[1];
		b0 += a0;
		b1 += a1;
	}

	ZIO_SET_CHECKSUM(zcp, a0, a1, b0, b1);
}

void
fletcher_2_byteswap(const void *buf, uint64_t size, zio_cksum_t *zcp)
{
	const uint64_t *ip = buf;
	const uint64_t *ipend = ip + (size / sizeof (uint64_t));
	uint64_t a0, b0, a1, b1;

	for (a0 = b0 = a1 = b1 = 0; ip < ipend; ip += 2) {
		a0 += BSWAP_64(ip[0]);
		a1 += BSWAP_64(ip[1]);
		b0 += a0;
		b1 += a1;
	}

	ZIO_SET_CHECKSUM(zcp, a0, a1, b0, b1);
}

void
fletcher_4_native(const void *buf, uint64_t size, zio_cksum_t *zcp)
{
	const uint32_t *ip = buf;
	const uint32_t *ipend = ip + (size / sizeof (uint32_t));
	uint64_t a, b, c, d;

	for (a = b = c = d = 0; ip < ipend; ip++) {
		a += ip[0];
		b += a;
		c += b;
		d += c;
	}

	ZIO_SET_CHECKSUM(zcp, a, b, c, d);
}

void
fletcher_4_byteswap(const void *buf, uint64_t size, zio_cksum_t *zcp)
{
	const uint32_t *ip = buf;
	const uint32_t *ipend = ip + (size / sizeof (uint32_t));
	uint64_t a, b, c, d;

	for (a = b = c = d = 0; ip < ipend; ip++) {
		a += BSWAP_32(ip[0]);
		b += a;
		c += b;
		d += c;
	}

	ZIO_SET_CHECKSUM(zcp, a, b, c, d);
}
