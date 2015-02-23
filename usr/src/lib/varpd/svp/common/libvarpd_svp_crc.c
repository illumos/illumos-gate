/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2015, Joyent, Inc.
 */

/*
 * Perform standard crc32 functions.
 *
 * For more information, see the big theory statement in
 * lib/varpd/svp/common/libvarpd_svp.c.
 *
 * Really, this should just be a libcrc.
 */

#include <sys/crc32.h>
#include <stdint.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <inttypes.h>
#include <libvarpd_svp.h>

static uint32_t svp_crc32_tab[] = { CRC32_TABLE };

static uint32_t
svp_crc32(uint32_t old, const uint8_t *buf, size_t len)
{
	uint32_t out;

	CRC32(out, buf, len, old, svp_crc32_tab);
	return (out);
}

void
svp_query_crc32(svp_req_t *shp, void *buf, size_t data)
{
	uint32_t crc = -1U;

	shp->svp_crc32 = 0;
	crc = svp_crc32(crc, (uint8_t *)shp, sizeof (svp_req_t));
	crc = svp_crc32(crc, buf, data);
	crc = ~crc;
	shp->svp_crc32 = htonl(crc);
}
