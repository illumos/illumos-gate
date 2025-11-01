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
 * Copyright 2025 Oxide Computer Company
 */

/*
 * Minimally emulate a TS5111. We use a basic register template for this. We
 * allow a minimum number of writable registers, but that doesn't change
 * behavior for anything. We will ignore any attempts to go to I3C mode or to
 * change the default read address mode and starting point.
 */

#include <stdlib.h>
#include <string.h>
#include <err.h>
#include <sys/sysmacros.h>
#include <sys/bitext.h>

#include "i2csimd.h"

#define	TS5111_REGLEN	256

typedef struct ts5111 {
	uint8_t ts_data[TS5111_REGLEN];
	uint8_t ts_curaddr;
} ts5111_t;

/*
 * Default register values from the spec, ignoring what we're going to set for
 * the temperature when this is created.
 */
static const uint8_t ts5111_tmpl[TS5111_REGLEN] = {
	[0x00] = 0x51,
	[0x01] = 0x11,
	[0x02] = 0x12,
	[0x03] = 0x00,
	[0x04] = 0x01,
	[0x07] = 0x0e,
	[0x28] = 0x70,
	[0x29] = 0x03,
	[0x32] = 0x50,
	[0x33] = 0x05
};

/*
 * While we could emulate and support writes for a subset of the device space
 * that's writable, we just discard everything other than setting the current
 * address because we don't need it.
 */
static bool
ts5111_write(void *arg, uint32_t len, const uint8_t *buf)
{
	ts5111_t *ts = arg;

	if (len > 0) {
		ts->ts_curaddr = buf[0];
	}

	return (true);
}

/*
 * If someone reads past the end of the device, we just wrap to the start.
 */
static bool
ts5111_read(void *arg, uint32_t len, uint8_t *buf)
{
	ts5111_t *ts = arg;

	while (len > 0) {
		uint16_t rem = sizeof (ts->ts_data) - ts->ts_curaddr + 1;
		uint16_t toread = MIN(rem, len);

		(void) memcpy(buf, &ts->ts_data[ts->ts_curaddr], toread);
		buf += toread;
		len -= toread;
		ts->ts_curaddr += toread;
	}

	return (true);
}

static const i2csimd_ops_t ts5111_ops = {
	.sop_write = ts5111_write,
	.sop_read = ts5111_read
};

i2csimd_dev_t *
i2csimd_make_ts5111(uint8_t addr, uint16_t temp)
{
	ts5111_t *ts = calloc(1, sizeof (ts5111_t));
	if (ts == NULL) {
		err(EXIT_FAILURE, "failed to allocate a ts5111_t");
	}

	(void) memcpy(ts->ts_data, ts5111_tmpl, sizeof (ts5111_tmpl));
	ts->ts_data[0x31] = bitx16(temp, 7, 0);
	ts->ts_data[0x32] = bitx16(temp, 15, 8);

	i2csimd_dev_t *dev = calloc(1, sizeof (i2csimd_dev_t));
	if (dev == NULL) {
		err(EXIT_FAILURE, "failed to allocate i2csimd_dev_t");
	}

	dev->dev_name = "ts5111";
	dev->dev_addr = addr;
	dev->dev_arg = ts;
	dev->dev_ops = &ts5111_ops;

	return (dev);
}
