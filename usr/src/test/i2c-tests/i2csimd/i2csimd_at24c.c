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
 * Basic emulation of the AT24C family devices.
 */

#include <stdlib.h>
#include <string.h>
#include <err.h>
#include <sys/sysmacros.h>

#include "i2csimd.h"

typedef struct at24c {
	uint8_t *at_data;
	uint32_t at_len;
	uint8_t at_page;
	bool at_addr16;
	uint16_t at_curaddr;
} at24c_t;

static bool
at24c_write(void *arg, uint32_t len, const uint8_t *buf)
{
	at24c_t *at24c = arg;

	/*
	 * If we have no data to write, then we're done and that's fine.
	 */
	if (len == 0) {
		return (true);
	}

	/*
	 * The first byte or two (depending on the part) always indicates the
	 * address that we should write to. If we require a 2-byte address but
	 * we don't have enough bytes, it's not quite clear what the device
	 * expects. We just treat it as setting the high byte.
	 */
	if (at24c->at_addr16) {
		at24c->at_curaddr = buf[0] << 8;
		if (len == 1) {
			return (true);
		}
		at24c->at_curaddr |= buf[1];
		len -= 2;
		buf += 2;
	} else {
		at24c->at_curaddr = buf[0];
		len--;
		buf++;
	}

	/*
	 * Now that we've set the address, write to data within the page. Note
	 * that once we hit the end of the page, we go back to the start of the
	 * page.
	 */
	while (len > 0) {
		uint32_t page_start = at24c->at_curaddr &
		    ~(at24c->at_page - 1);
		uint32_t page_end = page_start + at24c->at_page - 1;
		uint32_t page_rem = page_end - at24c->at_curaddr + 1;
		uint32_t towrite = MIN(page_rem, len);

		(void) memcpy(&at24c->at_data[at24c->at_curaddr], buf, towrite);
		len -= towrite;
		buf += towrite;
		at24c->at_curaddr += towrite;
		if (at24c->at_curaddr == page_end + 1) {
			at24c->at_curaddr = page_start;
		}
	}

	return (true);
}

static bool
at24c_read(void *arg, uint32_t len, uint8_t *buf)
{
	at24c_t *at24c = arg;

	/*
	 * Read from the current device offset. It should be incremented when
	 * we're done. If we read the entire device, then we wrap around to the
	 * start.
	 */
	while (len > 0) {
		uint16_t rem = at24c->at_len - at24c->at_curaddr + 1;
		uint16_t toread = MIN(rem, len);

		(void) memcpy(buf, &at24c->at_data[at24c->at_curaddr], toread);
		len -= toread;
		buf += toread;
		at24c->at_curaddr += toread;
		if (at24c->at_curaddr == at24c->at_len)
			at24c->at_curaddr = 0;
	}

	return (true);
}

static const i2csimd_ops_t at24c_ops = {
	.sop_write = at24c_write,
	.sop_read = at24c_read
};

static i2csimd_dev_t *
i2csimd_make_at24c(uint8_t addr, const char *data, size_t dlen, uint32_t len,
    uint8_t page, bool addr16)
{
	at24c_t *at24c = calloc(1, sizeof (at24c_t));
	if (at24c == NULL) {
		err(EXIT_FAILURE, "failed to allocate at24c");
	}

	at24c->at_len = len;
	at24c->at_data = calloc(sizeof (uint8_t), len);
	if (at24c->at_data == NULL) {
		err(EXIT_FAILURE, "failed to allocate %u bytes for data", len);
	}

	(void) memset(at24c->at_data, 0xff, at24c->at_len);
	if (dlen > 0) {
		(void) memcpy(at24c->at_data, data, dlen);
	}

	at24c->at_page = page;
	at24c->at_addr16 = addr16;

	i2csimd_dev_t *dev = calloc(1, sizeof (i2csimd_dev_t));
	if (dev == NULL) {
		err(EXIT_FAILURE, "failed to allocate i2csimd_dev_t");
	}

	dev->dev_name = "at24c";
	dev->dev_addr = addr;
	dev->dev_arg = at24c;
	dev->dev_ops = &at24c_ops;

	return (dev);
}

i2csimd_dev_t *
i2csimd_make_at24c32(uint8_t addr, const char *data, size_t len)
{
	return (i2csimd_make_at24c(addr, data, len, 4096, 32, true));
}

/*
 * This makes a 256-bit AT24C slice that is 256 bytes wide. This is designed for
 * the multi-address devices like the at24c04 or at24c16.
 */
i2csimd_dev_t *
i2csimd_make_at24cXX(uint8_t addr, const char *data, size_t len)
{
	return (i2csimd_make_at24c(addr, data, len, 256, 16, false));
}
