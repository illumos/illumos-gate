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
 * Copyright 2026 Argo Technology East
 */

/*
 * Pack and unpack the EFI_LOAD_OPTION record (UEFI 2.10 section 3.1.3),
 * the on-disk shape of any Boot####, Driver#### or SysPrep#### variable.
 *
 * The record is little-endian and tightly packed:
 *
 *   uint32_t Attributes
 *   uint16_t FilePathListLength
 *   CHAR16   Description[]            (NUL-terminated UCS-2 LE)
 *   uint8_t  FilePathList[FilePathListLength]
 *   uint8_t  OptionalData[]
 *
 * The end of OptionalData is the variable length, so we have to read
 * datasize from the caller.
 */

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>

#include <libefivar.h>

#include "libefivar_impl.h"

/*
 * Helpers to read/write little-endian fields from an unaligned byte
 * buffer.  The host (amd64) is little-endian so a memcpy is enough.
 */
static uint16_t
le16_read(const uint8_t *p)
{
	uint16_t v;
	(void) memcpy(&v, p, sizeof (v));
	return (v);
}

static uint32_t
le32_read(const uint8_t *p)
{
	uint32_t v;
	(void) memcpy(&v, p, sizeof (v));
	return (v);
}

static void
le16_write(uint8_t *p, uint16_t v)
{
	(void) memcpy(p, &v, sizeof (v));
}

static void
le32_write(uint8_t *p, uint32_t v)
{
	(void) memcpy(p, &v, sizeof (v));
}

int
efi_load_option_parse(const uint8_t *data, size_t datasize,
    efi_load_option_t *out)
{
	size_t off, ndesc_chars, dp_off, opt_off, fpllen;
	int saved;

	bzero(out, sizeof (*out));

	if (data == NULL || datasize < sizeof (uint32_t) + sizeof (uint16_t)) {
		errno = EINVAL;
		return (-1);
	}

	out->elo_attributes = le32_read(data);
	fpllen = le16_read(data + sizeof (uint32_t));

	off = sizeof (uint32_t) + sizeof (uint16_t);

	/*
	 * Description: NUL-terminated CHAR16 array starting at off.
	 * Walk until we find a zero CHAR16 or run off the end.
	 */
	ndesc_chars = 0;
	while (off + (ndesc_chars + 1) * sizeof (uint16_t) <= datasize) {
		if (le16_read(data + off +
		    ndesc_chars * sizeof (uint16_t)) == 0)
			break;
		ndesc_chars++;
	}
	if (off + (ndesc_chars + 1) * sizeof (uint16_t) > datasize) {
		errno = EINVAL;
		return (-1);
	}

	/* Convert description (excluding NUL) to UTF-8. */
	if (_efivar_ucs2_to_ascii((const uint16_t *)(data + off),
	    ndesc_chars * sizeof (uint16_t), &out->elo_description) < 0)
		return (-1);

	/* Device path follows the description. */
	dp_off = off + (ndesc_chars + 1) * sizeof (uint16_t);
	if (dp_off + fpllen > datasize) {
		saved = errno = EINVAL;
		goto fail;
	}
	if (fpllen > 0) {
		out->elo_device_path = malloc(fpllen);
		if (out->elo_device_path == NULL) {
			saved = errno;
			goto fail;
		}
		(void) memcpy(out->elo_device_path, data + dp_off, fpllen);
	}
	out->elo_device_path_size = fpllen;

	/* Anything after the device path is optional data. */
	opt_off = dp_off + fpllen;
	if (opt_off < datasize) {
		out->elo_optional_data_size = datasize - opt_off;
		out->elo_optional_data = malloc(out->elo_optional_data_size);
		if (out->elo_optional_data == NULL) {
			saved = errno;
			goto fail;
		}
		(void) memcpy(out->elo_optional_data, data + opt_off,
		    out->elo_optional_data_size);
	}

	return (0);

fail:
	efi_load_option_clear(out);
	errno = saved;
	return (-1);
}

int
efi_load_option_build(const efi_load_option_t *in, uint8_t **out_p,
    size_t *outsize_p)
{
	uint16_t *desc16 = NULL;
	size_t desc16_size = 0;
	size_t total;
	uint8_t *buf;
	uint8_t *p;
	int saved;

	if (in == NULL || in->elo_description == NULL ||
	    in->elo_device_path_size > UINT16_MAX) {
		errno = EINVAL;
		return (-1);
	}

	if (_efivar_ascii_to_ucs2(in->elo_description, &desc16,
	    &desc16_size) < 0)
		return (-1);

	total = sizeof (uint32_t) + sizeof (uint16_t) + desc16_size +
	    in->elo_device_path_size + in->elo_optional_data_size;

	if (total < desc16_size || total < in->elo_device_path_size ||
	    total < in->elo_optional_data_size) {
		free(desc16);
		errno = EOVERFLOW;
		return (-1);
	}

	buf = malloc(total);
	if (buf == NULL) {
		saved = errno;
		free(desc16);
		errno = saved;
		return (-1);
	}

	p = buf;
	le32_write(p, in->elo_attributes);
	p += sizeof (uint32_t);
	le16_write(p, (uint16_t)in->elo_device_path_size);
	p += sizeof (uint16_t);
	(void) memcpy(p, desc16, desc16_size);
	p += desc16_size;
	if (in->elo_device_path_size > 0) {
		(void) memcpy(p, in->elo_device_path,
		    in->elo_device_path_size);
		p += in->elo_device_path_size;
	}
	if (in->elo_optional_data_size > 0) {
		(void) memcpy(p, in->elo_optional_data,
		    in->elo_optional_data_size);
	}

	free(desc16);
	*out_p = buf;
	*outsize_p = total;
	return (0);
}

void
efi_load_option_clear(efi_load_option_t *opt)
{
	if (opt == NULL)
		return;
	free(opt->elo_description);
	free(opt->elo_device_path);
	free(opt->elo_optional_data);
	bzero(opt, sizeof (*opt));
}
