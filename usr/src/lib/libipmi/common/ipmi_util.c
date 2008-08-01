/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <libipmi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include "ipmi_impl.h"

/*
 * Extracts bits between index h (high, inclusive) and l (low, exclusive) from
 * u, which must be an unsigned integer.
 */
#define	BITX(u, h, l)	(((u) >> (l)) & ((1LU << ((h) - (l) + 1LU)) - 1LU))

/*
 * Error handling
 */
int
ipmi_set_error(ipmi_handle_t *ihp, int error, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);

	ihp->ih_errno = error;
	if (fmt == NULL)
		ihp->ih_errmsg[0] = '\0';
	else
		(void) vsnprintf(ihp->ih_errmsg, sizeof (ihp->ih_errmsg),
		    fmt, ap);
	va_end(ap);

	return (-1);
}

int
ipmi_errno(ipmi_handle_t *ihp)
{
	return (ihp->ih_errno);
}

/* ARGSUSED */
const char *
ipmi_errmsg(ipmi_handle_t *ihp)
{
	int i;
	const char *str;

	str = NULL;
	for (i = 0; ipmi_errno_table[i].int_name != NULL; i++) {
		if (ipmi_errno_table[i].int_value == ihp->ih_errno) {
			str = ipmi_errno_table[i].int_name;
			break;
		}
	}

	if (str == NULL && (str = strerror(ihp->ih_errno)) == NULL)
		str = "unknown failure";

	if (ihp->ih_errmsg[0] == '\0')
		return (str);

	(void) snprintf(ihp->ih_errbuf, sizeof (ihp->ih_errbuf),
	    "%s: %s", str, ihp->ih_errmsg);
	return (ihp->ih_errbuf);
}

/*
 * Memory allocation
 */
void *
ipmi_alloc(ipmi_handle_t *ihp, size_t size)
{
	void *ptr;

	if ((ptr = malloc(size)) == NULL)
		(void) ipmi_set_error(ihp, EIPMI_NOMEM, NULL);

	return (ptr);
}

void *
ipmi_zalloc(ipmi_handle_t *ihp, size_t size)
{
	void *ptr;

	if ((ptr = calloc(size, 1)) == NULL)
		(void) ipmi_set_error(ihp, EIPMI_NOMEM, NULL);

	return (ptr);
}

char *
ipmi_strdup(ipmi_handle_t *ihp, const char *str)
{
	char *ptr;

	if ((ptr = strdup(str)) == NULL)
		(void) ipmi_set_error(ihp, EIPMI_NOMEM, NULL);

	return (ptr);
}

/* ARGSUSED */
void
ipmi_free(ipmi_handle_t *ihp, void *ptr)
{
	free(ptr);
}

/*
 * Translation between #defines and strings.
 */
void
ipmi_entity_name(uint8_t id, char *buf, size_t len)
{
	ipmi_name_trans_t *ntp;

	for (ntp = &ipmi_entity_table[0]; ntp->int_name != NULL; ntp++) {
		if (ntp->int_value == id) {
			(void) strlcpy(buf, ntp->int_name, len);
			return;
		}
	}

	(void) snprintf(buf, len, "0x%02x", id);
}

void
ipmi_sensor_type_name(uint8_t type, char *buf, size_t len)
{
	ipmi_name_trans_t *ntp;

	for (ntp = &ipmi_sensor_type_table[0]; ntp->int_name != NULL; ntp++) {
		if (ntp->int_value == type) {
			(void) strlcpy(buf, ntp->int_name, len);
			return;
		}
	}

	(void) snprintf(buf, len, "0x%02x", type);
}

void
ipmi_sensor_units_name(uint8_t type, char *buf, size_t len)
{
	ipmi_name_trans_t *ntp;

	for (ntp = &ipmi_units_type_table[0]; ntp->int_name != NULL; ntp++) {
		if (ntp->int_value == type) {
			(void) strlcpy(buf, ntp->int_name, len);
			return;
		}
	}

	(void) snprintf(buf, len, "0x%02x", type);
}

void
ipmi_sensor_reading_name(uint8_t sensor_type, uint8_t reading_type,
    char *buf, size_t len)
{
	uint8_t val;
	ipmi_name_trans_t *ntp;

	if (reading_type == IPMI_RT_SPECIFIC) {
		val = sensor_type;
		ntp = &ipmi_sensor_type_table[0];
	} else {
		val = reading_type;
		ntp = &ipmi_reading_type_table[0];
	}

	for (; ntp->int_name != NULL; ntp++) {
		if (ntp->int_value == val) {
			(void) strlcpy(buf, ntp->int_name, len);
			return;
		}
	}

	if (reading_type == IPMI_RT_SPECIFIC)
		(void) snprintf(buf, len, "%02x/%02x", reading_type,
		    sensor_type);
	else
		(void) snprintf(buf, len, "%02x", reading_type);
}

/*
 * Converts a BCD decimal value to an integer.
 */
int
ipmi_convert_bcd(int value)
{
	int ret = 0;
	int digit;
	int i;

	for (i = 7; i >= 0; i--) {
		digit = ((value & (0xf << (i * 4))) >> (i * 4));
		ret += digit * 10 * i;
	}

	return (ret);
}

/*
 * See sections 43.15 and 43.16
 *
 * This is a utility function for decoding the strings that are packed into
 * sensor data records.  If the type is 6-bit packed ASCII, then it converts
 * the string to an 8-bit ASCII string and copies that into the suuplied buffer.
 * If it is 8-bit ASCII, it copies the string into the supplied buffer as-is.
 */
void
ipmi_decode_string(uint8_t type, uint8_t len, char *data, char *buf)
{
	int i, j = 0, chunks, leftovers;
	uint8_t tmp, lo;

	if (len == 0) {
		*buf = '\0';
		return;
	}
	/*
	 * If the type is 8-bit ASCII, we can simply copy the string and return
	 */
	if (type == 0x3) {
		(void) strncpy(buf, data, len);
		*(buf+len) = '\0';
		return;
	} else if (type == 0x1 || type == 0x0) {
		/*
		 * Yuck - they either used BCD plus encoding, which we don't
		 * currently handle, or they used an unspecified encoding type.
		 * In these cases we'll set buf to an empty string.  We still
		 * need to return the length so that we can get to the next
		 * record.
		 */
		*buf = '\0';
		return;
	}

	/*
	 * Otherwise, it's 6-bit packed ASCII, so we have to convert the
	 * data first
	 */
	chunks = len / 3;
	leftovers = len % 3;

	/*
	 * First we decode the 6-bit string in chunks of 3 bytes as far as
	 * possible
	 */
	for (i = 0; i < chunks; i++) {
		tmp = BITX(*(data+j), 5, 0);
		*buf++ = (char)(tmp + 32);

		lo = BITX(*(data+j++), 7, 6);
		tmp = BITX(*(data+j), 3, 0);
		tmp = (tmp << 2) | lo;
		*buf++ = (char)(tmp + 32);

		lo = BITX(*(data+j++), 7, 4);
		tmp = BITX(*(data+j), 1, 0);
		tmp = (tmp << 4) | lo;
		*buf++ = (char)(tmp + 32);

		tmp = BITX(*(data+j++), 7, 2);
		*buf++ = (char)(tmp + 32);
	}
	switch (leftovers) {
		case 1:
			tmp = BITX(*(data+j), 5, 0);
			*buf++ = (char)(tmp + 32);
			break;
		case 2:
			tmp = BITX(*(data+j), 5, 0);
			*buf++ = (char)(tmp + 32);

			lo = BITX(*(data+j++), 7, 6);
			tmp = BITX(*(data+j), 3, 0);
			tmp = (tmp << 2) | lo;
			*buf++ = (char)(tmp + 32);
			break;
	}
	*buf = '\0';
}
