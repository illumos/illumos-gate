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
 * Copyright (c) 2014, Joyent, Inc.
 */

#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <wchar.h>
#include <sys/debug.h>
#include <stdarg.h>
#include <assert.h>

#include "libnvpair.h"

#define	FPRINTF(bufp, blen, offp, ...)			\
	do {						\
		if (nvlist_rasnprintf(bufp, blen, offp,	\
		    __VA_ARGS__) < 0)			\
			return (-1);			\
	} while (0)

/*
 * A realloc-aware snprintf/asprintf like function.
 */
/*PRINTFLIKE4*/
static int
nvlist_rasnprintf(char **bufp, size_t *blen, off_t *boff, char *input, ...)
{
	int ret;
	va_list ap;
	size_t size, asize;
	char *b;

	if (*bufp == NULL) {
		assert(*blen == 0);
		assert(*boff == 0);
		/* Pick a reasonable starting point, let's say 1k */
		*blen = 1024;
		*bufp = malloc(*blen);
		if (*bufp == NULL)
			return (-1);
	}

	size = *blen - *boff;
	va_start(ap, input);
	/* E_SEC_PRINTF_VAR_FMT */
	ret = vsnprintf(*bufp + *boff, size, input, ap);
	va_end(ap);
	if (ret < 0) {
		va_end(ap);
		return (-1);
	}
	if (ret >= size) {
		asize = *blen;
		while (ret >= asize)
			asize += 1024;
		if ((b = realloc(*bufp, asize)) == NULL)
			return (-1);
		*bufp = b;
		*blen = asize;
		size = *blen - *boff;
		va_start(ap, input);
		/* E_SEC_PRINTF_VAR_FMT */
		ret = vsnprintf(*bufp + *boff, size, input, ap);
		va_end(ap);
		if (ret < 0)
			return (-1);
		assert(ret < size);
	}
	*boff += ret;

	return (0);
}

/*
 * When formatting a string for JSON output we must escape certain characters,
 * as described in RFC4627.  This applies to both member names and
 * DATA_TYPE_STRING values.
 *
 * This function will only operate correctly if the following conditions are
 * met:
 *
 *       1. The input String is encoded in the current locale.
 *
 *       2. The current locale includes the Basic Multilingual Plane (plane 0)
 *          as defined in the Unicode standard.
 *
 * The output will be entirely 7-bit ASCII (as a subset of UTF-8) with all
 * representable Unicode characters included in their escaped numeric form.
 */
static int
nvlist_print_json_string(const char *input, char **bufp, size_t *blen,
    off_t *offp)
{
	mbstate_t mbr;
	wchar_t c;
	size_t sz;

	bzero(&mbr, sizeof (mbr));

	FPRINTF(bufp, blen, offp, "\"");
	while ((sz = mbrtowc(&c, input, MB_CUR_MAX, &mbr)) > 0) {
		switch (c) {
		case '"':
			FPRINTF(bufp, blen, offp, "\\\"");
			break;
		case '\n':
			FPRINTF(bufp, blen, offp, "\\n");
			break;
		case '\r':
			FPRINTF(bufp, blen, offp, "\\r");
			break;
		case '\\':
			FPRINTF(bufp, blen, offp, "\\\\");
			break;
		case '\f':
			FPRINTF(bufp, blen, offp, "\\f");
			break;
		case '\t':
			FPRINTF(bufp, blen, offp, "\\t");
			break;
		case '\b':
			FPRINTF(bufp, blen, offp, "\\b");
			break;
		default:
			if ((c >= 0x00 && c <= 0x1f) ||
			    (c > 0x7f && c <= 0xffff)) {
				/*
				 * Render both Control Characters and Unicode
				 * characters in the Basic Multilingual Plane
				 * as JSON-escaped multibyte characters.
				 */
				FPRINTF(bufp, blen, offp, "\\u%04x",
				    (int)(0xffff & c));
			} else if (c >= 0x20 && c <= 0x7f) {
				/*
				 * Render other 7-bit ASCII characters directly
				 * and drop other, unrepresentable characters.
				 */
				FPRINTF(bufp, blen, offp, "%c",
				    (int)(0xff & c));
			}
			break;
		}
		input += sz;
	}

	if (sz == (size_t)-1 || sz == (size_t)-2) {
		/*
		 * We last read an invalid multibyte character sequence,
		 * so return an error.
		 */
		return (-1);
	}

	FPRINTF(bufp, blen, offp, "\"");
	return (0);
}

static int
nvlist_do_json(nvlist_t *nvl, char **bufp, size_t *blen, off_t *offp)
{
	nvpair_t *curr;
	boolean_t first = B_TRUE;

	FPRINTF(bufp, blen, offp, "{");

	for (curr = nvlist_next_nvpair(nvl, NULL); curr;
	    curr = nvlist_next_nvpair(nvl, curr)) {
		data_type_t type = nvpair_type(curr);

		if (!first)
			FPRINTF(bufp, blen, offp, ",");
		else
			first = B_FALSE;

		if (nvlist_print_json_string(nvpair_name(curr), bufp, blen,
		    offp) == -1)
			return (-1);
		FPRINTF(bufp, blen, offp, ":");

		switch (type) {
		case DATA_TYPE_STRING: {
			char *string = fnvpair_value_string(curr);
			if (nvlist_print_json_string(string, bufp, blen,
			    offp) == -1)
				return (-1);
			break;
		}

		case DATA_TYPE_BOOLEAN: {
			FPRINTF(bufp, blen, offp, "true");
			break;
		}

		case DATA_TYPE_BOOLEAN_VALUE: {
			FPRINTF(bufp, blen, offp, "%s",
			    fnvpair_value_boolean_value(curr) == B_TRUE ?
			    "true" : "false");
			break;
		}

		case DATA_TYPE_BYTE: {
			FPRINTF(bufp, blen, offp, "%hhu",
			    fnvpair_value_byte(curr));
			break;
		}

		case DATA_TYPE_INT8: {
			FPRINTF(bufp, blen, offp, "%hhd",
			    fnvpair_value_int8(curr));
			break;
		}

		case DATA_TYPE_UINT8: {
			FPRINTF(bufp, blen, offp, "%hhu",
			    fnvpair_value_uint8_t(curr));
			break;
		}

		case DATA_TYPE_INT16: {
			FPRINTF(bufp, blen, offp, "%hd",
			    fnvpair_value_int16(curr));
			break;
		}

		case DATA_TYPE_UINT16: {
			FPRINTF(bufp, blen, offp, "%hu",
			    fnvpair_value_uint16(curr));
			break;
		}

		case DATA_TYPE_INT32: {
			FPRINTF(bufp, blen, offp, "%d",
			    fnvpair_value_int32(curr));
			break;
		}

		case DATA_TYPE_UINT32: {
			FPRINTF(bufp, blen, offp, "%u",
			    fnvpair_value_uint32(curr));
			break;
		}

		case DATA_TYPE_INT64: {
			FPRINTF(bufp, blen, offp, "%lld",
			    (long long)fnvpair_value_int64(curr));
			break;
		}

		case DATA_TYPE_UINT64: {
			FPRINTF(bufp, blen, offp, "%llu",
			    (unsigned long long)fnvpair_value_uint64(curr));
			break;
		}

		case DATA_TYPE_HRTIME: {
			hrtime_t val;
			VERIFY0(nvpair_value_hrtime(curr, &val));
			FPRINTF(bufp, blen, offp, "%llu",
			    (unsigned long long)val);
			break;
		}

		case DATA_TYPE_DOUBLE: {
			double val;
			VERIFY0(nvpair_value_double(curr, &val));
			FPRINTF(bufp, blen, offp, "%f", val);
			break;
		}

		case DATA_TYPE_NVLIST: {
			if (nvlist_do_json(fnvpair_value_nvlist(curr), bufp,
			    blen, offp) == -1)
				return (-1);
			break;
		}

		case DATA_TYPE_STRING_ARRAY: {
			char **val;
			uint_t valsz, i;
			VERIFY0(nvpair_value_string_array(curr, &val, &valsz));
			FPRINTF(bufp, blen, offp, "[");
			for (i = 0; i < valsz; i++) {
				if (i > 0)
					FPRINTF(bufp, blen, offp, ",");
				if (nvlist_print_json_string(val[i], bufp,
				    blen, offp) == -1)
					return (-1);
			}
			FPRINTF(bufp, blen, offp, "]");
			break;
		}

		case DATA_TYPE_NVLIST_ARRAY: {
			nvlist_t **val;
			uint_t valsz, i;
			VERIFY0(nvpair_value_nvlist_array(curr, &val, &valsz));
			FPRINTF(bufp, blen, offp, "[");
			for (i = 0; i < valsz; i++) {
				if (i > 0)
					FPRINTF(bufp, blen, offp, ",");
				if (nvlist_do_json(val[i], bufp, blen,
				    offp) == -1)
					return (-1);
			}
			FPRINTF(bufp, blen, offp, "]");
			break;
		}

		case DATA_TYPE_BOOLEAN_ARRAY: {
			boolean_t *val;
			uint_t valsz, i;
			VERIFY0(nvpair_value_boolean_array(curr, &val, &valsz));
			FPRINTF(bufp, blen, offp, "[");
			for (i = 0; i < valsz; i++) {
				if (i > 0)
					FPRINTF(bufp, blen, offp, ",");
				FPRINTF(bufp, blen, offp, val[i] == B_TRUE ?
				    "true" : "false");
			}
			FPRINTF(bufp, blen, offp, "]");
			break;
		}

		case DATA_TYPE_BYTE_ARRAY: {
			uchar_t *val;
			uint_t valsz, i;
			VERIFY0(nvpair_value_byte_array(curr, &val, &valsz));
			FPRINTF(bufp, blen, offp, "[");
			for (i = 0; i < valsz; i++) {
				if (i > 0)
					FPRINTF(bufp, blen, offp, ",");
				FPRINTF(bufp, blen, offp, "%hhu", val[i]);
			}
			FPRINTF(bufp, blen, offp, "]");
			break;
		}

		case DATA_TYPE_UINT8_ARRAY: {
			uint8_t *val;
			uint_t valsz, i;
			VERIFY0(nvpair_value_uint8_array(curr, &val, &valsz));
			FPRINTF(bufp, blen, offp, "[");
			for (i = 0; i < valsz; i++) {
				if (i > 0)
					FPRINTF(bufp, blen, offp, ",");
				FPRINTF(bufp, blen, offp, "%hhu", val[i]);
			}
			FPRINTF(bufp, blen, offp, "]");
			break;
		}

		case DATA_TYPE_INT8_ARRAY: {
			int8_t *val;
			uint_t valsz, i;
			VERIFY0(nvpair_value_int8_array(curr, &val, &valsz));
			FPRINTF(bufp, blen, offp, "[");
			for (i = 0; i < valsz; i++) {
				if (i > 0)
					FPRINTF(bufp, blen, offp, ",");
				FPRINTF(bufp, blen, offp, "%hd", val[i]);
			}
			FPRINTF(bufp, blen, offp, "]");
			break;
		}

		case DATA_TYPE_UINT16_ARRAY: {
			uint16_t *val;
			uint_t valsz, i;
			VERIFY0(nvpair_value_uint16_array(curr, &val, &valsz));
			FPRINTF(bufp, blen, offp, "[");
			for (i = 0; i < valsz; i++) {
				if (i > 0)
					FPRINTF(bufp, blen, offp, ",");
				FPRINTF(bufp, blen, offp, "%hu", val[i]);
			}
			FPRINTF(bufp, blen, offp, "]");
			break;
		}

		case DATA_TYPE_INT16_ARRAY: {
			int16_t *val;
			uint_t valsz, i;
			VERIFY0(nvpair_value_int16_array(curr, &val, &valsz));
			FPRINTF(bufp, blen, offp, "[");
			for (i = 0; i < valsz; i++) {
				if (i > 0)
					FPRINTF(bufp, blen, offp, ",");
				FPRINTF(bufp, blen, offp, "%hd", val[i]);
			}
			FPRINTF(bufp, blen, offp, "]");
			break;
		}

		case DATA_TYPE_UINT32_ARRAY: {
			uint32_t *val;
			uint_t valsz, i;
			VERIFY0(nvpair_value_uint32_array(curr, &val, &valsz));
			FPRINTF(bufp, blen, offp, "[");
			for (i = 0; i < valsz; i++) {
				if (i > 0)
					FPRINTF(bufp, blen, offp, ",");
				FPRINTF(bufp, blen, offp, "%u", val[i]);
			}
			FPRINTF(bufp, blen, offp, "]");
			break;
		}

		case DATA_TYPE_INT32_ARRAY: {
			int32_t *val;
			uint_t valsz, i;
			VERIFY0(nvpair_value_int32_array(curr, &val, &valsz));
			FPRINTF(bufp, blen, offp, "[");
			for (i = 0; i < valsz; i++) {
				if (i > 0)
					FPRINTF(bufp, blen, offp, ",");
				FPRINTF(bufp, blen, offp, "%d", val[i]);
			}
			FPRINTF(bufp, blen, offp, "]");
			break;
		}

		case DATA_TYPE_UINT64_ARRAY: {
			uint64_t *val;
			uint_t valsz, i;
			VERIFY0(nvpair_value_uint64_array(curr, &val, &valsz));
			FPRINTF(bufp, blen, offp, "[");
			for (i = 0; i < valsz; i++) {
				if (i > 0)
					FPRINTF(bufp, blen, offp, ",");
				FPRINTF(bufp, blen, offp, "%llu",
				    (unsigned long long)val[i]);
			}
			FPRINTF(bufp, blen, offp, "]");
			break;
		}

		case DATA_TYPE_INT64_ARRAY: {
			int64_t *val;
			uint_t valsz, i;
			VERIFY0(nvpair_value_int64_array(curr, &val, &valsz));
			FPRINTF(bufp, blen, offp, "[");
			for (i = 0; i < valsz; i++) {
				if (i > 0)
					FPRINTF(bufp, blen, offp, ",");
				FPRINTF(bufp, blen, offp, "%lld",
				    (long long)val[i]);
			}
			FPRINTF(bufp, blen, offp, "]");
			break;
		}

		case DATA_TYPE_UNKNOWN:
			return (-1);
		}
	}

	FPRINTF(bufp, blen, offp, "}");
	return (0);
}

int
nvlist_dump_json(nvlist_t *nvl, char **bufp)
{
	off_t off = 0;
	size_t l = 0;

	*bufp = NULL;
	return (nvlist_do_json(nvl, bufp, &l, &off));
}

/* ARGSUSED */
void
nvlist_dump_json_free(nvlist_t *nvl, char *buf)
{
	free(buf);
}

/*
 * Dump a JSON-formatted representation of an nvlist to the provided FILE *.
 * This routine does not output any new-lines or additional whitespace other
 * than that contained in strings, nor does it call fflush(3C).
 */
int
nvlist_print_json(FILE *fp, nvlist_t *nvl)
{
	int ret;
	char *buf;

	if ((ret = nvlist_dump_json(nvl, &buf)) < 0)
		return (ret);
	ret = fprintf(fp, "%s", buf);
	nvlist_dump_json_free(nvl, buf);
	return (ret);
}
