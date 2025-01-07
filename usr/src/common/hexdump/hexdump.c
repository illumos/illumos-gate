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
 * Copyright 2024 Oxide Computer Company
 */

/*
 * A generic hexdump implementation suitable for use in the kernel or userland.
 * The output style is influenced by mdb's ::dump.
 */

#include <sys/ilstr.h>
#include <sys/kmem.h>
#include <sys/stdbool.h>
#include <sys/sysmacros.h>
#include <sys/hexdump.h>

#ifdef _KERNEL
#include <sys/sunddi.h>
#include <sys/errno.h>
#else
#include <stdint.h>
#include <stdio.h>
#include <strings.h>
#include <errno.h>
#endif

#define	HD_DEFGROUPING		1
#define	HD_DEFWIDTH		16

/*
 * We use a simple comparison to determine whether a character is printable in
 * the ASCII table. This is unaffected by locale settings and provides
 * consistent results regardless of the environment.
 */
#define	HEXDUMP_PRINTABLE(c) ((c) >= ' ' && (c) <= '~')

typedef struct {
	uint64_t	hdp_flags;
	uint8_t		hdp_grouping;	/* display bytes in groups of.. */
	uint8_t		hdp_width;	/* bytes per row */
	uint8_t		hdp_indent;	/* indent size */

	const uint8_t	*hdp_data;	/* Data to dump */
	uint64_t	hdp_len;	/* Length of data */

	uint8_t		hdp_addrwidth;	/* Width of address field */
	uint64_t	hdp_bufaddr;	/* The supplied buffer address */
	uint64_t	hdp_baseaddr;	/* The base address for aligned print */
	uint64_t	hdp_adj;	/* The adjustment (buf - base) */

	ilstr_t		hdp_buf;	/* Working buffer */
	ilstr_t		hdp_pbuf;	/* Previous line */
	uint64_t	hdp_offset;	/* Current offset */
	uint8_t		hdp_marker;	/* Marker offset */
} hexdump_param_t;

#ifdef _KERNEL
/*
 * In the kernel we do not have flsll, and ddi_fls is not available until
 * genunix is loaded. Since we wish to be usable before that point, provide a
 * simple alternative.
 */
static int
flsll(unsigned long x)
{
	int pos = 0;

	while (x != 0) {
		pos++;
		x >>= 1;
	}

	return (pos);
}
#endif /* _KERNEL */

void
hexdump_init(hexdump_t *h)
{
	bzero(h, sizeof (*h));
	h->h_grouping = HD_DEFGROUPING;
	h->h_width = HD_DEFWIDTH;
}

void
hexdump_fini(hexdump_t *h __unused)
{
}

void
hexdump_set_width(hexdump_t *h, uint8_t width)
{
	if (width == 0)
		h->h_width = HD_DEFWIDTH;
	else
		h->h_width = width;
}

void
hexdump_set_grouping(hexdump_t *h, uint8_t grouping)
{
	if (grouping == 0)
		h->h_grouping = 1;
	else
		h->h_grouping = grouping;
}

void
hexdump_set_indent(hexdump_t *h, uint8_t indent)
{
	h->h_indent = indent;
}

void
hexdump_set_addr(hexdump_t *h, uint64_t addr)
{
	h->h_addr = addr;
}

void
hexdump_set_addrwidth(hexdump_t *h, uint8_t width)
{
	h->h_addrwidth = width;
}

void
hexdump_set_marker(hexdump_t *h, uint8_t marker)
{
	h->h_marker = marker;
}

void
hexdump_set_buf(hexdump_t *h, uint8_t *buf, size_t buflen)
{
	h->h_buf = buf;
	h->h_buflen = buflen;
}

static void
hexdump_space(hexdump_param_t *hdp, uint_t idx)
{
	if (idx != 0 && idx % hdp->hdp_grouping == 0) {
		ilstr_append_char(&hdp->hdp_buf, ' ');
		/*
		 * If we are putting each byte in its own group, add an extra
		 * space every 8 bytes to improve readability.
		 */
		if (hdp->hdp_grouping == 1 && idx % 8 == 0)
			ilstr_append_char(&hdp->hdp_buf, ' ');
	}
	if (idx != 0 && hdp->hdp_flags & HDF_DOUBLESPACE)
		ilstr_append_char(&hdp->hdp_buf, ' ');
}

static void
hexdump_header(hexdump_param_t *hdp)
{
	int markerpos = -1;

	if (hdp->hdp_indent != 0)
		ilstr_aprintf(&hdp->hdp_buf, "%*s", hdp->hdp_indent, "");

	if (hdp->hdp_flags & HDF_ADDRESS)
		ilstr_aprintf(&hdp->hdp_buf, "%*s   ", hdp->hdp_addrwidth, "");

	for (uint_t i = 0; i < hdp->hdp_width; i++) {
		hexdump_space(hdp, i);

		if ((hdp->hdp_marker > 0 && i == hdp->hdp_marker) ||
		    ((hdp->hdp_flags & HDF_ALIGN) &&
		    hdp->hdp_baseaddr + i == hdp->hdp_bufaddr)) {
			ilstr_append_str(&hdp->hdp_buf, "\\/");
			markerpos = i;
		} else {
			ilstr_aprintf(&hdp->hdp_buf, "%2x",
			    (i + hdp->hdp_offset) & 0xf);
		}
	}

	if (hdp->hdp_flags & HDF_ASCII) {
		ilstr_append_str(&hdp->hdp_buf, "   ");
		for (uint_t i = 0; i < hdp->hdp_width; i++) {
			if (markerpos != -1 && markerpos == i) {
				ilstr_append_char(&hdp->hdp_buf, 'v');
			} else {
				ilstr_aprintf(&hdp->hdp_buf, "%x",
				    (i + hdp->hdp_offset) & 0xf);
			}
		}
	}
}

static void
hexdump_data(hexdump_param_t *hdp)
{
	uint64_t addr = hdp->hdp_baseaddr + hdp->hdp_offset;

	if (hdp->hdp_indent != 0)
		ilstr_aprintf(&hdp->hdp_buf, "%*s", hdp->hdp_indent, "");

	if (hdp->hdp_flags & HDF_ADDRESS) {
		ilstr_aprintf(&hdp->hdp_buf, "%0*llx:  ",
		    hdp->hdp_addrwidth, addr);
	}

	for (uint_t i = 0; i < hdp->hdp_width; i++) {
		if (hdp->hdp_offset + i >= hdp->hdp_len) {
			/*
			 * If we are not going to an ascii table, we don't need
			 * to pad this out with spaces to the right.
			 */
			if (!(hdp->hdp_flags & HDF_ASCII))
				break;
		}
		hexdump_space(hdp, i);
		if (addr + i < hdp->hdp_bufaddr ||
		    hdp->hdp_offset + i >= hdp->hdp_len) {
			ilstr_append_str(&hdp->hdp_buf, "  ");
		} else {
			ilstr_aprintf(&hdp->hdp_buf, "%02x",
			    hdp->hdp_data[hdp->hdp_offset + i - hdp->hdp_adj]);
		}
	}

	if (hdp->hdp_flags & HDF_ASCII) {
		ilstr_append_str(&hdp->hdp_buf, " | ");
		for (uint_t i = 0; i < hdp->hdp_width; i++) {
			if (hdp->hdp_offset + i >= hdp->hdp_len)
				break;
			if (addr + i < hdp->hdp_bufaddr) {
				ilstr_append_char(&hdp->hdp_buf, ' ');
			} else {
				char c = hdp->hdp_data[hdp->hdp_offset + i
				    - hdp->hdp_adj];

				ilstr_append_char(&hdp->hdp_buf,
				    HEXDUMP_PRINTABLE(c) ? c : '.');
			}
		}
	}
}

static int
hexdump_output(hexdump_param_t *hdp, bool hdr, hexdump_cb_f cb, void *cbarg)
{
	int ret;

	/*
	 * The callback is invoked with an address of UINT64_MAX for the header
	 * row.
	 */
	ret = cb(cbarg, hdr ? UINT64_MAX : hdp->hdp_bufaddr + hdp->hdp_offset,
	    ilstr_cstr(&hdp->hdp_buf), ilstr_len(&hdp->hdp_buf));
	ilstr_reset(&hdp->hdp_buf);

	return (ret);
}

static bool
hexdump_squishable(hexdump_param_t *hdp)
{
	const char *str = ilstr_cstr(&hdp->hdp_buf);
	const char *pstr = ilstr_cstr(&hdp->hdp_pbuf);

	if (hdp->hdp_flags & HDF_ADDRESS) {
		size_t strl = ilstr_len(&hdp->hdp_buf);
		size_t pstrl = ilstr_len(&hdp->hdp_pbuf);

		if (strl <= hdp->hdp_addrwidth || pstrl <= hdp->hdp_addrwidth)
			return (false);

		str += hdp->hdp_addrwidth;
		pstr += hdp->hdp_addrwidth;
	}

	return (strcmp(str, pstr) == 0);
}

int
hexdumph(hexdump_t *h, const uint8_t *data, size_t len, hexdump_flag_t flags,
    hexdump_cb_f cb, void *cbarg)
{
	hexdump_param_t hdp = { 0 };
	int ret = 0;

	if (data == NULL)
		return (0);

	/*
	 * We can use a pre-allocated buffer for the constructed lines if the
	 * caller has provided one. One use of this is to invoke this routine
	 * early in boot before kmem is ready.
	 */
#ifdef _KERNEL
	if (kmem_ready == 0 && (h == NULL || h->h_buf == NULL)) {
		panic("hexdump before kmem is ready requires pre-allocated "
		    "buffer");
	}
#endif
	if (h != NULL && h->h_buf != NULL) {
		ilstr_init_prealloc(&hdp.hdp_buf, (char *)h->h_buf,
		    h->h_buflen);
		/* We do not support HDF_DEDUP with a pre-allocated buffer */
		flags &= ~HDF_DEDUP;
	} else {
		/*
		 * The KM_SLEEP flag is ignored outside kernel context. If a
		 * memory allocation fails in userland that will result in the
		 * caller ultimately receiving -1 with errno set to ENOMEM.
		 */
		ilstr_init(&hdp.hdp_buf, KM_SLEEP);
		if (flags & HDF_DEDUP)
			ilstr_init(&hdp.hdp_pbuf, KM_SLEEP);
	}

	hdp.hdp_flags = flags;
	hdp.hdp_grouping = HD_DEFGROUPING;
	hdp.hdp_width = HD_DEFWIDTH;
	hdp.hdp_data = data;
	hdp.hdp_len = len;

	hdp.hdp_bufaddr = hdp.hdp_baseaddr = 0;
	hdp.hdp_offset = hdp.hdp_marker = hdp.hdp_adj = 0;

	if (h != NULL) {
		hdp.hdp_bufaddr = hdp.hdp_baseaddr = h->h_addr;
		hdp.hdp_width = h->h_width;
		hdp.hdp_grouping = h->h_grouping;
		hdp.hdp_indent = h->h_indent;
		hdp.hdp_marker = h->h_marker;
	}

	if (hdp.hdp_width == 0)
		hdp.hdp_width = HD_DEFWIDTH;
	if (hdp.hdp_grouping == 0)
		hdp.hdp_grouping = HD_DEFGROUPING;
	if (hdp.hdp_marker > HD_DEFWIDTH)
		hdp.hdp_marker = 0;

	/*
	 * If the grouping isn't a power of two, or the display width is not
	 * evenly divisible by the grouping we ignore the specified grouping
	 * and default to 4.
	 */
	if (!ISP2(hdp.hdp_grouping) || hdp.hdp_width % hdp.hdp_grouping != 0)
		hdp.hdp_grouping = 4;

	/*
	 * Determine how much space is required for the address field.
	 * We need one character for every four bits of the final address.
	 */
	hdp.hdp_addrwidth = (flsll(hdp.hdp_baseaddr + len) + 3) / 4;
	if (h != NULL && h->h_addrwidth > hdp.hdp_addrwidth)
		hdp.hdp_addrwidth = h->h_addrwidth;

	/*
	 * If alignment was requested and the address is not already aligned,
	 * adjust the starting address down to the nearest boundary. Missing
	 * data will be displayed as spaces.
	 */
	if (flags & HDF_ALIGN) {
		hdp.hdp_baseaddr = P2ALIGN(hdp.hdp_baseaddr, hdp.hdp_width);
		hdp.hdp_adj = hdp.hdp_bufaddr - hdp.hdp_baseaddr;
		hdp.hdp_len += hdp.hdp_adj;
	}

	if (flags & HDF_HEADER) {
		hexdump_header(&hdp);
		if ((ret = hexdump_output(&hdp, true, cb, cbarg)) != 0)
			goto out;
	}

	bool squishing = false;

	while (hdp.hdp_offset < hdp.hdp_len) {
		hexdump_data(&hdp);
		if (flags & HDF_DEDUP) {
			if (hexdump_squishable(&hdp)) {
				ilstr_reset(&hdp.hdp_buf);
				if (squishing) {
					hdp.hdp_offset += hdp.hdp_width;
					continue;
				}
				ilstr_append_str(&hdp.hdp_buf, "*");
				squishing = true;
			} else {
				ilstr_reset(&hdp.hdp_pbuf);
				ilstr_append_str(&hdp.hdp_pbuf,
				    ilstr_cstr(&hdp.hdp_buf));
				squishing = false;
			}
		}
		if ((ret = hexdump_output(&hdp, false, cb, cbarg)) != 0)
			break;
		hdp.hdp_offset += hdp.hdp_width;
	}

out:
	/*
	 * If ret is not zero then it is a value returned by a callback and we
	 * return that to the caller as-is. Otherwise we translate any errors
	 * from ilstr.
	 */
	if (ret == 0) {
		ilstr_errno_t ilerr = ilstr_errno(&hdp.hdp_buf);

		switch (ilerr) {
		case ILSTR_ERROR_OK:
			break;
		case ILSTR_ERROR_NOMEM:
			ret = ENOMEM;
			break;
		case ILSTR_ERROR_OVERFLOW:
			ret = EOVERFLOW;
			break;
		case ILSTR_ERROR_PRINTF:
		default:
			/*
			 * We don't expect to end up here but we should return
			 * an error if we somehow do.
			 */
			ret = EIO;
			break;
		}
#ifndef _KERNEL
		if (ret != 0) {
			errno = ret;
			ret = -1;
		}
#endif
	}

	ilstr_fini(&hdp.hdp_buf);
	if (flags & HDF_DEDUP)
		ilstr_fini(&hdp.hdp_pbuf);

	return (ret);
}

int
hexdump(const uint8_t *data, size_t len, hexdump_flag_t flags, hexdump_cb_f cb,
    void *cbarg)
{
	return (hexdumph(NULL, data, len, flags, cb, cbarg));
}

#ifndef _KERNEL
static int
hexdump_file_cb(void *arg, uint64_t addr __unused, const char *str,
    size_t len __unused)
{
	FILE *fp = (FILE *)arg;

	if (fprintf(fp, "%s\n", str) < 0)
		return (-1);
	return (0);
}

int
hexdump_fileh(hexdump_t *h, const uint8_t *data, size_t len,
    hexdump_flag_t flags, FILE *fp)
{
	return (hexdumph(h, data, len, flags, hexdump_file_cb, fp));
}

int
hexdump_file(const uint8_t *data, size_t len, hexdump_flag_t flags, FILE *fp)
{
	return (hexdumph(NULL, data, len, flags, hexdump_file_cb, fp));
}
#endif /* _KERNEL */
