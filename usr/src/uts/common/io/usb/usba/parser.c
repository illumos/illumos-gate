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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright 2014 Garrett D'Amore <garrett@damore.org>
 */


/*
 * Descriptor parsing functions
 */
#define	USBA_FRAMEWORK
#include <sys/usb/usba/usba_impl.h>
#include <sys/strsun.h>

#define	INCREMENT_BUF(buf) \
		if ((buf)[0] == 0) { \
			break; \
		} else { \
			(buf) += (buf)[0]; \
		}
#define	isdigit(ch) ((ch >= '0') && (ch <= '9'))

extern usba_cfg_pwr_descr_t default_cfg_power;
extern usba_if_pwr_descr_t default_if_power;

size_t
usb_parse_data(char	*format,
	uchar_t 	*data,
	size_t		datalen,
	void		*structure,
	size_t		structlen)
{
	int	fmt;
	int	counter = 1;
	int	multiplier = 0;
	uchar_t	*dataend = data + datalen;
	char	*structstart = (char *)structure;
	void	*structend = (void *)((intptr_t)structstart + structlen);

	if ((format == NULL) || (data == NULL) || (structure == NULL)) {

		return (USB_PARSE_ERROR);
	}

	while ((fmt = *format) != '\0') {

		/*
		 * Could some one pass a "format" that is greater than
		 * the structlen? Conversely, one could pass a ret_buf_len
		 * that is less than the "format" length.
		 * If so, we need to protect against writing over memory.
		 */
		if (counter++ > structlen) {
			break;
		}

		if (fmt == 'c') {
			uint8_t	*cp = (uint8_t *)structure;

			cp = (uint8_t *)(((uintptr_t)cp + _CHAR_ALIGNMENT - 1) &
			    ~(_CHAR_ALIGNMENT - 1));
			if (((data + 1) > dataend) ||
			    ((cp + 1) > (uint8_t *)structend))
				break;

			*cp++ = *data++;
			structure = (void *)cp;
			if (multiplier) {
				multiplier--;
			}
			if (multiplier == 0) {
				format++;
			}
		} else if (fmt == 's') {
			uint16_t	*sp = (uint16_t *)structure;

			sp = (uint16_t *)
			    (((uintptr_t)sp + _SHORT_ALIGNMENT - 1) &
			    ~(_SHORT_ALIGNMENT - 1));
			if (((data + 2) > dataend) ||
			    ((sp + 1) > (uint16_t *)structend))
				break;

			*sp++ = (data[1] << 8) + data[0];
			data += 2;
			structure = (void *)sp;
			if (multiplier) {
				multiplier--;
			}
			if (multiplier == 0) {
				format++;
			}
		} else if (fmt == 'l') {
			uint32_t	*lp = (uint32_t *)structure;

			lp = (uint32_t *)
			    (((uintptr_t)lp + _INT_ALIGNMENT - 1) &
			    ~(_INT_ALIGNMENT - 1));
			if (((data + 4) > dataend) ||
			    ((lp + 1) > (uint32_t *)structend))
				break;

			*lp++ = (((((
			    (uint32_t)data[3] << 8) | data[2]) << 8) |
			    data[1]) << 8) | data[0];
			data += 4;
			structure = (void *)lp;
			if (multiplier) {
				multiplier--;
			}
			if (multiplier == 0) {
				format++;
			}
		} else if (fmt == 'L') {
			uint64_t	*llp = (uint64_t *)structure;

			llp = (uint64_t *)
			    (((uintptr_t)llp + _LONG_LONG_ALIGNMENT - 1) &
			    ~(_LONG_LONG_ALIGNMENT - 1));
			if (((data + 8) > dataend) ||
			    ((llp + 1) >= (uint64_t *)structend))
				break;

			*llp++ = (((((((((((((data[7] << 8) |
			    data[6]) << 8) | data[5]) << 8) |
			    data[4]) << 8) | data[3]) << 8) |
			    data[2]) << 8) | data[1]) << 8) |
			    data[0];
			data += 8;
			structure = (void *)llp;
			if (multiplier) {
				multiplier--;
			}
			if (multiplier == 0) {
				format++;
			}
		} else if (isdigit(fmt)) {
			multiplier = (multiplier * 10) + (fmt - '0');
			format++;
			counter--;
		} else {
			multiplier = 0;
			break;
		}
	}

	return ((intptr_t)structure - (intptr_t)structstart);
}


size_t
usb_parse_CV_descr(char *format,
	uchar_t *data,
	size_t	datalen,
	void	*structure,
	size_t	structlen)
{
	return (usb_parse_data(format, data, datalen, structure,
	    structlen));
}


/*
 *	Helper function: returns pointer to n-th descriptor of
 *	type descr_type, unless the end of the buffer or a descriptor
 *	of type	stop_descr_type1 or stop_descr_type2 is encountered first.
 */
static uchar_t *
usb_nth_descr(uchar_t	*buf,
	size_t		buflen,
	int		descr_type,
	uint_t		n,
	int		stop_descr_type1,
	int		stop_descr_type2)
{
	uchar_t	*bufstart = buf;
	uchar_t *bufend = buf + buflen;

	if (buf == NULL) {

		return (NULL);
	}

	while (buf + 2 <= bufend) {
		if ((buf != bufstart) && ((buf[1] == stop_descr_type1) ||
		    (buf[1] == stop_descr_type2))) {

			return (NULL);
		}

		if ((descr_type == USB_DESCR_TYPE_ANY) ||
		    (buf[1] == descr_type)) {
			if (n-- == 0) {

				return (buf);
			}
		}

		/*
		 * Check for a bad buffer.
		 * If buf[0] is 0, then this will be an infite loop
		 */
		INCREMENT_BUF(buf);
	}

	return (NULL);
}


size_t
usb_parse_dev_descr(uchar_t	*buf,	/* from GET_DESCRIPTOR(DEVICE) */
	size_t			buflen,
	usb_dev_descr_t		*ret_descr,
	size_t			ret_buf_len)
{
	if ((buf == NULL) || (ret_descr == NULL) ||
	    (buflen < 2) || (buf[1] != USB_DESCR_TYPE_DEV)) {

		return (USB_PARSE_ERROR);
	}

	return (usb_parse_data("ccsccccssscccc",
	    buf, buflen, ret_descr, ret_buf_len));
}


size_t
usb_parse_cfg_descr(uchar_t	*buf,	/* from GET_DESCRIPTOR(CONFIGURATION) */
	size_t			buflen,
	usb_cfg_descr_t		*ret_descr,
	size_t			ret_buf_len)
{
	if ((buf == NULL) || (ret_descr == NULL) ||
	    (buflen < 2) || (buf[1] != USB_DESCR_TYPE_CFG)) {

		return (USB_PARSE_ERROR);
	}

	return (usb_parse_data("ccsccccc",
	    buf, buflen, ret_descr, ret_buf_len));
}


size_t
usba_parse_cfg_pwr_descr(
	uchar_t			*buf,	/* from GET_DESCRIPTOR(CONFIGURATION) */
	size_t			buflen,
	usba_cfg_pwr_descr_t	*ret_descr,
	size_t			ret_buf_len)
{
	uchar_t *bufend = buf + buflen;

	if ((buf == NULL) || (ret_descr == NULL)) {

		return (USB_PARSE_ERROR);
	}
	while (buf + 2 <= bufend) {

		if (buf[1] == USBA_DESCR_TYPE_CFG_PWR_1_1) {
			return (usb_parse_data("ccsccccccccsss",
			    buf, buflen, ret_descr, ret_buf_len));
		}

		/*
		 * Check for a bad buffer.
		 * If buf[0] is 0, then this will be an infinite loop
		 */
		INCREMENT_BUF(buf);
	}

	/* return the default configuration power descriptor */
	bcopy(&default_cfg_power, ret_descr, USBA_CFG_PWR_DESCR_SIZE);

	return (ret_descr->bLength);

}


size_t
usb_parse_ia_descr(uchar_t	*buf,	/* from GET_DESCRIPTOR(CONFIGURATION) */
	size_t			buflen,
	size_t			first_if,
	usb_ia_descr_t		*ret_descr,
	size_t			ret_buf_len)
{
	uchar_t *bufend = buf + buflen;

	if ((buf == NULL) || (ret_descr == NULL)) {

		return (USB_PARSE_ERROR);
	}

	while (buf + USB_IA_DESCR_SIZE <= bufend) {
		if ((buf[1] == USB_DESCR_TYPE_IA) &&
		    (buf[2] == first_if)) {

			return (usb_parse_data("cccccccc",
			    buf, _PTRDIFF(bufend, buf),
			    ret_descr, ret_buf_len));
		}

		/*
		 * Check for a bad buffer.
		 * If buf[0] is 0, then this will be an infinite loop
		 */
		INCREMENT_BUF(buf);
	}

	return (USB_PARSE_ERROR);
}


size_t
usb_parse_if_descr(uchar_t	*buf,	/* from GET_DESCRIPTOR(CONFIGURATION) */
	size_t			buflen,
	uint_t			if_number,
	uint_t			alt_if_setting,
	usb_if_descr_t		*ret_descr,
	size_t			ret_buf_len)
{
	uchar_t *bufend = buf + buflen;

	if ((buf == NULL) || (ret_descr == NULL)) {

		return (USB_PARSE_ERROR);
	}

	while (buf + 4 <= bufend) {
		if ((buf[1] == USB_DESCR_TYPE_IF) &&
		    (buf[2] == if_number) &&
		    (buf[3] == alt_if_setting)) {

			return (usb_parse_data("ccccccccc",
			    buf, _PTRDIFF(bufend, buf),
			    ret_descr, ret_buf_len));
		}

		/*
		 * Check for a bad buffer.
		 * If buf[0] is 0, then this will be an infinite loop
		 */
		INCREMENT_BUF(buf);
	}

	return (USB_PARSE_ERROR);
}

size_t
usba_parse_if_pwr_descr(uchar_t	*buf,	/* from GET_DESCRIPTOR(CONFIGURATION) */
	size_t			buflen,
	uint_t			if_number,
	uint_t			alt_if_setting,
	usba_if_pwr_descr_t	*ret_descr,
	size_t			ret_buf_len)
{
	uchar_t *bufend = buf + buflen;

	if ((buf == NULL) || (ret_descr == NULL)) {

		return (USB_PARSE_ERROR);
	}

	while (buf + 4 <= bufend) {
		if ((buf[1] == USB_DESCR_TYPE_IF) &&
		    (buf[2] == if_number) &&
		    (buf[3] == alt_if_setting)) {

			buf += buf[0];

			if (buf + 2 <= bufend) {
				if (buf[1] == USBA_DESCR_TYPE_IF_PWR_1_1) {

					return (
					    usb_parse_data("cccccccccsss", buf,
					    _PTRDIFF(bufend, buf), ret_descr,
					    ret_buf_len));
				} else {
					break;
				}
			} else {
				break;
			}
		}

		/*
		 * Check for a bad buffer.
		 * If buf[0] is 0, then this will be an infinite loop
		 */
		INCREMENT_BUF(buf);
	}

	/* return the default interface power descriptor */
	bcopy(&default_if_power, ret_descr, USBA_IF_PWR_DESCR_SIZE);

	return (ret_descr->bLength);
}


/*
 * the endpoint index is relative to the interface. index 0 is
 * the first endpoint
 */
size_t
usb_parse_ep_descr(uchar_t	*buf,	/* from GET_DESCRIPTOR(CONFIGURATION) */
	size_t			buflen,
	uint_t			if_number,
	uint_t			alt_if_setting,
	uint_t			ep_index,
	usb_ep_descr_t		*ret_descr,
	size_t			ret_buf_len)
{
	uchar_t *bufend = buf + buflen;

	if ((buf == NULL) || (ret_descr == NULL)) {

		return (USB_PARSE_ERROR);
	}

	while ((buf + 4) <= bufend) {
		if (buf[1] == USB_DESCR_TYPE_IF &&
		    buf[2] == if_number &&
		    buf[3] == alt_if_setting) {
			if ((buf = usb_nth_descr(buf,
			    _PTRDIFF(bufend, buf),
			    USB_DESCR_TYPE_EP, ep_index,
			    USB_DESCR_TYPE_IF, -1)) == NULL) {

				break;
			}

			return (usb_parse_data("ccccsc",
			    buf, _PTRDIFF(bufend, buf),
			    ret_descr, ret_buf_len));
		}

		/*
		 * Check for a bad buffer.
		 * If buf[0] is 0, then this will be an infinite loop
		 */
		INCREMENT_BUF(buf);
	}

	return (USB_PARSE_ERROR);
}


/*
 * Returns (at ret_descr) a null-terminated string.  Null termination is
 * guaranteed, even if the string is longer than the buffer.  Thus, a
 * maximum of (ret_buf_len - 1) characters are returned.
 * Stops silently on first character not in UNICODE format.
 */
/*ARGSUSED*/
size_t
usba_ascii_string_descr(uchar_t	*buf,	/* from GET_DESCRIPTOR(STRING) */
	size_t			buflen,
	char			*ret_descr,
	size_t			ret_buf_len)
{
	int	i = 1;
	char	*retstart = ret_descr;
	uchar_t *bufend = buf + buflen;

	if ((buf == NULL) || (ret_descr == NULL) ||
	    (ret_buf_len == 0) || (buflen < 2) ||
	    (buf[0] < 2) || (buf[1] != USB_DESCR_TYPE_STRING)) {

		return (USB_PARSE_ERROR);
	}

	for (buf = buf + 2; buf+1 < bufend && ret_buf_len > 1 &&
	    buf[0] != 0 && buf[1] == 0 && (i < ret_buf_len); buf += 2, i++) {
		*ret_descr++ = buf[0];
	}

	*ret_descr++ = 0;

	return (_PTRDIFF(ret_descr, retstart));
}


size_t
usb_parse_CV_cfg_descr(uchar_t	*buf,	/* from GET_DESCRIPTOR(CONFIGURATION) */
	size_t			buflen,
	char			*fmt,
	uint_t			descr_type,
	uint_t			descr_index,
	void			*ret_descr,
	size_t			ret_buf_len)
{
	uchar_t *bufend = buf + buflen;

	if ((buf == NULL) || (ret_descr == NULL) || (fmt == NULL) ||
	    (buflen < 2) || ((buf = usb_nth_descr(buf, buflen, descr_type,
	    descr_index, -1, -1)) == NULL)) {

		return (USB_PARSE_ERROR);
	}

	return (usb_parse_data(fmt, buf,
	    _PTRDIFF(bufend, buf), ret_descr,
	    ret_buf_len));
}


size_t
usb_parse_CV_if_descr(uchar_t	*buf,	/* from GET_DESCRIPTOR(CONFIGURATION) */
	size_t			buflen,
	char			*fmt,
	uint_t			if_number,
	uint_t			alt_if_setting,
	uint_t			descr_type,
	uint_t			descr_index,
	void			*ret_descr,
	size_t			ret_buf_len)
{
	uchar_t *bufend = buf + buflen;

	if ((buf == NULL) || (ret_descr == NULL) || (fmt == NULL)) {

		return (USB_PARSE_ERROR);
	}

	while (buf + 4 <= bufend) {
		if ((buf[1] == USB_DESCR_TYPE_IF) &&
		    (buf[2] == if_number) &&
		    (buf[3] == alt_if_setting)) {
			if ((buf = usb_nth_descr(buf,
			    _PTRDIFF(bufend, buf), descr_type,
			    descr_index, USB_DESCR_TYPE_IF, -1)) ==
			    NULL) {
				break;
			}

			return (usb_parse_data(fmt, buf,
			    _PTRDIFF(bufend, buf),
			    ret_descr, ret_buf_len));
		}

		/*
		 * Check for a bad buffer.
		 * If buf[0] is 0, then this will be an infinite loop
		 */
		INCREMENT_BUF(buf);
	}

	return (USB_PARSE_ERROR);
}


size_t
usb_parse_CV_ep_descr(uchar_t	*buf,	/* from GET_DESCRIPTOR(CONFIGURATION) */
	size_t			buflen,
	char			*fmt,
	uint_t			if_number,
	uint_t			alt_if_setting,
	uint_t			ep_index,
	uint_t			descr_type,
	uint_t			descr_index,
	void			*ret_descr,
	size_t			ret_buf_len)
{
	uchar_t *bufend = buf + buflen;

	if ((buf == NULL) || (ret_descr == NULL) || (fmt == NULL)) {

		return (USB_PARSE_ERROR);
	}

	while (buf + 4 <= bufend) {
		if ((buf[1] == USB_DESCR_TYPE_IF) &&
		    (buf[2] == if_number) &&
		    (buf[3] == alt_if_setting)) {
			if ((buf = usb_nth_descr(buf,
			    _PTRDIFF(bufend, buf),
			    USB_DESCR_TYPE_EP, ep_index,
			    USB_DESCR_TYPE_IF, -1)) == NULL) {

				break;
			}

			if ((buf = usb_nth_descr(buf,
			    _PTRDIFF(bufend, buf),
			    descr_type, descr_index,
			    USB_DESCR_TYPE_EP,
			    USB_DESCR_TYPE_IF)) == NULL) {

				break;
			}

			return (usb_parse_data(fmt, buf,
			    _PTRDIFF(bufend, buf),
			    ret_descr, ret_buf_len));
		}

		/*
		 * Check for a bad buffer.
		 * If buf[0] is 0, then this will be an infite loop
		 */
		INCREMENT_BUF(buf);
	}

	return (USB_PARSE_ERROR);
}
