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
 * Copyright 2013 Pluribus Networks Inc.
 */

#ifndef _COMPAT_FREEBSD_LIBUTIL_H_
#define	_COMPAT_FREEBSD_LIBUTIL_H_

int	expand_number(const char *_buf, uint64_t *_num);
int	humanize_number(char *_buf, size_t _len, int64_t _number,
    const char *_suffix, int _scale, int _flags);

/* Values for humanize_number(3)'s flags parameter. */
#define HN_DECIMAL      0x01
#define HN_NOSPACE      0x02
#define HN_B            0x04
#define HN_DIVISOR_1000     0x08
#define HN_IEC_PREFIXES     0x10

/* Values for humanize_number(3)'s scale parameter. */
#define HN_GETSCALE     0x10
#define HN_AUTOSCALE        0x20


#endif	/* _COMPAT_FREEBSD_LIBUTIL_H_ */
