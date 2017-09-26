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
 * Copyright 2014 Pluribus Networks Inc.
 */

#ifndef _COMPAT_FREEBSD_UUID_H_
#define	_COMPAT_FREEBSD_UUID_H_

#include <sys/endian.h>
#include <uuid/uuid.h>

/* Status codes returned by the functions. */
#define	uuid_s_ok			0
#define	uuid_s_bad_version		1
#define	uuid_s_invalid_string_uuid	2

static __inline void
uuid_from_string(char *str, uuid_t *uuidp, uint32_t *status)
{
	if (uuid_parse(str, *uuidp) == 0) {
		*status = uuid_s_ok;
	} else {
		*status = uuid_s_invalid_string_uuid;
	}
}

static __inline void
uuid_enc_le(void *buf, uuid_t *uuidp)
{
	uchar_t	*p;
	int	i;

	p = buf;
	be32enc(p, ((struct uuid *)uuidp)->time_low);
	be16enc(p + 4, ((struct uuid *)uuidp)->time_mid);
	be16enc(p + 6, ((struct uuid *)uuidp)->time_hi_and_version);
	p[8] = ((struct uuid *)uuidp)->clock_seq_hi_and_reserved;
	p[9] = ((struct uuid *)uuidp)->clock_seq_low;

	for (i = 0; i < 6; i++)
		p[10 + i] = ((struct uuid *)uuidp)->node_addr[i];

}

#endif	/* _COMPAT_FREEBSD_UUID_H_ */
