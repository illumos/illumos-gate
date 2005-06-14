/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2002-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/salib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/bootvfs.h>
#include <netinet/in.h>

/*
 * This structure defines the static area where gethostbyname()
 * stores the hostent data that it returns to the caller.
 */
static struct {
	struct hostent	he;
	in_addr_t	*ha_list[2];
	in_addr_t	ha_addr;
	char		ha_name[MAXHOSTNAMELEN+1];
} hostinfo;

int h_errno;

static in_addr_t inet_addr(const char *);
static in_addr_t nam2addr(const char *);

/* Very stripped-down gethostbyname() */
struct hostent *
gethostbyname(const char *nam)
{
	bzero(&hostinfo, sizeof (hostinfo));

	hostinfo.ha_addr = inet_addr(nam);
	if ((int32_t)hostinfo.ha_addr == -1) {
		if (get_default_fs() == NULL) {
			h_errno = HOST_NOT_FOUND;
			return (NULL);
		}
		hostinfo.ha_addr = nam2addr(nam);
		if ((int32_t)hostinfo.ha_addr == -1) {
			h_errno = HOST_NOT_FOUND;
			return (NULL);
		}
	}

	hostinfo.he.h_addrtype = AF_INET;
	(void) strlcpy(hostinfo.ha_name, nam, MAXHOSTNAMELEN);
	hostinfo.he.h_name = hostinfo.ha_name;
	hostinfo.he.h_length = sizeof (struct in_addr);
	hostinfo.ha_list[0] = &hostinfo.ha_addr;
	hostinfo.he.h_addr_list = (char **)&hostinfo.ha_list;
	return (&hostinfo.he);
}

#define	SKIP_SPACE(_p)							\
	{								\
		char	_c;						\
		while ((_c = *(_p)) != '\0' && isspace(_c))		\
			p++;						\
		if (_c == '\0')						\
			goto next_line;					\
	}

#define	SKIP_TOKEN(_p)							\
	{								\
		char	_c;						\
		while ((_c = *(_p)) != '\0' && !isspace(_c))		\
			p++;						\
		if (_c == '\0')						\
			goto next_line;					\
	}

#define	TRIM_LINE(_l)							\
	{								\
		char	_c, *_p = (_l);					\
		while ((_c = *_p) != '#' && _c != '\n' && _c != '\0')	\
			_p++;						\
		*_p = '\0';						\
	}

#define	BUFSZ	1024
#define	HOSTDB	"/etc/inet/hosts"

static in_addr_t
nam2addr(const char *nam)
{
	FILE *h;
	char c, buf[BUFSZ];
	char *l, *p, *s;
	boolean_t first_token;

	if ((h = fopen(HOSTDB, "r")) == NULL) {
		return ((in_addr_t)-1);
	}

next_line:
	if ((l = fgets(buf, BUFSZ, h)) == NULL) {
		(void) fclose(h);
		return ((in_addr_t)-1);
	}
	TRIM_LINE(l);

	p = l;
	first_token = B_TRUE;
next_token:
	SKIP_SPACE(p);

	if (first_token) {
		first_token = B_FALSE;
		SKIP_TOKEN(p);

		*p++ = '\0';
		goto next_token;
	}

	s = (char *)nam;
	if (*p++ == *s++) {
		while ((c = *s++) == *p && c != '\0')
			p++;
		if (c == '\0' && (isspace(*p) || *p == '\0'))
			goto match;
	}

	SKIP_TOKEN(p);
	goto next_token;
match:
	(void) fclose(h);
	return (inet_addr((const char *)l));
}

static in_addr_t
inet_addr(const char *cp)
{
	in_addr_t val;
	uint_t base, n;
	char c;
	in_addr_t parts[4], *pp = parts;

again:
	/*
	 * Collect number up to ``.''.
	 * Values are specified as for C:
	 * 0x=hex, 0=octal, other=decimal.
	 */
	val = 0; base = 10;
	if (*cp == '0') {
		if (*++cp == 'x' || *cp == 'X')
			base = 16, cp++;
		else
			base = 8;
	}

	while ((c = *cp) != 0) {
		if (isdigit(c)) {
			if ((c - '0') >= base)
				break;
			val = (val * base) + (c - '0');
			cp++;
			continue;
		}
		if (base == 16 && isxdigit(c)) {
			val = (val << 4) + (c + 10 - (islower(c) ? 'a' : 'A'));
			cp++;
			continue;
		}
		break;
	}
	if (*cp == '.') {
		/*
		 * Internet format:
		 *	a.b.c.d
		 *	a.b.c	(with c treated as 16-bits)
		 *	a.b	(with b treated as 24 bits)
		 */
		if (pp >= parts + 4)
			return ((in_addr_t)-1);
		*pp++ = val, cp++;
		goto again;
	}
	/*
	 * Check for trailing characters.
	 */
	if (*cp && !isspace(*cp))
		return ((in_addr_t)-1);
	*pp++ = val;
	/*
	 * Concoct the address according to
	 * the number of parts specified.
	 */
	n = pp - parts;
	switch (n) {

	case 1:			 /* a -- 32 bits */
		val = parts[0];
		break;

	case 2:			 /* a.b -- 8.24 bits */
		val = (parts[0] << 24) | (parts[1] & 0xffffff);
		break;

	case 3:			 /* a.b.c -- 8.8.16 bits */
		val = (parts[0] << 24) | ((parts[1] & 0xff) << 16) |
			(parts[2] & 0xffff);
		break;

	case 4:			 /* a.b.c.d -- 8.8.8.8 bits */
		val = (parts[0] << 24) | ((parts[1] & 0xff) << 16) |
			((parts[2] & 0xff) << 8) | (parts[3] & 0xff);
		break;

	default:
		return ((in_addr_t)-1);
	}
	val = htonl(val);
	return (val);
}
