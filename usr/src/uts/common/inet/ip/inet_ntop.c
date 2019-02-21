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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2017 Nexenta Systems, Inc.
 */

#include <sys/types.h>
#include <sys/cmn_err.h>
#include <sys/systm.h>
#include <sys/socket.h>
#include <sys/sunddi.h>
#include <netinet/in.h>
#include <inet/led.h>

/*
 * v6 formats supported
 * General format xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx
 * The short hand notation :: is used for COMPAT addr
 * Other forms : fe80::xxxx:xxxx:xxxx:xxxx
 */
static void
convert2ascii(char *buf, const in6_addr_t *addr)
{
	int		hexdigits;
	int		head_zero = 0;
	int		tail_zero = 0;
	/* tempbuf must be big enough to hold ffff:\0 */
	char		tempbuf[6];
	char		*ptr;
	uint16_t	*addr_component;
	size_t		len;
	boolean_t	first = B_FALSE;
	boolean_t	med_zero = B_FALSE;
	boolean_t	end_zero = B_FALSE;

	addr_component = (uint16_t *)addr;
	ptr = buf;

	/* First count if trailing zeroes higher in number */
	for (hexdigits = 0; hexdigits < 8; hexdigits++) {
		if (*addr_component == 0) {
			if (hexdigits < 4)
				head_zero++;
			else
				tail_zero++;
		}
		addr_component++;
	}
	addr_component = (uint16_t *)addr;
	if (tail_zero > head_zero && (head_zero + tail_zero) != 7)
		end_zero = B_TRUE;

	for (hexdigits = 0; hexdigits < 8; hexdigits++) {

		/* if entry is a 0 */

		if (*addr_component == 0) {
			if (!first && *(addr_component + 1) == 0) {
				if (end_zero && (hexdigits < 4)) {
					*ptr++ = '0';
					*ptr++ = ':';
				} else {
					/*
					 * address starts with 0s ..
					 * stick in leading ':' of pair
					 */
					if (hexdigits == 0)
						*ptr++ = ':';
					/* add another */
					*ptr++ = ':';
					first = B_TRUE;
					med_zero = B_TRUE;
				}
			} else if (first && med_zero) {
				if (hexdigits == 7)
					*ptr++ = ':';
				addr_component++;
				continue;
			} else {
				*ptr++ = '0';
				*ptr++ = ':';
			}
			addr_component++;
			continue;
		}
		if (med_zero)
			med_zero = B_FALSE;

		tempbuf[0] = '\0';
		(void) sprintf(tempbuf, "%x:", ntohs(*addr_component) & 0xffff);
		len = strlen(tempbuf);
		bcopy(tempbuf, ptr, len);
		ptr = ptr + len;
		addr_component++;
	}
	*--ptr = '\0';
}

/*
 * search for char c, terminate on trailing white space
 */
static char *
strchr_w(const char *sp, int c)
{
	/* skip leading white space */
	while (*sp && (*sp == ' ' || *sp == '\t')) {
		sp++;
	}

	do {
		if (*sp == (char)c)
			return ((char *)sp);
		if (*sp == ' ' || *sp == '\t')
			return (NULL);
	} while (*sp++);
	return (NULL);
}

static int
str2inet_addr(char *cp, ipaddr_t *addrp)
{
	char *end;
	long byte;
	int i;
	ipaddr_t addr = 0;

	for (i = 0; i < 4; i++) {
		if (ddi_strtol(cp, &end, 10, &byte) != 0 || byte < 0 ||
		    byte > 255) {
			return (0);
		}
		addr = (addr << 8) | (uint8_t)byte;
		if (i < 3) {
			if (*end != '.') {
				return (0);
			} else {
				cp = end + 1;
			}
		} else {
			cp = end;
		}
	}
	*addrp = addr;
	return (1);
}

/*
 * inet_ntop: Convert an IPv4 or IPv6 address in binary form into
 * printable form, and return a pointer to that string.  Caller should
 * provide a buffer of correct length to store string into.
 * Note: this routine is kernel version of inet_ntop.  It has similar
 * format as inet_ntop() defined in RFC 2553, but it does not do
 * error handling operations exactly as RFC 2553 defines.
 */
static char *
__inet_ntop(int af, const void *addr, char *buf, int addrlen, int compat)
{
	static char	*badaf = "<badfamily>";
	in6_addr_t	*v6addr;
	uchar_t		*v4addr;
	char		*caddr;

	VERIFY(addr != NULL);
	VERIFY(OK_32PTR(addr));
	VERIFY(buf != NULL);

	buf[0] = '\0';

#define	UC(b)	(((int)b) & 0xff)
	switch (af) {
	case AF_INET:
		ASSERT(addrlen >= INET_ADDRSTRLEN);
		v4addr = (uchar_t *)addr;
		(void) sprintf(buf,
		    (compat) ? "%03d.%03d.%03d.%03d" : "%d.%d.%d.%d",
		    UC(v4addr[0]), UC(v4addr[1]), UC(v4addr[2]), UC(v4addr[3]));
		return (buf);
	case AF_INET6:
		ASSERT(addrlen >= INET6_ADDRSTRLEN);
		v6addr = (in6_addr_t *)addr;
		if (IN6_IS_ADDR_V4MAPPED(v6addr)) {
			caddr = (char *)addr;
			(void) sprintf(buf, "::ffff:%d.%d.%d.%d",
			    UC(caddr[12]), UC(caddr[13]),
			    UC(caddr[14]), UC(caddr[15]));
		} else if (IN6_IS_ADDR_V4COMPAT(v6addr)) {
			caddr = (char *)addr;
			(void) sprintf(buf, "::%d.%d.%d.%d",
			    UC(caddr[12]), UC(caddr[13]), UC(caddr[14]),
			    UC(caddr[15]));
		} else if (IN6_IS_ADDR_UNSPECIFIED(v6addr)) {
			(void) sprintf(buf, "::");
		} else {
			convert2ascii(buf, v6addr);
		}
		return (buf);

	default:
		return (badaf);
	}
#undef UC
}

/*
 * Provide fixed inet_ntop() implementation.
 */
char *
_inet_ntop(int af, const void *addr, char *buf, int addrlen)
{
	return (__inet_ntop(af, addr, buf, addrlen, 0));
}

/*
 * Provide old inet_ntop() implementation by default for binary
 * compatibility.
 */
char *
inet_ntop(int af, const void *addr, char *buf, int addrlen)
{
	static char	local_buf[INET6_ADDRSTRLEN];
	static char	*badaddr = "<badaddr>";

	if (addr == NULL || !(OK_32PTR(addr)))
		return (badaddr);

	if (buf == NULL) {
		buf = local_buf;
		addrlen = sizeof (local_buf);
	}

	return (__inet_ntop(af, addr, buf, addrlen, 1));
}

/*
 * inet_pton: This function takes string format IPv4 or IPv6 address and
 * converts it to binary form. The format of this function corresponds to
 * inet_pton() in the socket library.
 *
 * Return values:
 *  0 invalid IPv4 or IPv6 address
 *  1 successful conversion
 * -1 af is not AF_INET or AF_INET6
 */
static int
__inet_pton(int af, char *inp, void *outp, int compat)
{
	int i;
	long byte;
	char *end;

	switch (af) {
	case AF_INET:
		if (str2inet_addr(inp, (ipaddr_t *)outp) != 0) {
			if (!compat)
				*(uint32_t *)outp = htonl(*(uint32_t *)outp);
			return (1);
		} else {
			return (0);
		}
	case AF_INET6: {
		union v6buf_u {
			uint16_t v6words_u[8];
			in6_addr_t v6addr_u;
		} v6buf, *v6outp;
		uint16_t	*dbl_col = NULL;
		char lastbyte = '\0';

		v6outp = (union v6buf_u *)outp;

		if (strchr_w(inp, '.') != NULL) {
			int ret = 0;

			/* v4 mapped or v4 compatable */
			if (strncmp(inp, "::ffff:", 7) == 0) {
				ipaddr_t ipv4_all_zeroes = 0;
				/* mapped - first init prefix and then fill */
				IN6_IPADDR_TO_V4MAPPED(ipv4_all_zeroes,
				    &v6outp->v6addr_u);
				ret = str2inet_addr(inp + 7,
				    &(v6outp->v6addr_u.s6_addr32[3]));
			} else if (strncmp(inp, "::", 2) == 0) {
				/* v4 compatable - prefix all zeroes */
				bzero(&v6outp->v6addr_u, sizeof (in6_addr_t));
				ret = str2inet_addr(inp + 2,
				    &(v6outp->v6addr_u.s6_addr32[3]));
			}
			if (ret > 0 && !compat) {
				v6outp->v6addr_u.s6_addr32[3] =
				    htonl(v6outp->v6addr_u.s6_addr32[3]);
			}
			return (ret);
		}
		for (i = 0; i < 8; i++) {
			int error;
			/*
			 * if ddi_strtol() fails it could be because
			 * the string is "::".  That is valid and
			 * checked for below so just set the value to
			 * 0 and continue.
			 */
			if ((error = ddi_strtol(inp, &end, 16, &byte)) != 0) {
				if (error == ERANGE)
					return (0);
				byte = 0;
			}
			if (byte < 0 || byte > 0x0ffff) {
				return (0);
			}
			if (compat) {
				v6buf.v6words_u[i] = (uint16_t)byte;
			} else {
				v6buf.v6words_u[i] = htons((uint16_t)byte);
			}
			if (*end == '\0' || i == 7) {
				inp = end;
				break;
			}
			if (inp == end) {	/* not a number must be */
				if (*inp == ':' &&
				    ((i == 0 && *(inp + 1) == ':') ||
				    lastbyte == ':')) {
					if (dbl_col) {
						return (0);
					}
					if (byte != 0)
						i++;
					dbl_col = &v6buf.v6words_u[i];
					if (i == 0)
						inp++;
				} else if (*inp == '\0' || *inp == ' ' ||
				    *inp == '\t') {
					break;
				} else {
					return (0);
				}
			} else {
				inp = end;
			}
			if (*inp != ':') {
				return (0);
			}
			inp++;
			if (*inp == '\0' || *inp == ' ' || *inp == '\t') {
				break;
			}
			lastbyte = *inp;
		}
		if (*inp != '\0' && *inp != ' ' && *inp != '\t') {
			return (0);
		}
		/*
		 * v6words now contains the bytes we could translate
		 * dbl_col points to the word (should be 0) where
		 * a double colon was found
		 */
		if (i == 7) {
			v6outp->v6addr_u = v6buf.v6addr_u;
		} else {
			int rem;
			int word;
			int next;
			if (dbl_col == NULL) {
				return (0);
			}
			bzero(&v6outp->v6addr_u, sizeof (in6_addr_t));
			rem = dbl_col - &v6buf.v6words_u[0];
			for (next = 0; next < rem; next++) {
				v6outp->v6words_u[next] = v6buf.v6words_u[next];
			}
			next++;	/* skip dbl_col 0 */
			rem = i - rem;
			word = 8 - rem;
			while (rem > 0) {
				v6outp->v6words_u[word] = v6buf.v6words_u[next];
				word++;
				rem--;
				next++;
			}
		}
		return (1);	/* Success */
	}
	}	/* switch */
	return (-1);	/* return -1 for default case */
}

/*
 * Provide fixed inet_pton() implementation.
 */
int
_inet_pton(int af, char *inp, void *outp)
{
	return (__inet_pton(af, inp, outp, 0));
}

/*
 * Provide broken inet_pton() implementation by default for binary
 * compatibility.
 */
int
inet_pton(int af, char *inp, void *outp)
{
	return (__inet_pton(af, inp, outp, 1));
}
