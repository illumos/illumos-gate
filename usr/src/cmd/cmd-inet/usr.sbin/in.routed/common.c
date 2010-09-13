/*
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Common (shared) routines used by in.routed daemon and the
 * the rtquery utility program
 */

#include "defs.h"
#include <ctype.h>

/* Return the classical netmask for an IP address. */
in_addr_t			/* host byte order */
std_mask(in_addr_t addr)	/* network byte order */
{
	addr = ntohl(addr);

	if (addr == 0)		/* default route has mask 0 */
		return (0);
	if (IN_CLASSA(addr))
		return (IN_CLASSA_NET);
	if (IN_CLASSB(addr))
		return (IN_CLASSB_NET);
	if (IN_CLASSC(addr))
		return (IN_CLASSC_NET);
	return (IN_CLASSE_NET);
}

/*
 * Get a network number as a name or a number, with an optional "/xx"
 * netmask.
 */
boolean_t					/* 0=bad */
getnet(const char *name,
    in_addr_t *netp,			/* network in host byte order */
    in_addr_t *maskp)			/* masks are always in host order */
{
	int i;
	struct netent *np;
	in_addr_t mask;			/* in host byte order */
	struct in_addr in;		/* a network and so host byte order */
	char hname[MAXHOSTNAMELEN+1];
	char *mname, *p;


	/*
	 * The "name" argument of this function can be one of
	 * the follwoing:
	 *	a) network name/mask
	 *	b) network name
	 *	c) network number/mask
	 *	d) network number
	 *	e) host IP address/mask
	 *	f) host IP address
	 *	g) "default"
	 *
	 * Detect and separate "1.2.3.4/24"
	 */
	if (NULL != (mname = strrchr(name, '/'))) {
		i = (int)(mname - name);
		if (i > (int)sizeof (hname)-1)	/* name too long */
			return (_B_FALSE);
		(void) memmove(hname, name, i);
		hname[i] = '\0';
		mname++;
		name = hname;
	}

	if ((in.s_addr = inet_network(name)) == (in_addr_t)-1) {
		if (mname == NULL && strcasecmp(name, "default") == 0)
			in.s_addr = ntohl(RIP_DEFAULT);
		else if ((np = getnetbyname(name)) != NULL)
			in.s_addr = np->n_net;
		else
			return (_B_FALSE);
	}
	/* Left-align the host-byte-order result from above. */
	if (0 == (in.s_addr & 0xff000000))
		in.s_addr <<= 8;
	if (0 == (in.s_addr & 0xff000000))
		in.s_addr <<= 8;
	if (0 == (in.s_addr & 0xff000000))
		in.s_addr <<= 8;

	if (mname == NULL) {
		mask = std_mask(htonl(in.s_addr));
		if ((~mask & in.s_addr) != 0)
			mask = HOST_MASK;
	} else {
		mask = (uint32_t)strtoul(mname, &p, 0);
		if (*p != '\0' || mask > 32 || mname == p)
			return (_B_FALSE);
		if (mask != 0)
			mask = HOST_MASK << (32-mask);
	}

	/* must have mask of 0 with default */
	if (mask != 0 && in.s_addr == RIP_DEFAULT)
		return (_B_FALSE);
	/* no host bits allowed in a network number */
	if ((~mask & in.s_addr) != 0)
		return (_B_FALSE);
	/* require non-zero network number */
	if ((mask & in.s_addr) == 0 && in.s_addr != RIP_DEFAULT)
		return (_B_FALSE);
	if ((in.s_addr >> 24) == 0 && in.s_addr != RIP_DEFAULT)
		return (_B_FALSE);
	if ((in.s_addr >> 24) == 0xff)
		return (_B_FALSE);

	*netp = in.s_addr;
	*maskp = mask;
	return (_B_TRUE);
}

/*
 * Convert string to printable characters
 */
char *
qstring(const uchar_t *srcp, int len)
{
	/*
	 * Authentication schemes for RIPv2 uses the space of an
	 * 20-octet route entry.
	 */
	static char buf[8*20+1];
	char *prcp, *tmp_ptr;
	uchar_t c;
	const uchar_t *s2;

	s2 = srcp + len;
	while (s2 > srcp && *--s2 == '\0')
		len--;
	for (prcp = buf; len != 0 && prcp < &buf[sizeof (buf)-1]; len--) {
		c = *srcp++;
		if (isprint(c) && c != '\\') {
			*prcp++ = c;
			continue;
		}

		*prcp++ = '\\';
		tmp_ptr = strchr("\\\\\nn\rr\tt\bb\aa\ff", c);
		if (tmp_ptr != NULL)
			*prcp++ = tmp_ptr[1];
		else
			prcp += snprintf(prcp,
			    (sizeof (buf) - (strlen(buf)+1)), "%o", c);
	}
	*prcp = '\0';
	return (buf);
}

/* like strtok(), but honoring backslash and not changing the source string */
int			/* 0=ok, -1=bad */
parse_quote(char **linep,	/* look here */
    const char *delims,		/* for these delimiters */
    char *delimp,		/* 0 or put found delimiter here */
    char *buf,			/* copy token to here */
    int	lim)			/* at most this many bytes */
{
	char c = '\0', *pc;
	const char *p;


	pc =  *linep;
	if (*pc == '\0')
		return (-1);

	while (lim != 0) {
		c = *pc++;
		if (c == '\0')
			break;

		if (c == '\\' && *pc != '\0') {
			c = *pc++;
			switch (c) {
			case 'n':
				c = '\n';
				break;
			case 'r':
				c = '\r';
				break;
			case 't':
				c = '\t';
				break;
			case 'b':
				c = '\b';
			}
			if (c >= '0' && c <= '7') {
				c -= '0';
				if (*pc >= '0' && *pc <= '7') {
					c = (c<<3)+(*pc++ - '0');
					if (*pc >= '0' && *pc <= '7')
					    c = (c<<3)+(*pc++ - '0');
				}
			}

		} else {
			for (p = delims; *p != '\0'; ++p) {
				if (*p == c || isspace(c) && *p == ' ')
					goto exit;
			}
		}

		*buf++ = c;
		--lim;
	}
exit:
	if (lim == 0)
		return (-1);

	*buf = '\0';			/* terminate copy of token */
	if (delimp != NULL)
		*delimp = c;		/* return delimiter */
	*linep = pc-1;			/* say where we ended */
	return (0);
}

/*
 * Find the option buffer in the msg corresponding to cmsg_type.
 */
void *
find_ancillary(struct msghdr *msg, int cmsg_type)
{
	struct cmsghdr *cmsg;

	for (cmsg = CMSG_FIRSTHDR(msg); cmsg != NULL;
	    cmsg = CMSG_NXTHDR(msg, cmsg)) {
		if (cmsg->cmsg_level == IPPROTO_IP &&
		    cmsg->cmsg_type == cmsg_type) {
			return (CMSG_DATA(cmsg));
		}
	}
	return (NULL);
}
