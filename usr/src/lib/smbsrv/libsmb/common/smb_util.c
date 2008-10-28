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

#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <sys/varargs.h>
#include <sys/types.h>
#include <smbsrv/string.h>
#include <smbsrv/libsmb.h>
#include <tiuser.h>
#include <netconfig.h>
#include <netdir.h>
#include <sys/systeminfo.h>
#include <sys/utsname.h>

static uint_t smb_make_mask(char *, uint_t);
static boolean_t smb_netmatch(struct netbuf *, char *);
static boolean_t smb_netgroup_match(struct nd_hostservlist *, char *, int);

extern  int __multi_innetgr();
extern int __netdir_getbyaddr_nosrv(struct netconfig *,
    struct nd_hostservlist **, struct netbuf *);

#define	C2H(c)		"0123456789ABCDEF"[(c)]
#define	H2C(c)    (((c) >= '0' && (c) <= '9') ? ((c) - '0') :     \
	((c) >= 'a' && (c) <= 'f') ? ((c) - 'a' + 10) :         \
	((c) >= 'A' && (c) <= 'F') ? ((c) - 'A' + 10) :         \
	'\0')
#define	DEFAULT_SBOX_SIZE		256

/*
 *
 * hexdump
 *
 * Simple hex dump display function. Displays nbytes of buffer in hex and
 * printable format. Non-printing characters are shown as '.'. It is safe
 * to pass a null pointer. Each line begins with the offset. If nbytes is
 * 0, the line will be blank except for the offset. Example output:
 *
 * 00000000  54 68 69 73 20 69 73 20 61 20 70 72 6F 67 72 61  This is a progra
 * 00000010  6D 20 74 65 73 74 2E 00                          m test..
 *
 */
void
hexdump_offset(unsigned char *buffer, int nbytes, unsigned long *start)
{
	static char *hex = "0123456789ABCDEF";
	int i, count;
	int offset;
	unsigned char *p;
	char ascbuf[64];
	char hexbuf[64];
	char *ap = ascbuf;
	char *hp = hexbuf;

	if ((p = buffer) == NULL)
		return;

	offset = *start;

	*ap = '\0';
	*hp = '\0';
	count = 0;

	for (i = 0; i < nbytes; ++i) {
		if (i && (i % 16) == 0) {
			smb_tracef("%06X %s  %s", offset, hexbuf, ascbuf);
			ap = ascbuf;
			hp = hexbuf;
			count = 0;
			offset += 16;
		}

		ap += sprintf(ap, "%c",
		    (*p >= 0x20 && *p < 0x7F) ? *p : '.');
		hp += sprintf(hp, " %c%c",
		    hex[(*p >> 4) & 0x0F], hex[(*p & 0x0F)]);
		++p;
		++count;
	}

	if (count) {
		smb_tracef("%06X %-48s  %s", offset, hexbuf, ascbuf);
		offset += count;
	}

	*start = offset;
}

void
hexdump(unsigned char *buffer, int nbytes)
{
	unsigned long start = 0;

	hexdump_offset(buffer, nbytes, &start);
}

/*
 * bintohex
 *
 * Converts the given binary data (srcbuf) to
 * its equivalent hex chars (hexbuf).
 *
 * hexlen should be at least twice as srclen.
 * if hexbuf is not big enough returns 0.
 * otherwise returns number of valid chars in
 * hexbuf which is srclen * 2.
 */
size_t
bintohex(const char *srcbuf, size_t srclen,
    char *hexbuf, size_t hexlen)
{
	size_t outlen;
	char c;

	outlen = srclen << 1;

	if (hexlen < outlen)
		return (0);

	while (srclen-- > 0) {
		c = *srcbuf++;
		*hexbuf++ = C2H(c & 0xF);
		*hexbuf++ = C2H((c >> 4) & 0xF);
	}

	return (outlen);
}

/*
 * hextobin
 *
 * Converts hex to binary.
 *
 * Assuming hexbuf only contains hex digits (chars)
 * this function convert every two bytes of hexbuf
 * to one byte and put it in dstbuf.
 *
 * hexlen should be an even number.
 * dstlen should be at least half of hexlen.
 *
 * Returns 0 if sizes are not correct, otherwise
 * returns the number of converted bytes in dstbuf
 * which is half of hexlen.
 */
size_t
hextobin(const char *hexbuf, size_t hexlen,
    char *dstbuf, size_t dstlen)
{
	size_t outlen;

	if ((hexlen % 2) != 0)
		return (0);

	outlen = hexlen >> 1;
	if (dstlen < outlen)
		return (0);

	while (hexlen > 0) {
		*dstbuf = H2C(*hexbuf) & 0x0F;
		hexbuf++;
		*dstbuf++ |= (H2C(*hexbuf) << 4) & 0xF0;
		hexbuf++;

		hexlen -= 2;
	}

	return (outlen);
}

/*
 * trim_whitespace
 *
 * Trim leading and trailing whitespace chars (as defined by isspace)
 * from a buffer. Example; if the input buffer contained "  text  ",
 * it will contain "text", when we return. We assume that the buffer
 * contains a null terminated string. A pointer to the buffer is
 * returned.
 */
char *
trim_whitespace(char *buf)
{
	char *p = buf;
	char *q = buf;

	if (buf == NULL)
		return (NULL);

	while (*p && isspace(*p))
		++p;

	while ((*q = *p++) != 0)
		++q;

	if (q != buf) {
		while ((--q, isspace(*q)) != 0)
			*q = '\0';
	}

	return (buf);
}

/*
 * randomize
 *
 * Randomize the contents of the specified buffer.
 */
void
randomize(char *data, unsigned len)
{
	unsigned dwlen = len / 4;
	unsigned remlen = len % 4;
	unsigned tmp;
	unsigned i; /*LINTED E_BAD_PTR_CAST_ALIGN*/
	unsigned *p = (unsigned *)data;

	for (i = 0; i < dwlen; ++i)
		*p++ = random();

	if (remlen) {
		tmp = random();
		(void) memcpy(p, &tmp, remlen);
	}
}

/*
 * This is the hash mechanism used to encrypt passwords for commands like
 * SamrSetUserInformation. It uses a 256 byte s-box.
 */
void
rand_hash(
    unsigned char *data,
    size_t datalen,
    unsigned char *key,
    size_t keylen)
{
	unsigned char sbox[DEFAULT_SBOX_SIZE];
	unsigned char tmp;
	unsigned char index_i = 0;
	unsigned char index_j = 0;
	unsigned char j = 0;
	int i;

	for (i = 0; i < DEFAULT_SBOX_SIZE; ++i)
		sbox[i] = (unsigned char)i;

	for (i = 0; i < DEFAULT_SBOX_SIZE; ++i) {
		j += (sbox[i] + key[i % keylen]);

		tmp = sbox[i];
		sbox[i] = sbox[j];
		sbox[j] = tmp;
	}

	for (i = 0; i < datalen; ++i) {
		index_i++;
		index_j += sbox[index_i];

		tmp = sbox[index_i];
		sbox[index_i] = sbox[index_j];
		sbox[index_j] = tmp;

		tmp = sbox[index_i] + sbox[index_j];
		data[i] = data[i] ^ sbox[tmp];
	}
}

/*
 * smb_chk_hostaccess
 *
 * Determine whether an access list grants rights to a particular host.
 * We match on aliases of the hostname as well as on the canonical name.
 * Names in the access list may be either hosts or netgroups;  they're
 * not distinguished syntactically.  We check for hosts first because
 * it's cheaper (just M*N strcmp()s), then try netgroups.
 *
 * Function returns:
 *	-1 for "all"
 *	0 not found
 *	1 found
 */
int
smb_chk_hostaccess(ipaddr_t ipaddr, char *access_list)
{
	int nentries;
	char *gr;
	char *lasts;
	char *host;
	int off;
	int i;
	int netgroup_match;
	int response;
	struct nd_hostservlist *clnames;
	struct in_addr inaddr;
	struct sockaddr_in sa;
	struct netbuf buf;
	struct netconfig *config;

	inaddr.s_addr = (uint32_t)ipaddr;

	/*
	 * If no access list - then it's "all"
	 */
	if (access_list == NULL || *access_list == '\0' ||
	    strcmp(access_list, "*") == 0)
		return (-1);

	nentries = 0;

	/* For now, only IPv4 */

	sa.sin_family = AF_INET;
	sa.sin_port = 0;
	sa.sin_addr = inaddr;

	buf.len = buf.maxlen = sizeof (sa);
	buf.buf = (char *)&sa;

	config = getnetconfigent("tcp");
	if (config == NULL)
		return (1);

	if (__netdir_getbyaddr_nosrv(config, &clnames, &buf)) {
		freenetconfigent(config);
		return (0);
	}
	freenetconfigent(config);

	for (gr = strtok_r(access_list, ":", &lasts);
	    gr != NULL; gr = strtok_r(NULL, ":", &lasts)) {

		/*
		 * If the list name has a '-' prepended
		 * then a match of the following name
		 * implies failure instead of success.
		 */
		if (*gr == '-') {
			response = 0;
			gr++;
		} else {
			response = 1;
		}

		/*
		 * The following loops through all the
		 * client's aliases.  Usually it's just one name.
		 */
		for (i = 0; i < clnames->h_cnt; i++) {
			host = clnames->h_hostservs[i].h_host;
			/*
			 * If the list name begins with a dot then
			 * do a domain name suffix comparison.
			 * A single dot matches any name with no
			 * suffix.
			 */
			if (*gr == '.') {
				if (*(gr + 1) == '\0') {  /* single dot */
					if (strchr(host, '.') == NULL)
						return (response);
				} else {
					off = strlen(host) - strlen(gr);
					if (off > 0 &&
					    strcasecmp(host + off, gr) == 0) {
						return (response);
					}
				}
			} else {

				/*
				 * If the list name begins with an at
				 * sign then do a network comparison.
				 */
				if (*gr == '@') {
					if (smb_netmatch(&buf, gr + 1))
						return (response);
				} else {
					/*
					 * Just do a hostname match
					 */
					if (strcasecmp(gr, host) == 0)
						return (response);
				}
			}
		}

		nentries++;
	}

	netgroup_match = smb_netgroup_match(clnames, access_list, nentries);

	return (netgroup_match);
}

/*
 * smb_make_mask
 *
 * Construct a mask for an IPv4 address using the @<dotted-ip>/<len>
 * syntax or use the default mask for the IP address.
 */
static uint_t
smb_make_mask(char *maskstr, uint_t addr)
{
	uint_t mask;
	uint_t bits;

	/*
	 * If the mask is specified explicitly then
	 * use that value, e.g.
	 *
	 *    @109.104.56/28
	 *
	 * otherwise assume a mask from the zero octets
	 * in the least significant bits of the address, e.g.
	 *
	 *   @109.104  or  @109.104.0.0
	 */
	if (maskstr) {
		bits = atoi(maskstr);
		mask = bits ? ~0 << ((sizeof (struct in_addr) * NBBY) - bits)
		    : 0;
		addr &= mask;
	} else {
		if ((addr & IN_CLASSA_HOST) == 0)
			mask = IN_CLASSA_NET;
		else if ((addr & IN_CLASSB_HOST) == 0)
			mask = IN_CLASSB_NET;
		else if ((addr & IN_CLASSC_HOST) == 0)
			mask = IN_CLASSC_NET;
		else
			mask = IN_CLASSE_NET;
	}

	return (mask);
}

/*
 * smb_netmatch
 *
 * Check to see if the address in the netbuf matches the "net"
 * specified by name.  The format of "name" can be:
 *	fully qualified domain name
 *	dotted IP address
 *	dotted IP address followed by '/<len>'
 *	See sharen_nfs(1M) for details.
 */

static boolean_t
smb_netmatch(struct netbuf *nb, char *name)
{
	uint_t claddr;
	struct netent n, *np;
	char *mp, *p;
	uint_t addr, mask;
	int i;
	char buff[256];

	/*
	 * Check if it's an IPv4 addr
	 */
	if (nb->len != sizeof (struct sockaddr_in))
		return (B_FALSE);

	(void) memcpy(&claddr,
	    /* LINTED pointer alignment */
	    &((struct sockaddr_in *)nb->buf)->sin_addr.s_addr,
	    sizeof (struct in_addr));
	claddr = ntohl(claddr);

	mp = strchr(name, '/');
	if (mp)
		*mp++ = '\0';

	if (isdigit(*name)) {
		/*
		 * Convert a dotted IP address
		 * to an IP address. The conversion
		 * is not the same as that in inet_addr().
		 */
		p = name;
		addr = 0;
		for (i = 0; i < 4; i++) {
			addr |= atoi(p) << ((3-i) * 8);
			p = strchr(p, '.');
			if (p == NULL)
				break;
			p++;
		}
	} else {
		/*
		 * Turn the netname into
		 * an IP address.
		 */
		np = getnetbyname_r(name, &n, buff, sizeof (buff));
		if (np == NULL) {
			return (B_FALSE);
		}
		addr = np->n_net;
	}

	mask = smb_make_mask(mp, addr);
	return ((claddr & mask) == addr);
}

/*
 * smb_netgroup_match
 *
 * Check whether any of the hostnames in clnames are
 * members (or non-members) of the netgroups in glist.
 * Since the innetgr lookup is rather expensive, the
 * result is cached. The cached entry is valid only
 * for VALID_TIME seconds.  This works well because
 * typically these lookups occur in clusters when
 * a client is mounting.
 *
 * Note that this routine establishes a host membership
 * in a list of netgroups - we've no idea just which
 * netgroup in the list it is a member of.
 *
 * glist is a character array containing grc strings
 * representing netgroup names (optionally prefixed
 * with '-'). Each string is ended with '\0'  and
 * followed immediately by the next string.
 */
static boolean_t
smb_netgroup_match(struct nd_hostservlist *clnames, char  *glist, int grc)
{
	char **grl;
	char *gr;
	int nhosts = clnames->h_cnt;
	char *host;
	int i, j, n;
	boolean_t response;
	boolean_t belong = B_FALSE;
	static char *domain = NULL;

	if (domain == NULL) {
		int	ssize;

		domain = malloc(SYS_NMLN);
		if (domain == NULL)
			return (B_FALSE);

		ssize = sysinfo(SI_SRPC_DOMAIN, domain, SYS_NMLN);
		if (ssize > SYS_NMLN) {
			free(domain);
			domain = malloc(ssize);
			if (domain == NULL)
				return (B_FALSE);
			ssize = sysinfo(SI_SRPC_DOMAIN, domain, ssize);
		}
		/* Check for error in syscall or NULL domain name */
		if (ssize <= 1)
			return (B_FALSE);
	}

	grl = calloc(grc, sizeof (char *));
	if (grl == NULL)
		return (B_FALSE);

	for (i = 0, gr = glist; i < grc && !belong; ) {
		/*
		 * If the netgroup name has a '-' prepended
		 * then a match of this name implies a failure
		 * instead of success.
		 */
		response = (*gr != '-') ? B_TRUE : B_FALSE;

		/*
		 * Subsequent names with or without a '-' (but no mix)
		 * can be grouped together for a single check.
		 */
		for (n = 0; i < grc; i++, n++, gr += strlen(gr) + 1) {
			if ((response && *gr == '-') ||
			    (!response && *gr != '-'))
				break;

			grl[n] = response ? gr : gr + 1;
		}

		/*
		 * Check the netgroup for each
		 * of the hosts names (usually just one).
		 */
		for (j = 0; j < nhosts && !belong; j++) {
			host = clnames->h_hostservs[j].h_host;
			if (__multi_innetgr(n, grl, 1, &host, 0, NULL,
			    1, &domain))
				belong = B_TRUE;
		}
	}

	free(grl);
	return (belong ? response : B_FALSE);
}
