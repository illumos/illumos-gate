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
 */

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <fcntl.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/time.h>

#include <sys/socket.h>
#include <sys/sockio.h>
#include <net/if.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <netinet/if_ether.h>
#include <inet/ipsecesp.h>
#include <inet/ipsecah.h>
#include "snoop.h"

/* ARGSUSED */
int
interpret_esp(int flags, uint8_t *hdr, int iplen, int fraglen)
{
	/* LINTED: alignment */
	esph_t *esph = (esph_t *)hdr;
	esph_t *aligned_esph;
	esph_t storage;	/* In case hdr isn't aligned. */
	char *line;

	if (fraglen < sizeof (esph_t))
		return (fraglen);	/* incomplete header */

	if (!IS_P2ALIGNED(hdr, 4)) {
		aligned_esph = &storage;
		bcopy(hdr, aligned_esph, sizeof (esph_t));
	} else {
		aligned_esph = esph;
	}

	if (flags & F_SUM) {
		line = (char *)get_sum_line();
		/*
		 * sprintf() is safe because line guarantees us 80 columns,
		 * and SPI and replay certainly won't exceed that.
		 */
		(void) sprintf(line, "ESP SPI=0x%x Replay=%u",
		    ntohl(aligned_esph->esph_spi),
		    ntohl(aligned_esph->esph_replay));
		line += strlen(line);
	}

	if (flags & F_DTAIL) {
		show_header("ESP:  ", "Encapsulating Security Payload",
		    sizeof (esph_t));
		show_space();
		/*
		 * sprintf() is safe because get_line guarantees us 80 columns,
		 * and SPI and replay certainly won't exceed that.
		 */
		(void) sprintf(get_line((char *)&esph->esph_spi - dlc_header,
		    4), "SPI = 0x%x", ntohl(aligned_esph->esph_spi));
		(void) sprintf(get_line((char *)&esph->esph_replay -
		    dlc_header, 4), "Replay = %u",
		    ntohl(aligned_esph->esph_replay));
		(void) sprintf(get_line((char *)(esph + 1) - dlc_header,
		    4), "   ....ENCRYPTED DATA....");
	}

	return (sizeof (esph_t));
}

int
interpret_ah(int flags, uint8_t *hdr, int iplen, int fraglen)
{
	/* LINTED: alignment */
	ah_t *ah = (ah_t *)hdr;
	ah_t *aligned_ah;
	ah_t storage;	/* In case hdr isn't aligned. */
	char *line, *buff;
	uint_t ahlen, auth_data_len;
	uint8_t *auth_data, *data;
	int new_iplen;
	uint8_t proto;

	if (fraglen < sizeof (ah_t))
		return (fraglen);		/* incomplete header */

	if (!IS_P2ALIGNED(hdr, 4)) {
		aligned_ah = (ah_t *)&storage;
		bcopy(hdr, &storage, sizeof (ah_t));
	} else {
		aligned_ah = ah;
	}

	/*
	 * "+ 8" is for the "constant" part that's not included in the AH
	 * length.
	 *
	 * The AH RFC specifies the length field in "length in 4-byte units,
	 * not counting the first 8 bytes".  So if an AH is 24 bytes long,
	 * the length field will contain "4".  (4 * 4 + 8 == 24).
	 */
	ahlen = (aligned_ah->ah_length << 2) + 8;
	fraglen -= ahlen;
	if (fraglen < 0)
		return (fraglen + ahlen);	/* incomplete header */

	auth_data_len = ahlen - sizeof (ah_t);
	auth_data = (uint8_t *)(ah + 1);
	data = auth_data + auth_data_len;

	if (flags & F_SUM) {
		line = (char *)get_sum_line();
		(void) sprintf(line, "AH SPI=0x%x Replay=%u",
		    ntohl(aligned_ah->ah_spi), ntohl(aligned_ah->ah_replay));
		line += strlen(line);
	}

	if (flags & F_DTAIL) {
		show_header("AH:  ", "Authentication Header", ahlen);
		show_space();
		(void) sprintf(get_line((char *)&ah->ah_nexthdr - dlc_header,
		    1), "Next header = %d (%s)", aligned_ah->ah_nexthdr,
		    getproto(aligned_ah->ah_nexthdr));
		(void) sprintf(get_line((char *)&ah->ah_length - dlc_header, 1),
		    "AH length = %d (%d bytes)", aligned_ah->ah_length, ahlen);
		(void) sprintf(get_line((char *)&ah->ah_reserved - dlc_header,
		    2), "<Reserved field = 0x%x>",
		    ntohs(aligned_ah->ah_reserved));
		(void) sprintf(get_line((char *)&ah->ah_spi - dlc_header, 4),
		    "SPI = 0x%x", ntohl(aligned_ah->ah_spi));
		(void) sprintf(get_line((char *)&ah->ah_replay - dlc_header, 4),
		    "Replay = %u", ntohl(aligned_ah->ah_replay));

		/*
		 * 2 for two hex digits per auth_data byte
		 * plus one byte for trailing null byte.
		 */
		buff = malloc(auth_data_len * 2 + 1);
		if (buff != NULL) {
			int i;

			for (i = 0; i < auth_data_len; i++)
				sprintf(buff + i * 2, "%02x", auth_data[i]);
		}

		(void) sprintf(get_line((char *)auth_data - dlc_header,
		    auth_data_len), "ICV = %s",
		    (buff == NULL) ? "<out of memory>" : buff);

		/* malloc(3c) says I can call free even if buff == NULL */
		free(buff);

		show_space();
	}

	new_iplen = iplen - ahlen;
	proto = aligned_ah->ah_nexthdr;

	/*
	 * Print IPv6 Extension Headers, or skip them in the summary case.
	 */
	if (proto == IPPROTO_HOPOPTS || proto == IPPROTO_DSTOPTS ||
	    proto == IPPROTO_ROUTING || proto == IPPROTO_FRAGMENT) {
		(void) print_ipv6_extensions(flags, &data, &proto, &iplen,
		    &fraglen);
	}

	if (fraglen > 0)
		switch (proto) {
			case IPPROTO_ENCAP:
				/* LINTED: alignment */
				(void) interpret_ip(flags, (struct ip *)data,
				    new_iplen);
				break;
			case IPPROTO_IPV6:
				(void) interpret_ipv6(flags, (ip6_t *)data,
				    new_iplen);
				break;
			case IPPROTO_ICMP:
				(void) interpret_icmp(flags,
				    /* LINTED: alignment */
				    (struct icmp *)data, new_iplen, fraglen);
				break;
			case IPPROTO_ICMPV6:
				/* LINTED: alignment */
				(void) interpret_icmpv6(flags, (icmp6_t *)data,
				    new_iplen, fraglen);
				break;
			case IPPROTO_TCP:
				(void) interpret_tcp(flags,
				    (struct tcphdr *)data, new_iplen, fraglen);
				break;

			case IPPROTO_ESP:
				(void) interpret_esp(flags, data, new_iplen,
				    fraglen);
				break;

			case IPPROTO_AH:
				(void) interpret_ah(flags, data, new_iplen,
				    fraglen);
				break;

			case IPPROTO_UDP:
				(void) interpret_udp(flags,
				    (struct udphdr *)data, new_iplen, fraglen);
				break;
			/* default case is to not print anything else */
		}

	return (ahlen);
}
