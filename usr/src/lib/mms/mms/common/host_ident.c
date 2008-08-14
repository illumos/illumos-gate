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
 *
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


/*
 * Covert host name or ip mms_address to internal mm ident.
 *
 * IPv6 and IPv4 lookup code is from:
 * http://aggregate.eng/ws/onnv_nightly/source
 * /usr/src/cmd/auditconfig/auditconfig.c
 */
#include <string.h>
#include <sys/types.h>
#include <string.h>
#include <stdlib.h>
#include <netdb.h>
#include <nss_dbdefs.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <ctype.h>
#include <strings.h>
#include "mms_network.h"
#include "host_ident.h"


typedef enum mms_address_type mms_a_type_t;
enum mms_address_type {
	MMS_ADDRESS_IPv4,
	MMS_ADDRESS_IPv6
};

typedef struct mms_address mms_address_t;
struct mms_address {
	mms_a_type_t a_type;
	uint_t a_addr[4];
};

static void mms_get_address(char *host_str, mms_address_t *addressp);
static void mms_get_strings(char *host, char *ip, mms_address_t *addressp);
static void mms_get_localhost(char *host_str);


char *
mms_host_ident(char *host_str, char *host, char *ip)
{
	mms_address_t mms_address;

	(void) memset(&mms_address, 0, sizeof (mms_address_t));
	if (host_str == NULL || host == NULL || ip == NULL)
		return (NULL);
	host[0] = '\0';
	ip[0] = '\0';

	mms_get_localhost(host_str);
	mms_get_address(host_str, &mms_address);
	mms_get_strings(host, ip, &mms_address);

	if (strcmp(host, "unknown") == 0 ||
	    strcmp(ip, "::") == 0) {
		return (NULL);
	}

	/* currently mm uses ip addresses internally */
	return (ip);
}

static void
mms_get_address(char *host_str, mms_address_t *addressp)
{
	struct hostent *phe;
	int err;
	uint32_t ibuf;
	uint32_t ibuf6[4];

	addressp->a_type = 0;
	bzero(addressp->a_addr, 16);

	/* try ip mms_address first */
	if (inet_pton(AF_INET, host_str, &ibuf)) {
		addressp->a_addr[0] = ibuf;
		addressp->a_type = MMS_ADDRESS_IPv4;
		return;
	} else if (inet_pton(AF_INET6, host_str, ibuf6)) {
		addressp->a_addr[0] = ibuf6[0];
		addressp->a_addr[1] = ibuf6[1];
		addressp->a_addr[2] = ibuf6[2];
		addressp->a_addr[3] = ibuf6[3];
		addressp->a_type = MMS_ADDRESS_IPv6;
		return;
	}

	/* try by name */
	phe = getipnodebyname((const void *)host_str, AF_INET, 0, &err);
	if (phe == 0) {
		phe = getipnodebyname((const void *)host_str, AF_INET6,
		    0, &err);
	}

	if (phe != NULL) {
		if (phe->h_addrtype == AF_INET6) {
			/* mms_address is IPv6 (128 bits) */
			(void) memcpy(&addressp->a_addr[0],
			    phe->h_addr_list[0], 16);
			addressp->a_type = MMS_ADDRESS_IPv6;
		} else {
			/* mms_address is IPv4 (32 bits) */
			(void) memcpy(&addressp->a_addr[0],
			    phe->h_addr_list[0], 4);
			addressp->a_type = MMS_ADDRESS_IPv4;
		}
		freehostent(phe);
	}
}

static void
mms_get_strings(char *host, char *ip, mms_address_t *addressp)
{
	struct hostent *phe = NULL;
	char *hostname = NULL;
	struct in_addr ia;
	uint32_t *addr = NULL;
	int err;
	char buf[256];
	char *bufp = NULL;

	struct hostent result;
	char *buffer;

	/* IPV6 or IPV4 mms_address */
	if (addressp->a_type == MMS_ADDRESS_IPv4) {
		buffer = (char *)malloc(NSS_BUFLEN_HOSTS);
		if (buffer != NULL &&
		    (phe = gethostbyaddr_r((char *)&addressp->a_addr[0],
		    sizeof (addressp->a_addr[0]), AF_INET,
		    &result, buffer, NSS_BUFLEN_HOSTS, &err))
		    != (struct hostent *)NULL)
			hostname = phe->h_name;
		else
			hostname = "unknown";

		ia.s_addr = addressp->a_addr[0];

		(void) strcpy(host, hostname);
		(void) strcpy(ip, inet_ntoa(ia));
		if (buffer) {
			free(buffer);
		}
	} else {
		addr = &addressp->a_addr[0];
		phe = getipnodebyaddr((const void *)addr, 16,
		    AF_INET6, &err);

		bzero(buf, sizeof (buf));

		(void) inet_ntop(AF_INET6, (void *)addr, buf, sizeof (buf));
		if (phe == (struct hostent *)0) {
			bufp = "unknown";
		} else {
			bufp = phe->h_name;
		}

		(void) strcpy(host, bufp);
		(void) strcpy(ip, buf);
		if (phe) {
			freehostent(phe);
		}
	}
}

static void
mms_get_localhost(char *host_str)
{
	char		ip[MMS_IP_IDENT_LEN+1];

	if (strcmp(host_str, "localhost") == 0 ||
	    strcmp(host_str, "127.0.0.1") == 0 ||
	    strcmp(host_str, "::1") == 0) {
		(void) mms_host_info(host_str, ip);
	}
}

/* localhost info */
char *
mms_host_info(char *host, char *ip)
{
	char		host_str[MMS_HOST_IDENT_LEN+1];
	mms_address_t	mms_address;

	(void) memset(&mms_address, 0, sizeof (mms_address_t));
	(void) gethostname(host_str, sizeof (host_str));
	mms_get_address(host_str, &mms_address);
	mms_get_strings(host, ip, &mms_address);

	return (ip);
}
