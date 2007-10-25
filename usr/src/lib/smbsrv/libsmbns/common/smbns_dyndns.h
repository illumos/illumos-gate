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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SMBSRV_DYNDNS_H
#define	_SMBSRV_DYNDNS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <smbsrv/libsmbns.h>

/*
 * Header section format:
 *
 * The header contains the following fields:
 *
 *                                     1  1  1  1  1  1
 *       0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
 *     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *     |                      ID                       |
 *     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *     |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
 *     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *     |                    QDCOUNT                    |
 *     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *     |                    ANCOUNT                    |
 *     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *     |                    NSCOUNT                    |
 *     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *     |                    ARCOUNT                    |
 *     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *
 * where:
 *
 * ID              A 16 bit identifier assigned by the program that
 *                 generates any kind of query.  This identifier is copied
 *                 the corresponding reply and can be used by the requester
 *                 to match up replies to outstanding queries.
 *
 * QR              A one bit field that specifies whether this message is a
 *                 query (0), or a response (1).
 *
 * OPCODE          A four bit field that specifies kind of query in this
 *                 message.  This value is set by the originator of a query
 *                 and copied into the response.  The values are:
 *
 *                 0               a standard query (QUERY)
 *
 *                 1               an inverse query (IQUERY)
 *
 *                 2               a server status request (STATUS)
 *
 *                 3-15            reserved for future use
 *
 * AA              Authoritative Answer - this bit is valid in responses,
 *                 and specifies that the responding name server is an
 *                 authority for the domain name in question section.
 *
 *                 Note that the contents of the answer section may have
 *                 multiple owner names because of aliases.  The AA bit
 *
 *                 corresponds to the name which matches the query name, or
 *                 the first owner name in the answer section.
 *
 * TC              TrunCation - specifies that this message was truncated
 *                 due to length greater than that permitted on the
 *                 transmission channel.
 *
 * RD              Recursion Desired - this bit may be set in a query and
 *                 is copied into the response.  If RD is set, it directs
 *                 the name server to pursue the query recursively.
 *                 Recursive query support is optional.
 *
 * RA              Recursion Available - this be is set or cleared in a
 *                 response, and denotes whether recursive query support is
 *                 available in the name server.
 *
 * Z               Reserved for future use.  Must be zero in all queries
 *                 and responses.
 *
 * RCODE           Response code - this 4 bit field is set as part of
 *                 responses.  The values have the following
 *                 interpretation:
 *
 *                 0               No error condition
 *
 *                 1               Format error - The name server was
 *                                 unable to interpret the query.
 *
 *                 2               Server failure - The name server was
 *                                 unable to process this query due to a
 *                                 problem with the name server.
 *
 *                 3               Name Error - Meaningful only for
 *                                 responses from an authoritative name
 *                                 server, this code signifies that the
 *                                 domain name referenced in the query does
 *                                 not exist.
 *
 *                 4               Not Implemented - The name server does
 *                                 not support the requested kind of query.
 *
 *                 5               Refused - The name server refuses to
 *                                 perform the specified operation for
 *                                 policy reasons.  For example, a name
 *                                 server may not wish to provide the
 *                                 information to the particular requester,
 *                                 or a name server may not wish to perform
 *                                 a particular operation (e.g., zone
 *
 *                                 transfer) for particular data.
 *
 *                 6-15            Reserved for future use.
 *
 * QDCOUNT         an unsigned 16 bit integer specifying the number of
 *                 entries in the question section.
 *
 * ANCOUNT         an unsigned 16 bit integer specifying the number of
 *                 resource records in the answer section.
 *
 * NSCOUNT         an unsigned 16 bit integer specifying the number of name
 *                 server resource records in the authority records
 *                 section.
 *
 * ARCOUNT         an unsigned 16 bit integer specifying the number of
 *                 resource records in the additional records section.
 */

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Other definitions: */
#define	REQ_QUERY	1	/* DNS query request */
#define	REQ_UPDATE	0	/* DNS update request */
#define	UPDATE_FORW	1	/* Update forward lookup zone */
#define	UPDATE_REV	0	/* Update reverse lookup zone */
#define	UPDATE_ADD	1	/* Update add request */
#define	UPDATE_DEL	0	/* Update remove request */
#define	MODE_GSS_API	3	/* Key negotiation mode */

/* Max buffer size for send and receive buffer */
#define	MAX_BUF_SIZE	2000
#define	MAX_RETRIES	3	/* Max number of send retries if no response */
#define	TSIG_SIGNED	1	/* TSIG contains signed data */
#define	TSIG_UNSIGNED	0	/* TSIG does not conain signed data */
#define	DNS_CHECK	1	/* Check DNS for entry */
#define	DNS_NOCHECK	0	/* Don't check DNS for entry */
#define	MAX_TCP_SIZE 	2000	/* max tcp DNS message size */

/* Delete 1 entry */
#define	DEL_ONE		1
/* Delete all entries of the same resource name */
#define	DEL_ALL		0

#define	DNSF_RECUR_SUPP 0x80    /* Server can do recursive queries */
#define	DNSF_RECUR_QRY  0x100   /* Query is recursive */

#define	BUFLEN_TCP(x, y) (MAX_TCP_SIZE-(x-y))
#define	BUFLEN_UDP(x, y) (NS_PACKETSZ-(x-y))

extern char *dyndns_get_nshort(char *, uint16_t *);
extern char *dyndns_get_int(char *, int *);
extern int dyndns_build_header(char **, int, uint16_t, int,
    uint16_t, uint16_t, uint16_t, uint16_t, int);
extern int dyndns_build_quest_zone(char **, int, char *, int, int);
extern int dyndns_open_init_socket(int sock_type, unsigned long dest_addr,
    int port);
extern int dyndns_udp_send_recv(int, char *, int, char *);
extern void dyndns_msg_err(int);

/*
 * DDNS_TTL is the time to live in DNS caches. Note that this
 * does not affect the entry in the authoritative DNS database.
 */
#define	DDNS_TTL	1200

#ifdef __cplusplus
}
#endif

#endif /* _SMBSRV_DYNDNS_H */
