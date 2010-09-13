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
#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Copyright (c) 1996-2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <syslog.h>
#include <netinet/in.h>
#include <netinet/dhcp.h>
#include <dhcp_gen.h>
#include <dhcpd.h>
#include <per_network.h>
#include <dhcp_msgs.h>

int debug = 1;
int verbose = 1;

/*
 * smalloc()  --  safe malloc()
 *
 * Always returns a valid pointer (if it returns at all).  The allocated
 * memory is initialized to all zeros.  If malloc() returns an error, a
 * message is printed using the syslog() function and the program aborts
 * with a status of 1.
 */
char *
smalloc(uint_t nbytes)
{
	char *retvalue;

	if ((retvalue = (char *)malloc(nbytes)) == (char *)NULL) {
		dhcp_error(LOG_ERR, DHCP_MSGS(DCMSG_NO_MEMORY));
		(void) exit(1);
	}
	memset(retvalue, 0, nbytes);
	return (retvalue);
}

int
main(void)
{
	struct in_addr five_net = {109, 108, 5, 0};
	struct in_addr five_mask = {109, 108, 5, 255};
	struct in_addr serverid = {109, 108, 5, 138};
	struct in_addr scratch;
	PER_NET_DB	pndb;
	PN_REC		pn;
	uchar_t buf[MAX_CID_LEN] = {0x1, 0x0, 0x0, 0xc0, 0xee, 0xe, 0x4c };
	char tbuf[MAX_CID_LEN];
	int recs;
	unsigned int len;
	register int i, err = 0;


	/*
	 * Test 0. Open the per network database, and locate a *single*
	 * record by cid.
	 */
	printf("Test 0: START ******************************************\n");
	memset(&pndb, 0, sizeof (pndb));

	if (open_per_net(&pndb, &five_net, &five_mask) != 0) {
		printf("didn't work.\n");
		return (1);
	}

	/*
	 * Should only be one.
	 */
	memset(&pn, 0, sizeof (pn));
	recs = lookup_per_net(&pndb, PN_CID, (void *)buf, 7, &serverid, &pn);
	if (recs < 0)
		printf("lookup didn't work.\n");
	else {
		if (recs > 0) {
			len = MAX_CID_LEN;
			octet_to_hexascii(buf, 7, tbuf, &len);
			printf("Client id: %s\n", tbuf);
			printf("flags: 0x%x\n", pn.flags);
			printf("IP address is: %s\n", inet_ntoa(pn.clientip));
			printf("server IP address is: %s\n",
			    inet_ntoa(pn.serverip));

			len = MAX_CID_LEN;
			octet_to_hexascii(&pn.lease, 4, tbuf, &len);
			printf("lease is %s, 0x%x\n", tbuf, pn.lease);
			printf("macro is %s\n", pn.macro);
			printf("Number of records: %d\n", recs);
		}
	}
	close_per_net(&pndb);

	printf("Test 0: END ******************************************\n");
	/* END TEST 0 ********************************************* */

	/*
	 * Test 1. Open the per net database, locate all records with
	 * cid of 0.
	 */
	printf("Test 1: START ******************************************\n");
	if (open_per_net(&pndb, &five_net, &five_mask) != 0) {
		printf("didn't work.\n");
		return (1);
	} else {
		printf("name: %s\n", pndb.name);
	}

	memset(buf, 0, MAX_CID_LEN);
	recs = lookup_per_net(&pndb, PN_CID, (void *)buf, 1, &serverid, &pn);
	if (recs < 0)
		printf("lookup didn't work.\n");
	else {
		printf("datatype: %d\n", pndb.datatype);
		printf("row: %d\n", pndb.row);
		if (recs > 0) {
			len = MAX_CID_LEN;
			octet_to_hexascii(buf, 7, tbuf, &len);
			printf("Client id: %s\n", tbuf);
			printf("flags: 0x%x\n", pn.flags);
			printf("IP address is: %s\n", inet_ntoa(pn.clientip));
			printf("server IP address is: %s\n",
			    inet_ntoa(pn.serverip));

			len = MAX_CID_LEN;
			octet_to_hexascii(&pn.lease, 4, tbuf, &len);
			printf("lease is %s, 0x%x\n", tbuf, pn.lease);
			printf("macro is %s\n", pn.macro);
			printf("Number of records: %d\n", recs);
			for (i = 0; i < recs; i++) {
				if (get_per_net(&pndb, PN_CID, &pn) != 0) {
					printf("didn't work 2: \n");
					break;
				}
				len = MAX_CID_LEN;
				octet_to_hexascii(buf, 7, tbuf, &len);
				printf("Client id: %s\n", tbuf);
				printf("flags: 0x%x\n", pn.flags);
				printf("IP address is: %s\n",
				    inet_ntoa(pn.clientip));
				printf("server IP address is: %s\n",
				    inet_ntoa(pn.serverip));

				len = MAX_CID_LEN;
				octet_to_hexascii(&pn.lease, 4, tbuf, &len);
				printf("lease is %s, 0x%x\n", tbuf, pn.lease);
				printf("macro is %s\n", pn.macro);
			}
		}
	}

	close_per_net(&pndb);
	printf("Test 1: END ******************************************\n");
	printf("Test 2: START ******************************************\n");
	/*
	 * Locate client ip 109.108.5.221.
	 */
	scratch.s_addr = 0x6d6c05dd;
	if (open_per_net(&pndb, &five_net, &five_mask) != 0) {
		printf("didn't work.\n");
		return (1);
	} else {
		printf("name: %s\n", pndb.name);
	}

	recs = lookup_per_net(&pndb, PN_CLIENT_IP, (void *)&scratch, 4,
	    &serverid, &pn);
	if (recs < 0)
		printf("lookup didn't work.\n");
	else {
		printf("datatype: %d\n", pndb.datatype);
		printf("row: %d\n", pndb.row);
		if (recs > 0) {
			len = MAX_CID_LEN;
			octet_to_hexascii(buf, 7, tbuf, &len);
			printf("Client id: %s\n", tbuf);
			printf("flags: 0x%x\n", pn.flags);
			printf("IP address is: %s\n", inet_ntoa(pn.clientip));
			printf("server IP address is: %s\n",
			    inet_ntoa(pn.serverip));

			len = MAX_CID_LEN;
			octet_to_hexascii(&pn.lease, 4, tbuf, &len);
			printf("lease is %s, 0x%x\n", tbuf, pn.lease);
			printf("macro is %s\n", pn.macro);
			printf("Number of records: %d\n", recs);
		}
	}

	printf("Test 2: END ******************************************\n");
	printf("Test 3: START ******************************************\n");
	if (recs > 0) {
		/*
		 * Using the record from test 2, change the cid, flags, and
		 * lease, then write the record.
		 */
		pn.cid_len = 7;
		for (i = 0; (uchar_t)i < pn.cid_len; i++)
			pn.cid[i] = i;
		pn.flags |= F_AUTOMATIC;
		pn.lease = htonl(time(NULL));

		if ((err = put_per_net(&pndb, &pn, PN_CLIENT_IP)) != 0) {
			printf("didn't work. error: %d\n", err);
		} else
			printf("it worked.\n");
	}
	close_per_net(&pndb);
	printf("Test 3: END ******************************************\n");

	return (0);
}
