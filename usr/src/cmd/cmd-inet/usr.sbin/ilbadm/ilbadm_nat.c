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

#include <sys/types.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <stdio.h>
#include <strings.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <libilb.h>
#include "ilbadm.h"

/*
 * For each iteration through the kernel table, ask for at most NUM_ENTRIES
 * entries to be returned.
 */
#define	NUM_ENTRIES	500

static void
print_nat_info(ilb_nat_info_t *info)
{
	char *tmp;
	ipaddr_t addr_v4;
	char addr[INET6_ADDRSTRLEN];

	if (info->nat_proto == IPPROTO_TCP)
		tmp = "TCP";
	else if (info->nat_proto == IPPROTO_UDP)
		tmp = "UDP";
	else
		tmp = "Unknown";
	(void) printf("%4s: ", tmp);

	if (IN6_IS_ADDR_V4MAPPED(&info->nat_out_global)) {
		IN6_V4MAPPED_TO_IPADDR(&info->nat_out_global, addr_v4);
		(void) printf("%s.%d > ", inet_ntop(AF_INET, &addr_v4, addr,
		    INET6_ADDRSTRLEN), ntohs(info->nat_out_global_port));
		IN6_V4MAPPED_TO_IPADDR(&info->nat_in_global, addr_v4);
		(void) printf("%s.%d >>> ", inet_ntop(AF_INET, &addr_v4, addr,
		    INET6_ADDRSTRLEN), ntohs(info->nat_in_global_port));

		IN6_V4MAPPED_TO_IPADDR(&info->nat_out_local, addr_v4);
		(void) printf("%s.%d > ", inet_ntop(AF_INET, &addr_v4, addr,
		    INET6_ADDRSTRLEN), ntohs(info->nat_out_local_port));
		IN6_V4MAPPED_TO_IPADDR(&info->nat_in_local, addr_v4);
		(void) printf("%s.%d\n", inet_ntop(AF_INET, &addr_v4, addr,
		    INET6_ADDRSTRLEN), ntohs(info->nat_in_local_port));
	} else {
		(void) printf("%s.%d > ", inet_ntop(AF_INET6,
		    &info->nat_out_global, addr, INET6_ADDRSTRLEN),
		    ntohs(info->nat_out_global_port));
		(void) printf("%s.%d >>> ", inet_ntop(AF_INET6,
		    &info->nat_in_global, addr, INET6_ADDRSTRLEN),
		    ntohs(info->nat_in_global_port));

		(void) printf("%s.%d > ", inet_ntop(AF_INET6,
		    &info->nat_out_local, addr, INET6_ADDRSTRLEN),
		    ntohs(info->nat_out_local_port));
		(void) printf("%s.%d\n", inet_ntop(AF_INET6,
		    &info->nat_in_local, addr, INET6_ADDRSTRLEN),
		    ntohs(info->nat_in_local_port));
	}
}

static void
print_persist_info(ilb_persist_info_t *info)
{
	char addr[INET6_ADDRSTRLEN];

	(void) printf("%s: ", info->persist_rule_name);
	if (IN6_IS_ADDR_V4MAPPED(&info->persist_req_addr)) {
		ipaddr_t addr_v4;

		IN6_V4MAPPED_TO_IPADDR(&info->persist_req_addr, addr_v4);
		(void) printf("%s --> ", inet_ntop(AF_INET, &addr_v4, addr,
		    INET6_ADDRSTRLEN));
		IN6_V4MAPPED_TO_IPADDR(&info->persist_srv_addr, addr_v4);
		(void) printf("%s\n", inet_ntop(AF_INET, &addr_v4, addr,
		    INET6_ADDRSTRLEN));
	} else {
		(void) printf("%s --> ", inet_ntop(AF_INET6,
		    &info->persist_req_addr, addr, INET6_ADDRSTRLEN));
		(void) printf("%s\n", inet_ntop(AF_INET6,
		    &info->persist_srv_addr, addr, INET6_ADDRSTRLEN));
	}
}

/* Tell ilbadm_show_info() which table to show. */
enum which_tbl {
	show_nat = 1,
	show_persist
};

typedef union {
	ilb_nat_info_t		*nbuf;
	ilb_persist_info_t	*pbuf;
	char			*buf;
} show_buf_t;

static ilbadm_status_t
ilbadm_show_info(int argc, char *argv[], enum which_tbl tbl)
{
	ilb_handle_t		h = ILB_INVALID_HANDLE;
	show_buf_t		buf;
	ilb_status_t		rclib = ILB_STATUS_OK;
	ilbadm_status_t		rc = ILBADM_OK;
	int32_t			i, num_entries;
	size_t			num;
	boolean_t		end;
	size_t			entry_sz;

	/*
	 * If the user does not specify a count, return the whole table.
	 * This requires setting the fourth param to ilb_show_nat/persist()
	 * end to B_FALSE.  Otherwise, set end to B_TRUE;
	 */

	switch (argc) {
	case 1:
		num_entries = -1;
		end = B_FALSE;
		break;
	case 2:
		num_entries = atoi(argv[1]);
		if (num_entries < 1) {
			rc = ILBADM_EINVAL;
			goto out;
		}
		end = B_TRUE;
		break;
	default:
		rc = ILBADM_EINVAL;
		goto out;
	}

	if (tbl == show_nat)
		entry_sz = sizeof (ilb_nat_info_t);
	else
		entry_sz = sizeof (ilb_persist_info_t);
	if ((buf.buf = malloc((num_entries > 0 ? num_entries : NUM_ENTRIES) *
	    entry_sz)) == NULL) {
		rc = ILBADM_ENOMEM;
		goto out;
	}

	rclib = ilb_open(&h);
	if (rclib != ILB_STATUS_OK)
		goto out;

	do {
		num = num_entries > 0 ? num_entries : NUM_ENTRIES;
		bzero(buf.buf, num * entry_sz);

		if (tbl == show_nat)
			rclib = ilb_show_nat(h, buf.nbuf, &num, &end);
		else
			rclib = ilb_show_persist(h, buf.pbuf, &num, &end);

		if (rclib != ILB_STATUS_OK)
			break;

		for (i = 0; i < num; i++) {
			if (tbl == show_nat)
				print_nat_info(&buf.nbuf[i]);
			else
				print_persist_info(&buf.pbuf[i]);
		}
		if (num_entries > 0) {
			num_entries -= num;
			if (num_entries <= 0)
				break;
		}
	} while (!end);
	free(buf.buf);
out:
	if (h != ILB_INVALID_HANDLE)
		(void) ilb_close(h);
	if (rclib != ILB_STATUS_OK) {
		ilbadm_err(ilb_errstr(rclib));
		rc = ILBADM_LIBERR;
	}
	if ((rc != ILBADM_OK) && (rc != ILBADM_LIBERR))
		ilbadm_err(ilbadm_errstr(rc));
	return (rc);
}


ilbadm_status_t
ilbadm_show_nat(int argc, char *argv[])
{
	return (ilbadm_show_info(argc, argv, show_nat));
}

ilbadm_status_t
ilbadm_show_persist(int argc, char *argv[])
{
	return (ilbadm_show_info(argc, argv, show_persist));
}
