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
 * Copyright 2001-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * mkdstore: fast datastore creation program.
 *
 * mkdstore <table> <nrecords> <cid> <flags> <cip> <sip> <lease> <comment>
 */

#include <stdio.h>
#include <netdb.h>

#include <string.h>
#include <stdlib.h>
#include <rpcsvc/nis.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <errno.h>
#include <assert.h>
#include <string.h>
#include <syslog.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <netinet/dhcp.h>
#include <netdb.h>
#include <locale.h>
#include <signal.h>
#include <tnf/probe.h>

#include <dhcp_svc_confopt.h>
#include <dhcp_svc_private.h>
#include <dhcp_impl.h>

dsvc_handle_t	dh;		/* data handle */
dsvc_datastore_t	datastore;	/* Datastore for container access */
uint_t		nrecords;
char		network[INET_ADDRSTRLEN];
struct in_addr	net;

/*
 * mkdstore <table> <nrecords> <cid> <flags> <cip> <sip> <lease> <macro>
 * <comment>
 */
main(int c, char **v)
{
	long long	cid;
	uchar_t	flags;
	struct in_addr	cip;
	struct in_addr	sip;
	int		i, j;
	char		**entries;
	uint_t		lease;
	char		*network = v[1];
	int		ct = strtol(v[2], 0L, 0L);
	char		*server;
	char		*macro;
	int		err;
	uint32_t	query;
	dn_rec_t	dn;
	dn_rec_list_t	*dncp = NULL;
	dhcp_confopt_t	*dsp = NULL;

#ifdef	DEBUG
	mallocctl(MTDEBUGPATTERN, 1);
	mallocctl(MTINITBUFFER, 1);
#endif				/* DEBUG */

	if (c == 1) {
		(void) fprintf(stderr, "/*\n * mkdstore <table> <nrecords> "
		    "<cid> <flags> <cip> <sip> <lease> <comment>\n*/");
		return (0);
	}

	cid = (c > 3) ? strtoul(v[3], 0L, 0L) : 0;
	flags = (c > 4) ? (char)strtol(v[4], 0L, 0L) : 0;
	cip.s_addr = (c > 5) ? strtoul(v[5], 0L, 0L) : 0;
	sip.s_addr = (c > 6) ? strtoul(v[6], 0L, 0L) : 0;
	lease = (c > 7) ? strtoul(v[7], 0L, 0L) : 0;
	macro = (c > 8) ? v[8] : 0;
	server = (c > 9) ? v[9] : "unknown";

	entries = (char **) malloc(ct * (sizeof (char *) * 8 + 4));

	/* Load current datastore. */
	(void) read_dsvc_conf(&dsp);
	if ((i = confopt_to_datastore(dsp, &datastore)) != DSVC_SUCCESS) {
		(void) fprintf(stderr, "Invalid datastore: %s\n",
		    dhcpsvc_errmsg(i));
		return (EINVAL);
	}
	err = open_dd(&dh, &datastore, DSVC_DHCPNETWORK, network,
	    DSVC_READ | DSVC_WRITE);

	if (err != DSVC_SUCCESS) {
		(void) fprintf(stderr, "Invalid network: %s trying create...\n",
		    dhcpsvc_errmsg(err));

		err = open_dd(&dh, &datastore, DSVC_DHCPNETWORK, network,
		    DSVC_READ | DSVC_WRITE | DSVC_CREATE);
		if (err != DSVC_SUCCESS) {
			(void) fprintf(stderr, "Can't create network: %s\n",
			    dhcpsvc_errmsg(err));
			return (err);
		}
	}
	/* XXXX: bug: currently can't get the count as advertised */
	(void) memset(&dn, '\0', sizeof (dn));
	DSVC_QINIT(query);
	err = lookup_dd(dh, B_FALSE, query, -1,
		    (const void *) &dn, (void **) &dncp, &nrecords);
	if (dncp)
		free_dd_list(dh, dncp);

	if (err != DSVC_SUCCESS) {
		(void) fprintf(stderr, "Bad nrecords: %s [%d]\n",
		    dhcpsvc_errmsg(err), nrecords);
		return (err);
	}

	for (i = 0, j = 0; i < ct; i++) {
		TNF_PROBE_1(main, "main",
			    "main%debug 'in function main'",
			    tnf_ulong, record, i);
		if (cid) {
			(void) memcpy(dn.dn_cid, &cid, sizeof (long long));
			dn.dn_cid_len = 7;
		} else {
			(void) memset(dn.dn_cid, '\0', sizeof (long long));
			dn.dn_cid_len = 1;
		}
		dn.dn_sig = 0;
		dn.dn_flags = flags;
		dn.dn_cip.s_addr = cip.s_addr;
		dn.dn_sip.s_addr = sip.s_addr;
		dn.dn_lease = lease;
		strcpy(dn.dn_macro, macro);
		strcpy(dn.dn_comment, server);
		(void) add_dd_entry(dh, &dn);
		if (cid)
			cid += 0x100;
		cip.s_addr++;

		TNF_PROBE_0(main_end, "main", "");
	}
	(void) close_dd(&dh);

	return (0);
}
