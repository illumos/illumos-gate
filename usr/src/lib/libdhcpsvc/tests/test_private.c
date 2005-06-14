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
 * Copyright (c) 2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <alloca.h>
#include <strings.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <errno.h>
#include <dhcp_svc_confopt.h>
#include <dhcp_svc_private.h>
#include <dhcp_svc_public.h>
#include <libinetutil.h>

/*
 * Argument: resource, and path in that resource.
 */
int
main(int argc, char *argv[])
{
	int			nmods, i, error;
	boolean_t		dsp_valid = B_FALSE;
	char			**mods, **listpp;
	uint32_t		count;
	dsvc_datastore_t	dsp;
	dsvc_handle_t		handle;
	char			cid[DN_MAX_CID_LEN * 2 + 1];
	uint_t			cidlen;
	char			cip[INET_ADDRSTRLEN], sip[INET_ADDRSTRLEN];
	uint32_t		query;
	dt_rec_t		dt, *dtp, *ntp;
	dt_rec_list_t		*resdtp, *wtp;
	dn_rec_t		dn, *dnp;
	dn_rec_list_t		*resdnp, *wnp;

	if (argc != 3) {
		(void) fprintf(stderr, "Usage: %s <resource> <path>\n",
		    argv[0]);
		return (1);
	}

	/* enumerate_dd() */
	(void) printf("enumerate_dd: ... ");
	error = enumerate_dd(&mods, &nmods);
	(void) printf("%s\n", dhcpsvc_errmsg(error));

	if (error != DSVC_SUCCESS)
		return (1);

	(void) printf("enumerate_dd: count of modules: %d\n", nmods);
	for (i = 0; i < nmods; i++) {
		(void) printf("    %d is: %s\n", i, mods[i]);
		if (strcmp(argv[1], mods[i]) == 0) {
			dsp.d_location = argv[2];
			dsp.d_resource = strdup(mods[i]);
			dsp.d_conver = DSVC_CUR_CONVER;
			dsp_valid = B_TRUE;
		}
		free(mods[i]);
	}
	free(mods);

	if (!dsp_valid) {
		(void) printf("%s: no module for resource `%s'\n", argv[0],
		    argv[1]);
		return (1);
	}

	(void) printf("\nstarting testing on %s, tables @ %s\n",
	    argv[1], argv[2]);

	/*
	 * Using the datastore struct we built from arguments, begin poking
	 * at the user selected public module.
	 */

	/* status_dd */
	(void) printf("status_dd: ... ");
	error = status_dd(&dsp);
	(void) printf("%s\n", dhcpsvc_errmsg(error));

	(void) printf("Datastore version is %d\n", dsp.d_conver);

	/* mklocation_dd */
	(void) printf("mklocation_dd of %s: ... ", dsp.d_location);
	error = mklocation_dd(&dsp);
	(void) printf("%s\n", dhcpsvc_errmsg(error));

	/* list_dd - dhcptab */
	(void) printf("\nlist_dd of dhcptab containers: ... ");
	error = list_dd(&dsp, DSVC_DHCPTAB, &listpp, &count);
	(void) printf("    %s\n", dhcpsvc_errmsg(error));
	if (error == DSVC_SUCCESS) {
		(void) printf("    %d dhcptab container(s): ", count);
		for (i = 0; i < count; i++) {
			(void) printf("%s ", listpp[i] != NULL ?
			    listpp[i] : "NULL");
			free(listpp[i]);
		}
		(void) printf("\n");
		free(listpp);
	} else {
		(void) printf("list_dd: listpp: 0x%p, count: %d\n",
		    (void *)listpp, count);
	}

	/* open_dd - dhcptab (create) */
	(void) printf("open_dd: dhcptab: ... ");
	error = open_dd(&handle, &dsp, DSVC_DHCPTAB, "dhcptab",
	    DSVC_CREATE | DSVC_READ | DSVC_WRITE);
	(void) printf("%s\n", dhcpsvc_errmsg(error));
	if (error != DSVC_SUCCESS)
		return (1);

	/* add_dd_entry - dhcptab */
	{
		dt_rec_t recs[5];

		(void) strcpy(recs[0].dt_key, "172.21.0.0");
		recs[0].dt_type = DT_MACRO;
		recs[0].dt_value = ":Router=172.21.0.1:Subnet=255.255.0.0:";

		(void) strcpy(recs[1].dt_key, "172.20.64.0");
		recs[1].dt_type = DT_MACRO;
		recs[1].dt_value =
		    ":Router=172.20.64.2:Subnet=255.255.255.192:";

		(void) strcpy(recs[2].dt_key, "172.20.64.64");
		recs[2].dt_type = DT_MACRO;
		recs[2].dt_value =
		    ":Router=172.20.64.65:Subnet=255.255.255.192:";

		(void) strcpy(recs[3].dt_key, "172.20.64.128");
		recs[3].dt_type = DT_MACRO;
		recs[3].dt_value =
		    ":Router=172.20.64.129:Subnet=255.255.255.128:";

		(void) strcpy(recs[4].dt_key, "172.22.0.0");
		recs[4].dt_type = DT_MACRO;
		recs[4].dt_value =
		    ":Router=172.22.0.1:Subnet=255.255.0.0:MTU=4532:";

		(void) printf("add_dd_entry: ... key type value\n");
		for (i = 0; i < sizeof (recs) / sizeof (dt_rec_t); i++) {
			(void) printf("    %s %c %s ... ",
			    recs[i].dt_key, recs[i].dt_type, recs[i].dt_value);
			error = add_dd_entry(handle, &recs[i]);
			(void) printf("%s\n", dhcpsvc_errmsg(error));
			if (error != DSVC_SUCCESS)
				break;
		}
	}

	/* lookup_dd - dhcptab - macro called '172.20.64.128', then delete it */

	DSVC_QINIT(query);
	DSVC_QEQ(query, DT_QKEY);
	DSVC_QEQ(query, DT_QTYPE);

	(void) memset(&dt, 0, sizeof (dt));
	(void) strcpy(dt.dt_key, "172.20.64.128");
	dt.dt_type = 'm';

	(void) printf("lookup_dd: macro %s ... ", dt.dt_key);
	error = lookup_dd(handle, B_FALSE, query, -1, &dt, (void **)&resdtp,
	    &count);
	(void) printf("%s\n", dhcpsvc_errmsg(error));

	if (error == DSVC_SUCCESS) {
		if (count != 1) {
			(void) printf("lookup_dd: expected 1 record,  got %d\n",
			    count);
		}

		for (i = 0, wtp = resdtp; i < count && wtp != NULL; i++) {
			dtp = wtp->dtl_rec;
			(void) printf("    %s %c %s\n",
			    dtp->dt_key, dtp->dt_type, dtp->dt_value);
			wtp = wtp->dtl_next;
		}
		free_dd_list(handle, resdtp);
	}

	/* Delete it */
	(void) printf("delete_dd_entry: %s ... ", dt.dt_key);
	error = delete_dd_entry(handle, &dt);
	(void) printf("%s\n", dhcpsvc_errmsg(error));


	/*
	 * lookup_dd - dhcptab - macro called '172.21.0.0', and modify its
	 * definition and replace the value.
	 */

	DSVC_QINIT(query);
	DSVC_QEQ(query, DT_QKEY);

	(void) memset(&dt, 0, sizeof (dt));
	(void) strcpy(dt.dt_key, "172.21.0.0");

	(void) printf("lookup_dd: macro %s ... ", dt.dt_key);
	error = lookup_dd(handle, B_FALSE, query, 1, &dt, (void **)&resdtp,
	    &count);
	(void) printf("%s\n", dhcpsvc_errmsg(error));

	if (error == DSVC_SUCCESS) {
		if (count != 1) {
			(void) printf("lookup_dd: expected 1 record, "
			    "got %d\n", count);
		} else {
			dtp = resdtp->dtl_rec;
			(void) printf("    %s %c %s\n", dtp->dt_key,
			    dtp->dt_type, dtp->dt_value);

			ntp = alloc_dtrec(dtp->dt_key, dtp->dt_type,
			    ":Subnet=255.255.0.0:Router=172.21.0.1 "
			    "172.21.0.2:MTU=1500:");
			if (ntp != NULL) {
				ntp->dt_sig = dtp->dt_sig;

				/* Modify it */
				(void) printf("modify_dd_entry: macro %s ... ",
				    dt.dt_key);
				error = modify_dd_entry(handle, dtp, ntp);
				(void) printf("%s\n", dhcpsvc_errmsg(error));
				free_dd(handle, ntp);
			}
		}
		free_dd_list(handle, resdtp);
	}

	/* lookup_dd - all records */

	DSVC_QINIT(query);

	(void) printf("lookup_dd: all records ... ");
	error = lookup_dd(handle, B_FALSE, query, -1, &dt, (void **)&resdtp,
	    &count);
	(void) printf("%s\n", dhcpsvc_errmsg(error));
	if (error == DSVC_SUCCESS) {
		for (i = 0, wtp = resdtp; i < count && wtp != NULL; i++) {
			dtp = wtp->dtl_rec;
			(void) printf("    %s %c %s\n", dtp->dt_key,
			    dtp->dt_type, dtp->dt_value);
			wtp = wtp->dtl_next;
		}
		free_dd_list(handle, resdtp);
	}

	/* close_dd - dhcptab */
	(void) printf("close_dd: dhcptab ... ");
	error = close_dd(&handle);
	(void) printf("%s\n", dhcpsvc_errmsg(error));

	/* list_dd - dhcp network containers */
	(void) printf("list_dd: dhcptab ... ");
	error = list_dd(&dsp, DSVC_DHCPTAB, &listpp, &count);
	(void) printf("%s\n", dhcpsvc_errmsg(error));
	if (error == DSVC_SUCCESS) {
		(void) printf("    %d dhcp network container(s): ", count);
		for (i = 0; i < count; i++) {
			(void) printf("%s ", listpp[i] != NULL ?
			    listpp[i] : "NULL");
			free(listpp[i]);
		}
		free(listpp);
		(void) printf("\n");
	} else {
		(void) printf("list_dd: listpp: 0x%p, count: %d\n",
		    (void *)listpp, count);
	}

	/* remove_dd - dhcptab */
	(void) printf("remove_dd: dhcptab ... ");
	error = remove_dd(&dsp, DSVC_DHCPTAB, NULL);
	(void) printf("%s\n", dhcpsvc_errmsg(error));

	/* open_dd - 129.148.5.0 create */
	(void) printf("\nopen_dd: 129.148.5.0: ... ");
	error = open_dd(&handle, &dsp, DSVC_DHCPNETWORK, "129.148.5.0",
	    DSVC_CREATE | DSVC_READ | DSVC_WRITE);
	(void) printf("%s\n", dhcpsvc_errmsg(error));
	if (error  != DSVC_SUCCESS)
		return (1);

	/* add_dd_entry - 129.148.5.0 */
	{
		uchar_t cid0[7] = { 0x01, 0x08, 0x00, 0x20, 0x00, 0x00, 0x01 };
		dn_rec_t recs[5] = { 0 };

		recs[0].dn_cid_len = sizeof (cid0);
		recs[0].dn_flags = 2;
		recs[0].dn_cip.s_addr = 0x81940502;
		recs[0].dn_sip.s_addr = 0x81940501;
		(void) memcpy(recs[0].dn_cid, cid0, sizeof (cid0));
		(void) strlcpy(recs[0].dn_macro, "myserv", DSVC_MAX_MACSYM_LEN);
		(void) strlcpy(recs[0].dn_comment, "dave", DN_MAX_COMMENT_LEN);

		recs[1].dn_cid_len = 1;
		recs[1].dn_flags = 1;
		recs[1].dn_cip.s_addr = 0x81940503;
		recs[1].dn_sip.s_addr = 0x81940501;
		(void) strlcpy(recs[1].dn_macro, "myserv", DSVC_MAX_MACSYM_LEN);
		(void) strlcpy(recs[1].dn_comment, "meem", DN_MAX_COMMENT_LEN);

		recs[2].dn_cid_len = 1;
		recs[2].dn_cip.s_addr = 0x81940504;
		recs[2].dn_sip.s_addr = 0x81940501;
		(void) strlcpy(recs[2].dn_macro, "myserv", DSVC_MAX_MACSYM_LEN);
		(void) strlcpy(recs[2].dn_comment, "cpj", DN_MAX_COMMENT_LEN);

		recs[3].dn_cid_len = 1;
		recs[3].dn_cip.s_addr = 0x81940505;
		recs[3].dn_sip.s_addr = 0x81940501;
		(void) strlcpy(recs[3].dn_macro, "myserv", DSVC_MAX_MACSYM_LEN);
		(void) strlcpy(recs[3].dn_comment, "mwc", DN_MAX_COMMENT_LEN);

		recs[4].dn_cid_len = 1;
		recs[4].dn_cip.s_addr = 0x81940506;
		recs[4].dn_sip.s_addr = 0x81940501;
		(void) strlcpy(recs[4].dn_macro, "myserv", DSVC_MAX_MACSYM_LEN);
		(void) strlcpy(recs[4].dn_comment, "markh", DN_MAX_COMMENT_LEN);

		(void) printf("add_dd_entry: ... cid flag cip sip lease "
		    "macro comment\n");
		for (i = 0; i < sizeof (recs) / sizeof (dn_rec_t); i++) {
			cidlen = sizeof (cid);
			(void) octet_to_hexascii(recs[i].dn_cid,
			    recs[i].dn_cid_len, cid, &cidlen);
			(void) printf("    %s %d %s %s %u %s %s ... ",
			    cid, recs[i].dn_flags,
			    inet_ntop(AF_INET, &recs[i].dn_cip, cip,
			    INET_ADDRSTRLEN),
			    inet_ntop(AF_INET, &recs[i].dn_sip, sip,
			    INET_ADDRSTRLEN),
			    recs[i].dn_lease, recs[i].dn_macro,
			    recs[i].dn_comment);

			error = add_dd_entry(handle, &recs[i]);
			(void) printf("%s\n", dhcpsvc_errmsg(error));
			if (error != DSVC_SUCCESS)
				break;
		}
	}

	/* lookup_dd - lookup all records. */
	DSVC_QINIT(query);

	(void) printf("lookup_dd: 129.148.5.0 ... ");
	error = lookup_dd(handle, B_FALSE, query, -1, &dn, (void **)&resdnp,
	    &count);
	(void) printf("%s\n", dhcpsvc_errmsg(error));
	if (error == DSVC_SUCCESS) {
		for (i = 0, wnp = resdnp; i < count && wnp != NULL; i++) {
			dnp = wnp->dnl_rec;
			cidlen = sizeof (cid);
			(void) octet_to_hexascii(dnp->dn_cid,
			    dnp->dn_cid_len, cid, &cidlen);
			(void) inet_ntop(AF_INET, &dnp->dn_cip,
			    cip, INET_ADDRSTRLEN);
			(void) inet_ntop(AF_INET, &dnp->dn_sip,
			    sip, INET_ADDRSTRLEN);
			(void) printf("    %s %02u %s %s %u '%s' #%s\n",
			    cid, dnp->dn_flags, cip, sip, dnp->dn_lease,
			    dnp->dn_macro, dnp->dn_comment);
			wnp = wnp->dnl_next;
		}
		free_dd_list(handle, resdnp);
	}

	/* delete_dd_entry - 129.148.5.3 */
	dn.dn_sig = 0;
	dn.dn_cip.s_addr = ntohl(inet_addr("129.148.5.3"));
	(void) printf("delete_dd_entry: 129.148.5.3 ... ");
	error = delete_dd_entry(handle, &dn);
	(void) printf("%s\n", dhcpsvc_errmsg(error));

	/*
	 * lookup_dd - 129.148.5.0 - record with cid of 01080020000001, modify
	 * flags to MANUAL+BOOTP, lease to -1, macro to foobar, and server to
	 * 129.148.174.27.
	 */
	DSVC_QINIT(query);
	DSVC_QEQ(query, DN_QCID);

	(void) memset(&dn, 0, sizeof (dn));
	dn.dn_cid[0] = 0x1;
	dn.dn_cid[1] = 0x8;
	dn.dn_cid[2] = 0x0;
	dn.dn_cid[3] = 0x20;
	dn.dn_cid[4] = 0x0;
	dn.dn_cid[5] = 0x0;
	dn.dn_cid[6] = 0x1;
	dn.dn_cid_len = 7;

	(void) printf("lookup_dd: 01080020000001 ... ");
	error = lookup_dd(handle, B_FALSE, query, 1, &dn, (void **)&resdnp,
	    &count);
	(void) printf("%s\n", dhcpsvc_errmsg(error));

	if (error == DSVC_SUCCESS) {
		if (count != 1) {
			(void) printf("lookup_dd: expected 1 record, got %d\n",
			    count);
		} else {
			dnp = resdnp->dnl_rec;
			dn = *dnp; /* struct copy */

			dn.dn_flags = DN_FMANUAL | DN_FBOOTP_ONLY;
			dn.dn_lease = DHCP_PERM;
			(void) strcpy(dn.dn_macro, "foobar");
			dn.dn_sip.s_addr = ntohl(inet_addr("129.148.174.27"));

			/* Modify it */
			(void) printf("modify_dd_entry: 01080020000001 ... ");
			error = modify_dd_entry(handle, dnp, &dn);
			(void) printf("%s\n", dhcpsvc_errmsg(error));
		}
		free_dd_list(handle, resdnp);
	}

	/* lookup_dd - lookup all fields with DN_FMANUAL set */

	DSVC_QINIT(query);
	DSVC_QEQ(query, DN_QFMANUAL);

	(void) memset(&dn, 0, sizeof (dn));
	dn.dn_flags = DN_FMANUAL;

	(void) printf("lookup_dd: F_MANUAL ... ");
	error = lookup_dd(handle, B_FALSE, query, 1, &dn, (void **)&resdnp,
	    &count);
	(void) printf("%s\n", dhcpsvc_errmsg(error));

	if (error == DSVC_SUCCESS) {
		if (count != 1) {
			(void) printf("lookup_dd: expected 1 record, "
			    "got %d\n", count);
		} else {
			dnp = resdnp->dnl_rec;
			cidlen = sizeof (cid);
			(void) octet_to_hexascii(dnp->dn_cid,
			    dnp->dn_cid_len, cid, &cidlen);
			(void) inet_ntop(AF_INET, &dnp->dn_cip,
			    cip, INET_ADDRSTRLEN);
			(void) inet_ntop(AF_INET, &dnp->dn_sip,
			    sip, INET_ADDRSTRLEN);
			(void) printf("    %s %02u %s %s %u '%s' #%s\n",
			    cid, dnp->dn_flags, cip, sip, dnp->dn_lease,
			    dnp->dn_macro, dnp->dn_comment);
		}
		free_dd_list(handle, resdnp);
	}

	/* lookup_dd - lookup all records. */

	DSVC_QINIT(query);

	(void) printf("lookup_dd: 129.148.5.0  ...");
	error = lookup_dd(handle, B_FALSE, query, -1, &dn, (void **)&resdnp,
	    &count);
	(void) printf("%s\n", dhcpsvc_errmsg(error));

	if (error == DSVC_SUCCESS) {
		for (i = 0, wnp = resdnp; i < count && wnp != NULL; i++) {
			cidlen = sizeof (cid);
			dnp = wnp->dnl_rec;
			(void) octet_to_hexascii(dnp->dn_cid,
			    dnp->dn_cid_len, cid, &cidlen);
			(void) inet_ntop(AF_INET, &dnp->dn_cip,
			    cip, INET_ADDRSTRLEN);
			(void) inet_ntop(AF_INET, &dnp->dn_sip,
			    sip, INET_ADDRSTRLEN);
			(void) printf("    %s %02u %s %s %u '%s' #%s\n",
			    cid, dnp->dn_flags, cip, sip, dnp->dn_lease,
			    dnp->dn_macro, dnp->dn_comment);
			wnp = wnp->dnl_next;
		}
		free_dd_list(handle, resdnp);
	}

	/* close_dd - 129.148.5.0 */
	(void) printf("close_dd: 129.148.5.0 ... ");
	error = close_dd(&handle);
	(void) printf("%s\n", dhcpsvc_errmsg(error));

	/* list_dd - dhcp network containers */
	(void) printf("list_dd: ... ");
	error = list_dd(&dsp, DSVC_DHCPNETWORK, &listpp, &count);
	(void) printf("%s\n", dhcpsvc_errmsg(error));
	if (error == DSVC_SUCCESS) {
		(void) printf("    %d dhcp network container(s): ", count);
		for (i = 0; i < count; i++) {
			(void) printf("%s ", listpp[i] != NULL ?
			    listpp[i] : "NULL");
			free(listpp[i]);
		}
		free(listpp);
		(void) printf("\n");
	} else {
		(void) printf("list_dd: listpp: 0x%p, count: %d\n",
		    (void *)listpp, count);
	}

	/* remove_dd - 129.148.5.0 */
	(void) printf("remove_dd_entry: 129.148.5.0 ... ");
	error = remove_dd(&dsp, DSVC_DHCPNETWORK, "129.148.5.0");
	(void) printf("%s\n", dhcpsvc_errmsg(error));

	return (0);
}
