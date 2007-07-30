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
 * Convert an RSM configuration to plain text
 */

#include <stdio.h>
#include <sys/wrsm_config.h>

#define	bool_string(x) (x == B_TRUE ? "true" : "false")

static void
print_stripe_group(FILE *fp, wrsm_stripe_group_t *group)
{
	int i;
	(void) fprintf(fp, "\tstripe_group %d {\n", group->group_id);
	(void) fprintf(fp, "\t\twcis");
	for (i = 0; i < group->nwcis; ++i)
		(void) fprintf(fp, " %d", group->wcis[i]);
	(void) fprintf(fp, "\n\t}\n");
}

static void
print_route(FILE *fp, wrsm_preferred_route_t *route)
{
	(void) fprintf(fp, "\t\tpreferred_route {\n");
	(void) fprintf(fp, "\t\t\tstriping_level %d\n", route->striping_level);
	(void) fprintf(fp, "\t\t\trouting_method %s\n",
	    (route->method == routing_multihop) ? "multihop":
	    (route->method == routing_passthrough) ? "passthrough":"ERROR");
	if (route->route_type == route_stripe_group)
		(void) fprintf(fp, "\t\t\tstripe_group %d\n",
		    route->route.stripe_group_id);
	else if (route->route_type == route_wci)
		(void) fprintf(fp, "\t\t\tuse_wci %d\n", route->route.wci_id);
	if (route->nswitches) {
		int i;
		(void) fprintf(fp, "\t\t\tswitches");
		for (i = 0; i < route->nswitches; ++i)
			(void) fprintf(fp, " %d", route->switches[i]);
		(void) fprintf(fp, "\n");
	}
	(void) fprintf(fp, "\t\t}\n");
}

static void
print_policy(FILE *fp, wrsm_routing_policy_t *policy)
{
	int i;
	(void) fprintf(fp, "\trouting_policy %d {\n", policy->cnodeid);
	for (i = 0; i < policy->nroutes; ++i)
		print_route(fp,
		    policy->WRSM_ALIGN_PTR(preferred_routes)[i]);
	(void) fprintf(fp, "\t\twcis_balanced %s\n",
	    bool_string(policy->wcis_balanced));
	(void) fprintf(fp, "\t\tstriping_important %s\n",
	    bool_string(policy->striping_important));
	if (policy->forwarding_allowed) {
		(void) fprintf(fp, "\t\tforwarding_ncslices");
		for (i = 0; i < WRSM_MAX_NCSLICES; i++) {
			if (WRSM_IN_SET(policy->forwarding_ncslices, i)) {
				(void) fprintf(fp, " 0x%x", i);
			}
		}
		(void) fprintf(fp, "\n");
	}
	(void) fprintf(fp, "\t}\n");
}

static void
print_link(FILE *fp, wrsm_link_data_t *link, int n)
{
	if (!link->present)
		return;
	(void) fprintf(fp, "\t\tlink %d {\n", n);
	(void) fprintf(fp, "\t\t\tremote_gnid %d\n", link->remote_gnid);
	(void) fprintf(fp, "\t\t\tremote_link %d\n", link->remote_link_num);
	(void) fprintf(fp, "\t\t\tremote_wci %d\n", link->remote_port);
	(void) fprintf(fp, "\t\t}\n");
}

static void
print_wci(FILE *fp, wrsm_wci_data_t *wci)
{
	int wnid;
	int gnid;
	int link;

	(void) fprintf(fp, "\twci {\n");
	(void) fprintf(fp, "\t\tsafari_port_id %d\n", wci->port);
	(void) fprintf(fp, "\t\twnodeid %d\n", wci->local_wnode);
	(void) fprintf(fp, "\t\tgnid %d\n", wci->local_gnid);
	(void) fprintf(fp, "\t\treachable");
	for (wnid = 0; wnid < WRSM_MAX_WNODES; ++wnid) {
		if (wci->wnode_reachable[wnid]) {
			(void) fprintf(fp, " (%d,", wnid);
			for (gnid = 0; gnid < WRSM_MAX_WNODES; gnid++) {
				if (wci->gnid_to_wnode[gnid] == wnid) {
					break;
				}
			}
			(void) fprintf(fp, "%d,", gnid);
			(void) fprintf(fp, "%d)", wci->reachable[wnid]);
		}
	}
	(void) fprintf(fp, "\n");
	(void) fprintf(fp, "\t\troute_map_striping %s\n",
		bool_string(wci->route_map_striping));
	(void) fprintf(fp, "\t\ttopology_type %s\n",
		(wci->topology_type == topology_central_switch ?
		    "central_switch":
		(wci->topology_type == topology_distributed_switch ?
		    "distributed_switch":
		(wci->topology_type == topology_san_switch ?
		    "san_switch":"none"))));
	for (link = 0; link < WRSM_MAX_LINKS_PER_WCI; ++link)
		if (&wci->links[link]) {
			print_link(fp, &wci->links[link], link);
		}
	(void) fprintf(fp, "\t}\n");
}

static void
print_routing(FILE *fp, wrsm_routing_data_t *routing)
{
	int i;
	for (i = 0; i < routing->nwcis; ++i)
		print_wci(fp, routing->WRSM_ALIGN_PTR(wcis)[i]);
	for (i = 0; i < routing->npolicy; ++i)
		print_policy(fp, routing->WRSM_ALIGN_PTR(policy)[i]);
	for (i = 0; i < routing->ngroups; ++i)
		print_stripe_group
		    (fp, routing->WRSM_ALIGN_PTR(stripe_groups)[i]);
}

static void
print_member(FILE *fp, wrsm_net_member_t *member)
{
	int i;
	(void) fprintf(fp, "\tcnodeid %d {\n", member->cnodeid);
	(void) fprintf(fp, "\t\tfmnodeid 0x%llx ",
		(longlong_t)member->fmnodeid);
	(void) fprintf(fp, "%s\n", member->hostname);

	(void) fprintf(fp, "\t\texported_ncslices {");
	for (i = 0; i < WRSM_NODE_NCSLICES; ++i) {
		if (member->exported_ncslices.id[i]) {
			(void) fprintf(fp, " 0x%x",
			    member->exported_ncslices.id[i]);
		}
	}
	(void) fprintf(fp, " }\n");

	(void) fprintf(fp, "\t\timported_ncslices {");
	for (i = 0; i < WRSM_NODE_NCSLICES; ++i) {
		if (member->imported_ncslices.id[i]) {
			(void) fprintf(fp, " 0x%x",
			    member->imported_ncslices.id[i]);
		}
	}
	(void) fprintf(fp, " }\n");

	(void) fprintf(fp, "\t\tlocal_offset 0x%llx\n",
		(longlong_t)member->local_offset);
	(void) fprintf(fp, "\t\tcomm_ncslice 0x%x 0x%llx\n",
	    member->comm_ncslice,
	    (longlong_t)member->comm_offset);
	(void) fprintf(fp, "\t}\n");
}

void
wrsm_print_controller(FILE *fp, wrsm_controller_t *cont)
{
	int i;
	(void) fprintf(fp, "fmnodeid 0x%llx ",
		(longlong_t)cont->fmnodeid);
	(void) fprintf(fp, "%s\n", cont->hostname);
	(void) fprintf(fp, "controller %d {\n", cont->controller_id);
	(void) fprintf(fp, "\tconfig_protocol_version %u\n",
	    cont->config_protocol_version);
	(void) fprintf(fp, "\tversion %llu\n",
		(longlong_t)cont->version_stamp);
	(void) fprintf(fp, "\tlocal_cnodeid %d\n", cont->cnodeid);
	for (i = 0; i < cont->nmembers; ++i)
		print_member(fp, cont->WRSM_ALIGN_PTR(members)[i]);
	print_routing(fp, cont->WRSM_ALIGN_PTR(routing));
	(void) fprintf(fp, "}\n");
}
