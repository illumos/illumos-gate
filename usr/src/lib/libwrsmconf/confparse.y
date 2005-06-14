%{
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
 *
 * Copyright (c) 2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <strings.h>
#include <stdlib.h>
#include <sys/wrsm_config.h>
#include "util.h"
#include "wrsmconf.h"
#include "wrsmconf_impl.h"

int yyerror(const char *);

static wrsm_controller_t controller[WRSM_MAX_CNODES] = {0};
static int num_ctlrs = 0;
static int nmembers = 0;
static int nwcis = 0;
static int ngroups = 0;
static int npolicy = 0;
static int nroutes = 0;
static wrsm_link_data_t cur_links[WRSM_MAX_LINKS_PER_WCI];
static wrsm_wci_data_t **cur_wci_list;
static wrsm_wci_data_t *cur_wci;

struct intlist {
	int length;
	int *list;
};

#ifdef DEBUG
#define	TRACE(s)	(void) fprintf(stderr, "%s\n", s);
#else
#define	TRACE(s)
#endif /* DEBUG */

%}

%union {
	uint64_t ival;
	char *name;
	int value;
	boolean_t bool;
	struct intlist *intlist;
	wrsm_topology_t tt;
	wrsm_controller_t *controller;
	wrsm_net_member_t *member;
	wrsm_net_member_t **members;
	wrsm_wci_data_t **wcis;
	wrsm_wci_data_t *wci;
	wrsm_routing_data_t *routing;
	wrsm_routing_policy_t **policies;
	wrsm_routing_policy_t *policy;
	wrsm_routing_method_t rm;
	wrsm_stripe_group_t *stripe_group;
	wrsm_stripe_group_t **stripe_groups;
	wrsm_preferred_route_t **routes;
	wrsm_preferred_route_t *route;
	wrsm_ncslice_info_t *slice_info;
}

%type <controller> controller
%type <member> net_member
%type <members> net_members
%type <wcis> wcis
%type <wci> wci
%type <tt> topology_type
%type <bool> route_map_striping
%type <routing> routing
%type <ival> remote_gnid remote_link remote_wci
%type <value> reachable
%type <policies> routing_policies
%type <policy> routing_policy
%type <routes> preferred_routes
%type <route> preferred_route
%type <bool> wcis_balanced striping_important
%type <ival> striping_level use_wci use_stripe
%type <rm> routing_method
%type <intlist> int_list switches forwarding_ncslices
%type <stripe_group> stripe_group
%type <stripe_groups> stripe_groups

%token <ival> INT
%token <name> NAME
%token <bool> BOOL
%token <tt> TT
%token <rm> RM

%token <value> LB RB COMMA LP RP
%token <value> FMNODEID CONTROLLER VERSION LOCAL_CNODEID
%token <value> IMPORTED_NCSLICES EXPORTED_NCSLICES CONF_PROTOCOL_VERSION
%token <value> CNODEID COMM_NCSLICE LOCAL_OFFSET SMALL LARGE GNID
%token <value> SAFARI_PORT_ID WNODEID ROUTE_MAP_STRIPING TOPOLOGY_TYPE
%token <value> REACHABLE WCI LINK REMOTE_GNID REMOTE_LINK REMOTE_WCI
%token <value> PREFERRED_ROUTES WCIS_BALANCED STRIPING_IMPORTANT
%token <value> FORWARDING_NCSLICES ROUTING_POLICY
%token <value> PREFERRED_ROUTE STRIPING_LEVEL ROUTING_METHOD USE_WCI
%token <value> STRIPE_GROUP WCIS SWITCHES

%%

controllers: controllers controller | controller;

controller:
	FMNODEID INT NAME CONTROLLER INT LB 
	CONF_PROTOCOL_VERSION INT VERSION INT LOCAL_CNODEID INT 
	{ nmembers=0; } net_members 
	{ nwcis=0; ngroups=0; } routing RB { 
		int i;
		TRACE("controller");
		controller[num_ctlrs].fmnodeid = $2;
		strcpy(controller[num_ctlrs].hostname, $3);
		controller[num_ctlrs].controller_id = $5;
		controller[num_ctlrs].config_protocol_version = $8;
		controller[num_ctlrs].version_stamp = $10;
		controller[num_ctlrs].cnodeid = $12;
		controller[num_ctlrs].nmembers = nmembers;
		controller[num_ctlrs].WRSM_ALIGN_PTR(members) = $14;
		controller[num_ctlrs].WRSM_ALIGN_PTR(routing) = $16;
		postprocess_controller(&controller[num_ctlrs]);

		num_ctlrs++;
	}
;


net_members:
	net_member net_members {
		TRACE("net_members 1");
		++nmembers;
		$$ = (wrsm_net_member_t **)realloc($2,
			sizeof(wrsm_net_member_t *) * nmembers);
		$$[nmembers-1] = $1;
	}
|	net_member {
		TRACE("net_members 2");
		++nmembers;
		$$ = (wrsm_net_member_t **)malloc(
			sizeof(wrsm_net_member_t *) * nmembers);
		$$[nmembers-1] = $1;
	}
;

net_member:
	CNODEID INT LB
	FMNODEID INT NAME
	EXPORTED_NCSLICES LB int_list RB
	IMPORTED_NCSLICES LB int_list RB
	LOCAL_OFFSET INT 
	COMM_NCSLICE INT INT RB {
		int i;
		TRACE("net_member");
		$$ = (wrsm_net_member_t *)malloc(sizeof(wrsm_net_member_t));
		$$->cnodeid = $2;
		$$->fmnodeid = $5;
		strcpy($$->hostname,$6);
		/*
		 * The first ncslice listed in the file becomes the last
		 * ncslice in the int list. So pick off the last one as
		 * the small page ncslice, and sort the rest based on
		 * large page index (lower 3 bits).
		 */
		memset(&($$->exported_ncslices), 0,
		    sizeof($$->exported_ncslices));
		$$->exported_ncslices.id[0] = $9->list[$9->length - 1];
		for (i = 0; i < $9->length - 1; i++) {
			int index = $9->list[i] & 0x3;
			if ($$->exported_ncslices.id[index] != 0) {
				char errmsg[128];
				sprintf(errmsg, "exported_ncslices for "
				    "cnode %d: Large ncslice 0x%x attempts "
				    "to use position %d which is already "
				    "used by ncslice 0x%x",
				    $$->cnodeid, $9->list[i], index, 
				    $$->exported_ncslices.id[index]);
				yyerror(errmsg);
			}
			$$->exported_ncslices.id[index] = $9->list[i];
		}
		memset(&($$->imported_ncslices), 0,
		    sizeof($$->imported_ncslices));
		$$->imported_ncslices.id[0] = $13->list[$13->length - 1];
		for (i = 0; i < $13->length - 1; i++) {
			int index = $13->list[i] & 0x3;
			if ($$->imported_ncslices.id[index] != 0) {
				char errmsg[128];
				sprintf(errmsg, "imported_ncslices for "
				    "cnode %d: Large ncslice 0x%x attempts "
				    "to use position %d which is already "
				    "used by ncslice 0x%x",
				    $$->cnodeid, $13->list[i], index, 
				    $$->imported_ncslices.id[index]);
				yyerror(errmsg);
			}
			$$->imported_ncslices.id[index] = $13->list[i];
		}
		$$->local_offset = $16;
		$$->comm_ncslice = $18;
		$$->comm_offset = $19;
	}
;

routing:
	wcis { cur_wci_list=$1; npolicy=0;} 
	routing_policies stripe_groups {
		TRACE("routing");
		$$ = (wrsm_routing_data_t *)malloc
			(sizeof(wrsm_routing_data_t));
		$$->WRSM_ALIGN_PTR(wcis) = $1;
		$$->nwcis = nwcis;
		$$->WRSM_ALIGN_PTR(policy) = $3;
		$$->npolicy = npolicy;
		$$->WRSM_ALIGN_PTR(stripe_groups) = $4;
		$$->ngroups = ngroups;
	}

wcis:
	wci wcis {
		TRACE("wcis 1");
		++nwcis;
		$$ = (wrsm_wci_data_t **)realloc($2,
			sizeof(wrsm_wci_data_t *) * nwcis);
		$$[nwcis-1] = $1;
	}
|	wci {
		TRACE("wcis 2");
		++nwcis;
		$$ = (wrsm_wci_data_t **)malloc(
			sizeof(wrsm_wci_data_t *) * nwcis);
		$$[nwcis-1] = $1;
	}
;

wci:
	WCI {
		wrsm_gnid_t gnid;
		cur_wci = _calloc(wrsm_wci_data_t,1);
		for (gnid = 0; gnid < WRSM_MAX_WNODES; gnid++) {
			cur_wci->gnid_to_wnode[gnid] = 0xff;
		}
	}
	LB SAFARI_PORT_ID INT
	WNODEID INT GNID INT reachable route_map_striping topology_type 
	{ memset(cur_links, 0, sizeof(cur_links)); } links RB {
		TRACE("wci");
		$$ = cur_wci;
		$$->port = $5;
		$$->local_wnode = $7;
		$$->local_gnid = $9;
		$$->route_map_striping = $11;
		$$->topology_type = $12;
		memcpy($$->links, cur_links, sizeof(wrsm_link_data_t) *
			WRSM_MAX_LINKS_PER_WCI);
	}
;

reachable:
	REACHABLE triplet_list
;

triplet_list:
	int_triplet triplet_list
|	int_triplet
;

int_triplet:
	LP INT COMMA INT COMMA INT RP {
		TRACE("triplet");
		if ($2 < 0 || $2 >= WRSM_MAX_WNODES)
			Error("Illegal wnodeid %d", $2);
		if ($4 < 0 || $4 >= WRSM_MAX_WNODES)
			Error("Illegal gnid %d", $4);
		cur_wci->reachable[$2] = $6;
		cur_wci->gnid_to_wnode[$4] = $2;
		cur_wci->wnode_reachable[$2] = B_TRUE;
	}
;

route_map_striping:
	ROUTE_MAP_STRIPING BOOL	{ $$ = $2; }
;

topology_type:
	TOPOLOGY_TYPE TT { $$ = $2; }
;

links:
	link links
|
;

link:
	LINK INT LB remote_gnid remote_link remote_wci RB {
		TRACE("link");
		if ($2 < 0 || $2 >= WRSM_MAX_LINKS_PER_WCI)
			yyerror("Illegal link number");
		cur_links[$2].present = B_TRUE;
		cur_links[$2].remote_gnid = $4;
		cur_links[$2].remote_link_num = $5;
		cur_links[$2].remote_port = $6;
	}

remote_gnid:
	REMOTE_GNID INT { $$ = $2; }
;

remote_link:
	REMOTE_LINK INT { $$ = $2; }
;

remote_wci:
	REMOTE_WCI INT { $$ = $2; }
;

routing_policies:
	routing_policy routing_policies {
		TRACE("routing_policies 1");
		++npolicy;
		$$ = (wrsm_routing_policy_t **)realloc
			($2, sizeof(wrsm_routing_policy_t *) * npolicy);
		$$[npolicy-1] = $1;
	}
|	routing_policy {
		TRACE("routing_policies 2");
		++npolicy;
		$$ = (wrsm_routing_policy_t **)malloc
			(sizeof(wrsm_routing_policy_t *) * npolicy);
		$$[npolicy-1] = $1;
	}
;

routing_policy:
	ROUTING_POLICY INT LB { nroutes=0; } preferred_routes wcis_balanced 
	striping_important forwarding_ncslices RB {
		int i;
		TRACE("routing_policy");
		$$ = (wrsm_routing_policy_t *)malloc
			(sizeof(wrsm_routing_policy_t));
		$$->cnodeid = $2;
		$$->nroutes = nroutes;
		$$->WRSM_ALIGN_PTR(preferred_routes) = $5;
		$$->wcis_balanced = $6;
		$$->striping_important = $7;
		$$->forwarding_allowed = ($8 != NULL) && ($8->length > 0);
		WRSMSET_ZERO($$->forwarding_ncslices);
		for (i = 0; $8 && i < $8->length; i++) {
			WRSMSET_ADD($$->forwarding_ncslices, $8->list[i]);
		}
	}
;

wcis_balanced:
	WCIS_BALANCED BOOL { $$ = $2; }
;

striping_important:
	STRIPING_IMPORTANT BOOL { $$ = $2; }
;

preferred_routes:
	preferred_route preferred_routes {
		TRACE("preferred_routes 1");
		++nroutes;
		$$ = _realloc($2, wrsm_preferred_route_t *, nroutes);
		$$[nroutes-1] = $1;
	}
|	preferred_route {
		TRACE("preferred_routes 2");
		++nroutes;
		$$ = _malloc(wrsm_preferred_route_t *, nroutes);
		$$[nroutes-1] = $1;
	}
;

preferred_route:
	PREFERRED_ROUTE LB striping_level routing_method use_wci switches RB {
		int i;
		TRACE("preferred_route 1");
		$$ = _calloc(wrsm_preferred_route_t,1);
		$$->striping_level = $3;
		$$->method = $4;
		$$->route_type = route_wci;
		$$->route.wci_id = $5;
		if ($6) {
			$$->nswitches = $6->length;
			for (i = 0; i < $6->length; ++i)
				$$->switches[i] = $6->list[$6->length - i - 1];
		}
	}
|	PREFERRED_ROUTE LB striping_level routing_method use_stripe switches 
	RB {
		int i;
		TRACE("preferred_route 2");
		$$ = _calloc(wrsm_preferred_route_t,1);
		$$->striping_level = $3;
		$$->method = $4;
		$$->route_type = route_stripe_group;
		$$->route.stripe_group_id = $5;
		if ($6) {
			$$->nswitches = $6->length;
			for (i = 0; i < $6->length; ++i)
				$$->switches[i] = $6->list[$6->length - i - 1];
		}
	}
;

striping_level:
	STRIPING_LEVEL INT {
		TRACE("striping_level");
		$$ = $2;
	}
;

routing_method:
	ROUTING_METHOD RM {
		TRACE("routing_method");
		$$ = $2;
	}
;

use_wci:
	USE_WCI INT {
		TRACE("use_wci");
		$$ = $2;
	}
;

use_stripe:
	STRIPE_GROUP INT {
		TRACE("use_stripe");
		$$ = $2;
	}
;

switches:
	SWITCHES int_list 	{ $$ = $2; }
|				{ $$ = NULL; }
;

forwarding_ncslices:
	FORWARDING_NCSLICES int_list	{ $$ = $2; }
|				{ $$ = NULL; }
;

stripe_groups:
	stripe_group stripe_groups {
		TRACE("stripe_groups");
		++ngroups;
		$$ = _realloc($2, wrsm_stripe_group_t *, ngroups);
		$$[ngroups-1] = $1;
	}
|	{ $$ = NULL; }
;

stripe_group:
	STRIPE_GROUP INT LB WCIS int_list RB {
		int i;
		TRACE("stripe_group");
		$$ = _calloc(wrsm_stripe_group_t,1);
		$$->group_id = $2;
		if ($5->length > WRSM_MAX_WCIS_PER_STRIPE)
			Error("Too many wcis in stripe group");
		else {
			$$->nwcis = $5->length;
			for (i = 0; i < $$->nwcis; ++i)
				$$->wcis[i] = $5->list[i];
			free($5->list);
			free($5);
		}
	}
;

int_list:
	INT int_list {
		TRACE("int_list 1");
		$$ = $2;
		$$->length++;
		$$->list = _realloc($$->list,int,$$->length);
		$$->list[$$->length-1] = $1;
	}		
|	INT { 
		TRACE("int_list 2");
		$$ = _malloc(struct intlist,1);
		$$->length = 1;
		$$->list = _malloc(int,$$->length);
		$$->list[$$->length-1] = $1;
	}
;

%%


static int
compare_member(const void *a, const void *b)
{
	wrsm_cnodeid_t id_a, id_b;
	TRACE("compare_member");
	id_a = (*(wrsm_net_member_t **)a)->cnodeid;
	id_b = (*(wrsm_net_member_t **)b)->cnodeid;
	return (id_a - id_b);
}

static int
compare_policy(const void *a, const void *b)
{
	wrsm_cnodeid_t id_a, id_b;
	TRACE("compare_policy");
	id_a = (*(wrsm_routing_policy_t **)a)->cnodeid;
	id_b = (*(wrsm_routing_policy_t **)b)->cnodeid;
	return (id_a - id_b);
}

static int
compare_stripe_group(const void *a, const void *b)
{
	uint32_t id_a, id_b;
	TRACE("compare_stripe_group");
	id_a = (*(wrsm_stripe_group_t **)a)->group_id;
	id_b = (*(wrsm_stripe_group_t **)b)->group_id;
	return (id_a - id_b);
}

static int
compare_wci(const void *a, const void *b)
{
	uint32_t id_a, id_b;
	TRACE("compare_wci");
	id_a = (*(wrsm_wci_data_t **)a)->port;
	id_b = (*(wrsm_wci_data_t **)b)->port;
	return (id_a - id_b);
}


static void
postprocess_controller(wrsm_controller_t *cont)
{
	int i, j;
	TRACE("postprocess_controller");

	/* sort network members by cnodeid */
	qsort(cont->WRSM_ALIGN_PTR(members), cont->nmembers,
	    sizeof (wrsm_net_member_t *),
	    &compare_member);

	if (cont->WRSM_ALIGN_PTR(routing)) {
		wrsm_routing_data_t *routing;
		routing = cont->WRSM_ALIGN_PTR(routing);

		/* sort routing policies by cnodeid */
		qsort(routing->WRSM_ALIGN_PTR(policy), routing->npolicy,
		    sizeof (wrsm_routing_policy_t *), &compare_policy);

		/* sort stripe groupd by group id */
		qsort(routing->WRSM_ALIGN_PTR(stripe_groups),
		    routing->ngroups,
		    sizeof (wrsm_stripe_group_t *),
		    &compare_stripe_group);

		/* sort wcis by safari port id */
		qsort(routing->WRSM_ALIGN_PTR(wcis), routing->nwcis,
		    sizeof (wrsm_wci_data_t *), &compare_wci);

		/* Reverse the order of the preferred routes list */
		for (i = 0; i < routing->npolicy; ++i) {
			wrsm_preferred_route_t **routes = 
			    routing->WRSM_ALIGN_PTR(policy)[i]->
			    WRSM_ALIGN_PTR(preferred_routes);
			int nroutes =
				routing->WRSM_ALIGN_PTR(policy)[i]->nroutes;
			for (j = 0; j < (nroutes/2); ++j) {
				wrsm_preferred_route_t *tmp;
				tmp = routes[j];
				routes[j] = routes[nroutes - j - 1];
				routes[nroutes - j - 1] = tmp;
			}
		}
		/* Reverse the order of the stripe groups */
		for (i = 0; i < routing->ngroups; ++i) {
			wrsm_stripe_group_t *group =
				routing->WRSM_ALIGN_PTR(stripe_groups)[i];
			int nwcis = group->nwcis;
			for (j = 0; j < (nwcis / 2); ++j) {
				wrsm_safari_port_t tmp;
				tmp = group->wcis[j];
				group->wcis[j] = group->wcis[nwcis - j - 1];
				group->wcis[nwcis - j - 1] = tmp;
			}
		}
	}
}

wrsm_controller_t *
wrsm_find_controller(char *host, int id)
{
	int i;
	int j;
	TRACE("wrsm_find_controller");

	for (i = 0; i < num_ctlrs; i++) {
		if (host == NULL ||
		    strcmp(host, controller[i].hostname) == 0) {
			if (controller[i].controller_id == id) {
				return (&controller[i]);
			}
		}
	}
	return (NULL);
}

wrsm_controller_t *
wrsm_find_controller_by_hostname(char *host)
{
	int i;
	int j;
	TRACE("wrsm_find_controller_by_hostname");

	if (!host)
		return (NULL);

	for (i = 0; i < num_ctlrs; i++) {
		if (strcmp(host, controller[i].hostname) == 0) {
			return (&controller[i]);
		}
	}
	return (NULL);
}

void
wrsm_yacc_reset()
{
	int i;
	TRACE("wrsm_yacc_reset");

	for (i = 0; i < num_ctlrs; i++) {
		wrsm_cf_free(&controller[i], 0);
	}
	memset(controller, 0, sizeof(wrsm_controller_t) * WRSM_MAX_CNODES);
	num_ctlrs = 0;
	nmembers = 0;
	nwcis = 0;
	ngroups = 0;
	npolicy = 0;
	nroutes = 0;
}
