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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This program converts a 'netlist' file into a config file, suitable
 * for configuring the Wildcat RSM driver.
 *
 * Caveats:
 *    Handles 2-way wci striping, but not 4-way.
 *    Assumes you want to do as much striping as possible.
 */

#include <sys/types.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <libintl.h>
#include <errno.h>
#include <sys/wrsm_types.h>
#include <sys/wrsm_config.h>
#include "wrsmconf_msgs.h"

#ifdef DEBUG
#define	TRACE(f)	printf(f)
#define	DPRINTF(s)	printf s
#else
#define	TRACE(f)
#define	DPRINTF(s)
#endif

#define	MAXHOSTS	256
#define	MAXWCIS		(3 * 18)
#define	MAXLINKS	8
#define	MAXOPTLEN	80
#define	MAXULONGSTR	11 /* E.g., 0xffffffff or 4294967295 */


#define	NCSLICE_BASE	0xA1	/* Works for Serengeti and Starcat */
#define	NCSLICE_CTRL	(multihop_allowed ? 10 : 4) /* Nodes per ctrl */
#define	COMM_BASE	2	/* Start with page 2 */
#define	PAGE_SIZE	0x2000

#define	MAXCTRL		((WRSM_MAX_NCSLICES - 1) - ncslice_base)/NCSLICE_CTRL
#define	WRSMCONF_CREATE "create"

/*
 *	Macros to produce a quoted string containing the value of a
 *	preprocessor macro. For example, if SIZE is defined to be 256,
 *	VAL2STR(SIZE) is "256". This is used to construct format
 *	strings for scanf-family functions below.
 */
#define	QUOTE(x)	#x
#define	VAL2STR(x)	QUOTE(x)

static int ncslice_base = NCSLICE_BASE;
static int controller = 0; /* Controller number to assign */
static int gnid_offset = 0;
static boolean_t passthrough_allowed = B_FALSE;
static boolean_t multihop_allowed = B_FALSE;
static FILE *outf = stdout;

typedef struct {
	boolean_t in_use;
	int remote_cnode;
	int remote_wci;
	int remote_link;
} link_info_t;

typedef struct {
	int wci_id;
	link_info_t links[MAXLINKS];
} wci_info_t;

typedef struct {
	boolean_t in_use;
	char name[WRSM_HOSTNAMELEN];
	int num_wcis;
	wci_info_t wcis[MAXWCIS];
	boolean_t wcswitch;
} host_info_t;

typedef struct {
	host_info_t hosts[MAXHOSTS];
	int num_hosts;
	union {
		struct {
			uint32_t upper_word;
			time_t clock_val;
		} raw;
		uint64_t val;
	} version_stamp;
} config_info_t;

typedef struct {
	int wcia;
	int wcib;
} stripe_group_t;

typedef struct {
	stripe_group_t sg[36];
	int nsg;
} stripe_list_t;

typedef enum {
	CAN_REACH_NO,
	CAN_REACH_DIRECT,
	CAN_REACH_MULTIHOP,
	CAN_REACH_PASSTHROUGH
} can_reach_t;

/*
 * Finds the WCI associated with the given cnodeid, and if not found
 * creates a new WCI for that cnode.
 */
static wci_info_t *
add_wci(config_info_t *config, int cnode, int wci_id)
{
	int i;
	host_info_t *host = &(config->hosts[cnode]);
	wci_info_t *wci;

	DPRINTF(("add_wci(cnode=%d, wci_id=%d)\n", cnode, wci_id));
	/* First search for a matching WCI */
	for (i = 0; i < host->num_wcis; i++) {
		wci = &(host->wcis[i]);
		if (wci->wci_id == wci_id) {
			return (wci);
		}
	}
	/* Otherwise, create the WCI */
	wci = &(host->wcis[host->num_wcis]);
	wci->wci_id = wci_id;
	host->num_wcis++;
	return (wci);
}

/* Adds link info to a host's wci */
static void
add_link(config_info_t *config, int cnode, int wci_id, int link,
    int rem_cnode, int rem_wci, int rem_link)
{
	host_info_t *host = &(config->hosts[cnode]);
	wci_info_t *wci = add_wci(config, cnode, wci_id);

	DPRINTF(("add_link(cnode=%d, wci_id=%d, link=%d, rem_cnode=%d, "
	    "rem_wci=%d, rem_link=%d)\n", cnode, wci_id, link, rem_cnode,
	    rem_wci, rem_link));

	/* Check for loopback links and ignore */
	if (cnode == rem_cnode && wci_id == rem_wci && link == rem_link) {
		return;
	}

	if (wci->links[link].in_use) {
		(void) fprintf(stderr, MSG_LINK_IN_USE,
		    WRSMCONF_CREATE, host->name, wci->wci_id, link);
		exit(1);
	}
	wci->links[link].in_use = B_TRUE;
	wci->links[link].remote_cnode = rem_cnode;
	wci->links[link].remote_wci = rem_wci;
	wci->links[link].remote_link = rem_link;
}

/* Creates a new host entry */
static int
add_host(config_info_t *config, char *hostname, boolean_t wcswitch)
{
	int i;
	int start = wcswitch ? 16 : 0; /* Bias switches to be > 16 */

	DPRINTF(("add_host(hostname=%s, wcswitch=%d)\n", hostname, wcswitch));

	for (i = start; i < MAXHOSTS; i++) {
		if (!config->hosts[i].in_use) {
			break;
		}
	}
	if (i == MAXHOSTS) {
		(void) fprintf(stderr, MSG_NUM_HOSTS, WRSMCONF_CREATE,
		    MAXHOSTS);
		exit(1);
	}
	config->hosts[i].in_use = B_TRUE;
	(void) strlcpy(config->hosts[i].name, hostname, WRSM_HOSTNAMELEN);
	config->hosts[i].wcswitch = wcswitch;

	return (i);
}

/* Given a host name, returns its cnode id, or creates a new one */
static int
host2node(config_info_t *config, char *hostname)
{
	int i;

	/* First search for previous occurence */
	for (i = 0; i < MAXHOSTS; i++) {
		if (config->hosts[i].in_use &&
		    strcmp(hostname, config->hosts[i].name) == 0) {
			return (i);
		}
	}
	return (add_host(config, hostname, B_FALSE));
}

/* Parses the netlist file into the config structure */
static void
parse_file(char *filename, config_info_t *config)
{
	char s[255];
	char t[255];
	FILE *f;
	boolean_t show_usage;

	if (strcmp(filename, "-") == 0) {
		f = stdin;
		show_usage = isatty(0) ? B_TRUE : B_FALSE;
	} else {
		f = fopen(filename, "r");
		show_usage = B_TRUE;
	}

	if (f == NULL) {
		perror(filename);
		exit(1);
	}
	if (show_usage) {
		(void) fprintf(stderr, MSG_INPUT1);
		(void) fprintf(stderr, MSG_INPUT2);
		(void) fprintf(stderr, MSG_INPUT3);
	}
	while (fgets(t, sizeof (t), f)) {
		int i;
		int x;
		char hosta[WRSM_HOSTNAMELEN+1];
		char hostb[WRSM_HOSTNAMELEN+1];
		char wciastr[MAXULONGSTR+1], wcibstr[MAXULONGSTR+1];
		int cnodea, wcia, linka, cnodeb, wcib, linkb;

		DPRINTF(("parsing line: %s\n", t));
		(void) fprintf(outf, "# %s", t);
		for (i = 0; t[i]; i++) {
			if (t[i] == '#') {
				break;
			} else if (t[i] == '.') {
				s[i] = ' ';
			} else if (t[i] == '=') {
				s[i] = ' ';
			} else {
				s[i] = t[i];
			}
		}
		s[i] = 0;

		/* Check if this line is an "option" */
		if (s[0] == '-') {
			char opt[MAXOPTLEN+1];
			char args[2][WRSM_HOSTNAMELEN+1];
			x = sscanf(&s[1],
			    "%" VAL2STR(MAXOPTLEN) "s "
			    "%" VAL2STR(WRSM_HOSTNAMELEN) "s "
			    "%" VAL2STR(WRSM_HOSTNAMELEN) "s",
			    opt, args[0], args[1]);
			if (strcmp(opt, "multihop") == 0 && x == 1) {
				multihop_allowed = B_TRUE;
			} else if (strcmp(opt, "passthrough") == 0 && x == 1) {
				passthrough_allowed = B_TRUE;
			} else if (strcmp(opt, "host") == 0 && x == 2) {
				(void) add_host(config, args[0], B_FALSE);
			} else if (strcmp(opt, "switch") == 0 && x == 2) {
				(void) add_host(config, args[0], B_TRUE);
				multihop_allowed = B_TRUE;
			} else if (strcmp(opt, "controller") == 0 && x == 2) {
				controller = strtol(args[0], NULL, 0);
			} else if (strcmp(opt, "ncslice") == 0 && x == 2) {
				int n = strtol(args[0], NULL, 0);
				if (n < 1 || n > 254) {
					(void) fprintf(stderr, MSG_INVALID,
					    WRSMCONF_CREATE, "ncslice", n);
				} else {
					ncslice_base = n;
				}
			} else if (strcmp(opt, "gnid") == 0 && x == 2) {
				gnid_offset = strtol(args[0], NULL, 0);
			} else {
				(void) fprintf(stderr, MSG_UNKNOWN,
				    WRSMCONF_CREATE, opt);
			}
			continue;
		}
		x = sscanf(s,
		    " %" VAL2STR(WRSM_HOSTNAMELEN) "s "
		    "%" VAL2STR(MAXULONGSTR) "s "
		    "%d "
		    "%" VAL2STR(WRSM_HOSTNAMELEN) "s "
		    "%" VAL2STR(MAXULONGSTR) "s "
		    "%d",
		    hosta, wciastr, &linka, hostb, wcibstr, &linkb);
		if (x < 1) {
			/* Blank line */
			continue;
		} else if (x < 6) {
			(void) fprintf(stderr, MSG_PARSE_ERR,
			    WRSMCONF_CREATE, t);
			continue;
		}
		wcia = strtol(wciastr, NULL, 0);
		wcib = strtol(wcibstr, NULL, 0);
		if (linka > MAXLINKS || linkb > MAXLINKS) {
			(void) fprintf(stderr, MSG_LINK_RANGE,
			    WRSMCONF_CREATE, s);
			exit(1);
		}
		cnodea = host2node(config, hosta);
		cnodeb = host2node(config, hostb);
		/* Link goes it both directions, so add both directions */
		add_link(config, cnodea, wcia, linka, cnodeb, wcib, linkb);
		add_link(config, cnodeb, wcib, linkb, cnodea, wcia, linka);
	}
}

/*
 * The following functions generate the actual config file
 */

/* Prints cnodeid section of config file */
static void
print_cnodeids(config_info_t *config, int cnode)
{
	int i;
	int comm_offset = (cnode + COMM_BASE) * PAGE_SIZE;

	for (i = 0; i < MAXHOSTS; i++) {
		int ncslice = i + ncslice_base + controller * NCSLICE_CTRL;
		int local_offset = (i + COMM_BASE) * PAGE_SIZE;

		if (!config->hosts[i].in_use ||
		    config->hosts[i].wcswitch) {
			continue;
		}

		(void) fprintf(outf, "\tcnodeid %d {\n", i);
		(void) fprintf(outf, "\t\tfmnodeid 0x%x %s\n",
		    i + gnid_offset, config->hosts[i].name);
		(void) fprintf(outf, "\t\texported_ncslices { 0x%02x }\n",
		    ncslice);
		(void) fprintf(outf, "\t\timported_ncslices { 0x%02x }\n",
		    cnode + ncslice_base + (controller * NCSLICE_CTRL));
		(void) fprintf(outf, "\t\tlocal_offset 0x%04x\n",
		    local_offset);
		(void) fprintf(outf, "\t\tcomm_ncslice 0x%02x 0x%04x\n",
		    ncslice, comm_offset);
		(void) fprintf(outf, "\t}\n");
	}
}

/* Prints the link subsection of the wci section of the config file */
static void
print_link(link_info_t *link)
{
	int remote_gnid;

	if (link->remote_cnode >= WRSM_MAX_WNODES)
		remote_gnid = link->remote_cnode;
	else
		remote_gnid = link->remote_cnode + gnid_offset;

	(void) fprintf(outf, "\t\t\tremote_gnid %d\n", remote_gnid);
	(void) fprintf(outf, "\t\t\tremote_link %d\n", link->remote_link);
	(void) fprintf(outf, "\t\t\tremote_wci %d\n", link->remote_wci);
}

/* Checks if a node is already reachable */
static int
is_duplicate(int reachable_list[], int *num_reachable, int cnode)
{
	int i;

	for (i = 0; i < *num_reachable; i++) {
		if (reachable_list[i] == cnode) {
			return (B_TRUE);
		}
	}
	reachable_list[*num_reachable] = cnode;
	(*num_reachable)++;
	return (B_FALSE);
}

/* Prints the wci section of the config file */
static void
print_wci(config_info_t *config, wci_info_t *wci, int cnode)
{
	int i;
	int j;
	boolean_t route_map_striping = B_FALSE;

	/* Check for route_map_striping */
	for (i = 0; i < MAXLINKS; i++) {
		link_info_t *ilink = &(wci->links[i]);
		if (!ilink->in_use) {
			continue;
		}
		for (j = 0; j < i; j++) {
			link_info_t *jlink = &(wci->links[j]);
			if (!jlink->in_use) {
				continue;
			}
			if (ilink->remote_cnode == jlink->remote_cnode &&
				ilink->remote_wci == jlink->remote_wci) {
				route_map_striping = B_TRUE;
			}
		}
	}

	(void) fprintf(outf, "\twci {\n");
	(void) fprintf(outf, "\t\tsafari_port_id %d\n", wci->wci_id);
	(void) fprintf(outf, "\t\twnodeid %d\n", cnode);
	(void) fprintf(outf, "\t\tgnid %d\n", cnode + gnid_offset);
	(void) fprintf(outf, "\t\treachable (%d,%d,%d)", cnode,
	    cnode + gnid_offset, cnode);

	for (i = 0; i < MAXLINKS; i++) {
		int reachable_list[MAXHOSTS];
		int num_reachable = 0;
		link_info_t *link = &(wci->links[i]);

		/* Add ourselves to the reachable list */
		reachable_list[num_reachable++] = cnode;

		if (!link->in_use) {
			continue;
		}
		/* Make sure it's not a dup */
		if (is_duplicate(reachable_list, &num_reachable,
		    link->remote_cnode)) {
			continue;
		}

		/* If not duplicate and remote node is a switch... */
		if (config->hosts[link->remote_cnode].wcswitch) {
			/* Ignore switch, report on remote cnodes */
			wci_info_t *swwci =
				&config->hosts[link->remote_cnode].wcis[0];

			for (j = 0; j < MAXLINKS; j++) {
				link_info_t *swlink = &(swwci->links[j]);
				if (!swlink->in_use) {
					continue;
				}
				if (is_duplicate(reachable_list,
				    &num_reachable, swlink->remote_cnode)) {
					continue;
				}
				(void) fprintf(outf, " (%d,%d,%d)",
				    swlink->remote_cnode,
				    swlink->remote_cnode + gnid_offset,
				    swlink->remote_cnode);
			}
		} else {
			(void) fprintf(outf, " (%d,%d,%d)",
			    link->remote_cnode,
			    link->remote_cnode + gnid_offset,
			    link->remote_cnode);
		}
	}
	(void) fprintf(outf, "\n");
	(void) fprintf(outf, "\t\troute_map_striping %s\n",
	    (route_map_striping)?"true":"false");
	(void) fprintf(outf, "\t\ttopology_type distributed_switch\n");
	for (i = 0; i < MAXLINKS; i++) {
		link_info_t *link = &(wci->links[i]);
		if (link->in_use) {
			(void) fprintf(outf, "\t\tlink %d {\n", i);
			print_link(link);
			(void) fprintf(outf, "\t\t}\n");
		}
	}
	(void) fprintf(outf, "\t}\n");
}

static wci_info_t *
wci_from_cnode(config_info_t *config, int cnode, int wci_id)
{
	int i;
	DPRINTF(("wci_from_cnode(cnode=%d, wci=%d)\n", cnode, wci_id));
	for (i = 0; i < config->hosts[cnode].num_wcis; i++) {
		if (config->hosts[cnode].wcis[i].wci_id == wci_id) {
			return (&config->hosts[cnode].wcis[i]);
		}
	}
	return (NULL);
}

static boolean_t
wci_can_reach_direct(wci_info_t *wci, int dest_cnode)
{
	int link;
	DPRINTF(("wci_can_reach_direct(wci=%d, dest_cnode=%d)\n",
	    wci->wci_id, dest_cnode));

	/* Look for direct connect */
	for (link = 0; link < MAXLINKS; link++) {
		if (wci->links[link].in_use &&
		    wci->links[link].remote_cnode == dest_cnode) {
			DPRINTF((" wci_can_reach_direct: TRUE\n"));
			return (B_TRUE);
		}
	}
	DPRINTF((" wci_can_reach_direct: FALSE\n"));
	return (B_FALSE);
}

static boolean_t
wci_can_reach_multihop(config_info_t *config, wci_info_t *wci,
    int dest_cnode)
{
	int link;

	DPRINTF(("wci_can_reach_multihop(wci=%d, dest_cnode=%d)\n",
	    wci->wci_id, dest_cnode));

	for (link = 0; link < MAXLINKS; link++) {
		if (wci->links[link].in_use) {
			/* Find the WCI at the other end of the link */
			wci_info_t *mh_wci =
				wci_from_cnode(config,
				    wci->links[link].remote_cnode,
				    wci->links[link].remote_wci);
			if (mh_wci == NULL) {
				exit(1);
			}
			/* See if that WCI can get us where we're going */
			if (wci_can_reach_direct(mh_wci, dest_cnode)) {
				DPRINTF((" wci_can_reach_multihop: TRUE\n"));
				return (B_TRUE);
			}
		}
	}
	DPRINTF((" wci_can_reach_multihop: FALSE\n"));
	return (B_FALSE);
}

static boolean_t
cnode_can_reach_direct(config_info_t *config, int cnode, int dest_cnode)
{
	int i;
	DPRINTF(("cnode_can_reach_direct(cnode=%d, dest_cnode=%d)\n",
	    cnode, dest_cnode));
	for (i = 0; i < config->hosts[cnode].num_wcis; i++) {
		if (wci_can_reach_direct(
			&config->hosts[cnode].wcis[i],
			    dest_cnode)) {
			DPRINTF((" cnode_can_reach_direct: TRUE\n"));
			return (B_TRUE);
		}
	}
	DPRINTF((" cnode_can_reach_direct: FALSE\n"));
	return (B_FALSE);
}

static boolean_t
wci_can_reach_passthrough(config_info_t *config, wci_info_t *wci,
    int dest_cnode, int *pt_cnode, int *num_switches)
{
	int link;
	DPRINTF(("wci_can_reach_passthrough(wci=%d, dest_cnode=%d)\n",
	    wci->wci_id, dest_cnode));

	*num_switches = 0;
	/* Try all links, until we've found two switches */
	for (link = 0; link < MAXLINKS && *num_switches < 2; link++) {
		/*
		 * If this link is in use, and the cnode at the other
		 * end of the link can reach the destination cnode,
		 * then we have a passthrough route.
		 */
		if (wci->links[link].in_use &&
		    cnode_can_reach_direct(config,
			wci->links[link].remote_cnode,
			dest_cnode)) {
			/* Remember the passthrough node */
			pt_cnode[*num_switches] =
				wci->links[link].remote_cnode;
			(*num_switches)++;
			DPRINTF((" wci_can_reach_passthrough: TRUE\n"));
		}
	}
	DPRINTF((" wci_can_reach_passthrough: %d\n", *num_switches));
	return (*num_switches > 0);
}

/* Checks if this wci can reach the dest_cnode on one of its links */
static can_reach_t
wci_can_reach(config_info_t *config, wci_info_t *wci, int dest_cnode,
    int *pt_cnodes, int *num_switches)
{
	DPRINTF(("wci_can_reach(wci=%d, dest_cnode=%d)\n",
	    wci->wci_id, dest_cnode));

	*pt_cnodes = -1;
	*num_switches = 0;

	/* First try direct connect */
	if (wci_can_reach_direct(wci, dest_cnode)) {
		return (CAN_REACH_DIRECT);
	}
	/* Look for multihop */
	if (multihop_allowed &&
	    wci_can_reach_multihop(config, wci, dest_cnode)) {
		return (CAN_REACH_MULTIHOP);
	}
	/* Finally, try passthrough */
	if (pt_cnodes != NULL && passthrough_allowed &&
	    wci_can_reach_passthrough(config, wci, dest_cnode,
		pt_cnodes, num_switches)) {
		return (CAN_REACH_PASSTHROUGH);
	}
	return (CAN_REACH_NO);
}

/* Given two wcis, returns their stripe group (or creates a new one) */
static int
get_stripe_group(stripe_list_t *sl, int wcia, int wcib) {
	int i;

	for (i = 0; i < sl->nsg; i++) {
		if ((sl->sg[i].wcia == wcia && sl->sg[i].wcib == wcib) ||
		    (sl->sg[i].wcia == wcib && sl->sg[i].wcib == wcia))
			return (i);
	}
	sl->sg[i].wcia = wcia;
	sl->sg[i].wcib = wcib;
	sl->nsg++;
	return (i);
}

/* Prints the stripe_group section of the config file */
static void
print_stripe_groups(stripe_list_t *sl)
{
	int i;
	for (i = 0; i < sl->nsg; i++) {
		(void) fprintf(outf, "\tstripe_group %d { \n", i);
		(void) fprintf(outf, "\t\twcis 0x%x 0x%x\n",
		    sl->sg[i].wcia, sl->sg[i].wcib);
		(void) fprintf(outf, "\t}\n");
	}
}

/* Prints the routing sections of the config file */
static void
print_routing(config_info_t *config, int cnode)
{
	int i;
	int j;
	int k;
	stripe_list_t sl;
	host_info_t *host = &(config->hosts[cnode]);
	int ptswitches[4];
	int num_switches = 0;

	sl.nsg = 0;

	for (i = 0; i < MAXHOSTS; i++) {
		boolean_t same_node = (i == cnode);
		boolean_t found_a_route = B_FALSE;

		if (!config->hosts[i].in_use ||
		    config->hosts[i].wcswitch) {
			continue;
		}

		(void) fprintf(outf, "\trouting_policy %d { # %s\n",
		    i, same_node ? "loopback" : config->hosts[i].name);
		/* First check for WCI striping */
		for (j = 0; j < host->num_wcis && !same_node; j++) {
			wci_info_t *jwci = &(host->wcis[j]);
			can_reach_t can_reach_j = wci_can_reach(config,
			    jwci, i, ptswitches, &num_switches);
			if (can_reach_j == CAN_REACH_NO) {
				continue;
			}
			for (k = 0; k < j; k++) {
				wci_info_t *kwci = &(host->wcis[k]);
				int sg;
				int new_ptswitches[2];
				int new_switches = 0;
				can_reach_t can_reach_k =
					wci_can_reach(config, kwci, i,
					    new_ptswitches,
					    &new_switches);
				if (can_reach_k != can_reach_j) {
					continue;
				}
				found_a_route = B_TRUE;

				/* Make sure pt striping is balanced */
				if (num_switches == new_switches) {
					int k;
					for (k = 0; k < new_switches; k++) {
						ptswitches[num_switches + k] =
							new_ptswitches[k];
					}
					num_switches += new_switches;
				} else if (num_switches > 0) {
					ptswitches[1] = new_ptswitches[0];
					num_switches = 2;
				}
				sg = get_stripe_group(&sl, jwci->wci_id,
				    kwci->wci_id);
				(void) fprintf(outf,
				    "\t\tpreferred_route {\n");
				(void) fprintf(outf,
				    "\t\t\tstriping_level %d\n",
				    (can_reach_j == CAN_REACH_PASSTHROUGH) ?
				    num_switches : 2);
				(void) fprintf(outf,
				    "\t\t\trouting_method %s\n",
				    (can_reach_j == CAN_REACH_PASSTHROUGH) ?
				    "passthrough" : "multihop");
				(void) fprintf(outf,
				    "\t\t\tstripe_group %d\n", sg);
				if (can_reach_j == CAN_REACH_PASSTHROUGH) {
					int k;
					(void) fprintf(outf,
					    "\t\t\tswitches");
					for (k = 0; k < num_switches; k++) {
						(void) fprintf(outf, " %d",
						    ptswitches[k]);
					}
					(void) fprintf(outf, "\n");
				}
				(void) fprintf(outf, "\t\t}\n");
			}
		}

		/* Next, find out how many WCIs go there */
		for (j = 0; j < host->num_wcis; j++) {
			wci_info_t *wci = &(host->wcis[j]);
			/* Note: We can always reach ourselves */
			can_reach_t can_reach;
			if (same_node) {
				can_reach = CAN_REACH_MULTIHOP;
			} else {
				can_reach = wci_can_reach(config,
				    wci, i, &ptswitches[0], &num_switches);
			}

			if (can_reach == CAN_REACH_NO && i != cnode) {
				continue;
			}
			found_a_route = B_TRUE;
			(void) fprintf(outf, "\t\tpreferred_route {\n");
			(void) fprintf(outf, "\t\t\tstriping_level %d\n",
			    (can_reach == CAN_REACH_PASSTHROUGH) ?
			    num_switches : 1);
			(void) fprintf(outf, "\t\t\trouting_method %s\n",
			    (can_reach == CAN_REACH_PASSTHROUGH) ?
			    "passthrough" : "multihop");
			(void) fprintf(outf, "\t\t\tuse_wci %d\n",
			    wci->wci_id);
			if (can_reach == CAN_REACH_PASSTHROUGH) {
				int k;
				(void) fprintf(outf, "\t\t\tswitches");
				for (k = 0; k < num_switches; k++) {
					(void) fprintf(outf, " %d",
					    ptswitches[k]);
				}
				(void) fprintf(outf, "\n");
			}
			(void) fprintf(outf, "\t\t}\n");
		}
		if (!found_a_route) {
			(void) fprintf(stderr, MSG_NO_ROUTE, WRSMCONF_CREATE,
			    config->hosts[i].name, config->hosts[j].name);
			(void) fprintf(outf, "\t\t/* NO ROUTE */\n");
		}
		(void) fprintf(outf, "\t\twcis_balanced false\n");
		(void) fprintf(outf, "\t\tstriping_important true\n");
		if (passthrough_allowed && !same_node) {
			(void) fprintf(outf,
			    "\t\tforwarding_ncslices 0x%x\n",
			    i + ncslice_base + (controller * NCSLICE_CTRL));
		}
		(void) fprintf(outf, "\t}\n");
	}
	print_stripe_groups(&sl);
}

/* Prints a specific host configuration */
static void
print_host(config_info_t *config, int cnode)
{
	int i;
	host_info_t *host = &(config->hosts[cnode]);

	(void) fprintf(outf, "\n");
	(void) fprintf(outf, "#\n");
	(void) fprintf(outf, "# Config for host %s\n", host->name);
	(void) fprintf(outf, "#\n");
	(void) fprintf(outf, "fmnodeid 0x%x %s\n", cnode + gnid_offset,
	    host->name);
	(void) fprintf(outf, "controller %d {\n", controller);
	(void) fprintf(outf, "\tconfig_protocol_version %u\n",
	    2);
	(void) fprintf(outf, "\tversion %llu\n", config->version_stamp.val);
	(void) fprintf(outf, "\tlocal_cnodeid %d\n", cnode);
	print_cnodeids(config, cnode);
	for (i = 0; i < host->num_wcis; i++) {
		print_wci(config, &(host->wcis[i]), cnode);
	}
	print_routing(config, cnode);
	(void) fprintf(outf, "}\n");
}

/* Prints config file for all hosts */
static void
print_config_file(config_info_t *config)
{
	int i;
	for (i = 0; i < MAXHOSTS; i++) {
		if (config->hosts[i].in_use &&
		    !config->hosts[i].wcswitch) {
			print_host(config, i);
		}
	}
}

/* Main */
int
mkconfig(char *input_file, char *output_file, int controller_id)
{
	config_info_t the_config;

	(void) memset(&the_config, 0, sizeof (the_config));
	(void) time(&the_config.version_stamp.raw.clock_val);
	/* Set MSB to differentiate from FM-generated version stamps */
	the_config.version_stamp.raw.upper_word = 0x80000000;

	if (controller_id > MAXCTRL || controller_id < 0) {
		errno = EINVAL;
		perror(WRSMCONF_CREATE);
		return (1);
	}
	controller = controller_id;

	if (input_file == NULL)
		input_file = "-";
	if (output_file != NULL) {
		outf = fopen(output_file, "w");
		if (outf == NULL) {
			perror(WRSMCONF_CREATE);
			return (1);
		}
	}
	parse_file(input_file, &the_config);
	if (the_config.num_hosts > NCSLICE_CTRL) {
		(void) fprintf(stderr, MSG_NUM_HOSTS,
		    WRSMCONF_CREATE, NCSLICE_CTRL);
		return (1);
	}
	print_config_file(&the_config);
	return (0);
}
