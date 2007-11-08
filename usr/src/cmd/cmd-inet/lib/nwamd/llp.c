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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This file contains the routines that manipulate Link Layer Profiles
 * (aka LLPs) and various support functions.  This includes parsing and
 * updating of the /etc/nwam/llp file.
 *
 * The daemon maintains a list of llp_t structures that represent the
 * provided configuration information for a link.  After the llp file
 * is read, entries are added to the LLP list for any known links
 * (identified by checking the interface list, which is based on the
 * v4 interfaces present after 'ifconfig -a plumb') which were not
 * represented in the llp file.  These entries contain the default
 * "automatic" settings: plumb both IPv4 and IPv6, use DHCP on the
 * v4 interface, and accept router- and DHCPv6-assigned addresses on
 * the v6 interface.  The default entries created by the daemon are
 * also added to the llp file.
 *
 * LLP priority is assigned based on two factors: the order within
 * the llp file, with earlier entries having higher priority; and
 * a preference for wired interfaces before wireless.  Entries that
 * are added to the file by the daemon are added *after* any existing
 * entries; within the added block, wired entries are added before
 * wireless.  Thus if the llp file is never modified externally, wired
 * will generally be ordered before wireless.  However, if the
 * administrator creates the file with wireless entries before wired,
 * that priority order will be respected.
 *
 * The llp list (pointed to by the global llp_head) is protected by
 * the global llp_lock, which should be pthread_mutex_lock()'d before
 * reading or writing the list.
 */

#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <strings.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <syslog.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <atomic.h>
#include <pthread.h>
#include <signal.h>

#include "defines.h"
#include "structures.h"
#include "functions.h"
#include "variables.h"

/* Lock to protect the llp list. */
static pthread_mutex_t llp_lock = PTHREAD_MUTEX_INITIALIZER;

llp_t *llp_head = NULL;
llp_t *link_layer_profile = NULL;

/*
 * Global variable to hold the highest priority.  Need to use the atomic
 * integer arithmetic functions to update it.
 */
static uint32_t llp_highest_pri = 0;

static void print_llp_list(void);

char *
llp_prnm(llp_t *llp)
{
	if (llp == NULL)
		return ("null_llp");
	else if (llp->llp_lname == NULL)
		return ("null_lname");
	else
		return (llp->llp_lname);
}

static void
llp_list_free(llp_t *head)
{
	llp_t **llpp;
	llp_t *llpfree;

	if (pthread_mutex_lock(&llp_lock) != 0) {
		/* Something very serious is wrong... */
		syslog(LOG_ERR, "llp_list_free: cannot lock mutex: %m");
		return;
	}
	llpp = &head;
	while (*llpp != NULL) {
		llpfree = *llpp;
		*llpp = llpfree->llp_next;
		free(llpfree->llp_ipv4addrstr);
		free(llpfree);
	}
	(void) pthread_mutex_unlock(&llp_lock);
}

llp_t *
llp_lookup(const char *link)
{
	llp_t *llp;

	if (link == NULL)
		return (NULL);

	/* The name may change.  Better hold the lock. */
	if (pthread_mutex_lock(&llp_lock) != 0) {
		/* Something very serious is wrong... */
		syslog(LOG_ERR, "llp_lookup: cannot lock mutex: %m");
		return (NULL);
	}
	for (llp = llp_head; llp != NULL; llp = llp->llp_next) {
		if (strcmp(link, llp->llp_lname) == 0)
			break;
	}
	(void) pthread_mutex_unlock(&llp_lock);
	return (llp);
}

/*
 * Choose the higher priority llp of the two passed in.  If one is
 * NULL, the other will be higher priority.  If both are NULL, NULL
 * is returned.
 *
 * Assumes that both are available (i.e. doesn't check IFF_RUNNING
 * or IF_DHCPFAILED flag values).
 */
llp_t *
llp_high_pri(llp_t *a, llp_t *b)
{
	if (a == NULL)
		return (b);
	else if (b == NULL)
		return (a);

	/*
	 * Higher priority is represented by a lower number.  This seems a
	 * bit backwards, but for now it makes assigning priorities very easy.
	 *
	 * We shouldn't have ties right now, but just in case, tie goes to a.
	 */
	return ((a->llp_pri <= b->llp_pri) ? a : b);
}

/*
 * Chooses the highest priority link that corresponds to an
 * available interface.
 */
llp_t *
llp_best_avail(void)
{
	llp_t *p, *rtnllp = NULL;
	struct interface *ifp;

	/* The priority may change.  Better hold the lock. */
	if (pthread_mutex_lock(&llp_lock) != 0) {
		/* Something very serious is wrong... */
		syslog(LOG_ERR, "llp_best_avail: cannot lock mutex: %m");
		return (NULL);
	}
	for (p = llp_head; p != NULL; p = p->llp_next) {
		ifp = get_interface(p->llp_lname);
		if (ifp == NULL || !is_plugged_in(ifp) ||
		    (ifp->if_lflags & IF_DHCPFAILED) != 0)
			continue;
		rtnllp = llp_high_pri(p, rtnllp);
	}
	(void) pthread_mutex_unlock(&llp_lock);

	return (rtnllp);
}

/*
 * Returns B_TRUE if llp is successfully activated;
 * B_FALSE if activation fails.
 */
boolean_t
llp_activate(llp_t *llp)
{
	boolean_t rtn;
	char *host;
	/*
	 * Choosing "dhcp" as a hostname is unsupported right now.
	 * We use hostname="dhcp" as a keyword telling bringupinterface()
	 * to use dhcp on the interface.
	 */
	char *dhcpstr = "dhcp";

	llp_deactivate();

	host = (llp->llp_ipv4src == IPV4SRC_DHCP) ? dhcpstr :
	    llp->llp_ipv4addrstr;

	if (bringupinterface(llp->llp_lname, host, llp->llp_ipv6addrstr,
	    llp->llp_ipv6onlink)) {
		link_layer_profile = llp;
		dprintf("llp_activate: activated llp for %s", llp_prnm(llp));
		rtn = B_TRUE;
	} else {
		dprintf("llp_activate: failed to bringup %s", llp_prnm(llp));
		link_layer_profile = NULL;
		rtn = B_FALSE;
	}

	return (rtn);
}

/*
 * Deactivate the current active llp (link_layer_profile)
 */
void
llp_deactivate(void)
{
	if (link_layer_profile == NULL)
		return;

	takedowninterface(link_layer_profile->llp_lname, B_TRUE,
	    link_layer_profile->llp_ipv6onlink);

	dprintf("llp_deactivate: setting link_layer_profile(%p) to NULL",
	    (void *)link_layer_profile);
	link_layer_profile = NULL;
}

/*
 * Replace the currently active link layer profile with the one
 * specified.  And since we're changing the lower layer stuff,
 * we need to first deactivate the current upper layer profile.
 * An upper layer profile will be reactivated later, when we get
 * confirmation that the new llp is fully up (has an address
 * assigned).
 *
 * If the new llp is the same as the currently active one, don't
 * do anything.
 *
 * If the new llp is NULL, just take down the currently active one.
 */
void
llp_swap(llp_t *newllp)
{
	char *upifname;

	if (newllp == link_layer_profile)
		return;

	deactivate_upper_layer_profile();

	if (link_layer_profile == NULL) {
		/*
		 * there shouldn't be anything else running;
		 * make sure that's the case!
		 */
		upifname = (newllp == NULL) ? NULL : newllp->llp_lname;
		take_down_all_ifs(upifname);
	} else {
		dprintf("taking down current link layer profile (%s)",
		    llp_prnm(link_layer_profile));
		llp_deactivate();
	}
	if (newllp != NULL) {
		dprintf("bringing up new link layer profile (%s)",
		    llp_prnm(newllp));
		(void) llp_activate(newllp);
	}
}

/*
 *
 * ifp->if_family == AF_INET, addr_src == DHCP ==> addr == NULL
 * ifp->if_family == AF_INET, addr_src == STATIC ==> addr non null sockaddr_in
 * ifp->if_family == AF_INET6, ipv6onlink == FALSE ==> addr == NULL
 * ifp->if_family == AF_INET6, ipv6onlink == TRUE,
 *     if addr non NULL then it is the textual representation of the address
 *     and prefix.
 *
 * The above set of conditions describe what the inputs to this fuction are
 * expected to be.  Given input which meets those conditions this functions
 * then outputs a line of configuration describing the inputs.
 *
 * Note that it is assumed only one thread can call this function at
 * any time.  So there is no lock to protect the file writing.  This
 * is true as the only caller of this function should originate from
 * llp_parse_config(), which is done at program initialization time.
 */
static void
add_if_file(FILE *fp, struct interface *ifp, ipv4src_t addr_src,
    boolean_t ipv6onlink, void *addr)
{
	char addr_buf[INET6_ADDRSTRLEN];

	switch (ifp->if_family) {
	case AF_INET:
		switch (addr_src) {
		case IPV4SRC_STATIC:
			/* This is not supposed to happen... */
			if (addr == NULL) {
				(void) fprintf(fp, "%s\tdhcp\n", ifp->if_name);
				break;
			}
			(void) inet_ntop(AF_INET, addr, addr_buf,
			    INET6_ADDRSTRLEN);
			(void) fprintf(fp, "%s\tstatic\t%s\n", ifp->if_name,
			    addr_buf);
			break;
		case IPV4SRC_DHCP:
			/* Default is DHCP for now. */
		default:
			(void) fprintf(fp, "%s\tdhcp\n", ifp->if_name);
			break;
		}
		break;

	case AF_INET6:
		if (ipv6onlink)
			(void) fprintf(fp, "%s\tipv6\n", ifp->if_name);
		break;

	default:
		syslog(LOG_ERR, "interface %s of type %d?!", ifp->if_name,
		    ifp->if_family);
		break;
	}
}

/*
 * Walker function to pass to walk_interface() to add a default
 * interface description to the LLPFILE.
 *
 * Regarding IF_TUN interfaces: see comments before find_and_add_llp()
 * for an explanation of why we skip them.
 */
static void
add_if_default(struct interface *ifp, void *arg)
{
	FILE *fp = (FILE *)arg;

	if (ifp->if_type != IF_TUN)
		add_if_file(fp, ifp, IPV4SRC_DHCP, B_TRUE, NULL);
}

/* Create the LLPFILE using info from the interface list. */
static void
create_llp_file(void)
{
	FILE *fp;
	int dirmode = S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH;

	/* Create the NWAM directory in case it does not exist. */
	if (mkdir(LLPDIR, dirmode) != 0) {
		if (errno != EEXIST) {
			syslog(LOG_ERR, "create NWAM directory: %m");
			return;
		}
	}
	if ((fp = fopen(LLPFILE, "w")) == NULL) {
		syslog(LOG_ERR, "create LLP config file: %m");
		return;
	}
	syslog(LOG_INFO, "Creating %s", LLPFILE);
	walk_interface(add_if_default, fp);
	(void) fclose(fp);
}

/*
 * Append an llp struct to the end of the llp list.
 */
static void
llp_list_append(llp_t *llp)
{
	llp_t **wpp = &llp_head;

	/*
	 * should be a no-op, but for now, make sure we only
	 * create llps for wired and wireless interfaces.
	 */
	if (llp->llp_type != IF_WIRED && llp->llp_type != IF_WIRELESS)
		return;

	if (pthread_mutex_lock(&llp_lock) != 0) {
		/* Something very serious is wrong... */
		syslog(LOG_ERR, "llp_list_append: cannot lock mutex: %m");
		return;
	}

	while (*wpp != NULL)
		wpp = &(*wpp)->llp_next;
	*wpp = llp;
	llp->llp_next = NULL;

	(void) pthread_mutex_unlock(&llp_lock);
}

/*
 * Create a llp given the parameters and add it to the global list.
 */
static void
create_and_add_llp(const char *name, ipv4src_t ipv4src, const char *addrstr,
    boolean_t ipv6onlink, const char *ipv6addrstr)
{
	llp_t *newllp;
	int lnamelen;

	if ((newllp = llp_lookup(name)) != NULL) {
		if (ipv6addrstr != NULL) {
			newllp->llp_ipv6addrstr = strdup(ipv6addrstr);
			if (newllp->llp_ipv6addrstr == NULL) {
				syslog(LOG_ERR, "could not save ipv6 static "
				    "address for %s", name);
			}
		}
		newllp->llp_ipv6onlink = ipv6onlink;
		return;
	} else if ((newllp = calloc(1, sizeof (llp_t))) == NULL) {
		syslog(LOG_ERR, "calloc llp: %m");
		return;
	}

	lnamelen = sizeof (newllp->llp_lname);
	if (strlcpy(newllp->llp_lname, name, lnamelen) >= lnamelen) {
		syslog(LOG_ERR, "llp: link name too long; ignoring entry");
		free(newllp);
		return;
	}
	if (ipv4src == IPV4SRC_STATIC) {
		if ((newllp->llp_ipv4addrstr = strdup(addrstr)) == NULL) {
			syslog(LOG_ERR, "malloc ipaddrstr: %m");
			free(newllp);
			return;
		}
	} else {
		newllp->llp_ipv4addrstr = NULL;
	}
	newllp->llp_next = NULL;
	newllp->llp_pri = atomic_add_32_nv(&llp_highest_pri, 1);
	newllp->llp_ipv4src = ipv4src;
	newllp->llp_type = find_if_type(newllp->llp_lname);
	newllp->llp_ipv6onlink = ipv6onlink;

	if (ipv6onlink && ipv6addrstr != NULL) {
		newllp->llp_ipv6addrstr = strdup(ipv6addrstr);
		if (newllp->llp_ipv6addrstr == NULL)
			syslog(LOG_WARNING, "could not store static address %s"
			    "on interface %s", ipv6addrstr, newllp->llp_lname);
	} else {
		newllp->llp_ipv6addrstr = NULL;
	}

	llp_list_append(newllp);

	dprintf("created llp for link %s, pri %d", newllp->llp_lname,
	    newllp->llp_pri);
}

/*
 * Walker function to pass to walk_interface() to find out if
 * an interface description is missing from LLPFILE.  If it is,
 * add it.
 *
 * Currently, IF_TUN type interfaces are special-cased: they are
 * only handled as user-enabled, layered links (which may be created
 * as part of a higher-layer profile, for example).  Thus, they
 * shouldn't be considered when looking at the llp list, so don't
 * add them here.
 */
static void
find_and_add_llp(struct interface *ifp, void *arg)
{
	FILE *fp = (FILE *)arg;

	if (ifp->if_type != IF_TUN && (llp_lookup(ifp->if_name) == NULL)) {
		dprintf("Adding %s to %s", ifp->if_name, LLPFILE);
		add_if_file(fp, ifp, IPV4SRC_DHCP, B_TRUE, NULL);
		/* If we run out of memory, ignore this interface for now. */
		create_and_add_llp(ifp->if_name, IPV4SRC_DHCP, NULL,
		    B_TRUE, NULL);
	}
}

/*
 * This is a very "slow" function.  It uses walk_interface() to find
 * out if any of the interface is missing from the LLPFILE.  For the
 * missing ones, add them to the LLPFILE.
 */
static void
add_missing_if_llp(FILE *fp)
{
	walk_interface(find_and_add_llp, fp);
}

static void
print_llp_list(void)
{
	llp_t *wp;

	dprintf("Walking llp list");
	for (wp = llp_head; wp != NULL; wp = wp->llp_next)
		dprintf("==> %s", wp->llp_lname);
}

/*
 * This function parses /etc/nwam/llp which describes the phase 0 link layer
 * profile.  The file is line oriented with each line containing tab or space
 * delimited fields.  Each address family (IPv4, IPv6) is described on a
 * separate line.
 * The first field is a link name.
 * The second field can be either static, dhcp, ipv6, or noipv6.
 * If the second field is static then the next field is an ipv4 address which
 *    can contain a prefix.  Previous versions of this file could contain a
 *    hostname in this field which is no longer supported.
 * If the second field is dhcp then dhcp will be used on the interface.
 * If the second field is ipv6 then an ipv6 interface is plumbed up.  The
 *    outcome of this is that if offered by the network in.ndpd and dhcp
 *    will conspire to put addresses on additional ipv6 logical interfaces.
 *    If the next field is non-null then it is taken to be an IPv6 address
 *    and possible prefix which are applied to the interface.
 * If the second field is noipv6 then no ipv6 interfaces will be put on that
 *    link.
 */
void
llp_parse_config(void)
{
	static const char STATICSTR[] = "static";
	static const char DHCP[] = "dhcp";
	static const char IPV6[] = "ipv6";
	static const char NOIPV6[] = "noipv6";
	FILE *fp;
	char line[LINE_MAX];
	char *cp, *lasts, *lstr, *srcstr, *addrstr, *v6addrstr;
	int lnum;
	ipv4src_t ipv4src;
	boolean_t ipv6onlink;

	fp = fopen(LLPFILE, "r+");
	if (fp == NULL) {
		if (errno != ENOENT) {
			/*
			 * XXX See comment before create_llp_file() re
			 * better error handling.
			 */
			syslog(LOG_ERR, "open LLP config file: %m");
			return;
		}

		/*
		 * If there is none, we should create one instead.
		 * For now, we will use the order of the interface list
		 * for the priority.  We should have a priority field
		 * in the llp file eventually...
		 */
		create_llp_file();

		/* Now we can try to reopen the file for processing. */
		fp = fopen(LLPFILE, "r+");
		if (fp == NULL) {
			syslog(LOG_ERR, "2nd open LLP config file: %m");
			return;
		}
	}

	if (llp_head != NULL)
		llp_list_free(llp_head);
	llp_head = NULL;

	for (lnum = 1; fgets(line, sizeof (line), fp) != NULL; lnum++) {
		ipv4src = IPV4SRC_DHCP;
		ipv6onlink = B_FALSE;
		addrstr = NULL;
		v6addrstr = NULL;

		if (line[strlen(line) - 1] == '\n')
			line[strlen(line) - 1] = '\0';

		cp = line;
		while (isspace(*cp))
			cp++;

		if (*cp == '#' || *cp == '\0')
			continue;

		dprintf("parsing llp conf file line %d...", lnum);

		if (((lstr = strtok_r(cp, " \t", &lasts)) == NULL) ||
		    ((srcstr = strtok_r(NULL, " \t", &lasts)) == NULL)) {
			syslog(LOG_ERR, "llp:%d: not enough tokens; "
			    "ignoring entry", lnum);
			continue;
		}
		if (strcasecmp(srcstr, STATICSTR) == 0) {
			if ((addrstr = strtok_r(NULL, " \t", &lasts)) == NULL ||
			    atoi(addrstr) == 0) { /* crude check for number */
				syslog(LOG_ERR, "llp:%d: missing ipaddr "
				    "for static config; ignoring entry",
				    lnum);
				continue;
			}
			ipv4src = IPV4SRC_STATIC;
		} else if (strcasecmp(srcstr, DHCP) == 0) {
			ipv4src = IPV4SRC_DHCP;
		} else if (strcasecmp(srcstr, IPV6) == 0) {
			ipv6onlink = B_TRUE;
			if ((addrstr = strtok_r(NULL, " \t", &lasts)) != NULL) {
				v6addrstr = strdup(addrstr);
				if (v6addrstr == NULL) {
					syslog(LOG_ERR, "could not store v6 "
					    "static address %s for %s",
					    v6addrstr, lstr);
				}
			} else {
				v6addrstr = NULL;
			}
		} else if (strcasecmp(srcstr, NOIPV6) == 0) {
			ipv6onlink = B_FALSE;
		} else {
			syslog(LOG_ERR, "llp:%d: unrecognized "
			    "field; ignoring entry", lnum);
			continue;
		}

		create_and_add_llp(lstr, ipv4src, addrstr, ipv6onlink,
		    v6addrstr);
	}

	/*
	 * So we have read in the llp file, is there an interface which
	 * it does not describe?  If yes, we'd better add it to the
	 * file for future reference.  Again, since we don't have a
	 * priority field yet, we will add the interface in the order
	 * in the interface list.
	 */
	add_missing_if_llp(fp);

	(void) fclose(fp);

	print_llp_list();
}
