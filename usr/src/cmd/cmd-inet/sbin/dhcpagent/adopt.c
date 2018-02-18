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
 *
 * ADOPTING state of the client state machine.  This is used only during
 * diskless boot with IPv4.
 */

#include <sys/types.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/socket.h>
#include <net/if_arp.h>
#include <netinet/in.h>
#include <sys/systeminfo.h>
#include <netinet/inetutil.h>
#include <netinet/dhcp.h>
#include <dhcpmsg.h>
#include <libdevinfo.h>

#include "agent.h"
#include "async.h"
#include "util.h"
#include "packet.h"
#include "interface.h"
#include "states.h"


typedef struct {
	char		dk_if_name[IFNAMSIZ];
	char		dk_ack[1];
} dhcp_kcache_t;

static int	get_dhcp_kcache(dhcp_kcache_t **, size_t *);

static boolean_t	get_prom_prop(const char *, const char *, uchar_t **,
			    uint_t *);

/*
 * dhcp_adopt(): adopts the interface managed by the kernel for diskless boot
 *
 *   input: void
 *  output: boolean_t: B_TRUE success, B_FALSE on failure
 */

boolean_t
dhcp_adopt(void)
{
	int		retval;
	dhcp_kcache_t	*kcache = NULL;
	size_t		kcache_size;
	PKT_LIST	*plp = NULL;
	dhcp_lif_t	*lif;
	dhcp_smach_t	*dsmp = NULL;
	uint_t		client_id_len;

	retval = get_dhcp_kcache(&kcache, &kcache_size);
	if (retval == 0 || kcache_size < sizeof (dhcp_kcache_t)) {
		dhcpmsg(MSG_CRIT, "dhcp_adopt: cannot fetch kernel cache");
		goto failure;
	}

	dhcpmsg(MSG_DEBUG, "dhcp_adopt: fetched %s kcache", kcache->dk_if_name);

	/*
	 * convert the kernel's ACK into binary
	 */

	plp = alloc_pkt_entry(strlen(kcache->dk_ack) / 2, B_FALSE);
	if (plp == NULL)
		goto failure;

	dhcpmsg(MSG_DEBUG, "dhcp_adopt: allocated ACK of %d bytes", plp->len);

	if (hexascii_to_octet(kcache->dk_ack, plp->len * 2, plp->pkt,
	    &plp->len) != 0) {
		dhcpmsg(MSG_CRIT, "dhcp_adopt: cannot convert kernel ACK");
		goto failure;
	}

	if (dhcp_options_scan(plp, B_TRUE) != 0) {
		dhcpmsg(MSG_CRIT, "dhcp_adopt: cannot parse kernel ACK");
		goto failure;
	}

	/*
	 * make an interface to represent the "cached interface" in
	 * the kernel, hook up the ACK packet we made, and send out
	 * the extend request (to attempt to renew the lease).
	 *
	 * we do a send_extend() instead of doing a dhcp_init_reboot()
	 * because although dhcp_init_reboot() is more correct from a
	 * protocol perspective, it introduces a window where a
	 * diskless client has no IP address but may need to page in
	 * more of this program.  we could mlockall(), but that's
	 * going to be a mess, especially with handling malloc() and
	 * stack growth, so it's easier to just renew().  the only
	 * catch here is that if we are not granted a renewal, we're
	 * totally hosed and can only bail out.
	 */

	if ((lif = attach_lif(kcache->dk_if_name, B_FALSE, &retval)) == NULL) {
		dhcpmsg(MSG_ERROR, "dhcp_adopt: unable to attach %s: %d",
		    kcache->dk_if_name, retval);
		goto failure;
	}

	if ((dsmp = insert_smach(lif, &retval)) == NULL) {
		dhcpmsg(MSG_ERROR, "dhcp_adopt: unable to create state "
		    "machine for %s: %d", kcache->dk_if_name, retval);
		goto failure;
	}

	/*
	 * If the agent is adopting a lease, then OBP is initially
	 * searched for a client-id.
	 */

	dhcpmsg(MSG_DEBUG, "dhcp_adopt: getting /chosen:clientid property");

	client_id_len = 0;
	if (!get_prom_prop("chosen", "client-id", &dsmp->dsm_cid,
	    &client_id_len)) {
		/*
		 * a failure occurred trying to acquire the client-id
		 */

		dhcpmsg(MSG_DEBUG,
		    "dhcp_adopt: cannot allocate client id for %s",
		    dsmp->dsm_name);
		goto failure;
	} else if (dsmp->dsm_hwtype == ARPHRD_IB && dsmp->dsm_cid == NULL) {
		/*
		 * when the interface is infiniband and the agent
		 * is adopting the lease there must be an OBP
		 * client-id.
		 */

		dhcpmsg(MSG_DEBUG, "dhcp_adopt: no /chosen:clientid id for %s",
		    dsmp->dsm_name);
		goto failure;
	}

	dsmp->dsm_cidlen = client_id_len;

	if (set_lif_dhcp(lif) != DHCP_IPC_SUCCESS)
		goto failure;

	if (!set_smach_state(dsmp, ADOPTING))
		goto failure;
	dsmp->dsm_dflags = DHCP_IF_PRIMARY;

	/*
	 * move to BOUND and use the information in our ACK packet.
	 * adoption will continue after DAD via dhcp_adopt_complete.
	 */

	if (!dhcp_bound(dsmp, plp)) {
		dhcpmsg(MSG_CRIT, "dhcp_adopt: cannot use cached packet");
		goto failure;
	}

	free(kcache);
	return (B_TRUE);

failure:
	/* Note: no need to free lif; dsmp holds reference */
	if (dsmp != NULL)
		remove_smach(dsmp);
	free(kcache);
	free_pkt_entry(plp);
	return (B_FALSE);
}

/*
 * dhcp_adopt_complete(): completes interface adoption process after kernel
 *			  duplicate address detection (DAD) is done.
 *
 *   input: dhcp_smach_t *: the state machine on which a lease is being adopted
 *  output: none
 */

void
dhcp_adopt_complete(dhcp_smach_t *dsmp)
{
	dhcpmsg(MSG_DEBUG, "dhcp_adopt_complete: completing adoption");

	if (async_start(dsmp, DHCP_EXTEND, B_FALSE) == 0) {
		dhcpmsg(MSG_CRIT, "dhcp_adopt_complete: async_start failed");
		return;
	}

	if (dhcp_extending(dsmp) == 0) {
		dhcpmsg(MSG_CRIT,
		    "dhcp_adopt_complete: cannot send renew request");
		return;
	}

	if (grandparent != (pid_t)0) {
		dhcpmsg(MSG_DEBUG, "adoption complete, signalling parent (%ld)"
		    " to exit.", grandparent);
		(void) kill(grandparent, SIGALRM);
	}
}

/*
 * get_dhcp_kcache(): fetches the DHCP ACK and interface name from the kernel
 *
 *   input: dhcp_kcache_t **: a dynamically-allocated cache packet
 *	    size_t *: the length of that packet (on return)
 *  output: int: nonzero on success, zero on failure
 */

static int
get_dhcp_kcache(dhcp_kcache_t **kernel_cachep, size_t *kcache_size)
{
	char	dummy;
	long	size;

	size = sysinfo(SI_DHCP_CACHE, &dummy, sizeof (dummy));
	if (size == -1)
		return (0);

	*kcache_size   = size;
	*kernel_cachep = malloc(*kcache_size);
	if (*kernel_cachep == NULL)
		return (0);

	(void) sysinfo(SI_DHCP_CACHE, (caddr_t)*kernel_cachep, size);
	return (1);
}

/*
 * get_prom_prop(): get the value of the named property on the named node in
 *		    devinfo root.
 *
 *   input: const char *: The name of the node containing the property.
 *	    const char *: The name of the property.
 *	    uchar_t **: The property value, modified iff B_TRUE is returned.
 *                      If no value is found the value is set to NULL.
 *	    uint_t *: The length of the property value
 *  output: boolean_t: Returns B_TRUE if successful (no problems),
 *                     otherwise B_FALSE.
 *    note: The memory allocated by this function must be freed by
 *          the caller.
 */

static boolean_t
get_prom_prop(const char *nodename, const char *propname, uchar_t **propvaluep,
    uint_t *lenp)
{
	di_node_t		root_node;
	di_node_t		node;
	di_prom_handle_t	phdl = DI_PROM_HANDLE_NIL;
	di_prom_prop_t		pp;
	uchar_t			*value = NULL;
	unsigned int		len = 0;
	boolean_t		success = B_TRUE;

	/*
	 * locate root node
	 */

	if ((root_node = di_init("/", DINFOCPYALL)) == DI_NODE_NIL ||
	    (phdl = di_prom_init()) == DI_PROM_HANDLE_NIL) {
		dhcpmsg(MSG_DEBUG, "get_prom_prop: property root node "
		    "not found");
		goto get_prom_prop_cleanup;
	}

	/*
	 * locate nodename within '/'
	 */

	for (node = di_child_node(root_node);
	    node != DI_NODE_NIL;
	    node = di_sibling_node(node)) {
		if (strcmp(di_node_name(node), nodename) == 0) {
			break;
		}
	}

	if (node == DI_NODE_NIL) {
		dhcpmsg(MSG_DEBUG, "get_prom_prop: node not found");
		goto get_prom_prop_cleanup;
	}

	/*
	 * scan all properties of /nodename for the 'propname' property
	 */

	for (pp = di_prom_prop_next(phdl, node, DI_PROM_PROP_NIL);
	    pp != DI_PROM_PROP_NIL;
	    pp = di_prom_prop_next(phdl, node, pp)) {

		dhcpmsg(MSG_DEBUG, "get_prom_prop: property = %s",
		    di_prom_prop_name(pp));

		if (strcmp(propname, di_prom_prop_name(pp)) == 0) {
			break;
		}
	}

	if (pp == DI_PROM_PROP_NIL) {
		dhcpmsg(MSG_DEBUG, "get_prom_prop: property not found");
		goto get_prom_prop_cleanup;
	}

	/*
	 * get the property; allocate some memory copy it out
	 */

	len = di_prom_prop_data(pp, (uchar_t **)&value);

	if (value == NULL) {
		/*
		 * property data read problems
		 */

		success = B_FALSE;
		dhcpmsg(MSG_ERR, "get_prom_prop: cannot read property data");
		goto get_prom_prop_cleanup;
	}

	if (propvaluep != NULL) {
		/*
		 * allocate somewhere to copy the property value to
		 */

		*propvaluep = calloc(len, sizeof (uchar_t));

		if (*propvaluep == NULL) {
			/*
			 * allocation problems
			 */

			success = B_FALSE;
			dhcpmsg(MSG_ERR, "get_prom_prop: cannot allocate "
			    "memory for property value");
			goto get_prom_prop_cleanup;
		}

		/*
		 * copy data out
		 */

		(void) memcpy(*propvaluep, value, len);

		/*
		 * copy out the length if a suitable pointer has
		 * been supplied
		 */

		if (lenp != NULL) {
			*lenp = len;
		}

		dhcpmsg(MSG_DEBUG, "get_prom_prop: property value "
		    "length = %d", len);
	}

get_prom_prop_cleanup:

	if (phdl != DI_PROM_HANDLE_NIL) {
		di_prom_fini(phdl);
	}

	if (root_node != DI_NODE_NIL) {
		di_fini(root_node);
	}

	return (success);
}
