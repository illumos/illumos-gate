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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <unistd.h>
#include <door.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <syslog.h>
#include <sys/socket.h>
#include "mipagentstat_door.h"
#include "conflib.h"
#include "mip.h"
#include "hash.h"
#include "agent.h"

/*
 * Server for mipagentstat. This uses the protocol defined in
 * "mipagentstat_door.h" to act as a door server for home and
 * foreign agent statistics.
 *
 * The door server is created with the entry point dispatch;
 * the door itself is created and bound to the rendezvous point
 * on the filesystem by start_stat_server. dispatch simply
 * sets up the enumeration if the operation is FIRST_ENT, and
 * dispatches the enumeration call and it parameters to either
 * the home or foreign agent enumeration function.
 *
 * This module and the hash module both use the enumeration state
 * passed to and from the client. The are currently two different
 * types of hash tables to enumerate: the faVisitorHash is two
 * dimensional, the first being the hash buckets, and the second
 * being the chains on each bucket; the haMobileNodeHash is three
 * dimensional, the first and second dimensions being the same
 * as faVisitorHash, and the extra third dimension being chains
 * of bindings off each node in the hash chain.
 *
 * We use the notion of dimensions to optimize hash table
 * enumeration. The first dimension corresponds to the hash
 * table bucket, the second to the offset from that bucket,
 * and the third (in the case of haMobileNodeHash) to the
 * binding (which is an offset from the second offset). The state
 * is decomposed into four 32-bit counters, of which only the
 * first three are currently used. The first holds the bucket
 * counter, the second the offset counter, and the third the
 * binding offset counter. enumerateAllHashTableEntries handles
 * the bucket and offset state, which enumerateHABindings handles
 * the binding offset state.
 *
 * The counters are used as follows: we first jump to the bucket
 * indicated by the bucket counter; next we count off into the
 * chain until we reach the node following the node indicated by
 * the offset counter, and finally, in the case of haMobileNodeHash,
 * we count off from that node into the bindings list up to the
 * node following the binding counter. If either the offset or
 * binding offset counter reaches the end of its chain, we reset
 * it to zero, and proceed with the next bucket or chain. This
 * algorithm has the same computational complexity as the hash
 * algorithm itself, with respect to finding the next node.
 *
 * The following #defines specify which 32-bit words in the enumeration
 * state are used for what:
 */

#define	BUCKET	0
#define	OFFSET	1
#define	BINDING	2

extern HashTable faVisitorHash;		/* Foreign agent hashtable */
extern HashTable haMobileNodeHash;	/* Home agent hashtable */
extern HashTable mipAgentHash;		/* Mobility agent peers */

extern int  logVerbosity;

static int did = -1; /* file-descriptor for stat server door; -1 means unset */

/*
 * Function: enumerateHABindings
 *
 * Arguments:	state - IN/OUT 128 bits of enumeration state
 *		lck   - IN/OUT lock which protects the binding
 *			entry returned. If an entry was returned,
 *			lck will point to the node lock which
 *			the caller MUST unlock when done.
 *
 * Description:	This function gets the next mobile node binding
 *		from the hash table haMobileNodeHash. The HA
 *		hastable is three dimensional: The first is the
 *		hashtable bucket array, the second is the linked
 *		list of HashEntries off each bucket, and the
 *		third is the linked list of bindings associated
 *		with each HaMobileNodeEntry. Hence we need three
 *		state counters for this enumeration.
 *
 *		The enumeration state is contained in the state
 *		parameter, which is here cast to an array
 *		of four 32-bit unsigned integers. This function
 *		only used the first three words; the first two
 *		are used as enumeration state for
 *		enumerateAllHashTableEntries, while the third is
 *		used to find the next HaBindingEntry.
 *
 * Returns:	a HaBindingEntry on success
 *		NULL if there are no more entries in the table
 */
static HaBindingEntry *enumerateHABindings(uint32_t state[4], rwlock_t **lck) {
	HaMobileNodeEntry *hamne;
	HaBindingEntry *habe;
	uint32_t i;

	/* Find the next HaMobileNodeEntry */
	while ((hamne = enumerateAllHashTableEntries(&haMobileNodeHash,
						    state + BUCKET,
						    state + OFFSET,
						    LOCK_READ)) != NULL) {
	    habe = hamne->bindingEntries;

	    /* Find the next HaBindingEntry */
	    for (i = 0; habe; habe = habe->next, i++) {
		if (i == state[BINDING]) {
		    /* got it */
		    (state[BINDING])++;

		    /* Pass the nodeLock back to the caller to unlock */
		    *lck = &(hamne->haMnNodeLock);
		    return (habe);
		}
	    }

	    /* If we got here, there are no more bindings for this node */
	    state[BINDING] = 0;

	    (void) rw_unlock(&(hamne->haMnNodeLock));
	}

	/* If we got here, we have enumerated the whole table */
	return (NULL);
}

/*
 * Function:	enumerateHAStats
 *
 * Arguments:	args - IN/OUT The stat call/reply buffer
 *
 * Description:	This function uses enumerateHABindings to retrieve the
 *		next binding in the enumeration and then extracts
 *		the data needed for the stats call into the
 *		DoorStatArgs args.
 *
 * Returns:	1 on success, more entries to come
 *		0 on success, no more entries
 */
static int enumerateHAStats(DoorStatArgs *args) {
	HaBindingEntry *habe;
	/*LINTED pointer cast may result in improper alignment*/
	uint32_t *state = (uint32_t *)args->enum_state;
	rwlock_t *nodeLock = NULL;

	if ((habe = enumerateHABindings(state, &nodeLock)) == NULL) {
	    /* enumeration has completed */
	    return (0);
	}

	/* copy out mobile node's address */
	args->node_af = AF_INET;
	(void) memcpy(args->node,
			&(habe->haBindingMN),
			sizeof (habe->haBindingMN));
	/* copy out foreign agent's address */
	args->agent_af = AF_INET;
	(void) memcpy(args->agent,
			&(habe->haBindingCOA),
			sizeof (habe->haBindingCOA));
	/* Copy out time granted and remaining */
	args->granted = (uint32_t)habe->haBindingTimeGranted;
	args->expires = (uint32_t)habe->haBindingTimeExpires;
	/* Finally, copy in the flags! */
	args->service_flags = (uint8_t)habe->haBindingRegFlags;

	(void) rw_unlock(nodeLock);
	return (1);
}

/*
 * Function:	enumerateFAStats
 *
 * Arguments:	args - IN/OUT The stat call/reply buffer
 *
 * Description:	This function uses enumerateAllHashTableEntries
 *		to retrieve the next FaVisitorEntry in the enumeration
 *		and then extracts the data needed for the stats call
 *		into the DoorStatArgs args.
 *
 * Returns:	1 on success, more entries to come
 *		0 on success, no more entries
 */
static int enumerateFAStats(DoorStatArgs *args) {
	FaVisitorEntry *fave;
	/*LINTED pointer cast may result in improper alignment*/
	uint32_t *state = (uint32_t *)args->enum_state;

	if ((fave = enumerateAllHashTableEntries(&faVisitorHash,
						    state + BUCKET,
						    state + OFFSET,
						    LOCK_READ)) == NULL) {
	    /* enumeration has completed */
	    return (0);
	}

	/* copy out mobile node's home address */
	args->node_af = AF_INET;
	(void) memcpy(args->node,
			&(fave->faVisitorHomeAddr),
			sizeof (fave->faVisitorHomeAddr));
	/* copy out home agent's address */
	args->agent_af = AF_INET;
	(void) memcpy(args->agent,
			&(fave->faVisitorHomeAgentAddr),
			sizeof (fave->faVisitorHomeAgentAddr));
	/* Copy out time granted and remaining */
	args->granted = fave->faVisitorTimeGranted;
	args->expires = fave->faVisitorTimeExpires;
	/* Finally, copy in the flags! */
	args->service_flags = (uint8_t)fave->faVisitorRegFlags;

	(void) rw_unlock(&(fave->faVisitorNodeLock));
	return (1);
}


/*
 * Function:	enumerateAgentPeerStats
 *
 * Arguments:	args - IN/OUT The stat call/reply buffer
 *
 * Description:	This function uses enumerateAllHashTableEntres to
 *		retrieve the next MobilityAgentEntry in mipAgentHash,
 *		and then extracts the data needed for the stats call
 *		into the DoorStatArgs args.
 *
 * Returns:	1 on success, more entries to come
 *		0 on success, no more entries
 */
int enumerateAgentPeerStats(DoorStatArgs *args, uint8_t flags) {
	MobilityAgentEntry *mae;

	/* LINTED pointer cast may result in improper alignment */
	uint32_t *state = (uint32_t *)args->enum_state;

	/* skip the agent-peers that we're not looking for */
	do {
		mae = enumerateAllHashTableEntries(&mipAgentHash,
		    state + BUCKET, state + OFFSET, LOCK_READ);

		if (mae == NULL)
			return (0);

	} while ((mae->maPeerFlags & flags) == 0);

	/* copy out agent-peer's address */
	args->agent_af = AF_INET;
	(void) memcpy(args->agent, &(mae->maAddr), sizeof (mae->maAddr));

	/* Copy the flags */
	if (flags == FA_PEER)
		/*
		 * User wants FA_PEER SAs, so this is us as the HA.  Pass
		 * the SA bits which are relavent to us as HA peer, namely:
		 * request apply, and tunnel apply, and reply permit and
		 * reverse tunnel permit.  Also make sure we're only showing
		 * what's invoked (not just what's configured)!
		 */
		args->service_flags = (mae->maIPsecFlags &
		    ((mae->maIPsecSAFlags[IPSEC_APPLY] & HA_PEER_APPLY_MASK) | \
		    (mae->maIPsecSAFlags[IPSEC_PERMIT] & HA_PEER_PERMIT_MASK)));
	else
		/*
		 * For us as FA peer, we pass: request apply, reply permit,
		 * tunnel permit, and reverse tunnel apply.
		 */
		args->service_flags = (mae->maIPsecFlags &
		    ((mae->maIPsecSAFlags[IPSEC_APPLY] & FA_PEER_APPLY_MASK) | \
		    (mae->maIPsecSAFlags[IPSEC_PERMIT] & FA_PEER_PERMIT_MASK)));

	/* fin */
	(void) rw_unlock(&(mae->maNodeLock));
	return (1);
}

/*
 * Function:	dispatch
 *
 * Arguments:	see door_create(3x) for the description of the
 *		arguments passed to this function. The DoorStatArgs
 *		structure used for the IPC is in argp.
 *
 * Description:	Sets up the enumeration if the operation is FIRST_ENT,
 *		and then dispatches to either enumerateHAStats or
 *		enumerateFAStats. This is entry point to the door
 *		created by start_stat_server.
 */
/*ARGSUSED*/
static void dispatch(void *cookie, char *argp, size_t argsize,
    door_desc_t *dp, size_t ndesc)
{

	/*LINTED pointer cast may result in improper alignment*/
	DoorStatArgs *args = (DoorStatArgs *)argp;

	if (argsize < sizeof (*args)) {
	    mipverbose(("stats server: call buffer too small\n"));
	    (void) door_return(NULL, 0, NULL, 0);
	}

	/* Set up the enumeration operation */
	if (args->op == FIRST_ENT) {
	    initEnumeratorState(args->enum_state,
				sizeof (*(args->enum_state)));
	} else if (args->op != NEXT_ENT) {
	    /* sanity check: if the op isn't FIRST_ENT, it must be NEXT_ENT */
	    mipverbose(("stats server: Unknown enumeration operation\n"));
	    (void) door_return(NULL, 0, NULL, 0);
	}

	/* Dispatch to the HA or FA stat function */
	switch (args->type) {
	case HOME_AGENT:
	    if (enumerateHAStats(args) == 0)
		(void) door_return(NULL, 0, NULL, 0);
	    break;

	case FOREIGN_AGENT:
	    if (enumerateFAStats(args) == 0)
		(void) door_return(NULL, 0, NULL, 0);
	    break;

	case HOME_AGENT_PEER:
		if (enumerateAgentPeerStats(args, HA_PEER) == 0)
			(void) door_return(NULL, 0, NULL, 0);
		break;

	case FOREIGN_AGENT_PEER:
		if (enumerateAgentPeerStats(args, FA_PEER) == 0)
			(void) door_return(NULL, 0, NULL, 0);
		break;

	default:
	    mipverbose(("stats server: Unknown agent type requested\n"));
	    (void) door_return(NULL, 0, NULL, 0);
	}

	(void) door_return((char *)args, argsize, NULL, 0);
}

/*
 * Function:	startStatServer
 *
 * Description:	Creates the server door for receiving stat requests.
 *		If the door rendezvous file does not exist, creates it.
 *		This is the only entry point from mipagent into this
 *		module.
 *
 * Returns:	1 on error
 *		0 on success
 */
int startStatServer() {
	struct stat buf;

	if (did != -1) {
	    /* Door server is already running */
	    return (0);
	}

	/* Create the filesystem rendezvous point if not already there */
	if (stat(MIPAGENTSTAT_DOOR, &buf) < 0) {
	    int fd;
	    if ((fd = creat(MIPAGENTSTAT_DOOR, 0444)) < 0) {
		syslog(LOG_ERR, "Cannot create %s", MIPAGENTSTAT_DOOR);
		return (1);
	    }
	    (void) close(fd);
	}

	/* Create the door ... */
	if ((did = door_create(dispatch, NULL,
	    DOOR_REFUSE_DESC | DOOR_NO_CANCEL)) < 0) {
		syslog(LOG_ERR, "door_create failed: %s", strerror(errno));
		return (1);
	}

	/*
	 * And attach it to the rendezvous point, cleaning up any
	 * stale associations first.
	 */
	(void) fdetach(MIPAGENTSTAT_DOOR);

	if (fattach(did, MIPAGENTSTAT_DOOR) < 0) {
	    syslog(LOG_ERR, "Cannot attach door to %s: %s",
		    MIPAGENTSTAT_DOOR, strerror(errno));
	    return (1);
	}

	return (0);
}

/*
 * Function:	killStatServer
 *
 * Description:	This function is used to shut down the stat
 *		door server.
 *
 * Returns:	0 if successful, -1 on failure
 */
int killStatServer() {
	int err = door_revoke(did);
	did = -1;
	return (err);
}
