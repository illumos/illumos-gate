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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * file: setup.c
 *
 * This file contains the routines used to create data
 * structures, such as Mobile Nodes, Visitor Entries,
 * interfaces and security association.
 */
#include <stdio.h>
#include <syslog.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <limits.h>

#include <errno.h>
#include "agent.h"
#include "mip.h"
#include "setup.h"
#include "agentKernelIntfce.h"

/* ----------------- Common to all mobility agents ------------------- */
extern struct hash_table maAdvConfigHash;

/*
 * This table stores all of the Security Associations
 */
extern HashTable mipSecAssocHash;

/*
 * This table has one entry for each known Mobility Agent
 */
extern HashTable mipAgentHash;

/*
 * This table has one entry for each pool defined in the config file
 */
extern HashTable mipPoolHash;

/*
 * This table has one entry for each active tunnel number
 */
extern HashTable mipTunlHash;

/* Home Agent specific data structures. */
extern struct hash_table haMobileNodeHash;

/* Other external declarations */
extern int  logVerbosity;

/* MipTunlEntryLookup function defined in agentKernelIntfce.c */
extern boolean_t MipTunlEntryLookup(void *, ipaddr_t, uint32_t, uint32_t);
/*
 * Given that we are acting as an SNMP Sub-Agent, we will need
 * to register our address with the SNMP Master Agent. The
 * subagent_addr variable is used for this purpose.
 */
ipaddr_t subagent_addr = 0;
static ipaddr_t haAddr = 0;


extern void HAinitID(uint32_t *, uint32_t *, int);
#define	VNI		"vni"
#define	VNISTRLEN	3

/*
 * Function: CreateMobileNodeEntry
 *
 * Arguments:	mnEntryType - Whether the entry is dynamic or
 *			static
 *		homeAddr - The Mobile Node's Home Address
 *		mnNAI - The Mobile Node's NAI
 *		mnNAILen - The length of the NAI
 *		homeAgentAddr - The Mobile Node's Home Agent
 *		SPI - The Mobile Node's SPI
 *		state - A RADIUS thing. not needed for now
 *		poolIdentifier - The Pool Identifier
 *
 * Description: This function is used to create a Mobile Node
 *		entry, which is added to the hash table. The
 *		SPI provided MUST have been previously defined
 *		as is the pool (if a non-zero value was provided
 *		as the pool id).
 *
 *		If a Home Address was provided, we will add the
 *		node to the hash table based on the Home Address
 *		otherwise the NAI will be used.
 *
 *		The Mobile Node entry will be locked upon return.
 *		The caller is responsible for unlocking the
 *		node when it is finished with it.
 *
 * Returns:	upon successful return, this function will
 *		return the Mobile Node Entry pointer, otherwise
 *		NULL.
 *
 */
/* ARGSUSED */
HaMobileNodeEntry *
CreateMobileNodeEntry(boolean_t isDynamic, ipaddr_t homeAddr, char *mnNAI,
    uint32_t mnNaiLen, ipaddr_t homeAgentAddr, uint32_t SPI, char *state,
    uint32_t poolIdentifier)
{
	HaMobileNodeEntry *entry = NULL;
	MipSecAssocEntry *saEntry;
#ifdef RADIUS_ENABLED
	time_t currentTime;
#endif /* RADIUS_ENABLED */

	if (homeAddr == INADDR_ANY && (mnNAI == NULL || mnNaiLen == 0)) {
		syslog(LOG_ERR, "Home Address OR NAI Must be specified");
		return (NULL);
	}
	/*
	 * First, let's make sure that we already have
	 * this SPI defined.
	 */
	if ((saEntry = findHashTableEntryUint(&mipSecAssocHash,
	    SPI, LOCK_NONE, NULL, 0, 0, 0)) == NULL) {
		syslog(LOG_ERR, "SPI entry %d not found", SPI);
		return (NULL);
	}

	/*
	 * Let's see if we already have this pool.
	 */
	if (poolIdentifier) {
		if (findHashTableEntryUint(&mipPoolHash,
		    poolIdentifier, LOCK_NONE, NULL, 0, 0, 0) == NULL) {
			syslog(LOG_CRIT, "Pool entry %d not found.",
			    poolIdentifier);
			return (NULL);
		}
	}

	/*
	 * If an NAI is provided, make sure that it is legal
	 */
	if (mnNAI) {
		if (mnNaiLen > MAX_NAI_LENGTH) {
			syslog(LOG_ERR, "Error: Mobile Node NAI too long");
			return (NULL);
		}
	}


	entry = (HaMobileNodeEntry *)calloc(1, sizeof (HaMobileNodeEntry));

	if (!entry) {
		syslog(LOG_CRIT, "FATAL: Unable to allocate Mobile Node Entry");
		return (NULL);
	}

	/* Now add our values */
	entry->haMnIsEntryDynamic = isDynamic;
	entry->haMnAddr = homeAddr;
	if (homeAgentAddr == 0) {
		entry->haBindingIfaceAddr = haAddr;
	} else {
		entry->haBindingIfaceAddr = homeAgentAddr;
	}
	entry->haMnBindingCnt = 0;
#ifdef RADIUS_ENABLED
	GET_TIME(currentTime);
	entry->haRadiusState = state;
	entry->haRadiusLastLookupTime = currentTime;
#endif /* RADIUS_ENABLED */
	entry->haMnSPI = SPI;
	entry->haPoolIdentifier = poolIdentifier;

	if (mnNAI) {
		(void) strncpy((char *)entry->haMnNAI, mnNAI, mnNaiLen);
		entry->haMnNAI[mnNaiLen] = '\0';
		entry->haMnNAILen = mnNaiLen;
	}

	HAinitID(&entry->haMnRegIDHigh, &entry->haMnRegIDLow,
	    saEntry->mipSecReplayMethod);

	if (rwlock_init(&entry->haMnNodeLock, USYNC_THREAD, NULL)) {
		syslog(LOG_ERR, "Unable to initialize read/write lock");
		free(entry);
		return (NULL);
	}

	if (poolIdentifier && mnNaiLen) {
		/* Add the entry to the NAI hash */
		if (linkHashTableEntryString(&haMobileNodeHash,
		    (unsigned char *)entry->haMnNAI, mnNaiLen,
		    entry, LOCK_WRITE)) {
			syslog(LOG_ERR, "Unable to add Mobile Node entry to "
			    "hash table");
			(void) rwlock_destroy(&entry->haMnNodeLock);
			free(entry);
			return (NULL);
		}
	} else {
		if (linkHashTableEntryUint(&haMobileNodeHash, entry->haMnAddr,
		    entry, LOCK_WRITE)) {
			syslog(LOG_ERR, "Unable to add Mobile Node entry to "
			    "hash table");
			(void) rwlock_destroy(&entry->haMnNodeLock);
			free(entry);
			return (NULL);
		}
	}

	return (entry);
}

/*
 * Function: CreateMobilityAgentEntry
 *
 * Arguments:	maEntryType - Whether the entry is dynamic or
 *			static
 *		address - The Mobility Agent's IP Address
 *		SPI - The Mobility Agent's SPI
 *		lifetime - The lifetime of the entry (for
 *			dynamic entries only)
 *
 * Description: This function will create the Mobility Agent
 *		Entry, and will add it to the Hash table.
 *		The SPI provided MUST have been previously
 *		defined, otherwise an error will occur.
 *
 *		If the node is created as a dynamic entry,
 *		we will setup the entry's expiration time.
 *
 *		The entry will be locked upon return.
 *		The caller is responsible for unlocking the
 *		node when it is finished with it.
 *
 * Returns:	upon successful return, this function will
 *		return the Mobility Agent Entry pointer,
 *		otherwise NULL.
 */
MobilityAgentEntry *
CreateMobilityAgentEntry(boolean_t isDynamic, ipaddr_t address,
    uint32_t SPI, uint32_t lifetime)
{
	MobilityAgentEntry *entry = NULL;
	time_t currentTime;

	/*
	 * First, let's make sure that we do not already have
	 * this SPI defined.
	 */
	if (findHashTableEntryUint(&mipSecAssocHash,
	    SPI, LOCK_NONE, NULL, 0, 0, 0) == NULL) {
		syslog(LOG_ERR, "SPI entry %d not found", SPI);
		return (NULL);
	}

	entry = (MobilityAgentEntry *)calloc(1, sizeof (MobilityAgentEntry));

	if (!entry) {
		syslog(LOG_CRIT, "FATAL: Unable to allocate MIP Agent Entry");
		return (NULL);
	}

	/* Now add our values */
	entry->maAddr = address;
	entry->maSPI = SPI;
	entry->maIsEntryDynamic = isDynamic;

	if (isDynamic) {
		/*
		 * Setup when the key expires...
		 */
		GET_TIME(currentTime);
		entry->maExpiration = currentTime + lifetime;
	} else {
		entry->maExpiration = TIME_INFINITY;
	}

	if (rwlock_init(&entry->maNodeLock, USYNC_THREAD, NULL)) {
		syslog(LOG_ERR, "Unable to initialize read/write lock");
		free(entry);
		return (NULL);
	}

	if (linkHashTableEntryUint(&mipAgentHash, entry->maAddr, entry,
	    LOCK_WRITE)) {
		syslog(LOG_ERR, "Unable to add MIP Agent entry to hash "
		    "table");
		(void) rwlock_destroy(&entry->maNodeLock);
		free(entry);
		return (NULL);
	}

	return (entry);
}

/*
 * Function: CreateSecAssocEntry
 *
 * Arguments:	SPI - Security Parameter Index
 *		SaType - Whether the entry is dynamic or
 *			static
 *		ReplayProtection - The replay protection
 *			type
 *		AlgorithmType - The authentication algorithm
 *			type
 *		AlgorithmMode - The mode used for the
 *			algorithm.
 *		keyLength - The length of the key
 *		key - A pointer to the key
 *		lifetime - The lifetime of the entry (for
 *			dynamic entries only)
 *
 * Description: This function will create a Security Association
 *		entry, and will add it to the hash table. If the
 *		SPI already exists, we will return an error.
 *
 *		If the node is created as a dynamic entry,
 *		we will setup the entry's expiration time.
 *
 *              Also, if the SA is dynamic and a duplicate SA
 *              is received, it is updated, and no error is
 *              returned.  (if the SA is *not* dynamic, an
 *              error *is* returned.)
 *
 *		The entry will be locked upon return.
 *		The caller is responsible for unlocking the
 *		node when it is finished with it.
 *
 * Returns:	upon successful return, this function will
 *		return the Security Association Entry
 *		pointer, otherwise NULL.
 */
MipSecAssocEntry *
CreateSecAssocEntry(boolean_t isDynamic, uint32_t SPI, int ReplayProtection,
    int AlgorithmType, int AlgorithmMode, int keyLength, char *key,
    int lifetime)
{
	MipSecAssocEntry *entry = NULL;
	time_t currentTime;
	boolean_t alreadyInserted = _B_FALSE;

	/*
	 * First, let's make sure that we do not already have
	 * this SPI defined.
	 */
	if ((entry = findHashTableEntryUint(&mipSecAssocHash, SPI,
	    LOCK_WRITE, NULL, 0, 0, 0)) != NULL) {
		if (isDynamic == _B_FALSE) {
			syslog(LOG_ERR, "Duplicate SPI entry requested %d",
			    SPI);
			(void) rw_unlock(&entry->mipSecNodeLock);
			return (NULL);
		} else {
			alreadyInserted = _B_TRUE;
			(void) fprintf(stderr, "Updating SPI %d\n", SPI);
		}
	}

	/* Entry is set if dynamic and already found */
	if (!entry) {
		entry = (MipSecAssocEntry *)calloc(1,
		    sizeof (MipSecAssocEntry));
		if (!entry) {
			syslog(LOG_CRIT,
			    "FATAL: Unable to allocate Sec Assoc Entry");
			return (NULL);
		}
	}

	entry->mipSecSPI = SPI;
	entry->mipSecReplayMethod = ReplayProtection;
	entry->mipSecAlgorithmType = AlgorithmType;
	entry->mipSecAlgorithmMode = AlgorithmMode;
	entry->mipSecKeyLen = keyLength;
	entry->mipSecIsEntryDynamic = isDynamic;

	if (isDynamic) {
		/*
		 * Setup when the key expires...
		 */
		GET_TIME(currentTime);
		entry->mipSecKeyLifetime = currentTime + lifetime;
	} else {
		entry->mipSecKeyLifetime = TIME_INFINITY;
	}

	(void) memcpy(entry->mipSecKey, key, keyLength);

	/* If it is already in table, we already own it with the RWLOCK set */
	if (!alreadyInserted) {
		if (rwlock_init(&entry->mipSecNodeLock, USYNC_THREAD, NULL)) {
			syslog(LOG_ERR, "Unable to initialize "
			    "read/write lock");
			free(entry);
			return (NULL);
		}

		if (linkHashTableEntryUint(&mipSecAssocHash, SPI,
		    entry, LOCK_WRITE)) {
			syslog(LOG_ERR, "Unable to add Security "
			    "Assoc. entry to hash tabl");
			(void) rwlock_destroy(&entry->mipSecNodeLock);
			free(entry);
			return (NULL);
		}
	}
	return (entry);
}

/*
 * Function: CreateInterfaceEntry
 *
 * Arguments:	dev - A pointer to the device name
 *		regLifetime - The maximum registration lifetime that
 *			are willing to accept.
 *		advertiseOnBcast - Whether we will advertise on the
 *			broadcast address.
 *		minInterval - The minimum interval between adv.
 *		maxInterval - The maximum interval between adv.
 *		advLifetime - The maximum advertisement lifetime
 *			lifetime that we will advertise on this
 *			interface.
 *		advSeqNum - The sequence number that we will
 *			initially advertise.
 *		servicesFlags - The flags that we will advertise
 *			on the interface.
 *		prefixFlags - determines whether we will advertise
 *			the prefix length extension.
 *		reverseTunnelAllowed - are we going to allow MN's to
 *			request the reverse tunnel, and thereby send
 *			FA_REVERSE_TUNNEL_UNAVAILABLE errors to MN's
 *			requesting a reverse tunnel?  Note, this is set to
 *			RT_NONE, RT_FA, RT_HA, or RT_BOTH depending on which
 *			of our agents is allowing the reverse tunnel.
 *		reverseTunnelRequired - are we going to require MN's to
 *			request the reverse tunnel, and thereby send
 *			FA_REVERSE_TUNNEL_REQUIRED errors to MN's not
 *			requesting a reverse tunnel?  Note, this is set to
 *			RT_NONE, RT_FA, RT_HA, or RT_BOTH depending on which
 *			of our agents is requiring the reverse tunnel.
 *		advInterval - Advertisement interval for this interface
 *
 * Description: This function will create an interface entry,
 *		and will add it to the hash table. We will
 *		directly retrieve the interface's IP address and
 *		MAC address.
 *
 * Returns: int, 0 if successful.
 *
 * Comment:	This function takes too many arguments. If this function
 *		ever needs a major change, passing a structure with all
 *		arguments should be considered.
 *
 */
int
CreateInterfaceEntry(char *dev, int regLifetime, boolean_t advertiseOnBcast,
    int minInterval, int maxInterval, int advLifetime, uint16_t advSeqNum,
    int servicesFlags, boolean_t prefixFlags, uint8_t reverseTunnelAllowed,
    uint8_t reverseTunnelRequired, boolean_t advLimitUnsolicited, uint8_t
    advInitCount, uint32_t advInterval, boolean_t isDynamic)
{
	MaAdvConfigEntry *entry;
	char *cp;

	/* If a virtual network interface is specified, warn the user */
	if (dev != NULL) {
		if ((strncmp(dev, VNI, VNISTRLEN) == 0)) {
			cp = dev + VNISTRLEN;
			cp += strspn(cp, "0123456789");
			if (*cp == '\0' || *cp == ':' || *cp == '*')
				syslog(LOG_WARNING, "%s specified. vni is a"
				    " virtual interface that does not transmit"
				    " or receive packets. See vni(7D)", dev);
		}
	}

	/* Let's check for dynamic interface entry */
	if (strchr(dev, '*') == NULL) {
		entry = (MaAdvConfigEntry *) calloc(1,
		    sizeof (MaAdvConfigEntry));
		if (entry == NULL) {
			syslog(LOG_CRIT, "FATAL: Unable to allocate "
			    "AdvConfigEntry");
			return (-2);
		}
	} else {
		int	len;
		DynamicIfaceTypeEntry	*dyn_entry;
		DynamicIfaceTypeEntry	*save_entry;

		/*
		 * Since devicename contains '*', it must be an entry
		 * for dynamic interface.For dynamic interface entry
		 * in the config file, we do not create entry in the
		 * MaAdvConfigEntry[], rather we keep a linked list
		 * of dynamic interface types. For each type of dynamic
		 * interface entry, the attributes will be common and
		 * saved in DynamicIfaceTypeEntry data structure.
		 * When mipagent detects one new interface that matches
		 * with the same type and that is not an exisisting one
		 * that went through down-up cycle, then it creates a new
		 * entry and attaches to the MaAdvConfigEntry list
		 */
		len = strlen(dev);
		if (len > 0 && dev[len - 1] != '*') {
			syslog(LOG_ERR,
			    "Invalid dynamic interface %s in mipagent.conf",
			    dev);
			return (-1);
		}
		/* Replace '*' with null character */
		dev[len -1] = '\0';
		mipverbose(("CreateInterfaceEntry: dynamic device %s\n",
		    dev));


		if (dynamicIfaceHead == NULL) {
			dynamicIfaceHead = (DynamicIfaceTypeEntry *) calloc(1,
			    sizeof (DynamicIfaceTypeEntry));
			dyn_entry = dynamicIfaceHead;
		} else {

			/* search if this type exists already */
			dyn_entry = dynamicIfaceHead;
			while (dyn_entry != NULL) {
				if (strcmp(dyn_entry->dynamicIfcetype, dev)
				    == 0) {
					mipverbose(("CreateInterfaceEntry:"
					    " Dynamic Entry already exists"
					    " %s\n", dev));
					return (0);
				}
				save_entry = dyn_entry;
				dyn_entry = dyn_entry->next;
			}

			dyn_entry = (DynamicIfaceTypeEntry *) calloc(1,
			    sizeof (DynamicIfaceTypeEntry));
			if (dyn_entry != NULL) {
				/* Link to the dynamicEntry list */
				save_entry->next = dyn_entry;
			}
		}

		/* Fill in the structure with the parameter values */
		(void) strncpy(dyn_entry->dynamicIfcetype, dev, LIFNAMSIZ);
		dyn_entry->AdvLimitUnsolicited = advLimitUnsolicited;
		dyn_entry->AdvInitCount = advInitCount;
		dyn_entry->AdvInterval = advInterval;
		dyn_entry->AdvServiceflag = servicesFlags;
		dyn_entry->AdvPrefixflag = prefixFlags;
		dyn_entry->RevtunReqd = reverseTunnelRequired;
		dyn_entry->RevtunAllowed = reverseTunnelAllowed;
		dyn_entry->RegLifetime = regLifetime;
		dyn_entry->AdvLifetime = advLifetime;
		dyn_entry->advertiseOnBcast = advertiseOnBcast;
		dyn_entry->next = NULL;

		/* Set the global variable DynamicInterface */
		DynamicInterface = _B_TRUE;
		return (0);
	} /* else dynamic entry */

	/* Now add our interface values */
	(void) strncpy(entry->maIfaceName, dev, (LIFNAMSIZ -1));

	/*
	 * Simplify the configuration effort, read IP address, netmask
	 * and hardware address directly from the interface.
	 */
	if (getIfaceInfo(entry->maIfaceName, &entry->maIfaceAddr,
	    &entry->maIfaceNetmask, &entry->maIfaceFlags,
	    &entry->maIfindex)) {
		free(entry);
		syslog(LOG_ERR, "Unable to get interface information: %m");
		return (-1);
	}

	/*
	 * Save the first address usable for registering with the
	 * SNMP master.
	 */
	if (subagent_addr != 0)
		subagent_addr = entry->maIfaceAddr;

	/*
	 * Don't attempt to get the hardware address if it's a point-to-point
	 * interface.
	 */
	if ((entry->maIfaceFlags & IFF_POINTOPOINT) == 0) {
		if (getEthernetAddr(entry->maIfaceName, entry->maIfaceHWaddr)) {
			syslog(LOG_ERR, "Unable to get interface address "
			    "information on %s (%s)", dev, strerror(errno));
			mipverbose(("Unable to get interface address "
			    "information on %s (%s)\n", dev, strerror(errno)));
			free(entry);
			return (-1);
		}
	}

	entry->maAdvMaxRegLifetime = regLifetime;

	/*
	 * TODO: Under Solaris, pkts for LINK_BCAST_ADDR seem to
	 * be sent on all of a host's interfaces. Don't know if this
	 * can be controlled using some options similar to
	 * IP_MULTICAST_IF.
	 */
	if (advertiseOnBcast == 1) {
		entry->maAdvAddr = inet_addr(LINK_BCAST_ADDR);
	} else {
		entry->maAdvAddr = inet_addr(LINK_MCAST_ADV_ADDR);
	}

	entry->maAdvMaxInterval = maxInterval;
	entry->maAdvMinInterval = minInterval;
	entry->maAdvMaxAdvLifetime = advLifetime;
	entry->maAdvSeqNum = advSeqNum;
	entry->maAdvServiceFlags = (char)servicesFlags;
	entry->maAdvPrefixLenInclusion = prefixFlags;
	entry->maReverseTunnelAllowed = reverseTunnelAllowed;
	entry->maReverseTunnelRequired = reverseTunnelRequired;
	entry->maAdvLimitUnsolicited = advLimitUnsolicited;
	if (advLimitUnsolicited == _B_FALSE)
		entry->maAdvInitCount = 1;
	else
		entry->maAdvInitCount = advInitCount;
	entry->maAdvInterval = advInterval;
	/* Set maNextAdvTime in getAndDispatchNetwork */
	entry->maNextAdvTime = LONG_MAX;
	/* The follwoing is always set false in this routine */
	entry->maAdvDynamicInterface = isDynamic;

	if (rwlock_init(&entry->maIfaceNodeLock, USYNC_THREAD, NULL)) {
		syslog(LOG_ERR, "Unable to initialize read/write lock");
		free(entry);
		return (NULL);
	}

	/*
	 * Ok, this is just a temp hack, but we need to save the
	 * local address of the interface. Otherwise we will need to
	 * configure the home agent for each Mobile Node, which is
	 * just too much config for everybody. Given that we really
	 * only work with one interface, this is not a big deal, but
	 * this DOES need to be cleaned up.
	 */
	haAddr = entry->maIfaceAddr;

	/*
	 * We do not request that the node be locked in this case since
	 * we do not need the pointer to be returned. We are just calling
	 * and ensuring that a pointer was in fact returned.
	 */
	if (linkHashTableEntryUint(&maAdvConfigHash, entry->maIfaceAddr, entry,
	    LOCK_NONE)) {
		syslog(LOG_ERR, "Unable to add interface entry to hash table");
		(void) rwlock_destroy(&entry->maIfaceNodeLock);
		free(entry);
		return (-1);
	}

	return (0);
}


/*
 * Function: CreateTunlEntry
 *
 * Arguments:	tnum - Tunnel number
 *		target - target address
 *		tunsrc - Tunnel source endpoint address
 *		muxfd -  file desc of the stream that is
 *                       associated with the tunnel.
 *
 * Description: This function will create a Tunnel
 *		entry, and will add it to the hash table.
 *
 * Returns:	upon successful return, this function will
 *		return the Tunnel Entry pointer, otherwise NULL.
 */

MipTunlEntry *
CreateTunlEntry(int tnum, ipaddr_t target, ipaddr_t tunsrc, int muxfd)
{
	MipTunlEntry *entry = NULL;

	/*
	 * First, let's make sure that we do not already have
	 * this target defined.
	 */
	if ((findHashTableEntryUint(&mipTunlHash, target,
	    LOCK_NONE, MipTunlEntryLookup, tunsrc, 0, 0)) != NULL) {
		syslog(LOG_ERR, "Duplicate target entry requested %x", target);
		return (NULL);
	}

	entry = (MipTunlEntry *)calloc(1, sizeof (MipTunlEntry));
	if (!entry) {
		syslog(LOG_CRIT, "FATAL: Unable to allocate Tunl Entry");
		return (NULL);
	}

	entry->tunnelno = tnum;
	entry->tunnelsrc = tunsrc;
	entry->mux_fd = muxfd;

	if (rwlock_init(&entry->TunlNodeLock, USYNC_THREAD, NULL)) {
		syslog(LOG_ERR, "Unable to initialize read/write lock");
		free(entry);
		return (NULL);
	}


	if (linkHashTableEntryUint(&mipTunlHash, target, entry, LOCK_WRITE)) {
	    syslog(LOG_ERR, "Unable to add Tunnel entry to hash table");
	    (void) rwlock_destroy(&entry->TunlNodeLock);
	    free(entry);
	    return (NULL);
	}

	return (entry);
}
