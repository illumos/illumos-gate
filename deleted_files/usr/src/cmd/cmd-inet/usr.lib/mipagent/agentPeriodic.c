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
 * Copyright 1999-2002 Sun Microsystems, Inc.
 * All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * file: agentPeriodic.c
 *
 * This file includes the routines that are periodically called
 * for agent advertisement and garbage collection of data structures
 * such as visitor entries, mobile node entries, security
 * assocations, etc.
 */

#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <assert.h>

#include "mip.h"
#include "agent.h"
#include "pool.h"
#include "agentKernelIntfce.h"
#include "conflib.h"
#include "mipagentstat_door.h"

static 	pthread_t periodicThreadId = 0;
/* global variables declared here */
boolean_t faBusy = _B_FALSE;
/*
 * if need to disable mobility service, set
 * advBusy so that agent advertisement B(usy)
 * Bit is set.  This informs MNs not to make
 * a registration request per RFC2002.
 */
boolean_t advBusy = _B_FALSE;

extern boolean_t faNAIadv;		/* Determines whether we advertise */
					/* our NAI */
extern boolean_t faChallengeAdv;	/* Determines whether we advertise */
					/* challenges */

/*
 * Common to all mobility agents
 */
extern struct hash_table maAdvConfigHash;

/* Counters common to all Mobility Agents */
extern CommonCounters commonCounters;

extern char maNai[MAX_NAI_LENGTH];

/* Foreign Agent specific data structures. */

extern struct hash_table faVisitorHash;

/* Counters maintained by Foreign Agents */
extern ForeignAgentCounters faCounters;

/* The last two challenges advertised */
extern char faLastChallengeIssued[2][ADV_CHALLENGE_LENGTH];

/* Home Agent specific data structures. */
extern struct hash_table haMobileNodeHash;

/*
 * This table has one entry for each known Mobility Agent
 */
extern struct hash_table  mipAgentHash;

/*
 * This table stores all of the Security Associations
 */
extern HashTable mipSecAssocHash;

#ifdef FIREWALL_SUPPORT
extern DomainInfo domainInfo;
#endif /* FIREWALL_SUPPORT */

/* Other external declarations */
extern int  logVerbosity;
extern int  advLifetime;
extern int  periodicInterval;
extern AAA_Protocol_Code aaaProtocol;
extern unsigned short inChecksum(unsigned short *, int);
extern char *ntoa(uint32_t, char *);
extern void sendICMPmessage(int, ipaddr_t, unsigned char *, int);
extern char *err2str(int);
#ifdef FIREWALL_SUPPORT
extern boolean_t isOutsideProtectedDomain(uint32_t);
#endif /* FIREWALL_SUPPORT */
extern uint32_t getRandomValue();
extern int prefixLen(uint32_t);
extern int arpIfdel(ipaddr_t, char *, uint32_t);
extern int gettunnelno(ipaddr_t, ipaddr_t);
extern MobilityAgentEntry *findMaeFromIp(ipaddr_t, int);
extern int removeIPsecPolicy(char *);

#define	LOWEST_ROUTER_PRIORITY		0x80000000

static void doPeriodicTask();
void maSendAdvertisement(MaAdvConfigEntry *, ipaddr_t, int, boolean_t faBusy);

/*
 * Function: disableService
 *
 * Arguments:
 *
 *
 * Description: Function will set a flag to indicate
 *              that all agent advertisements on all
 *              interfaces will have the B(usy) Bit
 *              set.  In addition, the Agent Advertisement
 *              sequence number for all interfaces will
 *              be set to zero. This function is called
 *              to disable mobility service while keeping
 *              the mobility agent up and running.  NOTE: A
 *              corresponding function enableService()
 *              is called to reenable mobility service.
 *
 * Returns:
 */
void
disableService(struct hash_table *htbl)
{
	int index, nentry;
	MaAdvConfigEntry *entry;
	struct hash_entry *p;

	advBusy = _B_TRUE;
	for (index = 0, nentry = 0;
	    index < HASH_TBL_SIZE && (nentry < htbl->size); index++) {
		p = htbl->buckets[index];
		while (p) {
			nentry++;
			entry = (MaAdvConfigEntry *)p->data;
			entry->maAdvSeqNum = 0;
			p = p->next;
		}
	}
}

/*
 * Function: enableService
 *
 * Arguments:
 *
 * Description: Function will set a flag to indicate
 *              that all agent advertisements on all
 *              interfaces should not have the
 *              B(usy) bit set.
 *
 * Returns:
 */
void
enableService()
{
	advBusy = _B_FALSE;
}

/*
 * Function: maSendAdvertisement
 *
 * Arguments:	entry - Pointer to MaAdvConfigEntry
 *		dst   - Destination addr of the advertisement
 *		AdvType - Type of advertisement -solicited or
 *			  unsolicited
 *		faBusy - boolean dictating whether we are
 *			busy.
 *
 * Description: Prepare and send agent advertisement on
 *		specified interface.
 *
 * Returns:
 */
void
maSendAdvertisement(MaAdvConfigEntry *entry, ipaddr_t dst, int advType,
    boolean_t faBusy)
{
	int		j;
	static unsigned char advPkt[512];
	int		naiLength;
	uint32_t	randomValue;
	unsigned char	*randomValuePtr;
	int		len;
	icmph		*icmpPtr;
	ipaddr_t	*addrPtr;
	advExt		*advExtPtr;
	unsigned char	*cp;


	/* We don't do unsolicited adv if AdvInitCount = 0 */
	if (entry->maAdvInitCount == 0 && advType == UNSOLICITED_ADV) {
		mipverbose(("maSendAdvertisement: zero InitCount\n"));
		return;
	}


	/* Fill out the ICMP header for a router advertisement */

	/* LINTED BAD_PTR_CAST_ALIGN */
	icmpPtr = (icmph *) advPkt;
	icmpPtr->type = ICMP_ROUTERADVERT;
	icmpPtr->code = 16;
	icmpPtr->icmpAdvNumAddr = 0;
	icmpPtr->icmpAdvAddrEntrySize = 2;
	icmpPtr->icmpAdvLifetime = htons((uint16_t)advLifetime);

	/* create advertisement ... */
	len = sizeof (icmph);
	/* LINTED BAD_PTR_CAST_ALIGN */
	addrPtr = (uint32_t *)(advPkt + sizeof (icmph));

	/*
	 * ... fill (optional) addresses in the RFC 1256 portion
	 * we only fill out one address.
	 */
	icmpPtr->icmpAdvNumAddr = 1;
	icmpPtr->icmpAdvAddrEntrySize = 2;
	*addrPtr++ = htonl(entry->maIfaceAddr);
	len += sizeof (uint32_t);
	*addrPtr++ = htonl(LOWEST_ROUTER_PRIORITY);
	len += sizeof (uint32_t);

	/*
	 * ... fill out the mobility agent advertisement extension
	 * we only advertise one address
	 */
	/* LINTED BAD_PTR_CAST_ALIGN */
	advExtPtr = (advExt *) (advPkt + len);
	advExtPtr->type = ADV_EXT_TYPE;
	advExtPtr->length = 10;
	advExtPtr->seqNum = htons(entry->maAdvSeqNum);

	/*
	 * We set the advertisement sequence number. Note that this
	 * value wraps around at 255. This is used by Mobile Nodes
	 * to determine whether the Foreign Agent has rebooted.
	 */
	if (++entry->maAdvSeqNum == 0)
		entry->maAdvSeqNum = 256;
	advExtPtr->regLifetime = htons(entry->maAdvMaxRegLifetime);
	advExtPtr->advFlags = entry->maAdvServiceFlags;

	/* set the busy bit, if appropriate */
	if ((advBusy) || (faBusy && (advExtPtr->advFlags &
	    ADV_IS_FOREIGN_AGENT))) {
		faCounters.faIsBusyCnt++;
		advExtPtr->advFlags |= ADV_IS_BUSY;
	}

	advExtPtr->reserved = 0;
	len += sizeof (advExt);

	/* fill out the advertised care-of address */
	/* LINTED BAD_PTR_CAST_ALIGN */
	addrPtr = (uint32_t *)(advPkt + len);
	*addrPtr++ = htonl(entry->maIfaceAddr);
	len += sizeof (uint32_t);

	/*
	 * We only advertise our NAI if we were
	 * configured to do so.
	 */
	if (faNAIadv == _B_TRUE) {
		/* Add the Mobility Agent NAI */
		naiLength = strlen(maNai);
		cp = advPkt + len;
		*cp++ = ADV_AGENT_NAI_EXT_TYPE;
		*cp++ = (uchar_t)naiLength;
		len += 2;
		(void) strncpy((char *)cp, maNai, naiLength);
		len += naiLength;
	}

	/*
	 * We only advertise challenges
	 * if we were configured to do so.
	 */
	if (faChallengeAdv == _B_TRUE) {
		if (advType == UNSOLICITED_ADV) {

			/* Add the Foreign Agent Challenge Value */
			cp = advPkt + len;
			*cp++ = ADV_CHALLENGE_EXT_TYPE;
			*cp++ = ADV_CHALLENGE_LENGTH;
			len += 2;

			/*
			 * Save the last Challenge issued
			 */
			(void) memcpy(faLastChallengeIssued[1],
			    faLastChallengeIssued[0],
			    ADV_CHALLENGE_LENGTH);

			randomValuePtr = cp;

			/* We want a 16 octet (128 bit) challenge */
			for (j = 0; j < ADV_CHALLENGE_LENGTH; j += 4) {
				randomValue = getRandomValue();
				(void) strncpy((char *)cp, (char *)&randomValue,
					sizeof (randomValue));
				len += sizeof (randomValue);
				cp += sizeof (randomValue);
			}

			/* We want a 16 octet (128 bit) challenge */
			/*
			 * Save the New Challenge issued
			 */
			(void) memcpy(faLastChallengeIssued[0], randomValuePtr,
			    ADV_CHALLENGE_LENGTH);
		} else  if (advType == SOLICITED_ADV) {

			/* Add the Foreign Agent Challenge Value */
			cp = advPkt + len;
			*cp++ = ADV_CHALLENGE_EXT_TYPE;
			*cp++ = ADV_CHALLENGE_LENGTH;
			len += 2;
			/* We use the last advertised challenge */
			(void) memcpy(cp, faLastChallengeIssued[0],
			    ADV_CHALLENGE_LENGTH);
			len += ADV_CHALLENGE_LENGTH;
			cp += ADV_CHALLENGE_LENGTH;
		}
	}

	/* fill out prefix length extension, if required */
	if ((entry->maAdvPrefixLenInclusion == _B_TRUE) &&
		icmpPtr->icmpAdvNumAddr) {
	    cp = advPkt + len;
	    *cp++ = ADV_PREFIX_EXT_TYPE;
	    *cp++ = icmpPtr->icmpAdvNumAddr;
	    len += 2;
	    /* fill out prefix len for each addr in RFC1256 portion */
	    for (j = 0; j < icmpPtr->icmpAdvNumAddr; j++) {
		*cp++ = prefixLen(entry->maIfaceNetmask);
		len++;
	    }
	}

	/* pad ICMP message to even length, if required */
	if (len % 2) {
		*cp++ = ADV_PADDING_EXT_TYPE;
		len++;
	}

	/* fill out ICMP checksum */
	icmpPtr->checksum = 0;
	icmpPtr->checksum = inChecksum((unsigned short *) icmpPtr, len);

	/* ship it! */
	commonCounters.maAdvSentCnt++;

	/*
	 * IP_XMIT_IF  or IP_MULTICAST_IF are set on this socket
	 * during initiation time in InitSockets().
	 */
	sendICMPmessage(entry->maIfaceIcmpSock, dst, advPkt, len);


	/*
	 * Now update maAdvInitCount for limited unsolicited advertisement
	 * case. Note, we need to update this value to make sure that
	 * we don't send unsolicited advertisements beyond maAdvInitCount
	 * value specified in the mipagent.conf file.
	 * I am updating this value, otherwise we need to keep another
	 * data structure for each dynamic interface, which can grow large
	 * with the number of interfaces. Besides, there is no reason I find
	 * at present, to preserve it's initial value.
	 */
	if (entry->maAdvLimitUnsolicited && entry->maAdvInitCount > 0) {
		/* update maAdvInitCount */
		entry->maAdvInitCount--;
		mipverbose(("maSendAdvertisement: updating maAdvInitCount "
		    " to %d\n", entry->maAdvInitCount));
	}

	/*
	 * Note that the mipverbose format is different here.
	 * We want to just print the interface index with each
	 * advertisement.
	 */
	mipverbose(("+[%d]", entry->maIfindex));
}


/*
 * Function: delHABEent
 *
 * Arguments:	mnePtr - Pointer to a Mobile Node Entry
 *		entry - Pointer to a Binding Entry
 *
 * Description: This function will delete a binding entry.
 *		If a Home Address was assigned to the Mobile
 *		Node via a local pool, and the number of
 *		bindings is set to zero (0), we will free
 *		the Home Address.
 *
 *		Note that the caller MUST have locked the
 *		Mobile Node Entry prior to calling this
 *		function.
 *
 * Returns:
 */
void
delHABEent(HaMobileNodeEntry *mnePtr, HaBindingEntry *entry)
{
	ipaddr_t mnAddr, coAddr;
	char addrstr1[INET_ADDRSTRLEN];
	char addrstr2[INET_ADDRSTRLEN];
	int val;
	time_t localTime;
	time_t sessionLifeTime;
	int result;

	mnAddr = entry->haBindingMN;
	coAddr = entry->haBindingCOA;

	/*
	 * Disable encapsulation to this coaddr. Decrease
	 * binding count for MN. If zero, cancel proxy ARP & route
	 */

#ifdef FIREWALL_SUPPORT
	/*
	 * If the care-of-address was outside protected domain remove
	 * the encapsulation through the firewall's internal address.
	 * TODO: This works only if we assume that a single external
	 * COAddr is never shared by multiple mobile nodes. For now,
	 * that's always the case.
	 */
	if (isOutsideProtectedDomain(coAddr)) {
	    mipverbose(("Removing tunnel for %s through FW %s\n",
		ntoa(coAddr, addrstr1),
		ntoa(domainInfo.fwAddr[0], addrstr2)));
	    if ((val = encaprem(coAddr)) < 0) {
		syslog(LOG_ERR, "encaprem failed ... %s", err2str(val));
	    }
	}
#endif /* FIREWALL_SUPPORT */

	/*
	 * Terminate encapsulation and decapsulation of MN's
	 * packets to COA. For now, this also handles reverse
	 * tunneling
	 */
	mipverbose(("Removing tunnel for %s through %s\n",
	    ntoa(mnAddr, addrstr1), ntoa(coAddr, addrstr2)));

	if ((val = encaprem(mnAddr)) < 0) {
	    syslog(LOG_ERR, "encaprem failed ... %s", err2str(val));
	}

	/* if encaprem() returned 0, there are no more MNs using this tunnel */
	if (val == 0) {
		/* kill off any ipsec SA we have with this agent-peer */
		MobilityAgentEntry *mae;

		/* note: this should work for colocated MNs too! */
		if ((mae = findMaeFromIp(coAddr, LOCK_READ)) != NULL) {
			/*
			 * We're the HA, so we look for IPSEC_REPLY_APPLY to
			 * remove.  NOTE: we NEVER remove IPSEC_REQUEST_PERMIT,
			 * (unless shutting down), as these come unannounced.
			 * See agentInit.c: deleteIPsecSAHashHelper()
			 */
			if (mae->maIPsecFlags & IPSEC_REPLY_APPLY) {
				/* off it */
				if (removeIPsecPolicy(
				    mae->maIPsecReply[IPSEC_APPLY]) < 0) {
					/* whine about it */
					char peerAddr[IPv4_ADDR_LEN];

					(void) ntoa(coAddr, peerAddr);
					syslog(LOG_CRIT, "Could not remove %s"
					    "ipsec regisration reply apply.",
					    peerAddr);
				} else
					/* it's gone, unset the flag bit */
					mae->maIPsecFlags &=
					    ~IPSEC_REPLY_APPLY;
			}

			/* The tunnels are down, so just unset those bits */
			mae->maIPsecFlags &= ~IPSEC_TUNNEL_APPLY;
			mae->maIPsecFlags &= ~IPSEC_REVERSE_TUNNEL_PERMIT;

			/* more importantly, this is no longer an agent peer */
			mae->maPeerFlags &= ~FA_PEER;

			/* unlock */
			(void) rw_unlock(&mae->maNodeLock);
		}
	}

	if (--mnePtr->haMnBindingCnt == 0) {

		/*
		 * Notify AAA server that the MN is going away.
		 */
		if ((aaaProtocol == RADIUS || aaaProtocol == DIAMETER)) {
			GET_TIME(localTime);
			sessionLifeTime =  localTime -
			    entry->haBindingTimeGranted;
			result = sendAccountingRecord(
			    MOBILE_IP_ACCOUNTING_STOP_REQUEST,
			    (unsigned char *)mnePtr->haMnNAI,
			    mnePtr->haMnNAILen, mnAddr, coAddr,
			    entry->haBindingHaAddr,
			    sessionLifeTime, MN_DEREGISTERED);
			if (result) {
				syslog(LOG_ERR, "Unable to send accounting "
				    "stop record");
			}
		}

		mipverbose(("Terminating arp service for %s\n",
		    ntoa(mnAddr, addrstr1)));

		/*
		 * TODO:
		 * Solaris gets confused if it has two ARP entries
		 * for the same host on different interfaces. This
		 * needs further looking into(at least it tries to
		 * keep a separate ARP table for each interface).
		 */
		mipverbose(("Removing proxy ARP entry for %s\n",
		    ntoa(mnAddr, addrstr1)));
		if ((val = arpdel(mnAddr)) < 0) {
			syslog(LOG_ERR, "arpdel failed ... %s", err2str(val));
		}

		/*
		 * Do we have an assigned Home Address that we need
		 * to free?
		 */
		if (mnePtr->haPoolIdentifier && mnePtr->haMnAddr) {
			if (freeAddressFromPool(mnePtr->haPoolIdentifier,
			    mnePtr->haMnAddr) != _B_TRUE) {
				syslog(LOG_ERR,
				    "Unable to free address from pool %d",
				    mnePtr->haPoolIdentifier);
			}
			mnePtr->haMnAddr = 0;
		}
	}

	mipverbose((
		"HA binding removed for %s@%s at entry %p (Binding Cnt %d).\n",
		ntoa(mnAddr, addrstr1), ntoa(coAddr, addrstr2), (void *)entry,
		mnePtr->haMnBindingCnt));
}


/*
 * Function: delFAVEptr
 *
 * Arguments:	entry - Foreign Agent Visitor Entry
 *		sendASR - whether to send Accounting Stop Request
 *
 * Description: This function will delete a Foreign Agent's
 *		Visitor entry. If the visitor entry was in
 *		the ACCEPTED state (meaning that service was
 *		provided to the Mobile Node), we must remove
 *		the route, delete the tunnel interface and
 *		the MN's ARP entry.
 *
 *		Note that the caller MUST have locked the
 *		Mobile Node Entry prior to calling this
 *		function.
 *
 * Returns:
 */
void
delFAVEptr(FaVisitorEntry *entry, boolean_t sendASR, uint32_t releaseindicator)
{
	int val;
	int tun_num;
	int in_index;
	char tun_name[LIFNAMSIZ];
	char addrstr1[INET_ADDRSTRLEN];
	char addrstr2[INET_ADDRSTRLEN];
	int result;
	time_t localTime;
	time_t sessionLifeTime;


#if 0
	/*
	 * Of course, this causes us a heart ache if we are called from
	 * an interrupt handler, since we will not be locking
	 */

	/*
	 * Let's just make sure that the caller did indeed
	 * lock the visitor entry...
	 */
	if (rw_trywrlock(&entry->nodeLock) == 0) {
		assert(0);
	}

#endif

	mipverbose(("FA expired %s visitor entry for %s\n",
	    (entry->faVisitorRegIsAccepted ?
		"accepted" : "pending"),
	    ntoa(entry->faVisitorHomeAddr, addrstr1)));

	/* For accepted requests, kill route and disable decapsulation. */

	if (entry->faVisitorRegIsAccepted == _B_TRUE) {

		tun_num = gettunnelno(entry->faVisitorHomeAgentAddr,
		    entry->faVisitorIfaceAddr);
		if (tun_num < 0) {
			syslog(LOG_ERR, "gettunnelno returns -1");
			return;
		}
		(void) snprintf(tun_name, sizeof (tun_name), "ip.tun%d",
		    tun_num);
		in_index = if_nametoindex(tun_name);
		if (in_index == 0) {
			/* if_nametoindex fails... */
			syslog(LOG_ERR, "if_nametoindex failed for tunnel %s",
			    tun_name);
		}
		mipverbose((
		    "Removing direct, local route for visitor %s thru %s\n",
		    ntoa(entry->faVisitorHomeAddr, addrstr1),
		    ntoa(entry->faVisitorIfaceAddr, addrstr2)));

		if ((val = routedel(entry->faVisitorHomeAddr,
			entry->faVisitorIfaceAddr, 0, in_index,
			entry->faVisitorInIfindex)) < 0) {
			syslog(LOG_ERR,
				"routedel failed ...for visitor %s: %s\n",
			    ntoa(entry->faVisitorHomeAddr, addrstr1),
			    err2str(val));
		}

		if (entry->faVisitorRegFlags & REG_REVERSE_TUNNEL) {

			/* delete Reverse Tunnel route */
			mipverbose((
			    "Removing Reverse tunnel route for visitor %s at"
			    " interface index %d\n",
			    ntoa(entry->faVisitorHomeAddr, addrstr2),
			    entry->faVisitorInIfindex));

			if ((val = routedel(0, 0,
			    entry->faVisitorHomeAddr,
			    entry->faVisitorInIfindex,
			    in_index)) < 0) {
				syslog(LOG_ERR,
				    "Reverse Tunnel route delete failed: %s:"
				    " for visitor %s at interface index %d",
				    err2str(val),
				    ntoa(entry->faVisitorHomeAddr, addrstr1),
				    entry->faVisitorInIfindex);
			}
		}
		/*
		 * Notify AAA server that the MN is going away.
		 * In the case we are here because of a Close Session Request
		 * received from AAA, AAA already knows it should stop
		 * accounting.
		 */
		if ((aaaProtocol == RADIUS || aaaProtocol == DIAMETER) &&
		    (sendASR == _B_TRUE)) {
			GET_TIME(localTime);
			sessionLifeTime =  localTime -
			    entry->faVisitorTimeGranted;
			result = sendAccountingRecord(
			    MOBILE_IP_ACCOUNTING_STOP_REQUEST,
			    (unsigned char *)entry->faVisitorMnNAI,
			    entry->faVisitorMnNAILen,
			    entry->faVisitorHomeAddr,
			    entry->faVisitorCOAddr,
			    entry->faVisitorHomeAgentAddr,
			    sessionLifeTime, releaseindicator);
			if (result) {
				syslog(LOG_ERR, "Unable to send accounting "
				    "stop record");
			}
		}
		/*
		 * TODO: this behavior is incorrect if multiple coaddrs can be
		 * registered for a mobile node at a FA. Decaprem should occur
		 * ONLY after a mobile node has NO accepted registrations.
		 */
		mipverbose((
			"Disabling decapsulation of inner pkts sent to %s\n",
			ntoa(entry->faVisitorHomeAddr, addrstr1)));
		if ((val = decaprem(entry->faVisitorHomeAgentAddr,
		    entry->faVisitorIfaceAddr)) < 0) {
			syslog(LOG_ERR, "decaprem failed: %s", err2str(val));
		}

		/* if decaprem() returns 0 there are no MNs using the tunnel */
		if (val == 0) {
			/* kill any tunnel ipsec SAs we have with this peer */
			MobilityAgentEntry *mae;

			if ((mae =
			    findMaeFromIp(entry->faVisitorHomeAgentAddr,
			    LOCK_READ)) != NULL) {
				/*
				 * We're the FA, so we look for
				 * IPSEC_REPLY_PERMIT, and
				 * IPSEC_REQUEST_APPLY policies.
				 */
				if (mae->maIPsecFlags & IPSEC_REPLY_PERMIT) {
					/* off it */
					if (removeIPsecPolicy(
					    mae->maIPsecReply[IPSEC_PERMIT])
					    < 0) {
						/* whine about it */
						char peerAddr[IPv4_ADDR_LEN];
						(void) ntoa(entry->
						    faVisitorHomeAgentAddr,
						    peerAddr);
						syslog(LOG_CRIT,
						    "Could not remove %s's "
						    "ipsec reply permit.",
						    peerAddr);
					} else
						/* unset the flag bit */
						mae->maIPsecFlags &=
						    ~IPSEC_REPLY_PERMIT;
				}

				/*
				 * The tunnel policy itself is 'freed'
				 * when the tunnel is unplumbed, but
				 * we need to unset the flag bits.
				 *
				 * We don't care if *this* MN's got a reverse
				 * tunnel, but if *any* happenned to get one.
				 */
				mae->maIPsecFlags &= ~IPSEC_TUNNEL_PERMIT;
				mae->maIPsecFlags &=
				    ~IPSEC_REVERSE_TUNNEL_APPLY;

				/* this is no longer an agent peer */
				mae->maPeerFlags &= ~HA_PEER;

				/* unlock */
				(void) rw_unlock(&mae->maNodeLock);
			}
		}

		/*
		 * If the  entry is accepted we should have set up an ARP
		 * cache entry (marked with the permanent flag). Since this
		 * is the common entry point to deleting the FAVE, we delete
		 * the ARP entry here too. The other deletions are done in
		 * the registration request and reply processing code on the
		 * FA side. The ARP cache entry was set up to prevent the FA
		 * from broadcast ARPing. PVTODO: May need some special
		 * handling for 2 hosts with same addr (private overlapping
		 * address) on the same interface index, eg: specify link
		 * layer address here too. May need to modify ARP to delete
		 * based on ether addr too.
		 */
		if (entry->faVisitorIsSllaValid &&
		    ((val = arpIfdel(entry->faVisitorHomeAddr,
		    entry->faVisitorSlla.sdl_data,
		    entry->faVisitorInIfindex)) < 0)) {
			/*
			 * If deletion failed bcos there was'nt an entry
			 * mipagent need not report it
			 */
			if (val != (-1)*ENXIO)
				syslog(LOG_ERR, "arpIfdel failed ...%s\n",
				    err2str(val));
		}
	}
}


/*
 * Function: haAgeBindingsHashHelper
 *
 * Arguments:	entry - Pointer to Mobile Node Entry
 *		p1 - First parameter to match (current time)
 *
 * Description: This function is used as the Hash Table Helper routine
 *		for haAgeBinding() when looking for binding entries
 *		in the Hash Table that have expired, and will be
 *		called by getAllHashTableEntries().
 *
 * Returns:	_B_TRUE if the entry matches the desired criteria,
 *		otherwise _B_FALSE.
 */
static boolean_t
haAgeBindingsHashHelper(void *entry, uint32_t p1)
{
	HaMobileNodeEntry *hentry = entry;
	HaBindingEntry *bindingEntry;
	HaBindingEntry *prev_entry = NULL;
	HaBindingEntry *next_entry;

	bindingEntry = hentry->bindingEntries;
	while (bindingEntry) {
		next_entry = bindingEntry->next;
		if (bindingEntry->haBindingTimeExpires > p1) {
			/*
			 * We want to keep this one, so setup the pointer.
			 */
			prev_entry = bindingEntry;
		} else {
			if (prev_entry) {
			    prev_entry->next = bindingEntry->next;
			} else {
			    hentry->bindingEntries = bindingEntry->next;
			}
			delHABEent(hentry, bindingEntry);
			free(bindingEntry);
		}
		bindingEntry = next_entry;
	}

	/*
	 * We need to delete the Mobile Node Entry if the
	 * entry was dynamic and has no more bindings.
	 */
	if (hentry->haMnBindingCnt == 0 &&
	    hentry->haMnIsEntryDynamic == TRUE) {
		(void) rw_unlock(&hentry->haMnNodeLock);
		(void) rwlock_destroy(&hentry->haMnNodeLock);
		free(hentry);

		/*
		 * Returning _B_FALSE here informs the caller that
		 * the entry was freed.
		 */
		return (_B_FALSE);
	}
	return (_B_TRUE);
}

/*
 * Function: haAgeBindings
 *
 * Arguments:	htbl - Pointer to Hash Table
 *		currentTime - The current Time (absolute)
 *
 * Description: This function will step through each
 *		Mobile Node's Binding Entries and will
 *		delete expired entries.
 *
 *		If the Mobile Node Entry is marked as a
 *		DYNAMIC entry, and the number of binding
 *		entries is set to zero (0), we will free
 *		the Mobile Node Entry as well.
 *
 * Returns:
 */
static void
haAgeBindings(struct hash_table *htbl, time_t currentTime)
{
	getAllHashTableEntries(htbl, haAgeBindingsHashHelper, LOCK_WRITE,
	    currentTime, _B_FALSE);
}


/*
 * Function: faAgeVisitorsHashHelper
 *
 * Arguments:	entry - Pointer to Mobile Node Entry
 *		p1 - First parameter to match (current time)
 *
 * Description: This function is used as the Hash Table Helper routine
 *		for faAgeVisitors() when looking for visitor entries
 *		in the Hash Table that have expired, and will be
 *		called by getAllHashTableEntries().
 *
 * Returns:	_B_TRUE if the entry matches the desired criteria,
 *		otherwise _B_FALSE.
 */
static boolean_t
faAgeVisitorsHashHelper(void *entry, uint32_t p1)
{
	FaVisitorEntry *faEntry = entry;

	if (faEntry->faVisitorTimeExpires <= p1) {
		(void) fprintf(stderr, "Deleting visitor entry!!\n");
		/* Expired */
		delFAVEptr(faEntry, _B_TRUE, REG_EXPIRED);
		(void) rw_unlock(&faEntry->faVisitorNodeLock);
		(void) rwlock_destroy(&faEntry->faVisitorNodeLock);
		free(faEntry);
		return (_B_FALSE);
	}

	return (_B_TRUE);
}

/*
 * Function: faAgeVisitors
 *
 * Arguments:	htbl - Pointer to Hash Table
 *		currentTime - The current Time (absolute)
 *
 * Description: This function will step through each
 *		Foreign Agent Visitor Entries and will
 *		delete expired entries.
 *
 * Returns:
 */
static void
faAgeVisitors(struct hash_table *htbl, time_t currentTime)
{
	getAllHashTableEntries(htbl, faAgeVisitorsHashHelper, LOCK_WRITE,
	    currentTime, _B_FALSE);
}


/*
 * Function: mipAgeSecAssocHashHelper
 *
 * Arguments:	entry - Pointer to Mobile Node Entry
 *		p1 - First parameter to match (current time)
 *
 * Description: This function is used as the Hash Table Helper routine
 *		for mipAgeSecAssoc() when looking for visitor entries
 *		in the Hash Table that have expired, and will be
 *		called by getAllHashTableEntries().
 *
 * Returns:	_B_TRUE if the entry matches the desired criteria,
 *		otherwise _B_FALSE.
 */
static boolean_t
mipAgeSecAssocHashHelper(void *entry, uint32_t p1)
{
	MipSecAssocEntry *saEntry = entry;

	if (saEntry->mipSecIsEntryDynamic == TRUE &&
	    saEntry->mipSecKeyLifetime <= p1) {
		(void) fprintf(stderr,
		    "Deleting Security Assocation entry!!\n");
		/* Expired */
		(void) rw_unlock(&saEntry->mipSecNodeLock);
		(void) rwlock_destroy(&saEntry->mipSecNodeLock);
		free(saEntry);
		return (_B_FALSE);
	}

	return (_B_TRUE);
}

/*
 * Function: mipAgeSecAssoc
 *
 * Arguments:	htbl - Pointer to Hash Table
 *		currentTime - The current Time (absolute)
 *
 * Description: This function will step through each
 *		Security Association Entries and will
 *		delete the SAs marked as DYNAMIC that
 *		have expired.
 *
 * Returns:
 */
static void
mipAgeSecAssoc(struct hash_table *htbl, time_t currentTime)
{
	getAllHashTableEntries(htbl, mipAgeSecAssocHashHelper,
	    LOCK_WRITE, currentTime, _B_FALSE);
}

/*
 * Function: mipAgeMobilityAgentsHashHelper
 *
 * Arguments:	entry - Pointer to Mobile Node Entry
 *		p1 - First parameter to match (current time)
 *
 * Description: This function is used as the Hash Table Helper routine
 *		for mipAgeMobilityAgents() when looking for visitor entries
 *		in the Hash Table that have expired, and will be
 *		called by getAllHashTableEntries().
 *
 * Returns:	_B_TRUE if the entry matches the desired criteria,
 *		otherwise _B_FALSE.
 */
static boolean_t
mipAgeMobilityAgentsHashHelper(void *entry, uint32_t p1)
{
	MobilityAgentEntry *maEntry = entry;

	if (maEntry->maIsEntryDynamic == TRUE &&
	    maEntry->maExpiration <= p1) {
		(void) fprintf(stderr, "Deleting Mobility Agent entry!!\n");
		/* Expired */
		(void) rw_unlock(&maEntry->maNodeLock);
		(void) rwlock_destroy(&maEntry->maNodeLock);
		free(maEntry);
		return (_B_FALSE);
	}

	return (_B_TRUE);
}

/*
 * Function: mipAgeMobilityAgents
 *
 * Arguments:	htbl - Pointer to Hash Table
 *		currentTime - The current Time (absolute)
 *
 * Description: This function will step through each
 *		Mobility Agent Entries and will
 *		delete the ones marked as DYNAMIC that
 *		have expired.
 *
 * Returns:
 */
static void
mipAgeMobilityAgents(struct hash_table *htbl, time_t currentTime)
{
	getAllHashTableEntries(htbl, mipAgeMobilityAgentsHashHelper,
	    LOCK_WRITE, currentTime, _B_FALSE);
}

/*
 * Function: startPeriodicTaskThread
 *
 * Arguments:
 *
 * Description: This function is called to start the
 *		periodic task handling thread.
 *
 * Returns: int, 0 if successful.
 */
int
startPeriodicTaskThread(void)
{
	pthread_attr_t pthreadAttribute;
	int result;

	result = pthread_attr_init(&pthreadAttribute);

	if (result) {
		syslog(LOG_CRIT, "Error Initializing pthread.");
		return (-1);
	}

	/*
	 * We now create a thread to deal with all periodic task.
	 */
	result = pthread_create(&periodicThreadId, &pthreadAttribute,
	    (void *(*)()) doPeriodicTask,
	    (void *)NULL);

	if (result) {
		syslog(LOG_CRIT, "pthread_create() failed.");
		return (-1);
	}

	/*
	 * In order for system resources the be properly cleaned up,
	 * we need to detach the thread. Otherwise, we need to wait for
	 * a pthread_join(), which we do not want.
	 */
	result = pthread_detach(periodicThreadId);

	if (result) {
		syslog(LOG_CRIT, "pthread_detach() failed.");
		return (-1);
	}

	return (0);
}

/*
 * Function: killPeriodicTaskThread
 *
 * Arguments:
 *
 * Description: This function is called during the agent
 *		shutdown procedure in order to kill the
 *		periodic task handling thread.
 *
 * Returns:
 */
int
killPeriodicTaskThread()
{
	int result;

	if (periodicThreadId) {
		/*
		 * Next we need to kill the dispatching thread.
		 */
		result = pthread_cancel(periodicThreadId);

		if (result) {
			/*
			 * Well, there's not much we can do here..
			 */
			syslog(LOG_CRIT, "Unable to kill periodic thread");
			return (-1);
		}
	}
	return (0);

}

/*
 * Function: doPeriodicTask
 *
 * Arguments: void
 *
 * Description: This function is called by a thread
 *		and will periodically call the functions
 *		that free any expired control blocks, such
 *		as visitor entries, bindings, etc.
 *
 *		The frequency that these clean up tasks
 *		get called is configurable through the
 *		configuration file, but this feature is
 *		undocumented.
 *
 *		This function never returns, but will be
 *		killed if the master thread calls
 *		killPeriodicTaskThread()
 *
 * Returns: never!
 */
static void
doPeriodicTask(void)
{
	struct timeval tv;
	time_t nextPeriodicTime = 0;
	time_t currentTime;

	/* CONSTCOND */
	while (_B_TRUE) {
		GET_TIME(currentTime);

		if (currentTime < nextPeriodicTime) {
			tv.tv_sec = nextPeriodicTime - currentTime;
			tv.tv_usec = 0;
			(void) select(FD_SETSIZE, NULL, NULL, NULL, &tv);
			GET_TIME(currentTime);
		}

		if (currentTime >= nextPeriodicTime) {
			haAgeBindings(&haMobileNodeHash, currentTime);
			faAgeVisitors(&faVisitorHash, currentTime);
			(void) mipAgeSecAssoc(&mipSecAssocHash, currentTime);
			mipAgeMobilityAgents(&mipAgentHash, currentTime);
			nextPeriodicTime = currentTime + periodicInterval;
			mipverbose(("*"));
			(void) fflush(stdout);
		}
	}
}
