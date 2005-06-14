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
 * Copyright 1999-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * file: agentNet.c
 *
 * This file contains all routines used to interact with the
 * network, such as reading and writing.
 *
 * This file also contains the event dispatcher, which submits
 * packets for processing to a pool of threads.
 */

#include <stdio.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/fcntl.h>
#include <sys/poll.h>
#include <sys/sockio.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <net/route.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <syslog.h>
#include <assert.h>
#include <ctype.h>
#include <fcntl.h>

#include "mip.h"
#include "agent.h"
#include "thq.h"
#include "setup.h"
#include "agentKernelIntfce.h"

#define	MIN_IP_HDR_LEN		20
#define	INFTIM			-1

/*
 * The following is the max number of Message Headers we will
 * allocate in a single chunk. The bigger the value, the more
 * memory we allocate, the smaller, the more often we malloc().
 */
#define	MAX_MSG_HDR_NUM		512

#define	MIP_MAX_THREADS		64
#define	MIP_MIN_THREADS		4


static char *ifTypeName[] = {
	"Unicast",
	"Broadcast",
	"Multicast"
};

static tqTp	messageQueue = NULL;
static rwlock_t	msgQueueLock;
static MessageHdr *msgHdrQueue = NULL;
static int	allocatedMsgHdr = 0;
static pthread_t dispatchThreadId = 0;
static pthread_t DynamicThreadId = 0;
static fd_set	saved_fdvec;
static struct rt_msghdr	*rt_msg;
static struct if_msghdr	*ifm;
static int	ioc_sock;

/* Counters common to all Mobility Agents */
extern CommonCounters commonCounters;

/* Foreign Agent specific data structures. */
extern struct hash_table faVisitorHash;
extern ForeignAgentCounters faCounters;

extern int  logVerbosity;
extern struct hash_table maAdvConfigHash;
extern boolean_t faBusy;
extern int visitorEntryHighWaterMark;
extern int visitorEntryLowWaterMark;

static int lookup_existing_entries(ushort_t, ipaddr_t);
static void *processMsgHdr();
static void *getAndDispatchNetworkPacket(void);
static void *doDynamicInterfaceProcess(void *);
static void process_rtsock_msg(int);
static void processIncomingMessage(HashTable *, fd_set *);
static void *find_ancillary(struct msghdr *msg, int cmsg_type);
static void delmaAdvConfigEntry(uint32_t);
static DynamicIfaceTypeEntry   *match_dynamic_table(char *);

extern char *ntoa(uint32_t, char *);
extern void maSendAdvertisement(MaAdvConfigEntry *entry, ipaddr_t dst,
    int advType, boolean_t faBusy);
extern void FAprocessRegRequest(MessageHdr *, MaAdvConfigEntry *, ipaddr_t *);
extern void HAprocessRegRequest(MessageHdr *, MaAdvConfigEntry *, ipaddr_t *);
extern void FAprocessRegReply(MessageHdr *, MaAdvConfigEntry *);

extern void rejectFromICMPToMN(MessageHdr *, ipaddr_t, int);

extern void HAdispatchRadius(MessageHdr *messageHdr, MaAdvConfigEntry *entry,
    ipaddr_t *inAddr);

/*
 * Function: AllocateMessageHdrBlock
 *
 * Arguments:
 *
 * Description: This function will pre-allocate a block of
 *		MAX_MSG_HDR_NUM Message Control Blocks.
 *
 * Returns: int - 0 if successful.
 */
static boolean_t
AllocateMessageHdrBlock()
{
	MessageHdr *messageHdr;
	int i;

	/*
	 * Now we create the message control blocks...
	 */
#if 0
	msgHdrQueue = (MessageHdr *)calloc(1, sizeof (MessageHdr) *
		MAX_MSG_HDR_NUM);
#else
	msgHdrQueue = (MessageHdr *)calloc(MAX_MSG_HDR_NUM,
	    sizeof (MessageHdr));
#endif

	if (msgHdrQueue == NULL) {
		syslog(LOG_CRIT, "Unable to allocate message header queue");
		return (_B_TRUE);
	}

	for (i = 0, messageHdr = msgHdrQueue; i < MAX_MSG_HDR_NUM; i++) {
		messageHdr->next = messageHdr + 1;
	}
	messageHdr->next = NULL;

	return (_B_FALSE);
}

/*
 * Function: AllocateMessageHdr
 *
 * Arguments:
 *
 * Description: This function will return one of the Message
 *		Control Blocks from the queue. If none are
 *		available, we will attempt to allocate another
 *		chunk of control blocks.
 *
 * Returns: Pointer to Messge Control Block. NULL if failed.
 */
MessageHdr *
AllocateMessageHdr()
{
	MessageHdr *messageHdr = NULL;

	/*
	 * Lock the queue
	 */
	(void) rw_wrlock(&msgQueueLock);

	/*
	 * If there are no items on the queue, we will try to allocate
	 * another chunk.
	 */
	if (msgHdrQueue == NULL) {
		if (AllocateMessageHdrBlock()) {
		    syslog(LOG_CRIT, "Unable to allocate more message queues");
		    return (NULL);
		}
	}

	/*
	 * Now get the message header to return
	 */
	messageHdr = msgHdrQueue;
	msgHdrQueue = msgHdrQueue->next;
	allocatedMsgHdr++;

	/*
	 * Unlock the queue
	 */
	(void) rw_unlock(&msgQueueLock);

	/*
	 * Initialize the NAI stuff in the message header.
	 */
	messageHdr->mnNAILen = 0;
	messageHdr->mnNAI = NULL;

	messageHdr->faNAILen = 0;
	messageHdr->faNAI = NULL;

	messageHdr->dontDeleteNow = _B_FALSE;

#ifdef KEY_DISTRIBUTION
	/*
	 * KEY_DISTRIBUTION MUST ONLY BE COMPILED FOR TESTING!!!
	 *
	 * This version of mipagent supports a AAA/DIAMETER
	 * interface. The DIAMETER server generates keying
	 * material that is sent to the Home Agent. The keys
	 * sent are both for the Home Agent, and for the Mobile
	 * Node. The keys for the Mobile Nodes are added to the
	 * registration reply, and the keys for the Home Agent
	 * cause the Home Agent to create a local SA.
	 *
	 * Since DIAMETER/AAA is not currently a product, and key
	 * distribution must still be tested, we have added some
	 * test code in mipagent. When KEY_DISTRIBUTION is enabled,
	 * the home agent creates and encrypts session keys for
	 * the Mobile Node (mimicking DIAMETER), and creates local
	 * SAs. Further, since the session keys MUST also be sent
	 * to the Foreign Agent, the session keys are sent in the
	 * clear to the Foreign Agent through Vendor Specific
	 * extensions.
	 *
	 * Again, this code is for testing purpose only and must not
	 * be enabled for production code, since it hasn't been
	 * fully tested.
	 */
	messageHdr->mnHaKeyLen = 0;
	messageHdr->mnFaKeyLen = 0;
	messageHdr->faHaKeyLen = 0;
	messageHdr->kdcKeysPresent = _B_FALSE;
#endif /* KEY_DISTRIBUTION */
	return (messageHdr);
}

/*
 * Function: FreeMessageHdr
 *
 * Arguments: messageHdr - Pointer to a pointer to a
 *			Message Control Block
 *
 * Description: Puts a Message Control Block back on the
 *		free list.
 *
 * Returns:
 */
void
FreeMessageHdr(MessageHdr *messageHdr)
{
	/*
	 * When FA uses Radius to authenticate the RegReq, it sends a reg
	 * to Radius server and waits for the reply. Meanwhile, we want to
	 * preserve the messageHdr, because FA is going to need it. So,
	 * let's prevent messageHdr from being deleted, until FA is done and
	 * it explicitely calls FreeMessageHdr() with dontDeleteNow == FALSE
	 */
	if (messageHdr->dontDeleteNow)
		return;

	/* Free up faNAI space malloc-ed in aaa.c */
	if (messageHdr->faNAI != NULL)
		free(messageHdr->faNAI);
	/*
	 * Lock and put the item back on the queue
	 */
	(void) rw_wrlock(&msgQueueLock);
	messageHdr->next = msgHdrQueue;
	msgHdrQueue = messageHdr;
	allocatedMsgHdr--;
	(void) rw_unlock(&msgQueueLock);
}

/*
 * Function: startDispatcherTaskThread
 *
 * Arguments:
 *
 * Description: This function will allocate the thread queue,
 *		which is used to dispatch objects to be processed
 *		by threads created by the thread management module
 *		(thq.c). The function will also allocate the initial
 *		chunk of MAX_MSG_HDR_NUM Message Control Blocks and
 *		start the dispatching thread.
 *
 * Returns: int - 0 if successful.
 */
int
startDispatcherTaskThread(void)
{
	pthread_attr_t pthreadAttribute;
	int result;

	messageQueue = tq_alloc(processMsgHdr, NULL,
	    (void *) NULL, NULL, MIP_MAX_THREADS, MIP_MIN_THREADS, FALSE);

	if (!messageQueue) {
		syslog(LOG_CRIT, "Unable to create thread queue");
		return (-1);
	}

	(void) rw_wrlock(&msgQueueLock);

	if (AllocateMessageHdrBlock()) {
		(void) rw_unlock(&msgQueueLock);
		syslog(LOG_CRIT, "Unable to allocate message Queues");
		tq_shutdown(messageQueue, 1);
		return (-1);
	}

	(void) rw_unlock(&msgQueueLock);

	result = pthread_attr_init(&pthreadAttribute);

	if (result) {
		syslog(LOG_CRIT, "Error Initializing pthread.");
		tq_shutdown(messageQueue, 1);
		return (-1);
	}

	/*
	 * We now create a thread to deal with all periodic task.
	 */
	result = pthread_create(&dispatchThreadId, &pthreadAttribute,
	    (void *(*)()) getAndDispatchNetworkPacket,
	    (void *)NULL);

	if (result) {
		syslog(LOG_CRIT, "pthread_create() failed.");
		tq_shutdown(messageQueue, 1);
		return (-1);
	}

	/*
	 * In order for system resources to be properly cleaned up,
	 * we need to detach the thread. Otherwise, we need to wait for
	 * a pthread_join(), which we do not want.
	 */
	result = pthread_detach(dispatchThreadId);

	if (result) {
		syslog(LOG_CRIT, "pthread_detach() failed.");
		(void) pthread_cancel(dispatchThreadId);
		tq_shutdown(messageQueue, 1);
		return (-1);
	}

	return (0);
}

/*
 * Function: killDispatcherTaskThread
 *
 * Arguments:
 *
 * Description: This function is used to kill the dispatch thread,
 *		the threads that are created by the thread queue
 *		management sub-system as well as the thread queue.
 *
 * Returns: int - 0 if sucessful.
 */
int
killDispatcherTaskThread()
{
	int result;

	if (dispatchThreadId) {
		/*
		 * Next we need to kill the dispatching thread.
		 */
		result = pthread_cancel(dispatchThreadId);

		if (result) {
			/*
			 * Well, there's not much we can do here..
			 */
			syslog(LOG_CRIT, "Unable to kill dispatching thread");
		}
	}

	if (messageQueue) {
		/*
		 * First we kill all of the message handling threads.
		 */
		tq_shutdown(messageQueue, 1);
	}

	return (0);
}

/*
 * Function: startDynamicInterfaceThread
 * Arguments: None
 * Description:
 * This function is called only when
 * the configuration file indicates dynamic interface
 * and DynamicInterface variable is true.
 *
 * Returns 0 on success.
 */
int
startDynamicInterfaceThread(void)
{
	pthread_attr_t pthreadAttribute;
	int	result;

	result = pthread_attr_init(&pthreadAttribute);

	if (result != 0) {
		syslog(LOG_CRIT, "Error Initializing pthread: %m");
		return (-1);
	}

	/*
	 * We now create a thread to deal with processing new interfaces
	 */
	result = pthread_create(&DynamicThreadId, &pthreadAttribute,
	    doDynamicInterfaceProcess, NULL);

	if (result != 0) {
		syslog(LOG_CRIT, "pthread_create() failed: %m");
		return (-1);
	}

	/*
	 * In order for system resources the be properly cleaned up,
	 * we need to detach the thread. Otherwise, we need to wait for
	 * a pthread_join(), which we do not want.
	 */
	result = pthread_detach(DynamicThreadId);

	if (result != 0) {
		syslog(LOG_CRIT, "pthread_detach() failed: %m");
		return (-1);
	}

	return (0);
}



/*
 * Function: killDynamicInterfaceThread
 * Arguments:
 * Description: This function is used for thread cleanup
 * Returns 0 on success
 */
int
killDynamicInterfaceThread(void)
{
	int result;

	if (DynamicThreadId) {
		/*
		 * Next we need to kill the dispatching thread.
		 */
		result = pthread_cancel(DynamicThreadId);

		if (result != 0) {
			/*
			 * Well, there's not much we can do here..
			 */
			syslog(LOG_CRIT, "Unable to kill Dynamic thread: %m");
			return (-1);
		}
		DynamicThreadId = 0;
	}
	return (0);
}

/*
 * Function: dispatchMsgToThread
 *
 * Arguments: messageHdr - Pointer to a pointer to a
 *			Message Control Block
 *
 * Description: This function will submit a Message Control
 *		Block for processing to a child thread using
 *		the thread management sub-system.
 *
 * Returns: int - 0 if successfully dispatched to thread.
 */
int
dispatchMsgToThread(MessageHdr **messageHdr)
{

	if (*messageHdr == NULL) {
		return (-1);
	}

	if (tq_queue(messageQueue, *messageHdr)) {
		syslog(LOG_CRIT, "Unable to dispatch message to thread");
		return (-1);
	}

	/*
	 * Since we've queued the packet for a thread, we will
	 * NULL out the pointer so that it does not get re-used.
	 */
	*messageHdr = NULL;

	return (0);
}


/*
 * Function: sendUDPmessage
 *
 * Arguments:	sock - Socket
 *		pkt - Packet to send
 *		pktLen - packet Length
 *		dst - Destination IP Address
 *		dstPort - Destination IP Port
 *
 * Description: Send a UDP message from sock, to dst address and port
 *		dstPort. The pkt is contained in pkt and is of length
 *		pktLen. dst is already in network byte order.
 *
 * Returns:
 */
int
sendUDPmessage(int sock, unsigned char *pkt,  int pktLen,
    ipaddr_t dst, in_port_t dstPort)
{
	struct sockaddr_in sa;

	sa.sin_family = AF_INET;
	sa.sin_port = htons(dstPort);
	sa.sin_addr.s_addr = dst;

	/* send the message */
	if (sendto(sock, (char *)pkt, pktLen, 0, (struct sockaddr *)&sa,
	    sizeof (struct sockaddr_in)) < 0) {
	    syslog(LOG_ERR, "sendto() Sendto failed in sendUDPmessage.");
	    return (-1);
	}

	return (0);
}

/*
 * Function: sendICMPmessage
 *
 * Arguments:	s - socket
 *		dst - Destination Address
 *		data - Data to send
 *		len - length of data to send
 *
 * Description: Send an ICMP message contained in data to dst
 *		from src
 *
 * Returns:
 */
void
sendICMPmessage(int s, ipaddr_t dst,
	unsigned char data[], int len)
{
	struct sockaddr_in sa;

	sa.sin_family = AF_INET;
	sa.sin_port = 0;
	sa.sin_addr.s_addr = dst;

	/* send the message */
	if (sendto(s, (char *)data, len, 0, (struct sockaddr *)&sa,
		sizeof (struct sockaddr_in)) < 0) {
	    syslog(LOG_ERR, "sendto() Sendto failed in sendICMPmessage.");
	}
}


/*
 * Function: screenICMPpkt
 *
 * Arguments:	messageHdr - Pointer to a Message Control Block
 *
 * Description:	Pkt contains a complete IP datagram(including IP
 *		header) received on a socket monitoring ICMP packets.
 *
 * Returns:
 */
static void
screenICMPpkt(MessageHdr *messageHdr)
{
	icmph *icmpPtr;
	struct ip *ipPtr, *inneripPtr; /* ICMPs outer and inner IP headers */
	struct udphdr *innerudpPtr;    /* perchance the innerIP is UDP */
	char addrstr1[INET_ADDRSTRLEN];
	char addrstr2[INET_ADDRSTRLEN];
	uint16_t ipHdrLen, iError;
	ipaddr_t *ipDst;

	if (messageHdr->pktLen < sizeof (struct ip) + sizeof (icmph)) {
		syslog(LOG_ERR, "ICMP Packet received too small");
		return;
	}

	/* LINTED E_BAD_PTR_CAST_ALIGN */
	ipPtr = (struct ip *)&messageHdr->pkt;

	ipHdrLen = (uint16_t)(ipPtr->ip_hl << 2);

	if (messageHdr->pktLen < ipHdrLen + sizeof (icmph)) {
		syslog(LOG_ERR, "Packet received is smaller than reported");
		return;
	}

	/* LINTED E_BAD_PTR_CAST_ALIGN */
	icmpPtr = (icmph *)((char *)messageHdr->pkt + ipHdrLen);

	ipDst = (ipaddr_t *)&ipPtr->ip_dst;

	/*
	 * Note: we don't have to check the ICMP size, and/or the ICMP
	 * checksum because the kernel takes care of this.  As far as dst
	 * addr goes, the understanding is traffic is checked for forwarding
	 * before the kernel's parser mechanism gets it for passing up.
	 */

	if (icmpPtr->type == ICMP_ROUTERSOLICIT) {
		mipverbose((
		    "Got ICMP solicitation <type %d, code %d> from %s to %s.\n",
		    icmpPtr->type, icmpPtr->code,
		    ntoa(messageHdr->src, addrstr1),
		    ntoa(*ipDst, addrstr2)));

		if (icmpPtr->code == 0) {
			/* Currently, the only code for type 10 solicits. */
			commonCounters.maSolicitationsRecvdCnt++;

			/*
			 * Restrict advertisement to the particular interface
			 * on which the solicitation was received.
			 */
			if (((messageHdr->ifEntry->maIfaceFlags &
			    IFF_POINTOPOINT) == 0) ||
			    (messageHdr->src == INADDR_ANY)) {
				/*
				 * Since we don't have ARP information at this
				 * point, advertise on Bcast or Mcast addr.
				 */
				maSendAdvertisement(messageHdr->ifEntry,
				    messageHdr->ifEntry->maAdvAddr,
				    SOLICITED_ADV, faBusy);
			} else {
				/*
				 * Solicitation from PPP interface with a
				 * non-zero source address.
				 */
				maSendAdvertisement(messageHdr->ifEntry,
				    messageHdr->src, SOLICITED_ADV, faBusy);
			}

			/*
			 * should actually be manipulated inside
			 * maSendAdvertisement()
			 */
			commonCounters.maAdvSentForSolicitationsCnt++;
		}

		/* There can be only one reason we're in here, so we're done. */
		return;
	}

	/*
	 * If this ICMP is in response to a forwarded registration request,
	 * the IP dst addr should be ours...
	 */
	if (ipPtr->ip_dst.s_addr != messageHdr->ifEntry->maIfaceAddr) {
		/* not for us */
		return;
	}

	/*
	 * A response to a packet we sent, check if it's a undelivered regreQ.
	 * We'd better have gotten enough for a returned UDP header.
	 */
	if (messageHdr->pktLen < sizeof (struct ip) + sizeof (icmph) +
	    sizeof (struct udphdr)) {
		/* if we can't get to the udp port info, we can't continue */
		syslog(LOG_ERR,
		    "Recieved ICMP error allegedly for a packet we sent,"
		    " but it's too small to do anything with!\n");
		return;
	}

	/*
	 * Note: the belief is before the kernel sends up the ICMP, it's
	 * checked things like length, checksum, etc.
	 */

	/* It's time to look at the returned IP packet. */
	inneripPtr = (struct ip *)(icmpPtr+1);

	/* We should be the sender of the inner packet */
	if (inneripPtr->ip_src.s_addr != messageHdr->ifEntry->maIfaceAddr) {
		/* We're not responsible for sending that packet */
		return;
	}

	/* UDP? */
	if (inneripPtr->ip_p != IPPROTO_UDP) {
		/* protocol in returned IP header isn't UDP - <zap> */
		return;
	}

	/* OK, the encased IP packet allegedly carries UDP info - go there */
	ipHdrLen = (uint16_t)(inneripPtr->ip_hl << 2);
	/* LINTED E_BAD_PTR_CAST_ALIGN */
	innerudpPtr = (struct udphdr *)((char *)inneripPtr + ipHdrLen);

	/*
	 * Swapping madness for the port value because this piece is RAW off
	 * the network.  Note: htons() is a no-op on SPARC.
	 */
	if (htons(innerudpPtr->uh_dport) != MIP_PORT) {
		/* dst port of returned UDP packet isn't MIP_PORT <zzzt>. */
		return;
	}


	/*
	 * Looks like we were returned a UDP packet to port 434, so lets
	 * find out why delivery failed, then let the mobile node know.
	 *
	 * There are two reasons we could be geting an ICMP unreachable.  The
	 * most obvious comes from bad addresses, but another possibility is
	 * the simple timeout.
	 */
	if (icmpPtr->type == ICMP_UNREACH) {

		/* All that info implies it was for something we sent out */
		mipverbose((
		    "Received ICMP error in response to regreQ from MN: "));
		mipverbose(("Type: UNREACH, ICMPcode: %d.", icmpPtr->code));

		/* The error to the MN is based on the ICMP code... */
		switch (icmpPtr->code) {
		case ICMP_UNREACH_NET:
		case ICMP_UNREACH_NET_UNKNOWN:
		case ICMP_UNREACH_NET_PROHIB:
			/* return error 80 home network unreachable */
			mipverbose(("Home Network Unreachable.\n"));
			iError = FA_HA_NET_UNREACHABLE;
			break;

		case ICMP_UNREACH_HOST:
		case ICMP_UNREACH_HOST_UNKNOWN:
		case ICMP_UNREACH_HOST_PROHIB:
			/* return error 81 home agent host unreachable */
			mipverbose(("Home Agent IP Unreachable.\n"));
			iError = FA_HA_HOST_UNREACHABLE;
			break;

		case ICMP_UNREACH_PORT:
			/* return error 82 home agent port unreachable */
			mipverbose(("Home Agent Port Unreachable.\n"));
			iError = FA_HA_PORT_UNREACHABLE;
			break;

		case ICMP_UNREACH_ISOLATED:
		case ICMP_SOURCEQUENCH:
			/*
			 * Notes for the case of sourceQuench - the packet
			 * was lost somewhere (what else can we assume?)
			 * Two choices: send an unreachable error to the
			 * MN, or resend the registration request, but it's
			 * NOT contained in the ICMP error message.  If it
			 * cares, the MN will regenerate, perhaps to a
			 * fallback HA.
			 *
			 * Return error 88 home agent unreachable.
			 */
			mipverbose(("Home Agent Unreachable.\n"));
			iError = FA_HA_UNREACHABLE;
			break;

		default:
			/*
			 * E.g. ICMP_UNREACH_PROTOCOL, ICMP_UNREACH_NEEDFRAG,
			 * ICMP_UNREACH_SRCFAIL - catch them here (OK, the last
			 * two are a bit of a reach).  Also, anything "new" to
			 * ICMP will have to return something generic for now.
			 *
			 * Return error 88 home agent unreachable.
			 */
			mipverbose(("Unreachable default:"
			    " Home Agent Unreachable.\n"));
			iError = FA_HA_UNREACHABLE;
			break;

		} /* switch(icmpPtr->code) */

		/* bump our counters */
		faCounters.faRegRepliesICMPUnreachCnt++;

		/* only one ICMP type, so... */
		(void) rejectFromICMPToMN(messageHdr,
		    inneripPtr->ip_dst.s_addr, iError);

		/* There can be only one reason, we're done */
		return;
	}

	/* Don't forget timeouts */
	if (icmpPtr->type == ICMP_TIMXCEED) {
		mipverbose((
		    "Received ICMP error in response to regreQ from MN: "));

		mipverbose(("Type: TIMEOUT, ICMPcode: %d.", icmpPtr->code));

		/* The error is based on the ICMP message... */
		switch (icmpPtr->code) {
		case ICMP_TIMXCEED_INTRANS:
		case ICMP_TIMXCEED_REASS:
			mipverbose(("timeout-88: Home Agent Unreachable.\n"));
			iError = FA_HA_UNREACHABLE;
			break;

		default:
			/* Not the format of an ICMP_TIMXCEED, but still... */
			mipverbose(("timeout: default"
			    "88: Home Agent Unreachable.\n"));
			iError = FA_HA_UNREACHABLE;
			break;
		}

		/* bump our counters */
		faCounters.faRegRepliesICMPTimxceedCnt++;

		/* only one reason to reject... */
		(void) rejectFromICMPToMN(messageHdr,
		    inneripPtr->ip_dst.s_addr, iError);
	}

	/*
	 * Think: ICMP_REDIRECT{NET,HOST,TOSNET,TOSHOST} should be handled
	 * in-stack before we see it.    ^^^^^^ ^^^^^^^
	 */

	/* If we made it here, we don't care about this ICMP type; done... */
	return;

} /* screenICMPpkt() */


/*
 * Function: screenUDPpkt
 *
 * Arguments:	messageHdr - Pointer to a Message Control Block
 *
 * Description:	Pkt contains a complete UDP datagram received on
 *		a socket monitoring UDP packets.
 *
 * Returns:
 */
static void
screenUDPpkt(MessageHdr *messageHdr)
{
	regRequest *regReqPtr;
	unsigned char *cp;
	char addrstr1[INET_ADDRSTRLEN];
	char addrstr2[INET_ADDRSTRLEN];
	ipaddr_t inAddr;
	boolean_t ha_match, fa_match;
	boolean_t is_ha, is_fa;

	switch (messageHdr->ifType) {
	case ON_UNICAST_SOCK:
		inAddr = messageHdr->ifEntry->maIfaceAddr;
		break;

	case ON_MCAST_SOCK:
		inAddr = inet_addr(LINK_MCAST_REG_ADDR);
		break;

	case ON_BCAST_SOCK:
		inAddr = GENERATE_NET_BROADCAST_ADDR(messageHdr->ifEntry);
		break;
	default:
		syslog(LOG_ERR, "screenUDPpkt: Unknown socket type \n");
		break;

	}

	cp = messageHdr->pkt;

	switch (*cp) {

	case REG_REQUEST_TYPE:

		if (messageHdr->pktLen < sizeof (regRequest)) {
			syslog(LOG_ERR, "Received registration request is " \
			    "too short.");
			return;
		}
		/* LINTED E_BAD_PTR_CAST_ALIGN */
		regReqPtr = (regRequest *) messageHdr->pkt;

		/*
		 * Here is what we need to do. If the Home Agent Address
		 * matches our interface address, or the packet is a broadcast,
		 * then we process it as a Home Agent. However, if the packet's
		 * care of address matches our address, or if it is a
		 * multicast, then we process the packet as a Foreign Agent.
		 */
		is_ha = (messageHdr->ifEntry->maAdvServiceFlags &
		    ADV_IS_HOME_AGENT);
		ha_match = (is_ha && ((regReqPtr->haAddr == inAddr) ||
		    (messageHdr->ifType == ON_BCAST_SOCK)));

		is_fa = (messageHdr->ifEntry->maAdvServiceFlags &
		    ADV_IS_FOREIGN_AGENT);
		fa_match = (is_fa && ((regReqPtr->COAddr == inAddr) ||
		    (messageHdr->ifType == ON_MCAST_SOCK)));

		mipverbose(("req.haddr=0x%08x, inAddr=0x%08x, coAddr=0x%08x, ",
		    regReqPtr->haAddr, inAddr, regReqPtr->COAddr));
		mipverbose(("HAFlag = %d, FAFlag = %d, ", is_ha ? 1 : 0,
		    is_fa ? 1 : 0));
		if (ha_match)
			mipverbose((" we are *the* HA\n"));
		if (fa_match)
			mipverbose((" we are *the* FA\n"));

		/*
		 * Check out the matching criterias to determine if we are
		 * acting as the HA or FA for this request. If we match the
		 * request as the HA, process it as HA. If we match the request
		 * as the FA, process it as FA. In case we are acting as HA but
		 * the request doesn't match neither our HA nor FA, let's go
		 * ahead and process this request as an HA and deny it.
		 * Similarly, in case we are acting as FA but the request
		 * doesn't match neither our FA nor HA, let's go ahead and
		 * process this request as an FA and deny it.
		 */
		if (messageHdr->pktSource == MIP_PKT_FROM_RADIUS) {
			/*
			 * This occurs when the HA address in the registration
			 * request is invalid, which occurs when AAA is used
			 * and the Home Agent's address is set to either zero
			 * or 0xffffffff in the registration Request. In this
			 * case, we need to update the Home Agent's address
			 * in the Registration Reply.
			 *
			 * MIP_PKT_FROM_RADIUS is Radius specific.  In this
			 * case a call is made to HAprocessRegRequestRadius.
			 */
			regReqPtr->haAddr = messageHdr->ifEntry->maIfaceAddr;
			(void) HAdispatchRadius(messageHdr,
			    messageHdr->ifEntry, &inAddr);
		} else if (fa_match || (is_fa && !ha_match)) {
			/* process as FA */
			FAprocessRegRequest(messageHdr, messageHdr->ifEntry,
			    &inAddr);
		} else if (ha_match || (is_ha && !fa_match)) {
			/* process as HA */
			HAprocessRegRequest(messageHdr, messageHdr->ifEntry,
			    &inAddr);
		} else if (messageHdr->pktSource == MIP_PKT_FROM_AAA) {
			/*
			 * MIP_PKT_FROM_AAA - for all other aaa protocols.
			 * This also occurs when the HA address in the reg
			 * request is invalid, which occurs when AAA is used
			 * and the Home Agent's address is set to either zero
			 * or 0xffffffff in the registration Request. In this
			 * case, we need to update the Home Agent's address
			 * in the Registration Reply.
			 */
			regReqPtr->haAddr = messageHdr->ifEntry->maIfaceAddr;
			HAprocessRegRequest(messageHdr, messageHdr->ifEntry,
			    &inAddr);
		} else {
			syslog(LOG_ERR,
			    "Not configured to handle this reg req on addr " \
			    "%s from %s.",
			    ntoa(inAddr, addrstr1), ntoa(messageHdr->src,
				addrstr2));
		}
		break;

	case REG_REPLY_TYPE:
		if (messageHdr->pktLen < sizeof (regReply)) {
			syslog(LOG_ERR, "Received registration reply is too " \
			    "short.");
			return;
		}
		FAprocessRegReply(messageHdr, messageHdr->ifEntry);
		break;

	default:
		syslog(LOG_ERR,
		    "Unknown UDP message (first byte 0x%x) from %s.",
		    *cp, ntoa(messageHdr->src, addrstr1));
	}
}

/*
 * Function: processMsgHdr
 *
 * Description: This is the child thread that is called by
 *		the thread management sub-system to handle
 *		a specific Message Control Block. This function
 *		will remain in a while loop waiting for messages
 *		to handle.
 *
 *		This function never returns, but can be killed by
 *		another thread calling tq_shutdown().
 *
 * Returns:	void pointer of NULL. Note this is not really necessary,
 *		but makes thq.c/h prototypes happy.
 */
static void *
processMsgHdr()
{
	MessageHdr *messageHdr;

	/*
	 * Main while loop... should never exit
	 */
	/* CONSTCOND */
	while (_B_TRUE) {
		messageHdr = (MessageHdr *) tq_dequeue(messageQueue, 0);

		if (messageHdr == NULL)
			continue;

		switch (messageHdr->pktType) {
		case PKT_UDP:
			screenUDPpkt(messageHdr);
			break;
		case PKT_ICMP:
			screenICMPpkt(messageHdr);
			break;
		default:
			syslog(LOG_ERR, "processMsgHdr: Unknown Pkt type\n");
			break;
		}

		FreeMessageHdr(messageHdr);
	}

	return (NULL);
}


/*
 * Function: getAndDispatchNetworkPacket
 *
 * Arguments:
 *
 * Description: This is the main dispatch thread. This
 *		function has two main functions. First it will
 *		use select to determine if any data has been
 *		received on our sockets. Second, the select
 *		function is called with a timeout, which is
 *		used to determine when we need to send router
 *		advertisements.
 *
 *		This function never returns, but will be killed
 *		if killDispatcherTaskThread() is called.
 *
 * Returns:
 */
static void *
getAndDispatchNetworkPacket()
{
	int i, nentry;
	int result;
	static fd_set fdvec;
	static struct timeval tv;
	time_t nextAdvTime = 0;
	time_t currentTime;
	time_t lowestNextAdvTime = 0;
	struct hash_table *htbl;
	MaAdvConfigEntry *entry;
	struct hash_entry *p;

	htbl = &maAdvConfigHash;

	/*
	 * Setup the initial advertisement time.
	 */
	GET_TIME(currentTime);
	nextAdvTime = currentTime;

	/*
	 * We will save the file descriptor vector for future use.
	 * This saves us the trouble of having to skip through the
	 * while interface entry each time.
	 *
	 * NOTE: Since this block of code is called during initial static
	 * interface configuration, we do not need to lock the config
	 * entries here as the sequence at startup is startDispatcherTaskThread
	 * followed by startDynamicInterfaceThread.
	 */
	for (i = 0, nentry = 0;
	    i < HASH_TBL_SIZE && (nentry < htbl->size); i++) {
		p = htbl->buckets[i];
		while (p != NULL) {
			nentry++;
			entry = (MaAdvConfigEntry *)p->data;
			FD_SET(entry->maIfaceUnicastSock, &saved_fdvec);
			if ((entry->maIfaceFlags & IFF_POINTOPOINT) == 0) {
				FD_SET(entry->maIfaceDirBcastSock,
				    &saved_fdvec);
				FD_SET(entry->maIfaceBcastSock,
				    &saved_fdvec);
			}
			FD_SET(entry->maIfaceAdvMulticastSock, &saved_fdvec);
			FD_SET(entry->maIfaceRegMulticastSock, &saved_fdvec);
			FD_SET(entry->maIfaceIcmpSock, &saved_fdvec);
			/* Update maNextAdvtime to advertise now */
			entry->maNextAdvTime = currentTime;
			p = p->next;
		}
	}

	for (;;) {
		/*
		 * Take a snapshot of the file descriptors.
		 */
		fdvec = saved_fdvec;

		/*
		 * What time is it?
		 */
		GET_TIME(currentTime);

		/*
		 * Wait on select for next adv or input or when
		 * there is no static interface entry in the config file
		 */
		if ((currentTime < nextAdvTime) || (nentry == 0)) {
			tv.tv_sec = nextAdvTime - currentTime;
			tv.tv_usec = 0;

			/*
			 * Caveat: Currently, if one static/dynamic interface
			 * adv n sec later, then advertisement for new
			 * interface waits until select times out. So, in
			 * some cases, the first adv does not happen instantly.
			 * Recommended AdvFrequency is 2-3 sec for dynamic
			 * interfaces.
			 */
			result = select(FD_SETSIZE,
			    &fdvec, NULL, NULL, &tv);

			if (result < 0) {
				if ((errno != EINTR) && (errno != ERESTART) &&
				    (errno != EBADF)) {
					/*
					 * EBADF can be often set
					 * from select in situations when
					 * the socket fd's corresponding
					 * to the dynamic interface is gone
					 * while select was in sleep.
					 * This situation can happen often
					 * as the connection comes and goes.
					 * Assuming the mipagent sets
					 * FD_SET correctly, at this point
					 * it is best not to print syslog
					 * error for the EBADF case to avoid
					 * plenty of such messages in the
					 * console.
					 */
					syslog(LOG_ERR,
					    "select failed with error: %m");
				}
				continue;
			}

			/*
			 * Now that we've slept, let's get our current time.
			 */
			GET_TIME(currentTime);
		} else {
			/*
			 * It looks like it's time to advertise, so we set
			 * result to zero. This will ensure that we will not
			 * attempt to receive a network packet.
			 */
			result = 0;
		}

		/*
		 * Let's check if it is time to start advertising
		 */
		if (currentTime >= nextAdvTime) {
			/*
			 * Check each entry to see if it's time for at least
			 * one entry to advertise. lowestNextAdvTime keeps
			 * track of lowest NextAdvTime value of the traversed
			 * entries. During eachtime we check the entries to
			 * advertise, lowestNextAdvTime is updated to a
			 * lower value if the current entry's nextAdvTime is
			 * lower than the nextAdvTime local variable.
			 */
			lowestNextAdvTime = 0;
			for (i = 0, nentry = 0;
			    i < HASH_TBL_SIZE && (nentry < htbl->size); i++) {
				p = htbl->buckets[i];
				while (p) {
					nentry++;
					entry = (MaAdvConfigEntry *)p->data;
					(void) rw_rdlock(
					    &entry->maIfaceNodeLock);
					if (currentTime >=
					    entry->maNextAdvTime) {
						/* Advertise  now */
						if (faVisitorHash.size <=
						    visitorEntryLowWaterMark) {
							faBusy = _B_FALSE;
						} else if (faVisitorHash.size >=
						    visitorEntryHighWaterMark) {
							faBusy = _B_TRUE;
						}
						if (entry->maAdvInitCount > 0) {
							maSendAdvertisement(
							    entry,
							    entry->maAdvAddr,
							    UNSOLICITED_ADV,
							    faBusy);
						}
						entry->maNextAdvTime =
						    currentTime +
						    entry->maAdvInterval;
					}
					/*
					 * Set next timeout equal to the minimum
					 * time left for next advertisement for
					 * an entry. The following comparison is
					 * true when nextAdvTime is updated by
					 * interval and there is another entry
					 * in the list which needs to advertise
					 * before nextAdvTime.
					 */
					if (entry->maAdvInitCount > 0) {
						nextAdvTime =
						    entry->maNextAdvTime;

						if (lowestNextAdvTime == 0) {
							/* First pass */
							lowestNextAdvTime =
							    nextAdvTime;
						}
						if (nextAdvTime >
						    lowestNextAdvTime) {
							nextAdvTime =
							    lowestNextAdvTime;
						} else {
							lowestNextAdvTime =
							    nextAdvTime;
						}
					}
					p = p->next;
					(void) rw_unlock(
					    &entry->maIfaceNodeLock);
				}
			}
			/*
			 * If for some reason there is no entry in the
			 * Confighash table and nextAdvTime was not
			 * updated at all, then set the nextAdvTime to
			 * to default value to avoid looping. This block
			 * can also be exercized if there is no periodic
			 * advertisment is done as we may have set
			 * AdvLimitUnsolicited to all advertising interfaces.
			 */
			if (currentTime >= nextAdvTime) {
				nextAdvTime = currentTime +
				    DEFAULT_MIN_INTERVAL;
			}
		} else if (result > 0) {
			processIncomingMessage(htbl, &fdvec);
		}
	}
	/* LINTED E_STMT_NOT_REACHED */
	return (NULL);
}

/*
 * Function:	find_ancillary
 * Arguments:	msg - contains the ancillary information
 *		cmsg_type - type of ancillary data
 * Description: Return a pointer to the specified option buffer.
 *		If not found return NULL.
 */
static void *
find_ancillary(struct msghdr *msg, int cmsg_type)
{
	struct cmsghdr *cmsg;

	for (cmsg = CMSG_FIRSTHDR(msg); cmsg != NULL;
		cmsg = CMSG_NXTHDR(msg, cmsg)) {
		if (cmsg->cmsg_level == IPPROTO_IP &&
		    cmsg->cmsg_type == cmsg_type) {
			return (CMSG_DATA(cmsg));
		}
	}
	return (NULL);
}

/*
 * Function: recvNetworkPacket
 *
 * Arguments:	socket - Socket on which data is pending
 *		entry - Interface on which the data is pending
 *		ifType - Whether the interface if UNICAST, BCAST or MCAST
 *		packetType - Wether the packet is UDP or ICMP
 *
 * Description: This function is called if data is pending
 *		on one of our sockets. This function will
 *		allocate a Messge Control Block, receive
 *		the data and call the function that dispatches
 *		the control block to a thread.
 *
 * Returns:
 */
static void
recvNetworkPacket(int socket, MaAdvConfigEntry *entry, uint32_t ifType,
    uint32_t packetType)
{
	MessageHdr *messageHdr;
	struct sockaddr_in from;
	static uint64_t in_packet[(MAX_PKT_SIZE + 1)/8];
	static uint64_t ancillary_data[(MAX_PKT_SIZE + 1)/8];
	struct msghdr msg;
	struct iovec iov;
	uchar_t *opt;

	iov.iov_base = (char *)in_packet;
	iov.iov_len = sizeof (in_packet);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_name = (struct sockaddr *)&from;
	msg.msg_namelen = sizeof (from);
	msg.msg_control = ancillary_data;
	msg.msg_controllen = sizeof (ancillary_data);

	/*
	 * Allocate a Message Header.
	 */
	if ((messageHdr = AllocateMessageHdr()) == NULL) {
		syslog(LOG_CRIT,
		    "Unable to allocate a message header");
		return;
	}

	if ((messageHdr->pktLen = recvmsg(socket, &msg, 0))
		== (unsigned int) (-1)) {
		FreeMessageHdr(messageHdr);
		syslog(LOG_ERR,
		    "recvmsg failed for UDP on "
		    "%s socket...%s", ifTypeName[ifType], strerror(errno));
	} else {
		unsigned char *cp;

		(void) memcpy(messageHdr->pkt, in_packet, MAX_PKT_SIZE);

		cp = messageHdr->pkt;
		/*
		 * If it's a registration request then we need to get the
		 * ancillary information.
		 * TODO: 1. Fix this section of code to IP_RECVIF
		 * 		for ICMP packets too.
		 *	2. Add kernel support for IP_RECVSLLA for ICMP
		 *		packets. This is required for response to
		 *		unicast address for agent solicitation
		 */
		if ((packetType == PKT_UDP) && (*cp == REG_REQUEST_TYPE)) {

			/*
			 * If this is an PPP interface, don't attempt to
			 * get the slla.
			 */
			if (entry->maIfaceFlags & IFF_POINTOPOINT) {
				messageHdr->isSllaValid = _B_FALSE;
			} else {
				/* try to extract slla from the packet */
				opt = find_ancillary(&msg, IP_RECVSLLA);
				if (opt == NULL) {
					syslog(LOG_ERR,
					    "receving IP_RECVSLLA ancillary"
					    "failed...%s", strerror(errno));
					/*
					 * IP_RECVSLLA could fail for various
					 * reasons:
					 * a> the interface is no-resolver type
					 *    (eg PPP)
					 * b> kernel ran out of memory
					 * c> the information the driver passed
					 *    to IP is bogus
					 * we could return from here but this
					 * info (i.e SLLA) is non-critical, so
					 * we don't. Instead we mark the entry
					 * as invalid so it's not used in the
					 * code. Currently the entry is used to
					 * prevent the FA from broadcast ARPing
					 */
					messageHdr->isSllaValid = _B_FALSE;
				} else {
					messageHdr->isSllaValid = _B_TRUE;
					bcopy(opt, &messageHdr->slla,
					    sizeof (struct sockaddr_dl));
				}
			}

			opt = find_ancillary(&msg, IP_RECVIF);
			if (opt == NULL) {
				syslog(LOG_ERR, "receving IP_RECVIF ancillary"
				    "failed");
				FreeMessageHdr(messageHdr);
				return;
			}

			/* LINTED BAD_PTR_CAST_ALIGN */
			messageHdr->inIfindex = *(uint_t *)opt;

			opt = find_ancillary(&msg, IP_RECVTTL);
			if (opt == NULL) {
				syslog(LOG_ERR, "receving IP_RECVTTL ancillary"
				    "failed");
				FreeMessageHdr(messageHdr);
				return;
			}

			messageHdr->ttl = *(uint8_t *)opt;
		} else {

			/*
			 * Make sure they are initialized, just in case
			 */
			messageHdr->inIfindex = 0;
			messageHdr->isSllaValid = _B_FALSE;
		}

		messageHdr->src =
		    from.sin_addr.s_addr;
		messageHdr->srcPort =
		    ntohs(from.sin_port);
		messageHdr->ifEntry = entry;
		messageHdr->ifType = ifType;
		messageHdr->pktType = packetType;
		messageHdr->pktSource = MIP_PKT_FROM_FA;
		assert(!messageHdr->mnNAILen);
		(void) dispatchMsgToThread(&messageHdr);
	}
}

/*
 * Function: getFirstInterface
 *
 * Arguments: none
 *
 * Description: This function will return the first interface in the hash
 *		table.  Todo: Pick the closest interface
 *
 * Returns: MaAdvConfigEntry *
 */
MaAdvConfigEntry *
getFirstInterface()
{
	HashTable *htbl;
	MaAdvConfigEntry *entry;
	HashEntry *p;
	int i, nentry;

	/*
	 * for each mobility supporting interface ...
	 */
	htbl = &maAdvConfigHash;

	for (i = 0, nentry = 0;
	    i < HASH_TBL_SIZE && (nentry < htbl->size); i++) {
		p = htbl->buckets[i];
		if (p) {
			nentry++;
			entry = (MaAdvConfigEntry *)p->data;
			return (entry);
		}
	}
	return (NULL);
} /* getFirstInterface */


/*
 * Function: getClosestInterfaceAddr
 *
 * Arguments: ipaddr_t dest
 *
 * Description: This routine will return the nerest interface for reaching
 *		the dest.  (For now, it will simply lookup the ip address
 *		of our first mobility interface.)  Todo!
 *
 * Returns: ipaddr_t (0 on error)
 */
ipaddr_t
/* LINTED E_FUNC_ARG_UNUSED */
getClosestInterfaceAddr(ipaddr_t dest)
{
	MaAdvConfigEntry *entry;

	/*
	 * for each mobility supporting interface ...
	 */

	entry = getFirstInterface();
	if (entry)
		return (entry->maIfaceAddr);
	else
		return (0);
} /* getClosestInterfaceAddr */

/*
 * Function: processIncomingMessage
 *
 * Arguments:	htbl - Pointer to the Hash Table
 *		fdvec - Pointer to file descriptor
 *
 * Description: This function is called if data is pending
 *		on one of our sockets. This function loop
 *		through the interfaces looking for the socket
 *		on which data is pending.
 *
 * Returns:
 */
static void
processIncomingMessage(HashTable *htbl, fd_set *fdvec)
{
	MaAdvConfigEntry *entry;
	HashEntry *p;
	int i, nentry;

	/*
	 * for each mobility supporting interface ...
	 */
	htbl = &maAdvConfigHash;

	for (i = 0, nentry = 0;
	    i < HASH_TBL_SIZE && (nentry < htbl->size); i++) {
		p = htbl->buckets[i];
		while (p) {
			nentry++;
			entry = (MaAdvConfigEntry *)p->data;

			/*
			 * process data received on ICMP socket
			 */
			if (FD_ISSET(entry->maIfaceIcmpSock, fdvec)) {
				recvNetworkPacket(entry->maIfaceIcmpSock,
				    entry, ON_BCAST_SOCK, PKT_ICMP);
			}

			if (FD_ISSET(entry->maIfaceAdvMulticastSock, fdvec)) {
				recvNetworkPacket(
				    entry->maIfaceAdvMulticastSock,
				    entry, ON_MCAST_SOCK, PKT_ICMP);
			}

			/*
			 * ... process data on UDP socket bound to
			 * unicast address
			 */
			if (FD_ISSET(entry->maIfaceUnicastSock, fdvec)) {
				recvNetworkPacket(entry->maIfaceUnicastSock,
				    entry, ON_UNICAST_SOCK, PKT_UDP);
			}

			/*
			 * mipagent doesn't listen to broadcast sockets if
			 * this is a PPP interface.
			 */
			if ((entry->maIfaceFlags & IFF_POINTOPOINT) == 0) {
				/*
				 * ... process data on UDP socket bound to
				 * directed broadcast address
				 */
				if (FD_ISSET(entry->maIfaceDirBcastSock,
				    fdvec)) {
					recvNetworkPacket(
					    entry->maIfaceDirBcastSock,
					    entry, ON_BCAST_SOCK, PKT_UDP);
				}

				/*
				 * ... process data on UDP socket bound to
				 * broadcast address
				 */
				if (FD_ISSET(entry->maIfaceBcastSock, fdvec)) {
					recvNetworkPacket(
					    entry->maIfaceBcastSock,
					    entry, ON_BCAST_SOCK, PKT_UDP);
				}
			}

			/*
			 * ... process data on UDP socket bound to
			 * multicast address
			 */
			if (FD_ISSET(entry->maIfaceRegMulticastSock, fdvec)) {
				recvNetworkPacket(
					entry->maIfaceRegMulticastSock,
				    entry, ON_MCAST_SOCK, PKT_UDP);
			}
			p = p->next;
		}
	}
}


/*
 * Function: doDynamicInterfaceProcess
 * Argument:
 * Description:
 *	This process is launched by dynamic interface thread. It's purpose
 *	is to hang around and poll to check if any new interface comes up.
 *	It calls process_rtsock_msg() for any valid RTM_INFO.
 *
 * Returns : NULL
 */

/* ARGSUSED */
static void *
doDynamicInterfaceProcess(void * arg)
{
	int	s;	/* Routing socket id */
	int	ret;
	struct	pollfd	pollfds[1];

	/* Open a socket to send ICOTL cmd down by rtsock_process_msg */
	ioc_sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (ioc_sock < 0) {
		syslog(LOG_CRIT, "Can't open IOC socket: %m");
		return (NULL);
	}
	s = socket(PF_ROUTE, SOCK_RAW, AF_INET);
	if (s == -1) {
		syslog(LOG_CRIT,
		    "unable to open Routing socket for dynamic interface: %m");
		(void) close(ioc_sock);
		return (NULL);
	}
	ret = fcntl(s, F_SETFL, O_NDELAY|O_NONBLOCK);
	if (ret < 0) {
		syslog(LOG_CRIT,
		    "fcntl failed on routing socket: %m");
		(void) close(ioc_sock);
		(void) close(s);
		return (NULL);
	}

	pollfds->fd = s;
	pollfds->events = POLLIN;

	for (;;) {
		if (poll(pollfds, 1, INFTIM) < 0 ||
		    (pollfds->revents & POLLERR)) {
			if (errno == EINTR)
				continue;
			syslog(LOG_CRIT,
			    "Poll failed: %m");
			(void) close(s);
			(void) close(ioc_sock);
			return (NULL);
		}
		if (!pollfds->revents & POLLIN)
			continue;
		if (pollfds->fd == s) {
			mipverbose(("doDynamicInterfaceProcess: "
			    "received message on RTsocket\n"));
			process_rtsock_msg(s);
		}
	}
	/* LINTED E_STMT_NOT_REACHED */
	return (NULL);	/* Never reached */
}


/*
 * Function: process_rtsock_msg
 * Argument : int
 * Description :
 *	process_rtsock_msg processes the RTM_INFO messages. It checks
 *	if the flag is IFF_UP for the specified interface index. It also
 *	checks that this is IPV4, non-loopback, non-logical interface. It
 *	makes all other necessary checks before establishing the new
 *	interface as mobility interface. When an interface is plumbed it
 *	receives two RTM_IFINFO messages per interface.
 */

static void
process_rtsock_msg(int rtsock)
{

#define	RTSOCK_MAX_MSG	2048

	int64_t msg[RTSOCK_MAX_MSG / sizeof (int64_t)];
	int	num;
	struct lifreq lifr;
	ipaddr_t	addr;
	struct sockaddr_in *sin;
	DynamicIfaceTypeEntry	*d_entry;
	MaAdvConfigEntry	*ifentry;
	uint64_t	ifflags;
	time_t		currentTime;

	num = (int)read(rtsock, msg, sizeof (msg));
	if (num <= 0) {
		/* No messages */
		return;
	}
	rt_msg = (struct rt_msghdr *)msg;
	if (rt_msg->rtm_version != RTM_VERSION) {
		syslog(LOG_CRIT, "Bad RTM version: %d", rt_msg->rtm_version);
		return;
	}

	if (rt_msg->rtm_type != RTM_IFINFO)
		return;

	/* Now process the RTM_INFO message */
	ifm = (struct if_msghdr *)rt_msg;
	mipverbose(("process_rtsock_msg: RTM_IFINFO for if_index %d\n",
	    ifm->ifm_index));

	(void) memset(&lifr, 0, sizeof (struct lifreq));
	if (if_indextoname(ifm->ifm_index, lifr.lifr_name) == NULL) {
		/*
		 * Interface unplumbed ?
		 * Make sure we delete any unused entry.
		 */
		(void) delmaAdvConfigEntry(ifm->ifm_index);
		return;
	}
	/* Found the ifname, check if it's new */

	if (strchr(lifr.lifr_name, ':') != NULL) {
		/* We don't support logical interfaces */
		mipverbose(("process_rtsock_msg: logical interface %s\n",
		    lifr.lifr_name));
		return;
	}

	/*
	 * Check if this entry belongs to any existing interfaces
	 * that were already configured at the time of mipagent
	 * startup. If any of those interfaces ifconfiged down and then
	 * ifconfig'ed  up, we don't consider them as dynamic interface.
	 */
	if (existingStaticInterface(lifr.lifr_name))
		return;

	/* Check for IPv4  and multicast flag */
	if ((int)ioctl(ioc_sock, SIOCGLIFFLAGS, (char *)&lifr) < 0) {
		/* Interface disappeared ? */
		mipverbose(("process_rtsock_msg: SIOCGLIFFLAGS failed\n"));
		return;
	}
	if (!(lifr.lifr_flags & IFF_IPV4) ||
	    !(lifr.lifr_flags & IFF_MULTICAST)) {
		mipverbose(("process_rtsock_msg: flag not IPV4 MULTICAST\n"));
		return;
	}

	ifflags = lifr.lifr_flags;

	if (ioctl(ioc_sock, SIOCGLIFADDR, (caddr_t)&lifr) < 0) {
		syslog(LOG_ERR, "Could not read IP address for"
		    "%s: %m", lifr.lifr_name);
		return;
	}
	sin = (struct sockaddr_in *)&lifr.lifr_addr;
	addr = sin->sin_addr.s_addr;

	/* Now lookup for existing dynamic interface entries */
	num = lookup_existing_entries(ifm->ifm_index, addr);
	/*
	 * num = 1 means this entry is a static one.
	 * num = 0 means this entry is a dynamic existing entry
	 * We only care about dynamic entries here.
	 */
	if (num == 1) {
		mipverbose(("process_rtsock_msg: Uninteresting "
		    "static entry\n"));
		return;
	} else if (num == 0) {
		if (!(ifflags & IFF_UP)) {
			/* The entry is down ? Is it unplumbed ? */
			(void) delmaAdvConfigEntry(ifm->ifm_index);
		}
		return;
	}
	if (!(ifflags & IFF_UP)) {
		mipverbose(("process_rtsock_msg: Interface is down?\n"));
		return;
	}

	if ((d_entry = match_dynamic_table(lifr.lifr_name)) != NULL) {
		/*
		 * Create the dynamic interface entry into the
		 * ConfigHash table
		 */

		if (CreateInterfaceEntry(lifr.lifr_name,
		    d_entry->RegLifetime, d_entry->advertiseOnBcast,
		    DEFAULT_MIN_INTERVAL, DEFAULT_MAX_INTERVAL,
		    d_entry->AdvLifetime, 0, d_entry->AdvServiceflag,
		    d_entry->AdvPrefixflag, d_entry->RevtunAllowed,
		    d_entry->RevtunReqd, d_entry->AdvLimitUnsolicited,
		    d_entry->AdvInitCount, d_entry->AdvInterval,
		    _B_TRUE) != 0) {
			syslog(LOG_ERR,
			    "Unable to create dynamic Interface: %m");
			return;
		}
		/* Find my entry */

		if ((ifentry = (MaAdvConfigEntry *)findHashTableEntryUint(
		    &maAdvConfigHash, addr, LOCK_WRITE,
		    ConfigEntryHashLookup, (uint32_t)ifm->ifm_index, 0,
		    0)) == NULL) {
			syslog(LOG_CRIT,
			    "Can't find dynamic entry in Hash table");
			mipverbose(("process_rtsock_msg: Can't find dynamic "
			    "entry in Hash table\n"));
			return;
		}
		if (InitSockets(ifentry) != 0) {
			syslog(LOG_CRIT, "InitSockets failed for dynamic"
			    " Interface %s", ifentry->maIfaceName);
			(void) rw_unlock(&ifentry->maIfaceNodeLock);
			return;
		}
		/* Now set the FDs for advertisements */
		GET_TIME(currentTime);
		ifentry->maNextAdvTime = currentTime;
		FD_SET(ifentry->maIfaceUnicastSock, &saved_fdvec);
		if (!(ifflags & IFF_POINTOPOINT)) {
			FD_SET(ifentry->maIfaceDirBcastSock, &saved_fdvec);
			FD_SET(ifentry->maIfaceBcastSock, &saved_fdvec);
		}
		FD_SET(ifentry->maIfaceAdvMulticastSock, &saved_fdvec);
		FD_SET(ifentry->maIfaceRegMulticastSock, &saved_fdvec);
		FD_SET(ifentry->maIfaceIcmpSock, &saved_fdvec);
		(void) rw_unlock(&ifentry->maIfaceNodeLock);
		return;
	}
	mipverbose(("process_rtsock_msg: entry %s not found\n",
	    lifr.lifr_name));
}


/*
 * Function: Lookup_existing_entries
 * Description: Looks for any existing entry in config table.
 * returns :	1 if finds a static entry
 *		0 if finds a dynamic entry
 *		-1 if none found
 */

static int
lookup_existing_entries(ushort_t index, ipaddr_t ifaddr)
{
	MaAdvConfigEntry *	ifentry;

	ifentry = (MaAdvConfigEntry *)findHashTableEntryUint(
	    &maAdvConfigHash, ifaddr, LOCK_READ, ConfigEntryHashLookup,
	    (uint32_t)index, 0, 0);

	if (ifentry == NULL) {
		mipverbose(("lookup_existing_entries: "
		    "Can't find entry in Hash table for index %d\n",
		    index));
		return (-1);
	}
	/* found an existing entry */
	if (ifentry->maAdvDynamicInterface == _B_TRUE) {
		(void) rw_unlock(&ifentry->maIfaceNodeLock);
		return (0);
	} else {
		(void) rw_unlock(&ifentry->maIfaceNodeLock);
		return (1);
	}
}


/*
 * Function: match_dynamic_table
 * Argument : interface name
 *
 * Description:
 * Match the dynamic interface table to see if this interface
 * is valid to become a dynamic mobility interface.
 * dynamicIface list is handled by a single thread, thus
 * we are not locking here.
 * returns : DynamicIfceTypeEntry pointer
 */

static DynamicIfaceTypeEntry *
match_dynamic_table(char *ifname)
{
	DynamicIfaceTypeEntry *dynentry;
	int	typelen;


	dynentry = dynamicIfaceHead;
	while (dynentry != NULL) {
		typelen = strlen(dynentry->dynamicIfcetype);
		if ((strncmp(ifname, dynentry->dynamicIfcetype,
		    (size_t)typelen) == 0) &&
		    ((int)isdigit(ifname[typelen]) != 0)) {
			/* Matches devicename with dynamicIfacetype */
			mipverbose(("match_dynamic_table: matched entry\n"));
			return (dynentry);
		}
		dynentry = dynentry->next;
	}

	return (NULL);
}


/*
 * Function: delmaAdvConfigEntry
 * Argument: Interface index
 * Description: It can only take index, as there may be situation when
 *              it's too late to find name/addr info because the interface
 *		is gone (ENXIO error). So, in those cases we have no other
 *		info in hand and thus we have to go through the whole
 *		table and delete the entry.
 */
static void
delmaAdvConfigEntry(uint32_t index)
{

	MaAdvConfigEntry *ifentry;
	struct hash_entry *hash_entry;
	struct hash_table *conf_htbl;
	int		count;
	boolean_t	found = _B_FALSE;
	ipaddr_t	addr;


	conf_htbl = &maAdvConfigHash;

	/*
	 * The following search does not provide high performance
	 * result. The confighash table needs to be hashed with key
	 * <interface-index>. Currently all hashtables are hashed by
	 * address. But when delmaAdvConfigEntry() is called from
	 * process_rtsock_msg() routine, interface might be unplumbed
	 * already and thus the addr cannot be known. So we have to do
	 * a long search to compare the interface index for each entry.
	 * There could be two solutions in future to  address this:
	 * 1. hash configHash table with interface index
	 * 2. Or modify routing socket to return addr and flag etc with
	 * the routing socket message.
	 */

	for (count = 0; count < HASH_TBL_SIZE && !found; count++) {
		hash_entry = conf_htbl->buckets[count];
		while (hash_entry != NULL) {
			if (ConfigEntryHashLookup(hash_entry->data,
			    index, 0, 0)) {
				(void) rw_wrlock((rwlock_t *)hash_entry->data);
				found = _B_TRUE;
				break;
			}
			hash_entry = hash_entry->next;
		}
	}
	if (found) {
		ifentry = hash_entry->data;
		addr = ifentry->maIfaceAddr;
	} else {
		mipverbose(("delmaAdvConfigEntry: "
		    "Can't find dynamic entry in Hash table\n"));
		return;
	}
	/* close all sockets */
	FD_CLR(ifentry->maIfaceUnicastSock, &saved_fdvec);
	FD_CLR(ifentry->maIfaceAdvMulticastSock, &saved_fdvec);
	FD_CLR(ifentry->maIfaceRegMulticastSock, &saved_fdvec);
	FD_CLR(ifentry->maIfaceIcmpSock, &saved_fdvec);
	(void) close(ifentry->maIfaceUnicastSock);
	if (ifentry->maIfaceDirBcastSock > -1) {
		FD_CLR(ifentry->maIfaceDirBcastSock, &saved_fdvec);
		(void) close(ifentry->maIfaceDirBcastSock);
	}
	if (ifentry->maIfaceBcastSock > -1) {
		FD_CLR(ifentry->maIfaceBcastSock, &saved_fdvec);
		(void) close(ifentry->maIfaceBcastSock);
	}
	(void) close(ifentry->maIfaceAdvMulticastSock);
	(void) close(ifentry->maIfaceRegMulticastSock);
	(void) close(ifentry->maIfaceIcmpSock);

	if (delHashTableEntryUint(&maAdvConfigHash, ifentry, addr,
	    LOCK_NONE)) {
		/* Success: Entry has been taken out of the table */
		(void) rw_unlock(&(ifentry->maIfaceNodeLock));
		(void) rwlock_destroy(&(ifentry->maIfaceNodeLock));
		free(ifentry);
		mipverbose(("delmaAdvConfigEntry: deleted config entry\n"));
	}
}
