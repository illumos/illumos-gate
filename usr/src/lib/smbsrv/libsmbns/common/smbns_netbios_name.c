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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Description:
 *
 *	Contains base code for netbios name service.
 *
 *
 * 6.  DEFINED CONSTANTS AND VARIABLES
 *
 *   GENERAL:
 *
 *      SCOPE_ID                   The name of the NetBIOS scope.
 *
 *                                 This is expressed as a character
 *                                 string meeting the requirements of
 *                                 the domain name system and without
 *                                 a leading or trailing "dot".
 *
 *                                 An implementation may elect to make
 *                                 this a single global value for the
 *                                 node or allow it to be specified
 *                                 with each separate NetBIOS name
 *                                 (thus permitting cross-scope
 *                                 references.)
 *
 *      BROADCAST_ADDRESS          An IP address composed of the
 *                                 nodes's network and subnetwork
 *                                 numbers with all remaining bits set
 *                                 to one.
 *
 *                                 I.e. "Specific subnet" broadcast
 *                                 addressing according to section 2.3
 *                                 of RFC 950.
 *
 *      BCAST_REQ_RETRY_TIMEOUT    250 milliseconds.
 *                                 An adaptive timer may be used.
 *
 *      BCAST_REQ_RETRY_COUNT      3
 *
 *      UCAST_REQ_RETRY_TIMEOUT    5 seconds
 *                                 An adaptive timer may be used.
 *
 *      UCAST_REQ_RETRY_COUNT      3
 *
 *      MAX_DATAGRAM_LENGTH        576 bytes (default)
 *
 *
 *   NAME SERVICE:
 *
 *      REFRESH_TIMER              Negotiated with NAME for each name.
 *
 *      CONFLICT_TIMER             1 second
 *                                 Implementations may chose a longer
 *                                 value.
 *
 *
 *      NAME_SERVICE_TCP_PORT      137 (decimal)
 *
 *      NAME_SERVICE_UDP_PORT      137 (decimal)
 *
 *      INFINITE_TTL               0
 */

#include <unistd.h>
#include <syslog.h>
#include <stdlib.h>
#include <synch.h>
#include <errno.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <arpa/inet.h>
#include <net/if_arp.h>

#include <smbsrv/libsmbns.h>
#include <smbns_netbios.h>

#define	NAME_HEADER_SIZE 12

typedef struct name_reply {
	struct name_reply *forw;
	struct name_reply *back;
	struct name_packet *packet;
	struct addr_entry *addr;
	unsigned short name_trn_id;
	unsigned short flags;
} name_reply;

static struct name_reply reply_queue;
static mutex_t rq_mtx;

static mutex_t reply_mtx;
static cond_t reply_cv;

static name_queue_t delete_queue;
static name_queue_t refresh_queue;

/*
 * Flag to control whether or not NetBIOS name refresh requests
 * are logged. Set to non-zero to enable logging.
 */

static unsigned short netbios_name_transcation_id = 1;
static int name_sock = 0;

static int bcast_num = 0;
static int nbns_num = 0;
static struct addr_entry smb_bcast_list[SMB_PI_MAX_NETWORKS];
static struct addr_entry smb_nbns[SMB_PI_MAX_WINS];

static int smb_netbios_process_response(unsigned short, struct addr_entry *,
    struct name_packet *, uint32_t);

static int smb_send_name_service_packet(struct addr_entry *addr,
    struct name_packet *packet);

static int
smb_end_node_challenge(struct name_reply *reply_info)
{
	int			rc;
	uint32_t		retry;
	unsigned short		tid;
	struct resource_record	*answer;
	struct name_question	question;
	struct addr_entry 	*addr;
	struct name_entry 	*destination;
	struct name_packet	packet;
	struct timespec 	st;

	/*
	 * The response packet has in it the address of the presumed owner
	 * of the name.  Challenge that owner.  If owner either does not
	 * respond or indicates that he no longer owns the name, claim the
	 * name.  Otherwise, the name cannot be claimed.
	 */

	if ((answer = reply_info->packet->answer) == 0)
		return (-1);

	destination = answer->name;
	question.name = answer->name;

	packet.info = NAME_QUERY_REQUEST | NM_FLAGS_UNICAST;
	packet.qdcount = 1;	/* question entries */
	packet.question = &question;
	packet.ancount = 0;	/* answer recs */
	packet.answer = NULL;
	packet.nscount = 0;	/* authority recs */
	packet.authority = NULL;
	packet.arcount = 0;	/* additional recs */
	packet.additional = NULL;

	addr = &destination->addr_list;
	for (retry = 0; retry < UCAST_REQ_RETRY_COUNT; retry++) {
		tid = netbios_name_transcation_id++;
		packet.name_trn_id = tid;
		if (smb_send_name_service_packet(addr, &packet) >= 0) {
			if ((rc = smb_netbios_process_response(tid, addr,
			    &packet, UCAST_REQ_RETRY_TIMEOUT)) != 0)
				return (rc);
		}
		st.tv_sec = 0;
		st.tv_nsec = (UCAST_REQ_RETRY_TIMEOUT * 1000000);
		(void) nanosleep(&st, 0);
	}
	/* No reply */
	return (0);
}


static struct name_reply *
smb_name_get_reply(unsigned short tid, uint32_t timeout)
{
	unsigned short		info;
	struct resource_record	*answer;
	struct name_reply 	*reply;
	uint32_t 		wait_time, to_save; /* in millisecond */
	struct timeval 		wt;
	timestruc_t 		to;

	to_save = timeout;
	reply = (struct name_reply *)malloc(sizeof (struct name_reply));
	if (reply != 0) {
		reply->flags = 0;
		reply->name_trn_id = tid;
		(void) mutex_lock(&rq_mtx);
		QUEUE_INSERT_TAIL(&reply_queue, reply);
		(void) mutex_unlock(&rq_mtx);

		for (;;) {
			(void) gettimeofday(&wt, 0);
			wait_time = wt.tv_usec / 1000;

			(void) mutex_lock(&reply_mtx);
			to.tv_sec = 0;
			to.tv_nsec = timeout * 1000000;
			(void) cond_reltimedwait(&reply_cv, &reply_mtx, &to);
			(void) mutex_unlock(&reply_mtx);

			if (reply->flags != 0) {
				info = reply->packet->info;
				if (PACKET_TYPE(info) == WACK_RESPONSE) {
					answer = reply->packet->answer;
					wait_time = (answer) ?
					    TO_MILLISECONDS(answer->ttl) :
					    DEFAULT_TTL;
					free(reply->addr);
					free(reply->packet);
					timeout = to_save + wait_time;
					reply->flags = 0;
					reply->name_trn_id = tid;
					(void) mutex_lock(&rq_mtx);
					QUEUE_INSERT_TAIL(&reply_queue, reply);
					(void) mutex_unlock(&rq_mtx);
					continue;
				}
				return (reply);
			}
			(void) gettimeofday(&wt, 0);
			wait_time = (wt.tv_usec / 1000) - wait_time;
			if (wait_time >= timeout) {
				(void) mutex_lock(&rq_mtx);
				QUEUE_CLIP(reply);
				(void) mutex_unlock(&rq_mtx);
				free(reply);
				break;
			}
			timeout -= wait_time;
		}
	}

	return (0);
}

static void
smb_reply_ready(struct name_packet *packet, struct addr_entry *addr)
{
	struct name_reply *reply;
	struct resource_record *answer;

	(void) mutex_lock(&rq_mtx);
	for (reply = reply_queue.forw; reply != &reply_queue;
	    reply = reply->forw) {
		if (reply->name_trn_id == packet->name_trn_id) {
			QUEUE_CLIP(reply);
			(void) mutex_unlock(&rq_mtx);

			reply->addr = addr;
			reply->packet = packet;

			(void) mutex_lock(&reply_mtx);
			reply->flags |= 0x0001; /* reply ready */
			(void) cond_signal(&reply_cv);
			(void) mutex_unlock(&reply_mtx);

			return;
		}
	}
	(void) mutex_unlock(&rq_mtx);

	/* Presumably nobody is waiting any more... */
	free(addr);

	answer = packet->answer;
	if (answer)
		smb_netbios_name_freeaddrs(answer->name);
	free(packet);
}

static int
smb_netbios_process_response(unsigned short tid, struct addr_entry *addr,
    struct name_packet *packet, uint32_t timeout)
{
	int			rc = 0;
	unsigned short		info;
	struct name_reply 	*reply;
	struct resource_record	*answer;
	struct name_entry 	*name;
	struct name_entry 	*entry;
	struct name_question 	*question;
	uint32_t 		ttl;

	if ((reply = smb_name_get_reply(tid, timeout)) == 0) {
		return (0); /* No reply: retry */
	}
	info = reply->packet->info;
	answer = reply->packet->answer;

	/* response */
	switch (PACKET_TYPE(info)) {
	case NAME_QUERY_RESPONSE:
		if (POSITIVE_RESPONSE(info)) {
			addr = &answer->name->addr_list;
			do {
				/*
				 * Make sure that remote name is not
				 * flagged local
				 */
				addr->attributes &= ~NAME_ATTR_LOCAL;

				addr->refresh_ttl = addr->ttl =
				    (answer && answer->ttl) ?
				    (answer->ttl >> 1) :
				    TO_SECONDS(DEFAULT_TTL);
				addr = addr->forw;
			} while (addr != &answer->name->addr_list);
			smb_netbios_name_dump(answer->name);
			(void) smb_netbios_cache_insert_list(answer->name);
			rc = 1;
		} else {
			rc = -1;
		}
		break;

	case NAME_REGISTRATION_RESPONSE:
		if (NEGATIVE_RESPONSE(info)) {
			if (RCODE(info) == RCODE_CFT_ERR) {
				if (answer == 0) {
					rc = -RCODE(info);
					break;
				}

				name = answer->name;
				entry = smb_netbios_cache_lookup(name);
				if (entry) {
					/*
					 * a name in the state "conflict
					 * detected" does not "logically" exist
					 * on that node. No further session
					 * will be accepted on that name.
					 * No datagrams can be sent against
					 * that name.
					 * Such an entry will not be used for
					 * purposes of processing incoming
					 * request packets.
					 * The only valid user NetBIOS operation
					 * against such a name is DELETE NAME.
					 */
					entry->attributes |= NAME_ATTR_CONFLICT;
					syslog(LOG_DEBUG,
					    "NETBIOS Name conflict: %15.15s",
					    entry->name);
					smb_netbios_cache_unlock_entry(entry);
				}
			}
			rc = -RCODE(info);
			break;
		}

		/*
		 * name can be added:
		 *   adjust refresh timeout value,
		 *   TTL, for this name
		 */
		question = packet->question;
		ttl = (answer && answer->ttl) ? answer->ttl >> 1
		    : TO_SECONDS(DEFAULT_TTL);
		if ((entry = smb_netbios_cache_lookup(question->name)) != 0) {
			addr = &entry->addr_list;
			do {
				if ((addr->refresh_ttl == 0) ||
				    (ttl < addr->refresh_ttl))
					addr->refresh_ttl = addr->ttl = ttl;
				addr = addr->forw;
			} while (addr != &entry->addr_list);
			smb_netbios_cache_unlock_entry(entry);
		}

		rc = 1;
		break;

	case NAME_RELEASE_RESPONSE:
		rc = 1;
		break;

	case END_NODE_CHALLENGE_REGISTRATION_REQUEST:
		/*
		 * The response packet has in it the
		 * address of the presumed owner of the
		 * name.  Challenge that owner.  If
		 * owner either does not respond or
		 * indicates that he no longer owns the
		 * name, claim the name.  Otherwise,
		 * the name cannot be claimed.
		 */
		rc = smb_end_node_challenge(reply);
		break;

	default:
		rc = 0;
		break;
	}

	if (answer)
		smb_netbios_name_freeaddrs(answer->name);
	free(reply->addr);
	free(reply->packet);
	free(reply);
	return (rc);  /* retry */
}

/*
 * smb_name_buf_from_packet
 *
 * Description:
 *	Convert a NetBIOS Name Server Packet Block (npb)
 *	into the bits and bytes destined for the wire.
 *	The "buf" is used as a heap.
 *
 * Inputs:
 *	char *		buf	-> Buffer, from the wire
 *	unsigned	n_buf	-> Length of 'buf'
 *	name_packet	*npb	-> Packet block, decode into
 *	unsigned	n_npb	-> Max bytes in 'npb'
 *
 * Returns:
 *	>0	-> Encode successful, value is length of packet in "buf"
 *	-1	-> Hard error, can not possibly encode
 *	-2	-> Need more memory in buf -- it's too small
 */

static int
smb_name_buf_from_packet(unsigned char *buf,
    int n_buf,
    struct name_packet *npb)
{
	struct addr_entry 	*raddr;
	unsigned char 		*heap = buf;
	unsigned char 		*end_heap = heap + n_buf;
	unsigned char 		*dnptrs[32];
	unsigned char		comp_name_buf[MAX_NAME_LENGTH];
	unsigned int		tmp;
	int			i, step;

	if (n_buf < NAME_HEADER_SIZE)
		return (-1);		/* no header, impossible */

	dnptrs[0] = heap;
	dnptrs[1] = 0;

	BE_OUT16(heap, npb->name_trn_id);
	heap += 2;

	BE_OUT16(heap, npb->info);
	heap += 2;

	BE_OUT16(heap, npb->qdcount);
	heap += 2;

	BE_OUT16(heap, npb->ancount);
	heap += 2;

	BE_OUT16(heap, npb->nscount);
	heap += 2;

	BE_OUT16(heap, npb->arcount);
	heap += 2;

	for (i = 0; i < npb->qdcount; i++) {
		if ((heap + 34 + 4) > end_heap)
			return (-2);

		(void) smb_first_level_name_encode(npb->question[i].name,
		    comp_name_buf, sizeof (comp_name_buf));
		(void) strcpy((char *)heap, (char *)comp_name_buf);
		heap += strlen((char *)comp_name_buf) + 1;

		BE_OUT16(heap, npb->question[i].question_type);
		heap += 2;

		BE_OUT16(heap, npb->question[i].question_class);
		heap += 2;
	}

	for (step = 1; step <= 3; step++) {
		struct resource_record *nrr;
		int n;

		/* truly ugly, but saves code copying */
		if (step == 1) {
			n = npb->ancount;
			nrr = npb->answer;
		} else if (step == 2) {
			n = npb->nscount;
			nrr = npb->authority;
		} else { /* step == 3 */
			n = npb->arcount;
			nrr = npb->additional;
		}

		for (i = 0; i < n; i++) {
			if ((heap + 34 + 10) > end_heap)
				return (-2);

			(void) smb_first_level_name_encode(nrr->name,
			    comp_name_buf, sizeof (comp_name_buf));
			(void) strcpy((char *)heap, (char *)comp_name_buf);
			heap += strlen((char *)comp_name_buf) + 1;

			BE_OUT16(heap, nrr[i].rr_type);
			heap += 2;

			BE_OUT16(heap, nrr[i].rr_class);
			heap += 2;

			BE_OUT32(heap, nrr[i].ttl);
			heap += 4;

			BE_OUT16(heap, nrr[i].rdlength);
			heap += 2;

			if ((tmp = nrr[i].rdlength) > 0) {
				if ((heap + tmp) > end_heap)
					return (-2);

				if (nrr[i].rr_type == NAME_RR_TYPE_NB &&
				    nrr[i].rr_class == NAME_RR_CLASS_IN &&
				    tmp >= 6 && nrr[i].rdata == 0) {
					tmp = nrr[i].name->attributes &
					    (NAME_ATTR_GROUP |
					    NAME_ATTR_OWNER_NODE_TYPE);
					BE_OUT16(heap, tmp);
					heap += 2;

					raddr = &nrr[i].name->addr_list;
					(void) memcpy(heap,
					    &raddr->sin.sin_addr.s_addr,
					    sizeof (uint32_t));
					heap += 4;
				} else {
					bcopy(nrr[i].rdata, heap, tmp);
					heap += tmp;
				}
			}
		}
	}
	return (heap - buf);
}

/*
 * strnchr
 *
 * Lookup for character 'c' in first 'n' chars of string 's'.
 * Returns pointer to the found char, otherwise returns 0.
 */
static char *
strnchr(const char *s, char c, int n)
{
	char *ps = (char *)s;
	char *es = (char *)s + n;

	while (ps < es && *ps) {
		if (*ps == c)
			return (ps);

		++ps;
	}

	if (*ps == '\0' && c == '\0')
		return (ps);

	return (0);
}

static boolean_t
is_multihome(char *name)
{
	return (smb_nic_getnum(name) > 1);
}

/*
 * smb_netbios_getname
 *
 * Get the Netbios name part of the given record.
 * Does some boundary checks.
 *
 * Returns the name length on success, otherwise
 * returns 0.
 */
static int
smb_netbios_getname(char *name, char *buf, char *buf_end)
{
	char *name_end;
	int name_len;

	if (buf >= buf_end) {
		/* no room for a NB name */
		return (0);
	}

	name_end = strnchr(buf, '\0', buf_end - buf + 1);
	if (name_end == 0) {
		/* not a valid NB name */
		return (0);
	}

	name_len = name_end - buf + 1;

	(void) strlcpy(name, buf, name_len);
	return (name_len);
}


/*
 * smb_name_buf_to_packet
 *
 * Description:
 *	Convert the bits and bytes that came from the wire
 *	into a NetBIOS Name Server Packet Block (npb).
 *	The "block" is used as a heap.
 *
 * Inputs:
 *	char *		buf	-> Buffer, from the wire
 *	int		n_buf	-> Length of 'buf'
 *	name_packet	*npb	-> Packet block, decode into
 *	int		n_npb	-> Max bytes in 'npb'
 *
 * Returns:
 *	>0	-> Decode (parse) successful, value is byte length of npb
 *	-1	-> Hard error, can not possibly decode
 *	-2	-> Need more memory in npb -- it's too small
 */

static struct name_packet *
smb_name_buf_to_packet(char *buf, int n_buf)
{
	struct name_packet *npb;
	unsigned char *heap;
	unsigned char *scan = (unsigned char *)buf;
	unsigned char *scan_end = scan + n_buf;
	char name_buf[MAX_NAME_LENGTH];
	struct resource_record *nrr = 0;
	int	rc, i, n, nn, ns;
	unsigned short name_trn_id, info;
	unsigned short qdcount, ancount, nscount, arcount;
	struct addr_entry *next;
	int name_len;

	if (n_buf < NAME_HEADER_SIZE) {
		/* truncated header */
		syslog(LOG_DEBUG, "SmbNBNS: packet is too short (%d)",
		    n_buf);
		return (0);
	}

	name_trn_id = BE_IN16(scan); scan += 2;
	info = BE_IN16(scan); scan += 2;
	qdcount = BE_IN16(scan); scan += 2;
	ancount = BE_IN16(scan); scan += 2;
	nscount = BE_IN16(scan); scan += 2;
	arcount = BE_IN16(scan); scan += 2;

	ns = sizeof (struct name_entry);
	n = n_buf + sizeof (struct name_packet) +
	    ((unsigned)qdcount * (sizeof (struct name_question) + ns)) +
	    ((unsigned)ancount * (sizeof (struct resource_record) + ns)) +
	    ((unsigned)nscount * (sizeof (struct resource_record) + ns)) +
	    ((unsigned)arcount * (sizeof (struct resource_record) + ns));

	if ((npb = (struct name_packet *)malloc(n)) == 0) {
		return (0);
	}
	bzero(npb, n);

	heap = npb->block_data;
	npb->name_trn_id = name_trn_id;
	npb->info = info;
	npb->qdcount = qdcount;
	npb->ancount = ancount;
	npb->nscount = nscount;
	npb->arcount = arcount;

	/* scan is in position for question entries */

	/*
	 * Measure the space needed for the tables
	 */
	if (qdcount > 0) {
		/* LINTED - E_BAD_PTR_CAST_ALIGN */
		npb->question = (struct name_question *)heap;
		heap += qdcount * sizeof (struct name_question);
		for (i = 0; i < qdcount; i++) {
			/* LINTED - E_BAD_PTR_CAST_ALIGN */
			npb->question[i].name = (struct name_entry *)heap;
			heap += sizeof (struct name_entry);
		}
	}

	/* LINTED - E_BAD_PTR_CAST_ALIGN */
	nrr = (struct resource_record *)heap;

	if (ancount > 0) {
		/* LINTED - E_BAD_PTR_CAST_ALIGN */
		npb->answer = (struct resource_record *)heap;
		heap += ancount * sizeof (struct resource_record);
	}

	if (nscount > 0) {
		/* LINTED - E_BAD_PTR_CAST_ALIGN */
		npb->authority = (struct resource_record *)heap;
		heap += nscount * sizeof (struct resource_record);
	}

	if (arcount > 0) {
		/* LINTED - E_BAD_PTR_CAST_ALIGN */
		npb->additional = (struct resource_record *)heap;
		heap += arcount * sizeof (struct resource_record);
	}

	/*
	 * Populate each resource_record's .name field.
	 * Done as a second pass so that all resource records
	 * (answer, authority, additional) are consecutive via nrr[i].
	 */
	for (i = 0; i < (ancount + nscount + arcount); i++) {
		/* LINTED - E_BAD_PTR_CAST_ALIGN */
		nrr[i].name = (struct name_entry *)heap;
		heap += sizeof (struct name_entry);
	}


	for (i = 0; i < npb->qdcount; i++) {
		name_len = smb_netbios_getname(name_buf, (char *)scan,
		    (char *)scan_end);
		if (name_len <= 0) {
			free(npb);
			return (0);
		}

		smb_init_name_struct(NETBIOS_EMPTY_NAME, 0, 0, 0, 0, 0, 0,
		    npb->question[i].name);
		rc = smb_first_level_name_decode((unsigned char *)name_buf,
		    npb->question[i].name);
		if (rc < 0) {
			/* Couldn't decode the question name */
			free(npb);
			return (0);
		}

		scan += name_len;
		if (scan + 4 > scan_end) {
			/* no room for Question Type(2) and Class(2) fields */
			free(npb);
			return (0);
		}

		npb->question[i].question_type = BE_IN16(scan); scan += 2;
		npb->question[i].question_class = BE_IN16(scan); scan += 2;
	}

	/*
	 * Cheat. Remaining sections are of the same resource_record
	 * format. Table space is consecutive.
	 */

	for (i = 0; i < (ancount + nscount + arcount); i++) {
		if (scan[0] == 0xc0) {
			/* Namebuf is reused... */
			rc = 2;
		} else {
			name_len = smb_netbios_getname(name_buf, (char *)scan,
			    (char *)scan_end);
			if (name_len <= 0) {
				free(npb);
				return (0);
			}
			rc = name_len;
		}
		scan += rc;

		if (scan + 10 > scan_end) {
			/*
			 * no room for RR_TYPE (2), RR_CLASS (2), TTL (4) and
			 * RDLENGTH (2) fields.
			 */
			free(npb);
			return (0);
		}

		smb_init_name_struct(NETBIOS_EMPTY_NAME, 0, 0, 0, 0, 0, 0,
		    nrr[i].name);
		if ((rc = smb_first_level_name_decode((unsigned char *)name_buf,
		    nrr[i].name)) < 0) {
			free(npb);
			return (0);
		}

		nrr[i].rr_type = BE_IN16(scan); scan += 2;
		nrr[i].rr_class = BE_IN16(scan); scan += 2;
		nrr[i].ttl = BE_IN32(scan); scan += 4;
		nrr[i].rdlength = BE_IN16(scan); scan += 2;

		if ((n = nrr[i].rdlength) > 0) {
			if ((scan + n) > scan_end) {
				/* no room for RDATA */
				free(npb);
				return (0);
			}
			bcopy(scan, heap, n);

			nn = n;
			if (nrr[i].rr_type == 0x0020 &&
			    nrr[i].rr_class == 0x01 && n >= 6) {
				while (nn) {
					if (nn == 6)
						next = &nrr[i].name->addr_list;
					else {
						next = (struct addr_entry *)
						    malloc(
						    sizeof (struct addr_entry));
						if (next == 0) {
							/* not enough memory */
							free(npb);
							return (0);
						}
						QUEUE_INSERT_TAIL(
						    &nrr[i].name->addr_list,
						    next);
					}
					nrr[i].name->attributes =
					    BE_IN16(scan);
					next->sin.sin_family = AF_INET;
					next->sinlen = sizeof (next->sin);
					(void) memcpy(
					    &next->sin.sin_addr.s_addr,
					    scan + 2, sizeof (uint32_t));
					next->sin.sin_port =
					    htons(DGM_SRVC_UDP_PORT);
					nn -= 6;
					scan += 6;
				}
			} else {
				nrr[i].rdata = heap;
				scan += n;
			}
			heap += n;
		}
	}
	return (npb);
}


/*
 * smb_send_name_service_packet
 *
 * Description:
 *
 *	Send out a name service packet to proper destination.
 *
 * Inputs:
 *	struct netbios_name *dest	-> NETBIOS name of destination
 *	struct name_packet *packet	-> Packet to send
 *
 * Returns:
 *	success	->  >0
 *	failure	-> <=0
 */

static int
smb_send_name_service_packet(struct addr_entry *addr,
				struct name_packet *packet)
{
	unsigned char buf[MAX_DATAGRAM_LENGTH];
	int len;

	if ((len = smb_name_buf_from_packet(buf, sizeof (buf), packet)) < 0) {
		errno = EINVAL;
		return (-1);
	}

	return (sendto(name_sock, buf, len, MSG_EOR,
	    (struct sockaddr *)&addr->sin, addr->sinlen));
}

/*
 * 4.2.1.1.  HEADER
 *
 *                        1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |         NAME_TRN_ID           | OPCODE  |   NM_FLAGS  | RCODE |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |          QDCOUNT              |           ANCOUNT             |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |          NSCOUNT              |           ARCOUNT             |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 *   Field     Description
 *
 *   NAME_TRN_ID      Transaction ID for Name Service Transaction.
 *                    Requester places a unique value for each active
 *                    transaction.  Responder puts NAME_TRN_ID value
 *                    from request packet in response packet.
 *
 *   OPCODE           Packet type code, see table below.
 *
 *   NM_FLAGS         Flags for operation, see table below.
 *
 *   RCODE            Result codes of request.  Table of RCODE values
 *                    for each response packet below.
 *
 *   QDCOUNT          Unsigned 16 bit integer specifying the number of
 *                    entries in the question section of a Name
 *
 *                    Service packet.  Always zero (0) for responses.
 *                    Must be non-zero for all NetBIOS Name requests.
 *
 *   ANCOUNT          Unsigned 16 bit integer specifying the number of
 *                    resource records in the answer section of a Name
 *                    Service packet.
 *
 *   NSCOUNT          Unsigned 16 bit integer specifying the number of
 *                    resource records in the authority section of a
 *                    Name Service packet.
 *
 *   ARCOUNT          Unsigned 16 bit integer specifying the number of
 *                    resource records in the additional records
 *                    section of a Name Service packet.
 *
 *   The OPCODE field is defined as:
 *
 *     0   1   2   3   4
 *   +---+---+---+---+---+
 *   | R |    OPCODE     |
 *   +---+---+---+---+---+
 *
 *   Symbol     Bit(s)   Description
 *
 *   OPCODE        1-4   Operation specifier:
 *                         0 = query
 *                         5 = registration
 *                         6 = release
 *                         7 = WACK
 *                         8 = refresh
 *
 *   R               0   RESPONSE flag:
 *                         if bit == 0 then request packet
 *                         if bit == 1 then response packet.
 */


/*
 *   The NM_FLAGS field is defined as:
 *
 *
 *     0   1   2   3   4   5   6
 *   +---+---+---+---+---+---+---+
 *   |AA |TC |RD |RA | 0 | 0 | B |
 *   +---+---+---+---+---+---+---+
 *
 *   Symbol     Bit(s)   Description
 *
 *   B               6   Broadcast Flag.
 *                         = 1: packet was broadcast or multicast
 *                         = 0: unicast
 *
 *   RA              3   Recursion Available Flag.
 *
 *                       Only valid in responses from a NetBIOS Name
 *                       Server -- must be zero in all other
 *                       responses.
 *
 *                       If one (1) then the NAME supports recursive
 *                       query, registration, and release.
 *
 *                       If zero (0) then the end-node must iterate
 *                       for query and challenge for registration.
 *
 *   RD              2   Recursion Desired Flag.
 *
 *                       May only be set on a request to a NetBIOS
 *                       Name Server.
 *
 *                       The NAME will copy its state into the
 *                       response packet.
 *
 *                       If one (1) the NAME will iterate on the
 *                       query, registration, or release.
 *
 *   TC              1   Truncation Flag.
 *
 *                       Set if this message was truncated because the
 *                       datagram carrying it would be greater than
 *                       576 bytes in length.  Use TCP to get the
 *                       information from the NetBIOS Name Server.
 *
 *   AA              0   Authoritative Answer flag.
 *
 *                       Must be zero (0) if R flag of OPCODE is zero
 *                       (0).
 *
 *                       If R flag is one (1) then if AA is one (1)
 *                       then the node responding is an authority for
 *                       the domain name.
 *
 *                       End nodes responding to queries always set
 *                       this bit in responses.
 *
 */

/*
 * 4.2.1.2.  QUESTION SECTION
 *
 *                        1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                                                               |
 *   /                         QUESTION_NAME                         /
 *   /                                                               /
 *   |                                                               |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |         QUESTION_TYPE         |        QUESTION_CLASS         |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 *   Field            Description
 *
 *   QUESTION_NAME    The compressed name representation of the
 *                    NetBIOS name for the request.
 *
 *   QUESTION_TYPE    The type of request.  The values for this field
 *                    are specified for each request.
 *
 *   QUESTION_CLASS   The class of the request.  The values for this
 *                    field are specified for each request.
 *
 *   QUESTION_TYPE is defined as:
 *
 *   Symbol      Value   Description:
 *
 *   NB         0x0020   NetBIOS general Name Service Resource Record
 *   NBSTAT     0x0021   NetBIOS NODE STATUS Resource Record (See NODE
 *                       STATUS REQUEST)
 *
 *   QUESTION_CLASS is defined as:
 *
 *   Symbol      Value   Description:
 *
 *   IN         0x0001   Internet class
 */

#define	QUESTION_TYPE_NETBIOS_GENERAL	0x20
#define	QUESTION_TYPE_NETBIOS_STATUS	0x21

#define	QUESTION_CLASS_INTERNET		0x0001

/*
 *
 * 4.2.1.3.  RESOURCE RECORD
 *
 *                        1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                                                               |
 *   /                            RR_NAME                            /
 *   /                                                               /
 *   |                                                               |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |           RR_TYPE             |          RR_CLASS             |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                              TTL                              |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |           RDLENGTH            |                               |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               |
 *   /                                                               /
 *   /                             RDATA                             /
 *   |                                                               |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 *   Field            Description
 *
 *   RR_NAME          The compressed name representation of the
 *                    NetBIOS name corresponding to this resource
 *                    record.
 *
 *   RR_TYPE          Resource record type code
 *
 *   RR_CLASS         Resource record class code
 *
 *   TTL              The Time To Live of a the resource record's
 *                    name.
 *
 *   RDLENGTH         Unsigned 16 bit integer that specifies the
 *                    number of bytes in the RDATA field.
 *
 *   RDATA            RR_CLASS and RR_TYPE dependent field.  Contains
 *                    the resource information for the NetBIOS name.
 *
 *   RESOURCE RECORD RR_TYPE field definitions:
 *
 *   Symbol      Value   Description:
 *
 *   A          0x0001   IP address Resource Record (See REDIRECT NAME
 *                       QUERY RESPONSE)
 *   NS         0x0002   Name Server Resource Record (See REDIRECT
 *                       NAME QUERY RESPONSE)
 *   NULL       0x000A   NULL Resource Record (See WAIT FOR
 *                       ACKNOWLEDGEMENT RESPONSE)
 *   NB         0x0020   NetBIOS general Name Service Resource Record
 *                       (See NB_FLAGS and NB_ADDRESS, below)
 *   NBSTAT     0x0021   NetBIOS NODE STATUS Resource Record (See NODE
 *                       STATUS RESPONSE)
 */

#define	RR_TYPE_IP_ADDRESS_RESOURCE	0x0001
#define	RR_TYPE_NAME_SERVER_RESOURCE	0x0002
#define	RR_TYPE_NULL_RESOURCE		0x000A
#define	RR_TYPE_NETBIOS_RESOURCE	0x0020
#define	RR_TYPE_NETBIOS_STATUS		0x0021

/*
 *
 *   RESOURCE RECORD RR_CLASS field definitions:
 *
 *   Symbol      Value   Description:
 *
 *   IN         0x0001   Internet class
 */
#define	RR_CLASS_INTERNET_CLASS		0x0001

/*
 *
 *   NB_FLAGS field of the RESOURCE RECORD RDATA field for RR_TYPE of
 *   "NB":
 *
 *                                             1   1   1   1   1   1
 *     0   1   2   3   4   5   6   7   8   9   0   1   2   3   4   5
 *   +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
 *   | G |  ONT  |                RESERVED                           |
 *   +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
 *
 *   Symbol     Bit(s)   Description:
 *
 *   RESERVED     3-15   Reserved for future use.  Must be zero (0).
 *   ONT           1,2   Owner Node Type:
 *                          00 = B node
 *                          01 = P node
 *                          10 = M node
 *                          11 = Reserved for future use
 *                       For registration requests this is the
 *                       claimant's type.
 *                       For responses this is the actual owner's
 *                       type.
 *
 *   G               0   Group Name Flag.
 *                       If one (1) then the RR_NAME is a GROUP
 *                       NetBIOS name.
 *                       If zero (0) then the RR_NAME is a UNIQUE
 *                       NetBIOS name.
 *
 *   The NB_ADDRESS field of the RESOURCE RECORD RDATA field for
 *   RR_TYPE of "NB" is the IP address of the name's owner.
 *
 */
#define	RR_FLAGS_NB_ONT_MASK		0x6000
#define	RR_FLAGS_NB_ONT_B_NODE		0x0000
#define	RR_FLAGS_NB_ONT_P_NODE		0x2000
#define	RR_FLAGS_NB_ONT_M_NODE		0x4000
#define	RR_FLAGS_NB_ONT_RESERVED	0x6000

#define	RR_FLAGS_NB_GROUP_NAME		0x8000

/*
 * smb_netbios_send_rcv
 *
 * This function sends the given NetBIOS packet to the given
 * address and get back the response. If send operation is not
 * successful, it's repeated 'retries' times.
 *
 * Returns:
 *		0		Unsuccessful send operation; no reply
 *		1		Got reply
 */
static int
smb_netbios_send_rcv(int bcast, struct addr_entry *destination,
					struct name_packet *packet,
					uint32_t retries, uint32_t timeout)
{
	uint32_t retry;
	unsigned short	tid;
	struct timespec st;
	int	rc;

	for (retry = 0; retry < retries; retry++) {
		if ((destination->flags & ADDR_FLAG_VALID) == 0)
			return (0);

		tid = netbios_name_transcation_id++;
		packet->name_trn_id = tid;
		if (smb_send_name_service_packet(destination, packet) >= 0) {
			rc = smb_netbios_process_response(tid, destination,
			    packet, timeout);

			if ((rc > 0) || (bcast == BROADCAST))
				return (1);

			if (rc != 0)
				return (0);
		}

		st.tv_sec = 0;
		st.tv_nsec = (timeout * 1000000);
		(void) nanosleep(&st, 0);
	}

	return (0);
}

/*
 * 4.2.2.  NAME REGISTRATION REQUEST
 *
 *                        1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |         NAME_TRN_ID           |0|  0x5  |0|0|1|0|0 0|B|  0x0  |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |          0x0001               |           0x0000              |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |          0x0000               |           0x0001              |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                                                               |
 *   /                         QUESTION_NAME                         /
 *   /                                                               /
 *   |                                                               |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |           NB (0x0020)         |        IN (0x0001)            |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                                                               |
 *   /                            RR_NAME                            /
 *   /                                                               /
 *   |                                                               |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |           NB (0x0020)         |         IN (0x0001)           |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                              TTL                              |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |           0x0006              |          NB_FLAGS             |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                          NB_ADDRESS                           |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 *   Since the RR_NAME is the same name as the QUESTION_NAME, the
 *   RR_NAME representation must use pointers to the QUESTION_NAME
 *   name's labels to guarantee the length of the datagram is less
 *   than the maximum 576 bytes.  See section above on name formats
 *   and also page 31 and 32 of RFC 883, Domain Names - Implementation
 *   and Specification, for a complete description of compressed name
 *   label pointers.
 */
static int
smb_send_name_registration_request(int bcast, struct name_question *question,
    struct resource_record *additional)
{
	int gotreply = 0;
	uint32_t retries;
	uint32_t timeout;
	struct addr_entry *destination;
	struct name_packet packet;
	unsigned char type;
	int i, addr_num, rc;

	type = question->name->name[15];
	if ((type != 0x00) && (type != 0x20)) {
		syslog(LOG_ERR, "netbios: error trying to register"
		    " non-local name");
		smb_netbios_name_logf(question->name);
		question->name->attributes &= ~NAME_ATTR_LOCAL;
		return (-1);
	}

	if (bcast == BROADCAST) {
		if (bcast_num == 0)
			return (0);
		destination = smb_bcast_list;
		addr_num = bcast_num;
		retries = BCAST_REQ_RETRY_COUNT;
		timeout = BCAST_REQ_RETRY_TIMEOUT;
		packet.info = NAME_REGISTRATION_REQUEST | NM_FLAGS_BROADCAST;
	} else {
		if (nbns_num == 0)
			return (0);
		destination = smb_nbns;
		addr_num = nbns_num;
		retries = UCAST_REQ_RETRY_COUNT;
		timeout = UCAST_REQ_RETRY_TIMEOUT;
		packet.info = NAME_REGISTRATION_REQUEST | NM_FLAGS_UNICAST;
	}

	packet.qdcount = 1;	/* question entries */
	packet.question = question;
	packet.ancount = 0;	/* answer recs */
	packet.answer = NULL;
	packet.nscount = 0;	/* authority recs */
	packet.authority = NULL;
	packet.arcount = 1;	/* additional recs */
	packet.additional = additional;

	if (IS_UNIQUE(question->name->attributes) &&
	    (is_multihome((char *)(question->name->name))))
		packet.info |= NAME_MULTIHOME_REGISTRATION_REQUEST;

	for (i = 0; i < addr_num; i++) {
		/*
		 * Only register with the Primary WINS server,
		 * unless we got no reply.
		 */
		if ((bcast == UNICAST) && gotreply)
			break;

		rc = smb_netbios_send_rcv(bcast, &destination[i], &packet,
		    retries, timeout);
		if (rc == 1)
			gotreply = 1;
	}

	return (gotreply);
}

/*
 *
 * 4.2.4.  NAME REFRESH REQUEST
 *
 *                        1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |         NAME_TRN_ID           |0|  0x8  |0|0|0|0|0 0|B|  0x0  |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |          0x0001               |           0x0000              |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |          0x0000               |           0x0001              |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                                                               |
 *   /                         QUESTION_NAME                         /
 *   /                                                               /
 *   |                                                               |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |           NB (0x0020)         |        IN (0x0001)            |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                                                               |
 *   /                            RR_NAME                            /
 *   /                                                               /
 *   |                                                               |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |           NB (0x0020)         |         IN (0x0001)           |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                              TTL                              |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |           0x0006              |          NB_FLAGS             |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                          NB_ADDRESS                           |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
/*ARGSUSED*/
static int
smb_send_name_refresh_request(int bcast, struct name_question *question,
    struct resource_record *additional, int force)
{
	int rc = 0;
	int gotreply = 0;
	uint32_t retries;
	uint32_t timeout;
	struct addr_entry *addr;
	struct addr_entry *destination;
	struct name_packet packet;
	unsigned char type;
	int i, addr_num, q_addrs = 0;

	type = question->name->name[15];
	if ((type != 0x00) && (type != 0x20)) {
		syslog(LOG_ERR, "attempt to refresh non-local name");
		smb_netbios_name_logf(question->name);
		question->name->attributes &= ~NAME_ATTR_LOCAL;
		return (-1);
	}
	switch (bcast) {
	case BROADCAST :
		if (bcast_num == 0)
			return (-1);
		destination = smb_bcast_list;
		addr_num = bcast_num;
		retries = BCAST_REQ_RETRY_COUNT;
		timeout = BCAST_REQ_RETRY_TIMEOUT;
		packet.info = NAME_REFRESH_REQUEST | NM_FLAGS_BROADCAST;
		break;

	case UNICAST :
		if (nbns_num == 0)
			return (-1);
		destination = smb_nbns;
		addr_num = nbns_num;
		retries = UCAST_REQ_RETRY_COUNT;
		timeout = UCAST_REQ_RETRY_TIMEOUT;
		packet.info = NAME_REFRESH_REQUEST | NM_FLAGS_UNICAST;
		break;

	default:
		destination = &question->name->addr_list;
		/*
		 * the value of addr_num is irrelvant here, because
		 * the code is going to do special_process so it doesn't
		 * need the addr_num. We set a value here just to avoid
		 * compiler warning.
		 */
		addr_num = 0;
		retries = UCAST_REQ_RETRY_COUNT;
		timeout = UCAST_REQ_RETRY_TIMEOUT;
		packet.info = NAME_REFRESH_REQUEST | NM_FLAGS_UNICAST;
		q_addrs = 1;
		break;
	}

	if (IS_UNIQUE(question->name->attributes) &&
	    (is_multihome((char *)(question->name->name))))
		packet.info |= NAME_MULTIHOME_REGISTRATION_REQUEST;

	packet.qdcount = 1;	/* question entries */
	packet.question = question;
	packet.ancount = 0;	/* answer recs */
	packet.answer = NULL;
	packet.nscount = 0;	/* authority recs */
	packet.authority = NULL;
	packet.arcount = 1;	/* additional recs */
	packet.additional = additional;

	if (q_addrs)
		goto special_process;

	for (i = 0; i < addr_num; i++) {
		rc = smb_netbios_send_rcv(bcast, &destination[i], &packet,
		    retries, timeout);
		if (rc == 1)
			gotreply = 1;
	}

	return (gotreply);

special_process:
	addr = destination;
	do {
		rc = smb_netbios_send_rcv(bcast, addr, &packet,
		    retries, timeout);
		if (rc == 1)
			gotreply = 1;
		addr = addr->forw;
	} while (addr != destination);

	return (gotreply);
}

/*
 * 4.2.5.  POSITIVE NAME REGISTRATION RESPONSE
 *
 *                        1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |         NAME_TRN_ID           |1|  0x5  |1|0|1|1|0 0|0|  0x0  |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |          0x0000               |           0x0001              |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |          0x0000               |           0x0000              |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                                                               |
 *   /                            RR_NAME                            /
 *   /                                                               /
 *   |                                                               |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |           NB (0x0020)         |         IN (0x0001)           |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                              TTL                              |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |           0x0006              |          NB_FLAGS             |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                          NB_ADDRESS                           |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 *
 *
 * 4.2.6.  NEGATIVE NAME REGISTRATION RESPONSE
 *
 *                        1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |         NAME_TRN_ID           |1|  0x5  |1|0|1|1|0 0|0| RCODE |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |          0x0000               |           0x0001              |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |          0x0000               |           0x0000              |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                                                               |
 *   /                            RR_NAME                            /
 *   /                                                               /
 *   |                                                               |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |           NB (0x0020)         |         IN (0x0001)           |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                              TTL                              |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |           0x0006              |          NB_FLAGS             |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                          NB_ADDRESS                           |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 *   RCODE field values:
 *
 *   Symbol      Value   Description:
 *
 *   FMT_ERR       0x1   Format Error.  Request was invalidly
 *                       formatted.
 *   SRV_ERR       0x2   Server failure.  Problem with NAME, cannot
 *                       process name.
 *   IMP_ERR       0x4   Unsupported request error.  Allowable only
 *                       for challenging NAME when gets an Update type
 *                       registration request.
 *   RFS_ERR       0x5   Refused error.  For policy reasons server
 *                       will not register this name from this host.
 *   ACT_ERR       0x6   Active error.  Name is owned by another node.
 *   CFT_ERR       0x7   Name in conflict error.  A UNIQUE name is
 *                       owned by more than one node.
 */
static int
smb_send_name_registration_response(struct addr_entry *addr,
    struct name_packet *original_packet, unsigned short rcode)
{
	struct name_packet	packet;
	struct resource_record	answer;

	bzero(&packet, sizeof (struct name_packet));
	bzero(&answer, sizeof (struct resource_record));

	packet.name_trn_id = original_packet->name_trn_id;
	packet.info = NAME_REGISTRATION_RESPONSE | NAME_NM_FLAGS_RA |
	    (rcode & NAME_RCODE_MASK);
	packet.qdcount = 0;	/* question entries */
	packet.question = NULL;
	packet.ancount = 1;	/* answer recs */
	packet.answer = &answer;
	packet.nscount = 0;	/* authority recs */
	packet.authority = NULL;
	packet.arcount = 0;	/* additional recs */
	packet.additional = NULL;

	answer.name = original_packet->question->name;
	answer.rr_type = NAME_QUESTION_TYPE_NB;
	answer.rr_class = NAME_QUESTION_CLASS_IN;
	answer.ttl = original_packet->additional->ttl;
	answer.rdlength = original_packet->additional->rdlength;
	answer.rdata = original_packet->additional->rdata;

	return (smb_send_name_service_packet(addr, &packet));
}

/*
 * 4.2.9.  NAME RELEASE REQUEST & DEMAND
 *
 *                        1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |         NAME_TRN_ID           |0|  0x6  |0|0|0|0|0 0|B|  0x0  |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |          0x0001               |           0x0000              |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |          0x0000               |           0x0001              |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                                                               |
 *   /                         QUESTION_NAME                         /
 *   /                                                               /
 *   |                                                               |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |           NB (0x0020)         |        IN (0x0001)            |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                                                               |
 *   /                            RR_NAME                            /
 *   /                                                               /
 *   |                                                               |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |           NB (0x0020)         |         IN (0x0001)           |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                          0x00000000                           |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |           0x0006              |          NB_FLAGS             |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                          NB_ADDRESS                           |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 *   Since the RR_NAME is the same name as the QUESTION_NAME, the
 *   RR_NAME representation must use label string pointers to the
 *   QUESTION_NAME labels to guarantee the length of the datagram is
 *   less than the maximum 576 bytes.  This is the same condition as
 *   with the NAME REGISTRATION REQUEST.
 */
static int
smb_send_name_release_request_and_demand(int bcast,
    struct name_question *question, struct resource_record *additional)
{
	int gotreply = 0;
	int i, rc;
	int addr_num;
	uint32_t retries;
	uint32_t timeout;
	struct addr_entry *destination;
	struct name_packet packet;

	if (bcast == BROADCAST) {
		if (bcast_num == 0)
			return (-1);
		destination = smb_bcast_list;
		addr_num = bcast_num;
		retries = 1; /* BCAST_REQ_RETRY_COUNT */
		timeout = 100; /* BCAST_REQ_RETRY_TIMEOUT */
		packet.info = NAME_RELEASE_REQUEST | NM_FLAGS_BROADCAST;
	} else {
		if (nbns_num == 0)
			return (-1);
		destination = smb_nbns;
		addr_num = nbns_num;
		retries = 1; /* UCAST_REQ_RETRY_COUNT */
		timeout = 100; /* UCAST_REQ_RETRY_TIMEOUT */
		packet.info = NAME_RELEASE_REQUEST | NM_FLAGS_UNICAST;
	}

	packet.qdcount = 1;	/* question entries */
	packet.question = question;
	packet.ancount = 0;	/* answer recs */
	packet.answer = NULL;
	packet.nscount = 0;	/* authority recs */
	packet.authority = NULL;
	packet.arcount = 1;	/* additional recs */
	packet.additional = additional;

	for (i = 0; i < addr_num; i++) {
		rc = smb_netbios_send_rcv(bcast, &destination[i], &packet,
		    retries, timeout);
		if (rc == 1)
			gotreply = 1;
	}

	return (gotreply);
}

/*
 * 4.2.10.  POSITIVE NAME RELEASE RESPONSE
 *
 *                        1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |         NAME_TRN_ID           |1|  0x6  |1|0|0|0|0 0|0|  0x0  |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |          0x0000               |           0x0001              |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |          0x0000               |           0x0000              |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                                                               |
 *   /                            RR_NAME                            /
 *   /                                                               /
 *   |                                                               |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |           NB (0x0020)         |         IN (0x0001)           |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                              TTL                              |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |           0x0006              |          NB_FLAGS             |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                          NB_ADDRESS                           |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 *
 * 4.2.11.  NEGATIVE NAME RELEASE RESPONSE
 *
 *                        1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |         NAME_TRN_ID           |1|  0x6  |1|0|0|0|0 0|0| RCODE |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |          0x0000               |           0x0001              |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |          0x0000               |           0x0000              |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                                                               |
 *   /                            RR_NAME                            /
 *   /                                                               /
 *   |                                                               |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |           NB (0x0020)         |         IN (0x0001)           |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                              TTL                              |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |           0x0006              |          NB_FLAGS             |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                          NB_ADDRESS                           |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 *   RCODE field values:
 *
 *   Symbol      Value   Description:
 *
 *   FMT_ERR       0x1   Format Error.  Request was invalidly
 *                       formatted.
 *
 *   SRV_ERR       0x2   Server failure.  Problem with NAME, cannot
 *                       process name.
 *
 *   RFS_ERR       0x5   Refused error.  For policy reasons server
 *                       will not release this name from this host.
 *
 *   ACT_ERR       0x6   Active error.  Name is owned by another node.
 *                       Only that node may release it.  A NetBIOS
 *                       Name Server can optionally allow a node to
 *                       release a name it does not own.  This would
 *                       facilitate detection of inactive names for
 *                       nodes that went down silently.
 */
static int
/* LINTED - E_STATIC_UNUSED */
smb_send_name_release_response(struct addr_entry *addr,
    struct name_packet *original_packet, unsigned short rcode)
{
	struct name_packet	packet;
	struct resource_record	answer;

	bzero(&packet, sizeof (struct name_packet));
	bzero(&answer, sizeof (struct resource_record));

	packet.name_trn_id = original_packet->name_trn_id;
	packet.info = NAME_RELEASE_RESPONSE | (rcode & NAME_RCODE_MASK);
	packet.qdcount = 0;	/* question entries */
	packet.question = NULL;
	packet.ancount = 1;	/* answer recs */
	packet.answer = &answer;
	packet.nscount = 0;	/* authority recs */
	packet.authority = NULL;
	packet.arcount = 0;	/* additional recs */
	packet.additional = NULL;

	answer.name = original_packet->question->name;
	answer.rr_type = NAME_QUESTION_TYPE_NB;
	answer.rr_class = NAME_QUESTION_CLASS_IN;
	answer.ttl = original_packet->additional->ttl;
	answer.rdlength = original_packet->additional->rdlength;
	answer.rdata = original_packet->additional->rdata;

	return (smb_send_name_service_packet(addr, &packet));
}

/*
 *
 * 4.2.12.  NAME QUERY REQUEST
 *
 *                        1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |         NAME_TRN_ID           |0|  0x0  |0|0|1|0|0 0|B|  0x0  |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |          0x0001               |           0x0000              |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |          0x0000               |           0x0000              |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                                                               |
 *   /                         QUESTION_NAME                         /
 *   /                                                               /
 *   |                                                               |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |           NB (0x0020)         |        IN (0x0001)            |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
static int
smb_send_name_query_request(int bcast, struct name_question *question)
{
	int			rc = 0;
	uint32_t		retry, retries;
	uint32_t		timeout;
	unsigned short		tid;
	struct addr_entry 	*destination;
	struct name_packet	packet;
	int 			i, addr_num;
	struct timespec 	st;

	if (bcast == BROADCAST) {
		if (bcast_num == 0)
			return (-1);
		destination = smb_bcast_list;
		addr_num = bcast_num;
		retries = BCAST_REQ_RETRY_COUNT;
		timeout = BCAST_REQ_RETRY_TIMEOUT;
		packet.info = NAME_QUERY_REQUEST | NM_FLAGS_BROADCAST;
	} else {
		if (nbns_num == 0)
			return (-1);
		destination = smb_nbns;
		addr_num = nbns_num;
		retries = UCAST_REQ_RETRY_COUNT;
		timeout = UCAST_REQ_RETRY_TIMEOUT;
		packet.info = NAME_QUERY_REQUEST | NM_FLAGS_UNICAST;
	}
	packet.qdcount = 1;	/* question entries */
	packet.question = question;
	packet.ancount = 0;	/* answer recs */
	packet.answer = NULL;
	packet.nscount = 0;	/* authority recs */
	packet.authority = NULL;
	packet.arcount = 0;	/* additional recs */
	packet.additional = NULL;

	for (i = 0; i < addr_num; i++) {
		for (retry = 0; retry < retries; retry++) {
			if ((destination->flags & ADDR_FLAG_VALID) == 0)
				break;
			tid = netbios_name_transcation_id++;
			packet.name_trn_id = tid;

			if (smb_send_name_service_packet(&destination[i],
			    &packet) >= 0) {
				if ((rc = smb_netbios_process_response(tid,
				    &destination[i],
				    &packet, timeout)) != 0)
					break;
			}
			st.tv_sec = 0;
			st.tv_nsec = (timeout * 1000000);
			(void) nanosleep(&st, 0);
		}
	}

	return (rc);
}


/*
 *
 * 4.2.13.  POSITIVE NAME QUERY RESPONSE
 *
 *                        1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |         NAME_TRN_ID           |1|  0x0  |1|T|1|?|0 0|0|  0x0  |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |          0x0000               |           0x0001              |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |          0x0000               |           0x0000              |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                                                               |
 *   /                            RR_NAME                            /
 *   /                                                               /
 *   |                                                               |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |           NB (0x0020)         |         IN (0x0001)           |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                              TTL                              |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |           RDLENGTH            |                               |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               |
 *   |                                                               |
 *   /                       ADDR_ENTRY ARRAY                        /
 *   /                                                               /
 *   |                                                               |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 *   The ADDR_ENTRY ARRAY a sequence of zero or more ADDR_ENTRY
 *   records.  Each ADDR_ENTRY record represents an owner of a name.
 *   For group names there may be multiple entries.  However, the list
 *   may be incomplete due to packet size limitations.  Bit 22, "T",
 *   will be set to indicate truncated data.
 *
 *   Each ADDR_ENTRY has the following format:
 *
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |          NB_FLAGS             |          NB_ADDRESS           |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |   NB_ADDRESS (continued)      |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 *
 *
 * 4.2.14.  NEGATIVE NAME QUERY RESPONSE
 *
 *                        1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |         NAME_TRN_ID           |1|  0x0  |1|0|1|?|0 0|0| RCODE |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |          0x0000               |           0x0000              |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |          0x0000               |           0x0000              |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                                                               |
 *   /                            RR_NAME                            /
 *   /                                                               /
 *   |                                                               |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |           NULL (0x000A)       |         IN (0x0001)           |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                          0x00000000                           |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |           0x0000              |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 *   RCODE field values:
 *
 *   Symbol      Value   Description
 *
 *   FMT_ERR       0x1   Format Error.  Request was invalidly
 *                       formatted.
 *   SRV_ERR       0x2   Server failure.  Problem with NAME, cannot
 *                       process name.
 *   NAM_ERR       0x3   Name Error.  The name requested does not
 *                       exist.
 *   IMP_ERR       0x4   Unsupported request error.  Allowable only
 *                       for challenging NAME when gets an Update type
 *                       registration request.
 *   RFS_ERR       0x5   Refused error.  For policy reasons server
 *                       will not register this name from this host.
 */
static int
smb_send_name_query_response(struct addr_entry *addr,
    struct name_packet *original_packet, struct name_entry *entry,
    unsigned short rcode)
{
	struct addr_entry 	*raddr;
	struct name_packet	packet;
	struct resource_record	answer;
	unsigned short		attr;
	unsigned char 		data[MAX_DATAGRAM_LENGTH];
	unsigned char 		*scan = data;

	packet.name_trn_id = original_packet->name_trn_id;
	packet.info = NAME_QUERY_RESPONSE | (rcode & NAME_RCODE_MASK);
	packet.qdcount = 0;	/* question entries */
	packet.question = NULL;
	packet.ancount = 1;	/* answer recs */
	packet.answer = &answer;
	packet.nscount = 0;	/* authority recs */
	packet.authority = NULL;
	packet.arcount = 0;	/* additional recs */
	packet.additional = NULL;

	answer.name = entry;
	answer.rr_class = NAME_QUESTION_CLASS_IN;
	answer.ttl = entry->addr_list.ttl;
	answer.rdata = data;
	if (rcode) {
		answer.rr_type = NAME_RR_TYPE_NULL;
		answer.rdlength = 0;
		bzero(data, 6);
	} else {
		answer.rdlength = 0;
		answer.rr_type = NAME_QUESTION_TYPE_NB;
		raddr = &entry->addr_list;
		scan = data;
		do {
			attr = entry->attributes & (NAME_ATTR_GROUP |
			    NAME_ATTR_OWNER_NODE_TYPE);

			BE_OUT16(scan, attr); scan += 2;

			*scan++ = raddr->sin.sin_addr.s_addr;
			*scan++ = raddr->sin.sin_addr.s_addr >> 8;
			*scan++ = raddr->sin.sin_addr.s_addr >> 16;
			*scan++ = raddr->sin.sin_addr.s_addr >> 24;

			answer.rdlength += 6;
			raddr = raddr->forw;
		} while (raddr != &entry->addr_list);
	}

	return (smb_send_name_service_packet(addr, &packet));
}

/*
 * 4.2.18.  NODE STATUS RESPONSE
 *
 *                        1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |         NAME_TRN_ID           |1|  0x0  |1|0|0|0|0 0|0|  0x0  |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |          0x0000               |           0x0001              |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |          0x0000               |           0x0000              |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                                                               |
 *   /                            RR_NAME                            /
 *   |                                                               |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |        NBSTAT (0x0021)        |         IN (0x0001)           |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                          0x00000000                           |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |          RDLENGTH             |   NUM_NAMES   |               |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+               +
 *   |                                                               |
 *   +                                                               +
 *   /                         NODE_NAME ARRAY                       /
 *   +                                                               +
 *   |                                                               |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                                                               |
 *   +                                                               +
 *   /                           STATISTICS                          /
 *   +                                                               +
 *   |                                                               |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 *   The NODE_NAME ARRAY is an array of zero or more NUM_NAMES entries
 *   of NODE_NAME records.  Each NODE_NAME entry represents an active
 *   name in the same NetBIOS scope as the requesting name in the
 *   local name table of the responder.  RR_NAME is the requesting
 *   name.
 *
 *   NODE_NAME Entry:
 *
 *                        1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                                                               |
 *   +---                                                         ---+
 *   |                                                               |
 *   +---                    NETBIOS FORMAT NAME                  ---+
 *   |                                                               |
 *   +---                                                         ---+
 *   |                                                               |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |         NAME_FLAGS            |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 *   The NAME_FLAGS field:
 *
 *                                             1   1   1   1   1   1
 *     0   1   2   3   4   5   6   7   8   9   0   1   2   3   4   5
 *   +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
 *   | G |  ONT  |DRG|CNF|ACT|PRM|          RESERVED                 |
 *   +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
 *
 *   The NAME_FLAGS field is defined as:
 *
 *   Symbol     Bit(s)   Description:
 *
 *   RESERVED     7-15   Reserved for future use.  Must be zero (0).
 *   PRM             6   Permanent Name Flag.  If one (1) then entry
 *                       is for the permanent node name.  Flag is zero
 *                       (0) for all other names.
 *   ACT             5   Active Name Flag.  All entries have this flag
 *                       set to one (1).
 *   CNF             4   Conflict Flag.  If one (1) then name on this
 *                       node is in conflict.
 *   DRG             3   Deregister Flag.  If one (1) then this name
 *                       is in the process of being deleted.
 *   ONT           1,2   Owner Node Type:
 *                          00 = B node
 *                          01 = P node
 *                          10 = M node
 *                          11 = Reserved for future use
 *   G               0   Group Name Flag.
 *                       If one (1) then the name is a GROUP NetBIOS
 *                       name.
 *                       If zero (0) then it is a UNIQUE NetBIOS name.
 */
#define	NAME_FLAGS_PERMANENT_NAME	0x0200
#define	NAME_FLAGS_ACTIVE_NAME		0x0400
#define	NAME_FLAGS_CONFLICT		0x0800
#define	NAME_FLAGS_DEREGISTER		0x1000
#define	NAME_FLAGS_ONT_MASK		0x6000
#define	NAME_FLAGS_ONT_B_NODE		0x0000
#define	NAME_FLAGS_ONT_P_NODE		0x2000
#define	NAME_FLAGS_ONT_M_NODE		0x4000
#define	NAME_FLAGS_ONT_RESERVED		0x6000
#define	NAME_FLAGS_GROUP_NAME		0x8000


/*
 *   STATISTICS Field of the NODE STATUS RESPONSE:
 *
 *                        1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |               UNIT_ID (Unique unit ID)                        |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |       UNIT_ID,continued       |    JUMPERS    |  TEST_RESULT  |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |       VERSION_NUMBER          |      PERIOD_OF_STATISTICS     |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |       NUMBER_OF_CRCs          |     NUMBER_ALIGNMENT_ERRORS   |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |       NUMBER_OF_COLLISIONS    |        NUMBER_SEND_ABORTS     |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                       NUMBER_GOOD_SENDS                       |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                      NUMBER_GOOD_RECEIVES                     |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |       NUMBER_RETRANSMITS      | NUMBER_NO_RESOURCE_CONDITIONS |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |  NUMBER_FREE_COMMAND_BLOCKS   |  TOTAL_NUMBER_COMMAND_BLOCKS  |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |MAX_TOTAL_NUMBER_COMMAND_BLOCKS|    NUMBER_PENDING_SESSIONS    |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |  MAX_NUMBER_PENDING_SESSIONS  |  MAX_TOTAL_SESSIONS_POSSIBLE  |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |   SESSION_DATA_PACKET_SIZE    |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
#define	MAX_NETBIOS_REPLY_DATA_SIZE	500

static int
smb_send_node_status_response(struct addr_entry *addr,
    struct name_packet *original_packet)
{
	uint32_t		net_ipaddr;
	int64_t			max_connections;
	struct arpreq 		arpreq;
	struct name_packet	packet;
	struct resource_record	answer;
	unsigned char 		*scan;
	unsigned char 		*scan_end;
	unsigned char		data[MAX_NETBIOS_REPLY_DATA_SIZE];
	boolean_t scan_done = B_FALSE;

	bzero(&packet, sizeof (struct name_packet));
	bzero(&answer, sizeof (struct resource_record));

	packet.name_trn_id = original_packet->name_trn_id;
	packet.info = NODE_STATUS_RESPONSE;
	packet.qdcount = 0;	/* question entries */
	packet.question = NULL;
	packet.ancount = 1;	/* answer recs */
	packet.answer = &answer;
	packet.nscount = 0;	/* authority recs */
	packet.authority = NULL;
	packet.arcount = 0;	/* additional recs */
	packet.additional = NULL;

	answer.name = original_packet->question->name;
	answer.rr_type = NAME_RR_TYPE_NBSTAT;
	answer.rr_class = NAME_QUESTION_CLASS_IN;
	answer.ttl = 0;
	answer.rdata = data;

	scan = smb_netbios_cache_status(data, MAX_NETBIOS_REPLY_DATA_SIZE,
	    original_packet->question->name->scope);

	scan_end = data + MAX_NETBIOS_REPLY_DATA_SIZE;

	if (smb_nic_exists(addr->sin.sin_addr.s_addr, B_TRUE))
		net_ipaddr = addr->sin.sin_addr.s_addr;
	else
		net_ipaddr = 0;

	(void) smb_config_getnum(SMB_CI_MAX_CONNECTIONS, &max_connections);

	while (!scan_done) {
		if ((scan + 6) >= scan_end) {
			packet.info |= NAME_NM_FLAGS_TC;
			break;
		}

		if (net_ipaddr != 0) {
			struct sockaddr_in *s_in;
			int s;

			s = socket(AF_INET, SOCK_DGRAM, 0);
			/* LINTED - E_BAD_PTR_CAST_ALIGN */
			s_in = (struct sockaddr_in *)&arpreq.arp_pa;
			s_in->sin_family = AF_INET;
			s_in->sin_addr.s_addr = net_ipaddr;
			if (ioctl(s, SIOCGARP, (caddr_t)&arpreq) < 0) {
				bzero(scan, 6);
			} else {
				bcopy(&arpreq.arp_ha.sa_data, scan, 6);
			}
			(void) close(s);
		} else {
			bzero(scan, 6);
		}
		scan += 6;

		if ((scan + 26) >= scan_end) {
			packet.info |= NAME_NM_FLAGS_TC;
			break;
		}
		bzero(scan, 26);
		scan += 26;

		if ((scan + 2) >= scan_end) {
			packet.info |= NAME_NM_FLAGS_TC;
			break;
		}
		BE_OUT16(scan, 0); scan += 2;

		if ((scan + 2) >= scan_end) {
			packet.info |= NAME_NM_FLAGS_TC;
			break;
		}
		BE_OUT16(scan, 0); scan += 2;

		if ((scan + 2) >= scan_end) {
			packet.info |= NAME_NM_FLAGS_TC;
			break;
		}
		BE_OUT16(scan, 0); scan += 2;

		if ((scan + 2) >= scan_end) {
			packet.info |= NAME_NM_FLAGS_TC;
			break;
		}
		BE_OUT16(scan, 0); scan += 2;

		if ((scan + 2) >= scan_end) {
			packet.info |= NAME_NM_FLAGS_TC;
			break;
		}
		BE_OUT16(scan, 0); scan += 2;

		if ((scan + 2) >= scan_end) {
			packet.info |= NAME_NM_FLAGS_TC;
			break;
		}
		BE_OUT16(scan, 0); scan += 2;

		if ((scan + 2) >= scan_end) {
			packet.info |= NAME_NM_FLAGS_TC;
			break;
		}
		BE_OUT16(scan, 0); scan += 2;

		if ((scan + 2) >= scan_end) {
			packet.info |= NAME_NM_FLAGS_TC;
			break;
		}
		BE_OUT16(scan, max_connections); scan += 2;

		if ((scan + 2) >= scan_end) {
			packet.info |= NAME_NM_FLAGS_TC;
			break;
		}

		BE_OUT16(scan, 0); scan += 2;

		scan_done = B_TRUE;
	}
	answer.rdlength = scan - data;
	return (smb_send_name_service_packet(addr, &packet));
}

/*
 *
 * 5.1.  NAME SERVICE PROTOCOLS
 *
 *   A REQUEST packet is always sent to the well known UDP port -
 *   NAME_SERVICE_UDP_PORT.  The destination address is normally
 *   either the IP broadcast address or the address of the NAME - the
 *   address of the NAME server it set up at initialization time.  In
 *   rare cases, a request packet will be sent to an end node, e.g.  a
 *   NAME QUERY REQUEST sent to "challenge" a node.
 *
 *   A RESPONSE packet is always sent to the source UDP port and
 *   source IP address of the request packet.
 *
 *   A DEMAND packet must always be sent to the well known UDP port -
 *   NAME_SERVICE_UDP_PORT.  There is no restriction on the target IP
 *   address.
 *
 *   Terms used in this section:
 *
 *   tid -            Transaction ID.  This is a value composed from
 *                    the requestor's IP address and a unique 16 bit
 *                    value generated by the originator of the
 *                    transaction.
 */


/*
 *
 * 5.1.1.  B-NODE ACTIVITY
 *
 * 5.1.1.1.  B-NODE ADD NAME
 *
 *   PROCEDURE add_name(name)
 *
 *   (*
 *    * Host initiated processing for a B node
 *    *)
 *   BEGIN
 *
 *        REPEAT
 *
 *             (* build name service packet *)
 *
 *             ONT = B_NODE; (* broadcast node *)
 *             G = UNIQUE;   (* unique name *)
 *             TTL = 0;
 *
 *             broadcast NAME REGISTRATION REQUEST packet;
 *
 *             (*
 *              * remote node(s) will send response packet
 *              * if applicable
 *              *)
 *             pause(BCAST_REQ_RETRY_TIMEOUT);
 *
 *        UNTIL response packet is received or
 *             retransmit count has been exceeded
 *
 *        IF no response packet was received THEN
 *        BEGIN (* no response *)
 *             (*
 *              * Build packet
 *              *)
 *
 *             ONT = B_NODE; (* broadcast node *)
 *             G = UNIQUE;   (* unique name *)
 *             TTL = 0;
 *
 *             (*
 *              * Let other nodes known you have the name
 *              *)
 *
 *             broadcast NAME UPDATE REQUEST packet;
 *             (* name can be added to local name table *)
 *             return success;
 *        END (* no response *)
 *        ELSE
 *        BEGIN (* got response *)
 *
 *             (*
 *              * Match return transaction id
 *              * against tid sent in request
 *              *)
 *
 *            IF NOT response tid = request tid THEN
 *            BEGIN
 *             ignore response packet;
 *            END
 *            ELSE
 *            CASE packet type OF
 *
 *            NEGATIVE NAME REGISTRATION RESPONSE:
 *
 *                 return failure; (* name cannot be added *)
 *
 *            POSITIVE NAME REGISTRATION RESPONSE:
 *            END-NODE CHALLENGE NAME REGISTRATION RESPONSE:
 *
 *                 (*
 *                  * B nodes should normally not get this
 *                  * response.
 *                  *)
 *
 *                  ignore packet;
 *            END (* case *);
 *        END (* got response *)
 *   END (* procedure *)
 *
 *
 *
 * 5.1.1.2.  B-NODE ADD_GROUP NAME
 *
 *   PROCEDURE add_group_name(name)
 *
 *   (*
 *    * Host initiated processing for a B node
 *    *)
 *
 *   BEGIN
 *        (*
 *         * same as for a unique name with the
 *         * exception that the group bit (G) must
 *         * be set in the request packets.
 *         *)
 *
 *        ...
 *        G = GROUP;
 *        ...
 *        ...
 *
 *        (*
 *         * broadcast request ...
 *         *)
 *
 *
 *   END
 */
static int
smb_name_Bnode_add_name(struct name_entry *name)
{
	struct name_question		question;
	struct resource_record		additional;
	unsigned char 			data[8];
	unsigned short			attr;
	struct addr_entry *addr;
	int rc = 0;

	addr = &name->addr_list;

	do {
		/* build name service packet */
		question.name = name;
		/*
		 * question.name->attributes |= NAME_NB_FLAGS_ONT_B;
		 * This is commented because NAME_NB_FLAGS_ONT_B is 0
		 */
		question.question_type = NAME_QUESTION_TYPE_NB;
		question.question_class = NAME_QUESTION_CLASS_IN;

		additional.name = name;
		additional.rr_class = NAME_QUESTION_CLASS_IN;
		additional.ttl = 0;
		additional.rdata = data;
		additional.rdlength = 6;
		additional.rr_type = NAME_QUESTION_TYPE_NB;
		attr = name->attributes & (NAME_ATTR_GROUP |
		    NAME_ATTR_OWNER_NODE_TYPE);

		BE_OUT16(&data[0], attr);
		(void) memcpy(&data[2], &addr->sin.sin_addr.s_addr,
		    sizeof (uint32_t));

		rc |= smb_send_name_registration_request(BROADCAST, &question,
		    &additional);
		addr = addr->forw;

	} while (addr != &name->addr_list);

	return (rc);
}

/*
 * 5.1.1.3.  B-NODE FIND_NAME
 *
 *   PROCEDURE find_name(name)
 *
 *   (*
 *    * Host initiated processing for a B node
 *    *)
 *
 *   BEGIN
 *
 *        REPEAT
 *             (*
 *              * build packet
 *              *)
 *             ONT = B;
 *             TTL = 0;
 *             G = DONT CARE;
 *			raddr = raddr->forw;
 *
 *             broadcast NAME QUERY REQUEST packet;
 *             (*
 *              * a node might send response packet
 *              *)
 *
 *             pause(BCAST_REQ_RETRY_TIMEOUT);
 *        UNTIL response packet received OR
 *             max transmit threshold exceeded
 *
 *        IF no response packet received THEN
 *             return failure;
 *        ELSE
 *        IF NOT response tid = request tid THEN
 *             ignore packet;
 *        ELSE
 *        CASE packet type OF
 *        POSITIVE NAME QUERY RESPONSE:
 *             (*
 *              * Start a timer to detect conflict.
 *              *
 *              * Be prepared to detect conflict if
 *              * any more response packets are received.
 *              *
 *              *)
 *
 *             save response as authoritative response;
 *             start_timer(CONFLICT_TIMER);
 *             return success;
 *
 *        NEGATIVE NAME QUERY RESPONSE:
 *        REDIRECT NAME QUERY RESPONSE:
 *
 *             (*
 *              * B Node should normally not get either
 *              * response.
 *              *)
 *
 *              ignore response packet;
 *
 *        END (* case *)
 *   END (* procedure *)
 */
static int
smb_name_Bnode_find_name(struct name_entry *name)
{
	struct name_question	question;

	question.name = name;
	question.question_type = NAME_QUESTION_TYPE_NB;
	question.question_class = NAME_QUESTION_CLASS_IN;

	return (smb_send_name_query_request(BROADCAST, &question));
}

/*
 * 5.1.1.4.  B NODE NAME RELEASE
 *
 *   PROCEDURE delete_name (name)
 *   BEGIN
 *
 *        REPEAT
 *
 *             (*
 *              * build packet
 *              *)
 *             ...
 *
 *             (*
 *              * send request
 *              *)
 *
 *             broadcast NAME RELEASE REQUEST packet;
 *
 *             (*
 *              * no response packet expected
 *              *)
 *
 *             pause(BCAST_REQ_RETRY_TIMEOUT);
 *
 *        UNTIL retransmit count has been exceeded
 *   END (* procedure *)
 */
static int
smb_name_Bnode_delete_name(struct name_entry *name)
{
	struct name_question	question;
	struct resource_record	additional;
	struct addr_entry 	*raddr;
	unsigned char 		data[MAX_DATAGRAM_LENGTH];
	unsigned char 		*scan = data;
	uint32_t		attr;

	/* build packet */
	question.name = name;
	question.question_type = NAME_QUESTION_TYPE_NB;
	question.question_class = NAME_QUESTION_CLASS_IN;

	additional.name = name;
	additional.rr_class = NAME_QUESTION_CLASS_IN;
	additional.ttl = 0;
	additional.rdata = data;
	additional.rdlength = 0;
	additional.rr_type = NAME_QUESTION_TYPE_NB;
	raddr = &name->addr_list;
	scan = data;
	do {
		attr = name->attributes & (NAME_ATTR_GROUP |
		    NAME_ATTR_OWNER_NODE_TYPE);

		BE_OUT16(scan, attr); scan += 2;

		*scan++ = raddr->sin.sin_addr.s_addr;
		*scan++ = raddr->sin.sin_addr.s_addr >> 8;
		*scan++ = raddr->sin.sin_addr.s_addr >> 16;
		*scan++ = raddr->sin.sin_addr.s_addr >> 24;

		additional.rdlength += 6;
	} while (raddr != &name->addr_list);

	return (smb_send_name_release_request_and_demand(BROADCAST,
	    &question, &additional));
}

/*
 *
 * 5.1.2.  P-NODE ACTIVITY
 *
 *   All packets sent or received by P nodes are unicast UDP packets.
 *   A P node sends name service requests to the NAME node that is
 *   specified in the P-node configuration.
 *
 * 5.1.2.1.  P-NODE ADD_NAME
 *
 *   PROCEDURE add_name(name)
 *
 *   (*
 *    * Host initiated processing for a P node
 *    *)
 *
 *   BEGIN
 *
 *        REPEAT
 *             (*
 *              * build packet
 *              *)
 *
 *             ONT = P;
 *             G = UNIQUE;
 *             ...
 *
 *             (*
 *              * send request
 *              *)
 *
 *             unicast NAME REGISTRATION REQUEST packet;
 *
 *             (*
 *              * NAME will send response packet
 *              *)
 *
 *             IF receive a WACK RESPONSE THEN
 *                  pause(time from TTL field of response);
 *             ELSE
 *                  pause(UCAST_REQ_RETRY_TIMEOUT);
 *        UNTIL response packet is received OR
 *             retransmit count has been exceeded
 *
 *        IF no response packet was received THEN
 *        BEGIN (* no response *)
 *             (*
 *              * NAME is down.  Cannot claim name.
 *              *)
 *
 *             return failure; (* name cannot be claimed *)
 *        END (* no response *)
 *        ELSE
 *        BEGIN (* response *)
 *            IF NOT response tid = request tid THEN
 *            BEGIN
 *             (*  Packet may belong to another transaction  *)
 *             ignore response packet;
 *            END
 *            ELSE
 *            CASE packet type OF
 *
 *            POSITIVE NAME REGISTRATION RESPONSE:
 *
 *                 (*
 *                  * name can be added
 *                  *)
 *
 *                 adjust refresh timeout value, TTL, for this name;
 *                 return success;      (* name can be added *)
 *
 *            NEGATIVE NAME REGISTRATION RESPONSE:
 *                 return failure; (* name cannot be added *)
 *
 *            END-NODE CHALLENGE REGISTRATION REQUEST:
 *            BEGIN (* end node challenge *)
 *
 *                 (*
 *                  * The response packet has in it the
 *                  * address of the presumed owner of the
 *                  * name.  Challenge that owner.
 *                  * If owner either does not
 *                  * respond or indicates that he no longer
 *                  * owns the name, claim the name.
 *                  * Otherwise, the name cannot be claimed.
 *                  *
 *                  *)
 *
 *                 REPEAT
 *                  (*
 *                   * build packet
 *                   *)
 *                  ...
 *
 *                  unicast NAME QUERY REQUEST packet to the
 *                       address contained in the END NODE
 *                       CHALLENGE RESPONSE packet;
 *
 *                  (*
 *                   * remote node may send response packet
 *                   *)
 *
 *                  pause(UCAST_REQ_RETRY_TIMEOUT);
 *
 *                 UNTIL response packet is received or
 *                     retransmit count has been exceeded
 *                 IF no response packet is received OR
 *                       NEGATIVE NAME QUERY RESPONSE packet
 *                       received THEN
 *                 BEGIN (* update *)
 *
 *                  (*
 *                   * name can be claimed
 *                   *)
 *
 *                  REPEAT
 *
 *                      (*
 *                       * build packet
 *                       *)
 *                       ...
 *
 *                      unicast NAME UPDATE REQUEST to NAME;
 *
 *                      (*
 *                       * NAME node will send response packet
 *                       *)
 *
 *                      IF receive a WACK RESPONSE THEN
 *                            pause(time from TTL field of response);
 *                      ELSE
 *                            pause(UCAST_REQ_RETRY_TIMEOUT);
 *                  UNTIL response packet is received or
 *                      retransmit count has been exceeded
 *                  IF no response packet received THEN
 *                  BEGIN (* no response *)
 *
 *                       (*
 *                        * name could not be claimed
 *                        *)
 *
 *                       return failure;
 *                  END (* no response *)
 *                  ELSE
 *                  CASE packet type OF
 *                       POSITIVE NAME REGISTRATION RESPONSE:
 *                            (*
 *                             * add name
 *                             *)
 *                            return success;
 *                       NEGATIVE NAME REGISTRATION RESPONSE:
 *
 *                            (*
 *                             * you lose  ...
 *                             *)
 *                            return failure;
 *                       END (* case *)
 *                 END (* update *)
 *                 ELSE
 *
 *                 (*
 *                  * received a positive response to the "challenge"
 *                  * Remote node still has name
 *                  *)
 *
 *                  return failure;
 *            END (* end node challenge *)
 *        END (* response *)
 *   END (* procedure *)
 *
 *
 * 5.1.2.2.  P-NODE ADD GROUP NAME
 *
 *   PROCEDURE add_group_name(name)
 *
 *   (*
 *    * Host initiated processing for a P node
 *    *)
 *
 *   BEGIN
 *        (*
 *         * same as for a unique name, except that the
 *         * request packet must indicate that a
 *         * group name claim is being made.
 *         *)
 *
 *        ...
 *        G = GROUP;
 *        ...
 *
 *        (*
 *         * send packet
 *         *)
 *         ...
 *
 *
 *   END
 */
static int
smb_name_Pnode_add_name(struct name_entry *name)
{
	struct name_question		question;
	struct resource_record		additional;
	unsigned char 			data[8];
	unsigned short			attr;
	struct addr_entry *addr;
	int rc = 0;

	/* build packet */
	addr = &name->addr_list;
	do {
		question.name = name;
		question.question_type = NAME_QUESTION_TYPE_NB;
		question.question_class = NAME_QUESTION_CLASS_IN;

		additional.name = name;
		additional.rr_class = NAME_QUESTION_CLASS_IN;
		additional.ttl = 0;
		additional.rdata = data;
		additional.rdlength = 6;
		additional.rr_type = NAME_QUESTION_TYPE_NB;
		attr = name->attributes &
		    (NAME_ATTR_GROUP | NAME_ATTR_OWNER_NODE_TYPE);

		BE_OUT16(&data[0], attr);
		(void) memcpy(&data[2], &addr->sin.sin_addr.s_addr,
		    sizeof (uint32_t));

		rc |= smb_send_name_registration_request(UNICAST, &question,
		    &additional);

		addr = addr->forw;

	} while (addr != &name->addr_list);

	return (rc);
}

static int
smb_name_Pnode_refresh_name(struct name_entry *name)
{
	struct name_question		question;
	struct resource_record		additional;
	unsigned char 			data[8];
	unsigned short			attr;
	struct addr_entry *addr;
	int rc = 0;

	/* build packet */
	addr = &name->addr_list;
	do {
		question.name = name;
		question.question_type = NAME_QUESTION_TYPE_NB;
		question.question_class = NAME_QUESTION_CLASS_IN;

		additional.name = name;
		additional.rr_class = NAME_QUESTION_CLASS_IN;
		additional.ttl = 0;
		additional.rdata = data;
		additional.rdlength = 6;
		additional.rr_type = NAME_QUESTION_TYPE_NB;
		attr = name->attributes &
		    (NAME_ATTR_GROUP | NAME_ATTR_OWNER_NODE_TYPE);

		BE_OUT16(&data[0], attr);
		(void) memcpy(&data[2], &addr->sin.sin_addr.s_addr,
		    sizeof (uint32_t));

		rc |= smb_send_name_refresh_request(UNICAST, &question,
		    &additional, 1);

		addr = addr->forw;
	} while (addr != &name->addr_list);

	return (rc);
}

/*
 * 5.1.2.3.  P-NODE FIND NAME
 *
 *   PROCEDURE find_name(name)
 *
 *   (*
 *    * Host initiated processing for a P node
 *    *)
 *
 *   BEGIN
 *        REPEAT
 *             (*
 *              * build packet
 *              *)
 *
 *             ONT = P;
 *             G = DONT CARE;
 *
 *             unicast NAME QUERY REQUEST packet;
 *
 *             (*
 *              * a NAME node might send response packet
 *              *)
 *
 *             IF receive a WACK RESPONSE THEN
 *                  pause(time from TTL field of response);
 *             ELSE
 *                  pause(UCAST_REQ_RETRY_TIMEOUT);
 *        UNTIL response packet received OR
 *             max transmit threshold exceeded
 *
 *        IF no response packet received THEN
 *             return failure;
 *        ELSE
 *        IF NOT response tid = request tid THEN
 *             ignore packet;
 *        ELSE
 *        CASE packet type OF
 *        POSITIVE NAME QUERY RESPONSE:
 *             return success;
 *
 *        REDIRECT NAME QUERY RESPONSE:
 *
 *             (*
 *              * NAME node wants this end node
 *              * to use some other NAME node
 *              * to resolve the query.
 *              *)
 *
 *              repeat query with NAME address
 *                  in the response packet;
 *        NEGATIVE NAME QUERY RESPONSE:
 *             return failure;
 *
 *        END (* case *)
 *   END (* procedure *)
 */
static int
smb_name_Pnode_find_name(struct name_entry *name)
{
	struct name_question	question;

	/*
	 * Host initiated processing for a P node
	 */
	question.name = name;
	question.name->attributes |= NAME_NB_FLAGS_ONT_P;
	question.question_type = NAME_QUESTION_TYPE_NB;
	question.question_class = NAME_QUESTION_CLASS_IN;

	return (smb_send_name_query_request(UNICAST, &question));
}

/*
 * 5.1.2.4.  P-NODE DELETE_NAME
 *
 *   PROCEDURE delete_name (name)
 *
 *   (*
 *    * Host initiated processing for a P node
 *    *)
 *
 *   BEGIN
 *
 *        REPEAT
 *
 *             (*
 *              * build packet
 *              *)
 *             ...
 *
 *             (*
 *              * send request
 *              *)
 *
 *             unicast NAME RELEASE REQUEST packet;
 *             IF receive a WACK RESPONSE THEN
 *                  pause(time from TTL field of response);
 *             ELSE
 *                  pause(UCAST_REQ_RETRY_TIMEOUT);
 *        UNTIL retransmit count has been exceeded
 *             or response been received
 *
 *        IF response has been received THEN
 *        CASE packet type OF
 *        POSITIVE NAME RELEASE RESPONSE:
 *             return success;
 *        NEGATIVE NAME RELEASE RESPONSE:
 *
 *             (*
 *              * NAME does want node to delete this
 *              * name !!!
 *              *)
 *
 *             return failure;
 *        END (* case *)
 *   END (* procedure *)
 */
static int
smb_name_Pnode_delete_name(struct name_entry *name)
{
	struct name_question	question;
	struct resource_record	additional;
	struct addr_entry 	*raddr;
	unsigned char 		data[MAX_DATAGRAM_LENGTH];
	unsigned char 		*scan = data;
	uint32_t		attr;

	/* build packet */
	question.name = name;
	question.name->attributes |= NAME_NB_FLAGS_ONT_P;
	question.question_type = NAME_QUESTION_TYPE_NB;
	question.question_class = NAME_QUESTION_CLASS_IN;

	additional.name = name;
	additional.rr_class = NAME_QUESTION_CLASS_IN;
	additional.ttl = 0;
	additional.rdata = data;
	additional.rdlength = 0;
	additional.rr_type = NAME_QUESTION_TYPE_NB;
	raddr = &name->addr_list;
	do {
		scan = data;
		attr = name->attributes & (NAME_ATTR_GROUP |
		    NAME_ATTR_OWNER_NODE_TYPE);

		BE_OUT16(scan, attr); scan += 2;

		*scan++ = raddr->sin.sin_addr.s_addr;
		*scan++ = raddr->sin.sin_addr.s_addr >> 8;
		*scan++ = raddr->sin.sin_addr.s_addr >> 16;
		*scan++ = raddr->sin.sin_addr.s_addr >> 24;

		additional.rdlength = 6;
		raddr = raddr->forw;
		(void) smb_send_name_release_request_and_demand(UNICAST,
		    &question, &additional);
	} while (raddr != &name->addr_list);

	return (1);
}

/*
 * 5.1.3.  M-NODE ACTIVITY
 *
 *   M nodes behavior is similar to that of P nodes with the addition
 *   of some B node-like broadcast actions.  M node name service
 *   proceeds in two steps:
 *
 *   1.Use broadcast UDP based name service.  Depending on the
 *     operation, goto step 2.
 *
 *   2.Use directed UDP name service.
 *
 *   The following code for M nodes is exactly the same as for a P
 *   node, with the exception that broadcast operations are done
 *   before P type operation is attempted.
 *
 * 5.1.3.1.  M-NODE ADD NAME
 *
 *   PROCEDURE add_name(name)
 *
 *   (*
 *    * Host initiated processing for a M node
 *    *)
 *
 *   BEGIN
 *
 *        (*
 *         * check if name exists on the
 *         * broadcast area
 *         *)
 *        REPEAT
 *            (* build packet *)
 *
 *            ....
 *            broadcast NAME REGISTRATION REQUEST packet;
 *            pause(BCAST_REQ_RETRY_TIMEOUT);
 *
 *        UNTIL response packet is received or
 *             retransmit count has been  exceeded
 *
 *        IF valid response received THEN
 *        BEGIN
 *             (* cannot claim name *)
 *
 *             return failure;
 *        END
 *
 *        (*
 *         * No objections received within the
 *         * broadcast area.
 *         * Send request to name server.
 *         *)
 *
 *        REPEAT
 *             (*
 *              * build packet
 *              *)
 *
 *             ONT = M;
 *             ...
 *
 *             unicast NAME REGISTRATION REQUEST packet;
 *
 *             (*
 *              * remote NAME will send response packet
 *              *)
 *
 *             IF receive a WACK RESPONSE THEN
 *                  pause(time from TTL field of response);
 *             ELSE
 *                  pause(UCAST_REQ_RETRY_TIMEOUT);
 *
 *        UNTIL response packet is received or
 *             retransmit count has been exceeded
 *
 *        IF no response packet was received THEN
 *        BEGIN (* no response *)
 *             (*
 *              * NAME is down.  Cannot claim name.
 *              *)
 *             return failure; (* name cannot be claimed *)
 *        END (* no response *)
 *        ELSE
 *        BEGIN (* response *)
 *            IF NOT response tid = request tid THEN
 *            BEGIN
 *             ignore response packet;
 *            END
 *            ELSE
 *            CASE packet type OF
 *            POSITIVE NAME REGISTRATION RESPONSE:
 *
 *                 (*
 *                  * name can be added
 *                  *)
 *
 *                 adjust refresh timeout value, TTL;
 *                 return success;      (* name can be added *)
 *
 *            NEGATIVE NAME REGISTRATION RESPONSE:
 *                 return failure; (* name cannot be added *)
 *
 *            END-NODE CHALLENGE REGISTRATION REQUEST:
 *            BEGIN (* end node challenge *)
 *
 *                 (*
 *                  * The response packet has in it the
 *                  * address of the presumed owner of the
 *                  * name.  Challenge that owner.
 *                  * If owner either does not
 *                  * respond or indicates that he no longer
 *                  * owns the name, claim the name.
 *                  * Otherwise, the name cannot be claimed.
 *                  *
 *                  *)
 *
 *                 REPEAT
 *                  (*
 *                   * build packet
 *                   *)
 *                  ...
 *
 *                  (*
 *                   * send packet to address contained in the
 *                   * response packet
 *                   *)
 *
 *                  unicast NAME QUERY REQUEST packet;
 *
 *                  (*
 *                   * remote node may send response packet
 *                   *)
 *
 *                  pause(UCAST_REQ_RETRY_TIMEOUT);
 *
 *                 UNTIL response packet is received or
 *                     retransmit count has been exceeded
 *                 IF no response packet is received THEN
 *                 BEGIN (* no response *)
 *
 *                  (*
 *                   * name can be claimed
 *                   *)
 *                  REPEAT
 *
 *                      (*
 *                       * build packet
 *                       *)
 *                       ...
 *
 *                      unicast NAME UPDATE REQUEST to NAME;
 *
 *                      (*
 *                       * NAME node will send response packet
 *                       *)
 *
 *                      IF receive a WACK RESPONSE THEN
 *                            pause(time from TTL field of response);
 *                  ELSE
 *                       pause(UCAST_REQ_RETRY_TIMEOUT);
 *
 *                  UNTIL response packet is received or
 *                      retransmit count has been exceeded
 *                  IF no response packet received THEN
 *                  BEGIN (* no response *)
 *
 *                       (*
 *                        * name could not be claimed
 *                        *)
 *
 *                       return failure;
 *                  END (* no response *)
 *                  ELSE
 *                  CASE packet type OF
 *                  POSITIVE NAME REGISTRATION RESPONSE:
 *                       (*
 *                        * add name
 *                        *)
 *
 *                       return success;
 *                  NEGATIVE NAME REGISTRATION RESPONSE:
 *                       (*
 *                        * you lose  ...
 *                        *)
 *
 *                       return failure;
 *                  END (* case *)
 *                 END (* no response *)
 *                 ELSE
 *                 IF NOT response tid = request tid THEN
 *                 BEGIN
 *                  ignore response packet;
 *                 END
 *
 *                 (*
 *                  * received a response to the "challenge"
 *                  * packet
 *                  *)
 *
 *                 CASE packet type OF
 *                 POSITIVE NAME QUERY:
 *
 *                  (*
 *                   * remote node still has name.
 *                   *)
 *
 *                  return failure;
 *                 NEGATIVE NAME QUERY:
 *
 *                  (*
 *                   * remote node no longer has name
 *                   *)
 *
 *                  return success;
 *                 END (* case *)
 *            END (* end node challenge *)
 *            END (* case *)
 *        END (* response *)
 *   END (* procedure *)
 *
 *
 * 5.1.3.2.  M-NODE ADD GROUP NAME
 *
 *   PROCEDURE add_group_name(name)
 *
 *   (*
 *    * Host initiated processing for a P node
 *    *)
 *
 *   BEGIN
 *        (*
 *         * same as for a unique name, except that the
 *         * request packet must indicate that a
 *         * group name claim is being made.
 *         *)
 *
 *        ...
 *        G = GROUP;
 *        ...
 *
 *        (*
 *         * send packet
 *         *)
 *         ...
 *
 *
 *   END
 */
static int
smb_name_Mnode_add_name(struct name_entry *name)
{
	if (smb_name_Bnode_add_name(name) > 0) {
		if (nbns_num == 0)
			return (1); /* No name server configured */

		return (smb_name_Pnode_add_name(name));
	}
	return (-1);
}

static int
smb_name_Hnode_add_name(struct name_entry *name)
{
	if (nbns_num > 0) {
		if (smb_name_Pnode_add_name(name) == 1)
			return (1);
	}

	return (smb_name_Bnode_add_name(name));
}

/*
 * 5.1.3.3.  M-NODE FIND NAME
 *
 *   PROCEDURE find_name(name)
 *
 *   (*
 *    * Host initiated processing for a M node
 *    *)
 *
 *   BEGIN
 *        (*
 *         * check if any node on the broadcast
 *         * area has the name
 *         *)
 *
 *        REPEAT
 *             (* build packet *)
 *             ...
 *
 *             broadcast NAME QUERY REQUEST packet;
 *             pause(BCAST_REQ_RETRY_TIMEOUT);
 *        UNTIL response packet received OR
 *             max transmit threshold exceeded
 *
 *        IF valid response received THEN
 *        BEGIN
 *             save response as authoritative response;
 *             start_timer(CONFLICT_TIMER);
 *             return success;
 *        END
 *
 *        (*
 *         * no valid response on the b'cast segment.
 *         * Try the name server.
 *         *)
 *
 *        REPEAT
 *             (*
 *              * build packet
 *              *)
 *
 *             ONT = M;
 *             G = DONT CARE;
 *
 *             unicast NAME QUERY REQUEST packet to NAME;
 *
 *             (*
 *              * a NAME node might send response packet
 *              *)
 *
 *             IF receive a WACK RESPONSE THEN
 *                  pause(time from TTL field of response);
 *             ELSE
 *                  pause(UCAST_REQ_RETRY_TIMEOUT);
 *        UNTIL response packet received OR
 *             max transmit threshold exceeded
 *
 *        IF no response packet received THEN
 *             return failure;
 *        ELSE
 *        IF NOT response tid = request tid THEN
 *             ignore packet;
 *        ELSE
 *        CASE packet type OF
 *        POSITIVE NAME QUERY RESPONSE:
 *             return success;
 *
 *        REDIRECT NAME QUERY RESPONSE:
 *
 *             (*
 *              * NAME node wants this end node
 *              * to use some other NAME node
 *              * to resolve the query.
 *              *)
 *
 *              repeat query with NAME address
 *                  in the response packet;
 *        NEGATIVE NAME QUERY RESPONSE:
 *             return failure;
 *
 *        END (* case *)
 *   END (* procedure *)
 */
static int
smb_name_Mnode_find_name(struct name_entry *name)
{
	if (smb_name_Bnode_find_name(name) == 1)
		return (1);

	if (nbns_num == 0)
		return (1); /* No name server configured */

	return (smb_name_Pnode_find_name(name));
}

static int
smb_name_Hnode_find_name(struct name_entry *name)
{
	if (nbns_num > 0)
		if (smb_name_Pnode_find_name(name) == 1)
			return (1);

	return (smb_name_Bnode_find_name(name));
}

/*
 * 5.1.3.4.  M-NODE DELETE NAME
 *
 *   PROCEDURE delete_name (name)
 *
 *   (*
 *    * Host initiated processing for a P node
 *    *)
 *
 *   BEGIN
 *        (*
 *         * First, delete name on NAME
 *         *)
 *
 *        REPEAT
 *
 *             (*
 *              * build packet
 *	struct addr_entry *addr;
 *              *)
 *             ...
 *
 *             (*
 *              * send request
 *              *)
 *
 *             unicast NAME RELEASE REQUEST packet to NAME;
 *
 *             IF receive a WACK RESPONSE THEN
 *                  pause(time from TTL field of response);
 *             ELSE
 *                  pause(UCAST_REQ_RETRY_TIMEOUT);
 *        UNTIL retransmit count has been exceeded
 *             or response been received
 *
 *        IF response has been received THEN
 *        CASE packet type OF
 *        POSITIVE NAME RELEASE RESPONSE:
 *             (*
 *              * Deletion of name on b'cast segment is deferred
 *              * until after NAME has deleted the name
 *              *)
 *
 *             REPEAT
 *                  (* build packet *)
 *
 *                  ...
 *                  broadcast NAME RELEASE REQUEST;
 *                  pause(BCAST_REQ_RETRY_TIMEOUT);
 *             UNTIL rexmt threshold exceeded
 *
 *             return success;
 *        NEGATIVE NAME RELEASE RESPONSE:
 *
 *             (*
 *              * NAME does want node to delete this
 *              * name
 *              *)
 *             return failure;
 *        END (* case *)
 *   END (* procedure *)
 */
static int
smb_name_Mnode_delete_name(struct name_entry *name)
{
	(void) smb_name_Bnode_delete_name(name);

	if (nbns_num == 0)
		return (-1); /* No name server configured */

	if (smb_name_Pnode_delete_name(name) > 0)
		return (1);

	return (-1);
}

static int
smb_name_Hnode_delete_name(struct name_entry *name)
{
	if (nbns_num > 0)
		if (smb_name_Pnode_delete_name(name) > 0)
			return (1);

	return (smb_name_Bnode_delete_name(name));
}

/*
 * 5.1.1.5.  B-NODE INCOMING PACKET PROCESSING
 *
 *   Following processing is done when broadcast or unicast packets
 *   are received at the NAME_SERVICE_UDP_PORT.
 *
 *   PROCEDURE process_incoming_packet(packet)
 *
 *   (*
 *    * Processing initiated by incoming packets for a B node
 *    *)
 *
 *   BEGIN
 *        (*
 *         * Note: response packets are always sent
 *         * to:
 *         * source IP address of request packet
 *         * source UDP port of request packet
 *         *)
 *
 *        CASE packet type OF
 *
 *        NAME REGISTRATION REQUEST (UNIQUE):
 *             IF name exists in local name table THEN
 *                  send NEGATIVE_NAME_REGISTRATION_RESPONSE ;
 *        NAME REGISTRATION REQUEST (GROUP):
 *             IF name exists in local name table THEN
 *             BEGIN
 *                  IF local entry is a unique name THEN
 *                      send NEGATIVE_NAME_REGISTRATION_RESPONSE ;
 *             END
 *        NAME QUERY REQUEST:
 *             IF name exists in local name table THEN
 *             BEGIN
 *                  build response packet;
 *                  send POSITIVE_NAME_QUERY_RESPONSE;
 *        POSITIVE NAME QUERY RESPONSE:
 *             IF name conflict timer is not active THEN
 *                 BEGIN
 *                      (*
 *                       * timer has expired already...  ignore this
 *                       * packet
 *                       *)
 *
 *                      return;
 *                 END
 *             ELSE (* timer is active *)
 *                 IF a response for this name has previously been
 *                      received THEN
 *                     BEGIN (* existing entry *)
 *
 *                      (*
 *                       * we sent out a request packet, and
 *                       * have already received (at least)
 *                       * one response
 *                       *
 *                       * Check if conflict exists.
 *                       * If so, send out a conflict packet.
 *                       *
 *                       * Note: detecting conflict does NOT
 *                       * affect any existing sessions.
 *                       *
 *                       *)
 *
 *                      (*
 *                       * Check for name conflict.
 *                       * See "Name Conflict" in Concepts and Methods
 *                       *)
 *                      check saved authoritative response against
 *                           information in this response packet;
 *                      IF conflict detected THEN
 *                      BEGIN
 *                           unicast NAME CONFLICT DEMAND packet;
 *                           IF entry exists in cache THEN
 *                           BEGIN
 *                                remove entry from cache;
 *                           END
 *                      END
 *                 END (* existing entry *)
 *             ELSE
 *                 BEGIN
 *                      (*
 *                       * Note: If this was the first response
 *                       * to a name query, it would have been
 *                       * handled in the
 *                       * find_name() procedure.
 *                       *)
 *
 *                      ignore packet;
 *                 END
 *        NAME CONFLICT DEMAND:
 *             IF name exists in local name table THEN
 *             BEGIN
 *                  mark name as conflict detected;
 *
 *                  (*
 *                   * a name in the state "conflict detected"
 *                   * does not "logically" exist on that node.
 *                   * No further session will be accepted on
 *                   * that name.
 *                   * No datagrams can be sent against that name.
 *                   * Such an entry will not be used for
 *                   * purposes of processing incoming request
 *                   * packets.
 *                   * The only valid user NetBIOS operation
 *                   * against such a name is DELETE NAME.
 *                   *)
 *             END
 *        NAME RELEASE REQUEST:
 *             IF caching is being done THEN
 *             BEGIN
 *                  remove entry from cache;
 *             END
 *        NAME UPDATE REQUEST:
 *             IF caching is being done THEN
 *             BEGIN
 *                  IF entry exists in cache already,
 *                       update cache;
 *                  ELSE IF name is "interesting" THEN
 *                  BEGIN
 *                       add entry to cache;
 *                  END
 *             END
 *
 *        NODE STATUS REQUEST:
 *             IF name exists in local name table THEN
 *             BEGIN
 *                  (*
 *                   * send only those names that are
 *                   * in the same scope as the scope
 *                   * field in the request packet
 *                   *)
 *
 *                  send NODE STATUS RESPONSE;
 *             END
 *   END
 */
static void
smb_name_process_Bnode_packet(struct name_packet *packet,
    struct addr_entry *addr)
{
	struct name_entry 	*name;
	struct name_entry 	*entry;
	struct name_question 	*question;
	struct resource_record 	*additional;

	question = packet->question;
	additional = packet->additional;

	switch (packet->info & NAME_OPCODE_OPCODE_MASK) {
	case NAME_OPCODE_REFRESH:
		/* Guard against malformed packets */
		if ((question == 0) || (additional == 0))
			break;
		if (additional->name->addr_list.sin.sin_addr.s_addr == 0)
			break;

		name = question->name;
		name->addr_list.ttl = additional->ttl;
		name->attributes = additional->name->attributes;
		name->addr_list.sin = additional->name->addr_list.sin;
		name->addr_list.forw = name->addr_list.back = &name->addr_list;

		if ((entry = smb_netbios_cache_lookup_addr(name)) != 0) {
			smb_netbios_cache_update_entry(entry, question->name);
			smb_netbios_cache_unlock_entry(entry);
		}
		else
			(void) smb_netbios_cache_insert(question->name);
		break;

	case NAME_OPCODE_QUERY:
		/*
		 * This opcode covers both NAME_QUERY_REQUEST and
		 * NODE_STATUS_REQUEST. They can be distinguished
		 * based on the type of question entry.
		 */

		/* All query requests have to have question entry */
		if (question == 0)
			break;

		if (question->question_type == NAME_QUESTION_TYPE_NB) {
			name = question->name;
			if ((entry = smb_netbios_cache_lookup(name)) != 0) {
				(void) smb_send_name_query_response(addr,
				    packet, entry, 0);
				smb_netbios_cache_unlock_entry(entry);
			}
		}
		else
		if (question->question_type == NAME_QUESTION_TYPE_NBSTAT) {
			/*
			 * Name of "*" may be used to force node to
			 * divulge status for administrative purposes
			 */
			name = question->name;
			entry = 0;
			if (NETBIOS_NAME_IS_STAR(name->name) ||
			    ((entry = smb_netbios_cache_lookup(name)) != 0)) {
				if (entry)
					smb_netbios_cache_unlock_entry(entry);
				/*
				 * send only those names that are
				 * in the same scope as the scope
				 * field in the request packet
				 */
				(void) smb_send_node_status_response(addr,
				    packet);
			}
		}
		break;

	default:
		break;
	}
}

/*
 * 5.1.2.5.  P-NODE INCOMING PACKET PROCESSING
 *
 *   Processing initiated by reception of packets at a P node
 *
 *   PROCEDURE process_incoming_packet(packet)
 *
 *   (*
 *    * Processing initiated by incoming packets at a P node
 *    *)
 *
 *   BEGIN
 *        (*
 *         * always ignore UDP broadcast packets
 *         *)
 *
 *        IF packet was sent as a broadcast THEN
 *        BEGIN
 *             ignore packet;
 *             return;
 *        END
 *        CASE packet type of
 *
 *        NAME CONFLICT DEMAND:
 *             IF name exists in local name table THEN
 *                  mark name as in conflict;
 *             return;
 *
 *        NAME QUERY REQUEST:
 *             IF name exists in local name table THEN
 *             BEGIN (* name exists *)
 *
 *                  (*
 *                   * build packet
 *                   *)
 *                  ...
 *
 *                  (*
 *                   * send response to the IP address and port
 *                   * number from which the request was received.
 *                   *)
 *
 *                  send POSITIVE_NAME_QUERY_RESPONSE ;
 *                  return;
 *             END (* exists *)
 *             ELSE
 *             BEGIN (* does not exist *)
 *
 *                  (*
 *                   * send response to the requestor
 *                   *)
 *
 *                  send NEGATIVE_NAME_QUERY_RESPONSE ;
 *                  return;
 *             END (* does not exist *)
 *        NODE STATUS REQUEST:
 *             (*
 *              * Name of "*" may be used for force node to
 *              * divulge status for administrative purposes
 *              *)
 *             IF name in local name table OR name = "*" THEN
 *             BEGIN
 *                  (*
 *                   * Build response packet and
 *                   * send to requestor node
 *                   * Send only those names that are
 *                   * in the same scope as the scope
 *                   * in the request packet.
 *                   *)
 *
 *                  send NODE_STATUS_RESPONSE;
 *             END
 *
 *        NAME RELEASE REQUEST:
 *             (*
 *              * This will be received if the NAME wants to flush the
 *              * name from the local name table, or from the local
 *              * cache.
 *              *)
 *
 *             IF name exists in the local name table THEN
 *             BEGIN
 *                  delete name from local name table;
 *                  inform user that name has been deleted;
 *             END
 *        END (* case *)
 *   END (* procedure *)
 *
 *   (*
 *    * Incoming packet processing on a NS node
 *    *)
 *
 *   BEGIN
 *        IF packet was sent as a broadcast THEN
 *        BEGIN
 *             discard packet;
 *             return;
 *        END
 *        CASE packet type of
 *
 *        NAME REGISTRATION REQUEST (UNIQUE):
 *             IF unique name exists in data base THEN
 *             BEGIN (* unique name exists *)
 *                  (*
 *                   * NAME node may be a "passive"
 *                   * server in that it expects the
 *                   * end node to do the challenge
 *                   * server.  Such a NAME node is
 *                   * called a "non-secure" server.
 *                   * A "secure" server will do the
 *                   * challenging before it sends
 *                   * back a response packet.
 *                   *)
 *
 *                  IF non-secure THEN
 *                  BEGIN
 *                       (*
 *                        * build response packet
 *                        *)
 *                       ...
 *
 *
 *                       (*
 *                        * let end node do the challenge
 *                        *)
 *
 *                       send END-NODE CHALLENGE NAME REGISTRATION
 *                            RESPONSE;
 *                       return;
 *                  END
 *                  ELSE
 *                  (*
 *                   * secure server - do the name
 *                   * challenge operation
 *                   *)
 *
 *                  REPEAT
 *                      send NAME QUERY REQUEST;
 *                      pause(UCAST_REQ_RETRY_TIMEOUT);
 *                  UNTIL response has been received or
 *                       retransmit count has been exceeded
 *                  IF no response was received THEN
 *                  BEGIN
 *
 *                       (* node down *)
 *
 *                       update data base - remove entry;
 *                       update data base - add new entry;
 *                       send POSITIVE NAME REGISTRATION RESPONSE;
 *                       return;
 *                  END
 *                  ELSE
 *                  BEGIN (* challenged node replied *)
 *                      (*
 *                       * challenged node replied with
 *                       * a response packet
 *                       *)
 *
 *                      CASE packet type
 *
 *                      POSITIVE NAME QUERY RESPONSE:
 *
 *                       (*
 *                        * name still owned by the
 *                        * challenged node
 *                        *
 *                        * build packet and send response
 *                        *)
 *                        ...
 *
 *
 *                       (*
 *                        * Note: The NAME will need to
 *                        * keep track (based on transaction id) of
 *                        * the IP address and port number
 *                        * of the original requestor.
 *                        *)
 *
 *                       send NEGATIVE NAME REGISTRATION RESPONSE;
 *                       return;
 *                      NEGATIVE NAME QUERY RESPONSE:
 *
 *                       update data base - remove entry;
 *                       update data base - add new  entry;
 *
 *                       (*
 *                        * build response packet and send
 *                        * response
 *                        *)
 *                       send POSITIVE NAME REGISTRATION RESPONSE;
 *                       return;
 *                      END (* case *)
 *                  END (* challenged node replied *)
 *             END (* unique name exists in data base *)
 *             ELSE
 *             IF group name exists in data base THEN
 *             BEGIN (* group names exists *)
 *
 *                  (*
 *                   * Members of a group name are NOT
 *                   * challenged.
 *                   * Make the assumption that
 *                   * at least some of the group members
 *                   * are still alive.
 *                   * Refresh mechanism will
 *                   * allow the NAME to detect when all
 *                   * members of a group no longer use that
 *                   * name
 *                   *)
 *
 *                   send NEGATIVE NAME REGISTRATION RESPONSE;
 *             END (* group name exists *)
 *             ELSE
 *             BEGIN (* name does not exist *)
 *
 *                  (*
 *                   * Name does not exist in data base
 *                   *
 *                   * This code applies to both non-secure
 *                   * and secure server.
 *                   *)
 *
 *                  update data base - add new entry;
 *                  send POSITIVE NAME REGISTRATION RESPONSE;
 *                  return;
 *             END
 *
 *        NAME QUERY REQUEST:
 *             IF name exists in data base THEN
 *             BEGIN
 *                  (*
 *                   * build response packet and send to
 *                   * requestor
 *                   *)
 *                   ...
 *
 *                  send POSITIVE NAME QUERY RESPONSE;
 *                  return;
 *             ELSE
 *             BEGIN
 *                  (*
 *                   * build response packet and send to
 *                   * requestor
 *                   *)
 *                   ...
 *
 *                  send NEGATIVE NAME QUERY RESPONSE;
 *                  return;
 *             END
 *
 *        NAME REGISTRATION REQUEST (GROUP):
 *             IF name exists in data base THEN
 *             BEGIN
 *                  IF local entry is a unique name THEN
 *                  BEGIN (* local is unique *)
 *
 *                      IF non-secure THEN
 *                      BEGIN
 *                       send  END-NODE CHALLENGE NAME
 *                            REGISTRATION RESPONSE;
 *                       return;
 *                      END
 *
 *                      REPEAT
 *                       send NAME QUERY REQUEST;
 *                       pause(UCAST_REQ_RETRY_TIMEOUT);
 *                      UNTIL response received or
 *                           retransmit count exceeded
 *                      IF no response received or
 *                           NEGATIVE NAME QUERY RESPONSE
 *                            received THEN
 *                      BEGIN
 *                       update data base - remove entry;
 *                       update data base - add new entry;
 *                       send POSITIVE NAME REGISTRATION RESPONSE;
 *                       return;
 *                      END
 *                      ELSE
 *                      BEGIN
 *                       (*
 *                        * name still being held
 *                        * by challenged node
 *                        *)
 *
 *                        send NEGATIVE NAME REGISTRATION RESPONSE;
 *                      END
 *                  END (* local is unique *)
 *                  ELSE
 *                  BEGIN (* local is group  *)
 *                       (*
 *                        * existing entry is a group name
 *                        *)
 *
 *                       update data base - remove entry;
 *                       update data base - add new entry;
 *                       send POSITIVE NAME REGISTRATION RESPONSE;
 *                       return;
 *                  END (* local is group *)
 *             END (* names exists *)
 *             ELSE
 *             BEGIN (* does not exist *)
 *
 *                  (* name does not exist in data base *)
 *
 *                  update data base - add new entry;
 *                  send POSITIVE NAME REGISTRATION RESPONSE;
 *                  return;
 *             END (* does not exist *)
 *
 *        NAME RELEASE REQUEST:
 *
 *             (*
 *              * secure server may choose to disallow
 *              * a node from deleting a name
 *              *)
 *
 *             update data base - remove entry;
 *             send POSITIVE NAME RELEASE RESPONSE;
 *             return;
 *
 *        NAME UPDATE REQUEST:
 *
 *             (*
 *              * End-node completed a successful challenge,
 *              * no update database
 *              *)
 *
 *             IF secure server THEN
 *                  send NEGATIVE NAME REGISTRATION RESPONSE;
 *             ELSE
 *             BEGIN (* new entry *)
 *                  IF entry already exists THEN
 *                       update data base - remove entry;
 *                  update data base - add new entry;
 *                  send POSITIVE NAME REGISTRATION RESPONSE;
 *                  start_timer(TTL);
 *             END
 *
 *        NAME REFRESH REQUEST:
 *             check for consistency;
 *
 *             IF node not allowed to have name THEN
 *             BEGIN
 *
 *                  (*
 *                   * tell end node that it can't have name
 *                   *)
 *                  send NEGATIVE NAME REGISTRATION RESPONSE;
 *             END
 *             ELSE
 *             BEGIN
 *
 *                  (*
 *                   * send confirmation response to the
 *                   * end node.
 *                   *)
 *                  send POSITIVE NAME REGISTRATION;
 *                  start_timer(TTL);
 *             END
 *             return;
 *        END (* case *)
 *   END (* procedure *)
 */
static void
smb_name_process_Pnode_packet(struct name_packet *packet,
    struct addr_entry *addr)
{
	struct name_entry 	*name;
	struct name_entry 	*entry;
	struct name_question 	*question;
	struct resource_record 	*additional;

	question = packet->question;
	additional = packet->additional;

	if (packet->info & NAME_NM_FLAGS_B) {
		/*
		 * always ignore UDP broadcast packets
		 */
		return;
	}

	switch (packet->info & NAME_OPCODE_OPCODE_MASK) {
	case NAME_OPCODE_REFRESH:
		/* Guard against malformed packets */
		if ((question == 0) || (additional == 0))
			break;
		if (additional->name->addr_list.sin.sin_addr.s_addr == 0)
			break;

		name = question->name;
		name->addr_list.ttl = additional->ttl;
		name->attributes = additional->name->attributes;
		name->addr_list.sin = additional->name->addr_list.sin;
		name->addr_list.forw = name->addr_list.back = &name->addr_list;

		if ((entry = smb_netbios_cache_lookup(name)) != 0) {
			smb_netbios_cache_update_entry(entry, name);
			smb_netbios_cache_unlock_entry(entry);
		}
		else
			(void) smb_netbios_cache_insert(name);

		(void) smb_send_name_registration_response(addr, packet, 0);
		break;

	case NAME_OPCODE_QUERY:
		/*
		 * This opcode covers both NAME_QUERY_REQUEST and
		 * NODE_STATUS_REQUEST. They can be distinguished
		 * based on the type of question entry.
		 */

		/* All query requests have to have question entry */
		if (question == 0)
			break;

		if (question->question_type == NAME_QUESTION_TYPE_NB) {
			name = question->name;
			if ((entry = smb_netbios_cache_lookup(name)) != 0) {
				/*
				 * send response to the IP address and port
				 * number from which the request was received.
				 */
				(void) smb_send_name_query_response(addr,
				    packet, entry, 0);
				smb_netbios_cache_unlock_entry(entry);
			} else {
				/*
				 * send response to the requestor
				 */
				(void) smb_send_name_query_response(addr,
				    packet, name, RCODE_NAM_ERR);
			}
		}
		else
		if (question->question_type == NAME_QUESTION_TYPE_NBSTAT) {
			/*
			 * Name of "*" may be used to force node to
			 * divulge status for administrative purposes
			 */
			name = question->name;
			entry = 0;
			if (NETBIOS_NAME_IS_STAR(name->name) ||
			    ((entry = smb_netbios_cache_lookup(name)) != 0)) {
				/*
				 * send only those names that are
				 * in the same scope as the scope
				 * field in the request packet
				 */
				if (entry)
					smb_netbios_cache_unlock_entry(entry);
				(void) smb_send_node_status_response(addr,
				    packet);
			}
		}
		break;

	default:
		break;
	}
}

/*
 * 5.1.3.5.  M-NODE INCOMING PACKET PROCESSING
 *
 *   Processing initiated by reception of packets at a M node
 *
 *   PROCEDURE process_incoming_packet(packet)
 *
 *   (*
 *    * Processing initiated by incoming packets at a M node
 *    *)
 *
 *   BEGIN
 *        CASE packet type of
 *
 *        NAME CONFLICT DEMAND:
 *             IF name exists in local name table THEN
 *                  mark name as in conflict;
 *             return;
 *
 *        NAME QUERY REQUEST:
 *             IF name exists in local name table THEN
 *             BEGIN (* name exists *)
 *
 *                  (*
 *                   * build packet
 *                   *)
 *                  ...
 *
 *                  (*
 *                   * send response to the IP address and port
 *                   * number from which the request was received.
 *                   *)
 *
 *                  send POSITIVE NAME QUERY RESPONSE ;
 *                  return;
 *             END (* exists *)
 *             ELSE
 *             BEGIN (* does not exist *)
 *
 *                  (*
 *                   * send response to the requestor
 *                   *)
 *
 *                  IF request NOT broadcast THEN
 *                       (*
 *                        * Don't send negative responses to
 *                        * queries sent by B nodes
 *                        *)
 *                       send NEGATIVE NAME QUERY RESPONSE ;
 *                  return;
 *             END (* does not exist *)
 *        NODE STATUS REQUEST:
 *             BEGIN
 *             (*
 *              * Name of "*" may be used to force node to
 *              * divulge status for administrative purposes
 *              *)
 *             IF name in local name table OR name = "*" THEN
 *                  (*
 *                   * Build response packet and
 *                   * send to requestor node
 *                   * Send only those names that are
 *                   * in the same scope as the scope
 *                   * in the request packet.
 *                   *)
 *
 *                  send NODE STATUS RESPONSE;
 *             END
 *
 *        NAME RELEASE REQUEST:
 *             (*
 *              * This will be received if the NAME wants to flush the
 *              * name from the local name table, or from the local
 *              * cache.
 *              *)
 *
 *             IF name exists in the local name table THEN
 *             BEGIN
 *                  delete name from local name table;
 *                  inform user that name has been deleted;
 *             END
 *        NAME REGISTRATION REQUEST (UNIQUE):
 *             IF name exists in local name table THEN
 *                  send NEGATIVE NAME REGISTRATION RESPONSE ;
 *        NAME REGISTRATION REQUEST (GROUP):
 *             IF name exists in local name table THEN
 *             BEGIN
 *                  IF local entry is a unique name THEN
 *                      send NEGATIVE NAME REGISTRATION RESPONSE ;
 *             END
 *        END (* case *)
 *   END (* procedure *)
 */
static void
smb_name_process_Mnode_packet(struct name_packet *packet,
    struct addr_entry *addr)
{
	if (packet->info & NAME_NM_FLAGS_B)
		smb_name_process_Bnode_packet(packet, addr);
	else
		smb_name_process_Pnode_packet(packet, addr);
}

static void
smb_name_process_Hnode_packet(struct name_packet *packet,
    struct addr_entry *addr)
{
	if (packet->info & NAME_NM_FLAGS_B)
		smb_name_process_Bnode_packet(packet, addr);
	else
		smb_name_process_Pnode_packet(packet, addr);
}


/*
 * smb_netbios_name_tick
 *
 * Called once a second to handle name server timeouts.
 */
void
smb_netbios_name_tick(void)
{
	struct name_entry *name;
	struct name_entry *entry;

	(void) mutex_lock(&refresh_queue.mtx);
	smb_netbios_cache_refresh(&refresh_queue);

	while ((name = refresh_queue.head.forw) != &refresh_queue.head) {
		QUEUE_CLIP(name);
		if (IS_LOCAL(name->attributes)) {
			if (IS_UNIQUE(name->attributes)) {
				(void) smb_name_Pnode_refresh_name(name);
			}
		} else {
			entry = smb_name_find_name(name);
			smb_name_unlock_name(entry);
		}
		free(name);
	}
	(void) mutex_unlock(&refresh_queue.mtx);

	smb_netbios_cache_reset_ttl();
}


/*
 * smb_name_find_name
 *
 * Lookup name cache for the given name.
 * If it's not in the cache it'll send a
 * name query request and then lookup the
 * cache again. Note that if a name is
 * returned it's locked and called MUST
 * unlock it by calling smb_name_unlock_name()
 */
struct name_entry *
smb_name_find_name(struct name_entry *name)
{
	struct name_entry *result;

	if ((result = smb_netbios_cache_lookup(name)) == 0) {
		switch (smb_node_type) {
		case 'B':
			(void) smb_name_Bnode_find_name(name);
			break;
		case 'P':
			(void) smb_name_Pnode_find_name(name);
			break;
		case 'M':
			(void) smb_name_Mnode_find_name(name);
			break;
		case 'H':
		default:
			(void) smb_name_Hnode_find_name(name);
			break;
		}
		return (smb_netbios_cache_lookup(name));
	}

	return (result);
}

void
smb_name_unlock_name(struct name_entry *name)
{
	smb_netbios_cache_unlock_entry(name);
}

int
smb_name_add_name(struct name_entry *name)
{
	int			rc = 1;

	smb_netbios_name_dump(name);

	switch (smb_node_type) {
	case 'B':
		rc = smb_name_Bnode_add_name(name);
		break;
	case 'P':
		rc = smb_name_Pnode_add_name(name);
		break;
	case 'M':
		rc = smb_name_Mnode_add_name(name);
		break;
	case 'H':
	default:
		rc = smb_name_Hnode_add_name(name);
		break;
	}

	if (rc >= 0)
		(void) smb_netbios_cache_insert(name);

	return (rc);
}

int
smb_name_delete_name(struct name_entry *name)
{
	int			rc;
	unsigned char type;

	type = name->name[15];
	if ((type != 0x00) && (type != 0x20)) {
		syslog(LOG_ERR,
		    "netbios: error trying to delete non-local name");
		smb_netbios_name_logf(name);
		name->attributes &= ~NAME_ATTR_LOCAL;
		return (-1);
	}

	smb_netbios_cache_delete(name);

	switch (smb_node_type) {
	case 'B':
		rc = smb_name_Bnode_delete_name(name);
		break;
	case 'P':
		rc = smb_name_Pnode_delete_name(name);
		break;
	case 'M':
		rc = smb_name_Mnode_delete_name(name);
		break;
	case 'H':
	default:
		rc = smb_name_Hnode_delete_name(name);
		break;
	}

	if (rc > 0)
		return (0);

	return (-1);
}

typedef struct {
	struct addr_entry *addr;
	char *buf;
	int length;
} worker_param_t;

/*
 * smb_netbios_worker
 *
 * Process incoming request/response packets for Netbios
 * name service (on port 138).
 */
void *
smb_netbios_worker(void *arg)
{
	worker_param_t *p = (worker_param_t *)arg;
	struct addr_entry *addr = p->addr;
	struct name_packet *packet;

	if ((packet = smb_name_buf_to_packet(p->buf, p->length)) != 0) {
		if (packet->info & NAME_OPCODE_R) {
			/* Reply packet */
			smb_reply_ready(packet, addr);
			free(p->buf);
			free(p);
			return (0);
		}

		/* Request packet */
		switch (smb_node_type) {
		case 'B':
			smb_name_process_Bnode_packet(packet, addr);
			break;
		case 'P':
			smb_name_process_Pnode_packet(packet, addr);
			break;
		case 'M':
			smb_name_process_Mnode_packet(packet, addr);
			break;
		case 'H':
		default:
			smb_name_process_Hnode_packet(packet, addr);
			break;
		}

		if (packet->answer)
			smb_netbios_name_freeaddrs(packet->answer->name);
		free(packet);
	} else {
		syslog(LOG_DEBUG, "SmbNBNS: error decoding received packet");
	}

	free(addr);
	free(p->buf);
	free(p);
	return (0);
}

static void
smb_netbios_wins_config(char *ip)
{
	uint32_t ipaddr;

	ipaddr = inet_addr(ip);
	if (ipaddr != INADDR_NONE) {
		smb_nbns[nbns_num].flags = ADDR_FLAG_VALID;
		smb_nbns[nbns_num].sinlen = sizeof (struct sockaddr_in);
		smb_nbns[nbns_num].sin.sin_family = AF_INET;
		smb_nbns[nbns_num].sin.sin_addr.s_addr = ipaddr;
		smb_nbns[nbns_num++].sin.sin_port =
		    htons(NAME_SERVICE_UDP_PORT);
		smb_node_type = SMB_NODETYPE_H;
	}
}

static void
smb_netbios_name_registration(void)
{
	nbcache_iter_t nbc_iter;
	struct name_entry *name;
	int rc;

	rc = smb_netbios_cache_getfirst(&nbc_iter);
	while (rc == 0) {
		name = nbc_iter.nbc_entry;
		(void) smb_netbios_name_logf(name);
		if (IS_UNIQUE(name->attributes) && IS_LOCAL(name->attributes)) {
			switch (smb_node_type) {
			case SMB_NODETYPE_B:
				(void) smb_name_Bnode_add_name(name);
				break;
			case SMB_NODETYPE_P:
				(void) smb_name_Pnode_add_name(name);
				break;
			case SMB_NODETYPE_M:
				(void) smb_name_Mnode_add_name(name);
				break;
			case SMB_NODETYPE_H:
			default:
				(void) smb_name_Hnode_add_name(name);
				break;
			}
		}
		free(name);
		rc = smb_netbios_cache_getnext(&nbc_iter);
	}
}

void
smb_netbios_name_config(void)
{
	struct name_entry name;
	char wins_ip[16];
	smb_niciter_t ni;
	int rc;

	/* Start with no broadcast addresses */
	bcast_num = 0;
	bzero(smb_bcast_list, sizeof (addr_entry_t) * SMB_PI_MAX_NETWORKS);

	/* Add all of the broadcast addresses */
	rc = smb_nic_getfirst(&ni);
	while (rc == 0) {
		if (ni.ni_nic.nic_smbflags &
		    (SMB_NICF_ALIAS | SMB_NICF_NBEXCL)) {
			rc = smb_nic_getnext(&ni);
			continue;
		}
		smb_bcast_list[bcast_num].flags = ADDR_FLAG_VALID;
		smb_bcast_list[bcast_num].attributes = NAME_ATTR_LOCAL;
		smb_bcast_list[bcast_num].sinlen = sizeof (struct sockaddr_in);
		smb_bcast_list[bcast_num].sin.sin_family = AF_INET;
		smb_bcast_list[bcast_num].sin.sin_port =
		    htons(NAME_SERVICE_UDP_PORT);
		smb_bcast_list[bcast_num++].sin.sin_addr.s_addr =
		    ni.ni_nic.nic_bcast;
		rc = smb_nic_getnext(&ni);
	}

	/* Start with no WINS */
	smb_node_type = SMB_NODETYPE_B;
	nbns_num = 0;
	bzero(smb_nbns, sizeof (addr_entry_t) * SMB_PI_MAX_WINS);

	/* add any configured WINS */
	(void) smb_config_getstr(SMB_CI_WINS_SRV1, wins_ip, sizeof (wins_ip));
	smb_netbios_wins_config(wins_ip);
	(void) smb_config_getstr(SMB_CI_WINS_SRV2, wins_ip, sizeof (wins_ip));
	smb_netbios_wins_config(wins_ip);

	if (smb_nic_getfirst(&ni) != 0)
		return;

	do {
		if (ni.ni_nic.nic_smbflags & SMB_NICF_NBEXCL)
			continue;

		smb_init_name_struct((unsigned char *)ni.ni_nic.nic_host,
		    0x00, 0, ni.ni_nic.nic_ip, htons(DGM_SRVC_UDP_PORT),
		    NAME_ATTR_UNIQUE, NAME_ATTR_LOCAL, &name);
		(void) smb_netbios_cache_insert(&name);

		smb_init_name_struct((unsigned char *)ni.ni_nic.nic_host,
		    0x20, 0, ni.ni_nic.nic_ip, htons(DGM_SRVC_UDP_PORT),
		    NAME_ATTR_UNIQUE, NAME_ATTR_LOCAL, &name);
		(void) smb_netbios_cache_insert(&name);
	} while (smb_nic_getnext(&ni) == 0);

	smb_netbios_name_registration();
}

void
smb_netbios_name_unconfig(void)
{
	struct name_entry *name;

	(void) mutex_lock(&delete_queue.mtx);
	smb_netbios_cache_delete_locals(&delete_queue);

	while ((name = delete_queue.head.forw) != &delete_queue.head) {
		QUEUE_CLIP(name);
		(void) smb_name_delete_name(name);
		free(name);
	}
	(void) mutex_unlock(&delete_queue.mtx);
}

void
smb_netbios_name_reconfig(void)
{
	smb_netbios_name_unconfig();
	smb_netbios_name_config();
}

/*
 * process_incoming Function: void smb_netbios_name_service_daemon(void)
 *
 * Description:
 *
 *	Put test description here.
 *
 * Inputs:
 *	Nothing
 *
 * Returns:
 *	int	-> Description
 */
/*ARGSUSED*/
void *
smb_netbios_name_service_daemon(void *arg)
{
	struct sockaddr_in	sin;
	struct addr_entry 	*addr;
	int			len;
	int			flag = 1;
	char 			*buf;
	worker_param_t 		*worker_param;

	/*
	 * Initialize reply_queue
	 */
	bzero(&reply_queue, sizeof (reply_queue));
	reply_queue.forw = reply_queue.back = &reply_queue;

	if (!smb_netbios_cache_init())
		return (0);

	bcast_num = 0;
	bzero(smb_bcast_list, sizeof (addr_entry_t) * SMB_PI_MAX_NETWORKS);

	if ((name_sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		syslog(LOG_ERR,
		    "smbd: Could not create AF_INET, SOCK_DGRAM, socket");
		smb_netbios_cache_fini();
		smb_netbios_chg_status(NETBIOS_NAME_SVC_FAILED, 1);
		return (0);
	}

	(void) setsockopt(name_sock, SOL_SOCKET, SO_BROADCAST, &flag,
	    sizeof (flag));

	bzero(&sin, sizeof (struct sockaddr_in));
	sin.sin_family = AF_INET;
	sin.sin_port = htons(NAME_SERVICE_UDP_PORT);
	if (bind(name_sock, (struct sockaddr *)&sin, sizeof (sin)) != 0) {
		syslog(LOG_ERR,
		    "smbd: Bind to name service port %d failed (%d)",
		    NAME_SERVICE_UDP_PORT, errno);
		smb_netbios_cache_fini();
		(void) close(name_sock);
		smb_netbios_chg_status(NETBIOS_NAME_SVC_FAILED, 1);
		return (0);
	}

	smb_netbios_chg_status(NETBIOS_NAME_SVC_RUNNING, 1);

	while (((nb_status.state & NETBIOS_SHUTTING_DOWN) == 0) ||
	    (nb_status.state & NETBIOS_BROWSER_RUNNING)) {
		if ((buf = malloc(MAX_DATAGRAM_LENGTH)) == 0) {
			/* Sleep for 10 sec and try again */
			(void) sleep(10);
			continue;
		}
		if ((addr = (struct addr_entry *)
		    malloc(sizeof (struct addr_entry))) == 0) {
			/* Sleep for 10 sec and try again */
			free(buf);
			(void) sleep(10);
			continue;
		}
ignore:		bzero(addr, sizeof (struct addr_entry));
		addr->sinlen = sizeof (addr->sin);
		addr->forw = addr->back = addr;

		if ((len = recvfrom(name_sock, buf, MAX_DATAGRAM_LENGTH,
		    0, (struct sockaddr *)&addr->sin, &addr->sinlen)) < 0) {
			if (errno == ENOMEM || errno == ENFILE ||
			    errno == EMFILE) {
				/* Sleep for 10 sec and try again */
				free(buf);
				free(addr);
				(void) sleep(10);
				continue;
			}
			syslog(LOG_ERR,
				"smbd: NETBIOS name service - recvfrom failed");
			free(buf);
			free(addr);
			smb_netbios_chg_status(NETBIOS_NAME_SVC_FAILED, 1);
			goto shutdown;
		}

		/* Ignore any incoming packets from myself... */
		if (smb_nic_exists(addr->sin.sin_addr.s_addr, B_FALSE))
			goto ignore;

		/*
		 * Launch a netbios worker to process the received packet.
		 */
		worker_param = (worker_param_t *)
		    malloc(sizeof (worker_param_t));
		if (worker_param) {
			pthread_t worker;
			pthread_attr_t tattr;

			worker_param->addr = addr;
			worker_param->buf = buf;
			worker_param->length = len;

			(void) pthread_attr_init(&tattr);
			(void) pthread_attr_setdetachstate(&tattr,
			    PTHREAD_CREATE_DETACHED);
			(void) pthread_create(&worker, &tattr,
			    smb_netbios_worker, worker_param);
			(void) pthread_attr_destroy(&tattr);
		}
	}

shutdown:
	smb_netbios_chg_status(NETBIOS_NAME_SVC_RUNNING, 0);

	(void) mutex_lock(&nb_status.mtx);
	while (nb_status.state & NETBIOS_BROWSER_RUNNING)
		(void) cond_wait(&nb_status.cv, &nb_status.mtx);
	(void) mutex_unlock(&nb_status.mtx);

	if ((nb_status.state & NETBIOS_NAME_SVC_FAILED) == 0) {
		/* this might delay shutdown, do we want to do this? */
		/*
		 * it'll send name release requests but nobody's waiting
		 * for response and it'll eventually timeout.
		 */
		smb_netbios_name_unconfig();
	}
	(void) close(name_sock);
	smb_netbios_cache_fini();
	syslog(LOG_DEBUG, "smbd: Netbios Name Service is down\n");
	return (0);
}
