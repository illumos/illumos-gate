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
 * Copyright (c) 1998 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "snmp_msg.h"
#include "snmp_api.h"
#include "error.h"


/***** GLOBAL VARIABLES *****/

int snmp_errno = 0;


/***** LOCAL CONSTANTS *****/

#define DEFAULT_COMMUNITY	"public"
#define DEFAULT_RETRIES		4
#define DEFAULT_TIMEOUT		1000000L
#define DEFAULT_REMPORT		SNMP_PORT
#define DEFAULT_LOCPORT		0
#define DEFAULT_ENTERPRISE	&sun_oid


/***** LOCAL TYPES *****/

/*
 *	A list of all the outstanding requests
 *	for a particular session
 */

typedef struct _SNMP_request_list {
	struct _SNMP_request_list *next_request;
	uint32_t request_id;	/* request id */
	int	predefined_id;
	int	retries;	/* Number of retries */
	uint32_t	timeout;	/* length to wait for timeout in usec */
	struct timeval time;	/* Time this request was made */
	struct timeval expire;	/* time this request is due to expire */
	SNMP_pdu *pdu;		/* The pdu for this request (saved so it can be retransmitted */
} SNMP_request_list;


/*
 *	Internal information about the state of the snmp session
 */

typedef struct _SNMP_internal_session {
	int		sd;		/* socket descriptor for this connection */
	Address		address;	/* address of connected peer */
	SNMP_request_list *requests;	/* Info about outstanding requests */
} SNMP_internal_session;


/*
 *	The list of active/open sessions.
 */

typedef struct _SNMP_session_list {
	struct _SNMP_session_list *next;
	SNMP_session *session;
	SNMP_internal_session *internal;
} SNMP_session_list;


/***** STATIC VARIABLES *****/

static SNMP_session_list *first_session = NULL;

static uint32_t static_request_id = 0;

static char *snmp_api_errors[5] = {
	"System error",
	"Unknown session",
	"Unknown host",
	"Invalid local port",
	"Unknown Error"
};

static char static_error_label[500] = "";


/***** STATIC FUNCTIONS *****/

static char *api_errstring(int snmp_errnumber);
/*
static init_snmp();
*/
static void free_request_list(SNMP_request_list *rp);
static int snmp_session_read_loop(fd_set *fdset);
static int snmp_session_timeout_loop();


/*******************************************************************/

static char *api_errstring(int snmp_errnumber)
{
	if(snmp_errnumber <= SNMPERR_SYSERR && snmp_errnumber >= SNMPERR_GENERR)
	{
		return snmp_api_errors[snmp_errnumber + 5];
	}
	else
	{
		return "Unknown Error";
	}
}


/*******************************************************************/

/*
 *	Gets initial request ID for all transactions
 */

/*
static init_snmp()
{
	struct timeval tv;

	(void)gettimeofday(&tv, (struct timezone *) 0);
	srandom(tv.tv_sec ^ tv.tv_usec);
	static_request_id = random();
}
*/


/*******************************************************************/

SNMP_session *snmp_session_open_default(char *peername, void callback(), void *callback_magic, char *error_label)
{
	return snmp_session_open(peername,
		NULL, SNMP_DEFAULT_RETRIES, SNMP_DEFAULT_TIMEOUT,
		callback, callback_magic, error_label);
}


/*******************************************************************/

SNMP_session *snmp_session_open(char *peername, char *community, int retries, int32_t timeout, void callback(), void *callback_magic, char *error_label)
{
	SNMP_session_list *slp;
	SNMP_internal_session *isp;
	SNMP_session *session;

	char *peername_dup;
	char *community_dup;

	u_short remote_port = SNMP_DEFAULT_REMPORT;
	u_short local_port = SNMP_DEFAULT_LOCPORT;

	struct sockaddr_in me;
	IPAddress ip_address;

	error_label[0] = '\0';

	if(peername == NULL)
	{
		sprintf(error_label, "BUG: snmp_session_open(): peername is NULL");
		return NULL;
	}

	if(callback == NULL)
	{
		sprintf(error_label, "BUG: snmp_session_open(): callback is NULL");
		return NULL;
	}


	if(community == SNMP_DEFAULT_COMMUNITY)
	{
		community = DEFAULT_COMMUNITY;
	}

	if(retries == SNMP_DEFAULT_RETRIES)
	{
		retries = DEFAULT_RETRIES;
	}

	if(timeout == SNMP_DEFAULT_TIMEOUT)
	{
		timeout = DEFAULT_TIMEOUT;
	}

	if(remote_port == SNMP_DEFAULT_REMPORT)
	{
		remote_port = SNMP_PORT;
	}

	if(local_port == SNMP_DEFAULT_LOCPORT)
	{
		local_port = DEFAULT_LOCPORT;
	}

	if(name_to_ip_address(peername, &ip_address, error_label))
	{
		snmp_errno = SNMPERR_BAD_ADDRESS;
		return NULL;
	}


	/****************************************/
	/* 1) allocate the different structures */
	/****************************************/

	peername_dup = strdup(peername);
	if(peername_dup == NULL)
	{
		sprintf(error_label, ERR_MSG_ALLOC);
		snmp_errno = SNMPERR_GENERR;
		return NULL;
	}

	community_dup = strdup(community);
	if(community_dup == NULL)
	{
		sprintf(error_label, ERR_MSG_ALLOC);
		snmp_errno = SNMPERR_GENERR;
		free(peername_dup);
		return NULL;
	}

	slp = (SNMP_session_list *) malloc(sizeof(SNMP_session_list));
	if(slp == NULL)
	{
		sprintf(error_label, ERR_MSG_ALLOC);
		snmp_errno = SNMPERR_GENERR;
		free(peername_dup);
		free(community_dup);
		return NULL;
	}
	memset(slp, 0, sizeof(SNMP_session_list));

	isp = (SNMP_internal_session *) malloc(sizeof(SNMP_internal_session));
	if(isp == NULL)
	{
		sprintf(error_label, ERR_MSG_ALLOC);
		snmp_errno = SNMPERR_GENERR;
		free(peername_dup);
		free(community_dup);
		free(slp);
		return NULL;
	}
	memset(isp, 0, sizeof(SNMP_internal_session));
	slp->internal = isp;

	slp->internal->sd = -1; /* mark it not set */
	session = (SNMP_session *) malloc(sizeof(SNMP_session));
	if(session == NULL)
	{
		sprintf(error_label, ERR_MSG_ALLOC);
		snmp_errno = SNMPERR_GENERR;
		free(peername_dup);
		free(community_dup);
		free(slp);
		free(isp);
		return NULL;
	}
	memset(session, 0, sizeof(SNMP_session));
	slp->session = session;


	/*************************************/
	/* 2) now link the SNMP_session_list */
	/*************************************/

	slp->next = first_session;
	first_session = slp;


	/***************************************/
	/* 3) initialize SNMP_session */
	/***************************************/

	session->community = community_dup;
	session->retries = retries;
	session->timeout = timeout;
	session->peername = peername_dup;
	session->remote_port = remote_port;
	session->local_port = local_port;
	session->callback = callback;
	session->callback_magic = callback_magic;


	/***************************************/
	/* 4) initialize SNMP_internal_session */
	/***************************************/

	/* Set up connections */
	isp->sd = socket(AF_INET, SOCK_DGRAM, 0);
	if(isp->sd < 0)
	{
		sprintf(error_label, ERR_MSG_SOCKET, errno_string());
		snmp_errno = SNMPERR_SYSERR;
		if(snmp_session_close(session, static_error_label))
		{
			(void)fprintf(stderr, ERR_MSG_CAN_NOT_ABORT_SESSION,
				static_error_label, api_errstring(snmp_errno));
			exit(1);
		}
		return NULL;
	}

	/* initialize address */
	isp->address.sin_addr.s_addr = ip_address.s_addr;
	isp->address.sin_family = AF_INET;
	isp->address.sin_port = session->remote_port;	/* byte swap is done in pdu.c */

	/* bind */
	me.sin_family = AF_INET;
	me.sin_addr.s_addr = INADDR_ANY;
	me.sin_port = htons(session->local_port);
	if(bind(isp->sd, (struct sockaddr *)&me, sizeof(me)) != 0)
	{
		sprintf(error_label, ERR_MSG_BIND, errno_string());
		snmp_errno = SNMPERR_BAD_LOCPORT;
		if(snmp_session_close(session, static_error_label))
		{
			(void)fprintf(stderr, ERR_MSG_CAN_NOT_ABORT_SESSION,
				static_error_label, api_errstring(snmp_errno));
			exit(1);
		}
		return NULL;
	}

	/* request list */
	isp->requests = NULL;
	session->sd = isp->sd;


	return session;
}


/*******************************************************************/

/*
 *	Free each element in the input request list.
 */

static void free_request_list(SNMP_request_list *rp)
{
	SNMP_request_list *orp;


	while(rp)
	{
		orp = rp;
		rp = rp->next_request;
		if(orp->pdu != NULL)
		{
			snmp_pdu_free(orp->pdu);
		}
		free(orp);
	}

	return;
}


/*******************************************************************/

int snmp_session_close(SNMP_session *session, char *error_label)
{
	SNMP_session_list *slp = NULL;
	SNMP_session_list *oslp = NULL;


	error_label[0] = '\0';

	if(first_session->session == session)
	{
		/* If first entry */
		slp = first_session;
		first_session = slp->next;
	}
	else
	{
		for(slp = first_session; slp; slp = slp->next)
		{
			if(slp->session == session)
			{
				if(oslp) /* if we found entry that points here */
				{
					oslp->next = slp->next;	/* link around this entry */
				}
				break;
			}
			oslp = slp;
		}
	}

	/* If we found the session, free all data associated with it */
	if(slp)
	{
		if(slp->session->community)
		{
			free(slp->session->community);
		}
		if(slp->session->peername)
		{
			free(slp->session->peername);
		}
		free(slp->session);
		if(slp->internal->sd != -1)
		{
			if(close(slp->internal->sd) == -1)
			{
				(void)fprintf(stderr, "close(%s) failed %s\n",
					slp->internal->sd, errno_string());
			}
		}
		free_request_list(slp->internal->requests);
		free((char *)slp->internal);
		free((char *)slp);
	}
	else
	{
		snmp_errno = SNMPERR_BAD_SESSION;
		return -1;
	}

	return 0;
}


/*******************************************************************/

/*
 *	1) sends the input pdu on the specified session
 *	2) if this request is a pdu, add it to the request list
 *
 *	Upon success, 0 is returned.
 *	On any error, -1 is returned and error_label is set.
 *
 *	The pdu is freed by snmp_session_send() unless a failure occured.
 */

int snmp_session_send(SNMP_session *session, int predefined_id, SNMP_pdu *pdu, char *error_label)
{
	SNMP_session_list *slp;
	SNMP_internal_session *isp = NULL;
	SNMP_request_list *rp;
	struct timeval tv;


	error_label[0] = '\0';

	for(slp = first_session; slp; slp = slp->next)
	{
		if(slp->session == session)
		{
			isp = slp->internal;
			break;
		}
	}
	if(isp == NULL)
	{
		snmp_errno = SNMPERR_BAD_SESSION;
		return -1;
	}

	if(pdu->community == NULL)
	{
		pdu->community = strdup(session->community);
		if(pdu->community == NULL)
		{
			sprintf(error_label, ERR_MSG_ALLOC);
			snmp_errno = SNMPERR_GENERR;
			return -1;
		}
	}

	if(pdu->type == GET_REQ_MSG || pdu->type == GETNEXT_REQ_MSG
		|| pdu->type == GET_RSP_MSG || pdu->type == SET_REQ_MSG)
	{
		pdu->request_id = ++static_request_id;
	}
	else
	{
		pdu->request_id = 0;
	}


	if( (pdu->type == GET_REQ_MSG)
		|| (pdu->type == GETNEXT_REQ_MSG)
		|| (pdu->type == SET_REQ_MSG) )
	{
		/* set up to expect a response */

		rp = (SNMP_request_list *) malloc(sizeof(SNMP_request_list));
		if(rp == NULL)
		{
			sprintf(error_label, ERR_MSG_ALLOC);
			snmp_errno = SNMPERR_GENERR;
			return -1;
		}
		memset(rp, 0, sizeof(SNMP_request_list));
	}

	(void)gettimeofday(&tv, (struct timezone *) 0);
	if(snmp_pdu_send(isp->sd, &(isp->address), pdu, error_label))
	{
		snmp_errno = SNMPERR_GENERR;
		return -1;
	}

	if( (pdu->type == GET_REQ_MSG)
		|| (pdu->type == GETNEXT_REQ_MSG)
		|| (pdu->type == SET_REQ_MSG) )
	{
		rp->next_request = isp->requests;
		isp->requests = rp;
		rp->pdu = pdu;
		rp->request_id = pdu->request_id;

		rp->retries = 1;

		rp->timeout = session->timeout;
		rp->predefined_id = predefined_id;

		rp->time.tv_sec = tv.tv_sec;
		rp->time.tv_usec = tv.tv_usec;
/*
printf("%d NOW:    %d sec and %d usec\n",
	rp->retries,
	tv.tv_sec,
	tv.tv_usec);
*/

		tv.tv_usec += rp->timeout;
		tv.tv_sec += tv.tv_usec / 1000000L;
		tv.tv_usec %= 1000000L;

		rp->expire.tv_sec = tv.tv_sec;
		rp->expire.tv_usec = tv.tv_usec;
/*
printf("%d EXPIRE: %d sec and %d usec\n\n",
	rp->retries,
	tv.tv_sec,
	tv.tv_usec);
*/
	}
	else
	{
		snmp_pdu_free(pdu);
	}


	return 0;
}


/*******************************************************************/

void snmp_session_read(fd_set *fdset)
{
	while(snmp_session_read_loop(fdset));
}

/*
 *	We need this function because the user may close the session
 *	in the callback and then corrupt the session list
 */

static int snmp_session_read_loop(fd_set *fdset)
{
	SNMP_session_list *slp;
	SNMP_session *sp;
	SNMP_internal_session *isp;
	SNMP_pdu *pdu;
	SNMP_request_list *rp, *orp;


	for(slp = first_session; slp; slp = slp->next)
	{
		if(FD_ISSET(slp->internal->sd, fdset))
		{
			Address address;


			FD_CLR(slp->internal->sd, fdset);

			sp = slp->session;
			isp = slp->internal;

			pdu = snmp_pdu_receive(isp->sd, &address, static_error_label);
			if(pdu == NULL)
			{
				(void)fprintf(stderr, ERR_MSG_RECEIVED_MANGLED_PACKET,
					static_error_label);
				return 0;
			}

			if(pdu->type == GET_RSP_MSG)
			{
				for(rp = isp->requests; rp; rp = rp->next_request)
				{
					if(rp->request_id == pdu->request_id)
					{
						/* delete request */

						orp = rp;
						if(isp->requests == orp)
						{
							/* first in list */

							isp->requests = orp->next_request;
						}
						else
						{
							for(rp = isp->requests; rp; rp = rp->next_request)
							{
								if(rp->next_request == orp)
								{
									rp->next_request = orp->next_request; /* link around it */
									break;
								}
							}
						}

						sp->callback(RECEIVED_MESSAGE, sp, pdu->request_id, orp->predefined_id, pdu, sp->callback_magic);

						snmp_pdu_free(orp->pdu);
						free(orp);

						/*
						 * Then we should return as soon as possible
						 * because may have closed the session and
						 * corrupted the pointers
						 */

						break;
					}
				}
			}
			else
			if( (pdu->type == GET_REQ_MSG)
				|| (pdu->type == GETNEXT_REQ_MSG)
				|| (pdu->type == TRP_REQ_MSG)
				|| (pdu->type == SET_REQ_MSG) )
			{
				sp->callback(RECEIVED_MESSAGE, sp, pdu->request_id, 0, pdu, sp->callback_magic);
				/*
				 * Then we should return as soon as possible
				 * because may have closed the session and
				 * corrupted the pointers
				 */
			}

			snmp_pdu_free(pdu);

			return 1;
		}
	}

	return 0;
}


void snmp_session_read_2(int fd)
{
	SNMP_session_list *slp;
	SNMP_session *sp;
	SNMP_internal_session *isp;
	SNMP_pdu *pdu;
	SNMP_request_list *rp, *orp;


	for(slp = first_session; slp; slp = slp->next)
	{
		if(slp->internal->sd == fd)
		{
			Address address;


			sp = slp->session;
			isp = slp->internal;

			pdu = snmp_pdu_receive(isp->sd, &address, static_error_label);
			if(pdu == NULL)
			{
				(void)fprintf(stderr, ERR_MSG_RECEIVED_MANGLED_PACKET,
					static_error_label);
				return;
			}

			if(pdu->type == GET_RSP_MSG)
			{
				for(rp = isp->requests; rp; rp = rp->next_request)
				{
					if(rp->request_id == pdu->request_id)
					{
						/* delete request */
						orp = rp;
						if(isp->requests == orp)
						{
							/* first in list */

							isp->requests = orp->next_request;
						}
						else
						{
							for(rp = isp->requests; rp; rp = rp->next_request)
							{
								if(rp->next_request == orp)
								{
									rp->next_request = orp->next_request; /* link around it */
									break;
								}
							}
						}

						sp->callback(RECEIVED_MESSAGE, sp, pdu->request_id, orp->predefined_id, pdu, sp->callback_magic);

						snmp_pdu_free(orp->pdu);
						free(orp);

						/*
						 * Then we should return as soon as possible
						 * because may have closed the session and
						 * corrupted the pointers
						 */

						break;
					}
				}
			}
			else
			if( (pdu->type == GET_REQ_MSG)
				|| (pdu->type == GETNEXT_REQ_MSG)
				|| (pdu->type == TRP_REQ_MSG)
				|| (pdu->type == SET_REQ_MSG) )
			{
				sp->callback(RECEIVED_MESSAGE, sp, pdu->request_id, 0, pdu, sp->callback_magic);
				/*
				 * Then we should return as soon as possible
				 * because may have closed the session and
				 * corrupted the pointers
				 */
			}

			snmp_pdu_free(pdu);

			return;
		}
	}

	return;
}


/*******************************************************************/

int snmp_session_select_info(int *numfds, fd_set *fdset, struct timeval *timeout)
{
	SNMP_session_list *slp;
	SNMP_internal_session *isp;
	SNMP_request_list *rp;
	struct timeval now, earliest;
	int active = 0, requests = 0;


	timerclear(&earliest);

	/*
	 *	For each request outstanding, add it's socket to the fdset,
	 *	and if it is the earliest timeout to expire, mark it as lowest.
	 */
	for(slp = first_session; slp; slp = slp->next)
	{
		active++;
		isp = slp->internal;
		if((isp->sd + 1) > *numfds)
		{
			*numfds = (isp->sd + 1);
		}
		FD_SET(isp->sd, fdset);

		if(isp->requests)
		{
			/* found another session with outstanding requests */
			for(rp = isp->requests; rp; rp = rp->next_request)
			{
				requests++;
				if(!timerisset(&earliest) || timercmp(&rp->expire, &earliest, <))
				{
					earliest.tv_sec = rp->expire.tv_sec;
					earliest.tv_usec = rp->expire.tv_usec;
				}
			}
		}
	}
/*
printf("NUM REQUESTS:     %d\n",
	requests);
*/

	if(requests == 0)
	{
		/* if none are active, skip arithmetic */

		return 0;
	}
/*
printf("EARLIEST TIMEOUT: %d sec and %d usec\n\n",
	earliest.tv_sec,
	earliest.tv_usec);
*/

	/*
	 *	Now find out how much time until the earliest timeout.  This
	 *	transforms earliest from an absolute time into a delta time, the
	 *	time left until the select should timeout.
	 */
	(void)gettimeofday(&now, (struct timezone *)0);
	earliest.tv_sec--;	/* adjust time to make arithmetic easier */
	earliest.tv_usec += 1000000L;
	earliest.tv_sec -= now.tv_sec;
	earliest.tv_usec -= now.tv_usec;
	while(earliest.tv_usec >= 1000000L)
	{
		earliest.tv_usec -= 1000000L;
		earliest.tv_sec += 1;
	}
	if(earliest.tv_sec < 0)
	{
		earliest.tv_sec = 0;
		earliest.tv_usec = 0;
	}
	if((earliest.tv_sec == 0) && (earliest.tv_usec == 0))
	{
		earliest.tv_sec = 0;
		earliest.tv_usec = 1;
	}

	if(timercmp(&earliest, timeout, <))
	{
		timeout->tv_sec = earliest.tv_sec;
		timeout->tv_usec = earliest.tv_usec;
	}
	else
	if((timeout->tv_sec == 0) && (timeout->tv_usec == 0))
	{
		timeout->tv_sec = earliest.tv_sec;
		timeout->tv_usec = earliest.tv_usec;
	}

/*
printf("NEW TIMEOUT: %d sec and %d usec\n\n",
	timeout->tv_sec,
	timeout->tv_usec);
*/

	return requests;
}


int snmp_session_itimeout_info(struct itimerval *itimeout)
{
	int numfds = 0;
	fd_set fdset;


	FD_ZERO(&fdset);

	return snmp_session_select_info(&numfds, &fdset, &(itimeout->it_value));
}


/*******************************************************************/

/*
 *	It may remain some bugs in this function
 *	because the user may close the session in the callback
 *	and then corrupt the list
 */

void snmp_session_timeout()
{
	while(snmp_session_timeout_loop());
}

static int snmp_session_timeout_loop()
{
	SNMP_session_list *slp;
	SNMP_session *sp;
	SNMP_internal_session *isp;
	SNMP_request_list *rp, *orp;
	struct timeval now;


	(void)gettimeofday(&now, (struct timezone *) 0);

	/*
	 *	For each request outstanding, check to see if it has expired.
	*/

	for(slp = first_session; slp; slp = slp->next)
	{
		sp = slp->session;
		isp = slp->internal;
		orp = NULL;
		for(rp = isp->requests; rp; rp = rp->next_request)
		{
			if(timercmp(&rp->expire, &now, <))
			{
				/* this timer has expired */

				if (rp->retries >= sp->retries)
				{
					/* No more chances, delete this entry */


					if(orp == NULL)
					{
						isp->requests = rp->next_request;
					}
					else
					{
						orp->next_request = rp->next_request;
					}

					sp->callback(TIMED_OUT, sp, rp->pdu->request_id, rp->predefined_id, rp->pdu, sp->callback_magic);

					snmp_pdu_free(rp->pdu);
					free(rp);

					return 1;
				}
				else
				{
					/* retransmit this pdu */

					struct timeval tv;


					rp->retries++;
					rp->timeout <<= 1;

					(void)gettimeofday(&tv, (struct timezone *) 0);
					if(snmp_pdu_send(isp->sd, &(isp->address), rp->pdu, static_error_label))
					{
						(void)fprintf(stderr, "snmp_pdu_send() failed: %s\n",
							static_error_label);
					}

					rp->time.tv_sec = tv.tv_sec;
					rp->time.tv_usec = tv.tv_usec;
/*
printf("%d NOW:    %d sec and %d usec\n",
	rp->retries,
	tv.tv_sec,
	tv.tv_usec);
*/

					tv.tv_usec += rp->timeout;
					tv.tv_sec += tv.tv_usec / 1000000L;
					tv.tv_usec %= 1000000L;

					rp->expire.tv_sec = tv.tv_sec;
					rp->expire.tv_usec = tv.tv_usec;
/*
printf("%d EXPIRE: %d sec and %d usec\n\n",
	rp->retries,
	tv.tv_sec,
	tv.tv_usec);
*/
				}
			}
			orp = rp;
		}
	}

	return 0;
}



