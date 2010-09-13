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

#ifndef _SNMP_API_H_
#define _SNMP_API_H_

#include <sys/types.h>
#include "impl.h"
#include "snmp.h"
#include "pdu.h"


/***** NEW CONSTANTS *****/

/*
 *	Set fields in session to the following to
 *	get a default or unconfigured value.
 */

#define SNMP_DEFAULT_COMMUNITY		NULL
#define SNMP_DEFAULT_RETRIES		-1
#define SNMP_DEFAULT_TIMEOUT		-1
#define SNMP_DEFAULT_REMPORT		0
#define SNMP_DEFAULT_LOCPORT		0


/*
 *	Error return values
 */

#define SNMPERR_GENERR		-1
#define SNMPERR_BAD_LOCPORT	-2  /* local port was already in use */
#define SNMPERR_BAD_ADDRESS	-3
#define SNMPERR_BAD_SESSION	-4
#define SNMPERR_SYSERR		-5


/*
 *	Operation values	(see callback())
 */

#define RECEIVED_MESSAGE	1
#define TIMED_OUT		2


/***** NEW TYPES *****/

/*
 *	community:	community for outgoing requests
 *	retries:	Number of retries before timeout 
 *	timeout:	Number of uS until first timeout, then exponential backoff
 *	peername:	Domain name or dotted IP address of default peer
 *	remote_port:	UDP port number of peer
 *	local_port:	My UDP port number, 0 for default, picked randomly
 *	callback:	Function to interpret incoming data
 *	callback_magic:	Pointer to data that the callback function may consider important
 *	sd:		socket descriptor associated with that session
 */

typedef struct SNMP_session {
	char	*community;
	int	retries;
	int32_t	timeout;
	char	*peername;
	u_short	remote_port;
	u_short	local_port;
	void	(*callback)();
	void	*callback_magic;
	int	sd;
} SNMP_session;


/***** GLOBAL VARIABLES *****/

extern int snmp_errno;


/***** GLOBAL FUNCTIONS *****/

/*
 *	snmp_session_open()
 * 
 *	Sets up the session with the information provided
 *	by the user. Then opens and binds the necessary UDP port.
 *	A handle to the created session is returned.
 *	On any error, NULL is returned
 *	and snmp_errno is set to the appropriate error code.
 */

SNMP_session *snmp_session_open(char *peername, char *community, int retries, int32_t timeout, void callback(), void *callback_magic, char *error_label);

SNMP_session *snmp_session_open_default(char *peername, void callback(), void *callback_magic, char *error_label);


/*
 *	snmp_session_close()
 * 
 *	Close the input session.  Frees all data allocated for the session,
 *	dequeues any pending requests, and closes any sockets allocated for
 *	the session.  Returns 0 on sucess, -1 otherwise.
 */

int snmp_session_close(SNMP_session *session, char *error_label);


/*
 *	snmp_session_send()
 * 
 *	Sends the input pdu on the session.
 *	Add a request corresponding to this pdu to the list
 *	of outstanding requests on this session, then send the pdu.
 *	Returns 0 upon sucess.
 *	On any error, -1 is returned.
 *
 *	The pdu is freed by snmp_send() unless a failure occured.
 */

int snmp_session_send(SNMP_session *session, int predefined_id, SNMP_pdu *pdu, char *error_label);


/*
 *	snmp_session_read()
 * 
 *	Checks to see if any of the fd's set in the fdset belong to
 *	snmp. Each socket with it's fd set has a packet read from it
 *	The resulting pdu is passed to the callback routine for that session.
 */

void snmp_session_read(fd_set *fdset);

void snmp_session_read_2(int fd);


/*
 *	snmp_session_select_info()
 *
 *	Returns info about what snmp requires from a select statement.
 *	numfds is the number of fds in the list that are significant.
 *	All file descriptors opened for SNMP are OR'd into the fdset.
 *	If activity occurs on any of these file descriptors, snmp_read
 *	should be called with that file descriptor set.
 *
 *	The timeout is the latest time that SNMP can wait for a timeout. The
 *	select should be done with the minimum time between timeout and any other
 *	timeouts necessary. This should be checked upon each invocation of select.
 *	If a timeout is received, snmp_timeout should be called to check if the
 *	timeout was for SNMP. (snmp_timeout is idempotent)
 *
 *	snmp_session_select_info returns the number of current requests.
 */

int snmp_session_select_info(int *numfds, fd_set *fdset, struct timeval *timeout);

int snmp_session_timeout_info(struct itimerval *itimeout);


/*
 *	snmp_session_timeout()
 * 
 *	snmp_timeout should be called whenever the timeout from snmp_select_info expires,
 *	but it is idempotent, so snmp_timeout can be polled (probably a cpu expensive
 *	proposition). snmp_timeout checks to see if any of the sessions have an
 *	outstanding request that has timed out.  If it finds one (or more), and that
 *	pdu has more retries available, a new packet is formed from the pdu and is
 *	resent. If there are no more retries available, the callback for the session
 *	is used to alert the user of the timeout.
 */

void snmp_session_timeout();


/*
 *	This routine must be supplied by the application:
 *
 *	void callback(
 *		int operation,
 *		SNMP_session *session,	The session authenticated under.
 *		int request_id,		The request id of this pdu (0 for TRAP)
 *		int predefined_id,
 *		SNMP_pdu *pdu,		The pdu information.
 *		void *magic);		A link to the data for this routine.
 *
 *	Any data in the pdu must be copied because it will be freed elsewhere.
 *	Operations are defined above.
 */

#endif

