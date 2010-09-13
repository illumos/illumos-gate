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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_LIBDSCP_H
#define	_LIBDSCP_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/socket.h>
#include <netinet/in.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * DSCP Error Codes
 */
typedef enum {
	DSCP_OK = 0,		/* Success */
	DSCP_ERROR,		/* General Error */
	DSCP_ERROR_ALREADY,	/* Socket Already Bound */
	DSCP_ERROR_INVALID,	/* Invalid Arguments */
	DSCP_ERROR_NOENT,	/* Lookup Failure From dscpIdent() */
	DSCP_ERROR_DB,		/* Error Reading Database */
	DSCP_ERROR_REJECT,	/* Rejection From dscpAuth() */
	DSCP_ERROR_DOWN		/* DSCP Interface down */
} dscp_err_t;

/*
 * Possible values for the 'which' parameter to dscpAddr().
 */
#define	DSCP_ADDR_LOCAL		(1)	/* Get the domain's local IP address */
#define	DSCP_ADDR_REMOTE	(2)	/* Get the SP's remote IP address */

/*
 * Define a special value used to represent the SP as a domain ID.
 */
#define	DSCP_IDENT_SP		(-1)

int	dscpBind(int domain, int sockfd, int port);
int	dscpSecure(int domain, int sockfd);
int	dscpAuth(int domain, struct sockaddr *saddr, int len);
int	dscpAddr(int domain, int which, struct sockaddr *saddr, int *lenp);
int	dscpIdent(struct sockaddr *saddr, int len, int *domainp);

#ifdef __cplusplus
}
#endif

#endif	/* _LIBDSCP_H */
