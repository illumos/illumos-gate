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
 * Copyright 2014 Garrett D'Amore <garrett@damore.org>
 *
 * Copyright 1989 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/

/*
 * Portions of this source code were derived from Berkeley 4.3 BSD
 * under license from the Regents of the University of California.
 */

#ifndef	_RPCSVC_YPCLNT_H
#define	_RPCSVC_YPCLNT_H

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * ypclnt.h
 * This defines the symbols used in the c language
 * interface to the yp client functions.  A description of this interface
 * can be read in ypclnt(3N).
 */

/*
 * Failure reason codes.  The success condition is indicated by a functional
 * value of "0".
 */
#define	YPERR_BADARGS 1			/* Args to function are bad */
#define	YPERR_RPC 2			/* RPC failure */
#define	YPERR_DOMAIN 3			/* Can't bind to a server which */
					/*   serves this domain. */
#define	YPERR_MAP 4			/* No such map in server's domain */
#define	YPERR_KEY 5			/* No such key in map */
#define	YPERR_YPERR 6			/* Internal yp server or client */
					/*   interface error */
#define	YPERR_RESRC 7			/* Local resource allocation failure */
#define	YPERR_NOMORE 8			/* No more records in map database */
#define	YPERR_PMAP 9			/* Can't communicate with portmapper */
#define	YPERR_YPBIND 10			/* Can't communicate with ypbind */
#define	YPERR_YPSERV 11			/* Can't communicate with ypserv */
#define	YPERR_NODOM 12			/* Local domain name not set */
#define	YPERR_BADDB 13			/*  yp data base is bad */
#define	YPERR_VERS 14			/* YP version mismatch */
#define	YPERR_ACCESS 15			/* Access violation */
#define	YPERR_BUSY 16			/* Database is busy */

/*
 * Types of update operations
 */
#define	YPOP_CHANGE 1			/* change, do not add */
#define	YPOP_INSERT 2			/* add, do not change */
#define	YPOP_DELETE 3			/* delete this entry */
#define	YPOP_STORE  4			/* add, or change */



/*
 * Data definitions
 */

/*
 * struct ypall_callback * is the arg which must be passed to yp_all
 */

struct ypall_callback {
	int (*foreach)();		/* Return non-0 to stop getting */
					/*   called */
	char *data;			/* Opaque pointer for use of callback */
					/*   function */
};

/*
 * External yp client function references.
 */

extern int yp_bind(char *);
extern void yp_unbind(char *);
extern int yp_get_default_domain(char **);
extern int yp_match(char *, char *, char *, int, char **, int *);
extern int yp_first(char *, char *, char **, int *, char **, int *);
extern int yp_next(char *, char *, char *, int, char **, int *, char **, int *);
extern int yp_master(char *, char *, char **);
extern int yp_order(char *, char *, unsigned long *);
extern int yp_all(char *, char *, struct ypall_callback *);
extern char *yperr_string(int);
extern int ypprot_err(int);
extern int yp_update(char *, char *, unsigned,  char *, int, char *, int);

/*
 * Global yp data structures
 */

#ifdef	__cplusplus
}
#endif

#endif	/* _RPCSVC_YPCLNT_H */
