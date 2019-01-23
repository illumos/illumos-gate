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

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

/*
 * code for netstat's -k option
 *
 * NOTES:
 * 1. A comment "LINTED: (note 1)" appears before certain lines where
 *    lint would have complained, "pointer cast may result in improper
 *    alignment". These are lines where lint had suspected potential
 *    improper alignment of a data structure; in each such situation
 *    we have relied on the kernel guaranteeing proper alignment.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <strings.h>
#include <string.h>
#include <kstat.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stream.h>
#include <sys/tiuser.h>
#include <sys/socketvar.h>
#include <sys/sysmacros.h>

static char		*typetoname(t_scalar_t);
static void		print_kn(kstat_t *);
static char		*nextstr(char *);
extern void		fail(int, char *, ...);

#define	NALEN	8			/* nulladdress string length	*/

/*
 * Print a summary of connections related to a unix protocol.
 */
void
unixpr(kstat_ctl_t 	*kc)
{
	kstat_t		*ksp;

	if (kc == NULL) {	/* sanity check.			*/
		fail(0, "unixpr: No kstat");
		exit(3);
	}

	/* find the sockfs kstat:					*/
	if ((ksp = kstat_lookup(kc, "sockfs", 0, "sock_unix_list")) ==
	    (kstat_t *)NULL) {
		fail(0, "kstat_data_lookup failed\n");
	}

	if (kstat_read(kc, ksp, NULL) == -1) {
		fail(0, "kstat_read failed for sock_unix_list\n");
	}

	print_kn(ksp);
}

static void
print_kn(kstat_t *ksp)
{
	int		i;
	struct sockinfo	*psi;		/* ptr to current sockinfo	*/
	char		*pas;		/* ptr to string-format addrs	*/
	char		*nullstr;	/* ptr to null string		*/
	char		*conn_vp;
	char		*local_vp;

	if (ksp->ks_ndata == 0) {
		return;			/* no AF_UNIX sockets found	*/
	}

	/*
	 * Having ks_data set with ks_data == NULL shouldn't happen;
	 * If it does, the sockfs kstat is seriously broken.
	 */
	if ((psi = ksp->ks_data) == NULL) {
		fail(0, "print_kn: no kstat data\n");
	}

	/* set pas to the address strings which are after the sockinfo	*/
	pas = &((char *)psi)[sizeof (struct sockinfo)];

	/* Create a string of NALEN "0"'s for NULL addresses.		*/
	if ((nullstr = calloc(1, NALEN)) == NULL) {
		fail(0, "print_kn: out of memory\n");
	}
	(void) memset((void *)nullstr, '0', NALEN);

	(void) printf("\nActive UNIX domain sockets\n");
	(void) printf("%-8.8s %-10.10s %8.8s %8.8s  "
	    "Local Addr      Remote Addr\n",
	    "Address", "Type", "Vnode", "Conn");

	/* for each sockinfo structure, display what we need:		*/
	for (i = 0; i < ksp->ks_ndata; i++) {
		/* display sonode's address. 1st string after sockinfo:	*/
		pas = &(((char *)psi)[sizeof (struct sockinfo)]);
		(void) printf("%s ", pas);

		(void) printf("%-10.10s ", typetoname(psi->si_serv_type));

		/* laddr.sou_vp: 2nd string after sockinfo:		*/
		pas = nextstr(pas);

		local_vp = conn_vp = nullstr;

		if ((psi->si_state & SS_ISBOUND) &&
		    (psi->si_ux_laddr_sou_magic == SOU_MAGIC_EXPLICIT)) {
			local_vp = pas;
		}

		/* faddr.sou_vp: 3rd string after sockinfo:		*/
		pas = nextstr(pas);
		if ((psi->si_state & SS_ISCONNECTED) &&
		    (psi->si_ux_faddr_sou_magic == SOU_MAGIC_EXPLICIT)) {
			conn_vp = pas;
		}

		(void) printf("%s %s ", local_vp, conn_vp);

		/* laddr.soa_sa: 					*/
		if ((psi->si_state & SS_ISBOUND) &&
		    strlen(psi->si_laddr_sun_path) != 0 &&
		    psi->si_laddr_soa_len != 0) {
			if (psi->si_faddr_noxlate) {
				(void) printf(" (socketpair)  ");
			} else {
				if (psi->si_laddr_soa_len >
				    sizeof (psi->si_laddr_family))
					(void) printf("%s ",
					    psi->si_laddr_sun_path);
				else
					(void) printf("               ");
			}
		} else
			(void) printf("               ");

		/* faddr.soa_sa:					*/
		if ((psi->si_state & SS_ISCONNECTED) &&
		    strlen(psi->si_faddr_sun_path) != 0 &&
		    psi->si_faddr_soa_len != 0) {

			if (psi->si_faddr_noxlate) {
				(void) printf(" (socketpair)  ");
			} else {
				if (psi->si_faddr_soa_len >
				    sizeof (psi->si_faddr_family))
					(void) printf("%s ",
					    psi->si_faddr_sun_path);
				else
					(void) printf("               ");
			}
		} else
			(void) printf("               ");

		(void) printf("\n");

		/* if si_size didn't get filled in, then we're done	*/
		if (psi->si_size == 0 ||
		    !IS_P2ALIGNED(psi->si_size, sizeof (psi))) {
			break;
		}

		/* LINTED: (note 1) */
		psi = (struct sockinfo *)&(((char *)psi)[psi->si_size]);
	}
}

static char *
typetoname(t_scalar_t type)
{
	switch (type) {
	case T_CLTS:
		return ("dgram");

	case T_COTS:
		return ("stream");

	case T_COTS_ORD:
		return ("stream-ord");

	default:
		return ("");
	}
}

/*
 * nextstr():	find the beginning of a next string.
 *	The sockfs kstat left-justifies each address string, leaving
 *	null's between the strings. Since we don't necessarily know
 *	the sizes of pointers in the kernel, we need to skip over these
 *	nulls in order to get to the start of the next string.
 */
static char *
nextstr(char *pas)
{
	char *next;

	for (next = &pas[strlen(pas) + 1]; *next == '\0'; ) {
		next++;
	}

	return (next);
}
