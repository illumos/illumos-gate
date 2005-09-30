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

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * unset the secret key on local machine
 */
#include <stdio.h>
#include <rpc/rpc.h>
#include <rpc/key_prot.h>
#include <nfs/nfs.h>
#include <nfs/nfssys.h>

extern int key_removesecret_g();

/* for revoking kernel NFS credentials */
struct nfs_revauth_args nra;

int
main(int argc, char *argv[])
{
	static char secret[HEXKEYBYTES + 1];
	int err = 0;

	if (geteuid() == 0) {
		if ((argc != 2) || (strcmp(argv[1], "-f") != 0)) {
			fprintf(stderr,
"keylogout by root would break the rpc services that");
			fprintf(stderr, " use secure rpc on this host!\n");
			fprintf(stderr,
"root may use keylogout -f to do this (at your own risk)!\n");
			exit(-1);
		}
	}

	if (key_removesecret_g() < 0) {
			fprintf(stderr, "Could not unset your secret key.\n");
			fprintf(stderr, "Maybe the keyserver is down?\n");
			err = 1;
	}
	if (key_setsecret(secret) < 0) {
		if (!err) {
			fprintf(stderr, "Could not unset your secret key.\n");
			fprintf(stderr, "Maybe the keyserver is down?\n");
			err = 1;
		}
	}

	nra.authtype = AUTH_DES;	/* only revoke DES creds */
	nra.uid = getuid();		/* use the real uid */
	if (_nfssys(NFS_REVAUTH, &nra) < 0) {
		perror("Warning: NFS credentials not destroyed");
		err = 1;
	}

	return (err);
}
