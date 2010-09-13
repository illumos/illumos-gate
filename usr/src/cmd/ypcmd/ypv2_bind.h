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
 * Copyright 1990 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Portions of this source code were derived from Berkeley 4.3 BSD
 * under license from the Regents of the University of California.
 */

#ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This file contains symbols and structures defining diffences
 * between Version 3 and Version 2 of the yp bind protocol.
 */

#include "netinet/in.h"

#define YPBINDOLDVERS	((u_long)2)
#define YPOLDMAXDOMAIN	((u_long)64)

struct domv2_binding {
	struct domv2_binding *dom_pnext;
	char dom_domain[YPMAXDOMAIN + 1];
	struct sockaddr_in dom_server_addr;
	unsigned short int dom_server_port;
	int dom_socket;
	CLIENT *dom_client;
	unsigned short int dom_local_port;
	long int dom_vers;
};


/*
 *		Protocol between clients and yp binder servers
 */

/*
 * Response structure and binding info
 */

struct ypbindv2_binding {
	struct in_addr ypbind_binding_addr;	/* In network order */
	unsigned short int ypbind_binding_port;	/* In network order */
};
struct ypbindv2_resp {
	enum ypbind_resptype ypbind_status;
	union {
		unsigned long ypbind_error;
		struct ypbindv2_binding ypbind_bindinfo;
	} ypbind_respbody;
};

/*
 * Request data structure for ypbind "Set domain" procedure.
 */
struct ypbindv2_setdom {
	char ypsetdom_domain[YPMAXDOMAIN + 1];
	struct ypbindv2_binding ypsetdom_binding;
	unsigned short ypsetdom_vers;
};
#define ypsetdom_addr ypsetdom_binding.ypbind_binding_addr
#define ypsetdom_port ypsetdom_binding.ypbind_binding_port
