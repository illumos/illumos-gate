%/*
% * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
% * Use is subject to license terms.
% *
% * CDDL HEADER START
% *
% * The contents of this file are subject to the terms of the
% * Common Development and Distribution License, Version 1.0 only
% * (the "License").  You may not use this file except in compliance
% * with the License.
% *
% * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
% * or http://www.opensolaris.org/os/licensing.
% * See the License for the specific language governing permissions
% * and limitations under the License.
% *
% * When distributing Covered Code, include this CDDL HEADER in each
% * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
% * If applicable, add the following below this CDDL HEADER, with the
% * fields enclosed by brackets "[]" replaced with your own identifying
% * information: Portions Copyright [yyyy] [name of copyright owner]
% *
% * CDDL HEADER END
% */
%
%#pragma ident	"%Z%%M%	%I%	%E% SMI"
%
%/* from nsm_addr.x */
%
%/*
% * This is the definition for the REG procedure which is used
% * to register name/address pairs with statd.
% */
%
enum nsm_addr_res {
	nsm_addr_succ = 0,		/* simple success/failure result */
	nsm_addr_fail = 1
};

struct reg1args {
	unsigned int family;		/* address families from socket.h */
	string name<1024>;		/* name to register with this addr */
	netobj address;
};

struct reg1res {
	nsm_addr_res status;
};
%
%/*
% * This is the definition for the UNREG procedure which is used
% * to unregister an address (and its associated name, if that name
% * has no other addresses registered with it) with statd.
% */
struct unreg1args {
	unsigned int family;		/* address families from socket.h */
	string name<1024>;		/* name under this addr to unregister */
	netobj address;
};

struct unreg1res {
	nsm_addr_res status;
};

%
%/*
% * This is the definition for the NSM address registration network
% * protocol which is used to privately support address registration
% * with the status daemon statd (NSM).
% */
program NSM_ADDR_PROGRAM {
	version NSM_ADDR_V1 {
		void
		 NSMADDRPROC1_NULL(void) = 0;
		reg1res
		 NSMADDRPROC1_REG(reg1args) = 1;
		unreg1res
		 NSMADDRPROC1_UNREG(unreg1args) = 2;
	} = 1;
} = 100133;
