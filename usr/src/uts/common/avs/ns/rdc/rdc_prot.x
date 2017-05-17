%/*
% * CDDL HEADER START
% *
% * The contents of this file are subject to the terms of the
% * Common Development and Distribution License (the "License").
% * You may not use this file except in compliance with the License.
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
%
%/*
% * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
% * Use is subject to license terms.
% */
%
%/*
% * Auto generated from rdc_prot.x
% */
%
%/* 
% * Network Replicator RPC spec
% */

%
%/*
% * We don't define netbuf in RPCL, since it would contain structure member
% * names that would conflict with the definition of struct netbuf in
% * <tiuser.h>.  Instead we merely declare the XDR routine xdr_netbuf() here,
% * and implement it ourselves in rpc/rpcb_prot.c.
% */
%#ifdef __cplusplus
%extern "C" bool_t xdr_netbuf(XDR *, struct netbuf *);
%
%#elif __STDC__
%extern  bool_t xdr_netbuf(XDR *, struct netbuf *);
%
%#else /* K&R C */
%bool_t xdr_netbuf();
%
%#endif /* K&R C */
const RDC_PORT          = 121;
const RDC_MAXDATA       = 32768;
const RDC_MAXNAMLEN	= 64;
const RDC_BMAPBLKSIZE	= 1024;
const RDC_MAXADDR	= 32;
const RDC_MAXPENDQ	= 64;

%/*
% * Use this to limit the size of the net_pendvec_t array
% * to ~ 32k
% */
const RDC_PENDQLIM	= 1365;    
%
%/*
% * Error status
% */
enum rdcstat {
	RDC_OK = 0,
	RDCERR_PERM = 1,
	RDCERR_NOENT = 2,
	RDCERR_NOMEM = 3
};

%
%/*
%* Set state (V4)
%*/

struct set_state4 {
	opaque		netaddr[RDC_MAXADDR];
	opaque		rnetaddr[RDC_MAXADDR];
	int		netaddrlen;
	int		rnetaddrlen;
	unsigned	flag;
	opaque 		pfile[RDC_MAXNAMLEN];
	opaque		sfile[RDC_MAXNAMLEN];
};

const RDC_XDR_MAXNAMLEN = RDC_MAXNAMLEN;

struct set_state {
	struct netbuf		netaddr;
	struct netbuf		rnetaddr;
	int		netaddrlen;
	int		rnetaddrlen;
	unsigned	flag;
	string 		pfile<RDC_XDR_MAXNAMLEN>;
	string		sfile<RDC_XDR_MAXNAMLEN>;
};

%
%/*
% * Get size of volume
% */
struct getsize {
	int cd;
};

%
%/*
% * Remote read (v5)
% */
struct rread {
	int cd;
	int len;
	int pos;
	int idx;
	int flag;
};

%
%/*
% * Remote read (v6)
% */
struct rread6 {
	int cd;
	int len;
	u_longlong_t pos;
	int idx;
	int flag;
};

%
%/*
% * status OK from remote read
% */
struct readok {
	opaque data<RDC_MAXDATA>;
};
union readres switch (rdcstat status) {
case RDC_OK:
	readok reply;
default:
	void;
};

%
%/*
% * Initiate bit map scoreboard transfer (v5)
% */
struct bmap {
	int cd;
	int dual;
	int size;
};

%
%/*
% * Initiate bit map scoreboard transfer (v6)
% */
struct bmap6 {
	int cd;
	int dual;
	u_longlong_t size;
};

%
%/*
% * Scoreboard bitmap data (v5)
% */
struct net_bdata {
	int cd;	
	int offset;
	int size;
	opaque data<RDC_BMAPBLKSIZE>;
};

%
%/*
% * Scoreboard bitmap data (v6)
% */
struct net_bdata6 {
	u_longlong_t offset;
	int size;
	int cd;	
	int endoblk;
	opaque data<RDC_BMAPBLKSIZE>;
};

%
%/*
% * Data transfer and allocation (v5)
% */
struct net_data5 {
	int local_cd;
	int cd;
	int pos;
	int len;
	int flag;
	int idx;
	int seq;
	int sfba;
	int endoblk;
	int nfba;
	opaque data<RDC_MAXDATA>;
};

%
%/*
% * Data transfer and allocation (v6)
% */
struct net_data6 {
	int local_cd;
	int cd;
	u_longlong_t pos;
	u_longlong_t qpos;
	u_longlong_t sfba;
	int nfba;
	int len;
	int flag;
	int idx;
	unsigned int seq;
	int endoblk;
	opaque data<RDC_MAXDATA>;
};


struct net_pendvec {
	u_longlong_t	apos;
	u_longlong_t	qpos;
	int		alen;
	unsigned int	seq;
	int		pindex;
};
typedef net_pendvec net_pendvec_t;



%/*
% * results returned from a netwrite request. (v6)
% * index = index number of request assigned by server when
% * requests is broken down into smaller chunks.
% * result = 0 request ok.
% * result = 1 request is pending.
% * result < 0 failure, set with -errno.
% * If the vecdata array is not empty, then it contains
% * a list of apos and alen
% * pairs of previously pending requests that have been written.
% */
struct netwriteres {
	int index;
	int result;
	unsigned int seq;
	net_pendvec_t vecdata<RDC_PENDQLIM>;
};



%
%/*
% * Ping
% */
struct rdc_ping6 {
	opaque p_ifaddr[RDC_MAXADDR];
	opaque s_ifaddr[RDC_MAXADDR];
};

struct rdc_ping {
	struct netbuf p_ifaddr;
	struct netbuf s_ifaddr;
};


/*
 * Remote file service routines
 */

program RDC_PROGRAM {

	/*
	 * This is protocol version 5 that shipped with SNDR 3.1
	 * We must support this protocol until (protocol
	 * version 7) is released.
	 * I.e. N-1 protocol support.
	 */

	version RDC_VERSION5 {

		void 
		RDCPROC_NULL(void) = 0;

		int 
		RDCPROC_GETSIZE(int) = 2;

		int 
		RDCPROC_WRITE5(net_data5) = 4;

		readres
		RDCPROC_READ5(rread) = 5;

		int
		RDCPROC_STATE(set_state4) = 7;

		int 
		RDCPROC_PING4(rdc_ping6) = 8;

		int
		RDCPROC_BMAP(net_bmap) = 9;

		int
		RDCPROC_BDATA(net_bdata) = 10;

		int
		RDCPROC_GETSTATE4(set_state4) = 12;
	} = 5;

	/*
	 * This is protocol version 6 that shipped with SNDR 3.2
	 * We must support this protocol until (protocol
	 * version 8) is released.
	 * I.e. N-1 protocol support.
	 *
	 * Changed to support multiple transmitting async threads
	 * (sequence numbers and write reply structure)
	 * and 64bit datapath.
	 */

	version RDC_VERSION6 {

		void 
		RDCPROC_NULL(void) = 0;

		u_longlong_t 
		RDCPROC_GETSIZE6(int) = 2;

		netwriteres 
		RDCPROC_WRITE6(net_data6) = 4;

		readres
		RDCPROC_READ6(rread6) = 5;

		int
		RDCPROC_STATE(set_state4) = 7;

		int 
		RDCPROC_PING4(rdc_ping6) = 8;

		int
		RDCPROC_BMAP6(net_bmap6) = 9;

		int
		RDCPROC_BDATA6(net_bdata6) = 10;

		int
		RDCPROC_GETSTATE4(set_state4) = 12;
	} = 6;

	version RDC_VERSION7 {

		void 
		RDCPROC_NULL(void) = 0;

		u_longlong_t 
		RDCPROC_GETSIZE6(int) = 2;

		netwriteres 
		RDCPROC_WRITE6(net_data6) = 4;

		readres
		RDCPROC_READ6(rread6) = 5;

		int
		RDCPROC_STATE(set_state) = 7;

		int 
		RDCPROC_PING4(rdc_ping) = 8;

		int
		RDCPROC_BMAP6(net_bmap6) = 9;

		int
		RDCPROC_BDATA6(net_bdata6) = 10;

		int
		RDCPROC_GETSTATE4(set_state) = 12;
	} = 7;

} = 100143;
