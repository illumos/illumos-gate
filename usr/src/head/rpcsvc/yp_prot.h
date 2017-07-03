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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/

/*
 * Portions of this source code were derived from Berkeley 4.3 BSD
 * under license from the Regents of the University of California.
 */

#ifndef	_RPCSVC_YP_PROT_H
#define	_RPCSVC_YP_PROT_H

#include <rpc/rpc.h>
#include <rpcsvc/ypclnt.h>
#include <ndbm.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * This file contains symbols and structures defining the rpc protocol
 * between the YP clients and the YP servers.  The servers are the YP
 * database servers, and the YP.
 */

/*
 * The following procedures are supported by the protocol:
 *
 * YPPROC_NULL() returns () takes nothing, returns nothing.  This indicates
 * that the yp server is alive.
 *
 * YPPROC_DOMAIN (char *) returns (bool_t) TRUE.  Indicates that the
 * responding yp server does serve the named domain; FALSE indicates no
 * support.
 *
 * YPPROC_DOMAIN_NONACK (char *) returns (TRUE) if the yp server does serve
 * the named domain, otherwise does not return.  Used in the broadcast case.
 *
 * YPPROC_MATCH (struct ypreq_key) returns (struct ypresp_val).  Returns the
 * right-hand value for a passed left-hand key, within a named map and
 * domain.
 *
 * YPPROC_FIRST (struct ypreq_nokey) returns (struct ypresp_key_val).
 * Returns the first key-value pair from a named domain and map.
 *
 * YPPROC_NEXT (struct ypreq_key) returns (struct ypresp_key_val).  Returns
 * the key-value pair following a passed key-value pair within a named
 * domain and map.
 *
 * YPPROC_XFR (struct ypreq_xfr) returns nothing.  Indicates to a server that
 * a map should be updated.
 *
 * YPPROC_NEWXFR (struct ypreq_newxfr) returns nothing.  Indicates to a server
 * that a map should be updated. Uses protocol independent request struct.
 *
 * YPPROC_CLEAR	takes nothing, returns nothing.  Instructs a yp server to
 * close the current map, so that old versions of the disk file don't get
 * held open.
 *
 * YPPROC_ALL (struct ypreq_nokey), returns
 *	union switch (bool more) {
 *		TRUE:	(struct ypresp_key_val);
 *		FALSE:	(struct) {};
 *	}
 *
 * YPPROC_MASTER (struct ypreq_nokey), returns (ypresp_master)
 *
 * YPPROC_ORDER (struct ypreq_nokey), returns (ypresp_order)
 *
 * YPPROC_MAPLIST (char *), returns (struct ypmaplist *)
 */

/* 'bool' is a built-in type for g++ */
#if !(defined(__cplusplus) && defined(_BOOL)) && !defined(__GNUG__)
#ifndef BOOL_DEFINED
typedef unsigned int bool;
#define	BOOL_DEFINED
#endif
#endif

/* Program and version symbols, magic numbers */

#define	YPPROG		((rpcprog_t)100004)
#define	YPVERS		((rpcvers_t)2)
#define	YPVERS_ORIG	((rpcvers_t)1)
#define	YPMAXRECORD	((uint_t)1024)
#define	YPMAXDOMAIN	((uint_t)256)
#define	YPMAXMAP	((uint_t)64)
#define	YPMAXPEER	((uint_t)256)

/* byte size of a large yp packet */
#define	YPMSGSZ		1600

struct ypmap_parms {
	char *domain;			/* Null string means not available */
	char *map;			/* Null string means not available */
	unsigned int ordernum;		/* 0 means not available */
	char *owner;			/* Null string means not available */
};

/*
 * Request parameter structures
 */

struct ypreq_key {
	char *domain;
	char *map;
	datum keydat;
};

struct ypreq_nokey {
	char *domain;
	char *map;
};

struct ypreq_xfr {
	struct ypmap_parms map_parms;
	unsigned int transid;
	unsigned int proto;
	unsigned short port;
};

struct ypreq_newxfr {
	struct ypmap_parms map_parms;
	unsigned int transid;
	unsigned int proto;
	char *name;
};

#define	ypxfr_domain map_parms.domain
#define	ypxfr_map map_parms.map
#define	ypxfr_ordernum map_parms.ordernum
#define	ypxfr_owner map_parms.owner

/*
 * Response parameter structures
 */

struct ypresp_val {
	unsigned int status;
	datum valdat;
};

struct ypresp_key_val {
	unsigned int status;
	datum valdat;
	datum keydat;
};

struct ypresp_master {
	unsigned int status;
	char *master;
};

struct ypresp_order {
	unsigned int status;
	unsigned int ordernum;
};

struct ypmaplist {
	char ypml_name[YPMAXMAP + 1];
	struct ypmaplist *ypml_next;
};

struct ypresp_maplist {
	unsigned int status;
	struct ypmaplist *list;
};

/*
 * Procedure symbols.  YPPROC_NULL, YPPROC_DOMAIN, and YPPROC_DOMAIN_NONACK
 * must keep the same values (0, 1, and 2) that they had in the first version
 * of the protocol.
 */

#define	YPPROC_NULL	((rpcproc_t)0)
#define	YPPROC_DOMAIN	((rpcproc_t)1)
#define	YPPROC_DOMAIN_NONACK ((rpcproc_t)2)
#define	YPPROC_MATCH	((rpcproc_t)3)
#define	YPPROC_FIRST	((rpcproc_t)4)
#define	YPPROC_NEXT	((rpcproc_t)5)
#define	YPPROC_XFR	((rpcproc_t)6)
#define	YPPROC_NEWXFR	((rpcproc_t)12)
#define	YPPROC_CLEAR	((rpcproc_t)7)
#define	YPPROC_ALL	((rpcproc_t)8)
#define	YPPROC_MASTER	((rpcproc_t)9)
#define	YPPROC_ORDER	((rpcproc_t)10)
#define	YPPROC_MAPLIST	((rpcproc_t)11)

/* Return status values */

#define	YP_TRUE		(1)	/* General purpose success code */
#define	YP_NOMORE	(2)	/* No more entries in map */
#define	YP_FALSE	(0)	/* General purpose failure code */
#define	YP_NOMAP	(-1)	/* No such map in domain */
#define	YP_NODOM	(-2)	/* Domain not supported */
#define	YP_NOKEY	(-3)	/* No such key in map */
#define	YP_BADOP	(-4)	/* Invalid operation */
#define	YP_BADDB	(-5)	/* Server data base is bad */
#define	YP_YPERR	(-6)	/* YP server error */
#define	YP_BADARGS	(-7)	/* Request arguments bad */
#define	YP_VERS		(-8)	/* YP server vers. mismatch - server */
				/*   can't supply requested service. */

enum ypreqtype {YPREQ_KEY = 1, YPREQ_NOKEY = 2, YPREQ_MAP_PARMS = 3};
struct yprequest {
	enum ypreqtype yp_reqtype;
	union {
		struct ypreq_key yp_req_keytype;
		struct ypreq_nokey yp_req_nokeytype;
		struct ypmap_parms yp_req_map_parmstype;
	}yp_reqbody;
};

#define	YPMATCH_REQTYPE YPREQ_KEY
#define	ypmatch_req_domain yp_reqbody.yp_req_keytype.domain
#define	ypmatch_req_map yp_reqbody.yp_req_keytype.map
#define	ypmatch_req_keydat yp_reqbody.yp_req_keytype.keydat
#define	ypmatch_req_keyptr yp_reqbody.yp_req_keytype.keydat.dptr
#define	ypmatch_req_keysize yp_reqbody.yp_req_keytype.keydat.dsize

#define	YPFIRST_REQTYPE YPREQ_NOKEY
#define	ypfirst_req_domain yp_reqbody.yp_req_nokeytype.domain
#define	ypfirst_req_map yp_reqbody.yp_req_nokeytype.map

#define	YPNEXT_REQTYPE YPREQ_KEY
#define	ypnext_req_domain yp_reqbody.yp_req_keytype.domain
#define	ypnext_req_map yp_reqbody.yp_req_keytype.map
#define	ypnext_req_keydat yp_reqbody.yp_req_keytype.keydat
#define	ypnext_req_keyptr yp_reqbody.yp_req_keytype.keydat.dptr
#define	ypnext_req_keysize yp_reqbody.yp_req_keytype.keydat.dsize

#define	YPPUSH_REQTYPE YPREQ_NOKEY
#define	yppush_req_domain yp_reqbody.yp_req_nokeytype.domain
#define	yppush_req_map yp_reqbody.yp_req_nokeytype.map

#define	YPPULL_REQTYPE YPREQ_NOKEY
#define	yppull_req_domain yp_reqbody.yp_req_nokeytype.domain
#define	yppull_req_map yp_reqbody.yp_req_nokeytype.map

#define	YPPOLL_REQTYPE YPREQ_NOKEY
#define	yppoll_req_domain yp_reqbody.yp_req_nokeytype.domain
#define	yppoll_req_map yp_reqbody.yp_req_nokeytype.map

#define	YPGET_REQTYPE YPREQ_MAP_PARMS
#define	ypget_req_domain yp_reqbody.yp_req_map_parmstype.domain
#define	ypget_req_map yp_reqbody.yp_req_map_parmstype.map
#define	ypget_req_ordernum yp_reqbody.yp_req_map_parmstype.ordernum
#define	ypget_req_owner yp_reqbody.yp_req_map_parmstype.owner

enum ypresptype {YPRESP_VAL = 1, YPRESP_KEY_VAL = 2, YPRESP_MAP_PARMS = 3};
struct ypresponse {
	enum ypresptype yp_resptype;
	union {
		struct ypresp_val yp_resp_valtype;
		struct ypresp_key_val yp_resp_key_valtype;
		struct ypmap_parms yp_resp_map_parmstype;
	} yp_respbody;
};

#define	YPMATCH_RESPTYPE YPRESP_VAL
#define	ypmatch_resp_status yp_respbody.yp_resp_valtype.status
#define	ypmatch_resp_valdat yp_respbody.yp_resp_valtype.valdat
#define	ypmatch_resp_valptr yp_respbody.yp_resp_valtype.valdat.dptr
#define	ypmatch_resp_valsize yp_respbody.yp_resp_valtype.valdat.dsize

#define	YPFIRST_RESPTYPE YPRESP_KEY_VAL
#define	ypfirst_resp_status yp_respbody.yp_resp_key_valtype.status
#define	ypfirst_resp_keydat yp_respbody.yp_resp_key_valtype.keydat
#define	ypfirst_resp_keyptr yp_respbody.yp_resp_key_valtype.keydat.dptr
#define	ypfirst_resp_keysize yp_respbody.yp_resp_key_valtype.keydat.dsize
#define	ypfirst_resp_valdat yp_respbody.yp_resp_key_valtype.valdat
#define	ypfirst_resp_valptr yp_respbody.yp_resp_key_valtype.valdat.dptr
#define	ypfirst_resp_valsize yp_respbody.yp_resp_key_valtype.valdat.dsize

#define	YPNEXT_RESPTYPE YPRESP_KEY_VAL
#define	ypnext_resp_status yp_respbody.yp_resp_key_valtype.status
#define	ypnext_resp_keydat yp_respbody.yp_resp_key_valtype.keydat
#define	ypnext_resp_keyptr yp_respbody.yp_resp_key_valtype.keydat.dptr
#define	ypnext_resp_keysize yp_respbody.yp_resp_key_valtype.keydat.dsize
#define	ypnext_resp_valdat yp_respbody.yp_resp_key_valtype.valdat
#define	ypnext_resp_valptr yp_respbody.yp_resp_key_valtype.valdat.dptr
#define	ypnext_resp_valsize yp_respbody.yp_resp_key_valtype.valdat.dsize

#define	YPPOLL_RESPTYPE YPRESP_MAP_PARMS
#define	yppoll_resp_domain yp_respbody.yp_resp_map_parmstype.domain
#define	yppoll_resp_map yp_respbody.yp_resp_map_parmstype.map
#define	yppoll_resp_ordernum yp_respbody.yp_resp_map_parmstype.ordernum
#define	yppoll_resp_owner yp_respbody.yp_resp_map_parmstype.owner


extern bool _xdr_yprequest();
extern bool _xdr_ypresponse();
/*
 *		Protocol between clients (ypxfr, only) and yppush
 *		yppush speaks a protocol in the transient range, which
 *		is supplied to ypxfr as a command-line parameter when it
 *		is activated by ypserv.
 */
#define	YPPUSHVERS		((rpcvers_t)1)
#define	YPPUSHVERS_ORIG		((rpcvers_t)1)

/* Procedure symbols */

#define	YPPUSHPROC_NULL		((rpcproc_t)0)
#define	YPPUSHPROC_XFRRESP	((rpcproc_t)1)

struct yppushresp_xfr {
	unsigned int transid;
	unsigned int status;
};

/* Status values for yppushresp_xfr.status */

#define	YPPUSH_SUCC	(1)	/* Success */
#define	YPPUSH_AGE	(2)	/* Master's version not newer */
#define	YPPUSH_NOMAP 	(-1)	/* Can't find server for map */
#define	YPPUSH_NODOM 	(-2)	/* Domain not supported */
#define	YPPUSH_RSRC 	(-3)	/* Local resouce alloc failure */
#define	YPPUSH_RPC 	(-4)	/* RPC failure talking to server */
#define	YPPUSH_MADDR	(-5)	/* Can't get master address */
#define	YPPUSH_YPERR 	(-6)	/* YP server/map db error */
#define	YPPUSH_BADARGS 	(-7)	/* Request arguments bad */
#define	YPPUSH_DBM	(-8)	/* Local dbm operation failed */
#define	YPPUSH_FILE	(-9)	/* Local file I/O operation failed */
#define	YPPUSH_SKEW	(-10)	/* Map version skew during transfer */
#define	YPPUSH_CLEAR	(-11)	/* Can't send "Clear" req to local */
				/*   ypserv */
#define	YPPUSH_FORCE	(-12)	/* No local order number in map - */
				/*   use -f flag. */
#define	YPPUSH_XFRERR	(-13)	/* ypxfr error */
#define	YPPUSH_REFUSED	(-14)	/* Transfer request refused by ypserv */
#define	YPPUSH_NOALIAS	(-15)	/* Alias not found for map or domain */

extern bool xdr_datum(XDR *, datum *);
extern bool xdr_ypdomain_wrap_string(XDR *, char **);
extern bool xdr_ypmap_wrap_string(XDR *, char **);
extern bool xdr_ypreq_key(XDR *, struct ypreq_key *);
extern bool xdr_ypreq_nokey(XDR *, struct ypreq_nokey *);
extern bool xdr_ypreq_xfr(XDR *, struct ypreq_xfr *);
extern bool xdr_ypreq_newxfr(XDR *, struct ypreq_newxfr *);
extern bool xdr_ypresp_val(XDR *, struct ypresp_val *);
extern bool xdr_ypresp_key_val(XDR *, struct ypresp_key_val *);
extern bool xdr_ypmap_parms(XDR *, struct ypmap_parms *);
extern bool xdr_ypowner_wrap_string(XDR *, char **);
extern bool xdr_yppushresp_xfr(XDR *, struct yppushresp_xfr *);
extern bool xdr_ypresp_order(XDR *, struct ypresp_order *);
extern bool xdr_ypresp_master(XDR *, struct ypresp_master *);
extern bool xdr_ypall(XDR *, struct ypall_callback *);
extern bool xdr_ypresp_maplist(XDR *, struct ypresp_maplist *);

#ifdef __cplusplus
}
#endif

#endif	/* _RPCSVC_YP_PROT_H */
