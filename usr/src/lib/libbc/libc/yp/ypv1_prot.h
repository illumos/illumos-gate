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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This contains symbol and structure definitions used in supporting the old
 * "v1" protocol.  They were previously defined in yp_prot.h.
 * 
 * This file exists so that the NIS system can provide backward compatibility.
 * Normal NIS client processes should not use this interface:  the old
 * protocol will not be supported in the next release.  
 */
#define YPOLDVERS		(YPVERS - 1)
#define YPOLDPROC_NULL		((u_long)0)
#define YPOLDPROC_DOMAIN	((u_long)1)
#define YPOLDPROC_DOMAIN_NONACK	((u_long)2)
#define YPOLDPROC_MATCH		((u_long)3)
#define YPOLDPROC_FIRST		((u_long)4)
#define YPOLDPROC_NEXT		((u_long)5)
#define YPOLDPROC_POLL		((u_long)6)
#define YPOLDPROC_PUSH		((u_long)7)
#define YPOLDPROC_PULL		((u_long)8)
#define YPOLDPROC_GET		((u_long)9)

enum ypreqtype {YPREQ_KEY = 1, YPREQ_NOKEY = 2, YPREQ_MAP_PARMS = 3};
struct yprequest {
	enum ypreqtype yp_reqtype;
	union {
		struct ypreq_key yp_req_keytype;
		struct ypreq_nokey yp_req_nokeytype;
		struct ypmap_parms yp_req_map_parmstype;
	}yp_reqbody;
};

#define YPMATCH_REQTYPE YPREQ_KEY
#define ypmatch_req_domain yp_reqbody.yp_req_keytype.domain
#define ypmatch_req_map yp_reqbody.yp_req_keytype.map
#define ypmatch_req_keydat yp_reqbody.yp_req_keytype.keydat
#define ypmatch_req_keyptr yp_reqbody.yp_req_keytype.keydat.dptr
#define ypmatch_req_keysize yp_reqbody.yp_req_keytype.keydat.dsize

#define YPFIRST_REQTYPE YPREQ_NOKEY
#define ypfirst_req_domain yp_reqbody.yp_req_nokeytype.domain
#define ypfirst_req_map yp_reqbody.yp_req_nokeytype.map

#define YPNEXT_REQTYPE YPREQ_KEY
#define ypnext_req_domain yp_reqbody.yp_req_keytype.domain
#define ypnext_req_map yp_reqbody.yp_req_keytype.map
#define ypnext_req_keydat yp_reqbody.yp_req_keytype.keydat
#define ypnext_req_keyptr yp_reqbody.yp_req_keytype.keydat.dptr
#define ypnext_req_keysize yp_reqbody.yp_req_keytype.keydat.dsize

#define YPPUSH_REQTYPE YPREQ_NOKEY
#define yppush_req_domain yp_reqbody.yp_req_nokeytype.domain
#define yppush_req_map yp_reqbody.yp_req_nokeytype.map

#define YPPULL_REQTYPE YPREQ_NOKEY
#define yppull_req_domain yp_reqbody.yp_req_nokeytype.domain
#define yppull_req_map yp_reqbody.yp_req_nokeytype.map

#define YPPOLL_REQTYPE YPREQ_NOKEY
#define yppoll_req_domain yp_reqbody.yp_req_nokeytype.domain
#define yppoll_req_map yp_reqbody.yp_req_nokeytype.map

#define YPGET_REQTYPE YPREQ_MAP_PARMS
#define ypget_req_domain yp_reqbody.yp_req_map_parmstype.domain
#define ypget_req_map yp_reqbody.yp_req_map_parmstype.map
#define ypget_req_ordernum yp_reqbody.yp_req_map_parmstype.ordernum
#define ypget_req_owner yp_reqbody.yp_req_map_parmstype.owner

enum ypresptype {YPRESP_VAL = 1, YPRESP_KEY_VAL = 2, YPRESP_MAP_PARMS = 3};
struct ypresponse {
	enum ypresptype yp_resptype;
	union {
		struct ypresp_val yp_resp_valtype;
		struct ypresp_key_val yp_resp_key_valtype;
		struct ypmap_parms yp_resp_map_parmstype;
	} yp_respbody;
};

#define YPMATCH_RESPTYPE YPRESP_VAL
#define ypmatch_resp_status yp_respbody.yp_resp_valtype.status
#define ypmatch_resp_valdat yp_respbody.yp_resp_valtype.valdat
#define ypmatch_resp_valptr yp_respbody.yp_resp_valtype.valdat.dptr
#define ypmatch_resp_valsize yp_respbody.yp_resp_valtype.valdat.dsize

#define YPFIRST_RESPTYPE YPRESP_KEY_VAL
#define ypfirst_resp_status yp_respbody.yp_resp_key_valtype.status
#define ypfirst_resp_keydat yp_respbody.yp_resp_key_valtype.keydat
#define ypfirst_resp_keyptr yp_respbody.yp_resp_key_valtype.keydat.dptr
#define ypfirst_resp_keysize yp_respbody.yp_resp_key_valtype.keydat.dsize
#define ypfirst_resp_valdat yp_respbody.yp_resp_key_valtype.valdat
#define ypfirst_resp_valptr yp_respbody.yp_resp_key_valtype.valdat.dptr
#define ypfirst_resp_valsize yp_respbody.yp_resp_key_valtype.valdat.dsize

#define YPNEXT_RESPTYPE YPRESP_KEY_VAL
#define ypnext_resp_status yp_respbody.yp_resp_key_valtype.status
#define ypnext_resp_keydat yp_respbody.yp_resp_key_valtype.keydat
#define ypnext_resp_keyptr yp_respbody.yp_resp_key_valtype.keydat.dptr
#define ypnext_resp_keysize yp_respbody.yp_resp_key_valtype.keydat.dsize
#define ypnext_resp_valdat yp_respbody.yp_resp_key_valtype.valdat
#define ypnext_resp_valptr yp_respbody.yp_resp_key_valtype.valdat.dptr
#define ypnext_resp_valsize yp_respbody.yp_resp_key_valtype.valdat.dsize

#define YPPOLL_RESPTYPE YPRESP_MAP_PARMS
#define yppoll_resp_domain yp_respbody.yp_resp_map_parmstype.domain
#define yppoll_resp_map yp_respbody.yp_resp_map_parmstype.map
#define yppoll_resp_ordernum yp_respbody.yp_resp_map_parmstype.ordernum
#define yppoll_resp_owner yp_respbody.yp_resp_map_parmstype.owner


extern bool _xdr_yprequest();
extern bool _xdr_ypresponse();

#define YPBINDOLDVERS 		(YPBINDVERS - 1)
struct ypbind_oldsetdom {
	char ypoldsetdom_domain[YPMAXDOMAIN + 1];
	struct ypbind_binding ypoldsetdom_binding;
};
#define ypoldsetdom_addr ypoldsetdom_binding.ypbind_binding_addr
#define ypoldsetdom_port ypoldsetdom_binding.ypbind_binding_port

extern bool _xdr_ypbind_oldsetdom();
