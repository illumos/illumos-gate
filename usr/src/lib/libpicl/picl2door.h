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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_PICL2DOOR_H
#define	_PICL2DOOR_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#define	PICLD_DOOR_VERSION	1
#define	PICLD_DOOR	"/var/run/picld_door"
#define	PICLD_DOOR_COOKIE	((void *)(0xdeaffeed ^ PICLD_DOOR_VERSION))

/*
 * PICL service calls
 */
typedef enum {
	PICL_CNUM_INIT = 0x1,		/* initialize */
	PICL_CNUM_FINI,			/* fini */
	PICL_CNUM_GETROOT,		/* get root node */
	PICL_CNUM_GETATTRVAL, 		/* get attr val */
	PICL_CNUM_GETATTRVALBYNAME,	/* get attr val by name */
	PICL_CNUM_GETATTRINFO,		/* get attribute information */
	PICL_CNUM_GETFIRSTATTR, 	/* get first attribute */
	PICL_CNUM_GETNEXTATTR, 		/* get next attribute */
	PICL_CNUM_GETATTRBYNAME,	/* get attr by name */
	PICL_CNUM_GETATTRBYROW,		/* get attr by row */
	PICL_CNUM_GETATTRBYCOL,		/* get attr by column */
	PICL_CNUM_SETATTRVAL, 		/* set attribute's value */
	PICL_CNUM_SETATTRVALBYNAME,	/* set attr val by name */
	PICL_CNUM_PING,			/* ping daemon */
	PICL_CNUM_WAIT,			/* wait n seconds for refresh */
	PICL_CNUM_ERROR,		/* error response */
	PICL_CNUM_FINDNODE,		/* find node */
	PICL_CNUM_NODEBYPATH,		/* get node by path */
	PICL_CNUM_FRUTREEPARENT		/* get frutree parent */
} picl_callnumber_t;

typedef	union {
		picl_nodehdl_t	nodeh;
		picl_prophdl_t	proph;
		char		str[1];
} propval_t;
#define	ret_buf		u.str
#define	ret_nodeh	u.nodeh
#define	ret_proph	u.proph

/*
 * Generic picl service request argument
 */
typedef struct {
	picl_callnumber_t	cnum;	/* service call number */
	char			buf[4];	/* buffer containing input arguments */
} picl_req_t;

typedef struct {
	picl_callnumber_t	cnum;	/* service call number */
	char			buf[4];	/* buffer containing the results */
} picl_ret_t;

	/*
	 * PICL initialize
	 */
typedef struct {
	picl_callnumber_t	cnum;	/* PICL_CNUM_INIT */
	unsigned int		clrev;	/* client's ID and revision number */
} picl_reqinit_t;

typedef struct {
	picl_callnumber_t	cnum;	/* PICL_CNUM_INIT */
	int			rev;	/* PICL daemon's revision number */
} picl_retinit_t;


	/*
	 * PICL shutdown
	 */
typedef struct {
	picl_callnumber_t	cnum;		/* PICL_CNUM_FINI */
} picl_reqfini_t;

typedef struct {
	picl_callnumber_t	cnum;		/* PICL_CNUM_FINI */
} picl_retfini_t;

	/*
	 * PICL get root
	 */
typedef struct {
	picl_callnumber_t	cnum;		/* PICL_CNUM_GETROOT */
} picl_reqroot_t;

typedef struct {
	picl_callnumber_t	cnum;		/* PICL_CNUM_GETROOT */
	picl_nodehdl_t		rnode;		/* root handle */
} picl_retroot_t;

	/*
	 * PICL get attr val
	 */
typedef struct {
	picl_callnumber_t	cnum;		/* PICL_CNUM_GETATTRVAL */
	picl_prophdl_t		attr;		/* attribute handle */
	uint32_t		bufsize;	/* value buffer size */
} picl_reqattrval_t;

typedef struct {
	picl_callnumber_t	cnum;		/* PICL_CNUM_GETATTRVAL */
	picl_prophdl_t		attr;		/* attribute handle */
	uint32_t		nbytes;		/* return value size */
	propval_t 		u;
} picl_retattrval_t;

	/*
	 * PICL get attr val by name
	 */
typedef struct {
	picl_callnumber_t	cnum;		/* PICL_CNUM_GETATTRVALBYNAME */
	picl_nodehdl_t		nodeh;		/* node handle */
						/* attribute name */
	char			propname[PICL_PROPNAMELEN_MAX];
	uint32_t		bufsize;	/* buffer size */
} picl_reqattrvalbyname_t;

typedef struct {
	picl_callnumber_t	cnum;		/* PICL_CNUM_GETATTRVALBYNAME */
	picl_nodehdl_t		nodeh;		/* node handle */
						/* attribute name */
	char			propname[PICL_PROPNAMELEN_MAX];
	uint32_t		nbytes;		/* return value size */
	propval_t		u;		/* return value */
} picl_retattrvalbyname_t;

	/*
	 * PICL get attr info
	 */
typedef struct {
	picl_callnumber_t	cnum;		/* PICL_CNUM_GETATTRINFO */
	picl_prophdl_t		attr;		/* attribute handle */
} picl_reqattrinfo_t;

typedef struct {
	picl_callnumber_t	cnum;		/* PICL_CNUM_GETATTRINFO */
	picl_prophdl_t		attr;		/* attribute handle */
	picl_prop_type_t	type;		/* attribute type */
	unsigned int		accessmode;	/* access mode */
	uint32_t		size;		/* value size */
						/* attr name */
	char			name[PICL_PROPNAMELEN_MAX];
} picl_retattrinfo_t;

	/*
	 * PICL get first attr
	 */
typedef struct {
	picl_callnumber_t	cnum;		/* PICL_CNUM_GETFIRSTATTR */
	picl_nodehdl_t		nodeh;		/* node handle */
} picl_reqfirstattr_t;

typedef struct {
	picl_callnumber_t	cnum;		/* PICL_CNUM_GETFIRSTATTR */
	picl_nodehdl_t		nodeh;		/* node handle */
	picl_prophdl_t		attr;		/* first attribute handle */
} picl_retfirstattr_t;

	/*
	 * PICL get next attr
	 */
typedef struct {
	picl_callnumber_t	cnum;		/* PICL_CNUM_GETNEXTATTR */
	picl_prophdl_t		attr;		/* attribute handle */
} picl_reqnextattr_t;

typedef struct {
	picl_callnumber_t	cnum;		/* PICL_CNUM_GETNEXTATTR */
	picl_prophdl_t		attr;		/* attribute handle */
	picl_prophdl_t		nextattr;	/* next attribute handle */
} picl_retnextattr_t;

	/*
	 * PICL get attr by name
	 */
typedef struct {
	picl_callnumber_t	cnum;		/* PICL_CNUM_GETATTRBYNAME */
	picl_nodehdl_t		nodeh;		/* node handle */
						/* attr name */
	char			propname[PICL_PROPNAMELEN_MAX];
} picl_reqattrbyname_t;

typedef struct {
	picl_callnumber_t	cnum;		/* PICL_CNUM_GETATTRBYNAME */
	picl_nodehdl_t		nodeh;		/* node handle */
						/* attr name */
	char			propname[PICL_PROPNAMELEN_MAX];
	picl_prophdl_t		attr;		/* attr handle */
} picl_retattrbyname_t;

	/*
	 * PICL get attr by row
	 */
typedef struct {
	picl_callnumber_t	cnum;		/* PICL_CNUM_GETATTRBYROW */
	picl_prophdl_t		attr;		/* attr handle */
} picl_reqattrbyrow_t;

typedef struct {
	picl_callnumber_t	cnum;		/* PICL_CNUM_GETATTRBYROW */
	picl_prophdl_t		attr;		/* attr handle */
	picl_prophdl_t		rowattr;	/* attr by row handle */
} picl_retattrbyrow_t;

	/*
	 * PICL get attr by column
	 */
typedef struct {
	picl_callnumber_t	cnum;		/* PICL_CNUM_GETATTRBYCOL */
	picl_prophdl_t		attr;		/* attr handle */
} picl_reqattrbycol_t;

typedef struct {
	picl_callnumber_t	cnum;		/* PICL_CNUM_GETATTRBYCOL */
	picl_prophdl_t		attr;		/* attr handle */
	picl_prophdl_t		colattr;	/* attr by col handle */
} picl_retattrbycol_t;

	/*
	 * PICL set attr val
	 */
typedef struct {
	picl_callnumber_t	cnum;		/* PICL_CNUM_SETATTRVAL */
	picl_prophdl_t		attr;		/* attribute handle */
	uint32_t		bufsize;	/* value buffer size */
	char			valbuf[1];
} picl_reqsetattrval_t;

typedef struct {
	picl_callnumber_t	cnum;		/* PICL_CNUM_SETATTRVAL */
	picl_prophdl_t		attr;		/* attribute handle */
} picl_retsetattrval_t;

	/*
	 * PICL set attr val by name
	 */
typedef struct {
	picl_callnumber_t	cnum;		/* PICL_CNUM_SETATTRVALBYNAME */
	picl_nodehdl_t		nodeh;		/* node handle */
						/* attr name */
	char			propname[PICL_PROPNAMELEN_MAX];
	uint32_t		bufsize;	/* buffer size */
	char			valbuf[1];
} picl_reqsetattrvalbyname_t;

typedef struct {
	picl_callnumber_t	cnum;		/* PICL_CNUM_SETATTRVALBYNAME */
	picl_nodehdl_t		nodeh;		/* node handle */
						/* attr name */
	char			propname[PICL_PROPNAMELEN_MAX];
} picl_retsetattrvalbyname_t;

	/*
	 * PICL ping
	 */
typedef struct {
	picl_callnumber_t	cnum;		/* PICL_CNUM_PING */
} picl_reqping_t;

typedef struct {
	picl_callnumber_t	cnum;		/* PICL_CNUM_PING */
} picl_retping_t;

	/*
	 * PICL wait
	 */
typedef struct {
	picl_callnumber_t	cnum;		/* PICL_CNUM_WAIT */
	unsigned int		secs;		/* number of seconds */
} picl_reqwait_t;

typedef struct {
	picl_callnumber_t	cnum;		/* PICL_CNUM_WAIT service */
	unsigned int		secs;		/* input seconds */
	int			retcode;	/* return code */
} picl_retwait_t;

	/*
	 * PICL find node
	 */
typedef struct {
	picl_callnumber_t	cnum;		/* PICL_CNUM_FINDNODE */
	picl_nodehdl_t		nodeh;		/* top node handle */
						/* property name */
	char			propname[PICL_PROPNAMELEN_MAX];
	picl_prop_type_t	ptype;		/* property type */
	uint32_t		valsize;	/* size of prop value */
	char			valbuf[1];	/* prop value */
} picl_reqfindnode_t;

typedef struct {
	picl_callnumber_t	cnum;		/* PICL_CNUM_FINDNODE */
	picl_nodehdl_t		rnodeh;		/* matched node */
} picl_retfindnode_t;

	/*
	 * PICL get node by path
	 */
typedef struct {
	picl_callnumber_t	cnum;		/* PICL_CNUM_NODEBYPATH */
	uint32_t		psize;		/* size of path */
	char			pathbuf[PATH_MAX];	/* picl path */
} picl_reqnodebypath_t;

typedef struct {
	picl_callnumber_t	cnum;		/* PICL_CNUM_NODEBYPATH */
	picl_nodehdl_t		nodeh;		/* node handle */
} picl_retnodebypath_t;

	/*
	 * PICL get frutree parent
	 */
typedef struct {
	picl_callnumber_t	cnum;		/* PICL_CNUM_FRUTREEPARENT */
	picl_nodehdl_t		devh;		/* dev node handle */
} picl_reqfruparent_t;

typedef struct {
	picl_callnumber_t	cnum;		/* PICL_CNUM_FRUTREEPARENT */
	picl_nodehdl_t		fruh;		/* fru parent handle */
} picl_retfruparent_t;

	/*
	 * PICL error return
	 */
typedef struct {
	picl_callnumber_t	cnum;		/* PICL_CNUM_ERROR */
	picl_callnumber_t	in_cnum;	/* requested service number */
	picl_errno_t		errnum;		/* return error code */
} picl_reterror_t;

typedef union {
	picl_req_t		in;			/* req arguments */
	picl_ret_t		out;			/* out results */

	picl_reqinit_t		req_init;		/* req initialize */
	picl_retinit_t		ret_init;		/* ret initialize */

	picl_reqfini_t		req_fini;		/* req fini */
	picl_retfini_t		ret_fini;		/* ret fini */

	picl_reqroot_t		req_root;		/* req root node */
	picl_retroot_t		ret_root;		/* ret root node */

	picl_reqattrval_t	req_attrval;		/* req attr value */
	picl_retattrval_t	ret_attrval;		/* ret attr value */

						/* req attr val by name */
	picl_reqattrvalbyname_t	req_attrvalbyname;
						/* ret attr val by name */
	picl_retattrvalbyname_t	ret_attrvalbyname;

	picl_reqattrinfo_t    	req_attrinfo;		/* req attr info */
	picl_retattrinfo_t    	ret_attrinfo;		/* ret attr info */

	picl_reqfirstattr_t	req_firstattr;		/* req first attr */
	picl_retfirstattr_t	ret_firstattr;		/* ret first attr */

	picl_reqnextattr_t	req_nextattr;		/* req next attr */
	picl_retnextattr_t	ret_nextattr;		/* ret next attr */

	picl_reqattrbyname_t	req_attrbyname;		/* req attr by name */
	picl_retattrbyname_t	ret_attrbyname;		/* ret attr by name */

	picl_reqattrbyrow_t	req_attrbyrow;		/* req attr by row */
	picl_retattrbyrow_t	ret_attrbyrow;		/* ret attr by row */

	picl_reqattrbycol_t	req_attrbycol;		/* req attr by col */
	picl_retattrbycol_t	ret_attrbycol;		/* ret attr by col */

						/* set attribute value */
	picl_reqsetattrval_t	req_setattrval;
						/* ret set attribute value */
	picl_retsetattrval_t	ret_setattrval;

						/* set attr val by name */
	picl_reqsetattrvalbyname_t	req_setattrvalbyname;
						/* set attr val by name */
	picl_retsetattrvalbyname_t	ret_setattrvalbyname;

	picl_reqping_t		req_ping;		/* req ping */
	picl_retping_t		ret_ping;		/* ret ping */

	picl_reqwait_t		req_wait;		/* req wait */
	picl_retwait_t		ret_wait;		/* ret wait */

	picl_reqfindnode_t	req_findnode;	/* req find node */
	picl_retfindnode_t	ret_findnode;	/* ret find node */

	picl_reqnodebypath_t	req_nodebypath;	/* get node by path */
	picl_retnodebypath_t	ret_nodebypath;	/* ret node by path */

	picl_reqfruparent_t	req_fruparent;	/* get frutree parent */
	picl_retfruparent_t	ret_fruparent;	/* ret frutree parent */

	picl_reterror_t		ret_error;		/* return error */
} picl_service_t;

#ifdef	__cplusplus
}
#endif

#endif	/* _PICL2DOOR_H */
