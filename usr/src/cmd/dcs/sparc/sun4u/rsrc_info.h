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

#ifndef	_RSRC_INFO_H
#define	_RSRC_INFO_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <libnvpair.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Request flags
 */
#define	RI_INCLUDE_QUERY	0x01
#define	RI_INCLUDE_UNMANAGED	0x02
#define	RI_FORCE		0x04
#define	RI_VERBOSE		0x08

/*
 * Error codes
 */
#define	RI_SUCCESS		0	/* No error */
#define	RI_FAILURE		1	/* Internal error */
#define	RI_INVAL		2	/* Invalid argument */
#define	RI_NOTSUP		3	/* Unsupported request */

/*
 * Attachment point properties
 *
 * 	Name	- RI_AP_REQ_ID
 * 	Value	- DATA_TYPE_STRING
 */
#define	RI_AP_REQ_ID	"ri.ap_req_id"

/*
 * CPU properties
 *
 * 	Name	- RI_CPU_ID
 * 	Value	- DATA_TYPE_INT32
 * 	Name	- RI_CPU_STATE
 * 	Value	- DATA_TYPE_STRING
 * 	Name	- RI_CPU_SPEED
 * 	Value	- DATA_TYPE_INT32
 * 	Name	- RI_CPU_ECACHE
 * 	Value 	_ DATA_TYPE_INT32
 */
#define	RI_CPU_ID	"ri.cpu_id"
#define	RI_CPU_STATE	"ri.cpu_state"
#define	RI_CPU_SPEED	"ri.cpu_speed"
#define	RI_CPU_ECACHE	"ri.cpu_ecache"

/*
 * Memory properties
 *
 * 	Name	- RI_MEM_BRD
 * 	Value	- DATA_TYPE_INT32
 * 	Name	- RI_MEM_PERM
 * 	Value	- DATA_TYPE_INT32
 * 	Name	- RI_MEM_ADDR
 * 	Value 	- DATA_TYPE_INT32
 * 	Name	- RI_MEM_DOMAIN
 * 	Value 	- DATA_TYPE_INT32
 * 	Name	- RI_MEM_TARG
 * 	Value	- DATA_TYPE_STRING
 * 	Name	- RI_MEM_SRC
 * 	Value	- DATA_TYPE_STRING
 * 	Name	- RI_MEM_DEL
 * 	Value	- DATA_TYPE_INT32
 * 	Name	- RI_MEM_REMAIN
 * 	Value	- DATA_TYPE_INT32
 */
#define	RI_MEM_BRD	"ri.mem_brd"
#define	RI_MEM_PERM	"ri.mem_perm"
#define	RI_MEM_ADDR	"ri.mem_addr"
#define	RI_MEM_DOMAIN	"ri.mem_domain"
#define	RI_MEM_TARG	"ri.mem_targ"
#define	RI_MEM_SRC	"ri.mem_src"
#define	RI_MEM_DEL	"ri.mem_del"
#define	RI_MEM_REMAIN	"ri.mem_rem"

/*
 * IO device properties
 *
 * 	Name	- RI_IO_DRV_INST
 * 	Value 	- DATA_TYPE_STRING
 */
#define	RI_IO_DRV_INST	"ri.io_drv_inst"

/*
 * RCM client usage properties
 *
 * 	Name	- RI_CLIENT_RSRC
 * 	Value	- DATA_TYPE_STRING
 * 	Name	- RI_CLIENT_USAGE
 * 	Value	- DATA_TYPE_STRING
 * 	Name	- RI_QUERY_STATE
 * 	Value	- DATA_TYPE_INT32
 * 	Name	- RI_QUERY_ERR
 * 	Value	- DATA_TYPE_STRING
 */
#define	RI_CLIENT_RSRC	"ri.client_rsrc"
#define	RI_CLIENT_USAGE	"ri.client_usage"
#define	RI_QUERY_STATE	"ri.query_state"
#define	RI_QUERY_ERR	"ri.query_err"

/*
 * Query states
 */
#define	RI_QUERY_UNKNOWN	-1
#define	RI_QUERY_OK		0
#define	RI_QUERY_FAIL		1

typedef	struct ri_hdl ri_hdl_t;
typedef struct ri_ap ri_ap_t;
typedef struct ri_dev ri_dev_t;
typedef struct ri_client ri_client_t;

#ifdef SMSLIB_TARGET
int		ri_init(uint_t, int, char **, int, ri_hdl_t **);
#else
int		ri_init(int, char **, int, ri_hdl_t **);
#endif /* SMSLIB_TARGET */
int		ri_pack(ri_hdl_t *, caddr_t *, size_t *, int encoding);
int		ri_unpack(caddr_t, size_t, ri_hdl_t **);
void		ri_fini(ri_hdl_t *);
ri_ap_t		*ri_ap_next(ri_hdl_t *, ri_ap_t *);
nvlist_t	*ri_ap_conf_props(ri_ap_t *);
ri_dev_t	*ri_cpu_next(ri_ap_t *, ri_dev_t *);
ri_dev_t	*ri_mem_next(ri_ap_t *, ri_dev_t *);
ri_dev_t	*ri_io_next(ri_ap_t *, ri_dev_t *);
nvlist_t	*ri_dev_conf_props(ri_dev_t *);
ri_client_t	*ri_client_next(ri_dev_t *, ri_client_t *);
nvlist_t	*ri_client_usage_props(ri_client_t *);
nvlist_t	*ri_client_verbose_props(ri_client_t *);
ri_client_t	*ri_cpu_cap_client_next(ri_hdl_t *, ri_client_t *);
ri_client_t	*ri_mem_cap_client_next(ri_hdl_t *, ri_client_t *);

#ifdef	__cplusplus
}
#endif

#endif	/* _RSRC_INFO_H */
