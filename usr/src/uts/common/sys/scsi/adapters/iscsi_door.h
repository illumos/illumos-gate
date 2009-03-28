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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_ISCSI_DOOR_H
#define	_ISCSI_DOOR_H

#ifdef __cplusplus
extern "C" {
#endif

#define	ISCSI_DOOR_REQ_SIGNATURE	0x53435349
#define	ISCSI_DOOR_REQ_VERSION_1	1
#define	ISCSI_DOOR_MAX_DATA_SIZE	8192


#define	ISCSI_DOOR_GETIPNODEBYNAME_REQ	0x0000
#define	ISCSI_DOOR_GETIPNODEBYNAME_CNF	0x4000
#define	ISCSI_DOOR_ERROR_IND		0x8000

#define	ISCSI_DOOR_STATUS_SUCCESS	0x00000000
#define	ISCSI_DOOR_STATUS_REQ_LENGTH	0x00000001
#define	ISCSI_DOOR_STATUS_REQ_FORMAT	0x00000002
#define	ISCSI_DOOR_STATUS_REQ_INVALID	0x00000003
#define	ISCSI_DOOR_STATUS_REQ_VERSION	0x00000004
#define	ISCSI_DOOR_STATUS_MORE		0x00000005

typedef struct _iscsi_door_msg_hdr {
	uint32_t		signature;
	uint32_t		version;
	uint32_t		opcode;
	uint32_t		status;
} iscsi_door_msg_hdr_t;

typedef struct _getipnodebyname_req {
	iscsi_door_msg_hdr_t	hdr;
	uint32_t		name_offset;
	uint32_t		name_length;
	uint32_t		af;
	uint32_t		flags;
} getipnodebyname_req_t;

typedef struct _getipnodebyname_cnf {
	iscsi_door_msg_hdr_t	hdr;
	uint32_t		h_size_needed;
	uint32_t		h_addr_list_offset;
	uint32_t		h_addr_list_length;
	uint32_t		h_addrtype;
	uint32_t		h_addrlen;
	uint32_t		h_name_offset;
	uint32_t		h_name_len;
	uint32_t		h_alias_list_offset;
	uint32_t		h_alias_list_length;
	int32_t			error_num;
} getipnodebyname_cnf_t;

typedef union _iscsi_door_req {
	iscsi_door_msg_hdr_t	hdr;
	getipnodebyname_req_t	ginbn_req;
} iscsi_door_req_t;

typedef union _iscsi_door_cnf {
	iscsi_door_msg_hdr_t	hdr;
	getipnodebyname_cnf_t	ginbn_cnf;
} iscsi_door_cnf_t;

typedef union _iscsi_door_ind {
	iscsi_door_msg_hdr_t	hdr;
	iscsi_door_msg_hdr_t	error_ind;
} iscsi_door_ind_t;

typedef union _iscsi_door_msg {
	iscsi_door_msg_hdr_t	hdr;
	iscsi_door_req_t	req;
	iscsi_door_cnf_t	cnf;
	iscsi_door_ind_t	ind;
} iscsi_door_msg_t;

#ifdef _KERNEL

/* Defines copied from netdb.h */
#define	HOST_NOT_FOUND	1 /* Authoritive Answer Host not found */
#define	TRY_AGAIN	2 /* Non-Authoritive Host not found, or SERVERFAIL */
#define	NO_RECOVERY	3 /* Non recoverable errors,FORMERR,REFUSED,NOTIMP */
#define	NO_DATA		4 /* Valid name, no data record of requested type */
#define	NO_ADDRESS	NO_DATA	/* no address, look for MX record */

#define	AI_V4MAPPED	0x0001 /* IPv4 mapped addresses if no IPv6 */
#define	AI_ALL		0x0002 /* IPv6 and IPv4 mapped addresses */
#define	AI_ADDRCONFIG	0x0004 /* AAAA or A records only if IPv6/IPv4 cnfgd */

struct  hostent {
	char	*h_name;	/* official name of host */
	char	**h_aliases;	/* alias list */
	int	h_addrtype;	/* host address type */
	int	h_length;	/* length of address */
	char	**h_addr_list;	/* list of addresses from name server */
};

boolean_t
iscsi_door_ini(void);

boolean_t
iscsi_door_term(void);

boolean_t
iscsi_door_bind(
	int		did
);

void
iscsi_door_unbind(void);

void
kfreehostent(
	struct hostent	*hptr
);

struct hostent *
kgetipnodebyname(
	const char	*name,
	int		af,
	int		flags,
	int		*error_num
);

#else	/* !_KERNEL */

#define	kfreehostent		freehostent
#define	kgetipnodebyname	getipnodebyname

#endif	/* _KERNEL */

/*
 * iSCSI initiator SMF service status in kernel
 */
#define	ISCSI_SERVICE_ENABLED		0x0
#define	ISCSI_SERVICE_DISABLED		0x1
#define	ISCSI_SERVICE_TRANSITION	0x2

#ifdef __cplusplus
}
#endif

#endif /* _ISCSI_DOOR_H */
