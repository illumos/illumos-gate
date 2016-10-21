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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_TOKTABLE_H
#define	_TOKTABLE_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Solaris Audit Token Table.
 */

typedef struct token_desc {
	char	*t_name;	/* name of the token */
	char	*t_tagname;	/* tag name */
	int	(*func)();	/* token processing function */
	short	t_type;		/* token or tag type */
} token_desc_t;


#define	NOFUNC		(int (*)())0

#define	MAXTOKEN	0xff

extern token_desc_t tokentable[];

/*
 * Tag types -
 *
 *	attribute:	an attribute:
 *			xxx="..."
 *
 *	element:	a simple element:
 *			<xxx> ... </xxx>
 *
 *	enclosed:	a self contained element, optionally with attributes:
 *			<xxx a="" b="" ... />
 *
 *	extended:	an element with attributes:
 *			<xxx a="" b="" ...> ... </xxx>
 */
#define	T_ATTRIBUTE	1	/* attribute */
#define	T_ELEMENT	2	/* element */
#define	T_ENCLOSED	3	/* enclosed element */
#define	T_EXTENDED	4	/* extended element */
#define	T_UNKNOWN	99	/* huh... */

/*
 * Define the kinds of tags
 */
enum tagnum_t { TAG_INVALID = MAXTOKEN,
	TAG_UID,
	TAG_GID,
	TAG_RUID,
	TAG_RGID,
	TAG_AUID,
	TAG_PID,
	TAG_SID,
	TAG_TID32,
	TAG_TID64,
	TAG_TID32_EX,
	TAG_TID64_EX,
	TAG_EVMOD,
	TAG_TOKVERS,
	TAG_EVTYPE,
	TAG_ISO,
	TAG_ERRVAL,
	TAG_RETVAL,
	TAG_SETTYPE,
	TAG_GROUPID,
	TAG_XID,
	TAG_XCUID,
	TAG_XSELTEXT,
	TAG_XSELTYPE,
	TAG_XSELDATA,
	TAG_ARGNUM,
	TAG_ARGVAL32,
	TAG_ARGVAL64,
	TAG_ARGDESC,
	TAG_MODE,
	TAG_FSID,
	TAG_NODEID32,
	TAG_NODEID64,
	TAG_DEVICE32,
	TAG_DEVICE64,
	TAG_SEQNUM,			/* with sequence token */
	TAG_ARGV,			/* with cmd token */
	TAG_ARGE,			/* with cmd token */
	TAG_ARG,			/* with exec_args token */
	TAG_ENV,			/* with exec_env token */
	TAG_XAT,			/* with attr_path token */
	TAG_RESULT,			/* with use_of_privilege token */
	TAG_CUID,			/* with IPC_perm token */
	TAG_CGID,			/* with IPC_perm token */
	TAG_SEQ,			/* with IPC_perm token */
	TAG_KEY,			/* with IPC_perm token */
	TAG_IPVERS,			/* with ip token */
	TAG_IPSERV,			/* with ip token */
	TAG_IPLEN,			/* with ip token */
	TAG_IPID,			/* with ip token */
	TAG_IPOFFS,			/* with ip token */
	TAG_IPTTL,			/* with ip token */
	TAG_IPPROTO,			/* with ip token */
	TAG_IPCKSUM,			/* with ip token */
	TAG_IPSRC,			/* with ip token */
	TAG_IPDEST,			/* with ip token */
	TAG_ACLTYPE,			/* with acl token */
	TAG_ACLVAL,			/* with acl token */
	TAG_SOCKTYPE,			/* with socket token */
	TAG_SOCKPORT,			/* with socket token */
	TAG_SOCKADDR,			/* with socket token */
	TAG_SOCKEXDOM,			/* with socket_ex token */
	TAG_SOCKEXTYPE,			/* with socket_ex token */
	TAG_SOCKEXLPORT,		/* with socket_ex token */
	TAG_SOCKEXLADDR,		/* with socket_ex token */
	TAG_SOCKEXFPORT,		/* with socket_ex token */
	TAG_SOCKEXFADDR,		/* with socket_ex token */
	TAG_IPCTYPE,			/* with IPC token */
	TAG_IPCID,			/* with IPC token */
	TAG_ARBPRINT,			/* with arbitrary (data) token */
	TAG_ARBTYPE,			/* with arbitrary (data) token */
	TAG_ARBCOUNT,			/* with arbitrary (data) token */
	TAG_HOSTID,			/* with extended header token */
	TAG_ZONENAME,			/* with zonename token */
	TAG_TID_TYPE,			/* with tid token */
	TAG_IP,				/* with tid token, type=ip */
	TAG_IP_LOCAL,			/* with tid token, type=ip */
	TAG_IP_REMOTE,			/* with tid token, type=ip */
	TAG_IP_ADR,			/* with tid token, type=ip */
	TAG_ACEMASK,			/* with ace token */
	TAG_ACEFLAGS,			/* with ace token */
	TAG_ACETYPE,			/* with ace token */
	TAG_ACEID,			/* with ace token */
	TAG_USERNAME,			/* with user token */
	MAXTAG
};


/*
 * These tokens are the same for all versions of Solaris
 */

/*
 * Control tokens
 */

extern int	file_token();
extern int	trailer_token();
extern int	header_token();
extern int	header32_ex_token();

/*
 * Data tokens
 */

extern int	arbitrary_data_token();
extern int	fmri_token();
extern int	s5_IPC_token();
extern int	path_token();
extern int	path_attr_token();
extern int	subject32_token();
extern int	process32_token();
extern int	return_value32_token();
extern int	text_token();
extern int	opaque_token();
extern int	ip_addr_token();
extern int	ip_token();
extern int	iport_token();
extern int	argument32_token();
extern int	socket_token();
extern int	sequence_token();

/*
 * Modifier tokens
 */

extern int	acl_token();
extern int	ace_token();
extern int	attribute_token();
extern int	s5_IPC_perm_token();
extern int	group_token();
extern int	label_token();
extern int	privilege_token();
extern int	useofpriv_token();
extern int	liaison_token();
extern int	newgroup_token();
extern int	exec_args_token();
extern int	exec_env_token();
extern int	attribute32_token();
extern int	useofauth_token();
extern int	user_token();
extern int	zonename_token();
extern int	secflags_token();

/*
 * X windows tokens
 */

extern int	xatom_token();
extern int	xselect_token();
extern int	xcolormap_token();
extern int	xcursor_token();
extern int	xfont_token();
extern int	xgc_token();
extern int	xpixmap_token();
extern int	xproperty_token();
extern int	xwindow_token();
extern int	xclient_token();

/*
 * Command tokens
 */

extern int	cmd_token();
extern int	exit_token();

/*
 * Miscellaneous tokens
 */

extern int	host_token();

/*
 * Solaris64 tokens
 */

extern int	argument64_token();
extern int	return_value64_token();
extern int	attribute64_token();
extern int	header64_token();
extern int	subject64_token();
extern int	process64_token();
extern int	file64_token();

/*
 * Extended network address tokens
 */

extern int	header64_ex_token();
extern int	subject32_ex_token();
extern int	process32_ex_token();
extern int	subject64_ex_token();
extern int	process64_ex_token();
extern int	ip_addr_ex_token();
extern int	socket_ex_token();
extern int	tid_token();

#ifdef __cplusplus
}
#endif

#endif	/* _TOKTABLE_H */
