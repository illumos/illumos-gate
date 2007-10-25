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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SMBSRV_SMB_DOOR_SVC_H
#define	_SMBSRV_SMB_DOOR_SVC_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <smbsrv/smb_token.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * SMB door service (user-space and kernel-space)
 */
#define	SMB_DR_SVC_NAME		"/var/run/smbd_door"
#define	SMB_DR_SVC_VERSION	1
#define	SMB_DR_SVC_COOKIE	((void*)(0xdeadbeef^SMB_DR_SVC_VERSION))

/*
 * Door argument buffer starts off by the four-byte opcode.
 * Door result buffer starts off by the four-byte status.
 * The real data starts at offset 4 of the door buffer.
 */
#define	SMB_DR_DATA_OFFSET	4

/*
 * A smb_dr_op_t exists for each user-space door operation.
 * A smb_kdr_op_t exists for each kernel-space door operation.
 *
 * The first argument to smb_dr_op_t/smb_kdr_op_t is a pointer to the
 * door argument buffer. The second argument indicates the size of
 * the door argument buffer.
 *
 * The user-space door server accepts file descriptors from clients.
 * Thus, door_desc_t and n_desc can be passed to any smb_dr_op_t operation.
 *
 * Returns door result buffer and its size 'rbufsize' upon success.
 * Otherwise, NULL pointer will be returned and appropriate error code
 * will be set.
 */
typedef char *(*smb_dr_op_t)(char *argp, size_t arg_size, door_desc_t *dp,
    uint_t n_desc, size_t *rbufsize, int *err);
typedef char *(*smb_kdr_op_t)(char *argp, size_t arg_size, size_t *rbufsize,
    int *errno);

extern smb_dr_op_t smb_doorsrv_optab[];

/*
 * Door Opcode
 * -------------
 * smb_dr_opcode_t - opcodes for user-space door operations.
 * smb_kdr_opcode_t - opcodes for kernel-space door operations.
 */
enum smb_dr_opcode_t {
	SMB_DR_USER_AUTH_LOGON,
	SMB_DR_SET_DWNCALL_DESC,
	SMB_DR_USER_NONAUTH_LOGON,
	SMB_DR_USER_AUTH_LOGOFF,
	SMB_DR_USER_LIST,
	SMB_DR_GROUP_ADD,
	SMB_DR_GROUP_DELETE,
	SMB_DR_GROUP_MEMBER_ADD,
	SMB_DR_GROUP_MEMBER_REMOVE,
	SMB_DR_GROUP_COUNT,
	SMB_DR_GROUP_CACHE_SIZE,
	SMB_DR_GROUP_MODIFY,
	SMB_DR_GROUP_PRIV_NUM,
	SMB_DR_GROUP_PRIV_LIST,
	SMB_DR_GROUP_PRIV_GET,
	SMB_DR_GROUP_PRIV_SET,
	SMB_DR_GROUP_LIST,
	SMB_DR_GROUP_MEMBER_LIST,
	SMB_DR_GROUP_MEMBER_COUNT
};

enum smb_kdr_opcode_t {
	SMB_KDR_USER_NUM,
	SMB_KDR_USER_LIST,
	SMB_KDR_SHARE
};

/*
 * Door result status
 * SMB door servers will pass the following result status along with the
 * requested data back to the clients.
 */
#define	SMB_DR_OP_SUCCESS		0
#define	SMB_DR_OP_ERR			1
#define	SMB_DR_OP_ERR_DECODE		2
#define	SMB_DR_OP_ERR_ENCODE		3
#define	SMB_DR_OP_ERR_EMPTYBUF		4
#define	SMB_DR_OP_ERR_INVALID_OPCODE	5

#ifdef _KERNEL
/*
 * The 2nd argument of the smb_kdoor_srv_callback will be of the
 * following data structure type.
 *
 * rbuf - The pointer to a dynamically allocated door result buffer that
 *	  is required to be freed after the kernel completes the copyout
 *	  operation.
 */
typedef struct smb_kdoor_cb_arg {
	char *rbuf;
	size_t rbuf_size;
} smb_kdoor_cb_arg_t;

/*
 * SMB kernel door server
 * ------------------------
 * NOTE: smb_kdoor_srv_init()/smb_kdoor_srv_fini() are noops.
 */
extern int smb_kdoor_srv_start();
extern void smb_kdoor_srv_stop();
extern int smb_kdr_is_valid_opcode(int opcode);

extern char *smb_kdr_op_user_num(char *argp, size_t arg_size,
    size_t *rbufsize, int *errno);
extern char *smb_kdr_op_users(char *argp, size_t arg_size,
    size_t *rbufsize, int *errno);
extern char *smb_kdr_op_share(char *argp, size_t arg_size,
    size_t *rbufsize, int *errno);

/*
 * SMB kernel door client
 * ------------------------
 * NOTE: smb_kdoor_clnt_init()/smb_kdoor_clnt_fini() are noops.
 */
extern int smb_kdoor_clnt_start();
extern void smb_kdoor_clnt_stop();
extern void smb_kdoor_clnt_free();
extern char *smb_kdoor_clnt_upcall(char *argp, size_t arg_size, door_desc_t *dp,
    uint_t desc_num, size_t *rbufsize);

/*
 * SMB upcalls
 */
extern smb_token_t *smb_upcall_get_token(netr_client_t *clnt_info);
extern int smb_upcall_set_dwncall_desc(uint32_t opcode, door_desc_t *dp,
    uint_t n_desc);
extern void smb_user_nonauth_logon(uint32_t);
extern void smb_user_auth_logoff(uint32_t);
#else /* _KERNEL */

/*
 * SMB user-space door server
 */
extern int smb_door_srv_start();
extern void smb_door_srv_stop(void);

/* downcall descriptor */
typedef int (*smb_dwncall_get_desc_t)();
extern int smb_dwncall_install_callback(smb_dwncall_get_desc_t get_desc_cb);

extern int smb_dr_is_valid_opcode(int opcode);

/*
 * SMB user-space door client
 */
extern int smb_dr_clnt_open(int *fd, char *path, char *op_desc);
extern char *smb_dr_clnt_call(int fd, char *argp, size_t arg_size,
    size_t *rbufsize, char *op_desc);
extern void smb_dr_clnt_free(char *argp, size_t arg_size, char *rbufp,
    size_t rbuf_size);
/*
 * SMB downcalls
 */
extern int smb_dwncall_get_users(int offset, smb_dr_ulist_t *users);
extern int smb_dwncall_share(int op, char *path, char *sharename);

#endif /* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SMBSRV_SMB_DOOR_SVC_H */
