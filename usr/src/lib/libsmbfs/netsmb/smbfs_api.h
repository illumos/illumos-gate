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
 * Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
 */

#ifndef _NETSMB_SMBFS_API_H
#define	_NETSMB_SMBFS_API_H

/*
 * Define the API exported to our commands and to
 * libraries doing DCE-RPC over SMB named pipes.
 */

#include <sys/types.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Some errno values we need to expose in this API.
 * NB: These two defines are duplicated from the
 * driver smb_dev.h to avoid exposing that here.
 *
 * EBADRPC is used for message decoding errors.
 * EAUTH is used for CIFS authentication errors.
 */
#ifndef EBADRPC
#define	EBADRPC 	113
#endif
#ifndef EAUTH
#define	EAUTH		114
#endif


/*
 * Share type values for smb_ctx_new, _init
 * Based on NetUseAdd() USE_INFO_[12] _asg_type values
 * They also happen to match: STYPE_DISKTREE, etc.
 * Note: these values appear on the wire.
 */
typedef enum {
	USE_DISKDEV = 0,	/* also STYPE_DISKTREE */
	USE_SPOOLDEV,		/* also STYPE_PRINTQ */
	USE_CHARDEV,		/* also STYPE_DEVICE */
	USE_IPC,		/* also STYPE_IPC */
	USE_WILDCARD		/* also STYPE_UNKNOWN */
} smb_use_shtype_t;

/*
 * Parse "level" spec. for smb_ctx_parseunc()
 * i.e. whether we require a share name, etc.
 */
typedef enum {
	SMBL_NONE = 0,	/* have nothing */
	SMBL_SERVER,	/* have server */
	SMBL_VC = 1,	/* alias for _SERVER */
	SMBL_SHARE,	/* have server share */
	SMBL_PATH	/* have server share path */
} smb_parse_level_t;

/*
 * Authentication type flags
 * See: smb_ctx_setauthflags()
 */
#define	SMB_AT_ANON	1	/* anonymous (NULL session) */
#define	SMB_AT_LM1	2	/* LM1 (with NTLM) */
#define	SMB_AT_NTLM1	4	/* NTLM (v1) */
#define	SMB_AT_NTLM2	8	/* NTLMv2 */
#define	SMB_AT_KRB5	0x10	/* Kerberos5 (AD) */

struct smb_ctx;	/* anonymous here; real one in smb_lib.h */
typedef struct smb_ctx smb_ctx_t;

extern int smb_debug, smb_verbose;

int  smb_lib_init(void);
void smb_error(const char *, int, ...);

/*
 * Context management
 */
int  smb_ctx_alloc(struct smb_ctx **);
void smb_ctx_free(struct smb_ctx *);
int  smb_ctx_kill(struct smb_ctx *);

int  smb_ctx_scan_argv(struct smb_ctx *, int, char **, int, int, int);
int  smb_ctx_parseunc(struct smb_ctx *, const char *, int, int, int,
	const char **);
int  smb_ctx_readrc(struct smb_ctx *);
int  smb_ctx_opt(struct smb_ctx *, int, const char *);
int  smb_get_authentication(struct smb_ctx *);

int  smb_ctx_flags2(struct smb_ctx *);
int  smb_ctx_resolve(struct smb_ctx *);
int  smb_ctx_get_ssn(struct smb_ctx *);
int  smb_ctx_get_tree(struct smb_ctx *);

int  smb_ctx_setauthflags(struct smb_ctx *, int);
int  smb_ctx_setcharset(struct smb_ctx *, const char *);
int  smb_ctx_setfullserver(struct smb_ctx *, const char *);
int  smb_ctx_setsigning(struct smb_ctx *, int ena, int req);

int  smb_ctx_setnbflags(struct smb_ctx *, int ena, int bcast);
int  smb_ctx_setscope(struct smb_ctx *, const char *);
int  smb_ctx_setwins(struct smb_ctx *, const char *, const char *);

int  smb_ctx_setsrvaddr(struct smb_ctx *, const char *);
int  smb_ctx_setserver(struct smb_ctx *, const char *);
int  smb_ctx_setshare(struct smb_ctx *, const char *, int);

int  smb_ctx_setdomain(struct smb_ctx *, const char *, int);
int  smb_ctx_setuser(struct smb_ctx *, const char *, int);
int  smb_ctx_setpassword(struct smb_ctx *, const char *, int);
int  smb_ctx_setpwhash(struct smb_ctx *, const uchar_t *, const uchar_t *);

typedef void (*smb_ctx_close_hook_t)(struct smb_ctx *);
void smb_ctx_set_close_hook(smb_ctx_close_hook_t);
int  smb_fh_close(int);
int  smb_fh_open(struct smb_ctx *ctx, const char *, int);
int  smb_fh_read(int, off_t, size_t, char *);
int  smb_fh_write(int, off_t, size_t, const char *);
int  smb_fh_xactnp(int, int, const char *,
	int *, char *, int *);
int  smb_fh_getssnkey(int, uchar_t *, size_t);

int  smb_open_printer(struct smb_ctx *, const char *, int, int);

void smbfs_set_default_domain(const char *);
void smbfs_set_default_user(const char *);

char *smb_strerror(int);

#ifdef	__cplusplus
}
#endif

#endif /* _NETSMB_SMBFS_API_H */
