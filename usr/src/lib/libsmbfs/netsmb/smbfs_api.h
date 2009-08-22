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

#ifndef _NETSMB_SMBFS_API_H
#define	_NETSMB_SMBFS_API_H

/*
 * Define the API exported to our commands and to the
 * MS-style RPC-over-named-pipes library (mlrpc).
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
 */
typedef enum {
	USE_WILDCARD = -1,
	USE_DISKDEV,
	USE_SPOOLDEV,
	USE_CHARDEV,
	USE_IPC
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
#define	SMB_AT_DEFAULT	(SMB_AT_KRB5 | SMB_AT_NTLM2 | SMB_AT_NTLM1)

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
int  smb_ctx_get_ssnkey(struct smb_ctx *, uchar_t *, size_t);
int  smb_ctx_get_tree(struct smb_ctx *);

int  smb_ctx_setauthflags(struct smb_ctx *, int);
int  smb_ctx_setcharset(struct smb_ctx *, const char *);
int  smb_ctx_setflags(struct smb_ctx *, int, int, int);
int  smb_ctx_setfullserver(struct smb_ctx *, const char *);
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
int  smb_fh_close(struct smb_ctx *ctx, int);
int  smb_fh_open(struct smb_ctx *ctx, const char *, int, int *);
int  smb_fh_read(struct smb_ctx *, int, off_t, size_t, char *);
int  smb_fh_write(struct smb_ctx *, int, off_t, size_t, const char *);
int  smb_fh_xactnp(struct smb_ctx *, int, int, const char *,
	int *, char *, int *);

int  smb_iod_start(struct smb_ctx *);

int  smb_t2_request(struct smb_ctx *, int, uint16_t *, const char *,
	int, void *, int, void *, int *, void *, int *, void *, int *);

int  smb_printer_open(struct smb_ctx *, int, int, const char *, int *);
int  smb_printer_close(struct smb_ctx *, int);

char *smb_strerror(int);

#ifdef	__cplusplus
}
#endif

#endif /* _NETSMB_SMBFS_API_H */
