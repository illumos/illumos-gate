/*
 * Copyright (c) 2000-2001 Boris Popov
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    This product includes software developed by Boris Popov.
 * 4. Neither the name of the author nor the names of any co-contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $Id: smb_lib.h,v 1.21.82.2 2005/06/02 00:55:39 lindak Exp $
 */

/*
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
 */

#ifndef _NETSMB_SMB_LIB_H_
#define	_NETSMB_SMB_LIB_H_

/*
 * Internal interface exported to our commands in:
 *	usr/src/cmd/fs.d/smbclnt/
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/byteorder.h>

#include <netsmb/smbfs_api.h>
#include <netsmb/smb_dev.h>

extern const char smbutil_std_opts[];
#define	STDPARAM_OPT	smbutil_std_opts

/*
 * bits to indicate the source of error
 */
#define	SMB_ERRTYPE_MASK	0xf0000
#define	SMB_SYS_ERROR		0x00000
#define	SMB_RAP_ERROR		0x10000
#define	SMB_NB_ERROR		0x20000

/*
 * Size of all LM/NTLM hashes (16 bytes).
 * The driver needs to know this, so it's
 * defined by smb_dev.h
 */
#define	NTLM_HASH_SZ		SMBIOC_HASH_SZ
#define	NTLM_CHAL_SZ		8	/* challenge size */

/*
 * This is what goes across the door call to the IOD
 * when asking for a new connection.
 */
struct smb_iod_ssn {
	struct smbioc_ossn iod_ossn;
	int		iod_authflags;	/* SMB_AT_x */
	uchar_t		iod_nthash[NTLM_HASH_SZ];
	uchar_t		iod_lmhash[NTLM_HASH_SZ];
	/* Kerberos cred. cache res. name? */
};
typedef struct smb_iod_ssn smb_iod_ssn_t;


/*
 * SMB work context. Used to store all values which are necessary
 * to establish connection to an SMB server.
 */
struct smb_ctx {
	int		ct_flags;	/* SMBCF_ */
	int		ct_dev_fd;	/* device handle */
	int		ct_door_fd;	/* to smbiod */
	int		ct_parsedlevel;
	int		ct_minlevel;
	int		ct_maxlevel;
	char		*ct_fullserver; /* orig. server name from cmd line */
	char		*ct_srvaddr_s;	/* hostname or IP address of server */
	struct addrinfo *ct_addrinfo;	/* IP addresses of the server */
	struct nb_ctx	*ct_nb;		/* NetBIOS info. */
	char		*ct_locname;	/* local (machine) name */
	smb_iod_ssn_t	ct_iod_ssn;
	/* smbioc_oshare_t	ct_sh; XXX */
	int		ct_minauth;
	int		ct_shtype_req;	/* share type wanted */
	char		*ct_origshare;
	char		*ct_home;
	char		*ct_rpath;	/* remote file name */

	/* Connection setup SMB stuff. */
	/* Strings from the SMB negotiate response. */
	char		*ct_srv_OS;
	char		*ct_srv_LM;
	uint32_t	ct_clnt_caps;

	/* NTLM auth. stuff */
	uchar_t		ct_clnonce[NTLM_CHAL_SZ];
	uchar_t		ct_srv_chal[NTLM_CHAL_SZ];
	char		ct_password[SMBIOC_MAX_NAME];

	/* See ssp.c */
	void		*ct_ssp_ctx;
	smbioc_ssn_work_t ct_work;
};


/*
 * Short-hand for some of the substruct fields above
 */
#define	ct_ssn		ct_iod_ssn.iod_ossn
#define	ct_vopt		ct_iod_ssn.iod_ossn.ssn_vopt
#define	ct_owner	ct_iod_ssn.iod_ossn.ssn_owner
#define	ct_srvaddr	ct_iod_ssn.iod_ossn.ssn_srvaddr
#define	ct_domain	ct_iod_ssn.iod_ossn.ssn_domain
#define	ct_user 	ct_iod_ssn.iod_ossn.ssn_user
#define	ct_srvname 	ct_iod_ssn.iod_ossn.ssn_srvname
#define	ct_authflags	ct_iod_ssn.iod_authflags
#define	ct_nthash	ct_iod_ssn.iod_nthash
#define	ct_lmhash	ct_iod_ssn.iod_lmhash

#define	ct_sopt		ct_work.wk_sopt
#define	ct_iods		ct_work.wk_iods
#define	ct_tran_fd	ct_work.wk_iods.is_tran_fd
#define	ct_hflags	ct_work.wk_iods.is_hflags
#define	ct_hflags2	ct_work.wk_iods.is_hflags2
#define	ct_vcflags	ct_work.wk_iods.is_vcflags
#define	ct_ssn_key	ct_work.wk_iods.is_ssn_key
#define	ct_mac_seqno	ct_work.wk_iods.is_next_seq
#define	ct_mackeylen	ct_work.wk_iods.is_u_maclen
#define	ct_mackey	ct_work.wk_iods.is_u_mackey.lp_ptr


/*
 * Bits in smb_ctx_t.ct_flags
 */
#define	SMBCF_NOPWD		    0x0001 /* don't ask for a password */
#define	SMBCF_SRIGHTS		    0x0002 /* share access rights supplied */
#define	SMBCF_LOCALE		    0x0004 /* use current locale */
#define	SMBCF_CMD_DOM		    0x0010 /* CMD specified domain */
#define	SMBCF_CMD_USR		    0x0020 /* CMD specified user */
#define	SMBCF_CMD_PW		    0x0040 /* CMD specified password */
#define	SMBCF_RESOLVED		    0x8000 /* structure has been verified */
#define	SMBCF_KCBAD		0x00080000 /* keychain password failed */
#define	SMBCF_KCFOUND		0x00100000 /* password is from keychain */
#define	SMBCF_BROWSEOK		0x00200000 /* browser dialogue may be used */
#define	SMBCF_AUTHREQ		0x00400000 /* auth. dialog requested */
#define	SMBCF_KCSAVE		0x00800000 /* add to keychain requested */
#define	SMBCF_XXX		0x01000000 /* mount-all, a very bad thing */
#define	SMBCF_SSNACTIVE		0x02000000 /* session setup succeeded */
#define	SMBCF_KCDOMAIN		0x04000000 /* use domain in KC lookup */


/*
 * Context management
 */

int  smb_ctx_init(struct smb_ctx *);
void smb_ctx_done(struct smb_ctx *);
int  smb_open_driver(void);

int  smb_ctx_gethandle(struct smb_ctx *);
int  smb_ctx_findvc(struct smb_ctx *);
int  smb_ctx_newvc(struct smb_ctx *);

/*
 * I/O daemon stuff
 */

#define	SMBIOD_RUNDIR	"/var/run/smbiod"
#define	SMBIOD_SVC_DOOR	SMBIOD_RUNDIR "/.svc"
#define	SMBIOD_USR_DOOR	SMBIOD_RUNDIR "/%d"
#define	SMBIOD_START	1

int  smb_iod_cl_newvc(smb_ctx_t *ctx);
char *smb_iod_door_path(void);
int smb_iod_open_door(int *);
int smb_iod_connect(struct smb_ctx *);
int smb_iod_work(struct smb_ctx *);

/*
 * Other stuff
 */

int  smb_open_rcfile(char *);
void smb_close_rcfile(void);

void smb_simplecrypt(char *dst, const char *src);
int  smb_simpledecrypt(char *dst, const char *src);

int	nls_setrecode(const char *, const char *);
int	nls_setlocale(const char *);
char	*nls_str_toext(char *, const char *);
char	*nls_str_toloc(char *, const char *);
void	*nls_mem_toext(void *, const void *, int);
void	*nls_mem_toloc(void *, const void *, int);
char	*nls_str_upper(char *, const char *);
char	*nls_str_lower(char *, const char *);

char *smb_getprogname();
#define	__progname smb_getprogname()

#endif /* _NETSMB_SMB_LIB_H_ */
