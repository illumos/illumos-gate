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
 * $Id: smb_dev.h,v 1.10.178.1 2005/05/27 02:35:29 lindak Exp $
 */

/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright 2018 Nexenta Systems, Inc.  All rights reserved.
 */

#ifndef _NETSMB_DEV_H_
#define	_NETSMB_DEV_H_

/*
 * This file defines an internal ABI for the "nsmb" driver,
 * particularly the various data structures passed to ioctl.
 * In order to avoid some messy 32-bit to 64-bit conversions
 * in the driver, we take pains to define all data structures
 * that pass across the user/kernel boundary in a way that
 * makes them invariant across 32-bit and 64-bit ABIs.
 * This invariance is checked during the driver build
 * using a mechanism similar to genassym.h builds.
 *
 * If you change any of the ioctl data structures in
 * this file, YOU MUST ALSO edit this file:
 *   uts/common/fs/smbclnt/netsmb/offsets.in
 * and then verify the invariance describe above.
 *
 * Also, remember to "bump" NSMB_VER below when
 * any part of this user/kernel I/F changes.
 */

#include <sys/types.h>
#include <sys/socket_impl.h>
#include <netinet/in.h>

#define	NSMB_NAME		"nsmb"

/*
 * Update NSMB_VER* if any of the ioctl codes and/or
 * associated structures change in ways that would
 * make them incompatible with an old driver.
 */
#define	NSMB_VERMAJ	2
#define	NSMB_VERMIN	0x100
#define	NSMB_VERSION	((NSMB_VERMAJ << 16) | NSMB_VERMIN)

/*
 * Some errno values we need to expose to the library.
 * NB: these are also defined in the library smbfs_api.h
 * to avoid exposing all of this stuff in that API.
 *
 * EBADRPC is used for message decoding errors.
 * EAUTH is used for CIFS authentication errors.
 */
#ifndef EBADRPC
#define	EBADRPC		113
#endif
#ifndef EAUTH
#define	EAUTH		114
#endif

/*
 * Upper/lower case options
 */
#define	SMB_CS_NONE	0x0000
#define	SMB_CS_UPPER	0x0001	/* convert passed string to upper case */
#define	SMB_CS_LOWER	0x0002	/* convert passed string to lower case */

/*
 * access mode stuff (see also smb_lib.h)
 */
#define	SMBM_ANY_OWNER		((uid_t)-1)
#define	SMBM_ANY_GROUP		((gid_t)-1)

/*
 * Option flags in smbioc_ossn.ioc_opt
 * and vcspec.optflags
 */
#define	SMBVOPT_CREATE		0x0001	/* create object if necessary */
#define	SMBVOPT_PRIVATE		0x0002	/* connection should be private */
#define	SMBVOPT_SINGLESHARE	0x0004	/* keep only one share at this VC */
#define	SMBVOPT_PERMANENT	0x0010	/* object will keep last reference */
#define	SMBVOPT_ANONYMOUS	0x0020	/* using a NULL session */

#define	SMBVOPT_SIGNING_ENABLED		0x10000	/* sign if server agrees */
#define	SMBVOPT_SIGNING_REQUIRED	0x20000 /* signing required */
#define	SMBVOPT_SIGNING_MASK		0x30000	/* all signing bits */

#define	SMB2_DIALECT_BASE	0x0200
#define	SMB2_DIALECT_0202	0x0202
#define	SMB2_DIALECT_02ff	0x02ff
#define	SMB2_DIALECT_0210	0x0210
#define	SMB2_DIALECT_0300	0x0300
#define	SMB2_DIALECT_0302	0x0302

/* Maximum supported dialect (for ssn_maxver) */
#define	SMB2_DIALECT_MAX	SMB2_DIALECT_0302

/*
 * Option flags in smbioc_oshare.ioc_opt
 * and sharespec.optflags
 */
#define	SMBSOPT_CREATE		SMBVOPT_CREATE
#define	SMBSOPT_PERMANENT	SMBVOPT_PERMANENT

/* All user and machine names. */
#define	SMBIOC_MAX_NAME		256

/*
 * Size of storage for p/w hashes.
 * Also for SMBIOC_GETSSNKEY.
 */
#define	SMBIOC_HASH_SZ	16

/*
 * network IO daemon states
 */
enum smbiod_state {
	SMBIOD_ST_UNINIT = 0,	/* uninitialized */
	SMBIOD_ST_RECONNECT,	/* a [re]connect attempt requested */
	SMBIOD_ST_RCFAILED,	/* a reconnect attempt has failed */
	SMBIOD_ST_CONNECTED,	/* Transport (TCP) connected */
	SMBIOD_ST_NEGOTIATED,	/* Negotiated SMB/SMB2+ */
	SMBIOD_ST_AUTHCONT,	/* Session setup continuing */
	SMBIOD_ST_AUTHFAIL,	/* Session setup failed */
	SMBIOD_ST_AUTHOK,	/* Session setup success */
	SMBIOD_ST_VCACTIVE,	/* iod_work running */
	SMBIOD_ST_IDLE,		/* no trees, will go DEAD */
	SMBIOD_ST_DEAD		/* connection gone, no IOD */
};


/*
 * We're now using structures that are invariant
 * across 32-bit vs 64-bit compilers for all
 * member sizes and offsets.  Scalar members
 * simply have to use fixed-size types.
 * Pointers are a little harder...
 * We use this union for all pointers that
 * must pass between user and kernel.
 */
typedef union lptr {
	uint64_t lp_ll;
#ifdef _LP64
	void	*lp_ptr;
#endif
#ifdef _ILP32
	void	*_lp_p2[2];
#ifdef _LITTLE_ENDIAN
#define	lp_ptr	_lp_p2[0]
#define	lp_pad	_lp_p2[1]
#else /* _ENDIAN */
#define	lp_pad	_lp_p2[0]
#define	lp_ptr	_lp_p2[1]
#endif /* _ENDIAN */
#endif /* _ILP32 */
} lptr_t;

/*
 * Handy union of sockaddr types we use.
 * Type discriminator is sa_family
 */
union smbioc_sockaddr {
	struct sockaddr sa;	/* generic */
	struct sockaddr_in sin;
	struct sockaddr_in6 sin6;
};
typedef union smbioc_sockaddr smbioc_sockaddr_t;

/*
 * This is what identifies a session.
 */
struct smbioc_ssn_ident {
	smbioc_sockaddr_t id_srvaddr;
	char		id_domain[SMBIOC_MAX_NAME];
	char		id_user[SMBIOC_MAX_NAME];
};
typedef struct smbioc_ssn_ident smbioc_ssn_ident_t;

/*
 * Flags for smbioc_ossn.ssn_opt
 */
#define	SMBLK_CREATE		SMBVOPT_CREATE

/*
 * Structure used with SMBIOC_SSN_FIND, _CREATE
 */
struct smbioc_ossn {
	uint32_t		ssn_owner;	/* Unix owner (UID) */
	uint32_t		ssn_vopt;	/* i.e. SMBVOPT_CREATE */
	uint16_t		ssn_minver;	/* Min SMB version. */
	uint16_t		ssn_maxver;	/* Max SMB version. */
	smbioc_ssn_ident_t	ssn_id;
	char			ssn_srvname[SMBIOC_MAX_NAME];
};
typedef struct smbioc_ossn smbioc_ossn_t;
/* Convenience names for members under ssn_id */
#define	ssn_srvaddr	ssn_id.id_srvaddr
#define	ssn_domain	ssn_id.id_domain
#define	ssn_user	ssn_id.id_user

/*
 * Structure used with SMBIOC_TREE_FIND, _CONNECT
 */
struct smbioc_oshare {
	uint32_t	sh_use;		/* requested */
	uint32_t	sh_type;	/* returned */
	char		sh_name[SMBIOC_MAX_NAME];
	char		sh_pass[SMBIOC_MAX_NAME];
};
typedef struct smbioc_oshare smbioc_oshare_t;

typedef struct smbioc_tcon {
	int32_t		tc_flags;
	int32_t		tc_opt;
	smbioc_oshare_t	tc_sh;
} smbioc_tcon_t;

/*
 * This is the operational state information passed
 * in and out of the driver for SMBIOC_SSN_WORK
 */
struct smbioc_ssn_work {
	uint32_t	wk_out_state;	/* out-only */
	uint32_t	wk_u_ssnkey_len; /* ssn key length */
	lptr_t		wk_u_ssnkey_buf; /* user-space ptr! */
	uint32_t	wk_u_auth_rlen;	/* recv auth tok len */
	uint32_t	wk_u_auth_wlen;	/* send auth tok len */
	lptr_t		wk_u_auth_rbuf;	/* recv auth tok buf */
	lptr_t		wk_u_auth_wbuf;	/* send auth tok buf */
	uint8_t		wk_cl_guid[16];	/* client GUID */
};
typedef struct smbioc_ssn_work smbioc_ssn_work_t;

/*
 * User-level SMB requests
 */

typedef struct smbioc_rw {
	uint32_t	ioc_cnt;
	uint32_t	ioc_flags;
	lloff_t	_ioc_offset;
	lptr_t	_ioc_base;
} smbioc_rw_t;
#define	ioc_offset	_ioc_offset._f
#define	ioc_base	_ioc_base.lp_ptr

/* Transact on named pipe (send/recv) */
typedef struct smbioc_xnp {
	uint32_t	ioc_tdlen;	/* transmit len */
	uint32_t	ioc_rdlen;	/* recv maxlen */
	uint32_t	ioc_more;	/* more data to read */
	uint32_t	ioc_pad1;
	lptr_t		_ioc_tdata;
	lptr_t		_ioc_rdata;
} smbioc_xnp_t;
#define	ioc_tdata	_ioc_tdata.lp_ptr
#define	ioc_rdata	_ioc_rdata.lp_ptr

typedef struct smbioc_ntcreate {
	uint32_t	ioc_req_acc;
	uint32_t	ioc_efattr;
	uint32_t	ioc_share_acc;
	uint32_t	ioc_open_disp;
	uint32_t	ioc_creat_opts;
	char		ioc_name[SMBIOC_MAX_NAME];
} smbioc_ntcreate_t;

typedef struct smbioc_printjob {
	uint16_t	ioc_setuplen;
	uint16_t	ioc_prmode;
	char		ioc_title[SMBIOC_MAX_NAME];
} smbioc_printjob_t;

/* Password Keychain (PK) support. */
typedef struct smbioc_pk {
	uid_t	pk_uid;				/* UID for PAM use */
	char pk_dom[SMBIOC_MAX_NAME];		/* CIFS domain name */
	char pk_usr[SMBIOC_MAX_NAME];		/* CIFS user name */
	uchar_t pk_lmhash[SMBIOC_HASH_SZ];	/* LanMan p/w hash */
	uchar_t pk_nthash[SMBIOC_HASH_SZ];	/* NTLM p/w hash */
} smbioc_pk_t;


/*
 * Device IOCTLs
 *
 * Define ioctl codes the way ZFS does.
 * The "base" value is arbitrary, and can
 * occupy the high word if we like, because
 * our driver does its own copyin/copyout.
 * Keep GETVERS first and use it to verify
 * driver compatibility with the library.
 */
#define	SMBIOC_BASE	((('n' << 8) | 's') << 8)
typedef enum nsmb_ioc {
	SMBIOC_GETVERS = SMBIOC_BASE,	/* keep first */
	SMBIOC_FLAGS2,		/* obsolete */
	SMBIOC_GETSSNKEY,	/* get SMB session key */
	SMBIOC_DUP_DEV,		/* duplicate dev handle */

	SMBIOC_READ,		/* read (pipe) */
	SMBIOC_WRITE,		/* write (pipe) */
	SMBIOC_XACTNP,		/* "transact" (pipe) */
	SMBIOC_NTCREATE,	/* open or create */
	SMBIOC_PRINTJOB,	/* open print job */
	SMBIOC_CLOSEFH,		/* from ntcreate or printjob */

	SMBIOC_SSN_CREATE,
	SMBIOC_SSN_FIND,
	SMBIOC_SSN_KILL,	/* force disconnect */
	SMBIOC_SSN_RELE,	/* drop our reference */

	SMBIOC_TREE_CONNECT,	/* create and connect */
	SMBIOC_TREE_FIND,
	SMBIOC_TREE_KILL,
	SMBIOC_TREE_RELE,

	SMBIOC_IOD_CONNECT,	/* Setup connection */
	SMBIOC_IOD_NEGOTIATE,	/* SMB/SMB2 negotiate */
	SMBIOC_IOD_SSNSETUP,	/* SMB/SMB2 session setup */
	SMBIOC_IOD_WORK,	/* work on session requests */
	SMBIOC_IOD_IDLE,	/* wait for requests on this session */
	SMBIOC_IOD_RCFAIL,	/* tell driver reconnect failed */

	/* Password Keychain (PK) support. */
	SMBIOC_PK_ADD,    /* Add/Modify a password entry */
	SMBIOC_PK_CHK,    /* Check for a password entry */
	SMBIOC_PK_DEL,    /* Delete specified password entry */
	SMBIOC_PK_DEL_OWNER,	/* all owned by the caller */
	SMBIOC_PK_DEL_EVERYONE	/* all owned by everyone */
} nsmb_ioc_t;

#endif /* _NETSMB_DEV_H_ */
