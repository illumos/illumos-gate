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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
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

#ifndef _KERNEL
#include <sys/types.h>
#endif

#include <sys/socket_impl.h>
#include <netsmb/smb.h>
#include <netsmb/netbios.h>

#define	NSMB_NAME		"nsmb"

/*
 * Update NSMB_VER* if any of the ioctl codes and/or
 * associated structures change in ways that would
 * make them incompatible with an old driver.
 */
#define	NSMB_VERMAJ	1
#define	NSMB_VERMIN	3600
#define	NSMB_VERSION	(NSMB_VERMAJ * 100000 + NSMB_VERMIN)
#define	NSMB_VER_STR "1.36"

#define	NSMBFL_OPEN		0x0001
#define	NSMBFL_NEWVC		0x0002

/*
 * Hack-ish errno values we need to expose to the library.
 * EBADRPC is used for message decoding errors.
 * EAUTH is used for CIFS authentication errors.
 */
#ifndef EBADRPC
#define	EBADRPC 	113 /* XXX */
#endif
#ifndef EAUTH
#define	EAUTH		114 /* XXX */
#endif

/*
 * "Level" in the connection object hierarchy
 */
#define	SMBL_SM		0
#define	SMBL_VC		1
#define	SMBL_SHARE	2
#define	SMBL_NUM	3
#define	SMBL_NONE	(-1)

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
#define	SMBM_MASK		0777
#define	SMBM_EXACT		010000	/* check for specified mode exactly */
#ifdef _KERNEL
/* In-kernel, we prefer the vnode.h names. */
#define	SMBM_READ	VREAD	/* (S_IRUSR) read conn attrs. */
#define	SMBM_WRITE	VWRITE	/* (S_IWUSR) modify conn attrs */
#define	SMBM_EXEC	VEXEC	/* (S_IXUSR) can send SMB requests */
#endif

/*
 * Option flags in smbioc_ossn.ioc_opt
 * and vcspec.optflags
 */
#define	SMBVOPT_CREATE		0x0001	/* create object if necessary */
#define	SMBVOPT_PRIVATE		0x0002	/* connection should be private */
#define	SMBVOPT_SINGLESHARE	0x0004	/* keep only one share at this VC */
#define	SMBVOPT_PERMANENT	0x0010	/* object will keep last reference */
#define	SMBVOPT_EXT_SEC		0x0020	/* extended security negotiation */
#define	SMBVOPT_USE_KEYCHAIN	0x0040	/* get p/w from keychain */
#define	SMBVOPT_KC_DOMAIN	0x0080	/* keychain lookup uses domain */

#define	SMBVOPT_SIGNING_ENABLED		0x0100	/* sign if server agrees */
#define	SMBVOPT_SIGNING_REQUIRED	0x0200	/* signing required */
#define	SMBVOPT_SIGNING_MASK		0x0300	/* all signing bits */

/* XXX: How about a separate field for these? */
#define	SMBVOPT_MINAUTH			0x7000	/* min. auth. level (mask) */
#define	SMBVOPT_MINAUTH_NONE		0x0000	/* any authentication OK */
#define	SMBVOPT_MINAUTH_LM		0x1000	/* no plaintext passwords */
#define	SMBVOPT_MINAUTH_NTLM		0x2000	/* don't send LM reply */
#define	SMBVOPT_MINAUTH_NTLMV2		0x3000	/* don't fall back to NTLMv1 */
#define	SMBVOPT_MINAUTH_KERBEROS	0x4000	/* don't do NTLMv1 or v2 */

/*
 * Option flags in smbioc_oshare.ioc_opt
 * and sharespec.optflags
 */
#define	SMBSOPT_CREATE		SMBVOPT_CREATE
#define	SMBSOPT_PERMANENT	SMBVOPT_PERMANENT

#define	MAX_STR_LEN	8	/* Maxilum length of the minor device name */

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
union sockaddr_any {
	struct sockaddr sa;
	struct sockaddr_in in;
	struct sockaddr_nb nb;
};


/*
 * SMBIOC_LOOKUP flags
 */
#define	SMBLK_CREATE		SMBVOPT_CREATE

#define	DEF_SEC_TOKEN_LEN 2048

struct smbioc_ossn {
	union sockaddr_any		ioc_server;
	union sockaddr_any		ioc_local;
	char		ioc_localcs[16];	/* local charset */
	char		ioc_servercs[16];	/* server charset */
	char		ioc_srvname[SMB_MAXSRVNAMELEN + 1];
	char		ioc_user[SMB_MAXUSERNAMELEN + 1];
	char		ioc_workgroup[SMB_MAXUSERNAMELEN + 1];
	char		ioc_password[SMB_MAXPASSWORDLEN + 1];
	int32_t		ioc_opt;
	int32_t		ioc_timeout;    /* ignored?! XXX */
	int32_t		ioc_retrycount; /* number of retries before giveup */
	uid_t		ioc_owner;	/* proposed owner */
	gid_t		ioc_group;	/* proposed group */
	mode_t		ioc_mode;	/* desired access mode */
	mode_t		ioc_rights;	/* SMBM_* */
	int32_t		ioc_intoklen;
	int32_t		ioc_outtoklen;
	/* copyout ends at this offset */
	lptr_t		_ioc_intok;
	lptr_t		_ioc_outtok;
};
typedef struct smbioc_ossn smbioc_ossn_t;
#define	ioc_intok	_ioc_intok.lp_ptr
#define	ioc_outtok	_ioc_outtok.lp_ptr


struct smbioc_oshare {
	char		ioc_share[SMB_MAXSHARENAMELEN + 1];
	char		ioc_password[SMB_MAXPASSWORDLEN + 1];
	int32_t		ioc_opt;
	int32_t		ioc_stype;	/* share type */
	uid_t		ioc_owner;	/* proposed owner of share */
	gid_t		ioc_group;	/* proposed group of share */
	mode_t		ioc_mode;	/* desired access mode to share */
	mode_t		ioc_rights;	/* SMBM_* */
	/*
	 * Hack: need the size of this to be 8-byte aligned
	 * so that the ioc_ossn following it in smbioc_lookup
	 * is correctly aligned...
	 */
	int32_t		ioc__pad;
};
typedef struct smbioc_oshare smbioc_oshare_t;

typedef struct smbioc_rq {
	uchar_t		ioc_cmd;
	uchar_t		ioc_twc; /* _twords */
	ushort_t	ioc_tbc; /* _tbytes */
	int32_t		ioc_rpbufsz; /* _rpbuf */
	uchar_t		ioc__pad1;
	uchar_t		ioc_rwc;
	ushort_t	ioc_rbc;
	uchar_t		ioc__pad2;
	uint8_t 	ioc_errclass;
	uint16_t	ioc_serror;
	uint32_t	ioc_error;
	uint32_t	ioc__pad3;
	/*
	 * Copyout all but the pointers, which
	 * we may have set to kernel memory.
	 * See ..._COPYOUT_SIZE
	 */
	lptr_t		_ioc_twords;
	lptr_t		_ioc_tbytes;
	lptr_t		_ioc_rpbuf;
} smbioc_rq_t;
#define	ioc_twords	_ioc_twords.lp_ptr
#define	ioc_tbytes	_ioc_tbytes.lp_ptr
#define	ioc_rpbuf	_ioc_rpbuf.lp_ptr
#define	SMBIOC_RQ_COPYOUT_SIZE \
	(offsetof(smbioc_rq_t, _ioc_twords))


#define	SMBIOC_T2RQ_MAXNAME 128

typedef struct smbioc_t2rq {
	uint16_t	ioc_setup[SMB_MAXSETUPWORDS];
	int32_t		ioc_setupcnt;
	char		ioc_name[SMBIOC_T2RQ_MAXNAME];
	ushort_t	ioc_tparamcnt;
	ushort_t	ioc_tdatacnt;
	ushort_t	ioc_rparamcnt;
	ushort_t	ioc_rdatacnt;
	uint8_t 	ioc__pad1;
	uint8_t 	ioc_errclass;
	uint16_t	ioc_serror;
	uint32_t	ioc_error;
	uint16_t	ioc_rpflags2;
	uint16_t	ioc__pad2;
	/*
	 * Copyout all but the pointers, which
	 * we may have set to kernel memory.
	 * See ..._COPYOUT_SIZE
	 */
	lptr_t		_ioc_tparam;
	lptr_t		_ioc_tdata;
	lptr_t		_ioc_rparam;
	lptr_t		_ioc_rdata;
} smbioc_t2rq_t;
#define	ioc_tparam	_ioc_tparam.lp_ptr
#define	ioc_tdata	_ioc_tdata.lp_ptr
#define	ioc_rparam	_ioc_rparam.lp_ptr
#define	ioc_rdata	_ioc_rdata.lp_ptr
#define	SMBIOC_T2RQ_COPYOUT_SIZE \
	(offsetof(smbioc_t2rq_t, _ioc_tparam))


typedef struct smbioc_flags {
	int32_t		ioc_level;	/* 0 - session, 1 - share */
	int32_t		ioc_mask;
	int32_t		ioc_flags;
} smbioc_flags_t;

typedef struct smbioc_lookup {
	int32_t		ioc_level;
	int32_t		ioc_flags;
	struct smbioc_oshare	ioc_sh;
	struct smbioc_ossn	ioc_ssn;
} smbioc_lookup_t;
#define	SMBIOC_LOOK_COPYOUT_SIZE \
	(offsetof(smbioc_lookup_t, ioc_ssn._ioc_intok))

typedef struct smbioc_rw {
	uint16_t	ioc_fh;
	uint32_t	ioc_cnt;
	lloff_t	_ioc_offset;
	lptr_t	_ioc_base;
} smbioc_rw_t;
#define	ioc_offset	_ioc_offset._f
#define	ioc_base	_ioc_base.lp_ptr
#define	SMBIOC_RW_COPYOUT_SIZE \
	(offsetof(smbioc_rw_t, _ioc_base))

/* Password Keychain (PK) support. */
#define	SMBIOC_PK_MAXLEN 255
typedef struct smbioc_pk {
	uid_t	pk_uid;				/* UID for PAM use */
	char pk_dom[SMBIOC_PK_MAXLEN+1];	/* CIFS domain name */
	char pk_usr[SMBIOC_PK_MAXLEN+1];	/* CIFS user name */
	char pk_pass[SMBIOC_PK_MAXLEN+1];	/* CIFS password */
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
#define	SMBIOC_BASE 	((('n' << 8) | 's') << 8)
typedef enum nsmb_ioc {
	SMBIOC_GETVERS = SMBIOC_BASE,
	SMBIOC_REQUEST,
	SMBIOC_T2RQ,
	SMBIOC_LOOKUP,
	SMBIOC_READ,
	SMBIOC_WRITE,
	SMBIOC_FINDVC,
	SMBIOC_NEGOTIATE,
	SMBIOC_SSNSETUP,
	SMBIOC_TCON,
	SMBIOC_TDIS,
	SMBIOC_FLAGS2,
	/* Password Keychain (PK) support. */
	SMBIOC_PK_ADD,    /* Add/Modify a password entry */
	SMBIOC_PK_CHK,    /* Check for a password entry */
	SMBIOC_PK_DEL,    /* Delete specified password entry */
	SMBIOC_PK_DEL_OWNER,	/* all owned by the caller */
	SMBIOC_PK_DEL_EVERYONE	/* all owned by everyone */
} nsmb_ioc_t;

#ifdef _KERNEL
#include <sys/dditypes.h>	/* for dev_info_t */

#define	SMBST_CONNECTED	1

/* Size of storage for p/w hashes. */
#define	SMB_PWH_MAX	24

extern const uint32_t nsmb_version;

struct smb_cred;
struct smb_share;
struct smb_vc;

typedef struct smb_dev {
	int		sd_opened;	/* Opened or not */
	int		sd_level;	/* Future use */
	struct smb_vc	*sd_vc;		/* Reference to VC */
	struct smb_share *sd_share;	/* Reference to share if any */
	int		sd_poll;	/* Future use */
	int		sd_seq;		/* Kind of minor number/instance no */
	int		sd_flags;	/* State of connection */
	zoneid_t	zoneid;		/* Zone id */
	dev_info_t	*smb_dip;	/* ptr to dev_info node */
	void		*sd_devfs;	/* Dont know how to use this. but */
	struct cred	*smb_cred;	/* per dev credentails. Future use */
} smb_dev_t;

/*
 * Compound user interface
 */
int smb_usr_findvc(struct smbioc_lookup *dp, struct smb_cred *scred,
	struct smb_vc **vcpp);
int  smb_usr_negotiate(struct smbioc_lookup *dp, struct smb_cred *scred,
	struct smb_vc **vcpp);
int  smb_usr_ssnsetup(struct smbioc_lookup *dp, struct smb_cred *scred,
	struct smb_vc *vcp);
int  smb_usr_tcon(struct smbioc_lookup *dp, struct smb_cred *scred,
	struct smb_vc *vcp, struct smb_share **sspp);
int  smb_usr_simplerequest(struct smb_share *ssp, struct smbioc_rq *data,
	struct smb_cred *scred);
int  smb_usr_t2request(struct smb_share *ssp, struct smbioc_t2rq *data,
	struct smb_cred *scred);
int  smb_usr_rw(struct smb_share *ssp, smbioc_rw_t *dp,
	int cmd, struct smb_cred *scred);
int  smb_dev2share(int fd, struct smb_share **sspp);

#endif /* _KERNEL */
#endif /* _NETSMB_DEV_H_ */
