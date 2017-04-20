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
 * Copyright 2017 Joyent Inc
 * Use is subject to license terms.
 */
/* Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T */
/* All Rights Reserved */
/*
 * Portions of this source code were derived from Berkeley
 * 4.3 BSD under license from the Regents of the University of
 * California.
 */

/*
 * auth.h, Authentication interface.
 *
 * The data structures are completely opaque to the client. The client
 * is required to pass a AUTH * to routines that create rpc
 * "sessions".
 */

#ifndef	_RPC_AUTH_H
#define	_RPC_AUTH_H

#include <rpc/xdr.h>
#include <rpc/clnt_stat.h>
#include <sys/cred.h>
#include <sys/tiuser.h>
#ifdef _KERNEL
#include <sys/zone.h>
#endif

#ifdef	__cplusplus
extern "C" {
#endif

#define	MAX_AUTH_BYTES	400	/* maximum length of an auth type, from RFC */
#define	MAXNETNAMELEN	255	/* maximum length of network user's name */

/*
 * NOTE: this value *must* be kept larger than the maximum size of all the
 * structs that rq_clntcred is cast to in the different authentication types.
 * If changes are made to any of these *_area structs, double-check they all
 * still fit. If any new authentication mechanisms are added, add a note here.
 *
 * Currently these structs can be found in:
 *  - __svcauth_sys (svc_auth_sys.c)
 *  - __svcauth_des (svcauth_des.c)
 *  - __svcauth_loopback (svc_auth_loopb.c)
 */
#define	RQCRED_SIZE	700	/* size allocated for rq_clntcred */

/*
 *  Client side authentication/security data
 */
typedef struct sec_data {
	uint_t	secmod;		/* security mode number e.g. in nfssec.conf */
	uint_t	rpcflavor;	/* rpc flavors:AUTH_UNIX,AUTH_DES,RPCSEC_GSS */
	int	flags;		/* AUTH_F_xxx flags */
	uid_t	uid;		/* uid of caller for all sec flavors (NFSv4)  */
	caddr_t	data;		/* opaque data per flavor */
} sec_data_t;

#ifdef _SYSCALL32_IMPL
struct sec_data32 {
	uint32_t	secmod;	/* security mode number e.g. in nfssec.conf */
	uint32_t	rpcflavor; /* AUTH_UNIX,AUTH_DES,RPCSEC_GSS */
	int32_t		flags;	/* AUTH_F_xxx flags */
	uid_t		uid;	/* uid of caller for all sec flavors (NFSv4) */
	caddr32_t	data;	/* opaque data per flavor */
};
#endif /* _SYSCALL32_IMPL */

/*
 * AUTH_DES flavor specific data from sec_data opaque data field.
 * AUTH_KERB has the same structure.
 */
typedef struct des_clnt_data {
	struct netbuf	syncaddr;	/* time sync addr */
	struct knetconfig *knconf;	/* knetconfig info that associated */
					/* with the syncaddr. */
	char		*netname;	/* server's netname */
	int		netnamelen;	/* server's netname len */
} dh_k4_clntdata_t;

#ifdef _SYSCALL32_IMPL
struct des_clnt_data32 {
	struct netbuf32 syncaddr;	/* time sync addr */
	caddr32_t knconf;		/* knetconfig info that associated */
					/* with the syncaddr. */
	caddr32_t netname;		/* server's netname */
	int32_t	netnamelen;		/* server's netname len */
};
#endif /* _SYSCALL32_IMPL */

/*
 * flavor specific data to hold the data for AUTH_DES/AUTH_KERB(v4)
 * in sec_data->data opaque field.
 */
typedef struct krb4_svc_data {
	int		window;		/* window option value */
} krb4_svcdata_t;

typedef struct krb4_svc_data	des_svcdata_t;

/*
 * authentication/security specific flags
 */
#define	AUTH_F_RPCTIMESYNC	0x001	/* use RPC to do time sync */
#define	AUTH_F_TRYNONE		0x002	/* allow fall back to AUTH_NONE */


/*
 * Status returned from authentication check
 */
enum auth_stat {
	AUTH_OK = 0,
	/*
	 * failed at remote end
	 */
	AUTH_BADCRED = 1,		/* bogus credentials (seal broken) */
	AUTH_REJECTEDCRED = 2,		/* client should begin new session */
	AUTH_BADVERF = 3,		/* bogus verifier (seal broken) */
	AUTH_REJECTEDVERF = 4,		/* verifier expired or was replayed */
	AUTH_TOOWEAK = 5,		/* rejected due to security reasons */
	/*
	 * failed locally
	 */
	AUTH_INVALIDRESP = 6,		/* bogus response verifier */
	AUTH_FAILED = 7,			/* some unknown reason */
	/*
	 * kerberos errors
	 */
	AUTH_KERB_GENERIC = 8,		/* kerberos generic error */
	AUTH_TIMEEXPIRE = 9,		/* time of credential expired */
	AUTH_TKT_FILE = 10,		/* something wrong with ticket file */
	AUTH_DECODE = 11,		/* can't decode authenticator */
	AUTH_NET_ADDR = 12,		/* wrong net address in ticket */
	/*
	 * GSS related errors
	 */
	RPCSEC_GSS_NOCRED = 13,		/* no credentials for user */
	RPCSEC_GSS_FAILED = 14		/* GSS failure, credentials deleted */
};
typedef enum auth_stat AUTH_STAT;

union des_block {
	struct	{
		uint32_t high;
		uint32_t low;
	} key;
	char c[8];
};
typedef union des_block des_block;

#ifdef __STDC__
extern bool_t xdr_des_block(XDR *, des_block *);
#else
extern bool_t xdr_des_block();
#endif


/*
 * Authentication info. Opaque to client.
 */
struct opaque_auth {
	enum_t	oa_flavor;		/* flavor of auth */
	caddr_t	oa_base;		/* address of more auth stuff */
	uint_t	oa_length;		/* not to exceed MAX_AUTH_BYTES */
};


/*
 * Auth handle, interface to client side authenticators.
 */
typedef struct __auth {
	struct	opaque_auth	ah_cred;
	struct	opaque_auth	ah_verf;
	union	des_block	ah_key;
	struct auth_ops {
#ifdef __STDC__
		void	(*ah_nextverf)(struct __auth *);
#ifdef _KERNEL
		int	(*ah_marshal)(struct __auth *, XDR *, struct cred *);
#else
		int	(*ah_marshal)(struct __auth *, XDR *);
#endif
		/* nextverf & serialize */
		int	(*ah_validate)(struct __auth *,
		    struct opaque_auth *);
		/* validate varifier */
#ifdef _KERNEL
		int	(*ah_refresh)(struct __auth *, struct rpc_msg *,
		    cred_t *);
#else
		int	(*ah_refresh)(struct __auth *, void *);
		/* refresh credentials */
#endif
		void	(*ah_destroy)(struct __auth *);
		/* destroy this structure */

#ifdef _KERNEL
		int	(*ah_wrap)(struct __auth *, caddr_t, uint_t,
		    XDR *, xdrproc_t, caddr_t);
		int	(*ah_unwrap)(struct __auth *, XDR *, xdrproc_t,
		    caddr_t);
#endif
#else
		void	(*ah_nextverf)();
		int	(*ah_marshal)();	/* nextverf & serialize */
		int	(*ah_validate)();	/* validate verifier */
		int	(*ah_refresh)();	/* refresh credentials */
		void	(*ah_destroy)();	/* destroy this structure */
#ifdef _KERNEL
		int	(*ah_wrap)();		/* encode XDR data */
		int	(*ah_unwrap)();		/* decode XDR data */
#endif

#endif
	} *ah_ops;
	caddr_t ah_private;
} AUTH;


/*
 * Authentication ops.
 * The ops and the auth handle provide the interface to the authenticators.
 *
 * AUTH	*auth;
 * XDR	*xdrs;
 * struct opaque_auth verf;
 */
#define	AUTH_NEXTVERF(auth)		\
		((*((auth)->ah_ops->ah_nextverf))(auth))
#define	auth_nextverf(auth)		\
		((*((auth)->ah_ops->ah_nextverf))(auth))


#ifdef _KERNEL
#define	AUTH_MARSHALL(auth, xdrs, cred)	\
		((*((auth)->ah_ops->ah_marshal))(auth, xdrs, cred))
#define	auth_marshall(auth, xdrs, cred)	\
		((*((auth)->ah_ops->ah_marshal))(auth, xdrs, cred))
#else
#define	AUTH_MARSHALL(auth, xdrs)	\
		((*((auth)->ah_ops->ah_marshal))(auth, xdrs))
#define	auth_marshall(auth, xdrs)	\
		((*((auth)->ah_ops->ah_marshal))(auth, xdrs))
#endif


#define	AUTH_VALIDATE(auth, verfp)	\
		((*((auth)->ah_ops->ah_validate))((auth), verfp))
#define	auth_validate(auth, verfp)	\
		((*((auth)->ah_ops->ah_validate))((auth), verfp))

#ifdef _KERNEL
#define	AUTH_REFRESH(auth, msg, cr)		\
		((*((auth)->ah_ops->ah_refresh))(auth, msg, cr))
#define	auth_refresh(auth, msg, cr)		\
		((*((auth)->ah_ops->ah_refresh))(auth, msg, cr))
#else
#define	AUTH_REFRESH(auth, msg)		\
		((*((auth)->ah_ops->ah_refresh))(auth, msg))
#define	auth_refresh(auth, msg)		\
		((*((auth)->ah_ops->ah_refresh))(auth, msg))
#endif

#define	AUTH_DESTROY(auth)		\
		((*((auth)->ah_ops->ah_destroy))(auth))
#define	auth_destroy(auth)		\
		((*((auth)->ah_ops->ah_destroy))(auth))

/*
 * Auth flavors can now apply a transformation in addition to simple XDR
 * on the body of a call/response in ways that depend on the flavor being
 * used.  These interfaces provide a generic interface between the
 * internal RPC frame and the auth flavor specific code to allow the
 * auth flavor to encode (WRAP) or decode (UNWRAP) the body.
 */
#ifdef _KERNEL
#define	AUTH_WRAP(auth, buf, buflen, xdrs, xfunc, xwhere)	\
		((*((auth)->ah_ops->ah_wrap))(auth, buf, buflen, \
				xdrs, xfunc, xwhere))
#define	auth_wrap(auth, buf, buflen, xdrs, xfunc, xwhere)	\
		((*((auth)->ah_ops->ah_wrap))(auth, buf, buflen, \
				xdrs, xfunc, xwhere))

#define	AUTH_UNWRAP(auth, xdrs, xfunc, xwhere)	\
		((*((auth)->ah_ops->ah_unwrap))(auth, xdrs, xfunc, xwhere))
#define	auth_unwrap(auth, xdrs)	\
		((*((auth)->ah_ops->ah_unwrap))(auth, xdrs, xfunc, xwhere))
#endif

extern struct opaque_auth _null_auth;

/*
 * These are the various implementations of client side authenticators.
 */

/*
 * System style authentication
 * AUTH *authsys_create(machname, uid, gid, len, aup_gids)
 *	const char *machname;
 *	const uid_t uid;
 *	const gid_t gid;
 *	const int len;
 *	const gid_t *aup_gids;
 */
#ifdef _KERNEL
extern AUTH *authkern_create(void);		/* takes no parameters */
extern int authkern_init(void *, void *, int);
extern struct kmem_cache *authkern_cache;
extern AUTH *authnone_create(void);		/* takes no parameters */
extern int authnone_init(void *, void *, int);
extern struct kmem_cache *authnone_cache;
extern AUTH *authloopback_create(void);		/* takes no parameters */
extern int authloopback_init(void *, void *, int);
extern struct kmem_cache *authloopback_cache;
#else /* _KERNEL */
#ifdef __STDC__
extern AUTH *authsys_create(const char *, const uid_t, const gid_t, const int,
    const gid_t *);
extern AUTH *authsys_create_default(void);	/* takes no parameters */
extern AUTH *authnone_create(void);		/* takes no parameters */
#else /* __STDC__ */
extern AUTH *authsys_create();
extern AUTH *authsys_create_default();	/* takes no parameters */
extern AUTH *authnone_create();	/* takes no parameters */
#endif /* __STDC__ */
/* Will get obsolete in near future */
#define	authunix_create		authsys_create
#define	authunix_create_default authsys_create_default
#endif /* _KERNEL */

/*
 * DES style authentication
 * AUTH *authdes_seccreate(servername, window, timehost, ckey)
 *	const char *servername;		- network name of server
 *	const uint_t window;			- time to live
 *	const char *timehost;			- optional hostname to sync with
 *	const des_block *ckey;		- optional conversation key to use
 */
/* Will get obsolete in near future */
#ifdef _KERNEL
extern int authdes_create(char *, uint_t, struct netbuf *, struct knetconfig *,
    des_block *, int, AUTH **retauth);
#else /* _KERNEL */
#ifdef __STDC__
extern AUTH *authdes_seccreate(const char *, const uint_t, const  char *,
    const des_block *);
#else
extern AUTH *authdes_seccreate();
#endif /* __STDC__ */
#endif /* _KERNEL */

/*
 *  Netname manipulating functions
 */

#ifdef	_KERNEL
extern enum clnt_stat netname2user(char *, uid_t *, gid_t *, int *, gid_t *);
#endif
#ifdef __STDC__
extern int getnetname(char *);
extern int host2netname(char *, const char *, const char *);
extern int user2netname(char *, const uid_t, const char *);
#ifndef	_KERNEL
extern int netname2user(const char *, uid_t *, gid_t *, int *, gid_t *);
#endif
extern int netname2host(const char *, char *, const int);
#else
extern int getnetname();
extern int host2netname();
extern int user2netname();
extern int netname2host();
#endif

/*
 * These routines interface to the keyserv daemon
 */

#ifdef _KERNEL
extern enum clnt_stat key_decryptsession();
extern enum clnt_stat key_encryptsession();
extern enum clnt_stat key_gendes();
extern enum clnt_stat key_getnetname();
#endif

#ifndef _KERNEL
#ifdef	__STDC__
extern int key_decryptsession(const char *, des_block *);
extern int key_encryptsession(const char *, des_block *);
extern int key_gendes(des_block *);
extern int key_setsecret(const char *);
extern int key_secretkey_is_set(void);
/*
 * The following routines are private.
 */
extern int key_setnet_ruid();
extern int key_setnet_g_ruid();
extern int key_removesecret_g_ruid();
extern int key_secretkey_is_set_g_ruid();
extern AUTH *authsys_create_ruid();
#else
extern int key_decryptsession();
extern int key_encryptsession();
extern int key_gendes();
extern int key_setsecret();
extern int key_secretkey_is_set();
#endif
#endif


/*
 * Kerberos style authentication
 * AUTH *authkerb_seccreate(service, srv_inst, realm, window, timehost, status)
 *	const char *service;			- service name
 *	const char *srv_inst;			- server instance
 *	const char *realm;			- server realm
 *	const uint_t window;			- time to live
 *	const char *timehost;			- optional hostname to sync with
 *	int *status;			- kerberos status returned
 */
#ifdef _KERNEL
extern int    authkerb_create(char *, char *, char *, uint_t,
    struct netbuf *, int *, struct knetconfig *, int, AUTH **);
#else
#ifdef __STDC__
extern AUTH *authkerb_seccreate(const char *, const char *, const  char *,
    const uint_t, const char *, int *);
#else
extern AUTH *authkerb_seccreate();
#endif
#endif /* _KERNEL */

/*
 * Map a kerberos credential into a unix cred.
 *
 *  authkerb_getucred(rqst, uid, gid, grouplen, groups)
 *	const struct svc_req *rqst;		- request pointer
 *	uid_t *uid;
 *	gid_t *gid;
 *	short *grouplen;
 *	int   *groups;
 *
 */
#ifdef __STDC__
struct svc_req;
extern int authkerb_getucred(struct svc_req *, uid_t *, gid_t *,
    short *, int *);
#else
extern int authkerb_getucred();
#endif

#ifdef _KERNEL
/*
 * XDR an opaque authentication struct.  See auth.h.
 */
extern bool_t xdr_opaque_auth(XDR *, struct opaque_auth *);
#endif

#ifdef _KERNEL
extern int authany_wrap(AUTH *, caddr_t, uint_t, XDR *, xdrproc_t, caddr_t);
extern int authany_unwrap(AUTH *, XDR *, xdrproc_t, caddr_t);
#endif

#define	AUTH_NONE	0		/* no authentication */
#define	AUTH_NULL	0		/* backward compatibility */
#define	AUTH_SYS	1		/* unix style (uid, gids) */
#define	AUTH_UNIX	AUTH_SYS
#define	AUTH_SHORT	2		/* short hand unix style */
#define	AUTH_DH		3		/* for Diffie-Hellman mechanism */
#define	AUTH_DES	AUTH_DH		/* for backward compatibility */
#define	AUTH_KERB	4		/* kerberos style */
#define	RPCSEC_GSS	6		/* GSS-API style */

#define	AUTH_LOOPBACK	21982		/* unix style w/ expanded groups */
					/* for use over the local transport */

#ifdef _KERNEL
extern char	loopback_name[];

extern zone_key_t	auth_zone_key;
extern void *		auth_zone_init(zoneid_t);
extern void		auth_zone_fini(zoneid_t, void *);
#endif

#ifdef	__cplusplus
}
#endif

#endif	/* !_RPC_AUTH_H */
