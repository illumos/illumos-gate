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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/param.h>
#include <sys/types.h>
#include <sys/systm.h>
#include <sys/cred.h>
#include <sys/proc.h>
#include <sys/user.h>
#include <sys/time.h>
#include <sys/buf.h>
#include <sys/vfs.h>
#include <sys/vnode.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/tiuser.h>
#include <sys/swap.h>
#include <sys/errno.h>
#include <sys/debug.h>
#include <sys/kmem.h>
#include <sys/kstat.h>
#include <sys/cmn_err.h>
#include <sys/vtrace.h>
#include <sys/session.h>
#include <sys/dnlc.h>
#include <sys/bitmap.h>
#include <sys/thread.h>
#include <sys/policy.h>

#include <netinet/in.h>
#include <rpc/types.h>
#include <rpc/xdr.h>
#include <rpc/auth.h>
#include <rpc/auth_des.h>	/* for authdes_create() */
#include <rpc/clnt.h>
#include <rpc/rpcsec_gss.h>

#define	MAXCLIENTS	16
static int clnt_authdes_cachesz = 64;

static uint_t authdes_win = 5*60;  /* 5 minutes -- should be mount option */

struct kmem_cache *authkern_cache;

struct kmem_cache *authloopback_cache;

static struct desauthent {
	struct	sec_data *da_data;
	uid_t da_uid;
	zoneid_t da_zoneid;
	short da_inuse;
	AUTH *da_auth;
} *desauthtab;
static int nextdesvictim;
static kmutex_t desauthtab_lock;	/* Lock to protect DES auth cache */

/* RPC stuff */
kmutex_t authdes_ops_lock;   /* auth_ops initialization in authdes_ops() */

static void  purge_authtab(struct sec_data *);

/* Zone stuff */
zone_key_t auth_zone_key;

/*
 *  Load RPCSEC_GSS specific data from user space to kernel space.
 */
/*ARGSUSED*/
static int
gss_clnt_loadinfo(caddr_t usrdata, caddr_t *kdata, model_t model)
{
	struct gss_clnt_data *data;
	caddr_t	elements;
	int error = 0;

	/* map opaque data to gss specific structure */
	data = kmem_alloc(sizeof (*data), KM_SLEEP);

#ifdef _SYSCALL32_IMPL
	if (model != DATAMODEL_NATIVE) {
		struct gss_clnt_data32 gd32;

		if (copyin(usrdata, &gd32, sizeof (gd32)) == -1) {
			error = EFAULT;
		} else {
			data->mechanism.length = gd32.mechanism.length;
			data->mechanism.elements =
			    (caddr_t)(uintptr_t)gd32.mechanism.elements;
			data->service = gd32.service;
			bcopy(gd32.uname, data->uname, sizeof (gd32.uname));
			bcopy(gd32.inst, data->inst, sizeof (gd32.inst));
			bcopy(gd32.realm, data->realm, sizeof (gd32.realm));
			data->qop = gd32.qop;
		}
	} else
#endif /* _SYSCALL32_IMPL */
	if (copyin(usrdata, data, sizeof (*data)))
		error = EFAULT;

	if (error == 0) {
		if (data->mechanism.length > 0) {
			elements = kmem_alloc(data->mechanism.length, KM_SLEEP);
			if (!(copyin(data->mechanism.elements, elements,
			    data->mechanism.length))) {
				data->mechanism.elements = elements;
				*kdata = (caddr_t)data;
				return (0);
			} else
				kmem_free(elements, data->mechanism.length);
		}
	} else {
		*kdata = NULL;
		kmem_free(data, sizeof (*data));
	}
	return (EFAULT);
}


/*
 *  Load AUTH_DES specific data from user space to kernel space.
 */
/*ARGSUSED2*/
int
dh_k4_clnt_loadinfo(caddr_t usrdata, caddr_t *kdata, model_t model)
{
	size_t nlen;
	int error = 0;
	char *userbufptr;
	dh_k4_clntdata_t *data;
	char netname[MAXNETNAMELEN+1];
	struct netbuf *syncaddr;
	struct knetconfig *knconf;

	/* map opaque data to des specific strucutre */
	data = kmem_alloc(sizeof (*data), KM_SLEEP);

#ifdef _SYSCALL32_IMPL
	if (model != DATAMODEL_NATIVE) {
		struct des_clnt_data32 data32;

		if (copyin(usrdata, &data32, sizeof (data32)) == -1) {
			error = EFAULT;
		} else {
			data->syncaddr.maxlen = data32.syncaddr.maxlen;
			data->syncaddr.len = data32.syncaddr.len;
			data->syncaddr.buf =
			    (caddr_t)(uintptr_t)data32.syncaddr.buf;
			data->knconf =
			    (struct knetconfig *)(uintptr_t)data32.knconf;
			data->netname = (caddr_t)(uintptr_t)data32.netname;
			data->netnamelen = data32.netnamelen;
		}
	} else
#endif /* _SYSCALL32_IMPL */
	if (copyin(usrdata, data, sizeof (*data)))
		error = EFAULT;

	if (error == 0) {
		syncaddr = &data->syncaddr;
		if (syncaddr == NULL)
			error = EINVAL;
		else {
			userbufptr = syncaddr->buf;
			syncaddr->buf =  kmem_alloc(syncaddr->len, KM_SLEEP);
			syncaddr->maxlen = syncaddr->len;
			if (copyin(userbufptr, syncaddr->buf, syncaddr->len)) {
				kmem_free(syncaddr->buf, syncaddr->len);
				syncaddr->buf = NULL;
				error = EFAULT;
			} else {
				(void) copyinstr(data->netname, netname,
				    sizeof (netname), &nlen);
				if (nlen != 0) {
					data->netname =
					    kmem_alloc(nlen, KM_SLEEP);
					bcopy(netname, data->netname, nlen);
					data->netnamelen = (int)nlen;
				}
			}
		}
	}

	if (!error) {
		/*
		 * Allocate space for a knetconfig structure and
		 * its strings and copy in from user-land.
		 */
		knconf = kmem_alloc(sizeof (*knconf), KM_SLEEP);
#ifdef _SYSCALL32_IMPL
		if (model != DATAMODEL_NATIVE) {
			struct knetconfig32 knconf32;

			if (copyin(data->knconf, &knconf32,
			    sizeof (knconf32)) == -1) {
				kmem_free(knconf, sizeof (*knconf));
				kmem_free(syncaddr->buf, syncaddr->len);
				syncaddr->buf = NULL;
				kmem_free(data->netname, nlen);
				error = EFAULT;
			} else {
				knconf->knc_semantics = knconf32.knc_semantics;
				knconf->knc_protofmly =
				    (caddr_t)(uintptr_t)knconf32.knc_protofmly;
				knconf->knc_proto =
				    (caddr_t)(uintptr_t)knconf32.knc_proto;
				knconf->knc_rdev = expldev(knconf32.knc_rdev);
			}
		} else
#endif /* _SYSCALL32_IMPL */
		if (copyin(data->knconf, knconf, sizeof (*knconf))) {
			kmem_free(knconf, sizeof (*knconf));
			kmem_free(syncaddr->buf, syncaddr->len);
			syncaddr->buf = NULL;
			kmem_free(data->netname, nlen);
			error = EFAULT;
		}
	}

	if (!error) {
		size_t nmoved_tmp;
		char *p, *pf;

		pf = kmem_alloc(KNC_STRSIZE, KM_SLEEP);
		p = kmem_alloc(KNC_STRSIZE, KM_SLEEP);
		error = copyinstr(knconf->knc_protofmly, pf,
		    KNC_STRSIZE, &nmoved_tmp);
		if (error) {
			kmem_free(pf, KNC_STRSIZE);
			kmem_free(p, KNC_STRSIZE);
			kmem_free(knconf, sizeof (*knconf));
			kmem_free(syncaddr->buf, syncaddr->len);
			kmem_free(data->netname, nlen);
		}

		if (!error) {
			error = copyinstr(knconf->knc_proto,
			    p, KNC_STRSIZE, &nmoved_tmp);
			if (error) {
				kmem_free(pf, KNC_STRSIZE);
				kmem_free(p, KNC_STRSIZE);
				kmem_free(knconf, sizeof (*knconf));
				kmem_free(syncaddr->buf, syncaddr->len);
				kmem_free(data->netname, nlen);
			}
		}

		if (!error) {
			knconf->knc_protofmly = pf;
			knconf->knc_proto = p;
		}
	}

	if (error) {
		*kdata = NULL;
		kmem_free(data, sizeof (*data));
		return (error);
	}

	data->knconf = knconf;
	*kdata = (caddr_t)data;
	return (0);
}

/*
 *  Free up AUTH_DES specific data.
 */
void
dh_k4_clnt_freeinfo(caddr_t cdata)
{
	dh_k4_clntdata_t *data;

	data = (dh_k4_clntdata_t *)cdata;
	if (data->netnamelen > 0) {
		kmem_free(data->netname, data->netnamelen);
	}
	if (data->syncaddr.buf != NULL) {
		kmem_free(data->syncaddr.buf, data->syncaddr.len);
	}
	if (data->knconf != NULL) {
		kmem_free(data->knconf->knc_protofmly, KNC_STRSIZE);
		kmem_free(data->knconf->knc_proto, KNC_STRSIZE);
		kmem_free(data->knconf, sizeof (*data->knconf));
	}

	kmem_free(data, sizeof (*data));
}

/*
 *  Load application auth related data from user land to kernel.
 *  Map opaque data field to dh_k4_clntdata_t for AUTH_DES
 *
 */
int
sec_clnt_loadinfo(struct sec_data *in, struct sec_data **out, model_t model)
{
	struct	sec_data	*secdata;
	int	error = 0;

	secdata = kmem_alloc(sizeof (*secdata), KM_SLEEP);

#ifdef _SYSCALL32_IMPL
	if (model != DATAMODEL_NATIVE) {
		struct sec_data32 sd32;

		if (copyin(in, &sd32, sizeof (sd32)) == -1) {
			error = EFAULT;
		} else {
			secdata->secmod = sd32.secmod;
			secdata->rpcflavor = sd32.rpcflavor;
			secdata->uid = sd32.uid;
			secdata->flags = sd32.flags;
			secdata->data = (caddr_t)(uintptr_t)sd32.data;
		}
	} else
#endif /* _SYSCALL32_IMPL */

	if (copyin(in, secdata, sizeof (*secdata)) == -1) {
		error = EFAULT;
	}
	/*
	 * Copy in opaque data field per flavor.
	 */
	if (!error) {
		switch (secdata->rpcflavor) {
		case AUTH_NONE:
		case AUTH_UNIX:
		case AUTH_LOOPBACK:
			break;

		case AUTH_DES:
			error = dh_k4_clnt_loadinfo(secdata->data,
			    &secdata->data, model);
			break;

		case RPCSEC_GSS:
			error = gss_clnt_loadinfo(secdata->data,
			    &secdata->data, model);
			break;

		default:
			error = EINVAL;
			break;
		}
	}

	if (!error) {
		*out = secdata;
	} else {
		kmem_free(secdata, sizeof (*secdata));
		*out = (struct sec_data *)NULL;
	}

	return (error);
}

/*
 * Null the sec_data index in the cache table, and
 * free the memory allocated by sec_clnt_loadinfo.
 */
void
sec_clnt_freeinfo(struct sec_data *secdata)
{
	switch (secdata->rpcflavor) {
	case AUTH_DES:
		purge_authtab(secdata);
		if (secdata->data)
			dh_k4_clnt_freeinfo(secdata->data);
		break;

	case RPCSEC_GSS:
		rpc_gss_secpurge((void *)secdata);
		if (secdata->data) {
			gss_clntdata_t *gss_data;

			gss_data = (gss_clntdata_t *)secdata->data;
			if (gss_data->mechanism.elements) {
				kmem_free(gss_data->mechanism.elements,
				    gss_data->mechanism.length);
			}
			kmem_free(secdata->data, sizeof (gss_clntdata_t));
		}
		break;

	case AUTH_NONE:
	case AUTH_UNIX:
	case AUTH_LOOPBACK:
	default:
		break;
	}
	kmem_free(secdata, sizeof (*secdata));
}

/*
 *  Get an AUTH handle for a RPC client based on the given sec_data.
 *  If an AUTH handle exists for the same sec_data, use that AUTH handle,
 *  otherwise create a new one.
 */
int
sec_clnt_geth(CLIENT *client, struct sec_data *secdata, cred_t *cr, AUTH **ap)
{
	int i;
	struct desauthent *da;
	int authflavor;
	cred_t *savecred;
	int stat;			/* return (errno) status */
	char gss_svc_name[MAX_GSS_NAME];
	dh_k4_clntdata_t	*desdata;
	AUTH *auth;
	gss_clntdata_t *gssdata;
	zoneid_t zoneid = getzoneid();

	if ((client == NULL) || (secdata == NULL) || (ap == NULL))
		return (EINVAL);
	*ap = (AUTH *)NULL;

	authflavor = secdata->rpcflavor;
	for (;;) {
		int nlen;
		char *netname;

		switch (authflavor) {
		case AUTH_NONE:
			/*
			 * XXX: should do real AUTH_NONE, instead of AUTH_UNIX
			 */
		case AUTH_UNIX:
			*ap = (AUTH *) authkern_create();
			return ((*ap != NULL) ? 0 : EINTR);

		case AUTH_LOOPBACK:
			*ap = (AUTH *) authloopback_create();
			return ((*ap != NULL) ? 0 : EINTR);

		case AUTH_DES:
			mutex_enter(&desauthtab_lock);
			if (desauthtab == NULL) {
				desauthtab = kmem_zalloc(clnt_authdes_cachesz *
				    sizeof (struct desauthent), KM_SLEEP);
			}
			for (da = desauthtab;
			    da < &desauthtab[clnt_authdes_cachesz];
			    da++) {
				if (da->da_data == secdata &&
				    da->da_uid == crgetuid(cr) &&
				    da->da_zoneid == zoneid &&
				    !da->da_inuse &&
				    da->da_auth != NULL) {
					da->da_inuse = 1;
					mutex_exit(&desauthtab_lock);
					*ap = da->da_auth;
					return (0);
				}
			}
			mutex_exit(&desauthtab_lock);

			/*
			 *  A better way would be to have a cred paramater to
			 *  authdes_create.
			 */
			savecred = curthread->t_cred;
			curthread->t_cred = cr;

			/*
			 * Note that authdes_create() expects a
			 * NUL-terminated string for netname, but
			 * dh_k4_clntdata_t gives us netname & netnamelen.
			 *
			 * We must create a string for authdes_create();
			 * the latter takes a copy of it, so we may
			 * immediately free it.
			 */
			desdata = (dh_k4_clntdata_t *)secdata->data;
			nlen = desdata->netnamelen;
			/* must be NUL-terminated */
			netname = kmem_zalloc(nlen + 1, KM_SLEEP);
			bcopy(desdata->netname, netname, nlen);
			stat = authdes_create(netname, authdes_win,
			    &desdata->syncaddr, desdata->knconf,
			    (des_block *)NULL,
			    (secdata->flags & AUTH_F_RPCTIMESYNC) ? 1 : 0,
			    &auth);
			kmem_free(netname, nlen + 1);

			curthread->t_cred = savecred;
			*ap = auth;

			if (stat != 0) {
				/*
				 *  If AUTH_F_TRYNONE is on, try again
				 *  with AUTH_NONE.  See bug 1180236.
				 */
				if (secdata->flags & AUTH_F_TRYNONE) {
					authflavor = AUTH_NONE;
					continue;
				} else
					return (stat);
			}

			i = clnt_authdes_cachesz;
			mutex_enter(&desauthtab_lock);
			do {
				da = &desauthtab[nextdesvictim++];
				nextdesvictim %= clnt_authdes_cachesz;
			} while (da->da_inuse && --i > 0);

			if (da->da_inuse) {
				mutex_exit(&desauthtab_lock);
				/* overflow of des auths */
				return (stat);
			}
			da->da_inuse = 1;
			mutex_exit(&desauthtab_lock);

			if (da->da_auth != NULL)
				auth_destroy(da->da_auth);

			da->da_auth = auth;
			da->da_uid = crgetuid(cr);
			da->da_zoneid = zoneid;
			da->da_data = secdata;
			return (stat);

		case RPCSEC_GSS:
			/*
			 *  For RPCSEC_GSS, cache is done in rpc_gss_secget().
			 *  For every rpc_gss_secget(),  it should have
			 *  a corresponding rpc_gss_secfree() call.
			 */
			gssdata = (gss_clntdata_t *)secdata->data;
			(void) sprintf(gss_svc_name, "%s@%s", gssdata->uname,
			    gssdata->inst);

			stat = rpc_gss_secget(client, gss_svc_name,
			    &gssdata->mechanism,
			    gssdata->service,
			    gssdata->qop,
			    NULL, NULL,
			    (caddr_t)secdata, cr, &auth);
			*ap = auth;

			/* success */
			if (stat == 0)
				return (stat);

			/*
			 * let the caller retry if connection timedout
			 * or reset.
			 */
			if (stat == ETIMEDOUT || stat == ECONNRESET)
				return (stat);

			/*
			 *  If AUTH_F_TRYNONE is on, try again
			 *  with AUTH_NONE.  See bug 1180236.
			 */
			if (secdata->flags & AUTH_F_TRYNONE) {
				authflavor = AUTH_NONE;
				continue;
			}

			RPCLOG(1, "sec_clnt_geth: rpc_gss_secget"
			    " failed with %d", stat);
			return (stat);

		default:
			/*
			 * auth create must have failed, try AUTH_NONE
			 * (this relies on AUTH_NONE never failing)
			 */
			cmn_err(CE_NOTE, "sec_clnt_geth: unknown "
			    "authflavor %d, trying AUTH_NONE", authflavor);
			authflavor = AUTH_NONE;
		}
	}
}

void
sec_clnt_freeh(AUTH *auth)
{
	struct desauthent *da;

	switch (auth->ah_cred.oa_flavor) {
	case AUTH_NONE: /* XXX: do real AUTH_NONE */
	case AUTH_UNIX:
	case AUTH_LOOPBACK:
		auth_destroy(auth);	/* was overflow */
		break;

	case AUTH_DES:
		mutex_enter(&desauthtab_lock);
		if (desauthtab != NULL) {
			for (da = desauthtab;
			    da < &desauthtab[clnt_authdes_cachesz]; da++) {
				if (da->da_auth == auth) {
					da->da_inuse = 0;
					mutex_exit(&desauthtab_lock);
					return;
				}
			}
		}
		mutex_exit(&desauthtab_lock);
		auth_destroy(auth);	/* was overflow */
		break;

	case RPCSEC_GSS:
		(void) rpc_gss_secfree(auth);
		break;

	default:
		cmn_err(CE_NOTE, "sec_clnt_freeh: unknown authflavor %d",
		    auth->ah_cred.oa_flavor);
		break;
	}
}

/*
 *  Revoke the authentication key in the given AUTH handle by setting
 *  it to NULL.  If newkey is true, then generate a new key instead of
 *  nulling out the old one.  This is necessary for AUTH_DES because
 *  the new key will be used next time the user does a keylogin.  If
 *  the zero'd key is used as actual key, then it cannot be revoked
 *  again!
 */
void
revoke_key(AUTH *auth, int newkey)
{
	if (auth == NULL)
		return;

	if (newkey) {
		if (key_gendes(&auth->ah_key) != RPC_SUCCESS) {
			/* failed to get new key, munge the old one */
			auth->ah_key.key.high ^= auth->ah_key.key.low;
			auth->ah_key.key.low  += auth->ah_key.key.high;
		}
	} else {
		/* null out old key */
		auth->ah_key.key.high = 0;
		auth->ah_key.key.low  = 0;
	}
}

/*
 *  Revoke all rpc credentials (of the selected auth type) for the given uid
 *  from the auth cache.  Must be root to do this if the requested uid is not
 *  the effective uid of the requestor.
 *
 *  Called from nfssys() for backward compatibility, and also
 *  called from krpc_sys().
 *
 *  AUTH_DES does not refer to the "mechanism" information.
 *  RPCSEC_GSS requires the "mechanism" input.
 *  The input argument, mechanism, is a user-space address and needs
 *  to be copied into the kernel address space.
 *
 *  Returns error number.
 */
/*ARGSUSED*/
int
sec_clnt_revoke(int rpcflavor, uid_t uid, cred_t *cr, void *mechanism,
						model_t model)
{
	struct desauthent *da;
	int error = 0;
	zoneid_t zoneid = getzoneid();

	if (uid != crgetuid(cr) && secpolicy_nfs(cr) != 0)
		return (EPERM);

	switch (rpcflavor) {
	case AUTH_DES:
		mutex_enter(&desauthtab_lock);
		if (desauthtab != NULL) {
			for (da = desauthtab;
			    da < &desauthtab[clnt_authdes_cachesz]; da++) {
				if (uid == da->da_uid &&
				    zoneid == da->da_zoneid)
					revoke_key(da->da_auth, 1);
			}
		}
		mutex_exit(&desauthtab_lock);
		return (0);

	case RPCSEC_GSS: {
		rpc_gss_OID	mech;
		caddr_t		elements;

		if (!mechanism)
			return (EINVAL);

		/* copyin the gss mechanism type */
		mech = kmem_alloc(sizeof (rpc_gss_OID_desc), KM_SLEEP);
#ifdef _SYSCALL32_IMPL
		if (model != DATAMODEL_NATIVE) {
			gss_OID_desc32 mech32;

			if (copyin(mechanism, &mech32,
			    sizeof (gss_OID_desc32))) {
				kmem_free(mech, sizeof (rpc_gss_OID_desc));
				return (EFAULT);
			}
			mech->length = mech32.length;
			mech->elements = (caddr_t)(uintptr_t)mech32.elements;
		} else
#endif /* _SYSCALL32_IMPL */
		if (copyin(mechanism, mech, sizeof (rpc_gss_OID_desc))) {
			kmem_free(mech, sizeof (rpc_gss_OID_desc));
			return (EFAULT);
		}

		elements = kmem_alloc(mech->length, KM_SLEEP);
		if (copyin(mech->elements, elements, mech->length)) {
			kmem_free(elements, mech->length);
			kmem_free(mech, sizeof (rpc_gss_OID_desc));
			return (EFAULT);
		}
		mech->elements = elements;

		error = rpc_gss_revauth(uid, mech);

		kmem_free(elements, mech->length);
		kmem_free(mech, sizeof (rpc_gss_OID_desc));

		return (error);
	}

	default:
		/* not an auth type with cached creds */
		return (EINVAL);
	}
}

/*
 *  Since sec_data is the index for the client auth handles
 *  cache table,  whenever the sec_data is freed, the index needs
 *  to be nulled.
 */
void
purge_authtab(struct sec_data *secdata)
{
	struct desauthent *da;

	switch (secdata->rpcflavor) {

	case AUTH_DES:
		mutex_enter(&desauthtab_lock);
		if (desauthtab != NULL) {
			for (da = desauthtab;
			    da < &desauthtab[clnt_authdes_cachesz]; da++) {
				if (da->da_data == secdata) {
					da->da_data = NULL;
					da->da_inuse = 0;
				}
			}
		}
		mutex_exit(&desauthtab_lock);
		return;

	case RPCSEC_GSS:
		rpc_gss_secpurge((void *)secdata);
		return;

	default:
		return;
	}
}

void
sec_subrinit(void)
{
	authkern_cache = kmem_cache_create("authkern_cache",
	    sizeof (AUTH), 0, authkern_init, NULL, NULL, NULL, NULL, 0);
	authloopback_cache = kmem_cache_create("authloopback_cache",
	    sizeof (AUTH), 0, authloopback_init, NULL, NULL, NULL, NULL, 0);
	mutex_init(&desauthtab_lock, NULL, MUTEX_DEFAULT, NULL);

	/* RPC stuff */
	mutex_init(&authdes_ops_lock, NULL, MUTEX_DEFAULT, NULL);
	zone_key_create(&auth_zone_key, auth_zone_init, NULL, auth_zone_fini);
}

/*
 * Destroys the caches and mutexes previously allocated and initialized
 * in sec_subrinit().
 * This routine is called by _init() if mod_install() failed.
 */
void
sec_subrfini(void)
{
	mutex_destroy(&desauthtab_lock);
	kmem_cache_destroy(authkern_cache);
	kmem_cache_destroy(authloopback_cache);

	/* RPC stuff */
	mutex_destroy(&authdes_ops_lock);
	(void) zone_key_delete(auth_zone_key);
}
