/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/param.h>
#include <sys/errno.h>
#include <sys/vfs.h>
#include <sys/vnode.h>
#include <sys/cred.h>
#include <sys/cmn_err.h>
#include <sys/systm.h>
#include <sys/kmem.h>
#include <sys/pathname.h>
#include <sys/utsname.h>
#include <sys/debug.h>

#include <rpc/types.h>
#include <rpc/auth.h>
#include <rpc/clnt.h>

#include <nfs/nfs.h>
#include <nfs/export.h>
#include <nfs/nfs_clnt.h>
#include <rpcsvc/nfsauth_prot.h>

#define	EQADDR(a1, a2)  \
	(bcmp((char *)(a1)->buf, (char *)(a2)->buf, (a1)->len) == 0 && \
	(a1)->len == (a2)->len)

static struct knetconfig auth_knconf;
static servinfo_t svp;
static clinfo_t ci;

static struct kmem_cache *exi_cache_handle;
static void exi_cache_reclaim(void *);
static void exi_cache_trim(struct exportinfo *exi);

int nfsauth_cache_hit;
int nfsauth_cache_miss;
int nfsauth_cache_reclaim;

/*
 * Number of seconds to wait for an NFSAUTH upcall.
 */
static int nfsauth_timeout = 20;

void
nfsauth_init(void)
{
	vnode_t *kvp;
	int error;
	char addrbuf[SYS_NMLN+16];

	/*
	 * Setup netconfig.
	 * Assume a connectionless loopback transport.
	 */
	if ((error = lookupname("/dev/ticotsord", UIO_SYSSPACE, FOLLOW,
		NULLVPP, &kvp)) != 0) {
		cmn_err(CE_CONT, "nfsauth: lookupname: %d\n", error);
		return;
	}

	auth_knconf.knc_rdev = kvp->v_rdev;
	auth_knconf.knc_protofmly = NC_LOOPBACK;
	auth_knconf.knc_semantics = NC_TPI_COTS_ORD;
	VN_RELE(kvp);

	(void) strcpy(addrbuf, utsname.nodename);
	(void) strcat(addrbuf, ".nfsauth");

	svp.sv_knconf = &auth_knconf;
	svp.sv_addr.buf = kmem_alloc(strlen(addrbuf)+1, KM_SLEEP);
	(void) strcpy(svp.sv_addr.buf, addrbuf);
	svp.sv_addr.len = (uint_t)strlen(addrbuf);
	svp.sv_addr.maxlen = svp.sv_addr.len;
	svp.sv_secdata = kmem_alloc(sizeof (struct sec_data), KM_SLEEP);
	svp.sv_secdata->rpcflavor = AUTH_LOOPBACK;
	svp.sv_secdata->data = NULL;

	ci.cl_prog = NFSAUTH_PROG;
	ci.cl_vers = NFSAUTH_VERS;
	ci.cl_readsize = 0;
	ci.cl_retrans = 1;
	ci.cl_flags = 0x0;

	/*
	 * Allocate nfsauth cache handle
	 */
	exi_cache_handle = kmem_cache_create("exi_cache_handle",
		sizeof (struct auth_cache), 0, NULL, NULL,
		exi_cache_reclaim, NULL, NULL, 0);
}

/*
 * Finalization routine for nfsauth. It is important to call this routine
 * before destroying the exported_lock.
 */
void
nfsauth_fini(void)
{
	/*
	 * Deallocate nfsauth cache handle
	 */
	kmem_cache_destroy(exi_cache_handle);
}

static int
nfsauth_clget(CLIENT **newcl, struct chtab **chp)
{
	return (clget(&ci, &svp, CRED(), newcl, chp));
}

/*
 * Convert the address in a netbuf to
 * a hash index for the auth_cache table.
 */
static int
hash(struct netbuf *a)
{
	int i, h = 0;

	for (i = 0; i < a->len; i++)
		h ^= a->buf[i];

	return (h & (AUTH_TABLESIZE - 1));
}

/*
 * Mask out the components of an
 * address that do not identify
 * a host. For socket addresses the
 * masking gets rid of the port number.
 */
static void
addrmask(struct netbuf *addr, struct netbuf *mask)
{
	int i;

	for (i = 0; i < addr->len; i++)
		addr->buf[i] &= mask->buf[i];
}

/*
 * nfsauth4_access is used for NFS V4 auth checking. Besides doing
 * the common nfsauth_access(), it will check if the client can
 * have a limited access to this vnode even if the security flavor
 * used does not meet the policy.
 */
int
nfsauth4_access(struct exportinfo *exi, vnode_t *vp, struct svc_req *req)
{
	int access;

	access = nfsauth_access(exi, req);

	/*
	 * There are cases that the server needs to allow the client
	 * to have a limited view.
	 *
	 * e.g.
	 * /export is shared as "sec=sys,rw=dfs-test-4,sec=krb5,rw"
	 * /export/home is shared as "sec=sys,rw"
	 *
	 * When the client mounts /export with sec=sys, the client
	 * would get a limited view with RO access on /export to see
	 * "home" only because the client is allowed to access
	 * /export/home with auth_sys.
	 */
	if (access & NFSAUTH_DENIED || access & NFSAUTH_WRONGSEC) {
		/*
		 * Allow ro permission with LIMITED view if there is a
		 * sub-dir exported under vp.
		 */
		if (has_visible(exi, vp)) {
			return (NFSAUTH_LIMITED);
		}
	}

	return (access);
}

/*
 * Get the access information from the cache or callup to the mountd
 * to get and cache the access information in the kernel.
 */
int
nfsauth_cache_get(struct exportinfo *exi, struct svc_req *req, int flavor)
{
	struct netbuf addr, *claddr;
	struct auth_cache **head, *ap;
	CLIENT *clnt;
	struct chtab *ch;
	struct auth_req request;
	struct auth_res result;
	enum clnt_stat rpcstat;
	int access;
	struct timeval timout;
	static time_t exi_msg = 0;
	time_t now;

	/*
	 * Now check whether this client already
	 * has an entry for this flavor in the cache
	 * for this export.
	 * Get the caller's address, mask off the
	 * parts of the address that do not identify
	 * the host (port number, etc), and then hash
	 * it to find the chain of cache entries.
	 */

	claddr = svc_getrpccaller(req->rq_xprt);
	addr = *claddr;
	addr.buf = mem_alloc(addr.len);
	bcopy(claddr->buf, addr.buf, claddr->len);
	addrmask(&addr, svc_getaddrmask(req->rq_xprt));
	head = &exi->exi_cache[hash(&addr)];

	rw_enter(&exi->exi_cache_lock, RW_READER);
	for (ap = *head; ap; ap = ap->auth_next) {
		if (EQADDR(&addr, &ap->auth_addr) && flavor == ap->auth_flavor)
			break;
	}
	if (ap) {				/* cache hit */
		access = ap->auth_access;
		ap->auth_time = gethrestime_sec();
		nfsauth_cache_hit++;
	}

	rw_exit(&exi->exi_cache_lock);

	if (ap) {
		kmem_free(addr.buf, addr.len);
		return (access);
	}

	nfsauth_cache_miss++;

	/*
	 * No entry in the cache for this client/flavor
	 * so we need to call the nfsauth service in the
	 * mount daemon.
	 */

	if (nfsauth_clget(&clnt, &ch)) {
		kmem_free(addr.buf, addr.len);
		return (NFSAUTH_DROP);
	}

	timout.tv_sec = nfsauth_timeout;
	timout.tv_usec = 0;

	request.req_client.n_len = addr.len;
	request.req_client.n_bytes = addr.buf;
	request.req_netid = svc_getnetid(req->rq_xprt);
	request.req_path = exi->exi_export.ex_path;
	request.req_flavor = flavor;

	rpcstat = clnt_call(clnt, NFSAUTH_ACCESS,
		(xdrproc_t)xdr_auth_req, (caddr_t)&request,
		(xdrproc_t)xdr_auth_res, (caddr_t)&result,
		timout);

	switch (rpcstat) {
	case RPC_SUCCESS:
		access = result.auth_perm;
		break;
	case RPC_INTR:
		break;
	case RPC_TIMEDOUT:
		/*
		 * Show messages no more than once per minute
		 */
		now = gethrestime_sec();
		if ((exi_msg + 60) < now) {
			exi_msg = now;
			cmn_err(CE_WARN, "nfsauth: mountd not responding");
		}
		break;
	default:
		/*
		 * Show messages no more than once per minute
		 */
		now = gethrestime_sec();
		if ((exi_msg + 60) < now) {
			char *errmsg;

			exi_msg = now;
			errmsg = clnt_sperror(clnt, "nfsauth upcall failed");
			cmn_err(CE_WARN, errmsg);
			kmem_free(errmsg, MAXPATHLEN);
		}
		break;
	}

	clfree(clnt, ch);
	if (rpcstat != RPC_SUCCESS) {
		kmem_free(addr.buf, addr.len);
		return (NFSAUTH_DROP);
	}

	/*
	 * Now cache the result on the cache chain
	 * for this export (if there's enough memory)
	 */
	ap = kmem_cache_alloc(exi_cache_handle, KM_NOSLEEP);
	if (ap) {
		ap->auth_addr = addr;
		ap->auth_flavor = flavor;
		ap->auth_access = access;
		ap->auth_time = gethrestime_sec();
		rw_enter(&exi->exi_cache_lock, RW_WRITER);
		ap->auth_next = *head;
		*head = ap;
		rw_exit(&exi->exi_cache_lock);
	} else {
		kmem_free(addr.buf, addr.len);
	}

	return (access);
}

/*
 * Check if the requesting client has access to the filesystem with
 * a given nfs flavor number which is an explicitly shared flavor.
 */
int
nfsauth4_secinfo_access(struct exportinfo *exi, struct svc_req *req,
			int flavor, int perm)
{
	int access;

	if (! (perm & M_4SEC_EXPORTED)) {
		return (NFSAUTH_DENIED);
	}

	/*
	 * Optimize if there are no lists
	 */
	if ((perm & M_ROOT) == 0) {
		perm &= ~M_4SEC_EXPORTED;
		if (perm == M_RO)
			return (NFSAUTH_RO);
		if (perm == M_RW)
			return (NFSAUTH_RW);
	}

	access = nfsauth_cache_get(exi, req, flavor);

	return (access);
}

int
nfsauth_access(struct exportinfo *exi, struct svc_req *req)
{
	int access, mapaccess;
	struct secinfo *sp;
	int i, flavor, perm;
	int authnone_entry = -1;

	/*
	 *  Get the nfs flavor number from xprt.
	 */
	flavor = (int)(uintptr_t)req->rq_xprt->xp_cookie;

	/*
	 * First check the access restrictions on the filesystem.  If
	 * there are no lists associated with this flavor then there's no
	 * need to make an expensive call to the nfsauth service or to
	 * cache anything.
	 */

	sp = exi->exi_export.ex_secinfo;
	for (i = 0; i < exi->exi_export.ex_seccnt; i++) {
		if (flavor != sp[i].s_secinfo.sc_nfsnum) {
			if (sp[i].s_secinfo.sc_nfsnum == AUTH_NONE)
				authnone_entry = i;
			continue;
		}
		break;
	}

	mapaccess = 0;

	if (i >= exi->exi_export.ex_seccnt) {
		/*
		 * Flavor not found, but use AUTH_NONE if it exists
		 */
		if (authnone_entry == -1)
			return (NFSAUTH_DENIED);
		flavor = AUTH_NONE;
		mapaccess = NFSAUTH_MAPNONE;
		i = authnone_entry;
	}

	/*
	 * If the flavor is in the ex_secinfo list, but not an explicitly
	 * shared flavor by the user, it is a result of the nfsv4 server
	 * namespace setup. We will grant an RO permission similar for
	 * a pseudo node except that this node is a shared one.
	 *
	 * e.g. flavor in (flavor) indicates that it is not explictly
	 *	shared by the user:
	 *
	 *		/	(sys, krb5)
	 *		|
	 *		export  #share -o sec=sys (krb5)
	 *		|
	 *		secure  #share -o sec=krb5
	 *
	 *	In this case, when a krb5 request coming in to access
	 *	/export, RO permission is granted.
	 */
	if (!(sp[i].s_flags & M_4SEC_EXPORTED))
		return (mapaccess | NFSAUTH_RO);

	/*
	 * Optimize if there are no lists
	 */
	perm = sp[i].s_flags;
	if ((perm & M_ROOT) == 0) {
		perm &= ~M_4SEC_EXPORTED;
		if (perm == M_RO)
			return (mapaccess | NFSAUTH_RO);
		if (perm == M_RW)
			return (mapaccess | NFSAUTH_RW);
	}

	access = nfsauth_cache_get(exi, req, flavor);

	return (access | mapaccess);
}

/*
 * Free the nfsauth cache for a given export
 */
void
nfsauth_cache_free(struct exportinfo *exi)
{
	int i;
	struct auth_cache *p, *next;

	for (i = 0; i < AUTH_TABLESIZE; i++) {
		for (p = exi->exi_cache[i]; p; p = next) {
			kmem_free(p->auth_addr.buf, p->auth_addr.len);
			next = p->auth_next;
			kmem_cache_free(exi_cache_handle, (void *)p);
		}
	}
}

/*
 * Called by the kernel memory allocator when
 * memory is low. Free unused cache entries.
 * If that's not enough, the VM system will
 * call again for some more.
 */
/*ARGSUSED*/
void
exi_cache_reclaim(void *cdrarg)
{
	int i;
	struct exportinfo *exi;

	rw_enter(&exported_lock, RW_READER);

	for (i = 0; i < EXPTABLESIZE; i++) {
		for (exi = exptable[i]; exi; exi = exi->exi_hash) {
			exi_cache_trim(exi);
		}
	}
	nfsauth_cache_reclaim++;

	rw_exit(&exported_lock);
}

/*
 * Don't reclaim entries until they've been
 * in the cache for at least exi_cache_time
 * seconds.
 */
time_t exi_cache_time = 60 * 60;

void
exi_cache_trim(struct exportinfo *exi)
{
	struct auth_cache *p;
	struct auth_cache *prev, *next;
	int i;
	time_t stale_time;

	stale_time = gethrestime_sec() - exi_cache_time;

	rw_enter(&exi->exi_cache_lock, RW_WRITER);

	for (i = 0; i < AUTH_TABLESIZE; i++) {

		/*
		 * Free entries that have not been
		 * used for exi_cache_time seconds.
		 */
		prev = NULL;
		for (p = exi->exi_cache[i]; p; p = next) {
			next = p->auth_next;
			if (p->auth_time > stale_time) {
				prev = p;
				continue;
			}

			kmem_free(p->auth_addr.buf, p->auth_addr.len);
			kmem_cache_free(exi_cache_handle, (void *)p);
			if (prev == NULL)
				exi->exi_cache[i] = next;
			else
				prev->auth_next = next;
		}
	}

	rw_exit(&exi->exi_cache_lock);
}
