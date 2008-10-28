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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

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
#include <sys/door.h>
#include <sys/sdt.h>

#include <rpc/types.h>
#include <rpc/auth.h>
#include <rpc/clnt.h>

#include <nfs/nfs.h>
#include <nfs/export.h>
#include <nfs/nfs_clnt.h>
#include <nfs/auth.h>

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

/*
 * mountd is a server-side only daemon. This will need to be
 * revisited if the NFS server is ever made zones-aware.
 */
kmutex_t	mountd_lock;
door_handle_t   mountd_dh;

void
mountd_args(uint_t did)
{
	mutex_enter(&mountd_lock);
	if (mountd_dh)
		door_ki_rele(mountd_dh);
	mountd_dh = door_ki_lookup(did);
	mutex_exit(&mountd_lock);
}

void
nfsauth_init(void)
{
	/*
	 * mountd can be restarted by smf(5). We need to make sure
	 * the updated door handle will safely make it to mountd_dh
	 */
	mutex_init(&mountd_lock, NULL, MUTEX_DEFAULT, NULL);

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
		if (has_visible(exi, vp))
			return (NFSAUTH_LIMITED);
	}

	return (access);
}

static void
sys_log(const char *msg)
{
	static time_t	tstamp = 0;
	time_t		now;

	/*
	 * msg is shown (at most) once per minute
	 */
	now = gethrestime_sec();
	if ((tstamp + 60) < now) {
		tstamp = now;
		cmn_err(CE_WARN, msg);
	}
}

/*
 * Get the access information from the cache or callup to the mountd
 * to get and cache the access information in the kernel.
 */
int
nfsauth_cache_get(struct exportinfo *exi, struct svc_req *req, int flavor)
{
	struct netbuf		  addr;
	struct netbuf		 *claddr;
	struct auth_cache	**head;
	struct auth_cache	 *ap;
	int			  access;
	varg_t			  varg = {0};
	nfsauth_res_t		  res = {0};
	XDR			  xdrs_a;
	XDR			  xdrs_r;
	size_t			  absz;
	caddr_t			  abuf;
	size_t			  rbsz = (size_t)(BYTES_PER_XDR_UNIT * 2);
	char			  result[BYTES_PER_XDR_UNIT * 2] = {0};
	caddr_t			  rbuf = (caddr_t)&result;
	int			  last = 0;
	door_arg_t		  da;
	door_info_t		  di;
	door_handle_t		  dh;
	uint_t			  ntries = 0;

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
	addr.buf = kmem_alloc(addr.len, KM_SLEEP);
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
retry:
	mutex_enter(&mountd_lock);
	dh = mountd_dh;
	if (dh)
		door_ki_hold(dh);
	mutex_exit(&mountd_lock);

	if (dh == NULL) {
		/*
		 * The rendezvous point has not been established yet !
		 * This could mean that either mountd(1m) has not yet
		 * been started or that _this_ routine nuked the door
		 * handle after receiving an EINTR for a REVOKED door.
		 *
		 * Returning NFSAUTH_DROP will cause the NFS client
		 * to retransmit the request, so let's try to be more
		 * rescillient and attempt for ntries before we bail.
		 */
		if (++ntries % NFSAUTH_DR_TRYCNT) {
			delay(hz);
			goto retry;
		}
		sys_log("nfsauth: mountd has not established door");
		kmem_free(addr.buf, addr.len);
		return (NFSAUTH_DROP);
	}
	ntries = 0;
	varg.vers = V_PROTO;
	varg.arg_u.arg.cmd = NFSAUTH_ACCESS;
	varg.arg_u.arg.areq.req_client.n_len = addr.len;
	varg.arg_u.arg.areq.req_client.n_bytes = addr.buf;
	varg.arg_u.arg.areq.req_netid = svc_getnetid(req->rq_xprt);
	varg.arg_u.arg.areq.req_path = exi->exi_export.ex_path;
	varg.arg_u.arg.areq.req_flavor = flavor;

	/*
	 * Setup the XDR stream for encoding the arguments. Notice that
	 * in addition to the args having variable fields (req_netid and
	 * req_path), the argument data structure is itself versioned,
	 * so we need to make sure we can size the arguments buffer
	 * appropriately to encode all the args. If we can't get sizing
	 * info _or_ properly encode the arguments, there's really no
	 * point in continuting, so we fail the request.
	 */
	DTRACE_PROBE1(nfsserv__func__nfsauth__varg, varg_t *, &varg);
	if ((absz = xdr_sizeof(xdr_varg, (void *)&varg)) == 0) {
		door_ki_rele(dh);
		kmem_free(addr.buf, addr.len);
		return (NFSAUTH_DENIED);
	}
	abuf = (caddr_t)kmem_alloc(absz, KM_SLEEP);
	xdrmem_create(&xdrs_a, abuf, absz, XDR_ENCODE);
	if (!xdr_varg(&xdrs_a, &varg)) {
		door_ki_rele(dh);
		goto fail;
	}
	XDR_DESTROY(&xdrs_a);

	/*
	 * The result (nfsauth_res_t) is always two int's, so we don't
	 * have to dynamically size (or allocate) the results buffer.
	 * Now that we've got what we need, we prep the door arguments
	 * and place the call.
	 */
	da.data_ptr = (char *)abuf;
	da.data_size = absz;
	da.desc_ptr = NULL;
	da.desc_num = 0;
	da.rbuf = (char *)rbuf;
	da.rsize = rbsz;

	switch (door_ki_upcall_limited(dh, &da, NULL, SIZE_MAX, 0)) {
		case 0:				/* Success */
			if (da.data_ptr != da.rbuf && da.data_size == 0) {
				/*
				 * The door_return that contained the data
				 * failed ! We're here because of the 2nd
				 * door_return (w/o data) such that we can
				 * get control of the thread (and exit
				 * gracefully).
				 */
				DTRACE_PROBE1(nfsserv__func__nfsauth__door__nil,
				    door_arg_t *, &da);
				door_ki_rele(dh);
				goto fail;

			} else if (rbuf != da.rbuf) {
				/*
				 * The only time this should be true
				 * is iff userland wanted to hand us
				 * a bigger response than what we
				 * expect; that should not happen
				 * (nfsauth_res_t is only 2 int's),
				 * but we check nevertheless.
				 */
				rbuf = da.rbuf;
				rbsz = da.rsize;

			} else if (rbsz > da.data_size) {
				/*
				 * We were expecting two int's; but if
				 * userland fails in encoding the XDR
				 * stream, we detect that here, since
				 * the mountd forces down only one byte
				 * in such scenario.
				 */
				door_ki_rele(dh);
				goto fail;
			}
			door_ki_rele(dh);
			break;

		case EAGAIN:
			/*
			 * Server out of resources; back off for a bit
			 */
			door_ki_rele(dh);
			kmem_free(abuf, absz);
			delay(hz);
			goto retry;
			/* NOTREACHED */

		case EINTR:
			if (!door_ki_info(dh, &di)) {
				if (di.di_attributes & DOOR_REVOKED) {
					/*
					 * The server barfed and revoked
					 * the (existing) door on us; we
					 * want to wait to give smf(5) a
					 * chance to restart mountd(1m)
					 * and establish a new door handle.
					 */
					mutex_enter(&mountd_lock);
					if (dh == mountd_dh)
						mountd_dh = NULL;
					mutex_exit(&mountd_lock);
					door_ki_rele(dh);
					kmem_free(abuf, absz);
					delay(hz);
					goto retry;
				}
				/*
				 * If the door was _not_ revoked on us,
				 * then more than likely we took an INTR,
				 * so we need to fail the operation.
				 */
				door_ki_rele(dh);
				goto fail;
			}
			/*
			 * The only failure that can occur from getting
			 * the door info is EINVAL, so we let the code
			 * below handle it.
			 */
			/* FALLTHROUGH */

		case EBADF:
		case EINVAL:
		default:
			/*
			 * If we have a stale door handle, give smf a last
			 * chance to start it by sleeping for a little bit.
			 * If we're still hosed, we'll fail the call.
			 *
			 * Since we're going to reacquire the door handle
			 * upon the retry, we opt to sleep for a bit and
			 * _not_ to clear mountd_dh. If mountd restarted
			 * and was able to set mountd_dh, we should see
			 * the new instance; if not, we won't get caught
			 * up in the retry/DELAY loop.
			 */
			door_ki_rele(dh);
			if (!last) {
				delay(hz);
				last++;
				goto retry;
			}
			sys_log("nfsauth: stale mountd door handle");
			goto fail;
	}

	/*
	 * No door errors encountered; setup the XDR stream for decoding
	 * the results. If we fail to decode the results, we've got no
	 * other recourse than to fail the request.
	 */
	xdrmem_create(&xdrs_r, rbuf, rbsz, XDR_DECODE);
	if (!xdr_nfsauth_res(&xdrs_r, &res))
		goto fail;
	XDR_DESTROY(&xdrs_r);

	DTRACE_PROBE1(nfsserv__func__nfsauth__results, nfsauth_res_t *, &res);
	switch (res.stat) {
		case NFSAUTH_DR_OKAY:
			access = res.ares.auth_perm;
			kmem_free(abuf, absz);
			break;

		case NFSAUTH_DR_EFAIL:
		case NFSAUTH_DR_DECERR:
		case NFSAUTH_DR_BADCMD:
		default:
fail:
			kmem_free(addr.buf, addr.len);
			kmem_free(abuf, absz);
			return (NFSAUTH_DENIED);
			/* NOTREACHED */
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
	if ((perm & (M_ROOT|M_NONE)) == 0) {
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
	if ((perm & (M_ROOT|M_NONE)) == 0) {
		perm &= ~M_4SEC_EXPORTED;
		if (perm == M_RO)
			return (mapaccess | NFSAUTH_RO);
		if (perm == M_RW)
			return (mapaccess | NFSAUTH_RW);
	}

	access = nfsauth_cache_get(exi, req, flavor);
	if (access & NFSAUTH_DENIED)
		access = NFSAUTH_DENIED;

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
