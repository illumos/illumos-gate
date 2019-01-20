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

/*
 * Copyright (c) 2008, The Ohio State University. All rights reserved.
 *
 * Portions of this source code is developed by the team members of
 * The Ohio State University's Network-Based Computing Laboratory (NBCL),
 * headed by Professor Dhabaleswar K. (DK) Panda.
 *
 * Acknowledgements to contributions from developors:
 *   Ranjit Noronha: noronha@cse.ohio-state.edu
 *   Lei Chai      : chail@cse.ohio-state.edu
 *   Weikuan Yu    : yuw@cse.ohio-state.edu
 *
 */

#include <sys/systm.h>
#include <sys/kstat.h>
#include <sys/modctl.h>
#include <sys/sdt.h>
#include <rpc/rpc_rdma.h>

#include <sys/ib/ibtl/ibti.h>

uint_t rdma_minchunk = RDMA_MINCHUNK;

/*
 * Globals
 */
int rdma_modloaded = 0;		/* flag to load RDMA plugin modules */
int rdma_dev_available = 0;	/* if any RDMA device is loaded */
kmutex_t rdma_modload_lock;	/* protects rdma_modloaded flag */

rdma_svc_wait_t rdma_wait;

rdma_registry_t	*rdma_mod_head = NULL;	/* head for RDMA modules */
krwlock_t	rdma_lock;		/* protects rdma_mod_head list */
ldi_ident_t rpcmod_li = NULL;	/* identifies us with ldi_ framework */

kmem_cache_t *clist_cache = NULL;

/*
 * Statics
 */
ldi_handle_t rpcib_handle = NULL;

/*
 * Externs
 */
extern	kstat_named_t	*rdmarcstat_ptr;
extern	uint_t		rdmarcstat_ndata;
extern	kstat_named_t	*rdmarsstat_ptr;
extern	uint_t		rdmarsstat_ndata;

void rdma_kstat_init();

/*
 * RDMATF module registration routine.
 * This routine is expected to be called by the init routine in
 * the plugin modules.
 */
rdma_stat
rdma_register_mod(rdma_mod_t *mod)
{
	rdma_registry_t **mp, *m;

	if (mod->rdma_version != RDMATF_VERS) {
		return (RDMA_BADVERS);
	}

	rw_enter(&rdma_lock, RW_WRITER);
	/*
	 * Ensure not already registered
	 */
	mp = &rdma_mod_head;
	while (*mp != NULL) {
		if (strncmp((*mp)->r_mod->rdma_api, mod->rdma_api,
		    KNC_STRSIZE) == 0) {
			if ((*mp)->r_mod_state == RDMA_MOD_INACTIVE) {
				(*mp)->r_mod_state = RDMA_MOD_ACTIVE;
				(*mp)->r_mod->rdma_ops = mod->rdma_ops;
				(*mp)->r_mod->rdma_count = mod->rdma_count;
				goto announce_hca;
			}
			rw_exit(&rdma_lock);
			return (RDMA_REG_EXIST);
		}
		mp = &((*mp)->r_next);
	}

	/*
	 * New one, create and add to registry
	 */
	m = kmem_alloc(sizeof (rdma_registry_t), KM_SLEEP);
	m->r_mod = kmem_alloc(sizeof (rdma_mod_t), KM_SLEEP);
	*m->r_mod = *mod;
	m->r_next = NULL;
	m->r_mod->rdma_api = kmem_zalloc(KNC_STRSIZE, KM_SLEEP);
	(void) strncpy(m->r_mod->rdma_api, mod->rdma_api, KNC_STRSIZE);
	m->r_mod->rdma_api[KNC_STRSIZE - 1] = '\0';
	m->r_mod_state = RDMA_MOD_ACTIVE;
	*mp = m;

announce_hca:
	rw_exit(&rdma_lock);
	/*
	 * Start the nfs service on the rdma xprts.
	 * (this notification mechanism will need to change when we support
	 * multiple hcas and have support for multiple rdma plugins).
	 */
	mutex_enter(&rdma_wait.svc_lock);
	rdma_wait.svc_stat = RDMA_HCA_ATTACH;
	cv_signal(&rdma_wait.svc_cv);
	mutex_exit(&rdma_wait.svc_lock);

	return (RDMA_SUCCESS);
}

/*
 * RDMATF module unregistration routine.
 * This routine is expected to be called by the fini routine in
 * the plugin modules.
 */
rdma_stat
rdma_unregister_mod(rdma_mod_t *mod)
{
	rdma_registry_t **m, *mmod = NULL;

	rw_enter(&rdma_lock, RW_WRITER);

	m = &rdma_mod_head;
	while (*m != NULL) {
		if (strncmp((*m)->r_mod->rdma_api, mod->rdma_api,
		    KNC_STRSIZE) != 0) {
			m = &((*m)->r_next);
			continue;
		}
		/*
		 * Check if any device attached, if so return error
		 */
		if (mod->rdma_count != 0) {
			rw_exit(&rdma_lock);
			return (RDMA_FAILED);
		}
		/*
		 * Found entry. Mark it inactive.
		 */
		mmod = *m;
		mmod->r_mod->rdma_count = 0;
		mmod->r_mod_state = RDMA_MOD_INACTIVE;
		break;
	}

	rdma_modloaded = 0;
	rdma_dev_available = 0;
	rw_exit(&rdma_lock);

	/*
	 * Stop the nfs service running on the rdma xprts.
	 * (this notification mechanism will need to change when we support
	 * multiple hcas and have support for multiple rdma plugins).
	 */
	mutex_enter(&rdma_wait.svc_lock);
	rdma_wait.svc_stat = RDMA_HCA_DETACH;
	cv_signal(&rdma_wait.svc_cv);
	mutex_exit(&rdma_wait.svc_lock);

	/*
	 * Not found.
	 */
	return (RDMA_SUCCESS);
}

struct clist *
clist_alloc(void)
{
	struct clist *clp;

	clp = kmem_cache_alloc(clist_cache, KM_SLEEP);

	bzero(clp, sizeof (*clp));

	return (clp);
}

uint32_t
clist_len(struct clist *cl)
{
	uint32_t len = 0;
	while (cl) {
		len += cl->c_len;
		cl = cl->c_next;
	}
	return (len);
}

void
clist_zero_len(struct clist *cl)
{
	while (cl != NULL) {
		if (cl->c_dmemhandle.mrc_rmr == 0)
			break;
		cl->c_len = 0;
		cl = cl->c_next;
	}
}

/*
 * Creates a new chunk list entry, and
 * adds it to the end of a chunk list.
 */
void
clist_add(struct clist **clp, uint32_t xdroff, int len,
    struct mrc *shandle, caddr_t saddr,
    struct mrc *dhandle, caddr_t daddr)
{
	struct clist *cl;

	/* Find the end of the list */

	while (*clp != NULL)
		clp = &((*clp)->c_next);

	cl = clist_alloc();
	cl->c_xdroff = xdroff;
	cl->c_len = len;
	cl->w.c_saddr = (uint64_t)(uintptr_t)saddr;
	if (shandle)
		cl->c_smemhandle = *shandle;
	cl->u.c_daddr = (uint64_t)(uintptr_t)daddr;
	if (dhandle)
		cl->c_dmemhandle = *dhandle;
	cl->c_next = NULL;

	*clp = cl;
}

rdma_stat
clist_register(CONN *conn, struct clist *cl, clist_dstsrc dstsrc)
{
	struct clist *c;
	int status;

	for (c = cl; c; c = c->c_next) {
		if (c->c_len <= 0)
			continue;

		c->c_regtype = dstsrc;

		switch (dstsrc) {
		case CLIST_REG_SOURCE:
			status = RDMA_REGMEMSYNC(conn,
			    (caddr_t)(struct as *)c->c_adspc,
			    (caddr_t)(uintptr_t)c->w.c_saddr3, c->c_len,
			    &c->c_smemhandle, (void **)&c->c_ssynchandle,
			    (void *)c->rb_longbuf.rb_private);
			break;
		case CLIST_REG_DST:
			status = RDMA_REGMEMSYNC(conn,
			    (caddr_t)(struct as *)c->c_adspc,
			    (caddr_t)(uintptr_t)c->u.c_daddr3, c->c_len,
			    &c->c_dmemhandle, (void **)&c->c_dsynchandle,
			    (void *)c->rb_longbuf.rb_private);
			break;
		default:
			return (RDMA_INVAL);
		}
		if (status != RDMA_SUCCESS) {
			(void) clist_deregister(conn, cl);
			return (status);
		}
	}

	return (RDMA_SUCCESS);
}

rdma_stat
clist_deregister(CONN *conn, struct clist *cl)
{
	struct clist *c;

	for (c = cl; c; c = c->c_next) {
		switch (c->c_regtype) {
		case CLIST_REG_SOURCE:
			if (c->c_smemhandle.mrc_rmr != 0) {
				(void) RDMA_DEREGMEMSYNC(conn,
				    (caddr_t)(uintptr_t)c->w.c_saddr3,
				    c->c_smemhandle,
				    (void *)(uintptr_t)c->c_ssynchandle,
				    (void *)c->rb_longbuf.rb_private);
				c->c_smemhandle.mrc_rmr = 0;
				c->c_ssynchandle = 0;
			}
			break;
		case CLIST_REG_DST:
			if (c->c_dmemhandle.mrc_rmr != 0) {
				(void) RDMA_DEREGMEMSYNC(conn,
				    (caddr_t)(uintptr_t)c->u.c_daddr3,
				    c->c_dmemhandle,
				    (void *)(uintptr_t)c->c_dsynchandle,
				    (void *)c->rb_longbuf.rb_private);
				c->c_dmemhandle.mrc_rmr = 0;
				c->c_dsynchandle = 0;
			}
			break;
		default:
			/* clist unregistered. continue */
			break;
		}
	}

	return (RDMA_SUCCESS);
}

rdma_stat
clist_syncmem(CONN *conn, struct clist *cl, clist_dstsrc dstsrc)
{
	struct clist *c;
	rdma_stat status;

	c = cl;
	switch (dstsrc) {
	case CLIST_REG_SOURCE:
		while (c != NULL) {
			if (c->c_ssynchandle) {
				status = RDMA_SYNCMEM(conn,
				    (void *)(uintptr_t)c->c_ssynchandle,
				    (caddr_t)(uintptr_t)c->w.c_saddr3,
				    c->c_len, 0);
				if (status != RDMA_SUCCESS)
					return (status);
			}
			c = c->c_next;
		}
		break;
	case CLIST_REG_DST:
		while (c != NULL) {
			if (c->c_ssynchandle) {
				status = RDMA_SYNCMEM(conn,
				    (void *)(uintptr_t)c->c_dsynchandle,
				    (caddr_t)(uintptr_t)c->u.c_daddr3,
				    c->c_len, 1);
				if (status != RDMA_SUCCESS)
					return (status);
			}
			c = c->c_next;
		}
		break;
	default:
		return (RDMA_INVAL);
	}

	return (RDMA_SUCCESS);
}

/*
 * Frees up entries in chunk list
 */
void
clist_free(struct clist *cl)
{
	struct clist *c = cl;

	while (c != NULL) {
		cl = cl->c_next;
		kmem_cache_free(clist_cache, c);
		c = cl;
	}
}

rdma_stat
rdma_clnt_postrecv(CONN *conn, uint32_t xid)
{
	struct clist *cl = NULL;
	rdma_stat retval;
	rdma_buf_t rbuf = {0};

	rbuf.type = RECV_BUFFER;
	if (RDMA_BUF_ALLOC(conn, &rbuf)) {
		return (RDMA_NORESOURCE);
	}

	clist_add(&cl, 0, rbuf.len, &rbuf.handle, rbuf.addr,
	    NULL, NULL);
	retval = RDMA_CLNT_RECVBUF(conn, cl, xid);
	clist_free(cl);

	return (retval);
}

rdma_stat
rdma_clnt_postrecv_remove(CONN *conn, uint32_t xid)
{
	return (RDMA_CLNT_RECVBUF_REMOVE(conn, xid));
}

rdma_stat
rdma_svc_postrecv(CONN *conn)
{
	struct clist *cl = NULL;
	rdma_stat retval;
	rdma_buf_t rbuf = {0};

	rbuf.type = RECV_BUFFER;
	if (RDMA_BUF_ALLOC(conn, &rbuf)) {
		retval = RDMA_NORESOURCE;
	} else {
		clist_add(&cl, 0, rbuf.len, &rbuf.handle, rbuf.addr,
		    NULL, NULL);
		retval = RDMA_SVC_RECVBUF(conn, cl);
		clist_free(cl);
	}
	return (retval);
}

rdma_stat
rdma_buf_alloc(CONN *conn, rdma_buf_t *rbuf)
{
	return (RDMA_BUF_ALLOC(conn, rbuf));
}

void
rdma_buf_free(CONN *conn, rdma_buf_t *rbuf)
{
	if (!rbuf || rbuf->addr == NULL) {
		return;
	}
	RDMA_BUF_FREE(conn, rbuf);
	bzero(rbuf, sizeof (rdma_buf_t));
}

/*
 * Caller is holding rdma_modload_lock mutex
 */
int
rdma_modload()
{
	int status;
	ASSERT(MUTEX_HELD(&rdma_modload_lock));
	/*
	 * Load all available RDMA plugins which right now is only IB plugin.
	 * If no IB hardware is present, then quit right away.
	 * ENODEV -- For no device on the system
	 * EPROTONOSUPPORT -- For module not avilable either due to failure to
	 * load or some other reason.
	 */
	rdma_modloaded = 1;
	if (ibt_hw_is_present() == 0) {
		rdma_dev_available = 0;
		return (ENODEV);
	}

	rdma_dev_available = 1;
	if (rpcmod_li == NULL)
		return (EPROTONOSUPPORT);

	status = ldi_open_by_name("/devices/ib/rpcib@0:rpcib",
	    FREAD | FWRITE, kcred,
	    &rpcib_handle, rpcmod_li);

	if (status != 0)
		return (EPROTONOSUPPORT);


	/*
	 * We will need to reload the plugin module after it was unregistered
	 * but the resources below need to allocated only the first time.
	 */
	if (!clist_cache) {
		clist_cache = kmem_cache_create("rdma_clist",
		    sizeof (struct clist), _POINTER_ALIGNMENT, NULL,
		    NULL, NULL, NULL, 0, 0);
		rdma_kstat_init();
	}

	(void) ldi_close(rpcib_handle, FREAD|FWRITE, kcred);

	return (0);
}

void
rdma_kstat_init(void)
{
	kstat_t *ksp;

	/*
	 * The RDMA framework doesn't know how to deal with Zones, and is
	 * only available in the global zone.
	 */
	ASSERT(INGLOBALZONE(curproc));
	ksp = kstat_create_zone("unix", 0, "rpc_rdma_client", "rpc",
	    KSTAT_TYPE_NAMED, rdmarcstat_ndata,
	    KSTAT_FLAG_VIRTUAL | KSTAT_FLAG_WRITABLE, GLOBAL_ZONEID);
	if (ksp) {
		ksp->ks_data = (void *) rdmarcstat_ptr;
		kstat_install(ksp);
	}

	ksp = kstat_create_zone("unix", 0, "rpc_rdma_server", "rpc",
	    KSTAT_TYPE_NAMED, rdmarsstat_ndata,
	    KSTAT_FLAG_VIRTUAL | KSTAT_FLAG_WRITABLE, GLOBAL_ZONEID);
	if (ksp) {
		ksp->ks_data = (void *) rdmarsstat_ptr;
		kstat_install(ksp);
	}
}

rdma_stat
rdma_kwait(void)
{
	int ret;
	rdma_stat stat;

	mutex_enter(&rdma_wait.svc_lock);

	ret = cv_wait_sig(&rdma_wait.svc_cv, &rdma_wait.svc_lock);

	/*
	 * If signalled by a hca attach/detach, pass the right
	 * stat back.
	 */

	if (ret)
		stat =  rdma_wait.svc_stat;
	else
		stat = RDMA_INTR;

	mutex_exit(&rdma_wait.svc_lock);

	return (stat);
}
