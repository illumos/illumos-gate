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
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * Copyright (c) 2018, Joyent, Inc.
 */

/*
 * FMA event subscription interfaces - subscribe to FMA protocol
 * from outside the fault manager.
 */

#include <sys/types.h>
#include <atomic.h>
#include <libsysevent.h>
#include <libuutil.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <fm/libtopo.h>

#include <fm/libfmevent.h>

#include "fmev_impl.h"

static topo_hdl_t *g_topohdl;

typedef struct {
	struct fmev_hdl_cmn sh_cmn;
	evchan_t *sh_binding;
	uu_avl_pool_t *sh_pool;
	uu_avl_t *sh_avl;
	uint32_t sh_subcnt;
	uint32_t sh_flags;
	sysevent_subattr_t *sh_attr;
	pthread_mutex_t sh_lock;
	pthread_mutex_t sh_srlz_lock;
} fmev_shdl_impl_t;

#define	HDL2IHDL(hdl)	((fmev_shdl_impl_t *)(hdl))
#define	IHDL2HDL(ihdl)	((fmev_shdl_t)(ihdl))

#define	_FMEV_SHMAGIC	0x5368446c	/* ShDl */
#define	FMEV_SHDL_VALID(ihdl)	((ihdl)->sh_cmn.hc_magic == _FMEV_SHMAGIC)

#define	SHDL_FL_SERIALIZE	0x1

#define	FMEV_API_ENTER(hdl, v) \
	fmev_api_enter(&HDL2IHDL(hdl)->sh_cmn, LIBFMEVENT_VERSION_##v)

/*
 * For each subscription on a handle we add a node to an avl tree
 * to track subscriptions.
 */

#define	FMEV_SID_SZ	(16 + 1)	/* Matches MAX_SUBID_LEN */

struct fmev_subinfo {
	uu_avl_node_t si_node;
	fmev_shdl_impl_t *si_ihdl;
	char si_pat[FMEV_MAX_CLASS];
	char si_sid[FMEV_SID_SZ];
	fmev_cbfunc_t *si_cb;
	void *si_cbarg;
};

struct fmev_hdl_cmn *
fmev_shdl_cmn(fmev_shdl_t hdl)
{
	return (&HDL2IHDL(hdl)->sh_cmn);
}

static int
shdlctl_start(fmev_shdl_impl_t *ihdl)
{
	(void) pthread_mutex_lock(&ihdl->sh_lock);

	if (ihdl->sh_subcnt == 0) {
		return (1);	/* lock still held */
	} else {
		(void) pthread_mutex_unlock(&ihdl->sh_lock);
		return (0);
	}
}

static void
shdlctl_end(fmev_shdl_impl_t *ihdl)
{
	(void) pthread_mutex_unlock(&ihdl->sh_lock);
}

fmev_err_t
fmev_shdlctl_serialize(fmev_shdl_t hdl)
{
	fmev_shdl_impl_t *ihdl = HDL2IHDL(hdl);

	if (!FMEV_API_ENTER(hdl, 1))
		return (fmev_errno);

	if (!shdlctl_start(ihdl))
		return (fmev_seterr(FMEVERR_BUSY));

	if (!(ihdl->sh_flags & SHDL_FL_SERIALIZE)) {
		(void) pthread_mutex_init(&ihdl->sh_srlz_lock, NULL);
		ihdl->sh_flags |= SHDL_FL_SERIALIZE;
	}

	shdlctl_end(ihdl);
	return (fmev_seterr(FMEV_SUCCESS));
}

fmev_err_t
fmev_shdlctl_thrattr(fmev_shdl_t hdl, pthread_attr_t *attr)
{
	fmev_shdl_impl_t *ihdl = HDL2IHDL(hdl);

	if (!FMEV_API_ENTER(hdl, 1))
		return (fmev_errno);

	if (!shdlctl_start(ihdl))
		return (fmev_seterr(FMEVERR_BUSY));

	sysevent_subattr_thrattr(ihdl->sh_attr, attr);

	shdlctl_end(ihdl);
	return (fmev_seterr(FMEV_SUCCESS));
}

fmev_err_t
fmev_shdlctl_sigmask(fmev_shdl_t hdl, sigset_t *set)
{
	fmev_shdl_impl_t *ihdl = HDL2IHDL(hdl);

	if (!FMEV_API_ENTER(hdl, 1))
		return (fmev_errno);

	if (!shdlctl_start(ihdl))
		return (fmev_seterr(FMEVERR_BUSY));

	sysevent_subattr_sigmask(ihdl->sh_attr, set);

	shdlctl_end(ihdl);
	return (fmev_seterr(FMEV_SUCCESS));
}

fmev_err_t
fmev_shdlctl_thrsetup(fmev_shdl_t hdl, door_xcreate_thrsetup_func_t *func,
    void *cookie)
{
	fmev_shdl_impl_t *ihdl = HDL2IHDL(hdl);

	if (!FMEV_API_ENTER(hdl, 1))
		return (fmev_errno);

	if (!shdlctl_start(ihdl))
		return (fmev_seterr(FMEVERR_BUSY));

	sysevent_subattr_thrsetup(ihdl->sh_attr, func, cookie);

	shdlctl_end(ihdl);
	return (fmev_seterr(FMEV_SUCCESS));
}

fmev_err_t
fmev_shdlctl_thrcreate(fmev_shdl_t hdl, door_xcreate_server_func_t *func,
    void *cookie)
{
	fmev_shdl_impl_t *ihdl = HDL2IHDL(hdl);

	if (!FMEV_API_ENTER(hdl, 1))
		return (fmev_errno);

	if (!shdlctl_start(ihdl))
		return (fmev_seterr(FMEVERR_BUSY));

	sysevent_subattr_thrcreate(ihdl->sh_attr, func, cookie);

	shdlctl_end(ihdl);
	return (fmev_seterr(FMEV_SUCCESS));
}

/*
 * Our door service function.  We return 0 regardless so that the kernel
 * does not keep either retrying (EAGAIN) or bleat to cmn_err.
 */

uint64_t fmev_proxy_cb_enomem;

static int
fmev_proxy_cb(sysevent_t *sep, void *arg)
{
	struct fmev_subinfo *sip = arg;
	fmev_shdl_impl_t *ihdl = sip->si_ihdl;
	nvlist_t *nvl;
	char *class;
	fmev_t ev;

	if ((ev = fmev_sysev2fmev(IHDL2HDL(ihdl), sep, &class, &nvl)) == NULL) {
		fmev_proxy_cb_enomem++;
		return (0);
	}

	if (ihdl->sh_flags & SHDL_FL_SERIALIZE)
		(void) pthread_mutex_lock(&ihdl->sh_srlz_lock);

	sip->si_cb(ev, class, nvl, sip->si_cbarg);

	if (ihdl->sh_flags & SHDL_FL_SERIALIZE)
		(void) pthread_mutex_unlock(&ihdl->sh_srlz_lock);

	fmev_rele(ev);	/* release hold obtained in fmev_sysev2fmev */

	return (0);
}

static volatile uint32_t fmev_subid;

fmev_err_t
fmev_shdl_subscribe(fmev_shdl_t hdl, const char *pat, fmev_cbfunc_t func,
    void *funcarg)
{
	fmev_shdl_impl_t *ihdl = HDL2IHDL(hdl);
	struct fmev_subinfo *sip;
	uu_avl_index_t idx;
	uint64_t nsid;
	int serr;

	if (!FMEV_API_ENTER(hdl, 1))
		return (fmev_errno);

	if (pat == NULL || func == NULL)
		return (fmev_seterr(FMEVERR_API));

	/*
	 * Empty class patterns are illegal, as is the sysevent magic for
	 * all classes.  Also validate class length.
	 */
	if (*pat == '\0' || strncmp(pat, EC_ALL, sizeof (EC_ALL)) == 0 ||
	    strncmp(pat, EC_SUB_ALL, sizeof (EC_SUB_ALL)) == 0 ||
	    strnlen(pat, FMEV_MAX_CLASS) == FMEV_MAX_CLASS)
		return (fmev_seterr(FMEVERR_BADCLASS));

	if ((sip = fmev_shdl_zalloc(hdl, sizeof (*sip))) == NULL)
		return (fmev_seterr(FMEVERR_ALLOC));

	(void) strncpy(sip->si_pat, pat, sizeof (sip->si_pat));

	uu_avl_node_init(sip, &sip->si_node, ihdl->sh_pool);

	(void) pthread_mutex_lock(&ihdl->sh_lock);

	if (uu_avl_find(ihdl->sh_avl, sip, NULL, &idx) != NULL) {
		(void) pthread_mutex_unlock(&ihdl->sh_lock);
		fmev_shdl_free(hdl, sip, sizeof (*sip));
		return (fmev_seterr(FMEVERR_DUPLICATE));
	}

	/*
	 * Generate a subscriber id for GPEC that is unique to this
	 * subscription.  There is no provision for persistent
	 * subscribers.  The subscriber id must be unique within
	 * this zone.
	 */
	nsid = (uint64_t)getpid() << 32 | atomic_inc_32_nv(&fmev_subid);
	(void) snprintf(sip->si_sid, sizeof (sip->si_sid), "%llx", nsid);

	sip->si_ihdl = ihdl;
	sip->si_cb = func;
	sip->si_cbarg = funcarg;

	if ((serr = sysevent_evc_xsubscribe(ihdl->sh_binding, sip->si_sid,
	    sip->si_pat, fmev_proxy_cb, sip, 0, ihdl->sh_attr)) != 0) {
		fmev_err_t err;

		(void) pthread_mutex_unlock(&ihdl->sh_lock);
		fmev_shdl_free(hdl, sip, sizeof (*sip));

		switch (serr) {
		case ENOMEM:
			err = FMEVERR_MAX_SUBSCRIBERS;
			break;

		default:
			err = FMEVERR_INTERNAL;
			break;
		}

		return (fmev_seterr(err));
	}

	uu_avl_insert(ihdl->sh_avl, sip, idx);
	ihdl->sh_subcnt++;

	(void) pthread_mutex_unlock(&ihdl->sh_lock);

	return (fmev_seterr(FMEV_SUCCESS));
}

static int
fmev_subinfo_fini(fmev_shdl_impl_t *ihdl, struct fmev_subinfo *sip,
    boolean_t doavl)
{
	int err;

	ASSERT(sip->si_ihdl == ihdl);

	err = sysevent_evc_unsubscribe(ihdl->sh_binding, sip->si_sid);

	if (err == 0) {
		if (doavl) {
			uu_avl_remove(ihdl->sh_avl, sip);
			uu_avl_node_fini(sip, &sip->si_node, ihdl->sh_pool);
		}
		fmev_shdl_free(IHDL2HDL(ihdl), sip, sizeof (*sip));
		ihdl->sh_subcnt--;
	}

	return (err);
}

fmev_err_t
fmev_shdl_unsubscribe(fmev_shdl_t hdl, const char *pat)
{
	fmev_shdl_impl_t *ihdl = HDL2IHDL(hdl);
	fmev_err_t rv = FMEVERR_NOMATCH;
	struct fmev_subinfo *sip;
	struct fmev_subinfo si;
	int err;

	if (!FMEV_API_ENTER(hdl, 1))
		return (fmev_errno);

	if (pat == NULL)
		return (fmev_seterr(FMEVERR_API));

	if (*pat == '\0' || strncmp(pat, EVCH_ALLSUB, sizeof (EC_ALL)) == 0 ||
	    strnlen(pat, FMEV_MAX_CLASS) == FMEV_MAX_CLASS)
		return (fmev_seterr(FMEVERR_BADCLASS));

	(void) strncpy(si.si_pat, pat, sizeof (si.si_pat));

	(void) pthread_mutex_lock(&ihdl->sh_lock);

	if ((sip = uu_avl_find(ihdl->sh_avl, &si, NULL, NULL)) != NULL) {
		if ((err = fmev_subinfo_fini(ihdl, sip, B_TRUE)) == 0) {
			rv = FMEV_SUCCESS;
		} else {
			/*
			 * Return an API error if the unsubscribe was
			 * attempted from within a door callback invocation;
			 * other errors should not happen.
			 */
			rv = (err == EDEADLK) ? FMEVERR_API : FMEVERR_INTERNAL;
		}
	}

	(void) pthread_mutex_unlock(&ihdl->sh_lock);

	return (fmev_seterr(rv));
}

void *
fmev_shdl_alloc(fmev_shdl_t hdl, size_t sz)
{
	fmev_shdl_impl_t *ihdl = HDL2IHDL(hdl);

	if (!FMEV_API_ENTER(hdl, 1))
		return (NULL);

	return (ihdl->sh_cmn.hc_alloc(sz));
}

void *
fmev_shdl_zalloc(fmev_shdl_t hdl, size_t sz)
{
	fmev_shdl_impl_t *ihdl = HDL2IHDL(hdl);

	if (!FMEV_API_ENTER(hdl, 1))
		return (NULL);

	return (ihdl->sh_cmn.hc_zalloc(sz));
}

void
fmev_shdl_free(fmev_shdl_t hdl, void *buf, size_t sz)
{
	fmev_shdl_impl_t *ihdl = HDL2IHDL(hdl);

	if (!FMEV_API_ENTER(hdl, 1))
		return;

	ihdl->sh_cmn.hc_free(buf, sz);
}

char *
fmev_shdl_strdup(fmev_shdl_t hdl, char *src)
{
	fmev_shdl_impl_t *ihdl = HDL2IHDL(hdl);
	size_t srclen;
	char *dst;

	if (!FMEV_API_ENTER(hdl, 2))
		return (NULL);

	srclen = strlen(src);

	if ((dst = ihdl->sh_cmn.hc_alloc(srclen + 1)) == NULL) {
		(void) fmev_seterr(FMEVERR_ALLOC);
		return (NULL);
	}

	(void) strncpy(dst, src, srclen);
	dst[srclen] = '\0';
	return (dst);
}

void
fmev_shdl_strfree(fmev_shdl_t hdl, char *buf)
{
	fmev_shdl_impl_t *ihdl = HDL2IHDL(hdl);

	(void) FMEV_API_ENTER(hdl, 2);

	ihdl->sh_cmn.hc_free(buf, strlen(buf) + 1);
}

int
fmev_shdl_valid(fmev_shdl_t hdl)
{
	return (FMEV_SHDL_VALID(HDL2IHDL(hdl)));
}

/*ARGSUSED*/
static int
fmev_keycmp(const void *l, const void *r, void *arg)
{
	struct fmev_subinfo *left = (struct fmev_subinfo *)l;
	struct fmev_subinfo *right = (struct fmev_subinfo *)r;

	return (strncmp(left->si_pat, right->si_pat, FMEV_MAX_CLASS));
}

fmev_shdl_t
fmev_shdl_init(uint32_t caller_version, void *(*hdlalloc)(size_t),
    void *(*hdlzalloc)(size_t), void (*hdlfree)(void *, size_t))
{
	fmev_shdl_impl_t *ihdl;
	struct fmev_hdl_cmn hc;
	const char *chan_name;
	int err;

	hc.hc_magic = _FMEV_SHMAGIC;
	hc.hc_api_vers = caller_version;
	hc.hc_alloc = hdlalloc ? hdlalloc : dflt_alloc;
	hc.hc_zalloc = hdlzalloc ? hdlzalloc : dflt_zalloc;
	hc.hc_free = hdlfree ? hdlfree : dflt_free;

	if (!fmev_api_init(&hc))
		return (NULL);	/* error type set */

	if (!((hdlalloc == NULL && hdlzalloc == NULL && hdlfree == NULL) ||
	    (hdlalloc != NULL && hdlzalloc != NULL && hdlfree != NULL))) {
		(void) fmev_seterr(FMEVERR_API);
		return (NULL);
	}

	if (hdlzalloc == NULL)
		ihdl = dflt_zalloc(sizeof (*ihdl));
	else
		ihdl = hdlzalloc(sizeof (*ihdl));

	if (ihdl == NULL) {
		(void) fmev_seterr(FMEVERR_ALLOC);
		return (NULL);
	}

	ihdl->sh_cmn = hc;

	if ((ihdl->sh_attr = sysevent_subattr_alloc()) == NULL) {
		err = FMEVERR_ALLOC;
		goto error;
	}

	(void) pthread_mutex_init(&ihdl->sh_lock, NULL);

	/*
	 * For simulation purposes we allow an environment variable
	 * to provide a different channel name.
	 */
	if ((chan_name = getenv("FMD_SNOOP_CHANNEL")) == NULL)
		chan_name = FMD_SNOOP_CHANNEL;

	/*
	 * Try to bind to the event channel. If it's not already present,
	 * attempt to create the channel so that we can startup before
	 * the event producer (who will also apply choices such as
	 * channel depth when they bind to the channel).
	 */
	if (sysevent_evc_bind(chan_name, &ihdl->sh_binding,
	    EVCH_CREAT | EVCH_HOLD_PEND_INDEF) != 0) {
		switch (errno) {
		case EINVAL:
		default:
			err = FMEVERR_INTERNAL;
			break;
		case ENOMEM:
			err = FMEVERR_ALLOC;
			break;
		case EPERM:
			err = FMEVERR_NOPRIV;
			break;
		}
		goto error;
	}

	if ((ihdl->sh_pool = uu_avl_pool_create("subinfo_pool",
	    sizeof (struct fmev_subinfo),
	    offsetof(struct fmev_subinfo, si_node), fmev_keycmp,
	    UU_AVL_POOL_DEBUG)) == NULL) {
		err = FMEVERR_INTERNAL;
		goto error;
	}

	if ((ihdl->sh_avl = uu_avl_create(ihdl->sh_pool, NULL,
	    UU_DEFAULT)) == NULL) {
		err = FMEVERR_INTERNAL;
		goto error;
	}

	return (IHDL2HDL(ihdl));

error:
	(void) fmev_shdl_fini(IHDL2HDL(ihdl));
	(void) fmev_seterr(err);
	return (NULL);
}

fmev_err_t
fmev_shdl_getauthority(fmev_shdl_t hdl, nvlist_t **nvlp)
{
	fmev_shdl_impl_t *ihdl = HDL2IHDL(hdl);
	nvlist_t *propnvl;
	fmev_err_t rc;

	if (!FMEV_API_ENTER(hdl, 2))
		return (fmev_errno);

	(void) pthread_mutex_lock(&ihdl->sh_lock);

	if (sysevent_evc_getpropnvl(ihdl->sh_binding, &propnvl) != 0) {
		*nvlp = NULL;
		(void) pthread_mutex_unlock(&ihdl->sh_lock);
		return (fmev_seterr(FMEVERR_UNKNOWN));
	}

	if (propnvl == NULL) {
		rc = FMEVERR_BUSY;	/* Other end has not bound */
	} else {
		nvlist_t *auth;

		if (nvlist_lookup_nvlist(propnvl, "fmdauth", &auth) == 0) {
			rc = (nvlist_dup(auth, nvlp, 0) == 0) ? FMEV_SUCCESS :
			    FMEVERR_ALLOC;
		} else {
			rc = FMEVERR_INTERNAL;
		}
		nvlist_free(propnvl);
	}

	(void) pthread_mutex_unlock(&ihdl->sh_lock);

	if (rc != FMEV_SUCCESS) {
		*nvlp = NULL;
		(void) fmev_seterr(rc);
	}

	return (rc);
}

char *
fmev_shdl_nvl2str(fmev_shdl_t hdl, nvlist_t *nvl)
{
	fmev_shdl_impl_t *ihdl = HDL2IHDL(hdl);
	char *fmri, *fmricp;
	fmev_err_t err;
	int topoerr;

	if (!FMEV_API_ENTER(hdl, 2))
		return (NULL);

	if (g_topohdl == NULL) {
		(void) pthread_mutex_lock(&ihdl->sh_lock);
		if (g_topohdl == NULL)
			g_topohdl = topo_open(TOPO_VERSION, NULL, &topoerr);
		(void) pthread_mutex_unlock(&ihdl->sh_lock);

		if (g_topohdl == NULL) {
			(void) fmev_seterr(FMEVERR_INTERNAL);
			return (NULL);
		}
	}

	if (topo_fmri_nvl2str(g_topohdl, nvl, &fmri, &topoerr) == 0) {
		fmricp = fmev_shdl_strdup(hdl, fmri);
		topo_hdl_strfree(g_topohdl, fmri);
		return (fmricp);	/* fmev_errno set if strdup failed */
	}

	switch (topoerr) {
	case ETOPO_FMRI_NOMEM:
		err = FMEVERR_ALLOC;
		break;

	case ETOPO_FMRI_MALFORM:
	case ETOPO_METHOD_NOTSUP:
	case ETOPO_METHOD_INVAL:
	default:
		err = FMEVERR_INVALIDARG;
		break;
	}

	(void) fmev_seterr(err);
	return (NULL);
}

fmev_err_t
fmev_shdl_fini(fmev_shdl_t hdl)
{
	fmev_shdl_impl_t *ihdl = HDL2IHDL(hdl);

	if (!FMEV_API_ENTER(hdl, 1))
		return (fmev_errno);

	(void) pthread_mutex_lock(&ihdl->sh_lock);

	/*
	 * Verify that we are not in callback context - return an API
	 * error if we are.
	 */
	if (sysevent_evc_unsubscribe(ihdl->sh_binding, "invalidsid") ==
	    EDEADLK) {
		(void) pthread_mutex_unlock(&ihdl->sh_lock);
		return (fmev_seterr(FMEVERR_API));
	}

	if (ihdl->sh_avl) {
		void *cookie = NULL;
		struct fmev_subinfo *sip;

		while ((sip = uu_avl_teardown(ihdl->sh_avl, &cookie)) != NULL)
			(void) fmev_subinfo_fini(ihdl, sip, B_FALSE);

		uu_avl_destroy(ihdl->sh_avl);
		ihdl->sh_avl = NULL;
	}

	ASSERT(ihdl->sh_subcnt == 0);

	if (ihdl->sh_binding) {
		(void) sysevent_evc_unbind(ihdl->sh_binding);
		ihdl->sh_binding = NULL;
	}

	if (ihdl->sh_pool) {
		uu_avl_pool_destroy(ihdl->sh_pool);
		ihdl->sh_pool = NULL;
	}

	if (ihdl->sh_attr) {
		sysevent_subattr_free(ihdl->sh_attr);
		ihdl->sh_attr = NULL;
	}

	ihdl->sh_cmn.hc_magic = 0;

	if (g_topohdl) {
		topo_close(g_topohdl);
		g_topohdl = NULL;
	}

	(void) pthread_mutex_unlock(&ihdl->sh_lock);
	(void) pthread_mutex_destroy(&ihdl->sh_lock);

	fmev_shdl_free(hdl, hdl, sizeof (*ihdl));

	fmev_api_freetsd();

	return (fmev_seterr(FMEV_SUCCESS));
}
