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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * MD Event Generator (MDEG) Module
 */

#include <sys/machsystm.h>
#include <sys/taskq.h>
#include <sys/disp.h>
#include <sys/cmn_err.h>
#include <sys/note.h>

#include <sys/mdeg.h>
#include <sys/mach_descrip.h>
#include <sys/mdesc.h>

/*
 * A single client registration
 */
typedef struct mdeg_clnt {
	boolean_t		valid;		/* structure is in active use */
	mdeg_node_match_t	*nmatch;	/* node match filter */
	mdeg_node_spec_t	*pspec;		/* parent match filter */
	mdeg_cb_t		cb;		/* the client callback */
	caddr_t			cb_arg;		/* argument to the callback */
	uint64_t		magic;		/* sanity checking magic */
	mdeg_handle_t		hdl;		/* handle assigned by MDEG */
} mdeg_clnt_t;

/*
 * Global MDEG data
 *
 * Locking Strategy:
 *
 *   mdeg.lock - lock used to synchronize system-wide MD updates. An
 *	MD update must be treated as an atomic event. The lock is
 *	taken when notification that a new MD is available and held
 *	until all clients have been notified.
 *
 *   mdeg.rwlock - lock used to synchronize access to the table of
 *	registered clients. The reader lock must be held when looking
 *	up client information in the table. The writer lock must be
 *	held when modifying any client information.
 */
static struct mdeg {
	taskq_t		*taskq;		/* for internal processing */
	boolean_t	enabled;	/* enable/disable taskq processing */
	kmutex_t	lock;		/* synchronize MD updates */
	md_t		*md_prev;	/* previous MD */
	md_t		*md_curr;	/* current MD */
	mdeg_clnt_t	*tbl;		/* table of registered clients */
	krwlock_t	rwlock;		/* client table lock */
	uint_t		maxclnts;	/* client table size */
	uint_t		nclnts;		/* current number of clients */
} mdeg;

/*
 * Debugging routines
 */
#ifdef DEBUG
uint_t mdeg_debug = 0x0;

static void mdeg_dump_clnt(mdeg_clnt_t *clnt);
static void mdeg_dump_table(void);

#define	MDEG_DBG		if (mdeg_debug) printf
#define	MDEG_DUMP_CLNT		mdeg_dump_clnt
#define	MDEG_DUMP_TABLE		mdeg_dump_table

#else /* DEBUG */

#define	MDEG_DBG		_NOTE(CONSTCOND) if (0) printf
#define	MDEG_DUMP_CLNT(...)
#define	MDEG_DUMP_TABLE(...)

#endif /* DEBUG */

/*
 * Global constants
 */
#define	MDEG_MAX_TASKQ_THR	512	/* maximum number of taskq threads */
#define	MDEG_MAX_CLNTS_INIT	64	/* initial client table size */

#define	MDEG_MAGIC		0x4D4445475F48444Cull	/* 'MDEG_HDL' */

/*
 * A client handle is a 64 bit value with two pieces of
 * information encoded in it. The upper 32 bits are the
 * index into the table of a particular client structure.
 * The lower 32 bits are a counter that is incremented
 * each time a client structure is reused.
 */
#define	MDEG_IDX_SHIFT			32
#define	MDEG_COUNT_MASK			0xfffffffful

#define	MDEG_ALLOC_HDL(_idx, _count)	(((uint64_t)_idx << MDEG_IDX_SHIFT) | \
					((uint64_t)(_count + 1) &	      \
					MDEG_COUNT_MASK))
#define	MDEG_HDL2IDX(hdl)		(hdl >> MDEG_IDX_SHIFT)
#define	MDEG_HDL2COUNT(hdl)		(hdl & MDEG_COUNT_MASK)

static const char trunc_str[] = " ... }";

/*
 * Utility routines
 */
static mdeg_clnt_t *mdeg_alloc_clnt(void);
static void mdeg_notify_client(void *);
static mde_cookie_t mdeg_find_start_node(md_t *, mdeg_node_spec_t *);
static boolean_t mdeg_node_spec_match(md_t *, mde_cookie_t, mdeg_node_spec_t *);
static void mdeg_get_diff_results(md_diff_cookie_t, mdeg_result_t *);

int
mdeg_init(void)
{
	int	tblsz;

	/*
	 * Grab the current MD
	 */
	if ((mdeg.md_curr = md_get_handle()) == NULL) {
		cmn_err(CE_WARN, "unable to cache snapshot of MD");
		return (-1);
	}

	/*
	 * Initialize table of registered clients
	 */
	mdeg.maxclnts = MDEG_MAX_CLNTS_INIT;

	tblsz = mdeg.maxclnts * sizeof (mdeg_clnt_t);
	mdeg.tbl = kmem_zalloc(tblsz, KM_SLEEP);

	rw_init(&mdeg.rwlock, NULL, RW_DRIVER, NULL);

	mdeg.nclnts = 0;

	/*
	 * Initialize global lock
	 */
	mutex_init(&mdeg.lock, NULL, MUTEX_DRIVER, NULL);

	/*
	 * Initialize the task queue
	 */
	mdeg.taskq = taskq_create("mdeg_taskq", 1, minclsyspri, 1,
	    MDEG_MAX_TASKQ_THR, TASKQ_PREPOPULATE | TASKQ_DYNAMIC);

	/* ready to begin handling clients */
	mdeg.enabled = B_TRUE;

	return (0);
}

void
mdeg_fini(void)
{
	/*
	 * Flip the enabled switch off to make sure that
	 * no events get dispatched while things are being
	 * torn down.
	 */
	mdeg.enabled = B_FALSE;

	/* destroy the task queue */
	taskq_destroy(mdeg.taskq);

	/*
	 * Deallocate the table of registered clients
	 */
	kmem_free(mdeg.tbl, mdeg.maxclnts * sizeof (mdeg_clnt_t));
	rw_destroy(&mdeg.rwlock);

	/*
	 * Free up the cached MDs.
	 */
	if (mdeg.md_curr)
		(void) md_fini_handle(mdeg.md_curr);

	if (mdeg.md_prev)
		(void) md_fini_handle(mdeg.md_prev);

	mutex_destroy(&mdeg.lock);
}

static mdeg_clnt_t *
mdeg_alloc_clnt(void)
{
	mdeg_clnt_t	*clnt;
	int		idx;
	mdeg_clnt_t	*newtbl;
	uint_t		newmaxclnts;
	uint_t		newtblsz;
	uint_t		oldtblsz;

	ASSERT(RW_WRITE_HELD(&mdeg.rwlock));

	/* search for an unused slot in the table */
	for (idx = 0; idx < mdeg.maxclnts; idx++) {
		clnt = &mdeg.tbl[idx];
		if (!clnt->valid) {
			break;
		}
	}

	/* found any empty slot */
	if (idx != mdeg.maxclnts) {
		goto found;
	}

	/*
	 * There was no free space in the table. Grow
	 * the table to double its current size.
	 */

	MDEG_DBG("client table full:\n");
	MDEG_DUMP_TABLE();

	newmaxclnts = mdeg.maxclnts * 2;
	newtblsz = newmaxclnts * sizeof (mdeg_clnt_t);

	newtbl = kmem_zalloc(newtblsz, KM_SLEEP);

	/* copy old table data to the new table */
	oldtblsz = mdeg.maxclnts * sizeof (mdeg_clnt_t);
	bcopy(mdeg.tbl, newtbl, oldtblsz);

	/*
	 * Since the old table was full, the first free entry
	 * will be just past the end of the old table data in
	 * the new table.
	 */
	clnt = &newtbl[mdeg.maxclnts];

	/* clean up the old table */
	kmem_free(mdeg.tbl, oldtblsz);
	mdeg.tbl = newtbl;
	mdeg.maxclnts = newmaxclnts;

found:
	ASSERT(clnt->valid == 0);

	clnt->hdl = MDEG_ALLOC_HDL(idx, MDEG_HDL2COUNT(clnt->hdl));

	return (clnt);
}

static mdeg_clnt_t *
mdeg_get_client(mdeg_handle_t hdl)
{
	int		idx;
	mdeg_clnt_t	*clnt;

	idx = MDEG_HDL2IDX(hdl);

	/* check if index is out of bounds */
	if ((idx < 0) || (idx >= mdeg.maxclnts)) {
		MDEG_DBG("mdeg_get_client: index out of bounds\n");
		return (NULL);
	}

	clnt = &mdeg.tbl[idx];

	/* check for a valid client */
	if (!clnt->valid) {
		MDEG_DBG("mdeg_get_client: client is not valid\n");
		return (NULL);
	}

	/* make sure the handle is an exact match */
	if (clnt->hdl != hdl) {
		MDEG_DBG("mdeg_get_client: bad handle\n");
		return (NULL);
	}

	if (clnt->magic != MDEG_MAGIC) {
		MDEG_DBG("mdeg_get_client: bad magic\n");
		return (NULL);
	}

	return (clnt);
}

/*
 * Send a notification to a client immediately after it registers.
 * The result_t is a list of all the nodes that match their specified
 * nodes of interest, all returned on the added list. This serves
 * as a base of reference to the client. All future MD updates are
 * relative to this list.
 */
static int
mdeg_notify_client_reg(mdeg_clnt_t *clnt)
{
	md_t			*mdp = NULL;
	mde_str_cookie_t	nname;
	mde_str_cookie_t	aname;
	mde_cookie_t		startnode;
	int			nnodes;
	int			nodechk;
	mde_cookie_t		*listp = NULL;
	mdeg_result_t		*mdeg_res = NULL;
	int			rv = MDEG_SUCCESS;

	mutex_enter(&mdeg.lock);

	/*
	 * Handle the special case where the node specification
	 * is NULL. In this case, call the client callback without
	 * any results. All processing is left to the client.
	 */
	if (clnt->pspec == NULL) {
		/* call the client callback */
		(void) (*clnt->cb)(clnt->cb_arg, NULL);
		goto done;
	}

	if ((mdp = md_get_handle()) == NULL) {
		cmn_err(CE_WARN, "unable to retrieve current MD");
		rv = MDEG_FAILURE;
		goto done;
	}

	startnode = mdeg_find_start_node(mdp, clnt->pspec);
	if (startnode == MDE_INVAL_ELEM_COOKIE) {
		/* not much we can do */
		cmn_err(CE_WARN, "unable to match node specifier");
		rv = MDEG_FAILURE;
		goto done;
	}

	/*
	 * Use zalloc to provide correct default values for the
	 * unused removed, match_prev, and match_curr lists.
	 */
	mdeg_res = kmem_zalloc(sizeof (mdeg_result_t), KM_SLEEP);

	nname = md_find_name(mdp, clnt->nmatch->namep);
	aname = md_find_name(mdp, "fwd");

	nnodes = md_scan_dag(mdp, startnode, nname, aname, NULL);

	if (nnodes == 0) {
		MDEG_DBG("mdeg_notify_client_reg: no nodes of interest\n");
		rv = MDEG_SUCCESS;
		goto done;
	} else if (nnodes == -1) {
		MDEG_DBG("error scanning DAG\n");
		rv = MDEG_FAILURE;
		goto done;
	}

	MDEG_DBG("mdeg_notify_client_reg: %d node%s of interest\n",
	    nnodes, (nnodes == 1) ? "" : "s");

	/* get the list of nodes of interest */
	listp = kmem_alloc(sizeof (mde_cookie_t) * nnodes, KM_SLEEP);
	nodechk = md_scan_dag(mdp, startnode, nname, aname, listp);

	ASSERT(nodechk == nnodes);

	mdeg_res->added.mdp = mdp;
	mdeg_res->added.mdep = listp;
	mdeg_res->added.nelem = nnodes;

	/* call the client callback */
	(void) (*clnt->cb)(clnt->cb_arg, mdeg_res);

done:
	mutex_exit(&mdeg.lock);

	if (mdp)
		(void) md_fini_handle(mdp);

	if (listp)
		kmem_free(listp, sizeof (mde_cookie_t) * nnodes);

	if (mdeg_res)
		kmem_free(mdeg_res, sizeof (mdeg_result_t));

	return (rv);
}

/*
 * Register to receive an event notification when the system
 * machine description is updated.
 *
 * Passing NULL for the node specification parameter is valid
 * as long as the match specification is also NULL. In this
 * case, the client will receive a notification when the MD
 * has been updated, but the callback will not include any
 * information. The client is then responsible for obtaining
 * its own copy of the system MD and performing any processing
 * manually.
 */
int
mdeg_register(mdeg_node_spec_t *pspecp, mdeg_node_match_t *nmatchp,
    mdeg_cb_t cb, void *cb_arg, mdeg_handle_t *hdlp)
{
	mdeg_clnt_t	*clnt;

	/* should never be called from a callback */
	ASSERT(!taskq_member(mdeg.taskq, curthread));

	/* node spec and node match must both be valid, or both NULL */
	if (((pspecp != NULL) && (nmatchp == NULL)) ||
	    ((pspecp == NULL) && (nmatchp != NULL))) {
		MDEG_DBG("mdeg_register: invalid parameters\n");
		return (MDEG_FAILURE);
	}

	rw_enter(&mdeg.rwlock, RW_WRITER);

	clnt = mdeg_alloc_clnt();

	ASSERT(clnt);

	/*
	 * Fill in the rest of the data
	 */
	clnt->nmatch = nmatchp;
	clnt->pspec = pspecp;
	clnt->cb = cb;
	clnt->cb_arg = cb_arg;
	clnt->magic = MDEG_MAGIC;

	/* do this last */
	clnt->valid = B_TRUE;

	MDEG_DBG("client registered (0x%lx):\n", clnt->hdl);
	MDEG_DUMP_CLNT(clnt);

	mdeg.nclnts++;

	if (mdeg_notify_client_reg(clnt) != MDEG_SUCCESS) {
		bzero(clnt, sizeof (mdeg_clnt_t));
		rw_exit(&mdeg.rwlock);
		return (MDEG_FAILURE);
	}

	rw_exit(&mdeg.rwlock);

	*hdlp = clnt->hdl;

	return (MDEG_SUCCESS);
}

int
mdeg_unregister(mdeg_handle_t hdl)
{
	mdeg_clnt_t	*clnt;
	mdeg_handle_t	mdh;

	/* should never be called from a callback */
	ASSERT(!taskq_member(mdeg.taskq, curthread));

	rw_enter(&mdeg.rwlock, RW_WRITER);

	/* lookup the client */
	if ((clnt = mdeg_get_client(hdl)) == NULL) {
		rw_exit(&mdeg.rwlock);
		return (MDEG_FAILURE);
	}

	MDEG_DBG("client unregistered (0x%lx):\n", hdl);
	MDEG_DUMP_CLNT(clnt);

	/* save the handle to prevent reuse */
	mdh = clnt->hdl;
	bzero(clnt, sizeof (mdeg_clnt_t));

	clnt->hdl = mdh;

	mdeg.nclnts--;

	rw_exit(&mdeg.rwlock);

	return (MDEG_SUCCESS);
}

/*
 * Simple algorithm for now, grab the global lock and let all
 * the clients update themselves in parallel. There is a lot of
 * room for improvement here. We could eliminate some scans of
 * the DAG by incrementally scanning at lower levels of the DAG
 * rather than having each client start its own scan from the root.
 */
void
mdeg_notify_clients(void)
{
	md_t		*md_new;
	mdeg_clnt_t	*clnt;
	int		idx;
	int		nclnt;

	rw_enter(&mdeg.rwlock, RW_READER);
	mutex_enter(&mdeg.lock);

	/*
	 * Rotate the MDs
	 */
	if ((md_new = md_get_handle()) == NULL) {
		cmn_err(CE_WARN, "unable to retrieve new MD");
		goto done;
	}

	if (mdeg.md_prev) {
		(void) md_fini_handle(mdeg.md_prev);
	}

	mdeg.md_prev = mdeg.md_curr;
	mdeg.md_curr = md_new;

	if (mdeg.nclnts == 0) {
		MDEG_DBG("mdeg_notify_clients: no clients registered\n");
		goto done;
	}

	/* dispatch the update notification to all clients */
	for (idx = 0, nclnt = 0; idx < mdeg.maxclnts; idx++) {
		clnt = &mdeg.tbl[idx];

		if (!clnt->valid)
			continue;

		MDEG_DBG("notifying client 0x%lx (%d/%d)\n", clnt->hdl,
		    ++nclnt, mdeg.nclnts);

		(void) taskq_dispatch(mdeg.taskq, mdeg_notify_client,
		    (void *)clnt, TQ_SLEEP);
	}

	/*
	 * Wait for all mdeg_notify_client notifications to
	 * finish while we are still holding mdeg.rwlock.
	 */
	taskq_wait(mdeg.taskq);

done:
	mutex_exit(&mdeg.lock);
	rw_exit(&mdeg.rwlock);
}

static void
mdeg_notify_client(void *arg)
{
	mdeg_clnt_t		*clnt = (mdeg_clnt_t *)arg;
	md_diff_cookie_t	mdd = MD_INVAL_DIFF_COOKIE;
	mdeg_result_t		mdeg_res;
	mde_cookie_t		md_prev_start;
	mde_cookie_t		md_curr_start;

	/*
	 * mdeg.rwlock must be held as a reader while this function
	 * executes. However, we do not need to acquire the lock as a
	 * reader here because it is held as a reader by the thread
	 * executing mdeg_notify_clients which triggers the execution
	 * of this function from a taskq. Since mdeg_notify_clients
	 * holds the lock as a reader until the taskq callbacks have
	 * completed, it will be held for the life of this function call.
	 * Furthermore, we must not attempt to acquire the lock as a
	 * reader with rw_enter because if there is a pending writer,
	 * we will block, creating a circular deadlock with this function,
	 * the writer, and mdeg_notify_clients. Since we do not need
	 * to acquire the lock, just assert that it is held.
	 */
	ASSERT(RW_READ_HELD(&mdeg.rwlock));

	if (!mdeg.enabled) {
		/* trying to shutdown */
		MDEG_DBG("mdeg_notify_client: mdeg disabled, aborting\n");
		goto cleanup;
	}

	/*
	 * Handle the special case where the node specification
	 * is NULL. In this case, call the client callback without
	 * any results. All processing is left to the client.
	 */
	if (clnt->pspec == NULL) {
		/* call the client callback */
		(void) (*clnt->cb)(clnt->cb_arg, NULL);

		MDEG_DBG("MDEG client callback done\n");
		goto cleanup;
	}

	/* find our start nodes */
	md_prev_start = mdeg_find_start_node(mdeg.md_prev, clnt->pspec);
	if (md_prev_start == MDE_INVAL_ELEM_COOKIE) {
		goto cleanup;
	}

	md_curr_start = mdeg_find_start_node(mdeg.md_curr, clnt->pspec);
	if (md_curr_start == MDE_INVAL_ELEM_COOKIE) {
		goto cleanup;
	}

	/* diff the MDs */
	mdd = md_diff_init(mdeg.md_prev, md_prev_start, mdeg.md_curr,
	    md_curr_start, clnt->nmatch->namep, clnt->nmatch->matchp);

	if (mdd == MD_INVAL_DIFF_COOKIE) {
		MDEG_DBG("unable to diff MDs\n");
		goto cleanup;
	}

	/*
	 * Cache the results of the diff
	 */
	mdeg_get_diff_results(mdd, &mdeg_res);

	/* call the client callback */
	(void) (*clnt->cb)(clnt->cb_arg, &mdeg_res);

	MDEG_DBG("MDEG client callback done\n");

cleanup:
	if (mdd != MD_INVAL_DIFF_COOKIE)
		(void) md_diff_fini(mdd);
}

static mde_cookie_t
mdeg_find_start_node(md_t *md, mdeg_node_spec_t *nspec)
{
	mde_cookie_t		*nodesp;
	mde_str_cookie_t	nname;
	mde_str_cookie_t	aname;
	int			nnodes;
	int			idx;

	if ((md == NULL) || (nspec == NULL))
		return (MDE_INVAL_ELEM_COOKIE);

	nname = md_find_name(md, nspec->namep);
	aname = md_find_name(md, "fwd");

	nnodes = md_scan_dag(md, 0, nname, aname, NULL);
	if (nnodes == 0)
		return (MDE_INVAL_ELEM_COOKIE);

	nodesp = kmem_alloc(sizeof (mde_cookie_t) * nnodes, KM_SLEEP);

	(void) md_scan_dag(md, 0, nname, aname, nodesp);

	for (idx = 0; idx < nnodes; idx++) {

		if (mdeg_node_spec_match(md, nodesp[idx], nspec)) {
			mde_cookie_t res = nodesp[idx];

			kmem_free(nodesp, sizeof (mde_cookie_t) * nnodes);
			return (res);
		}
	}

	kmem_free(nodesp, sizeof (mde_cookie_t) * nnodes);
	return (MDE_INVAL_ELEM_COOKIE);
}

static boolean_t
mdeg_node_spec_match(md_t *md, mde_cookie_t node, mdeg_node_spec_t *nspec)
{
	mdeg_prop_spec_t	*prop;

	ASSERT(md && nspec);
	ASSERT(node != MDE_INVAL_ELEM_COOKIE);

	prop = nspec->specp;

	while (prop->type != MDET_LIST_END) {

		switch (prop->type) {
		case MDET_PROP_VAL: {
			uint64_t val;

			if (md_get_prop_val(md, node, prop->namep, &val) != 0)
				return (B_FALSE);

			if (prop->ps_val != val)
				return (B_FALSE);

			break;
		}
		case MDET_PROP_STR: {
			char	*str;

			if (md_get_prop_str(md, node, prop->namep, &str) != 0)
				return (B_FALSE);

			if (strcmp(prop->ps_str, str) != 0)
				return (B_FALSE);

			break;
		}

		default:
			return (B_FALSE);
		}

		prop++;
	}

	return (B_TRUE);
}

static void
mdeg_get_diff_results(md_diff_cookie_t mdd, mdeg_result_t *res)
{
	/*
	 * Cache added nodes.
	 */
	res->added.mdp = mdeg.md_curr;
	res->added.nelem = md_diff_added(mdd, &(res->added.mdep));

	if (res->added.nelem == -1) {
		bzero(&(res->added), sizeof (mdeg_diff_t));
	}

	/*
	 * Cache removed nodes.
	 */
	res->removed.mdp = mdeg.md_prev;
	res->removed.nelem = md_diff_removed(mdd, &(res->removed.mdep));

	if (res->removed.nelem == -1) {
		bzero(&(res->removed), sizeof (mdeg_diff_t));
	}

	/*
	 * Cache matching node pairs.
	 */
	res->match_curr.mdp = mdeg.md_curr;
	res->match_prev.mdp = mdeg.md_prev;
	res->match_curr.nelem = md_diff_matched(mdd, &(res->match_prev.mdep),
	    &(res->match_curr.mdep));
	res->match_prev.nelem = res->match_curr.nelem;

	if (res->match_prev.nelem == -1) {
		bzero(&(res->match_prev), sizeof (mdeg_diff_t));
		bzero(&(res->match_curr), sizeof (mdeg_diff_t));
	}
}

#ifdef DEBUG
/*
 * Generate a string that represents the node specifier
 * structure. Clamp the string length if the specifier
 * structure contains too much information.
 *
 *	General form:
 *
 *		<nodename>:{<propname>=<propval>,...}
 *	e.g.
 *		vdevice:{name=vsw,reg=0x0}
 */
static void
mdeg_spec_str(mdeg_node_spec_t *spec, char *buf, int len)
{
	mdeg_prop_spec_t	*prop;
	int			offset;
	boolean_t		first = B_TRUE;
	char			*end = buf + len;

	offset = snprintf(buf, len, "%s:{", spec->namep);

	buf += offset;
	len -= offset;
	if (len <= 0)
		goto trunc;

	prop = spec->specp;

	while (prop->type != MDET_LIST_END) {

		switch (prop->type) {
		case MDET_PROP_VAL:
			offset = snprintf(buf, len, "%s%s=0x%lx",
			    (first) ? "" : ",", prop->namep, prop->ps_val);
			buf += offset;
			len -= offset;
			if (len <= 0)
				goto trunc;
			break;

		case MDET_PROP_STR:
			offset = snprintf(buf, len, "%s%s=%s",
			    (first) ? "" : ",", prop->namep, prop->ps_str);
			buf += offset;
			len -= offset;
			if (len <= 0)
				goto trunc;
			break;

		default:
			(void) snprintf(buf, len, "}");
			return;
		}

		if (first)
			first = B_FALSE;
		prop++;
	}

	(void) snprintf(buf, len, "}");
	return;

trunc:
	/* string too long, truncate it */
	buf = end - (strlen(trunc_str) + 1);
	(void) sprintf(buf, trunc_str);
}

/*
 * Generate a string that represents the match structure.
 * Clamp the string length if the match structure contains
 * too much information.
 *
 *	General form:
 *
 *		<nodename>:{<propname>,...}
 *	e.g.
 *		nmatch=vport:{reg}
 */
static void
mdeg_match_str(mdeg_node_match_t *match, char *buf, int len)
{
	md_prop_match_t	*prop;
	int		offset;
	boolean_t	first = B_TRUE;
	char		*end = buf + len;

	offset = snprintf(buf, len, "%s:{", match->namep);

	buf += offset;
	len -= offset;
	if (len <= 0)
		goto trunc;

	prop = match->matchp;

	while (prop->type != MDET_LIST_END) {
		offset = snprintf(buf, len, "%s%s", (first) ? "" : ",",
		    prop->namep);
		buf += offset;
		len -= offset;
		if (len <= 0)
			goto trunc;

		if (first)
			first = B_FALSE;
		prop++;
	}

	(void) snprintf(buf, len, "}");
	return;

trunc:
	/* string too long, truncate it */
	buf = end - (strlen(trunc_str) + 1);
	(void) sprintf(buf, trunc_str);
}

#define	MAX_FIELD_STR	80

static void
mdeg_dump_clnt(mdeg_clnt_t *clnt)
{
	char	str[MAX_FIELD_STR] = "";

	if (!clnt->valid) {
		MDEG_DBG("  valid=B_FALSE\n");
		return;
	}

	if (clnt->pspec) {
		mdeg_spec_str(clnt->pspec, str, MAX_FIELD_STR);
		MDEG_DBG("  pspecp=%s\n", str);
	}

	if (clnt->nmatch) {
		mdeg_match_str(clnt->nmatch, str, MAX_FIELD_STR);
		MDEG_DBG("  nmatch=%s\n", str);
	}
}

static void
mdeg_dump_table(void)
{
	int		idx;
	mdeg_clnt_t	*clnt;

	for (idx = 0; idx < mdeg.maxclnts; idx++) {
		clnt = &(mdeg.tbl[idx]);

		MDEG_DBG("client %d (0x%lx):\n", idx, clnt->hdl);
		mdeg_dump_clnt(clnt);
	}
}
#endif /* DEBUG */
