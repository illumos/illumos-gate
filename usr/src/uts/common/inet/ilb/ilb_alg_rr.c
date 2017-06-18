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

#include <sys/errno.h>
#include <sys/sysmacros.h>
#include <sys/debug.h>
#include <sys/kmem.h>
#include <sys/list.h>
#include <net/if.h>
#include <netinet/in.h>
#include <inet/ilb.h>
#include "ilb_impl.h"
#include "ilb_alg.h"

typedef struct {
	ilb_server_t	*server;
	boolean_t	enabled;
	list_node_t	list;
} rr_server_t;

typedef struct rr_s {
	kmutex_t	rr_lock;
	list_t		rr_servers;
	rr_server_t	*rr_next;
} rr_t;

static void rr_fini(ilb_alg_data_t **);

/* ARGSUSED */
static boolean_t
rr_lb(in6_addr_t *saddr, in_port_t sport, in6_addr_t *daddr,
    in_port_t dport, void *alg_data, ilb_server_t **ret_server)
{
	rr_t *rr_alg = (rr_t *)alg_data;
	list_t *servers;
	rr_server_t *start;

	ASSERT(ret_server != NULL);
	*ret_server = NULL;

	mutex_enter(&rr_alg->rr_lock);
	servers = &rr_alg->rr_servers;
	if (list_is_empty(servers)) {
		mutex_exit(&rr_alg->rr_lock);
		return (B_FALSE);
	}
	if (rr_alg->rr_next == NULL)
		rr_alg->rr_next = list_head(servers);
	start = rr_alg->rr_next;
	while (!rr_alg->rr_next->enabled) {
		rr_alg->rr_next = list_next(servers, rr_alg->rr_next);
		if (rr_alg->rr_next == NULL)
			rr_alg->rr_next = list_head(servers);
		if (rr_alg->rr_next == start) {
			mutex_exit(&rr_alg->rr_lock);
			return (B_FALSE);
		}
	}

	*ret_server = rr_alg->rr_next->server;
	rr_alg->rr_next = list_next(servers, rr_alg->rr_next);
	mutex_exit(&rr_alg->rr_lock);
	return (B_TRUE);
}

static int
rr_server_del(ilb_server_t *host, void *alg_data)
{
	rr_t *rr_alg = (rr_t *)alg_data;
	list_t *servers = &rr_alg->rr_servers;
	rr_server_t *tmp_server;

	mutex_enter(&rr_alg->rr_lock);
	for (tmp_server = list_head(servers); tmp_server != NULL;
	    tmp_server = list_next(servers, tmp_server)) {
		if (tmp_server->server == host) {
			if (rr_alg->rr_next == tmp_server) {
				rr_alg->rr_next = list_next(servers,
				    tmp_server);
			}
			list_remove(servers, tmp_server);
			break;
		}
	}
	mutex_exit(&rr_alg->rr_lock);
	if (tmp_server == NULL)
		return (EINVAL);
	kmem_free(tmp_server, sizeof (rr_server_t));

	ILB_SERVER_REFRELE(host);
	return (0);
}

static int
rr_server_add(ilb_server_t *host, void *alg_data)
{
	rr_t *rr_alg = (rr_t *)alg_data;
	rr_server_t *new_server;

	new_server = kmem_alloc(sizeof (rr_server_t), KM_NOSLEEP);
	if (new_server == NULL)
		return (ENOMEM);
	new_server->server = host;
	new_server->enabled = host->iser_enabled;

	mutex_enter(&rr_alg->rr_lock);
	list_insert_head(&rr_alg->rr_servers, new_server);
	mutex_exit(&rr_alg->rr_lock);

	ILB_SERVER_REFHOLD(host);
	return (0);
}

static int
rr_server_toggle(list_t *servers, ilb_server_t *host, boolean_t value)
{
	rr_server_t *tmp_server;

	if (list_is_empty(servers))
		return (EINVAL);

	for (tmp_server = list_head(servers); tmp_server != NULL;
	    tmp_server = list_next(servers, tmp_server)) {
		if (tmp_server->server == host) {
			tmp_server->enabled = value;
			break;
		}
	}
	if (tmp_server != NULL)
		return (0);
	else
		return (EINVAL);
}

static int
rr_server_enable(ilb_server_t *host, void *alg_data)
{
	rr_t *rr_alg = (rr_t *)alg_data;
	list_t *servers;
	int ret;

	mutex_enter(&rr_alg->rr_lock);
	servers = &rr_alg->rr_servers;
	ret = rr_server_toggle(servers, host, B_TRUE);
	mutex_exit(&rr_alg->rr_lock);
	return (ret);
}

static int
rr_server_disable(ilb_server_t *host, void *alg_data)
{
	rr_t *rr_alg = (rr_t *)alg_data;
	list_t *servers;
	int ret;

	mutex_enter(&rr_alg->rr_lock);
	servers = &rr_alg->rr_servers;
	ret = rr_server_toggle(servers, host, B_FALSE);
	mutex_exit(&rr_alg->rr_lock);
	return (ret);
}

/* ARGSUSED */
ilb_alg_data_t *
ilb_alg_rr_init(ilb_rule_t *rule, void *arg)
{
	ilb_alg_data_t	*alg;
	rr_t		*rr_alg;

	if ((alg = kmem_alloc(sizeof (ilb_alg_data_t), KM_NOSLEEP)) == NULL)
		return (NULL);
	if ((rr_alg = kmem_alloc(sizeof (rr_t), KM_NOSLEEP)) == NULL) {
		kmem_free(alg, sizeof (ilb_alg_data_t));
		return (NULL);
	}

	alg->ilb_alg_lb = rr_lb;
	alg->ilb_alg_server_del = rr_server_del;
	alg->ilb_alg_server_add = rr_server_add;
	alg->ilb_alg_server_enable = rr_server_enable;
	alg->ilb_alg_server_disable = rr_server_disable;
	alg->ilb_alg_fini = rr_fini;
	alg->ilb_alg_data = rr_alg;

	mutex_init(&rr_alg->rr_lock, NULL, MUTEX_DEFAULT, NULL);
	list_create(&rr_alg->rr_servers, sizeof (rr_server_t),
	    offsetof(rr_server_t, list));
	rr_alg->rr_next = NULL;

	return (alg);
}

static void
rr_fini(ilb_alg_data_t **alg)
{
	rr_t		*rr_alg;
	rr_server_t	*tmp_server;
	list_t		*servers;

	rr_alg = (*alg)->ilb_alg_data;
	servers = &rr_alg->rr_servers;
	while ((tmp_server = list_head(servers)) != NULL) {
		list_remove(servers, tmp_server);
		ILB_SERVER_REFRELE(tmp_server->server);
		kmem_free(tmp_server, sizeof (rr_server_t));
	}
	list_destroy(servers);
	kmem_free(rr_alg, sizeof (rr_t));
	kmem_free(*alg, sizeof (ilb_alg_data_t));
	*alg = NULL;
}
