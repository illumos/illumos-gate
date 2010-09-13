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

#include <sys/types.h>
#include <sys/cmn_err.h>
#include <netinet/in.h>
#include <inet/ip.h>
#include <inet/ip6.h>
#include <sys/crc32.h>

#include <inet/ilb.h>
#include "ilb_impl.h"
#include "ilb_alg.h"

#define	HASH_IP_V4(hash, addr, size) 					\
{									\
	CRC32((hash), &(addr), sizeof (in_addr_t), -1U, crc32_table);	\
	(hash) %= (size);						\
}
#define	HASH_IP_V6(hash, addr, size)					\
	HASH_IP_V4((hash), (addr)->s6_addr32[3], (size))

#define	HASH_IP_PORT_V4(hash, addr, port, size) 			\
{									\
	uint32_t val = (addr) ^ ((port) << 16) ^ (port);		\
	CRC32((hash), &val, sizeof (uint32_t), -1U, crc32_table);	\
	(hash) %= (size);						\
}
#define	HASH_IP_PORT_V6(hash, addr, port, size)				\
	HASH_IP_PORT_V4((hash), (addr)->s6_addr32[3], (port), (size))

#define	HASH_IP_VIP_V4(hash, saddr, daddr, size)			\
{									\
	uint32_t val = (saddr) ^ (daddr);				\
	CRC32((hash), &val, sizeof (uint32_t), -1U, crc32_table);	\
	(hash) %= (size);						\
}
#define	HASH_IP_VIP_V6(hash, saddr, daddr, size) 			\
	HASH_IP_VIP_V4((hash), (saddr)->s6_addr32[3], (daddr)->s6_addr32[3], \
	(size))

#define	INIT_HASH_TBL_SIZE	10

typedef struct {
	ilb_server_t	*server;
	boolean_t	enabled;
} hash_server_t;

/*
 * There are two hash tables.  The hash_tbl holds all servers, both enabled
 * and disabled.  The hash_enabled_tbl only holds enabled servers.  Having
 * two tables allows the hash on a client request remains the same even when
 * some servers are disabled.  If a server is disabled and a client's request
 * hashes to it, we will do another hash.  This time the has is on the enabled
 * server table.
 */
typedef struct hash_s {
	kmutex_t	hash_lock;
	size_t		hash_servers;		/* Total # of servers */
	size_t		hash_tbl_size;		/* All server table size */
	size_t		hash_enabled_servers;	/* # of enabled servers */
	size_t		hash_enabled_tbl_size;	/* Enabled server table size */
	hash_server_t	*hash_tbl;
	hash_server_t	*hash_enabled_tbl;
	ilb_algo_impl_t	hash_type;
} hash_t;

static void hash_fini(ilb_alg_data_t **);

/* ARGSUSED */
static boolean_t
hash_lb(in6_addr_t *saddr, in_port_t sport, in6_addr_t *daddr,
    in_port_t dport, void *alg_data, ilb_server_t **ret_server)
{
	hash_t *hash_alg = (hash_t *)alg_data;
	uint32_t i;

	ASSERT(ret_server != NULL);
	*ret_server = NULL;

	mutex_enter(&hash_alg->hash_lock);

	if (hash_alg->hash_servers == 0) {
		mutex_exit(&hash_alg->hash_lock);
		return (B_FALSE);
	}

	switch (hash_alg->hash_type) {
	case ILB_ALG_IMPL_HASH_IP:
		HASH_IP_V6(i, saddr, hash_alg->hash_servers);
		break;
	case ILB_ALG_IMPL_HASH_IP_SPORT:
		HASH_IP_PORT_V6(i, saddr, sport, hash_alg->hash_servers);
		break;
	case ILB_ALG_IMPL_HASH_IP_VIP:
		HASH_IP_VIP_V6(i, saddr, daddr, hash_alg->hash_servers);
		break;
	default:
		mutex_exit(&hash_alg->hash_lock);
		return (B_FALSE);
	}
	if (hash_alg->hash_tbl[i].enabled) {
		*ret_server = hash_alg->hash_tbl[i].server;
		mutex_exit(&hash_alg->hash_lock);
		return (B_TRUE);
	}

	if (hash_alg->hash_enabled_servers == 0) {
		mutex_exit(&hash_alg->hash_lock);
		return (B_FALSE);
	}

	switch (hash_alg->hash_type) {
	case ILB_ALG_IMPL_HASH_IP:
		HASH_IP_V6(i, saddr, hash_alg->hash_enabled_servers);
		break;
	case ILB_ALG_IMPL_HASH_IP_SPORT:
		HASH_IP_PORT_V6(i, saddr, sport,
		    hash_alg->hash_enabled_servers);
		break;
	case ILB_ALG_IMPL_HASH_IP_VIP:
		HASH_IP_VIP_V6(i, saddr, daddr,
		    hash_alg->hash_enabled_servers);
		break;
	default:
		ASSERT(0);
		break;
	}
	*ret_server = hash_alg->hash_enabled_tbl[i].server;
	mutex_exit(&hash_alg->hash_lock);
	return (B_TRUE);
}

static boolean_t
del_server(hash_server_t *tbl, size_t hash_size, ilb_server_t *host)
{
	size_t i, j;

	for (i = 0; i < hash_size; i++) {
		if (tbl[i].server == host) {
			if (i == hash_size - 1)
				break;
			for (j = i; j < hash_size - 1; j++)
				tbl[j] = tbl[j + 1];
			break;
		}
	}
	/* Not found... */
	if (i == hash_size)
		return (B_FALSE);
	tbl[hash_size - 1].server = NULL;
	tbl[hash_size - 1].enabled = B_FALSE;
	return (B_TRUE);
}

static int
hash_server_del(ilb_server_t *host, void *alg_data)
{
	hash_t *hash_alg = (hash_t *)alg_data;
	boolean_t ret;

	mutex_enter(&hash_alg->hash_lock);

	ret = del_server(hash_alg->hash_tbl, hash_alg->hash_servers, host);
	if (!ret) {
		mutex_exit(&hash_alg->hash_lock);
		return (EINVAL);
	}
	hash_alg->hash_servers--;

	/* The server may not be enabled. */
	ret = del_server(hash_alg->hash_enabled_tbl,
	    hash_alg->hash_enabled_servers, host);
	if (ret)
		hash_alg->hash_enabled_servers--;

	mutex_exit(&hash_alg->hash_lock);
	ILB_SERVER_REFRELE(host);
	return (0);
}

static int
grow_tbl(hash_server_t **hash_tbl, size_t *tbl_size)
{
	size_t mem_size;
	hash_server_t *new_tbl;

	if ((new_tbl = kmem_zalloc(sizeof (hash_server_t) *
	    (*tbl_size + INIT_HASH_TBL_SIZE), KM_NOSLEEP)) == NULL) {
		return (ENOMEM);
	}
	mem_size = *tbl_size * sizeof (hash_server_t);
	bcopy(*hash_tbl, new_tbl, mem_size);
	kmem_free(*hash_tbl, mem_size);
	*hash_tbl = new_tbl;
	*tbl_size += INIT_HASH_TBL_SIZE;
	return (0);
}

static int
hash_server_add(ilb_server_t *host, void *alg_data)
{
	hash_t *hash_alg = (hash_t *)alg_data;
	size_t new_size;

	mutex_enter(&hash_alg->hash_lock);

	/* First add the server to the hash_tbl. */
	new_size = hash_alg->hash_servers + 1;
	if (new_size > hash_alg->hash_tbl_size) {
		if (grow_tbl(&hash_alg->hash_tbl, &hash_alg->hash_tbl_size) !=
		    0) {
			mutex_exit(&hash_alg->hash_lock);
			return (ENOMEM);
		}
	}

	hash_alg->hash_tbl[hash_alg->hash_servers].server = host;
	hash_alg->hash_tbl[hash_alg->hash_servers].enabled = host->iser_enabled;
	hash_alg->hash_servers++;

	if (!host->iser_enabled) {
		mutex_exit(&hash_alg->hash_lock);
		ILB_SERVER_REFHOLD(host);
		return (0);
	}

	/* If the server is enabled, add it to the hasn_enabled_tbl. */
	new_size = hash_alg->hash_enabled_servers + 1;
	if (new_size > hash_alg->hash_enabled_tbl_size) {
		if (grow_tbl(&hash_alg->hash_enabled_tbl,
		    &hash_alg->hash_enabled_tbl_size) != 0) {
			mutex_exit(&hash_alg->hash_lock);
			return (ENOMEM);
		}
	}
	hash_alg->hash_enabled_tbl[hash_alg->hash_enabled_servers].server =
	    host;
	hash_alg->hash_enabled_tbl[hash_alg->hash_enabled_servers].enabled =
	    B_TRUE;
	hash_alg->hash_enabled_servers++;

	mutex_exit(&hash_alg->hash_lock);
	ILB_SERVER_REFHOLD(host);
	return (0);
}

static int
hash_server_enable(ilb_server_t *host, void *alg_data)
{
	hash_t *alg = (hash_t *)alg_data;
	size_t new_size, i;

	mutex_enter(&alg->hash_lock);

	for (i = 0; i < alg->hash_servers; i++) {
		if (alg->hash_tbl[i].server == host) {
			if (alg->hash_tbl[i].enabled) {
				mutex_exit(&alg->hash_lock);
				return (0);
			} else {
				break;
			}
		}
	}
	if (i == alg->hash_servers) {
		mutex_exit(&alg->hash_lock);
		return (EINVAL);
	}

#if DEBUG
	/* The server should not be in the enabled tabled. */
	{
		size_t j;

		for (j = 0; j < alg->hash_enabled_servers; j++) {
			if (alg->hash_enabled_tbl[j].server == host) {
				cmn_err(CE_PANIC, "Corrupted ILB enabled hash "
				    "table");
			}
		}
	}
#endif

	new_size = alg->hash_enabled_servers + 1;
	if (new_size > alg->hash_enabled_tbl_size) {
		if (grow_tbl(&alg->hash_enabled_tbl,
		    &alg->hash_enabled_tbl_size) != 0) {
			mutex_exit(&alg->hash_lock);
			return (ENOMEM);
		}
	}
	alg->hash_tbl[i].enabled = B_TRUE;
	alg->hash_enabled_tbl[alg->hash_enabled_servers].server = host;
	alg->hash_enabled_tbl[alg->hash_enabled_servers].enabled = B_TRUE;
	alg->hash_enabled_servers++;

	mutex_exit(&alg->hash_lock);
	return (0);
}

static int
hash_server_disable(ilb_server_t *host, void *alg_data)
{
	hash_t *alg = (hash_t *)alg_data;
	size_t i;

	mutex_enter(&alg->hash_lock);

	for (i = 0; i < alg->hash_servers; i++) {
		if (alg->hash_tbl[i].server == host) {
			if (!alg->hash_tbl[i].enabled) {
				mutex_exit(&alg->hash_lock);
				return (0);
			} else {
				break;
			}
		}
	}
	if (i == alg->hash_servers) {
		mutex_exit(&alg->hash_lock);
		return (EINVAL);
	}

	alg->hash_tbl[i].enabled = B_FALSE;
#if DEBUG
	ASSERT(del_server(alg->hash_enabled_tbl, alg->hash_enabled_servers,
	    host));
#else
	(void) del_server(alg->hash_enabled_tbl, alg->hash_enabled_servers,
	    host);
#endif
	alg->hash_enabled_servers--;

	mutex_exit(&alg->hash_lock);
	return (0);
}

/* ARGSUSED */
ilb_alg_data_t *
ilb_alg_hash_init(ilb_rule_t *rule, const void *arg)
{
	ilb_alg_data_t	*alg;
	hash_t		*hash_alg;
	int		flags = *(int *)arg;

	if ((alg = kmem_alloc(sizeof (ilb_alg_data_t), KM_NOSLEEP)) == NULL)
		return (NULL);
	if ((hash_alg = kmem_alloc(sizeof (hash_t), KM_NOSLEEP)) == NULL) {
		kmem_free(alg, sizeof (ilb_alg_data_t));
		return (NULL);
	}
	alg->ilb_alg_lb = hash_lb;
	alg->ilb_alg_server_del = hash_server_del;
	alg->ilb_alg_server_add = hash_server_add;
	alg->ilb_alg_server_enable = hash_server_enable;
	alg->ilb_alg_server_disable = hash_server_disable;
	alg->ilb_alg_fini = hash_fini;
	alg->ilb_alg_data = hash_alg;

	mutex_init(&hash_alg->hash_lock, NULL, MUTEX_DEFAULT, NULL);
	hash_alg->hash_type = flags;

	/* Table of all servers */
	hash_alg->hash_servers = 0;
	hash_alg->hash_tbl_size = INIT_HASH_TBL_SIZE;
	hash_alg->hash_tbl = kmem_zalloc(sizeof (hash_server_t) *
	    INIT_HASH_TBL_SIZE, KM_NOSLEEP);
	if (hash_alg->hash_tbl == NULL) {
		kmem_free(hash_alg, sizeof (hash_t));
		kmem_free(alg, sizeof (ilb_alg_data_t));
		return (NULL);
	}

	/* Table of only enabled servers */
	hash_alg->hash_enabled_servers = 0;
	hash_alg->hash_enabled_tbl_size = INIT_HASH_TBL_SIZE;
	hash_alg->hash_enabled_tbl = kmem_zalloc(sizeof (hash_server_t) *
	    INIT_HASH_TBL_SIZE, KM_NOSLEEP);
	if (hash_alg->hash_tbl == NULL) {
		kmem_free(hash_alg->hash_tbl, INIT_HASH_TBL_SIZE *
		    sizeof (ilb_server_t *));
		kmem_free(hash_alg, sizeof (hash_t));
		kmem_free(alg, sizeof (ilb_alg_data_t));
		return (NULL);
	}

	return (alg);
}

static void
hash_fini(ilb_alg_data_t **alg)
{
	hash_t		*hash_alg;
	int		i;

	hash_alg = (*alg)->ilb_alg_data;
	for (i = 0; i < hash_alg->hash_servers; i++)
		ILB_SERVER_REFRELE(hash_alg->hash_tbl[i].server);

	kmem_free(hash_alg->hash_tbl, sizeof (hash_server_t) *
	    hash_alg->hash_tbl_size);
	kmem_free(hash_alg->hash_enabled_tbl, sizeof (hash_server_t) *
	    hash_alg->hash_enabled_tbl_size);
	kmem_free(hash_alg, sizeof (hash_t));
	kmem_free(*alg, sizeof (ilb_alg_data_t));
	*alg = NULL;
}
