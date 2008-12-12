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

#include <sys/sysmacros.h>
#include <sys/atomic.h>
#include <sys/strsubr.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/cmn_err.h>
#include <sys/modctl.h>
#include <sys/sdt.h>

list_t smod_list;
kmutex_t smod_list_lock;

so_create_func_t sock_comm_create_function;
so_destroy_func_t sock_comm_destroy_function;

static smod_info_t *smod_create(const char *);
static void smod_destroy(smod_info_t *);

extern void smod_add(smod_info_t *);

void
smod_init(void)
{
	list_create(&smod_list, sizeof (smod_info_t),
	    offsetof(smod_info_t, smod_node));
	mutex_init(&smod_list_lock, NULL, MUTEX_DEFAULT, NULL);
}

static smod_info_t *
smod_find(const char *modname)
{
	smod_info_t *smodp;

	ASSERT(MUTEX_HELD(&smod_list_lock));

	for (smodp = list_head(&smod_list); smodp != NULL;
	    smodp = list_next(&smod_list, smodp))
		if (strcmp(smodp->smod_name, modname) == 0)
			return (smodp);
	return (NULL);
}

/*
 * Register the socket module.
 */
int
smod_register(const smod_reg_t *reg)
{
	smod_info_t	*smodp;

	/*
	 * Make sure the socket module does not depend on capabilities
	 * not available on the system.
	 */
	if (reg->smod_version != SOCKMOD_VERSION ||
	    reg->smod_dc_version != SOCK_DC_VERSION ||
	    reg->smod_uc_version != SOCK_UC_VERSION) {
		cmn_err(CE_WARN,
		    "Failed to register socket module %s: version mismatch",
		    reg->smod_name);
		return (EINVAL);
	}

#ifdef DEBUG
	mutex_enter(&smod_list_lock);
	if ((smodp = smod_find(reg->smod_name)) != NULL) {
		mutex_exit(&smod_list_lock);
		return (EEXIST);
	}
	mutex_exit(&smod_list_lock);
#endif

	smodp = smod_create(reg->smod_name);
	smodp->smod_version = reg->smod_version;
	if (strcmp(smodp->smod_name, SOTPI_SMOD_NAME) == 0 ||
	    strcmp(smodp->smod_name, "socksctp") == 0 ||
	    strcmp(smodp->smod_name, "socksdp") == 0) {
		ASSERT(smodp->smod_proto_create_func == NULL);
		ASSERT(reg->__smod_priv != NULL);
		smodp->smod_sock_create_func =
		    reg->__smod_priv->smodp_sock_create_func;
		smodp->smod_sock_destroy_func =
		    reg->__smod_priv->smodp_sock_destroy_func;
		smodp->smod_proto_create_func = NULL;
	} else {
		if (reg->smod_proto_create_func == NULL ||
		    (reg->__smod_priv != NULL &&
		    (reg->__smod_priv->smodp_sock_create_func != NULL ||
		    reg->__smod_priv->smodp_sock_destroy_func != NULL))) {
#ifdef DEBUG
			cmn_err(CE_CONT, "smod_register of %s failed",
			    smodp->smod_name);
#endif
			smod_destroy(smodp);
			return (EINVAL);
		}
		smodp->smod_proto_create_func = reg->smod_proto_create_func;
		smodp->smod_sock_create_func = sock_comm_create_function;
		smodp->smod_sock_destroy_func = sock_comm_destroy_function;
		smodp->smod_uc_version = reg->smod_uc_version;
		smodp->smod_dc_version = reg->smod_dc_version;
		if (reg->__smod_priv != NULL) {
			smodp->smod_proto_fallback_func =
			    reg->__smod_priv->smodp_proto_fallback_func;
		}
	}
	smod_add(smodp);
	return (0);
}

/*
 * Unregister the socket module
 */
int
smod_unregister(const char *mod_name)
{
	smod_info_t 	*smodp;

	mutex_enter(&smod_list_lock);
	if ((smodp = smod_find(mod_name)) != NULL) {
		if (smodp->smod_refcnt != 0) {
			mutex_exit(&smod_list_lock);
			return (EBUSY);
		} else {
			/*
			 * Delete the entry from the socket module list.
			 */
			list_remove(&smod_list, smodp);
			mutex_exit(&smod_list_lock);

			smod_destroy(smodp);
			return (0);
		}
	}
	mutex_exit(&smod_list_lock);

	return (ENXIO);
}

/*
 * Initialize the socket module entry.
 */
static smod_info_t *
smod_create(const char *modname)
{
	smod_info_t *smodp;
	int len;

	smodp = kmem_zalloc(sizeof (*smodp), KM_SLEEP);
	len = strlen(modname) + 1;
	smodp->smod_name = kmem_alloc(len, KM_SLEEP);
	bcopy(modname, smodp->smod_name, len);
	smodp->smod_name[len - 1] = '\0';
	return (smodp);
}

/*
 * Clean up the socket module part of the sockparams entry.
 */
static void
smod_destroy(smod_info_t *smodp)
{
	ASSERT(smodp->smod_name != NULL);
	ASSERT(smodp->smod_refcnt == 0);
	ASSERT(!list_link_active(&smodp->smod_node));
	ASSERT(strcmp(smodp->smod_name, "socktpi") != 0);

	kmem_free(smodp->smod_name, strlen(smodp->smod_name) + 1);
	smodp->smod_name = NULL;
	smodp->smod_proto_create_func = NULL;
	smodp->smod_sock_create_func = NULL;
	smodp->smod_sock_destroy_func = NULL;
	kmem_free(smodp, sizeof (*smodp));
}

/*
 * Add an entry at the front of the socket module list.
 */
void
smod_add(smod_info_t *smodp)
{
	ASSERT(smodp != NULL);
	mutex_enter(&smod_list_lock);
	list_insert_head(&smod_list, smodp);
	mutex_exit(&smod_list_lock);
}

/*
 * Lookup the socket module table by the socket module name.
 * If there is an existing entry, then increase the reference count.
 * Otherwise we load the module and in the module register function create
 * a new entry and add it to the end of the socket module table.
 */
smod_info_t *
smod_lookup_byname(const char *modname)
{
	smod_info_t *smodp;
	int error;

again:
	/*
	 * If find an entry, increase the reference count and
	 * return the entry pointer.
	 */
	mutex_enter(&smod_list_lock);
	if ((smodp = smod_find(modname)) != NULL) {
		SMOD_INC_REF(smodp);
		mutex_exit(&smod_list_lock);
		return (smodp);
	}
	mutex_exit(&smod_list_lock);

	/*
	 * We have a sockmod, and it is not loaded.
	 * Load the module into the kernel, modload() will
	 * take care of the multiple threads.
	 */
	DTRACE_PROBE1(load__socket__module, char *, modname);
	error = modload(SOCKMOD_PATH, modname);
	if (error == -1) {
		cmn_err(CE_CONT, "modload of %s/%s failed",
		    SOCKMOD_PATH, modname);
		return (NULL);
	}
	goto again;
}
