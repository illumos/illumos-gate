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
 * This file is part of the core Kernel Cryptographic Framework.
 * It implements the management of the policy table. Entries are
 * added and removed by administrative ioctls.
 *
 * Each element of the policy table contains a pointer to a
 * policy descriptor, or NULL if the entry is free.
 */

#include <sys/types.h>
#include <sys/kmem.h>
#include <sys/cmn_err.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/ksynch.h>
#include <sys/crypto/common.h>
#include <sys/crypto/impl.h>

#define	KCF_MAX_POLICY	512	/* max number of policy entries */

static kmutex_t policy_tab_mutex; /* ensure exclusive access to the table */
static kcf_policy_desc_t **policy_tab = NULL;
static uint_t policy_tab_num = 0; /* number of providers in table */
static uint_t policy_tab_max = KCF_MAX_POLICY;

static int kcf_policy_add_entry(kcf_policy_desc_t *);
static kcf_policy_desc_t *kcf_policy_alloc_desc(int);

/*
 * Initialize the policy table. The policy table is dynamically
 * allocated with policy_tab_max entries.
 */
void
kcf_policy_tab_init(void)
{
	mutex_init(&policy_tab_mutex, NULL, MUTEX_DRIVER, NULL);

	policy_tab = kmem_zalloc(policy_tab_max * sizeof (kcf_policy_desc_t *),
	    KM_SLEEP);
}

/*
 * Add entry to the policy table. If no free slot can be found
 * return CRYPTO_HOST_MEMORY, otherwise CRYPTO_SUCCESS.
 *
 * policy_tab_mutex must already be held.
 */
static int
kcf_policy_add_entry(kcf_policy_desc_t *policy_desc)
{
	uint_t i = 0;

	ASSERT(policy_tab != NULL);
	ASSERT(MUTEX_HELD(&policy_tab_mutex));

	/* find free slot in policy table */
	while (i < KCF_MAX_POLICY && policy_tab[i] != NULL)
		i++;

	if (i == KCF_MAX_POLICY) {
		/* ran out of policy entries */
		cmn_err(CE_WARN, "out of policy entries");
		return (CRYPTO_HOST_MEMORY);
	}

	/* initialize entry */
	policy_tab[i] = policy_desc;
	KCF_POLICY_REFHOLD(policy_desc);
	policy_tab_num++;

	return (CRYPTO_SUCCESS);
}

/*
 * Remove policy descriptor for the specified software module.
 */
void
kcf_policy_remove_by_name(char *module_name, uint_t *count,
    crypto_mech_name_t **array)
{
	kcf_policy_desc_t *policy_desc;
	int i;

	ASSERT(policy_tab != NULL);
	ASSERT(policy_tab_num != (uint_t)-1); /* underflow */

	mutex_enter(&policy_tab_mutex);

	for (i = 0; i < KCF_MAX_POLICY; i++) {
		if ((policy_desc = policy_tab[i]) != NULL &&
		    policy_desc->pd_prov_type == CRYPTO_SW_PROVIDER) {
			ASSERT(policy_desc->pd_name != NULL);
			if (strncmp(module_name, policy_desc->pd_name,
			    MAXNAMELEN) == 0) {
				*count = policy_desc->pd_disabled_count;
				*array = policy_desc->pd_disabled_mechs;
				mutex_destroy(&policy_desc->pd_mutex);
				kmem_free(policy_desc->pd_name,
				    strlen(policy_desc->pd_name) + 1);
				kmem_free(policy_desc,
				    sizeof (kcf_policy_desc_t));
				policy_tab[i] = NULL;
				policy_tab_num--;
				break;
			}
		}
	}
	if (i == KCF_MAX_POLICY) {
		*count = 0;
		*array = NULL;
	}

	mutex_exit(&policy_tab_mutex);
}

/*
 * Remove policy descriptor for the specified device.
 */
void
kcf_policy_remove_by_dev(char *name, uint_t instance, uint_t *count,
    crypto_mech_name_t **array)
{
	kcf_policy_desc_t *policy_desc;
	int i;

	ASSERT(policy_tab != NULL);
	ASSERT(policy_tab_num != (uint_t)-1); /* underflow */

	mutex_enter(&policy_tab_mutex);

	for (i = 0; i < KCF_MAX_POLICY; i++) {
		if ((policy_desc = policy_tab[i]) != NULL &&
		    policy_desc->pd_prov_type == CRYPTO_HW_PROVIDER &&
		    strncmp(policy_desc->pd_name, name, MAXNAMELEN) == 0 &&
		    policy_desc->pd_instance == instance) {
			*count = policy_desc->pd_disabled_count;
			*array = policy_desc->pd_disabled_mechs;
			mutex_destroy(&policy_desc->pd_mutex);
			kmem_free(policy_desc->pd_name,
			    strlen(policy_desc->pd_name) + 1);
			kmem_free(policy_desc, sizeof (kcf_policy_desc_t));
			policy_tab[i] = NULL;
			policy_tab_num--;
			break;
		}
	}
	if (i == KCF_MAX_POLICY) {
		*count = 0;
		*array = NULL;
	}

	mutex_exit(&policy_tab_mutex);
}

/*
 * Returns policy descriptor for the specified software module.
 */
kcf_policy_desc_t *
kcf_policy_lookup_by_name(char *module_name)
{
	kcf_policy_desc_t *policy_desc;
	uint_t i;

	mutex_enter(&policy_tab_mutex);

	for (i = 0; i < KCF_MAX_POLICY; i++) {
		if ((policy_desc = policy_tab[i]) != NULL &&
		    policy_desc->pd_prov_type == CRYPTO_SW_PROVIDER) {
			ASSERT(policy_desc->pd_name != NULL);
			if (strncmp(module_name, policy_desc->pd_name,
			    MAXNAMELEN) == 0) {
				KCF_POLICY_REFHOLD(policy_desc);
				mutex_exit(&policy_tab_mutex);
				return (policy_desc);
			}
		}
	}

	mutex_exit(&policy_tab_mutex);
	return (NULL);
}

/*
 * Returns policy descriptor for the specified device.
 */
kcf_policy_desc_t *
kcf_policy_lookup_by_dev(char *name, uint_t instance)
{
	kcf_policy_desc_t *policy_desc;
	uint_t i;

	mutex_enter(&policy_tab_mutex);

	for (i = 0; i < KCF_MAX_POLICY; i++) {
		if ((policy_desc = policy_tab[i]) != NULL &&
		    policy_desc->pd_prov_type == CRYPTO_HW_PROVIDER &&
		    strncmp(policy_desc->pd_name, name, MAXNAMELEN) == 0 &&
		    policy_desc->pd_instance == instance) {
			KCF_POLICY_REFHOLD(policy_desc);
			mutex_exit(&policy_tab_mutex);
			return (policy_desc);
		}
	}

	mutex_exit(&policy_tab_mutex);
	return (NULL);
}

/*
 * Loads disabled mechanism array for specified software provider, and
 * creates a policy descriptor if one does not already exist.
 * Important note: new_array is consumed.
 */
int
kcf_policy_load_soft_disabled(char *module_name, uint_t new_count,
    crypto_mech_name_t *new_array, uint_t *prev_count,
    crypto_mech_name_t **prev_array)
{
	kcf_policy_desc_t *new_desc, *policy_desc = NULL;
	uint_t i;
	int rv;

	/*
	 * Allocate storage for a new entry.
	 * Free new entry if a policy descriptor already exists.
	 */
	new_desc = kcf_policy_alloc_desc(KM_SLEEP);
	new_desc->pd_prov_type = CRYPTO_SW_PROVIDER;
	new_desc->pd_name = kmem_alloc(strlen(module_name) + 1, KM_SLEEP);
	(void) strcpy(new_desc->pd_name, module_name);

	mutex_enter(&policy_tab_mutex);

	/*
	 * Search for an existing entry.
	 */
	for (i = 0; i < KCF_MAX_POLICY; i++) {
		if (policy_tab[i] != NULL &&
		    policy_tab[i]->pd_prov_type == CRYPTO_SW_PROVIDER) {
			ASSERT(policy_tab[i]->pd_name != NULL);
			if (strncmp(policy_tab[i]->pd_name, module_name,
			    MAXNAMELEN) == 0) {
				policy_desc = policy_tab[i];
				break;
			}
		}
	}
	if (policy_desc == NULL) {
		rv = kcf_policy_add_entry(new_desc);
		if (rv != CRYPTO_SUCCESS) {
			mutex_exit(&policy_tab_mutex);
			kcf_policy_free_desc(new_desc);
			return (rv);
		}
		policy_desc = new_desc;
	} else {
		kcf_policy_free_desc(new_desc);
	}

	mutex_enter(&policy_desc->pd_mutex);
	*prev_count = policy_desc->pd_disabled_count;

	/* prev_array is freed by the caller */
	*prev_array = policy_desc->pd_disabled_mechs;
	policy_desc->pd_disabled_count = new_count;
	policy_desc->pd_disabled_mechs = new_array;
	mutex_exit(&policy_desc->pd_mutex);
	mutex_exit(&policy_tab_mutex);
	return (CRYPTO_SUCCESS);
}

/*
 * Loads disabled mechanism array for specified device, and
 * creates a policy descriptor if one does not already exist.
 * Important note: new_array is consumed.
 */
int
kcf_policy_load_dev_disabled(char *name, uint_t instance, uint_t new_count,
    crypto_mech_name_t *new_array, uint_t *prev_count,
    crypto_mech_name_t **prev_array)
{
	kcf_policy_desc_t *new_desc, *policy_desc = NULL;
	uint_t i;
	int rv;

	/*
	 * Allocate storage for a new entry.
	 * Free new entry if a policy descriptor already exists.
	 */
	new_desc = kcf_policy_alloc_desc(KM_SLEEP);
	new_desc->pd_prov_type = CRYPTO_HW_PROVIDER;
	new_desc->pd_name = kmem_alloc(strlen(name) + 1, KM_SLEEP);
	(void) strcpy(new_desc->pd_name, name);
	new_desc->pd_instance = instance;

	mutex_enter(&policy_tab_mutex);

	/*
	 * Search for an existing entry.
	 */
	for (i = 0; i < KCF_MAX_POLICY; i++) {
		if (policy_tab[i] != NULL &&
		    policy_tab[i]->pd_prov_type == CRYPTO_HW_PROVIDER &&
		    strncmp(policy_tab[i]->pd_name, name, MAXNAMELEN) == 0 &&
		    policy_tab[i]->pd_instance == instance) {
			policy_desc = policy_tab[i];
			break;
		}
	}
	if (policy_desc == NULL) {
		rv = kcf_policy_add_entry(new_desc);
		if (rv != CRYPTO_SUCCESS) {
			mutex_exit(&policy_tab_mutex);
			kcf_policy_free_desc(new_desc);
			return (rv);
		}
		policy_desc = new_desc;
	} else {
		kcf_policy_free_desc(new_desc);
	}

	mutex_enter(&policy_desc->pd_mutex);
	*prev_count = policy_desc->pd_disabled_count;

	/* prev_array is freed by the caller */
	*prev_array = policy_desc->pd_disabled_mechs;
	policy_desc->pd_disabled_count = new_count;
	policy_desc->pd_disabled_mechs = new_array;
	mutex_exit(&policy_desc->pd_mutex);
	mutex_exit(&policy_tab_mutex);
	return (CRYPTO_SUCCESS);
}

/*
 * Allocate a policy descriptor.
 */
static kcf_policy_desc_t *
kcf_policy_alloc_desc(int km_flag)
{
	kcf_policy_desc_t *desc;

	if ((desc = kmem_zalloc(sizeof (kcf_policy_desc_t), km_flag)) == NULL)
		return (NULL);

	mutex_init(&desc->pd_mutex, NULL, MUTEX_DEFAULT, NULL);

	return (desc);
}

/*
 * Free a policy descriptor.
 */
void
kcf_policy_free_desc(kcf_policy_desc_t *desc)
{
	if (desc == NULL)
		return;

	mutex_destroy(&desc->pd_mutex);

	ASSERT(desc->pd_name != NULL);
	kmem_free(desc->pd_name, strlen(desc->pd_name) + 1);

	if (desc->pd_disabled_mechs != NULL)
		kmem_free(desc->pd_disabled_mechs, sizeof (crypto_mech_name_t) *
		    desc->pd_disabled_count);

	kmem_free(desc, sizeof (kcf_policy_desc_t));
}
