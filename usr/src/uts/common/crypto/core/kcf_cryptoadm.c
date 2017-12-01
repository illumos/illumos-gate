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
 * Core KCF (Kernel Cryptographic Framework). This file implements
 * the cryptoadm entry points.
 */

#include <sys/systm.h>
#include <sys/errno.h>
#include <sys/cmn_err.h>
#include <sys/rwlock.h>
#include <sys/kmem.h>
#include <sys/modctl.h>
#include <sys/sunddi.h>
#include <sys/door.h>
#include <sys/crypto/common.h>
#include <sys/crypto/api.h>
#include <sys/crypto/spi.h>
#include <sys/crypto/impl.h>
#include <sys/crypto/sched_impl.h>

/* protects the the soft_config_list. */
kmutex_t soft_config_mutex;

/*
 * This linked list contains software configuration entries.
 * The initial list is just software providers loaded by kcf_soft_config_init().
 * Additional entries may appear for both hardware and software providers
 * from kcf.conf.  These come from "cryptoadm start", which reads file kcf.conf
 * and updates this table using the CRYPTO_LOAD_SOFT_CONFIG ioctl.
 * Further cryptoadm commands modify this file and update this table with ioctl.
 * This list is protected by the soft_config_mutex.
 */
kcf_soft_conf_entry_t *soft_config_list;

static int add_soft_config(char *, uint_t, crypto_mech_name_t *);
static int dup_mech_names(kcf_provider_desc_t *, crypto_mech_name_t **,
    uint_t *, int);
static void free_soft_config_entry(kcf_soft_conf_entry_t *);

#define	KCF_MAX_CONFIG_ENTRIES 512 /* maximum entries in soft_config_list */

#if DEBUG
extern int kcf_frmwrk_debug;
static void kcf_soft_config_dump(char *message);
#endif /* DEBUG */

/*
 * Count and return the number of mechanisms in an array of crypto_mech_name_t
 * (excluding final NUL-character string element).
 */
static int
count_mechanisms(crypto_mech_name_t mechs[])
{
	int	count;
	for (count = 0; mechs[count][0] != '\0'; ++count)
		;
	return (count);
}

/*
 * Initialize a mutex and populate soft_config_list with default entries
 * of kernel software providers.
 * Called from kcf module _init().
 */
void
kcf_soft_config_init(void)
{
	typedef struct {
		char			*name;
		crypto_mech_name_t	*mechs;
	} initial_soft_config_entry_t;

	/*
	 * This provides initial default values to soft_config_list.
	 * It is equivalent to these lines in /etc/crypto/kcf.conf
	 * (without line breaks and indenting):
	 *
	 * # /etc/crypto/kcf.conf
	 * des:supportedlist=CKM_DES_CBC,CKM_DES_ECB,CKM_DES3_CBC,CKM_DES3_ECB
	 * aes:supportedlist=CKM_AES_ECB,CKM_AES_CBC,CKM_AES_CTR,CKM_AES_CCM,\
	 * CKM_AES_GCM,CKM_AES_GMAC,CKM_AES_CMAC
	 * arcfour:supportedlist=CKM_RC4
	 * blowfish:supportedlist=CKM_BLOWFISH_ECB,CKM_BLOWFISH_CBC
	 * ecc:supportedlist=CKM_EC_KEY_PAIR_GEN,CKM_ECDH1_DERIVE,CKM_ECDSA,\
	 * CKM_ECDSA_SHA1
	 * sha1:supportedlist=CKM_SHA_1,CKM_SHA_1_HMAC_GENERAL,CKM_SHA_1_HMAC
	 * sha2:supportedlist=CKM_SHA256,CKM_SHA256_HMAC,\
	 * CKM_SHA256_HMAC_GENERAL,CKM_SHA384,CKM_SHA384_HMAC,\
	 * CKM_SHA384_HMAC_GENERAL,CKM_SHA512,CKM_SHA512_HMAC,\
	 * CKM_SHA512_HMAC_GENERAL
	 * md4:supportedlist=CKM_MD4
	 * md5:supportedlist=CKM_MD5,CKM_MD5_HMAC_GENERAL,CKM_MD5_HMAC
	 * rsa:supportedlist=CKM_RSA_PKCS,CKM_RSA_X_509,CKM_MD5_RSA_PKCS,\
	 * CKM_SHA1_RSA_PKCS,CKM_SHA256_RSA_PKCS,CKM_SHA384_RSA_PKCS,\
	 * CKM_SHA512_RSA_PKCS
	 * swrand:supportedlist=random
	 *
	 * WARNING: If you add a new kernel crypto provider or mechanism,
	 * you must update these structures.
	 *
	 * 1. To add a new mechanism to a provider add the string to the
	 * appropriate array below and comment above.
	 *
	 * 2. To add a new provider, create a new *_mechs array listing the
	 * provider's mechanism(s) and a new comment line above.
	 * Add the new *_mechs array to initial_soft_config_entry[].
	 *
	 * 3. If appropriate (that is the new mechanism is needed before
	 * cryptosvc runs), add to kcf_init_mech_tabs() in kcf_mech_tabs.c.
	 */
	static crypto_mech_name_t	des_mechs[] = {
	    "CKM_DES_CBC", "CKM_DES_ECB", "CKM_DES3_CBC", "CKM_DES3_ECB", ""};
	static crypto_mech_name_t	aes_mechs[] = {
	    "CKM_AES_ECB", "CKM_AES_CBC", "CKM_AES_CTR", "CKM_AES_CCM",
	    "CKM_AES_GCM", "CKM_AES_GMAC", "CKM_AES_CMAC", ""};
	static crypto_mech_name_t	arcfour_mechs[] = {
	    "CKM_RC4", ""};
	static crypto_mech_name_t	blowfish_mechs[] = {
	    "CKM_BLOWFISH_ECB", "CKM_BLOWFISH_CBC", ""};
	static crypto_mech_name_t	ecc_mechs[] = {
	    "CKM_EC_KEY_PAIR_GEN", "CKM_ECDH1_DERIVE", "CKM_ECDSA",
	    "CKM_ECDSA_SHA1", ""};
	static crypto_mech_name_t	sha1_mechs[] = {
	    "CKM_SHA_1", "CKM_SHA_1_HMAC_GENERAL", "CKM_SHA_1_HMAC", ""};
	static crypto_mech_name_t	sha2_mechs[] = {
	    "CKM_SHA256", "CKM_SHA256_HMAC", "CKM_SHA256_HMAC_GENERAL",
	    "CKM_SHA384", "CKM_SHA384_HMAC", "CKM_SHA384_HMAC_GENERAL",
	    "CKM_SHA512", "CKM_SHA512_HMAC", "CKM_SHA512_HMAC_GENERAL", ""};
	static crypto_mech_name_t	md4_mechs[] = {
	    "CKM_MD4", ""};
	static crypto_mech_name_t	md5_mechs[] = {
	    "CKM_MD5", "CKM_MD5_HMAC_GENERAL", "CKM_MD5_HMAC", ""};
	static crypto_mech_name_t	rsa_mechs[] = {
	    "CKM_RSA_PKCS", "CKM_RSA_X_509", "CKM_MD5_RSA_PKCS",
	    "CKM_SHA1_RSA_PKCS", "CKM_SHA256_RSA_PKCS", "CKM_SHA384_RSA_PKCS",
	    "CKM_SHA512_RSA_PKCS", ""};
	static crypto_mech_name_t	swrand_mechs[] = {
	    "random", NULL};
	static initial_soft_config_entry_t
	    initial_soft_config_entry[] = {
		"des", des_mechs,
		"aes", aes_mechs,
		"arcfour", arcfour_mechs,
		"blowfish", blowfish_mechs,
		"ecc", ecc_mechs,
		"sha1", sha1_mechs,
		"sha2", sha2_mechs,
		"md4", md4_mechs,
		"md5", md5_mechs,
		"rsa", rsa_mechs,
		"swrand", swrand_mechs
	};
	const int	initial_soft_config_entries =
	    sizeof (initial_soft_config_entry)
	    / sizeof (initial_soft_config_entry_t);
	int		i;

	mutex_init(&soft_config_mutex, NULL, MUTEX_DRIVER, NULL);

	/*
	 * Initialize soft_config_list with default providers.
	 * Populate the linked list backwards so the first entry appears first.
	 */
	for (i = initial_soft_config_entries - 1; i >= 0; --i) {
		initial_soft_config_entry_t *p = &initial_soft_config_entry[i];
		crypto_mech_name_t	*mechsp;
		uint_t			alloc_size;
		int			mech_count, r;

		/* allocate/initialize memory for mechanism list */
		mech_count = count_mechanisms(p->mechs);
		alloc_size = mech_count * CRYPTO_MAX_MECH_NAME;
		mechsp = kmem_alloc(alloc_size, KM_SLEEP);
		bcopy(p->mechs, mechsp, alloc_size);

		r = add_soft_config(p->name, mech_count, mechsp);
		if (r != 0)
			cmn_err(CE_WARN,
			    "add_soft_config(%s) failed; returned %d\n",
			    p->name, r);
	}
#if DEBUG
	if (kcf_frmwrk_debug >= 1)
		kcf_soft_config_dump("kcf_soft_config_init");
#endif /* DEBUG */
}


#if DEBUG
/*
 * Dump soft_config_list, containing a list of kernel software providers
 * and (optionally) hardware providers, with updates from kcf.conf.
 * Dump mechanism lists too if kcf_frmwrk_debug is >= 2.
 */
static void
kcf_soft_config_dump(char *message)
{
	kcf_soft_conf_entry_t	*p;
	uint_t			i;

	mutex_enter(&soft_config_mutex);
	printf("Soft provider config list soft_config_list: %s\n",
	    message != NULL ? message : "");

	for (p = soft_config_list; p != NULL; p = p->ce_next) {
		printf("ce_name: %s, %d ce_mechs\n", p->ce_name, p->ce_count);
		if (kcf_frmwrk_debug >= 2) {
			printf("\tce_mechs: ");
			for (i = 0; i < p->ce_count; i++) {
				printf("%s ", p->ce_mechs[i]);
			}
			printf("\n");
		}
	}
	printf("(end of soft_config_list)\n");

	mutex_exit(&soft_config_mutex);
}
#endif /* DEBUG */


/*
 * Utility routine to identify the providers to filter out and
 * present only one provider. This happens when a hardware provider
 * registers multiple units of the same device instance.
 *
 * Called from crypto_get_dev_list().
 */
static void
filter_providers(uint_t count, kcf_provider_desc_t **provider_array,
    char *skip_providers, int *mech_counts, int *new_count)
{
	int i, j;
	kcf_provider_desc_t *prov1, *prov2;
	int n = 0;

	for (i = 0; i < count; i++) {
		if (skip_providers[i] == 1)
			continue;

		prov1 = provider_array[i];
		mech_counts[i] = prov1->pd_mech_list_count;
		for (j = i + 1; j < count; j++) {
			prov2 = provider_array[j];
			if (strncmp(prov1->pd_name, prov2->pd_name,
			    MAXNAMELEN) == 0 &&
			    prov1->pd_instance == prov2->pd_instance) {
				skip_providers[j] = 1;
				mech_counts[i] += prov2->pd_mech_list_count;
			}
		}
		n++;
	}

	*new_count = n;
}


/*
 * Return a list of kernel hardware providers and a count of each
 * provider's supported mechanisms.
 * Called from the CRYPTO_GET_DEV_LIST ioctl.
 */
int
crypto_get_dev_list(uint_t *count, crypto_dev_list_entry_t **array)
{
	kcf_provider_desc_t **provider_array;
	kcf_provider_desc_t *pd;
	crypto_dev_list_entry_t *p;
	size_t skip_providers_size, mech_counts_size;
	char *skip_providers;
	uint_t provider_count;
	int rval, i, j, new_count, *mech_counts;

	/*
	 * Take snapshot of provider table returning only hardware providers
	 * that are in a usable state. Logical providers not included.
	 */
	rval = kcf_get_hw_prov_tab(&provider_count, &provider_array, KM_SLEEP,
	    NULL, 0, B_FALSE);
	if (rval != CRYPTO_SUCCESS)
		return (rval);

	if (provider_count == 0) {
		*array = NULL;
		*count = 0;
		return (CRYPTO_SUCCESS);
	}

	skip_providers_size = provider_count * sizeof (char);
	mech_counts_size = provider_count * sizeof (int);

	skip_providers = kmem_zalloc(skip_providers_size, KM_SLEEP);
	mech_counts = kmem_zalloc(mech_counts_size, KM_SLEEP);
	filter_providers(provider_count, provider_array, skip_providers,
	    mech_counts, &new_count);

	p = kmem_alloc(new_count * sizeof (crypto_dev_list_entry_t), KM_SLEEP);
	for (i = 0, j = 0; i < provider_count; i++) {
		if (skip_providers[i] == 1) {
			ASSERT(mech_counts[i] == 0);
			continue;
		}
		pd = provider_array[i];
		p[j].le_mechanism_count = mech_counts[i];
		p[j].le_dev_instance = pd->pd_instance;
		(void) strncpy(p[j].le_dev_name, pd->pd_name, MAXNAMELEN);
		j++;
	}

	kcf_free_provider_tab(provider_count, provider_array);
	kmem_free(skip_providers, skip_providers_size);
	kmem_free(mech_counts, mech_counts_size);

	*array = p;
	*count = new_count;
	return (CRYPTO_SUCCESS);
}

/*
 * Return a buffer containing the null terminated names of software providers
 * loaded by CRYPTO_LOAD_SOFT_CONFIG.
 * Called from the CRYPTO_GET_SOFT_LIST ioctl.
 */
int
crypto_get_soft_list(uint_t *count, char **array, size_t *len)
{
	char *names = NULL, *namep, *end;
	kcf_soft_conf_entry_t *p;
	uint_t n = 0, cnt = 0, final_count = 0;
	size_t name_len, final_size = 0;

	/* first estimate */
	mutex_enter(&soft_config_mutex);
	for (p = soft_config_list; p != NULL; p = p->ce_next) {
		n += strlen(p->ce_name) + 1;
		cnt++;
	}
	mutex_exit(&soft_config_mutex);

	if (cnt == 0)
		goto out;

again:
	namep = names = kmem_alloc(n, KM_SLEEP);
	end = names + n;
	final_size = 0;
	final_count = 0;

	mutex_enter(&soft_config_mutex);
	for (p = soft_config_list; p != NULL; p = p->ce_next) {
		name_len = strlen(p->ce_name) + 1;
		/* check for enough space */
		if ((namep + name_len) > end) {
			mutex_exit(&soft_config_mutex);
			kmem_free(names, n);
			n = n << 1;
			goto again;
		}
		(void) strcpy(namep, p->ce_name);
		namep += name_len;
		final_size += name_len;
		final_count++;
	}
	mutex_exit(&soft_config_mutex);

	ASSERT(final_size <= n);

	/* check if buffer we allocated is too large */
	if (final_size < n) {
		char *final_buffer;

		final_buffer = kmem_alloc(final_size, KM_SLEEP);
		bcopy(names, final_buffer, final_size);
		kmem_free(names, n);
		names = final_buffer;
	}
out:
	*array = names;
	*count = final_count;
	*len = final_size;
	return (CRYPTO_SUCCESS);
}

/*
 * Check if a mechanism name is already in a mechanism name array
 * Called by crypto_get_dev_info().
 */
static boolean_t
duplicate(char *name, crypto_mech_name_t *array, int count)
{
	int i;

	for (i = 0; i < count; i++) {
		if (strncmp(name, &array[i][0],
		    sizeof (crypto_mech_name_t)) == 0)
			return (B_TRUE);
	}
	return (B_FALSE);
}

/*
 * Return a list of kernel hardware providers for a given name and instance.
 * For each entry, also return a list of their supported mechanisms.
 * Called from the CRYPTO_GET_DEV_INFO ioctl.
 */
int
crypto_get_dev_info(char *name, uint_t instance, uint_t *count,
    crypto_mech_name_t **array)
{
	int rv;
	crypto_mech_name_t *mech_names, *resized_array;
	int i, j, k = 0, max_count;
	uint_t provider_count;
	kcf_provider_desc_t **provider_array;
	kcf_provider_desc_t *pd;

	/*
	 * Get provider table entries matching name and instance
	 * for hardware providers that are in a usable state.
	 * Logical providers not included. NULL name matches
	 * all hardware providers.
	 */
	rv = kcf_get_hw_prov_tab(&provider_count, &provider_array, KM_SLEEP,
	    name, instance, B_FALSE);
	if (rv != CRYPTO_SUCCESS)
		return (rv);

	if (provider_count == 0)
		return (CRYPTO_ARGUMENTS_BAD);

	/* Count all mechanisms supported by all providers */
	max_count = 0;
	for (i = 0; i < provider_count; i++)
		max_count += provider_array[i]->pd_mech_list_count;

	if (max_count == 0) {
		mech_names = NULL;
		goto out;
	}

	/* Allocate space and copy mech names */
	mech_names = kmem_alloc(max_count * sizeof (crypto_mech_name_t),
	    KM_SLEEP);

	k = 0;
	for (i = 0; i < provider_count; i++) {
		pd = provider_array[i];
		for (j = 0; j < pd->pd_mech_list_count; j++) {
			/* check for duplicate */
			if (duplicate(&pd->pd_mechanisms[j].cm_mech_name[0],
			    mech_names, k))
				continue;
			bcopy(&pd->pd_mechanisms[j].cm_mech_name[0],
			    &mech_names[k][0], sizeof (crypto_mech_name_t));
			k++;
		}
	}

	/* resize */
	if (k != max_count) {
		resized_array =
		    kmem_alloc(k * sizeof (crypto_mech_name_t), KM_SLEEP);
		bcopy(mech_names, resized_array,
		    k * sizeof (crypto_mech_name_t));
		kmem_free(mech_names,
		    max_count * sizeof (crypto_mech_name_t));
		mech_names = resized_array;
	}

out:
	kcf_free_provider_tab(provider_count, provider_array);
	*count = k;
	*array = mech_names;

	return (CRYPTO_SUCCESS);
}

/*
 * Given a kernel software provider name, return a list of mechanisms
 * it supports.
 * Called from the CRYPTO_GET_SOFT_INFO ioctl.
 */
int
crypto_get_soft_info(caddr_t name, uint_t *count, crypto_mech_name_t **array)
{
	ddi_modhandle_t modh = NULL;
	kcf_provider_desc_t *provider;
	int rv;

	provider = kcf_prov_tab_lookup_by_name(name);
	if (provider == NULL) {
		char *tmp;
		int name_len;

		/* strlen("crypto/") + NULL terminator == 8 */
		name_len = strlen(name);
		tmp = kmem_alloc(name_len + 8, KM_SLEEP);
		bcopy("crypto/", tmp, 7);
		bcopy(name, &tmp[7], name_len);
		tmp[name_len + 7] = '\0';

		modh = ddi_modopen(tmp, KRTLD_MODE_FIRST, NULL);
		kmem_free(tmp, name_len + 8);

		if (modh == NULL) {
			return (CRYPTO_ARGUMENTS_BAD);
		}

		provider = kcf_prov_tab_lookup_by_name(name);
		if (provider == NULL) {
			return (CRYPTO_ARGUMENTS_BAD);
		}
	}

	rv = dup_mech_names(provider, array, count, KM_SLEEP);
	KCF_PROV_REFRELE(provider);
	if (modh != NULL)
		(void) ddi_modclose(modh);
	return (rv);
}


/*
 * Change the mechanism list for a provider.
 * If "direction" is CRYPTO_MECH_ADDED, add new mechanisms.
 * If "direction" is CRYPTO_MECH_REMOVED, remove the mechanism list.
 * Called from crypto_load_dev_disabled().
 */
static void
kcf_change_mechs(kcf_provider_desc_t *provider, uint_t count,
    crypto_mech_name_t *array, crypto_event_change_t direction)
{
	crypto_notify_event_change_t ec;
	crypto_mech_info_t *mi;
	kcf_prov_mech_desc_t *pmd;
	char *mech;
	int i, j, n;

	ASSERT(direction == CRYPTO_MECH_ADDED ||
	    direction == CRYPTO_MECH_REMOVED);

	if (provider == NULL) {
		/*
		 * Nothing to add or remove from the tables since
		 * the provider isn't registered.
		 */
		return;
	}

	for (i = 0; i < count; i++) {
		if (array[i][0] == '\0')
			continue;

		mech = &array[i][0];

		n = provider->pd_mech_list_count;
		for (j = 0; j < n; j++) {
			mi = &provider->pd_mechanisms[j];
			if (strncmp(mi->cm_mech_name, mech,
			    CRYPTO_MAX_MECH_NAME) == 0)
				break;
		}
		if (j == n)
			continue;

		switch (direction) {
		case CRYPTO_MECH_ADDED:
			(void) kcf_add_mech_provider(j, provider, &pmd);
			break;

		case CRYPTO_MECH_REMOVED:
			kcf_remove_mech_provider(mech, provider);
			break;
		}

		/* Inform interested clients of the event */
		ec.ec_provider_type = provider->pd_prov_type;
		ec.ec_change = direction;

		(void) strncpy(ec.ec_mech_name, mech, CRYPTO_MAX_MECH_NAME);
		kcf_walk_ntfylist(CRYPTO_EVENT_MECHS_CHANGED, &ec);
	}
}

/*
 * If a mech name in the second array (prev_array) is also in the
 * first array, then a NULL character is written into the first byte
 * of the mech name in the second array.  This effectively removes
 * the mech name from the second array.
 */
static void
kcf_compare_mechs(uint_t count, crypto_mech_name_t *array, uint_t prev_count,
    crypto_mech_name_t *prev_array)
{
	int i, j;

	for (i = 0; i < prev_count; i++) {
		for (j = 0; j < count; j++) {
			if (strncmp(&prev_array[i][0], &array[j][0],
			    CRYPTO_MAX_MECH_NAME) == 0) {
				prev_array[i][0] = '\0';
			}
		}
	}
}

/*
 * Called from CRYPTO_LOAD_DEV_DISABLED ioctl.
 * If new_count is 0, then completely remove the entry.
 */
int
crypto_load_dev_disabled(char *name, uint_t instance, uint_t new_count,
    crypto_mech_name_t *new_array)
{
	kcf_provider_desc_t *provider = NULL;
	kcf_provider_desc_t **provider_array;
	crypto_mech_name_t *prev_array;
	uint_t provider_count, prev_count;
	int i, rv = CRYPTO_SUCCESS;

	/*
	 * Remove the policy entry if new_count is 0, otherwise put disabled
	 * mechanisms into policy table.
	 */
	if (new_count == 0) {
		kcf_policy_remove_by_dev(name, instance, &prev_count,
		    &prev_array);
	} else if ((rv = kcf_policy_load_dev_disabled(name, instance, new_count,
	    new_array, &prev_count, &prev_array)) != CRYPTO_SUCCESS) {
		return (rv);
	}

	/*
	 * Get provider table entries matching name and instance
	 * for providers that are are in a usable or unverified state.
	 */
	rv = kcf_get_hw_prov_tab(&provider_count, &provider_array, KM_SLEEP,
	    name, instance, B_TRUE);
	if (rv != CRYPTO_SUCCESS)
		return (rv);

	for (i = 0; i < provider_count; i++) {
		provider = provider_array[i];

		/* previously disabled mechanisms may become enabled */
		if (prev_array != NULL) {
			kcf_compare_mechs(new_count, new_array,
			    prev_count, prev_array);
			kcf_change_mechs(provider, prev_count, prev_array,
			    CRYPTO_MECH_ADDED);
		}

		kcf_change_mechs(provider, new_count, new_array,
		    CRYPTO_MECH_REMOVED);
	}

	kcf_free_provider_tab(provider_count, provider_array);
	crypto_free_mech_list(prev_array, prev_count);
	return (rv);
}

/*
 * Called from CRYPTO_LOAD_SOFT_DISABLED ioctl.
 * If new_count is 0, then completely remove the entry.
 */
int
crypto_load_soft_disabled(char *name, uint_t new_count,
    crypto_mech_name_t *new_array)
{
	kcf_provider_desc_t *provider = NULL;
	crypto_mech_name_t *prev_array;
	uint_t prev_count = 0;
	int rv;

	provider = kcf_prov_tab_lookup_by_name(name);
	if (provider != NULL) {
		mutex_enter(&provider->pd_lock);
		/*
		 * Check if any other thread is disabling or removing
		 * this provider. We return if this is the case.
		 */
		if (provider->pd_state >= KCF_PROV_DISABLED) {
			mutex_exit(&provider->pd_lock);
			KCF_PROV_REFRELE(provider);
			return (CRYPTO_BUSY);
		}
		provider->pd_state = KCF_PROV_DISABLED;
		mutex_exit(&provider->pd_lock);

		undo_register_provider(provider, B_TRUE);
		KCF_PROV_REFRELE(provider);
		if (provider->pd_kstat != NULL)
			KCF_PROV_REFRELE(provider);

		/* Wait till the existing requests complete. */
		while (kcf_get_refcnt(provider, B_TRUE) > 0) {
			/* wait 1 second and try again. */
			delay(1 * drv_usectohz(1000000));
		}
	}

	if (new_count == 0) {
		kcf_policy_remove_by_name(name, &prev_count, &prev_array);
		crypto_free_mech_list(prev_array, prev_count);
		rv = CRYPTO_SUCCESS;
		goto out;
	}

	/* put disabled mechanisms into policy table */
	if ((rv = kcf_policy_load_soft_disabled(name, new_count, new_array,
	    &prev_count, &prev_array)) == CRYPTO_SUCCESS) {
		crypto_free_mech_list(prev_array, prev_count);
	}

out:
	if (provider != NULL) {
		redo_register_provider(provider);
		if (provider->pd_kstat != NULL)
			KCF_PROV_REFHOLD(provider);
		mutex_enter(&provider->pd_lock);
		provider->pd_state = KCF_PROV_READY;
		mutex_exit(&provider->pd_lock);
	} else if (rv == CRYPTO_SUCCESS) {
		/*
		 * There are some cases where it is useful to kCF clients
		 * to have a provider whose mechanism is enabled now to be
		 * available. So, we attempt to load it here.
		 *
		 * The check, new_count < prev_count, ensures that we do this
		 * only in the case where a mechanism(s) is now enabled.
		 * This check assumes that enable and disable are separate
		 * administrative actions and are not done in a single action.
		 */
		if ((new_count < prev_count) &&
		    (modload("crypto", name) != -1)) {
			struct modctl *mcp;
			boolean_t load_again = B_FALSE;

			if ((mcp = mod_hold_by_name(name)) != NULL) {
				mcp->mod_loadflags |= MOD_NOAUTOUNLOAD;

				/* memory pressure may have unloaded module */
				if (!mcp->mod_installed)
					load_again = B_TRUE;
				mod_release_mod(mcp);

				if (load_again)
					(void) modload("crypto", name);
			}
		}
	}

	return (rv);
}

/* called from the CRYPTO_LOAD_SOFT_CONFIG ioctl */
int
crypto_load_soft_config(caddr_t name, uint_t count, crypto_mech_name_t *array)
{
	return (add_soft_config(name, count, array));
}

/*
 * Unload a kernel software crypto module.
 * Called from the CRYPTO_UNLOAD_SOFT_MODULE ioctl.
 */
int
crypto_unload_soft_module(caddr_t name)
{
	int error;
	modid_t id;
	kcf_provider_desc_t *provider;
	struct modctl *mcp;

	/* verify that 'name' refers to a registered crypto provider */
	if ((provider = kcf_prov_tab_lookup_by_name(name)) == NULL)
		return (CRYPTO_UNKNOWN_PROVIDER);

	/*
	 * We save the module id and release the reference. We need to
	 * do this as modunload() calls unregister which waits for the
	 * refcnt to drop to zero.
	 */
	id = provider->pd_module_id;
	KCF_PROV_REFRELE(provider);

	if ((mcp = mod_hold_by_name(name)) != NULL) {
		mcp->mod_loadflags &= ~(MOD_NOAUTOUNLOAD);
		mod_release_mod(mcp);
	}

	if ((error = modunload(id)) != 0) {
		return (error == EBUSY ? CRYPTO_BUSY : CRYPTO_FAILED);
	}

	return (CRYPTO_SUCCESS);
}

/*
 * Free the list of kernel hardware crypto providers.
 * Called by get_dev_list() for the CRYPTO_GET_DEV_LIST ioctl.
 */
void
crypto_free_dev_list(crypto_dev_list_entry_t *array, uint_t count)
{
	if (count == 0 || array == NULL)
		return;

	kmem_free(array, count * sizeof (crypto_dev_list_entry_t));
}

/*
 * Returns duplicate array of mechanisms.  The array is allocated and
 * must be freed by the caller.
 */
static int
dup_mech_names(kcf_provider_desc_t *provider, crypto_mech_name_t **array,
    uint_t *count, int kmflag)
{
	crypto_mech_name_t *mech_names;
	uint_t n;
	uint_t i;

	if ((n = provider->pd_mech_list_count) == 0) {
		*count = 0;
		*array = NULL;
		return (CRYPTO_SUCCESS);
	}

	mech_names = kmem_alloc(n * sizeof (crypto_mech_name_t), kmflag);
	if (mech_names == NULL)
		return (CRYPTO_HOST_MEMORY);

	for (i = 0; i < n; i++) {
		bcopy(&provider->pd_mechanisms[i].cm_mech_name[0],
		    &mech_names[i][0], sizeof (crypto_mech_name_t));
	}

	*count = n;
	*array = mech_names;
	return (CRYPTO_SUCCESS);
}

/*
 * Returns B_TRUE if the specified mechanism is disabled, B_FALSE otherwise.
 */
boolean_t
is_mech_disabled_byname(crypto_provider_type_t prov_type, char *pd_name,
    uint_t pd_instance, crypto_mech_name_t mech_name)
{
	kcf_policy_desc_t *policy;
	uint_t i;

	ASSERT(prov_type == CRYPTO_SW_PROVIDER ||
	    prov_type == CRYPTO_HW_PROVIDER);

	switch (prov_type) {
	case CRYPTO_SW_PROVIDER:
		policy = kcf_policy_lookup_by_name(pd_name);
		/* no policy for provider - so mechanism can't be disabled */
		if (policy == NULL)
			return (B_FALSE);
		break;

	case CRYPTO_HW_PROVIDER:
		policy = kcf_policy_lookup_by_dev(pd_name, pd_instance);
		/* no policy for provider - so mechanism can't be disabled */
		if (policy == NULL)
			return (B_FALSE);
		break;
	}

	mutex_enter(&policy->pd_mutex);
	for (i = 0; i < policy->pd_disabled_count; i ++) {
		if (strncmp(mech_name, &policy->pd_disabled_mechs[i][0],
		    CRYPTO_MAX_MECH_NAME) == 0) {
			mutex_exit(&policy->pd_mutex);
			KCF_POLICY_REFRELE(policy);
			return (B_TRUE);
		}
	}
	mutex_exit(&policy->pd_mutex);
	KCF_POLICY_REFRELE(policy);
	return (B_FALSE);
}

/*
 * Returns B_TRUE if the specified mechanism is disabled, B_FALSE otherwise.
 *
 * This is a wrapper routine around is_mech_disabled_byname() above and
 * takes a pointer kcf_provider_desc structure as argument.
 */
boolean_t
is_mech_disabled(kcf_provider_desc_t *provider, crypto_mech_name_t name)
{
	kcf_provider_list_t *e;
	kcf_provider_desc_t *pd;
	boolean_t found = B_FALSE;
	uint_t count, i;

	if (provider->pd_prov_type != CRYPTO_LOGICAL_PROVIDER) {
		return (is_mech_disabled_byname(provider->pd_prov_type,
		    provider->pd_name, provider->pd_instance, name));
	}

	/*
	 * Lock the logical provider just in case one of its hardware
	 * provider members unregisters.
	 */
	mutex_enter(&provider->pd_lock);
	for (e = provider->pd_provider_list; e != NULL; e = e->pl_next) {

		pd = e->pl_provider;
		ASSERT(pd->pd_prov_type == CRYPTO_HW_PROVIDER);

		/* find out if mechanism is offered by hw provider */
		count = pd->pd_mech_list_count;
		for (i = 0; i < count; i++) {
			if (strncmp(&pd->pd_mechanisms[i].cm_mech_name[0],
			    name, MAXNAMELEN) == 0) {
				break;
			}
		}
		if (i == count)
			continue;

		found = !is_mech_disabled_byname(pd->pd_prov_type,
		    pd->pd_name, pd->pd_instance, name);

		if (found)
			break;
	}
	mutex_exit(&provider->pd_lock);
	/*
	 * If we found the mechanism, then it means it is still enabled for
	 * at least one hardware provider, so the mech can't be disabled
	 * for the logical provider.
	 */
	return (!found);
}

/*
 * Builds array of permitted mechanisms.  The array is allocated and
 * must be freed by the caller.
 */
int
crypto_build_permitted_mech_names(kcf_provider_desc_t *provider,
    crypto_mech_name_t **array, uint_t *count, int kmflag)
{
	crypto_mech_name_t *mech_names, *p;
	uint_t i;
	uint_t scnt = provider->pd_mech_list_count;
	uint_t dcnt = 0;

	/*
	 * Compute number of 'permitted mechanisms', which is
	 * 'supported mechanisms' - 'disabled mechanisms'.
	 */
	for (i = 0; i < scnt; i++) {
		if (is_mech_disabled(provider,
		    &provider->pd_mechanisms[i].cm_mech_name[0])) {
			dcnt++;
		}
	}

	/* all supported mechanisms have been disabled */
	if (scnt == dcnt) {
		*count = 0;
		*array = NULL;
		return (CRYPTO_SUCCESS);
	}

	mech_names = kmem_alloc((scnt - dcnt) * sizeof (crypto_mech_name_t),
	    kmflag);
	if (mech_names == NULL)
		return (CRYPTO_HOST_MEMORY);

	/* build array of permitted mechanisms */
	for (i = 0, p = mech_names; i < scnt; i++) {
		if (!is_mech_disabled(provider,
		    &provider->pd_mechanisms[i].cm_mech_name[0])) {
			bcopy(&provider->pd_mechanisms[i].cm_mech_name[0],
			    p++, sizeof (crypto_mech_name_t));
		}
	}

	*count = scnt - dcnt;
	*array = mech_names;
	return (CRYPTO_SUCCESS);
}

/*
 * Free memory for elements in a kcf_soft_config_entry_t.  This entry must
 * have been previously removed from the soft_config_list linked list.
 */
static void
free_soft_config_entry(kcf_soft_conf_entry_t *p)
{
	kmem_free(p->ce_name, strlen(p->ce_name) + 1);
	crypto_free_mech_list(p->ce_mechs, p->ce_count);
	kmem_free(p, sizeof (kcf_soft_conf_entry_t));
}

/*
 * Store configuration information for software providers in a linked list.
 * If the list already contains an entry for the specified provider
 * and the specified mechanism list has at least one mechanism, then
 * the mechanism list for the provider is updated. If the mechanism list
 * is empty, the entry for the provider is removed.
 *
 * Called from kcf_soft_config_init() (to initially populate the list
 * with default kernel providers) and from crypto_load_soft_config() for
 * the CRYPTO_LOAD_SOFT_CONFIG ioctl (for third-party kernel modules).
 *
 * Important note: the array argument must be allocated memory
 * since it is consumed in soft_config_list.
 *
 * Parameters:
 * name		Provider name to add or remove.
 * count	Number of mechanisms to add.
 *		If 0, then remove provider from the list (instead of add).
 * array	An array of "count" mechanism names (use only if count > 0).
 */
static int
add_soft_config(char *name, uint_t count, crypto_mech_name_t *array)
{
	static uint_t soft_config_count = 0;
	kcf_soft_conf_entry_t *prev = NULL, *entry = NULL, *new_entry, *p;
	size_t name_len;

	/*
	 * Allocate storage for a new entry.
	 * Free later if an entry already exists.
	 */
	name_len = strlen(name) + 1;
	new_entry = kmem_zalloc(sizeof (kcf_soft_conf_entry_t), KM_SLEEP);
	new_entry->ce_name = kmem_alloc(name_len, KM_SLEEP);
	(void) strcpy(new_entry->ce_name, name);

	mutex_enter(&soft_config_mutex);

	/* Search to see if provider already in soft_config_list */
	for (p = soft_config_list; p != NULL; p = p->ce_next) {
		if (strncmp(name, p->ce_name, MAXNAMELEN) == 0) { /* found */
			entry = p;
			break;
		}
		prev = p;
	}

	if (entry == NULL) { /* new provider (not in soft_config_list) */
		if (count == 0) { /* free memory--no entry exists to remove */
			mutex_exit(&soft_config_mutex);
			kmem_free(new_entry->ce_name, name_len);
			kmem_free(new_entry, sizeof (kcf_soft_conf_entry_t));
			return (CRYPTO_SUCCESS);
		}

		if (soft_config_count > KCF_MAX_CONFIG_ENTRIES) { /* full */
			mutex_exit(&soft_config_mutex);
			kmem_free(new_entry->ce_name, name_len);
			kmem_free(new_entry, sizeof (kcf_soft_conf_entry_t));
			cmn_err(CE_WARN, "out of soft_config_list entries");
			return (CRYPTO_FAILED);
		}

		/* add new provider to head of list */
		new_entry->ce_next = soft_config_list;
		soft_config_list = new_entry;
		soft_config_count++;
		entry = new_entry;

	} else { /* mechanism already in soft_config_list */
		kmem_free(new_entry->ce_name, name_len);
		kmem_free(new_entry, sizeof (kcf_soft_conf_entry_t));
	}

	if (count == 0) { /* remove provider entry from soft_config_list */
		if (prev == NULL) {
			/* entry to remove is at the head of the list */
			soft_config_list = entry->ce_next;
		} else {
			prev->ce_next = entry->ce_next;
		}
		soft_config_count--;
		mutex_exit(&soft_config_mutex);

		/* free entry */
		free_soft_config_entry(entry);

	} else { /* add provider entry to soft_config_list */
		/*
		 * Don't replace a mechanism list if it's already present.
		 * This is because the default entries for Software providers
		 * are more up-to-date than possibly stale entries in kcf.conf.
		 * If an entry is to be deleted, the proper way to do it is
		 * to add it to the disablelist (with cryptoadm(1M)),
		 * instead of removing it from the supportedlist.
		 */
		if (entry->ce_mechs == NULL) { /* add new mechanisms */
			entry->ce_mechs = array;
			entry->ce_count = count;
			mutex_exit(&soft_config_mutex);
		} else { /* ignore replacement mechanism list */
			mutex_exit(&soft_config_mutex);
			crypto_free_mech_list(array, count);
		}
	}

	return (CRYPTO_SUCCESS);
}

/*
 * This function removes a module entry from the soft_config_list.
 *
 * This comes in handy if FIPS 140 is enabled, but fails to validate.  At
 * which point when the kernel reports its' supported modules, it shows only
 * those that are not within the boundary
 */
void
remove_soft_config(char *name)
{
	kcf_soft_conf_entry_t *p, *entry = NULL, *prev = NULL;

	mutex_enter(&soft_config_mutex);
	/* Search for provider in soft_config_list */
	for (p = soft_config_list; p != NULL; p = p->ce_next) {
		if (strncmp(name, p->ce_name, MAXNAMELEN) == 0) {
			entry = p;
			break;
		}
		prev = p;
	}

	if (prev == NULL) {
		/* entry to remove is at the head of the list */
		soft_config_list = entry->ce_next;
	} else {
		prev->ce_next = entry->ce_next;
	}

	mutex_exit(&soft_config_mutex);

	/* free entry */
	free_soft_config_entry(entry);
}

/*
 * This routine searches the soft_config_list for the first entry that
 * has the specified mechanism in its mechanism list.  If found,
 * a buffer containing the name of the software module that implements
 * the mechanism is allocated and stored in 'name'.
 */
int
get_sw_provider_for_mech(crypto_mech_name_t mech, char **name)
{
	kcf_soft_conf_entry_t *p, *next;
	char tmp_name[MAXNAMELEN];
	size_t name_len = 0;
	int i;

	mutex_enter(&soft_config_mutex);
	p = soft_config_list;
	while (p != NULL) {
		next = p->ce_next;
		for (i = 0; i < p->ce_count; i++) {
			if (strncmp(mech, &p->ce_mechs[i][0],
			    CRYPTO_MAX_MECH_NAME) == 0) {
				name_len = strlen(p->ce_name) + 1;
				bcopy(p->ce_name, tmp_name, name_len);
				break;
			}
		}
		p = next;
	}
	mutex_exit(&soft_config_mutex);

	if (name_len == 0)
		return (CRYPTO_FAILED);

	*name = kmem_alloc(name_len, KM_SLEEP);
	bcopy(tmp_name, *name, name_len);
	return (CRYPTO_SUCCESS);
}
