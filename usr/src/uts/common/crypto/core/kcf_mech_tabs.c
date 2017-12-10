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
#include <sys/sunddi.h>
#include <sys/errno.h>
#include <sys/disp.h>
#include <sys/modctl.h>
#include <sys/modhash.h>
#include <sys/crypto/common.h>
#include <sys/crypto/api.h>
#include <sys/crypto/impl.h>

/* Cryptographic mechanisms tables and their access functions */

/*
 * Internal numbers assigned to mechanisms are coded as follows:
 *
 * +----------------+----------------+
 * | mech. class    | mech. index    |
 * <--- 32-bits --->+<--- 32-bits --->
 *
 * the mech_class identifies the table the mechanism belongs to.
 * mech_index  is the index for that mechanism in the table.
 * A mechanism belongs to exactly 1 table.
 * The tables are:
 * . digest_mechs_tab[] for the msg digest mechs.
 * . cipher_mechs_tab[] for encrypt/decrypt and wrap/unwrap mechs.
 * . mac_mechs_tab[] for MAC mechs.
 * . sign_mechs_tab[] for sign & verify mechs.
 * . keyops_mechs_tab[] for key/key pair generation, and key derivation.
 * . misc_mechs_tab[] for mechs that don't belong to any of the above.
 *
 * There are no holes in the tables.
 */

/*
 * Locking conventions:
 * --------------------
 * A global mutex, kcf_mech_tabs_lock, serializes writes to the
 * mechanism table via kcf_create_mech_entry().
 *
 * A mutex is associated with every entry of the tables.
 * The mutex is acquired whenever the entry is accessed for
 * 1) retrieving the mech_id (comparing the mech name)
 * 2) finding a provider for an xxx_init() or atomic operation.
 * 3) altering the mechs entry to add or remove a provider.
 *
 * In 2), after a provider is chosen, its prov_desc is held and the
 * entry's mutex must be dropped. The provider's working function (SPI) is
 * called outside the mech_entry's mutex.
 *
 * The number of providers for a particular mechanism is not expected to be
 * long enough to justify the cost of using rwlocks, so the per-mechanism
 * entry mutex won't be very *hot*.
 *
 * When both kcf_mech_tabs_lock and a mech_entry mutex need to be held,
 * kcf_mech_tabs_lock must always be acquired first.
 *
 */

		/* Mechanisms tables */


/* RFE 4687834 Will deal with the extensibility of these tables later */

kcf_mech_entry_t kcf_digest_mechs_tab[KCF_MAXDIGEST];
kcf_mech_entry_t kcf_cipher_mechs_tab[KCF_MAXCIPHER];
kcf_mech_entry_t kcf_mac_mechs_tab[KCF_MAXMAC];
kcf_mech_entry_t kcf_sign_mechs_tab[KCF_MAXSIGN];
kcf_mech_entry_t kcf_keyops_mechs_tab[KCF_MAXKEYOPS];
kcf_mech_entry_t kcf_misc_mechs_tab[KCF_MAXMISC];

kcf_mech_entry_tab_t kcf_mech_tabs_tab[KCF_LAST_OPSCLASS + 1] = {
	{0, NULL},				/* No class zero */
	{KCF_MAXDIGEST, kcf_digest_mechs_tab},
	{KCF_MAXCIPHER, kcf_cipher_mechs_tab},
	{KCF_MAXMAC, kcf_mac_mechs_tab},
	{KCF_MAXSIGN, kcf_sign_mechs_tab},
	{KCF_MAXKEYOPS, kcf_keyops_mechs_tab},
	{KCF_MAXMISC, kcf_misc_mechs_tab}
};

/*
 * Protects fields in kcf_mech_entry. This is an array
 * of locks indexed by the cpuid. A reader needs to hold
 * a single lock while a writer needs to hold all locks.
 * krwlock_t is not an option here because the hold time
 * is very small for these locks.
 */
kcf_lock_withpad_t *me_mutexes;

#define	ME_MUTEXES_ENTER_ALL()	\
	for (int i = 0; i < max_ncpus; i++)	\
		mutex_enter(&me_mutexes[i].kl_lock);

#define	ME_MUTEXES_EXIT_ALL()	\
	for (int i = 0; i < max_ncpus; i++)	\
		mutex_exit(&me_mutexes[i].kl_lock);

/*
 * Per-algorithm internal thresholds for the minimum input size of before
 * offloading to hardware provider.
 * Dispatching a crypto operation  to a hardware provider entails paying the
 * cost of an additional context switch.  Measurments with Sun Accelerator 4000
 * shows that 512-byte jobs or smaller are better handled in software.
 * There is room for refinement here.
 *
 */
int kcf_md5_threshold = 512;
int kcf_sha1_threshold = 512;
int kcf_des_threshold = 512;
int kcf_des3_threshold = 512;
int kcf_aes_threshold = 512;
int kcf_bf_threshold = 512;
int kcf_rc4_threshold = 512;

kmutex_t kcf_mech_tabs_lock;
static uint32_t kcf_gen_swprov = 0;

int kcf_mech_hash_size = 256;
mod_hash_t *kcf_mech_hash;	/* mech name to id hash */

static crypto_mech_type_t
kcf_mech_hash_find(char *mechname)
{
	mod_hash_val_t hv;
	crypto_mech_type_t mt;

	mt = CRYPTO_MECH_INVALID;
	if (mod_hash_find(kcf_mech_hash, (mod_hash_key_t)mechname, &hv) == 0) {
		mt = *(crypto_mech_type_t *)hv;
		ASSERT(mt != CRYPTO_MECH_INVALID);
	}

	return (mt);
}

/*
 * kcf_init_mech_tabs()
 *
 * Called by the misc/kcf's _init() routine to initialize the tables
 * of mech_entry's.
 */
void
kcf_init_mech_tabs()
{
	int i, max;
	kcf_ops_class_t class;
	kcf_mech_entry_t *me_tab;

	/* Initializes the mutex locks. */

	mutex_init(&kcf_mech_tabs_lock, NULL, MUTEX_DEFAULT, NULL);

	/* Then the pre-defined mechanism entries */

	/* Two digests */
	(void) strncpy(kcf_digest_mechs_tab[0].me_name, SUN_CKM_MD5,
	    CRYPTO_MAX_MECH_NAME);
	kcf_digest_mechs_tab[0].me_threshold = kcf_md5_threshold;

	(void) strncpy(kcf_digest_mechs_tab[1].me_name, SUN_CKM_SHA1,
	    CRYPTO_MAX_MECH_NAME);
	kcf_digest_mechs_tab[1].me_threshold = kcf_sha1_threshold;

	/* The symmetric ciphers in various modes */
	(void) strncpy(kcf_cipher_mechs_tab[0].me_name, SUN_CKM_DES_CBC,
	    CRYPTO_MAX_MECH_NAME);
	kcf_cipher_mechs_tab[0].me_threshold = kcf_des_threshold;

	(void) strncpy(kcf_cipher_mechs_tab[1].me_name, SUN_CKM_DES3_CBC,
	    CRYPTO_MAX_MECH_NAME);
	kcf_cipher_mechs_tab[1].me_threshold = kcf_des3_threshold;

	(void) strncpy(kcf_cipher_mechs_tab[2].me_name, SUN_CKM_DES_ECB,
	    CRYPTO_MAX_MECH_NAME);
	kcf_cipher_mechs_tab[2].me_threshold = kcf_des_threshold;

	(void) strncpy(kcf_cipher_mechs_tab[3].me_name, SUN_CKM_DES3_ECB,
	    CRYPTO_MAX_MECH_NAME);
	kcf_cipher_mechs_tab[3].me_threshold = kcf_des3_threshold;

	(void) strncpy(kcf_cipher_mechs_tab[4].me_name, SUN_CKM_BLOWFISH_CBC,
	    CRYPTO_MAX_MECH_NAME);
	kcf_cipher_mechs_tab[4].me_threshold = kcf_bf_threshold;

	(void) strncpy(kcf_cipher_mechs_tab[5].me_name, SUN_CKM_BLOWFISH_ECB,
	    CRYPTO_MAX_MECH_NAME);
	kcf_cipher_mechs_tab[5].me_threshold = kcf_bf_threshold;

	(void) strncpy(kcf_cipher_mechs_tab[6].me_name, SUN_CKM_AES_CBC,
	    CRYPTO_MAX_MECH_NAME);
	kcf_cipher_mechs_tab[6].me_threshold = kcf_aes_threshold;

	(void) strncpy(kcf_cipher_mechs_tab[7].me_name, SUN_CKM_AES_ECB,
	    CRYPTO_MAX_MECH_NAME);
	kcf_cipher_mechs_tab[7].me_threshold = kcf_aes_threshold;

	(void) strncpy(kcf_cipher_mechs_tab[8].me_name, SUN_CKM_RC4,
	    CRYPTO_MAX_MECH_NAME);
	kcf_cipher_mechs_tab[8].me_threshold = kcf_rc4_threshold;


	/* 6 HMACs */
	(void) strncpy(kcf_mac_mechs_tab[0].me_name, SUN_CKM_MD5_HMAC,
	    CRYPTO_MAX_MECH_NAME);
	kcf_mac_mechs_tab[0].me_threshold = kcf_md5_threshold;

	(void) strncpy(kcf_mac_mechs_tab[1].me_name, SUN_CKM_MD5_HMAC_GENERAL,
	    CRYPTO_MAX_MECH_NAME);
	kcf_mac_mechs_tab[1].me_threshold = kcf_md5_threshold;

	(void) strncpy(kcf_mac_mechs_tab[2].me_name, SUN_CKM_SHA1_HMAC,
	    CRYPTO_MAX_MECH_NAME);
	kcf_mac_mechs_tab[2].me_threshold = kcf_sha1_threshold;

	(void) strncpy(kcf_mac_mechs_tab[3].me_name, SUN_CKM_SHA1_HMAC_GENERAL,
	    CRYPTO_MAX_MECH_NAME);
	kcf_mac_mechs_tab[3].me_threshold = kcf_sha1_threshold;

	(void) strncpy(kcf_mac_mechs_tab[4].me_name, SUN_CKM_AES_GMAC,
	    CRYPTO_MAX_MECH_NAME);
	kcf_mac_mechs_tab[4].me_threshold = kcf_sha1_threshold;

	(void) strncpy(kcf_mac_mechs_tab[5].me_name, SUN_CKM_AES_CMAC,
	    CRYPTO_MAX_MECH_NAME);
	kcf_mac_mechs_tab[5].me_threshold = kcf_sha1_threshold;

	/* 1 random number generation pseudo mechanism */
	(void) strncpy(kcf_misc_mechs_tab[0].me_name, SUN_RANDOM,
	    CRYPTO_MAX_MECH_NAME);

	kcf_mech_hash = mod_hash_create_strhash("kcf mech2id hash",
	    kcf_mech_hash_size, mod_hash_null_valdtor);

	for (class = KCF_FIRST_OPSCLASS; class <= KCF_LAST_OPSCLASS; class++) {
		max = kcf_mech_tabs_tab[class].met_size;
		me_tab = kcf_mech_tabs_tab[class].met_tab;
		for (i = 0; i < max; i++) {
			if (me_tab[i].me_name[0] != 0) {
				me_tab[i].me_mechid = KCF_MECHID(class, i);
				(void) mod_hash_insert(kcf_mech_hash,
				    (mod_hash_key_t)me_tab[i].me_name,
				    (mod_hash_val_t)&(me_tab[i].me_mechid));
			}
		}
	}

	me_mutexes = kmem_zalloc(max_ncpus * sizeof (kcf_lock_withpad_t),
	    KM_SLEEP);
	for (i = 0; i < max_ncpus; i++) {
		mutex_init(&me_mutexes[i].kl_lock, NULL, MUTEX_DEFAULT, NULL);
	}
}

/*
 * kcf_create_mech_entry()
 *
 * Arguments:
 *	. The class of mechanism.
 *	. the name of the new mechanism.
 *
 * Description:
 *	Creates a new mech_entry for a mechanism not yet known to the
 *	framework.
 *	This routine is called by kcf_add_mech_provider, which is
 *	in turn invoked for each mechanism supported by a provider.
 *	The'class' argument depends on the crypto_func_group_t bitmask
 *	in the registering provider's mech_info struct for this mechanism.
 *	When there is ambiguity in the mapping between the crypto_func_group_t
 *	and a class (dual ops, ...) the KCF_MISC_CLASS should be used.
 *
 * Context:
 *	User context only.
 *
 * Returns:
 *	KCF_INVALID_MECH_CLASS or KCF_INVALID_MECH_NAME if the class or
 *	the mechname is bogus.
 *	KCF_MECH_TAB_FULL when there is no room left in the mech. tabs.
 *	KCF_SUCCESS otherwise.
 */
static int
kcf_create_mech_entry(kcf_ops_class_t class, char *mechname)
{
	crypto_mech_type_t mt;
	kcf_mech_entry_t *me_tab;
	int i = 0, size;

	if ((class < KCF_FIRST_OPSCLASS) || (class > KCF_LAST_OPSCLASS))
		return (KCF_INVALID_MECH_CLASS);

	if ((mechname == NULL) || (mechname[0] == 0))
		return (KCF_INVALID_MECH_NAME);
	/*
	 * First check if the mechanism is already in one of the tables.
	 * The mech_entry could be in another class.
	 */
	mutex_enter(&kcf_mech_tabs_lock);
	mt = kcf_mech_hash_find(mechname);
	if (mt != CRYPTO_MECH_INVALID) {
		/* Nothing to do, regardless the suggested class. */
		mutex_exit(&kcf_mech_tabs_lock);
		return (KCF_SUCCESS);
	}
	/* Now take the next unused mech entry in the class's tab */
	me_tab = kcf_mech_tabs_tab[class].met_tab;
	size = kcf_mech_tabs_tab[class].met_size;

	while (i < size) {
		ME_MUTEXES_ENTER_ALL();
		if (me_tab[i].me_name[0] == 0) {
			/* Found an empty spot */
			(void) strncpy(me_tab[i].me_name, mechname,
			    CRYPTO_MAX_MECH_NAME);
			me_tab[i].me_name[CRYPTO_MAX_MECH_NAME-1] = '\0';
			me_tab[i].me_mechid = KCF_MECHID(class, i);
			/*
			 * No a-priori information about the new mechanism, so
			 * the threshold is set to zero.
			 */
			me_tab[i].me_threshold = 0;

			ME_MUTEXES_EXIT_ALL();
			/* Add the new mechanism to the hash table */
			(void) mod_hash_insert(kcf_mech_hash,
			    (mod_hash_key_t)me_tab[i].me_name,
			    (mod_hash_val_t)&(me_tab[i].me_mechid));
			break;
		}
		ME_MUTEXES_EXIT_ALL();
		i++;
	}

	mutex_exit(&kcf_mech_tabs_lock);

	if (i == size) {
		return (KCF_MECH_TAB_FULL);
	}

	return (KCF_SUCCESS);
}

/*
 * kcf_add_mech_provider()
 *
 * Arguments:
 *	. An index in to  the provider mechanism array
 *      . A pointer to the provider descriptor
 *	. A storage for the kcf_prov_mech_desc_t the entry was added at.
 *
 * Description:
 *      Adds  a new provider of a mechanism to the mechanism's mech_entry
 *	chain.
 *
 * Context:
 *      User context only.
 *
 * Returns
 *      KCF_SUCCESS on success
 *      KCF_MECH_TAB_FULL otherwise.
 */
int
kcf_add_mech_provider(short mech_indx,
    kcf_provider_desc_t *prov_desc, kcf_prov_mech_desc_t **pmdpp)
{
	int error;
	kcf_mech_entry_t *mech_entry;
	crypto_mech_info_t *mech_info;
	crypto_mech_type_t kcf_mech_type, mt;
	kcf_prov_mech_desc_t *prov_mech, *prov_mech2;
	crypto_func_group_t simple_fg_mask, dual_fg_mask;
	crypto_mech_info_t *dmi;
	crypto_mech_info_list_t *mil, *mil2;
	kcf_mech_entry_t *me;
	int i;

	ASSERT(prov_desc->pd_prov_type != CRYPTO_LOGICAL_PROVIDER);

	mech_info = &prov_desc->pd_mechanisms[mech_indx];
	/*
	 * Do not use the provider for the mechanism if
	 * policy does not allow it.
	 */
	if (is_mech_disabled(prov_desc, mech_info->cm_mech_name)) {
		*pmdpp = NULL;
		return (KCF_SUCCESS);
	}

	/*
	 * A mechanism belongs to exactly one mechanism table.
	 * Find the class corresponding to the function group flag of
	 * the mechanism.
	 */
	kcf_mech_type = kcf_mech_hash_find(mech_info->cm_mech_name);
	if (kcf_mech_type == CRYPTO_MECH_INVALID) {
		crypto_func_group_t fg = mech_info->cm_func_group_mask;
		kcf_ops_class_t class;

		if (fg & CRYPTO_FG_DIGEST || fg & CRYPTO_FG_DIGEST_ATOMIC)
			class = KCF_DIGEST_CLASS;
		else if (fg & CRYPTO_FG_ENCRYPT || fg & CRYPTO_FG_DECRYPT ||
		    fg & CRYPTO_FG_ENCRYPT_ATOMIC ||
		    fg & CRYPTO_FG_DECRYPT_ATOMIC)
			class = KCF_CIPHER_CLASS;
		else if (fg & CRYPTO_FG_MAC || fg & CRYPTO_FG_MAC_ATOMIC)
			class = KCF_MAC_CLASS;
		else if (fg & CRYPTO_FG_SIGN || fg & CRYPTO_FG_VERIFY ||
		    fg & CRYPTO_FG_SIGN_ATOMIC ||
		    fg & CRYPTO_FG_VERIFY_ATOMIC ||
		    fg & CRYPTO_FG_SIGN_RECOVER ||
		    fg & CRYPTO_FG_VERIFY_RECOVER)
			class = KCF_SIGN_CLASS;
		else if (fg & CRYPTO_FG_GENERATE ||
		    fg & CRYPTO_FG_GENERATE_KEY_PAIR ||
		    fg & CRYPTO_FG_WRAP || fg & CRYPTO_FG_UNWRAP ||
		    fg & CRYPTO_FG_DERIVE)
			class = KCF_KEYOPS_CLASS;
		else
			class = KCF_MISC_CLASS;

		/*
		 * Attempt to create a new mech_entry for the specified
		 * mechanism. kcf_create_mech_entry() can handle the case
		 * where such an entry already exists.
		 */
		if ((error = kcf_create_mech_entry(class,
		    mech_info->cm_mech_name)) != KCF_SUCCESS) {
			return (error);
		}
		/* get the KCF mech type that was assigned to the mechanism */
		kcf_mech_type = kcf_mech_hash_find(mech_info->cm_mech_name);
		ASSERT(kcf_mech_type != CRYPTO_MECH_INVALID);
	}

	error = kcf_get_mech_entry(kcf_mech_type, &mech_entry);
	ASSERT(error == KCF_SUCCESS);

	/* allocate and initialize new kcf_prov_mech_desc */
	prov_mech = kmem_zalloc(sizeof (kcf_prov_mech_desc_t), KM_SLEEP);
	bcopy(mech_info, &prov_mech->pm_mech_info, sizeof (crypto_mech_info_t));
	prov_mech->pm_prov_desc = prov_desc;
	prov_desc->pd_mech_indx[KCF_MECH2CLASS(kcf_mech_type)]
	    [KCF_MECH2INDEX(kcf_mech_type)] = mech_indx;

	KCF_PROV_REFHOLD(prov_desc);

	dual_fg_mask = mech_info->cm_func_group_mask & CRYPTO_FG_DUAL_MASK;

	if (dual_fg_mask == ((crypto_func_group_t)0))
		goto add_entry;

	simple_fg_mask = mech_info->cm_func_group_mask &
	    CRYPTO_FG_SIMPLEOP_MASK | CRYPTO_FG_RANDOM;

	for (i = 0; i < prov_desc->pd_mech_list_count; i++) {
		dmi = &prov_desc->pd_mechanisms[i];

		/* skip self */
		if (dmi->cm_mech_number == mech_info->cm_mech_number)
			continue;

		/* skip if policy doesn't allow mechanism */
		if (is_mech_disabled(prov_desc, dmi->cm_mech_name))
			continue;

		/* skip if not a dual operation mechanism */
		if (!(dmi->cm_func_group_mask & dual_fg_mask) ||
		    (dmi->cm_func_group_mask & simple_fg_mask))
			continue;

		mt = kcf_mech_hash_find(dmi->cm_mech_name);
		if (mt == CRYPTO_MECH_INVALID)
			continue;

		if (kcf_get_mech_entry(mt, &me) != KCF_SUCCESS)
			continue;

		mil = kmem_zalloc(sizeof (*mil), KM_SLEEP);
		mil2 = kmem_zalloc(sizeof (*mil2), KM_SLEEP);

		/*
		 * Ignore hard-coded entries in the mech table
		 * if the provider hasn't registered.
		 */
		ME_MUTEXES_ENTER_ALL();
		if (me->me_hw_prov_chain == NULL && me->me_sw_prov == NULL) {
			ME_MUTEXES_EXIT_ALL();
			kmem_free(mil, sizeof (*mil));
			kmem_free(mil2, sizeof (*mil2));
			continue;
		}

		/*
		 * Add other dual mechanisms that have registered
		 * with the framework to this mechanism's
		 * cross-reference list.
		 */
		mil->ml_mech_info = *dmi; /* struct assignment */
		mil->ml_kcf_mechid = mt;

		/* add to head of list */
		mil->ml_next = prov_mech->pm_mi_list;
		prov_mech->pm_mi_list = mil;

		if (prov_desc->pd_prov_type == CRYPTO_HW_PROVIDER)
			prov_mech2 = me->me_hw_prov_chain;
		else
			prov_mech2 = me->me_sw_prov;

		if (prov_mech2 == NULL) {
			kmem_free(mil2, sizeof (*mil2));
			ME_MUTEXES_EXIT_ALL();
			continue;
		}

		/*
		 * Update all other cross-reference lists by
		 * adding this new mechanism.
		 */
		while (prov_mech2 != NULL) {
			if (prov_mech2->pm_prov_desc == prov_desc) {
				/* struct assignment */
				mil2->ml_mech_info = *mech_info;
				mil2->ml_kcf_mechid = kcf_mech_type;

				/* add to head of list */
				mil2->ml_next = prov_mech2->pm_mi_list;
				prov_mech2->pm_mi_list = mil2;
				break;
			}
			prov_mech2 = prov_mech2->pm_next;
		}
		if (prov_mech2 == NULL)
			kmem_free(mil2, sizeof (*mil2));

		ME_MUTEXES_EXIT_ALL();
	}

add_entry:
	/*
	 * Add new kcf_prov_mech_desc at the front of HW providers
	 * chain.
	 */
	switch (prov_desc->pd_prov_type) {

	case CRYPTO_HW_PROVIDER:
		ME_MUTEXES_ENTER_ALL();
		prov_mech->pm_me = mech_entry;
		prov_mech->pm_next = mech_entry->me_hw_prov_chain;
		mech_entry->me_hw_prov_chain = prov_mech;
		mech_entry->me_num_hwprov++;
		ME_MUTEXES_EXIT_ALL();
		break;

	case CRYPTO_SW_PROVIDER:
		ME_MUTEXES_ENTER_ALL();
		if (mech_entry->me_sw_prov != NULL) {
			/*
			 * There is already a SW provider for this mechanism.
			 * Since we allow only one SW provider per mechanism,
			 * report this condition.
			 */
			cmn_err(CE_WARN, "The cryptographic software provider "
			    "\"%s\" will not be used for %s. The provider "
			    "\"%s\" will be used for this mechanism "
			    "instead.", prov_desc->pd_description,
			    mech_info->cm_mech_name,
			    mech_entry->me_sw_prov->pm_prov_desc->
			    pd_description);
			KCF_PROV_REFRELE(prov_desc);
			kmem_free(prov_mech, sizeof (kcf_prov_mech_desc_t));
			prov_mech = NULL;
		} else {
			/*
			 * Set the provider as the software provider for
			 * this mechanism.
			 */
			mech_entry->me_sw_prov = prov_mech;

			/* We'll wrap around after 4 billion registrations! */
			mech_entry->me_gen_swprov = kcf_gen_swprov++;
		}
		ME_MUTEXES_EXIT_ALL();
		break;
	}

	*pmdpp = prov_mech;

	return (KCF_SUCCESS);
}

/*
 * kcf_remove_mech_provider()
 *
 * Arguments:
 *      . mech_name: the name of the mechanism.
 *      . prov_desc: The provider descriptor
 *
 * Description:
 *      Removes a provider from chain of provider descriptors.
 *	The provider is made unavailable to kernel consumers for the specified
 *	mechanism.
 *
 * Context:
 *      User context only.
 */
void
kcf_remove_mech_provider(char *mech_name, kcf_provider_desc_t *prov_desc)
{
	crypto_mech_type_t mech_type;
	kcf_prov_mech_desc_t *prov_mech, *prov_chain;
	kcf_prov_mech_desc_t **prev_entry_next;
	kcf_mech_entry_t *mech_entry;
	crypto_mech_info_list_t *mil, *mil2, *next, **prev_next;

	ASSERT(prov_desc->pd_prov_type != CRYPTO_LOGICAL_PROVIDER);

	/* get the KCF mech type that was assigned to the mechanism */
	if ((mech_type = kcf_mech_hash_find(mech_name)) ==
	    CRYPTO_MECH_INVALID) {
		/*
		 * Provider was not allowed for this mech due to policy or
		 * configuration.
		 */
		return;
	}

	/* get a ptr to the mech_entry that was created */
	if (kcf_get_mech_entry(mech_type, &mech_entry) != KCF_SUCCESS) {
		/*
		 * Provider was not allowed for this mech due to policy or
		 * configuration.
		 */
		return;
	}

	ME_MUTEXES_ENTER_ALL();

	switch (prov_desc->pd_prov_type) {

	case CRYPTO_HW_PROVIDER:
		/* find the provider in the mech_entry chain */
		prev_entry_next = &mech_entry->me_hw_prov_chain;
		prov_mech = mech_entry->me_hw_prov_chain;
		while (prov_mech != NULL &&
		    prov_mech->pm_prov_desc != prov_desc) {
			prev_entry_next = &prov_mech->pm_next;
			prov_mech = prov_mech->pm_next;
		}

		if (prov_mech == NULL) {
			/* entry not found, simply return */
			ME_MUTEXES_EXIT_ALL();
			return;
		}

		/* remove provider entry from mech_entry chain */
		*prev_entry_next = prov_mech->pm_next;
		ASSERT(mech_entry->me_num_hwprov > 0);
		mech_entry->me_num_hwprov--;
		break;

	case CRYPTO_SW_PROVIDER:
		if (mech_entry->me_sw_prov == NULL ||
		    mech_entry->me_sw_prov->pm_prov_desc != prov_desc) {
			/* not the software provider for this mechanism */
			ME_MUTEXES_EXIT_ALL();
			return;
		}
		prov_mech = mech_entry->me_sw_prov;
		mech_entry->me_sw_prov = NULL;
		break;
	}

	ME_MUTEXES_EXIT_ALL();

	/* Free the dual ops cross-reference lists  */
	mil = prov_mech->pm_mi_list;
	while (mil != NULL) {
		next = mil->ml_next;
		if (kcf_get_mech_entry(mil->ml_kcf_mechid,
		    &mech_entry) != KCF_SUCCESS) {
			mil = next;
			continue;
		}

		ME_MUTEXES_ENTER_ALL();
		if (prov_desc->pd_prov_type == CRYPTO_HW_PROVIDER)
			prov_chain = mech_entry->me_hw_prov_chain;
		else
			prov_chain = mech_entry->me_sw_prov;

		while (prov_chain != NULL) {
			if (prov_chain->pm_prov_desc == prov_desc) {
				prev_next = &prov_chain->pm_mi_list;
				mil2 = prov_chain->pm_mi_list;
				while (mil2 != NULL &&
				    mil2->ml_kcf_mechid != mech_type) {
					prev_next = &mil2->ml_next;
					mil2 = mil2->ml_next;
				}
				if (mil2 != NULL) {
					*prev_next = mil2->ml_next;
					kmem_free(mil2, sizeof (*mil2));
				}
				break;
			}
			prov_chain = prov_chain->pm_next;
		}

		ME_MUTEXES_EXIT_ALL();
		kmem_free(mil, sizeof (crypto_mech_info_list_t));
		mil = next;
	}

	/* free entry  */
	KCF_PROV_REFRELE(prov_mech->pm_prov_desc);
	kmem_free(prov_mech, sizeof (kcf_prov_mech_desc_t));
}

/*
 * kcf_get_mech_entry()
 *
 * Arguments:
 *      . The framework mechanism type
 *      . Storage for the mechanism entry
 *
 * Description:
 *      Retrieves the mechanism entry for the mech.
 *
 * Context:
 *      User and interrupt contexts.
 *
 * Returns:
 *      KCF_MECHANISM_XXX appropriate error code.
 *      KCF_SUCCESS otherwise.
 */
int
kcf_get_mech_entry(crypto_mech_type_t mech_type, kcf_mech_entry_t **mep)
{
	kcf_ops_class_t		class;
	int			index;
	kcf_mech_entry_tab_t	*me_tab;

	ASSERT(mep != NULL);

	class = KCF_MECH2CLASS(mech_type);

	if ((class < KCF_FIRST_OPSCLASS) || (class > KCF_LAST_OPSCLASS)) {
		/* the caller won't need to know it's an invalid class */
		return (KCF_INVALID_MECH_NUMBER);
	}

	me_tab = &kcf_mech_tabs_tab[class];
	index = KCF_MECH2INDEX(mech_type);

	if ((index < 0) || (index >= me_tab->met_size)) {
		return (KCF_INVALID_MECH_NUMBER);
	}

	*mep = &((me_tab->met_tab)[index]);

	return (KCF_SUCCESS);
}

/*
 * Returns TRUE if the provider is usable and the MOD_NOAUTOUNLOAD flag
 * is set in the modctl structure.
 */
static boolean_t
auto_unload_flag_set(kcf_prov_mech_desc_t *pm)
{
	kcf_provider_desc_t *pd;
	struct modctl *mp;
	boolean_t ret = B_FALSE;

	if (pm != NULL) {
		pd = pm->pm_prov_desc;
		KCF_PROV_REFHOLD(pd);

		if (KCF_IS_PROV_USABLE(pd)) {
			mp = pd->pd_mctlp;
			if (mp->mod_loadflags & MOD_NOAUTOUNLOAD) {
				ret = B_TRUE;
			}
		}
		KCF_PROV_REFRELE(pd);
	}

	return (ret);
}

/*
 * Lookup the hash table for an entry that matches the mechname.
 * If there are no hardware or software providers for the mechanism,
 * but there is an unloaded software provider, this routine will attempt
 * to load it.
 *
 * If the MOD_NOAUTOUNLOAD flag is not set, a software provider is
 * in constant danger of being unloaded.  For consumers that call
 * crypto_mech2id() only once, the provider will not be reloaded
 * if it becomes unloaded.  If a provider gets loaded elsewhere
 * without the MOD_NOAUTOUNLOAD flag being set, we set it now.
 */
crypto_mech_type_t
crypto_mech2id_common(char *mechname, boolean_t load_module)
{
	crypto_mech_type_t mt;
	kcf_mech_entry_t *me;
	int i;
	kcf_ops_class_t class;
	boolean_t second_time = B_FALSE;
	boolean_t try_to_load_software_provider = B_FALSE;
	kcf_lock_withpad_t *mp;

try_again:
	mt = kcf_mech_hash_find(mechname);
	if (!load_module || second_time == B_TRUE || servicing_interrupt())
		return (mt);

	if (mt != CRYPTO_MECH_INVALID) {
		class = KCF_MECH2CLASS(mt);
		i = KCF_MECH2INDEX(mt);
		me = &(kcf_mech_tabs_tab[class].met_tab[i]);
		mp = &me_mutexes[CPU_SEQID];
		mutex_enter(&mp->kl_lock);

		if (load_module && !auto_unload_flag_set(me->me_sw_prov)) {
			try_to_load_software_provider = B_TRUE;
		}
		mutex_exit(&mp->kl_lock);
	}

	if (mt == CRYPTO_MECH_INVALID || try_to_load_software_provider) {
		struct modctl *mcp;
		boolean_t load_again = B_FALSE;
		char *module_name;
		int module_name_size;

		/* try to find a software provider for the mechanism */
		if (get_sw_provider_for_mech(mechname, &module_name)
		    != CRYPTO_SUCCESS) {
			/* mt may already be set for a hw provider */
			return (mt);
		}

		module_name_size = strlen(module_name) + 1;
		if (modload("crypto", module_name) == -1 ||
		    (mcp = mod_hold_by_name(module_name)) == NULL) {
			kmem_free(module_name, module_name_size);
			/* mt may already be set for a hw provider */
			return (mt);
		}

		mcp->mod_loadflags |= MOD_NOAUTOUNLOAD;

		/* memory pressure may have unloaded the module */
		if (!mcp->mod_installed)
			load_again = B_TRUE;
		mod_release_mod(mcp);

		if (load_again)
			(void) modload("crypto", module_name);

		kmem_free(module_name, module_name_size);

		/* mt may already be set for a hw provider */
		if (mt != CRYPTO_MECH_INVALID)
			return (mt);

		/*
		 * Try again.  Should find a software provider in the
		 * table this time around.
		 */
		second_time = B_TRUE;
		goto try_again;
	}

	return (mt);
}
