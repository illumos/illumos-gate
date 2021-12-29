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
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <sys/types.h>
#include <sys/sunddi.h>
#include <sys/disp.h>
#include <sys/modctl.h>
#include <sys/sysmacros.h>
#include <sys/crypto/common.h>
#include <sys/crypto/api.h>
#include <sys/crypto/impl.h>
#include <sys/crypto/sched_impl.h>

#define	isspace(ch)	(((ch) == ' ') || ((ch) == '\r') || ((ch) == '\n') || \
			((ch) == '\t') || ((ch) == '\f'))

#define	CRYPTO_OPS_OFFSET(f)		offsetof(crypto_ops_t, co_##f)
#define	CRYPTO_KEY_OFFSET(f)		offsetof(crypto_key_ops_t, f)
#define	CRYPTO_PROVIDER_OFFSET(f)	\
	offsetof(crypto_provider_management_ops_t, f)

/* Miscellaneous exported entry points */

/*
 * All event subscribers are put on a list. kcf_notify_list_lock
 * protects changes to this list.
 *
 * The following locking order is maintained in the code - The
 * global kcf_notify_list_lock followed by the individual lock
 * in a kcf_ntfy_elem structure (kn_lock).
 */
kmutex_t		ntfy_list_lock;
kcondvar_t		ntfy_list_cv;   /* cv the service thread waits on */
static kcf_ntfy_elem_t *ntfy_list_head;
static kcf_ntfy_elem_t *ntfy_list_tail;

/* count all the hardware and software providers */
#define	PROV_COUNT(me) \
	(((me)->me_sw_prov != NULL ? 1 : 0) + (me)->me_num_hwprov)

/*
 * crypto_mech2id()
 *
 * Arguments:
 *	. mechname: A null-terminated string identifying the mechanism name.
 *
 * Description:
 *	Walks the mechanisms tables, looking for an entry that matches the
 *	mechname. Once it find it, it builds the 64-bit mech_type and returns
 *	it.  If there are no hardware or software providers for the mechanism,
 *	but there is an unloaded software provider, this routine will attempt
 *	to load it.
 *
 * Context:
 *	Process and interruption.
 *
 * Returns:
 *	The unique mechanism identified by 'mechname', if found.
 *	CRYPTO_MECH_INVALID otherwise.
 */
crypto_mech_type_t
crypto_mech2id(const char *mechname)
{
	return (crypto_mech2id_common((char *)mechname, B_TRUE));
}

/*
 * crypto_get_mech_list()
 *
 * Arguments:
 *	. countp: pointer to contain the number of mech names returned
 *	. kmflag: memory allocation flag.
 *
 * Description:
 *	Allocates an array of crypto_mech_name_t containing all the mechanisms
 *	currently available on the system. Sets *countp with the number of
 *	mechanism names returned.
 *
 *	We get a list of mech names which have a hardware provider by walking
 *	all the mechanism tables. We merge them with mech names obtained from
 *	the hint list. A mech name in the hint list is considered only if it
 *	is not disabled for the provider. Note that the hint list contains only
 *	software providers and the mech names supported by them.
 *
 * Context:
 *	Process and interruption. kmflag should be KM_NOSLEEP when called
 *	from an interruption context.
 *
 * Returns:
 *	The array of the crypto_mech_t allocated.
 *	NULL otherwise.
 */
crypto_mech_name_t *
crypto_get_mech_list(uint_t *countp, int kmflag)
{
	uint_t count = 0, me_tab_size, i, j;
	kcf_ops_class_t cl;
	kcf_mech_entry_t *me, *me_tab;
	crypto_mech_name_t *mech_name_tab, *tmp_mech_name_tab;
	char *mech_name, *hint_mech, *end;
	kcf_soft_conf_entry_t *p;
	size_t n;
	kcf_lock_withpad_t *mp;

	/*
	 * Count the maximum possible mechanisms that can come from the
	 * hint list.
	 */
	mutex_enter(&soft_config_mutex);
	p = soft_config_list;
	while (p != NULL) {
		count += p->ce_count;
		p = p->ce_next;
	}
	mutex_exit(&soft_config_mutex);

	/* First let's count'em, for mem allocation */
	for (cl = KCF_FIRST_OPSCLASS; cl <= KCF_LAST_OPSCLASS; cl++) {
		me_tab_size = kcf_mech_tabs_tab[cl].met_size;
		me_tab = kcf_mech_tabs_tab[cl].met_tab;
		for (i = 0; i < me_tab_size; i++) {
			me = &me_tab[i];
			mp = &me_mutexes[CPU_SEQID];
			mutex_enter(&mp->kl_lock);
			if ((me->me_name[0] != 0) && (me->me_num_hwprov >= 1)) {
				ASSERT(me->me_hw_prov_chain != NULL);
				count++;
			}
			mutex_exit(&mp->kl_lock);
		}
	}

	/*
	 * Allocate a buffer to hold the mechanisms from
	 * mech tabs and mechanisms from the hint list.
	 */
	n = count * CRYPTO_MAX_MECH_NAME;

again:
	count = 0;
	tmp_mech_name_tab = kmem_zalloc(n, kmflag);
	if (tmp_mech_name_tab == NULL) {
		*countp = 0;
		return (NULL);
	}

	/*
	 * Second round, fill in the table
	 */

	mech_name = (char *)tmp_mech_name_tab;
	end = mech_name + n;

	for (cl = KCF_FIRST_OPSCLASS; cl <= KCF_LAST_OPSCLASS; cl++) {
		me_tab_size = kcf_mech_tabs_tab[cl].met_size;
		me_tab = kcf_mech_tabs_tab[cl].met_tab;
		for (i = 0; i < me_tab_size; i++) {
			me = &me_tab[i];
			mp = &me_mutexes[CPU_SEQID];
			mutex_enter(&mp->kl_lock);
			if ((me->me_name[0] != 0) && (me->me_num_hwprov >= 1)) {
				ASSERT(me->me_hw_prov_chain != NULL);
				if ((mech_name + CRYPTO_MAX_MECH_NAME) > end) {
					mutex_exit(&mp->kl_lock);
					kmem_free(tmp_mech_name_tab, n);
					n = n << 1;
					goto again;
				}
				(void) strncpy(mech_name, me->me_name,
				    CRYPTO_MAX_MECH_NAME);

				mech_name += CRYPTO_MAX_MECH_NAME;
				count++;
			}
			mutex_exit(&mp->kl_lock);
		}
	}

	/*
	 * Search tmp_mech_name_tab for each mechanism in the hint list. We
	 * have to add any new mechanisms found in the hint list. Note that we
	 * should not modload the providers here as it will be too early. It
	 * may be the case that the caller never uses a provider.
	 */
	mutex_enter(&soft_config_mutex);
	p = soft_config_list;
	while (p != NULL) {
		for (i = 0; i < p->ce_count; i++) {
			hint_mech = p->ce_mechs[i];

			/* Do not consider the mechanism if it is disabled. */
			if (is_mech_disabled_byname(CRYPTO_SW_PROVIDER,
			    p->ce_name, 0, hint_mech))
				continue;

			/*
			 * There may be duplicate mechanisms in the hint list.
			 * So, we need to search all the entries that have been
			 * added so far. That number would be count.
			 */
			for (j = 0; j < count; j++) {
				if (strcmp(hint_mech,
				    tmp_mech_name_tab[j]) == 0)
					break;
			}

			if (j == count) {	/* This is a new one. Add it. */
				ASSERT((char *)&tmp_mech_name_tab[count] ==
				    mech_name);
				if ((mech_name + CRYPTO_MAX_MECH_NAME) > end) {
					mutex_exit(&soft_config_mutex);
					kmem_free(tmp_mech_name_tab, n);
					n = n << 1;
					goto again;
				}
				(void) strncpy(tmp_mech_name_tab[count],
				    hint_mech, CRYPTO_MAX_MECH_NAME);
				mech_name += CRYPTO_MAX_MECH_NAME;
				count++;
			}
		}
		p = p->ce_next;
	}
	mutex_exit(&soft_config_mutex);

	/*
	 * Check if we have consumed all of the space. We are done if
	 * this is the case.
	 */
	ASSERT(mech_name <= end);
	if (mech_name == end) {
		mech_name_tab = tmp_mech_name_tab;
		goto done;
	}

	/*
	 * Allocate a buffer of the right size now that we have the
	 * correct count.
	 */
	mech_name_tab = kmem_zalloc(count * CRYPTO_MAX_MECH_NAME, kmflag);
	if (mech_name_tab == NULL) {
		kmem_free(tmp_mech_name_tab, n);
		*countp = 0;
		return (NULL);
	}

	bcopy(tmp_mech_name_tab, mech_name_tab, count * CRYPTO_MAX_MECH_NAME);
	kmem_free(tmp_mech_name_tab, n);

done:
	*countp = count;
	return (mech_name_tab);
}

/*
 * crypto_free_mech_list()
 *
 * Arguments:
 *	. mech_names: An array of crypto_mech_name_t previously allocated by
 *	  crypto_get_mech_list.
 *	. count: the number of mech names in mech_names
 *
 * Description:
 *	Frees the the mech_names array.
 *
 * Context:
 *	Process and interruption.
 */
void
crypto_free_mech_list(crypto_mech_name_t *mech_names, uint_t count)
{
	if ((mech_names != NULL) && (count > 0))
		kmem_free(mech_names, count * CRYPTO_MAX_MECH_NAME);
}

/*
 * crypto_notify_events()
 *
 * Arguments:
 *	. nf: Callback function to invoke when event occurs.
 *	. event_mask: Mask of events.
 *
 * Description:
 *	Allocates a new element and inserts it in to the notification
 *	list.
 *
 * Context:
 *	Process context.
 *
 * Returns:
 *	A handle is returned if the client is put on the notification list.
 *	NULL is returned otherwise.
 */
crypto_notify_handle_t
crypto_notify_events(crypto_notify_callback_t nf, uint32_t event_mask)
{
	kcf_ntfy_elem_t *nep;
	crypto_notify_handle_t hndl;

	/* Check the input */
	if (nf == NULL || !(event_mask & (CRYPTO_EVENT_MECHS_CHANGED |
	    CRYPTO_EVENT_PROVIDER_REGISTERED |
	    CRYPTO_EVENT_PROVIDER_UNREGISTERED))) {
		return (NULL);
	}

	nep = kmem_zalloc(sizeof (kcf_ntfy_elem_t), KM_SLEEP);
	mutex_init(&nep->kn_lock, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&nep->kn_cv, NULL, CV_DEFAULT, NULL);
	nep->kn_state = NTFY_WAITING;
	nep->kn_func = nf;
	nep->kn_event_mask = event_mask;

	mutex_enter(&ntfy_list_lock);
	if (ntfy_list_head == NULL) {
		ntfy_list_head = ntfy_list_tail = nep;
	} else {
		ntfy_list_tail->kn_next = nep;
		nep->kn_prev = ntfy_list_tail;
		ntfy_list_tail = nep;
	}

	hndl = (crypto_notify_handle_t)nep;
	mutex_exit(&ntfy_list_lock);

	return (hndl);
}

/*
 * crypto_unnotify_events()
 *
 * Arguments:
 *	. hndl - Handle returned from an earlier crypto_notify_events().
 *
 * Description:
 *	Removes the element specified by hndl from the notification list.
 *	We wait for the notification routine to complete, if the routine
 *	is currently being called. We also free the element.
 *
 * Context:
 *	Process context.
 */
void
crypto_unnotify_events(crypto_notify_handle_t hndl)
{
	kcf_ntfy_elem_t *nep = (kcf_ntfy_elem_t *)hndl;

	if (hndl == NULL)
		return;

retry:
	mutex_enter(&ntfy_list_lock);
	mutex_enter(&nep->kn_lock);

	if (nep->kn_state == NTFY_WAITING) {
		kcf_ntfy_elem_t *nextp = nep->kn_next;
		kcf_ntfy_elem_t *prevp = nep->kn_prev;

		if (nextp != NULL)
			nextp->kn_prev = prevp;
		else
			ntfy_list_tail = prevp;

		if (prevp != NULL)
			prevp->kn_next = nextp;
		else
			ntfy_list_head = nextp;
	} else {
		ASSERT(nep->kn_state == NTFY_RUNNING);

		/*
		 * We have to drop this lock as the client might call
		 * crypto_notify_events() in the callback routine resulting
		 * in a deadlock.
		 */
		mutex_exit(&ntfy_list_lock);

		/*
		 * Another thread is working on this element. We will wait
		 * for that thread to signal us when done. No other thread
		 * will free this element. So, we can be sure it stays valid
		 * after the wait.
		 */
		while (nep->kn_state == NTFY_RUNNING)
			cv_wait(&nep->kn_cv, &nep->kn_lock);
		mutex_exit(&nep->kn_lock);

		/*
		 * We have to remove the element from the notification list.
		 * So, start over and do the work (acquire locks etc.). This is
		 * safe (i.e. We won't be in this routine forever) as the
		 * events do not happen frequently. We have to revisit this
		 * code if we add a new event that happens often.
		 */
		goto retry;
	}

	mutex_exit(&nep->kn_lock);

	/* Free the element */
	mutex_destroy(&nep->kn_lock);
	cv_destroy(&nep->kn_cv);
	kmem_free(nep, sizeof (kcf_ntfy_elem_t));

	mutex_exit(&ntfy_list_lock);
}

/*
 * We walk the notification list and do the callbacks.
 */
void
kcf_walk_ntfylist(uint32_t event, void *event_arg)
{
	kcf_ntfy_elem_t *nep;
	int nelem = 0;

	mutex_enter(&ntfy_list_lock);

	/*
	 * Count how many clients are on the notification list. We need
	 * this count to ensure that clients which joined the list after we
	 * have started this walk, are not wrongly notified.
	 */
	for (nep = ntfy_list_head; nep != NULL; nep = nep->kn_next)
		nelem++;

	for (nep = ntfy_list_head; (nep != NULL && nelem); nep = nep->kn_next) {
		nelem--;

		/*
		 * Check if this client is interested in the
		 * event.
		 */
		if (!(nep->kn_event_mask & event))
			continue;

		mutex_enter(&nep->kn_lock);
		nep->kn_state = NTFY_RUNNING;
		mutex_exit(&nep->kn_lock);
		mutex_exit(&ntfy_list_lock);

		/*
		 * We invoke the callback routine with no locks held. Another
		 * client could have joined the list meanwhile. This is fine
		 * as we maintain nelem as stated above. The NULL check in the
		 * for loop guards against shrinkage. Also, any callers of
		 * crypto_unnotify_events() at this point cv_wait till kn_state
		 * changes to NTFY_WAITING. Hence, nep is assured to be valid.
		 */
		(*nep->kn_func)(event, event_arg);

		mutex_enter(&nep->kn_lock);
		nep->kn_state = NTFY_WAITING;
		cv_broadcast(&nep->kn_cv);
		mutex_exit(&nep->kn_lock);

		mutex_enter(&ntfy_list_lock);
	}

	mutex_exit(&ntfy_list_lock);
}

/*
 * crypto_key_check()
 *
 * Arguments:
 *	. mech: the mechanism to check the key with.
 *	. key: the key to check for validity and weakness.
 *
 * Description:
 *	Checks the validity and strength of the key for the mechanism.
 *	CRYPTO_KEY_REFERENCE is not supported for this routine.
 *	If more than one provider is capable of key checking for the mechanism,
 *	then run the key through them all.
 *	A conservative approach is adopted here: New weak keys may be
 *	discovered with more recent providers. If at least one provider is
 *	not happy with a key, then it is no good.
 *
 * Context:
 *	Process and interruption.
 */
int
crypto_key_check(crypto_mechanism_t *mech, crypto_key_t *key)
{
	int error;
	kcf_mech_entry_t *me;
	kcf_provider_desc_t *pd;
	kcf_prov_mech_desc_t *prov_chain;
	kcf_lock_withpad_t *mp;

	/* when mech is a valid mechanism, me will be its mech_entry */
	if ((mech == NULL) || (key == NULL) ||
	    (key->ck_format == CRYPTO_KEY_REFERENCE))
		return (CRYPTO_ARGUMENTS_BAD);

	if ((error = kcf_get_mech_entry(mech->cm_type, &me)) != KCF_SUCCESS) {
		/* error is one of the KCF_INVALID_MECH_XXX's */
		return (CRYPTO_MECHANISM_INVALID);
	}

	mp = &me_mutexes[CPU_SEQID];
	mutex_enter(&mp->kl_lock);

	/* First let the software provider check this key */
	if (me->me_sw_prov != NULL) {
		pd = me->me_sw_prov->pm_prov_desc;
		KCF_PROV_REFHOLD(pd);

		if ((KCF_PROV_KEY_OPS(pd) != NULL) &&
		    (KCF_PROV_KEY_OPS(pd)->key_check != NULL)) {
			crypto_mechanism_t lmech;

			mutex_exit(&mp->kl_lock);
			lmech = *mech;
			KCF_SET_PROVIDER_MECHNUM(mech->cm_type, pd, &lmech);
			error = KCF_PROV_KEY_CHECK(pd, &lmech, key);

			if (error != CRYPTO_SUCCESS) {
				KCF_PROV_REFRELE(pd);
				return (error);
			}

			mutex_enter(&mp->kl_lock);
		}
		KCF_PROV_REFRELE(pd);
	}

	prov_chain = me->me_hw_prov_chain;
	while (prov_chain != NULL) {
		pd = prov_chain->pm_prov_desc;
		KCF_PROV_REFHOLD(pd);

		if ((KCF_PROV_KEY_OPS(pd) != NULL) &&
		    (KCF_PROV_KEY_OPS(pd)->key_check != NULL)) {
			crypto_mechanism_t lmech;

			mutex_exit(&mp->kl_lock);
			lmech = *mech;
			KCF_SET_PROVIDER_MECHNUM(mech->cm_type, pd,
			    &lmech);
			error = KCF_PROV_KEY_CHECK(pd, &lmech, key);

			if (error != CRYPTO_SUCCESS) {
				KCF_PROV_REFRELE(pd);
				return (error);
			}
			mutex_enter(&mp->kl_lock);
		}
		KCF_PROV_REFRELE(pd);
		prov_chain = prov_chain->pm_next;
	}

	mutex_exit(&mp->kl_lock);

	/* All are happy with this key */
	return (CRYPTO_SUCCESS);
}

int
crypto_key_check_prov(crypto_provider_t provider, crypto_mechanism_t *mech,
    crypto_key_t *key)
{
	kcf_provider_desc_t *pd = provider;
	kcf_provider_desc_t *real_provider = pd;
	crypto_mechanism_t lmech;
	int rv;

	ASSERT(KCF_PROV_REFHELD(pd));

	if ((mech == NULL) || (key == NULL) ||
	    (key->ck_format == CRYPTO_KEY_REFERENCE))
		return (CRYPTO_ARGUMENTS_BAD);

	/* no logical providers currently support the key check */
	if (pd->pd_prov_type == CRYPTO_LOGICAL_PROVIDER) {
		return (CRYPTO_NOT_SUPPORTED);
	}

	lmech = *mech;
	KCF_SET_PROVIDER_MECHNUM(mech->cm_type, real_provider, &lmech);
	rv = KCF_PROV_KEY_CHECK(real_provider, &lmech, key);
	if (pd->pd_prov_type == CRYPTO_LOGICAL_PROVIDER)
		KCF_PROV_REFRELE(real_provider);

	return (rv);
}

/*
 * Initialize the specified crypto_mechanism_info_t structure for
 * the specified mechanism provider descriptor. Used by
 * crypto_get_all_mech_info().
 */
static void
init_mechanism_info(crypto_mechanism_info_t *mech_info,
    kcf_prov_mech_desc_t *pmd)
{
	crypto_func_group_t fg = pmd->pm_mech_info.cm_func_group_mask;

	/* min/max key sizes */
	mech_info->mi_keysize_unit = pmd->pm_mech_info.cm_mech_flags &
	    (CRYPTO_KEYSIZE_UNIT_IN_BITS | CRYPTO_KEYSIZE_UNIT_IN_BYTES);
	mech_info->mi_min_key_size =
	    (size_t)pmd->pm_mech_info.cm_min_key_length;
	mech_info->mi_max_key_size =
	    (size_t)pmd->pm_mech_info.cm_max_key_length;

	/* usage flag */
	mech_info->mi_usage = 0;
	if (fg & (CRYPTO_FG_ENCRYPT | CRYPTO_FG_ENCRYPT_ATOMIC))
		mech_info->mi_usage |= CRYPTO_MECH_USAGE_ENCRYPT;
	if (fg & (CRYPTO_FG_DECRYPT | CRYPTO_FG_DECRYPT_ATOMIC))
		mech_info->mi_usage |= CRYPTO_MECH_USAGE_DECRYPT;
	if (fg & (CRYPTO_FG_MAC | CRYPTO_FG_MAC_ATOMIC))
		mech_info->mi_usage |= CRYPTO_MECH_USAGE_MAC;
}

/*
 * Return the mechanism info for the specified mechanism.
 */
int
crypto_get_all_mech_info(crypto_mech_type_t mech_type,
    crypto_mechanism_info_t **mech_infos, uint_t *num_mech_infos,
    int km_flag)
{
	uint_t ninfos, cur_info;
	kcf_mech_entry_t *me;
	int rv;
	kcf_prov_mech_desc_t *hwp;
	crypto_mechanism_info_t *infos;
	size_t infos_size;
	kcf_lock_withpad_t *mp;

	/* get to the mech entry corresponding to the specified mech type */
	if ((rv = kcf_get_mech_entry(mech_type, &me)) != CRYPTO_SUCCESS) {
		return (rv);
	}

	/* compute the number of key size ranges to return */
	mp = &me_mutexes[CPU_SEQID];
	mutex_enter(&mp->kl_lock);
again:
	ninfos = PROV_COUNT(me);
	mutex_exit(&mp->kl_lock);

	if (ninfos == 0) {
		infos = NULL;
		rv = CRYPTO_SUCCESS;
		goto bail;
	}
	infos_size = ninfos * sizeof (crypto_mechanism_info_t);
	infos = kmem_alloc(infos_size, km_flag);
	if (infos == NULL) {
		rv = CRYPTO_HOST_MEMORY;
		goto bail;
	}

	mutex_enter(&mp->kl_lock);
	if (ninfos != PROV_COUNT(me)) {
		kmem_free(infos, infos_size);
		goto again;
	}

	/* populate array of crypto mechanism infos */
	cur_info = 0;

	/* software provider, if present */
	if (me->me_sw_prov != NULL)
		init_mechanism_info(&infos[cur_info++], me->me_sw_prov);

	/* hardware providers */
	for (hwp = me->me_hw_prov_chain; hwp != NULL; hwp = hwp->pm_next)
		init_mechanism_info(&infos[cur_info++], hwp);

	mutex_exit(&mp->kl_lock);
	ASSERT(cur_info == ninfos);
bail:
	*mech_infos = infos;
	*num_mech_infos = ninfos;
	return (rv);
}

/*
 * Frees the array of mechanism infos previously allocated by
 * crypto_get_all_mech_info().
 */
void
crypto_free_all_mech_info(crypto_mechanism_info_t *mech_infos, uint_t count)
{
	if ((mech_infos != NULL) && (count > 0))
		kmem_free(mech_infos, count * sizeof (crypto_mechanism_info_t));
}

/*
 * memcmp_pad_max() is a specialized version of memcmp() which
 * compares two pieces of data up to a maximum length.  If the
 * the two data match up the maximum length, they are considered
 * matching.  Trailing blanks do not cause the match to fail if
 * one of the data is shorter.
 *
 * Examples of matches:
 *	"one"           |
 *	"one      "     |
 *	                ^maximum length
 *
 *	"Number One     |  X"	(X is beyond maximum length)
 *	"Number One   " |
 *	                ^maximum length
 *
 * Examples of mismatches:
 *	" one"
 *	"one"
 *
 *	"Number One    X|"
 *	"Number One     |"
 *	                ^maximum length
 */
static int
memcmp_pad_max(void *d1, uint_t d1_len, void *d2, uint_t d2_len, uint_t max_sz)
{
	uint_t		len, extra_len;
	char		*marker;

	/* No point in comparing anything beyond max_sz */
	if (d1_len > max_sz)
		d1_len = max_sz;
	if (d2_len > max_sz)
		d2_len = max_sz;

	/* Find shorter of the two data. */
	if (d1_len <= d2_len) {
		len = d1_len;
		extra_len = d2_len;
		marker = d2;
	} else {	/* d1_len > d2_len */
		len = d2_len;
		extra_len = d1_len;
		marker = d1;
	}

	/* Have a match in the shortest length of data? */
	if (memcmp(d1, d2, len) != 0)
		/* CONSTCOND */
		return (!0);

	/* If the rest of longer data is nulls or blanks, call it a match. */
	while (len < extra_len)
		if (!isspace(marker[len++]))
			/* CONSTCOND */
			return (!0);
	return (0);
}

/*
 * Obtain ext info for specified provider and see if it matches.
 */
static boolean_t
match_ext_info(kcf_provider_desc_t *pd, char *label, char *manuf, char *serial,
    crypto_provider_ext_info_t *ext_info)
{
	int rv;

	rv = crypto_get_provinfo(pd, ext_info);
	ASSERT(rv != CRYPTO_NOT_SUPPORTED);
	if (rv != CRYPTO_SUCCESS)
		return (B_FALSE);

	if (memcmp_pad_max(ext_info->ei_label, CRYPTO_EXT_SIZE_LABEL,
	    label, strlen(label), CRYPTO_EXT_SIZE_LABEL))
		return (B_FALSE);

	if (manuf != NULL) {
		if (memcmp_pad_max(ext_info->ei_manufacturerID,
		    CRYPTO_EXT_SIZE_MANUF, manuf, strlen(manuf),
		    CRYPTO_EXT_SIZE_MANUF))
			return (B_FALSE);
	}

	if (serial != NULL) {
		if (memcmp_pad_max(ext_info->ei_serial_number,
		    CRYPTO_EXT_SIZE_SERIAL, serial, strlen(serial),
		    CRYPTO_EXT_SIZE_SERIAL))
			return (B_FALSE);
	}
	return (B_TRUE);
}

/*
 * Find a provider based on its label, manufacturer ID, and serial number.
 */
crypto_provider_t
crypto_get_provider(char *label, char *manuf, char *serial)
{
	kcf_provider_desc_t **provider_array, *pd;
	crypto_provider_ext_info_t *ext_info;
	uint_t count;
	int i;

	/* manuf and serial are optional */
	if (label == NULL)
		return (NULL);

	if (kcf_get_slot_list(&count, &provider_array, B_FALSE)
	    != CRYPTO_SUCCESS)
		return (NULL);

	if (count == 0)
		return (NULL);

	ext_info = kmem_zalloc(sizeof (crypto_provider_ext_info_t), KM_SLEEP);

	for (i = 0; i < count; i++) {
		pd = provider_array[i];
		if (match_ext_info(pd, label, manuf, serial, ext_info)) {
			KCF_PROV_REFHOLD(pd);
			break;
		}
	}
	if (i == count)
		pd = NULL;

	kcf_free_provider_tab(count, provider_array);
	kmem_free(ext_info, sizeof (crypto_provider_ext_info_t));
	return (pd);
}

/*
 * Get the provider information given a provider handle. The caller
 * needs to allocate the space for the argument, info.
 */
int
crypto_get_provinfo(crypto_provider_t hndl, crypto_provider_ext_info_t *info)
{
	int rv;
	kcf_req_params_t params;
	kcf_provider_desc_t *pd;
	kcf_provider_desc_t *real_provider;

	pd = (kcf_provider_desc_t *)hndl;
	rv = kcf_get_hardware_provider_nomech(
	    CRYPTO_OPS_OFFSET(provider_ops), CRYPTO_PROVIDER_OFFSET(ext_info),
	    pd, &real_provider);

	if (rv == CRYPTO_SUCCESS && real_provider != NULL) {
		ASSERT(real_provider == pd ||
		    pd->pd_prov_type == CRYPTO_LOGICAL_PROVIDER);
		KCF_WRAP_PROVMGMT_OPS_PARAMS(&params, KCF_OP_MGMT_EXTINFO,
		    0, NULL, 0, NULL, 0, NULL, info, pd);
		rv = kcf_submit_request(real_provider, NULL, NULL, &params,
		    B_FALSE);
		KCF_PROV_REFRELE(real_provider);
	}

	return (rv);
}

void
crypto_release_provider(crypto_provider_t provider)
{
	KCF_PROV_REFRELE((kcf_provider_desc_t *)provider);
}
