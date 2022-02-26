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
/*
 * Copyright 2010 Nexenta Systems, Inc.  All rights reserved.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <link.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <errno.h>
#include <pthread.h>
#include <sys/mman.h>

#include <sys/crypto/elfsign.h>
#include <cryptoutil.h>

#include <security/cryptoki.h>
#include "pkcs11Global.h"
#include "pkcs11Conf.h"
#include "pkcs11Slot.h"
#include "metaGlobal.h"

/*
 * Fastpath is used when there is only one slot available from a single provider
 * plugged into the framework this is the common case.
 * These globals are used to track the function pointers and policy when
 * the fast-path is activated.
 * This will need to be revisted if per-slot policy is ever
 * implemented.
 */
boolean_t purefastpath = B_FALSE;
boolean_t policyfastpath = B_FALSE;
CK_FUNCTION_LIST_PTR fast_funcs = NULL;
CK_SLOT_ID fast_slot = 0;
boolean_t metaslot_enabled = B_FALSE;
boolean_t metaslot_auto_key_migrate = B_FALSE;
metaslot_config_t metaslot_config;
void (*Tmp_GetThreshold)(void *) = NULL;
cipher_mechs_threshold_t meta_mechs_threshold[MAX_NUM_THRESHOLD];

static const char *conf_err = "See cryptoadm(8). Skipping this plug-in.";

/*
 * Set up metaslot for the framework using either user configuration
 * or system wide configuration options
 *
 * Also sets up the global "slottable" to have the first slot be metaslot.
 */
static CK_RV
setup_metaslot(uentry_t *metaslot_entry) {
	CK_RV rv;
	CK_MECHANISM_TYPE_PTR prov_pol_mechs = NULL;
	pkcs11_slot_t *cur_slot;

	/* process policies for mechanisms */
	if ((metaslot_entry) && (metaslot_entry->count > 0)) {
		rv = pkcs11_mech_parse(metaslot_entry->policylist,
		    &prov_pol_mechs, metaslot_entry->count);

		if (rv == CKR_HOST_MEMORY) {
			cryptoerror(LOG_ERR,
			    "libpkcs11: Could not parse configuration,"
			    "out of memory. Cannot continue parsing "
			    "%s.\n", _PATH_PKCS11_CONF);
			return (rv);
		} else if (rv == CKR_MECHANISM_INVALID) {
			/*
			 * Configuration file is corrupted for metaslot
			 */
			cryptoerror(LOG_ERR,
			    "libpkcs11: Policy invalid or corrupted "
			    "for metaslot. Use cryptoadm(8) to fix "
			    "this. Disabling metaslot functionality.\n");
			metaslot_enabled = B_FALSE;
			return (rv);
		}
	}

	/*
	 * Check for metaslot policy.  If all mechanisms are
	 * disabled, disable metaslot since there is nothing
	 * interesting for it to do
	 */
	if ((metaslot_entry) && (metaslot_entry->flag_enabledlist) &&
	    (prov_pol_mechs == NULL)) {
		metaslot_enabled = B_FALSE;
		return (rv);
	}

	/*
	 * save system wide value for metaslot's keystore.
	 * If either slot description or token label is specified by
	 * the user, the system wide value for both is ignored.
	 */
	if ((metaslot_entry) &&
	    (!metaslot_config.keystore_token_specified) &&
	    (!metaslot_config.keystore_slot_specified)) {
		/*
		 * blank_str is used for comparing with token label,
		 * and slot description, make sure it is better than
		 * the larger of both
		 */
		char blank_str[TOKEN_LABEL_SIZE + SLOT_DESCRIPTION_SIZE];

		bzero(blank_str, sizeof (blank_str));

		if (memcmp(metaslot_entry->metaslot_ks_token,
		    blank_str, TOKEN_LABEL_SIZE) != 0) {
			metaslot_config.keystore_token_specified = B_TRUE;
			(void) strlcpy(
			    (char *)metaslot_config.keystore_token,
			    (const char *)metaslot_entry->metaslot_ks_token,
			    TOKEN_LABEL_SIZE);
		}

		if (memcmp(metaslot_entry->metaslot_ks_slot,
		    blank_str, SLOT_DESCRIPTION_SIZE) != 0) {
			metaslot_config.keystore_slot_specified = B_TRUE;
			(void) strlcpy(
			    (char *)metaslot_config.keystore_slot,
			    (const char *)metaslot_entry->metaslot_ks_slot,
			    SLOT_DESCRIPTION_SIZE);
		}
	}

	/* check system-wide value for auto_key_migrate */
	if (metaslot_config.auto_key_migrate_specified) {
		/* take user's specified value */
		metaslot_auto_key_migrate = metaslot_config.auto_key_migrate;
	} else {
		if (metaslot_entry) {
			/* use system-wide default */
			metaslot_auto_key_migrate =
			    metaslot_entry->flag_metaslot_auto_key_migrate;
		} else {
			/*
			 * there's no system wide metaslot entry,
			 * default auto_key_migrate to true
			 */
			metaslot_auto_key_migrate = B_TRUE;
		}
	}


	/* Make first slotID be 0, for metaslot. */
	slottable->st_first = 0;

	/* Set up the slottable entry for metaslot */
	slottable->st_slots[0] = NULL;
	cur_slot = calloc(1, sizeof (pkcs11_slot_t));
	if (cur_slot == NULL) {
		rv = CKR_HOST_MEMORY;
		return (rv);
	}
	cur_slot->sl_wfse_state = WFSE_CLEAR;
	cur_slot->sl_enabledpol = B_FALSE;
	cur_slot->sl_no_wfse = B_FALSE;
	(void) pthread_mutex_init(&cur_slot->sl_mutex, NULL);

	/*
	 * The metaslot entry was prealloc'd by
	 * pkcs11_slottable_increase()
	 */
	(void) pthread_mutex_lock(&slottable->st_mutex);
	slottable->st_slots[0] = cur_slot;
	(void) pthread_mutex_unlock(&slottable->st_mutex);

	(void) pthread_mutex_lock(&cur_slot->sl_mutex);
	cur_slot->sl_id = METASLOT_SLOTID;
	cur_slot->sl_func_list = &metaslot_functionList;
	if (metaslot_entry) {
		cur_slot->sl_enabledpol = metaslot_entry->flag_enabledlist;
		cur_slot->sl_pol_count = metaslot_entry->count;
	} else {
		/* if no metaslot entry, assume all mechs are enabled */
		cur_slot->sl_enabledpol = B_FALSE;
		cur_slot->sl_pol_count = 0;
	}
	cur_slot->sl_pol_mechs = prov_pol_mechs;
	cur_slot->sl_dldesc = NULL; /* not applicable */
	cur_slot->sl_prov_id = 0;
	(void) pthread_mutex_unlock(&cur_slot->sl_mutex);

	/* Call the meta_Initialize() to initialize metaslot */
	rv = meta_Initialize(NULL);
	if (rv != CKR_OK) {
		cryptoerror(LOG_ERR,
		    "libpkcs11: Can't initialize metaslot (%s)",
		    pkcs11_strerror(rv));
		goto cleanup;
	}

	return (CKR_OK);

cleanup:
	metaslot_enabled = B_FALSE;
	slottable->st_slots[0] = NULL;

	if (cur_slot) {
		(void) pthread_mutex_destroy(&cur_slot->sl_mutex);
		free(cur_slot);
	}
	return (rv);
}

/*
 * For each provider found in pkcs11.conf: expand $ISA if necessary,
 * verify the module is signed, load the provider, find all of its
 * slots, and store the function list and disabled policy.
 *
 * This function requires that the uentrylist_t and pkcs11_slottable_t
 * already have memory allocated, and that the uentrylist_t is already
 * populated with provider and policy information.
 *
 * pInitArgs can be set to NULL, but is normally the same value
 * the framework's C_Initialize() was called with.
 *
 * Unless metaslot is explicitly disabled, it is setup when all other
 * providers are loaded.
 */
CK_RV
pkcs11_slot_mapping(uentrylist_t *pplist, CK_VOID_PTR pInitArgs)
{
	CK_RV rv = CKR_OK;
	CK_RV prov_rv;			/* Provider's return code */
	CK_INFO prov_info;
	CK_RV (*Tmp_C_GetFunctionList)(CK_FUNCTION_LIST_PTR_PTR);
	CK_FUNCTION_LIST_PTR prov_funcs = NULL; /* Provider's function list */
	CK_ULONG prov_slot_count; 		/* Number of slots */
	CK_SLOT_ID slot_id; 		/* slotID assigned for framework */
	CK_SLOT_ID_PTR prov_slots = NULL; 	/* Provider's slot list */
					/* Enabled or Disabled policy */
	CK_MECHANISM_TYPE_PTR prov_pol_mechs = NULL;

	void *dldesc = NULL;
	char *isa, *fullpath = NULL, *dl_error;
	uentrylist_t *phead;
	uint_t prov_count = 0;
	pkcs11_slot_t *cur_slot;
	CK_ULONG i;
	size_t len;
	uentry_t *metaslot_entry = NULL;
	/* number of slots in the framework, not including metaslot */
	uint_t slot_count = 0;

	phead = pplist;

	/* Loop through all of the provider listed in pkcs11.conf */
	while (phead != NULL) {
		if (!strcasecmp(phead->puent->name, "metaslot")) {
			/*
			 * Skip standard processing for metaslot
			 * entry since it is not an actual library
			 * that can be dlopened.
			 * It will be initialized later.
			 */
			if (metaslot_entry != NULL) {
				cryptoerror(LOG_ERR,
				    "libpkcs11: multiple entries for metaslot "
				    "detected.  All but the first entry will "
				    "be ignored");
			} else {
				metaslot_entry = phead->puent;
			}
			goto contparse;
		}

		if (!strcasecmp(phead->puent->name, FIPS_KEYWORD)) {
			/*
			 * Skip standard processing for fips-140
			 * entry since it is not an actual library
			 * that can be dlopened.
			 */
			goto contparse;
		}

		/* Check for Instruction Set Architecture indicator */
		if ((isa = strstr(phead->puent->name, PKCS11_ISA)) != NULL) {
			/* Substitute the architecture dependent path */
			len = strlen(phead->puent->name) -
			    strlen(PKCS11_ISA) +
			    strlen(PKCS11_ISA_DIR) + 1;
			if ((fullpath = (char *)malloc(len)) == NULL) {
				cryptoerror(LOG_ERR,
				    "libpksc11: parsing %s, out of memory. "
				    "Cannot continue parsing.",
				    _PATH_PKCS11_CONF);
				rv = CKR_HOST_MEMORY;
				goto conferror;
			}
			*isa = '\000';
			isa += strlen(PKCS11_ISA);
			(void) snprintf(fullpath, len, "%s%s%s",
			    phead->puent->name, PKCS11_ISA_DIR, isa);
		} else if ((fullpath = strdup(phead->puent->name)) == 0) {
			cryptoerror(LOG_ERR,
			    "libpkcs11: parsing %s, out of memory. "
			    "Cannot continue parsing.",
			    _PATH_PKCS11_CONF);
			rv = CKR_HOST_MEMORY;
			goto conferror;
		}

		/*
		 * Open the provider. We assume all of our plugins have
		 * their symbols properly defined, so the use of RTLD_NOW
		 * to flush out errors immediately is not necessary.
		 *
		 * Note that for proper operation, all plugins must be
		 * built with direct bindings enabled.
		 */
		dldesc = dlopen(fullpath, RTLD_LAZY);

		/*
		 * If we failed to load it, we will just skip this
		 * provider and move on to the next one.
		 */
		if (dldesc == NULL) {
			dl_error = dlerror();
			cryptoerror(LOG_ERR,
			    "libpkcs11: Cannot load PKCS#11 library %s.  "
			    "dlerror: %s. %s",
			    fullpath, dl_error != NULL ? dl_error : "Unknown",
			    conf_err);
			goto contparse;
		}

		/* Get the pointer to provider's C_GetFunctionList() */
		Tmp_C_GetFunctionList =
		    (CK_RV(*)())dlsym(dldesc, "C_GetFunctionList");

		/*
		 * If we failed to get the pointer to C_GetFunctionList(),
		 * skip this provider and continue to the next one.
		 */
		if (Tmp_C_GetFunctionList == NULL) {
			cryptoerror(LOG_ERR,
			    "libpkcs11: Could not dlsym() C_GetFunctionList() "
			    "for %s. May not be a PKCS#11 library. %s",
			    fullpath, conf_err);
			(void) dlclose(dldesc);
			goto contparse;
		}


		/* Get the provider's function list */
		prov_rv = Tmp_C_GetFunctionList(&prov_funcs);

		/*
		 * If we failed to get the provider's function list,
		 * skip this provider and continue to the next one.
		 */
		if (prov_rv != CKR_OK) {
			cryptoerror(LOG_ERR,
			    "libpkcs11: Could not get function list for %s. "
			    "%s Error: %s.",
			    fullpath, conf_err, pkcs11_strerror(prov_rv));
			(void) dlclose(dldesc);
			goto contparse;
		}

		/* Initialize this provider */
		prov_rv = prov_funcs->C_Initialize(pInitArgs);

		/*
		 * If we failed to initialize this provider,
		 * skip this provider and continue to the next one.
		 */
		if ((prov_rv != CKR_OK) &&
		    (prov_rv != CKR_CRYPTOKI_ALREADY_INITIALIZED)) {
			cryptoerror(LOG_ERR,
			    "libpkcs11: Could not initialize %s. "
			    "%s Error: %s.",
			    fullpath, conf_err, pkcs11_strerror(prov_rv));
			(void) dlclose(dldesc);
			goto contparse;
		}

		/*
		 * Make sure this provider is implementing the same
		 * major version, and at least the same minor version
		 * that we are.
		 */
		prov_rv = prov_funcs->C_GetInfo(&prov_info);

		/*
		 * If we can't verify that we are implementing the
		 * same major version, or if it is definitely not the same
		 * version, we need to skip this provider.
		 */
		if ((prov_rv != CKR_OK) ||
		    (prov_info.cryptokiVersion.major !=
		    CRYPTOKI_VERSION_MAJOR))  {
			if (prov_rv != CKR_OK) {
				cryptoerror(LOG_ERR,
				    "libpkcs11: Could not verify version of "
				    "%s. %s Error: %s.", fullpath,
				    conf_err, pkcs11_strerror(prov_rv));
			} else {
				cryptoerror(LOG_ERR,
				    "libpkcs11: Only CRYPTOKI major version "
				    "%d is supported.  %s is major "
				    "version %d. %s",
				    CRYPTOKI_VERSION_MAJOR, fullpath,
				    prov_info.cryptokiVersion.major, conf_err);
			}
			(void) prov_funcs->C_Finalize(NULL);
			(void) dlclose(dldesc);
			goto contparse;
		}

		/*
		 * Warn the administrator (at debug) that a provider with
		 * a significantly older or newer version of
		 * CRYPTOKI is being used.  It should not cause
		 * problems, but logging a warning makes it easier
		 * to debug later.
		 */
		if ((prov_info.cryptokiVersion.minor <
		    CRYPTOKI_VERSION_WARN_MINOR) ||
		    (prov_info.cryptokiVersion.minor >
		    CRYPTOKI_VERSION_MINOR)) {
			cryptoerror(LOG_DEBUG,
			    "libpkcs11: %s CRYPTOKI minor version, %d, may "
			    "not be compatible with minor version %d.",
			    fullpath, prov_info.cryptokiVersion.minor,
			    CRYPTOKI_VERSION_MINOR);
		}

		/*
		 * Find out how many slots this provider has,
		 * call with tokenPresent set to FALSE so all
		 * potential slots are returned.
		 */
		prov_rv = prov_funcs->C_GetSlotList(FALSE,
		    NULL, &prov_slot_count);

		/*
		 * If the call failed, or if no slots are returned,
		 * then skip this provider and continue to next one.
		 */
		if (prov_rv != CKR_OK) {
			cryptoerror(LOG_ERR,
			    "libpksc11: Could not get slot list from %s. "
			    "%s Error: %s.",
			    fullpath, conf_err, pkcs11_strerror(prov_rv));
			(void) prov_funcs->C_Finalize(NULL);
			(void) dlclose(dldesc);
			goto contparse;
		}

		if (prov_slot_count == 0) {
			cryptodebug("libpkcs11: No slots presented from %s. "
			    "Skipping this plug-in at this time.\n",
			    fullpath);
			(void) prov_funcs->C_Finalize(NULL);
			(void) dlclose(dldesc);
			goto contparse;
		}

		/* Allocate memory for the slot list */
		prov_slots = calloc(prov_slot_count, sizeof (CK_SLOT_ID));

		if (prov_slots == NULL) {
			cryptoerror(LOG_ERR,
			    "libpkcs11: Could not allocate memory for "
			    "plug-in slots. Cannot continue parsing %s\n",
			    _PATH_PKCS11_CONF);
			rv = CKR_HOST_MEMORY;
			goto conferror;
		}

		/* Get slot list from provider */
		prov_rv = prov_funcs->C_GetSlotList(FALSE,
		    prov_slots, &prov_slot_count);

		/* if second call fails, drop this provider */
		if (prov_rv != CKR_OK) {
			cryptoerror(LOG_ERR,
			    "libpkcs11: Second call to C_GetSlotList() for %s "
			    "failed. %s Error: %s.",
			    fullpath, conf_err, pkcs11_strerror(prov_rv));
			(void) prov_funcs->C_Finalize(NULL);
			(void) dlclose(dldesc);
			goto contparse;
		}

		/*
		 * Parse the list of disabled or enabled mechanisms, will
		 * apply to each of the provider's slots.
		 */
		if (phead->puent->count > 0) {
			rv = pkcs11_mech_parse(phead->puent->policylist,
			    &prov_pol_mechs, phead->puent->count);

			if (rv == CKR_HOST_MEMORY) {
				cryptoerror(LOG_ERR,
				    "libpkcs11: Could not parse configuration,"
				    "out of memory. Cannot continue parsing "
				    "%s.", _PATH_PKCS11_CONF);
				goto conferror;
			} else if (rv == CKR_MECHANISM_INVALID) {
				/*
				 * Configuration file is corrupted for this
				 * provider.
				 */
				cryptoerror(LOG_ERR,
				    "libpkcs11: Policy invalid or corrupted "
				    "for %s. Use cryptoadm(8) to fix "
				    "this. Skipping this plug-in.",
				    fullpath);
				(void) prov_funcs->C_Finalize(NULL);
				(void) dlclose(dldesc);
				goto contparse;
			}
		}

		/* Allocate memory in our slottable for these slots */
		rv = pkcs11_slottable_increase(prov_slot_count);

		/*
		 * If any error is returned, it will be memory related,
		 * so we need to abort the attempt at filling the
		 * slottable.
		 */
		if (rv != CKR_OK) {
			cryptoerror(LOG_ERR,
			    "libpkcs11: slottable could not increase. "
			    "Cannot continue parsing %s.",
			    _PATH_PKCS11_CONF);
			goto conferror;
		}

		/* Configure information for each new slot */
		for (i = 0; i < prov_slot_count; i++) {
			/* allocate slot in framework */
			rv = pkcs11_slot_allocate(&slot_id);
			if (rv != CKR_OK) {
				cryptoerror(LOG_ERR,
				    "libpkcs11: Could not allocate "
				    "new slot.  Cannot continue parsing %s.",
				    _PATH_PKCS11_CONF);
				goto conferror;
			}
			slot_count++;
			cur_slot = slottable->st_slots[slot_id];
			(void) pthread_mutex_lock(&cur_slot->sl_mutex);
			cur_slot->sl_id = prov_slots[i];
			cur_slot->sl_func_list = prov_funcs;
			cur_slot->sl_enabledpol =
			    phead->puent->flag_enabledlist;
			cur_slot->sl_pol_mechs = prov_pol_mechs;
			cur_slot->sl_pol_count = phead->puent->count;
			cur_slot->sl_norandom = phead->puent->flag_norandom;
			cur_slot->sl_dldesc = dldesc;
			cur_slot->sl_prov_id = prov_count + 1;
			(void) pthread_mutex_unlock(&cur_slot->sl_mutex);
		}

		/*
		 * Get the pointer to private interface _SUNW_GetThreshold()
		 * in pkcs11_kernel.
		 */

		if (Tmp_GetThreshold == NULL) {
			Tmp_GetThreshold =
			    (void(*)())dlsym(dldesc, "_SUNW_GetThreshold");

			/* Get the threshold values for the supported mechs */
			if (Tmp_GetThreshold != NULL) {
				(void) memset(meta_mechs_threshold, 0,
				    sizeof (meta_mechs_threshold));
				Tmp_GetThreshold(meta_mechs_threshold);
			}
		}

		/* Set and reset values to process next provider */
		prov_count++;
contparse:
		prov_slot_count = 0;
		Tmp_C_GetFunctionList = NULL;
		prov_funcs = NULL;
		dldesc = NULL;
		if (fullpath != NULL) {
			free(fullpath);
			fullpath = NULL;
		}
		if (prov_slots != NULL) {
			free(prov_slots);
			prov_slots = NULL;
		}
		phead = phead->next;
	}

	if (slot_count == 0) {
		/*
		 * there's no other slot in the framework,
		 * there is nothing to do
		 */
		goto config_complete;
	}

	/* determine if metaslot should be enabled */

	/*
	 * Check to see if any environment variable is defined
	 * by the user for configuring metaslot.  Users'
	 * setting always take precedence over the system wide
	 * setting.  So, we will first check for any user's
	 * defined env variables before looking at the system-wide
	 * configuration.
	 */
	get_user_metaslot_config();

	/* no metaslot entry in /etc/crypto/pkcs11.conf */
	if (!metaslot_entry) {
		/*
		 * If user env variable indicates metaslot should be enabled,
		 * but there's no entry in /etc/crypto/pkcs11.conf for
		 * metaslot at all, will respect the user's defined value
		 */
		if ((metaslot_config.enabled_specified) &&
		    (metaslot_config.enabled)) {
			metaslot_enabled = B_TRUE;
		}
	} else {
		if (!metaslot_config.enabled_specified) {
			/*
			 * take system wide value if
			 * it is not specified by user
			 */
			metaslot_enabled
			    = metaslot_entry->flag_metaslot_enabled;
		} else {
			metaslot_enabled = metaslot_config.enabled;
		}
	}

	/*
	 *
	 * As long as the user or system configuration file does not
	 * disable metaslot, it will be enabled regardless of the
	 * number of slots plugged into the framework.  Therefore,
	 * metaslot is enabled even when there's only one slot
	 * plugged into the framework.  This is necessary for
	 * presenting a consistent token label view to applications.
	 *
	 * However, for the case where there is only 1 slot plugged into
	 * the framework, we can use "fastpath".
	 *
	 * "fastpath" will pass all of the application's requests
	 * directly to the underlying provider.  Only when policy is in
	 * effect will we need to keep slotID around.
	 *
	 * When metaslot is enabled, and fastpath is enabled,
	 * all the metaslot processing will be skipped.
	 * When there is only 1 slot, there's
	 * really not much metaslot can do in terms of combining functionality
	 * of different slots, and object migration.
	 *
	 */

	/* check to see if fastpath can be used */
	if (slottable->st_last == slottable->st_first) {

		cur_slot = slottable->st_slots[slottable->st_first];

		(void) pthread_mutex_lock(&cur_slot->sl_mutex);

		if ((cur_slot->sl_pol_count == 0) &&
		    (!cur_slot->sl_enabledpol) && (!cur_slot->sl_norandom)) {
			/* No policy is in effect, don't need slotid */
			fast_funcs = cur_slot->sl_func_list;
			purefastpath = B_TRUE;
		} else {
			fast_funcs = cur_slot->sl_func_list;
			fast_slot = slottable->st_first;
			policyfastpath = B_TRUE;
		}

		(void) pthread_mutex_unlock(&cur_slot->sl_mutex);
	}

	if ((purefastpath || policyfastpath) && (!metaslot_enabled)) {
		goto config_complete;
	}

	/*
	 * If we get here, there are more than 2 slots in the framework,
	 * we need to set up metaslot if it is enabled
	 */
	if (metaslot_enabled) {
		rv = setup_metaslot(metaslot_entry);
		if (rv != CKR_OK) {
			goto conferror;
		}
	}


config_complete:

	return (CKR_OK);

conferror:
	/*
	 * This cleanup code is only exercised when a major,
	 * unrecoverable error like "out of memory".
	 */
	if (prov_funcs != NULL) {
		(void) prov_funcs->C_Finalize(NULL);
	}
	if (dldesc != NULL) {
		(void) dlclose(dldesc);
	}
	if (fullpath != NULL) {
		free(fullpath);
		fullpath = NULL;
	}
	if (prov_slots != NULL) {
		free(prov_slots);
		prov_slots = NULL;
	}

	return (rv);
}

/*
 * pkcs11_mech_parse will take hex mechanism ids, as a list of
 * strings, and convert them to CK_MECHANISM_TYPE_PTR.
 */
CK_RV
pkcs11_mech_parse(umechlist_t *str_list, CK_MECHANISM_TYPE_PTR *mech_list,
    int mech_count)
{
	CK_MECHANISM_TYPE_PTR tmp_list;
	umechlist_t *shead = str_list;

	tmp_list = malloc(mech_count * sizeof (CK_MECHANISM_TYPE));

	if (tmp_list == NULL) {
		cryptoerror(LOG_ERR, "libpkcs11: parsing %s, out of memory. "
		    "Cannot continue.",
		    _PATH_PKCS11_CONF);
		return (CKR_HOST_MEMORY);
	}

	*mech_list = tmp_list;

	/*
	 * The following will loop mech_count times, as there are
	 * exactly mech_count items in the str_list.
	 */
	while (shead != NULL) {
		CK_MECHANISM_TYPE cur_mech;

		errno = 0;

		/*
		 * "name" is a hexadecimal number, preceded by 0x.
		 */
		cur_mech = strtoul(shead->name, NULL, 16);

		if ((cur_mech == 0) &&
		    ((errno == EINVAL) || (errno == ERANGE))) {
			free(mech_list);
			return (CKR_MECHANISM_INVALID);
		}
		*tmp_list = (CK_MECHANISM_TYPE)cur_mech;
		tmp_list++;
		shead = shead->next;
	}

	return (CKR_OK);
}

/*
 * pkcs11_is_dismech is provided a slotid and a mechanism.
 * If mech is not disabled, then return B_FALSE.
 */
boolean_t
pkcs11_is_dismech(CK_SLOT_ID slotid, CK_MECHANISM_TYPE mech)
{
	ulong_t i;
	boolean_t enabled_pol;
	CK_MECHANISM_TYPE_PTR pol_mechs;
	ulong_t pol_count;

	/* Find the associated slot and get the mech policy info */
	(void) pthread_mutex_lock(&slottable->st_slots[slotid]->sl_mutex);
	enabled_pol = slottable->st_slots[slotid]->sl_enabledpol;
	pol_mechs = slottable->st_slots[slotid]->sl_pol_mechs;
	pol_count = slottable->st_slots[slotid]->sl_pol_count;
	(void) pthread_mutex_unlock(&slottable->st_slots[slotid]->sl_mutex);

	/* Check for policy */
	if ((!enabled_pol) && (pol_mechs == NULL)) {
		/* no policy */
		return (B_FALSE);
	} else if (pol_mechs == NULL) {
		/*
		 * We have an empty enabled list, which means no
		 * mechanisms are exempted from this policy: all
		 * are disabled.
		 */
		return (B_TRUE);
	}

	for (i = 0; i < pol_count; i++) {
		/*
		 * If it matches, return status based on this
		 * being and enabled or a disabled list of mechs.
		 */
		if (pol_mechs[i] == mech) {
			return (enabled_pol ? B_FALSE : B_TRUE);
		}
	}

	/* mech was not found in list */
	return (enabled_pol ? B_TRUE : B_FALSE);
}
