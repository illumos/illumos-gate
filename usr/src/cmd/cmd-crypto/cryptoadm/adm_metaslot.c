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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Administration for metaslot
 *
 * All the "list" operations will call functions in libpkcs11.so
 * Normally, it doesn't make sense to call functions in libpkcs11.so directly
 * because libpkcs11.so depends on the configuration file (pkcs11.conf) the
 * cryptoadm command is trying to administer.  However, since metaslot
 * is part of the framework, it is not possible to get information about
 * it without actually calling functions in libpkcs11.so.
 *
 * So, for the listing operation, which won't modify the value of pkcs11.conf
 * it is safe to call libpkcs11.so.
 *
 * For other operations that modifies the pkcs11.conf file, libpkcs11.so
 * will not be called.
 *
 */

#include <cryptoutil.h>
#include <stdio.h>
#include <libintl.h>
#include <dlfcn.h>
#include <link.h>
#include <strings.h>
#include <security/cryptoki.h>
#include <cryptoutil.h>
#include "cryptoadm.h"

#define	METASLOT_ID	0

int
list_metaslot_info(boolean_t show_mechs, boolean_t verbose,
    mechlist_t *mechlist)
{
	int rc = SUCCESS;
	CK_RV rv;
	CK_SLOT_INFO slot_info;
	CK_TOKEN_INFO token_info;
	CK_MECHANISM_TYPE_PTR pmech_list = NULL;
	CK_ULONG mech_count;
	int i;
	CK_RV (*Tmp_C_GetFunctionList)(CK_FUNCTION_LIST_PTR_PTR);
	CK_FUNCTION_LIST_PTR	funcs;
	void *dldesc = NULL;
	boolean_t lib_initialized = B_FALSE;
	uentry_t *puent;
	char buf[128];


	/*
	 * Display the system-wide metaslot settings as specified
	 * in pkcs11.conf file.
	 */
	if ((puent = getent_uef(METASLOT_KEYWORD)) == NULL) {
		cryptoerror(LOG_STDERR,
		    gettext("metaslot entry doesn't exist."));
		return (FAILURE);
	}

	(void) printf(gettext("System-wide Meta Slot Configuration:\n"));
	/*
	 * TRANSLATION_NOTE:
	 * Strictly for appearance's sake, this line should be as long as
	 * the length of the translated text above.
	 */
	(void) printf(gettext("------------------------------------\n"));
	(void) printf(gettext("Status: %s\n"), puent->flag_metaslot_enabled ?
	    gettext("enabled") : gettext("disabled"));
	(void) printf(gettext("Sensitive Token Object Automatic Migrate: %s\n"),
	    puent->flag_metaslot_auto_key_migrate ? gettext("enabled") :
	    gettext("disabled"));

	bzero(buf, sizeof (buf));
	if (memcmp(puent->metaslot_ks_slot, buf, SLOT_DESCRIPTION_SIZE) != 0) {
		(void) printf(gettext("Persistent object store slot: %s\n"),
		    puent->metaslot_ks_slot);
	}

	if (memcmp(puent->metaslot_ks_token, buf, TOKEN_LABEL_SIZE) != 0) {
		(void) printf(gettext("Persistent object store token: %s\n"),
		    puent->metaslot_ks_token);
	}

	if ((!verbose) && (!show_mechs)) {
		return (SUCCESS);
	}

	if (verbose) {
		(void) printf(gettext("\nDetailed Meta Slot Information:\n"));
		/*
		 * TRANSLATION_NOTE:
		 * Strictly for appearance's sake, this line should be as
		 * long as the length of the translated text above.
		 */
		(void) printf(gettext("-------------------------------\n"));
	}

	/*
	 * Need to actually make calls to libpkcs11.so to get
	 * information about metaslot.
	 */

	dldesc = dlopen(UEF_FRAME_LIB, RTLD_NOW);
	if (dldesc == NULL) {
		char *dl_error;
		dl_error = dlerror();
		cryptodebug("Cannot load PKCS#11 framework library. "
		    "dlerror:%s", dl_error);
		return (FAILURE);
	}

	/* Get the pointer to library's C_GetFunctionList() */
	Tmp_C_GetFunctionList = (CK_RV(*)())dlsym(dldesc, "C_GetFunctionList");
	if (Tmp_C_GetFunctionList == NULL) {
		cryptodebug("Cannot get the address of the C_GetFunctionList "
		    "from framework");
		rc = FAILURE;
		goto finish;
	}


	/* Get the provider's function list */
	rv = Tmp_C_GetFunctionList(&funcs);
	if (rv != CKR_OK) {
		cryptodebug("failed to call C_GetFunctionList in "
		    "framework library");
		rc = FAILURE;
		goto finish;
	}

	/* Initialize this provider */
	rv = funcs->C_Initialize(NULL_PTR);
	if (rv != CKR_OK) {
		cryptodebug("C_Initialize failed with error code 0x%x\n", rv);
		rc = FAILURE;
		goto finish;
	} else {
		lib_initialized = B_TRUE;
	}

	/*
	 * We know for sure that metaslot is slot 0 in the framework,
	 * so, we will do a C_GetSlotInfo() trying to see if it works.
	 * If it fails with CKR_SLOT_ID_INVALID, we know that metaslot
	 * is not really enabled.
	 */
	rv = funcs->C_GetSlotInfo(METASLOT_ID, &slot_info);
	if (rv == CKR_SLOT_ID_INVALID) {
		(void) printf(gettext("actual status: disabled.\n"));
		/*
		 * Even if the -m and -v flag is supplied, there's nothing
		 * interesting to display about metaslot since it is disabled,
		 * so, just stop right here.
		 */
		goto finish;
	}

	if (rv != CKR_OK) {
		cryptodebug("C_GetSlotInfo failed with error "
		    "code 0x%x\n", rv);
		rc = FAILURE;
		goto finish;
	}

	if (!verbose) {
		goto display_mechs;
	}

	(void) printf(gettext("actual status: enabled.\n"));

	(void) printf(gettext("Description: %.64s\n"),
	    slot_info.slotDescription);

	(void) printf(gettext("Token Present: %s\n"),
	    (slot_info.flags & CKF_TOKEN_PRESENT ?
	    gettext("True") : gettext("False")));

	rv = funcs->C_GetTokenInfo(METASLOT_ID, &token_info);
	if (rv != CKR_OK) {
		cryptodebug("C_GetTokenInfo failed with error "
		    "code 0x%x\n", rv);
		rc = FAILURE;
		goto finish;
	}

	(void) printf(gettext("Token Label: %.32s\n"
	    "Manufacturer ID: %.32s\n"
	    "Model: %.16s\n"
	    "Serial Number: %.16s\n"
	    "Hardware Version: %d.%d\n"
	    "Firmware Version: %d.%d\n"
	    "UTC Time: %.16s\n"
	    "PIN Length: %d-%d\n"),
	    token_info.label,
	    token_info.manufacturerID,
	    token_info.model,
	    token_info.serialNumber,
	    token_info.hardwareVersion.major,
	    token_info.hardwareVersion.minor,
	    token_info.firmwareVersion.major,
	    token_info.firmwareVersion.minor,
	    token_info.utcTime,
	    token_info.ulMinPinLen,
	    token_info.ulMaxPinLen);

	display_token_flags(token_info.flags);

	if (!show_mechs) {
		goto finish;
	}

display_mechs:

	if (mechlist == NULL) {
		rv = funcs->C_GetMechanismList(METASLOT_ID, NULL_PTR,
		    &mech_count);
		if (rv != CKR_OK) {
			cryptodebug("C_GetMechanismList failed with error "
			    "code 0x%x\n", rv);
			rc = FAILURE;
			goto finish;
		}

		if (mech_count > 0) {
			pmech_list = malloc(mech_count *
			    sizeof (CK_MECHANISM_TYPE));
			if (pmech_list == NULL) {
				cryptodebug("out of memory");
				rc = FAILURE;
				goto finish;
			}
			rv = funcs->C_GetMechanismList(METASLOT_ID, pmech_list,
			    &mech_count);
			if (rv != CKR_OK) {
				cryptodebug("C_GetMechanismList failed with "
				    "error code 0x%x\n", rv);
				rc = FAILURE;
				goto finish;
			}
		}
	} else {
		rc = convert_mechlist(&pmech_list, &mech_count, mechlist);
		if (rc != SUCCESS) {
			goto finish;
		}
	}

	(void) printf(gettext("Mechanisms:\n"));
	if (mech_count == 0) {
		/* should never be this case */
		(void) printf(gettext("No mechanisms\n"));
		goto finish;
	}
	if (verbose) {
		display_verbose_mech_header();
	}

	for (i = 0; i < mech_count; i++) {
		CK_MECHANISM_TYPE	mech = pmech_list[i];

		if (mech > CKM_VENDOR_DEFINED) {
			(void) printf("%#lx", mech);
		} else {
			(void) printf("%-29s", pkcs11_mech2str(mech));
		}

		if (verbose) {
			CK_MECHANISM_INFO mech_info;
			rv = funcs->C_GetMechanismInfo(METASLOT_ID,
			    mech, &mech_info);
			if (rv != CKR_OK) {
				cryptodebug("C_GetMechanismInfo failed with "
				    "error code 0x%x\n", rv);
				rc = FAILURE;
				goto finish;
			}
			display_mech_info(&mech_info);
		}
		(void) printf("\n");
	}

finish:

	if ((rc == FAILURE) && (show_mechs)) {
		(void) printf(gettext(
		    "metaslot: failed to retrieve the mechanism list.\n"));
	}

	if (lib_initialized) {
		(void) funcs->C_Finalize(NULL_PTR);
	}

	if (dldesc != NULL) {
		(void) dlclose(dldesc);
	}

	if (pmech_list != NULL) {
		(void) free(pmech_list);
	}

	return (rc);
}

int
list_metaslot_policy()
{

	uentry_t *puent;
	int rc;

	if ((puent = getent_uef(METASLOT_KEYWORD)) == NULL) {
		cryptoerror(LOG_STDERR,
		    gettext("metaslot entry doesn't exist."));
		return (FAILURE);
	}

	rc = display_policy(puent);
	(void) printf("\n");
	free_uentry(puent);
	return (rc);
}

/*
 * disable metaslot and some of its configuration options
 *
 * If mechlist==NULL, and the other 2 flags are false, just disabled
 * the metaslot feature.
 *
 * mechlist: list of mechanisms to disable
 * allflag: if true, indicates all mechanisms should be disabled.
 * auto_key_migrate_flag: if true, indicates auto key migrate should be disabled
 */
int
disable_metaslot(mechlist_t *mechlist, boolean_t allflag,
    boolean_t auto_key_migrate_flag)
{
	uentry_t *puent;
	int rc = SUCCESS;

	if ((puent = getent_uef(METASLOT_KEYWORD)) == NULL) {
		cryptoerror(LOG_STDERR,
		    gettext("metaslot entry doesn't exist."));
		return (FAILURE);
	}


	if ((mechlist == NULL) && (!auto_key_migrate_flag) && (!allflag)) {
		/* disable metaslot */
		puent->flag_metaslot_enabled = B_FALSE;
		goto write_to_file;
	}

	if (auto_key_migrate_flag) {
		/* need to disable auto_key_migrate */
		puent->flag_metaslot_auto_key_migrate = B_FALSE;
	}

	if ((mechlist == NULL) && (!allflag)) {
		goto write_to_file;
	}

	/* disable specified mechanisms */
	if (allflag) {
		free_umechlist(puent->policylist);
		puent->policylist = NULL;
		puent->count = 0;
		puent->flag_enabledlist = B_TRUE;
		rc = SUCCESS;
	} else {
		if (puent->flag_enabledlist == B_TRUE) {
			/*
			 * The current default policy mode
			 * is "all are disabled, except ...", so if a
			 * specified mechanism is in the exception list
			 * (the policylist), delete it from the policylist.
			 */
			rc = update_policylist(puent, mechlist, DELETE_MODE);
		} else {
			/*
			 * The current default policy mode of this library
			 * is "all are enabled", so if a specified mechanism
			 * is not in the exception list (policylist), add
			 * it into the policylist.
			 */
			rc = update_policylist(puent, mechlist, ADD_MODE);
		}
	}

	if (rc != SUCCESS) {
		goto finish;
	}

	/* If all mechanisms are disabled, metaslot will be disabled as well */
	if ((puent->flag_enabledlist) && (puent->count == 0)) {
		puent->flag_metaslot_enabled = B_FALSE;
	}

write_to_file:

	rc = update_pkcs11conf(puent);

finish:
	free_uentry(puent);
	return (rc);
}

/*
 * enable metaslot and some of its configuration options
 *
 * If mechlist==NULL, and the other flags are false, or not specified,
 * just enable the metaslot feature.
 *
 * token: if specified, indicate label of token to be used as keystore.
 * slot: if specified, indicate slot to be used as keystore.
 * use_default: if true, indicate to use the default keystore.  It should
 * 		not be specified if either token or slot is specified.
 * mechlist: list of mechanisms to enable
 * allflag: if true, indicates all mechanisms should be enabled.
 * auto_key_migrate_flag: if true, indicates auto key migrate should be enabled
 */
int
enable_metaslot(char *token, char *slot, boolean_t use_default,
    mechlist_t *mechlist,  boolean_t allflag, boolean_t auto_key_migrate_flag)
{
	uentry_t *puent;
	int rc = SUCCESS;

	if ((puent = getent_uef(METASLOT_KEYWORD)) == NULL) {
		cryptoerror(LOG_STDERR,
		    gettext("metaslot entry doesn't exist."));
		return (FAILURE);
	}

	puent->flag_metaslot_enabled = B_TRUE;

	if (auto_key_migrate_flag) {
		/* need to enable auto_key_migrate */
		puent->flag_metaslot_auto_key_migrate = B_TRUE;
	}

	if (allflag) {
		/*
		 * If enabling all, what needs to be done are cleaning up the
		 * policylist and setting the "flag_enabledlist" flag to
		 * B_FALSE.
		 */
		free_umechlist(puent->policylist);
		puent->policylist = NULL;
		puent->count = 0;
		puent->flag_enabledlist = B_FALSE;
		rc = SUCCESS;
	} else {
		if (mechlist) {
			if (puent->flag_enabledlist == B_TRUE) {
				/*
				 * The current default policy mode of this
				 * library is "all are disabled, except ...",
				 * so if a specified mechanism is not in the
				 * exception list (policylist), add it.
				 */
				rc = update_policylist(puent, mechlist,
				    ADD_MODE);
			} else {
				/*
				 * The current default policy mode of this
				 * library is "all are enabled, except", so if
				 * a specified  mechanism is in the exception
				 * list (policylist), delete it.
				 */
				rc = update_policylist(puent, mechlist,
				    DELETE_MODE);
			}
		}
	}

	if (rc != SUCCESS) {
		goto finish;
	}

	if (!use_default && !token && !slot) {
		/* no need to change metaslot keystore */
		goto write_to_file;
	}

	(void) bzero((char *)puent->metaslot_ks_token, TOKEN_LABEL_SIZE);
	(void) bzero((char *)puent->metaslot_ks_slot, SLOT_DESCRIPTION_SIZE);

	if (use_default) {
		(void) strlcpy((char *)puent->metaslot_ks_token,
		    SOFT_TOKEN_LABEL, TOKEN_LABEL_SIZE);
		(void) strlcpy((char *)puent->metaslot_ks_slot,
		    SOFT_SLOT_DESCRIPTION, SLOT_DESCRIPTION_SIZE);
	} else {

		if (token) {
			(void) strlcpy((char *)puent->metaslot_ks_token, token,
			    TOKEN_LABEL_SIZE);
		}

		if (slot) {
			(void) strlcpy((char *)puent->metaslot_ks_slot, slot,
			    SLOT_DESCRIPTION_SIZE);
		}
	}


write_to_file:

	rc = update_pkcs11conf(puent);

finish:
	free_uentry(puent);
	return (rc);
}
