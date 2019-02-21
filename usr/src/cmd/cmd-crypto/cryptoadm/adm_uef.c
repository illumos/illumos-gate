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
 * Copyright 2010 Nexenta Systems, Inc.  All rights resrved.
 * Copyright (c) 2018, Joyent, Inc.
 */

#include <cryptoutil.h>
#include <fcntl.h>
#include <libintl.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <unistd.h>
#include <errno.h>
#include <dlfcn.h>
#include <link.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <security/cryptoki.h>
#include "cryptoadm.h"

#define	HDR1 "                                     P\n"
#define	HDR2 "                         S     V  K  a     U  D\n"
#define	HDR3 "                         i     e  e  i     n  e\n"
#define	HDR4 "                      S  g  V  r  y  r  W  w  r\n"
#define	HDR5 "             E  D  D  i  n  e  i  G  G  r  r  i\n"
#define	HDR6 "          H  n  e  i  g  +  r  +  e  e  a  a  v  E\n"
#define	HDR7 "min  max  W  c  c  g  n  R  i  R  n  n  p  p  e  C\n"


static int err; /* To store errno which may be overwritten by gettext() */
static boolean_t is_in_policylist(midstr_t, umechlist_t *);
static char *uent2str(uentry_t *);
static boolean_t check_random(CK_SLOT_ID, CK_FUNCTION_LIST_PTR);

static void display_slot_flags(CK_FLAGS flags)
{
	(void) printf(gettext("Slot Flags: "));
	if (flags & CKF_TOKEN_PRESENT)
		(void) printf("CKF_TOKEN_PRESENT ");
	if (flags & CKF_REMOVABLE_DEVICE)
		(void) printf("CKF_REMOVABLE_DEVICE ");
	if (flags & CKF_HW_SLOT)
		(void) printf("CKF_HW_SLOT ");
	(void) printf("\n");
}

void
display_token_flags(CK_FLAGS flags)
{
	(void) printf(gettext("Flags: "));
	if (flags & CKF_RNG)
		(void) printf("CKF_RNG ");
	if (flags & CKF_WRITE_PROTECTED)
		(void) printf("CKF_WRITE_PROTECTED ");
	if (flags & CKF_LOGIN_REQUIRED)
		(void) printf("CKF_LOGIN_REQUIRED ");
	if (flags & CKF_USER_PIN_INITIALIZED)
		(void) printf("CKF_USER_PIN_INITIALIZED ");
	if (flags & CKF_RESTORE_KEY_NOT_NEEDED)
		(void) printf("CKF_RESTORE_KEY_NOT_NEEDED ");
	if (flags & CKF_CLOCK_ON_TOKEN)
		(void) printf("CKF_CLOCK_ON_TOKEN ");
	if (flags & CKF_PROTECTED_AUTHENTICATION_PATH)
		(void) printf("CKF_PROTECTED_AUTHENTICATION_PATH ");
	if (flags & CKF_DUAL_CRYPTO_OPERATIONS)
		(void) printf("CKF_DUAL_CRYPTO_OPERATIONS ");
	if (flags & CKF_TOKEN_INITIALIZED)
		(void) printf("CKF_TOKEN_INITIALIZED ");
	if (flags & CKF_SECONDARY_AUTHENTICATION)
		(void) printf("CKF_SECONDARY_AUTHENTICATION ");
	if (flags & CKF_USER_PIN_COUNT_LOW)
		(void) printf("CKF_USER_PIN_COUNT_LOW ");
	if (flags & CKF_USER_PIN_FINAL_TRY)
		(void) printf("CKF_USER_PIN_FINAL_TRY ");
	if (flags & CKF_USER_PIN_LOCKED)
		(void) printf("CKF_USER_PIN_LOCKED ");
	if (flags & CKF_USER_PIN_TO_BE_CHANGED)
		(void) printf("CKF_USER_PIN_TO_BE_CHANGED ");
	if (flags & CKF_SO_PIN_COUNT_LOW)
		(void) printf("CKF_SO_PIN_COUNT_LOW ");
	if (flags & CKF_SO_PIN_FINAL_TRY)
		(void) printf("CKF_SO_PIN_FINAL_TRY ");
	if (flags & CKF_SO_PIN_LOCKED)
		(void) printf("CKF_SO_PIN_LOCKED ");
	if (flags & CKF_SO_PIN_TO_BE_CHANGED)
		(void) printf("CKF_SO_PIN_TO_BE_CHANGED ");
	if (flags & CKF_SO_PIN_TO_BE_CHANGED)
		(void) printf("CKF_SO_PIN_TO_BE_CHANGED ");
	(void) printf("\n");
}

void
display_mech_info(CK_MECHANISM_INFO *mechInfo)
{
	CK_FLAGS ec_flags = CKF_EC_F_P | CKF_EC_F_2M | CKF_EC_ECPARAMETERS |
	    CKF_EC_NAMEDCURVE | CKF_EC_UNCOMPRESS | CKF_EC_COMPRESS;

	(void) printf("%-4ld %-4ld ", mechInfo->ulMinKeySize,
	    mechInfo->ulMaxKeySize);
	(void) printf("%s  %s  %s  %s  %s  %s  %s  %s  %s  %s  %s  %s  "
	    "%s  %s",
	    (mechInfo->flags & CKF_HW) ? "X" : ".",
	    (mechInfo->flags & CKF_ENCRYPT) ? "X" : ".",
	    (mechInfo->flags & CKF_DECRYPT) ? "X" : ".",
	    (mechInfo->flags & CKF_DIGEST) ? "X" : ".",
	    (mechInfo->flags & CKF_SIGN) ? "X" : ".",
	    (mechInfo->flags & CKF_SIGN_RECOVER) ? "X" : ".",
	    (mechInfo->flags & CKF_VERIFY) ? "X" : ".",
	    (mechInfo->flags & CKF_VERIFY_RECOVER) ? "X" : ".",
	    (mechInfo->flags & CKF_GENERATE) ? "X" : ".",
	    (mechInfo->flags & CKF_GENERATE_KEY_PAIR) ? "X" : ".",
	    (mechInfo->flags & CKF_WRAP) ? "X" : ".",
	    (mechInfo->flags & CKF_UNWRAP) ? "X" : ".",
	    (mechInfo->flags & CKF_DERIVE) ? "X" : ".",
	    (mechInfo->flags & ec_flags) ? "X" : ".");
}

/*
 * Converts the provided list of mechanism names in their string format to
 * their corresponding PKCS#11 mechanism IDs.
 *
 * The list of mechanism names to be converted is provided in the
 * "mlist" argument.  The list of converted mechanism IDs is returned
 * in the "pmech_list" argument.
 *
 * This function is called by list_metaslot_info() and
 * list_mechlist_for_lib() functions.
 */
int
convert_mechlist(CK_MECHANISM_TYPE **pmech_list, CK_ULONG *mech_count,
    mechlist_t *mlist)
{
	int i, n = 0;
	mechlist_t *p = mlist;

	while (p != NULL) {
		p = p->next;
		n++;
	}

	*pmech_list = malloc(n * sizeof (CK_MECHANISM_TYPE));
	if (*pmech_list == NULL) {
		cryptodebug("out of memory");
		return (FAILURE);
	}
	p = mlist;
	for (i = 0; i < n; i++) {
		if (pkcs11_str2mech(p->name, &(*pmech_list[i])) != CKR_OK) {
			free(*pmech_list);
			return (FAILURE);
		}
		p = p->next;
	}
	*mech_count = n;
	return (SUCCESS);
}

/*
 * Display the mechanism list for a user-level library
 */
int
list_mechlist_for_lib(char *libname, mechlist_t *mlist,
		flag_val_t *rng_flag, boolean_t no_warn,
		boolean_t verbose, boolean_t show_mechs)
{
	CK_RV	rv = CKR_OK;
	CK_RV	(*Tmp_C_GetFunctionList)(CK_FUNCTION_LIST_PTR_PTR);
	CK_FUNCTION_LIST_PTR	prov_funcs; /* Provider's function list */
	CK_SLOT_ID_PTR		prov_slots = NULL; /* Provider's slot list */
	CK_MECHANISM_TYPE_PTR	pmech_list = NULL; /* mech list for a slot */
	CK_SLOT_INFO	slotinfo;
	CK_ULONG	slot_count;
	CK_ULONG	mech_count;
	uentry_t	*puent = NULL;
	boolean_t	lib_initialized = B_FALSE;
	void		*dldesc = NULL;
	char		*dl_error;
	const char 	*mech_name;
	char		*isa;
	char		libpath[MAXPATHLEN];
	char		buf[MAXPATHLEN];
	int		i, j;
	int		rc = SUCCESS;

	if (libname == NULL) {
		/* should not happen */
		cryptoerror(LOG_STDERR, gettext("internal error."));
		cryptodebug("list_mechlist_for_lib() - libname is NULL.");
		return (FAILURE);
	}

	/* Check if the library is in the pkcs11.conf file */
	if ((puent = getent_uef(libname)) == NULL) {
		cryptoerror(LOG_STDERR,
		    gettext("%s does not exist."), libname);
		return (FAILURE);
	}
	free_uentry(puent);

	/* Remove $ISA from the library name */
	if (strlcpy(buf, libname, sizeof (buf)) >= sizeof (buf)) {
		(void) printf(gettext("%s: the provider name is too long."),
		    libname);
		return (FAILURE);
	}

	if ((isa = strstr(buf, PKCS11_ISA)) != NULL) {
		*isa = '\000';
		isa += strlen(PKCS11_ISA);
		(void) snprintf(libpath, MAXPATHLEN, "%s%s%s", buf, "/", isa);
	} else {
		(void) strlcpy(libpath, libname, sizeof (libpath));
	}

	/*
	 * Open the provider. Use RTLD_NOW here, as a way to
	 * catch any providers with incomplete symbols that
	 * might otherwise cause problems during libpkcs11's
	 * execution.
	 */
	dldesc = dlopen(libpath, RTLD_NOW);
	if (dldesc == NULL) {
		dl_error = dlerror();
		cryptodebug("Cannot load PKCS#11 library %s.  dlerror: %s",
		    libname, dl_error != NULL ? dl_error : "Unknown");
		rc = FAILURE;
		goto clean_exit;
	}

	/* Get the pointer to provider's C_GetFunctionList() */
	Tmp_C_GetFunctionList = (CK_RV(*)())dlsym(dldesc, "C_GetFunctionList");
	if (Tmp_C_GetFunctionList == NULL) {
		cryptodebug("Cannot get the address of the C_GetFunctionList "
		    "from %s", libname);
		rc = FAILURE;
		goto clean_exit;
	}

	/* Get the provider's function list */
	rv = Tmp_C_GetFunctionList(&prov_funcs);
	if (rv != CKR_OK) {
		cryptodebug("failed to call C_GetFunctionList from %s",
		    libname);
		rc = FAILURE;
		goto clean_exit;
	}

	/* Initialize this provider */
	rv = prov_funcs->C_Initialize(NULL_PTR);
	if (rv != CKR_OK) {
		cryptodebug("failed to call C_Initialize from %s, "
		    "return code = %d", libname, rv);
		rc = FAILURE;
		goto clean_exit;
	} else {
		lib_initialized = B_TRUE;
	}

	/*
	 * Find out how many slots this provider has, call with tokenPresent
	 * set to FALSE so all potential slots are returned.
	 */
	rv = prov_funcs->C_GetSlotList(FALSE, NULL_PTR, &slot_count);
	if (rv != CKR_OK) {
		cryptodebug("failed to get the slotlist from %s.", libname);
		rc = FAILURE;
		goto clean_exit;
	} else if (slot_count == 0) {
		if (!no_warn)
			(void) printf(gettext("%s: no slots presented.\n"),
			    libname);
		rc = SUCCESS;
		goto clean_exit;
	}

	/* Allocate memory for the slot list */
	prov_slots = malloc(slot_count * sizeof (CK_SLOT_ID));
	if (prov_slots == NULL) {
		cryptodebug("out of memory.");
		rc = FAILURE;
		goto clean_exit;
	}

	/* Get the slot list from provider */
	rv = prov_funcs->C_GetSlotList(FALSE, prov_slots, &slot_count);
	if (rv != CKR_OK) {
		cryptodebug("failed to call C_GetSlotList() from %s.",
		    libname);
		rc = FAILURE;
		goto clean_exit;
	}

	if (verbose) {
		(void) printf(gettext("Number of slots: %d\n"), slot_count);
	}

	/* Get the mechanism list for each slot */
	for (i = 0; i < slot_count; i++) {
		if (verbose)
			/*
			 * TRANSLATION_NOTE
			 * In some languages, the # symbol should be
			 * converted to "no", an "n" followed by a
			 * superscript "o"..
			 */
			(void) printf(gettext("\nSlot #%d\n"), i+1);

		if ((rng_flag != NULL) && (*rng_flag == NO_RNG)) {
			if (check_random(prov_slots[i], prov_funcs)) {
				*rng_flag = HAS_RNG;
				rc = SUCCESS;
				goto clean_exit;
			} else
				continue;
		}

		rv = prov_funcs->C_GetSlotInfo(prov_slots[i], &slotinfo);
		if (rv != CKR_OK) {
			cryptodebug("failed to get slotinfo from %s", libname);
			rc = FAILURE;
			break;
		}
		if (verbose) {
			CK_TOKEN_INFO tokeninfo;

			(void) printf(gettext("Description: %.64s\n"
			    "Manufacturer: %.32s\n"
			    "PKCS#11 Version: %d.%d\n"),
			    slotinfo.slotDescription,
			    slotinfo.manufacturerID,
			    prov_funcs->version.major,
			    prov_funcs->version.minor);

			(void) printf(gettext("Hardware Version: %d.%d\n"
			    "Firmware Version: %d.%d\n"),
			    slotinfo.hardwareVersion.major,
			    slotinfo.hardwareVersion.minor,
			    slotinfo.firmwareVersion.major,
			    slotinfo.firmwareVersion.minor);

			(void) printf(gettext("Token Present: %s\n"),
			    (slotinfo.flags & CKF_TOKEN_PRESENT ?
			    gettext("True") : gettext("False")));

			display_slot_flags(slotinfo.flags);

			rv = prov_funcs->C_GetTokenInfo(prov_slots[i],
			    &tokeninfo);
			if (rv != CKR_OK) {
				cryptodebug("Failed to get "
				    "token info from %s", libname);
				rc = FAILURE;
				break;
			}

			(void) printf(gettext("Token Label: %.32s\n"
			    "Manufacturer ID: %.32s\n"
			    "Model: %.16s\n"
			    "Serial Number: %.16s\n"
			    "Hardware Version: %d.%d\n"
			    "Firmware Version: %d.%d\n"
			    "UTC Time: %.16s\n"
			    "PIN Min Length: %d\n"
			    "PIN Max Length: %d\n"),
			    tokeninfo.label,
			    tokeninfo.manufacturerID,
			    tokeninfo.model,
			    tokeninfo.serialNumber,
			    tokeninfo.hardwareVersion.major,
			    tokeninfo.hardwareVersion.minor,
			    tokeninfo.firmwareVersion.major,
			    tokeninfo.firmwareVersion.minor,
			    tokeninfo.utcTime,
			    tokeninfo.ulMinPinLen,
			    tokeninfo.ulMaxPinLen);

			display_token_flags(tokeninfo.flags);
		}

		if (mlist == NULL) {
			rv = prov_funcs->C_GetMechanismList(prov_slots[i],
			    NULL_PTR, &mech_count);
			if (rv != CKR_OK) {
				cryptodebug(
				    "failed to call C_GetMechanismList() "
				    "from %s.", libname);
				rc = FAILURE;
				break;
			}

			if (mech_count == 0) {
				/* no mechanisms in this slot */
				continue;
			}

			pmech_list = malloc(mech_count *
			    sizeof (CK_MECHANISM_TYPE));
			if (pmech_list == NULL) {
				cryptodebug("out of memory");
				rc = FAILURE;
				break;
			}

			/* Get the actual mechanism list */
			rv = prov_funcs->C_GetMechanismList(prov_slots[i],
			    pmech_list, &mech_count);
			if (rv != CKR_OK) {
				cryptodebug(
				    "failed to call C_GetMechanismList() "
				    "from %s.", libname);
				free(pmech_list);
				rc = FAILURE;
				break;
			}
		} else  {
			/* use the mechanism list passed in */
			rc = convert_mechlist(&pmech_list, &mech_count, mlist);
			if (rc != SUCCESS) {
				goto clean_exit;
			}
		}
		if (show_mechs)
			(void) printf(gettext("Mechanisms:\n"));

		if (verbose && show_mechs) {
			display_verbose_mech_header();
		}
		/*
		 * Merge the current mechanism list into the returning
		 * mechanism list.
		 */
		for (j = 0; show_mechs && j < mech_count; j++) {
			CK_MECHANISM_TYPE	mech = pmech_list[j];
			CK_MECHANISM_INFO mech_info;

			rv = prov_funcs->C_GetMechanismInfo(
			    prov_slots[i], mech, &mech_info);
			if (rv != CKR_OK) {
				cryptodebug(
				    "failed to call "
				    "C_GetMechanismInfo() from %s.",
				    libname);
				free(pmech_list);
				pmech_list = NULL;
				rc = FAILURE;
				break;
			}
			if (mech >= CKM_VENDOR_DEFINED) {
				(void) printf("%#lx", mech);
			} else {
				mech_name = pkcs11_mech2str(mech);
				(void) printf("%-29s", mech_name);
			}

			if (verbose) {
				display_mech_info(&mech_info);
			}
			(void) printf("\n");
		}
		if (pmech_list)
			free(pmech_list);
		if (rc == FAILURE) {
			break;
		}
	}

	if (rng_flag != NULL || rc == FAILURE) {
		goto clean_exit;
	}

clean_exit:

	if (rc == FAILURE) {
		(void) printf(gettext(
		    "%s: failed to retrieve the mechanism list.\n"), libname);
	}

	if (lib_initialized) {
		(void) prov_funcs->C_Finalize(NULL_PTR);
	}

	if (dldesc != NULL) {
		(void) dlclose(dldesc);
	}

	if (prov_slots != NULL) {
		free(prov_slots);
	}

	return (rc);
}


/*
 * Display the mechanism policy for a user-level library
 */
int
list_policy_for_lib(char *libname)
{
	uentry_t *puent = NULL;
	int rc;

	if (libname == NULL) {
		/* should not happen */
		cryptoerror(LOG_STDERR, gettext("internal error."));
		cryptodebug("list_policy_for_lib() - libname is NULL.");
		return (FAILURE);
	}

	/* Get the library entry from the pkcs11.conf file */
	if ((puent = getent_uef(libname)) == NULL) {
		cryptoerror(LOG_STDERR,
		    gettext("%s does not exist."), libname);
		return (FAILURE);
	}

	/* Print the policy for this library */
	rc = print_uef_policy(puent);
	free_uentry(puent);

	return (rc);
}


/*
 * Disable mechanisms for a user-level library
 */
int
disable_uef_lib(char *libname, boolean_t rndflag, boolean_t allflag,
    mechlist_t *marglist)
{
	uentry_t	*puent;
	int	rc;

	if (libname == NULL) {
		/* should not happen */
		cryptoerror(LOG_STDERR, gettext("internal error."));
		cryptodebug("disable_uef_lib() - libname is NULL.");
		return (FAILURE);
	}

	/* Get the provider entry from the pkcs11.conf file */
	if ((puent = getent_uef(libname)) == NULL) {
		cryptoerror(LOG_STDERR,
		    gettext("%s does not exist."), libname);
		return (FAILURE);
	}

	/*
	 * Update the mechanism policy of this library entry, based on
	 * the current policy mode of the library and the mechanisms specified
	 * in CLI.
	 */
	if (allflag) {
		/*
		 * If disabling all, just need to clean up the policylist and
		 * set the flag_enabledlist flag to be B_TRUE.
		 */
		free_umechlist(puent->policylist);
		puent->policylist = NULL;
		puent->count = 0;
		puent->flag_enabledlist = B_TRUE;
		rc = SUCCESS;
	} else if (marglist != NULL) {
		if (puent->flag_enabledlist == B_TRUE) {
			/*
			 * The current default policy mode of this library
			 * is "all are disabled, except ...", so if a
			 * specified mechanism is in the exception list
			 * (the policylist), delete it from the policylist.
			 */
			rc = update_policylist(puent, marglist, DELETE_MODE);
		} else {
			/*
			 * The current default policy mode of this library
			 * is "all are enabled", so if a specified mechanism
			 * is not in the exception list (policylist), add
			 * it into the policylist.
			 */
			rc = update_policylist(puent, marglist, ADD_MODE);
		}
	} else if (!rndflag) {
		/* should not happen */
		cryptoerror(LOG_STDERR, gettext("internal error."));
		cryptodebug("disable_uef_lib() - wrong arguments.");
		return (FAILURE);
	}

	if (rndflag)
		puent->flag_norandom = B_TRUE;

	if (rc == FAILURE) {
		free_uentry(puent);
		return (FAILURE);
	}

	/* Update the pkcs11.conf file with the updated entry */
	rc = update_pkcs11conf(puent);
	free_uentry(puent);
	return (rc);
}


/*
 * Enable disabled mechanisms for a user-level library.
 */
int
enable_uef_lib(char *libname, boolean_t rndflag, boolean_t allflag,
    mechlist_t *marglist)
{
	uentry_t	*puent;
	int	rc = SUCCESS;

	if (libname == NULL) {
		/* should not happen */
		cryptoerror(LOG_STDERR, gettext("internal error."));
		cryptodebug("enable_uef_lib() - libname is NULL.");
		return (FAILURE);
	}

	/* Get the provider entry from the pkcs11.conf file */
	if ((puent = getent_uef(libname)) == NULL) {
		cryptoerror(LOG_STDERR,
		    gettext("%s does not exist."), libname);
		return (FAILURE);
	}

	/*
	 * Update the mechanism policy of this library entry, based on
	 * the current policy mode of the library and the mechanisms
	 * specified in CLI.
	 */
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
	} else if (marglist != NULL) {
		if (puent->flag_enabledlist == B_TRUE) {
			/*
			 * The current default policy mode of this library
			 * is "all are disabled, except ...", so if a
			 * specified mechanism is not in the exception list
			 * (policylist), add it.
			 */
			rc = update_policylist(puent, marglist, ADD_MODE);
		} else {
			/*
			 * The current default policy mode of this library
			 * is "all are enabled, except", so if a specified
			 * mechanism is in the exception list (policylist),
			 * delete it.
			 */
			rc = update_policylist(puent, marglist, DELETE_MODE);
		}
	} else if (!rndflag) {
		/* should not come here */
		cryptoerror(LOG_STDERR, gettext("internal error."));
		cryptodebug("enable_uef_lib() - wrong arguments.");
		return (FAILURE);
	}

	if (rndflag)
		puent->flag_norandom = B_FALSE;

	if (rc == FAILURE) {
		free_uentry(puent);
		return (FAILURE);
	}

	/* Update the pkcs11.conf file with the updated entry */
	rc = update_pkcs11conf(puent);
	free_uentry(puent);
	return (rc);
}


/*
 * Install a user-level library.
 */
int
install_uef_lib(char *libname)
{
	uentry_t	*puent;
	struct stat 	statbuf;
	char	libpath[MAXPATHLEN];
	char	libbuf[MAXPATHLEN];
	char	*isa;

	if (libname == NULL) {
		/* should not happen */
		cryptoerror(LOG_STDERR, gettext("internal error."));
		cryptodebug("install_uef_lib() - libname is NULL.");
		return (FAILURE);
	}

	/* Check if the provider already exists in the framework */
	if ((puent = getent_uef(libname)) != NULL) {
		cryptoerror(LOG_STDERR, gettext("%s exists already."),
		    libname);
		free_uentry(puent);
		return (FAILURE);
	}

	/*
	 * Check if the library exists in the system. if $ISA is in the
	 * path, only check the 32bit version.
	 */
	if (strlcpy(libbuf, libname, MAXPATHLEN) >= MAXPATHLEN) {
		cryptoerror(LOG_STDERR,
		    gettext("the provider name is too long - %s"), libname);
		return (FAILURE);
	}

	if ((isa = strstr(libbuf, PKCS11_ISA)) != NULL) {
		*isa = '\000';
		isa += strlen(PKCS11_ISA);
		(void) snprintf(libpath, sizeof (libpath), "%s%s%s", libbuf,
		    "/", isa);
	} else {
		(void) strlcpy(libpath, libname, sizeof (libpath));
	}

	/* Check if it is same as the framework library */
	if (strcmp(libpath, UEF_FRAME_LIB) == 0) {
		cryptoerror(LOG_STDERR, gettext(
		    "The framework library %s can not be installed."),
		    libname);
		return (FAILURE);
	}

	if (stat(libpath, &statbuf) != 0) {
		cryptoerror(LOG_STDERR, gettext("%s not found"), libname);
		return (FAILURE);
	}

	/* Need to add "\n" to libname for adding into the config file */
	if (strlcat(libname, "\n", MAXPATHLEN) >= MAXPATHLEN) {
		cryptoerror(LOG_STDERR, gettext(
		    "can not install %s; the name is too long."), libname);
		return (FAILURE);
	}

	return (update_conf(_PATH_PKCS11_CONF, libname));

}


/*
 * Uninstall a user-level library.
 */
int
uninstall_uef_lib(char *libname)
{
	uentry_t	*puent;
	FILE	*pfile;
	FILE	*pfile_tmp;
	char 	buffer[BUFSIZ];
	char 	buffer2[BUFSIZ];
	char	tmpfile_name[MAXPATHLEN];
	char 	*name;
	boolean_t	found;
	boolean_t	in_package;
	int	len;
	int	rc = SUCCESS;

	if (libname == NULL) {
		/* should not happen */
		cryptoerror(LOG_STDERR, gettext("internal error."));
		cryptodebug("uninstall_uef_lib() - libname is NULL.");
		return (FAILURE);
	}

	/* Check if the provider exists */
	if ((puent = getent_uef(libname)) == NULL) {
		cryptoerror(LOG_STDERR,
		    gettext("%s does not exist."), libname);
		return (FAILURE);
	}
	free_uentry(puent);

	/*  Open the pkcs11.conf file and lock it */
	if ((pfile = fopen(_PATH_PKCS11_CONF, "r+")) == NULL) {
		err = errno;
		cryptoerror(LOG_STDERR,
		    gettext("failed to update the configuration - %s"),
		    strerror(err));
		cryptodebug("failed to open %s for write.", _PATH_PKCS11_CONF);
		return (FAILURE);
	}

	if (lockf(fileno(pfile), F_TLOCK, 0) == -1) {
		err = errno;
		cryptoerror(LOG_STDERR,
		    gettext("failed to lock the configuration - %s"),
		    strerror(err));
		(void) fclose(pfile);
		return (FAILURE);
	}

	/*
	 * Create a temporary file in the /etc/crypto directory to save
	 * the new configuration file first.
	 */
	(void) strlcpy(tmpfile_name, TMPFILE_TEMPLATE, sizeof (tmpfile_name));
	if (mkstemp(tmpfile_name) == -1) {
		err = errno;
		cryptoerror(LOG_STDERR,
		    gettext("failed to create a temporary file - %s"),
		    strerror(err));
		(void) fclose(pfile);
		return (FAILURE);
	}

	if ((pfile_tmp = fopen(tmpfile_name, "w")) == NULL) {
		err = errno;
		cryptoerror(LOG_STDERR, gettext("failed to open %s - %s"),
		    tmpfile_name, strerror(err));
		if (unlink(tmpfile_name) != 0) {
			err = errno;
			cryptoerror(LOG_STDERR, gettext(
			    "(Warning) failed to remove %s: %s"),
			    tmpfile_name, strerror(err));
		}
		(void) fclose(pfile);
		return (FAILURE);
	}


	/*
	 * Loop thru the config file.  If the library to be uninstalled
	 * is in a package, just comment it off.
	 */
	in_package = B_FALSE;
	while (fgets(buffer, BUFSIZ, pfile) != NULL) {
		found = B_FALSE;
		if (!(buffer[0] == ' ' || buffer[0] == '\n' ||
		    buffer[0] == '\t')) {
			if (strstr(buffer, " Start ") != NULL) {
				in_package = B_TRUE;
			} else if (strstr(buffer, " End ") != NULL) {
				in_package = B_FALSE;
			} else if (buffer[0] != '#') {
				(void) strlcpy(buffer2, buffer, BUFSIZ);

				/* get rid of trailing '\n' */
				len = strlen(buffer2);
				if (buffer2[len-1] == '\n') {
					len--;
				}
				buffer2[len] = '\0';

				if ((name = strtok(buffer2, SEP_COLON))
				    == NULL) {
					rc = FAILURE;
					break;
				} else if (strcmp(libname, name) == 0) {
					found = B_TRUE;
				}
			}
		}

		if (found) {
			if (in_package) {
				(void) snprintf(buffer2, sizeof (buffer2),
				    "%s%s%s", "#", libname, "\n");
				if (fputs(buffer2, pfile_tmp) == EOF) {
					rc = FAILURE;
				}
			}
		} else {
			if (fputs(buffer, pfile_tmp) == EOF) {
				rc = FAILURE;
			}
		}

		if (rc == FAILURE) {
			break;
		}
	}

	if (rc == FAILURE) {
		cryptoerror(LOG_STDERR, gettext("write error."));
		(void) fclose(pfile);
		(void) fclose(pfile_tmp);
		if (unlink(tmpfile_name) != 0) {
			err = errno;
			cryptoerror(LOG_STDERR, gettext(
			    "(Warning) failed to remove %s: %s"),
			    tmpfile_name, strerror(err));
		}
		return (FAILURE);
	}

	(void) fclose(pfile);
	if (fclose(pfile_tmp) != 0) {
		err = errno;
		cryptoerror(LOG_STDERR,
		    gettext("failed to close a temporary file - %s"),
		    strerror(err));
		return (FAILURE);
	}

	/* Now update the real config file */
	if (rename(tmpfile_name, _PATH_PKCS11_CONF) == -1) {
		err = errno;
		cryptoerror(LOG_STDERR,
		    gettext("failed to update the configuration - %s"),
		    strerror(err));
		cryptodebug("failed to rename %s to %s: %s", tmpfile,
		    _PATH_PKCS11_CONF, strerror(err));
		rc = FAILURE;
	} else if (chmod(_PATH_PKCS11_CONF,
	    S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH) == -1) {
		err = errno;
		cryptoerror(LOG_STDERR,
		    gettext("failed to update the configuration - %s"),
		    strerror(err));
		cryptodebug("failed to chmod to %s: %s", _PATH_PKCS11_CONF,
		    strerror(err));
		rc = FAILURE;
	} else {
		rc = SUCCESS;
	}

	if ((rc == FAILURE) && (unlink(tmpfile_name) != 0)) {
		err = errno;
		cryptoerror(LOG_STDERR, gettext(
		    "(Warning) failed to remove %s: %s"),
		    tmpfile_name, strerror(err));
	}

	return (rc);
}


int
display_policy(uentry_t *puent)
{
	CK_MECHANISM_TYPE	mech_id;
	const char		*mech_name;
	umechlist_t		*ptr;

	if (puent == NULL) {
		return (SUCCESS);
	}

	if (puent->flag_enabledlist == B_FALSE) {
		(void) printf(gettext("%s: all mechanisms are enabled"),
		    puent->name);
		ptr = puent->policylist;
		if (ptr == NULL) {
			(void) printf(".");
		} else {
			(void) printf(gettext(", except "));
			while (ptr != NULL) {
				mech_id = strtoul(ptr->name, NULL, 0);
				if (mech_id & CKO_VENDOR_DEFINED) {
					/* vendor defined mechanism */
					(void) printf("%s", ptr->name);
				} else {
					if (mech_id >= CKM_VENDOR_DEFINED) {
						(void) printf("%#lx", mech_id);
					} else {
						mech_name = pkcs11_mech2str(
						    mech_id);
						if (mech_name == NULL) {
							return (FAILURE);
						}
						(void) printf("%s", mech_name);
					}
				}

				ptr = ptr->next;
				if (ptr == NULL) {
					(void) printf(".");
				} else {
					(void) printf(",");
				}
			}
		}
	} else { /* puent->flag_enabledlist == B_TRUE */
		(void) printf(gettext("%s: all mechanisms are disabled"),
		    puent->name);
		ptr = puent->policylist;
		if (ptr == NULL) {
			(void) printf(".");
		} else {
			(void) printf(gettext(", except "));
			while (ptr != NULL) {
				mech_id = strtoul(ptr->name, NULL, 0);
				if (mech_id & CKO_VENDOR_DEFINED) {
					/* vendor defined mechanism */
					(void) printf("%s", ptr->name);
				} else {
					mech_name = pkcs11_mech2str(mech_id);
					if (mech_name == NULL) {
						return (FAILURE);
					}
					(void) printf("%s", mech_name);
				}
				ptr = ptr->next;
				if (ptr == NULL) {
					(void) printf(".");
				} else {
					(void) printf(",");
				}
			}
		}
	}
	return (SUCCESS);
}



/*
 * Print out the mechanism policy for a user-level provider pointed by puent.
 */
int
print_uef_policy(uentry_t *puent)
{
	flag_val_t rng_flag;

	if (puent == NULL) {
		return (FAILURE);
	}

	rng_flag = NO_RNG;
	if (list_mechlist_for_lib(puent->name, NULL, &rng_flag, B_TRUE,
	    B_FALSE, B_FALSE) != SUCCESS) {
		cryptoerror(LOG_STDERR,
		    gettext("%s internal error."), puent->name);
		return (FAILURE);
	}

	if (display_policy(puent) != SUCCESS) {
		goto failed_exit;
	}


	if (puent->flag_norandom == B_TRUE)
		/*
		 * TRANSLATION_NOTE
		 * "random" is a keyword and not to be translated.
		 */
		(void) printf(gettext(" %s is disabled."), "random");
	else {
		if (rng_flag == HAS_RNG)
			/*
			 * TRANSLATION_NOTE
			 * "random" is a keyword and not to be translated.
			 */
			(void) printf(gettext(" %s is enabled."), "random");
	}
	(void) printf("\n");

	return (SUCCESS);

failed_exit:

	(void) printf(gettext("\nout of memory.\n"));
	return (FAILURE);
}


/*
 * Check if the mechanism is in the mechanism list.
 */
static boolean_t
is_in_policylist(midstr_t mechname, umechlist_t *plist)
{
	boolean_t found = B_FALSE;

	if (mechname == NULL) {
		return (B_FALSE);
	}

	while (plist != NULL) {
		if (strcmp(plist->name, mechname) == 0) {
			found = B_TRUE;
			break;
		}
		plist = plist->next;
	}

	return (found);
}


/*
 * Update the pkcs11.conf file with the updated entry.
 */
int
update_pkcs11conf(uentry_t *puent)
{
	FILE	*pfile;
	FILE	*pfile_tmp;
	char buffer[BUFSIZ];
	char buffer2[BUFSIZ];
	char tmpfile_name[MAXPATHLEN];
	char *name;
	char *str;
	int len;
	int rc = SUCCESS;
	boolean_t found;

	if (puent == NULL) {
		cryptoerror(LOG_STDERR, gettext("internal error."));
		return (FAILURE);
	}

	/* Open the pkcs11.conf file */
	if ((pfile = fopen(_PATH_PKCS11_CONF, "r+")) == NULL) {
		err = errno;
		cryptoerror(LOG_STDERR,
		    gettext("failed to update the configuration - %s"),
		    strerror(err));
		cryptodebug("failed to open %s for write.", _PATH_PKCS11_CONF);
		return (FAILURE);
	}

	/* Lock the pkcs11.conf file */
	if (lockf(fileno(pfile), F_TLOCK, 0) == -1) {
		err = errno;
		cryptoerror(LOG_STDERR,
		    gettext("failed to update the configuration - %s"),
		    strerror(err));
		(void) fclose(pfile);
		return (FAILURE);
	}

	/*
	 * Create a temporary file in the /etc/crypto directory to save
	 * updated configuration file first.
	 */
	(void) strlcpy(tmpfile_name, TMPFILE_TEMPLATE, sizeof (tmpfile_name));
	if (mkstemp(tmpfile_name) == -1) {
		err = errno;
		cryptoerror(LOG_STDERR,
		    gettext("failed to create a temporary file - %s"),
		    strerror(err));
		(void) fclose(pfile);
		return (FAILURE);
	}

	if ((pfile_tmp = fopen(tmpfile_name, "w")) == NULL) {
		err = errno;
		cryptoerror(LOG_STDERR, gettext("failed to open %s - %s"),
		    tmpfile_name, strerror(err));
		if (unlink(tmpfile_name) != 0) {
			err = errno;
			cryptoerror(LOG_STDERR, gettext(
			    "(Warning) failed to remove %s: %s"),
			    tmpfile_name, strerror(err));
		}
		(void) fclose(pfile);
		return (FAILURE);
	}


	/*
	 * Loop thru entire pkcs11.conf file, update the entry to be
	 * updated and save the updated file to the temporary file first.
	 */
	while (fgets(buffer, BUFSIZ, pfile) != NULL) {
		found = B_FALSE;
		if (!(buffer[0] == '#' || buffer[0] == ' ' ||
		    buffer[0] == '\n'|| buffer[0] == '\t')) {
			/*
			 * Get the provider name from this line and check if
			 * this is the entry to be updated. Note: can not use
			 * "buffer" directly because strtok will change its
			 * value.
			 */
			(void) strlcpy(buffer2, buffer, BUFSIZ);

			/* get rid of trailing '\n' */
			len = strlen(buffer2);
			if (buffer2[len-1] == '\n') {
				len--;
			}
			buffer2[len] = '\0';

			if ((name = strtok(buffer2, SEP_COLON)) == NULL) {
				rc = FAILURE;
				break;
			} else if (strcmp(puent->name, name) == 0) {
				found = B_TRUE;
			}
		}

		if (found) {
			/*
			 * This is the entry to be modified, get the updated
			 * string.
			 */
			if ((str = uent2str(puent)) == NULL) {
				rc = FAILURE;
				break;
			} else {
				(void) strlcpy(buffer, str, BUFSIZ);
				free(str);
			}
		}

		if (fputs(buffer, pfile_tmp) == EOF) {
			err = errno;
			cryptoerror(LOG_STDERR, gettext(
			    "failed to write to a temp file: %s."),
			    strerror(err));
			rc = FAILURE;
			break;
		}
	}

	if (rc == FAILURE) {
		(void) fclose(pfile);
		(void) fclose(pfile_tmp);
		if (unlink(tmpfile_name) != 0) {
			err = errno;
			cryptoerror(LOG_STDERR, gettext(
			    "(Warning) failed to remove %s: %s"),
			    tmpfile_name, strerror(err));
		}
		return (FAILURE);
	}

	(void) fclose(pfile);
	if (fclose(pfile_tmp) != 0) {
		err = errno;
		cryptoerror(LOG_STDERR,
		    gettext("failed to close %s: %s"), tmpfile_name,
		    strerror(err));
		return (FAILURE);
	}

	/* Copy the temporary file to the pkcs11.conf file */
	if (rename(tmpfile_name, _PATH_PKCS11_CONF) == -1) {
		err = errno;
		cryptoerror(LOG_STDERR,
		    gettext("failed to update the configuration - %s"),
		    strerror(err));
		cryptodebug("failed to rename %s to %s: %s", tmpfile_name,
		    _PATH_PKCS11_CONF, strerror(err));
		rc = FAILURE;
	} else if (chmod(_PATH_PKCS11_CONF,
	    S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH) == -1) {
		err = errno;
		cryptoerror(LOG_STDERR,
		    gettext("failed to update the configuration - %s"),
		    strerror(err));
		cryptodebug("failed to chmod to %s: %s", _PATH_PKCS11_CONF,
		    strerror(err));
		rc = FAILURE;
	} else {
		rc = SUCCESS;
	}

	if ((rc == FAILURE) && (unlink(tmpfile_name) != 0)) {
		err = errno;
		cryptoerror(LOG_STDERR, gettext(
		    "(Warning) failed to remove %s: %s"),
		    tmpfile_name, strerror(err));
	}

	return (rc);
}


/*
 * Convert an uentry to a character string
 */
static char *
uent2str(uentry_t *puent)
{
	umechlist_t	*phead;
	boolean_t tok1_present = B_FALSE;
	char *buf;
	char blank_buf[128];

	if (puent == NULL) {
		cryptoerror(LOG_STDERR, gettext("internal error."));
		return (NULL);
	}

	buf = malloc(BUFSIZ);
	if (buf == NULL) {
		cryptoerror(LOG_STDERR, gettext("out of memory."));
		return (NULL);
	}

	/* convert the library name */
	if (strlcpy(buf, puent->name, BUFSIZ) >= BUFSIZ) {
		free(buf);
		return (NULL);
	}


	/* convert the enabledlist or the disabledlist */
	if (puent->flag_enabledlist == B_TRUE) {
		if (strlcat(buf, SEP_COLON, BUFSIZ) >= BUFSIZ) {
			free(buf);
			return (NULL);
		}

		if (strlcat(buf, EF_ENABLED, BUFSIZ) >= BUFSIZ) {
			free(buf);
			return (NULL);
		}

		phead = puent->policylist;
		while (phead != NULL) {
			if (strlcat(buf, phead->name, BUFSIZ) >= BUFSIZ) {
				free(buf);
				return (NULL);
			}

			phead = phead->next;
			if (phead != NULL) {
				if (strlcat(buf, SEP_COMMA, BUFSIZ)
				    >= BUFSIZ) {
					free(buf);
					return (NULL);
				}
			}
		}
		tok1_present = B_TRUE;
	} else if (puent->policylist != NULL) {
		if (strlcat(buf, SEP_COLON, BUFSIZ) >= BUFSIZ) {
			free(buf);
			return (NULL);
		}

		if (strlcat(buf, EF_DISABLED, BUFSIZ) >= BUFSIZ) {
			free(buf);
			return (NULL);
		}
		phead = puent->policylist;
		while (phead != NULL) {
			if (strlcat(buf, phead->name, BUFSIZ) >= BUFSIZ) {
				free(buf);
				return (NULL);
			}

			phead = phead->next;
			if (phead != NULL) {
				if (strlcat(buf, SEP_COMMA, BUFSIZ)
				    >= BUFSIZ) {
					free(buf);
					return (NULL);
				}
			}
		}
		tok1_present = B_TRUE;
	}

	if (puent->flag_norandom == B_TRUE) {
		if (strlcat(buf, (tok1_present ? SEP_SEMICOLON : SEP_COLON),
		    BUFSIZ) >= BUFSIZ) {
			free(buf);
			return (NULL);
		}

		if (strlcat(buf, EF_NORANDOM, BUFSIZ) >= BUFSIZ) {
			free(buf);
			return (NULL);
		}
	}

	if (strcmp(puent->name, METASLOT_KEYWORD) == 0) {

		/* write the metaslot_status= value */
		if (strlcat(buf, (tok1_present ? SEP_SEMICOLON : SEP_COLON),
		    BUFSIZ) >= BUFSIZ) {
			free(buf);
			return (NULL);
		}

		if (strlcat(buf, METASLOT_STATUS, BUFSIZ) >= BUFSIZ) {
			free(buf);
			return (NULL);
		}

		if (puent->flag_metaslot_enabled) {
			if (strlcat(buf, ENABLED_KEYWORD, BUFSIZ) >= BUFSIZ) {
				free(buf);
				return (NULL);
			}
		} else {
			if (strlcat(buf, DISABLED_KEYWORD, BUFSIZ)
			    >= BUFSIZ) {
				free(buf);
				return (NULL);
			}
		}

		if (!tok1_present) {
			tok1_present = B_TRUE;
		}

		if (strlcat(buf, SEP_SEMICOLON, BUFSIZ) >= BUFSIZ) {
			free(buf);
			return (NULL);
		}

		if (strlcat(buf, METASLOT_AUTO_KEY_MIGRATE, BUFSIZ) >= BUFSIZ) {
			free(buf);
			return (NULL);
		}

		if (puent->flag_metaslot_auto_key_migrate) {
			if (strlcat(buf, ENABLED_KEYWORD, BUFSIZ) >= BUFSIZ) {
				free(buf);
				return (NULL);
			}
		} else {
			if (strlcat(buf, DISABLED_KEYWORD, BUFSIZ) >= BUFSIZ) {
				free(buf);
				return (NULL);
			}
		}

		bzero(blank_buf, sizeof (blank_buf));

		/* write metaslot_token= if specified */
		if (memcmp(puent->metaslot_ks_token, blank_buf,
		    TOKEN_LABEL_SIZE) != 0) {
			/* write the metaslot_status= value */
			if (strlcat(buf, (tok1_present ?
			    SEP_SEMICOLON : SEP_COLON), BUFSIZ) >= BUFSIZ) {
				free(buf);
				return (NULL);
			}

			if (strlcat(buf, METASLOT_TOKEN, BUFSIZ) >= BUFSIZ) {
				free(buf);
				return (NULL);
			}

			if (strlcat(buf,
			    (const char *)puent->metaslot_ks_token, BUFSIZ)
			    >= BUFSIZ) {
				free(buf);
				return (NULL);
			}
		}

		/* write metaslot_slot= if specified */
		if (memcmp(puent->metaslot_ks_slot, blank_buf,
		    SLOT_DESCRIPTION_SIZE) != 0) {
			/* write the metaslot_status= value */
			if (strlcat(buf, (tok1_present ?
			    SEP_SEMICOLON : SEP_COLON), BUFSIZ) >= BUFSIZ) {
				free(buf);
				return (NULL);
			}

			if (strlcat(buf, METASLOT_SLOT, BUFSIZ) >= BUFSIZ) {
				free(buf);
				return (NULL);
			}

			if (strlcat(buf,
			    (const char *)puent->metaslot_ks_slot, BUFSIZ)
			    >= BUFSIZ) {
				free(buf);
				return (NULL);
			}
		}
	}

	if (strlcat(buf, "\n", BUFSIZ) >= BUFSIZ) {
		free(buf);
		return (NULL);
	}

	return (buf);
}


/*
 * This function updates the default policy mode and the policy exception list
 * for a user-level provider based on the mechanism specified in the disable
 * or enable subcommand and the update mode.   This function is called by the
 * enable_uef_lib() or disable_uef_lib().
 */
int
update_policylist(uentry_t *puent, mechlist_t *marglist, int update_mode)
{
	CK_MECHANISM_TYPE mech_type;
	midstr_t	midname;
	umechlist_t	*phead;
	umechlist_t	*pcur;
	umechlist_t	*pumech;
	boolean_t	found;
	int	rc = SUCCESS;

	if ((puent == NULL) || (marglist == NULL)) {
		/* should not happen */
		cryptoerror(LOG_STDERR, gettext("internal error."));
		cryptodebug("update_policylist()- puent or marglist is NULL.");
		return (FAILURE);
	}

	if ((update_mode != ADD_MODE) && (update_mode != DELETE_MODE)) {
		/* should not happen */
		cryptoerror(LOG_STDERR, gettext("internal error."));
		cryptodebug("update_policylist() - update_mode is incorrect.");
		return (FAILURE);
	}

	/*
	 * For each mechanism operand, get its mechanism type first.
	 * If fails to get the mechanism type, the mechanism operand must be
	 * invalid, gives an warning and ignore it. Otherwise,
	 * - convert the mechanism type to the internal representation (hex)
	 *   in the pkcs11.conf file
	 * - If update_mode == DELETE_MODE,
	 *	If the mechanism is in the policy list, delete it.
	 *	If the mechanism is not in the policy list, do nothing.
	 * - If update_mode == ADD_MODE,
	 *	If the mechanism is not in the policy list, add it.
	 *	If the mechanism is in the policy list already, do nothing.
	 */
	while (marglist) {
		if (pkcs11_str2mech(marglist->name, &mech_type) != CKR_OK) {
			/*
			 * This mechanism is not a valid PKCS11 mechanism,
			 * give warning and ignore it.
			 */
			cryptoerror(LOG_STDERR, gettext(
			    "(Warning) %s is not a valid PKCS#11 mechanism."),
			    marglist->name);
			rc = FAILURE;
		} else {
			(void) snprintf(midname, sizeof (midname), "%#010x",
			    (int)mech_type);
			if (update_mode == DELETE_MODE) {
				found = B_FALSE;
				phead = pcur = puent->policylist;
				while (!found && pcur) {
					if (strcmp(pcur->name, midname) == 0) {
						found = B_TRUE;
					} else {
						phead = pcur;
						pcur = pcur->next;
					}
				}

				if (found) {
					if (phead == pcur) {
						puent->policylist =
						    puent->policylist->next;
						free(pcur);
					} else {
						phead->next = pcur->next;
						free(pcur);
					}
					puent->count--;
					if (puent->count == 0) {
						puent->policylist = NULL;
					}
				}
			} else if (update_mode == ADD_MODE) {
				if (!is_in_policylist(midname,
				    puent->policylist)) {
					pumech = create_umech(midname);
					if (pumech == NULL) {
						rc = FAILURE;
						break;
					}
					phead = puent->policylist;
					puent->policylist = pumech;
					pumech->next = phead;
					puent->count++;
				}
			}
		}
		marglist = marglist->next;
	}

	return (rc);
}

/*
 * Open a session to the given slot and check if we can do
 * random numbers by asking for one byte.
 */
static boolean_t
check_random(CK_SLOT_ID slot_id, CK_FUNCTION_LIST_PTR prov_funcs)
{
	CK_RV rv;
	CK_SESSION_HANDLE hSession;
	CK_BYTE test_byte;
	CK_BYTE_PTR test_byte_ptr = &test_byte;

	rv = prov_funcs->C_OpenSession(slot_id, CKF_SERIAL_SESSION,
	    NULL_PTR, NULL, &hSession);
	if (rv != CKR_OK)
		return (B_FALSE);

	/* We care only about the return value */
	rv = prov_funcs->C_GenerateRandom(hSession, test_byte_ptr,
	    sizeof (test_byte));
	(void) prov_funcs->C_CloseSession(hSession);

	/*
	 * These checks are purely to determine whether the slot can do
	 * random numbers. So, we don't check whether the routine
	 * succeeds. The reason we check for CKR_RANDOM_NO_RNG also is that
	 * this error effectively means CKR_FUNCTION_NOT_SUPPORTED.
	 */
	if (rv != CKR_FUNCTION_NOT_SUPPORTED && rv != CKR_RANDOM_NO_RNG)
		return (B_TRUE);
	else
		return (B_FALSE);
}

void
display_verbose_mech_header()
{
	(void) printf("%28s %s", " ", HDR1);
	(void) printf("%28s %s", " ", HDR2);
	(void) printf("%28s %s", " ", HDR3);
	(void) printf("%28s %s", " ", HDR4);
	(void) printf("%28s %s", " ", HDR5);
	(void) printf("%28s %s", " ", HDR6);
	(void) printf("%-28.28s %s", gettext("mechanism name"), HDR7);
	/*
	 * TRANSLATION_NOTE
	 * Strictly for appearance's sake, the first header line should be
	 * as long as the length of the translated text above.  The format
	 * lengths should all match too.
	 */
	(void) printf("%28s ---- ---- "
	    "-  -  -  -  -  -  -  -  -  -  -  -  -  -\n",
	    gettext("----------------------------"));
}
