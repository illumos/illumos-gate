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
 *
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <strings.h>
#include <ctype.h>
#include <libgen.h>
#include <libintl.h>
#include <errno.h>
#include <sys/stat.h>
#include <kmfapiP.h>
#include "util.h"

#define	LIB_NSS_PATH	"/usr/lib/mps/libnss3.so"
#define	LIB_NSPR_PATH	"/usr/lib/mps/libnspr4.so"

static void
show_policy(KMF_POLICY_RECORD *plc)
{
	int i;
	if (plc == NULL)
		return;

	(void) printf("Name: %s\n", plc->name);

	(void) printf(gettext("Ignore Date: %s\n"),
	    plc->ignore_date ? gettext("true") : gettext("false"));

	(void) printf(gettext("Ignore Unknown EKUs: %s\n"),
	    plc->ignore_unknown_ekus ? gettext("true") : gettext("false"));

	(void) printf(gettext("Ignore TA: %s\n"),
	    plc->ignore_trust_anchor ? gettext("true") : gettext("false"));

	(void) printf(gettext("Validity Adjusted Time: %s\n"),
	    plc->validity_adjusttime ? plc->validity_adjusttime : "<null>");

	if (plc->ta_name == NULL && plc->ta_serial == NULL) {
		(void) printf(gettext("Trust Anchor Certificate: <null>\n"));
	} else {
		(void) printf(gettext("Trust Anchor Certificate:\n"));
		(void) printf(gettext("\tName: %s\n"),
		    plc->ta_name ? plc->ta_name : "<null>");
		(void) printf(gettext("\tSerial Number: %s\n"),
		    plc->ta_serial ? plc->ta_serial : "<null>");
	}

	if (plc->ku_bits != 0) {
		(void) printf(gettext("Key Usage Bits: "));
		for (i = KULOWBIT; i <= KUHIGHBIT; i++) {
			char *s = kmf_ku_to_string(
			    (plc->ku_bits & (1<<i)));
			if (s != NULL) {
				(void) printf("%s ", s);
			}
		}
		(void) printf("\n");
	} else {
		(void) printf(gettext("Key Usage Bits: 0\n"));
	}

	if (plc->eku_set.eku_count > 0) {
		(void) printf(gettext("Extended Key Usage Values:\n"));
		for (i = 0; i < plc->eku_set.eku_count; i++) {
			char *s = kmf_oid_to_ekuname(
			    &plc->eku_set.ekulist[i]);
			(void) printf("\t%s\t(%s)\n",
			    kmf_oid_to_string(&plc->eku_set.ekulist[i]),
			    s ? s : "unknown");
		}
	} else {
		(void) printf(gettext("Extended Key Usage Values: <null>\n"));
	}

	(void) printf(gettext("Validation Policy Information:\n"));

	if (plc->revocation & KMF_REVOCATION_METHOD_OCSP) {
		(void) printf(gettext("    OCSP:\n"));

		(void) printf(gettext("\tResponder URI: %s\n"),
		    plc->VAL_OCSP_BASIC.responderURI ?
		    plc->VAL_OCSP_BASIC.responderURI : "<null>");

		(void) printf(gettext("\tProxy: %s\n"),
		    plc->VAL_OCSP_BASIC.proxy ?
		    plc->VAL_OCSP_BASIC.proxy : "<null>");

		(void) printf(gettext("\tUse ResponderURI from Certificate: "
		    "%s\n"), plc->VAL_OCSP_BASIC.uri_from_cert ?
		    gettext("true") : gettext("false"));

		(void) printf(gettext("\tResponse lifetime: %s\n"),
		    plc->VAL_OCSP_BASIC.response_lifetime ?
		    plc->VAL_OCSP_BASIC.response_lifetime : "<null>");

		(void) printf(gettext("\tIgnore Response signature: %s\n"),
		    plc->VAL_OCSP_BASIC.ignore_response_sign ?
		    gettext("true") : gettext("false"));

		if (!plc->VAL_OCSP.has_resp_cert) {
			(void) printf(gettext("\tResponder Certificate:"
			    " <null>\n"));
		} else {
			(void) printf(gettext("\tResponder Certificate:\n"));
			(void) printf(gettext("\t\tName: %s\n"),
			    plc->VAL_OCSP_RESP_CERT.name ?
			    plc->VAL_OCSP_RESP_CERT.name : "<null>");
			(void) printf(gettext("\t\tSerial: %s\n"),
			    plc->VAL_OCSP_RESP_CERT.serial ?
			    plc->VAL_OCSP_RESP_CERT.serial : "<null>");
		}
	}

	if (plc->revocation & KMF_REVOCATION_METHOD_CRL) {
		(void) printf(gettext("    CRL:\n"));

		(void) printf(gettext("\tBase filename: %s\n"),
		    plc->validation_info.crl_info.basefilename ?
		    plc->validation_info.crl_info.basefilename : "<null>");

		(void) printf(gettext("\tDirectory: %s\n"),
		    plc->validation_info.crl_info.directory ?
		    plc->validation_info.crl_info.directory : "<null>");

		(void) printf(gettext("\tDownload and cache CRL: %s\n"),
		    plc->validation_info.crl_info.get_crl_uri ?
		    gettext("true") : gettext("false"));

		(void) printf(gettext("\tProxy: %s\n"),
		    plc->validation_info.crl_info.proxy ?
		    plc->validation_info.crl_info.proxy : "<null>");

		(void) printf(gettext("\tIgnore CRL signature: %s\n"),
		    plc->validation_info.crl_info.ignore_crl_sign ?
		    gettext("true") : gettext("false"));

		(void) printf(gettext("\tIgnore CRL validity date: %s\n"),
		    plc->validation_info.crl_info.ignore_crl_date ?
		    gettext("true") : gettext("false"));
	}

	(void) printf("\n");
}

void
show_plugin(void)
{
	conf_entrylist_t *phead = NULL;
	struct stat 	statbuf;

	(void) printf(gettext("KMF plugin information:\n"));
	(void) printf(gettext("-----------------------\n"));

	/* List the built-in plugins */
	(void) printf("pkcs11:kmf_pkcs11.so.1 (built-in)\n");
	(void) printf("file:kmf_openssl.so.1 (built-in)\n");

	/*
	 * If the NSS libraries are not installed in the system,
	 * then we will not show the nss plugin either.
	 */
	if (stat(LIB_NSS_PATH, &statbuf) == 0 &&
	    stat(LIB_NSPR_PATH, &statbuf) == 0) {
		(void) printf("nss:kmf_nss.so.1 (built-in)\n");
	}

	/* List non-default plugins, if there is any. */
	if (get_entrylist(&phead) == KMF_OK) {
		while (phead != NULL) {
			(void) printf("%s:%s", phead->entry->keystore,
			    phead->entry->modulepath);

			if (phead->entry->option == NULL)
				(void) printf("\n");
			else
				(void) printf(";option=%s\n",
				    phead->entry->option);
			phead = phead->next;
		}
		free_entrylist(phead);
	}
}


int
kc_list(int argc, char *argv[])
{
	int 		rv = KC_OK;
	int		opt, found = 0;
	extern int	optind_av;
	extern char	*optarg_av;
	char		*filename = NULL;
	char		*policyname = NULL;
	POLICY_LIST	*plclist = NULL, *pnode;
	int		sanity_err = 0;
	boolean_t	list_plugin = B_FALSE;

	while ((opt = getopt_av(argc, argv, "i:(dbfile)p:(policy)m(plugin)"))
	    != EOF) {
		switch (opt) {
		case 'i':
			if (list_plugin)
				rv = KC_ERR_USAGE;
			else {
				filename = get_string(optarg_av, &rv);
				if (filename == NULL) {
					(void) fprintf(stderr,
					    gettext("Error dbfile input.\n"));
				}
			}
			break;
		case 'p':
			if (list_plugin)
				rv = KC_ERR_USAGE;
			else {
				policyname = get_string(optarg_av, &rv);
				if (policyname == NULL) {
					(void) fprintf(stderr,
					    gettext("Error policy name.\n"));
				}
			}
			break;
		case 'm':
			list_plugin = B_TRUE;
			break;
		default:
			(void) fprintf(stderr,
			    gettext("Error input option.\n"));
			rv = KC_ERR_USAGE;
			break;
		}
		if (rv != KC_OK)
			goto out;
	}

	/* No additional args allowed. */
	argc -= optind_av;
	if (argc) {
		(void) fprintf(stderr,
		    gettext("Error input option\n"));
		rv = KC_ERR_USAGE;
		goto out;
	}

	if (list_plugin) {
		show_plugin();
		goto out;
	}

	if (filename == NULL) {
		filename = strdup(KMF_DEFAULT_POLICY_FILE);
		if (filename == NULL) {
			rv = KC_ERR_MEMORY;
			goto out;
		}
	}

	/* Check the access permission of the policy DB */
	if (access(filename, R_OK) < 0) {
		int err = errno;
		(void) fprintf(stderr,
		    gettext("Cannot access \"%s\" for list - %s\n"), filename,
		    strerror(err));
		rv = KC_ERR_ACCESS;
		goto out;
	}

	rv = load_policies(filename, &plclist);
	if (rv != KMF_OK) {
		goto out;
	}

	pnode = plclist;
	while (pnode != NULL) {
		if (policyname == NULL ||
		    strcmp(policyname, pnode->plc.name) == 0) {
			KMF_POLICY_RECORD *plc = &pnode->plc;

			found++;
			rv = kmf_verify_policy(plc);
			if (rv != KMF_OK) {
				(void) fprintf(stderr, gettext(
				    "Policy Name: '%s' is invalid\n"),
				    plc->name);
				sanity_err++;
			} else {
				show_policy(&pnode->plc);
			}
		}
		pnode = pnode->next;
	}

	free_policy_list(plclist);

	if (!found) {
		if (policyname)
			(void) fprintf(stderr, gettext(
			    "Cannot find policy '%s'\n"), policyname);
		else
			(void) fprintf(stderr, gettext("Cannot find "
			    "any policies to display\n"));
		rv = KC_ERR_FIND_POLICY;
	} else if (sanity_err) {
		rv = KC_ERR_VERIFY_POLICY;
	}

out:

	if (filename != NULL)
		free(filename);

	if (policyname != NULL)
		free(policyname);

	return (rv);
}
