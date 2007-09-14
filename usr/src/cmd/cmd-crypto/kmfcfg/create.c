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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <strings.h>
#include <ctype.h>
#include <libgen.h>
#include <libintl.h>
#include <errno.h>
#include <kmfapiP.h>
#include <cryptoutil.h>
#include "util.h"

int
kc_create(int argc, char *argv[])
{
	KMF_RETURN	ret;
	int 		rv = KC_OK;
	int		opt;
	extern int	optind_av;
	extern char	*optarg_av;
	char		*filename = NULL;
	int		ocsp_set_attr = 0;
	boolean_t	crl_set_attr = 0;
	KMF_POLICY_RECORD plc;

	(void) memset(&plc, 0, sizeof (KMF_POLICY_RECORD));

	while ((opt = getopt_av(argc, argv,
	    "i:(dbfile)"
	    "p:(policy)"
	    "d:(ignore-date)"
	    "e:(ignore-unknown-eku)"
	    "a:(ignore-trust-anchor)"
	    "v:(validity-adjusttime)"
	    "t:(ta-name)"
	    "s:(ta-serial)"
	    "o:(ocsp-responder)"
	    "P:(ocsp-proxy)"
	    "r:(ocsp-use-cert-responder)"
	    "T:(ocsp-response-lifetime)"
	    "R:(ocsp-ignore-response-sign)"
	    "n:(ocsp-responder-cert-name)"
	    "A:(ocsp-responder-cert-serial)"
	    "c:(crl-basefilename)"
	    "I:(crl-directory)"
	    "g:(crl-get-crl-uri)"
	    "X:(crl-proxy)"
	    "S:(crl-ignore-crl-sign)"
	    "D:(crl-ignore-crl-date)"
	    "u:(keyusage)"
	    "E:(ekunames)"
	    "O:(ekuoids)")) != EOF) {
		switch (opt) {
			case 'i':
				filename = get_string(optarg_av, &rv);
				if (filename == NULL) {
					(void) fprintf(stderr,
					    gettext("Error dbfile input.\n"));
				}
				break;
			case 'p':
				plc.name = get_string(optarg_av, &rv);
				if (plc.name == NULL) {
					(void) fprintf(stderr,
					    gettext("Error policy name.\n"));
				}
				break;
			case 'd':
				plc.ignore_date = get_boolean(optarg_av);
				if (plc.ignore_date == -1) {
					(void) fprintf(stderr,
					    gettext("Error boolean input.\n"));
					rv = KC_ERR_USAGE;
				}
				break;
			case 'e':
				plc.ignore_unknown_ekus =
				    get_boolean(optarg_av);
				if (plc.ignore_unknown_ekus == -1) {
					(void) fprintf(stderr,
					    gettext("Error boolean input.\n"));
					rv = KC_ERR_USAGE;
				}
				break;
			case 'a':
				plc.ignore_trust_anchor =
				    get_boolean(optarg_av);
				if (plc.ignore_trust_anchor == -1) {
					(void) fprintf(stderr,
					    gettext("Error boolean input.\n"));
					rv = KC_ERR_USAGE;
				}
				break;
			case 'v':
				plc.validity_adjusttime =
				    get_string(optarg_av, &rv);
				if (plc.validity_adjusttime == NULL) {
					(void) fprintf(stderr,
					    gettext("Error time input.\n"));
				} else {
					uint32_t adj;
					/* for syntax checking */
					if (str2lifetime(
					    plc.validity_adjusttime,
					    &adj) < 0) {
						(void) fprintf(stderr,
						    gettext("Error time "
						    "input.\n"));
						rv = KC_ERR_USAGE;
					}
				}
				break;
			case 't':
				plc.ta_name = get_string(optarg_av, &rv);
				if (plc.ta_name == NULL) {
					(void) fprintf(stderr,
					    gettext("Error name input.\n"));
				} else {
					KMF_X509_NAME taDN;
					/* for syntax checking */
					if (kmf_dn_parser(plc.ta_name,
					    &taDN) != KMF_OK) {
						(void) fprintf(stderr,
						    gettext("Error name "
						    "input.\n"));
						rv = KC_ERR_USAGE;
					} else {
						kmf_free_dn(&taDN);
					}
				}
				break;
			case 's':
				plc.ta_serial = get_string(optarg_av, &rv);
				if (plc.ta_serial == NULL) {
					(void) fprintf(stderr,
					    gettext("Error serial input.\n"));
				} else {
					uchar_t *bytes = NULL;
					size_t bytelen;

					ret = kmf_hexstr_to_bytes(
					    (uchar_t *)plc.ta_serial,
					    &bytes, &bytelen);
					if (ret != KMF_OK || bytes == NULL) {
						(void) fprintf(stderr,
						    gettext("serial number "
						    "must be specified as a "
						    "hex number "
						    "(ex: 0x0102030405"
						    "ffeeddee)\n"));
						rv = KC_ERR_USAGE;
					}
					if (bytes != NULL)
						free(bytes);
				}
				break;
			case 'o':
				plc.VAL_OCSP_RESPONDER_URI =
				    get_string(optarg_av, &rv);
				if (plc.VAL_OCSP_RESPONDER_URI == NULL) {
					(void) fprintf(stderr, gettext(
					    "Error responder input.\n"));
				} else {
					ocsp_set_attr++;
				}
				break;
			case 'P':
				plc.VAL_OCSP_PROXY =
				    get_string(optarg_av, &rv);
				if (plc.VAL_OCSP_PROXY == NULL) {
					(void) fprintf(stderr,
					    gettext("Error proxy input.\n"));
				} else {
					ocsp_set_attr++;
				}
				break;
			case 'r':
				plc.VAL_OCSP_URI_FROM_CERT =
				    get_boolean(optarg_av);
				if (plc.VAL_OCSP_URI_FROM_CERT == -1) {
					(void) fprintf(stderr,
					    gettext("Error boolean input.\n"));
					rv = KC_ERR_USAGE;
				} else {
					ocsp_set_attr++;
				}
				break;
			case 'T':
				plc.VAL_OCSP_RESP_LIFETIME =
				    get_string(optarg_av, &rv);
				if (plc.VAL_OCSP_RESP_LIFETIME == NULL) {
					(void) fprintf(stderr,
					    gettext("Error time input.\n"));
				} else {
					uint32_t adj;
					/* for syntax checking */
					if (str2lifetime(
					    plc.VAL_OCSP_RESP_LIFETIME,
					    &adj) < 0) {
						(void) fprintf(stderr,
						    gettext("Error time "
						    "input.\n"));
						rv = KC_ERR_USAGE;
					} else {
						ocsp_set_attr++;
					}
				}
				break;
			case 'R':
				plc.VAL_OCSP_IGNORE_RESP_SIGN =
				    get_boolean(optarg_av);
				if (plc.VAL_OCSP_IGNORE_RESP_SIGN == -1) {
					(void) fprintf(stderr,
					    gettext("Error boolean input.\n"));
					rv = KC_ERR_USAGE;
				} else {
					ocsp_set_attr++;
				}
				break;
			case 'n':
				plc.VAL_OCSP_RESP_CERT_NAME =
				    get_string(optarg_av, &rv);
				if (plc.VAL_OCSP_RESP_CERT_NAME == NULL) {
					(void) fprintf(stderr,
					    gettext("Error name input.\n"));
				} else {
					KMF_X509_NAME respDN;
					/* for syntax checking */
					if (kmf_dn_parser(
					    plc.VAL_OCSP_RESP_CERT_NAME,
					    &respDN) != KMF_OK) {
						(void) fprintf(stderr,
						    gettext("Error name "
						    "input.\n"));
						rv = KC_ERR_USAGE;
					} else {
						kmf_free_dn(&respDN);
						ocsp_set_attr++;
					}
				}
				break;
			case 'A':
				plc.VAL_OCSP_RESP_CERT_SERIAL =
				    get_string(optarg_av, &rv);
				if (plc.VAL_OCSP_RESP_CERT_SERIAL == NULL) {
					(void) fprintf(stderr,
					    gettext("Error serial input.\n"));
				} else {
					uchar_t *bytes = NULL;
					size_t bytelen;

					ret = kmf_hexstr_to_bytes((uchar_t *)
					    plc.VAL_OCSP_RESP_CERT_SERIAL,
					    &bytes, &bytelen);
					if (ret != KMF_OK || bytes == NULL) {
						(void) fprintf(stderr,
						    gettext("serial number "
						    "must be specified as a "
						    "hex number "
						    "(ex: 0x0102030405"
						    "ffeeddee)\n"));
						rv = KC_ERR_USAGE;
						break;
					}
					if (bytes != NULL)
						free(bytes);
					ocsp_set_attr++;
				}
				break;
			case 'c':
				plc.VAL_CRL_BASEFILENAME =
				    get_string(optarg_av, &rv);
				if (plc.VAL_CRL_BASEFILENAME == NULL) {
					(void) fprintf(stderr,
					    gettext("Error boolean input.\n"));
				} else {
					crl_set_attr++;
				}
				break;
			case 'I':
				plc.VAL_CRL_DIRECTORY =
				    get_string(optarg_av, &rv);
				if (plc.VAL_CRL_DIRECTORY == NULL) {
					(void) fprintf(stderr,
					    gettext("Error boolean input.\n"));
				} else {
					crl_set_attr++;
				}
				break;
			case 'g':
				plc.VAL_CRL_GET_URI = get_boolean(optarg_av);
				if (plc.VAL_CRL_GET_URI == -1) {
					(void) fprintf(stderr,
					    gettext("Error boolean input.\n"));
					rv = KC_ERR_USAGE;
				} else {
					crl_set_attr++;
				}
				break;
			case 'X':
				plc.VAL_CRL_PROXY = get_string(optarg_av, &rv);
				if (plc.VAL_CRL_PROXY == NULL) {
					(void) fprintf(stderr,
					    gettext("Error proxy input.\n"));
				} else {
					crl_set_attr++;
				}
				break;
			case 'S':
				plc.VAL_CRL_IGNORE_SIGN =
				    get_boolean(optarg_av);
				if (plc.VAL_CRL_IGNORE_SIGN == -1) {
					(void) fprintf(stderr,
					    gettext("Error boolean input.\n"));
					rv = KC_ERR_USAGE;
				} else {
					crl_set_attr++;
				}
				break;
			case 'D':
				plc.VAL_CRL_IGNORE_DATE =
				    get_boolean(optarg_av);
				if (plc.VAL_CRL_IGNORE_DATE == -1) {
					(void) fprintf(stderr,
					    gettext("Error boolean input.\n"));
					rv = KC_ERR_USAGE;
				} else {
					crl_set_attr++;
				}
				break;
			case 'u':
				plc.ku_bits = parseKUlist(optarg_av);
				if (plc.ku_bits == 0) {
					(void) fprintf(stderr, gettext(
					    "Error keyusage input.\n"));
					rv = KC_ERR_USAGE;
				}
				break;
			case 'E':
				if (parseEKUNames(optarg_av, &plc) != 0) {
					(void) fprintf(stderr,
					    gettext("Error EKU input.\n"));
					rv = KC_ERR_USAGE;
				}
				break;
			case 'O':
				if (parseEKUOIDs(optarg_av, &plc) != 0) {
					(void) fprintf(stderr,
					    gettext("Error EKU OID input.\n"));
					rv = KC_ERR_USAGE;
				}
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

	if (filename == NULL) {
		filename = strdup(KMF_DEFAULT_POLICY_FILE);
		if (filename == NULL) {
			rv = KC_ERR_MEMORY;
			goto out;
		}
	}

	/*
	 * Must have a policy name. The policy name can not be default
	 * if using the default policy file.
	 */
	if (plc.name == NULL) {
		(void) fprintf(stderr,
		    gettext("You must specify a policy name\n"));
		rv = KC_ERR_USAGE;
		goto out;
	} else if (strcmp(filename, KMF_DEFAULT_POLICY_FILE) == 0 &&
	    strcmp(plc.name, KMF_DEFAULT_POLICY_NAME) == 0) {
		(void) fprintf(stderr,
		    gettext("Can not create a default policy in the default "
		    "policy file\n"));
		rv = KC_ERR_USAGE;
		goto out;
	}

	/*
	 * If the policy file exists and the policy is in the policy file
	 * already, we will not create it again.
	 */
	if (access(filename, R_OK) == 0) {
		POLICY_LIST *plclist = NULL, *pnode;
		int found = 0;

		rv = load_policies(filename, &plclist);
		if (rv != KMF_OK)
			goto out;

		pnode = plclist;
		while (pnode != NULL && !found) {
			if (strcmp(plc.name, pnode->plc.name) == 0)
				found++;
			pnode = pnode->next;
		}
		free_policy_list(plclist);

		if (found) {
			(void) fprintf(stderr,
			    gettext("Could not create policy \"%s\" - exists "
			    "already\n"), plc.name);
			rv = KC_ERR_USAGE;
			goto out;
		}
	}

	/*
	 * If any OCSP attribute is set, turn on the OCSP checking flag.
	 * Also set "has_resp_cert" to be true, if the responder cert
	 * is provided.
	 */
	if (ocsp_set_attr > 0)
		plc.revocation |= KMF_REVOCATION_METHOD_OCSP;

	if (plc.VAL_OCSP_RESP_CERT.name != NULL &&
	    plc.VAL_OCSP_RESP_CERT.serial != NULL) {
		plc.VAL_OCSP.has_resp_cert = B_TRUE;
	}

	/*
	 * If any CRL attribute is set, turn on the CRL checking flag.
	 */
	if (crl_set_attr > 0)
		plc.revocation |= KMF_REVOCATION_METHOD_CRL;

	/*
	 * Does a sanity check on the new policy.
	 */
	ret = kmf_verify_policy(&plc);
	if (ret != KMF_OK) {
		print_sanity_error(ret);
		rv = KC_ERR_ADD_POLICY;
		goto out;
	}

	/*
	 * Add to the DB.
	 */
	ret = kmf_add_policy_to_db(&plc, filename, B_FALSE);
	if (ret != KMF_OK) {
		(void) fprintf(stderr,
		    gettext("Error adding policy to database: 0x%04x\n"), ret);
		rv = KC_ERR_ADD_POLICY;
	}

out:
	if (filename != NULL)
		free(filename);

	kmf_free_policy_record(&plc);

	return (rv);
}
