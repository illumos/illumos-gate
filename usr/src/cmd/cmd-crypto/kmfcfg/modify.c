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
#include <sys/stat.h>
#include <sys/param.h>
#include "util.h"

#define	KC_IGNORE_DATE			0x0000001
#define	KC_IGNORE_UNKNOWN_EKUS		0x0000002
#define	KC_IGNORE_TRUST_ANCHOR		0x0000004
#define	KC_VALIDITY_ADJUSTTIME		0x0000008
#define	KC_TA_NAME			0x0000010
#define	KC_TA_SERIAL			0x0000020
#define	KC_OCSP_RESPONDER_URI		0x0000040
#define	KC_OCSP_PROXY			0x0000080
#define	KC_OCSP_URI_FROM_CERT		0x0000100
#define	KC_OCSP_RESP_LIFETIME		0x0000200
#define	KC_OCSP_IGNORE_RESP_SIGN 	0x0000400
#define	KC_OCSP_RESP_CERT_NAME		0x0000800
#define	KC_OCSP_RESP_CERT_SERIAL	0x0001000
#define	KC_OCSP_NONE			0x0002000
#define	KC_CRL_BASEFILENAME		0x0004000
#define	KC_CRL_DIRECTORY		0x0008000
#define	KC_CRL_GET_URI			0x0010000
#define	KC_CRL_PROXY			0x0020000
#define	KC_CRL_IGNORE_SIGN		0x0040000
#define	KC_CRL_IGNORE_DATE		0x0080000
#define	KC_CRL_NONE			0x0100000
#define	KC_KEYUSAGE			0x0200000
#define	KC_KEYUSAGE_NONE		0x0400000
#define	KC_EKUS				0x0800000
#define	KC_EKUS_NONE			0x1000000

static int err; /* To store errno which may be overwritten by gettext() */


int
kc_modify_policy(int argc, char *argv[])
{
	KMF_RETURN	ret;
	int 		rv = KC_OK;
	int		opt;
	extern int	optind_av;
	extern char	*optarg_av;
	char		*filename = NULL;
	uint32_t	flags = 0;
	boolean_t	ocsp_none_opt = B_FALSE;
	boolean_t	crl_none_opt = B_FALSE;
	boolean_t	ku_none_opt = B_FALSE;
	boolean_t	eku_none_opt = B_FALSE;
	int		ocsp_set_attr = 0;
	int		crl_set_attr = 0;
	KMF_POLICY_RECORD oplc, plc;

	(void) memset(&plc, 0, sizeof (KMF_POLICY_RECORD));
	(void) memset(&oplc, 0, sizeof (KMF_POLICY_RECORD));

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
	    "y:(ocsp-none)"
	    "c:(crl-basefilename)"
	    "I:(crl-directory)"
	    "g:(crl-get-crl-uri)"
	    "X:(crl-proxy)"
	    "S:(crl-ignore-crl-sign)"
	    "D:(crl-ignore-crl-date)"
	    "z:(crl-none)"
	    "u:(keyusage)"
	    "Y:(keyusage-none)"
	    "E:(ekunames)"
	    "O:(ekuoids)"
	    "Z:(eku-none)")) != EOF) {
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
				} else {
					flags |= KC_IGNORE_DATE;
				}
				break;
			case 'e':
				plc.ignore_unknown_ekus =
				    get_boolean(optarg_av);
				if (plc.ignore_unknown_ekus == -1) {
					(void) fprintf(stderr,
					    gettext("Error boolean input.\n"));
					rv = KC_ERR_USAGE;
				} else {
					flags |= KC_IGNORE_UNKNOWN_EKUS;
				}
				break;
			case 'a':
				plc.ignore_trust_anchor =
				    get_boolean(optarg_av);
				if (plc.ignore_trust_anchor == -1) {
					(void) fprintf(stderr,
					    gettext("Error boolean input.\n"));
					rv = KC_ERR_USAGE;
				} else {
					flags |= KC_IGNORE_TRUST_ANCHOR;
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
					} else {
						flags |= KC_VALIDITY_ADJUSTTIME;
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
						flags |= KC_TA_NAME;
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
						break;
					}
					if (bytes != NULL)
						free(bytes);
					flags |= KC_TA_SERIAL;
				}
				break;
			case 'o':
				plc.VAL_OCSP_RESPONDER_URI =
				    get_string(optarg_av, &rv);
				if (plc.VAL_OCSP_RESPONDER_URI == NULL) {
					(void) fprintf(stderr,
					    gettext("Error responder "
					    "input.\n"));
				} else {
					flags |= KC_OCSP_RESPONDER_URI;
					ocsp_set_attr++;
				}
				break;
			case 'P':
				plc.VAL_OCSP_PROXY = get_string(optarg_av, &rv);
				if (plc.VAL_OCSP_PROXY == NULL) {
					(void) fprintf(stderr,
					    gettext("Error proxy input.\n"));
				} else {
					flags |= KC_OCSP_PROXY;
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
					flags |= KC_OCSP_URI_FROM_CERT;
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
						flags |= KC_OCSP_RESP_LIFETIME;
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
					flags |= KC_OCSP_IGNORE_RESP_SIGN;
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
						flags |= KC_OCSP_RESP_CERT_NAME;
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
					flags |= KC_OCSP_RESP_CERT_SERIAL;
					ocsp_set_attr++;
				}
				break;
			case 'y':
				ocsp_none_opt = get_boolean(optarg_av);
				if (ocsp_none_opt == -1) {
					(void) fprintf(stderr,
					    gettext("Error boolean input.\n"));
					rv = KC_ERR_USAGE;
				} else {
					flags |= KC_OCSP_NONE;
				}
				break;
			case 'c':
				plc.VAL_CRL_BASEFILENAME =
				    get_string(optarg_av, &rv);
				if (plc.VAL_CRL_BASEFILENAME == NULL) {
					(void) fprintf(stderr, gettext(
					    "Error basefilename input.\n"));
				} else {
					flags |= KC_CRL_BASEFILENAME;
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
					flags |= KC_CRL_DIRECTORY;
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
					flags |= KC_CRL_GET_URI;
					crl_set_attr++;
				}
				break;
			case 'X':
				plc.VAL_CRL_PROXY = get_string(optarg_av, &rv);
				if (plc.VAL_CRL_PROXY == NULL) {
					(void) fprintf(stderr,
					    gettext("Error proxy input.\n"));
				} else {
					flags |= KC_CRL_PROXY;
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
					flags |= KC_CRL_IGNORE_SIGN;
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
					flags |= KC_CRL_IGNORE_DATE;
					crl_set_attr++;
				}
				break;
			case 'z':
				crl_none_opt = get_boolean(optarg_av);
				if (crl_none_opt == -1) {
					(void) fprintf(stderr,
					    gettext("Error boolean input.\n"));
					rv = KC_ERR_USAGE;
				} else {
					flags |= KC_CRL_NONE;
				}
				break;
			case 'u':
				plc.ku_bits = parseKUlist(optarg_av);
				if (plc.ku_bits == 0) {
					(void) fprintf(stderr, gettext(
					    "Error keyusage input.\n"));
					rv = KC_ERR_USAGE;
				} else {
					flags |= KC_KEYUSAGE;
				}
				break;
			case 'Y':
				ku_none_opt = get_boolean(optarg_av);
				if (ku_none_opt == -1) {
					(void) fprintf(stderr,
					    gettext("Error boolean input.\n"));
					rv = KC_ERR_USAGE;
				} else {
					flags |= KC_KEYUSAGE_NONE;
				}
				break;
			case 'E':
				if (parseEKUNames(optarg_av, &plc) != 0) {
					(void) fprintf(stderr,
					    gettext("Error EKU input.\n"));
					rv = KC_ERR_USAGE;
				} else {
					flags |= KC_EKUS;
				}
				break;
			case 'O':
				if (parseEKUOIDs(optarg_av, &plc) != 0) {
					(void) fprintf(stderr,
					    gettext("Error EKU OID input.\n"));
					rv = KC_ERR_USAGE;
				} else {
					flags |= KC_EKUS;
				}
				break;
			case 'Z':
				eku_none_opt = get_boolean(optarg_av);
				if (eku_none_opt == -1) {
					(void) fprintf(stderr,
					    gettext("Error boolean input.\n"));
					rv = KC_ERR_USAGE;
				} else {
					flags |= KC_EKUS_NONE;
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
		    gettext("You must specify a policy name.\n"));
		rv = KC_ERR_USAGE;
		goto out;
	} else if (strcmp(filename, KMF_DEFAULT_POLICY_FILE) == 0 &&
	    strcmp(plc.name, KMF_DEFAULT_POLICY_NAME) == 0) {
		(void) fprintf(stderr,
		    gettext("Can not modify the default policy in the default "
		    "policy file.\n"));
		rv = KC_ERR_USAGE;
		goto out;
	}

	/* Check the access permission of the policy DB */
	if (access(filename, W_OK) < 0) {
		int err = errno;
		(void) fprintf(stderr,
		    gettext("Cannot access \"%s\" for modify - %s\n"),
		    filename, strerror(err));
		rv = KC_ERR_ACCESS;
		goto out;
	}

	/* Try to load the named policy from the DB */
	ret = kmf_get_policy(filename, plc.name, &oplc);
	if (ret != KMF_OK) {
		(void) fprintf(stderr,
		    gettext("Error loading policy \"%s\" from %s\n"), filename,
		    plc.name);
		return (KC_ERR_FIND_POLICY);
	}

	/* Update the general policy attributes. */
	if (flags & KC_IGNORE_DATE)
		oplc.ignore_date = plc.ignore_date;

	if (flags & KC_IGNORE_UNKNOWN_EKUS)
		oplc.ignore_unknown_ekus = plc.ignore_unknown_ekus;

	if (flags & KC_IGNORE_TRUST_ANCHOR)
		oplc.ignore_trust_anchor = plc.ignore_trust_anchor;

	if (flags & KC_VALIDITY_ADJUSTTIME) {
		if (oplc.validity_adjusttime)
			free(oplc.validity_adjusttime);
		oplc.validity_adjusttime =
		    plc.validity_adjusttime;
	}

	if (flags & KC_TA_NAME) {
		if (oplc.ta_name)
			free(oplc.ta_name);
		oplc.ta_name = plc.ta_name;
	}
	if (flags & KC_TA_SERIAL) {
		if (oplc.ta_serial)
			free(oplc.ta_serial);
		oplc.ta_serial = plc.ta_serial;
	}

	/* Update the OCSP policy */
	if (ocsp_none_opt == B_TRUE) {
		if (ocsp_set_attr > 0) {
			(void) fprintf(stderr,
			    gettext("Can not set ocsp-none=true and other "
			    "OCSP attributes at the same time.\n"));
			rv = KC_ERR_USAGE;
			goto out;
		}

		/*
		 * If the original policy does not have OCSP checking,
		 * then we do not need to do anything.  If the original
		 * policy has the OCSP checking, then we need to release the
		 * space of OCSP attributes and turn the OCSP checking off.
		 */
		if (oplc.revocation & KMF_REVOCATION_METHOD_OCSP) {
			if (oplc.VAL_OCSP_BASIC.responderURI) {
				free(oplc.VAL_OCSP_BASIC.responderURI);
				oplc.VAL_OCSP_BASIC.responderURI = NULL;
			}

			if (oplc.VAL_OCSP_BASIC.proxy) {
				free(oplc.VAL_OCSP_BASIC.proxy);
				oplc.VAL_OCSP_BASIC.proxy = NULL;
			}

			if (oplc.VAL_OCSP_BASIC.response_lifetime) {
				free(oplc.VAL_OCSP_BASIC.response_lifetime);
				oplc.VAL_OCSP_BASIC.response_lifetime = NULL;
			}

			if (flags & KC_OCSP_RESP_CERT_NAME) {
				free(oplc.VAL_OCSP_RESP_CERT.name);
				oplc.VAL_OCSP_RESP_CERT.name = NULL;
			}

			if (flags & KC_OCSP_RESP_CERT_SERIAL) {
				free(oplc.VAL_OCSP_RESP_CERT.serial);
				oplc.VAL_OCSP_RESP_CERT.serial = NULL;
			}

			/* Turn off the OCSP checking */
			oplc.revocation &= ~KMF_REVOCATION_METHOD_OCSP;
		}

	} else {
		/*
		 * If the "ocsp-none" option is not set or is set to false,
		 * then we only need to do the modification if there is at
		 * least one OCSP attribute is specified.
		 */
		if (ocsp_set_attr > 0) {
			if (flags & KC_OCSP_RESPONDER_URI) {
				if (oplc.VAL_OCSP_RESPONDER_URI)
					free(oplc.VAL_OCSP_RESPONDER_URI);
				oplc.VAL_OCSP_RESPONDER_URI =
				    plc.VAL_OCSP_RESPONDER_URI;
			}

			if (flags & KC_OCSP_PROXY) {
				if (oplc.VAL_OCSP_PROXY)
					free(oplc.VAL_OCSP_PROXY);
				oplc.VAL_OCSP_PROXY = plc.VAL_OCSP_PROXY;
			}

			if (flags & KC_OCSP_URI_FROM_CERT)
				oplc.VAL_OCSP_URI_FROM_CERT =
				    plc.VAL_OCSP_URI_FROM_CERT;

			if (flags & KC_OCSP_RESP_LIFETIME) {
				if (oplc.VAL_OCSP_RESP_LIFETIME)
					free(oplc.VAL_OCSP_RESP_LIFETIME);
				oplc.VAL_OCSP_RESP_LIFETIME =
				    plc.VAL_OCSP_RESP_LIFETIME;
			}

			if (flags & KC_OCSP_IGNORE_RESP_SIGN)
				oplc.VAL_OCSP_IGNORE_RESP_SIGN =
				    plc.VAL_OCSP_IGNORE_RESP_SIGN;

			if (flags & KC_OCSP_RESP_CERT_NAME) {
				if (oplc.VAL_OCSP_RESP_CERT_NAME)
					free(oplc.VAL_OCSP_RESP_CERT_NAME);
				oplc.VAL_OCSP_RESP_CERT_NAME =
				    plc.VAL_OCSP_RESP_CERT_NAME;
			}

			if (flags & KC_OCSP_RESP_CERT_SERIAL) {
				if (oplc.VAL_OCSP_RESP_CERT_SERIAL)
					free(oplc.VAL_OCSP_RESP_CERT_SERIAL);
				oplc.VAL_OCSP_RESP_CERT_SERIAL =
				    plc.VAL_OCSP_RESP_CERT_SERIAL;
			}

			if (oplc.VAL_OCSP_RESP_CERT_NAME != NULL &&
			    oplc.VAL_OCSP_RESP_CERT_SERIAL != NULL)
				oplc.VAL_OCSP.has_resp_cert = B_TRUE;
			else
				oplc.VAL_OCSP.has_resp_cert = B_FALSE;

			/* Turn on the OCSP checking */
			oplc.revocation |= KMF_REVOCATION_METHOD_OCSP;
		}
	}

	/* Update the CRL policy */
	if (crl_none_opt == B_TRUE) {
		if (crl_set_attr > 0) {
			(void) fprintf(stderr,
			    gettext("Can not set crl-none=true and other CRL "
			    "attributes at the same time.\n"));
			rv = KC_ERR_USAGE;
			goto out;
		}

		/*
		 * If the original policy does not have CRL checking,
		 * then we do not need to do anything.  If the original
		 * policy has the CRL checking, then we need to release the
		 * space of CRL attributes and turn the CRL checking off.
		 */
		if (oplc.revocation & KMF_REVOCATION_METHOD_CRL) {
			if (oplc.VAL_CRL_BASEFILENAME) {
				free(oplc.VAL_CRL_BASEFILENAME);
				oplc.VAL_CRL_BASEFILENAME = NULL;
			}

			if (oplc.VAL_CRL_DIRECTORY) {
				free(oplc.VAL_CRL_DIRECTORY);
				oplc.VAL_CRL_DIRECTORY = NULL;
			}

			if (oplc.VAL_CRL_PROXY) {
				free(oplc.VAL_CRL_PROXY);
				oplc.VAL_CRL_PROXY = NULL;
			}

			/* Turn off the CRL checking */
			oplc.revocation &= ~KMF_REVOCATION_METHOD_CRL;
		}
	} else {
		/*
		 * If the "ocsp-none" option is not set or is set to false,
		 * then we only need to do the modification if there is at
		 * least one CRL attribute is specified.
		 */
		if (crl_set_attr > 0) {
			if (flags & KC_CRL_BASEFILENAME) {
				if (oplc.VAL_CRL_BASEFILENAME)
					free(oplc.VAL_CRL_BASEFILENAME);
				oplc.VAL_CRL_BASEFILENAME =
				    plc.VAL_CRL_BASEFILENAME;
			}

			if (flags & KC_CRL_DIRECTORY) {
				if (oplc.VAL_CRL_DIRECTORY)
					free(oplc.VAL_CRL_DIRECTORY);
				oplc.VAL_CRL_DIRECTORY = plc.VAL_CRL_DIRECTORY;
			}

			if (flags & KC_CRL_GET_URI) {
				oplc.VAL_CRL_GET_URI = plc.VAL_CRL_GET_URI;
			}

			if (flags & KC_CRL_PROXY) {
				if (oplc.VAL_CRL_PROXY)
					free(oplc.VAL_CRL_PROXY);
				oplc.VAL_CRL_PROXY = plc.VAL_CRL_PROXY;
			}

			if (flags & KC_CRL_IGNORE_SIGN) {
				oplc.VAL_CRL_IGNORE_SIGN =
				    plc.VAL_CRL_IGNORE_SIGN;
			}

			if (flags & KC_CRL_IGNORE_DATE) {
				oplc.VAL_CRL_IGNORE_DATE =
				    plc.VAL_CRL_IGNORE_DATE;
			}

			/* Turn on the CRL checking */
			oplc.revocation |= KMF_REVOCATION_METHOD_CRL;
		}
	}

	/* Update the Key Usage */
	if (ku_none_opt == B_TRUE) {
		if (flags & KC_KEYUSAGE) {
			(void) fprintf(stderr,
			    gettext("Can not set keyusage-none=true and "
			    "modify the keyusage value at the same time.\n"));
			rv = KC_ERR_USAGE;
			goto out;
		}

		oplc.ku_bits = 0;
	} else {
		/*
		 * If the "keyusage-none" option is not set or is set to
		 * false, then we only need to do the modification if
		 * the keyusage value is specified.
		 */
		if (flags & KC_KEYUSAGE)
			oplc.ku_bits = plc.ku_bits;
	}


	/* Update the Extended Key Usage */
	if (eku_none_opt == B_TRUE) {
		if (flags & KC_EKUS) {
			(void) fprintf(stderr,
			    gettext("Can not set eku-none=true and modify "
			    "EKU values at the same time.\n"));
			rv = KC_ERR_USAGE;
			goto out;
		}

		/* Release current EKU list (if any) */
		if (oplc.eku_set.eku_count > 0) {
			kmf_free_eku_policy(&oplc.eku_set);
			oplc.eku_set.eku_count = 0;
			oplc.eku_set.ekulist = NULL;
		}
	} else {
		/*
		 * If the "eku-none" option is not set or is set to false,
		 * then we only need to do the modification if either
		 * "ekuname" or "ekuoids" is specified.
		 */
		if (flags & KC_EKUS) {
			/* Release current EKU list (if any) */
			kmf_free_eku_policy(&oplc.eku_set);
			oplc.eku_set = plc.eku_set;
		}
	}

	/* Do a sanity check on the modified policy */
	ret = kmf_verify_policy(&oplc);
	if (ret != KMF_OK) {
		print_sanity_error(ret);
		rv = KC_ERR_VERIFY_POLICY;
		goto out;
	}

	/* The modify operation is a delete followed by an add */
	ret = kmf_delete_policy_from_db(oplc.name, filename);
	if (ret != KMF_OK) {
		rv = KC_ERR_DELETE_POLICY;
		goto out;
	}

	/*
	 * Now add the modified policy back to the DB.
	 */
	ret = kmf_add_policy_to_db(&oplc, filename, B_FALSE);
	if (ret != KMF_OK) {
		(void) fprintf(stderr,
		    gettext("Error adding policy to database: 0x%04x\n"), ret);
		rv = KC_ERR_ADD_POLICY;
		goto out;
	}

out:
	if (filename != NULL)
		free(filename);

	kmf_free_policy_record(&oplc);

	return (rv);
}


static int
kc_modify_plugin(int argc, char *argv[])
{
	int 		rv = KC_OK;
	int		opt;
	extern int	optind_av;
	extern char	*optarg_av;
	char 		*keystore_name = NULL;
	char		*option = NULL;
	boolean_t	modify_plugin = B_FALSE;
	boolean_t 	has_option_arg = B_FALSE;
	conf_entry_t	*entry = NULL;
	FILE		*pfile = NULL;
	FILE		*pfile_tmp = NULL;
	char		tmpfile_name[MAXPATHLEN];
	char 		buffer[MAXPATHLEN];
	char 		buffer2[MAXPATHLEN];

	while ((opt = getopt_av(argc, argv, "p(plugin)k:(keystore)o:(option)"))
	    != EOF) {
		switch (opt) {
		case 'p':
			if (modify_plugin) {
				(void) fprintf(stderr,
				    gettext("duplicate plugin input.\n"));
				rv = KC_ERR_USAGE;
			} else {
				modify_plugin = B_TRUE;
			}
			break;
		case 'k':
			if (keystore_name != NULL)
				rv = KC_ERR_USAGE;
			else {
				keystore_name = get_string(optarg_av, &rv);
				if (keystore_name == NULL) {
					(void) fprintf(stderr, gettext(
					    "Error keystore input.\n"));
					rv = KC_ERR_USAGE;
				}
			}
			break;
		case 'o':
			if (has_option_arg) {
				(void) fprintf(stderr,
				    gettext("duplicate option input.\n"));
				rv = KC_ERR_USAGE;
			} else {
				has_option_arg = B_TRUE;
				option = get_string(optarg_av, NULL);
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

	if (keystore_name == NULL || has_option_arg == B_FALSE) {
		(void) fprintf(stderr,
		    gettext("Error input option\n"));
		rv = KC_ERR_USAGE;
		goto out;
	}

	if (strcasecmp(keystore_name, "nss") == 0 ||
	    strcasecmp(keystore_name, "pkcs11") == 0 ||
	    strcasecmp(keystore_name, "file") == 0) {
		(void) fprintf(stderr,
		    gettext("Can not modify the built-in keystore %s\n"),
		    keystore_name);
		rv = KC_ERR_USAGE;
		goto out;
	}

	entry = get_keystore_entry(keystore_name);
	if (entry == NULL) {
		(void) fprintf(stderr, gettext("%s does not exist.\n"),
		    keystore_name);
		rv = KC_ERR_USAGE;
		goto out;
	}

	if ((entry->option == NULL && option == NULL) ||
	    (entry->option != NULL && option != NULL &&
	    strcmp(entry->option, option) == 0)) {
		(void) fprintf(stderr, gettext("No change - "
		    "the new option is same as the old option.\n"));
		rv = KC_OK;
		goto out;
	}

	if ((pfile = fopen(_PATH_KMF_CONF, "r+")) == NULL) {
		err = errno;
		(void) fprintf(stderr,
		    gettext("failed to update the configuration - %s\n"),
		    strerror(err));
		rv = KC_ERR_ACCESS;
		goto out;
	}

	if (lockf(fileno(pfile), F_TLOCK, 0) == -1) {
		err = errno;
		(void) fprintf(stderr,
		    gettext("failed to lock the configuration - %s\n"),
		    strerror(err));
		rv = KC_ERR_MODIFY_PLUGIN;
		goto out;
	}

	/*
	 * Create a temporary file in the /etc/crypto directory.
	 */
	(void) strlcpy(tmpfile_name, CONF_TEMPFILE, sizeof (tmpfile_name));
	if (mkstemp(tmpfile_name) == -1) {
		err = errno;
		(void) fprintf(stderr,
		    gettext("failed to create a temporary file - %s\n"),
		    strerror(err));
		rv = KC_ERR_MODIFY_PLUGIN;
		goto out;
	}

	if ((pfile_tmp = fopen(tmpfile_name, "w")) == NULL) {
		err = errno;
		(void) fprintf(stderr,
		    gettext("failed to open %s - %s\n"),
		    tmpfile_name, strerror(err));
		rv = KC_ERR_MODIFY_PLUGIN;
		goto out;
	}

	/*
	 * Loop thru the config file and update the entry.
	 */
	while (fgets(buffer, MAXPATHLEN, pfile) != NULL) {
		char *name;
		int len;

		if (buffer[0] == '#') {
			if (fputs(buffer, pfile_tmp) == EOF) {
				rv = KC_ERR_MODIFY_PLUGIN;
				goto out;
			} else {
				continue;
			}
		}

		/*
		 * make a copy of the original buffer to buffer2.  Also get
		 * rid of the trailing '\n' from buffer2.
		 */
		(void) strlcpy(buffer2, buffer, MAXPATHLEN);
		len = strlen(buffer2);
		if (buffer2[len-1] == '\n') {
			len--;
		}
		buffer2[len] = '\0';

		if ((name = strtok(buffer2, SEP_COLON)) == NULL) {
			rv = KC_ERR_UNINSTALL;
			goto out;
		}

		if (strcmp(name, keystore_name) == 0) {
			/* found the entry */
			if (option == NULL)
				(void) snprintf(buffer, MAXPATHLEN,
				    "%s:%s%s\n", keystore_name,
				    CONF_MODULEPATH, entry->modulepath);
			else
				(void) snprintf(buffer, MAXPATHLEN,
				    "%s:%s%s;%s%s\n", keystore_name,
				    CONF_MODULEPATH, entry->modulepath,
				    CONF_OPTION, option);

			if (fputs(buffer, pfile_tmp) == EOF) {
				err = errno;
				(void) fprintf(stderr, gettext(
				    "failed to write to %s: %s\n"),
				    tmpfile_name, strerror(err));
				rv = KC_ERR_MODIFY_PLUGIN;
				goto out;
			}
		} else {

			if (fputs(buffer, pfile_tmp) == EOF) {
				rv = KC_ERR_UNINSTALL;
				goto out;
			}
		}
	}

	if (rename(tmpfile_name, _PATH_KMF_CONF) == -1) {
		err = errno;
		(void) fprintf(stderr, gettext(
		    "failed to update the configuration - %s"), strerror(err));
		rv = KC_ERR_MODIFY_PLUGIN;
		goto out;
	}

	if (chmod(_PATH_KMF_CONF,
	    S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH) == -1) {
		err = errno;
		(void) fprintf(stderr, gettext(
		    "failed to update the configuration - %s\n"),
		    strerror(err));
		rv = KC_ERR_MODIFY_PLUGIN;
		goto out;
	}

out:
	if (entry != NULL)
		free_entry(entry);

	if (pfile != NULL)
		(void) fclose(pfile);

	if (rv != KC_OK && pfile_tmp != NULL)
		(void) unlink(tmpfile_name);

	if (pfile_tmp != NULL)
		(void) fclose(pfile_tmp);

	return (rv);
}


int
kc_modify(int argc, char *argv[])
{
	if (argc > 2 &&
	    strcmp(argv[0], "modify") == 0 &&
	    strcmp(argv[1], "plugin") == 0) {
		return (kc_modify_plugin(argc, argv));
	} else {
		return (kc_modify_policy(argc, argv));
	}
}
