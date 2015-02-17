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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <malloc.h>
#include <libgen.h>
#include <fcntl.h>
#include <errno.h>
#include <cryptoutil.h>
#include "common.h"
#include <kmfapi.h>

int
pk_download(int argc, char *argv[])
{
	int rv;
	int opt;
	extern int	optind_av;
	extern char	*optarg_av;
	int oclass = 0;
	char *url = NULL;
	char *http_proxy = NULL;
	char *dir = NULL;
	char *outfile = NULL;
	char *proxy = NULL;
	int  proxy_port = 0;
	KMF_HANDLE_T	kmfhandle = NULL;
	KMF_ENCODE_FORMAT format;
	KMF_RETURN ch_rv = KMF_OK;
	char *fullpath = NULL;
	KMF_DATA cert = { 0, NULL };
	KMF_DATA cert_der = { 0, NULL };

	while ((opt = getopt_av(argc, argv,
	    "t:(objtype)u:(url)h:(http_proxy)o:(outfile)d:(dir)")) != EOF) {

		if (EMPTYSTRING(optarg_av))
			return (PK_ERR_USAGE);
		switch (opt) {
		case 't':
			if (oclass)
				return (PK_ERR_USAGE);
			oclass = OT2Int(optarg_av);
			if (!(oclass & (PK_CERT_OBJ | PK_CRL_OBJ)))
				return (PK_ERR_USAGE);
			break;
		case 'u':
			if (url)
				return (PK_ERR_USAGE);
			url = optarg_av;
			break;
		case 'h':
			if (http_proxy)
				return (PK_ERR_USAGE);
			http_proxy = optarg_av;
			break;
		case 'o':
			if (outfile)
				return (PK_ERR_USAGE);
			outfile = optarg_av;
			break;
		case 'd':
			if (dir)
				return (PK_ERR_USAGE);
			dir = optarg_av;
			break;
		default:
			cryptoerror(LOG_STDERR, gettext(
			    "unrecognized download option '%s'\n"),
			    argv[optind_av]);
			return (PK_ERR_USAGE);
		}
	}

	/* No additional args allowed. */
	argc -= optind_av;
	argv += optind_av;
	if (argc) {
		return (PK_ERR_USAGE);
	}

	/* Check the dir and outfile options */
	if (outfile == NULL) {
		/* If outfile is not specified, use the basename of URI */
		outfile = basename(url);
	}

	fullpath = get_fullpath(dir, outfile);
	if (fullpath == NULL) {
		cryptoerror(LOG_STDERR, gettext("Incorrect dir or outfile "
		    "option value \n"));
		return (PK_ERR_USAGE);
	}
	/* Check if the file exists and might be overwritten. */
	if (verify_file(fullpath) != KMF_OK) {
		cryptoerror(LOG_STDERR,
		    gettext("Warning: file \"%s\" exists, "
		    "will be overwritten."), fullpath);
		if (yesno(gettext("Continue with download? "),
		    gettext("Respond with yes or no.\n"), B_FALSE) == B_FALSE) {
			return (0);
		}
	}
	/* URI MUST be specified */
	if (url == NULL) {
		cryptoerror(LOG_STDERR, gettext("A URL must be specified\n"));
		rv = PK_ERR_USAGE;
		goto end;
	}

	/*
	 * Get the http proxy from the command "http_proxy" option or the
	 * environment variable.  The command option has a higher priority.
	 */
	if (http_proxy == NULL)
		http_proxy = getenv("http_proxy");

	if (http_proxy != NULL) {
		char *ptmp = http_proxy;
		char *proxy_port_s;

		if (strncasecmp(ptmp, "http://", 7) == 0)
			ptmp += 7;	/* skip the scheme prefix */

		proxy = strtok(ptmp, ":");
		proxy_port_s = strtok(NULL, "\0");
		if (proxy_port_s != NULL)
			proxy_port = strtol(proxy_port_s, NULL, 0);
		else
			proxy_port = 8080;
	}

	/* If objtype is not specified, default to CRL */
	if (oclass == 0) {
		oclass = PK_CRL_OBJ;
	}

	if ((rv = kmf_initialize(&kmfhandle, NULL, NULL)) != KMF_OK) {
		cryptoerror(LOG_STDERR, gettext("Error initializing KMF\n"));
		rv = PK_ERR_USAGE;
		goto end;
	}

	/* Now we are ready to download */
	if (oclass & PK_CRL_OBJ) {
		rv = kmf_download_crl(kmfhandle, url, proxy, proxy_port, 30,
		    fullpath, &format);
	} else if (oclass & PK_CERT_OBJ) {
		rv = kmf_download_cert(kmfhandle, url, proxy, proxy_port, 30,
		    fullpath, &format);
	}

	if (rv != KMF_OK) {
		switch (rv) {
		case KMF_ERR_BAD_URI:
			cryptoerror(LOG_STDERR,
			    gettext("Error in parsing URI\n"));
			rv = PK_ERR_USAGE;
			break;
		case KMF_ERR_OPEN_FILE:
			cryptoerror(LOG_STDERR,
			    gettext("Error in opening file\n"));
			rv = PK_ERR_USAGE;
			break;
		case KMF_ERR_WRITE_FILE:
			cryptoerror(LOG_STDERR,
			    gettext("Error in writing file\n"));
			rv = PK_ERR_USAGE;
			break;
		case KMF_ERR_BAD_CRLFILE:
			cryptoerror(LOG_STDERR, gettext("Not a CRL file\n"));
			rv = PK_ERR_USAGE;
			break;
		case KMF_ERR_BAD_CERTFILE:
			cryptoerror(LOG_STDERR,
			    gettext("Not a certificate file\n"));
			rv = PK_ERR_USAGE;
			break;
		case KMF_ERR_MEMORY:
			cryptoerror(LOG_STDERR,
			    gettext("Not enough memory\n"));
			rv = PK_ERR_SYSTEM;
			break;
		default:
			cryptoerror(LOG_STDERR,
			    gettext("Error in downloading the file.\n"));
			rv = PK_ERR_SYSTEM;
			break;
		}
		goto end;
	}

	/*
	 * If the file is successfully downloaded, we also check the date.
	 * If the downloaded file is outdated, give a warning.
	 */
	if (oclass & PK_CRL_OBJ) {
		ch_rv = kmf_check_crl_date(kmfhandle, fullpath);
	} else { /* certificate */
		ch_rv = kmf_read_input_file(kmfhandle, fullpath, &cert);
		if (ch_rv != KMF_OK)
			goto end;

		if (format == KMF_FORMAT_PEM) {
			int len;
			ch_rv = kmf_pem_to_der(cert.Data, cert.Length,
			    &cert_der.Data, &len);
			if (ch_rv != KMF_OK)
				goto end;
			cert_der.Length = (size_t)len;
		}

		ch_rv = kmf_check_cert_date(kmfhandle,
		    format == KMF_FORMAT_ASN1 ? &cert : &cert_der);
	}

end:
	if (ch_rv == KMF_ERR_VALIDITY_PERIOD) {
		cryptoerror(LOG_STDERR,
		    gettext("Warning: the downloaded file is expired.\n"));
	} else if (ch_rv != KMF_OK) {
		cryptoerror(LOG_STDERR,
		    gettext("Warning: failed to check the validity.\n"));
	}

	if (fullpath)
		free(fullpath);

	kmf_free_data(&cert);
	kmf_free_data(&cert_der);

	(void) kmf_finalize(kmfhandle);
	return (rv);
}
