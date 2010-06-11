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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * KMF CN certificate-to-name mapper.
 */

#include <kmftypes.h>
#include <kmfapi.h>
#include <fcntl.h>

/*
 * KMF uses long identifiers for RDN processing which makes it hard to keep
 * cstyle cleanliness without using some auxiliary macros. Parameter 'x' is of
 * the KMF_X509_NAME type.
 */
#define	RDN_VALUE(x, i) \
	(&x.RelativeDistinguishedName[i].AttributeTypeAndValue->value)

#define	RDN_OID(x, i) \
	(&x.RelativeDistinguishedName[i].AttributeTypeAndValue->type)

#define	RDN_NPAIRS(x, i) (x.RelativeDistinguishedName[i].numberOfPairs)

/* Error codes specific to this mapper. */
#define	CN_MAPPER_CN_RDN_NOT_PRESENT	1

typedef struct cooked_opts {
	int casesensitive;
} cooked_opts;

KMF_RETURN
mapper_initialize(KMF_HANDLE_T h, char *options)
{
	cooked_opts *opts;

	if ((opts = malloc(sizeof (cooked_opts))) == NULL)
		return (KMF_ERR_MEMORY);

	/* This is the default. */
	opts->casesensitive = B_FALSE;

	if (options != NULL) {
		if (strcmp(options, "casesensitive") == 0)
			opts->casesensitive = B_TRUE;
	}

	kmf_set_mapper_options(h, opts);

	return (KMF_OK);
}

void
mapper_finalize(KMF_HANDLE_T h)
{
	void *opts;

	if ((opts = kmf_get_mapper_options(h)) != NULL)
		free(opts);
	kmf_set_mapper_options(h, NULL);
}

/*
 * The CN string returned in name.Data will be NULL-terminated. The caller is
 * expected to free name->Data after use.
 */
KMF_RETURN
mapper_map_cert_to_name(KMF_HANDLE_T h, KMF_DATA *cert, KMF_DATA *name)
{
	int i, j;
	char *dn;
	KMF_RETURN rv;
	uchar_t *cn = NULL;
	KMF_X509_NAME x509name;

	kmf_set_mapper_lasterror(h, KMF_OK);

	if ((rv = kmf_get_cert_subject_str(h, cert, &dn)) != KMF_OK)
		return (rv);

	if ((rv = kmf_dn_parser(dn, &x509name)) != KMF_OK)
		return (rv);

	/* Go through the list of RDNs and look for the CN. */
	for (i = 0; i < x509name.numberOfRDNs; ++i) {
		for (j = 0; j < RDN_NPAIRS(x509name, i); ++j) {
			KMF_OID *oid = RDN_OID(x509name, i);
			KMF_DATA *data = RDN_VALUE(x509name, i);

			if (oid == NULL)
				continue;

			/* Is this RDN a Common Name? */
			if (oid->Length == KMFOID_CommonName.Length &&
			    memcmp(oid->Data, KMFOID_CommonName.Data,
			    oid->Length) == 0) {
				if ((cn = malloc(data->Length + 1)) == NULL) {
					kmf_free_dn(&x509name);
					return (KMF_ERR_MEMORY);
				}
				(void) memcpy(cn, data->Data, data->Length);
				/* Terminate the string. */
				cn[data->Length] = '\0';
				name->Length = data->Length + 1;
				name->Data = cn;
				goto finished;
			}
		}
	}

finished:
	kmf_free_dn(&x509name);
	if (cn != NULL)
		return (KMF_OK);
	else {
		kmf_set_mapper_lasterror(h, CN_MAPPER_CN_RDN_NOT_PRESENT);
		return (KMF_ERR_INTERNAL);
	}
}

/*
 * Note that name_to_match->Data might or might not be NULL terminated. If
 * mapped_name->Length returned is greater than zero the caller is expected to
 * free mapped_name->Data after use.
 */
KMF_RETURN
mapper_match_cert_to_name(KMF_HANDLE_T h, KMF_DATA *cert,
    KMF_DATA *name_to_match, KMF_DATA *mapped_name)
{
	int ret;
	KMF_RETURN rv;
	KMF_DATA get_name;
	cooked_opts *opts = NULL;

	opts = (cooked_opts *)kmf_get_mapper_options(h);

	/* Initialize the output parameter. */
	if (mapped_name != NULL) {
		mapped_name->Length = 0;
		mapped_name->Data = NULL;
	}

	if ((rv = mapper_map_cert_to_name(h, cert, &get_name)) != KMF_OK)
		return (rv);

	/*
	 * If name_to_match->Data is not NULL terminated, check that we have the
	 * same number of characters.
	 */
	if (name_to_match->Data[name_to_match->Length - 1] != '\0')
		/* We know that get_name.Data is NULL terminated. */
		if (name_to_match->Length != get_name.Length - 1)
			return (KMF_ERR_NAME_NOT_MATCHED);

	/*
	 * Compare the strings. We must use name_to_match->Length in case
	 * name_to_match->Data was not NULL terminated. If we used
	 * get_name.Length we could overrun name_to_match->Data by one byte.
	 */
	if (opts->casesensitive == B_TRUE)
		ret = strncmp((char *)name_to_match->Data,
		    (char *)get_name.Data, name_to_match->Length);
	else
		ret = strncasecmp((char *)name_to_match->Data,
		    (char *)get_name.Data, name_to_match->Length);

	if (mapped_name != NULL) {
		mapped_name->Length = get_name.Length;
		mapped_name->Data = get_name.Data;
	} else
		kmf_free_data(&get_name);

	if (ret == 0)
		return (KMF_OK);
	else
		return (KMF_ERR_NAME_NOT_MATCHED);
}

/* The caller is responsible for freeing the error string when done with it. */
KMF_RETURN
mapper_get_error_str(KMF_HANDLE_T h, char **errstr)
{
	uint32_t lasterr;

	lasterr = kmf_get_mapper_lasterror(h);
	*errstr = NULL;
	if (lasterr == 0)
		return (KMF_ERR_MISSING_ERRCODE);

	switch (lasterr) {
	case CN_MAPPER_CN_RDN_NOT_PRESENT:
		*errstr = (char *)strdup("CN_MAPPER_CN_RDN_NOT_PRESENT");
		break;
	default:
		*errstr = (char *)strdup("KMF_ERR_MISSING_MAPPER_ERRCODE");
	}

	if (*errstr == NULL)
		return (KMF_ERR_MEMORY);

	return (KMF_OK);
}
