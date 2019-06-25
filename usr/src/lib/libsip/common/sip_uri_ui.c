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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>

#include "sip_parse_uri.h"

void
sip_free_parsed_uri(sip_uri_t uri)
{
	_sip_uri_t	*_uri;

	if (uri == NULL)
		return;

	_uri = (_sip_uri_t *)uri;
	if (_uri->sip_uri_issip) {
		sip_param_t	*param;
		sip_param_t	*param_next;

		param = _uri->sip_uri_params;
		while (param != NULL) {
			param_next = param->param_next;
			free(param);
			param = param_next;
		}
	}
	free(_uri);
}

/*
 * Parse the URI in uri_str
 */
struct sip_uri *
sip_parse_uri(sip_str_t *uri_str, int *error)
{
	struct sip_uri	*parsed_uri;

	if (error != NULL)
		*error = 0;

	if (uri_str == NULL) {
		if (error != NULL)
			*error = EINVAL;
		return (NULL);
	}
	parsed_uri = calloc(1, sizeof (_sip_uri_t));
	if (parsed_uri == NULL) {
		if (error != NULL)
			*error = ENOMEM;
		return (NULL);
	}

	sip_uri_parse_it(parsed_uri, uri_str);
	if (parsed_uri->sip_uri_errflags & SIP_URIERR_MEMORY) {
		free(parsed_uri);
		if (error != NULL)
			*error = ENOMEM;
		return (NULL);
	}
	if (parsed_uri->sip_uri_errflags != 0 && error != NULL)
		*error = EPROTO;
	return ((sip_uri_t)parsed_uri);
}

/*
 * Get parsed URI
 */
const struct sip_uri *
sip_get_uri_parsed(sip_header_value_t value, int *error)
{
	const struct sip_uri	*ret = NULL;

	if (error != NULL)
		*error = 0;
	if (value == NULL || value->sip_value_parse_uri == NULL ||
	    value->value_state == SIP_VALUE_DELETED) {
		if (error != NULL)
			*error = EINVAL;
		return (NULL);
	}
	ret = value->sip_value_parse_uri;
	if (ret->sip_uri_errflags != 0 && error != NULL)
		*error = EINVAL;
	return ((sip_uri_t)ret);
}

/*
 * Return TRUE if this is a SIP URI
 */
boolean_t
sip_is_sipuri(const struct sip_uri *uri)
{
	_sip_uri_t	*_uri;

	if (uri == NULL)
		return (B_FALSE);
	_uri = (_sip_uri_t *)uri;
	if ((_uri->sip_uri_errflags & SIP_URIERR_SCHEME) == 0 &&
	    _uri->sip_uri_scheme.sip_str_len > 0 && _uri->sip_uri_issip) {
		return (B_TRUE);
	}
	return (B_FALSE);
}

/*
 * Some common checks
 */
static _sip_uri_t *
sip_check_get_param(const struct sip_uri *uri, int *error)
{
	if (error != NULL)
		*error = 0;

	if (uri == NULL) {
		if (error != NULL)
			*error = EINVAL;
		return (NULL);
	}
	return ((_sip_uri_t *)uri);
}


/*
 * Return the URI scheme
 */
const sip_str_t *
sip_get_uri_scheme(const struct sip_uri *uri, int *error)
{
	_sip_uri_t	*_uri;

	_uri = sip_check_get_param(uri, error);
	if (_uri == NULL)
		return (NULL);

	if (((_uri->sip_uri_errflags & SIP_URIERR_SCHEME) != 0 ||
	    _uri->sip_uri_scheme.sip_str_len == 0) && error != NULL) {
		*error = EINVAL;
	}
	if (_uri->sip_uri_scheme.sip_str_len > 0)
		return (&_uri->sip_uri_scheme);
	return (NULL);
}

/*
 *  Return user name from URI
 */
const sip_str_t *
sip_get_uri_user(const struct sip_uri *uri, int *error)
{
	_sip_uri_t	*_uri;

	_uri = sip_check_get_param(uri, error);
	if (_uri == NULL)
		return (NULL);

	if ((_uri->sip_uri_errflags & SIP_URIERR_USER) != 0 && error != NULL)
		*error = EINVAL;
	if (uri->sip_uri_user.sip_str_len > 0)
		return (&uri->sip_uri_user);
	return (NULL);
}

/*
 *  Return password from URI
 */
const sip_str_t *
sip_get_uri_password(const struct sip_uri *uri, int *error)
{
	_sip_uri_t	*_uri;

	_uri = sip_check_get_param(uri, error);
	if (_uri == NULL)
		return (NULL);

	if ((_uri->sip_uri_errflags & SIP_URIERR_PASS) != 0 && error != NULL)
		*error = EINVAL;
	if (_uri->sip_uri_password.sip_str_len > 0)
		return (&_uri->sip_uri_password);
	return (NULL);
}

/*
 * Get host from the URI
 */
const sip_str_t *
sip_get_uri_host(const struct sip_uri *uri, int *error)
{
	_sip_uri_t	*_uri;

	_uri = sip_check_get_param(uri, error);
	if (_uri == NULL)
		return (NULL);

	if ((_uri->sip_uri_errflags & SIP_URIERR_HOST) != 0 && error != NULL)
		*error = EINVAL;
	if (_uri->sip_uri_host.sip_str_len > 0)
		return (&_uri->sip_uri_host);
	return (NULL);
}

/*
 * Get port from the URI
 */
int
sip_get_uri_port(const struct sip_uri *uri, int *error)
{
	_sip_uri_t	*_uri;

	_uri = sip_check_get_param(uri, error);
	if (_uri == NULL)
		return (0);

	if ((_uri->sip_uri_errflags & SIP_URIERR_PORT) != 0) {
		if (error != NULL)
			*error = EINVAL;
		return (0);
	}
	return (_uri->sip_uri_port);
}

const sip_param_t *
sip_get_uri_params(const struct sip_uri *uri, int *error)
{
	_sip_uri_t		*_uri;

	_uri = sip_check_get_param(uri, error);
	if (_uri == NULL)
		return (NULL);

	if (!_uri->sip_uri_issip) {
		if (error != NULL)
			*error = EINVAL;
		return (NULL);
	}

	if ((_uri->sip_uri_errflags & SIP_URIERR_PARAM) != 0 && error != NULL)
		*error = EINVAL;
	return (_uri->sip_uri_params);
}

/*
 * Get headers from the URI
 */
const sip_str_t *
sip_get_uri_headers(const struct sip_uri *uri, int *error)
{
	_sip_uri_t	*_uri;

	_uri = sip_check_get_param(uri, error);
	if (_uri == NULL)
		return (NULL);

	if (!_uri->sip_uri_issip) {
		if (error != NULL)
			*error = EINVAL;
		return (NULL);
	}
	if ((_uri->sip_uri_errflags & SIP_URIERR_HEADER) != 0 && error != NULL)
		*error = EINVAL;
	if (_uri->sip_uri_headers.sip_str_len > 0)
		return (&_uri->sip_uri_headers);
	return (NULL);
}

/*
 *  Return opaque value for an ABS URI
 */
const sip_str_t *
sip_get_uri_opaque(const struct sip_uri *uri, int *error)
{
	_sip_uri_t	*_uri;

	_uri = sip_check_get_param(uri, error);
	if (_uri == NULL)
		return (NULL);

	if (_uri->sip_uri_issip) {
		if (error != NULL)
			*error = EINVAL;
		return (NULL);
	}
	if ((_uri->sip_uri_errflags & SIP_URIERR_OPAQUE) != 0 && error != NULL)
		*error = EINVAL;
	if (_uri->sip_uri_opaque.sip_str_len > 0)
		return (&_uri->sip_uri_opaque);
	return (NULL);
}

/*
 * Return query from an absolute URI
 */
const sip_str_t *
sip_get_uri_query(const struct sip_uri *uri, int *error)
{
	_sip_uri_t	*_uri;

	_uri = sip_check_get_param(uri, error);
	if (_uri == NULL)
		return (NULL);

	if (_uri->sip_uri_issip) {
		if (error != NULL)
			*error = EINVAL;
		return (NULL);
	}
	if ((_uri->sip_uri_errflags & SIP_URIERR_QUERY) != 0 && error != NULL)
		*error = EINVAL;
	if (_uri->sip_uri_query.sip_str_len > 0)
		return (&_uri->sip_uri_query);
	return (NULL);
}

/*
 *  Get path from an assolute URI
 */
const sip_str_t *
sip_get_uri_path(const struct sip_uri *uri, int *error)
{
	_sip_uri_t	*_uri;

	_uri = sip_check_get_param(uri, error);
	if (_uri == NULL)
		return (NULL);

	if (_uri->sip_uri_issip) {
		if (error != NULL)
			*error = EINVAL;
		return (NULL);
	}
	if ((_uri->sip_uri_errflags & SIP_URIERR_PATH) != 0 && error != NULL)
		*error = EINVAL;
	if (_uri->sip_uri_path.sip_str_len > 0)
		return (&_uri->sip_uri_path);
	return (NULL);
}

/*
 * Get the reg-name from absolute URI
 */
const sip_str_t	*
sip_get_uri_regname(const struct sip_uri *uri, int *error)
{
	_sip_uri_t	*_uri;

	_uri = sip_check_get_param(uri, error);
	if (_uri == NULL)
		return (NULL);

	if (_uri->sip_uri_issip) {
		if (error != NULL)
			*error = EINVAL;
		return (NULL);
	}
	if ((_uri->sip_uri_errflags & SIP_URIERR_REGNAME) != 0 && error != NULL)
		*error = EINVAL;
	if (_uri->sip_uri_regname.sip_str_len > 0)
		return (&_uri->sip_uri_regname);
	return (NULL);
}

/*
 * Return TRUE if this is a teluser
 */
boolean_t
sip_is_uri_teluser(const struct sip_uri *uri)
{
	_sip_uri_t	*_uri;

	if (uri == NULL)
		return (B_FALSE);

	_uri = (_sip_uri_t *)uri;
	return (_uri->sip_uri_isteluser);
}

int
sip_get_uri_errflags(const struct sip_uri *uri, int *error)
{
	_sip_uri_t	*_uri;

	_uri = sip_check_get_param(uri, error);
	if (_uri == NULL)
		return (0);
	return (_uri->sip_uri_errflags);
}

/*
 * the caller is responsible for freeing the returned string
 */
char *
sip_uri_errflags_to_str(int errflags)
{
	char	*err_info = NULL;

	if (errflags == 0)
		return (NULL);

	err_info = (char *)malloc(SIP_URI_BUF_SIZE);
	if (err_info == NULL)
		return (NULL);

	if (errflags & SIP_URIERR_NOURI) {
		(void) strncpy(err_info, "Error : No URI",
		    strlen("Error : No URI"));
		err_info[strlen("Error : No URI")] = '\0';
		return (err_info);
	}

	(void) strncpy(err_info, "Error(s) in", strlen("Error(s) in"));
	err_info[strlen("Error(s) in")] = '\0';
	if (errflags & SIP_URIERR_SCHEME)
		(void) strncat(err_info, " SCHEME,", strlen(" SCHEME,"));
	if (errflags & SIP_URIERR_USER)
		(void) strncat(err_info, " USER,", strlen(" USER,"));
	if (errflags & SIP_URIERR_PASS)
		(void) strncat(err_info, " PASSWORD,", strlen(" PASSWORD,"));
	if (errflags & SIP_URIERR_HOST)
		(void) strncat(err_info, " HOST,", strlen(" HOST,"));
	if (errflags & SIP_URIERR_PORT)
		(void) strncat(err_info, " PORT,", strlen(" PORT,"));
	if (errflags & SIP_URIERR_PARAM) {
		(void) strncat(err_info, " PARAMETERS,",
		    strlen(" PARAMETERS,"));
	}
	if (errflags & SIP_URIERR_HEADER)
		(void) strncat(err_info, " HEADERS,", strlen(" HEADERS,"));
	if (errflags & SIP_URIERR_OPAQUE)
		(void) strncat(err_info, " OPAQUE,", strlen(" OPAQUE,"));
	if (errflags & SIP_URIERR_QUERY)
		(void) strncat(err_info, " QUERY,", strlen(" QUERY,"));
	if (errflags & SIP_URIERR_PATH)
		(void) strncat(err_info, " PATH,", strlen(" PATH,"));
	if (errflags & SIP_URIERR_REGNAME)
		(void) strncat(err_info, " REG-NAME,", strlen(" REG-NAME,"));
	if (strlen(err_info) == strlen("Error(s) in")) {
		free(err_info);
		err_info = NULL;
	} else {
		err_info[strlen(err_info) - 1] = '\0';
		(void) strncat(err_info, " part(s)", strlen(" part(s)"));
	}
	return (err_info);
}
