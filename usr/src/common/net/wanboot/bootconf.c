/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Functions for accessing the wanboot.conf(4) file.
 */

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <parseURL.h>
#include <netboot_paths.h>
#include <wanboot_conf.h>

/*
 * Parser helper macros:
 */
#define	is_whitespace(c)	((c) == ' ' || (c) == '\t')
#define	skip_whitespace(p)	while (is_whitespace(*(p))) ++p

/*
 * Table of valid wanboot.conf(4) names:
 */
static const char *bootconf_names[] = {
	BC_BOOT_FILE,
	BC_ROOT_SERVER,
	BC_ROOT_FILE,
	BC_ENCRYPTION_TYPE,
	BC_SIGNATURE_TYPE,
	BC_CLIENT_AUTHENTICATION,
	BC_SERVER_AUTHENTICATION,
	BC_BOOT_LOGGER,
	BC_RESOLVE_HOSTS,
	BC_SYSTEM_CONF,
	NULL
};

/*
 * Check whether 'name' is valid within wanboot.conf(4).
 */
static boolean_t
valid_name(const char *name)
{
	int	i;

	for (i = 0; bootconf_names[i] != NULL; ++i) {
		if (strcmp(name, bootconf_names[i]) == 0) {
			return (B_TRUE);
		}
	}

	return (B_FALSE);
}

/*
 * parse_bootconf() parses a wanboot.conf(4) file and, if there are no
 * errors, creates an nvpair list of the name-value pairs defined therein.
 *
 * Lines must be blank or of the form:
 *	[name=value] [# comment]
 *
 * Returns:
 *	B_TRUE	- success
 *	B_FALSE	- error (return code in handle->bc_error_code, line number
 *		  on which the error occurred in handle->bc_error_pos)
 */
static boolean_t
parse_bootconf(bc_handle_t *handle, const char *bootconf)
{
	FILE		*fp = NULL;
	nvlist_t	*nvl = NULL;
	char		line[BC_MAX_LINE_LENGTH];

	if ((fp = fopen(bootconf, "r")) == NULL) {
		handle->bc_error_code = BC_E_ACCESS;
		goto cleanup;
	}

	if (nvlist_alloc(&nvl, NV_UNIQUE_NAME, 0) != 0) {
		handle->bc_error_code = BC_E_NVLIST;
		goto cleanup;
	}

	while (fgets(line, sizeof (line), fp) != NULL) {
		int	i;
		char	*p = line;
		char	*ks, *ke, *vs, *ve;
		char	quote;

		++(handle->bc_error_pos);

		/*
		 * Strip off the '\n' at the end of the line.
		 */
		if ((i = strlen(line)) < 1) {
			handle->bc_error_code = BC_E_IOERR;
			goto cleanup;
		} else if (line[i - 1] != '\n') {
			handle->bc_error_code = BC_E_TOO_LONG;
			goto cleanup;
		}
		line[i - 1] = '\0';

		/*
		 * Skip leading whitespace.
		 */
		skip_whitespace(p);

		/*
		 * Blank line/comment-only line?
		 */
		if (*p == '\0' || *p == '#') {
			continue;
		}

		/*
		 * Get start and end pointers to the 'name'.
		 */
		ks = p;
		while (!is_whitespace(*p) && *p != '=') {
			++p;
		}
		ke = p;

		/*
		 * Must be of the form "name=value"; skip leading and
		 * trailing whitespace.
		 */
		skip_whitespace(p);
		if (*p == '=') {
			++p;		/* skip '=' */
			skip_whitespace(p);
		} else {
			handle->bc_error_code = BC_E_SYNTAX;
			goto cleanup;
		}

		/*
		 * The 'value' may be quoted.
		 */
		if (*p == '"' || *p == '\'') {
			quote = *p;
			++p;		/* skip '"' */
		} else {
			quote = '\0';
		}

		/*
		 * Get start and end pointers to the 'value' string.
		 * Note that 'value' may be the empty string.
		 */
		vs = p;
		if (quote != '\0' || *p != '#') {
			while (*p != '\0' && *p != quote) {
				/*
				 * White space that is not part of a quoted
				 * value signals end of value.
				 */
				if (is_whitespace(*p) && quote == '\0') {
					break;
				}
				++p;
			}
		}
		ve = p;

		/*
		 * If 'value' string was quoted, ensure that there is a
		 * balancing close-quote and skip it.
		 */
		if (quote != '\0') {
			if (*p == quote) {
				++p;
			} else {
				handle->bc_error_code = BC_E_SYNTAX;
				goto cleanup;
			}
		}

		/*
		 * Verify line is well-formed; the rest of the line should
		 * be blank or comment.
		 */
		skip_whitespace(p);
		if (*p != '\0' && *p != '#') {
			handle->bc_error_code = BC_E_SYNTAX;
			goto cleanup;
		}

		/*
		 * Nul-terminate both the 'name' and the 'value' string.
		 */
		*ke = '\0';
		*ve = '\0';

		/*
		 * Check that this is a valid parameter name.
		 */
		if (!valid_name(ks)) {
			handle->bc_error_code = BC_E_UNKNOWN_NAME;
			goto cleanup;
		}

		/*
		 * Add the name-value pair to the nvpair list.
		 */
		if (nvlist_add_string(nvl, ks, vs) != 0) {
			handle->bc_error_code = BC_E_NVLIST;
			goto cleanup;
		}
	}

	/*
	 * Verify that we didn't exit the parsing loop because of an
	 * input error.
	 */
	if (ferror(fp)) {
		handle->bc_error_code = BC_E_IOERR;
		goto cleanup;
	}

cleanup:
	/*
	 * Close the file if open and free the nvlist if an error occurred.
	 */
	if (fp != NULL && fclose(fp) != 0) {
		handle->bc_error_code = BC_E_IOERR;
	}
	if (handle->bc_error_code != BC_E_NOERROR) {
		if (nvl != NULL) {
			nvlist_free(nvl);
		}
		return (B_FALSE);
	}

	/*
	 * All is well.
	 */
	handle->bc_nvl = nvl;

	return (B_TRUE);
}

/*
 * valid_encryption() validitate the encryption type value
 *
 * Returns:
 *	B_TRUE	- success
 *	B_FALSE	- error (return code in handle->bc_error_code)
 */
static boolean_t
valid_encryption(bc_handle_t *handle, boolean_t *is_encrypted)
{
	nvlist_t	*nvl = handle->bc_nvl;
	char		*strval;

	/*
	 * Until proven otherwise, encryption is not enabled.
	 */
	*is_encrypted = B_FALSE;

	/*
	 * If encryption_type was specified then it must be either
	 * "3des", "aes" or "".
	 */
	if (nvlist_lookup_string(nvl, BC_ENCRYPTION_TYPE, &strval) == 0) {
		if (strlen(strval) > 0) {
			if (strcmp(strval, BC_ENCRYPTION_3DES) != 0 &&
			    strcmp(strval, BC_ENCRYPTION_AES) != 0) {
				handle->bc_error_code = BC_E_ENCRYPTION_ILLEGAL;
				return (B_FALSE);
			}
			*is_encrypted = B_TRUE;
		}
	}
	return (B_TRUE);
}

/*
 * valid_signature() validates the signature type value
 *
 * Returns:
 *	B_TRUE	- success
 *	B_FALSE	- error (return code in handle->bc_error_code)
 */
static boolean_t
valid_signature(bc_handle_t *handle, boolean_t *is_signed)
{
	nvlist_t	*nvl = handle->bc_nvl;
	char		*strval;

	/*
	 * Until proven otherwise, signing is not enabled.
	 */
	*is_signed = B_FALSE;

	/*
	 * If signature_type was specified then it must be either
	 * "sha1" or "".
	 */
	if (nvlist_lookup_string(nvl, BC_SIGNATURE_TYPE, &strval) == 0) {
		if (strlen(strval) > 0) {
			if (strcmp(strval, BC_SIGNATURE_SHA1) != 0) {
				handle->bc_error_code = BC_E_SIGNATURE_ILLEGAL;
				return (B_FALSE);
			}
			*is_signed = B_TRUE;
		}
	}

	return (B_TRUE);
}

/*
 * valid_client_authentication() validates the client authentication value
 *
 * Returns:
 *	B_TRUE	- success
 *	B_FALSE	- error (return code in handle->bc_error_code)
 */
static boolean_t
valid_client_authentication(bc_handle_t *handle, boolean_t *is_authenticated)
{
	nvlist_t	*nvl = handle->bc_nvl;
	char		*strval;

	/*
	 * Until proven otherwise, authentication is not enabled.
	 */
	*is_authenticated = B_FALSE;

	/*
	 * If client_authentication was specified then it must be either
	 * "yes" or "no".
	 */
	if (nvlist_lookup_string(nvl, BC_CLIENT_AUTHENTICATION, &strval) == 0) {
		if (strcmp(strval, BC_YES) == 0) {
			*is_authenticated = B_TRUE;
		} else if (strcmp(strval, BC_NO) != 0) {
			handle->bc_error_code = BC_E_CLIENT_AUTH_ILLEGAL;
			return (B_FALSE);
		}
	}

	return (B_TRUE);
}

/*
 * valid_server_authentication() validates the server authentication value
 *
 * Returns:
 *	B_TRUE	- success
 *	B_FALSE	- error (return code in handle->bc_error_code)
 */
static boolean_t
valid_server_authentication(bc_handle_t *handle, boolean_t *is_authenticated)
{
	nvlist_t	*nvl = handle->bc_nvl;
	char		*strval;

	/*
	 * Until proven otherwise, authentication is not enabled.
	 */
	*is_authenticated = B_FALSE;

	/*
	 * If server_authentication was specified then it must be either
	 * "yes" or"no".
	 */
	if (nvlist_lookup_string(nvl, BC_SERVER_AUTHENTICATION, &strval) == 0) {
		if (strcmp(strval, BC_YES) == 0) {
			*is_authenticated = B_TRUE;
		} else if (strcmp(strval, BC_NO) != 0) {
			handle->bc_error_code = BC_E_SERVER_AUTH_ILLEGAL;
			return (B_FALSE);
		}
	}

	return (B_TRUE);
}

/*
 * valid_root_server() validates the root server and root file values
 *
 * Returns:
 *	B_TRUE	- success
 *	B_FALSE	- error (return code in handle->bc_error_code)
 */
static boolean_t
valid_root_server(bc_handle_t *handle, boolean_t *is_https)
{
	nvlist_t	*nvl = handle->bc_nvl;
	char		*strval;
	url_t		url;

	/*
	 * Until proven otherwise, assume not https.
	 */
	*is_https = B_FALSE;

	/*
	 * Check whether a root_server URL was specified, and if so whether
	 * it is a secure URL (of the form https://...).
	 */
	if (nvlist_lookup_string(nvl, BC_ROOT_SERVER, &strval) == 0) {
		if (url_parse(strval, &url) != URL_PARSE_SUCCESS) {
			handle->bc_error_code = BC_E_ROOT_SERVER_BAD;
			return (B_FALSE);
		}
		*is_https = url.https;

		/*
		 * Ensure that a root_file was also specified.
		 */
		if (nvlist_lookup_string(nvl, BC_ROOT_FILE, &strval) != 0 ||
		    strlen(strval) == 0) {
			handle->bc_error_code = BC_E_ROOT_FILE_ABSENT;
			return (B_FALSE);
		}
	} else {
		handle->bc_error_code = BC_E_ROOT_SERVER_ABSENT;
		return (B_FALSE);
	}

	return (B_TRUE);
}

/*
 * valid_boot_logger() validates the boot_logger value
 *
 * Returns:
 *	B_TRUE	- success
 *	B_FALSE	- error (return code in handle->bc_error_code)
 */
static boolean_t
valid_boot_logger(bc_handle_t *handle, boolean_t *is_https)
{
	nvlist_t	*nvl = handle->bc_nvl;
	char		*strval;
	url_t		url;

	/*
	 * Until proven otherwise, assume not https.
	 */
	*is_https = B_FALSE;

	/*
	 * If boot_logger was specified, make sure that it is a valid URL.
	 */
	if (nvlist_lookup_string(nvl, BC_BOOT_LOGGER, &strval) == 0 &&
	    strlen(strval) > 0) {
		if (url_parse(strval, &url) != URL_PARSE_SUCCESS) {
			handle->bc_error_code = BC_E_BOOT_LOGGER_BAD;
			return (B_FALSE);
		}
		*is_https = url.https;
	}

	return (B_TRUE);
}

/*
 * validate_bootconf() checks the consistency of the nvpair list representation
 * of a wanboot.conf(4) file as returned by the parse_bootconf() function.
 *
 * Returns:
 *	B_TRUE	- success
 *	B_FALSE	- error (return code in handle->bc_error_code)
 */
static boolean_t
validate_bootconf(bc_handle_t *handle)
{
	boolean_t	is_encrypted;
	boolean_t	is_signed;
	boolean_t	client_is_authenticated;
	boolean_t	server_is_authenticated;
	boolean_t	rootserver_is_https;
	boolean_t	bootlogger_is_https;

	/*
	 * Check to make sure option values are valid.
	 */
	if (!valid_encryption(handle, &is_encrypted) ||
	    !valid_signature(handle, &is_signed) ||
	    !valid_client_authentication(handle, &client_is_authenticated) ||
	    !valid_server_authentication(handle, &server_is_authenticated) ||
	    !valid_root_server(handle, &rootserver_is_https) ||
	    !valid_boot_logger(handle, &bootlogger_is_https))
		return (B_FALSE);

	/*
	 * Now do consistency checking between bootconf settings.
	 */
	if (is_encrypted && !is_signed) {
		handle->bc_error_code = BC_E_ENCRYPTED_NOT_SIGNED;
		return (B_FALSE);
	}
	if (client_is_authenticated) {
		if (!(is_encrypted && is_signed)) {
			handle->bc_error_code = BC_E_CLIENT_AUTH_NOT_ENCRYPTED;
			return (B_FALSE);
		}

		if (!server_is_authenticated) {
			handle->bc_error_code = BC_E_CLIENT_AUTH_NOT_SERVER;
			return (B_FALSE);
		}
	}
	if (server_is_authenticated) {
		if (!is_signed) {
			handle->bc_error_code = BC_E_SERVER_AUTH_NOT_SIGNED;
			return (B_FALSE);
		}

		if (!rootserver_is_https) {
			handle->bc_error_code = BC_E_SERVER_AUTH_NOT_HTTPS;
			return (B_FALSE);
		}
	} else if (rootserver_is_https) {
		handle->bc_error_code = BC_E_SERVER_AUTH_NOT_HTTP;
		return (B_FALSE);
	} else if (bootlogger_is_https) {
		handle->bc_error_code = BC_E_BOOTLOGGER_AUTH_NOT_HTTP;
		return (B_FALSE);
	}

	return (B_TRUE);
}


/*
 * bootconf_end() cleans up once we're done accessing the nvpair list
 * representation of wanboot.conf(4).
 */
void
bootconf_end(bc_handle_t *handle)
{
	if (handle->bc_nvl != NULL) {
		nvlist_free(handle->bc_nvl);
		handle->bc_nvl = NULL;
	}
}

/*
 * bootconf_init() must be called to initialize 'handle' before bootconf_get()
 * can be used to access values from the wanboot.conf(4) file.
 */
int
bootconf_init(bc_handle_t *handle, const char *bootconf)
{
	/*
	 * Initalise the handle's fields to sensible values.
	 */
	handle->bc_nvl = NULL;
	handle->bc_error_code = BC_E_NOERROR;
	handle->bc_error_pos = 0;

	/*
	 * Provide a default path for the bootconf file if none was given.
	 */
	if (bootconf == NULL) {
		bootconf = NB_WANBOOT_CONF_PATH;
	}

	/*
	 * Check that we can successfully parse and validate the file.
	 */
	if (parse_bootconf(handle, bootconf) && validate_bootconf(handle)) {
		return (BC_SUCCESS);
	}

	/*
	 * Parse/validate error; free any allocated resources.
	 */
	bootconf_end(handle);

	return (BC_FAILURE);
}

/*
 * bootconf_get() returns the value of a parameter in the wanboot.conf(4) file.
 *
 * Returns:
 *	!= NULL	- the given value
 *	== NULL	- value not found or is empty
 */
char *
bootconf_get(bc_handle_t *handle, const char *name)
{
	char	*strval;

	/*
	 * Look up the name in bc_nvl and return its value if found.
	 */
	if (handle->bc_nvl != NULL &&
	    nvlist_lookup_string(handle->bc_nvl, (char *)name, &strval) == 0) {
		return (strlen(strval) == 0 ? NULL : strval);
	}

	return (NULL);
}
