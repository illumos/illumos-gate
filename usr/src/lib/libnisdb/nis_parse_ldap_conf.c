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
 * Copyright 2015 Gary Mills
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <locale.h>
#include <sys/stat.h>
#include <lber.h>
#include <ldap.h>
#include <deflt.h>

#include "ldap_map.h"

#include "ldap_parse.h"
#include "ldap_glob.h"
#include "nis_parse_ldap_conf.h"

__nis_ldap_proxy_info	proxyInfo		=
	{NULL, (auth_method_t)NO_VALUE_SET, (tls_method_t)NO_VALUE_SET, NULL,
		NULL, NULL, NULL, NULL, (follow_referral_t)NO_VALUE_SET};
__nis_config_t		ldapConfig;
__nisdb_table_mapping_t ldapDBTableMapping;
__nis_table_mapping_t	*ldapTableMapping	= NULL;
__yp_domain_context_t	ypDomains;

parse_error		p_error			= no_parse_error;
int			cur_line_num		= 0;
int			start_line_num		= 0;
int			seq_num 		= 0;
const char		*warn_file		= NULL;

char			_key_val[38];
const char		*command_line_source	= NULL;
const char		*file_source		= NULL;
const char		*ldap_source		= NULL;

static
const char *const	*cmdline_config		= NULL;
static bool_t		got_config_data		= FALSE;

/* high level parsing functions functions */
static int parse_ldap_cmd_line(const char *const *cmdline_options,
    __nis_ldap_proxy_info *proxy_info, __nis_config_t *nis_config,
    __nis_table_mapping_t **table_mapping, __nis_config_info_t *config_info,
    __nisdb_table_mapping_t *table_info);
static int parse_ldap_default_conf(__nis_ldap_proxy_info *proxy_info,
    __nis_config_t *nis_config, __nis_config_info_t *config_info,
    __nisdb_table_mapping_t *table_info);
static int parse_ldap_config_file(const char *config_file,
    __nis_ldap_proxy_info *proxy_info, __nis_config_t *nis_config,
    __nis_table_mapping_t **table_mapping, __nis_config_info_t *config_info,
    __nisdb_table_mapping_t *table_info);
static int parse_ldap_config_dn_attrs(__nis_ldap_proxy_info *proxy_info,
    __nis_config_t *nis_config, __nis_table_mapping_t **table_mapping,
    __nis_config_info_t *config_info, __nisdb_table_mapping_t *table_info);
static int yp_parse_ldap_default_conf(__nis_ldap_proxy_info *proxy_info,
	__nis_config_t *nis_config, __nis_config_info_t *config_info,
	__nisdb_table_mapping_t *table_info);

/* Forward declarations */
int yp_parse_ldap_config_file(const char *, __nis_ldap_proxy_info *,
    __nis_config_t *, __nis_table_mapping_t **, __nis_config_info_t *,
    __nisdb_table_mapping_t *, 	__yp_domain_context_t *);


/* helper functions */
static config_key get_attrib_num_cmdline(const char *s,
    const char **begin_s, const char **end_s);
static config_key get_file_attr_val(int fd, char **attr_val);
static void get_attribute_list(
	const __nis_ldap_proxy_info *proxy_info,
	const __nis_config_t *nis_config,
	const __nis_config_info_t *config_info,
	const __nisdb_table_mapping_t *table_info,
	char **ldap_config_attributes);

/*
 * FUNCTION:	parse_ldap_migration
 *
 *	Parses the information for LDAP. The values are first
 *	obtained from the command line, secondly from the preference
 *	file, and finally from an LDAP profile (if so configured in
 *	the command line or preference file). Any unset values will
 *	be set to their default values.
 *
 *	If no command line options, no settings in the /etc/default
 *  configuration file, and no mapping file, then no mapping
 *  should be used.
 *
 * RETURN VALUE:
 *			0	Success
 *			-1	Config file stat/open or parse error
 *			1	No mapping should be used.
 *
 * INPUT:		command line parameters, configuration file
 */

int
parse_ldap_migration(
	const char *const	*cmdline_options,
	const char		*config_file)
{
	int			rc	= 0;
	__nis_config_info_t	config_info
				= {NULL, NULL, (auth_method_t)NO_VALUE_SET,
					(tls_method_t)NO_VALUE_SET, NULL,
					NULL, NULL};
	struct stat		buf;

	p_error = no_parse_error;

	if (verbose)
		report_info("Getting LDAP configuration", NULL);

	initialize_parse_structs(&proxyInfo, &ldapConfig, &ldapDBTableMapping);

	if (yp2ldap)
		initialize_yp_parse_structs(&ypDomains);

	if (cmdline_options != NULL) {
		got_config_data = TRUE;
		/* NIS to LDAP does not read command line attributes */
		if (!yp2ldap)
			rc = parse_ldap_cmd_line(cmdline_options, &proxyInfo,
			    &ldapConfig, &ldapTableMapping, &config_info,
			    &ldapDBTableMapping);
		else
			rc = 0;
	}

	if (rc == 0) {
		if (yp2ldap)
			rc = yp_parse_ldap_default_conf(&proxyInfo, &ldapConfig,
			    &config_info, &ldapDBTableMapping);
		else
			rc = parse_ldap_default_conf(&proxyInfo, &ldapConfig,
			    &config_info, &ldapDBTableMapping);
	}

	if (config_file == NULL) {
		if (yp2ldap) {
			if (stat(YP_DEFAULT_MAPPING_FILE, &buf) == 0)
				config_file = YP_DEFAULT_MAPPING_FILE;
		} else {
			if (stat(DEFAULT_MAPPING_FILE, &buf) == 0)
				config_file = DEFAULT_MAPPING_FILE;
		}
	}

	if (rc == 0 && config_file != NULL) {
		got_config_data = TRUE;
		warn_file = config_file;
		cmdline_config = cmdline_options;
		if (yp2ldap)
			rc = yp_parse_ldap_config_file(config_file, &proxyInfo,
			    &ldapConfig, &ldapTableMapping, &config_info,
			    &ldapDBTableMapping, &ypDomains);
		else
			rc = parse_ldap_config_file(config_file, &proxyInfo,
			    &ldapConfig, &ldapTableMapping, &config_info,
			    &ldapDBTableMapping);

		warn_file = NULL;
		cmdline_config = NULL;
	}
	if (rc == 0 && (config_info.config_dn != NULL) &&
	    (config_info.config_dn[0] != '\0')) {
		rc = parse_ldap_config_dn_attrs(&proxyInfo,
		    &ldapConfig, &ldapTableMapping, &config_info,
		    &ldapDBTableMapping);
	}

	free_config_info(&config_info);

	if (rc == 0 && got_config_data == FALSE)
		rc = 1;

	set_default_values(&proxyInfo, &ldapConfig, &ldapDBTableMapping);

	if (yp2ldap == 1 && rc == 0) {
		rc = second_parser_pass(&ldapTableMapping);
		if (rc == 0)
			rc = final_parser_pass(&ldapTableMapping, &ypDomains);
		if (rc == -2)
			return (-1);
	}

	if (rc == 0)
		rc = finish_parse(&proxyInfo, &ldapTableMapping);

	if (rc == 0)
		rc = linked2hash(ldapTableMapping);

	if ((rc == 0) && yptol_mode)
		rc = map_id_list_init();

	if (rc != 0) {
		free_parse_structs();
	} else if (verbose)
		report_info("LDAP configuration complete", NULL);
	return (rc);
}

/*
 * FUNCTION:	parse_ldap_cmd_line
 *
 *	Parses the information for LDAP from the command line
 *
 * RETURN VALUE:	0 on success, -1 on failure
 *
 * INPUT:		command line values
 */

static int
parse_ldap_cmd_line(
	const char *const	*cmdline_options,
	__nis_ldap_proxy_info	*proxy_info,
	__nis_config_t		*nis_config,
	__nis_table_mapping_t	**table_mapping,
	__nis_config_info_t	*config_info,
	__nisdb_table_mapping_t	*table_info)
{
	int		rc = 0;
	config_key	attrib_num;
	const char	*begin_s;
	const char	*end_s;

	if (verbose)
		report_info("Command line values: ", NULL);
	while (*cmdline_options != NULL) {
		if (verbose)
			report_info("\t", *cmdline_options);

		attrib_num = get_attrib_num_cmdline(
		    *cmdline_options, &begin_s, &end_s);
		if (attrib_num == key_bad) {
			command_line_source = "command line";
			report_error(*cmdline_options, NULL);
			command_line_source = NULL;
			rc = -1;
			break;
		} else if (IS_CONFIG_KEYWORD(attrib_num)) {
			rc = add_config_attribute(attrib_num,
			    begin_s, end_s - begin_s, config_info);
		} else if (IS_BIND_INFO(attrib_num)) {
			rc = add_bind_attribute(attrib_num,
			    begin_s, end_s - begin_s, proxy_info);
		} else if (IS_OPER_INFO(attrib_num)) {
			rc = add_operation_attribute(attrib_num,
			    begin_s, end_s - begin_s, nis_config,
			    table_info);
		} else {
			rc = add_mapping_attribute(attrib_num,
			    begin_s, end_s - begin_s, table_mapping);
		}

		if (rc < 0) {
			command_line_source = "command line";
			report_error(begin_s, _key_val);
			command_line_source = NULL;
			break;
		}
		cmdline_options++;
	}
	return (rc);
}

static int
parse_ldap_default_conf(
	__nis_ldap_proxy_info *proxy_info,
	__nis_config_t *nis_config,
	__nis_config_info_t *config_info,
	__nisdb_table_mapping_t	*table_info)
{
	int		rc = 0;
	char		*ldap_config_attributes[n_config_keys];
	char		attr_buf[128];
	char		*attr;
	char		*attr_val;
	int		defflags;
	config_key	attrib_num;
	int		i;
	int		len;
	int		attr_len;
	void		*defp;

	if ((defp = defopen_r(ETCCONFFILE)) != NULL) {
		file_source = ETCCONFFILE;
		if (verbose)
			report_info("default configuration values: ", NULL);
		/* Set defread_r() to be case insensitive */
		defflags = defcntl_r(DC_GETFLAGS, 0, defp);
		TURNOFF(defflags, DC_CASE);
		(void) defcntl_r(DC_SETFLAGS, defflags, defp);

		get_attribute_list(proxy_info, nis_config, config_info,
		    table_info, ldap_config_attributes);
		i = 0;
		while ((attr = ldap_config_attributes[i++]) != NULL) {
			(void) strlcpy(attr_buf, attr, sizeof (attr_buf));
			/*
			 * if nisplusUpdateBatching, make sure
			 * we don't match nisplusUpdateBatchingTimeout
			 */
			if (strcmp(attr, UPDATE_BATCHING) == 0) {
				attr_len = strlen(attr);
				attr_buf[attr_len] = '=';
				attr_buf[attr_len + 1] = '\0';
				attr_val = defread_r(attr_buf, defp);

				if (attr_val == 0) {
					attr_buf[attr_len] = ' ';
					attr_val = defread_r(attr_buf, defp);
				}
				if (attr_val == 0) {
					attr_buf[attr_len] = '\t';
					attr_val = defread_r(attr_buf, defp);
				}
				if (attr_val == 0) {
					attr_buf[attr_len] = '\n';
					attr_val = defread_r(attr_buf, defp);
				}
			} else {
				attr_val = defread_r(attr_buf, defp);
			}
			if (attr_val == NULL)
				continue;

			got_config_data = TRUE;
			attrib_num = get_attrib_num(attr, strlen(attr));
			if (attrib_num == key_bad) {
				report_error(attr, NULL);
				rc = -1;
				break;
			}

			/*
			 * Allow either entries of the form
			 *	attr val
			 *	   or
			 *	attr = val
			 */
			while (is_whitespace(*attr_val))
				attr_val++;
			if (*attr_val == '=')
				attr_val++;
			while (is_whitespace(*attr_val))
				attr_val++;
			len = strlen(attr_val);
			while (len > 0 && is_whitespace(attr_val[len - 1]))
				len--;

			if (verbose) {
				report_info("\t", attr);
				report_info("\t\t", attr_val);
			}
			if (IS_BIND_INFO(attrib_num)) {
				rc = add_bind_attribute(attrib_num,
				    attr_val, len, proxy_info);
			} else if (IS_OPER_INFO(attrib_num)) {
				rc = add_operation_attribute(attrib_num,
				    attr_val, len, nis_config,
				    table_info);
			}
			if (p_error != no_parse_error) {
				report_error(attr_val, attr);
				rc = -1;
				break;
			}
		}
		file_source = NULL;
		/* Close the /etc/default file */
		defclose_r(defp);
	}
	return (rc);
}

static int
yp_parse_ldap_default_conf(
	__nis_ldap_proxy_info *proxy_info,
	__nis_config_t	*nis_config,
	__nis_config_info_t *config_info,
	__nisdb_table_mapping_t *table_info)
{
	int rc = 0;
	char		*ldap_config_attributes[n_config_keys];
	char		attr_buf[128];
	char		*attr;
	char		*attr_val;
	int		defflags;
	config_key	attrib_num;
	int 		i, len;
	void		*defp;

	if ((defp = defopen_r(YP_ETCCONFFILE)) != NULL) {
		file_source = YP_ETCCONFFILE;
		if (verbose)
			report_info("default configuration values: ", NULL);
		/* Set defread_r() to be case insensitive */
		defflags = defcntl_r(DC_GETFLAGS, 0, defp);
		TURNOFF(defflags, DC_CASE);
		(void) defcntl_r(DC_SETFLAGS, defflags, defp);

		get_attribute_list(proxy_info, nis_config, config_info,
		    table_info, ldap_config_attributes);
		i = 0;
		while ((attr = ldap_config_attributes[i++]) != NULL) {
			if ((strlcpy(attr_buf, attr, sizeof (attr_buf))) >=
			    sizeof (attr_buf)) {
				report_error(
				    "Static buffer attr_buf overflow", NULL);
				defclose_r(defp);
				return (-1);
			}

			if ((attr_val = defread_r(attr_buf, defp)) == NULL)
				continue;

			got_config_data = TRUE;
			attrib_num = get_attrib_num(attr, strlen(attr));
			if (attrib_num == key_bad) {
				report_error(attr, NULL);
				rc = -1;
				break;
			}

			/*
			 * Allow either entries of the form
			 * attr val
			 * or
			 * attr = val
			 */
			while (is_whitespace(*attr_val))
				attr_val++;
			if (*attr_val == '=')
				attr_val++;
			while (is_whitespace(*attr_val))
				attr_val++;
			len = strlen(attr_val);
			while (len > 0 && is_whitespace(attr_val[len - 1]))
				len--;

			if (verbose) {
				report_info("\t", attr);
				report_info("\t\t", attr_val);
			}
			if (IS_YP_BIND_INFO(attrib_num)) {
				rc = add_bind_attribute(attrib_num,
				    attr_val, len, proxy_info);
			} else if (IS_YP_OPER_INFO(attrib_num)) {
				rc = add_operation_attribute(attrib_num,
				    attr_val, len, nis_config,
				    table_info);
			}
			if (p_error != no_parse_error) {
				report_error(attr_val, attr);
				rc = -1;
				break;
			}
		}
		file_source = NULL;
		/* Close the /etc/default file */
		defclose_r(defp);
	}
	return (rc);
}

/*
 * FUNCTION:	get_attrib_num_cmdline
 *
 *	Parses the information for LDAP from the command line
 *	The form of the command line request is
 *		-x attribute=value
 *
 * RETURN VALUE:	0 on success, -1 on failure
 *
 * INPUT:		command line values
 */

static config_key
get_attrib_num_cmdline(
	const char	*s,
	const char 	**begin_s,
	const char 	**end_s)
{
	const char	*s_end		= s + strlen(s);
	const char	*equal_s;
	const char	*s1;
	config_key	attrib_num;

	while (s < s_end && is_whitespace(*s))
		s++;

	for (equal_s = s; equal_s < s_end; equal_s++)
		if (*equal_s == EQUAL_CHAR)
			break;

	if (equal_s == s_end) {
		p_error = parse_bad_command_line_attribute_format;
		return (key_bad);
	}

	for (s1 = equal_s; s1 > s && is_whitespace(s1[-1]); s1--)
		;

	if (s1 == s) {
		p_error = parse_bad_command_line_attribute_format;
		return (key_bad);
	}

	attrib_num = get_attrib_num(s, s1 - s);

	if (attrib_num != key_bad) {
		s1 = equal_s + 1;
		while (s1 < s_end && is_whitespace(*s1))
			s1++;
		*begin_s = s1;
		while (s_end > s1 && is_whitespace(s_end[-1]))
			s_end--;
		*end_s = s_end;
	}

	return (attrib_num);
}

/*
 * FUNCTION:	parse_ldap_config_file
 *
 *	Parses the information for LDAP from a configuration
 *	file. If no file is specified, /var/nis/NIS+LDAPmapping
 *	is used
 *
 * RETURN VALUE:	0 on success, -1 on failure
 *
 * INPUT:		configuration file name
 */

static int
parse_ldap_config_file(
	const char 		*config_file,
	__nis_ldap_proxy_info	*proxy_info,
	__nis_config_t		*nis_config,
	__nis_table_mapping_t	**table_mapping,
	__nis_config_info_t	*config_info,
	__nisdb_table_mapping_t	*table_info)
{
	int		rc = 0;
	config_key	attrib_num;
	int		fd;
	char		*attr_val;
	int		len;

	if ((fd = open(config_file, O_RDONLY)) == -1) {
		p_error = parse_open_file_error;
		report_error(config_file, NULL);
		return (-1);
	}

	start_line_num = 1;
	cur_line_num = 1;

	if (verbose)
		report_info("Reading configuration from ", config_file);

	file_source = config_file;
	while ((attrib_num = get_file_attr_val(fd, &attr_val)) > 0) {
		len = attr_val == NULL ? 0 : strlen(attr_val);
		if (IS_CONFIG_KEYWORD(attrib_num)) {
			rc = add_config_attribute(attrib_num,
			    attr_val, len, config_info);
		} else if (IS_BIND_INFO(attrib_num)) {
			rc = add_bind_attribute(attrib_num,
			    attr_val, len, proxy_info);
		} else if (IS_OPER_INFO(attrib_num)) {
			rc = add_operation_attribute(attrib_num,
			    attr_val, len, nis_config, table_info);
		} else {
			rc = add_mapping_attribute(attrib_num,
			    attr_val, len, table_mapping);
		}

		if (rc < 0) {
			report_error(attr_val == NULL ?
			    "<no attribute>" : attr_val, _key_val);
			if (attr_val)
				free(attr_val);
			break;
		}
		if (attr_val)
			free(attr_val);
	}

	(void) close(fd);
	if (attrib_num == key_bad) {
		report_error(_key_val, NULL);
		rc = -1;
	}
	start_line_num = 0;
	file_source = NULL;
	return (rc);
}

/*
 * FUNCTION:	yp_parse_ldap_config_file
 *
 * Parses the information for LDAP from a configuration
 * file. If no file is specified, /var/yp/NISLDAPmapping
 * is used
 *
 * RETURN VALUE:    0 on success, -1 on failure
 *
 * INPUT:       configuration file name
 */

int
yp_parse_ldap_config_file(
	const char	*config_file,
	__nis_ldap_proxy_info	*proxy_info,
	__nis_config_t			*nis_config,
	__nis_table_mapping_t	**table_mapping,
	__nis_config_info_t		*config_info,
	__nisdb_table_mapping_t	*table_info,
	__yp_domain_context_t	*ypDomains)
{
	int	rc = 0;
	config_key	attrib_num;
	int	fd;
	char	*attr_val = NULL;
	int		len;

	if ((fd = open(config_file, O_RDONLY)) == -1) {
		p_error = parse_open_file_error;
		report_error(config_file, NULL);
		return (-1);
	}

	start_line_num = 1;
	cur_line_num = 1;

	if (verbose)
		report_info("Reading configuration from ", config_file);

	file_source = config_file;
	while ((attrib_num = get_file_attr_val(fd, &attr_val)) > 0) {
		len = attr_val == NULL ? 0 : strlen(attr_val);
		if (IS_YP_CONFIG_KEYWORD(attrib_num)) {
			rc = add_config_attribute(attrib_num,
			    attr_val, len, config_info);
		} else if (IS_YP_BIND_INFO(attrib_num)) {
			rc = add_bind_attribute(attrib_num,
			    attr_val, len, proxy_info);
		} else if (IS_YP_OPER_INFO(attrib_num)) {
			rc = add_operation_attribute(attrib_num,
			    attr_val, len, nis_config, table_info);
		} else if (IS_YP_DOMAIN_INFO(attrib_num)) {
			rc = add_ypdomains_attribute(attrib_num,
			    attr_val, len, ypDomains);
		} else if (IS_YP_MAP_ATTR(attrib_num)) {
			rc = add_mapping_attribute(attrib_num,
			    attr_val, len, table_mapping);
		} else {
			rc = -1;
			p_error = parse_unsupported_format;
		}

		if (rc < 0) {
			report_error(attr_val == NULL ?
			    "<no attribute>" : attr_val, _key_val);
			if (attr_val)
				free(attr_val);
			break;
		}
		if (attr_val) {
			free(attr_val);
			attr_val = NULL;
		}
	}

	(void) close(fd);
	if (attrib_num == key_bad) {
		report_error(_key_val, NULL);
		rc = -1;
	}
	start_line_num = 0;
	file_source = NULL;
	return (rc);
}

/*
 * FUNCTION:	get_file_attr_val
 *
 *	Gets the next attribute from the configuration file.
 *
 * RETURN VALUE:	The config key if more attributes
 *			no_more_keys if eof
 *			key_bad if error
 */

static config_key
get_file_attr_val(int fd, char **attr_val)
{
	char		buf[BUFSIZE];
	char		*start_tag;
	char		*start_val;
	char		*end_val;
	char		*cut_here;
	char		*s;
	char		*a;
	char		*attribute_value;
	int		ret;
	config_key	attrib_num = no_more_keys;

	*attr_val = NULL;

	if ((ret = read_line(fd, buf, sizeof (buf))) > 0) {
		for (s = buf; is_whitespace(*s); s++)
			;

		start_tag = s;
		while (*s != '\0' && !is_whitespace(*s))
			s++;

		if (verbose)
			report_info("\t", start_tag);
		attrib_num = get_attrib_num(start_tag, s - start_tag);
		if (attrib_num == key_bad)
			return (key_bad);

		while (is_whitespace(*s))
			s++;
		if (*s == '\0')
			return (attrib_num);
		start_val = s;

		/* note that read_line will not return a line ending with \ */
		for (; *s != '\0'; s++) {
			if (*s == ESCAPE_CHAR)
				s++;
		}
		while (s > start_val && is_whitespace(s[-1]))
			s--;

		attribute_value =
		    calloc(1, (size_t)(s - start_val) + 1);
		if (attribute_value == NULL) {
			p_error = parse_no_mem_error;
			return (key_bad);
		}
		attr_val[0] = attribute_value;

		a = *attr_val;
		end_val = s;
		cut_here = 0;
		for (s = start_val; s < end_val; s++) {
			if (*s == POUND_SIGN) {
					cut_here = s;
					while (s < end_val) {
						if (*s == DOUBLE_QUOTE_CHAR ||
						    *s == SINGLE_QUOTE_CHAR) {
							cut_here = 0;
							break;
						}
						s++;
					}
			}
		}
		if (cut_here != 0)
			end_val = cut_here;

		for (s = start_val; s < end_val; s++)
			*a++ = *s;
		*a++ = '\0';
	}
	if (ret == -1)
		return (key_bad);

	return (attrib_num);
}

static LDAP *
connect_to_ldap_config_server(
	char			*sever_name,
	int			server_port,
	__nis_config_info_t	*config_info)
{
	LDAP		*ld		= NULL;
	int		ldapVersion	= LDAP_VERSION3;
	int		derefOption	= LDAP_DEREF_ALWAYS;
	int		timelimit	= LDAP_NO_LIMIT;
	int		sizelimit	= LDAP_NO_LIMIT;
	int		errnum;
	bool_t		retrying	= FALSE;
	int		sleep_seconds	= 1;
	struct berval	cred;

	if (config_info->tls_method == no_tls) {
		ld = ldap_init(sever_name, server_port);
		if (ld == NULL) {
			p_error = parse_ldap_init_error;
			report_error(strerror(errno), NULL);
			return (NULL);
		}
	} else {
		if ((errnum = ldapssl_client_init(
		    config_info->tls_cert_db, NULL)) < 0) {
			p_error = parse_ldapssl_client_init_error;
			report_error(ldapssl_err2string(errnum), NULL);
			return (NULL);
		}
		ld = ldapssl_init(sever_name, server_port, 1);
		if (ld == NULL) {
			p_error = parse_ldapssl_init_error;
			report_error(strerror(errno), NULL);
			return (NULL);
		}
	}

	(void) ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION,
	    &ldapVersion);
	(void) ldap_set_option(ld, LDAP_OPT_DEREF, &derefOption);
	(void) ldap_set_option(ld, LDAP_OPT_REFERRALS, LDAP_OPT_OFF);
	(void) ldap_set_option(ld, LDAP_OPT_TIMELIMIT, &timelimit);
	(void) ldap_set_option(ld, LDAP_OPT_SIZELIMIT, &sizelimit);

	/*
	 * Attempt to bind to the LDAP server.
	 * We will loop until success or until an error other
	 * than LDAP_CONNECT_ERROR or LDAP_SERVER_DOWN
	 */
	if (verbose)
		report_info("Connecting to ", sever_name);

	for (;;) {
		if (config_info->auth_method == simple) {
			errnum = ldap_simple_bind_s(ld, config_info->proxy_dn,
			    config_info->proxy_passwd);
		} else if (config_info->auth_method == cram_md5) {
			cred.bv_len = strlen(config_info->proxy_passwd);
			cred.bv_val = config_info->proxy_passwd;
			errnum = ldap_sasl_cram_md5_bind_s(ld,
			    config_info->proxy_dn, &cred, NULL, NULL);
		} else if (config_info->auth_method == digest_md5) {
			cred.bv_len = strlen(config_info->proxy_passwd);
			cred.bv_val = config_info->proxy_passwd;
			errnum = ldap_x_sasl_digest_md5_bind_s(ld,
			    config_info->proxy_dn, &cred, NULL, NULL);
		} else {
			errnum = ldap_simple_bind_s(ld, NULL, NULL);
		}

		if (errnum == LDAP_SUCCESS)
			break;

		if (errnum == LDAP_CONNECT_ERROR ||
		    errnum == LDAP_SERVER_DOWN) {
			if (!retrying) {
				if (verbose)
					report_info(
					"LDAP server unavailable. Retrying...",
					    NULL);
				retrying = TRUE;
			}
			(void) sleep(sleep_seconds);
			sleep_seconds *= 2;
			if (sleep_seconds > MAX_LDAP_CONFIG_RETRY_TIME)
				sleep_seconds = MAX_LDAP_CONFIG_RETRY_TIME;
			p_error = no_parse_error;
			continue;
		}
		p_error = parse_ldap_bind_error;
		report_error2(config_info->proxy_dn, ldap_err2string(errnum));
		(void) ldap_unbind(ld);
		return (NULL);
	}

	if (verbose)
		report_info("Reading values from ", config_info->config_dn);

	return (ld);
}

/*
 * FUNCTION:	process_ldap_config_result
 *
 *	Extracts the LDAPMessage containing the nis+/LDAP
 *	configuration
 *
 * RETURN VALUE:	0 on success, -1 on failure
 *
 * INPUT:		LDAP		the LDAP connection
 *			LDAPMessage	the LDAP message
 */

static int
process_ldap_config_result(
	LDAP			*ld,
	LDAPMessage		*resultMsg,
	__nis_ldap_proxy_info	*proxy_info,
	__nis_config_t		*nis_config,
	__nis_table_mapping_t	**table_mapping,
	__nisdb_table_mapping_t	*table_info)
{
	LDAPMessage	*e;
	int		errnum;
	char		*attr;
	BerElement	*ber		= NULL;
	config_key	attrib_num;
	char		**vals;
	int		n;
	int		i;
	char		*attr_val;
	int		len;
	int		rc = 0;
	bool_t		error_reported	= FALSE;

	e = ldap_first_entry(ld, resultMsg);

	if (e != NULL) {
		for (attr = ldap_first_attribute(ld, e, &ber); attr != NULL;
		    attr = ldap_next_attribute(ld, e, ber)) {
			if (verbose)
				report_info("\t", attr);
			attrib_num = get_attrib_num(attr, strlen(attr));
			if (attrib_num == key_bad) {
				report_error(attr, NULL);
				break;
			}
			if ((vals = ldap_get_values(ld, e, attr)) != NULL) {
				n = ldap_count_values(vals);
				/* parse the attribute values */
				for (i = 0; i < n; i++) {
					attr_val = vals[i];
					while (is_whitespace(*attr_val))
						attr_val++;
					if (verbose)
						report_info("\t\t", attr_val);
					len = strlen(attr_val);
					while (len > 0 &&
					    is_whitespace(attr_val[len - 1]))
						len--;
		if (yp2ldap) {
			if (IS_YP_BIND_INFO(attrib_num)) {
				rc = add_bind_attribute(attrib_num, attr_val,
				    len, proxy_info);
			} else if (IS_YP_OPER_INFO(attrib_num)) {
				rc = add_operation_attribute(attrib_num,
				    attr_val, len, nis_config, table_info);
			} else if (IS_YP_MAP_ATTR(attrib_num)) {
				rc = add_mapping_attribute(attrib_num, attr_val,
				    len, table_mapping);
			} else {
				p_error = parse_unsupported_format;
			}
		} else {
			if (IS_BIND_INFO(attrib_num)) {
				rc = add_bind_attribute(attrib_num, attr_val,
				    len, proxy_info);
			} else if (IS_OPER_INFO(attrib_num)) {
				rc = add_operation_attribute(attrib_num,
				    attr_val, len, nis_config, table_info);
			} else {
				rc = add_mapping_attribute(attrib_num, attr_val,
				    len, table_mapping);
			}
		}
					if (p_error != no_parse_error) {
						report_error(attr_val, attr);
						error_reported = TRUE;
						break;
					}
				}
				ldap_value_free(vals);
			} else {
				(void) ldap_get_option(ld,
				    LDAP_OPT_ERROR_NUMBER, &errnum);
				if (errnum != LDAP_SUCCESS)
					p_error = parse_ldap_get_values_error;
			}
			ldap_memfree(attr);
			if (p_error != no_parse_error)
				break;
		}
	} else {
		errnum = ldap_result2error(ld, resultMsg, FALSE);
		if (errnum != LDAP_SUCCESS)
			p_error = parse_ldap_search_error;
	}
	if (ber != NULL)
		ber_free(ber, 0);

	if (!error_reported && p_error != no_parse_error) {
		report_error(ldap_err2string(errnum), 0);
	}

	if (p_error != no_parse_error)
		rc = -1;
	return (rc);
}

/*
 * FUNCTION:	process_ldap_referral
 *
 *	Retrieves the configuration for a referral url
 *
 * RETURN VALUE:	0 on success, -1 on failure, 1 on skip
 *
 * INPUT:		url		the ldap url
 *			__nis_ldap_proxy_info
 */

static int
process_ldap_referral(
	char			*url,
	char			**attrs,
	__nis_ldap_proxy_info	*proxy_info,
	__nis_config_t		*nis_config,
	__nis_table_mapping_t	**table_mapping,
	__nis_config_info_t	*config_info,
	__nisdb_table_mapping_t	*table_info)
{
	LDAPURLDesc	*ludpp		= NULL;
	int		rc;
	LDAP		*ld		= NULL;
	int		errnum;
	LDAPMessage	*resultMsg	= NULL;

	if ((rc = ldap_url_parse(url, &ludpp)) != LDAP_SUCCESS)
		return (1);

#ifdef LDAP_URL_OPT_SECURE
	if (ludpp->lud_options & LDAP_URL_OPT_SECURE) {
		if (config_info->tls_method != ssl_tls) {
			ldap_free_urldesc(ludpp);
			return (1);
		}
	} else {
		if (config_info->tls_method != no_tls) {
			ldap_free_urldesc(ludpp);
			return (1);
		}
	}
#endif

	if ((ld = connect_to_ldap_config_server(ludpp->lud_host,
	    ludpp->lud_port, config_info)) == NULL) {
		ldap_free_urldesc(ludpp);
		return (-1);
	}

	errnum = ldap_search_s(ld, config_info->config_dn, LDAP_SCOPE_BASE,
	    "objectclass=nisplusLDAPconfig", attrs, 0, &resultMsg);

	ldap_source = config_info->config_dn;

	if (errnum != LDAP_SUCCESS) {
		p_error = parse_ldap_search_error;
		report_error(ldap_err2string(errnum), 0);
		rc = -1;
	} else {
		rc = process_ldap_config_result(ld, resultMsg, proxy_info,
		    nis_config, table_mapping, table_info);
	}

	ldap_source = NULL;
	(void) ldap_unbind(ld);
	if (resultMsg != NULL)
		(void) ldap_msgfree(resultMsg);

	return (rc);
}

/*
 * FUNCTION:	process_ldap_referral_msg
 *
 *	Retrieves the configuration from referred servers
 *
 * RETURN VALUE:	0 on success, -1 on failure
 *
 * INPUT:		LDAP		the LDAP connection
 *			LDAPMessage	the LDAP message
 *			__nis_ldap_proxy_info
 */

static int
process_ldap_referral_msg(
	LDAP			*ld,
	LDAPMessage		*resultMsg,
	char			**attrs,
	__nis_ldap_proxy_info	*proxy_info,
	__nis_config_t		*nis_config,
	__nis_table_mapping_t	**table_mapping,
	__nis_config_info_t	*config_info,
	__nisdb_table_mapping_t	*table_info)
{
	int	errCode;
	char	**referralsp	= NULL;
	int	i;
	int	rc;

	rc = ldap_parse_result(ld, resultMsg, &errCode, NULL, NULL, &referralsp,
	    NULL, 0);

	if (rc != LDAP_SUCCESS || errCode != LDAP_REFERRAL) {
		p_error = parse_ldap_get_values_error;
		report_error(ldap_err2string(errCode), 0);
		rc = -1;
	} else {
		for (i = 0; referralsp[i] != NULL; i++) {
			rc = process_ldap_referral(referralsp[i], attrs,
			    proxy_info, nis_config, table_mapping,
			    config_info, table_info);
			if (rc <= 0)
				break;
			else
				report_info("Cannot use referral \n",
				    referralsp[i]);

		}
		if (rc > 0) {
			p_error = parse_no_available_referrals_error;
			report_error(0, 0);
		}
	}

	if (referralsp)
		ldap_value_free(referralsp);

	return (rc);
}

/*
 * FUNCTION:	parse_ldap_config_dn_attrs
 *
 *	Parses the information for LDAP from the LDAP profile
 *	- the profile object name, the LDAP server, and the
 *	authentication method must be specified.
 *
 * RETURN VALUE:	0 on success, -1 on failure
 *
 * INPUT:		__nis_ldap_proxy_info
 */

static int
parse_ldap_config_dn_attrs(
	__nis_ldap_proxy_info	*proxy_info,
	__nis_config_t		*nis_config,
	__nis_table_mapping_t	**table_mapping,
	__nis_config_info_t	*config_info,
	__nisdb_table_mapping_t	*table_info)
{
	int		rc		= 0;
	LDAP		*ld		= NULL;
	int		errnum;
	char		*ldap_config_attributes[n_config_keys];
	LDAPMessage	*resultMsg	= NULL;

	/* Determine if properly configured for LDAP lookup */
	if (config_info->auth_method == simple &&
	    config_info->proxy_dn == NULL)
		p_error = parse_no_proxy_dn_error;
	else if (config_info->auth_method ==
	    (auth_method_t)NO_VALUE_SET)
		p_error = parse_no_config_auth_error;
	else if ((config_info->default_servers == NULL) ||
	    (config_info->default_servers[0] == '\0'))
		p_error = parse_no_config_server_addr;
	if (p_error != no_parse_error) {
		report_error(NULL, NULL);
		return (-1);
	}

	if (config_info->tls_method == (tls_method_t)NO_VALUE_SET)
		config_info->tls_method = no_tls;
	else if (config_info->tls_method == ssl_tls &&
	    (config_info->tls_cert_db == NULL ||
	    *config_info->tls_cert_db == '\0')) {
		p_error = parse_no_config_cert_db;
		report_error(NULL, NULL);
		return (-1);
	}

	if (verbose)
		report_info(
		    "Getting configuration from LDAP server(s): ",
		    config_info->default_servers);

	/* Determine which attributes should be retrieved */
	get_attribute_list(proxy_info, nis_config, NULL, table_info,
	    ldap_config_attributes);

	if ((ld = connect_to_ldap_config_server(config_info->default_servers, 0,
	    config_info)) == NULL)
		return (-1);

	/* Get the attribute values */
	errnum = ldap_search_s(ld, config_info->config_dn, LDAP_SCOPE_BASE,
	    "objectclass=nisplusLDAPconfig",
	    ldap_config_attributes, 0, &resultMsg);
	ldap_source = config_info->config_dn;

	if (errnum == LDAP_REFERRAL) {
		rc = process_ldap_referral_msg(ld, resultMsg,
		    ldap_config_attributes, proxy_info, nis_config,
		    table_mapping, config_info, table_info);
	} else if (errnum != LDAP_SUCCESS) {
		p_error = parse_ldap_search_error;
		report_error(ldap_err2string(errnum), 0);
		rc = -1;
	} else {
		rc = process_ldap_config_result(ld, resultMsg, proxy_info,
		    nis_config, table_mapping, table_info);
	}

	ldap_source = NULL;
	(void) ldap_unbind(ld);
	if (resultMsg != NULL)
		(void) ldap_msgfree(resultMsg);

	return (rc);
}

bool_t
is_cmd_line_option(config_key a_num)
{
	const char *const	*cmdline_options = cmdline_config;
	config_key		attrib_num;
	const char		*begin_s;
	const char		*end_s;

	if (cmdline_options == NULL)
		return (FALSE);

	while (*cmdline_options != NULL) {
		attrib_num = get_attrib_num_cmdline(
		    *cmdline_options, &begin_s, &end_s);
		if (attrib_num == a_num)
			break;
		cmdline_options++;
	}
	return (*cmdline_options != NULL);
}

/*
 * FUNCTION:	get_attribute_list
 *
 *	Get a list of attributes from the LDAP server that have not yet
 *	been gotten. If config_info is NULL, the associated parameters
 *	are not needed.
 *
 * RETURN VALUE:	none
 *
 * INPUT:		Returns a list of parameters in attributes
 *			which is assumed to be of sufficient size.
 */

static void
get_attribute_list(
	const __nis_ldap_proxy_info	*proxy_info,
	const __nis_config_t		*nis_config,
	const __nis_config_info_t	*config_info,
	const __nisdb_table_mapping_t	*table_info,
	char				**attributes)
{
	int		n_attrs;

	/* Determine which attributes should be retrieved */
	n_attrs = 0;

	if (config_info != NULL) {
		if (yp2ldap) {
			if (config_info->config_dn == NULL)
				attributes[n_attrs++] = YP_CONFIG_DN;
			if (config_info->default_servers == NULL)
				attributes[n_attrs++] = YP_CONFIG_SERVER_LIST;
			if (config_info->auth_method ==
			    (auth_method_t)NO_VALUE_SET)
				attributes[n_attrs++] = YP_CONFIG_AUTH_METHOD;
			if (config_info->tls_method ==
			    (tls_method_t)NO_VALUE_SET)
				attributes[n_attrs++] = YP_CONFIG_TLS_OPTION;
			if (config_info->proxy_dn == NULL)
				attributes[n_attrs++] = YP_CONFIG_PROXY_USER;
			if (config_info->proxy_passwd == NULL)
				attributes[n_attrs++] = YP_CONFIG_PROXY_PASSWD;
			if (config_info->tls_cert_db == NULL)
				attributes[n_attrs++] = YP_CONFIG_TLS_CERT_DB;
		} else {
			if (config_info->config_dn == NULL)
				attributes[n_attrs++] = CONFIG_DN;
			if (config_info->default_servers == NULL)
				attributes[n_attrs++] = CONFIG_SERVER_LIST;
			if (config_info->auth_method ==
			    (auth_method_t)NO_VALUE_SET)
				attributes[n_attrs++] = CONFIG_AUTH_METHOD;
			if (config_info->tls_method ==
			    (tls_method_t)NO_VALUE_SET)
				attributes[n_attrs++] = CONFIG_TLS_OPTION;
			if (config_info->proxy_dn == NULL)
				attributes[n_attrs++] = CONFIG_PROXY_USER;
			if (config_info->proxy_passwd == NULL)
				attributes[n_attrs++] = CONFIG_PROXY_PASSWD;
			if (config_info->tls_cert_db == NULL)
				attributes[n_attrs++] = CONFIG_TLS_CERT_DB;
		}
	} else {
		if (yp2ldap) {
			attributes[n_attrs++] = YP_DOMAIN_CONTEXT;
			attributes[n_attrs++] = YPPASSWDD_DOMAINS;
			attributes[n_attrs++] = YP_DB_ID_MAP;
			attributes[n_attrs++] = YP_COMMENT_CHAR;
			attributes[n_attrs++] = YP_MAP_FLAGS;
			attributes[n_attrs++] = YP_ENTRY_TTL;
			attributes[n_attrs++] = YP_NAME_FIELDS;
			attributes[n_attrs++] = YP_SPLIT_FIELD;
			attributes[n_attrs++] = YP_REPEATED_FIELD_SEPARATORS;
			attributes[n_attrs++] = YP_LDAP_OBJECT_DN;
			attributes[n_attrs++] = NIS_TO_LDAP_MAP;
			attributes[n_attrs++] = LDAP_TO_NIS_MAP;
		} else {
			attributes[n_attrs++] = DB_ID_MAP;
			attributes[n_attrs++] = ENTRY_TTL;
			attributes[n_attrs++] = LDAP_OBJECT_DN;
			attributes[n_attrs++] = NISPLUS_TO_LDAP_MAP;
			attributes[n_attrs++] = LDAP_TO_NISPLUS_MAP;
		}
	}

	if (yp2ldap) {
		if (proxy_info->default_servers == NULL)
			attributes[n_attrs++] = PREFERRED_SERVERS;
		if (proxy_info->auth_method == (auth_method_t)NO_VALUE_SET)
			attributes[n_attrs++] = AUTH_METHOD;
		if (proxy_info->tls_method == (tls_method_t)NO_VALUE_SET)
			attributes[n_attrs++] = YP_TLS_OPTION;
		if (proxy_info->tls_cert_db == NULL)
			attributes[n_attrs++] = YP_TLS_CERT_DB;
		if (proxy_info->default_search_base == NULL)
			attributes[n_attrs++] = SEARCH_BASE;
		if (proxy_info->proxy_dn == NULL)
			attributes[n_attrs++] = YP_PROXY_USER;
		if (proxy_info->proxy_passwd == NULL)
			attributes[n_attrs++] = YP_PROXY_PASSWD;
		if (proxy_info->default_nis_domain == NULL)
			attributes[n_attrs++] = YP_LDAP_BASE_DOMAIN;
		if (proxy_info->bind_timeout.tv_sec ==
		    (time_t)NO_VALUE_SET)
			attributes[n_attrs++] = YP_BIND_TIMEOUT;
		if (proxy_info->search_timeout.tv_sec ==
		    (time_t)NO_VALUE_SET)
			attributes[n_attrs++] = YP_SEARCH_TIMEOUT;
		if (proxy_info->modify_timeout.tv_sec ==
		    (time_t)NO_VALUE_SET)
			attributes[n_attrs++] = YP_MODIFY_TIMEOUT;
		if (proxy_info->add_timeout.tv_sec == (time_t)NO_VALUE_SET)
			attributes[n_attrs++] = YP_ADD_TIMEOUT;
		if (proxy_info->delete_timeout.tv_sec ==
		    (time_t)NO_VALUE_SET)
			attributes[n_attrs++] = YP_DELETE_TIMEOUT;
		if (proxy_info->search_time_limit == (int)NO_VALUE_SET)
			attributes[n_attrs++] = YP_SEARCH_TIME_LIMIT;
		if (proxy_info->search_size_limit == (int)NO_VALUE_SET)
			attributes[n_attrs++] = YP_SEARCH_SIZE_LIMIT;
		if (proxy_info->follow_referral ==
		    (follow_referral_t)NO_VALUE_SET)
			attributes[n_attrs++] = YP_FOLLOW_REFERRAL;

		if (table_info->retrieveError ==
		    (__nis_retrieve_error_t)NO_VALUE_SET)
			attributes[n_attrs++] = YP_RETRIEVE_ERROR_ACTION;
		if (table_info->retrieveErrorRetry.attempts == NO_VALUE_SET)
			attributes[n_attrs++] = YP_RETREIVE_ERROR_ATTEMPTS;
		if (table_info->retrieveErrorRetry.timeout ==
		    (time_t)NO_VALUE_SET)
			attributes[n_attrs++] = YP_RETREIVE_ERROR_TIMEOUT;
		if (table_info->storeError ==
		    (__nis_store_error_t)NO_VALUE_SET)
			attributes[n_attrs++] = YP_STORE_ERROR_ACTION;
		if (table_info->storeErrorRetry.attempts == NO_VALUE_SET)
			attributes[n_attrs++] = YP_STORE_ERROR_ATTEMPTS;
		if (table_info->storeErrorRetry.timeout ==
		    (time_t)NO_VALUE_SET)
			attributes[n_attrs++] = YP_STORE_ERROR_TIMEOUT;
		if (table_info->refreshError ==
		    (__nis_refresh_error_t)NO_VALUE_SET)
			attributes[n_attrs++] = REFRESH_ERROR_ACTION;
		if (table_info->refreshErrorRetry.attempts == NO_VALUE_SET)
			attributes[n_attrs++] = REFRESH_ERROR_ATTEMPTS;
		if (table_info->refreshErrorRetry.timeout ==
		    (time_t)NO_VALUE_SET)
			attributes[n_attrs++] = REFRESH_ERROR_TIMEOUT;
		if (table_info->matchFetch ==
		    (__nis_match_fetch_t)NO_VALUE_SET)
			attributes[n_attrs++] = YP_MATCH_FETCH;
	} else {
		if (proxy_info->default_servers == NULL)
			attributes[n_attrs++] = PREFERRED_SERVERS;
		if (proxy_info->auth_method == (auth_method_t)NO_VALUE_SET)
			attributes[n_attrs++] = AUTH_METHOD;
		if (proxy_info->tls_method == (tls_method_t)NO_VALUE_SET)
			attributes[n_attrs++] = TLS_OPTION;
		if (proxy_info->tls_cert_db == NULL)
			attributes[n_attrs++] = TLS_CERT_DB;
		if (proxy_info->default_search_base == NULL)
			attributes[n_attrs++] = SEARCH_BASE;
		if (proxy_info->proxy_dn == NULL)
			attributes[n_attrs++] = PROXY_USER;
		if (proxy_info->proxy_passwd == NULL)
			attributes[n_attrs++] = PROXY_PASSWD;
		if (proxy_info->default_nis_domain == NULL)
			attributes[n_attrs++] = LDAP_BASE_DOMAIN;
		if (proxy_info->bind_timeout.tv_sec ==
		    (time_t)NO_VALUE_SET)
			attributes[n_attrs++] = BIND_TIMEOUT;
		if (proxy_info->search_timeout.tv_sec ==
		    (time_t)NO_VALUE_SET)
			attributes[n_attrs++] = SEARCH_TIMEOUT;
		if (proxy_info->modify_timeout.tv_sec ==
		    (time_t)NO_VALUE_SET)
			attributes[n_attrs++] = MODIFY_TIMEOUT;
		if (proxy_info->add_timeout.tv_sec == (time_t)NO_VALUE_SET)
			attributes[n_attrs++] = ADD_TIMEOUT;
		if (proxy_info->delete_timeout.tv_sec ==
		    (time_t)NO_VALUE_SET)
			attributes[n_attrs++] = DELETE_TIMEOUT;
		if (proxy_info->search_time_limit == (int)NO_VALUE_SET)
			attributes[n_attrs++] = SEARCH_TIME_LIMIT;
		if (proxy_info->search_size_limit == (int)NO_VALUE_SET)
			attributes[n_attrs++] = SEARCH_SIZE_LIMIT;
		if (proxy_info->follow_referral ==
		    (follow_referral_t)NO_VALUE_SET)
			attributes[n_attrs++] = FOLLOW_REFERRAL;

		if (table_info->retrieveError ==
		    (__nis_retrieve_error_t)NO_VALUE_SET)
			attributes[n_attrs++] = RETRIEVE_ERROR_ACTION;
		if (table_info->retrieveErrorRetry.attempts == NO_VALUE_SET)
			attributes[n_attrs++] = RETREIVE_ERROR_ATTEMPTS;
		if (table_info->retrieveErrorRetry.timeout ==
		    (time_t)NO_VALUE_SET)
			attributes[n_attrs++] = RETREIVE_ERROR_TIMEOUT;
		if (table_info->storeError ==
		    (__nis_store_error_t)NO_VALUE_SET)
			attributes[n_attrs++] = STORE_ERROR_ACTION;
		if (table_info->storeErrorRetry.attempts == NO_VALUE_SET)
			attributes[n_attrs++] = STORE_ERROR_ATTEMPTS;
		if (table_info->storeErrorRetry.timeout ==
		    (time_t)NO_VALUE_SET)
			attributes[n_attrs++] = STORE_ERROR_TIMEOUT;
		if (table_info->refreshError ==
		    (__nis_refresh_error_t)NO_VALUE_SET)
			attributes[n_attrs++] = REFRESH_ERROR_ACTION;
		if (table_info->refreshErrorRetry.attempts == NO_VALUE_SET)
			attributes[n_attrs++] = REFRESH_ERROR_ATTEMPTS;
		if (table_info->refreshErrorRetry.timeout ==
		    (time_t)NO_VALUE_SET)
			attributes[n_attrs++] = REFRESH_ERROR_TIMEOUT;
		if (table_info->matchFetch ==
		    (__nis_match_fetch_t)NO_VALUE_SET)
			attributes[n_attrs++] = MATCH_FETCH;
	}

	switch (nis_config->initialUpdate) {
	case (__nis_initial_update_t)NO_VALUE_SET:
		attributes[n_attrs++] = INITIAL_UPDATE_ACTION;
		attributes[n_attrs++] = INITIAL_UPDATE_ONLY;
		break;
	case (__nis_initial_update_t)INITIAL_UPDATE_NO_ACTION:
	case (__nis_initial_update_t)NO_INITIAL_UPDATE_NO_ACTION:
		attributes[n_attrs++] = INITIAL_UPDATE_ACTION;
		break;
	case (__nis_initial_update_t)FROM_NO_INITIAL_UPDATE:
	case (__nis_initial_update_t)TO_NO_INITIAL_UPDATE:
		attributes[n_attrs++] = INITIAL_UPDATE_ONLY;
		break;
	}

	if (nis_config->threadCreationError ==
	    (__nis_thread_creation_error_t)NO_VALUE_SET)
		attributes[n_attrs++] = THREAD_CREATE_ERROR_ACTION;
	if (nis_config->threadCreationErrorTimeout.attempts == NO_VALUE_SET)
		attributes[n_attrs++] = THREAD_CREATE_ERROR_ATTEMPTS;
	if (nis_config->threadCreationErrorTimeout.timeout ==
	    (time_t)NO_VALUE_SET)
		attributes[n_attrs++] = THREAD_CREATE_ERROR_TIMEOUT;
	if (nis_config->dumpError == (__nis_dump_error_t)NO_VALUE_SET)
		attributes[n_attrs++] = DUMP_ERROR_ACTION;
	if (nis_config->dumpErrorTimeout.attempts == NO_VALUE_SET)
		attributes[n_attrs++] = DUMP_ERROR_ATTEMPTS;
	if (nis_config->dumpErrorTimeout.timeout == (time_t)NO_VALUE_SET)
		attributes[n_attrs++] = DUMP_ERROR_TIMEOUT;
	if (nis_config->resyncService == (__nis_resync_service_t)NO_VALUE_SET)
		attributes[n_attrs++] = RESYNC;
	if (nis_config->updateBatching ==
	    (__nis_update_batching_t)NO_VALUE_SET)
		attributes[n_attrs++] = UPDATE_BATCHING;
	if (nis_config->updateBatchingTimeout.timeout == (time_t)NO_VALUE_SET)
		attributes[n_attrs++] = UPDATE_BATCHING_TIMEOUT;
	if (nis_config->numberOfServiceThreads == (int)NO_VALUE_SET)
		attributes[n_attrs++] = NUMBER_THEADS;
	if (nis_config->emulate_yp == (int)NO_VALUE_SET)
		attributes[n_attrs++] = YP_EMULATION;

	/* maxRPCRecordSize is not configurable through LDAP profiles */
	if (nis_config->maxRPCRecordSize == (int)NO_VALUE_SET)
		attributes[n_attrs++] = MAX_RPC_RECSIZE;

	attributes[n_attrs++] = NULL;
}

/*
 *	Notes on adding new attributes
 *	1. Determine where the attribute value will be saved
 *	    Currently, the following structures are defined:
 *		__nis_config_info_t	config_info
 *		__nis_ldap_proxy_info	proxyInfo
 *		__nis_config_t		ldapConfig
 *		__nisdb_table_mapping_t	ldapDBTableMapping
 *		__nis_table_mapping_t	ldapTableMapping
 *	    or add a new structure or variable - this will require
 *	    more code.
 *	2. Initialize the value to a known unconfigured value.
 *	    This can be done in initialize_parse_structs or
 *	    parse_ldap_migration.
 *	3. In the header file nis_parse_ldap_conf.h, add the name
 *	    of the attribute. (Currently, the attribute name is assumed
 *	    to be the same for the command line, the preference file,
 *	    and LDAP.) The names are grouped logically. Add a corresponding
 *	    config_key to the enum. Note that position in this file is
 *	    essential because the macros such as IS_BIND_INFO depend on
 *	    the sequence. The corresponding macro (IS_CONFIG_KEYWORD,
 *	    IS_BIND_INFO, or IS_OPER_INFO) may need to be adjusted. These
 *	    are used to partition the attributes into smaller chunks.
 *	4. Add the correspond entry to the keyword_lookup array in
 *	    nis_parse_ldap_attr.c, which is used to determine the config_key
 *	    from the corresponding key word.
 *	5. Add the attribute to the list of attributes to retrieve from
 *	    the LDAP server if no value has been set in the function
 *	    parse_ldap_config_dn_attrs. (This assumes that the attribute
 *	    is not used to get the configuration from the LDAP server.)
 *	6. Add logic to parse the individual attribute in
 *	    add_config_attribute, add_bind_attribute,
 *	    add_operation_attribute, or add_mapping_attribute depending
 *	    which group of attributes the added attribute belongs to.
 *	7. In set_default_values, if the attribute value has not been set, set
 *	    the default value. If any additional fixup is needed depending
 *	    on other configuration values, it should be done here.
 *	8. If an attribute name is a subset of another, parse_ldap_default_conf
 *          should be modified.
 */
