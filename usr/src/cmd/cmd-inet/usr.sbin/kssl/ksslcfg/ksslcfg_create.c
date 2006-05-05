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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"


#include <libscf.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <sys/types.h>
#include "ksslcfg.h"

void
usage_create(boolean_t do_print)
{
	if (do_print)
		(void) fprintf(stderr, gettext("Usage:\n"));
	(void) fprintf(stderr, "ksslcfg create"
		" -f pkcs11 [-d softtoken_directory] -T <token_label>"
		" -C <certificate_label> -x <proxy_port>"
		" [-h <ca_certchain_file>]"
		" [options] [<server_address>] <server_port>\n");

	(void) fprintf(stderr, "ksslcfg create"
		" -f pkcs12 -i <cert_and_key_pk12file> -x <proxy_port>"
		" [options] [<server_address>] <server_port>\n");

	(void) fprintf(stderr, "ksslcfg create"
		" -f pem -i <cert_and_key_pemfile> -x <proxy_port>"
		" [options] [<server_address>] <server_port>\n");

	(void) fprintf(stderr, gettext("options are:\n"));
	(void) fprintf(stderr, "\t[-c <ciphersuites>]\n"
		"\t[-p <password_file>]\n"
		"\t[-t <ssl_session_cache_timeout>]\n"
		"\t[-u <username>]\n"
		"\t[-z <ssl_session_cache_size>]\n"
		"\t[-v]\n");
}

static scf_propertygroup_t *
add_property_group_to_instance(scf_handle_t *handle, scf_instance_t *instance,
    const char *pg_name, const char *pg_type)
{
	scf_propertygroup_t *pg;

	pg = scf_pg_create(handle);
	if (pg == NULL) {
		KSSL_DEBUG("scf_pg_create failed: %s\n",
		    scf_strerror(scf_error()));
		(void) fprintf(stderr, gettext(
		    "Unexpected fatal libscf error: %s. Exiting.\n"),
		    scf_strerror(scf_error()));
		return (NULL);
	}

	if (scf_instance_add_pg(instance, pg_name, pg_type, 0, pg) != 0) {
		KSSL_DEBUG("ERROR: scf_instance_add_pg failed: %s\n",
		    scf_strerror(scf_error()));
		if (scf_error() == SCF_ERROR_EXISTS)
			(void) fprintf(stderr, gettext(
			    "Error: another process is modifying this instance."
			    " Exiting.\n"));
		else
			(void) fprintf(stderr, gettext(
			    "Unexpected fatal libscf error: %s. Exiting.\n"),
			    scf_strerror(scf_error()));
		scf_pg_destroy(pg);
		return (NULL);
	} else {
		KSSL_DEBUG("property group created\n");
	}

	return (pg);
}

static int
add_new_property(scf_handle_t *handle, const char *prop_name,
    scf_type_t type, const char *val, scf_transaction_t *tx)
{
	scf_value_t *value = NULL;
	scf_transaction_entry_t *entry = NULL;
	int status = FAILURE;

	entry = scf_entry_create(handle);
	if (entry == NULL) {
		KSSL_DEBUG("scf_entry_create failed: %s\n",
		    scf_strerror(scf_error()));
		goto out;
	}
	KSSL_DEBUG("scf_entry_create succeeded\n");

	value = scf_value_create(handle);
	if (value == NULL) {
		goto out;
	}
	KSSL_DEBUG("scf_value_create succeeded\n");

	if (scf_transaction_property_new(tx, entry, prop_name, type) != 0) {
		goto out;
	}
	KSSL_DEBUG("scf_transaction_property_new succeeded\n");

	if (scf_value_set_from_string(value, type, val) != 0) {
		goto out;
	}
	KSSL_DEBUG("scf_value_set_from_string \'%s\' succeeded\n", val);

	if (scf_entry_add_value(entry, value) != 0) {
		KSSL_DEBUG(
		    "scf_entry_add_value failed: %s\n",
		    scf_strerror(scf_error()));
		goto out;
	}
	KSSL_DEBUG("scf_entry_add_value succeeded\n");

	status = SUCCESS;

out:
	if (status != SUCCESS)
		(void) fprintf(stderr, gettext(
		    "Unexpected fatal libscf error: %s. Exiting.\n"),
		    scf_strerror(scf_error()));
	return (status);
}

static int
set_method_context(scf_handle_t *handle, scf_transaction_t *tran,
    const char *value_str)
{
	if ((add_new_property(handle, SCF_PROPERTY_USE_PROFILE,
		SCF_TYPE_BOOLEAN, "false", tran) != SUCCESS) ||
	    (add_new_property(handle, SCF_PROPERTY_USER, SCF_TYPE_ASTRING,
		value_str, tran) != SUCCESS) ||
	    (add_new_property(handle, SCF_PROPERTY_GROUP, SCF_TYPE_ASTRING,
		":default", tran) != SUCCESS) ||
	    (add_new_property(handle, SCF_PROPERTY_LIMIT_PRIVILEGES,
		SCF_TYPE_ASTRING, ":default", tran) != SUCCESS) ||
	    (add_new_property(handle, SCF_PROPERTY_WORKING_DIRECTORY,
		SCF_TYPE_ASTRING, ":default", tran) != SUCCESS) ||
	    (add_new_property(handle, SCF_PROPERTY_SUPP_GROUPS,
		SCF_TYPE_ASTRING, ":default", tran) != SUCCESS) ||
	    (add_new_property(handle, SCF_PROPERTY_RESOURCE_POOL,
		SCF_TYPE_ASTRING, ":default", tran) != SUCCESS) ||
	    (add_new_property(handle, SCF_PROPERTY_PROJECT, SCF_TYPE_ASTRING,
		":default", tran) != SUCCESS) ||
	    (add_new_property(handle, SCF_PROPERTY_PRIVILEGES,
		SCF_TYPE_ASTRING, "basic,sys_net_config", tran) != SUCCESS))
		return (FAILURE);

	return (SUCCESS);
}

static int
add_pg_method(scf_handle_t *handle, scf_instance_t *instance,
    const char *kssl_entry, const char *pg_name, const char *flags,
    const char *value_str)
{
	int len, rv;
	char *command;
	const char *base_command;
	int status = FAILURE;
	boolean_t errflag = B_FALSE;
	scf_transaction_t *tran;
	scf_propertygroup_t *pg;

	pg = add_property_group_to_instance(handle, instance,
	    pg_name, SCF_GROUP_METHOD);
	if (pg == NULL) {
		/* flag is false to suppress duplicate error messages */
		errflag = B_FALSE;
		goto out0;
	}
	KSSL_DEBUG("%s method added\n", pg_name);

	tran = scf_transaction_create(handle);
	if (tran == NULL) {
		KSSL_DEBUG("scf_transaction_create failed: %s\n",
		    scf_strerror(scf_error()));
		errflag = B_TRUE;
		goto out0;
	}
	KSSL_DEBUG("scf_transaction_create succeeded\n");

	do {
		if (scf_transaction_start(tran, pg) != 0) {
			KSSL_DEBUG("scf_transaction_start failed: %s\n",
			    scf_strerror(scf_error()));
			if (scf_error() == SCF_ERROR_PERMISSION_DENIED) {
				(void) fprintf(stderr, gettext(
				    "Error: Permission denied.\n"));
				errflag = B_FALSE;
			} else if (scf_error() ==  SCF_ERROR_DELETED) {
				(void) fprintf(stderr, gettext(
				    "Error: property group %s has"
				    " been deleted.\n"), pg_name);
				errflag = B_FALSE;
			} else
				errflag = B_TRUE;
			goto out1;
		}
		KSSL_DEBUG("scf_transaction_start succeeded\n");

		if (strcmp(pg_name, "stop") == 0)
			base_command = "/usr/lib/kssladm delete";
		else
			base_command = "/usr/lib/kssladm create";

		len = strlen(base_command) + strlen(flags) +
		    strlen(kssl_entry) + 3;

		command = malloc(len);
		if (command == NULL) {
			goto out2;
		}

		(void) snprintf(command, len, "%s %s %s",
		    base_command, flags, kssl_entry);
		KSSL_DEBUG("command=%s\n", command);

		if (add_new_property(handle, SCF_PROPERTY_EXEC,
		    SCF_TYPE_ASTRING, command, tran) != SUCCESS) {
			free(command);
			goto out2;
		}
		free(command);

		if (add_new_property(handle, SCF_PROPERTY_TIMEOUT,
		    SCF_TYPE_COUNT, "60", tran) != SUCCESS)
			goto out2;

		if (set_method_context(handle, tran, value_str) != SUCCESS)
			goto out2;

		rv = scf_transaction_commit(tran);
		switch (rv) {
		case 1:
			KSSL_DEBUG("scf_transaction_commit succeeded\n");
			status = SUCCESS;
			goto out2;
		case 0:
			scf_transaction_reset(tran);
			if (scf_pg_update(pg) == -1) {
				goto out2;
			}
			break;
		case -1:
		default:
			KSSL_DEBUG("ERROR: scf_transaction_commit failed: %s\n",
			    scf_strerror(scf_error()));
			if (scf_error() == SCF_ERROR_PERMISSION_DENIED) {
				(void) fprintf(stderr, gettext(
				    "Error: Permission denied.\n"));
				errflag = B_FALSE;
			} else {
				errflag = B_TRUE;
			}
			goto out2;
		}
	} while (rv == 0);

out2:
	scf_transaction_reset(tran);
out1:
	scf_transaction_destroy_children(tran);
	scf_transaction_destroy(tran);
out0:
	if (pg != NULL)
		scf_pg_destroy(pg);
	if (errflag)
		(void) fprintf(stderr, gettext(
		    "Unexpected fatal libscf error: %s. Exiting.\n"),
		    scf_strerror(scf_error()));
	return (status);
}

static int
create_instance(scf_handle_t *handle, scf_service_t *svc,
    const char *instance_name, const char *kssl_entry, const char *command,
    const char *username, char *inaddr_any_name)
{
	int status = FAILURE;
	char *buf;
	boolean_t errflag = B_FALSE;
	ssize_t max_fmri_len;
	scf_instance_t *instance;

	instance = scf_instance_create(handle);
	if (instance == NULL) {
		errflag = B_TRUE;
		KSSL_DEBUG("scf_instance_create failed: %s\n",
		    scf_strerror(scf_error()));
		goto out;
	}
	KSSL_DEBUG("scf_instance_create succeeded\n");

	if (scf_service_get_instance(svc, inaddr_any_name, instance) == 0) {
		/* Let the caller deal with the duplicate instance */
		status = INSTANCE_ANY_EXISTS;
		goto out;
	}

	if (scf_service_add_instance(svc, instance_name, instance) != 0) {
		if (scf_error() == SCF_ERROR_EXISTS) {
			/* Let the caller deal with the duplicate instance */
			status = INSTANCE_OTHER_EXISTS;
			goto out;
		}

		errflag = B_TRUE;
		KSSL_DEBUG("scf_service_add_instance failed: %s\n",
		    scf_strerror(scf_error()));
		goto out;
	}
	KSSL_DEBUG("scf_service_add_instance succeeded\n");

	if ((add_pg_method(handle, instance, kssl_entry, "start",
		command, username) != SUCCESS) ||
	    (add_pg_method(handle, instance, kssl_entry, "refresh",
		command, username) != SUCCESS) ||
	    (add_pg_method(handle, instance, kssl_entry, "stop",
		"", username) != SUCCESS)) {
		scf_instance_destroy(instance);
		return (status);
	}

	/* enabling the instance */
	max_fmri_len = scf_limit(SCF_LIMIT_MAX_FMRI_LENGTH);
	if ((buf = malloc(max_fmri_len + 1)) == NULL)
		goto out;

	if (scf_instance_to_fmri(instance, buf, max_fmri_len + 1) > 0) {
		KSSL_DEBUG("instance_fmri=%s\n", buf);
		if (smf_enable_instance(buf, 0) != 0) {
			errflag = B_TRUE;
			KSSL_DEBUG(
			    "smf_enable_instance failed: %s\n",
			    scf_strerror(scf_error()));
			goto out;
		}
		status = SUCCESS;
	}

out:
	if (instance != NULL)
		scf_instance_destroy(instance);
	if (errflag)
		(void) fprintf(stderr, gettext(
		    "Unexpected fatal libscf error: %s. Exiting.\n"),
		    scf_strerror(scf_error()));
	return (status);
}

static int
create_service(const char *instance_name, const char *kssl_entry,
    const char *command, const char *username, char *inaddr_any_name)
{
	int status = FAILURE;
	scf_scope_t *scope;
	scf_service_t *svc;
	scf_handle_t *handle;
	boolean_t errflag = B_TRUE;

	handle = scf_handle_create(SCF_VERSION);
	if (handle == NULL) {
		KSSL_DEBUG("scf_handle_create failed: %s\n",
		    scf_strerror(scf_error()));
		goto out1;
	}
	KSSL_DEBUG("scf_handle_create succeeded\n");

	if (scf_handle_bind(handle) == -1) {
		KSSL_DEBUG("scf_handle_bind failed: %s\n",
		    scf_strerror(scf_error()));
		goto out1;
	}
	KSSL_DEBUG("scf_handle_bind succeeded\n");

	if ((scope = scf_scope_create(handle)) == NULL) {
		KSSL_DEBUG("scf_scope_create failed: %s\n",
		    scf_strerror(scf_error()));
		goto out2;
	}
	KSSL_DEBUG("scf_scope_create succeeded\n");

	if ((svc = scf_service_create(handle)) == NULL) {
		KSSL_DEBUG("scf_service_create failed: %s\n",
		    scf_strerror(scf_error()));
		goto out3;
	}
	KSSL_DEBUG("scf_service_create succeeded\n");

	if (scf_handle_decode_fmri(handle, SERVICE_NAME, NULL, svc,
	    NULL, NULL, NULL, SCF_DECODE_FMRI_EXACT) != 0) {
		KSSL_DEBUG("scf_handle_decode_fmri failed: %s\n",
		    scf_strerror(scf_error()));
		if (scf_error() == SCF_ERROR_NOT_FOUND) {
			(void) fprintf(stderr, gettext(
			    "service %s not found in the repository."
			    " Exiting.\n"), SERVICE_NAME);
			errflag = B_FALSE;
		}
		goto out4;
	}

	status = create_instance(handle, svc, instance_name, kssl_entry,
	    command, username, inaddr_any_name);

out4:
	scf_service_destroy(svc);
out3:
	scf_scope_destroy(scope);
out2:
	(void) scf_handle_unbind(handle);
out1:
	if (handle != NULL)
		scf_handle_destroy(handle);

	if (status != SUCCESS && status != INSTANCE_OTHER_EXISTS &&
	    status != INSTANCE_ANY_EXISTS && errflag)
		(void) fprintf(stderr, gettext(
		    "Unexpected fatal libscf error: %s. Exiting.\n"),
		    scf_strerror(scf_error()));
	return (status);
}

int
do_create(int argc, char *argv[])
{
	char c;
	char *buf, *ptr, *instance_name;
	char *inaddr_any_name = NULL;
	int i, status, len, pcnt;
	const char *token_label = NULL;
	const char *filename = NULL;
	const char *certname = NULL;
	const char *username = NULL;
	const char *proxy_port = NULL;
	char *format = NULL;
	boolean_t quote_next;
	char address_port[MAX_ADRPORT_LEN + 1];

	argc -= 1;
	argv += 1;

	/*
	 * Many of these arguments are passed on to kssladm command
	 * in the start method of the SMF instance created. So, we do only
	 * the basic usage checks here and let kssladm check the validity
	 * of the arguments. This is the reason we ignore optarg
	 * for some of the cases below.
	 */
	while ((c = getopt(argc, argv, "vT:d:f:h:i:p:c:C:t:u:x:z:")) != -1) {
		switch (c) {
		case 'd':
			break;
		case 'c':
			break;
		case 'C':
			certname = optarg;
			break;
		case 'f':
			format = optarg;
			break;
		case 'h':
			break;
		case 'i':
			filename = optarg;
			break;
		case 'T':
			token_label = optarg;
			break;
		case 'p':
			break;
		case 't':
			break;
		case 'u':
			username = optarg;
			break;
		case 'x':
			proxy_port = optarg;
			break;
		case 'v':
			verbose = B_TRUE;
			break;
		case 'z':
			break;
		default:
			goto err;
		}
	}

	if (format == NULL || proxy_port == NULL) {
		goto err;
	}

	if (get_portnum(proxy_port, NULL) == 0) {
		(void) fprintf(stderr,
		    gettext("Error: Invalid proxy port value %s\n"),
		    proxy_port);
		goto err;
	}

	if (strcmp(format, "pkcs11") == 0) {
		if (token_label == NULL || certname == NULL) {
			goto err;
		}
	} else if (strcmp(format, "pkcs12") == 0 ||
	    strcmp(format, "pem") == 0) {
		if (filename == NULL) {
			goto err;
		}
	} else {
		goto err;
	}

	pcnt = argc - optind;
	if (pcnt == 1) {
		if (strlen(argv[optind]) < MAX_ADRPORT_LEN) {
			(void) strcpy(address_port, argv[optind]);
		} else {
			(void) fprintf(stderr, gettext(
			    "argument too long -- %s\n"),
			    argv[optind]);
			return (FAILURE);
		}
	} else if (pcnt == 2) {
		if ((len = strlen(argv[optind])) +
		    (strlen(argv[optind + 1])) < MAX_ADRPORT_LEN) {
			(void) strcpy(address_port, argv[optind]);
			address_port[len] = ' ';
			(void) strcpy(address_port + len + 1, argv[optind + 1]);
		} else {
			(void) fprintf(stderr, gettext(
			    "arguments too long -- %s %s\n"),
			    argv[optind], argv[optind + 1]);
			return (FAILURE);
		}
	} else {
		goto err;
	}

	/*
	 * We need to create the kssladm command line in
	 * the SMF instance from the current arguments.
	 *
	 * Construct a buffer with all the arguments except
	 * the -u argument. We have to quote the string arguments,
	 * -T and -C, as they can contain white space.
	 */
	len = 0;
	for (i = 1; i < optind; i++) {
		len += strlen(argv[i]) + 3;
	}

	if ((buf = malloc(len)) == NULL) {
		return (FAILURE);
	}

	ptr = buf;
	quote_next = B_FALSE;
	for (i = 1; i < optind; i++) {
		int arglen =  strlen(argv[i]) + 1;

		if (strncmp(argv[i], "-u", 2) == 0) {
			i++;
			continue;
		}

		if (quote_next) {
			(void) snprintf(ptr, len, "\"%s\" ", argv[i]);
			quote_next = B_FALSE;
			arglen += 2;
		} else {
			(void) snprintf(ptr, len, "%s ", argv[i]);
		}

		quote_next = (strncmp(argv[i], "-T", 2) == 0 ||
		    strncmp(argv[i], "-C", 2) == 0);

		ptr += arglen;
		len -= arglen;
	}
	KSSL_DEBUG("buf=%s\n", buf);

	instance_name = create_instance_name(address_port,
	    &inaddr_any_name, B_TRUE);
	if (instance_name == NULL || inaddr_any_name == NULL) {
		free(buf);
		return (FAILURE);
	}
	KSSL_DEBUG("instance_name=%s\n", instance_name);
	KSSL_DEBUG("inaddr_any_name=%s\n", inaddr_any_name);

	if (username == NULL)
		username = "root";
	status = create_service(instance_name, address_port,
	    buf, username, inaddr_any_name);
	if (status == INSTANCE_OTHER_EXISTS || status == INSTANCE_ANY_EXISTS) {
		if (status == INSTANCE_ANY_EXISTS &&
		    (strcmp(instance_name, inaddr_any_name) != SUCCESS)) {
			/*
			 * The following could result in a misconfiguration.
			 * Better bail out with an error.
			 */
			(void) fprintf(stderr,
			    gettext("Error: INADDR_ANY instance exists."
			    " Can not create a new instance %s.\n"),
			    instance_name);
			free(instance_name);
			free(inaddr_any_name);
			free(buf);
			return (status);
		}

		/*
		 * Delete the existing instance and create a new instance
		 * with the supplied arguments.
		 */
		KSSL_DEBUG("Deleting duplicate instance\n");
		if (delete_instance(instance_name) != SUCCESS) {
			(void) fprintf(stderr,
			    gettext(
			    "Error: Can not delete existing instance %s.\n"),
			    instance_name);
		} else {
			(void) fprintf(stdout, gettext(
			    "Note: reconfiguring the existing instance %s.\n"),
			    instance_name);
			status = create_service(instance_name, address_port,
			    buf, username, inaddr_any_name);
		}
	}

	free(instance_name);
	free(inaddr_any_name);
	free(buf);
	return (status);

err:
	usage_create(B_TRUE);
	return (ERROR_USAGE);
}
