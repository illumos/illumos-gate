/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * kadmin/ldap_util/kdb5_ldap_services.c
 */

/* Copyright (c) 2004-2005, Novell, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *   * Redistributions of source code must retain the above copyright notice,
 *       this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *   * The copyright holder's name is not used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * Create / Delete / Modify / View / List service objects.
 */

/*
 * Service objects have rights over realm objects and principals. The following
 * functions manage the service objects.
 */

#include <stdio.h>
#include <k5-int.h>
#include <libintl.h> /* Solaris Kerberos */
#include <locale.h> /* Solaris Kerberos */
#include "kdb5_ldap_util.h"
#include "kdb5_ldap_list.h"

#ifdef HAVE_EDIRECTORY

krb5_error_code
rem_service_entry_from_file(int argc,
			    char *argv[],
			    char *file_name,
			    char *service_object);

extern char *yes;
extern krb5_boolean db_inited;

static int process_host_list(char **host_list, int servicetype)
{
    krb5_error_code retval = 0;
    char *pchr = NULL;
    char host_str[MAX_LEN_LIST_ENTRY] = "", proto_str[PROTOCOL_STR_LEN + 1] = "", port_str[PORT_STR_LEN + 1] = "";
    int j = 0;

    /* Protocol and port number processing */
    for (j = 0; host_list[j]; j++) {
	/* Look for one hash */
	if ((pchr = strchr(host_list[j], HOST_INFO_DELIMITER))) {
	    unsigned int hostname_len = pchr - host_list[j];

	    /* Check input for buffer overflow */
	    if (hostname_len >= MAX_LEN_LIST_ENTRY) {
		retval = EINVAL;
		goto cleanup;
	    }

	    /* First copy off the host name portion */
	    strncpy (host_str, host_list[j], hostname_len);

	    /* Parse for the protocol string and translate to number */
	    strncpy (proto_str, pchr + 1, PROTOCOL_STR_LEN);
	    if (!strcmp(proto_str, "udp"))
		sprintf (proto_str, "%d", PROTOCOL_NUM_UDP);
	    else if (!strcmp(proto_str, "tcp"))
		sprintf (proto_str, "%d", PROTOCOL_NUM_TCP);
	    else
		proto_str[0] = '\0'; /* Make the string null if invalid */

	    /* Look for one more hash */
	    if ((pchr = strchr(pchr + 1, HOST_INFO_DELIMITER))) {
		/* Parse for the port string and check if it is numeric */
		strncpy (port_str, pchr + 1, PORT_STR_LEN);
		if (!strtol(port_str, NULL, 10)) /* Not a valid number */
		    port_str[0] = '\0';
	    } else
		port_str[0] = '\0';
	} else { /* We have only host name */
	    strncpy (host_str, host_list[j], MAX_LEN_LIST_ENTRY - 1);
	    proto_str[0] = '\0';
	    port_str[0] = '\0';
	}

	/* Now, based on service type, fill in suitable protocol
	   and port values if they are absent or not matching */
	if (servicetype == LDAP_KDC_SERVICE) {
	    if (proto_str[0] == '\0')
		sprintf (proto_str, "%d", PROTOCOL_DEFAULT_KDC);

	    if (port_str[0] == '\0')
		sprintf (port_str, "%d", PORT_DEFAULT_KDC);
	} else if (servicetype == LDAP_ADMIN_SERVICE) {
	    if (proto_str[0] == '\0')
		sprintf (proto_str, "%d", PROTOCOL_DEFAULT_ADM);
	    else if (strcmp(proto_str, "1")) {
		sprintf (proto_str, "%d", PROTOCOL_DEFAULT_ADM);

		/* Print warning message */
		printf (gettext("Admin Server supports only TCP protocol, hence setting that\n"));
	    }

	    if (port_str[0] == '\0')
		sprintf (port_str, "%d", PORT_DEFAULT_ADM);
	} else if (servicetype == LDAP_PASSWD_SERVICE) {
	    if (proto_str[0] == '\0')
		sprintf (proto_str, "%d", PROTOCOL_DEFAULT_PWD);
	    else if (strcmp(proto_str, "0")) {
		sprintf (proto_str, "%d", PROTOCOL_DEFAULT_PWD);

		/* Print warning message */
		printf (gettext("Password Server supports only UDP protocol, hence setting that\n"));
	    }

	    if (port_str[0] == '\0')
		sprintf (port_str, "%d", PORT_DEFAULT_PWD);
	}

	/* Finally form back the string */
	free (host_list[j]);
	host_list[j] = (char*) malloc(sizeof(char) *
				      (strlen(host_str) + strlen(proto_str) + strlen(port_str) + 2 + 1));
	if (host_list[j] == NULL) {
	    retval = ENOMEM;
	    goto cleanup;
	}
	snprintf (host_list[j], strlen(host_str) + strlen(proto_str) + strlen(port_str) + 2 + 1,
		  "%s#%s#%s", host_str, proto_str, port_str);
    }

cleanup:
    return retval;
}


/*
 * Given a realm name, this function will convert it to a DN by appending the
 * Kerberos container location.
 */
static krb5_error_code
convert_realm_name2dn_list(list, krbcontainer_loc)
    char **list;
    const char *krbcontainer_loc;
{
    krb5_error_code retval = 0;
    char temp_str[MAX_DN_CHARS] = "\0";
    char *temp_node = NULL;
    int i = 0;

    if (list == NULL) {
	return EINVAL;
    }

    for (i = 0; (list[i] != NULL) && (i < MAX_LIST_ENTRIES); i++) {
	/* Restrict copying to max. length to avoid buffer overflow */
	snprintf (temp_str, MAX_DN_CHARS, "cn=%s,%s", list[i], krbcontainer_loc);

	/* Make copy of string to temporary node */
	temp_node = strdup(temp_str);
	if (list[i] == NULL) {
	    retval = ENOMEM;
	    goto cleanup;
	}

	/* On success, free list node and attach new one */
	free (list[i]);
	list[i] = temp_node;
	temp_node = NULL;
    }

cleanup:
    return retval;
}


/*
 * This function will create a service object on the LDAP Server, with the
 * specified attributes.
 */
void kdb5_ldap_create_service(argc, argv)
    int argc;
    char *argv[];
{
    /* Solaris Kerberos */
    char *me = progname;
    krb5_error_code retval = 0;
    krb5_ldap_service_params *srvparams = NULL;
    krb5_boolean print_usage = FALSE;
    krb5_boolean no_msg = FALSE;
    int mask = 0;
    char **extra_argv = NULL;
    int extra_argc = 0;
    int i = 0;
    krb5_ldap_realm_params *rparams = NULL;
    int rmask = 0;
    int rightsmask =0;
    char **temprdns = NULL;
    char *realmName = NULL;
    kdb5_dal_handle *dal_handle = NULL;
    krb5_ldap_context *ldap_context=NULL;
    krb5_boolean service_obj_created = FALSE;

    /* Check for number of arguments */
    if ((argc < 3) || (argc > 10)) {
	exit_status++;
	goto err_usage;
    }

    /* Allocate memory for service parameters structure */
    srvparams = (krb5_ldap_service_params*) calloc(1, sizeof(krb5_ldap_service_params));
    if (srvparams == NULL) {
	retval = ENOMEM;
	goto cleanup;
    }

    dal_handle = (kdb5_dal_handle *) util_context->db_context;
    ldap_context = (krb5_ldap_context *) dal_handle->db_context;

    /* Allocate memory for extra arguments to be used for setting
       password -- it's OK to allocate as much as the total number
       of arguments */
    extra_argv = (char **) calloc((unsigned int)argc, sizeof(char*));
    if (extra_argv == NULL) {
	retval = ENOMEM;
	goto cleanup;
    }

    /* Set first of the extra arguments as the program name */
    extra_argv[0] = me;
    extra_argc++;

    /* Read Kerberos container info, to construct realm DN from name
     * and for assigning rights
     */
    if ((retval = krb5_ldap_read_krbcontainer_params(util_context,
						     &(ldap_context->krbcontainer)))) {
	com_err(me, retval, gettext("while reading Kerberos container information"));
	goto cleanup;
    }

    /* Parse all arguments */
    for (i = 1; i < argc; i++) {
	if (!strcmp(argv[i], "-kdc")) {
	    srvparams->servicetype = LDAP_KDC_SERVICE;
	} else if (!strcmp(argv[i], "-admin")) {
	    srvparams->servicetype = LDAP_ADMIN_SERVICE;
	} else if (!strcmp(argv[i], "-pwd")) {
	    srvparams->servicetype = LDAP_PASSWD_SERVICE;
	} else if (!strcmp(argv[i], "-servicehost")) {
	    if (++i > argc - 1)
		goto err_usage;

	    srvparams->krbhostservers = (char **)calloc(MAX_LIST_ENTRIES,
							sizeof(char *));
	    if (srvparams->krbhostservers == NULL) {
		retval = ENOMEM;
		goto cleanup;
	    }

	    if ((retval = krb5_parse_list(argv[i], LIST_DELIMITER,
					  srvparams->krbhostservers))) {
		goto cleanup;
	    }

	    if ((retval = process_host_list (srvparams->krbhostservers,
					     srvparams->servicetype))) {
		goto cleanup;
	    }

	    mask |= LDAP_SERVICE_HOSTSERVER;
	} else if (!strcmp(argv[i], "-realm")) {
	    if (++i > argc - 1)
		goto err_usage;

	    srvparams->krbrealmreferences = (char **)calloc(MAX_LIST_ENTRIES,
							    sizeof(char *));
	    if (srvparams->krbrealmreferences == NULL) {
		retval = ENOMEM;
		goto cleanup;
	    }

	    if ((retval = krb5_parse_list(argv[i], LIST_DELIMITER,
					  srvparams->krbrealmreferences))) {
		goto cleanup;
	    }

	    /* Convert realm names to realm DNs */
	    if ((retval = convert_realm_name2dn_list(
		     srvparams->krbrealmreferences,
		     ldap_context->krbcontainer->DN))) {
		goto cleanup;
	    }

	    mask |= LDAP_SERVICE_REALMREFERENCE;
	}
	/* If argument is none of the above and beginning with '-',
	 * it must be related to password -- collect it
	 * to pass onto kdb5_ldap_set_service_password()
	 */
	else if (*(argv[i]) == '-') {
	    /* Checking for options of setting the password for the
	     * service (by using 'setsrvpw') is not modular. --need to
	     * have a common function that can be shared with 'setsrvpw'
	     */
	    if (!strcmp(argv[i], "-randpw")) {
		extra_argv[extra_argc] = argv[i];
		extra_argc++;
	    } else if (!strcmp(argv[i], "-fileonly")) {
		extra_argv[extra_argc] = argv[i];
		extra_argc++;
	    }
	    /* For '-f' option alone, pick up the following argument too */
	    else if (!strcmp(argv[i], "-f")) {
		extra_argv[extra_argc] = argv[i];
		extra_argc++;

		if (++i > argc - 1)
		    goto err_usage;

		extra_argv[extra_argc] = argv[i];
		extra_argc++;
	    } else { /* Any other option is invalid */
		exit_status++;
		goto err_usage;
	    }
	} else { /* Any other argument must be service DN */
	    /* First check if service DN is already provided --
	     * if so, there's a usage error
	     */
	    if (srvparams->servicedn != NULL) {
		com_err(me, EINVAL, gettext("while creating service object"));
		goto err_usage;
	    }

	    /* If not present already, fill up service DN */
	    srvparams->servicedn = strdup(argv[i]);
	    if (srvparams->servicedn == NULL) {
		com_err(me, ENOMEM, gettext("while creating service object"));
		goto err_nomsg;
	    }
	}
    }

    /* No point in proceeding further if service DN value is not available */
    if (srvparams->servicedn == NULL) {
	com_err(me, EINVAL, gettext("while creating service object"));
	goto err_usage;
    }

    if (srvparams->servicetype == 0) { /* Not provided and hence not set */
	com_err(me, EINVAL, gettext("while creating service object"));
	goto err_usage;
    }

    /* Create object with all attributes provided */
    if ((retval = krb5_ldap_create_service(util_context, srvparams, mask)))
	goto cleanup;

    service_obj_created = TRUE;

    /* ** NOTE ** srvparams structure should not be modified, as it is
     * used for deletion of the service object in case of any failures
     * from now on.
     */

    /* Set password too */
    if (extra_argc >= 1) {
	/* Set service DN as the last argument */
	extra_argv[extra_argc] = strdup(srvparams->servicedn);
	if (extra_argv[extra_argc] == NULL) {
            retval = ENOMEM;
            goto cleanup;
        }
	extra_argc++;

	if ((retval = kdb5_ldap_set_service_password(extra_argc, extra_argv)) != 0) {
	    goto err_nomsg;
	}
    }
    /* Rights assignment */
    if (mask & LDAP_SERVICE_REALMREFERENCE) {

	printf("%s", gettext("Changing rights for the service object. Please wait ... "));
	fflush(stdout);

	rightsmask =0;
	rightsmask |= LDAP_REALM_RIGHTS;
	rightsmask |= LDAP_SUBTREE_RIGHTS;

	if ((srvparams != NULL) && (srvparams->krbrealmreferences != NULL)) {
	    for (i=0; (srvparams->krbrealmreferences[i] != NULL); i++) {

		/* Get the realm name, not the dn */
		temprdns = ldap_explode_dn(srvparams->krbrealmreferences[i], 1);

		if (temprdns[0] == NULL) {
		    retval = EINVAL;
		    goto cleanup;
		}

		realmName = strdup(temprdns[0]);
		if (realmName == NULL) {
		    retval = ENOMEM;
		    goto cleanup;
		}

		if ((retval = krb5_ldap_read_realm_params(util_context,
							  realmName, &rparams, &rmask))) {
		    com_err(me, retval, gettext("while reading information of realm '%s'"),
			    realmName);
		    goto cleanup;
		}

		if ((retval = krb5_ldap_add_service_rights(util_context,
							   srvparams->servicetype, srvparams->servicedn,
							   realmName, rparams->subtree, rightsmask))) {
		    printf(gettext("failed\n"));
		    com_err(me, retval, gettext("while assigning rights '%s'"),
			    srvparams->servicedn);
		    goto cleanup;
		}

		if (rparams)
		    krb5_ldap_free_realm_params(rparams);
	    }
	}
	printf(gettext("done\n"));
    }
    goto cleanup;

err_usage:
    print_usage = TRUE;

err_nomsg:
    no_msg = TRUE;

cleanup:

    if ((retval != 0) && (service_obj_created == TRUE)) {
	/* This is for deleting the service object if something goes
	 * wrong in creating the service object
	 */

	/* srvparams is populated from the user input and should be correct as
	 * we were successful in creating a service object. Reusing the same
	 */
	krb5_ldap_delete_service(util_context, srvparams, srvparams->servicedn);
    }

    /* Clean-up structure */
    krb5_ldap_free_service (util_context, srvparams);

    if (extra_argv) {
	free (extra_argv);
	extra_argv = NULL;
    }
    if (realmName) {
	free(realmName);
	realmName = NULL;
    }
    if (print_usage)
	db_usage (CREATE_SERVICE);

    if (retval) {
	if (!no_msg)
	    com_err(me, retval, gettext("while creating service object"));

	exit_status++;
    }

    return;
}


/*
 * This function will modify the attributes of a given service
 * object on the LDAP Server
 */
void kdb5_ldap_modify_service(argc, argv)
    int argc;
    char *argv[];
{
    /* Solaris Kerberos */
    char *me = progname;
    krb5_error_code retval = 0;
    krb5_ldap_service_params *srvparams = NULL;
    krb5_boolean print_usage = FALSE;
    krb5_boolean no_msg = FALSE;
    char *servicedn = NULL;
    int i = 0;
    int in_mask = 0, out_mask = 0;
    int srvhost_flag = 0, realmdn_flag = 0;
    char **list = NULL;
    int existing_entries = 0, new_entries = 0;
    char **temp_ptr = NULL;
    krb5_ldap_realm_params *rparams = NULL;
    int j = 0;
    int rmask = 0;
    int rightsmask =0;
    char **oldrealmrefs = NULL;
    char **newrealmrefs = NULL;
    char **temprdns = NULL;
    char *realmName = NULL;
    kdb5_dal_handle *dal_handle = NULL;
    krb5_ldap_context *ldap_context=NULL;

    /* Check for number of arguments */
    if ((argc < 3) || (argc > 10)) {
	exit_status++;
	goto err_usage;
    }

    dal_handle = (kdb5_dal_handle *) util_context->db_context;
    ldap_context = (krb5_ldap_context *) dal_handle->db_context;

    /* Parse all arguments, only to pick up service DN (Pass 1) */
    for (i = 1; i < argc; i++) {
	/* Skip arguments next to 'servicehost'
	   and 'realmdn' arguments */
	if (!strcmp(argv[i], "-servicehost")) {
	    ++i;
	} else if (!strcmp(argv[i], "-clearservicehost")) {
	    ++i;
	} else if (!strcmp(argv[i], "-addservicehost")) {
	    ++i;
	} else if (!strcmp(argv[i], "-realm")) {
	    ++i;
	} else if (!strcmp(argv[i], "-clearrealm")) {
	    ++i;
	} else if (!strcmp(argv[i], "-addrealm")) {
	    ++i;
	} else { /* Any other argument must be service DN */
	    /* First check if service DN is already provided --
	       if so, there's a usage error */
	    if (servicedn != NULL) {
		com_err(me, EINVAL, gettext("while modifying service object"));
		goto err_usage;
	    }

	    /* If not present already, fill up service DN */
	    servicedn = strdup(argv[i]);
	    if (servicedn == NULL) {
		com_err(me, ENOMEM, gettext("while modifying service object"));
		goto err_nomsg;
	    }
	}
    }

    /* No point in proceeding further if service DN value is not available */
    if (servicedn == NULL) {
	com_err(me, EINVAL, gettext("while modifying service object"));
	goto err_usage;
    }

    retval = krb5_ldap_read_service(util_context, servicedn, &srvparams, &in_mask);
    if (retval) {
	/* Solaris Kerberos */
	com_err(me, retval, gettext("while reading information of service '%s'"),
		servicedn);
	goto err_nomsg;
    }

    /* Read Kerberos container info, to construct realm DN from name
     * and for assigning rights
     */
    if ((retval = krb5_ldap_read_krbcontainer_params(util_context,
						     &(ldap_context->krbcontainer)))) {
	com_err(me, retval, gettext("while reading Kerberos container information"));
	goto cleanup;
    }

    /* Parse all arguments, but skip the service DN (Pass 2) */
    for (i = 1; i < argc; i++) {
	if (!strcmp(argv[i], "-servicehost")) {
	    if (++i > argc - 1)
		goto err_usage;

	    /* Free the old list if available */
	    if (srvparams->krbhostservers) {
		krb5_free_list_entries (srvparams->krbhostservers);
		free (srvparams->krbhostservers);
	    }

	    srvparams->krbhostservers = (char **)calloc(MAX_LIST_ENTRIES,
							sizeof(char *));
	    if (srvparams->krbhostservers == NULL) {
		retval = ENOMEM;
		goto cleanup;
	    }

	    if ((retval = krb5_parse_list(argv[i], LIST_DELIMITER,
					  srvparams->krbhostservers))) {
		goto cleanup;
	    }

	    if ((retval = process_host_list (srvparams->krbhostservers,
					     srvparams->servicetype))) {
		goto cleanup;
	    }

	    out_mask |= LDAP_SERVICE_HOSTSERVER;

	    /* Set flag to ignore 'add' and 'clear' */
	    srvhost_flag = 1;
	} else if (!strcmp(argv[i], "-clearservicehost")) {
	    if (++i > argc - 1)
		goto err_usage;

	    if (!srvhost_flag) {
		/* If attribute doesn't exist, don't permit 'clear' option */
		if ((in_mask & LDAP_SERVICE_HOSTSERVER) == 0) {
		    /* Send out some proper error message here */
		    com_err(me, EINVAL, gettext("service host list is empty\n"));
		    goto err_nomsg;
		}

		/* Allocate list for processing */
		list = (char**) calloc(MAX_LIST_ENTRIES, sizeof(char*));
		if (list == NULL) {
		    retval = ENOMEM;
		    goto cleanup;
		}

		if ((retval = krb5_parse_list(argv[i], LIST_DELIMITER, list)))
		    goto cleanup;

		if ((retval = process_host_list (list, srvparams->servicetype))) {
		    goto cleanup;
		}

		list_modify_str_array(&(srvparams->krbhostservers),
				      (const char**)list, LIST_MODE_DELETE);

		out_mask |= LDAP_SERVICE_HOSTSERVER;

		/* Clean up */
		free (list);
		list = NULL;
	    }
	} else if (!strcmp(argv[i], "-addservicehost")) {
	    if (++i > argc - 1)
		goto err_usage;

	    if (!srvhost_flag) {
		/* Allocate list for processing */
		list = (char**) calloc(MAX_LIST_ENTRIES, sizeof(char*));
		if (list == NULL) {
		    retval = ENOMEM;
		    goto cleanup;
		}

		if ((retval = krb5_parse_list(argv[i], LIST_DELIMITER, list)))
		    goto cleanup;

		if ((retval = process_host_list (list, srvparams->servicetype))) {
		    goto cleanup;
		}

		/* Call list_modify_str_array() only if host server attribute
		 * exists already --Actually, it's better to handle this
		 * within list_modify_str_array()
		 */
		if (in_mask & LDAP_SERVICE_HOSTSERVER) {
		    /* Re-size existing list */
		    existing_entries = list_count_str_array(srvparams->krbhostservers);
		    new_entries = list_count_str_array(list);
		    temp_ptr = (char **) realloc(srvparams->krbhostservers,
						 sizeof(char *) * (existing_entries + new_entries + 1));
		    if (temp_ptr == NULL) {
			retval = ENOMEM;
			goto cleanup;
		    }
		    srvparams->krbhostservers = temp_ptr;

		    list_modify_str_array(&(srvparams->krbhostservers),
					  (const char**)list, LIST_MODE_ADD);

		    /* Clean up */
		    free (list);
		    list = NULL;
		} else
		    srvparams->krbhostservers = list;

		out_mask |= LDAP_SERVICE_HOSTSERVER;
	    }
	} else if (!strcmp(argv[i], "-realm")) {
	    if (++i > argc - 1)
		goto err_usage;

	    if ((in_mask & LDAP_SERVICE_REALMREFERENCE) && (srvparams->krbrealmreferences)) {
		if (!oldrealmrefs) {
		    /* Store the old realm list for removing rights */
		    oldrealmrefs = (char**) calloc(MAX_LIST_ENTRIES, sizeof(char*));
		    if (oldrealmrefs == NULL) {
			retval = ENOMEM;
			goto cleanup;
		    }

		    for (j = 0; srvparams->krbrealmreferences[j] != NULL; j++) {
			oldrealmrefs[j] = strdup(srvparams->krbrealmreferences[j]);
			if (oldrealmrefs[j] == NULL) {
			    retval = ENOMEM;
			    goto cleanup;
			}
		    }
		    oldrealmrefs[j] = NULL;
		}

		/* Free the old list if available */
		krb5_free_list_entries (srvparams->krbrealmreferences);
		free (srvparams->krbrealmreferences);
	    }

	    srvparams->krbrealmreferences = (char **)calloc(MAX_LIST_ENTRIES,
							    sizeof(char *));
	    if (srvparams->krbrealmreferences == NULL) {
		retval = ENOMEM;
		goto cleanup;
	    }

	    if ((retval = krb5_parse_list(argv[i], LIST_DELIMITER,
					  srvparams->krbrealmreferences))) {
		goto cleanup;
	    }

	    /* Convert realm names to realm DNs */
	    if ((retval = convert_realm_name2dn_list(
		     srvparams->krbrealmreferences,
		     ldap_context->krbcontainer->DN))) {
		goto cleanup;
	    }

	    out_mask |= LDAP_SERVICE_REALMREFERENCE;

	    /* Set flag to ignore 'add' and 'clear' */
	    realmdn_flag = 1;
	} else if (!strcmp(argv[i], "-clearrealm")) {
	    if (++i > argc - 1)
		goto err_usage;

	    if (!realmdn_flag) {
		/* If attribute doesn't exist, don't permit 'clear' option */
		if (((in_mask & LDAP_SERVICE_REALMREFERENCE) == 0) || (srvparams->krbrealmreferences == NULL)) {
		    /* Send out some proper error message here */
		    goto err_nomsg;
		}

		if (!oldrealmrefs) {
		    /* Store the old realm list for removing rights */
		    oldrealmrefs = (char**) calloc(MAX_LIST_ENTRIES, sizeof(char*));
		    if (oldrealmrefs == NULL) {
			retval = ENOMEM;
			goto cleanup;
		    }

		    for (j = 0; srvparams->krbrealmreferences[j] != NULL; j++) {
			oldrealmrefs[j] = strdup(srvparams->krbrealmreferences[j]);
			if (oldrealmrefs[j] == NULL) {
			    retval = ENOMEM;
			    goto cleanup;
			}
		    }
		    oldrealmrefs[j] = NULL;
		}

		/* Allocate list for processing */
		list = (char**) calloc(MAX_LIST_ENTRIES, sizeof(char*));
		if (list == NULL) {
		    retval = ENOMEM;
		    goto cleanup;
		}

		if ((retval = krb5_parse_list(argv[i], LIST_DELIMITER, list)))
		    goto cleanup;

		/* Convert realm names to realm DNs */
		if ((retval = convert_realm_name2dn_list(list,
							 ldap_context->krbcontainer->DN))) {
		    goto cleanup;
		}

		list_modify_str_array(&(srvparams->krbrealmreferences),
				      (const char**)list, LIST_MODE_DELETE);

		out_mask |= LDAP_SERVICE_REALMREFERENCE;

		/* Clean up */
		free (list);
		list = NULL;
	    }
	} else if (!strcmp(argv[i], "-addrealm")) {
	    if (++i > argc - 1)
		goto err_usage;

	    if (!realmdn_flag) {
		/* Allocate list for processing */
		list = (char**) calloc(MAX_LIST_ENTRIES, sizeof(char*));
		if (list == NULL) {
		    retval = ENOMEM;
		    goto cleanup;
		}

		if ((retval = krb5_parse_list(argv[i], LIST_DELIMITER, list)))
		    goto cleanup;

		/* Convert realm names to realm DNs */
		if ((retval = convert_realm_name2dn_list(list,
							 ldap_context->krbcontainer->DN))) {
		    goto cleanup;
		}

		if ((in_mask & LDAP_SERVICE_REALMREFERENCE) && (srvparams->krbrealmreferences) && (!oldrealmrefs)) {
		    /* Store the old realm list for removing rights */
		    oldrealmrefs = (char**) calloc(MAX_LIST_ENTRIES, sizeof(char*));
		    if (oldrealmrefs == NULL) {
			retval = ENOMEM;
			goto cleanup;
		    }

		    for (j = 0; srvparams->krbrealmreferences[j] != NULL; j++) {
			oldrealmrefs[j] = strdup(srvparams->krbrealmreferences[j]);
			if (oldrealmrefs[j] == NULL) {
			    retval = ENOMEM;
			    goto cleanup;
			}
		    }
		    oldrealmrefs[j] = NULL;
		}

		/* Call list_modify_str_array() only if realm DN attribute
		 * exists already -- Actually, it's better to handle this
		 * within list_modify_str_array() */
		if (in_mask & LDAP_SERVICE_REALMREFERENCE) {
		    /* Re-size existing list */
		    existing_entries = list_count_str_array(
			srvparams->krbrealmreferences);
		    new_entries = list_count_str_array(list);
		    temp_ptr = (char **) realloc(srvparams->krbrealmreferences,
						 sizeof(char *) * (existing_entries + new_entries + 1));
		    if (temp_ptr == NULL) {
			retval = ENOMEM;
			goto cleanup;
		    }
		    srvparams->krbrealmreferences = temp_ptr;

		    list_modify_str_array(&(srvparams->krbrealmreferences),
					  (const char**)list, LIST_MODE_ADD);

		    /* Clean up */
		    free (list);
		    list = NULL;
		} else
		    srvparams->krbrealmreferences = list;

		out_mask |= LDAP_SERVICE_REALMREFERENCE;
	    }
	} else {
	    /* Any other argument must be service DN
	       -- skip it */
	}
    }

    /* Modify attributes of object */
    if ((retval = krb5_ldap_modify_service(util_context, srvparams, out_mask)))
	goto cleanup;

    /* Service rights modification code */
    if (out_mask & LDAP_SERVICE_REALMREFERENCE) {

	printf("%s", gettext("Changing rights for the service object. Please wait ... "));
	fflush(stdout);

	newrealmrefs = (char**) calloc(MAX_LIST_ENTRIES, sizeof(char*));
	if (newrealmrefs == NULL) {
	    retval = ENOMEM;
	    goto cleanup;
	}

	if ((srvparams != NULL) && (srvparams->krbrealmreferences != NULL)) {
	    for (j = 0; srvparams->krbrealmreferences[j] != NULL; j++) {
		newrealmrefs[j] = strdup(srvparams->krbrealmreferences[j]);
		if (newrealmrefs[j] == NULL) {
		    retval = ENOMEM;
		    goto cleanup;
		}
	    }
	    newrealmrefs[j] = NULL;
	}
	disjoint_members(oldrealmrefs, newrealmrefs);

	/* Delete the rights for the given service, on each of the realm
	 * container & subtree in the old realm reference list.
	 */
	if (oldrealmrefs) {
	    rightsmask = 0;
	    rightsmask |= LDAP_REALM_RIGHTS;
	    rightsmask |= LDAP_SUBTREE_RIGHTS;

	    for (i = 0; (oldrealmrefs[i] != NULL); i++) {
		/* Get the realm name, not the dn */
		temprdns = ldap_explode_dn(oldrealmrefs[i], 1);

		if (temprdns[0] == NULL) {
		    retval = EINVAL;
		    goto cleanup;
		}

		realmName = strdup(temprdns[0]);
		if (realmName == NULL) {
		    retval = ENOMEM;
		    goto cleanup;
		}

		if ((retval = krb5_ldap_read_realm_params(util_context,
							  realmName, &rparams, &rmask))) {
		    com_err(me, retval, gettext("while reading information of realm '%s'"),
			    realmName);
		    goto err_nomsg;
		}

		if ((retval = krb5_ldap_delete_service_rights(util_context,
							      srvparams->servicetype, srvparams->servicedn,
							      realmName, rparams->subtree, rightsmask))) {
		    printf(gettext("failed\n"));
		    com_err(me, retval, gettext("while assigning rights '%s'"),
			    srvparams->servicedn);
		    goto err_nomsg;
		}

		if (rparams)
		    krb5_ldap_free_realm_params(rparams);
	    }
	}

	/* Add the rights for the given service, on each of the realm
	 * container & subtree in the new realm reference list.
	 */
	if (newrealmrefs) {
	    rightsmask = 0;
	    rightsmask |= LDAP_REALM_RIGHTS;
	    rightsmask |= LDAP_SUBTREE_RIGHTS;

	    for (i = 0; (newrealmrefs[i] != NULL); i++) {
		/* Get the realm name, not the dn */
		temprdns = ldap_explode_dn(newrealmrefs[i], 1);

		if (temprdns[0] == NULL) {
		    retval = EINVAL;
		    goto cleanup;
		}

		realmName = strdup(temprdns[0]);
		if (realmName == NULL) {
		    retval = ENOMEM;
		    goto cleanup;
		}

		if ((retval = krb5_ldap_read_krbcontainer_params(util_context,
								 &(ldap_context->krbcontainer)))) {
		    com_err(me, retval,
			    gettext("while reading Kerberos container information"));
		    goto cleanup;
		}

		if ((retval = krb5_ldap_read_realm_params(util_context,
							  realmName, &rparams, &rmask))) {
		    com_err(me, retval, gettext("while reading information of realm '%s'"),
			    realmName);
		    goto err_nomsg;
		}

		if ((retval = krb5_ldap_add_service_rights(util_context,
							   srvparams->servicetype, srvparams->servicedn,
							   realmName, rparams->subtree, rightsmask))) {
		    printf(gettext("failed\n"));
		    com_err(me, retval, gettext("while assigning rights '%s'"),
			    srvparams->servicedn);
		    goto err_nomsg;
		}

		if (rparams) {
		    krb5_ldap_free_realm_params(rparams);
		    rparams = NULL;
		}
	    }
	    printf(gettext("done\n"));
	}
    }
    goto cleanup;

err_usage:
    print_usage = TRUE;

err_nomsg:
    no_msg = TRUE;

cleanup:
    /* Clean-up structure */
    krb5_ldap_free_service(util_context, srvparams);

    if (servicedn)
	free(servicedn);

    if (list) {
	free(list);
	list = NULL;
    }

    if (oldrealmrefs) {
	for (i = 0; oldrealmrefs[i] != NULL; i++)
	    free(oldrealmrefs[i]);
	free(oldrealmrefs);
    }

    if (newrealmrefs) {
	for (i = 0; newrealmrefs[i] != NULL; i++)
	    free(newrealmrefs[i]);
	free(newrealmrefs);
    }
    if (realmName) {
	free(realmName);
	realmName = NULL;
    }

    if (print_usage)
	db_usage(MODIFY_SERVICE);

    if (retval) {
	if (!no_msg)
	    com_err(me, retval, gettext("while modifying service object"));
	exit_status++;
    }

    return;
}


/*
 * This function will delete the entry corresponding to the service object
 * from the service password file.
 */
static krb5_error_code
rem_service_entry_from_file(argc, argv, file_name, service_object)
    int argc;
    char *argv[];
    char *file_name;
    char *service_object;
{
    int     st        = EINVAL;
    /* Solaris Kerberos */
    char    *me       = progname;
    char    *tmp_file = NULL;
    int     tmpfd     = -1;
    FILE    *pfile    = NULL;
    unsigned int len  = 0;
    char    line[MAX_LEN]={0};
    mode_t  omask     = umask(077);

    /* Check for permissions on the password file */
    if (access(file_name, W_OK) == -1) {
	/* If the specified file itself is not there, no need to show error */
	if (errno == ENOENT) {
	    st=0;
	    goto cleanup;
	} else {
	    com_err(me, errno, gettext("while deleting entry from file %s", file_name));
	    goto cleanup;
	}
    }

    /* Create a temporary file which contains all the entries except the
       entry for the given service dn */
    pfile = fopen(file_name, "r+F");
    if (pfile == NULL) {
	com_err(me, errno, gettext("while deleting entry from file %s"), file_name);
	goto cleanup;
    }

    /* Create a new file with the extension .tmp */
    tmp_file = (char *)malloc(strlen(file_name) + 4 + 1);
    if (tmp_file == NULL) {
	com_err(me, ENOMEM, gettext("while deleting entry from file"));
	fclose(pfile);
	goto cleanup;
    }
    snprintf (tmp_file, strlen(file_name) + 4 + 1, "%s%s", file_name, ".tmp");


    tmpfd = creat(tmp_file, S_IRUSR|S_IWUSR);
    umask(omask);
    if (tmpfd == -1) {
	com_err(me, errno, gettext("while deleting entry from file\n"));
	fclose(pfile);
	goto cleanup;
    }

    /* Copy only those lines which donot have the specified service dn */
    while (fgets(line, MAX_LEN, pfile) != NULL) {
	if ((strstr(line, service_object) != NULL) &&
	    (line[strlen(service_object)] == '#')) {
	    continue;
	} else {
	    len = strlen(line);
	    if (write(tmpfd, line, len) != len) {
		com_err(me, errno, gettext("while deleting entry from file\n"));
		close(tmpfd);
		unlink(tmp_file);
		fclose(pfile);
		goto cleanup;
	    }
	}
    }

    fclose(pfile);
    if (unlink(file_name) == 0) {
	link(tmp_file, file_name);
    } else {
	com_err(me, errno, gettext("while deleting entry from file\n"));
    }
    unlink(tmp_file);

    st=0;

cleanup:

    if (tmp_file)
	free(tmp_file);

    return st;
}


/*
 * This function will delete the service object from the LDAP Server
 * and unlink the references to the Realm objects (if any)
 */
void
kdb5_ldap_destroy_service(argc, argv)
    int argc;
    char *argv[];
{
    int i = 0;
    char buf[5] = {0};
    krb5_error_code retval = EINVAL;
    int force = 0;
    char *servicedn = NULL;
    char *stashfilename = NULL;
    int mask = 0;
    krb5_ldap_service_params *lserparams = NULL;
    krb5_boolean print_usage = FALSE;

    if ((argc < 2) || (argc > 5)) {
	exit_status++;
	goto err_usage;
    }

    for (i=1; i < argc; i++) {

	if (strcmp(argv[i],"-force")==0) {
	    force++;
	} else if (strcmp(argv[i],"-f")==0) {
	    if (argv[i+1]) {
		stashfilename=strdup(argv[i+1]);
		if (stashfilename == NULL) {
		    /* Solaris Kerberos */
		    com_err(progname, ENOMEM, gettext("while destroying service"));
		    exit_status++;
		    goto cleanup;
		}
		i++;
	    } else {
		exit_status++;
		goto err_usage;
	    }
	} else {
	    if ((argv[i]) && (servicedn == NULL)) {
		servicedn=strdup(argv[i]);
		if (servicedn == NULL) {
		    /* Solaris Kerberos */
		    com_err(progname, ENOMEM, gettext("while destroying service"));
		    exit_status++;
		    goto cleanup;
		}
	    } else {
		exit_status++;
		goto err_usage;
	    }
	}
    }

    if (!servicedn) {
	exit_status++;
	goto err_usage;
    }

    if (!force) {
	printf(gettext("This will delete the service object '%s', are you sure?\n"), servicedn);
	printf(gettext("(type 'yes' to confirm)? "));
	if (fgets(buf, sizeof(buf), stdin) == NULL) {
	    exit_status++;
	    goto cleanup;;
	}
	if (strcmp(buf, yes)) {
	    exit_status++;
	    goto cleanup;
	}
    }

    if ((retval = krb5_ldap_read_service(util_context, servicedn,
					 &lserparams, &mask))) {
	/* Solaris Kerberos */
	com_err(progname, retval, gettext("while destroying service '%s'"), servicedn);
	exit_status++;
	goto cleanup;
    }

    retval = krb5_ldap_delete_service(util_context, lserparams, servicedn);

    if (retval) {
	/* Solaris Kerberos */
	com_err(progname, retval, gettext("while destroying service '%s'"), servicedn);
	exit_status++;
	goto cleanup;
    }

    if (stashfilename == NULL) {
	stashfilename = strdup(DEF_SERVICE_PASSWD_FILE);
	if (stashfilename == NULL) {
	    /* Solaris Kerberos */
	    com_err(progname, ENOMEM, gettext("while destroying service"));
	    exit_status++;
	    goto cleanup;
	}
    }
    printf(gettext("** service object '%s' deleted.\n"), servicedn);
    retval = rem_service_entry_from_file(argc, argv, stashfilename, servicedn);

    if (retval)
	printf(gettext("** error removing service object entry '%s' from password file.\n"),
	       servicedn);

    goto cleanup;


err_usage:
    print_usage = TRUE;

cleanup:

    if (lserparams) {
	krb5_ldap_free_service(util_context, lserparams);
    }

    if (servicedn) {
	free(servicedn);
    }

    if (stashfilename) {
	free(stashfilename);
    }

    if (print_usage) {
	db_usage(DESTROY_SERVICE);
    }

    return;
}


/*
 * This function will display information about the given service object
 */
void kdb5_ldap_view_service(argc, argv)
    int argc;
    char *argv[];
{
    krb5_ldap_service_params *lserparams = NULL;
    krb5_error_code retval = 0;
    char *servicedn = NULL;
    int mask = 0;
    krb5_boolean print_usage = FALSE;

    if (!(argc == 2)) {
	exit_status++;
	goto err_usage;
    }

    servicedn=strdup(argv[1]);
    if (servicedn == NULL) {
	/* Solaris Kerberos */
	com_err(progname, ENOMEM, gettext("while viewing service"));
	exit_status++;
	goto cleanup;
    }

    if ((retval = krb5_ldap_read_service(util_context, servicedn, &lserparams, &mask))) {
	/* Solaris Kerberos */
	com_err(progname, retval, gettext("while viewing service '%s'"), servicedn);
	exit_status++;
	goto cleanup;
    }

    print_service_params(lserparams, mask);

    goto cleanup;

err_usage:
    print_usage = TRUE;

cleanup:

    if (lserparams) {
	krb5_ldap_free_service(util_context, lserparams);
    }

    if (servicedn)
	free(servicedn);

    if (print_usage) {
	db_usage(VIEW_SERVICE);
    }

    return;
}


/*
 * This function will list the DNs of kerberos services present on
 * the LDAP Server under a specific sub-tree (entire tree by default)
 */
void kdb5_ldap_list_services(argc, argv)
    int argc;
    char *argv[];
{
    /* Solaris Kerberos */
    char *me = progname;
    krb5_error_code retval = 0;
    char *basedn = NULL;
    char **list = NULL;
    char **plist = NULL;
    krb5_boolean print_usage = FALSE;

    /* Check for number of arguments */
    if ((argc != 1) && (argc != 3)) {
	exit_status++;
	goto err_usage;
    }

    /* Parse base DN argument if present */
    if (argc == 3) {
	if (strcmp(argv[1], "-basedn")) {
	    retval = EINVAL;
	    goto err_usage;
	}

	basedn = strdup(argv[2]);
	if (basedn == NULL) {
	    com_err(me, ENOMEM, gettext("while listing services"));
	    exit_status++;
	    goto cleanup;
	}
    }

    retval = krb5_ldap_list_services(util_context, basedn, &list);
    if ((retval != 0) || (list == NULL)) {
	exit_status++;
	goto cleanup;
    }

    for (plist = list; *plist != NULL; plist++) {
	printf("%s\n", *plist);
    }

    goto cleanup;

err_usage:
    print_usage = TRUE;

cleanup:
    if (list != NULL) {
	krb5_free_list_entries (list);
	free (list);
    }

    if (basedn)
	free (basedn);

    if (print_usage) {
	db_usage(LIST_SERVICE);
    }

    if (retval) {
	com_err(me, retval, gettext("while listing policy objects"));
	exit_status++;
    }

    return;
}


/*
 * This function will print the service object information
 * to the standard output
 */
static void
print_service_params(lserparams, mask)
    krb5_ldap_service_params *lserparams;
    int mask;
{
    int            i=0;

    /* Print the service dn */
    printf("%20s%-20s\n", gettext("Service dn: "), lserparams->servicedn);

    /* Print the service type of the object to be read */
    if (lserparams->servicetype == LDAP_KDC_SERVICE) {
	printf("%20s%-20s\n", gettext("Service type: "), "kdc");
    } else if (lserparams->servicetype == LDAP_ADMIN_SERVICE) {
	printf("%20s%-20s\n", gettext("Service type: "), "admin");
    } else if (lserparams->servicetype == LDAP_PASSWD_SERVICE) {
	printf("%20s%-20s\n", gettext("Service type: "), "pwd");
    }

    /* Print the host server values */
    printf("%20s\n", gettext("Service host list: "));
    if (mask & LDAP_SERVICE_HOSTSERVER) {
	for (i=0; lserparams->krbhostservers[i] != NULL; ++i) {
	    printf("%20s%-50s\n","",lserparams->krbhostservers[i]);
	}
    }

    /* Print the realm reference dn values */
    printf("%20s\n", gettext("Realm DN list: "));
    if (mask & LDAP_SERVICE_REALMREFERENCE) {
	for (i=0; lserparams && lserparams->krbrealmreferences && lserparams->krbrealmreferences[i] != NULL; ++i) {
	    printf("%20s%-50s\n","",lserparams->krbrealmreferences[i]);
	}
    }

    return;
}


/*
 * This function will generate random  password of length(RANDOM_PASSWD_LEN)
 *
 *
 * INPUT:
 *      ctxt - context
 *
 * OUTPUT:
 *     RANDOM_PASSWD_LEN length random password
 */
static int generate_random_password(krb5_context ctxt, char **randpwd, unsigned int *passlen)
{
    char *random_pwd = NULL;
    int ret = 0;
    krb5_data data;
    int i=0;
    /*int len = 0;*/

    /* setting random password length in the range 16-32 */
    srand((unsigned int)(time(0) ^ getpid()));

    data.length = RANDOM_PASSWD_LEN;
    random_pwd = (char *)malloc(data.length + 1);
    if (random_pwd == NULL) {
	com_err("setsrvpw", ENOMEM, gettext("while generating random password"));
	return ENOMEM;
    }
    memset(random_pwd, 0, data.length + 1);
    data.data = random_pwd;

    ret = krb5_c_random_make_octets(ctxt, &data);
    if (ret) {
	com_err("setsrvpw", ret, gettext("Error generating random password"));
	free(random_pwd);
	return ret;
    }

    for (i=0; i<data.length; i++) {
	/* restricting to ascii chars. Need to change this when 8.8 supports */
	if ((unsigned char)random_pwd[i] > 127) {
	    random_pwd[i] = (unsigned char)random_pwd[i] % 128;
	} else if (random_pwd[i] == 0) {
	    random_pwd[i] = (rand()/(RAND_MAX/127 + 1))+1;
	}
    }

    *randpwd = random_pwd;
    *passlen = data.length;

    return 0;
}


/*
 * This function will set the password of the service object in the directory
 * and/or the specified service password file.
 *
 *
 * INPUT:
 *      argc - contains the number of arguments for this sub-command
 *      argv - array of arguments for this sub-command
 *
 * OUTPUT:
 *      void
 */
int
kdb5_ldap_set_service_password(argc, argv)
    int argc;
    char **argv;
{
    krb5_ldap_context *lparams = NULL;
    char *file_name = NULL;
    char *tmp_file = NULL;
    /* Solaris Kerberos */
    char *me = progname;
    int filelen = 0;
    int random_passwd = 0;
    int set_dir_pwd = 1;
    krb5_boolean db_init_local = FALSE;
    char *service_object = NULL;
    char *passwd = NULL;
    char *prompt1 = NULL;
    char *prompt2 = NULL;
    unsigned int passwd_len = 0;
    krb5_error_code errcode = -1;
    int retval = 0, i = 0;
    unsigned int len = 0;
    krb5_boolean print_usage = FALSE;
    FILE *pfile = NULL;
    char *str = NULL;
    char line[MAX_LEN];
    kdb5_dal_handle *dal_handle = NULL;
    struct data encrypted_passwd = {0, NULL};

    /* The arguments for setsrv password should contain the service object DN
     * and options to specify whether the password should be updated in file only
     * or both file and directory. So the possible combination of arguments are:
     * setsrvpw servicedn				wherein argc is 2
     * setsrvpw	-fileonly servicedn 			wherein argc is 3
     * setsrvpw -randpw servicedn			wherein argc is 3
     * setsrvpw -f filename servicedn			wherein argc is 4
     * setsrvpw -fileonly -f filename servicedn 	wherein argc is 5
     * setsrvpw -randpw -f filename servicedn 		wherein argc is 5
     */
    if ((argc < 2) || (argc > 5)) {
	print_usage = TRUE;
	goto cleanup;
    }

    dal_handle = (kdb5_dal_handle *)util_context->db_context;
    lparams = (krb5_ldap_context *) dal_handle->db_context;

    if (lparams == NULL) {
	printf(gettext("%s: Invalid LDAP handle\n"), me);
	goto cleanup;
    }

    /* Parse the arguments */
    for (i = 1; i < argc -1 ; i++) {
	if (strcmp(argv[i], "-randpw") == 0) {
	    random_passwd = 1;
	} else if (strcmp(argv[i], "-fileonly") == 0) {
	    set_dir_pwd = 0;
	} else if (strcmp(argv[i], "-f") == 0) {
	    if (argv[++i] == NULL) {
		print_usage = TRUE;
		goto cleanup;
	    }

	    file_name = strdup(argv[i]);
	    if (file_name == NULL) {
		com_err(me, ENOMEM, gettext("while setting service object password"));
		goto cleanup;
	    }
	    /* Verify if the file location has the proper file name
	     * for eg, if the file location is a directory like /home/temp/,
	     * we reject it.
	     */
	    filelen = strlen(file_name);
	    if ((filelen == 0) || (file_name[filelen-1] == '/')) {
		printf(gettext("%s: Filename not specified for setting service object password\n"), me);
		print_usage = TRUE;
		goto cleanup;
	    }
	} else {
	    printf(gettext("%s: Invalid option specified for \"setsrvpw\" command\n"), me);
	    print_usage = TRUE;
	    goto cleanup;
	}
    }

    if (i != argc-1) {
	print_usage = TRUE;
	goto cleanup;
    }

    service_object = strdup(argv[i]);
    if (service_object == NULL) {
	com_err(me, ENOMEM, gettext("while setting service object password"));
	goto cleanup;
    }

    if (strlen(service_object) == 0) {
	printf(gettext("%s: Service object not specified for \"setsrvpw\" command\n"), me);
	print_usage = TRUE;
	goto cleanup;
    }

    if (service_object[0] == '-') {
	print_usage = TRUE;
	goto cleanup;
    }

    if (file_name == NULL) {
	file_name = strdup(DEF_SERVICE_PASSWD_FILE);
	if (file_name == NULL) {
	    com_err(me, ENOMEM, gettext("while setting service object password"));
	    goto cleanup;
	}
    }

    if (set_dir_pwd) {
	if (db_inited == FALSE) {
	    if ((errcode = krb5_ldap_db_init(util_context, lparams))) {
		com_err(me, errcode, gettext("while initializing database"));
		goto cleanup;
	    }
	    db_init_local = TRUE;
	}
    }

    if (random_passwd) {
	if (!set_dir_pwd) {
	    printf(gettext("%s: Invalid option specified for \"setsrvpw\" command\n"), me);
	    print_usage = TRUE;
	    goto cleanup;
	} else {
	    /* Generate random password */

	    if ((errcode = generate_random_password(util_context, &passwd, &passwd_len))) {
		printf(gettext("%s: Failed to set service object password\n"), me);
		goto cleanup;
	    }
	    passwd_len = strlen(passwd);
	}
    } else {
	/* Get the service object password from the terminal */
	passwd = (char *)malloc(MAX_SERVICE_PASSWD_LEN + 1);
	if (passwd == NULL) {
	    com_err(me, ENOMEM, gettext("while setting service object password"));
	    goto cleanup;
	}
	memset(passwd, 0, MAX_SERVICE_PASSWD_LEN + 1);
	passwd_len = MAX_SERVICE_PASSWD_LEN;

	len = strlen(service_object);
	/* size of allocation=strlen of servicedn + strlen("Password for \" \"")=20 */
	prompt1 = (char *)malloc(len + 20);
	if (prompt1 == NULL) {
	    com_err(me, ENOMEM, gettext("while setting service object password"));
	    goto cleanup;
	}
	sprintf(prompt1, gettext("Password for \"%s\""), service_object);

	/* size of allocation=strlen of servicedn + strlen("Re-enter Password for \" \"")=30 */
	prompt2 = (char *)malloc(len + 30);
	if (prompt2 == NULL) {
	    com_err(me, ENOMEM, gettext("while setting service object password"));
	    free(prompt1);
	    goto cleanup;
	}
	sprintf(prompt2, gettext("Re-enter password for \"%s\""), service_object);

	retval = krb5_read_password(util_context, prompt1, prompt2, passwd, &passwd_len);
	free(prompt1);
	free(prompt2);
	if (retval) {
	    com_err(me, retval, gettext("while setting service object password"));
	    memset(passwd, 0, MAX_SERVICE_PASSWD_LEN);
	    goto cleanup;
	}
	if (passwd_len == 0) {
	    printf(gettext("%s: Invalid password\n"), me);
	    memset(passwd, 0, MAX_SERVICE_PASSWD_LEN);
	    goto cleanup;
	}
	passwd_len = strlen(passwd);
    }

    /* Hex the password */
    {
	krb5_data pwd, hex;
	pwd.length = passwd_len;
	pwd.data = passwd;

	errcode = tohex(pwd, &hex);
	if (errcode != 0) {
	    if (hex.length != 0) {
		memset(hex.data, 0, hex.length);
		free(hex.data);
	    }
	    com_err(me, errcode, gettext("Failed to convert the password to hex"));
	    memset(passwd, 0, passwd_len);
	    goto cleanup;
	}
	/* Password = {CRYPT}<encrypted password>:<encrypted key> */
	encrypted_passwd.value = (unsigned char *)malloc(strlen(service_object) +
							 1 + 5 + hex.length + 2);
	if (encrypted_passwd.value == NULL) {
	    com_err(me, ENOMEM, gettext("while setting service object password"));
	    memset(passwd, 0, passwd_len);
	    memset(hex.data, 0, hex.length);
	    free(hex.data);
	    goto cleanup;
	}
	encrypted_passwd.value[strlen(service_object) +
			       1 + 5 + hex.length + 1] = '\0';
	sprintf((char *)encrypted_passwd.value, "%s#{HEX}%s\n", service_object, hex.data);
	encrypted_passwd.len = strlen((char *)encrypted_passwd.value);
	memset(hex.data, 0, hex.length);
	free(hex.data);
    }

    /* We should check if the file exists and we have permission to write into that file */
    if (access(file_name, W_OK) == -1) {
	if (errno == ENOENT) {
	    mode_t omask;
	    int fd = -1;

	    printf(gettext("File does not exist. Creating the file %s...\n"), file_name);
	    omask = umask(077);
	    fd = creat(file_name, S_IRUSR|S_IWUSR);
	    umask(omask);
	    if (fd == -1) {
		com_err(me, errno, gettext("Error creating file %s"), file_name);
		memset(passwd, 0, passwd_len);
		goto cleanup;
	    }
	    close(fd);
	} else {
	    com_err(me, errno, gettext("Unable to access the file %s"), file_name);
	    memset(passwd, 0, passwd_len);
	    goto cleanup;
	}
    }

    if (set_dir_pwd) {
	if ((errcode = krb5_ldap_set_service_passwd(util_context, service_object, passwd)) != 0) {
	    com_err(me, errcode, gettext("Failed to set password for service object %s"), service_object);
	    memset(passwd, 0, passwd_len);
	    goto cleanup;
	}
    }

    memset(passwd, 0, passwd_len);


    /* TODO: file lock for the service password file */
    /* set password in the file */
    pfile = fopen(file_name, "r+F");
    if (pfile == NULL) {
	com_err(me, errno, gettext("Failed to open file %s"), file_name);
	goto cleanup;
    }

    while (fgets(line, MAX_LEN, pfile) != NULL) {
	if ((str = strstr(line, service_object)) != NULL) {
	    if (line[strlen(service_object)] == '#') {
		break;
	    }
	    str = NULL;
	}
    }
    if (str == NULL) {
	if (feof(pfile)) {
	    /* If the service object dn is not present in the service password file */
	    if (fwrite(encrypted_passwd.value, (unsigned int)encrypted_passwd.len, 1, pfile) != 1) {
		com_err(me, errno, gettext("Failed to write service object password to file"));
		goto cleanup;
	    }
	} else {
	    com_err(me, errno, gettext("Error reading service object password file"));
	    goto cleanup;
	}
	fclose(pfile);
	pfile = NULL;
    } else {
	/* Password entry for the service object is already present in the file */
	/* Delete the existing entry and add the new entry */
	FILE *newfile = NULL;
	mode_t omask;

	/* Create a new file with the extension .tmp */
	tmp_file = (char *) malloc(sizeof(char) * (strlen(file_name) + 4 + 1));
	if (tmp_file == NULL) {
	    com_err(me, ENOMEM, gettext("while setting service object password"));
	    goto cleanup;
	}
	sprintf(tmp_file,"%s.%s",file_name,"tmp");

	omask = umask(077);
	newfile = fopen(tmp_file, "w+F");
	umask(omask);
	if (newfile == NULL) {
	    com_err(me, errno, gettext("Error creating file %s"), tmp_file);
	    goto cleanup;
	}


	fseek(pfile, 0, SEEK_SET);
	while (fgets(line, MAX_LEN, pfile) != NULL) {
	    if (((str = strstr(line, service_object)) != NULL) && (line[strlen(service_object)] == '#')) {
		if (fprintf(newfile, "%s", encrypted_passwd.value) < 0) {
		    com_err(me, errno, gettext("Failed to write service object password to file"));
		    fclose(newfile);
		    unlink(tmp_file);
		    goto cleanup;
		}
	    } else {
		len = strlen(line);
		if (fprintf(newfile, "%s", line) < 0) {
		    com_err(me, errno, gettext("Failed to write service object password to file"));
		    fclose(newfile);
		    unlink(tmp_file);
		    goto cleanup;
		}
	    }
	}

	if (!feof(pfile)) {
	    com_err(me, errno, gettext("Error reading service object password file"));
	    fclose(newfile);
	    unlink(tmp_file);
	    goto cleanup;
	}

	/* TODO: file lock for the service password file */
	fclose(pfile);
	pfile = NULL;

	fclose(newfile);
	newfile = NULL;

	if (unlink(file_name) == 0) {
	    link(tmp_file, file_name);
	} else {
	    com_err(me, errno, gettext("Failed to write service object password to file"));
	    unlink(tmp_file);
	    goto cleanup;
	}
	unlink(tmp_file);
    }
    errcode = 0;

cleanup:
    if (db_init_local)
	krb5_ldap_close(util_context);

    if (service_object)
	free(service_object);

    if (file_name)
	free(file_name);

    if (passwd)
	free(passwd);

    if (encrypted_passwd.value) {
	memset(encrypted_passwd.value, 0, encrypted_passwd.len);
	free(encrypted_passwd.value);
    }

    if (pfile)
	fclose(pfile);

    if (tmp_file)
	free(tmp_file);

    if (print_usage)
	db_usage(SET_SRV_PW);

    return errcode;
}

#else /* #ifdef HAVE_EDIRECTORY */

/*
 * Convert the user supplied password into hexadecimal and stash it. Only a
 * little more secure than storing plain password in the file ...
 */
void
kdb5_ldap_stash_service_password(argc, argv)
    int argc;
    char **argv;
{
    int ret = 0;
    unsigned int passwd_len = 0;
    /* Solaris Kerberos */
    char *me = progname;
    char *service_object = NULL;
    char *file_name = NULL, *tmp_file = NULL;
    char passwd[MAX_SERVICE_PASSWD_LEN];
    char *str = NULL;
    char line[MAX_LEN];
    int fd;
    FILE *pfile = NULL;
    krb5_boolean print_usage = FALSE;
    krb5_data hexpasswd = {0, 0, NULL};
    mode_t old_mode = 0;

    /*
     * Format:
     *   stashsrvpw [-f filename] service_dn
     * where
     *   'service_dn' is the DN of the service object
     *   'filename' is the path of the stash file
     */
    if (argc != 2 && argc != 4) {
	print_usage = TRUE;
	goto cleanup;
    }

    if (argc == 4) {
	/* Find the stash file name */
	if (strcmp (argv[1], "-f") == 0) {
	    if (((file_name = strdup (argv[2])) == NULL) ||
	        ((service_object = strdup (argv[3])) == NULL)) {
	        com_err(me, ENOMEM, gettext("while setting service object password"));
	        goto cleanup;
	    }
	} else if (strcmp (argv[2], "-f") == 0) {
	    if (((file_name = strdup (argv[3])) == NULL) ||
	        ((service_object = strdup (argv[1])) == NULL)) {
	        com_err(me, ENOMEM, gettext("while setting service object password"));
	        goto cleanup;
	    }
	} else {
	    print_usage = TRUE;
	    goto cleanup;
	}
	if (file_name == NULL) {
	    com_err(me, ENOMEM, gettext("while setting service object password"));
	    goto cleanup;
	}
    } else { /* argc == 2 */
	char *section;

	service_object = strdup (argv[1]);
	if (service_object == NULL) {
	    com_err(me, ENOMEM, gettext("while setting service object password"));
	    goto cleanup;
	}

	/* Pick up the stash-file name from krb5.conf */
	profile_get_string(util_context->profile, KDB_REALM_SECTION,
			   util_context->default_realm, KDB_MODULE_POINTER, NULL, &section);

	if (section == NULL) {
	    profile_get_string(util_context->profile, KDB_MODULE_DEF_SECTION,
			       KDB_MODULE_POINTER, NULL, NULL, &section);
	    if (section == NULL) {
		/* Stash file path neither in krb5.conf nor on command line */
		file_name = strdup(DEF_SERVICE_PASSWD_FILE);
	        if (file_name == NULL) {
	            com_err(me, ENOMEM, gettext("while setting service object password"));
	            goto cleanup;
	        }
		goto done;
	    }
	}

	profile_get_string (util_context->profile, KDB_MODULE_SECTION, section,
			    "ldap_service_password_file", NULL, &file_name);

	/*
	 * Solaris Kerberos: use default if ldap_service_password_file not set
	 */
	if (file_name == NULL) {
	    file_name = strdup(DEF_SERVICE_PASSWD_FILE);
	    if (file_name == NULL) {
		com_err(me, ENOMEM, gettext("while setting service object password"));
		goto cleanup;
	    }
	}
    }
done:

    /* Get password from user */
    {
	char prompt1[256], prompt2[256];

	/* Get the service object password from the terminal */
	memset(passwd, 0, sizeof (passwd));
	passwd_len = sizeof (passwd);

	/* size of prompt = strlen of servicedn + strlen("Password for \" \"") */
	assert (sizeof (prompt1) > (strlen (service_object)
				    + sizeof ("Password for \" \"")));
	sprintf(prompt1, gettext("Password for \"%s\""), service_object);

	/* size of prompt = strlen of servicedn + strlen("Re-enter Password for \" \"") */
	assert (sizeof (prompt2) > (strlen (service_object)
				    + sizeof ("Re-enter Password for \" \"")));
	sprintf(prompt2, gettext("Re-enter password for \"%s\""), service_object);

	ret = krb5_read_password(util_context, prompt1, prompt2, passwd, &passwd_len);
	if (ret != 0) {
	    com_err(me, ret, gettext("while setting service object password"));
	    memset(passwd, 0, sizeof (passwd));
	    goto cleanup;
	}

	if (passwd_len == 0) {
	    printf(gettext("%s: Invalid password\n"), me);
	    memset(passwd, 0, MAX_SERVICE_PASSWD_LEN);
	    goto cleanup;
	}
    }

    /* Convert the password to hexadecimal */
    {
	krb5_data pwd;

	pwd.length = passwd_len;
	pwd.data = passwd;

	ret = tohex(pwd, &hexpasswd);
	if (ret != 0) {
	    com_err(me, ret, gettext("Failed to convert the password to hexadecimal"));
	    memset(passwd, 0, passwd_len);
	    goto cleanup;
	}
    }
    memset(passwd, 0, passwd_len);

    /* TODO: file lock for the service passowrd file */

    /* set password in the file */
#if 0 /* ************ Begin IFDEF'ed OUT ***************************** */
    old_mode = umask(0177);
    pfile = fopen(file_name, "a+");
    if (pfile == NULL) {
	com_err(me, errno, gettext("Failed to open file %s: %s"), file_name,
		strerror (errno));
	goto cleanup;
    }
    rewind (pfile);
    umask(old_mode);
#else
    /* Solaris Kerberos: safer than the above */
    fd = open(file_name, O_CREAT|O_RDWR|O_APPEND, 0600);
    if (fd < 0) {
	com_err(me, errno, gettext("Failed to open file %s: %s"), file_name,
		strerror (errno));
	goto cleanup;
    }
    pfile = fdopen(fd, "a+F");
    if (pfile == NULL) {
	com_err(me, errno, gettext("Failed to open file %s: %s"), file_name,
		strerror (errno));
	goto cleanup;
    }
    rewind (pfile);
#endif

    while (fgets (line, MAX_LEN, pfile) != NULL) {
	if ((str = strstr (line, service_object)) != NULL) {
	    /*
	     * White spaces not allowed, # delimits the service dn from the
	     * password
	     */
	    if (line [strlen (service_object)] == '#')
		break;
	    str = NULL;
	}
    }

    if (str == NULL) {
	if (feof(pfile)) {
	    /* If the service object dn is not present in the service password file */
	    if (fprintf(pfile, "%s#{HEX}%s\n", service_object, hexpasswd.data) < 0) {
		com_err(me, errno, gettext("Failed to write service object password to file"));
		fclose(pfile);
		goto cleanup;
	    }
	} else {
	    com_err(me, errno, gettext("Error reading service object password file"));
	    fclose(pfile);
	    goto cleanup;
	}
	fclose(pfile);
    } else {
	/*
	 * Password entry for the service object is already present in the file
	 * Delete the existing entry and add the new entry
	 */
	FILE *newfile;

	mode_t omask;

	/* Create a new file with the extension .tmp */
	tmp_file = (char *) malloc(sizeof(char) * (strlen(file_name) + 4 + 1));
	if (tmp_file == NULL) {
	    com_err(me, ENOMEM, gettext("while setting service object password"));
	    fclose(pfile);
	    goto cleanup;
	}
	sprintf(tmp_file,"%s.%s",file_name,"tmp");

	omask = umask(077);
	newfile = fopen(tmp_file, "wF");
	umask (omask);
	if (newfile == NULL) {
	    com_err(me, errno, gettext("Error creating file %s"), tmp_file);
	    fclose(pfile);
	    goto cleanup;
	}

	fseek(pfile, 0, SEEK_SET);
	while (fgets(line, MAX_LEN, pfile) != NULL) {
	    if (((str = strstr(line, service_object)) != NULL) &&
		(line[strlen(service_object)] == '#')) {
		if (fprintf(newfile, "%s#{HEX}%s\n", service_object, hexpasswd.data) < 0) {
		    com_err(me, errno, gettext("Failed to write service object password to file"));
		    fclose(newfile);
		    unlink(tmp_file);
		    fclose(pfile);
		    goto cleanup;
		}
	    } else {
		if (fprintf (newfile, "%s", line) < 0) {
		    com_err(me, errno, gettext("Failed to write service object password to file"));
		    fclose(newfile);
		    unlink(tmp_file);
		    fclose(pfile);
		    goto cleanup;
		}
	    }
	}

	if (!feof(pfile)) {
	    com_err(me, errno, gettext("Error reading service object password file"));
	    fclose(newfile);
	    unlink(tmp_file);
	    fclose(pfile);
	    goto cleanup;
	}

	/* TODO: file lock for the service passowrd file */

	fclose(pfile);
	fclose(newfile);

	ret = rename(tmp_file, file_name);
	if (ret != 0) {
	    com_err(me, errno, gettext("Failed to write service object password to "
		    "file"));
	    goto cleanup;
	}
    }
    ret = 0;

cleanup:

    if (hexpasswd.length != 0) {
	memset(hexpasswd.data, 0, hexpasswd.length);
	free(hexpasswd.data);
    }

    if (service_object)
	free(service_object);

    if (file_name)
	free(file_name);

    if (tmp_file)
	free(tmp_file);

    if (print_usage)
	usage();
/*	db_usage(STASH_SRV_PW); */

    if (ret)
	exit_status++;
}

#endif /* #ifdef HAVE_EDIRECTORY */
