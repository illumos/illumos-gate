/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


/*
 * kadmin/ldap_util/kdb5_ldap_util.c
 *
 * (C) Copyright 1990,1991, 1996 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * Export of this software from the United States of America may
 *   require a specific license from the United States Government.
 *   It is the responsibility of any person or organization contemplating
 *   export to obtain such a license before exporting.
 *
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of M.I.T. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 *
 *
 * Edit a KDC database.
 */

/*
 * Copyright (C) 1998 by the FundsXpress, INC.
 *
 * All rights reserved.
 *
 * Export of this software from the United States of America may require
 * a specific license from the United States Government.  It is the
 * responsibility of any person or organization contemplating export to
 * obtain such a license before exporting.
 *
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of FundsXpress. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  FundsXpress makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.
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

#include <stdio.h>
#include <time.h>

#include <k5-int.h>
#include <kadm5/admin.h>
#include <adm_proto.h>
#include <libintl.h>
#include <locale.h>
#include "kdb5_ldap_util.h"

typedef void (*cmd_func)(int, char **);
int cmd_index(char *name);

char *mkey_password = 0;
int exit_status = 0;
krb5_context util_context;
kadm5_config_params global_params;
krb5_boolean db_inited = FALSE;

char *progname;
krb5_boolean manual_mkey = FALSE;

/*
 * This function prints the usage of kdb5_ldap_util, which is
 * the LDAP configuration utility.
 */
void usage()
{
    fprintf(stderr, "%s: "
"kdb5_ldap_util [-D user_dn [-w passwd]] [-H ldapuri]\n"
"\tcmd [cmd_options]\n"

/* Create realm */
"create          [-subtrees subtree_dn_list] [-sscope search_scope] [-containerref container_reference_dn]\n"
#ifdef HAVE_EDIRECTORY
"\t\t[-kdcdn kdc_service_list] [-admindn admin_service_list]\n"
"\t\t[-pwddn passwd_service_list]\n"
#endif
"\t\t[-m|-P password|-sf stashfilename] [-k mkeytype] [-s]\n"
"\t\t[-maxtktlife max_ticket_life] [-maxrenewlife max_renewable_ticket_life]\n"
"\t\t[ticket_flags] [-r realm]\n"

/* modify realm */
"modify          [-subtrees subtree_dn_list] [-sscope search_scope] [-containerref container_reference_dn]\n"
#ifdef HAVE_EDIRECTORY
"\t\t[-kdcdn kdc_service_list |\n"
"\t\t[-clearkdcdn kdc_service_list] [-addkdcdn kdc_service_list]]\n"
"\t\t[-admindn admin_service_list | [-clearadmindn admin_service_list]\n"
"\t\t[-addadmindn admin_service_list]] [-pwddn passwd_service_list |\n"
"\t\t[-clearpwddn passwd_service_list] [-addpwddn passwd_service_list]]\n"
#endif
"\t\t[-maxtktlife max_ticket_life] [-maxrenewlife max_renewable_ticket_life]\n"
"\t\t[ticket_flags] [-r realm]\n"
/* View realm */
"view            [-r realm]\n"

/* Destroy realm */
"destroy	        [-f] [-r realm]\n"

/* List realms */
"list\n"

#ifdef HAVE_EDIRECTORY
/* Create Service */
"create_service  {-kdc|-admin|-pwd} [-servicehost service_host_list]\n"
"\t\t[-realm realm_list] \n"
"\t\t[-randpw|-fileonly] [-f filename] service_dn\n"

/* Modify service */
"modify_service  [-servicehost service_host_list |\n"
"\t\t[-clearservicehost service_host_list]\n"
"\t\t[-addservicehost service_host_list]]\n"
"\t\t[-realm realm_list | [-clearrealm realm_list]\n"
"\t\t[-addrealm realm_list]] service_dn\n"

/* View Service */
"view_service    service_dn\n"

/* Destroy Service */
"destroy_service [-force] [-f stashfilename] service_dn\n"

/* List services */
"list_service    [-basedn base_dn]\n"

/* Set Service password */
"setsrvpw        [-randpw|-fileonly] [-f filename] service_dn\n"

#else

/* Stash the service password */
"stashsrvpw      [-f filename] service_dn\n"

#endif

/* Create policy */
"create_policy   [-r realm] [-maxtktlife max_ticket_life]\n"
"\t\t[-maxrenewlife max_renewable_ticket_life] [ticket_flags] policy\n"

/* Modify policy */
"modify_policy   [-r realm] [-maxtktlife max_ticket_life]\n"
"\t\t[-maxrenewlife max_renewable_ticket_life] [ticket_flags] policy\n"

/* View policy */
"view_policy     [-r realm] policy\n"

/* Destroy policy */
"destroy_policy  [-r realm] [-force] policy\n"

/* List policies */
"list_policy     [-r realm]\n",
    gettext("Usage"));
}

void db_usage (int type) {
    /*
     * This should print usage of 'type' command. For now, we will print usage
     * of all commands.
     */
    usage ();
}

/* The help messages for all sub-commands should be in the
 * same order as listed in this table.
 */
static struct _cmd_table {
    char *name;
    cmd_func func;
    int opendb;
} cmd_table[] = {
    {"create", kdb5_ldap_create, 1},
    {"modify", kdb5_ldap_modify, 1},
    {"view", kdb5_ldap_view, 1},
    {"destroy", kdb5_ldap_destroy, 1},
    {"list", kdb5_ldap_list, 1},
#ifdef HAVE_EDIRECTORY
    {"create_service", kdb5_ldap_create_service, 1},
    {"modify_service", kdb5_ldap_modify_service, 1},
    {"view_service", kdb5_ldap_view_service, 1},
    {"destroy_service", kdb5_ldap_destroy_service, 1},
    {"list_service",kdb5_ldap_list_services,1},
    {"setsrvpw", kdb5_ldap_set_service_password, 0},
#else
    {"stashsrvpw", kdb5_ldap_stash_service_password, 0},
#endif
    {"create_policy", kdb5_ldap_create_policy, 1},
    {"modify_policy", kdb5_ldap_modify_policy, 1},
    {"view_policy", kdb5_ldap_view_policy, 1},
    {"destroy_policy", kdb5_ldap_destroy_policy, 1},
    {"list_policy", kdb5_ldap_list_policies, 1},
    {NULL, NULL, 0},
};


/*
 * The function cmd_lookup returns the structure matching the
 * command name and returns NULL if nothing matches.
 */
static struct _cmd_table *cmd_lookup(name)
    char *name;
{
    int i;

    for (i = 0; cmd_table[i].name != NULL; i++)
	if (strcmp(cmd_table[i].name, name) == 0)
	    return &cmd_table[i];

    return NULL;
}


/*
 * The function cmd_index provides the offset of the command
 * in the command table, which can be used to get the corresponding
 * help from the help message table.
 */
int cmd_index(name)
    char *name;
{
    int i;

    if (name == NULL)
	return -1;

    for (i = 0; cmd_table[i].name != NULL; i++)
	if (strcmp(cmd_table[i].name, name) == 0)
	    return i;

    return -1;
}

static void extended_com_err_fn (const char *myprog, errcode_t code,
				 const char *fmt, va_list args)
{
    const char *emsg;
    /* Solaris Kerberos: code should be like that in kdb5_util.c */
    if (code) {
	emsg = krb5_get_error_message (util_context, code);
	fprintf (stderr, "%s: %s ", myprog, emsg);
	krb5_free_error_message (util_context, emsg);
    } else {
	fprintf (stderr, "%s: ", myprog);
    }
    vfprintf (stderr, fmt, args);
    fprintf (stderr, "\n");
}

int main(argc, argv)
    int argc;
    char *argv[];
{
    struct _cmd_table *cmd = NULL;
    char *koptarg = NULL, **cmd_argv = NULL;
    int cmd_argc = 0;
    krb5_error_code retval;
    int usage_print = 0;
    int gp_is_static = 1;
    krb5_error_code db_retval = 1;
    char *bind_dn = NULL;
    char *passwd = NULL;
    char *ldap_server = NULL;
    unsigned int ldapmask = 0;
    unsigned int passwd_len = 0;
    char *prompt = NULL;
    kdb5_dal_handle *dal_handle = NULL;
    krb5_ldap_context *ldap_context=NULL;
    char *value = NULL, *conf_section = NULL;
    krb5_boolean realm_name_required = TRUE;
    krb5_boolean print_help_message = FALSE;

    /*
     * Solaris Kerberos:
     * Ensure that "progname" is set before calling com_err.
     */
    progname = (strrchr(argv[0], '/') ? strrchr(argv[0], '/')+1 : argv[0]);

    retval = krb5_init_context(&util_context);
    set_com_err_hook(extended_com_err_fn);
    if (retval) {
	com_err (progname, retval, gettext("while initializing Kerberos code"));
	exit_status++;
	goto cleanup;
    }

    cmd_argv = (char **) malloc(sizeof(char *)*argc);
    if (cmd_argv == NULL) {
	com_err(progname, ENOMEM, gettext("while creating sub-command arguments"));
	exit_status++;
	goto cleanup;
    }
    memset(cmd_argv, 0, sizeof(char *)*argc);
    cmd_argc = 1;

    memset(&global_params, 0, sizeof(kadm5_config_params));

    argv++; argc--;
    while (*argv) {
	if (strcmp(*argv, "--help") == 0) {
	    print_help_message = TRUE;
	}
	if (strcmp(*argv, "-P") == 0 && ARG_VAL) {
	    mkey_password = koptarg;
	    manual_mkey = TRUE;
	} else if (strcmp(*argv, "-r") == 0 && ARG_VAL) {
	    global_params.realm = koptarg;
	    global_params.mask |= KADM5_CONFIG_REALM;
	    /* not sure this is really necessary */
	    if ((retval = krb5_set_default_realm(util_context,
						 global_params.realm))) {
		com_err(progname, retval, gettext("while setting default realm name"));
		exit_status++;
		goto cleanup;
	    }
	} else if (strcmp(*argv, "-k") == 0 && ARG_VAL) {
	    if (krb5_string_to_enctype(koptarg, &global_params.enctype))
		com_err(argv[0], 0, gettext("%s is an invalid enctype"), koptarg);
	    else
		global_params.mask |= KADM5_CONFIG_ENCTYPE;
	} else if (strcmp(*argv, "-M") == 0 && ARG_VAL) {
	    global_params.mkey_name = koptarg;
	    global_params.mask |= KADM5_CONFIG_MKEY_NAME;
	} else if (strcmp(*argv, "-sf") == 0 && ARG_VAL) {
	    global_params.stash_file = koptarg;
	    global_params.mask |= KADM5_CONFIG_STASH_FILE;
	} else if (strcmp(*argv, "-m") == 0) {
	    manual_mkey = TRUE;
	    global_params.mkey_from_kbd = 1;
	    global_params.mask |= KADM5_CONFIG_MKEY_FROM_KBD;
	} else if (strcmp(*argv, "-D") == 0 && ARG_VAL) {
	    bind_dn = koptarg;
	    if (bind_dn == NULL) {
		com_err(progname, ENOMEM, gettext("while reading ldap parameters"));
		exit_status++;
		goto cleanup;
	    }
	    ldapmask |= CMD_LDAP_D;
	} else if (strcmp(*argv, "-w") == 0 && ARG_VAL) {
	    passwd = strdup(koptarg);
	    if (passwd == NULL) {
		com_err(progname, ENOMEM, gettext("while reading ldap parameters"));
		exit_status++;
		goto cleanup;
	    }
	    ldapmask |= CMD_LDAP_W;
	} else if (strcmp(*argv, "-H") == 0 && ARG_VAL) {
	    ldap_server = koptarg;
	    if (ldap_server == NULL) {
		com_err(progname, ENOMEM, gettext("while reading ldap parameters"));
		exit_status++;
		goto cleanup;
	    }
	    ldapmask |= CMD_LDAP_H;
	} else if (cmd_lookup(*argv) != NULL) {
	    if (cmd_argv[0] == NULL)
		cmd_argv[0] = *argv;
	    else {
		free(cmd_argv);
		cmd_argv = NULL;
		usage();
		goto cleanup;
	    }
	} else {
	    cmd_argv[cmd_argc++] = *argv;
	}
	argv++; argc--;
    }

    if (cmd_argv[0] == NULL) {
	free(cmd_argv);
	cmd_argv = NULL;
	usage();
	goto cleanup;
    }

    /* if we need to print the help message (because of --help option)
     * we will print the help corresponding to the sub-command.
     */
    if (print_help_message) {
	char *cmd_name = cmd_argv[0];
	free(cmd_argv);
	cmd_argv = NULL;
	usage();
	goto cleanup;
    }

    /* We need to check for the presence of default realm name only in
     * the case of realm related operations like create, destroy etc.
     */
    if ((strcmp(cmd_argv[0], "list") == 0) ||
        (strcmp(cmd_argv[0], "stashsrvpw") == 0)) {
        realm_name_required = FALSE;
    }

    if (!util_context->default_realm) {
	char *temp = NULL;
	retval = krb5_get_default_realm(util_context, &temp);
	if (retval) {
	    if (realm_name_required) {
		com_err (progname, retval, gettext("while getting default realm"));
		exit_status++;
		goto cleanup;
	    }
	} else
	    util_context->default_realm = temp;
    }
    /* If we have the realm name, we can safely say that
     * realm_name is required so that we don't neglect any information.
     */
    else
	realm_name_required = TRUE;

    retval = profile_get_string(util_context->profile, KDB_REALM_SECTION,
				util_context->default_realm, KDB_MODULE_POINTER,
				NULL,
				&value);

    if (!(value)) {
	retval = profile_get_string(util_context->profile, KDB_MODULE_DEF_SECTION,
				    KDB_MODULE_POINTER, NULL,
				    NULL,
				    &value);
	if (!(value)) {
	    if (util_context->default_realm)
		conf_section = strdup(util_context->default_realm);
	} else {
	    conf_section = strdup(value);
	    free(value);
	}
    } else {
	conf_section = strdup(value);
	free(value);
    }

    if (realm_name_required) {
	retval = kadm5_get_config_params(util_context, 1,
					 &global_params, &global_params);
	if (retval) {
	    com_err(argv[0], retval, gettext("while retreiving configuration parameters"));
	    exit_status++;
	    goto cleanup;
	}
	gp_is_static = 0;
    }

    if ((retval = krb5_ldap_lib_init()) != 0) {
	com_err(argv[0], retval, gettext("while initializing error handling"));
	exit_status++;
	goto cleanup;
    }

    /* Initialize the ldap context */
    ldap_context = calloc(sizeof(krb5_ldap_context), 1);
    if (ldap_context == NULL) {
	com_err(argv[0], ENOMEM, gettext("while initializing ldap handle"));
	exit_status++;
	goto cleanup;
    }

    ldap_context->kcontext = util_context;

    /* If LDAP parameters are specified, replace them with the values from config */
    if (ldapmask & CMD_LDAP_D) {
	/* If password is not specified, prompt for it */
	if (passwd == NULL) {
	    passwd = (char *)malloc(MAX_PASSWD_LEN);
	    if (passwd == NULL) {
		com_err(argv[0], ENOMEM, gettext("while retrieving ldap configuration"));
		exit_status++;
		goto cleanup;
	    }
	    prompt = (char *)malloc(MAX_PASSWD_PROMPT_LEN);
	    if (prompt == NULL) {
		free(passwd);
		passwd = NULL;
		com_err(argv[0], ENOMEM, gettext("while retrieving ldap configuration"));
		exit_status++;
		goto cleanup;
	    }
	    memset(passwd, 0, sizeof(passwd));
	    passwd_len = MAX_PASSWD_LEN - 1;
	    snprintf(prompt, MAX_PASSWD_PROMPT_LEN, gettext("Password for \"%s\""), bind_dn);

	    db_retval = krb5_read_password(util_context, prompt, NULL, passwd, &passwd_len);

	    if ((db_retval) || (passwd_len == 0)) {
		com_err(argv[0], ENOMEM, gettext("while retrieving ldap configuration"));
		free(passwd);
		passwd = NULL;
		exit_status++;
		goto cleanup;
	    }
	}

	ldap_context->bind_pwd = passwd;
    }

    /* If ldaphost is specified, release entry filled by configuration & use this */
    if (ldapmask & CMD_LDAP_H) {

	ldap_context->server_info_list = (krb5_ldap_server_info **) calloc (2, sizeof (krb5_ldap_server_info *)) ;
	if (ldap_context->server_info_list == NULL) {
	    com_err(argv[0], ENOMEM, gettext("while initializing server list"));
	    exit_status++;
	    goto cleanup;
	}

	ldap_context->server_info_list[0] = (krb5_ldap_server_info *) calloc (1, sizeof (krb5_ldap_server_info));
	if (ldap_context->server_info_list[0] == NULL) {
	    com_err(argv[0], ENOMEM, gettext("while initializing server list"));
	    exit_status++;
	    goto cleanup;
	}

	ldap_context->server_info_list[0]->server_status = NOTSET;

	ldap_context->server_info_list[0]->server_name = strdup(ldap_server);
	if (ldap_context->server_info_list[0]->server_name == NULL) {
	    com_err(argv[0], ENOMEM, gettext("while initializing server list"));
	    exit_status++;
	    goto cleanup;
	}
    }
    if (bind_dn) {
	ldap_context->bind_dn = strdup(bind_dn);
	if (ldap_context->bind_dn == NULL) {
	    com_err(argv[0], ENOMEM, gettext("while retrieving ldap configuration"));
	    exit_status++;
	    goto cleanup;
	}
    } else
	ldap_context->bind_dn = NULL;

    ldap_context->service_type = SERVICE_DN_TYPE_CLIENT;

    if (realm_name_required) {
	if ((global_params.enctype != ENCTYPE_UNKNOWN) &&
	    (!krb5_c_valid_enctype(global_params.enctype))) {
	    com_err(argv[0], KRB5_PROG_KEYTYPE_NOSUPP,
		    gettext("while setting up enctype %d"), global_params.enctype);
	}
    }

    cmd = cmd_lookup(cmd_argv[0]);

    /* Setup DAL handle to access the database */
    dal_handle = calloc((size_t)1, sizeof(kdb5_dal_handle));
    if (dal_handle == NULL) {
	goto cleanup;
    }
    dal_handle->db_context = ldap_context;
    util_context->db_context = (void *) dal_handle;

    db_retval = krb5_ldap_read_server_params(util_context, conf_section, KRB5_KDB_SRV_TYPE_OTHER);
    if (db_retval) {
	com_err(argv[0], db_retval, gettext("while reading ldap configuration"));
	exit_status++;
	goto cleanup;
    }

    if (cmd->opendb) {
	db_retval = krb5_ldap_db_init(util_context, ldap_context);
	if (db_retval) {
	    com_err(progname, db_retval, gettext("while initializing database"));
	    exit_status++;
	    goto cleanup;
	}
	db_inited = TRUE;
    }
    (*cmd->func)(cmd_argc, cmd_argv);

    goto cleanup;

cleanup:
    if (passwd)
	memset(passwd, 0, sizeof(passwd));
    if (ldap_context && ldap_context->bind_pwd)
	memset(ldap_context->bind_pwd, 0, sizeof(ldap_context->bind_pwd));

    if (util_context) {
	if (gp_is_static == 0)
	    kadm5_free_config_params(util_context, &global_params);
	krb5_ldap_close(util_context);
	krb5_free_context(util_context);
    }

    if (cmd_argv)
	free(cmd_argv);
    if (prompt)
	free(prompt);
    if (conf_section)
	free(conf_section);
    if (dal_handle)
	free(dal_handle);

    if (usage_print) {
	usage();
    }

    return exit_status;
}
