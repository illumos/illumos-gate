/*
 * Copyright 2017 Gary Mills
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * kadmin/ldap_util/kdb5_ldap_realm.c
 *
 * Copyright 1990,1991,2001, 2002 by the Massachusetts Institute of Technology.
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

/*
 * Create / Modify / Destroy / View / List realm(s)
 */

/* Needed for getting the definition of KRB5_TL_DB_ARGS */
#define SECURID

#include <stdio.h>
#include <k5-int.h>
#include <kadm5/admin.h>
#include <libintl.h>
#include <locale.h>
#include "kdb5_ldap_util.h"
#include "kdb5_ldap_list.h"
#include <ldap_principal.h>
#include <ldap_krbcontainer.h>
extern time_t get_date(char *); /* kadmin/cli/getdate.o */

char *yes = "yes\n"; /* \n to compare against result of fgets */
krb5_key_salt_tuple def_kslist = {ENCTYPE_DES_CBC_CRC, KRB5_KDB_SALTTYPE_NORMAL};

struct realm_info rblock = {
    KRB5_KDB_MAX_LIFE,
    KRB5_KDB_MAX_RLIFE,
    KRB5_KDB_EXPIRATION,
    KRB5_KDB_DEF_FLAGS,
    (krb5_keyblock *) NULL,
    1,
    &def_kslist
};

krb5_data tgt_princ_entries[] = {
    {0, KRB5_TGS_NAME_SIZE, KRB5_TGS_NAME},
    {0, 0, 0} };

krb5_data db_creator_entries[] = {
    {0, sizeof("db_creation")-1, "db_creation"} };


static krb5_principal_data db_create_princ = {
    0,					/* magic number */
    {0, 0, 0},				/* krb5_data realm */
    db_creator_entries,			/* krb5_data *data */
    1,					/* int length */
    KRB5_NT_SRV_INST			/* int type */
};

extern char *mkey_password;
extern char *progname;
extern kadm5_config_params global_params;

static void print_realm_params(krb5_ldap_realm_params *rparams, int mask);
static int kdb_ldap_create_principal (krb5_context context, krb5_principal
				      princ, enum ap_op op, struct realm_info *pblock);


static char *strdur(time_t duration);
static int get_ticket_policy(krb5_ldap_realm_params *rparams, int *i, char *argv[],int argc);
static krb5_error_code krb5_dbe_update_mod_princ_data_new (krb5_context context, krb5_db_entry *entry, krb5_timestamp mod_date, krb5_const_principal mod_princ);
static krb5_error_code krb5_dbe_update_tl_data_new ( krb5_context context, krb5_db_entry *entry, krb5_tl_data *new_tl_data);

#define ADMIN_LIFETIME 60*60*3 /* 3 hours */
#define CHANGEPW_LIFETIME 60*5 /* 5 minutes */

static int get_ticket_policy(rparams,i,argv,argc)
    krb5_ldap_realm_params *rparams;
    int *i;
    char *argv[];
    int argc;
{
    time_t date;
    time_t now;
    int mask = 0;
    krb5_error_code retval = 0;

    /* Solaris Kerberos */
    char *me = progname;

    time(&now);
    if (!strcmp(argv[*i], "-maxtktlife")) {
	if (++(*i) > argc-1)
	    goto err;
	date = get_date(argv[*i]);
	if (date == (time_t)(-1)) {
	    retval = EINVAL;
	    com_err (me, retval, gettext("while providing time specification"));
	    goto err;
	}
	rparams->max_life = date-now;
	mask |= LDAP_REALM_MAXTICKETLIFE;
    }


    else if (!strcmp(argv[*i], "-maxrenewlife")) {
	if (++(*i) > argc-1)
	    goto err;

	date = get_date(argv[*i]);
	if (date == (time_t)(-1)) {
	    retval = EINVAL;
	    com_err (me, retval, gettext("while providing time specification"));
	    goto err;
	}
	rparams->max_renewable_life = date-now;
	mask |= LDAP_REALM_MAXRENEWLIFE;
    } else if (!strcmp((argv[*i] + 1), "allow_postdated")) {
	if (*(argv[*i]) == '+')
	    rparams->tktflags &= (int)(~KRB5_KDB_DISALLOW_POSTDATED);
	else if (*(argv[*i]) == '-')
	    rparams->tktflags |= KRB5_KDB_DISALLOW_POSTDATED;
	else
	    goto err;

	mask |= LDAP_REALM_KRBTICKETFLAGS;
    } else if (!strcmp((argv[*i] + 1), "allow_forwardable")) {
	if (*(argv[*i]) == '+')
	    rparams->tktflags &= (int)(~KRB5_KDB_DISALLOW_FORWARDABLE);

	else if (*(argv[*i]) == '-')
	    rparams->tktflags |= KRB5_KDB_DISALLOW_FORWARDABLE;
	else
	    goto err;

	mask |= LDAP_REALM_KRBTICKETFLAGS;
    } else if (!strcmp((argv[*i] + 1), "allow_renewable")) {
	if (*(argv[*i]) == '+')
	    rparams->tktflags &= (int)(~KRB5_KDB_DISALLOW_RENEWABLE);
	else if (*(argv[*i]) == '-')
	    rparams->tktflags |= KRB5_KDB_DISALLOW_RENEWABLE;
	else
	    goto err;

	mask |= LDAP_REALM_KRBTICKETFLAGS;
    } else if (!strcmp((argv[*i] + 1), "allow_proxiable")) {
	if (*(argv[*i]) == '+')
	    rparams->tktflags &= (int)(~KRB5_KDB_DISALLOW_PROXIABLE);
	else if (*(argv[*i]) == '-')
	    rparams->tktflags |= KRB5_KDB_DISALLOW_PROXIABLE;
	else
	    goto err;

	mask |= LDAP_REALM_KRBTICKETFLAGS;
    } else if (!strcmp((argv[*i] + 1), "allow_dup_skey")) {
	if (*(argv[*i]) == '+')
	    rparams->tktflags &= (int)(~KRB5_KDB_DISALLOW_DUP_SKEY);
	else if (*(argv[*i]) == '-')
	    rparams->tktflags |= KRB5_KDB_DISALLOW_DUP_SKEY;
	else
	    goto err;

	mask |= LDAP_REALM_KRBTICKETFLAGS;
    }

    else if (!strcmp((argv[*i] + 1), "requires_preauth")) {
	if (*(argv[*i]) == '+')
	    rparams->tktflags |= KRB5_KDB_REQUIRES_PRE_AUTH;
	else if (*(argv[*i]) == '-')
	    rparams->tktflags &= (int)(~KRB5_KDB_REQUIRES_PRE_AUTH);
	else
	    goto err;

	mask |= LDAP_REALM_KRBTICKETFLAGS;
    } else if (!strcmp((argv[*i] + 1), "requires_hwauth")) {
	if (*(argv[*i]) == '+')
	    rparams->tktflags |= KRB5_KDB_REQUIRES_HW_AUTH;
	else if (*(argv[*i]) == '-')
	    rparams->tktflags &= (int)(~KRB5_KDB_REQUIRES_HW_AUTH);
	else
	    goto err;

	mask |= LDAP_REALM_KRBTICKETFLAGS;
    } else if (!strcmp((argv[*i] + 1), "allow_svr")) {
	if (*(argv[*i]) == '+')
	    rparams->tktflags &= (int)(~KRB5_KDB_DISALLOW_SVR);
	else if (*(argv[*i]) == '-')
	    rparams->tktflags |= KRB5_KDB_DISALLOW_SVR;
	else
	    goto err;

	mask |= LDAP_REALM_KRBTICKETFLAGS;
    } else if (!strcmp((argv[*i] + 1), "allow_tgs_req")) {
	if (*(argv[*i]) == '+')
	    rparams->tktflags &= (int)(~KRB5_KDB_DISALLOW_TGT_BASED);
	else if (*(argv[*i]) == '-')
	    rparams->tktflags |= KRB5_KDB_DISALLOW_TGT_BASED;
	else
	    goto err;

	mask |= LDAP_REALM_KRBTICKETFLAGS;
    } else if (!strcmp((argv[*i] + 1), "allow_tix")) {
	if (*(argv[*i]) == '+')
	    rparams->tktflags &= (int)(~KRB5_KDB_DISALLOW_ALL_TIX);
	else if (*(argv[*i]) == '-')
	    rparams->tktflags |= KRB5_KDB_DISALLOW_ALL_TIX;
	else
	    goto err;

	mask |= LDAP_REALM_KRBTICKETFLAGS;
    } else if (!strcmp((argv[*i] + 1), "needchange")) {
	if (*(argv[*i]) == '+')
	    rparams->tktflags |= KRB5_KDB_REQUIRES_PWCHANGE;
	else if (*(argv[*i]) == '-')
	    rparams->tktflags &= (int)(~KRB5_KDB_REQUIRES_PWCHANGE);
	else
	    goto err;

	mask |= LDAP_REALM_KRBTICKETFLAGS;
    } else if (!strcmp((argv[*i] + 1), "password_changing_service")) {
	if (*(argv[*i]) == '+')
	    rparams->tktflags |= KRB5_KDB_PWCHANGE_SERVICE;
	else if (*(argv[*i]) == '-')
	    rparams->tktflags &= (int)(~KRB5_KDB_PWCHANGE_SERVICE);
	else
	    goto err;

	mask |=LDAP_REALM_KRBTICKETFLAGS;
    }

err:

    return mask;
}

/*
 * This function will create a realm on the LDAP Server, with
 * the specified attributes.
 */
void kdb5_ldap_create(argc, argv)
    int argc;
    char *argv[];
{
    krb5_error_code retval = 0;
    krb5_keyblock master_keyblock;
    krb5_ldap_realm_params *rparams = NULL;
    krb5_principal master_princ = NULL;
    kdb5_dal_handle *dal_handle = NULL;
    krb5_ldap_context *ldap_context=NULL;
    krb5_boolean realm_obj_created = FALSE;
    krb5_boolean create_complete = FALSE;
    krb5_boolean print_usage = FALSE;
    krb5_boolean no_msg = FALSE;
    char *oldcontainerref=NULL;
    char pw_str[1024];
    int do_stash = 0;
    int i = 0;
    int mask = 0, ret_mask = 0;
    char **list = NULL;
#ifdef HAVE_EDIRECTORY
    int rightsmask = 0;
#endif

    memset(&master_keyblock, 0, sizeof(master_keyblock));

    rparams = (krb5_ldap_realm_params *)malloc(
	sizeof(krb5_ldap_realm_params));
    if (rparams == NULL) {
	retval = ENOMEM;
	goto cleanup;
    }
    memset(rparams, 0, sizeof(krb5_ldap_realm_params));

    /* Parse the arguments */
    for (i = 1; i < argc; i++) {
	if (!strcmp(argv[i], "-subtrees")) {
	    if (++i > argc-1)
		goto err_usage;

	    if(strncmp(argv[i], "", strlen(argv[i]))!=0) {
		list = (char **) calloc(MAX_LIST_ENTRIES, sizeof(char *));
		if (list == NULL) {
		    retval = ENOMEM;
		    goto cleanup;
		}
		if ((retval = krb5_parse_list(argv[i], LIST_DELIMITER, list))) {
		    free(list);
		    list = NULL;
		    goto cleanup;
		}

		rparams->subtreecount=0;
		while(list[rparams->subtreecount]!=NULL)
		    (rparams->subtreecount)++;
		rparams->subtree = list;
	    } else if(strncmp(argv[i], "", strlen(argv[i]))==0) {
		 /* dont allow subtree value to be set at the root(NULL, "") of the tree */
		 /* Solaris Kerberos */
		 com_err(progname, EINVAL,
			  gettext("for subtree while creating realm '%s'"),
			   global_params.realm);
		 goto err_nomsg;
	    }
	    rparams->subtree[rparams->subtreecount] = NULL;
	    mask |= LDAP_REALM_SUBTREE;
	} else if (!strcmp(argv[i], "-containerref")) {
	    if (++i > argc-1)
		goto err_usage;
	    if(strncmp(argv[i], "", strlen(argv[i]))==0) {
		 /* dont allow containerref value to be set at the root(NULL, "") of the tree */
		 /* Solaris Kerberos */
		 com_err(progname, EINVAL,
			  gettext("for container reference while creating realm '%s'"),
			   global_params.realm);
		 goto err_nomsg;
	    }
	    rparams->containerref = strdup(argv[i]);
	    if (rparams->containerref == NULL) {
		retval = ENOMEM;
		goto cleanup;
	    }
	    mask |= LDAP_REALM_CONTREF;
	} else if (!strcmp(argv[i], "-sscope")) {
	    if (++i > argc-1)
		goto err_usage;
	    /* Possible values for search scope are
	     * one (or 1) and sub (or 2)
	     */
	    if (!strcasecmp(argv[i], "one")) {
		rparams->search_scope = 1;
	    } else if (!strcasecmp(argv[i], "sub")) {
		rparams->search_scope = 2;
	    } else {
		rparams->search_scope = atoi(argv[i]);
		if ((rparams->search_scope != 1) &&
		    (rparams->search_scope != 2)) {
		    /* Solaris Kerberos */
		    com_err(progname, EINVAL,
			    gettext("invalid search scope while creating realm '%s'"),
			    global_params.realm);
		    goto err_nomsg;
		}
	    }
	    mask |= LDAP_REALM_SEARCHSCOPE;
	}
#ifdef HAVE_EDIRECTORY
	else if (!strcmp(argv[i], "-kdcdn")) {
	    if (++i > argc-1)
		goto err_usage;
	    rparams->kdcservers = (char **)malloc(
		sizeof(char *) * MAX_LIST_ENTRIES);
	    if (rparams->kdcservers == NULL) {
		retval = ENOMEM;
		goto cleanup;
	    }
	    memset(rparams->kdcservers, 0, sizeof(char*)*MAX_LIST_ENTRIES);
	    if ((retval = krb5_parse_list(argv[i], LIST_DELIMITER,
					  rparams->kdcservers))) {
		goto cleanup;
	    }
	    mask |= LDAP_REALM_KDCSERVERS;
	} else if (!strcmp(argv[i], "-admindn")) {
	    if (++i > argc-1)
		goto err_usage;
	    rparams->adminservers = (char **)malloc(
		sizeof(char *) * MAX_LIST_ENTRIES);
	    if (rparams->adminservers == NULL) {
		retval = ENOMEM;
		goto cleanup;
	    }
	    memset(rparams->adminservers, 0, sizeof(char*)*MAX_LIST_ENTRIES);
	    if ((retval = krb5_parse_list(argv[i], LIST_DELIMITER,
					  rparams->adminservers))) {
		goto cleanup;
	    }
	    mask |= LDAP_REALM_ADMINSERVERS;
	} else if (!strcmp(argv[i], "-pwddn")) {
	    if (++i > argc-1)
		goto err_usage;
	    rparams->passwdservers = (char **)malloc(
		sizeof(char *) * MAX_LIST_ENTRIES);
	    if (rparams->passwdservers == NULL) {
		retval = ENOMEM;
		goto cleanup;
	    }
	    memset(rparams->passwdservers, 0, sizeof(char*)*MAX_LIST_ENTRIES);
	    if ((retval = krb5_parse_list(argv[i], LIST_DELIMITER,
					  rparams->passwdservers))) {
		goto cleanup;
	    }
	    mask |= LDAP_REALM_PASSWDSERVERS;
	}
#endif
	else if (!strcmp(argv[i], "-s")) {
	    do_stash = 1;
	} else if ((ret_mask= get_ticket_policy(rparams,&i,argv,argc)) !=0) {
	    mask|=ret_mask;
	}

	else {
	    printf(gettext("'%s' is an invalid option\n"), argv[i]);
	    goto err_usage;
	}
    }

    /* If the default enctype/salttype is not provided, use the
     * default values and also add to the list of supported
     * enctypes/salttype
     */

    rblock.max_life = global_params.max_life;
    rblock.max_rlife = global_params.max_rlife;
    rblock.expiration = global_params.expiration;
    rblock.flags = global_params.flags;
    rblock.nkslist = global_params.num_keysalts;
    rblock.kslist = global_params.keysalts;

    krb5_princ_set_realm_data(util_context, &db_create_princ, global_params.realm);
    krb5_princ_set_realm_length(util_context, &db_create_princ, strlen(global_params.realm));

    printf(gettext("Initializing database for realm '%s'\n"), global_params.realm);

    if (!mkey_password) {
	unsigned int pw_size;
	printf(gettext("You will be prompted for the database Master Password.\n"));
	printf(gettext("It is important that you NOT FORGET this password.\n"));
	fflush(stdout);

	pw_size = sizeof (pw_str);
	memset(pw_str, 0, pw_size);

	retval = krb5_read_password(util_context, KRB5_KDC_MKEY_1, KRB5_KDC_MKEY_2,
				    pw_str, &pw_size);
	if (retval) {
	    /* Solaris Kerberos */
	    com_err(progname, retval, gettext("while reading master key from keyboard"));
	    goto err_nomsg;
	}
	mkey_password = pw_str;
    }

    rparams->mkey.enctype = global_params.enctype;
    /* We are sure that 'mkey_password' is a regular string ... */
    rparams->mkey.length = strlen(mkey_password) + 1;
    rparams->mkey.contents = (krb5_octet *)strdup(mkey_password);
    if (rparams->mkey.contents == NULL) {
	retval = ENOMEM;
	goto cleanup;
    }

    rparams->realm_name = strdup(global_params.realm);
    if (rparams->realm_name == NULL) {
	retval = ENOMEM;
	/* Solaris Kerberos */
	com_err(progname, ENOMEM, gettext("while creating realm '%s'"),
		global_params.realm);
	goto err_nomsg;
    }

    dal_handle = (kdb5_dal_handle *) util_context->db_context;
    ldap_context = (krb5_ldap_context *) dal_handle->db_context;
    if (!ldap_context) {
	retval = EINVAL;
	goto cleanup;
    }

    /* read the kerberos container */
    if ((retval=krb5_ldap_read_krbcontainer_params (util_context,
						    &(ldap_context->krbcontainer))) == KRB5_KDB_NOENTRY) {
	/* Prompt the user for entering the DN of Kerberos container */
	char krb_location[MAX_KRB_CONTAINER_LEN];
	krb5_ldap_krbcontainer_params kparams;
	int krb_location_len = 0;
	memset(&kparams, 0, sizeof(kparams));

	/* Read the kerberos container location from configuration file */
	if (ldap_context->conf_section) {
	    if ((retval=profile_get_string(util_context->profile,
					   KDB_MODULE_SECTION, ldap_context->conf_section,
					   "ldap_kerberos_container_dn", NULL,
					   &kparams.DN)) != 0) {
		goto cleanup;
	    }
	}
	if (kparams.DN == NULL) {
	    if ((retval=profile_get_string(util_context->profile,
					   KDB_MODULE_DEF_SECTION,
					   "ldap_kerberos_container_dn", NULL,
					   NULL, &kparams.DN)) != 0) {
		goto cleanup;
	    }
	}

	printf(gettext("\nKerberos container is missing. Creating now...\n"));
	if (kparams.DN == NULL) {
#ifdef HAVE_EDIRECTORY
	    printf(gettext("Enter DN of Kerberos container [cn=Kerberos,cn=Security]: "));
#else
	    printf(gettext("Enter DN of Kerberos container: "));
#endif
	    if (fgets(krb_location, MAX_KRB_CONTAINER_LEN, stdin) != NULL) {
		/* Remove the newline character at the end */
		krb_location_len = strlen(krb_location);
		if ((krb_location[krb_location_len - 1] == '\n') ||
		    (krb_location[krb_location_len - 1] == '\r')) {
		    krb_location[krb_location_len - 1] = '\0';
		    krb_location_len--;
		}
		/* If the user has not given any input, take the default location */
		else if (krb_location[0] == '\0')
		    kparams.DN = NULL;
		else
		    kparams.DN = krb_location;
	    } else
		kparams.DN = NULL;
	}

	/* create the kerberos container */
	retval = krb5_ldap_create_krbcontainer(util_context,
					       ((kparams.DN != NULL) ? &kparams : NULL));
	if (retval)
	    goto cleanup;

	retval = krb5_ldap_read_krbcontainer_params(util_context,
						    &(ldap_context->krbcontainer));
	if (retval) {
	    /* Solaris Kerberos */
	    com_err(progname, retval, gettext("while reading kerberos container information"));
	    goto cleanup;
	}
    } else if (retval) {
	/* Solaris Kerberos */
	com_err(progname, retval, gettext("while reading kerberos container information"));
	goto cleanup;
    }

    if ((retval = krb5_ldap_create_realm(util_context,
					 /* global_params.realm, */ rparams, mask))) {
	goto cleanup;
    }

    /* We just created the Realm container. Here starts our transaction tracking */
    realm_obj_created = TRUE;

    if ((retval = krb5_ldap_read_realm_params(util_context,
					      global_params.realm,
					      &(ldap_context->lrparams),
					      &mask))) {
	/* Solaris Kerberos */
	com_err(progname, retval, gettext("while reading information of realm '%s'"),
		global_params.realm);
	goto err_nomsg;
    }
    ldap_context->lrparams->realm_name = strdup(global_params.realm);
    if (ldap_context->lrparams->realm_name == NULL) {
	retval = ENOMEM;
	goto cleanup;
    }

    /* assemble & parse the master key name */
    if ((retval = krb5_db_setup_mkey_name(util_context,
					  global_params.mkey_name,
					  global_params.realm,
					  0, &master_princ))) {
	/* Solaris Kerberos */
	com_err(progname, retval, gettext("while setting up master key name"));
	goto err_nomsg;
    }

    /* Obtain master key from master password */
    {
	krb5_data master_salt, pwd;

	pwd.data = mkey_password;
	pwd.length = strlen(mkey_password);
	retval = krb5_principal2salt(util_context, master_princ, &master_salt);
	if (retval) {
	    /* Solaris Kerberos */
	    com_err(progname, retval, gettext("while calculating master key salt"));
	    goto err_nomsg;
	}

	retval = krb5_c_string_to_key(util_context, rparams->mkey.enctype,
				      &pwd, &master_salt, &master_keyblock);

	if (master_salt.data)
	    free(master_salt.data);

	if (retval) {
	    /* Solaris Kerberos */
	    com_err(progname, retval, gettext("while transforming master key from password"));
	    goto err_nomsg;
	}

    }

    rblock.key = &master_keyblock;
    ldap_context->lrparams->mkey = master_keyblock;
    ldap_context->lrparams->mkey.contents = (krb5_octet *) malloc
	(master_keyblock.length);
    if (ldap_context->lrparams->mkey.contents == NULL) {
	retval = ENOMEM;
	goto cleanup;
    }
    memcpy (ldap_context->lrparams->mkey.contents, master_keyblock.contents,
	    master_keyblock.length);

    /* Create special principals inside the realm subtree */
    {
	char princ_name[MAX_PRINC_SIZE];
	krb5_principal_data tgt_princ = {
	    0,					/* magic number */
	    {0, 0, 0},				/* krb5_data realm */
	    tgt_princ_entries,			/* krb5_data *data */
	    2,					/* int length */
	    KRB5_NT_SRV_INST			/* int type */
	};
	krb5_principal p, temp_p=NULL;

	krb5_princ_set_realm_data(util_context, &tgt_princ, global_params.realm);
	krb5_princ_set_realm_length(util_context, &tgt_princ, strlen(global_params.realm));
	krb5_princ_component(util_context, &tgt_princ,1)->data = global_params.realm;
	krb5_princ_component(util_context, &tgt_princ,1)->length = strlen(global_params.realm);
	/* The container reference value is set to NULL, to avoid service principals
	 * getting created within the container reference at realm creation */
	if (ldap_context->lrparams->containerref != NULL) {
	    oldcontainerref = ldap_context->lrparams->containerref;
	    ldap_context->lrparams->containerref = NULL;
	}

	/* Create 'K/M' ... */
	rblock.flags |= KRB5_KDB_DISALLOW_ALL_TIX;
	if ((retval = kdb_ldap_create_principal(util_context, master_princ, MASTER_KEY, &rblock))) {
	    /* Solaris Kerberos */
	    com_err(progname, retval, gettext("while adding entries to the database"));
	    goto err_nomsg;
	}

	/* Create 'krbtgt' ... */
	rblock.flags = 0; /* reset the flags */
	if ((retval = kdb_ldap_create_principal(util_context, &tgt_princ, TGT_KEY, &rblock))) {
	    /* Solaris Kerberos */
	    com_err(progname, retval, gettext("while adding entries to the database"));
	    goto err_nomsg;
	}
	/*
	 * Solaris Kerberos:
	 * The kadmin/admin principal is unused on Solaris. This principal is used
	 * in AUTH_GSSAPI but Solaris doesn't support AUTH_GSSAPI. RPCSEC_GSS can only
	 * be used with host-based principals. 
	 *
	 */
#if 0 /* ************ Begin IFDEF'ed OUT ***************************** */
	/* Create 'kadmin/admin' ... */
	snprintf(princ_name, sizeof(princ_name), "%s@%s", KADM5_ADMIN_SERVICE, global_params.realm);
	if ((retval = krb5_parse_name(util_context, princ_name, &p))) {
	    /* Solaris Kerberos */
	    com_err(progname, retval, gettext("while adding entries to the database"));
	    goto err_nomsg;
	}
	rblock.max_life = ADMIN_LIFETIME;
	rblock.flags = KRB5_KDB_DISALLOW_TGT_BASED;
	if ((retval = kdb_ldap_create_principal(util_context, p, TGT_KEY, &rblock))) {
	    krb5_free_principal(util_context, p);
	    /* Solaris Kerberos */
	    com_err(progname, retval, gettext("while adding entries to the database"));
	    goto err_nomsg;
	}
	krb5_free_principal(util_context, p);
#endif /* ************** END IFDEF'ed OUT ***************************** */

	/* Create 'kadmin/changepw' ... */
	snprintf(princ_name, sizeof(princ_name), "%s@%s", KADM5_CHANGEPW_SERVICE, global_params.realm);
	if ((retval = krb5_parse_name(util_context, princ_name, &p))) {
	    /* Solaris Kerberos */
	    com_err(progname, retval, gettext("while adding entries to the database"));
	    goto err_nomsg;
	}
	rblock.max_life = CHANGEPW_LIFETIME;
	rblock.flags = KRB5_KDB_DISALLOW_TGT_BASED | KRB5_KDB_PWCHANGE_SERVICE;
	if ((retval = kdb_ldap_create_principal(util_context, p, TGT_KEY, &rblock))) {
	    krb5_free_principal(util_context, p);
	    /* Solaris Kerberos */
	    com_err(progname, retval, gettext("while adding entries to the database"));
	    goto err_nomsg;
	}
	krb5_free_principal(util_context, p);

	/* Create 'kadmin/history' ... */
	snprintf(princ_name, sizeof(princ_name), "%s@%s", KADM5_HIST_PRINCIPAL, global_params.realm);
	if ((retval = krb5_parse_name(util_context, princ_name, &p))) {
	    /* Solaris Kerberos */
	    com_err(progname, retval, gettext("while adding entries to the database"));
	    goto err_nomsg;
	}
	rblock.max_life = global_params.max_life;
	rblock.flags = 0;
	if ((retval = kdb_ldap_create_principal(util_context, p, TGT_KEY, &rblock))) {
	    krb5_free_principal(util_context, p);
	    /* Solaris Kerberos */
	    com_err(progname, retval, gettext("while adding entries to the database"));
	    goto err_nomsg;
	}
	krb5_free_principal(util_context, p);

	/* Create 'kadmin/<hostname>' ... */
	if ((retval=krb5_sname_to_principal(util_context, NULL, KADM5_ADMIN_HOST_SERVICE, KRB5_NT_SRV_HST, &p))) {
	    /* Solaris Kerberos */
	    com_err(progname, retval, gettext("krb5_sname_to_principal, while adding entries to the database"));
	    goto err_nomsg;
	}

	if ((retval=krb5_copy_principal(util_context, p, &temp_p))) {
	    /* Solaris Kerberos */
	    com_err(progname, retval, gettext("krb5_copy_principal, while adding entries to the database"));
	    goto err_nomsg;
	}

	/* change the realm portion to the default realm */
	free(temp_p->realm.data);
	temp_p->realm.length = strlen(util_context->default_realm);
	temp_p->realm.data = strdup(util_context->default_realm);
	if (temp_p->realm.data == NULL) {
	    /* Solaris Kerberos */
	    com_err(progname, ENOMEM, gettext("while adding entries to the database"));
	    goto err_nomsg;
	}

	rblock.max_life = ADMIN_LIFETIME;
	rblock.flags = KRB5_KDB_DISALLOW_TGT_BASED;
	if ((retval = kdb_ldap_create_principal(util_context, temp_p, TGT_KEY, &rblock))) {
	    krb5_free_principal(util_context, p);
	    /* Solaris Kerberos */
	    com_err(progname, retval, gettext("while adding entries to the database"));
	    goto err_nomsg;
	}
	krb5_free_principal(util_context, temp_p);
	krb5_free_principal(util_context, p);

	/* Solaris Kerberos: Create 'changepw/<hostname>' ... */
	if ((retval=krb5_sname_to_principal(util_context, NULL, KADM5_CHANGEPW_HOST_SERVICE, KRB5_NT_SRV_HST, &p))) {
	    /* Solaris Kerberos */
	    com_err(progname, retval, gettext("krb5_sname_to_principal, while adding entries to the database"));
	    goto err_nomsg;
	}

	if ((retval=krb5_copy_principal(util_context, p, &temp_p))) {
	    /* Solaris Kerberos */
	    com_err(progname, retval, gettext("krb5_copy_principal, while adding entries to the database"));
	    goto err_nomsg;
	}

	/* change the realm portion to the default realm */
	free(temp_p->realm.data);
	temp_p->realm.length = strlen(util_context->default_realm);
	temp_p->realm.data = strdup(util_context->default_realm);
	if (temp_p->realm.data == NULL) {
	    /* Solaris Kerberos */
	    com_err(progname, ENOMEM, gettext("while adding entries to the database"));
	    goto err_nomsg;
	}

	rblock.max_life = ADMIN_LIFETIME;
	rblock.flags = KRB5_KDB_DISALLOW_TGT_BASED | KRB5_KDB_PWCHANGE_SERVICE;
	if ((retval = kdb_ldap_create_principal(util_context, temp_p, TGT_KEY, &rblock))) {
	    krb5_free_principal(util_context, p);
	    /* Solaris Kerberos */
	    com_err(progname, retval, gettext("while adding entries to the database"));
	    goto err_nomsg;
	}
	krb5_free_principal(util_context, temp_p);
	krb5_free_principal(util_context, p);

	if (oldcontainerref != NULL) {
	    ldap_context->lrparams->containerref = oldcontainerref;
	    oldcontainerref=NULL;
	}
    }

#ifdef HAVE_EDIRECTORY
    if ((mask & LDAP_REALM_KDCSERVERS) || (mask & LDAP_REALM_ADMINSERVERS) ||
	(mask & LDAP_REALM_PASSWDSERVERS)) {

	printf(gettext("Changing rights for the service object. Please wait ... "));
	fflush(stdout);

	rightsmask =0;
	rightsmask |= LDAP_REALM_RIGHTS;
	rightsmask |= LDAP_SUBTREE_RIGHTS;
	if ((rparams != NULL) && (rparams->kdcservers != NULL)) {
	    for (i=0; (rparams->kdcservers[i] != NULL); i++) {
		if ((retval=krb5_ldap_add_service_rights(util_context,
							 LDAP_KDC_SERVICE, rparams->kdcservers[i],
							 rparams->realm_name, rparams->subtree, rightsmask)) != 0) {
		    printf(gettext("failed\n"));
		    /* Solaris Kerberos */
		    com_err(progname, retval, gettext("while assigning rights to '%s'"),
			    rparams->realm_name);
		    goto err_nomsg;
		}
	    }
	}

	rightsmask = 0;
	rightsmask |= LDAP_REALM_RIGHTS;
	rightsmask |= LDAP_SUBTREE_RIGHTS;
	if ((rparams != NULL) && (rparams->adminservers != NULL)) {
	    for (i=0; (rparams->adminservers[i] != NULL); i++) {
		if ((retval=krb5_ldap_add_service_rights(util_context,
							 LDAP_ADMIN_SERVICE, rparams->adminservers[i],
							 rparams->realm_name, rparams->subtree, rightsmask)) != 0) {
		    printf(gettext("failed\n"));
		    /* Solaris Kerberos */
		    com_err(progname, retval, gettext("while assigning rights to '%s'"),
			    rparams->realm_name);
		    goto err_nomsg;
		}
	    }
	}

	rightsmask = 0;
	rightsmask |= LDAP_REALM_RIGHTS;
	rightsmask |= LDAP_SUBTREE_RIGHTS;
	if ((rparams != NULL) && (rparams->passwdservers != NULL)) {
	    for (i=0; (rparams->passwdservers[i] != NULL); i++) {
		if ((retval=krb5_ldap_add_service_rights(util_context,
							 LDAP_PASSWD_SERVICE, rparams->passwdservers[i],
							 rparams->realm_name, rparams->subtree, rightsmask)) != 0) {
		    printf(gettext("failed\n"));
		    /* Solaris Kerberos */
		    com_err(progname, retval, gettext("while assigning rights to '%s'"),
			    rparams->realm_name);
		    goto err_nomsg;
		}
	    }
	}

	printf(gettext("done\n"));
    }
#endif
    /* The Realm creation is completed. Here is the end of transaction */
    create_complete = TRUE;

    /* Stash the master key only if '-s' option is specified */
    if (do_stash || global_params.mask & KADM5_CONFIG_STASH_FILE) {
	retval = krb5_def_store_mkey(util_context,
				     global_params.stash_file,
				     master_princ,
				     &master_keyblock, NULL);
	if (retval) {
	    /* Solaris Kerberos */
	    com_err(progname, errno, gettext("while storing key"));
	    printf(gettext("Warning: couldn't stash master key.\n"));
	}
    }

    goto cleanup;


err_usage:
    print_usage = TRUE;

err_nomsg:
    no_msg = TRUE;

cleanup:
    /* If the Realm creation is not complete, do the roll-back here */
    if ((realm_obj_created) && (!create_complete))
	krb5_ldap_delete_realm(util_context, global_params.realm);

    if (rparams)
	krb5_ldap_free_realm_params(rparams);

    memset (pw_str, 0, sizeof (pw_str));

    if (print_usage)
	db_usage(CREATE_REALM);

    if (retval) {
	if (!no_msg) {
	    /* Solaris Kerberos */
	    com_err(progname, retval, gettext("while creating realm '%s'"),
		    global_params.realm);
	}
	exit_status++;
    }

    return;
}


/*
 * This function will modify the attributes of a given realm object
 */
void kdb5_ldap_modify(argc, argv)
    int argc;
    char *argv[];
{
    krb5_error_code retval = 0;
    krb5_ldap_realm_params *rparams = NULL;
    krb5_boolean print_usage = FALSE;
    krb5_boolean no_msg = FALSE;
    kdb5_dal_handle *dal_handle = NULL;
    krb5_ldap_context *ldap_context=NULL;
    int i = 0;
    int mask = 0, rmask = 0, ret_mask = 0;
    char **slist = {NULL};
#ifdef HAVE_EDIRECTORY
    int j = 0;
    char *list[MAX_LIST_ENTRIES];
    int existing_entries = 0, list_entries = 0;
    int newkdcdn = 0, newadmindn = 0, newpwddn = 0;
    char **tempstr = NULL;
    char **oldkdcdns = NULL;
    char **oldadmindns = NULL;
    char **oldpwddns = NULL;
    char **newkdcdns = NULL;
    char **newsubtrees = NULL;
    char **newadmindns = NULL;
    char **newpwddns = NULL;
    char **oldsubtrees = {NULL};
    int rightsmask = 0;
    int subtree_changed = 0;
#endif

    dal_handle = (kdb5_dal_handle *) util_context->db_context;
    ldap_context = (krb5_ldap_context *) dal_handle->db_context;
    if (!(ldap_context)) {
	retval = EINVAL;
	goto cleanup;
    }

    if ((retval = krb5_ldap_read_krbcontainer_params(util_context,
						     &(ldap_context->krbcontainer)))) {
	/* Solaris Kerberos */
	com_err(progname, retval, gettext("while reading Kerberos container information"));
	goto err_nomsg;
    }

    retval = krb5_ldap_read_realm_params(util_context,
					 global_params.realm, &rparams, &rmask);
    if (retval)
	goto cleanup;
    /* Parse the arguments */
    for (i = 1; i < argc; i++) {
	int k = 0;
	if (!strcmp(argv[i], "-subtrees")) {
	    if (++i > argc-1)
		goto err_usage;

	    if (rmask & LDAP_REALM_SUBTREE) {
		if (rparams->subtree) {
#ifdef HAVE_EDIRECTORY
		    oldsubtrees =  (char **) calloc(rparams->subtreecount+1, sizeof(char *));
		    if (oldsubtrees == NULL) {
			retval = ENOMEM;
			goto cleanup;
		    }
		    for(k=0; rparams->subtree[k]!=NULL && rparams->subtreecount; k++) {
			oldsubtrees[k] = strdup(rparams->subtree[k]);
			if( oldsubtrees[k] == NULL ) {
			    retval = ENOMEM;
			    goto cleanup;
			}
		    }
#endif
		    for(k=0; k<rparams->subtreecount && rparams->subtree[k]; k++)
			free(rparams->subtree[k]);
		    rparams->subtreecount=0;
		}
	    }
	    if (strncmp(argv[i] ,"", strlen(argv[i]))!=0) {
		slist =  (char **) calloc(MAX_LIST_ENTRIES, sizeof(char *));
		if (slist == NULL) {
		    retval = ENOMEM;
		    goto cleanup;
		}
		if (( retval = krb5_parse_list(argv[i], LIST_DELIMITER, slist))) {
		    free(slist);
		    slist = NULL;
		    goto cleanup;
		}

		rparams->subtreecount=0;
		while(slist[rparams->subtreecount]!=NULL)
		    (rparams->subtreecount)++;
		rparams->subtree =  slist;
	    } else if(strncmp(argv[i], "", strlen(argv[i]))==0) {
		 /* dont allow subtree value to be set at the root(NULL, "") of the tree */
		    /* Solaris Kerberos */
		    com_err(progname, EINVAL,
			    gettext("for subtree while modifying realm '%s'"),
			    global_params.realm);
		    goto err_nomsg;
	    }
	    rparams->subtree[rparams->subtreecount] = NULL;
	    mask |= LDAP_REALM_SUBTREE;
	} else if (!strncmp(argv[i], "-containerref", strlen(argv[i]))) {
	    if (++i > argc-1)
		goto err_usage;
	    if(strncmp(argv[i], "", strlen(argv[i]))==0) {
		 /* dont allow containerref value to be set at the root(NULL, "") of the tree */
		 /* Solaris Kerberos */
		 com_err(progname, EINVAL,
			  gettext("for container reference while modifying realm '%s'"),
			   global_params.realm);
		 goto err_nomsg;
	    }
	    rparams->containerref = strdup(argv[i]);
	    if (rparams->containerref == NULL) {
		retval = ENOMEM;
		goto cleanup;
	    }
	    mask |= LDAP_REALM_CONTREF;
	} else if (!strcmp(argv[i], "-sscope")) {
	    if (++i > argc-1)
		goto err_usage;
	    /* Possible values for search scope are
	     * one (or 1) and sub (or 2)
	     */
	    if (strcasecmp(argv[i], "one") == 0) {
		rparams->search_scope = 1;
	    } else if (strcasecmp(argv[i], "sub") == 0) {
		rparams->search_scope = 2;
	    } else {
		rparams->search_scope = atoi(argv[i]);
		if ((rparams->search_scope != 1) &&
		    (rparams->search_scope != 2)) {
		    retval = EINVAL;
		    /* Solaris Kerberos */
		    com_err(progname, retval,
			    gettext("specified for search scope while modifying information of realm '%s'"),
			    global_params.realm);
		    goto err_nomsg;
		}
	    }
	    mask |= LDAP_REALM_SEARCHSCOPE;
	}
#ifdef HAVE_EDIRECTORY
	else if (!strcmp(argv[i], "-kdcdn")) {
	    if (++i > argc-1)
		goto err_usage;

	    if ((rmask & LDAP_REALM_KDCSERVERS) && (rparams->kdcservers)) {
		if (!oldkdcdns) {
		    /* Store the old kdc dns list for removing rights */
		    oldkdcdns = (char**) calloc(MAX_LIST_ENTRIES, sizeof(char*));
		    if (oldkdcdns == NULL) {
			retval = ENOMEM;
			goto cleanup;
		    }

		    for (j=0; rparams->kdcservers[j] != NULL; j++) {
			oldkdcdns[j] = strdup(rparams->kdcservers[j]);
			if (oldkdcdns[j] == NULL) {
			    retval = ENOMEM;
			    goto cleanup;
			}
		    }
		    oldkdcdns[j] = NULL;
		}

		krb5_free_list_entries(rparams->kdcservers);
		free(rparams->kdcservers);
	    }

	    rparams->kdcservers = (char **)malloc(
		sizeof(char *) * MAX_LIST_ENTRIES);
	    if (rparams->kdcservers == NULL) {
		retval = ENOMEM;
		goto cleanup;
	    }
	    memset(rparams->kdcservers, 0, sizeof(char *)*MAX_LIST_ENTRIES);
	    if ((retval = krb5_parse_list(argv[i], LIST_DELIMITER,
					  rparams->kdcservers))) {
		goto cleanup;
	    }
	    mask |= LDAP_REALM_KDCSERVERS;
	    /* Going to replace the existing value by this new value. Hence
	     * setting flag indicating that add or clear options will be ignored
	     */
	    newkdcdn = 1;
	} else if (!strcmp(argv[i], "-clearkdcdn")) {
	    if (++i > argc-1)
		goto err_usage;
	    if ((!newkdcdn) && (rmask & LDAP_REALM_KDCSERVERS) && (rparams->kdcservers)) {
		if (!oldkdcdns) {
		    /* Store the old kdc dns list for removing rights */
		    oldkdcdns = (char**) calloc(MAX_LIST_ENTRIES, sizeof(char*));
		    if (oldkdcdns == NULL) {
			retval = ENOMEM;
			goto cleanup;
		    }

		    for (j=0; rparams->kdcservers[j] != NULL; j++) {
			oldkdcdns[j] = strdup(rparams->kdcservers[j]);
			if (oldkdcdns[j] == NULL) {
			    retval = ENOMEM;
			    goto cleanup;
			}
		    }
		    oldkdcdns[j] = NULL;
		}

		memset(list, 0, sizeof(char *) * MAX_LIST_ENTRIES);
		if ((retval = krb5_parse_list(argv[i], LIST_DELIMITER, list))) {
		    goto cleanup;
		}
		list_modify_str_array(&rparams->kdcservers, (const char **)list,
				      LIST_MODE_DELETE);
		mask |= LDAP_REALM_KDCSERVERS;
		krb5_free_list_entries(list);
	    }
	} else if (!strcmp(argv[i], "-addkdcdn")) {
	    if (++i > argc-1)
		goto err_usage;
	    if (!newkdcdn) {
		if ((rmask & LDAP_REALM_KDCSERVERS) && (rparams->kdcservers) && (!oldkdcdns)) {
		    /* Store the old kdc dns list for removing rights */
		    oldkdcdns = (char**) calloc(MAX_LIST_ENTRIES, sizeof(char*));
		    if (oldkdcdns == NULL) {
			retval = ENOMEM;
			goto cleanup;
		    }

		    for (j = 0; rparams->kdcservers[j] != NULL; j++) {
			oldkdcdns[j] = strdup(rparams->kdcservers[j]);
			if (oldkdcdns[j] == NULL) {
			    retval = ENOMEM;
			    goto cleanup;
			}
		    }
		    oldkdcdns[j] = NULL;
		}

		memset(list, 0, sizeof(char *) * MAX_LIST_ENTRIES);
		if ((retval = krb5_parse_list(argv[i], LIST_DELIMITER, list))) {
		    goto cleanup;
		}
		existing_entries = list_count_str_array(rparams->kdcservers);
		list_entries = list_count_str_array(list);
		if (rmask & LDAP_REALM_KDCSERVERS) {
		    tempstr = (char **)realloc(
			rparams->kdcservers,
			sizeof(char *) * (existing_entries+list_entries+1));
		    if (tempstr == NULL) {
			retval = ENOMEM;
			goto cleanup;
		    }
		    rparams->kdcservers = tempstr;
		} else {
		    rparams->kdcservers = (char **)malloc(sizeof(char *) * (list_entries+1));
		    if (rparams->kdcservers == NULL) {
			retval = ENOMEM;
			goto cleanup;
		    }
		    memset(rparams->kdcservers, 0, sizeof(char *) * (list_entries+1));
		}
		list_modify_str_array(&rparams->kdcservers, (const char **)list,
				      LIST_MODE_ADD);
		mask |= LDAP_REALM_KDCSERVERS;
	    }
	} else if (!strcmp(argv[i], "-admindn")) {
	    if (++i > argc-1)
		goto err_usage;

	    if ((rmask & LDAP_REALM_ADMINSERVERS) && (rparams->adminservers)) {
		if (!oldadmindns) {
		    /* Store the old admin dns list for removing rights */
		    oldadmindns = (char**) calloc(MAX_LIST_ENTRIES, sizeof(char*));
		    if (oldadmindns == NULL) {
			retval = ENOMEM;
			goto cleanup;
		    }

		    for (j=0; rparams->adminservers[j] != NULL; j++) {
			oldadmindns[j] = strdup(rparams->adminservers[j]);
			if (oldadmindns[j] == NULL) {
			    retval = ENOMEM;
			    goto cleanup;
			}
		    }
		    oldadmindns[j] = NULL;
		}

		krb5_free_list_entries(rparams->adminservers);
		free(rparams->adminservers);
	    }

	    rparams->adminservers = (char **)malloc(
		sizeof(char *) * MAX_LIST_ENTRIES);
	    if (rparams->adminservers == NULL) {
		retval = ENOMEM;
		goto cleanup;
	    }
	    memset(rparams->adminservers, 0, sizeof(char *)*MAX_LIST_ENTRIES);
	    if ((retval = krb5_parse_list(argv[i], LIST_DELIMITER,
					  rparams->adminservers))) {
		goto cleanup;
	    }
	    mask |= LDAP_REALM_ADMINSERVERS;
	    /* Going to replace the existing value by this new value. Hence
	     * setting flag indicating that add or clear options will be ignored
	     */
	    newadmindn = 1;
	} else if (!strcmp(argv[i], "-clearadmindn")) {
	    if (++i > argc-1)
		goto err_usage;

	    if ((!newadmindn) && (rmask & LDAP_REALM_ADMINSERVERS) && (rparams->adminservers)) {
		if (!oldadmindns) {
		    /* Store the old admin dns list for removing rights */
		    oldadmindns = (char**) calloc(MAX_LIST_ENTRIES, sizeof(char*));
		    if (oldadmindns == NULL) {
			retval = ENOMEM;
			goto cleanup;
		    }

		    for (j=0; rparams->adminservers[j] != NULL; j++) {
			oldadmindns[j] = strdup(rparams->adminservers[j]);
			if (oldadmindns[j] == NULL) {
			    retval = ENOMEM;
			    goto cleanup;
			}
		    }
		    oldadmindns[j] = NULL;
		}

		memset(list, 0, sizeof(char *) * MAX_LIST_ENTRIES);
		if ((retval = krb5_parse_list(argv[i], LIST_DELIMITER, list))) {
		    goto cleanup;
		}
		list_modify_str_array(&rparams->adminservers, (const char **)list,
				      LIST_MODE_DELETE);
		mask |= LDAP_REALM_ADMINSERVERS;
		krb5_free_list_entries(list);
	    }
	} else if (!strcmp(argv[i], "-addadmindn")) {
	    if (++i > argc-1)
		goto err_usage;
	    if (!newadmindn) {
		if ((rmask & LDAP_REALM_ADMINSERVERS) && (rparams->adminservers) && (!oldadmindns)) {
		    /* Store the old admin dns list for removing rights */
		    oldadmindns = (char**) calloc(MAX_LIST_ENTRIES, sizeof(char*));
		    if (oldadmindns == NULL) {
			retval = ENOMEM;
			goto cleanup;
		    }

		    for (j=0; rparams->adminservers[j] != NULL; j++) {
			oldadmindns[j] = strdup(rparams->adminservers[j]);
			if (oldadmindns[j] == NULL) {
			    retval = ENOMEM;
			    goto cleanup;
			}
		    }
		    oldadmindns[j] = NULL;
		}

		memset(list, 0, sizeof(char *) * MAX_LIST_ENTRIES);
		if ((retval = krb5_parse_list(argv[i], LIST_DELIMITER, list))) {
		    goto cleanup;
		}
		existing_entries = list_count_str_array(rparams->adminservers);
		list_entries = list_count_str_array(list);
		if (rmask & LDAP_REALM_ADMINSERVERS) {
		    tempstr = (char **)realloc(
			rparams->adminservers,
			sizeof(char *) * (existing_entries+list_entries+1));
		    if (tempstr == NULL) {
			retval = ENOMEM;
			goto cleanup;
		    }
		    rparams->adminservers = tempstr;
		} else {
		    rparams->adminservers = (char **)malloc(sizeof(char *) * (list_entries+1));
		    if (rparams->adminservers == NULL) {
			retval = ENOMEM;
			goto cleanup;
		    }
		    memset(rparams->adminservers, 0, sizeof(char *) * (list_entries+1));
		}
		list_modify_str_array(&rparams->adminservers, (const char **)list,
				      LIST_MODE_ADD);
		mask |= LDAP_REALM_ADMINSERVERS;
	    }
	} else if (!strcmp(argv[i], "-pwddn")) {
	    if (++i > argc-1)
		goto err_usage;

	    if ((rmask & LDAP_REALM_PASSWDSERVERS) && (rparams->passwdservers)) {
		if (!oldpwddns) {
		    /* Store the old pwd dns list for removing rights */
		    oldpwddns = (char**) calloc(MAX_LIST_ENTRIES, sizeof(char*));
		    if (oldpwddns == NULL) {
			retval = ENOMEM;
			goto cleanup;
		    }

		    for (j=0; rparams->passwdservers[j] != NULL; j++) {
			oldpwddns[j] = strdup(rparams->passwdservers[j]);
			if (oldpwddns[j] == NULL) {
			    retval = ENOMEM;
			    goto cleanup;
			}
		    }
		    oldpwddns[j] = NULL;
		}

		krb5_free_list_entries(rparams->passwdservers);
		free(rparams->passwdservers);
	    }

	    rparams->passwdservers = (char **)malloc(
		sizeof(char *) * MAX_LIST_ENTRIES);
	    if (rparams->passwdservers == NULL) {
		retval = ENOMEM;
		goto cleanup;
	    }
	    memset(rparams->passwdservers, 0, sizeof(char *)*MAX_LIST_ENTRIES);
	    if ((retval = krb5_parse_list(argv[i], LIST_DELIMITER,
					  rparams->passwdservers))) {
		goto cleanup;
	    }
	    mask |= LDAP_REALM_PASSWDSERVERS;
	    /* Going to replace the existing value by this new value. Hence
	     * setting flag indicating that add or clear options will be ignored
	     */
	    newpwddn = 1;
	} else if (!strcmp(argv[i], "-clearpwddn")) {
	    if (++i > argc-1)
		goto err_usage;

	    if ((!newpwddn) && (rmask & LDAP_REALM_PASSWDSERVERS) && (rparams->passwdservers)) {
		if (!oldpwddns) {
		    /* Store the old pwd dns list for removing rights */
		    oldpwddns = (char**) calloc(MAX_LIST_ENTRIES, sizeof(char*));
		    if (oldpwddns == NULL) {
			retval = ENOMEM;
			goto cleanup;
		    }

		    for (j=0; rparams->passwdservers[j] != NULL; j++) {
			oldpwddns[j] = strdup(rparams->passwdservers[j]);
			if (oldpwddns[j] == NULL) {
			    retval = ENOMEM;
			    goto cleanup;
			}
		    }
		    oldpwddns[j] = NULL;
		}

		memset(list, 0, sizeof(char *) * MAX_LIST_ENTRIES);
		if ((retval = krb5_parse_list(argv[i], LIST_DELIMITER, list))) {
		    goto cleanup;
		}
		list_modify_str_array(&rparams->passwdservers, (const char**)list,
				      LIST_MODE_DELETE);
		mask |= LDAP_REALM_PASSWDSERVERS;
		krb5_free_list_entries(list);
	    }
	} else if (!strcmp(argv[i], "-addpwddn")) {
	    if (++i > argc-1)
		goto err_usage;
	    if (!newpwddn) {
		if ((rmask & LDAP_REALM_PASSWDSERVERS) && (rparams->passwdservers) && (!oldpwddns)) {
		    /* Store the old pwd dns list for removing rights */
		    oldpwddns = (char**) calloc(MAX_LIST_ENTRIES, sizeof(char*));
		    if (oldpwddns == NULL) {
			retval = ENOMEM;
			goto cleanup;
		    }

		    for (j=0; rparams->passwdservers[j] != NULL; j++) {
			oldpwddns[j] = strdup(rparams->passwdservers[j]);
			if (oldpwddns[j] == NULL) {
			    retval = ENOMEM;
			    goto cleanup;
			}
		    }
		    oldpwddns[j] = NULL;
		}

		memset(list, 0, sizeof(char *) * MAX_LIST_ENTRIES);
		if ((retval = krb5_parse_list(argv[i], LIST_DELIMITER, list))) {
		    goto cleanup;
		}
		existing_entries = list_count_str_array(rparams->passwdservers);
		list_entries = list_count_str_array(list);
		if (rmask & LDAP_REALM_PASSWDSERVERS) {
		    tempstr = (char **)realloc(
			rparams->passwdservers,
			sizeof(char *) * (existing_entries+list_entries+1));
		    if (tempstr == NULL) {
			retval = ENOMEM;
			goto cleanup;
		    }
		    rparams->passwdservers = tempstr;
		} else {
		    rparams->passwdservers = (char **)malloc(sizeof(char *) * (list_entries+1));
		    if (rparams->passwdservers == NULL) {
			retval = ENOMEM;
			goto cleanup;
		    }
		    memset(rparams->passwdservers, 0, sizeof(char *) * (list_entries+1));
		}
		list_modify_str_array(&rparams->passwdservers, (const char**)list,
				      LIST_MODE_ADD);
		mask |= LDAP_REALM_PASSWDSERVERS;
	    }
	}
#endif
	else if ((ret_mask= get_ticket_policy(rparams,&i,argv,argc)) !=0) {
	    mask|=ret_mask;
	} else {
	    printf(gettext("'%s' is an invalid option\n"), argv[i]);
	    goto err_usage;
	}
    }

    if ((retval = krb5_ldap_modify_realm(util_context,
					 /* global_params.realm, */ rparams, mask))) {
	goto cleanup;
    }

#ifdef HAVE_EDIRECTORY
    if ((mask & LDAP_REALM_SUBTREE) || (mask & LDAP_REALM_KDCSERVERS) ||
	(mask & LDAP_REALM_ADMINSERVERS) || (mask & LDAP_REALM_PASSWDSERVERS)) {

	printf(gettext("Changing rights for the service object. Please wait ... "));
	fflush(stdout);

	if (!(mask & LDAP_REALM_SUBTREE)) {
	    if (rparams->subtree != NULL) {
		for(i=0; rparams->subtree[i]!=NULL;i++) {
		    oldsubtrees[i] = strdup(rparams->subtree[i]);
		    if( oldsubtrees[i] == NULL ) {
			retval = ENOMEM;
			goto cleanup;
		    }
		}
	    }
	}

	if ((mask & LDAP_REALM_SUBTREE)) {
	    int check_subtree = 1;

	    newsubtrees = (char**) calloc(rparams->subtreecount, sizeof(char*));

	    if (newsubtrees == NULL) {
		retval = ENOMEM;
		goto cleanup;
	    }

	    if ( (rparams != NULL) && (rparams->subtree != NULL) ) {
		for (j=0; j<rparams->subtreecount && rparams->subtree[j]!= NULL; j++) {
		    newsubtrees[j] = strdup(rparams->subtree[j]);
		    if (newsubtrees[j] == NULL) {
			retval = ENOMEM;
			goto cleanup;
		    }
		}
		newsubtrees[j] = NULL;
	    }
	    for(j=0;oldsubtrees[j]!=NULL;j++) {
		check_subtree = 1;
		for(i=0; ( (oldsubtrees[j] && !rparams->subtree[i]) ||
			(!oldsubtrees[j] && rparams->subtree[i])); i++) {
		    if(strcasecmp( oldsubtrees[j], rparams->subtree[i]) == 0) {
			check_subtree = 0;
			continue;
		    }
		}
		if (check_subtree != 0) {
		    subtree_changed=1;
		    break;
		}
	    }
	    /* this will return list of the disjoint members */
	    disjoint_members( oldsubtrees, newsubtrees);
	}

	if ((mask & LDAP_REALM_SUBTREE) || (mask & LDAP_REALM_KDCSERVERS)) {

	    newkdcdns = (char**) calloc(MAX_LIST_ENTRIES, sizeof(char*));
	    if (newkdcdns == NULL) {
		retval = ENOMEM;
		goto cleanup;
	    }

	    if ((rparams != NULL) && (rparams->kdcservers != NULL)) {
		for (j=0;  rparams->kdcservers[j]!= NULL; j++) {
		    newkdcdns[j] = strdup(rparams->kdcservers[j]);
		    if (newkdcdns[j] == NULL) {
			retval = ENOMEM;
			goto cleanup;
		    }
		}
		newkdcdns[j] = NULL;
	    }

	    if (!subtree_changed) {
		disjoint_members(oldkdcdns, newkdcdns);
	    } else { /* Only the subtrees was changed. Remove the rights on the old subtrees. */
		if (!(mask & LDAP_REALM_KDCSERVERS)) {

		    oldkdcdns = (char**) calloc(MAX_LIST_ENTRIES, sizeof(char*));
		    if (oldkdcdns == NULL) {
			retval = ENOMEM;
			goto cleanup;
		    }

		    if ((rparams != NULL) && (rparams->kdcservers != NULL)) {
			for (j=0;  rparams->kdcservers[j]!= NULL; j++) {
			    oldkdcdns[j] = strdup(rparams->kdcservers[j]);
			    if (oldkdcdns[j] == NULL) {
				retval = ENOMEM;
				goto cleanup;
			    }
			}
			oldkdcdns[j] = NULL;
		    }
		}
	    }

	    rightsmask =0;
	    rightsmask |= LDAP_REALM_RIGHTS;
	    rightsmask |= LDAP_SUBTREE_RIGHTS;
	    /* Remove the rights on the old subtrees */
	    if (oldkdcdns) {
		for (i=0; (oldkdcdns[i] != NULL); i++) {
		    if ((retval=krb5_ldap_delete_service_rights(util_context,
								LDAP_KDC_SERVICE, oldkdcdns[i],
								rparams->realm_name, oldsubtrees, rightsmask)) != 0) {
			printf(gettext("failed\n"));
			/* Solaris Kerberos */
			com_err(progname, retval, gettext("while assigning rights '%s'"),
				rparams->realm_name);
			goto err_nomsg;
		    }
		}
	    }

	    rightsmask =0;
	    rightsmask |= LDAP_REALM_RIGHTS;
	    rightsmask |= LDAP_SUBTREE_RIGHTS;
	    if (newkdcdns) {
		for (i=0; (newkdcdns[i] != NULL); i++) {

		    if ((retval=krb5_ldap_add_service_rights(util_context,
							     LDAP_KDC_SERVICE, newkdcdns[i], rparams->realm_name,
							     rparams->subtree, rightsmask)) != 0) {
			printf(gettext("failed\n"));
			/* Solaris Kerberos */
			com_err(progname, retval, gettext("while assigning rights to '%s'"),
				rparams->realm_name);
			goto err_nomsg;
		    }
		}
	    }
	}

	if ((mask & LDAP_REALM_SUBTREE) || (mask & LDAP_REALM_ADMINSERVERS)) {

	    newadmindns = (char**) calloc(MAX_LIST_ENTRIES, sizeof(char*));
	    if (newadmindns == NULL) {
		retval = ENOMEM;
		goto cleanup;
	    }

	    if ((rparams != NULL) && (rparams->adminservers != NULL)) {
		for (j=0;  rparams->adminservers[j]!= NULL; j++) {
		    newadmindns[j] = strdup(rparams->adminservers[j]);
		    if (newadmindns[j] == NULL) {
			retval = ENOMEM;
			goto cleanup;
		    }
		}
		newadmindns[j] = NULL;
	    }

	    if (!subtree_changed) {
		disjoint_members(oldadmindns, newadmindns);
	    } else { /* Only the subtrees was changed. Remove the rights on the old subtrees. */
		if (!(mask & LDAP_REALM_ADMINSERVERS)) {

		    oldadmindns = (char**) calloc(MAX_LIST_ENTRIES, sizeof(char*));
		    if (oldadmindns == NULL) {
			retval = ENOMEM;
			goto cleanup;
		    }

		    if ((rparams != NULL) && (rparams->adminservers != NULL)) {
			for (j=0;  rparams->adminservers[j]!= NULL; j++) {
			    oldadmindns[j] = strdup(rparams->adminservers[j]);
			    if (oldadmindns[j] == NULL) {
				retval = ENOMEM;
				goto cleanup;
			    }
			}
			oldadmindns[j] = NULL;
		    }
		}
	    }

	    rightsmask = 0;
	    rightsmask |= LDAP_REALM_RIGHTS;
	    rightsmask |= LDAP_SUBTREE_RIGHTS;
	    /* Remove the rights on the old subtrees */
	    if (oldadmindns) {
		for (i=0; (oldadmindns[i] != NULL); i++) {

		    if ((retval=krb5_ldap_delete_service_rights(util_context,
								LDAP_ADMIN_SERVICE, oldadmindns[i],
								rparams->realm_name, oldsubtrees, rightsmask)) != 0) {
			printf(gettext("failed\n"));
			/* Solaris Kerberos */
			com_err(progname, retval, gettext("while assigning rights '%s'"),
				rparams->realm_name);
			goto err_nomsg;
		    }
		}
	    }

	    rightsmask = 0;
	    rightsmask |= LDAP_REALM_RIGHTS;
	    rightsmask |= LDAP_SUBTREE_RIGHTS;
	    /* Add rights on the new subtree for all the kdc dns */
	    if (newadmindns) {
		for (i=0; (newadmindns[i] != NULL); i++) {

		    if ((retval=krb5_ldap_add_service_rights(util_context,
							     LDAP_ADMIN_SERVICE, newadmindns[i],
							     rparams->realm_name, rparams->subtree, rightsmask)) != 0) {
			printf(gettext("failed\n"));
			/* Solaris Kerberos */
			com_err(progname, retval, gettext("while assigning rights to '%s'"),
				rparams->realm_name);
			goto err_nomsg;
		    }
		}
	    }
	}


	if ((mask & LDAP_REALM_SUBTREE) || (mask & LDAP_REALM_PASSWDSERVERS)) {

	    newpwddns = (char**) calloc(MAX_LIST_ENTRIES, sizeof(char*));
	    if (newpwddns == NULL) {
		retval = ENOMEM;
		goto cleanup;
	    }

	    if ((rparams != NULL) && (rparams->passwdservers != NULL)) {
		for (j=0;  rparams->passwdservers[j]!= NULL; j++) {
		    newpwddns[j] = strdup(rparams->passwdservers[j]);
		    if (newpwddns[j] == NULL) {
			retval = ENOMEM;
			goto cleanup;
		    }
		}
		newpwddns[j] = NULL;
	    }

	    if (!subtree_changed) {
		disjoint_members(oldpwddns, newpwddns);
	    } else { /* Only the subtrees was changed. Remove the rights on the old subtrees. */
		if (!(mask & LDAP_REALM_ADMINSERVERS)) {

		    oldpwddns = (char**) calloc(MAX_LIST_ENTRIES, sizeof(char*));
		    if (oldpwddns == NULL) {
			retval = ENOMEM;
			goto cleanup;
		    }

		    if ((rparams != NULL) && (rparams->passwdservers != NULL)) {
			for (j=0;  rparams->passwdservers[j]!= NULL; j++) {
			    oldpwddns[j] = strdup(rparams->passwdservers[j]);
			    if (oldpwddns[j] == NULL) {
				retval = ENOMEM;
				goto cleanup;
			    }
			}
			oldpwddns[j] = NULL;
		    }
		}
	    }

	    rightsmask =0;
	    rightsmask |= LDAP_REALM_RIGHTS;
	    rightsmask |= LDAP_SUBTREE_RIGHTS;
	    /* Remove the rights on the old subtrees */
	    if (oldpwddns) {
		for (i=0; (oldpwddns[i] != NULL); i++) {
		    if ((retval = krb5_ldap_delete_service_rights(util_context,
								  LDAP_PASSWD_SERVICE, oldpwddns[i],
								  rparams->realm_name, oldsubtrees, rightsmask))) {
			printf(gettext("failed\n"));
			/* Solaris Kerberos */
			com_err(progname, retval, gettext("while assigning rights '%s'"),
				rparams->realm_name);
			goto err_nomsg;
		    }
		}
	    }

	    rightsmask =0;
	    rightsmask |= LDAP_REALM_RIGHTS;
	    rightsmask |= LDAP_SUBTREE_RIGHTS;
	    /* Add rights on the new subtree for all the kdc dns */
	    if (newpwddns) {
		for (i=0; (newpwddns[i] != NULL); i++) {
		    if ((retval = krb5_ldap_add_service_rights(util_context,
							       LDAP_PASSWD_SERVICE, newpwddns[i],
							       rparams->realm_name, rparams->subtree, rightsmask))) {
			printf(gettext("failed\n"));
			/* Solaris Kerberos */
			com_err(progname, retval, gettext("while assigning rights to '%s'"),
				rparams->realm_name);
			goto err_nomsg;
		    }
		}
	    }
	}

	printf(gettext("done\n"));
    }
#endif

    goto cleanup;

err_usage:
    print_usage = TRUE;

err_nomsg:
    no_msg = TRUE;

cleanup:
    krb5_ldap_free_realm_params(rparams);


#ifdef HAVE_EDIRECTORY
    if (oldkdcdns) {
	for (i=0; oldkdcdns[i] != NULL; i++)
	    free(oldkdcdns[i]);
	free(oldkdcdns);
    }
    if (oldpwddns) {
	for (i=0; oldpwddns[i] != NULL; i++)
	    free(oldpwddns[i]);
	free(oldpwddns);
    }
    if (oldadmindns) {
	for (i=0; oldadmindns[i] != NULL; i++)
	    free(oldadmindns[i]);
	free(oldadmindns);
    }
    if (newkdcdns) {
	for (i=0; newkdcdns[i] != NULL; i++)
	    free(newkdcdns[i]);
	free(newkdcdns);
    }
    if (newpwddns) {
	for (i=0; newpwddns[i] != NULL; i++)
	    free(newpwddns[i]);
	free(newpwddns);
    }
    if (newadmindns) {
	for (i=0; newadmindns[i] != NULL; i++)
	    free(newadmindns[i]);
	free(newadmindns);
    }
    if (oldsubtrees) {
	for (i=0;oldsubtrees[i]!=NULL; i++)
	    free(oldsubtrees[i]);
	free(oldsubtrees);
    }
    if (newsubtrees) {
	for (i=0;newsubtrees[i]!=NULL; i++)
	    free(newsubtrees[i]);
	free(oldsubtrees);
    }
#endif
    if (print_usage) {
	db_usage(MODIFY_REALM);
    }

    if (retval) {
	if (!no_msg) {
	    /* Solaris Kerberos */
	    com_err(progname, retval, gettext("while modifying information of realm '%s'"),
		    global_params.realm);
	}
	exit_status++;
    }

    return;
}



/*
 * This function displays the attributes of a Realm
 */
void kdb5_ldap_view(argc, argv)
    int argc;
    char *argv[];
{
    krb5_ldap_realm_params *rparams = NULL;
    krb5_error_code retval = 0;
    kdb5_dal_handle *dal_handle=NULL;
    krb5_ldap_context *ldap_context=NULL;
    int mask = 0;

    dal_handle = (kdb5_dal_handle *) util_context->db_context;
    ldap_context = (krb5_ldap_context *) dal_handle->db_context;
    if (!(ldap_context)) {
	retval = EINVAL;
	/* Solaris Kerberos */
	com_err(progname, retval, gettext("while initializing database"));
	exit_status++;
	return;
    }

    /* Read the kerberos container information */
    if ((retval = krb5_ldap_read_krbcontainer_params(util_context,
						     &(ldap_context->krbcontainer))) != 0) {
	/* Solaris Kerberos */
	com_err(progname, retval, gettext("while reading kerberos container information"));
	exit_status++;
	return;
    }

    if ((retval = krb5_ldap_read_realm_params(util_context,
					      global_params.realm, &rparams, &mask)) || (!rparams)) {
	/* Solaris Kerberos */
	com_err(progname, retval, gettext("while reading information of realm '%s'"),
		global_params.realm);
	exit_status++;
	return;
    }
    print_realm_params(rparams, mask);
    krb5_ldap_free_realm_params(rparams);

    return;
}

static char *strdur(duration)
    time_t duration;
{
    static char out[50];
    int neg, days, hours, minutes, seconds;

    if (duration < 0) {
	duration *= -1;
	neg = 1;
    } else
	neg = 0;
    days = duration / (24 * 3600);
    duration %= 24 * 3600;
    hours = duration / 3600;
    duration %= 3600;
    minutes = duration / 60;
    duration %= 60;
    seconds = duration;
    snprintf(out, sizeof(out), "%s%d %s %02d:%02d:%02d", neg ? "-" : "",
	    days, days == 1 ? gettext("day") : gettext("days"),
	    hours, minutes, seconds);
    return out;
}

/*
 * This function prints the attributes of a given realm to the
 * standard output.
 */
static void print_realm_params(krb5_ldap_realm_params *rparams, int mask)
{
    char **slist = NULL;
    int num_entry_printed = 0, i = 0;

    /* Print the Realm Attributes on the standard output */
    printf("%25s: %-50s\n", gettext("Realm Name"), global_params.realm);
    if (mask & LDAP_REALM_SUBTREE) {
	for (i=0; rparams->subtree[i]!=NULL; i++)
	    printf("%25s: %-50s\n", gettext("Subtree"), rparams->subtree[i]);
    }
    if (mask & LDAP_REALM_CONTREF)
	printf("%25s: %-50s\n", gettext("Principal Container Reference"), rparams->containerref);
    if (mask & LDAP_REALM_SEARCHSCOPE) {
	if ((rparams->search_scope != 1) &&
	    (rparams->search_scope != 2)) {
	    printf("%25s: %-50s\n", gettext("SearchScope"), gettext("Invalid !"));
	} else {
	    printf("%25s: %-50s\n", gettext("SearchScope"),
		   (rparams->search_scope == 1) ? gettext("ONE") : gettext("SUB"));
	}
    }
    if (mask & LDAP_REALM_KDCSERVERS) {
	printf("%25s:", gettext("KDC Services"));
	if (rparams->kdcservers != NULL) {
	    num_entry_printed = 0;
	    for (slist = rparams->kdcservers; *slist != NULL; slist++) {
		if (num_entry_printed)
		    printf(" %25s %-50s\n", " ", *slist);
		else
		    printf(" %-50s\n", *slist);
		num_entry_printed++;
	    }
	}
	if (num_entry_printed == 0)
	    printf("\n");
    }
    if (mask & LDAP_REALM_ADMINSERVERS) {
	printf("%25s:", gettext("Admin Services"));
	if (rparams->adminservers != NULL) {
	    num_entry_printed = 0;
	    for (slist = rparams->adminservers; *slist != NULL; slist++) {
		if (num_entry_printed)
		    printf(" %25s %-50s\n", " ", *slist);
		else
		    printf(" %-50s\n", *slist);
		num_entry_printed++;
	    }
	}
	if (num_entry_printed == 0)
	    printf("\n");
    }
    if (mask & LDAP_REALM_PASSWDSERVERS) {
	printf("%25s:", gettext("Passwd Services"));
	if (rparams->passwdservers != NULL) {
	    num_entry_printed = 0;
	    for (slist = rparams->passwdservers; *slist != NULL; slist++) {
		if (num_entry_printed)
		    printf(" %25s %-50s\n", " ", *slist);
		else
		    printf(" %-50s\n", *slist);
		num_entry_printed++;
	    }
	}
	if (num_entry_printed == 0)
	    printf("\n");
    }
    if (mask & LDAP_REALM_MAXTICKETLIFE) {
	printf("%25s:", gettext("Maximum Ticket Life"));
	printf(" %s \n", strdur(rparams->max_life));
    }

    if (mask & LDAP_REALM_MAXRENEWLIFE) {
	printf("%25s:", gettext("Maximum Renewable Life"));
	printf(" %s \n", strdur(rparams->max_renewable_life));
    }

    if (mask & LDAP_REALM_KRBTICKETFLAGS) {
	int ticketflags = rparams->tktflags;

	printf("%25s: ", gettext("Ticket flags"));
	if (ticketflags & KRB5_KDB_DISALLOW_POSTDATED)
	    printf("%s ","DISALLOW_POSTDATED");

	if (ticketflags & KRB5_KDB_DISALLOW_FORWARDABLE)
	    printf("%s ","DISALLOW_FORWARDABLE");

	if (ticketflags & KRB5_KDB_DISALLOW_RENEWABLE)
	    printf("%s ","DISALLOW_RENEWABLE");

	if (ticketflags & KRB5_KDB_DISALLOW_PROXIABLE)
	    printf("%s ","DISALLOW_PROXIABLE");

	if (ticketflags & KRB5_KDB_DISALLOW_DUP_SKEY)
	    printf("%s ","DISALLOW_DUP_SKEY");

	if (ticketflags & KRB5_KDB_REQUIRES_PRE_AUTH)
	    printf("%s ","REQUIRES_PRE_AUTH");

	if (ticketflags & KRB5_KDB_REQUIRES_HW_AUTH)
	    printf("%s ","REQUIRES_HW_AUTH");

	if (ticketflags & KRB5_KDB_DISALLOW_SVR)
	    printf("%s ","DISALLOW_SVR");

	if (ticketflags & KRB5_KDB_DISALLOW_TGT_BASED)
	    printf("%s ","DISALLOW_TGT_BASED");

	if (ticketflags & KRB5_KDB_DISALLOW_ALL_TIX)
	    printf("%s ","DISALLOW_ALL_TIX");

	if (ticketflags & KRB5_KDB_REQUIRES_PWCHANGE)
	    printf("%s ","REQUIRES_PWCHANGE");

	if (ticketflags & KRB5_KDB_PWCHANGE_SERVICE)
	    printf("%s ","PWCHANGE_SERVICE");

	printf("\n");
    }


    return;
}



/*
 * This function lists the Realm(s) present under the Kerberos container
 * on the LDAP Server.
 */
void kdb5_ldap_list(argc, argv)
    int argc;
    char *argv[];
{
    char **list = NULL;
    char **plist = NULL;
    krb5_error_code retval = 0;
    kdb5_dal_handle *dal_handle=NULL;
    krb5_ldap_context *ldap_context=NULL;

    dal_handle = (kdb5_dal_handle *)util_context->db_context;
    ldap_context = (krb5_ldap_context *) dal_handle->db_context;
    if (!(ldap_context)) {
	retval = EINVAL;
	exit_status++;
	return;
    }

    /* Read the kerberos container information */
    if ((retval = krb5_ldap_read_krbcontainer_params(util_context,
						     &(ldap_context->krbcontainer))) != 0) {
	/* Solaris Kerberos */
	com_err(progname, retval, gettext("while reading kerberos container information"));
	exit_status++;
	return;
    }

    retval = krb5_ldap_list_realm(util_context, &list);
    if (retval != 0) {
	krb5_ldap_free_krbcontainer_params(ldap_context->krbcontainer);
	ldap_context->krbcontainer = NULL;
	/* Solaris Kerberos */
	com_err (progname, retval, gettext("while listing realms"));
	exit_status++;
	return;
    }
    /* This is to handle the case of realm not present */
    if (list == NULL) {
	krb5_ldap_free_krbcontainer_params(ldap_context->krbcontainer);
	ldap_context->krbcontainer = NULL;
	return;
    }

    for (plist = list; *plist != NULL; plist++) {
	printf("%s\n", *plist);
    }
    krb5_ldap_free_krbcontainer_params(ldap_context->krbcontainer);
    ldap_context->krbcontainer = NULL;
    krb5_free_list_entries(list);
    free(list);

    return;
}

/*
 * Duplicating the following two functions here because
 * 'krb5_dbe_update_tl_data' uses backend specific memory allocation. The catch
 * here is that the backend is not initialized - kdb5_ldap_util doesn't go
 * through DAL.
 * 1. krb5_dbe_update_tl_data
 * 2. krb5_dbe_update_mod_princ_data
 */

/* Start duplicate code ... */

static krb5_error_code
krb5_dbe_update_tl_data_new(context, entry, new_tl_data)
    krb5_context context;
    krb5_db_entry *entry;
    krb5_tl_data *new_tl_data;
{
    krb5_tl_data *tl_data = NULL;
    krb5_octet *tmp;

    /* copy the new data first, so we can fail cleanly if malloc()
     * fails */
/*
    if ((tmp =
	 (krb5_octet *) krb5_db_alloc(context, NULL,
				      new_tl_data->tl_data_length)) == NULL)
*/
    if ((tmp = (krb5_octet *) malloc (new_tl_data->tl_data_length)) == NULL)
	return (ENOMEM);

    /* Find an existing entry of the specified type and point at
     * it, or NULL if not found */

    if (new_tl_data->tl_data_type != KRB5_TL_DB_ARGS) {	/* db_args can be multiple */
	for (tl_data = entry->tl_data; tl_data;
	     tl_data = tl_data->tl_data_next)
	    if (tl_data->tl_data_type == new_tl_data->tl_data_type)
		break;
    }

    /* if necessary, chain a new record in the beginning and point at it */

    if (!tl_data) {
/*
	if ((tl_data =
	     (krb5_tl_data *) krb5_db_alloc(context, NULL,
					    sizeof(krb5_tl_data)))
	    == NULL) {
*/
	if ((tl_data = (krb5_tl_data *) malloc (sizeof(krb5_tl_data))) == NULL) {
	    free(tmp);
	    return (ENOMEM);
	}
	memset(tl_data, 0, sizeof(krb5_tl_data));
	tl_data->tl_data_next = entry->tl_data;
	entry->tl_data = tl_data;
	entry->n_tl_data++;
    }

    /* fill in the record */

    if (tl_data->tl_data_contents)
	krb5_db_free(context, tl_data->tl_data_contents);

    tl_data->tl_data_type = new_tl_data->tl_data_type;
    tl_data->tl_data_length = new_tl_data->tl_data_length;
    tl_data->tl_data_contents = tmp;
    memcpy(tmp, new_tl_data->tl_data_contents, tl_data->tl_data_length);

    return (0);
}

static krb5_error_code
krb5_dbe_update_mod_princ_data_new(context, entry, mod_date, mod_princ)
    krb5_context	  context;
    krb5_db_entry	* entry;
    krb5_timestamp	  mod_date;
    krb5_const_principal  mod_princ;
{
    krb5_tl_data          tl_data;

    krb5_error_code 	  retval = 0;
    krb5_octet		* nextloc = 0;
    char		* unparse_mod_princ = 0;
    unsigned int	unparse_mod_princ_size;

    if ((retval = krb5_unparse_name(context, mod_princ,
				    &unparse_mod_princ)))
	return(retval);

    unparse_mod_princ_size = strlen(unparse_mod_princ) + 1;

    if ((nextloc = (krb5_octet *) malloc(unparse_mod_princ_size + 4))
	== NULL) {
	free(unparse_mod_princ);
	return(ENOMEM);
    }

    tl_data.tl_data_type = KRB5_TL_MOD_PRINC;
    tl_data.tl_data_length = unparse_mod_princ_size + 4;
    tl_data.tl_data_contents = nextloc;

    /* Mod Date */
    krb5_kdb_encode_int32(mod_date, nextloc);

    /* Mod Princ */
    memcpy(nextloc+4, unparse_mod_princ, unparse_mod_princ_size);

    retval = krb5_dbe_update_tl_data_new(context, entry, &tl_data);

    free(unparse_mod_princ);
    free(nextloc);

    return(retval);
}

static krb5_error_code
kdb_ldap_tgt_keysalt_iterate(ksent, ptr)
    krb5_key_salt_tuple *ksent;
    krb5_pointer        ptr;
{
    krb5_context        context;
    krb5_error_code     kret;
    struct iterate_args *iargs;
    krb5_keyblock       key;
    krb5_int32          ind;
    krb5_data   pwd;
    krb5_db_entry       *entry;

    iargs = (struct iterate_args *) ptr;
    kret = 0;

    context = iargs->ctx;
    entry = iargs->dbentp;

    /*
     * Convert the master key password into a key for this particular
     * encryption system.
     */
    pwd.data = mkey_password;
    pwd.length = strlen(mkey_password);
    kret = krb5_c_random_seed(context, &pwd);
    if (kret)
	return kret;

    /*if (!(kret = krb5_dbe_create_key_data(iargs->ctx, iargs->dbentp))) {*/
    if ((entry->key_data =
	     (krb5_key_data *) realloc(entry->key_data,
					    (sizeof(krb5_key_data) *
					    (entry->n_key_data + 1)))) == NULL)
	return (ENOMEM);

    memset(entry->key_data + entry->n_key_data, 0, sizeof(krb5_key_data));
    ind = entry->n_key_data++;

    if (!(kret = krb5_c_make_random_key(context, ksent->ks_enctype,
					&key))) {
	kret = krb5_dbekd_encrypt_key_data(context,
					   iargs->rblock->key,
					   &key,
					   NULL,
					   1,
					   &entry->key_data[ind]);
	krb5_free_keyblock_contents(context, &key);
    }
    /*}*/

    return(kret);
}
/* End duplicate code */

/*
 * This function creates service principals when
 * creating the realm object.
 */
static int
kdb_ldap_create_principal (context, princ, op, pblock)
    krb5_context context;
    krb5_principal princ;
    enum ap_op op;
    struct realm_info *pblock;
{
    int              retval=0, currlen=0, princtype = 2 /* Service Principal */;
    unsigned char    *curr=NULL;
    krb5_tl_data     *tl_data=NULL;
    krb5_db_entry    entry;
    int              nentry=1;
    long             mask = 0;
    krb5_keyblock    key;
    int              kvno = 0;
    kdb5_dal_handle *dal_handle = NULL;
    krb5_ldap_context *ldap_context=NULL;
    struct iterate_args   iargs;
    krb5_data       *pdata;

    if ((pblock == NULL) || (context == NULL)) {
	retval = EINVAL;
	goto cleanup;
    }
    dal_handle = (kdb5_dal_handle *) context->db_context;
    ldap_context = (krb5_ldap_context *) dal_handle->db_context;
    if (!(ldap_context)) {
	retval = EINVAL;
	goto cleanup;
    }

    memset(&entry, 0, sizeof(entry));

    tl_data = malloc(sizeof(*tl_data));
    if (tl_data == NULL) {
	retval = ENOMEM;
	goto cleanup;
    }
    memset(tl_data, 0, sizeof(*tl_data));
    tl_data->tl_data_length = 1 + 2 + 2 + 1 + 2 + 4;
    tl_data->tl_data_type = 7; /* KDB_TL_USER_INFO */
    curr = tl_data->tl_data_contents = malloc(tl_data->tl_data_length);
    if (tl_data->tl_data_contents == NULL) {
	retval = ENOMEM;
	goto cleanup;
    }

    memset(curr, 1, 1); /* Passing the mask as principal type */
    curr += 1;
    currlen = 2;
    STORE16_INT(curr, currlen);
    curr += currlen;
    STORE16_INT(curr, princtype);
    curr += currlen;

    mask |= KADM5_PRINCIPAL;
    mask |= KADM5_ATTRIBUTES ;
    mask |= KADM5_MAX_LIFE ;
    mask |= KADM5_MAX_RLIFE ;
    mask |= KADM5_PRINC_EXPIRE_TIME ;
    mask |= KADM5_KEY_DATA;

    entry.tl_data = tl_data;
    entry.n_tl_data += 1;
    /* Set the creator's name */
    {
	krb5_timestamp now;
	if ((retval = krb5_timeofday(context, &now)))
	    goto cleanup;
	if ((retval = krb5_dbe_update_mod_princ_data_new(context, &entry,
			now, &db_create_princ)))
	    goto cleanup;
    }
    entry.attributes = pblock->flags;
    entry.max_life = pblock->max_life;
    entry.max_renewable_life = pblock->max_rlife;
    entry.expiration = pblock->expiration;
    entry.mask = mask;
    if ((retval = krb5_copy_principal(context, princ, &entry.princ)))
	goto cleanup;


    switch (op) {
    case TGT_KEY:
	if ((pdata = krb5_princ_component(context, princ, 1)) &&
	    pdata->length == strlen("history") &&
	    !memcmp(pdata->data, "history", strlen("history"))) {

	    /* Allocate memory for storing the key */
	    if ((entry.key_data = (krb5_key_data *) malloc(
					      sizeof(krb5_key_data))) == NULL) {
		retval = ENOMEM;
		goto cleanup;
	    }

	    memset(entry.key_data, 0, sizeof(krb5_key_data));
	    entry.n_key_data++;

	    retval = krb5_c_make_random_key(context, global_params.enctype, &key);
	    if (retval) {
		goto cleanup;
	    }
	    kvno = 1; /* New key is getting set */
	    retval = krb5_dbekd_encrypt_key_data(context,
					&ldap_context->lrparams->mkey,
					&key, NULL, kvno,
					&entry.key_data[entry.n_key_data - 1]);
	    krb5_free_keyblock_contents(context, &key);
	    if (retval) {
		goto cleanup;
	    }
	} else {
	    /*retval = krb5_c_make_random_key(context, 16, &key) ;*/
	    iargs.ctx = context;
	    iargs.rblock = pblock;
	    iargs.dbentp = &entry;

	    /*
	     * create a set of random keys by iterating through the key/salt
	     * list, ignoring salt types.
	     */
	    if ((retval = krb5_keysalt_iterate(pblock->kslist,
					       pblock->nkslist,
					       1,
					       kdb_ldap_tgt_keysalt_iterate,
					       (krb5_pointer) &iargs)))
		return retval;
	}
	break;

    case MASTER_KEY:
	/* Allocate memory for storing the key */
	if ((entry.key_data = (krb5_key_data *) malloc(
					      sizeof(krb5_key_data))) == NULL) {
	    retval = ENOMEM;
	    goto cleanup;
	}

	memset(entry.key_data, 0, sizeof(krb5_key_data));
	entry.n_key_data++;
	kvno = 1; /* New key is getting set */
	retval = krb5_dbekd_encrypt_key_data(context, pblock->key,
					 &ldap_context->lrparams->mkey,
					 NULL, kvno,
					 &entry.key_data[entry.n_key_data - 1]);
	if (retval) {
	    goto cleanup;
	}
	break;

    case NULL_KEY:
    default:
	break;
    } /* end of switch */

    retval = krb5_ldap_put_principal(context, &entry, &nentry, NULL);
    if (retval) {
	com_err(NULL, retval, gettext("while adding entries to database"));
	goto cleanup;
    }

cleanup:
    krb5_dbe_free_contents(context, &entry);
    return retval;
}


/*
 * This function destroys the realm object and the associated principals
 */
void
kdb5_ldap_destroy(argc, argv)
    int argc;
    char *argv[];
{
    extern char *optarg;
    extern int optind;
    int optchar = 0;
    char buf[5] = {0};
    krb5_error_code retval = 0;
    int force = 0;
    int mask = 0;
    kdb5_dal_handle *dal_handle = NULL;
    krb5_ldap_context *ldap_context = NULL;
#ifdef HAVE_EDIRECTORY
    int i = 0, rightsmask = 0;
    krb5_ldap_realm_params *rparams = NULL;
#endif
    /* Solaris Kerberos: to remove stash file */
    char *stash_file = NULL;
    struct stat stb;

    optind = 1;
    while ((optchar = getopt(argc, argv, "f")) != -1) {
	switch (optchar) {
	case 'f':
	    force++;
	    break;
	case '?':
	default:
	    db_usage(DESTROY_REALM);
	    return;
	    /*NOTREACHED*/
	}
    }

    if (!force) {
	printf(gettext("Deleting KDC database of '%s', are you sure?\n"), global_params.realm);
	printf(gettext("(type 'yes' to confirm)? "));
	if (fgets(buf, sizeof(buf), stdin) == NULL) {
	    exit_status++;
	    return;
	}
	if (strcmp(buf, yes)) {
	    exit_status++;
	    return;
	}
	printf(gettext("OK, deleting database of '%s'...\n"), global_params.realm);
    }

    dal_handle = (kdb5_dal_handle *)util_context->db_context;
    ldap_context = (krb5_ldap_context *) dal_handle->db_context;
    if (!(ldap_context)) {
	/* Solaris Kerberos */
	com_err(progname, EINVAL, gettext("while initializing database"));
	exit_status++;
	return;
    }

    /* Read the kerberos container from the LDAP Server */
    if ((retval = krb5_ldap_read_krbcontainer_params(util_context,
						     &(ldap_context->krbcontainer))) != 0) {
	/* Solaris Kerberos */
	com_err(progname, retval, gettext("while reading kerberos container information"));
	exit_status++;
	return;
    }

    /* Read the Realm information from the LDAP Server */
    if ((retval = krb5_ldap_read_realm_params(util_context, global_params.realm,
					      &(ldap_context->lrparams), &mask)) != 0) {
	/* Solaris Kerberos */
	com_err(progname, retval, gettext("while reading realm information"));
	exit_status++;
	return;
    }

#ifdef HAVE_EDIRECTORY
    if ((mask & LDAP_REALM_KDCSERVERS) || (mask & LDAP_REALM_ADMINSERVERS) ||
	(mask & LDAP_REALM_PASSWDSERVERS)) {

	printf(gettext("Changing rights for the service object. Please wait ... "));
	fflush(stdout);

	rparams = ldap_context->lrparams;
	rightsmask = 0;
	rightsmask |= LDAP_REALM_RIGHTS;
	rightsmask |= LDAP_SUBTREE_RIGHTS;
	if ((rparams != NULL) && (rparams->kdcservers != NULL)) {
	    for (i=0; (rparams->kdcservers[i] != NULL); i++) {
		if ((retval = krb5_ldap_delete_service_rights(util_context,
							      LDAP_KDC_SERVICE, rparams->kdcservers[i],
							      rparams->realm_name, rparams->subtree, rightsmask)) != 0) {
		    printf(gettext("failed\n"));
		    /* Solaris Kerberos */
		    com_err(progname, retval, gettext("while assigning rights to '%s'"),
			    rparams->realm_name);
		    return;
		}
	    }
	}
	rightsmask = 0;
	rightsmask |= LDAP_REALM_RIGHTS;
	rightsmask |= LDAP_SUBTREE_RIGHTS;
	if ((rparams != NULL) && (rparams->adminservers != NULL)) {
	    for (i=0; (rparams->adminservers[i] != NULL); i++) {
		if ((retval = krb5_ldap_delete_service_rights(util_context,
							      LDAP_ADMIN_SERVICE, rparams->adminservers[i],
							      rparams->realm_name, rparams->subtree, rightsmask)) != 0) {
		    printf(gettext("failed\n"));
		    /* Solaris Kerberos */
		    com_err(progname, retval, gettext("while assigning rights to '%s'"),
			    rparams->realm_name);
		    return;
		}
	    }
	}
	rightsmask = 0;
	rightsmask |= LDAP_REALM_RIGHTS;
	rightsmask |= LDAP_SUBTREE_RIGHTS;
	if ((rparams != NULL) && (rparams->passwdservers != NULL)) {
	    for (i=0; (rparams->passwdservers[i] != NULL); i++) {
		if ((retval = krb5_ldap_delete_service_rights(util_context,
							      LDAP_PASSWD_SERVICE, rparams->passwdservers[i],
							      rparams->realm_name, rparams->subtree, rightsmask)) != 0) {
		    printf(gettext("failed\n"));
		    /* Solaris Kerberos */
		    com_err(progname, retval, gettext("while assigning rights to '%s'"),
			    rparams->realm_name);
		    return;
		}
	    }
	}
	printf(gettext("done\n"));
    }
#endif
    /* Delete the realm container and all the associated principals */
    retval = krb5_ldap_delete_realm(util_context, global_params.realm);
    if (retval) {
	/* Solaris Kerberos */
	com_err(progname, retval, gettext("deleting database of '%s'"), global_params.realm);
	exit_status++;
	return;
    }

    /*
     * Solaris Kerberos: check for a stash file and delete it if necessary
     * This behavior exists in the Solaris version of kdb5_util destroy.
     */
    if (global_params.stash_file == NULL) {
	char stashbuf[MAXPATHLEN+1];
	int realm_len = strlen(global_params.realm);

	(void) strlcpy(stashbuf, DEFAULT_KEYFILE_STUB, sizeof (stashbuf)); 

	if (realm_len <= (MAXPATHLEN-strlen(stashbuf))) {
	    (void) strncat(stashbuf, global_params.realm,
		(MAXPATHLEN-strlen(stashbuf)));
	} else {
	    /* Solaris Kerberos */
	    com_err(progname, EINVAL,
		gettext("can not determine stash file name for '%s'"),
		global_params.realm);
	    exit_status++;
	    return;
	}
	stash_file = stashbuf;
    } else {
	stash_file = global_params.stash_file;
    }
    /* Make sure stash_file is a regular file before unlinking */
    if (stat(stash_file, &stb) == 0) {
	if ((stb.st_mode & S_IFMT) == S_IFREG) {
	    (void)unlink(stash_file);
	} else {
	    /* Solaris Kerberos */
	    com_err(progname, EINVAL,
		gettext("stash file '%s' not a regular file, can not delete"),
		stash_file);
	    exit_status++;
	    return;
	}
    } else if (errno != ENOENT) {
	/*
	 * If the error is something other than the file doesn't exist set an
	 * error.
	 */
	/* Solaris Kerberos */
	com_err(progname, EINVAL,
	    gettext("could not stat stash file '%s', could not delete"),
	    stash_file);
	exit_status++;
	return;
    }

    printf(gettext("** Database of '%s' destroyed.\n"), global_params.realm);

    return;
}
