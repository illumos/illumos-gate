/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING
 *
 *	Openvision retains the copyright to derivative works of
 *	this source code.  Do *NOT* create a derivative of this
 *	source code before consulting with your legal department.
 *	Do *NOT* integrate *ANY* of this source code into another
 *	product before consulting with your legal department.
 *
 *	For further information, read the top-level Openvision
 *	copyright which is contained in the top-level MIT Kerberos
 *	copyright.
 *
 * WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING
 *
 */


/*
 * admin/create/kdb5_create.c
 *
 * Copyright 1990,1991 by the Massachusetts Institute of Technology.
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
 * Generate (from scratch) a Kerberos KDC database.
 */

/*
 *  Yes, I know this is a hack, but we need admin.h without including the
 *  rpc.h header. Additionally, our rpc.h header brings in
 *  a des.h header which causes other problems.
 */
#define	_RPC_RPC_H

#include <stdio.h>
#include <k5-int.h>
#include <krb5/kdb.h>
#include <kadm5/server_internal.h>
#include <kadm5/admin.h>
#include <rpc/types.h>
#include <rpc/xdr.h>
#include <libintl.h>
#include "kdb5_util.h"

enum ap_op {
    NULL_KEY,				/* setup null keys */
    MASTER_KEY,				/* use master key as new key */
    TGT_KEY				/* special handling for tgt key */
};

krb5_key_salt_tuple def_kslist = { ENCTYPE_DES_CBC_CRC, KRB5_KDB_SALTTYPE_NORMAL };

struct realm_info {
    krb5_deltat max_life;
    krb5_deltat max_rlife;
    krb5_timestamp expiration;
    krb5_flags flags;
    krb5_keyblock *key;
    krb5_int32 nkslist;
    krb5_key_salt_tuple *kslist;
} rblock = { /* XXX */
    KRB5_KDB_MAX_LIFE,
    KRB5_KDB_MAX_RLIFE,
    KRB5_KDB_EXPIRATION,
    KRB5_KDB_DEF_FLAGS,
    (krb5_keyblock *) NULL,
    1,
    &def_kslist
};

struct iterate_args {
    krb5_context	ctx;
    struct realm_info	*rblock;
    krb5_db_entry	*dbentp;
};

static krb5_error_code add_principal
	(krb5_context,
	 krb5_principal,
	 enum ap_op,
	 struct realm_info *,
		krb5_keyblock *);

/*
 * Steps in creating a database:
 *
 * 1) use the db calls to open/create a new database
 *
 * 2) get a realm name for the new db
 *
 * 3) get a master password for the new db; convert to an encryption key.
 *
 * 4) create various required entries in the database
 *
 * 5) close & exit
 */

extern krb5_principal master_princ;

krb5_data tgt_princ_entries[] = {
	{0, KRB5_TGS_NAME_SIZE, KRB5_TGS_NAME},
	{0, 0, 0} };

krb5_data db_creator_entries[] = {
	{0, sizeof("db_creation")-1, "db_creation"} };

/* XXX knows about contents of krb5_principal, and that tgt names
 are of form TGT/REALM@REALM */
krb5_principal_data tgt_princ = {
        0,					/* magic number */
	{0, 0, 0},				/* krb5_data realm */
	tgt_princ_entries,			/* krb5_data *data */
	2,					/* int length */
	KRB5_NT_SRV_INST			/* int type */
};

krb5_principal_data db_create_princ = {
        0,					/* magic number */
	{0, 0, 0},				/* krb5_data realm */
	db_creator_entries,			/* krb5_data *data */
	1,					/* int length */
	KRB5_NT_SRV_INST			/* int type */
};

extern char *mkey_password;

extern char *progname;
extern int exit_status;
extern kadm5_config_params global_params;
extern krb5_context util_context;

void kdb5_create(argc, argv)
   int argc;
   char *argv[];
{
    int optchar;

    krb5_error_code retval;
    char *mkey_fullname;
    char *pw_str = 0;
    unsigned int pw_size = 0;
    int do_stash = 0;
    krb5_data pwd, seed;
    kdb_log_context *log_ctx;
    krb5_keyblock mkey;
    krb5_data master_salt = { 0 };

    /* Solaris Kerberos */
    (void) memset(&mkey, 0, sizeof (mkey));

/* Solaris Kerberos */
#if 0
    if (strrchr(argv[0], '/'))
	argv[0] = strrchr(argv[0], '/')+1;
#endif
    while ((optchar = getopt(argc, argv, "s")) != -1) {
	switch(optchar) {
	case 's':
	    do_stash++;
	    break;
	case 'h':
	    if (!add_db_arg("hash=true")) {
		com_err(progname, ENOMEM, "while parsing command arguments\n");
		exit(1);
	    }
	    break;
	case '?':
	default:
	    usage();
	    return;
	}
    }

    rblock.max_life = global_params.max_life;
    rblock.max_rlife = global_params.max_rlife;
    rblock.expiration = global_params.expiration;
    rblock.flags = global_params.flags;
    rblock.nkslist = global_params.num_keysalts;
    rblock.kslist = global_params.keysalts;

    log_ctx = util_context->kdblog_context;

/* SUNW14resync XXX */
#if 0
    printf ("Loading random data\n");
    retval = krb5_c_random_os_entropy (util_context, 1, NULL);
    if (retval) {
      /* Solaris Kerberos */
      com_err (progname, retval, "Loading random data");
      exit_status++; return;
    }
#endif
    /* assemble & parse the master key name */

    if ((retval = krb5_db_setup_mkey_name(util_context,
					  global_params.mkey_name,
					  global_params.realm,
					  &mkey_fullname, &master_princ))) {
	/* Solaris Kerberos */
	com_err(progname, retval,
			gettext("while setting up master key name"));
	exit_status++; return;
    }

    krb5_princ_set_realm_data(util_context, &db_create_princ, global_params.realm);
    krb5_princ_set_realm_length(util_context, &db_create_princ, strlen(global_params.realm));
    krb5_princ_set_realm_data(util_context, &tgt_princ, global_params.realm);
    krb5_princ_set_realm_length(util_context, &tgt_princ, strlen(global_params.realm));
    krb5_princ_component(util_context, &tgt_princ,1)->data = global_params.realm;
    krb5_princ_component(util_context, &tgt_princ,1)->length = strlen(global_params.realm);

	printf(gettext("Initializing database '%s' for realm '%s',\n"
			"master key name '%s'\n"),
	   global_params.dbname, global_params.realm, mkey_fullname);

    if (!mkey_password) {
	printf(gettext("You will be prompted for the "
			"database Master Password.\n"));
	printf(gettext("It is important that you NOT FORGET this password.\n"));
	fflush(stdout);

	pw_size = 1024;
	pw_str = malloc(pw_size);

	retval = krb5_read_password(util_context,
			    gettext("Enter KDC database master key"),
			    gettext("Re-enter KDC database "
				    "master key to verify"),
			    pw_str, &pw_size);
	if (retval) {
	    /* Solaris Kerberos */
	    com_err(progname, retval,
		    gettext("while reading master key from keyboard"));
	    exit_status++; return;
	}
	mkey_password = pw_str;
    }

    pwd.data = mkey_password;
    pwd.length = strlen(mkey_password);
    retval = krb5_principal2salt(util_context, master_princ, &master_salt);
    if (retval) {
	/* Solaris Kerberos */
	com_err(progname, retval,
		gettext("while calculated master key salt"));
	exit_status++;
	goto cleanup;
    }

    retval = krb5_c_string_to_key(util_context, global_params.enctype,
				  &pwd, &master_salt, &mkey);
    if (retval) {
	/* Solaris Kerberos */
	com_err(progname, retval,
	    gettext("while transforming master key from password"));
	exit_status++;
	goto cleanup;
    }

    retval = krb5_copy_keyblock(util_context, &mkey, &rblock.key);
    if (retval) {
	/* Solaris Kerberos */
	com_err(progname, retval, gettext("while copying master key"));
	exit_status++;
	goto cleanup;
    }

    seed.length = mkey.length;
    seed.data = (char *)mkey.contents;

    if ((retval = krb5_c_random_seed(util_context, &seed))) {
	/* Solaris Kerberos */
	com_err(progname, retval,
		gettext("while initializing random key generator"));
	exit_status++;
	goto cleanup;
    }
    if ((retval = krb5_db_create(util_context, db5util_db_args))) {
	/* Solaris Kerberos */
	com_err(progname, retval,
		gettext("while creating database '%s'"),
		global_params.dbname);
	exit_status++;
	goto cleanup;
    }
#if 0 /************** Begin IFDEF'ed OUT *******************************/
    if (retval = krb5_db_fini(util_context)) {
	/* Solaris Kerberos */
	com_err(progname, retval,
		gettext("while closing current database"));
	exit_status++;
	goto cleanup;
    }
    if ((retval = krb5_db_set_name(util_context, global_params.dbname))) {
	/* Solaris Kerberos */
	com_err(progname, retval,
		gettext("while setting active database to '%s'"),
               global_params.dbname);
	exit_status++;
	goto cleanup;
    }
    if ((retval = krb5_db_init(util_context))) {
	com_err(progname, retval,
		gettext("while initializing the database '%s'"),
	global_params.dbname);
	exit_status++;
	goto cleanup;
    }
#endif /**************** END IFDEF'ed OUT *******************************/

    /* Solaris Kerberos: for iprop */
    if (log_ctx && log_ctx->iproprole) {
	if (retval = ulog_map(util_context, &global_params, FKCOMMAND)) {
		/* Solaris Kerberos */
		com_err(progname, retval,
			gettext("while creating update log"));
		exit_status++;
		goto cleanup;
	}

	/*
	 * We're reinitializing the update log in case one already
	 * existed, but this should never happen.
	 */
	(void) memset(log_ctx->ulog, 0, sizeof (kdb_hlog_t));

	log_ctx->ulog->kdb_hmagic = KDB_HMAGIC;
	log_ctx->ulog->db_version_num = KDB_VERSION;
	log_ctx->ulog->kdb_state = KDB_STABLE;
	log_ctx->ulog->kdb_block = ULOG_BLOCK;

	/*
	 * Since we're creating a new db we shouldn't worry about
	 * adding the initial principals since any slave might as well
	 * do full resyncs from this newly created db.
	 */
	log_ctx->iproprole = IPROP_NULL;
    }

    if ((retval = add_principal(util_context, master_princ, MASTER_KEY, &rblock, &mkey)) ||
	(retval = add_principal(util_context, &tgt_princ, TGT_KEY, &rblock, &mkey))) {
	(void) krb5_db_fini(util_context);
	/* Solaris Kerberos */
	com_err(progname, retval, gettext("while adding entries to the database"));
	exit_status++;
	goto cleanup;
    }
    /*
     * Always stash the master key so kadm5_create does not prompt for
     * it; delete the file below if it was not requested.  DO NOT EXIT
     * BEFORE DELETING THE KEYFILE if do_stash is not set.
     */
    retval = krb5_db_store_master_key(util_context,
				      global_params.stash_file,
				      master_princ,
				      &mkey,
				      mkey_password);

    if (retval) {
	/* Solaris Kerberos */
	com_err(progname, errno, gettext("while storing key"));
	printf(gettext("Warning: couldn't stash master key.\n"));
    }

    if (pw_str)
	memset(pw_str, 0, pw_size);

    if (kadm5_create(&global_params)) {
	 if (!do_stash) unlink(global_params.stash_file);
	 exit_status++;
	 goto cleanup;
    }
    if (!do_stash) unlink(global_params.stash_file);

/* Solaris Kerberos: deal with master_keyblock in better way */
cleanup:
    if (pw_str) {
	if (mkey_password == pw_str)
		mkey_password = NULL;
	free(pw_str);
    }
    if (master_salt.data)
	free(master_salt.data);
    krb5_free_keyblock(util_context, rblock.key);
    krb5_free_keyblock_contents(util_context, &mkey);
    (void) krb5_db_fini(util_context);

    return;
}

static krb5_error_code
tgt_keysalt_iterate(ksent, ptr)
    krb5_key_salt_tuple	*ksent;
    krb5_pointer	ptr;
{
    krb5_context	context;
    krb5_error_code	kret;
    struct iterate_args	*iargs;
    krb5_keyblock	key;
    krb5_int32		ind;
    krb5_data	pwd;

    iargs = (struct iterate_args *) ptr;
    kret = 0;

    context = iargs->ctx;

    /*
     * Convert the master key password into a key for this particular
     * encryption system.
     */
    pwd.data = mkey_password;
    pwd.length = strlen(mkey_password);
    kret = krb5_c_random_seed(context, &pwd);
    if (kret)
	return kret;

    if (!(kret = krb5_dbe_create_key_data(iargs->ctx, iargs->dbentp))) {
	ind = iargs->dbentp->n_key_data-1;
	if (!(kret = krb5_c_make_random_key(context, ksent->ks_enctype,
					    &key))) {
	    kret = krb5_dbekd_encrypt_key_data(context,
					       iargs->rblock->key,
					       &key,
					       NULL,
					       1,
					       &iargs->dbentp->key_data[ind]);
	    krb5_free_keyblock_contents(context, &key);
	}
    }

    return(kret);
}

static krb5_error_code
add_principal(context, princ, op, pblock, mkey)
    krb5_context context;
    krb5_principal princ;
    enum ap_op op;
    struct realm_info *pblock;
    krb5_keyblock *mkey;
{
    krb5_error_code 	  retval;
    krb5_db_entry 	  entry;

    krb5_timestamp	  now;
    struct iterate_args	  iargs;

    int			  nentries = 1;

    memset((char *) &entry, 0, sizeof(entry));

    entry.len = KRB5_KDB_V1_BASE_LENGTH;
    entry.attributes = pblock->flags;
    entry.max_life = pblock->max_life;
    entry.max_renewable_life = pblock->max_rlife;
    entry.expiration = pblock->expiration;

    if ((retval = krb5_copy_principal(context, princ, &entry.princ)))
	goto error_out;

    if ((retval = krb5_timeofday(context, &now)))
	goto error_out;

    if ((retval = krb5_dbe_update_mod_princ_data(context, &entry,
						 now, &db_create_princ)))
	goto error_out;

    switch (op) {
    case MASTER_KEY:
	if ((entry.key_data=(krb5_key_data*)malloc(sizeof(krb5_key_data)))
	    == NULL)
	    goto error_out;
	memset((char *) entry.key_data, 0, sizeof(krb5_key_data));
	entry.n_key_data = 1;

	entry.attributes |= KRB5_KDB_DISALLOW_ALL_TIX;
	if ((retval = krb5_dbekd_encrypt_key_data(context, pblock->key,
						  mkey, NULL,
						  1, entry.key_data)))
	    goto error_out;
	break;
    case TGT_KEY:
	iargs.ctx = context;
	iargs.rblock = pblock;
	iargs.dbentp = &entry;
	/*
	 * Iterate through the key/salt list, ignoring salt types.
	 */
	if ((retval = krb5_keysalt_iterate(pblock->kslist,
					   pblock->nkslist,
					   1,
					   tgt_keysalt_iterate,
					   (krb5_pointer) &iargs)))
	    return retval;
	break;
    case NULL_KEY:
	return EOPNOTSUPP;
    default:
	break;
    }

    entry.mask = (KADM5_KEY_DATA | KADM5_PRINCIPAL | KADM5_ATTRIBUTES |
	KADM5_MAX_LIFE | KADM5_MAX_RLIFE | KADM5_TL_DATA |
	KADM5_PRINC_EXPIRE_TIME);

    retval = krb5_db_put_principal(context, &entry, &nentries);

error_out:;
    krb5_db_free_principal(context, &entry, 1);
    return retval;
}
