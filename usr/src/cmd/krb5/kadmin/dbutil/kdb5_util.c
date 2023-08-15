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
 * admin/edit/kdb5_edit.c
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

/*
 *  Yes, I know this is a hack, but we need admin.h without including the
 *  rpc.h header. Additionally, our rpc.h header brings in
 *  a des.h header which causes other problems.
 */
#define	_RPC_RPC_H

#include <stdio.h>
#include <k5-int.h>
#include <kadm5/admin.h>
#include <rpc/types.h>
#include <krb5/adm_proto.h>
#include <rpc/xdr.h>
#include <time.h>
#include <libintl.h>
#include <locale.h>
#include "kdb5_util.h"

char	*Err_no_master_msg = "Master key not entered!\n";
char	*Err_no_database = "Database not currently opened!\n";

/*
 * XXX Ick, ick, ick.  These global variables shouldn't be global....
 */
char *mkey_password = 0;

/*
 * I can't figure out any way for this not to be global, given how ss
 * works.
 */

int exit_status = 0;
krb5_context util_context;
kadm5_config_params global_params;

void usage()
{
     fprintf(stderr, "%s: "
	   "kdb5_util [-x db_args]* [-r realm] [-d dbname] [-k mkeytype] [-M mkeyname]\n"
	     "\t        [-sf stashfilename] [-P password] [-m] cmd [cmd_options]\n"
	     "\tcreate	[-s]\n"
	     "\tdestroy	[-f]\n"
	     "\tstash	[-f keyfile]\n"
	     "\tdump	[-old] [-ov] [-b6] [-verbose] [filename	[princs...]]\n"
	     "\t	[-mkey_convert] [-new_mkey_file mkey_file]\n"
	     "\t	[-rev] [-recurse] [filename [princs...]]\n"
	     "\tload	[-old] [-ov] [-b6] [-verbose] [-update] filename\n"
	     "\tark	[-e etype_list] principal\n"
	     "\nwhere,\n\t[-x db_args]* - any number of database specific arguments.\n"
	     "\t\t\tLook at each database documentation for supported arguments\n",
		gettext("Usage"));
     exit(1);
}

krb5_keyblock master_key;
extern krb5_principal master_princ;
krb5_db_entry master_entry;
int	valid_master_key = 0;

char *progname;
krb5_boolean manual_mkey = FALSE;
krb5_boolean dbactive = FALSE;

static int open_db_and_mkey(void);

static void add_random_key(int, char **);

typedef void (*cmd_func)(int, char **);

struct _cmd_table {
     char *name;
     cmd_func func;
     int opendb;
} cmd_table[] = {
     {"create", kdb5_create, 0},
     {"destroy", kdb5_destroy, 1},
     {"stash", kdb5_stash, 1},
     {"dump", dump_db, 1},
     {"load", load_db, 0},
     {"ark", add_random_key, 1},
     {NULL, NULL, 0},
};

static struct _cmd_table *cmd_lookup(name)
   char *name;
{
     struct _cmd_table *cmd = cmd_table;
     while (cmd->name) {
	  if (strcmp(cmd->name, name) == 0)
	       return cmd;
	  else
	       cmd++;
     }

     return NULL;
}

#define ARG_VAL (--argc > 0 ? (koptarg = *(++argv)) : (char *)(usage(), NULL))

char **db5util_db_args = NULL;
int    db5util_db_args_size = 0;

static void extended_com_err_fn (const char *myprog, errcode_t code,
				 const char *fmt, va_list args)
{
    const char *emsg;
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

int add_db_arg(char *arg)
{
    char **temp;
    db5util_db_args_size++;
    temp = realloc(db5util_db_args,
		   sizeof(char *) * (db5util_db_args_size + 1));
    if (temp == NULL)
	return 0;
    db5util_db_args = temp;
    db5util_db_args[db5util_db_args_size-1] = arg;
    db5util_db_args[db5util_db_args_size]   = NULL;
    return 1;
}

int main(argc, argv)
    int argc;
    char *argv[];
{
    struct _cmd_table *cmd = NULL;
    char *koptarg, **cmd_argv;
    char *db_name_tmp = NULL;
    int cmd_argc;
    krb5_error_code retval;

	(void) setlocale(LC_ALL, "");
    set_com_err_hook(extended_com_err_fn);

#if !defined(TEXT_DOMAIN)  /* Should be defined by cc -D */
#define	TEXT_DOMAIN	"SYS_TEST"	/* Use this only if it weren't */
#endif

	(void) textdomain(TEXT_DOMAIN);

	Err_no_master_msg = gettext("Master key not entered!\n");
	Err_no_database = gettext("Database not currently opened!\n");

	/*
	 * Solaris Kerberos:
	 * Ensure that "progname" is set before calling com_err.
	 */
	progname = (strrchr(argv[0], '/') ?
		    strrchr(argv[0], '/') + 1 : argv[0]);

    retval = kadm5_init_krb5_context(&util_context);
    if (retval) {
	    com_err (progname, retval,
		gettext("while initializing Kerberos code"));
	    exit(1);
    }

    cmd_argv = (char **) malloc(sizeof(char *)*argc);
    if (cmd_argv == NULL) {
		com_err(progname, ENOMEM,
		    gettext("while creating sub-command arguments"));
	 exit(1);
    }
    memset(cmd_argv, 0, sizeof(char *)*argc);
    cmd_argc = 1;

    argv++; argc--;
    while (*argv) {
       if (strcmp(*argv, "-P") == 0 && ARG_VAL) {
	    mkey_password = koptarg;
	    manual_mkey = TRUE;
       } else if (strcmp(*argv, "-d") == 0 && ARG_VAL) {
	    global_params.dbname = koptarg;
	    global_params.mask |= KADM5_CONFIG_DBNAME;

	    db_name_tmp = malloc( strlen(global_params.dbname) + sizeof("dbname="));
	    if( db_name_tmp == NULL )
	    {
		com_err(progname, ENOMEM, "while parsing command arguments");
		exit(1);
	    }

	    strcpy( db_name_tmp, "dbname=");
	    strcat( db_name_tmp, global_params.dbname );

	    if (!add_db_arg(db_name_tmp)) {
		com_err(progname, ENOMEM, "while parsing command arguments\n");
		exit(1);
	    }

       } else if (strcmp(*argv, "-x") == 0 && ARG_VAL) {
	   if (!add_db_arg(koptarg)) {
		com_err(progname, ENOMEM, "while parsing command arguments\n");
		exit(1);
	   }

       } else if (strcmp(*argv, "-r") == 0 && ARG_VAL) {
	    global_params.realm = koptarg;
	    global_params.mask |= KADM5_CONFIG_REALM;
	    /* not sure this is really necessary */
	    if ((retval = krb5_set_default_realm(util_context,
						 global_params.realm))) {
				com_err(progname, retval,
					gettext("while setting default "
						"realm name"));
		 exit(1);
	    }
       } else if (strcmp(*argv, "-k") == 0 && ARG_VAL) {
	    if (krb5_string_to_enctype(koptarg, &global_params.enctype)) {
		/* Solaris Kerberos */
		 com_err(progname, 0, gettext("%s is an invalid enctype"), koptarg);
	    }
	    else
		 global_params.mask |= KADM5_CONFIG_ENCTYPE;
       } else if (strcmp(*argv, "-M") == 0 && ARG_VAL) {
	    global_params.mkey_name = koptarg;
	    global_params.mask |= KADM5_CONFIG_MKEY_NAME;
       } else if (((strcmp(*argv, "-sf") == 0)
		/* SUNWresync121 - carry the old -f forward too */
		|| (strcmp(*argv, "-f") == 0)) && ARG_VAL) {
	    global_params.stash_file = koptarg;
	    global_params.mask |= KADM5_CONFIG_STASH_FILE;
       } else if (strcmp(*argv, "-m") == 0) {
	    manual_mkey = TRUE;
	    global_params.mkey_from_kbd = 1;
	    global_params.mask |= KADM5_CONFIG_MKEY_FROM_KBD;
       } else if (cmd_lookup(*argv) != NULL) {
	    if (cmd_argv[0] == NULL)
		 cmd_argv[0] = *argv;
	    else
		 usage();
       } else {
	    cmd_argv[cmd_argc++] = *argv;
       }
       argv++; argc--;
    }

    if (cmd_argv[0] == NULL)
	 usage();

    if( !util_context->default_realm )
    {
	char *temp = NULL;
	retval = krb5_get_default_realm(util_context, &temp);
	if( retval )
	{
	    com_err (progname, retval, "while getting default realm");
	    exit(1);
	}
	util_context->default_realm = temp;
    }

    retval = kadm5_get_config_params(util_context, 1,
				     &global_params, &global_params);
    if (retval) {
		/* Solaris Kerberos */
		com_err(progname, retval,
		    gettext("while retreiving configuration parameters"));
	 exit(1);
    }

    /*
     * Dump creates files which should not be world-readable.  It is
     * easiest to do a single umask call here.
     */
    (void) umask(077);

    (void) memset(&master_key, 0, sizeof (krb5_keyblock));

    if ((global_params.enctype != ENCTYPE_UNKNOWN) &&
	(!krb5_c_valid_enctype(global_params.enctype))) {
	/* Solaris Kerberos */
	com_err(progname, KRB5_PROG_KEYTYPE_NOSUPP,
	    gettext("while setting up enctype %d"), global_params.enctype);
	exit(1);
    }

    cmd = cmd_lookup(cmd_argv[0]);
    if (cmd->opendb && open_db_and_mkey())
	 return exit_status;

	if (global_params.iprop_enabled == TRUE)
		ulog_set_role(util_context, IPROP_MASTER);
	else
		ulog_set_role(util_context, IPROP_NULL);

    (*cmd->func)(cmd_argc, cmd_argv);

    if( db_name_tmp )
	free( db_name_tmp );

    if( db5util_db_args )
	free(db5util_db_args);

    kadm5_free_config_params(util_context, &global_params);
    krb5_free_context(util_context);
    return exit_status;
}

#if 0
/*
 * This function is no longer used in kdb5_util (and it would no
 * longer work, anyway).
 */
void set_dbname(argc, argv)
    int argc;
    char *argv[];
{
    krb5_error_code retval;

    if (argc < 3) {
		/* Solaris Kerberos */
		com_err(progname, 0, gettext("Too few arguments"));
		com_err(progname, 0, gettext("Usage: %s dbpathname realmname"),
			progname);
	exit_status++;
	return;
    }
    if (dbactive) {
	if ((retval = krb5_db_fini(util_context)) && retval!= KRB5_KDB_DBNOTINITED) {
	    /* Solaris Kerberos */
	    com_err(progname, retval, gettext("while closing previous database"));
	    exit_status++;
	    return;
	}
	if (valid_master_key) {
	    krb5_free_keyblock_contents(util_context, &master_key);
	    master_key.contents = NULL;
	    valid_master_key = 0;
	}
	krb5_free_principal(util_context, master_princ);
	dbactive = FALSE;
    }

    /* Solaris Kerberos */
    (void) set_dbname_help(progname, argv[1]);
    return;
}
#endif

/*
 * open_db_and_mkey: Opens the KDC and policy database, and sets the
 * global master_* variables.  Sets dbactive to TRUE if the databases
 * are opened, and valid_master_key to 1 if the global master
 * variables are set properly.  Returns 0 on success, and 1 on
 * failure, but it is not considered a failure if the master key
 * cannot be fetched (the master key stash file may not exist when the
 * program is run).
 */
static int open_db_and_mkey()
{
    krb5_error_code retval;
    int nentries;
    krb5_boolean more;
    krb5_data scratch, pwd, seed;

    dbactive = FALSE;
    valid_master_key = 0;

    if ((retval = krb5_db_open(util_context, db5util_db_args,
			       KRB5_KDB_OPEN_RW | KRB5_KDB_SRV_TYPE_ADMIN))) {
	com_err(progname, retval, "while initializing database");
	exit_status++;
	return(1);
    }

   /* assemble & parse the master key name */

    if ((retval = krb5_db_setup_mkey_name(util_context,
					  global_params.mkey_name,
					  global_params.realm,
					  0, &master_princ))) {
		com_err(progname, retval,
		    gettext("while setting up master key name"));
	exit_status++;
	return(1);
    }
    nentries = 1;
    if ((retval = krb5_db_get_principal(util_context, master_princ,
					&master_entry, &nentries, &more))) {
		com_err(progname, retval,
		    gettext("while retrieving master entry"));
	exit_status++;
	(void) krb5_db_fini(util_context);
	return(1);
    } else if (more) {
	com_err(progname, KRB5KDC_ERR_PRINCIPAL_NOT_UNIQUE,
		    gettext("while retrieving master entry"));
	exit_status++;
	(void) krb5_db_fini(util_context);
	return(1);
    } else if (!nentries) {
		com_err(progname, KRB5_KDB_NOENTRY,
		    gettext("while retrieving master entry"));
	exit_status++;
	(void) krb5_db_fini(util_context);
	return(1);
    }

    krb5_db_free_principal(util_context, &master_entry, nentries);

    /* the databases are now open, and the master principal exists */
    dbactive = TRUE;

    if (mkey_password) {
	pwd.data = mkey_password;
	pwd.length = strlen(mkey_password);
	retval = krb5_principal2salt(util_context, master_princ, &scratch);
	if (retval) {
		com_err(progname, retval,
		    gettext("while calculated master key salt"));
	    /* Solaris Kerberos */
	    exit_status++;
	    return(1);
	}

	/* If no encryption type is set, use the default */
	if (global_params.enctype == ENCTYPE_UNKNOWN) {
	    global_params.enctype = DEFAULT_KDC_ENCTYPE;
	    if (!krb5_c_valid_enctype(global_params.enctype))
		com_err(progname, KRB5_PROG_KEYTYPE_NOSUPP,
			gettext("while setting up enctype %d"),
			global_params.enctype);
	}

	retval = krb5_c_string_to_key(util_context, global_params.enctype,
				      &pwd, &scratch, &master_key);
	if (retval) {
	    com_err(progname, retval,
		gettext("while transforming master key from password"));
	    /* Solaris Kerberos */
	    exit_status++;
	    return(1);
	}
	free(scratch.data);
	mkey_password = 0;
    } else if ((retval = krb5_db_fetch_mkey(util_context, master_princ,
					    global_params.enctype,
					    manual_mkey, FALSE,
					    global_params.stash_file,
					    0, &master_key))) {
	com_err(progname, retval,
	    gettext("while reading master key"));
	com_err(progname, 0,
	    gettext("Warning: proceeding without master key"));
	/*
	 * Solaris Kerberos: We don't want to count as an error if for instance
	 * the stash file is not present and we are trying to automate
	 * propagation, which really doesn't need a master key to do so.
	 */
	if (retval != KRB5_KDB_CANTREAD_STORED)
		exit_status++;
	return(0);
    }
    if ((retval = krb5_db_verify_master_key(util_context, master_princ,
		&master_key))) {
	com_err(progname, retval,
		gettext("while verifying master key"));
	exit_status++;
	krb5_free_keyblock_contents(util_context, &master_key);
	return(1);
    }

    seed.length = master_key.length;
    seed.data = (char *)master_key.contents;

    if ((retval = krb5_c_random_seed(util_context, &seed))) {
	com_err(progname, retval,
		gettext("while initializing random key generator"));
	exit_status++;
	krb5_free_keyblock_contents(util_context, &master_key);
	return(1);
    }

    valid_master_key = 1;
    dbactive = TRUE;
    return 0;
}

#ifdef HAVE_GETCWD
#undef getwd
#endif

int
quit()
{
    krb5_error_code retval;
    static krb5_boolean finished = 0;

    if (finished)
	return 0;
    retval = krb5_db_fini(util_context);
    krb5_free_keyblock_contents(util_context, &master_key);
    finished = TRUE;
    krb5_free_context(util_context);
    if (retval && retval != KRB5_KDB_DBNOTINITED) {
		com_err(progname, retval, gettext("while closing database"));
	exit_status++;
	return 1;
    }
    return 0;
}

static void
add_random_key(argc, argv)
    int argc;
    char **argv;
{
    krb5_error_code ret;
    krb5_principal princ;
    krb5_db_entry dbent;
    int n;
    krb5_boolean more;
    krb5_timestamp now;

    krb5_key_salt_tuple *keysalts = NULL;
    krb5_int32 num_keysalts = 0;

    int free_keysalts;
    /* Solaris Kerberos */
    char *me = progname;
    char *ks_str = NULL;
    char *pr_str;

    if (argc < 2)
	usage();
    for (argv++, argc--; *argv; argv++, argc--) {
	if (!strcmp(*argv, "-e")) {
	    argv++; argc--;
	    ks_str = *argv;
	    continue;
	} else
	    break;
    }
    if (argc < 1)
	usage();
    pr_str = *argv;
    ret = krb5_parse_name(util_context, pr_str, &princ);
    if (ret) {
	com_err(me, ret, gettext("while parsing principal name %s"), pr_str);
	exit_status++;
	return;
    }
    n = 1;
    ret = krb5_db_get_principal(util_context, princ, &dbent,
				&n, &more);
    if (ret) {
	com_err(me, ret, gettext("while fetching principal %s"), pr_str);
	exit_status++;
	return;
    }
    if (n != 1) {
	fprintf(stderr, gettext("principal %s not found\n"), pr_str);
	exit_status++;
	return;
    }
    if (more) {
	fprintf(stderr, gettext("principal %s not unique\n"), pr_str);
	krb5_db_free_principal(util_context, &dbent, 1);
	exit_status++;
	return;
    }
    ret = krb5_string_to_keysalts(ks_str,
				  ", \t", ":.-", 0,
				  &keysalts,
				  &num_keysalts);
    if (ret) {
	com_err(me, ret, gettext("while parsing keysalts %s"), ks_str);
	exit_status++;
	return;
    }
    if (!num_keysalts || keysalts == NULL) {
	num_keysalts = global_params.num_keysalts;
	keysalts = global_params.keysalts;
	free_keysalts = 0;
    } else
	free_keysalts = 1;
    ret = krb5_dbe_ark(util_context, &master_key,
		       keysalts, num_keysalts,
		       &dbent);
    if (free_keysalts)
	free(keysalts);
    if (ret) {
	com_err(me, ret, gettext("while randomizing principal %s"), pr_str);
	krb5_db_free_principal(util_context, &dbent, 1);
	exit_status++;
	return;
    }
    dbent.attributes &= ~KRB5_KDB_REQUIRES_PWCHANGE;
    ret = krb5_timeofday(util_context, &now);
    if (ret) {
	com_err(me, ret, gettext("while getting time"));
	krb5_db_free_principal(util_context, &dbent, 1);
	exit_status++;
	return;
    }
    ret = krb5_dbe_update_last_pwd_change(util_context, &dbent, now);
    if (ret) {
	com_err(me, ret, gettext("while setting changetime"));
	krb5_db_free_principal(util_context, &dbent, 1);
	exit_status++;
	return;
    }
    ret = krb5_db_put_principal(util_context, &dbent, &n);
    krb5_db_free_principal(util_context, &dbent, 1);
    if (ret) {
	com_err(me, ret, gettext("while saving principal %s"), pr_str);
	exit_status++;
	return;
    }
    printf("%s changed\n", pr_str);
}
