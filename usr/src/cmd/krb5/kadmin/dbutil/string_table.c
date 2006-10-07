#pragma ident	"%Z%%M%	%I%	%E% SMI"

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
 * Copyright 1993 OpenVision Technologies, Inc., All Rights Reserved.
 * 
 */

/* String table of messages for kadm5_create */
/*
 * I18n HACK. We define gettext(s) to be s so that we can extract the
 * strings here to the .po file. At the end of this file we will undef
 * gettext.
 */

#define	gettext(s) s

char *str_PARSE_NAME = gettext("while parsing admin principal name.");

char *str_HISTORY_PARSE_NAME =
gettext("while parsing admin history principal name.");

char *str_ADMIN_PRINC_EXISTS =
gettext("Warning! Admin principal already exists.");

char *str_CHANGEPW_PRINC_EXISTS =
gettext("Warning! Changepw principal already exists.");

char *str_HISTORY_PRINC_EXISTS =
gettext("Warning! Admin history principal already exists.");

char *str_ADMIN_PRINC_WRONG_ATTRS =
gettext("Warning! Admin principal has incorrect attributes.\n"
	"\tDISALLOW_TGT should be set, and max_life should be three hours.\n"
	"\tThis program will leave them as-is, but beware!.");

char *str_CHANGEPW_PRINC_WRONG_ATTRS =
gettext("Warning! Changepw principal has incorrect attributes.\n"
	"\tDISALLOW_TGT and PW_CHANGE_SERVICE should both be set, and "
	"max_life should be five minutes.\n"
	"\tThis program will leave them as-is, but beware!.");

char *str_HISTORY_PRINC_WRONG_ATTRS =
gettext("Warning! Admin history principal has incorrect attributes.\n"
	"\tDISALLOW_ALL_TIX should be set.\n"
	"\tThis program will leave it as-is, but beware!.");

char *str_CREATED_PRINC_DB =
gettext("%s: Admin principal database created "
	"(or it already existed).\n");	/* whoami */

char *str_CREATED_POLICY_DB =
gettext("%s: Admin policy database created "
	"(or it already existed).\n");	/* whoami */

char *str_RANDOM_KEY =
gettext("while calling random key for %s.");	/* principal name */

char *str_ENCRYPT_KEY =
gettext("while calling encrypt key for %s.");	/* principal name */

char *str_PUT_PRINC =
gettext("while storing %s in Kerberos database.");	/* principal name */

char *str_CREATING_POLICY_DB =
gettext("while creating/opening admin policy database.");

char *str_CLOSING_POLICY_DB = gettext("while closing admin policy database.");

char *str_CREATING_PRINC_DB =
gettext("while creating/opening admin principal database.");

char *str_CLOSING_PRINC_DB =
gettext("while closing admin principal database.");

char *str_CREATING_PRINC_ENTRY =
gettext("while creating admin principal "
	"database entry for %s.");	/* princ_name */

char *str_A_PRINC = gettext("a principal");

char *str_UNPARSE_PRINC = gettext("while unparsing principal.");

char *str_CREATED_PRINC =
gettext("%s: Created %s principal.\n");	/* whoami, princ_name */

char *str_INIT_KDB = gettext("while initializing kdb.");

char *str_NO_KDB = 
gettext("while initializing kdb.\nThe Kerberos KDC database "
	"needs to exist in /krb5.\nIf you haven't run "
	"kdb5_create you need to do so before running this command.");


char *str_INIT_RANDOM_KEY =
gettext("while initializing random key generator.");

char *str_TOO_MANY_ADMIN_PRINC = 
gettext("while fetching admin princ. Can only have one admin principal.");

char *str_TOO_MANY_CHANGEPW_PRINC = 
gettext("while fetching changepw princ. "
	"Can only have one changepw principal.");

char *str_TOO_MANY_HIST_PRINC = 
gettext("while fetching history princ. "
	"Can only have one history principal.");

char *str_WHILE_DESTROYING_ADMIN_SESSION =
gettext("while closing session with admin server and destroying tickets.");

#undef gettext
