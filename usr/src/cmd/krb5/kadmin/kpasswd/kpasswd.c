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
 * Copyright 1993-1994 OpenVision Technologies, Inc., All Rights Reserved.
 *
 * $Header$
 *
 *
 */

static char rcsid[] = "$Id: kpasswd.c 17258 2005-06-21 01:36:03Z raeburn $";

#include <kadm5/admin.h>
#include <krb5.h>

#include "kpasswd_strings.h"
#define string_text error_message

#include "kpasswd.h"

#include <stdio.h>
#include <pwd.h>
#include <string.h>
#include <libintl.h>

extern char *whoami;

extern void display_intro_message();
extern long read_old_password();
extern long read_new_password();

#define MISC_EXIT_STATUS 6

/*
 * Function: kpasswd
 *
 * Purpose: Initialize and call lower level routines to change a password
 *
 * Arguments:
 *
 *	context		(r) krb5_context to use
 *	argc/argv	(r) principal name to use, optional
 *	read_old_password (f) function to read old password
 *	read_new_password (f) function to read new and change password
 *	display_intro_message (f) function to display intro message
 *	whoami		(extern) argv[0]
 *
 * Returns:
 *                      exit status of 0 for success
 *			1 principal unknown
 *			2 old password wrong
 *			3 cannot initialize admin server session
 *			4 new passwd mismatch or error trying to change pw
 *                      5 password not typed
 *                      6 misc error
 *                      7 incorrect usage
 *
 * Requires:
 *	Passwords cannot be more than 255 characters long.
 *
 * Effects:
 *
 * If argc is 2, the password for the principal specified in argv[1]
 * is changed; otherwise, the principal of the default credential
 * cache or username is used.  display_intro_message is called with
 * the arguments KPW_STR_CHANGING_PW_FOR and the principal name.
 * read_old_password is then called to prompt for the old password.
 * The admin system is then initialized, the principal's policy
 * retrieved and explained, if appropriate, and finally
 * read_new_password is called to read the new password and change the
 * principal's password (presumably ovsec_kadm_chpass_principal).
 * admin system is de-initialized before the function returns.
 *
 * Modifies:
 *
 * Changes the principal's password.
 *
 */
int
kpasswd(context, argc, argv)
   krb5_context context;
   int argc;
   char *argv[];
{
  kadm5_ret_t code;
  krb5_ccache ccache = NULL;
  krb5_principal princ = 0;
  char *princ_str;
  struct passwd *pw = 0;
  unsigned int pwsize;
  char password[255];  /* I don't really like 255 but that's what kinit uses */
  char msg_ret[1024], admin_realm[1024];
  kadm5_principal_ent_rec principal_entry;
  kadm5_policy_ent_rec policy_entry;
  void *server_handle;
  kadm5_config_params params;
  char *cpw_service;

	memset((char *)&params, 0, sizeof (params));
	memset(&principal_entry, 0, sizeof (principal_entry));
	memset(&policy_entry, 0, sizeof (policy_entry));

  if (argc > 2) {
      com_err(whoami, KPW_STR_USAGE, 0);
      return(7);
      /*NOTREACHED*/
    }

  /************************************
   *  Get principal name to change    *
   ************************************/

  /* Look on the command line first, followed by the default credential
     cache, followed by defaulting to the Unix user name */

  if (argc == 2)
    princ_str = strdup(argv[1]);
  else {
    code = krb5_cc_default(context, &ccache);
    /* If we succeed, find who is in the credential cache */
    if (code == 0) {
      /* Get default principal from cache if one exists */
      code = krb5_cc_get_principal(context, ccache, &princ);
      /* if we got a principal, unparse it, otherwise get out of the if
	 with an error code */
      (void) krb5_cc_close(context, ccache);
      if (code == 0) {
	code = krb5_unparse_name(context, princ, &princ_str);
	if (code != 0) {
	  com_err(whoami,  code, string_text(KPW_STR_UNPARSE_NAME));
	  return(MISC_EXIT_STATUS);
	}
      }
    }

    /* this is a crock.. we want to compare against */
    /* "KRB5_CC_DOESNOTEXIST" but there is no such error code, and */
    /* both the file and stdio types return FCC_NOFILE.  If there is */
    /* ever another ccache type (or if the error codes are ever */
    /* fixed), this code will have to be updated. */
    if (code && code != KRB5_FCC_NOFILE) {
      com_err(whoami, code, string_text(KPW_STR_WHILE_LOOKING_AT_CC));
      return(MISC_EXIT_STATUS);
    }

    /* if either krb5_cc failed check the passwd file */
    if (code != 0) {
      pw = getpwuid( getuid());
      if (pw == NULL) {
	com_err(whoami, 0, string_text(KPW_STR_NOT_IN_PASSWD_FILE));
	return(MISC_EXIT_STATUS);
      }
      princ_str = strdup(pw->pw_name);
    }
  }

  display_intro_message(string_text(KPW_STR_CHANGING_PW_FOR), princ_str);

  /* Need to get a krb5_principal, unless we started from with one from
     the credential cache */

  if (! princ) {
      code = krb5_parse_name (context, princ_str, &princ);
      if (code != 0) {
	  com_err(whoami, code, string_text(KPW_STR_PARSE_NAME), princ_str);
	  free(princ_str);
	  return(MISC_EXIT_STATUS);
      }
  }

  pwsize = sizeof(password);
  code = read_old_password(context, password, &pwsize);

  if (code != 0) {
    memset(password, 0, sizeof(password));
    com_err(whoami, code, string_text(KPW_STR_WHILE_READING_PASSWORD));
    krb5_free_principal(context, princ);
    free(princ_str);
    return(MISC_EXIT_STATUS);
  }
  if (pwsize == 0) {
    memset(password, 0, sizeof(password));
    com_err(whoami, 0, string_text(KPW_STR_NO_PASSWORD_READ));
    krb5_free_principal(context, princ);
    free(princ_str);
    return(5);
  }

	snprintf(admin_realm, sizeof (admin_realm),
		krb5_princ_realm(context, princ)->data);
	params.mask |= KADM5_CONFIG_REALM;
	params.realm = admin_realm;


	if (kadm5_get_cpw_host_srv_name(context, admin_realm, &cpw_service)) {
		fprintf(stderr, gettext("%s: unable to get host based "
					"service name for realm %s\n"),
			whoami, admin_realm);
		exit(1);
	}

	code = kadm5_init_with_password(princ_str, password, cpw_service,
					&params, KADM5_STRUCT_VERSION,
					KADM5_API_VERSION_2, NULL,
					&server_handle);
	free(cpw_service);
	if (code != 0) {
		if (code == KADM5_BAD_PASSWORD)
			com_err(whoami, 0,
				string_text(KPW_STR_OLD_PASSWORD_INCORRECT));
		else
			com_err(whoami, 0,
				string_text(KPW_STR_CANT_OPEN_ADMIN_SERVER),
				admin_realm,
				error_message(code));
		krb5_free_principal(context, princ);
		free(princ_str);
		return ((code == KADM5_BAD_PASSWORD) ? 2 : 3);
	}

	/*
	 * we can only check the policy if the server speaks
	 * RPCSEC_GSS
	 */
	if (_kadm5_get_kpasswd_protocol(server_handle) == KRB5_CHGPWD_RPCSEC) {
		/* Explain policy restrictions on new password if any. */
		/*
		 * Note: copy of this exists in login
		 * (kverify.c/get_verified_in_tkt).
		 */

		code = kadm5_get_principal(server_handle, princ,
					&principal_entry,
					KADM5_PRINCIPAL_NORMAL_MASK);
		if (code != 0) {
			com_err(whoami, 0,
				string_text((code == KADM5_UNK_PRINC)
					    ? KPW_STR_PRIN_UNKNOWN :
					    KPW_STR_CANT_GET_POLICY_INFO),
				princ_str);
			krb5_free_principal(context, princ);
			free(princ_str);
			(void) kadm5_destroy(server_handle);
			return ((code == KADM5_UNK_PRINC) ? 1 :
				MISC_EXIT_STATUS);
		}
		if ((principal_entry.aux_attributes & KADM5_POLICY) != 0) {
			code = kadm5_get_policy(server_handle,
						principal_entry.policy,
						&policy_entry);
			if (code != 0) {
				/*
				 * doesn't matter which error comes back,
				 * there's no nice recovery or need to
				 * differentiate to the user
				 */
				com_err(whoami, 0,
				string_text(KPW_STR_CANT_GET_POLICY_INFO),
				princ_str);
				(void) kadm5_free_principal_ent(server_handle,
							&principal_entry);
				krb5_free_principal(context, princ);
				free(princ_str);
				free(princ_str);
				(void) kadm5_destroy(server_handle);
				return (MISC_EXIT_STATUS);
			}
			com_err(whoami, 0,
				string_text(KPW_STR_POLICY_EXPLANATION),
				princ_str, principal_entry.policy,
				policy_entry.pw_min_length,
				policy_entry.pw_min_classes);
			if (code = kadm5_free_principal_ent(server_handle,
						    &principal_entry)) {
				(void) kadm5_free_policy_ent(server_handle,
							    &policy_entry);
				krb5_free_principal(context, princ);
				free(princ_str);
				com_err(whoami, code,
				string_text(KPW_STR_WHILE_FREEING_PRINCIPAL));
				(void) kadm5_destroy(server_handle);
				return (MISC_EXIT_STATUS);
			}
			if (code = kadm5_free_policy_ent(server_handle,
							&policy_entry)) {
				krb5_free_principal(context, princ);
				free(princ_str);
				com_err(whoami, code,
				string_text(KPW_STR_WHILE_FREEING_POLICY));
				(void) kadm5_destroy(server_handle);
				return (MISC_EXIT_STATUS);
			}
		} else {
			/*
			 * kpasswd *COULD* output something here to
			 * encourage the choice of good passwords,
			 * in the absence of an enforced policy.
			 */
			if (code = kadm5_free_principal_ent(server_handle,
						    &principal_entry)) {
				krb5_free_principal(context, princ);
				free(princ_str);
				com_err(whoami, code,
				string_text(KPW_STR_WHILE_FREEING_PRINCIPAL));
				(void) kadm5_destroy(server_handle);
				return (MISC_EXIT_STATUS);
			}
		}
	} /* if protocol == KRB5_CHGPWD_RPCSEC */

  pwsize = sizeof(password);
  code = read_new_password(server_handle, password, &pwsize, msg_ret, sizeof (msg_ret), princ);
  memset(password, 0, sizeof(password));

  if (code)
    com_err(whoami, 0, msg_ret);

  krb5_free_principal(context, princ);
  free(princ_str);

  (void) kadm5_destroy(server_handle);

  if (code == KRB5_LIBOS_CANTREADPWD)
     return(5);
  else if (code)
     return(4);
  else
     return(0);
}
