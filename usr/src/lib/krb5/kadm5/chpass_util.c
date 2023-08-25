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
 * Copyright 1993 OpenVision Technologies, Inc., All Rights Reserved.
 */


#include <stdio.h>
#ifdef HAVE_MEMORY_H
#include <memory.h>
#endif
#include <time.h>
#include <locale.h>

#include <kadm5/admin.h>
#include "admin_internal.h"

#include <krb5.h>
#include <strings.h>

#define string_text error_message

const char *chpw_error_message(kadm5_ret_t code);

/*
 * Function: kadm5_chpass_principal_util
 *
 * Purpose: Wrapper around chpass_principal. We can read new pw, change pw and return useful messages
 *
 * Arguments:
 *
 *      princ          (input) a krb5b_principal structure for the
 *                     principal whose password we should change.
 *
 *      new_password   (input) NULL or a null terminated string with the
 *                     the principal's desired new password.  If new_password
 *                     is NULL then this routine will read a new password.
 *
 *	pw_ret		(output) if non-NULL, points to a static buffer
 *			containing the new password (if password is prompted
 *			internally), or to the new_password argument (if
 *			that is non-NULL).  If the former, then the buffer
 *			is only valid until the next call to the function,
 *			and the caller should be sure to zero it when
 *			it is no longer needed.
 *
 *      msg_ret         (output) a useful message is copied here.
 *
 *      <return value>  exit status of 0 for success, else the com err code
 *                      for the last significant routine called.
 *
 * Requires:
 *
 *      A msg_ret should point to a buffer large enough for the messasge.
 *
 * Effects:
 *
 * Modifies:
 *
 *
 */

kadm5_ret_t _kadm5_chpass_principal_util(void *server_handle,
					 void *lhandle,
					 krb5_principal princ,
					 char *new_pw,
					 char **ret_pw,
					 char *msg_ret,
					 unsigned int msg_len)
{
  int code, code2;
  unsigned int pwsize;
  static char buffer[255];
  char *new_password;
  kadm5_principal_ent_rec princ_ent;
  kadm5_policy_ent_rec policy_ent;
  krb5_chgpwd_prot passwd_protocol;

  _KADM5_CHECK_HANDLE(server_handle);

  if (ret_pw)
    *ret_pw = NULL;

  if (new_pw != NULL) {
    new_password = new_pw;
  } else { /* read the password */
    krb5_context context;

    if ((code = (int) kadm5_init_krb5_context(&context)) == 0) {
      pwsize = sizeof(buffer);
      code = krb5_read_password(context, KADM5_PW_FIRST_PROMPT,
				KADM5_PW_SECOND_PROMPT,
				buffer, &pwsize);
      krb5_free_context(context);
    }

    if (code == 0)
      new_password = buffer;
    else {
#ifdef ZEROPASSWD
      memset(buffer, 0, sizeof(buffer));
#endif
      if (code == KRB5_LIBOS_BADPWDMATCH) {
	(void) strncpy(msg_ret, string_text(CHPASS_UTIL_NEW_PASSWORD_MISMATCH),
		msg_len - 1);
	msg_ret[msg_len - 1] = '\0';
	return(code);
      } else {
        (void) strncpy(msg_ret, error_message(code), msg_len - 1);
        (void) strncat(msg_ret, " ", msg_len - 1);
        (void) strncat(msg_ret, string_text(CHPASS_UTIL_WHILE_READING_PASSWORD),
		msg_len - 1);
        (void) strncat(msg_ret, string_text(CHPASS_UTIL_PASSWORD_NOT_CHANGED),
		msg_len - 1);
	msg_ret[msg_len - 1] = '\0';
	return(code);
      }
    }
    if (pwsize == 0) {
#ifdef ZEROPASSWD
      memset(buffer, 0, sizeof(buffer));
#endif
      strncpy(msg_ret, string_text(CHPASS_UTIL_NO_PASSWORD_READ), msg_len - 1);
      msg_ret[msg_len - 1] = '\0';
      return(KRB5_LIBOS_CANTREADPWD); /* could do better */
    }
  }

  if (ret_pw)
    *ret_pw = new_password;

	passwd_protocol = _kadm5_get_kpasswd_protocol(server_handle);
	if (passwd_protocol == KRB5_CHGPWD_CHANGEPW_V2) {
		kadm5_ret_t srvr_rsp_code;
		krb5_data   srvr_msg;

		srvr_msg.length = 0;
		srvr_msg.data = NULL;

		code = kadm5_chpass_principal_v2(server_handle, princ,
						new_password,
						&srvr_rsp_code,
						&srvr_msg);
		if (srvr_rsp_code) {
			sprintf(msg_ret, "%s%s%.*s\n",
				chpw_error_message(srvr_rsp_code),
				srvr_msg.length? ": " : "",
				srvr_msg.length,
				srvr_msg.data ? srvr_msg.data : "");

			return (srvr_rsp_code);
		}
		return (code);

	} else if (passwd_protocol == KRB5_CHGPWD_RPCSEC) {
		code = kadm5_chpass_principal(server_handle, princ,
					    new_password);

#ifdef ZEROPASSWD
  if (!ret_pw)
    memset(buffer, 0, sizeof(buffer)); /* in case we read a new password */
#endif

  if (code == KADM5_OK) {
    strncpy(msg_ret, string_text(CHPASS_UTIL_PASSWORD_CHANGED), msg_len - 1);
    msg_ret[msg_len - 1] = '\0';
    return(0);
  }

  if ((code != KADM5_PASS_Q_TOOSHORT) &&
      (code != KADM5_PASS_REUSE) &&(code != KADM5_PASS_Q_CLASS) &&
      (code != KADM5_PASS_Q_DICT) && (code != KADM5_PASS_TOOSOON)) {
    /* Can't get more info for other errors */
    sprintf(buffer, "%s %s", error_message(code),
	    string_text(CHPASS_UTIL_WHILE_TRYING_TO_CHANGE));
    sprintf(msg_ret, "%s\n%s\n", string_text(CHPASS_UTIL_PASSWORD_NOT_CHANGED),
	    buffer);
    return(code);
  }

  /* Ok, we have a password quality error. Return a good message */

  if (code == KADM5_PASS_REUSE) {
    strncpy(msg_ret, string_text(CHPASS_UTIL_PASSWORD_REUSE), msg_len - 1);
    msg_ret[msg_len - 1] = '\0';
    return(code);
  }

  if (code == KADM5_PASS_Q_DICT) {
    strncpy(msg_ret, string_text(CHPASS_UTIL_PASSWORD_IN_DICTIONARY),
	    msg_len - 1);
    msg_ret[msg_len - 1] = '\0';
    return(code);
  }

  /* Look up policy for the remaining messages */

  code2 = kadm5_get_principal (lhandle, princ, &princ_ent,
			       KADM5_PRINCIPAL_NORMAL_MASK);
  if (code2 != 0) {
    strncpy(msg_ret, error_message(code2), msg_len - 1);
    strncat(msg_ret, " ", msg_len - 1 - strlen(msg_ret));
    strncat(msg_ret, string_text(CHPASS_UTIL_GET_PRINC_INFO), msg_len - 1 - strlen(msg_ret));
    strncat(msg_ret, "\n", msg_len - 1 - strlen(msg_ret));
    strncat(msg_ret, error_message(code), msg_len - 1 - strlen(msg_ret));
    strncat(msg_ret, " ", msg_len - 1 - strlen(msg_ret));
    strncat(msg_ret, string_text(CHPASS_UTIL_WHILE_TRYING_TO_CHANGE),
	    msg_len - 1 - strlen(msg_ret));
    strncat(msg_ret, "\n\n", msg_len - 1 - strlen(msg_ret));
    strncat(msg_ret, string_text(CHPASS_UTIL_PASSWORD_NOT_CHANGED),
	    msg_len - 1 - strlen(msg_ret));
    strncat(msg_ret, "\n", msg_len - 1 - strlen(msg_ret));
    msg_ret[msg_len - 1] = '\0';
    return(code);
  }

  if ((princ_ent.aux_attributes & KADM5_POLICY) == 0) {
    strncpy(msg_ret, error_message(code), msg_len - 1 - strlen(msg_ret));
    strncat(msg_ret, " ", msg_len - 1 - strlen(msg_ret));
    strncpy(msg_ret, string_text(CHPASS_UTIL_NO_POLICY_YET_Q_ERROR),
	    msg_len - 1 - strlen(msg_ret));
    strncat(msg_ret, "\n\n", msg_len - 1 - strlen(msg_ret));
    strncpy(msg_ret, string_text(CHPASS_UTIL_PASSWORD_NOT_CHANGED),
	    msg_len - 1 - strlen(msg_ret));
    msg_ret[msg_len - 1] = '\0';

    (void) kadm5_free_principal_ent(lhandle, &princ_ent);
    return(code);
  }

  code2 = kadm5_get_policy(lhandle, princ_ent.policy,
			   &policy_ent);
  if (code2 != 0) {
    sprintf(msg_ret, "%s %s\n%s %s\n\n%s\n ", error_message(code2),
	    string_text(CHPASS_UTIL_GET_POLICY_INFO),
	    error_message(code),
	    string_text(CHPASS_UTIL_WHILE_TRYING_TO_CHANGE),
	    string_text(CHPASS_UTIL_PASSWORD_NOT_CHANGED));
    (void) kadm5_free_principal_ent(lhandle, &princ_ent);
    return(code);
  }

  if (code == KADM5_PASS_Q_TOOSHORT) {
    sprintf(msg_ret, string_text(CHPASS_UTIL_PASSWORD_TOO_SHORT),
	    policy_ent.pw_min_length);
    (void) kadm5_free_principal_ent(lhandle, &princ_ent);
    (void) kadm5_free_policy_ent(lhandle, &policy_ent);
    return(code);
  }


  if (code == KADM5_PASS_Q_CLASS) {
    sprintf(msg_ret, string_text(CHPASS_UTIL_TOO_FEW_CLASSES),
	    policy_ent.pw_min_classes);
    (void) kadm5_free_principal_ent(lhandle, &princ_ent);
    (void) kadm5_free_policy_ent(lhandle, &policy_ent);
    return(code);
  }

  if (code == KADM5_PASS_TOOSOON) {
    time_t until;
    char *time_string, *ptr;

    until = princ_ent.last_pwd_change + policy_ent.pw_min_life;

    time_string = ctime(&until);
    if (*(ptr = &time_string[strlen(time_string)-1]) == '\n')
      *ptr = '\0';

    sprintf(msg_ret, string_text(CHPASS_UTIL_PASSWORD_TOO_SOON),
	    time_string);
    (void) kadm5_free_principal_ent(lhandle, &princ_ent);
    (void) kadm5_free_policy_ent(lhandle, &policy_ent);
    return(code);
  } else {

  /* We should never get here, but just in case ... */
  sprintf(buffer, "%s %s", error_message(code),
	  string_text(CHPASS_UTIL_WHILE_TRYING_TO_CHANGE));
  sprintf(msg_ret, "%s\n%s\n", string_text(CHPASS_UTIL_PASSWORD_NOT_CHANGED),
	  buffer);
  (void) kadm5_free_principal_ent(lhandle, &princ_ent);
  (void) kadm5_free_policy_ent(lhandle, &policy_ent);
  return(code);
		}
	} else {
		sprintf(msg_ret, "%s\n%s\n",
			string_text(CHPASS_UTIL_PASSWORD_NOT_CHANGED),
			"Password protocol in krb5.conf is not supported\n");
		return (-1);
	}
}

/*
 * krb5_chpw_result_code_string
 *
 * convert the return code received from the password server
 * to a human-readable string.
 */
const char *
chpw_error_message(kadm5_ret_t result_code)
{
	switch (result_code) {
	case KRB5_KPASSWD_MALFORMED:
		return (dgettext(TEXT_DOMAIN, "Malformed request error"));
	case KRB5_KPASSWD_HARDERROR:
		return (dgettext(TEXT_DOMAIN, "Server error"));
	case KRB5_KPASSWD_AUTHERROR:
		return (dgettext(TEXT_DOMAIN, "Authentication error"));
	case KRB5_KPASSWD_SOFTERROR:
		return (dgettext(TEXT_DOMAIN, "Password change rejected"));
	case KRB5_KPASSWD_ACCESSDENIED:
		return (dgettext(TEXT_DOMAIN,
				"Not authorized to change password"));
	case KRB5_KPASSWD_BAD_VERSION:
		return (dgettext(TEXT_DOMAIN, "Protocol version unsupported"));
	case KRB5_KPASSWD_INITIAL_FLAG_NEEDED:
		return (dgettext(TEXT_DOMAIN,
				"initial flag required in changepw request"));
	case KRB5_KPASSWD_POLICY_REJECT:
		return (dgettext(TEXT_DOMAIN, "new password fails policy"));
	case KRB5_KPASSWD_BAD_PRINCIPAL:
		return (dgettext(TEXT_DOMAIN,
		    "target principal does not exist for "
		    "changepw request"));
	case KRB5_KPASSWD_ETYPE_NOSUPP:
		return (dgettext(TEXT_DOMAIN,
		    "changepw request key sequence has an "
		    "unsupported Etype"));
	default:
		return (dgettext(TEXT_DOMAIN, "Password change failed"));
	}
}
