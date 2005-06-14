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
 * Copyright 1993 OpenVision Technologies, Inc., All Rights Reserved
 *
 * $Header: /afs/athena.mit.edu/astaff/project/krbdev/.cvsroot/src/lib/kadm5/srv/svr_iters.c,v 1.2 1996/11/07 21:43:14 bjaspan Exp $
 */

#if !defined(lint) && !defined(__CODECENTER__)
static char *rcsid = "$Header: /afs/athena.mit.edu/astaff/project/krbdev/.cvsroot/src/lib/kadm5/srv/svr_iters.c,v 1.2 1996/11/07 21:43:14 bjaspan Exp $";
#endif

#if defined(HAVE_COMPILE) && defined(HAVE_STEP)
#define SOLARIS_REGEXPS
#elif defined(HAVE_REGCOMP) && defined(HAVE_REGEXEC)
#define POSIX_REGEXPS
#elif defined(HAVE_RE_COMP) && defined(HAVE_RE_EXEC)
#define BSD_REGEXPS
#else
#error I cannot find any regexp functions
#endif

#include	<sys/types.h>
#include	<string.h>
#include	<kadm5/admin.h>
#include	"adb.h"
#include	<dyn/dyn.h>
#ifdef SOLARIS_REGEXPS
#include	<regexpr.h>
#endif
#ifdef POSIX_REGEXPS
#include	<regex.h>
#endif
#include <stdlib.h>

#include	"server_internal.h"

krb5_error_code
kdb_iter_entry(kadm5_server_handle_t handle,
	       void (*iter_fct)(void *, krb5_principal), void *data);

struct iter_data {
     krb5_context context;
     DynObject matches;
     char *exp;
#ifdef SOLARIS_REGEXPS
     char *expbuf;
#endif
#ifdef POSIX_REGEXPS
     regex_t preg;
#endif
};

/*
 * Function: glob_to_regexp
 *
 * Arguments:
 *
 *	glob	(r) the shell-style glob (?*[]) to convert
 *	realm	(r) the default realm to append, or NULL
 *	regexp	(w) the ed-style regexp created from glob
 *
 * Effects:
 *
 * regexp is filled in with allocated memory contained a regular
 * expression to be used with re_comp/compile that matches what the
 * shell-style glob would match.  If glob does not contain an "@"
 * character and realm is not NULL, "@*" is appended to the regexp.
 *
 * Conversion algorithm:
 *
 *	quoted characters are copied quoted
 *	? is converted to .
 *	* is converted to .*
 * 	active characters are quoted: ^, $, .
 *	[ and ] are active but supported and have the same meaning, so
 *		they are copied
 *	other characters are copied
 *	regexp is anchored with ^ and $
 */
kadm5_ret_t glob_to_regexp(char *glob, char *realm, char **regexp)
{
     int append_realm;
     char *p;

     /* validate the glob */
     if (glob[strlen(glob)-1] == '\\')
	  return EINVAL;

     /* A character of glob can turn into two in regexp, plus ^ and $ */
     /* and trailing null.  If glob has no @, also allocate space for */
     /* the realm. */
     append_realm = (realm != NULL) && (strchr(glob, '@') == NULL);
     p = (char *) malloc(strlen(glob)*2+ 3 + (append_realm ? 2 : 0));
     if (p == NULL)
	  return ENOMEM;
     *regexp = p;

     *p++ = '^';
     while (*glob) {
	  switch (*glob) {
	  case '?':
	       *p++ = '.';
	       break;
	  case '*':
	       *p++ = '.';
	       *p++ = '*';
	       break;
	  case '.':
	  case '^':
	  case '$':
	       *p++ = '\\';
	       *p++ = *glob;
	       break;
	  case '\\':
	       *p++ = '\\';
	       *p++ = ++*glob;
	       break;
	  default:
	       *p++ = *glob;
	       break;
	  }
	  glob++;
     }

     if (append_realm) {
	  *p++ = '@';
	  *p++ = '*';
     }

     *p++ = '$';
     *p++ = '\0';
     return KADM5_OK;
}

void get_either_iter(struct iter_data *data, char *name)
{
     if (
#ifdef SOLARIS_REGEXPS
	 (step(name, data->expbuf) != 0)
#endif
#ifdef POSIX_REGEXPS
	 (regexec(&data->preg, name, 0, NULL, 0) == 0)
#endif
#ifdef BSD_REGEXPS
	 (re_exec(name) != 0)
#endif
	 )
     {
	  (void) DynAdd(data->matches, &name);
     } else
	  free(name);
}

void get_pols_iter(void *data, osa_policy_ent_t entry)
{
     char *name;

     if ((name = strdup(entry->name)) == NULL)
	  return;
     get_either_iter(data, name);
}

void get_princs_iter(void *data, krb5_principal princ)
{
     struct iter_data *id = (struct iter_data *) data;
     char *name;
     
     if (krb5_unparse_name(id->context, princ, &name) != 0)
	  return;
     get_either_iter(data, name);
}

kadm5_ret_t kadm5_get_either(int princ,
				       void *server_handle,
				       char *exp,
				       char ***princs,
				       int *count)
{
     struct iter_data data;
     char *msg, *regexp;
     int ret;
     kadm5_server_handle_t handle = server_handle;
     
     *count = 0;
     if (exp == NULL)
	  exp = "*";

     CHECK_HANDLE(server_handle);

     if ((ret = glob_to_regexp(exp, princ ? handle->params.realm : NULL,
			       &regexp)) != KADM5_OK)
	  return ret;

     if (
#ifdef SOLARIS_REGEXPS
	 ((data.expbuf = compile(regexp, NULL, NULL)) == NULL)
#endif
#ifdef POSIX_REGEXPS
	 ((regcomp(&data.preg, regexp, REG_NOSUB)) != 0)
#endif
#ifdef BSD_REGEXPS
	 ((msg = (char *) re_comp(regexp)) != NULL)
#endif
	 )
     {
	  /* XXX syslog msg or regerr(regerrno) */
	  free(regexp);
	  return EINVAL;
     }

     if ((data.matches = DynCreate(sizeof(char *), -4)) == NULL) {
	  free(regexp);
	  return ENOMEM;
     }

     if (princ) {
	  data.context = handle->context;
	  ret = kdb_iter_entry(handle, get_princs_iter, (void *) &data);
     } else {
	  ret = osa_adb_iter_policy(handle->policy_db, get_pols_iter, (void *)&data);
     }
     
     if (ret != OSA_ADB_OK) {
	  free(regexp);
	  DynDestroy(data.matches);
	  return ret;
     }

     (*princs) = (char **) DynArray(data.matches);
     *count = DynSize(data.matches);
     DynRelease(data.matches);
     free(regexp);
     return KADM5_OK;
}

kadm5_ret_t kadm5_get_principals(void *server_handle,
					   char *exp,
					   char ***princs,
					   int *count)
{
     return kadm5_get_either(1, server_handle, exp, princs, count);
}

kadm5_ret_t kadm5_get_policies(void *server_handle,
					   char *exp,
					   char ***pols,
					   int *count)
{
     return kadm5_get_either(0, server_handle, exp, pols, count);
}

