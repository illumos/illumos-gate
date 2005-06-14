/*
 * Copyright 2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * lib/krb5/krb/conv_princ.c
 *
 * Copyright 1992 by the Massachusetts Institute of Technology.
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
 * Build a principal from a V4 specification, or separate a V5
 * principal into name, instance, and realm.
 *
 * NOTE: This is highly site specific, and is only really necessary
 * for sites who need to convert from V4 to V5.  It is used by both
 * the KDC and the kdb5_convert program.  Since its use is highly
 * specialized, the necesary information is just going to be
 * hard-coded in this file.
 */

#include <k5-int.h>
#include <string.h>
#include <ctype.h>

/* The maximum sizes for V4 aname, realm, sname, and instance +1 */
/* Taken from krb.h */
#define 	ANAME_SZ	40
#define		REALM_SZ	40
#define		SNAME_SZ	40
#define		INST_SZ		40

struct krb_convert {
	char	*v4_str;
	char	*v5_str;
	int	flags;
};

#define DO_REALM_CONVERSION 0x00000001

/*
 * Kadmin doesn't do realm conversion because it's currently
 * kadmin/REALM.NAME.  It should be kadmin/kerberos.master.host, but
 * we'll fix that in the next release.
 */
static const struct krb_convert sconv_list[] = {
    {"kadmin",	"kadmin",	0},
    {"rcmd",	"host",		DO_REALM_CONVERSION},
    {"discuss",	"discuss",	DO_REALM_CONVERSION},
    {"rvdsrv",	"rvdsrv",	DO_REALM_CONVERSION},
    {"sample",	"sample",	DO_REALM_CONVERSION},
    {"olc",	"olc",		DO_REALM_CONVERSION},
    {"pop",	"pop",		DO_REALM_CONVERSION},
    {"sis",	"sis",		DO_REALM_CONVERSION},
    {"rfs",	"rfs",		DO_REALM_CONVERSION},
    {"imap",	"imap",		DO_REALM_CONVERSION},
    {"ftp",	"ftp",		DO_REALM_CONVERSION},
    {"ecat",	"ecat",		DO_REALM_CONVERSION},
    {"daemon",        "daemon",       DO_REALM_CONVERSION},
    {"gnats", "gnats",        DO_REALM_CONVERSION},
    {"moira", "moira",        DO_REALM_CONVERSION},
    {"prms",  "prms",         DO_REALM_CONVERSION},
    {"mandarin",      "mandarin",     DO_REALM_CONVERSION},
    {"register",      "register",     DO_REALM_CONVERSION},
    {"changepw",      "changepw",     DO_REALM_CONVERSION},
    {"sms",   "sms",          DO_REALM_CONVERSION},
    {"afpserver",     "afpserver",    DO_REALM_CONVERSION},
    {"gdss",  "gdss",         DO_REALM_CONVERSION},
    {"news",  "news",         DO_REALM_CONVERSION},
    {"abs",   "abs",          DO_REALM_CONVERSION},
    {"nfs",   "nfs",          DO_REALM_CONVERSION},
    {"tftp",  "tftp",         DO_REALM_CONVERSION},
    {"zephyr",        "zephyr",       0},
    {"http",  "http",         DO_REALM_CONVERSION},
    {"khttp", "khttp",        DO_REALM_CONVERSION},
    {"pgpsigner", "pgpsigner",        DO_REALM_CONVERSION},
    {"irc",   "irc",          DO_REALM_CONVERSION},
    {"mandarin-agent",        "mandarin-agent",       DO_REALM_CONVERSION},
    {"write", "write",        DO_REALM_CONVERSION},
    {"palladium", "palladium",        DO_REALM_CONVERSION},
    {0,		0,		0},
};

/*
 * char *strnchr(s, c, n)
 *   char *s;
 *   char c;
 *   int n;
 *
 * returns a pointer to the first occurrence of character c in the
 * string s, or a NULL pointer if c does not occur in in the string;
 * however, at most the first n characters will be considered.
 *
 * This falls in the "should have been in the ANSI C library"
 * category. :-)
 */
static char *strnchr(s, c, n)
   register char *s, c;
   register int n;
{
     if (n < 1)
	  return 0;

     while (n-- && *s) {
	  if (*s == c)
	       return s;
	  s++;
     }
     return 0;
}


/* XXX This calls for a new error code */
#define KRB5_INVALID_PRINCIPAL KRB5_LNAME_BADFORMAT

/*ARGSUSED*/
KRB5_DLLIMP krb5_error_code KRB5_CALLCONV
krb5_524_conv_principal(context, princ, name, inst, realm)
    krb5_context context;
    const krb5_principal princ;
    char FAR *name;
    char FAR *inst;
    char FAR *realm;
{
     const struct krb_convert *p;
     krb5_data *compo;
     char *c, *tmp_realm, *tmp_prealm;
     int tmp_realm_len, retval;

     *name = *inst = '\0';
     switch (krb5_princ_size(context, princ)) {
     case 2:
	  /* Check if this principal is listed in the table */
	  compo = krb5_princ_component(context, princ, 0);
	  p = sconv_list;
	  while (p->v4_str) {
	       if (strncmp(p->v5_str, compo->data, compo->length) == 0) {
		   /*
		    * It is, so set the new name now, and chop off
		    * instance's domain name if requested.
		    */
		   if (strlen (p->v4_str) > ANAME_SZ - 1)
		       return KRB5_INVALID_PRINCIPAL;
		   strcpy(name, p->v4_str);
		   if (p->flags & DO_REALM_CONVERSION) {
		       compo = krb5_princ_component(context, princ, 1);
		       c = strnchr(compo->data, '.', compo->length);
		       if (!c || (c - compo->data) >= INST_SZ - 1)
			   return KRB5_INVALID_PRINCIPAL;
		       memcpy(inst, compo->data, c - compo->data);
		       inst[c - compo->data] = '\0';
		   }
		   break;
	       }
	       p++;
	  }
	  /* If inst isn't set, the service isn't listed in the table, */
	  /* so just copy it. */
	  if (*inst == '\0') {
	       compo = krb5_princ_component(context, princ, 1);
	       if (compo->length >= INST_SZ - 1)
		    return KRB5_INVALID_PRINCIPAL;
	       memcpy(inst, compo->data, compo->length);
	       inst[compo->length] = '\0';
	  }
	  /* fall through */
	  /*FALLTHRU*/
     case 1:
	  /* name may have been set above; otherwise, just copy it */
	  if (*name == '\0') {
	       compo = krb5_princ_component(context, princ, 0);
	       if (compo->length >= ANAME_SZ)
		    return KRB5_INVALID_PRINCIPAL;
	       memcpy(name, compo->data, compo->length);
	       name[compo->length] = '\0';
	  }
	  break;
     default:
	  return KRB5_INVALID_PRINCIPAL;
     }

     compo = krb5_princ_realm(context, princ);

     tmp_prealm = malloc(compo->length + 1);
     if (tmp_prealm == NULL)
	 return ENOMEM;
     strncpy(tmp_prealm, compo->data, compo->length);
     tmp_prealm[compo->length] = '\0';

     /* Ask for v4_realm corresponding to
	krb5 principal realm from krb5.conf realms stanza */

     if (context->profile == 0)
       return KRB5_CONFIG_CANTOPEN;
     retval = profile_get_string(context->profile, "realms",
				 tmp_prealm, "v4_realm", 0,
				 &tmp_realm);
     free(tmp_prealm);
     if (retval) {
	 return retval;
     } else {
	 if (tmp_realm == 0) {
	     if (compo->length > REALM_SZ - 1)
		 return KRB5_INVALID_PRINCIPAL;
	     strncpy(realm, compo->data, compo->length);
	     realm[compo->length] = '\0';
	 } else {
	     tmp_realm_len =  strlen(tmp_realm);
	     if (tmp_realm_len > REALM_SZ - 1)
		 return KRB5_INVALID_PRINCIPAL;
	     strncpy(realm, tmp_realm, tmp_realm_len);
	     realm[tmp_realm_len] = '\0';
	     profile_release_string(tmp_realm);
	 }
     }
     return 0;
}

/*ARGSUSED*/
KRB5_DLLIMP krb5_error_code KRB5_CALLCONV
krb5_425_conv_principal(context, name, instance, realm, princ)
   krb5_context context;
   const char	FAR *name;
   const char	FAR *instance;
   const char	FAR *realm;
   krb5_principal	FAR *princ;
{
     const struct krb_convert *p;
     char buf[256];		/* V4 instances are limited to 40 characters */
     krb5_error_code retval;
     char **full_name = 0;
     char *domain, *cp;
     const char *names[5];
     void*	iterator = NULL;
     char** v4realms = NULL;
     char* realm_name = NULL;
     char* dummy_value = NULL;

     /* First, convert the realm, since the v4 realm is not necessarily the same as the v5 realm
        To do that, iterate over all the realms in the config file, looking for a matching
        v4_realm line */
     names [0] = "realms";
     names [1] = NULL;
     retval = profile_iterator_create (context -> profile, names, PROFILE_ITER_LIST_SECTION | PROFILE_ITER_SECTIONS_ONLY, &iterator);
     while (retval == 0) {
     	retval = profile_iterator (&iterator, &realm_name, &dummy_value);
     	if ((retval == 0) && (realm_name != NULL)) {
     		names [0] = "realms";
     		names [1] = realm_name;
     		names [2] = "v4_realm";
     		names [3] = NULL;

     		retval = profile_get_values (context -> profile, names, &v4realms);
     		if ((retval == 0) && (v4realms != NULL) && (v4realms [0] != NULL) && (strcmp (v4realms [0], realm) == 0)) {
     			realm = realm_name;
     			break;
     		} else if (retval == PROF_NO_RELATION) {
     			/* If it's not found, just keep going */
     			retval = 0;
     		}
     	} else if ((retval == 0) && (realm_name == NULL)) {
     		break;
     	}
     	if (realm_name != NULL) {
     		profile_release_string (realm_name);
     		realm_name = NULL;
     	}
     	if (dummy_value != NULL) {
     		profile_release_string (dummy_value);
     		dummy_value = NULL;
     	}
     }

     if (instance) {
	  if (instance[0] == '\0') {
	       instance = 0;
	       goto not_service;
	  }
	  p = sconv_list;
	 /*CONSTCOND*/
	  while (TRUE) {
	       if (!p->v4_str)
		    goto not_service;
	       if (!strcmp(p->v4_str, name))
		    break;
	       p++;
	  }
	  name = p->v5_str;
	  if ((p->flags & DO_REALM_CONVERSION) && !strchr(instance, '.')) {
	      names[0] = "realms";
	      names[1] = realm;
	      names[2] = "v4_instance_convert";
	      names[3] = instance;
	      names[4] = 0;
	      retval = profile_get_values(context->profile, names, &full_name);
	      if (retval == 0 && full_name && full_name[0]) {
		  instance = full_name[0];
	      } else {
		  strncpy(buf, instance, sizeof(buf));
		  buf[sizeof(buf) - 1] = '\0';
		  retval = krb5_get_realm_domain(context, realm, &domain);
		  if (retval)
		      return retval;
		  if (domain) {
		      for (cp = domain; *cp; cp++)
			  if (isupper(*cp))
			      *cp = tolower(*cp);
		      strncat(buf, ".", sizeof(buf) - 1 - strlen(buf));
		      strncat(buf, domain, sizeof(buf) - 1 - strlen(buf));
		      krb5_xfree(domain);
		  }
		  instance = buf;
	      }
	  }
     }

not_service:	
     retval = krb5_build_principal(context, princ, strlen(realm), realm, name,
				   instance, 0);
     profile_iterator_free (&iterator);
     profile_free_list(full_name);
     profile_free_list(v4realms);
     profile_release_string (realm_name);
     profile_release_string (dummy_value);
     return retval;
}
