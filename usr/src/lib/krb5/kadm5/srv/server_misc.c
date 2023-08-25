
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
 * $Header$
 */

#if !defined(lint) && !defined(__CODECENTER__)
static char *rcsid = "$Header$";
#endif

#include    "k5-int.h"
#include    <krb5/kdb.h>
#include    <ctype.h>
#include    <pwd.h>

/* for strcasecmp */
#include    <string.h>

#include    "server_internal.h"

kadm5_ret_t
adb_policy_init(kadm5_server_handle_t handle)
{
    /* now policy is initialized as part of database. No seperate call needed */
    /* Solaris Kerberos: krb5_db_inited returns 0 when db has been inited */
    if( krb5_db_inited( handle->context ) == 0 )
	return KADM5_OK;

    return krb5_db_open( handle->context, NULL,
			 KRB5_KDB_OPEN_RW | KRB5_KDB_SRV_TYPE_ADMIN );
}

kadm5_ret_t
adb_policy_close(kadm5_server_handle_t handle)
{
    /* will be taken care by database close */
    return KADM5_OK;
}

#ifdef HESIOD
/* stolen from v4sever/kadm_funcs.c */
static char *
reverse(str)
	char	*str;
{
	static char newstr[80];
	char	*p, *q;
	int	i;

	i = strlen(str);
	if (i >= sizeof(newstr))
		i = sizeof(newstr)-1;
	p = str+i-1;
	q = newstr;
	q[i]='\0';
	for(; i > 0; i--)
		*q++ = *p--;

	return(newstr);
}
#endif /* HESIOD */

#if 0
static int
lower(str)
	char	*str;
{
	register char	*cp;
	int	effect=0;

	for (cp = str; *cp; cp++) {
		if (isupper(*cp)) {
			*cp = tolower(*cp);
			effect++;
		}
	}
	return(effect);
}
#endif

#ifdef HESIOD
static int
str_check_gecos(gecos, pwstr)
	char	*gecos;
	char	*pwstr;
{
	char		*cp, *ncp, *tcp;

	for (cp = gecos; *cp; ) {
		/* Skip past punctuation */
		for (; *cp; cp++)
			if (isalnum(*cp))
				break;
		/* Skip to the end of the word */
		for (ncp = cp; *ncp; ncp++)
			if (!isalnum(*ncp) && *ncp != '\'')
				break;
		/* Delimit end of word */
		if (*ncp)
			*ncp++ = '\0';
		/* Check word to see if it's the password */
		if (*cp) {
			if (!strcasecmp(pwstr, cp))
				return 1;
			tcp = reverse(cp);
			if (!strcasecmp(pwstr, tcp))
				return 1;
			cp = ncp;
		} else
			break;
	}
	return 0;
}
#endif /* HESIOD */

/* some of this is stolen from gatekeeper ... */
kadm5_ret_t
passwd_check(kadm5_server_handle_t handle,
	     char *password, int use_policy, kadm5_policy_ent_t pol,
	     krb5_principal principal)
{
    int	    nupper = 0,
	    nlower = 0,
	    ndigit = 0,
	    npunct = 0,
	    nspec = 0;
    char    c, *s, *cp;
#ifdef HESIOD
    extern  struct passwd *hes_getpwnam();
    struct  passwd *ent;
#endif

    if(use_policy) {
	if(strlen(password) < pol->pw_min_length)
	    return KADM5_PASS_Q_TOOSHORT;
	s = password;
	while ((c = *s++)) {
	    if (islower((unsigned char) c)) {
		nlower = 1;
		continue;
	    }
	    else if (isupper((unsigned char) c)) {
		nupper = 1;
		continue;
	    } else if (isdigit((unsigned char) c)) {
		ndigit = 1;
		continue;
	    } else if (ispunct((unsigned char) c)) {
		npunct = 1;
		continue;
	    } else {
		nspec = 1;
		continue;
	    }
	}
	if ((nupper + nlower + ndigit + npunct + nspec) < pol->pw_min_classes)
	    return KADM5_PASS_Q_CLASS;
	if((find_word(password) == KADM5_OK))
	    return KADM5_PASS_Q_DICT;
	else {
	    int	i, n = krb5_princ_size(handle->context, principal);
	    cp = krb5_princ_realm(handle->context, principal)->data;
	    if (strcasecmp(cp, password) == 0)
		return KADM5_PASS_Q_DICT;
	    for (i = 0; i < n ; i++) {
		cp = krb5_princ_component(handle->context, principal, i)->data;
		if (strcasecmp(cp, password) == 0)
		    return KADM5_PASS_Q_DICT;
#ifdef HESIOD
		ent = hes_getpwnam(cp);
		if (ent && ent->pw_gecos)
		    if (str_check_gecos(ent->pw_gecos, password))
			return KADM5_PASS_Q_DICT; /* XXX new error code? */
#endif
	    }
	    return KADM5_OK;
	}
    } else {
	if (strlen(password) < 1)
	    return KADM5_PASS_Q_TOOSHORT;
    }
    return KADM5_OK;
}

void
trunc_name(size_t *len, char **dots)
{
    *dots = *len > MAXPRINCLEN ? "..." : "";
    *len = *len > MAXPRINCLEN ? MAXPRINCLEN : *len;
}
