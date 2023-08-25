/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


/*
 * lib/krb5/os/an_to_ln.c
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
 * krb5_aname_to_localname()
 */

/*
 * We're only to AN_TO_LN rules at this point, and not doing the
 * database lookup  (moved from configure script)
 */
#define AN_TO_LN_RULES

#include "k5-int.h"
#include <ctype.h>
#if	HAVE_REGEX_H
#include <regex.h>
#endif	/* HAVE_REGEX_H */
#include <string.h>
/*
 * Use compile(3) if no regcomp present.
 */
#if	!defined(HAVE_REGCOMP) && defined(HAVE_REGEXPR_H) && defined(HAVE_COMPILE)
#define	RE_BUF_SIZE	1024
#include <regexpr.h>
#endif	/* !HAVE_REGCOMP && HAVE_REGEXP_H && HAVE_COMPILE */

#define	MAX_FORMAT_BUFFER	1024
#ifndef	min
#define	min(a,b)	((a>b) ? b : a)
#endif	/* min */
#ifdef ANAME_DB
/*
 * Use standard DBM code.
 */
#define	KDBM_OPEN(db, fl, mo)	dbm_open(db, fl, mo)
#define	KDBM_CLOSE(db)		dbm_close(db)
#define	KDBM_FETCH(db, key)	dbm_fetch(db, key)
#endif /*ANAME_DB*/

/*
 * Find the portion of the flattened principal name that we use for mapping.
 */
static char *
aname_full_to_mapping_name(char *fprincname)
{
    char	*atp;
    size_t	mlen;
    char	*mname;

    mname = (char *) NULL;
    if (fprincname) {
	atp = strrchr(fprincname, '@');
	if (!atp)
	    atp = &fprincname[strlen(fprincname)];
	mlen = (size_t) (atp - fprincname);

	if ((mname = (char *) malloc(mlen+1))) {
	    strncpy(mname, fprincname, mlen);
	    mname[mlen] = '\0';
	}
    }
    return(mname);
}

#ifdef ANAME_DB
/*
 * Implementation:  This version uses a DBM database, indexed by aname,
 * to generate a lname.
 *
 * The entries in the database are normal C strings, and include the trailing
 * null in the DBM datum.size.
 */
static krb5_error_code
db_an_to_ln(context, dbname, aname, lnsize, lname)
    krb5_context context;
    char *dbname;
    krb5_const_principal aname;
    const unsigned int lnsize;
    char *lname;
{
#if !defined(_WIN32)
    DBM *db;
    krb5_error_code retval;
    datum key, contents;
    char *princ_name;

    if ((retval = krb5_unparse_name(context, aname, &princ_name)))
	return(retval);
    key.dptr = princ_name;
    key.dsize = strlen(princ_name)+1;	/* need to store the NULL for
					   decoding */

    db = KDBM_OPEN(dbname, O_RDONLY, 0600);
    if (!db) {
	krb5_xfree(princ_name);
	return KRB5_LNAME_CANTOPEN;
    }

    contents = KDBM_FETCH(db, key);

    krb5_xfree(princ_name);

    if (contents.dptr == NULL) {
	retval = KRB5_LNAME_NOTRANS;
    } else {
	strncpy(lname, contents.dptr, lnsize);
	if (lnsize < contents.dsize)
	    retval = KRB5_CONFIG_NOTENUFSPACE;
	else if (lname[contents.dsize-1] != '\0')
	    retval = KRB5_LNAME_BADFORMAT;
	else
	    retval = 0;
    }
    /* can't close until we copy the contents. */
    (void) KDBM_CLOSE(db);
    return retval;
#else	/* !_WIN32 && !MACINTOSH */
    /*
     * If we don't have support for a database mechanism, then we can't
     * translate this now, can we?
     */
    return KRB5_LNAME_NOTRANS;
#endif	/* !_WIN32 && !MACINTOSH */
}
#endif /*ANAME_DB*/

#ifdef	AN_TO_LN_RULES
/*
 * Format and transform a principal name to a local name.  This is particularly
 * useful when Kerberos principals and local user names are formatted to
 * some particular convention.
 *
 * There are three parts to each rule:
 * First part - formulate the string to perform operations on:  If not present
 * then the string defaults to the fully flattened principal minus the realm
 * name.  Otherwise the syntax is as follows:
 *	"[" <ncomps> ":" <format> "]"
 *		Where:
 *			<ncomps> is the number of expected components for this
 *			rule.  If the particular principal does not have this
 *			many components, then this rule does not apply.
 *
 *			<format> is a string of <component> or verbatim
 *			characters to be inserted.
 *
 *			<component> is of the form "$"<number> to select the
 *			<number>th component.  <number> begins from 1.
 *
 * Second part - select rule validity:  If not present, then this rule may
 * apply to all selections.  Otherwise the syntax is as follows:
 *	"(" <regexp> ")"
 *		Where:	<regexp> is a selector regular expression.  If this
 *			regular expression matches the whole pattern generated
 *			from the first part, then this rule still applies.
 *
 * Last part - Transform rule:  If not present, then the selection string
 * is passed verbatim and is matched.  Otherwise, the syntax is as follows:
 *	<rule> ...
 *		Where:	<rule> is of the form:
 *			"s/" <regexp> "/" <text> "/" ["g"]
 *
 * In order to be able to select rule validity, the native system must support
 * one of compile(3), re_comp(3) or regcomp(3).  In order to be able to
 * transform (e.g. substitute), the native system must support regcomp(3) or
 * compile(3).
 */

/*
 * aname_do_match() 	- Does our name match the parenthesized regular
 *			  expression?
 *
 * Chew up the match portion of the regular expression and update *contextp.
 * If no re_comp() or regcomp(), then always return a match.
 */
static krb5_error_code
aname_do_match(char *string, char **contextp)
{
    krb5_error_code	kret;
    char		*regexp, *startp, *endp = 0;
    size_t		regexlen;
#if	HAVE_REGCOMP
    regex_t		match_exp;
    regmatch_t		match_match;
#elif	HAVE_REGEXPR_H
    char		regexp_buffer[RE_BUF_SIZE];
#endif	/* HAVE_REGEXP_H */

    kret = 0;
    /*
     * Is this a match expression?
     */
    if (**contextp == '(') {
	kret = KRB5_CONFIG_BADFORMAT;
	startp = (*contextp) + 1;
	endp = strchr(startp, ')');
	/* Find the end of the match expression. */
	if (endp) {
	    regexlen = (size_t) (endp - startp);
	    regexp = (char *) malloc((size_t) regexlen+1);
	    kret = ENOMEM;
	    if (regexp) {
		strncpy(regexp, startp, regexlen);
		regexp[regexlen] = '\0';
		kret = KRB5_LNAME_NOTRANS;
		/*
		 * Perform the match.
		 */
#if	HAVE_REGCOMP
		if (!regcomp(&match_exp, regexp, REG_EXTENDED) &&
		    !regexec(&match_exp, string, 1, &match_match, 0)) {
		    if ((match_match.rm_so == 0) &&
			(match_match.rm_eo == strlen(string)))
			kret = 0;
		}
		regfree(&match_exp);
#elif	HAVE_REGEXPR_H
		compile(regexp,
			regexp_buffer,
			&regexp_buffer[RE_BUF_SIZE]);
		if (step(string, regexp_buffer)) {
		    if ((loc1 == string) &&
			(loc2 == &string[strlen(string)]))
			kret = 0;
		}
#elif	HAVE_RE_COMP
		if (!re_comp(regexp) && re_exec(string))
		    kret = 0;
#else	/* HAVE_RE_COMP */
		kret = 0;
#endif	/* HAVE_RE_COMP */
		free(regexp);
	    }
	    endp++;
	}
	else
	    endp = startp;
    }
    *contextp = endp;
    return(kret);
}

/*
 * do_replacement()	- Replace the regular expression with the specified
 * 			  replacement.
 *
 * If "doall" is set, it's a global replacement, otherwise, just a oneshot
 * deal.
 * If no regcomp() then just return the input string verbatim in the output
 * string.
 */
#define use_bytes(x) \
    out_used += (x); \
    if (out_used > MAX_FORMAT_BUFFER) goto mem_err

static int
do_replacement(char *regexp, char *repl, int doall, char *in, char *out)
{
    size_t out_used = 0;
#if	HAVE_REGCOMP
    regex_t	match_exp;
    regmatch_t	match_match;
    int		matched;
    char	*cp;
    char	*op;

    if (!regcomp(&match_exp, regexp, REG_EXTENDED)) {
	cp = in;
	op = out;
	matched = 0;
	do {
	    if (!regexec(&match_exp, cp, 1, &match_match, 0)) {
		if (match_match.rm_so) {
		    use_bytes(match_match.rm_so);
		    strncpy(op, cp, match_match.rm_so);
		    op += match_match.rm_so;
		}
		use_bytes(strlen(repl));
		strncpy(op, repl, MAX_FORMAT_BUFFER - 1 - (op - out));
		op += strlen(op);
		cp += match_match.rm_eo;
		if (!doall) {
		    use_bytes(strlen(cp));
		    strncpy(op, cp, MAX_FORMAT_BUFFER - 1 - (op - out));
		}
		matched = 1;
	    }
	    else {
		use_bytes(strlen(cp));
		strncpy(op, cp, MAX_FORMAT_BUFFER - 1 - (op - out));
		matched = 0;
	    }
	} while (doall && matched);
	regfree(&match_exp);
    }
#elif	HAVE_REGEXPR_H
    int		matched;
    char	*cp;
    char	*op;
    char	regexp_buffer[RE_BUF_SIZE];
    size_t	sdispl, edispl;

    compile(regexp,
	    regexp_buffer,
	    &regexp_buffer[RE_BUF_SIZE]);
    cp = in;
    op = out;
    matched = 0;
    do {
	if (step(cp, regexp_buffer)) {
	    sdispl = (size_t) (loc1 - cp);
	    edispl = (size_t) (loc2 - cp);
	    if (sdispl) {
		use_bytes(sdispl);
		strncpy(op, cp, sdispl);
		op += sdispl;
	    }
	    use_bytes(strlen(repl));
	    strncpy(op, repl, MAX_FORMAT_BUFFER - 1 - (op - out));
	    op += strlen(repl);
	    cp += edispl;
	    if (!doall) {
		use_bytes(strlen(cp));
		strncpy(op, cp, MAX_FORMAT_BUFFER - 1 - (op - out));
	    }
	    matched = 1;
	}
	else {
	    use_bytes(strlen(cp));
	    strncpy(op, cp, MAX_FORMAT_BUFFER - 1 - (op - out));
	    matched = 0;
	}
    } while (doall && matched);
#else	/* HAVE_REGEXP_H */
    memcpy(out, in, MAX_FORMAT_BUFFER);
#endif	/* HAVE_REGCOMP */
    return 1;
 mem_err:
#ifdef HAVE_REGCMP
    	regfree(&match_exp);
#endif
	return 0;

}
#undef use_bytes

/*
 * aname_replacer()	- Perform the specified substitutions on the input
 *			  string and return the result.
 *
 * This routine enforces the "s/<pattern>/<replacement>/[g]" syntax.
 */
static krb5_error_code
aname_replacer(char *string, char **contextp, char **result)
{
    krb5_error_code	kret;
    char		*in;
    char		*out;
    char		*cp, *ep, *tp;
    char		*rule, *repl;
    size_t		rule_size, repl_size;
    int			doglobal;
    char		sep;

    kret = ENOMEM;
    *result = (char *) NULL;
    /* Allocate the formatting buffers */
    /* Solaris Kerberos */
    if (((in = (char *) malloc(MAX_FORMAT_BUFFER)) != NULL) &&
	((out = (char *) malloc(MAX_FORMAT_BUFFER)) != NULL)) {
	/*
	 * Prime the buffers.  Copy input string to "out" to simulate it
	 * being the result of an initial iteration.
	 */
	strncpy(out, string, MAX_FORMAT_BUFFER - 1);
	out[MAX_FORMAT_BUFFER - 1] = '\0';
	in[0] = '\0';
	kret = 0;
	/*
	 * Pound through the expression until we're done.
	 */
	for (cp = *contextp; *cp; ) {
	    /* Skip leading whitespace */
	    while (isspace((int) (*cp)))
		cp++;

	    /*
	     * Solaris Kerberos
	     * Find our separators.  First two characters must be "s<sep>"
	     * We must also find another "<sep>" followed by another * "<sep>".
	     */
	    if (cp[0] != 's') {
		/* Bad syntax */
		kret = KRB5_CONFIG_BADFORMAT;
		break;
	    }
	    if (strspn(cp + 1, ",/;|!%") < 1) {
		/* Bad syntax */
		kret = KRB5_CONFIG_BADFORMAT;
		break;
	    }
	    sep = cp[1];

	    if (((ep = strchr(&cp[2], sep)) != NULL) &&
		((tp = strchr(&ep[1], sep)) != NULL)) {

		/* Figure out sizes of strings and allocate them */
		rule_size = (size_t) (ep - &cp[2]);
		repl_size = (size_t) (tp - &ep[1]);
		/* Solaris Kerberos */
		if (((rule = (char *) malloc(rule_size+1)) != NULL) &&
		    ((repl = (char *) malloc(repl_size+1)) != NULL)) {

		    /* Copy the strings */
		    strncpy(rule, &cp[2], rule_size);
		    strncpy(repl, &ep[1], repl_size);
		    rule[rule_size] = repl[repl_size] = '\0';

		    /* Check for trailing "g" */
		    doglobal = (tp[1] == 'g') ? 1 : 0;
		    if (doglobal)
			tp++;

		    /* Swap previous in and out buffers */
		    ep = in;
		    in = out;
		    out = ep;

		    /* Do the replacemenbt */
		    memset(out, '\0', MAX_FORMAT_BUFFER);
		    if (!do_replacement(rule, repl, doglobal, in, out)) {
			free(rule);
		    free(repl);
			kret = KRB5_LNAME_NOTRANS;
			break;
		    }
		    free(rule);
		    free(repl);

		    /* If we have no output buffer left, this can't be good */
		    if (strlen(out) == 0) {
			kret = KRB5_LNAME_NOTRANS;
			break;
		    }
		}
		else {
		    /* No memory for copies */
		    kret = ENOMEM;
		    break;
		}
	    }
	    else {
		/* Bad syntax */
		kret = KRB5_CONFIG_BADFORMAT;
		break;
	    }
	    /* Advance past trailer */
	    cp = &tp[1];
	}
	free(in);
	if (!kret)
	    *result = out;
	else
	    free(out);
    }
    return(kret);
}

/*
 * rule_an_to_ln()	- Handle aname to lname translations for RULE rules.
 *
 * The initial part of this routine handles the formulation of the strings from
 * the principal name.
 */
static krb5_error_code
rule_an_to_ln(krb5_context context, char *rule, krb5_const_principal aname, const unsigned int lnsize, char *lname)
{
    krb5_error_code	kret;
    char		*current;
    char		*fprincname;
    char		*selstring = 0;
    int			num_comps, compind;
    size_t selstring_used;
    char		*cout;
    krb5_const krb5_data *datap;
    char		*outstring;

    /*
     * First flatten the name.
     */
    current = rule;
    if (!(kret = krb5_unparse_name(context, aname, &fprincname))) {
	/*
	 * First part.
	 */
	if (*current == '[') {
	    if (sscanf(current+1,"%d:", &num_comps) == 1) {
		if (num_comps == aname->length) {
		    /*
		     * We have a match based on the number of components.
		     */
		    current = strchr(current, ':');
		    selstring = (char *) malloc(MAX_FORMAT_BUFFER);
		    selstring_used = 0;
		    if (current && selstring) {
			current++;
			cout = selstring;
			/*
			 * Plow through the string.
			 */
			while ((*current != ']') &&
			       (*current != '\0')) {
			    /*
			     * Expand to a component.
			     */
			    if (*current == '$') {
				if ((sscanf(current+1, "%d", &compind) == 1) &&
				    (compind <= num_comps) &&
				    (datap =
				     (compind > 0)
				     ? krb5_princ_component(context, aname,
							    compind-1)
				     : krb5_princ_realm(context, aname))
				    ) {
				    if ((datap->length < MAX_FORMAT_BUFFER)
					&&  (selstring_used+datap->length
					     < MAX_FORMAT_BUFFER)) {
					selstring_used += datap->length;
				    } else {
					kret = ENOMEM;
					goto errout;
				    }
				    strncpy(cout,
					    datap->data,
					    (unsigned) datap->length);
				    cout += datap->length;
				    *cout = '\0';
				    current++;
				    /* Point past number */
				    while (isdigit((int) (*current)))
					current++;
				}
				else
				    kret = KRB5_CONFIG_BADFORMAT;
			    }
			    else {
				/* Copy in verbatim. */
				*cout = *current;
				cout++;
				*cout = '\0';
				current++;
			    }
			}

			/*
			 * Advance past separator if appropriate.
			 */
			if (*current == ']')
			    current++;
			else
			    kret = KRB5_CONFIG_BADFORMAT;

			errout: if (kret)
			    free(selstring);
		    }
		}
		else
		    kret = KRB5_LNAME_NOTRANS;
	    }
	    else
		kret = KRB5_CONFIG_BADFORMAT;
	}
	else {
	    if (!(selstring = aname_full_to_mapping_name(fprincname)))
		kret = ENOMEM;
	}
	krb5_xfree(fprincname);
    }
    if (!kret) {
	/*
	 * Second part
	 */
	if (*current == '(')
	    kret = aname_do_match(selstring, &current);

	/*
	 * Third part.
	 */
	if (!kret) {
	    outstring = (char *) NULL;
	    kret = aname_replacer(selstring, &current, &outstring);
	    if (outstring) {
		/* Copy out the value if there's enough room */
		if (strlen(outstring)+1 <= (size_t) lnsize)
		    strcpy(lname, outstring);
		else
		    kret = KRB5_CONFIG_NOTENUFSPACE;
		free(outstring);
	    }
	}
	free(selstring);
    }

    return(kret);
}
#endif	/* AN_TO_LN_RULES */

/*
 * Solaris Kerberos
 * Return true (1) if the princ's realm matches any of the
 * 'auth_to_local_realm' relations in the default realm section.
 */
static int
an_to_ln_realm_chk(
	krb5_context context,
	krb5_const_principal aname,
	char *def_realm,
	int realm_length)
{
	char        **values, **cpp;
	const char  *realm_names[4];
	krb5_error_code     retval;

	realm_names[0] = "realms";
	realm_names[1] = def_realm;
	realm_names[2] = "auth_to_local_realm";
	realm_names[3] = 0;

	if (context->profile == 0)
		return (0);

	retval = profile_get_values(context->profile, realm_names,
				    &values);
	if (retval)
		return (0);

	for (cpp = values; *cpp; cpp++) {

		if (((size_t) realm_length == strlen(*cpp)) &&
		    (memcmp(*cpp, krb5_princ_realm(context, aname)->data,
			    realm_length) == 0)) {

			profile_free_list(values);
			return (1); /* success */
		}
	}

	profile_free_list(values);
	return (0);
}

/*
 * Implementation:  This version checks the realm to see if it is the local
 * realm; if so, and there is exactly one non-realm component to the name,
 * that name is returned as the lname.
 */
static krb5_error_code
default_an_to_ln(krb5_context context, krb5_const_principal aname, const unsigned int lnsize, char *lname)
{
    krb5_error_code retval;
    char *def_realm;
    unsigned int realm_length;

    realm_length = krb5_princ_realm(context, aname)->length;

    if ((retval = krb5_get_default_realm(context, &def_realm))) {
	return(retval);
    }
    /* Solaris Kerberos */
    /* compare against default realm and auth_to_local_realm(s) */
    if ((((size_t) realm_length != strlen(def_realm)) ||
        (memcmp(def_realm, krb5_princ_realm(context, aname)->data,
		realm_length))) &&
	!an_to_ln_realm_chk(context, aname, def_realm,
			    realm_length)) {
        free(def_realm);
        return KRB5_LNAME_NOTRANS;
    }

    if (krb5_princ_size(context, aname) != 1) {
        if (krb5_princ_size(context, aname) == 2 ) {
           /* Check to see if 2nd component is the local realm. */
           if ( strncmp(krb5_princ_component(context, aname,1)->data,def_realm,
                        realm_length) ||
                realm_length != krb5_princ_component(context, aname,1)->length) {
		    /* XXX an_to_ln_realm_chk ? */
		/* Solaris Kerberos */
		free(def_realm);
                return KRB5_LNAME_NOTRANS;
	    }
        }
        else {
           /* no components or more than one component to non-realm part of name
           --no translation. */
	    /* Solaris Kerberos */
	    free(def_realm);
            return KRB5_LNAME_NOTRANS;
	}
    }

    free(def_realm);
    strncpy(lname, krb5_princ_component(context, aname,0)->data,
	    min(krb5_princ_component(context, aname,0)->length,lnsize));
    if (lnsize <= krb5_princ_component(context, aname,0)->length ) {
	retval = KRB5_CONFIG_NOTENUFSPACE;
    } else {
	lname[krb5_princ_component(context, aname,0)->length] = '\0';
	retval = 0;
    }
    return retval;
}

/*
 Converts an authentication name to a local name suitable for use by
 programs wishing a translation to an environment-specific name (e.g.
 user account name).

 lnsize specifies the maximum length name that is to be filled into
 lname.
 The translation will be null terminated in all non-error returns.

 returns system errors, NOT_ENOUGH_SPACE
*/

krb5_error_code KRB5_CALLCONV
krb5_aname_to_localname(krb5_context context, krb5_const_principal aname, const int lnsize_in, char *lname)
{
    krb5_error_code	kret;
    char		*realm;
    char		*pname;
    char		*mname;
    const char		*hierarchy[5];
    char		**mapping_values;
    int			i, nvalid;
    char		*cp, *s;
    char		*typep, *argp;
    unsigned int        lnsize;

    if (lnsize_in < 0)
      return KRB5_CONFIG_NOTENUFSPACE;

    lnsize = lnsize_in; /* Unsigned */

    /*
     * First get the default realm.
     */
    if (!(kret = krb5_get_default_realm(context, &realm))) {
	/* Flatten the name */
	if (!(kret = krb5_unparse_name(context, aname, &pname))) {
	    if ((mname = aname_full_to_mapping_name(pname))) {
		/*
		 * Search first for explicit mappings of the form:
		 *
		 * [realms]->realm->"auth_to_local_names"->mapping_name
		 */
		hierarchy[0] = "realms";
		hierarchy[1] = realm;
		hierarchy[2] = "auth_to_local_names";
		hierarchy[3] = mname;
		hierarchy[4] = (char *) NULL;
		if (!(kret = profile_get_values(context->profile,
						hierarchy,
						&mapping_values))) {
		    /* We found one or more explicit mappings. */
		    for (nvalid=0; mapping_values[nvalid]; nvalid++);

		    /* Just use the last one. */
		    /* Trim the value. */
		    s = mapping_values[nvalid-1];
		    cp = s + strlen(s);
		    while (cp > s) {
			cp--;
			if (!isspace((int)(*cp)))
			    break;
			*cp = '\0';
		    }

		    /* Copy out the value if there's enough room */
		    if (strlen(mapping_values[nvalid-1])+1 <= (size_t) lnsize)
			strcpy(lname, mapping_values[nvalid-1]);
		    else
			kret = KRB5_CONFIG_NOTENUFSPACE;

		    /* Free residue */
		    profile_free_list(mapping_values);
		}
		else {
		    /*
		     * OK - There's no explicit mapping.  Now check for
		     * general auth_to_local rules of the form:
		     *
		     * [realms]->realm->"auth_to_local"
		     *
		     * This can have one or more of the following kinds of
		     * values:
		     *	DB:<filename>	- Look up principal in aname database.
		     *	RULE:<sed-exp>	- Formulate lname from sed-exp.
		     *	DEFAULT		- Use default rule.
		     * The first rule to find a match is used.
		     */
		    hierarchy[0] = "realms";
		    hierarchy[1] = realm;
		    hierarchy[2] = "auth_to_local";
		    hierarchy[3] = (char *) NULL;
		    if (!(kret = profile_get_values(context->profile,
						    hierarchy,
						    &mapping_values))) {
			/*
			 * Loop through all the mapping values.
			 */
			for (i=0; mapping_values[i]; i++) {
			    typep = mapping_values[i];
			    argp = strchr(typep, ':');
			    if (argp) {
				*argp = '\0';
				argp++;
			    }
#ifdef ANAME_DB
			    if (!strcmp(typep, "DB") && argp) {
				kret = db_an_to_ln(context,
						   argp,
						   aname,
						   lnsize,
						   lname);
				if (kret != KRB5_LNAME_NOTRANS)
				    break;
			    }
			    else
#endif
#ifdef	AN_TO_LN_RULES
			    if (!strcmp(typep, "RULE") && argp) {
				kret = rule_an_to_ln(context,
						     argp,
						     aname,
						     lnsize,
						     lname);
				if (kret != KRB5_LNAME_NOTRANS)
				    break;
			    }
			    else
#endif	/* AN_TO_LN_RULES */
			    if (!strcmp(typep, "DEFAULT") && !argp) {
				kret = default_an_to_ln(context,
							aname,
							lnsize,
							lname);
				if (kret != KRB5_LNAME_NOTRANS)
				    break;
			    }
			    else {
				kret = KRB5_CONFIG_BADFORMAT;
				break;
			    }
			}

			/* We're done, clean up the droppings. */
			profile_free_list(mapping_values);
		    }
		    else {
			/*
			 * No profile relation found, try default mapping.
			 */
			kret = default_an_to_ln(context,
						aname,
						lnsize,
						lname);
		    }
		}
		free(mname);
	    }
	    else
		kret = ENOMEM;
	    krb5_xfree(pname);
	}
	krb5_xfree(realm);
    }
    return(kret);
}

