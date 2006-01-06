/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

/*
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "synonyms.h"
#include "mtlib.h"
#include <ctype.h>
#include <locale.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <libintl.h>
#include <thread.h>
#include <synch.h>
#include <limits.h>
#include <unistd.h>
#include "libc.h"
#include "_loc_path.h"
#include "msgfmt.h"
#include "gettext.h"
#include "nlspath_checks.h"

static int	process_nlspath(const char *, const char *,
	const char *, char **);
static char *replace_nls_option(char *, const char *, char *,
	char *, char *, char *, char *);
static char *key_2_text(Msg_s_node *, const char *);
static char *handle_mo(struct cache_pack *, struct msg_pack *);
static void	mini_strcpy(char *, const char *);
static size_t	mini_strlen(const char *);

char *
_real_gettext_u(const char *domain,
	const char *msgid1, const char *msgid2,
	unsigned long int ln, int category,
	int plural)
{
	char	msgfile[MAXPATHLEN]; 	/* 1024 */
	char	binding[MAXPATHLEN]; 	/* 1024 */
	char	mydomain[TEXTDOMAINMAX + 1]; /* 256 + 1 */
	char	*cur_binding;	/* points to current binding in list */
	char	*bptr, *cur_locale, *cur_domain, *result, *nlspath;
	char	*locale, *msgloc, *cb, *cur_domain_binding;
	char	*language;
	int	n = (unsigned int)ln;	/* we don't need long for n */
	size_t	cblen, cur_locale_len, cur_domain_len;
	unsigned int	hash_locale;

	struct msg_pack	*mp, omp;
	struct cache_pack	*cp, ocp;

#ifdef GETTEXT_DEBUG
	(void) printf("*************** _real_gettext_u(%s, %s, "
		"%s, %d, %d, %d)\n",
	    domain ? domain : "NULL", msgid1 ? msgid1 : "NULL",
		msgid2 ? msgid2 : "NULL", n, category, plural);
#endif

	if (msgid1 == NULL)
		return (NULL);

	cp = memset(&ocp, 0, sizeof (ocp));	/* cache pack */
	mp = memset(&omp, 0, sizeof (omp));	/* msg pack */

	/*
	 * category may be LC_MESSAGES or LC_TIME
	 * locale contains the value of 'category'
	 * hash_locale contains the hash value of locale
	 * msgloc contains the value of LC_MESSAGES
	 * hash_msgloc contains the hash value of msgloc
	 */
	locale = setlocale(category, NULL);
	hash_locale = get_hashid(locale, &cur_locale_len);

	/*
	 * content of locale will be overridden by
	 * succeeding setlocale invocation.
	 * So, duplicate it
	 */
	cur_locale = (char *)malloc(cur_locale_len + 1);
	if (!cur_locale) {
		DFLTMSG(result, msgid1, msgid2, n, plural);
		return (result);
	}
	mini_strcpy(cur_locale, locale);

	language = getenv("LANGUAGE"); /* for GNU */
	if (language) {
		if (!*language || strchr(language, '/') != NULL) {
			/*
			 * LANGUAGE is an empty string or
			 * LANGUAGE contains '/'.
			 * Ignore it.
			 */
			language = NULL;
		}
	}

	/*
	 * Query the current domain if domain argument is NULL pointer
	 */
	mydomain[0] = '\0';
	if (!domain) {
		/*
		 * if NULL is specified for domainname,
		 * use the currently bound domain.
		 */
		cur_domain = _textdomain_u(NULL, mydomain);
		cur_domain_len = mini_strlen(cur_domain);
	} else if (!*domain) {
		/*
		 * if an empty string is specified
		 */
		cur_domain = DEFAULT_DOMAIN;
		cur_domain_len = DEFAULT_DOMAIN_LEN;
	} else {
		cur_domain_len = mini_strlen(domain);
		if (cur_domain_len > TEXTDOMAINMAX) {
			/* domain is invalid, return msg_id */
			free(cur_locale);
			DFLTMSG(result, msgid1, msgid2, n, plural);
			return (result);
		}
		cur_domain = (char *)domain;
	}

	nlspath = getenv("NLSPATH"); /* get the content of NLSPATH */
	if (!nlspath || !*nlspath) {
		/* no NLSPATH is defined in the environ */
		if ((*cur_locale == 'C') && (*(cur_locale + 1) == '\0')) {
			/*
			 * If C locale,
			 * return the original msgid immediately.
			 */
			free(cur_locale);
			DFLTMSG(result, msgid1, msgid2, n, plural);
			return (result);
		}
		nlspath = NULL;
	} else {
		/* NLSPATH is set */
		int	ret;

		msgloc = setlocale(LC_MESSAGES, NULL);

		ret = process_nlspath(cur_domain, msgloc,
			(const char *)nlspath, &cur_binding);
		if (ret == -1) {
			/* error occurred */
			free(cur_locale);
			DFLTMSG(result, msgid1, msgid2, n, plural);
			return (result);
		} else if (ret == 0) {
			nlspath = NULL;
		}
	}

	cur_domain_binding = _real_bindtextdomain_u(cur_domain,
		NULL, TP_BINDING);
	if (!cur_domain_binding) {
		free(cur_locale);
		DFLTMSG(result, msgid1, msgid2, n, plural);
		return (result);
	}

	mp->msgid1 = msgid1;
	mp->msgid2 = msgid2;
	mp->msgfile = msgfile;
	mp->domain = cur_domain;
	mp->binding = cur_domain_binding;
	mp->locale = cur_locale;
	mp->language = language;
	mp->locale_len = cur_locale_len;
	mp->domain_len = cur_domain_len;
	mp->n = n;
	mp->category = category;
	mp->plural = plural;
	mp->hash_locale = hash_locale;

	/*
	 * Spec1170 requires that we use NLSPATH if it's defined, to
	 * override any system default variables.  If NLSPATH is not
	 * defined or if a message catalog is not found in any of the
	 * components (bindings) specified by NLSPATH, dcgettext_u() will
	 * search for the message catalog in either a) the binding path set
	 * by any previous application calls to bindtextdomain() or
	 * b) the default binding path (/usr/lib/locale).  Save the original
	 * binding path so that we can search it if the message catalog
	 * is not found via NLSPATH.  The original binding is restored before
	 * returning from this routine because the gettext routines should
	 * not change the binding set by the application.  This allows
	 * bindtextdomain() to be called once for all gettext() calls in the
	 * application.
	 */

	/*
	 * First, examine NLSPATH
	 */
	bptr = binding;
	if (nlspath) {
		/*
		 * NLSPATH binding has been successfully built
		 */
#ifdef GETTEXT_DEBUG
		(void) printf("************************** examining NLSPATH\n");
		(void) printf("       cur_binding: \"%s\"\n",
			cur_binding ? cur_binding : "(null)");
#endif

		mp->nlsp = 1;
		/*
		 * cur_binding always ends with ':' before a null
		 * termination.
		 */
		while (*cur_binding) {
			cb = cur_binding;
			while (*cur_binding != ':')
				cur_binding++;
			cblen = cur_binding - cb;
			cur_binding++;
			if (cblen >= MAXPATHLEN) {
				/* cur_binding too long */
				free(cur_locale);
				DFLTMSG(result, msgid1, msgid2, n, plural);
				return (result);
			}
			(void) memcpy(bptr, cb, cblen);
			*(bptr + cblen) = '\0';

			(void) memcpy(mp->msgfile, bptr, cblen + 1);
			mp->msgfile_len = cblen;
#ifdef GETTEXT_DEBUG
			(void) printf("*******************"
				"********************* \n");
			(void) printf("       msgfile: \"%s\"\n",
				msgfile ? msgfile : "(null)");
			(void) printf("*******************"
				"********************* \n");
#endif
			result = handle_mo(cp, mp);
			if (result) {
				free(cur_locale);
				return (result);
			}
		}
	}

	mp->nlsp = 0;
	mp->binding = cur_domain_binding;
	/*
	 * Next, examine LANGUAGE
	 */
	if (language) {
		char	*ret_msg;
		ret_msg = handle_lang(cp, mp);
		if (ret_msg != NULL) {
			/*
			 * GNU MO found
			 */
			free(cur_locale);
			return (ret_msg);
		}
		/*
		 * handle_lang() may have overridden
		 * locale and hash_locale
		 */
		mp->locale = cur_locale;
		mp->locale_len = cur_locale_len;
		mp->hash_locale = hash_locale;
	}

	/*
	 * Finally, handle a single binding
	 */
#ifdef GETTEXT_DEBUG
	*mp->msgfile = '\0';
#endif
	if (mk_msgfile(mp) == NULL) {
		free(cur_locale);
		DFLTMSG(result, msgid1, msgid2, n, plural);
		return (result);
	}

	result = handle_mo(cp, mp);
	free(cur_locale);
	if (result) {
		return (result);
	}
	DFLTMSG(result, msgid1, msgid2, n, plural);
	return (result);
} /* _real_gettext_u */

#define	ALLFREE	\
	free_all(nlstmp, nnp, pathname, ppaths, lang, cacheline, cnp)

static void
free_all(Nlstmp *nlstmp, Nls_node *nnp, char *pathname,
	char *ppaths, char *lang, int cacheline, Cache_node *cnp)
{
	Nlstmp	*tp, *tq;

	tp = nlstmp;
	while (tp) {
		tq = tp->next;
		free(tp);
		tp = tq;
	}
	if (nnp->locale)
		free(nnp->locale);
	if (nnp->domain)
		free(nnp->domain);
	if (pathname)
		free(pathname);
	if (ppaths)
		free(ppaths);
	if (lang)
		free(lang);
	if (!cacheline)
		free(cnp);
	free(nnp);
}

/*
 * process_nlspath(): process the NLSPATH environment variable.
 *
 *		this routine looks at NLSPATH in the environment,
 *		and will try to build up the binding list based
 *		on the settings of NLSPATH.
 *
 * RETURN:
 * -1:  Error occurred
 *  0:  No error, but no binding list has been built
 *  1:  No error, and a binding list has been built
 *
 */
static int
process_nlspath(const char *cur_domain, const char *cur_msgloc,
	const char *nlspath, char **binding)
{
	char 	*s;				/* generic string ptr */
	char	*territory;		/* our current territory element */
	char	*codeset;		/* our current codeset element */
	char	*s1;			/* for handling territory */
	char	*s2;			/* for handling codeset */
	char	*lang = NULL;	/* our current language element */
	char	*ppaths = NULL;	/* ptr to all of the templates */
	char	*pathname = NULL;	/* the full pathname to the file */
	unsigned int	hashid;
	size_t	nlspath_len, domain_len, locale_len, path_len;
	size_t	ppaths_len = 0;
	int	cacheline = 0;
	Nlstmp	*nlstmp = NULL;
	Nlstmp	*pnlstmp, *qnlstmp;
	Cache_node	*cnp;
	Nls_node	*cur_nls, *nnp = NULL;
	Gettext_t	*gt = global_gt;

#ifdef GETTEXT_DEBUG
	(void) printf("*************** process_nlspath(%s, %s, "
		"%s, 0x%p)\n", cur_domain,
	    cur_msgloc, nlspath, (void *)binding);
#endif

	cur_nls = gt->c_n_node;
	if (cur_nls &&
		(strcmp(cur_nls->domain, cur_domain) == 0 &&
		strcmp(cur_nls->locale, cur_msgloc) == 0 &&
		strcmp(cur_nls->nlspath, nlspath) == 0)) {
		*binding = cur_nls->ppaths;
		return (1);
	}

	hashid = get_hashid(cur_msgloc, NULL);

	cnp = gt->c_node;
	while (cnp) {
		if (cnp->hashid == hashid) {
			nnp = cnp->n_node;
			cacheline = 1;
			while (nnp) {
				if (strcmp(nnp->locale, cur_msgloc) == 0 &&
					strcmp(nnp->domain, cur_domain) == 0 &&
					strcmp(nnp->nlspath, nlspath) == 0) {
					gt->c_n_node = nnp;
					*binding = nnp->ppaths;
					return (1);
				}
				nnp = nnp->next;
			}
			break;
		} else {
			cnp = cnp->next;
		}
	}

	if (cacheline) {
		nnp = (Nls_node *)calloc(1, sizeof (Nls_node));
		if (!nnp) {
			ALLFREE;
			return (-1);
		}
	} else {
		cnp = (Cache_node *)calloc(1, sizeof (Cache_node));
		if (!cnp) {
			ALLFREE;
			return (-1);
		}
		cnp->hashid = hashid;
		nnp = (Nls_node *)calloc(1, sizeof (Nls_node));
		if (!nnp) {
			ALLFREE;
			return (-1);
		}
		cnp->n_node = nnp;
		cnp->n_last = nnp;
	}

	nlspath_len = strlen(nlspath);
	locale_len = strlen(cur_msgloc);
	domain_len = strlen(cur_domain);

	/*
	 * nlspath_len, locale_len, and domain_len
	 * are including a null termination.
	 */
	nlspath_len++;
	locale_len++;
	domain_len++;

	lang = NULL;
	territory = NULL;
	codeset = NULL;

	if (cur_msgloc) {
		lang = s = strdup(cur_msgloc);
		if (lang == NULL) {
			ALLFREE;
			return (-1);
		}
		s1 = s2 = NULL;
		while (s && *s) {
			if (*s == '_') {
				s1 = s;
				*s1++ = '\0';
			} else if (*s == '.') {
				s2 = s;
				*s2++ = '\0';
			}
			s++;
		}
		territory = s1;
		codeset = s2;
	}

	/*
	 * now that we have the name (domain), we first look through NLSPATH,
	 * in an attempt to get the locale. A locale may be completely
	 * specified as "language_territory.codeset". NLSPATH consists
	 * of templates separated by ":" characters. The following are
	 * the substitution values within NLSPATH:
	 *	%N = DEFAULT_DOMAIN
	 *	%L = The value of the LC_MESSAGES category.
	 *	%I = The language element from the LC_MESSAGES category.
	 *	%t = The territory element from the LC_MESSAGES category.
	 *	%c = The codeset element from the LC_MESSAGES category.
	 *	%% = A single character.
	 * if we find one of these characters, we will carry out the
	 * appropriate substitution.
	 */
	pathname = (char *)malloc(MAXPATHLEN);
	if (pathname == NULL) {
		ALLFREE;
		return (-1);
	}
	s = (char *)nlspath;		/* s has a content of NLSPATH */
	while (*s) {				/* march through NLSPATH */
		(void) memset(pathname, 0, MAXPATHLEN);
		if (*s == ':') {
			/*
			 * this loop only occurs if we have to replace
			 * ":" by "name". replace_nls_option() below
			 * will handle the subsequent ":"'s.
			 */
			pnlstmp = (Nlstmp *)malloc(sizeof (Nlstmp));
			if (!pnlstmp) {
				ALLFREE;
				return (-1);
			}

			(void) memcpy(pnlstmp->pathname, cur_domain,
				domain_len);
			ppaths_len += domain_len;

			pnlstmp->next = NULL;

			if (!nlstmp) {
				nlstmp = pnlstmp;
				qnlstmp = pnlstmp;
			} else {
				qnlstmp->next = pnlstmp;
				qnlstmp = pnlstmp;
			}

			++s;
			continue;
		}
		/* replace Substitution field */
		s = replace_nls_option(s, cur_domain, pathname,
			(char *)cur_msgloc, lang, territory, codeset);

		if (s == NULL) {
			ALLFREE;
			return (-1);
		}

		/* if we've found a valid file: */
		if (*pathname) {
			/* add template to end of chain of pathnames: */
			pnlstmp = (Nlstmp *)malloc(sizeof (Nlstmp));
			if (!pnlstmp) {
				ALLFREE;
				return (-1);
			}

			path_len = strlen(pathname) + 1;
			(void) memcpy(pnlstmp->pathname, pathname,
				path_len);
			ppaths_len += path_len;

			pnlstmp->next = NULL;

			if (!nlstmp) {
				nlstmp = pnlstmp;
				qnlstmp = pnlstmp;
			} else {
				qnlstmp->next = pnlstmp;
				qnlstmp = pnlstmp;
			}
		}
		if (*s) {
			++s;
		}
	}
	/*
	 * now that we've handled the pathname templates, concatenate them
	 * all into the form "template1:template2:..." for _bindtextdomain_u()
	 */

	if (ppaths_len != 0) {
		ppaths = (char *)malloc(ppaths_len + 1);
		if (!ppaths) {
			ALLFREE;
			return (-1);
		}
		*ppaths = '\0';
	} else {
		ALLFREE;
		return (0);
	}

	/*
	 * extract the path templates (fifo), and concatenate them
	 * all into a ":" separated string for _bindtextdomain_u()
	 */
	pnlstmp = nlstmp;
	while (pnlstmp) {
		(void) strcat(ppaths, pnlstmp->pathname);
		(void) strcat(ppaths, ":");
		qnlstmp = pnlstmp->next;
		free(pnlstmp);
		pnlstmp = qnlstmp;
	}
	nlstmp = NULL;

	nnp->domain = (char *)malloc(domain_len);
	if (!nnp->domain) {
		ALLFREE;
		return (-1);
	} else {
		(void) memcpy(nnp->domain, cur_domain, domain_len);
	}
	nnp->locale = (char *)malloc(locale_len);
	if (!nnp->locale) {
		ALLFREE;
		return (-1);
	} else {
		(void) memcpy(nnp->locale, cur_msgloc, locale_len);
	}
	nnp->nlspath = (char *)malloc(nlspath_len);
	if (!nnp->nlspath) {
		ALLFREE;
		return (-1);
	} else {
		(void) memcpy(nnp->nlspath, nlspath, nlspath_len);
	}
	nnp->ppaths = ppaths;
	nnp->next = NULL;

	if (cacheline) {
		if (cnp->n_last)
			cnp->n_last->next = nnp;
		else
			cnp->n_node = nnp;
		cnp->n_last = nnp;
	} else {
		if (gt->c_last)
			gt->c_last->next = cnp;
		else
			gt->c_node = cnp;
		gt->c_last = cnp;
	}
	gt->c_n_node = nnp;

	free(pathname);
	free(lang);
#ifdef GETTEXT_DEBUG
	(void) printf("*************** existing process_nlspath "
		"with success\n");
	(void) printf("       binding: \"%s\"\n", ppaths);
#endif
	*binding = ppaths;
	return (1);
}


/*
 * This routine will replace substitution parameters in NLSPATH
 * with appropiate values.
 */
static char *
replace_nls_option(char *s, const char *name, char *pathname,
	char *locale, char *lang, char *territory, char *codeset)
{
	char	*t, *u;
	char	*limit;

	t = pathname;
	limit = pathname + MAXPATHLEN - 1;

	while (*s && *s != ':') {
		if (t < limit) {
			/*
			 * %% is considered a single % character (XPG).
			 * %L : LC_MESSAGES (XPG4) LANG(XPG3)
			 * %l : The language element from the current locale.
			 *	(XPG3, XPG4)
			 */
			if (*s != '%')
				*t++ = *s;
			else if (*++s == 'N') {
				if (name) {
					u = (char *)name;
					while (*u && (t < limit))
						*t++ = *u++;
				}
			} else if (*s == 'L') {
				if (locale) {
					u = locale;
					while (*u && (t < limit))
						*t++ = *u++;
				}
			} else if (*s == 'l') {
				if (lang) {
					u = lang;
					while (*u && (*u != '_') &&
						(t < limit))
						*t++ = *u++;
				}
			} else if (*s == 't') {
				if (territory) {
					u = territory;
					while (*u && (*u != '.') &&
						(t < limit))
						*t++ = *u++;
				}
			} else if (*s == 'c') {
				if (codeset) {
					u = codeset;
					while (*u && (t < limit))
						*t++ = *u++;
				}
			} else {
				if (t < limit)
					*t++ = *s;
			}
		} else {
			/* too long pathname */
			return (NULL);
		}
		++s;
	}
	*t = '\0';
	return (s);
}


char *
_real_bindtextdomain_u(const char *domain, const char *binding,
	int type)
{
	struct domain_binding	*bind, *prev;
	Gettext_t	*gt = global_gt;
	char	**binding_addr;

#ifdef GETTEXT_DEBUG
	(void) printf("*************** _real_bindtextdomain_u(%s, %s, %s)\n",
		(domain ? domain : ""),
		(binding ? binding : ""),
		(type == TP_BINDING) ? "TP_BINDING" : "TP_CODESET");
#endif

	/*
	 * If domain is a NULL pointer, no change will occur regardless
	 * of binding value. Just return NULL.
	 */
	if (!domain) {
		return (NULL);
	}

	/*
	 * Global Binding is not supported any more.
	 * Just return NULL if domain is NULL string.
	 */
	if (*domain == '\0') {
		return (NULL);
	}

	/* linear search for binding, rebind if found, add if not */
	bind = FIRSTBIND(gt);
	prev = NULL;	/* Two pointers needed for pointer operations */

	while (bind) {
		if (strcmp(domain, bind->domain) == 0) {
			/*
			 * Domain found.
			 */
			binding_addr = (type == TP_BINDING) ? &(bind->binding) :
				&(bind->codeset);
			if (!binding) {
				/*
				 * if binding is null, then query
				 */
				return (*binding_addr);
			}
			/* replace existing binding with new binding */
			if (*binding_addr) {
				free(*binding_addr);
			}
			if ((*binding_addr = strdup(binding)) == NULL) {
				return (NULL);
			}
#ifdef GETTEXT_DEBUG
			printlist();
#endif
			return (*binding_addr);
		}
		prev = bind;
		bind = bind->next;
	} /* while (bind) */

	/* domain has not been found in the list at this point */
	if (binding) {
		/*
		 * domain is not found, but binding is not NULL.
		 * Then add a new node to the end of linked list.
		 */

		if ((bind = (Dbinding *)malloc(sizeof (Dbinding))) == NULL) {
			return (NULL);
		}
		if ((bind->domain = strdup(domain)) == NULL) {
			free(bind);
			return (NULL);
		}
		bind->binding = NULL;
		bind->codeset = NULL;
		binding_addr = (type == TP_BINDING) ? &(bind->binding) :
			&(bind->codeset);
		if ((*binding_addr = strdup(binding)) == NULL) {
			free(bind->domain);
			free(bind);
			return (NULL);
		}
		bind->next = NULL;

		if (prev) {
			/* reached the end of list */
			prev->next = bind;
		} else {
			/* list was empty */
			FIRSTBIND(gt) = bind;
		}

#ifdef GETTEXT_DEBUG
		printlist();
#endif
		return (*binding_addr);
	} else {
		/*
		 * Query of domain which is not found in the list
		 * for bindtextdomain, returns defaultbind
		 * for bind_textdomain_codeset, returns NULL
		 */
		if (type == TP_BINDING) {
			return ((char *)defaultbind);
		} else {
			return (NULL);
		}
	} /* if (binding) */

	/* Must not reach here */

} /* _real_bindtextdomain_u */


char *
_textdomain_u(const char *domain, char *result)
{
	char	*p;
	size_t	domain_len;
	Gettext_t	*gt = global_gt;

#ifdef GETTEXT_DEBUG
	(void) printf("*************** _textdomain_u(\"%s\", 0x%p)\n",
		(domain ? domain : ""), (void *)result);
#endif

	/* Query is performed for NULL domain pointer */
	if (domain == NULL) {
		mini_strcpy(result, CURRENT_DOMAIN(gt));
		return (result);
	}

	/* check for error. */
	/*
	 * domain is limited to TEXTDOMAINMAX bytes
	 * excluding a null termination.
	 */
	domain_len = mini_strlen(domain);
	if (domain_len > TEXTDOMAINMAX) {
		/* too long */
		return (NULL);
	}

	/*
	 * Calling textdomain() with a null domain string sets
	 * the domain to the default domain.
	 * If non-null string is passwd, current domain is changed
	 * to the new domain.
	 */

	/* actually this if clause should be protected from signals */
	if (*domain == '\0') {
		if (CURRENT_DOMAIN(gt) != default_domain) {
			free(CURRENT_DOMAIN(gt));
			CURRENT_DOMAIN(gt) = (char *)default_domain;
		}
	} else {
		p = (char *)malloc(domain_len + 1);
		if (!p)
			return (NULL);
		mini_strcpy(p, domain);
		if (CURRENT_DOMAIN(gt) != default_domain)
			free(CURRENT_DOMAIN(gt));
		CURRENT_DOMAIN(gt) = p;
	}

	mini_strcpy(result, CURRENT_DOMAIN(gt));
	return (result);
} /* _textdomain_u */

/*
 * key_2_text() translates msd_id into target string.
 */
static char *
key_2_text(Msg_s_node *messages, const char *key_string)
{
	int	val;
	char	*msg_id_str;
	unsigned char	kc = *(unsigned char *)key_string;
	struct msg_struct	*check_msg_list;

#ifdef GETTEXT_DEBUG
	(void) printf("*************** key_2_text(0x%p, \"%s\")\n",
		(void *)messages, key_string ? key_string : "(null)");
	printsunmsg(messages, 0);
#endif

	check_msg_list = messages->msg_list +
		messages->msg_file_info->msg_mid;
	for (;;) {
		msg_id_str = messages->msg_ids +
			check_msg_list->msgid_offset;
		/*
		 * To maintain the compatibility with Zeus mo file,
		 * msg_id's are stored in descending order.
		 * If the ascending order is desired, change "msgfmt.c"
		 * and switch msg_id_str and key_string in the following
		 * strcmp() statement.
		 */
		val = *(unsigned char *)msg_id_str - kc;
		if ((val == 0) &&
			(val = strcmp(msg_id_str, key_string)) == 0) {
			return (messages->msg_strs
				+ check_msg_list->msgstr_offset);
		} else if (val < 0) {
			if (check_msg_list->less != LEAFINDICATOR) {
				check_msg_list = messages->msg_list +
					check_msg_list->less;
				continue;
			}
			return ((char *)key_string);
		} else {
			/* val > 0 */
			if (check_msg_list->more != LEAFINDICATOR) {
				check_msg_list = messages->msg_list +
					check_msg_list->more;
				continue;
			}
			return ((char *)key_string);
		}
	}
}

static char *
handle_type_mo(struct cache_pack *cp, struct msg_pack *mp)
{
	char	*result;

	switch (cp->mnp->type) {
	case T_ILL_MO:
		return (NULL);
	case T_SUN_MO:
		if (mp->plural) {
			/*
			 * *ngettext is called against
			 * Sun MO file
			 */
			int	exp = (mp->n == 1);
			result = (char *)mp->msgid1;
			if (!exp)
				result = (char *)mp->msgid2;
			return (result);
		}
		result = key_2_text(cp->mnp->msg.sunmsg, mp->msgid1);
		if (!cp->mnp->trusted) {
			result = check_format(mp->msgid1, result, 0);
		}
		return (result);
	case T_GNU_MO:
		if (mp->language) {
			/*
			 * LANGUAGE has been set.
			 * Failed to find out a valid GNU MO in
			 * handle_lang() using LANGUAGE.
			 * Now found a valid GNU MO. But, gettext()
			 * needs to default-return.
			 */
			DFLTMSG(result, mp->msgid1, mp->msgid2,
				mp->n, mp->plural);
			return (result);
		}
		result = gnu_key_2_text(cp->mnp->msg.gnumsg,
			get_codeset(mp->domain), mp);
		if (!cp->mnp->trusted) {
			result = check_format(mp->msgid1, result, 0);
			if (result == mp->msgid1) {
				DFLTMSG(result, mp->msgid1, mp->msgid2,
					mp->n, mp->plural);
			}
		}
		return (result);
	default:
		/* this should never happen */
		return (NULL);
	}
	/* NOTREACHED */
}

static char *
handle_mo(struct cache_pack *cp, struct msg_pack *mp)
{
	int	fd, ret;
	char	*result;
	struct stat64	statbuf;
	Gettext_t	*gt = global_gt;

#ifdef GETTEXT_DEBUG
	(void) printf("*************** handle_mo(0x%p, 0x%p)\n",
		(void *)cp, (void *)mp);
	printcp(cp, 0);
	printmp(mp, 0);
#endif

	/*
	 * At this point, msgfile contains full path for
	 * domain.
	 * Look up cache entry first. If cache misses,
	 * then search domain look-up table.
	 */

	ret = check_cache(cp, mp);

	if (ret) {
		/* cache found */
		gt->c_m_node = cp->mnp;
		return (handle_type_mo(cp, mp));
	}
	/*
	 * Valid entry not found in the cache
	 */
	fd = nls_safe_open(mp->msgfile, &statbuf, &mp->trusted,
			!mp->nlsp);
	if ((fd == -1) || (statbuf.st_size > LONG_MAX)) {
		if (connect_invalid_entry(cp, mp) == -1) {
			DFLTMSG(result, mp->msgid1, mp->msgid2,
				mp->n, mp->plural);
			return (result);
		}
		return (NULL);
	}
	mp->fsz = (size_t)statbuf.st_size;
	mp->addr = mmap(0, mp->fsz, PROT_READ, MAP_SHARED, fd, 0);
	(void) close(fd);

	if (mp->addr == (caddr_t)-1) {
		if (connect_invalid_entry(cp, mp) == -1) {
			DFLTMSG(result, mp->msgid1, mp->msgid2,
				mp->n, mp->plural);
			return (result);
		}
		return (NULL);
	}

	cp->mnp = create_mnp(mp);
	if (!cp->mnp) {
		free_mnp_mp(cp->mnp, mp);
		DFLTMSG(result, mp->msgid1, mp->msgid2, mp->n, mp->plural);
		return (result);
	}

	if (setmsg(cp->mnp, (char *)mp->addr, mp->fsz) == -1) {
		free_mnp_mp(cp->mnp, mp);
		(void) munmap(mp->addr, mp->fsz);
		DFLTMSG(result, mp->msgid1, mp->msgid2, mp->n, mp->plural);
		return (result);
	}
	if (!cp->cacheline) {
		cp->cnp = create_cnp(cp->mnp, mp);
		if (!cp->cnp) {
			free_mnp_mp(cp->mnp, mp);
			(void) munmap(mp->addr, mp->fsz);
			DFLTMSG(result, mp->msgid1, mp->msgid2,
				mp->n, mp->plural);
			return (result);
		}
	}
	cp->mnp->trusted = mp->trusted;
	connect_entry(cp);

	return (handle_type_mo(cp, mp));
	/* NOTREACHED */
}

static void
mini_strcpy(char *dst, const char *src)
{
	const char	*p = (const char *)src;
	char	*q = dst;
	while (*q++ = *p++)
		;
}

static size_t
mini_strlen(const char *str)
{
	const char	*p = (const char *)str;
	size_t	len;

	while (*p)
		p++;
	len = (size_t)(p - str);
	return (len);
}
