/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright 2015 Joyent, Inc.
 */

#include "lint.h"
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
static char	*replace_nls_option(char *, const char *, char *,
    char *, char *, char *, char *);

char *
_real_gettext_u(const char *domain, const char *msgid1, const char *msgid2,
    unsigned long int ln, int category, int plural, locale_t loc)
{
	char	msgfile[MAXPATHLEN]; 	/* 1024 */
	char	mydomain[TEXTDOMAINMAX + 1]; /* 256 + 1 */
	char	*cur_binding;	/* points to current binding in list */
	const char *cur_locale;
	char	*cur_domain, *result, *nlspath;
	char	*msgloc, *cb, *cur_domain_binding;
	char	*language;
	unsigned int	n = (unsigned int)ln;	/* we don't need long for n */
	uint32_t	cur_domain_len, cblen;
	uint32_t	hash_domain;
	struct msg_pack	*mp, omp;

#ifdef GETTEXT_DEBUG
	gprintf(0, "*************** _real_gettext_u(\"%s\", \"%s\", "
	    "\"%s\", %d, %d, %d)\n",
	    domain ? domain : "NULL", msgid1 ? msgid1 : "NULL",
	    msgid2 ? msgid2 : "NULL", n, category, plural);
	gprintf(0, "***************** global_gt: 0x%p\n", global_gt);
	printgt(global_gt, 1);
#endif

	if (msgid1 == NULL)
		return (NULL);

	mp = memset(&omp, 0, sizeof (omp));	/* msg pack */

	/*
	 * category may be LC_MESSAGES or LC_TIME
	 * locale contains the value of 'category'
	 */
	if (loc == NULL)
		loc = uselocale(NULL);
	cur_locale = current_locale(loc, category);

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
	if (domain == NULL) {
		/*
		 * if NULL is specified for domainname,
		 * use the currently bound domain.
		 */
		cur_domain = _textdomain_u(NULL, mydomain);
	} else if (!*domain) {
		/*
		 * if an empty string is specified
		 */
		cur_domain = DEFAULT_DOMAIN;
	} else {
		cur_domain = (char *)domain;
	}

	hash_domain = get_hashid(cur_domain, &cur_domain_len);
	if (cur_domain_len > TEXTDOMAINMAX) {
		/* domain is invalid, return msg_id */
		DFLTMSG(result, msgid1, msgid2, n, plural);
		return (result);
	}

	nlspath = getenv("NLSPATH"); /* get the content of NLSPATH */
	if (nlspath == NULL || !*nlspath) {
		/* no NLSPATH is defined in the environ */
		if ((*cur_locale == 'C') && (*(cur_locale + 1) == '\0')) {
			/*
			 * If C locale,
			 * return the original msgid immediately.
			 */
			DFLTMSG(result, msgid1, msgid2, n, plural);
			return (result);
		}
		nlspath = NULL;
	} else {
		/* NLSPATH is set */
		int	ret;

		msgloc = current_locale(loc, LC_MESSAGES);

		ret = process_nlspath(cur_domain, msgloc,
		    (const char *)nlspath, &cur_binding);
		if (ret == -1) {
			/* error occurred */
			DFLTMSG(result, msgid1, msgid2, n, plural);
			return (result);
		} else if (ret == 0) {
			nlspath = NULL;
		}
	}

	cur_domain_binding = _real_bindtextdomain_u(cur_domain,
	    NULL, TP_BINDING);
	if (cur_domain_binding == NULL) {
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
	mp->domain_len = cur_domain_len;
	mp->n = n;
	mp->category = category;
	mp->plural = plural;
	mp->hash_domain = hash_domain;

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
	if (nlspath) {
		/*
		 * NLSPATH binding has been successfully built
		 */
#ifdef GETTEXT_DEBUG
		gprintf(0, "************************** examining NLSPATH\n");
		gprintf(0, "       cur_binding: \"%s\"\n",
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
				DFLTMSG(result, msgid1, msgid2, n, plural);
				return (result);
			}

			(void) memcpy(mp->msgfile, cb, cblen);
			*(mp->msgfile + cblen) = '\0';

#ifdef GETTEXT_DEBUG
			gprintf(0, "*******************"
			    "********************* \n");
			gprintf(0, "       msgfile: \"%s\"\n",
			    msgfile ? msgfile : "(null)");
			gprintf(0, "*******************"
			    "********************* \n");
#endif
			result = handle_mo(mp);
			if (result) {
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
		ret_msg = handle_lang(mp);
		if (ret_msg != NULL) {
			/* valid msg found in GNU MO */
			return (ret_msg);
		}
		/*
		 * handle_lang() may have overridden locale
		 */
		mp->locale = cur_locale;
		mp->status = 0;
	}

	/*
	 * Finally, handle a single binding
	 */
#ifdef GETTEXT_DEBUG
	*mp->msgfile = '\0';
#endif
	if (mk_msgfile(mp) == NULL) {
		DFLTMSG(result, msgid1, msgid2, n, plural);
		return (result);
	}

	result = handle_mo(mp);
	if (result) {
		return (result);
	}
	DFLTMSG(result, msgid1, msgid2, n, plural);
	return (result);
} /* _real_gettext_u */

#define	ALLFREE	\
	free_all(nlstmp, nnp, pathname, ppaths, lang)

static void
free_all(Nlstmp *nlstmp, Nls_node *nnp, char *pathname,
    char *ppaths, char *lang)
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
	size_t	nlspath_len, domain_len, locale_len, path_len;
	size_t	ppaths_len = 0;
	Nlstmp	*nlstmp = NULL;
	Nlstmp	*pnlstmp, *qnlstmp;
	Nls_node	*cur_nls, *nnp;
	Gettext_t	*gt = global_gt;

#ifdef GETTEXT_DEBUG
	gprintf(0, "*************** process_nlspath(%s, %s, "
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

	nnp = gt->n_node;
	while (nnp) {
		if (strcmp(nnp->domain, cur_domain) == 0 &&
		    strcmp(nnp->locale, cur_msgloc) == 0 &&
		    strcmp(nnp->nlspath, nlspath) == 0) {
			/* found */
			gt->c_n_node = nnp;
			*binding = nnp->ppaths;
			return (1);
		}
		nnp = nnp->next;
	}
	/* not found */

	nnp = calloc(1, sizeof (Nls_node));
	if (nnp == NULL) {
		ALLFREE;
		return (-1);
	}

	nlspath_len = strlen(nlspath);
	locale_len = strlen(cur_msgloc);
	domain_len = strlen(cur_domain);

	lang = s = strdup(cur_msgloc);
	if (lang == NULL) {
		ALLFREE;
		return (-1);
	}
	s1 = s2 = NULL;
	while (*s) {
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
	pathname = malloc(MAXPATHLEN);
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
			pnlstmp = malloc(sizeof (Nlstmp));
			if (pnlstmp == NULL) {
				ALLFREE;
				return (-1);
			}

			(void) memcpy(pnlstmp->pathname, cur_domain,
			    domain_len + 1);
			pnlstmp->len = domain_len;
			ppaths_len += domain_len + 1; /* 1 for ':' */


			pnlstmp->next = NULL;

			if (nlstmp == NULL) {
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
			pnlstmp = malloc(sizeof (Nlstmp));
			if (pnlstmp == NULL) {
				ALLFREE;
				return (-1);
			}

			path_len = strlen(pathname);
			(void) memcpy(pnlstmp->pathname, pathname,
			    path_len + 1);
			pnlstmp->len = path_len;
			ppaths_len += path_len + 1; /* 1 for ':' */

			pnlstmp->next = NULL;

			if (nlstmp == NULL) {
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
		ppaths = malloc(ppaths_len + 1);
		if (ppaths == NULL) {
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
	s = ppaths;
	while (pnlstmp) {
		(void) memcpy(s, pnlstmp->pathname, pnlstmp->len);
		s += pnlstmp->len;
		*s++ = ':';
		qnlstmp = pnlstmp->next;
		free(pnlstmp);
		pnlstmp = qnlstmp;
	}
	*s = '\0';
	nlstmp = NULL;

	nnp->domain = malloc(domain_len + 1);
	if (nnp->domain == NULL) {
		ALLFREE;
		return (-1);
	} else {
		(void) memcpy(nnp->domain, cur_domain, domain_len + 1);
	}
	nnp->locale = malloc(locale_len + 1);
	if (nnp->locale == NULL) {
		ALLFREE;
		return (-1);
	} else {
		(void) memcpy(nnp->locale, cur_msgloc, locale_len + 1);
	}
	nnp->nlspath = malloc(nlspath_len + 1);
	if (nnp->nlspath == NULL) {
		ALLFREE;
		return (-1);
	} else {
		(void) memcpy(nnp->nlspath, nlspath, nlspath_len + 1);
	}
	nnp->ppaths = ppaths;

	nnp->next = gt->n_node;
	gt->n_node = nnp;
	gt->c_n_node = nnp;

	free(pathname);
	free(lang);
#ifdef GETTEXT_DEBUG
	gprintf(0, "*************** existing process_nlspath with success\n");
	gprintf(0, "       binding: \"%s\"\n", ppaths);
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
	gprintf(0, "*************** _real_bindtextdomain_u(\"%s\", "
	    "\"%s\", \"%s\")\n",
	    (domain ? domain : ""),
	    (binding ? binding : ""),
	    (type == TP_BINDING) ? "TP_BINDING" : "TP_CODESET");
#endif

	/*
	 * If domain is a NULL pointer, no change will occur regardless
	 * of binding value. Just return NULL.
	 */
	if (domain == NULL) {
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
			if (binding == NULL) {
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

		if ((bind = malloc(sizeof (Dbinding))) == NULL) {
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
	gprintf(0, "*************** _textdomain_u(\"%s\", 0x%p)\n",
	    (domain ? domain : ""), (void *)result);
#endif

	/* Query is performed for NULL domain pointer */
	if (domain == NULL) {
		(void) strcpy(result, CURRENT_DOMAIN(gt));
		return (result);
	}

	/* check for error. */
	/*
	 * domain is limited to TEXTDOMAINMAX bytes
	 * excluding a null termination.
	 */
	domain_len = strlen(domain);
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
		p = malloc(domain_len + 1);
		if (p == NULL)
			return (NULL);
		(void) strcpy(p, domain);
		if (CURRENT_DOMAIN(gt) != default_domain)
			free(CURRENT_DOMAIN(gt));
		CURRENT_DOMAIN(gt) = p;
	}

	(void) strcpy(result, CURRENT_DOMAIN(gt));
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
	gprintf(0, "*************** key_2_text(0x%p, \"%s\")\n",
	    (void *)messages, key_string ? key_string : "(null)");
	printsunmsg(messages, 1);
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

/*
 * sun_setmsg
 *
 * INPUT
 *   mnp  - message node
 *   addr - address to the mmapped file
 *   size - size of the file
 *
 * RETURN
 *   0   - either T_SUN_MO or T_ILL_MO has been set
 *   1   - not a valid sun mo file
 *  -1   - failed
 */
static int
sun_setmsg(Msg_node *mnp, char *addr, size_t size)
{
	struct msg_info	*sun_header;
	Msg_s_node	*p;
	uint32_t	first_4bytes;
	int	mid, count;
	int	struct_size, struct_size_old;
	int	msg_struct_size;

	if (size < sizeof (struct msg_info)) {
		/* invalid mo file */
		mnp->type = T_ILL_MO;
#ifdef GETTEXT_DEBUG
		gprintf(0, "********* exiting sun_setmsg\n");
		printmnp(mnp, 1);
#endif
		return (0);
	}

	first_4bytes = *((uint32_t *)(uintptr_t)addr);
	if (first_4bytes > INT_MAX) {
		/*
		 * Not a valid sun mo file
		 */
		return (1);
	}

	/* candidate for sun mo */

	sun_header = (struct msg_info *)(uintptr_t)addr;
	mid = sun_header->msg_mid;
	count = sun_header->msg_count;
	msg_struct_size = sun_header->msg_struct_size;
	struct_size_old = (int)(OLD_MSG_STRUCT_SIZE * count);
	struct_size = (int)(MSG_STRUCT_SIZE * count);

	if ((((count - 1) / 2) != mid) ||
	    ((msg_struct_size != struct_size_old) &&
	    (msg_struct_size != struct_size))) {
		/* invalid mo file */
		mnp->type = T_ILL_MO;
#ifdef GETTEXT_DEBUG
		gprintf(0, "********* exiting sun_setmsg\n");
		printmnp(mnp, 1);
#endif
		return (0);
	}
	/* valid sun mo file */

	p = malloc(sizeof (Msg_s_node));
	if (p == NULL) {
		return (-1);
	}

	p->msg_file_info = sun_header;
	p->msg_list = (struct msg_struct *)(uintptr_t)
	    (addr + sizeof (struct msg_info));
	p->msg_ids = (char *)(addr + sizeof (struct msg_info) +
	    struct_size);
	p->msg_strs = (char *)(addr + sizeof (struct msg_info) +
	    struct_size + sun_header->str_count_msgid);

	mnp->msg.sunmsg = p;
	mnp->type = T_SUN_MO;
#ifdef GETTEXT_DEBUG
	gprintf(0, "******** exiting sun_setmsg\n");
	printmnp(mnp, 1);
#endif
	return (0);
}

/*
 * setmsg
 *
 * INPUT
 *   mnp  - message node
 *   addr - address to the mmapped file
 *   size - size of the file
 *
 * RETURN
 *   0   - succeeded
 *  -1   - failed
 */
static int
setmsg(Msg_node *mnp, char *addr, size_t size)
{
	int	ret;
	if ((ret = sun_setmsg(mnp, addr, size)) <= 0)
		return (ret);

	return (gnu_setmsg(mnp, addr, size));
}

static char *
handle_type_mo(Msg_node *mnp, struct msg_pack *mp)
{
	char	*result;

	switch (mnp->type) {
	case T_ILL_MO:
		/* invalid MO */
		return (NULL);
	case T_SUN_MO:
		/* Sun MO found */
		mp->status |= ST_SUN_MO_FOUND;

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
		result = key_2_text(mnp->msg.sunmsg, mp->msgid1);
		if (!mnp->trusted) {
			result = check_format(mp->msgid1, result, 0);
		}
		return (result);
	case T_GNU_MO:
		/* GNU MO found */
		mp->status |= ST_GNU_MO_FOUND;

		result = gnu_key_2_text(mnp->msg.gnumsg,
		    get_codeset(mp->domain), mp);

		if (result == mp->msgid1 || result == mp->msgid2) {
			/* no valid msg found */
			return (result);
		}

		/* valid msg found */
		mp->status |= ST_GNU_MSG_FOUND;

		if (!mnp->trusted) {
			result = check_format(mp->msgid1, result, 0);
			if (result == mp->msgid1) {
				DFLTMSG(result, mp->msgid1, mp->msgid2,
				    mp->n, mp->plural);
			}
		}
		return (result);
	default:
		/* this should never happen */
		DFLTMSG(result, mp->msgid1, mp->msgid2, mp->n, mp->plural);
		return (result);
	}
	/* NOTREACHED */
}

/*
 * handle_mo() returns NULL if invalid MO found.
 */
char *
handle_mo(struct msg_pack *mp)
{
	int	fd;
	char	*result;
	struct stat64	statbuf;
	Msg_node	*mnp;
	Gettext_t	*gt = global_gt;

#define	CONNECT_ENTRY	\
	mnp->next = gt->m_node; \
	gt->m_node = mnp; \
	gt->c_m_node = mnp

#ifdef GETTEXT_DEBUG
	gprintf(0, "*************** handle_mo(0x%p)\n", (void *)mp);
	printmp(mp, 1);
#endif

	mnp = check_cache(mp);

	if (mnp != NULL) {
		/* cache found */
		return (handle_type_mo(mnp, mp));
	}

	/*
	 * Valid entry not found in the cache
	 */
	mnp = calloc(1, sizeof (Msg_node));
	if (mnp == NULL) {
		DFLTMSG(result, mp->msgid1, mp->msgid2, mp->n, mp->plural);
		return (result);
	}
	mnp->hashid = mp->hash_domain;
	mnp->path = strdup(mp->msgfile);
	if (mnp->path == NULL) {
		free(mnp);
		DFLTMSG(result, mp->msgid1, mp->msgid2, mp->n, mp->plural);
		return (result);
	}

	fd = nls_safe_open(mp->msgfile, &statbuf, &mp->trusted, !mp->nlsp);
	if ((fd == -1) || (statbuf.st_size > LONG_MAX)) {
		if (fd != -1)
			(void) close(fd);
		mnp->type = T_ILL_MO;
		CONNECT_ENTRY;
		return (NULL);
	}
	mp->fsz = (size_t)statbuf.st_size;
	mp->addr = mmap(NULL, mp->fsz, PROT_READ, MAP_SHARED, fd, 0);
	(void) close(fd);

	if (mp->addr == MAP_FAILED) {
		free(mnp->path);
		free(mnp);
		DFLTMSG(result, mp->msgid1, mp->msgid2, mp->n, mp->plural);
		return (result);
	}

	if (setmsg(mnp, (char *)mp->addr, mp->fsz) == -1) {
		free(mnp->path);
		free(mnp);
		(void) munmap(mp->addr, mp->fsz);
		DFLTMSG(result, mp->msgid1, mp->msgid2, mp->n, mp->plural);
		return (result);
	}
	mnp->trusted = mp->trusted;
	CONNECT_ENTRY;

	return (handle_type_mo(mnp, mp));
}
