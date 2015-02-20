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
 *
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <stdio.h>
#include <strings.h>
#include <ctype.h>
#include <libgen.h>
#include <libintl.h>

#include <libxml/tree.h>
#include <libxml/parser.h>

#include <kmfapiP.h>
#include "util.h"


/* Supporting structures and global variables for getopt_av(). */
typedef struct	av_opts_s {
	int		shortnm;	/* short name character */
	char		*longnm;	/* long name string, NOT terminated */
	int		longnm_len;	/* length of long name string */
	boolean_t	has_arg;	/* takes optional argument */
} av_opts;

static av_opts		*opts_av = NULL;
static const char	*_save_optstr = NULL;
static int		_save_numopts = 0;
int			optind_av = 1;
char			*optarg_av = NULL;

void
free_policy_list(POLICY_LIST *plist)
{
	POLICY_LIST *n = plist, *old;

	if (plist == NULL)
		return;

	while (n != NULL) {
		old = n;
		kmf_free_policy_record(&n->plc);
		n = n->next;
		free(old);
	}
	plist = NULL;
}

int
load_policies(char *file, POLICY_LIST **policy_list)
{
	int rv = KC_OK;
	KMF_RETURN kmfrv = KMF_OK;
	POLICY_LIST *newitem, *plist = NULL;
	xmlParserCtxtPtr ctxt;
	xmlDocPtr doc = NULL;
	xmlNodePtr cur, node;

	/* Create a parser context */
	ctxt = xmlNewParserCtxt();
	if (ctxt == NULL)
		return (KMF_ERR_POLICY_DB_FORMAT);

	/* Read the policy DB and verify it against the schema. */
	doc = xmlCtxtReadFile(ctxt, file, NULL,
	    XML_PARSE_DTDVALID | XML_PARSE_NOERROR | XML_PARSE_NOWARNING);
	if (doc == NULL || ctxt->valid == 0) {
		kmfrv = KMF_ERR_POLICY_DB_FORMAT;
		goto end;
	}

	cur = xmlDocGetRootElement(doc);
	if (cur == NULL) {
		kmfrv = KMF_ERR_POLICY_DB_FORMAT;
		goto end;
	}

	node = cur->xmlChildrenNode;
	while (node != NULL) {
		char *c;
		/*
		 * Search for the policy that matches the given name.
		 */
		if (!xmlStrcmp((const xmlChar *)node->name,
		    (const xmlChar *)KMF_POLICY_ELEMENT)) {
			/* Check the name attribute */
			c = (char *)xmlGetProp(node,
			    (const xmlChar *)KMF_POLICY_NAME_ATTR);

			/* If a match, parse the rest of the data */
			if (c != NULL) {
				xmlFree(c);
				newitem = malloc(sizeof (POLICY_LIST));
				if (newitem != NULL) {
					(void) memset(newitem, 0,
					    sizeof (POLICY_LIST));
					kmfrv = parsePolicyElement(node,
					    &newitem->plc);
				} else {
					kmfrv = KMF_ERR_MEMORY;
					goto end;
				}
				/* add to linked list */
				if (plist == NULL) {
					plist = newitem;
				} else {
					POLICY_LIST *n = plist;
					while (n->next != NULL)
						n = n->next;

					n->next = newitem;
					newitem->next = NULL;
				}
			}
		}
		node = node->next;
	}

end:
	if (ctxt != NULL)
		xmlFreeParserCtxt(ctxt);

	if (doc != NULL)
		xmlFreeDoc(doc);

	if (kmfrv != KMF_OK) {
		free_policy_list(plist);
		rv = KC_ERR_LOADDB;
	} else {
		*policy_list = plist;
	}

	return (rv);
}

/*
 * Return 0 if there is any error in the input string.
 */
uint16_t
parseKUlist(char *kustring)
{
	uint16_t cur_bit;
	uint16_t kubits = 0;
	char *p;

	p = strtok(kustring, ",");
	while (p != NULL) {
		cur_bit = kmf_string_to_ku(p);
		if (cur_bit == 0) {
			kubits = 0;
			break;
		}
		kubits |= cur_bit;
		p = strtok(NULL, ",");
	}

	return (kubits);
}

static void
addToEKUList(KMF_EKU_POLICY *ekus, KMF_OID *newoid)
{
	if (newoid != NULL && ekus != NULL) {
		ekus->eku_count++;
		ekus->ekulist = realloc(
		    ekus->ekulist, ekus->eku_count * sizeof (KMF_OID));
		if (ekus->ekulist != NULL) {
			ekus->ekulist[ekus->eku_count-1] = *newoid;
		}
	}
}

int
parseEKUNames(char *ekulist, KMF_POLICY_RECORD *plc)
{
	int rv = KC_OK;
	char *p;
	KMF_OID *newoid;
	KMF_EKU_POLICY *ekus = &plc->eku_set;

	if (ekulist == NULL || !strlen(ekulist))
		return (0);

	/*
	 * The list should be comma separated list of EKU Names.
	 */
	p = strtok(ekulist, ",");

	/* If no tokens found, then maybe its just a single EKU value */
	if (p == NULL) {
		newoid = kmf_ekuname_to_oid(ekulist);
		if (newoid != NULL) {
			addToEKUList(ekus, newoid);
			free(newoid);
		} else {
			rv = KC_ERR_USAGE;
		}
	}

	while (p != NULL) {
		newoid = kmf_ekuname_to_oid(p);
		if (newoid != NULL) {
			addToEKUList(ekus, newoid);
			free(newoid);
		} else {
			rv = KC_ERR_USAGE;
			break;
		}
		p = strtok(NULL, ",");
	}

	if (rv != KC_OK)
		kmf_free_eku_policy(ekus);

	return (rv);
}

int
parseEKUOIDs(char *ekulist, KMF_POLICY_RECORD *plc)
{
	int rv = KC_OK;
	char *p;
	KMF_OID newoid = { 0, NULL };
	KMF_EKU_POLICY *ekus = &plc->eku_set;

	if (ekulist == NULL || !strlen(ekulist))
		return (0);

	/*
	 * The list should be comma separated list of EKU Names.
	 */
	p = strtok(ekulist, ",");
	if (p == NULL) {
		if (kmf_string_to_oid(ekulist, &newoid) == KMF_OK) {
			addToEKUList(ekus, &newoid);
		} else {
			rv = KC_ERR_USAGE;
		}
	}

	while (p != NULL && rv == 0) {
		if (kmf_string_to_oid(p, &newoid) == KMF_OK) {
			addToEKUList(ekus, &newoid);
		} else {
			rv = KC_ERR_USAGE;
			break;
		}
		p = strtok(NULL, ",");
	}

	if (rv != KC_OK)
		kmf_free_eku_policy(ekus);

	return (rv);
}

int
get_boolean(char *arg)
{
	if (arg == NULL)
		return (-1);
	if (strcasecmp(arg, "true") == 0)
		return (1);
	if (strcasecmp(arg, "false") == 0)
		return (0);
	return (-1);
}

/*
 * This function processes the input string.  It removes the beginning
 * and ending blank's first, makes a copy of the resulting string and
 * return it.
 *
 * This function returns NULL, if there is an error in the
 * input string or when the system is out of memory.  The output
 * "err_flag" argument will record the error code, if it is not NULL.
 */
char *
get_string(char *str, int *err_flag)
{
	char *p;
	int len, i;
	char *retstr = NULL;

	if (str == NULL) {
		if (err_flag != NULL)
			*err_flag = KC_ERR_USAGE;
		return (NULL);
	}

	/* Remove beginning whitespace */
	p = str;
	while (p != NULL && isspace(*p))
		p++;

	if (p == NULL) {
		if (err_flag != NULL)
			*err_flag = KC_ERR_USAGE;
		return (NULL);
	}

	/* Remove the trailing blanks */
	len = strlen(p);
	while (len > 0 && isspace(p[len-1]))
		len--;

	if (len == 0) {
		if (err_flag != NULL)
			*err_flag = KC_ERR_USAGE;
		return (NULL);
	}

	/* Check if there is any non-printable character */
	i = 0;
	while (i < len) {
		if (isprint(p[i]))
			i++;
		else {
			if (err_flag != NULL)
				*err_flag = KC_ERR_USAGE;
			return (NULL);
		}
	}

	/* Make a copy of the string and return it */
	retstr = malloc(len + 1);
	if (retstr == NULL) {
		if (err_flag != NULL)
			*err_flag = KC_ERR_MEMORY;
		return (NULL);
	}

	if (err_flag != NULL)
		*err_flag = KC_OK;

	(void) strncpy(retstr, p, len);
	retstr[len] = '\0';
	return (retstr);
}

/*
 * Breaks out the getopt-style option string into a structure that can be
 * traversed later for calls to getopt_av().  Option string is NOT altered,
 * but the struct fields point to locations within option string.
 */
static int
populate_opts(char *optstring)
{
	int		i;
	av_opts		*temp;
	char		*marker;

	if (optstring == NULL || *optstring == '\0')
		return (0);

	/*
	 * This tries to imitate getopt(3c) Each option must conform to:
	 * <short name char> [ ':' ] [ '(' <long name string> ')' ]
	 * If long name is missing, the short name is used for long name.
	 */
	for (i = 0; *optstring != '\0'; i++) {
		if ((temp = (av_opts *)((i == 0) ? malloc(sizeof (av_opts)) :
		    realloc(opts_av, (i+1) * sizeof (av_opts)))) == NULL) {
			free(opts_av);
			opts_av = NULL;
			return (0);
		} else
			opts_av = (av_opts *)temp;

		marker = optstring;		/* may need optstring later */

		opts_av[i].shortnm = *marker++;	/* set short name */

		if (*marker == ':') {		/* check for opt arg */
			marker++;
			opts_av[i].has_arg = B_TRUE;
		}

		if (*marker == '(') {		/* check and set long name */
			marker++;
			opts_av[i].longnm = marker;
			opts_av[i].longnm_len = strcspn(marker, ")");
			optstring = marker + opts_av[i].longnm_len + 1;
		} else {
			/* use short name option character */
			opts_av[i].longnm = optstring;
			opts_av[i].longnm_len = 1;
			optstring = marker;
		}
	}

	return (i);
}

/*
 * getopt_av() is very similar to getopt(3c) in that the takes an option
 * string, compares command line arguments for matches, and returns a single
 * letter option when a match is found.  However, getopt_av() differs from
 * getopt(3c) by allowing both longname options and values be found
 * on the command line.
 */
int
getopt_av(int argc, char * const *argv, const char *optstring)
{
	int	i;
	int	len;

	if (optind_av >= argc)
		return (EOF);

	/* First time or when optstring changes from previous one */
	if (_save_optstr != optstring) {
		if (opts_av != NULL)
			free(opts_av);
		opts_av = NULL;
		_save_optstr = optstring;
		_save_numopts = populate_opts((char *)optstring);
	}

	for (i = 0; i < _save_numopts; i++) {
		if (strcmp(argv[optind_av], "--") == 0) {
			optind_av++;
			break;
		}

		len = strcspn(argv[optind_av], "=");

		if (len == opts_av[i].longnm_len && strncmp(argv[optind_av],
		    opts_av[i].longnm, opts_av[i].longnm_len) == 0) {
			/* matched */
			if (!opts_av[i].has_arg) {
				optind_av++;
				return (opts_av[i].shortnm);
			}

			/* needs optarg */
			if (argv[optind_av][len] == '=') {
				optarg_av = &(argv[optind_av][len+1]);
				optind_av++;
				return (opts_av[i].shortnm);
			}

			optarg_av = NULL;
			optind_av++;
			return ((int)'?');
		}
	}

	return (EOF);
}

void
print_sanity_error(KMF_RETURN ret)
{
	switch (ret) {
	case KMF_ERR_POLICY_NAME:
		(void) fprintf(stderr, gettext("Error in the policy name\n"));
		break;
	case KMF_ERR_TA_POLICY:
		(void) fprintf(stderr,
		    gettext("Error in trust anchor attributes\n"));
		break;
	case KMF_ERR_OCSP_POLICY:
		(void) fprintf(stderr,
		    gettext("Error in OCSP policy attributes\n"));
		break;
	default:
		break;
	}
}


conf_entry_t *
get_keystore_entry(char *kstore_name)
{
	conf_entrylist_t *phead = NULL;
	conf_entrylist_t *ptr;
	conf_entry_t	*rtn_entry = NULL;

	if (kstore_name == NULL)
		return (NULL);

	if (get_entrylist(&phead) != KMF_OK)
		return (NULL);

	ptr = phead;
	while (ptr != NULL) {
		if (strcmp(ptr->entry->keystore, kstore_name) == 0)
			break;
		ptr = ptr->next;
	}

	if (ptr != NULL) /* found the entry */
		rtn_entry = dup_entry(ptr->entry);

	free_entrylist(phead);
	return (rtn_entry);
}
