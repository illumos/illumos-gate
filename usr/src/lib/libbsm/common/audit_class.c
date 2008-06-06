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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Interfaces to audit_class(5)  (/etc/security/audit_class)
 */

#include <stdlib.h>
#include <stdio.h>
#include <limits.h>
#include <sys/types.h>
#include <bsm/audit.h>
#include <bsm/libbsm.h>
#include <string.h>
#include <synch.h>

static char	au_class_fname[PATH_MAX] = AUDITCLASSFILE;
static FILE	*au_class_file = NULL;
static mutex_t	mutex_classfile = DEFAULTMUTEX;
static mutex_t	mutex_classcache = DEFAULTMUTEX;

void
setauclass()
{
	(void) mutex_lock(&mutex_classfile);
	if (au_class_file) {
		(void) fseek(au_class_file, 0L, 0);
	}
	(void) mutex_unlock(&mutex_classfile);
}


void
endauclass()
{
	(void) mutex_lock(&mutex_classfile);
	if (au_class_file) {
		(void) fclose(au_class_file);
		au_class_file = NULL;
	}
	(void) mutex_unlock(&mutex_classfile);
}

/*
 * getauclassent():
 *	This is not MT-safe because of the static variables.
 */
au_class_ent_t *
getauclassent()
{
	static au_class_ent_t e;
	static char	cname[AU_CLASS_NAME_MAX];
	static char	cdesc[AU_CLASS_DESC_MAX];

	e.ac_name = cname;
	e.ac_desc = cdesc;

	return (getauclassent_r(&e));
}

/*
 * getauclassent_r
 *	This is MT-safe if each thread passes in its own pointer
 *	to the space where the class entry is returned.  Becareful
 *	to also allocate space from the cname and cdesc pointers
 *	in the au_class_ent structure.
 */
au_class_ent_t *
getauclassent_r(au_class_entry)
	au_class_ent_t *au_class_entry;
{
	int	i, error = 0, found = 0;
	char	*s, input[256];
	unsigned long v;

	if (au_class_entry == (au_class_ent_t *)NULL ||
		au_class_entry->ac_name == (char *)NULL ||
		au_class_entry->ac_desc == (char *)NULL) {
			return ((au_class_ent_t *)NULL);
	}

	/* open audit class file if it isn't already */
	(void) mutex_lock(&mutex_classfile);
	if (!au_class_file) {
		if (!(au_class_file = fopen(au_class_fname, "rF"))) {
			(void) mutex_unlock(&mutex_classfile);
			return ((au_class_ent_t *)0);
		}
	}

	while (fgets(input, 256, au_class_file)) {
		if (input[0] != '#') {
			s = input + strspn(input, " \t\r\n");
			if ((*s == '\0') || (*s == '#')) {
				continue;
			}
			found = 1;
			s = input;

			/* parse bitfield */
			i = strcspn(s, ":");
			s[i] = '\0';
			if (strncmp(s, "0x", 2) == 0) {
				(void) sscanf(&s[2], "%lx", &v);
			} else {
				(void) sscanf(s, "%lu", &v);
			}
			au_class_entry->ac_class = v;
			s = &s[i+1];

			/* parse class name */
			i = strcspn(s, ":");
			s[i] = '\0';
			(void) strncpy(au_class_entry->ac_name, s,
			    AU_CLASS_NAME_MAX);
			s = &s[i+1];

			/* parse class description */
			i = strcspn(s, "\n\0");
			s[i] = '\0';
			(void) strncpy(au_class_entry->ac_desc, s,
			    AU_CLASS_DESC_MAX);

			break;
		}
	}

	(void) mutex_unlock(&mutex_classfile);

	if (!error && found) {
		return (au_class_entry);
	} else {
		return ((au_class_ent_t *)0);
	}
}


au_class_ent_t *
#ifdef __STDC__
getauclassnam(char *name)
#else
getauclassnam(name)
	char *name;
#endif
{
	static au_class_ent_t e;
	static char	cname[AU_CLASS_NAME_MAX];
	static char	cdesc[AU_CLASS_DESC_MAX];

	e.ac_name = cname;
	e.ac_desc = cdesc;

	return (getauclassnam_r(&e, name));
}

au_class_ent_t *
#ifdef __STDC__
getauclassnam_r(au_class_ent_t *e, char *name)
#else
getauclassnam_r()
	au_class_ent_t *e;
	char *name;
#endif
{
	while (getauclassent_r(e) != NULL) {
		if (strcmp(e->ac_name, name) == 0) {
			return (e);
		}
	}
	return ((au_class_ent_t *)NULL);
}


/*
 * xcacheauclass:
 *	Read the entire audit_class file into memory.
 *	Return a pointer to the requested entry in the cache
 *	or a pointer to an invalid entry if the the class
 *	requested is not known.
 *
 *	Return < 0, do not set result pointer, if error.
 *	Return   0, set result pointer to invalid entry, if class not in cache.
 *	Return   1, set result pointer to a valid entry, if class is in cache.
 */
static int
xcacheauclass(result, class_name, class_no, flags)
	au_class_ent_t **result; /* set this pointer to an entry in the cache */
	char	*class_name; /* name of class to look up */
	au_class_t class_no;
	int	flags;
{
	static int	invalid;
	static au_class_ent_t **class_tbl;
	static int	called_once;
	static int	lines = 0;

	char		line[256];
	FILE		*fp;
	au_class_ent_t	*p_class;
	int		i;
	int		hit = 0;
	char		*s;

	(void) mutex_lock(&mutex_classcache);
	if (called_once == 0) {

		/* Count number of lines in the class file */
		if ((fp = fopen(au_class_fname, "rF")) == NULL) {
			(void) mutex_unlock(&mutex_classcache);
			return (-1);
		}
		while (fgets(line, 256, fp) != NULL) {
			s = line + strspn(line, " \t\r\n");
			if ((*s == '\0') || (*s == '#')) {
				continue;
			}
			lines++;
		}
		(void) fclose(fp);
		class_tbl = (au_class_ent_t **)calloc((size_t)lines + 1,
			sizeof (au_class_ent_t));
		if (class_tbl == NULL) {
			(void) mutex_unlock(&mutex_classcache);
			return (-2);
		}

		lines = 0;
		setauclass();
		/*
		 * This call to getauclassent is protected by
		 * mutex_classcache, so we don't need to use the thread-
		 * safe version (getauclassent_r).
		 */
		while ((p_class = getauclassent()) != NULL) {
			class_tbl[lines] = (au_class_ent_t *)
				malloc(sizeof (au_class_ent_t));
			if (class_tbl[lines] == NULL) {
				(void) mutex_unlock(&mutex_classcache);
				return (-3);
			}
			class_tbl[lines]->ac_name = strdup(p_class->ac_name);
			class_tbl[lines]->ac_class = p_class->ac_class;
			class_tbl[lines]->ac_desc = strdup(p_class->ac_desc);
#ifdef DEBUG2
			printclass(class_tbl[lines]);
#endif
			lines++;
		}
		endauclass();
		invalid = lines;
		class_tbl[invalid] = (au_class_ent_t *)
			malloc(sizeof (au_class_ent_t));
		if (class_tbl[invalid] == NULL) {
			(void) mutex_unlock(&mutex_classcache);
			return (-4);
		}
		class_tbl[invalid]->ac_name = "invalid class";
		class_tbl[invalid]->ac_class = 0;
		class_tbl[invalid]->ac_desc = class_tbl[invalid]->ac_name;

		called_once = 1;

#ifdef DEBUG2
		for (i = 0; i <= lines; i++) {
			printclass(class_tbl[i]);
		}
#endif

	} /* END if called_once */
	*result = class_tbl[invalid];
	if (flags & AU_CACHE_NAME) {
		for (i = 0; i < lines; i++) {
			if (strcmp(class_name, class_tbl[i]->ac_name) == 0) {
				*result = class_tbl[i];
				hit = 1;
				break;
			}
		}
	} else if (flags & AU_CACHE_NUMBER) {
		for (i = 0; i < lines; i++) {
			if (class_no == class_tbl[i]->ac_class) {
				*result = class_tbl[i];
				hit = 1;
				break;
			}
		}
	}
	(void) mutex_unlock(&mutex_classcache);
	return (hit);
}


int
#ifdef __STDC__
cacheauclass(au_class_ent_t **result, au_class_t class_no)
#else
cacheauclass(result, class_no)
	au_class_ent_t **result; /* set this pointer to an entry in the cache */
	au_class_t class_no;
#endif
{
	return (xcacheauclass(result, "", class_no, AU_CACHE_NUMBER));
}


int
#ifdef __STDC__
cacheauclassnam(au_class_ent_t **result, char *class_name)
#else
cacheauclassnam(result, class_name)
	au_class_ent_t **result; /* set this pointer to an entry in the cache */
	char	*class_name;
#endif
{
	return (xcacheauclass(result, class_name, (au_class_t)0,
		AU_CACHE_NAME));
}


#ifdef DEBUG2
void
printclass(p_c)
au_class_ent_t *p_c;
{
	printf("%x:%s:%s\n", p_c->ac_class, p_c->ac_name, p_c->ac_desc);
	fflush(stdout);
}


#endif
