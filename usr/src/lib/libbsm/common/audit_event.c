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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


/*
 * Interfaces to audit_event(5)  (/etc/security/audit_event)
 */

/*
 * This routine is obsolete.  I have removed its inclusion by removing
 * the .o from the makefile.  Please use cacheauevent() or any of the
 * getauev* routines.
 */

#include <sys/types.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <bsm/audit.h>
#include <bsm/libbsm.h>
#include <synch.h>

/*
 *	Macros to produce a quoted string containing the value of a
 *	preprocessor macro. For example, if SIZE is defined to be 256,
 *	VAL2STR(SIZE) is "256". This is used to construct format
 *	strings for scanf-family functions below.
 */
#define	QUOTE(x)	#x
#define	VAL2STR(x)	QUOTE(x)

static au_class_t flagstohex(char *);

static char	au_event_fname[PATH_MAX] = AUDITEVENTFILE;
static FILE *au_event_file = (FILE *)0;
static mutex_t mutex_eventfile = DEFAULTMUTEX;
static mutex_t mutex_eventcache = DEFAULTMUTEX;
/*
 * If an error occurs during the call to cacheauclassnam() inside
 * flagstohex() any return value could be seen as a valid class mask so
 * the following global variable, cacheauclass_failure, is set to indicate
 * that an error has occurred.
 */
static int cacheauclass_failure = 0;

#ifdef DEBUG2
void
printevent(au_event_ent_t *p_event)
{
	(void) printf("%d:%s:%s:%d\n", p_event->ae_number, p_event->ae_name,
	    p_event->ae_desc, p_event->ae_class);
	(void) fflush(stdout);
}
#endif

void
setauevent()
{
	(void) mutex_lock(&mutex_eventfile);
	if (au_event_file) {
		(void) fseek(au_event_file, 0L, 0);
	}
	(void) mutex_unlock(&mutex_eventfile);
}

void
endauevent()
{
	(void) mutex_lock(&mutex_eventfile);
	if (au_event_file) {
		(void) fclose(au_event_file);
		au_event_file = (FILE *)0;
	}
	(void) mutex_unlock(&mutex_eventfile);
}

au_event_ent_t *
getauevent()
{
	static au_event_ent_t au_event_entry;
	static char	ename[AU_EVENT_NAME_MAX];
	static char	edesc[AU_EVENT_DESC_MAX];

	/* initialize au_event_entry structure */
	au_event_entry.ae_name = ename;
	au_event_entry.ae_desc = edesc;

	return (getauevent_r(&au_event_entry));
}

au_event_ent_t *
getauevent_r(au_event_ent_t *au_event_entry)
{
	int	i, error = 0, found = 0;
	char	*s, input[AU_EVENT_LINE_MAX];
	char	trim_buf[AU_EVENT_NAME_MAX+1];

	/* open audit event file if it isn't already */
	(void) mutex_lock(&mutex_eventfile);
	if (!au_event_file)
		if (!(au_event_file = fopen(au_event_fname, "rF"))) {
			(void) mutex_unlock(&mutex_eventfile);
			return (NULL);
		}

	while (fgets(input, AU_EVENT_LINE_MAX, au_event_file)) {
		if (input[0] != '#') {
			s = input + strspn(input, " \t\r\n");
			if ((*s == '\0') || (*s == '#')) {
				continue;
			}
			found = 1;
			s = input;

			/* parse number */
			i = strcspn(s, ":");
			s[i] = '\0';
			(void) sscanf(s, "%hu", &au_event_entry->ae_number);
			s = &s[i+1];

			/* parse event name */
			i = strcspn(s, ":");
			s[i] = '\0';
			(void) sscanf(s, "%" VAL2STR(AU_EVENT_NAME_MAX) "s",
			    trim_buf);
			(void) strncpy(au_event_entry->ae_name, trim_buf,
			    AU_EVENT_NAME_MAX);
			s = &s[i+1];

			/* parse event description */
			i = strcspn(s, ":");
			s[i] = '\0';
			(void) strncpy(au_event_entry->ae_desc, s,
			    AU_EVENT_DESC_MAX);
			s = &s[i+1];

			/* parse class */
			i = strcspn(s, "\n\0");
			s[i] = '\0';
			(void) sscanf(s, "%" VAL2STR(AU_EVENT_NAME_MAX) "s",
			    trim_buf);
			au_event_entry->ae_class = flagstohex(trim_buf);
			if (cacheauclass_failure == 1) {
				error = 1;
				cacheauclass_failure = 0;
			}

			break;
		}
	}
	(void) mutex_unlock(&mutex_eventfile);

	if (!error && found) {
		return (au_event_entry);
	} else {
		return (NULL);
	}
}

au_event_ent_t *
getauevnam(char *name)
{
	static au_event_ent_t au_event_entry;
	static char	ename[AU_EVENT_NAME_MAX];
	static char	edesc[AU_EVENT_DESC_MAX];

	/* initialize au_event_entry structure */
	au_event_entry.ae_name = ename;
	au_event_entry.ae_desc = edesc;

	return (getauevnam_r(&au_event_entry, name));
}

au_event_ent_t *
getauevnam_r(au_event_ent_t *e, char *name)
{
	setauevent();
	while (getauevent_r(e) != NULL) {
		if (strcmp(e->ae_name, name) == 0) {
			endauevent();
			return (e);
		}
	}
	endauevent();
	return (NULL);
}

au_event_ent_t *
getauevnum_r(au_event_ent_t *e, au_event_t event_number)
{
	setauevent();
	while (getauevent_r(e) != NULL) {
		if (e->ae_number == event_number) {
			endauevent();
			return (e);
		}
	}
	endauevent();
	return (NULL);
}

au_event_ent_t *
getauevnum(au_event_t event_number)
{
	static au_event_ent_t e;
	static char	ename[AU_EVENT_NAME_MAX];
	static char	edesc[AU_EVENT_DESC_MAX];

	/* initialize au_event_entry structure */
	e.ae_name = ename;
	e.ae_desc = edesc;

	return (getauevnum_r(&e, event_number));
}

au_event_t
getauevnonam(char *event_name)
{
	au_event_ent_t e;
	char ename[AU_EVENT_NAME_MAX];
	char edesc[AU_EVENT_DESC_MAX];

	/* initialize au_event_entry structure */
	e.ae_name = ename;
	e.ae_desc = edesc;

	if (getauevnam_r(&e, event_name) == NULL) {
		return (0);
	}
	return (e.ae_number);
}

/*
 * cacheauevent:
 *	Read the entire audit_event file into memory.
 *	Set a pointer to the requested entry in the cache
 *	or a pointer to an invalid entry if the event number
 *	is not known.
 *
 *	Return < 0, if error.
 *	Return   0, if event number not in cache.
 *	Return   1, if event number is in cache.
 */
int
cacheauevent(au_event_ent_t **result, au_event_t event_number)
{
	static au_event_t max; /* the highest event number in the file */
	static au_event_t min; /* the lowest event number in the file */
	static int	invalid; /* 1+index of the highest event number */
	static au_event_ent_t **index_tbl;
	static au_event_ent_t **p_tbl;
	static int	called_once = 0;

	char	line[AU_EVENT_LINE_MAX];
	int	lines = 0;
	FILE	*fp;
	au_event_ent_t *p_event;
	int	i, size;
	int	hit = 0;
	char	*s;

	(void) mutex_lock(&mutex_eventcache);
	if (called_once == 0) {

		/* Count number of lines in the events file */
		if ((fp = fopen(au_event_fname, "rF")) == NULL) {
			(void) mutex_unlock(&mutex_eventcache);
			return (-1);
		}
		while (fgets(line, AU_EVENT_LINE_MAX, fp) != NULL) {
			s = line + strspn(line, " \t\r\n");
			if ((*s == '\0') || (*s == '#')) {
				continue;
			}
			lines++;
		}
		(void) fclose(fp);
		size = lines;

		/*
		 * Make an array in which each element in an entry in the
		 * events file.  Make the next to last element an invalid
		 * event.  Make the last element a NULL pointer.
		 */

		p_tbl = calloc(lines + 1, sizeof (au_event_ent_t));
		if (p_tbl == NULL) {
			(void) mutex_unlock(&mutex_eventcache);
			return (-2);
		}
		lines = 0;
		max = 0;
		min = 65535;
		setauevent();
		while ((p_event = getauevent()) != NULL) {
			p_tbl[lines] = (au_event_ent_t *)
			    malloc(sizeof (au_event_ent_t));
			if (p_tbl[lines] == NULL) {
				(void) mutex_unlock(&mutex_eventcache);
				return (-3);
			}
			p_tbl[lines]->ae_number = p_event->ae_number;
			p_tbl[lines]->ae_name   = strdup(p_event->ae_name);
			p_tbl[lines]->ae_desc   = strdup(p_event->ae_desc);
			p_tbl[lines]->ae_class  = p_event->ae_class;
#ifdef DEBUG2
			printevent(p_tbl[lines]);
#endif
			if (p_event->ae_number > max) {
				max = p_event->ae_number;
			}
			if (p_event->ae_number < min) {
				min = p_event->ae_number;
			}
			lines++;
		}
		endauevent();
		invalid = lines;
		p_tbl[invalid] = (au_event_ent_t *)
		    malloc(sizeof (au_event_ent_t));
		if (p_tbl[invalid] == NULL) {
			(void) mutex_unlock(&mutex_eventcache);
			return (-4);
		}
		p_tbl[invalid]->ae_number = (au_event_t)-1;
		p_tbl[invalid]->ae_name   = "invalid event number";
		p_tbl[invalid]->ae_desc   = p_tbl[invalid]->ae_name;
		p_tbl[invalid]->ae_class  = (au_class_t)-1;

#ifdef DEBUG2
		for (i = 0; i < size; i++) {
			(void) printf("%d:%s:%s:%d\n", p_tbl[i]->ae_number,
			    p_tbl[i]->ae_name, p_tbl[i]->ae_desc,
			    p_tbl[i]->ae_class);
		}
#endif

		/* get space for the index_tbl */
		index_tbl = calloc(max+1, sizeof (au_event_ent_t *));
		if (index_tbl == NULL) {
			(void) mutex_unlock(&mutex_eventcache);
			return (-5);
		}

		/* intialize the index_tbl to the invalid event number */
		for (i = 0; (au_event_t)i < max; i++) {
			index_tbl[i] = p_tbl[invalid];
		}

		/* point each index_tbl element at the corresponding event */
		for (i = 0; i < size; i++) {
			index_tbl[p_tbl[i]->ae_number] = p_tbl[i];
		}

		called_once = 1;

	}

	if (event_number > max || event_number < min) {
		*result = index_tbl[invalid];
	} else {
		*result = index_tbl[event_number];
		hit = 1;
	}
	(void) mutex_unlock(&mutex_eventcache);
	return (hit);
}

static au_class_t
flagstohex(char *flags)
{
	au_class_ent_t *p_class;
	au_class_t	hex = 0;
	char	*comma = ",";
	char	*s;
	char	*last;

	s = strtok_r(flags, comma, &last);
	while (s != NULL) {
		if ((cacheauclassnam(&p_class, s)) < 0) {
			cacheauclass_failure = 1;
			return ((au_class_t)-1);
		}
		hex |= p_class->ac_class;
		s = strtok_r(NULL, comma, &last);
	}
	return (hex);
}
