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
 * Copyright (c) 2005, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <sys/kobj.h>
#include <sys/kobj_lex.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/acpi/acpi.h>
#include <sys/acpica.h>

#define	masterfile "/boot/solaris/devicedb/master"

/*
 * Internal definitions
 */

typedef enum {
	MF_UNEXPECTED = -1,
	MF_IDENT,
	MF_STRING,
	MF_EOF,
	MF_NEWLINE,
	MF_EQUALS,
	MF_BIT_OR
} mftoken_t;

typedef enum {
	MF_INIT,
	MF_DEVID,
	MF_NAME,
	MF_DEVTYPE,
	MF_BUSTYPE,
	MF_BEFNAME,
	MF_DESCRIPTION,
	MF_PROPNAME,
	MF_PROPASSIGN,
	MF_PROPVAL,
	MF_VERSION_DONE,
	MF_VALID_DONE,
	MF_ERROR_DONE
} mfparse_t;


static master_rec_t *master_list = NULL;

device_id_t *
mf_alloc_device_id()
{
	return ((device_id_t *)kmem_zalloc(sizeof (device_id_t), KM_SLEEP));
}

void
mf_free_device_id(device_id_t *d)
{
	if (d->id != NULL)
		strfree(d->id);

	kmem_free(d, sizeof (device_id_t));
}

static property_t *
mf_alloc_property()
{
	return ((property_t *)kmem_zalloc(sizeof (property_t), KM_SLEEP));
}

static void
mf_free_property(property_t *p)
{
	if (p->name != NULL)
		strfree(p->name);

	if (p->value != NULL)
		strfree(p->value);

	kmem_free(p, sizeof (property_t));
}

static master_rec_t *
mf_alloc_master_rec()
{
	return ((master_rec_t *)kmem_zalloc(sizeof (master_rec_t), KM_SLEEP));
}

static void
mf_free_master_rec(master_rec_t *m)
{
	device_id_t *d;
	property_t *p;

	if (m->name != NULL)
		strfree(m->name);

	if (m->description != NULL)
		strfree(m->description);

	d = m->device_ids;
	while (d != NULL) {
		device_id_t *next;

		next = d->next;
		mf_free_device_id(d);
		d = next;
	}

	p = m->properties;
	while (p != NULL) {
		property_t *next;

		next = p->next;
		mf_free_property(p);
		p = next;
	}

	kmem_free(m, sizeof (master_rec_t));
}

void
free_master_data()
{
	master_rec_t *m;

	m = master_list;
	while (m != NULL) {
		master_rec_t *next;

		next = m->next;
		mf_free_master_rec(m);
		m = next;
	}
	master_list = NULL;
}

/*
 * Unfortunately, kobj_lex() is too sophisticated for our needs
 */
static mftoken_t
mf_lex(struct _buf *file, char *val, size_t size)
{
	char *cp;
	int ch, badquote;
	size_t remain;
	mftoken_t token = MF_UNEXPECTED;

	if (size < 2)
		return (token);	/* MF_UNEXPECTED */

	cp = val;

	/* skip leading whitespace */
	while ((ch = kobj_getc(file)) == ' ' || ch == '\t')
		;

	/* strip comments */
	if (ch == '#') {
		while ((ch = kobj_getc(file)) != '\n' && ch != '\r' &&
		    ch != -1)
			;
	}

	remain = size - 1;
	*cp++ = (char)ch;
	switch (ch) {
	case -1:
		token = MF_EOF;
		break;
	case '\n':
	case '\r':
		token = MF_NEWLINE;
		break;
	case '=':
		token = MF_EQUALS;
		break;
	case '|':
		token = MF_BIT_OR;
		break;
	case '"':
		remain++;
		cp--;
		badquote = 0;
		while (!badquote && (ch  = kobj_getc(file)) != '"') {
			switch (ch) {
			case '\n':
			case -1:
				remain = size - 1;
				cp = val;
				*cp++ = '\n';
				badquote = 1;
				/* since we consumed the newline/EOF */
				(void) kobj_ungetc(file);
				break;
			default:
				if (--remain == 0) {
					token = MF_UNEXPECTED;
					goto out;
				}
				*cp++ = (char)ch;
				break;
			}
		}
		token = MF_STRING;
		break;
	default:
		do {
			if (--remain == 0) {
				token = MF_UNEXPECTED;
				break;
			}

			token = MF_IDENT;
			*cp++ = (char)(ch = kobj_getc(file));

			/* if terminating character, break out */
			if ((ch == -1) || (ch == ' ') || (ch == '\t') ||
			    (ch == '\n') || (ch == '\r') || (ch == '=') ||
			    (ch == '|')) {
				(void) kobj_ungetc(file);
				remain++;
				cp--;
				break;
			}

			if ((ch == '#') || (ch == '"'))
				token = MF_UNEXPECTED;
		} while (token != MF_UNEXPECTED);
		break;
	}
out:
	*cp = '\0';

	return (token);
}

static master_rec_t *
get_line(struct _buf *file)
{
	master_rec_t *m = NULL;
	device_id_t *d = NULL;
	property_t *p = NULL;
	mftoken_t token;
	char tokval[MAXPATHLEN];
	mfparse_t parse_state;

	parse_state = MF_INIT;
	token = mf_lex(file, tokval, sizeof (tokval));
	while (token != MF_EOF) {
		switch (parse_state) {
		case MF_INIT:
			m = mf_alloc_master_rec();
			parse_state = MF_DEVID;
			/*FALLTHROUGH*/
		case MF_DEVID:
			if (token == MF_IDENT) {
				d = mf_alloc_device_id();
				d->id = strdup(tokval);
				d->next = m->device_ids;
				m->device_ids = d;
				parse_state = MF_NAME;
			} else if (token != MF_NEWLINE)
				parse_state = MF_ERROR_DONE;
			break;
		case MF_NAME:
			if (token == MF_IDENT) {
				m->name = strdup(tokval);
				parse_state = MF_DEVTYPE;
			} else if (token == MF_BIT_OR) {
				parse_state = MF_DEVID;
			} else
				parse_state = MF_ERROR_DONE;
			break;
		case MF_DEVTYPE:
			if (token == MF_IDENT) {
				/* device_type not used */
				parse_state = MF_BUSTYPE;
			} else if (token == MF_NEWLINE) {
				/* version line ignored */
				parse_state = MF_VERSION_DONE;
			} else
				parse_state = MF_ERROR_DONE;
			break;
		case MF_BUSTYPE:
			if (token == MF_IDENT) {
				/* bus_type ignored */
				parse_state = MF_BEFNAME;
			} else
				parse_state = MF_ERROR_DONE;
			break;
		case MF_BEFNAME:
			if (token == MF_IDENT) {
				/* realmode driver name ignored */
				parse_state = MF_DESCRIPTION;
			} else
				parse_state = MF_ERROR_DONE;
			break;
		case MF_DESCRIPTION:
			if (token == MF_STRING) {
				m->description = strdup(tokval);
				parse_state = MF_PROPNAME;
			} else
				parse_state = MF_ERROR_DONE;
			break;
		case MF_PROPNAME:
			if (token == MF_IDENT) {
				p = mf_alloc_property();
				p->name = strdup(tokval);
				parse_state = MF_PROPASSIGN;
			} else if (token == MF_NEWLINE) {
				parse_state = MF_VALID_DONE;
			} else
				parse_state = MF_ERROR_DONE;
			break;
		case MF_PROPASSIGN:
			if (token == MF_EQUALS) {
				parse_state = MF_PROPVAL;
			} else
				parse_state = MF_ERROR_DONE;
			break;
		case MF_PROPVAL:
			if (token == MF_STRING || token == MF_IDENT) {
				p->value = strdup(tokval);
				p->next = m->properties;
				/* delete properties which begin with '$' */
				if (*p->name == '$') {
					mf_free_property(p);
				} else
					m->properties = p;
				p = NULL;
				parse_state = MF_PROPNAME;
			} else
				parse_state = MF_ERROR_DONE;
			break;
		case MF_VERSION_DONE:
		case MF_VALID_DONE:
		case MF_ERROR_DONE:
			/* terminating states handled outside switch() */
			break;
		}

		if (parse_state == MF_VERSION_DONE) {
			/* ignore version line */
			mf_free_master_rec(m);
			parse_state = MF_INIT;
		} else if (parse_state == MF_VALID_DONE) {
			/* valid line */
			break;
		} else if (parse_state == MF_ERROR_DONE) {
			mf_free_master_rec(m);
			if (p != NULL)
				mf_free_property(p);
			/*
			 * Error in master file.  Should never happen
			 * since master file is not user-edited.  Eat rest
			 * of line to attempt error recovery
			 */
			cmn_err(CE_NOTE, "!error in %s", masterfile);
			while (token != MF_NEWLINE && token != MF_EOF)
				token = mf_lex(file, tokval, sizeof (tokval));
			parse_state = MF_INIT;
			continue;
		}

		token = mf_lex(file, tokval, sizeof (tokval));
	}

	return (m);
}

void
process_master_file()
{
	struct _buf *file;
	master_rec_t *m;

	if ((file = kobj_open_file(masterfile)) == (struct _buf *)-1) {
		cmn_err(CE_WARN, "!cannot open master file: %s", masterfile);
		return;
	}

	while ((m = get_line(file)) != NULL) {
		m->next = master_list;
		master_list = m;
	}

	kobj_close_file(file);
}

/*
 * Return the first master file record found matching pnpid list
 */
const master_rec_t *
master_file_lookup(device_id_t *pnpid)
{
	master_rec_t *m;
	device_id_t *d;

	while (pnpid != NULL) {
		m = master_list;
		while (m != NULL) {
			d = m->device_ids;
			while (d != NULL) {
				if (strcmp(pnpid->id, d->id) == 0)
					return (m);
				d = d->next;
			}
			m = m->next;
		}
		pnpid = pnpid->next;
	}

	return (NULL);
}
