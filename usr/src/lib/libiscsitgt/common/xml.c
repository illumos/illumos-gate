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
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <inttypes.h>
#include <assert.h>
#include <libxml/xmlreader.h>
#include <strings.h>
#include <ctype.h>
#include <stdlib.h>
#include <syslog.h>
#include <sys/stat.h>

#include "iscsitgt_impl.h"

/*
 * Forward declarations
 */
static char *strip_space(char *value);
static tgt_node_t *node_alloc();
static void node_free(tgt_node_t *x);
static Boolean_t node_name(tgt_node_t *x, const xmlChar *n);
static Boolean_t node_value(tgt_node_t *x, const xmlChar *n, Boolean_t s);
static tgt_node_t *node_parent(tgt_node_t *x);
static tgt_node_t *node_child(tgt_node_t *x);
static tgt_node_t *node_alloc_attr(tgt_node_t *x);
static void buf_add_node_attr(char **b, tgt_node_t *x);
static void buf_add_comment(char **b, char *comment);
static void buf_add_str(char **b, char *str);

#define	XML_COMMENT_STR	"!--"
#define	XML_COMMENT_END "--"

void
tgt_node_free(tgt_node_t *n)
{
	tgt_node_t	*c;
	tgt_node_t	*c1;

	if (n == NULL)
		return;
	for (c = n->x_child; c; ) {
		c1 = c->x_sibling;
		tgt_node_free(c);
		c = c1;
	}
	for (c = n->x_attr; c; ) {
		c1 = c->x_sibling;
		node_free(c);
		c = c1;
	}
	node_free(n);

}

/*
 * tgt_dump2buf -- dumps node tree to buffer, allocating memory as it goes
 *
 * It is up to the caller, when finished with 'buf', to call free()
 */
void
tgt_dump2buf(tgt_node_t *n, char **buf)
{
	tgt_node_t	*c;

	if (n == NULL)
		return;
	if (strcmp(n->x_name, XML_COMMENT_STR) == 0) {
		buf_add_comment(buf, n->x_value);
		return;
	}
	buf_add_node_attr(buf, n);
	if (n->x_value != NULL)
		tgt_buf_add_tag(buf, n->x_value, Tag_String);
	for (c = n->x_child; c; c = c->x_sibling)
		tgt_dump2buf(c, buf);
	tgt_buf_add_tag(buf, n->x_name, Tag_End);
}

char *common_attr_list[] = {
	XML_ELEMENT_NAME,
	XML_ELEMENT_VERS,
	XML_ELEMENT_INCORE,
	0
};

Boolean_t
tgt_node_process(xmlTextReaderPtr r, tgt_node_t **node)
{
	const xmlChar	*name;
	const xmlChar	*value;
	char		**ap;
	xmlElementType	node_type;
	tgt_node_t	*n;
	tgt_node_t	*an;

	n = *node;
	if (n == NULL) {
		n = node_alloc();
		if (n == NULL)
			return (False);
		*node = n;
	}

	name = (xmlChar *)xmlTextReaderConstName(r);
	if (name == NULL) {
		node_free(n);
		*node = NULL;
		return (False);
	}

	node_type = (xmlElementType)xmlTextReaderNodeType(r);

	value = (xmlChar *)xmlTextReaderConstValue(r);

	if (node_type == XML_ELEMENT_NODE) {
		if (n->x_state != NodeAlloc) {
			n = node_child(n);
			*node = n;
			if (n == NULL)
				return (False);
		}
		if (xmlTextReaderAttributeCount(r) > 0) {

			for (ap = common_attr_list; *ap; ap++) {
				value = xmlTextReaderGetAttribute(r,
				    (xmlChar *)*ap);

				if (value != NULL) {
					if ((an = node_alloc_attr(n)) == NULL)
						return (False);
					if (node_name(an, (xmlChar *)*ap) ==
					    False) {
						node_free(an);
						return (False);
					}
					if (node_value(an, value, True) ==
					    False) {
						node_free(an);
						return (False);
					}
					free((char *)value);
				}
			}
		}

		if (node_name(n, name) == False) {
			node_free(n);
			*node = NULL;
			return (False);
		}
	} else if ((value != NULL) && (node_type == XML_TEXT_NODE)) {
		if (node_value(n, value, True) == False) {
			node_free(n);
			*node = NULL;
			return (False);
		}
	} else if (node_type == XML_ELEMENT_DECL) {
		n = node_parent(n);
		if (n == NULL)
			return (False);
		*node = n;
	} else if (node_type == XML_COMMENT_NODE) {
		n = node_child(n);
		if (node_name(n, (xmlChar *)XML_COMMENT_STR) == False) {
			node_free(n);
			*node = NULL;
			return (False);
		}
		if (node_value(n, (xmlChar *)value, False) == False) {
			node_free(n);
			*node = NULL;
			return (False);
		}
	} else if (node_type != XML_DTD_NODE) {
		node_free(n);
		*node = NULL;
		return (False);
	}
	return (True);
}

Boolean_t
tgt_find_attr_str(tgt_node_t *n, char *attr, char **value)
{
	tgt_node_t	*a;

	if ((n == NULL) || (n->x_attr == NULL))
		return (False);

	for (a = n->x_attr; a; a = a->x_sibling)
		if (strcmp(a->x_name, attr) == 0) {
			*value = a->x_value ? strdup(a->x_value) : NULL;
			return (True);
		}
	return (False);
}

Boolean_t
tgt_find_value_str(tgt_node_t *n, char *name, char **value)
{
	tgt_node_t	*c;

	if ((n == NULL) || (n->x_name == NULL))
		return (False);

	if (strcmp(n->x_name, name) == 0) {
		*value = n->x_value ? strdup(n->x_value) : NULL;
		return (True);
	}
	for (c = n->x_child; c; c = c->x_sibling) {
		if (tgt_find_value_str(c, name, value) == True)
			return (True);
	}
	return (False);
}

Boolean_t
tgt_find_value_int(tgt_node_t *n, char *name, int *value)
{
	tgt_node_t	*c;

	if ((n == NULL) || (n->x_name == NULL))
		return (False);

	if (strcmp(n->x_name, name) == 0) {
		if (n->x_value == NULL)
			return (False);
		*value = strtol(n->x_value, NULL, 0);
		return (True);
	}
	for (c = n->x_child; c; c = c->x_sibling) {
		if (tgt_find_value_int(c, name, value) == True)
			return (True);
	}
	return (False);
}

/*
 * []----
 * | xml_find_value_intchk -- if node exists, check to see if value is okay
 * []----
 */
Boolean_t
tgt_find_value_intchk(tgt_node_t *n, char *name, int *value)
{
	char		*str;
	char		chk[32];
	Boolean_t	rval;

	if (tgt_find_value_str(n, name, &str) == True) {

		*value = strtol(str, NULL, 0);
		/*
		 * Validate that the input string hasn't overrun what
		 * what an integer can handle. This is done by simply
		 * printing out the result of the conversion into a buffer
		 * and comparing it to the incoming string. That way when
		 * someone enters 4294967296 which strtol returns as 0
		 * we'll catch it.
		 */
		if ((str[0] == '0') && (str[1] != '\0')) {
			if (str[1] == 'x')
				(void) snprintf(chk, sizeof (chk), "0x%x",
				    *value);
			else if (str[1] == 'X')
				(void) snprintf(chk, sizeof (chk), "0X%x",
				    *value);
			else
				(void) snprintf(chk, sizeof (chk), "0%o",
				    *value);
		} else
			(void) snprintf(chk, sizeof (chk), "%d", *value);
		if (strcmp(chk, str) == 0)
			rval = True;
		else
			rval = False;
		free(str);
		return (rval);
	} else
		return (True);
}

Boolean_t
tgt_find_value_boolean(tgt_node_t *n, char *name, Boolean_t *value)
{
	tgt_node_t	*c;

	if ((n == NULL) || (n->x_name == NULL))
		return (False);

	if (strcmp(n->x_name, name) == 0) {
		if (n->x_value == NULL)
			return (False);
		*value = strcmp(n->x_value, "true") == 0 ? True : False;
		return (True);
	}
	for (c = n->x_child; c; c = c->x_sibling) {
		if (tgt_find_value_boolean(c, name, value) == True)
			return (True);
	}
	return (False);
}

tgt_node_t *
tgt_node_next(tgt_node_t *n, char *name, tgt_node_t *cur)
{
	tgt_node_t	*x;
	tgt_node_t	*p;

	if (n == NULL)
		return (NULL);

	if (cur != NULL) {
		for (x = cur->x_sibling; x; x = x->x_sibling)
			if (strcmp(x->x_name, name) == 0)
				return (x);
		return (NULL);
	}

	if (n->x_name == NULL)
		return (NULL);

	if (strcmp(n->x_name, name) == 0)
		return (n);
	for (x = n->x_child; x; x = x->x_sibling)
		if ((p = tgt_node_next(x, name, 0)) != NULL)
			return (p);
	return (NULL);
}

tgt_node_t *
tgt_node_next_child(tgt_node_t *n, char *name, tgt_node_t *cur)
{
	if (cur != NULL) {
		n = cur->x_sibling;
	} else {
		if (n != NULL)
			n = n->x_child;
		else
			return (NULL);
	}
	while (n) {
		if (strcmp(n->x_name, name) == 0)
			return (n);
		n = n->x_sibling;
	}
	return (NULL);
}

void
tgt_node_add(tgt_node_t *p, tgt_node_t *c)
{
	if ((p == NULL) || (c == NULL))
		return;

	c->x_parent = p;
	if (p->x_child == NULL)
		p->x_child = c;
	else {
		c->x_sibling = p->x_child;
		p->x_child = c;
	}
}

void
tgt_node_add_attr(tgt_node_t *p, tgt_node_t *a)
{
	if ((p == NULL) || (a == NULL))
		return;

	if (p->x_attr == NULL)
		p->x_attr = a;
	else {
		a->x_sibling = p->x_attr;
		p->x_attr = a;
	}
}

tgt_node_t *
tgt_node_alloc(char *name, xml_val_type_t type, void *value)
{
	tgt_node_t	*d		= node_alloc();
	int		value_len	= 0;
	char		*value_str	= NULL;

	if (d == NULL)
		return (NULL);
	switch (type) {
	case String:
		if (value)
			value_len = strlen((char *)value) + 1;
		break;
	case Int:
		value_len = sizeof (int) * 2 + 3;
		break;
	case Uint64:
		value_len = sizeof (uint64_t) * 2 + 3;
		break;
	}
	if (value_len &&
	    (value_str = (char *)calloc(sizeof (char), value_len)) == NULL)
		return (NULL);
	if (node_name(d, (xmlChar *)name) == False) {
		free(value_str);
		return (NULL);
	}
	if (value_str) {
		switch (type) {
		case String:
			(void) snprintf(value_str, value_len, "%s",
			    (char *)value);
			break;
		case Int:
			(void) snprintf(value_str, value_len, "%d",
			    *(int *)value);
			break;
		case Uint64:
			(void) snprintf(value_str, value_len, "0x%llx",
			    *(uint64_t *)value);
			break;
		}
	}
	(void) node_value(d, (xmlChar *)value_str, True);
	free(value_str);

	return (d);
}

Boolean_t
tgt_xml_encode(uint8_t *ip, size_t ip_size, char **buf, size_t *buf_size)
{
	char *bp;
	*buf_size = (ip_size * 2) + 1;

	if ((*buf = (char *)malloc(*buf_size)) == NULL) {
		*buf_size = 0;
		return (False);
	}

	for (bp = *buf; ip_size; ip_size--) {
		(void) sprintf(bp, "%.2x", *ip);
		ip++;
		bp += 2;
	}

	/* make it null terminated */
	*bp = 0;

	return (True);
}

Boolean_t
tgt_xml_decode(char *buf, uint8_t **ip, size_t *ip_size)
{
	uint8_t *i;
	size_t buf_size = strlen(buf);
	*ip_size = buf_size / 2;

	if ((*ip = (uint8_t *)malloc(*ip_size)) == NULL) {
		*ip_size = 0;
		return (False);
	}

	for (i = *ip; buf_size; buf_size -= 2) {
		char x[3];
		bcopy(buf, x, 2);
		x[2] = 0;
		*i++ = strtol(x, NULL, 16);
		buf += 2;
	}
	return (True);
}

Boolean_t
tgt_node_remove(tgt_node_t *parent, tgt_node_t *child, match_type_t m)
{
	tgt_node_t	*s;
	tgt_node_t	*c	= NULL;

	if ((parent == NULL) || (child == NULL))
		return (False);

	for (s = parent->x_child; s; c = s, s = s->x_sibling) {

		/*
		 * See if the new child node matches one of the children
		 * in the parent.
		 */
		if ((strcmp(s->x_name, child->x_name) == 0) &&
		    ((m == MatchName) || (strcmp(s->x_value,
		    child->x_value) == 0))) {

			if (parent->x_child == s) {
				parent->x_child = s->x_sibling;
			} else {
				c->x_sibling = s->x_sibling;
			}
			tgt_node_free(s);
			break;
		}
	}
	if (s == NULL)
		return (False);
	else
		return (True);
}

void
tgt_node_replace(tgt_node_t *parent, tgt_node_t *child, match_type_t m)
{
	tgt_node_t	*s;
	tgt_node_t	*c;

	if ((parent == NULL) || (child == NULL))
		return;

	for (s = parent->x_child; s; s = s->x_sibling) {

		/*
		 * See if the new child node matches one of the children
		 * in the parent.
		 */
		if ((strcmp(s->x_name, child->x_name) == 0) &&
		    ((m == MatchName) || (strcmp(s->x_value,
		    child->x_value) == 0))) {

			/*
			 * We have a match. Now save the values of the new
			 * child in this current node.
			 */
			free(s->x_name);
			free(s->x_value);
			s->x_name	= strdup(child->x_name);
			s->x_value	= strdup(child->x_value);
			if (s->x_child) {
				tgt_node_free(s->x_child);
				s->x_child = NULL;
			}
			for (c = child->x_child; c; c = c->x_sibling)
				(void) tgt_node_add(s, tgt_node_dup(c));
			break;
		}
	}

	if (s == NULL) {
		/*
		 * Never found the child so add it
		 */
		(void) tgt_node_add(parent, tgt_node_dup(child));
	}
}

Boolean_t
tgt_update_value_str(tgt_node_t *node, char *name, char *str)
{
	if ((node == NULL) || (strcmp(name, node->x_name) != 0))
		return (False);
	if (node->x_value != NULL)
		free(node->x_value);
	node->x_value = strdup(str);
	node->x_state = NodeValue;
	return (True);
}

tgt_node_t *
tgt_node_find(tgt_node_t *n, char *name)
{
	tgt_node_t	*rval;

	for (rval = n->x_child; rval; rval = rval->x_sibling)
		if (strcmp(rval->x_name, name) == 0)
			break;
	return (rval);
}

tgt_node_t *
tgt_node_dup(tgt_node_t *n)
{
	tgt_node_t	*d = node_alloc();
	tgt_node_t	*c;

	if (d == NULL)
		return (NULL);
	if (node_name(d, (xmlChar *)n->x_name) == False)
		return (NULL);
	if (n->x_value && (node_value(d, (xmlChar *)n->x_value, True) == False))
		return (NULL);
	for (c = n->x_child; c; c = c->x_sibling)
		(void) tgt_node_add(d, tgt_node_dup(c));
	for (c = n->x_attr; c; c = c->x_sibling)
		(void) tgt_node_add_attr(d, tgt_node_dup(c));
	return (d);
}

#define	MAX_REPLACEMENT_ENTITY	8
#define	MAX_REPLACEMENT_BUFFER	1024
void
tgt_buf_add(char **b, char *element, const char *cdata)
{
	char	entity[MAX_REPLACEMENT_ENTITY];
	char	buf[MAX_REPLACEMENT_BUFFER];
	int	len, i;

	bzero(buf, sizeof (buf));

	tgt_buf_add_tag(b, element, Tag_Start);
	/*
	 * we have to transform the predefined xml entities;
	 */
	if (cdata != NULL) {
		len = strlen(cdata);
		for (i = 0; i < len; i++) {
			switch (cdata[i]) {
			case '&':
				(void) strcpy(entity, "&amp;");
				break;
			case '<':
				(void) strcpy(entity, "&lt;");
				break;
			case '>':
				(void) strcpy(entity, "&gt;");
				break;
			case '\'':
				(void) strcpy(entity, "&apos;");
				break;
			case '"':
				(void) strcpy(entity, "&quot;");
				break;
			default:
				entity[0] = cdata[i];
				entity[1] = '\0';
				break;
			}
			(void) strlcat(buf, entity, sizeof (buf));
		}
		tgt_buf_add_tag(b, buf, Tag_String);
	}
	tgt_buf_add_tag(b, element, Tag_End);
}

/*
 * []----
 * | tgt_buf_add_tag -- adds string to buffer allocating space, sets up tags too
 * |
 * | Helper function to build a string by allocating memory as we go.
 * | If the string argument 'str' is defined to be a start or end tag
 * | as declared by 'type' argument add the appropriate characters.
 * []----
 */
void
tgt_buf_add_tag(char **b, const char *str, val_type_t type)
{
	char	*buf;
	int	len;

	/*
	 * We will add potentially up to 3 extra characters plus the NULL byte
	 */
	len = strlen(str) + 4;
	if ((buf = malloc(len)) == NULL)
		return;

	(void) snprintf(buf, len, "%s%s%s%s", type == Tag_String ? "" : "<",
	    type == Tag_End ? "/" : "", str, type == Tag_String ? "" : ">");
	buf_add_str(b, buf);
	free(buf);
}

/*
 * []----
 * | tgt_buf_add_tag_and_attr -- variant on tgt_buf_add_tag which also gives
 * |    attr
 * []----
 */
void
tgt_buf_add_tag_and_attr(char **b, char *str, char *attr)
{
	char	*buf;
	int	len;

	/*
	 * In addition to the 'str' and 'attr' strings the code will add
	 * three characters plus a null byte.
	 */
	len = strlen(str) + strlen(attr) + 4;
	if ((buf = malloc(len)) == NULL)
		return;

	(void) snprintf(buf, len, "<%s %s>", str, attr);
	buf_add_str(b, buf);
	free(buf);
}

/*
 * []----
 * | Utility functions
 * []----
 */
static tgt_node_t *
node_alloc()
{
	tgt_node_t	*x = (tgt_node_t *)calloc(sizeof (tgt_node_t), 1);

	if (x == NULL)
		return (NULL);

	x->x_state = NodeAlloc;
	return (x);
}

static void
node_free(tgt_node_t *x)
{
	x->x_state = NodeFree;
	if (x->x_name)
		free(x->x_name);
	if (x->x_value)
		free(x->x_value);
	free(x);
}

static Boolean_t
node_name(tgt_node_t *x, const xmlChar *n)
{
	assert(x->x_state == NodeAlloc);
	if ((n == NULL) || (strlen((char *)n) == 0))
		return (False);

	x->x_state = NodeName;
	x->x_name = strip_space((char *)n);
	return (True);
}

static Boolean_t
node_value(tgt_node_t *x, const xmlChar *n, Boolean_t do_strip)
{
	assert(x->x_state == NodeName);
	if ((n == NULL) || (strlen((char *)n) == NULL))
		return (False);

	x->x_state = NodeValue;
	x->x_value = (do_strip == True) ?
	    strip_space((char *)n) : strdup((char *)n);
	return (True);
}

static tgt_node_t *
node_parent(tgt_node_t *x)
{
	return (x->x_parent);
}

static tgt_node_t *
node_child(tgt_node_t *x)
{
	tgt_node_t	*n;

	if ((n = node_alloc()) == NULL)
		return (NULL);

	if (x->x_child == NULL) {
		x->x_child = n;
	} else {
		n->x_sibling = x->x_child;
		x->x_child = n;
	}
	n->x_parent = x;
	return (n);
}

static tgt_node_t *
node_alloc_attr(tgt_node_t *x)
{
	tgt_node_t	*n;
	tgt_node_t	*next;

	n = node_alloc();
	if (x->x_attr == NULL) {
		x->x_attr = n;
	} else {
		for (next = x->x_attr; next->x_sibling; next = next->x_sibling)
			;
		next->x_sibling = n;
	}
	if (n != NULL)
		n->x_parent = x;
	return (n);
}

static void
buf_add_str(char **b, char *str)
{
	int	len;
	int	olen	= 0;
	char	*p = *b;

	/*
	 * Make sure we have enough room for the string and tag characters
	 * plus a NULL byte.
	 */
	if (str == NULL)
		return;

	len = strlen(str) + 1;
	if (p == NULL) {
		if ((p = malloc(len)) == NULL)
			return;
	} else {
		olen = strlen(p);
		p = realloc(p, olen + len);
	}
	(void) strncpy(p + olen, str, len);
	*b = p;
}

static void
buf_add_node_attr(char **b, tgt_node_t *x)
{
	char		*buf;
	tgt_node_t	*n;
	int		len;

	/* ---- null byte and starting '<' character ---- */
	len = strlen(x->x_name) + 2;
	if ((buf = malloc(len)) == NULL)
		return;
	(void) snprintf(buf, len, "<%s", x->x_name);
	buf_add_str(b, buf);
	free(buf);

	for (n = x->x_attr; n; n = n->x_sibling) {
		len = strlen(n->x_name) + strlen(n->x_value) + 5;
		if ((buf = malloc(len)) == NULL)
			return;
		(void) snprintf(buf, len, " %s='%s'", n->x_name, n->x_value);
		buf_add_str(b, buf);
		free(buf);
	}
	buf_add_str(b, ">");
}

static void
buf_add_comment(char **b, char *comment)
{
	char	*p	= *b;
	int	len;
	int	olen;

	if (comment == NULL)
		return;

	/*
	 * Room for the strings, plus the brackets and NULL byte
	 */
	len = strlen(comment) + strlen(XML_COMMENT_STR) +
	    strlen(XML_COMMENT_END) + 3;

	if (p == NULL)
		p = malloc(len);
	else {
		olen = strlen(p);
		p = realloc(p, olen + len);
	}
	(void) snprintf(p + olen, len, "<%s%s%s>", XML_COMMENT_STR, comment,
	    XML_COMMENT_END);
	*b = p;
}

static char *
strip_space(char *value)
{
	char	*p;
	char	*n;

	for (p = value; p && *p; p++)
		if (!isspace(*p))
			break;
	if ((p == NULL) || (*p == '\0'))
		return (NULL);

	p = strdup(p);
	for (n = (p + strlen(p) - 1); n >= p; n--)
		if (!isspace(*n)) {
			n++;
			break;
		}
	*n = '\0';
	return (p);
}
