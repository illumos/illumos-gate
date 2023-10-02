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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sys/openpromio.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>			/* sprintf() */
#include <unistd.h>

/*
 * opp_zalloc(): allocates and initializes a struct openpromio
 *
 *   input: size_t: the size of the variable-length part of the openpromio
 *          const char *: an initial value for oprom_array, if non-NULL
 *  output: struct openpromio: the allocated, initialized openpromio
 */

static struct openpromio *
opp_zalloc(size_t size, const char *prop)
{
	struct openpromio *opp = malloc(sizeof (struct openpromio) + size);

	if (opp != NULL) {
		(void) memset(opp, 0, sizeof (struct openpromio) + size);
		opp->oprom_size = size;
		if (prop != NULL)
			(void) strcpy(opp->oprom_array, prop);
	}
	return (opp);
}

/*
 * goto_rootnode(): moves to the root of the devinfo tree
 *
 *   input: int: an open descriptor to /dev/openprom
 *  output: int: nonzero on success
 */

static int
goto_rootnode(int prom_fd)
{
	struct openpromio op = { sizeof (int), 0 };

	/* zero it explicitly since a union is involved */
	op.oprom_node = 0;
	return (ioctl(prom_fd, OPROMNEXT, &op) == 0);
}

/*
 * return_property(): returns the value of a given property
 *
 *   input: int: an open descriptor to /dev/openprom
 *          const char *: the property to look for in the current devinfo node
 *  output: the value of that property (dynamically allocated)
 */

static char *
return_property(int prom_fd, const char *prop)
{
	int			proplen;
	char			*result;
	struct openpromio	*opp = opp_zalloc(strlen(prop) + 1, prop);

	if (opp == NULL)
		return (NULL);

	if (ioctl(prom_fd, OPROMGETPROPLEN, opp) == -1) {
		free(opp);
		return (NULL);
	}

	proplen = opp->oprom_len;
	if (proplen > (strlen(prop) + 1)) {
		free(opp);
		opp = opp_zalloc(proplen, prop);
		if (opp == NULL)
			return (NULL);
	}

	if (ioctl(prom_fd, OPROMGETPROP, opp) == -1) {
		free(opp);
		return (NULL);
	}

	result = strdup(opp->oprom_array);
	free(opp);
	return (result);
}

/*
 * sanitize_class_id(): translates the class id into a canonical format,
 *			so that it can be used easily with dhcptab(5).
 *
 *   input: char *: the class id to canonicalize
 *  output: void
 */

static void
sanitize_class_id(char *src_ptr)
{
	char	*dst_ptr = src_ptr;

	/* remove all spaces and change all commas to periods */
	while (*src_ptr != '\0') {

		switch (*src_ptr) {

		case ' ':
			break;

		case ',':
			*dst_ptr++ = '.';
			break;

		default:
			*dst_ptr++ = *src_ptr;
			break;
		}
		src_ptr++;
	}
	*dst_ptr = '\0';
}

/*
 * get_class_id(): retrieves the class id from the prom, then canonicalizes it
 *
 *   input: void
 *  output: char *: the class id (dynamically allocated and sanitized)
 */

char *
get_class_id(void)
{
	int	prom_fd;
	char    *name, *class_id = NULL;
	size_t	len;

	prom_fd = open("/dev/openprom", O_RDONLY);
	if (prom_fd == -1)
		return (NULL);

	if (goto_rootnode(prom_fd) == 0) {
		(void) close(prom_fd);
		return (NULL);
	}

	/*
	 * the `name' property is the same as the result of `uname -i', modulo
	 * some stylistic issues we fix up via sanitize_class_id() below.
	 */

	name = return_property(prom_fd, "name");
	(void) close(prom_fd);
	if (name == NULL)
		return (NULL);

	/*
	 * if the name is not prefixed with a vendor name, add "SUNW," to make
	 * it more likely to be globally unique; see PSARC/2004/674.
	 */

	if (strchr(name, ',') == NULL) {
		len = strlen(name) + sizeof ("SUNW,");
		class_id = malloc(len);
		if (class_id == NULL) {
			free(name);
			return (NULL);
		}
		(void) snprintf(class_id, len, "SUNW,%s", name);
		free(name);
	} else {
		class_id = name;
	}

	sanitize_class_id(class_id);
	return (class_id);
}
