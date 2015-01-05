/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * String utility functions with dynamic memory management.
 */

/*
 * Copyright 2014, Joyent, Inc.
 */

#include <stdlib.h>
#include <err.h>
#include <string.h>

#include "libcmdutils.h"

struct custr {
	size_t cus_strlen;
	size_t cus_datalen;
	char *cus_data;
};

#define	STRING_CHUNK_SIZE	64

void
custr_reset(custr_t *cus)
{
	if (cus->cus_data == NULL)
		return;

	cus->cus_strlen = 0;
	cus->cus_data[0] = '\0';
}

size_t
custr_len(custr_t *cus)
{
	return (cus->cus_strlen);
}

const char *
custr_cstr(custr_t *cus)
{
	return (cus->cus_data);
}

int
custr_appendc(custr_t *cus, char newc)
{
	char news[2];

	news[0] = newc;
	news[1] = '\0';

	return (custr_append(cus, news));
}

int
custr_append(custr_t *cus, const char *news)
{
	size_t len = strlen(news);
	size_t chunksz = STRING_CHUNK_SIZE;

	while (chunksz < len) {
		chunksz *= 2;
	}

	if (len + cus->cus_strlen + 1 >= cus->cus_datalen) {
		char *new_data;
		size_t new_datalen = cus->cus_datalen + chunksz;

		/*
		 * Allocate replacement memory:
		 */
		if ((new_data = malloc(new_datalen)) == NULL) {
			return (-1);
		}

		/*
		 * Copy existing data into replacement memory and free
		 * the old memory.
		 */
		if (cus->cus_data != NULL) {
			(void) memcpy(new_data, cus->cus_data,
			    cus->cus_strlen + 1);
			free(cus->cus_data);
		}

		/*
		 * Swap in the replacement buffer:
		 */
		cus->cus_data = new_data;
		cus->cus_datalen = new_datalen;
	}
	/*
	 * Append new string to existing string:
	 */
	(void) memcpy(cus->cus_data + cus->cus_strlen, news, len + 1);
	cus->cus_strlen += len;

	return (0);
}

int
custr_alloc(custr_t **cus)
{
	custr_t *t;

	if ((t = calloc(1, sizeof (*t))) == NULL) {
		*cus = NULL;
		return (-1);
	}

	*cus = t;
	return (0);
}

void
custr_free(custr_t *cus)
{
	if (cus == NULL)
		return;

	free(cus->cus_data);
	free(cus);
}
