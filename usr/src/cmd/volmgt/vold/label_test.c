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
 * Copyright (c) 1994 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include	<stdio.h>
#include	<stdlib.h>
#include	<unistd.h>
#include	<errno.h>
#include	<string.h>
#include	<sys/types.h>
#include	<sys/stat.h>
#include	<fcntl.h>

#include	"vold.h"


/*
 * This is the "test" label.  It is just a hack that will grow, change
 * and serve as the example "label" interface.
 */

static char		*test_key(label *);
static bool_t 		test_compare(label *, label *);
static enum laread_res	test_read(int, label *, struct devs *);
static void		test_setup(vol_t *);
static void		test_xdr(label *, enum xdr_op, void **);

#define	TEST_SIZE	12

static struct label_loc	test_labelloc = {0, TEST_SIZE};

static struct labsw	testlabsw = {
	test_key,	/* l_key */
	test_compare, 	/* l_compare */
	test_read, 	/* l_read */
	NULL, 		/* l_write */
	test_setup, 	/* l_setup */
	test_xdr, 	/* l_xdr */
	TEST_SIZE, 	/* l_size */
	TEST_SIZE,	/* l_xdrsize */	/* not normal */
	TEST_LTYPE,	/* l_ident */
	1,		/* l_nll */
	&test_labelloc,	/* l_ll */
};



bool_t
label_init()
{
	info("label_test: init\n");

	label_new(&testlabsw);
	return (TRUE);
}


/*ARGSUSED*/
static enum laread_res
test_read(int fd, label *la, struct devs *dp)
{
	int	err;

#ifdef notdef
	printf("test_read: %s\n", dp->dp_path);
#endif
	(void) lseek(fd, 0, SEEK_SET);
	la->l_label = (void *)malloc(TEST_SIZE);
	if ((err = read(fd, la->l_label, TEST_SIZE)) < 0) {
		goto errout;
	}
	if (err != TEST_SIZE) {	/* short read */
		errno = EIO;
		goto errout;
	}
	return (L_FOUND);
errout:
	free(la->l_label);
	la->l_label = 0;
	return (L_ERROR);
}

static char *
test_key(label *la)
{
	return (makename(la->l_label, TEST_SIZE));
}

static bool_t
test_compare(label *la1, label *la2)
{
#if 0
	printf("test_compare: ");
#endif
	if (memcmp(la1->l_label, la2->l_label, TEST_SIZE) == 0) {
#if 0
		printf("TRUE\n");
#endif
		return (TRUE);
	}
#if 0
	printf("FALSE\n");
#endif
	return (FALSE);
}


static void
test_setup(vol_t *v)
{
	size_t	length = (size_t) strlen(v->v_label.l_label);

	if (length > TEST_SIZE) {
		length = TEST_SIZE;
	}
	v->v_obj.o_name = makename(v->v_label.l_label, length);
}


void
test_xdr(label *l, enum xdr_op op, void **data)
{
	/* yes, well I don't feel like writing xdr code right now */
	if (op == XDR_ENCODE) {
		*data = malloc(TEST_SIZE);
		(void) memcpy(*data, l->l_label, TEST_SIZE);
	} else if (op == XDR_DECODE) {
		if (l->l_label != NULL) {
			free(l->l_label);
		}
		l->l_label = malloc(TEST_SIZE);
		(void) memcpy(l->l_label, *data, TEST_SIZE);
	}
}
