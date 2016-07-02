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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2016 Nexenta Systems, Inc. All rights reserved.
 */


#include <stdio.h>
#include <unistd.h>
#include <strings.h>
#include <libdevinfo.h>

static void
usage(void)
{
	(void) fprintf(stderr,
	    "Usage: devprop [-n device-path] "
	    "[-vq] [-{b|i|l|s}] [property [...]]\n");
}

int
main(int argc, char *argv[])
{
	int c;
	boolean_t verbose = B_FALSE, quote = B_FALSE,
	    error = B_FALSE;
	int type = DI_PROP_TYPE_UNKNOWN;
	char *path = "/";
	di_node_t dn;
	uchar_t *val_b;
	int *val_i;
	int64_t *val_l;
	char *val_s, *ptr;
	int n;

	extern char *optarg;
	extern int optind;

#define	BOOL(ch, var)				\
case ch:					\
	var = B_TRUE;				\
	break

#define	PER_OPT(ch, typ)			\
case ch:					\
	if (type != DI_PROP_TYPE_UNKNOWN) {	\
		usage();			\
		return (1);			\
	}					\
	type = (typ);				\
	break

	while ((c = getopt(argc, argv, ":n:vqbils")) != -1) {
		switch (c) {
		case 'n':
			if ((path = realpath(optarg, NULL)) == NULL)
				path = optarg;
			break;
		case ':':
			usage();
			return (1);

		BOOL('v', verbose);
		BOOL('q', quote);
		BOOL('?', error);

		PER_OPT('b', DI_PROP_TYPE_BYTE);
		PER_OPT('i', DI_PROP_TYPE_INT);
		PER_OPT('l', DI_PROP_TYPE_INT64);
		PER_OPT('s', DI_PROP_TYPE_STRING);
		}
	}

#undef	BOOL
#undef	PER_OPT

	if (error) {
		usage();
		return (1);
	}

	/* default to strings */
	if (type == DI_PROP_TYPE_UNKNOWN)
		type = DI_PROP_TYPE_STRING;

	/*
	 * It's convenient to use the filesystem as a source of device
	 * node paths.  In that case, the path will be prefixed with
	 * "/devices", which we strip off here as di_init() expects
	 * just the path to the node.
	 */
	if (strncmp("/devices/", path, strlen("/devices/")) == 0) {
		path += strlen("/devices");

		/* cut off minor name */
		if ((ptr = strrchr(path, ':')) != NULL)
			*ptr = '\0';
	}

	if ((dn = di_init(path, DINFOPROP)) == DI_NODE_NIL) {
		perror("di_init");
		return (1);
	}

	/* Careful with that axe, Eugene... */
#define	PER_TYPE(typ, func, val, incr, form, pv, sep)	\
case (typ):						\
	n = func(DDI_DEV_T_ANY,				\
	    dn, argv[optind], &(val));			\
	while (n > 0) {					\
		(void) printf((form), pv);		\
		incr;					\
		n--;					\
		if (n > 0)				\
			(void) printf(sep);		\
	}						\
	(void) printf("\n");				\
	break

	while (optind < argc) {
		if (verbose)
			(void) printf("%s=", argv[optind]);

		switch (type) {
		PER_TYPE(DI_PROP_TYPE_BYTE, di_prop_lookup_bytes,
		    val_b, val_b++, "%2.2x", *val_b, ".");
		PER_TYPE(DI_PROP_TYPE_INT, di_prop_lookup_ints,
		    val_i, val_i++, "%8.8x", *val_i, ".");
		PER_TYPE(DI_PROP_TYPE_INT64, di_prop_lookup_int64,
		    val_l, val_l++, "%16.16llx", *val_l, ".");
		PER_TYPE(DI_PROP_TYPE_STRING, di_prop_lookup_strings,
		    val_s, val_s += strlen(val_s) + 1,
		    (quote ? "\"%s\"" : "%s"), val_s, " + ");
		}

		optind++;
	}

#undef	PER_TYPE

	di_fini(dn);

	return (0);
}
