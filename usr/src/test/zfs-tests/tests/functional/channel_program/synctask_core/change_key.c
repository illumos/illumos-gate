/*
 * CDDL HEADER START
 *
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 *
 * CDDL HEADER END
 */

/*
 * Copyright 2020 Joyent, Inc.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/debug.h>
#include <sys/fs/zfs.h>
#include <libzfs_core.h>
#include <libnvpair.h>

const char prog[] =
	"arg = ... \n"
	"fs = arg[\"dataset\"]\n"
	"hexkey = arg[\"" ZPOOL_HIDDEN_ARGS "\"][\"key\"]\n"
	"err = zfs.sync.change_key(fs, hexkey, 'hex')\n"
	"msg = \"changing key on \" .. fs .. \" err=\" .. err\n"
	"return msg";

/*
 * Get the pool name from a dataset. This is crude but good enough
 * for a test.
 */
static char *
get_pool(const char *dataset)
{
	char *res = strdup(dataset);

	if (res == NULL)
		abort();

	char *p = strchr(res, '/');

	if (p != NULL)
		*p = '\0';

	return (res);
}

int
main(int argc, char *argv[])
{
	const char *dataset = argv[1];
	const char *key = argv[2];
	char *pool = NULL;
	nvlist_t *args = fnvlist_alloc();
	nvlist_t *hidden_args = fnvlist_alloc();
	nvlist_t *result = NULL;
	int ret = 0;

	if (argc != 3) {
		(void) fprintf(stderr, "Usage: %s dataset key\n", argv[0]);
		exit(2);
	}

	VERIFY0(libzfs_core_init());

	pool = get_pool(dataset);

	fnvlist_add_string(args, "dataset", dataset);
	fnvlist_add_string(hidden_args, "key", key);
	fnvlist_add_nvlist(args, ZPOOL_HIDDEN_ARGS, hidden_args);

	ret = lzc_channel_program(pool, prog, ZCP_DEFAULT_INSTRLIMIT,
	    ZCP_DEFAULT_MEMLIMIT, args, &result);

	(void) printf("lzc_channel_program returned %d", ret);
	if (ret != 0)
		(void) printf(" (%s)", strerror(ret));
	(void) fputc('\n', stdout);

	dump_nvlist(result, 5);

	nvlist_free(args);
	nvlist_free(hidden_args);
	nvlist_free(result);
	free(pool);

	libzfs_core_fini();

	return (ret);
}
