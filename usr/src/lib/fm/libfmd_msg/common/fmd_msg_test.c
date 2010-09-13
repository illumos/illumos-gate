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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/types.h>
#include <sys/wait.h>

#include <sys/fm/protocol.h>
#include <fm/fmd_msg.h>

#include <unistd.h>
#include <signal.h>
#include <strings.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

#define	TEST_ARR_SZ	2

int
main(int argc, char *argv[])
{
	fmd_msg_hdl_t *h;
	pid_t pid;
	int i, err = 0;
	char *s;

	nvlist_t *auth, *fmri, *list, *test_arr[TEST_ARR_SZ];
	const char *code = "TEST-8000-08";
	int64_t tod[] = { 0x9400000, 0 };

	if (argc > 1) {
		(void) fprintf(stderr, "Usage: %s\n", argv[0]);
		return (2);
	}

	/*
	 * Build up a valid list.suspect event for a fictional diagnosis
	 * using a diagnosis code from our test dictionary so we can format
	 * messages.
	 */
	if (nvlist_alloc(&auth, NV_UNIQUE_NAME, 0) != 0 ||
	    nvlist_alloc(&fmri, NV_UNIQUE_NAME, 0) != 0 ||
	    nvlist_alloc(&list, NV_UNIQUE_NAME, 0) != 0) {
		(void) fprintf(stderr, "%s: nvlist_alloc failed\n", argv[0]);
		return (1);
	}

	err |= nvlist_add_uint8(auth, FM_VERSION, FM_FMRI_AUTH_VERSION);
	err |= nvlist_add_string(auth, FM_FMRI_AUTH_PRODUCT, "product");
	err |= nvlist_add_string(auth, FM_FMRI_AUTH_PRODUCT_SN, "product_sn");
	err |= nvlist_add_string(auth, FM_FMRI_AUTH_CHASSIS, "chassis");
	err |= nvlist_add_string(auth, FM_FMRI_AUTH_DOMAIN, "domain");
	err |= nvlist_add_string(auth, FM_FMRI_AUTH_SERVER, "server");

	if (err != 0) {
		(void) fprintf(stderr, "%s: failed to build auth nvlist: %s\n",
		    argv[0], strerror(err));
		return (1);
	}

	err |= nvlist_add_uint8(fmri, FM_VERSION, FM_FMD_SCHEME_VERSION);
	err |= nvlist_add_string(fmri, FM_FMRI_SCHEME, FM_FMRI_SCHEME_FMD);
	err |= nvlist_add_nvlist(fmri, FM_FMRI_AUTHORITY, auth);
	err |= nvlist_add_string(fmri, FM_FMRI_FMD_NAME, "fmd_msg_test");
	err |= nvlist_add_string(fmri, FM_FMRI_FMD_VERSION, "1.0");

	if (err != 0) {
		(void) fprintf(stderr, "%s: failed to build fmri nvlist: %s\n",
		    argv[0], strerror(err));
		return (1);
	}

	err |= nvlist_add_uint8(list, FM_VERSION, FM_SUSPECT_VERSION);
	err |= nvlist_add_string(list, FM_CLASS, FM_LIST_SUSPECT_CLASS);
	err |= nvlist_add_string(list, FM_SUSPECT_UUID, "12345678");
	err |= nvlist_add_string(list, FM_SUSPECT_DIAG_CODE, code);
	err |= nvlist_add_int64_array(list, FM_SUSPECT_DIAG_TIME, tod, 2);
	err |= nvlist_add_nvlist(list, FM_SUSPECT_DE, fmri);
	err |= nvlist_add_uint32(list, FM_SUSPECT_FAULT_SZ, 0);

	/*
	 * Add a contrived nvlist array to our list.suspect so that we can
	 * exercise the expansion syntax for dereferencing nvlist array members
	 */
	for (i = 0; i < TEST_ARR_SZ; i++) {
		if (nvlist_alloc(&test_arr[i], NV_UNIQUE_NAME, 0) != 0) {
			(void) fprintf(stderr, "%s: failed to alloc nvlist "
			    "array: %s\n", argv[0], strerror(err));
			return (1);
		}
		err |= nvlist_add_uint8(test_arr[i], "index", i);
	}
	err |= nvlist_add_nvlist_array(list, "test_arr", test_arr, TEST_ARR_SZ);

	if (err != 0) {
		(void) fprintf(stderr, "%s: failed to build list nvlist: %s\n",
		    argv[0], strerror(err));
		return (1);
	}

	/*
	 * Now initialize the libfmd_msg library for testing, using the message
	 * catalogs found in the proto area of the current workspace.
	 */
	if ((h = fmd_msg_init(getenv("ROOT"), FMD_MSG_VERSION)) == NULL) {
		(void) fprintf(stderr, "%s: fmd_msg_init failed: %s\n",
		    argv[0], strerror(errno));
		return (1);
	}

	/*
	 * Test 0: Verify that both fmd_msg_getitem_id and fmd_msg_gettext_id
	 * return NULL and EINVAL for an illegal message code, and NULL
	 * and ENOENT for a valid but not defined message code.
	 */
	s = fmd_msg_getitem_id(h, NULL, "I_AM_NOT_VALID", 0);
	if (s != NULL || errno != EINVAL) {
		(void) fprintf(stderr, "%s: test0 FAIL: illegal code returned "
		    "s = %p, errno = %d\n", argv[0], (void *)s, errno);
		return (1);
	}

	s = fmd_msg_gettext_id(h, NULL, "I_AM_NOT_VALID");
	if (s != NULL || errno != EINVAL) {
		(void) fprintf(stderr, "%s: test0 FAIL: illegal code returned "
		    "s = %p, errno = %d\n", argv[0], (void *)s, errno);
		return (1);
	}

	s = fmd_msg_getitem_id(h, NULL, "I_AM_NOT_HERE-0000-0000", 0);
	if (s != NULL || errno != ENOENT) {
		(void) fprintf(stderr, "%s: test0 FAIL: missing code returned "
		    "s = %p, errno = %d\n", argv[0], (void *)s, errno);
		return (1);
	}

	s = fmd_msg_gettext_id(h, NULL, "I_AM_NOT_HERE-0000-0000");
	if (s != NULL || errno != ENOENT) {
		(void) fprintf(stderr, "%s: test0 FAIL: missing code returned "
		    "s = %p, errno = %d\n", argv[0], (void *)s, errno);
		return (1);
	}

	/*
	 * Test 1: Use fmd_msg_getitem_id to retrieve the item strings for
	 * a known message code without having any actual event handle.
	 */
	for (i = 0; i < FMD_MSG_ITEM_MAX; i++) {
		if ((s = fmd_msg_getitem_id(h, NULL, code, i)) == NULL) {
			(void) fprintf(stderr, "%s: fmd_msg_getitem_id failed "
			    "for %s, item %d: %s\n",
			    argv[0], code, i, strerror(errno));
		}

		(void) printf("code %s item %d = <<%s>>\n", code, i, s);
		free(s);
	}

	/*
	 * Test 2: Use fmd_msg_gettext_id to retrieve the complete message for
	 * a known message code without having any actual event handle.
	 */
	if ((s = fmd_msg_gettext_id(h, NULL, code)) == NULL) {
		(void) fprintf(stderr, "%s: fmd_msg_gettext_id failed for %s: "
		    "%s\n", argv[0], code, strerror(errno));
		return (1);
	}

	(void) printf("%s\n", s);
	free(s);

	/*
	 * Test 3: Use fmd_msg_getitem_nv to retrieve the item strings for
	 * our list.suspect event handle.
	 */
	for (i = 0; i < FMD_MSG_ITEM_MAX; i++) {
		if ((s = fmd_msg_getitem_nv(h, NULL, list, i)) == NULL) {
			(void) fprintf(stderr, "%s: fmd_msg_getitem_nv failed "
			    "for %s, item %d: %s\n",
			    argv[0], code, i, strerror(errno));
		}

		(void) printf("code %s item %d = <<%s>>\n", code, i, s);
		free(s);
	}

	/*
	 * Test 4: Use fmd_msg_getitem_nv to retrieve the complete message for
	 * a known message code using our list.suspect event handle.
	 */
	if ((s = fmd_msg_gettext_nv(h, NULL, list)) == NULL) {
		(void) fprintf(stderr, "%s: fmd_msg_gettext_nv failed for %s: "
		    "%s\n", argv[0], code, strerror(errno));
		return (1);
	}

	(void) printf("%s\n", s);
	free(s);

	/*
	 * Test 5: Use fmd_msg_getitem_nv to retrieve the complete message for
	 * a known message code using our list.suspect event handle, but this
	 * time set the URL to our own customized URL.  Our contrived message
	 * has been designed to exercise the key aspects of the variable
	 * expansion syntax.
	 */
	if (fmd_msg_url_set(h, "http://foo.bar.com/") != 0) {
		(void) fprintf(stderr, "%s: fmd_msg_url_set failed: %s\n",
		    argv[0], strerror(errno));
	}

	if ((s = fmd_msg_gettext_nv(h, NULL, list)) == NULL) {
		(void) fprintf(stderr, "%s: fmd_msg_gettext_nv failed for %s: "
		    "%s\n", argv[0], code, strerror(errno));
		return (1);
	}

	(void) printf("%s\n", s);
	free(s);

	for (i = 0; i < TEST_ARR_SZ; i++)
		nvlist_free(test_arr[i]);
	nvlist_free(fmri);
	nvlist_free(auth);
	nvlist_free(list);

	fmd_msg_fini(h);	/* free library state before dumping core */
	pid = fork();		/* fork into background to not bother make(1) */

	switch (pid) {
	case -1:
		(void) fprintf(stderr, "FAIL (failed to fork)\n");
		return (1);
	case 0:
		abort();
		return (1);
	}

	if (waitpid(pid, &err, 0) == -1) {
		(void) fprintf(stderr, "FAIL (failed to wait for %d: %s)\n",
		    (int)pid, strerror(errno));
		return (1);
	}

	if (WIFSIGNALED(err) == 0 || WTERMSIG(err) != SIGABRT) {
		(void) fprintf(stderr, "FAIL (child did not SIGABRT)\n");
		return (1);
	}

	if (!WCOREDUMP(err)) {
		(void) fprintf(stderr, "FAIL (no core generated)\n");
		return (1);
	}

	(void) fprintf(stderr, "done\n");
	return (0);
}
