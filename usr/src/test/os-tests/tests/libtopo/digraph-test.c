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
 * Copyright 2020 Joyent, Inc.
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <libnvpair.h>
#include <string.h>
#include <stropts.h>
#include <unistd.h>
#include <fm/libtopo.h>
#include <sys/debug.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/varargs.h>


#define	TEST_HOME		"/opt/os-tests/tests/libtopo/"
#define	TEST_XML_IN		"digraph-test-in.xml"
#define	TEST_XML_IN_BADSCHEME	"digraph-test-in-badscheme.xml"
#define	TEST_XML_IN_BADNUM	"digraph-test-in-badnum.xml"
#define	TEST_XML_IN_BADEDGE	"digraph-test-in-badedge.xml"
#define	TEST_XML_IN_BADELEMENT	"digraph-test-in-badelement.xml"
#define	TEST_GRAPH_SZ		7
#define	TEST_XML_OUT_DIR	"/var/tmp"
#define	TEST_XML_OUT_PREFIX	"digraph-test-out"

static const char *pname;

extern int topo_hdl_errno(topo_hdl_t *);

/*
 * Generate an ISO 8601 timestamp
 */
static void
get_timestamp(char *buf, size_t bufsize)
{
	time_t utc_time;
	struct tm *p_tm;

	(void) time(&utc_time);
	p_tm = localtime(&utc_time);

	(void) strftime(buf, bufsize, "%FT%TZ", p_tm);
}

/* PRINTFLIKE1 */
static void
logmsg(const char *format, ...)
{
	char timestamp[128];
	va_list ap;

	get_timestamp(timestamp, sizeof (timestamp));
	(void) fprintf(stdout, "%s ", timestamp);
	va_start(ap, format);
	(void) vfprintf(stdout, format, ap);
	va_end(ap);
	(void) fprintf(stdout, "\n");
	(void) fflush(stdout);
}

static topo_digraph_t *
test_deserialize(topo_hdl_t *thp, const char *path)
{
	struct stat statbuf = { 0 };
	char *buf = NULL;
	int fd = -1;
	topo_digraph_t *tdg = NULL;

	logmsg("\tOpening test XML topology");
	if ((fd = open(path, O_RDONLY)) < 0) {
		logmsg("\tfailed to open %s (%s)", path, strerror(errno));
		goto out;
	}
	if (fstat(fd, &statbuf) != 0) {
		logmsg("\tfailed to stat %s (%s)", path, strerror(errno));
		goto out;
	}
	if ((buf = malloc(statbuf.st_size)) == NULL) {
		logmsg("\tfailed to alloc read buffer: (%s)", strerror(errno));
		goto out;
	}
	if (read(fd, buf, statbuf.st_size) != statbuf.st_size) {
		logmsg("\tfailed to read file: (%s)", strerror(errno));
		goto out;
	}

	logmsg("\tDeserializing XML topology");
	tdg = topo_digraph_deserialize(thp, buf, statbuf.st_size);
	if (tdg == NULL) {
		logmsg("\ttopo_digraph_deserialize() failed!");
		goto out;
	}
	logmsg("\ttopo_digraph_deserialize() succeeded");
out:
	free(buf);
	if (fd > 0) {
		(void) close(fd);
	}
	return (tdg);
}

struct cb_arg {
	topo_vertex_t	**vertices;
};

static int
test_paths_cb(topo_hdl_t *thp, topo_vertex_t *vtx, boolean_t last_vtx,
    void *arg)
{
	struct cb_arg *cbarg = arg;
	uint_t idx = topo_node_instance(topo_vertex_node(vtx));

	cbarg->vertices[idx] = vtx;

	return (TOPO_WALK_NEXT);
}

static int
test_paths(topo_hdl_t *thp, topo_digraph_t *tdg)
{
	topo_vertex_t *vertices[TEST_GRAPH_SZ];
	struct cb_arg cbarg = { 0 };
	int ret = -1;
	topo_path_t **paths;
	uint_t np;

	cbarg.vertices = vertices;
	if (topo_vertex_iter(thp, tdg, test_paths_cb, &cbarg) != 0) {
		logmsg("\tfailed to iterate over graph vertices");
		goto out;
	}

	logmsg("\tCalculating number of paths between node 0 and node 4");
	if (topo_digraph_paths(thp, tdg, vertices[0], vertices[4], &paths,
	    &np) < 0) {
		logmsg("\ttopo_digraph_paths() failed");
		goto out;
	}
	if (np != 2) {
		logmsg("\t%d paths found (expected 2)", np);
		goto out;
	}
	for (uint_t i = 0; i < np; i++) {
		topo_path_destroy(thp, paths[i]);
	}
	topo_hdl_free(thp, paths, np * sizeof (topo_path_t *));

	logmsg("\tCalculating number of paths between node 6 and node 4");
	if (topo_digraph_paths(thp, tdg, vertices[6], vertices[4], &paths,
	    &np) < 0) {
		logmsg("\ttopo_digraph_paths() failed");
		goto out;
	}
	if (np != 1) {
		logmsg("\t%d paths found (expected 1)", np);
		goto out;
	}
	for (uint_t i = 0; i < np; i++) {
		topo_path_destroy(thp, paths[i]);
	}
	topo_hdl_free(thp, paths, np * sizeof (topo_path_t *));

	logmsg("\tCalculating number of paths between node 5 and node 1");
	if (topo_digraph_paths(thp, tdg, vertices[5], vertices[1], &paths,
	    &np) < 0) {
		logmsg("\ttopo_digraph_paths() failed");
		goto out;
	}
	if (np != 0) {
		logmsg("\t%d paths found (expected 0)", np);
		goto out;
	}
	ret = 0;

out:
	if (np > 0) {
		for (uint_t i = 0; i < np; i++) {
			topo_path_destroy(thp, paths[i]);
		}
		topo_hdl_free(thp, paths, np * sizeof (topo_path_t *));
	}
	return (ret);
}

static int
test_serialize(topo_hdl_t *thp, topo_digraph_t *tdg, const char *path)
{
	FILE *xml_out;

	if ((xml_out = fopen(path, "w")) == NULL) {
		logmsg("\tfailed to open %s for writing (%s)",
		    strerror(errno));
		return (-1);
	}
	logmsg("\tSerializing topology to XML (%s)", path);
	if (topo_digraph_serialize(thp, tdg, xml_out) != 0) {
		logmsg("\ttopo_digraph_serialize() failed!");
		(void) fclose(xml_out);
		return (-1);
	}
	(void) fclose(xml_out);
	return (0);
}

int
main(int argc, char **argv)
{
	topo_hdl_t *thp = NULL;
	topo_digraph_t *tdg;
	char *root = "/", *out_path = NULL;
	boolean_t abort_on_exit = B_FALSE;
	int err, status = EXIT_FAILURE;

	pname = argv[0];

	/*
	 * Setting DIGRAPH_TEST_CORE causes us to abort and dump core before
	 * exiting.  This is useful for examining for memory leaks.
	 */
	if (getenv("DIGRAPH_TEST_CORE") != NULL) {
		abort_on_exit = B_TRUE;
	}

	logmsg("Opening libtopo");
	if ((thp = topo_open(TOPO_VERSION, root, &err)) == NULL) {
		logmsg("failed to get topo handle: %s", topo_strerror(err));
		goto out;
	}

	logmsg("TEST: Deserialize directed graph topology");
	if ((tdg = test_deserialize(thp, TEST_HOME TEST_XML_IN)) == NULL) {
		logmsg("FAIL");
		goto out;
	}
	logmsg("PASS");

	logmsg("TEST: Serialize directed graph topology");
	if ((out_path = tempnam(TEST_XML_OUT_DIR, TEST_XML_OUT_PREFIX)) ==
	    NULL) {
		logmsg("\tFailed to create temporary file name under %s (%s)",
		    TEST_XML_OUT_DIR, strerror(errno));
		logmsg("FAIL");
		goto out;
	}
	if (test_serialize(thp, tdg, out_path) != 0) {
		logmsg("FAIL");
		goto out;
	}
	logmsg("PASS");

	logmsg("Closing libtopo");
	topo_close(thp);

	logmsg("Reopening libtopo");
	if ((thp = topo_open(TOPO_VERSION, root, &err)) == NULL) {
		logmsg("failed to get topo handle: %s", topo_strerror(err));
		goto out;
	}

	logmsg("TEST: Deserialize directed graph topology (pass 2)");
	if ((tdg = test_deserialize(thp, out_path)) == NULL) {
		logmsg("FAIL");
		goto out;
	}
	logmsg("PASS");

	logmsg("TEST: Calculating paths between vertices");
	if (test_paths(thp, tdg) != 0) {
		logmsg("FAIL");
		goto out;
	}
	logmsg("PASS");

	logmsg("Closing libtopo");
	topo_close(thp);

	logmsg("Reopening libtopo");
	if ((thp = topo_open(TOPO_VERSION, root, &err)) == NULL) {
		logmsg("failed to get topo handle: %s", topo_strerror(err));
		goto out;
	}

	/*
	 * The following tests attempt to deserialize XML files that either
	 * violate the DTD or contain invalid attribute values.
	 *
	 * The expection is that topo_digraph_deserialize() should fail
	 * gracefully (i.e. not segfault) and topo_errno should be set.
	 */
	logmsg("TEST: Deserialize directed graph topology (bad scheme)");
	if ((tdg = test_deserialize(thp, TEST_HOME TEST_XML_IN_BADSCHEME)) !=
	    NULL) {
		logmsg("FAIL");
		goto out;
	} else if (topo_hdl_errno(thp) == 0) {
		logmsg("\texpected topo_errno to be non-zero");
		logmsg("FAIL");
		goto out;
	} else {
		logmsg("PASS");
	}

	logmsg("TEST: Deserialize directed graph topology (bad number)");
	if ((tdg = test_deserialize(thp, TEST_HOME TEST_XML_IN_BADNUM)) !=
	    NULL) {
		logmsg("FAIL");
		goto out;
	} else if (topo_hdl_errno(thp) == 0) {
		logmsg("\texpected topo_errno to be non-zero");
		logmsg("FAIL");
		goto out;
	} else {
		logmsg("PASS");
	}

	logmsg("TEST: Deserialize directed graph topology (bad edge)");
	if ((tdg = test_deserialize(thp, TEST_HOME TEST_XML_IN_BADEDGE)) !=
	    NULL) {
		logmsg("FAIL");
		goto out;
	} else if (topo_hdl_errno(thp) == 0) {
		logmsg("\texpected topo_errno to be non-zero");
		logmsg("FAIL");
		goto out;
	} else {
		logmsg("PASS");
	}

	logmsg("TEST: Deserialize directed graph topology (bad element)");
	if ((tdg = test_deserialize(thp, TEST_HOME TEST_XML_IN_BADELEMENT)) !=
	    NULL) {
		logmsg("FAIL");
		goto out;
	} else if (topo_hdl_errno(thp) == 0) {
		logmsg("\texpected topo_errno to be non-zero");
		logmsg("FAIL");
		goto out;
	} else {
		logmsg("PASS");
	}

	/*
	 * If any tests failed, we don't unlink the temp file, as its contents
	 * may be useful for root-causing the test failure.
	 */
	if (unlink(out_path) != 0) {
		logmsg("Failed to unlink temp file: %s (%s)", out_path,
		    strerror(errno));
	}
	status = EXIT_SUCCESS;
out:
	if (thp != NULL) {
		topo_close(thp);
	}
	if (out_path != NULL) {
		free(out_path);
	}
	logmsg("digraph tests %s",
	    status == EXIT_SUCCESS ? "passed" : "failed");

	if (abort_on_exit) {
		abort();
	}
	return (status);
}
