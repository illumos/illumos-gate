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
 * Copyright 2018 Joyent, Inc.
 * Copyright 2022 OmniOS Community Edition (OmniOSce) Association.
 */

#include <errno.h>
#include <fcntl.h>
#include <libzfs.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <unistd.h>
#include <zone.h>

#include <sys/types.h>
#include <sys/stat.h>

#include "testlib.h"
#include "mevent.h"

#define	MB (1024 * 1024)

static char *cookie = "Chocolate chip with fudge stripes";

static pthread_mutex_t mtx = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cv = PTHREAD_COND_INITIALIZER;

static void
callback(int fd, enum ev_type ev, void *arg)
{
	static off_t size = 0;
	struct stat st;

	ASSERT_INT_EQ(("bad event"), ev, EVF_VNODE);
	ASSERT_PTR_EQ(("bad cookie"), arg, cookie);

	if (fstat(fd, &st) != 0)
		FAIL_ERRNO("fstat failed");

	ASSERT_INT64_NEQ(("Size has not changed"), size, st.st_size);
	size = st.st_size;

	pthread_mutex_lock(&mtx);
	pthread_cond_signal(&cv);
	VERBOSE(("wakeup"));
	pthread_mutex_unlock(&mtx);
}

static void
destroy_zpool(libzfs_handle_t *zfshdl, zpool_handle_t *poolhdl,
    zfs_handle_t *volhdl)
{
	if (volhdl != NULL) {
		if (zfs_destroy(volhdl, B_FALSE) != 0) {
			FAIL(("Failed to destroy ZVOL - %s",
			    libzfs_error_description(zfshdl)));
		}
	}

	if (poolhdl != NULL) {
		if (zpool_destroy(poolhdl, testlib_prog) != 0) {
			FAIL(("Failed to destroy ZPOOL - %s",
			    libzfs_error_description(zfshdl)));
		}
	}
}

static void
create_zpool(libzfs_handle_t *zfshdl, const char *pool, const char *file)
{
	nvlist_t *nvroot, *props;
	nvlist_t *vdevs[1];

	nvroot = fnvlist_alloc();
	props = fnvlist_alloc();
	vdevs[0] = fnvlist_alloc();

	fnvlist_add_string(vdevs[0], ZPOOL_CONFIG_PATH, file);
	fnvlist_add_string(vdevs[0], ZPOOL_CONFIG_TYPE, VDEV_TYPE_FILE);
	fnvlist_add_uint64(vdevs[0], ZPOOL_CONFIG_IS_LOG, 0);

	fnvlist_add_string(nvroot, ZPOOL_CONFIG_TYPE, VDEV_TYPE_ROOT);
	fnvlist_add_nvlist_array(nvroot, ZPOOL_CONFIG_CHILDREN, vdevs, 1);

	fnvlist_add_string(props,
	    zfs_prop_to_name(ZFS_PROP_MOUNTPOINT), ZFS_MOUNTPOINT_NONE);

	if (zpool_create(zfshdl, pool, nvroot, NULL, props) != 0) {
		FAIL(("Failed to create ZPOOL %s using %s - %s",
		    pool, file, libzfs_error_description(zfshdl)));
	}

	VERBOSE(("Created ZFS pool %s", pool));
}

static bool
create_zvol(libzfs_handle_t *zfshdl, const char *vol)
{
	nvlist_t *volprops;
	int err;

	volprops = fnvlist_alloc();
	fnvlist_add_uint64(volprops,
	    zfs_prop_to_name(ZFS_PROP_VOLSIZE), 1 * MB);

	err = zfs_create(zfshdl, vol, ZFS_TYPE_VOLUME, volprops);
	if (err != 0) {
		(void) printf("Failed to create ZVOL %s - %s",
		    vol, libzfs_error_description(zfshdl));
		return (false);
	}

	VERBOSE(("Created ZVOL %s", vol));
	return (true);
}

int
main(int argc, const char **argv)
{
	libzfs_handle_t *zfshdl;
	char *template, *pool, *vol, *backend;
	struct mevent *evp;
	zpool_handle_t *poolhdl = NULL;
	zfs_handle_t *volhdl = NULL;
	int err, fd;

	start_test(argv[0], 10);
	set_mevent_file_poll_interval_ms(1000);

	if (getzoneid() != GLOBAL_ZONEID)
		FAIL(("Can only be run in the global zone"));

	if ((zfshdl = libzfs_init()) == NULL)
		FAIL_ERRNO("Could not open ZFS library");

	template = strdup("/tmp/mevent.vnode.zvol.XXXXXX");
	ASSERT_PTR_NEQ(("strdup"), template, NULL);
	fd = mkstemp(template);
	if (fd == -1)
		FAIL_ERRNO("Couldn't create temporary file with mkstemp");
	VERBOSE(("Opened temporary file at '%s'", template));

	err = asprintf(&pool, "mevent_test_%d", getpid());
	ASSERT_INT_NEQ(("asprintf pool"), err, -1);

	err = asprintf(&vol, "%s/test_zvol_%d", pool, getpid());
	ASSERT_INT_NEQ(("asprintf vol"), err, -1);

	err = asprintf(&backend, "/dev/zvol/rdsk/%s", vol);
	ASSERT_INT_NEQ(("asprintf backend"), err, -1);

	err = ftruncate(fd, 64 * MB);
	if (err != 0)
		FAIL_ERRNO("ftruncate");
	(void) close(fd);
	fd = -1;

	/*
	 * Create the pool as late as possible to reduce the risk of leaving
	 * a test pool hanging around.
	 */
	create_zpool(zfshdl, pool, template);

	if ((poolhdl = zpool_open(zfshdl, pool)) == NULL) {
		(void) printf("Could not open ZPOOL - %s\n",
		    libzfs_error_description(zfshdl));
		err = EXIT_FAIL;
		goto out;
	}

	if (!create_zvol(zfshdl, vol)) {
		err = EXIT_FAIL;
		goto out;
	}

	if ((volhdl = zfs_open(zfshdl, vol, ZFS_TYPE_VOLUME)) == NULL) {
		(void) printf("Could not open ZFS volume - %s\n",
		    libzfs_error_description(zfshdl));
		err = EXIT_FAIL;
		goto out;
	}

	if ((fd = open(backend, O_RDWR)) == -1) {
		(void) printf("Failed to open '%s': %s\n",
		    backend, strerror(errno));
		err = EXIT_FAIL;
		goto out;
	}
	VERBOSE(("Opened backend %s", backend));

	start_event_thread();

	evp = mevent_add_flags(fd, EVF_VNODE, EVFF_ATTRIB, callback, cookie);
	if (evp == NULL) {
		(void) printf("mevent_add returned NULL\n");
		err = EXIT_FAIL;
		goto out;
	}

	for (uint_t i = 2; i < 4; i++) {
		ssize_t written;
		char buf[64];

		/*
		 * Check that a write to the volume does not trigger an event.
		 */
		if (lseek(fd, 0, SEEK_SET) == -1)
			FAIL_ERRNO("lseek");
		written = write(fd, cookie, strlen(cookie));
		if (written < 0)
			FAIL_ERRNO("bad write");
		ASSERT_INT64_EQ(("write cookie", i), written, strlen(cookie));

		(void) snprintf(buf, sizeof (buf), "%llu", i * MB);
		VERBOSE(("Setting volsize to %s", buf));

		if (zfs_prop_set(volhdl,
		    zfs_prop_to_name(ZFS_PROP_VOLSIZE), buf) != 0) {
			(void) printf("Failed to increase ZFS volume size\n");
			pthread_mutex_unlock(&mtx);
			err = EXIT_FAIL;
			goto out;
		}

		/* Wait for the size change to be processed */
		pthread_mutex_lock(&mtx);
		pthread_cond_wait(&cv, &mtx);
		pthread_mutex_unlock(&mtx);
	}

	(void) mevent_disable(evp);

	err = EXIT_PASS;

out:

	(void) close(fd);
	destroy_zpool(zfshdl, poolhdl, volhdl);
	(void) libzfs_fini(zfshdl);
	(void) unlink(template);

	if (err == EXIT_PASS)
		PASS();

	exit(err);
}
