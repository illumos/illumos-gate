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
 * Copyright 2025 Bill Sommerfeld
 */

/*
 * Demonstration of idmap collisions due to missing locking and a
 * fencepost error in get_next_eph_uid.  On a 24-core Zen 4 system
 * (EPYC 8224P) with a batchsize of 1000 and 20 threads, I see a
 * couple dups per run.  Dups ending in 001 are from the fencepost error.
 *
 * Build with: gcc -O2 -o idmaptest idmaptest.c -lidmap
 */
#include <err.h>
#include <idmap.h>
#include <pthread.h>
#include <stdio.h>
#include <stdbool.h>
#include <time.h>

struct batch {
	idmap_rid_t base;
	int count;
	uid_t *idbuf;
	idmap_stat *statbuf;
	idmap_stat *statbuf2;
};

static volatile int go;
static char sid[32];

static pthread_mutex_t m;
static int ready_count;
static bool test_gid;

void *
get_idmap_batch(void *arg)
{
	idmap_rid_t rid;
	int i;
	struct batch *b = arg;

	(void) pthread_mutex_lock(&m);
	ready_count += 1;
	(void) pthread_mutex_unlock(&m);

	/* spinwait until all threads are created */
	while (!go)
		;

	for (i = 0; i < b->count; i++) {
		idmap_get_handle_t *h;
		rid = b->base + i;
		(void) idmap_get_create(&h);
		if (test_gid) {
			(void) idmap_get_gidbysid(h, sid, rid,
			    IDMAP_REQ_FLG_USE_CACHE,
			    &b->idbuf[i], &b->statbuf[i]);
		} else {
			(void) idmap_get_uidbysid(h, sid, rid,
			    IDMAP_REQ_FLG_USE_CACHE,
			    &b->idbuf[i], &b->statbuf[i]);
		}
		b->statbuf2[i] = idmap_get_mappings(h);
		idmap_get_destroy(h);
	}
	return (NULL);
}

#define	NTHREAD 20
#define	BATCHSIZE 1000
#define	RIDBASE 2000

int
cmpugid(const void *a, const void *b)
{
	uid_t x = *(const uid_t *)a;
	uid_t y = *(const uid_t *)b;
	if (x > y)
		return (1);
	if (x < y)
		return (-1);
	return (0);
}

static const struct timespec usec100 = { 0, 100000 };

bool
test_idmap()
{
	int i, j, err;
	time_t now;
	bool fail = false;
	const char *whatsit = test_gid ? "gid" : "uid";

	pthread_t thread[NTHREAD];
	struct batch b[NTHREAD];
	uid_t idbuf[NTHREAD*BATCHSIZE];

	go = 0;
	ready_count = 0;

	(void) time(&now);
	(void) snprintf(sid, sizeof (sid), "S-1-5-21-44444444-%ld", now);

	printf("testing for dup %s\n", whatsit);

	printf("base sid: %s\n", sid);

	for (i = 0; i < NTHREAD; i++) {
		b[i].base = RIDBASE +  i * BATCHSIZE;
		b[i].count = BATCHSIZE;
		b[i].idbuf = &idbuf[i * BATCHSIZE];
		b[i].statbuf = calloc(BATCHSIZE, sizeof (idmap_stat));
		b[i].statbuf2 = calloc(BATCHSIZE, sizeof (idmap_stat));
	}
	for (i = 0; i < NTHREAD; i++) {
		err = pthread_create(&thread[i], NULL, get_idmap_batch, &b[i]);
		if (err) {
			errc(EXIT_FAILURE, err,
			    "Failed to create thread %d", i);
		}
	}

	for (;;) {
		int n;
		(void) pthread_mutex_lock(&m);
		n = ready_count;
		(void) pthread_mutex_unlock(&m);
		if (n == NTHREAD) {
			go = 1;
			break;
		}
		(void) nanosleep(&usec100, NULL);
	}

	go = 1;
	for (i = 0; i < NTHREAD; i++) {
		int err = pthread_join(thread[i], NULL);
		if (err != 0) {
			printf("thread %d error %d\n", i, err);
			fail = true;
		}
	}
	for (i = 0; i < NTHREAD; i++) {
		for (j = 0; j < BATCHSIZE; j++) {
			if (b[i].statbuf[j]) {
				printf("fail 1: %d,%d => %d\n",
				    i, j, b[i].statbuf[j]);
				fail = true;
			}
			if (b[i].statbuf2[j]) {
				printf("fail 2: %d,%d => %d\n",
				    i, j, b[i].statbuf2[j]);
				fail = true;
			}
		}
	}
	qsort(idbuf, NTHREAD*BATCHSIZE, sizeof (uid_t), cmpugid);
	for (i = 1; i < NTHREAD*BATCHSIZE; i++) {
		if (idbuf[i] == idbuf[i-1]) {
			printf("dup %s %x\n", whatsit, idbuf[i]);
			fail = true;
		}
	}
	return (fail);
}

bool
idmapd_running()
{
	bool running = false;
	idmap_get_handle_t *h;
	idmap_stat status;
	idmap_stat s = idmap_get_create(&h);
	idmap_rid_t rid;
	char *domain;

	if (s != 0) {
		fprintf(stderr, "Can't create idmap handle: %s\n",
		    idmap_stat2string(s));
		return (false);
	}

	s = idmap_get_sidbyuid(h, 0,
	    IDMAP_REQ_FLG_USE_CACHE, &domain, &rid, &status);
	if (s != IDMAP_SUCCESS) {
		fprintf(stderr, "Can't create queue map request: %s\n",
		    idmap_stat2string(s));
	} else if ((s = idmap_get_mappings(h)) != 0) {
		fprintf(stderr, "idmap_get_mappings failed: %s\n",
		    idmap_stat2string(s));
	} else if (status != IDMAP_SUCCESS) {
		fprintf(stderr, "mapping of 0 failed: %s\n",
		    idmap_stat2string(status));
	} else {
		running = true;
	}
	idmap_get_destroy(h);
	return (running);
}

int
main(int argc, char **argv)
{
	bool fail = false;

	if (!idmapd_running()) {
		fprintf(stderr, "Is idmapd running?\n");
		exit(4);	/* signal a "SKIP" to the testing framework */
	}
	fprintf(stderr, "idmapd is running\n");

	(void) pthread_mutex_init(&m, NULL);

	test_gid = false;
	if (test_idmap())
		fail = true;

	test_gid = true;
	if (test_idmap())
		fail = true;

	if (fail) {
		fprintf(stderr, "FAIL: test failed\n");
		exit(EXIT_FAILURE);
	}
	fprintf(stderr, "PASS: duplicate ids not detected\n");
	exit(EXIT_SUCCESS);
}
