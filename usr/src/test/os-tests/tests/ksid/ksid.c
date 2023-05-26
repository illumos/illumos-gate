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
 * Copyright 2020 Tintri by DDN, Inc. All rights reserved.
 */

/*
 * Test the kernel ksid interfaces used by ZFS and SMB
 */

#include <sys/sid.h>
#include <sys/time.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <errno.h>

extern int ksl_bin_search_cutoff;

#define	MAX_DOMAINS 8
#define	DEFAULT_NUMSIDS 128
#define	DEFAULT_ITERS 1

char ksid_sids[MAX_DOMAINS+2][256];
ksid_t *bad_ksids;

boolean_t
run_test(ksidlist_t *ksl, uint32_t idx, uint32_t numsids,
    uint32_t iters, boolean_t pid)
{
	uint64_t savenum = ksl->ksl_nsid;
	uint64_t success = 0;
	hrtime_t start, end;
	uint32_t i, id;
	boolean_t expect_success = (idx < numsids);
	ksid_t *ks;

	ksl->ksl_nsid = numsids;

	start = gethrtime();
	if (pid) {
		/*
		 * Only the first savenum entries are sorted,
		 * but ksl_sorted is only used when numsids > cutoff.
		 * Use ksl_sorted when idx is among them
		 */
		if (numsids <= ksl_bin_search_cutoff)
			id = ksl->ksl_sids[idx].ks_id;
		else if (idx >= savenum)
			id = bad_ksids[idx - savenum].ks_id;
		else
			id = ksl->ksl_sorted[idx]->ks_id;

		for (i = 0; i < iters; i++) {
			success += (ksidlist_has_pid(ksl, id) ==
			    expect_success) ? 1 : 0;
		}
	} else {
		if (idx >= savenum)
			ks = &bad_ksids[idx - savenum];
		else
			ks = &ksl->ksl_sids[idx];

		for (i = 0; i < iters; i++) {
			success += (ksidlist_has_sid(ksl,
			    ksid_getdomain(ks), ks->ks_rid) ==
			    expect_success) ? 1 : 0;
		}
	}
	end = gethrtime();

	if (iters > 1) {
		printf("avg time to %s %s in %d sids "
		    "over %d iterations: %llu\n",
		    (expect_success) ? "find" : "not find",
		    (pid) ? "pid" : "sid", numsids, iters,
		    (end - start) / iters);
	}

	ksl->ksl_nsid = savenum;
	return (success == iters);
}

void
usage(char *prog)
{
	fprintf(stderr, "usage: %s [num sids] [num iters]\n", prog);
}

int
main(int argc, char *argv[])
{
	credsid_t *kcr;
	ksidlist_t *ksl;
	uint64_t num_failures = 0;
	uint32_t i, j, numsids, iters;
	boolean_t retry;

	if (argc > 1) {
		errno = 0;
		numsids = strtoul(argv[1], NULL, 0);
		if (errno != 0) {
			fprintf(stderr, "error decoding numsids (%s): \n",
			    argv[1]);
			usage(argv[0]);
			perror(argv[0]);
			return (errno);
		}
	} else {
		numsids = DEFAULT_NUMSIDS;
	}

	if (argc > 2) {
		iters = strtoul(argv[2], NULL, 0);
		if (errno != 0) {
			fprintf(stderr, "error decoding iters (%s): \n",
			    argv[2]);
			usage(argv[0]);
			perror(argv[0]);
			return (errno);
		}
	} else {
		iters = DEFAULT_ITERS;
	}

	if (numsids < 1 || iters < 1) {
		fprintf(stderr, "both numsids and iters "
		    "need to be at least 1\n");
		usage(argv[0]);
		return (2);
	}

	/* create MAX_DOMAINS random SIDs */
	for (i = 0; i < MAX_DOMAINS; i++) {
		(void) snprintf(ksid_sids[i], sizeof (ksid_sids[0]),
		    "S-1-5-21-%u-%u-%u",
		    arc4random(), arc4random(), arc4random());
	}

	/* create two unique SIDs for negative testing */
	for (j = MAX_DOMAINS; j < MAX_DOMAINS+2; j++) {
		do {
			retry = B_FALSE;
			(void) snprintf(ksid_sids[j], sizeof (ksid_sids[0]),
			    "S-1-5-21-%u-%u-%u",
			    arc4random(), arc4random(), arc4random());
			for (i = 0; i < MAX_DOMAINS; i++) {
				if (strncmp(ksid_sids[i], ksid_sids[j],
				    sizeof (ksid_sids[0])) == 0) {
					retry = B_TRUE;
					break;
				}
			}
		} while (retry);
	}

	ksl = calloc(1, KSIDLIST_MEM(numsids));
	ksl->ksl_ref = 1;
	ksl->ksl_nsid = numsids;
	ksl->ksl_neid = 0;

	bad_ksids = malloc(sizeof (ksid_t) * numsids);

	/* initialize numsids random sids and ids in the sidlist */
	for (i = 0; i < numsids; i++) {
		uint32_t idx = arc4random_uniform(MAX_DOMAINS);

		ksl->ksl_sids[i].ks_id = arc4random();
		ksl->ksl_sids[i].ks_rid = arc4random();
		ksl->ksl_sids[i].ks_domain = ksid_lookupdomain(ksid_sids[idx]);
		ksl->ksl_sids[i].ks_attr = 0;
	}

	/*
	 * create numsids random sids, whose sids and ids aren't in
	 * the sidlist for negative testing
	 */
	for (i = 0; i < numsids; i++) {
		bad_ksids[i].ks_attr = 0;
		bad_ksids[i].ks_rid = arc4random();
		bad_ksids[i].ks_domain =
		    ksid_lookupdomain(ksid_sids[MAX_DOMAINS +
		    (arc4random() % 2)]);

		do {
			retry = B_FALSE;
			bad_ksids[i].ks_id = arc4random();
			for (j = 0; j < numsids; j++) {
				if (ksl->ksl_sids[j].ks_id ==
				    bad_ksids[i].ks_id) {
					retry = B_TRUE;
					break;
				}
			}
		} while (retry);
	}

	kcr = kcrsid_setsidlist(NULL, ksl);

	/* run tests */
	for (i = 1; i <= numsids; i++) {
		uint32_t s_idx = arc4random_uniform(i);
		uint32_t f_idx = numsids + i - 1;

		if (!run_test(ksl, s_idx, i, iters, B_FALSE)) {
			fprintf(stderr, "Sid search failed unexpectedly: "
			    "numsids %u\n", i);
			fprintf(stderr, "Bad SID: id %u rid %u domain %s\n",
			    ksl->ksl_sids[s_idx].ks_id,
			    ksl->ksl_sids[s_idx].ks_rid,
			    ksid_getdomain(&ksl->ksl_sids[s_idx]));
			num_failures++;
		}
		if (!run_test(ksl, s_idx, i, iters, B_TRUE)) {
			fprintf(stderr, "Pid search failed unexpectedly: "
			    "numsids %u\n", i);
			fprintf(stderr, "Bad PID: id %u rid %u domain %s\n",
			    ksl->ksl_sorted[s_idx]->ks_id,
			    ksl->ksl_sorted[s_idx]->ks_rid,
			    ksid_getdomain(ksl->ksl_sorted[s_idx]));
			num_failures++;
		}

		if (!run_test(ksl, f_idx, i, iters, B_FALSE)) {
			fprintf(stderr, "Sid search succeeded unexpectedly: "
			    "numsids %u\n", i);
			fprintf(stderr, "Bad SID: id %u rid %u domain %s\n",
			    ksl->ksl_sids[f_idx].ks_id,
			    ksl->ksl_sids[f_idx].ks_rid,
			    ksid_getdomain(&ksl->ksl_sids[f_idx]));
			num_failures++;
		}
		if (!run_test(ksl, f_idx, i, iters, B_TRUE)) {
			fprintf(stderr, "Pid search succeeded unexpectedly: "
			    "numsids %u\n", i);
			fprintf(stderr, "Bad PID: id %u rid %u domain %s\n",
			    ksl->ksl_sids[f_idx].ks_id,
			    ksl->ksl_sids[f_idx].ks_rid,
			    ksid_getdomain(&ksl->ksl_sids[f_idx]));
			num_failures++;
		}
	}

	for (i = 0; i < numsids - 1; i++) {
		if (ksl->ksl_sorted[i]->ks_id > ksl->ksl_sorted[i + 1]->ks_id) {
			fprintf(stderr, "PID %u is not sorted correctly: "
			    "%u %u\n", i, ksl->ksl_sorted[i]->ks_id,
			    ksl->ksl_sorted[i + 1]->ks_id);
			num_failures++;
		}
		if (ksl->ksl_sids[i].ks_rid > ksl->ksl_sids[i + 1].ks_rid) {
			fprintf(stderr, "RID %u is not sorted correctly: "
			    "%u %u\n", i, ksl->ksl_sids[i].ks_rid,
			    ksl->ksl_sids[i + 1].ks_rid);
			num_failures++;
		} else if (ksl->ksl_sids[i].ks_rid ==
		    ksl->ksl_sids[i + 1].ks_rid &&
		    strcmp(ksid_getdomain(&ksl->ksl_sids[i]),
		    ksid_getdomain(&ksl->ksl_sids[i + 1])) > 0) {
			fprintf(stderr, "SID %u is not sorted correctly: "
			    "%s %s\n", i, ksl->ksl_sids[i].ks_rid,
			    ksl->ksl_sids[i + 1].ks_rid);
			num_failures++;
		}
	}

	if (num_failures != 0) {
		fprintf(stderr, "%d failures detected; dumping SID table\n",
		    num_failures);
		for (i = 0; i < numsids; i++) {
			fprintf(stderr, "SID %u: %s-%u -> %u\n", i,
			    ksid_getdomain(&ksl->ksl_sids[i]),
			    ksl->ksl_sids[i].ks_rid,
			    ksl->ksl_sids[i].ks_id);
		}

		for (i = 0; i < numsids; i++) {
			fprintf(stderr, "SID %u: %s-%u -> %u\n",
			    i + numsids,
			    ksid_getdomain(&bad_ksids[i]),
			    bad_ksids[i].ks_rid,
			    bad_ksids[i].ks_id);
		}

		for (i = 0; i < numsids; i++) {
			fprintf(stderr, "PID %u: %u\n", i,
			    ksl->ksl_sorted[i]->ks_id);
		}
	} else {
		printf("all tests completed successfully!\n");
	}

	kcrsid_rele(kcr);

	return (num_failures);
}
