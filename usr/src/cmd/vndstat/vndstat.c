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
 * Copyright (c) 2014, Joyent, Inc. All rights reserved.
 */

#include <sys/kstat.h>
#include <kstat.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <alloca.h>
#include <signal.h>
#include <sys/varargs.h>
#include <sys/int_limits.h>
#include <sys/sysmacros.h>

#define	KSTAT_FIELD_USEINSTANCE		0x01
#define	KSTAT_FIELD_NODELTA		0x02
#define	KSTAT_FIELD_FILLER		0x04
#define	KSTAT_FIELD_STRING		0x08
#define	KSTAT_FIELD_UNIT		0x10
#define	KSTAT_FIELD_LJUST		0x20

typedef struct kstat_field {
	char *ksf_header;		/* header for field */
	char *ksf_name;			/* name of stat, if any */
	int ksf_width;			/* width for field in output line */
	uint32_t ksf_flags;		/* flags for this field, if any */
	char *ksf_suffix;		/* optional suffix for units */
	int ksf_hint;			/* index hint for field in kstat */
} kstat_field_t;

typedef struct kstat_instance {
	char ksi_name[KSTAT_STRLEN];	/* name of the underlying kstat */
	int ksi_instance;		/* instance identifer of this kstat */
	kstat_t *ksi_ksp;		/* pointer to the kstat */
	uint64_t *ksi_data[2];		/* pointer to two generations of data */
	hrtime_t ksi_snaptime[2];	/* hrtime for data generations */
	int ksi_gen;			/* current generation */
	struct kstat_instance *ksi_next; /* next in instance list */
} kstat_instance_t;

const char *g_cmd = "vndstat";

static void
kstat_nicenum(uint64_t num, char *buf, size_t buflen)
{
	uint64_t n = num;
	int index = 0;
	char u;

	while (n >= 1024) {
		n /= 1024;
		index++;
	}

	u = " KMGTPE"[index];

	if (index == 0) {
		(void) snprintf(buf, buflen, "%llu", n);
	} else if ((num & ((1ULL << 10 * index) - 1)) == 0) {
		/*
		 * If this is an even multiple of the base, always display
		 * without any decimal precision.
		 */
		(void) snprintf(buf, buflen, "%llu%c", n, u);
	} else {
		/*
		 * We want to choose a precision that reflects the best choice
		 * for fitting in 5 characters.  This can get rather tricky when
		 * we have numbers that are very close to an order of magnitude.
		 * For example, when displaying 10239 (which is really 9.999K),
		 * we want only a single place of precision for 10.0K.  We could
		 * develop some complex heuristics for this, but it's much
		 * easier just to try each combination in turn.
		 */
		int i;
		for (i = 2; i >= 0; i--) {
			if (snprintf(buf, buflen, "%.*f%c", i,
			    (double)num / (1ULL << 10 * index), u) <= 5)
				break;
		}
	}
}

static void
fatal(char *fmt, ...)
{
	va_list ap;
	int error = errno;

	va_start(ap, fmt);

	(void) fprintf(stderr, "%s: ", g_cmd);
	/*LINTED*/
	(void) vfprintf(stderr, fmt, ap);

	if (fmt[strlen(fmt) - 1] != '\n')
		(void) fprintf(stderr, ": %s\n", strerror(error));

	exit(EXIT_FAILURE);
}

int
kstat_field_hint(kstat_t *ksp, kstat_field_t *field)
{
	kstat_named_t *nm = KSTAT_NAMED_PTR(ksp);
	int i;

	assert(ksp->ks_type == KSTAT_TYPE_NAMED);

	for (i = 0; i < ksp->ks_ndata; i++) {
		if (strcmp(field->ksf_name, nm[i].name) == 0)
			return (field->ksf_hint = i);
	}

	fatal("could not find field '%s' in %s:%d\n",
	    field->ksf_name, ksp->ks_name, ksp->ks_instance);

	return (0);
}

int
kstat_instances_compare(const void *lhs, const void *rhs)
{
	kstat_instance_t *l = *((kstat_instance_t **)lhs);
	kstat_instance_t *r = *((kstat_instance_t **)rhs);
	int rval;

	if ((rval = strcmp(l->ksi_name, r->ksi_name)) != 0)
		return (rval);

	if (l->ksi_instance < r->ksi_instance)
		return (-1);

	if (l->ksi_instance > r->ksi_instance)
		return (1);

	return (0);
}

void
kstat_instances_update(kstat_ctl_t *kcp, kstat_instance_t **head,
    boolean_t (*interested)(kstat_t *))
{
	int ninstances = 0, i;
	kstat_instance_t **sorted, *ksi, *next;
	kstat_t *ksp;
	kid_t kid;

	if ((kid = kstat_chain_update(kcp)) == 0 && *head != NULL)
		return;

	if (kid == -1)
		fatal("failed to update kstat chain");

	for (ksi = *head; ksi != NULL; ksi = ksi->ksi_next)
		ksi->ksi_ksp = NULL;

	for (ksp = kcp->kc_chain; ksp != NULL; ksp = ksp->ks_next) {
		kstat_instance_t *last = NULL;

		if (!interested(ksp))
			continue;

		/*
		 * Now look to see if we have this instance and name.  (Yes,
		 * this is a linear search; we're assuming that this list is
		 * modest in size.)
		 */
		for (ksi = *head; ksi != NULL; ksi = ksi->ksi_next) {
			last = ksi;

			if (ksi->ksi_instance != ksp->ks_instance)
				continue;

			if (strcmp(ksi->ksi_name, ksp->ks_name) != 0)
				continue;

			ksi->ksi_ksp = ksp;
			ninstances++;
			break;
		}

		if (ksi != NULL)
			continue;

		if ((ksi = malloc(sizeof (kstat_instance_t))) == NULL)
			fatal("could not allocate memory for stat instance");

		bzero(ksi, sizeof (kstat_instance_t));
		(void) strlcpy(ksi->ksi_name, ksp->ks_name, KSTAT_STRLEN);
		ksi->ksi_instance = ksp->ks_instance;
		ksi->ksi_ksp = ksp;
		ksi->ksi_next = NULL;

		if (last == NULL) {
			assert(*head == NULL);
			*head = ksi;
		} else {
			last->ksi_next = ksi;
		}

		ninstances++;
	}

	/*
	 * Now we know how many instances we have; iterate back over them,
	 * pruning the stale ones and adding the active ones to a holding
	 * array in which to sort them.
	 */
	sorted = (void *)alloca(ninstances * sizeof (kstat_instance_t *));
	ninstances = 0;

	for (ksi = *head; ksi != NULL; ksi = next) {
		next = ksi->ksi_next;

		if (ksi->ksi_ksp == NULL) {
			free(ksi);
		} else {
			sorted[ninstances++] = ksi;
		}
	}

	if (ninstances == 0) {
		*head = NULL;
		return;
	}

	qsort(sorted, ninstances, sizeof (kstat_instance_t *),
	    kstat_instances_compare);

	*head = sorted[0];

	for (i = 0; i < ninstances; i++) {
		ksi = sorted[i];
		ksi->ksi_next = i < ninstances - 1 ? sorted[i + 1] : NULL;
	}
}

void
kstat_instances_read(kstat_ctl_t *kcp, kstat_instance_t *instances,
    kstat_field_t *fields)
{
	kstat_instance_t *ksi;
	int i, nfields;

	for (nfields = 0; fields[nfields].ksf_header != NULL; nfields++)
		continue;

	for (ksi = instances; ksi != NULL; ksi = ksi->ksi_next) {
		kstat_t *ksp = ksi->ksi_ksp;

		if (ksp == NULL)
			continue;

		if (kstat_read(kcp, ksp, NULL) == -1) {
			if (errno == ENXIO) {
				/*
				 * Our kstat has been removed since the update;
				 * NULL it out to prevent us from trying to read
				 * it again (and to indicate that it should not
				 * be displayed) and drive on.
				 */
				ksi->ksi_ksp = NULL;
				continue;
			}

			fatal("failed to read kstat %s:%d",
			    ksi->ksi_name, ksi->ksi_instance);
		}

		if (ksp->ks_type != KSTAT_TYPE_NAMED) {
			fatal("%s:%d is not a named kstat", ksi->ksi_name,
			    ksi->ksi_instance);
		}

		if (ksi->ksi_data[0] == NULL) {
			size_t size = nfields * sizeof (uint64_t) * 2;
			uint64_t *data;

			if ((data = malloc(size)) == NULL)
				fatal("could not allocate memory");

			bzero(data, size);
			ksi->ksi_data[0] = data;
			ksi->ksi_data[1] = &data[nfields];
		}

		for (i = 0; i < nfields; i++) {
			kstat_named_t *nm = KSTAT_NAMED_PTR(ksp);
			kstat_field_t *field = &fields[i];
			int hint = field->ksf_hint;

			if (field->ksf_name == NULL)
				continue;

			if (hint < 0 || hint >= ksp->ks_ndata ||
			    strcmp(field->ksf_name, nm[hint].name) != 0) {
				hint = kstat_field_hint(ksp, field);
			}

			if (field->ksf_flags & KSTAT_FIELD_STRING)
				ksi->ksi_data[ksi->ksi_gen][i] =
				    (uint64_t)(uintptr_t)
				    nm[hint].value.str.addr.ptr;
			else
				ksi->ksi_data[ksi->ksi_gen][i] =
				    nm[hint].value.ui64;
		}

		ksi->ksi_snaptime[ksi->ksi_gen] = ksp->ks_snaptime;
		ksi->ksi_gen ^= 1;
	}
}

uint64_t
kstat_instances_delta(kstat_instance_t *ksi, int i)
{
	int gen = ksi->ksi_gen;
	uint64_t delta = ksi->ksi_data[gen ^ 1][i] - ksi->ksi_data[gen][i];
	uint64_t tdelta = ksi->ksi_snaptime[gen ^ 1] - ksi->ksi_snaptime[gen];

	return (((delta * (uint64_t)NANOSEC) + (tdelta / 2)) / tdelta);
}

void
kstat_instances_print(kstat_instance_t *instances, kstat_field_t *fields,
    boolean_t header)
{
	kstat_instance_t *ksi = instances;
	int i, nfields;

	for (nfields = 0; fields[nfields].ksf_header != NULL; nfields++)
		continue;

	if (header) {
		for (i = 0; i < nfields; i++) {
			if (fields[i].ksf_flags & KSTAT_FIELD_LJUST) {
				(void) printf("%s%c", fields[i].ksf_header,
				    i < nfields - 1 ? ' ' : '\n');
				continue;
			}
			(void) printf("%*s%c", fields[i].ksf_width,
			    fields[i].ksf_header, i < nfields - 1 ? ' ' : '\n');
		}
	}

	for (ksi = instances; ksi != NULL; ksi = ksi->ksi_next) {
		if (ksi->ksi_snaptime[1] == 0 || ksi->ksi_ksp == NULL)
			continue;

		for (i = 0; i < nfields; i++) {
			char trailer = i < nfields - 1 ? ' ' : '\n';

			if (fields[i].ksf_flags & KSTAT_FIELD_FILLER) {
				(void) printf("%*s%c", fields[i].ksf_width,
				    fields[i].ksf_header, trailer);
				continue;
			}

			if (fields[i].ksf_flags & KSTAT_FIELD_STRING) {
				(void) printf("%*s%c", fields[i].ksf_width,
				    (char *)(uintptr_t)ksi->ksi_data[
				    ksi->ksi_gen ^ 1][i],
				    trailer);
				continue;
			}

			if (fields[i].ksf_flags & KSTAT_FIELD_UNIT) {
				char buf[128];
				size_t flen = fields[i].ksf_width + 1;
				const char *suffix = "";

				if (fields[i].ksf_suffix != NULL) {
					suffix = fields[i].ksf_suffix;
					flen -= strlen(fields[i].ksf_suffix);
				}

				kstat_nicenum(fields[i].ksf_flags &
				    KSTAT_FIELD_NODELTA ?
				    ksi->ksi_data[ksi->ksi_gen ^ 1][i] :
				    kstat_instances_delta(ksi, i), buf,
				    MIN(sizeof (buf), flen));
				(void) printf("%*s%s%c", flen - 1, buf,
				    suffix, trailer);
				continue;
			}

			(void) printf("%*lld%c", fields[i].ksf_width,
			    fields[i].ksf_flags & KSTAT_FIELD_USEINSTANCE ?
			    ksi->ksi_instance :
			    fields[i].ksf_flags & KSTAT_FIELD_NODELTA ?
			    ksi->ksi_data[ksi->ksi_gen ^ 1][i] :
			    kstat_instances_delta(ksi, i), trailer);
		}
	}
}

static boolean_t
interested(kstat_t *ksp)
{
	const char *module = "vnd";
	const char *class = "net";

	if (strcmp(ksp->ks_module, module) != 0)
		return (B_FALSE);

	if (strcmp(ksp->ks_class, class) != 0)
		return (B_FALSE);

	return (B_TRUE);
}

/* BEGIN CSTYLED */
char *g_usage = "Usage: vndstat [interval [count]]\n"
    "\n"
    "  Displays statistics for active vnd devices, with one line per device.\n"
    "  All statistics are reported as per-second rates.\n"
    "\n"
    "  The columns are as follows:\n"
    "\n"
    "    zone   =>  name of the zone with the device\n"
    "    name   =>  name of the vnd device\n"
    "    rx     =>  bytes received\n"
    "    tx     =>  bytes transmitted\n"
    "    drops  =>  number of dropped packets\n"
    "    txfc   =>  number of transmit flow control events\n"
    "\n";
/* END CSTYLED */

void
usage()
{
	(void) fprintf(stderr, "%s", g_usage);
	exit(EXIT_FAILURE);
}

/*ARGSUSED*/
void
intr(int sig)
{}

/*ARGSUSED*/
int
main(int argc, char **argv)
{
	kstat_ctl_t *kcp;
	kstat_instance_t *instances = NULL;
	int i = 0;
	int interval = 1;
	int count = INT32_MAX;
	struct itimerval itimer;
	struct sigaction act;
	sigset_t set;
	char *endp;

	kstat_field_t fields[] =  {
		{ "name", "linkname", 6, KSTAT_FIELD_STRING },
		{ "|", NULL, 1, KSTAT_FIELD_FILLER },
		{ "rx B/s", "rbytes", 8, KSTAT_FIELD_UNIT, "B/s" },
		{ "|", NULL, 1, KSTAT_FIELD_FILLER },
		{ "tx B/s", "obytes", 8, KSTAT_FIELD_UNIT, "B/s" },
		{ "|", NULL, 1, KSTAT_FIELD_FILLER },
		{ "drops", "total_drops", 5 },
		{ "txfc", "flowcontrol_events", 4 },
		{ "|", NULL, 1, KSTAT_FIELD_FILLER },
		{ "zone", "zonename", 36,
			KSTAT_FIELD_STRING | KSTAT_FIELD_LJUST },
		{ NULL }
	};

	if (argc > 1) {
		interval = strtol(argv[1], &endp, 10);

		if (*endp != '\0' || interval <= 0)
			usage();
	}

	if (argc > 2) {
		count = strtol(argv[2], &endp, 10);

		if (*endp != '\0' || count <= 0)
			usage();
	}

	if ((kcp = kstat_open()) == NULL)
		fatal("could not open /dev/kstat");

	(void) sigemptyset(&act.sa_mask);
	act.sa_flags = 0;
	act.sa_handler = intr;
	(void) sigaction(SIGALRM, &act, NULL);

	(void) sigemptyset(&set);
	(void) sigaddset(&set, SIGALRM);
	(void) sigprocmask(SIG_BLOCK, &set, NULL);

	bzero(&itimer, sizeof (itimer));
	itimer.it_value.tv_sec = interval;
	itimer.it_interval.tv_sec = interval;

	if (setitimer(ITIMER_REAL, &itimer, NULL) != 0) {
		fatal("could not set timer to %d second%s", interval,
		    interval == 1 ? "" : "s");
	}

	(void) sigemptyset(&set);

	for (;;) {
		kstat_instances_update(kcp, &instances, interested);
		kstat_instances_read(kcp, instances, fields);

		if (i++ > 0) {
			kstat_instances_print(instances, fields,
			    instances != NULL && instances->ksi_next == NULL ?
			    (((i - 2) % 20) == 0) : B_TRUE);
		}

		if (i > count)
			break;

		(void) sigsuspend(&set);
	}

	/*NOTREACHED*/
	return (0);
}
