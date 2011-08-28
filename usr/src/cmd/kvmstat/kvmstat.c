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
 * Copyright (c) 2011, Joyent, Inc. All rights reserved.
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

#define	KSTAT_FIELD_USEINSTANCE		0x01
#define	KSTAT_FIELD_NODELTA		0x02
#define	KSTAT_FIELD_FILLER		0x04

typedef struct kstat_field {
	char *ksf_header;		/* header for field */
	char *ksf_name;			/* name of stat, if any */
	int ksf_width;			/* width for field in output line */
	uint32_t ksf_flags;		/* flags for this field, if any */
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

const char *g_cmd = "kvmstat";

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

			ksi->ksi_data[ksi->ksi_gen][i] = nm[hint].value.ui64;
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

			(void) printf("%*lld%c", fields[i].ksf_width,
			    fields[i].ksf_flags & KSTAT_FIELD_USEINSTANCE ?
			    ksi->ksi_instance :
			    fields[i].ksf_flags & KSTAT_FIELD_NODELTA ?
			    ksi->ksi_data[ksi->ksi_gen ^ 1][i] :
			    kstat_instances_delta(ksi, i), trailer);
		}
	}
}

boolean_t
interested(kstat_t *ksp)
{
	const char *module = "kvm";
	const char *class = "misc";
	const char *name = "vcpu-";

	if (strcmp(ksp->ks_module, module) != 0)
		return (B_FALSE);

	if (strcmp(ksp->ks_class, class) != 0)
		return (B_FALSE);

	if (strstr(ksp->ks_name, name) != ksp->ks_name)
		return (B_FALSE);

	return (B_TRUE);
}

/* BEGIN CSTYLED */
char *g_usage = "Usage: kvmstat [interval [count]]\n"
    "\n"
    "  Displays statistics for running kernel virtual machines, with one line\n"
    "  per virtual CPU.  All statistics are reported as per-second rates.\n"
    "\n"
    "  The columns are as follows:\n"
    "\n"
    "    pid    =>  identifier of process controlling the virtual CPU\n"
    "    vcpu   =>  virtual CPU identifier relative to its virtual machine\n"
    "    exits  =>  virtual machine exits for the virtual CPU\n"
    "    haltx  =>  virtual machine exits due to the HLT instruction\n"
    "    irqx   =>  virtual machine exits due to a pending external interrupt\n"
    "    irqwx  =>  virtual machine exits due to an open interrupt window\n"
    "    iox    =>  virtual machine exits due to an I/O instruction\n"
    "    mmiox  =>  virtual machine exits due to memory mapped I/O \n"
    "    irqs   =>  interrupts injected into the virtual CPU\n"
    "    emul   =>  instructions emulated in the kernel\n"
    "    eptv   =>  extended page table violations\n"
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
		{ "pid", "pid", 6, KSTAT_FIELD_NODELTA },
		{ "vcpu", NULL, 4, KSTAT_FIELD_USEINSTANCE },
		{ "|", NULL, 1, KSTAT_FIELD_FILLER },
		{ "exits", "exits", 6 },
		{ ":", NULL, 1, KSTAT_FIELD_FILLER },
		{ "haltx", "halt-exits", 6 },
		{ "irqx", "irq-exits", 6 },
		{ "irqwx", "irq-window-exits", 6 },
		{ "iox", "io-exits", 6 },
		{ "mmiox", "mmio-exits", 6 },
		{ "|", NULL, 1, KSTAT_FIELD_FILLER },
		{ "irqs", "irq-injections", 6 },
		{ "emul", "insn-emulation", 6 },
		{ "eptv", "pf-fixed", 6 },
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
