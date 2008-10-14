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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <kstat.h>
#include <signal.h>
#include <setjmp.h>

#include "sdbc_stats.h"
#include "report.h"
#include "common.h"

static sigjmp_buf env;
static sig_atomic_t sig_raised = 0;
static void sig_handler(int);

void
sig_handler(int sig)
{
	switch (sig) {
		case SIGSEGV:
			sig_raised = 1;
			siglongjmp(env, sig);
		default:
			exit(sig);
	}
}

/*
 * kstat_retrieve() - populate the ks_data field of the kstat_t structure
 *
 * This function is a user-land equivalent of a ks_snapshot
 *
 * parameters
 * 	kstat_ctl_t *kc - kstat_ctl_t structure representing returned from
 *			  kstat_open()
 * 	kstat_t *ksp - kstat_t strcture to popluate ks_data into
 *
 * returns
 * 	NULL pointer on failure
 * 	kstat_t * structure on success
 */
kstat_t *
kstat_retrieve(kstat_ctl_t *kc, kstat_t *ksp)
{

	kstat_t *rval;
	kstat_named_t *knp;
	char *end;
	int i;
	struct sigaction segv_act;	/* default actions */

	if (ksp == NULL)
		return (NULL);

	if (ksp->ks_data == NULL &&
	    kstat_read(kc, ksp, NULL) == -1)
		return (NULL);

	rval = (kstat_t *)calloc(1, sizeof (*ksp));
	memcpy(rval, ksp, sizeof (*ksp));

	rval->ks_data = (void *) calloc(1, ksp->ks_data_size);
	memcpy(rval->ks_data, ksp->ks_data,
	    sizeof (kstat_named_t) * ksp->ks_ndata);

	/* special handling for variable length string KSTAT_DATA_STRING */
	knp = (kstat_named_t *)rval->ks_data;
	end = (char *)(knp + ksp->ks_ndata);
	for (i = 0; i < ksp->ks_ndata; i++, knp++) {
		if (knp->data_type == KSTAT_DATA_STRING &&
		    KSTAT_NAMED_STR_PTR(knp) != NULL) {
			/* catch SIGSEGV (bug 6384130) */
			sig_raised = 0;
			(void) sigaction(SIGSEGV, NULL, &segv_act);
			(void) signal(SIGSEGV, sig_handler);

			strncpy(end, KSTAT_NAMED_STR_PTR(knp),
			    KSTAT_NAMED_STR_BUFLEN(knp));
			KSTAT_NAMED_STR_PTR(knp) = end;
			end += KSTAT_NAMED_STR_BUFLEN(knp);

			/* bug 6384130 */
			(void) sigsetjmp(env, 0);
			if (sig_raised) {
				bzero(end, KSTAT_NAMED_STR_BUFLEN(knp));
				KSTAT_NAMED_STR_PTR(knp) = end;
				end += KSTAT_NAMED_STR_BUFLEN(knp);
			}
			(void) sigaction(SIGSEGV, &segv_act, NULL);
		}
	}

	return (rval);
}

/*
 * kstat_value() - retrieve value of a field in a kstat_named_t kstat.
 *
 * parameters
 * 	kstat_t *ksp - kstat containing the field
 * 	char *name - text string representing the field name
 *
 * returns
 *	void * - pointer to data retrieved
 */
void *
kstat_value(kstat_t *ksp, char *name)
{
	kstat_named_t *knm;

	if ((knm = kstat_data_lookup(ksp, name)) == NULL)
		return (NULL);

	switch (knm->data_type) {
		case KSTAT_DATA_CHAR :
			return (knm->value.c);
		case KSTAT_DATA_INT32 :
			return (&knm->value.i32);
		case KSTAT_DATA_UINT32 :
			return (&knm->value.ui32);
		case KSTAT_DATA_INT64 :
			return (&knm->value.i64);
		case KSTAT_DATA_UINT64 :
			return (&knm->value.ui64);
		case KSTAT_DATA_STRING :
			return (KSTAT_NAMED_STR_PTR(knm));
	}

	return (NULL);
}

/*
 * kstat_free() - deallocated memory associated with a kstat
 *
 * paramters
 * 	kstat_t ksp - kstat to be deallocated
 *
 * returns
 * 	void
 */
void
kstat_free(kstat_t *ksp)
{
	if (ksp != NULL) {
		if (ksp->ks_data != NULL)
			free(ksp->ks_data);
		free(ksp);
	}
}

uint32_t
kstat_delta(kstat_t *pksp, kstat_t *cksp, char *name)
{
	uint32_t *pv, *cv;

	pv = kstat_value(pksp, name);
	cv = kstat_value(cksp, name);

	return (u32_delta(*pv, *cv));
}
