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
#include <unistd.h>
#include <errno.h>

#include <sys/mutex.h>

#include <kstat.h>

#include <sys/unistat/spcs_s.h>
#include <sys/nsctl/dsw.h>
#include "../../../uts/common/avs/ns/dsw/dsw_dev.h"
#include <sys/nsctl/dsw_dev.h>

#include "sdbc_stats.h"
#include "ii_stats.h"

#include "dsstat.h"
#include "common.h"
#include "report.h"

static iistat_t *ii_top = NULL;

void ii_add_stat(iistat_t *);
iistat_t *ii_del_stat(iistat_t *);

int ii_value_check(iistat_t *iistat);
int ii_validate(kstat_t *ksp);
int ii_vol_selected(kstat_t *);

/*
 * ii_discover() - looks for new statistics to be monitored.
 * Verifies that any statistics found are now already being
 * monitored.
 *
 */
int
ii_discover(kstat_ctl_t *kc)
{
	static int validated = 0;

	kstat_t *ksp;

	/* Loop on all kstats */
	for (ksp = kc->kc_chain; ksp; ksp = ksp->ks_next) {
		char *kname;
		iistat_t *cur;
		iistat_t *iistat = NULL;
		kstat_t *mst_ksp;
		kstat_t *shd_ksp;
		kstat_t *bmp_ksp;
		kstat_t *ovr_ksp;

		/* Search for II set */
		if (strcmp(ksp->ks_class, II_KSTAT_CLASS) != 0)
			continue;

		if (kstat_read(kc, ksp, NULL) == -1)
			continue;

		/*
		 * Validate kstat structure
		 */
		if (! validated) {
			if (ii_validate(ksp))
				return (EINVAL);

			validated++;
		}

		/*
		 * Duplicate check
		 */
		for (cur = ii_top; cur != NULL; cur = cur->next) {
			char *cur_vname, *tst_vname;
			uint32_t cur_inst, tst_inst;

			cur_vname = cur->pre_set->ks_name;
			cur_inst = cur->pre_set->ks_instance;

			tst_vname = ksp->ks_name;
			tst_inst = ksp->ks_instance;

			if (strcmp(cur_vname, tst_vname) == 0 &&
			    cur_inst == tst_inst)
				goto next;
		}

		/*
		 * Initialize new record
		 */
		iistat = (iistat_t *)calloc(1, sizeof (iistat_t));

		/*
		 * Set kstat
		 */
		iistat->pre_set = kstat_retrieve(kc, ksp);

		if (iistat->pre_set == NULL)
			goto next;

		iistat->collected |= GOT_SETSTAT;

		/*
		 * Master kstat
		 */
		kname = kstat_value(iistat->pre_set, DSW_SKSTAT_MSTIO);

		mst_ksp = kstat_lookup(kc, II_KSTAT_MODULE, -1, kname);
		iistat->pre_mst = kstat_retrieve(kc, mst_ksp);

		if (iistat->pre_mst == NULL)
			goto next;

		iistat->collected |= GOT_MSTSTAT;

		/*
		 * Shadow kstat
		 */
		kname = kstat_value(iistat->pre_set, DSW_SKSTAT_SHDIO);

		shd_ksp = kstat_lookup(kc, II_KSTAT_MODULE, -1, kname);
		iistat->pre_shd = kstat_retrieve(kc, shd_ksp);

		if (iistat->pre_shd == NULL)
			goto next;

		iistat->collected |= GOT_SHDSTAT;

		/*
		 * Bitmap kstat
		 */
		kname = kstat_value(iistat->pre_set, DSW_SKSTAT_BMPIO);

		bmp_ksp = kstat_lookup(kc, II_KSTAT_MODULE, -1, kname);
		iistat->pre_bmp = kstat_retrieve(kc, bmp_ksp);

		if (iistat->pre_bmp == NULL)
			goto next;

		iistat->collected |= GOT_BMPSTAT;

		/*
		 * Overflow kstat
		 */
		kname = kstat_value(iistat->pre_set, DSW_SKSTAT_OVRIO);

		ovr_ksp = kstat_lookup(kc, II_KSTAT_MODULE, -1, kname);
		iistat->pre_ovr = kstat_retrieve(kc, ovr_ksp);

		if (iistat->pre_ovr == NULL)
			goto next;

		iistat->collected |= GOT_OVRSTAT;

next:
		/*
		 * Check if we got a complete set of stats
		 */
		if (iistat == NULL)
			continue;

		if (IIMG_COMPLETE(iistat->collected)) {
			(void) ii_del_stat(iistat);
			continue;
		}

		/*
		 * Add to linked list
		 */
		ii_add_stat(iistat);
	}

	if (ii_top == NULL)
		return (EAGAIN);

	return (0);
}

/*
 * ii_update() - updates all of the statistics currently being monitored.
 *
 */
int
ii_update(kstat_ctl_t *kc)
{
	iistat_t *cur;

	for (cur = ii_top; cur != NULL; cur = cur->next) {
		char volname[KSTAT_STRLEN + 1];
		char *kname;

		kstat_t *ksp = NULL;

		cur->collected = 0;

		/*
		 * Age off old stats
		 */
		if (cur->cur_set != NULL) {
			kstat_free(cur->pre_set);
			kstat_free(cur->pre_mst);
			kstat_free(cur->pre_shd);
			kstat_free(cur->pre_bmp);

			cur->pre_set = cur->cur_set;
			cur->pre_mst = cur->cur_mst;
			cur->pre_shd = cur->cur_shd;
			cur->pre_bmp = cur->cur_bmp;

			if (cur->cur_ovr != NULL) {
				kstat_free(cur->pre_ovr);
				cur->pre_ovr = cur->cur_ovr;
			}
		}

		/*
		 * Set kstat
		 */
		strncpy(volname, cur->pre_set->ks_name, KSTAT_STRLEN);
		volname[KSTAT_STRLEN] = '\0';

		ksp = kstat_lookup(kc, II_KSTAT_MODULE, -1, volname);

		if ((cur->cur_set = kstat_retrieve(kc, ksp)) == NULL)
			continue;

		cur->collected |= GOT_SETSTAT;

		/*
		 * Validate set
		 */
		if (strcmp(cur->pre_set->ks_name, cur->cur_set->ks_name) != 0 ||
		    cur->pre_set->ks_instance != cur->cur_set->ks_instance)
			continue;

		/*
		 * Master kstat
		 */
		kname = kstat_value(cur->cur_set, DSW_SKSTAT_MSTIO);

		ksp = kstat_lookup(kc, II_KSTAT_MODULE, -1, kname);

		if ((cur->cur_mst = kstat_retrieve(kc, ksp)) == NULL)
			continue;

		cur->collected |= GOT_MSTSTAT;

		/*
		 * Shadow kstat
		 */
		kname = kstat_value(cur->cur_set, DSW_SKSTAT_SHDIO);

		ksp = kstat_lookup(kc, II_KSTAT_MODULE, -1, kname);

		if ((cur->cur_shd = kstat_retrieve(kc, ksp)) == NULL)
			continue;

		cur->collected |= GOT_SHDSTAT;

		/*
		 * Bitmap kstat
		 */
		kname = kstat_value(cur->pre_set, DSW_SKSTAT_BMPIO);

		ksp = kstat_lookup(kc, II_KSTAT_MODULE, -1, kname);

		if ((cur->cur_bmp = kstat_retrieve(kc, ksp)) == NULL)
			continue;

		cur->collected |= GOT_BMPSTAT;

		/*
		 * Overflow kstat
		 */
		kname = kstat_value(cur->cur_set, DSW_SKSTAT_OVRIO);

		ksp = kstat_lookup(kc, II_KSTAT_MODULE, -1, kname);

		if (ksp == NULL) {
			if (cur->pre_ovr != NULL) {
				kstat_free(cur->pre_ovr);
				cur->pre_ovr = NULL;
			}
			if (cur->cur_ovr != NULL) {
				kstat_free(cur->cur_ovr);
				cur->cur_ovr = NULL;
			}
			continue;
		}

		if (cur->pre_ovr == NULL) {
			if ((cur->pre_ovr = kstat_retrieve(kc, ksp)) == NULL)
				continue;
		} else {
			if ((cur->cur_ovr = kstat_retrieve(kc, ksp)) == NULL)
				continue;
		}

		cur->collected |= GOT_OVRSTAT;
	}

	return (0);
}

/*
 * ii_report() - outputs statistics for the statistics currently being
 * monitored.  Deletes statistics for volumes that have been disabled.
 *
 */
int
ii_report()
{
	uint32_t *flags;
	int padsz = 0;
	char pad[20] = {0};
	iistat_t *cur, *pre = NULL;

	if (ii_top == NULL) {
		return (0);
	}

	/* Create padding string for secondary report lines */
	if (dflags & FLAGS) {
		padsz += STAT_HDR_SIZE;
		padsz += STAT_HDR_SIZE;
	}

	if (dflags & PCTS)
		padsz += PCT_HDR_SIZE;

	if (padsz) {
		char fmt[20];
		sprintf(fmt, "%%%ds", padsz);
		sprintf(pad, fmt, "");
	}

	for (cur = ii_top; cur; /* CSTYLED */) {
		int first = 1;
		char data[20] = {0};

		/* Check to see if this is this a complete */
		if (IIMG_COMPLETE(cur->collected)) {
			char *c;
			char vol[(NAMED_LEN * 4) + 1] = {0};
			int offset;
			iistat_t *next;

			/* notify user of set being disabled */
			c = kstat_value(cur->pre_set, DSW_SKSTAT_SETA);
			strncpy(vol, c, NAMED_LEN);
			c = kstat_value(cur->pre_set, DSW_SKSTAT_SETB);
			strncat(vol, c, NAMED_LEN);
			c = kstat_value(cur->pre_set, DSW_SKSTAT_SETC);
			strncat(vol, c, NAMED_LEN);
			c = kstat_value(cur->pre_set, DSW_SKSTAT_SETD);
			strncat(vol, c, NAMED_LEN);

			offset = strlen(vol) - NAMED_LEN;

			if (offset < 0)
				offset = 0;

			printf(DATA_C16, vol + offset);
			printf(" %s\n", II_DISABLED);

			/* free memory and remove stat from list */
			next = ii_del_stat(cur);

			if (! pre)
				cur = ii_top = next;
			else
				cur = pre->next = next;

			continue;
		}

		/* Check to see if the user specified this volume */
		if (! ii_vol_selected(cur->pre_set))
			goto next;

		/* Check to see if zflag applies */
		if (zflag && ii_value_check(cur) == 0)
			goto next;

		/* Calculate flags */
		flags = kstat_value(cur->cur_set, DSW_SKSTAT_FLAGS);

		if (dflags & FLAGS) {

			char c[STAT_HDR_SIZE];
			char vtype[STAT_HDR_SIZE];
			char vstat[STAT_HDR_SIZE];

			if (*flags & DSW_GOLDEN)
				strcpy(c, II_INDEPENDENT);
			else
				strcpy(c, II_DEPENDENT);

			sprintf(vtype, DATA_C2, c);
			strcat(data, vtype);

			if (*flags & DSW_COPYINGP)
				strcpy(c, II_COPYING);
			else
				strcpy(c, NO_INFO);


			sprintf(vstat, DATA_C2, c);
			strcat(data, vstat);
		}

		/* Calculate sync needed precentage */
		if (dflags & PCTS) {
			char snpct[10];
			uint32_t *chkbits;
			uint32_t *cpybits;
			uint32_t *shdbits;
			uint32_t *volsize;
			float pct;

			cpybits =
			    kstat_value(cur->cur_set, DSW_SKSTAT_COPYBITS);

			shdbits =
			    kstat_value(cur->cur_set, DSW_SKSTAT_SHDBITS);

			volsize =
			    kstat_value(cur->cur_set, DSW_SKSTAT_SIZE);

			*volsize /= DSW_SIZE;

			chkbits = *cpybits >= *shdbits ? cpybits : shdbits;

			pct = ((float)*chkbits / *volsize) * 100.0;

			sprintf(snpct, DATA_F62, pct);

			strcat(data, snpct);
		}

		/* Master statistics */
		if (rflags & IIMG_MST) {
			char *c;
			char vol[(NAMED_LEN * 4) + 1] = {0};
			int offset;

			c = kstat_value(cur->cur_set, DSW_SKSTAT_MSTA);
			strncat(vol, c, NAMED_LEN);
			c = kstat_value(cur->cur_set, DSW_SKSTAT_MSTB);
			strncat(vol, c, NAMED_LEN);
			c = kstat_value(cur->cur_set, DSW_SKSTAT_MSTC);
			strncat(vol, c, NAMED_LEN);
			c = kstat_value(cur->cur_set, DSW_SKSTAT_MSTD);
			strncat(vol, c, NAMED_LEN);

			offset = strlen(vol) - NAMED_LEN;

			if (offset < 0)
				offset = 0;

			header();
			printf(DATA_C16, vol + offset);
			printf("%s", data);
			printf(ROLE_INF_FMT, II_MASTER);

			if (*flags & DSW_MSTOFFLINE) {
				printf(" <<offline>>");
				linesout++;
			} else {
				io_report(cur->cur_mst->ks_data,
				    cur->pre_mst->ks_data,
				    sdbc_getstat(vol + offset));
			}

			printf("\n");

			if (first) {
				strcpy(data, strlen(pad) > 0 ? pad : "");
				first = 0;
			}
		}

		/* Shadow statistics */
		if (rflags & IIMG_SHD) {
			char *c;
			char vol[(NAMED_LEN * 4) + 1] = {0};
			int offset;

			c = kstat_value(cur->cur_set, DSW_SKSTAT_SETA);
			strncat(vol, c, NAMED_LEN);
			c = kstat_value(cur->cur_set, DSW_SKSTAT_SETB);
			strncat(vol, c, NAMED_LEN);
			c = kstat_value(cur->cur_set, DSW_SKSTAT_SETC);
			strncat(vol, c, NAMED_LEN);
			c = kstat_value(cur->cur_set, DSW_SKSTAT_SETD);
			strncat(vol, c, NAMED_LEN);

			offset = strlen(vol) - NAMED_LEN;

			if (offset < 0)
				offset = 0;

			header();
			printf(DATA_C16, vol + offset);
			printf("%s", data);
			printf(ROLE_INF_FMT, II_SHADOW);

			if (*flags & DSW_SHDOFFLINE) {
				printf(" <<offline>>");
				linesout++;
			} else {
				io_report(cur->cur_shd->ks_data,
				    cur->pre_shd->ks_data,
				    sdbc_getstat(vol + offset));
			}

			printf("\n");

			if (first) {
				strcpy(data, strlen(pad) > 0 ? pad : "");
				first = 0;
			}
		}

		/* Bitmap statistics */
		if (rflags & IIMG_BMP) {
			char *c;
			char vol[(NAMED_LEN * 4) + 1] = {0};
			int offset;

			c = kstat_value(cur->cur_set, DSW_SKSTAT_BMPA);
			strncat(vol, c, NAMED_LEN);
			c = kstat_value(cur->cur_set, DSW_SKSTAT_BMPB);
			strncat(vol, c, NAMED_LEN);
			c = kstat_value(cur->cur_set, DSW_SKSTAT_BMPC);
			strncat(vol, c, NAMED_LEN);
			c = kstat_value(cur->cur_set, DSW_SKSTAT_BMPD);
			strncat(vol, c, NAMED_LEN);

			offset = strlen(vol) - NAMED_LEN;

			if (offset < 0)
				offset = 0;

			header();
			printf(DATA_C16, vol + offset);
			printf("%s", data);
			printf(ROLE_INF_FMT, II_BITMAP);

			if (*flags & DSW_BMPOFFLINE) {
				printf(" <<offline>>");
				linesout++;
			} else {
				io_report(cur->cur_bmp->ks_data,
				    cur->pre_bmp->ks_data,
				    sdbc_getstat(vol + offset));
			}
			printf("\n");

			if (first) {
				strcpy(data, strlen(pad) > 0 ? pad : "");
				first = 0;
			}
		}

		/* Overflow statistics */
		if (rflags & IIMG_OVR) {
			char *c;
			char msg[20] = {0};
			char vol[(NAMED_LEN * 4) + 1] = {0};
			int offset;

			if (cur->cur_ovr == NULL && cur->pre_ovr != NULL)
				strcpy(msg, " <<attached>>");

			if (! (cur->collected & GOT_OVRSTAT))
				strcpy(msg, " <<not attached>>");

			c = kstat_value(cur->cur_set, DSW_SKSTAT_OVRA);
			strncpy(vol, c, NAMED_LEN);
			c = kstat_value(cur->cur_set, DSW_SKSTAT_OVRB);
			strncat(vol, c, NAMED_LEN);
			c = kstat_value(cur->cur_set, DSW_SKSTAT_OVRC);
			strncat(vol, c, NAMED_LEN);
			c = kstat_value(cur->cur_set, DSW_SKSTAT_OVRD);
			strncat(vol, c, NAMED_LEN);

			offset = strlen(vol) - NAMED_LEN;

			if (offset < 0)
				offset = 0;

			header();
			printf(DATA_C16, vol + offset);
			printf("%s", data);
			printf(ROLE_INF_FMT, II_OVERFLOW);

			if (strlen(msg)) {
				printf("%s\n", msg);
				linesout++;
				goto next;
			}

			if (*flags & DSW_OVROFFLINE) {
				printf(" <<offline>>");
				linesout++;
			} else {
				io_report(cur->cur_ovr->ks_data,
				    cur->pre_ovr->ks_data,
				    sdbc_getstat(vol + offset));
			}

			printf("\n");

			if (first) {
				strcpy(data, strlen(pad) > 0 ? pad : "");
				first = 0;
			}
		}


next:
		pre = cur;
		cur = cur->next;
	}

	return (0);
}

/*
 * ii_add_stat() - adds a fully populated iistat_t structure
 * to the linked list of currently monitored kstats.  The structure
 * will be added in alphabetical order, using the volume name of
 * the shadow volume as the key.
 *
 */
void
ii_add_stat(iistat_t *iistat)
{

	iistat_t *cur;

	if (ii_top == NULL) {
		ii_top = iistat;
		return;
	}

	for (cur = ii_top; cur != NULL; cur = cur->next) {
		if (strcmp(cur->pre_set->ks_name,
		    iistat->pre_set->ks_name) <= 0) {
			/*
			 * If we get to the last item in the list, then just
			 * add this one to the end
			 */
			if (cur->next == NULL) {
				cur->next = iistat;
				return;
			}

			if (strcmp(cur->next->pre_set->ks_name,
			    iistat->pre_set->ks_name) > 0) {
				iistat->next = cur->next;
				cur->next = iistat;
				return;
			}
		} else {
			if (cur == ii_top)
				ii_top = iistat;

			iistat->next = cur;

			return;
		}
	}
}

/*
 * ii_del_stat() - deallocate memory for the structure being
 * passed in.
 *
 * parameters
 * 	iistat_t *iistat - structure to be deallocated
 *
 * returns
 * 	iistat_t * - pointer to the "next" structures in the
 * 	linked list. May be NULL if we are removing the last
 * 	structure in the linked list.
 *
 */
iistat_t *
ii_del_stat(iistat_t *iistat)
{

	iistat_t *next = iistat->next;

	kstat_free(iistat->pre_set);
	kstat_free(iistat->pre_mst);
	kstat_free(iistat->pre_shd);
	kstat_free(iistat->pre_bmp);
	kstat_free(iistat->pre_ovr);
	kstat_free(iistat->cur_set);
	kstat_free(iistat->cur_mst);
	kstat_free(iistat->cur_shd);
	kstat_free(iistat->cur_bmp);
	kstat_free(iistat->cur_ovr);

	free(iistat);

	return (next);
}

int
ii_value_check(iistat_t *iistat)
{
	if (IIMG_COMPLETE(iistat->collected))
		return (1);

	if (io_value_check(iistat->pre_mst->ks_data,
	    iistat->cur_mst->ks_data)) {
		return (1);
	}

	if (io_value_check(iistat->pre_shd->ks_data,
	    iistat->cur_shd->ks_data)) {
		return (1);
	}

	if (io_value_check(iistat->pre_bmp->ks_data,
	    iistat->cur_bmp->ks_data)) {
		return (1);
	}

	if (iistat->pre_ovr && iistat->cur_ovr) {
		if (io_value_check(iistat->pre_ovr->ks_data,
		    iistat->cur_ovr->ks_data)) {
			return (1);
		}
	}

	return (0);
}

int
ii_validate(kstat_t *ksp)
{
	if (! kstat_value(ksp, DSW_SKSTAT_MSTIO) ||
	    ! kstat_value(ksp, DSW_SKSTAT_SHDIO) ||
	    ! kstat_value(ksp, DSW_SKSTAT_BMPIO) ||
	    ! kstat_value(ksp, DSW_SKSTAT_OVRIO) ||
	    ! kstat_value(ksp, DSW_SKSTAT_FLAGS) ||
	    ! kstat_value(ksp, DSW_SKSTAT_MSTA) ||
	    ! kstat_value(ksp, DSW_SKSTAT_SETA) ||
	    ! kstat_value(ksp, DSW_SKSTAT_BMPA) ||
	    ! kstat_value(ksp, DSW_SKSTAT_OVRA) ||
	    ! kstat_value(ksp, DSW_SKSTAT_SHDBITS) ||
	    ! kstat_value(ksp, DSW_SKSTAT_COPYBITS) ||
	    ! kstat_value(ksp, DSW_SKSTAT_SIZE))
		return (1);

	return (0);
}

int
ii_vol_selected(kstat_t *ksp)
{
	vslist_t *vslist = vs_top;

	for (vslist = vs_top; vslist != NULL; vslist = vslist->next) {
		char *vn;
		int off = 0;

		vn = ksp->ks_name;

		if ((off = strlen(vn) - NAMED_LEN) <= 0) {
			off = 0;
		}

		if (strcmp(vslist->volname, &vn[off]) == 0) {
			break;
		}
	}

	if (vs_top != NULL && vslist == NULL) {
		return (0);
	} else {
		return (1);
	}
}
