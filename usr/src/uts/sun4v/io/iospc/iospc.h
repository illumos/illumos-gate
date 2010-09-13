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

#ifndef	_IOSPC_H
#define	_IOSPC_H

/*
 * Definitions which deal with things other than registers.
 */

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/sunddi.h>

#define	SUCCESS	0
#define	FAILURE	-1

#define	NAMEINST(dip)	ddi_driver_name(dip), ddi_get_instance(dip)

/* Used for data structure retrieval during kstat update. */
typedef struct iospc_ksinfo {
	kstat_t		*cntr_ksp;
	struct iospc	*iospc_p;
	struct iospc_grp *grp_p;
	void		*arg;
} iospc_ksinfo_t;

#define	IOSPC_MAX_NUM_GRPS	10

/* State structure. */
typedef struct iospc {
	dev_info_t	*iospc_dip;
	iospc_ksinfo_t	*iospc_ksinfo_p[IOSPC_MAX_NUM_GRPS];
} iospc_t;

/*
 * Description of a counter's events.  Each counter will have an array of these,
 * to define the events it can be programmed to report.  Nonprogrammable
 * counters still need an array of these, to contain the name busstat will
 * display for it, and a CLEAR_PIC entry.
 */
typedef struct iospc_event {
	char *name;
	uint64_t value;
} iospc_event_t;

#define	NUM_EVTS(x)	(sizeof (x) / sizeof (iospc_event_t))

/*
 * Counter description, including its access logistics and how to zero it.
 */
typedef struct iospc_cntr {
	off_t regoff;		/* Register offset or address. */
	uint64_t fld_mask;	/* Width of the active part of the register */
	off_t zero_regoff;	/* Offset of register used to zero counter. */
	uint64_t zero_value;	/* Value to write to zero_regoff, to clr cntr */
} iospc_cntr_t;

#define	FULL64BIT	-1ULL   /* Can use this for fld_mask. */

#define	NUM_CTRS(x)	(sizeof (x) / sizeof (iospc_cntr_t))

/*
 * Description of a counter's event selection.  There will be one entry for
 * each counter in the group.
 */
typedef struct iospc_regsel_fld {
	iospc_event_t *events_p;
	int num_events;		/* Size of events array. */
	uint64_t event_mask;	/* Width of the event field. */
	int event_offset;	/* Offset of the event field. */
} iospc_regsel_fld_t;

/*
 * Description of a group's select register.
 */
typedef struct iospc_regsel {
	off_t regoff;			/* Register offset or address. */
	iospc_regsel_fld_t *fields_p;	/* select reg subfield descriptions.  */
	int num_fields;			/* Size of the fields array. */
} iospc_regsel_t;

#define	NUM_FLDS(x)	(sizeof (x) / sizeof (iospc_regsel_fld_t))

#define	IOSPC_REG_READ	0
#define	IOSPC_REG_WRITE	1

/* Standin symbol for when there is no register. */
#define	NO_REGISTER	(off_t)-1ULL

/*
 * Group description.
 */
typedef struct iospc_grp {
	char *grp_name;		 /* Name, shows up as busstat "module" name. */
	iospc_regsel_t *regsel_p; /* Select register. */
	iospc_cntr_t *counters_p; /* Counter definitions. */
	int num_counters;	 /* Size of the counters array. */
	int (*access_init)(iospc_t *iospc_p, iospc_ksinfo_t *ksinfo_p);
	int (*access)(iospc_t *iospc_p, void *, int op, int regid,
	    uint64_t *data);
	int (*access_fini)(iospc_t *iospc_p, iospc_ksinfo_t *ksinfo_p);
	kstat_t **name_kstats_pp; /* Named kstats.  One for all instances. */
} iospc_grp_t;

/* Debugging facility. */
#ifdef DEBUG
extern int iospc_debug;
#define	IOSPC_DBG1 if (iospc_debug >= 1) printf
#define	IOSPC_DBG2 if (iospc_debug >= 2) printf
#else
#define	IOSPC_DBG1 0 &&
#define	IOSPC_DBG2 0 &&
#endif	/* DEBUG */

/* Function definitions exported among different modules. */
extern int iospc_kstat_init(void);
extern void iospc_kstat_fini(void);
extern int iospc_kstat_attach(iospc_t *iospc_p);
extern void iospc_kstat_detach(iospc_t *iospc_p);
extern iospc_grp_t **rfios_bind_group(void);
extern void rfios_unbind_group(void);

#ifdef	__cplusplus
}
#endif

#endif	/* _IOSPC_H */
