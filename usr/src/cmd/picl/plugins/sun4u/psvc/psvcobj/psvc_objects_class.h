/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 1999-2001, 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_PSVC_OBJECTS_CLASS_H
#define	_PSVC_OBJECTS_CLASS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Platform Services Framework private definitions
 */
#include	<pthread.h>

#define	NAMELEN		32
#define	PATHLEN		256

/* Logical device class */
typedef struct {
	int32_t		class;
	int32_t		subclass;
	int32_t		instance;
	uint64_t	features;
	uint64_t	addr_spec;
	char		state[32];
	char		previous_state[32];
	char		fault_id[32];
	boolean_t	present;
	boolean_t	previous_presence;
	boolean_t	enabled;
	char		label[32];
	int32_t 	(*constructor)();
	int32_t		(*destructor)();
	int32_t		(*get_attr)();
	int32_t		(*set_attr)();
} EObj_t;

typedef struct {
	EObj_t		ld;		/* logical device */
	int32_t		hw_lo_shut;
	int32_t		lo_warn;	/* low warning threshold */
	int32_t		lo_shut;	/* low shutdown threshold */
	int32_t		opt_temp;
	int32_t		hi_warn;	/* high warning threshold */
	int32_t		hi_shut;	/* high shutdown threshold */
	int32_t		hw_hi_shut;
} ETempSensor_t;

typedef struct {
	EObj_t		ld;		/* logical device */
	int16_t		setpoint;
	int16_t		hysteresis;
	int16_t		loopgain;
	int16_t		loopbias;
	float		temp_differential[PSVC_MAXERRORS];
	int16_t		temp_differential_index;
} EFan_t;

typedef struct {
	EObj_t		ld;			/* logical device */
} ESystem_t;

typedef struct {
	EObj_t		ld;		/* logical device */
	int32_t		lo_warn;	/* low warning threshold */
	int32_t		lo_shut;	/* low shutdown threshold */
	int32_t		hi_warn;	/* high warning threshold */
	int32_t		hi_shut;	/* high shutdown threshold */
} EDigiSensor_t;

typedef struct {
	EObj_t		ld;			/* logical device */
} EDigiControl_t;

typedef struct {
	EObj_t		ld;			/* logical device */
} EBoolSensor_t;

typedef struct {
	EObj_t		ld;
} EGPIO8_t;

typedef struct {
	EObj_t		ld;			/* logical device */
	int16_t		lit_count;
	char		color[32];
	char		is_locator[8];
	char		locator_name[32];
} ELed_t;

typedef struct {
	EObj_t		ld;		/* logical device */
	int32_t		lo_warn;	/* low warning threshold */
	int32_t		lo_shut;	/* low shutdown threshold */
	int32_t		hi_warn;	/* high warning threshold */
	int32_t		hi_shut;	/* high shutdown threshold */
} EFanTach_t;

typedef struct {
	EObj_t		ld;			/* logical device */
	char		switch_state[32];
} ESwitch_t;

typedef struct {
	EObj_t		ld;			/* logical device */
} EKeySwitch_t;

typedef struct {
	EObj_t		ld;			/* logical device */
	int32_t		(*get_temperature)();
	int32_t		(*get_fanspeed)();
	int32_t		(*get_bit)();
	int32_t		(*set_bit)();
	int32_t		(*get_port)();
	int32_t		(*set_port)();
	int32_t		(*get_reg)();
	int32_t		(*set_reg)();
	int32_t		(*get_output)();
	int32_t		(*set_output)();
	int32_t		(*get_input)();
} EPhysDev_t;

typedef struct {
	uint8_t		cell_type;
	uint32_t	size;
	int64_t		*table;
} ETable_t;

typedef struct {
	char		antecedent_id[NAMELEN];
	int32_t		ant_key;
	char		dependent_id[NAMELEN];
} EAssoc_t;

typedef struct {
	char		name[NAMELEN];
	uint32_t	count;
	EAssoc_t	*table;
} EAssocList_t;

/* structure for translating string to id */
typedef struct {
	int32_t		id;
	char		name[NAMELEN];
} EStringId_t;

typedef struct {
	uint32_t	controller;
	uint32_t	bus;
	uint32_t	addr;
	uint32_t	port;
	char		path[PATHLEN];
} EDevice_t;

/* translate name to object (or table) pointer */
typedef struct {
	char		name[NAMELEN];
	int32_t		key;
	EObj_t		*objp;
	int32_t		type;		/* object or table */
} ENamePtr_t;

typedef struct {
	ENamePtr_t	*obj_tbl;	/* object name to pointer translation */
	uint32_t	obj_count;	/* number of objects */
	uint32_t	nextid;		/* next open object slot */
} ETable_Array;

#define	PSVC_OBJ	0
#define	PSVC_TBL	1
#define	PSVC_MAX_TABLE_ARRAYS	10

typedef struct {
	ETable_Array	tbl_arry[PSVC_MAX_TABLE_ARRAYS];
	uint32_t	total_obj_count; /* Total number of objects */
	EStringId_t	*othr_tbl;	/* assoc string to id translations */
	uint32_t	othr_count;	/* number of assoc strings */
	EAssocList_t	*assoc_tbl;	/* associations between objects */
	uint32_t	assoc_count;	/* number of associations */
	EDevice_t	*dev_tbl;	/* device paths */
	uint32_t	dev_count;	/* number of device paths */
	FILE		*fp;		/* config file */
	pthread_mutex_t	mutex;		/* multi threaded protection */
} EHdl_t;

/* String lookup table for attributes */
static char *attr_str_tab[] = {
	"_class",				/* 0 */
	"Subclass",				/* 1 */
	"Presence",				/* 2 */
	"Previous-presence",			/* 3 */
	"State",				/* 4 */
	"Previous-state",			/* 5 */
	"Enabled",				/* 6 */
	"FaultInformation",			/* 7 */
	"Features",				/* 8 */
	"Label",				/* 9 */
	"Fruid",				/* 10 */
	"Instance",				/* 11 */
	"Led-color",				/* 12 */
	"Lo-warn",				/* 13 */
	"Lo-shut",				/* 14 */
	"Hi-warn",				/* 15 */
	"Hi-shut",				/* 16 */
	"Opt-temp",				/* 17 */
	"Hw-hi-shut",				/* 18 */
	"Hw-lo-shut",				/* 19 */
	"Setpoint",				/* 20 */
	"Hysteresis",				/* 21 */
	"Loopgain",				/* 22 */
	"Loopbias",				/* 23 */
	"Temp_differential",			/* 24 */
	"Temp_differential_index",		/* 25 */
	"Sensor-value",				/* 26 */
	"Gpio-value",				/* 27 */
	"#Bits",				/* 28 */
	"Control-value",			/* 29 */
	"Led-state",				/* 30 */
	"Switch-state",				/* 31 */
	"Probe-result",				/* 32 */
	"Table_value",				/* 33 */
	"Assoc_id",				/* 34 */
	"Assoc_matches",			/* 35 */
	"Addr-spec",				/* 36 */
	"Object-id",				/* 37 */
	"Led-lit-count",			/* 38 */
	"FRU-info",				/* 39 */
	"IsLocator",				/* 40 */
	"LocatorName"				/* 41 */
};

int	ATTR_STR_TAB_SIZE = sizeof (attr_str_tab) / sizeof (char *);

#ifdef	__cplusplus
}
#endif

#endif /* _PSVC_OBJECTS_CLASS_H */
