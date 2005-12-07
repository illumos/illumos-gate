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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This file consists of routines to manage objects in the
 * "Platform Environment Services Framework". The classes
 * and subclasses are defined by attributes and methods.
 * The objects, and their initial, static, attribute values are
 * specified in a configuration file, "psvcobj.conf".
 * psvc_init() reads the configuration file and creates a repository
 * of environmental objects in memory. A client application may manipulate
 * these objects by invoking the psvc_get_attr(), and psvc_set_attr()
 * routines with the object's string ID specified as an argument.
 */
#include <stdio.h>
#include <math.h>
#include <stdlib.h>
#include <unistd.h>
#include <stropts.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <syslog.h>
#include <stdarg.h>
#include <pthread.h>
#include <sys/systeminfo.h>

#define	LIBRARY_BUILD 1
#include <psvc_objects.h>
#include <psvc_objects_class.h>
#include <sys/i2c/clients/i2c_client.h>

/* Mutex used for Daktari Fan speed reading */
pthread_mutex_t fan_mutex = PTHREAD_MUTEX_INITIALIZER;

/*LINTLIBRARY*/

#define	ENV_DEBUG(str, id) printf("%s id %s\n", (str), (id))

#define	BUFSZ  512

#define	CLASS_MAX	12
#define	SUBCLASS_MAX	10

static int32_t i_psvc_constructor_0_0(EHdl_t *, char *, EObj_t **);
static int32_t i_psvc_constructor_0_1(EHdl_t *, char *, EObj_t **);
static int32_t i_psvc_constructor_1_0(EHdl_t *, char *, EObj_t **);
static int32_t i_psvc_constructor_2_0(EHdl_t *, char *, EObj_t **);
static int32_t i_psvc_constructor_2_1(EHdl_t *, char *, EObj_t **);
static int32_t i_psvc_constructor_2_2(EHdl_t *, char *, EObj_t **);
static int32_t i_psvc_constructor_3_0(EHdl_t *, char *, EObj_t **);
static int32_t i_psvc_constructor_4_0(EHdl_t *, char *, EObj_t **);
static int32_t i_psvc_constructor_5_0(EHdl_t *, char *, EObj_t **);
static int32_t i_psvc_constructor_6_0(EHdl_t *, char *, EObj_t **);
static int32_t i_psvc_constructor_7_0(EHdl_t *, char *, EObj_t **);
static int32_t i_psvc_constructor_8_0(EHdl_t *, char *, EObj_t **);
static int32_t i_psvc_constructor_9_0(EHdl_t *, char *, EObj_t **);
static int32_t i_psvc_constructor_10_0(EHdl_t *, char *, EObj_t **);
static int32_t i_psvc_constructor_10_1(EHdl_t *, char *, EObj_t **);
static int32_t i_psvc_constructor_11_0(EHdl_t *, char *, EObj_t **);
static int32_t i_psvc_constructor_11_1(EHdl_t *, char *, EObj_t **);
static int32_t i_psvc_constructor_11_2(EHdl_t *, char *, EObj_t **);
static int32_t i_psvc_constructor_11_3(EHdl_t *, char *, EObj_t **);
static int32_t i_psvc_constructor_11_4(EHdl_t *, char *, EObj_t **);
static int32_t i_psvc_constructor_11_5(EHdl_t *, char *, EObj_t **);
static int32_t i_psvc_constructor_11_6(EHdl_t *, char *, EObj_t **);
static int32_t i_psvc_constructor_11_7(EHdl_t *, char *, EObj_t **);
static int32_t i_psvc_constructor_11_8(EHdl_t *, char *, EObj_t **);
static int32_t i_psvc_constructor_11_9(EHdl_t *, char *, EObj_t **);

static int32_t i_psvc_get_obj(EHdl_t *, char *, EObj_t **);
static int32_t i_psvc_destructor(EHdl_t *, char *, void *);
static int32_t i_psvc_get_devpath(EHdl_t *, uint64_t, char *);
static int32_t i_psvc_get_attr_generic(EHdl_t *, EObj_t *, int32_t, void *);
static int32_t i_psvc_get_attr_6_0(EHdl_t *, EObj_t *, int32_t, void *);
static int32_t i_psvc_get_reg_11_0(EHdl_t *hdlp, EObj_t *objp, int32_t attr_id,
    void *attrp);
static int32_t i_psvc_get_attr_10_1(EHdl_t *, EObj_t *, int32_t, void *);
static int32_t psvc_get_str_key(char *object);

int32_t ioctl_retry(int fp, int request, void * arg_pointer);

/*
 * Method lookup tables
 * Update when adding classes or subclasses.
 */


/* Lookup method by class, subclass, used when calling method */
static int32_t (*i_psvc_constructor[CLASS_MAX][SUBCLASS_MAX])(EHdl_t *,
	char *, EObj_t **) = {
{i_psvc_constructor_0_0, i_psvc_constructor_0_1, 0, 0, 0, 0, 0, 0, 0, 0},
	{i_psvc_constructor_1_0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
{i_psvc_constructor_2_0, i_psvc_constructor_2_1, i_psvc_constructor_2_2,
		0, 0, 0, 0, 0, 0, 0},
	{i_psvc_constructor_3_0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
	{i_psvc_constructor_4_0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
	{i_psvc_constructor_5_0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
	{i_psvc_constructor_6_0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
	{i_psvc_constructor_7_0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
	{i_psvc_constructor_8_0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
	{i_psvc_constructor_9_0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
{i_psvc_constructor_10_0, i_psvc_constructor_10_1, 0, 0, 0, 0, 0, 0, 0, 0},
{i_psvc_constructor_11_0, i_psvc_constructor_11_1, i_psvc_constructor_11_2,
	i_psvc_constructor_11_3, i_psvc_constructor_11_4,
	i_psvc_constructor_11_5, i_psvc_constructor_11_6,
	i_psvc_constructor_11_7, i_psvc_constructor_11_8,
	i_psvc_constructor_11_9},
};

static int32_t i_psvc_cell_size[8] = {1, 1, 2, 2, 4, 4, 8, 8};

static struct bits {
	uint64_t	bit;
	char		*label;
} feature_bits[] = {
{PSVC_DEV_PERM, "PERM="},
{PSVC_DEV_HOTPLUG, "HOTPLUG="},
{PSVC_DEV_OPTION, "OPTION="},
{PSVC_DEV_PRIMARY, "PRIMARY="},
{PSVC_DEV_SECONDARY, "SECONDARY="},
{PSVC_DEV_RDONLY, "RDONLY="},
{PSVC_DEV_RDWR, "RDWR="},
{PSVC_DEV_FRU, "FRU="},
{PSVC_LOW_WARN, "LO_WARN_MASK="},
{PSVC_LOW_SHUT, "LO_SHUT_MASK="},
{PSVC_HIGH_WARN, "HI_WARN_MASK="},
{PSVC_HIGH_SHUT, "HI_SHUT_MASK="},
{PSVC_CONVERSION_TABLE, "CONV_TABLE="},
{PSVC_OPT_TEMP, "OPT_TEMP_MASK="},
{PSVC_HW_LOW_SHUT, "HW_LO_MASK="},
{PSVC_HW_HIGH_SHUT, "HW_HI_MASK="},
{PSVC_FAN_DRIVE_PR, "FAN_DRIVE_PR="},
{PSVC_TEMP_DRIVEN, "TEMP_DRIVEN="},
{PSVC_SPEED_CTRL_PR, "SPEED_CTRL_PR="},
{PSVC_FAN_ON_OFF, "FAN_ON_OFF="},
{PSVC_CLOSED_LOOP_CTRL, "CLOSED_LOOP_CTRL="},
{PSVC_FAN_DRIVE_TABLE_PR, "FAN_DRIVE_TABLE_PR="},
{PSVC_DIE_TEMP, "DIE_TEMP="},
{PSVC_AMB_TEMP, "AMB_TEMP="},
{PSVC_DIGI_SENSOR, "DIGI_SENSOR="},
{PSVC_BI_STATE, "BI_STATE="},
{PSVC_TRI_STATE, "TRI_STATE="},
{PSVC_GREEN, "GREEN="},
{PSVC_AMBER, "AMBER="},
{PSVC_OUTPUT, "OUTPUT="},
{PSVC_INPUT, "INPUT="},
{PSVC_BIDIR, "BIDIR="},
{PSVC_BIT_POS, "BIT_POS="},
{PSVC_VAL_POS, "VAL_POS="},
{PSVC_NORMAL_POS_AV, "NORMAL_POS_AV="},
{PSVC_DIAG_POS_AV, "DIAG_POS_AV="},
{PSVC_LOCK_POS_AV, "LOCK_POS_AV="},
{PSVC_OFF_POS_AV, "OFF_POS_AV="},
{PSVC_GPIO_PORT, "GPIO_PORT="},
{PSVC_GPIO_REG, "GPIO_REG="}
};

#define	ASSOC_STR_TAB_SIZE 33
static char *assoc_str_tab[] = {
	"PSVC_PRESENCE_SENSOR",			/* 0 */
	"PSVC_FAN_ONOFF_SENSOR",		/* 1 */
	"PSVC_FAN_SPEED_TACHOMETER",		/* 2 */
	"PSVC_FAN_PRIM_SEC_SELECTOR",		/* 3 */
	"PSVC_DEV_TEMP_SENSOR",			/* 4 */
	"PSVC_FAN_DRIVE_CONTROL",		/* 5 */
	"PSVC_KS_NORMAL_POS_SENSOR",		/* 6 */
	"PSVC_KS_DIAG_POS_SENSOR",		/* 7 */
	"PSVC_KS_LOCK_POS_SENSOR",		/* 8 */
	"PSVC_KS_OFF_POS_SENSOR",		/* 9 */
	"PSVC_SLOT_FAULT_LED",			/* 10 */
	"PSVC_SLOT_REMOVE_LED",			/* 11 */
	"PSVC_TS_OVERTEMP_LED",			/* 12 */
	"PSVC_PS_I_SENSOR",			/* 13 */
	"PSVC_DEV_FAULT_SENSOR",		/* 14 */
	"PSVC_DEV_FAULT_LED",			/* 15 */
	"PSVC_TABLE",				/* 16 */
	"PSVC_PARENT",				/* 17 */
	"PSVC_CPU",				/* 18 */
	"PSVC_ALTERNATE",			/* 19 */
	"PSVC_HOTPLUG_ENABLE_SWITCH",		/* 20 */
	"PSVC_PS",				/* 21 */
	"PSVC_FAN",				/* 22 */
	"PSVC_TS",				/* 23 */
	"PSVC_DISK",				/* 24 */
	"PSVC_LED",				/* 25 */
	"PSVC_FSP_LED",				/* 26 */
	"PSVC_KEYSWITCH",			/* 27 */
	"PSVC_PCI_CARD",			/* 28 */
	"PSVC_PHYSICAL_DEVICE",			/* 29 */
	"PSVC_DEV_TYPE_SENSOR",			/* 30 */
	"PSVC_FAN_TRAY_FANS",			/* 31 */
	"PSVC_FRU"				/* 32 */
};

#define	FEATURE_BITS (sizeof (feature_bits) / sizeof (struct bits))

static struct bitfield {
	int8_t shift;
	char   *label;
	char   *format;
} addr_fields[] =
{
{PSVC_VERSION_SHIFT, "VERSION=", "%d"},
{PSVC_ACTIVE_LOW_SHIFT, "ACTIVE_LOW=", "%d"},
{PSVC_BIT_NUM_SHIFT, "BIT_NUM=", "%d"},
{PSVC_INVERT_SHIFT, "INVERT=", "%d"},
{PSVC_PORT_SHIFT, "PORT=", "%d"},
{PSVC_BITSHIFT_SHIFT, "BITSHIFT=", "%d"},
{PSVC_BYTEMASK_SHIFT, "BYTEMASK=", "%x"},
{PSVC_REG_SHIFT, "REG=", "%d"},
{PSVC_TYPE_SHIFT, "TYPE=", "%d"},
{PSVC_BUSADDR_SHIFT, "BUSADDR=", "%x"},
{PSVC_BUSNUM_SHIFT, "BUSNUM=", "%d"},
{PSVC_CNTLR_SHIFT, "CNTLR=", "%d"},
};
#define	ADDR_BITFIELDS (sizeof (addr_fields) / sizeof (struct bitfield))

/*
 * record format is:
 * pathname label1=val1,label2=val2,label3=val3
 * Must be a space after the pathname and a comma between variables.
 */

static char *
find_label(char *str, char *label)
{
	char *start;

	start = strchr(str, ' ');
	if (start == NULL)
		return (start);

	do {
		++start;
		if (strncmp(start, label, strlen(label)) == 0)
			return (start);

		start = strchr(start, ',');
	} while (start != NULL);

	return (NULL);
}

static int32_t
i_psvc_value(char *buf, int32_t attr_id, void *attrp)
{
	char *val;
	uint32_t temp32;
	uint64_t temp64;
	uint64_t result;
	int32_t i;
	int32_t found;
	char label[64];
	int val_size;
	int label_size;


	switch (attr_id) {
	case PSVC_CLASS_ATTR:
	case PSVC_SUBCLASS_ATTR:
	case PSVC_INSTANCE_ATTR:
	case PSVC_LO_WARN_ATTR:
	case PSVC_LO_SHUT_ATTR:
	case PSVC_HI_WARN_ATTR:
	case PSVC_HI_SHUT_ATTR:
	case PSVC_HW_HI_SHUT_ATTR:
	case PSVC_HW_LO_SHUT_ATTR:
	case PSVC_OPTIMAL_TEMP_ATTR:
		snprintf(label, sizeof (label), "%s=", attr_str_tab[attr_id]);
		val = find_label(buf, label);
		if (val == NULL) {
			errno = EINVAL;
			return (PSVC_FAILURE);
		}
		found = sscanf(val + strlen(label),
			"%d", (int32_t *)attrp);
		if (found == 0)
			*(int32_t *)attrp = 0;
		break;
	case PSVC_SETPOINT_ATTR:
	case PSVC_HYSTERESIS_ATTR:
	case PSVC_LOOPGAIN_ATTR:
	case PSVC_LOOPBIAS_ATTR:
		snprintf(label, sizeof (label), "%s=", attr_str_tab[attr_id]);
		val = find_label(buf, label);
		if (val == NULL) {
			errno = EINVAL;
			return (PSVC_FAILURE);
		}

		found = sscanf(val + strlen(label), "%hd", (int16_t *)attrp);
		if (found == 0)
			*(int16_t *)attrp = 0;
		break;
	case PSVC_LED_COLOR_ATTR:
	case PSVC_LED_IS_LOCATOR_ATTR:
	case PSVC_LED_LOCATOR_NAME_ATTR:
		snprintf(label, sizeof (label), "%s=", attr_str_tab[attr_id]);
		val = find_label(buf, label);
		if (val == NULL) {
			errno = EINVAL;
			return (PSVC_FAILURE);
		}
		val_size = strlen(val);
		label_size = strlen(label);

		for (i = 0; i < val_size && val[i] != ','; i++);
		if (i < strlen(val) - 1) {
			strncpy((char *)attrp, val+label_size,
				i - label_size);
		} else
		found = sscanf(val + label_size, "%s", (char *)attrp);
		if (found == 0)
			strcpy((char *)attrp, "");
		break;
	case PSVC_FEATURES_ATTR:
		result = 0;
		for (i = 0; i < FEATURE_BITS; ++i) {
			val = find_label(buf, feature_bits[i].label);
			if (val == NULL)
				continue;
			found = sscanf(val + strlen(feature_bits[i].label),
				"%d", &temp32);
			if (found != 0) {
				if (temp32 == 1)
					result |= feature_bits[i].bit;
			}
		}
		*(uint64_t *)attrp = result;
		break;
	case PSVC_ADDR_SPEC_ATTR:
		result = 0;
		for (i = 0; i < ADDR_BITFIELDS; ++i) {
			val = find_label(buf, addr_fields[i].label);
			if (val == NULL)
				continue;
			found = sscanf(val + strlen(addr_fields[i].label),
				addr_fields[i].format, &temp32);
			if (found != 0) {
				temp64 = temp32;
				temp64 <<= addr_fields[i].shift;
				result |= temp64;
			}
		}
		*(uint64_t *)attrp = result;
		break;
	default:
		errno = EINVAL;
		return (PSVC_FAILURE);
	}
	return (PSVC_SUCCESS);
}

/* determine number of records in file section */
static int32_t
i_psvc_count_records(FILE *fp, char *end, uint32_t *countp)
{
	long first_record;
	char *ret;
	char buf[BUFSZ];
	uint32_t count = 0;

	first_record = ftell(fp);

	while ((ret = fgets(buf, BUFSZ, fp)) != NULL) {
		if (strncmp(end, buf, strlen(end)) == 0)
			break;
		++count;
	}

	if (ret == NULL) {
		errno = EINVAL;
		return (PSVC_FAILURE);
	}

	fseek(fp, first_record, SEEK_SET);
	*countp = count;
	return (PSVC_SUCCESS);
}

/* determine number of records in file section */
static int32_t
i_psvc_count_tables_associations(FILE *fp, uint32_t *countp, char *end)
{
	long first_record;
	char *ret;
	char buf[BUFSZ];
	uint32_t count = 0;

	first_record = ftell(fp);

	while ((ret = fgets(buf, BUFSZ, fp)) != NULL) {
		if (strncmp(end, buf, strlen(end)) == 0)
			++count;
	}
#ifdef	lint
	ret = ret;
#endif

	fseek(fp, first_record, SEEK_SET);
	*countp = count;
	return (PSVC_SUCCESS);
}

/* determine number of records in a table */
static int32_t
i_psvc_count_table_records(FILE *fp, char *end, uint32_t *countp)
{
	long first_record;
	int ret;
	char string[BUFSZ];
	uint32_t count = 0;

	first_record = ftell(fp);

	while ((ret = fscanf(fp, "%s", string)) == 1) {
		if (strncmp(end, string, strlen(end)) == 0)
			break;
		++count;
	}

	if (ret != 1) {
		errno = EINVAL;
		return (PSVC_FAILURE);
	}

	fseek(fp, first_record, SEEK_SET);
	*countp = count;
	return (PSVC_SUCCESS);
}

/*
 * Find number of matches to an antecedent_id of a certain
 * association type.
 */
static int32_t
i_psvc_get_assoc_matches(EHdl_t *hdlp, char *antecedent, int32_t assoc_id,
	int32_t *matches)
{
	int i;
	int32_t key;
	EAssocList_t *ap = hdlp->assoc_tbl + assoc_id;

	*matches = 0;

	if (ap->table == 0) {
		errno = EINVAL;
		return (PSVC_FAILURE);
	}

	key = psvc_get_str_key(antecedent);

	for (i = 0; i < ap->count; ++i) {
		if (ap->table[i].ant_key == key) {
			if (strcmp(ap->table[i].antecedent_id, antecedent)
			    == 0)
				++*matches;
		}
	}
	return (PSVC_SUCCESS);
}

/*
 * Find 1st m matches to an antecedent_id of a certain
 * association type.
 * Returns zero for success, -1 for failure.
 */
static int32_t
i_psvc_get_assoc_id(EHdl_t *hdlp, char *antecedent, int32_t assoc_id,
	int32_t match, char **id_list)
{
	int i;
	int found = 0;
	int32_t key;
	EAssocList_t *ap = &hdlp->assoc_tbl[assoc_id];

	if (ap->table == 0) {
		errno = EINVAL;
		return (-1);
	}

	key = psvc_get_str_key(antecedent);

	for (i = 0; i < ap->count; ++i) {
		if (ap->table[i].ant_key == key) {
			if (strcmp(ap->table[i].antecedent_id, antecedent)
			    == 0) {
				if (found == match) {
					*id_list = ap->table[i].dependent_id;
					return (0);
				}
				++found;
			}
		}
	}

	errno = EINVAL;
	return (-1);
}

static int32_t
i_psvc_get_table_value(EHdl_t *hdlp, char *table_id, uint32_t index,
	void *value)
{
	int32_t i;
	ETable_t *tblp;
	ETable_Array *tbl_arr;
	int32_t key, array;

	key = psvc_get_str_key(table_id);
	array = key % PSVC_MAX_TABLE_ARRAYS;
	tbl_arr = &(hdlp->tbl_arry[array]);

	for (i = 0; i < tbl_arr->obj_count; ++i) {
		if (key == tbl_arr->obj_tbl[i].key) {
			if (strcmp(tbl_arr->obj_tbl[i].name,
				table_id) == 0)
				break;
		}
	}

	if (tbl_arr->obj_tbl[i].type != PSVC_TBL)
		return (PSVC_FAILURE);

	tblp = (ETable_t *)tbl_arr->obj_tbl[i].objp;

	if (tblp->table == NULL)
		return (PSVC_FAILURE);

	if (index >= tblp->size)
		return (PSVC_FAILURE);

	switch (tblp->cell_type) {
		case 0:
			*(int8_t *)value = *((int8_t *)tblp->table + index);
			break;
		case 1:
			*(uint8_t *)value = *((uint8_t *)tblp->table + index);
			break;
		case 2:
			*(int16_t *)value = *((int16_t *)tblp->table + index);
			break;
		case 3:
			*(uint16_t *)value = *((uint16_t *)tblp->table + index);
			break;
		case 4:
			*(int32_t *)value = *((int32_t *)tblp->table + index);
			break;
		case 5:
			*(uint32_t *)value = *((uint32_t *)tblp->table + index);
			break;
		case 6:
			*(int64_t *)value = *((int64_t *)tblp->table + index);
			break;
		case 7:
			*(uint64_t *)value = *((uint64_t *)tblp->table + index);
			break;
		default:
			return (PSVC_FAILURE);
	}

	return (PSVC_SUCCESS);
}

int32_t
psvc_get_attr(EHdl_t *hdlp, char *name, int32_t attr_id, void *attr_valuep, ...)
{
	EObj_t *objp;
	int32_t status = PSVC_SUCCESS;
	int32_t arg1, arg2;
	va_list ap;

	pthread_mutex_lock(&hdlp->mutex);

	if (attr_valuep == NULL) {
		errno = EFAULT;
		pthread_mutex_unlock(&hdlp->mutex);
		return (PSVC_FAILURE);
	}

	switch (attr_id) {
	case PSVC_TABLE_VALUE_ATTR:
		va_start(ap, attr_valuep);
		status = i_psvc_get_table_value(hdlp, name,
			va_arg(ap, uint32_t), attr_valuep);
		va_end(ap);
		break;
	case PSVC_ASSOC_MATCHES_ATTR:
		va_start(ap, attr_valuep);
		status = i_psvc_get_assoc_matches(hdlp, name,
			va_arg(ap, int32_t), attr_valuep);
		va_end(ap);
		break;
	case PSVC_ASSOC_ID_ATTR:
		va_start(ap, attr_valuep);
		arg1 = va_arg(ap, int32_t);
		arg2 = va_arg(ap, int32_t);
		status = i_psvc_get_assoc_id(hdlp, name,
		    arg1, arg2, attr_valuep);
		va_end(ap);
		break;
	default:
		status = i_psvc_get_obj(hdlp, name, &objp);
		if (status != PSVC_SUCCESS) {
			pthread_mutex_unlock(&hdlp->mutex);
			return (status);
		}
		status = (*objp->get_attr)(hdlp, objp, attr_id,
			attr_valuep);
	}

	if (status != PSVC_SUCCESS) {
		pthread_mutex_unlock(&hdlp->mutex);
		return (status);
	}

	pthread_mutex_unlock(&hdlp->mutex);
	return (status);
}

int32_t
psvc_set_attr(EHdl_t *hdlp, char *name, int32_t attr_id, void *attr_valuep)
{
	EObj_t *objp;
	int32_t status = PSVC_SUCCESS;

	pthread_mutex_lock(&hdlp->mutex);
	status = i_psvc_get_obj(hdlp, name, &objp);
	if (status != PSVC_SUCCESS) {
		pthread_mutex_unlock(&hdlp->mutex);
		return (status);
	}

	if (attr_valuep == NULL) {
		errno = EFAULT;
		pthread_mutex_unlock(&hdlp->mutex);
		return (PSVC_FAILURE);
	}

	status = (*objp->set_attr)(hdlp, objp, attr_id, attr_valuep);
	if (status != PSVC_SUCCESS) {
		pthread_mutex_unlock(&hdlp->mutex);
		return (status);
	}

	pthread_mutex_unlock(&hdlp->mutex);
	return (status);
}


static int32_t
i_psvc_get_presence(EHdl_t *hdlp, EObj_t *objp, boolean_t *pr)
{
	EObj_t *pobjp, *mobjp;
	int32_t matches;
	char *mid;
	char *parent_id;
	int32_t status = PSVC_SUCCESS;
	uint8_t value_8bit, value_8bit_inv;
	boolean_t active_low, value;

	if (strcmp(objp->label, PSVC_CHASSIS) == 0) {
		*pr = PSVC_PRESENT;
		objp->present = PSVC_PRESENT;
		return (PSVC_SUCCESS);
	}

	status = i_psvc_get_assoc_id(hdlp, objp->label, PSVC_PARENT, 0,
		&parent_id);
	if (status != PSVC_SUCCESS)
		return (status);

	if (strcmp(parent_id, PSVC_CHASSIS)) {
		status = i_psvc_get_obj(hdlp, parent_id, &pobjp);
		if (status != PSVC_SUCCESS)
			return (status);
		if (!pobjp->present) {
			pobjp->get_attr(hdlp, pobjp, PSVC_PRESENCE_ATTR, pr);
			*pr = pobjp->present;
			objp->present = pobjp->present;
			return (status);
		}
	}

	(void) i_psvc_get_assoc_matches(hdlp, objp->label,
		PSVC_PRESENCE_SENSOR, &matches);

	if (matches != 0) {
		status = i_psvc_get_assoc_id(hdlp, objp->label,
		    PSVC_PRESENCE_SENSOR, 0, &mid);
		if (status != PSVC_SUCCESS)
			return (status);
		status = i_psvc_get_obj(hdlp, mid, &mobjp);
		if (status != PSVC_SUCCESS)
			return (status);

		active_low = PSVC_IS_ACTIVE_LOW(mobjp->addr_spec);

		if (mobjp->class == PSVC_BOOLEAN_GPIO_CLASS) {
			status = mobjp->get_attr(hdlp, mobjp,
				PSVC_GPIO_VALUE_ATTR, &value);
			if (status != PSVC_SUCCESS)
				return (status);
			if (active_low)
				if (value == 0)
					*pr = PSVC_PRESENT;
				else
					*pr = PSVC_ABSENT;
			else
				if (value == 0)
					*pr = PSVC_ABSENT;
				else
					*pr = PSVC_PRESENT;
		} else if (mobjp->class == PSVC_8BIT_GPIO_CLASS) {
			uint8_t bitshift, bytemask;

			status = mobjp->get_attr(hdlp, mobjp,
				PSVC_GPIO_VALUE_ATTR, &value_8bit);
			if (status != PSVC_SUCCESS)
				return (status);
			if (PSVC_HP_INVERT(mobjp->addr_spec))
				value_8bit_inv = ~value_8bit;
			else
				value_8bit_inv = value_8bit;
			bitshift = PSVC_GET_ASPEC_BITSHIFT(mobjp->addr_spec);
			bytemask = PSVC_GET_ASPEC_BYTEMASK(mobjp->addr_spec);
			value_8bit_inv =
				value_8bit_inv & (bytemask >> bitshift);
			if (active_low)
				if (value_8bit_inv == 0)
					*pr = PSVC_PRESENT;
				else
					*pr = PSVC_ABSENT;
			else
				if (value_8bit_inv == 0)
					*pr = PSVC_ABSENT;
				else
					*pr = PSVC_PRESENT;
		} else {
			errno = EINVAL;
			return (PSVC_FAILURE);
		}
	} else {
		*pr = PSVC_PRESENT;
	}

	objp->present = *pr;

	return (status);
}

static int32_t
i_psvc_get_device_value_0_0(EHdl_t *hdlp, EObj_t *objp, int32_t *temp)
{
	int32_t status = PSVC_SUCCESS, m;
	char *tid;
	int16_t temp16;
	char *physid;
	EObj_t *physobjp;

	if (objp->present != PSVC_PRESENT) {
		errno = ENODEV;
		return (PSVC_FAILURE);
	}

	status = i_psvc_get_assoc_id(
		hdlp, objp->label, PSVC_PHYSICAL_DEVICE, 0, &physid);
	if (status != PSVC_SUCCESS) {
		return (status);
	}
	status = i_psvc_get_obj(hdlp, physid, &physobjp);
	if (status != PSVC_SUCCESS) {
		return (status);
	}

	status = ((EPhysDev_t *)physobjp)->get_temperature(hdlp,
		objp->addr_spec, temp);
	if (status != PSVC_SUCCESS) {
		return (status);
	}

	if (objp->features & PSVC_CONVERSION_TABLE) {
		status = i_psvc_get_assoc_matches(hdlp, objp->label,
		    PSVC_TABLE, &m);
		if ((status != PSVC_SUCCESS) || (m != 1)) {
			return (status);
		}

		(void) i_psvc_get_assoc_id(hdlp, objp->label, PSVC_TABLE, 0,
			&tid);

		status = i_psvc_get_table_value(hdlp, tid, *temp, &temp16);
		*temp = temp16;
	}
	return (status);
}

static int32_t
i_psvc_get_device_value_0_1(EHdl_t *hdlp, EObj_t *objp, int32_t *temp)
{
	int32_t status = PSVC_SUCCESS, m;
	char *tid;
	int16_t temp16;
	char *physid;
	EObj_t *physobjp;

	if (objp->present != PSVC_PRESENT) {
		errno = ENODEV;
		return (PSVC_FAILURE);
	}

	status = i_psvc_get_assoc_id(
		hdlp, objp->label, PSVC_PHYSICAL_DEVICE, 0, &physid);
	if (status != PSVC_SUCCESS) {
		return (status);
	}
	status = i_psvc_get_obj(hdlp, physid, &physobjp);
	if (status != PSVC_SUCCESS) {
		return (status);
	}

	status = ((EPhysDev_t *)physobjp)->get_temperature(hdlp,
		objp->addr_spec, temp);
	if (status != PSVC_SUCCESS) {
		return (status);
	}

	if (objp->features & PSVC_CONVERSION_TABLE) {
		status = i_psvc_get_assoc_matches(hdlp, objp->label,
		    PSVC_TABLE, &m);
		if ((status != PSVC_SUCCESS) || (m != 1)) {
			return (status);
		}

		(void) i_psvc_get_assoc_id(hdlp, objp->label, PSVC_TABLE, 0,
			&tid);

		status = i_psvc_get_table_value(hdlp, tid, *temp, &temp16);
		*temp = temp16;
	}
	return (status);
}

static int32_t
i_psvc_get_device_value_4_0(EHdl_t *hdlp, EObj_t *objp, int32_t *value)
{
	int32_t status = PSVC_SUCCESS;
	char *physid;
	EObj_t *physobjp;

	if (objp->present != PSVC_PRESENT) {
		errno = ENODEV;
		return (PSVC_FAILURE);
	}

	status = i_psvc_get_assoc_id(hdlp, objp->label, PSVC_PHYSICAL_DEVICE,
		0, &physid);
	if (status != PSVC_SUCCESS)
		return (status);
	status = i_psvc_get_obj(hdlp, physid, &physobjp);
	if (status != PSVC_SUCCESS)
		return (status);

	status = ((EPhysDev_t *)physobjp)->get_input(hdlp, objp->addr_spec,
		value);
	if (status != PSVC_SUCCESS)
		return (status);

	if (objp->features & PSVC_CONVERSION_TABLE) {
		int32_t m;
		char *tid;
		int16_t temp16;

		status = i_psvc_get_assoc_matches(hdlp, objp->label,
		    PSVC_TABLE, &m);
		if ((status != PSVC_SUCCESS) || (m != 1)) {
			return (status);
		}

		(void) i_psvc_get_assoc_id(hdlp, objp->label, PSVC_TABLE, 0,
			&tid);

		status = i_psvc_get_table_value(hdlp, tid, *value, &temp16);
		*value = temp16;
	}

	return (status);
}

static int32_t
i_psvc_set_device_value_5_0(EHdl_t *hdlp, EObj_t *objp, int32_t *value)
{
	int32_t status = PSVC_SUCCESS;
	char *physid;
	EObj_t *physobjp;

	if (objp->present != PSVC_PRESENT) {
		errno = ENODEV;
		return (PSVC_FAILURE);
	}

	status = i_psvc_get_assoc_id(hdlp, objp->label, PSVC_PHYSICAL_DEVICE,
		0, &physid);
	if (status != PSVC_SUCCESS)
		return (status);
	status = i_psvc_get_obj(hdlp, physid, &physobjp);
	if (status != PSVC_SUCCESS)
		return (status);
	status = ((EPhysDev_t *)physobjp)->set_output(hdlp, objp->addr_spec,
		*value);
	if (status != PSVC_SUCCESS)
		return (status);

	return (status);
}

static int32_t
i_psvc_get_device_value_5_0(EHdl_t *hdlp, EObj_t *objp, int32_t *value)
{
	int32_t status = PSVC_SUCCESS;
	char *physid;
	EObj_t *physobjp;

	if (objp->present != PSVC_PRESENT) {
		errno = ENODEV;
		return (PSVC_FAILURE);
	}

	status = i_psvc_get_assoc_id(hdlp, objp->label, PSVC_PHYSICAL_DEVICE,
		0, &physid);
	if (status != PSVC_SUCCESS)
		return (status);
	status = i_psvc_get_obj(hdlp, physid, &physobjp);
	if (status != PSVC_SUCCESS)
		return (status);

	status = ((EPhysDev_t *)physobjp)->get_output(hdlp, objp->addr_spec,
		value);
	if (status != PSVC_SUCCESS)
		return (status);

	if (objp->features & PSVC_CONVERSION_TABLE) {
		int32_t m;
		char *tid;
		int16_t temp16;

		status = i_psvc_get_assoc_matches(hdlp, objp->label,
		    PSVC_TABLE, &m);
		if ((status != PSVC_SUCCESS) || (m != 1)) {
			return (status);
		}

		(void) i_psvc_get_assoc_id(hdlp, objp->label, PSVC_TABLE, 0,
			&tid);

		status = i_psvc_get_table_value(hdlp, tid, *value, &temp16);
		*value = temp16;
	}
	return (status);
}

static int32_t
i_psvc_get_device_value_6_0(EHdl_t *hdlp, EObj_t *objp, boolean_t *value)
{
	int32_t status = PSVC_SUCCESS;
	int32_t bit_value;
	char *physid;
	EObj_t *physobjp;

	if (objp->present != PSVC_PRESENT) {
		errno = ENODEV;
		return (PSVC_FAILURE);
	}

	status = i_psvc_get_assoc_id(hdlp, objp->label, PSVC_PHYSICAL_DEVICE,
		0, &physid);
	if (status != PSVC_SUCCESS)
		return (status);
	status = i_psvc_get_obj(hdlp, physid, &physobjp);
	if (status != PSVC_SUCCESS)
		return (status);

	status = ((EPhysDev_t *)physobjp)->get_bit(hdlp, objp->addr_spec,
		&bit_value);
	if (status != PSVC_SUCCESS)
		return (status);

	*value = bit_value;

	return (status);
}

static int32_t
i_psvc_set_device_value_6_0(EHdl_t *hdlp, EObj_t *objp, boolean_t *value)
{
	int32_t status = PSVC_SUCCESS;
	int32_t bit_value;
	char *physid;
	EObj_t *physobjp;

	if (objp->present != PSVC_PRESENT) {
		errno = ENODEV;
		return (PSVC_FAILURE);
	}

	bit_value = *value;
	status = i_psvc_get_assoc_id(hdlp, objp->label, PSVC_PHYSICAL_DEVICE,
		0, &physid);
	if (status != PSVC_SUCCESS)
		return (status);
	status = i_psvc_get_obj(hdlp, physid, &physobjp);
	if (status != PSVC_SUCCESS)
		return (status);

	status = ((EPhysDev_t *)physobjp)->set_bit(hdlp, objp->addr_spec,
		bit_value);
	if (status != PSVC_SUCCESS)
		return (status);

	return (status);
}

static int32_t
i_psvc_get_device_value_1_0(EHdl_t *hdlp, EObj_t *objp, int32_t *fan_speed)
{
	int32_t status = PSVC_SUCCESS;
	EObj_t *ftobjp;
	char *fan_tach;

	if (objp->present != PSVC_PRESENT) {
		errno = ENODEV;
		return (PSVC_FAILURE);
	}

	status = i_psvc_get_assoc_id(hdlp, objp->label,
		PSVC_FAN_SPEED_TACHOMETER, 0, &fan_tach);
	if (status != PSVC_SUCCESS)
		return (status);

	status = i_psvc_get_obj(hdlp, fan_tach, &ftobjp);
	if (status != PSVC_SUCCESS)
		return (status);

	status = ftobjp->get_attr(hdlp, ftobjp, PSVC_SENSOR_VALUE_ATTR,
		fan_speed);
	if (status != PSVC_SUCCESS)
		return (status);

	return (status);
}

static int32_t
i_psvc_get_device_value_7_0(EHdl_t *hdlp, EObj_t *objp, int32_t *fan_speed)
{
	char *physid;
	EObj_t *physobjp;
	int32_t status = PSVC_SUCCESS;

	if (objp->present != PSVC_PRESENT) {
		errno = ENODEV;
		return (PSVC_FAILURE);
	}

	status = i_psvc_get_assoc_id(hdlp, objp->label, PSVC_PHYSICAL_DEVICE,
		0, &physid);
	if (status != PSVC_SUCCESS)
		return (status);
	status = i_psvc_get_obj(hdlp, physid, &physobjp);
	if (status != PSVC_SUCCESS)
		return (status);

	status = ((EPhysDev_t *)physobjp)->get_fanspeed(hdlp, objp->addr_spec,
		fan_speed);
	if (status != PSVC_SUCCESS)
		return (status);

	if (objp->features & PSVC_CONVERSION_TABLE) {
		int32_t m;
		char *tid;
		int16_t temp16;

		status = i_psvc_get_assoc_matches(hdlp, objp->label,
		    PSVC_TABLE, &m);
		if ((status != PSVC_SUCCESS) || (m != 1)) {
			return (status);
		}

		(void) i_psvc_get_assoc_id(hdlp, objp->label, PSVC_TABLE, 0,
			&tid);

		status = i_psvc_get_table_value(hdlp, tid, *fan_speed, &temp16);
		*fan_speed = temp16;
	}
	return (status);
}

static int32_t
i_psvc_get_device_state_2_0(EHdl_t *hdlp, EObj_t *objp, char *led_state)
{
	int32_t status = PSVC_SUCCESS;
	int32_t bit_value;
	boolean_t active_low;
	char *physid;
	EObj_t *physobjp;

	if (objp->present != PSVC_PRESENT) {
		errno = ENODEV;
		return (PSVC_FAILURE);
	}

	status = i_psvc_get_assoc_id(hdlp, objp->label, PSVC_PHYSICAL_DEVICE,
		0, &physid);
	if (status != PSVC_SUCCESS)
		return (status);
	status = i_psvc_get_obj(hdlp, physid, &physobjp);
	if (status != PSVC_SUCCESS)
		return (status);

	status = ((EPhysDev_t *)physobjp)->get_bit(hdlp, objp->addr_spec,
		&bit_value);
	if (status != PSVC_SUCCESS)
		return (status);

	active_low = PSVC_IS_ACTIVE_LOW(objp->addr_spec);
	if (active_low)
		if (bit_value == 0)
			strcpy(led_state, PSVC_LED_ON);
		else
			strcpy(led_state, PSVC_LED_OFF);
	else
		if (bit_value == 0)
			strcpy(led_state, PSVC_LED_OFF);
		else
			strcpy(led_state, PSVC_LED_ON);

	return (status);
}

static int32_t
i_psvc_set_device_state_2_0(EHdl_t *hdlp, EObj_t *objp, char *led_state)
{
	int32_t status = PSVC_SUCCESS;
	boolean_t active_low;
	int32_t bit_value;
	char *physid;
	EObj_t *physobjp;

	if (objp->present != PSVC_PRESENT) {
		errno = ENODEV;
		return (PSVC_FAILURE);
	}

	if (strcmp(((ELed_t *)objp)->is_locator, PSVC_LOCATOR_TRUE) != 0) {
		/*
		 * For Locator LEDs we ignore lit_count.  RSC may have
		 * altered the LED state underneath us, So we should
		 * always just do what the user asked instead of trying
		 * to be smart.
		 */

		if (strcmp(led_state, PSVC_LED_ON) == 0)
			((ELed_t *)objp)->lit_count++;
		else if (strcmp(led_state, PSVC_LED_OFF) == 0) {
			if (--((ELed_t *)objp)->lit_count > 0) {
				return (PSVC_SUCCESS);
			} else if (((ELed_t *)objp)->lit_count < 0)
				((ELed_t *)objp)->lit_count = 0;
			/* Fall through case is when lit_count is 0 */
		}
	}

	strcpy(objp->previous_state, objp->state);
	strcpy(objp->state, led_state);

	bit_value = (strcmp(led_state, PSVC_LED_ON) == 0);

	/*
	 * Flip the bit if necessary (for active_low devices,
	 * O ==> ON; 1 ==> OFF.
	 */
	active_low = PSVC_IS_ACTIVE_LOW(objp->addr_spec);
	bit_value ^= active_low;

	status = i_psvc_get_assoc_id(hdlp, objp->label, PSVC_PHYSICAL_DEVICE,
		0, &physid);
	if (status != PSVC_SUCCESS)
		return (status);
	status = i_psvc_get_obj(hdlp, physid, &physobjp);
	if (status != PSVC_SUCCESS)
		return (status);

	status = ((EPhysDev_t *)physobjp)->set_bit(hdlp, objp->addr_spec,
		bit_value);
	return (status);
}

static int32_t
i_psvc_get_device_state_2_1(EHdl_t *hdlp, EObj_t *objp, char *led_state)
{
	int32_t status = PSVC_SUCCESS;
	uint8_t value;
	char *physid;
	EObj_t *physobjp;

	if (objp->present != PSVC_PRESENT) {
		errno = ENODEV;
		return (PSVC_FAILURE);
	}

	status = i_psvc_get_assoc_id(hdlp, objp->label, PSVC_PHYSICAL_DEVICE,
		0, &physid);
	if (status != PSVC_SUCCESS)
		return (status);
	status = i_psvc_get_obj(hdlp, physid, &physobjp);
	if (status != PSVC_SUCCESS)
		return (status);

	status = ((EPhysDev_t *)physobjp)->get_reg(hdlp, objp->addr_spec,
		&value);
	if (status != PSVC_SUCCESS)
		return (status);

	switch (value) {
	case 0:
		strcpy(led_state, PSVC_LED_OFF);
		break;
	case 1:
		strcpy(led_state, PSVC_LED_SLOW_BLINK);
		break;
	case 2:
		strcpy(led_state, PSVC_LED_FAST_BLINK);
		break;
	case 3:
		strcpy(led_state, PSVC_LED_ON);
		break;
	}

	return (status);
}

static int32_t
i_psvc_set_device_state_2_1(EHdl_t *hdlp, EObj_t *objp, char *led_state)
{
	int32_t status = PSVC_SUCCESS;
	uint8_t value;
	char *physid;
	EObj_t *physobjp;

	if (objp->present != PSVC_PRESENT) {
		errno = ENODEV;
		return (PSVC_FAILURE);
	}

	if (strcmp(led_state, PSVC_LED_ON) == 0)
		((ELed_t *)objp)->lit_count++;
	else if (strcmp(led_state, PSVC_LED_OFF) == 0) {
		if (--((ELed_t *)objp)->lit_count > 0) {
			return (PSVC_SUCCESS);
		} else if (((ELed_t *)objp)->lit_count < 0)
			((ELed_t *)objp)->lit_count = 0;

		/* Fall through case is when lit_count is 0 */
	}

	strcpy(objp->previous_state, objp->state);
	strcpy(objp->state, led_state);

	if (strcmp(led_state, PSVC_LED_OFF) == 0)
		value = 0;
	else if (strcmp(led_state, PSVC_LED_SLOW_BLINK) == 0)
		value = 1;
	else if (strcmp(led_state, PSVC_LED_FAST_BLINK) == 0)
		value = 2;
	else if (strcmp(led_state, PSVC_LED_ON) == 0)
		value = 3;

	status = i_psvc_get_assoc_id(hdlp, objp->label, PSVC_PHYSICAL_DEVICE,
		0, &physid);
	if (status != PSVC_SUCCESS)
		return (status);
	status = i_psvc_get_obj(hdlp, physid, &physobjp);
	if (status != PSVC_SUCCESS)
		return (status);

	status = ((EPhysDev_t *)physobjp)->set_reg(hdlp, objp->addr_spec,
		value);

	return (status);
}

static int32_t
i_psvc_get_device_state_9_0(EHdl_t *hdlp, EObj_t *objp, char *pos)
{
	int32_t status = PSVC_SUCCESS, matches;
	char *sensorid;
	EObj_t *sensorp;
	char state[32];

	if (objp->present != PSVC_PRESENT) {
		errno = ENODEV;
		return (PSVC_FAILURE);
	}

	if (objp->features & PSVC_NORMAL_POS_AV) {
		(void) i_psvc_get_assoc_matches(hdlp, objp->label,
		    PSVC_KS_NORMAL_POS_SENSOR, &matches);
		if (matches == 1) {
			status = i_psvc_get_assoc_id(hdlp, objp->label,
				PSVC_KS_NORMAL_POS_SENSOR, 0, &sensorid);
			if (status != PSVC_SUCCESS)
				return (status);

			status = i_psvc_get_obj(hdlp, sensorid, &sensorp);
			if (status != PSVC_SUCCESS)
				return (status);

			status = sensorp->get_attr(hdlp, sensorp,
				PSVC_SWITCH_STATE_ATTR, state);
			if (status != PSVC_SUCCESS)
				return (status);

			if (strcmp(state, PSVC_SWITCH_ON) == 0) {
				strcpy(pos, PSVC_NORMAL_POS);
				return (PSVC_SUCCESS);
			}
		}
	}

	if (objp->features & PSVC_DIAG_POS_AV) {
		(void) i_psvc_get_assoc_matches(hdlp, objp->label,
		    PSVC_KS_DIAG_POS_SENSOR, &matches);
		if (matches == 1) {
			status = i_psvc_get_assoc_id(hdlp, objp->label,
			    PSVC_KS_DIAG_POS_SENSOR, 0, &sensorid);
			if (status != PSVC_SUCCESS)
				return (status);

			status = i_psvc_get_obj(hdlp, sensorid, &sensorp);
			if (status != PSVC_SUCCESS)
				return (status);

			status = sensorp->get_attr(hdlp, sensorp,
				PSVC_SWITCH_STATE_ATTR, state);
			if (status != PSVC_SUCCESS)
				return (status);

			if (strcmp(state, PSVC_SWITCH_ON) == 0) {
				strcpy(pos, PSVC_DIAG_POS);
				return (PSVC_SUCCESS);
			}
		}
	}

	if (objp->features & PSVC_LOCK_POS_AV) {
		(void) i_psvc_get_assoc_matches(hdlp, objp->label,
		    PSVC_KS_LOCK_POS_SENSOR, &matches);
		if (matches == 1) {
			status = i_psvc_get_assoc_id(hdlp, objp->label,
			    PSVC_KS_LOCK_POS_SENSOR, 0, &sensorid);
			if (status != PSVC_SUCCESS)
				return (status);

			status = i_psvc_get_obj(hdlp, sensorid, &sensorp);
			if (status != PSVC_SUCCESS)
				return (status);

			status = sensorp->get_attr(hdlp, sensorp,
				PSVC_SWITCH_STATE_ATTR, state);
			if (status != PSVC_SUCCESS)
				return (status);

			if (strcmp(state, PSVC_SWITCH_ON) == 0) {
				strcpy(pos, PSVC_LOCKED_POS);
				return (PSVC_SUCCESS);
			}
		}
	}

	if (objp->features & PSVC_OFF_POS_AV) {
		(void) i_psvc_get_assoc_matches(hdlp, objp->label,
		    PSVC_KS_OFF_POS_SENSOR, &matches);
		if (matches == 1) {
			status = i_psvc_get_assoc_id(hdlp, objp->label,
			    PSVC_KS_OFF_POS_SENSOR, 0, &sensorid);
			if (status != PSVC_SUCCESS)
				return (status);

			status = i_psvc_get_obj(hdlp, sensorid, &sensorp);
			if (status != PSVC_SUCCESS)
				return (status);

			status = sensorp->get_attr(hdlp, sensorp,
				PSVC_SWITCH_STATE_ATTR, state);
			if (status != PSVC_SUCCESS)
				return (status);

			if (strcmp(state, PSVC_SWITCH_ON) == 0) {
				strcpy(pos, PSVC_OFF_POS);
				return (PSVC_SUCCESS);
			}
		}
	}
	/* If we have fallen through till here, something's wrong */
	errno = EINVAL;
	return (PSVC_FAILURE);
}


static int32_t
i_psvc_get_device_value_10_0(EHdl_t *hdlp, EObj_t *objp, uint8_t *value)
{
	int32_t status = PSVC_SUCCESS;
	char *physid;
	EObj_t *physobjp;

	if (objp->present != PSVC_PRESENT) {
		errno = ENODEV;
		return (PSVC_FAILURE);
	}

	status = i_psvc_get_assoc_id(hdlp, objp->label, PSVC_PHYSICAL_DEVICE,
		0, &physid);
	if (status != PSVC_SUCCESS)
		return (status);
	status = i_psvc_get_obj(hdlp, physid, &physobjp);
	if (status != PSVC_SUCCESS)
		return (status);

	status = ((EPhysDev_t *)physobjp)->get_reg(hdlp, objp->addr_spec,
		value);
	if (status != PSVC_SUCCESS)
		return (status);

	if (objp->features & PSVC_CONVERSION_TABLE) {
		int32_t m;
		char *tid;
		uint8_t temp8;

		status = i_psvc_get_assoc_matches(hdlp, objp->label,
		    PSVC_TABLE, &m);
		if ((status != PSVC_SUCCESS) || (m != 1)) {
			return (status);
		}

		(void) i_psvc_get_assoc_id(hdlp, objp->label,
			PSVC_TABLE, 0, &tid);

		status = i_psvc_get_table_value(hdlp, tid, *value, &temp8);
		*value = temp8;
	}
	return (status);
}

static int32_t
i_psvc_get_device_value_10_1(EHdl_t *hdlp, EObj_t *objp, uint8_t *value)
{
	int32_t status = PSVC_SUCCESS;
	char *physid;
	EObj_t *physobjp;

	if (objp->present != PSVC_PRESENT) {
		errno = ENODEV;
		return (PSVC_FAILURE);
	}

	status = i_psvc_get_assoc_id(hdlp, objp->label, PSVC_PHYSICAL_DEVICE,
		0, &physid);
	if (status != PSVC_SUCCESS)
		return (status);
	status = i_psvc_get_obj(hdlp, physid, &physobjp);
	if (status != PSVC_SUCCESS)
		return (status);

	status = ((EPhysDev_t *)physobjp)->get_port(hdlp, objp->addr_spec,
		value);
	if (status != PSVC_SUCCESS)
		return (status);

	return (status);
}

static int32_t
i_psvc_set_device_value_10_0(EHdl_t *hdlp, EObj_t *objp, uint8_t *value)
{
	int32_t status = PSVC_SUCCESS;
	char *physid;
	EObj_t *physobjp;

	if (objp->present != PSVC_PRESENT) {
		errno = ENODEV;
		return (PSVC_FAILURE);
	}

	status = i_psvc_get_assoc_id(hdlp, objp->label, PSVC_PHYSICAL_DEVICE,
		0, &physid);
	if (status != PSVC_SUCCESS)
		return (status);
	status = i_psvc_get_obj(hdlp, physid, &physobjp);
	if (status != PSVC_SUCCESS)
		return (status);

	status = ((EPhysDev_t *)physobjp)->set_reg(hdlp, objp->addr_spec,
		*value);
	return (status);
}

static int32_t
i_psvc_set_device_value_10_1(EHdl_t *hdlp, EObj_t *objp, uint8_t *value)
{
	int32_t status = PSVC_SUCCESS;
	char *physid;
	EObj_t *physobjp;

	if (objp->present != PSVC_PRESENT) {
		errno = ENODEV;
		return (PSVC_FAILURE);
	}

	status = i_psvc_get_assoc_id(hdlp, objp->label, PSVC_PHYSICAL_DEVICE,
		0, &physid);
	if (status != PSVC_SUCCESS)
		return (status);
	status = i_psvc_get_obj(hdlp, physid, &physobjp);
	if (status != PSVC_SUCCESS)
		return (status);

	status = ((EPhysDev_t *)physobjp)->set_port(hdlp, objp->addr_spec,
		*value);
	return (status);
}

static int32_t
i_psvc_get_device_state_8_0(EHdl_t *hdlp, EObj_t *objp, char *sw_state)
{
	int32_t status = PSVC_SUCCESS;
	boolean_t active_low;
	int32_t bit_value;
	char *physid;
	EObj_t *physobjp;

	if (objp->present != PSVC_PRESENT) {
		errno = ENODEV;
		return (PSVC_FAILURE);
	}

	status = i_psvc_get_assoc_id(hdlp, objp->label, PSVC_PHYSICAL_DEVICE,
		0, &physid);
	if (status != PSVC_SUCCESS)
		return (status);
	status = i_psvc_get_obj(hdlp, physid, &physobjp);
	if (status != PSVC_SUCCESS)
		return (status);

	status = ((EPhysDev_t *)physobjp)->get_bit(hdlp, objp->addr_spec,
		&bit_value);
	if (status != PSVC_SUCCESS)
		return (status);

	active_low = PSVC_IS_ACTIVE_LOW(objp->addr_spec);
	if (active_low)
		if (bit_value == 0)
			strcpy(sw_state, PSVC_SWITCH_ON);
		else
			strcpy(sw_state, PSVC_SWITCH_OFF);
	else
		if (bit_value == 0)
			strcpy(sw_state, PSVC_SWITCH_OFF);
		else
			strcpy(sw_state, PSVC_SWITCH_ON);

	return (status);
}

static int32_t
i_psvc_set_device_state_8_0(EHdl_t *hdlp, EObj_t *objp, char *sw_state)
{
	int32_t status = PSVC_SUCCESS;
	boolean_t active_low;
	int32_t bit_value;
	char *physid;
	EObj_t *physobjp;

	if (objp->present != PSVC_PRESENT) {
		errno = ENODEV;
		return (PSVC_FAILURE);
	}

	strcpy(objp->previous_state, objp->state);
	strcpy(objp->state, sw_state);

	active_low = PSVC_IS_ACTIVE_LOW(objp->addr_spec);

	if (active_low)
		if (strcmp(sw_state, PSVC_SWITCH_ON) == 0)
			bit_value = 0;
		else
			bit_value = 1;
	else
		if (strcmp(sw_state, PSVC_SWITCH_ON) == 0)
			bit_value = 1;
		else
			bit_value = 0;

	status = i_psvc_get_assoc_id(hdlp, objp->label, PSVC_PHYSICAL_DEVICE,
		0, &physid);
	if (status != PSVC_SUCCESS)
		return (status);
	status = i_psvc_get_obj(hdlp, physid, &physobjp);
	if (status != PSVC_SUCCESS)
		return (status);

	status = ((EPhysDev_t *)physobjp)->set_bit(hdlp, objp->addr_spec,
		bit_value);
	return (status);
}

/* LM75 */
static int32_t
i_psvc_get_temperature_11_2(EHdl_t *hdlp, uint64_t aspec, int32_t *temp)
{
	int32_t status = PSVC_SUCCESS;
	char path[1024];
	int32_t fp;
	int16_t temp16;

	status = i_psvc_get_devpath(hdlp, aspec, path);
	if (status != PSVC_SUCCESS)
		return (status);

	fp = open(path, O_RDWR);
	if (fp == -1)
		return (PSVC_FAILURE);

	status = ioctl_retry(fp, I2C_GET_TEMPERATURE, (void *)&temp16);
	if (status == -1) {
		close(fp);
		errno = EIO;
		return (PSVC_FAILURE);
	}
	*temp = temp16;

	close(fp);

	return (status);
}

/* MAX1617 */
static int32_t
i_psvc_get_temperature_11_4(EHdl_t *hdlp, uint64_t aspec, int32_t *temp)
{
	int32_t status = PSVC_SUCCESS;
	char path[1024];
	int32_t fp;
	int16_t temp16;

	status = i_psvc_get_devpath(hdlp, aspec, path);
	if (status != PSVC_SUCCESS)
		return (status);

	fp = open(path, O_RDWR);
	if (fp == -1)
		return (PSVC_FAILURE);

	status = ioctl_retry(fp, I2C_GET_TEMPERATURE, (void *)&temp16);
	if (status == -1) {
		close(fp);
		errno = EIO;
		return (PSVC_FAILURE);
	}
	*temp = temp16;

	close(fp);

	return (status);
}

/* PCF8591 */
static int32_t
i_psvc_get_temperature_11_6(EHdl_t *hdlp, uint64_t aspec, int32_t *temp)
{
	int32_t status = PSVC_SUCCESS;
	char path[1024];
	int32_t fp;

	status = i_psvc_get_devpath(hdlp, aspec, path);
	if (status != PSVC_SUCCESS)
		return (status);

	fp = open(path, O_RDWR);
	if (fp == -1)
		return (PSVC_FAILURE);

	status = ioctl_retry(fp, I2C_GET_INPUT, (void *)temp);
	if (status == -1) {
		close(fp);
		errno = EIO;
		return (-1);
	}

	close(fp);

	return (status);
}

/* SSC050 */
static int32_t
i_psvc_get_fanspeed_11_7(EHdl_t *hdlp, uint64_t aspec, int32_t *fan_speed)
{
	int32_t ret, status = PSVC_SUCCESS;
	char path[1024];
	int32_t fp;

	status = i_psvc_get_devpath(hdlp, aspec, path);
	if (status != PSVC_SUCCESS)
		return (status);

	fp = open(path, O_RDWR);
	if (fp == -1)
		return (PSVC_FAILURE);

	ret = ioctl_retry(fp, I2C_GET_FAN_SPEED, (void *)fan_speed);
	if (ret == -1) {
		close(fp);
		errno = EIO;
		return (-1);
	}

	close(fp);

	return (status);
}

/* PCF8591 */
static int32_t
i_psvc_get_input_11_6(EHdl_t *hdlp, uint64_t aspec, int32_t *value)
{
	int32_t ret, status = PSVC_SUCCESS;
	char path[1024];
	int32_t fp;

	status = i_psvc_get_devpath(hdlp, aspec, path);
	if (status != PSVC_SUCCESS)
		return (status);

	fp = open(path, O_RDWR);
	if (fp == -1)
		return (PSVC_FAILURE);

	ret = ioctl_retry(fp, I2C_GET_INPUT, (void *)value);
	if (ret == -1) {
		close(fp);
		errno = EIO;
		return (-1);
	}

	close(fp);

	return (status);
}

/* LTC1427 */
static int32_t
i_psvc_get_output_11_3(EHdl_t *hdlp, uint64_t aspec, int32_t *value)
{
	int32_t ret, status = PSVC_SUCCESS;
	char path[1024];
	int32_t fp;

	status = i_psvc_get_devpath(hdlp, aspec, path);
	if (status != PSVC_SUCCESS)
		return (status);

	fp = open(path, O_RDWR);
	if (fp == -1)
		return (PSVC_FAILURE);

	ret = ioctl_retry(fp, I2C_GET_OUTPUT, (void *)value);
	if (ret == -1) {
		close(fp);
		errno = EIO;
		return (PSVC_FAILURE);
	}

	close(fp);

	return (status);
}

/* PCF8591 */
static int32_t
i_psvc_get_output_11_6(EHdl_t *hdlp, uint64_t aspec, int32_t *value)
{
	int32_t ret, status = PSVC_SUCCESS;
	char path[1024];
	int32_t fp;

	status = i_psvc_get_devpath(hdlp, aspec, path);
	if (status != PSVC_SUCCESS)
		return (status);

	fp = open(path, O_RDWR);
	if (fp == -1)
		return (PSVC_FAILURE);

	ret = ioctl_retry(fp, I2C_GET_OUTPUT, (void *)value);
	if (ret == -1) {
		close(fp);
		errno = EIO;
		return (PSVC_FAILURE);
	}

	close(fp);

	return (status);
}

/* TDA8444 */
static int32_t
i_psvc_get_output_11_8(EHdl_t *hdlp, uint64_t aspec, int32_t *value)
{
	int32_t ret, status = PSVC_SUCCESS;
	char path[1024];
	int32_t fp;
	int8_t buf;

	status = i_psvc_get_devpath(hdlp, aspec, path);
	if (status != PSVC_SUCCESS)
		return (status);

	fp = open(path, O_RDWR);
	if (fp == -1)
		return (PSVC_FAILURE);

	ret = read(fp, &buf, 1);
	if (ret == -1) {
		close(fp);
		errno = EIO;
		return (PSVC_FAILURE);
	}
	*value = buf;

	close(fp);

	return (status);
}

/* LTC1427 */
static int32_t
i_psvc_set_output_11_3(EHdl_t *hdlp, uint64_t aspec, int32_t value)
{
	int32_t ret, status = PSVC_SUCCESS;
	char path[1024];
	int32_t fp;

	status = i_psvc_get_devpath(hdlp, aspec, path);
	if (status != PSVC_SUCCESS)
		return (status);

	fp = open(path, O_RDWR);
	if (fp == -1)
		return (PSVC_FAILURE);

	ret = ioctl_retry(fp, I2C_SET_OUTPUT, (void *)&value);
	if (ret == -1) {
		close(fp);
		errno = EIO;
		return (PSVC_FAILURE);
	}

	close(fp);

	return (status);
}

/* PCF8591 */
static int32_t
i_psvc_set_output_11_6(EHdl_t *hdlp, uint64_t aspec, int32_t value)
{
	int32_t ret, status = PSVC_SUCCESS;
	char path[1024];
	int32_t fp;

	status = i_psvc_get_devpath(hdlp, aspec, path);
	if (status != PSVC_SUCCESS)
		return (status);

	fp = open(path, O_RDWR);
	if (fp == -1)
		return (PSVC_FAILURE);

	ret = ioctl_retry(fp, I2C_SET_OUTPUT, (void *)&value);
	if (ret == -1) {
		close(fp);
		errno = EIO;
		return (PSVC_FAILURE);
	}

	close(fp);

	return (status);
}

/* TDA8444 */
static int32_t
i_psvc_set_output_11_8(EHdl_t *hdlp, uint64_t aspec, int32_t value)
{
	int32_t ret, status = PSVC_SUCCESS;
	char path[1024];
	int32_t fp;
	int8_t buf;

	status = i_psvc_get_devpath(hdlp, aspec, path);
	if (status != PSVC_SUCCESS)
		return (status);

	fp = open(path, O_RDWR);
	if (fp == -1)
		return (PSVC_FAILURE);

	buf = value;
	ret = write(fp, &buf, 1);
	if (ret == -1) {
		close(fp);
		errno = EIO;
		return (PSVC_FAILURE);
	}

	close(fp);

	return (status);
}

/* HPC3130 */
static int32_t
i_psvc_get_reg_11_1(EHdl_t *hdlp, uint64_t aspec, uint8_t *value)
{
	int32_t ret, status = PSVC_SUCCESS;
	uint8_t bitshift, bytemask;
	char path[1024];
	i2c_reg_t i2cregarg;
	int32_t fp;

	status = i_psvc_get_devpath(hdlp, aspec, path);
	if (status != PSVC_SUCCESS)
		return (status);
	fp = open(path, O_RDWR);
	if (fp == -1)
		return (PSVC_FAILURE);

	i2cregarg.reg_num = PSVC_GET_ASPEC_REG(aspec);
	ret = ioctl_retry(fp, I2C_GET_REG, (void *)&i2cregarg);
	if (ret == -1) {
		close(fp);
		errno = EIO;
		return (-1);
	}

	bitshift = PSVC_GET_ASPEC_BITSHIFT(aspec);
	bytemask = PSVC_GET_ASPEC_BYTEMASK(aspec);
	if (value != NULL)
		*value = (i2cregarg.reg_value & bytemask) >> bitshift;
	close(fp);

	return (status);
}

/* SSC050 */
static int32_t
i_psvc_get_reg_11_7(EHdl_t *hdlp, uint64_t aspec, uint8_t *value)
{
	int32_t ret, status = PSVC_SUCCESS;
	uint8_t bitshift, bytemask;
	char path[1024];
	i2c_reg_t i2cregarg;
	int32_t fp;

	status = i_psvc_get_devpath(hdlp, aspec, path);
	if (status != PSVC_SUCCESS)
		return (status);

	fp = open(path, O_RDWR);
	if (fp == -1)
		return (PSVC_FAILURE);

	i2cregarg.reg_num = PSVC_GET_ASPEC_REG(aspec);
	ret = ioctl_retry(fp, I2C_GET_REG, (void *)&i2cregarg);
	if (ret == -1) {
		close(fp);
		errno = EIO;
		return (-1);
	}

	bitshift = PSVC_GET_ASPEC_BITSHIFT(aspec);
	bytemask = PSVC_GET_ASPEC_BYTEMASK(aspec);
	if (value != NULL)
		*value = (i2cregarg.reg_value & bytemask) >> bitshift;

	close(fp);

	return (status);
}

/* HPC3130 */
static int32_t
i_psvc_set_reg_11_1(EHdl_t *hdlp, uint64_t aspec, int32_t value)
{
	int32_t ret, status = PSVC_SUCCESS;
	char path[1024];
	i2c_reg_t i2cregarg;
	int8_t tval;
	uint8_t bitshift, bytemask;
	int32_t fp;

	status = i_psvc_get_devpath(hdlp, aspec, path);
	if (status != PSVC_SUCCESS)
		return (status);

	bitshift = PSVC_GET_ASPEC_BITSHIFT(aspec);
	bytemask = PSVC_GET_ASPEC_BYTEMASK(aspec);
	value = value << bitshift;

	fp = open(path, O_RDWR);
	if (fp == -1)
		return (PSVC_FAILURE);

	i2cregarg.reg_num = PSVC_GET_ASPEC_REG(aspec);
	if (bytemask != 0xFF) {
		ret = ioctl_retry(fp, I2C_GET_REG, (void *)&i2cregarg);
		if (ret == -1) {
			close(fp);
			errno = EIO;
			return (-1);
		}
		tval = i2cregarg.reg_value;
		tval = tval & ~bytemask;
	} else
		tval = 0;

	value = tval | value;
	i2cregarg.reg_value = value;
	ret = ioctl_retry(fp, I2C_SET_REG, (void *)&i2cregarg);
	if (ret == -1) {
		close(fp);
		errno = EIO;
		return (-1);
	}

	close(fp);

	return (status);
}

/* SSC050 */
static int32_t
i_psvc_set_reg_11_7(EHdl_t *hdlp, uint64_t aspec, int32_t value)
{
	int32_t ret, status = PSVC_SUCCESS;
	char path[1024];
	i2c_reg_t i2cregarg;
	int8_t tval;
	uint8_t bitshift, bytemask;
	int32_t fp;

	status = i_psvc_get_devpath(hdlp, aspec, path);
	if (status != PSVC_SUCCESS)
		return (status);

	bitshift = PSVC_GET_ASPEC_BITSHIFT(aspec);
	bytemask = PSVC_GET_ASPEC_BYTEMASK(aspec);
	value = value << bitshift;

	fp = open(path, O_RDWR);
	if (fp == -1)
		return (PSVC_FAILURE);

	i2cregarg.reg_num = PSVC_GET_ASPEC_REG(aspec);
	if (bytemask != 0xFF) {
		ret = ioctl_retry(fp, I2C_GET_REG, (void *)&i2cregarg);
		if (ret == -1) {
			close(fp);
			errno = EIO;
			return (-1);
		}
		tval = i2cregarg.reg_value;
		tval = tval & ~bytemask;
	} else
		tval = 0;

	value = tval | value;
	i2cregarg.reg_value = value;
	ret = ioctl_retry(fp, I2C_SET_REG, (void *)&i2cregarg);
	if (ret == -1) {
		close(fp);
		errno = EIO;
		return (-1);
	}

	close(fp);

	return (status);
}

/* PCF8574 */
static int32_t
i_psvc_get_bit_11_5(EHdl_t *hdlp, uint64_t aspec, int32_t *value)
{
	int32_t ret, status = PSVC_SUCCESS;
	char path[1024];
	i2c_bit_t bitarg;
	int32_t fp;

	status = i_psvc_get_devpath(hdlp, aspec, path);
	if (status != PSVC_SUCCESS)
		return (status);

	bitarg.bit_num = PSVC_GET_BIT_NUM(aspec);
	bitarg.direction = DIR_NO_CHANGE;

	fp = open(path, O_RDWR);
	if (fp == -1)
		return (PSVC_FAILURE);

	ret = ioctl_retry(fp, I2C_GET_BIT, (void *)&bitarg);
	if (ret == -1) {
		close(fp);
		errno = EIO;
		return (-1);
	}

	*value = bitarg.bit_value;

	close(fp);

	return (status);
}

/* PCF8574 */
static int32_t
i_psvc_get_port_11_5(EHdl_t *hdlp, uint64_t aspec, uint8_t *value)
{
	int32_t ret, status = PSVC_SUCCESS;
	char path[1024];
	i2c_port_t port;
	int32_t fp;

	status = i_psvc_get_devpath(hdlp, aspec, path);
	if (status != PSVC_SUCCESS)
		return (status);

	port.direction = DIR_NO_CHANGE;

	fp = open(path, O_RDWR);
	if (fp == -1)
		return (PSVC_FAILURE);

	ret = ioctl_retry(fp, I2C_GET_PORT, (void *)&port);
	if (ret == -1) {
		close(fp);
		errno = EIO;
		return (-1);
	}

	*value = port.value;

	close(fp);

	return (status);
}

/* SSC050 */
static int32_t
i_psvc_get_bit_11_7(EHdl_t *hdlp, uint64_t aspec, int32_t *value)
{
	int32_t ret, status = PSVC_SUCCESS;
	char path[1024];
	i2c_bit_t bitarg;
	int32_t fp;

	status = i_psvc_get_devpath(hdlp, aspec, path);
	if (status != PSVC_SUCCESS)
		return (status);

	bitarg.bit_num = PSVC_GET_BIT_NUM(aspec);
	bitarg.direction = DIR_NO_CHANGE;

	fp = open(path, O_RDWR);
	if (fp == -1)
		return (PSVC_FAILURE);

	ret = ioctl_retry(fp, I2C_GET_BIT, (void *)&bitarg);
	if (ret == -1) {
		close(fp);
		errno = EIO;
		return (-1);
	}

	*value = bitarg.bit_value;

	close(fp);

	return (status);
}

/* PCF8574 */
static int32_t
i_psvc_set_bit_11_5(EHdl_t *hdlp, uint64_t aspec, int32_t value)
{
	int32_t ret, status = PSVC_SUCCESS;
	char path[1024];
	i2c_bit_t bitarg;
	int32_t fp;

	status = i_psvc_get_devpath(hdlp, aspec, path);
	if (status != PSVC_SUCCESS)
		return (status);

	bitarg.bit_value = value;
	bitarg.bit_num = PSVC_GET_BIT_NUM(aspec);
	bitarg.direction = DIR_OUTPUT;
	fp = open(path, O_RDWR);
	if (fp == -1)
		return (PSVC_FAILURE);

	ret = ioctl_retry(fp, I2C_SET_BIT, (void *)&bitarg);
	if (ret == -1) {
		close(fp);
		errno = EIO;
		return (-1);
	}

	close(fp);

	return (status);
}

/* PCF8574 */
static int32_t
i_psvc_set_port_11_5(EHdl_t *hdlp, uint64_t aspec, int32_t value)
{
	int32_t ret, status = PSVC_SUCCESS;
	char path[1024];
	i2c_port_t port;
	int32_t fp;

	status = i_psvc_get_devpath(hdlp, aspec, path);
	if (status != PSVC_SUCCESS)
		return (status);

	port.value = (uint8_t)value;
	port.direction = DIR_NO_CHANGE;
	fp = open(path, O_RDWR);
	if (fp == -1)
		return (PSVC_FAILURE);

	ret = ioctl_retry(fp, I2C_SET_PORT, (void *)&port);
	if (ret == -1) {
		close(fp);
		errno = EIO;
		return (-1);
	}

	close(fp);

	return (status);
}

/* SSC050 */
static int32_t
i_psvc_set_bit_11_7(EHdl_t *hdlp, uint64_t aspec, int32_t value)
{
	int32_t ret, status = PSVC_SUCCESS;
	char path[1024];
	i2c_bit_t bitarg;
	int32_t fp;

	status = i_psvc_get_devpath(hdlp, aspec, path);
	if (status != PSVC_SUCCESS)
		return (status);

	bitarg.bit_value = value;
	bitarg.bit_num = PSVC_GET_BIT_NUM(aspec);
	bitarg.direction = DIR_OUTPUT;

	fp = open(path, O_RDWR);
	if (fp == -1)
		return (PSVC_FAILURE);

	ret = ioctl_retry(fp, I2C_SET_BIT, (void *)&bitarg);
	if (ret == -1) {
		close(fp);
		errno = EIO;
		return (-1);
	}

	close(fp);

	return (status);
}

/* AT24 */
static int32_t
i_psvc_probe_11_0(EHdl_t *hdlp, EObj_t *objp)
{
	int32_t ret, status = PSVC_SUCCESS;
	uint8_t value;
	char path[1024];
	int32_t fp;

	if (objp->present != PSVC_PRESENT) {
		errno = ENODEV;
		return (PSVC_FAILURE);
	}

	status = i_psvc_get_devpath(hdlp, objp->addr_spec, path);
	if (status != PSVC_SUCCESS) {
		return (status);
	}

	fp = open(path, O_RDWR);
	if (fp == -1) {
		return (PSVC_FAILURE);
	}

	ret = read(fp, &value, 1);
	if (ret == -1) {
		close(fp);
		errno = EIO;
		return (-1);
	}

	close(fp);

	return (status);
}

/* HPC3130 */
static int32_t
i_psvc_probe_11_1(EHdl_t *hdlp, EObj_t *objp)
{
	int32_t ret, status = PSVC_SUCCESS;
	char path[1024];
	i2c_reg_t reg;
	int32_t fp;

	if (objp->present != PSVC_PRESENT) {
		errno = ENODEV;
		return (PSVC_FAILURE);
	}

	status = i_psvc_get_devpath(hdlp, objp->addr_spec, path);
	if (status != PSVC_SUCCESS)
		return (status);

	fp = open(path, O_RDWR);
	if (fp == -1)
		return (PSVC_FAILURE);

	reg.reg_num = 0;
	ret = ioctl_retry(fp, I2C_GET_REG, (void *)&reg);
	if (ret == -1) {
		close(fp);
		errno = EIO;
		return (-1);
	}

	close(fp);

	return (status);
}

/* LM75 */
static int32_t
i_psvc_probe_11_2(EHdl_t *hdlp, EObj_t *objp)
{
	int32_t ret, status = PSVC_SUCCESS;
	char path[1024];
	int32_t fp;
	int16_t temp16;

	if (objp->present != PSVC_PRESENT) {
		errno = ENODEV;
		return (PSVC_FAILURE);
	}

	status = i_psvc_get_devpath(hdlp, objp->addr_spec, path);
	if (status != PSVC_SUCCESS) {
		return (status);
	}

	fp = open(path, O_RDWR);
	if (fp == -1) {
		return (PSVC_FAILURE);
	}

	ret = ioctl_retry(fp, I2C_GET_TEMPERATURE, (void *)&temp16);
	if (ret == -1) {
		close(fp);
		errno = EIO;
		return (-1);
	}

	close(fp);

	return (status);
}

/* LTC1427 */
static int32_t
i_psvc_probe_11_3(EHdl_t *hdlp, EObj_t *objp)
{
	int32_t ret, status = PSVC_SUCCESS;
	int32_t value;
	char path[1024];
	int32_t fp;

	if (objp->present != PSVC_PRESENT) {
		errno = ENODEV;
		return (PSVC_FAILURE);
	}

	status = i_psvc_get_devpath(hdlp, objp->addr_spec, path);
	if (status != PSVC_SUCCESS) {
		return (status);
	}

	fp = open(path, O_RDWR);
	if (fp == -1) {
		return (PSVC_FAILURE);
	}

	ret = ioctl_retry(fp, I2C_GET_OUTPUT, (void *)&value);
	if (ret == -1) {
		close(fp);
		errno = EINVAL;
		return (-1);
	}

	ret = ioctl_retry(fp, I2C_SET_OUTPUT, (void *)&value);
	if (ret == -1) {
		close(fp);
		errno = EIO;
		return (-1);
	}

	close(fp);
	return (status);
}

/* MAX1617 */
static int32_t
i_psvc_probe_11_4(EHdl_t *hdlp, EObj_t *objp)
{
	int32_t ret, status = PSVC_SUCCESS;
	char path[1024];
	int32_t fp;
	int16_t temp16;

	if (objp->present != PSVC_PRESENT) {
		errno = ENODEV;
		return (PSVC_FAILURE);
	}

	status = i_psvc_get_devpath(hdlp, objp->addr_spec, path);
	if (status != PSVC_SUCCESS) {
		return (status);
	}

	fp = open(path, O_RDWR);
	if (fp == -1) {
		return (PSVC_FAILURE);
	}

	ret = ioctl_retry(fp, I2C_GET_TEMPERATURE, (void *)&temp16);
	if (ret == -1) {
		close(fp);
		errno = EIO;
		return (-1);
	}

	close(fp);

	return (status);
}

/* PCF8574 */
static int32_t
i_psvc_probe_11_5(EHdl_t *hdlp, EObj_t *objp)
{
	int32_t ret, status = PSVC_SUCCESS;
	char path[1024];
	i2c_port_t port;
	int32_t fp;

	if (objp->present != PSVC_PRESENT) {
		errno = ENODEV;
		return (PSVC_FAILURE);
	}

	status = i_psvc_get_devpath(hdlp, objp->addr_spec, path);
	if (status != PSVC_SUCCESS) {
		return (status);
	}

	port.direction = DIR_NO_CHANGE;

	fp = open(path, O_RDWR);
	if (fp == -1) {
		return (PSVC_FAILURE);
	}

	ret = ioctl_retry(fp, I2C_GET_PORT, (void *)&port);
	if (ret == -1) {
		close(fp);
		errno = EIO;
		return (-1);
	}

	close(fp);

	return (status);
}

/* PCF8591 */
static int32_t
i_psvc_probe_11_6(EHdl_t *hdlp, EObj_t *objp)
{
	int32_t ret, status = PSVC_SUCCESS;
	char path[1024];
	int32_t arg;
	int32_t fp;

	if (objp->present != PSVC_PRESENT) {
		errno = ENODEV;
		return (PSVC_FAILURE);
	}

	status = i_psvc_get_devpath(hdlp, objp->addr_spec, path);
	if (status != PSVC_SUCCESS)
		return (status);

	fp = open(path, O_RDWR);
	if (fp == -1)
		return (PSVC_FAILURE);

	ret = ioctl_retry(fp, I2C_GET_INPUT, (void *)&arg);
	if (ret == -1) {
		close(fp);
		errno = EIO;
		return (-1);
	}

	close(fp);

	return (status);
}

/* SSC050 */
static int32_t
i_psvc_probe_11_7(EHdl_t *hdlp, EObj_t *objp)
{
	int32_t ret, status = PSVC_SUCCESS;
	char path[1024];
	i2c_port_t port;
	int32_t fp;

	if (objp->present != PSVC_PRESENT) {
		errno = ENODEV;
		return (PSVC_FAILURE);
	}

	status = i_psvc_get_devpath(hdlp, objp->addr_spec, path);
	if (status != PSVC_SUCCESS)
		return (status);

	port.direction = DIR_NO_CHANGE;

	fp = open(path, O_RDWR);
	if (fp == -1)
		return (PSVC_FAILURE);

	ret = ioctl_retry(fp, I2C_GET_PORT, (void *)&port);
	if (ret == -1) {
		close(fp);
		errno = EIO;
		return (-1);
	}

	close(fp);

	return (status);
}

/* TDA8444 */
static int32_t
i_psvc_probe_11_8(EHdl_t *hdlp, EObj_t *objp)
{
	int32_t ret, status = PSVC_SUCCESS;
	uint8_t value;
	char path[1024];
	int32_t fp;

	if (objp->present != PSVC_PRESENT) {
		errno = ENODEV;
		return (PSVC_FAILURE);
	}

	status = i_psvc_get_devpath(hdlp, objp->addr_spec, path);
	if (status != PSVC_SUCCESS)
		return (status);

	fp = open(path, O_RDWR);
	if (fp == -1)
		return (PSVC_FAILURE);

	ret = read(fp, &value, 1);
	if (ret == -1) {
		close(fp);
		errno = EIO;
		return (-1);
	}

	close(fp);

	return (status);
}


/* SSC100 */
static int32_t
i_psvc_probe_11_9(EHdl_t *hdlp, EObj_t *objp)
{
	int32_t ret, status = PSVC_SUCCESS;
	char path[1024];
	i2c_reg_t reg;
	int32_t fp;

	if (objp->present != PSVC_PRESENT) {
		errno = ENODEV;
		return (PSVC_FAILURE);
	}

	status = i_psvc_get_devpath(hdlp, objp->addr_spec, path);
	if (status != PSVC_SUCCESS) {
		return (status);
	}

	fp = open(path, O_RDWR);
	if (fp == -1) {
		return (PSVC_FAILURE);
	}

	/*
	 * There are only a few register numbers that are valid numbers to
	 * read from. 0x10 is one of these registers. Any non-valid registers
	 * cause unknown behavior to the ssc100 device.
	 */
	reg.reg_num = 0x10;
	ret = ioctl_retry(fp, I2C_GET_REG, (void *)&reg);
	if (ret == -1) {
		close(fp);
		errno = EIO;
		return (-1);
	}

	close(fp);

	return (status);
}


/*
 * Find start of a section within the config file,
 * Returns number of records in the section.
 * FILE *fd is set to first data record within section.
 */
static int32_t
i_psvc_find_file_section(FILE *fd, char *start)
{
	char *ret;
	char buf[BUFSZ];
	char name[32];
	int found;

	fseek(fd, 0, SEEK_SET);
	while ((ret = fgets(buf, BUFSZ, fd)) != NULL) {
		if (strncmp(start, buf, strlen(start)) == 0)
			break;
	}

	if (ret == NULL) {
		errno = EINVAL;
		return (-1);
	}

	found = sscanf(buf, "%s", name);
	if (found != 1) {
		errno = EINVAL;
		return (-1);
	} else {
		return (0);
	}

}

/* compare routine for qsort of str_tbl */
static int32_t
i_psvc_name_compare_qsort(EStringId_t *s1, EStringId_t *s2)
{
	return (strcmp(s1->name, s2->name));
}

/* compare routine for bsearch of str_tbl */
static int32_t
i_psvc_name_compare_bsearch(char *s1, EStringId_t *s2)
{
	return (strcmp(s1, s2->name));
}

/*
 * Determine the initial state of a device.
 */
static int32_t
i_psvc_init_state(EHdl_t *hp, EObj_t *objp)
{
	int32_t status = PSVC_SUCCESS;

	if (objp->class == PSVC_ON_OFF_SWITCH_CLASS) {
		char state[32];

		status = objp->get_attr(hp, objp, PSVC_SWITCH_STATE_ATTR,
			state);
		if (status != PSVC_SUCCESS)
			return (status);

		if (strcmp(state, PSVC_SWITCH_ON) == 0)
			strcpy(objp->state, PSVC_ON);
		else
			strcpy(objp->state, PSVC_OFF);
	}

	if (objp->class == PSVC_KEYSWITCH_CLASS) {
		char state[32];

		status = objp->get_attr(hp, objp, PSVC_SWITCH_STATE_ATTR,
			state);
		if (status != PSVC_SUCCESS)
			return (status);
		strcpy(objp->state, state);
	}

	return (status);
}

/*
 * Return the object pointer for the object name passed in.
 * Creates the object if this is the first access,
 * Returns 0 if successful, -1 if not.
 */
static int32_t
i_psvc_get_obj(EHdl_t *hp, char *dev_name, EObj_t **objp)
{
	int32_t i, ret;
	int32_t found, key, array;
	int32_t class, subclass;
	boolean_t presence;
	char name[NAMELEN];
	char buf[BUFSZ];
	char *start;
	ETable_Array *tbl_arr;

	key = psvc_get_str_key(dev_name);
	array = key % PSVC_MAX_TABLE_ARRAYS;
	tbl_arr = &(hp->tbl_arry[array]);

	for (i = 0; i < tbl_arr->obj_count; ++i) {
		if (key ==  tbl_arr->obj_tbl[i].key) {
			if (strcmp(dev_name, tbl_arr->obj_tbl[i].name) == 0) {
				if (tbl_arr->obj_tbl[i].type != PSVC_OBJ)
					return (-1);
				*objp = tbl_arr->obj_tbl[i].objp;
				return (0);
			}
		}
	}

	if (i_psvc_find_file_section(hp->fp, "OBJECT_INFO") == -1) {
		ENV_DEBUG("Couldn't find OBJECT_INFO section", dev_name);
		return (-1);
	}

	fgets(buf, BUFSZ, hp->fp);
	while (strcmp(buf, "OBJECT_INFO_END")) {
		start = strrchr(buf, '/');
		if (start == NULL) {
			errno = EINVAL;
			return (PSVC_FAILURE);
		}
		found = sscanf(start + 1, "%s",  name);
		if (found != 1) {
			errno = EINVAL;
			return (PSVC_FAILURE);
		}

		if (strcmp(name, dev_name) == 0) {

			if (i_psvc_value(buf, PSVC_CLASS_ATTR, &class)
			    != PSVC_SUCCESS)
				return (PSVC_FAILURE);
			if (i_psvc_value(buf, PSVC_SUBCLASS_ATTR, &subclass)
			    != PSVC_SUCCESS)
				return (PSVC_FAILURE);
			ret = (*i_psvc_constructor[class][subclass])(hp,
				dev_name, objp);
			if (ret != PSVC_SUCCESS) {
				return (-1);
			}
			ret = (*objp)->get_attr(hp, *objp, PSVC_PRESENCE_ATTR,
				&presence);
			(*objp)->previous_presence = presence;
			if (ret != PSVC_SUCCESS || presence != PSVC_PRESENT)
				return (ret);

			return (i_psvc_init_state(hp, *objp));
		}
		fgets(buf, BUFSZ, hp->fp);
	}

	errno = EINVAL;
	return (-1);
}

/*
 * Gets the device path associated with an object id.
 * Returns 0 if successful, -1 if not.
 */
static int32_t
i_psvc_get_devpath(EHdl_t *hp, uint64_t addr_spec, char *path)
{
	int i;
	EDevice_t *dp;
	uint32_t controller, bus, addr, port;

	controller = PSVC_GET_ASPEC_CNTLR(addr_spec);
	bus = PSVC_GET_ASPEC_BUSNUM(addr_spec);
	addr = PSVC_GET_ASPEC_BUSADDR(addr_spec);
	port = PSVC_GET_ASPEC_PORT(addr_spec);

	for (i = 0; i < hp->dev_count; ++i) {
		dp = &hp->dev_tbl[i];
		if (dp->controller == controller &&
		    dp->bus == bus &&
		    dp->addr == addr &&
		    dp->port == port) {
			strcpy(path, dp->path);
			return (PSVC_SUCCESS);
		}
	}

	errno = EINVAL;
	return (PSVC_FAILURE);
}


/* Load the association table */
static int32_t
i_psvc_load_associations(EHdl_t *hp, FILE *fp)
{
	uint32_t count;
	int found;
	int i, j;
	char name1[32], name2[32];
	char buf[BUFSZ];
	EStringId_t *namep;
	EAssoc_t *ap;
	int32_t id;
	int32_t status;

	/*
	 * ignore count in the file, correct count is highest
	 * association id + 1, now figured when loading ASSOC_STR
	 * section.
	 */
	if (i_psvc_find_file_section(fp, "ASSOCIATIONS") != PSVC_SUCCESS)
		return (-1);
	if ((hp->assoc_tbl = malloc(sizeof (EAssocList_t) * hp->assoc_count))
			== NULL) {
		return (-1);
	}
	memset(hp->assoc_tbl, 0, sizeof (EAssocList_t) * hp->assoc_count);

	for (i = 0; i < hp->assoc_count; ++i) {
		fgets(buf, BUFSZ, fp);
		found = sscanf(buf, "%s %s", name1, name2);
		if (strcmp("ASSOCIATIONS_END", name1) == 0)
			break;
		if (found != 2) {
			errno = EINVAL;
			return (-1);
		}
		namep = (EStringId_t *)bsearch(name2, hp->othr_tbl,
			hp->othr_count, sizeof (EStringId_t),
			(int (*)(const void *, const void *))
			i_psvc_name_compare_bsearch);
		if (namep == NULL) {
			errno = EINVAL;
			return (-1);
		}
		id = namep->id;

		status = i_psvc_count_records(fp, "ASSOCIATION_END", &count);
		if (status != PSVC_SUCCESS)
			return (status);
		hp->assoc_tbl[id].count = count;
		hp->assoc_tbl[id].table =
			(EAssoc_t *)malloc(sizeof (EAssoc_t) * count);
		if (hp->assoc_tbl[id].table == NULL)
			return (-1);

		for (j = 0; j < count; ++j) {
			ap = &hp->assoc_tbl[id].table[j];
			fgets(buf, BUFSZ, fp);
			found = sscanf(buf, "%s %s", ap->antecedent_id,
				ap->dependent_id);
			ap->ant_key = psvc_get_str_key(ap->antecedent_id);
			if (found != 2) {
				errno = EINVAL;
				return (-1);
			}
		}


		fgets(buf, BUFSZ, fp);
		if (strncmp(buf, "ASSOCIATION_END", 15) != 0) {
			errno = EINVAL;
			return (-1);
		}
	}

	return (0);
}

/* Load the table of tables */
static int32_t
i_psvc_load_tables(EHdl_t *hp, FILE *fp)
{
	int i, j;
	int found;
	int ret;
	int32_t cell_type;
	int64_t *table;
	char buf[BUFSZ];
	int32_t status;
	uint32_t table_count;
	int32_t num, key, array;
	char name[NAMELEN];
	ETable_Array *tbl_arr;

	if (i_psvc_find_file_section(fp, "TABLES") != PSVC_SUCCESS)
		return (PSVC_SUCCESS);	/* no tables */
	status = i_psvc_count_tables_associations(fp, &table_count,
			"TABLE_END");
	if (status != PSVC_SUCCESS || table_count == 0)
		return (status);

	for (i = 0; i < table_count; ++i) {
		int slot;
		ETable_t *tblp;

		fgets(buf, BUFSZ, fp);
		if (strncmp(buf, "TABLE", 5) != 0) {
			errno = EINVAL;
			return (-1);
		}

		fgets(buf, BUFSZ, fp);
		found = sscanf(buf, "%s %d", name, &cell_type);
		key = psvc_get_str_key(name);
		array = key % PSVC_MAX_TABLE_ARRAYS;
		tbl_arr = &(hp->tbl_arry[array]);

		if (tbl_arr->nextid == hp->total_obj_count) {
			errno = EINVAL;
			return (PSVC_FAILURE);
		} else {
			slot = tbl_arr->nextid++;
			tbl_arr->obj_count++;
		}

		strcpy(tbl_arr->obj_tbl[slot].name, name);

		tblp = (ETable_t *)malloc(sizeof (ETable_t));
		if (tblp == NULL)
			return (PSVC_FAILURE);
		tbl_arr->obj_tbl[slot].key = key;
		tbl_arr->obj_tbl[slot].objp = (EObj_t *)(void *)tblp;
		tbl_arr->obj_tbl[slot].type = PSVC_TBL;

		status = i_psvc_count_table_records(fp, "TABLE_END",
			&tblp->size);
		if (status != PSVC_SUCCESS)
			return (status);
		tblp->cell_type = (uint8_t)cell_type;
		if (found != 2) {
			errno = EINVAL;
			return (-1);
		}

		/* allocate and load table */
		tblp->table = (int64_t *)malloc(tblp->size *
			i_psvc_cell_size[tblp->cell_type]);
		if (tblp->table == NULL) {
			return (-1);
		}

		table = tblp->table;
		for (j = 0; j < tblp->size; ++j) {
			switch (cell_type) {
				case 0:
					ret = fscanf(fp, "%d", &num);
					*((int8_t *)table + j) = num;
					break;
				case 1:
					ret = fscanf(fp, "%d", &num);
					*((uint8_t *)table + j) = (uint8_t)num;
					break;
				case 2:
					ret = fscanf(fp, "%hd",
						((int16_t *)table + j));
					break;
				case 3:
					ret = fscanf(fp, "%hd",
						((uint16_t *)table + j));
					break;
				case 4:
					ret = fscanf(fp, "%d",
						((int32_t *)table + j));
					break;
				case 5:
					ret = fscanf(fp, "%d",
						((uint32_t *)table + j));
					break;
				case 6:
					ret = fscanf(fp, "%lld",
						((int64_t *)table + j));
					break;
				case 7:
					ret = fscanf(fp, "%lld",
						((uint64_t *)table + j));
					break;
				default:
					errno = EINVAL;
					return (-1);
			}
			if (ret != 1) {
				errno = EINVAL;
				return (-1);
			}
		}
		fgets(buf, BUFSZ, fp);  /* reads newline on data line */
		fgets(buf, BUFSZ, fp);
		if (strncmp(buf, "TABLE_END", 9) != 0) {
			errno = EINVAL;
			return (-1);
		}

	}

	return (0);
}

static int32_t
i_psvc_destructor(EHdl_t *hdlp, char *name, void *objp)
{
	int32_t i, key, array;

	key = psvc_get_str_key(name);
	array = key % PSVC_MAX_TABLE_ARRAYS;

	for (i = 0; i < hdlp->tbl_arry[array].obj_count; ++i) {
		if (key == hdlp->tbl_arry[array].obj_tbl[i].key) {
			if (strcmp(hdlp->tbl_arry[array].obj_tbl[i].name,
				name) == 0) {
				hdlp->tbl_arry[array].obj_tbl[i].name[0] = '\0';
				if (objp != NULL)
					free(objp);
				return (PSVC_SUCCESS);
			}
		}
	}

	return (PSVC_SUCCESS);
}

static int32_t
i_psvc_get_attr_generic(EHdl_t *hdlp, EObj_t *objp, int32_t attr_id,
    void * attrp)
{
	int32_t status = PSVC_SUCCESS;
	char *parent_id;

	switch (attr_id) {
	case PSVC_ADDR_SPEC_ATTR:
		*(uint64_t *)attrp = objp->addr_spec;
		break;
	case PSVC_CLASS_ATTR:
		*(int32_t *)attrp = objp->class;
		break;
	case PSVC_SUBCLASS_ATTR:
		*(int32_t *)attrp = objp->subclass;
		break;
	case PSVC_PRESENCE_ATTR:
		status = i_psvc_get_presence(hdlp, objp, (boolean_t *)attrp);
		break;
	case PSVC_PREV_PRESENCE_ATTR:
		*(boolean_t *)attrp = objp->previous_presence;
		break;
	case PSVC_STATE_ATTR:
		strcpy((char *)attrp, objp->state);
		break;
	case PSVC_PREV_STATE_ATTR:
		strcpy((char *)attrp, objp->previous_state);
		break;
	case PSVC_ENABLE_ATTR:
		*(boolean_t *)attrp = objp->enabled;
		break;
	case PSVC_FAULTID_ATTR:
		strcpy((char *)attrp, objp->fault_id);
		break;
	case PSVC_FEATURES_ATTR:
		*(uint64_t *)attrp = objp->features;
		break;
	case PSVC_LABEL_ATTR:
		strcpy((char *)attrp, objp->label);
		break;
	case PSVC_FRUID_ATTR:
		while ((objp->features & PSVC_DEV_FRU) == 0) {
			status = i_psvc_get_assoc_id(hdlp, objp->label,
				PSVC_PARENT, 0, &parent_id);
			if (status != PSVC_SUCCESS)
				return (status);

			status = i_psvc_get_obj(hdlp, parent_id, &objp);
			if (status != PSVC_SUCCESS)
				return (status);
		}

		strcpy((char *)attrp, objp->label);
		break;
	case PSVC_INSTANCE_ATTR:
		*(int32_t *)attrp = objp->instance;
		break;
	default:
		errno = EINVAL;
		return (PSVC_FAILURE);
	}

	return (status);
}

static int32_t
i_psvc_set_attr_generic(EHdl_t *hdlp, EObj_t *objp, int32_t attr_id,
    void * attrp)
{
	int32_t status = PSVC_SUCCESS;

	switch (attr_id) {
	case PSVC_PREV_PRESENCE_ATTR:
		objp->previous_presence = *(boolean_t *)attrp;
		break;
	case PSVC_STATE_ATTR:
		strcpy(objp->previous_state, objp->state);
		strcpy(objp->state, (char *)attrp);
		break;
	case PSVC_ENABLE_ATTR:
		objp->enabled = *(boolean_t *)attrp;
		break;
	case PSVC_FAULTID_ATTR:
		strcpy(objp->fault_id, (char *)attrp);
		break;
	default:
		errno = EINVAL;
		return (PSVC_FAILURE);
	}
	return (status);
}

static int32_t
i_psvc_get_attr_0_0(EHdl_t *hdlp, EObj_t *objp, int32_t attr_id, void *attrp)
{
	int32_t status = PSVC_SUCCESS;

	switch (attr_id) {
	case PSVC_SENSOR_VALUE_ATTR:
		return (i_psvc_get_device_value_0_0(hdlp, objp, attrp));
	case PSVC_LO_WARN_ATTR:
		*(int32_t *)attrp = ((ETempSensor_t *)objp)->lo_warn;
		return (status);
	case PSVC_LO_SHUT_ATTR:
		*(int32_t *)attrp = ((ETempSensor_t *)objp)->lo_shut;
		return (status);
	case PSVC_HI_WARN_ATTR:
		*(int32_t *)attrp = ((ETempSensor_t *)objp)->hi_warn;
		return (status);
	case PSVC_HI_SHUT_ATTR:
		*(int32_t *)attrp = ((ETempSensor_t *)objp)->hi_shut;
		return (status);
	}

	status = i_psvc_get_attr_generic(hdlp, objp, attr_id, attrp);

	return (status);
}

static int32_t
i_psvc_get_attr_0_1(EHdl_t *hdlp, EObj_t *objp, int32_t attr_id, void *attrp)
{
	int32_t status = PSVC_SUCCESS;

	switch (attr_id) {
	case PSVC_SENSOR_VALUE_ATTR:
		return (i_psvc_get_device_value_0_1(hdlp, objp, attrp));
	case PSVC_LO_WARN_ATTR:
		*(int32_t *)attrp = ((ETempSensor_t *)objp)->lo_warn;
		return (status);
	case PSVC_LO_SHUT_ATTR:
		*(int32_t *)attrp = ((ETempSensor_t *)objp)->lo_shut;
		return (status);
	case PSVC_HI_WARN_ATTR:
		*(int32_t *)attrp = ((ETempSensor_t *)objp)->hi_warn;
		return (status);
	case PSVC_HI_SHUT_ATTR:
		*(int32_t *)attrp = ((ETempSensor_t *)objp)->hi_shut;
		return (status);
	case PSVC_OPTIMAL_TEMP_ATTR:
		*(int32_t *)attrp = ((ETempSensor_t *)objp)->opt_temp;
		return (status);
	case PSVC_HW_HI_SHUT_ATTR:
		*(int32_t *)attrp = ((ETempSensor_t *)objp)->hw_hi_shut;
		return (status);
	case PSVC_HW_LO_SHUT_ATTR:
		*(int32_t *)attrp = ((ETempSensor_t *)objp)->hw_lo_shut;
		return (status);
	}

	status = i_psvc_get_attr_generic(hdlp, objp, attr_id, attrp);

	return (status);
}

static int32_t
i_psvc_set_attr_0_1(EHdl_t *hdlp, EObj_t *objp, int32_t attr_id, void *attrp)
{
	int32_t status = PSVC_SUCCESS;

	switch (attr_id) {
	case PSVC_LO_WARN_ATTR:
		((ETempSensor_t *)objp)->lo_warn = *(int32_t *)attrp;
		return (status);
	case PSVC_LO_SHUT_ATTR:
		((ETempSensor_t *)objp)->lo_shut = *(int32_t *)attrp;
		return (status);
	case PSVC_HI_WARN_ATTR:
		((ETempSensor_t *)objp)->hi_warn = *(int32_t *)attrp;
		return (status);
	case PSVC_HI_SHUT_ATTR:
		((ETempSensor_t *)objp)->hi_shut = *(int32_t *)attrp;
		return (status);
	case PSVC_OPTIMAL_TEMP_ATTR:
		((ETempSensor_t *)objp)->opt_temp = *(int32_t *)attrp;
		return (status);
	case PSVC_HW_HI_SHUT_ATTR:
		((ETempSensor_t *)objp)->hw_hi_shut = *(int32_t *)attrp;
		return (status);
	case PSVC_HW_LO_SHUT_ATTR:
		((ETempSensor_t *)objp)->hw_lo_shut = *(int32_t *)attrp;
		return (status);
	}

	status = i_psvc_set_attr_generic(hdlp, objp, attr_id, attrp);

	return (status);
}

static int32_t
i_psvc_get_attr_1_0(EHdl_t *hdlp, EObj_t *objp, int32_t attr_id, void *attrp)
{
	int32_t status = PSVC_SUCCESS;

	switch (attr_id) {
	case PSVC_SENSOR_VALUE_ATTR:
		return (i_psvc_get_device_value_1_0(hdlp, objp, attrp));
	case PSVC_SETPOINT_ATTR:
		*(int16_t *)attrp = ((EFan_t *)objp)->setpoint;
		return (status);
	case PSVC_HYSTERESIS_ATTR:
		*(int16_t *)attrp = ((EFan_t *)objp)->hysteresis;
		return (status);
	case PSVC_LOOPGAIN_ATTR:
		*(int16_t *)attrp = ((EFan_t *)objp)->loopgain;
		return (status);
	case PSVC_LOOPBIAS_ATTR:
		*(int16_t *)attrp = ((EFan_t *)objp)->loopbias;
		return (status);
	case PSVC_TEMP_DIFFERENTIAL_ATTR:
		memcpy(attrp, ((EFan_t *)objp)->temp_differential,
			sizeof (((EFan_t *)objp)->temp_differential));
		return (status);
	case PSVC_TEMP_DIFFERENTIAL_INDEX_ATTR:
		*(int16_t *)attrp = ((EFan_t *)objp)->temp_differential_index;
		return (status);
	}

	status = i_psvc_get_attr_generic(hdlp, objp, attr_id, attrp);

	return (status);
}

static int32_t
i_psvc_set_attr_1_0(EHdl_t *hdlp, EObj_t *objp, int32_t attr_id, void *attrp)
{
	int32_t status = PSVC_SUCCESS;

	switch (attr_id) {
	case PSVC_TEMP_DIFFERENTIAL_ATTR:
		memcpy(((EFan_t *)objp)->temp_differential, attrp,
			sizeof (((EFan_t *)objp)->temp_differential));
		return (status);
	case PSVC_TEMP_DIFFERENTIAL_INDEX_ATTR:
		((EFan_t *)objp)->temp_differential_index = *(int16_t *)attrp;
		return (status);
	case PSVC_SETPOINT_ATTR:
		((EFan_t *)objp)->setpoint = *(int16_t *)attrp;
		return (status);
	}

	status = i_psvc_set_attr_generic(hdlp, objp, attr_id, attrp);

	return (PSVC_SUCCESS);
}

static int32_t
i_psvc_get_attr_2_0(EHdl_t *hdlp, EObj_t *objp, int32_t attr_id, void *attrp)
{
	int32_t status = PSVC_SUCCESS;

	switch (attr_id) {
	case PSVC_LED_STATE_ATTR:
	case PSVC_STATE_ATTR:
		return (i_psvc_get_device_state_2_0(hdlp, objp, attrp));
	case PSVC_LED_COLOR_ATTR:
		strcpy((char *)attrp, ((ELed_t *)objp)->color);
		return (status);
	case PSVC_LIT_COUNT_ATTR:
		*(int16_t *)attrp = ((ELed_t *)objp)->lit_count;
		return (status);
	}

	status = i_psvc_get_attr_generic(hdlp, objp, attr_id, attrp);

	return (status);
}

static int32_t
i_psvc_set_attr_2_0(EHdl_t *hdlp, EObj_t *objp, int32_t attr_id, void *attrp)
{
	int32_t status = PSVC_SUCCESS;

	switch (attr_id) {
	case PSVC_LED_STATE_ATTR:
	case PSVC_STATE_ATTR:
		return (i_psvc_set_device_state_2_0(hdlp, objp, attrp));
	}

	status = i_psvc_set_attr_generic(hdlp, objp, attr_id, attrp);

	return (status);
}

static int32_t
i_psvc_get_attr_2_1(EHdl_t *hdlp, EObj_t *objp, int32_t attr_id, void *attrp)
{
	int32_t status = PSVC_SUCCESS;

	switch (attr_id) {
	case PSVC_LED_STATE_ATTR:
	case PSVC_STATE_ATTR:
		return (i_psvc_get_device_state_2_1(hdlp, objp, attrp));
	case PSVC_LED_COLOR_ATTR:
		strcpy((char *)attrp, ((ELed_t *)objp)->color);
		return (status);
	case PSVC_LIT_COUNT_ATTR:
		*(int16_t *)attrp = ((ELed_t *)objp)->lit_count;
		return (status);
	}

	status = i_psvc_get_attr_generic(hdlp, objp, attr_id, attrp);

	return (status);
}

static int32_t
i_psvc_set_attr_2_1(EHdl_t *hdlp, EObj_t *objp, int32_t attr_id, void *attrp)
{
	int32_t status = PSVC_SUCCESS;

	switch (attr_id) {
	case PSVC_LED_STATE_ATTR:
	case PSVC_STATE_ATTR:
		return (i_psvc_set_device_state_2_1(hdlp, objp, attrp));
	}

	status = i_psvc_set_attr_generic(hdlp, objp, attr_id, attrp);

	return (status);
}

static int32_t
i_psvc_get_attr_2_2(EHdl_t *hdlp, EObj_t *objp, int32_t attr_id, void *attrp)
{
	int32_t status = PSVC_SUCCESS;

	switch (attr_id) {
	case PSVC_LED_STATE_ATTR:
	case PSVC_STATE_ATTR:
		return (i_psvc_get_device_state_2_0(hdlp, objp, attrp));
	case PSVC_LED_COLOR_ATTR:
		strcpy((char *)attrp, ((ELed_t *)objp)->color);
		return (status);
	case PSVC_LIT_COUNT_ATTR:
		*(int16_t *)attrp = ((ELed_t *)objp)->lit_count;
		return (status);
	case PSVC_LED_IS_LOCATOR_ATTR:
		strcpy((char *)attrp, ((ELed_t *)objp)->is_locator);
		return (status);
	case PSVC_LED_LOCATOR_NAME_ATTR:
		strcpy((char *)attrp, ((ELed_t *)objp)->locator_name);
		return (status);
	}

	status = i_psvc_get_attr_generic(hdlp, objp, attr_id, attrp);

	return (status);
}

static int32_t
i_psvc_get_attr_4_0(EHdl_t *hdlp, EObj_t *objp, int32_t attr_id, void *attrp)
{
	int32_t status = PSVC_SUCCESS;

	switch (attr_id) {
	case PSVC_SENSOR_VALUE_ATTR:
		return (i_psvc_get_device_value_4_0(hdlp, objp, attrp));
	case PSVC_LO_WARN_ATTR:
		*(int32_t *)attrp = ((EDigiSensor_t *)objp)->lo_warn;
		return (status);
	case PSVC_LO_SHUT_ATTR:
		*(int32_t *)attrp = ((EDigiSensor_t *)objp)->lo_shut;
		return (status);
	case PSVC_HI_WARN_ATTR:
		*(int32_t *)attrp = ((EDigiSensor_t *)objp)->hi_warn;
		return (status);
	case PSVC_HI_SHUT_ATTR:
		*(int32_t *)attrp = ((EDigiSensor_t *)objp)->hi_shut;
		return (status);
	}

	status = i_psvc_get_attr_generic(hdlp, objp, attr_id, attrp);

	return (PSVC_SUCCESS);
}

static int32_t
i_psvc_get_attr_5_0(EHdl_t *hdlp, EObj_t *objp, int32_t attr_id, void *attrp)
{
	int32_t status = PSVC_SUCCESS;

	if (attr_id == PSVC_CONTROL_VALUE_ATTR) {
		return (i_psvc_get_device_value_5_0(hdlp, objp, attrp));
	}

	status = i_psvc_get_attr_generic(hdlp, objp, attr_id, attrp);

	return (status);
}

static int32_t
i_psvc_set_attr_5_0(EHdl_t *hdlp, EObj_t *objp, int32_t attr_id, void *attrp)
{
	int32_t status = PSVC_SUCCESS;

	if (attr_id == PSVC_CONTROL_VALUE_ATTR) {
		return (i_psvc_set_device_value_5_0(hdlp, objp, attrp));
	}

	status = i_psvc_set_attr_generic(hdlp, objp, attr_id, attrp);

	return (status);
}

static int32_t
i_psvc_get_attr_6_0(EHdl_t *hdlp, EObj_t *objp, int32_t attr_id, void *attrp)
{
	int32_t status = PSVC_SUCCESS;

	switch (attr_id) {
	case PSVC_GPIO_VALUE_ATTR:
		return (i_psvc_get_device_value_6_0(hdlp, objp, attrp));
	case PSVC_GPIO_BITS:
		*(int32_t *)attrp = 1;
		return (status);
	}

	status = i_psvc_get_attr_generic(hdlp, objp, attr_id, attrp);

	return (status);
}

static int32_t
i_psvc_set_attr_6_0(EHdl_t *hdlp, EObj_t *objp, int32_t attr_id, void *attrp)
{
	int32_t status = PSVC_SUCCESS;

	if (attr_id == PSVC_GPIO_VALUE_ATTR) {
		return (i_psvc_set_device_value_6_0(hdlp, objp, attrp));
	}

	status = i_psvc_set_attr_generic(hdlp, objp, attr_id, attrp);

	return (status);
}

static int32_t
i_psvc_get_attr_7_0(EHdl_t *hdlp, EObj_t *objp, int32_t attr_id, void *attrp)
{
	int32_t status = PSVC_SUCCESS;

	switch (attr_id) {
	case PSVC_SENSOR_VALUE_ATTR:
		return (i_psvc_get_device_value_7_0(hdlp, objp, attrp));
	case PSVC_LO_WARN_ATTR:
		*(int32_t *)attrp = ((EFanTach_t *)objp)->lo_warn;
		return (status);
	case PSVC_LO_SHUT_ATTR:
		*(int32_t *)attrp = ((EFanTach_t *)objp)->lo_shut;
		return (status);
	case PSVC_HI_WARN_ATTR:
		*(int32_t *)attrp = ((EFanTach_t *)objp)->hi_warn;
		return (status);
	case PSVC_HI_SHUT_ATTR:
		*(int32_t *)attrp = ((EFanTach_t *)objp)->hi_shut;
		return (status);
	}

	status = i_psvc_get_attr_generic(hdlp, objp, attr_id, attrp);

	return (PSVC_SUCCESS);
}

static int32_t
i_psvc_get_attr_8_0(EHdl_t *hdlp, EObj_t *objp, int32_t attr_id, void *attrp)
{
	int32_t status = PSVC_SUCCESS;

	switch (attr_id) {
	case PSVC_SWITCH_STATE_ATTR:
	case PSVC_STATE_ATTR:
		return (i_psvc_get_device_state_8_0(hdlp, objp, attrp));
	}

	status = i_psvc_get_attr_generic(hdlp, objp, attr_id, attrp);

	return (status);
}

static int32_t
i_psvc_set_attr_8_0(EHdl_t *hdlp, EObj_t *objp, int32_t attr_id, void *attrp)
{
	int32_t status = PSVC_SUCCESS;

	switch (attr_id) {
	case PSVC_SWITCH_STATE_ATTR:
	case PSVC_STATE_ATTR:
		return (i_psvc_set_device_state_8_0(hdlp, objp, attrp));
	}

	status = i_psvc_set_attr_generic(hdlp, objp, attr_id, attrp);

	return (status);
}

static int32_t
i_psvc_get_attr_9_0(EHdl_t *hdlp, EObj_t *objp, int32_t attr_id, void *attrp)
{
	int32_t status = PSVC_SUCCESS;

	switch (attr_id) {
	case PSVC_SWITCH_STATE_ATTR:
	case PSVC_STATE_ATTR:
		status = i_psvc_get_device_state_9_0(hdlp, objp, attrp);
		if ((status == PSVC_FAILURE) && (errno == EINVAL)) {
			strcpy((char *)attrp, PSVC_ERROR);
			return (PSVC_SUCCESS);
		} else {
			return (status);
		}
	}

	status = i_psvc_get_attr_generic(hdlp, objp, attr_id, attrp);

	return (status);
}

static int32_t
i_psvc_get_attr_10_0(EHdl_t *hdlp, EObj_t *objp, int32_t attr_id, void *attrp)
{
	int32_t status = PSVC_SUCCESS;

	switch (attr_id) {
	case PSVC_GPIO_VALUE_ATTR:
		return (i_psvc_get_device_value_10_0(hdlp, objp, attrp));
	case PSVC_GPIO_BITS:
		*(int32_t *)attrp = 8;
		return (status);
	}

	status = i_psvc_get_attr_generic(hdlp, objp, attr_id, attrp);

	return (status);
}

static int32_t
i_psvc_set_attr_10_0(EHdl_t *hdlp, EObj_t *objp, int32_t attr_id, void *attrp)
{
	int32_t status = PSVC_SUCCESS;

	if (attr_id == PSVC_GPIO_VALUE_ATTR) {
		return (i_psvc_set_device_value_10_0(hdlp, objp, attrp));
	}

	status = i_psvc_set_attr_generic(hdlp, objp, attr_id, attrp);

	return (status);
}

static int32_t
i_psvc_get_attr_10_1(EHdl_t *hdlp, EObj_t *objp, int32_t attr_id, void *attrp)
{
	int32_t status = PSVC_SUCCESS;

	switch (attr_id) {
	case PSVC_GPIO_VALUE_ATTR:
		return (i_psvc_get_device_value_10_1(hdlp, objp, attrp));
	case PSVC_GPIO_BITS:
		*(int32_t *)attrp = 8;
		return (status);
	}

	status = i_psvc_get_attr_generic(hdlp, objp, attr_id, attrp);

	return (status);
}

static int32_t
i_psvc_set_attr_10_1(EHdl_t *hdlp, EObj_t *objp, int32_t attr_id, void *attrp)
{
	int32_t status = PSVC_SUCCESS;

	if (attr_id == PSVC_GPIO_VALUE_ATTR) {
		return (i_psvc_set_device_value_10_1(hdlp, objp, attrp));
	}

	status = i_psvc_set_attr_generic(hdlp, objp, attr_id, attrp);

	return (status);
}

/* AT24 */
static int32_t
i_psvc_get_attr_11_0(EHdl_t *hdlp, EObj_t *objp, int32_t attr_id, void *attrp)
{
	int32_t status = PSVC_SUCCESS;
	int32_t probe_status;

	switch (attr_id) {
	case PSVC_PROBE_RESULT_ATTR:
		probe_status = i_psvc_probe_11_0(hdlp, objp);
		if (probe_status == PSVC_SUCCESS)
			strcpy((char *)attrp, PSVC_OK);
		else
			strcpy((char *)attrp, PSVC_ERROR);
		return (status);
	case PSVC_FRU_INFO_ATTR:
		status = i_psvc_get_reg_11_0(hdlp, objp, attr_id, attrp);
		return (status);
	}

	status = i_psvc_get_attr_generic(hdlp, objp, attr_id, attrp);

	return (status);
}

static int32_t
i_psvc_get_reg_11_0(EHdl_t *hdlp, EObj_t *objp, int32_t attr_id, void *attrp)
{
	int32_t status = PSVC_SUCCESS, ret;
	char path[1024], *data;
	int32_t fp, temp_errno;
	fru_info_t *fru_data;

	fru_data = (fru_info_t *)attrp;

	if (objp->present != PSVC_PRESENT) {
		errno = ENODEV;
		return (PSVC_FAILURE);
	}

	status = i_psvc_get_devpath(hdlp, objp->addr_spec, path);
	if (status != PSVC_SUCCESS)
		return (status);

	fp = open(path, O_RDWR);
	if (fp == -1) {
		return (PSVC_FAILURE);
	}

	ret = lseek(fp, fru_data->buf_start, SEEK_SET);
	if (ret != fru_data->buf_start) {
		temp_errno = errno;
		close(fp);
		errno = temp_errno;
		return (PSVC_FAILURE);
	}

	data = (char *)malloc(fru_data->read_size);
	ret = read(fp, data, fru_data->read_size);
	if (ret == -1) {
		free(data);
		close(fp);
		errno = EIO;
		return (-1);
	}

	memcpy(fru_data->buf, data, fru_data->read_size);
	free(data);
	close(fp);

	return (status);
}

static int32_t
i_psvc_get_attr_11_1(EHdl_t *hdlp, EObj_t *objp, int32_t attr_id, void *attrp)
{
	int32_t status = PSVC_SUCCESS;
	int32_t probe_status;

	if (attr_id == PSVC_PROBE_RESULT_ATTR) {
		probe_status = i_psvc_probe_11_1(hdlp, objp);
		if (probe_status == PSVC_SUCCESS)
			strcpy((char *)attrp, PSVC_OK);
		else
			strcpy((char *)attrp, PSVC_ERROR);
		return (status);
	}

	status = i_psvc_get_attr_generic(hdlp, objp, attr_id, attrp);

	return (status);
}

static int32_t
i_psvc_get_attr_11_2(EHdl_t *hdlp, EObj_t *objp, int32_t attr_id, void *attrp)
{
	int32_t status = PSVC_SUCCESS;
	int32_t probe_status;

	if (attr_id == PSVC_PROBE_RESULT_ATTR) {
		probe_status = i_psvc_probe_11_2(hdlp, objp);
		if (probe_status == PSVC_SUCCESS)
			strcpy((char *)attrp, PSVC_OK);
		else
			strcpy((char *)attrp, PSVC_ERROR);
		return (status);
	}

	status = i_psvc_get_attr_generic(hdlp, objp, attr_id, attrp);

	return (status);
}

static int32_t
i_psvc_get_attr_11_3(EHdl_t *hdlp, EObj_t *objp, int32_t attr_id, void *attrp)
{
	int32_t status = PSVC_SUCCESS;
	int32_t probe_status;

	if (attr_id == PSVC_PROBE_RESULT_ATTR) {
		probe_status = i_psvc_probe_11_3(hdlp, objp);
		if (probe_status == PSVC_SUCCESS)
			strcpy((char *)attrp, PSVC_OK);
		else
			strcpy((char *)attrp, PSVC_ERROR);
		return (status);
	}

	status = i_psvc_get_attr_generic(hdlp, objp, attr_id, attrp);

	return (status);
}

static int32_t
i_psvc_get_attr_11_4(EHdl_t *hdlp, EObj_t *objp, int32_t attr_id, void *attrp)
{
	int32_t status = PSVC_SUCCESS;
	int32_t probe_status;

	if (attr_id == PSVC_PROBE_RESULT_ATTR) {
		probe_status = i_psvc_probe_11_4(hdlp, objp);
		if (probe_status == PSVC_SUCCESS)
			strcpy((char *)attrp, PSVC_OK);
		else
			strcpy((char *)attrp, PSVC_ERROR);
		return (status);
	}

	status = i_psvc_get_attr_generic(hdlp, objp, attr_id, attrp);

	return (status);
}

static int32_t
i_psvc_get_attr_11_5(EHdl_t *hdlp, EObj_t *objp, int32_t attr_id, void *attrp)
{
	int32_t status = PSVC_SUCCESS;
	int32_t probe_status;

	if (attr_id == PSVC_PROBE_RESULT_ATTR) {
		probe_status = i_psvc_probe_11_5(hdlp, objp);
		if (probe_status == PSVC_SUCCESS)
			strcpy((char *)attrp, PSVC_OK);
		else
			strcpy((char *)attrp, PSVC_ERROR);
		return (status);
	}

	status = i_psvc_get_attr_generic(hdlp, objp, attr_id, attrp);

	return (status);
}

static int32_t
i_psvc_get_attr_11_6(EHdl_t *hdlp, EObj_t *objp, int32_t attr_id, void *attrp)
{
	int32_t status = PSVC_SUCCESS;
	int32_t probe_status;

	if (attr_id == PSVC_PROBE_RESULT_ATTR) {
		probe_status = i_psvc_probe_11_6(hdlp, objp);
		if (probe_status == PSVC_SUCCESS)
			strcpy((char *)attrp, PSVC_OK);
		else
			strcpy((char *)attrp, PSVC_ERROR);
		return (status);
	}

	status = i_psvc_get_attr_generic(hdlp, objp, attr_id, attrp);

	return (status);
}

static int32_t
i_psvc_get_attr_11_7(EHdl_t *hdlp, EObj_t *objp, int32_t attr_id, void *attrp)
{
	int32_t status = PSVC_SUCCESS;
	int32_t probe_status;

	if (attr_id == PSVC_PROBE_RESULT_ATTR) {
		probe_status = i_psvc_probe_11_7(hdlp, objp);
		if (probe_status == PSVC_SUCCESS)
			strcpy((char *)attrp, PSVC_OK);
		else
			strcpy((char *)attrp, PSVC_ERROR);
		return (status);
	}

	status = i_psvc_get_attr_generic(hdlp, objp, attr_id, attrp);

	return (status);
}

static int32_t
i_psvc_get_attr_11_8(EHdl_t *hdlp, EObj_t *objp, int32_t attr_id, void *attrp)
{
	int32_t status = PSVC_SUCCESS;
	int32_t probe_status;

	if (attr_id == PSVC_PROBE_RESULT_ATTR) {
		probe_status = i_psvc_probe_11_8(hdlp, objp);
		if (probe_status == PSVC_SUCCESS)
			strcpy((char *)attrp, PSVC_OK);
		else
			strcpy((char *)attrp, PSVC_ERROR);
		return (status);
	}

	status = i_psvc_get_attr_generic(hdlp, objp, attr_id, attrp);

	return (status);
}

static int32_t
i_psvc_get_attr_11_9(EHdl_t *hdlp, EObj_t *objp, int32_t attr_id, void *attrp)
{
	int32_t status = PSVC_SUCCESS;
	int32_t probe_status;

	if (attr_id == PSVC_PROBE_RESULT_ATTR) {
		probe_status = i_psvc_probe_11_9(hdlp, objp);
		if (probe_status == PSVC_SUCCESS)
			strcpy((char *)attrp, PSVC_OK);
		else
			strcpy((char *)attrp, PSVC_ERROR);
		return (status);
	}

	status = i_psvc_get_attr_generic(hdlp, objp, attr_id, attrp);

	return (status);
}

static int32_t
i_psvc_load_generic(
	EHdl_t	*hdlp,
	char	*name,
	EObj_t    **objpp,
	char	  *buf,
	int32_t   obj_size)
{
	int32_t found, key, array;
	EObj_t *objp;
	char *start;
	char  cur_device[NAMELEN];
	int slot;
	ETable_Array *tbl_arr;

	key = psvc_get_str_key(name);
	array = key % PSVC_MAX_TABLE_ARRAYS;
	tbl_arr = &(hdlp->tbl_arry[array]);

	if (tbl_arr->nextid == hdlp->total_obj_count) {
		errno = EINVAL;
		return (PSVC_FAILURE);
	} else {
		slot = tbl_arr->nextid++;
		tbl_arr->obj_count++;
	}

	if (i_psvc_find_file_section(hdlp->fp, "OBJECT_INFO") != PSVC_SUCCESS)
		return (PSVC_FAILURE);

	fgets(buf, BUFSZ, hdlp->fp);
	while (strcmp(buf, "OBJECT_INFO_END")) {
		start = strrchr(buf, '/');
		if (start == NULL) {
			errno = EINVAL;
			return (PSVC_FAILURE);
		}
		found = sscanf(start + 1, "%s",  cur_device);
		if (found != 1) {
			errno = EINVAL;
			return (PSVC_FAILURE);
		}
		if (strcmp(name, cur_device) == 0)  /* found it */
			break;
		fgets(buf, BUFSZ, hdlp->fp);
	}

	tbl_arr->obj_tbl[slot].objp = (EObj_t *)malloc(obj_size);
	if (tbl_arr->obj_tbl[slot].objp == 0)
		return (PSVC_FAILURE);
	objp = (EObj_t *)tbl_arr->obj_tbl[slot].objp;
	tbl_arr->obj_tbl[slot].type = PSVC_OBJ;

	memset(objp, 0, obj_size);
	strcpy(objp->label, name);
	strcpy(tbl_arr->obj_tbl[slot].name, name);

	tbl_arr->obj_tbl[slot].key = key;

	if (i_psvc_value(buf, PSVC_CLASS_ATTR, &objp->class) != PSVC_SUCCESS) {
		i_psvc_destructor(hdlp, name, objp);
		return (PSVC_FAILURE);
	}
	if (i_psvc_value(buf, PSVC_SUBCLASS_ATTR, &objp->subclass) !=
		PSVC_SUCCESS) {
		i_psvc_destructor(hdlp, name, objp);
		return (PSVC_FAILURE);
	}
	if (i_psvc_value(buf, PSVC_INSTANCE_ATTR, &objp->instance) !=
		PSVC_SUCCESS) {
		i_psvc_destructor(hdlp, name, objp);
		return (PSVC_FAILURE);
	}
	if (i_psvc_value(buf, PSVC_FEATURES_ATTR, &objp->features) !=
		PSVC_SUCCESS) {
		i_psvc_destructor(hdlp, name, objp);
		return (PSVC_FAILURE);
	}
	if (i_psvc_value(buf, PSVC_ADDR_SPEC_ATTR, &objp->addr_spec) !=
		PSVC_SUCCESS) {
		i_psvc_destructor(hdlp, name, objp);
		return (PSVC_FAILURE);
	}

	if (objp->features & PSVC_DEV_SECONDARY)
		objp->enabled = PSVC_DISABLED;
	else
		objp->enabled = PSVC_ENABLED;

	if (PSVC_GET_VERSION(objp->addr_spec) > PSVC_VERSION) {
		errno = EINVAL;
		i_psvc_destructor(hdlp, name, objp);
		return (PSVC_FAILURE);
	}

	*objpp = objp;
	return (PSVC_SUCCESS);

}


static int32_t
i_psvc_not_supported()
{
	errno = ENOTSUP;
	return (PSVC_FAILURE);
}

/* Temperature sensor */
/* Class 0 Subclass 0 are temperature sensors that cannot be updated */
static int32_t
i_psvc_constructor_0_0(
	EHdl_t	*hdlp,
	char	*id,
	EObj_t    **objpp)
{
	int32_t status;
	char buf[BUFSZ];
	ETempSensor_t *dp;

	status = i_psvc_load_generic(hdlp, id, objpp, buf,
		sizeof (ETempSensor_t));
	if (status != PSVC_SUCCESS)
		return (status);

	/* Load class specific info */
	dp = (ETempSensor_t *)*objpp;
	if (i_psvc_value(buf, PSVC_LO_WARN_ATTR, &dp->lo_warn)
	    != PSVC_SUCCESS) {
		i_psvc_destructor(hdlp, id, dp);
		return (PSVC_FAILURE);
	}
	if (i_psvc_value(buf, PSVC_LO_SHUT_ATTR, &dp->lo_shut)
	    != PSVC_SUCCESS) {
		i_psvc_destructor(hdlp, id, dp);
		return (PSVC_FAILURE);
	}
	if (i_psvc_value(buf, PSVC_HI_WARN_ATTR, &dp->hi_warn)
	    != PSVC_SUCCESS) {
		i_psvc_destructor(hdlp, id, dp);
		return (PSVC_FAILURE);
	}
	if (i_psvc_value(buf, PSVC_HI_SHUT_ATTR, &dp->hi_shut)
	    != PSVC_SUCCESS) {
		i_psvc_destructor(hdlp, id, dp);
		return (PSVC_FAILURE);
	}

	dp->ld.constructor = i_psvc_constructor_0_0;
	dp->ld.destructor = i_psvc_destructor;
	dp->ld.get_attr = i_psvc_get_attr_0_0;
	dp->ld.set_attr = i_psvc_set_attr_generic;

	return (0);
}

/* Class 0 Subclass 1 are temperature sensors that can be updated */
static int32_t
i_psvc_constructor_0_1(
	EHdl_t	*hdlp,
	char	*id,
	EObj_t    **objpp)
{
	int32_t status;
	char buf[BUFSZ];
	ETempSensor_t *dp;

	status = i_psvc_load_generic(hdlp, id, objpp, buf,
		sizeof (ETempSensor_t));
	if (status != PSVC_SUCCESS)
		return (status);

	/* Load class specific info */
	dp = (ETempSensor_t *)*objpp;
	if (i_psvc_value(buf, PSVC_LO_WARN_ATTR, &dp->lo_warn)
	    != PSVC_SUCCESS) {
		i_psvc_destructor(hdlp, id, dp);
		return (PSVC_FAILURE);
	}
	if (i_psvc_value(buf, PSVC_LO_SHUT_ATTR, &dp->lo_shut)
	    != PSVC_SUCCESS) {
		i_psvc_destructor(hdlp, id, dp);
		return (PSVC_FAILURE);
	}
	if (i_psvc_value(buf, PSVC_HI_WARN_ATTR, &dp->hi_warn)
	    != PSVC_SUCCESS) {
		i_psvc_destructor(hdlp, id, dp);
		return (PSVC_FAILURE);
	}
	if (i_psvc_value(buf, PSVC_HI_SHUT_ATTR, &dp->hi_shut)
	    != PSVC_SUCCESS) {
		i_psvc_destructor(hdlp, id, dp);
		return (PSVC_FAILURE);
	}

	if ((*objpp)->features & PSVC_OPT_TEMP) {
		if (i_psvc_value(buf, PSVC_OPTIMAL_TEMP_ATTR, &dp->opt_temp)
		    != PSVC_SUCCESS) {
			i_psvc_destructor(hdlp, id, dp);
			return (PSVC_FAILURE);
		}
	}
	if ((*objpp)->features & PSVC_HW_LOW_SHUT) {
		if (i_psvc_value(buf, PSVC_HW_LO_SHUT_ATTR, &dp->hw_lo_shut)
		    != PSVC_SUCCESS) {
			i_psvc_destructor(hdlp, id, dp);
			return (PSVC_FAILURE);
		}
	}
	if ((*objpp)->features & PSVC_HW_HIGH_SHUT) {
		if (i_psvc_value(buf, PSVC_HW_HI_SHUT_ATTR, &dp->hw_hi_shut)
		    != PSVC_SUCCESS) {
			i_psvc_destructor(hdlp, id, dp);
			return (PSVC_FAILURE);
		}
	}

	dp->ld.constructor = i_psvc_constructor_0_1;
	dp->ld.destructor = i_psvc_destructor;
	dp->ld.get_attr = i_psvc_get_attr_0_1;
	dp->ld.set_attr = i_psvc_set_attr_0_1;

	return (0);
}

/* Fan */
static int32_t
i_psvc_constructor_1_0(
	EHdl_t	*hdlp,
	char	*id,
	EObj_t  **objpp)
{
	int32_t status;
	char buf[BUFSZ];
	EFan_t *dp;

	status = i_psvc_load_generic(hdlp, id, objpp, buf,
		sizeof (EFan_t));
	if (status != PSVC_SUCCESS)
		return (status);

	/* Load class specific info */
	dp = (EFan_t *)*objpp;
	if (i_psvc_value(buf, PSVC_SETPOINT_ATTR, &dp->setpoint)
	    != PSVC_SUCCESS) {
		i_psvc_destructor(hdlp, id, dp);
		return (PSVC_FAILURE);
	}
	if (i_psvc_value(buf, PSVC_HYSTERESIS_ATTR, &dp->hysteresis)
	    != PSVC_SUCCESS) {
		i_psvc_destructor(hdlp, id, dp);
		return (PSVC_FAILURE);
	}
	if (i_psvc_value(buf, PSVC_LOOPGAIN_ATTR, &dp->loopgain)
	    != PSVC_SUCCESS) {
		i_psvc_destructor(hdlp, id, dp);
		return (PSVC_FAILURE);
	}
	if (i_psvc_value(buf, PSVC_LOOPBIAS_ATTR, &dp->loopbias)
	    != PSVC_SUCCESS) {
		i_psvc_destructor(hdlp, id, dp);
		return (PSVC_FAILURE);
	}

	dp->ld.constructor = i_psvc_constructor_1_0;
	dp->ld.destructor = i_psvc_destructor;
	dp->ld.get_attr = i_psvc_get_attr_1_0;
	dp->ld.set_attr = i_psvc_set_attr_1_0;

	return (PSVC_SUCCESS);
}


/* LED */
static int32_t
i_psvc_constructor_2_0(
	EHdl_t	*hdlp,
	char	*id,
	EObj_t  **objpp)
{
	int32_t status;
	char buf[BUFSZ];
	ELed_t *dp;

	status = i_psvc_load_generic(hdlp, id, objpp, buf,
		sizeof (ELed_t));
	if (status != PSVC_SUCCESS)
		return (status);

	/* Load class specific info */
	dp = (ELed_t *)*objpp;

	if (i_psvc_value(buf, PSVC_LED_COLOR_ATTR, dp->color)
	    != PSVC_SUCCESS) {
		i_psvc_destructor(hdlp, id, dp);
		return (PSVC_FAILURE);
	}

	dp->ld.constructor = i_psvc_constructor_2_0;
	dp->ld.destructor = i_psvc_destructor;
	dp->ld.get_attr = i_psvc_get_attr_2_0;
	dp->ld.set_attr = i_psvc_set_attr_2_0;

	return (PSVC_SUCCESS);
}

static int32_t
i_psvc_constructor_2_1(
	EHdl_t	*hdlp,
	char	*id,
	EObj_t  **objpp)
{
	int32_t status;
	char buf[BUFSZ];
	ELed_t *dp;

	status = i_psvc_load_generic(hdlp, id, objpp, buf,
		sizeof (ELed_t));
	if (status != PSVC_SUCCESS)
		return (status);

	/* Load class specific info */
	dp = (ELed_t *)*objpp;

	if (i_psvc_value(buf, PSVC_LED_COLOR_ATTR, dp->color)
	    != PSVC_SUCCESS) {
		i_psvc_destructor(hdlp, id, dp);
		return (PSVC_FAILURE);
	}

	dp->ld.constructor = i_psvc_constructor_2_1;
	dp->ld.destructor = i_psvc_destructor;
	dp->ld.get_attr = i_psvc_get_attr_2_1;
	dp->ld.set_attr = i_psvc_set_attr_2_1;

	return (PSVC_SUCCESS);
}

static int32_t
i_psvc_constructor_2_2(
	EHdl_t	*hdlp,
	char	*id,
	EObj_t  **objpp)
{
	int32_t status;
	char buf[BUFSZ];
	ELed_t *dp;

	status = i_psvc_load_generic(hdlp, id, objpp, buf,
		sizeof (ELed_t));
	if (status != PSVC_SUCCESS)
		return (status);

	/* Load class specific info */
	dp = (ELed_t *)*objpp;

	if (i_psvc_value(buf, PSVC_LED_COLOR_ATTR, dp->color)
	    != PSVC_SUCCESS) {
		i_psvc_destructor(hdlp, id, dp);
		return (PSVC_FAILURE);
	}
	if (i_psvc_value(buf, PSVC_LED_IS_LOCATOR_ATTR, dp->is_locator)
	    != PSVC_SUCCESS) {
		i_psvc_destructor(hdlp, id, dp);
		return (PSVC_FAILURE);
	}
	if (strcmp(dp->is_locator, PSVC_LOCATOR_TRUE) == 0) {
		if (i_psvc_value(buf, PSVC_LED_LOCATOR_NAME_ATTR,
		    dp->locator_name) != PSVC_SUCCESS) {
			i_psvc_destructor(hdlp, id, dp);
			return (PSVC_FAILURE);
		}
	} else {
		strcpy(dp->locator_name, "N/A");
	}

	dp->ld.constructor = i_psvc_constructor_2_2;
	dp->ld.destructor = i_psvc_destructor;
	dp->ld.get_attr = i_psvc_get_attr_2_2;
	dp->ld.set_attr = i_psvc_set_attr_2_0;

	return (PSVC_SUCCESS);
}

/* System Device */
static int32_t
i_psvc_constructor_3_0(
	EHdl_t	*hdlp,
	char	*id,
	EObj_t  **objpp)
{
	int32_t status;
	char buf[BUFSZ];
	ESystem_t *dp;

	status = i_psvc_load_generic(hdlp, id, objpp, buf, sizeof (ESystem_t));
	if (status != PSVC_SUCCESS)
		return (status);

	/* Load class specific info */
	dp = (ESystem_t *)*objpp;

	dp->ld.constructor = i_psvc_constructor_3_0;
	dp->ld.destructor = i_psvc_destructor;
	dp->ld.get_attr = i_psvc_get_attr_generic;
	dp->ld.set_attr = i_psvc_set_attr_generic;

	return (PSVC_SUCCESS);
}

/* Digital Sensor */
static int32_t
i_psvc_constructor_4_0(
	EHdl_t	*hdlp,
	char	*id,
	EObj_t  **objpp)
{
	int32_t status;
	char buf[BUFSZ];
	EDigiSensor_t *dp;

	status = i_psvc_load_generic(hdlp, id, objpp, buf,
		sizeof (EDigiSensor_t));
	if (status != PSVC_SUCCESS) {
		return (status);
	}

	/* Load class specific info */
	dp = (EDigiSensor_t *)*objpp;
	if (i_psvc_value(buf, PSVC_LO_WARN_ATTR, &dp->lo_warn)
	    != PSVC_SUCCESS) {
		i_psvc_destructor(hdlp, id, dp);
		return (PSVC_FAILURE);
	}
	if (i_psvc_value(buf, PSVC_LO_SHUT_ATTR, &dp->lo_shut)
	    != PSVC_SUCCESS) {
		i_psvc_destructor(hdlp, id, dp);
		return (PSVC_FAILURE);
	}
	if (i_psvc_value(buf, PSVC_HI_WARN_ATTR, &dp->hi_warn)
	    != PSVC_SUCCESS) {
		i_psvc_destructor(hdlp, id, dp);
		return (PSVC_FAILURE);
	}
	if (i_psvc_value(buf, PSVC_HI_SHUT_ATTR, &dp->hi_shut)
	    != PSVC_SUCCESS) {
		i_psvc_destructor(hdlp, id, dp);
		return (PSVC_FAILURE);
	}

	dp->ld.constructor = i_psvc_constructor_4_0;
	dp->ld.destructor = i_psvc_destructor;
	dp->ld.get_attr = i_psvc_get_attr_4_0;
	dp->ld.set_attr = i_psvc_set_attr_generic;

	return (PSVC_SUCCESS);
}

/* Digital Control */
static int32_t
i_psvc_constructor_5_0(
	EHdl_t	*hdlp,
	char	*id,
	EObj_t  **objpp)
{
	int32_t status;
	char buf[BUFSZ];
	EDigiControl_t *dp;

	status = i_psvc_load_generic(hdlp, id, objpp, buf,
		sizeof (EDigiControl_t));
	if (status != PSVC_SUCCESS)
		return (status);

	/* Load class specific info */
	dp = (EDigiControl_t *)*objpp;

	dp->ld.constructor = i_psvc_constructor_5_0;
	dp->ld.destructor = i_psvc_destructor;
	dp->ld.get_attr = i_psvc_get_attr_5_0;
	dp->ld.set_attr = i_psvc_set_attr_5_0;
	return (PSVC_SUCCESS);
}

/* Boolean GPIO */
static int32_t
i_psvc_constructor_6_0(
	EHdl_t	*hdlp,
	char	*id,
	EObj_t  **objpp)
{
	int32_t status;
	char buf[BUFSZ];
	EBoolSensor_t *dp;

	status = i_psvc_load_generic(hdlp, id, objpp, buf,
		sizeof (EBoolSensor_t));
	if (status != PSVC_SUCCESS)
		return (status);

	/* Load class specific info */
	dp = (EBoolSensor_t *)*objpp;

	dp->ld.constructor = i_psvc_constructor_6_0;
	dp->ld.destructor = i_psvc_destructor;
	dp->ld.get_attr = i_psvc_get_attr_6_0;
	dp->ld.set_attr = i_psvc_set_attr_6_0;

	return (PSVC_SUCCESS);
}

/* Fan Tachometer */
static int32_t
i_psvc_constructor_7_0(
	EHdl_t	*hdlp,
	char	*id,
	EObj_t  **objpp)
{
	int32_t status;
	char buf[BUFSZ];
	EFanTach_t *dp;

	status = i_psvc_load_generic(hdlp, id, objpp, buf,
		sizeof (EFanTach_t));
	if (status != PSVC_SUCCESS)
		return (status);

	/* Load class specific info */
	dp = (EFanTach_t *)*objpp;
	if (i_psvc_value(buf, PSVC_LO_WARN_ATTR, &dp->lo_warn)
	    != PSVC_SUCCESS) {
		i_psvc_destructor(hdlp, id, dp);
		return (PSVC_FAILURE);
	}
	if (i_psvc_value(buf, PSVC_LO_SHUT_ATTR, &dp->lo_shut)
	    != PSVC_SUCCESS) {
		i_psvc_destructor(hdlp, id, dp);
		return (PSVC_FAILURE);
	}
	if (i_psvc_value(buf, PSVC_HI_WARN_ATTR, &dp->hi_warn)
	    != PSVC_SUCCESS) {
		i_psvc_destructor(hdlp, id, dp);
		return (PSVC_FAILURE);
	}
	if (i_psvc_value(buf, PSVC_HI_SHUT_ATTR, &dp->hi_shut)
	    != PSVC_SUCCESS) {
		i_psvc_destructor(hdlp, id, dp);
		return (PSVC_FAILURE);
	}

	dp->ld.constructor = i_psvc_constructor_7_0;
	dp->ld.destructor = i_psvc_destructor;
	dp->ld.get_attr = i_psvc_get_attr_7_0;
	dp->ld.set_attr = i_psvc_set_attr_generic;

	return (PSVC_SUCCESS);
}

/* On Off Switch */
static int32_t
i_psvc_constructor_8_0(
	EHdl_t	*hdlp,
	char	*id,
	EObj_t  **objpp)
{
	int32_t status;
	char buf[BUFSZ];
	ESwitch_t *dp;

	status = i_psvc_load_generic(hdlp, id, objpp, buf,
		sizeof (ESwitch_t));
	if (status != PSVC_SUCCESS)
		return (status);

	/* Load class specific info */
	dp = (ESwitch_t *)*objpp;

	dp->ld.constructor = i_psvc_constructor_8_0;
	dp->ld.destructor = i_psvc_destructor;
	dp->ld.get_attr = i_psvc_get_attr_8_0;
	dp->ld.set_attr = i_psvc_set_attr_8_0;

	return (PSVC_SUCCESS);
}

/* Key Switch */
static int32_t
i_psvc_constructor_9_0(
	EHdl_t	*hdlp,
	char	*id,
	EObj_t  **objpp)
{
	int32_t status;
	char buf[BUFSZ];
	EKeySwitch_t *dp;

	status = i_psvc_load_generic(hdlp, id, objpp, buf,
		sizeof (EKeySwitch_t));
	if (status != PSVC_SUCCESS)
		return (status);

	/* Load class specific info */
	dp = (EKeySwitch_t *)*objpp;

	dp->ld.constructor = i_psvc_constructor_9_0;
	dp->ld.destructor = i_psvc_destructor;
	dp->ld.get_attr = i_psvc_get_attr_9_0;
	dp->ld.set_attr = i_psvc_set_attr_generic;

	return (PSVC_SUCCESS);
}

/* 8 Bit GPIO , devices with registers, calls get_reg()/set_reg() */
static int32_t
i_psvc_constructor_10_0(
	EHdl_t	*hdlp,
	char	*id,
	EObj_t  **objpp)
{
	int32_t status;
	char buf[BUFSZ];
	EGPIO8_t *dp;

	status = i_psvc_load_generic(hdlp, id, objpp, buf, sizeof (EGPIO8_t));
	if (status != PSVC_SUCCESS)
		return (status);

	/* Load class specific info */
	dp = (EGPIO8_t *)*objpp;

	dp->ld.constructor = i_psvc_constructor_10_0;
	dp->ld.destructor = i_psvc_destructor;
	dp->ld.get_attr = i_psvc_get_attr_10_0;
	dp->ld.set_attr = i_psvc_set_attr_10_0;

	return (PSVC_SUCCESS);
}

/* 8 Bit GPIO , devices with ports, calls get_port()/set_port() */
static int32_t
i_psvc_constructor_10_1(
	EHdl_t	*hdlp,
	char	*id,
	EObj_t  **objpp)
{
	int32_t status;
	char buf[BUFSZ];
	EGPIO8_t *dp;

	status = i_psvc_load_generic(hdlp, id, objpp, buf, sizeof (EGPIO8_t));
	if (status != PSVC_SUCCESS)
		return (status);

	/* Load class specific info */
	dp = (EGPIO8_t *)*objpp;

	dp->ld.constructor = i_psvc_constructor_10_1;
	dp->ld.destructor = i_psvc_destructor;
	dp->ld.get_attr = i_psvc_get_attr_10_1;
	dp->ld.set_attr = i_psvc_set_attr_10_1;

	return (PSVC_SUCCESS);
}

/* AT24 */
static int32_t
i_psvc_constructor_11_0(
	EHdl_t	*hdlp,
	char	*id,
	EObj_t  **objpp)
{
	int32_t status;
	char buf[BUFSZ];
	EPhysDev_t *dp;

	status = i_psvc_load_generic(hdlp, id, objpp, buf,
		sizeof (EPhysDev_t));
	if (status != PSVC_SUCCESS)
		return (status);

	/* Load class specific info */
	dp = (EPhysDev_t *)*objpp;

	dp->ld.constructor = i_psvc_constructor_11_0;
	dp->ld.destructor = i_psvc_destructor;
	dp->ld.get_attr = i_psvc_get_attr_11_0;
	dp->ld.set_attr = i_psvc_set_attr_generic;
	dp->get_temperature = i_psvc_not_supported;
	dp->get_fanspeed = i_psvc_not_supported;
	dp->get_input = i_psvc_not_supported;
	dp->get_bit = i_psvc_not_supported;
	dp->set_bit = i_psvc_not_supported;
	dp->get_port = i_psvc_not_supported;
	dp->set_port = i_psvc_not_supported;
	dp->get_output = i_psvc_not_supported;
	dp->set_output = i_psvc_not_supported;
	dp->get_reg = i_psvc_get_reg_11_0;
	dp->set_reg = i_psvc_not_supported;

	return (PSVC_SUCCESS);
}

/* HPC3130 */
static int32_t
i_psvc_constructor_11_1(
	EHdl_t	*hdlp,
	char	*id,
	EObj_t  **objpp)
{
	int32_t status;
	char buf[BUFSZ];
	EPhysDev_t *dp;

	status = i_psvc_load_generic(hdlp, id, objpp, buf, sizeof (EPhysDev_t));
	if (status != PSVC_SUCCESS)
		return (status);

	/* Load class specific info */
	dp = (EPhysDev_t *)*objpp;

	dp->ld.constructor = i_psvc_constructor_11_1;
	dp->ld.destructor = i_psvc_destructor;
	dp->ld.get_attr = i_psvc_get_attr_11_1;
	dp->ld.set_attr = i_psvc_set_attr_generic;
	dp->get_temperature = i_psvc_not_supported;
	dp->get_fanspeed = i_psvc_not_supported;
	dp->get_input = i_psvc_not_supported;
	dp->get_bit = i_psvc_not_supported;
	dp->set_bit = i_psvc_not_supported;
	dp->get_port = i_psvc_not_supported;
	dp->set_port = i_psvc_not_supported;
	dp->get_output = i_psvc_not_supported;
	dp->set_output = i_psvc_not_supported;
	dp->get_reg = i_psvc_get_reg_11_1;
	dp->set_reg = i_psvc_set_reg_11_1;

	return (PSVC_SUCCESS);
}

/* LM75 */
static int32_t
i_psvc_constructor_11_2(
	EHdl_t	*hdlp,
	char	*id,
	EObj_t  **objpp)
{
	int32_t status;
	char buf[BUFSZ];
	EPhysDev_t *dp;

	status = i_psvc_load_generic(hdlp, id, objpp, buf, sizeof (EPhysDev_t));
	if (status != PSVC_SUCCESS)
		return (status);

	/* Load class specific info */
	dp = (EPhysDev_t *)*objpp;

	dp->ld.constructor = i_psvc_constructor_11_2;
	dp->ld.destructor = i_psvc_destructor;
	dp->ld.get_attr = i_psvc_get_attr_11_2;
	dp->ld.set_attr = i_psvc_set_attr_generic;
	dp->get_temperature = i_psvc_get_temperature_11_2;
	dp->get_fanspeed = i_psvc_not_supported;
	dp->get_input = i_psvc_not_supported;
	dp->get_bit = i_psvc_not_supported;
	dp->set_bit = i_psvc_not_supported;
	dp->get_port = i_psvc_not_supported;
	dp->set_port = i_psvc_not_supported;
	dp->get_output = i_psvc_not_supported;
	dp->set_output = i_psvc_not_supported;
	dp->get_reg = i_psvc_not_supported;
	dp->set_reg = i_psvc_not_supported;

	return (PSVC_SUCCESS);
}

/* LTC1427 */
static int32_t
i_psvc_constructor_11_3(
	EHdl_t	*hdlp,
	char	*id,
	EObj_t  **objpp)
{
	int32_t status;
	char buf[BUFSZ];
	EPhysDev_t *dp;
	char path[1024];

	status = i_psvc_load_generic(hdlp, id, objpp, buf, sizeof (EPhysDev_t));
	if (status != PSVC_SUCCESS)
		return (status);

	/*
	 * The following code upto and including the open() call is so the
	 * device driver for the ltc1427 does not get unloaded by the OS at
	 * any time. This is important as the device driver is a write only
	 * physical device but DOES keep readable states in the device unitp
	 * structure (I2C_GET_OUTPUT) as a result this device should not
	 * be unload while PSVC is up and running
	 */
	status = i_psvc_get_devpath(hdlp, (*objpp)->addr_spec, path);
	if (status != PSVC_SUCCESS) {
		return (status);
	}

	/*
	 * We deliberately do not close our file handle, to prevent
	 * any device instances from being detached.  If an instance
	 * is detached, the "readable states in the device unitp"
	 * will be unloaded, causing loss of control of the device
	 * and incorrect error(s) to be displayed.
	 */
	if (open(path, O_RDWR) == -1) {
		return (PSVC_FAILURE);
	}
	/* Load class specific info */
	dp = (EPhysDev_t *)*objpp;

	dp->ld.constructor = i_psvc_constructor_11_3;
	dp->ld.destructor = i_psvc_destructor;
	dp->ld.get_attr = i_psvc_get_attr_11_3;
	dp->ld.set_attr = i_psvc_set_attr_generic;
	dp->get_temperature = i_psvc_not_supported;
	dp->get_fanspeed = i_psvc_not_supported;
	dp->get_input = i_psvc_not_supported;
	dp->get_bit = i_psvc_not_supported;
	dp->set_bit = i_psvc_not_supported;
	dp->get_port = i_psvc_not_supported;
	dp->set_port = i_psvc_not_supported;
	dp->get_output = i_psvc_get_output_11_3;
	dp->set_output = i_psvc_set_output_11_3;
	dp->get_reg = i_psvc_not_supported;
	dp->set_reg = i_psvc_not_supported;

	return (PSVC_SUCCESS);
}

/* MAX1617 */
static int32_t
i_psvc_constructor_11_4(
	EHdl_t	*hdlp,
	char	*id,
	EObj_t  **objpp)
{
	int32_t status;
	char buf[BUFSZ];
	EPhysDev_t *dp;

	status = i_psvc_load_generic(hdlp, id, objpp, buf, sizeof (EPhysDev_t));
	if (status != PSVC_SUCCESS)
		return (status);

	/* Load class specific info */
	dp = (EPhysDev_t *)*objpp;

	dp->ld.constructor = i_psvc_constructor_11_4;
	dp->ld.destructor = i_psvc_destructor;
	dp->ld.get_attr = i_psvc_get_attr_11_4;
	dp->ld.set_attr = i_psvc_set_attr_generic;
	dp->get_temperature = i_psvc_get_temperature_11_4;
	dp->get_fanspeed = i_psvc_not_supported;
	dp->get_input = i_psvc_not_supported;
	dp->get_bit = i_psvc_not_supported;
	dp->set_bit = i_psvc_not_supported;
	dp->get_port = i_psvc_not_supported;
	dp->set_port = i_psvc_not_supported;
	dp->get_output = i_psvc_not_supported;
	dp->set_output = i_psvc_not_supported;
	dp->get_reg = i_psvc_not_supported;
	dp->set_reg = i_psvc_not_supported;

	return (PSVC_SUCCESS);
}

/* PCF8574 */
static int32_t
i_psvc_constructor_11_5(
	EHdl_t	*hdlp,
	char	*id,
	EObj_t  **objpp)
{
	int32_t status;
	char buf[BUFSZ];
	EPhysDev_t *dp;

	status = i_psvc_load_generic(hdlp, id, objpp, buf, sizeof (EPhysDev_t));
	if (status != PSVC_SUCCESS)
		return (status);

	/* Load class specific info */
	dp = (EPhysDev_t *)*objpp;

	dp->ld.constructor = i_psvc_constructor_11_5;
	dp->ld.destructor = i_psvc_destructor;
	dp->ld.get_attr = i_psvc_get_attr_11_5;
	dp->ld.set_attr = i_psvc_set_attr_generic;
	dp->get_temperature = i_psvc_not_supported;
	dp->get_fanspeed = i_psvc_not_supported;
	dp->get_input = i_psvc_not_supported;
	dp->get_bit = i_psvc_get_bit_11_5;
	dp->set_bit = i_psvc_set_bit_11_5;
	dp->get_port = i_psvc_get_port_11_5;
	dp->set_port = i_psvc_set_port_11_5;
	dp->get_output = i_psvc_not_supported;
	dp->set_output = i_psvc_not_supported;
	dp->get_reg = i_psvc_not_supported;
	dp->set_reg = i_psvc_not_supported;

	return (PSVC_SUCCESS);
}

/* PCF8591 */
static int32_t
i_psvc_constructor_11_6(
	EHdl_t	*hdlp,
	char	*id,
	EObj_t  **objpp)
{
	int32_t status;
	char buf[BUFSZ];
	EPhysDev_t *dp;

	status = i_psvc_load_generic(hdlp, id, objpp, buf, sizeof (EPhysDev_t));
	if (status != PSVC_SUCCESS)
		return (status);

	/* Load class specific info */
	dp = (EPhysDev_t *)*objpp;

	dp->ld.constructor = i_psvc_constructor_11_6;
	dp->ld.destructor = i_psvc_destructor;
	dp->ld.get_attr = i_psvc_get_attr_11_6;
	dp->ld.set_attr = i_psvc_set_attr_generic;
	dp->get_temperature = i_psvc_get_temperature_11_6;
	dp->get_fanspeed = i_psvc_not_supported;
	dp->get_input = i_psvc_get_input_11_6;
	dp->get_bit = i_psvc_not_supported;
	dp->set_bit = i_psvc_not_supported;
	dp->get_port = i_psvc_not_supported;
	dp->set_port = i_psvc_not_supported;
	dp->get_output = i_psvc_get_output_11_6;
	dp->set_output = i_psvc_set_output_11_6;
	dp->get_reg = i_psvc_not_supported;
	dp->set_reg = i_psvc_not_supported;

	return (PSVC_SUCCESS);
}

/* SSC050 */
static int32_t
i_psvc_constructor_11_7(
	EHdl_t	*hdlp,
	char	*id,
	EObj_t  **objpp)
{
	int32_t status;
	char buf[BUFSZ];
	EPhysDev_t *dp;

	status = i_psvc_load_generic(hdlp, id, objpp, buf, sizeof (EPhysDev_t));
	if (status != PSVC_SUCCESS)
		return (status);

	/* Load class specific info */
	dp = (EPhysDev_t *)*objpp;

	dp->ld.constructor = i_psvc_constructor_11_7;
	dp->ld.destructor = i_psvc_destructor;
	dp->ld.get_attr = i_psvc_get_attr_11_7;
	dp->ld.set_attr = i_psvc_set_attr_generic;
	dp->get_temperature = i_psvc_not_supported;
	dp->get_fanspeed = i_psvc_get_fanspeed_11_7;
	dp->get_input = i_psvc_not_supported;
	dp->get_bit = i_psvc_get_bit_11_7;
	dp->set_bit = i_psvc_set_bit_11_7;
	dp->get_port = i_psvc_get_port_11_5;	/* same as for class = 11, 5 */
	dp->set_port = i_psvc_set_port_11_5;
	dp->get_output = i_psvc_not_supported;
	dp->set_output = i_psvc_not_supported;
	dp->get_reg = i_psvc_get_reg_11_7;
	dp->set_reg = i_psvc_set_reg_11_7;

	return (PSVC_SUCCESS);
}

/* TDA8444 */
static int32_t
i_psvc_constructor_11_8(
	EHdl_t	*hdlp,
	char	*id,
	EObj_t  **objpp)
{
	int32_t status;
	char buf[BUFSZ];
	EPhysDev_t *dp;

	status = i_psvc_load_generic(hdlp, id, objpp, buf, sizeof (EPhysDev_t));
	if (status != PSVC_SUCCESS)
		return (status);

	/* Load class specific info */
	dp = (EPhysDev_t *)*objpp;

	dp->ld.constructor = i_psvc_constructor_11_8;
	dp->ld.destructor = i_psvc_destructor;
	dp->ld.get_attr = i_psvc_get_attr_11_8;
	dp->ld.set_attr = i_psvc_set_attr_generic;
	dp->get_temperature = i_psvc_not_supported;
	dp->get_fanspeed = i_psvc_not_supported;
	dp->get_input = i_psvc_not_supported;
	dp->get_bit = i_psvc_not_supported;
	dp->set_bit = i_psvc_not_supported;
	dp->get_port = i_psvc_not_supported;
	dp->set_port = i_psvc_not_supported;
	dp->get_output = i_psvc_get_output_11_8;
	dp->set_output = i_psvc_set_output_11_8;
	dp->get_reg = i_psvc_not_supported;
	dp->set_reg = i_psvc_not_supported;

	return (PSVC_SUCCESS);
}

/* SSC100 */
static int32_t
i_psvc_constructor_11_9(
	EHdl_t	*hdlp,
	char	*id,
	EObj_t  **objpp)
{
	int32_t status;
	char buf[BUFSZ];
	EPhysDev_t *dp;

	status = i_psvc_load_generic(hdlp, id, objpp, buf, sizeof (EPhysDev_t));
	if (status != PSVC_SUCCESS)
		return (status);

	/* Load class specific info */
	dp = (EPhysDev_t *)*objpp;

	dp->ld.constructor = i_psvc_constructor_11_9;
	dp->ld.destructor = i_psvc_destructor;
	dp->ld.get_attr = i_psvc_get_attr_11_9;
	dp->ld.set_attr = i_psvc_set_attr_generic;
	dp->get_temperature = i_psvc_not_supported;
	dp->get_fanspeed = i_psvc_not_supported;
	dp->get_input = i_psvc_not_supported;
	dp->get_bit = i_psvc_not_supported;
	dp->set_bit = i_psvc_not_supported;
	dp->get_port = i_psvc_get_port_11_5;	/* Same as for class = 11, 5 */
	dp->set_port = i_psvc_set_port_11_5;
	dp->get_output = i_psvc_not_supported;
	dp->set_output = i_psvc_not_supported;
	dp->get_reg = i_psvc_not_supported;
	dp->set_reg = i_psvc_not_supported;

	return (PSVC_SUCCESS);
}

int32_t
psvc_init(EHdl_t **hdlpp)
{
	EHdl_t *hdlp;
	int    i;
	char   buf[BUFSZ];
	char   platform[32];
	char   filename[256];
	int    found;
	int32_t status;
	pthread_mutexattr_t mutex_attr;
	uint32_t table_count;
	int	forward_slash = 47;
	int	new_line = 10;
	char	*nl_char;

	hdlp = (EHdl_t *)malloc(sizeof (EHdl_t));
	if (hdlp == NULL)
		return (-1);
	memset(hdlp, 0, sizeof (EHdl_t));

	/* Initialize the lock */
	status = pthread_mutexattr_init(&mutex_attr);
	if (status != 0) {
		errno = status;
		return (-1);
	}
	status = pthread_mutex_init(&hdlp->mutex, &mutex_attr);
	if (status != 0) {
		errno = status;
		return (-1);
	}
	pthread_mutexattr_destroy(&mutex_attr);

	if (sysinfo(SI_PLATFORM, platform, sizeof (platform)) == -1) {
		return (-1);
	}

	snprintf(filename, sizeof (filename),
	    "/usr/platform/%s/lib/psvcobj.conf", platform);
	if ((hdlp->fp = fopen(filename, "r")) == NULL) {
		return (-1);
	}


	/* Build the association ID lookup table */

	hdlp->othr_count = hdlp->assoc_count = ASSOC_STR_TAB_SIZE;
	if ((hdlp->othr_tbl = (EStringId_t *)malloc(sizeof (EStringId_t) *
		hdlp->othr_count)) == NULL) {
		return (-1);
	}

	for (i = 0; i < hdlp->othr_count; ++i) {
		hdlp->othr_tbl[i].id = i;
		strcpy(hdlp->othr_tbl[i].name, assoc_str_tab[i]);
	}
	qsort(hdlp->othr_tbl, hdlp->othr_count, sizeof (EStringId_t),
		(int (*)(const void *, const void *))i_psvc_name_compare_qsort);

	/* determine total number of objects + tables */
	if (i_psvc_find_file_section(hdlp->fp, "OBJECT_INFO") == -1) {
		return (-1);
	}
	if (i_psvc_count_records(hdlp->fp, "OBJECT_INFO_END",
		&hdlp->total_obj_count) == -1) {
		return (-1);
	}
	if (i_psvc_find_file_section(hdlp->fp, "TABLES") == PSVC_SUCCESS) {
		status = i_psvc_count_tables_associations(hdlp->fp,
			&table_count, "TABLE_END");
		if (status == PSVC_FAILURE) {
			return (status);
		}
		hdlp->total_obj_count += table_count;
	}

	/* Allocate object name to object pointer translation table */
	for (i = 0; i < PSVC_MAX_TABLE_ARRAYS; i++) {
		if ((hdlp->tbl_arry[i].obj_tbl =
			(ENamePtr_t *)malloc(
		sizeof (ENamePtr_t) *hdlp->total_obj_count)) == NULL) {
			return (-1);
		}
		memset(hdlp->tbl_arry[i].obj_tbl, 0,
		    sizeof (ENamePtr_t) * hdlp->total_obj_count);
		hdlp->tbl_arry[i].obj_count = 0;
	}

	/* Build the association table */
	if (i_psvc_load_associations(hdlp, hdlp->fp) == -1)
		return (-1);

	/* Build the table of device paths */
	if (i_psvc_find_file_section(hdlp->fp, "DEVPATHS") == -1)
		return (-1);
	if (i_psvc_count_records(hdlp->fp, "DEVPATHS_END",
		&hdlp->dev_count) == -1)
		return (-1);
	if ((hdlp->dev_tbl = (EDevice_t *)malloc(sizeof (EDevice_t) *
		hdlp->dev_count)) == NULL) {
		return (-1);
	}
	for (i = 0; i < hdlp->dev_count; ++i) {
		fgets(buf, BUFSZ, hdlp->fp);
		found = sscanf(buf, "%d %d %x %d",
			&hdlp->dev_tbl[i].controller,
			&hdlp->dev_tbl[i].bus, &hdlp->dev_tbl[i].addr,
			&hdlp->dev_tbl[i].port);
		if (found != 4) {
			errno = EINVAL;
			return (-1);
		}
		strcpy(hdlp->dev_tbl[i].path, strchr(buf, forward_slash));
		/*
		 * Replace new line character with NUL character
		 */
		nl_char = strchr(hdlp->dev_tbl[i].path, new_line);
		*nl_char = 0;
	}

	/* Build the table of tables */
	if (i_psvc_load_tables(hdlp, hdlp->fp) == -1)
		return (-1);
	*hdlpp = hdlp;
	return (0);
}

int32_t
psvc_fini(EHdl_t *hdlp)
{
	int32_t i, j;
	ETable_Array *array;

	if (hdlp == 0)
		return (PSVC_SUCCESS);

	for (j = 0; j < PSVC_MAX_TABLE_ARRAYS; j++) {
		if (hdlp->tbl_arry[j].obj_tbl != 0) {
			array = &(hdlp->tbl_arry[j]);
			for (i = 0; i < array->obj_count; ++i) {
				if (array->obj_tbl[i].type == PSVC_OBJ) {
					if (!array->obj_tbl[i].objp) {
						/* Skip non-existent object */
						continue;
					}
					array->obj_tbl[i].objp->destructor(hdlp,
					    array->obj_tbl[i].objp->label,
					    array->obj_tbl[i].objp);
				}

				if (array->obj_tbl[i].type == PSVC_TBL) {
					ETable_t *tblp =
					    (ETable_t *)array->obj_tbl[i].objp;
					if (tblp->table != 0)
						free(tblp->table);
				}
			}

			free(array->obj_tbl);
		}
	}

	if (hdlp->othr_tbl != 0)
		free(hdlp->othr_tbl);

	if (hdlp->assoc_tbl != 0) {
		for (i = 0; i < hdlp->assoc_count; ++i) {
			if (hdlp->assoc_tbl[i].table != 0)
				free(hdlp->assoc_tbl[i].table);
		}
		free(hdlp->assoc_tbl);
	}

	if (hdlp->dev_tbl != 0)
		free(hdlp->dev_tbl);
	if (hdlp->fp != 0)
		fclose(hdlp->fp);
	pthread_mutex_destroy(&hdlp->mutex);
	free(hdlp);
	return (PSVC_SUCCESS);
}

int32_t
ioctl_retry(int fp, int request, void * arg_pointer)
{
	int32_t ret = PSVC_SUCCESS;
	int32_t tries = 0;

	/*
	 * Becuase the i2c bus is a multimaster bus we need to protect
	 * ourselves from bus masters that are not being good bus citizens.
	 * A retry number of 10 should be sufficient to handle any bad bus
	 * citizens.  After that we will simply say that there is something
	 * wrong with the ioctl transaction and let it bubble back up.
	 */
	do {
		ret = ioctl(fp, request, arg_pointer);
		tries ++;
	} while ((ret == -1) && (tries < 10));

	return (ret);
}

static int32_t
psvc_get_str_key(char *object)
{
	int32_t key = 0;
	int i, length;

	length = strlen(object);
	for (i = 0; i < length; i++) {
		if ((object[i] > 47) && (object[i] < 58)) {
			key = key + ((object[i] - 50) + 2);
		} else {
			key = key + object[i];
		}
	}


	return (key);
}
