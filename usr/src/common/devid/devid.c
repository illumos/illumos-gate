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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 2018, Joyent, Inc.
 */

#include <sys/types.h>
#include <sys/stropts.h>
#include <sys/debug.h>
#include <sys/isa_defs.h>
#include <sys/dditypes.h>
#include <sys/ddi_impldefs.h>
#include "devid_impl.h"

static int devid_str_decode_id(char *devidstr, ddi_devid_t *devidp,
    char **minor_namep, impl_devid_t *id);


/*
 * Validate device id.
 */
int
#ifdef	_KERNEL
ddi_devid_valid(ddi_devid_t devid)
#else	/* !_KERNEL */
devid_valid(ddi_devid_t devid)
#endif	/* _KERNEL */
{
	impl_devid_t	*id = (impl_devid_t *)devid;
	ushort_t	type;

	DEVID_ASSERT(devid != NULL);

	if (id->did_magic_hi != DEVID_MAGIC_MSB)
		return (DEVID_RET_INVALID);

	if (id->did_magic_lo != DEVID_MAGIC_LSB)
		return (DEVID_RET_INVALID);

	if (id->did_rev_hi != DEVID_REV_MSB)
		return (DEVID_RET_INVALID);

	if (id->did_rev_lo != DEVID_REV_LSB)
		return (DEVID_RET_INVALID);

	type = DEVID_GETTYPE(id);
	if ((type == DEVID_NONE) || (type > DEVID_MAXTYPE))
		return (DEVID_RET_INVALID);

	return (DEVID_RET_VALID);
}

/*
 * Return the sizeof a device id. If called with NULL devid it returns
 * the amount of space needed to determine the size.
 */
size_t
#ifdef	_KERNEL
ddi_devid_sizeof(ddi_devid_t devid)
#else	/* !_KERNEL */
devid_sizeof(ddi_devid_t devid)
#endif	/* _KERNEL */
{
	impl_devid_t	*id = (impl_devid_t *)devid;

	if (id == NULL)
		return (sizeof (*id) - sizeof (id->did_id));

	DEVID_ASSERT(DEVID_FUNC(devid_valid)(devid) == DEVID_RET_VALID);

	return (sizeof (*id) + DEVID_GETLEN(id) - sizeof (id->did_id));
}

/*
 * Compare two device id's.
 *	-1 - less than
 *	0  - equal
 * 	1  - greater than
 */
int
#ifdef	_KERNEL
ddi_devid_compare(ddi_devid_t id1, ddi_devid_t id2)
#else	/* !_KERNEL */
devid_compare(ddi_devid_t id1, ddi_devid_t id2)
#endif	/* _KERNEL */
{
	int		rval;
	impl_devid_t	*i_id1	= (impl_devid_t *)id1;
	impl_devid_t	*i_id2	= (impl_devid_t *)id2;
	ushort_t	i_id1_type;
	ushort_t	i_id2_type;

	DEVID_ASSERT((id1 != NULL) && (id2 != NULL));
	DEVID_ASSERT(DEVID_FUNC(devid_valid)(id1) == DEVID_RET_VALID);
	DEVID_ASSERT(DEVID_FUNC(devid_valid)(id2) == DEVID_RET_VALID);

	/* magic and revision comparison */
	if ((rval = bcmp(id1, id2, 4)) != 0) {
		return (rval);
	}

	/* get current devid types */
	i_id1_type = DEVID_GETTYPE(i_id1);
	i_id2_type = DEVID_GETTYPE(i_id2);

	/*
	 * Originaly all page83 devids used DEVID_SCSI3_WWN.
	 * To avoid a possible uniqueness issue each type of page83
	 * encoding supported is represented as a separate
	 * devid type.  If comparing DEVID_SCSI3_WWN against
	 * one of the new page83 encodings we assume that no
	 * uniqueness issue exists (since we had apparently been
	 * running with the old DEVID_SCSI3_WWN encoding without
	 * a problem).
	 */
	if ((i_id1_type == DEVID_SCSI3_WWN) ||
	    (i_id2_type == DEVID_SCSI3_WWN)) {
		/*
		 * Atleast one devid is using old scsi
		 * encode algorithm.  Force devid types
		 * to same scheme for comparison.
		 */
		if (IS_DEVID_SCSI3_VPD_TYPE(i_id1_type)) {
			i_id1_type = DEVID_SCSI3_WWN;
		}
		if (IS_DEVID_SCSI3_VPD_TYPE(i_id2_type)) {
			i_id2_type = DEVID_SCSI3_WWN;
		}
	}

	/* type comparison */
	if (i_id1_type != i_id2_type) {
		return ((i_id1_type < i_id2_type) ? -1 : 1);
	}

	/* length comparison */
	if (DEVID_GETLEN(i_id1) != DEVID_GETLEN(i_id2)) {
		return (DEVID_GETLEN(i_id1) < DEVID_GETLEN(i_id2) ? -1 : 1);
	}

	/* id comparison */
	rval = bcmp(i_id1->did_id, i_id2->did_id, DEVID_GETLEN(i_id1));

	return (rval);
}

/*
 * Free a Device Id
 */
void
#ifdef	_KERNEL
ddi_devid_free(ddi_devid_t devid)
#else	/* !_KERNEL */
devid_free(ddi_devid_t devid)
#endif	/* _KERNEL */
{
	DEVID_ASSERT(devid != NULL);
	DEVID_FREE(devid, DEVID_FUNC(devid_sizeof)(devid));
}

/*
 * Encode a device id into a string.  See ddi_impldefs.h for details.
 */
char *
#ifdef	_KERNEL
ddi_devid_str_encode(ddi_devid_t devid, char *minor_name)
#else	/* !_KERNEL */
devid_str_encode(ddi_devid_t devid, char *minor_name)
#endif	/* _KERNEL */
{
	impl_devid_t	*id = (impl_devid_t *)devid;
	size_t		driver_len, devid_len, slen;
	char		*sbuf, *dsp, *dp, ta;
	int		i, n, ascii;

	/* "id0" is the encoded representation of a NULL device id */
	if (devid == NULL) {
		if ((sbuf = DEVID_MALLOC(4)) == NULL)
			return (NULL);
		*(sbuf+0) = DEVID_MAGIC_MSB;
		*(sbuf+1) = DEVID_MAGIC_LSB;
		*(sbuf+2) = '0';
		*(sbuf+3) = 0;
		return (sbuf);
	}

	/* verify input */
	if (DEVID_FUNC(devid_valid)(devid) != DEVID_RET_VALID)
		return (NULL);

	/* scan the driver hint to see how long the hint is */
	for (driver_len = 0; driver_len < DEVID_HINT_SIZE; driver_len++)
		if (id->did_driver[driver_len] == '\0')
			break;

	/* scan the contained did_id to see if it meets ascii requirements */
	devid_len = DEVID_GETLEN(id);
	for (ascii = 1, i = 0; i < devid_len; i++)
		if (!DEVID_IDBYTE_ISASCII(id->did_id[i])) {
			ascii = 0;
			break;
		}

	/* some types should always go hex even if they look ascii */
	if (DEVID_TYPE_BIN_FORCEHEX(id->did_type_lo))
		ascii = 0;

	/* set the length of the resulting string */
	slen = 2 + 1;					/* <magic><rev> "id1" */
	slen += 1 + driver_len + 1 + 1;			/* ",<driver>@<type>" */
	slen += ascii ? devid_len : (devid_len * 2);	/* did_id field */
	if (minor_name) {
		slen += 1;				/* '/' */
		slen += strlen(minor_name);		/* len of minor_name */
	}
	slen += 1;					/* NULL */

	/* allocate string */
	if ((sbuf = DEVID_MALLOC(slen)) == NULL)
		return (NULL);

	/* perform encode of id to hex string */
	dsp = sbuf;
	*dsp++ = id->did_magic_hi;
	*dsp++ = id->did_magic_lo;
	*dsp++ = DEVID_REV_BINTOASCII(id->did_rev_lo);
	*dsp++ = ',';
	for (i = 0; i < driver_len; i++)
		*dsp++ = id->did_driver[i];
	*dsp++ = '@';
	ta = DEVID_TYPE_BINTOASCII(id->did_type_lo);
	if (ascii)
		ta = DEVID_TYPE_SETASCII(ta);
	*dsp++ = ta;
	for (i = 0, dp = &id->did_id[0]; i < devid_len; i++, dp++) {
		if (ascii) {
			if (*dp == ' ')
				*dsp++ = '_';
			else if (*dp == 0x00)
				*dsp++ = '~';
			else
				*dsp++ = *dp;
		} else {
			n = ((*dp) >> 4) & 0xF;
			*dsp++ = (n < 10) ? (n + '0') : (n + ('a' - 10));
			n = (*dp) & 0xF;
			*dsp++ = (n < 10) ? (n + '0') : (n + ('a' - 10));
		}
	}

	if (minor_name) {
		*dsp++ = '/';
		(void) strcpy(dsp, minor_name);
	} else
		*dsp++ = 0;

	/* ensure that (strlen + 1) is correct length for free */
	DEVID_ASSERT((strlen(sbuf) + 1) == slen);
	return (sbuf);
}

/* free the string returned by devid_str_encode */
void
#ifdef	_KERNEL
ddi_devid_str_free(char *devidstr)
#else	/* !_KERNEL */
devid_str_free(char *devidstr)
#endif	/* _KERNEL */
{
	DEVID_FREE(devidstr, strlen(devidstr) + 1);
}

/*
 * given the string representation of a device id returned by calling
 * devid_str_encode (passed in as devidstr), return pointers to the
 * broken out devid and minor_name as requested. Devidstr remains
 * allocated and unmodified. The devid returned in *devidp should be freed by
 * calling devid_free.  The minor_name returned in minor_namep should
 * be freed by calling devid_str_free(minor_namep).
 *
 * See ddi_impldefs.h for format details.
 */
int
#ifdef	_KERNEL
ddi_devid_str_decode(
#else	/* !_KERNEL */
devid_str_decode(
#endif	/* _KERNEL */
    char *devidstr, ddi_devid_t *devidp, char **minor_namep)
{
	return (devid_str_decode_id(devidstr, devidp, minor_namep, NULL));
}

/* implementation for (ddi_)devid_str_decode */
static int
devid_str_decode_id(char *devidstr, ddi_devid_t *devidp,
    char **minor_namep, impl_devid_t *id)
{
	char		*str, *msp, *dsp, *dp, ta;
	int		slen, devid_len, ascii, i, n, c, pre_alloc = FALSE;
	unsigned short	id_len, type;		/* for hibyte/lobyte */

	if (devidp != NULL)
		*devidp = NULL;
	if (minor_namep != NULL)
		*minor_namep = NULL;
	if (id != NULL)
		pre_alloc = TRUE;

	if (devidstr == NULL)
		return (DEVID_FAILURE);

	/* the string must atleast contain the ascii two byte header */
	slen = strlen(devidstr);
	if ((slen < 3) || (devidstr[0] != DEVID_MAGIC_MSB) ||
	    (devidstr[1] != DEVID_MAGIC_LSB))
		return (DEVID_FAILURE);

	/* "id0" is the encoded representation of a NULL device id */
	if ((devidstr[2] == '0') && (slen == 3))
		return (DEVID_SUCCESS);

	/* "id1,@S0" is the shortest possible, reject if shorter */
	if (slen <  7)
		return (DEVID_FAILURE);

	/* find the optional minor name, start after ',' */
	if ((msp = strchr(&devidstr[4], '/')) != NULL)
		msp++;

	/* skip devid processing if we are not asked to return it */
	if (devidp) {
		/* find the required '@' separator */
		if ((str = strchr(devidstr, '@')) == NULL)
			return (DEVID_FAILURE);
		str++;					/* skip '@' */

		/* pick up <type> after the '@' and verify */
		ta = *str++;
		ascii = DEVID_TYPE_ISASCII(ta);
		type = DEVID_TYPE_ASCIITOBIN(ta);
		if (type > DEVID_MAXTYPE)
			return (DEVID_FAILURE);

		/* determine length of id->did_id field */
		if (msp == NULL)
			id_len = strlen(str);
		else
			id_len = msp - str - 1;

		/* account for encoding: with hex, binary is half the size */
		if (!ascii) {
			/* hex id field must be even length */
			if (id_len & 1)
				return (DEVID_FAILURE);
			id_len /= 2;
		}

		/* add in size of the binary devid header */
		devid_len = id_len + sizeof (*id) - sizeof (id->did_id);

		/*
		 * Allocate space for devid if we are asked to decode it
		 * decode it and space wasn't pre-allocated.
		 */
		if (pre_alloc == FALSE) {
			if ((id = (impl_devid_t *)DEVID_MALLOC(
			    devid_len)) == NULL)
				return (DEVID_FAILURE);
		}

		/* decode header portion of the string into the binary devid */
		dsp = devidstr;
		id->did_magic_hi = *dsp++;		/* <magic> "id" */
		id->did_magic_lo = *dsp++;
		id->did_rev_hi = 0;
		id->did_rev_lo =
		    DEVID_REV_ASCIITOBIN(*dsp);		/* <rev> "1" */
		dsp++;					/* skip "1" */
		dsp++;					/* skip "," */
		for (i = 0; i < DEVID_HINT_SIZE; i++) {	/* <driver>@ */
			if (*dsp == '@')
				break;
			id->did_driver[i] = *dsp++;
		}
		for (; i < DEVID_HINT_SIZE; i++)
			id->did_driver[i] = 0;

		/* we must now be at the '@' */
		if (*dsp != '@')
			goto efree;

		/* set the type and length */
		DEVID_FORMTYPE(id, type);
		DEVID_FORMLEN(id, id_len);

		/* decode devid portion of string into the binary */
		for (i = 0, dsp = str, dp = &id->did_id[0];
		    i < id_len; i++, dp++) {
			if (ascii) {
				if (*dsp == '_')
					*dp = ' ';
				else if (*dsp == '~')
					*dp = 0x00;
				else
					*dp = *dsp;
				dsp++;
			} else {
				c = *dsp++;
				if (c >= '0' && c <= '9')
					n = (c - '0') & 0xFF;
				else if (c >= 'a' && c <= 'f')
					n = (c - ('a' - 10)) & 0xFF;
				else
					goto efree;
				n <<= 4;
				c = *dsp++;
				if (c >= '0' && c <= '9')
					n |= (c - '0') & 0xFF;
				else if (c >= 'a' && c <= 'f')
					n |= (c - ('a' - 10)) & 0xFF;
				else
					goto efree;
				*dp = n;
			}
		}

		/* verify result */
		if (DEVID_FUNC(devid_valid)((ddi_devid_t)id) != DEVID_RET_VALID)
			goto efree;
	}

	/* duplicate minor_name if we are asked to decode it */
	if (minor_namep && msp) {
		if ((*minor_namep = DEVID_MALLOC(strlen(msp) + 1)) == NULL)
			goto efree;
		(void) strcpy(*minor_namep, msp);
	}

	/* return pointer to binary */
	if (devidp)
		*devidp = (ddi_devid_t)id;
	return (DEVID_SUCCESS);

efree:
	if ((pre_alloc == FALSE) && (id))
		DEVID_FREE(id, devid_len);
	return (DEVID_FAILURE);
}


/*
 * Compare two device id's in string form
 *	-1 - id1 less than id2
 *	0  - equal
 * 	1  - id1 greater than id2
 */
int
#ifdef	_KERNEL
ddi_devid_str_compare(char *id1_str, char *id2_str)
#else	/* !_KERNEL */
devid_str_compare(char *id1_str, char *id2_str)
#endif	/* _KERNEL */
{
	int		rval	= DEVID_FAILURE;
	ddi_devid_t	devid1;
	ddi_devid_t	devid2;
#ifdef	_KERNEL
	/* kernel use static protected by lock. */
	static kmutex_t	id_lock;
	static uchar_t	id1[sizeof (impl_devid_t) + MAXPATHLEN];
	static uchar_t	id2[sizeof (impl_devid_t) + MAXPATHLEN];
#else	/* !_KERNEL */
	/* userland place on stack, since malloc might fail */
	uchar_t		id1[sizeof (impl_devid_t) + MAXPATHLEN];
	uchar_t		id2[sizeof (impl_devid_t) + MAXPATHLEN];
#endif	/* _KERNEL */

#ifdef	_KERNEL
	mutex_enter(&id_lock);
#endif	/* _KERNEL */

	/*
	 * encode string form of devid
	 */
	if ((devid_str_decode_id(id1_str, &devid1, NULL, (impl_devid_t *)id1) ==
	    DEVID_SUCCESS) &&
	    (devid_str_decode_id(id2_str, &devid2, NULL, (impl_devid_t *)id2) ==
	    DEVID_SUCCESS)) {
		rval = DEVID_FUNC(devid_compare)(devid1, devid2);
	}

#ifdef	_KERNEL
	mutex_exit(&id_lock);
#endif	/* _KERNEL */

	return (rval);
}
