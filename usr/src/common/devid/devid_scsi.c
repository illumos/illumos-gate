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

/*
 * Copyright 2019 Joyent, Inc.
 * Copyright 2023 Racktop Systems, Inc.
 */

/*
 * These functions are used to encode SCSI INQUIRY data into
 * Solaris devid / guid values.
 */

#ifndef _KERNEL
#include <stdio.h>
#endif /* _KERNEL */

#include <sys/inttypes.h>
#include <sys/types.h>
#include <sys/stropts.h>
#include <sys/debug.h>
#include <sys/isa_defs.h>
#include <sys/dditypes.h>
#include <sys/ddi_impldefs.h>
#include <sys/scsi/scsi.h>
#ifndef _KERNEL
#include <sys/libdevid.h>
#endif /* !_KERNEL */
#include "devid_impl.h"

#define	SCSI_INQUIRY_VID_POS			9
#define	SCSI_INQUIRY_VID_SUN			"SUN"
#define	SCSI_INQUIRY_VID_SUN_LEN		3
#define	SCSI_INQUIRY_VID_HITACHI		"HITACHI"
#define	SCSI_INQUIRY_VID_HITACHI_LEN		7
#define	SCSI_INQUIRY_PID_HITACHI_OPEN		"OPEN-"
#define	SCSI_INQUIRY_PID_HITACHI_OPEN_LEN	5
#define	SCSI_INQUIRY_VID_EMC			"EMC     "
#define	SCSI_INQUIRY_VID_EMC_LEN		8
#define	SCSI_INQUIRY_PID_EMC_SYMMETRIX		"SYMMETRIX       "
#define	SCSI_INQUIRY_PID_EMC_SYMMETRIX_LEN	16

#define	MSG_NOT_STANDARDS_COMPLIANT "!Page83 data not standards compliant "
#define	MSG_NOT_STANDARDS_COMPLIANT_SIZE	( \
	sizeof (MSG_NOT_STANDARDS_COMPLIANT) + \
	sizeof (((struct scsi_inquiry *)NULL)->inq_vid) + \
	sizeof (((struct scsi_inquiry *)NULL)->inq_pid) + \
	sizeof (((struct scsi_inquiry *)NULL)->inq_revision) + 4)

#define	IS_DEVID_GUID_TYPE(type) ((type == DEVID_SCSI3_WWN)	|| \
				(IS_DEVID_SCSI3_VPD_TYPE(type)))

#define	IS_DEVID_SCSI_TYPE(type) ((IS_DEVID_GUID_TYPE(type)) || \
				(type == DEVID_SCSI_SERIAL))

/*
 * The max inquiry page 83 size as expected in the code today
 * is 0xf0 bytes. Defining a constant to make it easy incase
 * this needs to be changed at a later time.
 */

#define	SCMD_MAX_INQUIRY_PAGE83_SIZE			0xFF
#define	SCMD_MIN_INQUIRY_PAGE83_SIZE			0x08
#define	SCMD_INQUIRY_PAGE83_HDR_SIZE			4
#define	SCSI_INQUIRY_PAGE83_EMC_SYMMETRIX_ID_LEN	16

#define	SCMD_MAX_INQUIRY_PAGE80_SIZE	0xFF
#define	SCMD_MIN_INQUIRY_PAGE80_SIZE	0x04

#define	SCMD_MIN_STANDARD_INQUIRY_SIZE	0x04

#define	SCMD_INQUIRY_PAGE83_IDENT_DESC_HDR_SIZE		4

#define	SCMD_INQUIRY_VPD_TYPE_T10	0x01
#define	SCMD_INQUIRY_VPD_TYPE_EUI	0x02
#define	SCMD_INQUIRY_VPD_TYPE_NAA	0x03
#define	SCMD_INQUIRY_VPD_TYPE_RTP	0x04
#define	SCMD_INQUIRY_VPD_TYPE_TPG	0x05
#define	SCMD_INQUIRY_VPD_TYPE_LUG	0x06
#define	SCMD_INQUIRY_VPD_TYPE_MD5	0x07
#define	SCMD_INQUIRY_VPD_TYPE_SSN	0x08

static int is_page83_data_valid(uchar_t *inq83, size_t inq83_len);
static int is_page80_data_valid(uchar_t *inq80, size_t inq80_len);
static int is_initialized_id(uchar_t *id, size_t id_len);

static void encode_scsi3_page83(int version, uchar_t *inq83,
    size_t inq83_len, uchar_t **id, size_t *id_len, ushort_t *id_type);
static void encode_scsi3_page83_emc(int version, uchar_t *inq83,
    size_t inq83_len, uchar_t **id, size_t *id_len, ushort_t *id_type);
static void encode_serialnum(int version, uchar_t *inq, uchar_t *inq80,
    size_t inq80_len, uchar_t **id, size_t *id_len, ushort_t *id_type);
static void encode_sun_serialnum(int version, uchar_t *inq,
    size_t inq_len, uchar_t **id, size_t *id_len, ushort_t *id_type);

static int devid_scsi_init(char *driver_name,
    uchar_t *raw_id, size_t raw_id_len, ushort_t raw_id_type,
    ddi_devid_t *ret_devid);

static char ctoi(char c);

#ifdef	_KERNEL
#define	devid_scsi_encode	ddi_devid_scsi_encode
#define	devid_to_guid		ddi_devid_to_guid
#define	devid_free_guid		ddi_devid_free_guid
#endif	/* _KERNEL */

/*
 *    Function: ddi_/devid_scsi_encode
 *
 * Description: This routine finds and encodes a unique devid
 *
 *   Arguments: version - id encode algorithm version
 *		driver_name - binding driver name (if ! known use NULL)
 *		inq - standard inquiry buffer
 *		inq_len - standard inquiry buffer length
 *		inq80 - serial number inquiry buffer
 *		inq80_len - serial number inquiry buffer length
 *		inq83 - vpd inquiry buffer
 *		inq83_len - vpd inquiry buffer length
 *		devid - id returned
 *
 * Return Code: DEVID_SUCCESS - success
 *		DEVID_FAILURE - failure
 *		DEVID_RETRY - LUN is in a transitional state.  A delay should
 *		occur and then this inquiry data should be re-acquired and
 *		this function should be called again.
 */
int
devid_scsi_encode(
    int version,	/* IN */
    char *driver_name,	/* IN */
    uchar_t *inq,	/* IN */
    size_t inq_len,	/* IN */
    uchar_t *inq80,	/* IN */
    size_t inq80_len,	/* IN */
    uchar_t *inq83,	/* IN */
    size_t inq83_len,	/* IN */
    ddi_devid_t *devid)	/* OUT */
{
	int			rval		= DEVID_FAILURE;
	uchar_t			*id		= NULL;
	size_t			id_len		= 0;
	ushort_t		id_type		= DEVID_NONE;
	struct scsi_inquiry	*inq_std	= (struct scsi_inquiry *)inq;
#ifdef	_KERNEL
	char			*msg		= NULL;
#endif	/* _KERNEL */

	DEVID_ASSERT(devid != NULL);

	/* verify valid version */
	if (version > DEVID_SCSI_ENCODE_VERSION_LATEST) {
		return (rval);
	}

	/* make sure minimum inquiry bytes are available */
	if (inq_len < SCMD_MIN_STANDARD_INQUIRY_SIZE) {
		return (rval);
	}

	/*
	 * If 0x83 is availible, that is the best choice.  Our next choice is
	 * 0x80.  If neither are availible, we leave it to the caller to
	 * determine possible alternate ID, although discouraged.  In the
	 * case of the target drivers they create a fabricated id which is
	 * stored in the acyl.  The HBA drivers should avoid using an
	 * alternate id.  Although has already created a hack of using the
	 * node wwn in some cases.  Which needs to be carried forward for
	 * legacy reasons.
	 */
	if (inq83 != NULL) {
		/*
		 * Perform page 83 validation tests and report offenders.
		 * We cannot enforce the page 83 specification because
		 * many Sun partners (ex. HDS) do not conform to the
		 * standards yet.
		 */
		if (is_page83_data_valid(inq83, inq83_len) ==
		    DEVID_RET_INVALID) {
			/*
			 * invalid page 83 data.  bug 4939576 introduced
			 * handling for EMC non-standard data.
			 */
			if ((bcmp(inq_std->inq_vid, SCSI_INQUIRY_VID_EMC,
			    SCSI_INQUIRY_VID_EMC_LEN) == 0) &&
			    (bcmp(inq_std->inq_pid,
			    SCSI_INQUIRY_PID_EMC_SYMMETRIX,
			    SCSI_INQUIRY_PID_EMC_SYMMETRIX_LEN) == 0)) {
				encode_scsi3_page83_emc(version, inq83,
				    inq83_len, &id, &id_len, &id_type);
			}
#ifdef	_KERNEL
			/*
			 * invalid page 83 data. Special hack for HDS
			 * specific device, to suppress the warning msg.
			 */
			if ((bcmp(inq_std->inq_vid, SCSI_INQUIRY_VID_HITACHI,
			    SCSI_INQUIRY_VID_HITACHI_LEN) != 0) ||
			    (bcmp(inq_std->inq_pid,
			    SCSI_INQUIRY_PID_HITACHI_OPEN,
			    SCSI_INQUIRY_PID_HITACHI_OPEN_LEN) != 0)) {
				/*
				 * report the page 0x83 standards violation.
				 */
				msg = kmem_alloc(
				    MSG_NOT_STANDARDS_COMPLIANT_SIZE,
				    KM_SLEEP);
				(void) strcpy(msg, MSG_NOT_STANDARDS_COMPLIANT);
				(void) strncat(msg, inq_std->inq_vid,
				    sizeof (inq_std->inq_vid));
				(void) strcat(msg, " ");
				(void) strncat(msg, inq_std->inq_pid,
				    sizeof (inq_std->inq_pid));
				(void) strcat(msg, " ");
				(void) strncat(msg, inq_std->inq_revision,
				    sizeof (inq_std->inq_revision));
				(void) strcat(msg, "\n");
				cmn_err(CE_WARN, "%s", msg);
				kmem_free(msg,
				    MSG_NOT_STANDARDS_COMPLIANT_SIZE);
			}
#endif	/* _KERNEL */
		}

		if (id_type == DEVID_NONE) {
			encode_scsi3_page83(version, inq83,
			    inq83_len, &id, &id_len, &id_type);
		}
	}

	/*
	 * If no vpd page is available at this point then we
	 * attempt to use a SCSI serial number from page 0x80.
	 */
	if ((id_type == DEVID_NONE) &&
	    (inq != NULL) &&
	    (inq80 != NULL)) {
		if (is_page80_data_valid(inq80, inq80_len) == DEVID_RET_VALID) {
			encode_serialnum(version, inq, inq80,
			    inq80_len, &id, &id_len, &id_type);
		}
	}

	/*
	 * If no vpd page  or serial is available at this point and
	 * it's a SUN disk it conforms to the disk qual. 850 specifications
	 * and we can fabricate a serial number id based on the standard
	 * inquiry page.
	 */
	if ((id_type == DEVID_NONE) &&
	    (inq != NULL)) {
		encode_sun_serialnum(version, inq, inq_len,
		    &id, &id_len, &id_type);
	}

	if (id_type != DEVID_NONE) {
		if (is_initialized_id(id, id_len) == DEVID_RET_VALID) {
			rval = devid_scsi_init(driver_name,
			    id, id_len, id_type, devid);
		} else {
			rval = DEVID_RETRY;
		}
		DEVID_FREE(id, id_len);
	}

	return (rval);
}


/*
 *    Function: is_page83_data_valid
 *
 * Description: This routine is used to validate the page 0x83 data
 *		passed in valid based on the standards specification.
 *
 *   Arguments: inq83 -
 *		inq83_len -
 *
 * Return Code: DEVID_RET_VALID
 *              DEVID_RET_INVALID
 *
 */
static int
is_page83_data_valid(uchar_t *inq83, size_t inq83_len)
{

	int	covered_desc_len	= 0;
	int	dlen			= 0;
	uchar_t	*dblk			= NULL;

	DEVID_ASSERT(inq83 != NULL);

	/* if not large enough fail */
	if (inq83_len < SCMD_MIN_INQUIRY_PAGE83_SIZE)
		return (DEVID_RET_INVALID);

	/*
	 * Ensuring that the Peripheral device type(bits 0 - 4) has
	 * the valid settings - the value 0x1f indicates no device type.
	 * Only this value can be validated since all other fields are
	 * either used or reserved.
	 */
	if ((inq83[0] & DTYPE_MASK) == DTYPE_UNKNOWN) {
		/* failed-peripheral devtype */
		return (DEVID_RET_INVALID);
	}

	/*
	 * Ensure that the page length field - third and 4th bytes
	 * contain a non zero length value. Our implementation
	 * does not seem to expect more that 255 bytes of data...
	 * what is to be done if the reported size is > 255 bytes?
	 * Yes the device will return only 255 bytes as we provide
	 * buffer to house only that much data but the standards
	 * prevent the targets from reporting the truncated size
	 * in this field.
	 *
	 * Currently reporting sizes more than 255 as failure.
	 *
	 */

	if ((inq83[2] == 0) && (inq83[3] == 0)) {
		/* length field is 0! */
		return (DEVID_RET_INVALID);
	}
	if (inq83[3] > (SCMD_MAX_INQUIRY_PAGE83_SIZE - 3)) {
		/* length field exceeds expected size of 255 bytes */
		return (DEVID_RET_INVALID);
	}

	/*
	 * Validation of individual descriptor blocks are done in the
	 * following while loop. It is possible to have multiple
	 * descriptor blocks.
	 * the 'dblk' pointer will be pointing to the start of
	 * each entry of the descriptor block.
	 */
	covered_desc_len = 0;
	dblk = &inq83[4]; /* start of first decriptor blk */
	while (covered_desc_len < inq83[3]) {

		/*
		 * Ensure that the length field is non zero
		 * Further length validations will be done
		 * along with the 'identifier type' as some of
		 * the lengths are dependent on it.
		 */
		dlen = dblk[3];
		if (dlen == 0) {
			/* descr length is 0 */
			return (DEVID_RET_INVALID);
		}

		/*
		 * ensure that the size of the descriptor block does
		 * not claim to be larger than the entire page83
		 * data that has been received.
		 */
		if ((covered_desc_len + dlen) > inq83[3]) {
			/* failed-descr length */
			return (DEVID_RET_INVALID);
		}

		/*
		 * The spec says that if the PIV field is 0 OR the
		 * association field contains value other than 1 and 2,
		 * then the protocol identifier field should be ignored.
		 * If association field contains a value of 1 or 2
		 * and the PIV field is set, then the protocol identifier
		 * field has to be validated.
		 * The protocol identifier values 0 - f are either assigned
		 * or reserved. Nothing to validate here, hence skipping
		 * over to the next check.
		 */

		/*
		 * Check for valid code set values.
		 * All possible values are reserved or assigned. Nothing
		 * to validate - skipping over.
		 */

		/*
		 * Identifier Type validation
		 * All SPC3rev22 identified types and the expected lengths
		 * are validated.
		 */
		switch (dblk[1] & 0x0f) {
		case SCMD_INQUIRY_VPD_TYPE_T10: /* T10 vendor Id */
			/* No specific length validation required */
			break;

		case SCMD_INQUIRY_VPD_TYPE_EUI: /* EUI 64 ID */
			/* EUI-64: size is expected to be 8, 12, or 16 bytes */
			if ((dlen != 8) && (dlen != 12) && (dlen != 16)) {
				/* page83 validation failed-EIU64 */
				return (DEVID_RET_INVALID);
			}
			break;

		case SCMD_INQUIRY_VPD_TYPE_NAA: /* NAA Id type */

			/*
			 * the size for this varies -
			 * IEEE extended/registered is 8 bytes
			 * IEEE Registered extended is 16 bytes
			 */
			switch (dblk[4] & 0xf0) {

				case 0x20: /* IEEE Ext */
				case 0x50: /* IEEE Reg */
					if (dlen != 8) {
						/* failed-IEE E/R len */
						return (DEVID_RET_INVALID);
					}
					/*
					 * the codeSet for this MUST
					 * be set to 1
					 */
					if ((dblk[0] & 0x0f) != 1) {
						/*
						 * failed-IEEE E/R
						 * codeSet != 1.
						 */
						return (DEVID_RET_INVALID);
					}
				break;

				case 0x60: /* IEEE EXT REG */
					if (dlen != 16) {
						/* failed-IEEE ER len */
						return (DEVID_RET_INVALID);
					}
					/*
					 * the codeSet for this MUST
					 * be set to 1
					 */
					if ((dblk[0] & 0x0f) != 1) {
						/*
						 * failed-IEEE ER
						 * codeSet != 1.
						 */
						return (DEVID_RET_INVALID);
						}
				break;

				default:
					/* reserved values */
					break;
			}
			break;

		case SCMD_INQUIRY_VPD_TYPE_RTP: /* Relative Target port */
			if (dlen != 4) {
				/* failed-Rel target Port length */
				return (DEVID_RET_INVALID);
			}
			break;

		case SCMD_INQUIRY_VPD_TYPE_TPG: /* Target port group */
			if (dlen != 4) {
				/* failed-target Port group length */
				return (DEVID_RET_INVALID);
			}
			break;

		case SCMD_INQUIRY_VPD_TYPE_LUG: /* Logical unit group */
			if (dlen != 4) {
				/* failed-Logical Unit group length */
				return (DEVID_RET_INVALID);
			}
			break;

		case SCMD_INQUIRY_VPD_TYPE_MD5: /* MD5 unit group */
			if (dlen != 16) {
				/* failed-MD5 Unit grp */
				return (DEVID_RET_INVALID);
			}
			break;

		default:
			break;
		}

		/*
		 * Now lets advance to the next descriptor block
		 * and validate it.
		 * the descriptor block size is <descr Header> + <descr Data>
		 * <descr Header> is equal to 4 bytes
		 * <descr Data> is available in dlen or dblk[3].
		 */
		dblk = &dblk[4 + dlen];

		/*
		 * update the covered_desc_len so that we can ensure that
		 * the 'while' loop terminates.
		 */
		covered_desc_len += (dlen + 4);
	}
	return (DEVID_RET_VALID);
}


/*
 *    Function: is_initialized_id
 *
 * Description: Routine to ensure that the ID calculated is not a
 *		space or zero filled ID. Returning a space / zero
 *		filled ID when the luns on the target are not fully
 *		initialized is a valid response from the target as
 *		per the T10 spec. When a space/zero filled ID is
 *		found its information needs to be polled again
 *		after sometime time to see if the luns are fully
 *		initialized to return a valid guid information.
 *
 *   Arguments: id - raw id
 *              id_len - raw id len
 *
 * Return Code:	DEVID_VALID - indicates a non space/zero filled id
 *		DEVID_INVALID - indicates id contains uninitialized data
 *		and suggests retry of the collection commands.
 */
static int
is_initialized_id(uchar_t *id, size_t id_len)
{
	int idx;

	if ((id == NULL) ||
	    (id_len == 0)) {
		/* got id length as 0 fetch info again */
		return (DEVID_RET_INVALID);
	}

	/* First lets check if the guid is filled with spaces */
	for (idx = 0; idx < id_len; idx++) {
		if (id[idx] != ' ') {
			break;
		}
	}

	/*
	 * Lets exit if we find that it contains ALL spaces
	 * saying that it has an uninitialized guid
	 */
	if (idx >= id_len) {
		/* guid filled with spaces found */
		return (DEVID_RET_INVALID);
	}

	/*
	 * Since we have found that it is not filled with spaces
	 * now lets ensure that the guid is not filled with only
	 * zeros.
	 */
	for (idx = 0; idx < id_len; idx ++) {
		if (id[idx] != 0) {
			return (DEVID_RET_VALID);
		}
	}

	/* guid filled with zeros found */
	return (DEVID_RET_INVALID);
}


/*
 *    Function: is_page80_data_valid
 *
 * Description: This routine is used to validate the page 0x80 data
 *		passed in valid based on the standards specification.
 *
 *   Arguments: inq80 -
 *		inq80_len -
 *
 * Return Code: DEVID_RET_VALID
 *              DEVID_RET_INVALID
 *
 */
/* ARGSUSED */
static int
is_page80_data_valid(uchar_t *inq80, size_t inq80_len)
{
	DEVID_ASSERT(inq80);

	/* if not large enough fail */
	if (inq80_len < SCMD_MIN_INQUIRY_PAGE80_SIZE) {
		return (DEVID_RET_INVALID);
	}

	/*
	 * (inq80_len - 4) is the size of the buffer space available
	 * for the product serial number.  So inq80[3] (ie. product
	 * serial number) should be <= (inq80_len -4).
	 */
	if (inq80[3] > (inq80_len - 4)) {
		return (DEVID_RET_INVALID);
	}

	return (DEVID_RET_VALID);
}


/*
 *    Function: encode_devid_page
 *
 * Description: This routine finds the unique devid if available and
 *		fills the devid and length parameters.
 *
 *   Arguments: version - encode version
 *		inq83 - driver soft state (unit) structure
 *		inq83_len - length of raw inq83 data
 *		id - raw id
 *		id_len - len of raw id
 *		id_type - type of id
 *
 *        Note: DEVID_NONE is returned in the id_type field
 *		if no supported page 83 id is found.
 */
static void
encode_scsi3_page83(int version, uchar_t *inq83, size_t inq83_len,
    uchar_t **id, size_t *id_len, ushort_t *id_type)
{
	size_t	descriptor_bytes_left   = 0;
	size_t	offset			= 0;
	int	idx			= 0;
	size_t	offset_id_type[4];

	DEVID_ASSERT(inq83 != NULL);
	/* inq83 length was already validate in is_page83_valid */
	DEVID_ASSERT(id != NULL);
	DEVID_ASSERT(id_len != NULL);
	DEVID_ASSERT(id_type != NULL);

	/* preset defaults */
	*id = NULL;
	*id_len = 0;
	*id_type = DEVID_NONE;

	/* verify we have enough memory for a ident header */
	if (inq83_len < SCMD_INQUIRY_PAGE83_HDR_SIZE) {
		return;
	}

	/*
	 * Attempt to validate the page data.  Once validated, we'll walk
	 * the descriptors, looking for certain identifier types that will
	 * mark this device with a unique id/wwn.  Note the comment below
	 * for what we really want to receive.
	 */

	/*
	 * The format of the inq83 data (Device Identification VPD page) is
	 * a header (containing the total length of the page, from which
	 * descriptor_bytes_left is calculated), followed by a list of
	 * identification descriptors. Each identifcation descriptor has a
	 * header which includes the length of the individual identification
	 * descriptor).
	 *
	 * Set the offset to the beginning byte of the first identification
	 * descriptor.  We'll index everything from there.
	 */
	offset = SCMD_INQUIRY_PAGE83_HDR_SIZE;
	descriptor_bytes_left = (size_t)((inq83[2] << 8) | inq83[3]);

	/*
	 * If the raw data states that the data is larger
	 * than what is actually received abort encode.
	 * Otherwise we will run off into unknown memory
	 * on the decode.
	 */
	if ((descriptor_bytes_left + offset) > inq83_len) {
		return;
	}


	/* Zero out our offset array */
	bzero(offset_id_type, sizeof (offset_id_type));

	/*
	 * According to the scsi spec 8.4.3 SPC-2, there could be several
	 * descriptors associated with each lun.  Some we care about and some
	 * we don't.  This loop is set up to iterate through the descriptors.
	 * We want the 0x03 case which represents an FC-PH, FC-PH3 or FC-FS
	 * Name_Identifier.  The spec mentions nothing about ordering, so we
	 * don't assume any.
	 *
	 * We need to check if we've finished walking the list of descriptors,
	 * we also perform additional checks to be sure the newly calculated
	 * offset is within the bounds of the buffer, and the identifier length
	 * (as calculated by the length field in the header) is valid. This is
	 * done to protect against devices which return bad page83 data.
	 */
	while ((descriptor_bytes_left > 0) && (offset_id_type[3] == 0) &&
	    (offset + SCMD_INQUIRY_PAGE83_IDENT_DESC_HDR_SIZE <= inq83_len) &&
	    (offset + SCMD_INQUIRY_PAGE83_IDENT_DESC_HDR_SIZE +
	    (size_t)inq83[offset + 3] <= inq83_len)) {
		/*
		 * Inspect the Identification descriptor list. Store the
		 * offsets in the devid page separately for 0x03, 0x01 and
		 * 0x02.  Identifiers 0x00 and 0x04 are not useful as they
		 * don't represent unique identifiers for a lun.  We also
		 * check the association by masking with 0x3f because we want
		 * an association of 0x0 - indicating the identifier field is
		 * associated with the addressed physical or logical device
		 * and not the port.
		 */
		switch ((inq83[offset + 1] & 0x3f)) {
		case SCMD_INQUIRY_VPD_TYPE_T10:
			offset_id_type[SCMD_INQUIRY_VPD_TYPE_T10] = offset;
			break;
		case SCMD_INQUIRY_VPD_TYPE_EUI:
			offset_id_type[SCMD_INQUIRY_VPD_TYPE_EUI] = offset;
			break;
		case SCMD_INQUIRY_VPD_TYPE_NAA:
			offset_id_type[SCMD_INQUIRY_VPD_TYPE_NAA] = offset;
			break;
		default:
			/* Devid page undesired id type */
			break;
		}
		/*
		 * Calculate the descriptor bytes left and move to
		 * the beginning byte of the next id descriptor.
		 */
		descriptor_bytes_left -= (size_t)(inq83[offset + 3] +
		    SCMD_INQUIRY_PAGE83_IDENT_DESC_HDR_SIZE);
		offset += (SCMD_INQUIRY_PAGE83_IDENT_DESC_HDR_SIZE +
		    (size_t)inq83[offset + 3]);
	}

	offset = 0;

	/*
	 * We can't depend on an order from a device by identifier type, but
	 * once we have them, we'll walk them in the same order to prevent a
	 * firmware upgrade from breaking our algorithm.  Start with the one
	 * we want the most: id_offset_type[3].
	 */
	for (idx = 3; idx > 0; idx--) {
		if (offset_id_type[idx] > 0) {
			offset = offset_id_type[idx];
			break;
		}
	}

	/*
	 * We have a valid Device ID page, set the length of the
	 * identifier and copy the value into the wwn.
	 */
	if (offset > 0) {
		*id_len = (size_t)inq83[offset + 3];
		if ((*id = DEVID_MALLOC(*id_len)) == NULL) {
			*id_len = 0;
			return;
		}
		bcopy(&inq83[offset + SCMD_INQUIRY_PAGE83_IDENT_DESC_HDR_SIZE],
		    *id, *id_len);

		/* set devid type */
		switch (version) {
		/* In version 1 all page 83 types were grouped */
		case DEVID_SCSI_ENCODE_VERSION1:
			*id_type = DEVID_SCSI3_WWN;
			break;
		/* In version 2 we break page 83 apart to be unique */
		case DEVID_SCSI_ENCODE_VERSION2:
			switch (idx) {
			case 3:
				*id_type = DEVID_SCSI3_VPD_NAA;
				break;
			case 2:
				*id_type = DEVID_SCSI3_VPD_EUI;
				break;
			case 1:
				*id_type = DEVID_SCSI3_VPD_T10;
				break;
			default:
				DEVID_FREE(*id, *id_len);
				*id_len = 0;
				break;
			}
			break;
		default:
			DEVID_FREE(*id, *id_len);
			*id_len = 0;
			break;
		}
	}
}


/*
 *    Function: encode_scsi3_page83_emc
 *
 * Description: Routine to handle proprietary page 83 of EMC Symmetrix
 *              device. Called by ssfcp_handle_page83()
 *
 *   Arguments: version - encode version
 *		inq83 - scsi page 83 buffer
 *		inq83_len - scsi page 83 buffer size
 *		id - raw emc id
 *		id_len - len of raw emc id
 *		id_type - type of emc id
 */
static void
encode_scsi3_page83_emc(int version, uchar_t *inq83,
    size_t inq83_len, uchar_t **id, size_t *id_len, ushort_t *id_type)
{
	uchar_t	*guidp	= NULL;

	DEVID_ASSERT(inq83 != NULL);
	DEVID_ASSERT(id != NULL);
	DEVID_ASSERT(id_len != NULL);
	DEVID_ASSERT(id_type != NULL);

	/* preset defaults */
	*id = NULL;
	*id_len = 0;
	*id_type = DEVID_NONE;

	/* The initial devid algorithm didn't use EMC page 83 data */
	if (version == DEVID_SCSI_ENCODE_VERSION1) {
		return;
	}

	/* EMC page 83 requires atleast 20 bytes */
	if (inq83_len < (SCMD_INQUIRY_PAGE83_HDR_SIZE +
	    SCSI_INQUIRY_PAGE83_EMC_SYMMETRIX_ID_LEN)) {
		return;
	}

	/*
	 * The 4th byte in the page 83 info returned is most likely
	 * indicating the length of the id - which 0x10(16 bytes)
	 * and the 5th byte is indicating that the id is of
	 * IEEE Registered Extended Name format(6). Validate
	 * these code prints before proceeding further as the
	 * following proprietary approach is tied to the specific
	 * device type and incase the EMC firmware changes, we will
	 * have to validate for the changed device before we start
	 * supporting such a device.
	 */
	if ((inq83[3] != 0x10) || (inq83[4] != 0x60)) {
		/* unsupported emc symtx device type */
		return;
	} else {
		guidp = &inq83[SCMD_INQUIRY_PAGE83_HDR_SIZE];
		/*
		 * The GUID returned by the EMC device is
		 * in the IEEE Registered Extended Name format(6)
		 * as a result it is of 16 bytes in length.
		 * An IEEE Registered Name format(5) will be of
		 * 8 bytes which is NOT what is being returned
		 * by the device type for which we are providing
		 * the support.
		 */
		*id_len = SCSI_INQUIRY_PAGE83_EMC_SYMMETRIX_ID_LEN;
		if ((*id = DEVID_MALLOC(*id_len)) == NULL) {
			*id_len = 0;
			return;
		}
		bcopy(guidp, *id, *id_len);

		/* emc id matches type 3 */
		*id_type = DEVID_SCSI3_VPD_NAA;
	}
}


/*
 *    Function: encode_serialnum
 *
 * Description: This routine finds the unique devid from the inquiry page
 *		0x80, serial number page.  If available and fills the wwn
 *		and length parameters.
 *
 *   Arguments: version - encode version
 *		inq - standard inquiry data
 *		inq80 - serial inquiry data
 *		inq80_len - serial inquiry data len
 *		id - raw id
 *		id_len - raw id len
 *		id_type - raw id type
 */
/* ARGSUSED */
static void
encode_serialnum(int version, uchar_t *inq, uchar_t *inq80,
    size_t inq80_len, uchar_t **id, size_t *id_len, ushort_t *id_type)
{
	struct scsi_inquiry	*inq_std	= (struct scsi_inquiry *)inq;
	int			idx		= 0;

	DEVID_ASSERT(inq != NULL);
	DEVID_ASSERT(inq80 != NULL);
	DEVID_ASSERT(id != NULL);
	DEVID_ASSERT(id_len != NULL);
	DEVID_ASSERT(id_type != NULL);

	/* preset defaults */
	*id = NULL;
	*id_len = 0;
	*id_type = DEVID_NONE;

	/* verify inq80 buffer is large enough for a header */
	if (inq80_len < SCMD_MIN_INQUIRY_PAGE80_SIZE) {
		return;
	}

	/*
	 * Attempt to validate the page data.  Once validated, we'll check
	 * the serial number.
	 */
	*id_len = (size_t)inq80[3]; /* Store Product Serial Number length */

	/* verify buffer is large enough for serial number */
	if (inq80_len < (*id_len + SCMD_MIN_INQUIRY_PAGE80_SIZE)) {
		return;
	}

	/*
	 * Device returns ASCII space (20h) in all the bytes of successful data
	 * transfer, if the product serial number is not available.  So we end
	 * up having to check all the bytes for a space until we reach
	 * something else.
	 */
	for (idx = 0; idx < *id_len; idx++) {
		if (inq80[4 + idx] == ' ') {
			continue;
		}
		/*
		 * The serial number is valid, but since this is only vendor
		 * unique, we'll combine the inquiry vid and pid with the
		 * serial number.
		 */
		*id_len += sizeof (inq_std->inq_vid);
		*id_len += sizeof (inq_std->inq_pid);

		if ((*id = DEVID_MALLOC(*id_len)) == NULL) {
			*id_len = 0;
			return;
		}

		bcopy(&inq_std->inq_vid, *id, sizeof (inq_std->inq_vid));
		bcopy(&inq_std->inq_pid, &(*id)[sizeof (inq_std->inq_vid)],
		    sizeof (inq_std->inq_pid));
		bcopy(&inq80[4], &(*id)[sizeof (inq_std->inq_vid) +
		    sizeof (inq_std->inq_pid)], inq80[3]);

		*id_type = DEVID_SCSI_SERIAL;
		break;
	}

	/*
	 * The spec suggests that the command could succeed but return all
	 * spaces if the product serial number is not available.  In this case
	 * we need to fail this routine. To accomplish this, we compare our
	 * length to the serial number length. If they are the same, then we
	 * never copied in the vid and updated the length. That being the case,
	 * we must not have found a valid serial number.
	 */
	if (*id_len == (size_t)inq80[3]) {
		/* empty unit serial number */
		if (*id != NULL) {
			DEVID_FREE(*id, *id_len);
		}
		*id = NULL;
		*id_len = 0;
	}
}


/*
 *    Function: encode_sun_serialnum
 *
 * Description: This routine finds the unique devid from the inquiry page
 *		0x80, serial number page.  If available and fills the wwn
 *		and length parameters.
 *
 *   Arguments: version - encode version
 *		inq - standard inquiry data
 *		inq_len - standard inquiry data len
 *		id - raw id
 *		id_len - raw id len
 *		id_type - raw id type
 *
 * Return Code: DEVID_SUCCESS
 *              DEVID_FAILURE
 */
/* ARGSUSED */
static void
encode_sun_serialnum(int version, uchar_t *inq,
    size_t inq_len, uchar_t **id, size_t *id_len, ushort_t *id_type)
{
	struct scsi_inquiry *inq_std = (struct scsi_inquiry *)inq;

	DEVID_ASSERT(inq != NULL);
	DEVID_ASSERT(id != NULL);
	DEVID_ASSERT(id_len != NULL);
	DEVID_ASSERT(id_type != NULL);

	/* verify enough buffer is available */
	if (inq_len < SCMD_MIN_STANDARD_INQUIRY_SIZE) {
		return;
	}

	/* sun qual drive */
	if ((inq_std != NULL) &&
	    (bcmp(&inq_std->inq_pid[SCSI_INQUIRY_VID_POS],
	    SCSI_INQUIRY_VID_SUN, SCSI_INQUIRY_VID_SUN_LEN) == 0)) {
		/*
		 * VPD pages 0x83 and 0x80 are unavailable. This
		 * is a Sun qualified disk as indicated by
		 * "SUN" in bytes 25-27 of the inquiry data
		 * (bytes 9-11 of the pid).  Devid's are created
		 * for Sun qualified disks by combining the
		 * vendor id with the product id with the serial
		 * number located in bytes 36-47 of the inquiry data.
		 */

		/* get data size */
		*id_len = sizeof (inq_std->inq_vid) +
		    sizeof (inq_std->inq_pid) +
		    sizeof (inq_std->inq_serial);

		if ((*id = DEVID_MALLOC(*id_len)) == NULL) {
			*id_len = 0;
			return;
		}

		/* copy the vid at the beginning */
		bcopy(&inq_std->inq_vid, *id,
		    sizeof (inq_std->inq_vid));

		/* copy the pid after the vid */
		bcopy(&inq_std->inq_pid,
		    &(*id)[sizeof (inq_std->inq_vid)],
		    sizeof (inq_std->inq_pid));

		/* copy the serial number after the vid and pid */
		bcopy(&inq_std->inq_serial,
		    &(*id)[sizeof (inq_std->inq_vid) +
		    sizeof (inq_std->inq_pid)],
		    sizeof (inq_std->inq_serial));

		/* devid formed from inquiry data */
		*id_type = DEVID_SCSI_SERIAL;
	}
}


/*
 *    Function: devid_scsi_init
 *
 * Description: This routine is used to create a devid for a scsi
 *		devid type.
 *
 *   Arguments: hint - driver soft state (unit) structure
 *		raw_id - pass by reference variable to hold wwn
 *		raw_id_len - wwn length
 *		raw_id_type -
 *		ret_devid -
 *
 * Return Code: DEVID_SUCCESS
 *              DEVID_FAILURE
 *
 */
static int
devid_scsi_init(
	char		*driver_name,
	uchar_t		*raw_id,
	size_t		raw_id_len,
	ushort_t	raw_id_type,
	ddi_devid_t	*ret_devid)
{
	impl_devid_t	*i_devid	= NULL;
	int		i_devid_len	= 0;
	int		driver_name_len	= 0;
	ushort_t	u_raw_id_len	= 0;

	DEVID_ASSERT(raw_id != NULL);
	DEVID_ASSERT(ret_devid != NULL);

	if (!IS_DEVID_SCSI_TYPE(raw_id_type)) {
		*ret_devid = NULL;
		return (DEVID_FAILURE);
	}

	i_devid_len = sizeof (*i_devid) + raw_id_len - sizeof (i_devid->did_id);
	if ((i_devid = DEVID_MALLOC(i_devid_len)) == NULL) {
		*ret_devid = NULL;
		return (DEVID_FAILURE);
	}

	i_devid->did_magic_hi = DEVID_MAGIC_MSB;
	i_devid->did_magic_lo = DEVID_MAGIC_LSB;
	i_devid->did_rev_hi = DEVID_REV_MSB;
	i_devid->did_rev_lo = DEVID_REV_LSB;
	DEVID_FORMTYPE(i_devid, raw_id_type);
	u_raw_id_len = raw_id_len;
	DEVID_FORMLEN(i_devid, u_raw_id_len);

	/* Fill in driver name hint */
	bzero(i_devid->did_driver, DEVID_HINT_SIZE);
	if (driver_name != NULL) {
		driver_name_len = strlen(driver_name);
		if (driver_name_len > DEVID_HINT_SIZE) {
			/* Pick up last four characters of driver name */
			driver_name += driver_name_len - DEVID_HINT_SIZE;
			driver_name_len = DEVID_HINT_SIZE;
		}
		bcopy(driver_name, i_devid->did_driver, driver_name_len);
	}

	bcopy(raw_id, i_devid->did_id, raw_id_len);

	/* return device id */
	*ret_devid = (ddi_devid_t)i_devid;
	return (DEVID_SUCCESS);
}


/*
 *    Function: devid_to_guid
 *
 * Description: This routine extracts a guid string form a devid.
 *		The common use of this guid is for a HBA driver
 *		to pass into mdi_pi_alloc().
 *
 *   Arguments: devid - devid to extract guid from
 *
 * Return Code: guid string - success
 *		NULL - failure
 */
char *
devid_to_guid(ddi_devid_t devid)
{
	impl_devid_t	*id	= (impl_devid_t *)devid;
	int		len	= 0;
	int		idx	= 0;
	int		num	= 0;
	char		*guid	= NULL;
	char		*ptr	= NULL;
	char		*dp	= NULL;

	DEVID_ASSERT(devid != NULL);

	/* NULL devid -> NULL guid */
	if (devid == NULL)
		return (NULL);

	if (!IS_DEVID_GUID_TYPE(DEVID_GETTYPE(id)))
		return (NULL);

	/* guid is always converted to ascii, append NULL */
	len = DEVID_GETLEN(id);

	/* allocate guid string */
	if ((guid = DEVID_MALLOC((len * 2) + 1)) == NULL)
		return (NULL);

	/* perform encode of id to hex string */
	ptr = guid;
	for (idx = 0, dp = &id->did_id[0]; idx < len; idx++, dp++) {
		num = ((*dp) >> 4) & 0xF;
		*ptr++ = (num < 10) ? (num + '0') : (num + ('a' - 10));
		num = (*dp) & 0xF;
		*ptr++ = (num < 10) ? (num + '0') : (num + ('a' - 10));
	}
	*ptr = 0;

	return (guid);
}

/*
 *    Function: devid_free_guid
 *
 * Description: This routine frees a guid allocated by
 *		devid_to_guid().
 *
 *   Arguments: guid - guid to free
 */
void
devid_free_guid(char *guid)
{
	if (guid != NULL) {
		DEVID_FREE(guid, strlen(guid) + 1);
	}
}

static char
ctoi(char c)
{
	if ((c >= '0') && (c <= '9'))
		c -= '0';
	else if ((c >= 'A') && (c <= 'F'))
		c = c - 'A' + 10;
	else if ((c >= 'a') && (c <= 'f'))
		c = c - 'a' + 10;
	else
		c = -1;
	return (c);
}

/* ====NOTE: The scsi_* interfaces are not related to devids :NOTE==== */

/*
 *    Function: scsi_wwnstr_to_wwn
 *
 * Description: This routine translates wwn from wwnstr string to uint64 wwn.
 *
 *   Arguments: wwnstr - the string wwn to be transformed
 *              wwnp - the pointer to 64 bit wwn
 */
int
scsi_wwnstr_to_wwn(const char *wwnstr, uint64_t *wwnp)
{
	int		i;
	char		cl, ch;
	uint64_t	tmp;

	if (wwnp == NULL)
		return (DDI_FAILURE);
	*wwnp = 0;

	if (wwnstr == NULL)
		return (DDI_FAILURE);

	/* Skip leading 'w' if wwnstr is in unit-address form */
	wwnstr = scsi_wwnstr_skip_ua_prefix(wwnstr);

	if (strlen(wwnstr) != 16)
		return (DDI_FAILURE);

	for (i = 0; i < 8; i++) {
		ch = ctoi(*wwnstr++);
		cl = ctoi(*wwnstr++);
		if (cl == -1 || ch == -1) {
			return (DDI_FAILURE);
		}
		tmp = (ch << 4) + cl;
		*wwnp = (*wwnp << 8) | tmp;
	}
	return (DDI_SUCCESS);
}

/*
 *    Function: scsi_wwn_to_wwnstr
 *
 * Description: This routine translates from a uint64 wwn to a wwnstr
 *
 *   Arguments:
 *              wwn - the 64 bit wwn
 *		unit_address_form - do we want a leading 'w'?
 *		wwnstr - allow caller to perform wwnstr allocation.
 *			If non-NULL, don't use scsi_free_wwnstr(),
 *			and make sure you provide 18/17 bytes of  space.
 */
char *
scsi_wwn_to_wwnstr(uint64_t wwn, int unit_address_form, char *wwnstr)
{
	int	len;

	/* make space for leading 'w' */
	if (unit_address_form)
		len = 1 + 16 + 1;	/* "w0123456789abcdef\0" */
	else
		len = 16 + 1;		/* "0123456789abcdef\0" */

	if (wwnstr == NULL) {
		/* We allocate, caller uses scsi_free_wwnstr(). */
		if ((wwnstr = DEVID_MALLOC(len)) == NULL)
			return (NULL);
	}

	if (unit_address_form)
		(void) snprintf(wwnstr, len, "w%016" PRIx64, wwn);
	else
		(void) snprintf(wwnstr, len, "%016" PRIx64, wwn);
	return (wwnstr);
}

/*
 *    Function: scsi_wwnstr_hexcase
 *
 * Description: This routine switches a wwnstr to upper/lower case hex
 *		(a wwnstr uses lower-case hex by default).
 *
 *   Arguments:
 *              wwnstr - the pointer to the wwnstr string.
 *		upper_case_hex - non-zero will convert to upper_case hex
 *			zero will convert to lower case hex.
 */
void
scsi_wwnstr_hexcase(char *wwnstr, int upper_case_hex)
{
	char	*s;
	char	c;

	for (s = wwnstr; *s; s++) {
		c = *s;
		if ((upper_case_hex != 0) &&
		    ((c >= 'a') && (c <= 'f')))
			c -= ('a' - 'A');	/* lower to upper */
		else if ((upper_case_hex == 0) &&
		    ((c >= 'A') && (c <= 'F')))
			c += ('a' - 'A');	/* upper to lower */
		*s = c;
	}
}

/*
 * Function: scsi_wwnstr_skip_ua_prefix
 *
 * Description: This routine removes the leading 'w' in wwnstr,
 *		if its in unit-address form.
 *
 * Arguments: wwnstr - the string wwn to be transformed
 *
 */
const char *
scsi_wwnstr_skip_ua_prefix(const char *wwnstr)
{
	if (*wwnstr == 'w')
		wwnstr++;
	return (wwnstr);
}

/*
 *    Function: scsi_wwnstr_free
 *
 * Description: This routine frees a wwnstr returned by a call
 *		to scsi_wwn_to_strwwn with a NULL wwnstr argument.
 *
 *   Arguments:
 *              wwnstr - the pointer to the wwnstr string to free.
 */
void
scsi_free_wwnstr(char *wwnstr)
{
#ifdef	_KERNEL
	kmem_free(wwnstr, strlen(wwnstr) + 1);
#else	/* _KERNEL */
	free(wwnstr);
#endif	/* _KERNEL */
}

/*
 *    Function: scsi_lun_to_lun64/scsi_lun64_to_lun
 *
 * Description: Convert between normalized (SCSI-3) LUN format, as
 *		described by scsi_lun_t, and a normalized lun64_t
 *              representation (used by Solaris SCSI_ADDR_PROP_LUN64
 *		"lun64" property). The normalized representation maps
 *		in a compatible way to SCSI-2 LUNs. See scsi_address.h
 *
 *              SCSI-3 LUNs are 64 bits. SCSI-2 LUNs are 3 bits (up to
 *              5 bits in non-compliant implementations). SCSI-3 will
 *              pass a (64-bit) scsi_lun_t, but we need a
 *              representation from which we can for example, make
 *              device names. For unit-address compatibility, we represent
 *		64-bit LUN numbers in such a way that they appear like they
 *		would have under SCSI-2. This means that the single level
 *              LUN number is in the lowest byte with the second,
 *              third, and fourth level LUNs represented in
 *              successively higher bytes. In particular, if (and only
 *              if) the first byte of a 64 bit LUN is zero, denoting
 *              "Peripheral Device Addressing Method" and "Bus
 *              Identifier" zero, then the target implements LUNs
 *              compatible in spirit with SCSI-2 LUNs (although under
 *              SCSI-3 there may be up to 256 of them). Under SCSI-3
 *              rules, a target is *required* to use this format if it
 *              contains 256 or fewer Logical Units, none of which are
 *              dependent logical units. These routines have knowledge
 *		of the structure and size of a scsi_lun_t.
 *
 * NOTE: We tolerate vendors that use "Single level LUN structure using
 * peripheral device addressing method" with a non-zero bus identifier
 * (spec says bus identifier must be zero).  Described another way, we let
 * the non-'addressing method' bits of sl_lun1_msb contribute to our lun64
 * value).
 */
scsi_lun64_t
scsi_lun_to_lun64(scsi_lun_t lun)
{
	scsi_lun64_t    lun64;

	/*
	 * Check to see if we have a single level lun that uses the
	 * "Peripheral Device" addressing method. If so, the lun64 value is
	 * kept in Solaris 'unit-address compatibility' form.
	 */
	if (((lun.sl_lun2_msb == 0) && (lun.sl_lun2_lsb == 0) &&
	    (lun.sl_lun3_msb == 0) && (lun.sl_lun3_lsb == 0) &&
	    (lun.sl_lun4_msb == 0) && (lun.sl_lun4_lsb == 0)) &&
	    ((lun.sl_lun1_msb & SCSI_LUN_AM_MASK) == SCSI_LUN_AM_PDEV)) {
		/*
		 * LUN has Solaris 'unit-address compatibility' form, construct
		 * lun64 value from non-'addressing method' bits of msb and lsb.
		 */
		lun64 = ((lun.sl_lun1_msb & ~SCSI_LUN_AM_MASK) << 8) |
		    lun.sl_lun1_lsb;
	} else {
		/*
		 * LUN does not have a Solaris 'unit-address compatibility'
		 * form, construct lun64 value in full 64 bit LUN format.
		 */
		lun64 =
		    ((scsi_lun64_t)lun.sl_lun1_msb << 56) |
		    ((scsi_lun64_t)lun.sl_lun1_lsb << 48) |
		    ((scsi_lun64_t)lun.sl_lun2_msb << 40) |
		    ((scsi_lun64_t)lun.sl_lun2_lsb << 32) |
		    ((scsi_lun64_t)lun.sl_lun3_msb << 24) |
		    ((scsi_lun64_t)lun.sl_lun3_lsb << 16) |
		    ((scsi_lun64_t)lun.sl_lun4_msb <<  8) |
		    (scsi_lun64_t)lun.sl_lun4_lsb;
	}
	return (lun64);
}

scsi_lun_t
scsi_lun64_to_lun(scsi_lun64_t lun64)
{
	scsi_lun_t	lun;

	if (lun64 <= (((0xFF & ~SCSI_LUN_AM_MASK) << 8) | 0xFF)) {
		/*
		 * lun64 is in Solaris 'unit-address compatibility' form.
		 */
		lun.sl_lun1_msb = SCSI_LUN_AM_PDEV | (lun64 >> 8);
		lun.sl_lun1_lsb = (uchar_t)lun64;
		lun.sl_lun2_msb = 0;
		lun.sl_lun2_lsb = 0;
		lun.sl_lun3_msb = 0;
		lun.sl_lun3_lsb = 0;
		lun.sl_lun4_msb = 0;
		lun.sl_lun4_lsb = 0;
	} else {
		/* lun64 is in full 64 bit LUN format. */
		lun.sl_lun1_msb = (uchar_t)(lun64 >> 56);
		lun.sl_lun1_lsb = (uchar_t)(lun64 >> 48);
		lun.sl_lun2_msb = (uchar_t)(lun64 >> 40);
		lun.sl_lun2_lsb = (uchar_t)(lun64 >> 32);
		lun.sl_lun3_msb = (uchar_t)(lun64 >> 24);
		lun.sl_lun3_lsb = (uchar_t)(lun64 >> 16);
		lun.sl_lun4_msb = (uchar_t)(lun64 >>  8);
		lun.sl_lun4_lsb = (uchar_t)(lun64);
	}
	return (lun);
}

/*
 * This routine returns the true length of the ascii inquiry fields that are to
 * be created by removing the padded spaces at the end of the inquiry data.
 * This routine was designed for trimming spaces from the vid, pid and revision
 * which are defined as being left aligned.  In addition, we return 0 length
 * if the field is full of all 0's or spaces, indicating to the caller that
 * the device was not ready to return the inquiry data as per note 65 in
 * the scsi-2 spec.
 */
int
scsi_ascii_inquiry_len(char *field, size_t length)
{
	int retval;
	int trailer;
	char *p;

	retval = length;

	/*
	 * The vid, pid and revision are left-aligned ascii fields within the
	 * inquiry data.  Here we trim the end of these fields by discounting
	 * length associated with trailing spaces or NULL bytes.  The remaining
	 * bytes shall be only graphics codes - 0x20 through 0x7e as per the
	 * scsi spec definition.  If we have all 0's or spaces, we return 0
	 * length.  For devices that store inquiry data on the device, they
	 * can return 0's or spaces in these fields until the data is avail-
	 * able from the device (See NOTE 65 in the scsi-2 specification
	 * around the inquiry command.)  We don't want to create a field in
	 * the case of a device not able to return valid data.
	 */
	trailer = 1;
	for (p = field + length - 1; p >= field; p--) {
		if (trailer) {
			if ((*p == ' ') || (*p == '\0')) {
				retval--;
				continue;
			}
			trailer = 0;
		}

		/* each char must be within 0x20 - 0x7e */
		if (*p < 0x20 || *p > 0x7e) {
			retval = -1;
			break;
		}

	}

	return (retval);
}
