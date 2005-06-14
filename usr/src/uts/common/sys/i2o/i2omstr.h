/*
 * Copyright (c) 1998-1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */

/*
 * *****************************************************************************
 *
 * All software on this website is made available under the following terms and
 * conditions.  By downloading this software, you agree to abide by these terms
 * and conditions with respect to this software.
 *
 * I2O SIG All rights reserved.
 *
 * These header files are provided, pursuant to your I2O SIG membership
 * agreement, free of charge on an as-is basis without warranty of any kind,
 * either express or implied, including but not limited to, implied warranties
 * or merchantability and fitness for a particular purpose.  I2O SIG does not
 * warrant that this program will meet the user's requirements or that the
 * operation of these programs will be uninterrupted or error-free.
 * Acceptance and use of this program constitutes the user's understanding
 * that he will have no recourse to I2O SIG for any actual or consequential
 * damages including, but not limited to, loss profits arising out of use
 * or inability to use this program.
 *
 * Member is permitted to create derivative works to this header-file program.
 * However, all copies of the program and its derivative works must contain the
 * I2O SIG copyright notice.
 *
 * *****************************************************************************
 */

#ifndef	_SYS_I2OMSTOR_H
#define	_SYS_I2OMSTOR_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include	<sys/i2o/i2omsg.h>	/* the Base Message file */
#include	<sys/types.h>



#define	I2OMSTOR_REV 1_5_1	/* Header file revision string */


/*
 * ****************************************************************************
 *
 *    I2OMStor.h -- I2O Random Block Storage Devices Class Message defintion
 *			file
 *
 *    This file contains information presented in Chapter 6, Section 4 of
 *    the I2O Specification.
 *
 *  Revision History: (Revision History tracks the revision number of the I2O
 *	specification)
 *
 *	.92 - First marked revsion used for Proof of Concept.
 *	.93 - Change to match the rev .93 of the spec.
 *	.95 - Updated to Rev .95 of 2/5/96.
 *	1.00 - Checked and Updated against spec version 1.00 4/9/96.
 *	1.xx - Updated to the 1.x version of the I2O Specification (11/04/96).
 *		(RAID disk parameter group definition is not complete.)
 *	1.xx - 11/06/96 1) Changed to new SGL addressing nomenclature.
 *		2) Changed I2O_BSA_FLAGS reference to i2o_bsa_ctl_flags_t.
 *		3) Added BSA request message definitions.
 *		4) Commented out subclass and RAID request message definitions.
 *	1.xx - 11/11/96
 *		1) Updated BSA Cache Control parameters group definitions.
 *	1.xx - 11/13/96
 *		1) Changed messages definitions from "I20" to "I2O".
 *		2) Fixed I2O_BSA_MEDIA_EJECT references.
 *		3) Added "DSC" to Detailed Status Code definitions.
 *	1.xx   11/15/96 - Added #pragma statments for i960.
 *	1.5d   03/05/97 - Update for spec. draft version 1.5d.
 *		1) Added "_BSA" designation to the three reply messages.
 *		2) Added BSA_TIMEOUT DSC.
 *	1.5d   04/11/97 - Corrections from review cycle:
 *		1) Added reserved1 field to OPERATIONAL_CONTROL parameter group.
 *		2) Added reserved2 field to ERROR_LOG parameter group.
 *		3) Added reserved1 field to HIST_STATS parameter group.
 *		4) Added reserved2 field to HIST_STATS parameter group.
 *		5) Added reserved1 field to STORAGE_HIST_STATS parameter group.
 *		6) Added reserved2 field to STORAGE_HIST_STATS parameter group.
 *		7) Removed double underscore from MEDIA_INFO parameter group.
 *	1.5.1  05/02/97 - Corrections from review cycle:
 *		1) Change reply templates to include RetryCount field.
 *		2) Add Aborted Operation reply message.
 *		3) Remove #include for i2outil.h.
 *		4) Add field to 32-bit align CACHE_CONTROL parameter group.
 *		5) Add optional RAID parameter group definitions.
 *		6) Add fields to 32-bit align REDUNDANCY parameter group.
 *		7) Add fields to 32-bit align COMPONENT_SPARES parm group.
 *		8) Add fields to 32-bit align ASSOCIATION parameter group.
 *		9) Add revision string.
 *		10) Convert tabs to spaces.
 *		11) New disclaimer.
 *
 * ****************************************************************************
 */

/*
 * ****************************************************************************
 *  NOTES:
 *
 *   Gets, reads, receives, etc. are all even numbered functions.
 *   Sets, writes, sends, etc. are all odd numbered functions.
 *   Functions that both send and receive data can be either but an attempt
 *   is made to use the function number that indicates the greater transfer
 *   amount.  Functions that do not send or receive data use odd function
 *   numbers.
 *
 *   Some functions are synonyms like read, receive and send, write.
 *
 *   All common functions will have a code of less than 0x80.
 *   Unique functions to a class will start at 0x80.
 *   Executive Functions start at 0xA0.
 *
 *   Utility Message function codes range from 0 - 0x1f
 *   Base Message function codes range from 0x20 - 0xfe
 *   Private Message function code is 0xff.
 * *****************************************************************************
 */




/*
 *  Random Block Storage Class specific functions
 *
 *  Although the names are block storage class specific, the values
 *  assigned are common with other classes when applicable.
 */

#define	I2O_BSA_BLOCK_READ		0x30
#define	I2O_BSA_BLOCK_REASSIGN		0x71
#define	I2O_BSA_BLOCK_WRITE		0x31
#define	I2O_BSA_BLOCK_WRITE_VERIFY	0x33
#define	I2O_BSA_CACHE_FLUSH		0x37
#define	I2O_BSA_DEVICE_RESET		0x27
#define	I2O_BSA_MEDIA_EJECT		0x43
#define	I2O_BSA_MEDIA_FORMAT		0x45
#define	I2O_BSA_MEDIA_LOCK		0x49
#define	I2O_BSA_MEDIA_MOUNT		0x41
#define	I2O_BSA_MEDIA_UNLOCK		0x4B
#define	I2O_BSA_MEDIA_VERIFY		0x35
#define	I2O_BSA_POWER_MANAGEMENT	0x70
#define	I2O_BSA_STATUS_CHECK		0x25

/* RAID Additions. */
/*
 * #define	I2O_MANAGEMENT			0x81
 * #define	I2O_DIAGNOSTICS			0x83
 * #define	I2O_INSTRUMENTATION		0x85
 */

/* Detailed Status Codes for Random Block Storage operations */

#define	I2O_BSA_DSC_SUCCESS		0x0000
#define	I2O_BSA_DSC_MEDIA_ERROR		0x0001
#define	I2O_BSA_DSC_ACCESS_ERROR	0x0002
#define	I2O_BSA_DSC_DEVICE_FAILURE	0x0003
#define	I2O_BSA_DSC_DEVICE_NOT_READY	0x0004
#define	I2O_BSA_DSC_MEDIA_NOT_PRESENT	0x0005
#define	I2O_BSA_DSC_MEDIA_LOCKED	0x0006
#define	I2O_BSA_DSC_MEDIA_FAILURE	0x0007
#define	I2O_BSA_DSC_PROTOCOL_FAILURE	0x0008
#define	I2O_BSA_DSC_BUS_FAILURE		0x0009
#define	I2O_BSA_DSC_ACCESS_VIOLATION	0x000A
#define	I2O_BSA_DSC_WRITE_PROTECTED	0x000B
#define	I2O_BSA_DSC_DEVICE_RESET	0x000C
#define	I2O_BSA_DSC_VOLUME_CHANGED	0x000D
#define	I2O_BSA_DSC_TIMEOUT		0x000E


/* ************************************************************************** */

/* Block Storage Parameter Groups */

/* ************************************************************************* */

/* Block Storage Configuration and Operating Structures and Defines */

/* Block Storage Parameter Groups */

#define	I2O_BSA_DEVICE_INFO_GROUP_NO			0x0000
#define	I2O_BSA_OPERATIONAL_CONTROL_GROUP_NO		0x0001
#define	I2O_BSA_POWER_CONTROL_GROUP_NO			0x0002
#define	I2O_BSA_CACHE_CONTROL_GROUP_NO			0x0003
#define	I2O_BSA_MEDIA_INFO_GROUP_NO			0x0004
#define	I2O_BSA_ERROR_LOG_GROUP_NO			0x0005

/* Block Storage Optional Historical Statistics Parameter Groups */

#define	I2O_BSA_HISTORICAL_STATS_CONTROL_GROUP_NO	0x0180
#define	I2O_BSA_STORAGE_HISTORICAL_STATS_GROUP_NO	0x0181
#define	I2O_BSA_CACHE_HISTORICAL_STATS_GROUP_NO		0x0182

/* Block Storage Optional RAID Disk Parameter Groups */

#define	I2O_BSA_VOLUME_SET_INFORMATION_GROUP_NO		0x0200
#define	I2O_BSA_PROTECTED_SPACE_EXTENT_GROUP_NO		0x0201
#define	I2O_BSA_AGGREGATE_PROT_SPACE_EXT_GROUP_NO	0x0202
#define	I2O_BSA_PHYSICAL_EXTENT_GROUP_NO		0x0203
#define	I2O_BSA_AGGREGATE_PHYSICAL_EXT_GROUP_NO		0x0204
#define	I2O_BSA_REDUNDANCY_GROUP_NO			0x0205
#define	I2O_BSA_COMPONENT_SPARES_GROUP_NO		0x0206
#define	I2O_BSA_ASSOCIATION_TABLE_GROUP_NO		0x0207


/* - 0000h - Device Information Parameters Group defines */

/* Device Type */

#define	I2O_BSA_DEVICE_TYPE_DIRECT		0x00
#define	I2O_BSA_DEVICE_TYPE_WORM		0x04
#define	I2O_BSA_DEVICE_TYPE_CDROM		0x05
#define	I2O_BSA_DEVICE_TYPE_OPTICAL		0x07

/* Device Capability Support */

#define	I2O_BSA_DEV_CAP_CACHING			0x00000001
#define	I2O_BSA_DEV_CAP_MULTI_PATH		0x00000002
#define	I2O_BSA_DEV_CAP_DYNAMIC_CAPACITY	0x00000004
#define	I2O_BSA_DEV_CAP_REMOVABLE_MEDIA		0x00000008
#define	I2O_BSA_DEV_CAP_REMOVEABLE_DEVICE	0x00000010
#define	I2O_BSA_DEV_CAP_READ_ONLY		0x00000020
#define	I2O_BSA_DEV_CAP_LOCKOUT			0x00000040
#define	I2O_BSA_DEV_CAP_BOOT_BYPASS		0x00000080
#define	I2O_BSA_DEV_CAP_COMPRESSION		0x00000100
#define	I2O_BSA_DEV_CAP_DATA_SECURITY		0x00000200
#define	I2O_BSA_DEV_CAP_RAID			0x00000400

/* Device States */

#define	I2O_BSA_DEV_STATE_CACHING		0x00000001
#define	I2O_BSA_DEV_STATE_POWERED_ON		0x00000002
#define	I2O_BSA_DEV_STATE_READY			0x00000004
#define	I2O_BSA_DEV_STATE_MEDIA_LOADED		0x00000008
#define	I2O_BSA_DEV_STATE_DEVICE_LOADED		0x00000010
#define	I2O_BSA_DEV_STATE_READ_ONLY		0x00000020
#define	I2O_BSA_DEV_STATE_LOCKOUT		0x00000040
#define	I2O_BSA_DEV_STATE_BOOT_BYPASS		0x00000080
#define	I2O_BSA_DEV_STATE_COMPRESSION		0x00000100
#define	I2O_BSA_DEV_STATE_DATA_SECURITY		0x00000200
#define	I2O_BSA_DEV_STATE_RAID			0x00000400


/* - 0001h - Operational Control Parameters Group defines */

/* No definition required */


/* - 0002h - Power Control Parameters Group defines */

/* On Access */

#define	I2O_BSA_POWERED_UP_ON_ACCESS	0x00000001
#define	I2O_BSA_LOAD_ON_ACCESS		0x00000002


/* - 0003h - Cache Control Parameters Group defines */

/* Write Policy */

#define	I2O_BSA_NO_WRITE_CACHE		0x00
#define	I2O_BSA_WRITE_TO_CACHE		0x01
#define	I2O_BSA_WRITE_THRU_CACHE	0x02

/* Read Policy */

#define	I2O_BSA_NO_READ_CACHE		0x00
#define	I2O_BSA_READ_CACHE		0x01
#define	I2O_BSA_READ_AHEAD_CACHE	0x02
#define	I2O_BSA_READ_READ_AHEAD_CACHE	0x03

/* Error Correction */

#define	I2O_BSA_ERR_COR_NONE		0x00
#define	I2O_BSA_ERR_COR_UNKNOWN		0x01
#define	I2O_BSA_ERR_COR_OTHER		0x02
#define	I2O_BSA_ERR_COR_PARITY		0x03
#define	I2O_BSA_ERR_COR_SINGLE_BIT_ECC	0x04
#define	I2O_BSA_ERR_COR_MULTI_BIT_ECC	0x05


/* - 0004h - Media Information Parameters Group defines */

/* No definition required */


/* - 0005h - Error Log Parameters Group defines */

/* No definition required */


/* - 0180h - Historical Statistics Control Parameters Group defines */

/* Statistis Control */

#define	I2O_BSA_STAT_CTL_STORAGE_ENABLE		0x01
#define	I2O_BSA_STAT_CTL_CACHE_ENABLE		0x02


/* - 0181h - Storage Historical Statistics Parameter Group defines */

/* No definition required */


/* - 0182h - Cache Historical Statistics Parameter Group defines */

/* No definition required */


/* - 0200H - Volume Set Information Parameter Group defines */

/* No definition required */


/* - 0201h - Protected Space Extent Parameter Group defines */

/* Data Stripe Granularity */

#define	I2O_BSA_DATA_STRIPE_OTHER		0x00
#define	I2O_BSA_DATA_STRIPE_UNKNOWN		0x01
#define	I2O_BSA_DATA_STRIPE_BITS		0x02
#define	I2O_BSA_DATA_STRIPE_BYTES		0x03
#define	I2O_BSA_DATA_STRIPE_16BIT_WORDS		0x04
#define	I2O_BSA_DATA_STRIPE_32BIT_DWORDS	0x05
#define	I2O_BSA_DATA_STRIPE_BLOCKS		0x06

/* - 0202h - Aggregate Protected Space Extent Parameter Group defines */

/* No definition required */


/* - 0203h - Physical Extent Parameter Group defines */

/* Granularity Unit */

#define	I2O_BSA_GRANULARITY_OTHER		0x00
#define	I2O_BSA_GRANULARITY_UNKNOWN		0x01
#define	I2O_BSA_GRANULARITY_BITS		0x02
#define	I2O_BSA_GRANULARITY_BYTES		0x03
#define	I2O_BSA_GRANULARITY_16BIT_WORDS		0x04
#define	I2O_BSA_GRANULARITY_32BIT_DWORDS	0x05
#define	I2O_BSA_GRANULARITY_BLOCKS		0x06


/* - 0204h - Aggregate Physical Extent Parameter Group defines */

/* No definition required */


/* - 0205h - Redundancy Parameter Group defines */

/* Redundancy Type */

#define	I2O_BSA_REDUNDANCY_OTHER		0x00
#define	I2O_BSA_REDUNDANCY_UNKNOWN		0x01
#define	I2O_BSA_REDUNDANCY_NONE			0x02
#define	I2O_BSA_REDUNDANCY_COPY			0x03
#define	I2O_BSA_REDUNDANCY_XOR			0x04
#define	I2O_BSA_REDUNDANCY_P_Q			0x05
#define	I2O_BSA_REDUNDANCY_S			0x06
#define	I2O_BSA_REDUNDANCY_P_S			0x07


/* - 0206h - Component Spares Parameter Group defines */

/* Spare Functioning State */

#define	I2O_BSA_SPARE_STATE_OTHER		0x00
#define	I2O_BSA_SPARE_STATE_UNKNOWN		0x01
#define	I2O_BSA_SPARE_STATE_INACTIVE		0x02
#define	I2O_BSA_SPARE_STATE_ACTIVE		0x03
#define	I2O_BSA_SPARE_STATE_LOAD_BALANCE	0x04


/* - 0207h - Association Table Parameter Group defines */

/* Type */

#define	I2O_BSA_ASSOC_TYPE_PHYSICAL		0x00
#define	I2O_BSA_ASSOC_TYPE_LOGICAL		0x01
#define	I2O_BSA_ASSOC_TYPE_LOG_TO_PHYS		0x02
#define	I2O_BSA_ASSOC_TYPE_PROTECTION		0x03
#define	I2O_BSA_ASSOC_TYPE_SPARE		0x04
#define	I2O_BSA_ASSOC_TYPE_CACHE		0x05
#define	I2O_BSA_ASSOC_TYPE_SOFTWARE		0x06

/* Object 1 Type */

#define	I2O_BSA_OBJECT_1_CONTROLLER		0x00
#define	I2O_BSA_OBJECT_1_DEVICE			0x01
#define	I2O_BSA_OBJECT_1_BUS_PORT		0x02
#define	I2O_BSA_OBJECT_1_VOLUME_SET		0x03
#define	I2O_BSA_OBJECT_1_PROT_SPACE_EXT		0x04
#define	I2O_BSA_OBJECT_1_AGG_PROT_SPACE_EXT	0x05
#define	I2O_BSA_OBJECT_1_PHYSICAL_EXT		0x06
#define	I2O_BSA_OBJECT_1_AGG_PHYSICAL_EXT	0x07
#define	I2O_BSA_OBJECT_1_REDUNDANCY		0x08
#define	I2O_BSA_OBJECT_1_CACHE			0x09
#define	I2O_BSA_OBJECT_1_SOFTWARE		0x0A

/* Object 2 Type */

#define	I2O_BSA_OBJECT_2_CONTROLLER		0x00
#define	I2O_BSA_OBJECT_2_DEVICE			0x01
#define	I2O_BSA_OBJECT_2_BUS_PORT		0x02
#define	I2O_BSA_OBJECT_2_VOLUME_SET		0x03
#define	I2O_BSA_OBJECT_2_PROT_SPACE_EXT		0x04
#define	I2O_BSA_OBJECT_2_AGG_PROT_SPACE_EXT	0x05
#define	I2O_BSA_OBJECT_2_PHYSICAL_EXT		0x06
#define	I2O_BSA_OBJECT_2_AGG_PHYSICAL_EXT	0x07
#define	I2O_BSA_OBJECT_2_REDUNDANCY		0x08
#define	I2O_BSA_OBJECT_2_CACHE			0x09
#define	I2O_BSA_OBJECT_2_SOFTWARE		0x0A




/* Block Storage Group 0000h - Device Information Parameter Group */

typedef struct i2o_bsa_device_info_scalar {
    uint8_t		DeviceType;
    uint8_t		NumberOfPaths;
    uint16_t		PowerState;
    uint32_t		BlockSize;
    uint64_t		DeviceCapacity;
    uint32_t		DeviceCapabilitySupport;
    uint32_t		DeviceState;
} i2o_bsa_device_info_scalar_t;


/* Block Storage Group 0001h - Operational Control Parameter Group */

typedef struct i2o_bsa_operational_control_scalar {
    uint8_t		AutoReassign;
    uint8_t		ReassignTolerance;
    uint8_t		RetryAttempts;
    uint8_t		reserved1;
    uint32_t		ReassignSize;
    uint32_t		ExpectedTimeout;
    uint32_t		RWVTimeout;
    uint32_t		RWVTimeoutBase;
    uint32_t		TimeoutBase;
    uint32_t		OrderedRequestDepth;
    uint32_t		AtomicWriteSize;
} i2o_bsa_operational_control_scalar_t;


/* Block Storage Group 0002h - Power Control Parameter Group */

typedef struct i2o_bsa_power_control_scalar {
    uint32_t		PowerdownTimeout;
    uint32_t		OnAccess;
} i2o_bsa_power_control_scalar_t;


/* Block Storage Group 0003h - Cache Control Parameter Group */

typedef struct i2o_bsa_cache_control_scalar {
    uint32_t		TotalCacheSize;
    uint32_t		ReadCacheSize;
    uint32_t		WriteCacheSize;
    uint8_t		WritePolicy;
    uint8_t		ReadPolicy;
    uint8_t		ErrorCorrection;
    uint8_t		reserved1;	/* Note: not in 1.5 spec. */
} i2o_bsa_cache_control_scalar_t;


/* Block Storage Group 0004h - Media Information Parameter Group */

typedef struct i2o_bsa_media_info_scalar {
    uint64_t		Capacity;
    uint32_t		BlockSize;
} i2o_bsa_media_info_scalar_t;


/* Block Storage Group 0005h - Error Log Parameter Group */

typedef struct i2o_bsa_error_log_table {
    uint16_t		ErrorDataIndex;
    uint8_t		Function;
    uint8_t		RetryCount;
    uint16_t		DetailedErrorCode;
    uint16_t		reserved2;
    uint64_t		TimeStamp;
    uint32_t		UserInfo;
} i2o_bsa_error_log_table_t;


/* Block Storage Group 0180h - Optional Historical STATS Support/Control */

typedef struct i2o_bsa_hist_stats_scalar {
    uint8_t		StatisticsControl;
    uint8_t		reserved1;
    uint16_t		reserved2;
    uint32_t		StorageStatistics;
    uint32_t		CacheStatistics;
} i2o_bsa_hist_stats_scalar_t;


/* Block Storage Group 0181h - Optional Storage Historical STATS */

typedef struct i2o_bsa_storage_hist_stats_scalar {
    uint64_t		ReadCommands;
    uint64_t		WriteCommands;
    uint8_t		DataUnit;
    uint8_t		reserved1;
    uint16_t		reserved2;
    uint64_t		IORange1Read;
    uint64_t		IORange2Read;
    uint64_t		IORange3Read;
    uint64_t		IORange4Read;
    uint64_t		IORange1Write;
    uint64_t		IORange2Write;
    uint64_t		IORange3Write;
    uint64_t		IORange4Write;
    uint64_t		NumberSeeks;
} i2o_bsa_storage_hist_stats_scalar_t;


/* Block Storage Group 0182h - Optional Cache Historical STATS */

typedef struct i2o_bsa_cache_hist_stats_scalar {
    uint64_t		CacheAccess;
    uint64_t		CacheHit;
    uint64_t		PartialCacheHit;
    uint64_t		HitDataSize;
    uint32_t		ValidUsage;
    uint32_t		DirtyUsage;
    uint32_t		TimeLastFault;
    uint32_t		LastFaultFailure;
} i2o_bsa_cache_hist_stats_scalar_t;


/* Block Storage Group 0200h - Optional Volume Set Information */

typedef struct i2o_bsa_volume_info_scalar {
    uint8_t		Name[64];
    uint64_t		TotalStorageCapacity;
    uint64_t		StripeLength;
    uint64_t		InterleaveDepth;
} i2o_bsa_volume_info_scalar_t;


/* Block Storage Group 0201h - Optional Protected Space Extent */

typedef struct i2o_bsa_pro_space_ext_scalar {
    uint64_t		StartAddress;
    uint64_t		NumberBlocks;
    uint32_t		BlockSize;
    uint32_t		DataStripeGranularity;
    uint32_t		DataStripeLength;
} i2o_bsa_pro_space_ext_scalar_t;


/* Block Storage Group 0202h - Optional Aggregate Protected Space Extent */

typedef struct i2o_bsa_agg_prot_space_ext_scalar {
    uint64_t		NumberBlocks;
} i2o_bsa_agg_prot_space_ext_scalar_t;


/* Block Storage Group 0203h - Optional Physical Extent */

typedef struct i2o_bsa_phys_ext_scalar {
    uint64_t		StartAddress;
    uint64_t		NumberBlocks;
    uint32_t		BlockSize;
    uint32_t		GranularityUnit;
    uint64_t		CheckDataInterleave;
    uint64_t		CheckData;
    uint64_t		UserData;
} i2o_bsa_phys_ext_scalar_t;


/* Block Storage Group 0204h - Optional Aggregate Physical Extent */

typedef struct i2o_bsa_agg_phys_ext_scalar {
    uint64_t		NumberBlocks;
    uint64_t		CheckData;
} i2o_bsa_agg_phys_ext_scalar_t;


/* Block Storage Group 0205h - Optional Redundancy Table */

typedef struct i2o_bsa_redundancy_scalar {
    uint8_t	RedundancyType;
    uint8_t	reserved1;	/* Note: not in 1.5 spec. */
    uint16_t	reserved2;	/* Note: not in 1.5 spec. */
} i2o_bsa_redundancy_scalar_t;


/* Block Storage Group 0206h - Optional Component Spares */

typedef struct i2o_bsa_component_spares_table {
    uint8_t	RowNumber;
    uint8_t	SpareType;
    uint8_t	ToBeSparedIndex;
    uint8_t	SparedIndex;
    uint8_t	SpareFunctioningState;
    uint8_t	reserved1;	/* Note: not in 1.5 spec. */
    uint16_t	reserved2;	/* Note: not in 1.5 spec. */
} i2o_bsa_component_spares_table_t;


/* Block Storage Group 0207h - Optional Association Table */

typedef struct i2o_bsa_association_table {
    uint8_t	RowNumber;
    uint8_t	Type;
    uint8_t	Object1Type;
    uint8_t	Object1Index;
    uint8_t	Object2Type;
    uint8_t	Object2Index;
    uint16_t	reserved2;	/* Note: not in 1.5 spec. */
} i2o_bsa_association_table_t;



/* I2O BSA Block Storage Event Indicator Assignment */

#define	I2O_BSA_EVENT_VOLUME_LOAD		0x00000001
#define	I2O_BSA_EVENT_VOLUME_UNLOAD		0x00000002
#define	I2O_BSA_EVENT_VOLUME_UNLOAD_REQUEST	0x00000004
#define	I2O_BSA_EVENT_CAPACITY_CHANGE		0x00000008
#define	I2O_BSA_EVENT_SCSI_SMART		0x00000010




/* Block Storage Class Specific Message Definitions */


/* I2O Block Storage Reply Message Frame Template */

typedef struct i2o_bsa_reply_message_frame {
    i2o_message_frame_t		StdMessageFrame;
    i2o_transaction_context_t	TransactionContext;
    uint16_t			DetailedStatusCode;
    uint8_t			RetryCount;
    uint8_t			ReqStatus;
/* 				ReplyPayload	*/
} i2o_bsa_reply_message_frame_t;



/* I2O Block Storage Successful Completion Reply Message Frame */

typedef struct i2o_bsa_success_reply_message_frame {
    i2o_bsa_reply_message_frame_t BsaReplyFrame;
    uint32_t	TransferCount;
} i2o_bsa_success_reply_message_frame_t;



/* I2O Block Storage Aborted Operation Reply Message Frame */

typedef struct i2o_bsa_abort_reply_message_frame {
    i2o_bsa_reply_message_frame_t	BsaReplyFrame;
} i2o_bsa_abort_reply_message_frame_t;



/* I2O Block Storage Progress Report Reply Message Frame */

typedef struct i2o_bsa_progress_reply_message_frame {
    i2o_bsa_reply_message_frame_t	BsaReplyFrame;
    uint8_t				PercentComplete;
    uint8_t				Reserved[3];
} i2o_bsa_progress_reply_message_frame_t;


/* I2O Block Storage Error Report Reply Message Frame */

typedef struct i2o_bsa_error_reply_message_frame {
    i2o_bsa_reply_message_frame_t	BsaReplyFrame;
    uint32_t				TransferCount;
    uint64_t				LogicalByteAddress;
} i2o_bsa_error_reply_message_frame_t;




/* I2O BSA request message flag definitions */

/* I2O BSA Control Flags */

typedef	uint16_t	i2o_bsa_ctl_flags_t;

#define	I2O_BSA_FLAG_PROGRESS_REPORT	0x0080

/* I2O BSA Block Read Message Control Flags */

typedef uint16_t	i2o_bsa_read_flags_t;
#define	I2O_BSA_RD_FLAG_DONT_RETRY	0x0001
#define	I2O_BSA_RD_FLAG_SOLO		0x0002
#define	I2O_BSA_RD_FLAG_CACHE_READ	0x0004
#define	I2O_BSA_RD_FLAG_READ_PREFETCH	0x0008
#define	I2O_BSA_RD_FLAG_CACHE_DATA	0x0010

/* I2O BSA Block Write Message Control Flags */

typedef	uint16_t	i2o_bsa_write_flags_t;
#define	I2O_BSA_WR_FLAG_DONT_RETRY	0x0001
#define	I2O_BSA_WR_FLAG_SOLO		0x0002
#define	I2O_BSA_WR_FLAG_DONT_CACHE	0x0004
#define	I2O_BSA_WR_FLAG_WRITE_THRU	0x0008
#define	I2O_BSA_WR_FLAG_WRITE_TO	0x0010

/* I2O BSA Device Reset Message Control Flags */

typedef	uint16_t	i2o_bsa_reset_flags_t;
#define	I2O_BSA_FLAG_HARD_RESET	0x0001

/* I2O BSA Media Verify Message Control Flags */

typedef	uint16_t	i2o_bsa_verify_flags_t;
/* Progress Report flag definition is valid  */
#define	I2O_BSA_ERROR_CORRECTION	0x0040


/* I2O BSA Removeable Media Identifier values */

typedef	uint32_t	i2o_bsa_media_id_t;
#define	I2O_BSA_MEDIA_ID_CURRENT_MOUNTED    0xFFFFFFFF


/* I2O BSA Removeable Media Load Flags */

typedef	uint8_t	i2o_bsa_load_flags_t;
#define	I2O_BSA_LOAD_FLAG_MEDIA_LOCK    0x80


/* I2O BSA Power Management Operation values */

typedef	uint8_t	i2o_bsa_operation_t;
#define	I2O_BSA_POWER_MGT_PARTIAL_POWER_UP		0x01
#define	I2O_BSA_POWER_MGT_POWER_UP			0x02
#define	I2O_BSA_POWER_MGT_POWER_UP_LOAD			0x03
#define	I2O_BSA_POWER_MGT_QUIESCE_DEVICE		0x20
#define	I2O_BSA_POWER_MGT_PARTIAL_POWER_DOWN		0x21
#define	I2O_BSA_POWER_MGT_PARTIAL_POWER_DOWN_UNLOAD	0x22
#define	I2O_BSA_POWER_MGT_POWER_DOWN_UNLOAD		0x23
#define	I2O_BSA_POWER_MGT_POWER_DOWN_RETAIN		0x24



/* I2O BSA Block Read Message Frame */

typedef struct i2o_bsa_read_message {
    i2o_message_frame_t		StdMessageFrame;
    i2o_transaction_context_t	TransactionContext;
    i2o_bsa_read_flags_t	ControlFlags;
    uint8_t			TimeMultiplier;
    uint8_t			FetchAhead;
    uint32_t			TransferByteCount;
    uint64_t			LogicalByteAddress;
    i2o_sg_element_t		SGL;
} i2o_bsa_read_message_t;



/* I2O BSA Block Reassign Message Frame */

typedef struct i2o_bsa_block_reassign_message {
    i2o_message_frame_t		StdMessageFrame;
    i2o_transaction_context_t	TransactionContext;
    uint16_t			Reserved1;
    uint8_t			TimeMultiplier;
    uint8_t			Reserved2;
    i2o_sg_element_t		SGL;
} i2o_bsa_block_reassign_message_t;



/* I2O BSA Block Write Message Frame */

typedef struct i2o_bsa_write_message {
    i2o_message_frame_t		StdMessageFrame;
    i2o_transaction_context_t	TransactionContext;
    i2o_bsa_write_flags_t	ControlFlags;
    uint8_t			TimeMultiplier;
    uint8_t			Reserved;
    uint32_t			TransferByteCount;
    uint64_t			LogicalByteAddress;
    i2o_sg_element_t		SGL;
} i2o_bsa_write_message_t;



/* I2O BSA Block Write and Verify Message Frame */

typedef struct i2o_bsa_write_verify_message {
    i2o_message_frame_t		StdMessageFrame;
    i2o_transaction_context_t	TransactionContext;
    i2o_bsa_write_flags_t	ControlFlags;
    uint8_t			TimeMultiplier;
    uint8_t			Reserved;
    uint32_t			TransferByteCount;
    uint64_t			LogicalByteAddress;
    i2o_sg_element_t		SGL;
} i2o_bsa_write_verify_message_t;



/* I2O BSA Cache Flush Message Frame */

typedef struct i2o_bsa_cache_flush_message {
    i2o_message_frame_t		StdMessageFrame;
    i2o_transaction_context_t	TransactionContext;
    i2o_bsa_ctl_flags_t		ControlFlags;
    uint8_t			TimeMultiplier;
    uint8_t			Reserved;
} i2o_bsa_cache_flush_message_t;



/* I2O BSA Device Reset Message Frame */

typedef struct _12o_bsa_device_reset_message {
    i2o_message_frame_t		StdMessageFrame;
    i2o_transaction_context_t	TransactionContext;
    i2o_bsa_reset_flags_t	ControlFlags;
    uint8_t			TimeMultiplier;
    uint8_t			Reserved;
} i2o_bsa_device_reset_message_t;



/* I2O BSA Media Eject for Removeable Media Message Frame */

typedef struct i2o_bsa_media_eject_message {
    i2o_message_frame_t		StdMessageFrame;
    i2o_transaction_context_t	TransactionContext;
    i2o_bsa_media_id_t		MediaIdentifier;
} i2o_bsa_media_eject_message_t;



/* I2O BSA Media Lock Message Frame */

typedef struct i2o_bsa_media_lock_message {
    i2o_message_frame_t		StdMessageFrame;
    i2o_transaction_context_t	TransactionContext;
    i2o_bsa_media_id_t		MediaIdentifier;
} i2o_bsa_media_lock_message_t;



/* I2O BSA Media Mount for Removeable Media Message Frame */

typedef struct i2o_bsa_media_mount_message {
    i2o_message_frame_t		StdMessageFrame;
    i2o_transaction_context_t	TransactionContext;
    i2o_bsa_media_id_t		MediaIdentifier;
    i2o_bsa_load_flags_t	LoadFlags;
    uint8_t			Reserved[3];
} i2o_bsa_media_mount_message_t;



/* I2O BSA Media Unlock Message Frame */

typedef struct i2o_bsa_media_unlock_message {
    i2o_message_frame_t		StdMessageFrame;
    i2o_transaction_context_t	TransactionContext;
    i2o_bsa_media_id_t		MediaIdentifier;
} i2o_bsa_media_unlock_message_t;



/* I2O BSA Media Verify Message Frame */

typedef struct i2o_bsa_media_verify_message {
    i2o_message_frame_t		StdMessageFrame;
    i2o_transaction_context_t	TransactionContext;
    i2o_bsa_verify_flags_t	ControlFlags;
    uint8_t			TimeMultiplier;
    uint8_t			Reserved;
    uint32_t			ByteCount;
    uint64_t			LogicalByteAddress;
} i2o_bsa_media_verify_message_t;



/* I2O BSA Power Management Message Frame */

typedef struct i2o_bsa_power_management_message {
    i2o_message_frame_t		StdMessageFrame;
    i2o_transaction_context_t	TransactionContext;
    i2o_bsa_ctl_flags_t		ControlFlags;
    uint8_t			TimeMultiplier;
    uint8_t			ReplyType;
    i2o_bsa_operation_t		Operation;
} i2o_bsa_power_management_message_t;



/* I2O BSA Status Check Message Frame */

typedef struct i2o_bsa_status_check_message {
    i2o_message_frame_t		StdMessageFrame;
    i2o_transaction_context_t	TransactionContext;
} i2o_bsa_status_check_message_t;


#ifdef	__cplusplus
}
#endif

#endif /* _SYS_I2OMSTOR_H */
