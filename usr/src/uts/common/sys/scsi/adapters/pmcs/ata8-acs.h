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
 *
 *
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * ATA8-ACS Definitions (subset) Working Draft AT Attachment 8 - ATA/ATAPI
 * Command Set (D1699r4c)
 */
#ifndef	_ATA8_ACS_H
#define	_ATA8_ACS_H
#ifdef	__cplusplus
extern "C" {
#endif

/*
 * ATA Command Set
 */
enum ata_opcode {
	ATA_NOP					= 0x00,
	CFA_REQUEST_EXTENDED_ERROR		= 0x03,
	DEVICE_RESET				= 0x08,
	READ_SECTORS				= 0x20,
	READ_SECTORS_EXT			= 0x24,
	READ_DMA_EXT				= 0x25,
	READ_DMA_QUEUED_EXT			= 0x26,
	READ_NATIVE_MAX_ADDRESS_EXT		= 0x27,
	READ_MULTIPLE_EXT			= 0x29,
	READ_STREAM_DMA_EXT			= 0x2A,
	READ_STREAM_EXT				= 0x2B,
	READ_LOG_EXT				= 0x2F,
	WRITE_SECTORS				= 0x30,
	WRITE_SECTORS_EXT			= 0x34,
	WRITE_DMA_EXT				= 0x35,
	WRITE_DMA_QUEUED_EXT			= 0x36,
	SET_MAX_ADDRESS_EXT			= 0x37,
	CFA_WRITE_SECTORS_WITHOUT_ERASE		= 0x38,
	WRITE_MULTIPLE_EXT			= 0x39,
	WRITE_STREAM_DMA_EXT			= 0x3A,
	WRITE_STREAM_EXT			= 0x3B,
	WRITE_DMA_FUA_EXT			= 0x3D,
	WRITE_DMA_QUEUED_FUA_EXT		= 0x3E,
	WRITE_LOG_EXT				= 0x3F,
	READ_VERIFY_SECTORS			= 0x40,
	READ_VERIFY_SECTORS_EXT			= 0x42,
	WRITE_UNCORRECTABLE_EXT			= 0x45,
	READ_LOG_DMA_EXT			= 0x47,
	CONFIGURE_STREAM			= 0x51,
	WRITE_LOG_DMA_EXT			= 0x57,
	TRUSTED_NON_DATA			= 0x5B,
	TRUSTED_RECEIVE				= 0x5C,
	TRUSTED_RECEIVE_DMA			= 0x5D,
	TRUSTED_SEND				= 0x5E,
	TRUSTED_SEND_DMA			= 0x5E,
	READ_FPDMA_QUEUED			= 0x60,
	WRITE_FPDMA_QUEUED			= 0x61,
	CFA_TRANSLATE_SECTOR			= 0x87,
	EXECUTE_DEVICE_DIAGNOSTIC		= 0x90,
	DOWNLOAD_MICROCODE			= 0x92,
	PACKET					= 0xA0,
	IDENTIFY_PACKET_DEVICE			= 0xA1,
	SERVICE					= 0xA2,
	SMART					= 0xB0,
	DEVICE_CONFIGURATION_OVERLAY		= 0xB1,
	NV_CACHE				= 0xB6,
	CFA_ERASE_SECTORS			= 0xC0,
	READ_MULTIPLE				= 0xC4,
	WRITE_MULTIPLE				= 0xC5,
	SET_MULTIPLE_MODE			= 0xC6,
	READ_DMA_QUEUED				= 0xC7,
	READ_DMA				= 0xC8,
	WRITE_DMA				= 0xCA,
	WRITE_DMA_QUEUED			= 0xCC,
	CFA_WRITE_MULTIPLE_WITHOUT_ERASE	= 0xCD,
	WRITE_MULTIPLE_FUA_EXT			= 0xCE,
	CHECK_MEDIA_CARD_TYPE			= 0xD1,
	STANDBY_IMMEDIATE			= 0xE0,
	IDLE_IMMEDIATE				= 0xE1,
	STANDBY					= 0xE2,
	IDLE					= 0xE3,
	ATA_READ_BUFFER				= 0xE4,
	CHECK_POWER_MODE			= 0xE5,
	SLEEP					= 0xE6,
	FLUSH_CACHE				= 0xE7,
	ATA_WRITE_BUFFER			= 0xE8,
	FLUSH_CACHE_EXT				= 0xEA,
	IDENTIFY_DEVICE				= 0xEC,
	MEDIA_EJECT				= 0xED,
	SET_FEATURES				= 0xEF,
	SECURITY_SET_PASSWORD			= 0xF1,
	SECURITY_UNLOCK				= 0xF2,
	SECURITY_ERASE_PREPARE			= 0xF3,
	SECURITY_ERASE_UNIT			= 0xF4,
	SECURITY_FREEZE_LOCK			= 0xF5,
	SECURITY_DISABLE_PASSWORD		= 0xF6,
	READ_NATIVE_MAX_ADDRESS			= 0xF8,
	SET_MAX_ADDRESS				= 0xF9
};

#ifdef	__cplusplus
}
#endif
#endif	/* _ATA8_ACS_H */
