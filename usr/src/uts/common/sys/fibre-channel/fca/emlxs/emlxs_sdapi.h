/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at
 * http://www.opensource.org/licenses/cddl1.txt.
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
 * Copyright (c) 2004-2011 Emulex. All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _EMLXS_SDAPI_H
#define	_EMLXS_SDAPI_H

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Although information in this file can be used by app, libdfc or driver,
 * its purpose is for communication between app and libdfc.
 * Its content come from the SAN Diag API Specification.
 */


/* Define for refering SCSI_IO_LATENCY */
#define	SD_SCSI_IO_LATENCY_TYPE		0x01

#define	SD_IO_LATENCY_MAX_BUCKETS	20	/* Size of array range */

/* Masks for ELS Commands */
#define	SD_ELS_SUBCATEGORY_PLOGI_RCV	0x01
#define	SD_ELS_SUBCATEGORY_PRLO_RCV	0x02
#define	SD_ELS_SUBCATEGORY_ADISC_RCV	0x04
#define	SD_ELS_SUBCATEGORY_LSRJT_RCV	0x08
#define	SD_ELS_SUBCATEGORY_LOGO_RCV	0x10
#define	SD_ELS_SUBCATEGORY_RSCN_RCV	0x20

/* Masks for Fabric events */
#define	SD_FABRIC_SUBCATEGORY_FABRIC_BUSY	0x01
#define	SD_FABRIC_SUBCATEGORY_PORT_BUSY		0x02
#define	SD_FABRIC_SUBCATEGORY_FCPRDCHKERR	0x04

/* Masks for SCSI events */
#define	SD_SCSI_SUBCATEGORY_QFULL			0x0001
#define	SD_SCSI_SUBCATEGORY_DEVBSY			0x0002
#define	SD_SCSI_SUBCATEGORY_CHECKCONDITION		0x0004
#define	SD_SCSI_SUBCATEGORY_LUNRESET			0x0008
#define	SD_SCSI_SUBCATEGORY_TGTRESET			0x0010
#define	SD_SCSI_SUBCATEGORY_BUSRESET			0x0020
#define	SD_SCSI_SUBCATEGORY_VARQUEDEPTH			0x0040

/* Masks for Board Events */
#define	SD_BOARD_SUBCATEGORY_PORTINTERR		0x01
#define	SD_BOARD_SUBCATEGORY_LINKATTE		0x02

/* Masks for Adapter Events */
#define	SD_ADAPTER_SUBCATEGORY_ARRIVAL		0x01
#define	SD_ADAPTER_SUBCATEGORY_DEPARTURE	0x02

/* Struct to hold SCSI IO Latency statistics per bucket */
struct SD_time_stats_v0 {
	int sd_tstats_bucket_count;
};

/* Struct per target for SCSI IO Latency */
struct SD_IO_Latency_Response {
	HBA_WWN sd_iolatency_target_wwpn;
	/* Size of array depends on range size */
	struct SD_time_stats_v0 sd_time_stats_array[SD_IO_LATENCY_MAX_BUCKETS];
};

/* Return Codes */
enum SD_RETURN_CODES {
	SD_OK,
	SD_ERROR_GENERIC,
	SD_ERROR_ARG,
	SD_ERROR_INVALID_BOARD_ID,
	SD_ERROR_INVALID_VPORT,
	SD_ERROR_NOT_SUPPORTED,
	SD_ERROR_CATEGORY_NOT_SUPPORTED,
	SD_ERROR_SUBCATEGORY_NOT_SUPPORTED,
	SD_ERROR_MORE_DATA_AVAILABLE,
	SD_ERROR_EVENT_ALREADY_REGISTERED,
	SD_ERROR_NO_ACTIVE_REGISTRATION,
	SD_ERROR_ARG_MISSING,
	SD_ERROR_NO_MEMORY,
	SD_ERROR_BUCKET_NOTSET,
	SD_ERROR_REG_HANDLE,
	SD_ERROR_INVALID_SEARCH_TYPE,
	SD_ERROR_FUNCTION_NOT_SUPPORTED,
	SD_ERROR_OUT_OF_HANDLES,
	SD_ERROR_LIB_NOT_INIT,
	SD_ERROR_DATA_COLLECTION_ACTIVE,
	SD_ERROR_DATA_COLLECTION_NOT_ACTIVE,
	SD_MAX_RETURN_CODES
};


#define	SD_SEARCH_LINEAR	0x01
#define	SD_SEARCH_POWER_2	0x02


extern uint32_t	DFC_SD_Get_Granularity(void);

extern int32_t	DFC_SD_Set_Bucket(uint16_t type,
				uint16_t search_type,
				uint32_t base,
				uint32_t step);

extern int32_t	DFC_SD_Destroy_Bucket(uint16_t type);

extern int32_t	DFC_SD_Get_Bucket(uint16_t type,
				uint16_t *search_type,
				uint32_t *base,
				uint32_t *step,
				uint64_t *values);

extern int32_t	DFC_SD_Start_Data_Collection(uint32_t board,
				HBA_WWN port_id,
				uint16_t type,
				void *arg);

extern int32_t	DFC_SD_Stop_Data_Collection(uint32_t board,
				HBA_WWN port_id,
				uint16_t type);

extern int32_t	DFC_SD_Reset_Data_Collection(uint32_t board,
				HBA_WWN port_id,
				uint16_t type);

extern int32_t	DFC_SD_Get_Data(uint32_t board,
				HBA_WWN port_id,
				uint16_t type,
				uint16_t *target,
				uint32_t buf_size,
				void *buff);

#define	SD_REG_ELS_EVENT	0x01
#define	SD_REG_FABRIC_EVENT	0x02
#define	SD_REG_SCSI_EVENT	0x04
#define	SD_REG_BOARD_EVENT	0x08
#define	SD_REG_ADAPTER_EVENT	0x10


#define	SD_ELS_SUBCATEGORY_VALID_MASK	(SD_ELS_SUBCATEGORY_PLOGI_RCV | \
	SD_ELS_SUBCATEGORY_PRLO_RCV | SD_ELS_SUBCATEGORY_ADISC_RCV | \
	SD_ELS_SUBCATEGORY_LSRJT_RCV | SD_ELS_SUBCATEGORY_LOGO_RCV | \
	SD_ELS_SUBCATEGORY_RSCN_RCV)


/* Generic Payload */
struct sd_event {
	uint32_t	sd_evt_version;
	size_t		sd_evt_size;
	void		*sd_evt_payload;
};


struct sd_els_event_details_v0 {
	uint32_t	sd_elsevt_version;
	void		*sd_elsevt_payload;
};


struct sd_plogi_rcv_v0 {
	uint32_t	sd_plogir_version;
	HBA_WWN		sd_plogir_portname;
	HBA_WWN		sd_plogir_nodename;
};


struct sd_prlo_rcv_v0 {
	uint32_t	sd_prlor_version;
	HBA_WWN		sd_prlor_remoteport;
};


struct sd_lsrjt_rcv_v0 {
	uint32_t	sd_lsrjtr_version;
	HBA_WWN		sd_lsrjtr_remoteport;
	uint32_t	sd_lsrjtr_original_cmd;
	uint32_t	sd_lsrjtr_reasoncode;
	uint32_t	sd_lsrjtr_reasoncodeexpl;
};


struct sd_adisc_rcv_v0 {
	uint32_t	sd_adiscr_version;
	HBA_WWN		sd_adiscr_portname;
	HBA_WWN		sd_adiscr_nodename;
};


#define	SD_FABRIC_SUBCATEGORY_VALID_MASK	(\
	SD_FABRIC_SUBCATEGORY_FABRIC_BUSY | SD_FABRIC_SUBCATEGORY_PORT_BUSY | \
	SD_FABRIC_SUBCATEGORY_FCPRDCHKERR)


struct sd_fabric_event_details_v0 {
	uint32_t	sd_fabric_evt_version;
	void		*sd_fabric_evt_payload;
};


struct sd_pbsy_rcv_v0 {
	uint32_t	sd_pbsyr_evt_version;
	HBA_WWN		sd_pbsyr_rport;
};


struct sd_fcprdchkerr_v0 {
	uint32_t	sd_fcprdchkerr_version;
	HBA_WWN		sd_fcprdchkerr_rport;
	uint32_t	sd_fcprdchkerr_lun;
	uint32_t	sd_fcprdchkerr_opcode;
	uint32_t	sd_fcprdchkerr_fcpiparam;
};


#define	SD_SCSI_SUBCATEGORY_VALID_MASK	(\
	SD_SCSI_SUBCATEGORY_QFULL | SD_SCSI_SUBCATEGORY_DEVBSY | \
	SD_SCSI_SUBCATEGORY_CHECKCONDITION | SD_SCSI_SUBCATEGORY_LUNRESET | \
	SD_SCSI_SUBCATEGORY_TGTRESET | SD_SCSI_SUBCATEGORY_BUSRESET | \
	SD_SCSI_SUBCATEGORY_VARQUEDEPTH)

struct sd_scsi_event_details_v0 {
	uint32_t	sd_scsi_evt_version;
	void		*sd_scsi_evt_payload;
};


struct sd_scsi_generic_v0 {
	uint32_t	sd_scsi_generic_version;
	HBA_WWN		sd_scsi_generic_rport;
	int32_t		sd_scsi_generic_lun;
};


struct sd_scsi_checkcond_v0 {
	uint32_t	sd_scsi_checkcond_version;
	HBA_WWN		sd_scsi_checkcond_rport;
	uint32_t	sd_scsi_checkcond_lun;
	uint32_t	sd_scsi_checkcond_cmdcode;
	uint32_t	sd_scsi_checkcond_sensekey;
	uint32_t	sd_scsi_checkcond_asc;
	uint32_t	sd_scsi_checkcond_ascq;
};


struct sd_scsi_varquedepth_v0 {
	uint32_t	sd_varquedepth_version;
	HBA_WWN		sd_varquedepth_rport;
	int32_t		sd_varquedepth_lun;
	uint32_t	sd_varquedepth_oldval;
	uint32_t	sd_varquedepth_newval;
};


/* Prototype for callback */
typedef void sd_callback(uint32_t board_id,
			HBA_WWN 	ort_id,
			uint32_t	category,
			uint32_t	subcategory,
			void		*context,
			struct sd_event	*sd_data);

/* Register for event */
extern int32_t DFC_SD_RegisterForEvent(uint32_t board_id,
				HBA_WWN		port_id,
				uint32_t	category,
				uint32_t	subcategory,
				void		*context,
				uint32_t	*reg_handle,
				sd_callback	*func);


/* Deregister a event */
extern int32_t DFC_SD_unRegisterForEvent(uint32_t board_id,
				HBA_WWN		vport_id,
				uint32_t	reg_handle);


#ifdef	__cplusplus
}
#endif

#endif	/* _EMLXS_SDAPI_H */
