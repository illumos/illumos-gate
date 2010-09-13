/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_MPI_RAID_H
#define	_SYS_MPI_RAID_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * RAID Volume Request
 */
typedef struct msg_raid_action {
	uint8_t			Action;
	uint8_t			Reserved1;
	uint8_t			ChainOffset;
	uint8_t			Function;
	uint8_t			VolumeID;
	uint8_t			VolumeBus;
	uint8_t			PhysDiskNum;
	uint8_t			MsgFlags;
	uint32_t		MsgContext;
	uint32_t		Reserved2;
	uint32_t		ActionDataWord;
	sge_simple_union_t	ActionDataSGE;
} msg_raid_action_t;


/* RAID Volume Action values */

#define	MPI_RAID_ACTION_STATUS				0x00
#define	MPI_RAID_ACTION_INDICATOR_STRUCT		0x01
#define	MPI_RAID_ACTION_CREATE_VOLUME			0x02
#define	MPI_RAID_ACTION_DELETE_VOLUME			0x03
#define	MPI_RAID_ACTION_DISABLE_VOLUME			0x04
#define	MPI_RAID_ACTION_ENABLE_VOLUME			0x05
#define	MPI_RAID_ACTION_QUIESCE_PHYS_IO			0x06
#define	MPI_RAID_ACTION_ENABLE_PHYS_IO			0x07
#define	MPI_RAID_ACTION_CHANGE_VOLUME_SETTINGS		0x08
#define	MPI_RAID_ACTION_PHYSDISK_OFFLINE		0x0A
#define	MPI_RAID_ACTION_PHYSDISK_ONLINE			0x0B
#define	MPI_RAID_ACTION_CHANGE_PHYSDISK_SETTINGS	0x0C
#define	MPI_RAID_ACTION_CREATE_PHYSDISK			0x0D
#define	MPI_RAID_ACTION_DELETE_PHYSDISK			0x0E
#define	MPI_RAID_ACTION_FAIL_PHYSDISK			0x0F
#define	MPI_RAID_ACTION_REPLACE_PHYSDISK		0x10
#define	MPI_RAID_ACTION_ACTIVATE_VOLUME			0x11
#define	MPI_RAID_ACTION_INACTIVATE_VOLUME		0x12

#define	MPI_RAID_ACTION_ADATA_DO_NOT_SYNC		0x00000001

#define	MPI_RAID_ACTION_ADATA_KEEP_PHYS_DISKS		0x00000000
#define	MPI_RAID_ACTION_ADATA_DEL_PHYS_DISKS		0x00000001

/* RAID Volume reply message */

typedef struct msg_raid_action_reply {
	uint8_t			Action;
	uint8_t			Reserved;
	uint8_t			MsgLength;
	uint8_t			Function;
	uint8_t			VolumeID;
	uint8_t			VolumeBus;
	uint8_t			PhysDiskNum;
	uint8_t			MsgFlags;
	uint32_t		MsgContext;
	uint16_t		ActionStatus;
	uint16_t		IOCStatus;
	uint32_t		IOCLogInfo;
	uint32_t		VolumeStatus;
	uint32_t		ActionData;
} msg_raid_action_reply_t;


/* RAID Volume reply ActionStatus values */

#define	MPI_RAID_VOL_ASTATUS_SUCCESS		0x0000
#define	MPI_RAID_VOL_ASTATUS_INVALID_ACTION	0x0001
#define	MPI_RAID_VOL_ASTATUS_FAILURE		0x0002
#define	MPI_RAID_VOL_ASTATUS_IN_PROGRESS	0x0003


/* RAID Volume reply RAID Volume Indicator structure */

typedef struct mpi_raid_vol_indicator {
	uint64_t		TotalBlocks;
	uint64_t		BlocksRemaining;
} mpi_raid_vol_indicator_t;


/*
 * SCSI IO RAID Passthrough Request
 */
typedef struct msg_scsi_io_raid_pt_request {
	uint8_t			PhysDiskNum;
	uint8_t			Reserved1;
	uint8_t			ChainOffset;
	uint8_t			Function;
	uint8_t			CDBLength;
	uint8_t			SenseBufferLength;
	uint8_t			Reserved2;
	uint8_t			MsgFlags;
	uint32_t		MsgContext;
	uint8_t			LUN[8];
	uint32_t		Control;
	uint8_t			CDB[16];
	uint32_t		DataLength;
	uint32_t		SenseBufferLowAddr;
	sge_io_union_t		SGL;
} msg_scsi_io_raid_pt_request_t;


/* SCSI IO RAID Passthrough reply structure */

typedef struct msg_scsi_io_raid_pt_reply {
	uint8_t			PhysDiskNum;
	uint8_t			Reserved1;
	uint8_t			MsgLength;
	uint8_t			Function;
	uint8_t			CDBLength;
	uint8_t			SenseBufferLength;
	uint8_t			Reserved2;
	uint8_t			MsgFlags;
	uint32_t		MsgContext;
	uint8_t			SCSIStatus;
	uint8_t			SCSIState;
	uint16_t		IOCStatus;
	uint32_t		IOCLogInfo;
	uint32_t		TransferCount;
	uint32_t		SenseCount;
	uint32_t		ResponseInfo;
} msg_scsi_io_raid_pt_reply_t;

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_MPI_RAID_H */
