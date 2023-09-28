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
 * pseudo scsi disk driver
 */

#include <sys/scsi/scsi.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/kmem.h>
#include <sys/taskq.h>
#include <sys/disp.h>
#include <sys/types.h>
#include <sys/buf.h>

#include <sys/emul64.h>
#include <sys/emul64cmd.h>
#include <sys/emul64var.h>

/*
 * Mode sense/select page control
 */
#define	MODE_SENSE_PC_CURRENT		0
#define	MODE_SENSE_PC_CHANGEABLE	1
#define	MODE_SENSE_PC_DEFAULT		2
#define	MODE_SENSE_PC_SAVED		3

/*
 * Byte conversion macros
 */
#if	defined(_BIG_ENDIAN)
#define	ushort_to_scsi_ushort(n)	(n)
#define	uint32_to_scsi_uint32(n)	(n)
#define	uint64_to_scsi_uint64(n)	(n)
#elif	defined(_LITTLE_ENDIAN)

#define	ushort_to_scsi_ushort(n)			\
		((((n) & 0x00ff) << 8) |		\
		(((n)  & 0xff00) >> 8))

#define	uint32_to_scsi_uint32(n)			\
		((((n) & 0x000000ff) << 24) |		\
		(((n)  & 0x0000ff00) << 8) |		\
		(((n)  & 0x00ff0000) >> 8) |		\
		(((n)  & 0xff000000) >> 24))
#define	uint64_to_scsi_uint64(n)				\
		((((n) & 0x00000000000000ff) << 56) |           \
		(((n)  & 0x000000000000ff00) << 40) |           \
		(((n)  & 0x0000000000ff0000) << 24) |           \
		(((n)  & 0x00000000ff000000) << 8) |            \
		(((n)  & 0x000000ff00000000) >> 8) |            \
		(((n)  & 0x0000ff0000000000) >> 24) |           \
		(((n)  & 0x00ff000000000000) >> 40) |           \
		(((n)  & 0xff00000000000000) >> 56))
#else
error no _BIG_ENDIAN or _LITTLE_ENDIAN
#endif
#define	uint_to_byte0(n)		((n) & 0xff)
#define	uint_to_byte1(n)		(((n)>>8) & 0xff)
#define	uint_to_byte2(n)		(((n)>>16) & 0xff)
#define	uint_to_byte3(n)		(((n)>>24) & 0xff)

/*
 * struct prop_map
 *
 * This structure maps a property name to the place to store its value.
 */
struct prop_map {
	char 		*pm_name;	/* Name of the property. */
	int		*pm_value;	/* Place to store the value. */
};

static int emul64_debug_blklist = 0;

/*
 * Some interesting statistics.  These are protected by the
 * emul64_stats_mutex.  It would be nice to have an ioctl to print them out,
 * but we don't have the development time for that now.  You can at least
 * look at them with adb.
 */

int		emul64_collect_stats = 1; /* Collect stats if non-zero */
kmutex_t	emul64_stats_mutex;	/* Protect these variables */
long		emul64_nowrite_count = 0; /* # active nowrite ranges */
static uint64_t	emul64_skipped_io = 0;	/* Skipped I/O operations, because of */
					/* EMUL64_WRITE_OFF. */
static uint64_t	emul64_skipped_blk = 0;	/* Skipped blocks because of */
					/* EMUL64_WRITE_OFF. */
static uint64_t	emul64_io_ops = 0;	/* Total number of I/O operations */
					/* including skipped and actual. */
static uint64_t	emul64_io_blocks = 0;	/* Total number of blocks involved */
					/* in I/O operations. */
static uint64_t	emul64_nonzero = 0;	/* Number of non-zero data blocks */
					/* currently held in memory */
static uint64_t	emul64_max_list_length = 0; /* Maximum size of a linked */
					    /* list of non-zero blocks. */
uint64_t emul64_taskq_max = 0;		/* emul64_scsi_start uses the taskq */
					/* mechanism to dispatch work. */
					/* If the number of entries in the */
					/* exceeds the maximum for the queue */
					/* the queue a 1 second delay is */
					/* encountered in taskq_ent_alloc. */
					/* This counter counts the number */
					/* times that this happens. */

/*
 * Since emul64 does no physical I/O, operations that would normally be I/O
 * intensive become CPU bound.  An example of this is RAID 5
 * initialization.  When the kernel becomes CPU bound, it looks as if the
 * machine is hung.
 *
 * To avoid this problem, we provide a function, emul64_yield_check, that does a
 * delay from time to time to yield up the CPU.  The following variables
 * are tunables for this algorithm.
 *
 *	emul64_num_delay_called	Number of times we called delay.  This is
 *				not really a tunable.  Rather it is a
 *				counter that provides useful information
 *				for adjusting the tunables.
 *	emul64_yield_length	Number of microseconds to yield the CPU.
 *	emul64_yield_period	Number of I/O operations between yields.
 *	emul64_yield_enable	emul64 will yield the CPU, only if this
 *				variable contains a non-zero value.  This
 *				allows the yield functionality to be turned
 *				off for experimentation purposes.
 *
 * The value of 1000 for emul64_yield_period has been determined by
 * experience with running the tests.
 */
static uint64_t		emul64_num_delay_called = 0;
static int		emul64_yield_length = 1000;
static int		emul64_yield_period = 1000;
static int		emul64_yield_enable = 1;
static kmutex_t		emul64_yield_mutex;
static kcondvar_t 	emul64_yield_cv;

/*
 * This array establishes a set of tunable variables that can be set by
 * defining properties in the emul64.conf file.
 */
struct prop_map emul64_properties[] = {
	"emul64_collect_stats",		&emul64_collect_stats,
	"emul64_yield_length",		&emul64_yield_length,
	"emul64_yield_period",		&emul64_yield_period,
	"emul64_yield_enable",		&emul64_yield_enable,
	"emul64_max_task",		&emul64_max_task,
	"emul64_task_nthreads",		&emul64_task_nthreads
};

static unsigned char *emul64_zeros = NULL; /* Block of 0s for comparison */

extern void emul64_check_cond(struct scsi_pkt *pkt, uchar_t key,
				uchar_t asc, uchar_t ascq);
/* ncyl=250000 acyl=2 nhead=24 nsect=357 */
uint_t dkg_rpm = 3600;

static int bsd_mode_sense_dad_mode_geometry(struct scsi_pkt *);
static int bsd_mode_sense_dad_mode_err_recov(struct scsi_pkt *);
static int bsd_mode_sense_modepage_disco_reco(struct scsi_pkt *);
static int bsd_mode_sense_dad_mode_format(struct scsi_pkt *);
static int bsd_mode_sense_dad_mode_cache(struct scsi_pkt *);
static int bsd_readblks(struct emul64 *, ushort_t, ushort_t, diskaddr_t,
				int, unsigned char *);
static int bsd_writeblks(struct emul64 *, ushort_t, ushort_t, diskaddr_t,
				int, unsigned char *);
emul64_tgt_t *find_tgt(struct emul64 *, ushort_t, ushort_t);
static blklist_t *bsd_findblk(emul64_tgt_t *, diskaddr_t, avl_index_t *);
static void bsd_allocblk(emul64_tgt_t *, diskaddr_t, caddr_t, avl_index_t);
static void bsd_freeblk(emul64_tgt_t *, blklist_t *);
static void emul64_yield_check();
static emul64_rng_overlap_t bsd_tgt_overlap(emul64_tgt_t *, diskaddr_t, int);

char *emul64_name = "emul64";


/*
 * Initialize globals in this file.
 */
void
emul64_bsd_init()
{
	emul64_zeros = (unsigned char *) kmem_zalloc(DEV_BSIZE, KM_SLEEP);
	mutex_init(&emul64_stats_mutex, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&emul64_yield_mutex, NULL, MUTEX_DRIVER, NULL);
	cv_init(&emul64_yield_cv, NULL, CV_DRIVER, NULL);
}

/*
 * Clean up globals in this file.
 */
void
emul64_bsd_fini()
{
	cv_destroy(&emul64_yield_cv);
	mutex_destroy(&emul64_yield_mutex);
	mutex_destroy(&emul64_stats_mutex);
	if (emul64_zeros != NULL) {
		kmem_free(emul64_zeros, DEV_BSIZE);
		emul64_zeros = NULL;
	}
}

/*
 * Attempt to get the values of the properties that are specified in the
 * emul64_properties array.  If the property exists, copy its value to the
 * specified location.  All the properties have been assigned default
 * values in this driver, so if we cannot get the property that is not a
 * problem.
 */
void
emul64_bsd_get_props(dev_info_t *dip)
{
	uint_t		count;
	uint_t		i;
	struct prop_map	*pmp;
	int		*properties;

	for (pmp = emul64_properties, i = 0;
	    i < sizeof (emul64_properties) / sizeof (struct prop_map);
	    i++, pmp++) {
		if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, dip,
		    DDI_PROP_DONTPASS, pmp->pm_name, &properties,
		    &count) == DDI_PROP_SUCCESS) {
			if (count >= 1) {
				*pmp->pm_value = *properties;
			}
			ddi_prop_free((void *) properties);
		}
	}
}

int
emul64_bsd_blkcompare(const void *a1, const void *b1)
{
	blklist_t	*a = (blklist_t *)a1;
	blklist_t	*b = (blklist_t *)b1;

	if (a->bl_blkno < b->bl_blkno)
		return (-1);
	if (a->bl_blkno == b->bl_blkno)
		return (0);
	return (1);
}

/* ARGSUSED 0 */
int
bsd_scsi_start_stop_unit(struct scsi_pkt *pkt)
{
	return (0);
}

/* ARGSUSED 0 */
int
bsd_scsi_test_unit_ready(struct scsi_pkt *pkt)
{
	return (0);
}

/* ARGSUSED 0 */
int
bsd_scsi_request_sense(struct scsi_pkt *pkt)
{
	return (0);
}

int
bsd_scsi_inq_page0(struct scsi_pkt *pkt, uchar_t pqdtype)
{
	struct emul64_cmd	*sp = PKT2CMD(pkt);

	if (sp->cmd_count < 6) {
		cmn_err(CE_CONT, "%s: bsd_scsi_inq_page0: size %d required\n",
		    emul64_name, 6);
		return (EIO);
	}

	sp->cmd_addr[0] = pqdtype;	/* periph qual., dtype */
	sp->cmd_addr[1] = 0;		/* page code */
	sp->cmd_addr[2] = 0;		/* reserved */
	sp->cmd_addr[3] = 6 - 3;	/* length */
	sp->cmd_addr[4] = 0;		/* 1st page */
	sp->cmd_addr[5] = 0x83;		/* 2nd page */

	pkt->pkt_resid = sp->cmd_count - 6;
	return (0);
}

int
bsd_scsi_inq_page83(struct scsi_pkt *pkt, uchar_t pqdtype)
{
	struct emul64		*emul64 = PKT2EMUL64(pkt);
	struct emul64_cmd	*sp = PKT2CMD(pkt);
	int			instance = ddi_get_instance(emul64->emul64_dip);

	if (sp->cmd_count < 22) {
		cmn_err(CE_CONT, "%s: bsd_scsi_inq_page83: size %d required\n",
		    emul64_name, 22);
		return (EIO);
	}

	sp->cmd_addr[0] = pqdtype;	/* periph qual., dtype */
	sp->cmd_addr[1] = 0x83;		/* page code */
	sp->cmd_addr[2] = 0;		/* reserved */
	sp->cmd_addr[3] = (22 - 8) + 4;	/* length */

	sp->cmd_addr[4] = 1;		/* code set - binary */
	sp->cmd_addr[5] = 3;		/* association and device ID type 3 */
	sp->cmd_addr[6] = 0;		/* reserved */
	sp->cmd_addr[7] = 22 - 8;	/* ID length */

	sp->cmd_addr[8] = 0xde;		/* @8: identifier, byte 0 */
	sp->cmd_addr[9] = 0xca;
	sp->cmd_addr[10] = 0xde;
	sp->cmd_addr[11] = 0x80;

	sp->cmd_addr[12] = 0xba;
	sp->cmd_addr[13] = 0xbe;
	sp->cmd_addr[14] = 0xab;
	sp->cmd_addr[15] = 0xba;
					/* @22: */

	/*
	 * Instances seem to be assigned sequentially, so it unlikely that we
	 * will have more than 65535 of them.
	 */
	sp->cmd_addr[16] = uint_to_byte1(instance);
	sp->cmd_addr[17] = uint_to_byte0(instance);
	sp->cmd_addr[18] = uint_to_byte1(TGT(sp));
	sp->cmd_addr[19] = uint_to_byte0(TGT(sp));
	sp->cmd_addr[20] = uint_to_byte1(LUN(sp));
	sp->cmd_addr[21] = uint_to_byte0(LUN(sp));

	pkt->pkt_resid = sp->cmd_count - 22;
	return (0);
}

int
bsd_scsi_inquiry(struct scsi_pkt *pkt)
{
	struct emul64_cmd	*sp = PKT2CMD(pkt);
	union scsi_cdb		*cdb = (union scsi_cdb *)pkt->pkt_cdbp;
	emul64_tgt_t		*tgt;
	uchar_t			pqdtype;
	struct scsi_inquiry	inq;

	EMUL64_MUTEX_ENTER(sp->cmd_emul64);
	tgt = find_tgt(sp->cmd_emul64,
	    pkt->pkt_address.a_target, pkt->pkt_address.a_lun);
	EMUL64_MUTEX_EXIT(sp->cmd_emul64);

	if (sp->cmd_count < sizeof (inq)) {
		cmn_err(CE_CONT, "%s: bsd_scsi_inquiry: size %d required\n",
		    emul64_name, (int)sizeof (inq));
		return (EIO);
	}

	if (cdb->cdb_opaque[1] & 0xfc) {
		cmn_err(CE_WARN, "%s: bsd_scsi_inquiry: 0x%x",
		    emul64_name, cdb->cdb_opaque[1]);
		emul64_check_cond(pkt, 0x5, 0x24, 0x0);	/* inv. fld in cdb */
		return (0);
	}

	pqdtype = tgt->emul64_tgt_dtype;
	if (cdb->cdb_opaque[1] & 0x1) {
		switch (cdb->cdb_opaque[2]) {
		case 0x00:
			return (bsd_scsi_inq_page0(pkt, pqdtype));
		case 0x83:
			return (bsd_scsi_inq_page83(pkt, pqdtype));
		default:
			cmn_err(CE_WARN, "%s: bsd_scsi_inquiry: "
			    "unsupported 0x%x",
			    emul64_name, cdb->cdb_opaque[2]);
			return (0);
		}
	}

	/* set up the inquiry data we return */
	(void) bzero((void *)&inq, sizeof (inq));

	inq.inq_dtype = pqdtype;
	inq.inq_ansi = 2;
	inq.inq_rdf = 2;
	inq.inq_len = sizeof (inq) - 4;
	inq.inq_wbus16 = 1;
	inq.inq_cmdque = 1;

	(void) bcopy(tgt->emul64_tgt_inq, inq.inq_vid,
	    sizeof (tgt->emul64_tgt_inq));
	(void) bcopy("1", inq.inq_revision, 2);
	(void) bcopy((void *)&inq, sp->cmd_addr, sizeof (inq));

	pkt->pkt_resid = sp->cmd_count - sizeof (inq);
	return (0);
}

/* ARGSUSED 0 */
int
bsd_scsi_format(struct scsi_pkt *pkt)
{
	return (0);
}

int
bsd_scsi_io(struct scsi_pkt *pkt)
{
	struct emul64_cmd	*sp = PKT2CMD(pkt);
	union scsi_cdb		*cdb = (union scsi_cdb *)pkt->pkt_cdbp;
	diskaddr_t		lblkno;
	int			nblks;

	switch (cdb->scc_cmd) {
	case SCMD_READ:
			lblkno = (uint32_t)GETG0ADDR(cdb);
			nblks = GETG0COUNT(cdb);
			pkt->pkt_resid = bsd_readblks(sp->cmd_emul64,
			    pkt->pkt_address.a_target, pkt->pkt_address.a_lun,
			    lblkno, nblks, sp->cmd_addr);
			if (emul64debug) {
				cmn_err(CE_CONT, "%s: bsd_scsi_io: "
				    "read g0 blk=%lld (0x%llx) nblks=%d\n",
				    emul64_name, lblkno, lblkno, nblks);
			}
		break;
	case SCMD_WRITE:
			lblkno = (uint32_t)GETG0ADDR(cdb);
			nblks = GETG0COUNT(cdb);
			pkt->pkt_resid = bsd_writeblks(sp->cmd_emul64,
			    pkt->pkt_address.a_target, pkt->pkt_address.a_lun,
			    lblkno, nblks, sp->cmd_addr);
			if (emul64debug) {
				cmn_err(CE_CONT, "%s: bsd_scsi_io: "
				    "write g0 blk=%lld (0x%llx) nblks=%d\n",
				    emul64_name, lblkno, lblkno, nblks);
			}
		break;
	case SCMD_READ_G1:
			lblkno = (uint32_t)GETG1ADDR(cdb);
			nblks = GETG1COUNT(cdb);
			pkt->pkt_resid = bsd_readblks(sp->cmd_emul64,
			    pkt->pkt_address.a_target, pkt->pkt_address.a_lun,
			    lblkno, nblks, sp->cmd_addr);
			if (emul64debug) {
				cmn_err(CE_CONT, "%s: bsd_scsi_io: "
				    "read g1 blk=%lld (0x%llx) nblks=%d\n",
				    emul64_name, lblkno, lblkno, nblks);
			}
		break;
	case SCMD_WRITE_G1:
			lblkno = (uint32_t)GETG1ADDR(cdb);
			nblks = GETG1COUNT(cdb);
			pkt->pkt_resid = bsd_writeblks(sp->cmd_emul64,
			    pkt->pkt_address.a_target, pkt->pkt_address.a_lun,
			    lblkno, nblks, sp->cmd_addr);
			if (emul64debug) {
				cmn_err(CE_CONT, "%s: bsd_scsi_io: "
				    "write g1 blk=%lld (0x%llx) nblks=%d\n",
				    emul64_name, lblkno, lblkno, nblks);
			}
		break;
	case SCMD_READ_G4:
			lblkno = GETG4ADDR(cdb);
			lblkno <<= 32;
			lblkno |= (uint32_t)GETG4ADDRTL(cdb);
			nblks = GETG4COUNT(cdb);
			pkt->pkt_resid = bsd_readblks(sp->cmd_emul64,
			    pkt->pkt_address.a_target, pkt->pkt_address.a_lun,
			    lblkno, nblks, sp->cmd_addr);
			if (emul64debug) {
				cmn_err(CE_CONT, "%s: bsd_scsi_io: "
				    "read g4 blk=%lld (0x%llx) nblks=%d\n",
				    emul64_name, lblkno, lblkno, nblks);
			}
		break;
	case SCMD_WRITE_G4:
			lblkno = GETG4ADDR(cdb);
			lblkno <<= 32;
			lblkno |= (uint32_t)GETG4ADDRTL(cdb);
			nblks = GETG4COUNT(cdb);
			pkt->pkt_resid = bsd_writeblks(sp->cmd_emul64,
			    pkt->pkt_address.a_target, pkt->pkt_address.a_lun,
			    lblkno, nblks, sp->cmd_addr);
			if (emul64debug) {
				cmn_err(CE_CONT, "%s: bsd_scsi_io: "
				    "write g4 blk=%lld (0x%llx) nblks=%d\n",
				    emul64_name, lblkno, lblkno, nblks);
			}
		break;
	default:
		cmn_err(CE_WARN, "%s: bsd_scsi_io: unhandled I/O: 0x%x",
		    emul64_name, cdb->scc_cmd);
		break;
	}

	if (pkt->pkt_resid != 0)
		cmn_err(CE_WARN, "%s: bsd_scsi_io: "
		    "pkt_resid: 0x%lx, lblkno %lld, nblks %d",
		    emul64_name, pkt->pkt_resid, lblkno, nblks);

	return (0);
}

int
bsd_scsi_log_sense(struct scsi_pkt *pkt)
{
	union scsi_cdb		*cdb = (union scsi_cdb *)pkt->pkt_cdbp;
	struct emul64_cmd	*sp = PKT2CMD(pkt);
	int			page_code;

	if (sp->cmd_count < 9) {
		cmn_err(CE_CONT, "%s: bsd_scsi_log_sense size %d required\n",
		    emul64_name, 9);
		return (EIO);
	}

	page_code = cdb->cdb_opaque[2] & 0x3f;
	if (page_code) {
		cmn_err(CE_CONT, "%s: bsd_scsi_log_sense: "
		    "page 0x%x not supported\n", emul64_name, page_code);
		emul64_check_cond(pkt, 0x5, 0x24, 0x0); /* inv. fld in cdb */
		return (0);
	}

	sp->cmd_addr[0] = 0;		/* page code */
	sp->cmd_addr[1] = 0;		/* reserved */
	sp->cmd_addr[2] = 0;		/* MSB of page length */
	sp->cmd_addr[3] = 8 - 3;	/* LSB of page length */

	sp->cmd_addr[4] = 0;		/* MSB of parameter code */
	sp->cmd_addr[5] = 0;		/* LSB of parameter code */
	sp->cmd_addr[6] = 0;		/* parameter control byte */
	sp->cmd_addr[7] = 4 - 3;	/* parameter length */
	sp->cmd_addr[8] = 0x0;		/* parameter value */

	pkt->pkt_resid = sp->cmd_count - 9;
	return (0);
}

int
bsd_scsi_mode_sense(struct scsi_pkt *pkt)
{
	union scsi_cdb	*cdb = (union scsi_cdb *)pkt->pkt_cdbp;
	int		page_control;
	int		page_code;
	int		rval = 0;

	switch (cdb->scc_cmd) {
	case SCMD_MODE_SENSE:
			page_code = cdb->cdb_opaque[2] & 0x3f;
			page_control = (cdb->cdb_opaque[2] >> 6) & 0x03;
			if (emul64debug) {
				cmn_err(CE_CONT, "%s: bsd_scsi_mode_sense: "
				    "page=0x%x control=0x%x nbytes=%d\n",
				    emul64_name, page_code, page_control,
				    GETG0COUNT(cdb));
			}
		break;
	case SCMD_MODE_SENSE_G1:
			page_code = cdb->cdb_opaque[2] & 0x3f;
			page_control = (cdb->cdb_opaque[2] >> 6) & 0x03;
			if (emul64debug) {
				cmn_err(CE_CONT, "%s: bsd_scsi_mode_sense: "
				    "page=0x%x control=0x%x nbytes=%d\n",
				    emul64_name, page_code, page_control,
				    GETG1COUNT(cdb));
			}
		break;
	default:
		cmn_err(CE_CONT, "%s: bsd_scsi_mode_sense: "
		    "cmd 0x%x not supported\n", emul64_name, cdb->scc_cmd);
		return (EIO);
	}

	switch (page_code) {
	case DAD_MODE_GEOMETRY:
		rval = bsd_mode_sense_dad_mode_geometry(pkt);
		break;
	case DAD_MODE_ERR_RECOV:
		rval = bsd_mode_sense_dad_mode_err_recov(pkt);
		break;
	case MODEPAGE_DISCO_RECO:
		rval = bsd_mode_sense_modepage_disco_reco(pkt);
		break;
	case DAD_MODE_FORMAT:
		rval = bsd_mode_sense_dad_mode_format(pkt);
		break;
	case DAD_MODE_CACHE:
		rval = bsd_mode_sense_dad_mode_cache(pkt);
		break;
	default:
		cmn_err(CE_CONT, "%s: bsd_scsi_mode_sense: "
		    "page 0x%x not supported\n", emul64_name, page_code);
		rval = EIO;
		break;
	}

	return (rval);
}


static int
bsd_mode_sense_dad_mode_geometry(struct scsi_pkt *pkt)
{
	struct emul64_cmd	*sp = PKT2CMD(pkt);
	union scsi_cdb		*cdb = (union scsi_cdb *)pkt->pkt_cdbp;
	uchar_t			*addr = (uchar_t *)sp->cmd_addr;
	emul64_tgt_t		*tgt;
	int			page_control;
	struct mode_header	header;
	struct mode_geometry	page4;
	int			ncyl;
	int			rval = 0;

	page_control = (cdb->cdb_opaque[2] >> 6) & 0x03;

	if (emul64debug) {
		cmn_err(CE_CONT, "%s: bsd_mode_sense_dad_mode_geometry: "
		    "pc=%d n=%d\n", emul64_name, page_control, sp->cmd_count);
	}

	if (sp->cmd_count < (sizeof (header) + sizeof (page4))) {
		cmn_err(CE_CONT, "%s: bsd_mode_sense_dad_mode_geometry: "
		    "size %d required\n",
		    emul64_name, (int)(sizeof (header) + sizeof (page4)));
		return (EIO);
	}

	(void) bzero(&header, sizeof (header));
	(void) bzero(&page4, sizeof (page4));

	header.length = sizeof (header) + sizeof (page4) - 1;
	header.bdesc_length = 0;

	page4.mode_page.code = DAD_MODE_GEOMETRY;
	page4.mode_page.ps = 1;
	page4.mode_page.length = sizeof (page4) - sizeof (struct mode_page);

	switch (page_control) {
	case MODE_SENSE_PC_CURRENT:
	case MODE_SENSE_PC_DEFAULT:
	case MODE_SENSE_PC_SAVED:
		EMUL64_MUTEX_ENTER(sp->cmd_emul64);
		tgt = find_tgt(sp->cmd_emul64,
		    pkt->pkt_address.a_target, pkt->pkt_address.a_lun);
		EMUL64_MUTEX_EXIT(sp->cmd_emul64);
		ncyl = tgt->emul64_tgt_ncyls;
		page4.cyl_ub = uint_to_byte2(ncyl);
		page4.cyl_mb = uint_to_byte1(ncyl);
		page4.cyl_lb = uint_to_byte0(ncyl);
		page4.heads = uint_to_byte0(tgt->emul64_tgt_nheads);
		page4.rpm = ushort_to_scsi_ushort(dkg_rpm);
		break;
	case MODE_SENSE_PC_CHANGEABLE:
		page4.cyl_ub = 0xff;
		page4.cyl_mb = 0xff;
		page4.cyl_lb = 0xff;
		page4.heads = 0xff;
		page4.rpm = 0xffff;
		break;
	}

	(void) bcopy(&header, addr, sizeof (header));
	(void) bcopy(&page4, addr + sizeof (header), sizeof (page4));

	pkt->pkt_resid = sp->cmd_count - sizeof (page4) - sizeof (header);
	rval = 0;

	return (rval);
}

static int
bsd_mode_sense_dad_mode_err_recov(struct scsi_pkt *pkt)
{
	struct emul64_cmd	*sp = PKT2CMD(pkt);
	union scsi_cdb		*cdb = (union scsi_cdb *)pkt->pkt_cdbp;
	uchar_t			*addr = (uchar_t *)sp->cmd_addr;
	int			page_control;
	struct mode_header	header;
	struct mode_err_recov	page1;
	int			rval = 0;

	page_control = (cdb->cdb_opaque[2] >> 6) & 0x03;

	if (emul64debug) {
		cmn_err(CE_CONT, "%s: bsd_mode_sense_dad_mode_err_recov: "
		    "pc=%d n=%d\n", emul64_name, page_control, sp->cmd_count);
	}

	if (sp->cmd_count < (sizeof (header) + sizeof (page1))) {
		cmn_err(CE_CONT, "%s: bsd_mode_sense_dad_mode_err_recov: "
		    "size %d required\n",
		    emul64_name, (int)(sizeof (header) + sizeof (page1)));
		return (EIO);
	}

	(void) bzero(&header, sizeof (header));
	(void) bzero(&page1, sizeof (page1));

	header.length = sizeof (header) + sizeof (page1) - 1;
	header.bdesc_length = 0;

	page1.mode_page.code = DAD_MODE_ERR_RECOV;
	page1.mode_page.ps = 1;
	page1.mode_page.length = sizeof (page1) - sizeof (struct mode_page);

	switch (page_control) {
	case MODE_SENSE_PC_CURRENT:
	case MODE_SENSE_PC_DEFAULT:
	case MODE_SENSE_PC_SAVED:
		break;
	case MODE_SENSE_PC_CHANGEABLE:
		break;
	}

	(void) bcopy(&header, addr, sizeof (header));
	(void) bcopy(&page1, addr + sizeof (header), sizeof (page1));

	pkt->pkt_resid = sp->cmd_count - sizeof (page1) - sizeof (header);
	rval = 0;

	return (rval);
}

static int
bsd_mode_sense_modepage_disco_reco(struct scsi_pkt *pkt)
{
	struct emul64_cmd	*sp = PKT2CMD(pkt);
	union scsi_cdb		*cdb = (union scsi_cdb *)pkt->pkt_cdbp;
	int			rval = 0;
	uchar_t			*addr = (uchar_t *)sp->cmd_addr;
	int			page_control;
	struct mode_header	header;
	struct mode_disco_reco	page2;

	page_control = (cdb->cdb_opaque[2] >> 6) & 0x03;

	if (emul64debug) {
		cmn_err(CE_CONT, "%s: bsd_mode_sense_modepage_disco_reco: "
		    "pc=%d n=%d\n", emul64_name, page_control, sp->cmd_count);
	}

	if (sp->cmd_count < (sizeof (header) + sizeof (page2))) {
		cmn_err(CE_CONT, "%s: bsd_mode_sense_modepage_disco_reco: "
		    "size %d required\n",
		    emul64_name, (int)(sizeof (header) + sizeof (page2)));
		return (EIO);
	}

	(void) bzero(&header, sizeof (header));
	(void) bzero(&page2, sizeof (page2));

	header.length = sizeof (header) + sizeof (page2) - 1;
	header.bdesc_length = 0;

	page2.mode_page.code = MODEPAGE_DISCO_RECO;
	page2.mode_page.ps = 1;
	page2.mode_page.length = sizeof (page2) - sizeof (struct mode_page);

	switch (page_control) {
	case MODE_SENSE_PC_CURRENT:
	case MODE_SENSE_PC_DEFAULT:
	case MODE_SENSE_PC_SAVED:
		break;
	case MODE_SENSE_PC_CHANGEABLE:
		break;
	}

	(void) bcopy(&header, addr, sizeof (header));
	(void) bcopy(&page2, addr + sizeof (header), sizeof (page2));

	pkt->pkt_resid = sp->cmd_count - sizeof (page2) - sizeof (header);
	rval = 0;

	return (rval);
}

static int
bsd_mode_sense_dad_mode_format(struct scsi_pkt *pkt)
{
	struct emul64_cmd	*sp = PKT2CMD(pkt);
	union scsi_cdb		*cdb = (union scsi_cdb *)pkt->pkt_cdbp;
	uchar_t			*addr = (uchar_t *)sp->cmd_addr;
	emul64_tgt_t		*tgt;
	int			page_control;
	struct mode_header	header;
	struct mode_format	page3;
	int			rval = 0;

	page_control = (cdb->cdb_opaque[2] >> 6) & 0x03;

	if (emul64debug) {
		cmn_err(CE_CONT, "%s: bsd_mode_sense_dad_mode_format: "
		    "pc=%d n=%d\n", emul64_name, page_control, sp->cmd_count);
	}

	if (sp->cmd_count < (sizeof (header) + sizeof (page3))) {
		cmn_err(CE_CONT, "%s: bsd_mode_sense_dad_mode_format: "
		    "size %d required\n",
		    emul64_name, (int)(sizeof (header) + sizeof (page3)));
		return (EIO);
	}

	(void) bzero(&header, sizeof (header));
	(void) bzero(&page3, sizeof (page3));

	header.length = sizeof (header) + sizeof (page3) - 1;
	header.bdesc_length = 0;

	page3.mode_page.code = DAD_MODE_FORMAT;
	page3.mode_page.ps = 1;
	page3.mode_page.length = sizeof (page3) - sizeof (struct mode_page);

	switch (page_control) {
	case MODE_SENSE_PC_CURRENT:
	case MODE_SENSE_PC_DEFAULT:
	case MODE_SENSE_PC_SAVED:
		page3.data_bytes_sect = ushort_to_scsi_ushort(DEV_BSIZE);
		page3.interleave = ushort_to_scsi_ushort(1);
		EMUL64_MUTEX_ENTER(sp->cmd_emul64);
		tgt = find_tgt(sp->cmd_emul64,
		    pkt->pkt_address.a_target, pkt->pkt_address.a_lun);
		EMUL64_MUTEX_EXIT(sp->cmd_emul64);
		page3.sect_track = ushort_to_scsi_ushort(tgt->emul64_tgt_nsect);
		break;
	case MODE_SENSE_PC_CHANGEABLE:
		break;
	}

	(void) bcopy(&header, addr, sizeof (header));
	(void) bcopy(&page3, addr + sizeof (header), sizeof (page3));

	pkt->pkt_resid = sp->cmd_count - sizeof (page3) - sizeof (header);
	rval = 0;

	return (rval);
}

static int
bsd_mode_sense_dad_mode_cache(struct scsi_pkt *pkt)
{
	struct emul64_cmd	*sp = PKT2CMD(pkt);
	union scsi_cdb		*cdb = (union scsi_cdb *)pkt->pkt_cdbp;
	uchar_t			*addr = (uchar_t *)sp->cmd_addr;
	int			page_control;
	struct mode_header	header;
	struct mode_cache	page8;
	int			rval = 0;

	page_control = (cdb->cdb_opaque[2] >> 6) & 0x03;

	if (emul64debug) {
		cmn_err(CE_CONT, "%s: bsd_mode_sense_dad_mode_cache: "
		    "pc=%d n=%d\n", emul64_name, page_control, sp->cmd_count);
	}

	if (sp->cmd_count < (sizeof (header) + sizeof (page8))) {
		cmn_err(CE_CONT, "%s: bsd_mode_sense_dad_mode_cache: "
		    "size %d required\n",
		    emul64_name, (int)(sizeof (header) + sizeof (page8)));
		return (EIO);
	}

	(void) bzero(&header, sizeof (header));
	(void) bzero(&page8, sizeof (page8));

	header.length = sizeof (header) + sizeof (page8) - 1;
	header.bdesc_length = 0;

	page8.mode_page.code = DAD_MODE_CACHE;
	page8.mode_page.ps = 1;
	page8.mode_page.length = sizeof (page8) - sizeof (struct mode_page);

	switch (page_control) {
	case MODE_SENSE_PC_CURRENT:
	case MODE_SENSE_PC_DEFAULT:
	case MODE_SENSE_PC_SAVED:
		break;
	case MODE_SENSE_PC_CHANGEABLE:
		break;
	}

	(void) bcopy(&header, addr, sizeof (header));
	(void) bcopy(&page8, addr + sizeof (header), sizeof (page8));

	pkt->pkt_resid = sp->cmd_count - sizeof (page8) - sizeof (header);
	rval = 0;

	return (rval);
}

/* ARGSUSED 0 */
int
bsd_scsi_mode_select(struct scsi_pkt *pkt)
{
	return (0);
}

int
bsd_scsi_read_capacity_8(struct scsi_pkt *pkt)
{
	struct emul64_cmd	*sp = PKT2CMD(pkt);
	emul64_tgt_t		*tgt;
	struct scsi_capacity	cap;
	int			rval = 0;

	EMUL64_MUTEX_ENTER(sp->cmd_emul64);
	tgt = find_tgt(sp->cmd_emul64,
	    pkt->pkt_address.a_target, pkt->pkt_address.a_lun);
	EMUL64_MUTEX_EXIT(sp->cmd_emul64);
	if (tgt->emul64_tgt_sectors > 0xffffffff)
		cap.capacity = 0xffffffff;
	else
		cap.capacity =
		    uint32_to_scsi_uint32(tgt->emul64_tgt_sectors);
	cap.lbasize = uint32_to_scsi_uint32((uint_t)DEV_BSIZE);

	pkt->pkt_resid = sp->cmd_count - sizeof (struct scsi_capacity);

	(void) bcopy(&cap, (caddr_t)sp->cmd_addr,
	    sizeof (struct scsi_capacity));
	return (rval);
}

int
bsd_scsi_read_capacity_16(struct scsi_pkt *pkt)
{
	struct emul64_cmd	*sp = PKT2CMD(pkt);
	emul64_tgt_t		*tgt;
	struct scsi_capacity_16 cap;
	int			rval = 0;

	EMUL64_MUTEX_ENTER(sp->cmd_emul64);
	tgt = find_tgt(sp->cmd_emul64,
	    pkt->pkt_address.a_target, pkt->pkt_address.a_lun);
	EMUL64_MUTEX_EXIT(sp->cmd_emul64);

	cap.sc_capacity = uint64_to_scsi_uint64(tgt->emul64_tgt_sectors);
	cap.sc_lbasize = uint32_to_scsi_uint32((uint_t)DEV_BSIZE);
	cap.sc_rto_en = 0;
	cap.sc_prot_en = 0;
	cap.sc_rsvd0 = 0;
	bzero(&cap.sc_rsvd1[0], sizeof (cap.sc_rsvd1));

	pkt->pkt_resid = sp->cmd_count - sizeof (struct scsi_capacity_16);

	(void) bcopy(&cap, (caddr_t)sp->cmd_addr,
	    sizeof (struct scsi_capacity_16));
	return (rval);
}
int
bsd_scsi_read_capacity(struct scsi_pkt *pkt)
{
	return (bsd_scsi_read_capacity_8(pkt));
}


/* ARGSUSED 0 */
int
bsd_scsi_reserve(struct scsi_pkt *pkt)
{
	return (0);
}

/* ARGSUSED 0 */
int
bsd_scsi_release(struct scsi_pkt *pkt)
{
	return (0);
}


int
bsd_scsi_read_defect_list(struct scsi_pkt *pkt)
{
	pkt->pkt_resid = 0;
	return (0);
}


/* ARGSUSED 0 */
int
bsd_scsi_reassign_block(struct scsi_pkt *pkt)
{
	return (0);
}


static int
bsd_readblks(struct emul64 *emul64, ushort_t target, ushort_t lun,
    diskaddr_t blkno, int nblks, unsigned char *bufaddr)
{
	emul64_tgt_t	*tgt;
	blklist_t	*blk;
	emul64_rng_overlap_t overlap;
	int		i = 0;

	if (emul64debug) {
		cmn_err(CE_CONT, "%s: bsd_readblks: "
		    "<%d,%d> blk %llu (0x%llx) nblks %d\n",
		    emul64_name, target, lun, blkno, blkno, nblks);
	}

	emul64_yield_check();

	EMUL64_MUTEX_ENTER(emul64);
	tgt = find_tgt(emul64, target, lun);
	EMUL64_MUTEX_EXIT(emul64);
	if (tgt == NULL) {
		cmn_err(CE_WARN, "%s: bsd_readblks: no target for %d,%d\n",
		    emul64_name, target, lun);
		goto unlocked_out;
	}

	if (emul64_collect_stats) {
		mutex_enter(&emul64_stats_mutex);
		emul64_io_ops++;
		emul64_io_blocks += nblks;
		mutex_exit(&emul64_stats_mutex);
	}
	mutex_enter(&tgt->emul64_tgt_blk_lock);

	/*
	 * Keep the ioctls from changing the nowrite list for the duration
	 * of this I/O by grabbing emul64_tgt_nw_lock.  This will keep the
	 * results from our call to bsd_tgt_overlap from changing while we
	 * do the I/O.
	 */
	rw_enter(&tgt->emul64_tgt_nw_lock, RW_READER);

	overlap = bsd_tgt_overlap(tgt, blkno, nblks);
	switch (overlap) {
	case O_SAME:
	case O_SUBSET:
	case O_OVERLAP:
		cmn_err(CE_WARN, "%s: bsd_readblks: "
		    "read to blocked area %lld,%d\n",
		    emul64_name, blkno, nblks);
		rw_exit(&tgt->emul64_tgt_nw_lock);
		goto errout;
	case O_NONE:
		break;
	}
	for (i = 0; i < nblks; i++) {
		if (emul64_debug_blklist)
			cmn_err(CE_CONT, "%s: bsd_readblks: "
			    "%d of %d: blkno %lld\n",
			    emul64_name, i+1, nblks, blkno);
		if (blkno > tgt->emul64_tgt_sectors)
			break;
		blk = bsd_findblk(tgt, blkno, NULL);
		if (blk) {
			(void) bcopy(blk->bl_data, bufaddr, DEV_BSIZE);
		} else {
			(void) bzero(bufaddr, DEV_BSIZE);
		}
		blkno++;
		bufaddr += DEV_BSIZE;
	}
	rw_exit(&tgt->emul64_tgt_nw_lock);

errout:
	mutex_exit(&tgt->emul64_tgt_blk_lock);

unlocked_out:
	return ((nblks - i) * DEV_BSIZE);
}


static int
bsd_writeblks(struct emul64 *emul64, ushort_t target, ushort_t lun,
    diskaddr_t blkno, int nblks, unsigned char *bufaddr)
{
	emul64_tgt_t	*tgt;
	blklist_t	*blk;
	emul64_rng_overlap_t overlap;
	avl_index_t	where;
	int		i = 0;

	if (emul64debug) {
		cmn_err(CE_CONT, "%s: bsd_writeblks: "
		    "<%d,%d> blk %llu (0x%llx) nblks %d\n",
		    emul64_name, target, lun, blkno, blkno, nblks);
	}

	emul64_yield_check();

	EMUL64_MUTEX_ENTER(emul64);
	tgt = find_tgt(emul64, target, lun);
	EMUL64_MUTEX_EXIT(emul64);
	if (tgt == NULL) {
		cmn_err(CE_WARN, "%s: bsd_writeblks: no target for %d,%d\n",
		    emul64_name, target, lun);
		goto unlocked_out;
	}

	if (emul64_collect_stats) {
		mutex_enter(&emul64_stats_mutex);
		emul64_io_ops++;
		emul64_io_blocks += nblks;
		mutex_exit(&emul64_stats_mutex);
	}
	mutex_enter(&tgt->emul64_tgt_blk_lock);

	/*
	 * Keep the ioctls from changing the nowrite list for the duration
	 * of this I/O by grabbing emul64_tgt_nw_lock.  This will keep the
	 * results from our call to bsd_tgt_overlap from changing while we
	 * do the I/O.
	 */
	rw_enter(&tgt->emul64_tgt_nw_lock, RW_READER);
	overlap = bsd_tgt_overlap(tgt, blkno, nblks);
	switch (overlap) {
	case O_SAME:
	case O_SUBSET:
		if (emul64_collect_stats) {
			mutex_enter(&emul64_stats_mutex);
			emul64_skipped_io++;
			emul64_skipped_blk += nblks;
			mutex_exit(&emul64_stats_mutex);
		}
		rw_exit(&tgt->emul64_tgt_nw_lock);
		mutex_exit(&tgt->emul64_tgt_blk_lock);
		return (0);
	case O_OVERLAP:
	case O_NONE:
		break;
	}
	for (i = 0; i < nblks; i++) {
		if ((overlap == O_NONE) ||
		    (bsd_tgt_overlap(tgt, blkno, 1) == O_NONE)) {
			/*
			 * If there was no overlap for the entire I/O range
			 * or if there is no overlap for this particular
			 * block, then we need to do the write.
			 */
			if (emul64_debug_blklist)
				cmn_err(CE_CONT, "%s: bsd_writeblks: "
				    "%d of %d: blkno %lld\n",
				    emul64_name, i+1, nblks, blkno);
			if (blkno > tgt->emul64_tgt_sectors) {
				cmn_err(CE_WARN, "%s: bsd_writeblks: "
				    "blkno %lld, tgt_sectors %lld\n",
				    emul64_name, blkno,
				    tgt->emul64_tgt_sectors);
				break;
			}

			blk = bsd_findblk(tgt, blkno, &where);
			if (bcmp(bufaddr, emul64_zeros, DEV_BSIZE) == 0) {
				if (blk) {
					bsd_freeblk(tgt, blk);
				}
			} else {
				if (blk) {
					(void) bcopy(bufaddr, blk->bl_data,
					    DEV_BSIZE);
				} else {
					bsd_allocblk(tgt, blkno,
					    (caddr_t)bufaddr, where);
				}
			}
		}
		blkno++;
		bufaddr += DEV_BSIZE;
	}

	/*
	 * Now that we're done with our I/O, allow the ioctls to change the
	 * nowrite list.
	 */
	rw_exit(&tgt->emul64_tgt_nw_lock);
	mutex_exit(&tgt->emul64_tgt_blk_lock);

unlocked_out:
	return ((nblks - i) * DEV_BSIZE);
}

emul64_tgt_t *
find_tgt(struct emul64 *emul64, ushort_t target, ushort_t lun)
{
	emul64_tgt_t	*tgt;

	tgt = emul64->emul64_tgt;
	while (tgt) {
		if (tgt->emul64_tgt_saddr.a_target == target &&
		    tgt->emul64_tgt_saddr.a_lun == lun) {
			break;
		}
		tgt = tgt->emul64_tgt_next;
	}
	return (tgt);

}

/*
 * Free all blocks that are part of the specified range.
 */
int
bsd_freeblkrange(emul64_tgt_t *tgt, emul64_range_t *range)
{
	blklist_t	*blk;
	blklist_t	*nextblk;

	ASSERT(mutex_owned(&tgt->emul64_tgt_blk_lock));
	for (blk = (blklist_t *)avl_first(&tgt->emul64_tgt_data);
	    blk != NULL;
	    blk = nextblk) {
		/*
		 * We need to get the next block pointer now, because blk
		 * will be freed inside the if statement.
		 */
		nextblk = AVL_NEXT(&tgt->emul64_tgt_data, blk);

		if (emul64_overlap(range, blk->bl_blkno, (size_t)1) != O_NONE) {
			bsd_freeblk(tgt, blk);
		}
	}
	return (0);
}

static blklist_t *
bsd_findblk(emul64_tgt_t *tgt, diskaddr_t blkno, avl_index_t *where)
{
	blklist_t	*blk;
	blklist_t	search;

	ASSERT(mutex_owned(&tgt->emul64_tgt_blk_lock));

	search.bl_blkno = blkno;
	blk = (blklist_t *)avl_find(&tgt->emul64_tgt_data, &search, where);
	return (blk);
}


static void
bsd_allocblk(emul64_tgt_t *tgt,
		diskaddr_t blkno,
		caddr_t data,
		avl_index_t where)
{
	blklist_t	*blk;

	if (emul64_debug_blklist)
		cmn_err(CE_CONT, "%s: bsd_allocblk: %llu\n",
		    emul64_name, blkno);

	ASSERT(mutex_owned(&tgt->emul64_tgt_blk_lock));

	blk = (blklist_t *)kmem_zalloc(sizeof (blklist_t), KM_SLEEP);
	blk->bl_data = (uchar_t *)kmem_zalloc(DEV_BSIZE, KM_SLEEP);
	blk->bl_blkno = blkno;
	(void) bcopy(data, blk->bl_data, DEV_BSIZE);
	avl_insert(&tgt->emul64_tgt_data, (void *) blk, where);

	if (emul64_collect_stats) {
		mutex_enter(&emul64_stats_mutex);
		emul64_nonzero++;
		tgt->emul64_list_length++;
		if (tgt->emul64_list_length > emul64_max_list_length) {
			emul64_max_list_length = tgt->emul64_list_length;
		}
		mutex_exit(&emul64_stats_mutex);
	}
}

static void
bsd_freeblk(emul64_tgt_t *tgt, blklist_t *blk)
{
	if (emul64_debug_blklist)
		cmn_err(CE_CONT, "%s: bsd_freeblk: <%d,%d> blk=%lld\n",
		    emul64_name, tgt->emul64_tgt_saddr.a_target,
		    tgt->emul64_tgt_saddr.a_lun, blk->bl_blkno);

	ASSERT(mutex_owned(&tgt->emul64_tgt_blk_lock));

	avl_remove(&tgt->emul64_tgt_data, (void *) blk);
	if (emul64_collect_stats) {
		mutex_enter(&emul64_stats_mutex);
		emul64_nonzero--;
		tgt->emul64_list_length--;
		mutex_exit(&emul64_stats_mutex);
	}
	kmem_free(blk->bl_data, DEV_BSIZE);
	kmem_free(blk, sizeof (blklist_t));
}

/*
 * Look for overlap between a nowrite range and a block range.
 *
 * NOTE:  Callers of this function must hold the tgt->emul64_tgt_nw_lock
 *	  lock.  For the purposes of this function, a reader lock is
 *	  sufficient.
 */
static emul64_rng_overlap_t
bsd_tgt_overlap(emul64_tgt_t *tgt, diskaddr_t blkno, int count)
{
	emul64_nowrite_t	*nw;
	emul64_rng_overlap_t	rv = O_NONE;

	for (nw = tgt->emul64_tgt_nowrite;
	    (nw != NULL) && (rv == O_NONE);
	    nw = nw->emul64_nwnext) {
		rv = emul64_overlap(&nw->emul64_blocked, blkno, (size_t)count);
	}
	return (rv);
}

/*
 * Operations that do a lot of I/O, such as RAID 5 initializations, result
 * in a CPU bound kernel when the device is an emul64 device.  This makes
 * the machine look hung.  To avoid this problem, give up the CPU from time
 * to time.
 */

static void
emul64_yield_check()
{
	static uint_t	emul64_io_count = 0;	/* # I/Os since last wait */
	static uint_t	emul64_waiting = FALSE;	/* TRUE -> a thread is in */
						/*   cv_timed wait. */
	clock_t		ticks;

	if (emul64_yield_enable == 0)
		return;

	mutex_enter(&emul64_yield_mutex);

	if (emul64_waiting == TRUE) {
		/*
		 * Another thread has already started the timer.  We'll
		 * just wait here until their time expires, and they
		 * broadcast to us.  When they do that, we'll return and
		 * let our caller do more I/O.
		 */
		cv_wait(&emul64_yield_cv, &emul64_yield_mutex);
	} else if (emul64_io_count++ > emul64_yield_period) {
		/*
		 * Set emul64_waiting to let other threads know that we
		 * have started the timer.
		 */
		emul64_waiting = TRUE;
		emul64_num_delay_called++;
		ticks = drv_usectohz(emul64_yield_length);
		if (ticks == 0)
			ticks = 1;
		(void) cv_reltimedwait(&emul64_yield_cv, &emul64_yield_mutex,
		    ticks, TR_CLOCK_TICK);
		emul64_io_count = 0;
		emul64_waiting = FALSE;

		/* Broadcast in case others are waiting. */
		cv_broadcast(&emul64_yield_cv);
	}

	mutex_exit(&emul64_yield_mutex);
}
