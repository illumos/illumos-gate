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
 * Enclosure Services Devices, SAF-TE Enclosure Routines
 *
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/modctl.h>
#include <sys/file.h>
#include <sys/scsi/scsi.h>
#include <sys/stat.h>
#include <sys/scsi/targets/sesio.h>
#include <sys/scsi/targets/ses.h>


static int set_objstat_sel(ses_softc_t *, ses_objarg *, int);
static int wrbuf16(ses_softc_t *, uchar_t, uchar_t, uchar_t, uchar_t, int);
static void wrslot_stat(ses_softc_t *, int);
static int perf_slotop(ses_softc_t *, uchar_t, uchar_t, int);

#define	ALL_ENC_STAT \
	(ENCSTAT_CRITICAL|ENCSTAT_UNRECOV|ENCSTAT_NONCRITICAL|ENCSTAT_INFO)

#define	SCRATCH	64
#define	NPSEUDO_THERM	1
#define	NPSEUDO_ALARM	1
struct scfg {
	/*
	 * Cached Configuration
	 */
	uchar_t	Nfans;		/* Number of Fans */
	uchar_t	Npwr;		/* Number of Power Supplies */
	uchar_t	Nslots;		/* Number of Device Slots */
	uchar_t	DoorLock;	/* Door Lock Installed */
	uchar_t	Ntherm;		/* Number of Temperature Sensors */
	uchar_t	Nspkrs;		/* Number of Speakers */
	uchar_t  Nalarm;		/* Number of Alarms (at least one) */
	/*
	 * Cached Flag Bytes for Global Status
	 */
	uchar_t	flag1;
	uchar_t	flag2;
	/*
	 * What object index ID is where various slots start.
	 */
	uchar_t	pwroff;
	uchar_t	slotoff;
#define	ALARM_OFFSET(cc)	(cc)->slotoff - 1
};
#define	FLG1_ALARM	0x1
#define	FLG1_GLOBFAIL	0x2
#define	FLG1_GLOBWARN	0x4
#define	FLG1_ENCPWROFF	0x8
#define	FLG1_ENCFANFAIL	0x10
#define	FLG1_ENCPWRFAIL	0x20
#define	FLG1_ENCDRVFAIL	0x40
#define	FLG1_ENCDRVWARN	0x80

#define	FLG2_LOCKDOOR	0x4
#define	SAFTE_PRIVATE	sizeof (struct scfg)

#if	!defined(lint)
_NOTE(MUTEX_PROTECTS_DATA(scsi_device::sd_mutex, scfg))
_NOTE(DATA_READABLE_WITHOUT_LOCK(scfg::Nfans))
_NOTE(DATA_READABLE_WITHOUT_LOCK(scfg::Npwr))
_NOTE(DATA_READABLE_WITHOUT_LOCK(scfg::Nslots))
_NOTE(DATA_READABLE_WITHOUT_LOCK(scfg::DoorLock))
_NOTE(DATA_READABLE_WITHOUT_LOCK(scfg::Ntherm))
_NOTE(DATA_READABLE_WITHOUT_LOCK(scfg::Nspkrs))
_NOTE(DATA_READABLE_WITHOUT_LOCK(scfg::Nalarm))
_NOTE(DATA_READABLE_WITHOUT_LOCK(scfg::flag1))
_NOTE(DATA_READABLE_WITHOUT_LOCK(scfg::flag2))
_NOTE(DATA_READABLE_WITHOUT_LOCK(scfg::pwroff))
_NOTE(DATA_READABLE_WITHOUT_LOCK(scfg::slotoff))
#endif

static int
safte_getconfig(ses_softc_t *ssc)
{
	struct scfg *cfg;
	int err;
	Uscmd local, *lp = &local;
	char rqbuf[SENSE_LENGTH], *sdata;
	static char cdb[CDB_GROUP1] =
	    { SCMD_READ_BUFFER, 1, SAFTE_RD_RDCFG, 0, 0, 0, 0, 0, SCRATCH, 0 };

	cfg = ssc->ses_private;
	if (cfg == NULL)
		return (ENXIO);

	sdata = kmem_alloc(SCRATCH, KM_SLEEP);
	if (sdata == NULL)
		return (ENOMEM);

	lp->uscsi_flags = USCSI_READ|USCSI_RQENABLE;
	lp->uscsi_timeout = ses_io_time;
	lp->uscsi_cdb = cdb;
	lp->uscsi_bufaddr = sdata;
	lp->uscsi_buflen = SCRATCH;
	lp->uscsi_cdblen = sizeof (cdb);
	lp->uscsi_rqbuf = rqbuf;
	lp->uscsi_rqlen = sizeof (rqbuf);

	err = ses_runcmd(ssc, lp);
	if (err) {
		kmem_free(sdata, SCRATCH);
		return (err);
	}

	if ((lp->uscsi_buflen - lp->uscsi_resid) < 6) {
		SES_LOG(ssc, CE_NOTE, "Too little data (%ld) for configuration",
		    lp->uscsi_buflen - lp->uscsi_resid);
		kmem_free(sdata, SCRATCH);
		return (EIO);
	}
	SES_LOG(ssc, SES_CE_DEBUG1, "Nfans %d Npwr %d Nslots %d Lck %d Ntherm "
	    "%d Nspkrs %d", sdata[0], sdata[1], sdata[2], sdata[3], sdata[4],
	    sdata[5]);

	mutex_enter(&ssc->ses_devp->sd_mutex);
	cfg->Nfans = sdata[0];
	cfg->Npwr = sdata[1];
	cfg->Nslots = sdata[2];
	cfg->DoorLock = sdata[3];
	cfg->Ntherm = sdata[4];
	cfg->Nspkrs = sdata[5];
	cfg->Nalarm = NPSEUDO_ALARM;
	mutex_exit(&ssc->ses_devp->sd_mutex);
	kmem_free(sdata, SCRATCH);
	return (0);
}

int
safte_softc_init(ses_softc_t *ssc, int doinit)
{
	int r, i;
	struct scfg *cc;

	if (doinit == 0) {
		mutex_enter(&ssc->ses_devp->sd_mutex);
		if (ssc->ses_nobjects) {
			if (ssc->ses_objmap) {
				kmem_free(ssc->ses_objmap,
				    ssc->ses_nobjects * sizeof (encobj));
				ssc->ses_objmap = NULL;
			}
			ssc->ses_nobjects = 0;
		}
		if (ssc->ses_private) {
			kmem_free(ssc->ses_private, SAFTE_PRIVATE);
			ssc->ses_private = NULL;
		}
		mutex_exit(&ssc->ses_devp->sd_mutex);
		return (0);
	}

	mutex_enter(&ssc->ses_devp->sd_mutex);
	if (ssc->ses_private == NULL) {
		ssc->ses_private = kmem_zalloc(SAFTE_PRIVATE, KM_SLEEP);
		if (ssc->ses_private == NULL) {
			mutex_exit(&ssc->ses_devp->sd_mutex);
			return (ENOMEM);
		}
	}

	ssc->ses_nobjects = 0;
	ssc->ses_encstat = 0;
	mutex_exit(&ssc->ses_devp->sd_mutex);

	if ((r = safte_getconfig(ssc)) != 0) {
		return (r);
	}

	/*
	 * The number of objects here, as well as that reported by the
	 * READ_BUFFER/GET_CONFIG call, are the over-temperature flags (15)
	 * that get reported during READ_BUFFER/READ_ENC_STATUS.
	 */
	mutex_enter(&ssc->ses_devp->sd_mutex);
	cc = ssc->ses_private;
	ssc->ses_nobjects = cc->Nfans + cc->Npwr + cc->Nslots + cc->DoorLock +
	    cc->Ntherm + cc->Nspkrs + NPSEUDO_THERM + NPSEUDO_ALARM;
	ssc->ses_objmap = (encobj *)
	    kmem_zalloc(ssc->ses_nobjects * sizeof (encobj), KM_SLEEP);
	mutex_exit(&ssc->ses_devp->sd_mutex);
	if (ssc->ses_objmap == NULL)
		return (ENOMEM);
	r = 0;
	/*
	 * Note that this is all arranged for the convenience
	 * in later fetches of status.
	 */
	mutex_enter(&ssc->ses_devp->sd_mutex);
	for (i = 0; i < cc->Nfans; i++)
		ssc->ses_objmap[r++].enctype = SESTYP_FAN;
	cc->pwroff = (uchar_t)r;
	for (i = 0; i < cc->Npwr; i++)
		ssc->ses_objmap[r++].enctype = SESTYP_POWER;
	for (i = 0; i < cc->DoorLock; i++)
		ssc->ses_objmap[r++].enctype = SESTYP_DOORLOCK;
	for (i = 0; i < cc->Nspkrs; i++)
		ssc->ses_objmap[r++].enctype = SESTYP_ALARM;
	for (i = 0; i < cc->Ntherm; i++)
		ssc->ses_objmap[r++].enctype = SESTYP_THERM;
	for (i = 0; i < NPSEUDO_THERM; i++)
		ssc->ses_objmap[r++].enctype = SESTYP_THERM;
	ssc->ses_objmap[r++].enctype = SESTYP_ALARM;
	cc->slotoff = (uchar_t)r;
	for (i = 0; i < cc->Nslots; i++)
		ssc->ses_objmap[r++].enctype = SESTYP_DEVICE;
	mutex_exit(&ssc->ses_devp->sd_mutex);
	return (0);
}

int
safte_init_enc(ses_softc_t *ssc)
{
	int err;
	Uscmd local, *lp = &local;
	char rqbuf[SENSE_LENGTH], *sdata;
	static char cdb0[CDB_GROUP1] = { SCMD_SDIAG };
	static char cdb[CDB_GROUP1] =
	    { SCMD_WRITE_BUFFER, 1, 0, 0, 0, 0, 0, 0, SCRATCH, 0 };

	sdata = kmem_alloc(SCRATCH, KM_SLEEP);
	lp->uscsi_flags = USCSI_RQENABLE;
	lp->uscsi_timeout = ses_io_time;
	lp->uscsi_cdb = cdb0;
	lp->uscsi_bufaddr = NULL;
	lp->uscsi_buflen = 0;
	lp->uscsi_cdblen = sizeof (cdb0);
	lp->uscsi_rqbuf = rqbuf;
	lp->uscsi_rqlen = sizeof (rqbuf);
	err = ses_runcmd(ssc, lp);
	if (err) {
		kmem_free(sdata, SCRATCH);
		return (err);
	}

	lp->uscsi_flags = USCSI_WRITE|USCSI_RQENABLE;
	lp->uscsi_timeout = ses_io_time;
	lp->uscsi_cdb = cdb;
	lp->uscsi_bufaddr = sdata;
	lp->uscsi_buflen = SCRATCH;
	lp->uscsi_cdblen = sizeof (cdb);
	lp->uscsi_rqbuf = rqbuf;
	lp->uscsi_rqlen = sizeof (rqbuf);
	bzero(&sdata[1], 15);
	sdata[0] = SAFTE_WT_GLOBAL;
	err = ses_runcmd(ssc, lp);
	kmem_free(sdata, SCRATCH);
	return (err);
}


static char *toolittle = "Too Little Data Returned (%d) at line %d";
#define	BAIL(r, x, k, l, m, n) \
	if (r >= x) { \
		SES_LOG(ssc, CE_NOTE, toolittle, x, __LINE__); \
		kmem_free(k, l); \
		kmem_free(m, n); \
		return (EIO); \
	}

static int
safte_rdstat(ses_softc_t *ssc, int slpflg)
{
	int err, oid, r, i, hiwater, nitems;
	ushort_t tempflags;
	size_t buflen;
	uchar_t status, oencstat;
	Uscmd local, *lp = &local;
	struct scfg *cc = ssc->ses_private;
	char rqbuf[SENSE_LENGTH], *sdata;
	char cdb[CDB_GROUP1];
	int *driveids, id_size = cc->Nslots * sizeof (int);

	driveids = kmem_alloc(id_size, slpflg);
	if (driveids == NULL) {
		return (ENOMEM);
	}

	/*
	 * The number of bytes of data we need to get is
	 * Nfans + Npwr + Nslots + Nspkrs + Ntherm + nochoice
	 * (nochoice = 1 doorlock + 1 spkr + 2 pseudo therms + 10 extra)
	 * the extra are simply for good luck.
	 */
	buflen = cc->Nfans + cc->Npwr + cc->Nslots + cc->Nspkrs;
	buflen += cc->Ntherm + 14;

	/*
	 * Towards the end of this function this buffer is reused.
	 * Thus we need to make sure that we have allocated enough
	 * memory retrieving buffer 1 & 4.
	 * buffer 1 -> element status & drive id
	 * buffer 4 -> drive status & drive command history.
	 * buffer 4 uses 4 bytes per drive bay.
	 */

	if (buflen < cc->Nslots * 4) {
		buflen = cc->Nslots * 4;
	}

	if (ssc->ses_nobjects > buflen)
		buflen = ssc->ses_nobjects;

	if (buflen > 0xffff) {
		cmn_err(CE_WARN, "Illogical SCSI data");
		kmem_free(driveids, id_size);
		return (EIO);
	}

	sdata = kmem_alloc(buflen, slpflg);
	if (sdata == NULL) {
		kmem_free(driveids, id_size);
		return (ENOMEM);
	}

	cdb[0] = SCMD_READ_BUFFER;
	cdb[1] = 1;
	cdb[2] = SAFTE_RD_RDESTS;
	cdb[3] = 0;
	cdb[4] = 0;
	cdb[5] = 0;
	cdb[6] = 0;
	cdb[7] = (buflen >> 8) & 0xff;
	cdb[8] = buflen & 0xff;
	cdb[9] = 0;
	lp->uscsi_flags = USCSI_READ|USCSI_RQENABLE;
	lp->uscsi_timeout = ses_io_time;
	lp->uscsi_cdb = cdb;
	lp->uscsi_bufaddr = sdata;
	lp->uscsi_buflen = buflen;
	lp->uscsi_cdblen = sizeof (cdb);
	lp->uscsi_rqbuf = rqbuf;
	lp->uscsi_rqlen = sizeof (rqbuf);

	err = ses_runcmd(ssc, lp);
	if (err) {
		kmem_free(sdata, buflen);
		kmem_free(driveids, id_size);
		return (err);
	}

	hiwater = lp->uscsi_buflen - lp->uscsi_resid;

	/*
	 * invalidate all status bits.
	 */
	mutex_enter(&ssc->ses_devp->sd_mutex);
	for (i = 0; i < ssc->ses_nobjects; i++)
		ssc->ses_objmap[i].svalid = 0;
	oencstat = ssc->ses_encstat & ALL_ENC_STAT;
	ssc->ses_encstat = 0;
	mutex_exit(&ssc->ses_devp->sd_mutex);

	/*
	 * Now parse returned buffer.
	 * If we didn't get enough data back,
	 * that's considered a fatal error.
	 */
	oid = r = 0;

	for (nitems = i = 0; i < cc->Nfans; i++) {
		BAIL(r, hiwater, sdata, buflen, driveids, id_size);
		/*
		 * 0 = Fan Operational
		 * 1 = Fan is malfunctioning
		 * 2 = Fan is not present
		 * 0x80 = Unknown or Not Reportable Status
		 */
		mutex_enter(&ssc->ses_devp->sd_mutex);
		ssc->ses_objmap[oid].encstat[1] = 0;	/* resvd */
		ssc->ses_objmap[oid].encstat[2] = 0;	/* resvd */
		switch ((uchar_t)sdata[r]) {
		case 0:
			nitems++;
			ssc->ses_objmap[oid].encstat[0] = SESSTAT_OK;
			/*
			 * We could get fancier and cache
			 * fan speeds that we have set, but
			 * that isn't done now.
			 */
			ssc->ses_objmap[oid].encstat[3] = 7;
			break;

		case 1:
			ssc->ses_objmap[oid].encstat[0] = SESSTAT_CRIT;
			/*
			 * FAIL and FAN STOPPED synthesized
			 */
			ssc->ses_objmap[oid].encstat[3] = 0x40;
			/*
			 * Enclosure marked with CRITICAL error
			 * if only one fan or no thermometers,
			 * else NONCRIT error set.
			 */
			if (cc->Nfans == 1 || cc->Ntherm == 0)
				ssc->ses_encstat |= ENCSTAT_CRITICAL;
			else
				ssc->ses_encstat |= ENCSTAT_NONCRITICAL;
			break;
		case 2:
			ssc->ses_objmap[oid].encstat[0] = SESSTAT_NOTINSTALLED;
			ssc->ses_objmap[oid].encstat[3] = 0;
			if (cc->Nfans == 1)
				ssc->ses_encstat |= ENCSTAT_CRITICAL;
			else
				ssc->ses_encstat |= ENCSTAT_NONCRITICAL;
			break;
		case 0x80:
			ssc->ses_objmap[oid].encstat[0] = SESSTAT_UNKNOWN;
			ssc->ses_objmap[oid].encstat[3] = 0;
			ssc->ses_encstat |= ENCSTAT_INFO;
			break;
		default:
			ssc->ses_objmap[oid].encstat[0] = SESSTAT_UNSUPPORTED;
			SES_LOG(ssc, CE_NOTE, "unknown fan%d status 0x%x",
			    i, sdata[r] & 0xff);
			break;
		}
		ssc->ses_objmap[oid++].svalid = 1;
		mutex_exit(&ssc->ses_devp->sd_mutex);
		r++;
	}
	mutex_enter(&ssc->ses_devp->sd_mutex);
	/*
	 * No matter how you cut it, no cooling elements when there
	 * should be some there is critical.
	 */
	if (cc->Nfans && nitems == 0) {
		ssc->ses_encstat |= ENCSTAT_CRITICAL;
	}
	mutex_exit(&ssc->ses_devp->sd_mutex);


	for (i = 0; i < cc->Npwr; i++) {
		BAIL(r, hiwater, sdata, buflen, driveids, id_size);
		mutex_enter(&ssc->ses_devp->sd_mutex);
		ssc->ses_objmap[oid].encstat[0] = SESSTAT_UNSUPPORTED;
		ssc->ses_objmap[oid].encstat[1] = 0;	/* resvd */
		ssc->ses_objmap[oid].encstat[2] = 0;	/* resvd */
		ssc->ses_objmap[oid].encstat[3] = 0x20;	/* requested on */
		switch ((uchar_t)sdata[r]) {
		case 0x00:	/* pws operational and on */
			ssc->ses_objmap[oid].encstat[0] = SESSTAT_OK;
			break;
		case 0x01:	/* pws operational and off */
			ssc->ses_objmap[oid].encstat[3] = 0x10;
			ssc->ses_objmap[oid].encstat[0] = SESSTAT_NOTAVAIL;
			ssc->ses_encstat |= ENCSTAT_INFO;
			break;
		case 0x10:	/* pws is malfunctioning and commanded on */
			ssc->ses_objmap[oid].encstat[3] = 0x61;
			ssc->ses_objmap[oid].encstat[0] = SESSTAT_CRIT;
			if (cc->Npwr < 2)
				ssc->ses_encstat |= ENCSTAT_CRITICAL;
			else
				ssc->ses_encstat |= ENCSTAT_NONCRITICAL;
			break;

		case 0x11:	/* pws is malfunctioning and commanded off */
			ssc->ses_objmap[oid].encstat[3] = 0x51;
			ssc->ses_objmap[oid].encstat[0] = SESSTAT_CRIT;
			if (cc->Npwr < 2)
				ssc->ses_encstat |= ENCSTAT_CRITICAL;
			else
				ssc->ses_encstat |= ENCSTAT_NONCRITICAL;
			break;
		case 0x20:	/* pws is not present */
			ssc->ses_objmap[oid].encstat[0] = SESSTAT_NOTINSTALLED;
			ssc->ses_objmap[oid].encstat[3] = 0;
			if (cc->Npwr < 2)
				ssc->ses_encstat |= ENCSTAT_CRITICAL;
			else
				ssc->ses_encstat |= ENCSTAT_INFO;
			break;
		case 0x21:	/* pws is present */
			break;
		case 0x80:	/* Unknown or Not Reportable Status */
			ssc->ses_objmap[oid].encstat[0] = SESSTAT_UNKNOWN;
			ssc->ses_objmap[oid].encstat[3] = 0;
			ssc->ses_encstat |= ENCSTAT_INFO;
			break;
		default:
			ssc->ses_objmap[oid].encstat[0] = SESSTAT_UNSUPPORTED;
			SES_LOG(ssc, CE_NOTE, "unknown pwr%d status 0x%x",
			    i, sdata[r] & 0xff);
			break;
		}
		ssc->ses_objmap[oid++].svalid = 1;
		mutex_exit(&ssc->ses_devp->sd_mutex);
		r++;
	}

	/*
	 * Now I am going to save the target id's for the end of
	 * the function.  (when I build the drive objects)
	 * that is when I will be getting the drive status from buffer 4
	 */

	for (i = 0; i < cc->Nslots; i++) {
		driveids[i] = sdata[r++];
	}



	/*
	 * We always have doorlock status, no matter what,
	 * but we only save the status if we have one.
	 */
	BAIL(r, hiwater, sdata, buflen, driveids, id_size);
	if (cc->DoorLock) {
		/*
		 * 0 = Door Locked
		 * 1 = Door Unlocked, or no Lock Installed
		 * 0x80 = Unknown or Not Reportable Status
		 */
		mutex_enter(&ssc->ses_devp->sd_mutex);
		ssc->ses_objmap[oid].encstat[1] = 0;
		ssc->ses_objmap[oid].encstat[2] = 0;
		switch ((uchar_t)sdata[r]) {
		case 0:
			ssc->ses_objmap[oid].encstat[0] = SESSTAT_OK;
			ssc->ses_objmap[oid].encstat[3] = 0;
			break;
		case 1:
			ssc->ses_objmap[oid].encstat[0] = SESSTAT_OK;
			ssc->ses_objmap[oid].encstat[3] = 1;
			break;
		case 0x80:
			ssc->ses_objmap[oid].encstat[0] = SESSTAT_UNKNOWN;
			ssc->ses_objmap[oid].encstat[3] = 0;
			ssc->ses_encstat |= ENCSTAT_INFO;
			break;
		default:
			ssc->ses_objmap[oid].encstat[0] = SESSTAT_UNSUPPORTED;
			SES_LOG(ssc, CE_NOTE, "unknown lock status 0x%x",
			    sdata[r] & 0xff);
			break;
		}
		ssc->ses_objmap[oid++].svalid = 1;
		mutex_exit(&ssc->ses_devp->sd_mutex);
	}
	r++;

	/*
	 * We always have speaker status, no matter what,
	 * but we only save the status if we have one.
	 */
	BAIL(r, hiwater, sdata, buflen, driveids, id_size);
	if (cc->Nspkrs) {
		mutex_enter(&ssc->ses_devp->sd_mutex);
		ssc->ses_objmap[oid].encstat[1] = 0;
		ssc->ses_objmap[oid].encstat[2] = 0;
		if (sdata[r] == 1) {
			/*
			 * We need to cache tone urgency indicators.
			 * Someday.
			 */
			ssc->ses_objmap[oid].encstat[0] = SESSTAT_NONCRIT;
			ssc->ses_objmap[oid].encstat[3] = 0x8;
			ssc->ses_encstat |= ENCSTAT_NONCRITICAL;
		} else if (sdata[r] == 0) {
			ssc->ses_objmap[oid].encstat[0] = SESSTAT_OK;
			ssc->ses_objmap[oid].encstat[3] = 0;
		} else {
			ssc->ses_objmap[oid].encstat[0] = SESSTAT_UNSUPPORTED;
			ssc->ses_objmap[oid].encstat[3] = 0;
			SES_LOG(ssc, CE_NOTE, "unknown spkr status 0x%x",
			    sdata[r] & 0xff);
		}
		ssc->ses_objmap[oid++].svalid = 1;
		mutex_exit(&ssc->ses_devp->sd_mutex);
	}
	r++;

	for (i = 0; i < cc->Ntherm; i++) {
		BAIL(r, hiwater, sdata, buflen, driveids, id_size);
		/*
		 * Status is a range from -10 to 245 deg Celsius,
		 * which we need to normalize to -20 to -235 according
		 * to the latest SCSI spec.
		 */
		mutex_enter(&ssc->ses_devp->sd_mutex);
		ssc->ses_objmap[oid].encstat[1] = 0;
		ssc->ses_objmap[oid].encstat[2] =
		    ((unsigned int) sdata[r]) - 10;
		if (sdata[r] < 20) {
			ssc->ses_objmap[oid].encstat[0] = SESSTAT_CRIT;
			/*
			 * Set 'under temperature' failure.
			 */
			ssc->ses_objmap[oid].encstat[3] = 2;
			ssc->ses_encstat |= ENCSTAT_CRITICAL;
		} else if (sdata[r] > 30) {
			ssc->ses_objmap[oid].encstat[0] = SESSTAT_CRIT;
			/*
			 * Set 'over temperature' failure.
			 */
			ssc->ses_objmap[oid].encstat[3] = 8;
			ssc->ses_encstat |= ENCSTAT_CRITICAL;
		} else {
			ssc->ses_objmap[oid].encstat[0] = SESSTAT_OK;
		}
		ssc->ses_objmap[oid++].svalid = 1;
		mutex_exit(&ssc->ses_devp->sd_mutex);
		r++;
	}

	/*
	 * Now, for "pseudo" thermometers, we have two bytes
	 * of information in enclosure status- 16 bits. Actually,
	 * the MSB is a single TEMP ALERT flag indicating whether
	 * any other bits are set, but, thanks to fuzzy thinking,
	 * in the SAF-TE spec, this can also be set even if no
	 * other bits are set, thus making this really another
	 * binary temperature sensor.
	 */

	BAIL(r, hiwater, sdata, buflen, driveids, id_size);
	tempflags = sdata[r++];
	BAIL(r, hiwater, sdata, buflen, driveids, id_size);
	tempflags |= (tempflags << 8) | sdata[r++];
	mutex_enter(&ssc->ses_devp->sd_mutex);

#if	NPSEUDO_THERM == 1
	ssc->ses_objmap[oid].encstat[1] = 0;
	if (tempflags) {
		/* Set 'over temperature' failure. */
		ssc->ses_objmap[oid].encstat[0] = SESSTAT_CRIT;
		ssc->ses_objmap[oid].encstat[3] = 8;
		ssc->ses_encstat |= ENCSTAT_CRITICAL;
	} else {
		/* Set 'nominal' temperature. */
		ssc->ses_objmap[oid].encstat[0] = SESSTAT_OK;
	}
	ssc->ses_objmap[oid++].svalid = 1;

#else	/* NPSEUDO_THERM == 1 */
	for (i = 0; i < NPSEUDO_THERM; i++) {
		ssc->ses_objmap[oid].encstat[1] = 0;
		if (tempflags & (1 << (NPSEUDO_THERM - i - 1))) {
			ssc->ses_objmap[oid].encstat[0] = SESSTAT_CRIT;
			/* ssc->ses_objmap[oid].encstat[2] = 0; */

			/*
			 * Set 'over temperature' failure.
			 */
			ssc->ses_objmap[oid].encstat[3] = 8;
			ssc->ses_encstat |= ENCSTAT_CRITICAL;
		} else {
			/*
			 * Set 'nominal' temperature.
			 */
			ssc->ses_objmap[oid].encstat[0] = SESSTAT_OK;
			/* ssc->ses_objmap[oid].encstat[2] = 0; */
		}
		ssc->ses_objmap[oid++].svalid = 1;
	}
#endif	/* NPSEUDO_THERM == 1 */


	/*
	 * Get alarm status.
	 */
	ssc->ses_objmap[oid].encstat[0] = SESSTAT_OK;
	ssc->ses_objmap[oid].encstat[3] = ssc->ses_objmap[oid].priv;
	ssc->ses_objmap[oid++].svalid = 1;
	mutex_exit(&ssc->ses_devp->sd_mutex);

	/*
	 * Now get drive slot status
	 */
	cdb[2] = SAFTE_RD_RDDSTS;
	err = ses_runcmd(ssc, lp);
	if (err) {
		kmem_free(sdata, buflen);
		kmem_free(driveids, id_size);
		return (err);
	}
	hiwater = lp->uscsi_buflen - lp->uscsi_resid;
	for (r = i = 0; i < cc->Nslots; i++, r += 4) {
		BAIL(r+3, hiwater, sdata, buflen, driveids, id_size);
		mutex_enter(&ssc->ses_devp->sd_mutex);
		ssc->ses_objmap[oid].encstat[0] = SESSTAT_UNSUPPORTED;
		ssc->ses_objmap[oid].encstat[1] = (uchar_t)driveids[i];
		ssc->ses_objmap[oid].encstat[2] = 0;
		ssc->ses_objmap[oid].encstat[3] = 0;
		status = sdata[r+3];
		if ((status & 0x1) == 0) {	/* no device */
			ssc->ses_objmap[oid].encstat[0] = SESSTAT_NOTINSTALLED;
		} else {
			ssc->ses_objmap[oid].encstat[0] = SESSTAT_OK;
		}
		if (status & 0x2) {
			ssc->ses_objmap[oid].encstat[2] = 0x8;
		}
		if ((status & 0x4) == 0) {
			ssc->ses_objmap[oid].encstat[3] = 0x10;
		}
		ssc->ses_objmap[oid++].svalid = 1;
		mutex_exit(&ssc->ses_devp->sd_mutex);
	}
	mutex_enter(&ssc->ses_devp->sd_mutex);
	/* see comment below about sticky enclosure status */
	ssc->ses_encstat |= ENCI_SVALID | oencstat;
	mutex_exit(&ssc->ses_devp->sd_mutex);
	kmem_free(sdata, buflen);
	kmem_free(driveids, id_size);
	return (0);
}

int
safte_get_encstat(ses_softc_t *ssc, int slpflg)
{
	return (safte_rdstat(ssc, slpflg));
}

int
safte_set_encstat(ses_softc_t *ssc, uchar_t encstat, int slpflg)
{
	struct scfg *cc = ssc->ses_private;
	if (cc == NULL)
		return (0);
	mutex_enter(&ssc->ses_devp->sd_mutex);
	/*
	 * Since SAF-TE devices aren't necessarily sticky in terms
	 * of state, make our soft copy of enclosure status 'sticky'-
	 * that is, things set in enclosure status stay set (as implied
	 * by conditions set in reading object status) until cleared.
	 */
	ssc->ses_encstat &= ~ALL_ENC_STAT;
	ssc->ses_encstat |= (encstat & ALL_ENC_STAT);
	ssc->ses_encstat |= ENCI_SVALID;
	cc->flag1 &= ~(FLG1_ALARM|FLG1_GLOBFAIL|FLG1_GLOBWARN);
	if ((encstat & (ENCSTAT_CRITICAL|ENCSTAT_UNRECOV)) != 0) {
		cc->flag1 |= FLG1_ALARM|FLG1_GLOBFAIL;
	} else if ((encstat & ENCSTAT_NONCRITICAL) != 0) {
		cc->flag1 |= FLG1_GLOBWARN;
	}
	mutex_exit(&ssc->ses_devp->sd_mutex);
	return (wrbuf16(ssc, SAFTE_WT_GLOBAL, cc->flag1, cc->flag2, 0, slpflg));
}

int
safte_get_objstat(ses_softc_t *ssc, ses_objarg *obp, int slpflg)
{
	int i = (int)obp->obj_id;

	if ((ssc->ses_encstat & ENCI_SVALID) == 0 ||
	    (ssc->ses_objmap[i].svalid) == 0) {
		int r = safte_rdstat(ssc, slpflg);
		if (r)
			return (r);
	}
	obp->cstat[0] = ssc->ses_objmap[i].encstat[0];
	obp->cstat[1] = ssc->ses_objmap[i].encstat[1];
	obp->cstat[2] = ssc->ses_objmap[i].encstat[2];
	obp->cstat[3] = ssc->ses_objmap[i].encstat[3];
	return (0);
}


int
safte_set_objstat(ses_softc_t *ssc, ses_objarg *obp, int slp)
{
	int idx, err;
	encobj *ep;
	struct scfg *cc;


	SES_LOG(ssc, SES_CE_DEBUG2, "safte_set_objstat(%d): %x %x %x %x",
	    (int)obp->obj_id, obp->cstat[0], obp->cstat[1], obp->cstat[2],
	    obp->cstat[3]);

	/*
	 * If this is clear, we don't do diddly.
	 */
	if ((obp->cstat[0] & SESCTL_CSEL) == 0) {
		return (0);
	}

	err = 0;
	/*
	 * Check to see if the common bits are set and do them first.
	 */
	if (obp->cstat[0] & ~SESCTL_CSEL) {
		err = set_objstat_sel(ssc, obp, slp);
		if (err)
			return (err);
	}

	cc = ssc->ses_private;
	if (cc == NULL)
		return (0);

	idx = (int)obp->obj_id;
	ep = &ssc->ses_objmap[idx];

	switch (ep->enctype) {
	case SESTYP_DEVICE:
	{
		uchar_t slotop = 0;
		/*
		 * XXX: I should probably cache the previous state
		 * XXX: of SESCTL_DEVOFF so that when it goes from
		 * XXX: true to false I can then set PREPARE FOR OPERATION
		 * XXX: flag in PERFORM SLOT OPERATION write buffer command.
		 */
		if (obp->cstat[2] & (SESCTL_RQSINS|SESCTL_RQSRMV)) {
			slotop |= 0x2;
		}
		if (obp->cstat[2] & SESCTL_RQSID) {
			slotop |= 0x4;
		}
		err = perf_slotop(ssc, (uchar_t)idx - (uchar_t)cc->slotoff,
		    slotop, slp);
		if (err)
			return (err);
		mutex_enter(&ssc->ses_devp->sd_mutex);
		if (obp->cstat[3] & SESCTL_RQSFLT) {
			ep->priv |= 0x2;
		} else {
			ep->priv &= ~0x2;
		}
		if (ep->priv & 0xc6) {
			ep->priv &= ~0x1;
		} else {
			ep->priv |= 0x1;	/* no errors */
		}
		mutex_exit(&ssc->ses_devp->sd_mutex);
		wrslot_stat(ssc, slp);
		break;
	}
	case SESTYP_POWER:
		mutex_enter(&ssc->ses_devp->sd_mutex);
		if (obp->cstat[3] & SESCTL_RQSTFAIL) {
			cc->flag1 |= FLG1_ENCPWRFAIL;
		} else {
			cc->flag1 &= ~FLG1_ENCPWRFAIL;
		}
		mutex_exit(&ssc->ses_devp->sd_mutex);
		err = wrbuf16(ssc, SAFTE_WT_GLOBAL, cc->flag1,
		    cc->flag2, 0, slp);
		if (err)
			return (err);
		if (obp->cstat[3] & SESCTL_RQSTON) {
			(void) wrbuf16(ssc, SAFTE_WT_ACTPWS,
			    idx - cc->pwroff, 0, 0, slp);
		} else {
			(void) wrbuf16(ssc, SAFTE_WT_ACTPWS,
			    idx - cc->pwroff, 0, 1, slp);
		}
		break;
	case SESTYP_FAN:
		mutex_enter(&ssc->ses_devp->sd_mutex);
		if (obp->cstat[3] & SESCTL_RQSTFAIL) {
			cc->flag1 |= FLG1_ENCFANFAIL;
		} else {
			cc->flag1 &= ~FLG1_ENCFANFAIL;
		}
		mutex_exit(&ssc->ses_devp->sd_mutex);
		err = wrbuf16(ssc, SAFTE_WT_GLOBAL, cc->flag1,
		    cc->flag2, 0, slp);
		if (err)
			return (err);
		if (obp->cstat[3] & SESCTL_RQSTON) {
			uchar_t fsp;
			if ((obp->cstat[3] & 0x7) == 7) {
				fsp = 4;
			} else if ((obp->cstat[3] & 0x7) == 6) {
				fsp = 3;
			} else if ((obp->cstat[3] & 0x7) == 4) {
				fsp = 2;
			} else {
				fsp = 1;
			}
			(void) wrbuf16(ssc, SAFTE_WT_FANSPD, idx, fsp, 0, slp);
		} else {
			(void) wrbuf16(ssc, SAFTE_WT_FANSPD, idx, 0, 0, slp);
		}
		break;
	case SESTYP_DOORLOCK:
		mutex_enter(&ssc->ses_devp->sd_mutex);
		if (obp->cstat[3] & 0x1) {
			cc->flag2 &= ~FLG2_LOCKDOOR;
		} else {
			cc->flag2 |= FLG2_LOCKDOOR;
		}
		mutex_exit(&ssc->ses_devp->sd_mutex);
		(void) wrbuf16(ssc, SAFTE_WT_GLOBAL, cc->flag1,
		    cc->flag2, 0, slp);
		break;
	case SESTYP_ALARM:
		/*
		 * On all nonzero but the 'muted' bit, we turn on the alarm,
		 */
		mutex_enter(&ssc->ses_devp->sd_mutex);
		obp->cstat[3] &= ~0xa;
		if (obp->cstat[3] & 0x40) {
			cc->flag2 &= ~FLG1_ALARM;
		} else if (obp->cstat[3] != 0) {
			cc->flag2 |= FLG1_ALARM;
		} else {
			cc->flag2 &= ~FLG1_ALARM;
		}
		ep->priv = obp->cstat[3];
		mutex_exit(&ssc->ses_devp->sd_mutex);
		(void) wrbuf16(ssc, SAFTE_WT_GLOBAL, cc->flag1,
		    cc->flag2, 0, slp);
		break;
	default:
		break;
	}
	mutex_enter(&ssc->ses_devp->sd_mutex);
	ep->svalid = 0;
	mutex_exit(&ssc->ses_devp->sd_mutex);
	return (0);
}

static int
set_objstat_sel(ses_softc_t *ssc, ses_objarg *obp, int slp)
{
	int idx;
	encobj *ep;
	struct scfg *cc = ssc->ses_private;

	if (cc == NULL)
		return (0);

	idx = (int)obp->obj_id;
	ep = &ssc->ses_objmap[idx];

	switch (ep->enctype) {
	case SESTYP_DEVICE:
		mutex_enter(&ssc->ses_devp->sd_mutex);
		if (obp->cstat[0] & SESCTL_PRDFAIL) {
			ep->priv |= 0x40;
		}
		/* SESCTL_RSTSWAP has no correspondence in SAF-TE */
		if (obp->cstat[0] & SESCTL_DISABLE) {
			ep->priv |= 0x80;
			/*
			 * Hmm. Try to set the 'No Drive' flag.
			 * Maybe that will count as a 'disable'.
			 */
		}
		if (ep->priv & 0xc6) {
			ep->priv &= ~0x1;
		} else {
			ep->priv |= 0x1;	/* no errors */
		}
		mutex_exit(&ssc->ses_devp->sd_mutex);
		wrslot_stat(ssc, slp);
		break;
	case SESTYP_POWER:
		/*
		 * Okay- the only one that makes sense here is to
		 * do the 'disable' for a power supply.
		 */
		if (obp->cstat[0] & SESCTL_DISABLE) {
			(void) wrbuf16(ssc, SAFTE_WT_ACTPWS,
			    idx - cc->pwroff, 0, 0, slp);
		}
		break;
	case SESTYP_FAN:
		/*
		 * Okay- the only one that makes sense here is to
		 * set fan speed to zero on disable.
		 */
		if (obp->cstat[0] & SESCTL_DISABLE) {
			/* remember- fans are the first items, so idx works */
			(void) wrbuf16(ssc, SAFTE_WT_FANSPD, idx, 0, 0, slp);
		}
		break;
	case SESTYP_DOORLOCK:
		/*
		 * Well, we can 'disable' the lock.
		 */
		if (obp->cstat[0] & SESCTL_DISABLE) {
			mutex_enter(&ssc->ses_devp->sd_mutex);
			cc->flag2 &= ~FLG2_LOCKDOOR;
			mutex_exit(&ssc->ses_devp->sd_mutex);
			(void) wrbuf16(ssc, SAFTE_WT_GLOBAL, cc->flag1,
			    cc->flag2, 0, slp);
		}
		break;
	case SESTYP_ALARM:
		/*
		 * Well, we can 'disable' the alarm.
		 */
		if (obp->cstat[0] & SESCTL_DISABLE) {
			mutex_enter(&ssc->ses_devp->sd_mutex);
			cc->flag2 &= ~FLG1_ALARM;
			ep->priv |= 0x40;	/* Muted */
			mutex_exit(&ssc->ses_devp->sd_mutex);
			(void) wrbuf16(ssc, SAFTE_WT_GLOBAL, cc->flag1,
			    cc->flag2, 0, slp);
		}
		break;
	default:
		break;
	}
	mutex_enter(&ssc->ses_devp->sd_mutex);
	ep->svalid = 0;
	mutex_exit(&ssc->ses_devp->sd_mutex);
	return (0);
}

/*
 * This function handles all of the 16 byte WRITE BUFFER commands.
 */
static int
wrbuf16(ses_softc_t *ssc, uchar_t op, uchar_t b1, uchar_t b2,
    uchar_t b3, int slp)
{
	int err;
	Uscmd local, *lp = &local;
	char rqbuf[SENSE_LENGTH], *sdata;
	struct scfg *cc = ssc->ses_private;
	static char cdb[CDB_GROUP1] =
	    { SCMD_WRITE_BUFFER, 1, 0, 0, 0, 0, 0, 0, 16, 0 };

	if (cc == NULL)
		return (0);

	sdata = kmem_alloc(16, slp);
	if (sdata == NULL)
		return (ENOMEM);

	lp->uscsi_flags = USCSI_WRITE|USCSI_RQENABLE;
	lp->uscsi_timeout = ses_io_time;
	lp->uscsi_cdb = cdb;
	lp->uscsi_bufaddr = sdata;
	lp->uscsi_buflen = SCRATCH;
	lp->uscsi_cdblen = sizeof (cdb);
	lp->uscsi_rqbuf = rqbuf;
	lp->uscsi_rqlen = sizeof (rqbuf);

	sdata[0] = op;
	sdata[1] = b1;
	sdata[2] = b2;
	sdata[3] = b3;
	SES_LOG(ssc, SES_CE_DEBUG2, "saf_wrbuf16 %x %x %x %x", op, b1, b2, b3);
	bzero(&sdata[4], 12);
	err = ses_runcmd(ssc, lp);
	kmem_free(sdata, 16);
	return (err);
}

/*
 * This function updates the status byte for the device slot described.
 *
 * Since this is an optional SAF-TE command, there's no point in
 * returning an error.
 */
static void
wrslot_stat(ses_softc_t *ssc, int slp)
{
	int i;
	encobj *ep;
	Uscmd local, *lp = &local;
	char rqbuf[SENSE_LENGTH], cdb[CDB_GROUP1], *sdata;
	struct scfg *cc = ssc->ses_private;

	if (cc == NULL)
		return;

	SES_LOG(ssc, SES_CE_DEBUG2, "saf_wrslot");
	cdb[0] = SCMD_WRITE_BUFFER;
	cdb[1] = 1;
	cdb[2] = 0;
	cdb[3] = 0;
	cdb[4] = 0;
	cdb[5] = 0;
	cdb[6] = 0;
	cdb[7] = 0;
	cdb[8] = cc->Nslots * 3 + 1;
	cdb[9] = 0;

	sdata = kmem_zalloc(cc->Nslots * 3 + 1, slp);
	if (sdata == NULL)
		return;

	lp->uscsi_flags = USCSI_WRITE|USCSI_RQENABLE;
	lp->uscsi_timeout = ses_io_time;
	lp->uscsi_cdb = cdb;
	lp->uscsi_bufaddr = sdata;
	lp->uscsi_buflen = cc->Nslots * 3 + 1;
	lp->uscsi_cdblen = sizeof (cdb);
	lp->uscsi_rqbuf = rqbuf;
	lp->uscsi_rqlen = sizeof (rqbuf);

	sdata[0] = SAFTE_WT_DSTAT;
	for (i = 0; i < cc->Nslots; i++) {
		ep = &ssc->ses_objmap[cc->slotoff + i];
		SES_LOG(ssc, SES_CE_DEBUG2, "saf_wrslot %d <- %x", i,
		    ep->priv & 0xff);
		sdata[1 + (3 * i)] = ep->priv & 0xff;
	}
	(void) ses_runcmd(ssc, lp);
	kmem_free(sdata, cc->Nslots * 3 + 1);
}

/*
 * This function issues the "PERFORM SLOT OPERATION" command.
 */
static int
perf_slotop(ses_softc_t *ssc, uchar_t slot, uchar_t opflag, int slp)
{
	int err;
	Uscmd local, *lp = &local;
	char rqbuf[SENSE_LENGTH], *sdata;
	struct scfg *cc = ssc->ses_private;
	static char cdb[CDB_GROUP1] =
	    { SCMD_WRITE_BUFFER, 1, 0, 0, 0, 0, 0, 0, SCRATCH, 0 };

	if (cc == NULL)
		return (0);

	sdata = kmem_zalloc(SCRATCH, slp);
	if (sdata == NULL)
		return (ENOMEM);

	lp->uscsi_flags = USCSI_WRITE|USCSI_RQENABLE;
	lp->uscsi_timeout = ses_io_time;
	lp->uscsi_cdb = cdb;
	lp->uscsi_bufaddr = sdata;
	lp->uscsi_buflen = SCRATCH;
	lp->uscsi_cdblen = sizeof (cdb);
	lp->uscsi_rqbuf = rqbuf;
	lp->uscsi_rqlen = sizeof (rqbuf);

	sdata[0] = SAFTE_WT_SLTOP;
	sdata[1] = slot;
	sdata[2] = opflag;
	SES_LOG(ssc, SES_CE_DEBUG2, "saf_slotop slot %d op %x", slot, opflag);
	err = ses_runcmd(ssc, lp);
	kmem_free(sdata, SCRATCH);
	return (err);
}

/*
 * mode: c
 * Local variables:
 * c-indent-level: 8
 * c-brace-imaginary-offset: 0
 * c-brace-offset: -8
 * c-argdecl-indent: 8
 * c-label-offset: -8
 * c-continued-statement-offset: 8
 * c-continued-brace-offset: 0
 * End:
 */
