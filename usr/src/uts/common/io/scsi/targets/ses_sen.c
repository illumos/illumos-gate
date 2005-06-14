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
 * Enclosure Services Devices, SEN Enclosure Routines
 *
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/modctl.h>
#include <sys/file.h>
#include <sys/scsi/scsi.h>
#include <sys/stat.h>
#include <sys/scsi/targets/sesio.h>
#include <sys/scsi/targets/ses.h>


/*
 * The SEN unit is wired to support 7 disk units,
 * two power supplies, one fan module, one overtemp sensor,
 * and one alarm.
 */
#define	NOBJECTS	(7+2+1+1+1)
#define	DRVOFF	0
#define	SDRVOFF	20
#define	NDRV	7

#define	PWROFF	NDRV
#define	SPWROFF	28
#define	NPWR	2

#define	FANOFF	(PWROFF + NPWR)
#define	SFANOFF	30
#define	NFAN	1

#define	THMOFF	(FANOFF + NFAN)
#define	STHMOFF	31
#define	NTHM	1

#define	ALRMOFF	(THMOFF + NTHM)
#define	NALRM	1
#define	SALRMOFF	8

#define	SENPGINSIZE	32
#define	SENPGOUTSIZE	22

int
sen_softc_init(ses_softc_t *ssc, int doinit)
{
	int i;
	if (doinit == 0) {
		mutex_enter(&ssc->ses_devp->sd_mutex);
		if (ssc->ses_nobjects) {
			kmem_free(ssc->ses_objmap,
			    ssc->ses_nobjects * sizeof (encobj));
			ssc->ses_objmap = NULL;
			ssc->ses_nobjects = 0;
		}
		mutex_exit(&ssc->ses_devp->sd_mutex);
		return (0);
	}
	mutex_enter(&ssc->ses_devp->sd_mutex);
	ssc->ses_nobjects = 0;
	ssc->ses_encstat = 0;
	ssc->ses_objmap = (encobj *)
	    kmem_zalloc(NOBJECTS * sizeof (encobj), KM_SLEEP);
	if (ssc->ses_objmap == NULL) {
		mutex_exit(&ssc->ses_devp->sd_mutex);
		return (ENOMEM);
	}
	for (i = DRVOFF; i < DRVOFF + NDRV; i++) {
		ssc->ses_objmap[i].enctype = SESTYP_DEVICE;
	}
	for (i = PWROFF; i < PWROFF + NPWR; i++) {
		ssc->ses_objmap[i].enctype = SESTYP_POWER;
	}
	for (i = FANOFF; i < FANOFF + NFAN; i++) {
		ssc->ses_objmap[i].enctype = SESTYP_FAN;
	}
	for (i = THMOFF; i < THMOFF + NTHM; i++) {
		ssc->ses_objmap[i].enctype = SESTYP_THERM;
	}
	for (i = ALRMOFF; i < ALRMOFF + NALRM; i++) {
		ssc->ses_objmap[i].enctype = SESTYP_ALARM;
	}
	ssc->ses_nobjects = NOBJECTS;
	mutex_exit(&ssc->ses_devp->sd_mutex);
	return (0);
}

int
sen_init_enc(ses_softc_t *ssc)
{
	UNUSED_PARAMETER(ssc);
	return (0);
}

static int
sen_rdstat(ses_softc_t *ssc, int slpflag)
{
	int err, i, oid, baseid, tmp;
	Uscmd local, *lp = &local;
	char rqbuf[SENSE_LENGTH], *sdata;
	static char cdb[CDB_GROUP0] =
	    { SCMD_GDIAG, 0x10, 0x4, 0, SENPGINSIZE, 0 };

	/*
	 * Fetch current data
	 */
	sdata = kmem_alloc(SENPGINSIZE, slpflag);
	if (sdata == NULL)
		return (ENOMEM);

	lp->uscsi_flags = USCSI_READ|USCSI_RQENABLE;
	lp->uscsi_timeout = ses_io_time;
	lp->uscsi_cdb = cdb;
	lp->uscsi_bufaddr = sdata;
	lp->uscsi_buflen = SENPGINSIZE;
	lp->uscsi_cdblen = sizeof (cdb);
	lp->uscsi_rqbuf = rqbuf;
	lp->uscsi_rqlen = sizeof (rqbuf);
	err = ses_runcmd(ssc, lp);
	if (err) {
		kmem_free(sdata, SENPGINSIZE);
		return (err);
	}

	if ((lp->uscsi_buflen - lp->uscsi_resid)  < SENPGINSIZE) {
		SES_LOG(ssc, CE_NOTE, "sen_rdstat: too little data (%ld)",
		    lp->uscsi_buflen - lp->uscsi_resid);
		kmem_free(sdata, SENPGINSIZE);
		return (EIO);
	}

	/*
	 * Set base SCSI id for drives...
	 */
	if (sdata[10] & 0x80)
		baseid = 8;
	else
		baseid = 0;

	oid = 0;

	mutex_enter(&ssc->ses_devp->sd_mutex);
	/*
	 * Invalidate all status bits.
	 */
	for (i = 0; i < ssc->ses_nobjects; i++)
		ssc->ses_objmap[i].svalid = 0;
	ssc->ses_encstat = 0;

	/*
	 * Do Drives...
	 */
	for (i = SDRVOFF; i < SDRVOFF + NDRV; i++) {
		ssc->ses_objmap[oid].encstat[1] = baseid + i - SDRVOFF;
		ssc->ses_objmap[oid].encstat[2] = 0;
		if (sdata[i] & 0x80) {
			/*
			 * Drive is present
			 */
			ssc->ses_objmap[oid].encstat[0] = SESSTAT_OK;
		} else {
			ssc->ses_objmap[oid].encstat[0] = SESSTAT_NOTINSTALLED;
			ssc->ses_encstat |= ENCSTAT_INFO;
		}
		/*
		 * Is the fault LED lit?
		 */
		if (sdata[i] & 0x40) {
			ssc->ses_objmap[oid].encstat[0] = SESSTAT_CRIT;
			ssc->ses_objmap[oid].encstat[3] = 0x40;
			ssc->ses_encstat |= ENCSTAT_CRITICAL;
		} else {
			ssc->ses_objmap[oid].encstat[3] = 0x0;
		}
		ssc->ses_objmap[oid++].svalid = 1;
	}

	/*
	 * Do Power Supplies...
	 *
	 * Power supply bad, or not installed cannot be distinguished.
	 * Which one to pick? Let's say 'bad' and make it NONCRITICAL
	 * if only one is bad but CRITICAL if both are bad.
	 */
	for (tmp = 0, i = SPWROFF; i < SPWROFF + NPWR; i++) {
		ssc->ses_objmap[oid].encstat[1] = 0;
		ssc->ses_objmap[oid].encstat[2] = 0;
		if ((sdata[i] & 0x80) == 0) {
			/*
			 * Power supply 'ok'...
			 */
			ssc->ses_objmap[oid].encstat[0] = SESSTAT_OK;
			tmp++;
		} else {
			ssc->ses_objmap[oid].encstat[0] = SESSTAT_CRIT;
			ssc->ses_encstat |= ENCSTAT_NONCRITICAL;
		}
		ssc->ses_objmap[oid++].svalid = 1;
	}
	if (tmp == 0) {
		ssc->ses_encstat |= ENCSTAT_CRITICAL;
	}

	/*
	 *  Do the Fan(s)
	 */
	for (i = SFANOFF; i < SFANOFF + NFAN; i++) {
		ssc->ses_objmap[oid].encstat[1] = 0;
		ssc->ses_objmap[oid].encstat[2] = 0;
		if (sdata[i] & 0x20) {	/* both fans have failed */
			ssc->ses_objmap[oid].encstat[0] = SESSTAT_CRIT;
			ssc->ses_objmap[oid].encstat[3] = 0x40;
			ssc->ses_encstat |= ENCSTAT_CRITICAL;
		} else if (sdata[i] & 0x80) {	/* one fan has failed */
			ssc->ses_objmap[oid].encstat[0] = SESSTAT_NONCRIT;
			ssc->ses_objmap[oid].encstat[3] = 0x41;
			ssc->ses_encstat |= ENCSTAT_NONCRITICAL;
		} else {
			ssc->ses_objmap[oid].encstat[0] = SESSTAT_OK;
			ssc->ses_objmap[oid].encstat[3] = 0x6;
		}
		ssc->ses_objmap[oid++].svalid = 1;
	}

	/*
	 * Do the temperature sensor...
	 */
	for (i = STHMOFF; i < STHMOFF + NTHM; i++) {
		ssc->ses_objmap[oid].encstat[1] = 0;
		if (sdata[i] & 0x80) {
			ssc->ses_objmap[oid].encstat[0] = SESSTAT_CRIT;
			/* ssc->ses_objmap[oid].encstat[2] = 0; */
			ssc->ses_objmap[oid].encstat[3] = 0x8;
			ssc->ses_encstat |= ENCSTAT_CRITICAL;
		} else {
			ssc->ses_objmap[oid].encstat[0] = SESSTAT_OK;
			/* ssc->ses_objmap[oid].encstat[2] = 0; */
			ssc->ses_objmap[oid].encstat[3] = 0;
		}
		ssc->ses_objmap[oid++].svalid = 1;
	}

	/*
	 * and last, but not least, check the state of the alarm.
	 */
	for (i = SALRMOFF; i < SALRMOFF + NALRM; i++) {
		ssc->ses_objmap[oid].encstat[1] = 0;
		ssc->ses_objmap[oid].encstat[2] = 0;
		if (sdata[i]  & 0x80) {	/* Alarm is or was sounding */
			ssc->ses_objmap[oid].encstat[0] = SESSTAT_CRIT;
			ssc->ses_objmap[oid].encstat[3] = 0x2;
			if ((sdata[i] & 0xf))
				ssc->ses_objmap[oid].encstat[3] |= 0x40;
			ssc->ses_encstat |= ENCSTAT_CRITICAL;
		} else {
			ssc->ses_objmap[oid].encstat[0] = SESSTAT_OK;
			ssc->ses_objmap[oid].encstat[3] = 0;
		}
		ssc->ses_objmap[oid++].svalid = 1;
	}
	ssc->ses_encstat |= ENCI_SVALID;
	mutex_exit(&ssc->ses_devp->sd_mutex);
	kmem_free(sdata, SENPGINSIZE);
	return (0);
}

int
sen_get_encstat(ses_softc_t *ssc, int slpflag)
{
	return (sen_rdstat(ssc, slpflag));
}

int
sen_set_encstat(ses_softc_t *ssc, uchar_t encstat, int slpflag)
{
	UNUSED_PARAMETER(ssc);
	UNUSED_PARAMETER(encstat);
	UNUSED_PARAMETER(slpflag);
	return (0);
}

int
sen_get_objstat(ses_softc_t *ssc, ses_objarg *obp, int slpflag)
{
	int i = (int)obp->obj_id;

	if ((ssc->ses_encstat & ENCI_SVALID) == 0 ||
	    (ssc->ses_objmap[i].svalid) == 0) {
		int r = sen_rdstat(ssc, slpflag);
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
sen_set_objstat(ses_softc_t *ssc, ses_objarg *obp, int slpflag)
{
	encobj *ep;
	int err, runcmd, idx;
	Uscmd local, *lp = &local;
	char rqbuf[SENSE_LENGTH], *sdata;
	static char cdb[CDB_GROUP0] =
	    { SCMD_GDIAG, 0x10, 0x4, 0, SENPGINSIZE, 0 };
	static char cdb1[CDB_GROUP0] =
	    { SCMD_SDIAG, 0x10, 0, 0, SENPGOUTSIZE, 0 };

	/*
	 * If this is clear, we don't do diddly.
	 */
	if ((obp->cstat[0] & SESCTL_CSEL) == 0) {
		return (0);
	}
	/*
	 * Fetch current data
	 */
	sdata = kmem_alloc(SENPGINSIZE, slpflag);
	if (sdata == NULL)
		return (ENOMEM);
	lp->uscsi_flags = USCSI_READ|USCSI_RQENABLE;
	lp->uscsi_timeout = ses_io_time;
	lp->uscsi_cdb = cdb;
	lp->uscsi_bufaddr = sdata;
	lp->uscsi_buflen = SENPGINSIZE;
	lp->uscsi_cdblen = sizeof (cdb);
	lp->uscsi_rqbuf = rqbuf;
	lp->uscsi_rqlen = sizeof (rqbuf);
	err = ses_runcmd(ssc, lp);
	if (err) {
		kmem_free(sdata, SENPGINSIZE);
		return (err);
	}
	if ((lp->uscsi_buflen - lp->uscsi_resid)  < SENPGINSIZE) {
		SES_LOG(ssc, CE_NOTE, "Too Little Data Returned (%ld)",
		    lp->uscsi_buflen - lp->uscsi_resid);
		kmem_free(sdata, SENPGINSIZE);
		return (EIO);
	}
	/*
	 * Okay, now convert the input page to the output page.
	 */
	sdata[1] = 0;
	sdata[3] = 0x12;
	sdata[6] = 1;
	sdata[8] &= ~0x80;
	sdata[10] = 0;
	sdata[14] = sdata[20] & ~0x80;
	sdata[15] = sdata[21] & ~0x80;
	sdata[16] = sdata[22] & ~0x80;
	sdata[17] = sdata[23] & ~0x80;
	sdata[18] = sdata[24] & ~0x80;
	sdata[19] = sdata[25] & ~0x80;
	sdata[20] = sdata[26] & ~0x80;
	sdata[21] = 0;

	runcmd = 0;

	idx = (int)obp->obj_id;
	ep = &ssc->ses_objmap[idx];
	switch (ep->enctype) {
	case SESTYP_DEVICE:
		if (idx < 0 || idx >= NDRV) {
			err = EINVAL;
		} else if ((obp->cstat[3] & SESCTL_RQSFLT) != 0) {
			SES_LOG(ssc, SES_CE_DEBUG1, "faulted %d", idx);
			sdata[14 + idx] |= 0x40;
			runcmd++;
		} else {
			SES_LOG(ssc, SES_CE_DEBUG1, "clrd fault on %d", idx);
			sdata[14 + idx] &= ~0x40;
			runcmd++;
		}
		break;
	case SESTYP_POWER:
		if ((obp->cstat[3] & SESCTL_RQSTFAIL) ||
		    (obp->cstat[0] & SESCTL_DISABLE)) {
			SES_LOG(ssc, CE_WARN, "Commanding Off Power Supply!");
			sdata[10] |= 0x40;	/* Seppuku!!!! */
			runcmd++;
		}
		break;
	case SESTYP_ALARM:
		/*
		 * On all nonzero but the 'muted' bit,
		 * we turn on the alarm,
		 */
		obp->cstat[3] &= ~0xa;
		if ((obp->cstat[3] & 0x40) ||
		    (obp->cstat[0] & SESCTL_DISABLE)) {
			sdata[8] = 0;
		} else if (obp->cstat[3] != 0) {
			sdata[8] = 0x40;
		} else {
			sdata[8] = 0;
		}
		runcmd++;
		SES_LOG(ssc, SES_CE_DEBUG1, "%sabling alarm",
		    (sdata[8] & 0x40)? "en" : "dis");
		break;
	default:
		break;
	}

	if (runcmd) {
		lp->uscsi_flags = USCSI_WRITE|USCSI_RQENABLE;
		lp->uscsi_timeout = ses_io_time;
		lp->uscsi_cdb = cdb1;
		lp->uscsi_bufaddr = sdata;
		lp->uscsi_buflen = SENPGOUTSIZE;
		lp->uscsi_cdblen = sizeof (cdb);
		lp->uscsi_rqbuf = rqbuf;
		lp->uscsi_rqlen = sizeof (rqbuf);
		err = ses_runcmd(ssc, lp);
		/* preserve error across the rest of the action */
	} else {
		err = 0;
	}

	mutex_enter(&ssc->ses_devp->sd_mutex);
	ep->svalid = 0;
	mutex_exit(&ssc->ses_devp->sd_mutex);
	kmem_free(sdata, SENPGINSIZE);
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
