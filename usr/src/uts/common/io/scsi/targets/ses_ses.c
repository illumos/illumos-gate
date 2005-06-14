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
 * Enclosure Services Devices, SES Enclosure Routines
 */

#include <sys/modctl.h>
#include <sys/file.h>
#include <sys/scsi/scsi.h>
#include <sys/stat.h>
#include <sys/scsi/targets/ses.h>

/*
 * SES Diagnostic Page Codes
 */

typedef enum {
	SesConfigPage = 0x1,
	SesControlPage,
#define	SesStatusPage SesControlPage
	SesHelpTxt,
	SesStringOut,
#define	SesStringIn	SesStringOut
	SesThresholdOut,
#define	SesThresholdIn SesThresholdOut
	SesArrayControl,
#define	SesArrayStatus	SesArrayControl
	SesElementDescriptor,
	SesShortStatus
} SesDiagPageCodes;

/*
 * minimal amounts
 */

/*
 * Minimum amount of data, starting from byte 0, to have
 * the config header.
 */
#define	SES_CFGHDR_MINLEN	12

/*
 * Minimum amount of data, starting from byte 0, to have
 * the config header and one enclosure header.
 */
#define	SES_ENCHDR_MINLEN	48

/*
 * Take this value, subtract it from VEnclen and you know
 * the length of the vendor unique bytes.
 */
#define	SES_ENCHDR_VMIN		36

/*
 * SES Data Structures
 */

typedef struct {
	ulong_t	GenCode;	/* Generation Code */
	uchar_t	Nsubenc;	/* Number of Subenclosures */
} SesCfgHdr;

typedef struct {
	uchar_t	Subencid;	/* SubEnclosure Identifier */
	uchar_t	Ntypes;		/* # of supported types */
	uchar_t	VEnclen;	/* Enclosure Descriptor Length */
} SesEncHdr;

typedef struct {
	uchar_t	encWWN[8];	/* XXX- Not Right Yet */
	uchar_t	encVid[8];
	uchar_t	encPid[16];
	uchar_t	encRev[4];
	uchar_t	encVen[1];
} SesEncDesc;

typedef struct {
	uchar_t	enc_type;		/* type of element */
	uchar_t	enc_maxelt;		/* maximum supported */
	uchar_t	enc_subenc;		/* in SubEnc # N */
	uchar_t	enc_tlen;		/* Type Descriptor Text Length */
} SesThdr;

typedef struct {
	uchar_t	comstatus;
	uchar_t	comstat[3];
} SesComStat;
#if	!defined(lint)
_NOTE(SCHEME_PROTECTS_DATA("because I said so", SesComStat))
#endif

struct typidx {
	int ses_tidx;
	int ses_oidx;
};
#if	!defined(lint)
_NOTE(SCHEME_PROTECTS_DATA("because I said so", typidx))
#endif

struct sscfg {
	uchar_t ses_ntypes;	/* total number of types supported */

	/*
	 * We need to keep a type index as well as an object index
	 * for each object in an enclosure.
	 */
	struct typidx *ses_typidx;
	/*
	 * We also need to keep track of the number of elements
	 * per type of element. This is needed later so that we
	 * can find precisely in the returned status data the
	 * status for the Nth element of the Kth type.
	 */
	uchar_t *ses_eltmap;
};
#if	!defined(lint)
_NOTE(MUTEX_PROTECTS_DATA(scsi_device::sd_mutex, sscfg))
_NOTE(DATA_READABLE_WITHOUT_LOCK(sscfg))
#endif


/*
 * (de)canonicalization defines
 */
#define	sbyte(x, byte)	((((ulong_t)(x)) >> (byte * 8)) & 0xff)
#define	sbit(x, bit)	(((ulong_t)(x)) << bit)
#define	sset8(outp, idx, sval)	\
	(((uchar_t *)(outp))[idx++]) = sbyte(sval, 0)

#define	sset16(outp, idx, sval)	\
	(((uchar_t *)(outp))[idx++]) = sbyte(sval, 1), \
	(((uchar_t *)(outp))[idx++]) = sbyte(sval, 0)


#define	sset24(outp, idx, sval)	\
	(((uchar_t *)(outp))[idx++]) = sbyte(sval, 2), \
	(((uchar_t *)(outp))[idx++]) = sbyte(sval, 1), \
	(((uchar_t *)(outp))[idx++]) = sbyte(sval, 0)


#define	sset32(outp, idx, sval)	\
	(((uchar_t *)(outp))[idx++]) = sbyte(sval, 3), \
	(((uchar_t *)(outp))[idx++]) = sbyte(sval, 2), \
	(((uchar_t *)(outp))[idx++]) = sbyte(sval, 1), \
	(((uchar_t *)(outp))[idx++]) = sbyte(sval, 0)

#define	gbyte(x, byte)	((((ulong_t)(x)) & 0xff) << (byte * 8))
#define	gbit(lv, in, idx, shft, mask)	lv = ((in[idx] >> shft) & mask)
#define	sget8(inp, idx, lval)	lval = (((uchar_t *)(inp))[idx++])
#define	gget8(inp, idx, lval)	lval = (((uchar_t *)(inp))[idx])

#define	sget16(inp, idx, lval)	\
	lval = gbyte((((uchar_t *)(inp))[idx]), 1) | \
		(((uchar_t *)(inp))[idx+1]), idx += 2

#define	gget16(inp, idx, lval)	\
	lval = gbyte((((uchar_t *)(inp))[idx]), 1) | \
		(((uchar_t *)(inp))[idx+1])

#define	sget24(inp, idx, lval)	\
	lval = gbyte((((uchar_t *)(inp))[idx]), 2) | \
		gbyte((((uchar_t *)(inp))[idx+1]), 1) | \
			(((uchar_t *)(inp))[idx+2]), idx += 3

#define	gget24(inp, idx, lval)	\
	lval = gbyte((((uchar_t *)(inp))[idx]), 2) | \
		gbyte((((uchar_t *)(inp))[idx+1]), 1) | \
			(((uchar_t *)(inp))[idx+2])

#define	sget32(inp, idx, lval)	\
	lval = gbyte((((uchar_t *)(inp))[idx]), 3) | \
		gbyte((((uchar_t *)(inp))[idx+1]), 2) | \
		gbyte((((uchar_t *)(inp))[idx+2]), 1) | \
			(((uchar_t *)(inp))[idx+3]), idx += 4

#define	gget32(inp, idx, lval)	\
	lval = gbyte((((uchar_t *)(inp))[idx]), 3) | \
		gbyte((((uchar_t *)(inp))[idx+1]), 2) | \
		gbyte((((uchar_t *)(inp))[idx+2]), 1) | \
			(((uchar_t *)(inp))[idx+3])
#define	skip8(idx)	idx += 1
#define	skip16(idx)	idx += 2
#define	skip24(idx)	idx += 3
#define	skip32(idx)	idx += 4
static int ses_cfghdr(uchar_t *, int, SesCfgHdr *);
static int ses_enchdr(uchar_t *, int, uchar_t, SesEncHdr *);
static int ses_encdesc(uchar_t *, int, uchar_t, SesEncDesc *);
static int ses_getthdr(uchar_t *, int,  int, SesThdr *);
static int ses_decode(char *, int, uchar_t *, int, int, SesComStat *);
static int ses_encode(char *, int, uchar_t *, int, int, SesComStat *);

#define	SCSZ	0x4cc

static int
ses_getconfig(ses_softc_t *ssc)
{
	struct sscfg *cc;
	SesCfgHdr cf;
	SesEncHdr hd;
	SesEncDesc *cdp;
	SesThdr thdr;
	int err, amt, i, nobj, ntype, maxima;
	Uscmd local, *lp = &local;
	char storage[SCSZ], *sdata;
	static char cdb[CDB_GROUP0] =
	    { SCMD_GDIAG, 0x1, SesConfigPage, (char)(SCSZ >> 8),
	    (char)(SCSZ & 0xff), 0 };

	cc = ssc->ses_private;
	if (cc == NULL) {
		return (ENXIO);
	}

	sdata = kmem_alloc(SCSZ, KM_SLEEP);
	if (sdata == NULL)
		return (ENOMEM);

	lp->uscsi_flags = USCSI_READ|USCSI_RQENABLE;
	lp->uscsi_timeout = ses_io_time;
	lp->uscsi_cdb = cdb;
	lp->uscsi_bufaddr = sdata;
	lp->uscsi_buflen = SCSZ;
	lp->uscsi_cdblen = sizeof (cdb);
	lp->uscsi_rqbuf = storage;
	lp->uscsi_rqlen = SENSE_LENGTH;

	err = ses_runcmd(ssc, lp);
	if (err) {
		kmem_free(sdata, SCSZ);
		return (err);
	}
	amt = lp->uscsi_buflen - lp->uscsi_resid;

	if (ses_cfghdr((uchar_t *)sdata, amt, &cf)) {
		SES_LOG(ssc, CE_NOTE, "Unable to parse SES Config Header");
		kmem_free(sdata, SCSZ);
		return (EIO);
	}
	if (amt < SES_ENCHDR_MINLEN) {
		SES_LOG(ssc, CE_NOTE, "runt enclosure length (%d)", amt);
		kmem_free(sdata, SCSZ);
		return (EIO);
	}

	SES_LOG(ssc, SES_CE_DEBUG3, "GenCode %lx %d Subenclosures",
	    cf.GenCode, cf.Nsubenc);

	/*
	 * Now waltz through all the subenclosures toting up the
	 * number of types available in each. For this, we only
	 * really need the enclosure header. However, we get the
	 * enclosure descriptor for debug purposes, as well
	 * as self-consistency checking purposes.
	 */

	maxima = cf.Nsubenc + 1;
	cdp = (SesEncDesc *) storage;
	for (ntype = i = 0; i < maxima; i++) {
		bzero((caddr_t)cdp, sizeof (*cdp));
		if (ses_enchdr((uchar_t *)sdata, amt, i, &hd)) {
			SES_LOG(ssc, CE_NOTE,
			    "Cannot Extract Enclosure Header %d", i);
			kmem_free(sdata, SCSZ);
			return (EIO);
		}
		SES_LOG(ssc, SES_CE_DEBUG3,
		    "\tSubEnclosure ID %d, %d Types With this ID, Enclosure "
		    "Length %d\n", hd.Subencid, hd.Ntypes, hd.VEnclen);

		if (ses_encdesc((uchar_t *)sdata, amt, i, cdp)) {
			SES_LOG(ssc, CE_NOTE,
			    "Cannot Extract Enclosure Descriptor %d", i);
			kmem_free(sdata, SCSZ);
			return (EIO);
		}

		SES_LOG(ssc, SES_CE_DEBUG3,
		    "\tWWN: %02x%02x%02x%02x%02x%02x%02x%02x", cdp->encWWN[0],
		    cdp->encWWN[1], cdp->encWWN[2], cdp->encWWN[3],
		    cdp->encWWN[4], cdp->encWWN[5], cdp->encWWN[6],
		    cdp->encWWN[7]);
		ntype += hd.Ntypes;
	}

	/*
	 * Now waltz through all the types that are available, getting
	 * the type header so we can start adding up the number of
	 * objects available.
	 */
	for (nobj = i = 0; i < ntype; i++) {
		if (ses_getthdr((uchar_t *)sdata, amt, i, &thdr)) {
			SES_LOG(ssc, CE_NOTE,
			    "Cannot Extract Enclosure Type Header %d", i);
			kmem_free(sdata, SCSZ);
			return (EIO);
		}
		SES_LOG(ssc, SES_CE_DEBUG3,
		    "\tType Desc[%d]: Type 0x%x, MaxElt %d, In Subenc %d, "
		    "Text Length %d\n", i, thdr.enc_type, thdr.enc_maxelt,
		    thdr.enc_subenc, thdr.enc_tlen);
		nobj += thdr.enc_maxelt;
	}


	/*
	 * Now allocate the object array and type map.
	 */
	mutex_enter(&ssc->ses_devp->sd_mutex);


	ssc->ses_objmap = (encobj *)
	    kmem_zalloc(nobj * sizeof (encobj), KM_SLEEP);

	cc->ses_typidx = (struct typidx *)
	    kmem_zalloc(nobj * sizeof (struct typidx), KM_SLEEP);

	cc->ses_eltmap = kmem_zalloc(ntype, KM_SLEEP);

	if (ssc->ses_objmap == NULL || cc->ses_typidx == NULL ||
	    cc->ses_eltmap == NULL) {
		if (ssc->ses_objmap) {
			kmem_free(ssc->ses_objmap, (nobj * sizeof (encobj)));
			ssc->ses_objmap = NULL;
		}
		if (cc->ses_typidx) {
			kmem_free(cc->ses_typidx,
			    (nobj * sizeof (struct typidx)));
			cc->ses_typidx = NULL;
		}
		if (cc->ses_eltmap) {
			kmem_free(cc->ses_eltmap, ntype);
			cc->ses_eltmap = NULL;
		}
		mutex_exit(&ssc->ses_devp->sd_mutex);
		kmem_free(sdata, SCSZ);
		return (ENOMEM);
	}
	cc->ses_ntypes = (uchar_t)ntype;
	ssc->ses_nobjects = nobj;

	/*
	 * Now waltz through the # of types again to fill in the types
	 * (and subenclosure ids) of the allocated objects.
	 */
	nobj = 0;
	for (i = 0; i < ntype; i++) {
		int j;
		if (ses_getthdr((uchar_t *)sdata, amt, i, &thdr)) {
			continue;
		}
		cc->ses_eltmap[i] = thdr.enc_maxelt;
		for (j = 0; j < thdr.enc_maxelt; j++) {
			cc->ses_typidx[nobj].ses_tidx = i;
			cc->ses_typidx[nobj].ses_oidx = j;
			ssc->ses_objmap[nobj].subenclosure = thdr.enc_subenc;
			ssc->ses_objmap[nobj++].enctype = thdr.enc_type;
		}
	}
	mutex_exit(&ssc->ses_devp->sd_mutex);
	kmem_free(sdata, SCSZ);
	return (0);
}

/*
 */
int
ses_softc_init(ses_softc_t *ssc, int doinit)
{
	if (doinit == 0) {
		struct sscfg *cc;
		mutex_enter(&ssc->ses_devp->sd_mutex);
		if (ssc->ses_nobjects) {
			kmem_free(ssc->ses_objmap,
			    ssc->ses_nobjects * sizeof (encobj));
			ssc->ses_objmap = NULL;
		}
		if ((cc = ssc->ses_private) != NULL) {
			if (cc->ses_eltmap && cc->ses_ntypes) {
				kmem_free(cc->ses_eltmap, cc->ses_ntypes);
				cc->ses_eltmap = NULL;
				cc->ses_ntypes = 0;
			}
			if (cc->ses_typidx && ssc->ses_nobjects) {
				kmem_free(cc->ses_typidx, ssc->ses_nobjects *
				    sizeof (struct typidx));
				cc->ses_typidx = NULL;
			}
			kmem_free(cc, sizeof (struct sscfg));
			ssc->ses_private = NULL;
		}
		ssc->ses_nobjects = 0;
		mutex_exit(&ssc->ses_devp->sd_mutex);
		return (0);
	}
	mutex_enter(&ssc->ses_devp->sd_mutex);
	if (ssc->ses_private == NULL) {
		ssc->ses_private = kmem_zalloc(sizeof (struct sscfg), KM_SLEEP);
	}
	if (ssc->ses_private == NULL) {
		mutex_exit(&ssc->ses_devp->sd_mutex);
		return (ENOMEM);
	}
	ssc->ses_nobjects = 0;
	ssc->ses_encstat = 0;
	mutex_exit(&ssc->ses_devp->sd_mutex);
	return (ses_getconfig(ssc));
}

int
ses_init_enc(ses_softc_t *ssc)
{
	UNUSED_PARAMETER(ssc);
	return (0);
}

static int
ses_getputstat(ses_softc_t *ssc, int objid, SesComStat *sp, int slp, int in)
{
	struct sscfg *cc;
	int err, amt, bufsiz, tidx, oidx;
	Uscmd local, *lp = &local;
	char rqbuf[SENSE_LENGTH], *sdata;
	char cdb[CDB_GROUP0];

	cc = ssc->ses_private;
	if (cc == NULL) {
		return (ENXIO);
	}

	/*
	 * If we're just getting overall enclosure status,
	 * we only need 2 bytes of data storage.
	 *
	 * If we're getting anything else, we know how much
	 * storage we need by noting that starting at offset
	 * 8 in returned data, all object status bytes are 4
	 * bytes long, and are stored in chunks of types(M)
	 * and nth+1 instances of type M.
	 */
	if (objid == -1) {
		bufsiz = 2;
	} else {
		bufsiz = (ssc->ses_nobjects * 4) + (cc->ses_ntypes * 4) + 8;
	}
	cdb[0] = SCMD_GDIAG;
	cdb[1] = 1;
	cdb[2] = SesStatusPage;
	cdb[3] = bufsiz >> 8;
	cdb[4] = bufsiz & 0xff;
	cdb[5] = 0;
	sdata = kmem_alloc(bufsiz, slp);
	if (sdata == NULL)
		return (ENOMEM);

	lp->uscsi_flags = USCSI_READ|USCSI_RQENABLE;
	lp->uscsi_timeout = ses_io_time;
	lp->uscsi_cdb = cdb;
	lp->uscsi_bufaddr = sdata;
	lp->uscsi_buflen = bufsiz;
	lp->uscsi_cdblen = sizeof (cdb);
	lp->uscsi_rqbuf = rqbuf;
	lp->uscsi_rqlen = sizeof (rqbuf);

	err = ses_runcmd(ssc, lp);
	if (err) {
		kmem_free(sdata, bufsiz);
		return (err);
	}
	amt = lp->uscsi_buflen - lp->uscsi_resid;

	if (objid == -1) {
		tidx = -1;
		oidx = -1;
	} else {
		tidx = cc->ses_typidx[objid].ses_tidx;
		oidx = cc->ses_typidx[objid].ses_oidx;
	}
	if (in) {
		if (ses_decode(sdata, amt, cc->ses_eltmap, tidx, oidx, sp)) {
			err = ENODEV;
		}
	} else {
		if (ses_encode(sdata, amt, cc->ses_eltmap, tidx, oidx, sp)) {
			err = ENODEV;
		} else {
			cdb[0] = SCMD_SDIAG;
			cdb[1] = 0x10;
			cdb[2] = 0;
			cdb[3] = bufsiz >> 8;
			cdb[4] = bufsiz & 0xff;
			cdb[5] = 0;
			lp->uscsi_flags = USCSI_WRITE|USCSI_RQENABLE;
			lp->uscsi_timeout = ses_io_time;
			lp->uscsi_cdb = cdb;
			lp->uscsi_bufaddr = sdata;
			lp->uscsi_buflen = bufsiz;
			lp->uscsi_cdblen = sizeof (cdb);
			lp->uscsi_rqbuf = rqbuf;
			lp->uscsi_rqlen = sizeof (rqbuf);
			err = ses_runcmd(ssc, lp);
		}
	}
	kmem_free(sdata, bufsiz);
	return (0);
}

int
ses_get_encstat(ses_softc_t *ssc, int slpflag)
{
	SesComStat s;
	int r;

	if ((r = ses_getputstat(ssc, -1, &s, slpflag, 1)) != 0) {
		return (r);
	}
	mutex_enter(&ssc->ses_devp->sd_mutex);
	ssc->ses_encstat = s.comstatus | ENCI_SVALID;
	mutex_exit(&ssc->ses_devp->sd_mutex);
	return (0);
}

int
ses_set_encstat(ses_softc_t *ssc, uchar_t encstat, int slpflag)
{
	SesComStat s;
	int r;

	s.comstatus = encstat & 0xf;
	if ((r = ses_getputstat(ssc, -1, &s, slpflag, 0)) != 0) {
		return (r);
	}
	mutex_enter(&ssc->ses_devp->sd_mutex);
	ssc->ses_encstat = encstat & 0xf;	/* note no SVALID set */
	mutex_exit(&ssc->ses_devp->sd_mutex);
	return (0);
}

int
ses_get_objstat(ses_softc_t *ssc, ses_objarg *obp, int slpflag)
{
	int i = (int)obp->obj_id;

	if (ssc->ses_objmap[i].svalid == 0) {
		SesComStat s;
		int r = ses_getputstat(ssc, i, &s, slpflag, 1);
		if (r)
			return (r);
		mutex_enter(&ssc->ses_devp->sd_mutex);
		ssc->ses_objmap[i].encstat[0] = s.comstatus;
		ssc->ses_objmap[i].encstat[1] = s.comstat[0];
		ssc->ses_objmap[i].encstat[2] = s.comstat[1];
		ssc->ses_objmap[i].encstat[3] = s.comstat[2];
		ssc->ses_objmap[i].svalid = 1;
		mutex_exit(&ssc->ses_devp->sd_mutex);
	}
	obp->cstat[0] = ssc->ses_objmap[i].encstat[0];
	obp->cstat[1] = ssc->ses_objmap[i].encstat[1];
	obp->cstat[2] = ssc->ses_objmap[i].encstat[2];
	obp->cstat[3] = ssc->ses_objmap[i].encstat[3];
	return (0);
}

int
ses_set_objstat(ses_softc_t *ssc, ses_objarg *obp, int slpflag)
{
	SesComStat s;
	int r, i;
	/*
	 * If this is clear, we don't do diddly.
	 */
	if ((obp->cstat[0] & SESCTL_CSEL) == 0) {
		return (0);
	}
	s.comstatus = obp->cstat[0];
	s.comstat[0] = obp->cstat[1];
	s.comstat[1] = obp->cstat[2];
	s.comstat[2] = obp->cstat[3];
	i = (int)obp->obj_id;
	r = ses_getputstat(ssc, i, &s, slpflag, 0);
	mutex_enter(&ssc->ses_devp->sd_mutex);
	ssc->ses_objmap[i].svalid = 0;
	mutex_exit(&ssc->ses_devp->sd_mutex);
	return (r);
}

/*
 * Routines to parse returned SES data structures.
 * Architecture and compiler independent.
 */

static int
ses_cfghdr(uchar_t *buffer, int buflen, SesCfgHdr *cfp)
{
	if (buflen < SES_CFGHDR_MINLEN)
		return (-1);
	gget8(buffer, 1, cfp->Nsubenc);
	gget32(buffer, 4, cfp->GenCode);
	return (0);
}

static int
ses_enchdr(uchar_t *buffer, int amt, uchar_t SubEncId, SesEncHdr *chp)
{
	int s, off = 8;
	for (s = 0; s < SubEncId; s++) {
		if (off + 3 > amt)
			return (-1);
		off += buffer[off+3] + 4;
	}
	if (off + 3 > amt) {
		return (-1);
	}
	gget8(buffer, off+1, chp->Subencid);
	gget8(buffer, off+2, chp->Ntypes);
	gget8(buffer, off+3, chp->VEnclen);
	return (0);
}

static int
ses_encdesc(uchar_t *buffer, int amt, uchar_t SubEncId, SesEncDesc *cdp)
{
	int s, e, enclen, off = 8;
	for (s = 0; s < SubEncId; s++) {
		if (off + 3 > amt)
			return (-1);
		off += buffer[off+3] + 4;
	}
	if (off + 3 > amt) {
		return (-1);
	}
	gget8(buffer, off+3, enclen);
	off += 4;
	if (off  >= amt)
		return (-1);

	e = off + enclen;
	if (e > amt) {
		e = amt;
	}
	bcopy((caddr_t)&buffer[off], (caddr_t)cdp, e - off);
	return (0);
}

static int
ses_getthdr(uchar_t *buffer, int amt, int nth, SesThdr *thp)
{
	int s, off = 8;

	if (amt < SES_CFGHDR_MINLEN) {
		return (-1);
	}
	for (s = 0; s < buffer[1]; s++) {
		if (off + 3 > amt)
			return (-1);
		off += buffer[off+3] + 4;
	}
	if (off + 3 > amt) {
		return (-1);
	}
	off += buffer[off+3] + 4 + (nth * 4);
	if (amt < (off + 4))
		return (-1);

	gget8(buffer, off++, thp->enc_type);
	gget8(buffer, off++, thp->enc_maxelt);
	gget8(buffer, off++, thp->enc_subenc);
	gget8(buffer, off, thp->enc_tlen);
	return (0);
}

/*
 * This function needs a little explanation.
 *
 * The arguments are:
 *
 *
 *	char *b, int amt
 *
 *		These describes the raw input SES status data and length.
 *
 *	uchar_t *ep
 *
 *		This is a map of the number of types for each element type
 *		in the enclosure.
 *
 *	int elt
 *
 *		This is the element type being sought. If elt is -1,
 *		then overal enclosure status is being sought.
 *
 *	int elm
 *
 *		This is the ordinal Mth element of type elt being sought.
 *
 *	SesComStat *sp
 *
 *		This is the output area to store the status for
 *		the Mth element of type Elt.
 */

static int
ses_decode(char *b, int amt, uchar_t *ep, int elt, int elm, SesComStat *sp)
{
	int idx, i;

	/*
	 * If it's overall enclosure status being sought, get that.
	 * We need at least 2 bytes of status data to get that.
	 */
	if (elt == -1) {
		if (amt < 2)
			return (-1);
		gget8(b, 1, sp->comstatus);
		sp->comstat[0] = 0;
		sp->comstat[1] = 0;
		sp->comstat[2] = 0;
		return (0);
	}

	/*
	 * Check to make sure that the Mth element is legal for type Elt.
	 */

	if (elm >= ep[elt])
		return (-1);

	/*
	 * Starting at offset 8, start skipping over the storage
	 * for the element types we're not interested in.
	 */
	for (idx = 8, i = 0; i < elt; i++) {
		idx += ((ep[i] + 1) * 4);
	}

	/*
	 * Skip over Overall status for this element type.
	 */
	idx += 4;

	/*
	 * And skip to the index for the Mth element that we're going for.
	 */
	idx += (4 * elm);

	/*
	 * Make sure we haven't overflowed the buffer.
	 */
	if (idx+4 > amt)
		return (-1);
	/*
	 * Retrieve the status.
	 */
	gget8(b, idx++, sp->comstatus);
	gget8(b, idx++, sp->comstat[0]);
	gget8(b, idx++, sp->comstat[1]);
	gget8(b, idx++, sp->comstat[2]);
	SES_LOG(NULL, SES_CE_DEBUG5, "Get Elt 0x%x Elm 0x%x (idx %d)",
	    elt, elm, idx-4);
	return (0);
}

/*
 * This is the mirror function to ses_decode, but we set the 'select'
 * bit for the object which we're interested in. All other objects,
 * after a status fetch, should have that bit off. Hmm. It'd be easy
 * enough to ensure this, so we will.
 */

static int
ses_encode(char *b, int amt, uchar_t *ep, int elt, int elm, SesComStat *sp)
{
	int idx, i;

	/*
	 * If it's overall enclosure status being sought, get that.
	 * We need at least 2 bytes of status data to get that.
	 */
	if (elt == -1) {
		if (amt < 2)
			return (-1);
		i = 0;
		sset8(b, i, 0);
		sset8(b, i, sp->comstatus & 0xf);
		SES_LOG(NULL, SES_CE_DEBUG5, "set EncStat %x", sp->comstatus);
		return (0);
	}

	/*
	 * Check to make sure that the Mth element is legal for type Elt.
	 */

	if (elm >= ep[elt])
		return (-1);

	/*
	 * Starting at offset 8, start skipping over the storage
	 * for the element types we're not interested in.
	 */
	for (idx = 8, i = 0; i < elt; i++) {
		idx += ((ep[i] + 1) * 4);
	}

	/*
	 * Skip over Overall status for this element type.
	 */
	idx += 4;

	/*
	 * And skip to the index for the Mth element that we're going for.
	 */
	idx += (4 * elm);

	/*
	 * Make sure we haven't overflowed the buffer.
	 */
	if (idx+4 > amt)
		return (-1);

	/*
	 * Set the status.
	 */
	sset8(b, idx, sp->comstatus);
	sset8(b, idx, sp->comstat[0]);
	sset8(b, idx, sp->comstat[1]);
	sset8(b, idx, sp->comstat[2]);
	idx -= 4;

	SES_LOG(NULL, SES_CE_DEBUG2, "Set Elt 0x%x Elm 0x%x (idx %d) with "
	    "%x %x %x %x", elt, elm, idx, sp->comstatus, sp->comstat[0],
	    sp->comstat[1], sp->comstat[2]);

	/*
	 * Now make sure all other 'Select' bits are off.
	 */
	for (i = 8; i < amt; i += 4) {
		if (i != idx)
			b[i] &= ~0x80;
	}
	/*
	 * And make sure the INVOP bit is clear.
	 */
	b[1] &= ~INVOP;

	return (0);
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
