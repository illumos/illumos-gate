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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/types.h>
#include <sys/time.h>
#include <sys/nvpair.h>
#include <sys/cmn_err.h>
#include <sys/fm/util.h>
#include <sys/fm/protocol.h>
#include <sys/smbios.h>
#include <sys/smbios_impl.h>

/*
 * Variable used to determine if the x86 generic topology enumerator will
 * revert to legacy enumeration. I.E. Big Kill Switch... tunable via
 * /etc/system
 */
int x86gentopo_legacy = 0;

#define	MC		0
#define	PROC		1
#define	MAX_PAIRS	20
#define	MAX_CONT	40

typedef struct bbindex  {
	int count;
	uint16_t index[MAX_PAIRS];
} bbindex_t;

/*
 * the enum values come from DMTF
 */
typedef enum baseb {
	BB_BAD = 0,		/* There is no bb value 0 */
	BB_UNKNOWN,		/* Unknown */
	BB_OTHER,		/* Other */
	BB_BLADE,		/* Server Blade */
	BB_CONNSW,		/* Connectivity Switch */
	BB_SMM,			/* System Management Module */
	BB_PROCMOD,		/* Processor Module */
	BB_IOMOD,		/* I/O Module */
	BB_MEMMOD,		/* Memory Module */
	BB_DBOARD,		/* Daughter Board */
	BB_MBOARD,		/* Motherboard */
	BB_PROCMMOD,		/* Processor/Memory Module */
	BB_PROCIOMOD,		/* Processor/IO Module */
	BB_ICONNBD		/* Interconnect Board */
} bbd_t;

static struct bboard_type {
	bbd_t		baseb;
	const char	*name;
} bbd_type[] = {
	{BB_BAD,		NULL},
	{BB_UNKNOWN,		"unknown"},
	{BB_OTHER,		"other"},
	{BB_BLADE,		"systemboard"},
	{BB_CONNSW,		"connswitch"},
	{BB_SMM,		"smmodule"},
	{BB_PROCMOD,		"cpuboard"},
	{BB_IOMOD,		"ioboard"},
	{BB_MEMMOD,		"memboard"},
	{BB_DBOARD,		"systemboard"},
	{BB_MBOARD,		"motherboard"},
	{BB_PROCMMOD,		"systemboard"},
	{BB_PROCIOMOD,		"systemboard"},
	{BB_ICONNBD,		"systemboard"}
};

typedef struct smbs_con_ids {
	int id;
	int inst;
	int cont_count;
	uint16_t **cont_ids;
	int cont_by_id;
	int visited;
} smbs_con_ids_t;

typedef struct smbs_cnt {
	int type;			/* SMBIOS stucture type */
	int count;			/* number of table entries */
	smbs_con_ids_t **ids;		/* SMBIOS table entry id(s) */
} smbs_cnt_t;

/*
 * dynamically allocate the storage for the smbs_cnt_t
 */
static smbs_cnt_t *
smb_create_strcnt(int count)
{
	smbs_cnt_t *types = NULL;
	int i, j;

	types = kmem_zalloc(sizeof (smbs_cnt_t), KM_SLEEP);

	types->ids = (smbs_con_ids_t **)kmem_zalloc(
	    count * sizeof (smbs_con_ids_t *), KM_SLEEP);

	for (i = 0; i < count; i++) {
		types->ids[i] = (smbs_con_ids_t *)kmem_zalloc(
		    sizeof (smbs_con_ids_t), KM_SLEEP);
	}

	for (i = 0; i < count; i++) {
		types->ids[i]->cont_ids = (uint16_t **)kmem_zalloc(
		    MAX_CONT * sizeof (uint16_t *), KM_SLEEP);
	}

	for (i = 0; i < count; i++) {
		for (j = 0; j < MAX_CONT; j++) {
			types->ids[i]->cont_ids[j] = (uint16_t *)kmem_zalloc(
			    sizeof (uint16_t), KM_SLEEP);
		}
	}
	return (types);
}

/*
 * free the smbs_cnt_t memory
 */
static void
smb_free_strcnt(smbs_cnt_t *types, int count)
{
	int i, j;

	if (types == NULL)
		return;

	for (i = 0; i < count; i++) {
		for (j = 0; j < MAX_CONT; j++) {
			if (types->ids[i]->cont_ids[j] != NULL)
				kmem_free(types->ids[i]->cont_ids[j],
				    sizeof (uint16_t));
		}
	}

	for (i = 0; i < count; i++) {
		if (types->ids[i]->cont_ids != NULL)
			kmem_free(types->ids[i]->cont_ids,
			    MAX_CONT * sizeof (uint16_t *));
	}

	for (i = 0; i < count; i++) {
		if (types->ids[i] != NULL)
			kmem_free(types->ids[i], sizeof (smbs_con_ids_t));
	}

	if (types->ids != NULL)
		kmem_free(types->ids, count * sizeof (smbs_con_ids_t *));

	if (types != NULL)
		kmem_free(types, sizeof (smbs_cnt_t));

}

/*
 * count number of the structure type in the ksmbios
 */
static int
smb_cnttypes(smbios_hdl_t *shp, int type)
{
	const smb_struct_t *sp = shp->sh_structs;
	int nstructs = shp->sh_nstructs;
	int i;
	int cnt = 0;

	for (i = 0, cnt = 0; i < nstructs; i++, sp++) {
		if (sp->smbst_hdr->smbh_type == type)
			cnt++;
	}
	return (cnt);
}

static void
smb_strcnt(smbios_hdl_t *shp, smbs_cnt_t *stype)
{
	const smb_struct_t *sp = shp->sh_structs;
	int nstructs = shp->sh_nstructs;
	smbios_bboard_t bb;
	int i, cnt;
	int mb_cnt = 0;
	int cpub_cnt = 0;
	int sysb_cnt = 0;
	int memb_cnt = 0;
	int iob_cnt = 0;
	int inst = 0;
	int rc = 0;

	for (i = 0, cnt = 0; i < nstructs; i++, sp++) {
		if (sp->smbst_hdr->smbh_type == stype->type) {
			stype->ids[cnt]->id = sp->smbst_hdr->smbh_hdl;
			stype->ids[cnt]->inst = cnt;
			stype->ids[cnt]->visited = 0;
			stype->ids[cnt]->cont_by_id = -1;
			if (stype->type == SMB_TYPE_BASEBOARD) {
				rc = smbios_info_bboard(shp,
				    stype->ids[cnt]->id, &bb);
				if (rc == 0) {
					switch (bb.smbb_type) {
						case SMB_BBT_PROC :
							inst = cpub_cnt++;
							break;
						case SMB_BBT_IO :
							inst = iob_cnt++;
							break;
						case SMB_BBT_MEM :
							inst = memb_cnt++;
							break;
						case SMB_BBT_MOTHER :
							inst = mb_cnt++;
							break;
						default:
							/*
							 * SMB_BBT_UNKNOWN
							 * SMB_BBT_OTHER
							 * SMB_BBT_SBLADE
							 * SMB_BBT_CSWITCH
							 * SMB_BBT_SMM
							 * SMB_BBT_DAUGHTER
							 * SMB_BBT_PROCMEM
							 * SMB_BBT_PROCIO
							 * SMB_BBT_INTER
							 */
							inst = sysb_cnt++;
							break;
					}
					stype->ids[cnt]->inst = inst;
				}
			}
			cnt++;
		}
	}
	stype->count = cnt;
}

/*
 * Go through the smbios structures looking for type 2. Fill in
 * the cont_id and cont_by_id for each type 2
 *
 */
static void
smb_bb_contains(smbios_hdl_t *shp, smbs_cnt_t *stype)
{
	int i, j, cnt, c;
	uint_t cont_count;
	const smb_struct_t *spt;
	smbios_bboard_t smb_bb;
	uint16_t bb_id, cont_id;
	uint_t cont_len;
	id_t *cont_hdl = NULL;
	int rc;

	for (cnt = 0; cnt < stype->count; cnt++) {
		bb_id = stype->ids[cnt]->id;
		(void) smbios_info_bboard(shp, stype->ids[cnt]->id, &smb_bb);
		cont_count = (uint_t)smb_bb.smbb_contn;
		if (cont_count == 0) {
			continue;
		}

		cont_len = sizeof (id_t);
		cont_hdl = kmem_zalloc(cont_count * cont_len, KM_SLEEP);
		if (cont_hdl == NULL)
			continue;

		rc = smbios_info_contains(shp, stype->ids[cnt]->id,
		    cont_count, cont_hdl);
		if (rc > SMB_CONT_MAX) {
			kmem_free(cont_hdl, cont_count * cont_len);
			continue;
		}
		cont_count = MIN(rc, cont_count);

		/*
		 * fill in the type 2 and type 4 ids which are
		 * contained in this type 2
		 */
		c = 0;
		for (j = 0; j < cont_count; j++) {
			cont_id = (uint16_t)cont_hdl[j];
			spt = smb_lookup_id(shp, cont_id);
			if (spt->smbst_hdr->smbh_type == SMB_TYPE_BASEBOARD ||
			    spt->smbst_hdr->smbh_type == SMB_TYPE_PROCESSOR) {
				*stype->ids[cnt]->cont_ids[c] = cont_id;
				c++;
			}

			if (spt->smbst_hdr->smbh_type == SMB_TYPE_BASEBOARD) {
				for (i = 0; i < stype->count; i++) {
					if (stype->ids[i]->id == cont_id) {
						stype->ids[i]->cont_by_id =
						    bb_id;
					}
				}
			}

		}
		stype->ids[cnt]->cont_count = c;
		if (cont_hdl != NULL)
			kmem_free(cont_hdl, cont_count * cont_len);
	}
}

/*
 * Verify SMBIOS structures for x86 generic topology.
 *
 * Return (0) on success.
 */
static int
fm_smb_check(smbios_hdl_t *shp)
{
	int i, j;
	int bb_cnt = 0;
	int pr_cnt = 0;
	int expr_cnt = 0;
	int ma_cnt = 0;
	int exma_cnt = 0;
	int mdev_cnt = 0;
	int exmdev_cnt = 0;
	uint16_t bb_id;
	uint16_t pr_id, expr_id;
	uint16_t ma_id, exma_id;
	uint16_t mdev_id, exmdev_id;
	uint16_t *sys_ma;
	smbios_bboard_t bb;
	smbios_processor_ext_t exproc;
	smbios_memarray_t ma;
	smbios_memarray_ext_t exma;
	smbios_memdevice_t mdev;
	smbios_memdevice_ext_t exmdev;
	smbs_cnt_t *bb_stype;
	smbs_cnt_t *pr_stype, *expr_stype;
	smbs_cnt_t *ma_stype, *exma_stype;
	smbs_cnt_t *mdev_stype, *exmdev_stype;

	/*
	 * Verify the existance of the requuired extended OEM-Specific
	 * structures and they coincide with the structures they extend
	 * (e.g. the number of extended processor structures equal the
	 * number of processor structures).
	 */
	pr_cnt = smb_cnttypes(shp, SMB_TYPE_PROCESSOR);
	expr_cnt = smb_cnttypes(shp, SUN_OEM_EXT_PROCESSOR);
	ma_cnt = smb_cnttypes(shp, SMB_TYPE_MEMARRAY);
	exma_cnt = smb_cnttypes(shp, SUN_OEM_EXT_MEMARRAY);
	mdev_cnt = smb_cnttypes(shp, SMB_TYPE_MEMDEVICE);
	exmdev_cnt = smb_cnttypes(shp, SUN_OEM_EXT_MEMDEVICE);
	if (expr_cnt == 0 || exma_cnt == 0 || exmdev_cnt == 0 ||
	    expr_cnt != pr_cnt || exma_cnt > ma_cnt ||
	    exmdev_cnt > mdev_cnt) {
#ifdef	DEBUG
		cmn_err(CE_NOTE, "!Structure mismatch: ext_proc (%d) "
		    "proc (%d) ext_ma (%d) ma (%d) ext_mdev (%d) mdev (%d)\n",
		    expr_cnt, pr_cnt, exma_cnt, ma_cnt, exmdev_cnt,
		    mdev_cnt);
#endif	/* DEBUG */
		return (-1);
	}

	/*
	 * Verify the OEM-Specific structrures are correctly
	 * linked to the SMBIOS structure types they extend.
	 */

	/* allocate processor stypes */
	pr_stype = smb_create_strcnt(pr_cnt);
	expr_stype = smb_create_strcnt(expr_cnt);

	/* fill in stypes */
	pr_stype->type = SMB_TYPE_PROCESSOR;
	smb_strcnt(shp, pr_stype);
	expr_stype->type = SUN_OEM_EXT_PROCESSOR;
	smb_strcnt(shp, expr_stype);

	/* verify the ext proc struct belong to the proc struct */
	for (i = 0; i < pr_cnt; i++) {
		pr_id = pr_stype->ids[i]->id;
		expr_id = expr_stype->ids[i]->id;
		(void) smbios_info_extprocessor(shp, expr_id, &exproc);
		if (exproc.smbpe_processor != pr_id) {
#ifdef	DEBUG
			cmn_err(CE_NOTE, "!Processor struct linkage (%d)", i);
#endif	/* DEBUG */
			smb_free_strcnt(pr_stype, pr_cnt);
			smb_free_strcnt(expr_stype, expr_cnt);
			return (-1);
		}
	}

	/* free stypes */
	smb_free_strcnt(pr_stype, pr_cnt);
	smb_free_strcnt(expr_stype, expr_cnt);

	/* allocate memory array stypes */
	ma_stype = smb_create_strcnt(ma_cnt);
	exma_stype = smb_create_strcnt(exma_cnt);
	sys_ma = kmem_zalloc(sizeof (uint16_t) * ma_cnt, KM_SLEEP);

	/* fill in stypes */
	ma_stype->type = SMB_TYPE_MEMARRAY;
	smb_strcnt(shp, ma_stype);
	exma_stype->type = SUN_OEM_EXT_MEMARRAY;
	smb_strcnt(shp, exma_stype);

	/* verify linkage from ext memarray struct to memarray struct */
	for (i = 0; i < ma_cnt; i++) {
		sys_ma[i] = (uint16_t)-1;
		ma_id = ma_stype->ids[i]->id;
		(void) smbios_info_memarray(shp, ma_id, &ma);
		if (ma.smbma_use != SMB_MAU_SYSTEM)
			continue;
		/* this memarray is system memory */
		sys_ma[i] = ma_id;
		exma_id = exma_stype->ids[i]->id;
		(void) smbios_info_extmemarray(shp, exma_id, &exma);
		if (exma.smbmae_ma != ma_id) {
#ifdef	DEBUG
			cmn_err(CE_NOTE,
			    "!Memory Array struct linkage (%d)", i);
#endif	/* DEBUG */
			smb_free_strcnt(ma_stype, ma_cnt);
			smb_free_strcnt(exma_stype, exma_cnt);
			kmem_free(sys_ma, sizeof (uint16_t) * ma_cnt);
			return (-1);
		}
	}

	/* free stypes */
	smb_free_strcnt(ma_stype, ma_cnt);
	smb_free_strcnt(exma_stype, exma_cnt);

	/* allocate memory device stypes */
	mdev_stype = smb_create_strcnt(mdev_cnt);
	exmdev_stype = smb_create_strcnt(exmdev_cnt);

	/* fill in stypes */
	mdev_stype->type = SMB_TYPE_MEMDEVICE;
	smb_strcnt(shp, mdev_stype);
	exmdev_stype->type = SUN_OEM_EXT_MEMDEVICE;
	smb_strcnt(shp, exmdev_stype);

	/* verify linkage */
	for (i = 0; i < mdev_cnt; i++) {
		mdev_id = mdev_stype->ids[i]->id;
		(void) smbios_info_memdevice(shp, mdev_id, &mdev);
		/* only check system memory devices */
		for (j = 0; j < ma_cnt; j++) {
			if (sys_ma[j] == mdev.smbmd_array)
				break;
		}
		if (j == ma_cnt)
			continue;
		exmdev_id = exmdev_stype->ids[i]->id;
		(void) smbios_info_extmemdevice(shp, exmdev_id, &exmdev);
		if (exmdev.smbmdeve_md != mdev_id) {
#ifdef	DEBUG
			cmn_err(CE_NOTE, "!Memory Device struct linkage (%d)",
			    i);
#endif	/* DEBUG */
			smb_free_strcnt(mdev_stype, mdev_cnt);
			smb_free_strcnt(exmdev_stype, exmdev_cnt);
			kmem_free(sys_ma, sizeof (uint16_t) * ma_cnt);
			return (-1);
		}
	}

	/* free stypes */
	smb_free_strcnt(mdev_stype, mdev_cnt);
	smb_free_strcnt(exmdev_stype, exmdev_cnt);
	kmem_free(sys_ma, sizeof (uint16_t) * ma_cnt);

	/*
	 * Verify the presece of contained handles if there are more
	 * than one Type-2 (Base Board) structures.
	 */
	bb_cnt = smb_cnttypes(shp, SMB_TYPE_BASEBOARD);
	if (bb_cnt > 1) {
		/* allocate base board stypes */
		bb_stype = smb_create_strcnt(bb_cnt);

		/* fill in stypes */
		bb_stype->type = SMB_TYPE_BASEBOARD;
		smb_strcnt(shp, bb_stype);

		/* verify contained handles */
		for (i = 0; i < bb_cnt; i++) {
			bb_id = bb_stype->ids[i]->id;
			(void) smbios_info_bboard(shp, bb_id, &bb);
			if (bb.smbb_contn == 0) {
#ifdef	DEBUG
				cmn_err(CE_NOTE, "!No contained hanldes (%d)",
				    i);
#endif	/* DEBUG */
				smb_free_strcnt(bb_stype, bb_cnt);
				return (-1);
			}
		}

		/* free stypes */
		smb_free_strcnt(bb_stype, bb_cnt);
	}

	return (0);
}

void
fm_smb_fmacompat()
{
	int i, j;
	int id;
	int cnt;
	const char **oem_strings = NULL;
	smbs_cnt_t *oemstypes;
	smbios_hdl_t *shp;
	int strcnt;
	int compat = 0;

	/* check for BKS */
	if (x86gentopo_legacy == 1) {
		return;
	}

	shp = ksmbios;
	if (shp == NULL) {
		goto bad;
	}

	/* OEM strings (Type 11) */
	strcnt = smb_cnttypes(shp, SMB_TYPE_OEMSTR);
	if (strcnt == 0)
		goto bad;

	oemstypes = smb_create_strcnt(strcnt);
	if (oemstypes == NULL)
		goto bad;

	oemstypes->type = SMB_TYPE_OEMSTR;
	smb_strcnt(shp, oemstypes);

	for (i = 0; i < oemstypes->count && compat == 0; i++) {
		id = oemstypes->ids[i]->id;
		cnt = smbios_info_strtab(shp, id, 0, NULL);
		if (cnt > 0) {
			oem_strings = kmem_zalloc(sizeof (char *) * cnt,
			    KM_SLEEP);
			(void) smbios_info_strtab(shp, id, cnt, oem_strings);

			for (j = 0; j < cnt; j++) {
				if (strncmp(oem_strings[j], SMB_PRMS1,
				    strlen(SMB_PRMS1) + 1) == 0) {
					compat = 1;
					break;
				}
			}
			kmem_free(oem_strings, sizeof (char *) * cnt);
		}
	}
	smb_free_strcnt(oemstypes, strcnt);

	/* sanity check SMBIOS structures */
	if ((compat != 0) && (fm_smb_check(shp) == 0))
		return;

bad:
	/* not compatible with x86gentopo; revert to legacy enumeration */
#ifdef	DEBUG
	cmn_err(CE_NOTE,
	    "!SMBIOS is not compatible with x86 generic topology.");
	cmn_err(CE_NOTE, "!Invoking legacy x86 topology enumeration.");
#endif	/* DEBUG */
	x86gentopo_legacy = 1;
}

static int
find_matching_apic(smbios_hdl_t *shp, uint16_t proc_id, uint_t strand_apicid)
{
	uint16_t ext_id;
	int i, j;
	smbios_processor_ext_t ep;
	smbs_cnt_t *pstypes;
	int strcnt;

	strcnt = smb_cnttypes(shp, SUN_OEM_EXT_PROCESSOR);
	if (strcnt == 0)
		return (0);

	pstypes = smb_create_strcnt(strcnt);
	if (pstypes == NULL)
		return (0);

	pstypes->type = SUN_OEM_EXT_PROCESSOR;
	smb_strcnt(shp, pstypes);
	for (i = 0; i < pstypes->count; i++) {
		ext_id = pstypes->ids[i]->id;
		(void) smbios_info_extprocessor(shp, ext_id, &ep);
		if (ep.smbpe_processor == proc_id) {
			for (j = 0; j < ep.smbpe_n; j++) {
				if (ep.smbpe_apicid[j] == strand_apicid) {
					smb_free_strcnt(pstypes, strcnt);
					return (1);
				}
			}
		}
	}
	smb_free_strcnt(pstypes, strcnt);
	return (0);
}

/*
 * go throught the type 2 structure contained_ids looking for
 * the type 4 which  has strand_apicid == this strand_apicid
 */
static int
find_matching_proc(smbios_hdl_t *shp, uint_t strand_apicid,
    uint16_t bb_id, uint16_t proc_hdl, int is_proc)
{
	int n;
	const smb_struct_t *sp;
	smbios_bboard_t bb;
	uint_t cont_count, cont_len;
	uint16_t cont_id;
	id_t *cont_hdl = NULL;
	int rc;


	(void) smbios_info_bboard(shp, bb_id, &bb);
	cont_count = (uint_t)bb.smbb_contn;
	if (cont_count == 0)
		return (0);

	cont_len = sizeof (id_t);
	cont_hdl = kmem_zalloc(cont_count * cont_len, KM_SLEEP);
	if (cont_hdl == NULL)
		return (0);

	rc = smbios_info_contains(shp, bb_id, cont_count, cont_hdl);
	if (rc > SMB_CONT_MAX) {
		kmem_free(cont_hdl, cont_count * cont_len);
		return (0);
	}
	cont_count = MIN(rc, cont_count);

	for (n = 0; n < cont_count; n++) {
		cont_id = (uint16_t)cont_hdl[n];
		sp = smb_lookup_id(shp, cont_id);
		if (sp->smbst_hdr->smbh_type == SMB_TYPE_PROCESSOR) {
			if (is_proc) {
				if (find_matching_apic(shp, cont_id,
				    strand_apicid)) {
					kmem_free(cont_hdl,
					    cont_count * cont_len);
					return (1);
				}
			} else {
				if (cont_id == proc_hdl) {
					kmem_free(cont_hdl,
					    cont_count * cont_len);
					return (1);
				}
			}
		}
	}
	if (cont_hdl != NULL)
		kmem_free(cont_hdl, cont_count * cont_len);

	return (0);
}

void
get_bboard_index(smbs_cnt_t *bbstypes, uint_t bb_id, bbindex_t *bb_idx)
{
	int curr_id, tmp_id;
	int i, j, nb;
	bbindex_t tmp_idx;

	for (i = 0; i < MAX_PAIRS; i++)
		tmp_idx.index[i] = 0;

	tmp_idx.count = 0;

	curr_id = bb_id;
	for (nb = bbstypes->count-1, i = 0; nb >= 0; nb--) {
		tmp_id = bbstypes->ids[nb]->id;
		if (tmp_id == curr_id) {
			tmp_idx.index[i] = nb;
			tmp_idx.count++;
			curr_id = bbstypes->ids[nb]->cont_by_id;
			if (curr_id == -1)
				break;
			i++;
		}
	}

	for (i = tmp_idx.count - 1, j = 0; i >= 0; i--) {
		bb_idx->index[j] = tmp_idx.index[i];
		j++;
	}

	bb_idx->count = tmp_idx.count;
}

int
get_chassis_inst(smbios_hdl_t *shp, uint16_t *chassis_inst,
    uint16_t bb_id, int *chcnt)
{
	int ch_strcnt;
	smbs_cnt_t *chstypes;
	uint16_t chassis_id, tmp_id;
	smbios_bboard_t bb;
	int rc = 0;
	int i;

	rc = smbios_info_bboard(shp, bb_id, &bb);
	if (rc != 0) {
		return (-1);
	}

	chassis_id = bb.smbb_chassis;

	ch_strcnt = smb_cnttypes(shp, SMB_TYPE_CHASSIS);

	if (ch_strcnt == 0)
		return (-1);

	chstypes = smb_create_strcnt(ch_strcnt);
	if (chstypes == NULL)
		return (-1);

	chstypes->type = SMB_TYPE_CHASSIS;
	smb_strcnt(shp, chstypes);

	for (i = 0; i < chstypes->count; i++) {
		tmp_id = chstypes->ids[i]->id;
		if (tmp_id == chassis_id) {
			*chassis_inst = chstypes->ids[i]->inst;
			if (chstypes->ids[i]->inst != 0)
				*chcnt = 2;
			else
				*chcnt = 1;
			smb_free_strcnt(chstypes, ch_strcnt);
			return (0);
		}
	}

	smb_free_strcnt(chstypes, ch_strcnt);
	return (-1);
}

int
smb_get_bb_fmri(smbios_hdl_t *shp, nvlist_t *fmri,  uint_t parent,
    smbs_cnt_t *bbstypes)
{
	int rc = 0;
	int i, j, n, cnt;
	int id, index;
	nvlist_t *pairs[MAX_PAIRS];
	smbios_bboard_t bb;
	uint16_t chassis_inst, mch_inst;
	char name[40];
	char idstr[11];
	bbindex_t bb_idx;
	uint16_t bbid;
	int chcnt = 0;

	for (n = 0; n < MAX_PAIRS; n++) {
		bb_idx.index[n] = 0;
		pairs[n] = NULL;
	}
	bb_idx.count = 0;

	get_bboard_index(bbstypes, parent, &bb_idx);

	index = bb_idx.index[0];
	bbid = bbstypes->ids[index]->id;

	rc = get_chassis_inst(shp, &chassis_inst, bbid, &chcnt);

	if (rc != 0) {
		return (rc);
	}

	if ((bb_idx.count + chcnt) > MAX_PAIRS) {
		return (-1);
	}

	i = 0;
	if (chcnt > 1) {
		/*
		 * create main chassis pair
		 */
		pairs[i] = fm_nvlist_create(NULL);
		if (pairs[i] == NULL) {
			return (-1);
		}
		mch_inst = 0;
		(void) snprintf(idstr, sizeof (idstr), "%u", mch_inst);
		if ((nvlist_add_string(pairs[i], FM_FMRI_HC_NAME,
		    "chassis") != 0) ||
		    (nvlist_add_string(pairs[i], FM_FMRI_HC_ID, idstr)) != 0) {
			fm_nvlist_destroy(pairs[i], FM_NVA_FREE);
			return (-1);
		}
		i++;
	}

	/*
	 * create chassis pair
	 */
	pairs[i] = fm_nvlist_create(NULL);
	if (pairs[i] == NULL) {
		for (n = 0; n < MAX_PAIRS; n++) {
			if (pairs[n] != NULL)
				fm_nvlist_destroy(pairs[n], FM_NVA_FREE);
		}
		return (-1);
	}
	(void) snprintf(idstr, sizeof (idstr), "%u", chassis_inst);
	if ((nvlist_add_string(pairs[i], FM_FMRI_HC_NAME, "chassis") != 0) ||
	    (nvlist_add_string(pairs[i], FM_FMRI_HC_ID, idstr) != 0)) {
		for (n = 0; n < MAX_PAIRS; n++) {
			if (pairs[n] != NULL)
				fm_nvlist_destroy(pairs[n], FM_NVA_FREE);
		}
		return (-1);
	}

	for (j = 0, i = chcnt, cnt = chcnt; j < bb_idx.count; j++) {
		index = bb_idx.index[j];
		bbid = bbstypes->ids[index]->id;
		rc =  smbios_info_bboard(shp, bbid, &bb);
		if (rc != 0) {
			rc = -1;
			break;
		}

		pairs[i] = fm_nvlist_create(NULL);
		if (pairs[i] == NULL) {
			rc = -1;
			break;
		}

		id = bbstypes->ids[index]->inst;
		(void) snprintf(idstr, sizeof (idstr), "%u", id);
		(void) strncpy(name, bbd_type[bb.smbb_type].name,
		    sizeof (name));
		cnt++;

		if (nvlist_add_string(pairs[i], FM_FMRI_HC_NAME, name) != 0 ||
		    nvlist_add_string(pairs[i], FM_FMRI_HC_ID, idstr)
		    != 0) {
			rc = -1;
			break;
		}
		i++;
	}

	if (rc != -1) {
		if (nvlist_add_nvlist_array(fmri, FM_FMRI_HC_LIST,
		    pairs, cnt) != 0) {
			rc = -1;
		}
	}

	for (n = 0; n < cnt; n++) {
		if (pairs[n] != NULL)
			fm_nvlist_destroy(pairs[n], FM_NVA_FREE);
	}

	return (rc);
}

/*
 * pass in strand_apic id
 * return chip's bboards list which has strand_apicid == passed
 * in strand_apic id
 */
static nvlist_t *
smb_bboard(uint_t strand_apicid, uint16_t proc_hdl, int is_proc)
{
	smbios_hdl_t *shp;
	smbs_cnt_t *bbstypes;
	int nb;
	int bb_smbid;
	nvlist_t *fmri = NULL;
	int rc = 0;
	int bb_strcnt;

	if (x86gentopo_legacy)
		return (NULL);

	shp = ksmbios;
	if (shp == NULL) {
		goto bad;
	}

	/*
	 * Type 2 structs : "base board"
	 */
	bb_strcnt = smb_cnttypes(shp, SMB_TYPE_BASEBOARD);
	if (bb_strcnt == 0) {
		goto bad;
	}

	bbstypes = smb_create_strcnt(bb_strcnt);
	if (bbstypes == NULL)  {
		goto bad;
	}

	bbstypes->type = SMB_TYPE_BASEBOARD;
	smb_strcnt(shp, bbstypes);
	smb_bb_contains(shp, bbstypes);

	for (nb = 0; nb < bbstypes->count; nb++) {
		if (bbstypes->ids[nb]->visited) {
			continue;
		}

		bbstypes->ids[nb]->visited = 1;
		bb_smbid = bbstypes->ids[nb]->id;

		/*
		 * check if there is a matching  processor under
		 * this board. If found, find base board(s) of this proc
		 * If proc is not in contained handle of a base board and
		 * there is only one base board in the system, treat that base
		 * board as the parent of the proc
		 */
		if (find_matching_proc(shp, strand_apicid,
		    bb_smbid, proc_hdl, is_proc) || (bbstypes->count == 1)) {
			fmri = fm_nvlist_create(NULL);
			if (fmri == NULL) {
				smb_free_strcnt(bbstypes, bb_strcnt);
				goto bad;
			}
			/*
			 * find parent by walking the cont_by_id
			 */
			rc = smb_get_bb_fmri(shp, fmri, bb_smbid, bbstypes);
			smb_free_strcnt(bbstypes, bb_strcnt);
			if (rc == 0) {
				return (fmri);
			} else
				goto bad;
		}

	}

	smb_free_strcnt(bbstypes, bb_strcnt);
bad:
	/* revert to legacy enumeration */
	x86gentopo_legacy = 1;

	return (NULL);
}

nvlist_t *
fm_smb_bboard(uint_t strand_apicid)
{
	return (smb_bboard(strand_apicid, 0, PROC));
}

int
fm_smb_chipinst(uint_t strand_apicid, uint_t *chip_inst, uint16_t *smbiosid)
{
	int n;
	smbios_hdl_t *shp;
	uint16_t proc_id;
	smbs_cnt_t *pstypes;
	int strcnt;

	if (x86gentopo_legacy)
		return (-1);

	shp = ksmbios;
	if (shp == NULL) {
		goto bad;
	}

	strcnt = smb_cnttypes(shp, SMB_TYPE_PROCESSOR);
	if (strcnt == 0)
		goto bad;

	pstypes = smb_create_strcnt(strcnt);
	if (pstypes == NULL)
		goto bad;

	pstypes->type = SMB_TYPE_PROCESSOR;
	smb_strcnt(shp, pstypes);
	for (n = 0; n < pstypes->count; n++) {
		proc_id = pstypes->ids[n]->id;
		if (find_matching_apic(shp, proc_id, strand_apicid)) {
			*chip_inst = pstypes->ids[n]->inst;
			*smbiosid = pstypes->ids[n]->id;
			smb_free_strcnt(pstypes, strcnt);
			return (0);
		}
	}
	smb_free_strcnt(pstypes, strcnt);
bad:
	/* revert to legacy enumerarion */
	x86gentopo_legacy = 1;

	return (-1);
}

nvlist_t *
fm_smb_mc_bboards(uint_t bdf)
{

	int i;
	smbios_hdl_t *shp;
	uint16_t ext_id;
	smbios_memarray_ext_t em;
	nvlist_t *fmri = NULL;
	smbs_cnt_t *mastypes;
	int strcnt;

	if (x86gentopo_legacy)
		return (NULL);

	shp = ksmbios;
	if (shp == NULL) {
		goto bad;
	}

	strcnt = smb_cnttypes(shp, SUN_OEM_EXT_MEMARRAY);
	if (strcnt == 0)
		goto bad;

	mastypes = smb_create_strcnt(strcnt);
	if (mastypes == NULL)
		goto bad;

	mastypes->type = SUN_OEM_EXT_MEMARRAY;
	smb_strcnt(shp, mastypes);
	for (i = 0; i < mastypes->count; i++) {
		ext_id = mastypes->ids[i]->id;
		(void) smbios_info_extmemarray(shp, ext_id, &em);
		if (em.smbmae_bdf == bdf) {
			fmri = smb_bboard(0, em.smbmae_comp, MC);
			smb_free_strcnt(mastypes, strcnt);
			return (fmri);
		}
	}
	smb_free_strcnt(mastypes, strcnt);
bad:
	/* revert to legacy enumerarion */
	x86gentopo_legacy = 1;

	return (NULL);
}

int
fm_smb_mc_chipinst(uint_t bdf, uint_t *chip_inst) {

	int i, j;
	smbios_hdl_t *shp;
	smbios_memarray_ext_t em;
	uint16_t ext_id, proc_id;
	smbs_cnt_t *mastypes;
	smbs_cnt_t *pstypes;
	int ma_strcnt, p_strcnt;

	if (x86gentopo_legacy)
		return (-1);

	shp = ksmbios;
	if (shp == NULL) {
		goto bad;
	}

	ma_strcnt = smb_cnttypes(shp, SUN_OEM_EXT_MEMARRAY);
	if (ma_strcnt == 0)
		goto bad;

	mastypes = smb_create_strcnt(ma_strcnt);
	if (mastypes == NULL)
		goto bad;

	mastypes->type = SUN_OEM_EXT_MEMARRAY;
	smb_strcnt(shp, mastypes);
	for (i = 0; i < mastypes->count; i++) {
		ext_id = mastypes->ids[i]->id;
		(void) smbios_info_extmemarray(shp, ext_id, &em);
		    if (em.smbmae_bdf == bdf) {
			p_strcnt = smb_cnttypes(shp, SMB_TYPE_PROCESSOR);
			if (p_strcnt == 0) {
				smb_free_strcnt(mastypes, ma_strcnt);
				goto bad;
			}

			pstypes = smb_create_strcnt(p_strcnt);
			if (pstypes == NULL) {
				smb_free_strcnt(mastypes, ma_strcnt);
				goto bad;
			}

			pstypes->type = SMB_TYPE_PROCESSOR;
			smb_strcnt(shp, pstypes);
			for (j = 0; j < pstypes->count; j++) {
				proc_id = pstypes->ids[j]->id;
				if (proc_id == em.smbmae_comp) {
					*chip_inst = pstypes->ids[j]->inst;
					smb_free_strcnt(mastypes, ma_strcnt);
					smb_free_strcnt(pstypes, p_strcnt);
					return (0);
				}
			}
		}
	}
	smb_free_strcnt(mastypes, ma_strcnt);
	smb_free_strcnt(pstypes, p_strcnt);
bad:
	/* revert to legacy enumeration */
	x86gentopo_legacy = 1;

	return (-1);
}
