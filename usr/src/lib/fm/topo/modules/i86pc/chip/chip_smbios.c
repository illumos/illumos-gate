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
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <unistd.h>
#include <ctype.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/devfm.h>
#include <libnvpair.h>
#include <sys/smbios.h>
#include <fm/topo_mod.h>
#include <sys/fm/protocol.h>
#include <sys/smbios_impl.h>

#include "chip.h"

#define	CPU_SLOTS	64
#define	DIMM_SLOTS	512
#define	MC_INSTANCES	128

#define	MAXNAMELEN	256
#define	LABEL		1

#define	SKIP_CS		9999


typedef struct cpu_smbios {
	id_t cpu_id;
	uint8_t status;
	uint8_t fru;
}csmb_t;

typedef struct dimm_smbios {
	id_t dimm_id;
	id_t extdimm_id;
	const char *bankloc;
}dsmb_t;

typedef struct mct_smbios {
	id_t extmct_id;
	id_t mct_id;
	id_t p_id;
}msmb_t;

csmb_t cpusmb[CPU_SLOTS];
dsmb_t dimmsmb[DIMM_SLOTS];
msmb_t mctsmb[MC_INSTANCES];

static int ncpu_ids = 0;
static int bb_count = 0;
static int ndimm_ids, nmct_ids = 0;

static int fill_chip_smbios = 0;
typedef int smbios_rec_f(topo_mod_t *, const smbios_struct_t *);

static smbios_struct_t *
smb_export(const smb_struct_t *stp, smbios_struct_t *sp)
{
	const smb_header_t *hdr;

	if (stp == NULL)
		return (NULL);

	hdr = stp->smbst_hdr;
	sp->smbstr_id = hdr->smbh_hdl;
	sp->smbstr_type = hdr->smbh_type;
	sp->smbstr_data = hdr;
	sp->smbstr_size = (size_t)(stp->smbst_end - (uchar_t *)hdr);

	return (sp);
}

static int
extdimmslot_to_dimmslot(topo_mod_t *mod, id_t chip_smbid, int channum,
    int csnum)
{
	smbios_memdevice_ext_t emd;
	smbios_memdevice_t md;
	int i, j;
	int match = 0;
	smbios_hdl_t *shp;

	shp = topo_mod_smbios(mod);
	if (shp == NULL)
		return (-1);

	if (chip_smbid == IGNORE_ID && bb_count <= 1 && nmct_ids <= 1) {
		for (i = 0; i < ndimm_ids; i++) {
			if (smbios_info_extmemdevice(shp, dimmsmb[i].extdimm_id,
			    &emd) != 0) {
				continue;
			}

			if (emd.smbmdeve_drch == channum) {
				uint_t ncs;
				uint8_t *cs;

				if (csnum == SKIP_CS) {
					return (emd.smbmdeve_md);
				}

				if (smbios_info_extmemdevice_cs(shp,
				    dimmsmb[i].extdimm_id, &ncs, &cs) != 0) {
					continue;
				}

				for (uint_t k = 0; k < ncs; k++) {
					if (cs[k] != csnum) {
						continue;
					}

					smbios_info_extmemdevice_cs_free(shp,
					    ncs, cs);
					return (emd.smbmdeve_md);
				}

				smbios_info_extmemdevice_cs_free(shp, ncs, cs);
			}
		}
	}

	for (j = 0; j < nmct_ids; j++) {
		if (mctsmb[j].p_id == chip_smbid) {
			for (i = 0; i < ndimm_ids; i++) {
				if (smbios_info_extmemdevice(shp,
				    dimmsmb[i].extdimm_id, &emd) != 0) {
					continue;
				}

				(void) smbios_info_memdevice(shp,
				    emd.smbmdeve_md, &md);
				if (md.smbmd_array == mctsmb[j].mct_id &&
				    emd.smbmdeve_drch == channum) {
					match = 1;
					break;
				}
			}
			if (match) {
				uint_t ncs;
				uint8_t *cs;

				if (csnum == SKIP_CS) {
					return (emd.smbmdeve_md);
				}

				if (smbios_info_extmemdevice_cs(shp,
				    dimmsmb[i].extdimm_id, &ncs, &cs) != 0) {
					continue;
				}

				for (uint_t k = 0; k < ncs; k++) {
					if (cs[k] != csnum) {
						continue;
					}

					smbios_info_extmemdevice_cs_free(shp,
					    ncs, cs);
					return (emd.smbmdeve_md);
				}
				smbios_info_extmemdevice_cs_free(shp, ncs, cs);
			}
		}
	}

	return (-1);
}

id_t
memnode_to_smbiosid(topo_mod_t *mod, uint16_t chip_smbid, const char *name,
    uint64_t nodeid, void *data)
{

	if (strcmp(name, CS_NODE_NAME) == 0) {
		int channum, csnum;
		id_t dimmslot = -1;

		if (data == NULL)
			return (-1);
		channum = *(int *)data;
		csnum = nodeid;
		/*
		 * Set the DIMM Slot label to the Chip Select Node
		 * Set the "data" to carry the DIMM instance
		 */
		dimmslot = extdimmslot_to_dimmslot(mod, chip_smbid, channum,
		    csnum);
		if (dimmslot != -1 && dimmsmb[0].dimm_id != 0)
			*((id_t *)data) = dimmslot % (dimmsmb[0].dimm_id);
		else
			*((id_t *)data) = -1;

		return (dimmslot);

	} else if (strcmp(name, DIMM_NODE_NAME) == 0) {
		static int dimmnum = 0;

		/*
		 * On certain Intel Chips, topology does not have
		 * chip-select nodes, it has the below layout
		 * chip/memory-controller/dram-channel/dimm
		 * so we check if channel instance is passed
		 * and get the SMBIOS ID based on the channel
		 */
		if (data != NULL) {
			int channum;
			id_t dimmslot = -1;

			channum = *(int *)data;
			dimmslot = extdimmslot_to_dimmslot(mod, chip_smbid,
			    channum, SKIP_CS);

			return (dimmslot);
		}
		dimmnum = nodeid;
		return (dimmsmb[dimmnum].dimm_id);
	}

	return (-1);
}


int
chip_get_smbstruct(topo_mod_t *mod, const smbios_struct_t *sp)
{
	smbios_processor_t p;
	smbios_memdevice_t md;
	smbios_processor_ext_t extp;
	smbios_memarray_ext_t extma;
	smbios_memdevice_ext_t extmd;
	int ext_match = 0;
	smbios_hdl_t *shp;

	shp = topo_mod_smbios(mod);
	if (shp == NULL)
		return (-1);

	switch (sp->smbstr_type) {
	case SMB_TYPE_BASEBOARD:
		bb_count++;
		break;
	case SMB_TYPE_MEMARRAY:
		mctsmb[nmct_ids].mct_id = sp->smbstr_id;
		nmct_ids++;
		break;
	case SUN_OEM_EXT_MEMARRAY:
		if (shp != NULL) {
			if (smbios_info_extmemarray(shp,
			    sp->smbstr_id, &extma) != 0) {
				topo_mod_dprintf(mod, "chip_get_smbstruct : "
				    "smbios_info_extmemarray()"
				    "failed\n");
				return (-1);
			}
		} else
			return (-1);
		for (int i = 0; i < nmct_ids; i++) {
			if (extma.smbmae_ma == mctsmb[i].mct_id) {
				mctsmb[i].extmct_id = sp->smbstr_id;
				mctsmb[i].p_id = extma.smbmae_comp;
				ext_match = 1;
				break;
			}
		}
		if (!ext_match) {
			topo_mod_dprintf(mod, "chip_get_smbstruct : "
			    "EXT_MEMARRAY-MEMARRAY records are mismatched\n");
			ext_match = 0;
			return (-1);
		}
		break;
	case SMB_TYPE_MEMDEVICE:
		dimmsmb[ndimm_ids].dimm_id = sp->smbstr_id;
		if (shp != NULL) {
			if (smbios_info_memdevice(shp,
			    sp->smbstr_id, &md) != 0)
				return (-1);
		} else
			return (-1);
		dimmsmb[ndimm_ids].bankloc = md.smbmd_bloc;
		ndimm_ids++;
		break;
	/*
	 * Every SMB_TYPE_MEMDEVICE SHOULD have a
	 * corresponding SUN_OEM_EXT_MEMDEVICE
	 */
	case SUN_OEM_EXT_MEMDEVICE:
		if (smbios_info_extmemdevice(shp,
		    sp->smbstr_id, &extmd) != 0) {
			topo_mod_dprintf(mod, "chip_get_smbstruct : "
			    "smbios_info_extmemdevice()"
			    "failed\n");
			return (-1);
		}
		for (int i = 0; i < ndimm_ids; i++) {
			if (extmd.smbmdeve_md == dimmsmb[i].dimm_id) {
				dimmsmb[i].extdimm_id = sp->smbstr_id;
				ext_match = 1;
				break;
			}
		}
		if (!ext_match) {
			topo_mod_dprintf(mod, "chip_get_smbstruct : "
			    "EXT_MEMDEVICE-MEMDEVICE records are mismatched\n");
			ext_match = 0;
			return (-1);
		}
		break;
	case SMB_TYPE_PROCESSOR:
		cpusmb[ncpu_ids].cpu_id = sp->smbstr_id;
		if (shp != NULL) {
			if (smbios_info_processor(shp,
			    sp->smbstr_id, &p) != 0) {
				topo_mod_dprintf(mod, "chip_get_smbstruct : "
				    "smbios_info_processor()"
				    "failed\n");
				return (-1);
			}
		}
		cpusmb[ncpu_ids].status = p.smbp_status;
		ncpu_ids++;
		break;
	/*
	 * Every SMB_TYPE_PROCESSOR SHOULD have a
	 * corresponding SUN_OEM_EXT_PROCESSOR
	 */
	case SUN_OEM_EXT_PROCESSOR:
		if (smbios_info_extprocessor(shp,
		    sp->smbstr_id, &extp) != 0) {
			topo_mod_dprintf(mod, "chip_get_smbstruct : "
			    "smbios_info_extprocessor()"
			    "failed\n");
			return (-1);
		}
		for (int i = 0; i < ncpu_ids; i++) {
			if (extp.smbpe_processor == cpusmb[i].cpu_id) {
				cpusmb[i].fru = extp.smbpe_fru;
				ext_match = 1;
				break;
			}
		}
		if (!ext_match) {
			topo_mod_dprintf(mod, "chip_get_smbstruct : "
			    "EXT_PROCESSOR-PROCESSOR records are mismatched\n");
			ext_match = 0;
			return (-1);
		}
		break;
	}
	return (0);
}

static int
chip_smbios_iterate(topo_mod_t *mod, smbios_rec_f *func_iter)
{
	const smb_struct_t *sp;
	smbios_struct_t s;
	int i, rv = 0;
	smbios_hdl_t *shp;

	shp = topo_mod_smbios(mod);
	if (shp == NULL)
		return (rv);

	sp = shp->sh_structs;
	for (i = 0; i < shp->sh_nstructs; i++, sp++) {
		if (sp->smbst_hdr->smbh_type != SMB_TYPE_INACTIVE &&
		    (rv = func_iter(mod, smb_export(sp, &s))) != 0)
			break;
	}
	return (rv);
}

int
init_chip_smbios(topo_mod_t *mod)
{
	if (!fill_chip_smbios) {
		if (chip_smbios_iterate(mod, chip_get_smbstruct) == -1)
			return (-1);
		fill_chip_smbios = 1;
	}

	return (0);
}

int
chip_status_smbios_get(topo_mod_t *mod, id_t smb_id)
{
	/*
	 * Type-4 Socket Status bit definitions per SMBIOS Version 2.6
	 *
	 * STATUS
	 * CPU Socket Populated
	 * CPU Socket Unpopulated
	 * Populated : Enabled
	 * Populated : Disabled by BIOS (Setup)
	 * Populated : Disabled by BIOS (Error)
	 * Populated : Idle
	 */
	uint8_t	enabled = 0x01;
	uint8_t	populated = 0x40;

	for (int i = 0; i < ncpu_ids; i++) {
		if (smb_id == cpusmb[i].cpu_id) {
			if (cpusmb[i].status  == (enabled | populated))
				return (1);
		}
	}

	topo_mod_dprintf(mod, "chip_status_smbios_get() failed"
	    " considering that Type 4 ID : %ld is disabled", smb_id);
	return (0);
}

int
chip_fru_smbios_get(topo_mod_t *mod, id_t smb_id)
{
	/*
	 * smbios_processor_ext_t->smbpe_fru : if set to 1
	 * processor is a FRU
	 */
	uint8_t	fru = 1;

	for (int i = 0; i < ncpu_ids; i++) {
		if (smb_id == cpusmb[i].cpu_id) {
			if (cpusmb[i].fru == fru)
				return (1);
			else
				return (0);
		}
	}

	topo_mod_dprintf(mod, "chip_fru_smbios_get() failed"
	    " considering that Type 4 ID : %ld is not a FRU", smb_id);
	return (0);
}

/*
 * This could be defined as topo_mod_strlen()
 */
size_t
chip_strlen(const char *str)
{
	int len = 0;

	if (str != NULL)
		len = strlen(str);

	return (len);
}

/*
 * We clean Serials, Revisions, Part No. strings, to
 * avoid getting lost when fmd synthesizes these
 * strings. :, =, /, ' ' characters are replaced
 * with character '-' any non-printable characters
 * as seen with !isprint() is also replaced with '-'
 * Labels are checked only for non-printable characters.
 */
static const char *
chip_cleanup_smbios_str(topo_mod_t *mod, const char *begin, int str_type)
{
	char buf[MAXNAMELEN];
	const char *end, *cp;
	char *pp;
	char c;
	int i;

	end = begin + strlen(begin);

	while (begin < end && isspace(*begin))
		begin++;
	while (begin < end && isspace(*(end - 1)))
		end--;

	if (begin >= end)
		return (NULL);

	cp = begin;
	for (i = 0; i < MAXNAMELEN - 1; i++) {
		if (cp >= end)
			break;
		c = *cp;
		if (str_type == LABEL) {
			if (!isprint(c))
				buf[i] = '-';
			else
				buf[i] = c;
		} else {
			if (c == ':' || c == '=' || c == '/' ||
			    isspace(c) || !isprint(c))
				buf[i] = '-';
			else
				buf[i] = c;
		}
		cp++;
	}
	buf[i] = 0;

	pp = topo_mod_strdup(mod, buf);

	if (str_type == LABEL)
		topo_mod_strfree(mod, (char *)begin);

	return (pp);
}

const char *
chip_label_smbios_get(topo_mod_t *mod, tnode_t *pnode, id_t smb_id,
    char *ksmbios_label)
{
	smbios_info_t c;
	char *label = NULL;
	char *buf = NULL;
	const char *lsmbios_label = NULL;
	int bufsz = 0;
	char *delim = NULL, *blank = " ";
	const char *dimm_bank = NULL;
	const char *clean_label = NULL;
	int err;
	smbios_hdl_t *shp;

	shp = topo_mod_smbios(mod);
	if (shp != NULL) {
		/*
		 * Get Parent FRU's label
		 */
		if (topo_prop_get_string(pnode, TOPO_PGROUP_PROTOCOL,
		    TOPO_PROP_LABEL, &label, &err) == -1)
			topo_mod_dprintf(mod, "Failed to get"
			    " Label of Parent Node error : %d\n", err);

		if (label != NULL)
			label = (char *)chip_cleanup_smbios_str(mod,
			    label, LABEL);

		/*
		 * On Intel the driver gets the label from ksmbios
		 * so we check if we already have it, if not we
		 * get it from libsmbios
		 */
		if (ksmbios_label == NULL && smb_id != -1) {
			if (smbios_info_common(shp, smb_id, &c) != SMB_ERR) {
				for (int i = 0; i < ndimm_ids; i++) {
					if (smb_id == dimmsmb[i].dimm_id) {
						dimm_bank = dimmsmb[i].bankloc;
						break;
					}
				}
				if (dimm_bank != NULL) {
					bufsz += chip_strlen(blank) +
					    chip_strlen(dimm_bank);
				}
				lsmbios_label = c.smbi_location;
			}
		} else
			lsmbios_label = ksmbios_label;

		if (label != NULL && lsmbios_label != NULL)
			delim = "/";

		bufsz += chip_strlen(label) + chip_strlen(delim) +
		    chip_strlen(lsmbios_label) + 1;

		buf = topo_mod_alloc(mod, bufsz);

		if (buf != NULL) {
			if (label != NULL) {
				(void) strlcpy(buf, label, bufsz);
				if (lsmbios_label != NULL) {
					(void) strlcat(buf, delim, bufsz);
					/*
					 * If we are working on a DIMM
					 * and we are deriving from libsmbios
					 * smbi_location has the Device Locator.
					 * add the Device Locator
					 * add Bank Locator latter
					 */
					(void) strlcat(buf, lsmbios_label,
					    bufsz);
				}
			} else if (lsmbios_label != NULL)
				(void) strlcpy(buf, lsmbios_label,
				    bufsz);

			if (dimm_bank != NULL) {
				(void) strlcat(buf, blank, bufsz);
				(void) strlcat(buf, dimm_bank, bufsz);
			}
		}

		clean_label = chip_cleanup_smbios_str(mod, buf, LABEL);
		topo_mod_strfree(mod, label);

		return (clean_label);
	}

	topo_mod_dprintf(mod, "Failed to get Label\n");
	return (NULL);
}


const char *
chip_serial_smbios_get(topo_mod_t *mod, id_t smb_id)
{
	smbios_info_t c;
	const char *clean_serial = NULL;
	smbios_hdl_t *shp;

	shp = topo_mod_smbios(mod);
	if (shp != NULL && smb_id != -1)
		if (smbios_info_common(shp, smb_id, &c) != SMB_ERR) {
			clean_serial = chip_cleanup_smbios_str(mod,
			    c.smbi_serial, 0);
			return (clean_serial);
		}

	topo_mod_dprintf(mod, "Failed to get Serial \n");
	return (NULL);
}


const char *
chip_part_smbios_get(topo_mod_t *mod, id_t smb_id)
{
	smbios_info_t c;
	const char *clean_part = NULL;
	smbios_hdl_t *shp;

	shp = topo_mod_smbios(mod);
	if (shp != NULL && smb_id != -1)
		if (smbios_info_common(shp, smb_id, &c) != SMB_ERR) {
			clean_part = chip_cleanup_smbios_str(mod,
			    c.smbi_part, 0);
			return (clean_part);
		}

	topo_mod_dprintf(mod, "Failed to get Part\n");
	return (NULL);
}

const char *
chip_rev_smbios_get(topo_mod_t *mod, id_t smb_id)
{
	smbios_info_t c;
	const char *clean_rev = NULL;
	smbios_hdl_t *shp;

	shp = topo_mod_smbios(mod);
	if (shp != NULL && smb_id != -1)
		if (smbios_info_common(shp, smb_id, &c) != SMB_ERR) {
			clean_rev = chip_cleanup_smbios_str(mod,
			    c.smbi_version, 0);
			return (clean_rev);
		}

	topo_mod_dprintf(mod, "Failed to get Revision\n");
	return (NULL);
}
