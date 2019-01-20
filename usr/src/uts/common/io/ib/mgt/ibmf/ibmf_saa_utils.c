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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/types.h>
#include <sys/kmem.h>
#include <sys/sunddi.h>
#include <sys/ib/mgt/ibmf/ibmf_saa_impl.h>
#include <sys/ib/mgt/ibmf/ibmf_saa_utils.h>

#define	IBMF_SAA_HDR_SIZE			20
#define	IBMF_SAA_DEFAULT_RID_SIZE		4
#define	IBMF_SAA_PARTITION_RID_SIZE		5
#define	IBMF_SAA_INFORMINFO_RID_SIZE		18

#define	IB_MAD_NOTICE_SIZE			80
#define	IB_MAD_CLASSPORTINFO_SIZE		72
#define	IB_MAD_INFORMINFO_SIZE			36

#define	SM_TRAP_DATA_DETAILS_SIZE		54
#define	SM_NODEINFO_SIZE			40
#define	SM_NODEDESC_SIZE			64
#define	SM_PORTINFO_SIZE			54
#define	SM_SLTOVL_SIZE				8
#define	SM_SWITCHINFO_SIZE			17
#define	SM_LINEARFDB_SIZE			64
#define	SM_RANDOMFDB_SIZE			64
#define	SM_MULTICASTFDB_SIZE			64
#define	SM_SMINFO_SIZE				21
#define	SM_GUIDINFO_SIZE			64
#define	SM_PARTITION_SIZE			64
#define	SM_VLARB_SIZE				64

#define	IBMF_SAA_NODE_RECORD_SIZE		108
#define	IBMF_SAA_PORTINFO_RECORD_SIZE		58
#define	IBMF_SAA_SLTOVL_RECORD_SIZE		16
#define	IBMF_SAA_SWITCHINFO_RECORD_SIZE		21
#define	IBMF_SAA_LINEARFDB_RECORD_SIZE		72
#define	IBMF_SAA_RANDOMFDB_RECORD_SIZE		72
#define	IBMF_SAA_MULTICASTFDB_RECORD_SIZE	72
#define	IBMF_SAA_SMINFO_RECORD_SIZE		25
#define	IBMF_SAA_INFORMINFO_RECORD_SIZE		60
#define	IBMF_SAA_LINK_RECORD_SIZE		6
#define	IBMF_SAA_GUIDINFO_RECORD_SIZE		72
#define	IBMF_SAA_SERVICE_RECORD_SIZE		176
#define	IBMF_SAA_PARTITION_RECORD_SIZE		72
#define	IBMF_SAA_PATH_RECORD_SIZE		64
#define	IBMF_SAA_VLARB_RECORD_SIZE		72
#define	IBMF_SAA_MCMEMBER_RECORD_SIZE		52
#define	IBMF_SAA_TRACE_RECORD_SIZE		46
#define	IBMF_SAA_MULTIPATH_RECORD_SIZE		24
#define	IBMF_SAA_SERVICEASSN_RECORD_SIZE	80

extern	int	ibmf_trace_level;

/* These functions have only been tested on a big-endian system */
static void ibmf_saa_classportinfo_parse_buffer(uchar_t *buffer, void *record);
static void ibmf_saa_notice_parse_buffer(uchar_t *buffer, void *record);
static void ibmf_saa_informinfo_parse_buffer(uchar_t *buffer, void *record);
static void ibmf_saa_node_record_parse_buffer(uchar_t *buffer, void *record);
static void ibmf_saa_portinfo_record_parse_buffer(uchar_t *buffer,
    void *record);
static void ibmf_saa_SLtoVLmapping_record_parse_buffer(uchar_t *buffer,
    void *record);
static void ibmf_saa_switchinfo_record_parse_buffer(uchar_t *buffer,
    void *record);
static void ibmf_saa_linearft_record_parse_buffer(uchar_t *buffer,
    void *record);
static void ibmf_saa_randomft_record_parse_buffer(uchar_t *buffer,
    void *record);
static void ibmf_saa_multicastft_record_parse_buffer(uchar_t *buffer,
    void *record);
static void ibmf_saa_sminfo_record_parse_buffer(uchar_t *buffer, void *record);
static void ibmf_saa_informinfo_record_parse_buffer(uchar_t *buffer,
    void *record);
static void ibmf_saa_link_record_parse_buffer(uchar_t *buffer, void *record);
static void ibmf_saa_guidinfo_record_parse_buffer(uchar_t *buffer,
    void *record);
static void ibmf_saa_service_record_parse_buffer(uchar_t *buffer, void *record);
static void ibmf_saa_partition_record_parse_buffer(uchar_t *buffer,
    void *record);
static void ibmf_saa_path_record_parse_buffer(uchar_t *buffer, void *record);
static void ibmf_saa_vlarb_record_parse_buffer(uchar_t *buffer, void *record);
static void ibmf_saa_mcmember_record_parse_buffer(uchar_t *buffer,
    void *record);
static void ibmf_saa_trace_record_parse_buffer(uchar_t *buffer, void *record);
static void ibmf_saa_multipath_record_parse_buffer(uchar_t *buffer,
    void *record);
static void ibmf_saa_service_assn_record_parse_buffer(uchar_t *buffer,
    void *record);

static void ibmf_saa_classportinfo_to_buf(void *record, uchar_t *buffer);
static void ibmf_saa_notice_to_buf(void *record, uchar_t *buffer);
static void ibmf_saa_informinfo_to_buf(void *record, uchar_t *buffer);
static void ibmf_saa_node_record_to_buf(void *record, uchar_t *buffer);
static void ibmf_saa_portinfo_record_to_buf(void *record, uchar_t *buffer);
static void ibmf_saa_SLtoVLmapping_record_to_buf(void *record, uchar_t *buffer);
static void ibmf_saa_switchinfo_record_to_buf(void *record, uchar_t *buffer);
static void ibmf_saa_linearft_record_to_buf(void *record, uchar_t *buffer);
static void ibmf_saa_randomft_record_to_buf(void *record, uchar_t *buffer);
static void ibmf_saa_multicastft_record_to_buf(void *record, uchar_t *buffer);
static void ibmf_saa_sminfo_record_to_buf(void *record, uchar_t *buffer);
static void ibmf_saa_informinfo_record_to_buf(void *record, uchar_t *buffer);
static void ibmf_saa_link_record_to_buf(void *record, uchar_t *buffer);
static void ibmf_saa_guidinfo_record_to_buf(void *record, uchar_t *buffer);
static void ibmf_saa_service_record_to_buf(void *record, uchar_t *buffer);
static void ibmf_saa_partition_record_to_buf(void *record, uchar_t *buffer);
static void ibmf_saa_path_record_to_buf(void *record, uchar_t *buffer);
static void ibmf_saa_vlarb_record_to_buf(void *record, uchar_t *buffer);
static void ibmf_saa_mcmember_record_to_buf(void *record, uchar_t *buffer);
static void ibmf_saa_multipath_record_to_buf(void *record, uchar_t *buffer);
static void ibmf_saa_service_assn_record_to_buf(void *record, uchar_t *buffer);

/*
 * *_record_parse_buffer functions:
 *
 * Each of these functions parses a buffer containing a single SA record.
 * The function copies the buffer into a structure taking care of any padding
 * and byte-endianness issues.  There is one function for each of the 22
 * attributes (Table 155).
 *
 * ibmf_utils_unpack_data() must be called for each structure in the structure
 * since Solaris will align the internal structure on a 64-bit boundary, even if
 * the first element is a 32-bit value.
 *
 * Input Arguments
 * buffer	pointer character array containing raw data
 *
 * Output Arguments
 * record	pointer to the SA attribute structure
 *
 * Returns	void
 */

static void
ibmf_saa_classportinfo_parse_buffer(uchar_t *buffer, void *record)
{
	ib_mad_classportinfo_t	*cpi = (ib_mad_classportinfo_t *)record;

	ibmf_utils_unpack_data("2csl2Ll2s2l2Ll2s2l", buffer,
	    IB_MAD_CLASSPORTINFO_SIZE, cpi, sizeof (ib_mad_classportinfo_t));
}

static void
ibmf_saa_notice_parse_buffer(uchar_t *buffer, void *record)
{
	ib_mad_notice_t		*notice = (ib_mad_notice_t *)record;

	ibmf_utils_unpack_data("4c3s54c2L", buffer, IB_MAD_NOTICE_SIZE,
	    notice, sizeof (ib_mad_notice_t));
}

static void
ibmf_saa_informinfo_parse_buffer(uchar_t *buffer, void *record)
{
	ib_mad_informinfo_t	*informinfo = (ib_mad_informinfo_t *)record;

	ibmf_utils_unpack_data("2L3s2c2s2l", buffer, IB_MAD_INFORMINFO_SIZE,
	    informinfo, sizeof (ib_mad_informinfo_t));
}

static void
ibmf_saa_node_record_parse_buffer(uchar_t *buffer, void *record)
{
	sa_node_record_t	*node_record = (sa_node_record_t *)record;

	/* first get record identifier information */
	ibmf_utils_unpack_data("2s", buffer, IBMF_SAA_DEFAULT_RID_SIZE,
	    node_record, 4);

	buffer += IBMF_SAA_DEFAULT_RID_SIZE;

	/* next get node info */
	ibmf_utils_unpack_data("4c3L2s2l", buffer, SM_NODEINFO_SIZE,
	    &node_record->NodeInfo, sizeof (sm_nodeinfo_t));

	buffer += SM_NODEINFO_SIZE;

	ibmf_utils_unpack_data("64c", buffer, SM_NODEDESC_SIZE,
	    &node_record->NodeDescription, sizeof (sm_nodedesc_t));
}

static void
ibmf_saa_portinfo_record_parse_buffer(uchar_t *buffer, void *record)
{

	sa_portinfo_record_t	*portinfo_record =
	    (sa_portinfo_record_t *)record;

	/* first get record identifier information */
	ibmf_utils_unpack_data("s2c", buffer, IBMF_SAA_DEFAULT_RID_SIZE,
	    portinfo_record, 4);

	buffer += IBMF_SAA_DEFAULT_RID_SIZE;

	/* next get portinfo info */
	ibmf_utils_unpack_data("LLsslss16c3s4c", buffer, SM_PORTINFO_SIZE,
	    &portinfo_record->PortInfo, sizeof (sm_portinfo_t));
}

static void
ibmf_saa_SLtoVLmapping_record_parse_buffer(uchar_t *buffer, void *record)
{

	sa_SLtoVLmapping_record_t	*SLtoVLmapping_record =
	    (sa_SLtoVLmapping_record_t *)record;

	/* first get record identifier information (plus 4 bytes reserved) */
	ibmf_utils_unpack_data("s2cl", buffer, IBMF_SAA_DEFAULT_RID_SIZE + 4,
	    SLtoVLmapping_record, 8);

	/* SLtoVL mapping has 4 reserved bytes between RID and attribute */
	buffer += IBMF_SAA_DEFAULT_RID_SIZE + 4;

	/* next get SLtoVLmapping info */
	ibmf_utils_unpack_data("8c", buffer, SM_SLTOVL_SIZE,
	    &SLtoVLmapping_record->SLtoVLMappingTable,
	    sizeof (sm_SLtoVL_mapping_table_t));
}

static void
ibmf_saa_switchinfo_record_parse_buffer(uchar_t *buffer, void *record)
{

	sa_switchinfo_record_t	*switchinfo_record =
	    (sa_switchinfo_record_t *)record;

	/* first get record identifier information */
	ibmf_utils_unpack_data("2s", buffer, IBMF_SAA_DEFAULT_RID_SIZE,
	    switchinfo_record, 4);

	buffer += IBMF_SAA_DEFAULT_RID_SIZE;

	/* next get switchinfo info */
	ibmf_utils_unpack_data("4s4c2sc", buffer, SM_SWITCHINFO_SIZE,
	    &switchinfo_record->SwitchInfo, sizeof (sm_switchinfo_t));

}

static void
ibmf_saa_linearft_record_parse_buffer(uchar_t *buffer, void *record)
{

	sa_linearft_record_t	*linearft_record =
	    (sa_linearft_record_t *)record;

	/* first get record identifier information (plus 4 bytes reserved) */
	ibmf_utils_unpack_data("2sl", buffer, IBMF_SAA_DEFAULT_RID_SIZE + 4,
	    linearft_record, 8);

	/* LFT has 4 reserved bytes between RID and attribute */
	buffer += IBMF_SAA_DEFAULT_RID_SIZE + 4;

	/* next get linearft info */
	ibmf_utils_unpack_data("64c", buffer, SM_LINEARFDB_SIZE,
	    &linearft_record->LinearFT, sizeof (sm_linear_forwarding_table_t));
}

static void
ibmf_saa_randomft_record_parse_buffer(uchar_t *buffer, void *record)
{

	sa_randomft_record_t	*randomft_record =
	    (sa_randomft_record_t *)record;

	/* first get record identifier information (plus 4 bytes reserved) */
	ibmf_utils_unpack_data("2sl", buffer, IBMF_SAA_DEFAULT_RID_SIZE + 4,
	    randomft_record, 8);

	/* RFT has 4 reserved bytes between RID and attribute */
	buffer += IBMF_SAA_DEFAULT_RID_SIZE + 4;

	/* next get randomft info */
	ibmf_utils_unpack_data("64c", buffer, SM_RANDOMFDB_SIZE,
	    &randomft_record->RandomFT, sizeof (sm_random_forwarding_table_t));
}

static void
ibmf_saa_multicastft_record_parse_buffer(uchar_t *buffer, void *record)
{

	sa_multicastft_record_t	*multicastft_record =
	    (sa_multicastft_record_t *)record;

	/* first get record identifier information (plus 4 bytes reserved) */
	ibmf_utils_unpack_data("2sl", buffer, IBMF_SAA_DEFAULT_RID_SIZE + 4,
	    multicastft_record, 8);

	/* MFT has 4 reserved bytes between RID and attribute */
	buffer += IBMF_SAA_DEFAULT_RID_SIZE + 4;

	/* next get multicastft info */
	ibmf_utils_unpack_data("32s", buffer, SM_MULTICASTFDB_SIZE,
	    &multicastft_record->MulticastFT,
	    sizeof (sm_multicast_forwarding_table_t));
}

static void
ibmf_saa_sminfo_record_parse_buffer(uchar_t *buffer, void *record)
{

	sa_sminfo_record_t	*sminfo_record =
	    (sa_sminfo_record_t *)record;

	/* first get record identifier information */
	ibmf_utils_unpack_data("2s", buffer, IBMF_SAA_DEFAULT_RID_SIZE,
	    sminfo_record, 4);

	buffer += IBMF_SAA_DEFAULT_RID_SIZE;

	/* next get sminfo info */
	ibmf_utils_unpack_data("2Llc", buffer, SM_SMINFO_SIZE,
	    &sminfo_record->SMInfo,
	    sizeof (sm_sminfo_t));
}

static void
ibmf_saa_informinfo_record_parse_buffer(uchar_t *buffer, void *record)
{

	sa_informinfo_record_t	*informinfo_record =
	    (sa_informinfo_record_t *)record;

	/* first get record identifier information */
	ibmf_utils_unpack_data("2Ls", buffer, IBMF_SAA_INFORMINFO_RID_SIZE,
	    informinfo_record, 18);

	/* InformInfo has 6 reserved bytes between RID and attribute */
	buffer += IBMF_SAA_INFORMINFO_RID_SIZE + 6;

	/* next get informinfo info */
	ibmf_utils_unpack_data("2L3s2c2s2l", buffer, IB_MAD_INFORMINFO_SIZE,
	    &informinfo_record->InformInfo,
	    sizeof (ib_mad_informinfo_t));
}

static void
ibmf_saa_link_record_parse_buffer(uchar_t *buffer, void *record)
{

	sa_link_record_t	*link_record = (sa_link_record_t *)record;

	ibmf_utils_unpack_data("s2cs", buffer, IBMF_SAA_LINK_RECORD_SIZE,
	    link_record, sizeof (sa_link_record_t));
}

static void
ibmf_saa_guidinfo_record_parse_buffer(uchar_t *buffer, void *record)
{

	sa_guidinfo_record_t	*guidinfo_record =
	    (sa_guidinfo_record_t *)record;

	/* first get record identifier information (plus 4 bytes reserved) */
	ibmf_utils_unpack_data("s2cl", buffer, IBMF_SAA_DEFAULT_RID_SIZE + 4,
	    guidinfo_record, 8);

	/* GUIDInfo has 4 reserved bytes between RID and attribute */
	buffer += IBMF_SAA_DEFAULT_RID_SIZE + 4;

	/* next get guidinfo info */
	ibmf_utils_unpack_data("8L", buffer, SM_GUIDINFO_SIZE,
	    &guidinfo_record->GUIDInfo, sizeof (sm_guidinfo_t));
}

static void
ibmf_saa_service_record_parse_buffer(uchar_t *buffer, void *record)
{

	sa_service_record_t	*service_record = (sa_service_record_t *)record;

	ibmf_utils_unpack_data("3L2sl2L64c16c8s4l2L", buffer,
	    IBMF_SAA_SERVICE_RECORD_SIZE, service_record,
	    sizeof (sa_service_record_t));
}

static void
ibmf_saa_partition_record_parse_buffer(uchar_t *buffer, void *record)
{

	sa_pkey_table_record_t	*partition_record =
	    (sa_pkey_table_record_t *)record;

	/* first get record identifier information (plus 4 bytes reserved) */
	ibmf_utils_unpack_data("2s4c", buffer, IBMF_SAA_PARTITION_RID_SIZE + 3,
	    partition_record, 8);

	/* Partition record has 3 reserved bytes between RID and attribute */
	buffer += IBMF_SAA_PARTITION_RID_SIZE + 3;

	/* next get partition info */
	ibmf_utils_unpack_data("32s",  buffer, SM_PARTITION_SIZE,
	    &partition_record->P_KeyTable, sizeof (sm_pkey_table_t));
}

static void
ibmf_saa_path_record_parse_buffer(uchar_t *buffer, void *record)
{

	sa_path_record_t	*path_record = (sa_path_record_t *)record;

	ibmf_utils_unpack_data("2l4L2sl2c2s4c", buffer,
	    IBMF_SAA_PATH_RECORD_SIZE, path_record, sizeof (sa_path_record_t));
}

static void
ibmf_saa_vlarb_record_parse_buffer(uchar_t *buffer, void *record)
{

	sa_VLarb_table_record_t	*VLarb_table_record =
	    (sa_VLarb_table_record_t *)record;

	/* first get record identifier information (plus 4 bytes reserved) */
	ibmf_utils_unpack_data("s2c", buffer, IBMF_SAA_DEFAULT_RID_SIZE + 4,
	    VLarb_table_record, 8);

	/* VLarb record has 4 reserved bytes between RID and attribute */
	buffer += IBMF_SAA_DEFAULT_RID_SIZE + 4;

	/* next get VLarb_table info */
	ibmf_utils_unpack_data("64c", buffer, SM_VLARB_SIZE,
	    &VLarb_table_record->VLArbTable,
	    sizeof (sm_VLarb_table_t));
}

static void
ibmf_saa_mcmember_record_parse_buffer(uchar_t *buffer, void *record)
{

	sa_mcmember_record_t	*mcmember_record =
	    (sa_mcmember_record_t *)record;

	ibmf_utils_unpack_data("4Lls2cs2c2l", buffer,
	    IBMF_SAA_MCMEMBER_RECORD_SIZE,
	    mcmember_record, sizeof (sa_mcmember_record_t));
}

static void
ibmf_saa_trace_record_parse_buffer(uchar_t *buffer, void *record)
{

	sa_trace_record_t	*trace_record =
	    (sa_trace_record_t *)record;

	ibmf_utils_unpack_data("Ls2c4L2c", buffer,
	    IBMF_SAA_TRACE_RECORD_SIZE,
	    trace_record, sizeof (sa_trace_record_t));
}

/*
 * ibmf_saa_multipath_record_parse_buffer:
 *
 * First unpack the standard part of the multipath record.  Then find the number
 * of gids and unpack those.  This function will probably never be called as the
 * ibmf_saa should not receive any multipath records.  It's in here for
 * completeness.
 */
static void ibmf_saa_multipath_record_parse_buffer(uchar_t *buffer,
    void *record)
{
	char			gid_str[20];
	uint16_t		num_gids;

	sa_multipath_record_t	*multipath_record =
	    (sa_multipath_record_t *)record;

	ibmf_utils_unpack_data("l2c2s14c", buffer,
	    IBMF_SAA_MULTIPATH_RECORD_SIZE, multipath_record,
	    sizeof (sa_multipath_record_t));

	num_gids = multipath_record->SGIDCount + multipath_record->DGIDCount;

	(void) sprintf(gid_str, "%dL", 2 * num_gids);

	ibmf_utils_unpack_data(gid_str, buffer + IBMF_SAA_MULTIPATH_RECORD_SIZE,
	    sizeof (ib_gid_t) * num_gids,
	    multipath_record + sizeof (sa_multipath_record_t),
	    sizeof (ib_gid_t) * num_gids);

}

static void
ibmf_saa_service_assn_record_parse_buffer(uchar_t *buffer, void *record)
{

	sa_service_assn_record_t	*service_assn_record =
	    (sa_service_assn_record_t *)record;

	ibmf_utils_unpack_data("2L64c", buffer,
	    IBMF_SAA_SERVICEASSN_RECORD_SIZE,
	    service_assn_record, sizeof (sa_service_assn_record_t));
}

void
ibmf_saa_gid_trap_parse_buffer(uchar_t *buffer, sm_trap_64_t *sm_trap_64)
{

	ibmf_utils_unpack_data("6c2L32c", buffer, SM_TRAP_DATA_DETAILS_SIZE,
	    sm_trap_64, sizeof (sm_trap_64_t));
}

void
ibmf_saa_capmask_chg_trap_parse_buffer(uchar_t *buffer,
    sm_trap_144_t *sm_trap_144)
{

	ibmf_utils_unpack_data("2cs2cl44c", buffer, SM_TRAP_DATA_DETAILS_SIZE,
	    sm_trap_144, sizeof (sm_trap_144_t));
}

void
ibmf_saa_sysimg_guid_chg_trap_parse_buffer(uchar_t *buffer,
    sm_trap_145_t *sm_trap_145)
{

	ibmf_utils_unpack_data("2cs2cL44c", buffer, SM_TRAP_DATA_DETAILS_SIZE,
	    sm_trap_145, sizeof (sm_trap_145_t));
}

/*
 * *_record_to_buf functions:
 *
 * Each of these functions copies a single SA record out of a structure and into
 * a buffer for sending on the wire.  The function will take care of any padding
 * and byte-endianness isues.  There is one function for each of the 22
 * attributes (Table 155).
 *
 * ibmf_utils_pack_data() must be called for each structure in the structure
 * since Solaris will align the internal structure on a 64-bit boundary, even if
 * the first element is a 32-bit value.
 *
 * Input Arguments
 * record	pointer to the structure to be parsed
 *
 * Output Arguments
 * buffer	pointer to array to place the data in (allocated by caller)
 *
 * Returns	void
 */

static void
ibmf_saa_classportinfo_to_buf(void *record, uchar_t *buffer)
{
	ib_mad_classportinfo_t	*cpi = (ib_mad_classportinfo_t *)record;

	ibmf_utils_pack_data("2csl2Ll2s2l2Ll2s2l",
	    cpi, sizeof (ib_mad_classportinfo_t),
	    buffer, IB_MAD_CLASSPORTINFO_SIZE);
}

static void
ibmf_saa_notice_to_buf(void *record, uchar_t *buffer)
{
	ib_mad_notice_t		*notice = (ib_mad_notice_t *)record;

	ibmf_utils_pack_data("4c3s54c2L", notice, sizeof (ib_mad_notice_t),
	    buffer, IB_MAD_NOTICE_SIZE);
}

static void
ibmf_saa_informinfo_to_buf(void *record, uchar_t *buffer)
{
	ib_mad_informinfo_t	*informinfo = (ib_mad_informinfo_t *)record;

	ibmf_utils_pack_data("2L3s2c2s2l", informinfo,
	    sizeof (ib_mad_informinfo_t), buffer, IB_MAD_INFORMINFO_SIZE);
}

static void
ibmf_saa_node_record_to_buf(void *record, uchar_t *buffer)
{

	sa_node_record_t	*node_record = (sa_node_record_t *)record;

	/* first get record identifier information */
	ibmf_utils_pack_data("2s", node_record, 4, buffer,
	    IBMF_SAA_DEFAULT_RID_SIZE);

	buffer += IBMF_SAA_DEFAULT_RID_SIZE;

	/* next get node info */
	ibmf_utils_pack_data("4c3L2s2l", &node_record->NodeInfo,
	    sizeof (sm_nodeinfo_t), buffer, SM_NODEINFO_SIZE);

	buffer += SM_NODEINFO_SIZE;

	/* next get node description */
	ibmf_utils_pack_data("64c", &node_record->NodeDescription,
	    sizeof (sm_nodedesc_t), buffer, SM_NODEDESC_SIZE);

}

static void
ibmf_saa_portinfo_record_to_buf(void *record, uchar_t *buffer)
{

	sa_portinfo_record_t	*portinfo_record =
	    (sa_portinfo_record_t *)record;

	/* first get record identifier information */
	ibmf_utils_pack_data("s2c", portinfo_record, 4, buffer,
	    IBMF_SAA_DEFAULT_RID_SIZE);

	buffer += IBMF_SAA_DEFAULT_RID_SIZE;

	/* next get portinfo info */
	ibmf_utils_pack_data("LLsslss16c3s4c",
	    &portinfo_record->PortInfo, sizeof (sm_portinfo_t), buffer,
	    SM_PORTINFO_SIZE);

}

static void
ibmf_saa_SLtoVLmapping_record_to_buf(void *record, uchar_t *buffer)
{

	sa_SLtoVLmapping_record_t	*SLtoVLmapping_record =
	    (sa_SLtoVLmapping_record_t *)record;

	/* first get record identifier information (plus 4 bytes reserved) */
	ibmf_utils_pack_data("s2cl", SLtoVLmapping_record, 8, buffer,
	    IBMF_SAA_DEFAULT_RID_SIZE + 4);

	/* SLtoVL mapping has 4 reserved bytes between RID and attribute */
	buffer += IBMF_SAA_DEFAULT_RID_SIZE + 4;

	/* next get SLtoVLmapping info */
	ibmf_utils_pack_data("8c", &SLtoVLmapping_record->SLtoVLMappingTable,
	    sizeof (sm_SLtoVL_mapping_table_t), buffer, SM_SLTOVL_SIZE);
}

static void
ibmf_saa_switchinfo_record_to_buf(void *record, uchar_t *buffer)
{

	sa_switchinfo_record_t	*switchinfo_record =
	    (sa_switchinfo_record_t *)record;

	/* first get record identifier information */
	ibmf_utils_pack_data("2s", switchinfo_record, 4, buffer,
	    IBMF_SAA_DEFAULT_RID_SIZE);

	buffer += IBMF_SAA_DEFAULT_RID_SIZE;

	/* next get switchinfo info */
	ibmf_utils_pack_data("4s4c2sc", &switchinfo_record->SwitchInfo,
	    sizeof (sm_switchinfo_t), buffer, SM_SWITCHINFO_SIZE);

}

static void
ibmf_saa_linearft_record_to_buf(void *record, uchar_t *buffer)
{

	sa_linearft_record_t	*linearft_record =
	    (sa_linearft_record_t *)record;

	/* first get record identifier information (plus 4 bytes reserved) */
	ibmf_utils_pack_data("2sl", linearft_record, 8, buffer,
	    IBMF_SAA_DEFAULT_RID_SIZE + 4);

	/* LFT has 4 reserved bytes between RID and attribute */
	buffer += IBMF_SAA_DEFAULT_RID_SIZE + 4;

	/* next get linearft info */
	ibmf_utils_pack_data("64c", &linearft_record->LinearFT,
	    sizeof (sm_linear_forwarding_table_t), buffer, SM_LINEARFDB_SIZE);
}

static void
ibmf_saa_randomft_record_to_buf(void *record, uchar_t *buffer)
{

	sa_randomft_record_t	*randomft_record =
	    (sa_randomft_record_t *)record;

	/* first get record identifier information (plus 4 bytes reserved) */
	ibmf_utils_pack_data("2sl", randomft_record, 8, buffer,
	    IBMF_SAA_DEFAULT_RID_SIZE + 4);

	/* RFT has 4 reserved bytes between RID and attribute */
	buffer += IBMF_SAA_DEFAULT_RID_SIZE + 4;

	/* next get randomft info */
	ibmf_utils_pack_data("64c", &randomft_record->RandomFT,
	    sizeof (sm_random_forwarding_table_t), buffer, SM_RANDOMFDB_SIZE);
}

static void
ibmf_saa_multicastft_record_to_buf(void *record, uchar_t *buffer)
{

	sa_multicastft_record_t	*multicastft_record =
	    (sa_multicastft_record_t *)record;

	/* first get record identifier information (plus 4 bytes reserved) */
	ibmf_utils_pack_data("2sl", multicastft_record, 8, buffer,
	    IBMF_SAA_DEFAULT_RID_SIZE + 4);

	/* MFT has 4 reserved bytes between RID and attribute */
	buffer += IBMF_SAA_DEFAULT_RID_SIZE + 4;

	/* next get multicastft info */
	ibmf_utils_pack_data("32s", &multicastft_record->MulticastFT,
	    sizeof (sm_multicast_forwarding_table_t), buffer,
	    SM_MULTICASTFDB_SIZE);
}

static void
ibmf_saa_sminfo_record_to_buf(void *record, uchar_t *buffer)
{

	sa_sminfo_record_t	*sminfo_record =
	    (sa_sminfo_record_t *)record;

	/* first get record identifier information */
	ibmf_utils_pack_data("2s", sminfo_record, 4, buffer,
	    IBMF_SAA_DEFAULT_RID_SIZE);

	buffer += IBMF_SAA_DEFAULT_RID_SIZE;

	/* next get sminfo info */
	ibmf_utils_pack_data("2Llc", &sminfo_record->SMInfo,
	    sizeof (sm_sminfo_t), buffer, SM_SMINFO_SIZE);
}

static void
ibmf_saa_informinfo_record_to_buf(void *record, uchar_t *buffer)
{

	sa_informinfo_record_t	*informinfo_record =
	    (sa_informinfo_record_t *)record;

	/* first get record identifier information */
	ibmf_utils_pack_data("2Ls", informinfo_record, 18, buffer,
	    IBMF_SAA_INFORMINFO_RID_SIZE);

	/* InformInfo has 6 reserved bytes between RID and attribute */
	buffer += IBMF_SAA_INFORMINFO_RID_SIZE + 6;

	/* next get informinfo info */
	ibmf_utils_pack_data("2L3s2c2s2l", &informinfo_record->InformInfo,
	    sizeof (ib_mad_informinfo_t), buffer, IB_MAD_INFORMINFO_SIZE);
}

static void
ibmf_saa_link_record_to_buf(void *record, uchar_t *buffer)
{

	sa_link_record_t	*link_record = (sa_link_record_t *)record;

	ibmf_utils_pack_data("s2cs", link_record,
	    sizeof (sa_link_record_t), buffer, IBMF_SAA_LINK_RECORD_SIZE);
}

static void
ibmf_saa_guidinfo_record_to_buf(void *record, uchar_t *buffer)
{

	sa_guidinfo_record_t	*guidinfo_record =
	    (sa_guidinfo_record_t *)record;

	/* first get record identifier information (plus 4 bytes reserved) */
	ibmf_utils_pack_data("s2cl", guidinfo_record,
	    8, buffer, IBMF_SAA_DEFAULT_RID_SIZE + 4);

	/* GUIDInfo has 4 reserved bytes between RID and attribute */
	buffer += IBMF_SAA_DEFAULT_RID_SIZE + 4;

	/* next get guidinfo info */
	ibmf_utils_pack_data("8L", &guidinfo_record->GUIDInfo,
	    sizeof (sm_guidinfo_t), buffer, SM_GUIDINFO_SIZE);
}

static void
ibmf_saa_service_record_to_buf(void *record, uchar_t *buffer)
{

	sa_service_record_t	*service_record = (sa_service_record_t *)record;

	ibmf_utils_pack_data("3L2sl2L64c16c8s4l2L", service_record,
	    sizeof (sa_service_record_t), buffer, IBMF_SAA_SERVICE_RECORD_SIZE);
}

static void
ibmf_saa_partition_record_to_buf(void *record, uchar_t *buffer)
{

	sa_pkey_table_record_t	*partition_record =
	    (sa_pkey_table_record_t *)record;

	/* first get record identifier information (plus 4 bytes reserved) */
	ibmf_utils_pack_data("2s4c", partition_record, 8, buffer,
	    IBMF_SAA_PARTITION_RID_SIZE	+ 3);

	/*  Partition record has 3 reserved bytes between RID and attribute */
	buffer += IBMF_SAA_PARTITION_RID_SIZE + 3;

	/* next get partition info */
	ibmf_utils_pack_data("32s", &partition_record->P_KeyTable,
	    sizeof (sm_pkey_table_t), buffer, SM_PARTITION_SIZE);
}

static void
ibmf_saa_path_record_to_buf(void *record, uchar_t *buffer)
{

	sa_path_record_t	*path_record = (sa_path_record_t *)record;

	ibmf_utils_pack_data("2l4L2sl2c2s4c", path_record,
	    sizeof (sa_path_record_t), buffer, IBMF_SAA_PATH_RECORD_SIZE);
}

static void
ibmf_saa_vlarb_record_to_buf(void *record, uchar_t *buffer)
{

	sa_VLarb_table_record_t	*VLarb_table_record =
	    (sa_VLarb_table_record_t *)record;

	/* first get record identifier information (plus 4 bytes reserved) */
	ibmf_utils_pack_data("s2c", VLarb_table_record, 8, buffer,
	    IBMF_SAA_DEFAULT_RID_SIZE + 4);

	/*  VLarb record has 4 reserved bytes between RID and attribute */
	buffer += IBMF_SAA_DEFAULT_RID_SIZE + 4;

	/* next get VLarb_table info */
	ibmf_utils_pack_data("64c", &VLarb_table_record->VLArbTable,
	    sizeof (sm_VLarb_table_t), buffer, SM_VLARB_SIZE);
}


static void
ibmf_saa_mcmember_record_to_buf(void *record, uchar_t *buffer)
{

	sa_mcmember_record_t	*mcmember_record =
	    (sa_mcmember_record_t *)record;

	ibmf_utils_pack_data("4Lls2cs2c2l", mcmember_record,
	    sizeof (sa_mcmember_record_t),
	    buffer, IBMF_SAA_MCMEMBER_RECORD_SIZE);
}

static void ibmf_saa_multipath_record_to_buf(void *record, uchar_t *buffer)
{
	char			gid_str[20];
	uint16_t		num_gids;
	sa_multipath_record_t	*multipath_record =
	    (sa_multipath_record_t *)record;

	num_gids = multipath_record->SGIDCount + multipath_record->DGIDCount;

	(void) sprintf(gid_str, "l2c2s14c%dL", 2 * num_gids);

	ibmf_utils_pack_data(gid_str, multipath_record,
	    sizeof (sa_multipath_record_t) + sizeof (ib_gid_t) * num_gids,
	    buffer,
	    IBMF_SAA_MULTIPATH_RECORD_SIZE + sizeof (ib_gid_t) * num_gids);
}

static void
ibmf_saa_service_assn_record_to_buf(void *record, uchar_t *buffer)
{

	sa_service_assn_record_t	*service_assn_record =
	    (sa_service_assn_record_t *)record;

	ibmf_utils_pack_data("2L64c", service_assn_record,
	    sizeof (sa_service_assn_record_t),
	    buffer, IBMF_SAA_SERVICEASSN_RECORD_SIZE);
}

int
ibmf_saa_utils_pack_sa_hdr(ib_sa_hdr_t *sa_hdr, void **packed_class_hdr,
    size_t *packed_class_hdr_len, int km_sleep_flag)
{

	*packed_class_hdr = kmem_zalloc(IBMF_SAA_HDR_SIZE, km_sleep_flag);
	if (*packed_class_hdr == NULL) {

		IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L1,
		    ibmf_saa_utils_pack_sa_hdr_err,
		    IBMF_TNF_ERROR, "", "ibmf_saa_utils_pack_sa_hdr: "
		    "could not allocate memory for header\n");

		return (IBMF_NO_MEMORY);
	}

	ibmf_utils_pack_data("LssL", sa_hdr, sizeof (ib_sa_hdr_t),
	    (uchar_t *)*packed_class_hdr, IBMF_SAA_HDR_SIZE);

	*packed_class_hdr_len = IBMF_SAA_HDR_SIZE;

	return (IBMF_SUCCESS);
}

int
ibmf_saa_utils_unpack_sa_hdr(void *packed_class_hdr,
    size_t packed_class_hdr_len, ib_sa_hdr_t **sa_hdr, int km_sleep_flag)
{
	if (packed_class_hdr_len != IBMF_SAA_HDR_SIZE) {

		IBMF_TRACE_3(IBMF_TNF_DEBUG, DPRINT_L1,
		    ibmf_saa_utils_unpack_sa_hdr_err,
		    IBMF_TNF_ERROR, "", "ibmf_saa_utils_unpack_sa_hdr: %s,"
		    " sa_class_hdr_len = %d, pkt_class_hdr_len = %d\n",
		    tnf_string, msg, "invalid class hdr length for SA packet",
		    tnf_int, sa_class_hdr_len, IBMF_SAA_HDR_SIZE,
		    tnf_int, pkt_class_hdr_len, packed_class_hdr_len);

		return (IBMF_REQ_INVALID);
	}

	*sa_hdr = kmem_zalloc(sizeof (ib_sa_hdr_t), km_sleep_flag);
	if (*sa_hdr == NULL) {

		IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L1,
		    ibmf_saa_utils_unpack_sa_hdr_err,
		    IBMF_TNF_ERROR, "", "ibmf_saa_utils_unpack_sa_hdr: "
		    "could not allocate memory for header\n");

		return (IBMF_NO_MEMORY);
	}

	ibmf_utils_unpack_data("LssL", (uchar_t *)packed_class_hdr,
	    IBMF_SAA_HDR_SIZE, *sa_hdr, sizeof (ib_sa_hdr_t));

	return (IBMF_SUCCESS);
}

/*
 * ibmf_saa_utils_pack_payload:
 *
 * Takes a pointer to an array of sa record structures.  For each element packs
 * the structure into a character buffer removing any padding and account for
 * endianness issues.
 *
 */
int
ibmf_saa_utils_pack_payload(uchar_t *structs_payload, size_t
    structs_payload_length, uint16_t attr_id, void **buf_payloadp,
    size_t *buf_payload_lengthp, int km_sleep_flag)
{

	int	i;
	int	struct_size, buf_size;
	int	num_records;
	void	(*pack_data_fn)(void *, uchar_t *);

	if (structs_payload_length == 0) {

		*buf_payload_lengthp = 0;
		*buf_payloadp = NULL;

		return (IBMF_SUCCESS);
	}

	ASSERT(structs_payload != NULL);

	/* trace records should never be sent (or packed) by ibmf_saa */
	ASSERT(attr_id != SA_TRACERECORD_ATTRID);

	switch (attr_id) {
		case SA_CLASSPORTINFO_ATTRID:
			struct_size = sizeof (ib_mad_classportinfo_t);
			buf_size = IB_MAD_CLASSPORTINFO_SIZE;
			pack_data_fn = ibmf_saa_classportinfo_to_buf;
			break;
		case SA_NOTICE_ATTRID:
			struct_size = sizeof (ib_mad_notice_t);
			buf_size = IB_MAD_NOTICE_SIZE;
			pack_data_fn = ibmf_saa_notice_to_buf;
			break;
		case SA_INFORMINFO_ATTRID:
			struct_size = sizeof (ib_mad_informinfo_t);
			buf_size = IB_MAD_INFORMINFO_SIZE;
			pack_data_fn = ibmf_saa_informinfo_to_buf;
			break;
		case SA_NODERECORD_ATTRID:
			struct_size = sizeof (sa_node_record_t);
			buf_size = IBMF_SAA_NODE_RECORD_SIZE;
			pack_data_fn = ibmf_saa_node_record_to_buf;
			break;
		case SA_PORTINFORECORD_ATTRID:
			struct_size = sizeof (sa_portinfo_record_t);
			buf_size = IBMF_SAA_PORTINFO_RECORD_SIZE;
			pack_data_fn = ibmf_saa_portinfo_record_to_buf;
			break;
		case SA_SLTOVLRECORD_ATTRID:
			struct_size = sizeof (sa_SLtoVLmapping_record_t);
			buf_size = IBMF_SAA_SLTOVL_RECORD_SIZE;
			pack_data_fn = ibmf_saa_SLtoVLmapping_record_to_buf;
			break;
		case SA_SWITCHINFORECORD_ATTRID:
			struct_size = sizeof (sa_switchinfo_record_t);
			buf_size = IBMF_SAA_SWITCHINFO_RECORD_SIZE;
			pack_data_fn = ibmf_saa_switchinfo_record_to_buf;
			break;
		case SA_LINEARFDBRECORD_ATTRID:
			struct_size = sizeof (sa_linearft_record_t);
			buf_size = IBMF_SAA_LINEARFDB_RECORD_SIZE;
			pack_data_fn = ibmf_saa_linearft_record_to_buf;
			break;
		case SA_RANDOMFDBRECORD_ATTRID:
			struct_size = sizeof (sa_randomft_record_t);
			buf_size = IBMF_SAA_RANDOMFDB_RECORD_SIZE;
			pack_data_fn = ibmf_saa_randomft_record_to_buf;
			break;
		case SA_MULTICASTFDBRECORD_ATTRID:
			struct_size = sizeof (sa_multicastft_record_t);
			buf_size = IBMF_SAA_MULTICASTFDB_RECORD_SIZE;
			pack_data_fn = ibmf_saa_multicastft_record_to_buf;
			break;
		case SA_SMINFORECORD_ATTRID:
			struct_size = sizeof (sa_sminfo_record_t);
			buf_size = IBMF_SAA_SMINFO_RECORD_SIZE;
			pack_data_fn = ibmf_saa_sminfo_record_to_buf;
			break;
		case SA_INFORMINFORECORD_ATTRID:
			struct_size = sizeof (sa_informinfo_record_t);
			buf_size = IBMF_SAA_INFORMINFO_RECORD_SIZE;
			pack_data_fn = ibmf_saa_informinfo_record_to_buf;
			break;
		case SA_LINKRECORD_ATTRID:
			struct_size = sizeof (sa_link_record_t);
			buf_size = IBMF_SAA_LINK_RECORD_SIZE;
			pack_data_fn = ibmf_saa_link_record_to_buf;
			break;
		case SA_GUIDINFORECORD_ATTRID:
			struct_size = sizeof (sa_guidinfo_record_t);
			buf_size = IBMF_SAA_GUIDINFO_RECORD_SIZE;
			pack_data_fn = ibmf_saa_guidinfo_record_to_buf;
			break;
		case SA_SERVICERECORD_ATTRID:
			struct_size = sizeof (sa_service_record_t);
			buf_size = IBMF_SAA_SERVICE_RECORD_SIZE;
			pack_data_fn = ibmf_saa_service_record_to_buf;
			break;
		case SA_PARTITIONRECORD_ATTRID:
			struct_size = sizeof (sa_pkey_table_record_t);
			buf_size = IBMF_SAA_PARTITION_RECORD_SIZE;
			pack_data_fn = ibmf_saa_partition_record_to_buf;
			break;
		case SA_PATHRECORD_ATTRID:
			struct_size = sizeof (sa_path_record_t);
			buf_size = IBMF_SAA_PATH_RECORD_SIZE;
			pack_data_fn = ibmf_saa_path_record_to_buf;
			break;
		case SA_VLARBRECORD_ATTRID:
			struct_size = sizeof (sa_VLarb_table_record_t);
			buf_size = IBMF_SAA_VLARB_RECORD_SIZE;
			pack_data_fn = ibmf_saa_vlarb_record_to_buf;
			break;
		case SA_MCMEMBERRECORD_ATTRID:
			struct_size = sizeof (sa_mcmember_record_t);
			buf_size = IBMF_SAA_MCMEMBER_RECORD_SIZE;
			pack_data_fn = ibmf_saa_mcmember_record_to_buf;
			break;
		case SA_MULTIPATHRECORD_ATTRID:
			/*
			 * array is of size 1 since multipath can be request
			 * only; data size greater than multipath_record_t
			 * size is due to gids at the end
			 */
			struct_size = structs_payload_length;
			buf_size = IBMF_SAA_MULTIPATH_RECORD_SIZE +
			    struct_size - sizeof (sa_multipath_record_t);
			pack_data_fn = ibmf_saa_multipath_record_to_buf;
			break;
		case SA_SERVICEASSNRECORD_ATTRID:
			struct_size = sizeof (sa_service_assn_record_t);
			buf_size = IBMF_SAA_SERVICEASSN_RECORD_SIZE;
			pack_data_fn = ibmf_saa_service_assn_record_to_buf;
			break;
		default:

			/* don't know about structure; do bcopy */
			*buf_payload_lengthp = structs_payload_length;
			*buf_payloadp = kmem_zalloc(*buf_payload_lengthp,
			    km_sleep_flag);
			if (*buf_payloadp == NULL) {

				*buf_payload_lengthp = 0;
				return (IBMF_NO_MEMORY);
			}

			bcopy(structs_payload, *buf_payloadp,
			    *buf_payload_lengthp);

			return (IBMF_SUCCESS);
	}

	*buf_payload_lengthp = structs_payload_length / struct_size * buf_size;
	num_records = structs_payload_length / struct_size;
	*buf_payloadp = kmem_zalloc(*buf_payload_lengthp, km_sleep_flag);
	if (*buf_payloadp == NULL) {

		IBMF_TRACE_2(IBMF_TNF_DEBUG, DPRINT_L1,
		    ibmf_saa_utils_pack_payload_err,
		    IBMF_TNF_ERROR, "", "ibmf_saa_utils_pack_payload: %s,"
		    " size = %d\n",
		    tnf_string, msg, "could not allocate memory for payload",
		    tnf_int, size, *buf_payload_lengthp);

		*buf_payload_lengthp = 0;
		return (IBMF_NO_MEMORY);
	}

	for (i = 0; i < num_records; i++) {

		pack_data_fn(
		    (void *)((uchar_t *)structs_payload + i * struct_size),
		    ((uchar_t *)*buf_payloadp + i * buf_size));
	}

	return (IBMF_SUCCESS);
}


/*
 * ibmf_saa_utils_unpack_payload:
 *
 * Unpacks a buffer of data received over the wire and places into an array of
 * structure in host format.
 *
 * for getResp() ibmf always reports payload length as 200 bytes
 * (MAD_SIZE - headers).  To keep the client from having to determine the actual
 * length of the one attribute (since we do it here) the is_get_resp parameter
 * indicates that there is one attribute in the buffer.
 */
int
ibmf_saa_utils_unpack_payload(uchar_t *buf_payload, size_t buf_payload_length,
    uint16_t attr_id, void **structs_payloadp, size_t *structs_payload_lengthp,
    uint16_t attr_offset, boolean_t is_get_resp, int km_sleep_flag)
{

	int	i;
	int	struct_size, buf_size;
	int	num_records;
	void	(*unpack_data_fn)(uchar_t *, void *);
	int	bytes_between_recs;

	if (buf_payload_length == 0) {

		*structs_payload_lengthp = 0;
		*structs_payloadp = NULL;

		return (IBMF_SUCCESS);
	}

	switch (attr_id) {
		case SA_CLASSPORTINFO_ATTRID:
			struct_size = sizeof (ib_mad_classportinfo_t);
			buf_size = IB_MAD_CLASSPORTINFO_SIZE;
			unpack_data_fn = ibmf_saa_classportinfo_parse_buffer;
			break;
		case SA_NOTICE_ATTRID:
			struct_size = sizeof (ib_mad_notice_t);
			buf_size = IB_MAD_NOTICE_SIZE;
			unpack_data_fn = ibmf_saa_notice_parse_buffer;
			break;
		case SA_INFORMINFO_ATTRID:
			struct_size = sizeof (ib_mad_informinfo_t);
			buf_size = IB_MAD_INFORMINFO_SIZE;
			unpack_data_fn = ibmf_saa_informinfo_parse_buffer;
			break;
		case SA_NODERECORD_ATTRID:
			struct_size = sizeof (sa_node_record_t);
			buf_size = IBMF_SAA_NODE_RECORD_SIZE;
			unpack_data_fn = ibmf_saa_node_record_parse_buffer;
			break;
		case SA_PORTINFORECORD_ATTRID:
			struct_size = sizeof (sa_portinfo_record_t);
			buf_size = IBMF_SAA_PORTINFO_RECORD_SIZE;
			unpack_data_fn = ibmf_saa_portinfo_record_parse_buffer;
			break;
		case SA_SLTOVLRECORD_ATTRID:
			struct_size = sizeof (sa_SLtoVLmapping_record_t);
			buf_size = IBMF_SAA_SLTOVL_RECORD_SIZE;
			unpack_data_fn =
			    ibmf_saa_SLtoVLmapping_record_parse_buffer;
			break;
		case SA_SWITCHINFORECORD_ATTRID:
			struct_size = sizeof (sa_switchinfo_record_t);
			buf_size = IBMF_SAA_SWITCHINFO_RECORD_SIZE;
			unpack_data_fn =
			    ibmf_saa_switchinfo_record_parse_buffer;
			break;
		case SA_LINEARFDBRECORD_ATTRID:
			struct_size = sizeof (sa_linearft_record_t);
			buf_size = IBMF_SAA_LINEARFDB_RECORD_SIZE;
			unpack_data_fn = ibmf_saa_linearft_record_parse_buffer;
			break;
		case SA_RANDOMFDBRECORD_ATTRID:
			struct_size = sizeof (sa_randomft_record_t);
			buf_size = IBMF_SAA_RANDOMFDB_RECORD_SIZE;
			unpack_data_fn = ibmf_saa_randomft_record_parse_buffer;
			break;
		case SA_MULTICASTFDBRECORD_ATTRID:
			struct_size = sizeof (sa_multicastft_record_t);
			buf_size = IBMF_SAA_MULTICASTFDB_RECORD_SIZE;
			unpack_data_fn =
			    ibmf_saa_multicastft_record_parse_buffer;
			break;
		case SA_SMINFORECORD_ATTRID:
			struct_size = sizeof (sa_sminfo_record_t);
			buf_size = IBMF_SAA_SMINFO_RECORD_SIZE;
			unpack_data_fn = ibmf_saa_sminfo_record_parse_buffer;
			break;
		case SA_INFORMINFORECORD_ATTRID:
			struct_size = sizeof (sa_informinfo_record_t);
			buf_size = IBMF_SAA_INFORMINFO_RECORD_SIZE;
			unpack_data_fn =
			    ibmf_saa_informinfo_record_parse_buffer;
			break;
		case SA_LINKRECORD_ATTRID:
			struct_size = sizeof (sa_link_record_t);
			buf_size = IBMF_SAA_LINK_RECORD_SIZE;
			unpack_data_fn = ibmf_saa_link_record_parse_buffer;
			break;
		case SA_GUIDINFORECORD_ATTRID:
			struct_size = sizeof (sa_guidinfo_record_t);
			buf_size = IBMF_SAA_GUIDINFO_RECORD_SIZE;
			unpack_data_fn = ibmf_saa_guidinfo_record_parse_buffer;
			break;
		case SA_SERVICERECORD_ATTRID:
			struct_size = sizeof (sa_service_record_t);
			buf_size = IBMF_SAA_SERVICE_RECORD_SIZE;
			unpack_data_fn = ibmf_saa_service_record_parse_buffer;
			break;
		case SA_PARTITIONRECORD_ATTRID:
			struct_size = sizeof (sa_pkey_table_record_t);
			buf_size = IBMF_SAA_PARTITION_RECORD_SIZE;
			unpack_data_fn =
			    ibmf_saa_partition_record_parse_buffer;
			break;
		case SA_PATHRECORD_ATTRID:
			struct_size = sizeof (sa_path_record_t);
			buf_size = IBMF_SAA_PATH_RECORD_SIZE;
			unpack_data_fn = ibmf_saa_path_record_parse_buffer;
			break;
		case SA_VLARBRECORD_ATTRID:
			struct_size = sizeof (sa_VLarb_table_record_t);
			buf_size = IBMF_SAA_VLARB_RECORD_SIZE;
			unpack_data_fn = ibmf_saa_vlarb_record_parse_buffer;
			break;
		case SA_MCMEMBERRECORD_ATTRID:
			struct_size = sizeof (sa_mcmember_record_t);
			buf_size = IBMF_SAA_MCMEMBER_RECORD_SIZE;
			unpack_data_fn = ibmf_saa_mcmember_record_parse_buffer;
			break;
		case SA_TRACERECORD_ATTRID:
			struct_size = sizeof (sa_trace_record_t);
			buf_size = IBMF_SAA_TRACE_RECORD_SIZE;
			unpack_data_fn = ibmf_saa_trace_record_parse_buffer;
			break;
		case SA_MULTIPATHRECORD_ATTRID:
			/*
			 * array is of size 1 since multipath can be request
			 * only; data size greater than multipath_record_t
			 * size is due to gids at the end
			 */
			buf_size = buf_payload_length;
			struct_size = sizeof (sa_multipath_record_t) +
			    buf_size - IBMF_SAA_MULTIPATH_RECORD_SIZE;
			unpack_data_fn = ibmf_saa_multipath_record_parse_buffer;
			break;
		case SA_SERVICEASSNRECORD_ATTRID:
			struct_size = sizeof (sa_service_assn_record_t);
			buf_size = IBMF_SAA_SERVICEASSN_RECORD_SIZE;
			unpack_data_fn =
			    ibmf_saa_service_assn_record_parse_buffer;
			break;
		default:
			/* don't know about structure; do bcopy */

			*structs_payload_lengthp = buf_payload_length;
			*structs_payloadp = kmem_zalloc(
			    *structs_payload_lengthp, km_sleep_flag);
			if (*structs_payloadp == NULL) {

				*structs_payload_lengthp = 0;
				return (IBMF_NO_MEMORY);
			}

			bcopy(buf_payload, *structs_payloadp,
			    *structs_payload_lengthp);

			return (IBMF_SUCCESS);
	}

	/* compute distance between successive records */
	if (attr_offset > 0) {

		if ((attr_offset * 8) < buf_size) {

			IBMF_TRACE_3(IBMF_TNF_DEBUG, DPRINT_L1,
			    ibmf_saa_utils_unpack_payload, IBMF_TNF_ERROR, "",
			    "ibmf_saa_utils_unpack_payload: %s, attr_offset = "
			    "%d, attr_size = %d\n",
			    tnf_string, msg, "attribute offset times 8 is less"
			    " than attribute size",
			    tnf_int, attr_offset, attr_offset,
			    tnf_int, attr_size, buf_size);

			return (IBMF_TRANS_FAILURE);
		}

		bytes_between_recs = attr_offset * 8;
	} else {
		bytes_between_recs = buf_size;
	}

	if (is_get_resp == B_TRUE) {

		buf_payload_length = buf_size;
		num_records = 1;
	} else {

		num_records = buf_payload_length / bytes_between_recs;
	}

	*structs_payload_lengthp = num_records * struct_size;

	*structs_payloadp = kmem_zalloc(*structs_payload_lengthp,
	    km_sleep_flag);
	if (*structs_payloadp == NULL) {

		IBMF_TRACE_2(IBMF_TNF_DEBUG, DPRINT_L1,
		    ibmf_saa_utils_unpack_payload_err,
		    IBMF_TNF_ERROR, "", "ibmf_saa_utils_unpack_payload: %s,"
		    " size = %d\n",
		    tnf_string, msg, "could not allocate memory for payload",
		    tnf_int, size, *structs_payload_lengthp);

		*structs_payload_lengthp = 0;
		return (IBMF_NO_MEMORY);
	}


	for (i = 0; i < num_records; i++) {

		unpack_data_fn(
		    (uchar_t *)buf_payload + (i * bytes_between_recs),
		    (void *)((uchar_t *)*structs_payloadp + i *
		    struct_size));
	}

	return (IBMF_SUCCESS);
}
