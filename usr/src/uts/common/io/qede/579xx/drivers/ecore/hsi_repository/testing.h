/*
* CDDL HEADER START
*
* The contents of this file are subject to the terms of the
* Common Development and Distribution License, v.1,  (the "License").
* You may not use this file except in compliance with the License.
*
* You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
* or http://opensource.org/licenses/CDDL-1.0.
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
* Copyright 2014-2017 Cavium, Inc. 
* The contents of this file are subject to the terms of the Common Development 
* and Distribution License, v.1,  (the "License").

* You may not use this file except in compliance with the License.

* You can obtain a copy of the License at available 
* at http://opensource.org/licenses/CDDL-1.0

* See the License for the specific language governing permissions and 
* limitations under the License.
*/

#ifndef __TESTING__
#define __TESTING__ 

struct CfcLoadErrorTestParams
{
	u8 testType;
	u8 errorBits;
	__le16 reserved1;
	__le32 cid;
	__le32 tid;
	__le32 reserved2;
	u8 reserved3[96];
};


struct EngineIsolationTestDmaRequestParams
{
	__le32 dmaParams0;
#define ENGINEISOLATIONTESTDMAREQUESTPARAMS_DLENGTH_MASK          0xFFFF
#define ENGINEISOLATIONTESTDMAREQUESTPARAMS_DLENGTH_SHIFT         0
#define ENGINEISOLATIONTESTDMAREQUESTPARAMS_STINDEX_MASK          0x1FF
#define ENGINEISOLATIONTESTDMAREQUESTPARAMS_STINDEX_SHIFT         16
#define ENGINEISOLATIONTESTDMAREQUESTPARAMS_STHINT_MASK           0x3
#define ENGINEISOLATIONTESTDMAREQUESTPARAMS_STHINT_SHIFT          25
#define ENGINEISOLATIONTESTDMAREQUESTPARAMS_TPHVALID_MASK         0x7
#define ENGINEISOLATIONTESTDMAREQUESTPARAMS_TPHVALID_SHIFT        27
#define ENGINEISOLATIONTESTDMAREQUESTPARAMS_ENDIANITY_MASK        0x3
#define ENGINEISOLATIONTESTDMAREQUESTPARAMS_ENDIANITY_SHIFT       30
	__le32 dmaParams1;
#define ENGINEISOLATIONTESTDMAREQUESTPARAMS_ATC_MASK              0x7
#define ENGINEISOLATIONTESTDMAREQUESTPARAMS_ATC_SHIFT             0
#define ENGINEISOLATIONTESTDMAREQUESTPARAMS_NOSNOOP_MASK          0x1
#define ENGINEISOLATIONTESTDMAREQUESTPARAMS_NOSNOOP_SHIFT         3
#define ENGINEISOLATIONTESTDMAREQUESTPARAMS_RELAXEDORDERING_MASK  0x1
#define ENGINEISOLATIONTESTDMAREQUESTPARAMS_RELAXEDORDERING_SHIFT 4
#define ENGINEISOLATIONTESTDMAREQUESTPARAMS_ADDRTYPE_MASK         0x1
#define ENGINEISOLATIONTESTDMAREQUESTPARAMS_ADDRTYPE_SHIFT        5
#define ENGINEISOLATIONTESTDMAREQUESTPARAMS_DONETYPE_MASK         0x1
#define ENGINEISOLATIONTESTDMAREQUESTPARAMS_DONETYPE_SHIFT        6
#define ENGINEISOLATIONTESTDMAREQUESTPARAMS_WAITFOREOP_MASK       0x1
#define ENGINEISOLATIONTESTDMAREQUESTPARAMS_WAITFOREOP_SHIFT      7
#define ENGINEISOLATIONTESTDMAREQUESTPARAMS_VQID_MASK             0x1F
#define ENGINEISOLATIONTESTDMAREQUESTPARAMS_VQID_SHIFT            8
#define ENGINEISOLATIONTESTDMAREQUESTPARAMS_LAST_MASK             0x7
#define ENGINEISOLATIONTESTDMAREQUESTPARAMS_LAST_SHIFT            13
#define ENGINEISOLATIONTESTDMAREQUESTPARAMS_OFID_MASK             0xFFFF
#define ENGINEISOLATIONTESTDMAREQUESTPARAMS_OFID_SHIFT            16
	__le32 dmaParams2;
#define ENGINEISOLATIONTESTDMAREQUESTPARAMS_ADDRLO_MASK           0xFFFFFFFF
#define ENGINEISOLATIONTESTDMAREQUESTPARAMS_ADDRLO_SHIFT          0
	__le32 dmaParams3;
#define ENGINEISOLATIONTESTDMAREQUESTPARAMS_ADDRHI_MASK           0xFFFFFFFF
#define ENGINEISOLATIONTESTDMAREQUESTPARAMS_ADDRHI_SHIFT          0
	u8 immediateCount /* user should ensure that rest of the paramters agree (if needed) with the number of immediate dwords specified here */;
	u8 unusedPad8;
	__le16 unusedPad16;
	__le32 unusedPad;
	__le32 immediateDataValues[16];
};


enum EngineIsolationTestGrcAccessType
{
	GRC_ACCESS_READ=1,
	GRC_ACCESS_WRITE=2,
	MAX_ENGINEISOLATIONTESTGRCACCESSTYPE
};


struct EngineIsolationTestRequestParamsGrc
{
	__le32 reg00Value /* Value to write to register, or value read back from register */;
	u8 requestType;
	u8 unused8;
	__le16 opaqueFid;
	__le32 regField;
#define ENGINEISOLATIONTESTREQUESTPARAMSGRC_REG00ADDR_MASK  0x7FFFFF
#define ENGINEISOLATIONTESTREQUESTPARAMSGRC_REG00ADDR_SHIFT 0
#define ENGINEISOLATIONTESTREQUESTPARAMSGRC_UNUSED9_MASK    0x1FF
#define ENGINEISOLATIONTESTREQUESTPARAMSGRC_UNUSED9_SHIFT   23
	__le32 unused32;
	__le32 unusedPad[22];
};

struct EngineIsolationTestRequestParamsSdmDma
{
	__le32 hdrFields;
#define ENGINEISOLATIONTESTREQUESTPARAMSSDMDMA_LENGTH_MASK  0xFFF /* (hdr) dma hdr length */
#define ENGINEISOLATIONTESTREQUESTPARAMSSDMDMA_LENGTH_SHIFT 0
#define ENGINEISOLATIONTESTREQUESTPARAMSSDMDMA_SRC_MASK     0xF /* (hdr) dma src (type) */
#define ENGINEISOLATIONTESTREQUESTPARAMSSDMDMA_SRC_SHIFT    12
#define ENGINEISOLATIONTESTREQUESTPARAMSSDMDMA_DST_MASK     0xF /* (hdr) dma dst (type) */
#define ENGINEISOLATIONTESTREQUESTPARAMSSDMDMA_DST_SHIFT    16
#define ENGINEISOLATIONTESTREQUESTPARAMSSDMDMA_UNUSED_MASK  0xFFF /* (hdr) dma dst (type) */
#define ENGINEISOLATIONTESTREQUESTPARAMSSDMDMA_UNUSED_SHIFT 20
	__le16 address /* (hdr) Short address in DMA hdr */;
	__le16 unused16;
	struct EngineIsolationTestDmaRequestParams dmaParams;
	__le32 unused128[2];
};

struct EngineIsolationTestRequestParamsPrmDma
{
	__le32 hdr0;
#define ENGINEISOLATIONTESTREQUESTPARAMSPRMDMA_PB_MASK             0x1 /* (hdr) pbFlag */
#define ENGINEISOLATIONTESTREQUESTPARAMSPRMDMA_PB_SHIFT            0
#define ENGINEISOLATIONTESTREQUESTPARAMSPRMDMA_DIF_MASK            0x1 /* (hdr) difFlag */
#define ENGINEISOLATIONTESTREQUESTPARAMSPRMDMA_DIF_SHIFT           1
#define ENGINEISOLATIONTESTREQUESTPARAMSPRMDMA_TR_MASK             0x1 /* (hdr) tr flag */
#define ENGINEISOLATIONTESTREQUESTPARAMSPRMDMA_TR_SHIFT            2
#define ENGINEISOLATIONTESTREQUESTPARAMSPRMDMA_LDRENQTRIG_MASK     0x1 /* (hdr) ldrEnqTrigFlag */
#define ENGINEISOLATIONTESTREQUESTPARAMSPRMDMA_LDRENQTRIG_SHIFT    3
#define ENGINEISOLATIONTESTREQUESTPARAMSPRMDMA_LDRDONETRIG_MASK    0x1 /* (hdr) ldrDoneTrigFlag */
#define ENGINEISOLATIONTESTREQUESTPARAMSPRMDMA_LDRDONETRIG_SHIFT   4
#define ENGINEISOLATIONTESTREQUESTPARAMSPRMDMA_WAITYEVENT_MASK     0x1 /* (hdr) waitYeventFlag */
#define ENGINEISOLATIONTESTREQUESTPARAMSPRMDMA_WAITYEVENT_SHIFT    5
#define ENGINEISOLATIONTESTREQUESTPARAMSPRMDMA_WAITUEVENT_MASK     0x1 /* (hdr) waitUeventFlag */
#define ENGINEISOLATIONTESTREQUESTPARAMSPRMDMA_WAITUEVENT_SHIFT    6
#define ENGINEISOLATIONTESTREQUESTPARAMSPRMDMA_PTUMODE_MASK        0x1 /* (hdr) ptuMode */
#define ENGINEISOLATIONTESTREQUESTPARAMSPRMDMA_PTUMODE_SHIFT       7
#define ENGINEISOLATIONTESTREQUESTPARAMSPRMDMA_CMDLENGTH_MASK      0xFF /* (hdr) cmd length */
#define ENGINEISOLATIONTESTREQUESTPARAMSPRMDMA_CMDLENGTH_SHIFT     8
#define ENGINEISOLATIONTESTREQUESTPARAMSPRMDMA_SRC_MASK            0x7 /* (hdr) src */
#define ENGINEISOLATIONTESTREQUESTPARAMSPRMDMA_SRC_SHIFT           16
#define ENGINEISOLATIONTESTREQUESTPARAMSPRMDMA_DST_MASK            0x1 /* (hdr) dst */
#define ENGINEISOLATIONTESTREQUESTPARAMSPRMDMA_DST_SHIFT           19
#define ENGINEISOLATIONTESTREQUESTPARAMSPRMDMA_BRBNUMREL_MASK      0x3FF /* (hdr) brbNumRel */
#define ENGINEISOLATIONTESTREQUESTPARAMSPRMDMA_BRBNUMREL_SHIFT     20
#define ENGINEISOLATIONTESTREQUESTPARAMSPRMDMA_BRBSRCREADREL_MASK  0x3 /* (hdr) brbSrcReadRel */
#define ENGINEISOLATIONTESTREQUESTPARAMSPRMDMA_BRBSRCREADREL_SHIFT 30
	__le32 hdr1;
#define ENGINEISOLATIONTESTREQUESTPARAMSPRMDMA_SLENGTH_MASK        0xFF /* (hdr) slength */
#define ENGINEISOLATIONTESTREQUESTPARAMSPRMDMA_SLENGTH_SHIFT       0
#define ENGINEISOLATIONTESTREQUESTPARAMSPRMDMA_INSERTPAD_MASK      0x1 /* (hdr) insertPad */
#define ENGINEISOLATIONTESTREQUESTPARAMSPRMDMA_INSERTPAD_SHIFT     8
#define ENGINEISOLATIONTESTREQUESTPARAMSPRMDMA_REQTYPE_MASK        0x3 /* (hdr) reqType */
#define ENGINEISOLATIONTESTREQUESTPARAMSPRMDMA_REQTYPE_SHIFT       9
#define ENGINEISOLATIONTESTREQUESTPARAMSPRMDMA_UNUSED5_MASK        0x1F
#define ENGINEISOLATIONTESTREQUESTPARAMSPRMDMA_UNUSED5_SHIFT       11
#define ENGINEISOLATIONTESTREQUESTPARAMSPRMDMA_BRBOFFSET_MASK      0xFFFF /* (hdr) brbOffset */
#define ENGINEISOLATIONTESTREQUESTPARAMSPRMDMA_BRBOFFSET_SHIFT     16
	__le32 hdr2;
#define ENGINEISOLATIONTESTREQUESTPARAMSPRMDMA_BRBDEBUG_MASK       0xFFFF /* (hdr) brbDebug */
#define ENGINEISOLATIONTESTREQUESTPARAMSPRMDMA_BRBDEBUG_SHIFT      0
#define ENGINEISOLATIONTESTREQUESTPARAMSPRMDMA_BRBSTARTBLK_MASK    0xFFFF /* (hdr) brbStartBlk */
#define ENGINEISOLATIONTESTREQUESTPARAMSPRMDMA_BRBSTARTBLK_SHIFT   16
	__le32 dmaParamsPrmSpecific;
#define ENGINEISOLATIONTESTREQUESTPARAMSPRMDMA_DISCARD_MASK        0x1
#define ENGINEISOLATIONTESTREQUESTPARAMSPRMDMA_DISCARD_SHIFT       0
#define ENGINEISOLATIONTESTREQUESTPARAMSPRMDMA_PADCL_MASK          0x1
#define ENGINEISOLATIONTESTREQUESTPARAMSPRMDMA_PADCL_SHIFT         1
#define ENGINEISOLATIONTESTREQUESTPARAMSPRMDMA_UNUSED30_MASK       0x3FFFFFFF
#define ENGINEISOLATIONTESTREQUESTPARAMSPRMDMA_UNUSED30_SHIFT      2
	struct EngineIsolationTestDmaRequestParams dmaParams;
};

union EngineIsolationTestSpecific
{
	struct EngineIsolationTestRequestParamsGrc grcAccess;
	struct EngineIsolationTestRequestParamsSdmDma sdmDma;
	struct EngineIsolationTestRequestParamsPrmDma prmDma;
};

struct EngineIsolationTestRequestParams
{
	u8 testType;
	u8 status /* user should set to idle, and then keep checking as long as status remains busy */;
	__le16 unused16;
	__le32 unused32;
	union EngineIsolationTestSpecific testSpecific;
};






enum EngineIsolationTestStatusType
{
	TEST_STATUS_IDLE=0,
	TEST_STATUS_BUSY=1,
	TEST_STATUS_SUCCESS=2,
	TEST_STATUS_FAILURE=255,
	MAX_ENGINEISOLATIONTESTSTATUSTYPE
};


enum EngineIsolationTestType
{
	TEST_TYPE_SDM_GRC_ACCESS=1,
	TEST_TYPE_SDM_DMA=2,
	TEST_TYPE_PRM_DMA=3,
	MAX_ENGINEISOLATIONTESTTYPE
};


struct IntegTestDataHdr
{
	u8 opcode;
	u8 enable;
	u8 reserved[6];
};

struct LatencyMeasurementParams
{
	__le32 numMeasurements /* Number of measurements to conduct. Will be rounded down to nearest power of 2 */;
	__le32 meanMeasurement /* Average time of all measurements in 40ns units */;
	__le32 minMeasurement /* Minimum time taken in 40ns units */;
	__le32 maxMeasurement /* Maximum time taken in 40ns units */;
	__le32 delay /* Time to wait between measurements in us */;
	__le32 addrLo /* DMA address. Will be set by first PF to load */;
	__le32 addrHi /* DMA address. Will be set by first PF to load */;
	u8 pfId /* PF id. Will be set by first PF to load */;
	u8 done /* Bit indicating measurement is done */;
	u8 error /* Bit indicating there was an error during the measurement */;
	u8 reserved;
	__le32 reserved1[20];
};

struct PramParityErrorTestParams
{
	__le32 done;
	__le32 reserved;
	u8 reserved1[104];
};

struct PqTxQueuePciAccess
{
	__le32 pause;
	__le16 queueId;
	__le16 reserved0;
	u8 reserved1[104];
};

struct PfcTestParams
{
	u8 pause;
	u8 portId;
	u8 tcPauseBitmap;
	u8 reserved0[5];
	u8 reserved1[104];
};

struct QmInterfacesTestParams
{
	__le16 connection_icid;
	__le16 connection_fid;
	__le32 counter;
	__le32 dataValid;
	__le32 incomingCid;
	u8 reserved[96];
};

struct SflowTestParams
{
	u8 header[32];
	u8 headerSize;
	u8 sendFactor;
	u8 reserved[6];
	u8 reserved1[72];
};

struct IntegTestEdpmIntfEnParams
{
	u8 releaseExistInQm;
	u8 existInQmReleased;
	u8 setXoffState;
	u8 setXonState;
	u8 reserved[4];
	u8 reserved1[104];
};

struct VfcStressTestParams
{
	__le32 done;
	__le32 status;
	__le32 last_index;
	__le32 mac_filter_cnt;
	__le32 vlan_filter_cnt;
	__le32 pair_filter_cnt;
	u8 reserved[88];
};

struct UnmaskSdmTestParams
{
	u8 sdmUnmaskIntIndex /* SDM aggregative interrupt index to unmask */;
	u8 reserved[111];
};

struct QcnRlTestParams
{
	__le32 done;
	__le32 status;
	u8 rl_id;
	u8 cmd;
	__le16 val;
	__le32 repeat_cnt;
	__le32 repeat_interval_us;
	__le16 force_dcqcn_alpha;
	__le16 reserved;
	__le32 reserved1[22];
};

union IntegTestDataParams
{
	struct LatencyMeasurementParams latencyMeasurementParams;
	struct PramParityErrorTestParams pramParityErrorTestParams;
	struct PqTxQueuePciAccess pqTxQueuePciAccess;
	struct PfcTestParams pfcTestParams;
	struct QmInterfacesTestParams qmInterfacesTestParams;
	struct SflowTestParams sFlowTestParams;
	struct CfcLoadErrorTestParams cfcLoadErrorTestParams;
	struct IntegTestEdpmIntfEnParams edpmIntfEnTestParams;
	struct EngineIsolationTestRequestParams engineIsolationTestParams;
	struct VfcStressTestParams vfcStressTestParams;
	struct UnmaskSdmTestParams unmaskSdmTestParams;
	struct QcnRlTestParams qcnRlTestParams;
};

struct IntegTestData
{
	struct IntegTestDataHdr hdr;
	union IntegTestDataParams params;
};





enum IntegTestOpcodeEnum
{
	PRAM_PARITY_ERROR_RECOVERY=0,
	SDM_TCFC_AC_TEST=1,
	XY_LOADER_PCI_ERRORS_TEST=2,
	MU_LOADER_PCI_ERRORS_TEST=3,
	TM_LOADER_PCI_ERRORS_TEST=4,
	XY_LOADER_CFC_ERRORS_TEST=5,
	MU_LOADER_CFC_ERRORS_TEST=6,
	TM_LOADER_CFC_ERRORS_TEST=7,
	X_QM_PAUSE_TX_PQ_ERRORS_TEST=8,
	X_QM_UNPAUSE_TX_PQ_ERRORS_TEST=9,
	X_QM_QUEUES_PCI_ACCESS_TEST=10,
	RECORDING_HANDLER_TEST=12,
	PFC_TX_TEST=13,
	PFC_RX_PRS_TEST=14,
	PFC_RX_NIG_TEST=15,
	QM_INTERFACES_TEST=16,
	PROP_HEADER_TEST=17,
	S_FLOW_TEST=18,
	CFC_ERRORS_TEST=19,
	M_ENGINE_ISOLATION_TEST=20,
	VFC_STRESS_TEST=30,
	SDM_AGG_INT_UNMASK_TEST=31,
	CDU_VALIDATION_TEST=32,
	QCN_RL_TEST=33,
	LATENCY_MEASURMENT_TEST=34,
	MAX_INTEGTESTOPCODEENUM
};






enum QcnRlTestCmdType
{
	QCN_RL_TEST_CNM /* Simulite CNM arriveal. CNM interval and amount can be configurated. */,
	QCN_RL_TEST_PKT,
	QCN_RL_TEST_TIMER,
	QCN_RL_UNMASK_INTERRUPT,
	MAX_QCNRLTESTCMDTYPE
};







enum VfcStressTestStatusType
{
	VFC_STRESS_SUCCSES=0,
	VFC_STRESS_INIT,
	VFC_STRESS_MAC_SEARCH,
	VFC_STRESS_VLAN_SEARCH,
	VFC_STRESS_PAIR_SEARCH,
	VFC_STRESS_CLEAN,
	VFC_STRESS_MAC_NOT_FOUND,
	VFC_STRESS_MAC_NOT_SET_MTT,
	VFC_STRESS_MAC_NOT_SET_STT,
	VFC_STRESS_VLAN_NOT_FOUND,
	VFC_STRESS_VLAN_NOT_SET,
	VFC_STRESS_PAIR_NOT_FOUND,
	VFC_STRESS_PAIR_NOT_SET,
	VFC_STRESS_VLAN_CNT_NON_ZERO,
	VFC_STRESS_VFC_CNT_NON_ZERO,
	VFC_STRESS_VLAN_MOVE_FAIL,
	MAX_VFCSTRESSTESTSTATUSTYPE
};

#endif /* __TESTING__ */
