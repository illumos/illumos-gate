#ifndef _GRC_ADDR_H
#define _GRC_ADDR_H
/*
 * This file defines GRC base address for every block.
 * This file is included by chipsim, asm microcode and cpp microcode.
 * These values are used in Design.xml on regBase attribute
 * Use the base with the generated offsets of specific registers.
 */
 
#define GRCBASE_PXPCS       0x000000  // this is the pciex core
#define GRCBASE_PCICONFIG   0x002000
#define GRCBASE_PCIREG      0x002400
#define GRCBASE_EMAC0       0x008000
#define GRCBASE_EMAC1       0x008400
#define GRCBASE_DBU	        0x008800
#define GRCBASE_PGLUE_B     0x009000
#define GRCBASE_MISC        0x00A000
#define GRCBASE_DBG	        0x00C000
#define GRCBASE_NIG	        0x010000
#define GRCBASE_XCM	        0x020000
#define GRCBASE_PRS         0x040000
#define GRCBASE_SRCH        0x040400
#define GRCBASE_TSDM        0x042000  //Note: regBase is made to fit in 20 bits, for TsdmTB::GrcCmd test			
#define GRCBASE_TCM	        0x050000
#define GRCBASE_BRB1        0x060000
#define GRCBASE_MCP	        0x080000
#define GRCBASE_UPB	        0x0C1000
#define GRCBASE_CSDM        0x0C2000
#define GRCBASE_USDM        0x0C4000
#define GRCBASE_CCM	        0x0D0000
#define GRCBASE_UCM	        0x0E0000
#define GRCBASE_CDU	        0x101000
#define GRCBASE_DMAE        0x102000
#define GRCBASE_PXP	        0x103000  // we have 2 pxp blocks now
#define GRCBASE_CFC	        0x104000
#define GRCBASE_HC	        0x108000
#define GRCBASE_ATC	        0x110000
#define GRCBASE_PXP2        0x120000  // this is the 2nd pxp
#define GRCBASE_IGU         0x130000
#define GRCBASE_PBF         0x140000
#define GRCBASE_UMAC0       0x160000
#define GRCBASE_UMAC1       0x160400
#define GRCBASE_XPB         0x161000  // pbf_pb
#define GRCBASE_MSTAT0      0x162000
#define GRCBASE_MSTAT1      0x162800
#define GRCBASE_XMAC0       0x163000
#define GRCBASE_XMAC1       0x163800
#define GRCBASE_TIMERS      0x164000
#define GRCBASE_XSDM        0x166000
#define GRCBASE_QM	        0x168000
#define GRCBASE_QM_4PORT    0x168000 // a dummy block for generating 4-port-specific QM init values
#define GRCBASE_DQ	        0x170000
#define GRCBASE_TSEM        0x180000 // was previously GRCBASE_TSTORM 		
#define GRCBASE_CSEM        0x200000 // was previously GRCBASE_CSTORM		
#define GRCBASE_XSEM        0x280000 // was previously GRCBASE_XSTORM 		
#define GRCBASE_XSEM_4PORT  0x280000 // a dummy block for generating 4-port-specific XSEM init values
#define GRCBASE_USEM        0x300000 // was previously GRCBASE_USTORM		
#define GRCBASE_MCP_A       0x380000
#define GRCBASE_MISC_AEU    GRCBASE_MISC // just for driver init  
#define GRCBASE_Tstorm      GRCBASE_TSEM
#define GRCBASE_Cstorm      GRCBASE_CSEM
#define GRCBASE_Xstorm      GRCBASE_XSEM
#define GRCBASE_Ustorm      GRCBASE_USEM


#endif //_GRC_ADRR_H

