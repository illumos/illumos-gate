#ifndef IGU_DEFS_H
#define IGU_DEFS_H

#define IGU_FUNC_BASE			0x0400

#define IGU_ADDR_MSIX			0x0000
#define IGU_ADDR_INT_ACK		0x0200
#define IGU_ADDR_PROD_UPD		0x0201
#define IGU_ADDR_ATTN_BITS_UPD	0x0202
#define IGU_ADDR_ATTN_BITS_SET	0x0203
#define IGU_ADDR_ATTN_BITS_CLR	0x0204
#define IGU_ADDR_COALESCE_NOW	0x0205
#define IGU_ADDR_SIMD_MASK		0x0206
#define IGU_ADDR_SIMD_NOMASK	0x0207
#define IGU_ADDR_MSI_CTL		0x0210
#define IGU_ADDR_MSI_ADDR_LO	0x0211
#define IGU_ADDR_MSI_ADDR_HI	0x0212
#define IGU_ADDR_MSI_DATA		0x0213


#define IGU_USE_REGISTER_ustorm_type_0_sb_cleanup  0
#define IGU_USE_REGISTER_ustorm_type_1_sb_cleanup  1
#define IGU_USE_REGISTER_cstorm_type_0_sb_cleanup  2
#define IGU_USE_REGISTER_cstorm_type_1_sb_cleanup  3

#define COMMAND_REG_INT_ACK         0x0      
#define COMMAND_REG_PROD_UPD        0x4
#define COMMAND_REG_ATTN_BITS_UPD   0x8
#define COMMAND_REG_ATTN_BITS_SET   0xc
#define COMMAND_REG_ATTN_BITS_CLR   0x10
#define COMMAND_REG_COALESCE_NOW    0x14
#define COMMAND_REG_SIMD_MASK       0x18
#define COMMAND_REG_SIMD_NOMASK     0x1c


// Memory addresses on the BAR for the IGU Sub Block
#define IGU_MEM_BASE						0x0000

#define IGU_MEM_MSIX_BASE					0x0000
#define IGU_MEM_MSIX_UPPER					0x007f
#define IGU_MEM_MSIX_RESERVED_UPPER			0x01ff

#define IGU_MEM_PBA_MSIX_BASE				0x0200
#define IGU_MEM_PBA_MSIX_UPPER				0x0200

#define IGU_CMD_BACKWARD_COMP_PROD_UPD		0x0201
#define IGU_MEM_PBA_MSIX_RESERVED_UPPER		0x03ff

#define IGU_CMD_INT_ACK_BASE				0x0400
#define IGU_CMD_INT_ACK_UPPER				(IGU_CMD_INT_ACK_BASE + MAX_SB_PER_PATH - 1)
#define IGU_CMD_INT_ACK_RESERVED_UPPER		0x04ff

#define IGU_CMD_E2_PROD_UPD_BASE			0x0500
#define IGU_CMD_E2_PROD_UPD_UPPER			(IGU_CMD_E2_PROD_UPD_BASE + MAX_SB_PER_PATH  - 1)
#define IGU_CMD_E2_PROD_UPD_RESERVED_UPPER	0x059f

#define IGU_CMD_ATTN_BIT_UPD_UPPER			0x05a0
#define IGU_CMD_ATTN_BIT_SET_UPPER			0x05a1
#define IGU_CMD_ATTN_BIT_CLR_UPPER			0x05a2

#define IGU_REG_SISR_MDPC_WMASK_UPPER		0x05a3
#define IGU_REG_SISR_MDPC_WMASK_LSB_UPPER	0x05a4
#define IGU_REG_SISR_MDPC_WMASK_MSB_UPPER	0x05a5
#define IGU_REG_SISR_MDPC_WOMASK_UPPER		0x05a6


#define IGU_REG_RESERVED_UPPER				0x05ff

#define IGU_SEG_IDX_ATTN	2
#define IGU_SEG_IDX_DEFAULT	1
/* Fields of IGU PF CONFIGRATION REGISTER */
#define IGU_PF_CONF_FUNC_EN       (0x1<<0)  /* function enable        */
#define IGU_PF_CONF_MSI_MSIX_EN   (0x1<<1)  /* MSI/MSIX enable        */
#define IGU_PF_CONF_INT_LINE_EN   (0x1<<2)  /* INT enable             */
#define IGU_PF_CONF_ATTN_BIT_EN   (0x1<<3)  /* attention enable       */
#define IGU_PF_CONF_SINGLE_ISR_EN (0x1<<4)  /* single ISR mode enable */
#define IGU_PF_CONF_SIMD_MODE     (0x1<<5)  /* simd all ones mode     */

/* Fields of IGU VF CONFIGRATION REGISTER */
#define IGU_VF_CONF_FUNC_EN        (0x1<<0)  /* function enable        */
#define IGU_VF_CONF_MSI_MSIX_EN    (0x1<<1)  /* MSI/MSIX enable        */
#define IGU_VF_CONF_PARENT_MASK    (0x3<<2)  /* Parent PF              */
#define IGU_VF_CONF_PARENT_SHIFT   2         /* Parent PF              */
#define IGU_VF_CONF_SINGLE_ISR_EN  (0x1<<4)  /* single ISR mode enable */


#define IGU_BC_DSB_NUM_SEGS    5
#define IGU_BC_NDSB_NUM_SEGS   2
#define IGU_NORM_DSB_NUM_SEGS  2
#define IGU_NORM_NDSB_NUM_SEGS 1
#define IGU_BC_BASE_DSB_PROD   128
#define IGU_NORM_BASE_DSB_PROD 136

/* FID (if VF - [6] = 0; [5:0] = VF number; if PF - [6] = 1; [5:2] = 0; [1:0] = PF number) */
#define IGU_FID_ENCODE_IS_PF        (0x1<<6)
#define IGU_FID_ENCODE_IS_PF_SHIFT  6
#define IGU_FID_VF_NUM_MASK         (0x3f)
#define IGU_FID_PF_NUM_MASK         (0x7)

#define IGU_REG_MAPPING_MEMORY_VALID            (1<<0)
#define IGU_REG_MAPPING_MEMORY_VECTOR_MASK      (0x3F<<1)
#define IGU_REG_MAPPING_MEMORY_VECTOR_SHIFT     1
#define IGU_REG_MAPPING_MEMORY_FID_MASK         (0x7F<<7)
#define IGU_REG_MAPPING_MEMORY_FID_SHIFT        7

#endif //IGU_DEFS_H

