#define DBU_REG_DBU_CMD                             0x0	//ACCESS:??  DataWidth:0x20
        #define DBU_CMD_ENABLE                             (1L<<0)
        #define DBU_CMD_ENABLE_BITSHIFT                    0
        #define DBU_CMD_RX_ERROR                           (1L<<1)
        #define DBU_CMD_RX_ERROR_BITSHIFT                  1
        #define DBU_CMD_RX_OVERFLOW                        (1L<<2)
        #define DBU_CMD_RX_OVERFLOW_BITSHIFT               2
#define DBU_REG_DBU_STATUS                          0x4	//ACCESS:??  DataWidth:0x20
        #define DBU_STATUS_RXDATA_VALID                    (1L<<0)
        #define DBU_STATUS_RXDATA_VALID_BITSHIFT           0
        #define DBU_STATUS_TXDATA_OCCUPIED                 (1L<<1)
        #define DBU_STATUS_TXDATA_OCCUPIED_BITSHIFT        1
#define DBU_REG_DBU_CONFIG                          0x8	//ACCESS:??  DataWidth:0x20
        #define DBU_CONFIG_TIMING_OVERRIDE                 (1L<<0)
        #define DBU_CONFIG_TIMING_OVERRIDE_BITSHIFT        0
        #define DBU_CONFIG_DEBUGSM_ENABLE                  (1L<<1)
        #define DBU_CONFIG_DEBUGSM_ENABLE_BITSHIFT         1
        #define DBU_CONFIG_CRLF_ENABLE                     (1L<<2)
        #define DBU_CONFIG_CRLF_ENABLE_BITSHIFT            2
#define DBU_REG_DBU_TIMING                          0xc	//ACCESS:??  DataWidth:0x20
        #define DBU_TIMING_FB_SMPL_OFFSET                  (0xffffL<<0)
        #define DBU_TIMING_FB_SMPL_OFFSET_BITSHIFT         0
        #define DBU_TIMING_BIT_INTERVAL                    (0xffffL<<16)
        #define DBU_TIMING_BIT_INTERVAL_BITSHIFT           16
#define DBU_REG_DBU_RXDATA                          0x10	//ACCESS:??  DataWidth:0x20
        #define DBU_RXDATA_VALUE                           (0xffL<<0)
        #define DBU_RXDATA_VALUE_BITSHIFT                  0
        #define DBU_RXDATA_ERROR                           (1L<<8)
        #define DBU_RXDATA_ERROR_BITSHIFT                  8
#define DBU_REG_DBU_TXDATA                          0x14	//ACCESS:??  DataWidth:0x20
        #define DBU_TXDATA_VALUE                           (0xffL<<0)
        #define DBU_TXDATA_VALUE_BITSHIFT                  0
#define DBU_REG_DBU_VFID_CFG                        0x18	//ACCESS:??  DataWidth:0x20
        #define DBU_VFID_CFG_VFID_VALUE                    (0x3fL<<0)
        #define DBU_VFID_CFG_VFID_VALUE_BITSHIFT           0
        #define DBU_VFID_CFG_VFID_VALID                    (1L<<16)
        #define DBU_VFID_CFG_VFID_VALID_BITSHIFT           16
        #define DBU_VFID_CFG_PATHID                        (1L<<20)
        #define DBU_VFID_CFG_PATHID_BITSHIFT               20
        #define DBU_VFID_CFG_PATH_FORCE                    (1L<<31)
        #define DBU_VFID_CFG_PATH_FORCE_BITSHIFT           31
            #define DBU_VFID_CFG_PATH_FORCE_0              (0L<<31)
            #define DBU_VFID_CFG_PATH_FORCE_0_BITSHIFT     31
            #define DBU_VFID_CFG_PATH_FORCE_1              (1L<<31)
            #define DBU_VFID_CFG_PATH_FORCE_1_BITSHIFT     31
#define DBU_REG_DBU_UNUSED_A                        0x1c	//ACCESS:??  DataWidth:0x20
#define DBU_REG_DBU_UNUSED_A_COUNT                  249
