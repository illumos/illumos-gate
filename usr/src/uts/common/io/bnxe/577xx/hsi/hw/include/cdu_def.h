#ifndef CDU_DEF_H
#define CDU_DEF_H

#define CDU_REGION_NUMBER_XCM_AG 2
#define CDU_REGION_NUMBER_UCM_AG 4


/* String-to-compress [31:8] = CID (all 24 bits)
 * String-to-compress [7:4] = Region
 * String-to-compress [3:0] = Type
 */
#define CDU_VALID_DATA(_cid, _region, _type) (((_cid) << 8) | (((_region)&0xf)<<4) | (((_type)&0xf)))
#define CDU_CRC8(_cid, _region, _type) (calc_crc8(CDU_VALID_DATA(_cid, _region, _type), 0xff))
#define CDU_RSRVD_VALUE_TYPE_A(_cid, _region, _type) (0x80 | ((CDU_CRC8(_cid, _region, _type)) & 0x7f))
#define CDU_RSRVD_VALUE_TYPE_B(_crc, _type) (0x80 | ((_type)&0xf << 3) | ((CDU_CRC8(_cid, _region, _type)) & 0x7))
#define CDU_RSRVD_INVALIDATE_CONTEXT_VALUE(_val) ((_val) & ~0x80)

/******************************************************************************
 * Description:
 *         Calculates crc 8 on a word value: polynomial 0-1-2-8
 *         Code was translated from Verilog.
 * Return:
 *****************************************************************************/
static u8 calc_crc8(u32 data, u8 crc)
{
    u8 D[32];
    u8 NewCRC[8];
    u8 C[8];
    u8 crc_res;
    u8 i;

    /* split the data into 31 bits */
    for (i = 0; i < 32; i++) {
        D[i] = (u8)(data & 1);
        data = data >> 1;
    }

    /* split the crc into 8 bits */
    for (i = 0; i < 8; i++ ) {
        C[i] = crc & 1;
        crc = crc >> 1;
    }

    NewCRC[0] = D[31] ^ D[30] ^ D[28] ^ D[23] ^ D[21] ^ D[19] ^ D[18] ^
	    D[16] ^ D[14] ^ D[12] ^ D[8] ^ D[7] ^ D[6] ^ D[0] ^ C[4] ^
	    C[6] ^ C[7];
    NewCRC[1] = D[30] ^ D[29] ^ D[28] ^ D[24] ^ D[23] ^ D[22] ^ D[21] ^
	    D[20] ^ D[18] ^ D[17] ^ D[16] ^ D[15] ^ D[14] ^ D[13] ^
	    D[12] ^ D[9] ^ D[6] ^ D[1] ^ D[0] ^ C[0] ^ C[4] ^ C[5] ^ C[6];
    NewCRC[2] = D[29] ^ D[28] ^ D[25] ^ D[24] ^ D[22] ^ D[17] ^ D[15] ^
	    D[13] ^ D[12] ^ D[10] ^ D[8] ^ D[6] ^ D[2] ^ D[1] ^ D[0] ^
	    C[0] ^ C[1] ^ C[4] ^ C[5];
    NewCRC[3] = D[30] ^ D[29] ^ D[26] ^ D[25] ^ D[23] ^ D[18] ^ D[16] ^
	    D[14] ^ D[13] ^ D[11] ^ D[9] ^ D[7] ^ D[3] ^ D[2] ^ D[1] ^
	    C[1] ^ C[2] ^ C[5] ^ C[6];
    NewCRC[4] = D[31] ^ D[30] ^ D[27] ^ D[26] ^ D[24] ^ D[19] ^ D[17] ^
	    D[15] ^ D[14] ^ D[12] ^ D[10] ^ D[8] ^ D[4] ^ D[3] ^ D[2] ^
	    C[0] ^ C[2] ^ C[3] ^ C[6] ^ C[7];
    NewCRC[5] = D[31] ^ D[28] ^ D[27] ^ D[25] ^ D[20] ^ D[18] ^ D[16] ^
	    D[15] ^ D[13] ^ D[11] ^ D[9] ^ D[5] ^ D[4] ^ D[3] ^ C[1] ^
	    C[3] ^ C[4] ^ C[7];
    NewCRC[6] = D[29] ^ D[28] ^ D[26] ^ D[21] ^ D[19] ^ D[17] ^ D[16] ^
	    D[14] ^ D[12] ^ D[10] ^ D[6] ^ D[5] ^ D[4] ^ C[2] ^ C[4] ^ C[5];
    NewCRC[7] = D[30] ^ D[29] ^ D[27] ^ D[22] ^ D[20] ^ D[18] ^ D[17] ^
	    D[15] ^ D[13] ^ D[11] ^ D[7] ^ D[6] ^ D[5] ^ C[3] ^ C[5] ^ C[6];

    crc_res = 0;
    for (i = 0; i < 8; i++) {
        crc_res |= (NewCRC[i] << i);
    }

    return crc_res;
}

#endif //CDU_DEF_H

