/*******************************************************************************
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
 *
 * Copyright 2014 QLogic Corporation
 * The contents of this file are subject to the terms of the
 * QLogic End User License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the License at
 * http://www.qlogic.com/Resources/Documents/DriverDownloadHelp/
 * QLogic_End_User_Software_License.txt
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 *
 * Module Description:
 *      This file contains general LM utility functions
 *
 ******************************************************************************/

#include "lm5710.h"

#ifdef _VBD_CMD_
#include "everest_sim.h"
#endif

#define MASK_01010101 (((unsigned int)(-1))/3)
#define MASK_00110011 (((unsigned int)(-1))/5)
#define MASK_00001111 (((unsigned int)(-1))/17)

u32_t count_bits(u32_t n)
{
    n = (n & MASK_01010101) + ((n >> 1) & MASK_01010101) ;
    n = (n & MASK_00110011) + ((n >> 2) & MASK_00110011) ;
    n = (n & MASK_00001111) + ((n >> 4) & MASK_00001111) ;

    return n % 255 ;
}

unsigned long log2_align(unsigned long n)
{
    unsigned long ret = n ? 1 : 0;
    unsigned long _n  = n >> 1;

    while (_n)
    {
        _n >>= 1;
        ret <<= 1;
    }

    if (ret < n)
        ret <<= 1;

    return ret;
}
/**
 * @description
 * Should be moved to a common file.
 * Calculates the lower align of power 2.
 * Values lower than 0 are returned directly.
 * @param n
 *
 * @return unsigned long
 * lower align of power 2.
 */
unsigned long power2_lower_align(unsigned long n)
{
    unsigned long ret = 0;
    if(0 == n)
    {
        return 0;
    }

    if(TRUE == POWER_OF_2(n))
    {
        // The number is already a power of 2.
        return n;
    }

    //Calculates the lower align of power 2.
    ret = log2_align(n);
    DbgBreakIf(FALSE == POWER_OF_2(ret));
    ret >>= 1;

    return ret;
}
/*
Log2
this function calculates rounded LOG2 of a certain number
e.g.: LOG2(1080) = 10 (2^10=1024)
*/
u32_t LOG2(u32_t v){
    u32_t r=0;
    while (v >>= 1) {
        r++;
    }
    return r;
}

/**
 * @description
 *  Should be moved to a common place.
 *  Find the next power of 2 that is larger than "num".
 * @param num - The variable to find a power of 2 that is
 *            larger.
 * @param num_bits_supported - The largest number of bits
 *                           supported
 *
 * @return u32_t - The next power of 2 that is larger than
 *         "num".
 */
u32_t
upper_align_power_of_2(IN const u16_t num,
                       IN const u8_t num_bits_supported)
{
    u32_t const largest_power_of_2 = 1 << (num_bits_supported - 1);
    u32_t prev_power_of_2 = largest_power_of_2;
    u32_t cur_power_of_2 = 0;
    u8_t  i = 0;

    //This is not realy needed (the for also handles this case) but to avoide confusing
    if(num >= largest_power_of_2)
    {
        DbgBreakMsg("num is larger than num_bits_supported");
        return largest_power_of_2;
    }
    // Exception case
    if(0 == num)
    {
        return 1;
    }

    // Look for a value that is smaller than prev_power_of_2 and bigger than cur_power_of_2
    for (i = (num_bits_supported - 1) ; i != 0 ;i--)
    {
        cur_power_of_2 = 1 << (i);
        if(num > cur_power_of_2)
        {
            break;
        }
        prev_power_of_2 = cur_power_of_2;
    }
    return prev_power_of_2;
}

/**
 * General function that waits for a certain state to change,
 * not protocol specific. It takes into account vbd-commander
 * and reset-is-in-progress
 *
 * @param pdev
 * @param curr_state -> what to poll on
 * @param new_state -> what we're waiting for
 *
 * @return lm_status_t TIMEOUT if state didn't change, SUCCESS
 *         otherwise
 */


/**
 * @param pdev
 *
 * @return 0 if device is ASIC.
 */
int lm_chip_is_slow(struct _lm_device_t *pdev)
{
    u32_t val = 0;

    lm_reg_rd_ind(pdev, MISC_REG_CHIP_REV, &val);

    val = (val & 0xf) << 12;

    if (val > CHIP_REV_Cx) {
        DbgMessage(pdev, VERBOSEi, "Chip is slow\n");
        return 1;
    } else {
        return 0;
    }
}

lm_status_t lm_wait_state_change(struct _lm_device_t *pdev, volatile u32_t * curr_state, u32_t new_state)
{
    u32_t delay_us = 0;
    u32_t to_cnt   = 10000 + 2360; // We'll wait 10,000 times 100us (1 second) + 2360 times 25000us (59sec) = total 60 sec
                                                                    // (Winodws only note) the 25000 wait will cause wait to be without CPU stall (look in win_util.c)
    lm_status_t lm_status = LM_STATUS_SUCCESS;


#ifdef _VBD_CMD_
    if (!GET_FLAGS(*g_everest_sim_flags_ptr, EVEREST_SIM_RAMROD))
    {
        *curr_state = new_state;
        return lm_status;
    }
#endif


    /* wait for state change */
    while ((*curr_state != new_state) && to_cnt--)
    {
        delay_us = (to_cnt >= 2360) ? 100 : 25000 ;
        mm_wait(pdev, delay_us);

        #ifdef DOS
            sleep(0); // rescheduling threads, since we don't have a memory barrier.
        #elif defined(__LINUX)
            mm_read_barrier(); // synchronize on eth_con->con_state
        #endif

        // in case reset in progress
        // we won't get completion so no need to wait
        if( lm_reset_is_inprogress(pdev) )
        {
            lm_status = LM_STATUS_ABORTED;
            break;
        }
    }

    if ( *curr_state != new_state)
    {
        DbgMessage(pdev, FATAL,
                    "lm_wait_state_change: state change timeout, curr state=%d, expected new state=%d!\n",
                    *curr_state, new_state);
        if (!lm_reset_is_inprogress(pdev)) {
            #if defined(_VBD_)
            DbgBreak();
            #endif
            lm_status = LM_STATUS_TIMEOUT;
        }
    }

    return lm_status;
}

/*******************************************************************************
 * Description:
 *         Calculates crc 32 on a buffer
 *         Note: crc32_length MUST be aligned to 8
 * Return:
 ******************************************************************************/
u32_t calc_crc32( u8_t* crc32_packet, u32_t crc32_length, u32_t crc32_seed, u8_t complement)
{
   u32_t byte             = 0 ;
   u32_t bit              = 0 ;
   u8_t  msb              = 0 ; // 1
   u32_t temp             = 0 ;
   u32_t shft             = 0 ;
   u8_t  current_byte     = 0 ;
   u32_t crc32_result     = crc32_seed;
   const u32_t CRC32_POLY = 0x1edc6f41;
    if( CHK_NULL( crc32_packet) || ERR_IF( 0 == crc32_length ) || ERR_IF( 0 != ( crc32_length % 8 ) ) )
    {
        return crc32_result ;
    }
    for (byte = 0; byte < crc32_length; byte = byte + 1)
    {
        current_byte = crc32_packet[byte];
        for (bit = 0; bit < 8; bit = bit + 1)
        {
            msb = (u8_t)(crc32_result >> 31) ; // msb = crc32_result[31];
            crc32_result = crc32_result << 1;
            if ( msb != ( 0x1 & (current_byte>>bit)) ) // (msb != current_byte[bit])
            {
               crc32_result = crc32_result ^ CRC32_POLY;
               crc32_result |= 1 ;//crc32_result[0] = 1;
            }
         }
      }
      // Last step is to "mirror" every bit, swap the 4 bytes, and then complement each bit.
      //
      // Mirror:
      temp = crc32_result ;
      shft = sizeof(crc32_result) * 8 -1 ;
      for( crc32_result>>= 1; crc32_result; crc32_result>>= 1 )
      {
        temp <<= 1;
        temp  |= crc32_result & 1;
        shft-- ;
      }
      temp <<= shft ;
      //temp[31-bit] = crc32_result[bit];
      // Swap:
      // crc32_result = {temp[7:0], temp[15:8], temp[23:16], temp[31:24]};
      {
          u32_t t0, t1, t2, t3 ;
          t0 = ( ( 0x000000ff ) & ( temp >> 24 ) ) ; // temp >> 24 ;
          t1 = ( ( 0x0000ff00 ) & ( temp >> 8 ) ) ;
          t2 = ( ( 0x00ff0000 ) & ( temp << 8 ) ) ;
          t3 = ( ( 0xff000000 ) & ( temp << 24 ) ) ;
          crc32_result = t0 | t1 | t2 | t3 ;
      }
      // Complement:
      if (complement)
      {
          crc32_result = ~crc32_result ;
      }
      return crc32_result  ;
}

/**
 *  @brief: convert 4 bytes version into 32 bit BCD formatted version
 *
 *  1. Format the product_version string:
 *     a. The "Major, "Minor, "Build and "Sub build" bytes are BCD-encoded, and each byte holds two BCD digits.
 *     b. The semantics of these fields follow the semantics specified in DSP4004.
 *     c. The value 0xF in the most-significant nibble of a BCD-encoded value indicates that the most significant nibble should be ignored and the overall field treated as a single digit value.
 *     d. A value of 0xFF indicates that the entire field is not present. 0xFF is not allowed as a value for the fields.
 *     Example: Version 3.7.10.FF --> 0xF3F710FF
 *

 * @param[in] CONST u8_t IN ver_arr[4]
 *
 * @return u32_t value
 */
u32_t
convert_to_bcd( const u8_t IN ver_arr[4] )
{
    u32_t                 ver_32             = 0xffffffff;
    u8_t                  idx                = 0;
    u8_t                  ver_current        = 0;

    if ( ver_arr )
    {
        ver_32 = 0;

        // convert to BCD format
        // We have for sure 4 digits only
        // ARRSIZE(ver_arr) won't work here since in non x86 compile it is NOT 4....
        for( idx = 0; idx < 4; idx++ )
        {
            ver_current = ver_arr[idx];
            if ( 0 == ( ver_current & 0xf0 ) )
            {
                ver_current |= 0xf0 ;
            }
            ver_32 =  ( ver_32<<8 ) | ver_current ;
        }
    }

    return ver_32;
}
