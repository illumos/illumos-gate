#include "lm5710.h"
#include "command.h"

/* Zeros all attn_bits/ack back to the start, along with the state and the original mask of AEU lines
 *
 * Parameters:
 * pdev      - this is the LM device
 */
static void dbg_zero_all_attn(lm_device_t *pdev)
{
	volatile struct host_def_status_block *def_sb = NULL;
	
	DbgMessage(pdev, INFORMi, "dbg_zero_all_attn() inside!\n");

    def_sb = lm_get_default_status_block(pdev);
    DbgBreakIf(!def_sb);

    def_sb->atten_status_block.attn_bits     = 0;
    def_sb->atten_status_block.attn_bits_ack = 0;
    pdev->vars.aeu_mask_attn_func            = 0x303;
    pdev->vars.attn_state                    = 0;
}

/* modifies attn_bits to '1' asserted state
 *
 * Parameters:
 * pdev      - this is the LM device
 * lines_to_assert - lines which goes up (asserted)
 */
static void dbg_assert_attn_lines(lm_device_t *pdev, u16_t lines_to_assert)
{
	volatile struct host_def_status_block *def_sb = NULL;
	
	DbgMessage1(pdev, INFORMi, "dbg_assert_attn_lines() inside! lines_to_assert:0x%x\n", lines_to_assert);

    def_sb = lm_get_default_status_block(pdev);
    DbgBreakIf(!def_sb);
    DbgBreakIf(mm_le32_to_cpu(def_sb->atten_status_block.attn_bits) & lines_to_assert);

    /*
    attns bits  line_to_assert
        1           1             -> ERROR
        1           0             -> 1
        0           0             -> 0
        0           1             -> 1
    */
    def_sb->atten_status_block.attn_bits |= mm_cpu_to_le32(lines_to_assert);
}

/* modifies attn_bits to '0' deasserted state
 *
 * Parameters:
 * pdev      - this is the LM device
 * lines_to_deassert - lines which goes down (deasserted)
 */
static void dbg_deassert_attn_lines(lm_device_t *pdev, u16_t lines_to_deassert)
{
	volatile struct host_def_status_block *def_sb = NULL;
	
	DbgMessage1(pdev, INFORMi, "dbg_deassert_attn_lines() inside! lines_to_deassert:0x%x\n", lines_to_deassert);

    def_sb = lm_get_default_status_block(pdev);
    DbgBreakIf(!def_sb);
    DbgBreakIf(~mm_le32_to_cpu(def_sb->atten_status_block.attn_bits) & lines_to_deassert);
/*
    attns bits  line_to_deassert
        1           1             -> 0
        1           0             -> 1
        0           0             -> 0
        0           1             -> ERROR
*/
    def_sb->atten_status_block.attn_bits ^= mm_cpu_to_le32(lines_to_deassert);
}

/* modifies attn_ack to '1' asserted state
 *
 * Parameters:
 * pdev      - this is the LM device
 * assert_lines_to_ack - lines for which we simulate a write of '1' to the attn_ack (asserted)
 */
static void dbg_ack_assert_attn_lines(lm_device_t *pdev, u16_t assert_lines_to_ack)
{
	volatile struct host_def_status_block *def_sb = NULL;
	
	DbgMessage1(pdev, INFORMi, "dbg_ack_assert_attn_lines() inside! assert_lines_to_ack:0x%x\n", assert_lines_to_ack);

    def_sb = lm_get_default_status_block(pdev);
    DbgBreakIf(!def_sb);
    DbgBreakIf(mm_le32_to_cpu(def_sb->atten_status_block.attn_bits_ack) & assert_lines_to_ack);
/*
    attns bits ack  assert_lines_to_ack
        1                1             -> ERROR
        1                0             -> 1
        0                0             -> 0
        0                1             -> 1
*/
    def_sb->atten_status_block.attn_bits_ack ^= mm_cpu_to_le32(assert_lines_to_ack);
}

/* modifies attn_ack to '0' deasserted state
 *
 * Parameters:
 * pdev      - this is the LM device
 * deassert_lines_to_ack - lines for which we simulate a write of '0' to the attn_ack (deasserted)
 */
/*
static void dbg_ack_deassert_attn_lines(lm_device_t *pdev, u16_t deassert_lines_to_ack)
{
	volatile struct host_def_status_block *def_sb = NULL;
	
	DbgMessage1(pdev, INFORMi, "dbg_ack_deassert_attn_lines() inside! deassert_lines_to_ack:0x%x\n", deassert_lines_to_ack);

    def_sb = lm_get_default_status_block(pdev);
    DbgBreakIf(!def_sb);
    DbgBreakIf(~def_sb->atten_status_block.attn_bits_ack & deassert_lines_to_ack);

    //attns bits ack  deassert_lines_to_ack
    //    1                1             -> 0
    //    1                0             -> 1
    //    0                0             -> 0
    //    0                1             -> ERROR

    def_sb->atten_status_block.attn_bits_ack ^= deassert_lines_to_ack;
}
*/

static void dbg_change_sb_index(lm_device_t *pdev, u8_t rss_id)
{
	volatile struct host_status_block *rss_sb	  = NULL;
	volatile struct host_def_status_block *def_sb = NULL;
	
	DbgBreakIf(!pdev || rss_id > MAX_RSS_CHAINS);
	DbgMessage(pdev, INFORMi, "dbg_change_sb_index() inside!\n");
	//this is the default status block
	if(rss_id == DEF_STATUS_BLOCK_INDEX)
	{
		def_sb = lm_get_default_status_block(pdev);
		DbgBreakIf(!def_sb);
		//increment the status index of all storms for this status block
		def_sb->c_def_status_block.status_block_index = mm_cpu_to_le16(mm_le16_to_cpu(def_sb->c_def_status_block.status_block_index) + 1);
		def_sb->u_def_status_block.status_block_index = mm_cpu_to_le16(mm_le16_to_cpu(def_sb->u_def_status_block.status_block_index) + 1);
		def_sb->x_def_status_block.status_block_index = mm_cpu_to_le16(mm_le16_to_cpu(def_sb->x_def_status_block.status_block_index) + 1);
		def_sb->t_def_status_block.status_block_index = mm_cpu_to_le16(mm_le16_to_cpu(def_sb->t_def_status_block.status_block_index) + 1);
		def_sb->atten_status_block.attn_bits_index    = mm_cpu_to_le16(mm_le16_to_cpu(def_sb->atten_status_block.attn_bits_index) + 1);

		DbgMessage6(pdev, INFORMi, "dbg_change_sb_index():sb#%d indices are now: c_def_prod_idx:%d, u_def_prod_idx:%d, x_def_prod_idx:%d, t_def_prod_idx:%d\n",
			rss_id,
			mm_le16_to_cpu(def_sb->c_def_status_block.status_block_index),
			mm_le16_to_cpu(def_sb->u_def_status_block.status_block_index), 
			mm_le16_to_cpu(def_sb->x_def_status_block.status_block_index),
			mm_le16_to_cpu(def_sb->t_def_status_block.status_block_index),
			mm_le16_to_cpu(def_sb->atten_status_block.attn_bits_index));
	}
	//it is one of the non-default status block
	else
	{
		rss_sb = lm_get_status_block(pdev, rss_id);
		DbgBreakIf(!rss_sb);
		//increment the status index of all storms for this status block
		rss_sb->c_status_block.status_block_index = mm_cpu_to_le16(mm_le16_to_cpu(rss_sb->c_status_block.status_block_index) + 1);
		rss_sb->u_status_block.status_block_index = mm_cpu_to_le16(mm_le16_to_cpu(rss_sb->u_status_block.status_block_index) + 1);

		DbgMessage3(pdev, INFORMi, "dbg_change_sb_index():sb#%d indices are now: c_rss_prod_idx:%d, u_rss_prod_idx:%d\n",
			rss_id,
			mm_le16_to_cpu(rss_sb->c_status_block.status_block_index),
			mm_le16_to_cpu(rss_sb->u_status_block.status_block_index));
	}
}

/* UM calls this in case there was a change in the default status block. 
 * This function does the work of the DPC. 
 * Parameters:
 * pdev   - this is the LM device
 * sb_idx - this is the index where the status block lies in the array under the lm_device
 */
static void dbg_def_sb_dpc(lm_device_t *pdev)
{
	u8_t is_updated               = 0;
    u32_t cnt                     = 0;
    //Attntion vars
    u32_t total_activ_to_ack      = 0;
    u32_t cnt_acks                = 0;
    u32_t activity_flg            = 0;
    u16_t lcl_attn_bits           = 0;
    u16_t lcl_attn_ack            = 0;
    u16_t asserted_proc_grps      = 0;
    u16_t deasserted_proc_grps    = 0;
    u32_t dpc_loop_cnt            = 1; //hard-coded! part of the UM device params.

	DbgBreakIf(!pdev);
	DbgMessage(pdev, INFORMi, "dbg_def_sb_dpc(): inside!\n");
	
	//check if the default status block has changed, thus have a new status index.
	//it is possible that even here, there is no difference in the index due to hw queues races(the DMA op is delayed)so bail out.
	if ((is_updated = lm_is_def_sb_updated(pdev)) == 0)
	{
		//Agreed with Shay that we don't need to ack the index in case it matches the local copy, just enable ints
		DbgMessage(pdev, INFORMi, "dbg_def_sb_dpc(): no change in status index so get out!\n");
		lm_int_ack_sb(pdev, DEF_STATUS_BLOCK_INDEX, TSTORM_ID, DEF_SB_INDEX_OF_TSTORM(pdev), IGU_INT_ENABLE, 0);	
		

		return;
	}
	for(cnt = 0; cnt < dpc_loop_cnt; cnt++)
	{
        //update the local copy of indices with the newly fresh indices values just read from the default status block
		lm_update_hc_indices(pdev, DEF_STATUS_BLOCK_INDEX, &activity_flg);

        DbgBreakIf(!(activity_flg & LM_DEF_EVENT_MASK));

        total_activ_to_ack |= activity_flg;

        //attn bits handling   
        if (activity_flg & LM_DEF_ATTN_ACTIVE)
        {
            lcl_attn_bits = 0;
            lcl_attn_ack  = 0;
            lm_get_attn_info(pdev, &lcl_attn_bits, &lcl_attn_ack);

            GET_ATTN_CHNG_GROUPS(pdev, lcl_attn_bits, lcl_attn_ack, &asserted_proc_grps, &deasserted_proc_grps);

            DbgMessage2(pdev, INFORMi, "dbg_def_sb_dpc(): asserted_proc_grps:0x%x, deasserted_proc_grps:0x%x\n", asserted_proc_grps, deasserted_proc_grps);

            if (asserted_proc_grps)
                lm_handle_assertion_processing(pdev, asserted_proc_grps);

            if (deasserted_proc_grps)
                lm_handle_deassertion_processing(pdev, deasserted_proc_grps);
        }

        if (activity_flg & LM_DEF_USTORM_ACTIVE)
        {
            //TODO: USTORM protocol indices processing processing
        }
        if (activity_flg & LM_DEF_CSTORM_ACTIVE)
        {
            //TODO: CSTORM protocol indices processing processing
        }
        activity_flg = 0;
        //if no change beneath our legs, get out.
        if ((is_updated = lm_is_def_sb_updated(pdev)) == 0)
        {
            break;
        }
	}
    //optimization to ack only the relevant parts to chip, and the last one must enable ints.
    cnt_acks = count_bits(total_activ_to_ack);

    DbgMessage2(pdev, INFORMi, "um_bdrv_def_dpc(): cnt_acks:%d, total_activ_to_ack:0x%x\n", cnt_acks, total_activ_to_ack);

    if (total_activ_to_ack & LM_DEF_ATTN_ACTIVE)
        lm_int_ack_sb(pdev, DEF_STATUS_BLOCK_INDEX, ATTENTION_ID, DEF_SB_INDEX_OF_ATTN(pdev), --cnt_acks ? IGU_INT_NOP : IGU_INT_ENABLE, 1);    

    if (total_activ_to_ack & LM_DEF_USTORM_ACTIVE)
        lm_int_ack_sb(pdev, DEF_STATUS_BLOCK_INDEX, USTORM_ID, DEF_SB_INDEX_OF_USTORM(pdev), --cnt_acks ? IGU_INT_NOP : IGU_INT_ENABLE, 1);

    if (total_activ_to_ack & LM_DEF_CSTORM_ACTIVE)
        lm_int_ack_sb(pdev, DEF_STATUS_BLOCK_INDEX, CSTORM_ID, DEF_SB_INDEX_OF_CSTORM(pdev), --cnt_acks ? IGU_INT_NOP : IGU_INT_ENABLE, 1);	

    if (total_activ_to_ack & LM_DEF_XSTORM_ACTIVE)
        lm_int_ack_sb(pdev, DEF_STATUS_BLOCK_INDEX, XSTORM_ID, DEF_SB_INDEX_OF_XSTORM(pdev), --cnt_acks ? IGU_INT_NOP : IGU_INT_ENABLE, 1);	

    if (total_activ_to_ack & LM_DEF_TSTORM_ACTIVE)
		lm_int_ack_sb(pdev, DEF_STATUS_BLOCK_INDEX, TSTORM_ID, DEF_SB_INDEX_OF_TSTORM(pdev), --cnt_acks ? IGU_INT_NOP : IGU_INT_ENABLE, 1);	

		DbgMessage(pdev, INFORMi, "dbg_def_sb_dpc(): FINISH _______________________________________________\n");
}

/* UM calls this in case there was a change in the status block. 
 * This function does the work of the DPC. 
 * Parameters:
 * pdev   - this is the LM device
 * sb_idx - this is the index where the status block lies in the array under the lm_device
 */
static void dbg_sb_dpc(lm_device_t *pdev, u8_t rss_id)
{
	u8_t is_updated               = 0;
    u32_t activity_flg            = 0;
    u32_t total_activ_to_ack      = 0;
    u32_t cnt_acks                = 0;
    u32_t cnt                     = 0;
    u32_t dpc_loop_cnt            = 1; //hardcoded! - part of original UM device params.

	DbgBreakIf(!pdev);
	DbgBreakIf(rss_id >= MAX_RSS_CHAINS);

	DbgMessage1(pdev, INFORMi, "dbg_sb_dpc(): handling RSS status block #%d\n", rss_id);

	//check if the non-default status block has changed, thus have a new status index.
	//it is possible that even here, there is no difference in the index due to hw queues races(the DMA op is delayed)so bail out.
	if ((is_updated = lm_is_sb_updated(pdev, rss_id)) == 0)
	{
		//Agreed with Shay that we don't need to ack the index in case it matches the local copy, just enable ints
		DbgMessage(pdev, INFORMi, "handle_sb(): no change is status index so get out!\n");
		lm_int_ack_sb(pdev, rss_id, CSTORM_ID, SB_INDEX_OF_CSTORM(pdev,rss_id), IGU_INT_ENABLE, 0);

		return;
	}
	for(cnt = 0; cnt < dpc_loop_cnt; cnt++)
	{
        //update the local copy of indices with the newly fresh indices values just read from the status block
		lm_update_hc_indices(pdev, rss_id, &activity_flg);

        DbgBreakIf(!(activity_flg & LM_NON_DEF_EVENT_MASK));

        total_activ_to_ack |= activity_flg;

        if (activity_flg & LM_NON_DEF_USTORM_ACTIVE)
        {
            //Check for Rx completions
    		if (lm_is_rx_completion(pdev, rss_id))  
    		{
    			//Call here service_rx_intr(pdev, rss_id);
    		}
        }

        if (activity_flg & LM_NON_DEF_CSTORM_ACTIVE)
        {
            //Check for Tx completions
    		if (lm_is_tx_completion(pdev, rss_id))  
    		{
    			//Call here service_tx_intr(pdev, rss_id);
    		}
        }
        activity_flg = 0;
		//check whether the status block has been change meanwhile, if so, lets process again
		if ((is_updated = lm_is_sb_updated(pdev, rss_id)) == 0)
        {
            break;
        }
	}
    //optimization to ack only the relevant parts to chip, and the last one must enable ints.
    cnt_acks = count_bits(total_activ_to_ack);
    DbgMessage2(pdev, INFORMi, "dbg_sb_dpc(): cnt_acks:%d, total_activ_to_ack:0x%x\n", cnt_acks, total_activ_to_ack);

    if (total_activ_to_ack & LM_NON_DEF_USTORM_ACTIVE)
        lm_int_ack_sb(pdev, rss_id, USTORM_ID, SB_INDEX_OF_USTORM(pdev,rss_id), --cnt_acks ? IGU_INT_NOP : IGU_INT_ENABLE, 1);

    if (total_activ_to_ack & LM_NON_DEF_CSTORM_ACTIVE)
        lm_int_ack_sb(pdev, rss_id, CSTORM_ID, SB_INDEX_OF_CSTORM(pdev,rss_id), --cnt_acks ? IGU_INT_NOP : IGU_INT_ENABLE, 1);

	//after all fast-path processing done, call this to enable posting pending requests to the SQ
	lm_sq_post_pending(pdev);
	DbgMessage(pdev, INFORMi, "handle_sb(): FINISH _______________________________________________\n");
}

static u8_t dbg_isr(lm_device_t *pdev, u32_t intr_status)
{
    u8_t intr_recognized;
	u8_t rss_id = 0;

    intr_recognized = FALSE;
	
	DbgBreakIf(!pdev);
	DbgMessage(pdev, INFORMi, "dbg_isr() inside!\n");

	//get the relevant status blocks for which we need to schedule the appropriate DPC 
	//please note this implicitly de-asserts the interrupt line, which must not be forgotten to be enabled via the DPC
	//the LSB(bit 0) describes the default status blocks and bit 1-16 describe the RSS non-default status blocks.
	//In case RSS not supported, everything will arrive on RSS 0, that means that lm_get_interrupt_status() 
	//will return on the maximum bit0 and bit1 toggled in that case.

    //intr_status = lm_get_interrupt_status(pdev);

	//this is not our interrupt so bail out!
	if (!intr_status) 
	{
		return intr_recognized;
	}

    //TODO: In Windows, must assure that there is only one DPC running!
	//TODO: Get the CPU number on which this ISR is running (needed for RSS)

	//go over all the status blocks updates we received from reading the single ISR/multiple DPCs register, 
	//and queue the corresponding DPCs for them.
	//Currently, RSS is not supported, but still, a scenario might occur where we need to queue both the fast-path DPC as well as 
	//the slow-path DPC
	while(intr_status)
    {
        if(intr_status & 1)
        {
			//this means that there is a change in the default sb, so queue the relevant DPC of the default sb.
			if (rss_id == 0)
			{
				//This is the interface for Xdiag. In Windows, this will be the function which will get queued 
				//within the DPC object.
				dbg_def_sb_dpc(pdev);
			}

			//take care of the non-default sb according to RSS.
			else
			{
				//(rss_id - 1) is used since the non-default sbs are located in lm_device at indices 0-15 
				dbg_sb_dpc(pdev, rss_id - 1);
			}
        }

		intr_status >>= 1;
        rss_id++;
    }

	intr_recognized = TRUE;

	DbgMessage1(pdev, INFORMi, "dbg_isr(): intr_recognized is:%s\n", intr_recognized ? "TRUE" : "FALSE");
     
    return intr_recognized;
} /* dbg_isr */


void dbg_sb_ints_test_suite(lm_device_t *pdev)
{
	u8_t index;
	volatile struct host_def_status_block *def_sb = NULL;
    def_sb = lm_get_default_status_block(pdev);

    //This part is dedicated to checking the entire status block mechanism and Interrupts API.
	//The test should change the default/non-defualt status block parameters and print as debug information
	//the whole status block fields.
	
	//print entire info of all status blocks!
	print_sb_info(pdev);
	
	//handle default status block (=DPC of status block) - nothing should happen yet!
	dbg_def_sb_dpc(pdev);
	
	//handle all rss non-default status blocks - nothing should happen yet
	for(index = 0; index < MAX_RSS_CHAINS; index++)
	{
		dbg_sb_dpc(pdev, index);
	}
	
	//now it's time to change the status index of "some" of the status block as if there
	//was a change regarding them
	for(index = 0; index <= MAX_RSS_CHAINS; index++)
	{
		//do update only for odd index status blocks and the default status block
		if((index % 2) || (index == MAX_RSS_CHAINS))
		{
			dbg_change_sb_index(pdev, index);
		}
	}
    //assert groups: 0,1
    dbg_assert_attn_lines(pdev, 0x3);
    
    //This part is hardcoded for simulating a change on the default status block(0) and RSS sb: 1,3,5,7,9,11,13,15
    dbg_isr(pdev, 0x15555);

    //now we have for groups 0,1:
    //             attn_bits: 1 1 
    //             attn_ack:  0 0
    //             mask:      0 0
    //             state:     1 1 

    //simulate as if the chip wrote 1 1 to the attn_ack
    dbg_ack_assert_attn_lines(pdev, 0x3);

    //now we have for groups 0,1:
    //             attn_bits: 1 1 
    //             attn_ack:  1 1
    //             mask:      0 0
    //             state:     1 1 

    //simulate as if due to the mask of the AEU line, 0 has arrived at the line and written by chip to attn_bits
    dbg_deassert_attn_lines(pdev, 0x3);

    //now we have for groups 0,1:
    //             attn_bits: 0 0 
    //             attn_ack:  1 1
    //             mask:      0 0
    //             state:     1 1 

    //simulate an increment of the attn producer by chip due to change in attn bits/attn_ack from monitored state.
    def_sb->atten_status_block.attn_bits_index = mm_cpu_to_le16(mm_le16_to_cpu(def_sb->atten_status_block.attn_bits_index) + 1) ;

    //Call the dbg ISR routine to simulate lines de-asserted at the default sb DPC only!
	dbg_isr(pdev, 0x1);

    //Set everything back to zero to start all over again!
    dbg_zero_all_attn(pdev);

    // **************************   Create an unacceptable state! ***************************

    //assert groups: 0,1
    dbg_assert_attn_lines(pdev, 0x3);

    //simulate as if the chip wrote 1 1 to the attn_ack
    dbg_ack_assert_attn_lines(pdev, 0x3);

    //now we have for groups 0,1:
    //             attn_bits: 1 1 
    //             attn_ack:  1 1
    //             mask:      0 0
    //             state:     0 0 

    def_sb->atten_status_block.attn_bits_index = mm_cpu_to_le16(mm_le16_to_cpu(def_sb->atten_status_block.attn_bits_index) + 1);

    dbg_isr(pdev, 0x1);
}
