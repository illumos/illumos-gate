



#include "lm5710.h"
#include "init_defs.h"

/* Vnics per mode */
#define ECORE_PORT2_MODE_NUM_VNICS 4


/* QM queue numbers */
#define ECORE_ETH_Q		0
#define ECORE_TOE_Q		3
#define ECORE_TOE_ACK_Q		6
#define ECORE_ISCSI_Q		9
#define ECORE_ISCSI_ACK_Q	11
#define ECORE_FCOE_Q		10

/* Vnics per mode */
#define ECORE_PORT4_MODE_NUM_VNICS 2

/* COS offset for port1 in E3 B0 4port mode */
#define ECORE_E3B0_PORT1_COS_OFFSET 3

/* QM Register addresses */
#define ECORE_Q_VOQ_REG_ADDR(pf_q_num)\
	(QM_REG_QVOQIDX_0 + 4 * (pf_q_num))
#define ECORE_VOQ_Q_REG_ADDR(cos, pf_q_num)\
	(QM_REG_VOQQMASK_0_LSB + 4 * ((cos) * 2 + ((pf_q_num) >> 5)))
#define ECORE_Q_CMDQ_REG_ADDR(pf_q_num)\
	(QM_REG_BYTECRDCMDQ_0 + 4 * ((pf_q_num) >> 4))

/* extracts the QM queue number for the specified port and vnic */
#define ECORE_PF_Q_NUM(q_num, port, vnic)\
	((((port) << 1) | (vnic)) * 16 + (q_num))


/* Maps the specified queue to the specified COS */
void ecore_map_q_cos(struct _lm_device_t *pdev, u32_t q_num, u32_t new_cos)
{
	/* find current COS mapping */
	u32_t curr_cos = REG_RD(pdev, QM_REG_QVOQIDX_0 + q_num * 4);

	/* check if queue->COS mapping has changed */
	if (curr_cos != new_cos) {
		u32_t num_vnics = ECORE_PORT2_MODE_NUM_VNICS;
		u32_t reg_addr, reg_bit_map, vnic;

		/* update parameters for 4port mode */
		if (INIT_MODE_FLAGS(pdev) & MODE_PORT4) {
			num_vnics = ECORE_PORT4_MODE_NUM_VNICS;
			if (PORT_ID(pdev)) {
				curr_cos += ECORE_E3B0_PORT1_COS_OFFSET;
				new_cos += ECORE_E3B0_PORT1_COS_OFFSET;
			}
		}

		/* change queue mapping for each VNIC */
		for (vnic = 0; vnic < num_vnics; vnic++) {
			u32_t pf_q_num =
				ECORE_PF_Q_NUM(q_num, PORT_ID(pdev), vnic);
			u32_t q_bit_map = 1 << (pf_q_num & 0x1f);

			/* overwrite queue->VOQ mapping */
			REG_WR(pdev, ECORE_Q_VOQ_REG_ADDR(pf_q_num), new_cos);

			/* clear queue bit from current COS bit map */
			reg_addr = ECORE_VOQ_Q_REG_ADDR(curr_cos, pf_q_num);
			reg_bit_map = REG_RD(pdev, reg_addr);
			REG_WR(pdev, reg_addr, reg_bit_map & (~q_bit_map));

			/* set queue bit in new COS bit map */
			reg_addr = ECORE_VOQ_Q_REG_ADDR(new_cos, pf_q_num);
			reg_bit_map = REG_RD(pdev, reg_addr);
			REG_WR(pdev, reg_addr, reg_bit_map | q_bit_map);

			/* set/clear queue bit in command-queue bit map
			(E2/E3A0 only, valid COS values are 0/1) */
			if (!(INIT_MODE_FLAGS(pdev) & MODE_E3_B0)) {
				reg_addr = ECORE_Q_CMDQ_REG_ADDR(pf_q_num);
				reg_bit_map = REG_RD(pdev, reg_addr);
				q_bit_map = 1 << (2 * (pf_q_num & 0xf));
				reg_bit_map = new_cos ?
					      (reg_bit_map | q_bit_map) :
					      (reg_bit_map & (~q_bit_map));
				REG_WR(pdev, reg_addr, reg_bit_map);
			}
		}
	}
}

/* Configures the QM according to the specified per-traffic-type COSes */
void ecore_dcb_config_qm(struct _lm_device_t *pdev, enum cos_mode mode,
				       struct priority_cos *traffic_cos)
{
	ecore_map_q_cos(pdev, ECORE_FCOE_Q,
			traffic_cos[LLFC_TRAFFIC_TYPE_FCOE].cos);
	ecore_map_q_cos(pdev, ECORE_ISCSI_Q,
			traffic_cos[LLFC_TRAFFIC_TYPE_ISCSI].cos);
	ecore_map_q_cos(pdev, ECORE_ISCSI_ACK_Q,
		traffic_cos[LLFC_TRAFFIC_TYPE_ISCSI].cos);
	if (mode != STATIC_COS) {
		/* required only in OVERRIDE_COS mode */
		ecore_map_q_cos(pdev, ECORE_ETH_Q,
				traffic_cos[LLFC_TRAFFIC_TYPE_NW].cos);
		ecore_map_q_cos(pdev, ECORE_TOE_Q,
				traffic_cos[LLFC_TRAFFIC_TYPE_NW].cos);
		ecore_map_q_cos(pdev, ECORE_TOE_ACK_Q,
				traffic_cos[LLFC_TRAFFIC_TYPE_NW].cos);
	}
}


/*
 * congestion managment port init api description
 * the api works as follows:
 * the driver should pass the cmng_init_input struct, the port_init function
 * will prepare the required internal ram structure which will be passed back
 * to the driver (cmng_init) that will write it into the internal ram.
 *
 * IMPORTANT REMARKS:
 * 1. the cmng_init struct does not represent the contiguous internal ram
 *    structure. the driver should use the XSTORM_CMNG_PERPORT_VARS_OFFSET
 *    offset in order to write the port sub struct and the
 *    PFID_FROM_PORT_AND_VNIC offset for writing the vnic sub struct (in other
 *    words - don't use memcpy!).
 * 2. although the cmng_init struct is filled for the maximal vnic number
 *    possible, the driver should only write the valid vnics into the internal
 *    ram according to the appropriate port mode.
 */
#define BITS_TO_BYTES(x) ((x)/8)

/* CMNG constants, as derived from system spec calculations */

/* default MIN rate in case VNIC min rate is configured to zero- 100Mbps */
#define DEF_MIN_RATE 100

/* resolution of the rate shaping timer - 400 usec */
#define RS_PERIODIC_TIMEOUT_USEC 400

/*
 *  number of bytes in single QM arbitration cycle -
 *  coefficient for calculating the fairness timer
 */
#define QM_ARB_BYTES 160000

/* resolution of Min algorithm 1:100 */
#define MIN_RES 100

/*
 *  how many bytes above threshold for
 *  the minimal credit of Min algorithm
 */
#define MIN_ABOVE_THRESH 32768

/*
 *  Fairness algorithm integration time coefficient -
 *  for calculating the actual Tfair
 */
#define T_FAIR_COEF ((MIN_ABOVE_THRESH + QM_ARB_BYTES) * 8 * MIN_RES)

/* Memory of fairness algorithm - 2 cycles */
#define FAIR_MEM 2
#define SAFC_TIMEOUT_USEC 52

#define SDM_TICKS 4


void ecore_init_max(const struct cmng_init_input *input_data,
				  u32_t r_param, struct cmng_init *ram_data)
{
	u32_t vnic;
	struct cmng_vnic *vdata = &ram_data->vnic;
	struct cmng_struct_per_port *pdata = &ram_data->port;
	/*
	 * rate shaping per-port variables
	 *  100 micro seconds in SDM ticks = 25
	 *  since each tick is 4 microSeconds
	 */

	pdata->rs_vars.rs_periodic_timeout =
	RS_PERIODIC_TIMEOUT_USEC / SDM_TICKS;

	/* this is the threshold below which no timer arming will occur.
	 *  1.25 coefficient is for the threshold to be a little bigger
	 *  then the real time to compensate for timer in-accuracy
	 */
	pdata->rs_vars.rs_threshold =
	(5 * RS_PERIODIC_TIMEOUT_USEC * r_param)/4;

	/* rate shaping per-vnic variables */
	for (vnic = 0; vnic < ECORE_PORT2_MODE_NUM_VNICS; vnic++) {
		/* global vnic counter */
		vdata->vnic_max_rate[vnic].vn_counter.rate =
		input_data->vnic_max_rate[vnic];
		/*
		 * maximal Mbps for this vnic
		 * the quota in each timer period - number of bytes
		 * transmitted in this period
		 */
		vdata->vnic_max_rate[vnic].vn_counter.quota =
			RS_PERIODIC_TIMEOUT_USEC *
			(u32_t)vdata->vnic_max_rate[vnic].vn_counter.rate / 8;
	}

}

void ecore_init_max_per_vn(u16_t vnic_max_rate,
				  struct rate_shaping_vars_per_vn *ram_data)
{	
	/* global vnic counter */
	ram_data->vn_counter.rate = vnic_max_rate;
	
	/*
	* maximal Mbps for this vnic
	* the quota in each timer period - number of bytes
	* transmitted in this period
	*/
	ram_data->vn_counter.quota = 
		RS_PERIODIC_TIMEOUT_USEC * (u32_t)vnic_max_rate / 8;
}

void ecore_init_min(const struct cmng_init_input *input_data,
				  u32_t r_param, struct cmng_init *ram_data)
{
	u32_t vnic, fair_periodic_timeout_usec, vnicWeightSum, tFair;
	struct cmng_vnic *vdata = &ram_data->vnic;
	struct cmng_struct_per_port *pdata = &ram_data->port;

	/* this is the resolution of the fairness timer */
	fair_periodic_timeout_usec = QM_ARB_BYTES / r_param;

	/*
	 * fairness per-port variables
	 * for 10G it is 1000usec. for 1G it is 10000usec.
	 */
	tFair = T_FAIR_COEF / input_data->port_rate;

	/* this is the threshold below which we won't arm the timer anymore */
	pdata->fair_vars.fair_threshold = QM_ARB_BYTES;

	/*
	 *  we multiply by 1e3/8 to get bytes/msec. We don't want the credits
	 *  to pass a credit of the T_FAIR*FAIR_MEM (algorithm resolution)
	 */
	pdata->fair_vars.upper_bound = r_param * tFair * FAIR_MEM;

	/* since each tick is 4 microSeconds */
	pdata->fair_vars.fairness_timeout =
				fair_periodic_timeout_usec / SDM_TICKS;

	/* calculate sum of weights */
	vnicWeightSum = 0;

	for (vnic = 0; vnic < ECORE_PORT2_MODE_NUM_VNICS; vnic++)
		vnicWeightSum += input_data->vnic_min_rate[vnic];

	/* global vnic counter */
	if (vnicWeightSum > 0) {
		/* fairness per-vnic variables */
		for (vnic = 0; vnic < ECORE_PORT2_MODE_NUM_VNICS; vnic++) {
			/*
			 *  this is the credit for each period of the fairness
			 *  algorithm - number of bytes in T_FAIR (this vnic
			 *  share of the port rate)
			 */
			vdata->vnic_min_rate[vnic].vn_credit_delta =
				((u32_t)(input_data->vnic_min_rate[vnic]) * 100 *
				(T_FAIR_COEF / (8 * 100 * vnicWeightSum)));
			if (vdata->vnic_min_rate[vnic].vn_credit_delta <
			    pdata->fair_vars.fair_threshold +
			    MIN_ABOVE_THRESH) {
				vdata->vnic_min_rate[vnic].vn_credit_delta =
					pdata->fair_vars.fair_threshold +
					MIN_ABOVE_THRESH;
			}
		}
	}
}

void ecore_init_fw_wrr(const struct cmng_init_input *input_data,
				     u32_t r_param, struct cmng_init *ram_data)
{
	u32_t vnic, cos;
	u32_t cosWeightSum = 0;
	struct cmng_vnic *vdata = &ram_data->vnic;
	struct cmng_struct_per_port *pdata = &ram_data->port;

	for (cos = 0; cos < MAX_COS_NUMBER; cos++)
		cosWeightSum += input_data->cos_min_rate[cos];

	if (cosWeightSum > 0) {

		for (vnic = 0; vnic < ECORE_PORT2_MODE_NUM_VNICS; vnic++) {
			/*
			 *  Since cos and vnic shouldn't work together the rate
			 *  to divide between the coses is the port rate.
			 */
			u32_t *ccd = vdata->vnic_min_rate[vnic].cos_credit_delta;
			for (cos = 0; cos < MAX_COS_NUMBER; cos++) {
				/*
				 * this is the credit for each period of
				 * the fairness algorithm - number of bytes
				 * in T_FAIR (this cos share of the vnic rate)
				 */
				ccd[cos] =
				    ((u32_t)input_data->cos_min_rate[cos] * 100 *
				    (T_FAIR_COEF / (8 * 100 * cosWeightSum)));
				 if (ccd[cos] < pdata->fair_vars.fair_threshold
						+ MIN_ABOVE_THRESH) {
					ccd[cos] =
					    pdata->fair_vars.fair_threshold +
					    MIN_ABOVE_THRESH;
				}
			}
		}
	}
}

void ecore_init_safc(const struct cmng_init_input *input_data,
				   struct cmng_init *ram_data)
{
	/* in microSeconds */
	ram_data->port.safc_vars.safc_timeout_usec = SAFC_TIMEOUT_USEC;
}

/* Congestion management port init */
void ecore_init_cmng(const struct cmng_init_input *input_data,
				   struct cmng_init *ram_data)
{
	u32_t r_param;
	mm_mem_zero(ram_data,sizeof(struct cmng_init));

	ram_data->port.flags = input_data->flags;

	/*
	 *  number of bytes transmitted in a rate of 10Gbps
	 *  in one usec = 1.25KB.
	 */
	r_param = BITS_TO_BYTES(input_data->port_rate);
	ecore_init_max(input_data, r_param, ram_data);
	ecore_init_min(input_data, r_param, ram_data);
	ecore_init_fw_wrr(input_data, r_param, ram_data);
	ecore_init_safc(input_data, ram_data);
}

