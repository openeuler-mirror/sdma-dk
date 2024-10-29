/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2024. All rights reserved.
 * Description: mdk_sdma.c
 * Author:
 * Create: 2024
 * Notes:
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <sched.h>
#include <fcntl.h>
#include <errno.h>

#include "hisi_sdma.h"
#include "mdk_sdma.h"

#define CQE_ERR_CODE_BASE (-100000)
#define NORMAL_SQE_CNT 16
#define ERR_SQE_CNT 0
#define SDMA_SQ_SIZE 0x400
#define SDMA_CQ_SIZE 0x100
#define SDMA_SYNC_INFO_SIZE 0x100
#define SDMA_SEND_TASK_TIMES 2

#define SDMA_ERR(fmt, args...) \
	printf("SDMA ERROR (%s|%u): " fmt, __FUNCTION__, __LINE__, ##args)

#ifdef USRTEST
#define SDMA_DBG(fmt, args...) \
	printf("SDMA DEBUG (%s|%u): " fmt, __FUNCTION__, __LINE__, ##args)
#else
#define SDMA_DBG(fmt, args...)
#endif

#define SDMA_WMB() __asm volatile("dsb st" ::: "memory")
#define SDMA_RMB() __asm volatile("dsb ld" ::: "memory")

typedef struct sdma_handle {
	int fd;
	uint32_t chn;
	struct hisi_sdma_sq_entry *sqe;
	struct hisi_sdma_cq_entry *cqe;
	struct hisi_sdma_queue_info *sync_info;
	struct hisi_sdma_queue_data q_data;
	uint16_t streamid;
	void *io_align_base;
	void *io_base;
	struct sdma_mode_funcs *funcs;
} sdma_handle_t;

typedef int (*sdma_reg_func)(const sdma_handle_t *pchan, uint32_t *reg_val);
struct sdma_mode_funcs {
	unsigned int cmd;
	sdma_reg_func reg_func;
};

static bool g_sdma_mode = HISI_SDMA_SAFE_MODE;
static size_t g_page_size = 0;

static void sdma_channel_set_val_mask_shift(const sdma_handle_t *pchan, int reg, uint32_t val,
					    uint32_t mask, uint32_t shift)
{
	uint32_t reg_val = SDMA_READ(pchan->io_base + reg);

	reg_val = (reg_val & ~(mask << shift)) | ((val & mask) << shift);
	SDMA_WMB();
	SDMA_WRITE(reg_val, pchan->io_base + reg);
}

static uint32_t sdma_channel_get_val_mask_shift(const sdma_handle_t *pchan, int reg,
						uint32_t mask, uint32_t shift)
{
	uint32_t reg_val = SDMA_READ(pchan->io_base + reg);

	return (reg_val >> shift) & mask;
}

static int sdma_channel_get_sq_tail(const sdma_handle_t *pchan, uint32_t *reg_val)
{
	*reg_val = sdma_channel_get_val_mask_shift(pchan, HISI_SDMA_CH_SQTDBR_REG, 0xFFFF, 0);

	return 0;
}

static int sdma_channel_set_sq_tail(const sdma_handle_t *pchan, uint32_t *reg_val)
{
	SDMA_WMB();
	SDMA_WRITE(*reg_val, pchan->io_base + HISI_SDMA_CH_SQTDBR_REG);

	return 0;
}

static int sdma_channel_get_sq_head(const sdma_handle_t *pchan, uint32_t *reg_val)
{
	*reg_val = sdma_channel_get_val_mask_shift(pchan, HISI_SDMA_CH_SQHDBR_REG, 0xFFFF, 0);

	return 0;
}

static int sdma_channel_get_cq_head(const sdma_handle_t *pchan, uint32_t *reg_val)
{
	*reg_val = sdma_channel_get_val_mask_shift(pchan, HISI_SDMA_CH_CQHDBR_REG, 0xFFFF, 0);

	return 0;
}

static int sdma_channel_set_cq_head(const sdma_handle_t *pchan, uint32_t *reg_val)
{
	SDMA_WMB();
	SDMA_WRITE(*reg_val, pchan->io_base + HISI_SDMA_CH_CQHDBR_REG);

	return 0;
}

static int sdma_channel_get_cq_tail(const sdma_handle_t *pchan, uint32_t *reg_val)
{
	*reg_val = sdma_channel_get_val_mask_shift(pchan, HISI_SDMA_CH_CQTDBR_REG, 0xFFFF, 0);

	return 0;
}

static int sdma_channel_get_dfx_reg(const sdma_handle_t *pchan, uint32_t *reg_val)
{
	*reg_val = sdma_channel_get_val_mask_shift(pchan, HISI_SDMA_CH_DFX_REG, 0xFFFFFFFF, 0);

	return 0;
}

static int sdma_channel_clr_normal_sqe_cnt(const sdma_handle_t *pchan,
					   uint32_t *reg_val SDMA_UNUSED)
{
	sdma_channel_set_val_mask_shift(pchan, HISI_SDMA_CH_DFX_REG, 0x0, 0xFFFF, NORMAL_SQE_CNT);

	return 0;
}

static int sdma_channel_clr_err_sqe_cnt(const sdma_handle_t *pchan, uint32_t *reg_val SDMA_UNUSED)
{
	sdma_channel_set_val_mask_shift(pchan, HISI_SDMA_CH_DFX_REG, 0x0, 0xFFFF, ERR_SQE_CNT);

	return 0;
}

static int sdma_get_sq_head_ioctl(const sdma_handle_t *pchan, uint32_t *reg_val)
{
	struct hisi_sdma_reg_info reg_info = {0};
	int ret;

	reg_info.chn = pchan->chn;
	reg_info.type = HISI_SDMA_READ_REG;
	ret = ioctl(pchan->fd, IOCTL_SDMA_SQ_HEAD_REG, &reg_info);
	if (ret != 0) {
		SDMA_ERR("IOCTL_SDMA_SQ_HEAD_REG fail,%s!\n", strerror(errno));
		return ret;
	}
	*reg_val = reg_info.reg_value;

	return 0;
}

static int sdma_get_sq_tail_ioctl(const sdma_handle_t *pchan, uint32_t *reg_val)
{
	struct hisi_sdma_reg_info reg_info = {0};
	int ret;

	reg_info.chn = pchan->chn;
	reg_info.type = HISI_SDMA_READ_REG;
	ret = ioctl(pchan->fd, IOCTL_SDMA_SQ_TAIL_REG, &reg_info);
	if (ret != 0) {
		SDMA_ERR("IOCTL_SDMA_SQ_TAIL_REG fail,%s!\n", strerror(errno));
		return ret;
	}
	*reg_val = reg_info.reg_value;

	return 0;
}

static int sdma_get_cq_head_ioctl(const sdma_handle_t *pchan, uint32_t *reg_val)
{
	struct hisi_sdma_reg_info reg_info = {0};
	int ret;

	reg_info.chn = pchan->chn;
	reg_info.type = HISI_SDMA_READ_REG;
	ret = ioctl(pchan->fd, IOCTL_SDMA_CQ_HEAD_REG, &reg_info);
	if (ret != 0) {
		SDMA_ERR("IOCTL_SDMA_CQ_HEAD_REG fail,%s!\n", strerror(errno));
		return ret;
	}
	*reg_val = reg_info.reg_value;

	return 0;
}

static int sdma_set_cq_head_ioctl(const sdma_handle_t *pchan, uint32_t *reg_val)
{
	struct hisi_sdma_reg_info reg_info = {0};
	int ret;

	reg_info.chn = pchan->chn;
	reg_info.type = HISI_SDMA_WRITE_REG;
	reg_info.reg_value = *reg_val;
	ret = ioctl(pchan->fd, IOCTL_SDMA_CQ_HEAD_REG, &reg_info);
	if (ret != 0) {
		SDMA_ERR("IOCTL_SDMA_CQ_HEAD_REG fail,%s!\n", strerror(errno));
		return ret;
	}

	return 0;
}

static int sdma_get_cq_tail_ioctl(const sdma_handle_t *pchan, uint32_t *reg_val)
{
	struct hisi_sdma_reg_info reg_info = {0};
	int ret;

	reg_info.chn = pchan->chn;
	reg_info.type = HISI_SDMA_READ_REG;
	ret = ioctl(pchan->fd, IOCTL_SDMA_CQ_TAIL_REG, &reg_info);
	if (ret != 0) {
		SDMA_ERR("IOCTL_SDMA_CQ_TAIL_REG fail,%s!\n", strerror(errno));
		return ret;
	}
	*reg_val = reg_info.reg_value;

	return 0;
}

static int sdma_get_dfx_reg_ioctl(const sdma_handle_t *pchan, uint32_t *reg_val)
{
	struct hisi_sdma_reg_info reg_info = {0};
	int ret;

	reg_info.chn = pchan->chn;
	ret = ioctl(pchan->fd, IOCTL_SDMA_DFX_REG, &reg_info);
	if (ret != 0) {
		SDMA_ERR("IOCTL_SDMA_DFX_REG fail,%s!\n", strerror(errno));
		return ret;
	}
	*reg_val = reg_info.reg_value;

	return 0;
}

static int sdma_clr_normal_sqe_cnt_ioctl(const sdma_handle_t *pchan, uint32_t *reg_val SDMA_UNUSED)
{
	struct hisi_sdma_reg_info clr_info = {0};
	int ret;

	clr_info.chn = pchan->chn;
	clr_info.type = HISI_SDMA_CLR_NORMAL_SQE_CNT;
	ret = ioctl(pchan->fd, IOCTL_SDMA_SQE_CNT_REG, &clr_info);
	if (ret != 0) {
		SDMA_ERR("IOCTL_SDMA_SQE_CNT_REG fail,%s!\n", strerror(errno));
		return ret;
	}

	return 0;
}

static int sdma_clr_err_sqe_cnt_ioctl(const sdma_handle_t *pchan, uint32_t *reg_val SDMA_UNUSED)
{
	struct hisi_sdma_reg_info clr_info = {0};
	int ret;

	clr_info.chn = pchan->chn;
	clr_info.type = HISI_SDMA_CLR_ERR_SQE_CNT;
	ret = ioctl(pchan->fd, IOCTL_SDMA_SQE_CNT_REG, &clr_info);
	if (ret != 0) {
		SDMA_ERR("IOCTL_SDMA_SQE_CNT_REG fail,%s!\n", strerror(errno));
		return ret;
	}

	return 0;
}

struct sdma_mode_funcs g_fast_mode_list[] = {
	{SDMA_SQ_HEAD_READ,	sdma_channel_get_sq_head},
	{SDMA_SQ_TAIL_READ,	sdma_channel_get_sq_tail},
	{SDMA_SQ_TAIL_WRITE,	sdma_channel_set_sq_tail},
	{SDMA_CQ_HEAD_READ,	sdma_channel_get_cq_head},
	{SDMA_CQ_HEAD_WRITE,	sdma_channel_set_cq_head},
	{SDMA_CQ_TAIL_READ,	sdma_channel_get_cq_tail},
	{SDMA_DFX_REG_READ,	sdma_channel_get_dfx_reg},
	{SDMA_CLR_NORM_CNT,	sdma_channel_clr_normal_sqe_cnt},
	{SDMA_CLR_ERR_CNT,	sdma_channel_clr_err_sqe_cnt},
};

struct sdma_mode_funcs g_safe_mode_list[] = {
	{SDMA_SQ_HEAD_READ,	sdma_get_sq_head_ioctl},
	{SDMA_SQ_TAIL_READ,	sdma_get_sq_tail_ioctl},
	{SDMA_SQ_TAIL_WRITE,	NULL},
	{SDMA_CQ_HEAD_READ,	sdma_get_cq_head_ioctl},
	{SDMA_CQ_HEAD_WRITE,	sdma_set_cq_head_ioctl},
	{SDMA_CQ_TAIL_READ,	sdma_get_cq_tail_ioctl},
	{SDMA_DFX_REG_READ,	sdma_get_dfx_reg_ioctl},
	{SDMA_CLR_NORM_CNT,	sdma_clr_normal_sqe_cnt_ioctl},
	{SDMA_CLR_ERR_CNT,	sdma_clr_err_sqe_cnt_ioctl},
};

static int cqe_err_code(uint32_t status)
{
	return CQE_ERR_CODE_BASE - (int)status;
}

static int sdma_cqe_check(sdma_handle_t *pchan, uint16_t sq_id, uint16_t cq_tail)
{
	struct hisi_sdma_cq_entry *cq_entry = NULL;
	int ret = 0;

	cq_entry = pchan->cqe + cq_tail;
	if (cq_entry->status != 0) {
		SDMA_ERR("cq_entry invalid, status: %u\n", cq_entry->status);
		ret = cqe_err_code(cq_entry->status);
		pchan->sync_info->cqe_err[cq_tail] = ret;
		__sync_fetch_and_add(&pchan->sync_info->err_cnt, 1);
	} else {
			pchan->sync_info->cqe_err[cq_tail] = 0;
		}
	if (sq_id != cq_entry->sqe_id) {
		SDMA_ERR("sqe_id error, cq_head = %hu, sqe_id = %u\n", sq_id, cq_entry->sqe_id);
		ret = SDMA_CQE_ID_WRONG;
		pchan->sync_info->cqe_err[cq_tail] = ret;
		__sync_fetch_and_add(&pchan->sync_info->err_cnt, 1);
	}
	pchan->sync_info->round_cnt[cq_tail]++;

	return ret;
}

static uint32_t sdma_task_num(uint32_t head, uint32_t tail)
{
	return (tail + HISI_SDMA_SQ_LEN - head) & (HISI_SDMA_SQ_LEN - 1);
}

static void sdma_lock_chn(volatile int *lock, uint32_t *lock_pid)
{
	while (__sync_bool_compare_and_swap(lock, 0, 1) != 1)
		sched_yield();

	*lock_pid = (uint32_t)getpid();
}

static void sdma_unlock_chn(volatile int *lock, uint32_t *lock_pid)
{
	*lock_pid = 0;
	SDMA_WMB();
	*lock = 0;
}

static int update_hw_sw_ptr(sdma_handle_t *pchan, uint32_t sq_head, uint32_t cq_tail)
{
	int ret;

	/* Updata HW CQ HEAD */
	ret = pchan->funcs[SDMA_CQ_HEAD_WRITE].reg_func(pchan, &cq_tail);
	if (ret != 0) {
		SDMA_ERR("write cq_head failed, ret = %d\n", ret);
		return SDMA_FAILED;
	}
	pchan->sync_info->sq_head = sq_head;
	pchan->sync_info->cq_tail = cq_tail;
	pchan->sync_info->cq_head = cq_tail;

	return SDMA_SUCCESS;
}

static int sdma_task_timeout_handle(sdma_handle_t *pchan, uint32_t sq_head, uint32_t cq_tail,
				    uint32_t left_num)
{
	uint32_t hardware_sq_tail;
	uint32_t hardware_sq_head;
	int ret;

	ret = pchan->funcs[SDMA_SQ_TAIL_READ].reg_func(pchan, &hardware_sq_tail);
	if (ret != 0) {
		SDMA_ERR("read sq_tail value failed, ret = %d\n", ret);
		return SDMA_FAILED;
	}
	if (hardware_sq_tail >= HISI_SDMA_SQ_LEN) {
		SDMA_ERR("sq_tail value invalid, sq_tail = %u\n", hardware_sq_tail);
		return SDMA_FAILED;
	}
	if (pchan->sync_info->sq_tail != (uint16_t)hardware_sq_tail) {
		return SDMA_INVALID_DOORBELL;
	}
	ret = pchan->funcs[SDMA_SQ_HEAD_READ].reg_func(pchan, &hardware_sq_head);
	if (ret != 0) {
		SDMA_ERR("read sq_head value failed, ret = %d\n", ret);
		return SDMA_FAILED;
	}
	if (hardware_sq_head >= HISI_SDMA_SQ_LEN) {
		SDMA_ERR("sq_head value invalid, sq_head = %u\n", hardware_sq_head);
		return SDMA_FAILED;
	}
	if (pchan->sync_info->sq_tail == (uint16_t)hardware_sq_head) {
		return SDMA_CQE_MEM_RSVD;
	}
	SDMA_ERR("Timeout CQEs id = %u, there are still %u task left!\n", cq_tail, left_num);
	ret = update_hw_sw_ptr(pchan, sq_head, cq_tail);
	if (ret != 0) {
		return SDMA_FAILED;
	}

	return SDMA_TASK_TIMEOUT;
}

static int sdma_task_check(sdma_handle_t *pchan, uint32_t task_num)
{
	struct hisi_sdma_cq_entry *cq_entry = NULL;
	uint32_t cq_vld, num = task_num;
	uint32_t cq_tail, sq_head;
	int ret = SDMA_SUCCESS;
	bool cqe_wrong = false;
	int i = 0;

	if (num == 0)
		return ret;

	sq_head = pchan->sync_info->sq_head;
	cq_tail = pchan->sync_info->cq_tail;
	cq_vld = pchan->sync_info->cq_vld;

	while (i++ < HISI_SDMA_CQE_TIMEOUT && num > 0) {
		cq_entry = pchan->cqe + cq_tail;
		/* check whether the cqe is valid */
		if (cq_vld != cq_entry->vld)
			continue;
		/* ensure the order of cqe */
		SDMA_RMB();
		ret = sdma_cqe_check(pchan, sq_head, cq_tail);
		if (ret != 0) {
			cqe_wrong = true;
		}
		sq_head = (sq_head + 1) & (HISI_SDMA_SQ_LEN - 1);
		cq_tail = (cq_tail + 1) & (HISI_SDMA_CQ_LEN - 1);
		if (cq_tail == 0) {
			pchan->sync_info->cq_vld ^= 1;
			cq_vld ^= 1;
		}
		num--;
	}

	if (i > HISI_SDMA_CQE_TIMEOUT) {
		return sdma_task_timeout_handle(pchan, sq_head, cq_tail, num);
	}
	ret = update_hw_sw_ptr(pchan, sq_head, cq_tail);
	if (ret != 0) {
		return SDMA_FAILED;
	}
	if (cqe_wrong) {
		return SDMA_CQE_ERROR;
	}

	return SDMA_SUCCESS;
}

int sdma_check_handle(void *phandle)
{
	sdma_handle_t *pchan;

	if (!phandle) {
		SDMA_ERR("sdma channel handle is NULL!\n");
		return SDMA_NULL_POINTER;
	}

	pchan = (sdma_handle_t *)phandle;
	if (!pchan->cqe || !pchan->sync_info || !pchan->funcs) {
		SDMA_ERR("sdma handle content invalid!\n");
		return SDMA_NULL_POINTER;
	}

	if (pchan->sync_info->sq_head >= HISI_SDMA_SQ_LEN ||
	    pchan->sync_info->sq_tail >= HISI_SDMA_SQ_LEN ||
	    pchan->sync_info->cq_head >= HISI_SDMA_CQ_LEN ||
	    pchan->sync_info->cq_tail >= HISI_SDMA_CQ_LEN) {
		SDMA_ERR("sdma sq/cq register info invalid!\n");
		return SDMA_QNUM_OVERFLOW;
	}

	if (g_sdma_mode == HISI_SDMA_FAST_MODE) {
		if (!pchan->sqe || !pchan->io_align_base) {
			SDMA_ERR("sdma handle content invalid under fast mode!\n");
			return SDMA_NULL_POINTER;
		}
	}

	return SDMA_SUCCESS;
}

int sdma_wait_chn(void *phandle, uint32_t count)
{
	sdma_handle_t *pchan;
	uint32_t num;
	int ret;

	ret = sdma_check_handle(phandle);
	if (ret != 0) {
		return ret;
	}

	pchan = (sdma_handle_t *)phandle;
	num = sdma_task_num(pchan->sync_info->sq_head, pchan->sync_info->sq_tail);
	if (num < count) {
		return SDMA_WAIT_NUM_OVERFLOW;
	}

	return sdma_task_check(pchan, count);
}

static int update_round_cnt(sdma_handle_t *pchan, uint32_t hardware_cq_tail)
{
	struct hisi_sdma_cq_entry *cq_entry = NULL;
	uint32_t cq_head;
	int ret;

	cq_head = pchan->sync_info->cq_head;
	if (hardware_cq_tail == cq_head) {
		return SDMA_SUCCESS;
	}
	while (cq_head != hardware_cq_tail) {
		cq_entry = pchan->cqe + cq_head;
		if (cq_entry->status != 0) {
			SDMA_ERR("cq_entry invalid, status: %u\n", cq_entry->status);
			pchan->sync_info->cqe_err[cq_head] = cqe_err_code(cq_entry->status);
			__sync_fetch_and_add(&pchan->sync_info->err_cnt, 1);
		} else {
			pchan->sync_info->cqe_err[cq_head] = 0;
		}

		pchan->sync_info->round_cnt[cq_head]++;
		cq_head = (cq_head + 1) & (HISI_SDMA_CQ_LEN - 1);
	}

	ret = pchan->funcs[SDMA_CQ_HEAD_WRITE].reg_func(pchan, &hardware_cq_tail);
	if (ret != 0) {
		SDMA_ERR("write cq_head failed, ret = %d\n", ret);
		return SDMA_FAILED;
	}
	pchan->sync_info->cq_tail = hardware_cq_tail;
	pchan->sync_info->cq_head = hardware_cq_tail;
	pchan->sync_info->sq_head = hardware_cq_tail;

	return SDMA_SUCCESS;
}

static int sdma_query_cqe_check(sdma_handle_t *pchan, uint32_t hardware_cq_tail)
{
	struct hisi_sdma_cq_entry *cq_entry = NULL;
	bool cqe_wrong = false;
	uint32_t cq_head;
	int ret;

	cq_head = pchan->sync_info->cq_head;
	while (cq_head != hardware_cq_tail) {
		cq_entry = pchan->cqe + cq_head;
		if (cq_entry->status != 0) {
			SDMA_ERR("cq_entry invalid, status: %u\n", cq_entry->status);
			pchan->sync_info->cqe_err[cq_head] = cqe_err_code(cq_entry->status);
			cqe_wrong = true;
		} else {
			pchan->sync_info->cqe_err[cq_head] = 0;
		}
		cq_head = (cq_head + 1) & (HISI_SDMA_CQ_LEN - 1);
	}
	ret = pchan->funcs[SDMA_CQ_HEAD_WRITE].reg_func(pchan, &hardware_cq_tail);
	if (ret != 0) {
		SDMA_ERR("write cq_head failed, ret = %d\n", ret);
		return SDMA_FAILED;
	}
	pchan->sync_info->cq_tail = (uint16_t)hardware_cq_tail;
	pchan->sync_info->cq_head = (uint16_t)hardware_cq_tail;
	pchan->sync_info->sq_head = (uint16_t)hardware_cq_tail;
	if (cqe_wrong) {
		SDMA_ERR("chn%u has wrong cqe, please check!\n", pchan->chn);
		return SDMA_FAILED;
	}

	return 0;
}

int sdma_query_chn(void *phandle, uint32_t count)
{
	uint32_t hardware_cq_tail = 0;
	uint32_t finish_count;
	sdma_handle_t *pchan;
	uint32_t head_before;
	int ret;

	ret = sdma_check_handle(phandle);
	if (ret != 0) {
		return ret;
	}
	if (count == 0) {
		return SDMA_SUCCESS;
	}
	pchan = (sdma_handle_t *)phandle;
	ret = pchan->funcs[SDMA_CQ_TAIL_READ].reg_func(pchan, &hardware_cq_tail);
	if (ret != 0) {
		SDMA_ERR("read cq_tail value failed, ret = %d\n", ret);
		return SDMA_FAILED;
	}
	if (hardware_cq_tail >= HISI_SDMA_CQ_LEN) {
		SDMA_ERR("cq_tail value invalid, cq_tail = %u\n", hardware_cq_tail);
		return SDMA_FAILED;
	}
	head_before = pchan->sync_info->cq_head;
	finish_count = (hardware_cq_tail + HISI_SDMA_CQ_LEN - head_before) &
		       (HISI_SDMA_CQ_LEN - 1);
	if (finish_count < count) {
		return SDMA_TASK_UNFINISH;
	}

	return sdma_query_cqe_check(pchan, hardware_cq_tail);
}

static bool rndcnt_invalid(const sdma_handle_t *pchan, uint32_t last_req_cqe, uint32_t round_cnt)
{
	if (last_req_cqe < HISI_SDMA_CQ_LEN) {
		if (pchan->sync_info->round_cnt[last_req_cqe] <= round_cnt) {
			if (round_cnt == UINT32_MAX &&
			    pchan->sync_info->round_cnt[last_req_cqe] == 0) {
				return false;
			}
			return true;
		}
	} else if (pchan->sync_info->round_cnt[last_req_cqe % HISI_SDMA_CQ_LEN] <= round_cnt + 1) {
		if (round_cnt == UINT32_MAX - 1 &&
		    pchan->sync_info->round_cnt[last_req_cqe % HISI_SDMA_CQ_LEN] == 0) {
			return false;
		}
		return true;
	}

	return false;
}

static int cqe_status(sdma_handle_t *pchan, uint16_t req_id, uint32_t req_cnt)
{
	uint32_t cqe_id;
	int ret = 0;
	uint32_t i;

	if (pchan->sync_info->err_cnt == 0) {
		return ret;
	}

	for (i = 0; i < req_cnt; i++) {
		cqe_id = (req_id + i) % HISI_SDMA_CQ_LEN;
		if (pchan->sync_info->cqe_err[cqe_id] != 0) {
			SDMA_ERR("cqe%u error status = %d\n", cqe_id,
				 pchan->sync_info->cqe_err[cqe_id]);
			ret = pchan->sync_info->cqe_err[cqe_id];
			pchan->sync_info->cqe_err[cqe_id] = 0;
			__sync_fetch_and_sub(&pchan->sync_info->err_cnt, 1);
		}
	}

	return ret;
}

static int sdma_request_check(sdma_handle_t *pchan, sdma_request_t *request)
{
	uint32_t req_cnt, round_cnt;
	uint32_t last_req_cqe;
	uint16_t req_id;

	req_id = request->req_id;
	req_cnt = request->req_cnt;
	round_cnt = request->round_cnt;
	last_req_cqe = req_id + req_cnt - 1;

	if (rndcnt_invalid(pchan, last_req_cqe, round_cnt)) {
		return SDMA_RNDCNT_ERR;
	}

	return cqe_status(pchan, req_id, req_cnt);
}

int sdma_iwait_chn(void *phandle, sdma_request_t *request)
{
	sdma_handle_t *pchan;
	uint32_t num;
	int ret;

	ret = sdma_check_handle(phandle);
	if (ret != 0) {
		return ret;
	}

	if (!request) {
		SDMA_ERR("sdma request is NULL!\n");
		return SDMA_NULL_POINTER;
	}

	pchan = (sdma_handle_t *)phandle;
	if (request->req_cnt == 0) {
		return SDMA_SUCCESS;
	}

	sdma_lock_chn(&pchan->sync_info->lock, &pchan->sync_info->lock_pid);
	num = sdma_task_num(pchan->sync_info->sq_head, pchan->sync_info->sq_tail);
	if (num > 0) {
		ret = sdma_task_check(pchan, num);
		if (ret == SDMA_INVALID_DOORBELL || ret == SDMA_CQE_MEM_RSVD ||
		    ret == SDMA_FAILED) {
			sdma_unlock_chn(&pchan->sync_info->lock, &pchan->sync_info->lock_pid);
			return ret;
		}
	}
	sdma_unlock_chn(&pchan->sync_info->lock, &pchan->sync_info->lock_pid);

	return sdma_request_check(pchan, request);
}

int sdma_iquery_chn(void *phandle, sdma_request_t *request)
{
	uint32_t hardware_cq_tail;
	sdma_handle_t *pchan;
	int ret;

	ret = sdma_check_handle(phandle);
	if (ret != 0) {
		return ret;
	}

	if (!request) {
		SDMA_ERR("sdma request is NULL!\n");
		return SDMA_NULL_POINTER;
	}

	if (request->req_cnt == 0) {
		return SDMA_SUCCESS;
	}

	pchan = (sdma_handle_t *)phandle;

	sdma_lock_chn(&pchan->sync_info->lock, &pchan->sync_info->lock_pid);
	ret = pchan->funcs[SDMA_CQ_TAIL_READ].reg_func(pchan, &hardware_cq_tail);
	if (ret != 0) {
		sdma_unlock_chn(&pchan->sync_info->lock, &pchan->sync_info->lock_pid);
		SDMA_ERR("read cq_tail value failed, ret = %d\n", ret);
		return SDMA_FAILED;
	}
	if (hardware_cq_tail >= HISI_SDMA_CQ_LEN) {
		sdma_unlock_chn(&pchan->sync_info->lock, &pchan->sync_info->lock_pid);
		SDMA_ERR("cq_tail value invalid, cq_tail = %u\n", hardware_cq_tail);
		return SDMA_FAILED;
	}
	ret = update_round_cnt(pchan, hardware_cq_tail);
	if (ret != 0) {
		sdma_unlock_chn(&pchan->sync_info->lock, &pchan->sync_info->lock_pid);
		return SDMA_FAILED;
	}
	sdma_unlock_chn(&pchan->sync_info->lock, &pchan->sync_info->lock_pid);

	return sdma_request_check(pchan, request);
}

static int sdma_get_mmap_size(uint32_t depth, size_t *sqe, size_t *cqe, size_t *sync)
{
	g_page_size = (size_t)getpagesize();
	if (g_page_size < HISI_SDMA_REG_SIZE) {
		return SDMA_FAILED;
	}

	*sqe = (size_t)((depth * sizeof(struct hisi_sdma_sq_entry) + g_page_size - 1) /
			g_page_size * g_page_size);
	*cqe = (size_t)((depth * sizeof(struct hisi_sdma_cq_entry) + g_page_size - 1) /
			g_page_size * g_page_size);
	*sync = (size_t)((sizeof(struct hisi_sdma_queue_info) + g_page_size - 1) /
			 g_page_size * g_page_size);

	return SDMA_SUCCESS;
}

static int sdma_mmap(uint32_t chn_num, sdma_handle_t *phandle, size_t sqe_size, size_t cqe_size,
		     size_t sync_size)
{
	off_t offset;
	void *ptr;

	/* The offset of the mapped sqe memory ranges is [0, chn_num] * pagesize */
	if (g_sdma_mode == HISI_SDMA_FAST_MODE) {
		offset = (off_t)(phandle->chn * g_page_size);
		ptr = mmap(NULL, sqe_size, PROT_READ | PROT_WRITE, MAP_SHARED, phandle->fd,
			   offset);
		if (ptr == MAP_FAILED) {
			SDMA_ERR("mmap sqe failed\n");
			return SDMA_FAILED;
		}
		phandle->sqe = (struct hisi_sdma_sq_entry *)ptr;
	}

	/* The offset of the mapped cqe memory ranges is [chn_num, 2*chn_num] * pagesize */
	offset = (off_t)((phandle->chn + chn_num * HISI_SDMA_MMAP_CQE) * g_page_size);
	ptr = mmap(NULL, cqe_size, PROT_READ | PROT_WRITE, MAP_SHARED, phandle->fd, offset);
	if (ptr == MAP_FAILED) {
		SDMA_ERR("mmap cqe failed\n");
		goto unmap_sqe;
	}
	phandle->cqe = (struct hisi_sdma_cq_entry *)ptr;

	/* The offset of the mapped io_register ranges is [2*chn_num, 3*chn_num] * pagesize */
	if (g_sdma_mode == HISI_SDMA_FAST_MODE) {
		offset = (off_t)((chn_num * HISI_SDMA_MMAP_IO + phandle->chn) * g_page_size);
		ptr = mmap(NULL, g_page_size, PROT_READ | PROT_WRITE, MAP_SHARED, phandle->fd,
			   offset);
		if (ptr == MAP_FAILED) {
			SDMA_ERR("mmap io reg failed\n");
			goto unmap_cqe;
		}
		phandle->io_align_base = ptr;
		phandle->io_base = ptr + (phandle->chn % (g_page_size / HISI_SDMA_REG_SIZE)) *
				   HISI_SDMA_REG_SIZE;
	}

	/* The offset of the mapped io_register ranges is [3*chn_num, 4*chn_num] * pagesize */
	offset = (off_t)((chn_num * HISI_SDMA_MMAP_SHMEM + phandle->chn) * g_page_size);
	ptr = mmap(NULL, sync_size, PROT_READ | PROT_WRITE, MAP_SHARED, phandle->fd, offset);
	if (ptr == MAP_FAILED) {
		SDMA_ERR("mmap sync info failed\n");
		goto unmap_io;
	}
	phandle->sync_info = (struct hisi_sdma_queue_info *)ptr;

	return SDMA_SUCCESS;

unmap_io:
	if (phandle->io_align_base) {
		munmap(phandle->io_align_base, g_page_size);
		phandle->io_align_base = NULL;
	}
unmap_cqe:
	if (phandle->cqe) {
		munmap(phandle->cqe, cqe_size);
		phandle->cqe = NULL;
	}
unmap_sqe:
	if (phandle->sqe) {
		munmap(phandle->sqe, sqe_size);
		phandle->sqe = NULL;
	}

	return SDMA_FAILED;
}

static void sdma_munmap_chn(sdma_handle_t *phandle)
{
	size_t sqe_size, cqe_size, sync_size;
	int ret;

	ret = sdma_get_mmap_size(HISI_SDMA_SQ_LEN, &sqe_size, &cqe_size, &sync_size);
	if (ret < 0) {
		SDMA_ERR("get mmap size failed\n");
		return;
	}

	if (phandle->sqe) {
		munmap(phandle->sqe, sqe_size);
		phandle->sqe = NULL;
	}

	if (phandle->cqe) {
		munmap(phandle->cqe, cqe_size);
		phandle->cqe = NULL;
	}

	if (phandle->io_align_base) {
		munmap(phandle->io_align_base, g_page_size);
		phandle->io_align_base = NULL;
	}

	if (phandle->sync_info) {
		munmap(phandle->sync_info, sync_size);
		phandle->sync_info = NULL;
	}
}

static int sdma_mmap_chn(uint32_t chn_num, sdma_handle_t *phandle)
{
	size_t sqe_size, cqe_size, sync_size;
	int ret;

	ret = sdma_get_mmap_size(HISI_SDMA_SQ_LEN, &sqe_size, &cqe_size, &sync_size);
	if (ret < 0) {
		SDMA_ERR("get mmap size failed\n");
		return SDMA_FAILED;
	}

	if (sqe_size > (SDMA_SQ_SIZE * g_page_size) || cqe_size > (SDMA_CQ_SIZE * g_page_size) ||
	    sync_size > (SDMA_SYNC_INFO_SIZE * g_page_size)) {
		SDMA_ERR("invalid mmap size\n");
		return SDMA_FAILED;
	}

	ret = sdma_mmap(chn_num, phandle, sqe_size, cqe_size, sync_size);
	if (ret < 0) {
		SDMA_ERR("sdma mmap failed, ret = %d\n", ret);
		return SDMA_FAILED;
	}

	return SDMA_SUCCESS;
}

static int sdma_prep_operations(int fd, struct hisi_sdma_chn_num chn_num, sdma_handle_t *pchan)
{
	uint32_t streamid = 0;

	if (ioctl(fd, IOCTL_SDMA_GET_STREAMID, &streamid) != 0) {
		SDMA_ERR("IOCTL_SDMA_GET_STREAMID fail,%s!\n", strerror(errno));
		return SDMA_FAILED;
	}
	pchan->streamid = (uint16_t)streamid;
	if (ioctl(fd, IOCTL_GET_SDMA_MODE, &g_sdma_mode) != 0) {
		SDMA_ERR("IOCTL_GET_SDMA_MODE fail,%s!\n", strerror(errno));
		return SDMA_FAILED;
	}

	if (sdma_mmap_chn(chn_num.total_chn_num, pchan) != 0) {
		SDMA_ERR("sdma_mmap_chn fail!\n");
		return SDMA_FAILED;
	}

	if (g_sdma_mode == HISI_SDMA_FAST_MODE) {
		pchan->funcs = g_fast_mode_list;
	} else {
		pchan->funcs = g_safe_mode_list;
	}

	return SDMA_SUCCESS;
}

static int sdma_update_chn_pointer(sdma_handle_t *pchan)
{
	uint32_t sq_head, sq_tail, cq_head, cq_tail;
	int ret;

	ret = pchan->funcs[SDMA_SQ_HEAD_READ].reg_func(pchan, &sq_head);
	if (ret != 0) {
		SDMA_ERR("read sq_head value failed, ret = %d\n", ret);
		return SDMA_FAILED;
	}
	if (sq_head >= HISI_SDMA_SQ_LEN) {
		SDMA_ERR("sq_head value invalid, sq_head = %u\n", sq_head);
		return SDMA_FAILED;
	}
	ret = pchan->funcs[SDMA_SQ_TAIL_READ].reg_func(pchan, &sq_tail);
	if (ret != 0) {
		SDMA_ERR("read sq_tail value failed, ret = %d\n", ret);
		return SDMA_FAILED;
	}
	if (sq_tail >= HISI_SDMA_SQ_LEN) {
		SDMA_ERR("sq_tail value invalid, sq_tail = %u\n", sq_tail);
		return SDMA_FAILED;
	}

	ret = pchan->funcs[SDMA_CQ_HEAD_READ].reg_func(pchan, &cq_head);
	if (ret != 0) {
		SDMA_ERR("read cq_head value failed, ret = %d\n", ret);
		return SDMA_FAILED;
	}
	if (cq_head >= HISI_SDMA_CQ_LEN) {
		SDMA_ERR("cq_head value invalid, cq_head = %u\n", cq_head);
		return SDMA_FAILED;
	}
	ret = pchan->funcs[SDMA_CQ_TAIL_READ].reg_func(pchan, &cq_tail);
	if (ret != 0) {
		SDMA_ERR("read cq_tail value failed, ret = %d\n", ret);
		return SDMA_FAILED;
	}
	if (cq_tail >= HISI_SDMA_CQ_LEN) {
		SDMA_ERR("cq_tail value invalid, cq_tail = %u\n", cq_tail);
		return SDMA_FAILED;
	}
	pchan->sync_info->sq_head = (uint16_t)sq_head;
	pchan->sync_info->sq_tail = (uint16_t)sq_tail;
	pchan->sync_info->cq_head = (uint16_t)cq_head;
	pchan->sync_info->cq_tail = (uint16_t)cq_tail;

	if (sq_head != sq_tail) {
		SDMA_ERR("sdma chn%u SQE unnormal! SQ head = %u, SQ tail = %u\n", pchan->chn,
			 sq_head, sq_tail);
		return SDMA_FAILED;
	}
	if (cq_head != cq_tail) {
		ret = pchan->funcs[SDMA_CQ_HEAD_WRITE].reg_func(pchan, &cq_tail);
		if (ret != 0) {
			SDMA_ERR("write cq_head failed, ret = %d\n", ret);
			return SDMA_FAILED;
		}
		pchan->sync_info->cq_head = cq_tail;
	}

	return SDMA_SUCCESS;
}

void *sdma_alloc_chn(int fd)
{
	struct hisi_sdma_chn_num chn_num;
	sdma_handle_t *pchan = NULL;
	uint32_t chn;
	int ret;

	if (ioctl(fd, IOCTL_GET_SDMA_CHN_NUM, &chn_num) != 0) {
		SDMA_ERR("IOCTL_GET_SDMA_CHN_NUM fail,%s!\n", strerror(errno));
		goto err_out;
	}
	if (ioctl(fd, IOCTL_SDMA_GET_CHN, &chn) != 0) {
		SDMA_ERR("IOCTL_SDMA_GET_CHN fail,%s!\n", strerror(errno));
		goto err_out;
	}
	pchan = (sdma_handle_t *)calloc(1, sizeof(sdma_handle_t));
	if (pchan == NULL) {
		SDMA_ERR("calloc pchan failed,%s!\n", strerror(errno));
		goto err_put;
	}
	pchan->chn = chn;
	pchan->fd = fd;
	ret = sdma_prep_operations(fd, chn_num, pchan);
	if (ret != 0) {
		goto err_free;
	}
	ret = sdma_update_chn_pointer(pchan);
	if (ret != 0) {
		goto err_unmap;
	}

	return (void *)pchan;

err_unmap:
	sdma_munmap_chn(pchan);
err_free:
	free(pchan);
err_put:
	if(!ioctl(fd, IOCTL_SDMA_PUT_CHN, &chn)) {
		SDMA_ERR("IOCTL_SDMA_PUT_CHN fail,%s!\n", strerror(errno));
	}
err_out:
	return NULL;
}

void *sdma_init_chn(int fd, uint32_t chn)
{
	struct hisi_sdma_share_chn share_chn;
	struct hisi_sdma_chn_num chn_num;
	sdma_handle_t *pchan = NULL;
	int ret;

	ret = ioctl(fd, IOCTL_GET_SDMA_CHN_NUM, &chn_num);
	if (ret != 0) {
		SDMA_ERR("IOCTL_GET_SDMA_CHN_NUM fail,%s!\n", strerror(errno));
		goto err_out;
	}

	if (chn_num.share_chn_num == 0) {
		SDMA_ERR("no share_chn avaliable!\n");
		goto err_out;
	}

	pchan = (sdma_handle_t *)calloc(1, sizeof(sdma_handle_t));
	if (pchan == NULL) {
		SDMA_ERR("calloc pchan failed,%s!\n", strerror(errno));
		goto err_out;
	}

	pchan->chn = chn % chn_num.share_chn_num;
	pchan->fd = fd;
	share_chn.chn_idx = pchan->chn;
	share_chn.init_flag = true;
	ret = ioctl(fd, IOCTL_SDMA_CHN_USED_REFCOUNT, &share_chn);
	if (ret != 0) {
		SDMA_ERR("IOCTL_SDMA_CHN_USED_REFCOUNT fail,%s!\n", strerror(errno));
		goto err_free;
	}
	ret = sdma_prep_operations(fd, chn_num, pchan);
	if (ret != 0) {
		goto err_free;
	}

	return (void *)pchan;

err_free:
	share_chn.init_flag = false;
	ret = ioctl(fd, IOCTL_SDMA_CHN_USED_REFCOUNT, &share_chn);
	if (ret != 0) {
		SDMA_ERR("IOCTL_SDMA_CHN_USED_REFCOUNT fail,%s!\n", strerror(errno));
	}
	free(pchan);
err_out:
	return NULL;
}

static void fill_sdma_tasks(struct hisi_sdma_sq_entry *entry, sdma_handle_t *pchan,
			    sdma_sqe_task_t *sdma_sqe, uint16_t sq_tail)
{
	entry->opcode		= sdma_sqe->opcode;
	entry->src_streamid	= pchan->streamid;
	entry->dst_streamid	= pchan->streamid;
	/* 0xffffffff:src_addr low 32bit */
	entry->src_addr_l	= (uint32_t)(sdma_sqe->src_addr & 0xffffffff);
	/* 32:src_addr high 32bit */
	entry->src_addr_h	= (uint32_t)(sdma_sqe->src_addr >> 32);
	/* 0xffffffff:dst_addr low 32bit */
	entry->dst_addr_l	= (uint32_t)(sdma_sqe->dst_addr & 0xffffffff);
	/* 32:dst_addr high 32bit */
	entry->dst_addr_h	= (uint32_t)(sdma_sqe->dst_addr >> 32);
	entry->length_move	= sdma_sqe->length;
	entry->sns		= 1;
	entry->dns		= 1;
	entry->comp_en		= 1;
	entry->mpamns		= 1;
	entry->sssv		= 1;
	entry->dssv		= 1;
	entry->src_substreamid	= sdma_sqe->src_process_id;
	entry->dst_substreamid	= sdma_sqe->dst_process_id;
	entry->sqe_id		= sq_tail;
	entry->src_stride_len	= sdma_sqe->src_stride_len;
	entry->dst_stride_len	= sdma_sqe->dst_stride_len;
	entry->stride_num	= sdma_sqe->stride_num;
	entry->stride		= sdma_sqe->stride_num ? 1 : 0;
	entry->mpam_partid	= sdma_sqe->mpam_partid;
	entry->pmg		= sdma_sqe->pmg;
	entry->qos		= sdma_sqe->qos;
}

static int sdma_safe_mode_fill_task(sdma_handle_t *pchan, sdma_sqe_task_t *sdma_sqe, uint32_t count,
				    uint32_t *req_cnt)
{
	struct hisi_sdma_task_info task_info = {0};
	int ret = 0;

	task_info.task_cnt = count;
	task_info.chn = pchan->chn;
	task_info.task_addr = (uintptr_t)(void *)sdma_sqe;
	if (req_cnt) {
		task_info.req_cnt = *req_cnt;
	}
	ret = ioctl(pchan->fd, IOCTL_SDMA_SEND_TASK, &task_info);
	if (ret != 0) {
		SDMA_ERR("IOCTL_SDMA_SEND_TASK failed to execute,%s!\n", strerror(errno));
		return ret;
	}
	if (req_cnt) {
		*req_cnt = task_info.req_cnt;
	}

	return ret;
}

static int sdma_send_task_kernel(sdma_handle_t *pchan, sdma_sqe_task_t *sdma_sqe, uint32_t count,
				 uint32_t *req_cnt)
{
	sdma_sqe_task_t *task = sdma_sqe;
	uint32_t send_task_cnt = count;
	uint32_t tmp_cnt;
	int ret;

	while (send_task_cnt != 0) {
		tmp_cnt = send_task_cnt;
		if ((send_task_cnt * sizeof(sdma_sqe_task_t)) > HISI_SDMA_MAX_ALLOC_SIZE) {
			tmp_cnt = HISI_SDMA_MAX_ALLOC_SIZE / sizeof(sdma_sqe_task_t);
		}
		send_task_cnt -= tmp_cnt;
		ret = sdma_safe_mode_fill_task(pchan, task, tmp_cnt, req_cnt);
		if (ret != 0) {
			SDMA_ERR("sdma_fill_task failed!\n");
			return ret;
		}
		task += tmp_cnt;
	}

	return SDMA_SUCCESS;
}

static int sdma_copy_safe_mode(sdma_handle_t *pchan, sdma_sqe_task_t *sdma_sqe, uint16_t sq_tail,
			       uint32_t count)
{
	sdma_sqe_task_t *task;
	uint16_t tail;
	uint32_t i;

	task = sdma_sqe;
	tail = sq_tail;
	for (i = 0; i < count; i++) {
		pchan->q_data.task_cb[tail] = task->task_cb;
		pchan->q_data.task_data[tail] = task->task_data;
		tail = (tail + 1) & (HISI_SDMA_SQ_LEN - 1);
		task = task->next_sqe;
	}

	return sdma_send_task_kernel(pchan, sdma_sqe, count, NULL);
}

static int sdma_copy_fast_mode(sdma_handle_t *pchan, sdma_sqe_task_t *sdma_sqe, uint16_t sq_tail, uint32_t count)
{
	struct hisi_sdma_sq_entry *entry;
	sdma_sqe_task_t *task;
	uint32_t tail;
	uint32_t i;
	int ret;

	task = sdma_sqe;
	tail = sq_tail;
	for (i = 0; i < count; i++) {
		entry = pchan->sqe + tail;
		fill_sdma_tasks(entry, pchan, task, tail);
		pchan->q_data.task_cb[tail] = task->task_cb;
		pchan->q_data.task_data[tail] = task->task_data;
		tail = (tail + 1) & (HISI_SDMA_SQ_LEN - 1);
		task = task->next_sqe;
	}
	ret = pchan->funcs[SDMA_SQ_TAIL_WRITE].reg_func(pchan, &tail);
	if (ret != 0) {
		SDMA_ERR("write sq_tail failed, ret = %d\n", ret);
		return SDMA_FAILED;
	}
	pchan->sync_info->sq_tail = (uint16_t)tail;

	return SDMA_SUCCESS;
}

int sdma_copy_data(void *phandle, sdma_sqe_task_t *sdma_sqe, uint32_t count)
{
	sdma_sqe_task_t *task;
	sdma_handle_t *pchan;
	uint16_t sq_tail;
	uint32_t i;
	int ret;

	ret = sdma_check_handle(phandle);
	if (ret != 0) {
		return ret;
	}

	pchan = (sdma_handle_t *)phandle;
	sq_tail = pchan->sync_info->sq_tail;

	if (!sdma_sqe) {
		SDMA_ERR("sdma_sqe empty\n");
		return SDMA_NULL_POINTER;
	}

	if (count == 0) {
		SDMA_ERR("sdma task count = 0\n");
		return SDMA_FAILED;
	}

	for (i = 0, task = sdma_sqe; i < count; i++) {
		if (task->length == 0) {
			SDMA_ERR("sdma task[%u] data length = 0\n", i);
			return SDMA_FAILED;
		}
		task = task->next_sqe;
	}

	if (count > sdma_query_sqe_num(pchan)) {
		SDMA_ERR("sdma sqe number = %u is overflow!\n", count);
		return SDMA_FAILED;
	}

	if (g_sdma_mode == HISI_SDMA_FAST_MODE) {
		return sdma_copy_fast_mode(pchan, sdma_sqe, sq_tail, count);
	} else {
		ret = sdma_copy_safe_mode(pchan, sdma_sqe, sq_tail, count);
		if (ret != 0) {
			SDMA_ERR("sdma copy under safe mode failed!\n");
			return SDMA_FAILED;
		}
 	}

	return SDMA_SUCCESS;
}

static void sdma_exec_callback_func(sdma_handle_t *pchan, uint32_t sqe_id, int sqe_status)
{
	sdma_task_callback task_cb;
	void *task_data;

	task_cb = pchan->q_data.task_cb[sqe_id];
	if (task_cb) {
		task_data = pchan->q_data.task_data[sqe_id];
		task_cb(sqe_status, task_data);
	} else {
		SDMA_DBG("chn%u task callback function is NULL, sqe_id = %u, status = %d\n",
			pchan->chn, sqe_id, sqe_status);
	}
}

int sdma_progress(void *phandle)
{
	uint32_t sq_head, cq_head, cq_vld, sqe_id, flag = 0, num = 0, i = 0;
	struct hisi_sdma_cq_entry *cq_entry;
	sdma_handle_t *pchan;
	int sqe_status, ret;

	ret = sdma_check_handle(phandle);
	if (ret != 0)
		return ret;
	pchan = (sdma_handle_t *)phandle;

	sq_head = pchan->sync_info->sq_head;
	cq_head = pchan->sync_info->cq_head;
	cq_vld = pchan->sync_info->cq_vld;
	num = sdma_task_num(pchan->sync_info->sq_head, pchan->sync_info->sq_tail);
	while (i++ < HISI_SDMA_CQE_TIMEOUT && num > 0) {
		cq_entry = pchan->cqe + cq_head;
		if (cq_vld != cq_entry->vld)
			continue;
		SDMA_RMB();
		flag = 1;
		sqe_id = cq_entry->sqe_id;
		sqe_status = cq_entry->status ? cqe_err_code(cq_entry->status) : 0;
		sdma_exec_callback_func(pchan, sqe_id, sqe_status);
		sq_head = (sq_head + 1) & (HISI_SDMA_SQ_LEN - 1);
		cq_head = (cq_head + 1) & (HISI_SDMA_CQ_LEN - 1);
		if (cq_head == 0) {
			cq_vld ^= 1;
		}
		num--;
	}

	if (flag) {
		ret = pchan->funcs[SDMA_CQ_HEAD_WRITE].reg_func(pchan, &cq_head);
		if (ret != 0) {
			SDMA_ERR("write cq_head failed, ret = %d\n", ret);
			return SDMA_FAILED;
		}
		pchan->sync_info->sq_head = sq_head;
		pchan->sync_info->cq_head = cq_head;
		pchan->sync_info->cq_tail = cq_head;
		pchan->sync_info->cq_vld = cq_vld;
	}

	return SDMA_SUCCESS;
}

static int icopy_check_input(void *phandle, sdma_sqe_task_t *sdma_sqe, uint32_t count,
			     sdma_request_t *request)
{
	int ret;

	ret = sdma_check_handle(phandle);
	if (ret != 0) {
		return ret;
	}
	if (!sdma_sqe || !request) {
		SDMA_ERR("sdma request/sdma_sqe is NULL!\n");
		return SDMA_NULL_POINTER;
	}

	if (count == 0) {
		SDMA_ERR("sdma sqe number = 0\n");
		return SDMA_FAILED;
	}

	return SDMA_SUCCESS;
}

static int sdma_icopy_fast_mode(sdma_handle_t *pchan, sdma_sqe_task_t *sdma_sqe, uint16_t sq_tail,
				 uint32_t count, sdma_request_t *request)
{
	struct hisi_sdma_sq_entry *entry = NULL;
	uint32_t tail;
	uint32_t i;
	int ret;

	tail = sq_tail;
	for (i = 0; i < count; i++) {
		if (sdma_sqe[i].length == 0) {
			request->req_cnt--;
			continue;
		}
		entry = pchan->sqe + tail;
		fill_sdma_tasks(entry, pchan, &sdma_sqe[i], tail);
		tail = (tail + 1) & (HISI_SDMA_SQ_LEN - 1);
	}

	ret = pchan->funcs[SDMA_SQ_TAIL_WRITE].reg_func(pchan, &tail);
	if (ret != 0) {
		SDMA_ERR("write sq_tail failed, ret = %d\n", ret);
		return SDMA_FAILED;
	}
	pchan->sync_info->sq_tail = (uint16_t)tail;

	return SDMA_SUCCESS;
}

int sdma_icopy_data(void *phandle, sdma_sqe_task_t *sdma_sqe, uint32_t count,
		    sdma_request_t *request)
{
	sdma_handle_t *pchan = NULL;
	uint16_t sq_tail, req_id;
	int ret;

	ret = icopy_check_input(phandle, sdma_sqe, count, request);
	if (ret != 0) {
		return ret;
	}

	pchan = (sdma_handle_t *)phandle;
	sdma_lock_chn(&pchan->sync_info->lock, &pchan->sync_info->lock_pid);
	sq_tail = pchan->sync_info->sq_tail;
	req_id = pchan->sync_info->sq_tail;
	request->req_id = req_id;
	request->req_cnt = count;
	request->round_cnt = pchan->sync_info->round_cnt[req_id];

	if (count > sdma_query_sqe_num(pchan)) {
		sdma_unlock_chn(&pchan->sync_info->lock, &pchan->sync_info->lock_pid);
		SDMA_ERR("sdma sqe number = %u is overflow!\n", count);
		return SDMA_FAILED;
	}

	if (g_sdma_mode == HISI_SDMA_FAST_MODE) {
		ret = sdma_icopy_fast_mode(pchan, sdma_sqe, sq_tail, count, request);
	} else {
		ret = sdma_send_task_kernel(pchan, sdma_sqe, count, &request->req_cnt);
		if (ret != 0) {
			sdma_unlock_chn(&pchan->sync_info->lock, &pchan->sync_info->lock_pid);
			SDMA_ERR("sdma icopy under safe mode failed\n");
			return SDMA_FAILED;
		}
 	}
	sdma_unlock_chn(&pchan->sync_info->lock, &pchan->sync_info->lock_pid);

	return ret;
}

int sdma_get_process_id(int fd, uint32_t *id)
{
	int ret;

	if (!id) {
		SDMA_ERR("sdma input id is NULL!\n");
		return SDMA_NULL_POINTER;
	}
	ret = ioctl(fd, IOCTL_SDMA_GET_PROCESS_ID, id);
	if (ret != 0) {
		SDMA_ERR("IOCTL_SDMA_GET_PROCESS_ID fail, %s!\n", strerror(errno));
		return SDMA_FAILED;
	}

	return SDMA_SUCCESS;
}

int sdma_free_chn(void *phandle)
{
	sdma_handle_t *pchan = NULL;
	int ret;

	ret = sdma_check_handle(phandle);
	if (ret != 0) {
		return ret;
	}
	pchan = (sdma_handle_t *)phandle;
	sdma_munmap_chn(pchan);

	ret = ioctl(pchan->fd, IOCTL_SDMA_PUT_CHN, &(pchan->chn));
	if (ret != 0) {
		SDMA_ERR("IOCTL_SDMA_PUT_CHN fail,%s!\n", strerror(errno));
		return SDMA_FAILED;
	}
	free(phandle);

	return ret;
}

int sdma_deinit_chn(void *phandle)
{
	struct hisi_sdma_share_chn share_chn;
	sdma_handle_t *pchan = NULL;
	int ret;

	ret = sdma_check_handle(phandle);
	if (ret != 0) {
		return ret;
	}
	pchan = (sdma_handle_t *)phandle;
	sdma_munmap_chn(pchan);

	share_chn.chn_idx = (uint16_t)pchan->chn;
	share_chn.init_flag = false;
	ret = ioctl(pchan->fd, IOCTL_SDMA_CHN_USED_REFCOUNT, &share_chn);
	if (ret != 0) {
		SDMA_ERR("IOCTL_SDMA_CHN_USED_REFCOUNT fail,%s!\n", strerror(errno));
		return SDMA_FAILED;
	}
	free(phandle);

	return SDMA_SUCCESS;
}

int sdma_query_sqe_num(void *phandle)
{
	sdma_handle_t *pchan = NULL;
	uint32_t tail;
	uint32_t head;
	uint32_t num;
	int ret;

	ret = sdma_check_handle(phandle);
	if (ret != 0) {
		return ret;
	}
	pchan = (sdma_handle_t *)phandle;
	tail = pchan->sync_info->sq_tail;
	head = pchan->sync_info->sq_head;

	if (tail >= head) {
		num = HISI_SDMA_SQ_LEN - (tail - head) - 1;
	} else {
		num = head - tail - 1;
	}

	return (int)num;
}

int sdma_devices_num(int fd)
{
	int ret;
	int num;

	ret = ioctl(fd, IOCTL_GET_SDMA_NUM, &num);
	if (ret != 0) {
		SDMA_ERR("IOCTL_GET_SDMA_NUM fail,%s!\n", strerror(errno));
		return SDMA_FAILED;
	}

	return num;
}

int sdma_nearest_id(void)
{
	int id;
	int fd;

	fd = open("/dev/sdma0", O_RDWR);
	if (fd < 0) {
		SDMA_ERR("Open SDMA fail:%s\n", strerror(errno));
		return SDMA_FAILED;
	}

	if (ioctl(fd, IOCTL_GET_NEAR_SDMAID, &id) != 0) {
		SDMA_ERR("IOCTL_GET_NEAR_SDMAID fail,%s!\n", strerror(errno));
		close(fd);
		return SDMA_FAILED;
	}
	close(fd);

	return id;
}

int sdma_finish_sqe_cnt(void *phandle, bool clr)
{
	uint32_t normal_sqe_cnt;
	sdma_handle_t *pchan;
	uint32_t dfx_reg;
	int ret;

	ret = sdma_check_handle(phandle);
	if (ret != 0) {
		return ret;
	}
	pchan = (sdma_handle_t *)phandle;
	ret = pchan->funcs[SDMA_DFX_REG_READ].reg_func(pchan, &dfx_reg);
	if (ret != 0) {
		SDMA_ERR("read dfx register failed, ret = %d\n", ret);
		return SDMA_FAILED;
	}
	normal_sqe_cnt = dfx_reg >> NORMAL_SQE_SHIFT;

	if (clr) {
		ret = pchan->funcs[SDMA_CLR_NORM_CNT].reg_func(pchan, 0);
		if (ret != 0) {
			SDMA_ERR("clear dfx normal count failed, ret = %d\n", ret);
			return SDMA_FAILED;
		}
		return SDMA_SUCCESS;
	}

	return (int)normal_sqe_cnt;
}

int sdma_err_sqe_cnt(void *phandle, bool clr)
{
	uint32_t err_sqe_cnt;
	sdma_handle_t *pchan;
	uint32_t dfx_reg;
	int ret;

	ret = sdma_check_handle(phandle);
	if (ret != 0) {
		return ret;
	}
	pchan = (sdma_handle_t *)phandle;
	ret = pchan->funcs[SDMA_DFX_REG_READ].reg_func(pchan, &dfx_reg);
	if (ret != 0) {
		SDMA_ERR("read dfx register failed, ret = %d\n", ret);
		return SDMA_FAILED;
	}
	err_sqe_cnt = dfx_reg & ERR_SQE_MASK;

	if (clr) {
		pchan->sync_info->err_cnt = 0;
		ret = pchan->funcs[SDMA_CLR_ERR_CNT].reg_func(pchan, 0);
		if (ret != 0) {
			SDMA_ERR("clear dfx error count failed, ret = %d\n", ret);
			return SDMA_FAILED;
		}
		return SDMA_SUCCESS;
	}

	return (int)err_sqe_cnt;
}

int sdma_pin_umem(int fd, void *vma, uint32_t size, uint64_t *cookie)
{
	struct hisi_sdma_umem_info umem_info;
	int ret;

	if (!vma || size == 0) {
		SDMA_ERR("sdma vma/size is NULL!\n");
		return SDMA_NULL_POINTER;
	}

	if (!cookie) {
		SDMA_ERR("sdma cookie is NULL!\n");
		return SDMA_NULL_POINTER;
	}

	umem_info.vma = (uintptr_t)vma;
	umem_info.size = size;
	ret = ioctl(fd, IOCTL_SDMA_PIN_UMEM, &umem_info);
	if (ret != 0) {
		SDMA_ERR("IOCTL_SDMA_PIN_UMEM fail,%s!\n", strerror(errno));
		return SDMA_FAILED;
	}
	*cookie = umem_info.cookie;
	SDMA_DBG("pin get cookie = %llx\n", *cookie);

	return SDMA_SUCCESS;
}

int sdma_unpin_umem(int fd, uint64_t cookie)
{
	uint64_t ck = cookie;
	int ret;

	SDMA_DBG("unpin cookie = %llx\n", ck);
	ret = ioctl(fd, IOCTL_SDMA_UNPIN_UMEM, &ck);
	if (ret != 0) {
		SDMA_ERR("IOCTL_SDMA_UNPIN_UMEM fail,%s!\n", strerror(errno));
		return SDMA_FAILED;
	}

	return SDMA_SUCCESS;
}

int sdma_mpamid_cfg(int fd, mpam_cfg_t *mpam_cfg)
{
	struct hisi_sdma_mpamcfg cfg = {0};
	int ret;

	if (!mpam_cfg) {
		SDMA_ERR("sdma mpam_cfg is NULL!\n");
		return SDMA_NULL_POINTER;
	}
	cfg.partid = mpam_cfg->mpam_partid;
	cfg.pmg = mpam_cfg->pmg;
	cfg.qos = mpam_cfg->qos;
	cfg.mpamid_replace_en = mpam_cfg->replace_en;

	ret = ioctl(fd, IOCTL_SDMA_MPAMID_CFG, &cfg);
	if (ret != 0) {
		SDMA_ERR("IOCTL_SDMA_MPAMID_CFG fail, %s!\n", strerror(errno));
		return SDMA_FAILED;
	}

	return SDMA_SUCCESS;
}

int sdma_chn_err_info(void *phandle, sdma_chn_err_t *chn_err)
{
	sdma_handle_t *pchan;
	int ret;

	ret = sdma_check_handle(phandle);
	if (ret != 0) {
		return ret;
	}
	if (!chn_err) {
		SDMA_ERR("sdma chn_err is NULL!\n");
		return SDMA_NULL_POINTER;
	}

	pchan = (sdma_handle_t *)phandle;
	chn_err->ch_err_status = pchan->sync_info->ioe.ch_err_status;
	chn_err->ch_cqe_sqeid = pchan->sync_info->ioe.ch_cqe_sqeid;
	chn_err->ch_cqe_status = pchan->sync_info->ioe.ch_cqe_status;

	return SDMA_SUCCESS;
}

int sdma_add_authority(int fd, uint32_t *id_list, uint32_t num)
{
	struct hisi_sdma_pid_info info;
	int ret;

	if (!id_list) {
		SDMA_ERR("sdma id_list is NULL!\n");
		return SDMA_NULL_POINTER;
	}
	info.num = num;
	info.pid_list_addr = (uintptr_t)(void *)id_list;
	ret = ioctl(fd, IOCTL_SDMA_ADD_AUTH_HT, &info);
	if (ret != 0) {
		SDMA_ERR("IOCTL_SDMA_ADD_OWNER fail, %s!\n", strerror(errno));
		return SDMA_FAILED;
	}

	return SDMA_SUCCESS;
}