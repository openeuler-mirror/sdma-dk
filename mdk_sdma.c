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
#include <pthread.h>
#include <errno.h>

#include "hisi_sdma.h"
#include "mdk_sdma.h"

#define CQE_ERR_CODE_BASE (-100000)
#define NORMAL_SQE_CNT 16
#define ERR_SQE_CNT 0
#define SDMA_CQ_SIZE 0x100
#define SDMA_SYNC_INFO_SIZE 0x100
#define SDMA_SEND_TASK_TIMES 2

#define sdma_err(fmt, args...) \
	printf("SDMA ERROR (%s|%u): " fmt, __FUNCTION__, __LINE__, ##args)

#ifdef USRTEST
#define sdma_dbg(fmt, args...) \
	printf("SDMA DEBUG (%s|%u): " fmt, __FUNCTION__, __LINE__, ##args)
#else
#define sdma_dbg(fmt, args...)
#endif

typedef struct sdma_handle {
	int fd;
	int chn;
	struct hisi_sdma_sq_entry *sqe;
	struct hisi_sdma_cq_entry *cqe;
	struct hisi_sdma_queue_info *sync_info;
	struct hisi_sdma_queue_data q_data;
	uint32_t chan_qe_depth;
	uint16_t streamid;
	void *io_align_base;
	void *io_base;
	struct sdma_ioctl_funcs *funcs;
} sdma_handle_t;

typedef uint32_t (*sdma_reg_func)(const sdma_handle_t *pchan, uint32_t reg_val);
struct sdma_ioctl_funcs {
	unsigned int cmd;
	sdma_reg_func reg_func;
};

static size_t g_page_size = 0;
typedef struct hisi_sdma_cq_entry sdma_cq_entry_t;

static uint32_t sdma_get_sq_head_ioctl(const sdma_handle_t *pchan, uint32_t reg_val SDMA_UNUSED)
{
	struct hisi_sdma_reg_info reg_info = {0};

	reg_info.chn = pchan->chn;
	reg_info.type = HISI_SDMA_READ_REG;
	if (ioctl(pchan->fd, IOCTL_SDMA_SQ_HEAD_REG, &reg_info) != 0) {
		sdma_err("IOCTL_SDMA_SQ_HEAD_REG fail,%s!\n", strerror(errno));
	}

	return reg_info.reg_value;
}

static uint32_t sdma_get_sq_tail_ioctl(const sdma_handle_t *pchan, uint32_t reg_val SDMA_UNUSED)
{
	struct hisi_sdma_reg_info reg_info = {0};

	reg_info.chn = pchan->chn;
	reg_info.type = HISI_SDMA_READ_REG;
	if (ioctl(pchan->fd, IOCTL_SDMA_SQ_TAIL_REG, &reg_info) != 0) {
		sdma_err("IOCTL_SDMA_SQ_TAIL_REG fail,%s!\n", strerror(errno));
	}

	return reg_info.reg_value;
}

static uint32_t sdma_set_sq_tail_ioctl(const sdma_handle_t *pchan, uint32_t reg_val)
{
	struct hisi_sdma_reg_info reg_info = {0};

	reg_info.chn = pchan->chn;
	reg_info.type = HISI_SDMA_WRITE_REG;
	reg_info.reg_value = reg_val;
	if (ioctl(pchan->fd, IOCTL_SDMA_SQ_TAIL_REG, &reg_info) != 0) {
		sdma_err("IOCTL_SDMA_SQ_TAIL_REG fail,%s!\n", strerror(errno));
	}

	return 0;
}

static uint32_t sdma_get_cq_head_ioctl(const sdma_handle_t *pchan, uint32_t reg_val SDMA_UNUSED)
{
	struct hisi_sdma_reg_info reg_info = {0};

	reg_info.chn = pchan->chn;
	reg_info.type = HISI_SDMA_READ_REG;
	if (ioctl(pchan->fd, IOCTL_SDMA_CQ_HEAD_REG, &reg_info) != 0) {
		sdma_err("IOCTL_SDMA_CQ_HEAD_REG fail,%s!\n", strerror(errno));
	}

	return reg_info.reg_value;
}

static uint32_t sdma_set_cq_head_ioctl(const sdma_handle_t *pchan, uint32_t reg_val)
{
	struct hisi_sdma_reg_info reg_info = {0};

	reg_info.chn = pchan->chn;
	reg_info.type = HISI_SDMA_WRITE_REG;
	reg_info.reg_value = reg_val;
	if (ioctl(pchan->fd, IOCTL_SDMA_CQ_HEAD_REG, &reg_info) != 0) {
		sdma_err("IOCTL_SDMA_CQ_HEAD_REG fail,%s!\n", strerror(errno));
	}

	return 0;
}

static uint32_t sdma_get_cq_tail_ioctl(const sdma_handle_t *pchan, uint32_t reg_val SDMA_UNUSED)
{
	struct hisi_sdma_reg_info reg_info = {0};

	reg_info.chn = pchan->chn;
	reg_info.type = HISI_SDMA_READ_REG;
	if (ioctl(pchan->fd, IOCTL_SDMA_CQ_TAIL_REG, &reg_info) != 0) {
		sdma_err("IOCTL_SDMA_CQ_TAIL_REG fail,%s!\n", strerror(errno));
	}

	return reg_info.reg_value;
}

static uint32_t sdma_get_dfx_reg_ioctl(const sdma_handle_t *pchan, uint32_t reg_val SDMA_UNUSED)
{
	struct hisi_sdma_reg_info reg_info = {0};

	reg_info.chn = pchan->chn;
	if (ioctl(pchan->fd, IOCTL_SDMA_DFX_REG, &reg_info) != 0) {
		sdma_err("IOCTL_SDMA_DFX_REG fail,%s!\n", strerror(errno));
	}

	return reg_info.reg_value;
}

static uint32_t sdma_clr_normal_sqe_cnt_ioctl(const sdma_handle_t *pchan,
					      uint32_t reg_val SDMA_UNUSED)
{
	struct hisi_sdma_reg_info clr_info = {0};

	clr_info.chn = pchan->chn;
	clr_info.type = HISI_SDMA_CLR_NORMAL_SQE_CNT;
	if (ioctl(pchan->fd, IOCTL_SDMA_SQE_CNT_REG, &clr_info) != 0) {
		sdma_err("IOCTL_SDMA_SQE_CNT_REG fail,%s!\n", strerror(errno));
	}

	return 0;
}

static uint32_t sdma_clr_err_sqe_cnt_ioctl(const sdma_handle_t *pchan, uint32_t reg_val SDMA_UNUSED)
{
	struct hisi_sdma_reg_info clr_info = {0};

	clr_info.chn = pchan->chn;
	clr_info.type = HISI_SDMA_CLR_ERR_SQE_CNT;
	if (ioctl(pchan->fd, IOCTL_SDMA_SQE_CNT_REG, &clr_info) != 0) {
		sdma_err("IOCTL_SDMA_SQE_CNT_REG fail,%s!\n", strerror(errno));
	}

	return 0;
}

struct sdma_ioctl_funcs g_sdma_ioctl_list[] = {
	{SDMA_SQ_HEAD_READ, sdma_get_sq_head_ioctl},
	{SDMA_SQ_TAIL_READ, sdma_get_sq_tail_ioctl},
	{SDMA_SQ_TAIL_WRITE, sdma_set_sq_tail_ioctl},
	{SDMA_CQ_HEAD_READ, sdma_get_cq_head_ioctl},
	{SDMA_CQ_HEAD_WRITE, sdma_set_cq_head_ioctl},
	{SDMA_CQ_TAIL_READ, sdma_get_cq_tail_ioctl},
	{SDMA_DFX_REG_READ, sdma_get_dfx_reg_ioctl},
	{SDMA_CLR_NORM_CNT, sdma_clr_normal_sqe_cnt_ioctl},
	{SDMA_CLR_ERR_CNT, sdma_clr_err_sqe_cnt_ioctl},
};

static uint32_t sdma_channel_get_finish_count(sdma_handle_t *pchan)
{
	uint32_t head, head_before;

	head = pchan->funcs[SDMA_SQ_HEAD_READ].reg_func(pchan, 0);
	head_before = pchan->sync_info->sq_head;

	if (head < head_before) {
		return (head + HISI_SDMA_SQ_LEN - head_before) & (pchan->chan_qe_depth - 1);
	}

	return (head - head_before) & (pchan->chan_qe_depth - 1);
}

static int sdma_lock_chn(volatile int *lock, uint32_t *lock_pid)
{
	int i = 0;

	while (__sync_bool_compare_and_swap(lock, 0, 1) != 1) {
		sched_yield();
		i++;
		if (i > HISI_SDMA_LOCK_TIMEOUT_US) {
			return SDMA_LOCK_TIMEOUT;
		}
	}
	*lock_pid = (uint32_t)getpid();

	return SDMA_SUCCESS;
}

static void sdma_unlock_chn(volatile int *lock, uint32_t *lock_pid)
{
	*lock = 0;
	*lock_pid = 0;
}

int sdma_check_handle(void *phandle)
{
	sdma_handle_t *pchan;

	if (!phandle) {
		sdma_err("sdma channel handle is NULL!\n");
		return SDMA_NULL_POINTER;
	}

	pchan = (sdma_handle_t *)phandle;
	if (!pchan->cqe || !pchan->sync_info || !pchan->funcs) {
		sdma_err("sdma handle content invalid!\n");
		return SDMA_NULL_POINTER;
	}

	return SDMA_SUCCESS;
}

int sdma_query_chn(void *phandle, uint32_t count)
{
	uint32_t sq_finish_count;
	sdma_handle_t *pchan;
	int ret;

	ret = sdma_check_handle(phandle);
	if (ret != 0) {
		return ret;
	}
	pchan = (sdma_handle_t *)phandle;
	sq_finish_count = sdma_channel_get_finish_count(pchan);
	if (sq_finish_count >= count) {
		return SDMA_SUCCESS;
	}

	return SDMA_TASK_UNFINISH;
}

static void update_round_cnt(sdma_handle_t *pchan, uint16_t hardware_cq_tail)
{
	sdma_cq_entry_t *cq_entry = NULL;
	uint16_t cq_head;

	cq_head = pchan->sync_info->cq_head;
	while (cq_head != hardware_cq_tail) {
		cq_entry = pchan->cqe + cq_head;
		if (cq_entry->status != 0) {
			sdma_err("cq_entry invalid, status: %u\n", cq_entry->status);
			pchan->sync_info->cqe_err[cq_head] = (int)cq_entry->status;
			__sync_fetch_and_add(&pchan->sync_info->err_cnt, 1);
		}

		pchan->sync_info->round_cnt[cq_head]++;
		cq_head++;
	}

	pchan->sync_info->cq_tail = hardware_cq_tail;
	pchan->sync_info->cq_head = cq_head;
	/* iwait模式 软件的CQ HEAD和SQ HEAD应保持一致 */
	pchan->sync_info->sq_head = pchan->sync_info->cq_head;
	(void)pchan->funcs[SDMA_CQ_HEAD_WRITE].reg_func(pchan, pchan->sync_info->cq_head);
}

static bool rndcnt_invalid(const sdma_handle_t *pchan, uint32_t last_req_cqe, uint32_t round_cnt)
{
	if (last_req_cqe < HISI_SDMA_CQ_LEN) {
		if (pchan->sync_info->round_cnt[last_req_cqe] <= round_cnt) {
			return true;
		}
	} else if (pchan->sync_info->round_cnt[last_req_cqe % HISI_SDMA_CQ_LEN] <= round_cnt + 1) {
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
		return 0;
	}

	for (i = 0; i < req_cnt; i++) {
		cqe_id = (req_id + i) % HISI_SDMA_CQ_LEN;
		if (pchan->sync_info->cqe_err[cqe_id] != 0) {
			sdma_err("cqe%u error status = %d\n", req_id + i,
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
		sdma_err("sdma request is NULL!\n");
		return SDMA_NULL_POINTER;
	}

	if (request->req_cnt == 0) {
		return SDMA_SUCCESS;
	}

	pchan = (sdma_handle_t *)phandle;

	ret = sdma_lock_chn(&pchan->sync_info->lock, &pchan->sync_info->lock_pid);
	if (ret != 0) {
		return ret;
	}

	hardware_cq_tail = pchan->funcs[SDMA_CQ_TAIL_READ].reg_func(pchan, 0);
	update_round_cnt(pchan, (uint16_t)hardware_cq_tail);

	sdma_unlock_chn(&pchan->sync_info->lock, &pchan->sync_info->lock_pid);

	return sdma_request_check(pchan, request);
}

static int sdma_get_mmap_size(uint32_t depth, size_t *cqe, size_t *sync)
{
	g_page_size = (size_t)getpagesize();
	if (g_page_size < HISI_SDMA_REG_SIZE) {
		return SDMA_FAILED;
	}

	*cqe = (size_t)((depth * sizeof(struct hisi_sdma_cq_entry) + g_page_size - 1) /
		g_page_size * g_page_size);
	*sync = (size_t)((sizeof(struct hisi_sdma_queue_info) + g_page_size - 1) /
		g_page_size * g_page_size);

	return 0;
}

static int sdma_mmap(uint32_t chn_num, sdma_handle_t *phandle, size_t cqe_size, size_t sync_size)
{
	off_t offset;
	void *ptr;

	/* The offset of the mapped cqe memory ranges is [chn_num, 2*chn_num] * pagesize */
	offset = (off_t)(((uint32_t)phandle->chn + chn_num * HISI_SDMA_MMAP_CQE) * g_page_size);
	ptr = mmap(NULL, cqe_size, PROT_READ | PROT_WRITE, MAP_SHARED, phandle->fd, offset);
	if (ptr == MAP_FAILED) {
		sdma_err("mmap cqe failed\n");
		return SDMA_FAILED;
	}
	phandle->cqe = (sdma_cq_entry_t *)ptr;

	/* The offset of the mapped io_register ranges is [3*chn_num, 4*chn_num] * pagesize */
	offset = (off_t)((chn_num * HISI_SDMA_MMAP_SHMEM + (uint32_t)phandle->chn) * g_page_size);
	ptr = mmap(NULL, sync_size, PROT_READ | PROT_WRITE, MAP_SHARED, phandle->fd, offset);
	if (ptr == MAP_FAILED) {
		sdma_err("mmap sync info failed\n");
		goto unmap_io;
	}
	phandle->sync_info = (struct hisi_sdma_queue_info *)ptr;

	return SDMA_SUCCESS;

unmap_io:
	if (phandle->io_align_base) {
		munmap(phandle->io_align_base, g_page_size);
	}
unmap_cqe:
	if (phandle->cqe) {
		munmap(phandle->cqe, cqe_size);
	}

	return SDMA_FAILED;
}

static void sdma_munmap_chn(sdma_handle_t *phandle)
{
	size_t cqe_size, sync_size;
	int ret;

	ret = sdma_get_mmap_size(phandle->chan_qe_depth, &cqe_size, &sync_size);
	if (ret < 0) {
		sdma_err("get mmap size failed\n");
		return;
	}

	if (phandle->cqe) {
		munmap(phandle->cqe, cqe_size);
	}
	if (phandle->io_align_base) {
		munmap(phandle->io_align_base, g_page_size);
	}
	if (phandle->sync_info) {
		munmap(phandle->sync_info, sync_size);
	}
}

static int sdma_mmap_chn(uint32_t chn_num, sdma_handle_t *phandle)
{
	size_t cqe_size, sync_size;
	int ret;

	phandle->chan_qe_depth = HISI_SDMA_SQ_LEN;
	ret = sdma_get_mmap_size(phandle->chan_qe_depth, &cqe_size, &sync_size);
	if (ret < 0) {
		sdma_err("get mmap size failed\n");
		return SDMA_FAILED;
	}

	if (cqe_size > (SDMA_CQ_SIZE * g_page_size) ||
		sync_size > (SDMA_SYNC_INFO_SIZE * g_page_size)) {
		sdma_err("invalid mmap size\n");
		return SDMA_FAILED;
	}

	ret = sdma_mmap(chn_num, phandle, cqe_size, sync_size);
	if (ret < 0) {
		sdma_err("sdma mmap failed, ret = %d\n", ret);
		return SDMA_FAILED;
	}

	ret = pthread_spin_init(&(phandle->q_data.task_lock), PTHREAD_PROCESS_PRIVATE);
	if (ret != 0) {
		sdma_err("lock init failed, err = %d\n", ret);
		sdma_munmap_chn(phandle);
		return SDMA_FAILED;
	}

	return SDMA_SUCCESS;
}

static int sdma_prep_operations(int fd, struct hisi_sdma_chn_num chn_num, sdma_handle_t *pchan)
{
	uint32_t streamid = 0;

	if (ioctl(fd, IOCTL_SDMA_GET_STREAMID, &streamid) != 0) {
		sdma_err("IOCTL_SDMA_GET_STREAMID fail,%s!\n", strerror(errno));
		return SDMA_FAILED;
	}
	pchan->streamid = (uint16_t)streamid;

	if (sdma_mmap_chn(chn_num.total_chn_num, pchan) != 0) {
		sdma_err("sdma_mmap_chn fail,%s!\n", strerror(errno));
		return SDMA_FAILED;
	}

	pchan->funcs = g_sdma_ioctl_list;

	return 0;
}

void *sdma_alloc_chn(int fd)
{
	struct hisi_sdma_chn_num chn_num;
	sdma_handle_t *pchan = NULL;
	int chn;
	int ret;

	if (ioctl(fd, IOCTL_GET_SDMA_CHN_NUM, &chn_num) != 0) {
		sdma_err("IOCTL_GET_SDMA_CHN_NUM fail,%s!\n", strerror(errno));
		goto err_out;
	}
	if (ioctl(fd, IOCTL_SDMA_GET_CHN, &chn) != 0) {
		sdma_err("IOCTL_SDMA_GET_CHN fail,%s!\n", strerror(errno));
		goto err_out;
	}
	pchan = (sdma_handle_t *)calloc(1, sizeof(sdma_handle_t));
	if (pchan == NULL) {
		sdma_err("calloc pchan failed,%s!\n", strerror(errno));
		ioctl(fd, IOCTL_SDMA_PUT_CHN, &chn);
		goto err_out;
	}
	pchan->chn = chn;
	pchan->fd = fd;
	ret = sdma_prep_operations(fd, chn_num, pchan);
	if (ret != 0) {
		goto err_free;
	}
	pchan->sync_info->sq_head = pchan->funcs[SDMA_SQ_HEAD_READ].reg_func(pchan, 0);
	pchan->sync_info->sq_tail = pchan->funcs[SDMA_SQ_TAIL_READ].reg_func(pchan, 0);
	pchan->sync_info->cq_head = pchan->funcs[SDMA_CQ_HEAD_READ].reg_func(pchan, 0);
	pchan->sync_info->cq_tail = pchan->funcs[SDMA_CQ_TAIL_READ].reg_func(pchan, 0);
	if (pchan->sync_info->sq_head != pchan->sync_info->sq_tail) {
		sdma_err("sdma chn%d SQE unnormal! SQ head = %hu,SQ tail = %hu\n", chn,
			 pchan->sync_info->sq_head, pchan->sync_info->sq_tail);
		goto err_unmap;
	}
	if (pchan->sync_info->cq_head != pchan->sync_info->cq_tail) {
		pchan->sync_info->cq_head = pchan->sync_info->cq_tail;
		(void)pchan->funcs[SDMA_CQ_HEAD_WRITE].reg_func(pchan, pchan->sync_info->cq_head);
	}

	return (void *)pchan;

err_unmap:
	sdma_munmap_chn(pchan);
err_free:
	ioctl(pchan->fd, IOCTL_SDMA_PUT_CHN, &chn);
	free(pchan);
err_out:
	return NULL;
}

void *sdma_init_chn(int fd, int chn)
{
	struct hisi_sdma_share_chn share_chn;
	struct hisi_sdma_chn_num chn_num;
	sdma_handle_t *pchan = NULL;
	int ret;

	ret = ioctl(fd, IOCTL_GET_SDMA_CHN_NUM, &chn_num);
	if (ret != 0) {
		sdma_err("IOCTL_GET_SDMA_CHN_NUM fail,%s!\n", strerror(errno));
		goto err_out;
	}

	pchan = (sdma_handle_t *)calloc(1, sizeof(sdma_handle_t));
	if (pchan == NULL) {
		sdma_err("calloc pchan failed,%s!\n", strerror(errno));
		goto err_out;
	}

	pchan->chn = chn % (int)chn_num.share_chn_num;
	pchan->fd = fd;
	share_chn.chn_idx = pchan->chn;
	share_chn.init_flag = true;
	ret = ioctl(fd, IOCTL_SDMA_CHN_USED_REFCOUNT, &share_chn);
	if (ret != 0) {
		sdma_err("IOCTL_SDMA_CHN_USED_REFCOUNT fail,%s!\n", strerror(errno));
		goto err_free;
	}
	ret = sdma_prep_operations(fd, chn_num, pchan);
	if (ret != 0) {
		goto err_free;
	}

	return (void *)pchan;

err_free:
	free(pchan);
err_out:
	return NULL;
}

static int sdma_fill_task(sdma_handle_t *pchan, sdma_sqe_task_t *sdma_sqe, uint32_t count,
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
		sdma_err("IOCTL_SDMA_SEND_TASK failed to execute,%s!\n", strerror(errno));
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
	int ret;

	if ((count * sizeof(sdma_sqe_task_t)) > HISI_SDMA_MAX_ALLOC_SIZE) {
		ret = sdma_fill_task(pchan, task, send_task_cnt / SDMA_SEND_TASK_TIMES,
				     req_cnt);
		if (ret != 0) {
			sdma_err("sdma_fill_task failed!\n");
			return ret;
		}
		send_task_cnt -= send_task_cnt / SDMA_SEND_TASK_TIMES;
		task += send_task_cnt / SDMA_SEND_TASK_TIMES;
	}
	ret = sdma_fill_task(pchan, task, send_task_cnt, req_cnt);
	if (ret != 0) {
		sdma_err("sdma_fill_task failed!\n");
		return ret;
	}

	return SDMA_SUCCESS;
}

static int sdma_copy(sdma_handle_t *pchan, sdma_sqe_task_t *sdma_sqe, uint16_t sq_tail,
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
		sdma_err("sdma_sqe empty\n");
		return SDMA_NULL_POINTER;
	}

	if (count == 0) {
		sdma_err("sdma task count = 0\n");
		return SDMA_FAILED;
	}

	for (i = 0, task = sdma_sqe; i < count; i++) {
		if (task->length == 0) {
			sdma_err("sdma task[%u] data length = 0\n", i);
			return SDMA_FAILED;
		}
		task = task->next_sqe;
	}

	ret = pthread_spin_lock(&pchan->q_data.task_lock);
	if (ret != 0) {
		sdma_err("sdma failed to get lock\n");
		return ret;
	}

	if (count > (uint32_t)sdma_query_sqe_num(pchan)) {
		pthread_spin_unlock(&pchan->q_data.task_lock);
		sdma_err("sdma sqe number = %u is overflow!\n", count);
		return SDMA_FAILED;
	}

	ret = sdma_copy(pchan, sdma_sqe, sq_tail, count);
	if (ret != 0) {
		pthread_spin_unlock(&pchan->q_data.task_lock);
		sdma_err("sdma copy failed!\n");
		return SDMA_FAILED;
	}

	pthread_spin_unlock(&pchan->q_data.task_lock);

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
		sdma_err("sdma request/sdma_sqe is NULL!\n");
		return SDMA_NULL_POINTER;
	}

	if (count == 0) {
		sdma_err("sdma sqe number = 0\n");
		return SDMA_FAILED;
	}

	return SDMA_SUCCESS;
}

int sdma_icopy_data(void *phandle, sdma_sqe_task_t *sdma_sqe, uint32_t count,
		    sdma_request_t *request)
{
	sdma_handle_t *pchan = NULL;
	uint16_t req_id, sq_tail;
	int ret;

	ret = icopy_check_input(phandle, sdma_sqe, count, request);
	if (ret != 0) {
		return ret;
	}

	pchan = (sdma_handle_t *)phandle;
	if (pchan->sync_info->err_cnt != 0) {
		sdma_err("sdma err happend!\n");
		return SDMA_FAILED;
	}

	ret = sdma_lock_chn(&pchan->sync_info->lock, &pchan->sync_info->lock_pid);
	if (ret != 0) {
		sdma_err("sdma lock chn failed!\n");
		return ret;
	}
	req_id = pchan->sync_info->sq_tail;
	sq_tail = pchan->sync_info->sq_tail;
	request->req_id = req_id;
	request->req_cnt = count;
	request->round_cnt = pchan->sync_info->round_cnt[req_id];

	if (count > (uint32_t)sdma_query_sqe_num(pchan)) {
		sdma_unlock_chn(&pchan->sync_info->lock, &pchan->sync_info->lock_pid);
		sdma_err("sdma sqe number = %u is overflow!\n", count);
		return SDMA_FAILED;
	}

	ret = sdma_send_task_kernel(pchan, sdma_sqe, count, &request->req_cnt);
	if (ret != 0) {
		sdma_unlock_chn(&pchan->sync_info->lock, &pchan->sync_info->lock_pid);
		sdma_err("sdma icopy failed\n");
		return SDMA_FAILED;
	}

	sdma_unlock_chn(&pchan->sync_info->lock, &pchan->sync_info->lock_pid);

	return SDMA_SUCCESS;
}

int sdma_get_process_id(int fd, uint32_t *id)
{
	int ret;

	if (!id) {
		sdma_err("sdma input id is NULL!\n");
		return SDMA_NULL_POINTER;
	}
	ret = ioctl(fd, IOCTL_SDMA_GET_PROCESS_ID, id);
	if (ret != 0) {
		sdma_err("IOCTL_SDMA_GET_PROCESS_ID fail, %s!\n", strerror(errno));
		return SDMA_FAILED;
	}

	return SDMA_SUCCESS;
}

static void reset_rndcnt(sdma_handle_t *pchan)
{
	uint32_t *rndcnt;
	uint32_t head;
	uint32_t i;

	head = pchan->funcs[SDMA_SQ_HEAD_READ].reg_func(pchan, 0);
	if (pchan->sync_info->sq_tail < pchan->sync_info->sq_head) {
		pchan->sync_info->cq_vld ^= 1;
	}
	rndcnt = pchan->sync_info->round_cnt;

	memset(rndcnt, 0, sizeof(uint32_t) * HISI_SDMA_SQ_LEN);
	for (i = 0; i < head; i++) {
		rndcnt[i] = 1;
	}
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
	ret = ioctl(pchan->fd, IOCTL_SDMA_PUT_CHN, &(pchan->chn));
	if (ret != 0) {
		sdma_err("IOCTL_SDMA_PUT_CHN fail,%s!\n", strerror(errno));
		return SDMA_FAILED;
	}

	reset_rndcnt(pchan);
	sdma_munmap_chn(pchan);
	pthread_spin_destroy(&pchan->q_data.task_lock);
	free(phandle);
	phandle = NULL;

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
	share_chn.chn_idx = (uint16_t)pchan->chn;
	share_chn.init_flag = false;

	ret = ioctl(pchan->fd, IOCTL_SDMA_CHN_USED_REFCOUNT, &share_chn);
	if (ret != 0) {
		sdma_err("IOCTL_SDMA_CHN_USED_REFCOUNT fail,%s!\n", strerror(errno));
		return SDMA_FAILED;
	}

	sdma_munmap_chn(pchan);
	pthread_spin_destroy(&pchan->q_data.task_lock);
	free(phandle);
	phandle = NULL;

	return SDMA_SUCCESS;
}

int sdma_query_sqe_num(void *phandle)
{
	sdma_handle_t *pchan = NULL;
	int tail;
	int head;
	int num;
	int ret;

	ret = sdma_check_handle(phandle);
	if (ret != 0) {
		return ret;
	}
	pchan = (sdma_handle_t *)phandle;
	tail = (int)pchan->sync_info->sq_tail;
	head = (int)pchan->sync_info->sq_head;

	if (tail >= head) {
		num = (int)pchan->chan_qe_depth - (tail - head) - 1;
	} else {
		num = head - tail - 1;
	}

	return num;
}

int sdma_devices_num(int fd)
{
	int ret;
	int num;

	ret = ioctl(fd, IOCTL_GET_SDMA_NUM, &num);
	if (ret != 0) {
		sdma_err("IOCTL_GET_SDMA_NUM fail,%s!\n", strerror(errno));
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
		sdma_err("Open SDMA fail:%s\n", strerror(errno));
		return SDMA_FAILED;
	}

	if (ioctl(fd, IOCTL_GET_NEAR_SDMAID, &id) != 0) {
		sdma_err("IOCTL_GET_NEAR_SDMAID fail,%s!\n", strerror(errno));
		close(fd);
		return SDMA_FAILED;
	}
	close(fd);

	return id;
}
