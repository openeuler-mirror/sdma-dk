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
