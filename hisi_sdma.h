/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2024. All rights reserved.
 * Description: hisi_sdma.h
 * Author:
 * Create: 2024
 * Notes:
 */
#ifndef __HISI_SDMA_H__
#define __HISI_SDMA_H__

#include <stdint.h>
#include <asm-generic/ioctl.h>
#include <pthread.h>
#include "mdk_sdma.h"

/*
 * CQE TIMEOUT period = 10ns * 1000000000 = 10s
 */
#define HISI_SDMA_CQE_TIMEOUT		1000000000

#define HISI_SDMA_MMAP_CQE		1
#define HISI_SDMA_MMAP_IO		2
#define HISI_SDMA_MMAP_SHMEM		3
#define HISI_SDMA_FSM_TIMEOUT		10

#define HISI_SDMA_SQ_LEN		(1U << 16)
#define HISI_SDMA_CQ_LEN		(1U << 16)
#define HISI_SDMA_REG_SIZE		4096

#define HISI_SDMA_CH_SQTDBR_REG		0x4C
#define HISI_SDMA_CH_SQHDBR_REG		0x50
#define HISI_SDMA_CH_CQTDBR_REG		0x8C
#define HISI_SDMA_CH_CQHDBR_REG		0x90
#define HISI_SDMA_CH_DFX_REG		 0x300

#define ERR_SQE_MASK			0xffff
#define NORMAL_SQE_SHIFT		16
#define HISI_SDMA_READ_REG		1
#define HISI_SDMA_WRITE_REG		2
#define HISI_SDMA_MAX_ALLOC_SIZE	0x400000

#define HISI_SDMA_CLR_NORMAL_SQE_CNT	1
#define HISI_SDMA_CLR_ERR_SQE_CNT	2
#define HISI_SDMA_SRC_H_WIDTH		32

#define SDMA_UNUSED			__attribute__((__unused__))

struct chn_ioe_info {
	uint32_t ch_err_status;
	uint32_t ch_cqe_sqeid;
	uint32_t ch_cqe_status;
};

struct hisi_sdma_chn_num {
	uint32_t total_chn_num;
	uint32_t share_chn_num;
};

struct hisi_sdma_umem_info {
	uintptr_t vma;
	uint32_t size;
	uint64_t cookie;
};

struct hisi_sdma_sq_entry {
	uint32_t opcode			: 8;
	uint32_t sssv			: 1;
	uint32_t dssv			: 1;
	uint32_t sns			: 1;
	uint32_t dns			: 1;
	uint32_t sro			: 1;
	uint32_t dro			: 1;
	uint32_t stride			: 2;
	uint32_t ie			: 1;
	uint32_t comp_en		: 1;
	uint32_t reserved0		: 14;

	uint32_t sqe_id			: 16;
	uint32_t mpam_partid		: 8;
	uint32_t mpamns			: 1;
	uint32_t pmg			: 2;
	uint32_t qos			: 4;
	uint32_t reserved1		: 1;

	uint32_t src_streamid		: 16;
	uint32_t src_substreamid	: 16;
	uint32_t dst_streamid		: 16;
	uint32_t dst_substreamid	: 16;

	uint32_t src_addr_l		: 32;
	uint32_t src_addr_h		: 32;
	uint32_t dst_addr_l		: 32;
	uint32_t dst_addr_h		: 32;

	uint32_t length_move		: 32;

	uint32_t src_stride_len		: 32;
	uint32_t dst_stride_len		: 32;
	uint32_t stride_num		: 32;
	uint32_t reserved2		: 32;
	uint32_t reserved3		: 32;
	uint32_t reserved4		: 32;
	uint32_t reserved5		: 32;
};

struct hisi_sdma_cq_entry {
	uint32_t reserved1;
	uint32_t reserved2;
	uint32_t sqhd			: 16;
	volatile uint32_t sqe_id	: 16;
	uint32_t opcode			: 16;
	volatile uint32_t vld		: 1;
	volatile uint32_t status	: 15;
};

struct hisi_sdma_queue_info {
	uint32_t			sq_head;
	uint32_t			sq_tail;
	uint32_t			cq_head;
	uint32_t			cq_tail;
	uint32_t			cq_vld;
	int				lock;
	uint32_t			lock_pid;
	int				err_cnt;
	int				cqe_err[HISI_SDMA_SQ_LEN];
	uint32_t			round_cnt[HISI_SDMA_SQ_LEN];
	struct chn_ioe_info ioe;
};

struct hisi_sdma_queue_data {
	pthread_spinlock_t task_lock;
	sdma_task_callback task_cb[HISI_SDMA_SQ_LEN];
	void		   *task_data[HISI_SDMA_SQ_LEN];
};

struct hisi_sdma_mpamcfg {
	uint16_t partid			: 8;
	uint16_t pmg			: 2;
	uint16_t qos			: 4;
	uint16_t mpamid_replace_en	: 1;
	uint16_t rsv5			: 1;
};

struct hisi_sdma_share_chn {
	uint16_t chn_idx;
	bool init_flag;
};

struct hisi_sdma_pid_info {
	int num;
	uintptr_t pid_list_addr;
};

struct hisi_sdma_reg_info {
	int chn;
	int type;
	uint32_t reg_value;
};

struct hisi_sdma_task_info {
	int chn;
	uint32_t req_cnt;
	uint32_t task_cnt;
	uintptr_t task_addr;
};

enum sdma_reg_ops {
	SDMA_SQ_HEAD_READ,
	SDMA_SQ_TAIL_READ,
	SDMA_SQ_TAIL_WRITE,
	SDMA_CQ_HEAD_READ,
	SDMA_CQ_HEAD_WRITE,
	SDMA_CQ_TAIL_READ,
	SDMA_DFX_REG_READ,
	SDMA_CLR_NORM_CNT,
	SDMA_CLR_ERR_CNT,
};

#define IOCTL_SDMA_GET_PROCESS_ID	    _IOR('s', 1, uint32_t)
#define IOCTL_SDMA_GET_CHN		    _IOR('s', 2, int)
#define IOCTL_SDMA_PUT_CHN		    _IOW('s', 3, int)
#define IOCTL_SDMA_GET_STREAMID		    _IOR('s', 4, uint32_t)
#define IOCTL_SDMA_PIN_UMEM		    _IOWR('s', 5, struct hisi_sdma_umem_info)
#define IOCTL_SDMA_UNPIN_UMEM		    _IOW('s', 6, uint64_t)
#define IOCTL_GET_SDMA_NUM		    _IOR('s', 7, int)
#define IOCTL_GET_NEAR_SDMAID		    _IOR('s', 8, int)
#define IOCTL_GET_SDMA_CHN_NUM		    _IOR('s', 9, struct hisi_sdma_chn_num)
#define IOCTL_SDMA_MPAMID_CFG		    _IOW('s', 10, struct hisi_sdma_mpamcfg)
#define IOCTL_SDMA_CHN_USED_REFCOUNT	    _IOW('s', 11, struct hisi_sdma_share_chn)
#define IOCTL_SDMA_ADD_AUTH_HT		    _IOW('s', 12, struct hisi_sdma_pid_info)
#define IOCTL_SDMA_SEND_TASK		    _IOWR('s', 13, struct hisi_sdma_task_info)
#define IOCTL_SDMA_SQ_HEAD_REG		    _IOWR('s', 14, struct hisi_sdma_reg_info)
#define IOCTL_SDMA_SQ_TAIL_REG		    _IOWR('s', 15, struct hisi_sdma_reg_info)
#define IOCTL_SDMA_CQ_HEAD_REG		    _IOWR('s', 16, struct hisi_sdma_reg_info)
#define IOCTL_SDMA_CQ_TAIL_REG		    _IOWR('s', 17, struct hisi_sdma_reg_info)
#define IOCTL_SDMA_DFX_REG		    _IOWR('s', 18, struct hisi_sdma_reg_info)
#define IOCTL_SDMA_SQE_CNT_REG		    _IOW('s', 19, struct hisi_sdma_reg_info)

#endif
