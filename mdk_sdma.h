/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2024. All rights reserved.
 * Description: mdk_sdma.h
 * Author:
 * Create: 2024
 * Notes:
 */
#ifndef __MDK_SDMA_H__
#define __MDK_SDMA_H__

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define sdma_read(reg) (*(uint32_t *)(reg))
#define sdma_write(val, reg) (*(uint32_t *)(reg) = (uint32_t)(val))
#define HISI_SDMA_LOCK_TIMEOUT_US 1000000

typedef void (*sdma_task_callback)(int task_status, void *task_data);

typedef enum {
	SDMA_SUCCESS		= 0,
	SDMA_FAILED		= -1,
	SDMA_NULL_POINTER	= -2,
	SDMA_TASK_TIMEOUT	= -3,
	SDMA_TASK_UNFINISH	= -4,
	SDMA_LOCK_TIMEOUT	= -5,
	SDMA_CQE_ID_WRONG	= -6,
	SDMA_WAIT_NUM_OVERFLOW	= -7,
	SDMA_RNDCNT_ERR		= -8,
	SDMA_INVALID_DOORBELL	= -9,
	SDMA_CQE_MEM_RSVD	= -10,

	SDMA_INVALID_OPCODE	= -100001,
	SDMA_ECC_ERR		= -100002,
	SDMA_SMMU_TERMINATE	= -100003,
	SDMA_TLBI		= -100004,
	SDMA_SEC_ERR		= -100005,
	SDMA_DEC_ERR		= -100006,
	SDMA_OPCODE_ERR		= -100007,
	SDMA_DMC_ERR		= -100008,
	SDMA_COMP_ERR		= -100009,
	SDMA_COMP_DATA_ERR	= -100010,
	SDMA_ATOMIC_OVERFLOW	= -100011,
	SDMA_ATOMIC_INFINITY	= -100012,
	SDMA_ATOMIC_SRC_NAN	= -100013,
	SDMA_ATOMIC_DST_NAN	= -100014,
	SDMA_ATOMIC_BOTH_NAN	= -100015,
	SDMA_ATOMIC_NOT_EQUAL	= -100016,
} sdma_error_code;

/* user API interface */

/*****************************************************************************
 函 数 名  : sdma_alloc_chn
 功能描述  : 分配一个smda物理通道
 输入参数  : fd sdma设备的文件描述符
 输出参数  : 无
 返 回 值  : sdma句柄
****************************************************************************/
void *sdma_alloc_chn(int fd);

/*****************************************************************************
 函 数 名  : sdma_init_chn
 功能描述  : 初始化smda共享通道
 输入参数  : fd sdma设备的文件描述符  chn 通道号
 输出参数  : 无
 返 回 值  : sdma句柄
****************************************************************************/
void *sdma_init_chn(int fd, int chn);

/*****************************************************************************
 函 数 名  : sdma_deinit_chn
 功能描述  : 释放sdma共享通道资源
 输入参数  : phandle sdma句柄
 输出参数  : 无
 返 回 值  : 0--成功 其他--错误码
****************************************************************************/
int sdma_deinit_chn(void *phandle);

/*****************************************************************************
 函 数 名  : sdma_free_chn
 功能描述  : 释放通道
 输入参数  : phandle sdma句柄
 输出参数  : 无
 返 回 值  : 0--成功 其他--错误码
****************************************************************************/
int sdma_free_chn(void *phandle);

/*****************************************************************************
 函 数 名  : sdma_query_sqe_num
 功能描述  : 查询sdma通道剩余可用的sqe数目
 输入参数  : phandle--sdma句柄
 输出参数  : 无
 返 回 值  : sdma通道剩余可用的sqe数目
****************************************************************************/
int sdma_query_sqe_num(void *phandle);

#ifdef __cplusplus
}
#endif

#endif

