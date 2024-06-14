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

typedef struct sdma_sqe_task {
	uint64_t src_addr; /* source address of copy */
	uint64_t dst_addr; /* destination address of copy */
	uint32_t src_process_id; /* pasid/pid of source process */
	uint32_t dst_process_id; /* pasid/pid of destination process */
	uint32_t src_stride_len; /* stride length of source address */
	uint32_t dst_stride_len; /* stride length of destination address */
	uint32_t stride_num; /* 0 when not using stride mode */
	uint32_t length; /* data length */
	uint8_t  opcode; /* 0x0：normal; 0x5：memory set; 0x6: HBM cache preload */
	uint8_t  mpam_partid; /* partid for MPAM bandwidth control */
	uint8_t  pmg : 2; /* pmg for MPAM bandwidth control */
	uint8_t  resvd1 : 6;
	uint8_t  qos : 4; /* qos level for MPAM bandwidth control */
	uint8_t  resvd2 : 4;
	sdma_task_callback task_cb; /* callback function for progress */
	void *task_data; /* parameter of callback function */
	struct sdma_sqe_task *next_sqe; /* support list structure */
} sdma_sqe_task_t;

typedef struct sdma_request {
	uint16_t	req_id;
	uint32_t	req_cnt;
	uint32_t	round_cnt;
} sdma_request_t;

typedef struct mpam_cfg {
	uint32_t mpam_partid : 8; /* partid for MPAM bandwidth control */
	uint32_t pmg : 2; /* pmg for MPAM bandwidth control */
	uint32_t qos : 4; /* qos level for MPAM bandwidth control */
	uint32_t replace_en : 1; /* 1: enable MPAM bandwith control; 0: disable */
	uint32_t rsv : 17;
} mpam_cfg_t;

typedef struct sdma_chn_err {
	uint32_t ch_err_status;
	uint32_t ch_cqe_sqeid;
	uint32_t ch_cqe_status;
} sdma_chn_err_t;

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
 函 数 名  : sdma_copy_data
 功能描述  : sdma拷贝数据
 输入参数  : phandle--sdma句柄
			sdma_sqe--sqe数据指针
			count--sqe的数量
 输出参数  : 无
 返 回 值  : 0--成功 其他--错误码
****************************************************************************/
int sdma_copy_data(void *phandle, sdma_sqe_task_t *sdma_sqe, uint32_t count);

/*****************************************************************************
 函 数 名  : sdma_icopy_data
 功能描述  : sdma拷贝数据
 输入参数  : phandle--sdma句柄
			sdma_sqe--sqe数据指针
			count--sqe的数量
 输出参数  : request--sdma发送命令相关信息指针
 返 回 值  : 0--成功 其他--错误码
****************************************************************************/
int sdma_icopy_data(void *phandle, sdma_sqe_task_t *sdma_sqe,
		    uint32_t count, sdma_request_t *request);

/*****************************************************************************
 函 数 名  : sdma_wait_chn
 功能描述  : 等待sdma通道发送完成
 输入参数  : phandle--sdma句柄
			count--接收的cqe数量
 输出参数  : 无
 返 回 值  : 0--成功 其他--错误码
****************************************************************************/
int sdma_wait_chn(void *phandle, uint32_t count);

/*****************************************************************************
 函 数 名  : sdma_iwait_chn
 功能描述  : 等待sdma通道发送完成
 输入参数  : phandle--sdma句柄
			request--sdma发送命令相关信息指针
 输出参数  : 无
 返 回 值  : 0--成功 其他--错误码
****************************************************************************/
int sdma_iwait_chn(void *phandle, sdma_request_t *request);

/*****************************************************************************
 函 数 名  : sdma_progress
 功能描述  : 处理已完成的sdma任务
 输入参数  : phandle--sdma句柄
 输出参数  : 无
 返 回 值  : 0--成功 其他--错误码
****************************************************************************/
int sdma_progress(void *phandle);

/*****************************************************************************
 函 数 名  : sdma_get_process_id
 功能描述  : 获取进程相关id信息
 输入参数  : fd sdma设备的文件描述符
 输出参数  : id 获取到的pasid或者pid
 返 回 值  : 0--成功 其他--错误码
****************************************************************************/
int sdma_get_process_id(int fd, uint32_t *id);

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

/*****************************************************************************
 函 数 名  : sdma_query_chn
 功能描述  : 查询sdma通道是否已完成count个sqe任务
 输入参数  : phandle--sdma句柄 count--sqe数量
 输出参数  : 无
 返 回 值  : 0--成功 其他--错误码
****************************************************************************/
int sdma_query_chn(void *phandle, uint32_t count);

/*****************************************************************************
 函 数 名  : sdma_query_chn
 功能描述  : 查询sdma通道是否已完成count个sqe任务
 输入参数  : phandle--sdma句柄
			request--sdma发送命令相关信息指针
 输出参数  : 无
 返 回 值  : 0--成功 其他--错误码
****************************************************************************/
int sdma_iquery_chn(void *phandle, sdma_request_t *request);

/*****************************************************************************
 函 数 名  : sdma_devices_num
 功能描述  : 查询sdma设备数量
 输入参数  : fd--sdma文件句柄
 输出参数  : 无
 返 回 值  : sdma设备数量
****************************************************************************/
int sdma_devices_num(int fd);

/*****************************************************************************
 函 数 名  : sdma_nearest_id
 功能描述  : 查询当前进程就近的sdma设备Id
 输入参数  : 无
 输出参数  : 无
 返 回 值  : -1--未找到 其他--sdma设备id
****************************************************************************/
int sdma_nearest_id(void);

/*****************************************************************************
 函 数 名  : sdma_finish_sqe_cnt
 功能描述  : 查询/清除sdma完成sqe计数器
 输入参数  : phandle--sdma句柄
			clr--计数器清零标识 1有效
 输出参数  : 无
 返 回 值  : SDMA_NULL_POINTER--失败 其他--完成sqe数量
****************************************************************************/
int sdma_finish_sqe_cnt(void *phandle, bool clr);

/*****************************************************************************
 函 数 名  : sdma_err_sqe_cnt
 功能描述  : 查询/清除sdma异常sqe计数器
 输入参数  : phandle--sdma句柄
			clr--计数器清零标识 1有效
 输出参数  : 无
 返 回 值  : SDMA_NULL_POINTER--失败 其他--完成sqe数量
****************************************************************************/
int sdma_err_sqe_cnt(void *phandle, bool clr);

/*****************************************************************************
 函 数 名  : sdma_pin_umem
 功能描述  : 为用户进程虚拟地址PIN页表
 输入参数  : fd--sdma文件句柄 vma--虚拟地址 size--PIN内存大小
 输出参数  : cookie--用于标识pin过的内存，用于之后unpin内存
 返 回 值  : 0--成功 其他--错误码
****************************************************************************/
int sdma_pin_umem(int fd, void *vma, uint32_t size, uint64_t *cookie);

/*****************************************************************************
 函 数 名  : sdma_unpin_umem
 功能描述  : 为用户进程虚拟地址UNPIN页表
 输入参数  : fd--sdma文件句柄 cookie--unpin指定内存的密钥
 输出参数  : 无
 返 回 值  : 0--成功 其他--错误码
****************************************************************************/
int sdma_unpin_umem(int fd, uint64_t cookie);

/*****************************************************************************
 函 数 名  : sdma_mpamid_cfg
 功能描述  : 配置SDMA MPAMID全局替换寄存器
 输入参数  : fd--sdma文件句柄 mpam_cfg--mpam配置结构体
 输出参数  : 无
 返 回 值  : 0--成功 其他--错误码
****************************************************************************/
int sdma_mpamid_cfg(int fd, mpam_cfg_t *mpam_cfg);

/*****************************************************************************
 函 数 名  : sdma_chn_err_info
 功能描述  : 查询SDMA通道异常信息
 输入参数  : phandle--sdma句柄
 输出参数  : chn_err--通道错误信息结构体
 返 回 值  : 0--成功 其他--错误码
****************************************************************************/
int sdma_chn_err_info(void *phandle, sdma_chn_err_t *chn_err);

/*****************************************************************************
 函 数 名  : sdma_add_authority
 功能描述  : 保存pid信息
 输入参数  : id_list--信任的pid列表 num--信任的pid数量
 输出参数  : 无
 返 回 值  : 0--成功 其他--错误码
****************************************************************************/
int sdma_add_authority(int fd, int *id_list, int num);

#ifdef __cplusplus
}
#endif

#endif
