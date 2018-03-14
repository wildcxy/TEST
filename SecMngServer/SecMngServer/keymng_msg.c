
#define  _CRT_SECURE_NO_WARNINGS 

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "itcast_asn1_der.h"
#include "keymng_msg.h"
#include "itcastlog.h"


int MsgKey_Req_Encode(MsgKey_Req *pStruct, ITCAST_ANYBUF **outData)
{
	int				ret = 0;
	ITCAST_ANYBUF		*pTmp=NULL, *pHead=NULL;
	ITCAST_ANYBUF		*pTmpDABuf = NULL;
	ITCAST_ANYBUF		*pOutData = NULL;

	if (pStruct == NULL)
	{
		ret = WriteNullSequence(&pHead);
		if (ret != 0)
		{
			return ret;
		}
		//对空进行编码
		*outData = pHead;
		return ret;			
	}

	//编 cmdType 域
	ret = DER_ItAsn1_WriteInteger((unsigned long)pStruct->cmdType, &pHead);
	if (ret != 0)
	{
		DER_ITCAST_FreeQueue(pHead);
		ITCAST_LOG(__FILE__, __LINE__,IC_ERROR_LEVEL, ret,"func DER_ItAsn1_WriteInteger() err");
		return ret;
	}
	pTmp = pHead;

	//编 clientId 域
	ret = EncodeChar(pStruct->clientId, strlen(pStruct->clientId), &pTmp->next);
	if (ret != 0)
	{
		DER_ITCAST_FreeQueue(pHead);
		ITCAST_LOG(__FILE__, __LINE__,IC_ERROR_LEVEL, ret,"func EncodeChar() err");
		return ret;
	}
	pTmp = pTmp->next;

	//编 AuthCode 域
	ret = EncodeChar(pStruct->AuthCode, strlen(pStruct->AuthCode), &pTmp->next);
	if (ret != 0)
	{
		DER_ITCAST_FreeQueue(pHead);
		ITCAST_LOG(__FILE__, __LINE__,IC_ERROR_LEVEL, ret,"func EncodeChar() err");
		return ret;
	}
	pTmp = pTmp->next;

	//编 serverId 域
	ret = EncodeChar(pStruct->serverId, strlen(pStruct->serverId), &pTmp->next);
	if (ret != 0)
	{
		DER_ITCAST_FreeQueue(pHead);
		ITCAST_LOG(__FILE__, __LINE__,IC_ERROR_LEVEL, ret,"func EncodeChar() err");
		return ret;
	}
	pTmp = pTmp->next;

	//编 r1 域
	ret = EncodeChar(pStruct->r1, sizeof(pStruct->r1), &pTmp->next);
	if (ret != 0)
	{
		DER_ITCAST_FreeQueue(pHead);
		ITCAST_LOG(__FILE__, __LINE__,IC_ERROR_LEVEL, ret,"func EncodeChar() err");
		return ret;
	}
	pTmp = pTmp->next;

	//把结构体打包
	ret = DER_ItAsn1_WriteSequence(pHead, outData);
	if (ret != 0)
	{
		DER_ITCAST_FreeQueue(pHead);
		ITCAST_LOG(__FILE__, __LINE__,IC_ERROR_LEVEL, ret,"func DER_ItAsn1_WriteSequence() err");
		return ret;
	}
	DER_ITCAST_FreeQueue(pHead);

	return ret;
}

int MsgKey_Req_Decode(ITCAST_ANYBUF *inData, MsgKey_Req **pStruct)
{
	int					ret = 0;
	ITCAST_ANYBUF		*pTmp=NULL, *pHead=NULL;
	ITCAST_ANYBUF		*pTmpDABuf = NULL;
	ITCAST_ANYBUF		*pOutData = NULL;
	ITCAST_ANYBUF		*inAnyBuf = NULL;

	unsigned char		tag;
	unsigned long		tmpNum;
	MsgKey_Req			*pTmpStru = NULL;

	if (inData==NULL || pStruct==NULL)
	{
		ret = KeyMng_ParamErr;
		ITCAST_LOG(__FILE__, __LINE__,IC_ERROR_LEVEL, ret,"func MsgKey_Req_Decode() err check (inData==NULL || pStruct==NULL)");
		return ret;
	}

	//
	ret = DER_ItAsn1_ReadSequence(inData, &pHead);
	if (ret != 0)
	{
		ITCAST_LOG(__FILE__, __LINE__,IC_ERROR_LEVEL, ret,"func DER_ItAsn1_ReadSequence()");
		return ret;
	}
	pTmp = pHead;
	
	//判断是不是空
	ret = DER_ItAsn1_ReadNull(pTmp, &tag);
	if (ret == 0)
	{
		DER_ITCAST_FreeQueue(pHead);//Free Mem
		*pStruct = NULL;	
		return 0;
	}

	pTmpStru = 	(MsgKey_Req *)malloc(sizeof(MsgKey_Req));
	if (pTmpStru == NULL)
	{
		ret = KeyMng_MallocErr;
		DER_ITCAST_FreeQueue(pHead);//Free Mem
		ITCAST_LOG(__FILE__, __LINE__,IC_ERROR_LEVEL, ret,"check malloc err");
		return ret;
	}
	memset(pTmpStru, 0, sizeof(MsgKey_Req));

	//解 cmdType 域
	ret = DER_ItAsn1_ReadInteger(pTmp, &tmpNum);
	if (ret != 0)
	{
		if (pTmpStru != NULL) free(pTmpStru);
		DER_ITCAST_FreeQueue(pHead);
		ITCAST_LOG(__FILE__, __LINE__,IC_ERROR_LEVEL, ret,"func DER_ItAsn1_ReadInteger() err");
		return ret;
	}
	pTmpStru->cmdType = tmpNum;
	pTmp = pTmp->next;

	//解 clientId 域
	ret = DER_ItAsn1_ReadPrintableString(pTmp, &pTmpDABuf);
	if (ret != 0)
	{
		if (pTmpStru != NULL) free(pTmpStru);
		DER_ITCAST_FreeQueue(pHead);
		ITCAST_LOG(__FILE__, __LINE__,IC_ERROR_LEVEL, ret,"func DER_ItAsn1_ReadPrintableString() err");
		return ret;
	}
	memcpy(pTmpStru->clientId, pTmpDABuf->pData, pTmpDABuf->dataLen);
	DER_ITCAST_FreeQueue(pTmpDABuf);	
	pTmpDABuf = NULL;
	pTmp = pTmp->next;

	//解 AuthCode 域
	ret = DER_ItAsn1_ReadPrintableString(pTmp, &pTmpDABuf);
	if (ret != 0)
	{
		if (pTmpStru != NULL) free(pTmpStru);
		DER_ITCAST_FreeQueue(pHead);
		ITCAST_LOG(__FILE__, __LINE__,IC_ERROR_LEVEL, ret,"func DER_ItAsn1_ReadPrintableString() err");
		return ret;
	}
	memcpy(pTmpStru->AuthCode, pTmpDABuf->pData, pTmpDABuf->dataLen);
	DER_ITCAST_FreeQueue(pTmpDABuf);	
	pTmpDABuf = NULL;
	pTmp = pTmp->next;

	//解 serverId 域
	ret = DER_ItAsn1_ReadPrintableString(pTmp, &pTmpDABuf);
	if (ret != 0)
	{
		if (pTmpStru != NULL) free(pTmpStru);
		DER_ITCAST_FreeQueue(pHead);
		ITCAST_LOG(__FILE__, __LINE__,IC_ERROR_LEVEL, ret,"func DER_ItAsn1_ReadPrintableString() err");
		return ret;
	}
	memcpy(pTmpStru->serverId, pTmpDABuf->pData, pTmpDABuf->dataLen);
	DER_ITCAST_FreeQueue(pTmpDABuf);	
	pTmpDABuf = NULL;
	pTmp = pTmp->next;


	//解 r1 域
	ret = DER_ItAsn1_ReadPrintableString(pTmp, &pTmpDABuf);
	if (ret != 0)
	{
		if (pTmpStru != NULL) free(pTmpStru);
		DER_ITCAST_FreeQueue(pHead);
		ITCAST_LOG(__FILE__, __LINE__,IC_ERROR_LEVEL, ret,"func DER_ItAsn1_ReadPrintableString() err");
		return ret;
	}
	memcpy(pTmpStru->r1, pTmpDABuf->pData, pTmpDABuf->dataLen);
	
	//释放临时内存
	DER_ITCAST_FreeQueue(pHead);

	//间接赋值
	*pStruct = pTmpStru;

	return ret;
}

int MsgKey_Req_Free(MsgKey_Req **pStruct)
{
	if (pStruct == NULL)
	{
		return 0;
	}
	free(*pStruct);
	*pStruct = NULL;
	return 0;
}

int MsgKey_Res_Encode(MsgKey_Res *pStruct, ITCAST_ANYBUF **outData)
{
	int				ret = 0;
	ITCAST_ANYBUF		*pTmp=NULL, *pHead=NULL;
	ITCAST_ANYBUF		*pTmpDABuf = NULL;
	ITCAST_ANYBUF		*pOutData = NULL;

	if (pStruct == NULL)
	{
		ret = WriteNullSequence(&pHead);
		if (ret != 0)
		{
			return ret;
		}
		//对空进行编码
		*outData = pHead;
		return ret;			
	}

	//编 rv 域
	ret = DER_ItAsn1_WriteInteger((unsigned long)pStruct->rv, &pHead);
	if (ret != 0)
	{
		DER_ITCAST_FreeQueue(pHead);
		ITCAST_LOG(__FILE__, __LINE__,IC_ERROR_LEVEL, ret,"func DER_ItAsn1_WriteInteger() err");
		return ret;
	}
	pTmp = pHead;

	//编 clientId 域
	ret = EncodeChar(pStruct->clientId, strlen(pStruct->clientId), &pTmp->next);
	if (ret != 0)
	{
		DER_ITCAST_FreeQueue(pHead);
		ITCAST_LOG(__FILE__, __LINE__,IC_ERROR_LEVEL, ret,"func EncodeChar() err");
		return ret;
	}
	pTmp = pTmp->next;

	//编 serverId 域
	ret = EncodeChar(pStruct->serverId, strlen(pStruct->serverId), &pTmp->next);
	if (ret != 0)
	{
		DER_ITCAST_FreeQueue(pHead);
		ITCAST_LOG(__FILE__, __LINE__,IC_ERROR_LEVEL, ret,"func EncodeChar() err");
		return ret;
	}
	pTmp = pTmp->next;

	//编 r2 域
	ret = EncodeChar(pStruct->r2, sizeof(pStruct->r2), &pTmp->next);
	if (ret != 0)
	{
		DER_ITCAST_FreeQueue(pHead);
		ITCAST_LOG(__FILE__, __LINE__,IC_ERROR_LEVEL, ret,"func EncodeChar() err");
		return ret;
	}
	pTmp = pTmp->next;
	
	//编码 seckeyid 域 // modify by bombing 
	ret = DER_ItAsn1_WriteInteger(pStruct->seckeyid, &pTmp->next);
	if (ret != 0)
	{
		DER_ITCAST_FreeQueue(pHead);
		ITCAST_LOG(__FILE__, __LINE__,IC_ERROR_LEVEL, ret,"func EncodeChar() err");
		return ret;
	}
	pTmp = pTmp->next;
	

	//把结构体打包
	ret = DER_ItAsn1_WriteSequence(pHead, outData);
	if (ret != 0)
	{
		DER_ITCAST_FreeQueue(pHead);
		ITCAST_LOG(__FILE__, __LINE__,IC_ERROR_LEVEL, ret,"func DER_ItAsn1_WriteSequence() err");
		return ret;
	}
	DER_ITCAST_FreeQueue(pHead);

	return ret;
}

int MsgKey_Res_Decode(ITCAST_ANYBUF *inData, MsgKey_Res **pStruct)
{
	int					ret = 0;
	ITCAST_ANYBUF		*pTmp=NULL, *pHead=NULL;
	ITCAST_ANYBUF		*pTmpDABuf = NULL;
	ITCAST_ANYBUF		*pOutData = NULL;
	ITCAST_ANYBUF		*inAnyBuf = NULL;

	unsigned char		tag;
	unsigned long		tmpNum;
	MsgKey_Res			*pTmpStru = NULL;

	if (inData==NULL || pStruct==NULL)
	{
		ret = KeyMng_ParamErr;
		ITCAST_LOG(__FILE__, __LINE__,IC_ERROR_LEVEL, ret,"func MsgKey_Res_Decode() err check  (inData==NULL || pStruct==NULL)");
		return ret;
	}

	//
	ret = DER_ItAsn1_ReadSequence(inData, &pHead);
	if (ret != 0)
	{
		ITCAST_LOG(__FILE__, __LINE__,IC_ERROR_LEVEL, ret,"func DER_ItAsn1_ReadSequence() err");
		return ret;
	}  
	pTmp = pHead;

	//判断是不是空
	ret = DER_ItAsn1_ReadNull(pTmp, &tag);
	if (ret == 0)
	{
		DER_ITCAST_FreeQueue(pHead);//Free Mem
		*pStruct = NULL;	
		return 0;
	}

	pTmpStru = 	(MsgKey_Res *)malloc(sizeof(MsgKey_Res));
	if (pTmpStru == NULL)
	{
		ret = KeyMng_MallocErr;
		DER_ITCAST_FreeQueue(pHead);//Free Mem
		ITCAST_LOG(__FILE__, __LINE__,IC_ERROR_LEVEL, ret,"check malloc  err");
		return ret;
	}
	memset(pTmpStru, 0, sizeof(MsgKey_Res));

	//解 rv 域
	ret = DER_ItAsn1_ReadInteger(pTmp, &tmpNum);
	if (ret != 0)
	{
		if (pTmpStru != NULL) free(pTmpStru);
		DER_ITCAST_FreeQueue(pHead);
		ITCAST_LOG(__FILE__, __LINE__,IC_ERROR_LEVEL, ret,"func DER_ItAsn1_ReadInteger() err");
		return ret;
	}
	pTmpStru->rv = tmpNum;
	pTmp = pTmp->next;

	//解 clientId 域
	ret = DER_ItAsn1_ReadPrintableString(pTmp, &pTmpDABuf);
	if (ret != 0)
	{
		if (pTmpStru != NULL) free(pTmpStru);
		DER_ITCAST_FreeQueue(pHead);
		ITCAST_LOG(__FILE__, __LINE__,IC_ERROR_LEVEL, ret,"func DER_ItAsn1_ReadPrintableString() err");
		return ret;
	}
	memcpy(pTmpStru->clientId, pTmpDABuf->pData, pTmpDABuf->dataLen);
	DER_ITCAST_FreeQueue(pTmpDABuf);	
	pTmpDABuf = NULL;
	pTmp = pTmp->next;

	//解 serverId 域
	ret = DER_ItAsn1_ReadPrintableString(pTmp, &pTmpDABuf);
	if (ret != 0)
	{
		if (pTmpStru != NULL) free(pTmpStru);
		DER_ITCAST_FreeQueue(pHead);
		ITCAST_LOG(__FILE__, __LINE__,IC_ERROR_LEVEL, ret,"func DER_ItAsn1_ReadPrintableString() err");
		return ret;
	}
	memcpy(pTmpStru->serverId, pTmpDABuf->pData, pTmpDABuf->dataLen);
	DER_ITCAST_FreeQueue(pTmpDABuf);	
	pTmpDABuf = NULL;
	pTmp = pTmp->next;


	//解 r2 域
	ret = DER_ItAsn1_ReadPrintableString(pTmp, &pTmpDABuf);
	if (ret != 0)
	{
		if (pTmpStru != NULL) free(pTmpStru);
		DER_ITCAST_FreeQueue(pHead);
		ITCAST_LOG(__FILE__, __LINE__,IC_ERROR_LEVEL, ret,"func DER_ItAsn1_ReadPrintableString() err");
		return ret;
	}
	memcpy(pTmpStru->r2, pTmpDABuf->pData, pTmpDABuf->dataLen);
	DER_ITCAST_FreeQueue(pTmpDABuf);	
	pTmpDABuf = NULL;
	pTmp = pTmp->next;
	
	//解 seckeyid 域 //modify add
	ret = DER_ItAsn1_ReadInteger(pTmp, &tmpNum);
	if (ret != 0)
	{
		if (pTmpStru != NULL) free(pTmpStru);
		DER_ITCAST_FreeQueue(pHead);
		ITCAST_LOG(__FILE__, __LINE__,IC_ERROR_LEVEL, ret,"func DER_ItAsn1_ReadInteger() err");
		return ret;
	}
	pTmpStru->seckeyid = tmpNum;
	pTmp = pTmp->next;

	//
	DER_ITCAST_FreeQueue(pHead);

	//间接赋值
	*pStruct = pTmpStru;

	return ret;
}

int MsgKey_Res_Free(MsgKey_Res **pStruct)
{
	if (pStruct == NULL)
	{
		return 0;
	}
	free(*pStruct);
	*pStruct = NULL;
	return 0;
}

// ---------------- 报文编码通用接口 ---------------- 

int MsgEncode(
	void			*pStruct , /*in*/
	int				type,
	unsigned char	**outData, /*out*/
	int				*outLen )
{
	ITCAST_ANYBUF	*pHeadbuf=NULL, *pTemp=NULL;
	void			*pOutData=NULL;	
	int				ret = 0;

	if (pStruct == NULL || outData==NULL || outLen==NULL )
	{
		ret = KeyMng_ParamErr;
		ITCAST_LOG(__FILE__, __LINE__,IC_ERROR_LEVEL, ret,"func MsgEncode() err  (pStruct == NULL || outData==NULL || outLen==NULL )");
		return KeyMng_ParamErr;
	}

	//Write type
	ret = DER_ItAsn1_WriteInteger(type, &pHeadbuf);
	if (ret != 0)
	{
		DER_ITCAST_FreeQueue(pHeadbuf);
		ITCAST_LOG(__FILE__, __LINE__,IC_ERROR_LEVEL, ret,"func DER_ItAsn1_WriteInteger() err");
		return  ret;
	}

	switch(type)
	{  
	case ID_MsgKey_Req:
		ret = MsgKey_Req_Encode(pStruct, (ITCAST_ANYBUF **)&pOutData);
		if(ret != 0)
		{   
			DER_ITCAST_FreeQueue(pHeadbuf);
			ITCAST_LOG(__FILE__, __LINE__,IC_ERROR_LEVEL, ret,"func MsgKey_Req_Encode() err ");
			return ret;           
		}
		break;

	case ID_MsgKey_Res:
		ret = MsgKey_Res_Encode(pStruct, (ITCAST_ANYBUF **)&pOutData);
		if(ret != 0)
		{			 
			DER_ITCAST_FreeQueue(pHeadbuf);
			ITCAST_LOG(__FILE__, __LINE__,IC_ERROR_LEVEL, ret,"func MsgKey_Res_Encode() err ");
			return ret;		 
		}
		break;

	default: 
		DER_ITCAST_FreeQueue(pHeadbuf);
		ret  = KeyMng_TypeErr ;
		ITCAST_LOG(__FILE__, __LINE__,IC_ERROR_LEVEL, ret,"func MsgKey_Res_Encode() err ");
		return KeyMng_TypeErr;

	}

	//组成链表结点
	pHeadbuf->next = pOutData;

	//Write Sequence
	ret = DER_ItAsn1_WriteSequence(pHeadbuf, &pTemp);
	if (ret != 0)
	{
		DER_ITCAST_FreeQueue(pHeadbuf);
		DER_ITCAST_FreeQueue(pTemp);
		ITCAST_LOG(__FILE__, __LINE__,IC_ERROR_LEVEL, ret,"func DER_ItAsn1_WriteSequence() err ");
		return ret;	
	}
	DER_ITCAST_FreeQueue(pHeadbuf); //释放内存

	*outData = malloc(pTemp->dataLen);
	if(*outData == NULL)
	{
		ret = KeyMng_MallocErr;
		DER_ITCAST_FreeQueue(pTemp);
		ITCAST_LOG(__FILE__, __LINE__,IC_ERROR_LEVEL, ret,"check malloc err ");
		return KeyMng_MallocErr;
	}
	
	//copy数据
	memcpy(*outData , pTemp->pData , pTemp->dataLen);
	*outLen = pTemp->dataLen;

	DER_ITCAST_FreeQueue(pTemp);
	return ret;
}


// ---------------- 报文解码通用接口 ---------------- 

int MsgDecode ( 
	unsigned char *inData,/*in*/
	int           inLen,
	void          **pStruct /*out*/,
	int           *type /*out*/)
{
	ITCAST_ANYBUF		*pHeadBuf=NULL, *pTmp=NULL;
	int					ret;
	unsigned long		temp;

	if (inData==NULL || inLen <= 0)
	{
		ret = KeyMng_ParamErr;
		return ret;
	}
	pTmp = malloc(sizeof(ITCAST_ANYBUF));
	if( pTmp == NULL)
	{
		ret = KeyMng_MallocErr;
		ITCAST_LOG(__FILE__, __LINE__,IC_ERROR_LEVEL, ret,"func MsgDecode() err, check malloc err ");
		return ret;
	}
	memset(pTmp, 0, sizeof(ITCAST_ANYBUF));

	pTmp->pData = malloc(inLen);
	if( pTmp->pData == NULL)
	{
		ret = KeyMng_MallocErr;
		DER_ITCAST_FreeQueue(pTmp);
		ITCAST_LOG(__FILE__, __LINE__,IC_ERROR_LEVEL, ret,"func MsgDecode() err, check malloc err ");
		return ret;
	}
	memcpy(pTmp->pData, inData, inLen);
	pTmp->dataType = 0;
	pTmp->dataLen  = inLen;  

	//Read Sequence
	ret = DER_ItAsn1_ReadSequence(pTmp, &pHeadBuf);
	if (ret != 0)
	{
		DER_ITCAST_FreeQueue(pHeadBuf);
		DER_ITCAST_FreeQueue(pTmp);
		ITCAST_LOG(__FILE__, __LINE__,IC_ERROR_LEVEL, ret,"func DER_ItAsn1_ReadSequence() err");
		return ret;
	}
	DER_ITCAST_FreeQueue(pTmp); //释放临时内存
	pTmp = NULL;

	//Read type
	ret = DER_ItAsn1_ReadInteger(pHeadBuf, &temp);	
	if (ret != 0)
	{
		DER_ITCAST_FreeQueue(pHeadBuf);
		ITCAST_LOG(__FILE__, __LINE__,IC_ERROR_LEVEL, ret,"func DER_ItAsn1_ReadInteger() err");
		return ret;
	}

	*type = temp;
	if (pHeadBuf->next == NULL) //判断der格式是否正确
	{
		ret = KeyMng_ParamErr;
		DER_ITCAST_FreeQueue(pHeadBuf);
		ITCAST_LOG(__FILE__, __LINE__,IC_ERROR_LEVEL, ret,"check  (pHeadBuf->next == NULL)");
		return ret;
	}	  

	pTmp = pHeadBuf->next;
	if (pTmp->dataLen <= 0) //判断der长度是否正确
	{   
		ret = KeyMng_ParamErr;
		DER_ITCAST_FreeQueue(pHeadBuf);
		ITCAST_LOG(__FILE__, __LINE__,IC_ERROR_LEVEL, ret,"check  (判断der长度是否正确)");
		return ret;
	}	

	switch (temp)
	{
	case ID_MsgKey_Req:
		ret = MsgKey_Req_Decode(pTmp, (MsgKey_Req**)pStruct);//若失败 在函数AuToSsReqDecode内释放内存
		if (ret != 0)
		{
			DER_ITCAST_FreeQueue(pHeadBuf);
			ITCAST_LOG(__FILE__, __LINE__,IC_ERROR_LEVEL, ret,"func MsgKey_Req_Decode() err");
			return ret;
		}
		break;
	case ID_MsgKey_Res:
		ret = MsgKey_Res_Decode(pTmp,(MsgKey_Res**)pStruct);
		if (ret!=0)
		{
			DER_ITCAST_FreeQueue(pHeadBuf);
			ITCAST_LOG(__FILE__, __LINE__,IC_ERROR_LEVEL, ret,"func MsgKey_Res_Decode() err");
			return ret;			 
		}
		break;
	default: 
		ret = KeyMng_TypeErr;
		DER_ITCAST_FreeQueue(pHeadBuf);
		ITCAST_LOG(__FILE__, __LINE__,IC_ERROR_LEVEL, ret,"check type err");
		return KeyMng_TypeErr;
	}

	DER_ITCAST_FreeQueue(pHeadBuf);

	return ret;
}


int MsgMemFree(void **point,int type)
{
	int		ret = 0;
	if (point == NULL)
	{
		ret = 0;
		return ret;
	}
	switch(type)
	{
		//----------释放编码后的输出数据-------------------------------------
	case 0:
		free(*point);
		*point = NULL;
		break;
	case ID_MsgKey_Req:
		MsgKey_Req_Free((MsgKey_Req**)point);
		break;
	case ID_MsgKey_Res:
		MsgKey_Res_Free((MsgKey_Res**)point);
		break;	
	default:
		ret = KeyMng_TypeErr;
		ITCAST_LOG(__FILE__, __LINE__,IC_ERROR_LEVEL, ret,"func MsgMemFree() check type err");
		return ret;
	}
	return ret;
}


