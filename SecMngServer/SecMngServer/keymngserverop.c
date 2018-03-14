#include "keymngserverop.h"
#include "keymng_shmop.h"
#include "poolsocket.h"
#include "keymng_msg.h"
#include <time.h>
#include <errno.h>
#include "md5.h"
#include "icdbapi.h"
#include "keymng_dbop.h"


int MngServer_InitInfo(MngServer_Info * svrInfo)
{
	int ret;
	strcpy(svrInfo->serverId, "0001");
	strcpy(svrInfo->serverip, "127.0.0.1");
	svrInfo->serverport = 6666;
	svrInfo->maxnode = 100;
	svrInfo->shmkey = ftok("/home", 8);
	ret = KeyMng_ShmInit(svrInfo->shmkey, svrInfo->maxnode, &svrInfo->shmhdl);
	if (ret != 0)
	{
		perror(" KeyMng_ShmInit err");
		return ret;
	}
	strcpy(svrInfo->dbuse, "SECMNG");
	strcpy(svrInfo->dbpasswd, "SECMNG");
	strcpy(svrInfo->dbsid, "orcl");
	svrInfo->dbpoolnum = 20;
	ret=IC_DBApi_PoolInit(svrInfo->dbpoolnum, svrInfo->dbsid, svrInfo->dbuse, svrInfo->dbpasswd);
	if (ret != 0)
	{
		perror("IC_DBApi_PoolInit err");
		return -1;
	}
	return 0;
}
void GetRandString(int len, unsigned char*data)
{

	int i, c = 0;
	char buf[] = "~%$#_+!@^;'";
	for (i = 0; i < len; i++)
	{
		c = rand() % 4;
		switch (c)
		{
		case 0:data[i] = 'A' + rand() % 26;
			break;
		case 1:data[i] = 'a' + rand() % 26;
			break;
		case 2:data[i] = '0' + rand() % 10;
			break;
		case 3:data[i] = buf[rand() % strlen(buf)];
			break;
		default:
			break;
		}
	}
}
int MngServer_Agree(MngServer_Info * svrInfo, MsgKey_Req * msgkeyReq, unsigned char ** outData, int * datalen)
{
	
	srand((unsigned int)time(NULL));
	MsgKey_Res res; int ret,i;
	memset(&res, 0x00, sizeof(res));
	GetRandString(sizeof(res.r2) - 1, &res.r2);
	MD5_CTX context;
	MD5Init(&context);
	unsigned char digest[16] = { 0 };
	unsigned char md5[33] = { 0 };
	unsigned char str[3] = { 0 };
	MD5Update(&context, res.r2, strlen(res.r2));
	MD5Update(&context, msgkeyReq->r1, strlen(msgkeyReq->r1));
	MD5Final(&context, digest);
	for ( i = 0; i < 16; ++i)
	{
		sprintf(str, "%02x", digest[i]);
		strcat(md5, str);
	}

	printf("MD5:%s\n", md5);
	NodeSHMInfo pNodeInfo;
	pNodeInfo.status =0;
	memset(pNodeInfo.seckey, 0x00, sizeof(pNodeInfo.seckey));
	strcpy(pNodeInfo.clientId, msgkeyReq->clientId);
	strcpy(pNodeInfo.serverId, msgkeyReq->serverId);
	strcpy(pNodeInfo.seckey, md5);
	ICDBHandle dbhd1;
	ret = IC_DBApi_ConnGet(&dbhd1, 10, 10);
	if (ret != 0)
	{
		printf("IC_DBApi_ConnGet fail...\n");
		return -1;
	}
	IC_DBApi_BeginTran(dbhd1);
	KeyMngsvr_DBOp_GetKeyID(dbhd1, &res.seckeyid);
	pNodeInfo.seckeyid = res.seckeyid;
	ret=KeyMngsvr_DBOp_WriteSecKey(dbhd1, &pNodeInfo);
	if (ret != 0)
	{
		printf("KeyMngsvr_DBOp_WriteSecKey fail...\n");
		IC_DBApi_Rollback(dbhd1);
		if (ret == IC_DB_CONNECT_ERR)
		{
			IC_DBApi_ConnFree(dbhd1, 0);
		}
		return -1;
	}
	IC_DBApi_Commit(dbhd1);
	IC_DBApi_ConnFree(dbhd1,1);
	res.rv = 0;
	strcpy(res.clientId, msgkeyReq->clientId);
	strcpy(res.serverId, msgkeyReq->serverId);
     MsgEncode(&res, ID_MsgKey_Res, outData, datalen);
	/*if (ret != 0)
	{
		perror("MsgEncode err");
		return -1;
	}*/
	ret=KeyMng_ShmWrite(svrInfo->shmhdl, svrInfo->maxnode, &pNodeInfo);
	if (ret != 0)
	{
		perror("KeyMng_ShmWrite err");
		return -1;
	}

	
	return 0;
}
int MngServer_Check(MngServer_Info *svrInfo, MsgKey_Req *msgkeyReq, unsigned char **outData, int *datalen)
{

}
