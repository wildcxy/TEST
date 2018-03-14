#include<stdio.h>
#include"keymngserverop.h"
#include "keymng_msg.h"
#include "poolsocket.h"
#include <pthread.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <signal.h>
#include <stdlib.h>
static int Isexit = 0;

typedef struct sockinfo
{
	int connfd;
	int status;			// 描述connfd是否是有效的, 0 = 可用, 1=不可用
	pthread_t thid;
	MngServer_Info* info;
}SockInfo;


void* pthread_func(void*arg)
{
	int timeout = 30;
	SockInfo * sock = (SockInfo*)arg;
	int recvLen = -1;
	unsigned char* recvBuf = NULL;
	sckServer_rev(sock->connfd, timeout, &recvBuf, &recvLen);
	// 对数据进行解码 - asn.1
	int type = -1;
	MsgKey_Req* reqMsg = NULL;
	MsgDecode(recvBuf, recvLen, &reqMsg, &type);
	// 得到了MsgKey_Req, 并对客户端身份校验
	//  clientID
	//  authCode
	//  serverID - -可用判断
	if (strcmp(reqMsg->serverId, sock->info->serverId) != 0)
	{
		printf("serverID error\n");
		return NULL;
	}

	int outLen = -1;
	unsigned char* outData = NULL;
	// 根据得到cmdtype进行不同的逻辑处理
	switch (reqMsg->cmdType)
	{
	case KeyMng_NEWorUPDATE:
		// 秘钥协商
		MngServer_Agree(sock->info, reqMsg, &outData, &outLen);
		break;
	case KeyMng_Check:
		// 秘钥校验
		//MngServer_Check();
		break;
	case KeyMng_Revoke:
		// 秘钥注销
		//MngServer_Revoke();
		break;
	case KeyMng_View:
		break;
	}
	// char* 发送给客户端
	sckServer_send(sock->connfd, timeout, outData, outLen);
	// 关闭通信的套接字, 监听 的不关
	sckServer_close(sock->connfd);
	sock->status = 0;
	MsgMemFree(&recvBuf, 0);
	MsgMemFree(&reqMsg, 60);
	MsgMemFree(&outData, 0);
	return NULL;
	
}
void CreatDeamon();
void sigcallback(int num)
{
	printf("catch signal:%d\n", num);
	Isexit = 1;
}
int main()
{
	CreatDeamon();
	struct sigaction act;
	sigemptyset(&act.sa_mask);
	act.sa_flags = 0;
	act.sa_handler = sigcallback;
	sigaction(SIGUSR1, &act, NULL);
	SockInfo sockInfo[100]; int i;
	memset(&sockInfo, 0, sizeof(sockInfo));
	// 初始化一些数据(上边分析的数据)
	MngServer_Info info;
	MngServer_InitInfo(&info);
	// 创建套接字(监听)
	// 绑定
	// 设置监听
	int listenfd = -1;
	sckServer_init(info.serverport, &listenfd);
	while (1)
	{
		if (Isexit == 1)
		{
			break;
		}
		// 等待并接受连接请求
		// 拿出一个元素备用
		SockInfo* p = NULL;
		for ( i = 0; i < sizeof(sockInfo) / sizeof(SockInfo); ++i)
		{
			// 判断
			if (sockInfo[i].status == 0)
			{
				sockInfo[i].status = 1;
				p = &sockInfo[i];
				break;
			}
			if (i == sizeof(sockInfo) / sizeof(SockInfo) - 1)
			{
				printf("内存已满...\n");
				return 0;
			}
		}
		p->info = &info;
		int ret = sckServer_accept(listenfd, 5, &p->connfd);
		if (ret == Sck_ErrTimeOut)
		{
			printf("timeout,wait...\n");
				continue;
		}
		pthread_create(&p->thid, NULL, pthread_func, (void*)p);
		pthread_detach(p->thid);
	}
	// 释放资源
	sckServer_close(listenfd);
	sckServer_destroy();

	return 0;
}
void CreatDeamon()
{
	pid_t pid = fork();
	if (pid > 0)
	{
		//退出父进程
		exit(1);
	}
	else if (pid == 0)
	{
		//提升为会话
		setsid();
		chdir("/home");
		umask(0022);
		int fd = open("/dev/null", O_RDWR);
		dup2(fd,0);
		//dup2(fd, STDOUT_FILENO);
		dup2(fd,2);
	}
}