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
	int status;			// ����connfd�Ƿ�����Ч��, 0 = ����, 1=������
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
	// �����ݽ��н��� - asn.1
	int type = -1;
	MsgKey_Req* reqMsg = NULL;
	MsgDecode(recvBuf, recvLen, &reqMsg, &type);
	// �õ���MsgKey_Req, ���Կͻ������У��
	//  clientID
	//  authCode
	//  serverID - -�����ж�
	if (strcmp(reqMsg->serverId, sock->info->serverId) != 0)
	{
		printf("serverID error\n");
		return NULL;
	}

	int outLen = -1;
	unsigned char* outData = NULL;
	// ���ݵõ�cmdtype���в�ͬ���߼�����
	switch (reqMsg->cmdType)
	{
	case KeyMng_NEWorUPDATE:
		// ��ԿЭ��
		MngServer_Agree(sock->info, reqMsg, &outData, &outLen);
		break;
	case KeyMng_Check:
		// ��ԿУ��
		//MngServer_Check();
		break;
	case KeyMng_Revoke:
		// ��Կע��
		//MngServer_Revoke();
		break;
	case KeyMng_View:
		break;
	}
	// char* ���͸��ͻ���
	sckServer_send(sock->connfd, timeout, outData, outLen);
	// �ر�ͨ�ŵ��׽���, ���� �Ĳ���
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
	// ��ʼ��һЩ����(�ϱ߷���������)
	MngServer_Info info;
	MngServer_InitInfo(&info);
	// �����׽���(����)
	// ��
	// ���ü���
	int listenfd = -1;
	sckServer_init(info.serverport, &listenfd);
	while (1)
	{
		if (Isexit == 1)
		{
			break;
		}
		// �ȴ���������������
		// �ó�һ��Ԫ�ر���
		SockInfo* p = NULL;
		for ( i = 0; i < sizeof(sockInfo) / sizeof(SockInfo); ++i)
		{
			// �ж�
			if (sockInfo[i].status == 0)
			{
				sockInfo[i].status = 1;
				p = &sockInfo[i];
				break;
			}
			if (i == sizeof(sockInfo) / sizeof(SockInfo) - 1)
			{
				printf("�ڴ�����...\n");
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
	// �ͷ���Դ
	sckServer_close(listenfd);
	sckServer_destroy();

	return 0;
}
void CreatDeamon()
{
	pid_t pid = fork();
	if (pid > 0)
	{
		//�˳�������
		exit(1);
	}
	else if (pid == 0)
	{
		//����Ϊ�Ự
		setsid();
		chdir("/home");
		umask(0022);
		int fd = open("/dev/null", O_RDWR);
		dup2(fd,0);
		//dup2(fd, STDOUT_FILENO);
		dup2(fd,2);
	}
}