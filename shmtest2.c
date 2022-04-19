#include "types.h"
#include "stat.h"
#include "user.h"
#include "mmu.h"
#include "shmem.h"
#include "memlayout.h"

int main(){
	int key = 1234;
	int shmid = shmget(key,1024,02|IPC_CREAT);
	if(shmid<0){
		printf(1,"shmget failed");
		exit();
	}
	char *str = (char*)shmat(shmid,(void*)0,0);
	if((int)str<0){
		printf(1,"shmat failed");
		exit();
	}
	printf(1,"Data read from memory: %s\n",str);
	int dt = shmdt(str);
	if(dt<0){
		printf(1,"shmdt failed");
		exit();
	}
	printf(1,"Passed tests");
	exit();
}
