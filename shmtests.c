#include "types.h"
#include "stat.h"
#include "user.h"
#include "mmu.h"
#include "shmem.h"
#include "memlayout.h"


int main(int argc,char *argv[]){
	char *string = "TEsts";
	int key = 1234;
	int shmid = shmget(key,1024,02 | IPC_CREAT);
	if(shmid == -1){
		printf(1,"shmget fail");
		exit();
	}
	char *str = (char*)shmat(shmid,(void*)0,0);
	if((int)str < 0){
		printf(1,"shmat failed");
		exit();
	}
	printf(1,"Write Data: ");
	for(int i = 0; string[i] != 0; i++) {
		str[i] = string[i];
	}
	printf(1,"Data written in memory: %s\n",str);
	
	int dt = shmdt(str);
	if(dt<0){
		printf(1,"shmdt fail");
		exit();
	}
	
	str = (char*)shmat(shmid,(void*)0,0);
	if((int)str<0){
		printf(1,"second shmat failed");
		exit();
	}
	printf(1,"Data read from memory: %s",str);
	
	dt = shmdt(str);
	if(dt<0){
		printf(1,"Second shmdt failed");
		exit();
	}
	printf(1,"\nBasic Test of shmget, shmat, shmdt passed");
	exit();	
}
