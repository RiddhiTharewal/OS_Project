#include "types.h"
#include "stat.h"
#include "user.h"
#include "mmu.h"
#include "shmem.h"
#include "memlayout.h"

int key = 1234;
int key0 = 2211;
int key1 = 1111;
int shmid,shmid0,shmid1;


int test_read_and_write(){
	char *string = "test_read_and_write";
	int shmid = shmget(key,1024,02 | IPC_CREAT);
	if(shmid == -1){
		printf(1,"shmget fail");
		return -1;
	}
	char *str = (char*)shmat(shmid,(void*)0,0);
	if((int)str < 0){
		printf(1,"shmat failed");
		return -1;
	}
	for(int i = 0; string[i] != 0; i++) {
		str[i] = string[i];
	}
	printf(1,"Data written in memory: %s\n",str);

	int dt = shmdt(str);
	if(dt<0){
		printf(1,"shmdt fail");
		return -1;
	}
	str = (char*)shmat(shmid,(void*)0,0);
	if((int)str<0){
		printf(1,"second shmat failed");
		return -1;
	}
	printf(1,"Data read from memory: %s\n",str);

	dt = shmdt(str);
	if(dt<0){
		printf(1,"Second shmdt failed");
		return -1;
	}
	int ct = shmctl(shmid,IPC_RMID,(void*)0);
	if(ct<0){
		printf(1,"shmctl failed\n");
		return -1;
	}
	return 0;
}
int shmget_test(){
	printf(1,"Tests for shmget:\n");
	shmid = shmget(key,1024,02|IPC_CREAT);
	printf(1,"Checking if shared memory created: ");
	if(shmid<0){
		printf(1,"Failed\n");
		return -1;
	}
	printf(1,"Passed\n");
	printf(1,"Creating Shared Memory of less than 0 : ");
	shmid0 = shmget(key0,0,02|IPC_CREAT);
	if(shmid0 == -1){
		printf(1,"Passed\n");
	}
	else{
		printf(1,"Failed\n");
		return -1;
	}

	printf(1,"Checking if shared memory created for size greater than available size: ");
	shmid1 = shmget(key1,13200,02|IPC_PRIVATE);
	if(shmid1==-1){
		printf(1,"Passed\n");
	}
	else{
		printf(1,"Failed\n");
		return -1;
	}

	printf(1,"Creating shared memory of already created memory using IPC_EXCL flag : ");
	shmid = shmget(key,1024,02|IPC_CREAT|IPC_EXCL);
	if(shmid == -1){
		printf(1,"Passed\n");
	}
	else{
		printf(1,"Failed\n");
		return -1;
	}

	printf(1,"Checking for key not equal to IPC_PRIVATE when shmflg is not IPC_CREAT: ");
	shmid0 = shmget(key0,0,0);
	if(shmid0 == -1){
		printf(1,"Passed\n");
	}
	else{
		printf(1,"Failed\n");
		return -1;
	}
	return 0;
}


int shmat_test(){
	printf(1,"Testing for shmat\n");
	shmid = shmget(key,1024,02|IPC_CREAT);
	printf(1,"Basic shmat test:");
	char *p = (char*)shmat(shmid,(void*)(0),0);
	if((int)p!=-1){
		printf(1,"Passed\n");
	}
	else{
		printf(1,"Failed\n");
		return -1;
	}
	int d = shmdt((void*)p);
	if(d==-1){
		printf(1,"Detach failed\n");
		return -1;
	}

	printf(1,"Check if shmid out of bound");
	p = (char*)shmat(45,(void*)0,0);
	if((int)p==-1){
		printf(1,"Passed\n");
	}
	else{
		printf(1,"Failed\n");
		return -1;
	}
	printf(1,"Check if region with shmid is allocated:");
	p = (char*)shmat(30,(void*)0,0);
	if((int)p==-1){
		printf(1,"Passed\n");
	}
	else{
		printf(1,"Failed\n");
		return -1;
	}

	printf(1,"Check for shmaddr below MAXHEAP:");
	p = (char*)shmat(shmid,(void*)(MAXHEAP - 100),0);
	if((int)p==-1){
		printf(1,"Passed\n");
	}
	else{
		printf(1,"Failed\n");
		return -1;
	}
	printf(1,"Check for shmaddr above KERNBASE:");
	p = (char*)shmat(shmid,(void*)(KERNBASE+ 100),0);
	if((int)p==-1){
		printf(1,"Passed\n");
	}
	else{
		printf(1,"Failed\n");
		return -1;
	}
	printf(1,"Check for shmaddr in range:");
	p = (char*)shmat(shmid,(void*)(KERNBASE- 1000),0);
	if((int)p!=-1){
		printf(1,"Passed\n");
	}
	else{
		printf(1,"Failed\n");
		return -1;
	}
	d = shmdt((void*)p);
	if(d==-1){
		printf(1,"Detach failed\n");
		return -1;
	}
	return 0;
}


int main(){
	//testing shmget function
	if(test_read_and_write() == -1){
		printf(1,"Test failed\n");
	}
	else{
		printf(1,"Test of shmget, shmat, shmdt, shmctl passed\n");
	}
	if(shmget_test() == -1){
		printf(1,"\nshmget failed\n");
	}
	else{
		printf(1,"\nshmget passed\n");
	}

	if(shmat_test() == -1){
		printf(1,"\nshmat failed\n");
	}
	else{
		printf(1,"\nshmat passed\n");
	}
	exit();
}
