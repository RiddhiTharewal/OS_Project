//permission's macros
#define shm_rd 01
#define shm_rdwr 02
//macros for shmget
#define IPC_PRIVATE 0
#define IPC_CREAT 10000
#define IPC_EXCL 20000

//macros for shmat
#define SHM_EXEC 1000
#define SHM_RDONLY 2000
#define SHM_REMAP 3000
#define SHMLBA PGSIZE
#define SHM_RND 4000

//macros for shmctl
#define IPC_RMID 04
#define IPC_SET 05
