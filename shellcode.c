#include <sys/mman.h>
#include <fcntl.h>
#include <sys/shm.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>

int main()
{
    int shmid = shmget(0x486795ab, 0x1000, IPC_CREAT | S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
    void* ptr = shmat(shmid, NULL, 0);
    shmctl(shmid, IPC_RMID, NULL);
}