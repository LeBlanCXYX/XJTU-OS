#include <stdio.h>
#include <unistd.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <signal.h>
#include<time.h>
int flag = 1;
pid_t pid1 = -1, pid2 = -1;
void inter_handler() {
	if(pid1>0&&pid2>0)
	{
	printf("\ncatch SIGINT siganal!\n");
	kill(pid1,16);
	kill(pid2,17);
	}
}
void alrm_handler() {
	// TODO
	printf("\ncatch SIGALRM!!\n");
		kill(pid1, 16);
		kill(pid2, 17);
}
void inter_handler1(){
	printf("\nChild process1 is killed by parent!!\n");	
	flag=0;
}
void inter_handler2(){
	printf("\nChild process2 is killed by parent!!\n");
	flag=0;	
}
void child_handler(int signum) {
    // 子进程收到 SIGUSR1 信号表示已经准备好
    if (signum == SIGUSR1) {
        printf("\nChild1 process is ready to receive signals.\n");
    }
    else if(signum == SIGUSR2){
         printf("\nChild2 process is ready to receive signals.\n");
    }
}

int main() {
    signal(SIGUSR1, child_handler);
    signal(SIGUSR2, child_handler);
    signal(SIGINT, inter_handler);
    signal(SIGQUIT, inter_handler);
    while (pid1 == -1) {
        pid1 = fork();
    }

    if (pid1 > 0) {//父进程
        while (pid2 == -1)
	 {
            pid2 = fork();
          }

        if (pid2 > 0) {//父进程
    pause();
    pause();
    alarm(5);
	signal(SIGALRM, alrm_handler);
	wait(NULL);
	wait(NULL);            
	printf("\nParent process is killed!!\n");
        } 
	else {//pid 2 子进程
        sleep(1);
        signal(17,inter_handler2);
	    kill(getppid(),SIGUSR2);   
		while(flag)pause();
		return 0;
        }
    } 
        else 
	{//pid1子进程
    sleep(2);
    signal(16,inter_handler1);
    kill(getppid(),SIGUSR1);
	while(flag)pause();
	return 0;
    	}
    return 0;
}