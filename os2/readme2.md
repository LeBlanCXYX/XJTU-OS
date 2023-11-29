# 2.1 进程的软中断通信
## 代码  
```C
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

```
### 多次运行所写程序，比较 5s 内按下 Ctrl+\或 Ctrl+Delete 发送中断或 5s 内不进行任何操作发送中断，分别会出现什么结果？分析原因。
运行结果如下  
![2-1](2-1.png)  

如果在5s内按下Ctrl+\或Ctrl+Delete发送中断，会先打印catch SIGNIT siganl！后，子进程被结束然后父进程结束，说明是通过inter_handler()结束的子进程。  
如果在5s内没有进行任何中断发送操作，alarm(5)会在父进程创建5s后自动向父进程发送SIGALRM信号，通过alrm_handler()结束子进程。  

### 父进程向子进程发送信号时，如何确保子进程已经准备好接收信号？
子进程完成signal绑定后，通过kill向父进程发送SIGUSR信号，打断父进程的pause()挂起，父进程才执行之后的命令，保证父进程向子进程发送信号时，子进程已经准备好接收信号。

### 如何阻塞住子进程，让子进程等待父进程发来信号？
使用while(flag)pause();初始时flag=1，只有接收到父进程发来的特定信号才会使flag=0，退出循环。使用pause()可以避免忙等待，加快处理速度。  
# 2.2 进程的管道通信
## 代码
```c
/*管道通信实验程序完整版 */
#include <unistd.h>
#include <signal.h>
#include <stdio.h>
#include<stdlib.h>
#include<sys/wait.h>
int pid1, pid2; // 定义两个进程变量

int main( ) {
    int fd[2];
    char InPipe[4000]; // 定义读缓冲区
    char c1 = '1', c2 = '2';
    pipe(fd); // 创建管道

    while ((pid1 = fork( )) == -1); // 如果进程 1 创建不成功,则空循环

    if (pid1 == 0) { // 如果子进程 1 创建成功, pid1 为进程号
        close(fd[0]); 
	lockf(fd[1],1,0);
        for (int i = 0; i < 2000; i++) {
            write(fd[1], &c1, 1); // 分 2000 次每次向管道写入字符 '1'
        }
        sleep(5); // 等待读进程读出数据
	lockf(fd[1],0,0);
        close(fd[1]); 
        exit(0); // 结束进程 1
    } else {
        while ((pid2 = fork( )) == -1); // 若进程 2 创建不成功,则空循环

        if (pid2 == 0) {
            close(fd[0]);
            lockf(fd[1], 1, 0);
            for (int i = 0; i < 2000; i++) {
                write(fd[1], &c2, 1); // 分 2000 次每次向管道写入字符 '2'
            }
            sleep(5);
            lockf(fd[1], 0, 0);
            close(fd[1]);
            exit(0);
        } else {
            close(fd[1]);
            wait(NULL); // 等待子进程 1 结束
            wait(NULL); // 等待子进程 2 结束
            int bytesRead = read(fd[0], InPipe, 4000); // 从管道中读出 4000 个字符
            InPipe[bytesRead] = '\0'; // 加字符串结束符
            printf("%s\n", InPipe); // 显示读出的数据
            close(fd[0]);
            exit(0); // 父进程结束
        }
    }
return 0;
}
```
两进程都上锁  
![all lock](2-2alllock.png)
完全互斥访问  

只有一个进程上锁或者都不上锁  
![not lock](2-2notlock.png)

# 2.3内存分配与回收
```c
#include <stdio.h>
#include <malloc.h>
#include <stdlib.h>
#include <unistd.h>
#define PROCESS_NAME_LEN 32    //进程名长度
#define MIN_SLICE 10           //最小碎片的大小
#define DEFAULT_MEM_SIZE 1024  //内存大小
#define DEFAULT_MEM_START 0    //起始位置
//内存分配算法
#define MA_FF 1
#define MA_BF 2
#define MA_WF 3
//描述每一个空闲块的数据结构
struct free_block_type
{
    int size;        //空闲块大小
    int start_addr;  //空闲块起始位置
    struct free_block_type *next;  //指向下一个空闲块
};
//指向内存中空闲块链表的首地址
struct free_block_type *free_block= NULL;
//每个进程分配到的内存块的描述
struct allocated_block
{
    int pid;
    int size;  //进程大小
    int start_addr;   //进程分配到的内存块的起始地址
    char process_name[PROCESS_NAME_LEN];  //进程名
    struct allocated_block *next;   //指向下一个进程控制块
};
//进程分配内存块链表的首指针
struct allocated_block *allocated_block_head= NULL;
int free_block_count= 0;    //空闲块的个数
int mem_size= DEFAULT_MEM_SIZE;   //内存大小
int current_free_mem_size= 0;     //当前空闲内存大小
int ma_algorithm= MA_FF;          //当前分配算法
static int pid= 0;
int flag= 0;       //设置内存大小标志，表示内存大小是否设置

struct free_block_type* init_free_block(int mem_size);
void display_menu();
int set_mem_size();
void set_algorithm();
void rearrange(int algorithm);
int rearrange_WF();
int rearrange_BF();
int rearrange_FF();
int new_process();
int allocate_mem(struct allocated_block *ab);
void kill_process();
int free_mem(struct allocated_block *ab);
int dispose(struct allocated_block *free_ab);
int display_mem_usage();
struct allocated_block* find_process(int pid);
int do_exit();
int allocate(struct free_block_type *pre,struct free_block_type *allocate_free_nlock,struct allocated_block *ab);
int mem_retrench(struct allocated_block *ab);
int main(){
 char choice; pid=0;
 free_block = init_free_block(mem_size); //初始化空闲区
 while(1) {
 display_menu(); //显示菜单
 fflush(stdin);
 choice=getchar(); //获取用户输入
 switch(choice){
 case '1': set_mem_size(); break; //设置内存大小
 case '2': set_algorithm();flag=1; break;//设置算法
 case '3': new_process(); flag=1; break;//创建新进程
 case '4': kill_process(); flag=1; break;//删除进程
 case '5': display_mem_usage(); flag=1; break; //显示内存使用
 case '0': do_exit(); exit(0);//释放链表并退出
 default: break; } } 
 return 0;
}

//初始化空闲块，默认为一块，可以指定大小及起始地址
struct free_block_type* init_free_block(int mem_size)
{
    struct free_block_type *fb;
    fb= (struct free_block_type*)malloc(sizeof(struct free_block_type));
    if(fb== NULL)
    {
        printf("No mem\n");
        return NULL;
    }
    current_free_mem_size= mem_size;
    fb->size= mem_size;
    fb->start_addr= DEFAULT_MEM_START;
    fb->next= NULL;    //首地址指向NULL
    free_block_count=1;
    return fb;
}

//设置内存的大小
int set_mem_size()
{
    int size;
    if(flag!= 0)     //防止重复设置
    {
        printf("you've already set the memory size\n");
        return 0;
    }
    printf("Total memory size=");
    for(;;)
    {
        scanf("%d",&size);
        getchar();
        if(size> 0)
        {
            current_free_mem_size= size;
            mem_size= size;
            free_block->size= mem_size;
            break;
        }
        else
        {
            printf("The size must greater than zero!Please input again:");
        }
    }
    flag= 1;    //内存大小已经设置
    return 1;
}

//设置当前的分配算法
void set_algorithm()
{
    int algorithm;
    //system("clear");
    printf("\t1-First Fit\n");   //首次适应算法
    printf("\t2-Best Fit\n");    //最佳适应算法
    printf("\t3-Worst Fit\n");   //最坏适应算法
    printf("Please choose(1-3):");
    for(;;)
    {
        scanf("%d",&algorithm);
        getchar();
        if(algorithm>= 1&&algorithm<= 3)
        {
            ma_algorithm= algorithm;
            break;
        }
        else
        {
            printf("\nCannot input %d,Please input 1-3:",algorithm);
        }
    }
    rearrange(ma_algorithm);
}

void rearrange(int algorithm)
{
    switch(algorithm)
    {
        case MA_FF:
            rearrange_FF();
            break;
        case MA_BF:
            rearrange_BF();
            break;
        case MA_WF:
            rearrange_WF();
            break;
    }
}

//按FF算法重新整理内存空闲块链表，按空闲块首地址排序
int rearrange_FF()
{
    struct free_block_type *head= free_block;
    struct free_block_type *forehand,*pre,*rear;
    int i;
    if(head== NULL)
        return -1;
    for(i= 0;i< free_block_count-1;i++)
    {
        forehand= head;
        pre= forehand->next;
        rear= pre->next;
        if(forehand== head&&forehand->start_addr>= pre->start_addr)
            {
                //比较空闲链表中第一个空闲块与第二个空闲块的开始地址的大小
                head->next= pre->next;
                pre->next= head;
                head= pre;
                forehand= head;
                pre= forehand->next;
            }
        while(pre->next!= NULL)
        {  
            if(pre->start_addr>= rear->start_addr)
            {
                //比较链表中其它相邻两个结点的开始地址的大小
                pre->next= rear->next;
                forehand->next= rear;
                rear->next= pre;
                forehand= rear;
                rear= pre->next;
            }
            else
            {
                forehand= pre;
                pre= rear;
                rear= rear->next;
            }
        }
    }
    free_block=head;
    return 0;
}

//按BF算法重新整理内存空闲块链表，按空闲块大小从小到大排序
int rearrange_BF()
{
    struct free_block_type *head= free_block;
    struct free_block_type *forehand,*pre,*rear;
    int i;
    if(head== NULL)
        return -1;
    for(i= 0;i< free_block_count-1;i++)
    {
        forehand= head;
        pre= forehand->next;
        rear= pre->next;
        if(forehand== head&&forehand->size>= pre->size)//排在考前的空闲块的size比其之后的更大，需要交换
            {
                //比较空闲链表中第一个空闲块与第二个空闲块的空间的大小，size从小到大排序
                head->next= pre->next;
                pre->next= head;
                head= pre;
                forehand= head;
                pre= forehand->next;
                rear= pre->next;
            }
        while(pre->next!= NULL)
        {
            
            if(pre->size>= rear->size)
            {
                //比较链表中其它相邻两个结点的空间的大小
                pre->next= rear->next;
                forehand->next= rear;
                rear->next= pre;
                forehand= rear;
                rear= pre->next;
            }
            else
            {
                forehand= pre;
                pre= rear;
                rear= rear->next;
            }
        }
    }
    free_block=head;
    return 0;
}

//按WF算法重新整理内存空闲块链表，按空闲块大小从大到小排序
int rearrange_WF()
{
    struct free_block_type *head= free_block;
    struct free_block_type *forehand,*pre,*rear;
    int i;
    if(head== NULL)
        return -1;
    for(i= 0;i< free_block_count-1;i++)
    {
        forehand= head;
        pre= forehand->next;
        rear= pre->next;
        if(forehand== head&&forehand->size<=pre->size)
            {
                //比较空闲链表中第一个空闲块与第二个空闲块空间的大小,第一个空闲块比第二个空闲块小时交换
                head->next= pre->next;
                pre->next= head;
                head= pre;
                forehand= head;
                pre= forehand->next;
                rear= pre->next;
            }
        while(pre->next!= NULL)
        {
            
            if(pre->size<= rear->size)
            {
                //比较链表中其它相邻两个结点的空间的大小
                pre->next= rear->next;
                forehand->next= rear;
                rear->next= pre;
                forehand= rear;
                rear= pre->next;
            }
            else
            {
                forehand= pre;
                pre= rear;
                rear= rear->next;
            }
        }
    }
    free_block=head;
    return 0;
}


//创建一个新进程
int new_process()
{
    struct allocated_block *ab;
    int size;
    int ret;
    ab= (struct allocated_block*)malloc(sizeof(struct allocated_block));
    if(!ab)
        exit(-5);
    ab->next= NULL;
    pid++;
    sprintf(ab->process_name,"PROCESS-%02d",pid);//将格式化的数据写入某字符串中
    ab->pid= pid;
    printf("Memory for %s:",ab->process_name);
    for(;;)
    {
        scanf("%d",&size);
        getchar();
        if(size> 0)
        {
            ab->size= size;
            break;
        }
        else
            printf("The size have to greater than zero!Please input again!");
    }
    ret= allocate_mem(ab);
    if((ret== 1)&&(allocated_block_head== NULL))  //如果此时未赋值，则赋值
    {
        allocated_block_head= ab;
        return 1;
    }
    else if(ret== 1)  //分配成功，将该已分配块的描述插入已分配链表
    {
        struct allocated_block *p=allocated_block_head;
        while(p->next!=NULL)p=p->next;
        p->next=ab;
        return 2;
    }
    else if(ret== -1)  //分配不成功
    {
        printf("Allocation fail.\n");
        free(ab);
        return -1;
    }
    return 3;
}

//分配内存模块
int allocate_mem(struct allocated_block *ab)
{
    int ret;
    struct free_block_type *pre= NULL,*f= free_block;
    if(f== NULL)
        return -1;
    while(f!= NULL)
    {
        if(f->size>= ab->size)
        {
            ret= allocate(pre,f,ab);
            rearrange(ma_algorithm);
            return ret;
        }
        pre= f;
        f= pre->next;
    }
    if(f== NULL&&current_free_mem_size> ab->size)
        ret= mem_retrench(ab);
    else
        {
            ret= -2;
            printf("no such spare rooms!!\n");
        }
    return ret;
}

//给新进程分配内存空间
int allocate(struct free_block_type *pre,struct free_block_type *allocate_free_block,struct allocated_block *ab)
{
    //struct allocated_block *p= allocated_block_head;
    ab->start_addr= allocate_free_block->start_addr;
    if(allocate_free_block->size-ab->size< MIN_SLICE)
    {
        ab->size= allocate_free_block->size;
        if(pre!= NULL)
        {
            pre->next= allocate_free_block->next;
        }
        else
        {
            free_block= allocate_free_block->next;
        }
        free(allocate_free_block);
        free_block_count--;
    }
    else
    {
        allocate_free_block->start_addr+= ab->size;
        allocate_free_block->size-= ab->size;
    }
    /*if(p== NULL)
    {
        allocated_block_head= ab;
    }
    else
    {
        while(p->next!= NULL)
            p= p->next;
        p->next= ab;
    }*/
    current_free_mem_size-= ab->size;
    if(current_free_mem_size== 0)
        free_block= NULL;
    return 1;
}

//通过内存紧缩技术给新进程分配内存空间
int mem_retrench(struct allocated_block *ab)
{
    struct allocated_block *allocated_work,*allocated_pre= allocated_block_head;
    struct free_block_type *free_rare,*free_work= free_block->next;
    if(allocated_pre== NULL)
        return -1;
    allocated_pre->start_addr= 0;
    allocated_work= allocated_pre->next;
    while(allocated_work!= NULL)
    {
        allocated_work->start_addr= allocated_pre->start_addr+ allocated_pre->size;
        allocated_pre= allocated_work;
        allocated_work= allocated_work->next;
    }
    free_block->start_addr= allocated_pre->start_addr+ allocated_pre->size;
    free_block->size= current_free_mem_size;
    free_block->next=NULL;
    free_rare= free_work->next;
    while(free_rare!= NULL)
    {
        free(free_work);
        free_work= free_rare;
        free_rare=free_rare->next;
        if(free_rare== NULL)
            free(free_work);
    }
    free_block_count=1;
    allocate(NULL,free_block,ab);
    return 1;
}

//删除进程，归还分配的存储空间，并删除描述该进程内存分配的结点
void kill_process()
{
    struct allocated_block *ab;
    int pid;
    printf("Kill Process,pid=");
    scanf("%d",&pid);
    getchar();
    ab= find_process(pid);
    if(ab!= NULL)
    {
        free_mem(ab);  //释放ab所表示的分配区(free区)
        dispose(ab);   //释放ab数据结构结点
    }
}

struct allocated_block* find_process(int pid){
    struct allocated_block *p=allocated_block_head;
    while(p!=NULL){
        if(p->pid==pid)return p;
        p=p->next;
    }
    printf("no such a pid process!\n");
    return NULL;
}

//将ab所表示的已分配区归还，并进行可能的合并,对空闲块进行操作
int free_mem(struct allocated_block *ab){
    current_free_mem_size+= ab->size;
    struct free_block_type *pre,*work,*rear;
    work=(struct free_block_type*)malloc(sizeof(struct free_block_type));
    work->start_addr=ab->start_addr;
    work->size=ab->size;
    work->next=NULL;
    pre=free_block;
    if(pre==NULL){free_block=work;free_block_count++;return 1;}
    rear=pre->next;
    while(rear!=NULL){
        pre=rear;
        rear=rear->next;
    }
    pre->next=work;
    free_block_count++;
    rearrange_FF();
    pre=free_block;
    rear=free_block->next;
    while(rear!=NULL)
    {
        while(pre->start_addr+pre->size==rear->start_addr)
        {  
            pre->size+=rear->size;
            pre->next=rear->next;
            free(rear);
            free_block_count--;
            rear=pre->next;
            if(rear==NULL)break;
        }
        if(rear!=NULL){
        pre=rear;
        rear=rear->next;
        }
    }
    rearrange(ma_algorithm);
    return 1;
}

int dispose(struct allocated_block *free_ab){
    struct allocated_block *pre,*work;
    pre=allocated_block_head;
    if(pre==NULL)return -1;
    //如果是第一个节点
    if(pre->pid==free_ab->pid){allocated_block_head=pre->next;free(pre);return 1;}
    work=pre->next;
    while(work!=NULL){
        if(work->pid==free_ab->pid){
            pre->next=work->next;
            free(work);
            return 1;
        }
        else{
            pre=work;
            work=work->next;
        }
    }
}

//显示当前内存的使用情况，包括空闲区的情况和已经分配的情况
int display_mem_usage()
{
    struct free_block_type *fbt= free_block;
    struct allocated_block *ab= allocated_block_head;
    printf("-------------------------------------------------------------\n");
    printf("Free Memory:\n");
    printf("%20s %20s\n","     start_addr","     size");
    while(fbt!= NULL)
    {
        printf("%20d %20d\n",fbt->start_addr,fbt->size);
        fbt= fbt->next;
    }
    printf("\nUsed Memory:\n");
    printf("%10s %20s %10s %10s\n","PID","ProcessName","start_addr","size");
    while(ab!= NULL)
    {
        printf("%10d %20s %10d %10d\n",ab->pid,ab->process_name,ab->start_addr,ab->size);
        ab= ab->next;
    }
    printf("-------------------------------------------------------------\n");
    return 1;
}


int do_exit()
{
    struct allocated_block *allocated_ab,*allocated_pre;
    struct free_block_type *free_ab,*free_pre;
    free_pre= free_block;
    allocated_pre= allocated_block_head;
    if(free_pre!= NULL)
    {
        free_ab= free_pre->next;
        while(free_ab!= NULL)
        {
            free(free_pre);
            free_pre= free_ab;
            free_ab= free_ab->next;
        }
        free(free_pre);
    }
    if(allocated_pre!= NULL)
    {
        allocated_ab= allocated_pre->next;
        while(allocated_ab!= NULL)
        {
            free(allocated_pre);
            allocated_pre= allocated_ab;
            allocated_ab= allocated_ab->next;
        }
        free(allocated_pre);
    }
    return 0;
}

//显示主菜单
void display_menu()
{
    printf("\n");
    //system("clear");
    printf("1-Set memory size(default= %d)\n",DEFAULT_MEM_SIZE);
    printf("2-Select memory allocation algorithm\n");
    printf("3-New process\n");
    printf("4-Terminate a process\n");
    printf("5-Display memory usage\n");
    printf("0-Exit\n");
}
```
## 实验结果
### 设计分配算法为总选择空闲块队列里第一个符合要求的空闲块，通过对空闲队列进行不同的排序从而实现不同的选择策略  
#### 空闲块按起始地址排序
![first_fit](./first_fit.png)   
  
  #### 空闲块按空闲块大小 从小到大排序
![best_fit](./best_fit.png)
  
  #### 空闲块按空闲块大小 从大到小排序
![worst_fit](./worst_fit.png)  
  #### 单个空闲块不足但总剩余空闲内存足够时，进行内存紧缩分配内存
![jinsuo](./jinsuo.png)  
  #### 进程结束时归还内存，对连续的空闲块合并
![hebing](./hebing.png)