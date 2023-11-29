#include<sys/types.h>
#include<unistd.h>
#include<sys/stat.h>
#include<stdio.h>
#include<fcntl.h>
#include<string.h>
int main()
{
    int fd,i;
    char msg[101];
    fd= open("/dev/chardev0",O_RDWR,S_IRUSR|S_IWUSR);
    
    if(fd!=-1)
    {
        while(1)
        {
            for(i=0;i<101;i++)  //初始化
                msg[i]='\0';
            
            read(fd,msg,100);
            printf("%s\n",msg);
            
            if(strcmp(msg,"quit()")==0)
            {
                close(fd);
                break;
            }
        }
    }
    else
    {
        printf("device open failure,%d\n",fd);
    }
    return 0;
}