#include <linux/module.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/semaphore.h>
#include <linux/sched.h>
#include <linux/wait.h>
#include <linux/cdev.h>
#include <linux/kdev_t.h>
#include <linux/device.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/string.h>
#define MAXNUM 100
#define MAJOR_NUM 290
//函数声明部分
static ssize_t globalvar_read(struct file *filp, char __user *buf, size_t len, loff_t *ppos);
static ssize_t globalvar_write(struct file *filp, const char __user *buf, size_t len, loff_t *ppos);
static int globalvar_open(struct inode *inode,struct file *filp);
static int globalvar_release(struct inode *inode,struct file *filp);
int globalvar_init(void);
static void globalvar_exit(void);

struct dev{
	struct cdev devm;
	struct semaphore sem;
	wait_queue_head_t outq;
	int flag;
	char buffer[MAXNUM + 1];
	char *rd, *wr, *end;
	pid_t private_chat_pid;
	int read_count; // 新增字段，用于跟踪已经完成读操作的进程数量
	int total_readers; // 新增字段，用于存储读进程的总数
    struct list_head readers; // 读进程的列表
    int length;//最后一个读进程退出时用来更新读指针
}globalvar;

struct reader_node {
    pid_t pid; // 进程的PID
    struct list_head list; // 列表节点
};

static struct class *my_class;
static inline int isdigit(int ch)
{
    return ch >= '0' && ch <= '9';
}

int major = MAJOR_NUM;
static ssize_t globalvar_read(struct file *filp, char __user *buf, size_t len, loff_t *ppos)
{
    while(globalvar.flag == 1&&globalvar.read_count!=0)
    {
        if(down_interruptible(&globalvar.sem)) //P 操作
    {
        return -ERESTARTSYS;
    }
        up(&globalvar.sem); //V 操作        
    }

    if(wait_event_interruptible(globalvar.outq, globalvar.flag!=0&&(globalvar.private_chat_pid==0||(globalvar.private_chat_pid!=0&&current->pid == globalvar.private_chat_pid)))) //不可读时 阻塞读进程
    {
        return -ERESTARTSYS;
    }

    if(down_interruptible(&globalvar.sem)) //P 操作
    {
        return -ERESTARTSYS;
    }

    if(globalvar.rd < globalvar.wr)
        len = min(len,(size_t)(globalvar.wr - globalvar.rd)); //更新读写长度
    else
        len = min(len,(size_t)(globalvar.end - globalvar.rd));
    globalvar.length=len;
    printk("in read process,len is %d\n",len);
    if(copy_to_user(buf,globalvar.rd,len))
    {
        printk(KERN_ALERT"copy failed\n");
        up(&globalvar.sem);
        return -EFAULT;
    }
    

if(globalvar.private_chat_pid==0)    
    {  
        
        globalvar.read_count++; // 增加计数器
        printk("count++\nnow reader count is %d\n",globalvar.read_count);
        // 当计数器的值等于读进程的总数时，更新globalvar.rd的位置
        if(globalvar.read_count == globalvar.total_readers)
        {
            printk("in read process,before newing wr=%d,rd=%d\n",globalvar.wr-globalvar.buffer,globalvar.rd-globalvar.buffer);
            globalvar.rd = globalvar.rd + len;
            
            if(globalvar.rd == globalvar.end)
                globalvar.rd = globalvar.buffer; //字符缓冲区循环
            printk("in read process,after newing wr=%d,rd=%d\n",globalvar.wr-globalvar.buffer,globalvar.rd-globalvar.buffer);
            globalvar.read_count = 0; // 重置计数器
            globalvar.flag=0;
        }
    }
else//指定私聊进程的操作
    {   
        printk("in @ read process,before newing wr=%d,rd=%d\n",globalvar.wr-globalvar.buffer,globalvar.rd-globalvar.buffer);
        globalvar.rd = globalvar.rd + len;
        globalvar.flag=0;
            if(globalvar.rd == globalvar.end)
                globalvar.rd = globalvar.buffer; //字符缓冲区循环
        printk("in @ read process,after newing wr=%d,rd=%d\n",globalvar.wr-globalvar.buffer,globalvar.rd-globalvar.buffer);
    }
    up(&globalvar.sem); //V 操作
    
    return len;
}
static ssize_t globalvar_write(struct file *filp, const char __user *buf, size_t len, loff_t *ppos)
{   char *kbuf = kmalloc(len + 1, GFP_KERNEL); // 分配内核空间的内存
    if (!kbuf) 
    {
        printk("kmalloc error\n");
        up(&globalvar.sem); //V 操作
        return -ENOMEM;
    }
    
    if (copy_from_user(kbuf, buf, len)) { // 将用户空间的数据复制到内核空间
            printk("copy_from_user error\n");
            kfree(kbuf);
            up(&globalvar.sem); //V 操作
            return -EFAULT;
        }
    kbuf[len] = '\0'; // 确保字符串以null字符结束
    int i=-1;
    if(down_interruptible(&globalvar.sem)) //P 操作
    {
        return -ERESTARTSYS;
    }
    char first_char;
   if (get_user(first_char, buf))
	 {
	    printk("get_user error\n");
	    up(&globalvar.sem); //V 操作
	    return -EFAULT;
	}
    if(first_char == '@') //检查是否为私聊消息
    {
        pid_t pid;
        printk("kbuf is %s\n",kbuf);
        
        char pid_str[10];
        long tmp;
        for (i = 0; i < len-1 && i < (sizeof(pid_str) - 1) && isdigit(kbuf[i+1]); ++i)
        {
            pid_str[i] = kbuf[i+1];
        }
        pid_str[i] = '\0';


        // 转换为整数
        
        if (kstrtol(pid_str, 10, &tmp)!= 0)
        {
            printk("kstrtoint error\n");
            kfree(kbuf);
            up(&globalvar.sem); //V 操作
            return -EFAULT;
        }
        pid=(pid_t)tmp;

        // 检查指定的进程号是否在读进程的列表中
        struct list_head *pos;
        bool found = false;
        list_for_each(pos, &globalvar.readers)
        {
            struct reader_node *node = list_entry(pos, struct reader_node, list);
            if(node->pid == pid)
            {
                found = true;
                break;
            }
        }

            if(!found&&pid!=0)
            {   
                // 指定的进程号不在读进程的列表中，忽略这次操作，但是如果为0，则改为群发
                kfree(kbuf);
                printk(KERN_ALERT "Invalid pid: %d\n", pid);
                up(&globalvar.sem); //V 操作
                return -EINVAL;
            }
            // 指定的进程号在读进程的列表中，设置标志
            globalvar.private_chat_pid = pid;
    }
    
    if(globalvar.rd <= globalvar.wr)
        len = min(len-(i+1),(size_t)(globalvar.end - globalvar.wr));
    else
        len = min(len-(i+1),(size_t)(globalvar.rd - globalvar.wr-1));
    printk("in @write len is %d\n",len);
    /*if(copy_from_user(globalvar.wr,buf,len))
    {
        up(&globalvar.sem); //V 操作
        return -EFAULT;
    }*/
    strcpy(globalvar.wr, kbuf+i+1);
    printk("in write process,before newing,wr=%d,rd=%d\n",globalvar.wr-globalvar.buffer,globalvar.rd-globalvar.buffer);
    globalvar.wr = globalvar.wr + len;
    
    if(globalvar.wr == globalvar.end)
    	globalvar.wr = globalvar.buffer; //循环
    printk("in write process,after newing,wr=%d,rd=%d\n",globalvar.wr-globalvar.buffer,globalvar.rd-globalvar.buffer);
    up(&globalvar.sem);//V 操作
    
    globalvar.flag = 1; //条件成立,可以唤醒读进程
    
    wake_up_interruptible(&globalvar.outq); //唤醒读进程
    printk("write send a number!");
    return len;
}


static int globalvar_open(struct inode *inode,struct file *filp)
{
    try_module_get(THIS_MODULE); //模块计数加一
    if (filp->f_mode & FMODE_READ) // 检查打开模式
    {
        globalvar.total_readers++; //增加读进程的数量
        // 创建一个新的读进程节点
        struct reader_node *node = kmalloc(sizeof(struct reader_node), GFP_KERNEL);
        node->pid = current->pid;
        list_add(&node->list, &globalvar.readers); // 添加到读进程的列表
        printk("total reader+1,now is%d\n",globalvar.total_readers);
    }
    printk("This chrdev is in open\n");
    return(0);
}

static int globalvar_release(struct inode *inode,struct file *filp)
{
    module_put(THIS_MODULE); //模块计数减一
    if (filp->f_mode & FMODE_READ) // 检查打开模式
    {
        globalvar.total_readers--; //减少读进程的数量
        if(globalvar.read_count!=0)globalvar.read_count--;
        printk("total reader-1,now is%d\n",globalvar.total_readers);
        struct list_head *pos, *q;
        list_for_each_safe(pos, q, &globalvar.readers)
        {
            struct reader_node *node = list_entry(pos, struct reader_node, list);
            if(node->pid == current->pid)
            {
                list_del(pos);
                kfree(node);
                break;
            }
        }
        if(globalvar.total_readers==0)//最后一个释放的读进程要负责完善善后工作
        {
            globalvar.read_count = 0; // 重置计数器
            globalvar.flag=0;
        }
    }
    printk("now the total reader is %d\nthe count number%d\n",globalvar.total_readers,globalvar.read_count);
    printk("before release,wr=%d,rd=%d\n",globalvar.wr-globalvar.buffer,globalvar.rd-globalvar.buffer);
    printk("This chrdev is in release\n");
    return(0);
}


struct file_operations globalvar_fops =
{
	.read = globalvar_read,
	.write = globalvar_write,
	.open = globalvar_open,
	.release = globalvar_release,
};

int globalvar_init(void)
{
	dev_t dev = MKDEV(major, 0);

	int result;

	if(major)
    {
        //静态申请设备编号
        result = register_chrdev_region(dev, 1, "charmem");
    }
    else
    {
        //动态分配设备号
        result = alloc_chrdev_region(&dev, 0, 1, "charmem");
        major = MAJOR(dev);
    }

	if(result < 0)
		return result;
    
    globalvar.private_chat_pid=0;
    INIT_LIST_HEAD(&globalvar.readers);
    globalvar.read_count=0; 
    globalvar.total_readers=0; 
    
    
	cdev_init(&globalvar.devm, &globalvar_fops);
	globalvar.devm.owner = THIS_MODULE;
	cdev_add(&globalvar.devm, dev, 1);

	sema_init(&globalvar.sem, 1);
	init_waitqueue_head(&globalvar.outq);
	globalvar.rd = globalvar.buffer;
	globalvar.wr = globalvar.buffer;
	globalvar.end = globalvar.buffer + MAXNUM;
	globalvar.flag = 0;

    my_class = class_create(THIS_MODULE, "chardev0");
    device_create(my_class, NULL, dev, NULL, "chardev0");

    return 0;
}

static void globalvar_exit(void)
{
    // 遍历读进程的列表，并释放每个节点的内存
    struct list_head *pos, *q;
    list_for_each_safe(pos, q, &globalvar.readers)
    {
        struct reader_node *node = list_entry(pos, struct reader_node, list);
        list_del(pos);
        kfree(node);
    }

    device_destroy(my_class, MKDEV(major, 0));
    class_destroy(my_class);
    cdev_del(&globalvar.devm);
    unregister_chrdev_region(MKDEV(major, 0), 1);
}
module_init(globalvar_init);
module_exit(globalvar_exit);
MODULE_LICENSE("GPL");