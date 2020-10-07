#include <linux/module.h>
#include <linux/sched.h>
#include <linux/pid.h>
#include <linux/kthread.h>
#include <linux/kernel.h>
#include <linux/err.h>
#include <linux/slab.h>
#include <linux/printk.h>
#include <linux/jiffies.h>
#include <linux/kmod.h>

MODULE_LICENSE("GPL");

static struct task_struct *task;
struct wait_opts {
	enum pid_type			wo_type;
	int						wo_flags;
	struct pid				*wo_pid;

	struct siginfo __user	*wo_info;
	int __user				*wo_stat;
	struct rusage __user	*wo_rusage;

	wait_queue_t			child_wait;
	int						notask_error;
};
extern long _do_fork(unsigned long clone_flags,
					 unsigned long stack_start,
					 unsigned long stack_size,
					 int __user *parent_tidptr,
					 int __user *child_tidptr,
					 unsigned long tls);
extern int do_execve(struct filename *filename,
					 const char __user *const __user *__argv,
					 const char __user *const __user *__envp);
extern long  do_wait (struct wait_opts  *wo);
extern struct filename * getname(const char __user * filename);


int my_exec(void) {
	int result;
	const char path[] = "/media/sf_Shared/A1/source/program1/abort";
	const char *const argv[] = {path, NULL, NULL};
	const char *const envp[] = {"HOME=/", "PATH=/sbin:/user/sbin:bin:/usr/bin", NULL};

	struct filename * my_filename = getname(path);

	result = do_execve(my_filename, argv, envp);
	if (!result) {
		return 0;
	} else {
		do_exit(result);
	}
}

int my_wait(pid_t pid) {
	int status;
	struct wait_opts wo;
	struct pid *wo_pid = NULL;
	enum pid_type type;
	type = PIDTYPE_PID;
	wo_pid = find_get_pid(pid);

	wo.wo_type = type;
	wo.wo_pid = wo_pid;
	wo.wo_flags = (WEXITED | WUNTRACED);
	wo.wo_info = NULL;
	wo.wo_stat = (int __user*)&status;
	wo.wo_rusage = NULL;

	
	int a; 
	a = do_wait(&wo);
	// printk("[program2] : The return value is %d\n", &a);
	if ((*wo.wo_stat >> 8) == 19) {
		printk("[program2] : get SIGSTOP signal");
		printk("[program2] : The return signal is %d\n", (*wo.wo_stat >> 8));
	} else {
		switch (*wo.wo_stat) {
					case 1:
						printk("[program2] : child process get SIGHUP signal\n");
						printk("[program2] : child process is terminated by hangup signal\n");
						break;
					case 2:
						printk("[program2] : child process get SIGINT signal\n");
						printk("[program2] : child process is terminated by interrupt signal\n");
						break;
					case 3:
						printk("[program2] : child process get SIGQUIT signal\n");
						printk("[program2] : child process is terminated by quit signal\n");
						break;
					case 4:
						printk("[program2] : child process get SIGILL signal\n");
						printk("[program2] : child process is terminated by illegal instruction signal\n");
						break;
					case 5:
						printk("[program2] : child process get SIGTRAP signal\n");
						printk("[program2] : child process is terminated by trap signal\n");
						break;
					case 6:
						printk("[program2] : child process get SIGABRT signal\n");
						printk("[program2] : child process is terminated by abort signal\n");
						break;
					case 7:
						printk("[program2] : child process get SIGBUS signal\n");
						printk("[program2] : child process is terminated by bus signal\n");
						break;
					case 8:
						printk("[program2] : child process get SIGFPE signal\n");
						printk("[program2] : child process is terminated by floating signal\n");
						break;
					case 9:
						printk("[program2] : child process get SIGKILL signal\n");
						printk("[program2] : child process is terminated by kill signal\n");
						break;
					case 11:
						printk("[program2] : child process get SIGSEGV signal\n");
						printk("[program2] : child process is terminated by segment fault signal\n");
						break;
					case 13:
						printk("[program2] : child process get SIGPIPE signal\n");
						printk("[program2] : child process is terminated by pipe signal\n");
						break;
					case 14:
						printk("[program2] : child process get SIGALRM signal\n");
						printk("[program2] : child process is terminated by alarm signal\n");
						break;
					case 15:
						printk("[program2] : child process get SIGTERM signal\n");
						printk("[program2] : child process is terminated by terminate signal\n");
						break;
				}
		printk("[program2] : The return signal is %d\n", *wo.wo_stat);
	}
	

	put_pid(wo_pid);
	return;
}

//implement fork function
int my_fork(void *argc)
{

	//set default sigaction for current process
	int i;
	struct k_sigaction *k_action = &current->sighand->action[0];
	for (i = 0; i < _NSIG; i++)
	{
		k_action->sa.sa_handler = SIG_DFL;
		k_action->sa.sa_flags = 0;
		k_action->sa.sa_restorer = NULL;
		sigemptyset(&k_action->sa.sa_mask);
		k_action++;
	}

	/* fork a process using do_fork */

	/* execute a test program in child process */
	
	/* wait until child process terminates */

	pid_t pid;
	
	pid = _do_fork(SIGCHLD, (unsigned long)&my_exec, 0, NULL, NULL, 0);

	printk("[program2] : The child process has pid = %ld\n", pid);
	printk("[program2] : This is the parent process, pid = %d\n", (int)current->pid);
	printk("[program2] : child process");
	
	my_wait(pid);

	return 0;
}

static int __init program2_init(void)
{

	printk("[program2] : Module_init\n");

	/* write your code here */
	
	/* create a kernel thread to run my_fork */
	printk("[program2] : module_init create kthread starts\n");
	task = kthread_create(&my_fork, NULL, "MyThread");

	//wake up new thread if ok
	if (!IS_ERR(task))
	{
		printk("[program2] : module_init kthread starts\n");
		wake_up_process(task);
	}

	return 0;
}

static void __exit program2_exit(void)
{
	printk("[program2] : Module_exit\n");
}

module_init(program2_init);
module_exit(program2_exit);
