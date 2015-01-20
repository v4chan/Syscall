#include <types.h> 
#include <proc.h>
#include <kern/errno.h>
#include <kern/unistd.h>
#include <kern/wait.h>
#include <lib.h>
#include <syscall.h>
#include <current.h>
#include <proc.h>
#include <thread.h>
#include <addrspace.h>
#include <copyinout.h>
#include "opt-A2.h"
#include <kern/wait.h>
#include <vnode.h>
#include <mips/trapframe.h>
#include <vfs.h>
#include <kern/fcntl.h>

  /* this implementation of sys__exit does not do anything with the exit code */
  /* this needs to be fixed to get exit() and waitpid() working properly */

void sys__exit(int exitcode) {

	struct addrspace *as;
	struct proc * p = curproc;
#if OPT_A2	
	lock_acquire(p->p_exit_lock);
	if (p->p_parent_exit == 0) { // parent has not exited
		p->p_exit_status = _MKWAIT_EXIT(exitcode);
		p->p_exit = true;
		store_exitid(p);// store exit status
		flag_children(p);
		cv_broadcast(p->p_exit_cv,p->p_exit_lock);
		KASSERT(p->p_addrspace != NULL);
		as_deactivate();
		as = curproc_setas(NULL);
		as_destroy(as);
		lock_release(p->p_exit_lock);
		proc_remthread(curthread);
		proc_cleanup(p);
	}
	else { // parent has exited
		clear_exit_storage(p->p_id);
		clear_pid_storage(p);
		flag_children(p);
		lock_release(p->p_exit_lock);
		proc_remthread(curthread);
		proc_destroy(p);
	}
#endif
		thread_exit(); 
		/* thread_exit() does not return, so we should never get here */
		panic("return from thread_exit in sys_exit\n");
}


/* stub handler for getpid() system call                */
pid_t
sys_getpid()
{
#if OPT_A2
  return(curproc->p_id);
  panic("getpid() failed");
#endif
}

/* stub handler for waitpid() system call                */

pid_t
sys_waitpid(pid_t pid,int * status,int options){
	if (options != 0) {
		return(EINVAL*(-1));
	}
#if OPT_A2 
	if (curproc == NULL) { 
		return ESRCH*(-1);
	}
	/*if (exited(pid) != 0) {
		*status = exited(pid);
		return pid;
	}*/ 
	struct proc * child = locate_child(curproc, pid);
	if (child == NULL) { // race condition, child has already been removed
		*status = exited(pid);
		//clear_exit_storage(pid);
		return pid;
		//return ECHILD*(-1);
	}
	lock_acquire(child->p_exit_lock);
	int val = exited(pid);
	if (child->p_exit == 0 && val == -1) {
		//child->p_parent_waiting = true;
		cv_wait(child->p_exit_cv, child->p_exit_lock);
	}
	*status = exited(pid);//find_exitid(child);// find exit status
	//child->p_parent_waiting = false;
	lock_release(child->p_exit_lock);
	//cv_broadcast(child->p_exit_cv, child->p_child_lock);
	return pid;
#endif
}

#if OPT_A2

/*a new thread's entrypoint*/
void thread_starts_here(void * tf, unsigned long addr) {
	enter_forked_process(tf);
	(void)addr;
}

/*handler for fork() system call*/
pid_t 
sys_fork(struct trapframe * trapf) {
	struct trapframe * tf = kmalloc(sizeof(struct trapframe));
	if (tf == NULL) {
		return ENOMEM*(-1);
	} 
	*tf = *trapf;
	struct proc * child = create_fork(curproc);
	if (child == NULL) {
		kfree(tf);
		return ENOMEM*(-1);
	}
	int error = thread_fork(curthread->t_name,child,&thread_starts_here,(void*)tf,(unsigned long)curproc->p_addrspace);
	if (error) {
		proc_destroy(child);
		kfree(tf);
		return error*(-1);
	}
	return child->p_id;
}

/*handler for execv() system call*/
int 
sys_execv(const char *program, char **args) {
	struct addrspace *as;
	struct vnode *v;
	vaddr_t entrypoint, stackptr;
	int result;
	int argc = 0;

	if (strlen(program) <= 0) {
		return ENOENT*(-1); 
	}

	while(args[argc] != NULL) {
		argc++;
	}
	
	if (argc > E2BIG) {
		return E2BIG*(-1);
	}

	/*copy old address space in usermode*/
	char temp[128];
	KASSERT(sizeof(temp) > strlen(program)); 
	copyin((const_userptr_t)program, temp, strlen(program)+1);

	/*copy args*/
	char *arg_new[argc];
	for (int i = 0; i < argc; i++) {
		int arg_size = strlen(args[i]) + 1; //determine length of ith argument
		char *arg = kmalloc(sizeof(char)*arg_size); //allocate space for ith argument
		copyin((const_userptr_t)args[i], arg, arg_size); //copy ith argument from user space to kernel space
		arg_new[i] = arg; // copy ith argument to arg_new array
	}

	/*destroy old address space*/	
	KASSERT(curproc->p_addrspace != NULL);
	as_deactivate();
	as = curproc_setas(NULL);
	as_destroy(as);

	char *fname_temp;
	fname_temp = kstrdup(temp);

	/* Open the file. */
	result = vfs_open(fname_temp, O_RDONLY, 0, &v);
	kfree(fname_temp);
	if (result) {
		return result;
	}

	/* We should be a new process. */
	//KASSERT(curproc_getas() == NULL);

	/* Create a new address space. */
	as = as_create();
	if (as == NULL) {
		vfs_close(v);
		return ENOMEM*(-1);
	}
	
	/* Switch to it and activate it. */
	curproc_setas(as);
	as_activate();

	/* Load the executable. */
	result = load_elf(v, &entrypoint);
	if (result) {
		/* p_addrspace will go away when curproc is destroyed */
		vfs_close(v);
		return result;
	}

	/* Done with the file now. */
	vfs_close(v);

	/* Define the user stack in the address space */
	result = as_define_stack(as, &stackptr);
	if (result) {
		/* p_addrspace will go away when curproc is destroyed */
		return result;
	}

	// move args into addr space
	userptr_t arg_move[argc+1];
	for (int i = 0; i < argc; i++) {
		int arg_size = strlen(arg_new[i]) + 1;
		stackptr = stackptr - arg_size;
		copyout(arg_new[i], (userptr_t)stackptr, arg_size);
		arg_move[i] = (userptr_t)stackptr;
		kfree(arg_new[i]);
	}
	arg_move[argc] = NULL;

	stackptr = stackptr - (stackptr%4) - (argc+1)*4;
	copyout(arg_move, (userptr_t)stackptr, (argc+1)*4);
	userptr_t argv_addr = (userptr_t)stackptr;
	stackptr = stackptr - (stackptr%8);

	/* Warp to user mode. */
	enter_new_process(argc, argv_addr, stackptr, entrypoint);
	
	/* enter_new_process does not return. */
	panic("enter_new_process returned\n");
	return EINVAL*(-1);
}
#endif
