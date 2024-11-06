#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

/* Included synch.h and file.h*/
#include "threads/synch.h"
#include "filesys/file.h"

/* Structures for file system lock and file descriptor. */
struct lock file_system_lock;       

struct file_descriptor
{
    struct file *_file;             
    int fd;                         
    struct list_elem fd_elem;      
};


void syscall_init (void);

#endif /* userprog/syscall.h */
