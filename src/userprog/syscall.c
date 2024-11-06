#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "devices/shutdown.h"
#include "threads/vaddr.h"
#include "filesys/filesys.h"   
#include "string.h"

#define MIN_FILENAME 1
#define MAX_FILENAME 14


/* Lock for the file system */
struct lock lock;

static void syscall_handler (struct intr_frame *);

/* System call function declarations */
void halt(void); 
void exit(int status);
pid_t exec(const char** cmd_line);
int wait(pid_t pid);
bool create(const char** name, unsigned int initial_size);
bool remove(const char* name);
int open(const char** path);
int filesize(int fd);
int write(int fd, const void* buffer, unsigned size);
void seek(int fd, unsigned position);
unsigned tell(int fd);

void
syscall_init (void) 
{
  /* Initialize the file system lock */
  lock_init(&lock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

/* Get the file with the given fd */
struct file_desc*
get_file(int fd)
{
  struct list_elem* e = list_head(&thread_current()->files);
  while ((e = list_next (e)) != list_end (&thread_current()->files)) 
  {
    struct file_desc* file_desc = list_entry(e, struct file_desc, elem);
    /* writing to the file code if file is open*/
    if(file_desc->fd==fd) {
      return file_desc;
    }
  }

  return NULL;
}


/* Check if the current esp and the next pointer is valid */
static void
check_valid_uaddr(int *esp)
{
  if (!is_user_vaddr(esp) ||
      pagedir_get_page(thread_current()->pagedir, esp)==NULL )
    exit(-1);
}

static bool
check_valid_filename(const char* name)
{
  /* If the filename is not of the correct length */
  if(*name==NULL) exit(-1);
  /* check for a valid address */
  check_valid_uaddr((int*)name);
  /* check the length of the filename */
  int len = strlen(name);
  return len>=MIN_FILENAME && len<=MAX_FILENAME;
}

static void
syscall_handler (struct intr_frame *f) 
{
  check_valid_uaddr(f->esp);
  unsigned number = *(unsigned *)(f->esp);

  switch(number){
    case SYS_HALT:
      halt();
      break;
    case SYS_EXIT:{
      check_valid_uaddr((int*)f->esp+1);
      int status = *((int*)f->esp+1);
      exit(status);
      break;
    }
    case SYS_EXEC:{
      check_valid_uaddr((int*)f->esp+1);
      const char** cmd_line = (char**)((int*)f->esp+1);
      f->eax = exec(cmd_line);
      break;
    }
    case SYS_WAIT:{
      check_valid_uaddr((int*)f->esp+1);
      pid_t pid = *(pid_t*)((int*)f->esp+1);
      f->eax = wait(pid);
      break;
    }
    case SYS_CREATE:{
      check_valid_uaddr((int*)f->esp+2);
      char** name = (char**)((int*)f->esp+1);
      unsigned initial_size = *((unsigned *)f->esp+2);
      f->eax = create(name, initial_size);
      break;
    }
    case SYS_REMOVE:{
      check_valid_uaddr((int*)f->esp+1);
      const char* name = *(char*)((int*)f->esp+1);
      remove(name);
      break;
    }
    case SYS_OPEN:{
      check_valid_uaddr((int*)f->esp+1);
      const char** path = (char**)((int*)f->esp+1);
      f->eax = open(path);
      break;
    }
    case SYS_FILESIZE:{
      check_valid_uaddr((int*)f->esp+1);
      int fd = *((int*)f->esp + 1);
      f->eax = filesize(fd);
      break;
    }
    case SYS_READ:{
      check_valid_uaddr((int*)f->esp+3);
      int fd = *((int*)f->esp + 1);
      void* buffer = (void*)(*((int*)f->esp + 2));
      unsigned size = *((unsigned*)f->esp + 3);
      f->eax = read(fd, buffer, size);
      break;
    }
    case SYS_WRITE:{
      check_valid_uaddr((int*)f->esp+3);
      int fd = *((int*)f->esp + 1);
      void* buffer = (void*)(*((int*)f->esp + 2));
      unsigned size = *((unsigned*)f->esp + 3);
      f->eax = write(fd, buffer, size);
      break;
    }
    case SYS_SEEK:{
      check_valid_uaddr((int*)f->esp+2);
      int fd = *((int*)f->esp + 1);
      unsigned position = *((unsigned*)f->esp + 2);
      seek(fd, position);
      break;
    }
    case SYS_TELL:{
      check_valid_uaddr((int*)f->esp+1);
      int fd = *((int*)f->esp + 1);
      f->eax = tell(fd);
      break;
    }
    case SYS_CLOSE:{
      check_valid_uaddr((int*)f->esp+1);
      int fd = *((int*)f->esp + 1);
      close(fd);
      break;
    }
  }
}

/* System call functions */

/* Halt function - shutdown PintOS */
void 
halt(void)
{
  shutdown_power_off();
}

/* Exit function - exit a process */
void
exit(int status)
{
  struct thread* cur = thread_current();

  /* Save the status at process descriptor */
  struct list_elem *child;
  for (child = list_begin (&cur->parent->children); child != list_end (&cur->parent->children);
       child = list_next (child))
    {
      child_t* pt = list_entry(child, child_t, elem);
      if(pt->tid==cur->tid){
        pt->status = status;
        pt->is_alive = false;
        break;
      }
    }

  printf("%s: exit(%d)\n", cur->name, status);
  thread_exit();
}

/* Exec function - create a child process and execute
   program corresponding to the command line */
pid_t
exec(const char** cmd_line)
{
  pid_t pid = process_execute(*cmd_line);
    
  return pid;
}

/* Wait function - wait for termination of a child 
   process whose id is pid */
int
wait(pid_t pid)
{
  return process_wait(pid);
}

/* Create function - create a file which has an initial
   size of initial_size */
bool
create(const char** name, unsigned int initial_size)
{ 
  /* Check if the address is valid */
  if(check_valid_filename(*name)){
    bool status = filesys_create(*name, initial_size);
    return status;
  }

  return 0;
}

/* Remove function - remove a file whose name is file */
bool
remove(const char* name)
{
  lock_acquire(&lock);
  bool status = filesys_remove(name);
  lock_release(&lock);
  return status;
}

/* Open function - open the file corresponding to the 
   path in path */
int
open(const char** path)
{
  /* if path is empty */
  if(!strlen(*path)) return -1;

  /* check the validity of the file path */
  if(check_valid_filename(*path)){
    lock_acquire(&lock);
    struct file* f = filesys_open(*path);
    lock_release(&lock);

    if(f != NULL){
      /* add the file to the current threads file desc list */
      struct file_desc* file_desc = (struct file_desc*) malloc(sizeof(struct file_desc));
      thread_current()->fd_count++;
      file_desc->fd = thread_current()->fd_count+2;
      file_desc->file = f;
      file_desc->name = (char*) malloc(strlen(*path)+1);
      strlcpy(file_desc->name, *path, strlen(*path)+1);
      list_push_back(&thread_current()->files, &file_desc->elem);
      
      return file_desc->fd;  /* opened file successfully */
    }

    return -1; /* could not open the file successfully */
  }

  /* Filepath is empty */
  return 0;
  
}

/* Filesize function - Returns the size of the open file 
   as fd */
int
filesize(int fd){
  struct file_desc* file_desc = get_file(fd);
  if(file_desc!=NULL){
    lock_acquire(&lock);
    int size = file_length(file_desc->file);
    lock_release(&lock);
    return size;
  }

  return -1;
}

/* Read function - Reads size bytes from buffer to the 
   open file fd.*/
int
read(int fd, const void* buffer, unsigned size)
{ 
  /* Check if the buffer is valid */
  if(!is_user_vaddr(buffer+size)) exit(-1);

  /* Check if the fd is for the standard output file */
  if(fd==STDOUT_FILENO) exit(-1);

  /* Check if the fd is for the standard input file */
  if(fd==STDIN_FILENO){
    putbuf((const char*)buffer, size);
    return size;
  }

  /* Read from the file with the fd file id */
  struct file_desc* file_desc = get_file(fd);
  if(file_desc!=NULL){
    lock_acquire(&lock);
    int asize =  file_read(file_desc->file, buffer, size);
    lock_release(&lock);
    return asize;
  }

  return -1;
}

/* Write function - Writes size bytes from buffer to the 
   open file fd.*/
int
write(int fd, const void* buffer, unsigned size)
{ 
  /* Check if the buffer is valid */
  if(!is_user_vaddr(buffer+size)) exit(-1);
  
  /* Check if the buffer is at valid user address */
  if(fd==STDOUT_FILENO){
    putbuf((const char*)buffer, size);
    return size;
  }

  /* If trying to write to the input file */
  if(fd==STDIN_FILENO)  exit(-1);

  /* Write to the file with the fd file id */
  struct file_desc* file_desc = get_file(fd);
  if(file_desc!=NULL){
    lock_acquire(&lock);
    int asize = file_write(file_desc->file, buffer, size);
    lock_release(&lock);
    return asize;
  }
  
  return -1;
}

/* Seek function - changes the next byte to be read or written 
   an open file */
void
seek(int fd, unsigned position)
{
  struct file_desc* file_desc = get_file(fd);
  if(file_desc!=NULL){
    lock_acquire(&lock);
    file_seek(file_desc->file, position);
    lock_release(&lock);
  }
}

/* Tell function - changes the next byte to be read or written 
   an open file */
unsigned
tell(int fd)
{
  struct file_desc* file_desc = get_file(fd);
  if(file_desc!=NULL){
    lock_acquire(&lock);
    unsigned status = file_tell(file_desc->file);
    lock_release(&lock);
    return status;
  }

  return -1;
}

/* Close function - close the opened file */
void
close(int fd)
{
  if(fd==STDOUT_FILENO || fd==STDIN_FILENO)  return;

  /* Check if the file with fd file id is open*/
  struct file_desc* file_desc = get_file(fd);
  if(file_desc != NULL)
  {
    lock_acquire(&lock);
    file_close(file_desc->file);
    lock_release(&lock);
    list_remove(&file_desc->elem);
    thread_current()->fd_count--;
  }
}