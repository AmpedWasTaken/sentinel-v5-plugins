// Harmless Linux isolation smoke fixture: no network packets are transmitted.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <sys/mount.h>
#include <unistd.h>
int main(void) {
    char host[64]={0};
    if (gethostname(host,sizeof(host)-1)) return 2;
    int f=open("/etc/passwd",O_RDONLY);
    if(f>=0){close(f);return 3;}
    if(mount("tmpfs","/tmp","tmpfs",0,"size=1m")!=-1)return 4;
    if(unshare(CLONE_NEWNET)!=-1)return 5;
    int tmp=open("/tmp/native-smoke",O_CREAT|O_WRONLY|O_TRUNC,0600);
    if(tmp<0)return 6;
    close(tmp);
    int outside=open("/outside-native-smoke",O_CREAT|O_WRONLY,0600);
    if(outside!=-1){close(outside);return 7;}
    printf("pid=%ld hostname=%s host_file=denied mount=denied nested_namespace=denied tmp=ok hostroot_readonly=ok\n",(long)getpid(),host);
    return (getpid()==1)?0:8;
}
