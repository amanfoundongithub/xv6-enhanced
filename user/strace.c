#include "kernel/types.h"
#include "user/user.h"
#include "kernel/fcntl.h"

int main(int argc,char** argv)
{
    if (argc < 3)
    {
        printf("Atleast 3 parameters required\n");
        exit(1);
    }
    else if (trace(atoi(argv[1]))<0)
    {        
        printf("strace failed\n");
        exit(1);
    }

    char *arr[100];
    for (int i = 2; i < argc; i++)
    {
        arr[i-2]=argv[i];
    }
    
    exec(arr[0],arr);    
    exit(0);
    
}