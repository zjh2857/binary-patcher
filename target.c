#include <stdio.h>
int main(){
    char *p = malloc(20);
    read(0,p,10);
    printf(p);
    free(p);
    free(p);
    system("echo a");
    return 0;
}
