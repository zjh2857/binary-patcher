#include <stdio.h>
int main(){
    char *p = malloc(20);
    read(0,p,10);
    printf(p);
    printf("%s",p);
    return 0;
}
