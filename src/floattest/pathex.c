#include<stdio.h>
#include <stdlib.h>

// {"s":{"length": 8}}
int main(int argv, char* s[]) {
    int count = 0;
    for(int i = 0; i < 100; i++){
        if(s[1][i] == 48)
            count += 1;
    }
    printf("%d\n",count);
    if (count == 75){
        printf("bomb\n");
        return 3;
    }
    else
        return 0;
}
