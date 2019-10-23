#include<stdio.h>
#include <stdlib.h>
#include "a_tester.h"

// {"s":{"length": 8}}
int main(int argv, char* s[]) {
    float x = atof(s[1]);
    x = x/-10000.0;
    if(1024+x == 1024 && x>0)
        return BOMB_ENDING;
    else
        return NORMAL_ENDING;
}
