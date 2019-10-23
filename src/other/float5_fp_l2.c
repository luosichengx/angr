#include<stdio.h>
#include <stdlib.h>
#include "a_tester.h"

// {"s":{"length": 8}}
int main(int argv, char* s[]) {
    float x = atof(s[1]);
    x = x/10.0;
    x = x + 0.1;
    x = x * x;
    if (x > 0.1)
	x -= x;
    if(x != 0.02){
        x = x + 7.98;
        if(x == 8)
            return BOMB_ENDING;
    }
    return NORMAL_ENDING;
}
