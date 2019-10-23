#include <string.h>
#include "utils.h"
#include "a_tester.h"

long f(long x){
    if (x%2 == 0)
	return x/2;
    else if (x%3 == 0)
	return x/3;
    else
        return 3*x + 1;
}

// {"s":{"length": 4}}
int main(int argc, char* s[]) {
    int symvar = atoi(s[1]);
    if (symvar > 6 || symvar <= 0){
        return 1;
    }
    long j = f(symvar);
    int loopcount = 1;
    while(j != 1){
	j = f(j);
        loopcount ++;
    }
    printf("%d",loopcount);
    if(loopcount == 3)
        return BOMB_ENDING;
    else
        return NORMAL_ENDING;
}