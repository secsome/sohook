#include <stdio.h>

int func(int a, int b)
{
    return a + b;
}

int main()
{
    int a, b;
    printf("Enter two numbers: ");
    scanf("%d %d", &a, &b);
    printf("Sum: %d\n", func(a, b));
    return 0;
}
