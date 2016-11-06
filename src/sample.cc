#include <cstdio>

struct A {
    __attribute__((noinline))
    static double calc(int count)
    {
        double sum0 = 0.0;
        double sum1 = 0.0;
        double sum2 = 0.0;
        double sum3 = 0.0;
        double sum4 = 0.0;
        double sum5 = 0.0;
        double sum6 = 0.0;
        double sum7 = 0.0;
        for (int i = 0; i < count; i+=8) {
            sum0 += 0.1;
            sum1 += 0.1;
            sum2 += 0.1;
            sum3 += 0.1;
            sum4 += 0.1;
            sum5 += 0.1;
            sum6 += 0.1;
            sum7 += 0.1;
        }

        return sum0 + sum1 + sum2 + sum3 + sum4 + sum5 + sum6 + sum7;
    }
};

int main(int argc, char ** argv)
{
    double r = 0.0;
    for (int i = 0; i < 5; i++)
        r = A::calc(1000 * 1000);

    std::printf("result = %f\n", r);

    return 0;
}

