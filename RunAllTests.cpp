
#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTestExt/MockSupport.h>



int main(int ac, char **av) {
    return CommandLineTestRunner::RunAllTests(ac, av);
}
