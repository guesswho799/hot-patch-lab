#include <stdio.h>
#include <unistd.h>

void func() { printf("test\n"); }

int main() {
  sleep(10000);
  func();
  return 0;
}
