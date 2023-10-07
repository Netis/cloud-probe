#define ERROR 666
#define LOG4CPP_FIX_ERROR_COLLISION 1

#include <log4cpp/Priority.hh>
#include <assert.h>

int main(int argc, char** argv) {
    assert(ERROR == 666);
    return 0;
}
