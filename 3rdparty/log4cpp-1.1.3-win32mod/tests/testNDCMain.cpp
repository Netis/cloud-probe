#include <vector>
#include "cppunit/TestRegistry.h"
#include "cppunit/TextTestResult.h"
#include "cppunit/Test.h"
#include "cppunit/TestSuite.h"
#include "log4cpp/NDC.hh"
#include "NDCTest.hh"

int main(int argc, char** argv) {
    NDCTest<log4cpp::NDC> nDCTest("NDCTest<NDC>");

    CppUnit::TextTestResult result;
    CppUnit::TestSuite suite;

    nDCTest.registerTests(&suite);

    std::vector<CppUnit::Test*> tests = CppUnit::TestRegistry::getRegistry().getAllTests();
    for(std::vector<CppUnit::Test*>::iterator i = tests.begin(); i != tests.end(); i++) {
        (*i)->run(&result);
    }

    cout << result;

    return 0;
}
