#ifndef _NDCTEST_HH
#define _NDCTEST_HH

#include <string>
#include "cppunit/TestCaller.h"
#include "cppunit/TestCase.h"
#include "cppunit/TestSuite.h"
#include <iostream>

template<class NDCCLASS> class NDCTest : public CppUnit::TestCase {
    protected:
    NDCCLASS* _nDC;

    public:
    NDCTest() {
    }

    NDCTest(std::string name) : CppUnit::TestCase(name) {
    }

    virtual void registerTests(CppUnit::TestSuite* suite) {
       suite->addTest(new CppUnit::TestCaller<NDCTest>("testEmpty", 
           &NDCTest<NDCCLASS>::testEmpty));
       suite->addTest(new CppUnit::TestCaller<NDCTest>("testPush", 
           &NDCTest<NDCCLASS>::testPush));
       suite->addTest(new CppUnit::TestCaller<NDCTest>("testPush2", 
           &NDCTest<NDCCLASS>::testPush2));
       suite->addTest(new CppUnit::TestCaller<NDCTest>("testPop", 
           &NDCTest<NDCCLASS>::testPop));
       suite->addTest(new CppUnit::TestCaller<NDCTest>("testClear", 
           &NDCTest<NDCCLASS>::testClear));
     }

    int countTestCases() const {
        return 5;
    }

    void setUp() {
        _nDC = new NDCCLASS();
    }

    void tearDown() {
        delete _nDC;
    }

    void testEmpty() {
        assert(_nDC->_get() == "");
        assert(_nDC->_getDepth() == 0);
    }

    void testPush() {
        _nDC->_push("push context 1");
        assert(_nDC->_get() == "push context 1");
        assert(_nDC->_getDepth() == 1);
        
    }

    void testPush2() {
        _nDC->_push("push context 1");
        _nDC->_push("push context 2");
        assert(_nDC->_get() == "push context 1 push context 2");
        assert(_nDC->_getDepth() == 2);
        
    }

    void testPop() {
        _nDC->_push("push context 1");
        _nDC->_push("push context 2");
        _nDC->_pop();
        assert(_nDC->_get() == "push context 1");
        assert(_nDC->_getDepth() == 1);        
    }

    void testClear() {
        _nDC->_push("push context 1");
        _nDC->_push("push context 2");
        _nDC->_clear();
        assert(_nDC->_get() == "");
        assert(_nDC->_getDepth() == 0);        
    }
};

#endif // _NDCTEST_HH
