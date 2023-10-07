#include <log4cpp/Filter.hh>
#include <iostream>

class TestFilter : public log4cpp::Filter {
    public:
    TestFilter() {};
    virtual ~TestFilter() {};

    protected:
    virtual log4cpp::Filter::Decision _decide(const log4cpp::LoggingEvent& event) {
	log4cpp::Filter::Decision decision = log4cpp::Filter::NEUTRAL;

	if (event.categoryName == "deny")
	    decision = log4cpp::Filter::DENY;
	
	if (event.categoryName == "accept")
	    decision = log4cpp::Filter::ACCEPT;

	return decision;
    };
};


class TestFilter2 : public log4cpp::Filter {
    public:
    TestFilter2() {};
    virtual ~TestFilter2() {};

    protected:
    virtual log4cpp::Filter::Decision _decide(const log4cpp::LoggingEvent& event) {
	log4cpp::Filter::Decision decision = log4cpp::Filter::NEUTRAL;

	if (event.ndc == "test")
	    decision = log4cpp::Filter::DENY;
	
	return decision;
    };
};

int main(int argc, char** argv) {
    TestFilter filter;

    bool resultsOK = true;
    
    std::cout << "decision 1 (should be 1): " << filter.decide(log4cpp::LoggingEvent("accept", "bla", "ndc", log4cpp::Priority::INFO)) << std::endl;

    std::cout << "decision 2 (should be -1): " << filter.decide(log4cpp::LoggingEvent("deny", "bla", "ndc", log4cpp::Priority::INFO)) << std::endl;

    std::cout << "decision 3 (should be 0): " << filter.decide(log4cpp::LoggingEvent("neither", "bla", "ndc", log4cpp::Priority::INFO)) << std::endl;

    std::cout << "decision 4 (should be 0): " << filter.decide(log4cpp::LoggingEvent("neither", "bla", "test", log4cpp::Priority::INFO)) << std::endl;

    filter.setChainedFilter(new TestFilter2());
    
    std::cout << "decision 5 (should be 0): " << filter.decide(log4cpp::LoggingEvent("neither", "bla", "ndc", log4cpp::Priority::INFO)) << std::endl;

    std::cout << "decision 6 (should be -1): " << filter.decide(log4cpp::LoggingEvent("neither", "bla", "test", log4cpp::Priority::INFO)) << std::endl;

    return 0;
}
