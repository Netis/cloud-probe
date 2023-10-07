#include "Properties.hh"
#include <iostream>
#include <fstream>

int main(int argc, char** argv) {
    log4cpp::Properties properties;
    std::string inFile = (argc > 1) ? argv[1] : "log4cpp.properties";  
    std::ifstream in(inFile.c_str());

    properties.load(in);
    properties.save(std::cout);
    return 0;
}

