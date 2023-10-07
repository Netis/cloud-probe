This folder holds the project file for making a version of log4cpp that uses boost 1.28.0 
and STLport 4.5.3.

Compiling:
---------
This is a full list of the dependencies, in the order they should be included:

1. STLport 4.5.3
2. Microsoft Platform SDK, "Core" SDK. Tested with the 11/2001 and 10/2002 versions.
3. boost 1.28.0

All dependencies must be in the include and lib paths of MSVC. This can either be done
globally, or in the project file. 

Currently, the project file looks for the dependencies starting in a directory at the 
same level as that holding the log4cpp package. So if you have log4cpp in 
c:\packages\log4cpp, you would need to put the dependencies also in c:\packages.

Running:
-------
The boost library adds the run-time dependency of boost_threadmon.dll. This dll
must be in the executable path when using the boost version of log4cpp.

Running tests:
-------------
Note the version of log4cpp that is a dependency of the test you are running!
Currently, most of the tests are dependent on the regular dll version of log4cpp.


David Resnick
MobileSpear Inc.
dresnick@mobilespear.con