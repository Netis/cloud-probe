#include <log4cpp/Category.hh>
#include <log4cpp/RollingFileAppender.hh>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <iostream>

using namespace log4cpp;
using namespace std;
static const char* const test_message = "message";

bool remove_impl(const char* filename)
{
   int res = remove(filename);
   
   if (res != 0 && errno != ENOENT)
      cout << "Can't remove file '" << filename << "'.\n";

   return res == 0 || (res != 0 && errno == ENOENT);
}

bool remove_files()
{
   if (!remove_impl("rolling_file.log"))
      return false;
   if (!remove_impl("rolling_file.log.1"))
      return false;
   if (!remove_impl("rolling_file.log.2"))
      return false;

   return true;
}

bool setup()
{
   if (!remove_files())
      return false;

   Category& root = Category::getRoot();
   root.addAppender(new RollingFileAppender("rolling-appender", "rolling_file.log", 40, 3));
   root.setPriority(Priority::DEBUG);

   return true;
}

void make_log_files()
{
   Category::getRoot().debugStream() << test_message << 1;
   Category::getRoot().debugStream() << test_message << 2;
   Category::getRoot().debugStream() << test_message << 3;
   Category::getRoot().debugStream() << test_message << 4;
   Category::getRoot().debugStream() << test_message << 5;
}

bool exists(const char* filename)
{
   FILE* f = fopen(filename, "r");
   if (f == NULL)
   {
      cout << "File '" << filename << "' doesn't exists.\n"; 
      return false;
   }

   fclose(f);

   return true;
}

bool check_log_files()
{
   bool result = exists("rolling_file.log") &&
                 exists("rolling_file.log.1") &&
                 exists("rolling_file.log.2");

   Category::shutdown();
   return result && remove_files();
}

int main()
{
   if (!setup())
   {
      cout << "Setup has failed. Check for permissions on files 'rolling_file.log*'.\n";
      return -1;
   }

   make_log_files();

   if (check_log_files())
      return 0;
   else 
      return -1;
}