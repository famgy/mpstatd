# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.7

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list


# Suppress display of executed commands.
$(VERBOSE).SILENT:


# A target that is always out of date.
cmake_force:

.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/gpf/projects/my_pstat

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/gpf/projects/my_pstat/build

# Include any dependencies generated for this target.
include CMakeFiles/mseqlist.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/mseqlist.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/mseqlist.dir/flags.make

CMakeFiles/mseqlist.dir/mseqlist.c.o: CMakeFiles/mseqlist.dir/flags.make
CMakeFiles/mseqlist.dir/mseqlist.c.o: ../mseqlist.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/gpf/projects/my_pstat/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object CMakeFiles/mseqlist.dir/mseqlist.c.o"
	/usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/mseqlist.dir/mseqlist.c.o   -c /home/gpf/projects/my_pstat/mseqlist.c

CMakeFiles/mseqlist.dir/mseqlist.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/mseqlist.dir/mseqlist.c.i"
	/usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/gpf/projects/my_pstat/mseqlist.c > CMakeFiles/mseqlist.dir/mseqlist.c.i

CMakeFiles/mseqlist.dir/mseqlist.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/mseqlist.dir/mseqlist.c.s"
	/usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/gpf/projects/my_pstat/mseqlist.c -o CMakeFiles/mseqlist.dir/mseqlist.c.s

CMakeFiles/mseqlist.dir/mseqlist.c.o.requires:

.PHONY : CMakeFiles/mseqlist.dir/mseqlist.c.o.requires

CMakeFiles/mseqlist.dir/mseqlist.c.o.provides: CMakeFiles/mseqlist.dir/mseqlist.c.o.requires
	$(MAKE) -f CMakeFiles/mseqlist.dir/build.make CMakeFiles/mseqlist.dir/mseqlist.c.o.provides.build
.PHONY : CMakeFiles/mseqlist.dir/mseqlist.c.o.provides

CMakeFiles/mseqlist.dir/mseqlist.c.o.provides.build: CMakeFiles/mseqlist.dir/mseqlist.c.o


mseqlist: CMakeFiles/mseqlist.dir/mseqlist.c.o
mseqlist: CMakeFiles/mseqlist.dir/build.make

.PHONY : mseqlist

# Rule to build all files generated by this target.
CMakeFiles/mseqlist.dir/build: mseqlist

.PHONY : CMakeFiles/mseqlist.dir/build

CMakeFiles/mseqlist.dir/requires: CMakeFiles/mseqlist.dir/mseqlist.c.o.requires

.PHONY : CMakeFiles/mseqlist.dir/requires

CMakeFiles/mseqlist.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/mseqlist.dir/cmake_clean.cmake
.PHONY : CMakeFiles/mseqlist.dir/clean

CMakeFiles/mseqlist.dir/depend:
	cd /home/gpf/projects/my_pstat/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/gpf/projects/my_pstat /home/gpf/projects/my_pstat /home/gpf/projects/my_pstat/build /home/gpf/projects/my_pstat/build /home/gpf/projects/my_pstat/build/CMakeFiles/mseqlist.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/mseqlist.dir/depend

