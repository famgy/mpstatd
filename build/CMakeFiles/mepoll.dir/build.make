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
include CMakeFiles/mepoll.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/mepoll.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/mepoll.dir/flags.make

CMakeFiles/mepoll.dir/mepoll.c.o: CMakeFiles/mepoll.dir/flags.make
CMakeFiles/mepoll.dir/mepoll.c.o: ../mepoll.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/gpf/projects/my_pstat/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object CMakeFiles/mepoll.dir/mepoll.c.o"
	/usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/mepoll.dir/mepoll.c.o   -c /home/gpf/projects/my_pstat/mepoll.c

CMakeFiles/mepoll.dir/mepoll.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/mepoll.dir/mepoll.c.i"
	/usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/gpf/projects/my_pstat/mepoll.c > CMakeFiles/mepoll.dir/mepoll.c.i

CMakeFiles/mepoll.dir/mepoll.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/mepoll.dir/mepoll.c.s"
	/usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/gpf/projects/my_pstat/mepoll.c -o CMakeFiles/mepoll.dir/mepoll.c.s

CMakeFiles/mepoll.dir/mepoll.c.o.requires:

.PHONY : CMakeFiles/mepoll.dir/mepoll.c.o.requires

CMakeFiles/mepoll.dir/mepoll.c.o.provides: CMakeFiles/mepoll.dir/mepoll.c.o.requires
	$(MAKE) -f CMakeFiles/mepoll.dir/build.make CMakeFiles/mepoll.dir/mepoll.c.o.provides.build
.PHONY : CMakeFiles/mepoll.dir/mepoll.c.o.provides

CMakeFiles/mepoll.dir/mepoll.c.o.provides.build: CMakeFiles/mepoll.dir/mepoll.c.o


mepoll: CMakeFiles/mepoll.dir/mepoll.c.o
mepoll: CMakeFiles/mepoll.dir/build.make

.PHONY : mepoll

# Rule to build all files generated by this target.
CMakeFiles/mepoll.dir/build: mepoll

.PHONY : CMakeFiles/mepoll.dir/build

CMakeFiles/mepoll.dir/requires: CMakeFiles/mepoll.dir/mepoll.c.o.requires

.PHONY : CMakeFiles/mepoll.dir/requires

CMakeFiles/mepoll.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/mepoll.dir/cmake_clean.cmake
.PHONY : CMakeFiles/mepoll.dir/clean

CMakeFiles/mepoll.dir/depend:
	cd /home/gpf/projects/my_pstat/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/gpf/projects/my_pstat /home/gpf/projects/my_pstat /home/gpf/projects/my_pstat/build /home/gpf/projects/my_pstat/build /home/gpf/projects/my_pstat/build/CMakeFiles/mepoll.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/mepoll.dir/depend

