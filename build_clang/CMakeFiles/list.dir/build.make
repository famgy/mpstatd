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
CMAKE_BINARY_DIR = /home/gpf/projects/my_pstat/build_clang

# Include any dependencies generated for this target.
include CMakeFiles/list.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/list.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/list.dir/flags.make

CMakeFiles/list.dir/list.c.o: CMakeFiles/list.dir/flags.make
CMakeFiles/list.dir/list.c.o: ../list.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/gpf/projects/my_pstat/build_clang/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object CMakeFiles/list.dir/list.c.o"
	/usr/bin/clang-3.9  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/list.dir/list.c.o   -c /home/gpf/projects/my_pstat/list.c

CMakeFiles/list.dir/list.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/list.dir/list.c.i"
	/usr/bin/clang-3.9  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/gpf/projects/my_pstat/list.c > CMakeFiles/list.dir/list.c.i

CMakeFiles/list.dir/list.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/list.dir/list.c.s"
	/usr/bin/clang-3.9  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/gpf/projects/my_pstat/list.c -o CMakeFiles/list.dir/list.c.s

CMakeFiles/list.dir/list.c.o.requires:

.PHONY : CMakeFiles/list.dir/list.c.o.requires

CMakeFiles/list.dir/list.c.o.provides: CMakeFiles/list.dir/list.c.o.requires
	$(MAKE) -f CMakeFiles/list.dir/build.make CMakeFiles/list.dir/list.c.o.provides.build
.PHONY : CMakeFiles/list.dir/list.c.o.provides

CMakeFiles/list.dir/list.c.o.provides.build: CMakeFiles/list.dir/list.c.o


list: CMakeFiles/list.dir/list.c.o
list: CMakeFiles/list.dir/build.make

.PHONY : list

# Rule to build all files generated by this target.
CMakeFiles/list.dir/build: list

.PHONY : CMakeFiles/list.dir/build

CMakeFiles/list.dir/requires: CMakeFiles/list.dir/list.c.o.requires

.PHONY : CMakeFiles/list.dir/requires

CMakeFiles/list.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/list.dir/cmake_clean.cmake
.PHONY : CMakeFiles/list.dir/clean

CMakeFiles/list.dir/depend:
	cd /home/gpf/projects/my_pstat/build_clang && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/gpf/projects/my_pstat /home/gpf/projects/my_pstat /home/gpf/projects/my_pstat/build_clang /home/gpf/projects/my_pstat/build_clang /home/gpf/projects/my_pstat/build_clang/CMakeFiles/list.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/list.dir/depend
