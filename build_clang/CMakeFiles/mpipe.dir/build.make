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
include CMakeFiles/mpipe.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/mpipe.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/mpipe.dir/flags.make

CMakeFiles/mpipe.dir/mpipe.c.o: CMakeFiles/mpipe.dir/flags.make
CMakeFiles/mpipe.dir/mpipe.c.o: ../mpipe.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/gpf/projects/my_pstat/build_clang/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object CMakeFiles/mpipe.dir/mpipe.c.o"
	/usr/bin/clang-3.9  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/mpipe.dir/mpipe.c.o   -c /home/gpf/projects/my_pstat/mpipe.c

CMakeFiles/mpipe.dir/mpipe.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/mpipe.dir/mpipe.c.i"
	/usr/bin/clang-3.9  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/gpf/projects/my_pstat/mpipe.c > CMakeFiles/mpipe.dir/mpipe.c.i

CMakeFiles/mpipe.dir/mpipe.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/mpipe.dir/mpipe.c.s"
	/usr/bin/clang-3.9  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/gpf/projects/my_pstat/mpipe.c -o CMakeFiles/mpipe.dir/mpipe.c.s

CMakeFiles/mpipe.dir/mpipe.c.o.requires:

.PHONY : CMakeFiles/mpipe.dir/mpipe.c.o.requires

CMakeFiles/mpipe.dir/mpipe.c.o.provides: CMakeFiles/mpipe.dir/mpipe.c.o.requires
	$(MAKE) -f CMakeFiles/mpipe.dir/build.make CMakeFiles/mpipe.dir/mpipe.c.o.provides.build
.PHONY : CMakeFiles/mpipe.dir/mpipe.c.o.provides

CMakeFiles/mpipe.dir/mpipe.c.o.provides.build: CMakeFiles/mpipe.dir/mpipe.c.o


mpipe: CMakeFiles/mpipe.dir/mpipe.c.o
mpipe: CMakeFiles/mpipe.dir/build.make

.PHONY : mpipe

# Rule to build all files generated by this target.
CMakeFiles/mpipe.dir/build: mpipe

.PHONY : CMakeFiles/mpipe.dir/build

CMakeFiles/mpipe.dir/requires: CMakeFiles/mpipe.dir/mpipe.c.o.requires

.PHONY : CMakeFiles/mpipe.dir/requires

CMakeFiles/mpipe.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/mpipe.dir/cmake_clean.cmake
.PHONY : CMakeFiles/mpipe.dir/clean

CMakeFiles/mpipe.dir/depend:
	cd /home/gpf/projects/my_pstat/build_clang && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/gpf/projects/my_pstat /home/gpf/projects/my_pstat /home/gpf/projects/my_pstat/build_clang /home/gpf/projects/my_pstat/build_clang /home/gpf/projects/my_pstat/build_clang/CMakeFiles/mpipe.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/mpipe.dir/depend

