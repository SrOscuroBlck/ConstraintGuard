CXX ?= clang++
CC ?= clang
CXXFLAGS = -std=c++17 -Wall -Wextra
CFLAGS = -Wall -Wextra
SRC_DIR = Embedded Drone System2

all: drone_planner flight_controller

drone_planner:
	$(CXX) $(CXXFLAGS) -c "$(SRC_DIR)/DynamicPathPlanning.cpp" -o /dev/null

flight_controller:
	$(CXX) $(CXXFLAGS) -c "$(SRC_DIR)/flight_controller.cpp" -o /dev/null
