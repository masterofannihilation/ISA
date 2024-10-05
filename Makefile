# Variables
CXX = g++
CXXFLAGS = -Wall -Wextra -std=c++17 -g
LDFLAGS = -lpcap
TARGET = p2nprobe
SRC = p2nprobe.cpp
OBJ = $(SRC:.cpp=.o)

# Default rule to build the program
all: $(TARGET)

# Rule to compile the target
$(TARGET): $(OBJ)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(OBJ) $(LDFLAGS)

# Rule to compile object files
%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Clean rule to remove compiled files
clean:
	rm -f $(OBJ) $(TARGET)

# Phony targets to avoid filename conflicts
.PHONY: all clean
