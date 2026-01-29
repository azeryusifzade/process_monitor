# Makefile for Process Monitor

CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -O2
TARGET = process_monitor
SOURCES = main.cpp process.cpp utils.cpp
OBJECTS = $(SOURCES:.cpp=.o)
HEADERS = process.h utils.h

# Default target
all: $(TARGET)

# Link the executable
$(TARGET): $(OBJECTS)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(OBJECTS)

# Compile source files
%.o: %.cpp $(HEADERS)
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Clean build files
clean:
	rm -f $(OBJECTS) $(TARGET)

# Install (optional)
install: $(TARGET)
	install -m 755 $(TARGET) /usr/local/bin/

# Uninstall (optional)
uninstall:
	rm -f /usr/local/bin/$(TARGET)

# Debug build
debug: CXXFLAGS += -g -DDEBUG
debug: clean $(TARGET)

# Run the program
run: $(TARGET)
	./$(TARGET)

# Run with verbose output
run-verbose: $(TARGET)
	./$(TARGET) -v

# Run without whitelist (show all detections)
run-no-whitelist: $(TARGET)
	./$(TARGET) -v --no-whitelist

# Help
help:
	@echo "Available targets:"
	@echo "  all               - Build the project (default)"
	@echo "  clean             - Remove build files"
	@echo "  debug             - Build with debug symbols"
	@echo "  run               - Build and run the program"
	@echo "  run-verbose       - Build and run with verbose output"
	@echo "  run-no-whitelist  - Build and run without whitelist filtering"
	@echo "  install           - Install to /usr/local/bin (requires root)"
	@echo "  uninstall         - Remove from /usr/local/bin (requires root)"
	@echo "  help              - Show this help message"

.PHONY: all clean install uninstall debug run run-verbose run-no-whitelist help