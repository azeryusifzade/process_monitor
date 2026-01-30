# Makefile for Process Monitor

CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -O2
TARGET = process_monitor
SOURCES = main.cpp process.cpp utils.cpp
OBJECTS = $(SOURCES:.cpp=.o)
HEADERS = process.h utils.h

# Default target
all: $(TARGET)

# Link the executable from object files
# This only runs if any .o file is newer than the executable
$(TARGET): $(OBJECTS)
	@echo "Linking $(TARGET)..."
	@$(CXX) $(CXXFLAGS) -o $(TARGET) $(OBJECTS)
	@echo "✓ Build complete!"

# Compile each .cpp to .o (only recompiles if source or headers change)
%.o: %.cpp $(HEADERS)
	@echo "Compiling $<..."
	@$(CXX) $(CXXFLAGS) -c $< -o $@

# Clean everything (executable AND object files)
clean:
	@echo "Cleaning build files..."
	@rm -f $(OBJECTS) $(TARGET)
	@echo "✓ Clean complete!"

# Clean only object files (keeps executable)
clean-obj:
	@echo "Removing object files..."
	@rm -f $(OBJECTS)
	@echo "✓ Object files removed!"

# Install (optional)
install: $(TARGET)
	install -m 755 $(TARGET) /usr/local/bin/

# Uninstall (optional)
uninstall:
	rm -f /usr/local/bin/$(TARGET)

# Debug build
debug: CXXFLAGS += -g -DDEBUG
debug: clean $(TARGET)

# Rebuild from scratch
rebuild: clean all

# Run the program
run: $(TARGET)
	./$(TARGET)

# Run with verbose output
run-verbose: $(TARGET)
	./$(TARGET) -v

# Run without whitelist (show all detections)
run-no-whitelist: $(TARGET)
	./$(TARGET) -v --no-whitelist

# Show compilation info
info:
	@echo "Compiler: $(CXX)"
	@echo "Flags: $(CXXFLAGS)"
	@echo "Sources: $(SOURCES)"
	@echo "Objects: $(OBJECTS)"
	@echo "Target: $(TARGET)"

# Help
help:
	@echo "Available targets:"
	@echo "  all               - Build the project (default) [INCREMENTAL]"
	@echo "  rebuild           - Clean and build from scratch"
	@echo "  clean             - Remove all build files (.o and executable)"
	@echo "  clean-obj         - Remove only .o files (keep executable)"
	@echo "  debug             - Build with debug symbols"
	@echo "  run               - Build and run the program"
	@echo "  run-verbose       - Build and run with verbose output"
	@echo "  run-no-whitelist  - Build and run without whitelist filtering"
	@echo "  install           - Install to /usr/local/bin (requires root)"
	@echo "  uninstall         - Remove from /usr/local/bin (requires root)"
	@echo "  info              - Show compilation settings"
	@echo "  help              - Show this help message"

.PHONY: all clean clean-obj install uninstall debug rebuild run run-verbose run-no-whitelist info help