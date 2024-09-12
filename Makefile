CXX = g++
CXXFLAGS = -std=c++11 -Wall

SRC_DIR = src
OBJ_DIR = obj
BIN_DIR = bin

SRCS = $(wildcard $(SRC_DIR)/**/*.cpp)
OBJS = $(SRCS:$(SRC_DIR)/%.cpp=$(OBJ_DIR)/%.o)
DEPS = $(OBJS:.o=.d)

TARGET = $(BIN_DIR)/linux_agent

all: $(TARGET)

$(TARGET): $(OBJS)
    @mkdir -p $(BIN_DIR)
    $(CXX) $(CXXFLAGS) -o $@ $^

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.cpp
    @mkdir -p $(dir $@)
    $(CXX) $(CXXFLAGS) -MMD -c -o $@ $<

-include $(DEPS)

clean:
    rm -rf $(OBJ_DIR) $(BIN_DIR)

.PHONY: all clean
