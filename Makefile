CXX = g++
CXXFLAGS = -std=c++11 -Wall -Iinclude -Iinclude/core -Iinclude/platform/linux -Iinclude/utils -Iinclude/nDPI/src/include
LDFLAGS = -lpcap -lcap -Linclude/nDPI/src/lib -lndpi

SRC_DIR = src
PLATFORM_DIR = platform/linux
UTILS_DIR = utils
OBJ_DIR = obj
BIN_DIR = bin

SRC_SRCS = $(wildcard $(SRC_DIR)/**/*.cpp)
PLATFORM_SRCS = $(wildcard $(PLATFORM_DIR)/*.cpp)
UTILS_SRCS = $(wildcard $(UTILS_DIR)/*.cpp)
SRCS = $(SRC_SRCS) $(PLATFORM_SRCS) $(UTILS_SRCS)

SRC_OBJS = $(SRC_SRCS:$(SRC_DIR)/%.cpp=$(OBJ_DIR)/%.o)
PLATFORM_OBJS = $(PLATFORM_SRCS:$(PLATFORM_DIR)/%.cpp=$(OBJ_DIR)/%.o)
UTILS_OBJS = $(UTILS_SRCS:$(UTILS_DIR)/%.cpp=$(OBJ_DIR)/%.o)
OBJS = $(SRC_OBJS) $(PLATFORM_OBJS) $(UTILS_OBJS)

DEPS = $(OBJS:.o=.d)

TARGET = $(BIN_DIR)/linux_agent

all: $(TARGET)

$(TARGET): $(OBJS)
	@mkdir -p $(BIN_DIR)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) -MMD -c -o $@ $<

$(OBJ_DIR)/%.o: $(PLATFORM_DIR)/%.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) -MMD -c -o $@ $<

$(OBJ_DIR)/%.o: $(UTILS_DIR)/%.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) -MMD -c -o $@ $<

-include $(DEPS)

clean:
	rm -rf $(OBJ_DIR) $(BIN_DIR)

.PHONY: all clean