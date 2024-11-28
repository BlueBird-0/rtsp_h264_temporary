# 프로젝트 명과 기본 설정
PROJECT_NAME = rtspServer
ROOT = $(CURDIR)
SRC_DIR = $(ROOT)/src
INCLUDE_DIR = $(ROOT)/inc
OBJ_DIR = $(ROOT)/objs

# 컴파일러와 플래그
CXX = g++
CXXFLAGS = -std=c++11 -O2 -I$(INCLUDE_DIR) -I/usr/include/opencv4
LDFLAGS = -lavcodec -lavformat -lavutil -lswscale -lswresample \
          -lopencv_core -lopencv_videoio -lopencv_highgui \
          -lopencv_imgcodecs -lopencv_imgproc

# 소스 파일 정의
SRCS = $(wildcard $(SRC_DIR)/*.cpp)
OBJS = $(SRCS:$(SRC_DIR)/%.cpp=$(OBJ_DIR)/%.o)

# 실행 파일 경로
EXECUTABLE = $(PROJECT_NAME)

# 빌드 규칙
.PHONY: all clean

all: $(EXECUTABLE)

# 실행 파일 생성 규칙
$(EXECUTABLE): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

# 개별 소스 파일을 객체 파일로 컴파일
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.cpp
	@mkdir -p $(OBJ_DIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

# CLEAN
clean:
	rm -rf $(OBJ_DIR) $(EXECUTABLE)

