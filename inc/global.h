#ifndef GLOBAL_H
#define GLOBAL_H
#include <string.h>

enum ServerStreamType{
    Audio = 1,
    Video,
};

class ServerStream{
    public:
    ServerStreamType type;
    static ServerStream& getInstance(){
        static ServerStream instance;
        return instance;
    }
};

static std::string g_inputFile = "example/dragon.h264";

#endif //GLOBAL_H
