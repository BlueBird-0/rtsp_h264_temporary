#include <rtsp.hpp>

#include <iostream>
#include <cstdlib>

int main(int argc, char *argv[])
{
    if (argc != 3)
    {
        fprintf(stdout, "usage: %s <file name> <fps>\n", argv[0]);
        return 1;
    }

    std::cout << "fileName: " << argv[1] << std::endl;

    int width = 640;
    int height = 480;

    RTSP rtspServer(argv[1], width, height, atoi(argv[2]), AV_PIX_FMT_YUV420P);
    rtspServer.Start(19990825, "rpi5_picamera", 600, atof(argv[2]));

    return 0;
}
