#include "rtsp.hpp"
#include "h264.h"
#include "rtp_packet.hpp"

#include <cassert>
#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <iostream>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <sstream>
#include <thread>

#include <iostream>
#include <fstream>
#include <vector>
#include <opencv2/opencv.hpp> // OpenCV 사용
extern "C" {
#include <libavcodec/avcodec.h>
#include <libavutil/avutil.h>
#include <libavutil/imgutils.h>
}
#define OUTPUT_FILENAME "output.h264"

// Function to read a PNG image and convert it to YUV format
std::vector<uint8_t> convertPNGToYUV420P(const std::string &filename, int &width, int &height) {
    // Load the PNG image
    cv::Mat img = cv::imread(filename, cv::IMREAD_COLOR);
    if (img.empty()) {
        throw std::runtime_error("Failed to read the PNG image.");
    }

    // Original dimensions
    int original_width = img.cols;
    int original_height = img.rows;

    // Ensure even dimensions for YUV420P
    if (original_width % 2 != 0 || original_height % 2 != 0) {
        cv::resize(img, img, cv::Size(original_width & ~1, original_height & ~1));
    }

    // Set output width and height
    width = img.cols;
    height = img.rows;

    // Convert BGR to YUV420
    cv::Mat img_yuv;
    cv::cvtColor(img, img_yuv, cv::COLOR_BGR2YUV_I420);

    // Prepare YUV420P buffer
    size_t y_size = width * height;              // Luminance (Y)
    size_t uv_size = y_size / 4;                 // Chrominance (U and V)
    std::vector<uint8_t> yuv_buffer(y_size + 2 * uv_size);

    // Split Y, U, and V planes
    uint8_t *y_plane = img_yuv.data;
    uint8_t *u_plane = y_plane + y_size;
    uint8_t *v_plane = u_plane + uv_size;

    // Copy data into vector
    std::memcpy(yuv_buffer.data(), y_plane, y_size);                      // Copy Y plane
    std::memcpy(yuv_buffer.data() + y_size, u_plane, uv_size);            // Copy U plane
    std::memcpy(yuv_buffer.data() + y_size + uv_size, v_plane, uv_size);  // Copy V plane

    return yuv_buffer;
}

RTSP::RTSP(const char *filename, int width, int height, int fps, AVPixelFormat pix_fmt) /*: h264_file(filename)*/ 
{
    av_log_set_level(AV_LOG_DEBUG);

    codec = avcodec_find_encoder_by_name(codec_name);
    if(!codec) {
        std::cerr << "Codec not found." << std::endl;
        exit(0);
    }
    c = avcodec_alloc_context3(codec);
    if(!c) {
        std::cerr << "Codec not allocate codec context." << std::endl;
        exit(0);
    }


    // Set codec parameters
    c->bit_rate = 400000;
    c->width = width;
    c->height = height;
    c->time_base = {1, fps};
    c->framerate = {fps, 1};

    c->gop_size = 10;
    c->max_b_frames = 1;
    c->pix_fmt = pix_fmt;

    //if (codec->id == AV_CODEC_ID_H264) {
    //    av_dict_set(codec_ctx->priv_data, "preset", "ultrafast", 0);
    //}

}

RTSP::~RTSP()
{
	close(this->server_rtcp_sock_fd);
	close(this->server_rtp_sock_fd);
	close(this->server_rtsp_sock_fd);
}

int RTSP::Socket(int domain, int type, int protocol)
{
	int sockfd;
	const int optval = 1;

	if((sockfd = socket(domain, type, protocol)) < 0) {
        	fprintf(stderr, "RTSP::Socket() failed: %s\n", strerror(errno));
        	return sockfd;
    	}

    	if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) < 0) {
        	fprintf(stderr, "setsockopt() failed: %s\n", strerror(errno));
        	return -1;
    	}

    	if (setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &MAX_UDP_PACKET_SIZE,
			sizeof(MAX_UDP_PACKET_SIZE)) < 0)
	{
		fprintf(stderr, "setsockopt() failed: %s\n", strerror(errno));
		return -1;
	}
	return sockfd;
}

bool RTSP::Bind(int sockfd, const char *IP, const uint16_t port)
{
    sockaddr_in addr{};
    memset(&addr, 0 , sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, IP, &addr.sin_addr);
    if (bind(sockfd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) < 0) {
        fprintf(stderr, "bind() failed: %s\n", strerror(errno));
        return false;
    }
    return true;
}

bool RTSP::rtsp_sock_init(int rtspSockfd, const char *IP, const uint16_t port, const int64_t ListenQueue)
{
    if (!RTSP::Bind(rtspSockfd, IP, port))
        return false;

    if (listen(rtspSockfd, ListenQueue) < 0) {
        fprintf(stderr, "listen() failed: %s\n", strerror(errno));
        return false;
    }
    return true;
}

void RTSP::Start(const int ssrcNum, const char *sessionID, const int timeout, const float fps)
{
    this->server_rtsp_sock_fd = RTSP::Socket(AF_INET, SOCK_STREAM);
    if (!RTSP::rtsp_sock_init(this->server_rtsp_sock_fd, "0.0.0.0", SERVER_RTSP_PORT)) {
        fprintf(stderr, "failed to create RTSP socket: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
    this->server_rtp_sock_fd = RTSP::Socket(AF_INET, SOCK_DGRAM);
    this->server_rtcp_sock_fd = RTSP::Socket(AF_INET, SOCK_DGRAM);

    if (!RTSP::Bind(this->server_rtp_sock_fd, "0.0.0.0", SERVER_RTP_PORT)) {
        fprintf(stderr, "failed to create RTP socket: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
    if (!RTSP::Bind(this->server_rtcp_sock_fd, "0.0.0.0", SERVER_RTCP_PORT)) {
        fprintf(stderr, "failed to create RTCP socket: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    fprintf(stdout, "rtsp://127.0.0.1:%d\n", SERVER_RTSP_PORT);

    //while (true)
    //{
    sockaddr_in cliAddr{};
    bzero(&cliAddr, sizeof(cliAddr));
    socklen_t addrLen = sizeof(cliAddr);
    auto cli_sockfd = accept(this->server_rtsp_sock_fd, reinterpret_cast<sockaddr *>(&cliAddr), &addrLen);
    if (cli_sockfd < 0) {
        fprintf(stderr, "accept error(): %s\n", strerror(errno));
        //continue;
        return;
    }
    char IPv4[16]{0};
    fprintf(stdout,
            "Connection from %s:%d\n",
            inet_ntop(AF_INET, &cliAddr.sin_addr, IPv4, sizeof(IPv4)),
            ntohs(cliAddr.sin_port));
    this->serve_client(cli_sockfd, cliAddr, this->server_rtp_sock_fd, ssrcNum, sessionID, timeout, fps);
    //}
}

char *RTSP::line_parser(char *src, char *line)
{
    while (*src != '\n')
        *(line++) = *(src++);

    *line = '\n';
    *(++line) = 0;
    return (src + 1);
}
std::string ParseMethod(const std::string& request) {
    std::istringstream requestStream(request);
    std::string method;
    requestStream >> method;
    return method;
}

int ParseCSeq(const std::string& request) {
    std::istringstream requestStream(request);
    std::string line;
    while (getline(requestStream, line)) {
        if (line.find("CSeq") != std::string::npos) {
            std::istringstream lineStream(line);
            std::string label;
            int cseq;
            lineStream >> label >> cseq;
            return cseq;
        }
    }
    return -1; // CSeq not found
}

std::pair<int, int> ParsePorts(const std::string& request) {
    std::istringstream requestStream(request);
    std::string line;
    while (getline(requestStream, line)) {
        if (line.find("client_port=") != std::string::npos) {
            std::istringstream lineStream(line);
            std::string label;

            while (getline(lineStream, label, '/')) {
                std::string portRange;
                getline(lineStream, portRange);
                size_t eqPos = portRange.find('=') + 1;
                size_t dashPos = portRange.find('-');

                if (dashPos != std::string::npos) {
                    
                    int rtpPort = stoi(portRange.substr(eqPos, dashPos - eqPos));
                    int rtcpPort = stoi(portRange.substr(dashPos + 1));
		            return {rtpPort, rtcpPort};
                }
            }
        }
    }
    return {-1, -1};
}

static void encode(AVCodecContext *enc_ctx, AVFrame *frame, AVPacket *pkt, FILE *outfile)
{
    int ret;
    /* send the frame to the encoder */
    if (frame)
        printf("Send frame %3 PRId64 \n", frame->pts);
    ret = avcodec_send_frame(enc_ctx, frame);
    if (ret < 0) {
        fprintf(stderr, "Error sending a frame for encoding\n");
        exit(1);
    }

    while (ret >= 0) {
        ret = avcodec_receive_packet(enc_ctx, pkt);
        if (ret == AVERROR(EAGAIN) || ret == AVERROR_EOF)
            return;
        else if (ret < 0) {
            fprintf(stderr, "Error during encoding\n");
            exit(1);
        }
        printf("Write packet %3 PRId64 (size=%5d)\n", pkt->pts, pkt->size);
        fwrite(pkt->data, 1, pkt->size, outfile);
        av_packet_unref(pkt);
    }
}

// RTP 전송 함수
void send_rtp_packet(int sockfd, struct sockaddr_in &clientSock, uint8_t *data, int size, uint16_t &sequence, uint32_t timestamp, uint32_t ssrc) {
    uint8_t rtp_header[12] = {0};
    rtp_header[0] = 0x80; // Version 2, no padding, no extension, 0 CSRCs
    rtp_header[1] = 0x60; // Payload type 96 (dynamic), no marker bit
    rtp_header[2] = (sequence >> 8) & 0xFF; // Sequence number high byte
    rtp_header[3] = sequence & 0xFF;        // Sequence number low byte
    rtp_header[4] = (timestamp >> 24) & 0xFF;
    rtp_header[5] = (timestamp >> 16) & 0xFF;
    rtp_header[6] = (timestamp >> 8) & 0xFF;
    rtp_header[7] = timestamp & 0xFF;
    rtp_header[8] = (ssrc >> 24) & 0xFF;
    rtp_header[9] = (ssrc >> 16) & 0xFF;
    rtp_header[10] = (ssrc >> 8) & 0xFF;
    rtp_header[11] = ssrc & 0xFF;

    uint8_t rtp_packet[1500]; // RTP 패킷 버퍼
    int max_payload_size = 1400; // RTP 페이로드 크기 제한 (MTU 고려)

    if (size <= max_payload_size) {
        // 단일 RTP 패킷
        memcpy(rtp_packet, rtp_header, 12);
        memcpy(rtp_packet + 12, data, size);
        sendto(sockfd, rtp_packet, 12 + size, 0, (struct sockaddr *)&clientSock, sizeof(clientSock));
        sequence++;
    } else {
        // NAL 단위를 조각내어 전송 (FU-A 형식)
        uint8_t nal_header = data[0]; // 첫 바이트는 NAL 헤더
        uint8_t nal_type = nal_header & 0x1F; // NAL 유형 추출
        uint8_t fu_indicator = (nal_header & 0xE0) | 28; // FU-A 표시자
        int remaining = size - 1;
        uint8_t *nal_data = data + 1;
        bool start = true, end = false;

        while (remaining > 0) {
            int chunk_size = std::min(max_payload_size - 2, remaining);
            uint8_t fu_header = nal_type;
            if (start) {
                fu_header |= 0x80; // Start bit
                start = false;
            }
            if (remaining == chunk_size) {
                fu_header |= 0x40; // End bit
                end = true;
            }

            memcpy(rtp_packet, rtp_header, 12);
            rtp_packet[12] = fu_indicator;
            rtp_packet[13] = fu_header;
            memcpy(rtp_packet + 14, nal_data, chunk_size);

            sendto(sockfd, rtp_packet, 14 + chunk_size, 0, (struct sockaddr *)&clientSock, sizeof(clientSock));
            sequence++;
            remaining -= chunk_size;
            nal_data += chunk_size;
        }
    }
}

void stream_h264_rtp(const std::string &file_name, struct sockaddr_in &clientSock, int sockfd, uint16_t client_rtp_port) {
    // RTP 관련 변수
    static uint16_t sequence = 0;
    static uint32_t timestamp = 0;
    const uint32_t ssrc = 12345678; // SSRC (고유 값)
    const uint32_t timeStampStep = 90000 / 25; // 25fps 기준

    // 클라이언트 포트 설정
    clientSock.sin_port = htons(client_rtp_port);

    // H.264 파일 열기
    FILE *f = fopen(file_name.c_str(), "rb");
    if (!f) {
        std::cerr << "Failed to open H.264 file: " << file_name << std::endl;
        return;
    }

    uint8_t buffer[1500];
    while (!feof(f)) {
        // NAL 단위 읽기
        int nal_size = fread(buffer, 1, sizeof(buffer), f);
        if (nal_size <= 0) {
            break;
        }

        // RTP 패킷 전송
        send_rtp_packet(sockfd, clientSock, buffer, nal_size, sequence, timestamp, ssrc);

        // 타임스탬프 업데이트
        timestamp += timeStampStep;

        // Sleep to simulate frame timing
        usleep(1000 * 1000 / 25); // 25fps 기준
    }

    fclose(f);
}

void RTSP::serve_client(int clientfd, const sockaddr_in &cliAddr, int rtpFD, const int ssrcNum, const char *sessionID, const int timeout, const float fps)
{
    char url[100]{0};
    char version[10]{0};
    char line[500]{0};
    int cseq;
    int64_t heartbeatCount = 0;
    char recvBuf[1024]{0}, sendBuf[1024]{0};



    while (true)
    {
        auto recvLen = recv(clientfd, recvBuf, sizeof(recvBuf), 0);
        if (recvLen <= 0)
            break;
        recvBuf[recvLen] = 0;

        fprintf(stdout,"TestStart\n");
        fprintf(stdout, "--------------- [C->S] --------------\n");
        fprintf(stdout, "%s", recvBuf);
        fprintf(stdout,"Test000\n");


        //Request buffer
        std::string method = ParseMethod(recvBuf);
        int cseq = ParseCSeq(recvBuf);

        fprintf(stdout,"Test001\n");
        char *bufferPtr = RTSP::line_parser(recvBuf, line);

        fprintf(stdout,"Test002\n");
        memcpy(url, "rtsp:127.0.0.1:8554", sizeof(7));

        if (method == "OPTIONS") {
            RTSP::replyCmd_OPTIONS(sendBuf, sizeof(sendBuf), cseq);
        } else if (method =="DESCRIBE") {
            RTSP::replyCmd_DESCRIBE(sendBuf, sizeof(sendBuf), cseq, url);
        } else if (method == "SETUP") {
            auto ports = ParsePorts(recvBuf);
            this->client_rtp_port = ports.first;
            this->client_rtcp_port = ports.second;

            RTSP::replyCmd_SETUP(sendBuf, sizeof(sendBuf), cseq, this->client_rtp_port, ssrcNum, sessionID, timeout);
        } else if (method == "PLAY") {
            RTSP::replyCmd_PLAY(sendBuf, sizeof(sendBuf), cseq, sessionID, timeout);
        } else {
            fprintf(stderr, "Parse method error\n");
            break;
        }        
        fprintf(stdout,"Test003\n");


        fprintf(stdout, "--------------- [S->C] --------------\n");
        fprintf(stdout, "%s", sendBuf);
        if (send(clientfd, sendBuf, strlen(sendBuf), 0) < 0) {
            fprintf(stderr, "RTSP::serve_client() send() failed: %s\n", strerror(errno));
            break;
        }

        if (method== "PLAY") {
            char IPv4[16]{0};
            inet_ntop(AF_INET, &cliAddr.sin_addr, IPv4, sizeof(IPv4));

            struct sockaddr_in clientSock{};
            bzero(&clientSock, sizeof(sockaddr_in));
            clientSock.sin_family = AF_INET;
            inet_pton(clientSock.sin_family, IPv4, &clientSock.sin_addr);
            clientSock.sin_port = htons(this->client_rtp_port);

            fprintf(stdout, "start send stream to %s:%d\n", IPv4, ntohs(clientSock.sin_port));

            while(1){
                // Open the codec
                if (avcodec_open2(c, codec, nullptr) < 0)
                {
                    std::cerr << "Could not open codec." << std::endl;
                    exit(0);
                }

                f = fopen("hello.h264", "wb");
                if (!f)
                {
                    fprintf(stderr, "Could not open %s\n", "hello.h264");
                    exit(0);
                }

                AVPacket* pkt = av_packet_alloc();
                if (!pkt)
                    exit(1);

                const auto timeStampStep = uint32_t(90000 / fps);
                const auto sleepPeriod = uint32_t(1000 * 1000 / fps);
                RtpHeader rtpHeader(0, 0, ssrcNum);
                RtpPacket rtpPack{rtpHeader};


                // Step 1: Convert PNG to YUV
                //int width, height;
                //std::vector<uint8_t> yuv_data = convertPNGToYUV420P(file_name, width, height);
                //std::cout << "loadImg - width : " << width << " height : " << height << std::endl;

                

                // Step 2: make Frame
                std::cout<<"Step2\n";
                AVFrame *frame = av_frame_alloc();
                if(!frame){
                    fprintf(stderr, "Could not allcate video frame\n");
                    exit(1);
                }
                frame->format = c->pix_fmt;
                frame->width = c->width;
                frame->height = c->height;

                std::cout<<"Step3\n";
                ret = av_frame_get_buffer(frame, 32);
                if(ret < 0){
                    std::cout << AVERROR(ret) << std::endl;
                    fprintf(stderr, "Could not allcate video frame data\n");
                    exit(1);
                }
                std::cout << ret << std::endl;

                std::cout<<"start frame process\n";
                // encode 1 second of video
                for(i =0; i<25; i++) {
                    fflush(stdout);

                    ret = av_frame_make_writable(frame);
                    if(ret<0)
                        exit(1);

                    /* prepare a dummy image */
                    /* Y */
                    for (y = 0; y < c->height; y++)
                    {
                        for (x = 0; x < c->width; x++)
                        {
                            frame->data[0][y * frame->linesize[0] + x] = 255; // Y 값 최대화
                        }
                    }
                    /* Cb and Cr */
                    for (y = 0; y < c->height / 2; y++)
                    {
                        for (x = 0; x < c->width / 2; x++)
                        {
                            frame->data[1][y * frame->linesize[1] + x] = 128; // Cb 중립값
                            frame->data[2][y * frame->linesize[2] + x] = 128; // Cr 중립값
                        }
                    }

                    /* Y */
                    // for (y = 0; y < c->height; y++)
                    // {
                    //     for (x = 0; x < c->width; x++)
                    //     {
                    //         frame->data[0][y * frame->linesize[0] + x] = x + y + i * 3;
                    //     }
                    // }
                    // /* Cb and Cr */
                    // for (y = 0; y < c->height / 2; y++)
                    // {
                    //     for (x = 0; x < c->width / 2; x++)
                    //     {
                    //         frame->data[1][y * frame->linesize[1] + x] = 128 + y + i * 2;
                    //         frame->data[2][y * frame->linesize[2] + x] = 64 + x + i * 5;
                    //     }
                    // }
                    frame->pts = i;

                    //encode the image
                    encode(c, frame, pkt, f);
                }
                std::cout<<"end frame process\n";
                //flush the encoder
                uint8_t endcode[] = { 0, 0, 1, 0xb7 };
                encode(c, NULL, pkt, f);
                fwrite(endcode, 1, sizeof(endcode), f);
                fclose(f);

                stream_h264_rtp("hello.h264", clientSock, server_rtp_sock_fd, this->client_rtp_port);
                //avcodec_free_context(&c);
                //avcodec_flush_buffers(c);   //context는 그대로, 버퍼만 초기화
                avcodec_close(c);
                av_frame_free(&frame);
                av_packet_free(&pkt);
                
                //std::cout << "end.\n";
                //return;
                //break;
            }
        }
    }
    fprintf(stdout, "finish\n");
    close(clientfd);
}

int64_t RTSP::push_stream(int sockfd, RtpPacket &rtpPack, const uint8_t *data, const int64_t dataSize, const sockaddr *to, const uint32_t timeStampStep)
{
    const uint8_t naluHeader = data[0];
    if (dataSize <= MAX_RTP_DATA_SIZE) {
        rtpPack.load_data(data, dataSize);
        auto ret = rtpPack.rtp_sendto(sockfd, dataSize + RTP_HEADER_SIZE, 0, to, timeStampStep);
        if (ret < 0)
            fprintf(stderr, "RTP_Packet::rtp_sendto() failed: %s\n", strerror(errno));
        return ret;
    }

    const int64_t packetNum = dataSize / MAX_RTP_DATA_SIZE;
    const int64_t remainPacketSize = dataSize % MAX_RTP_DATA_SIZE;
    int64_t pos = 1;
    int64_t sentBytes = 0;
    auto payload = rtpPack.get_payload();
    for (int64_t i = 0; i < packetNum; i++) {
        rtpPack.load_data(data + pos, MAX_RTP_DATA_SIZE, FU_SIZE);
        payload[0] = (naluHeader & NALU_F_NRI_MASK) | SET_FU_A_MASK;
        payload[1] = naluHeader & NALU_TYPE_MASK;
        if (!i)
            payload[1] |= FU_S_MASK;
        else if (i == packetNum - 1 && remainPacketSize == 0)
            payload[1] |= FU_E_MASK;

        auto ret = rtpPack.rtp_sendto(sockfd, MAX_RTP_PACKET_LEN, 0, to, timeStampStep);
        if (ret < 0) {
            fprintf(stderr, "RTP_Packet::rtp_sendto() failed: %s\n", strerror(errno));
            return -1;
        }
        sentBytes += ret;
        pos += MAX_RTP_DATA_SIZE;
    }
    if (remainPacketSize > 0) {
        rtpPack.load_data(data + pos, remainPacketSize, FU_SIZE);
        payload[0] = (naluHeader & NALU_F_NRI_MASK) | SET_FU_A_MASK;
        payload[1] = (naluHeader & NALU_TYPE_MASK) | FU_E_MASK;
        auto ret = rtpPack.rtp_sendto(sockfd, remainPacketSize + RTP_HEADER_SIZE + FU_SIZE, 0, to, timeStampStep);
        if (ret < 0) {
            fprintf(stderr, "RTP_Packet::rtp_sendto() failed: %s\n", strerror(errno));
            return -1;
        }
        sentBytes += ret;
    }
    return sentBytes;
}

void RTSP::replyCmd_OPTIONS(char *buffer, const int64_t bufferLen, const int cseq)
{
    snprintf(buffer, bufferLen, "RTSP/1.0 200 OK\r\nCseq: %d\r\nPublic: OPTIONS, DESCRIBE, SETUP, PLAY\r\n\r\n", cseq);
}

void RTSP::replyCmd_SETUP(char *buffer, const int64_t bufferLen, const int cseq, const int clientRTP_Port, const int ssrcNum, const char *sessionID, const int timeout)
{
    snprintf(buffer, bufferLen, "RTSP/1.0 200 OK\r\nCseq: %d\r\nTransport: RTP/AVP;unicast;client_port=%d-%d;server_port=%d-%d;ssrc=%d;mode=play\r\nSession: %s; timeout=%d\r\n\r\n",
             cseq, clientRTP_Port, clientRTP_Port + 1, SERVER_RTP_PORT, SERVER_RTCP_PORT, ssrcNum, sessionID, timeout);
}

void RTSP::replyCmd_PLAY(char *buffer, const int64_t bufferLen, const int cseq, const char *sessionID, const int timeout)
{
    snprintf(buffer, bufferLen, "RTSP/1.0 200 OK\r\nCseq: %d\r\nRange: npt=0.000-\r\nSession: %s; timeout=%d\r\n\r\n", cseq, sessionID, timeout);
}

void RTSP::replyCmd_HEARTBEAT(char *buffer, const int64_t bufferLen, const int cseq, const char *sessionID)
{
    snprintf(buffer, bufferLen, "RTSP/1.0 200 OK\r\nCseq: %d\r\nRange: npt=0.000-\r\nHeartbeat: %s; \r\n\r\n", cseq, sessionID);
}

void RTSP::replyCmd_DESCRIBE(char *buffer, const int64_t bufferLen, const int cseq, const char *url)
{
    char ip[100]{0};
    char sdp[500]{0};
    sscanf(url, "rtsp://%[^:]:", ip);
    snprintf(sdp, sizeof(sdp), "v=0\r\no=- 9%ld 1 IN IP4 %s\r\nt=0 0\r\na=control:*\r\nm=video 0 RTP/AVP 96\r\na=rtpmap:96 H264/90000\r\na=control:track0\r\n", time(nullptr), ip);
    snprintf(buffer, bufferLen, "RTSP/1.0 200 OK\r\nCseq: %d\r\nContent-Base: %s\r\nContent-type: application/sdp\r\nContent-length: %ld\r\n\r\n%s", cseq, url, strlen(sdp), sdp);
}
