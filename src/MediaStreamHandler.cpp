#include "Protos.h"
#include "utils.h"
#include "TCPHandler.h"
#include "UDPHandler.h"
#include "MediaStreamHandler.h"
#include "AudioCapture.h"
#include "OpusEncoder.h"
#include "H264Encoder.h"
#include "global.h"

#include <iostream>
#include <cstdint>
#include <cstring>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <chrono>
#include <thread>
#include <mutex>
#include <utility>
#include <random>
#define PCM_FRAME_SIZE 1152

MediaStreamHandler::MediaStreamHandler(): streamState(MediaStreamState::eMediaStream_Init){}

void MediaStreamHandler::HandleMediaStream() {
    Protos protos;

    short pcmBuffer[OPUS_FRAME_SIZE * OPUS_CHANNELS];
    unsigned char encodedBuffer[MAX_PACKET_SIZE];

    unsigned int octetCount = 0;
    unsigned int packetCount = 0;
    unsigned short seqNum = (unsigned short)utils::GetRanNum(16);
    unsigned int timestamp = (unsigned int)utils::GetRanNum(16);

    Protos::SenderReport sr;
    Protos::RTPHeader rtpHeader;

    AudioCapture audioCapture(OPUS_SAMPLE_RATE);
    OpusEncoder opusEncoder;
    H264Encoder h264_file(g_inputFile);

    while (true) {
        if(streamState == MediaStreamState::eMediaStream_Pause) {
            std::unique_lock<std::mutex> lck(streamMutex);
            condition.wait(lck);
        }
        else if (streamState == MediaStreamState::eMediaStream_Teardown) {
            break;
        }
        else if(streamState == MediaStreamState::eMediaStream_Play) {
            if(g_serverStreamType == Audio) {
                int rc = audioCapture.read(pcmBuffer, OPUS_FRAME_SIZE);
                if (rc != OPUS_FRAME_SIZE)
                {
                    continue;
                }

                int encoded_bytes = opusEncoder.encode(pcmBuffer, OPUS_FRAME_SIZE, encodedBuffer);

                // make RTP Packet.
                unsigned char rtpPacket[sizeof(Protos::RTPHeader) + encoded_bytes] = { 0, };
                protos.CreateRTPHeader(&rtpHeader, seqNum, timestamp, PROTO_OPUS);
                memcpy(rtpPacket, &rtpHeader, sizeof(rtpHeader));
                memcpy(rtpPacket + sizeof(rtpHeader), encodedBuffer, encoded_bytes);
                udpHandler->SendRTPPacket(rtpPacket, sizeof(rtpPacket));

                seqNum++;
                timestamp += PCM_FRAME_SIZE;
                packetCount++;
                octetCount += encoded_bytes;

                if (packetCount % 100 == 0)
                {
                    std::cout << "RTCP sent" << std::endl;
                    protos.CreateSR(&sr, timestamp, packetCount, octetCount);
                    udpHandler->SendSenderReport(&sr, sizeof(sr));
                }
            }else if (g_serverStreamType == Video) {
                auto cur_frame = h264_file.get_next_frame();
                const auto ptr_cur_frame = cur_frame.first;
                const auto encoded_bytes = cur_frame.second;

                if (encoded_bytes < 0) {
                    fprintf(stderr, "RTSP::serve_client() H264::getOneFrame() failed\n");
                    break;
                } else if (!encoded_bytes) {
                    fprintf(stdout, "Finish serving the user\n");
                    return;
                }

                // Determine if the frame is a complete NALU or needs fragmentation
                const int64_t start_code_len = H264Encoder::is_start_code(ptr_cur_frame, encoded_bytes, 4) ? 4 : 3;
                const unsigned char *nal_unit = ptr_cur_frame + start_code_len;
                const int nal_unit_size = encoded_bytes - start_code_len;

                // RTP Packetize the NALU
                if (nal_unit_size <= MAX_RTP_PAYLOAD_SIZE)
                {
                    // Single NAL Unit Packet
                    unsigned char rtpPacket[sizeof(Protos::RTPHeader) + nal_unit_size] = {0};
                    protos.CreateRTPHeader(&rtpHeader, seqNum, timestamp, PROTO_H264);
                    memcpy(rtpPacket, &rtpHeader, sizeof(rtpHeader));
                    memcpy(rtpPacket + sizeof(rtpHeader), nal_unit, nal_unit_size);
                    udpHandler->SendRTPPacket(rtpPacket, sizeof(rtpPacket));

                    seqNum++;
                }
                else
                {
                    // Fragmented NAL Unit Packet (FU-A)
                    int remaining = nal_unit_size;
                    const unsigned char nal_header = nal_unit[0];
                    const unsigned char fu_indicator = (nal_header & 0xE0) | 28; // FU-A NAL type
                    const unsigned char fu_header_base = nal_header & 0x1F;      // Original NAL type

                    const unsigned char *payload = nal_unit + 1;
                    while (remaining > 0)
                    {
                        const int fragment_size = std::min(remaining, MAX_RTP_PAYLOAD_SIZE);

                        unsigned char rtpPacket[sizeof(Protos::RTPHeader) + 2 + fragment_size] = {0};
                        protos.CreateRTPHeader(&rtpHeader, seqNum, timestamp, PROTO_H264);

                        // FU-A Header
                        unsigned char fu_header = fu_header_base;
                        if (remaining == nal_unit_size - 1)
                        {
                            fu_header |= 0x80; // Start bit
                        }
                        else if (remaining <= fragment_size)
                        {
                            fu_header |= 0x40; // End bit
                        }

                        // Build RTP Packet
                        memcpy(rtpPacket, &rtpHeader, sizeof(rtpHeader));
                        rtpPacket[sizeof(rtpHeader)] = fu_indicator;
                        rtpPacket[sizeof(rtpHeader) + 1] = fu_header;
                        memcpy(rtpPacket + sizeof(rtpHeader) + 2, payload, fragment_size);

                        udpHandler->SendRTPPacket(rtpPacket, sizeof(rtpPacket));
                        seqNum++;
                        remaining -= fragment_size;
                        payload += fragment_size;
                    }
                }

                usleep(sleepPeriod);


                /*
                // make RTP Packet.
                unsigned char rtpPacket[sizeof(Protos::RTPHeader) + encoded_bytes] = { 0, };
                protos.CreateRTPHeader(&rtpHeader, seqNum, timestamp, PROTO_H264);
                memcpy(rtpPacket, &rtpHeader, sizeof(rtpHeader));
                memcpy(rtpPacket + sizeof(rtpHeader), encodedBuffer, encoded_bytes);
                udpHandler->SendRTPPacket(rtpPacket, sizeof(rtpPacket));

                const int64_t start_code_len = H264Encoder::is_start_code(ptr_cur_frame, encoded_bytes, 4) ? 4 : 3;


                //RTSP::push_stream(rtpFD, rtpPacket, ptr_cur_frame + start_code_len, encoded_bytes - start_code_len, (sockaddr *)&clientSock, timeStampStep);
                usleep(sleepPeriod);
                */
            }
        }

    }
}

#define BIAS 0x84
#define CLIP 32635
uint8_t MediaStreamHandler::pcm_to_ulaw(int16_t pcm_val) {
    int16_t mask;
    int16_t seg;
    uint8_t uval;

    // Handle negative values
    if (pcm_val < 0) {
        pcm_val = BIAS - pcm_val;
        mask = 0x7F;
    } else {
        pcm_val += BIAS;
        mask = 0xFF;
    }

    // Clip the value
    if (pcm_val > CLIP) pcm_val = CLIP;

    // Convert PCM value to segment and μ-law value
    seg = 8;
    for (int16_t value = pcm_val; value >= (1 << (seg + 3)); seg++) {}

    uval = (seg << 4) | ((pcm_val >> (seg + 3)) & 0x0F);
    return ~uval & mask;
}

void MediaStreamHandler::SetCmd(const std::string& cmd) {
    std::lock_guard<std::mutex> lock(streamMutex);
    if (cmd == "PLAY") {
        streamState = MediaStreamState::eMediaStream_Play;
        condition.notify_all();
    } else if (cmd == "PAUSE") {
        streamState = MediaStreamState::eMediaStream_Pause;
    } else if (cmd == "TEARDOWN") {
        streamState = MediaStreamState::eMediaStream_Teardown;
    }
}