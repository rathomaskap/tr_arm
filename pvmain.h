/**
 * @file pvmain.h
 * @author your name (you@domain.com)
 * @brief 
 * @version 0.1
 * @date 2024-06-21
 * 
 * @copyright Copyright (c) 2024
 * 
 */
#ifndef __PVMAIN_H
#define __PVMAIN_H


#include <string>
#include <pjmedia/sdp.h>

using namespace std;

enum call_state_t
{
    CS_IDLE = 1,
    CS_INVITE,
    CS_TRYING,
    CS_OK
}; // Zustände der State Machine

struct ed137_call_t
{
    unsigned int id;
    string call_id;
    unsigned short src_port;
    unsigned short des_port;

    pj_in_addr src_ip;
    pj_in_addr des_ip;

    // unsigned int src_ip;
    // unsigned int des_ip;


    enum call_state_t state; // invite,

    string dstUserPart;
    string srcUserPart;


    string dstUri;
    string srcUri;
    bool delayLineFound;    // true, wenn es zur Session einen passenden delay Line Eintrag gibt
};

#endif