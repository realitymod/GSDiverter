#include <stdio.h>
#include <stdlib.h>
#include "windivert.h"

#define MAXBUF  0xFFFF
#define MAGIC_BYTE_0 0xFE
#define MAGIC_BYTE_1 0xFD

#ifndef DEBUG
#define DEBUG false
#endif

#define DEBUG_MSG(pattern, ...) do{  if(DEBUG) { fprintf(stdout, pattern, __VA_ARGS__ );} }while(false)

// Declare worker function
static DWORD worker(LPVOID arg);

// target port; to Where we'll redirect requests
static UINT16 Target_Port; 
static UINT16 Listening_Port;

/*
 * Entry.
 */
int __cdecl main(int argc, char **argv)
{
    if (argc != 4)
    {
        fprintf(stderr, "usage: %s <num-threads> <listening port> <target port>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    int nThreads = 3; //atoi(argv[1]);
    if (nThreads < 1 || nThreads > 64)
    {
        fprintf(stderr, "error: invalid number of threads\n");
       exit(EXIT_FAILURE);
    }
    
	// Get the listening and targeting ports 
	Listening_Port = atoi(argv[2]);
    Target_Port = atoi(argv[3]);

    // Create the filter
    char filter[200];
    snprintf(filter, sizeof(filter), "(inbound == 1 and udp == 1 and udp.DstPort == %d and udp.PayloadLength >= %d) or (outbound == 1 and udp.SrcPort == %d)", Listening_Port, 11, Target_Port);

	DEBUG_MSG("filter: %s\n", filter);
    // Divert traffic matching the filter:
    HANDLE handle = WinDivertOpen(filter, WINDIVERT_LAYER_NETWORK, 0, 0);
    if (handle == INVALID_HANDLE_VALUE)
    {
        if (GetLastError() == ERROR_INVALID_PARAMETER)
        {
            fprintf(stderr, "error: filter syntax error\n");
            exit(EXIT_FAILURE);
        }
        fprintf(stderr, "error: failed to open the WinDivert device (%d)\n", GetLastError());
        exit(EXIT_FAILURE);
    }

    // Start the threads
    for (int i = 1; i < nThreads; i++)
    {
        HANDLE thread = CreateThread(nullptr, 1, (LPTHREAD_START_ROUTINE)worker, (LPVOID)handle, 0, nullptr);
        if (thread == nullptr)
        {
            fprintf(stderr, "error: failed to start passthru thread (%u)\n", GetLastError());
            exit(EXIT_FAILURE);
        }
    }

    // No reasons for the main thread to not work
    worker((LPVOID)handle);

    return 0;
}

/*
 * This is the function that will do the actuall job
 */
static DWORD worker(LPVOID arg)
{
	DEBUG_MSG("Starting a worker...\n");
    unsigned char packet[MAXBUF];			// buffer for the created outbound package
    unsigned int packet_length;				// total number of bytes written to the inboud buffer.
    WINDIVERT_ADDRESS addr;					// "address" of a captured or injected packet
    HANDLE handle = (HANDLE)arg;			// Our WinDivert handle 

    // Main loop:
    while (TRUE)
    {
        // Get a packet.
        if (!WinDivertRecv(handle, packet, sizeof(packet), &addr, &packet_length))
        {
            fprintf(stderr, "warning: failed to read packet (%d)\n", GetLastError());
            continue;
        }
		DEBUG_MSG("Obtain a package\n");

        
        // Parse a packet
        // - We only care about the UDP header and payload
        PWINDIVERT_UDPHDR pUDPHdr;
        PVOID payload;
        unsigned int payload_len;
        if (!WinDivertHelperParsePacket(packet, packet_length, nullptr, nullptr, nullptr, nullptr, nullptr, &pUDPHdr, &payload, &payload_len)) {
            fprintf(stderr, "warning; failed to parse packet\n");
            // Reinject
            WinDivertSend(handle, packet, packet_length, &addr, nullptr);
            continue;
        }

		if (addr.Direction == WINDIVERT_DIRECTION_OUTBOUND) {
			// Outbound! 
			pUDPHdr->SrcPort = htons(Listening_Port);			// We'll just fix the target port to the original(= listening) one	

		} else {
			// Inbound!
			UINT8* data = (UINT8*)payload;

			// do we care about this message?
			// - needs to start with 0xFE 0xFD
			// - 11th byte needs to have least significate byte to 1
			// - It has 11 bytes; no more no less
			if (data[0] == MAGIC_BYTE_0 && data[1] == MAGIC_BYTE_1 && (data[10] & 1) == 1 && payload_len == 11)  {
				pUDPHdr->DstPort = htons(Target_Port);			// Converting to network byte order (big-endian)
			}
		}

        // and... Re-inject it!
		DEBUG_MSG("Re-inject it...\n");
		WinDivertHelperCalcChecksums(packet, packet_length, 0);				// Updating the checksum field
        if (!WinDivertSend(handle, packet, packet_length, &addr, nullptr)) {
            fprintf(stderr, "warning; failed to re-inject packet: %d\n", GetLastError());
        }
    }
}

