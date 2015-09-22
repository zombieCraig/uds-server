/*
 * Instrument cluster simulator
 *
 * (c) 2014 Open Garages - Craig Smith <craig@theialabs.com>
 */

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <getopt.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <net/if.h>
#include <linux/can.h>
#include <linux/can/raw.h>

#include "uds-server.h"

#define DEBUG 0
//#define VIN "1G1ZT53826F109149"
//#define VIN "5YJSA1S2FEFA00001"
#define VIN "WAUZZZ8V9FA149850"
//#define VIN "2B3KA43R86H389824"
#define DATA_ALPHA     0
#define DATA_ALPHANUM  1
#define DATA_BINARY    2

/* Globals */
int running = 0;
int verbose = 0;
int no_flow_control = 0;
int fuzz_level = 0;
int keep_spec = 0;
FILE *plogfp = NULL;
char *vin = VIN;

/* This is for flow control packets */
char gBuffer[255];
int gBufSize;
int gBufLengthRemaining;
int gBufCounter;

/* Prototypes */
void print_pkt(struct canfd_frame);
void print_bin(unsigned char *, int);


void usage(char *app, char *msg) {
  printf("Simulates UDS responses\n");
  if (msg) printf("%s\n", msg);
  printf("Usage: %s [options] <can_interface>\n", app);
  printf("\t-z\t\tIncrease fuzz level\n");
  printf("\t-v\t\tVerbose\n");
  printf("\t-l <logfile>\tLog output to file instead of STDOUT\n");
  printf("\t-c\t\tDon't fuzz ISOTP Spec, just data\n");
  printf("\t-F\t\tDisable flow control (Functional Addressing)\n");
  printf("\t-V <vin>\tSpecify VIN (Default: %s)\n", VIN);
  printf("\n");
  exit(1);
}

// Simple function to print logging info to screen or to a file
void plog(char *fmt, ...) {
  va_list args;
  char buf[2046];
  int len;

  va_start(args, fmt);
  len = vsnprintf(buf, 2045, fmt, args);
  va_end(args);

  if(plogfp) {
    len = fwrite(buf, 1, len, plogfp);
  } else {
    printf("%s", buf);
  }
}

void intHandler(int sig) {
    running = 0;
}

// Generates data into a buff and returns it.
char *gen_data(int scope, int size) {
  char *charset, *buf;
  unsigned char byte;
  int num;
  int i;
  buf = malloc(size);
  memset(buf,0,size);
  switch(scope) {
    case DATA_ALPHA:
       charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
       for(i = 0; i < size; i++) {
         buf[i] = charset[rand() % strlen(charset)];
       } 
       break;
    case DATA_ALPHANUM:
       charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
       for(i = 0; i < size; i++) {
         num = rand() % strlen(charset);
         byte = charset[num];
if (DEBUG) printf("DEBUG: random byte[%d] = %d %02X\n", i, num, byte);
         buf[i] = byte;
       } 
       break;
    case DATA_BINARY:
       for(i = 0; i < size; i++) {
         buf[i] = rand() % 256;
       }
    default:
      break;
  }
  return buf;
}

// If a flow control packet comes in, push out more data
// This isn't fully supported, just a hack at the moment
void flow_control_push_to(int can, int id) {
  struct canfd_frame frame;
  int nbytes;
  if(no_flow_control) return;
  if(verbose) plog("FC: Flushing ISOTP buffers\n");
  frame.can_id = id;
  while(gBufLengthRemaining > 0) {
    if(gBufLengthRemaining > 7) {
      frame.len = 8;
      frame.data[0] = gBufCounter;
      memcpy(&frame.data[1], gBuffer+(gBufSize-gBufLengthRemaining), 7);
      nbytes = write(can, &frame, CAN_MTU);
      if(nbytes < 0) perror("Write packet (FC)");
      gBufCounter++;
      gBufLengthRemaining -= 7;
    } else {
      frame.len = gBufLengthRemaining + 1;
      frame.data[0] = gBufCounter;
      memcpy(&frame.data[1], gBuffer+(gBufSize-gBufLengthRemaining), CAN_MTU);
      nbytes = write(can, &frame, CAN_MTU);
      if(nbytes < 0) perror("Write packet (FC Final)");
      gBufLengthRemaining = 0;
    }
  }
}

void flow_control_push(int can) {
  flow_control_push_to(can, 0x7e8);
}

void isotp_send_to(int can, char *data, int size, int dest) {
  struct canfd_frame frame;
  int left = size;
  int counter;
  int nbytes;
  if(size > 256) return;
  frame.can_id = dest;
  if(size < 7) {
    frame.len = size + 1;
    frame.data[0] = size;
    memcpy(&frame.data[1], data, size);
    nbytes = write(can, &frame, CAN_MTU);
    if(nbytes < 0) perror("Write packet");
  } else {
    frame.len = 8;
    frame.data[0] = 0x10;
    if(fuzz_level > 2 && keep_spec == 0) {
      frame.data[1] = rand() % 256;
      printf("Breaking ISOTP specs real size = %d reported size = %d\n", size, frame.data[1]);
    } else {
      frame.data[1] = (char)size-1;
    }
    memcpy(&frame.data[2], data, 6);
    nbytes = write(can, &frame, CAN_MTU);
    if(nbytes < 0) perror("Write packet");
    left -= 6;
    counter = 0x21;
    if(no_flow_control) {
      while(left > 0) {
        if(left > 7) {
          frame.len = 8;
          frame.data[0] = counter;
          memcpy(&frame.data[1], data+(size-left), 7);
          write(can, &frame, CAN_MTU);
          counter++;
          left -= 7;
        } else {
          frame.len = left + 1;
          frame.data[0] = counter;
          memcpy(&frame.data[1], data+(size-left), CAN_MTU);
          write(can, &frame, frame.len);
          left = 0;
        }
      }
    } else { // FC
      memcpy(gBuffer, data, size); // Size is restricted to <256
      gBufSize = size;
      gBufLengthRemaining = left;
      gBufCounter = counter;
    }
  }
}

void isotp_send(int can, char *data, int size) {
  isotp_send_to(can, data, size, 0x7e8);
}

void send_dtcs(int can, char total, struct canfd_frame frame) {
  char resp[1024];
  char i;
  memset(resp, 0, 1024);
  switch(fuzz_level) {
    case 0:  // Default is to make P01XX where XX = total number of DTCs
      resp[0] = frame.data[1] + 0x40;
      resp[1] = total; // Total DTCs
      for(i = 0; i <= total*2; i+=2) {
        resp[2+i] = 1;
        resp[2+i+1] = i;
      }
      if(total == 0) {
        isotp_send(can, resp, 2);
      } else if (total < 3) {
        isotp_send(can, resp, 2+(total*2));
      } else {
        isotp_send(can, resp, total*2);
      }
      break;
    case 1:
      resp[0] = frame.data[1] + 0x40;
      resp[1] = rand() % 256;
      if (verbose) plog("Randomized total DTCs to %d real DTCs %d\n", resp[1], total);
      for(i = 0; i <= total*2; i+=2) {
        resp[2+i] = 1;
        resp[2+i+1] = i;
      }
      if(total == 0) {
        isotp_send(can, resp, 2);
      } else if (total < 3) {
        isotp_send(can, resp, 2+(total*2));
      } else {
        isotp_send(can, resp, total*2);
      }
      break;
    case 2:
    default:
      resp[0] = frame.data[1] + 0x40;
      total = rand() % 128;
      resp[1] = total;
      if (verbose) plog("Randomized total DTCs to %d\n", resp[1]);
      for(i = 0; i <= total*2; i+=2) {
        resp[2+i] = rand() % 256;
        resp[2+i+1] = rand() % 256;
      }
      if (verbose) {
        plog("DTC random data is:\n");
        print_bin(&resp[2], total*2);
      }
      if(total == 0) {
        isotp_send(can, resp, 2);
      } else if (total < 3) {
        isotp_send(can, resp, 2+(total*2));
      } else {
        isotp_send(can, resp, total*2);
      }
      break;
  }
}

unsigned char calc_vin_checksum(char *vin, int size) {
  char w[17] = { 8, 7, 6, 5, 4, 3, 2, 10, 0, 9, 8, 7, 6, 5, 4, 3, 2 };
  int i;
  int checksum = 0;
  int num;
  for(i=0; i < size; i++) {
    if(vin[i] == 'I' || vin[i] == 'O' || vin[i] == 'Q') {
      num = 0;
    } else {
      if(vin[i] >= '0' && vin[i] <='9') num = vin[i] - '0';
      if(vin[i] >= 'A' && vin[i] <='I') num = (vin[i] - 'A') + 1;
      if(vin[i] >= 'J' && vin[i] <='R') num = (vin[i] - 'J') + 1;
      if(vin[i] >= 'S' && vin[i] <='Z') num = (vin[i] - 'S') + 2;
    }
    checksum += num * w[i];
  }
  checksum = checksum % 11;
  if (checksum == 10) return 'X';
  return ('0' + checksum);
}

void send_error_snfs(int can, struct canfd_frame frame) {
  char resp[4];
  if(verbose) plog("Responded with Sub Function Not Supported\n");
  resp[0] = 0x7f;
  resp[1] = frame.data[1];
  resp[2] = 12; // SubFunctionNotSupported
  isotp_send(can, resp, 3);
}

void send_error_roor(int can, struct canfd_frame frame, int id) {
  char resp[4];
  if(verbose) plog("Responded with Sub Function Not Supported\n");
  resp[0] = 0x7f;
  resp[1] = frame.data[1];
  resp[2] = 31; // RequestOutOfRange
  isotp_send_to(can, resp, 3, id);
}

void generic_OK_resp(int can, struct canfd_frame frame) {
  char resp[4];
  if(verbose) plog("Responding with a generic OK message\n");
  resp[0] = frame.data[1] + 0x40;
  resp[1] = frame.data[2];
  resp[2] = 0;
  isotp_send(can, resp, 3);
}

void generic_OK_resp_to(int can, struct canfd_frame frame, int id) {
  char resp[4];
  if(verbose) plog("Responding with a generic OK message\n");
  resp[0] = frame.data[1] + 0x40;
  resp[1] = frame.data[2];
  resp[2] = 0;
  isotp_send_to(can, resp, 3, id);
}

void handle_current_data(int can, struct canfd_frame frame) {
  if(verbose) plog("Received Current info request\n");
  char resp[8];
  switch(frame.data[2]) {
    case 0x00: // Supported PIDs
      if(verbose) plog("Responding with a generic set of PIDs (1-20)\n");
      resp[0] = frame.data[1] + 0x40;
      resp[1] = frame.data[2];
      resp[2] = 0xBF;
      resp[3] = 0xBF;
      resp[4] = 0xB9;
      resp[5] = 0x93;
      isotp_send(can, resp, 6);
      break;
    case 0x01: // MIL & DTC Status
      if(verbose) plog("Responding to MIL and DTC Status request\n");
      resp[0] = frame.data[1] + 0x40;
      resp[1] = frame.data[2];
      resp[2] = 0x00;
      resp[3] = 0x07;
      resp[4] = 0xE5;
      resp[5] = 0xE5;
      isotp_send(can, resp, 6);
      break;
    case 0x20: // More supported PIDs (21-40)
      if(verbose) plog("Responding with PIDs supported (21-40)\n");
      resp[0] = frame.data[1] + 0x40;
      resp[1] = frame.data[2];
      resp[2] = 0xBF;
      resp[3] = 0xBF;
      resp[4] = 0xB9;
      resp[5] = 0x93;
      isotp_send(can, resp, 6);
      break;
    case 0x40: // More supported PIDs (41-60)
      if(verbose) plog("Responding with PIDs supported (41-60)\n");
      resp[0] = frame.data[1] + 0x40;
      resp[1] = frame.data[2];
      resp[2] = 0xBF;
      resp[3] = 0xBF;
      resp[4] = 0xB9;
      resp[5] = 0x93;
      isotp_send(can, resp, 6);
      break;
    case 0x41: // Monitor status this drive cycle
      resp[0] = frame.data[1] + 0x40;
      resp[1] = frame.data[2];
      resp[2] = 0;
      resp[3] = 0x0F;
      resp[4] = 0xFF;
      resp[5] = 0x00;
      isotp_send(can, resp, 6);
      break;
    case 0x60: // More supported PIDs (61-80)
      if(verbose) plog("Responding with PIDs supported (61-80)\n");
      resp[0] = frame.data[1] + 0x40;
      resp[1] = frame.data[2];
      resp[2] = 0xBF;
      resp[3] = 0xBF;
      resp[4] = 0xB9;
      resp[5] = 0x93;
      isotp_send(can, resp, 6);
      break;
    case 0x80: // More supported PIDs (81-100)
      if(verbose) plog("Responding with PIDs supported (81-100)\n");
      resp[0] = frame.data[1] + 0x40;
      resp[1] = frame.data[2];
      resp[2] = 0xBF;
      resp[3] = 0xBF;
      resp[4] = 0xB9;
      resp[5] = 0x93;
      isotp_send(can, resp, 6);
      break;
    case 0xA0:  // More Supported PIDs (101-120)
      if(verbose) plog("Responding with PIDs supported (101-120)\n");
      resp[0] = frame.data[1] + 0x40;
      resp[1] = frame.data[2];
      resp[2] = 0xBF;
      resp[3] = 0xBF;
      resp[4] = 0xB9;
      resp[5] = 0x93;
      isotp_send(can, resp, 6);
      break;
    case 0xC0: // More supported PIDs (121-140)
      if(verbose) plog("Responding with PIDs supported (121-140)\n");
      resp[0] = frame.data[1] + 0x40;
      resp[1] = frame.data[2];
      resp[2] = 0xBF;
      resp[3] = 0xBF;
      resp[4] = 0xB9;
      resp[5] = 0x93;
      isotp_send(can, resp, 6);
      break;
    default:
      if(verbose) plog("Note: Requested unsupported service %02X\n", frame.data[2]);
      break;
  }
}

void handle_vehicle_info(int can, struct canfd_frame frame) {
  char *buf;
  int pktsize = 0;
  unsigned char chksum;
  if(verbose) plog("Received Vehicle info request\n");
  char resp[300];
  switch(frame.data[2]) {
    case 0x00: // Supported PIDs
      if(verbose) plog("Replying with ALL Pids supported\n");
      resp[0] = frame.data[1] + 0x40;
      resp[1] = frame.data[2];
      resp[2] = 0x55;
      resp[3] = 0;
      resp[4] = 0;
      resp[5] = 0;
      isotp_send(can, resp, 6);
      break;
    case 0x02: // Get VIN
      switch(fuzz_level) {
        case 0:
          if(verbose) plog("Sending VIN %s\n", vin);
          resp[0] = frame.data[1] + 0x40;
          resp[1] = frame.data[2];
          resp[2] = 1;
          memcpy(&resp[3], vin, strlen(vin));
          isotp_send(can, resp, 4 + strlen(vin));
          break;
        case 1:
          if(verbose) plog("Fuzzing VIN with printable chars\n");
          resp[0] = frame.data[1] + 0x40;
          resp[1] = frame.data[2];
          resp[2] = 1;
          buf = gen_data(DATA_ALPHANUM, 17);
          chksum = calc_vin_checksum(buf, 17);
          buf[8] = chksum;
          if(verbose) plog("Using VIN: %s\n", buf);
          memcpy(&resp[3], buf, 17);
          free(buf);
          isotp_send(can, resp, 4 + 17);
          break;
        case 2:
        case 3:  // At 3 the ISOTP spec gets flaky
          pktsize = rand() % 252;
          if(verbose) plog("Fuzzing big VIN with printable chars\n");
          resp[0] = frame.data[1] + 0x40;
          resp[1] = frame.data[2];
          resp[2] = 1;
          buf = gen_data(DATA_ALPHANUM, pktsize);
          chksum = calc_vin_checksum(buf, pktsize);
          buf[8] = chksum;
          if(verbose) plog("Using big VIN (%d chars): %s\n",pktsize, buf);
          memcpy(&resp[3], buf, pktsize);
          free(buf);
          isotp_send(can, resp, 4 + pktsize);
          break;
        case 4:
          if(verbose) plog("Fuzzing VIN with binary data\n");
          resp[0] = frame.data[1] + 0x40;
          resp[1] = frame.data[2];
          resp[2] = 1;
          buf = gen_data(DATA_BINARY, 17);
          chksum = calc_vin_checksum(buf, 17);
          buf[8] = chksum;
          if(verbose) print_bin(buf, 17);
          memcpy(&resp[3], buf, 17);
          free(buf);
          isotp_send(can, resp, 4 + 17);
          break;
        case 5:
        default:
          pktsize = rand() % 252;
          if(verbose) plog("Fuzzing VIN with binary data with size %d\n", pktsize);
          resp[0] = frame.data[1] + 0x40;
          resp[1] = frame.data[2];
          resp[2] = 1;
          buf = gen_data(DATA_BINARY, pktsize);
          if(verbose) print_bin(buf, pktsize);
          memcpy(&resp[3], buf, pktsize);
          free(buf);
          isotp_send(can, resp, 4 + pktsize);
          break;
      }
      break;
    default:
      break;
  }
}

void handle_pending_codes(int can, struct canfd_frame frame) {
  if(verbose) plog("Received request for pending trouble codes\n");
  send_dtcs(can, 20, frame);
}

void handle_stored_codes(int can, struct canfd_frame frame) {
  if(verbose) plog("Received request for stored trouble codes\n");
  send_dtcs(can, 2, frame);
}

// TODO: This is wrong.  Record a real transaction to see the format
void handle_freeze_frame(int can, struct canfd_frame frame) {
  if(verbose) plog("Received request for freeze frame code\n");
  //send_dtcs(can, 1, frame);
  char resp[4];
  resp[0] = frame.data[1] + 0x40;
  resp[1] = 0x01;
  resp[2] = 0x01;
  isotp_send(can, resp, 3);
}

void handle_perm_codes(int can, struct canfd_frame frame) {
  if(verbose) plog("Received request for permanent trouble codes\n");
  send_dtcs(can, 0, frame);
}

void handle_dsc(int can, struct canfd_frame frame) {
  //if(verbose) plog("Received DSC Request\n");
  //send_error_snfs(can, frame);
  if(verbose) plog("Received DSC Request giving VCDS respose\n");
      frame.can_id = 0x77A;
      frame.len = 8;
      frame.data[0] = 0x06;
      frame.data[1] = 0x50;
      frame.data[2] = 0x03;
      frame.data[3] = 0x00;
      frame.data[4] = 0x32;
      frame.data[5] = 0x01;
      frame.data[6] = 0xF4;
      frame.data[7] = 0xAA;
      write(can, &frame, CAN_MTU);
}

/*
  ECU Memory, based on VCDS response for now
*/
void handle_read_data_by_id(int can, struct canfd_frame frame) {
  if(verbose) plog("Recieved Read Data by ID %02X %02X\n", frame.data[2], frame.data[3]);
  char resp[120];
  if(frame.data[2] = 0xF1) {
    switch(frame.data[3]) {
     case 0x87:
       if(verbose) plog("Read data by ID 0x87\n");
       resp[0] = frame.data[1] + 0x40;
       resp[1] = frame.data[2];
       resp[2] = 0x87;
       resp[3] = 0x30;
       resp[4] = 0x34;
       resp[5] = 0x45;
       resp[6] = 0x39;
       resp[7] = 0x30;
       resp[8] = 0x36;
       resp[9] = 0x33;
       resp[10] = 0x32;
       resp[11] = 0x33;
       resp[12] = 0x46;
       resp[13] = 0x20; // Note VCDS pads with 55's
       isotp_send_to(can, resp, 14, 0x77A);
       break;
      case 0x89:
          if(verbose) plog("Read data by ID 0x89\n");
          frame.can_id = 0x7E8;
          frame.len = 8;
          frame.data[0] = 0x07;
          frame.data[1] = 0x62;
          frame.data[2] = 0xF1;
          frame.data[3] = 0x89;
          frame.data[4] = 0x38; //8
          frame.data[5] = 0x34; //4
          frame.data[6] = 0x31; //1
          frame.data[7] = 0x30; //0
          write(can, &frame, CAN_MTU);
        break;
      case 0x9E:
        if(verbose) plog("Read data by ID 0x9E\n");
        resp[0] = frame.data[1] + 0x40;
        resp[1] = frame.data[2];
        resp[2] = 0x45; 
        resp[3] = 0x56;
        resp[4] = 0x5F;
        resp[5] = 0x47;
        resp[6] = 0x61;
        resp[7] = 0x74;
        resp[8] = 0x65;
        resp[9] = 0x77;
        resp[10] = 0x45;
        resp[11] = 0x56;
        resp[12] = 0x43;
        resp[13] = 0x6F;
        resp[14] = 0x6E;
        resp[15] = 0x74;
        resp[16] = 0x69;
        resp[17] = 0x00;
        isotp_send(can, resp, 0x13);
        break;
      case 0xA2: 
        if(verbose) plog("Read data by ID 0xA2\n");
        resp[0] = frame.data[1] + 0x40;
        resp[1] = frame.data[2];
        resp[2] = 0xA2;
        resp[3] = 0x30; // 004010
        resp[4] = 0x30;
        resp[5] = 0x34;
        resp[6] = 0x30;
        resp[7] = 0x31;
        resp[8] = 0x30;
        isotp_send(can, resp, 9);
        break;
     default:
        if(verbose) plog("Not responding to ID %02X\n", frame.data[3]);
        break;
     }
  } else if(frame.data[2] == 0x06) {
    switch(frame.data[3]) {
     case 0x00:
        if(verbose) plog("Read data by ID 0x9E\n");
        resp[0] = frame.data[1] + 0x40;
        resp[1] = frame.data[2];
        resp[2] = 0x02; 
        resp[3] = 0x01;
        resp[4] = 0x00;
        resp[5] = 0x17;
        resp[6] = 0x26;
        resp[7] = 0xF2;
        resp[8] = 0x00;
        resp[9] = 0x00;
        resp[10] = 0x5B;
        resp[11] = 0x00;
        resp[12] = 0x12;
        resp[13] = 0x08;
        resp[14] = 0x58;
        resp[15] = 0x00;
        resp[16] = 0x00;
        resp[17] = 0x00;
        resp[18] = 0x00;
        resp[19] = 0x01;
        resp[20] = 0x01;
        resp[21] = 0x01;
        resp[22] = 0x00;
        resp[23] = 0x01;
        resp[24] = 0x00;
        resp[25] = 0x00;
        resp[26] = 0x00;
        resp[27] = 0x00;
        resp[28] = 0x00;
        resp[29] = 0x00;
        resp[30] = 0x00;
        resp[31] = 0x00;
        isotp_send(can, resp, 0x21);
       break;
     case 0x01:
          if(verbose) plog("Read data by ID 0x01\n");
          send_error_roor(can, frame, 0x7E8);
       break;
     default:
       if(verbose) plog("Not responding to ID %02X\n", frame.data[3]);
       break;
     }
  } else {
    if(verbose) plog("Unknown read data by ID %02X\n", frame.data[2]);
  }
}

/*
 GM
*/

// Read DID from ID (GM)
// For now we are only setting this up to work with the BCM
// 244   [3]  02 1A 90
void handle_gm_read_did_by_id(int can, struct canfd_frame frame) {
  if(verbose) plog("Received GM Read DID by ID Request\n");
  char resp[300];
  char *buf;
  char *tracenum = "874602RA51950204";
  unsigned char chksum;
  switch(frame.data[2]) {
    case 0x90:  // VIN
      if(verbose) plog(" + Requested VIN\n");
      switch(fuzz_level) {
        case 0:
          if(verbose) plog("Sending VIN %s\n", vin);
          resp[0] = frame.data[1] + 0x40;
          resp[1] = frame.data[2];
          memcpy(&resp[2], vin, strlen(vin));
          isotp_send_to(can, resp, 3 + strlen(vin), 0x644);
          break;
        case 1:
          if(verbose) plog("Fuzzing VIN with printable chars\n");
          resp[0] = frame.data[1] + 0x40;
          resp[1] = frame.data[2];
          buf = gen_data(DATA_ALPHANUM, 17);
          chksum = calc_vin_checksum(buf, 17);
          buf[8] = chksum;
          if(verbose) plog("Using VIN: %s\n", buf);
          memcpy(&resp[2], buf, 17);
          free(buf);
          isotp_send_to(can, resp, 3 + 17, 0x644);
          break;
       }
      break;
    case 0xA1:  // SDM Primary Key
      if(verbose) plog(" + Requested SDM Primary Key\n");
      switch(fuzz_level) {
        case 0:
          if(verbose) plog("Sending SDM Key %04X\n", 0x6966);
          resp[0] = frame.data[1] + 0x40;
          resp[1] = frame.data[2];
          resp[2] = 0x69;
          resp[3] = 0x66;
          isotp_send_to(can, resp, 5, 0x644);
          break;
      }
      break;
    case 0xB4:  // Traceability Number
      if(verbose) plog(" + Requested Traceability Number\n");
      switch(fuzz_level) {
        case 0:
          if(verbose) plog("Sending Traceabiliity number %s\n", tracenum);
          resp[0] = frame.data[1] + 0x40;
          resp[1] = frame.data[2];
          memcpy(&resp[2], tracenum, strlen(tracenum));
          isotp_send_to(can, resp, 3 + strlen(tracenum), 0x644);
          break;
      }
      break;
    case 0xB7:  // Software Number
      if(verbose) plog(" + Requested Software Number\n");
      switch(fuzz_level) {
        case 0:
          if(verbose) plog("Sending SW # %d\n", 600);
          resp[0] = frame.data[1] + 0x40;
          resp[1] = frame.data[2];
          resp[2] = 0x42;
          resp[3] = 0xAA;
          resp[4] = 6;
          resp[5] = 2; // 600
          resp[6] = 0x58;
          isotp_send_to(can, resp, 6, 0x644);
          break;
      }
      break;
    case 0xCB:  // End Model Part #
      if(verbose) plog(" + Requested End Model Part Number\n");
      switch(fuzz_level) {
        case 0:
          if(verbose) plog("Sending End Model Part Number %d\n", 15804602);
          resp[0] = frame.data[1] + 0x40;
          resp[1] = frame.data[2];
          resp[2] = 0x00;
          resp[3] = 0xF1;
          resp[4] = 0x28;
          resp[5] = 0xBA;
          isotp_send_to(can, resp, 6, 0x644);
          break;
      }
      break;
    default:
      break;
  }
}

/* GM Read Data via PID */
/* 244   [5]  04 AA 03 02 07 */
/* 544#0738408D8B000200 */
/* 544#02508D8D00000000 */
/* TODO: Once a real queue is built add these request to those timers */
void handle_gm_read_data_by_id(int can, struct canfd_frame frame) {
  if(verbose) plog("Received GM Read Data by ID Request\n");
  int offset = 0;
  int i;
  int datacnt;
  char datacpy[8];
  if (frame.data[0] == 0xFE) offset = 1;
  memcpy(&datacpy, &frame.data, 8);
  if(frame.can_id == 0x7e0) {
    frame.can_id = 0x5e8;
  } else {
    frame.can_id = 0x500 + (frame.can_id & 0xFF);
  }
  frame.len = 8;
  switch(frame.data[2 + offset]) { // Subfunctions
    case 0x00:  // Stop
      if(verbose) plog(" + Stop Data Request\n");
      memset(frame.data, 0, 8);
      write(can, &frame, CAN_MTU);
      break;
    case 0x01:  // One Response
      if(verbose) plog(" + One Response\n");
      for(i=3; i < datacpy[0]+1; i++) {
        frame.data[0] = datacpy[i];
        for(datacnt=1; datacnt < 8; datacnt++) {
          frame.data[datacnt] = rand() % 256;
        }
        write(can, &frame, CAN_MTU);
        sleep(0.5);
      }
      break;
    case 0x02:  // Slow Rate
      if(verbose) plog(" + Slow Rate\n");
      if(verbose) plog(" + Medium Rate\n");
      for(i=3; i < datacpy[0]+1; i++) {
        frame.data[0] = datacpy[i];
        for(datacnt=1; datacnt < 8; datacnt++) {
          frame.data[datacnt] = rand() % 255;
        }
        write(can, &frame, CAN_MTU);
        sleep(1);
      }
      break;
    case 0x03:  // Medium Rate
      if(verbose) plog(" + Medium Rate\n");
      for(i=3; i < datacpy[0]+1; i++) {
        frame.data[0] = datacpy[i];
        for(datacnt=1; datacnt < 8; datacnt++) {
          frame.data[datacnt] = rand() % 255;
        }
        write(can, &frame, CAN_MTU);
        sleep(0.7);
      }
      break;
    case 0x04:  // Fast Rate
      if(verbose) plog(" + Fast Rate\n");
      for(i=3; i < datacpy[0]+1; i++) {
        frame.data[0] = datacpy[i];
        for(datacnt=1; datacnt < 8; datacnt++) {
          frame.data[datacnt] = rand() % 255;
        }
        sleep(0.3);
      }
      break;
    default:
      plog("Unknown subfunction timer\n");
      break;
  }
}

/* GM Diag format is either
     101#FE 03 A9 81 52  (Functional addressing: Where FE is the extended address)
     7E0#03 A9 81 52 (no extended addressing)
*/
void handle_gm_read_diag(int can, struct canfd_frame frame) {
  if(verbose) plog("Received GM Read Diagnostic Request\n");
  int offset = 0;
  int i, total;
  char resp[150];
  if(frame.data[0] == 0xFE) offset = 1;
  switch(frame.data[2 + offset]) { // Subfunctions
    case UDS_READ_STATUS_BY_MASK:  // Read DTCs by mask
      if(verbose) {
        plog(" + Read DTCs by mask\n");
        if(frame.data[3 + offset] & DTC_SUPPORTED_BY_CALIBRATION) plog("   - Supported By Calibration\n");
        if(frame.data[3 + offset] & DTC_CURRENT_DTC) plog("   - Current DTC\n");
        if(frame.data[3 + offset] & DTC_TEST_NOT_PASSED_SINCE_CLEARED) plog("   - Tests not passed since DTC cleared\n");
        if(frame.data[3 + offset] & DTC_TEST_FAILED_SINCE_CLEARED) plog("   - Tests failed since DTC cleared\n");
        if(frame.data[3 + offset] & DTC_HISTORY) plog("   - DTC History\n");
        if(frame.data[3 + offset] & DTC_TEST_NOT_PASSED_SINCE_POWER) plog("   - Tests not passed since power up\n");
        if(frame.data[3 + offset] & DTC_CURRENT_DTC_SINCE_POWER) plog("   - Tests failed since power up\n");
        if(frame.data[3 + offset] & DTC_WARNING_INDICATOR_STATE) plog("   - Warning Indicator State\n");
      }
      if(frame.can_id == 0x7e0) {
        frame.can_id = 0x5e8;
      } else {
        frame.can_id = 0x500 + (frame.can_id & 0xFF);
      }
      frame.len = 8;
      frame.data[0] = frame.data[2 + offset];
      frame.data[1] = 0;    // DTC 1st byte
      frame.data[2] = 0x30; // DTC 2nd byte
      frame.data[3] = 0;
      frame.data[4] = 0x6F; // Last Test/ This Ignition/ Last Clear bitflag
      frame.data[5] = 0;
      frame.data[6] = 0;
      frame.data[7] = 0;
      write(can, &frame, CAN_MTU);
      sleep(0.2); // Instead of actually processing the FC
      if(fuzz_level == 1) {
        total = rand() % 1024;
        if(verbose) plog("Sending %d DTCs\n", total);
        for(i = 0; i < total; i++) {
          frame.data[1] = rand() % 256;
          frame.data[2] = (rand() % 255) + 1;
          frame.data[3] = 0;
          frame.data[4] = 0x6F; // Last DTC
          write(can, &frame, CAN_MTU);
          sleep(1);
        }
      }
      frame.data[1] = 0; // Last frame must be a 0 DTC
      frame.data[2] = 0;
      frame.data[3] = 0;
      frame.data[4] = 0xFF; // Last DTC
      write(can, &frame, CAN_MTU);
      break;
    default:
      if(verbose) plog(" + Unknown subfunction request %02X\n", frame.data[2 + offset]);
      break;
  }
}

/*
  Gateway
*/
void handle_vcds_710(int can, struct canfd_frame frame) {
  if(verbose) plog("Received VCDS 0x710 gateway request\n");
  char resp[150];
  if(frame.data[0] == 0x30) { // Flow control
    flow_control_push(can);
    return;
  }
  switch(frame.data[1]) {
    //Pkt: 710#02 10 03 55 55 55 55 55 
    case 0x10: // Diagnostic Session Control
      frame.can_id = 0x77A;
      frame.len = 8;
      frame.data[0] = 0x06;
      frame.data[1] = 0x50;
      frame.data[2] = 0x03;
      frame.data[3] = 0x00;
      frame.data[4] = 0x32;
      frame.data[5] = 0x01;
      frame.data[6] = 0xF4;
      frame.data[7] = 0xAA;
      write(can, &frame, CAN_MTU);
      break;
    case 0x22: // Read Data By Identifier
      if(frame.data[2] = 0xF1) {
        switch(frame.data[3]) {
        case 0x87: // VAG Number
          if(verbose) plog("Read data by ID 0x87\n");
          resp[0] = frame.data[1] + 0x40;
          resp[1] = frame.data[2];
          resp[2] = 0x87;
          resp[3] = 0x35;
          resp[4] = 0x51;
          resp[5] = 0x45;
          resp[6] = 0x39;
          resp[7] = 0x30;
          resp[8] = 0x37;
          resp[9] = 0x35;
          resp[10] = 0x33;
          resp[11] = 0x30;
          resp[12] = 0x43;
          resp[13] = 0x20; // Note normally this would pad with AA's
          isotp_send_to(can, resp, 14, 0x77A);
        break;
        case 0x89: // VAG Number
          if(verbose) plog("Read data by ID 0x89\n");
          frame.can_id = 0x77A;
          frame.len = 8;
          frame.data[0] = 0x07;
          frame.data[1] = 0x62;
          frame.data[2] = 0xF1;
          frame.data[3] = 0x89;
          frame.data[4] = 0x33; //3
          frame.data[5] = 0x32; //2
          frame.data[6] = 0x30; //0
          frame.data[7] = 0x33; //3
          write(can, &frame, CAN_MTU);
        break;
        case 0x91: // VAG Number
          if(verbose) plog("Read data by ID 0x91\n");
          resp[0] = frame.data[1] + 0x40;
          resp[1] = frame.data[2];
          resp[2] = 0x87;
          resp[3] = 0x35;
          resp[4] = 0x51;
          resp[5] = 0x45;
          resp[6] = 0x39;
          resp[7] = 0x30;
          resp[8] = 0x37;
          resp[9] = 0x35;
          resp[10] = 0x33;
          resp[11] = 0x30;
          resp[12] = 0x41;
          resp[13] = 0x20; // Note normally this would pad with AA's
          isotp_send_to(can, resp, 14, 0x77A);
        break;
        default:
          if(verbose) plog("NOTE: Read data by unknown ID %02X\n", frame.data[3]);
          resp[0] = frame.data[1] + 0x40;
          resp[1] = frame.data[2];
          resp[2] = 0x87;
          resp[3] = 0x35;
          resp[4] = 0x51;
          resp[5] = 0x45;
          resp[6] = 0x39;
          resp[7] = 0x30;
          resp[8] = 0x37;
          resp[9] = 0x35;
          resp[10] = 0x33;
          resp[11] = 0x30;
          resp[12] = 0x41;
          resp[13] = 0x20; // Note normally this would pad with AA's
          isotp_send_to(can, resp, 14, 0x77A);
        break;
       
      }
    } else {
      if (verbose) plog("Unknown read data by Identifier %02X\n", frame.data[2]);
    }
    break;
  }
}

// return Mode/SIDs in english
char *get_mode_str(struct canfd_frame frame) {
  switch(frame.data[1]) {
    case OBD_MODE_SHOW_CURRENT_DATA:
       return "Show current Data";
       break;
    case OBD_MODE_SHOW_FREEZE_FRAME:
       return "Show freeze frame";
       break;
    case OBD_MODE_READ_DTC:
       return "Read DTCs";
       break;
    case OBD_MODE_CLEAR_DTC:
       return "Clear DTCs";
       break;
    case OBD_MODE_TEST_RESULTS_NON_CAN:
       return "Mode Test Results (Non-CAN)";
       break;
    case OBD_MODE_TEST_RESULTS_CAN:
       return "Mode Test Results (CAN)";
       break;
    case OBD_MODE_READ_PENDING_DTC:
       return "Read Pending DTCs";
       break;
    case OBD_MODE_CONTROL_OPERATIONS:
       return "Control Operations";
       break;
    case OBD_MODE_VEHICLE_INFORMATION:
       return "Vehicle Information";
       break;
    case OBD_MODE_READ_PERM_DTC:
       return "Read Permanent DTCs";
       break;
    case UDS_SID_DIAGNOSTIC_CONTROL:
       return "Diagnostic Control";
       break;
    case UDS_SID_ECU_RESET:
       return "ECU Reset";
       break;
    case UDS_SID_CLEAR_DTC:
       return "UDS Clear DTCs";
       break;
    case UDS_SID_READ_DTC:
       return "UDS Read DTCs";
       break;
    case UDS_SID_GM_READ_DID_BY_ID:
       return "Read DID by ID (GM)";
       break;
    case UDS_SID_RESTART_COMMUNICATIONS:
       return "Restore Normal Commnications";
       break;
    case UDS_SID_READ_DATA_BY_ID:
       return "Read DATA By ID";
       break;
    case UDS_SID_READ_MEM_BY_ADDRESS:
       return "Read Memory By Address";
       break;
    case UDS_SID_READ_SCALING_BY_ID:
       return "Read Scalling Data by ID";
       break;
    case UDS_SID_SECURITY_ACCESS:
       return "Security Access";
       break;
    case UDS_SID_COMMUNICATION_CONTROL:
       return "Communication Control";
       break;
    case UDS_SID_READ_DATA_BY_ID_PERIODIC:
       return "Read DATA By ID Periodically";
       break;
    case UDS_SID_DEFINE_DATA_ID:
       return "Define DATA By ID";
       break;
    case UDS_SID_WRITE_DATA_BY_ID:
       return "Write DATA By ID";
       break;
    case UDS_SID_IO_CONTROL_BY_ID:
       return "Input/Output Control By ID";
       break;
    case UDS_SID_ROUTINE_CONTROL:
       return "Routine Control";
       break;
    case UDS_SID_REQUEST_DOWNLOAD:
       return "Request Download";
       break;
    case UDS_SID_REQUEST_UPLOAD:
       return "Request Upload";
       break;
    case UDS_SID_TRANSFER_DATA:
       return "Transfer DATA";
       break;
    case UDS_SID_REQUEST_XFER_EXIT:
       return "Request Transfer Exit";
       break;
    case UDS_SID_REQUEST_XFER_FILE:
       return "Request Transfer File";
       break;
    case UDS_SID_WRITE_MEM_BY_ADDRESS:
       return "Write Memory By Address";
       break;
    case UDS_SID_TESTER_PRESENT:
       return "Tester Present";
       break;
    case UDS_SID_ACCESS_TIMING:
       return "Access Timing";
       break;
    case UDS_SID_SECURED_DATA_TRANS:
       return "Secured DATA Transfer";
       break;
    case UDS_SID_CONTROL_DTC_SETTINGS:
       return "Control DTC Settings";
       break;
    case UDS_SID_RESPONSE_ON_EVENT:
       return "Response On Event";
       break;
    case UDS_SID_LINK_CONTROL:
       return "Link Control";
       break;
    case UDS_SID_GM_PROGRAMMED_STATE:
       return "Programmed State (GM)";
       break;
    case UDS_SID_GM_PROGRAMMING_MODE:
       return "Programming Mode (GM)";
       break;
    case UDS_SID_GM_READ_DIAG_INFO:
       return "Read Diagnostic Information (GM)";
       break;
    case UDS_SID_GM_READ_DATA_BY_ID:
       return "Read DATA By ID (GM)";
       break;
    case UDS_SID_GM_DEVICE_CONTROL:
       return "Device Control (GM)";
       break;
    default:
       printf("Unknown mode/sid (%02X)\n", frame.data[1]);
       return "";
  }
}

// Prints raw packet in ID#DATA format
void print_pkt(struct canfd_frame frame) {
  int i;
  plog("Pkt: %02X#", frame.can_id);
  for(i = 0; i < frame.len; i++) {
    plog("%02X ", frame.data[i]);
  }
  plog("\n");
}

// Prints binary data in hex format
void print_bin(unsigned char *bin, int size) {
  int i;
  for(i = 0; i < size; i++) {
    plog("%02X ", bin[i]);
  }
  plog("\n");
}

// Handles the incomming CAN Packets
// Each ID that deals with specific controllers a note is
// given where that info came from.  There could be a lot of overlap
// and exceptions here. -- Craig
void handle_pkt(int can, struct canfd_frame frame) {
  print_pkt(frame);
  switch(frame.can_id) {
    case 0x243: // EBCM / GM / Chevy Malibu 2006
      switch(frame.data[1]) {
        case UDS_SID_TESTER_PRESENT:
          generic_OK_resp_to(can, frame, 0x643);
          break;
        case UDS_SID_GM_READ_DIAG_INFO:
          handle_gm_read_diag(can, frame);
          break;
        
        default:
          //if(verbose) plog("Unhandled mode/sid: %02X\n", frame.data[1]);
          if(verbose) plog("Unhandled mode/sid: %s\n", get_mode_str(frame));
          break;
      }
      break;
    case 0x244: // Body Control Module / GM / Chevy Malibu 2006
      if(frame.data[0] == 0x30) { // Flow control
        flow_control_push_to(can, 0x644);
        return;
      }
      switch(frame.data[1]) {
        case UDS_SID_TESTER_PRESENT:
          generic_OK_resp_to(can, frame, 0x644);
          break;
        case UDS_SID_GM_READ_DIAG_INFO:
          handle_gm_read_diag(can, frame);
          break;
        case UDS_SID_GM_READ_DATA_BY_ID:
          handle_gm_read_data_by_id(can, frame);
          break;
        case UDS_SID_GM_READ_DID_BY_ID:
          handle_gm_read_did_by_id(can, frame);
          break;
        default:
          //if(verbose) plog("Unhandled mode/sid: %02X\n", frame.data[1]);
          if(verbose) plog("Unhandled mode/sid: %s\n", get_mode_str(frame));
          break;
      }
      break;
    case 0x24A: // Power Steering / GM / Chevy Malibu 2006
      switch(frame.data[1]) {
        default:
          //if(verbose) plog("Unhandled mode/sid: %02X\n", frame.data[1]);
          if(verbose) plog("Unhandled mode/sid: %s\n", get_mode_str(frame));
          break;
      }
      break;
    case 0x350: // Unsure.  Seen RTRs to this when requesting VIN
      if (frame.can_id & CAN_RTR_FLAG) {
        if (verbose) plog("Received a RTR at ID %02X\n", frame.can_id);
      }
      break;
    case 0x710: // VCDS
      handle_vcds_710(can, frame);
      break;
    case 0x7df:
    case 0x7e0:  // Sometimes flow control comes here
      if(frame.data[0] == 0x30 && gBufLengthRemaining > 0) flow_control_push(can);
      if(frame.data[0] == 0 || frame.len == 0) return;
      if(frame.data[0] > frame.len) return;
      switch (frame.data[1]) {
        case OBD_MODE_SHOW_CURRENT_DATA:
          handle_current_data(can, frame);
          break;
        case OBD_MODE_SHOW_FREEZE_FRAME: 
          handle_freeze_frame(can, frame);
          break;
        case OBD_MODE_READ_DTC:
          handle_stored_codes(can, frame);
          break;
        case OBD_MODE_READ_PENDING_DTC:
          handle_pending_codes(can, frame);
          break;
        case OBD_MODE_VEHICLE_INFORMATION:
          handle_vehicle_info(can, frame);
          break;
        case OBD_MODE_READ_PERM_DTC:
          handle_perm_codes(can, frame);
          break;
        case UDS_SID_DIAGNOSTIC_CONTROL: // DSC
          handle_dsc(can, frame);
          break;
        case UDS_SID_READ_DATA_BY_ID:
          handle_read_data_by_id(can, frame);
          break;
        case UDS_SID_TESTER_PRESENT:
          generic_OK_resp(can, frame);
          break;
        case UDS_SID_GM_READ_DIAG_INFO:
          handle_gm_read_diag(can, frame);
          break;
        default:
          //if(verbose) plog("Unhandled mode/sid: %02X\n", frame.data[1]);
          if(verbose) plog("Unhandled mode/sid: %s\n", get_mode_str(frame));
          break;
      }
      break;
    default:
      if (DEBUG) plog("DEBUG: missed ID %02X\n", frame.can_id);
      break;
  }
}

int main(int argc, char *argv[]) {
  int opt;
  int can;
  int nbytes;
  struct ifreq ifr;
  struct sockaddr_can addr;
  struct iovec iov;
  struct msghdr msg;
  struct canfd_frame frame;
  char ctrlmsg[CMSG_SPACE(sizeof(struct timeval)) + CMSG_SPACE(sizeof(__u32))];
  struct sigaction act;

  verbose = 0;
  act.sa_handler = intHandler;
  sigaction(SIGINT, &act, NULL);
  sigaction(SIGHUP, &act, NULL);
  srand(time(NULL));

  while ((opt = getopt(argc, argv, "cV:zl:vFh?")) != -1) {
    switch(opt) {
        case 'c':
          keep_spec = 1;
          break;
        case 'v':
          verbose = 1;
          break;
        case 'V':
          vin = optarg;
          break;
        case 'F':
          no_flow_control = 1;
          break;
        case 'l':
          plogfp = fopen(optarg, "a+");
          break;
        case 'z':
          fuzz_level++;
          break;
        case 'h':
        case '?':
        default:
          usage(argv[0], NULL);
          break;
    }
  }

  if (optind >= argc) usage(argv[0], "You must specify at least one can device");

  // Create a new raw CAN socket
  can = socket(PF_CAN, SOCK_RAW, CAN_RAW);
  if(can < 0) usage(argv[0], "Couldn't create raw socket");

  addr.can_family = AF_CAN;
  memset(&ifr.ifr_name, 0, sizeof(ifr.ifr_name));
  strncpy(ifr.ifr_name, argv[optind], strlen(argv[optind]));
  if (verbose) plog("Using CAN interface %s\n", ifr.ifr_name);
  if (ioctl(can, SIOCGIFINDEX, &ifr) < 0) {
    perror("SIOCGIFINDEX");
    exit(1);
  }
  addr.can_ifindex = ifr.ifr_ifindex;

  if (bind(can, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        return 1;
  }

  iov.iov_base = &frame;
  iov.iov_len = sizeof(frame);
  msg.msg_name = &addr;
  msg.msg_namelen = sizeof(addr);
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  msg.msg_control = &ctrlmsg;
  msg.msg_controllen = sizeof(ctrlmsg);
  msg.msg_flags = 0;

  if(verbose) plog("Fuzz level set to: %d\n", fuzz_level);
  running = 1;
  while(running) {
    nbytes = recvmsg(can, &msg, 0);
    if (nbytes < 0) {
      perror("read");
      return 1;
    }
    if ((size_t)nbytes != CAN_MTU) {
      fprintf(stderr, "read: incomplete CAN frame\n");
      return 1;
    }
    handle_pkt(can, frame);
  }

  plog("Got Interrupt.  Shutting down gracefully\n");
  if(plogfp) fclose(plogfp);

}
