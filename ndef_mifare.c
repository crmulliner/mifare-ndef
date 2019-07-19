/*
 *  Copyright: Collin Mulliner <collin[at]mulliner.org>
 *  License: GPLv2
 *
 *  This is totally based on mifare-tool from librfid!!!
 *
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>

#ifndef __MINGW32__
#include <libgen.h>
#endif

#define _GNU_SOURCE
#include <getopt.h>

#include <librfid/rfid.h>
#include <librfid/rfid_scan.h>
#include <librfid/rfid_reader.h>
#include <librfid/rfid_layer2.h>
#include <librfid/rfid_protocol.h>

#include <librfid/rfid_protocol_mifare_classic.h>
#include <librfid/rfid_protocol_mifare_ul.h>

#include <librfid/rfid_access_mifare_classic.h>

#include "librfid-tool.h"

static struct option mifare_opts[] = {
	{ "read", 1, 0, 'r' },
	{ "write", 1 ,0, 'w' },
	{ "help", 0, 0, 'h' },
	{ "mf4k", 0, 0, '4' },
	{ "key-b", 0, 0, 'B' },
	{ "format", 1, 0, 'f' },
	{ "clear", 0, 0, 'c' },
	{ "dump", 1, 0, 'd' },
	{ "ign4kmad", 0, 0, 'm' },
	{ 0, 0, 0, 0 }
};

static void help(void)
{
	printf(
		"ndef_mifare v0.3: Copyright Collin Mulliner http://www.mulliner.org/nfc/\n"
		" License: GPLv2\n"
		"syntax: ndef_mifare <options> [file]\n\n"
		" -h	--help         Print this help message\n"
		" -r	--read [file]  Read a mifare card/tag\n"
		" -w	--write [file] Write a mifare card/tag\n"
		" -4	--mf4k         R/W Mifare 4K card/tag\n"
		" -m	--ign4kmad     Ignore second MAD in Mifare 4k\n"
		" -B	--key-b        Use B key\n"
		" -f	--format [sec] NDEF format card/tag, start at sector: sec\n"
		" -c	--clear        Clear/wipe data area\n"
		" -d	--dump [file]  Dump entire tag (inc. trailers)\n"
		"");
}

static int mifare_cl_auth(unsigned char *key, int page)
{
	int rc;

	rc = mfcl_set_key(ph, key);
	if (rc < 0) {
		fprintf(stderr, "key format error\n");
		return rc;
	}
	rc = mfcl_auth(ph, RFID_CMD_MIFARE_AUTH1A, page);
	if (rc < 0) {
		//fprintf(stderr, "mifare auth error\n");
		return rc;
	} else 
		printf("mifare auth succeeded!\n");
	
	return 0;
}

static int mifare_cl_authB(unsigned char *key, int page)
{
	int rc;

	rc = mfcl_set_key(ph, key);
	if (rc < 0) {
		fprintf(stderr, "key format error\n");
		return rc;
	}
	rc = mfcl_auth(ph, RFID_CMD_MIFARE_AUTH1B, page);
	if (rc < 0) {
		//fprintf(stderr, "mifare auth error\n");
		return rc;
	} else 
		printf("mifare auth succeeded!\n");
	
	return 0;
}

static void mifare_l3(void)
{
	while (l2_init(RFID_LAYER2_ISO14443A) < 0) ;

	printf("ISO14443-3A anticollision succeeded\n");

	while (l3_init(RFID_PROTOCOL_MIFARE_CLASSIC) < 0) ;

	printf("Mifare card available\n");
}

int main(int argc, char **argv)
{
	const char mifare_default_key[] = {"ffffffffffff"};
	const char ndef_key[] = {"d3f7d3f7d3f7"};
	const char ndef_key_write[] = {"c3f7d3f7d3f7"};
	const char mad_key[] = {"a0a1a2a3a4a5"};
	const char default_mad_data[] =     {0x00,0x01,0x03,0xe1,0x03,0xe1,0x03,0xe1,0x03,0xe1,0x03,0xe1,0x03,0xe1,0x03,0xe1};
	const char default_mad_data_2[] =   {0x03,0xe1,0x03,0xe1,0x03,0xe1,0x03,0xe1,0x03,0xe1,0x03,0xe1,0x03,0xe1,0x03,0xe1};
	const char default_ndef_trailer[] = {0xd3,0xf7,0xd3,0xf7,0xd3,0xf7,0x7f,0x07,0x88,0x40,0xd3,0xf7,0xd3,0xf7,0xd3,0xf7};
	const char default_mad_trailer[] =  {0xa0,0xa1,0xa2,0xa3,0xa4,0xa5,0x78,0x77,0x88,0xC1,0xa0,0xa1,0xa2,0xa3,0xa4,0xa5};
	char key[MIFARE_CL_KEY_LEN];
	char keyB[MIFARE_CL_KEY_LEN];
	char dkey[MIFARE_CL_KEY_LEN];
	char buf[MIFARE_CL_PAGE_SIZE];
	int lrc, c, option_index = 0;
	unsigned char *data = NULL;
	unsigned int data_len = 0;
	unsigned char AreadBwrite_sec_trailer[4] = {0};
	int mf4k = 0;
	int numsectors = 64;
	int AorB = 1;
	int clear = 0;
	int mf4k_ignore_second_mad = 0;
	
	rfid_init();

	if (reader_init() < 0) {
		fprintf(stderr, "error opening reader\n");
		help();
		exit(1);
	}

	hexread(key, ndef_key, strlen(ndef_key));
	hexread(dkey, mifare_default_key, strlen(mifare_default_key));

	while (1) {
		c = getopt_long(argc, argv, "mF:f:4hcBr:w:d:", mifare_opts, &option_index);
		if (c == -1)
			break;
	
		switch (c) {
		case 'f': // FORMAT tag
			{
			printf("NDEF Formatting card/tag with %d sectors\n", numsectors);
			
			hexread(key, mifare_default_key, strlen(mifare_default_key));
			int start = atoi(optarg);
			int len = MIFARE_CL_PAGE_SIZE;
			int i;
			int rc;
			mifare_l3();

			if (start < 4) {
				start = 4;
			}

			if (start == 4) {
			// MAD
			if (AorB == 1 && mifare_cl_auth(key, 1) < 0)
				exit(1);
			else if (AorB == 2 && mifare_cl_authB(key, 1) < 0)
				exit(1);

			rc = rfid_protocol_write(ph, 1, default_mad_data, len);
			if (rc < 0)
				exit(0);
				
			if (AorB == 1 && mifare_cl_auth(key, 2) < 0)
				exit(1);
			else if (AorB == 2 && mifare_cl_authB(key, 2) < 0)
				exit(1);
				
			rc = rfid_protocol_write(ph, 2, default_mad_data_2, len);
			if (rc < 0)
				exit(0);
				
			if (AorB == 1 && mifare_cl_auth(key, 3) < 0)
				exit(1);
			else if (AorB == 2 && mifare_cl_authB(key, 3) < 0)
				exit(1);
				
			rc = rfid_protocol_write(ph, 3, default_mad_trailer, len);
			if (rc < 0)
				exit(0);
			}
	
			// DATA
			for (i = start; i < numsectors; i++) {
				//printf("w %d\n", i * MIFARE_CL_PAGE_SIZE);
				int sec = i;

				// second MAD on Mifare 4K				
				if (mf4k == 1 && mf4k_ignore_second_mad == 0) {
					if (sec == 64) {
						if (AorB == 1 && mifare_cl_auth(key, 64) < 0)
							exit(1);
						else if (AorB == 2 && mifare_cl_authB(key, 64) < 0)
							exit(1);
					
						rc = rfid_protocol_write(ph, 64, default_mad_data, len);
						if (rc < 0)
							exit(0);
							
						continue;
					}
					else if (sec == 65 || sec == 66) {
						if (AorB == 1 && mifare_cl_auth(key, sec) < 0)
							exit(1);
						else if (AorB == 2 && mifare_cl_authB(key, sec) < 0)
							exit(1);
				
						rc = rfid_protocol_write(ph, sec, default_mad_data_2, len);
						if (rc < 0)
							exit(0);
							
						continue;
					}
					else if (sec == 67) {
						if (AorB == 1 && mifare_cl_auth(key, 67) < 0)
							exit(1);
						else if (AorB == 2 && mifare_cl_authB(key, 67) < 0)
							exit(1);
					
						rc = rfid_protocol_write(ph, 67, default_mad_trailer, len);
						if (rc < 0)
							exit(0);
							
						continue;
					}
				}
				
				// only write trailers
				if ((sec < 128 && sec % 4 == 3) || (sec >= 128 && sec % 16 == 15)) {
					printf("sec = %d\n", sec);
					if (AorB == 1 && mifare_cl_auth(key, sec) < 0)
						exit(1);
					else if (AorB == 2 && mifare_cl_authB(key, sec) < 0)
						exit(1);

					printf("formating sec = %d\n", sec);
					rc = rfid_protocol_write(ph, sec, default_ndef_trailer, len); 
					if (rc < 0) {
						printf("\n");
						fprintf(stderr, "error during write\n");
						break;
					}
				}
				else
					continue;
			}
		}
		exit(0);
		break;
		
		case 'B':
			AorB = 2;
			printf("using B key to authenticate\n");
			break;
		
		case '4':
			mf4k = 1;
			numsectors = (4 * 32) + (8 * 16);
			printf("Mifare 4k\n");
			break;
		
		case 'm':
			if (mf4k == 1) {
				mf4k_ignore_second_mad = 1;
				printf("Ignoring 2nd MAD in Mifare 4k\n");
			}
			break;
			
		case 'r':
		 {
		 	printf("Read card/tag\n");
			int fp = open(optarg, O_CREAT|O_RDWR, 00644);
			int len = MIFARE_CL_PAGE_SIZE;
			mifare_l3();
			
			int i;
			for (i = 4; i < numsectors; i++) {
				int sec = i;
				// skip trailers
				if (sec < 128 && sec % 4 == 3)
					continue;
				else if (sec >= 128 && sec % 16 == 15)
					continue;
					
				if (mf4k_ignore_second_mad == 0) {
					if (sec >= 64 && sec <= 67)
						continue;
				}

				if (AorB == 1 && mifare_cl_auth(key, sec) != 0)
					exit(1);
				else if (AorB == 2 && mifare_cl_authB(key, sec) != 0)
					exit(1);
				
				printf("reading sector: %d \n", sec);
				int rc = rfid_protocol_read(ph, sec, buf, &len);
				if (rc < 0) {
					printf("\n");
					fprintf(stderr, "error during read\n");
					break;
				}
				write(fp, buf, len);
				len = MIFARE_CL_PAGE_SIZE;
			}
			close(fp);
		}
		break;
			
		case 'd':
		 {
		 	printf("Dump card/tag\n");
			int fp = open(optarg, O_CREAT|O_RDWR, 00644);
			int len = MIFARE_CL_PAGE_SIZE;
			unsigned int uid,uid_len;
			uid_len = sizeof(uid);
			mifare_l3();
			if(rfid_layer2_getopt(l2h,RFID_OPT_LAYER2_UID,&uid,&uid_len)>=0)
				printf("UID=%08X (len=%u)\n",uid,uid_len);
			char mkey[MIFARE_CL_KEY_LEN];
			
			hexread(mkey, mad_key, strlen(mad_key));
			int i;
			for (i = 0; i < 4; i++) {
				int sec = i;

				if (AorB == 1 && mifare_cl_auth(mkey, sec) != 0)
					exit(1);
				else if (AorB == 2 && mifare_cl_authB(mkey, sec) != 0)
					exit(1);
				
				printf("reading sector: %d \n", sec);
				int rc = rfid_protocol_read(ph, sec, buf, &len);
				if (rc < 0) {
					printf("\n");
					fprintf(stderr, "error during read\n");
					break;
				}
				write(fp, buf, len);
				len = MIFARE_CL_PAGE_SIZE;
			}
			
			for (i = 4; i < numsectors; i++) {
				int sec = i;

				if (mf4k == 1) {
					if (sec >= 64 && sec <= 67) {
						if (AorB == 1 && mifare_cl_auth(mkey, sec) != 0)
							exit(1);
						else if (AorB == 2 && mifare_cl_authB(mkey, sec) != 0)
							exit(1);
					}
				}
				else {
					if (AorB == 1 && mifare_cl_auth(key, sec) != 0)
						exit(1);
					else if (AorB == 2 && mifare_cl_authB(key, sec) != 0)
						exit(1);
				}
						
				printf("reading sector: %d \n", sec);
				int rc = rfid_protocol_read(ph, sec, buf, &len);
				if (rc < 0) {
					printf("\n");
					fprintf(stderr, "error during read\n");
					break;
				}
				write(fp, buf, len);
				len = MIFARE_CL_PAGE_SIZE;
			}
			close(fp);
		}
		break;

		// clear data basically is a "write"
		case 'c':
			clear = 1;
		case 'w':
			{
			if (clear == 1) {
				printf("Clearing card/tag\n");
				data_len = 4096;
				data = malloc(data_len);
				memset(data, 0, data_len);
			}
			else {
				printf("Writting data to card/tag\n");
				int fp = open(optarg, O_RDONLY);
				data_len = lseek(fp, 0, SEEK_END);
				lseek(fp, SEEK_SET, 0);
				data = malloc(data_len);
				read(fp, data, data_len);
				close(fp);
			}
			
			int num = data_len / MIFARE_CL_PAGE_SIZE;
			int len = MIFARE_CL_PAGE_SIZE;
			int i;
			int i2 = 0;
			
			mifare_l3();
			
			for (i = 4; i < numsectors; i++) {
				int sec = i;
				
				// skip trailers
				if (sec < 128 && sec % 4 == 3)
					continue;
				else if (sec >= 128 && sec % 16 == 15)
					continue;
				
				if (mf4k_ignore_second_mad == 0) {
					if (sec >= 64 && sec <= 67)
						continue;
				}
				
				if (AorB == 1 && mifare_cl_auth(key, sec) < 0)
					exit(1);
				else if (AorB == 2 && mifare_cl_authB(key, sec) < 0)
					exit(1);
					
				printf("writting sector: %d \n", sec);
				int rc;
				rc = rfid_protocol_write(ph, sec, data + (i2 * MIFARE_CL_PAGE_SIZE), len); 
				if (rc < 0) {
					printf("\n");
					fprintf(stderr, "error during write\n");
					break;
				}
				i2++;
				if (num <= i2)
					break;
			}
			}
			if (data)
				free(data);
			break;
		
		case 'h':
		default:
			help();
		}
	}
}
