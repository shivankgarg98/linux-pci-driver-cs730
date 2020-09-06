/*
 * Copyright (c) 2020 Shivank Garg
 *
 */

#include<crypter.h>
#include<pthread.h>

pthread_mutex_t cry_lock;

/*Function template to create handle for the CryptoCard device.
On success it returns the device handle as an integer*/
struct key_map {
	KEY_COMP a;
	KEY_COMP b;
};

struct key_map key_store[60000];

DEV_HANDLE create_handle()
{
	DEV_HANDLE cdev = open("/dev/mycryptochar0", O_RDWR);
	if (cdev < 0) 
  		return ERROR;
//	printf("CryptoCard handle created\n");
	if (pthread_mutex_init(&cry_lock,NULL) != 0) {
//		printf("mutex init failed\n");
		return ERROR;
	}
	return cdev;
}

/*Function template to close device handle.
Takes an already opened device handle as an arguments*/
void close_handle(DEV_HANDLE cdev)
{
	key_store[cdev].a = 0;
	key_store[cdev].b = 0;
	close(cdev);
	pthread_mutex_destroy(&cry_lock);
}

/*Function template to encrypt a message using MMIO/DMA/Memory-mapped.
Takes four arguments
  cdev: opened device handle
  addr: data address on which encryption has to be performed
  length: size of data to be encrypt
  isMapped: TRUE if addr is memory-mapped address otherwise FALSE
*/
int __encrypt(DEV_HANDLE cdev, ADDR_PTR addr, uint64_t length, uint8_t isMapped)
{
	uint32_t buf1;
	uint64_t buf2;
	uint8_t isDMA;
	uint8_t isInterrupt;
	/*1. write data */
	DEV_HANDLE sysfd1 = open("/sys/kernel/CryptoSys/isDMA",O_RDONLY);
	if (sysfd1 < 0)
		return ERROR;
	if(pread(sysfd1,&isDMA,1,0) < 0) {
//		printf("encrypt: failed to read config\n");
		return ERROR;
	}
	close(sysfd1);
	DEV_HANDLE sysfd2 = open("/sys/kernel/CryptoSys/isInterrupt",O_RDONLY);
	if (sysfd2 < 0) {
//		printf("isInterrupt open failed\n");
		return ERROR;
	}
	if(pread(sysfd2,&isInterrupt,1,0) < 0) {
//		printf("encrypt: failed to read config\n");
		return ERROR;
	}
	close(sysfd2);
	isDMA = isDMA - 48;
	isInterrupt = isInterrupt - 48; 

//	printf("isDMA,isInterrupt %u,%u\n", isDMA,isInterrupt);

	switch (isDMA) {
	case 0:
	if (pwrite(cdev,addr,(uint32_t)length, 0xa8) < 0) {
//		printf("encrypt: write to device failed\n");				
		return ERROR;
	}
	buf1 = 0x00;
	if(isInterrupt){
		buf1 = buf1 | 0x80;
	}
	/*2.set bit 1 to 0 in MMIO status*/
	if (pwrite(cdev,&buf1,4,0x20) < 0) {
//		printf("encrypt: unsuccessful\n");
		return ERROR;	
	}
	/*3. set length of MMIO msg*/
	buf1 = (uint32_t)length;
	if(pwrite(cdev,&buf1,4,0x0c) < 0){
//		printf("encrypt: MMIO length failed\n");
		return ERROR;
	}
	/*4.write address of data MMIO data addr*/
	buf2 = 0xa8;
	if(pwrite(cdev,&buf2,8,0x80) < 0){
//		printf("data address write failed\n");
		return ERROR;
	}
	/*checks if device is done with encryption*/
	if(isInterrupt == 0) {
		while(pread(cdev,&buf1,4,0x20) > 0){
			if((buf1 & 0x01) == 0x00)
				break;
		}
	}

	/*5. read back it into buffer*/
	if (pread(cdev,addr,(uint32_t)length,0xa8) < 0){
//		printf("encrypt: read data failed\n");
		return ERROR;
	}
	break;
	case 1:
//	printf("DMA ENCRYPT\n");
	if (pwrite(cdev,addr,length, 0xa8) < 0) {
//		printf("encrypt: write to device failed\n");				
		return ERROR;
	}
	/* length of msg DMA */
	buf2 = (uint64_t)length;
	if (pwrite(cdev,&buf2,8,0x98) < 0) {
//		printf("encrypt: DMA length write failed\n");
		return ERROR;
	}
	if (pwrite(cdev,&buf2,8,0x90) < 0) {
//		printf("encrypt: DMA address write failed\n");
		return ERROR;
	}
	buf2 = 0x01 | 0x00;
	if(isInterrupt) {
		buf2 = buf2 | 0x04;
	}
	if (pwrite(cdev,&buf2,8,0xa0) < 0) {
//		printf("encrypt: DMA command register write failed\n");
		return ERROR;
	}
	if(isInterrupt == 0){
		while (pread(cdev,&buf2,8,0xa0) > 0) {
			if((buf2 & 0x01) == 0x00)
				break;
		}
	}
	if (pread(cdev,addr,length,0xa8) < 0) {
//		printf("encrypt: read data failed\n");
		return ERROR;
	}
	break;
	default:
		printf("SYSFS READ WRONG\n");
	}
	return 0;
}

/*Function template to decrypt a message using MMIO/DMA/Memory-mapped.
Takes four arguments
  cdev: opened device handle
  addr: data address on which decryption has to be performed
  length: size of data to be decrypt
  isMapped: TRUE if addr is memory-mapped address otherwise FALSE
*/
int __decrypt(DEV_HANDLE cdev, ADDR_PTR addr, uint64_t length, uint8_t isMapped)
{
	uint32_t buf1;
	uint64_t buf2;
	uint8_t isDMA;
	uint8_t isInterrupt;

	DEV_HANDLE sysfd1 = open("/sys/kernel/CryptoSys/isDMA",O_RDONLY);
	if (sysfd1 < 0)
		return ERROR;
	if(pread(sysfd1,&isDMA,1,0) < 0) {
//		printf("encrypt: failed to read config\n");
		return ERROR;
	}
	close(sysfd1);
	DEV_HANDLE sysfd2 = open("/sys/kernel/CryptoSys/isInterrupt",O_RDONLY);
	if (sysfd2 < 0) {
//		printf("isInterrupt open failed\n");
		return ERROR;
	}
	if(pread(sysfd2,&isInterrupt,1,0) < 0) {
//		printf("encrypt: failed to read config\n");
		return ERROR;
	}
	close(sysfd2);
	isDMA = isDMA - 48;
	isInterrupt = isInterrupt - 48; 
//	printf("isDMA,isInterrupt %u,%u\n", isDMA,isInterrupt);

	switch (isDMA){
	case 0:
	if (pwrite(cdev,addr,(uint32_t)length, 0xa8) < 0) {
//		printf("decrypt: write to device failed\n");				
		return ERROR;
	}
	/*2.set bit 1 to 1 in MMIO status*/
	buf1 = 0x02;
	if (isInterrupt)
		buf1 = 0x02 | 0x80;

	if (pwrite(cdev,&buf1,4,0x20) < 0) {
//		printf("decrypt: unsuccessful\n");
		return ERROR;	
	}
	/*3. set length of MMIO msg*/
	buf1 = (uint32_t)length;
	if(pwrite(cdev,&buf1,4,0x0c) < 0){
//		printf("decrypt: MMIO length failed\n");
		return ERROR;
	}
	/*4.write address of data MMIO data addr*/
	buf2 = 0xa8;
	if(pwrite(cdev,&buf2,8,0x80) < 0){
//		printf("data address write failed\n");
		return ERROR;
	}
	/*checks if device is done with encryption*/
	if (isInterrupt == 0) {
		while(pread(cdev,&buf1,4,0x20) > 0){
			if((buf1 & 0x01) == 0x00)
				break;
		}
	}
	/*5. read back it into buffer*/
	if (pread(cdev,addr,(uint32_t)length,0xa8) < 0){
//		printf("decrypt: read data failed\n");
		return ERROR;
	}
	break;
	case 1:
	if (pwrite(cdev,addr,length, 0xa8) < 0) {
//		printf("decrypt: write to device failed\n");				
		return ERROR;
	}
	/* length of msg DMA */
	buf2 = (uint64_t)length;
	if (pwrite(cdev,&buf2,8,0x98) < 0) {
//		printf("decrypt: DMA length write failed\n");
		return ERROR;
	}
	if (pwrite(cdev,&buf2,8,0x90) < 0) {
//		printf("decrypt: DMA address write failed\n");
		return ERROR;
	}
	buf2 = 0x01 | 0x02;
	if(isInterrupt)
		buf2 = buf2 | 0x04;

	if (pwrite(cdev,&buf2,8,0xa0) < 0) {
//		printf("decrypt: DMA command register write failed\n");
		return ERROR;
	}
	if(isInterrupt == 0){
		while (pread(cdev,&buf2,8,0xa0) > 0) {
			if((buf2 & 0x01) == 0x00)
				break;
		}
	}
	if (pread(cdev,addr,length,0xa8) < 0) {
//		printf("decrypt: read data failed\n");
		return ERROR;
	}
	break;
	default:
		printf("SYSFS READ WRONG\n");
	}	return 0;
}

int encrypt(DEV_HANDLE cdev, ADDR_PTR addr, uint64_t length, uint8_t isMapped)
{
	pthread_mutex_lock(&cry_lock);

	char* ptr;
	ptr = (char *)addr;
	uint64_t frac_len = 4096;
	uint64_t done_len = 0;
	
	uint32_t buf1;
	uint32_t buf2;
	buf1 = key_store[cdev].a;
	buf1 = buf1 << 8;
	buf2 = buf1 | key_store[cdev].b;

	if(pwrite(cdev, &buf2, 4, 0x08) < 0) {
//		printf("key write error\n");
		pthread_mutex_unlock(&cry_lock);
		return ERROR;
	}

	while (done_len + 4096 < length) {
		if(__encrypt(cdev,ptr,4096,isMapped) == ERROR) {
			pthread_mutex_unlock(&cry_lock);
			return ERROR;
		}
		done_len += 4096;
		ptr += 4096;
	}
	frac_len = length - done_len;
	if (frac_len)
		if(__encrypt(cdev,ptr,frac_len,isMapped) == ERROR){
			pthread_mutex_unlock(&cry_lock);	
			return ERROR;
		}
	pthread_mutex_unlock(&cry_lock);
	return 0;
}
int decrypt(DEV_HANDLE cdev, ADDR_PTR addr, uint64_t length, uint8_t isMapped)
{
	pthread_mutex_lock(&cry_lock);

	char* ptr;
	ptr = (char *)addr;
	uint64_t frac_len = 4096;
	uint64_t done_len = 0;
	
	uint32_t buf1;
	uint32_t buf2;
	buf1 = key_store[cdev].a;
	buf1 = buf1 << 8;
	buf2 = buf1 | key_store[cdev].b;

	if(pwrite(cdev, &buf2, 4, 0x08) < 0) {
//		printf("key write error\n");
		pthread_mutex_unlock(&cry_lock);
		return ERROR;
	}
	while (done_len + 4096 < length) {
		if(__decrypt(cdev,ptr,4096,isMapped) == ERROR) {
			pthread_mutex_unlock(&cry_lock);
			return ERROR;
		}
		done_len += 4096;
		ptr += 4096;
	}
	frac_len = length - done_len;
	if (frac_len)
		if(__decrypt(cdev,ptr,frac_len,isMapped) == ERROR) {
			pthread_mutex_unlock(&cry_lock);
			return ERROR;
		}
	pthread_mutex_unlock(&cry_lock);
	return 0;
}

/*Function template to set the key pair.
Takes three arguments
  cdev: opened device handle
  a: value of key component a
  b: value of key component b
Return 0 in case of key is set successfully*/
int set_key(DEV_HANDLE cdev, KEY_COMP a, KEY_COMP b)
{
	/*uint32_t buf1;
	uint32_t buf2;
	buf1 = a;
	buf1 = buf1 << 8;
	buf2 = buf1 | b;
	

	printf("Key: %x\n", buf2);	
	if(pwrite(cdev, &buf2, 4, 0x08) < 0) {
		printf("key write error\n");
		return ERROR;
	}*/
	key_store[cdev].a = a;
	key_store[cdev].b = b; 
	return 0;
}

/*Function template to set configuration of the device to operate.
Takes three arguments
  cdev: opened device handle
  type: type of configuration, i.e. set/unset DMA operation, interrupt
  value: SET/UNSET to enable or disable configuration as described in type
Return 0 in case of key is set successfully*/
int set_config(DEV_HANDLE cdev, config_t type, uint8_t value)
{
	pthread_mutex_lock(&cry_lock);

	uint8_t buf;
	char buf1[4];
	
	DEV_HANDLE sysfd;
	if (type == DMA) {
		sysfd = open("/sys/kernel/CryptoSys/isDMA",O_RDWR);
		if (sysfd < 0) {
			pthread_mutex_unlock(&cry_lock);	
			return ERROR;
		}	
	} 
	else if (type == INTERRUPT) {
		sysfd = open("/sys/kernel/CryptoSys/isInterrupt",O_RDWR);
		if (sysfd < 0) {
			pthread_mutex_unlock(&cry_lock);	
			return ERROR;
		}
	}
	if (value == SET) {
		buf = 1;
		snprintf(buf1,4,"%d",buf);
		if (write(sysfd,buf1,4) < 0) {
//			printf("write failed\n");
			goto failure_close;
		}
	}
	else if (value == UNSET) {
		buf = 0;
		snprintf(buf1,4,"%d",buf);
		if (write(sysfd,buf1,4) < 0) {
//			printf("write failed\n");
			goto failure_close;
		}
	}
	close(sysfd);
	pthread_mutex_unlock(&cry_lock);
	return 0;
failure_close:	
	close(sysfd);
	pthread_mutex_unlock(&cry_lock);	
	return ERROR;
}
/*Function template to device input/output memory into user space.
Takes three arguments
  cdev: opened device handle
  size: amount of memory-mapped into user-space (not more than 1MB strict check)
Return virtual address of the mapped memory*/
ADDR_PTR map_card(DEV_HANDLE cdev, uint64_t size)
{
  return NULL;
}

/*Function template to device input/output memory into user space.
Takes three arguments
  cdev: opened device handle
  addr: memory-mapped address to unmap from user-space*/
void unmap_card(DEV_HANDLE cdev, ADDR_PTR addr)
{

}
