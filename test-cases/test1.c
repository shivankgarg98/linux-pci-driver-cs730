#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <crypter.h>

int main()
{
  DEV_HANDLE cdev,cdev2;
  char *msg = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVW123456SHIvank";
  char *msg2 = "abcdefghijklmnopqrstuvwxyz@GARG";
  char op_text[4096*16];
 char op_text2[100];
  KEY_COMP a=30, b=17;
KEY_COMP A = 12, B= 99;
	
  uint64_t size = strlen(msg);
  uint64_t size2 = strlen(msg2);
  strcpy(op_text, msg);
strcpy(op_text2, msg2);
  cdev = create_handle();
cdev2 = create_handle();
  printf("setconfig: %d\n", set_config(cdev,DMA,SET));
  printf("setconfig: %d\n", set_config(cdev,INTERRUPT,UNSET));
	
  if(cdev == ERROR)
  {
    printf("Unable to create handle for device\n");
    exit(0);
  }
if(cdev2 == ERROR)
  {
    printf("Unable to create handle for device\n");
    exit(0);
  }
  if(set_key(cdev, a, b) == ERROR){
    printf("Unable to set key\n");
    exit(0);
  }
if(set_key(cdev2,A,B) == ERROR){
exit(0);
}
  printf("Original Text: %s\n", msg);

  encrypt(cdev, op_text, size, 0);
  printf("Encrypted Text 1: %s\n", op_text);
  encrypt(cdev2,op_text2,size2,0);
  printf("Encrypted Text 2: %s\n", op_text2);
  decrypt(cdev, op_text, size, 0);//
  printf("Decrypted Text 1: %s\n", op_text);
  decrypt(cdev2,op_text2,size2,0);
  printf("Decrypted Text 2: %s\n", op_text2);


  close_handle(cdev);
  return 0;
}
