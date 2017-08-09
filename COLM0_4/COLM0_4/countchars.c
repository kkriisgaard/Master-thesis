#include <stdio.h>

int main(int argc,char *argv[])
{
	if(argc<2)
	{
		printf("You need to supply a filename!\n");
		return 0;
	}
	int sz = 0;
	FILE *fp;
	fp = fopen(argv[1],"r");
	if(fp==NULL){printf("Couldn't open file. Terminating\n");return 0;}
	fseek(fp, 0L, SEEK_END);
	sz = ftell(fp);
	fclose(fp);
	int os = ((sz/(127*16))+1)*16;
	printf("Number of characters in file is: %d\n",sz);
	printf("COLM0 ciphertext will have length: %d\n", sz+16);
	printf("COLM127 ciphertext will have length: %d\n", sz+os);
	printf("COLM127 encryption will compute %d intermediate tags\n",os/16);
	return 0;
}
