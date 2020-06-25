#include <stdio.h>
#include <string.h>
#include <stdint.h>

typedef struct inputbin
{
	int size;
	uint8_t input[12176];
} inputbin;

int main()
{

	//read in the hex numbers from text file to an array
	FILE* infile = fopen("inputbytes.txt", "r");
    if(infile == NULL)
    {
    	printf("Input file error");
    	return(2);
    }

    
    inputbin inbin;
    inbin.size = 12176;
    //inbin.input = input;
    //uint8_t input[12172];
    //uint8_t input[12172] = {0x31};
    //printf("%u\n", input);
    for(int x = 0; x < 12176; x++)
    {
    	fscanf(infile, "%hhx", &inbin.input[x]);
    	printf("0x%hhx ", inbin.input[x]);
    }
    printf("\nSize = %d\n", inbin.size);
    fclose(infile);

    //write array with struct to file
	FILE* binfile = fopen("input.bin", "wb");
    if(binfile == NULL)
    {
    	printf("Binary file error");
    	return(2);
    }

    fwrite(&inbin, sizeof(inputbin), 1, binfile);
    fclose(binfile);

	return(0);
}