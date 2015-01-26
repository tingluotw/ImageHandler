#include <stdio.h>
#include <windows.h>
#include <winternl.h>
#include <tchar.h>
#include <strsafe.h>
#include <string.h>
#define one 1
#define two 2
CHAR* GetFileName(char* originalpath)
{
	char* out1;
	char* out2;
	char* out3;
	char out4[] = ".txt";
	int length = 0;

	/*
	origialpath will have \\ because of escape symbol
	but if I print out this originalpath the escape symbol will remove automatically
	e.g, originalpath = hello\\my.exe
	*/

	out1 = strrchr(originalpath, '\\'); //must use escape symbol, out1=\\me.exe
	out2 = strrchr(originalpath, '.');  //cannot use double quote, out2=.exe

	if (out1 == NULL){
		out1 = originalpath;
	}
	else
		out1++; //get rid of escape symbol, out1 = me.exe

	length = strlen(out1) - strlen(out2) + strlen(out4);
	out3 = malloc(sizeof(CHAR) * length);
	memset(out3, '\0', sizeof(CHAR) * length);

	strncpy(out3, out1, strlen(out1) - strlen(out2)); // so need to +1 at length to contain '.', out3=me.
	strncat(out3, out4, strlen(out4));//out = me.txt

	return out3;
}
/*
WriteToFile: write to a specific txt file
@imagepath
@inputStr: input string
return -1 if fail, otherwise return 0
*/
INT WriteToFile(char* imagepath, char* inputStr){

	FILE *pFile = NULL;
	// extract appropriate file name from imagepath, ex: xxx.txt
	char* openfile = GetFileName(imagepath);
	//printf(">> write_to file %s\n", openfile);
	pFile = fopen(openfile, "w");
	if (pFile){
		fputs(inputStr, pFile);
		fclose(pFile);
	}
	else{
		printf(">> Error: Write_to file fail...\n");
		return -1;
	}

	return 0;
}
CHAR* CheckForImagePath(CHAR* imagepath)
{
	CHAR *ret = NULL;
	CHAR str[] = "\\??\\";
	CHAR str2[] = "\\\\??\\";
	INT result = 0;

	
	if (strncmp(imagepath, str, strlen(str)) == 0)
	{
		ret = strrchr(imagepath, '?');
		ret = ret + 2;
	}
	else if (strncmp(imagepath, str2, strlen(str2)) == 0){		
		ret = strrchr(imagepath, '?');
		ret = ret + 2;	
	}
	else
		ret = imagepath;

	return ret;
}
CHAR* StringToLower(CHAR* str)
{
	CHAR* t = str;
	CHAR* result = NULL;
	INT i = 0;
	result = malloc(sizeof(CHAR)*strlen(str));
	while (*t != '\0')
	{
		if (*t >= 'A' && *t <= 'Z')
		{
			result[i] = tolower(*t);		
		}
		else{
			result[i] = *t;
		}
		t++;
		i++;
	}
	result[i] = '\0';
	return result;
}
int main(int argc, char* argv[]){
	CHAR str[] = "\\??\\c:\\test\\adb.txt";
	CHAR strr[] = "c:\\test\\AFETD.txt";
	CHAR strrr[] = "\\\\??\\C:\\test\\adddgnt.txt";

	CHAR *pstr;
	pstr = StringToLower(strr);
	printf("%s\n", pstr);

	pstr = CheckForImagePath(str);
	printf("%s\n", pstr);

	pstr = CheckForImagePath(strrr);
	printf("%s\n", pstr);

	system("pause");
	return 0;
}