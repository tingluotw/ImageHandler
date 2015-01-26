#include <stdio.h>
#include <string.h>
//#include <ntdef.h>
#include <tchar.h>
#include <sys/stat.h>
#include <errno.h>
#include <jansson.h>

#include "VtFile.h"
#include "VtResponse.h"

//#pragma comment(lib,"MyVtLibrary.lib")
#define MAX_LENGTH_OF_IMAGE_PATH 100
#define MAX_LENGTH_OF_APIKEY 100
#define RESP_BUF_SIZE 255
#define EXIT 0
#define SCAN 1
#define REPORT 2
static bool keep_running = true;

void print_usage(const char *prog_name) {
	printf("%s < --apikey YOUR_API_KEY >   [ --filescan FILE1 ] [ --filescan FILE2 ]\n", prog_name);
	printf("    --apikey YOUR_API_KEY          Your virus total API key.  This arg 1st \n");
	printf("    --filescan FILE          File to scan.   Note may specify this multiple times for multiple files\n");
	printf("    --report SHA/MD5          Get a Report on a resource\n");
	printf("    --cluster YYYY-MM-DD          Get a Report on a resource\n");
	printf("    --download <hash>            Output file for download\n");
	printf("    --out <file>            Output file for download\n");
}

void progress_callback(struct VtFile *file, void *data)
{
	int64_t dltotal = 0;
	int64_t dlnow = 0;
	int64_t ul_total = 0;
	int64_t ul_now = 0;
	//VtFile_getProgress(file, &dltotal, &dlnow, &ul_total, &ul_now);

	printf("progress_callback %lld/%lld\n", (long long)ul_now, (long long)ul_total);
	//if (!keep_running)
	//	VtFile_cancelOperation(file);
}

int scan_file(struct VtFile *scan, const char *path)
{
	int ret;
	struct _stat stat_buf;
	
	printf("Ready to scan %s (length:%d)\n", path,strlen(path));
	ret = _stat(path ,&stat_buf);

	if (ret !=0 ){
		perror("get file state error");
		switch (errno){
		case ENOENT:
			printf("file %ls not found\n", path);
			break;
		case EINVAL:
			printf("invalid parameters to _stat\n");
			break;
		default:
			printf("Unexpected error in _stat(%d)", errno);
		}
			
	}
	else{
		
		printf("File size is: %d\n", stat_buf.st_size);
		printf("File path is : %s\n", path);
		if (stat_buf.st_size < (64 * 1024 * 1024)) {
			ret = VtFile_scan(scan, path, NULL);
			printf("VtFile_scan return %d\n", ret);
		}
		else {
			ret = VtFile_scanBigFile(scan, path);
			printf(" VtFile_scanBigFile ret =%d \n", ret);
		}		
	}
	return ret;
	
}

int write_toFile(char* outfile, char* inputStr){
	FILE *pFile = NULL;
	pFile = fopen(outfile, "w");
	if (pFile){
		fputs(inputStr, pFile);
		fclose(pFile);
	}
	else{
		printf("write_toFile fail...\n");
		return -1;
	}

	return 0;
}

int main(int argc, char* argv[]){
	char imagePath[MAX_LENGTH_OF_IMAGE_PATH];
	char apiKey[MAX_LENGTH_OF_APIKEY] = {"18d3ac54fcd0e6329ae52c9afba4bbac7de3dd9af5aa7262f9855bb404e1eacb"};

	int c;
	int ret = 0;
	struct VtFile *file_scan;
	struct VtResponse *response;
	char *str = NULL;
	//char *api_key = NULL;
	//char *out = NULL;
	int response_code;
	int option = 0;
	char *scan_id = NULL;
	//struct CallbackData cb_data = { .counter = 0 };
	char buf[RESP_BUF_SIZE + 1] = { 0, };
	FILE  *pfile = NULL;
	char output1[] = "output_scan.txt";
	char output2[] = "output_report.txt";
	//char *positive = NULL;
	int positive = 0;
	memset((void*)&imagePath, '\0', sizeof(char) * MAX_LENGTH_OF_IMAGE_PATH);
		
	/*both _tscanf _tprintf will transform into wprintf and wscanf, 
	so params inside should use same format,i.e L must be added*/

	file_scan = VtFile_new();
	VtFile_setProgressCallback(file_scan, progress_callback, NULL);
	VtFile_setApiKey(file_scan, apiKey);

	if (argc != 3){
			printf("Please enter [options] [Image Path]\n");
			printf("[options: 0 - exit, 1 - scan, 2 - report] \n");
	}
	else{
			option = atoi(argv[1]);
			switch (option){
			case(EXIT) :
				return -1;
				break;

			case(SCAN):
				memcpy(imagePath, argv[2], strlen(argv[2]));
			
				ret = scan_file(file_scan, imagePath);
				if (ret) { 
					printf("scan_file error: %d \n", ret);
				}else {
					response = VtFile_getResponse(file_scan);
					str = VtResponse_toJSONstr(response, VT_JSON_FLAG_INDENT);
					if (str) {
						printf("Response:\n%s\n", str);
						write_toFile(output1, str);
						free(str);
					}
					VtResponse_put(&response);
				}
				break;

			case(REPORT) :
				scan_id =argv[2];				
				ret = VtFile_report(file_scan, scan_id); //get report from VirusTotal
				if (ret) {
					printf("Error: %d \n", ret);
				}
				else {

					response = VtFile_getResponse(file_scan); //get response from file_scan structure														
					str = VtResponse_toJSONstr(response, VT_JSON_FLAG_INDENT); //transfer to json object

					if (str) {

						//printf("Response:\n%s\n", str);
						write_toFile(output2, str);
						free(str);
					}
					
					VtResponse_getVerboseMsg(response, buf, RESP_BUF_SIZE);
					printf("Msg: %s\n", buf);

					ret = VtResponse_getResponseCode(response, &response_code);
					if (!ret) {
						printf("response code: %d\n", response_code);
					}

					//positive = VtResponse_getString(response, "permalink");

					//get positives number in response
					ret = VtResponse_getIntValue(response, "positives", &positive);
					if (ret == 0){
						printf("positives = %d \n", positive);
					}
					else{
						printf("VtResponse_getString return null\n");
					}
					//recycle the response object
					VtResponse_put(&response);
					
				}

			}//end of switch
	}//end of else
	system("pause");
	return 0;

}