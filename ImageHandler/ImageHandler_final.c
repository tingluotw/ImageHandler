/************************************************************************************************************* 
 *   ImageHandler_ver1
 *   Authored by Irene Luo 
 *   Last Modified 2015/5/30
 *   Description:
 *      0. Get ZwCreateProcess native api's address and send it to ImageController(kernel driver)
 *		1. Receive the captured image path from ImageController
 *      2. Send it to VirusTotal and get scan_id field
 *      3. Ask report periodically, and get positive value
 *      4. Check the result, and tell ImageController to execute the image or not
 *************************************************************************************************************/

#include <stdio.h>
#include <windows.h>
#include <winternl.h>
#include <tchar.h>
#include <strsafe.h>
#include <sys/stat.h>
#include <jansson.h>
#include <errno.h>
#include <string.h>
#include <openssl/md5.h>

#include "VtFile.h"
#include "VtResponse.h"


#define SIOCTL_TYPE 40000

/*  
	It's a CTL_CODE Macro
	@Device Object Type:SIOCTL_TYPE (FILE_DEVICE_UNKNOWN cannot use!) 
	@IOCTL code: 0x800 , defined by programmer(0x800 - 0xFFF)
	@Method: METHOD_BUFFERED, means to use buffer
	@Access: access rights
*/
#define IOCTL_GETADDRESS CTL_CODE(SIOCTL_TYPE, 0X800, METHOD_BUFFERED, FILE_READ_DATA|FILE_WRITE_DATA)

/*
	Following three states are pipe's state, using at namedpipe overlapped I/O communication
*/
#define CONNECTING_STATE 0 
#define READING_STATE 1 
#define WRITING_STATE 2 

#define INSTANCES 20								/* 50 instances in a namedpipe, upper bound is 255 */
#define PIPE_TIMEOUT 5000
#define BUFSIZE 1024								/* buffer size inside a pipe */

#define THREADCOUNT 3								/* thread total numbers */

#define MAX_LENGTH_OF_APIKEY 100					/* Max VirusTotal key length */
#define MAX_NUMBERS_OF_KEY 6
#define MAX_HASH_PER_IMAGE 100

#define RESP_BUF_SIZE 255							/* buffer size in VtResponse obj */
#define VIRUSTOTAL_ENGINES_NUMBERS 56
#define THRESHOLD VIRUSTOTAL_ENGINES_NUMBERS*1/3	/* threshold to judge the file is safe or not */
#define SCAN_PAUSE 15000							/* time to sleep when scanning (microsecond) */
#define REPORT_PAUSE 15000							/* time to sleep when reporting (microsecond) */
#define DONE_PAUSE 2000								/* time to sleep when asking done queue (microsecond) */

/* a function pointer points to ZwCreatUserProcess syscall */
typedef NTSTATUS(__stdcall *ZwCreateUserProcessPrototype)(
	PHANDLE ProcessHandle,
	PHANDLE ThreadHandle,
	PVOID Parameter2,
	PVOID Parameter3,
	PVOID ProcessSecurityDescriptor,
	PVOID ThreadSecurityDescriptor,
	PVOID Parameter6,
	PVOID Parameter7,
	PRTL_USER_PROCESS_PARAMETERS ProcessParameters,
	PVOID Parameter9,
	PVOID pProcessUnKnow
	);

/* Pipe Instance */
typedef struct
{
	OVERLAPPED oOverlap;
	HANDLE hPipeInst;
	TCHAR chRequest[BUFSIZE];
	INT reply;
	DWORD cbRead;
	//TCHAR chReply[BUFSIZE];
	DWORD cbToWrite;
	DWORD dwState;
	BOOL fPendingIO;
	
} PIPEINST, *LPPIPEINST;

/*
	The main object created to record the important info 
	@filepath
	@scan_id: id of scanned file on VirusTotal
	@key
	@hash: md5 hash from VtResponse
	@key_index
	@response_code: status after scanning a file on VirusTotal
	@positive: result from report on VirusTotal
	@scan_num: how many times to scan this file
	@report_num: how many times to get the report of this file
	@total_num: how many obj are in this list
	@id: node id
	@report_time
	@scan_time
	@http_response
	@FileState *prev
	@FileState *next
*/
typedef struct fileState {
	CHAR *filepath;
	CHAR *scan_id;      //id of scanned file on VirusTotal
	CHAR *key;
	UCHAR *hash;		//md5 hash from VtResponse
	int key_index;
	int response_code;	//status after scanning a file on VirusTotal
	int positive;		//result from report on VirusTotal
	int scan_num;		//how many times to scan this file
	int report_num;		//how many times to get the report of this file
	int total_num;		//how many obj are in this list
	int id;				//node id
	DWORD report_time;
	DWORD scan_time;
	DWORD execution_time;
	int http_response;
	struct FileState *prev;
	struct FileState *next;
} FileState;

FileState* ScanQueue = NULL;
FileState* ReportQueue = NULL;
FileState* DoneQueue = NULL;

PIPEINST Pipe[INSTANCES];
HANDLE hEvents[INSTANCES];
HANDLE hThread[THREADCOUNT];

HANDLE hMutex_dq = NULL; //mutex's handle of done queue
HANDLE hMutex_request = NULL;
INT TotalRequest = 0;
INT OuputCounter = 1;	//only used in WriteDoneRecord()
INT NumInSq = 0;
INT NumInRq = 0;
INT NumInDq = 0;
CHAR const KEY[MAX_NUMBERS_OF_KEY][MAX_LENGTH_OF_APIKEY] = {
						"d9ce2439d5fa7f4e064469605614c6cb61f416f735cd35a98e4644fc2cd42dc8",
						"18d3ac54fcd0e6329ae52c9afba4bbac7de3dd9af5aa7262f9855bb404e1eacb",
						"cfeab1fc040f8683c5de79adc1929b359526ec44c0b29f305a6c524533b43406",
						"c2923f15a33c701fb7e3efa6054a94905af3b1be9d1e84fbdd4213c928fcaa76",
						"035e6747575ce48975563167256750d56d2d81ba0af8e80a718f068fc5299b11",
						"fb23bb26cad438483eed19cc294ad8d55fe671f36aa7ee7bb58bbaa67f43f71f"};

/*
   CreateNode: Create a node and initialize it
    @filepath
	@scan_id:id of scanned file on VirusTotal
	@response_code: return status after scan a file on VirusTotal
	@positive: result from report on VirusTotal
	@scan_num: how many times to scan this file
	@report_num: how many times to get the report of this file
	@total_num: how many obj are in this list
	@id: node id
	return node pointer
 */
FileState*  CreateNode(CHAR* filepath, INT keyIndex)
{
	FileState *node = malloc(sizeof(FileState));
	if (!node){
		printf(">> Malloc a new node fail!\n");
		return NULL;
	}
	node->filepath = filepath;
	node->scan_id = NULL;
	node->key = KEY[keyIndex];
	node->hash = NULL;
	node->key_index = keyIndex;
	node->response_code = 0;
	node->positive = -1;
	node->scan_num = 0;
	node->report_num = 0;
	node->prev = NULL;
	node->next = NULL;
	node->total_num = 0;
	node->id = 0;
	node->report_time = 0;
	node->scan_time = 0;
	node->execution_time = 0;
	node->http_response = 0;
	return node;
}

/*
  InitLinkedList: Create head node for an init list
  return a list pointer
 */
FileState* InitLinkedList(){
	FileState *head, *tail;
	CHAR head_imagepath[5] = "head";

	head = CreateNode(head_imagepath, 0);

	if (head != NULL){
		head->next = head;
		head->prev = head;
	}
	else{
		printf(">> Error: CreateNode (Head) fail!\n");
	}
	return head;
}
/*
  InsertNode: insert a node into specific list
  @list: specific list
  @node
  return void
*/
VOID InsertNode(FileState *list, FileState *node){

	FileState *head = list;
	FileState *lastnode = head->prev;

	head->total_num = head->total_num + 1;
	node->id = head->total_num;

	node->next = NULL;
	node->prev = lastnode;
	lastnode->next = node;
	head->prev = node;

}
/*
  DeleteNode: delete a node in the specific list
  @list: the specific list
  @node
  return void
*/
VOID DeleteNode(FileState *list, FileState *node){

	CHAR head_imagepath[] = "head";
	FileState* head = list;

	//It is the middle node in this list
	if (node->filepath != head_imagepath && node->next != NULL){
		FileState *prev_node = node->prev;
		FileState *next_node = node->next;
		prev_node->next = next_node;
		next_node->prev = prev_node;
	}
	//It is the last node in this list
	else if (node->filepath != head_imagepath && node->next == NULL){
		FileState *prev_node = node->prev;
		prev_node->next = NULL;
		head->prev = prev_node;
	}
	head->total_num = head->total_num - 1;
}
VOID cleanNode(FileState* target){

	target->hash = NULL;
	target->http_response = 0;
	target->id = 0;
	target->positive = -1;
	
}
/*
  PrintNode: Print the specific list
  @list
  return void

*/
VOID PrintNode(FileState *list){
	FileState *ptr = list;

	printf("Print linked list start--------------------------------\n");
	printf("total num %d\n", ptr->total_num);
	for (ptr = ptr->next; ptr != NULL; ptr = ptr->next){
		printf("%d, %s\n", ptr->id, ptr->filepath);
		printf("positive: %d\n", ptr->positive);
		printf("scan time / scan num: %d / %d = %f \n", ptr->scan_time, ptr->scan_num, (FLOAT)ptr->scan_time / ptr->scan_num);
		printf("report time / report num: %d / %d = %f \n\n", ptr->report_time, ptr->report_num, (FLOAT)ptr->report_time / ptr->report_num);

	}
	printf("Print linked list end --------------------------------\n");
}


/*
	ReleaseNode
	@node
*/
VOID ReleaseNode(FileState* node){
	free(node);
}

VOID getErrorMsg(DWORD error)
{
	
	switch (error){
		case ERROR_IO_PENDING:	
			printf(">> Overlapped I/O operation is in progress\n");
			break;
		default:
			printf(">> Get error msg: %d\n",error);
			break;
	}
}

/*
 DisconnectAndReconnect
 @i: Namedpipe index

 This function is called when an error occurs or when the client 
 closes its handle to the pipe. Disconnect from this client, then 
 call ConnectNamedPipe to wait for another client to connect. 
*/
VOID DisconnectAndReconnect(DWORD i)
{
		
	//printf(">> Disconnect pipe[%d]\n", i);

	// Disconnect the pipe instance. 
	if (!DisconnectNamedPipe(Pipe[i].hPipeInst)){
		//printf(">> DisconnectNamedPipe failed with %d.\n", GetLastError());
		getErrorMsg(GetLastError());
	}

	// Call a subroutine to connect to the new client. 	
	Pipe[i].fPendingIO = ConnectToNewClient(
		Pipe[i].hPipeInst,
		&Pipe[i].oOverlap);

	Pipe[i].dwState = Pipe[i].fPendingIO ?
		CONNECTING_STATE : // still connecting 
		READING_STATE;     // ready to read 
}
 
/*
 ConnectToNewClient(HANDLE, LPOVERLAPPED)
 This function is called to start an overlapped connect operation.
 It returns TRUE if an operation is pending or FALSE if the
 connection has been completed.
*/
BOOL ConnectToNewClient(HANDLE hPipe, LPOVERLAPPED lpo)
{
	BOOL fConnected, fPendingIO = FALSE;

	//printf(">> Connect to new client..\n");
	
	// Start an overlapped connection for this pipe instance. 
	fConnected = ConnectNamedPipe(hPipe, lpo);

	// Overlapped ConnectNamedPipe should return zero. 
	if (fConnected){
		//printf(">> ConnectNamedPipe failed with %d.\n", GetLastError());
		getErrorMsg(GetLastError());
		return 0;
	}

	switch (GetLastError()){
		// The overlapped connection in progress. 
		case ERROR_IO_PENDING:
			//printf(">> Error io pending and set fPendingio=true\n");
			fPendingIO = TRUE;
			break;

		// Client is already connected, so signal an event. 

		case ERROR_PIPE_CONNECTED:
			//printf(">> Error pipe connected and set event\n");
			if (SetEvent(lpo->hEvent))
				break;

		// If an error occurs during the connect operation... 
		default:
		{
			//printf(">> ConnectNamedPipe failed with %d.\n", GetLastError());
			getErrorMsg(GetLastError());
		
			return 0;
		}
	}

	return fPendingIO;
}

/*
  GetAnswerToRequest:put the message into pipeinst's reply buffer
  @pipe: the specific pipe
  @replyvalue: the value are going to send to client
  reutrn void
*/
VOID GetAnswerToRequest(LPPIPEINST pipe, INT replyvalue)
{
	
	pipe->reply = replyvalue;	
	pipe->cbToWrite = sizeof(INT);
}

/*
 transferTcharToChar: transfer tchar string to char string
 @input: tchar pointer points to a tchar string
 return char pointer points to a char string 
*/
CHAR* TransferTcharToChar(TCHAR* input)
{

	int input_size = wcslen(input);
	char *out = malloc(sizeof(CHAR) * input_size);
	wcstombs(out, input, input_size + 1);
	return out;
}

/* Progress_callback: ask the progress when scanning the file to VirusTotal*/
VOID Progress_callback(struct VtFile *file, void *data)
{
	int64_t dltotal = 0;
	int64_t dlnow = 0;
	int64_t ul_total = 0;
	int64_t ul_now = 0;
	VtFile_getProgress(file, &dltotal, &dlnow, &ul_total, &ul_now);
	printf(">> progress_callback %lld/%lld\n", (long long)ul_now, (long long)ul_total);
	//if (!keep_running)
	//	VtFile_cancelOperation(file);
}

/*
  getFileName: get file name from the originalpath and append "txt"
  @originalpath
  return a txt file name
*/
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
	//free(openfile);
	return 0;
}
/*
WriteDoneRecord: Write out a file's info to a file
@file : FileState obj
*/
VOID WriteDoneRecord(FileState* file)
{

	DWORD dwWaitResult;
	FILE *pFile = NULL;
	//CHAR openfile[] = "result.txt"; //result_chrome.txt
	char* filename = GetFileName(file->filepath);
	char* tmp = "result_";
	int length = strlen(filename) + strlen(tmp) + 1;
	char* openfile = (char*)malloc(sizeof(char)*length); //15
	memset(openfile, '\0', length);
	strncpy(openfile, tmp, strlen(tmp));
	strcat_s(openfile, length, filename);

	pFile = fopen(openfile, "a");
	if (pFile){
		// old output format:
		//		id > imagepath
		//		positive = .. 
		//		scan time .. / scan num .. = .. (ms)
		//		report time .. / report num .. = ..(ms)

		// new output format:
		//		(positive) (scan time)	(scan num) 	(report time)	(report num)	(execution time)		

		//-----------old output format starts from here----------------------------
		//fprintf(pFile, "%d", OuputCounter);
		//fprintf(pFile, "%s", "> ");		
		//fprintf(pFile, "%s", file->filepath);
		//fprintf(pFile, "%s", "\n");

		//fprintf(pFile, "%s", "positive = ");
		fprintf(pFile, "%d", file->positive);
		//fprintf(pFile, "%s", "\n");
		fprintf(pFile, "%s", "\t");
		//fprintf(pFile, "%s", "scan time: ");
		fprintf(pFile, "%d", file->scan_time);
		//fprintf(pFile, "%s", " / ");
		fprintf(pFile, "%s", "\t");
		//fprintf(pFile, "%s", "scan num: ");
		fprintf(pFile, "%d", file->scan_num);
		fprintf(pFile, "%s", "\t");
		//fprintf(pFile, "%f", (FLOAT)file->scan_time / file->scan_num);
		//fprintf(pFile, "%s", " (ms)");
		//fprintf(pFile, "%s", " \n");

		//fprintf(pFile, "%s", "report time: ");
		fprintf(pFile, "%d", file->report_time);
		fprintf(pFile, "%s", "\t");
		//fprintf(pFile, "%s", "report num: ");
		fprintf(pFile, "%d", file->report_num);
		fprintf(pFile, "%s", "\t");
		//fprintf(pFile, "%s", " = ");
		//fprintf(pFile, "%f", (FLOAT)file->report_time / file->report_num);
		//fprintf(pFile, "%s", " (ms)");
		//fprintf(pFile, "%s", " \n");

		//fprintf(pFile, "%s", "execution time: ");
		fprintf(pFile, "%d", file->execution_time);
		//fprintf(pFile, "%s", " (ms)");
		fprintf(pFile, "%s", "\n");

		fclose(pFile);
		OuputCounter++;
	}
	else{//if pFile fail
		printf("write_to file fail...\n");
		return -1;
	}
	free(openfile);
	return 0;
}

/*
	CheckForImagePath: if iamge path is \\??\\C:\Windows..., then filter out \\??\\
*/
CHAR* CheckForImagePath(CHAR* imagepath)
{
	CHAR *ret = NULL;
	CHAR str[] = "\\??\\";
	CHAR str2[] = "\\\\??\\";
	CHAR str3[] = "\\\\?\\";
	INT result = 0;


	if (strncmp(imagepath, str, strlen(str)) == 0){
		ret = strrchr(imagepath, '?');
		ret = ret + 2;
	}
	else if (strncmp(imagepath, str2, strlen(str2)) == 0){
		ret = strrchr(imagepath, '?');
		ret = ret + 2;
	}
	else if (strncmp(imagepath, str3, strlen(str3)) == 0){
		ret = strrchr(imagepath, '?');
		ret = ret + 2;
	}
	else
		ret = imagepath;

	return ret;
}

/*
	StringToLower: Converse to lower case
*/
CHAR* StringToLower(CHAR* str)
{
	CHAR* t = str;
	CHAR* result = NULL;
	INT i = 0;
	result = malloc(sizeof(CHAR)*strlen(str));
	while (*t != '\0'){
		if (*t >= 'A' && *t <= 'Z'){
			result[i] = tolower(*t);
		}
		else{
			result[i] = *t;
		}
		t++;
		i++;
	};
	result[i] = '\0';
	return result;
}

/*
  ScanFile: call VtFile_scan() to scan a file and get response from VirusTotal
  @vtFile: VtFile object
  @file: FileState object
  return 0 if file scan success and get scan_id, otherwise return -1 if error
*/
INT ScanFile(struct VtFile *vtFile, FileState* file){
	int ret;
	struct _stat stat_buf; //structure that store this file's state
	char *path = file->filepath;
	struct VtResponse *vtResponse = NULL;
	int response_code = 0;
	DWORD startScanRequest = timeGetTime();
	DWORD endScanRequest;

	//printf("ScanFile:%s\n", path);
	ret = _stat(path, &stat_buf); //get the file state in system and store in stat_buf

	if (ret != 0){
		perror(">> ScanFile: get file state error");
		switch (errno){
		case ENOENT:
			printf(">> ScanFile: file %ls not found\n", path);
			break;
		case EINVAL:
			printf(">> ScanFile: invalid parameters to _stat\n");
			break;
		default:
			printf(">> ScanFile: Unexpected error in _stat(%d)", errno);
		}
	}
	else{//read file state successfully		
		printf(">> File size is: %d\n", stat_buf.st_size);
		
		//printf("File path is : %s\n", path);
		//scan file
		if (stat_buf.st_size < (64 * 1024 * 1024)) {
			ret = VtFile_scan(vtFile, path, NULL);
			//printf("VtFile_scan return %d\n", ret);
		}
		else {
			ret = VtFile_scanBigFile(vtFile, path);
			printf("--------------------------------------------------------------------------------\n");
			printf(">> VtFile_scanBigFile ret =%d \n", ret);
			printf("--------------------------------------------------------------------------------\n");
		}
		
		//increase the scan number of this file
		file->scan_num++;

		//handle ret
		if (ret == 204){
			file->http_response = 204;
			ret = -1;
		}
		else if (ret == 403){
			file->http_response = 403;
			ret = -1;
		}
		else if (ret == 0){
			char* str = NULL;
			//printf("Already scan : %s\n", file->filepath);
			file->http_response = 200;

			//get response from vtFile
			vtResponse = VtFile_getResponse(vtFile);

			//get response_code
			ret = VtResponse_getIntValue(vtResponse, "response_code", &response_code);
			file->response_code = response_code;

			//output response to a file
			str = VtResponse_toJSONstr(vtResponse, VT_JSON_FLAG_INDENT);
			if (str) {
				//printf("Response:\n%s\n", str);
				WriteToFile(file->filepath, str);
				free(str);
			}

			// get scan_id
			if (response_code == 1){
				file->scan_id = VtResponse_getString(vtResponse, "scan_id");
				//printf("\nget scan_id %s \n", file->scan_id);

			}

		}
		else{ // VtScan return -1, means curl has some problem
			//printf("scan file error! \n");
			ret = -1;
		}
	}
	//calculate scan request time
	endScanRequest = timeGetTime();
	file->scan_time = file->scan_time + (endScanRequest - startScanRequest);
	
	VtResponse_put(&vtResponse);
	return ret;
}

/*
  ReportFile: get a file's report from VirusTotal using VtFile_report() with scan_id
  @vtFile: VtFile object
  @file: FileState object
  return 0 if get report successfully, otherwise get -1 if error
*/
INT ReportFile(struct VtFile *vtFile, FileState* file)
{
	//struct VtFile* vtFile = NULL;
	struct VtResponse* vtResponse = NULL;
	int ret = -1;
	int response_code = 0;
	int positive = -1;
	CHAR *str = NULL;
	CHAR buf[RESP_BUF_SIZE + 1] = { 0 };
	DWORD startReportRequest = timeGetTime();
	DWORD endReportRequest;

	//printf("ReportFiile...\n");

	ret = VtFile_report(vtFile, file->scan_id); //get report from VirusTotal
	
	if (ret == 204) {
		file->http_response = 204;
		ret = -1;
	}
	else if (ret == 403){
		file->http_response = 403;
		ret = -1;
	}
	else if (ret == -1){
		//printf("VtFile_report : SSL connect error\n");
		ret = -1;
	}
	else { //if ret 0
		file->http_response = 200;

		vtResponse = VtFile_getResponse(vtFile); //get response from file_scan structure														
		str = VtResponse_toJSONstr(vtResponse, VT_JSON_FLAG_INDENT); //transfer to string

		if (str) {
			//printf("Response:\n%s\n", str);
			WriteToFile(file->filepath, str);
			free(str);
		}

		//get message from VtResponse and print it
		VtResponse_getVerboseMsg(vtResponse, buf, RESP_BUF_SIZE);
		
		printf(">> Msg after report file: %s\n", buf);
		
		//get response_code
		ret = VtResponse_getResponseCode(vtResponse, &response_code);
		file->response_code = response_code;

		// get the report from VT successfully, and get positive value in vtResponse
		if (response_code == 1) {
			//get positives number in response
			ret = VtResponse_getIntValue(vtResponse, "positives", &positive);
			//printf("get positive %d\n", positive);
			file->positive = positive;

			file->hash = VtResponse_getString(vtResponse, "md5");
		}

		//positive = VtResponse_getString(response, "permalink");	

	}//end of else

	//finish getting report from VirusTotal, and calculate the time
	endReportRequest = timeGetTime();
	//printf("old report_time:%d\n", file->report_time);
	file->report_time = file->report_time + (endReportRequest - startReportRequest);
	//printf("new report_time:%d\n", file->report_time);
	file->report_num++;
	
	//recycle the response object	
	VtResponse_put(&vtResponse);
	return ret;
}

INT MoveObjToScanQueue(FileState* node)
{
	INT ret = 0;
	DWORD dwWaitResult = WaitForSingleObject(hMutex_request, INFINITE);

	switch (dwWaitResult){
	case WAIT_OBJECT_0:
		__try{
			InsertNode(ScanQueue, node);
		}
		__finally{
			//release ownership of the mutex object
			if (!ReleaseMutex(hMutex_request))
			{
				printf(">> Error: MoveObjToScanQueue: Release mutex_request error\n");
				ret = -1;
			}
		}
		break;
	case WAIT_ABANDONED:
		printf(">> Error: SendObjToScanQueue error: Wait abandoned\n");
		ret = -1;
		break;
	}
}


/*
   MoveObjToReportQueue: move obj from scan queue to report queue
   @node
   return 0 if success, otherwise return -1
*/
INT MoveObjToReportQueue(FileState* node)
{
	INT ret = 0;
	
	if (node->scan_id != NULL){
		InsertNode(ReportQueue, node);
	}
	else{
		printf(">>Error: MoveObjToReportQueue: There's no scan_id in this node\n");
		ret = -1;
	}
	return ret;
}

/*
  MoveObjToDoneQueue: move obj from report queue to done queue, process will wait at
  WaitForSingleObject() until it get access right of mutex of done queue
  @node
  return 0 if success, otherwise return -1
*/
INT MoveObjToDoneQueue(FileState* node)
{
	DWORD dwWaitResult;
	INT ret = 0;
	//printf("MoveObjToDoneQueue %s \n", node->filepath);

	// wait for report queue 's mutex
	dwWaitResult = WaitForSingleObject(hMutex_dq, INFINITE);
	switch (dwWaitResult)
	{
		//The thread got ownership of the mutex
	case WAIT_OBJECT_0:
		__try{
			if (node->positive != -1){
				InsertNode(DoneQueue, node);
			}
			else{
				printf(">> Error: MoveObjToDoneQueue: there's no positive in this node\n");
				ret = -1;
			}
		}
		__finally{
			//release ownership of the mutex object
			if (!ReleaseMutex(hMutex_dq)){
				printf(">> Error: MoveObjToDoneQueue: Release mutex_dq error\n");
				ret = -1;
			}
		}
		break;
	case WAIT_ABANDONED:
		printf(">> Error: SendObjToReportQueue error: Wait abandoned\n");
		ret = -1;
		break;
	}//end of switch
}
/*
	AssignKey: if scan file or report file throught an error(i.e, return -1), then change the key in FileState obj
	@file: FileState obj
	@state: previous operation's return state 
 */
VOID AssignKey(FileState* file, INT state)
{
	switch (state){
	case -1: //change to next key
		file->key_index = (INT)(file->key_index + 1) % MAX_NUMBERS_OF_KEY;
		if (file->key_index >= MAX_NUMBERS_OF_KEY)
			printf(">> AssignKey: key_index out of bound\n");
		else
			file->key = KEY[file->key_index];
		break;
	default:
		printf(">> AssignKey error\n");
		break;

	}//end of switch(state)
}
VOID convert_hex(unsigned char *md, unsigned char *mdstr)
{
	int i;
	int j = 0;
	unsigned int c;
	static const char hex_chars[] = "0123456789abcdef";

	for (i = 0; i < MD5_DIGEST_LENGTH; i++) {
		c = (md[i] >> 4) & 0x0f;
		mdstr[j++] = hex_chars[c];
		mdstr[j++] = hex_chars[md[i] & 0x0f];
	}
	mdstr[MD5_DIGEST_LENGTH * 2] = '\0';
}
/*
	Calculate image md5 value and compare to the hash value stored in target structure,
	if image md5 doesn't match the hash value, it means this file may be modified.
	Hence, this file will be sent to the VirusTotal to scan again later.
	
	@target: current image's FileState struct
	return 1 if md5 match, otherwise return 0
*/
INT CheckImageMd5(FileState* target)
{
	unsigned char origMd5[MD5_DIGEST_LENGTH]; //MD5_DIGEST_LENGTH = 16
	unsigned char md5InHex[MD5_DIGEST_LENGTH * 2 + 1]; //last byte is for '\0'
	char *filename = target->filepath;
	FILE *inFile = fopen(filename, "rb");
	MD5_CTX mdContext;
	unsigned char *dataFromFile = NULL;
	unsigned long filesize = 0;
	int i;

	//printf("check image md5\n");

	if (inFile == NULL){
		printf("%s can't be opened.\n", filename);
		printf("Error %d \n", errno);
		return 0;
	}

	MD5_Init(&mdContext);

	fseek(inFile, 0, SEEK_END);
	filesize = ftell(inFile);
	fseek(inFile, 0, SEEK_SET);

	dataFromFile = malloc(filesize*sizeof(char));
	if (dataFromFile == NULL){
		printf("allocate error\n");
		return 0;
	}

	while ((fread(dataFromFile, sizeof(char), filesize, inFile)) != 0){ //fread will return file size
		MD5_Update(&mdContext, dataFromFile, filesize);
	}

	MD5_Final(origMd5, &mdContext);

	/*for (i = 0; i < MD5_DIGEST_LENGTH; i++)
		printf("%02x", origMd5[i]);*/

	convert_hex(origMd5, md5InHex);
	fclose(inFile);

	if (strncmp(md5InHex, target->hash, MD5_DIGEST_LENGTH) == 0){
		printf("image match and md5 correct!!\n");
		return 1;
	}
	else{
		printf("oops, md5 mismatch!!\n");
		return 0;
	}
	
}
/*
TraverseScanQueue: traverse scan queue, if file's id >0 then call ScanFile() to scan this file.
Then receive response from VirusTotal and retrieve the response_code and scan_id inside response msg.
return void
*/
VOID TraverseScanQueue(){

	FileState  *file = ScanQueue;
	FileState  *next = NULL;
	int lengthOfSq = file->total_num; //scan queue's total object numbers
	int ret = -1;
	DWORD dwWaitResult;
	
	if (file->total_num > 0){
			file = file->next;	// the first node in the list is head
			
			do{
				struct VtFile  *vtFile = NULL;

				vtFile = VtFile_new(); //create a VtFile obj
				VtFile_setApiKey(vtFile, file->key);
				//VtFile_setProgressCallback(vtFile, Progress_callback, NULL);

				//if the file is not scan before, and it is not head node,too
				//then call VtScan() 
				if (file->id > 0){
					//return 0 if get response code success, otherwise return -1
					ret = ScanFile(vtFile, file);
					TotalRequest++;

					if (ret != 0){
							if (file->http_response == 204) {
								printf(">> Error: Exceed the public API request rate limit! scan_time %d / scan_num %d\n", file->scan_time, file->scan_num);
							}else if (file->http_response == 403) {
								printf(">> Error: Do not have the required privilege\n");
							} else {/* if scan file error, then change another key */
								printf(">> Error: Scan file error! (%d times %d) %s\n", file->scan_num, TotalRequest, file->filepath);
							}	

							file->scan_time += SCAN_PAUSE;						
							file = file->next;

					} 
					else { // get response_code successfully
							if (file->response_code == 1){
								printf(">> Scan Success and move file to ReportQueue!\n");
								next = file->next;									
								DeleteNode(ScanQueue, file);
								MoveObjToReportQueue(file);
								file = next;
							}
							else if (file->response_code == 0){
								printf(">> The item you searched for was not present in VirusTotal's dataset!\n");
								next = file->next;									
								DeleteNode(ScanQueue, file);
								MoveObjToDoneQueue(file);
								file = next;
							}
							else if (file->response_code == -2){
								printf(">> Queued for analysis! (%d times %d) %s\n", file->scan_num, TotalRequest,file->filepath);
								file->scan_time += SCAN_PAUSE;								
								file = file->next;
							}
					}

				}//end of if(file->id >= 0)

				//release vtResponse and vtFile obj			
				VtFile_put(&vtFile);
						
		} while (file != NULL);//end of do
					
	}//end of if(file->total_num > 0)			
				
}

/*
TraverseReportQueue: traverse report queue, if file's positive < 0 then call ReportFile() 
to get the positive value of this file.
return void
*/
VOID TraverseReportQueue()
{
	
	FileState *file = ReportQueue;
	FileState *next = NULL;
	int positive;
	char *str = NULL;
	int ret = -1;
	DWORD dwWaitResult;
	
	
	if (file->total_num > 0){
			printf(">>>total_num inreport queue  %d\n", file->total_num);
			file = file->next;
				
			do{

				struct VtFile *vtFile;

				vtFile = VtFile_new();					
				VtFile_setApiKey(vtFile, file->key);

				// if file's positive is negative, then call ReportFile() to get report
				if (file->positive < 0){

					//return 0 if get positve successfully, otherwise return -1
					ret = ReportFile(vtFile, file);
					TotalRequest++;

					if (ret != 0){
						if (file->http_response == 204){
							printf(">> Error: Exceed the public API request rate limit! report_time %d / report_num %d\n", file->report_time, file->report_num);
						}
						else if (file->http_response == 403){
							printf(">> Error: Do not have the required privilege\n");
						}
						else {
							printf(">> Error: report file error!key:%d (%d times %d) %s \n", file->key_index, TotalRequest, file->report_num, file->filepath);
							printf("scan id = %s\n", file->scan_id);
						}					
						file->report_time += REPORT_PAUSE;							
						file = file->next;
					}
					else{ // get response_code successfully
						if (file->response_code == 1){
							printf(">> Scan Success and move file to DoneQueue!\n");
							next = file->next;
							DeleteNode(ReportQueue, file);
							MoveObjToDoneQueue(file);
							file = next;
						}
						else if (file->response_code == 0){

							printf(">> The item you searched for was not present in VirusTotal's dataset!\n");
							next = file->next;
							DeleteNode(ScanQueue, file);
							MoveObjToDoneQueue(file);
							file = next;
						}
						else if (file->response_code == -2){
							//printf(">> Queued for analysis!(%d times %d) %s\n", file->report_num, TotalRequest,file->filepath);
							printf(">> Queued for analysis!(%d times) %s\n", file->report_num,  file->filepath);
							file->report_time += REPORT_PAUSE;								
							file = file->next;
						}
					}

				}// end if(file->positive < 0)

				//release vtFile obj	
				VtFile_put(&vtFile);
					
		} while (file != NULL); // end of do
	}//end of if(file->total_num > 0)					
}
/*
TraverseDoneQueue: traverse done queue to get the target file's result after scanning on 
VirusTotal.
@filepath: imagepath that want to find
@target: as an output structure, the FileState object that points to the matching imagepath
return 0 if there's no such file in DoneQueue
       1 if the file has been in the DoneQueue and md5 value has changed
	   positives if the file has been in the DoneQueue and md5 value has no changed
*/
INT TraverseDoneQueue(CHAR* filepath, FileState* currentfile)
{
	FileState* file = DoneQueue;
	FileState *target;
	INT ret = -1;
	DWORD dwWaitResult;
	
	
	currentfile->filepath = (char*)malloc(strlen(filepath)+1);
	memset(currentfile->filepath, '\0', strlen(filepath) + 1);
	strcpy_s(currentfile->filepath, strlen(filepath)+1, filepath);
	//printf("%s\n", currentfile->filepath);

	//search this file in DoneQueue first
	dwWaitResult = WaitForSingleObject(hMutex_dq, INFINITE);
	switch (dwWaitResult){
		//The thread got ownership of the mutex
		case WAIT_OBJECT_0:
			__try {
				if (file->total_num > 0){				
					file = file->next; 
					while (file!=NULL){
						int same = strcmp(filepath, file->filepath);
						//the targeted file is in DoneQueue
						if (same == 0 && (file->positive != -1)) { 																							
							target = file;
							ret = target->positive;
							file = NULL; // find the file and stop the loop
																												
							//if the file had been scanned before
							if (target->hash != NULL){
								int match = CheckImageMd5(target);
								int sizeofHash = strlen(target->hash) + 1;
								currentfile->hash = (char*)malloc(sizeofHash);
								memset(currentfile->hash, '\0', sizeofHash);
								strcpy_s(currentfile->hash, sizeofHash, target->hash);

								if (!match){ //md5 does not match, means this file need to rescan
									DeleteNode(DoneQueue, target);
									cleanNode(target);
									MoveObjToScanQueue(target);
									ret = -2;			
								}									
							}
							else{
								currentfile->hash = NULL;
							}
							currentfile->id = target->id;
							currentfile->positive = target->positive;
							currentfile->scan_num = target->scan_num;
							currentfile->scan_time = target->scan_time;
							currentfile->report_num = target->report_num;
							currentfile->report_time = target->report_time;
													
						}
						else{
							file = file->next;
						}
					};
				}//end of if(file->total_num >= 0)
			}
			__finally{
				//release ownership of the mutex object
				if (!ReleaseMutex(hMutex_dq))
					printf(">> Release mutex_rq error\n");
			}
			break;
		case WAIT_ABANDONED:
			printf(">> Report mutex error: Wait abandoned\n");
			break;
	}//end of switch
	
	return ret;
}



/*
Thread1
1.create namedpipe and communicate with kernel driver
2. get ImagePath
3. create new FileState obj and insert into ScanningQueue

*/
DWORD WINAPI Thread_ReceiveImagePath(LPVOID lpParam)
{
	DWORD i, dwWait, cbRet, dwErr, dwWaitResult;
	BOOL fSuccess;
	LPTSTR lpszPipename = TEXT("\\\\.\\pipe\\mynamedpipe");
	HANDLE hHeap = GetProcessHeap();
	CHAR* imagepath = NULL;
	BOOL fileExist = FALSE; 
	BOOL fileModified = FALSE;
	INT positive = -1;
	INT reply = 0;
	CHAR userReply;
	INT ki=0;
	INT ret=0;
	FileState *CurrentFile = NULL;
	DWORD start_execution_time = 0;
	DWORD end_execution_time = 0;
	int sleepcounter = 0;
	/*-----------------------creates several instances of a named pipe------------------------------------------------*/
	//printf("Thread_ReceiveImagePath running...\n");

	// lpParam not used here, so called this function to avoid warnings
	UNREFERENCED_PARAMETER(lpParam);
	CurrentFile = (FileState*) malloc(sizeof(FileState));
	
	for (i = 0; i < INSTANCES; i++){
		// Create an event object for this instance. 
		hEvents[i] = CreateEvent(
			NULL,    // default security attribute 
			TRUE,    // manual-reset event 
			TRUE,    // initial state = signaled 
			NULL);   // unnamed event object 

		if (hEvents[i] == NULL){
			printf(">> Error: CreateEvent failed with %d.\n", GetLastError());
			getErrorMsg(GetLastError());
			return 0;
		}

		Pipe[i].oOverlap.hEvent = hEvents[i];

		Pipe[i].hPipeInst = CreateNamedPipe(
			lpszPipename,            // pipe name 
			PIPE_ACCESS_DUPLEX |     // read/write access 
			FILE_FLAG_OVERLAPPED,    // overlapped mode 
			PIPE_TYPE_MESSAGE |      // message-type pipe 
			PIPE_READMODE_MESSAGE |  // message-read mode 
			PIPE_WAIT,               // blocking mode 
			INSTANCES,               // number of instances 			    
			BUFSIZE,			     // output buffer size
			BUFSIZE,				 // input buffer size 
			PIPE_TIMEOUT,            // client time-out 
			NULL);                   // default security attributes 

		if (Pipe[i].hPipeInst == INVALID_HANDLE_VALUE){
			printf(">> Error: CreateNamedPipe failed\n");
			getErrorMsg(GetLastError());
			return 0;
		}

		// Call the subroutine to connect to the new client
		Pipe[i].fPendingIO = ConnectToNewClient(
			Pipe[i].hPipeInst,
			&Pipe[i].oOverlap);

		Pipe[i].dwState = Pipe[i].fPendingIO ?
			CONNECTING_STATE : // still connecting 
			READING_STATE;     // ready to read 

		//printf("Pipe[%d] fPendingIO: %d.\n", i, Pipe[i].fPendingIO);
	}
	while (1){
		//printf("----------------------WaitForMultipleObject---------------------\n");

		// Wait for the event object to be signaled, indicating 
		// completion of an overlapped read, write, or 
		// connect operation. 
		
		dwWait = WaitForMultipleObjects(
			INSTANCES,    // number of event objects 
			hEvents,      // array of event objects 
			FALSE,        // does not wait for all 
			INFINITE);    // waits indefinitely 

		// dwWait shows which pipe completed the operation.
		/* p.s dwWait is the index of the pipe */

		i = dwWait - WAIT_OBJECT_0;  // determines which pipe 
		if (i < 0 || i >(INSTANCES - 1)){
			printf(">> Error: Index out of range.\n");
			return 0;
		}

		// Get the result if the operation was pending. 
		//printf("Pipe[%d] fPendingIO: %d.\n", i, Pipe[i].fPendingIO);
		if (Pipe[i].fPendingIO){
			fSuccess = GetOverlappedResult(
				Pipe[i].hPipeInst, // handle to pipe 
				&Pipe[i].oOverlap, // OVERLAPPED structure 
				&cbRet,            // bytes transferred 
				FALSE);            // do not wait 

			switch (Pipe[i].dwState){
				// Pending connect operation 
				case CONNECTING_STATE:
					//printf("connection state\n");
					if (!fSuccess){
						getErrorMsg(GetLastError());
						//DisconnectAndReconnect(i);
						//return 0;
						continue;
					}
					Pipe[i].dwState = READING_STATE;
					break;

				// Pending read operation 
				case READING_STATE:
					//printf("reading state\n");				
					if (!fSuccess || cbRet == 0){
						DisconnectAndReconnect(i);
						continue;
					}
					else{
						/* when server write to client once or server write to client fail*/
						DisconnectAndReconnect(i);
						fileExist = FALSE;
						continue;
					}				
					Pipe[i].cbRead = cbRet;
					//_tprintf(TEXT("Reading from pipe %s\n"), Pipe[i].chRequest);
					Pipe[i].dwState = WRITING_STATE;
					break;

				// Pending write operation 
				case WRITING_STATE:
					//printf("writing state\n");
					//printf("cbRet %d , Pipe[i] %d\n", cbRet, Pipe[i].cbToWrite);
					if (!fSuccess || cbRet != Pipe[i].cbToWrite){
						DisconnectAndReconnect(i);
						continue;
					}
					//Pipe[i].dwState = READING_STATE;
					break;

				default:
					printf(">> Error: Invalid pipe state.\n");
					return 0;
			}//end of switch
		}//end of if

		// The pipe state determines which operation to do next. 

		switch (Pipe[i].dwState){
			// READING_STATE: 
			// The pipe instance is connected to the client 
			// and is ready to read a request from the client. 

			case READING_STATE:
				printf("2-reading state\n");
				fSuccess = ReadFile(
					Pipe[i].hPipeInst,
					Pipe[i].chRequest,
					BUFSIZE*sizeof(TCHAR),
					&Pipe[i].cbRead,
					&Pipe[i].oOverlap);
			
				// The read operation completed successfully. 
				if (fSuccess && Pipe[i].cbRead != 0){
					//_tprintf(TEXT("Reading from pipe %s\n"), Pipe[i].chRequest);

					FileState *node;
					CHAR *tempPath1, *tempPath2;
				
					tempPath1 = TransferTcharToChar(Pipe[i].chRequest);
					tempPath2 = CheckForImagePath(tempPath1);
					//printf("Transfer imagepath %s \n", imagepath);
				
					//calculate execution time 
					start_execution_time = timeGetTime();

					imagepath = StringToLower(tempPath2);
					sleepcounter = 0;
					//search if DoneQueue have this file already?
					ret = TraverseDoneQueue(imagepath, CurrentFile);
					switch (ret){					
						case -1: /* file doesn't exist in DoneQueue */
							fileExist = FALSE;
							fileModified = FALSE;
							printf("file do not exist and file is not modified\n");
							break;				
						case -2: /* file exist and md5 don't match */
							fileExist = TRUE;
							fileModified = TRUE;
							printf("file exist and file is modified\n");
							break;
						default: /* file exist and md5 match */
							fileExist = TRUE;
							fileModified = FALSE;
							printf("file exist and file is not modified\n");
							positive = ret;
							break;					
				}
				
				// special case imagepath
				// if imagepath isn't start with C:.. then print it
				if (strncmp(imagepath, "c:", strlen("c:"))){				
					printf(">> Special case %s\n", imagepath);				
					fileExist = TRUE;
					Pipe[i].fPendingIO = FALSE;
					Pipe[i].dwState = WRITING_STATE;
					continue;
				}

				if (!fileExist){
					node = CreateNode(imagepath, ki);
					ki++;
					if (ki == MAX_NUMBERS_OF_KEY)
						ki = ki % MAX_NUMBERS_OF_KEY;
					
					dwWaitResult = WaitForSingleObject(hMutex_request, INFINITE);
					switch (dwWaitResult){
						//The thread got ownership of the mutex
						case WAIT_OBJECT_0:
							__try{
								//add obj into sending queue							
								InsertNode(ScanQueue, node);
							}
							__finally{
								//release ownership of the mutex object
								if (!ReleaseMutex(hMutex_request))
									printf(">> Error: Release mutex_sq error\n");
							}
							break;
						case WAIT_ABANDONED:
							printf(">> Error: Thread_SendingImagePath: Wait abandoned\n");
							break;
					}//end of switch
					
				}//end of if(!fileExists)				

				Pipe[i].fPendingIO = FALSE;
				Pipe[i].dwState = WRITING_STATE;
				
				continue;
			}//end of if (fSuccess && Pipe[i].cbRead != 0)
			
			// The read operation is still pending. 
			dwErr = GetLastError();
			getErrorMsg(GetLastError());

			if (!fSuccess &&(dwErr == ERROR_IO_PENDING)){//readfile again
				Pipe[i].fPendingIO = TRUE;
				continue;
			}

			// An error occurred; disconnect from the client. 
			DisconnectAndReconnect(i);
			break;

			// WRITING_STATE: 
			// The request was successfully read from the client. 
			// Get the reply data and write it to the client. 

		case WRITING_STATE:
			printf("2-writing state\n");	
			
			while ((!fileExist && !fileModified) || (fileExist && fileModified) ){ //if the file is scanned first time, then keep traverse DoneQueue till the file has scanned over.
				Sleep(DONE_PAUSE);
				sleepcounter++;
				printf("sleep counter %d\n\n", sleepcounter);
				ret = TraverseDoneQueue(imagepath, CurrentFile);
				switch (ret){
					case -1: /* file doesn't exist in DoneQueue */
						fileExist = FALSE;
						fileModified = FALSE;
						//printf("file do not exist and file is not modified\n");
						break;
					case -2: /* file exist and md5 don't match */
						fileExist = TRUE;
						fileModified = TRUE;
						printf("file exist and file is modified\n");
						break;
					default: /* file exist and md5 match */
						fileExist = TRUE;
						fileModified = FALSE;
						positive = ret;
						printf("file  exist and file is not modified\n");
						break;
				}
			};
									
			//if at Reading State find that the file has already exist and md5 not changed, then set reply value here
			/*if (fileExist && !fileModified)
			{
				reply = (positive < THRESHOLD) ? 1 : 0;
			}*/

			// at Reading State find file doesn't exist, so keep traverse DoneQueue until
			// get a non-negative positive value
			//else if(!fileExist && (clock % 20) == 0)			
			
			//if fileExist=TRUE && fileModified=FALSE , then send reply to client
			if (fileExist && !fileModified){		
				reply = (positive < THRESHOLD) ? 1 : 0;

				

				//if the file is unsafe
				if (reply == 0){
					userReply = "";
					//tell the user that there's a file may be unsafe, and ask user to execute it or not?
					printf("==================================================================\n");
					printf("The file below may be unsafe!!\n %s\nStill want to execute it(y/n)?", imagepath);					
					scanf("%c", &userReply);
					if ((userReply == 'y'))
						reply = 1;
					else
						printf("userReply error -%c!!!\n",userReply);
				}	
				//caculate execution time and ouput CurrentFile info
				end_execution_time = timeGetTime();
				CurrentFile->execution_time = end_execution_time - start_execution_time;
				WriteDoneRecord(CurrentFile);

				GetAnswerToRequest(&Pipe[i], reply);
				fSuccess = WriteFile(
								Pipe[i].hPipeInst,
								//&Pipe[i].chReply,
								&Pipe[i].reply,
								Pipe[i].cbToWrite,
								&cbRet,
								&Pipe[i].oOverlap);

				

				// The write operation completed successfully. 
				if (fSuccess && cbRet == Pipe[i].cbToWrite){
					//now fileExists = 1;
					Sleep(DONE_PAUSE); //to avoid pipe disconnected before driver read the buffer
					Pipe[i].fPendingIO = TRUE;
					Pipe[i].dwState = READING_STATE;
					
					//DisconnectAndReconnect(i);
					continue;
				}
				// The write operation is still pending. 
				dwErr = GetLastError();
				getErrorMsg(dwErr);	

				if (!fSuccess && (dwErr == ERROR_IO_PENDING)){
					//now fileExists = 0;
					printf(">> Error: Write file failed, error io pending\n");
					Pipe[i].fPendingIO = TRUE;
					Pipe[i].dwState = READING_STATE;
					
					continue;
				}
				

				// An error occurred; disconnect from the client. 
				DisconnectAndReconnect(i);
				break;
			}
			break;
			
			//if file doesn't exists, then keep at Writing state and traverse done queue
		default:		
			printf(">>Error: Invalid pipe state.\n");
			return 0;
		
		}//end of switch
	}//end of while

}

DWORD WINAPI Thread_Scan(LPVOID lpParam)
{

	//printf("Thread_Scan running...\n");
	// lpParam not used here, so called this function to avoid warnings
	UNREFERENCED_PARAMETER(lpParam);

	DWORD dwWaitResult;
	FileState* file = ScanQueue;
	while (1){
		//wait until getting scanning queue's access right
		dwWaitResult = WaitForSingleObject(hMutex_request, INFINITE);
		switch (dwWaitResult){
			//The thread got ownership of the mutex
			case WAIT_OBJECT_0:
				__try{
					if (file->total_num > 0){					
						TraverseScanQueue();
						//printf("Scan all the files in ScanQueue already\n");
					}
				}
				__finally{
					//release ownership of the mutex object
					if (!ReleaseMutex(hMutex_request)){
						printf(">> Error: Release mutex_sq error\n");
					}
				}
				break;
			case WAIT_ABANDONED:
				printf(">> Error: Scan mutex : Wait abandoned\n");
				break;
		}//end of switch
		Sleep(SCAN_PAUSE);
	}
	return 0;
}
DWORD WINAPI Thread_Report(LPVOID lpParam)
{
	DWORD dwWaitResult;
	//printf("Thread_Report running...\n");
	FileState* file = ReportQueue;

	// lpParam not used here, so called this function to avoid warnings
	UNREFERENCED_PARAMETER(lpParam);

	while (1){
		Sleep(REPORT_PAUSE);
		dwWaitResult = WaitForSingleObject(hMutex_request, INFINITE);
		switch (dwWaitResult)
		{
			//The thread got ownership of the mutex
			case WAIT_OBJECT_0:
				__try{
					if (file->total_num > 0){
						TraverseReportQueue();
						//printf("Report all the files in ReportQueue already\n");
					}
					else{
						//printf("No file in Report Queue!\n");
					}
				}
				__finally{
					//release ownership of the mutex object
					if (!ReleaseMutex(hMutex_request)){
						printf(">>Error: Release mutex_rq error\n");
					}
				}
				break;
			case WAIT_ABANDONED:
				printf(">>Error: Report mutex error: Wait abandoned\n");
				break;
		}//end of switch		
	}
	return 0;
}



int main(int argc, char* argv[]){

	DWORD idThread_ReceiveImagePath = 0;
	DWORD idThread_Scan = 1;
	DWORD idThread_Report = 2;
	INT i = 0;

	/* Variables which be used to get ZwCreateUserProcess native api's entry */
	ZwCreateUserProcessPrototype zwCreateUserProcessStruct;
	PVOID info;
	UINT32 index;
	HMODULE module = LoadLibrary(_T("ntdll.dll")); /* load the ntdll.dll */
	HANDLE hdevice;
	PULONG api_address;
	LPCWSTR driver_name = L"\\\\.\\SSDT_getImagePath";
	char readBuffer[50] = { 2 };
	DWORD dwBytesRead = 0;
	//int restore_check = 1;
	//MSG msg;
	
	/* ---------------------------initialize ScanQueue, ReportQueue, DoneQueue ------------------------------------------*/
	ScanQueue = InitLinkedList();
	if (ScanQueue == NULL){
		printf(">> InitLinkedList error : ScanQueue \n");
		return -1;
	}

	ReportQueue = InitLinkedList();
	if (ReportQueue == NULL){
		printf(">> InitLinkedList error : ReportQueue \n");
		return -1;
	}

	DoneQueue = InitLinkedList();
	if (DoneQueue == NULL){
		printf(">> InitLinkedList error : DoneQueue \n");
		return -1;
	}

	/*-----------------------------------------phase 1--------------------------------------------------------------*/
	printf(">> SSDT Hooker...\n");

	/*get the ZwCreateUserProcess syscall address from ntdll.dll*/
	zwCreateUserProcessStruct = (ZwCreateUserProcessPrototype)GetProcAddress(module, "ZwCreateUserProcess");
	if (zwCreateUserProcessStruct == NULL){
		printf(">> Error: could not find the function NtCreateUserProcess in library ntdll.dll");
		exit(-1);
	}

	printf(">> ZwCreateUserProcess is located at 0x%x (0x%x) in ntdll.dll \n", (PULONG)zwCreateUserProcessStruct, *zwCreateUserProcessStruct);
	
	/* api_address is a pointer which points to syscall ZwCreateUserProcess*/
	api_address = (ULONG)&zwCreateUserProcessStruct;
	printf(">> api_address is %x at %x\n", api_address, &api_address);

	/* CreateFile to kernel driver and get a handle*/
	hdevice = CreateFile(driver_name, GENERIC_WRITE | GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hdevice == INVALID_HANDLE_VALUE){
		DWORD err = GetLastError();
		printf(">> Error: invalid handle value, error code=%x\n", err);
		getErrorMsg(GetLastError());
	}
	else
		//printf("Handle: %p\n", hdevice);

	/*use ioctl to send api_address to kernel driver and get response from readBuffer*/
	DeviceIoControl(hdevice, IOCTL_GETADDRESS, api_address, strlen(api_address), readBuffer, sizeof(readBuffer), &dwBytesRead, NULL);
	
	//printf("Message received from kernel: %s\n", readBuffer);
	//printf("Bytes read: %d\n", dwBytesRead);
	
	CloseHandle(hdevice);

	/*------------------------------------------phase 2 -------------------------------------------------*/
	
	printf(">> ImageHandler...\n");

	/* create mutex with no owner */	

	hMutex_dq = CreateMutex(NULL, FALSE, "mutex_dq");
	if (hMutex_dq == NULL){
		printf(">> CreateMutex error (hMutex_dq): %d\n", GetLastError());
		getErrorMsg(GetLastError());
		return -1;
	}
	hMutex_request = CreateMutex(NULL, FALSE, "mutex_rq");
	if (hMutex_request == NULL){
		printf(">> CreateMutex error (hMutex_request): %d\n", GetLastError());
		getErrorMsg(GetLastError());
		return -1;
	}

	/* create thread to receive from data from pipe */
	hThread[0] = CreateThread(NULL, 0, Thread_ReceiveImagePath, NULL, 0, &idThread_ReceiveImagePath);

	if (hThread[0] == NULL){
		printf(">> Create Thread_ReceiveImagePath Failed, %d\n", GetLastError());
		getErrorMsg(GetLastError());
		return -1;
	}

	/* create thread to  send scan request to VirusTotal */
	hThread[1] = CreateThread(NULL, 0, Thread_Scan, NULL, 0, &idThread_Scan);

	if (hThread[1] == NULL){
		printf(">> Create Thread_Scan Failed, %d\n", GetLastError());
		getErrorMsg(GetLastError());
		return -1;
	}

	/* create thread to  send report request to VirusTotal */
	hThread[2] = CreateThread(NULL, 0, Thread_Report, NULL, 0, &idThread_Report);

	if (hThread[2] == NULL){
		printf(">> Create Thread_Report Failed, %d\n", GetLastError());
		getErrorMsg(GetLastError());
		return -1;
	}


	//Wait for all threads to terminate
	WaitForMultipleObjects(THREADCOUNT, hThread, TRUE, INFINITE);

	for (i = 0; i < THREADCOUNT; i++)
		CloseHandle(hThread[i]);

	CloseHandle(hMutex_dq);
	CloseHandle(hMutex_request);

	system("pause");
	return 0;
}


