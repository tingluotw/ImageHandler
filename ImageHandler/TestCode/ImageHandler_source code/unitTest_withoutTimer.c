#include <stdio.h>

#include <windows.h>
#include <winternl.h>
#include <tchar.h>
#include <strsafe.h>
#include <sys/stat.h>
#include <jansson.h>
#include <errno.h>
#include <string.h>
#include <Mmsystem.h>

#include "VtFile.h"
#include "VtResponse.h"

#define CONNECTING_STATE 0 
#define READING_STATE 1 
#define WRITING_STATE 2 

/* buffer size inside a pipe */
#define BUFSIZE 1024
#define THREADCOUNT 3

#define ID_SCANTIMER 1
#define ID_REPORTTIMER 2
#define INTERVAL_SCANTIMER 20000
#define INTERVAL_REPORTTIMER 5000
#define MAX_LENGTH_OF_APIKEY 100
#define RESP_BUF_SIZE 255
#define KEY "18d3ac54fcd0e6329ae52c9afba4bbac7de3dd9af5aa7262f9855bb404e1eacb"
#define THRESHOLD 54*1/3
#define REQUEST_PAUSE 3000
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

typedef struct fileState {
	CHAR *filepath;
	CHAR *scan_id;      //id of scanned file on VirusTotal
	int response_code;	//status after scanning a file on VirusTotal
	int positive;		//result from report on VirusTotal
	int scan_num;		//how many times to scan this file
	int report_num;		//how many times to get the report of this file
	int total_num;		//how many obj are in this list
	int id;				//node id
	DWORD report_time;
	DWORD scan_time;
	int http_response;
	struct FileState *prev;
	struct FileState *next;
}FileState;

struct FileState* ScanQueue = NULL;
struct FileState* ReportQueue = NULL;
struct FileState* DoneQueue = NULL;


HANDLE hThread[THREADCOUNT];

HANDLE hMutex_sq = NULL; //mutex's handle of scan queue
HANDLE hMutex_rq = NULL; //mutex's handle of report queue
HANDLE hMutex_dq = NULL; //mutex's handle of done queue

HANDLE htest;
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
FileState*  CreateNode(CHAR* filepath)
{
	FileState *node = malloc(sizeof(FileState));
	if (!node){
		printf("malloc a new node fail!\n");
		return NULL;
	}
	node->filepath = filepath;
	node->scan_id = NULL;
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
	return node;
}

/*
InitLinkedList: Create head node for an init list
return a list pointer
*/
FileState* InitLinkedList(){
	FileState *head, *tail;
	CHAR head_imagepath[5] = "head";

	head = CreateNode(head_imagepath);

	if (head != NULL)
	{
		head->next = head;
		head->prev = head;
	}
	else
	{
		printf("ImageHandler_CreateNode (Head) fail!\n");
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
	if (node->filepath != head_imagepath && node->next != NULL)
	{
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
		printf("%d ,%s\n", ptr->id, ptr->filepath);
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

/*
transferTcharToChar: transfer tchar string to char string
@input: tchar pointer points to a tchar string
return char pointer points to a char string
*/
char* TransferTcharToChar(TCHAR* input)
{

	int input_size = wcslen(input);
	char *out = malloc(sizeof(CHAR) * input_size);
	wcstombs(out, input, input_size + 1);
	return out;
}

VOID Progress_callback(struct VtFile *file, void *data)
{
	int64_t dltotal = 0;
	int64_t dlnow = 0;
	int64_t ul_total = 0;
	int64_t ul_now = 0;
	VtFile_getProgress(file, &dltotal, &dlnow, &ul_total, &ul_now);
	printf("progress_callback %lld/%lld\n", (long long)ul_now, (long long)ul_total);
	//if (!keep_running)
	//	VtFile_cancelOperation(file);
}

/*
getFileName: get file name from the originalpath and append "txt"
@originalpath
return a txt file name
*/
char* GetFileName(char* originalpath)
{
	char* out1;
	char* out2;
	char* out3;
	char out4[] = ".txt";
	int length = 0;
	//char head[] = "C:/ImageHandler/"; //..\\ImageHandler\\ also fail

	/*origialpath will have \\ because of escape symbol
	but if I print out this originalpath the escape symbol will remove automatically
	ex: originalpath = hello\\my.exe*/
	
	out1 = strrchr(originalpath, '\\'); //must use escape symbol, out1=\\me.exe
	out2 = strrchr(originalpath, '.'); //cannot use double quote, out2=.exe

	out1++; //get rid of escape symbol, out1 = me.exe
	length = strlen(out1) - strlen(out2) + strlen(out4); 
	out3 = malloc(sizeof(CHAR) * length);
	memset(out3, '\0', sizeof(CHAR) * length);
	//strncpy(out3, head, strlen(head));
	strncpy(out3, out1, strlen(out1) - strlen(out2)); // so need to +1 at length to contain '.', out3=me.
	strncat(out3, out4, strlen(out4));//out = me.txt
	
	return out3;
}

CHAR* CheckForImagePath(CHAR* imagepath)
{
	CHAR *ret = NULL;
	CHAR str[] = "\\??\\";
	INT result = 0;

	result = strncmp(imagepath, str, strlen(str));
	if (result == 0)
	{
		ret = strrchr(imagepath, '?');
		ret = ret + 2;
	}
	else{
		ret = imagepath;
	}
	return ret;
}

/*
WriteToFile: write to a specific txt file
@imagepath
@inputStr: input string
return -1 if fail, otherwise return 0
*/
int WriteToFile(char* imagepath, char* inputStr){
	FILE *pFile = NULL;
	// extract appropriate file name from imagepath, ex: xxx.txt
	char* openfile = GetFileName(imagepath);
	printf("write_to file %s\n",openfile);
	pFile = fopen(openfile, "w");
	if (pFile){
		fputs(inputStr, pFile);
		fclose(pFile);
	}
	else{
		printf("write_to file fail...\n");
		return -1;
	}

	return 0;
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

	printf("ScanFile:%s\n", path);
	ret = _stat(path, &stat_buf); //get the file state in system and store in stat_buf

	if (ret != 0)
	{
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
	else //read file state successfully
	{
		printf("File size is: %d\n", stat_buf.st_size);
		//printf("File path is : %s\n", path);
		//scan file
		if (stat_buf.st_size < (64 * 1024 * 1024)) {
			ret = VtFile_scan(vtFile, path, NULL);
			//printf("VtFile_scan return %d\n", ret);
		}
		else {
			ret = VtFile_scanBigFile(vtFile, path);
			printf(" VtFile_scanBigFile ret =%d \n", ret);
		}
		//calculate scan request time
		endScanRequest = timeGetTime();
		file->scan_time = file->scan_time + (endScanRequest - startScanRequest);

		file->scan_num++;

		//handle ret
		if (ret == 204)
		{
			file->http_response = 204;
			ret = -1;
		}
		else if (ret == 403)
		{
			file->http_response = 403;
			ret = -1;
		}	
		else if(ret == 0)
		{
			char* str = NULL; 
			printf("Already scan : %s\n", file->filepath);
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
			if (response_code == 1) 
			{
				file->scan_id = VtResponse_getString(vtResponse, "scan_id");
				printf("\nget scan_id %s \n", file->scan_id);
			
			}
			
		}
		else
		{
			printf("scan file error! \n");
			ret = -1;
		}
	}

	
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
	CHAR buf[RESP_BUF_SIZE + 1] = { 0, };
	DWORD startReportRequest= timeGetTime();
	DWORD endReportRequest;

	printf("ReportFiile...\n");
	
	ret = VtFile_report(vtFile, file->scan_id); //get report from VirusTotal
	

	//finish getting report from VirusTotal, and calculate the time
	endReportRequest = timeGetTime();
	//printf("old report_time:%d\n", file->report_time);
	file->report_time = file->report_time + (endReportRequest - startReportRequest);
	//printf("new report_time:%d\n", file->report_time);
	file->report_num++;

	if (ret == 204) {
		file->http_response = 204;
		ret = -1;
	}
	else if (ret == 403){
		file->http_response = 403;
		ret = -1;
	}
	else if (ret == -1){
		printf("ssl connect error\n");
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
		printf("Msg after report file: %s\n", buf);

		//get response_code
		ret = VtResponse_getResponseCode(vtResponse, &response_code);
		file->response_code = response_code;

		// get the report from VT successfully, and get positive value in vtResponse
		if (response_code == 1) {
			//get positives number in response
			ret = VtResponse_getIntValue(vtResponse, "positives", &positive);
			printf("get positive %d\n", positive);
			file->positive = positive;
		}
		

		//positive = VtResponse_getString(response, "permalink");	
		
	}//end of else

	//recycle the response object	
	VtResponse_put(&vtResponse);
	return ret;
}
/*
MoveObjToReportQueue: move obj from scan queue to report queue, process will wait at
WaitForSingleObject() until it get access right of mutex of report queue
@node
return 0 if success, otherwise return -1
*/
INT MoveObjToReportQueue(FileState* node)
{
	DWORD dwWaitResult;
	INT ret = 0;
	// wait for report queue 's mutex
	dwWaitResult = WaitForSingleObject(hMutex_rq, INFINITE);
	switch (dwWaitResult)
	{
		//The thread got ownership of the mutex
	case WAIT_OBJECT_0:
		__try{
			if (node->scan_id != NULL)
			{
				InsertNode(ReportQueue, node);
			}
			else{
				printf("MoveObjToReportQueue error: there's no scan_id in this node\n");
				ret = -1;
			}
		}
		__finally{
			//release ownership of the mutex object
			if (!ReleaseMutex(hMutex_rq))
			{
				printf("MoveObjToReportQueue error: Release mutex_rq error\n");
				ret = -1;
			}
		}
		break;
	case WAIT_ABANDONED:
		printf("MoveObjToReportQueue error: Wait abandoned\n");
		ret = -1;
		break;
	}//end of switch

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

	// wait for report queue 's mutex
	dwWaitResult = WaitForSingleObject(hMutex_dq, INFINITE);
	switch (dwWaitResult)
	{
		//The thread got ownership of the mutex
	case WAIT_OBJECT_0:
		__try{
			if (node->positive != -1)
			{
				InsertNode(DoneQueue, node);

			}
			else{
				printf("MoveObjToDoneQueue error: there's no positive in this node\n");
				ret = -1;
			}
		}
		__finally{
			//release ownership of the mutex object
			if (!ReleaseMutex(hMutex_dq))
			{
				printf("MoveObjToDoneQueue error: Release mutex_dq error\n");
				ret = -1;
			}
		}
		break;
	case WAIT_ABANDONED:
		printf("sendObjToReportQueue error: Wait abandoned\n");
		ret = -1;
		break;
	}//end of switch
}

/*
TraverseScanQueue: traverse scan queue, if file's id >0 then call ScanFile() to scan this file.
Then receive response from VirusTotal and retrieve the response_code and scan_id inside response msg.
return void
*/
VOID TraverseScanQueue(){

	FileState  *file = ScanQueue;
	int lengthOfSq = file->total_num; //scan queue's total object numbers
	int ret = -1;

	printf("Traverse ScanQueue\n");
	if (file->total_num > 0)
	{
		//printf("Having file in ScanQueue\n");
		// the first node in the list is head
		for (file = file->next; file != NULL; file = file->next)
		{
			struct VtFile  *vtFile = NULL;
			
			vtFile = VtFile_new(); //create a VtFile obj
			VtFile_setProgressCallback(vtFile, Progress_callback, NULL);
			VtFile_setApiKey(vtFile, KEY);

			//if the file is not scan before, and it is not head node,too
			//then call VtScan() to send it to scan
			if (file->id > 0)
			{
				//return 0 if get response code success, otherwise return -1
				ret = ScanFile(vtFile, file);	
				
				if (ret != 0)
				{
					if (file->http_response == 204)
					{
						printf("Exceed the public API request rate limit! scan_time %d / scan_num %d\n", file->scan_time, file->scan_num);
						Sleep(REQUEST_PAUSE);
					}
					else if (file->http_response == 403)
					{
						printf("Do not have the required privilege\n");
					}
					else {
						printf("Scan file error!\n");
					}
					
				}
				else{ // get response_code successfully
					if (file->response_code == 1)
					{
						printf("Scan Success and move file to ReportQueue!\n");
						DeleteNode(ScanQueue, file);
						MoveObjToReportQueue(file);
					}
					else if (file->response_code == 0)
					{
						printf("The item you searched for was not present in VirusTotal's dataset!\n");
						DeleteNode(ScanQueue, file);
						MoveObjToDoneQueue(file);
					}
					else if (file->response_code == -2)
					{
						printf("The requested item is still queued for analysis!\n");
					}
				}
																									
			}//end of if(file->id >= 0)

			//release vtResponse and vtFile obj			
			VtFile_put(&vtFile);

			Sleep(REQUEST_PAUSE);
		}//end of for
	}//end of if(file->total_num > 0)

}

/*
TraverseReportQueue: traverse report queue, if file's positive<0 then call ReportFile()
to get the positive value of this file.
return void
*/
VOID TraverseReportQueue()
{
	printf("TraverseReportQueue\n");
	FileState *file = ReportQueue;
	
	int positive;
	char *str = NULL;
	int ret = -1;

	if (file->total_num > 0)
	{
		for (file = file->next; file != NULL; file = file->next)
		{
			
			struct VtFile *vtFile;

			vtFile = VtFile_new();
			//VtFile_setProgressCallback(vtFile, Progress_callback, NULL);
			VtFile_setApiKey(vtFile, KEY);

			// if file's positive is negative, then call ReportFile() to get report
			if (file->positive < 0)
			{
				//return 0 if get positve successfully, otherwise return -1
				ret = ReportFile(vtFile, file);

				if (ret != 0)
				{
					if (file->http_response == 204)
					{
						printf("Exceed the public API request rate limit! report_time %d / report_num %d\n", file->report_time, file->report_num);
						Sleep(REQUEST_PAUSE);
					}
					else if (file->http_response == 403)
					{
						printf("Do not have the required privilege\n");
					}
					else {
						printf("scan file error!\n");
					}

				}
				else{ // get response_code successfully
					if (file->response_code == 1)
					{
						printf("Scan Success and move file to DoneQueue!\n");
						DeleteNode(ReportQueue, file);
						MoveObjToDoneQueue(file);
					}
					else if (file->response_code == 0)
					{
						printf("The item you searched for was not present in VirusTotal's dataset!\n");
						DeleteNode(ScanQueue, file);
						MoveObjToDoneQueue(file);
					}
					else if (file->response_code == -2)
					{
						printf("The requested item is still queued for analysis!\n");
					}
				}
				
			}// end if(file->positive < 0)
			
			//release vtFile obj	
			VtFile_put(&vtFile);
			
			Sleep(REQUEST_PAUSE);
		}// end of for
	}//end of if(file->total_num > 0)

}

/*
TraverseDoneQueue: traverse done queue to get the target file's result after scanning on
VirusTotal.
@target: FileState object
return positive value of the file or -1 if error
*/
INT TraverseDoneQueue(CHAR* target)
{
	FileState* file = DoneQueue;
	INT ret = -1;
	DWORD dwWaitResult;

	printf("Traverse DoneQueue\n");

	//search this file in DoneQueue first
	dwWaitResult = WaitForSingleObject(hMutex_dq, INFINITE);
	switch (dwWaitResult)
	{
		//The thread got ownership of the mutex
	case WAIT_OBJECT_0:
		__try{
			if (file->total_num > 0)
			{
				//printf("Having file in DoneQueue\n");
				for (file = file->next; file!= NULL; file = file->next)
				{
					int same = strcmp(target, file->filepath);
					if (same == 0 && (file->positive != -1))
						return file->positive;
				}
				printf("No matching filepath in file\n");
			}//end of if(file->total_num >= 0)
		}
		__finally{
			//release ownership of the mutex object
			if (!ReleaseMutex(hMutex_dq))
				printf("Release mutex_rq error\n");
		}
		break;
	case WAIT_ABANDONED:
		printf("ReportTimer error: Wait abandoned\n");
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
	DWORD i = 0, dwWait, cbRet, dwErr, dwWaitResult;
	BOOL fSuccess;
	LPTSTR lpszPipename = TEXT("\\\\.\\pipe\\mynamedpipe");
	HANDLE hHeap = GetProcessHeap();

	INT state = READING_STATE;
	//TCHAR* src[3] = { L"C:\\Windows\\System32\\StickyNot.exe", L"C:\\Windows\\system32\\mspaint.exe", L"C:\\Windows\\system32\\msra.exe"};
	TCHAR *src[5] = { NULL };
	INT positive = 0;
	BOOL fileExist = FALSE;
	CHAR* imagepath = NULL;
	INT clock = 0;
	INT index = 0;
	TCHAR* imagepath1 = NULL;
	/*-----------------------creates several instances of a named pipe------------------------------------------------*/
	printf("Thread_ReceiveImagePath running...\n");
	src[0] = L"C:\\Windows\\System32\\notepad.exe";
	src[1] = L"C:\\Windows\\system32\\mspaint.exe";
	src[2] = L"C:\\Windows\\system32\\msra.exe";
	src[3] = L"C:\\Windows\\system32\\calc.exe";
	src[4] = L"C:\\Windows\\system32\\wordpad.exe";
	//imagepath1 = src[0];
	// lpParam not used here, so called this function to avoid warnings
	UNREFERENCED_PARAMETER(lpParam);

	while (1)
	{
		switch (state)
		{
		case READING_STATE:
			printf("------------------reading state------------------------\n");
			
			FileState *node;
			CHAR * test;
			test = TransferTcharToChar(src[i]);
			imagepath = CheckForImagePath(test);
			printf("Transfer imagepath %s \n", imagepath);

			//search if DoneQueue have this file already?
			positive = TraverseDoneQueue(imagepath);
			fileExist = (positive >= 0) ? TRUE : FALSE;
			if (!fileExist)
			{
				node = CreateNode(imagepath);
				printf("Create  a node \n");

				dwWaitResult = WaitForSingleObject(hMutex_sq, INFINITE);
				switch (dwWaitResult)
				{
					//The thread got ownership of the mutex
				case WAIT_OBJECT_0:
					__try{
						//add obj into sending queue
						//printf("Thread_ReceiveImagePath(%d) add obj into sending queue\n", GetCurrentThreadId());
						printf("Insert into ScanQueue \n");
						InsertNode(ScanQueue, node);
					}
					__finally{
						//release ownership of the mutex object
						if (!ReleaseMutex(hMutex_sq))
							printf("Release mutex_sq error\n");
					}
					break;
				case WAIT_ABANDONED:
					printf("WaitForSingleObject error (Thread_SendingImagePath): Wait abandoned\n");
					break;
				}//end of switch
			}//end of if(!fileExists)
			//imagepath1 = imagepath+1;
			i++;
			state = WRITING_STATE;
			break;


		case WRITING_STATE:
			printf("writing state\n");
			//imagepath = TransferTcharToChar(imagepath1);
			 

			DWORD dwWaitResult;
			FileState *filestate = NULL;
			INT reply = 0;
			
			

			//if at Reading State find file truely exist, then set reply value
			if (fileExist)
			{
			reply = (positive < THRESHOLD) ? 1 : 0;
			}
			// at Reading State find file doesn't exist, so keep traverse DoneQueue until
			// get a non-negative positive value
			//else if(!fileExist && (clock % 20) == 0)
			else 
			{
				positive = TraverseDoneQueue(imagepath);
				fileExist = (positive >= 0) ? TRUE : FALSE;
				// if get report from VirusTotal
				if (fileExist)
					reply = (positive < THRESHOLD) ? 1 : 0;
				//if file didn't scan success(ex: response_code from VirusTotal is 0 or -2)
				else
				{
					reply = 0;
				}
			}//end of if(fileExist)


			//if fileExist, then send reply to client
			if (fileExist && i<3)
			{
			printf("Finished and get reply %d",reply);
			clock = clock + 1;
			state = READING_STATE;
			}
			else if(i == 4){
				printf("Finished and get reply %d", reply);
				printf("no src\n");
				state = CONNECTING_STATE;
			}
			
			Sleep(REQUEST_PAUSE);
			break;

		case CONNECTING_STATE:
			break;
		default:
			printf("Invalid pipe state.\n");
			return 0;

		}//end of switch
	}//end of while
	return 0;
}

DWORD WINAPI Thread_Scan(LPVOID lpParam)
{

	printf("Thread_Scan running...\n");

	// lpParam not used here, so called this function to avoid warnings
	UNREFERENCED_PARAMETER(lpParam);

	DWORD dwWaitResult;
	FileState* file = ScanQueue;
	while (1)
	{
		//wait until getting scanning queue's access right
		dwWaitResult = WaitForSingleObject(hMutex_sq, INFINITE);
		switch (dwWaitResult)
		{
			//The thread got ownership of the mutex
		case WAIT_OBJECT_0:
			__try{
				if (file->total_num > 0)
				{
					TraverseScanQueue();
					//printf("Scan all the files in ScanQueue already\n");
				}
				
			}
			__finally{
				//release ownership of the mutex object
				if (!ReleaseMutex(hMutex_sq))
				{
					printf("Release mutex_sq error\n");
				}
			}
			break;
		case WAIT_ABANDONED:
			printf("ScanTimer: Wait abandoned\n");
			break;
		}//end of switch
	}
	return 0;
}
DWORD WINAPI Thread_Report(LPVOID lpParam)
{
	DWORD dwWaitResult;
	printf("Thread_Report running...\n");
	FileState* file = ReportQueue;
	// lpParam not used here, so called this function to avoid warnings
	UNREFERENCED_PARAMETER(lpParam);

	while (1)
	{
		
		dwWaitResult = WaitForSingleObject(hMutex_rq, INFINITE);
		switch (dwWaitResult)
		{
			//The thread got ownership of the mutex
		case WAIT_OBJECT_0:
			__try{
				if (file->total_num > 0)
				{
					TraverseReportQueue();
					//printf("Report all the files in ReportQueue already\n");
				}				
				else{
					//printf("No file in Report Queue!\n");
				}
			}
			__finally{
				//release ownership of the mutex object
				if (!ReleaseMutex(hMutex_rq))
				{
					printf("Release mutex_rq error\n");
				}
			}
			break;
		case WAIT_ABANDONED:
			printf("ReportTimer error: Wait abandoned\n");
			break;
		}//end of switch
	}
	return 0;
}

int main(int argc, char* argv[]){

	DWORD idThread_ReceiveImagePath = 0;
	DWORD idThread_Scan = 1;
	DWORD idThread_Report = 2;
	int i = 0;


	/* ---------------------------initialize ScanQueue, ReportQueue, DoneQueue ------------------------------------------*/
	ScanQueue = InitLinkedList();
	if (ScanQueue == NULL){
		printf("InitLinkedList error : ScanQueue \n");
		return -1;
	}

	ReportQueue = InitLinkedList();
	if (ReportQueue == NULL){
		printf("InitLinkedList error : ReportQueue \n");
		return -1;
	}

	DoneQueue = InitLinkedList();
	if (DoneQueue == NULL){
		printf("InitLinkedList error : DoneQueue \n");
		return -1;
	}


	hMutex_sq = CreateMutex(NULL, FALSE, "mutex_sq");
	if (hMutex_sq == NULL)
	{
		printf("CreateMutex error (hMutex_sq): %d\n", GetLastError());
		return -1;
	}

	hMutex_rq = CreateMutex(NULL, FALSE, "mutex_rq");
	if (hMutex_rq == NULL)
	{
		printf("CreateMutex error (hMutex_rq): %d\n", GetLastError());
		return -1;
	}

	hMutex_dq = CreateMutex(NULL, FALSE, "mutex_dq");
	if (hMutex_dq == NULL)
	{
		printf("CreateMutex error (hMutex_dq): %d\n", GetLastError());
		return -1;
	}

	/*---------- create thread to receive from data from pipe-----------*/
	hThread[0] = CreateThread(NULL, 0, Thread_ReceiveImagePath, NULL, 0, &idThread_ReceiveImagePath);

	if (hThread[0] == NULL){
		printf("Create Thread_ReceiveImagePath Failed, %d\n", GetLastError());
		return -1;
	}
	hThread[1] = CreateThread(NULL, 0, Thread_Scan, NULL, 0, &idThread_Scan);

	if (hThread[1] == NULL){
		printf("Create Thread_Scan Failed, %d\n", GetLastError());
		return -1;
	}
	hThread[2] = CreateThread(NULL, 0, Thread_Report, NULL, 0, &idThread_Report);

	if (hThread[2] == NULL){
		printf("Create Thread_Report Failed, %d\n", GetLastError());
		return -1;
	}
	

	//Wait for all threads to terminate
	WaitForMultipleObjects(3, hThread, TRUE, INFINITE);

	for (i = 0; i < THREADCOUNT; i++)
		CloseHandle(hThread[i]);

	CloseHandle(hMutex_sq);
	CloseHandle(hMutex_rq);
	CloseHandle(hMutex_dq);


	system("pause");
	return 0;
}