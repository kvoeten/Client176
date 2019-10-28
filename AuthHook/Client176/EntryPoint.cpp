//---------------------------------------------------------------------------------------------
// v176.1 Localhost Enabler - Rajan
//---------------------------------------------------------------------------------------------

#include <WinSock2.h>
#include "Functions.h"
#include <WS2spi.h>
#include <Windows.h>
#include <winnt.h>
#include <intrin.h>
#include <dbghelp.h>
#include <winternl.h>
#include "NMCO\NMGeneral.h"
#include "NMCO\NMFunctionObject.h"
#include "NMCO\NMSerializable.h"

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "detours.lib")

#define OPT_APPNAME			"Rebirth 176"
#define OPT_ADDR_HOSTNAME	"127.0.0.1"

#define OPT_ADDR_SEARCH		"8.31.99."
#define OPT_ADDR_NEXON		"8.31.99.141"

#define OPT_PORT_LOW		8484
#define OPT_PORT_HIGH		8989

#define OPT_APPVERSION		"2.0"

//---------------------------------------------------------------------------------------------

#define ZXString char*
typedef int (WINAPI* pWSPStartup)(WORD wVersionRequested, LPWSPDATA lpWSPData, LPWSAPROTOCOL_INFO lpProtocolInfo, WSPUPCALLTABLE UpcallTable, LPWSPPROC_TABLE lpProcTable);
typedef BOOL(__cdecl* pNMCO_CallNMFunc)(int uFuncCode, BYTE* pCallingData, BYTE**ppReturnData, UINT32&	uReturnDataLen);

//---------------------------------------------------------------------------------------------

pWSPStartup			g_WSPStartup;
WSPPROC_TABLE		g_ProcTable;
DWORD				g_dwAddrNexon;

pNMCO_CallNMFunc	g_NMCO_CallNMFunc;
LPSTR				g_lpUserName = new char[PASSPORT_SIZE];

//---------------------------------------------------------------------------------------------

void FuckMaple()
{
	Log(__FUNCTION__);

	PatchRetZero(0x01960B00); //TSingleton<CSecurityClient>::CreateInstance
	PatchJmp(0x019DD7AD, 0x019DD844); //CWvsContext::OnEnterField
}

//---------------------------------------------------------------------------------------------

int WINAPI WSPGetPeerName_Hook(SOCKET s, struct sockaddr *name, LPINT namelen, LPINT lpErrno)
{
	int nRet = g_ProcTable.lpWSPGetPeerName(s, name, namelen, lpErrno);

	if (nRet == SOCKET_ERROR)
	{
		Log("[WSPGetPeerName] ErrorCode: %d", *lpErrno);
	}
	else
	{
		char szAddr[50];
		DWORD dwLen = 50;
		WSAAddressToStringA((sockaddr*)name, *namelen, NULL, szAddr, &dwLen);

		sockaddr_in* service = (sockaddr_in*)name;

		auto nPort = ntohs(service->sin_port);

		if (nPort >= OPT_PORT_LOW && nPort <= OPT_PORT_HIGH)
		{
			service->sin_addr.S_un.S_addr = inet_addr(OPT_ADDR_NEXON);
			Log("[WSPGetPeerName] Replaced: %s", OPT_ADDR_NEXON);
		}
		else
		{
			Log("[WSPGetPeerName] Original: %s", szAddr);
		}
	}

	return  nRet;
}

int WINAPI WSPConnect_Hook(SOCKET s, const struct sockaddr *name, int namelen, LPWSABUF lpCallerData, LPWSABUF lpCalleeData, LPQOS lpSQOS, LPQOS lpGQOS, LPINT lpErrno)
{
	char szAddr[50];
	DWORD dwLen = 50;
	WSAAddressToStringA((sockaddr*)name, namelen, NULL, szAddr, &dwLen);

	sockaddr_in* service = (sockaddr_in*)name;

	if (strstr(szAddr, OPT_ADDR_SEARCH))
	{
		service->sin_addr.S_un.S_addr = inet_addr(OPT_ADDR_HOSTNAME);
		Log("[WSPConnect] Replaced: %s", OPT_ADDR_HOSTNAME);
	}
	else
	{
		Log("[WSPConnect] Original: %s", szAddr);
	}

	return g_ProcTable.lpWSPConnect(s, name, namelen, lpCallerData, lpCalleeData, lpSQOS, lpGQOS, lpErrno);
}

int WINAPI WSPStartup_Hook(WORD wVersionRequested, LPWSPDATA lpWSPData, LPWSAPROTOCOL_INFO lpProtocolInfo, WSPUPCALLTABLE UpcallTable, LPWSPPROC_TABLE lpProcTable)
{
	Log("[WSPStartup] Hijacked ProcTable");

	int ret = g_WSPStartup(wVersionRequested, lpWSPData, lpProtocolInfo, UpcallTable, lpProcTable);
	g_ProcTable = *lpProcTable;

	lpProcTable->lpWSPConnect = WSPConnect_Hook;
	lpProcTable->lpWSPGetPeerName = WSPGetPeerName_Hook;

	return ret;
}

//---------------------------------------------------------------------------------------------

BOOL NMCO_CallNMFunc_Hook(int uFuncCode, BYTE* pCallingData, BYTE**ppReturnData, UINT32& uReturnDataLen)
{
	Log("[NMCO_CallNMFunc_Hook] uFuncCode %d", uFuncCode);

	//CWvsApp::InitializeAuth
	if (uFuncCode == kNMFuncCode_SetLocale || uFuncCode == kNMFuncCode_Initialize)
	{
		CNMSimpleStream* returnStream = new CNMSimpleStream(); // Memleaked actually. 
		CNMSetLocaleFunc* retFunc = new CNMSetLocaleFunc(); // Memleaked actually. 
		retFunc->SetReturn();
		retFunc->bSuccess = true;

		if (retFunc->Serialize(*returnStream) == false)
			Log("[NMCO_CallNMFunc_Hook] Could not Serialize?!");

		*ppReturnData = returnStream->GetBufferPtr();
		uReturnDataLen = returnStream->GetBufferSize();

		return TRUE;
	}
	else if (uFuncCode == kNMFuncCode_LoginAuth)
	{
		CNMSimpleStream	ssStream;
		ssStream.SetBuffer(pCallingData);

		CNMLoginAuthFunc pFunc;
		pFunc.SetCalling();
		pFunc.DeSerialize(ssStream);

		memcpy(g_lpUserName, pFunc.szNexonID, PASSPORT_SIZE);
		Log("Username: %s", g_lpUserName);

		// Return to the client that login was successful.. NOT
		CNMSimpleStream* returnStream = new CNMSimpleStream(); // Memleaked actually. 
		CNMLoginAuthFunc* retFunc = new CNMLoginAuthFunc(); // Memleaked actually. 
		retFunc->SetReturn();
		retFunc->nErrorCode = kLoginAuth_OK;
		retFunc->bSuccess = true;

		if (retFunc->Serialize(*returnStream) == false)
			Log("[NMCO_CallNMFunc_Hook] Could not Serialize?!");

		*ppReturnData = returnStream->GetBufferPtr();
		uReturnDataLen = returnStream->GetBufferSize();

		return TRUE;
	}
	else if (uFuncCode == kNMFuncCode_GetNexonPassport)
	{
		CNMSimpleStream* ssStream = new CNMSimpleStream(); // Memleaked actually. 

		CNMGetNexonPassportFunc* pFunc = new CNMGetNexonPassportFunc(); // Memleaked actually. 
		pFunc->bSuccess = true;

		strcpy(pFunc->szNexonPassport, g_lpUserName);

		pFunc->SetReturn();

		if (pFunc->Serialize(*ssStream) == false)
			Log("[NMCO_CallNMFunc_Hook] Could not Serialize?!");

		*ppReturnData = ssStream->GetBufferPtr();
		uReturnDataLen = ssStream->GetBufferSize();

		return TRUE;
	}
	else if (uFuncCode == kNMFuncCode_LogoutAuth)
	{
		return TRUE;
	}

	Log("[NMCO_CallNMFunc_Hook] Whoops! Missing something: %x", uFuncCode);

	return g_NMCO_CallNMFunc(uFuncCode, pCallingData, ppReturnData, uReturnDataLen);
}

//---------------------------------------------------------------------------------------------

BOOL Hook_Winsock()
{
	auto address = GetFuncAddress("MSWSOCK", "WSPStartup");

	if (!address)
		return FALSE;

	g_WSPStartup = (pWSPStartup)address;

	return SetHook(true, (PVOID*)&g_WSPStartup, (PVOID)WSPStartup_Hook);
}

BOOL Hook_NMCO()
{
	auto address = GetFuncAddress("nmcogame", "NMCO_CallNMFunc");

	if (!address)
		return FALSE;

	g_NMCO_CallNMFunc = (pNMCO_CallNMFunc)address;

	return SetHook(true, (PVOID*)&g_NMCO_CallNMFunc, (PVOID)NMCO_CallNMFunc_Hook);
}

bool Hook_CreateWindowExA(bool bEnable)
{
	static auto _CreateWindowExA = decltype(&CreateWindowExA)(GetFuncAddress("USER32", "CreateWindowExA"));

	decltype(&CreateWindowExA) Hook = [](DWORD dwExStyle, LPCTSTR lpClassName, LPCTSTR lpWindowName, DWORD dwStyle, int x, int y, int nWidth, int nHeight, HWND hWndParent, HMENU hMenu, HINSTANCE hInstance, LPVOID lpParam) -> HWND
	{
		auto lpLocalWndName = lpWindowName;

		if (!strcmp(lpClassName, "StartUpDlgClass"))
		{
			FuckMaple();
			return NULL;
		}
		else if (!strcmp(lpClassName, "NexonADBallon"))
		{
			return NULL;
		}
		else if (!strcmp(lpClassName, "MapleStoryClass"))
		{
			lpLocalWndName = OPT_APPNAME;
			Log("CWvsApp [%#08x]", lpParam);
		}

		return _CreateWindowExA(dwExStyle, lpClassName, lpLocalWndName, dwStyle, x, y, nWidth, nHeight, hWndParent, hMenu, hInstance, lpParam);
	};

	return SetHook(bEnable, reinterpret_cast<void**>(&_CreateWindowExA), Hook);
}

bool Hook_CreateMutexA(bool bEnable)
{
	static auto _CreateMutexA = decltype(&CreateMutexA)(GetFuncAddress("KERNEL32", "CreateMutexA"));

	decltype(&CreateMutexA) Hook = [](LPSECURITY_ATTRIBUTES lpMutexAttributes, BOOL bInitialOwner, LPCSTR lpName) -> HANDLE
	{
		if (lpName && !strcmp(lpName, "WvsClientMtx"))
		{
			Log("MultiClient: Faking %s", lpName);
			return (HANDLE)0xBADF00D;
		}

		return _CreateMutexA(lpMutexAttributes, bInitialOwner, lpName);
	};

	return SetHook(bEnable, reinterpret_cast<void**>(&_CreateMutexA), Hook);
}

bool Hook_SetProgramState(bool bEnable)
{
	typedef int(__cdecl* pSetProgramState)(int nState);
	static auto _SetProgramState = reinterpret_cast<pSetProgramState>(0x0195F250);

	static pSetProgramState Hook = [](int nState) -> int
	{
		auto ret = _ReturnAddress();
		Log("SetProgramState %d [%#08x]", nState, ret);
		return _SetProgramState(nState);
	};

	return SetHook(bEnable, reinterpret_cast<void**>(&_SetProgramState), Hook);
}

bool Hook_WriteStageLogA(bool bEnable)
{
	typedef int(__cdecl* pWriteStageLogA)(int nIdx, ZXString szMessage);
	static auto _WriteStageLogA = (pWriteStageLogA)(GetFuncAddress("nxgsm", "WriteStageLogA"));

	pWriteStageLogA Hook = [](int nIdx, ZXString szMessage) -> int
	{
		Log("WriteStageLogA: %s", szMessage);
		return 0;
	};

	return SetHook(bEnable, reinterpret_cast<void**>(&_WriteStageLogA), Hook);
}

bool Hook_WriteErrorLogA(bool bEnable)
{
	typedef int(__cdecl* pWriteErrorLogA)(int nIdx, ZXString szMessage);
	static auto _WriteErrorLogA = (pWriteErrorLogA)(GetFuncAddress("nxgsm", "WriteErrorLogA"));

	pWriteErrorLogA Hook = [](int nIdx, ZXString szMessage) -> int
	{
		Log("WriteErrorLogA: %s", szMessage);
		return 0;
	};

	return SetHook(bEnable, reinterpret_cast<void**>(&_WriteErrorLogA), Hook);
}

//---------------------------------------------------------------------------------------------

void WINAPI HeaderProc(DWORD dwPID)
{
	Log("------------------------------------------------");
	Log("[Rajan] [%s] [v%s]", OPT_APPNAME, OPT_APPVERSION);
	Log("[Rajan]       \\    /\\  ");
	Log("[Rajan]        )  ( ')   ");
	Log("[Rajan]       (  /  )    ");
	Log("[Rajan] cat    \\(__)|   ");
	Log("[Rajan] [PID: %d] [Built: %s]", dwPID, __TIMESTAMP__);
	Log("------------------------------------------------");
}

long WINAPI ExcepProc(EXCEPTION_POINTERS* pExceptionInfo)
{
	Log("RegException: %08X (%08X)", pExceptionInfo->ExceptionRecord->ExceptionCode, pExceptionInfo->ExceptionRecord->ExceptionAddress);

	return EXCEPTION_CONTINUE_SEARCH;
}

DWORD WINAPI MainProc(PVOID)
{
	DWORD dwCurProcId = GetCurrentProcessId();
	HeaderProc(dwCurProcId);

	if (!Hook_Winsock())
		Log("Failed Hooking Winsock");

	//if (!Hook_NMCO())
	//	Log("Failed Hooking NMCO");

	if (!Hook_CreateWindowExA(true))
		Log("Failed Hooking CreateWindowExA");

	if (!Hook_CreateMutexA(true))
		Log("Failed Hooking CreateMutexA");

	//if (!Hook_SetProgramState(true))
	//	Log("Failed Hooking SetProgramState");

	if (!Hook_WriteStageLogA(true))
		Log("Failed Hooking WriteStageLogA");

	if (!Hook_WriteErrorLogA(true))
		Log("Failed Hooking WriteErrorLogA");

	return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
	if (fdwReason == DLL_PROCESS_ATTACH)
	{
		DisableThreadLibraryCalls(hinstDLL);

		//AddVectoredExceptionHandler(1, ExcepProc);
		CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)&MainProc, NULL, NULL, NULL);
	}
	else if (fdwReason == DLL_PROCESS_DETACH)
	{
		//
	}

	return TRUE;
}