//---------------------------------------------------------------------------------------------
// v176 Localhost Enabler - Rajan
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

#define OPT_APPNAME		"Rebirth 176"
#define OPT_PATTERN		"8.31.99."
#define OPT_HOSTNAME	"127.0.0.1"

//---------------------------------------------------------------------------------------------

typedef int (WINAPI* pWSPStartup)(WORD wVersionRequested, LPWSPDATA lpWSPData, LPWSAPROTOCOL_INFO lpProtocolInfo, WSPUPCALLTABLE UpcallTable, LPWSPPROC_TABLE lpProcTable);
typedef BOOL(__cdecl* pNMCO_CallNMFunc)(int uFuncCode, BYTE* pCallingData, BYTE**ppReturnData, UINT32&	uReturnDataLen);

//---------------------------------------------------------------------------------------------

LPSTR				g_lpUserName = new char[PASSPORT_SIZE];

pWSPStartup			g_WSPStartup;
pNMCO_CallNMFunc	g_NMCO_CallNMFunc;

SOCKET				g_hGameSock;
WSPPROC_TABLE		g_ProcTable;
DWORD				g_dwNexonAddr;

//---------------------------------------------------------------------------------------------

void FuckMaple()
{
	Log(__FUNCTION__ ": Patching NGS !!!!!");
	PatchRet(0x01960B00);

	Log(__FUNCTION__ ": Patching MSCRC !!!!!");
	PatchJmp(0x019DD7AD, 0x019DD844);
}

//---------------------------------------------------------------------------------------------

int WINAPI WSPGetPeerName_Hook(SOCKET s, struct sockaddr *name, LPINT namelen, LPINT lpErrno)
{
	int ret = g_ProcTable.lpWSPGetPeerName(s, name, namelen, lpErrno);

	if (s == g_hGameSock)
	{
		sockaddr_in* service = (sockaddr_in*)name;
		memcpy(&service->sin_addr, &g_dwNexonAddr, sizeof(DWORD));

		Log("Replace WSPGetPeerName");
	}

	return  ret;
}

int WINAPI WSPConnect_Hook(SOCKET s, const struct sockaddr *name, int namelen, LPWSABUF lpCallerData, LPWSABUF lpCalleeData, LPQOS lpSQOS, LPQOS lpGQOS, LPINT lpErrno)
{
	char buf[50];
	DWORD len = 50;
	WSAAddressToStringA((sockaddr*)name, namelen, NULL, buf, &len);
	Log("WSPConnect Original: %s", buf);

	if (strstr(buf, OPT_PATTERN))
	{
		g_hGameSock = s;

		Log("Replace WSPConnect");

		sockaddr_in* service = (sockaddr_in*)name;
		memcpy(&g_dwNexonAddr, &service->sin_addr, sizeof(DWORD)); //sin_adder -> g_dwNexonAddr

		service->sin_addr.S_un.S_addr = inet_addr(OPT_HOSTNAME);
	}

	return g_ProcTable.lpWSPConnect(s, name, namelen, lpCallerData, lpCalleeData, lpSQOS, lpGQOS, lpErrno);
}

int WINAPI WSPStartup_Hook(WORD wVersionRequested, LPWSPDATA lpWSPData, LPWSAPROTOCOL_INFO lpProtocolInfo, WSPUPCALLTABLE UpcallTable, LPWSPPROC_TABLE lpProcTable)
{
	Log("Hijacked WinSock ProcTable");

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

BOOL Hook_NMCO()
{
	auto address = GetFuncAddress("nmcogame", "NMCO_CallNMFunc");

	if (!address)
		return FALSE;

	g_NMCO_CallNMFunc = (pNMCO_CallNMFunc)address;

	return SetHook(true, (PVOID*)&g_NMCO_CallNMFunc, (PVOID)NMCO_CallNMFunc_Hook);
}

BOOL Hook_Winsock()
{
	auto address = GetFuncAddress("MSWSOCK", "WSPStartup");

	if (!address)
		return FALSE;

	g_WSPStartup = (pWSPStartup)address;

	return SetHook(true, (PVOID*)&g_WSPStartup, (PVOID)WSPStartup_Hook);
}

bool Hook_CreateWindowExA(bool bEnable)
{
	static auto _CreateWindowExA =
		decltype(&CreateWindowExA)(GetFuncAddress("USER32", "CreateWindowExA"));

	decltype(&CreateWindowExA) Hook = [](DWORD dwExStyle, LPCTSTR lpClassName, LPCTSTR lpWindowName, DWORD dwStyle, int x, int y, int nWidth, int nHeight, HWND hWndParent, HMENU hMenu, HINSTANCE hInstance, LPVOID lpParam) -> HWND
	{
		auto windowName = lpWindowName;

		if (!strcmp(lpClassName, "StartUpDlgClass"))
		{
			return NULL;
		}
		else if (!strcmp(lpClassName, "NexonADBallon"))
		{
			return NULL;
		}
		else if (!strcmp(lpClassName, "MapleStoryClass"))
		{
			windowName = OPT_APPNAME;

			FuckMaple();

			Log("CWvsApp [%#08x]", lpParam);
		}

		return _CreateWindowExA(dwExStyle, lpClassName, windowName, dwStyle, x, y, nWidth, nHeight, hWndParent, hMenu, hInstance, lpParam);
	};

	return SetHook(bEnable, reinterpret_cast<void**>(&_CreateWindowExA), Hook);
}

bool Hook_SetProgramState(bool bEnable)
{
	typedef int(__cdecl* pSetProgramState)(int nState);

	static auto _SetProgramState =
		reinterpret_cast<pSetProgramState>(0x0195F250);

	static pSetProgramState Hook = [](int nState) -> int
	{
		auto ret = _ReturnAddress();
		Log("SetProgramState %d [%#08x]", nState, ret);
		return _SetProgramState(nState);
	};

	return SetHook(bEnable, reinterpret_cast<void**>(&_SetProgramState), Hook);
}

//---------------------------------------------------------------------------------------------
DWORD WINAPI MainProc(PVOID)
{
	Log("Injected into MapleStory PID: %i", GetCurrentProcessId());

	//if (!Hook_NMCO())
	//	Log("Failed Hook_NMCO");

	if (!Hook_Winsock())
		Log("Failed Hook_Winsock");

	if (!Hook_CreateWindowExA(true))
		Log("Failed Hook_CreateWindowExA");

	//if (!Hook_SetProgramState(true))
	//	Log("Failed Hook_SetProgramState");

	return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
	if (fdwReason == DLL_PROCESS_ATTACH)
	{
		DisableThreadLibraryCalls(hinstDLL);
		CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)&MainProc, NULL, NULL, NULL);
	}
	else if (fdwReason == DLL_PROCESS_DETACH)
	{
		//
	}

	return TRUE;
}