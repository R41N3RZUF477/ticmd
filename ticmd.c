#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <windows.h>
#include <sddl.h>

#define SYSTEMTOKEN_FLAG_PRIV_ASSIGNPRIMARY 0x00000001

HANDLE GetSystemToken(DWORD dwFlags)
{
	DWORD lsapid = 0;
	DWORD lsapid_size = 0;
	HKEY key = NULL;
	HANDLE lsa_process = NULL;
	HANDLE token = NULL;
	HANDLE duptoken = NULL;
	TOKEN_PRIVILEGES priv;
	LUID luid;

	if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Lsa", 0, KEY_QUERY_VALUE, &key))
	{
		return NULL;
	}
	lsapid_size = sizeof(lsapid);
	if (RegQueryValueExW(key, L"LsaPid", NULL, NULL, (LPBYTE)&lsapid, &lsapid_size))
	{
		RegCloseKey(key);
		return NULL;
	}
	RegCloseKey(key);
	lsa_process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, lsapid);
	if (!lsa_process)
	{
		return NULL;
	}
	if (!OpenProcessToken(lsa_process, MAXIMUM_ALLOWED, &token))
	{
		CloseHandle(lsa_process);
		return NULL;
	}
	CloseHandle(lsa_process);
	if (DuplicateTokenEx(token, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenImpersonation, &duptoken))
	{
		CloseHandle(token);
		if (dwFlags & SYSTEMTOKEN_FLAG_PRIV_ASSIGNPRIMARY)
		{
			if (LookupPrivilegeValue(NULL, SE_ASSIGNPRIMARYTOKEN_NAME, &luid))
			{
				priv.PrivilegeCount = 1;
				priv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
				priv.Privileges[0].Luid = luid;
				AdjustTokenPrivileges(duptoken, FALSE, &priv, sizeof(priv), NULL, NULL);
			}
		}
		return duptoken;
	}
	return token;
}

typedef BOOL(WINAPI* __LogonUserExExW)(
	LPWSTR        lpszUsername,
	LPWSTR        lpszDomain,
	LPWSTR        lpszPassword,
	DWORD         dwLogonType,
	DWORD         dwLogonProvider,
	PTOKEN_GROUPS pTokenGroups,
	PHANDLE       phToken,
	PSID* ppLogonSid,
	PVOID* ppProfileBuffer,
	LPDWORD       pdwProfileLength,
	PQUOTA_LIMITS pQuotaLimits
	);

HANDLE CreateTrustedInstallerToken(void)
{
	HMODULE advapi32 = NULL;
	__LogonUserExExW _LogonUserExExW = NULL;
	HANDLE token = NULL;
	SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
	DWORD admin_sid_size = 0;
	PSID admin_sid = NULL;
	PSID ti_sid = NULL;
	BYTE tg_buffer[sizeof(TOKEN_GROUPS) * 2];
	PTOKEN_GROUPS tg = (PTOKEN_GROUPS)&tg_buffer[0];
	advapi32 = GetModuleHandleW(L"advapi32.dll");
	if (!advapi32)
	{
		return NULL;
	}
	_LogonUserExExW = (__LogonUserExExW)GetProcAddress(advapi32, "LogonUserExExW");
	if (!_LogonUserExExW)
	{
		return NULL;
	}
	admin_sid = (PSID)LocalAlloc(LPTR, SECURITY_MAX_SID_SIZE);
	if (!admin_sid)
	{
		return NULL;
	}
	admin_sid_size = SECURITY_MAX_SID_SIZE;
	if (!CreateWellKnownSid(WinBuiltinAdministratorsSid, NULL, admin_sid, &admin_sid_size))
	{
		LocalFree(admin_sid);
		return NULL;
	}
	if (!ConvertStringSidToSidW(L"S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464", &ti_sid))
	{
		LocalFree(admin_sid);
		return NULL;
	}
	memset(&tg_buffer[0], 0, sizeof(tg_buffer));
	tg->GroupCount = 2;
	tg->Groups[0].Attributes = SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_MANDATORY;
	tg->Groups[0].Sid = admin_sid;
	tg->Groups[1].Attributes = SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_OWNER;
	tg->Groups[1].Sid = ti_sid;
	_LogonUserExExW(L"SYSTEM", L"NT AUTHORITY", L"", LOGON32_LOGON_SERVICE, LOGON32_PROVIDER_DEFAULT, tg, &token, NULL, NULL, NULL, NULL);
	LocalFree(admin_sid);
	LocalFree(ti_sid);
	return token;
}

int main(int argc, char** argv)
{
	STARTUPINFOW si;
	PROCESS_INFORMATION pi;
	WCHAR* pcmdline = NULL;
	WCHAR* pnext = NULL;
	BOOL wspace = FALSE;
	WCHAR cmdpath[MAX_PATH + 1];
	HANDLE token = NULL;
	HANDLE logontoken = NULL;
	BOOL ret = FALSE;

	if (argc < 2)
	{
		if (!GetEnvironmentVariableW(L"ComSpec", cmdpath, MAX_PATH + 1))
		{
			wcscpy_s(cmdpath, MAX_PATH + 1, L"cmd.exe");
		}
		pcmdline = &cmdpath[0];
	}
	else
	{
		pcmdline = GetCommandLineW();
		if (pcmdline[0] == L'\"')
		{
			pnext = wcschr(&pcmdline[1], L'\"');
			if (pnext)
			{
				pcmdline = pnext + 1;
			}
		}
		wspace = FALSE;
		while (*pcmdline)
		{
			if (iswspace(*pcmdline))
			{
				wspace = TRUE;
			}
			else if (wspace)
			{
				break;
			}
			pcmdline++;
		}
	}
	token = GetSystemToken(SYSTEMTOKEN_FLAG_PRIV_ASSIGNPRIMARY);
	if (!token)
	{
		fprintf(stderr, "GetSystemToken() failed: %u\n", (unsigned int)GetLastError());
		return 1;
	}
	if (!ImpersonateLoggedOnUser(token))
	{
		fprintf(stderr, "ImpersonateLoggedOnUser() failed: %u\n", (unsigned int)GetLastError());
		CloseHandle(token);
		return 2;
	}
	logontoken = CreateTrustedInstallerToken();
	if (!logontoken)
	{
		fprintf(stderr, "CreateTrustedInstallerToken() failed: %u\n", (unsigned int)GetLastError());
		RevertToSelf();
		CloseHandle(token);
		return 3;
	}
	memset(&pi, 0, sizeof(pi));
	memset(&si, 0, sizeof(si));
	si.cb = sizeof(si);
	ret = CreateProcessAsUserW(logontoken, NULL, pcmdline, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
	if (!ret)
	{
		fprintf(stderr, "CreateProcessAsUserW() failed: %u\n", (unsigned int)GetLastError());
	}
	RevertToSelf();
	CloseHandle(logontoken);
	CloseHandle(token);
	if (ret)
	{
		CloseHandle(pi.hThread);
		WaitForSingleObject(pi.hProcess, INFINITE);
		CloseHandle(pi.hProcess);
		return 0;
	}
	return 4;
}
