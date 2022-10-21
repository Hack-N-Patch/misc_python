'''
Renames functions in Binary Ninja to include descriptions of Windows API calls within
Allows an analyst to quickly identify the functions performing relevant actions and
backtrace the arguments to the Windows API call

Intended to be pasted in the scripting window
TODO: Rework as Binary Ninja Plugin

Functions will be renamed with the following convention 
netw = networking functionality
  b = build
  c = connect
  l = listen
  s = send
  r = receive
  t = terminate
  m = modify

reg = registry functionality
  h = handle
  r = read
  w = write
  d = delete

file = file processing functionality
  h = handle
  r = read
  w = write
  d = delete
  c = copy
  m = move
  e = enumerate

proc = process manipulation functionality
  h = handle
  e = enumerate
  c = create
  t = terminate
  r = read process memory
  w = write process memory

serv = service manipulation functionality
  h = handle
  c = create
  d = delete
  s = start
  r = read
  w = write

thread = thread functionality
  c = create
  o = open
  s = suspend
  r = resume

str = string manipulation functionality
  c = compare

xref = number of cross references for the function

Inspired by https://github.com/AGDCservices/Ghidra-Scripts/blob/master/Preview_Function_Capabilities.py 
'''

# Set expected default and analyzed function prefixes
BINJA_FUNC_PREFIX = "sub_"
AUTO_FUNC_PREFIX = 'f_'

# Map the Windows API to a capability abbreviation
apiPurposeDict = {
    'socket':'netwB',
    #WSAStartup':'netwC',
    'connect':'netwC',
    'InternetOpen':'netwC',
    'InternetOpenA':'netwC',
    'InternetOpenW':'netwC',
    'InternetConnect':'netwC',
    'InternetConnectA':'netwC',
    'InternetConnectW':'netwC',
    'InternetOpenUrl':'netwC',
    'InternetOpenUrlA':'netwC',
    'InternetOpenUrlW':'netwC',
    'HttpOpenRequest':'netwC',
    'HttpOpenRequestA':'netwC',
    'HttpOpenRequestW':'netwC',
    'WinHttpConnect':'netwC',
    'WinHttpOpenRequest':'netwC',
    'bind':'netwL',
    'listen':'netwL',
    'accept':'netwL',
    'send':'netwS',
    'sendto':'netwS',
    'InternetWriteFile':'netwS',
    'HttpSendRequest':'netwS',
    'HttpSendRequestA':'netwS',
    'HttpSendRequestW':'netwS',
    'HttpSendRequestExA':'netwS',
    'HttpSendRequestExW':'netwS',
    'WSASend':'netwS',
    'WSASendTo':'netwS',
    'WinHttpSendRequest':'netwS',
    'WinHttpWriteData':'netwS',
    'recv':'netwR',
    'recvfrom':'netwR',
    'InternetReadFile':'netwR',
    'HttpReceiveHttpRequest':'netwR',
    'WSARecv':'netwR',
    'WSARecvFrom':'netwR',
    'WinHttpReceiveResponse':'netwR',
    'WinHttpReadData':'netwR',
    'WinHttpReadDataEx':'netwR',
    'URLDownloadToFile':'netwR',
    'URLDownloadToFileA':'netwR',
    'URLDownloadToFileW':'netwR',
    'inet_addr':'netwM',
    'htons':'netwM',
    'htonl':'netwM',
    'ntohs':'netwM',
    'ntohl':'netwM',
    'RegOpenKey':'regH',
    'RegQueryValue':'regR',
    'RegGetValue':'regR',
    'RegEnumValue':'regR',
    'RegSetValue':'regW',
    'RegSetKeyValue':'regW',
    'RegSetKeyValueEx':'regW',
    'RegDeleteValue':'regD',
    'RegDeleteKey':'regD',
    'RegDeleteKeyValue':'regD',
    'RegCreateKey':'regC',
    'CreateFile':'fileH',
    'CreateFileA':'fileH',
    'CreateFileW':'fileH',
    'fopen':'fileH',
    'fscan':'fileR',
    'fgetc':'fileR',
    'fgets':'fileR',
    'fread':'fileR',
    'ReadFile':'fileR',
    'ReadFileA':'fileR',
    'ReadFileW':'fileR',
    'flushfilebuffers':'fileW',
    'fprintf':'fileW',
    'fputc':'fileW',
    'fputs':'fileW',
    'fwrite':'fileW',
    'WriteFile':'fileW',
    'WriteFileA':'fileW',
    'WriteFileW':'fileW',
    'DeleteFile':'fileD',
    'DeleteFileA':'fileD',
    'DeleteFileW':'fileD',
    'CopyFile':'fileC',
    'CopyFileA':'fileC',
    'CopyFileW':'fileC',
    'MoveFile':'fileM',
    'MoveFileA':'fileM',
    'MoveFileW':'fileM',
    'FindFirstFile':'fileE',
    'FindFirstFileA':'fileE',
    'FindFirstFileW':'fileE',
    'FindNextFile':'fileE',
    'FindNextFileA':'fileE',
    'FindNextFileW':'fileE',
    'strcmp':'strC',
    'strncmp':'strC',
    'stricmp':'strC',
    'wcsicmp':'strC',
    'mbsicmp':'strC',
    'lstrcmp':'strC',
    'lstrcmpi':'strC',
    'OpenService':'servH',
    'OpenServiceA':'servH',
    'OpenServiceW':'servH',
    'QueryServiceStatus':'servR',
    'QueryServiceStatusEx':'servR',
    'QueryServiceConfig':'servR',
    'QueryServiceConfigA':'servR',
    'QueryServiceConfigW':'servR',
    'ChangeServiceConfig':'servW',
    'ChangeServiceConfigA':'servW',
    'ChangeServiceConfigW':'servW',
    'ChangeServiceConfig2':'servW',
    'ChangeServiceConfig2A':'servW',
    'ChangeServiceConfig2W':'servW',
    'CreateService':'servC',
    'CreateServiceA':'servC',
    'CreateServiceW':'servC',
    'DeleteService':'servD',
    'DeleteServiceA':'servD',
    'DeleteServiceW':'servD',
    'StartService':'servS',
    'StartServiceA':'servS',
    'StartServiceW':'servS',
    'CreateToolhelp32Snapshot':'procE',
    'Process32First':'procE',
    'Process32Next':'procE',
    'OpenProcess':'procH',
    'OpenProcessA':'procH',
    'OpenProcessW':'procH',
    'CreateProcess':'procC',
    'CreateProcessA':'procC',
    'CreateProcessW':'procC',
    'CreateProcessAsUser':'procC',
    'CreateProcessAsUserA':'procC',
    'CreateProcessAsUserW':'procC',
    'CreateProcessWithLogon':'procC',
    'CreateProcessWithLogonA':'procC',
    'CreateProcessWithLogonW':'procC',
    'CreateProcessWithToken':'procC',
    'CreateProcessWithTokenA':'procC',
    'CreateProcessWithTokenW':'procC',
    'ShellExecute':'procC',
    'ShellExecuteA':'procC',
    'ShellExecuteW':'procC',
    'ReadProcessMemory':'procR',
    'ReadProcessMemoryA':'procR',
    'ReadProcessMemoryW':'procR',
    'WriteProcessMemory':'procW',
    'WriteProcessMemoryA':'procW',
    'WriteProcessMemoryW':'procW',
    'CreateThread':'threadC',
    'CreateThreadEx':'threadC',
    'CreateRemoteThread':'threadC',
    'CreateRemoteThreadEx':'threadC',
    'beginthread':'threadC',
    'beginthreadex':'threadC',
    'OpenThread':'threadO',
    'OpenThreadA':'threadO',
    'OpenThreadW':'threadO',
    'SuspendThread':'threadS',
    'SuspendThreadA':'threadS',
    'SuspendThreadW':'threadS',
    'ResumeThread':'threadR',
    'ResumeThreadA':'threadR',
    'ResumeThreadW':'threadR'
}

# Gather a list of functions that start with the unanalyzed prefix 
functions = bv.functions
funcList = [f for f in functions if f.name.startswith((BINJA_FUNC_PREFIX, AUTO_FUNC_PREFIX))]

# Gather the list of Windows APIs imported
winAPIs = bv.get_symbols_of_type(SymbolType.ImportAddressSymbol)

# For each Windows API that with a capability abbreviation 
for i in winAPIs:
    if i.name in apiPurposeDict:
        # Get each function that calls that API
        apiCallers = bv.get_code_refs(i.address)
        for caller in apiCallers:
            # If it has the default function prefix rename it with capability abbreviation
            if caller.function.name[:4] == BINJA_FUNC_PREFIX:
                caller.function.name = AUTO_FUNC_PREFIX + str(hex(caller.address))[-4:] + "_" + apiPurposeDict[i.name]
            # If it has already been analyzed, append any new capability abbreviations
            elif caller.function.name[:2] == AUTO_FUNC_PREFIX and apiPurposeDict[i.name] not in caller.function.name:
                caller.function.name = caller.function.name + "_" + apiPurposeDict[i.name]

# Iterate through the list of functions, and add a crossreference count
for func in bv.functions:
	if func.name[:2] == AUTO_FUNC_PREFIX:
		func.name = func.name + "_xref" + str(len(func.callers))