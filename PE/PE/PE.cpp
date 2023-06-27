#include "Windows.h"
#include <iostream>

int main(int argc, char* argv[]) {
	HANDLE file = NULL;
	DWORD fileSize = NULL;
	DWORD bytesRead = NULL;
	LPVOID fileData = NULL;
	PIMAGE_DOS_HEADER dosHeader = {}, dosHeaderr = {};
	PIMAGE_NT_HEADERS imageNTHeaders = {};
	PIMAGE_SECTION_HEADER sectionHeader = {};
	PIMAGE_SECTION_HEADER importSection = {};
	IMAGE_IMPORT_DESCRIPTOR* importDescriptor, importDescriptorr = {};
	PIMAGE_THUNK_DATA thunkData = {};
	DWORD thunk = NULL;
	DWORD rawOffset = NULL;
	typedef struct _SET_NAME {
		DWORD a;
		DWORD b;
		DWORD c;
		DWORD d;
	}SET_NAME, * PSET_NAME;
	PSET_NAME setname = {}, setname2 = {};


	file = CreateFileA("D:\\test PE\\psiphon3.exe", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	fileSize = GetFileSize(file, NULL);

	fileData = HeapAlloc(GetProcessHeap(), 0, fileSize);

	ReadFile(file, fileData, fileSize, &bytesRead, NULL);

	dosHeader = (PIMAGE_DOS_HEADER)fileData;

	imageNTHeaders = (PIMAGE_NT_HEADERS)((DWORD)fileData + dosHeader->e_lfanew);

	DWORD sectionLocation = (DWORD)imageNTHeaders + sizeof(DWORD) + (DWORD)(sizeof(IMAGE_FILE_HEADER)) + (DWORD)imageNTHeaders->FileHeader.SizeOfOptionalHeader;

	DWORD sectionSize = (DWORD)sizeof(IMAGE_SECTION_HEADER);

	DWORD importDirectoryRVA = imageNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;

	for (int i = 0; i < imageNTHeaders->FileHeader.NumberOfSections; i++) {
		sectionHeader = (PIMAGE_SECTION_HEADER)sectionLocation;

		if (importDirectoryRVA >= sectionHeader->VirtualAddress && importDirectoryRVA < sectionHeader->VirtualAddress + sectionHeader->Misc.VirtualSize) {
			importSection = sectionHeader;
		}
		sectionLocation += sectionSize;
	}

	// get file offset to import table
	rawOffset = (DWORD)fileData + importSection->PointerToRawData;

	importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(rawOffset + (imageNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress - importSection->VirtualAddress));
	DWORD Name = NULL;
	DWORD Characteristics = NULL;
	DWORD OriginalFirstThunk = NULL;
	DWORD TimeDateStamp = NULL;
	DWORD ForwarderChain = NULL;
	DWORD FirstThunk = NULL;
	int aa = 0;
	for (; importDescriptor->Name != 0; importDescriptor++) {

		aa += 1;
	}
	if (importDescriptor->Name == 0) {
		importDescriptor--;
		DWORD bb = importDescriptor->Name;
		importDescriptor++;

		importDescriptor->Name = bb + 350;
		DWORD aa = rawOffset + (importDescriptor->Name - importSection->VirtualAddress);
		setname = (PSET_NAME)(aa);
		setname->a = 1129730893;
		setname->b = 808464722;
		setname->c = 1819042862;

		importDescriptor->FirstThunk = bb + 370;
		thunkData = (PIMAGE_THUNK_DATA)(rawOffset + (importDescriptor->FirstThunk - importSection->VirtualAddress));
		thunkData->u1.AddressOfData = bb + 390;
		thunkData->u1.ForwarderString = bb + 390;
		thunkData->u1.Function = bb + 390;
		thunkData->u1.Ordinal = bb + 390;

		aa = rawOffset + (thunkData->u1.AddressOfData - importSection->VirtualAddress + 2);
		setname2 = (PSET_NAME)(aa);
		setname2->a = 1769107571;
		setname2->b = 6714478;

		importDescriptor->Characteristics = NULL;
		importDescriptor->OriginalFirstThunk = NULL;
		TimeDateStamp = NULL;
		ForwarderChain = NULL;

	}
	HANDLE outputFile = CreateFileA("D:\\test PE\\output_pe.exe", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

	DWORD bytesWritten;
	if (WriteFile(outputFile, fileData, fileSize, &bytesWritten, NULL) && bytesWritten == fileSize) {
		printf("successfully");
	}
	CloseHandle(outputFile);
}
