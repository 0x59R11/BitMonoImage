#include <iostream>
#include <map>
#include <fstream>

using namespace std;


int main(int argc, char* argv[])
{
	if (argc > 1)
	{
		char* openFilePath = argv[1];
		string saveFilePath(openFilePath);
		
		if (argc > 2 && strcmp(argv[2], "--generateNewFile") == 0)
		{
			saveFilePath.append(".bitten.dll");
		}
		
		cout << "Opening file..." << endl;
		ifstream openFile(openFilePath, ios::binary | ios::ate);
		if (!openFile.is_open())
		{
			cout << "Cannot open file!" << endl;
			return 1;
		}

		openFile.seekg(0, ifstream::end);
		size_t size = openFile.tellg();
		
		iostream stream(openFile.rdbuf());
		{
			char buffer[4];
			
			stream.seekg(0x3C, SEEK_SET);
			stream.read(buffer, 4);
			unsigned int peHeader = *reinterpret_cast<unsigned int*>(&buffer);
			stream.seekg(peHeader, SEEK_SET);
			

			const unsigned int breakPeSignature = 0x00004550;
			memcpy(buffer, &breakPeSignature, sizeof(unsigned int));


			
			stream.write(buffer, 4); // BIT PE SIGNATURE
			cout << "\n[+] Restore PE Signature" << endl;


			stream.seekg(0x2, SEEK_CUR);
			stream.read(buffer, 2);
			unsigned short numberOfSections = *reinterpret_cast<unsigned short*>(&buffer);
			

			stream.seekg(0x10, SEEK_CUR);
			stream.read(buffer, 2);
			bool is64PEOptionsHeader = *reinterpret_cast<unsigned short*>(&buffer) == 0x20B;
			
			stream.seekg(is64PEOptionsHeader ? 0x38 : 0x28 + 0xA6, SEEK_CUR);
			stream.read(buffer, 4);
			unsigned int dotNetVirtualAddress = *reinterpret_cast<unsigned int*>(&buffer);


			unsigned int dotNetRawAddress = 0;
			unsigned int sectionVirtualAddress = 0;
			unsigned int sectionSizeOfRawData = 0;
			unsigned int sectionPointerToRawData = 0;

			stream.seekg(0xC, SEEK_CUR);

			for (int i = 0; i < numberOfSections; i++)
			{
				stream.seekg(0xC, SEEK_CUR);

				stream.read(buffer, 4);
				sectionVirtualAddress = *reinterpret_cast<unsigned int*>(&buffer);

				stream.read(buffer, 4);
				sectionSizeOfRawData = *reinterpret_cast<unsigned int*>(&buffer);

				stream.read(buffer, 4);
				sectionPointerToRawData = *reinterpret_cast<unsigned int*>(&buffer);

				stream.seekg(0x10, SEEK_CUR);

				if (dotNetVirtualAddress >= sectionVirtualAddress && dotNetVirtualAddress < sectionVirtualAddress + sectionSizeOfRawData)
				{
					dotNetRawAddress = dotNetVirtualAddress + sectionPointerToRawData - sectionVirtualAddress;
					break;
				}
			}

			if (dotNetRawAddress != 0)
			{
				stream.seekg(dotNetRawAddress, SEEK_SET);

				const unsigned int zero = 0;
				memcpy(buffer, &zero, sizeof(unsigned int));

				stream.write(buffer, 4); // BIT CB Bytes
				cout << "[+] Break CIL CB" << endl;
			
				stream.write(buffer, 4); // BIT Runtime versions
				cout << "[+] Break Runtime versions" << endl;
			
				stream.seekg(0x4, SEEK_CUR); // SKIP MetaData RVA
				stream.write(buffer, 4); // BIT Metadata size
				cout << "[+] Break MetaData size" << endl;
			}
		}
		
		char* buffer = static_cast<char*>(malloc(size));
		stream.seekg(0, SEEK_SET);
		stream.read(buffer, size);

		
		cout << "\nSaving file..." << endl;
		ofstream saveFile(saveFilePath, ios::binary | ios::trunc);
		saveFile.seekp(0, SEEK_SET);
		saveFile.write(&buffer[0], size);
		saveFile.close();
		cout << "Done!" << endl;
	}
}