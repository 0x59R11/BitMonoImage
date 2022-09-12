#include <iostream>
#include <fstream>

using namespace std;


int main(int argc, char* argv[])
{
	if (argc > 1)
	{
		fstream stream(argv[1], ios_base::in | ios_base::out | ios_base::binary);

		if (stream.is_open())
		{
			char buffer[4];

			stream.seekg(0x3C, SEEK_SET);
			stream.read(buffer, 4);
			unsigned int peHeader = *(unsigned int*)&buffer;
			stream.seekg(peHeader, SEEK_SET);


			const unsigned int breakPeSignature = 0x00014550;
			memcpy(buffer, &breakPeSignature, sizeof(unsigned int));

			stream.write(buffer, 4); // BIT PE SIGNATURE


			stream.seekg(0x2, SEEK_CUR);
			stream.read(buffer, 2);
			unsigned short numberOfSections = *(unsigned short*)&buffer;

			stream.seekg(0x10, SEEK_CUR);
			stream.read(buffer, 2);
			bool is64PEOptionsHeader = *(unsigned short*)&buffer == 0x20B;

			stream.seekg(is64PEOptionsHeader ? 0x38 : 0x28 + 0xA6, SEEK_CUR);
			stream.read(buffer, 4);
			unsigned int dotNetVirtualAddress = *(unsigned int*)&buffer;


			unsigned int dotNetRawAddress = 0;
			unsigned int sectionVirtualAddress = 0;
			unsigned int sectionSizeOfRawData = 0;
			unsigned int sectionPointerToRawData = 0;

			stream.seekg(0xC, SEEK_CUR);

			for (int i = 0; i < numberOfSections; i++)
			{
				stream.seekg(0xC, SEEK_CUR);

				stream.read(buffer, 4);
				sectionVirtualAddress = *(unsigned int*)&buffer;

				stream.read(buffer, 4);
				sectionSizeOfRawData = *(unsigned int*)&buffer;

				stream.read(buffer, 4);
				sectionPointerToRawData = *(unsigned int*)&buffer;

				stream.seekg(0x10, SEEK_CUR);

				if (dotNetVirtualAddress >= sectionVirtualAddress && dotNetVirtualAddress < sectionVirtualAddress + sectionSizeOfRawData)
				{
					dotNetRawAddress = dotNetVirtualAddress + sectionPointerToRawData - sectionVirtualAddress;
					break;
				}
			}

			stream.seekg(dotNetRawAddress, SEEK_SET);

			const unsigned int zero = 0;
			memcpy(buffer, &zero, sizeof(unsigned int));

			stream.write(buffer, 4); // BIT CB Bytes
			stream.seekg(0x8, SEEK_CUR);
			stream.write(buffer, 4); // BIT Metadata size
		}

		stream.close();
	}
}