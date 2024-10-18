import pefile
import hashlib
import math
import numpy as np
import pickle
import sklearn

# calculate MD5 hash
def calculate_md5(file_path):
    hash_md5 = hashlib.md5()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()

# calculate entropy
def calculate_entropy(data):
    if len(data) == 0:
        return 0.0
    occurrences = [0] * 256
    for byte in data:
        occurrences[byte] += 1
    entropy = 0
    for count in occurrences:
        if count == 0:
            continue
        p_x = float(count) / len(data)
        entropy -= p_x * math.log2(p_x)
    return entropy

# extract the necessary information
def extract_pe_info(file_path):
    pe = pefile.PE(file_path)

    # fields
    data = {
        'md5': calculate_md5(file_path),
        'Machine': pe.FILE_HEADER.Machine,
        'SizeOfOptionalHeader': pe.FILE_HEADER.SizeOfOptionalHeader,
        'Characteristics': pe.FILE_HEADER.Characteristics,
        'MajorLinkerVersion': pe.OPTIONAL_HEADER.MajorLinkerVersion,
        'MinorLinkerVersion': pe.OPTIONAL_HEADER.MinorLinkerVersion,
        'SizeOfCode': pe.OPTIONAL_HEADER.SizeOfCode,
        'SizeOfInitializedData': pe.OPTIONAL_HEADER.SizeOfInitializedData,
        'SizeOfUninitializedData': pe.OPTIONAL_HEADER.SizeOfUninitializedData,
        'AddressOfEntryPoint': pe.OPTIONAL_HEADER.AddressOfEntryPoint,
        'BaseOfCode': pe.OPTIONAL_HEADER.BaseOfCode,
        'BaseOfData': getattr(pe.OPTIONAL_HEADER, 'BaseOfData', None),  # Not always present in 64-bit binaries
        'ImageBase': pe.OPTIONAL_HEADER.ImageBase,
        'SectionAlignment': pe.OPTIONAL_HEADER.SectionAlignment,
        'FileAlignment': pe.OPTIONAL_HEADER.FileAlignment,
        'MajorOperatingSystemVersion': pe.OPTIONAL_HEADER.MajorOperatingSystemVersion,
        'MinorOperatingSystemVersion': pe.OPTIONAL_HEADER.MinorOperatingSystemVersion,
        'MajorImageVersion': pe.OPTIONAL_HEADER.MajorImageVersion,
        'MinorImageVersion': pe.OPTIONAL_HEADER.MinorImageVersion,
        'MajorSubsystemVersion': pe.OPTIONAL_HEADER.MajorSubsystemVersion,
        'MinorSubsystemVersion': pe.OPTIONAL_HEADER.MinorSubsystemVersion,
        'SizeOfImage': pe.OPTIONAL_HEADER.SizeOfImage,
        'SizeOfHeaders': pe.OPTIONAL_HEADER.SizeOfHeaders,
        'CheckSum': pe.OPTIONAL_HEADER.CheckSum,
        'Subsystem': pe.OPTIONAL_HEADER.Subsystem,
        'DllCharacteristics': pe.OPTIONAL_HEADER.DllCharacteristics,
        'SizeOfStackReserve': pe.OPTIONAL_HEADER.SizeOfStackReserve,
        'SizeOfStackCommit': pe.OPTIONAL_HEADER.SizeOfStackCommit,
        'SizeOfHeapReserve': pe.OPTIONAL_HEADER.SizeOfHeapReserve,
        'SizeOfHeapCommit': pe.OPTIONAL_HEADER.SizeOfHeapCommit,
        'LoaderFlags': pe.OPTIONAL_HEADER.LoaderFlags,
        'NumberOfRvaAndSizes': pe.OPTIONAL_HEADER.NumberOfRvaAndSizes,
        'SectionsNb': len(pe.sections),
        'ResourcesMeanEntropy': None,
        'ResourcesMinEntropy': None,
        'ResourcesMaxEntropy': None,
        'ResourcesMeanSize': None,
        'ResourcesMinSize': None,
        'ResourcesMaxSize': None,
        'LoadConfigurationSize': pe.OPTIONAL_HEADER.LoadConfigurationSize if hasattr(pe.OPTIONAL_HEADER, 'LoadConfigurationSize') else 0,
        'VersionInformationSize': pe.OPTIONAL_HEADER.VersionInformationSize if hasattr(pe.OPTIONAL_HEADER, 'VersionInformationSize') else 0,
    }

    # section statistics
    sections_entropy = []
    sections_rawsize = []
    sections_virtualsize = []

    # extract section data
    for section in pe.sections:
        sections_entropy.append(section.get_entropy())
        sections_rawsize.append(section.SizeOfRawData)
        sections_virtualsize.append(section.Misc_VirtualSize)

    if sections_entropy:
        data['SectionsMeanEntropy'] = sum(sections_entropy) / len(sections_entropy)
        data['SectionsMinEntropy'] = min(sections_entropy)
        data['SectionsMaxEntropy'] = max(sections_entropy)
    else:
        data['SectionsMeanEntropy'] = data['SectionsMinEntropy'] = data['SectionsMaxEntropy'] = 0

    if sections_rawsize:
        data['SectionsMeanRawsize'] = sum(sections_rawsize) / len(sections_rawsize)
        data['SectionsMinRawsize'] = min(sections_rawsize)
        data['SectionsMaxRawsize'] = max(sections_rawsize)
    else:
        data['SectionsMeanRawsize'] = data['SectionsMinRawsize'] = data['SectionsMaxRawsize'] = 0

    if sections_virtualsize:
        data['SectionsMeanVirtualsize'] = sum(sections_virtualsize) / len(sections_virtualsize)
        data['SectionsMinVirtualsize'] = min(sections_virtualsize)
        data['SectionsMaxVirtualsize'] = max(sections_virtualsize)
    else:
        data['SectionsMeanVirtualsize'] = data['SectionsMinVirtualsize'] = data['SectionsMaxVirtualsize'] = 0

    # Extract resource entropy, size
    resources = []
    if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
        for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            if hasattr(resource_type, 'directory'):
                for resource_id in resource_type.directory.entries:
                    if hasattr(resource_id, 'directory'):
                        for resource_lang in resource_id.directory.entries:
                            resource_data = pe.get_data(resource_lang.data.struct.OffsetToData, resource_lang.data.struct.Size)
                            entropy = calculate_entropy(resource_data)
                            resources.append({
                                'entropy': entropy,
                                'size': resource_lang.data.struct.Size
                            })

    if resources:
        data['ResourcesMeanEntropy'] = sum([r['entropy'] for r in resources]) / len(resources)
        data['ResourcesMinEntropy'] = min([r['entropy'] for r in resources])
        data['ResourcesMaxEntropy'] = max([r['entropy'] for r in resources])
        data['ResourcesMeanSize'] = sum([r['size'] for r in resources]) / len(resources)
        data['ResourcesMinSize'] = min([r['size'] for r in resources])
        data['ResourcesMaxSize'] = max([r['size'] for r in resources])
    
    return data

# fnction to convert the dictionary to array
def convert_to_array(pe_info):
    
    fields_order = [
        'md5', 'Machine', 'SizeOfOptionalHeader', 'Characteristics',
        'MajorLinkerVersion', 'MinorLinkerVersion', 'SizeOfCode',
        'SizeOfInitializedData', 'SizeOfUninitializedData',
        'AddressOfEntryPoint', 'BaseOfCode', 'BaseOfData', 'ImageBase',
        'SectionAlignment', 'FileAlignment', 'MajorOperatingSystemVersion',
        'MinorOperatingSystemVersion', 'MajorImageVersion', 'MinorImageVersion',
        'MajorSubsystemVersion', 'MinorSubsystemVersion', 'SizeOfImage',
        'SizeOfHeaders', 'CheckSum', 'Subsystem', 'DllCharacteristics',
        'SizeOfStackReserve', 'SizeOfStackCommit', 'SizeOfHeapReserve',
        'SizeOfHeapCommit', 'LoaderFlags', 'NumberOfRvaAndSizes', 'SectionsNb',
        'SectionsMeanEntropy', 'SectionsMinEntropy', 'SectionsMaxEntropy',
        'SectionsMeanRawsize', 'SectionsMinRawsize', 'SectionsMaxRawsize',
        'SectionsMeanVirtualsize', 'SectionsMinVirtualsize',
        'SectionsMaxVirtualsize', 'ImportsNbDLL', 'ImportsNb',
        'ImportsNbOrdinal', 'ExportNb', 'ResourcesNb', 'ResourcesMeanEntropy',
        'ResourcesMinEntropy', 'ResourcesMaxEntropy', 'ResourcesMeanSize',
        'ResourcesMinSize', 'ResourcesMaxSize', 'LoadConfigurationSize',
        'VersionInformationSize',
    ]

    array_data = []
    for field in fields_order:
        value = pe_info.get(field)
        if field == 'md5':
            value = int(value,16)
        array_data.append(value)

    return array_data


def scanfile(file_path):
    try:
        pe_info = extract_pe_info(file_path)
        if pe_info is None:
            return False

        pe_array = convert_to_array(pe_info)
        pe_array = np.array(pe_array).reshape(1, -1)

        with open('ranai.pkl', 'rb') as file:
            model = pickle.load(file)

        predictions = model.predict(pe_array)

        print(predictions)
        return "0" in predictions

    except Exception as e:
        print(f"Error in scanfile: {e}")
        return False
    finally:
        # Ensure all file handles are closed
        try:
            del pe_info
            del model
            import gc
            gc.collect()
        except:
            pass

# while True:
#     try:
#         print("ctrl+c to exit")
#         path = input('enter file path to scan:')
#         result = scanfile(path)
#         if result == True:
#             print("ransomware")
#         else:
#             print("clean file")
#     except KeyboardInterrupt:
#         exit()

