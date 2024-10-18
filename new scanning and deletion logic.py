
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

# Now let's modify the delete_file function to work with this
def delete_file(file_path):
    import os
    import time
    from win32com.shell import shell, shellcon

    max_attempts = 5
    delay = 1  #

    for attempt in range(max_attempts):
        try:
            if os.path.isfile(file_path):
                os.remove(file_path)
            elif os.path.isdir(file_path):
                os.rmdir(file_path)
            print(f"Successfully deleted: {file_path}")
            return True
        except PermissionError:
            print(f"Attempt {attempt + 1}: File is still in use. Retrying in {delay} seconds...")
            time.sleep(delay)
            
            
            if attempt == max_attempts - 1:
                try:
                    shell.SHFileOperation((0, shellcon.FO_DELETE, file_path, None, 
                                           shellcon.FOF_SILENT | shellcon.FOF_ALLOWUNDO | shellcon.FOF_NOCONFIRMATION,
                                           None, None))
                    print(f"Deleted using shell operation: {file_path}")
                    return True
                except Exception as e:
                    print(f"Failed to delete using shell operation: {e}")

    print(f"Failed to delete after {max_attempts} attempts: {file_path}")
    return False

# Example usage
if __name__ == "__main__":
    file_to_scan_and_delete = r"path\to\your\file.exe"
    
    if scanfile(file_to_scan_and_delete):
        print("File scanned successfully. Attempting to delete...")
        if delete_file(file_to_scan_and_delete):
            print("File deleted successfully.")
        else:
            print("Failed to delete the file.")
    else:
        print("File scan failed or file is safe. Not deleting.")