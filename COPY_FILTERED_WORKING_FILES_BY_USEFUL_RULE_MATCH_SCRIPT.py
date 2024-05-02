import os
import glob

def save_yar_yara_filenames(current_dir, output_filename):
    # Construct the pattern to find .yar and .yara files
    pattern = os.path.join(current_dir, '*.yar*')  # Matches both .yar and .yara
    
    # Find all matching files in the current directory
    file_names = glob.glob(pattern)
    
    # Write the names to the output file
    with open(output_filename, 'w') as file:
        for name in file_names:
            file.write(f"{os.path.basename(name)}\n")

if __name__ == "__main__":
    current_directory = os.getcwd()  # Get the current directory
    output_file = 'ALL_WORKING_AND_USEFUL_FILES_FROM_ALL_FOLDERS.txt'
    
    save_yar_yara_filenames(current_directory, output_file)
