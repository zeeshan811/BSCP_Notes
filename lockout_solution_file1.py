import sys

def insert_string_after_each_line(filename, string_to_add):
    try:
        # Read passwords from the specified file
        with open(filename, "r") as file:
            passwords = file.readlines()

        # Extract file name and extension
        file_parts = filename.split('.')
        file_name_without_extension = '.'.join(file_parts[:-1])
        file_extension = file_parts[-1]

        # Construct the new file name
        new_filename = f"{file_name_without_extension}_with_{string_to_add}.{file_extension}"

        # Open a new file to write the modified passwords
        with open(new_filename, "w") as output_file:
            for password in passwords:
                # Write the original password
                output_file.write(password.strip() + "\n")
                # Write the specified string after the password
                output_file.write(string_to_add + "\n")

        print(f"Modified list is saved in {new_filename}")

    except FileNotFoundError:
        print(f"Error: File '{filename}' not found.")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python3 script.py <filename> <string_to_add>")
    else:
        filename = sys.argv[1]
        string_to_add = sys.argv[2]

        insert_string_after_each_line(filename, string_to_add)
