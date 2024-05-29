import sys

def multiply_file_content(filename, multiplier):
    try:
        # Read lines from the specified file
        with open(filename, "r") as file:
            lines = file.readlines()

        # Remove newline characters and multiply the lines
        multiplied_lines = [line.strip() for line in lines] * multiplier

        # Write the multiplied lines to an output file
        output_filename = f"{filename.split('.')[0]}_multiplied.txt"
        with open(output_filename, "w") as output_file:
            for line in multiplied_lines:
                output_file.write(line + '\n')

        print(f"Multiplied content saved in '{output_filename}'")

    except FileNotFoundError:
        print(f"Error: File '{filename}' not found.")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python3 script.py <filename> <multiplier>")
    else:
        filename = sys.argv[1]
        multiplier = int(sys.argv[2])

        multiply_file_content(filename, multiplier)
