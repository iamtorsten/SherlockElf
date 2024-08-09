def read_memory_dump(file_path):
    with open(file_path, 'rb') as file:
        binary_data = file.read()

    return binary_data