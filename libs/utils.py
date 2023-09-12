
def calculate_needed_iterations(header, buffer_size):
    iterations = header['content_length'] // buffer_size
    if header['content_length'] % buffer_size:
        iterations += 1
    return iterations
