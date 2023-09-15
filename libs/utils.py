
def calculate_needed_iterations(header, buffer_size) -> int:
    """
    Function returns iteration needed to process all content through the buffer of given size.
    :param header: Contains info about content length.
    :param buffer_size: Size of the buffer
    :return: Number of iterations.
    """
    iterations = header['content_length'] // buffer_size
    if header['content_length'] % buffer_size:
        iterations += 1
    return iterations
