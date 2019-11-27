def create_copy_of_array(src):
    dst = [None]*len(src)
    for i in range(len(src)):
        dst[i] = src[i]
    return dst

