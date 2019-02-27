import os

def get_tor_c_files(tor_topdir, exclude_dirs):
    """
    Return a list with the .c filenames we want to get metrics of.
    """
    files_list = []

    for root, directories, filenames in os.walk(tor_topdir):
        for filename in filenames:
            # We only care about .c files
            if not filename.endswith(".c"):
                continue

            # Exclude the excluded paths
            full_path = os.path.join(root,filename)
            if any(exclude_dir in full_path for exclude_dir in exclude_dirs):
                continue

            files_list.append(full_path)

    return files_list

