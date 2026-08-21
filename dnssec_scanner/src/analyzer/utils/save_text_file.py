import os


def save(table: str, filename: str, root_path: str):
    path_to_save = os.path.join(root_path, filename)
    with open(path_to_save, "w", encoding="utf-8") as tex_file:
        tex_file.write(table)
