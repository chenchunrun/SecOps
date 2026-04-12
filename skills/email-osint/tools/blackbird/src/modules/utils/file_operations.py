import os


def isFile(fileName):
    return os.path.isfile(fileName)


def getLinesFromFile(fileName):
    try:
        with open(fileName, encoding='utf-8', errors='ignore') as f:
            lines = f.read().splitlines()
            return lines
    except:
        return False
