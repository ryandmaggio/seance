import os
import json

def truncate(name):
    while len(name) >=250:
        print("Truncating file %s" %name)
        name = name[int(len(name)/2):]
        
    return name

def make_json(name, directory, data):
    fname = os.path.join(directory, name)
    try:
        f = open(fname, 'w')
    except:
       f = None
       print("Could not make file %s" %fname)
    if f != None:    
        f.write(json.dumps(data))
        f.close()
