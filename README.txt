Seance

Requirements:
    angr and its requirements, see https://docs.angr.io/introductory-errata/install.
    As angr suggests using a virtual environment, the same recommendation is given here.
    Bear in mind, then, that you need to be running Seance in the same virtual environment
    where you have angr installed. 


Usage:
    
    Basic Use: 'seance.py -s <list,of,symbols> -b <name_of_binary>' to emulate the
        given symbols in the given binary, and produce outut of memory and
        register accesses + CFGs
    
    Use 'seance.py -h' to enumerate command line options which you will probably need to use.

    'seance_api.py' contains most of the actual functionality for execution and graph 
        generation you might need to build off of Seance. 'seance_find_parameters.py' 
        contains most of the post-processing functionality.

    Use 'seance_find_parameters.py -j <emulation_info_json>' to output every memory
        address accessed, and a list of offsets from those addresses that were
        also accessed. This script is used to do this automatically for Seance as well.

    'Seance_Explore.py' is a custom exploration technique. Add to 
        angr/exploration_techniques and, in that directory, edit __init__.py to 
        include Custom Limit like any other exploration technique. The code, in 
        its current form does not make use of or require this.

    'seance_workflow.txt' contains (hopefully) fairly explicit instructions on how to 
        go from having a set of binaries you want to analyse to having a database and
        comparisions to that database from one or more files. This is most likely what 
        you want to be doing.
 
