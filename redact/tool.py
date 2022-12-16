import glob
import hashlib
import json
import os
from time import sleep
from cestcrypto import generate_ECDH_key, to_pub, dohash

TOOL_FOLDER = "/pod-storage/redaction/"
READABLE_TOE = "/toe/"
READABLE_REPORT = "/toe/report/report.json"

def executeRemoveInstructions(instructions, report):
    for item in instructions.items():
        key = item[0]
        print("KEY: {}".format(key), flush=True)
        if isinstance(report, list):
            print("report is list: {}".format(report), flush=True)
            key = int(item[0])
        if (item[1] == True):
            print("item is list: {}".format(item[1]), flush=True)
            report[key] = "***Hidden by the Vendor***"
        elif not (type(item[1]) is dict):
            print("malformenddd: {}".format(type(item[1])), flush=True)
            raise Exception('Malformed', 'Instructions')
        else:
            print("deeper: item{} report:".format(item[1], report[key]), flush=True)
            executeRemoveInstructions(item[1], report[key])


def run_tool(result_folder, argument, tools_are_silent):
    print('runtool({}, {}, {})'.format(result_folder, argument, tools_are_silent), flush=True)

    try:
        f = open(READABLE_REPORT, 'r')
        json_blob = json.loads(f.read())
    except IOError:
        # TODO add to error folder
        print('Error While Opening the file!' + READABLE_REPORT)
        raise Exception("Unable to open file")


    report = json.loads(json_blob["report"])
    remove_instructions = json_blob["remove_instructions"]

    print("REPORT type {} remove_instructions: {}".format(type(report), type(remove_instructions)), flush=True)

    executeRemoveInstructions(remove_instructions, report)

    print("DID EXECUTE")

    return report
