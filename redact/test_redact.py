#!/usr/bin/env python3

import json


report = json.loads("""{
  "results": {
    "array": [
      {
        "bcd": "bla"
      },
      "123",
      "234",
      "345",
      "456"
      ],
    "@version": "2",
    "cppcheck": {
      "@version": "2.7"
    },
    "errors": {
      "error": {
        "@id": "unknownMacro",
        "@severity": "error",
        "@msg": "There is an unknown macro here somewhere. Configuration is required. If ED3 is a macro then please configure it.",
        "@verbose": "There is an unknown macro here somewhere. Configuration is required. If ED3 is a macro then please configure it.",
        "@file0": "/toe/OPEN5GS_SMF_ATSEC_FOLDER/binding.c",
        "location": {
          "@file": "/toe/OPEN5GS_SMF_ATSEC_FOLDER/context.h",
          "@line": "163",
          "@column": "1"
        }
      }
    }
  }
}""")


remove_instructions = json.loads("""{
  "results": {
    "array":
      {
        "0": {
          "bcd": true
        },
        "3": true
      }
      ,
    "errors": {
      "error": {
        "@id": true,
        "location": true
      }
    }
  }
}""")


def recur(instructions, report):
    for item in instructions.items():
      key = item[0]
      if isinstance(report, list):
        key = int(item[0])
      #print(type(key))
      if (item[1] == True):
          report[key] = "***DELETED BY CEST***"
      elif not (type(item[1]) is dict):
          raise Exception('Malformed', 'Instructions')
      else:
          #print(type(report[item[0]]))
          recur(item[1], report[key])


recur(remove_instructions, report)
print(report)
