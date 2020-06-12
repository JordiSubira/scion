#!/usr/bin/env python
"""
:mod:`write_topo` -- YANG topology.json generator
=================================================

This module suscribes for changes to the scion-topology data store and
changes the topology.json files
"""
##################################################
# Copyright 2019 ETH Zurich
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
##################################################
##################################################
# This script uses sysrepo swig module in order to take the configuration for
# one ISD-AS.
# It suscribes for changes on the topology data-store and writes the
# topology.json file
# into every service directory (i.e. Border routers, beacon servers, ...).
##################################################
##################################################
# Author: Jordi Subira
# Email: jonieto@student.ethz.ch
##################################################

import json
import os
import string
import traceback
from typing import Dict, Any, Union, Optional


import sysrepo as sr  # type: ignore
import sysrepo_type as sr_types


DIR_APP = os.getcwd()
DIR_HOME: Optional[str] = os.getenv("HOME")
if DIR_HOME is None:
    raise Exception("No defined HOME env.")

DIR_ISD_AS_FORMAT = "gen/ISD{}/AS{}/"
DIR_SCION: str = os.path.join(DIR_HOME, "go/src/github.com/scionproto/scion/")

AddrPortType = Dict[str, Union[int, str]]
TopologyDictType = Dict[str, Union[Dict[str, Any], str, int, bool]]


# Following function are helpers to treat strings for parsing:


def _conversion_helper(yang_str: str) -> str:
    # E.g converting isd-as -> to Isd_as ;
    if yang_str in ("isd-as", "mtu"):
        return yang_str.replace('-', '_').upper()
    # from border-routers to BorderRouters
    yang_str = string.capwords(yang_str, '-')
    return yang_str.replace('-', '')


def _get_key_list_path(x_path: str) -> str:
    # Asuming one key at the moment
    return x_path.split("'")[-2]


def _erase_prefix(yang_str: str) -> str:
    return yang_str.split(":")[1]


def _get_last_node_name(x_path: str) -> str:
    last_node: str = x_path.split(":")[-1].split("/")[-1]
    last_node = _conversion_helper(last_node)
    return last_node

# End helper for strings


def _create_list(session, x_path):
    json_list = list()

    values = session.get_items(x_path)

    if values is not None:
        for i in range(values.val_cnt()):
            valType = values.val(i).type()
            valXPath = values.val(i).xpath()
            if valType == sr_types.SR_CONTAINER_T:
                name = _get_last_node_name(valXPath)
                print("Container Name: ", name)
                json_list.append(_create_dict(session, valXPath))
            elif valType == sr_types.SR_LIST_T:
                key = _get_last_node_name(valXPath)
                print(valXPath)
                print("Key: ", key)
                json_list.append(_create_list(session, valXPath))
            else:  # assume leaf, treat for error
                name = _get_last_node_name(valXPath)
                print("Leaf Name: ", name)
                if name != "ISD_AS":
                    json_list.append(values.val(i).val_to_string())

    return {"Nets": json_list}


def _create_dict(session, x_path: str) -> TopologyDictType:
    # Recursive function to create a dict out of the data store configuration.

    json_obj: TopologyDictType = dict()

    values = session.get_items(x_path)
    if values is None:
        return json_obj

    name: str
    for i in range(values.val_cnt()):
        val_type: str = values.val(i).type()
        val_xpath: str = values.val(i).xpath()
        print(val_xpath)
        if val_type == sr_types.SR_CONTAINER_T:
            name = _get_last_node_name(val_xpath)
            aux_dict: TopologyDictType = _create_dict(session,
                                                      val_xpath + "/*")
            print(aux_dict)
            json_obj[name] = aux_dict

        elif val_type == sr_types.SR_LIST_T:  # assume leaf-list
            key: str = _get_key_list_path(val_xpath)
            json_obj[key] = _create_list(session, val_xpath + "/*")

        elif val_type in (sr_types.SR_UINT16_T, sr_types.SR_UINT32_T,
                          sr_types.SR_UINT64_T):
            name = _get_last_node_name(val_xpath)
            json_obj[name] = int(values.val(i).val_to_string())
        else:
            raise ValueError("Unexpected type for " + val_xpath)

    return json_obj


def _write_isd_as(json_topo: Dict[str, Any]) -> None:
    # This function writes the topology.json
    # file within every directory service

    topo_file = open('sig.json', 'w+')
    topo_file.truncate(0)
    json_st: str = json.dumps(json_topo, indent=4)
    topo_file.write(json_st)
    topo_file.close()
    print("------ SIG created in " + " ------")


def _change_current_config(session, module_name: str) -> None:
    # Function to write sig file

    top_cont_list = module_name.split("-")
    select_xpath: str = "/" + module_name + ":" + top_cont_list[1]

    select_xpath = select_xpath + "/*"

    # print_current_config(session, module_name)
    try:
        json_obj: TopologyDictType = _create_dict(session, select_xpath)
    except Exception:
        traceback.print_exc()
        raise

    if not json_obj:
        print("No changes applied.")
        return

    # _write_isd_as(json_obj)
    print(json.dumps(json_obj, indent=4))
    print("END Write.")


def print_current_config(session, module_name) -> None:
    select_xpath: str = "/" + module_name + ":*//*"

    values = session.get_items(select_xpath)
    if values is None:
        print("Empty Data Store")
        return

    for i in range(values.val_cnt()):
        print(values.val(i).to_string(), end='')


def module_change_cb(sess, module_name, event, private_ctx):
    # Callback for subscribed client of given session whenever configuration
    # changes.

    print("\n\n ========== CONFIG HAS CHANGED, "
          "CURRENT RUNNING CONFIG: ==========\n")

    _change_current_config(sess, module_name)

    return sr.SR_ERR_OK


def main():
    module_name: str = "scion-sig"

    # connect to sysrepo
    conn = sr.Connection(module_name)
    # start session
    sess = sr.Session(conn)
    # subscribe for changes in running config */
    subscribe = sr.Subscribe(sess)
    # setting callback
    subscribe.module_change_subscribe(module_name,
                                      module_change_cb, None, 0,
                                      sr.SR_SUBSCR_DEFAULT |
                                      sr.SR_SUBSCR_APPLY_ONLY)

    print("\n\n ========== READING STARTUP CONFIG: ==========\n")
    print_current_config(sess, module_name)

    _change_current_config(sess, module_name)
    print("\n\n ========== STARTUP CONFIG APPLIED AS RUNNING ==========\n")

    sr.global_loop()

    print("Application exit requested, exiting.\n")


if __name__ == '__main__':
    main()
