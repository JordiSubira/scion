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

import os
import re
import string
import traceback
from typing import Dict, Any, Union, Optional

import toml
import sysrepo as sr  # type: ignore
import sysrepo_type as sr_types

R_NUMBER = re.compile(r'[0-9]+')
R_BR = re.compile(r'br\S*')


DIR_APP = os.getcwd()
DIR_HOME: Optional[str] = os.getenv("HOME")
if DIR_HOME is None:
    raise Exception("No defined HOME env.")

DIR_ISD_AS_FORMAT = "gen/ISD{}/AS{}/"
DIR_SCION: str = os.path.join(DIR_HOME, "go/src/github.com/scionproto/scion/")

LIST_SERVICES = ["BeaconService", "BorderRouters", "BeaconService",
                 "PathService", "CertificateService"]
TUPLE_ADDR_CONT = ("server", "prometheus", "agent", "public", "bind")

AddrPortType = Dict[str, Union[int, str]]
TopologyDictType = Dict[str, Union[Dict[str, Any], str, int, bool]]


# Following function are helpers to treat strings for parsing:


def _conversion_helper(yang_str: str) -> str:
    if yang_str == "id":
        return yang_str.upper()
    # from border-routers to BorderRouters
    yang_str = string.capwords(yang_str, '-')
    yang_str = yang_str.replace('Db', 'DB')
    return yang_str.replace('-', '')


def _get_key_list_path(x_path: str) -> str:
    # Asuming one key at the moment
    return x_path.split("'")[-2]


def _erase_prefix(yang_str: str) -> str:
    return yang_str.split(":")[1]


def _get_last_node_name(x_path: str, is_leaf: bool = False) -> str:
    last_node: str = x_path.split(":")[-1].split("/")[-1]
    last_node = last_node.replace('sd-client', 'sd_client')
    last_node = _conversion_helper(last_node)
    if not is_leaf:
        last_node = last_node[:1].lower() + last_node[1:]
    return last_node


# End helper for strings


def _aux_create_addr_dict(session, x_path: str,
                          toml_obj: TopologyDictType) -> None:
    # Helper function to parse from YANG node names to
    # JSON node names for border router.

    values = session.get_items(x_path + "/*")

    print(x_path)

    name: str

    port: str = ""
    ipv4: str = ""
    isd: str = ""

    for i in range(values.val_cnt()):
        val_type: str = values.val(i).type()
        val_xpath: str = values.val(i).xpath()
        print(val_xpath)
        if val_type not in (sr_types.SR_UINT16_T, sr_types.SR_STRING_T):
            raise ValueError("Not expected sysrepo type on address structure")
        if val_type == sr_types.SR_UINT16_T:
            name = _get_last_node_name(val_xpath, True)
            if name != "L4Port":
                mess: str = "Not expected value for " + val_xpath
                raise ValueError(mess)
            port = values.val(i).val_to_string()
            print(port)
        else:  # must be string for name or address
            name = _get_last_node_name(val_xpath, True)
            if name == "Isd":
                isd = values.val(i).val_to_string()
            elif name == "Address":
                ipv4 = values.val(i).val_to_string()
            else:
                mess: str = "Not expected value for " + val_xpath
                raise ValueError(mess)

    if ipv4 != "" and port != "":
        container: str = _get_last_node_name(x_path)
        print(container)

        if container == "server":
            container = "Address"

        if isd != "":
            toml_obj[string.capwords(container)] = isd + "," + ipv4 + ":" + port
        else:
            toml_obj[string.capwords(container)] = ipv4 + ":" + port


def _create_dict(session, x_path: str) -> TopologyDictType:
    # Recursive function to create a dict out of the data store configuration.

    toml_obj = dict()

    values = session.get_items(x_path)
    if values is None:
        return toml_obj

    name: str
    for i in range(values.val_cnt()):
        val_type: str = values.val(i).type()
        val_xpath: str = values.val(i).xpath()
        print(val_xpath)
        if val_type == sr_types.SR_CONTAINER_T:
            name = _get_last_node_name(val_xpath)
            if name in TUPLE_ADDR_CONT:
                _aux_create_addr_dict(session, val_xpath, toml_obj)
            else:
                aux_dict: TopologyDictType = _create_dict(session,
                                                          val_xpath + "/*")
            # Checking not to write empty
                print(aux_dict)
                if aux_dict:
                    toml_obj[name] = aux_dict

        elif val_type in (sr_types.SR_UINT16_T, sr_types.SR_UINT32_T,
                          sr_types.SR_INT16_T):
            name = _get_last_node_name(val_xpath, True)
            toml_obj[name] = int(values.val(i).val_to_string())

        elif val_type == sr_types.SR_BOOL_T:
            name = _get_last_node_name(val_xpath, True)
            if values.val(i).val_to_string() == "true":
                toml_obj[name] = True
            else:
                toml_obj[name] = False

        else:  # assume leaf, treat for error TODO: treat numbers
            name = _get_last_node_name(val_xpath, True)
            toml_obj[name] = values.val(i).val_to_string()

    return toml_obj


def _change_current_config(session, module_name: str) -> None:
    # Function to write topology file in DIR_BR, apply config (run),
    # test and stop.

    top_cont_list = module_name.split("-")
    select_xpath: str = "/" + module_name + ":" + top_cont_list[2]

    if len(top_cont_list) > 3:
        select_xpath = select_xpath + "-" + top_cont_list[3]

    select_xpath = select_xpath + "/*"
    # print_current_config(session, module_name)
    try:
        toml_obj = _create_dict(session, select_xpath)
    except Exception:
        traceback.print_exc()
        raise

    if not toml_obj:
        print("No changes applied.")
        return

    print(toml.dumps(toml_obj))
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

    #print_current_config(sess, module_name)
    _change_current_config(sess, module_name)

    return sr.SR_ERR_OK


def main():
    module_name_bs: str = "scion-toml-beacon-server"
    module_name_br: str = "scion-toml-border-router"
    module_name_cs: str = "scion-toml-certificate-server"
    module_name_ps: str = "scion-toml-path-server"
    module_name_sd: str = "scion-toml-sciond"

    # connect to sysrepo
    conn = sr.Connection("scion-toml")
    # start session
    sess = sr.Session(conn)
    # subscribe for changes in running config */
    subscribe = sr.Subscribe(sess)
    # setting callback
    subscribe.module_change_subscribe(module_name_bs,
                                      module_change_cb, None, 0,
                                      sr.SR_SUBSCR_DEFAULT |
                                      sr.SR_SUBSCR_APPLY_ONLY)

    subscribe.module_change_subscribe(module_name_br,
                                      module_change_cb, None, 0,
                                      sr.SR_SUBSCR_DEFAULT |
                                      sr.SR_SUBSCR_APPLY_ONLY)

    subscribe.module_change_subscribe(module_name_cs,
                                      module_change_cb, None, 0,
                                      sr.SR_SUBSCR_DEFAULT |
                                      sr.SR_SUBSCR_APPLY_ONLY)

    subscribe.module_change_subscribe(module_name_ps,
                                      module_change_cb, None, 0,
                                      sr.SR_SUBSCR_DEFAULT |
                                      sr.SR_SUBSCR_APPLY_ONLY)

    subscribe.module_change_subscribe(module_name_sd,
                                      module_change_cb, None, 0,
                                      sr.SR_SUBSCR_DEFAULT |
                                      sr.SR_SUBSCR_APPLY_ONLY)

    print("\n\n ========== READING STARTUP CONFIG: ==========\n")
    print_current_config(sess, module_name_bs)
    print_current_config(sess, module_name_br)
    print_current_config(sess, module_name_cs)
    print_current_config(sess, module_name_ps)
    print_current_config(sess, module_name_sd)

    # _change_current_config(sess, module_name)
    # print("\n\n ========== STARTUP CONFIG APPLIED AS RUNNING ==========\n")

    sr.global_loop()

    print("Application exit requested, exiting.\n")


if __name__ == '__main__':
    main()
