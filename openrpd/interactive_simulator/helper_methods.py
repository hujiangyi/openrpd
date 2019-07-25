# Copyright (c) VECTOR TECHNOLOGIES SA Gdynia, Poland, and
#                    Cable Television Laboratories, Inc. ("CableLabs")
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#


def merge_statuses(dict1, dict2):
    for key in dict2:
        if key in dict1:
            try:
                dict1[key].append(dict2[key])
            except AttributeError:
                dict1[key] = [dict1[key], dict2[key]]
        else:
            dict1[key] = [dict2[key]]


def merge_attributes(dict1, dict2):
    nested1 = dict1.pop("nested_attrs", [])
    nested2 = dict2.pop("nested_attrs", [])
    passed1 = dict1.pop("passed_attrs", [])
    passed2 = dict2.pop("passed_attrs", [])
    for key in dict1:
        dict2[key] = dict1[key]
    dict2["nested_attrs"] = nested1 + nested2
    dict2["passed_attrs"] = passed1 + passed2
    return dict2


def overwrite_file_attrs(command_attrs, file_attrs):
    if command_attrs:
        for attr in command_attrs:
            c_name, c_value = attr.split("=")
            for file_attr in list(file_attrs):
                if file_attr:
                    f_name, f_value = file_attr.split("=")
                    if c_name == f_name:
                        file_attrs.remove(file_attr)


def parse_nested_attr(attr):
    path, value = attr.split("=")
    attributes = []
    splitted_path = path.split(".")
    for name in splitted_path:
        if name.count("[") == 1 and name.count("]"):
            repeated_name, repeated_index = name.split("[")
            attributes.append({"name": repeated_name, "is_repeated": True, "index": repeated_index.replace("]", "")})
        else:
            attributes.append({"name": name, "is_repeated": False})
    return attributes, value


def parse_dict_attr(attr):
    name, tail = attr.split("[")
    index, value = tail.replace("]", "").split("=")
    return name, index, value


def get_attr_name(attr):
    if attr.count("=") == 1:
        return attr.split("=")[0]
    return attr


def handle_prefixes(attrs):
    if not attrs:
        return []
    current_prefix = ""
    for index, attr in enumerate(attrs):
        if attr and attr[0].isupper() and current_prefix:
            attrs[index] = "{}.{}".format(current_prefix, attr)
        elif attr and attr[0:6] == "prefix" and attr.count("=") == 1:
            current_prefix = attr.split("=")[1]

    return [name for name in attrs if name[0:6] != "prefix"]


def parse_scenario_attrs(p_attrs):
    attrs = {}
    nested_attrs = []
    passed_attrs = []
    for attr in p_attrs:
        passed_attrs.append(get_attr_name(attr))
        if "." in attr and attr.count("=") == 1:
            nested_attrs.append(parse_nested_attr(attr))
        elif attr.count("=") == 1:
            name, value = attr.split("=")
            attrs[name] = value
        else:
            print attr
    attrs["nested_attrs"] = nested_attrs
    attrs["passed_attrs"] = passed_attrs
    return attrs
