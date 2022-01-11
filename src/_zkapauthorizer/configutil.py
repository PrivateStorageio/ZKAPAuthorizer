# Copyright 2021 PrivateStorage.io, LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Basic utilities related to the Tahoe configuration file.
"""


def _merge_dictionaries(dictionaries):
    """
    Collapse a sequence of dictionaries into one, with collisions resolved by
    taking the value from later dictionaries in the sequence.

    :param [dict] dictionaries: The dictionaries to collapse.

    :return dict: The collapsed dictionary.
    """
    result = {}
    for d in dictionaries:
        result.update(d)
    return result


def _tahoe_config_quote(text):
    """
    Quote **%** in a unicode string.

    :param unicode text: The string on which to perform quoting.

    :return unicode: The string with ``%%`` replacing ``%``.
    """
    return text.replace("%", "%%")


def config_string_from_sections(divided_sections):
    """
    Get the .ini-syntax unicode string representing the given configuration
    values.

    :param [dict] divided_sections: The configuration to use to generate the
        string.  Each ``dict`` maps a top-level section name to a ``dict`` of
        key/value pairs.  Dictionaries may have overlapping top-level
        sections, in which case the section items are merged (for collisions,
        last value wins).
    """
    sections = _merge_dictionaries(divided_sections)
    return "".join(
        list(
            "[{name}]\n{items}\n".format(
                name=name,
                items="\n".join(
                    "{key} = {value}".format(key=key, value=_tahoe_config_quote(value))
                    for (key, value) in contents.items()
                ),
            )
            for (name, contents) in sections.items()
        )
    )
