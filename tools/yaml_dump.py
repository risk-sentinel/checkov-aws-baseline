"""A dumper whose output Ruby's Psych reads back as the same data.

PyYAML wraps a long plain scalar at spaces. When a wrap lands so that a
continuation line begins with ':', Psych reads that line as a Ruby Symbol and
YAML.safe_load raises Psych::DisallowedClass -- the file is valid YAML to
PyYAML and unloadable to the tool that actually consumes it.

Both happened here: two `note:` values mentioning an InSpec column (":cluster_id")
wrapped exactly there. So any string that could wrap onto a colon is emitted
double-quoted instead, where the leading colon is unambiguous.
"""
import yaml


def _needs_quoting(text):
    return "\n" in text or any(w.startswith(":") for w in text.split())


class PsychSafeDumper(yaml.SafeDumper):
    pass


def _str_representer(dumper, data):
    if _needs_quoting(data):
        return dumper.represent_scalar("tag:yaml.org,2002:str", data, style='"')
    return dumper.represent_scalar("tag:yaml.org,2002:str", data)


PsychSafeDumper.add_representer(str, _str_representer)


def dump(doc, width=100):
    return yaml.dump(doc, Dumper=PsychSafeDumper, sort_keys=True,
                     default_flow_style=False, width=width, allow_unicode=True)
