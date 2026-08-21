import textwrap


def wrap_labels(labels, width=15):
    return ['\n'.join(textwrap.wrap(label, width)) for label in labels]
