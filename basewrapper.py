#!/usr/bin/env python

import abc
import subprocess

try:
    import glog as log
except ImportError:
    import logging as log


class ToolWrapper(object):
    """Abstract lazy-extracting tool wrapper.

    Delays calling extract() until the first time the tool is actually called,
    which can greatly reduce startup overhead of scripts with embedded tools.

    To use, subclass this and override extract() at a minimum.  Example:

        import gflags

        gflags.DEFINE_string(
            "huge_binary_path", None,
            "Path to huge_binary. Default is to use embedded version.")

        FLAGS = gflags.FLAGS

        class HugeBinary(ToolWrapper):
            def extract(self):
                return (
                    FLAGS.huge_binary_path or
                    resources.get_resource_filename(
                        "path_to_resource_within_runfiles")
                )

    Then you can use it:

        >>> hugebin = HugeBinary()
        >>> hugebin.call(["--foo", "--bar"])
    """
    __metaclass__ = abc.ABCMeta

    def __init__(self, bin_path=None):
        # If bin_path is passed explicitly, store it (obviously)
        self.__bin_path = bin_path
        # Otherwise, to avoid extracting the large helm binary on every
        # startup, defer fully resolving its path until the first time it is
        # needed.

    @abc.abstractmethod
    def extract(self):
        pass

    @property
    def bin_path(self):
        if not self.__bin_path:
            self.__bin_path = self.extract()
            if callable(getattr(self, "post_extract", None)):
                self.post_extract()
        return self.__bin_path

    @bin_path.setter
    def bin_path(self, path):
        self.__bin_path = path

    def call(self, args, *popenargs, **kwargs):
        """Run the wrapped executable.

        If necessary, extract it from the running .par and cache the location.

        Args:
            args: List or other sequence of strings to be commandline args
            *popenargs, **kwargs: Passed directly to subprocess.call
        """
        cmd = [self.bin_path] + list(args)
        log.debug("Running: %s", cmd)
        return subprocess.call(cmd, *popenargs, **kwargs)

    def check_call(self, args, *popenargs, **kwargs):
        """Run the wrapped executable.

        If necessary, extract it from the running .par and cache the location.

        Args:
            args: List or other sequence of strings to be commandline args
            *popenargs, **kwargs: Passed directly to subprocess.check_call
        """
        cmd = [self.bin_path] + list(args)
        log.debug("Running: %s", cmd)
        return subprocess.check_call(cmd, *popenargs, **kwargs)

    def check_output(self, args, *popenargs, **kwargs):
        """Run the wrapped executable.

        If necessary, extract it from the running .par and cache the location.

        Args:
            args: List or other sequence of strings to be commandline args
            *popenargs, **kwargs: Passed directly to subprocess.check_output
        """
        cmd = [self.bin_path] + list(args)
        log.debug("Running: %s", cmd)
        return subprocess.check_output(cmd, *popenargs, **kwargs)
