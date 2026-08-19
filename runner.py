from abc import ABC, abstractmethod


class IHook(ABC):
    """
    Interface used for "pipeline" hooks used in a runner.
    """

    @abstractmethod
    def run(self):
        """
        Defines the main execution logic.
        """

    @abstractmethod
    def assert_success(self):
        """
        Perform assertions to define success or failure conditions.
        Use in tandem with a run to assert the overall success or failure
        of the execution.
        """

    @abstractmethod
    def clean(self):
        """
        Define a clean state prior to a run.
        """


class SequentialRunner:
    """
    Simple iterative runner.
    """

    def __init__(self):
        self.hooks: list[IHook] = []

    def register(self, hook):
        self.hooks.append(hook)

    def run(self):
        for hook in self.hooks:
            hook.clean()
            hook.run()
            hook.assert_success()
