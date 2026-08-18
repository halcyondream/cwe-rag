from abc import ABC, abstractmethod


class IHook(ABC):
    @abstractmethod
    def run(self):
        pass

    @abstractmethod
    def assert_success(self):
        pass


class SequentialRunner:
    def __init__(self):
        self.hooks: list[IHook] = []

    def register(self, hook: type[IHook], **kwargs):
        new_hook = hook(**kwargs)
        self.hooks.append(new_hook)

    def run(self):
        for hook in self.hooks:
            hook.run()
