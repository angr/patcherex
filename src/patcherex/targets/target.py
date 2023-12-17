class Target:
    target_classes = []

    def __init__(self, p, binary_path):
        self.binary_path = binary_path
        self.p = p

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        cls.target_classes.append(cls)

    @classmethod
    def detect_target(cls, p, binary_path):
        for target_class in cls.target_classes:
            if target_class.detect_target(binary_path):
                return target_class(p, binary_path)
        raise ValueError("Unknown target")

    def get_component(self, component_name, component_opts):
        return getattr(self, f"get_{component_name}")(component_opts)
