from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class SleepArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="interval",
                type=ParameterType.Number,
                description="Callback interval in seconds (0 = fast-poll).",
                default_value=60,
            ),
            CommandParameter(
                name="jitter",
                type=ParameterType.Number,
                description="Jitter as a percentage of interval (0-100). Applied as a random addition.",
                default_value=10,
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            if self.command_line.strip().startswith("{"):
                self.load_args_from_json_string(self.command_line)
            else:
                parts = self.command_line.strip().split()
                self.add_arg("interval", int(parts[0]))
                if len(parts) > 1:
                    self.add_arg("jitter", int(parts[1]))

    async def parse_dictionary(self, dictionary_arguments):
        self.load_args_from_dictionary(dictionary_arguments)


class SleepCommand(CommandBase):
    cmd = "sleep"
    needs_admin = False
    help_cmd = "sleep <interval_secs> [jitter_pct]"
    description = (
        "Update callback interval and jitter mid-op. "
        "Interval is in seconds; jitter is a percentage (0-100) added randomly to each sleep. "
        "Takes effect after the current tasking round completes."
    )
    version = 1
    author = "@PatchRequest"
    attackmapping = []
    argument_class = SleepArguments
    attributes = CommandAttributes(
        suggested_command=False,
        builtin=True,
        supported_os=[SupportedOS.Windows],
    )
    script_only = False

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        interval = taskData.args.get_arg("interval")
        jitter = taskData.args.get_arg("jitter")
        return PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
            DisplayParams=f"{interval}s jitter {jitter}%",
        )

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
