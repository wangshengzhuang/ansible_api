# -*- coding: utf-8 -*-
# Author: xqzt
import json
from collections import Mapping, namedtuple
from ansible import constants as C
from ansible.inventory.host import Host
from ansible.vars.manager import VariableManager  # 用于管理变量的类，包括主机，组，扩展等变量
from ansible.inventory.manager import InventoryManager  # 用于创建和管理inventory，倒入inventory文件
from ansible.parsing.dataloader import DataLoader
from ansible.errors import AnsibleError
from ansible.playbook.play import Play
from ansible.executor.task_queue_manager import TaskQueueManager  # ad-hoc Ansible底层用到的任务队列
from ansible.plugins.callback import CallbackBase  # 回调基类，用来定义回调事件，比如返回失败成功等信息
from ansible.executor.playbook_executor import PlaybookExecutor  # 执行playbook
from ansible.utils.vars import load_extra_vars
from ansible.utils.vars import load_options_vars


class HostInventory(Host):
    def __init__(self, host_data):
        self.host_data = host_data
        hostname = host_data.get('hostname') or host_data.get('ip')
        port = host_data.get('port') or 22
        super(HostInventory, self).__init__(hostname, port)
        self.__set_required_variables()
        self.__set_extra_variables()

    def __set_required_variables(self):
        host_data = self.host_data
        self.set_variable('ansible_host', host_data['ip'])
        self.set_variable('ansible_port', host_data['port'])

        if host_data.get('username'):
            self.set_variable('ansible_user', host_data['username'])

        if host_data.get('password'):
            self.set_variable('ansible_ssh_pass', host_data['password'])

        if host_data.get('private_key'):
            self.set_variable('ansible_ssh_private_key_file', host_data['private_key'])

        become = host_data.get("become", False)
        if become:
            self.set_variable("ansible_become", True)
            self.set_variable("ansible_become_method", become.get('become_method', 'sudo'))
            self.set_variable("ansible_become_user", become.get('become_user', 'root'))
            self.set_variable("ansible_become_pass", become.get('become_pass', ''))
        else:
            self.set_variable("ansible_become", False)

    def __set_extra_variables(self):
        for k, v in self.host_data.get('vars', {}).items():
            self.set_variable(k, v)

    def __repr__(self):
        return self.name


class CustomInventory(InventoryManager):

    def __init__(self, resource=None):
        self.resource = resource
        self.loader = DataLoader()
        self.variable_manager = VariableManager()
        super(CustomInventory, self).__init__(self.loader)

    def get_group(self, name):
        return self._inventory.groups.get(name, None)

    def parse_sources(self, cache=False):
        group_all = self._inventory.groups.get('all')
        ungrouped = self._inventory.groups.get('ungrouped')
        if isinstance(resource, list):
            for host_data in self.resource:
                host = HostInventory(host_data=host_data)
                self.hosts[host_data['hostname']] = host
                groups_data = host_data.get('groups')
                if groups_data:
                    for group_name in groups_data:
                        group = self.get_group(group_name)
                        if group is None:
                            self.add_group(group_name)
                            group = self.get_group(group_name)
                        group.add_host(host)
                else:
                    ungrouped.add_host(host)
                group_all.add_host(host)

        elif isinstance(resource, dict):
            for k, v in self.resource.items():
                group = self.get_group(k)
                if group is None:
                    self.add_group(k)
                    group = self.get_group(k)

                if 'hosts' in v:
                    if not isinstance(v['hosts'], list):
                        raise AnsibleError(
                            "You defined a group '%s' with bad data for the host list:\n %s" % (group, v))
                    for host_data in v['hosts']:
                        host = HostInventory(host_data=host_data)
                        self.hosts[host_data['hostname']] = host
                        group.add_host(host)

                if 'vars' in v:
                    if not isinstance(v['vars'], dict):
                        raise AnsibleError("You defined a group '%s' with bad data for variables:\n %s" % (group, v))

                    for x, y in v['vars'].items():
                        self._inventory.groups[k].set_variable(x, y)


class ModuleResultsCollector(CallbackBase):

    def __init__(self, *args, **kwargs):
        super(ModuleResultsCollector, self).__init__(*args, **kwargs)
        self.host_ok = {}
        self.host_unreachable = {}
        self.host_failed = {}

    def v2_runner_on_unreachable(self, result):
        self.host_unreachable[result._host.get_name()] = result
        print '[%s]: UNREACHABLE! =>{"changed": %s, "msg": "%s", "unreachable": %s} ' % (
            result._host.get_name(), result._result['changed'], result._result['msg'], result._result['unreachable'])

    def v2_runner_on_ok(self, result, *args, **kwargs):
        self.host_ok[result._host.get_name()] = result
        print "%s: | SUCCESS    %s" % (result._host.get_name(), result._result['stdout'])

    def v2_runner_on_failed(self, result, *args, **kwargs):
        self.host_failed[result._host.get_name()] = result
        print "%s: | FAILED     %s" % (result._host.get_name(), result._result['stderr'])


class PlayBookResultsCollector(CallbackBase):
    """
    自定义状态回调输出内容
    具体方法参考: CallbackBase 类
    result 包含:
        '_check_key', '_host', '_result', '_task', '_task_fields',
        'is_changed', 'is_failed', 'is_skipped', 'is_unreachable', 'task_name'
    """
    CALLBACK_VERSION = 2.0

    def __init__(self, *args, **kwargs):
        super(PlayBookResultsCollector, self).__init__(*args, **kwargs)
        self.task_ok = {}
        self.task_skipped = {}
        self.task_failed = {}
        self.task_status = {}
        self.task_unreachable = {}
        self.task_changed = {}
        self.status_no_hosts = False

    def v2_runner_on_ok(self, result, *args, **kwargs):
        host = result._host.get_name()
        self.runner_on_ok(host, result._result)
        if not self.task_ok.get(host):
            self.task_ok[host] = list()
        self.task_ok[host].append(result)
        print "ok: [%s] " % (result._host.get_name())

    def v2_runner_on_failed(self, result, *args, **kwargs):
        host = result._host.get_name()
        self.runner_on_failed(host, result._result)
        if not self.task_failed.get(host):
            self.task_failed[host] = list()
        self.task_failed[host].append(result)
        print "%s: TASK [%s] faild" % (result._host.get_name(), result.task_name)

    def v2_runner_on_unreachable(self, result):
        # 主机无法访问
        host = result._host.get_name()
        self.runner_on_unreachable(host, result._result)
        if not self.task_unreachable.get(host):
            self.task_unreachable[host] = list()
        self.task_unreachable[host].append(result)
        print 'fatal: [%s]: UNREACHABLE! =>{"changed": %s, "msg": "%s", "unreachable": %s} ' % (
            result._host.get_name(), result._result['changed'], result._result['msg'], result._result['unreachable'])

    def v2_runner_on_skipped(self, result):
        host = result._host.get_name()
        self.runner_on_skipped(host, result._result)
        if not self.task_skipped.get(host):
            self.task_skipped[host] = list()
        self.task_skipped[host].append(result)
        print "skipping: [%s] " % (result._host.get_name())

    def v2_runner_on_changed(self, result):
        host = result._host.get_name()
        self.runner_on_changed(host, result._result)
        if not self.task_changed.get(host):
            self.task_changed[host] = list()
        self.task_changed[host].append(result)
        print "changed: [%s] " % (result._host.get_name())

    def v2_playbook_on_no_hosts_matched(self):
        self.playbook_on_no_hosts_matched()
        self.status_no_hosts = True

    def v2_playbook_on_task_start(self, task, is_conditional):
        print("\nTASK [%s]" % task.get_name().strip()).ljust(100, '#')

    def v2_playbook_on_play_start(self, play):
        name = play.get_name().strip()
        if not name:
            msg = "PLAY"
        else:
            msg = "PLAY [%s]" % name

        print(msg)

    def v2_playbook_on_stats(self, stats):
        print "\nPLAY RECAP".ljust(100, '#')
        hosts = sorted(stats.processed.keys())
        for h in hosts:
            t = stats.summarize(h)
            self.task_status[h] = {
                "ok": t['ok'],
                "changed": t['changed'],
                "unreachable": t['unreachable'],
                "skipped": t['skipped'],
                "failed": t['failures']
            }
            print "%s               : ok=%d    changed=%d    unreachable=%d    failed=%d" % (
                h, t['ok'], t['changed'], t['unreachable'], t['failures'])


class AnsibleRunner(object):

    def __init__(
            self,
            hosts=C.DEFAULT_HOST_LIST,
            module_name=C.DEFAULT_MODULE_NAME,
            module_args=C.DEFAULT_MODULE_ARGS,
            forks=C.DEFAULT_FORKS,
            timeout=C.DEFAULT_TIMEOUT,
            pattern="all",
            remote_user=C.DEFAULT_REMOTE_USER,
            module_path=None,
            connection_type="smart",
            become=None,
            become_method=None,
            become_user=None,
            check=False,
            passwords=None,
            extra_vars=None,
            private_key_file=None,
            listtags=False,
            listtasks=False,
            listhosts=False,
            ssh_common_args=None,
            ssh_extra_args=None,
            sftp_extra_args=None,
            scp_extra_args=None,
            verbosity=None,
            syntax=False,
            redisKey=None,
            logId=None
    ):
        self.Options = namedtuple("Options", [
            'listtags', 'listtasks', 'listhosts', 'syntax', 'connection',
            'module_path', 'forks', 'remote_user', 'private_key_file', 'timeout',
            'ssh_common_args', 'ssh_extra_args', 'sftp_extra_args', 'scp_extra_args',
            'become', 'become_method', 'become_user', 'verbosity', 'check',
            'extra_vars', 'diff'
        ]
                                  )
        self.results_raw = {}
        self.pattern = pattern
        self.module_name = module_name
        self.module_args = module_args
        self.gather_facts = 'no'
        self.options = self.Options(
            listtags=listtags,
            listtasks=listtasks,
            listhosts=listhosts,
            syntax=syntax,
            timeout=timeout,
            connection=connection_type,
            module_path=module_path,
            forks=forks,
            remote_user=remote_user,
            private_key_file=private_key_file,
            ssh_common_args=ssh_common_args or "",
            ssh_extra_args=ssh_extra_args or "",
            sftp_extra_args=sftp_extra_args,
            scp_extra_args=scp_extra_args,
            become=become,
            become_method=become_method,
            become_user=become_user,
            verbosity=verbosity,
            extra_vars=extra_vars or [],
            check=check,
            diff=False
        )
        self.redisKey = redisKey
        self.logId = logId
        self.loader = DataLoader()
        self.inventory = CustomInventory(resource=hosts)
        self.variable_manager = VariableManager(self.loader, self.inventory)
        self.variable_manager.extra_vars = load_extra_vars(loader=self.loader, options=self.options)
        self.variable_manager.options_vars = load_options_vars(self.options, "")
        self.passwords = passwords or {}

    def run_module(self, host_list, module_name, module_args):
        """
        :param host_list: ßß
        :param module_name: ansible 模块名称 (-m)
        :param module_args: ansible 模块参数 (-a)
        :return:
        """
        self.callback = ModuleResultsCollector()
        play_source = dict(
            name="Ansible Ad-hoc",
            hosts=host_list,
            gather_facts=self.gather_facts,
            tasks=[dict(action=dict(module=module_name, args=module_args))]
        )
        play = Play().load(play_source, loader=self.loader, variable_manager=self.variable_manager)
        tqm = None
        try:
            tqm = TaskQueueManager(
                inventory=self.inventory,
                variable_manager=self.variable_manager,
                loader=self.loader,
                options=self.options,
                passwords=self.passwords,
                stdout_callback=self.callback
            )
            tqm._stdout_callback = self.callback
            C.HOST_KEY_CHECKING = False  # 关闭第一次使用ansible连接客户端是输入命令
            tqm.run(play)
        except Exception as err:
            print err
        finally:
            if tqm is not None:
                tqm.cleanup()
            if self.loader:
                self.loader.cleanup_all_tmp_files()

    def run_playbook(self, host_list, playbook_path, extra_vars=dict()):
        """
        run ansible palybook
        :param host_list: --limit 参数
        :param playbook_path:  playbook的路径
        :param extra_vars:
        :return:
        """
        try:
            self.callback = PlayBookResultsCollector()
            self.variable_manager.extra_vars = extra_vars

            self.inventory.subset(host_list)
            executor = PlaybookExecutor(
                playbooks=[playbook_path], inventory=self.inventory, variable_manager=self.variable_manager,
                loader=self.loader,
                options=self.options, passwords=self.passwords,
            )
            executor._tqm._stdout_callback = self.callback
            C.HOST_KEY_CHECKING = False  # 关闭第一次使用ansible连接客户端时输入命令
            C.DEPRECATION_WARNINGS = False
            C.RETRY_FILES_ENABLED = False
            executor.run()
        except Exception as err:
            print err
            return False

    def get_module_result(self):
        """
        获取module执行结果
        :return:
        """
        self.results_raw = {'success': {}, 'failed': {}, 'unreachable': {}}
        for host, result in self.callback.host_ok.items():
            self.results_raw['success'][host] = result._result['stdout']

        for host, result in self.callback.host_failed.items():
            self.results_raw['failed'][host] = result._result['stderr']

        for host, result in self.callback.host_unreachable.items():
            self.results_raw['unreachable'][host] = result._result['msg']

        return json.dumps(self.results_raw)

    def get_playbook_result(self):
        """
        获取playbook的执行结果
        :return:
        """
        self.results_raw = {'skipped': {}, 'failed': {}, 'ok': {}, "status": {}, 'unreachable': {}, "changed": {}, }

        for host, results in self.callback.task_ok.items():
            for result in results:
                if not self.results_raw['ok'].get(host):
                    self.results_raw['ok'][host] = dict()
                task_name = result.task_name
                _result = result._result
                if not self.results_raw['ok'][host].get(task_name):
                    self.results_raw['ok'][host][task_name] = list()
                if task_name != 'Gathering Facts':
                    self.results_raw['ok'][host][task_name] = (_result['stdout'])

        for host, results in self.callback.task_failed.items():
            for result in results:
                if not self.results_raw['failed'].get(host):
                    self.results_raw['failed'][host] = dict()
                task_name = result.task_name
                _result = result._result
                if not self.results_raw['failed'][host].get(task_name):
                    self.results_raw['failed'][host][task_name] = list()
                if task_name != 'Gathering Facts':
                    self.results_raw['failed'][host][task_name] = (_result['stderr'])

        for host, results in self.callback.task_unreachable.items():
            for result in results:
                if not self.results_raw['unreachable'].get(host):
                    self.results_raw['unreachable'][host] = dict()
                task_name = result.task_name
                _result = result._result
                if not self.results_raw['unreachable'][host].get(task_name):
                    self.results_raw['unreachable'][host][task_name] = list()
                self.results_raw['unreachable'][host][task_name] = (_result['msg'])

        for host, results in self.callback.task_changed.items():
            for result in results:
                if not self.results_raw['changed'].get(host):
                    self.results_raw['changed'][host] = dict()
                task_name = result.task_name
                _result = result._result
                if not self.results_raw['changed'][host].get(task_name):
                    self.results_raw['changed'][host][task_name] = list()
                self.results_raw['changed'][host][task_name] = (_result['task_name'])

        for host, results in self.callback.task_skipped.items():
            for result in results:
                if not self.results_raw['skipped'].get(host):
                    self.results_raw['skipped'][host] = dict()
                task_name = result.task_name
                _result = result._result
                if not self.results_raw['skipped'][host].get(task_name):
                    self.results_raw['skipped'][host][task_name] = list()
                self.results_raw['skipped'][host][task_name] = (_result['task_name'])

        for host, result in self.callback.task_status.items():
            self.results_raw['status'][host] = result

        self.results_raw['status_no_hosts'] = self.callback.status_no_hosts
        return json.dumps(self.results_raw)


if __name__ == "__main__":
    # 数据为List
    resource = [
        {"hostname": "172.17.84.74", "port": "22", "username": "root", "password": "admin_123", "ip": "172.17.84.74",
         "groups": ["group1"],
         "become": {"become_pass": "admin_123"},
         "vars": {"redis_port": "6379"}},
        {"hostname": "172.17.84.75", "port": "22", "username": "root", "password": "admin_123", "ip": "172.17.84.75",
         "groups": ["group1"],
         "become": {"become_pass": "admin_123"},
         "vars": {"redis_port": "6379"}}
    ]

    resource = {
        "group1": {
            "hosts": [
                {"hostname": "172.17.84.74", "port": "22", "username": "root", "password": "admin_123",
                 "ip": "172.17.84.74"},
                {"hostname": "172.17.84.75", "port": "22", "username": "root", "password": "admin_123",
                 "ip": "172.17.84.75", "vars": {"name": "admin_123233"}}
            ],
            "vars": {"role": "slave"}
        },
        "group2": {
            "hosts": [
                {"hostname": "172.17.84.75", "port": "22", "username": "root", "password": "admin_123",
                 "ip": "172.17.84.75"}
            ],
            "vars": {"role": "master"}
        }
    }

    # inventory = MyInventory(resource=resource)
    # print inventory.groups["group1"].get_hosts()
    # print inventory.groups["group1"].vars

    runner = AnsibleRunner(hosts=resource)
    # runner.run_module(host_list="172.17.84.74", module_name='shell', module_args='sudo uptime')
    # print runner.get_module_result()

    runner.run_playbook(host_list="group*",
                        playbook_path='/Users/xqzt/Python_Projects/Ansible_Api/test.yml')
    print runner.get_playbook_result()
