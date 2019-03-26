# 使用

```
    runner = AnsibleRunner(hosts=resource)
    runner.run_module(host_list="172.17.84.71", module_name='shell', module_args='sudo uptime')
    print runner.get_module_result()

    runner.run_playbook(host_list="group1",
                        playbook_path='/Users/xqzt/Python_Projects/Ansible_Api/test.yml')
    print runner.get_playbook_result()
```



# 执行结果

module执行结果

```
172.17.84.74: | SUCCESS     15:50:43 up 21 days, 21:25,  4 users,  load average: 0.01, 0.04, 0.08
{"failed": {}, "success": {"172.17.84.74": " 15:50:43 up 21 days, 21:25,  4 users,  load average: 0.01, 0.04, 0.08"}, "unreachable": {}}
```

playbook执行结果

```
/Users/xqzt/Python_Projects/Ansible_Api/venv/bin/python /Users/xqzt/Python_Projects/Ansible_Api/util/ansible_api_2.4.py
PLAY [get hostname]

TASK [Gathering Facts]#############################################################################
ok: [172.17.84.75] 
ok: [172.17.84.74] 

TASK [hostname]####################################################################################
ok: [172.17.84.75] 
ok: [172.17.84.74] 
PLAY [get data]

TASK [Gathering Facts]#############################################################################
ok: [172.17.84.75] 

TASK [date]########################################################################################
ok: [172.17.84.75] 

PLAY RECAP#########################################################################################
172.17.84.74               : ok=2    changed=1    unreachable=0    failed=0
172.17.84.75               : ok=4    changed=2    unreachable=0    failed=0
{"status": {"172.17.84.75": {"unreachable": 0, "skipped": 0, "changed": 2, "ok": 4, "failed": 0}, "172.17.84.74": {"unreachable": 0, "skipped": 0, "changed": 1, "ok": 2, "failed": 0}}, "skipped": {}, "ok": {"172.17.84.75": {"date": "2019\u5e74 03\u6708 26\u65e5 \u661f\u671f\u4e8c 15:52:35 CST", "Gathering Facts": [], "hostname": "test005"}, "172.17.84.74": {"Gathering Facts": [], "hostname": "test004"}}, "changed": {}, "status_no_hosts": false, "failed": {}, "unreachable": {}}

Process finished with exit code 0
```



# Hosts文件格式

## 列表

```
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
```

## 字典

```
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
                {"hostname": "172.17.84.77", "port": "22", "username": "root", "password": "admin_123",
                 "ip": "172.17.84.77"}
            ],
            "vars": {"role": "master"}
        }
    }
```

